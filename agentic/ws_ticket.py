"""
Agent WebSocket ticket verification (STRIDE S6).

The `/ws/agent` init frame historically self-asserted `user_id`/`project_id`/
`session_id` with no authentication, letting any LAN host that guessed a live
session key hijack the running agent task and evict the operator. To close this
without breaking the direct browser->agent connection, the (JWT-authenticated)
webapp mints a short-lived HS256 ticket bound to the operator's identity, and
the agent verifies it here before registering the session.

Ticket format: a standard compact HS256 JWS produced by the webapp via `jose`
(`webapp/src/lib/auth.ts` -> createWsTicket), claims `{ sub, pid, sid, aud, iat, exp }`,
plus an optional `act`: the person actually signed in when an admin simulates
`sub`, which a triage run records as its real actor.

`aud` names the one socket the ticket opens (WS_AUDIENCES). Each socket passes its
own name as `expected_aud` and refuses a ticket without `aud` or with another
socket's (HD-25): a chat ticket, which every project member can mint, must never
open the Kali terminal, which only its grant holders may (the webapp checks the
grant before it mints a `kali-terminal` ticket).
Verification is stdlib-only (hmac/hashlib/base64) so the agent image needs no
new dependency.

Fail-CLOSED (STRIDE S2/S3/S4): when `AGENT_WS_TICKET_SECRET` is unset, the
`/ws/agent`, `/ws/kali-terminal`, and both `/ws/cypherfix-*` handlers REJECT the
connection (close 1008) instead of trusting a self-asserted identity. A stack
brought up WITHOUT `redamon.sh` (which generates the secret via
`ensure_auth_secrets`) therefore has non-functional WebSockets by design; run
`redamon.sh` or set the secret. `verify_ws_ticket` also fails closed when the
secret is configured but the ticket is missing/invalid/expired.
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import time
from typing import Optional

logger = logging.getLogger(__name__)

#: The sockets a ticket can name in `aud`, one per WebSocket endpoint. The webapp's
#: WS_SOCKETS (webapp/src/lib/wsTicket.ts) lists the same four.
WS_AUDIENCES = ("agent", "kali-terminal", "cypherfix-triage", "cypherfix-codefix")


def ticket_secret() -> str:
    """Return the configured signing secret, or '' when unset. An empty value
    makes every WS handler fail CLOSED (S2/S3/S4), not fail-open."""
    return os.environ.get("AGENT_WS_TICKET_SECRET", "") or ""


def check_ws_origin(origin: Optional[str], host: Optional[str], extra_allowed=None) -> bool:
    """Server-side WebSocket Origin check (CSWSH defense; STRIDE S3/S4).

    CORSMiddleware does NOT cover WebSocket handshakes, so each WS endpoint must
    validate Origin itself. Rule (per the remediation plan):

    - A missing Origin is allowed: CSWSH is a browser-only attack and browsers
      always send Origin on a cross-site WS; non-browser tooling (which sends no
      Origin) is still gated by the ticket, the primary control.
    - Same-origin is the primary allow rule: the Origin's hostname must equal the
      hostname of the Host the connection was reached on (cross-PORT on the same
      host is allowed, matching the local LAN posture where the UI is :3000 and
      the agent is :8090). This avoids the local-LAN regression a strict
      _cors_origins-only gate would cause.
    - extra_allowed (e.g. AGENT_CORS_ORIGINS) is an explicit superset for genuine
      cross-origin deployments.
    """
    if not origin:
        return True
    allowed = {o.strip() for o in (extra_allowed or []) if o and o.strip()}
    if origin in allowed:
        return True
    try:
        from urllib.parse import urlparse
        origin_host = urlparse(origin).hostname
    except Exception:
        return False
    if not origin_host or not host:
        return False
    host_only = host.split(":")[0]
    return origin_host == host_only


def cors_allowlist():
    """The agent's WS/CORS origin allowlist (same source as api.py's CORS)."""
    default = "http://localhost:3000,http://127.0.0.1:3000"
    return [o.strip() for o in os.getenv("AGENT_CORS_ORIGINS", default).split(",") if o.strip()]


def authorize_ws(origin, host, ticket, extra_allowed=None, *, aud):
    """Combined WS gate for the raw-proxy endpoints (kali terminal, cypherfix):
    same-origin check + fail-closed ticket verification for the socket `aud`.

    Returns ``(ok, claims, reason)``: ``ok`` True only when the origin is allowed
    AND a valid ticket for this socket verified against the configured secret.
    ``claims`` is the verified claim dict on success (None otherwise). ``reason``
    is a short fixed string for logging and the close frame when rejected. Fails
    CLOSED when the secret is unset (S3/S4).
    """
    if not check_ws_origin(origin, host, extra_allowed):
        return False, None, "disallowed origin"
    secret = ticket_secret()
    if not secret:
        return False, None, "ticket auth not configured"
    claims = verify_ws_ticket(ticket, secret, expected_aud=aud)
    if claims is None:
        return False, None, "missing or invalid ticket"
    return True, claims, "ok"


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def verify_ws_ticket(ticket: Optional[str], secret: str, *, expected_aud: str,
                     leeway: int = 30) -> Optional[dict]:
    """Verify a compact HS256 ticket for the socket `expected_aud`.

    Returns the claims dict on success, or None if the ticket is missing,
    malformed, wrong-algorithm, has a bad signature, is expired, lacks the
    required `sub`/`pid`/`sid` claims, or names no socket or another one than
    `expected_aud`. Never raises. `expected_aud` has no default, so a caller
    cannot forget to say which socket it guards.
    """
    if not ticket or not secret:
        return None

    parts = ticket.split(".")
    if len(parts) != 3:
        return None
    header_b64, payload_b64, sig_b64 = parts

    try:
        header = json.loads(_b64url_decode(header_b64))
    except Exception:
        return None
    # Only accept HS256; reject `alg: none` and any asymmetric/other alg.
    if not isinstance(header, dict) or header.get("alg") != "HS256":
        return None

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    expected_sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    try:
        got_sig = _b64url_decode(sig_b64)
    except Exception:
        return None
    if not hmac.compare_digest(expected_sig, got_sig):
        return None

    try:
        payload = json.loads(_b64url_decode(payload_b64))
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None

    exp = payload.get("exp")
    if not isinstance(exp, (int, float)) or time.time() > exp + leeway:
        return None

    if not payload.get("sub") or not payload.get("pid") or not payload.get("sid"):
        return None

    presented = payload.get("aud")
    if expected_aud not in WS_AUDIENCES or presented != expected_aud:
        # Signed by the webapp, so the claim is ours; still, only known names reach the log.
        named = presented if presented in WS_AUDIENCES else ("none" if presented is None else "other")
        logger.warning("[rbac] ticket refused aud=%s presented=%s", expected_aud, named)
        return None

    return payload
