"""
Redamon capture context tag (X-Redamon-Ctx) — sign / verify.

This is the security primitive the credential-free capture proxy depends on
(plan §7.2, §15.2, §20.4). Every generator (recon tool, agent tool) that routes
through the capture proxy attaches a compact signed token describing WHO the
traffic belongs to:

    {source, project_id, user_id, run_id, session_id, tool, phase, step, member_id}

Trust model (§20.4 — two minters, two keys, one verifier, proxy holds no key):
  - recon  signs with SCANNER_API_KEY   (it already holds it)
  - agent  signs with INTERNAL_API_KEY  (it already holds it)
  - traffic-ingest verifies: it picks the key by the *claimed* source, then
    checks the HMAC. Because the source is INSIDE the signed body, an attacker
    who lacks the key cannot forge a tag for either source.
  - the capture proxy only carries the opaque token verbatim and strips the
    header before forwarding upstream; it never holds a signing key and cannot
    decode or forge a tag.

Token format (URL-safe, header-friendly, no '='):  <b64url(json)>.<b64url(hmac)>
JSON is canonical (sorted keys, compact separators) so signer and verifier agree
byte-for-byte.

Pure stdlib so it can be dropped verbatim into recon, agent, and the ingest
worker without adding a dependency.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any, Dict, Mapping, Optional

# Only these keys are carried; anything else is dropped so a caller cannot smuggle
# extra fields past the signature into the ingest stamping logic. `is_replay` /
# `origin_id` let a signed replay (proxy_replay/proxy_fuzz) mark its lineage — the
# ingest stamps them from the VERIFIED tag, so a target/proxy cannot forge them.
_ALLOWED_FIELDS = (
    "source", "project_id", "user_id", "run_id", "session_id",
    "tool", "phase", "step", "member_id", "is_replay", "origin_id",
)

VALID_SOURCES = frozenset({"recon", "agent", "operator"})


def _b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _canonical(payload: Mapping[str, Any]) -> bytes:
    filtered = {k: payload[k] for k in _ALLOWED_FIELDS if payload.get(k) is not None}
    return json.dumps(filtered, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_tag(payload: Mapping[str, Any], key: str) -> str:
    """Sign a context payload with `key` (the minter's shared secret).

    Only whitelisted fields are included; `source` and the tenant fields must be
    present and correct at the minter (they cannot be added/altered downstream
    without the key).
    """
    if not key:
        raise ValueError("empty signing key")
    raw = _canonical(payload)
    sig = hmac.new(key.encode("utf-8"), raw, hashlib.sha256).digest()
    return _b64u_encode(raw) + "." + _b64u_encode(sig)


def verify_tag(token: str, keys: Mapping[str, str]) -> Optional[Dict[str, Any]]:
    """Verify a token and return its payload, or None if invalid.

    `keys` maps source -> secret, e.g. {"recon": SCANNER_API_KEY, "agent":
    INTERNAL_API_KEY}. The source is read from the (as-yet-unverified) body only
    to SELECT which key to check against; the HMAC over the whole body is what
    actually authenticates it, so a wrong/absent key or any tampering fails
    closed. Constant-time comparison avoids a timing side channel.
    """
    if not token or "." not in token:
        return None
    try:
        body_b64, sig_b64 = token.split(".", 1)
        raw = _b64u_decode(body_b64)
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            return None
        source = payload.get("source")
        if source not in VALID_SOURCES:
            return None
        key = keys.get(source)
        if not key:
            return None
        expected = hmac.new(key.encode("utf-8"), raw, hashlib.sha256).digest()
        provided = _b64u_decode(sig_b64)
        if not hmac.compare_digest(expected, provided):
            return None
        # Re-canonicalize + re-sign check: guarantees the payload contains no
        # extra (unsigned-relevant) fields beyond the canonical set. Because raw
        # was produced from the canonical form at signing, a body carrying extra
        # keys would not round-trip and is rejected.
        if _canonical(payload) != raw:
            return None
        return payload
    except (ValueError, KeyError, json.JSONDecodeError, UnicodeDecodeError):
        return None
