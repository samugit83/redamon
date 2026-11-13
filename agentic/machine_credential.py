"""
Machine credentials: short-lived HMAC tokens bound to a tenant, a project and a
run or a job (RBAC T15).

- run credential: minted by this agent for the sandbox's two clients that call it
  back, proxy_brain's `redamon` SDK (aud "traffic", 15 minutes, one per call) and
  the Kali terminal's redagraph (aud "graph", 12 hours, one per connection). They
  present it as X-Redamon-Run in place of the scanner key, which the sandbox no
  longer holds; the agent's graph and traffic routes take the tenant from it.
- job credential (aud "scan", 7 days): minted by the webapp at every scan start
  (webapp/src/lib/authz/machineCredential.ts), carried by the orchestrator into the
  scan container as REDAMON_JOB_CREDENTIAL and sent back as X-Redamon-Job beside
  the scanner key. The agent's /llm/* and /jev/* take the user from it.

Format: b64url(canonical JSON).b64url(HMAC-SHA256), the REDAMON_CTX tag's shape
and its base64url helpers. Claims: aud, ten, pid, run or job, exp (seconds); a run
credential may also name the person it acts for (sub) and an admin acting as them
(act), while `ten` stays the project's owner, whose graph and keys it uses. The
key is hmac(INTERNAL_API_KEY, label), one label per kind, so a run credential
never verifies as a job credential or a ctx tag, nor the other way round. A weak
master key (unset or "changeme") mints and verifies nothing.

The token is signed, not encrypted: whoever reads it sees its claims. Its expiry
bounds the use of one copied out of another process's environment.
"""
from __future__ import annotations

import binascii
import hashlib
import hmac
import json
import os
import time
from typing import Any, Dict, Mapping, Optional

from redamon_ctx import _b64u_decode, _b64u_encode

RUN_CREDENTIAL_LABEL = "redamon-run-credential-v1"
JOB_CREDENTIAL_LABEL = "redamon-job-credential-v1"

RUN_AUDIENCES = frozenset({"traffic", "graph"})
JOB_AUDIENCE = "scan"
TRAFFIC_TTL_SECONDS = 15 * 60
# PLACEHOLDER(OQ-38): a terminal connection's graph credential lasts as long as a
# working session; the owner may shorten it.
TERMINAL_TTL_SECONDS = 12 * 60 * 60

_CLAIMS = ("aud", "ten", "sub", "act", "pid", "run", "job", "exp")
# Only a run credential names a person; the job credential's twins (webapp,
# orchestrator) sign the other claims alone.
_PERSON_CLAIMS = ("sub", "act")
_MAX_TOKEN_LENGTH = 4096


class CredentialRefused(Exception):
    """A credential that must not be honoured; `code` says why (logged, sent to the caller)."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def derive_key(master: str, label: str) -> bytes:
    return hmac.new(master.encode("utf-8"), label.encode("utf-8"), hashlib.sha256).digest()


def _canonical(claims: Mapping[str, Any]) -> bytes:
    filtered = {k: claims[k] for k in _CLAIMS if claims.get(k) is not None}
    return json.dumps(filtered, sort_keys=True, separators=(",", ":")).encode("utf-8")


def mint(claims: Mapping[str, Any], key: bytes) -> str:
    """Sign `claims` (only the known ones are kept) with an already-derived key."""
    if not key:
        raise ValueError("empty signing key")
    raw = _canonical(claims)
    return _b64u_encode(raw) + "." + _b64u_encode(hmac.new(key, raw, hashlib.sha256).digest())


def verify(token: Any, key: bytes, aud: str, now: Optional[float] = None) -> Dict[str, Any]:
    """The claims of a valid, unexpired token for `aud`; raises CredentialRefused."""
    if not key:
        raise CredentialRefused("weak_master_key")
    if not isinstance(token, str) or len(token) > _MAX_TOKEN_LENGTH or token.count(".") != 1:
        raise CredentialRefused("malformed")
    body_b64, sig_b64 = token.split(".")
    try:
        raw = _b64u_decode(body_b64)
        sig = _b64u_decode(sig_b64)
    except (ValueError, binascii.Error):
        raise CredentialRefused("malformed")
    if not raw or not sig:
        raise CredentialRefused("malformed")
    if not hmac.compare_digest(hmac.new(key, raw, hashlib.sha256).digest(), sig):
        raise CredentialRefused("bad_signature")
    try:
        claims = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise CredentialRefused("malformed")
    # Re-canonicalising refuses a body carrying claims the signer would have dropped.
    if not isinstance(claims, dict) or _canonical(claims) != raw:
        raise CredentialRefused("malformed")
    if claims.get("aud") != aud:
        raise CredentialRefused("wrong_audience")
    exp = claims.get("exp")
    if type(exp) is not int:
        raise CredentialRefused("malformed")
    if exp <= (time.time() if now is None else now):
        raise CredentialRefused("expired")
    for name in ("ten", "pid"):
        if not isinstance(claims.get(name), str) or not claims[name]:
            raise CredentialRefused("missing_claims")
    return claims


def _master_derived_key(label: str) -> bytes:
    from llm_guard import master_key_is_weak

    if master_key_is_weak():
        raise CredentialRefused("weak_master_key")
    return derive_key(os.environ["INTERNAL_API_KEY"], label)


def _run_key() -> bytes:
    return _master_derived_key(RUN_CREDENTIAL_LABEL)


def mint_run_credential(aud: str, tenant: str, project_id: str, run_id: str, ttl_seconds: int,
                        now: Optional[float] = None, actor: Optional[str] = None,
                        real_actor: Optional[str] = None) -> str:
    """`actor` is the person the run acts for (attribution, consent), `real_actor` an
    admin acting as them; `tenant` is the project's owner either way."""
    if aud not in RUN_AUDIENCES:
        raise ValueError(f"not a run credential audience: {aud!r}")
    if not tenant or not project_id or not run_id:
        raise ValueError("a run credential needs its tenant, project and run")
    key = _run_key()
    issued = int(time.time() if now is None else now)
    return mint({"aud": aud, "ten": tenant, "sub": actor or None, "act": real_actor or None,
                 "pid": project_id, "run": run_id, "exp": issued + int(ttl_seconds)}, key)


def verify_run_credential(token: Any, aud: str, now: Optional[float] = None) -> Dict[str, Any]:
    claims = verify(token, _run_key(), aud, now)
    if not isinstance(claims.get("run"), str) or not claims["run"] or "job" in claims:
        raise CredentialRefused("missing_claims")
    for name in _PERSON_CLAIMS:
        if name in claims and (not isinstance(claims[name], str) or not claims[name]):
            raise CredentialRefused("missing_claims")
    return claims


def verify_job_credential(token: Any, now: Optional[float] = None) -> Dict[str, Any]:
    """The claims of a valid job credential (the webapp mints them; nothing here does)."""
    claims = verify(token, _master_derived_key(JOB_CREDENTIAL_LABEL), JOB_AUDIENCE, now)
    if any(name in claims for name in _PERSON_CLAIMS):
        # What the twins' canonical form answers for a claim they do not sign.
        raise CredentialRefused("malformed")
    if not isinstance(claims.get("job"), str) or not claims["job"] or "run" in claims:
        raise CredentialRefused("missing_claims")
    return claims
