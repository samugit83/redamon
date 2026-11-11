"""
Job credentials (RBAC T15, step 1.16), the orchestrator's half.

The webapp mints one at every scan start, bound to the project's owner (`ten`), the
project (`pid`) and that start (`job`), and sends it as the start request's
`job_credential`. The orchestrator verifies it, admits the scan under `ten` rather than
the body's `user_id`, and hands it to the scan container as REDAMON_JOB_CREDENTIAL; the
webapp and the agent accept the scanner key only together with it.

The format and key are webapp/src/lib/authz/machineCredential.ts's and
agentic/machine_credential.py's: b64url(canonical JSON) "." b64url(HMAC-SHA256) under
hmac(INTERNAL_API_KEY, "redamon-job-credential-v1"). This container mounts only its own
tree and recon/, so it cannot import the agent's module: this is the verifying half on
its own, held to the same tokens by tests/fixtures/machine_credential/vectors.json
(agentic/tests/test_machine_credential_interop.py runs both verifiers side by side).
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import time
from typing import Any, Dict, Mapping, Optional

JOB_CREDENTIAL_LABEL = "redamon-job-credential-v1"
JOB_AUDIENCE = "scan"

_CLAIMS = ("aud", "ten", "pid", "run", "job", "exp")
_MAX_TOKEN_LENGTH = 4096


class JobCredentialRefused(Exception):
    """A job credential that must not be honoured; `code` says why."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def master_key_is_weak() -> bool:
    master = os.environ.get("INTERNAL_API_KEY", "")
    return not master or master == "changeme"


def _key() -> bytes:
    if master_key_is_weak():
        raise JobCredentialRefused("weak_master_key")
    return hmac.new(os.environ["INTERNAL_API_KEY"].encode("utf-8"),
                    JOB_CREDENTIAL_LABEL.encode("utf-8"), hashlib.sha256).digest()


def _canonical(claims: Mapping[str, Any]) -> bytes:
    filtered = {k: claims[k] for k in _CLAIMS if claims.get(k) is not None}
    return json.dumps(filtered, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def verify_job_credential(token: Any, project_id: str, now: Optional[float] = None) -> Dict[str, Any]:
    """The claims of a valid, unexpired job credential for `project_id`; raises
    JobCredentialRefused (codes as the agent's, plus `project_mismatch`)."""
    key = _key()
    if not isinstance(token, str) or len(token) > _MAX_TOKEN_LENGTH or token.count(".") != 1:
        raise JobCredentialRefused("malformed")
    body_b64, sig_b64 = token.split(".")
    try:
        raw = _b64u_decode(body_b64)
        sig = _b64u_decode(sig_b64)
    except (ValueError, binascii.Error):
        raise JobCredentialRefused("malformed")
    if not raw or not sig:
        raise JobCredentialRefused("malformed")
    if not hmac.compare_digest(hmac.new(key, raw, hashlib.sha256).digest(), sig):
        raise JobCredentialRefused("bad_signature")
    try:
        claims = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise JobCredentialRefused("malformed")
    if not isinstance(claims, dict) or _canonical(claims) != raw:
        raise JobCredentialRefused("malformed")
    if claims.get("aud") != JOB_AUDIENCE:
        raise JobCredentialRefused("wrong_audience")
    exp = claims.get("exp")
    if type(exp) is not int:
        raise JobCredentialRefused("malformed")
    if exp <= (time.time() if now is None else now):
        raise JobCredentialRefused("expired")
    for name in ("ten", "pid", "job"):
        if not isinstance(claims.get(name), str) or not claims[name]:
            raise JobCredentialRefused("missing_claims")
    if "run" in claims:
        raise JobCredentialRefused("missing_claims")
    if claims["pid"] != project_id:
        raise JobCredentialRefused("project_mismatch")
    return claims
