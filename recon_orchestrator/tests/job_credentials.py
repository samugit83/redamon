"""Test helper: job credentials the orchestrator accepts, and the keys it checks them with.

Mints in the webapp's format (canonical JSON . HMAC-SHA256 under
hmac(INTERNAL_API_KEY, "redamon-job-credential-v1")); tests/fixtures/machine_credential/
vectors.json pins that format against the webapp's minter. Fake keys only.
"""
import base64
import hashlib
import hmac
import json
import time

MASTER = "orchestrator-test-master-key"
SCANNER = "orchestrator-test-scanner-key"
KEYS = {"INTERNAL_API_KEY": MASTER, "SCANNER_API_KEY": SCANNER}


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def job_credential(project_id: str = "p1", tenant: str = "u1", *, exp_in: int = 3600,
                   master: str = MASTER, aud: str = "scan", job: str = "job-1") -> str:
    claims = {"aud": aud, "ten": tenant, "pid": project_id, "job": job, "exp": int(time.time()) + exp_in}
    raw = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("utf-8")
    key = hmac.new(master.encode("utf-8"), b"redamon-job-credential-v1", hashlib.sha256).digest()
    return _b64u(raw) + "." + _b64u(hmac.new(key, raw, hashlib.sha256).digest())


def use_keys(monkeypatch, **override):
    """Give the orchestrator its master and scanner keys for one test."""
    for name, value in {**KEYS, **override}.items():
        monkeypatch.setenv(name, value)
