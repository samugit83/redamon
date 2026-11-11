"""A certificate of the same provider family is no provider mismatch (S-12c).

run_subdomain_takeover compares the tool's provider with the CNAME's through
same_provider_family (`azure` from a generic template and `azure-app-service`
from the CNAME are one provider), and must compare it with the certificate's
provider the same way. With a plain `!=`, the edge's own default certificate
(*.azurewebsites.net) marked cert_provider_mismatch on an Azure finding, and
the scorer subtracted 25 for a signal that corroborates it.

Scanners and DNS probes are mocked; the certificate is an http_probe one.
"""
from __future__ import annotations

import sys
from pathlib import Path

for _p in ("/repo", "/repo/recon", str(Path(__file__).resolve().parents[2]),
           str(Path(__file__).resolve().parents[1])):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from recon.helpers import takeover_helpers as th  # noqa: E402
from recon.main_recon_modules import subdomain_takeover as runner  # noqa: E402

SETTINGS = {
    "SUBDOMAIN_TAKEOVER_ENABLED": True,
    "SUBJACK_ENABLED": True,
    "NUCLEI_TAKEOVERS_ENABLED": True,
    "BADDNS_ENABLED": False,
    "TAKEOVER_CNAME_VALIDATION_ENABLED": True,
    "TAKEOVER_CERT_VALIDATION_ENABLED": True,
    "TAKEOVER_CONFIDENCE_THRESHOLD": 60,
}

HOST = "portal.example.test"


def _run(monkeypatch, *, cname, subjack_service=None, nuclei_template=None, cert_san):
    monkeypatch.setattr(runner, "_run_subjack", lambda subdomains, work_dir, settings: (
        [{"subdomain": HOST, "vulnerable": True, "service": subjack_service}] if subjack_service else []))
    monkeypatch.setattr(runner, "_run_nuclei_takeover", lambda urls, work_dir, settings: (
        [{"template-id": nuclei_template, "matched-at": f"https://{HOST}/",
          "info": {"name": nuclei_template, "severity": "high", "tags": ["takeover"]}}]
        if nuclei_template else []))
    th.resolve_cname_target.cache_clear()
    monkeypatch.setattr(runner, "resolve_cname_target",
                        lambda c, timeout=3.0: {"resolves": True, "ips": ("203.0.113.5",), "nxdomain": False})
    # The provider edge's own default certificate: names the provider, not the host.
    cert = {"subject_cn": cert_san, "san": [cert_san], "issuer": "Example Edge CA",
            "expired": False, "self_signed": False, "mismatched": False}
    recon = {
        "domain": "example.test",
        "dns": {"subdomains": {HOST: {"records": {"CNAME": f"{cname}."}}}},
        "http_probe": {"by_url": {f"https://{HOST}": {"status_code": 404, "host": HOST,
                                                       "tls": {"certificate": cert}}}},
    }
    out = runner.run_subdomain_takeover(recon, settings=dict(SETTINGS))
    [finding] = out["subdomain_takeover"]["findings"]
    return finding


def test_azure_template_with_the_azure_edge_certificate(monkeypatch):
    f = _run(monkeypatch, cname="example-portal.azurewebsites.net",
             nuclei_template="azure-takeover-detection", cert_san="*.azurewebsites.net")
    assert f["takeover_provider"] == "azure"
    assert f["cert_provider"] == "azure-app-service"
    assert not f.get("provider_mismatch"), "the CNAME check already calls these one provider"
    assert not f.get("cert_provider_mismatch"), \
        "the certificate of the same provider family was scored as a mismatch (-25)"


def test_control_another_providers_certificate_is_a_mismatch(monkeypatch):
    f = _run(monkeypatch, cname="example-portal.azurewebsites.net",
             nuclei_template="azure-takeover-detection", cert_san="*.herokuapp.com")
    assert f["cert_provider"] == "heroku"
    assert f.get("cert_provider_mismatch") is True
