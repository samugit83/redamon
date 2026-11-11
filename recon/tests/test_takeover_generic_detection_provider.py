"""A generic Nuclei detection is no provider, so it never disagrees with one (S-24).

normalize_nuclei_takeover gives `detect-dangling-cname` the provider
`dangling-cname` (and `dns-saas-service-detection` would give `dns-saas`): the
name of what the template detects, not of the service behind the CNAME. The
CNAME and certificate checks filled only "", "unknown" and "none" from the
provider they observed, and compared anything else with it, so a real
dangling CNAME to a known provider kept the placeholder and lost 25 points as
a provider mismatch. A placeholder now takes the observed provider, as
"unknown" does.

detect-dangling-cname is an `info` template (TAKEOVER_SEVERITY must list
info), and dns-saas-service-detection is tagged `dns,service,discovery`, which
the takeover normalizer drops: the last test pins that.

Scanners and DNS probes are mocked; the shapes are nuclei's JSONL rows.
"""
from __future__ import annotations

import sys
from pathlib import Path

for _p in ("/repo", "/repo/recon", str(Path(__file__).resolve().parents[2]),
           str(Path(__file__).resolve().parents[1])):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from recon.helpers import takeover_helpers as th  # noqa: E402
from recon.helpers.nuclei_helpers import parse_nuclei_finding  # noqa: E402
from recon.main_recon_modules import subdomain_takeover as runner  # noqa: E402

SETTINGS = {
    "SUBDOMAIN_TAKEOVER_ENABLED": True,
    "SUBJACK_ENABLED": False,
    "NUCLEI_TAKEOVERS_ENABLED": True,
    "BADDNS_ENABLED": False,
    "TAKEOVER_CNAME_VALIDATION_ENABLED": True,
    "TAKEOVER_CERT_VALIDATION_ENABLED": True,
    "TAKEOVER_CONFIDENCE_THRESHOLD": 60,
    "TAKEOVER_SEVERITY": ["info", "low", "medium", "high", "critical"],
}

HOST = "old.example.test"


def _dangling_row(cname):
    """detect-dangling-cname as nuclei writes it (dns/ template, extracted CNAME)."""
    return {"template-id": "detect-dangling-cname", "template": "dns/detect-dangling-cname.yaml",
            "info": {"name": "CNAME Detect Dangling", "severity": "info",
                     "tags": ["dns", "takeover", "discovery"]},
            "type": "dns", "host": HOST, "matched-at": HOST, "extracted-results": [cname]}


def _run(monkeypatch, row, *, cert=None):
    monkeypatch.setattr(runner, "_run_subjack", lambda subdomains, work_dir, settings: [])
    monkeypatch.setattr(runner, "_run_nuclei_takeover", lambda urls, work_dir, settings: [row])
    th.resolve_cname_target.cache_clear()
    monkeypatch.setattr(runner, "resolve_cname_target",
                        lambda c, timeout=3.0: {"resolves": False, "ips": (), "nxdomain": True})
    probe = {"status_code": 404, "host": HOST}
    if cert:
        probe["tls"] = {"certificate": cert}
    recon = {"domain": "example.test", "dns": {"subdomains": {}},
             "http_probe": {"by_url": {f"https://{HOST}": probe}}}
    out = runner.run_subdomain_takeover(recon, settings=dict(SETTINGS))
    [finding] = out["subdomain_takeover"]["findings"]
    return finding


def test_the_generic_detections_name_no_provider():
    assert th.provider_from_signal("detect-dangling-cname") == "dangling-cname"
    assert th.provider_from_signal("dns-saas-service-detection") == "dns-saas"
    for placeholder in ("dangling-cname", "dns-saas", "unknown", "", None, " Unknown "):
        assert th.is_placeholder_provider(placeholder)
    for provider in ("heroku", "aws", "azure-app-service"):
        assert not th.is_placeholder_provider(provider)


def test_a_dangling_cname_to_a_known_provider_takes_that_provider(monkeypatch):
    f = _run(monkeypatch, _dangling_row("orphan-app.azurewebsites.net"))
    assert not f.get("provider_mismatch"), \
        "the template's name was compared with the CNAME's provider (-25)"
    assert f["takeover_provider"] == "azure-app-service"
    assert f["cname_nxdomain"] is True
    assert f["confidence"] == 15  # the Nuclei match, nothing subtracted
    assert f["id"] == th.finding_id(HOST, "azure-app-service", "dns")


def test_a_dangling_cname_to_an_auto_exploitable_provider_scores_as_one(monkeypatch):
    f = _run(monkeypatch, _dangling_row("orphan-app.herokuapp.com"))
    assert f["takeover_provider"] == "heroku"
    assert not f.get("provider_mismatch")
    assert f["confidence"] == 35  # +15 Nuclei, +20 auto-exploitable


def test_the_certificate_names_the_provider_when_the_cname_does_not(monkeypatch):
    cert = {"subject_cn": "*.herokuapp.com", "san": ["*.herokuapp.com"],
            "issuer": "Example Edge CA", "expired": False, "self_signed": False,
            "mismatched": False}
    f = _run(monkeypatch, _dangling_row("orphan.deadcdn.example"), cert=cert)
    assert not f.get("cert_provider_mismatch"), \
        "the template's name was compared with the certificate's provider (-25)"
    assert f["takeover_provider"] == "heroku"
    assert f["cert_provider"] == "heroku"


def test_control_no_provider_observed_keeps_the_placeholder(monkeypatch):
    f = _run(monkeypatch, _dangling_row("orphan.deadcdn.example"))
    assert f["takeover_provider"] == "dangling-cname"
    assert not f.get("provider_mismatch")
    assert f["confidence"] == 15
    assert f["id"] == th.finding_id(HOST, "dangling-cname", "dns")


def test_control_a_real_provider_still_disagrees_with_another(monkeypatch):
    row = {"template-id": "heroku-takeover", "template": "http/takeovers/heroku-takeover.yaml",
           "info": {"name": "Heroku Takeover", "severity": "high", "tags": ["takeover"]},
           "host": f"https://{HOST}", "matched-at": f"https://{HOST}/",
           "extracted-results": ["orphan-app.azurewebsites.net"]}
    f = _run(monkeypatch, row)
    assert f["takeover_provider"] == "heroku"
    assert f.get("provider_mismatch") is True


def test_dns_saas_service_detection_never_reaches_the_takeover_scorer():
    row = {"template-id": "dns-saas-service-detection",
           "template": "dns/dns-saas-service-detection.yaml",
           "info": {"name": "DNS SaaS Service Detection", "severity": "info",
                    "tags": ["dns", "service", "discovery"]},
           "type": "dns", "host": HOST, "matched-at": HOST, "matcher-name": "azure",
           "extracted-results": ["portal.azurewebsites.net"]}
    assert th.normalize_nuclei_takeover(parse_nuclei_finding(row)) is None
