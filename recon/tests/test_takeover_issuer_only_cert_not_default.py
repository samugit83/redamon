"""A certificate known only by its issuer is not the edge's default certificate (S-25).

run_subdomain_takeover adds cert_provider_default (+20, "the edge presents its
own default certificate, so the name is claimable") when a certificate names
a provider and not the host. provider_from_cert names the provider two ways:
from a SAN on the provider's own edge domain (*.herokuapp.com, *.s3.amazonaws.com),
which is what an edge serves for a name nobody configured; or, failing that,
from the issuer alone. Amazon (ACM), Cloudflare and Google Trust Services
issue their customers' certificates too, so an issuer-only certificate that
names other names than this host is a customer's certificate, not the edge's
default: it is no evidence that the name is claimable.

Since S-27 the issuer does not name the finding's provider either (it is only
recorded as cert_provider), so the finding keeps the tool's placeholder.
Scanners and DNS probes are mocked; the certificate is an http_probe one. The
full pipeline and partial recon share run_subdomain_takeover.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

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

ACM = "CN=Amazon RSA 2048 M02,O=Amazon,C=US"
CLOUDFLARE = "CN=Cloudflare Inc ECC CA-3,O=Cloudflare\\, Inc.,C=US"
GTS = "CN=WR1,O=Google Trust Services,C=US"


def _run(monkeypatch, *, cname, san, issuer, subjack_service=""):
    monkeypatch.setattr(runner, "_run_subjack", lambda subdomains, work_dir, settings: (
        [{"subdomain": HOST, "vulnerable": True, "service": subjack_service}]))
    monkeypatch.setattr(runner, "_run_nuclei_takeover", lambda urls, work_dir, settings: [])
    th.resolve_cname_target.cache_clear()
    monkeypatch.setattr(runner, "resolve_cname_target", lambda c, timeout=3.0: {
        "resolves": True, "ips": ("203.0.113.5",), "nxdomain": False})
    cert = {"subject_cn": san[0], "san": list(san), "issuer": issuer,
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


@pytest.mark.parametrize("issuer, provider, cname", [
    (ACM, "aws", "app-123.us-east-1.elb.amazonaws.com"),
    (CLOUDFLARE, "cloudflare", "edge.example.net"),
    (GTS, "google", "edge.example.net"),
])
def test_a_customer_certificate_for_other_names_is_not_the_edges_default(
        monkeypatch, issuer, provider, cname):
    f = _run(monkeypatch, cname=cname, san=["www.example.org", "shop.example.org"],
             issuer=issuer)
    assert f["cert_provider"] == provider and f["takeover_provider"] == "unknown"
    assert f["cert_name_match"] is False
    assert not f.get("cert_provider_default"), \
        "an issuer-only certificate naming other names scored as the edge's default (+20)"
    # Subjack +25, CNAME +10, live CNAME of a provider that is not
    # auto-exploitable -30, unknown provider -10, floor 0.
    assert f["confidence"] == 0
    assert f["verdict"] == "manual_review"
    assert f["id"] == th.finding_id(HOST, "unknown", "cname")


def test_control_the_edges_own_certificate_is_still_its_default(monkeypatch):
    f = _run(monkeypatch, cname="example-app.herokuapp.com", san=["*.herokuapp.com"],
             issuer="Example Edge CA", subjack_service="heroku")
    assert f["cert_provider"] == "heroku" and f["cert_name_match"] is False
    assert f["cert_provider_default"] is True
    # Subjack +25, auto-exploitable +20, CNAME +10, the edge's default certificate +20.
    assert f["confidence"] == 75
    assert f["verdict"] == "confirmed"


def test_control_an_amazon_issued_s3_edge_certificate_is_its_default(monkeypatch):
    # The SAN, not the Amazon issuer, names the provider here.
    f = _run(monkeypatch, cname="assets.example.test.s3.amazonaws.com",
             san=["*.s3.amazonaws.com"], issuer=ACM, subjack_service="aws/s3")
    assert f["cert_provider"] == "aws-s3"
    assert f["cert_provider_default"] is True


def test_control_an_issuer_only_certificate_naming_the_host_is_no_default(monkeypatch):
    f = _run(monkeypatch, cname="edge.example.net", san=[HOST], issuer=CLOUDFLARE)
    assert f["cert_name_match"] is True
    assert not f.get("cert_provider_default")
