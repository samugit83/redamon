"""A certificate issuer alone never names the takeover provider (S-27).

provider_from_cert names a provider from a SAN on the provider's own edge
domain (*.herokuapp.com, *.s3.amazonaws.com) or, failing that, from issuer
markers. An issuer names who signed the certificate, not the edge serving the
host: Google Trust Services also signs Cloudflare Universal SSL certificates,
Amazon (ACM) and Cloudflare sign their customers' own names. Read as the
provider, the issuer

  (a) filled a finding whose tools and CNAME named none, so the host was
      labelled `google` (and keyed on it, the provider is part of the id);
  (b) counted as cert_provider_mismatch (-25) against the provider a tool or
      the CNAME named.

The issuer is still recorded as cert_provider, and an `aws` family issuer still
sits beside an `aws-*` provider without penalty (S-23); a SAN on the provider's
edge domain still names the provider and still disagrees with another one.

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
# A Cloudflare-proxied name: the CNAME suffix table names no provider for it.
CLOUDFLARE_CNAME = "portal.example.test.cdn.cloudflare.net"

ACM = "CN=Amazon RSA 2048 M02,O=Amazon,C=US"
CLOUDFLARE = "CN=Cloudflare Inc ECC CA-3,O=Cloudflare\\, Inc.,C=US"
GTS = "CN=WE1,O=Google Trust Services,C=US"

# A customer certificate: it names the customer's names, no provider edge.
CUSTOMER_SANS = ["example.org", "*.example.org"]


def _dangling(cname):
    return {"template-id": "detect-dangling-cname", "template": "dns/detect-dangling-cname.yaml",
            "info": {"name": "CNAME Detect Dangling", "severity": "info",
                     "tags": ["dns", "takeover", "discovery"]},
            "type": "dns", "host": HOST, "matched-at": HOST, "extracted-results": [cname]}


def _run(monkeypatch, *, issuer, sans=CUSTOMER_SANS, cname=CLOUDFLARE_CNAME,
         subjack_service=None, nuclei=()):
    monkeypatch.setattr(runner, "_run_subjack", lambda subdomains, work_dir, settings: (
        [{"subdomain": HOST, "vulnerable": True, "service": subjack_service}]
        if subjack_service is not None else []))
    monkeypatch.setattr(runner, "_run_nuclei_takeover",
                        lambda urls, work_dir, settings: list(nuclei))
    th.resolve_cname_target.cache_clear()
    monkeypatch.setattr(runner, "resolve_cname_target", lambda c, timeout=3.0: {
        "resolves": True, "ips": ("203.0.113.5",), "nxdomain": False})
    cert = {"subject_cn": sans[0], "san": list(sans), "issuer": issuer,
            "expired": False, "self_signed": False, "mismatched": False}
    records = {HOST: {"records": {"CNAME": f"{cname}."}}} if cname else {}
    recon = {
        "domain": "example.test",
        "dns": {"subdomains": records},
        "http_probe": {"by_url": {f"https://{HOST}": {"status_code": 404, "host": HOST,
                                                       "tls": {"certificate": cert}}}},
    }
    out = runner.run_subdomain_takeover(recon, settings=dict(SETTINGS))
    [finding] = out["subdomain_takeover"]["findings"]
    return finding


# --- (a) the issuer alone does not name the provider -------------------------

def test_a_gts_certificate_on_a_cloudflare_host_is_not_google(monkeypatch):
    f = _run(monkeypatch, issuer=GTS, subjack_service="")
    assert f["takeover_provider"] != "google", \
        "the certificate's issuer (Google Trust Services) was taken for the edge serving the host"
    assert f["takeover_provider"] == "unknown"
    assert f["id"] == th.finding_id(HOST, "unknown", "cname")
    # Who signed the certificate is still recorded.
    assert f["cert_provider"] == "google"
    assert not f.get("cert_provider_mismatch")


@pytest.mark.parametrize("issuer", [ACM, CLOUDFLARE, GTS])
def test_an_issuer_only_certificate_keeps_the_tools_placeholder(monkeypatch, issuer):
    f = _run(monkeypatch, issuer=issuer, subjack_service="")
    assert f["takeover_provider"] == "unknown"
    assert f["id"] == th.finding_id(HOST, "unknown", "cname")
    # Subjack +25, CNAME +10, live CNAME -30, unknown provider -10 (floor 0).
    assert f["confidence"] == 0


def test_a_dangling_cname_with_an_issuer_only_certificate_keeps_its_placeholder(monkeypatch):
    f = _run(monkeypatch, issuer=ACM, cname=None, nuclei=[_dangling("orphan.deadcdn.example")])
    assert f["takeover_provider"] == "dangling-cname"
    assert f["id"] == th.finding_id(HOST, "dangling-cname", "dns")
    assert f["cert_provider"] == "aws"


# --- (b) the issuer alone is no mismatch -------------------------------------

def test_a_gts_certificate_is_no_mismatch_with_the_tools_provider(monkeypatch):
    # A proxied name whose origin answers with GitHub Pages' unclaimed page.
    f = _run(monkeypatch, issuer=GTS, subjack_service="github")
    assert f["takeover_provider"] == "github-pages"
    assert not f.get("cert_provider_mismatch"), \
        "the certificate's issuer was scored as another provider than the tool's (-25)"
    # Subjack +25, auto-exploitable +20, CNAME +10.
    assert f["confidence"] == 55


def test_an_issuer_only_certificate_is_no_mismatch_with_the_cname_provider(monkeypatch):
    f = _run(monkeypatch, issuer=GTS, cname="example-app.herokudns.com", subjack_service="")
    assert f["takeover_provider"] == "heroku"
    assert not f.get("cert_provider_mismatch"), \
        "the certificate's issuer was scored as another provider than the CNAME's (-25)"


# --- controls ----------------------------------------------------------------

def test_control_a_san_on_the_edge_domain_still_names_the_provider(monkeypatch):
    f = _run(monkeypatch, issuer=ACM, sans=["*.herokuapp.com"], subjack_service="")
    assert f["takeover_provider"] == "heroku"
    assert f["cert_provider"] == "heroku"
    assert f["cert_provider_default"] is True
    assert f["id"] == th.finding_id(HOST, "heroku", "cname")


def test_control_a_san_on_another_edge_domain_is_still_a_mismatch(monkeypatch):
    f = _run(monkeypatch, issuer=GTS, sans=["*.herokuapp.com"], subjack_service="github")
    assert f["takeover_provider"] == "github-pages"
    assert f["cert_provider"] == "heroku"
    assert f.get("cert_provider_mismatch") is True


def test_control_an_amazon_issuer_sits_beside_an_aws_provider(monkeypatch):
    # S-23: the issuer names the `aws` family, recorded beside an aws-* provider
    # with no penalty.
    f = _run(monkeypatch, issuer=ACM, cname="d111111abcdef8.cloudfront.net", subjack_service="")
    assert f["takeover_provider"] == "aws-cloudfront"
    assert f["cert_provider"] == "aws"
    assert not f.get("cert_provider_mismatch")
