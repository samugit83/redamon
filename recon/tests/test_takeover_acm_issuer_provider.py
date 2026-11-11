"""An Amazon-issued certificate names AWS, not S3 (S-23).

provider_from_cert falls back to issuer markers when no SAN names a provider
edge. Amazon (ACM) issues the certificates of every AWS service and of its
customers' own names, so the issuer says "AWS" and nothing finer. Mapped to
`aws-s3`, any ACM certificate made a finding of unknown provider an S3 one:
+20 as auto-exploitable, exempt from the live-CNAME -30, and a -25
cert_provider_mismatch on a CloudFront or Elastic Beanstalk finding, which are
AWS too. The family slug `aws` is the same family as every `aws-*` provider
(same_provider_family) and is not auto-exploitable. Since S-27 the issuer is
only recorded as cert_provider: it never names the finding's provider.

Scanners and DNS probes are mocked; the certificate is an http_probe one. The
full pipeline and partial recon share run_subdomain_takeover.
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
ACM_ISSUER = "CN=Amazon RSA 2048 M02,O=Amazon,C=US"


def _run(monkeypatch, *, cname, cert_san, issuer=ACM_ISSUER, subjack_service="",
         resolves=True):
    monkeypatch.setattr(runner, "_run_subjack", lambda subdomains, work_dir, settings: (
        [{"subdomain": HOST, "vulnerable": True, "service": subjack_service}]))
    monkeypatch.setattr(runner, "_run_nuclei_takeover", lambda urls, work_dir, settings: [])
    th.resolve_cname_target.cache_clear()
    monkeypatch.setattr(runner, "resolve_cname_target", lambda c, timeout=3.0: {
        "resolves": resolves, "ips": ("203.0.113.5",) if resolves else (), "nxdomain": False})
    # A customer certificate the AWS edge serves: issued by ACM, naming other
    # names than this host, and no AWS edge domain.
    cert = {"subject_cn": cert_san, "san": [cert_san], "issuer": issuer,
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


def test_the_amazon_issuer_names_the_aws_family():
    assert th.provider_from_cert(ACM_ISSUER, ["www.example.test"]) == "aws"
    assert th.same_provider_family("aws", "aws-cloudfront")
    assert th.same_provider_family("aws", "aws-s3")
    assert "aws" not in th.AUTO_EXPLOITABLE_PROVIDERS


def test_an_acm_certificate_does_not_make_an_unknown_finding_an_s3_one(monkeypatch):
    # An ELB CNAME names no provider in the table, so only the certificate does.
    f = _run(monkeypatch, cname="app-123.us-east-1.elb.amazonaws.com",
             cert_san="www.example.test")
    # The issuer alone names no provider at all (S-27): the finding keeps the
    # tool's placeholder, and the certificate records the AWS family.
    assert f["takeover_provider"] == "unknown", \
        "an ACM certificate named the finding's provider"
    assert f["takeover_provider"] not in th.AUTO_EXPLOITABLE_PROVIDERS
    assert f["cert_provider"] == "aws"
    # Subjack +25, CNAME +10, live CNAME -30 (no auto-exploitable exemption),
    # unknown provider -10, floor 0; no default-cert bonus: an issuer-only ACM
    # certificate is a customer's (S-25).
    assert f["confidence"] == 0
    assert f["verdict"] == "manual_review"
    assert f["id"] == th.finding_id(HOST, "unknown", "cname")


def test_an_acm_certificate_corroborates_a_cloudfront_finding(monkeypatch):
    f = _run(monkeypatch, cname="d111111abcdef8.cloudfront.net", cert_san="www.example.test")
    assert f["takeover_provider"] == "aws-cloudfront"
    assert not f.get("cert_provider_mismatch"), \
        "an AWS certificate on a CloudFront finding was scored as another provider's (-25)"
    assert f["cert_provider"] == "aws"


def test_control_the_s3_edge_certificate_still_names_s3(monkeypatch):
    f = _run(monkeypatch, cname="assets.example.test.s3.amazonaws.com",
             cert_san="*.s3.amazonaws.com", subjack_service="aws/s3")
    assert f["takeover_provider"] == "aws-s3"
    assert f["cert_provider"] == "aws-s3"
    assert not f.get("cert_provider_mismatch")
    assert f["id"] == th.finding_id(HOST, "aws-s3", "cname")


def test_control_an_s3_finding_with_an_acm_certificate_stays_s3(monkeypatch):
    f = _run(monkeypatch, cname="assets.example.test.s3.amazonaws.com",
             cert_san="www.example.test", subjack_service="aws/s3")
    assert f["takeover_provider"] == "aws-s3"
    assert f["cert_provider"] == "aws"
    assert not f.get("cert_provider_mismatch")


def test_control_another_providers_certificate_is_still_a_mismatch(monkeypatch):
    f = _run(monkeypatch, cname="d111111abcdef8.cloudfront.net", cert_san="*.herokuapp.com",
             issuer="Example Edge CA")
    assert f["cert_provider"] == "heroku"
    assert f.get("cert_provider_mismatch") is True
