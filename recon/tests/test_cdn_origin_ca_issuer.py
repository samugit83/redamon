"""R-40: a Cloudflare Origin CA certificate is the origin's, never an edge's.

Cloudflare's Origin CA issues certificates that customers install on their
ORIGIN servers so the edge can talk TLS to them; the edge never serves one to
the public. Its issuer DN still says "CloudFlare, Inc.", and a plain substring
test on "cloudflare" tagged the origin as a Cloudflare edge: ``IP.is_cdn`` went
true, origin discovery dropped the address as a candidate, OSINT skipped it and
security checks suppressed its direct-IP findings.

The issuer strings below are CA names (Cloudflare's published Origin CA roots
and edge intermediates), not target data. tlsx emits the DN in more than one
shape across versions, so each variant is listed.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers.cdn_ranges import cdn_from_certificate, collect_reliable_edge_ips
from recon.main_recon_modules import tls_scan

ORIGIN_RSA_DN = ("C=US, O=CloudFlare, Inc., OU=CloudFlare Origin SSL Certificate Authority, "
                 "L=San Francisco, ST=California")
ORIGIN_ECC_DN = ("C=US, O=CloudFlare, Inc., OU=CloudFlare Origin SSL ECC Certificate Authority, "
                 "L=San Francisco, ST=California")

ORIGIN_ISSUERS = [
    pytest.param(ORIGIN_RSA_DN, id="rsa-root"),
    pytest.param(ORIGIN_ECC_DN, id="ecc-root"),
    # Go's pkix.Name.String(): RFC 2253 order, escaped comma.
    pytest.param("ST=California,L=San Francisco,OU=CloudFlare Origin SSL Certificate Authority,"
                 "O=CloudFlare\\, Inc.,C=US", id="rsa-rfc2253"),
    pytest.param("ST=California,L=San Francisco,OU=CloudFlare Origin SSL ECC Certificate Authority,"
                 "O=CloudFlare\\, Inc.,C=US", id="ecc-rfc2253"),
    # openssl's one-line form, as a lab-generated look-alike prints it.
    pytest.param("/C=US/O=CloudFlare, Inc./OU=CloudFlare Origin SSL Certificate Authority"
                 "/L=San Francisco/ST=California", id="rsa-openssl-slash"),
    pytest.param("CN=CloudFlare Origin CA, O=CloudFlare, Inc.", id="origin-ca-name"),
    pytest.param(["CloudFlare, Inc.", "CloudFlare Origin SSL ECC Certificate Authority"],
                 id="list-form"),
]

EDGE_ISSUERS = [
    pytest.param("CN=Cloudflare Inc ECC CA-3, O=Cloudflare, Inc., C=US", "cloudflare", id="cf-ecc-ca-3"),
    pytest.param("CN=Cloudflare Inc RSA CA-2, O=Cloudflare, Inc., C=US", "cloudflare", id="cf-rsa-ca-2"),
    # The lab edges' issuers (fp_regression_target .32, ip_hostnames_lab edge).
    pytest.param("/CN=Cloudflare Inc ECC CA-3/O=Cloudflare, Inc./C=US", "cloudflare", id="fp-lab-edge"),
    pytest.param("C=US, O=Cloudflare, Inc., CN=Cloudflare Inc ECC CA-3 (iphn lab)", "cloudflare",
                 id="iphn-lab-edge"),
    pytest.param(["Akamai Technologies, Inc."], "akamai", id="akamai-list"),
]


@pytest.mark.parametrize("issuer", ORIGIN_ISSUERS)
def test_an_origin_ca_issuer_names_no_cdn(issuer):
    assert cdn_from_certificate(issuer) is None


@pytest.mark.parametrize("issuer, cdn", EDGE_ISSUERS)
def test_an_edge_issuer_still_names_its_cdn(issuer, cdn):
    assert cdn_from_certificate(issuer) == cdn


# --------------------------------------------------------------------------- #
# Through the real tlsx phase: the mocked binary returns one origin and one
# edge certificate, as tlsx's JSON carries them (the Origin CA root has no CN).
# --------------------------------------------------------------------------- #
ORIGIN_IP = "192.0.2.40"
EDGE_IP = "192.0.2.41"


def _tlsx_line(ip, issuer_dn, issuer_cn, issuer_org):
    row = {
        "host": ip, "ip": ip, "port": "443", "probe_status": True,
        "subject_cn": "www.example.com", "subject_an": ["www.example.com"],
        "issuer_dn": issuer_dn, "issuer_org": issuer_org,
        "fingerprint_hash": {"sha256": ip.replace(".", "") * 4},
        "not_after": "2099-01-01T00:00:00Z",
    }
    if issuer_cn:
        row["issuer_cn"] = issuer_cn
    return row


def _run_tlsx():
    by_ip = {ip: {"ip": ip, "ports": [443], "cdn": None, "is_cdn": False}
             for ip in (ORIGIN_IP, EDGE_IP)}
    combined = {"port_scan": {"by_ip": by_ip, "by_host": {
        "www.example.com": {"host": "www.example.com", "ip": ORIGIN_IP, "cdn": None, "is_cdn": False}}}}
    stdout = "\n".join(json.dumps(x) for x in (
        _tlsx_line(ORIGIN_IP, ORIGIN_RSA_DN, None, ["CloudFlare, Inc."]),
        _tlsx_line(EDGE_IP, "CN=Cloudflare Inc ECC CA-3, O=Cloudflare, Inc., C=US",
                   "Cloudflare Inc ECC CA-3", ["Cloudflare, Inc."]),
    ))
    meta = {f"{ip}:443": ip for ip in (ORIGIN_IP, EDGE_IP)}
    proc = MagicMock(returncode=0)
    proc.communicate.return_value = (stdout, "")
    with patch.object(tls_scan, "_build_tlsx_targets", return_value=(list(meta), meta)), \
         patch("subprocess.Popen", return_value=proc):
        tls_scan.run_tlsx_enrichment(combined, {})
    return combined


def test_tlsx_leaves_an_origin_ca_host_untagged():
    out = _run_tlsx()
    origin = out["port_scan"]["by_ip"][ORIGIN_IP]
    assert (origin["is_cdn"], origin["cdn"]) == (False, None)
    assert "cdn_source" not in origin
    assert out["port_scan"]["by_host"]["www.example.com"]["is_cdn"] is False
    # cdn_by_ip is what the tlsx graph writer turns into IP.is_cdn.
    assert out["tlsx"]["cdn_by_ip"] == {EDGE_IP: "cloudflare"}


def test_the_origin_stays_out_of_the_edge_set_security_checks_suppress():
    assert collect_reliable_edge_ips(_run_tlsx()) == {EDGE_IP}
