"""Phase 0.6 (free wins) + Phase 2.3 (CDN attribution).

These recover certificate data the pipeline ALREADY paid for and then threw
away. Each test names the source that was being dropped.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers.target_helpers import collect_certificate_sans, merge_discovered_hostnames
from recon.helpers.cdn_ranges import cdn_from_certificate
from recon.main_recon_modules import tls_scan
from recon.main_recon_modules.shodan_enrich import _normalize_shodan_ssl


# --------------------------------------------------------------------------- #
# 0.6a: httpx SANs were never fed back
# --------------------------------------------------------------------------- #
def test_collect_certificate_sans_reads_the_httpx_certificate():
    """httpx grabs the full SAN list on every HTTPS port and nothing read it."""
    combined = {"http_probe": {"by_url": {"https://acme.test": {
        "tls": {"certificate": {"subject_cn": "acme.test",
                                "san": ["acme.test", "www.acme.test", "*.api.acme.test"]}},
    }}}}
    names = collect_certificate_sans(combined)
    assert "www.acme.test" in names
    assert "acme.test" in names
    assert "*.api.acme.test" in names, "wildcards must reach the scope filter raw"


def test_collect_certificate_sans_merges_both_sources():
    """Phase 1.0: the feedback path must not depend on tlsx being enabled."""
    combined = {
        "http_probe": {"by_url": {"https://a.test": {
            "tls": {"certificate": {"subject_cn": "a.test", "san": ["a.test"]}}}}},
        "tlsx": {"by_target": {"1.2.3.4:993": {"san": ["mail.a.test"]}}},
    }
    names = collect_certificate_sans(combined)
    assert {"a.test", "mail.a.test"} <= set(names)


def test_collect_certificate_sans_is_empty_without_certificates():
    assert collect_certificate_sans({}) == []
    assert collect_certificate_sans({"http_probe": {"by_url": {"https://x": {}}}}) == []


def test_httpx_sans_go_through_the_same_scope_containment():
    """The backfill must not bypass the apex allow-list."""
    combined = {"dns": {"subdomains": {}}, "http_probe": {"by_url": {"https://acme.test": {
        "tls": {"certificate": {"san": ["www.acme.test", "evil.attacker.test"]}}}}}}
    names = collect_certificate_sans(combined)
    with patch("socket.getaddrinfo",
               lambda host, *a, **k: [(2, 1, 6, "", ("93.184.216.34", 0))]):
        merge_discovered_hostnames(combined, names, source="certificate_san",
                                   root_domain="acme.test", settings={}, max_injected=50)
    assert "www.acme.test" in combined["dns"]["subdomains"]
    assert "evil.attacker.test" not in combined["dns"]["subdomains"]


# --------------------------------------------------------------------------- #
# 0.6c: Shodan's ssl block was parsed and discarded
# --------------------------------------------------------------------------- #
def test_shodan_ssl_block_is_normalised_not_dropped():
    out = _normalize_shodan_ssl({
        "cert": {
            "subject": {"CN": "mail.acme.test"},
            "issuer": {"CN": "R3", "O": "Lets Encrypt"},
            "serial": 12345, "expired": False,
            "fingerprint": {"sha256": "aabbcc"},
            "issued": "2026-01-01", "expires": "2027-01-01",
        },
        "jarm": "jarmhash", "ja3s": "ja3shash",
        "cipher": {"name": "TLS_AES_256_GCM_SHA384"},
        "versions": ["TLSv1.2", "TLSv1.3"],
    })
    assert out["subject_cn"] == "mail.acme.test"
    assert out["issuer"] == "R3, Lets Encrypt"
    assert out["serial"] == "12345"
    assert out["fingerprint_sha256"] == "aabbcc"
    assert out["jarm"] == "jarmhash" and out["ja3s"] == "ja3shash"
    assert out["versions"] == ["TLSv1.2", "TLSv1.3"]


def test_shodan_ssl_absent_or_malformed_is_harmless():
    assert _normalize_shodan_ssl(None) == {}
    assert _normalize_shodan_ssl("not a dict") == {}
    assert _normalize_shodan_ssl({}) == {}


def test_shodan_host_lookup_actually_attaches_the_ssl_block_to_the_service():
    """Covers the CALL SITE, not just the normaliser.

    A mutation that deletes `"ssl": _normalize_shodan_ssl(...)` from the host
    parser leaves the normaliser perfectly tested and the data still dropped --
    wiring is what silently breaks, so assert the wiring.
    """
    from recon.main_recon_modules import shodan_enrich

    api_payload = {
        "ip_str": "203.0.113.10", "ports": [8443], "vulns": {},
        "data": [{
            "port": 8443, "transport": "tcp", "product": "nginx",
            "_shodan": {"module": "https"},
            "ssl": {"cert": {"subject": {"CN": "shodan.acme.test"},
                             "issuer": {"CN": "R3"},
                             "fingerprint": {"sha256": "ddeeff"}},
                    "jarm": "shodanjarm"},
        }],
    }

    class _NoWait:
        def wait(self):
            return None

    with patch.object(shodan_enrich, "_shodan_get", return_value=api_payload):
        host = shodan_enrich._lookup_single_ip(
            "203.0.113.10", use_internetdb=False, api_key="k",
            key_rotator=None, rate_limiter=_NoWait())

    assert host, "host lookup returned nothing"
    svc = host["services"][0]
    assert svc["ssl"]["subject_cn"] == "shodan.acme.test"
    assert svc["ssl"]["fingerprint_sha256"] == "ddeeff"
    assert svc["ssl"]["jarm"] == "shodanjarm"


# --------------------------------------------------------------------------- #
# 2.3: CDN attribution from the handshake alone
# --------------------------------------------------------------------------- #
def test_cdn_from_certificate_identifies_an_edge_issuer():
    assert cdn_from_certificate("CN=Cloudflare Inc ECC CA-3, O=Cloudflare, Inc.") == "cloudflare"
    assert cdn_from_certificate(["Akamai Technologies"]) == "akamai"


def test_cdn_from_certificate_does_not_claim_amazon_is_an_edge():
    """ACM issues certs for bare ALB/EC2 origins that DO serve the app, so
    treating an Amazon issuer as CDN edge would suppress real Direct-IP
    findings -- the same reason RELIABLE_EDGE_CDN_NAMES excludes those names."""
    assert cdn_from_certificate("CN=Amazon RSA 2048 M01, O=Amazon") is None
    assert cdn_from_certificate("CN=R3, O=Let's Encrypt") is None
    assert cdn_from_certificate(None) is None


def test_tlsx_fills_cdn_where_the_port_scan_left_it_blank():
    combined = {"port_scan": {
        "by_ip": {"1.2.3.4": {"ip": "1.2.3.4", "ports": [8443], "cdn": None, "is_cdn": False}},
        "by_host": {"acme.test": {"host": "acme.test", "ip": "1.2.3.4", "cdn": None, "is_cdn": False}},
    }}
    by_target = {"1.2.3.4:8443": {"scanned_ip": "1.2.3.4", "probe_status": True,
                                  "issuer_dn": "CN=Cloudflare Inc ECC CA-3"}}
    tls_scan._attribute_cdn(combined, by_target)
    assert combined["port_scan"]["by_ip"]["1.2.3.4"]["cdn"] == "cloudflare"
    assert combined["port_scan"]["by_ip"]["1.2.3.4"]["is_cdn"] is True
    assert combined["port_scan"]["by_host"]["acme.test"]["cdn"] == "cloudflare"


def test_tlsx_never_overwrites_the_port_scans_own_attribution():
    """naabu's own fingerprinting wins; this only fills a blank."""
    combined = {"port_scan": {"by_ip": {
        "1.2.3.4": {"ip": "1.2.3.4", "cdn": "fastly", "is_cdn": True}}, "by_host": {}}}
    by_target = {"1.2.3.4:8443": {"scanned_ip": "1.2.3.4", "probe_status": True,
                                  "issuer_dn": "CN=Cloudflare Inc ECC CA-3"}}
    tls_scan._attribute_cdn(combined, by_target)
    assert combined["port_scan"]["by_ip"]["1.2.3.4"]["cdn"] == "fastly"


def test_a_failed_handshake_attributes_nothing():
    combined = {"port_scan": {"by_ip": {
        "1.2.3.4": {"ip": "1.2.3.4", "cdn": None, "is_cdn": False}}, "by_host": {}}}
    by_target = {"1.2.3.4:8443": {"scanned_ip": "1.2.3.4", "probe_status": False,
                                  "issuer_dn": "CN=Cloudflare Inc ECC CA-3"}}
    assert tls_scan._attribute_cdn(combined, by_target) == 0
    assert combined["port_scan"]["by_ip"]["1.2.3.4"]["cdn"] is None


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))


# --------------------------------------------------------------------------- #
# Pipeline wiring. A helper that is perfectly tested but never CALLED is the
# failure mode this feature kept hitting (the vhost SAN source, Shodan's ssl
# block, httpx's JARM). These assert the call sites exist.
# --------------------------------------------------------------------------- #
def _main_src() -> str:
    return (PROJECT_ROOT / "recon" / "main.py").read_text(encoding="utf-8")


def test_certificate_san_backfill_is_wired_into_the_pipeline():
    src = _main_src()
    assert "collect_certificate_sans" in src, (
        "the httpx SAN backfill helper exists but the pipeline never calls it")
    assert 'source="certificate_san"' in src


def test_the_san_backfill_runs_after_the_http_probe():
    """It must follow GROUP 4 -- httpx has to have grabbed the certificates
    before there are SANs to read -- and precede GROUP 6 so vhost sees them."""
    src = _main_src()
    probe = src.index("GROUP 4 — HTTP Probe")
    backfill = src.index("collect_certificate_sans")
    assert probe < backfill, "the SAN backfill runs before httpx has any certificates"


def test_tlsx_phase_is_wired_into_both_pipeline_modes():
    src = _main_src()
    assert src.count("run_tlsx_enrichment") >= 2, (
        "GROUP 3.6 must be wired in BOTH domain and IP mode")
