"""Phase 3: certificate-derived takeover signals + get_cert_for accessor.

Hermetic: exercises the pure helpers (provider_from_cert, score_finding, the
cert scoring rules) and the get_cert_for merge, no network.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers.takeover_helpers import provider_from_cert, score_finding
from recon.helpers.cert_access import get_cert_for


# --------------------------------------------------------------------------- #
# provider_from_cert (third, CNAME-independent provider signal)
# --------------------------------------------------------------------------- #
def test_provider_from_cert_by_san_suffix():
    assert provider_from_cert(None, ["foo.github.io"]) == "github-pages"


def test_provider_from_cert_by_issuer_marker():
    assert provider_from_cert("Cloudflare Inc ECC CA-3", []) == "cloudflare"


def test_provider_from_cert_none_when_unknown():
    assert provider_from_cert("Some Internal CA", ["host.customer.com"]) is None


# --------------------------------------------------------------------------- #
# Scoring rules
# --------------------------------------------------------------------------- #
def _score(**finding):
    return score_finding(dict(finding), confidence_threshold=60)["confidence"]


def test_clean_cert_name_match_demotes_by_35_even_for_auto_exploitable():
    base = {"sources": ["subjack", "nuclei_takeover"], "takeover_provider": "github-pages",
            "takeover_method": "cname"}
    without = _score(**base)
    with_match = _score(**base, cert_name_match=True)
    assert without - with_match == 35


def test_cert_name_match_ignored_when_cert_is_dirty():
    base = {"sources": ["subjack"], "takeover_method": "cname"}
    assert _score(**base, cert_name_match=True, cert_expired=True) == _score(**base)


def test_cert_provider_mismatch_subtracts_25():
    base = {"sources": ["subjack"], "takeover_method": "cname"}
    assert _score(**base) - _score(**base, cert_provider_mismatch=True) == 25


def test_cert_absent_adds_10_and_default_adds_20():
    base = {"sources": ["subjack"], "takeover_method": "cname"}
    assert _score(**base, cert_absent=True) - _score(**base) == 10
    assert _score(**base, cert_provider_default=True) - _score(**base) == 20


# --------------------------------------------------------------------------- #
# get_cert_for merge
# --------------------------------------------------------------------------- #
def test_get_cert_for_prefers_tlsx():
    combined = {"tlsx": {"by_target": {"1.2.3.4:443": {
        "port": 443, "scanned_ip": "1.2.3.4", "host": "a.com",
        "subject_cn": "a.com", "san": ["a.com"], "probe_status": True,
        "expired": False, "self_signed": False, "mismatched": False}}}}
    cert = get_cert_for(combined, "1.2.3.4", 443)
    assert cert and cert["source"] == "tlsx" and cert["subject_cn"] == "a.com"


def test_get_cert_for_falls_back_to_httpx():
    combined = {"http_probe": {"by_url": {"https://a.com": {
        "host": "a.com", "ip": "1.2.3.4",
        "tls": {"certificate": {"subject_cn": "a.com", "san": ["a.com"],
                                "not_after": "2099-01-01T00:00:00Z"}}}}}}
    cert = get_cert_for(combined, "a.com", 443)
    assert cert and cert["source"] == "http_probe" and cert["expired"] is False


def test_get_cert_for_returns_failed_probe_for_cert_absent_signal():
    combined = {"tlsx": {"by_target": {"1.2.3.4:443": {
        "port": 443, "scanned_ip": "1.2.3.4", "probe_status": False, "error": "no tls"}}}}
    cert = get_cert_for(combined, "1.2.3.4", 443)
    assert cert is not None and cert["probe_status"] is False


def test_get_cert_for_none_when_nothing():
    assert get_cert_for({}, "a.com", 443) is None


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
