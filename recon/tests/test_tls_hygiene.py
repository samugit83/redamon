"""Phase 5 TLS hygiene: the already-expired fix + tlsx-data-derived checks.

Hermetic: run_tls_data_checks reads certificate data already in memory (no
network), and the 5.1 test mocks the SSL fetch.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers import security_checks as sc


# --------------------------------------------------------------------------- #
# 5.1 already-expired bug fix (previously produced ZERO findings)
# --------------------------------------------------------------------------- #
def test_already_expired_cert_now_produces_a_high_finding():
    with patch.object(sc, "get_ssl_certificate",
                      return_value={"cert": {"notAfter": "Jan  1 00:00:00 2000 GMT"}}):
        result = sc.check_tls_expiring_soon("expired.example.com")
    assert result is not None
    assert result["type"] == "tls_expired"
    assert result["severity"] == "high"


def test_valid_cert_expiring_soon_still_low():
    from datetime import datetime, timedelta
    soon = (datetime.utcnow() + timedelta(days=5)).strftime("%b %d %H:%M:%S %Y GMT")
    with patch.object(sc, "get_ssl_certificate", return_value={"cert": {"notAfter": soon}}):
        result = sc.check_tls_expiring_soon("soon.example.com", days_threshold=30)
    assert result is not None and result["type"] == "tls_expiring_soon"
    assert result["severity"] == "low"


# --------------------------------------------------------------------------- #
# 5.2 tlsx-data-derived checks
# --------------------------------------------------------------------------- #
def _recon(entry):
    return {"tlsx": {"by_target": {"1.2.3.4:993": {**{"probe_status": True,
            "scanned_ip": "1.2.3.4", "host": "mail.acme.com", "port": 993}, **entry}}}}


_ALL_ON = {k: True for k in (
    "tls_expired", "tls_self_signed", "tls_hostname_mismatch",
    "tls_weak_version", "tls_weak_cipher", "tls_wildcard_overbroad")}


def _types(entry, enabled=None):
    return {f["type"] for f in sc.run_tls_data_checks(_recon(entry), enabled or _ALL_ON)}


def test_expired_flag_emits_high():
    fs = sc.run_tls_data_checks(_recon({"expired": True}), _ALL_ON)
    assert any(f["type"] == "tls_expired" and f["severity"] == "high" for f in fs)


def test_self_signed_and_mismatch():
    assert "tls_self_signed" in _types({"self_signed": True})
    assert "tls_hostname_mismatch" in _types({"mismatched": True})


def test_weak_version_token_matched_not_pretty_name():
    assert "tls_weak_version" in _types({"tls_version": "tls10"})
    assert "tls_weak_version" not in _types({"tls_version": "tls13"})


def test_weak_cipher_deny_list():
    assert "tls_weak_cipher" in _types({"cipher": "TLS_RSA_WITH_RC4_128_SHA"})
    assert "tls_weak_cipher" not in _types({"cipher": "TLS_AES_256_GCM_SHA384"})


def test_wildcard_overbroad_needs_threshold():
    san = [f"h{i}.acme.com" for i in range(25)]
    assert "tls_wildcard_overbroad" in _types({"wildcard": True, "san": san})
    assert "tls_wildcard_overbroad" not in _types({"wildcard": True, "san": ["a.acme.com"]})


def test_enum_supported_checks_are_flag_gated_data():
    assert "tls_weak_version_supported" in _types({"version_enum": ["tls10", "tls13"]})
    # H3: the shape below is tlsx's real `-ce -ct weak` output. This assertion
    # used to pass `[{"x": 1}]` -- a shape tlsx never emits -- and so enshrined
    # the bug that any enumerable server was reported as supporting weak
    # ciphers. See recon/tests/test_tls_enum_checks.py for the captured output.
    assert "tls_weak_cipher_supported" in _types(
        {"cipher_enum": [{"version": "tls10",
                          "ciphers": {"insecure": ["TLS_RSA_WITH_RC4_128_SHA"]}}]})
    assert "tls_weak_cipher_supported" not in _types(
        {"cipher_enum": [{"version": "tls12", "ciphers": {}}]})
    # no enum data -> no supported findings
    assert "tls_weak_version_supported" not in _types({"tls_version": "tls13"})


def test_probe_failure_produces_no_findings():
    recon = {"tlsx": {"by_target": {"1.2.3.4:993": {"probe_status": False, "error": "x"}}}}
    assert sc.run_tls_data_checks(recon, _ALL_ON) == []


def test_toggle_off_suppresses_only_that_check():
    enabled = {**_ALL_ON, "tls_self_signed": False}
    types = _types({"self_signed": True, "expired": True}, enabled)
    assert "tls_self_signed" not in types
    assert "tls_expired" in types


def test_findings_carry_vuln_mixin_required_shape():
    fs = sc.run_tls_data_checks(_recon({"expired": True}), _ALL_ON)
    f = fs[0]
    for req in ("type", "severity", "name", "description", "url"):
        assert req in f
    assert f.get("hostname") or f.get("matched_ip")


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
