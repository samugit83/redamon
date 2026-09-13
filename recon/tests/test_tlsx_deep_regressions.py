"""Second-pass regressions: defects a deeper review of the tlsx feature found.

Named after the bug, one per defect, so a revert cannot come back silently.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers import security_checks as sc
from recon.main_recon_modules.tls_scan import _build_tlsx_targets

_ALL_ON = {k: True for k in (
    "tls_expired", "tls_self_signed", "tls_hostname_mismatch",
    "tls_weak_version", "tls_weak_cipher", "tls_wildcard_overbroad")}


def _httpx_only(cert, version="tls13", cipher="TLS_AES_256_GCM_SHA384",
                url="https://mail.acme.test"):
    """recon_data with an httpx certificate and NO tlsx block at all."""
    return {"http_probe": {"by_url": {url: {
        "host": "mail.acme.test", "ip": "203.0.113.5",
        "tls": {"version": version, "cipher": cipher, "certificate": cert},
    }}}}


# --------------------------------------------------------------------------- #
# G1: the hygiene checks were effectively gated on TLSX_ENABLED
# --------------------------------------------------------------------------- #
def test_regression_g1_hygiene_checks_work_from_httpx_certs_with_tlsx_off():
    """Phase 1.0's core rule: gate the consumers on cert-data AVAILABILITY, not
    on the tool. run_tls_data_checks read only recon_data["tlsx"], so every
    passive preset (which sets tlsxEnabled:false) silently lost FIVE of the six
    TLS hygiene finding types even though httpx had already captured the 443
    certificate with its issuer, validity, SAN, cipher and version.
    """
    recon = _httpx_only({
        "subject_cn": "other.example.org", "issuer": ["Lets Encrypt"],
        "not_after": "2000-01-01T00:00:00Z",      # long expired
        "san": ["other.example.org"],             # does not name mail.acme.test
    }, version="tls10", cipher="TLS_RSA_WITH_RC4_128_SHA")

    types = {f["type"] for f in sc.run_tls_data_checks(recon, _ALL_ON)}
    assert "tls_expired" in types, "expired httpx cert produced no finding"
    assert "tls_hostname_mismatch" in types
    assert "tls_weak_version" in types
    assert "tls_weak_cipher" in types


def test_g1_a_healthy_httpx_certificate_produces_no_findings():
    """Control: the widened source must not invent findings."""
    recon = _httpx_only({
        "subject_cn": "mail.acme.test", "issuer": ["Lets Encrypt"],
        "not_after": "2099-01-01T00:00:00Z", "san": ["mail.acme.test"],
    })
    assert sc.run_tls_data_checks(recon, _ALL_ON) == []


def test_g1_overbroad_wildcard_is_derivable_from_an_httpx_certificate():
    recon = _httpx_only({
        "subject_cn": "*.acme.test", "issuer": ["LE"],
        "not_after": "2099-01-01T00:00:00Z",
        "san": ["*.acme.test"] + [f"h{i}.acme.test" for i in range(30)],
    }, url="https://h1.acme.test")
    types = {f["type"] for f in sc.run_tls_data_checks(recon, _ALL_ON)}
    assert "tls_wildcard_overbroad" in types


def test_g1_self_signed_is_not_guessed_from_httpx_data():
    """httpx exposes no subject_dn/issuer_dn, so self_signed is UNKNOWN. An
    unknown must not become a finding -- guessing it would be a false positive
    on every cert whose issuer string happens to resemble its subject."""
    recon = _httpx_only({
        "subject_cn": "mail.acme.test", "issuer": ["mail.acme.test"],
        "not_after": "2099-01-01T00:00:00Z", "san": ["mail.acme.test"],
    })
    types = {f["type"] for f in sc.run_tls_data_checks(recon, _ALL_ON)}
    assert "tls_self_signed" not in types


def test_g1_tlsx_data_still_takes_precedence_when_both_exist():
    """tlsx carries real verdict booleans; httpx only has derivable ones. When
    both describe the same target the richer source must win, not duplicate."""
    recon = _httpx_only({
        "subject_cn": "mail.acme.test", "issuer": ["LE"],
        "not_after": "2099-01-01T00:00:00Z", "san": ["mail.acme.test"],
    })
    recon["tlsx"] = {"by_target": {"203.0.113.5:443": {
        "host": "mail.acme.test", "scanned_ip": "203.0.113.5", "ip": "203.0.113.5",
        "port": 443, "probe_status": True, "self_signed": True,
        "subject_cn": "mail.acme.test", "san": ["mail.acme.test"],
        "tls_version": "tls13", "cipher": "TLS_AES_256_GCM_SHA384",
    }}}
    findings = sc.run_tls_data_checks(recon, _ALL_ON)
    assert [f["type"] for f in findings].count("tls_self_signed") == 1


# --------------------------------------------------------------------------- #
# G2: one exposure reported twice
# --------------------------------------------------------------------------- #
def test_regression_g2_a_hostname_target_does_not_carry_a_competing_matched_ip():
    """vuln_mixin keys the node on (type, url, matched_ip or hostname). The
    network TLS check emits hostname only; this one emitted BOTH, so
    matched_ip won and the same expired certificate on :443 became TWO
    Vulnerability nodes once TLSX_INCLUDE_HTTP_PORTS was enabled.

    The graph linkage is driven by the URL host, not by matched_ip, so dropping
    it for hostname targets loses nothing and lets the ids converge.
    """
    recon = {"tlsx": {"by_target": {"203.0.113.5:443": {
        "host": "mail.acme.test", "scanned_ip": "203.0.113.5", "ip": "203.0.113.5",
        "port": 443, "probe_status": True, "expired": True,
        "subject_cn": "mail.acme.test", "san": ["mail.acme.test"],
    }}}}
    f = sc.run_tls_data_checks(recon, _ALL_ON)[0]
    assert f["hostname"] == "mail.acme.test"
    assert not f.get("matched_ip"), (
        "a hostname target must not also set matched_ip, or the node id "
        "diverges from the network check's and the finding duplicates")


def test_g2_a_bare_ip_target_still_carries_matched_ip():
    """Control: an IP target has no hostname, so matched_ip is the only anchor."""
    recon = {"tlsx": {"by_target": {"203.0.113.5:993": {
        "host": "203.0.113.5", "scanned_ip": "203.0.113.5", "ip": "203.0.113.5",
        "port": 993, "probe_status": True, "expired": True,
        "subject_cn": "mail.acme.test", "san": ["mail.acme.test"],
    }}}}
    f = sc.run_tls_data_checks(recon, _ALL_ON)[0]
    assert f["matched_ip"] == "203.0.113.5"
    assert not f.get("hostname")


# --------------------------------------------------------------------------- #
# G5: "scan nothing" did not mean nothing
# --------------------------------------------------------------------------- #
def test_regression_g5_max_targets_zero_scans_nothing():
    """The cap was tested after appending, so 0 still emitted one handshake."""
    combined = {"port_scan": {"by_ip": {
        "93.184.216.34": {"ip": "93.184.216.34", "hostnames": [], "ports": [993, 995]},
    }}, "metadata": {}}
    lines, _ = _build_tlsx_targets(combined, {"TLSX_MAX_TARGETS": 0})
    assert lines == []


def test_g5_max_targets_one_still_scans_exactly_one():
    combined = {"port_scan": {"by_ip": {
        "93.184.216.34": {"ip": "93.184.216.34", "hostnames": [], "ports": [993, 995]},
    }}, "metadata": {}}
    lines, _ = _build_tlsx_targets(combined, {"TLSX_MAX_TARGETS": 1})
    assert len(lines) == 1


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
