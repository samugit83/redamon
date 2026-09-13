"""tlsx module: command built + JSONL parsed + target selection + never-raise.

Asserts BOTH directions (recon-tool-integration): the docker argv we build and
the parsed result from a mocked subprocess, including the field-name traps the
plan repeatedly got wrong.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.main_recon_modules import tls_scan


# --------------------------------------------------------------------------- #
# Command built
# --------------------------------------------------------------------------- #
def _cmd(settings=None):
    return tls_scan.build_tlsx_command("/tmp/redamon/x/tlsx_targets.txt",
                                       "/tmp/redamon/x", settings or {})


def test_base_flags_present_exactly_once():
    cmd = _cmd()
    for flag in ("-json", "-silent", "-duc", "-tps", "-se"):
        assert cmd.count(flag) == 1, flag
    assert cmd.count("-hash") == 1 and "sha256" in cmd
    assert "projectdiscovery/tlsx:latest" in cmd


def test_never_emits_output_filters():
    # -ex/-ss/-mm/-re/-un RESTRICT output to matching hosts; passing one would
    # silently drop every healthy host and no other test would catch it.
    cmd = _cmd({"TLSX_PROBE_JARM": True, "TLSX_VERSION_ENUM": True, "TLSX_CIPHER_ENUM": True})
    for bad in ("-ex", "-ss", "-mm", "-re", "-un", "-expired", "-self-signed"):
        assert bad not in cmd, bad


def test_loud_probes_are_flag_gated():
    assert "-jarm" not in _cmd()
    assert "-ve" not in _cmd()
    assert "-ce" not in _cmd()
    jarm = _cmd({"TLSX_PROBE_JARM": True})
    assert jarm.count("-jarm") == 1 and jarm.count("-ja3") == 1
    ve = _cmd({"TLSX_VERSION_ENUM": True})
    assert ve.count("-ve") == 1
    ce = _cmd({"TLSX_CIPHER_ENUM": True})
    assert ce.count("-ce") == 1 and "weak" in ce


# --------------------------------------------------------------------------- #
# Target selection
# --------------------------------------------------------------------------- #
def _combined(by_ip):
    return {"port_scan": {"by_ip": by_ip}, "metadata": {}}


def test_http_ports_excluded_by_default_non_http_kept():
    c = _combined({"93.184.216.34": {"ip": "93.184.216.34", "hostnames": [], "ports": [443, 993, 80]}})
    lines, meta = tls_scan._build_tlsx_targets(c, {})
    assert "93.184.216.34:993" in lines
    assert "93.184.216.34:443" not in lines
    assert "93.184.216.34:80" not in lines


def test_include_http_ports_when_enabled():
    c = _combined({"93.184.216.34": {"ip": "93.184.216.34", "hostnames": [], "ports": [443, 993]}})
    lines, _ = tls_scan._build_tlsx_targets(c, {"TLSX_INCLUDE_HTTP_PORTS": True})
    assert "93.184.216.34:443" in lines and "93.184.216.34:993" in lines


def test_sni_rule_hostname_emitted_but_keyed_on_ip():
    c = _combined({"93.184.216.34": {"ip": "93.184.216.34",
                                     "hostnames": ["mail.acme.com", "alt.acme.com"], "ports": [993]}})
    lines, meta = tls_scan._build_tlsx_targets(c, {"TLSX_MAX_HOSTNAMES_PER_IP": 1})
    # deterministic: sorted hostnames -> "alt.acme.com" first
    assert lines == ["alt.acme.com:993"]
    assert meta["alt.acme.com:993"] == "93.184.216.34"


def test_bare_ip_when_no_hostname():
    c = _combined({"93.184.216.34": {"ip": "93.184.216.34", "hostnames": [], "ports": [993]}})
    lines, meta = tls_scan._build_tlsx_targets(c, {})
    assert lines == ["93.184.216.34:993"]
    assert meta["93.184.216.34:993"] == "93.184.216.34"


def test_non_routable_ip_never_targeted():
    c = _combined({"10.0.0.5": {"ip": "10.0.0.5", "hostnames": [], "ports": [993]}})
    lines, _ = tls_scan._build_tlsx_targets(c, {})
    assert lines == []


def test_roe_excluded_ip_never_targeted():
    c = _combined({"93.184.216.34": {"ip": "93.184.216.34", "hostnames": [], "ports": [993]}})
    lines, _ = tls_scan._build_tlsx_targets(
        c, {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": ["93.184.216.34"]})
    assert lines == []


# --------------------------------------------------------------------------- #
# Parsing (the field-name traps)
# --------------------------------------------------------------------------- #
_LINE = {
    "host": "mail.acme.com", "ip": "203.0.113.5", "port": "993",  # port is a STRING
    "probe_status": True, "tls_version": "tls12", "cipher": "TLS_AES_256_GCM_SHA384",
    "tls_connection": "ctls", "sni": "mail.acme.com",
    "subject_cn": "mail.acme.com", "subject_dn": "CN=mail.acme.com",
    "subject_org": ["Acme"], "subject_an": ["mail.acme.com", "*.acme.com"],
    "issuer_cn": "R3", "issuer_dn": "CN=R3, O=LE", "issuer_org": ["Let's Encrypt"],
    "serial": "01AB", "not_before": "2026-01-01T00:00:00Z", "not_after": "2099-01-01T00:00:00Z",
    "wildcard_certificate": True,
    "fingerprint_hash": {"md5": "x", "sha1": "y", "sha256": "AABBCC"},
    "jarm_hash": "jarmval", "ja3_hash": "ja3val", "ja3s_hash": "ja3sval",
}


def _parse(line, meta=None):
    return tls_scan._parse_tlsx_output(json.dumps(line), meta or {"mail.acme.com:993": "203.0.113.5"})


def test_parse_field_name_traps():
    bt = _parse(_LINE)
    e = bt["203.0.113.5:993"]        # keyed on scanned ip:port, not returned ip
    assert e["port"] == 993 and isinstance(e["port"], int)   # coerced from string
    assert e["san"] == ["mail.acme.com", "acme.com"]         # subject_an -> san, wildcard stripped
    assert e["fingerprint_sha256"] == "AABBCC"               # nested fingerprint_hash.sha256
    assert e["jarm"] == "jarmval" and e["ja3s"] == "ja3sval" # *_hash -> jarm/ja3s
    assert e["wildcard"] is True                             # wildcard_certificate -> wildcard
    assert e["issuer_org"] == ["Let's Encrypt"]              # list


def test_derived_expired_from_not_after():
    line = dict(_LINE, not_after="2000-01-01T00:00:00Z")
    e = _parse(line)["203.0.113.5:993"]
    assert e["expired"] is True


def test_derived_self_signed_when_subject_equals_issuer():
    line = dict(_LINE, subject_dn="CN=self", issuer_dn="CN=self")
    e = _parse(line)["203.0.113.5:993"]
    assert e["self_signed"] is True


def test_derived_mismatch_when_host_not_in_names():
    line = dict(_LINE, host="other.example.org", subject_cn="mail.acme.com",
                subject_an=["mail.acme.com"])
    e = tls_scan._parse_tlsx_output(json.dumps(line), {"other.example.org:993": "203.0.113.5"})
    assert e["203.0.113.5:993"]["mismatched"] is True


def test_probe_status_false_is_recorded_not_dropped():
    line = {"host": "1.2.3.4", "ip": "1.2.3.4", "port": "990", "probe_status": False, "error": "no tls"}
    e = tls_scan._parse_tlsx_output(json.dumps(line), {"1.2.3.4:990": "1.2.3.4"})
    assert "1.2.3.4:990" in e
    assert e["1.2.3.4:990"]["probe_status"] is False


def test_malformed_line_skipped_without_sinking_others():
    good = json.dumps(_LINE)
    out = "not json\n" + good + "\n{bad json"
    bt = tls_scan._parse_tlsx_output(out, {"mail.acme.com:993": "203.0.113.5"})
    assert "203.0.113.5:993" in bt


# --------------------------------------------------------------------------- #
# Never raises
# --------------------------------------------------------------------------- #
def test_module_never_raises_when_runner_missing():
    c = _combined({"93.184.216.34": {"ip": "93.184.216.34", "hostnames": [], "ports": [993]}})
    with patch("subprocess.Popen", side_effect=FileNotFoundError("no docker")):
        out = tls_scan.run_tlsx_enrichment(c, {})
    assert "tlsx" in out  # a payload exists; the phase did not raise


def test_no_eligible_targets_is_graceful():
    c = _combined({"10.0.0.5": {"ip": "10.0.0.5", "hostnames": [], "ports": [993]}})
    out = tls_scan.run_tlsx_enrichment(c, {})
    assert out["tlsx"]["summary"]["targets"] == 0


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
