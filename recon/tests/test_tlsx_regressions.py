"""Named regressions for the defects found reviewing the tlsx feature.

One test per bug, named after it, so a revert cannot come back silently.
F1 (tls_service_hint never written to the graph) is owned by the live test
tests/test_tlsx_graph_live.py, which needs a real Neo4j to be meaningful.
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

from recon.main_recon_modules import tls_scan
from recon.helpers.target_helpers import merge_discovered_hostnames
from recon.helpers.cert_access import get_cert_for


# --------------------------------------------------------------------------- #
# F2: unbounded blocking DNS on the pipeline's critical path
# --------------------------------------------------------------------------- #
def test_regression_f2_dns_resolution_is_bounded_by_the_injection_cap():
    """Resolution used to run over EVERY in-scope SAN before the cap applied.

    Each one is a blocking getaddrinfo, and this runs in GROUP 3.6 ahead of the
    HTTP probe, so a scan that collected a few hundred SAN names could stall the
    whole pipeline on DNS timeouts. The cap must bound the lookups, not just the
    merge.
    """
    calls = []

    def counting_getaddrinfo(host, *a, **k):
        calls.append(host)
        return [(2, 1, 6, "", ("93.184.216.34", 0))]

    names = [f"h{i}.example.com" for i in range(200)]
    combined = {"dns": {"subdomains": {}}}
    with patch("socket.getaddrinfo", counting_getaddrinfo):
        merge_discovered_hostnames(combined, names, source="tlsx",
                                   root_domain="example.com", settings={}, max_injected=5)

    assert len(calls) <= 5, (
        f"resolved {len(calls)} names for a cap of 5: DNS work is unbounded")
    assert len(combined["dns"]["subdomains"]) <= 5


# --------------------------------------------------------------------------- #
# F3: a second certificate on one ip:port was silently discarded
# --------------------------------------------------------------------------- #
def _line(host, port, fp, cn):
    return json.dumps({
        "host": host, "ip": "1.2.3.4", "port": str(port), "probe_status": True,
        "subject_cn": cn, "subject_an": [cn], "fingerprint_hash": {"sha256": fp},
    })


def test_regression_f3_second_certificate_on_one_ip_port_is_not_overwritten():
    """TLSX_MAX_HOSTNAMES_PER_IP > 1 exists so an operator can map a vhost
    frontend that presents a DIFFERENT cert per SNI. by_target was keyed on
    ip:port alone, so every cert but the last was dropped -- the setting cost
    extra handshakes and returned nothing extra.
    """
    meta = {"a.example.com:443": "1.2.3.4", "b.example.com:443": "1.2.3.4"}
    out = tls_scan._parse_tlsx_output(
        _line("a.example.com", 443, "aaa", "a.example.com") + "\n"
        + _line("b.example.com", 443, "bbb", "b.example.com"), meta)

    fingerprints = {e["fingerprint_sha256"] for e in out.values()}
    assert fingerprints == {"aaa", "bbb"}, f"a certificate was lost: {out.keys()}"
    # the canonical ip:port key still resolves, so Service MATCH / get_cert_for work
    assert "1.2.3.4:443" in out


def test_regression_f3_the_same_certificate_reobserved_does_not_duplicate():
    """The flip side: one cert seen twice must stay one entry."""
    meta = {"a.example.com:443": "1.2.3.4", "b.example.com:443": "1.2.3.4"}
    out = tls_scan._parse_tlsx_output(
        _line("a.example.com", 443, "same", "a.example.com") + "\n"
        + _line("b.example.com", 443, "same", "a.example.com"), meta)
    assert len(out) == 1


# --------------------------------------------------------------------------- #
# F5: get_cert_for matched the wrong port / a foreign host
# --------------------------------------------------------------------------- #
def test_regression_f5_get_cert_for_does_not_return_another_ports_certificate():
    """Takeover scoring asks for the 443 cert. Returning the 8443 cert let an
    unrelated service's certificate demote (or promote) a takeover finding."""
    combined = {"http_probe": {"by_url": {
        "https://acme.com:8443": {
            "host": "acme.com",
            "tls": {"certificate": {"subject_cn": "wrong.acme.com", "san": ["wrong.acme.com"]}},
        },
    }}}
    assert get_cert_for(combined, "acme.com", 443) is None


def test_regression_f5_get_cert_for_does_not_substring_match_a_foreign_host():
    """`f"//{host}" in url` also matched "//acme.com.evil.com", attributing an
    attacker-controlled host's certificate to the host under test."""
    combined = {"http_probe": {"by_url": {
        "https://acme.com.evil.com": {
            "host": "acme.com.evil.com",
            "tls": {"certificate": {"subject_cn": "evil", "san": ["acme.com.evil.com"]}},
        },
    }}}
    assert get_cert_for(combined, "acme.com", 443) is None


def test_get_cert_for_still_returns_the_right_certificate_on_the_right_port():
    """Control: the narrowing must not break the normal case."""
    combined = {"http_probe": {"by_url": {
        "https://acme.com": {
            "host": "acme.com",
            "tls": {"certificate": {"subject_cn": "acme.com", "san": ["acme.com"]}},
        },
    }}}
    cert = get_cert_for(combined, "acme.com", 443)
    assert cert and cert["subject_cn"] == "acme.com"


# --------------------------------------------------------------------------- #
# F6: IPv6 targets were emitted unbracketed
# --------------------------------------------------------------------------- #
def test_regression_f6_ipv6_targets_are_bracketed():
    """"2001:db8::1:993" is ambiguous -- is the last group a port or an address
    group? tlsx cannot parse it, so every IPv6 host was silently skipped."""
    assert tls_scan._target_line("2001:db8::1", 993) == "[2001:db8::1]:993"


def test_ipv4_targets_are_not_bracketed():
    assert tls_scan._target_line("203.0.113.5", 993) == "203.0.113.5:993"


def test_hostnames_are_not_bracketed():
    assert tls_scan._target_line("mail.example.com", 993) == "mail.example.com:993"


def test_an_already_bracketed_address_is_not_double_bracketed():
    assert tls_scan._target_line("[2001:db8::1]", 993) == "[2001:db8::1]:993"


def test_a_routable_ipv6_reaches_the_target_file_bracketed():
    """End to end through _build_tlsx_targets. Routability is patched off so the
    assertion is about the target FORMAT, not about which ranges are global."""
    combined = {"port_scan": {"by_ip": {
        "2001:db8::1": {"ip": "2001:db8::1", "hostnames": [], "ports": [993]},
    }}, "metadata": {}}
    with patch("recon.main_recon_modules.ip_filter.is_non_routable_ip", return_value=False):
        lines, meta = tls_scan._build_tlsx_targets(combined, {})
    assert lines == ["[2001:db8::1]:993"], lines
    # meta stays unbracketed: tlsx echoes `host` without brackets.
    assert meta["2001:db8::1:993"] == "2001:db8::1"


def test_non_routable_ipv6_is_still_filtered_out():
    """The bracketing must not have weakened the SSRF/scope filter."""
    combined = {"port_scan": {"by_ip": {
        "2001:db8::1": {"ip": "2001:db8::1", "hostnames": [], "ports": [993]},
        "fe80::1": {"ip": "fe80::1", "hostnames": [], "ports": [993]},
    }}, "metadata": {}}
    lines, _ = tls_scan._build_tlsx_targets(combined, {})
    assert lines == []


# --------------------------------------------------------------------------- #
# F4: partial recon lost the operator's manually-entered IPs
# --------------------------------------------------------------------------- #
def test_regression_f4_partial_recon_records_the_operator_ips_on_the_user_input_node():
    """create_user_input_node reads input_type/values/tool_id. The call passed
    id/tool/ips/ports, so .get() defaults won and the node was written with
    values=[] -- the operator's IPs vanished from the graph with no error."""
    from recon.partial_recon_modules import tlsx_scanning

    client = MagicMock()
    client.verify_connection.return_value = True
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)

    fake_graph_db = MagicMock()
    fake_graph_db.Neo4jClient.return_value = client

    with patch.dict(sys.modules, {"graph_db": fake_graph_db}), \
         patch("recon.project_settings.get_settings", return_value={}), \
         patch("recon.main_recon_modules.tls_scan.run_tlsx_enrichment",
               side_effect=lambda rd, settings=None: rd):
        tlsx_scanning.run_tlsx({
            "domain": "acme.test",
            "include_graph_targets": False,
            "user_targets": {"ips": ["203.0.113.9"], "ports": [993]},
        })

    client.create_user_input_node.assert_called_once()
    payload = client.create_user_input_node.call_args.kwargs["user_input_data"]
    assert payload["values"] == ["203.0.113.9"], payload
    assert payload["input_type"] == "ips"
    assert payload["tool_id"] == "Tlsx"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
