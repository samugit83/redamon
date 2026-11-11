"""A Shodan CVE is checked against this run's port scan (plan 04.2).

Shodan runs beside the port scan and nobody compared a CVE's port with what the
scan found, so a CVE on a port that is closed today still looked live. Now each
CVE carries `port_confirmed`:

  - the scan covered that IP and port and found it open  -> True;
  - it covered them and did not find the port open        -> False;
  - it did not cover them (port outside the scanned list,
    IP not scanned, a top-N list we cannot know, passive
    mode, a UDP service, no port scan at all)             -> None (unknown).

Partial recon has no port scan: it reads the graph's active open Ports, and a
port with none stays unknown, never closed. No traffic, no Neo4j.
"""
from __future__ import annotations

import inspect
import sys
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers import port_coverage as pc  # noqa: E402
from recon.main_recon_modules import shodan_enrich as se  # noqa: E402

IP, OTHER = "198.51.100.30", "198.51.100.31"


def _combined(ports_config="22,80,443", open_ports=(80, 443), scanned=(IP,), masscan=None,
              passive=False):
    dns = {"domain": {}, "subdomains": {
        f"h{i}.example.com": {"has_records": True, "ips": {"ipv4": [ip], "ipv6": []}}
        for i, ip in enumerate(scanned)}}
    out = {"domain": "example.com", "dns": dns, "metadata": {},
           "port_scan": {"scan_metadata": {"ports_config": ports_config, "passive_mode": passive},
                         "by_ip": {IP: {"ports": list(open_ports)}} if open_ports else {}}}
    if masscan is not None:
        out["masscan_scan"] = {"scan_metadata": {"scanner": "masscan", "ports_config": masscan}}
    return out


def _cve(port, ip=IP):
    return {"cve_id": "CVE-2018-15473", "ip": ip, "source": "shodan_api", "port": port}


def _check(combined, cves, settings=None, hosts=()):
    data = {"cves": cves, "hosts": list(hosts)}
    return se.reachcheck_cves(data, pc.port_scan_coverage(combined, settings or {})), data["cves"]


class TestPortSpec:
    @pytest.mark.parametrize("spec,expected", [
        ("22,80,443", {22, 80, 443}),
        ("80, 8000-8002", {80, 8000, 8001, 8002}),
        ("t:22,u:53", {22}),
        ("T:443,U:161", {443}),
    ])
    def test_a_list_is_read_exactly(self, spec, expected):
        assert pc.parse_port_spec(spec) == frozenset(expected)

    def test_a_dash_or_full_is_every_port(self):
        assert pc.parse_port_spec("-") == pc.ALL_TCP_PORTS
        assert pc.ports_from_config("top-full") == pc.ALL_TCP_PORTS
        assert pc.ports_from_config("top-FULL") == pc.ALL_TCP_PORTS

    @pytest.mark.parametrize("spec", ["", None, "top-1000", "top-100", "abc", "22,x", "90-80",
                                      "0-70000"])
    def test_anything_unsure_is_unknown(self, spec):
        assert pc.ports_from_config(spec) is None


class TestReachCheck:
    def test_open_on_the_scan_is_true(self):
        counts, (cve,) = _check(_combined(), [_cve(443)])
        assert cve["port_confirmed"] is True
        assert counts == {"open": 1, "closed": 0, "unknown": 0}

    def test_scanned_and_not_open_is_false(self):
        _, (cve,) = _check(_combined(), [_cve(22)])
        assert cve["port_confirmed"] is False

    def test_a_port_outside_the_scanned_list_is_unknown(self):
        _, (cve,) = _check(_combined(ports_config="80,443"), [_cve(22)])
        assert "port_confirmed" in cve and cve["port_confirmed"] is None

    def test_an_ip_the_scan_did_not_target_is_unknown(self):
        _, (cve,) = _check(_combined(), [_cve(22, ip=OTHER)])
        assert cve["port_confirmed"] is None

    def test_a_top_n_scan_cannot_say_closed_but_can_say_open(self):
        _, cves = _check(_combined(ports_config="top-1000"), [_cve(22), _cve(443)])
        assert [c["port_confirmed"] for c in cves] == [None, True]

    def test_a_passive_mode_port_scan_confirms_nothing(self):
        _, cves = _check(_combined(passive=True), [_cve(22), _cve(443)])
        assert [c["port_confirmed"] for c in cves] == [None, None]

    def test_no_port_scan_at_all_is_unknown(self):
        combined = _combined()
        del combined["port_scan"]
        _, (cve,) = _check(combined, [_cve(443)])
        assert cve["port_confirmed"] is None

    def test_a_cve_without_a_port_is_unknown(self):
        _, (cve,) = _check(_combined(), [_cve(None)])
        assert cve["port_confirmed"] is None

    def test_a_udp_service_is_unknown(self):
        hosts = [{"ip": IP, "services": [{"port": 22, "transport": "udp"}]}]
        _, (cve,) = _check(_combined(), [_cve(22)], hosts=hosts)
        assert cve["port_confirmed"] is None

    def test_masscan_coverage_counts_too(self):
        combined = _combined(ports_config="80,443", masscan="22")
        _, (cve,) = _check(combined, [_cve(22)])
        assert cve["port_confirmed"] is False

    def test_masscan_with_exclusions_is_not_trusted_to_say_closed(self):
        combined = _combined(ports_config="80,443", masscan="22")
        _, (cve,) = _check(combined, [_cve(22)], settings={"MASSCAN_EXCLUDE_TARGETS": "198.51.100.0/24"})
        assert cve["port_confirmed"] is None

    def test_only_masscan_ran(self):
        combined = _combined(ports_config="22")
        combined["port_scan"]["scan_metadata"]["scanner"] = "masscan"
        combined["masscan_scan"] = {"scan_metadata": {"scanner": "masscan", "ports_config": "22"}}
        _, (cve,) = _check(combined, [_cve(22)])
        assert cve["port_confirmed"] is False


class TestThePipelineHook:
    def test_both_pipelines_run_it_after_the_cdn_drop_and_before_the_cve_write(self):
        # After the nmap merge too (R-39): test_regression_shodan_reachcheck_after_nmap.
        import recon.main as rm
        for fn in (rm.run_ip_recon, rm.run_domain_recon):
            body = inspect.getsource(fn)
            drop = body.index("_drop_shodan_cdn_ips(combined_result)")
            hook = body.index("_reachcheck_shodan_cves(combined_result,")
            write = body.index("_write_shodan_cves(combined_result)")
            assert drop < hook < write, fn.__name__

    def test_it_never_raises(self, monkeypatch):
        import recon.main as rm
        monkeypatch.setattr(se, "reachcheck_cves", mock.Mock(side_effect=RuntimeError("boom")))
        combined = _combined()
        combined["shodan"] = {"cves": [_cve(22)]}
        rm._reachcheck_shodan_cves(combined, {})
        assert "port_confirmed" not in combined["shodan"]["cves"][0]

    def test_it_marks_the_cves(self):
        import recon.main as rm
        combined = _combined()
        combined["shodan"] = {"cves": [_cve(22), _cve(443)], "hosts": []}
        rm._reachcheck_shodan_cves(combined, {})
        assert [c["port_confirmed"] for c in combined["shodan"]["cves"]] == [False, True]


class TestPartialRecon:
    def test_a_graph_port_confirms_and_nothing_else_is_written(self):
        data = {"cves": [_cve(22), _cve(443)], "hosts": []}
        counts = se.reachcheck_cves(data, lambda ip, port: True if port == 443 else None,
                                    clear_unknown=False)
        assert [c.get("port_confirmed", "absent") for c in data["cves"]] == ["absent", True]
        assert counts == {"open": 1, "closed": 0, "unknown": 1}

    def test_run_shodan_reads_the_active_open_ports_of_its_ips(self, monkeypatch):
        from recon.partial_recon_modules import osint_enrichment as oe

        class _Client:
            def __init__(self):
                self.asked = None
                self.written = None

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def verify_connection(self):
                return True

            def active_open_ports(self, user_id, project_id, ips):
                self.asked = sorted(ips)
                return {IP: {443}}

            def update_graph_from_shodan(self, recon_data, user_id, project_id):
                self.written = recon_data["shodan"]["cves"]
                return {}

        client = _Client()
        monkeypatch.setattr("graph_db.Neo4jClient", lambda *a, **k: client)
        monkeypatch.setattr(oe, "partial_settings", lambda config: {"SHODAN_PASSIVE_CVES": True})
        monkeypatch.setattr(oe, "_root_recon_data", lambda *a, **k: _combined())

        def fake_enrich(combined, settings):
            combined["shodan"] = {"hosts": [], "cves": [_cve(22), _cve(443)]}
            return combined

        monkeypatch.setattr(se, "run_shodan_enrichment", fake_enrich)
        out = oe.run_shodan({"domain": "example.com", "domains": ["example.com"]})
        assert out == {"example.com": "ok"}
        assert client.asked == [IP]
        assert [c.get("port_confirmed", "absent") for c in client.written] == ["absent", True]
