"""naabu + masscan keep a port only masscan found on a name's second address.

merge_port_scan_results folds masscan's by_host into naabu's when both ran.
A domain run's details name the address each port was found on (S-20), but
the merge deduplicated them by port number alone: with naabu's www.example.com
holding 443 on 192.0.2.10, masscan's 443 on 192.0.2.20 was dropped, and with
no by_host row left for it the graph never got that Port. It now keeps one
detail per address and port. An IP-mode run's untagged details merge as before.

recon.main is imported with stub settings; the merge and the graph writer (on
a fake Neo4j session) are real.
"""
from __future__ import annotations

import copy
import sys
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
for _p in (str(PROJECT_ROOT), str(PROJECT_ROOT / "recon")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

IP_A, IP_B = "192.0.2.10", "192.0.2.20"
WWW = "www.example.com"
T1 = "203.0.113.1"


@pytest.fixture
def recon_main():
    stub = {
        "TARGET_DOMAIN": "example.com", "SUBDOMAIN_LIST": [], "IP_MODE": False, "TARGET_IPS": [],
        "DOMAIN_BATCH_MODE": False, "DOMAIN_BATCH_GROUPS": [],
        "USE_BRUTEFORCE_FOR_SUBDOMAINS": False, "SCAN_MODULES": ["domain_discovery"],
        "UPDATE_GRAPH_DB": False, "USER_ID": "u1", "PROJECT_ID": "p1",
        "VERIFY_DOMAIN_OWNERSHIP": False, "STEALTH_MODE": False,
        "OWNERSHIP_TOKEN": "", "OWNERSHIP_TXT_PREFIX": "",
    }
    with mock.patch("recon.project_settings.get_settings", return_value=dict(stub)):
        for mod in [m for m in list(sys.modules) if m in ("recon.main", "main")]:
            del sys.modules[mod]
        import recon.main as rm
        yield rm


def _d(port, ip=None):
    detail = {"port": port, "protocol": "tcp", "service": "https" if port == 443 else "unknown"}
    if ip:
        detail["ip"] = ip
    return detail


def _entry(host, ip, details):
    return {"host": host, "ip": ip, "ports": sorted({d["port"] for d in details}),
            "port_details": details, "cdn": None, "is_cdn": False}


def _domain_run() -> dict:
    """naabu found 443 on A only; masscan found 443 on both and 8443 on B."""
    return {
        "port_scan": {
            "scan_metadata": {"scanners": ["naabu"]},
            "by_host": {WWW: _entry(WWW, IP_A, [_d(443, IP_A)]),
                        IP_A: _entry(IP_A, IP_A, [_d(443, IP_A)])},
            "by_ip": {IP_A: {"ip": IP_A, "hostnames": [WWW], "ports": [443]}},
            "all_ports": [443], "summary": {},
        },
        "masscan_scan": {
            "scan_metadata": {"scanner": "masscan"},
            "by_host": {WWW: _entry(WWW, IP_A, [_d(443, IP_A), _d(443, IP_B), _d(8443, IP_B)])},
            "by_ip": {IP_A: {"ip": IP_A, "hostnames": [WWW], "ports": [443]},
                      IP_B: {"ip": IP_B, "hostnames": [WWW], "ports": [443, 8443]}},
            "all_ports": [443, 8443], "ip_to_hostnames": {IP_A: [WWW], IP_B: [WWW]},
            "summary": {},
        },
    }


def _graph_ports(port_scan_section: dict) -> set:
    from graph_db.mixins.recon.port_mixin import PortMixin

    class _Session:
        calls = []

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def run(self, query, **params):
            self.calls.append((query, params))
            return mock.MagicMock()

    class _Writer(PortMixin):
        def __init__(self):
            self.driver = mock.MagicMock()
            self.session = _Session()
            self.session.calls = []
            self.driver.session.return_value = self.session

    writer = _Writer()
    stats = writer.update_graph_from_port_scan(
        {"domain": "example.com", "port_scan": port_scan_section}, "u1", "p1")
    assert stats["errors"] == []
    return {(p["ip_addr"], p["port_number"]) for q, p in writer.session.calls
            if "MERGE (p:Port" in q}


def test_a_port_only_masscan_found_on_the_second_address_survives(recon_main):
    combined = _domain_run()
    recon_main.merge_port_scan_results(combined)
    entry = combined["port_scan"]["by_host"][WWW]
    assert {(d.get("ip"), d["port"]) for d in entry["port_details"]} == {
        (IP_A, 443), (IP_B, 443), (IP_B, 8443)}
    assert entry["ports"] == [443, 8443]


def test_the_graph_gets_every_address_port(recon_main):
    combined = _domain_run()
    recon_main.merge_port_scan_results(combined)
    assert _graph_ports(combined["port_scan"]) == {(IP_A, 443), (IP_B, 443), (IP_B, 8443)}


def test_untagged_ip_mode_rows_merge_as_before(recon_main):
    naabu = _entry(T1, T1, [_d(443)])
    masscan = _entry(T1, T1, [_d(22), _d(443)])
    combined = {
        "port_scan": {"scan_metadata": {"scanners": ["naabu"]}, "by_host": {T1: copy.deepcopy(naabu)},
                      "by_ip": {T1: {"ip": T1, "hostnames": [], "ports": [443]}}, "all_ports": [443]},
        "masscan_scan": {"by_host": {T1: masscan},
                         "by_ip": {T1: {"ip": T1, "hostnames": [], "ports": [22, 443]}},
                         "all_ports": [22, 443], "ip_to_hostnames": {T1: [T1]}},
    }
    recon_main.merge_port_scan_results(combined)
    assert combined["port_scan"]["by_host"][T1] == {
        "host": T1, "ip": T1, "ports": [22, 443], "port_details": [_d(22), _d(443)],
        "cdn": None, "is_cdn": False}
