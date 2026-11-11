"""Partial Nmap: a custom port nmap found closed is not written as an open Port (C6).

The custom ports are still handed to nmap on every IP. Afterwards, on an IP nmap
scanned to completion, only the ones it found open reach the port_scan graph
writer. When nmap did not run, or gave up on that IP, the operator's explicit
input is all there is, and every custom port is written as before. The graph's
own ports never reach that writer: this run did not measure them (D5).
"""
from __future__ import annotations

import copy
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.partial_recon_modules import port_scanning  # noqa: E402

IP_A = "192.0.2.10"
HOST = "www.alpha.test"
BASE = {"_settings": {}, "domains": ["alpha.test"], "domain": "alpha.test",
        "domain_groups": [{"rootDomain": "alpha.test", "prefixes": ["*"], "batch": True}]}


def _graph_recon(roots, *a, **kw):
    detail = {"port": 80, "protocol": "tcp", "service": ""}
    return {
        "domain": roots[0], "domains": list(roots),
        "port_scan": {
            "by_ip": {IP_A: {"ip": IP_A, "hostnames": [HOST], "ports": [80],
                             "port_details": [dict(detail)]}},
            "by_host": {HOST: {"host": HOST, "ip": IP_A, "ports": [80],
                               "port_details": [dict(detail)]}},
            "ip_to_hostnames": {IP_A: [HOST]}, "all_ports": [80],
            "scan_metadata": {"scanners": ["naabu"]}, "summary": {},
        },
        "dns": {"domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
                "subdomains": {HOST: {"ips": {"ipv4": [IP_A], "ipv6": []}, "has_records": True}}},
        "metadata": {"include_root_domain": False},
    }


@pytest.fixture
def client(monkeypatch):
    client = MagicMock()
    client.verify_connection.return_value = True
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)
    client.update_graph_from_port_scan.return_value = {}
    client.update_graph_from_nmap.return_value = {}
    module = MagicMock()
    module.Neo4jClient.return_value = client
    monkeypatch.setitem(sys.modules, "graph_db", module)
    monkeypatch.setattr(port_scanning, "_build_port_scan_data_from_graph", _graph_recon)
    return client


def _nmap_finding(open_ports, unreachable=None, ran=True):
    seen = {}

    def fake(recon_data, output_file=None, settings=None):
        seen["port_scan"] = copy.deepcopy(recon_data["port_scan"])
        if not ran:
            return recon_data
        recon_data["nmap_scan"] = {
            "by_host": {HOST: {"host": HOST, "ip": IP_A, "ports": list(open_ports),
                               "port_details": [{"port": p, "protocol": "tcp", "state": "open",
                                                 "service": "", "product": "", "version": "",
                                                 "cpe": "", "scripts": {}} for p in open_ports]}},
            "services_detected": [], "nse_vulns": [],
        }
        if unreachable:
            recon_data["nmap_scan"]["unreachable_hosts"] = list(unreachable)
        return recon_data

    return fake, seen


def _run(client, fake, ports=(8443, 9090)):
    config = {**BASE, "user_targets": {"ips": [], "ports": list(ports), "ip_attach_to": None}}
    with patch("recon.main_recon_modules.nmap_scan.run_nmap_scan", side_effect=fake):
        port_scanning.run_nmap(config)
    return client.update_graph_from_port_scan.call_args.kwargs["recon_data"]["port_scan"]


class TestCustomPorts:
    def test_nmap_still_scans_every_custom_port(self, client):
        fake, seen = _nmap_finding(open_ports=[80])
        _run(client, fake)
        assert seen["port_scan"]["by_host"][HOST]["ports"] == [80, 8443, 9090]

    def test_a_custom_port_nmap_found_closed_is_not_written(self, client):
        fake, _ = _nmap_finding(open_ports=[80, 8443])
        ps = _run(client, fake)
        assert ps["by_host"][HOST]["ports"] == [8443]
        assert [pd["port"] for pd in ps["by_host"][HOST]["port_details"]] == [8443]

    def test_a_graph_port_is_not_written_back(self, client):
        # Reported open or not, 80 is the graph's: rewriting it would mark it
        # actively found, which a Shodan-only port is not.
        for open_ports in ([8443], [80, 8443]):
            fake, _ = _nmap_finding(open_ports=open_ports)
            ps = _run(client, fake)
            assert ps["by_host"][HOST]["ports"] == [8443]

    def test_nothing_measured_writes_no_host(self, client):
        fake, _ = _nmap_finding(open_ports=[80])
        ps = _run(client, fake)
        assert ps["by_host"] == {}

    def test_when_nmap_did_not_run_every_custom_port_is_written(self, client):
        fake, _ = _nmap_finding(open_ports=[], ran=False)
        ps = _run(client, fake)
        assert ps["by_host"][HOST]["ports"] == [8443, 9090]

    def test_when_nmap_gave_up_on_the_ip_every_custom_port_is_written(self, client):
        fake, _ = _nmap_finding(open_ports=[], unreachable=[IP_A])
        ps = _run(client, fake)
        assert ps["by_host"][HOST]["ports"] == [8443, 9090]

    def test_the_ip_keeps_its_ports_for_the_ip_node(self, client):
        # by_ip only decides whether the IP node is written; it keeps today's ports.
        fake, _ = _nmap_finding(open_ports=[80])
        ps = _run(client, fake)
        assert ps["by_ip"][IP_A]["ports"] == [80, 8443, 9090]
