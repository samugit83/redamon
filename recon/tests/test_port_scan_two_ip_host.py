"""A hostname with two addresses keeps each address's ports (S-20).

A domain run's masscan keys by_host by name, and every address of a name
shared one entry: its `ip` was the first address, the second address's ports
joined it untagged, and a port open on both was kept once.
update_graph_from_port_scan writes a detail under the entry's `ip` unless the
detail names its own, so 192.0.2.20's 8443 became a Port of 192.0.2.10 and
192.0.2.20's 443 was never written. naabu's parser did the same for a name it
reported on more than one address.

In a domain run every port detail now names the address it was found on. An
IP-mode run, whose by_host is keyed by address, keeps its exact shape.

The scanner processes are fakes; the run_* wrappers, the parsers and the
graph writer (on a fake Neo4j session) are real.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
for _p in (str(PROJECT_ROOT), str(PROJECT_ROOT / "recon")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from recon.helpers import circuit_breaker  # noqa: E402
from recon.main_recon_modules import masscan_scan, port_scan  # noqa: E402

IP_A, IP_B = "192.0.2.10", "192.0.2.20"
WWW = "www.example.com"
T1, T2 = "203.0.113.1", "203.0.113.2"


@pytest.fixture(autouse=True)
def _fresh_run():
    circuit_breaker.reset_registry()
    yield
    circuit_breaker.reset_registry()


def _domain_recon() -> dict:
    return {
        "domain": "example.com",
        "metadata": {"include_root_domain": False},
        "dns": {"domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
                "subdomains": {WWW: {"ips": {"ipv4": [IP_A, IP_B], "ipv6": []},
                                     "has_records": True}}},
    }


def _ip_recon() -> dict:
    """run_ip_recon's GROUP 1 shape: a label per address, plus a PTR name on both."""
    from recon.helpers.ip_placeholders import placeholder_for
    subs = {placeholder_for(ip): {"has_records": True, "is_mock": True, "actual_ip": ip,
                                  "records": {}, "ips": {"ipv4": [ip], "ipv6": []}}
            for ip in (T1, T2)}
    subs[WWW] = {"has_records": True, "ips": {"ipv4": [T1, T2], "ipv6": []}}
    return {
        "domain": "ip-targets.p1",
        "metadata": {"ip_mode": True, "expanded_ips": [T1, T2], "root_domain": "ip-targets.p1",
                     "scope_mode": "exact", "include_root_domain": False, "filtered_mode": True,
                     "subdomain_filter": [T1, T2, *subs]},
        "subdomains": list(subs),
        "dns": {"domain": {}, "subdomains": subs},
    }


class _FakePopen:
    returncode = 0

    def __init__(self, cmd, *_a, **_k):
        self.cmd = cmd

    def communicate(self, timeout=None):
        return "", ""

    def kill(self):
        pass

    def wait(self, timeout=None):
        return 0


def _masscan(recon: dict, open_ports) -> dict:
    """run_masscan_scan with a masscan that reports `open_ports` [(ip, port)]."""
    real_build = masscan_scan.build_masscan_command

    def build(targets_file, output_file, *args, **kwargs):
        Path(output_file).write_text("\n".join(json.dumps({
            "ip": ip, "port": port, "proto": "tcp", "rec_type": "status",
            "data": {"status": "open"}}) for ip, port in open_ports) + "\n")
        return real_build(targets_file, output_file, *args, **kwargs)

    with mock.patch.object(masscan_scan, "is_masscan_installed", return_value=True), \
            mock.patch.object(masscan_scan, "build_masscan_command", side_effect=build), \
            mock.patch.object(masscan_scan.subprocess, "Popen", _FakePopen):
        masscan_scan.run_masscan_scan(recon, settings={"MASSCAN_ENABLED": True})
    return recon["masscan_scan"]


def _naabu(recon: dict, rows) -> dict:
    """run_port_scan with a naabu that writes `rows` (its JSON lines)."""
    real_build = port_scan.build_naabu_command

    def build(targets_file, output_file, *args, **kwargs):
        Path(output_file).write_text("\n".join(json.dumps(r) for r in rows) + "\n")
        return real_build(targets_file, output_file, *args, **kwargs)

    settings = {"NAABU_ENABLED": True, "NAABU_SCAN_TYPE": "c"}
    if (recon.get("metadata") or {}).get("ip_mode"):
        settings.update(IP_MODE=True, TARGET_IPS=[T1, T2])
    with mock.patch.object(port_scan, "is_docker_installed", return_value=True), \
            mock.patch.object(port_scan, "is_docker_running", return_value=True), \
            mock.patch.object(port_scan, "pull_naabu_docker_image", return_value=True), \
            mock.patch.object(port_scan, "build_naabu_command", side_effect=build), \
            mock.patch.object(port_scan.subprocess, "Popen", _FakePopen):
        port_scan.run_port_scan(recon, settings=settings)
    return recon["port_scan"]


def _detail(port: int) -> dict:
    return {"port": port, "protocol": "tcp", "service": port_scan.get_service_name(port)}


def _pairs(entry: dict) -> set:
    return {(d.get("ip"), d["port"]) for d in entry["port_details"]}


class _Session:
    def __init__(self):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        self.calls.append((query, params))
        return mock.MagicMock()


def _graph_ports(port_scan_section: dict) -> set:
    """The (ip, port) pairs update_graph_from_port_scan MERGEs a Port for."""
    from graph_db.mixins.recon.port_mixin import PortMixin

    class _Writer(PortMixin):
        def __init__(self):
            self.session = _Session()
            self.driver = mock.MagicMock()
            self.driver.session.return_value = self.session

    writer = _Writer()
    stats = writer.update_graph_from_port_scan(
        {"domain": "example.com", "port_scan": port_scan_section}, "u1", "p1")
    assert stats["errors"] == []
    return {(p["ip_addr"], p["port_number"]) for q, p in writer.session.calls
            if "MERGE (p:Port" in q}


# ---------------------------------------------------------------------------
# masscan, domain run
# ---------------------------------------------------------------------------

MASSCAN_OPEN = [(IP_A, 80), (IP_A, 443), (IP_B, 443), (IP_B, 8443)]


def test_masscan_tags_each_port_of_a_two_address_name_with_its_address():
    out = _masscan(_domain_recon(), MASSCAN_OPEN)
    entry = out["by_host"][WWW]
    assert set(out["by_host"]) == {WWW}
    assert _pairs(entry) == set(MASSCAN_OPEN)
    # The name still lists every address's ports: httpx builds its targets from it.
    assert entry["ports"] == [80, 443, 8443]
    assert entry["ip"] == IP_A


def test_masscan_ports_land_on_the_address_they_were_found_on():
    out = _masscan(_domain_recon(), MASSCAN_OPEN)
    assert _graph_ports(out) == set(MASSCAN_OPEN)


# ---------------------------------------------------------------------------
# naabu, domain run
# ---------------------------------------------------------------------------

def test_naabu_name_reported_on_two_addresses_keeps_each_address():
    # A naabu that reports the name with each address it found it on.
    rows = [{"host": WWW, "ip": IP_A, "port": 443}, {"host": WWW, "ip": IP_B, "port": 443},
            {"host": WWW, "ip": IP_B, "port": 8443}]
    out = _naabu(_domain_recon(), rows)
    assert _pairs(out["by_host"][WWW]) == {(IP_A, 443), (IP_B, 443), (IP_B, 8443)}
    assert out["by_host"][WWW]["ports"] == [443, 8443]
    assert _graph_ports(out) == {(IP_A, 443), (IP_B, 443), (IP_B, 8443)}


def test_naabu_address_rows_tag_their_details_and_the_name_keeps_its_ports():
    # naabu 2.6: no "host" on any row; the name takes its first address's ports.
    out = _naabu(_domain_recon(), [{"ip": IP_A, "port": 443}, {"ip": IP_B, "port": 8443}])
    by_host = out["by_host"]
    assert set(by_host) == {IP_A, IP_B, WWW}
    assert _pairs(by_host[IP_A]) == {(IP_A, 443)}
    assert _pairs(by_host[IP_B]) == {(IP_B, 8443)}
    assert _pairs(by_host[WWW]) == {(IP_A, 443)}
    assert _graph_ports(out) == {(IP_A, 443), (IP_B, 8443)}


# ---------------------------------------------------------------------------
# IP mode: by_host keyed by address, unchanged
# ---------------------------------------------------------------------------

def test_ip_mode_masscan_shape_is_unchanged():
    recon = {"metadata": {"ip_mode": True, "expanded_ips": [T1, T2],
                          "ip_to_hostname": {T1: WWW}}}
    out = _masscan(recon, [(T1, 443), (T2, 22), (T2, 443)])
    assert out["by_host"] == {
        T1: {"host": T1, "ip": T1, "ports": [443], "cdn": None, "is_cdn": False,
             "port_details": [_detail(443)]},
        T2: {"host": T2, "ip": T2, "ports": [22, 443], "cdn": None, "is_cdn": False,
             "port_details": [_detail(22), _detail(443)]},
    }


def test_ip_mode_naabu_shape_is_unchanged():
    out = _naabu(_ip_recon(), [{"ip": T1, "port": 443}, {"ip": T2, "port": 22}])
    by_host = out["by_host"]
    assert set(by_host) == {T1, T2, WWW}
    assert all("ip" not in d for e in by_host.values() for d in e["port_details"])
    assert by_host[WWW] == {
        "host": WWW, "ip": T1, "ports": [443], "cdn": None, "is_cdn": False,
        "port_details": [_detail(443)]}
