"""A late name on two scanned addresses keeps each address's ports (S-20 class).

attach_known_ports gives a name found after the port scan the open ports of
the addresses it resolves to, with no packet sent. It built one by_host entry
on the name's first address, listing every address's ports with untagged
details picked by port number: the graph writer then put 192.0.2.20's 8443 on
192.0.2.10, never wrote 443 for 192.0.2.20, and 443's detail (banner, product)
could be the other address's.

A domain run's late name now gets one detail per address and port, each a
copy of that address's own detail and naming the address. IP mode (``targets``
given: pinned answers, a zero-port target counts as scanned) is unchanged.
"""
from __future__ import annotations

import copy
import sys
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
for _p in (str(PROJECT_ROOT), str(PROJECT_ROOT / "recon")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from recon.helpers import late_names as ln  # noqa: E402

IP_A, IP_B = "192.0.2.10", "192.0.2.20"
LATE = "late.example.com"
T1, T2 = "203.0.113.1", "203.0.113.2"


def _dns(*ips):
    return {"has_records": True, "ips": {"ipv4": list(ips), "ipv6": []}}


def _d(port, ip=None, **extra):
    detail = {"port": port, "protocol": "tcp", "service": "https" if port == 443 else "unknown", **extra}
    if ip:
        detail["ip"] = ip
    return detail


def _row(host, ip, details):
    return {"host": host, "ip": ip, "ports": sorted({d["port"] for d in details}),
            "port_details": details, "cdn": None, "is_cdn": False}


def _combined(tagged=True):
    tag = (lambda ip: ip) if tagged else (lambda ip: None)
    a, b = (IP_A, IP_B) if tagged else (T1, T2)
    return {
        "dns": {"subdomains": {LATE: _dns(a, b)}},
        "port_scan": {
            "by_ip": {a: {"ip": a, "hostnames": [], "ports": [443]},
                      b: {"ip": b, "hostnames": [], "ports": [443, 8443]}},
            "by_host": {a: _row(a, a, [_d(443, tag(a), product="nginx")]),
                        b: _row(b, b, [_d(443, tag(b), product="caddy"), _d(8443, tag(b))])},
        },
    }


def _graph_ports(port_scan_section: dict) -> set:
    from graph_db.mixins.recon.port_mixin import PortMixin
    calls = []

    class _Session:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def run(self, query, **params):
            calls.append((query, params))
            return mock.MagicMock()

    class _Writer(PortMixin):
        def __init__(self):
            self.driver = mock.MagicMock()
            self.driver.session.return_value = _Session()

    stats = _Writer().update_graph_from_port_scan(
        {"domain": "example.com", "port_scan": port_scan_section}, "u1", "p1")
    assert stats["errors"] == []
    return {(p["ip_addr"], p["port_number"]) for q, p in calls if "MERGE (p:Port" in q}


def test_a_late_name_keeps_each_addresss_ports_and_details():
    combined = _combined()
    assert ln.attach_known_ports(combined, [LATE]) == []
    row = combined["port_scan"]["by_host"][LATE]
    assert row["ip"] == IP_A and row["ports"] == [443, 8443]
    got = {(d.get("ip"), d["port"]): d.get("product") for d in row["port_details"]}
    assert got == {(IP_A, 443): "nginx", (IP_B, 443): "caddy", (IP_B, 8443): None}


def test_its_ports_land_on_their_own_address_in_the_graph():
    combined = _combined()
    ln.attach_known_ports(combined, [LATE])
    late_only = {"by_ip": {}, "by_host": {LATE: combined["port_scan"]["by_host"][LATE]}}
    assert _graph_ports(late_only) == {(IP_A, 443), (IP_B, 443), (IP_B, 8443)}


def test_the_source_rows_are_not_touched():
    combined = _combined()
    before = copy.deepcopy(combined["port_scan"]["by_host"][IP_B])
    ln.attach_known_ports(combined, [LATE])
    assert combined["port_scan"]["by_host"][IP_B] == before


def test_ip_mode_with_targets_keeps_its_shape():
    combined = _combined(tagged=False)
    ln.attach_known_ports(combined, [LATE], targets={T1, T2})
    # The first address's row, every address's port numbers, a detail per port.
    assert combined["port_scan"]["by_host"][LATE] == {
        "host": LATE, "ip": T1, "ports": [443, 8443],
        "port_details": [_d(443, product="caddy"), _d(8443)],
        "cdn": None, "is_cdn": False}
