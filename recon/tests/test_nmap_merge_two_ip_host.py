"""nmap's newly confirmed ports are judged per address (S-21).

nmap probes every address with the union of all addresses' ports, and
_add_nmap_confirmed_ports adds each open port the port scan did not report on
that address (nmap_scan.new_open_ports, which the graph writer turns into a
Port). It counted every port of a by_host entry as known on the entry's
first address. A domain run's name on two addresses (masscan's by_host, the
partial port builder's) lists both addresses' ports, each detail naming its
own address: 192.0.2.20's 8443 counted as known on 192.0.2.10, so nmap finding
8443 open on 192.0.2.10 was never reported and no Port was written for it.

A detail that names its address now counts on that address only. An entry
with no such detail (IP mode, keyed by address) is read as before.
"""
from __future__ import annotations

import copy
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
for _p in (str(PROJECT_ROOT), str(PROJECT_ROOT / "recon")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from recon.helpers.nmap_merge import merge_nmap_into_port_scan  # noqa: E402

IP_A, IP_B = "192.0.2.10", "192.0.2.20"
WWW = "www.example.com"
T1 = "203.0.113.1"


def _d(port, ip=None, **extra):
    detail = {"port": port, "protocol": "tcp", "service": "", **extra}
    if ip:
        detail["ip"] = ip
    return detail


def _nmap_pd(port, **extra):
    return {"port": port, "protocol": "tcp", "state": "open", "service": "",
            "product": "", "version": "", "cpe": "", "scripts": {}, **extra}


def _two_address_name() -> dict:
    """masscan's domain-run shape: www on A (80) and B (8443), one entry."""
    return {"port_scan": {
        "by_host": {WWW: {"host": WWW, "ip": IP_A, "ports": [80, 8443],
                          "port_details": [_d(80, IP_A), _d(8443, IP_B)],
                          "cdn": None, "is_cdn": False}},
        "by_ip": {IP_A: {"ip": IP_A, "hostnames": [WWW], "ports": [80], "is_cdn": False},
                  IP_B: {"ip": IP_B, "hostnames": [WWW], "ports": [8443], "is_cdn": False}},
        "all_ports": [80, 8443], "summary": {},
    }}


def _pairs(entry: dict) -> set:
    return {(d.get("ip"), d["port"]) for d in entry["port_details"]}


def test_a_port_another_address_of_the_name_has_is_still_new_here():
    combined = _two_address_name()
    # nmap: 8443 open on A too, 80 open on B too.
    combined["nmap_scan"] = {"by_host": {
        WWW: {"host": WWW, "ip": IP_A, "ports": [80, 8443],
              "port_details": [_nmap_pd(80), _nmap_pd(8443)]},
        IP_B: {"host": IP_B, "ip": IP_B, "ports": [80, 8443],
               "port_details": [_nmap_pd(80), _nmap_pd(8443)]}}}
    merge_nmap_into_port_scan(combined)

    added = {(a["ip"], a["port"]) for a in combined["nmap_scan"].get("new_open_ports", [])}
    assert added == {(IP_A, 8443), (IP_B, 80)}
    entry = combined["port_scan"]["by_host"][WWW]
    assert _pairs(entry) == {(IP_A, 80), (IP_B, 8443), (IP_A, 8443), (IP_B, 80)}
    assert entry["ports"] == [80, 8443]
    assert combined["port_scan"]["by_ip"][IP_A]["ports"] == [80, 8443]
    assert combined["port_scan"]["by_ip"][IP_B]["ports"] == [80, 8443]


def test_a_port_the_address_already_has_is_not_added_again():
    combined = _two_address_name()
    combined["nmap_scan"] = {"by_host": {
        WWW: {"host": WWW, "ip": IP_A, "ports": [80], "port_details": [_nmap_pd(80)]},
        IP_B: {"host": IP_B, "ip": IP_B, "ports": [8443], "port_details": [_nmap_pd(8443)]}}}
    merge_nmap_into_port_scan(combined)
    assert "new_open_ports" not in combined["nmap_scan"]
    assert _pairs(combined["port_scan"]["by_host"][WWW]) == {(IP_A, 80), (IP_B, 8443)}


def test_versions_go_to_the_detail_on_nmaps_address():
    combined = _two_address_name()
    by_host = combined["port_scan"]["by_host"][WWW]
    # 443 open on both addresses, B's detail listed first.
    by_host["ports"] = [80, 443, 8443]
    by_host["port_details"] = [_d(80, IP_A), _d(443, IP_B), _d(443, IP_A), _d(8443, IP_B)]
    combined["nmap_scan"] = {"by_host": {
        WWW: {"host": WWW, "ip": IP_A, "ports": [443],
              "port_details": [_nmap_pd(443, product="nginx", version="1.25.3")]}}}
    merge_nmap_into_port_scan(combined)
    products = {(d["ip"], d["port"]): d.get("product") for d in by_host["port_details"]}
    assert products[(IP_A, 443)] == "nginx"
    assert products[(IP_B, 443)] is None


def test_an_entry_with_untagged_details_is_read_as_before():
    """IP mode: by_host keyed by address, a name on it, no detail names its IP."""
    port_scan = {
        "by_host": {T1: {"host": T1, "ip": T1, "ports": [443], "port_details": [_d(443)]},
                    WWW: {"host": WWW, "ip": T1, "ports": [443], "port_details": [_d(443)]}},
        "by_ip": {T1: {"ip": T1, "hostnames": [WWW], "ports": [443]}},
        "all_ports": [443], "summary": {"total_open_ports": 2},
    }
    combined = {"port_scan": copy.deepcopy(port_scan), "nmap_scan": {"by_host": {
        WWW: {"host": WWW, "ip": T1, "ports": [22, 443],
              "port_details": [_nmap_pd(22, product="OpenSSH"), _nmap_pd(443)]}}}}
    merge_nmap_into_port_scan(combined)

    assert combined["nmap_scan"]["new_open_ports"] == [
        {"ip": T1, "port": 22, "protocol": "tcp", "service": ""}]
    for key in (T1, WWW):
        assert combined["port_scan"]["by_host"][key] == {
            "host": key, "ip": T1, "ports": [22, 443],
            "port_details": [_d(22, product="OpenSSH"), _d(443)]}
    assert combined["port_scan"]["summary"]["total_open_ports"] == 4
