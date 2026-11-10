"""Netlas keys a Port on its transport protocol, never the application one (audit L-4).

A Netlas item carries `prot4` (tcp / udp), `prot7` and `protocol` (http, https,
ssh ...). The parser kept `protocol or prot7` as the row's only protocol and the
writer used it as the Port's MERGE key, so naabu's Port {443, tcp} and Netlas's
Port {443, https} were two nodes for one socket. The Port key is the transport
(tcp unless Netlas says udp); the application protocol names the Service.

The parser runs for real; the writer runs against a fake Neo4j session that
records each statement and its parameters.
"""
from __future__ import annotations

from unittest.mock import MagicMock

from graph_db.mixins.osint_mixin import OsintMixin
from recon.main_recon_modules.netlas_enrich import _netlas_item_to_result

IP = "198.51.100.50"


class _Session:
    def __init__(self):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        self.calls.append((query, params))
        result = MagicMock()
        result.single.return_value = None
        return result


class _Writer(OsintMixin):
    def __init__(self):
        self.session = _Session()
        self.driver = MagicMock()
        self.driver.session.return_value = self.session


def _write(rows):
    w = _Writer()
    stats = w.update_graph_from_netlas(
        {"domain": "example.com", "domains": ["example.com"], "netlas": {"results": rows}},
        "u1", "p1")
    assert stats["errors"] == [], stats["errors"]
    ports = [p for q, p in w.session.calls if "MERGE (p:Port" in q]
    services = [p for q, p in w.session.calls if "MERGE (svc:Service" in q]
    return ports, services


def _item(**fields):
    return {"ip": IP, "port": 443, "host": "www.example.com", **fields}


def test_an_https_response_lands_on_the_tcp_port_the_scan_found():
    row = _netlas_item_to_result(_item(prot4="tcp", prot7="http", protocol="https"))
    ports, services = _write([row])
    assert [(p["port"], p["protocol"]) for p in ports] == [(443, "tcp")]
    # The application protocol names the Service, which hangs off that tcp Port.
    assert [(s["name"], s["port"], s["protocol"]) for s in services] == [("https", 443, "tcp")]


def test_a_udp_response_keys_a_udp_port():
    row = _netlas_item_to_result(_item(port=53, prot4="UDP", prot7="dns", protocol="dns"))
    ports, services = _write([row])
    assert [(p["port"], p["protocol"]) for p in ports] == [(53, "udp")]
    assert [(s["name"], s["protocol"]) for s in services] == [("dns", "udp")]


def test_an_item_without_prot4_is_tcp():
    row = _netlas_item_to_result(_item(port=22, prot7="ssh"))
    ports, services = _write([row])
    assert [p["protocol"] for p in ports] == ["tcp"]
    assert [s["name"] for s in services] == ["ssh"]


def test_an_unexpected_transport_is_not_a_port_key():
    # Target-controlled index data: anything but tcp/udp falls back to tcp.
    row = _netlas_item_to_result(_item(prot4="http", protocol="http"))
    ports, _ = _write([row])
    assert [p["protocol"] for p in ports] == ["tcp"]


def test_a_row_saved_before_the_transport_field_is_tcp():
    # A recon output written by an older parser carries only the app protocol.
    old_row = {"ip": IP, "port": 80, "protocol": "http", "banner": "", "title": ""}
    ports, services = _write([old_row])
    assert [(p["port"], p["protocol"]) for p in ports] == [(80, "tcp")]
    assert [(s["name"], s["protocol"]) for s in services] == [("http", "tcp")]
