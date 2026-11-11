"""A partial run writes back only the port data its tool measured (D5, R-26).

Partial Nmap, tlsx and httpx rebuild port_scan from the graph and used to hand
all of it to update_graph_from_port_scan, which rewrote every port as found by
an active scan (passive_only false), put a hostname's second IP's ports under
its first IP, and reset IP CDN tags. Now:

  * the port builder keeps each IP's own ports and carries each port's
    passive mark, so the rebuilt data says what the graph says;
  * each partial caller hands the writer only the ports its tool measured:
    the custom ports nmap confirmed, the typed targets httpx got an answer
    from, and none of the graph's own ports for tlsx.

Fixture names are example.com hosts, addresses RFC 5737.
"""
from __future__ import annotations

import copy
import sys
from pathlib import Path
from unittest import mock
from unittest.mock import MagicMock, patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.partial_recon_modules import graph_builders as gb  # noqa: E402
from recon.partial_recon_modules import http_probing, port_scanning, tlsx_scanning  # noqa: E402

WWW = "www.example.com"
SSH = "ssh.example.com"
IP_A, IP_B, IP_S = "192.0.2.10", "192.0.2.20", "192.0.2.14"
TYPED = "203.0.113.9"


def _port(number, passive_only=None, source=None):
    return {"number": number, "protocol": "tcp", "passive_only": passive_only, "source": source}


# (subdomain, ip, is_cdn, cdn_name, ports): www fronts two IPs with different
# ports; ssh's 22 is Shodan-only, 2222 is a Shodan port written before the
# passive mark existed, and 25 an old active one.
ROWS = [
    (WWW, IP_A, True, "fastly", [_port(80, False), _port(443, False)]),
    (WWW, IP_B, None, None, [_port(8080, False)]),
    (SSH, IP_S, None, None, [_port(22, True, "shodan"), _port(2222, None, "shodan"),
                             _port(25, None, None)]),
]
OWNER = {(IP_A, 80), (IP_A, 443), (IP_B, 8080), (IP_S, 22), (IP_S, 2222), (IP_S, 25)}


class _Result(list):
    def single(self):
        return self[0] if self else None


class _Session:
    def __init__(self, calls):
        self.calls = calls

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, cypher, **params):
        self.calls.append((cypher, params))
        rows = _Result()
        if "HAS_SUBDOMAIN" in cypher:
            for sub, ip, is_cdn, cdn, ports in ROWS:
                rows.append({"root": "example.com", "subdomain": sub, "ip": ip,
                             "version": "ipv4", "is_cdn": is_cdn, "cdn_name": cdn,
                             "ports": copy.deepcopy(ports)})
        return rows


class _Client:
    calls: list = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def verify_connection(self):
        return True

    @property
    def driver(self):
        driver = mock.MagicMock()
        driver.session.side_effect = lambda **_k: _Session(_Client.calls)
        return driver


@pytest.fixture
def built(monkeypatch):
    _Client.calls = []
    monkeypatch.setattr("graph_db.Neo4jClient", _Client)
    return gb._build_port_scan_data_from_graph(["example.com"], "u1", "p1")


def _owner_of(entry, detail):
    return detail.get("ip") or entry["ip"]


class TestBuilder:
    def test_no_port_is_put_under_another_ip(self, built):
        for entry in built["port_scan"]["by_host"].values():
            for detail in entry["port_details"]:
                assert (_owner_of(entry, detail), detail["port"]) in OWNER

    def test_every_graph_port_is_still_there(self, built):
        seen = {(_owner_of(e, d), d["port"])
                for e in built["port_scan"]["by_host"].values() for d in e["port_details"]}
        assert seen == OWNER

    def test_each_ip_lists_its_own_ports(self, built):
        by_ip = built["port_scan"]["by_ip"]
        assert sorted(by_ip[IP_A]["ports"]) == [80, 443]
        assert by_ip[IP_B]["ports"] == [8080]

    def test_the_hostname_still_lists_every_port_for_the_target_builders(self, built):
        # httpx builds http://www.example.com:8080 from by_host, keyed by name.
        entry = built["port_scan"]["by_host"][WWW]
        assert entry["ip"] == IP_A
        assert sorted(entry["ports"]) == [80, 443, 8080]

    def test_each_port_carries_the_graphs_passive_mark(self, built):
        # As stored: a Port from before the mark carries null, which the writer
        # reads as "not seen by this run" whatever its source.
        marks = {d["port"]: d["passive_only"]
                 for d in built["port_scan"]["by_host"][SSH]["port_details"]}
        assert marks == {22: True, 2222: None, 25: None}
        www = {d["port"]: d["passive_only"] for d in built["port_scan"]["by_host"][WWW]["port_details"]}
        assert www == {80: False, 443: False, 8080: False}

    def test_the_query_reads_each_ports_mark(self, built):
        query = next(c for c, _ in _Client.calls if "HAS_SUBDOMAIN" in c)
        assert "passive_only: p.passive_only" in query

    def test_the_cdn_tag_still_rides_along(self, built):
        assert built["port_scan"]["by_ip"][IP_A]["is_cdn"] is True
        assert built["port_scan"]["by_host"][WWW]["cdn"] == "fastly"

    def test_rows_from_an_older_graph_still_build(self, monkeypatch):
        class _Bare(_Session):
            def run(self, cypher, **params):
                rows = _Result()
                if "HAS_SUBDOMAIN" in cypher:
                    rows.append({"root": "example.com", "subdomain": WWW, "ip": IP_A,
                                 "version": "ipv4", "ports": [{"number": 80, "protocol": "tcp"}]})
                return rows

        class _BareClient(_Client):
            @property
            def driver(self):
                driver = mock.MagicMock()
                driver.session.side_effect = lambda **_k: _Bare([])
                return driver

        monkeypatch.setattr("graph_db.Neo4jClient", _BareClient)
        data = gb._build_port_scan_data_from_graph(["example.com"], "u1", "p1")
        detail = data["port_scan"]["by_host"][WWW]["port_details"][0]
        assert (detail["port"], detail["ip"], detail["passive_only"]) == (80, IP_A, None)


class _RecordingSession:
    def __init__(self):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        self.calls.append((query, params))
        return _Result()


def test_the_rebuilt_data_written_back_keeps_passive_ports_and_owners(built):
    """The writer's safety net, fed the builder's own output: a port carried as
    passive is no active hit, and each port is written under its own IP."""
    from graph_db.mixins.recon.port_mixin import PortMixin

    class _Graph(PortMixin):
        def __init__(self):
            self.session = _RecordingSession()
            self.driver = MagicMock()
            self.driver.session.return_value = self.session

    graph = _Graph()
    graph.update_graph_from_port_scan(built, "u1", "p1")
    ports = {(p["ip_addr"], p["port_number"]): p
             for q, p in graph.session.calls if "MERGE (p:Port" in q}
    assert set(ports) == OWNER
    assert ports[(IP_S, 22)].get("active") is False
    assert ports[(IP_S, 2222)].get("active") is False
    assert ports[(IP_S, 25)].get("active") is False
    assert ports[(IP_B, 8080)].get("active") is True


# --- the partial callers' hand-off -------------------------------------------

BASE = {"_settings": {}, "domains": ["example.com"], "domain": "example.com",
        "domain_groups": [{"rootDomain": "example.com", "prefixes": ["*"], "batch": True}]}


def _graph_recon(roots, *a, **kw):
    """What the builder returns for the fixture graph: www on two IPs, and
    ssh with a Shodan-only port 22."""
    def detail(port, ip, passive=False):
        return {"port": port, "protocol": "tcp", "service": "", "ip": ip, "passive_only": passive}

    return {
        "domain": roots[0], "domains": list(roots),
        "port_scan": {
            "by_ip": {
                IP_A: {"ip": IP_A, "hostnames": [WWW], "ports": [80], "is_cdn": True,
                       "cdn": "fastly", "port_details": [detail(80, IP_A)]},
                IP_S: {"ip": IP_S, "hostnames": [SSH], "ports": [22], "is_cdn": False,
                       "cdn": None, "port_details": [detail(22, IP_S, True)]},
            },
            "by_host": {
                WWW: {"host": WWW, "ip": IP_A, "ports": [80], "is_cdn": True, "cdn": "fastly",
                      "port_details": [detail(80, IP_A)]},
                SSH: {"host": SSH, "ip": IP_S, "ports": [22], "is_cdn": False, "cdn": None,
                      "port_details": [detail(22, IP_S, True)]},
            },
            "ip_to_hostnames": {IP_A: [WWW], IP_S: [SSH]}, "all_ports": [22, 80],
            "scan_metadata": {"scanners": ["naabu"]}, "summary": {},
        },
        "dns": {"domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
                "subdomains": {WWW: {"ips": {"ipv4": [IP_A], "ipv6": []}, "has_records": True},
                               SSH: {"ips": {"ipv4": [IP_S], "ipv6": []}, "has_records": True}}},
        "metadata": {"include_root_domain": False},
    }


@pytest.fixture
def client(monkeypatch):
    client = MagicMock()
    client.verify_connection.return_value = True
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)
    for writer in ("update_graph_from_port_scan", "update_graph_from_nmap",
                   "update_graph_from_tlsx", "update_graph_from_http_probe"):
        getattr(client, writer).return_value = {}
    module = MagicMock()
    module.Neo4jClient.return_value = client
    monkeypatch.setitem(sys.modules, "graph_db", module)
    for mod in (port_scanning, tlsx_scanning, http_probing):
        monkeypatch.setattr(mod, "_build_port_scan_data_from_graph", _graph_recon)
    return client


def _written(client):
    return client.update_graph_from_port_scan.call_args.kwargs["recon_data"]


def _written_ports(client):
    ps = _written(client)["port_scan"]
    return {(_owner_of(e, d), d["port"]) for e in ps["by_host"].values() for d in e["port_details"]}


class TestNmapHandOff:
    @staticmethod
    def _nmap(open_on):
        def fake(recon_data, output_file=None, settings=None):
            recon_data["nmap_scan"] = {"by_host": {
                f"h{i}": {"host": f"h{i}", "ip": ip, "ports": [port],
                          "port_details": [{"port": port, "protocol": "tcp", "state": "open",
                                            "service": "", "product": "", "version": "",
                                            "cpe": "", "scripts": {}}]}
                for i, (ip, port) in enumerate(open_on)},
                "services_detected": [], "nse_vulns": []}
            return recon_data
        return fake

    def _run(self, open_on, ports=(8443,)):
        config = {**BASE, "user_targets": {"ips": [], "ports": list(ports), "ip_attach_to": None}}
        with patch("recon.main_recon_modules.nmap_scan.run_nmap_scan", side_effect=self._nmap(open_on)):
            port_scanning.run_nmap(config)

    def test_only_the_custom_ports_nmap_confirmed_are_written(self, client):
        self._run(open_on=[(IP_A, 8443), (IP_A, 80), (IP_S, 8443)])
        assert _written_ports(client) == {(IP_A, 8443), (IP_S, 8443)}

    def test_a_shodan_only_port_is_not_rewritten(self, client):
        self._run(open_on=[(IP_A, 8443)])
        assert (IP_S, 22) not in _written_ports(client)

    def test_the_rest_of_the_recon_dict_still_reaches_the_writer(self, client):
        self._run(open_on=[(IP_A, 8443)])
        written = _written(client)
        assert written["domains"] == ["example.com"] and "dns" in written
        assert set(written["port_scan"]["by_ip"]) == {IP_A, IP_S}


class TestTlsxHandOff:
    def test_the_graphs_own_ports_are_not_rewritten(self, client):
        config = {**BASE, "user_targets": {"ips": [TYPED], "ports": [8443]}}
        with patch("recon.main_recon_modules.tls_scan.run_tlsx_enrichment",
                   side_effect=lambda rd, settings=None: rd):
            tlsx_scanning.run_tlsx(config)
        ps = _written(client)["port_scan"]
        assert ps["by_host"] == {}
        # by_ip still carries the typed address, whose IP node the tlsx writer MATCHes.
        assert 8443 in ps["by_ip"][TYPED]["ports"]


class TestHttpxHandOff:
    @staticmethod
    def _probe(answering):
        def fake(recon_data, output_file=None, settings=None):
            recon_data["http_probe"] = {"by_url": {url: {"url": url, "host": ""} for url in answering}}
            return recon_data
        return fake

    def _run(self, answering, ports=None):
        targets = {"ips": [TYPED]}
        if ports:
            targets["ports"] = list(ports)
        config = {**BASE, "user_targets": targets}
        with patch("recon.main_recon_modules.http_probe.run_http_probe",
                   side_effect=self._probe(answering)):
            http_probing.run_httpx(config)

    def test_only_the_typed_ports_that_answered_are_written(self, client):
        self._run(answering=[f"http://{TYPED}", f"http://{WWW}"])
        assert _written_ports(client) == {(TYPED, 80)}

    def test_custom_ports_on_graph_hosts_are_not_written(self, client):
        self._run(answering=[f"https://{TYPED}:8443", f"https://{WWW}:8443"], ports=[8443])
        assert _written_ports(client) == {(TYPED, 8443)}

    def test_an_ipv6_typed_target_matches_its_url(self, client):
        typed6 = "2001:db8::9"
        config = {**BASE, "user_targets": {"ips": [typed6]}}
        with patch("recon.main_recon_modules.http_probe.run_http_probe",
                   side_effect=self._probe([f"https://[{typed6}]"])):
            http_probing.run_httpx(config)
        assert _written_ports(client) == {(typed6, 443)}
