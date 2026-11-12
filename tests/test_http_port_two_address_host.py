"""httpx's answer on a two-address name lands on the address that has the port (S-20).

A domain run's name can resolve to two addresses with different ports open:
two.example.com -> X 192.0.2.10 (80, 443) and Y 192.0.2.20 (443, 8443). httpx
reports one address per URL, and for such a name it is not the one it
connected to. httpx v1.12 puts the name in `host`, so the parser takes `a[0]`,
the first resolved address; its `host_ip` is a per-name record that a
concurrent probe of the name's other port overwrites. When X refuses 8443
httpx falls back to Y, gets Y's page, and still names X. The writer then
MERGEd Port 8443, its Service and SERVES_URL under X, an address the port
scan found 8443 closed on (nested lab, final E2E A1 run 2).

In a domain run the writer now reads the port scan's per-address details
(each one names its address since S-20): when the port is open on other
addresses of the name and not on the one httpx named, the answer goes to
those. Everywhere else it keeps httpx's address: the address has the port,
the scan did not see the port anywhere, the details name no address, the
reported address is not one the run knows for the name, and IP mode.

Fake Neo4j session: these pin the parameters of every Port, Service and
HAS_PORT write. tests/test_http_port_two_address_host_graph_live.py proves
the graph on a real database.
"""
import os
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

sys.modules.setdefault("neo4j", MagicMock())
sys.modules.setdefault("dotenv", MagicMock())

from graph_db.mixins.recon.http_mixin import HttpMixin  # noqa: E402

HOST = "two.example.com"
X, Y, Z = "192.0.2.10", "192.0.2.20", "192.0.2.30"


class _Result(list):
    def single(self):
        return self[0] if self else None


class _Session:
    def __init__(self, queries):
        self.queries = queries

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        self.queries.append((" ".join(query.split()), params))
        return _Result()


class _Driver:
    def __init__(self, queries):
        self.queries = queries

    def session(self):
        return _Session(self.queries)


class _Client(HttpMixin):
    def __init__(self):
        self.queries = []
        self.driver = _Driver(self.queries)


def _detail(port, ip=None, protocol="tcp"):
    d = {"port": port, "protocol": protocol, "service": "https"}
    if ip:
        d["ip"] = ip
    return d


def _recon(url, reported, details, *, dns=(X, Y), ip_mode=False, port_scan=True):
    data = {
        "domain": "example.com",
        "metadata": {"root_domain": "example.com"},
        "dns": {"domain": {"ips": {"ipv4": [], "ipv6": []}},
                "subdomains": {HOST: {"ips": {"ipv4": list(dns), "ipv6": []}, "has_records": True}}},
        "http_probe": {"by_url": {url: {"url": url, "host": HOST, "ip": reported,
                                        "status_code": 200}}},
    }
    if port_scan:
        data["port_scan"] = {"by_host": {HOST: {
            "host": HOST, "ip": X, "ports": sorted({d["port"] for d in details}),
            "port_details": list(details)}}}
    if ip_mode:
        data["metadata"]["ip_mode"] = True
    return data


#: The lab name: X serves 80 and 443, Y serves 443 and 8443 (S-20 tagged details).
LAB = [_detail(80, X), _detail(443, X), _detail(443, Y), _detail(8443, Y)]


class _Base(unittest.TestCase):
    def _write(self, data):
        client = _Client()
        stats = client.update_graph_from_http_probe(data, "u1", "p1")
        self.assertEqual(stats["errors"], [])
        return client.queries

    @staticmethod
    def _addresses(queries, prefix):
        return sorted(p["ip_addr"] for q, p in queries if q.startswith(prefix))

    def _port_addresses(self, queries):
        return self._addresses(queries, "MERGE (p:Port")

    def _has_port_addresses(self, queries):
        return self._addresses(queries, "MATCH (i:IP {address: $ip_addr")

    def _service_addresses(self, queries):
        return self._addresses(queries, "MATCH (svc:Service {name: $service_name")


class TestTwoAddressName(_Base):
    def test_a_port_only_the_second_address_has_goes_there(self):
        queries = self._write(_recon(f"https://{HOST}:8443", X, LAB))
        self.assertEqual(self._port_addresses(queries), [Y])
        self.assertEqual(self._has_port_addresses(queries), [Y])
        self.assertEqual(self._service_addresses(queries), [Y])
        for q, p in queries:
            if "ip_addr" in p:
                self.assertNotEqual(p["ip_addr"], X, q)

    def test_the_passive_only_confirmation_rides_with_it(self):
        queries = self._write(_recon(f"https://{HOST}:8443", X, LAB))
        port = [(q, p) for q, p in queries if q.startswith("MERGE (p:Port")]
        self.assertEqual(len(port), 1)
        query, params = port[0]
        self.assertIn("SET p.state = 'open', p.passive_only = false", query)
        self.assertIn("MERGE (p:Port {number: $port_number, protocol: 'tcp', ip_address: $ip_addr, "
                      "user_id: $user_id, project_id: $project_id})", query)
        self.assertEqual((params["ip_addr"], params["port_number"]), (Y, 8443))
        self.assertEqual((params["user_id"], params["project_id"]), ("u1", "p1"))

    def test_every_write_keeps_the_tenant_key(self):
        queries = self._write(_recon(f"https://{HOST}:8443", X, LAB))
        for q, p in queries:
            if "ip_addr" in p:
                self.assertIn("user_id: $user_id, project_id: $project_id", q)
                self.assertEqual((p["user_id"], p["project_id"]), ("u1", "p1"))

    def test_httpx_naming_the_right_address_is_unchanged(self):
        queries = self._write(_recon(f"https://{HOST}:8443", Y, LAB))
        self.assertEqual(self._port_addresses(queries), [Y])

    def test_a_port_both_addresses_have_stays_on_the_reported_one(self):
        queries = self._write(_recon(f"https://{HOST}", X, LAB))
        self.assertEqual(self._port_addresses(queries), [X])
        queries = self._write(_recon(f"https://{HOST}", Y, LAB))
        self.assertEqual(self._port_addresses(queries), [Y])

    def test_a_port_several_other_addresses_have_goes_to_each(self):
        details = LAB + [_detail(8443, Z)]
        queries = self._write(_recon(f"https://{HOST}:8443", X, details, dns=(X, Y, Z)))
        self.assertEqual(self._port_addresses(queries), [Y, Z])
        self.assertEqual(self._has_port_addresses(queries), [Y, Z])
        self.assertEqual(self._service_addresses(queries), [Y, Z])

    def test_an_address_with_no_open_port_known_only_from_dns(self):
        # X answered nothing in the port scan, so only DNS knows it is the name's.
        details = [_detail(443, Y), _detail(8443, Y)]
        queries = self._write(_recon(f"https://{HOST}:8443", X, details))
        self.assertEqual(self._port_addresses(queries), [Y])

    def test_a_udp_detail_is_no_tcp_answer(self):
        details = [_detail(80, X), _detail(8443, Y, protocol="udp")]
        queries = self._write(_recon(f"https://{HOST}:8443", X, details))
        self.assertEqual(self._port_addresses(queries), [X])


class TestTodaysBehaviourKept(_Base):
    def test_no_port_scan_data(self):
        queries = self._write(_recon(f"https://{HOST}:8443", X, LAB, port_scan=False))
        self.assertEqual(self._port_addresses(queries), [X])

    def test_a_port_the_scan_saw_on_no_address(self):
        queries = self._write(_recon(f"http://{HOST}:8081", X, LAB))
        self.assertEqual(self._port_addresses(queries), [X])

    def test_details_that_name_no_address(self):
        details = [_detail(80), _detail(443), _detail(8443)]
        queries = self._write(_recon(f"https://{HOST}:8443", Y, details))
        self.assertEqual(self._port_addresses(queries), [Y])

    def test_a_reported_address_the_run_does_not_know_for_the_name(self):
        queries = self._write(_recon(f"https://{HOST}:8443", Z, LAB))
        self.assertEqual(self._port_addresses(queries), [Z])

    def test_ip_mode(self):
        queries = self._write(_recon(f"https://{HOST}:8443", X, LAB, ip_mode=True))
        self.assertEqual(self._port_addresses(queries), [X])

    def test_no_reported_address_writes_no_port(self):
        queries = self._write(_recon(f"https://{HOST}:8443", None, LAB))
        self.assertEqual(self._port_addresses(queries), [])


if __name__ == "__main__":
    unittest.main()
