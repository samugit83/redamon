"""An nmap or httpx answer on a passive port marks it found by an active scan (S-22).

A Port Shodan or InternetDB created carries `passive_only = true`; the Priority
Board reads it as "passive" reach until an active scanner reports the same
port. The port scan writer and nmap's new-port write lowered it, but:

  * nmap's enrichment of a Port that already existed (step 1 of
    update_graph_from_nmap: every open port nmap reports on an address) set
    product, version and nmap_scanned and left the mark, so a Shodan port nmap
    confirmed open stayed "passive" (a partial Nmap on graph targets, or a full
    run where the port scan had listed the port for the address);
  * httpx's answer on a URL MERGEs the Port with state 'open' and left the
    mark too (the DNS fallback's 80/443, a partial httpx on graph ports).

Both now set `passive_only = false` on the Port they confirmed: nmap only on
the protocol it scanned (a TCP answer says nothing of the UDP port), httpx on
the TCP port it got an HTTP answer from.

Fake Neo4j session: these pin the Cypher and its parameters. The live
counterpart, tests/test_port_confirmation_graph_live.py, proves the values.
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
from graph_db.mixins.recon.port_mixin import PortMixin  # noqa: E402

IP = "198.51.100.14"


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


class _Client(PortMixin, HttpMixin):
    def __init__(self):
        self.queries = []
        self.driver = _Driver(self.queries)


def _nmap(port, protocol="tcp", product="OpenSSH", version="9.6"):
    return {"nmap_scan": {"by_host": {IP: {"host": IP, "ip": IP, "ports": [port], "port_details": [
        {"port": port, "protocol": protocol, "state": "open", "service": "ssh",
         "product": product, "version": version, "cpe": "", "scripts": {}}]}}}}


class TestNmapEnrichment(unittest.TestCase):
    def _enrich(self, data):
        client = _Client()
        stats = client.update_graph_from_nmap(data, "u1", "p1")
        self.assertEqual(stats["errors"], [])
        writes = [(q, p) for q, p in client.queries
                  if q.startswith("MATCH (p:Port {number: $port_number, ip_address: $ip_addr")]
        self.assertEqual(len(writes), 1, client.queries)
        return writes[0]

    def test_an_open_port_nmap_reports_is_no_longer_passive(self):
        query, params = self._enrich(_nmap(22))
        self.assertIn("p.passive_only = CASE WHEN p.protocol = $protocol THEN false "
                      "ELSE p.passive_only END", query)
        self.assertEqual(params["protocol"], "tcp")
        self.assertEqual((params["ip_addr"], params["port_number"]), (IP, 22))

    def test_only_the_protocol_nmap_scanned(self):
        _, params = self._enrich(_nmap(53, protocol="udp", product="dnsmasq", version="2.90"))
        self.assertEqual(params["protocol"], "udp")

    def test_the_tenant_key_stays_on_the_match(self):
        query, params = self._enrich(_nmap(22))
        self.assertIn("user_id: $user_id, project_id: $project_id", query)
        self.assertEqual((params["user_id"], params["project_id"]), ("u1", "p1"))


class TestHttpxAnswer(unittest.TestCase):
    def _port_write(self, url, port):
        client = _Client()
        client.update_graph_from_http_probe({"http_probe": {"by_url": {url: {
            "url": url, "host": "www.example.com", "ip": IP, "status_code": 200}}}},
            "u1", "p1")
        writes = [(q, p) for q, p in client.queries if q.startswith("MERGE (p:Port")]
        self.assertEqual(len(writes), 1, client.queries)
        query, params = writes[0]
        self.assertEqual((params["ip_addr"], params["port_number"]), (IP, port))
        return query, params

    def test_the_port_httpx_got_an_answer_on_is_no_longer_passive(self):
        query, _ = self._port_write("https://www.example.com", 443)
        self.assertIn("SET p.state = 'open', p.passive_only = false", query)
        self.assertIn("MERGE (p:Port {number: $port_number, protocol: 'tcp', ip_address: $ip_addr, "
                      "user_id: $user_id, project_id: $project_id})", query)

    def test_a_non_default_port(self):
        self._port_write("http://www.example.com:8081/", 8081)


if __name__ == "__main__":
    unittest.main()
