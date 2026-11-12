"""LIVE-Neo4j proof that an nmap or httpx answer lowers a passive Port's mark (S-22).

tests/test_port_confirmation_passive_only.py pins the Cypher; only a real
database proves its values on Neo4j 5.x:

  * a Shodan-only Port nmap reports open on its address is passive_only false,
    with nmap's product; the UDP Port of the same number keeps its mark;
  * a Port nmap did not report keeps its mark, and one from before the mark
    keeps its null;
  * a Shodan-only Port httpx got an HTTP answer on is passive_only false;
  * nothing leaves the tenant.

Self-skips unless the neo4j driver imports AND a database answers. To run it:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m pytest tests/test_port_confirmation_graph_live.py -v

Everything is scoped to throwaway ids and DETACH DELETEd in teardown.
"""
import os
import sys
import unittest
import uuid

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

_SKIP_REASON = None
try:
    import neo4j as _neo4j  # noqa: F401
except ImportError:
    _SKIP_REASON = "neo4j driver not installed"

_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
_USER = os.getenv("NEO4J_USER", "neo4j")
_PASSWORD = os.getenv("NEO4J_PASSWORD")
if _SKIP_REASON is None and not _PASSWORD:
    _SKIP_REASON = "NEO4J_PASSWORD not set"


def _probe():
    if _SKIP_REASON:
        return False
    try:
        drv = _neo4j.GraphDatabase.driver(_URI, auth=(_USER, _PASSWORD))
        with drv.session() as s:
            s.run("RETURN 1").single()
        drv.close()
        return True
    except Exception:
        return False


_ALIVE = _probe()

IP = "198.51.100.14"


def _nmap(port, protocol="tcp"):
    return {"nmap_scan": {"by_host": {IP: {"host": IP, "ip": IP, "ports": [port], "port_details": [
        {"port": port, "protocol": protocol, "state": "open", "service": "ssh",
         "product": "OpenSSH", "version": "9.6", "cpe": "", "scripts": {}}]}}}}


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "Neo4j not reachable")
class TestPortConfirmationLive(unittest.TestCase):
    def setUp(self):
        from graph_db.mixins.recon.http_mixin import HttpMixin
        from graph_db.mixins.recon.port_mixin import PortMixin

        class _Graph(PortMixin, HttpMixin):
            def __init__(self, drv):
                self.driver = drv

        self.driver = _neo4j.GraphDatabase.driver(_URI, auth=(_USER, _PASSWORD))
        self.graph = _Graph(self.driver)
        self.uid = f"s22-live-{uuid.uuid4().hex[:8]}"
        self.pid, self.other = f"{self.uid}-p", f"{self.uid}-q"
        with self.driver.session() as s:
            for pid in (self.pid, self.other):
                s.run(
                    """
                    CREATE (i:IP {address: $ip, user_id: $uid, project_id: $pid})
                    FOREACH (row IN [[22, 'tcp', true], [22, 'udp', true], [443, 'tcp', true],
                                     [2222, 'tcp', true]] |
                        CREATE (i)-[:HAS_PORT]->(:Port {number: row[0], protocol: row[1],
                                ip_address: $ip, user_id: $uid, project_id: $pid, state: 'open',
                                source: 'shodan', passive_only: row[2]}))
                    CREATE (i)-[:HAS_PORT]->(:Port {number: 2223, protocol: 'tcp', ip_address: $ip,
                                user_id: $uid, project_id: $pid, state: 'open', source: 'shodan'})
                    """,
                    ip=IP, uid=self.uid, pid=pid)

    def tearDown(self):
        with self.driver.session() as s:
            s.run("MATCH (n {user_id: $uid}) DETACH DELETE n", uid=self.uid)
        self.driver.close()

    def _port(self, number, protocol="tcp", pid=None):
        with self.driver.session() as s:
            row = s.run("MATCH (p:Port {number: $n, protocol: $proto, ip_address: $ip, "
                        "user_id: $uid, project_id: $pid}) "
                        "RETURN p.passive_only AS passive, p.product AS product",
                        n=number, proto=protocol, ip=IP, uid=self.uid,
                        pid=pid or self.pid).single()
        return (row["passive"], row["product"]) if row else None

    def test_nmap_open_port_is_no_longer_passive(self):
        stats = self.graph.update_graph_from_nmap(_nmap(22), self.uid, self.pid)
        self.assertEqual(stats["errors"], [])
        self.assertEqual(self._port(22), (False, "OpenSSH"))
        # nmap's TCP answer says nothing of UDP 22: enriched as before, still passive.
        self.assertEqual(self._port(22, "udp")[0], True)
        self.assertEqual(self._port(2222), (True, None))
        self.assertEqual(self._port(2223), (None, None))
        self.assertEqual(self._port(22, pid=self.other), (True, None))

    def test_httpx_answer_is_no_longer_passive(self):
        url = "https://www.example.com"
        stats = self.graph.update_graph_from_http_probe({"http_probe": {"by_url": {url: {
            "url": url, "host": "www.example.com", "ip": IP, "status_code": 200}}}},
            self.uid, self.pid)
        self.assertEqual(stats["errors"], [])
        self.assertEqual(self._port(443)[0], False)
        self.assertEqual(self._port(22)[0], True)
        self.assertEqual(self._port(443, pid=self.other)[0], True)


if __name__ == "__main__":
    unittest.main()
