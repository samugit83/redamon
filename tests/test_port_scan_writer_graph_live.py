"""LIVE-Neo4j proof that update_graph_from_port_scan never lowers what it did not measure (D5, R-26).

tests/test_port_scan_writer_measured.py pins the Cypher; only a real database
proves its values on Neo4j 5.x:

  * a CDN-tagged IP stays tagged, with its first cdn_name and cdn_source, when
    masscan (which reports no CDN) writes the same address;
  * a Shodan-only Port stays passive_only true when the write carries the
    graph's own mark (partial port data rebuilt from the graph), and a Port
    from before the mark keeps its null; an active hit still lowers it;
  * a port detail naming its IP lands on that IP, not the host's first one;
  * on fresh nodes, the way a full run writes after clear_recon_data, the
    values are exactly what naabu reported;
  * nothing leaves the tenant.

Self-skips unless the neo4j driver imports AND a database answers. To run it:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m pytest tests/test_port_scan_writer_graph_live.py -v

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

EDGE, ORIGIN, OTHER = "198.51.100.10", "198.51.100.20", "198.51.100.30"


def _host(ip, details, is_cdn=False, cdn=None, key=None):
    return {key or ip: {"host": key or ip, "ip": ip, "ports": [d["port"] for d in details],
                        "port_details": details, "is_cdn": is_cdn, "cdn": cdn}}


def _scan(by_host, by_ip=None):
    return {"domain": "example.com", "port_scan": {"by_host": by_host, "by_ip": by_ip or {}}}


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "Neo4j not reachable")
class TestPortScanWriterLive(unittest.TestCase):
    def setUp(self):
        from graph_db.mixins.recon.port_mixin import PortMixin

        class _Graph(PortMixin):
            def __init__(self, drv):
                self.driver = drv

        self.driver = _neo4j.GraphDatabase.driver(_URI, auth=(_USER, _PASSWORD))
        self.graph = _Graph(self.driver)
        self.uid = f"d5-live-{uuid.uuid4().hex[:8]}"
        self.pid, self.other = f"{self.uid}-p", f"{self.uid}-q"
        with self.driver.session() as s:
            for pid in (self.pid, self.other):
                s.run(
                    """
                    CREATE (i:IP {address: $edge, user_id: $uid, project_id: $pid,
                                  is_cdn: true, cdn_name: 'fastly', cdn_source: 'tlsx'})
                    CREATE (i)-[:HAS_PORT]->(:Port {number: 22, protocol: 'tcp', ip_address: $edge,
                                  user_id: $uid, project_id: $pid, state: 'open',
                                  source: 'shodan', passive_only: true})
                    CREATE (i)-[:HAS_PORT]->(:Port {number: 2222, protocol: 'tcp', ip_address: $edge,
                                  user_id: $uid, project_id: $pid, state: 'open', source: 'shodan'})
                    """,
                    edge=EDGE, uid=self.uid, pid=pid)

    def tearDown(self):
        with self.driver.session() as s:
            s.run("MATCH (n {user_id: $uid}) DETACH DELETE n", uid=self.uid)
        self.driver.close()

    def _write(self, data, pid=None):
        stats = self.graph.update_graph_from_port_scan(data, self.uid, pid or self.pid)
        self.assertEqual(stats["errors"], [])

    def _ip(self, address, pid=None):
        with self.driver.session() as s:
            row = s.run("MATCH (i:IP {address: $a, user_id: $uid, project_id: $pid}) "
                        "RETURN i.is_cdn AS is_cdn, i.cdn_name AS cdn_name, i.cdn_source AS src",
                        a=address, uid=self.uid, pid=pid or self.pid).single()
        return (row["is_cdn"], row["cdn_name"], row["src"]) if row else None

    def _passive(self, address, number, pid=None):
        with self.driver.session() as s:
            row = s.run("MATCH (p:Port {number: $n, ip_address: $a, user_id: $uid, project_id: $pid}) "
                        "RETURN p.passive_only AS passive, p.state AS state",
                        n=number, a=address, uid=self.uid, pid=pid or self.pid).single()
        return (row["passive"], row["state"]) if row else None

    def test_masscan_on_a_tagged_ip_keeps_the_tag(self):
        detail = {"port": 80, "protocol": "tcp", "service": "http"}
        self._write(_scan(_host(EDGE, [detail]),
                          by_ip={EDGE: {"ip": EDGE, "ports": [80], "is_cdn": False, "cdn": None}}))
        self.assertEqual(self._ip(EDGE), (True, "fastly", "tlsx"))
        self.assertEqual(self._passive(EDGE, 80), (False, "open"))
        self.assertEqual(self._passive(EDGE, 22), (True, "open"))

    def test_ports_rebuilt_from_the_graph_keep_their_mark(self):
        rebuilt = [{"port": 22, "protocol": "tcp", "service": "", "ip": EDGE, "passive_only": True},
                   {"port": 2222, "protocol": "tcp", "service": "", "ip": EDGE, "passive_only": None}]
        self._write(_scan(_host(EDGE, rebuilt, is_cdn=True, cdn="fastly")))
        self.assertEqual(self._passive(EDGE, 22), (True, "open"))
        self.assertEqual(self._passive(EDGE, 2222), (None, "open"))

    def test_an_active_hit_still_lowers_the_mark(self):
        self._write(_scan(_host(EDGE, [{"port": 22, "protocol": "tcp", "service": "ssh"}])))
        self.assertEqual(self._passive(EDGE, 22), (False, "open"))
        self.assertEqual(self._passive(EDGE, 22, pid=self.other), (True, "open"))

    def test_a_detail_naming_its_ip_lands_there(self):
        details = [{"port": 443, "protocol": "tcp", "service": "https"},
                   {"port": 8080, "protocol": "tcp", "service": "http-alt", "ip": ORIGIN}]
        self._write(_scan(_host(EDGE, details, key="www.example.com"),
                          by_ip={ORIGIN: {"ip": ORIGIN, "ports": [8080], "hostnames": ["www.example.com"]}}))
        with self.driver.session() as s:
            owners = {(r["ip"], r["port"]) for r in s.run(
                "MATCH (i:IP {user_id: $uid, project_id: $pid})-[:HAS_PORT]->(p:Port) "
                "WHERE p.number IN [443, 8080] RETURN i.address AS ip, p.number AS port",
                uid=self.uid, pid=self.pid)}
        self.assertEqual(owners, {(EDGE, 443), (ORIGIN, 8080)})

    def test_fresh_nodes_get_exactly_what_naabu_reported(self):
        fresh = f"{self.uid}-fresh"
        self._write(_scan({**_host(ORIGIN, [{"port": 443, "protocol": "tcp", "service": "https"}],
                                   is_cdn=True, cdn="cloudflare"),
                           **_host(OTHER, [{"port": 22, "protocol": "tcp", "service": "ssh"}])},
                          by_ip={ORIGIN: {"ip": ORIGIN, "ports": [443], "is_cdn": True, "cdn": "cloudflare"},
                                 OTHER: {"ip": OTHER, "ports": [22], "is_cdn": False, "cdn": None}}),
                    pid=fresh)
        self.assertEqual(self._ip(ORIGIN, pid=fresh), (True, "cloudflare", None))
        self.assertEqual(self._ip(OTHER, pid=fresh), (False, None, None))
        self.assertEqual(self._passive(ORIGIN, 443, pid=fresh), (False, "open"))
        self.assertEqual(self._passive(OTHER, 22, pid=fresh), (False, "open"))

    def test_the_other_project_is_untouched(self):
        self._write(_scan(_host(EDGE, [{"port": 22, "protocol": "tcp", "service": "ssh"}]),
                          by_ip={EDGE: {"ip": EDGE, "ports": [22], "is_cdn": False}}))
        self.assertEqual(self._ip(EDGE, pid=self.other), (True, "fastly", "tlsx"))
        self.assertEqual(self._passive(EDGE, 22, pid=self.other), (True, "open"))


if __name__ == "__main__":
    unittest.main()
