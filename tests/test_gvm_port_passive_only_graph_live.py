"""LIVE-Neo4j proof that GVM's Port write lowers a passive Port's mark.

tests/test_gvm_port_passive_only.py pins the Cypher; on a real database:

  * a Shodan-only TCP Port GVM detected OpenSSH on is passive_only false;
  * the UDP Port of the same number keeps its mark;
  * the other project's Port is untouched.

Self-skips unless the neo4j driver imports AND a database answers. To run it:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m pytest tests/test_gvm_port_passive_only_graph_live.py -v

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


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "Neo4j not reachable")
class TestGvmPortWriteLive(unittest.TestCase):
    def setUp(self):
        self.driver = _neo4j.GraphDatabase.driver(_URI, auth=(_USER, _PASSWORD))
        self.uid = f"gvm-pass-{uuid.uuid4().hex[:8]}"
        self.pid, self.other = f"{self.uid}-p", f"{self.uid}-q"
        with self.driver.session() as s:
            for pid in (self.pid, self.other):
                s.run(
                    """
                    CREATE (i:IP {address: $ip, user_id: $uid, project_id: $pid})
                    FOREACH (proto IN ['tcp', 'udp'] |
                        CREATE (i)-[:HAS_PORT]->(:Port {number: 22, protocol: proto, ip_address: $ip,
                                user_id: $uid, project_id: $pid, state: 'open',
                                source: 'shodan', passive_only: true}))
                    """,
                    ip=IP, uid=self.uid, pid=pid)

    def tearDown(self):
        with self.driver.session() as s:
            s.run("MATCH (n {user_id: $uid}) DETACH DELETE n", uid=self.uid)
        self.driver.close()

    def _passive(self, protocol, pid=None):
        with self.driver.session() as s:
            row = s.run("MATCH (p:Port {number: 22, protocol: $proto, ip_address: $ip, "
                        "user_id: $uid, project_id: $pid}) RETURN p.passive_only AS passive, "
                        "p.source AS source",
                        proto=protocol, ip=IP, uid=self.uid, pid=pid or self.pid).single()
        return (row["passive"], row["source"]) if row else None

    def test_gvm_detection_lowers_the_tcp_ports_mark_only(self):
        from graph_db.mixins.gvm_mixin import GvmMixin
        stats = {"technologies_created": 0, "ports_created": 0, "relationships_created": 0}
        with self.driver.session() as s:
            GvmMixin()._merge_gvm_technology(
                s, {"name": "OpenSSH", "version": "9.6", "cpe": "cpe:/a:openbsd:openssh:9.6",
                    "target_ip": IP, "port": 22, "protocol": "tcp"},
                self.uid, self.pid, stats)
        # The provider that first reported the port stays its source.
        self.assertEqual(self._passive("tcp"), (False, "shodan"))
        self.assertEqual(self._passive("udp"), (True, "shodan"))
        self.assertEqual(self._passive("tcp", pid=self.other), (True, "shodan"))


if __name__ == "__main__":
    unittest.main()
