"""LIVE proof of the vector-DB Technology anchor (recon audit L-3).

On a real Neo4j, a vector DB confirmed on one host and port is linked to that
host's BaseURL only: another host on the same port, and a host whose URL merely
contains the port as a substring (`:80` inside `:8080`), stay unlinked.

Self-skips unless the neo4j driver imports AND a database answers. To run it
against the dev stack, with NEO4J_PASSWORD exported:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo/recon \\
    -e PYTHONPATH=/repo/recon:/repo -e HOME=/tmp -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD --entrypoint python redamon-recon:latest \\
    -m pytest -q tests/test_ai_surface_vector_db_live.py
"""
import os
import sys
import unittest
import uuid
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

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

ONE, TWO = "vdb-one.example.com", "vdb-two.example.com"


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class TestVectorDbAnchorLive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from graph_db.mixins.recon.ai_surface_recon_mixin import AiSurfaceReconMixin

        class Client(AiSurfaceReconMixin):
            def __init__(self, driver):
                self.driver = driver

        cls.driver = _neo4j.GraphDatabase.driver(_URI, auth=(_USER, _PASSWORD))
        cls.client = Client(cls.driver)

    @classmethod
    def tearDownClass(cls):
        cls.driver.close()

    def setUp(self):
        run = uuid.uuid4().hex[:8]
        self.uid, self.pid = f"vdb-{run}", f"VDB_{run}"
        urls = [f"http://{ONE}:8080", f"http://{TWO}:8080", f"http://{ONE}", f"https://{TWO}:18080"]
        with self.driver.session() as s:
            s.run("UNWIND $urls AS url CREATE (:BaseURL {url: url, user_id: $u, project_id: $p})",
                  urls=urls, u=self.uid, p=self.pid)

    def tearDown(self):
        with self.driver.session() as s:
            s.run("MATCH (n {user_id: $u, project_id: $p}) DETACH DELETE n", u=self.uid, p=self.pid)

    def _promote(self, tech, host, port, ip=None):
        payload = {"ai_surface_recon": {"vector_db": [
            {"service": tech, "host": host, "ip": ip, "port": port, "tech_name": tech,
             "confirmed_via": "read"}]}}
        stats = self.client.update_graph_from_ai_surface_recon(payload, self.uid, self.pid)
        self.assertEqual(stats["errors"], [])

    def _linked(self, tech):
        with self.driver.session() as s:
            return sorted(r["url"] for r in s.run(
                """
                MATCH (b:BaseURL {user_id: $u, project_id: $p})-[:USES_TECHNOLOGY]->
                      (t:Technology {name: $t, user_id: $u, project_id: $p})
                RETURN b.url AS url
                """, u=self.uid, p=self.pid, t=tech))

    def test_only_the_probed_host_and_port_gets_the_technology(self):
        self._promote("weaviate", ONE, 8080)
        self.assertEqual(self._linked("weaviate"), [f"http://{ONE}:8080"])

    def test_a_default_port_matches_the_url_without_a_port_and_nothing_longer(self):
        self._promote("chroma", ONE, 80)
        self.assertEqual(self._linked("chroma"), [f"http://{ONE}"])

    def _anchors(self, tech):
        with self.driver.session() as s:
            return sorted(r["anchor"] for r in s.run(
                """
                MATCH (n {user_id: $u, project_id: $p})-[]->
                      (t:Technology {name: $t, user_id: $u, project_id: $p})
                RETURN labels(n)[0] AS anchor
                """, u=self.uid, p=self.pid, t=tech))

    def test_the_port_on_the_ip_wins_over_every_baseurl(self):
        with self.driver.session() as s:
            s.run("""
                CREATE (:IP {address: '203.0.113.5', user_id: $u, project_id: $p})
                       -[:HAS_PORT]->(:Port {number: 8080, user_id: $u, project_id: $p})
                """, u=self.uid, p=self.pid)
        self._promote("weaviate", ONE, 8080, ip="203.0.113.5")
        self.assertEqual(self._anchors("weaviate"), ["Port"])

    def test_with_no_port_and_no_baseurl_for_it_the_ip_is_the_anchor(self):
        with self.driver.session() as s:
            s.run("CREATE (:IP {address: '203.0.113.6', user_id: $u, project_id: $p})",
                  u=self.uid, p=self.pid)
        self._promote("qdrant", "203.0.113.6", 6333, ip="203.0.113.6")
        self.assertEqual(self._anchors("qdrant"), ["IP"])


if __name__ == "__main__":
    unittest.main()
