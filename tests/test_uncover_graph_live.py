"""LIVE-Neo4j proof that uncover's Endpoints join the graph (K23).

Strategy row 7. uncover used to key its Endpoints on `url` and hang them off
the Domain, so a URL http_probe had already written became a SECOND Endpoint
outside the BaseURL tree. The mocked test pins the Cypher; only a real database
proves that the same URL from both writers is ONE node, under one BaseURL,
under the right host.

Self-skips unless the neo4j driver imports AND a database answers. To run it:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m pytest tests/test_uncover_graph_live.py -v
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


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class TestUncoverGraphLive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from graph_db.neo4j_client import Neo4jClient
        cls.client = Neo4jClient(_URI, _USER, _PASSWORD)

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def setUp(self):
        run = uuid.uuid4().hex[:8]
        self.uid = f"unc-{run}"
        self.pid = f"UNC_{run}"
        self.base = "https://www.uncover-itest.test"
        with self.client.driver.session() as s:
            # What http_probe leaves behind, keyed the canonical way.
            s.run(
                """
                CREATE (d:Domain {name: 'uncover-itest.test', user_id: $u, project_id: $p})
                CREATE (sub:Subdomain {name: 'www.uncover-itest.test', user_id: $u, project_id: $p})
                CREATE (b:BaseURL {url: $base, user_id: $u, project_id: $p, source: 'http_probe'})
                CREATE (e:Endpoint {path: '/page', method: 'GET', baseurl: $base,
                                    user_id: $u, project_id: $p, source: 'http_probe',
                                    status_code: 200, is_live: true})
                CREATE (sub)-[:HAS_BASE_URL]->(b)-[:HAS_ENDPOINT]->(e)
                """, u=self.uid, p=self.pid, base=self.base)

    def tearDown(self):
        with self.client.driver.session() as s:
            s.run("MATCH (n) WHERE n.user_id = $u DETACH DELETE n", u=self.uid)

    def _count(self, cypher, **params):
        with self.client.driver.session() as s:
            return s.run(cypher, **params).single()[0]

    def _uncover(self, urls):
        return self.client.update_graph_from_uncover({
            "domain": "uncover-itest.test",
            "uncover": {"hosts": [], "ips": [], "ip_ports": {}, "urls": urls,
                        "sources": ["shodan"], "source_counts": {}, "total_raw": 1,
                        "total_deduped": 1},
        }, self.uid, self.pid)

    # -- row 7 -------------------------------------------------------------
    def test_the_same_url_from_both_writers_is_one_endpoint(self):
        stats = self._uncover([f"{self.base}/page"])
        self.assertEqual(stats["urls_created"], 1)
        self.assertEqual(self._count(
            "MATCH (e:Endpoint {path: '/page', baseurl: $b, project_id: $p}) RETURN count(e)",
            b=self.base, p=self.pid), 1, "uncover duplicated http_probe's Endpoint")
        self.assertEqual(self._count(
            "MATCH (b:BaseURL {url: $b, project_id: $p}) RETURN count(b)",
            b=self.base, p=self.pid), 1)
        # It joined the existing tree rather than starting a second one.
        self.assertEqual(self._count(
            """MATCH (:Subdomain {name: 'www.uncover-itest.test', project_id: $p})
                     -[:HAS_BASE_URL]->(:BaseURL {url: $b})-[:HAS_ENDPOINT]->(e:Endpoint {path: '/page'})
               RETURN count(e)""", b=self.base, p=self.pid), 1)
        # And http_probe's facts on the shared node survived the merge.
        self.assertEqual(self._count(
            "MATCH (e:Endpoint {path: '/page', baseurl: $b, project_id: $p}) RETURN e.status_code",
            b=self.base, p=self.pid), 200)

    def test_a_new_path_lands_under_the_same_baseurl(self):
        self._uncover([f"{self.base}/admin"])
        self.assertEqual(self._count(
            "MATCH (:BaseURL {url: $b, project_id: $p})-[:HAS_ENDPOINT]->(e) RETURN count(e)",
            b=self.base, p=self.pid), 2)

    # -- regression: IP hosts -------------------------------------------------
    def test_an_ip_url_does_not_create_a_dotted_subdomain(self):
        self._uncover(["https://10.9.8.7/x"])
        self.assertEqual(self._count(
            "MATCH (s:Subdomain {name: '10.9.8.7', project_id: $p}) RETURN count(s)",
            p=self.pid), 0)
        self.assertEqual(self._count(
            """MATCH (:Domain {name: 'uncover-itest.test', project_id: $p})
                     -[:HAS_BASE_URL]->(:BaseURL {url: 'https://10.9.8.7'}) RETURN count(*)""",
            p=self.pid), 1, "the IP's BaseURL must still be owned by something")


if __name__ == "__main__":
    unittest.main()
