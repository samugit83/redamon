"""LIVE proof of tooling/scripts/cache_deception_rekey.py (recon-audit R-28).

On a real Neo4j, two plant-keyed deception findings for one page (the last
run's, and an older stale one a person muted, judged "False positive" and the
agent proved) collapse onto the stable id with all of that intact, the finding
hangs off the page's Endpoint, the throwaway plant Endpoints go, a plant-looking
Endpoint that carries anything else stays, `updated_at` never moves, and a second
run finds nothing. With DATABASE_URL set, the Postgres statements also run
against the real schema, inside a transaction that is rolled back.

Self-skips unless the neo4j driver imports AND a database answers. To run it
against the dev stack, with NEO4J_PASSWORD (and DATABASE_URL) exported:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://neo4j:7687 -e NEO4J_USER -e NEO4J_PASSWORD \\
    -e DATABASE_URL redamon-agent python -m pytest tests/test_cache_deception_rekey_graph_live.py -v
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

BASE = "https://shop.test"
PAGE = f"{BASE}/account"
PLANT_OLD = f"{PAGE}/rdmn1a2b3c.css"
PLANT_NEW = f"{PAGE}/rdmn4d5e6f.css"
GUARDED = "/account/rdmn0a0b0c.css"


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class TestCacheDeceptionRekeyGraphLive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.driver = _neo4j.GraphDatabase.driver(_URI, auth=(_USER, _PASSWORD))

    @classmethod
    def tearDownClass(cls):
        cls.driver.close()

    def setUp(self):
        from graph_db.mixins.cache_mixin import cache_vuln_id
        run = uuid.uuid4().hex[:8]
        self.uid, self.pid = f"cdr-{run}", f"CDR_{run}"
        self.project = {"id": self.pid, "user_id": self.uid}
        self.new_id = cache_vuln_id(self.uid, self.pid, "cache_deception", PAGE, "static-suffix:/.css")
        self.old = {p: cache_vuln_id(self.uid, self.pid, "cache_deception", p, "static-suffix")
                    for p in (PLANT_OLD, PLANT_NEW)}

    def tearDown(self):
        with self.driver.session() as s:
            s.run("MATCH (n {user_id: $u, project_id: $p}) DETACH DELETE n", u=self.uid, p=self.pid)

    def _seed(self):
        """What two pre-R-28 runs left: one node per plant, each under its plant Endpoint."""
        with self.driver.session() as s:
            s.run(
                """
                CREATE (bu:BaseURL {url: $base, user_id: $u, project_id: $p})
                CREATE (page:Endpoint {path: '/account', method: 'GET', baseurl: $base,
                        user_id: $u, project_id: $p, source: 'resource_enum'})
                CREATE (bu)-[:HAS_ENDPOINT]->(page)
                WITH bu
                UNWIND $plants AS plant
                CREATE (e:Endpoint {path: plant.path, method: 'GET', baseurl: $base,
                        user_id: $u, project_id: $p, source: 'cache_poisoning'})
                CREATE (v:Vulnerability {id: plant.id, vulnerability_id: plant.id,
                        source: 'cache_poisoning', cache_technique: 'cache_deception',
                        detection_mode: 'deception', cache_header: '', cache_param: 'static-suffix',
                        endpoint: plant.url, matched_at: plant.url, poc_link: plant.url,
                        user_id: $u, project_id: $p, updated_at: datetime(plant.seen)})
                CREATE (bu)-[:HAS_ENDPOINT]->(e)
                CREATE (e)-[:HAS_VULNERABILITY]->(v)
                CREATE (bu)-[:HAS_VULNERABILITY]->(v)
                """, base=BASE, u=self.uid, p=self.pid, plants=[
                    {"id": self.old[PLANT_OLD], "url": PLANT_OLD, "path": "/account/rdmn1a2b3c.css",
                     "seen": "2026-10-01T00:00:00Z"},
                    {"id": self.old[PLANT_NEW], "url": PLANT_NEW, "path": "/account/rdmn4d5e6f.css",
                     "seen": "2026-10-03T00:00:00Z"}])
            s.run(
                """
                MATCH (v:Vulnerability {id: $id, user_id: $u, project_id: $p})
                SET v:Muted, v.muted_by = 'user-1', v.muted_at = '2026-10-01T00:00:00Z',
                    v.triage_status = 'likely_noise', v.triage_source = 'human',
                    v.stale_since = datetime('2026-10-02T00:00:00Z')
                CREATE (cf:ChainFinding {id: 'cf-1', user_id: $u, project_id: $p,
                        finding_type: 'vulnerability_confirmed'})
                CREATE (cf)-[:CONFIRMS {confidence: 90, note: 'cached page read anonymously'}]->(v)
                WITH v
                MATCH (bu:BaseURL {url: $base, user_id: $u, project_id: $p})
                CREATE (g:Endpoint {path: $guarded, method: 'GET', baseurl: $base,
                        user_id: $u, project_id: $p, source: 'cache_poisoning'})
                CREATE (bu)-[:HAS_ENDPOINT]->(g)
                CREATE (g)-[:HAS_PARAMETER]->(:Parameter {name: 'q', user_id: $u, project_id: $p})
                """, id=self.old[PLANT_OLD], base=BASE, guarded=GUARDED, u=self.uid, p=self.pid)

    def _apply(self):
        from tooling.scripts import cache_deception_rekey as rk
        with self.driver.session() as s:
            plan = rk.plan_project(s, self.project)
            outcomes = [o for r in plan["rekeys"] for o in rk.rekey_graph(s, self.uid, self.pid, r)]
            s.run(rk.DELETE_PLANTS, uid=self.uid, pid=self.pid, plant_path=rk.PLANT_ENDPOINT_PATH)
            return plan, outcomes

    def _findings(self):
        with self.driver.session() as s:
            return {r["id"]: dict(r) for r in s.run(
                """
                MATCH (v:Vulnerability {user_id: $u, project_id: $p})
                RETURN v.id AS id, v:Muted AS muted, v.triage_status AS status,
                       v.muted_by AS muted_by, v.endpoint AS endpoint, v.cache_param AS vector,
                       v.vulnerability_id AS vid, v.poc_link AS poc, v.stale_since AS stale,
                       toString(v.updated_at) AS seen,
                       [(cf:ChainFinding)-[r:CONFIRMS]->(v) | r.confidence] AS proof,
                       [(parent)-[:HAS_VULNERABILITY]->(v) |
                            labels(parent)[0] + ':' + coalesce(parent.path, parent.url)] AS parents
                """, u=self.uid, p=self.pid)}

    def _endpoint_paths(self):
        with self.driver.session() as s:
            return sorted(r["path"] for r in s.run(
                "MATCH (e:Endpoint {user_id: $u, project_id: $p}) RETURN e.path AS path",
                u=self.uid, p=self.pid))

    def test_old_nodes_collapse_onto_the_stable_id_with_everything_on_them(self):
        self._seed()
        plan, outcomes = self._apply()
        self.assertEqual(len(plan["plants"]), 2, "the guarded plant-looking Endpoint is not listed")
        self.assertEqual(outcomes, ["renamed", "merged"])
        findings = self._findings()
        self.assertEqual(list(findings), [self.new_id])
        node = findings[self.new_id]
        self.assertEqual((node["muted"], node["status"], node["muted_by"], node["proof"]),
                         (True, "likely_noise", "user-1", [90]))
        self.assertEqual((node["endpoint"], node["vector"], node["vid"], node["poc"]),
                         (PAGE, "static-suffix:/.css", self.new_id, PLANT_NEW))
        self.assertIsNone(node["stale"], "the keeper is the node the last run saw")
        self.assertTrue(node["seen"].startswith("2026-10-03"))
        self.assertEqual(sorted(node["parents"]), ["BaseURL:" + BASE, "Endpoint:/account"])
        self.assertEqual(self._endpoint_paths(), ["/account", GUARDED])

    def test_a_second_run_finds_nothing(self):
        self._seed()
        self._apply()
        plan, outcomes = self._apply()
        self.assertEqual((plan["rekeys"], plan["plants"], outcomes), ([], [], []))

    @unittest.skipUnless(os.getenv("DATABASE_URL"), "DATABASE_URL not set")
    def test_the_postgres_statements_run_on_the_real_schema(self):
        import psycopg
        from tooling.scripts import cache_deception_rekey as rk
        rekey = {"new_id": self.new_id,
                 "old": [{"old_id": self.old[PLANT_NEW]}, {"old_id": self.old[PLANT_OLD]}]}
        with psycopg.connect(os.environ["DATABASE_URL"]) as conn:
            try:
                with conn.cursor() as cur:
                    rk.rekey_postgres(cur, self.pid, rekey)
            finally:
                conn.rollback()


if __name__ == "__main__":
    unittest.main()
