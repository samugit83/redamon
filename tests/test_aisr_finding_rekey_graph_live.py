"""LIVE proof of tooling/scripts/aisr_finding_rekey.py (recon audit L-9).

On a real Neo4j, a rule-less AI Surface MCP finding (muted, judged "False
positive" by a person, proven by the agent) moves to the id of the rule its
name gives, with all of that intact: renamed in place, or merged onto a node a
scan already wrote. `updated_at` never moves, and a second run finds nothing.
With DATABASE_URL set, the Postgres statements also run against the real
schema, inside a transaction that is rolled back.

Self-skips unless the neo4j driver imports AND a database answers. To run it
against the dev stack, with NEO4J_PASSWORD (and DATABASE_URL) exported:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://neo4j:7687 -e NEO4J_USER -e NEO4J_PASSWORD \\
    -e DATABASE_URL redamon-agent python -m pytest tests/test_aisr_finding_rekey_graph_live.py -v
"""

import hashlib
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

BASE = "http://mcp.example.com:8080"
RULE = "mcp_imperative_override"
OLD = "aisr_" + hashlib.sha256(
    f"mcp_prompt_injection|{BASE}|/mcp|None".encode()).hexdigest()[:16]
NEW = "aisr_" + hashlib.sha256(
    f"mcp_prompt_injection|{BASE}|/mcp|None|{RULE}".encode()).hexdigest()[:16]


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class TestAisrRekeyGraphLive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.driver = _neo4j.GraphDatabase.driver(_URI, auth=(_USER, _PASSWORD))

    @classmethod
    def tearDownClass(cls):
        cls.driver.close()

    def setUp(self):
        run = uuid.uuid4().hex[:8]
        self.uid, self.pid = f"ark-{run}", f"ARK_{run}"
        self.project = {"id": self.pid, "user_id": self.uid}
        with self.driver.session() as s:
            s.run(
                """
                CREATE (e:Endpoint {path: '/mcp', method: 'POST', baseurl: $base,
                        user_id: $u, project_id: $p})
                CREATE (v:Vulnerability:Muted {id: $old, source: 'ai_surface_recon',
                        type: 'mcp_prompt_injection', name: $name, severity: 'medium',
                        user_id: $u, project_id: $p, muted_by: 'user-1',
                        triage_status: 'likely_noise', triage_source: 'human',
                        updated_at: datetime('2026-10-01T00:00:00Z')})
                CREATE (e)-[:HAS_VULNERABILITY]->(v)
                CREATE (cf:ChainFinding {id: 'cf-1', user_id: $u, project_id: $p,
                        finding_type: 'vulnerability_confirmed'})
                CREATE (cf)-[:CONFIRMS {confidence: 90, note: 'tool call obeyed'}]->(v)
                """, base=BASE, old=OLD, name=f"MCP server instructions: {RULE}",
                u=self.uid, p=self.pid)

    def tearDown(self):
        with self.driver.session() as s:
            s.run("MATCH (n {user_id: $u, project_id: $p}) DETACH DELETE n", u=self.uid, p=self.pid)

    def _apply(self):
        from tooling.scripts import aisr_finding_rekey as rk
        with self.driver.session() as s:
            plan = rk.plan_project(s, self.project, rk._mcp_probe_paths())
            self.assertEqual(plan["unmapped"], [])
            return [rk.rekey_graph(s, self.uid, self.pid, r) for r in plan["rekeys"]]

    def _nodes(self):
        with self.driver.session() as s:
            return {r["id"]: dict(r) for r in s.run(
                """
                MATCH (v:Vulnerability {user_id: $u, project_id: $p})
                RETURN v.id AS id, v:Muted AS muted, v.triage_status AS status,
                       v.triage_source AS by, toString(v.updated_at) AS seen,
                       [(cf:ChainFinding)-[r:CONFIRMS]->(v) | r.confidence] AS proof,
                       [(parent)-[:HAS_VULNERABILITY]->(v) | labels(parent)[0]] AS parents
                """, u=self.uid, p=self.pid)}

    def test_the_finding_is_renamed_with_everything_on_it(self):
        self.assertEqual(self._apply(), ["renamed"])
        nodes = self._nodes()
        self.assertEqual(list(nodes), [NEW])
        node = nodes[NEW]
        self.assertEqual((node["muted"], node["status"], node["by"]), (True, "likely_noise", "human"))
        self.assertEqual((node["proof"], node["parents"]), ([90], ["Endpoint"]))
        self.assertTrue(node["seen"].startswith("2026-10-01"))

    def test_a_node_the_scan_already_wrote_takes_the_block_and_the_proof(self):
        with self.driver.session() as s:
            s.run("""
                MATCH (e:Endpoint {path: '/mcp', baseurl: $base, user_id: $u, project_id: $p})
                CREATE (e)-[:HAS_VULNERABILITY]->(:Vulnerability {id: $new,
                        source: 'ai_surface_recon', type: 'mcp_prompt_injection', name: $name,
                        user_id: $u, project_id: $p, triage_ai_verdict: 'real',
                        updated_at: datetime()})
                """, base=BASE, new=NEW, name=f"MCP server instructions: {RULE}",
                u=self.uid, p=self.pid)
        self.assertEqual(self._apply(), ["merged"])
        nodes = self._nodes()
        self.assertEqual(list(nodes), [NEW])
        self.assertEqual((nodes[NEW]["muted"], nodes[NEW]["status"], nodes[NEW]["proof"]),
                         (True, "likely_noise", [90]))

    def test_a_second_run_finds_nothing(self):
        self._apply()
        self.assertEqual(self._apply(), [])

    @unittest.skipUnless(os.getenv("DATABASE_URL"), "DATABASE_URL not set")
    def test_the_postgres_statements_run_on_the_real_schema(self):
        import psycopg
        from tooling.scripts import aisr_finding_rekey as rk
        with psycopg.connect(os.environ["DATABASE_URL"]) as conn:
            try:
                with conn.cursor() as cur:
                    rk.rekey_postgres(cur, self.pid, {"old_id": OLD, "new_id": NEW})
            finally:
                conn.rollback()


if __name__ == "__main__":
    unittest.main()
