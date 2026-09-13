"""LIVE-Neo4j proof that agent proof reaches the finding it proved (K1).

Strategy rows 1 and 2, plus the cap regression. The clause tests in
test_graph_writer_fixes.py pin the Cypher text; only a real database proves the
edge is actually written, to the right node, and to nothing else:

  * a reported id yields exactly one CONFIRMS edge to that Vulnerability, and
    MalPackageFinding is matched on its `finding_id` key (row 1);
  * an id from another project, and an id that exists nowhere, write nothing
    (row 2): a hallucinated id must not be able to mark anything proven;
  * the id list is capped, so a model emitting hundreds of ids cannot hold the
    graph in a scan per id (regression for the unbounded property scan).

Self-skips unless the neo4j driver imports AND a database answers. To run it:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo:/repo/agentic -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m pytest tests/test_chain_proof_graph_live.py -v

Everything is scoped to throwaway ids and DETACH DELETEd in teardown.
"""

import os
import sys
import unittest
import uuid

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for path in (_REPO, os.path.join(_REPO, "agentic")):
    if path not in sys.path:
        sys.path.insert(0, path)

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
class TestChainProofGraphLive(unittest.TestCase):
    def setUp(self):
        run = uuid.uuid4().hex[:8]
        self.uid = f"proof-{run}"
        self.pid = f"PROOF_{run}"
        self.other_pid = f"PROOF_OTHER_{run}"
        self.step_id = f"step-{run}"
        self.driver = _neo4j.GraphDatabase.driver(_URI, auth=(_USER, _PASSWORD))
        with self.driver.session() as s:
            s.run(
                """
                CREATE (:ChainStep {step_id: $step, user_id: $u, project_id: $p})
                CREATE (:Vulnerability {id: 'v1', user_id: $u, project_id: $p, source: 'nuclei'})
                CREATE (:MalPackageFinding {finding_id: 'mp1', user_id: $u, project_id: $p})
                CREATE (:Vulnerability {id: 'v-other', user_id: $u, project_id: $o, source: 'nuclei'})
                CREATE (:Subdomain {id: 'not-a-finding', name: 'x.test', user_id: $u, project_id: $p})
                """,
                step=self.step_id, u=self.uid, p=self.pid, o=self.other_pid,
            )

    def tearDown(self):
        with self.driver.session() as s:
            s.run("MATCH (n) WHERE n.user_id = $u DETACH DELETE n", u=self.uid)
        self.driver.close()

    def _confirm(self, ids):
        from orchestrator_helpers.chain_graph_writer import _write_finding
        finding_id = f"cf-{uuid.uuid4().hex[:8]}"
        _write_finding(
            _URI, _USER, _PASSWORD,
            finding_id=finding_id, chain_id="chain", step_id=self.step_id,
            user_id=self.uid, project_id=self.pid,
            finding_type="vulnerability_confirmed", severity="high",
            title="proved it", description="", evidence="",
            confidence=90, phase="exploitation", iteration=1,
            related_cves=[], related_ips=[], related_finding_ids=ids,
        )
        return finding_id

    def _edges(self, finding_id):
        with self.driver.session() as s:
            return {r["target"]: r["n"] for r in s.run(
                """
                MATCH (f:ChainFinding {finding_id: $fid})-[:CONFIRMS]->(t)
                RETURN coalesce(t.id, t.finding_id) AS target, count(*) AS n
                """, fid=finding_id)}

    # -- row 1 -------------------------------------------------------------
    def test_a_reported_id_yields_one_confirms_edge(self):
        edges = self._edges(self._confirm(["v1"]))
        self.assertEqual(edges, {"v1": 1})

    def test_a_mal_package_is_matched_on_its_own_key(self):
        edges = self._edges(self._confirm(["mp1"]))
        self.assertEqual(edges, {"mp1": 1})

    def test_the_proof_query_reads_it_back(self):
        """The whole point of the edge: the fact query the score model runs
        must collect the confirmed id."""
        from cypherfix_triage.fact_queries import PROJECT_FACT_QUERIES
        self._confirm(["v1"])
        proof = next(q for q in PROJECT_FACT_QUERIES if q["name"] == "proof")["query"]
        with self.driver.session() as s:
            rows = list(s.run(proof, userId=self.uid, projectId=self.pid))
        ids = {i for r in rows for i in (r["finding_ids"] or []) if i}
        self.assertIn("v1", ids)

    # -- row 2 -------------------------------------------------------------
    def test_another_projects_id_and_an_unknown_id_write_nothing(self):
        edges = self._edges(self._confirm(["v-other", "ghost-id"]))
        self.assertEqual(edges, {})

    def test_a_non_finding_node_cannot_be_confirmed(self):
        """An id that exists but is not a finding label (a Subdomain here) is
        refused: CONFIRMS on anything else could never be read back as proof."""
        edges = self._edges(self._confirm(["not-a-finding"]))
        self.assertEqual(edges, {})

    # -- regression: unbounded id list -------------------------------------
    def test_more_than_the_cap_is_ignored(self):
        from orchestrator_helpers.chain_graph_writer import _MAX_CONFIRMS_IDS
        padding = [f"ghost-{i}" for i in range(_MAX_CONFIRMS_IDS)]
        edges = self._edges(self._confirm(padding + ["v1"]))
        self.assertEqual(edges, {}, "the id past the cap must not be matched")


if __name__ == "__main__":
    unittest.main()
