"""LIVE-Neo4j proof of the prioritisation write path.

`test_triage_mixin.py` asserts the SHAPE of the Cypher `apply_triage_scores`
builds. It cannot prove Neo4j agrees: that the tenant clause really isolates, that
the `isHuman` FOREACH really skips a human-owned finding, that an ambiguous
re-run really preserves a prior verdict, and that `list_triage_findings` really
returns findings worst-first by score. Each of those is a guarantee the feature
rests on, so each is proved here against a real database.

Skipped unless the neo4j driver is importable AND a database answers. To run it:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://redamon-neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m unittest tests.test_triage_scoring_graph_live

Everything it creates is scoped to a throwaway tenant and deleted in tearDown.
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
class LiveScoreCase(unittest.TestCase):
    def setUp(self):
        from graph_db.mixins.recon.triage_mixin import TriageMixin

        run = uuid.uuid4().hex[:8]
        self.uid = f"score-{run}"
        self.pid = f"SCORE_{run}"
        self.other_uid = f"other-{run}"
        self.driver = _neo4j.GraphDatabase.driver(_URI, auth=(_USER, _PASSWORD))

        class _Client(TriageMixin):
            def __init__(self, driver):
                self.driver = driver

        self.client = _Client(self.driver)
        with self.driver.session() as s:
            s.run(
                """
                CREATE (top:Vulnerability {id:'top', user_id:$u, project_id:$p, severity:'medium'})
                CREATE (mid:Vulnerability {id:'mid', user_id:$u, project_id:$p, severity:'critical'})
                CREATE (hum:Vulnerability {id:'hum', user_id:$u, project_id:$p, severity:'low',
                                           triage_source:'human', triage_status:'confirmed',
                                           triage_priority_score:1.0})
                """,
                u=self.uid, p=self.pid,
            )

    def tearDown(self):
        with self.driver.session() as s:
            s.run("MATCH (n) WHERE n.user_id IN [$u, $o] AND n.project_id = $p DETACH DELETE n",
                  u=self.uid, o=self.other_uid, p=self.pid)
        self.driver.close()

    def _scores(self):
        return {r["id"]: r for r in self.client.list_triage_findings(self.uid, self.pid)}

    def test_scores_are_written_and_ranked_worst_first(self):
        self.client.apply_triage_scores(self.uid, self.pid, [
            {"id": "top", "score": 85.0, "signals": ["cisa_kev", "dast_confirmed"],
             "status": "confirmed", "confidence": 1.0},
            {"id": "mid", "score": 40.0, "signals": ["severity_critical"]},
        ], guard_updated_at=False)
        ordered = [r["id"] for r in self.client.list_triage_findings(self.uid, self.pid)]
        # 'top' has a far higher score than the plain critical 'mid', so a
        # KEV+DAST medium leads a bare critical -- the whole point.
        self.assertEqual(ordered[0], "top")
        self.assertLess(ordered.index("top"), ordered.index("mid"))
        rows = self._scores()
        self.assertEqual(rows["top"]["triage_priority_score"], 85.0)
        self.assertEqual(rows["top"]["triage_signals"], ["cisa_kev", "dast_confirmed"])

    def test_a_human_owned_finding_is_never_overwritten(self):
        result = self.client.apply_triage_scores(self.uid, self.pid, [
            {"id": "hum", "score": 99.0, "signals": ["applies_to_measurements"],
             "status": "likely_noise", "confidence": 0.1},
        ], guard_updated_at=False)
        # Score model v3 (C14): the measurements (score, signals) are facts and
        # are written even on a human-owned row; the VERDICT is what a person
        # owns, and that is what must not move.
        self.assertEqual(result["skipped_human"], 1)
        self.assertEqual(result["updated"], 1)
        row = self._scores()["hum"]
        self.assertEqual(row["triage_priority_score"], 99.0)     # measurement: updated
        self.assertEqual(row["triage_status"], "confirmed")      # verdict: unchanged
        self.assertEqual(row["triage_source"], "human")

    def test_an_ambiguous_rerun_preserves_a_prior_verdict(self):
        # First a decisive write, then a score-only re-run (status omitted).
        self.client.apply_triage_scores(self.uid, self.pid, [
            {"id": "top", "score": 90.0, "signals": ["cisa_kev"],
             "status": "confirmed", "confidence": 1.0}], guard_updated_at=False)
        self.client.apply_triage_scores(self.uid, self.pid, [
            {"id": "top", "score": 95.0, "signals": ["cisa_kev"]}],  # no status
            guard_updated_at=False)
        row = self._scores()["top"]
        self.assertEqual(row["triage_priority_score"], 95.0)    # score updated
        self.assertEqual(row["triage_status"], "confirmed")     # verdict preserved

    def test_a_never_triaged_finding_gets_its_first_ai_verdict(self):
        """Regression. `isHuman` was `n.triage_source = 'human'`, which is NULL
        on a node no run has touched; `NOT NULL` is NULL, so the verdict FOREACH
        never fired and a fresh project's first run wrote no AI verdicts at all.
        'mid' has no triage_source in the fixture on purpose."""
        self.client.apply_triage_scores(self.uid, self.pid, [
            {"id": "mid", "score": 40.0, "status": "likely_noise", "confidence": 0.8}],
            guard_updated_at=False)
        row = self._scores()["mid"]
        self.assertEqual(row["triage_status"], "likely_noise")
        self.assertEqual(row["triage_source"], "ai")

    def test_another_tenants_id_is_never_written(self):
        with self.driver.session() as s:
            s.run("CREATE (v:Vulnerability {id:'victim', user_id:$o, project_id:$p, severity:'high'})",
                  o=self.other_uid, p=self.pid)
        # Our tenant tries to score an id that belongs to another user.
        result = self.client.apply_triage_scores(self.uid, self.pid, [
            {"id": "victim", "score": 5000.0, "signals": ["x"]}])
        self.assertEqual(result["updated"], 0)                  # matched nothing
        with self.driver.session() as s:
            victim = s.run("MATCH (v:Vulnerability {id:'victim'}) RETURN v.triage_priority_score AS s"
                           ).single()
        self.assertIsNone(victim["s"])                          # untouched

    def test_the_write_never_mutes(self):
        self.client.apply_triage_scores(self.uid, self.pid, [
            {"id": "top", "score": 900.0, "signals": ["x"]}])
        with self.driver.session() as s:
            muted = s.run("MATCH (v:Vulnerability {id:'top', user_id:$u}) RETURN v:Muted AS m",
                          u=self.uid).single()["m"]
        self.assertFalse(muted)


if __name__ == "__main__":
    unittest.main()
