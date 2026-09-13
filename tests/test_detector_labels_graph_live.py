"""LIVE-Neo4j proof that Real / False positive clicks reach the next run.

Strategy rows 4 and 5. The unit tests pin the posterior and the query text;
only a real database proves the round trip: publish writes `triage_detector`,
`set_human_verdict` records a click, and the `detector_labels` fact query
counts those clicks per detector:

  * across every project of ONE user (a detector that is noise on one of your
    projects is noise on the next), and
  * never across users: another operator's clicks are absent (row 4).

Self-skips unless the neo4j driver imports AND a database answers. To run it:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo:/repo/agentic -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m pytest tests/test_detector_labels_graph_live.py -v
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
DETECTOR = "nuclei:tech-detect"


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class TestDetectorLabelsGraphLive(unittest.TestCase):
    def setUp(self):
        from graph_db.mixins.recon.triage_mixin import TriageMixin

        run = uuid.uuid4().hex[:8]
        self.user_a = f"det-a-{run}"
        self.user_b = f"det-b-{run}"
        self.p1 = f"DET1_{run}"
        self.p2 = f"DET2_{run}"
        self.driver = _neo4j.GraphDatabase.driver(_URI, auth=(_USER, _PASSWORD))

        class _Client(TriageMixin):
            def __init__(self, driver):
                self.driver = driver

        self.client = _Client(self.driver)
        with self.driver.session() as s:
            s.run(
                """
                UNWIND range(1, 5) AS i
                CREATE (:Vulnerability {id: 'a' + toString(i), user_id: $a, project_id: $p1,
                                        source: 'nuclei', severity: 'low'})
                """, a=self.user_a, p1=self.p1)
            s.run("CREATE (:Vulnerability {id: 'c1', user_id: $a, project_id: $p2, source: 'nuclei'})",
                  a=self.user_a, p2=self.p2)
            s.run(
                """
                UNWIND range(1, 3) AS i
                CREATE (:Vulnerability {id: 'b' + toString(i), user_id: $b, project_id: $p1,
                                        source: 'nuclei'})
                """, b=self.user_b, p1=self.p1)

        def publish(user, project, ids):
            self.client.apply_triage_scores(user, project, [
                {"id": i, "score": 30.0, "detector": DETECTOR} for i in ids],
                guard_updated_at=False)

        publish(self.user_a, self.p1, ["a1", "a2", "a3", "a4", "a5"])
        publish(self.user_a, self.p2, ["c1"])
        publish(self.user_b, self.p1, ["b1", "b2", "b3"])

    def tearDown(self):
        with self.driver.session() as s:
            s.run("MATCH (n) WHERE n.user_id IN [$a, $b] DETACH DELETE n",
                  a=self.user_a, b=self.user_b)
        self.driver.close()

    def _labels(self, user):
        from cypherfix_triage.fact_queries import PROJECT_FACT_QUERIES, build_project_facts
        query = next(q for q in PROJECT_FACT_QUERIES if q["name"] == "detector_labels")["query"]
        with self.driver.session() as s:
            rows = [dict(r) for r in s.run(query, userId=user, projectId=self.p1)]
        return build_project_facts({"detector_labels": rows}).detector_labels

    def test_the_publish_stored_the_detector(self):
        with self.driver.session() as s:
            stored = s.run("MATCH (v:Vulnerability {id: 'a1', user_id: $a}) RETURN v.triage_detector AS d",
                           a=self.user_a).single()["d"]
        self.assertEqual(stored, DETECTOR)

    # -- row 5 -------------------------------------------------------------
    def test_n_clicks_come_back_as_n_labels_across_the_users_projects(self):
        for i in ("a1", "a2", "a3"):
            self.client.set_human_verdict(self.user_a, self.p1, i, "likely_noise")
        self.client.set_human_verdict(self.user_a, self.p1, "a4", "confirmed")
        self.client.set_human_verdict(self.user_a, self.p2, "c1", "likely_noise")

        labels = self._labels(self.user_a)
        # 3 from project 1 + 1 from project 2: learning crosses the user's
        # projects on purpose. a5 was never judged and does not count.
        self.assertEqual(labels, {DETECTOR: {"real": 1, "fp": 4}})

    # -- row 4 -------------------------------------------------------------
    def test_another_users_verdicts_are_absent(self):
        for i in ("b1", "b2", "b3"):
            self.client.set_human_verdict(self.user_b, self.p1, i, "likely_noise")
        self.client.set_human_verdict(self.user_a, self.p1, "a1", "likely_noise")

        self.assertEqual(self._labels(self.user_a), {DETECTOR: {"real": 0, "fp": 1}})
        self.assertEqual(self._labels(self.user_b), {DETECTOR: {"real": 0, "fp": 3}})

    def test_an_ai_verdict_is_not_a_label(self):
        """The AI's verdict is the thing being corrected; counting it would make
        the model learn from itself."""
        self.client.apply_triage_scores(self.user_a, self.p1, [
            {"id": "a1", "score": 30.0, "detector": DETECTOR,
             "status": "likely_noise", "confidence": 0.9}], guard_updated_at=False)
        self.assertEqual(self._labels(self.user_a), {})


if __name__ == "__main__":
    unittest.main()
