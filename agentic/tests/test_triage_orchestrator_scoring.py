"""The orchestrator's prioritisation phase, wired but hermetic.

Proves the phase-1b flow without a database or an LLM: every scoring query's
rows are scored and ranked, the writes go out, a query that raises is skipped
(not fatal), and the reduced-LLM cluster/rationale step is best-effort — an LLM
failure leaves the deterministic ranking intact.

The Cypher itself is proved against a live Neo4j in test_triage_scoring_graph_live.py
and the scorer maths in test_triage_scoring.py; this pins the glue in run()'s
phase 1b.

Run: python -m pytest agentic/tests/test_triage_orchestrator_scoring.py
"""

import asyncio
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cypherfix_triage.orchestrator import TriageOrchestrator  # noqa: E402


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


class FakeNeo4j:
    """Returns canned rows per scoring query, keyed by a label token in the text."""

    def __init__(self, rows_by_label, raising=()):
        self.rows_by_label = rows_by_label
        self.raising = set(raising)
        self.connect_calls = 0

    async def connect(self):
        self.connect_calls += 1

    async def run_static_query(self, cypher):
        for label, rows in self.rows_by_label.items():
            if f"'{label}'" in cypher or f":{label} " in cypher or f"({label[:2].lower()}:{label}" in cypher:
                if label in self.raising:
                    raise RuntimeError(f"{label} query blew up")
                return rows
        return []


def make_orch(fake):
    o = TriageOrchestrator.__new__(TriageOrchestrator)
    o.user_id, o.project_id = "u", "p"
    o.neo4j = fake
    o.saved = []

    async def _save(rows):
        o.saved.append(rows)
    o._save_scores = _save
    return o


class TestScoreFindings(unittest.TestCase):
    def _fake(self, **kw):
        return FakeNeo4j({
            "Vulnerability": [{"id": "v1", "severity": "critical", "cisa_kev": True},
                              {"id": "v2", "severity": "low"}],
            "MalPackageFinding": [{"id": "m1", "severity": "high", "verdict": "malicious"}],
            "Secret": [{"id": "s1", "severity": "high", "validation_status": "validated"}],
        }, **kw)

    def test_all_labels_are_scored_and_ranked(self):
        o = make_orch(self._fake())
        scored = run(o._score_findings({"settings": {}}))
        ids = {r["id"] for r in scored}
        self.assertEqual(ids, {"v1", "v2", "m1", "s1"})
        # ranks assigned worst-first; the KEV critical and malicious pkg lead v2
        self.assertEqual(scored[0].get("rank"), 1)
        self.assertLess(
            next(r for r in scored if r["id"] == "v1")["rank"],
            next(r for r in scored if r["id"] == "v2")["rank"],
        )

    def test_scores_are_written(self):
        o = make_orch(self._fake())
        run(o._score_findings({"settings": {}}))
        self.assertTrue(o.saved, "no write happened")
        written = {r["id"] for batch in o.saved for r in batch}
        self.assertIn("v1", written)

    def test_a_raising_query_is_skipped_not_fatal(self):
        o = make_orch(self._fake(raising=["Secret"]))
        scored = run(o._score_findings({"settings": {}}))
        ids = {r["id"] for r in scored}
        self.assertIn("v1", ids)          # other labels still scored
        self.assertNotIn("s1", ids)       # the raising one dropped

    def test_no_findings_returns_empty(self):
        o = make_orch(FakeNeo4j({}))
        self.assertEqual(run(o._score_findings({"settings": {}})), [])

    def test_proven_flag_survives_to_the_return(self):
        o = make_orch(self._fake())
        scored = run(o._score_findings({"settings": {}}))
        malicious = next(r for r in scored if r["id"] == "m1")
        self.assertTrue(malicious["proven"])


class TestClusterAndExplainIsBestEffort(unittest.TestCase):
    def setUp(self):
        self.o = make_orch(FakeNeo4j({}))
        self.scored = [
            {"id": "a", "label": "Vulnerability", "name": "x", "severity": "high",
             "source": "nuclei", "host": "h", "score": 900.0, "signals": ["cisa_kev"],
             "proven": False, "status": None, "confidence": None},
        ]

    def test_an_llm_that_raises_does_not_crash_the_step(self):
        async def boom(*a, **k):
            raise RuntimeError("no model")
        self.o._call_llm = boom
        # must not raise; ranking already stands, nothing written back
        run(self.o._cluster_and_explain({"settings": {}}, self.scored))
        self.assertEqual(self.o.saved, [])

    def test_a_good_response_writes_back_reason_and_cluster(self):
        calls = {"n": 0}

        async def fake_llm(system, messages):
            calls["n"] += 1
            # first call is clustering, second is rationale
            if "cluster" in system.lower():
                text = '```json\n[{"id":"a","cluster_id":"grp-1"}]\n```'
            else:
                text = '```json\n[{"id":"a","reason":"because it matters"}]\n```'
            return {"content": [{"type": "text", "text": text}]}
        self.o._call_llm = fake_llm
        run(self.o._cluster_and_explain({"settings": {}}, self.scored))
        self.assertEqual(calls["n"], 2)
        self.assertTrue(self.o.saved)
        wb = self.o.saved[-1][0]
        self.assertEqual(wb["cluster_id"], "grp-1")
        self.assertEqual(wb["reason"], "because it matters")

    def test_an_id_not_in_the_batch_is_ignored(self):
        async def fake_llm(system, messages):
            return {"content": [{"type": "text",
                                 "text": '```json\n[{"id":"HALLUCINATED","reason":"x"}]\n```'}]}
        self.o._call_llm = fake_llm
        run(self.o._cluster_and_explain({"settings": {}}, self.scored))
        # nothing written back for an id we never asked about
        self.assertEqual(self.o.saved, [])


if __name__ == "__main__":
    unittest.main()
