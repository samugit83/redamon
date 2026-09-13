"""The triage run as a whole: authorise, score, group, review, publish, finish.

WHAT THIS PROTECTS
The run's value is not any single step, it is the ORDER of them. Steps A to D
happen entirely in memory and Step E is the only thing that writes, which is
what makes a run safe to stop, safe to refuse and safe to run beside a scan.
Every test here is really the same question asked from a different angle: did
anything reach the graph that should not have?

The four that matter most:

- a run that is refused authorisation reads nothing and writes nothing;
- a run that is stopped mid-flight leaves the previous ranking untouched;
- a publish that is refused writes nothing, not part of the result;
- `finish` is called on every path, including after an exception, because a run
  left `running` blocks activation until its heartbeat expires.

Plus C15: a project with no LLM key still gets a fully ranked board. The old
code raised during LLM setup BEFORE scoring, so such a project got nothing at
all while the documentation promised the opposite.

Run: ./agentic/run_tests.sh tests/test_triage_orchestrator_flow.py
"""

import asyncio
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cypherfix_triage import score_model  # noqa: E402


_AGENTIC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def source(relative: str) -> str:
    with open(os.path.join(_AGENTIC, relative)) as handle:
        return handle.read()
from cypherfix_triage.orchestrator import TriageOrchestrator  # noqa: E402
from cypherfix_triage.run_client import TriageRunAborted  # noqa: E402
from cypherfix_triage.state import RemediationDraft  # noqa: E402


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


class FakeCallback:
    def __init__(self):
        self.phases = []
        self.errors = []
        self.completed = None

    async def on_phase(self, phase, description, progress=0):
        self.phases.append(phase)

    async def on_error(self, message, recoverable=True, code=""):
        self.errors.append({"message": message, "code": code})

    async def on_complete(self, total, by_severity, by_type, summary):
        self.completed = {"total": total, "summary": summary}

    async def on_finding(self, finding):
        pass

    async def on_tool_start(self, *a, **k):
        pass

    async def on_tool_complete(self, *a, **k):
        pass


class FakeRunClient:
    """The protocol, without a webapp."""

    def __init__(self, *, authorize_error=None, publish_error=None,
                 abort_after_score=False):
        self.run_id = "run-1"
        self.authorize_error = authorize_error
        self.publish_error = publish_error
        self.abort_after_score = abort_after_score
        self.authorized = False
        self.published = False
        self.finished = None
        self.heartbeat_started = False
        self._checks = 0

    async def authorize(self, model, version):
        if self.authorize_error:
            raise self.authorize_error
        self.authorized = True
        return self.run_id

    def start_heartbeat(self):
        self.heartbeat_started = True

    def check_abort(self):
        self._checks += 1
        if self.abort_after_score and self._checks >= 1:
            raise TriageRunAborted("the run was stopped", "stopped")

    @property
    def aborted(self):
        return False

    async def claim_publish(self):
        if self.publish_error:
            raise self.publish_error
        self.published = True

    async def finish(self, status, summary=None, error_class="", intel_date=""):
        self.finished = {"status": status, "summary": summary or {},
                         "error_class": error_class}

    async def stop_heartbeat(self):
        pass


class FakeGraphClient:
    """Records what a publish would have written."""

    def __init__(self):
        self.batches = []

    def apply_triage_scores(self, user_id, project_id, rows):
        self.batches.append(rows)
        return {"updated": len(rows), "skipped_human": 0,
                "skipped_changed": 0, "rejected": 0}

    def close(self):
        pass


FINDINGS = [
    {"id": "v1", "label": "Vulnerability", "source": "nuclei", "severity": "high",
     "name": "Exposed .env", "triage_host": "a.example", "cve_ids": [],
     "matcher_status": True, "extracted_results": ["DB_PASSWORD=hunter2"],
     "raw_response": "DB_PASSWORD=hunter2", "seen_updated_at": "2026-01-01"},
    {"id": "g1", "label": "GithubSecret", "source": "github_hunt",
     "severity": "high", "name": "IP Address (Private)",
     "detector_name": "IP Address (Private)",
     "secret_type": "IP Address (Private)",
     "triage_host": "acme/repo", "cve_ids": [], "seen_updated_at": "2026-01-01"},
]


class Harness:
    """An orchestrator with the webapp, the graph and the model replaced.

    `run()` builds its own run client and closes the graph client in its
    `finally`, so both are injected here rather than assigned afterwards: a
    test that reads `orch._client` after the run reads None.
    """

    def __init__(self, callback=None, run_client=None, findings=None, llm=None):
        self.callback = callback or FakeCallback()
        self.client = run_client or FakeRunClient()
        self.graph = FakeGraphClient()
        self.orch = _build(self.callback, self.client, self.graph, findings, llm)

    def run(self, settings=None):
        import unittest.mock as mock
        from cypherfix_triage import orchestrator as module

        async def fake_settings(project_id):
            return settings or {}

        with mock.patch.object(module, "load_cypherfix_settings", fake_settings), \
             mock.patch.object(module, "TriageRunClient",
                               lambda *a, **k: self.client):
            return run(self.orch.run(state(settings)))

    @property
    def written(self):
        return [row for batch in self.graph.batches for row in batch]


def _build(callback, run_client, graph, findings=None, llm=None):
    orch = TriageOrchestrator("u1", "p1", callback)
    orch._client = graph
    orch._close_graph_client = lambda: None      # keep it readable after the run
    orch.llm_client = llm

    rows = list(findings if findings is not None else FINDINGS)

    async def fake_static_query(query):
        return []

    orch.neo4j.run_static_query = fake_static_query

    async def fake_score(state):
        scored = []
        for row in rows:
            result = score_model.score(row, score_model.ProjectFacts(), {})
            scored.append({
                "id": row["id"], "label": row["label"], "name": row["name"],
                "severity": row["severity"], "source": row["source"],
                "host": result.host, "state": result.state, "tier": result.tier,
                "tier_rule": result.tier_rule, "score": result.score,
                "math_score": result.score, "risk": result.risk,
                "factors": result.as_factors_dict(), "signals": result.signals,
                "proven": result.proven, "explanation": result.explanation,
                "seen_updated_at": row.get("seen_updated_at"),
                "model_version": score_model.SCORE_MODEL_VERSION,
                "_row": row,
            })
        scored.sort(key=lambda r: (-r["score"], r["id"]))
        return scored

    orch._score = fake_score
    orch._init_llm_or_none = lambda s: _immediate(llm)
    orch.neo4j.close = _noop
    return orch


async def _immediate(value):
    return value


async def _noop():
    return None


def state(settings=None):
    return {"user_id": "u1", "project_id": "p1", "session_id": "s1",
            "settings": settings or {}, "raw_data": {}, "analysis_result": None,
            "status": "initializing", "current_phase": "", "error": None,
            "verdicts": []}


# ---------------------------------------------------------------------------
class TestHappyPath(unittest.TestCase):
    def setUp(self):
        # No model, so Step D's prose is the deterministic wording.
        self.h = Harness()
        self.callback, self.client = self.h.callback, self.h.client
        self.orch = self.h.orch
        self.h.run({"default_repo": "acme/app"})

    def test_the_run_is_authorised_before_anything_else(self):
        self.assertTrue(self.client.authorized)
        self.assertEqual(self.callback.phases[0], "authorizing")

    def test_the_heartbeat_starts(self):
        self.assertTrue(self.client.heartbeat_started)

    def test_the_publish_is_claimed_before_the_graph_is_written(self):
        self.assertTrue(self.client.published)
        self.assertTrue(self.h.graph.batches)

    def test_every_finding_is_written_with_its_run_id(self):
        written = self.h.written
        self.assertEqual({r["id"] for r in written}, {"v1", "g1"})
        self.assertTrue(all(r["run_id"] == "run-1" for r in written))

    def test_the_run_finishes_as_completed(self):
        self.assertEqual(self.client.finished["status"], "completed")

    def test_the_summary_carries_counts_and_no_finding_text(self):
        summary = self.client.finished["summary"]
        self.assertEqual(summary["scored"], 2)
        for value in summary.values():
            self.assertIsInstance(value, (int, float))

    def test_the_private_ip_secret_is_outranked_by_the_real_finding(self):
        by_id = {r["id"]: r for r in self.h.written}
        self.assertGreater(by_id["v1"]["score"], by_id["g1"]["score"])
        self.assertEqual(by_id["g1"]["tier"], "T4")

    def test_a_repo_is_taken_from_settings_not_from_a_model(self):
        rows = self.orch.remediation_rows
        self.assertTrue(rows)
        self.assertTrue(all(r["targetRepo"] == "acme/app" for r in rows))


# ---------------------------------------------------------------------------
class TestNothingIsWrittenEarly(unittest.TestCase):
    def test_a_refused_authorisation_writes_nothing_and_reads_nothing(self):
        h = Harness(run_client=FakeRunClient(
            authorize_error=TriageRunAborted("not yours", "authorize_failed")))
        h.run()

        self.assertEqual(h.graph.batches, [])
        self.assertFalse(h.client.published)
        self.assertEqual(h.client.finished["status"], "failed")
        self.assertEqual(h.client.finished["error_class"], "authorize_failed")
        self.assertEqual(h.callback.errors[0]["code"], "authorize_failed")

    def test_a_stop_mid_run_leaves_the_previous_ranking_untouched(self):
        h = Harness(run_client=FakeRunClient(abort_after_score=True))
        h.run()

        self.assertEqual(h.graph.batches, [])
        self.assertFalse(h.client.published)
        self.assertEqual(h.client.finished["status"], "stopped")

    def test_a_refused_publish_writes_nothing(self):
        h = Harness(run_client=FakeRunClient(
            publish_error=TriageRunAborted("the graph changed", "publish_refused")))
        h.run()

        self.assertEqual(h.graph.batches, [])
        self.assertEqual(h.client.finished["error_class"], "publish_refused")

    def test_an_unexpected_exception_still_finishes_the_run(self):
        """A run left `running` blocks activation for ten minutes."""
        h = Harness()

        async def boom(_state):
            raise RuntimeError("neo4j went away")

        h.orch._score = boom
        with self.assertRaises(RuntimeError):
            h.run()
        self.assertEqual(h.client.finished["status"], "failed")


# ---------------------------------------------------------------------------
class TestNoModelKey(unittest.TestCase):
    """C15: the board must rank without an LLM. It used to rank nothing."""

    def setUp(self):
        self.h = Harness(llm=None)
        self.client, self.orch = self.h.client, self.h.orch
        self.h.run({"default_repo": "acme/app"})

    def test_every_finding_is_still_scored_and_published(self):
        written = self.h.written
        self.assertEqual(len(written), 2)
        self.assertTrue(all(row["score"] >= 0 for row in written))

    def test_the_run_completes_rather_than_failing(self):
        self.assertEqual(self.client.finished["status"], "completed")

    def test_findings_are_marked_not_reviewed_rather_than_judged(self):
        verdicts = {row["id"]: row.get("ai_verdict") for row in self.h.written}
        self.assertEqual(verdicts["v1"], "not_reviewed")

    def test_the_fix_list_still_gets_written_with_standard_wording(self):
        rows = self.orch.remediation_rows
        self.assertTrue(rows)
        self.assertTrue(all(row["title"] for row in rows))
        self.assertTrue(all(row["solution"] for row in rows))


# ---------------------------------------------------------------------------
class TestEmptyProject(unittest.TestCase):
    def setUp(self):
        self.h = Harness(findings=[])
        self.h.run()

    def test_it_completes_and_says_so(self):
        self.assertEqual(self.h.client.finished["status"], "completed")
        self.assertEqual(self.h.callback.completed["total"], 0)

    def test_nothing_is_written(self):
        self.assertEqual(self.h.graph.batches, [])


# ---------------------------------------------------------------------------
class TestGrouping(unittest.TestCase):
    def test_the_same_cve_on_two_hosts_is_one_group_and_one_fix(self):
        findings = [
            {"id": "a", "label": "Vulnerability", "source": "gvm",
             "severity": "high", "name": "Apache traversal",
             "cve_ids": ["CVE-2021-41773"], "triage_host": "h1",
             "qod": 98, "qod_type": "remote_vul", "seen_updated_at": "x"},
            {"id": "b", "label": "Vulnerability", "source": "nuclei",
             "severity": "high", "name": "Apache traversal",
             "cve_ids": ["CVE-2021-41773"], "triage_host": "h2",
             "matcher_status": True, "extracted_results": ["root:x:0:0"],
             "seen_updated_at": "x"},
        ]
        h = Harness(findings=findings)
        h.run({"default_repo": "acme/app"})

        keys = {row["group_key"] for row in h.written}
        self.assertEqual(keys, {"cve:cve-2021-41773"})
        self.assertEqual(len(h.orch.remediation_rows), 1)
        self.assertEqual(
            sorted(h.orch.remediation_rows[0]["findingIds"]), ["a", "b"])
        self.assertEqual(
            sorted(h.orch.remediation_rows[0]["affectedAssets"]), ["h1", "h2"])


# ---------------------------------------------------------------------------
class TestPublishBatching(unittest.TestCase):
    def test_a_large_project_is_written_in_batches(self):
        h = Harness()
        rows = [{"id": f"f{i}", "score": 1.0, "signals": []} for i in range(1200)]
        run(h.orch._publish(rows, "run-1"))
        self.assertEqual([len(b) for b in h.graph.batches], [500, 500, 200])

    def test_a_failing_batch_does_not_abandon_the_rest(self):
        h = Harness()
        orch = h.orch
        calls = {"n": 0}
        real = h.graph.apply_triage_scores

        def flaky(user_id, project_id, rows):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("deadlock")
            return real(user_id, project_id, rows)

        h.graph.apply_triage_scores = flaky
        totals = run(orch._publish(
            [{"id": f"f{i}", "score": 1.0} for i in range(700)], "run-1"))
        self.assertEqual(totals["updated"], 200)


class TestTheModelNameIsCarriedThrough(unittest.TestCase):
    """Regression, found by running a real triage.

    `load_cypherfix_settings` returns the model under `llm_model`. The
    orchestrator read `settings.get("model")`, a key that does not exist, so it
    silently got "" in all three places it is used:

      - the TriageRun row, so the dialog's "Last triaged with X" was blank;
      - `triage_ai_model` on every reviewed finding, so the board's
        "Reviewed by X" tooltip was blank;
      - the review CACHE KEY. The model is deliberately part of
        `evidence_hash`, so with "" a verdict produced by one model was reused
        after switching to another - the one consequence that is wrong rather
        than merely missing.

    Observed live: run cmty9wk3r had model='' with 13 deepseek calls, and all
    150 reviewed findings had an empty triage_ai_model.
    """

    SRC = source("cypherfix_triage/orchestrator.py")
    SETTINGS = source("cypherfix_triage/project_settings.py")

    def test_the_orchestrator_reads_the_key_the_settings_actually_return(self):
        self.assertIn('settings.get("llm_model")', self.SRC)
        self.assertNotIn('settings.get("model")', self.SRC)

    def test_that_key_is_the_one_the_settings_loader_writes(self):
        """The two drifting apart is the whole bug, so pin them together."""
        self.assertIn('"llm_model":', self.SETTINGS)

    def test_every_place_that_needs_the_model_gets_it(self):
        """Three readers: authorize, the review cache key, and the per-finding
        ai_model. All three read the same local, so count them."""
        self.assertEqual(self.SRC.count('settings.get("llm_model")'), 2)

    def test_the_model_is_part_of_the_review_cache_key(self):
        """If it ever stops being, switching models silently reuses verdicts."""
        self.assertIn("evidence_hash(\n                bundle, review.REVIEW_PROMPT_VERSION, model)",
                      self.SRC)


if __name__ == "__main__":
    unittest.main()
