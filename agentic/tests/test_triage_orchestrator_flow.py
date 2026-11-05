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

And the layered model (v3.2): a review lasts until its evidence changes, not one
run (B1); a run never re-reads over a still-valid external review; groups follow
the final values (B5); a failed batch makes the run `completed_partial` (B21); a
Stop is recorded as `stopped` (B11) and never splits a publish (B17).

Run: ./agentic/run_tests.sh tests/test_triage_orchestrator_flow.py
"""

import asyncio
import json
import os
import re
import sys
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cypherfix_triage import evidence, score_model  # noqa: E402
from cypherfix_triage.fact_queries import STORED_LAYERS  # noqa: E402


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

    async def on_error(self, message, recoverable=True, code="", **details):
        self.errors.append({"message": message, "code": code, **details})

    async def on_complete(self, total, by_severity, by_type, summary, **notices):
        self.completed = {"total": total, "summary": summary, **notices}

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

    async def authorize(self, model, version, **kwargs):
        if self.authorize_error:
            raise self.authorize_error
        self.authorized = True
        self.authorize_args = {"model": model, **kwargs}
        return self.run_id

    def start_heartbeat(self):
        self.heartbeat_started = True

    def set_progress(self, phase, progress):
        self.phase = phase

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
    """A graph that remembers what each publish wrote, like the real nodes do.

    `publish_triage_layers` runs the orchestrator's own `combine` against the
    node's CURRENT properties, exactly as the mixin does inside its write
    transaction, so a second run reads back what the first one published.
    """

    def __init__(self):
        self.batches = []
        self.written = []
        self.nodes: dict = {}
        self.proven: dict = {}
        self.fail_batches = 0

    def stored_rows(self):
        return [{"id": node_id, "label": props.get("_label", ""),
                 **{k: v for k, v in props.items() if k.startswith("triage_")}}
                for node_id, props in self.nodes.items()]

    def publish_triage_layers(self, user_id, project_id, rows, combine):
        if self.fail_batches:
            self.fail_batches -= 1
            raise RuntimeError("deadlock, after the driver's retries")
        self.batches.append(rows)
        reviews = 0
        for row in rows:
            props = dict(self.nodes.get(row["id"], {}))
            outcome = combine(row, props, self.proven.get(row["id"], False))
            final = outcome["final"]
            new = dict(props)
            new.update({
                "_label": row["label"],
                "triage_base_factors": row["base_factors"],
                "triage_base_tier": row["base_tier"],
                "triage_base_tier_rule": row["base_tier_rule"],
                "triage_base_state": row["base_state"],
                "triage_tier_inputs": row["tier_inputs"],
                "triage_math_score": row["math_score"],
                "triage_evidence_hash": row["evidence_hash"],
                "triage_run_id": row["run_id"],
            })
            if outcome["review"]:
                new.update(outcome["review"])
                reviews += 1
            elif row.get("mark_not_reviewed") and not new.get("triage_ai_verdict"):
                new["triage_ai_verdict"] = "not_reviewed"
            new.update(triage_priority_score=final["score"], triage_tier=final["tier"],
                       triage_state=final["state"], triage_decided_by=final["decided_by"])
            self.nodes[row["id"]] = new
            self.written.append({**row, **final, "written_review": outcome["review"]})
        return {"updated": len(rows), "skipped_changed": 0, "missing": 0,
                "reviews_written": reviews, "rejected": 0}

    def close(self):
        pass


class FakeLLM:
    """A model that answers per finding id, and records which ids it was asked."""

    def __init__(self, answer_for):
        self.answer_for = answer_for
        self.asked: list = []

    async def ainvoke(self, messages):
        text = messages[-1].content
        ids = re.findall(r"--- FINDING (\S+) ---", text)
        self.asked.extend(ids)
        answers = []
        for finding_id in ids:
            answer = self.answer_for(finding_id)
            if answer:
                answers.append({"id": finding_id, **answer})
        return SimpleNamespace(content="```json\n" + json.dumps(answers) + "\n```")


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

    def __init__(self, callback=None, run_client=None, findings=None, llm=None,
                 graph=None, **orch_kwargs):
        self.callback = callback or FakeCallback()
        self.client = run_client or FakeRunClient()
        self.graph = graph or FakeGraphClient()
        self.orch = _build(self.callback, self.client, self.graph, findings, llm,
                           **orch_kwargs)

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
        """What the publish wrote, with the final values combine produced."""
        return list(self.graph.written)


def _build(callback, run_client, graph, findings=None, llm=None, **orch_kwargs):
    orch = TriageOrchestrator("u1", "p1", callback, **orch_kwargs)
    orch._client = graph
    orch._close_graph_client = lambda: None      # keep it readable after the run
    orch.llm_client = llm

    rows = list(findings if findings is not None else FINDINGS)

    async def fake_static_query(query, params=None):
        if query == STORED_LAYERS["query"]:
            return graph.stored_rows()
        return []

    orch.neo4j.run_static_query = fake_static_query

    async def fake_score(state):
        facts = score_model.ProjectFacts()
        scored = []
        for row in rows:
            result = score_model.score(row, facts, {})
            scored.append(TriageOrchestrator.scored_row(row, result, facts))
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
        self.h.run({"default_repo": "acme/app", "triageReviewBudget": 0})

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

    def test_the_base_layer_is_published_beside_the_result(self):
        v1 = {r["id"]: r for r in self.h.written}["v1"]
        self.assertIn("C", v1["base_factors"])
        self.assertEqual(v1["math_score"], v1["score"])
        self.assertEqual(v1["decided_by"], "rules")
        self.assertEqual(len(v1["evidence_hash"]), 40)
        self.assertEqual(set(v1["tier_inputs"]), {"proven", "kev", "gates"})
        self.assertEqual(set(v1["tier_inputs"]["gates"]),
                         {"reachable_now", "attributed", "controlled", "impactful"})

    def test_the_run_never_writes_a_decision(self):
        for row in self.h.written:
            self.assertFalse({"status", "confidence", "reason"} & set(row))

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
        self.h.run({"default_repo": "acme/app", "triageReviewBudget": 0})

    def test_every_finding_is_still_scored_and_published(self):
        written = self.h.written
        self.assertEqual(len(written), 2)
        self.assertTrue(all(row["score"] >= 0 for row in written))

    def test_the_run_completes_rather_than_failing(self):
        self.assertEqual(self.client.finished["status"], "completed")

    def test_findings_are_marked_not_reviewed_rather_than_judged(self):
        self.assertEqual(self.h.graph.nodes["v1"]["triage_ai_verdict"], "not_reviewed")
        self.assertTrue(all(row["written_review"] is None for row in self.h.written))

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
        h.run({"default_repo": "acme/app", "triageReviewBudget": 0})

        keys = {row["group_key"] for row in h.written}
        self.assertEqual(keys, {"cve:cve-2021-41773"})
        self.assertEqual(len(h.orch.remediation_rows), 1)
        self.assertEqual(
            sorted(h.orch.remediation_rows[0]["findingIds"]), ["a", "b"])
        self.assertEqual(
            sorted(h.orch.remediation_rows[0]["affectedAssets"]), ["h1", "h2"])


# ---------------------------------------------------------------------------
def _publish_row(i: int) -> dict:
    result = score_model.score({"id": f"f{i}", "label": "Vulnerability"})
    return TriageOrchestrator.scored_row(
        {"id": f"f{i}", "label": "Vulnerability"}, result, score_model.ProjectFacts())


class TestPublishBatching(unittest.TestCase):
    def test_a_large_project_is_written_in_batches(self):
        h = Harness()
        rows = [_publish_row(i) for i in range(1200)]
        run(h.orch._publish(rows, "run-1"))
        self.assertEqual([len(b) for b in h.graph.batches], [500, 500, 200])

    def test_a_failing_batch_does_not_abandon_the_rest_and_is_counted(self):
        h = Harness()
        h.graph.fail_batches = 1
        totals = run(h.orch._publish([_publish_row(i) for i in range(700)], "run-1"))
        self.assertEqual(totals["updated"], 200)
        self.assertEqual(totals["publish_failed"], 500)

    def test_a_failed_batch_makes_the_run_completed_partial(self):
        """B21: a deadlock that outlasted the driver's retries used to be logged
        and skipped, and the run still ended `completed`."""
        h = Harness()
        h.graph.fail_batches = 1
        h.run({"default_repo": "acme/app", "triageReviewBudget": 0})
        self.assertEqual(h.client.finished["status"], "completed_partial")
        self.assertEqual(h.client.finished["error_class"], "publish_failed")
        self.assertEqual(h.client.finished["summary"]["publish_failed"], 2)


class TestTheTriageModelIsTheOwnersOwn(unittest.TestCase):
    """Models by feature (D7a): a review needs the owner's Triage review model,
    and nothing stands in for it; budget 0 ranks with no model at all."""

    def test_a_budget_with_no_model_is_refused_before_anything_is_read(self):
        h = Harness()
        h.run({"default_repo": "acme/app", "triageReviewBudget": 150, "llm_model": ""})
        self.assertFalse(h.client.authorized)
        self.assertEqual(h.callback.errors[-1]["code"], "model_required")
        self.assertFalse(h.graph.batches)

    def test_a_failed_settings_fetch_is_not_reported_as_model_required(self):
        """Review finding: the owner was asked to pick a model they already had."""
        h = Harness()
        h.run({"default_repo": "acme/app", "triageReviewBudget": 150, "llm_model": "",
               "settings_unavailable": True})
        self.assertFalse(h.client.authorized)
        self.assertEqual(h.callback.errors[-1]["code"], "settings_unavailable")
        self.assertFalse(h.graph.batches)

    def test_budget_zero_still_ranks_when_the_settings_could_not_be_read(self):
        h = Harness()

        async def no_llm(_settings):
            return None

        h.orch._init_llm_or_none = no_llm
        h.run({"default_repo": "acme/app", "triageReviewBudget": 0, "llm_model": "",
               "settings_unavailable": True})
        self.assertEqual(h.client.finished["status"], "completed")

    def test_budget_zero_with_no_model_ranks_and_never_builds_a_model(self):
        h = Harness()
        built = []

        async def tripwire(settings):
            built.append(settings)
            return None

        h.orch._init_llm_or_none = tripwire
        h.run({"default_repo": "acme/app", "triageReviewBudget": 0, "llm_model": ""})
        self.assertEqual(h.client.finished["status"], "completed")
        self.assertEqual(built, [])
        self.assertTrue(h.graph.batches)

    def test_a_set_model_is_built(self):
        h = Harness()
        built = []

        async def record(settings):
            built.append(settings.get("llm_model"))
            return None

        h.orch._init_llm_or_none = record
        h.run({"default_repo": "acme/app", "triageReviewBudget": 0,
               "llm_model": "gpt-5-mini"})
        self.assertEqual(built, ["gpt-5-mini"])

    def test_the_loader_reads_the_owners_feature_model_not_the_project(self):
        self.assertIn('feature_model(settings.get("user_settings"), "triage")',
                      source("cypherfix_triage/project_settings.py"))
        self.assertNotIn("cypherfixLlmModel", source("cypherfix_triage/project_settings.py"))
        self.assertNotIn("agentOpenaiModel", source("cypherfix_triage/project_settings.py"))


class TestTheModelNameIsCarriedThrough(unittest.TestCase):
    """Regression, found by running a real triage.

    `load_cypherfix_settings` returns the model under `llm_model`. The
    orchestrator once read `settings.get("model")`, a key that does not exist,
    so the run recorded no model, every review recorded no model, and a switch
    of model silently reused the previous one's verdicts.
    """

    SRC = source("cypherfix_triage/orchestrator.py")
    SETTINGS = source("cypherfix_triage/project_settings.py")

    def test_the_orchestrator_reads_the_key_the_settings_actually_return(self):
        self.assertIn('settings.get("llm_model")', self.SRC)
        self.assertNotIn('settings.get("model")', self.SRC)

    def test_that_key_is_the_one_the_settings_loader_writes(self):
        """The two drifting apart is the whole bug, so pin them together."""
        self.assertIn('"llm_model":', self.SETTINGS)

    def test_the_run_authorises_with_the_model(self):
        h = Harness(llm=FakeLLM(lambda i: None))
        h.run(dict(REVIEW_SETTINGS))
        self.assertEqual(h.client.authorize_args["model"], "fake-model")

    def test_a_review_records_its_model(self):
        h = Harness(llm=FakeLLM(_doubtful_v1))
        h.run(dict(REVIEW_SETTINGS))
        self.assertEqual(h.graph.nodes["v1"]["triage_ai_model"], "fake-model")


# ---------------------------------------------------------------------------
# The layered model
# ---------------------------------------------------------------------------
REVIEW_SETTINGS = {"default_repo": "acme/app", "triageReviewBudget": 10,
                   "llm_model": "fake-model"}
NO_MODEL = {"default_repo": "acme/app", "triageReviewBudget": 0, "llm_model": ""}


def _doubtful_v1(finding_id):
    if finding_id == "v1":
        return {"verdict": "doubtful", "evidence_quote": "Finding: Exposed .env",
                "why": "a sample file", "fix_lever": "remove the file"}
    return None


def _v1_hash() -> str:
    return evidence.bundle_hash(evidence.build_bundle(FINDINGS[0]))


def _external_review(verdict="doubtful", digest=None, channel="mcp", model="",
                     prompt_version=""):
    return {
        "_label": "Vulnerability",
        "triage_ai_verdict": verdict,
        "triage_ai_corrections": json.dumps({"verdict": verdict, "impact_multiplier": 1.0,
                                             "impact_quote": "", "disputed_facts": []}),
        "triage_ai_channel": channel,
        "triage_ai_by": "rdmn_mcp_0000abcd" if channel == "mcp" else "",
        "triage_ai_model": model,
        "triage_ai_prompt_version": prompt_version,
        "triage_ai_evidence_hash": digest or _v1_hash(),
        "triage_fix_lever": "agent-written lever",
        "triage_ai_quote": "Finding: Exposed .env",
    }


class TestAReviewLastsUntilTheEvidenceChanges(unittest.TestCase):
    """B1: the review used to be replaced by `unclear` at the very next run."""

    def setUp(self):
        self.graph = FakeGraphClient()
        first = Harness(llm=FakeLLM(_doubtful_v1), graph=self.graph)
        first.run(dict(REVIEW_SETTINGS))
        self.first = {r["id"]: r for r in first.written}

    def test_the_first_run_writes_the_review_and_moves_the_score(self):
        v1 = self.first["v1"]
        self.assertEqual(v1["written_review"]["triage_ai_verdict"], "doubtful")
        self.assertEqual(v1["written_review"]["triage_ai_channel"], "builtin")
        self.assertLess(v1["score"], v1["math_score"])
        self.assertEqual(v1["decided_by"], "review")

    def test_a_second_unchanged_run_keeps_it_without_asking_again(self):
        llm = FakeLLM(lambda i: {"verdict": "real", "evidence_quote": "Finding: Exposed .env"})
        second = Harness(llm=llm, graph=self.graph)
        second.run(dict(REVIEW_SETTINGS))
        v1 = {r["id"]: r for r in second.written}["v1"]
        self.assertNotIn("v1", llm.asked)
        self.assertIsNone(v1["written_review"])
        self.assertEqual(v1["score"], self.first["v1"]["score"])
        self.assertEqual(self.graph.nodes["v1"]["triage_ai_verdict"], "doubtful")
        self.assertEqual(second.client.finished["summary"]["reviews_kept"], 1)

    def test_a_no_model_run_keeps_the_stored_review(self):
        third = Harness(llm=None, graph=self.graph)
        third.run(dict(NO_MODEL))
        v1 = {r["id"]: r for r in third.written}["v1"]
        self.assertEqual(v1["score"], self.first["v1"]["score"])
        self.assertEqual(self.graph.nodes["v1"]["triage_ai_verdict"], "doubtful")

    def test_changed_evidence_retires_the_review(self):
        changed = [dict(FINDINGS[0], raw_response="entirely different body"), FINDINGS[1]]
        later = Harness(llm=None, graph=self.graph, findings=changed)
        later.run(dict(NO_MODEL))
        v1 = {r["id"]: r for r in later.written}["v1"]
        self.assertEqual(v1["score"], v1["math_score"])
        self.assertEqual(v1["decided_by"], "rules")


class _RateLimited(Exception):
    status_code = 429


class _RefusingLLM:
    """A provider that answers every review call with an error."""

    def __init__(self, error):
        self.error = error

    async def ainvoke(self, _messages):
        raise self.error


class _RateLimitedOnce:
    """A provider whose first call meets a full per-minute window, then answers."""

    def __init__(self):
        self.calls = 0

    async def ainvoke(self, _messages):
        from langchain_core.messages import AIMessage
        self.calls += 1
        if self.calls == 1:
            raise _RateLimited("Rate limit reached for key sk-live-123")
        return AIMessage(content="[]")


class TestAFailedReviewIsReported(unittest.TestCase):
    """G-6: a run whose reviews all failed used to complete looking clean."""

    def test_the_complete_event_counts_failed_batches_with_the_provider_status(self):
        import unittest.mock as mock
        h = Harness(llm=_RefusingLLM(_RateLimited("quota for key sk-live-123")))
        # No rate-limit waiting: every review fails at its first refusal.
        with mock.patch.dict(os.environ, {"LLM_RATE_LIMIT_MAX_WAIT_S": "0"}):
            h.run(dict(REVIEW_SETTINGS))
        self.assertEqual(h.client.finished["status"], "completed")
        self.assertGreaterEqual(h.callback.completed["review_failed"], 1)
        self.assertEqual(h.callback.completed["provider_status"], 429)
        self.assertEqual(h.callback.completed["error_class"], "_RateLimited")
        self.assertNotIn("sk-live-123", json.dumps(h.callback.completed))
        self.assertEqual(h.client.finished["summary"]["review_failed"],
                         h.callback.completed["review_failed"])

    def test_a_rate_limit_that_clears_is_waited_out_not_reported(self):
        import unittest.mock as mock
        from orchestrator_helpers.llm_retry import RateLimitWaiter
        llm = _RateLimitedOnce()
        h = Harness(llm=llm)
        with mock.patch.object(RateLimitWaiter, "next_wait_s", return_value=0.0):
            h.run(dict(REVIEW_SETTINGS))
        self.assertGreaterEqual(llm.calls, 2)
        self.assertEqual(h.callback.completed.get("review_failed", 0), 0)
        self.assertNotIn("provider_status", h.callback.completed)

    def test_a_model_that_could_not_be_set_up_is_reported(self):
        h = Harness(llm=None)
        h.orch.llm_setup_failure = {"error_class": "ValueError"}
        h.run(dict(REVIEW_SETTINGS))
        self.assertEqual(h.callback.completed["review_unavailable"], 1)
        self.assertEqual(h.callback.completed["error_class"], "ValueError")

    def test_a_run_with_no_review_expected_carries_no_notice(self):
        h = Harness(llm=None)
        h.run(dict(NO_MODEL))
        self.assertNotIn("review_failed", h.callback.completed)
        self.assertNotIn("review_unavailable", h.callback.completed)

    def test_a_clean_review_carries_no_notice(self):
        h = Harness(llm=FakeLLM(_doubtful_v1))
        h.run(dict(REVIEW_SETTINGS))
        self.assertNotIn("review_failed", h.callback.completed)


class TestARefusalSaysWhy(unittest.TestCase):
    """G-33/G-49: the webapp's own refusal and the code reach the tab."""

    def test_an_authorize_refusal_carries_the_webapp_reason_and_status(self):
        refusal = TriageRunAborted(
            "busy", "authorize_failed",
            public_reason="A triage run is already in progress for this project.",
            details={"upstream_status": 409})
        h = Harness(run_client=FakeRunClient(authorize_error=refusal))
        h.run()
        error = h.callback.errors[0]
        self.assertEqual(error["code"], "authorize_failed")
        self.assertEqual(error["upstream_status"], 409)
        self.assertTrue(error["message"].startswith(
            "The triage run could not be authorised and did not start."))
        self.assertIn("already in progress", error["message"])

    def test_a_lost_run_has_its_own_sentence(self):
        h = Harness(run_client=FakeRunClient(
            publish_error=TriageRunAborted("stale", "agent_lost")))
        h.run()
        error = h.callback.errors[0]
        self.assertEqual(error["code"], "agent_lost")
        self.assertIn("stopped checking in", error["message"])
        self.assertNotIn("Something went wrong", error["message"])


class TestExternalReviews(unittest.TestCase):
    def test_a_valid_external_review_is_never_re_reviewed_or_replaced(self):
        graph = FakeGraphClient()
        graph.nodes["v1"] = _external_review("doubtful")
        llm = FakeLLM(lambda i: {"verdict": "real", "evidence_quote": "Finding: Exposed .env"})
        h = Harness(llm=llm, graph=graph)
        h.run(dict(REVIEW_SETTINGS))
        v1 = {r["id"]: r for r in h.written}["v1"]
        self.assertNotIn("v1", llm.asked)
        self.assertIsNone(v1["written_review"])
        self.assertEqual(graph.nodes["v1"]["triage_ai_channel"], "mcp")
        self.assertEqual(v1["decided_by"], "review")
        self.assertEqual(h.client.finished["summary"]["external_reviews"], 1)

    def test_a_stale_external_review_is_re_reviewed(self):
        graph = FakeGraphClient()
        graph.nodes["v1"] = _external_review("doubtful", digest="f" * 40)
        llm = FakeLLM(_doubtful_v1)
        Harness(llm=llm, graph=graph).run(dict(REVIEW_SETTINGS))
        self.assertIn("v1", llm.asked)
        self.assertEqual(graph.nodes["v1"]["triage_ai_channel"], "builtin")

    def test_a_model_change_re_reviews_builtin_reviews_only(self):
        graph = FakeGraphClient()
        graph.nodes["v1"] = _external_review("doubtful", channel="builtin",
                                             model="old-model", prompt_version="review-v2")
        g1_hash = evidence.bundle_hash(evidence.build_bundle(FINDINGS[1]))
        graph.nodes["g1"] = {**_external_review("doubtful", digest=g1_hash),
                             "_label": "GithubSecret"}
        llm = FakeLLM(lambda i: None)
        Harness(llm=llm, graph=graph).run(dict(REVIEW_SETTINGS))
        self.assertIn("v1", llm.asked)
        self.assertNotIn("g1", llm.asked)

    def test_an_external_agent_s_fix_lever_never_reaches_the_fix_list(self):
        graph = FakeGraphClient()
        graph.nodes["v1"] = _external_review("real")
        h = Harness(llm=None, graph=graph)
        h.run(dict(NO_MODEL))
        for row in h.orch.remediation_rows:
            self.assertNotIn("agent-written lever", row["solution"])
            self.assertNotEqual(row["evidence"], "Finding: Exposed .env")

    def test_a_decision_given_during_the_run_wins_at_publish(self):
        """The publish re-reads the decision under the node lock."""
        graph = FakeGraphClient()
        llm = FakeLLM(_doubtful_v1)
        h = Harness(llm=llm, graph=graph)
        real_publish = graph.publish_triage_layers

        def with_a_verdict(user_id, project_id, rows, combine):
            graph.nodes.setdefault("v1", {}).update(
                triage_status="confirmed", triage_source="human")
            return real_publish(user_id, project_id, rows, combine)

        graph.publish_triage_layers = with_a_verdict
        h.run(dict(REVIEW_SETTINGS))
        v1 = {r["id"]: r for r in h.written}["v1"]
        self.assertEqual(v1["decided_by"], "person")
        self.assertIsNone(v1["written_review"])
        self.assertEqual(v1["factors"]["C"]["value"], 1.0)


class TestLegacyAdoption(unittest.TestCase):
    def test_an_unchanged_v31_review_is_kept_as_a_builtin_review(self):
        graph = FakeGraphClient()
        legacy_hash = evidence.evidence_hash(
            evidence.build_bundle_legacy(FINDINGS[0]), "review-v1", "old-model")
        graph.nodes["v1"] = {
            "_label": "Vulnerability",
            "triage_ai_verdict": "false_positive", "triage_ai_model": "old-model",
            "triage_ai_corrections": json.dumps({"verdict": "false_positive",
                                                 "impact_multiplier": 0.6,
                                                 "disputed_facts": []}),
            "triage_ai_quote": "Finding: Exposed .env",
            "triage_status": "likely_noise", "triage_source": "ai",
            "triage_reason": "the response is a sample",
            "triage_evidence_hash": legacy_hash,
        }
        findings = [dict(FINDINGS[0], triage_status="likely_noise", triage_source="ai"),
                    FINDINGS[1]]
        h = Harness(llm=None, graph=graph, findings=findings)
        h.run(dict(NO_MODEL))
        v1 = {r["id"]: r for r in h.written}["v1"]
        self.assertEqual(h.client.finished["summary"]["reviews_adopted"], 1)
        review = v1["written_review"]
        self.assertEqual(review["triage_ai_channel"], "builtin")
        self.assertEqual(review["triage_ai_evidence_hash"], _v1_hash())
        self.assertEqual(review["triage_ai_prompt_version"], "review-v1")
        self.assertEqual(review["triage_ai_why"], "the response is a sample")
        self.assertEqual(review["triage_ai_corrections"]["impact_multiplier"], 1.0)
        self.assertEqual(v1["state"], "false_positive")

    def test_a_v31_review_whose_evidence_changed_is_dropped(self):
        graph = FakeGraphClient()
        graph.nodes["v1"] = {"_label": "Vulnerability", "triage_ai_verdict": "doubtful",
                             "triage_ai_model": "m", "triage_evidence_hash": "0" * 40}
        h = Harness(llm=None, graph=graph)
        h.run(dict(NO_MODEL))
        v1 = {r["id"]: r for r in h.written}["v1"]
        self.assertEqual(h.client.finished["summary"]["reviews_adopted"], 0)
        self.assertEqual(v1["decided_by"], "rules")


def _cve_findings():
    return [
        {"id": "a", "label": "Vulnerability", "source": "gvm",
         "severity": "high", "name": "Apache traversal",
         "cve_ids": ["CVE-2021-41773"], "triage_host": "h1",
         "qod": 98, "qod_type": "remote_vul", "seen_updated_at": "x",
         "description": "Apache path traversal"},
        {"id": "b", "label": "Vulnerability", "source": "nuclei",
         "severity": "high", "name": "Apache traversal",
         "cve_ids": ["CVE-2021-41773"], "triage_host": "h2",
         "matcher_status": True, "extracted_results": ["root:x:0:0"],
         "raw_response": "HTTP/1.1 404 Not Found", "seen_updated_at": "x"},
    ]


class TestGroupsFollowTheFinalValues(unittest.TestCase):
    def test_a_false_positive_found_by_this_run_leaves_its_group(self):
        """B5: groups were scored before the review."""
        llm = FakeLLM(lambda i: {"verdict": "false_positive",
                                 "evidence_quote": "HTTP/1.1 404 Not Found"} if i == "b" else None)
        h = Harness(llm=llm, findings=_cve_findings())
        h.run(dict(REVIEW_SETTINGS))
        self.assertEqual(h.orch.remediation_rows[0]["liveMemberCount"], 1)

    def test_an_external_agent_s_false_positive_keeps_its_fix_item_member(self):
        """P2: an external review can never silently delete a fix item."""
        findings = _cve_findings()
        graph = FakeGraphClient()
        b_hash = evidence.bundle_hash(evidence.build_bundle(findings[1]))
        graph.nodes["b"] = _external_review("false_positive", digest=b_hash)
        h = Harness(llm=None, findings=findings, graph=graph)
        h.run(dict(NO_MODEL))
        b = {r["id"]: r for r in h.written}["b"]
        self.assertEqual(b["state"], "false_positive")
        self.assertEqual(h.orch.remediation_rows[0]["liveMemberCount"], 2)


class TestStopAndBudget(unittest.TestCase):
    def test_a_cancelled_run_is_recorded_as_stopped(self):
        """B11: a Stop used to be recorded as `failed`."""
        h = Harness()

        async def cancelled(state, scored):
            raise asyncio.CancelledError()

        h.orch._remediate = cancelled
        with self.assertRaises(asyncio.CancelledError):
            h.run(dict(NO_MODEL))
        self.assertEqual(h.client.finished["status"], "stopped")
        self.assertEqual(h.graph.batches, [])

    def test_a_run_that_lost_its_heartbeat_during_the_fix_items_does_not_publish(self):
        """Two failed heartbeats set the abort; nothing checked it again before
        the publish, which then ran with no heartbeat and could be declared lost
        mid-write."""
        client = FakeRunClient()
        lost = {"now": False}

        def check_abort():
            if lost["now"]:
                raise TriageRunAborted("the webapp could not be reached", "stopped")

        client.check_abort = check_abort
        h = Harness(run_client=client)
        remediate = h.orch._remediate

        async def remediate_then_lose(state, scored):
            out = await remediate(state, scored)
            lost["now"] = True
            return out

        h.orch._remediate = remediate_then_lose
        h.run(dict(NO_MODEL))
        self.assertFalse(client.published)
        self.assertEqual(h.graph.batches, [])
        self.assertEqual(client.finished["status"], "stopped")

    def test_a_stop_during_authorize_still_closes_the_row(self):
        """The webapp creates the row inside `authorize`; a cancel that cut the
        call short left the run without its id, so `finish` never closed the row
        and it blocked the project for ten minutes."""
        import unittest.mock as mock
        from cypherfix_triage import orchestrator as module

        class SlowAuthorize(FakeRunClient):
            async def authorize(self, model, version, **kwargs):
                self.started.set()
                await self.gate.wait()
                self.run_id = "run-1"
                return self.run_id

            async def finish(self, status, summary=None, error_class="", intel_date=""):
                self.finished = {"status": status, "run_id": self.run_id}

        client = SlowAuthorize()
        client.run_id = None
        h = Harness(run_client=client)

        async def fake_settings(project_id):
            return dict(NO_MODEL)

        async def scenario():
            client.started, client.gate = asyncio.Event(), asyncio.Event()
            task = asyncio.ensure_future(h.orch.run(state(dict(NO_MODEL))))
            await client.started.wait()
            task.cancel()
            await asyncio.sleep(0)
            client.gate.set()
            with self.assertRaises(asyncio.CancelledError):
                await task

        with mock.patch.object(module, "load_cypherfix_settings", fake_settings), \
             mock.patch.object(module, "TriageRunClient", lambda *a, **k: client):
            run(scenario())
        self.assertEqual(client.finished, {"status": "stopped", "run_id": "run-1"})

    def test_a_cancel_during_the_publish_lets_it_finish(self):
        """B17: half the batches and no fix list is worse than either."""
        h = Harness()
        entered, release = asyncio.Event(), asyncio.Event()
        real_publish = h.orch._publish

        async def slow_publish(scored, run_id):
            entered.set()
            await release.wait()
            return await real_publish(scored, run_id)

        h.orch._publish = slow_publish

        async def scenario():
            import unittest.mock as mock
            from cypherfix_triage import orchestrator as module

            async def fake_settings(project_id):
                return dict(NO_MODEL)

            with mock.patch.object(module, "load_cypherfix_settings", fake_settings), \
                 mock.patch.object(module, "TriageRunClient", lambda *a, **k: h.client):
                task = asyncio.ensure_future(h.orch.run(state(NO_MODEL)))
                await entered.wait()
                task.cancel()
                await asyncio.sleep(0)
                release.set()
                await task

        run(scenario())
        self.assertTrue(h.graph.batches)
        self.assertEqual(h.client.finished["status"], "completed")

    def test_the_review_budget_is_clamped(self):
        h = Harness(llm=FakeLLM(lambda i: None))
        h.run({**REVIEW_SETTINGS, "triageReviewBudget": 5000})
        self.assertEqual(h.client.finished["summary"]["review_budget"], 1000)
        self.assertEqual(h.client.authorize_args["review_budget"], 1000)

    def test_a_start_that_asked_for_no_review_needs_no_model(self):
        """An MCP start while the owner has no model: rules-only, not refused."""
        h = Harness(max_review_budget=0)
        h.run({"default_repo": "acme/app", "triageReviewBudget": 150, "llm_model": ""})
        self.assertEqual(h.client.finished["status"], "completed")
        self.assertEqual(h.client.finished["summary"]["review_budget"], 0)

    def test_a_start_can_ask_for_less(self):
        h = Harness(llm=FakeLLM(lambda i: None), max_review_budget=1)
        h.run(dict(REVIEW_SETTINGS))
        self.assertEqual(h.client.finished["summary"]["review_budget"], 1)
        self.assertEqual(len(h.orch.llm_client.asked), 1)

    def test_the_trigger_and_token_reach_authorize(self):
        h = Harness(trigger="mcp", token_id="tok1")
        h.run(dict(NO_MODEL))
        self.assertEqual(h.client.authorize_args["trigger"], "mcp")
        self.assertEqual(h.client.authorize_args["token_id"], "tok1")


class TestTheFixListStatsReachTheRunSummary(unittest.TestCase):
    """The route re-points a fix item whose findings were regrouped; the run's
    summary (what get_triage_status shows) must say how many followed."""

    def test_repointed_is_carried_into_the_summary(self):
        from unittest.mock import patch

        class Response:
            def raise_for_status(self):
                return None

            def json(self):
                return {"created": 1, "updated": 3, "deleted": 0, "skipped": 2,
                        "flagged": 0, "repointed": 2}

        class Client:
            def __init__(self, *a, **k):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def post(self, *a, **k):
                return Response()

        orch = TriageOrchestrator("u1", "p1", FakeCallback())
        draft = RemediationDraft(computed=[{"groupKey": "secret:abc", "findingIds": ["s1"]}])
        with patch("cypherfix_triage.orchestrator.httpx.AsyncClient", Client):
            out = run(orch._save_remediations(draft, "run-1"))
        self.assertEqual(out, {"remediations_created": 1, "remediations_updated": 3,
                               "remediations_deleted": 0, "remediations_skipped": 2,
                               "remediations_repointed": 2})


if __name__ == "__main__":
    unittest.main()
