"""The spent daily model budget through the real pipeline (T6.10 review finding 1; R-027, R-026).

A model call the budget refused is never retried, and the stages only count it: a model-guided
crawl stops after its start page, the focus, the tags and the summary go without the model. The
job then fails with ``llm_budget_exhausted``: with the default policy the previous version stays
live (never a start-page-only map or one without its tags), with ``replace`` the result is
swapped in and the job says why; and Save & refresh all stops the rest of its batch there, each
card saying so. The model is scripted (it runs out mid-job), the sites the fixture tree, the
store ``MemoryStore``: nothing real is reached.
"""

from __future__ import annotations

import asyncio
import functools
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from llm_budget import LlmBudgetExhausted  # noqa: E402
from tradecraft import jobs, net  # noqa: E402
from tradecraft.contract import JobContext, JobStartBatch, JobStartRequest  # noqa: E402
from tradecraft.ingest import pipeline  # noqa: E402
from tradecraft.settings import EffectiveSettings  # noqa: E402
from tradecraft_doubles import FakeClock, FixtureFetcher  # noqa: E402
from tradecraft_memory_store import MemoryStore, PipelineModel, padded_sites  # noqa: E402

FIXTURE = json.loads((Path(__file__).resolve().parent / "fixtures" / "tradecraft_contract" /
                      "JobStartBatch.valid.json").read_text())["jobs"][0]
OWNER = "u1"
WIKI = "https://wiki.tc-fixture.test/"
BLOG = "https://blog.tc-fixture.test/"
PREVIOUS_MAP = {"nav": [{"title": "old", "path": "old"}]}
SQLI = {"mode": "focused", "topics": ["sql_injection"]}


class SpentModel(PipelineModel):
    """Answers as ``PipelineModel`` until the budget runs out: at the first crawl decision
    (``at_crawl``, the crawl's own prompt) or after ``answer`` calls; from then on every call is
    refused."""

    def __init__(self, *, at_crawl=False, answer=None, follow=0):
        super().__init__(follow=follow)
        self.at_crawl, self.answer = at_crawl, answer
        self.answered = 0
        self.refused = 0

    async def ainvoke(self, messages, config=None, **kwargs):
        text = messages if isinstance(messages, str) else ""
        spent = self.refused > 0 or (self.at_crawl and "Pick links to follow next" in text) \
            or (self.answer is not None and self.answered >= self.answer)
        if spent:
            self.refused += 1
            raise LlmBudgetExhausted(OWNER, 10, "yours")
        self.answered += 1
        return await super().ainvoke(messages, config, **kwargs)


def request(job_id, rid, url, *, kind="refresh", bulk_id=None, settings=None, focus=None):
    spec = json.loads(json.dumps(FIXTURE))
    spec.update(job_id=job_id, user_id=OWNER, actor_user_id=OWNER, resource_id=rid, kind=kind, bulk_id=bulk_id,
                settings={"crawl.minTextChars": 0, **(settings or {})})
    spec["resource"].update(url=url, storage_mode="live", model="openai/fake-small-model", focus=focus or {})
    spec["secrets"] = {"github_token": None, "credentials": None}
    return spec


def seed_resource(store, rid, url):
    store.add_resource(OWNER, rid, url=url, slug=rid, storage_mode="live", summary="previous summary",
                       sitemap=json.loads(json.dumps(PREVIOUS_MAP)), generation=2)


def run_one(tmp_path, url, model, *, settings=None, focus=None):
    """One refresh through ``pipeline.run``, as the runner calls it."""
    store = MemoryStore()
    seed_resource(store, "r1", url)
    store.add_job(OWNER, "r1", "job-1", status="running")
    store.jobs["job-1"]["target_generation"] = 3
    req = JobStartRequest.model_validate(request("job-1", "r1", url, settings=settings, focus=focus))
    stages: list[str] = []

    async def set_stage(stage, progress=None):
        stages.append(stage)

    async def not_cancelled():
        return False

    async def build_llm(owner, model_id):
        return model

    ctx = JobContext(request=req, settings=EffectiveSettings(req.settings), target_generation=3,
                     is_cancelled=not_cancelled, set_stage=set_stage)
    with net.use_fetcher(FixtureFetcher(padded_sites(tmp_path))):
        outcome = asyncio.run(pipeline.run(ctx, store=store, build_llm=build_llm))
    return outcome, store, stages


def test_a_crawl_the_budget_cut_short_keeps_the_previous_map(tmp_path):
    model = SpentModel(at_crawl=True)
    outcome, store, _stages = run_one(tmp_path, BLOG, model)
    assert outcome.status == "failed" and outcome.error_code == "llm_budget_exhausted"
    assert not outcome.swapped and "swap" not in store.names()
    r = store.resources["r1"]
    # Not the start page alone in place of the map the resource had (R-194).
    assert r["sitemap"] == PREVIOUS_MAP and r["generation"] == 2 and r["summary"] == "previous summary"
    # The refused call was not retried, and nothing after it asked the model again.
    assert model.refused == 1


def test_with_replace_the_cut_result_is_swapped_and_the_job_says_why(tmp_path):
    outcome, store, _stages = run_one(tmp_path, BLOG, SpentModel(at_crawl=True), settings={"refreshing.onFailure": "replace"})
    assert outcome.status == "failed" and outcome.error_code == "llm_budget_exhausted" and outcome.swapped
    r = store.resources["r1"]
    assert r["generation"] == 3 and r["last_error"] == "llm_budget_exhausted"


def test_the_focus_counts_the_spent_budget_and_the_job_ends_there(tmp_path):
    """The focus triage is the wiki's first model call: refused, the job fails before it stores,
    tags or summarizes anything (the focus counted ``llm_budget_exhausted``, not only ``model_error``)."""
    model = SpentModel(answer=0)
    outcome, store, stages = run_one(tmp_path, WIKI, model, focus=SQLI)
    assert outcome.status == "failed" and outcome.error_code == "llm_budget_exhausted" and not outcome.swapped
    assert "focus" in stages and "store" not in stages and "tags" not in stages
    assert model.refused == 1
    assert store.resources["r1"]["sitemap"] == PREVIOUS_MAP


def test_a_summary_the_budget_refused_keeps_the_previous_version(tmp_path):
    """The wiki maps without the model; its first calls (tags, folder descriptions) are answered,
    then the budget runs out: the job fails at the summary instead of swapping a summary-less refresh."""
    probe = SpentModel()
    run_one(tmp_path / "probe", WIKI, probe)
    assert probe.answered >= 2 and probe.refused == 0
    model = SpentModel(answer=probe.answered - 1)
    outcome, store, stages = run_one(tmp_path / "cut", WIKI, model)
    assert outcome.status == "failed" and outcome.error_code == "llm_budget_exhausted" and not outcome.swapped
    assert "summary" in stages and "swap" not in stages
    assert store.resources["r1"]["summary"] == "previous summary" and store.resources["r1"]["generation"] == 2


def test_a_refresh_with_every_call_answered_is_swapped_as_before(tmp_path):
    outcome, store, _stages = run_one(tmp_path, BLOG, SpentModel(follow=1))
    assert outcome.status == "succeeded" and outcome.swapped and store.resources["r1"]["generation"] == 3


def test_save_and_refresh_all_stops_at_the_spent_budget_through_the_real_pipeline(tmp_path):
    """R-027: the wiki refreshes; the budget runs out during the website's crawl, which keeps its
    previous map and fails saying so; the third resource is never run, its card saying why."""
    root = padded_sites(tmp_path)
    store = MemoryStore()
    model = SpentModel(at_crawl=True)

    async def build_llm(owner, model_id):
        return model

    specs = [request("k1", "r-wiki", WIKI, kind="bulk", bulk_id="b1"),
             request("k2", "r-blog", BLOG, kind="bulk", bulk_id="b1"),
             request("k3", "r-wiki2", WIKI + "en/", kind="bulk", bulk_id="b1")]
    for spec in specs:
        seed_resource(store, spec["resource_id"], spec["resource"]["url"])
        store.add_job(OWNER, spec["resource_id"], spec["job_id"])
    batch = JobStartBatch.model_validate({"jobs": specs})

    async def go():
        runner = jobs.JobRunner(store, entry=functools.partial(pipeline.run, store=store, build_llm=build_llm),
                                instance="inst-test", clock=FakeClock(start=datetime(2026, 11, 17, 4, 0, tzinfo=timezone.utc)),
                                fetcher_factory=lambda: FixtureFetcher(root))
        answer = await runner.submit(batch)
        assert answer.accepted == ["k1", "k2", "k3"]
        for _ in range(400):
            if all(store.jobs[j]["status"] not in ("queued", "running") for j in ("k1", "k2", "k3")):
                break
            await asyncio.sleep(0)
        await runner.close()

    asyncio.run(go())
    assert store.jobs["k1"]["status"] == "succeeded", (store.jobs["k1"], store.resources["r-wiki"]["last_error"], model.refused, model.answered)
    assert store.resources["r-wiki"]["generation"] > 2
    assert store.jobs["k2"]["status"] == "failed" and store.jobs["k2"]["error_code"] == "llm_budget_exhausted"
    assert store.resources["r-blog"]["sitemap"] == PREVIOUS_MAP and store.resources["r-blog"]["generation"] == 2
    assert store.jobs["k3"]["status"] == "cancelled" and store.jobs["k3"]["error_code"] == "llm_budget_exhausted"
    assert store.resources["r-wiki2"]["sitemap"] == PREVIOUS_MAP and store.resources["r-wiki2"]["generation"] == 2
    assert model.refused == 1
