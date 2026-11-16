"""The ingestion pipeline (T1.8): the stage contract, the swap, the failure policy, the 1.x
columns, the report, and nothing secret in what the job writes.

The site is the fixture tree (``FixtureFetcher``), the store ``MemoryStore``, the model
scripted. The same run on Postgres, against 1.x: ``test_tradecraft_ingest_pipeline_integration.py``.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tradecraft import net  # noqa: E402
from tradecraft.contract import JOB_STAGES, IngestionReport, JobContext, JobStartRequest  # noqa: E402
from tradecraft.ingest import legacy_map, pipeline  # noqa: E402
from tradecraft.settings import EffectiveSettings  # noqa: E402
from tradecraft_doubles import FAKE_COOKIE, FixtureFetcher  # noqa: E402
from tradecraft_memory_store import MemoryStore, PipelineModel, padded_sites  # noqa: E402

FIXTURE = json.loads((Path(__file__).resolve().parent / "fixtures" / "tradecraft_contract" /
                      "JobStartBatch.valid.json").read_text())["jobs"][0]
TOKEN = "ghp_fake_token_never_written"
OWNER, RID, JID = "u1", "r1", "job-1"


class Harness:
    def __init__(self, tmp_path, url, *, mode="live", settings=None, model=None, cancel_after=None, root=None,
                 resource=None, secrets=None):
        self.store = MemoryStore()
        self.fetcher = FixtureFetcher(root or padded_sites(tmp_path))
        self.model = model if model is not None else PipelineModel()
        self.stages: list = []
        self.requests_at: dict = {}
        self.cancel_after = cancel_after
        spec = json.loads(json.dumps(FIXTURE))
        spec.update(job_id=JID, user_id=OWNER, actor_user_id=OWNER, resource_id=RID,
                    settings=dict(settings or {}))
        spec["resource"].update(url=url, storage_mode=mode, model="openai/fake-small-model", **(resource or {}))
        spec["secrets"] = secrets or {"github_token": None, "credentials": None}
        self.request = JobStartRequest.model_validate(spec)
        self.store.add_resource(OWNER, RID, url=url, storage_mode=mode, summary="previous summary",
                                sitemap={"nav": [{"title": "old", "path": "old"}]}, generation=2)
        self.store.add_job(OWNER, RID, JID, status="running")
        self.store.jobs[JID]["target_generation"] = 3

    async def is_cancelled(self):
        if self.cancel_after is None:
            return False
        return sum(1 for s in self.stages if s[0] == self.cancel_after) >= 1

    async def set_stage(self, stage, progress=None):
        self.requests_at.setdefault(stage, len(self.fetcher.requests) + len(self.fetcher.browser.renders))
        self.stages.append((stage, progress.model_dump() if progress else None))
        await self.store.set_job_stage(OWNER, JID, stage, progress.model_dump() if progress else {})

    def run(self):
        async def build_llm(owner, model):
            assert owner == OWNER
            return self.model

        ctx = JobContext(request=self.request, settings=EffectiveSettings(self.request.settings),
                         target_generation=3, is_cancelled=self.is_cancelled, set_stage=self.set_stage)
        with net.use_fetcher(self.fetcher):
            return asyncio.run(pipeline.run(ctx, store=self.store, build_llm=build_llm))

    @property
    def resource(self):
        return self.store.resources[RID]

    def stage_names(self):
        out = []
        for name, _p in self.stages:
            if not out or out[-1] != name:
                out.append(name)
        return out


WIKI = "https://wiki.tc-fixture.test/"


def test_stage_order(tmp_path):
    h = Harness(tmp_path, WIKI)
    outcome = h.run()
    assert outcome.status == "succeeded" and outcome.swapped
    names = h.stage_names()
    assert names == ["fetch_home", "detect", "build_map", "curation", "focus", "titles", "incremental", "store",
                     "cards", "sections", "tags", "entities", "tree", "content_check", "write", "summary",
                     "report", "legacy_map", "swap"]
    assert all(n in JOB_STAGES for n in names)
    assert [n for n in JOB_STAGES if n in names] == names


def test_report_fields(tmp_path):
    h = Harness(tmp_path, WIKI)
    outcome = h.run()
    report = IngestionReport.model_validate(h.resource["ingestion_report"])
    assert report == outcome.report
    assert report.kept == len(h.store.live_entries(RID)) > 0
    assert report.visited >= 1 and report.llmCalls == 1 and report.durationSec >= 0
    assert set(report.skipped.model_dump()) == {"excluded", "outOfScope", "tooLittleText", "robots", "outsideFocus"}
    assert report.stored.pages == 0  # a Live resource stores nothing


def test_writes_legacy_columns(tmp_path):
    h = Harness(tmp_path, WIKI)
    h.run()
    r = h.resource
    assert r["resource_type"] == "mkdocs-wiki" and r["map_version"] == 3 and r["generation"] == 3
    assert set(r["sitemap"]) == {"nav"} and r["sitemap"]["nav"]
    assert all(set(e) == {"title", "path"} for e in r["sitemap"]["nav"])
    assert r["legacy_map_hash"] == legacy_map.map_hash(r["sitemap"])
    assert r["summary"] == "A synthetic library of offensive techniques and payloads."
    assert r["summary_source"] == "generated" and r["last_error"] == ""
    assert r["settings_hash"] == FIXTURE["settings_hash"] and r["settings_snapshot"]["values"]
    assert r["last_refreshed_at"] and r["last_verified_at"] and r["active_job_id"] is None


def test_github_legacy_shape(tmp_path):
    h = Harness(tmp_path, "https://github.com/tc-fixture/payloads")
    h.run()
    sitemap = h.resource["sitemap"]
    assert h.resource["resource_type"] == "github-repo"
    assert {"tree", "owner", "repo", "branch"} == set(sitemap)
    assert {e["path"] for e in sitemap["tree"]} >= {"sqli/union.md", "README.md"}


def test_crawl_legacy_columns(tmp_path):
    h = Harness(tmp_path, "https://blog.tc-fixture.test/", model=PipelineModel(follow=2),
                settings={"crawl.minTextChars": 0})
    h.run()
    r = h.resource
    assert r["resource_type"] == "agentic-crawl" and set(r["sitemap"]) == {"nav"}
    # The model follows two links from the start page, then stops at the next decision.
    assert r["crawl_stats"]["pages_fetched"] == 2 and r["crawl_stopped_because"] == "enough"
    assert IngestionReport.model_validate(r["ingestion_report"]).stopReason == "llm_stop"


@pytest.mark.parametrize("policy", ["keep", "replace"])
def test_failure_policy(tmp_path, policy):
    h = Harness(tmp_path, "https://down.tc-fixture.test/", settings={"refreshing.onFailure": policy})
    outcome = h.run()
    assert outcome.status == "failed" and outcome.error_code == "fetch_failed"
    if policy == "keep":
        assert not outcome.swapped
        assert "swap" not in h.store.names()
        assert h.resource["summary"] == "previous summary" and h.resource["generation"] == 2
    else:
        assert outcome.swapped and h.resource["generation"] == 3
        assert h.resource["sitemap"] == {"nav": []} and h.resource["summary"] == ""
        assert h.resource["last_error"] == "fetch_failed"
        assert h.store.jobs[JID]["status"] == "failed"


def test_failed_refresh_keeps_previous(tmp_path):
    """AC-37 / R-194: with the default policy a failed refresh leaves summary and map as they were."""
    h = Harness(tmp_path, "https://contract.tc-fixture.test/missing.html")
    before = json.loads(json.dumps({k: h.resource[k] for k in ("summary", "sitemap", "generation", "resource_type")}))
    outcome = h.run()
    assert outcome.status == "failed" and not outcome.swapped
    assert {k: h.resource[k] for k in before} == before


def test_refusals_end_at_once(tmp_path):
    h = Harness(tmp_path, "https://contract.tc-fixture.test/to-private")
    outcome = h.run()
    assert outcome.error_code == "blocked_private_address" and h.stage_names() == ["fetch_home"]
    assert h.fetcher.browser.renders == []


def test_locked_summary(tmp_path):
    for fields in ({"summary_locked": True, "summary": "my words"}, {"summary_source": "manual", "summary": "mine"}):
        h = Harness(tmp_path / str(len(fields["summary"])), WIKI, resource=fields)
        h.resource["summary"] = fields["summary"]
        outcome = h.run()
        assert outcome.status == "succeeded"
        assert h.resource["summary"] == fields["summary"]
        assert h.model.summary_prompts == []
        swap = [a for n, a in h.store.calls if n == "swap"][0]
        assert "summary" not in swap[4]


@pytest.mark.parametrize("policy,site", [("keep", WIKI), ("replace", "https://down.tc-fixture.test/")])
@pytest.mark.parametrize("flags", [{"summary_locked": True}, {"summary_source": "manual"}])
def test_summary_written_or_locked_during_the_refresh_is_kept(tmp_path, flags, policy, site):
    """Finding A / AC-40: the job started with an unlocked, generated summary; the person then
    wrote or locked theirs. The swap keeps it, whatever the job generated (or, under "replace",
    the empty result would have written)."""
    h = Harness(tmp_path, site, settings={"refreshing.onFailure": policy})
    assert not h.request.resource.summary_locked and h.request.resource.summary_source == "generated"
    h.resource.update(summary="the person's own summary", **flags)
    outcome = h.run()
    assert outcome.swapped
    assert h.resource["summary"] == "the person's own summary"
    assert h.resource.get("summary_locked", False) == flags.get("summary_locked", False)
    assert h.resource["summary_source"] == flags.get("summary_source", "generated")


def _pages_failing(tmp_path, status=503):
    """The padded fixture sites, with every wiki page but its start page answering ``status``:
    the sitemap still answers, the pages do not."""
    root = padded_sites(tmp_path)
    wiki = root / "wiki.tc-fixture.test"
    paths = {"/" + p.parent.relative_to(wiki).as_posix() + "/": status
             for p in wiki.rglob("index.html") if p.parent != wiki}
    (wiki / "_status.json").write_text(json.dumps(paths))
    return root


@pytest.mark.parametrize("policy", ["keep", "replace"])
def test_stored_refresh_whose_pages_fail_keeps_the_previous_copies(tmp_path, policy):
    """Finding B / R-194 / AC-16: a Stored wiki whose index answers but whose pages fail; under
    the default policy the refresh fails and the previous generation, with its stored copies,
    stays live."""
    h = Harness(tmp_path, WIKI, mode="stored", root=_pages_failing(tmp_path),
                settings={"refreshing.onFailure": policy, "fetching.browserEnabled": False})
    outcome = h.run()
    assert outcome.status == "failed" and outcome.error_code == "fetch_failed"
    if policy == "keep":
        assert not outcome.swapped and "swap" not in h.store.names()
        assert h.resource["generation"] == 2 and h.resource["summary"] == "previous summary"
    else:
        assert outcome.swapped and h.resource["generation"] == 3 and h.resource["last_error"] == "fetch_failed"


def test_an_entry_over_the_url_limit_is_dropped_not_fatal(tmp_path, monkeypatch):
    """Finding C: whatever builds the map, an over-long URL never reaches the page store."""
    from tradecraft.ingest import crawl as crawl_mod
    from tradecraft.ingest.builders import Candidate

    good = "https://blog.tc-fixture.test/posts/01-xss-note-1/"
    long_url = "https://blog.tc-fixture.test/posts/?" + "x" * 3000

    async def fake_crawl(url, settings, **kw):
        return crawl_mod.CrawlResult(entries=[Candidate(good, "Good", "crawl", good),
                                              Candidate(long_url, "Long", "crawl", long_url)],
                                     stop_reason="frontier_empty", stats={"pages_fetched": 2, "llm_calls": 0})

    monkeypatch.setattr(pipeline.crawl, "crawl", fake_crawl)
    h = Harness(tmp_path, "https://blog.tc-fixture.test/")
    outcome = h.run()
    assert outcome.status == "succeeded"
    assert [e["url"] for e in h.store.live_entries(RID)] == [good]
    assert {"code": "url_too_long_or_bad", "count": 1} in h.resource["ingestion_report"]["errors"]


def test_wrapped_untrusted(tmp_path):
    h = Harness(tmp_path, WIKI, settings={"summary.extraInstructions": "List the vulnerability classes."})
    h.run()
    system, user = h.model.summary_prompts[0]
    assert "List the vulnerability classes." in system["content"]
    content = user["content"]
    first = content.index("<<<UNTRUSTED_WEB_CONTENT")
    assert "Synthetic offensive security notes" in content[first:]
    assert content.count("<<<UNTRUSTED_WEB_CONTENT") == 2
    assert "List the vulnerability classes." not in content


def test_report_has_no_secret_values(tmp_path):
    """A job with a GitHub token and a fake cookie whose fetches fail: neither value, nor a
    query string, appears in the progress, the report, the job row or lastError."""
    url = "https://down.tc-fixture.test/start?session=tc-query-secret"
    secrets = {"github_token": TOKEN, "credentials": {"cookie": FAKE_COOKIE, "headers": [], "basic_auth": None}}
    h = Harness(tmp_path, url, secrets=secrets, settings={"refreshing.onFailure": "replace"})
    outcome = h.run()
    assert outcome.status == "failed"
    written = json.dumps([h.stages, h.store.jobs, h.resource["ingestion_report"], h.resource["last_error"],
                          outcome.report.model_dump() if outcome.report else None], default=str)
    for secret in (TOKEN, FAKE_COOKIE, "tc-query-secret", "?session="):
        assert secret not in written


def test_cancel_between_pages(tmp_path):
    h = Harness(tmp_path, WIKI, mode="stored", cancel_after="store")
    outcome = h.run()
    assert outcome.status == "cancelled" and outcome.error_code == "cancelled"
    assert "swap" not in h.store.names() and h.resource["generation"] == 2


def test_cancel_during_the_crawl(tmp_path):
    h = Harness(tmp_path, "https://blog.tc-fixture.test/", cancel_after="build_map", model=PipelineModel(follow=5))
    assert h.run().status == "cancelled"
    assert "swap" not in h.store.names()


def test_stored_wiki_keeps_text(tmp_path):
    h = Harness(tmp_path, WIKI, mode="stored")
    outcome = h.run()
    entries = h.store.live_entries(RID)
    stored = [e for e in entries if e["stored_text"]]
    assert stored and outcome.report.stored.pages == len(stored)
    assert all("<" not in e["stored_text"][:200] for e in stored)
    assert all(e["stored_bytes"] == len(e["stored_text"].encode()) and len(e["text_hash"]) == 64 for e in stored)


def test_crawl_text_is_not_downloaded_again(tmp_path):
    h = Harness(tmp_path, "https://blog.tc-fixture.test/", mode="stored", model=PipelineModel(follow=2),
                settings={"crawl.minTextChars": 0})
    h.run()
    stored = [e for e in h.store.live_entries(RID) if e["stored_text"]]
    assert len(stored) == 2
    # Storing the crawled pages made no request: the crawl's own download is stored.
    assert h.requests_at["store"] == h.requests_at["cards"]


def test_cve_archive_is_never_stored_and_has_no_entries(tmp_path):
    h = Harness(tmp_path, "https://github.com/tc-fixture/cve", mode="stored")
    outcome = h.run()
    assert outcome.status == "succeeded" and h.store.live_entries(RID) == []
    assert h.resource["resource_type"] == "cve-poc-db" and set(h.resource["sitemap"]) == {"owner", "repo", "branch"}


def test_pdf_is_always_stored(tmp_path):
    h = Harness(tmp_path, "https://files.tc-fixture.test/guide.pdf", mode="live")
    outcome = h.run()
    entries = h.store.live_entries(RID)
    assert outcome.status == "succeeded" and len(entries) == 3 and all(e["stored_text"] for e in entries)
    assert h.resource["resource_type"] == "agentic-crawl" and [p["page"] for p in h.resource["sitemap"]["pages"]] == [1, 2, 3]


def test_forced_type_skips_detection(tmp_path):
    h = Harness(tmp_path, "https://book.tc-fixture.test/", resource={"forced_type": "agentic-crawl"})
    h.run()
    assert h.resource["resource_type"] == "agentic-crawl"


def test_thin_homepage_is_crawled_like_1x(tmp_path):
    root = Path(__file__).resolve().parent / "fixtures" / "tradecraft_sites"
    # The generated wiki's start page is thin: not classified, crawled as a website. Its text is
    # too short to keep and the model follows nothing, so the refresh fails and keeps the past.
    h = Harness(tmp_path, WIKI, root=root, settings={"fetching.browserEnabled": False})
    outcome = h.run()
    assert outcome.status == "failed" and outcome.error_code == "thin_homepage" and not outcome.swapped
    assert "build_map" in h.stage_names()
    # With a lower bar the crawl keeps the start page: the resource is a website, marked thin.
    h = Harness(tmp_path / "b", WIKI, root=root, settings={"fetching.browserEnabled": False, "crawl.minTextChars": 0})
    assert h.run().status == "succeeded"
    assert h.resource["resource_type"] == "agentic-crawl" and h.resource["last_error"] == "thin_homepage"


def test_swap_refused_when_the_resource_changed(tmp_path):
    h = Harness(tmp_path, WIKI)
    h.resource["url"] = "https://elsewhere.tc-fixture.test/"
    outcome = h.run()
    assert outcome.status == "failed" and outcome.error_code == "resource_changed" and not outcome.swapped


def test_refresh_replaces(tmp_path):
    h = Harness(tmp_path, WIKI, mode="stored")
    h.run()
    first = {e["url"] for e in h.store.live_entries(RID)}
    # A second refresh of the same resource writes generation 4 and swaps it in.
    h.store.add_job(OWNER, RID, "job-2", status="running")
    h.request = h.request.model_copy(update={"job_id": "job-2"})
    ctx = JobContext(request=h.request, settings=EffectiveSettings({}), target_generation=4,
                     is_cancelled=h.is_cancelled, set_stage=h.set_stage)

    async def build_llm(owner, model):
        return PipelineModel(summary="second summary")

    with net.use_fetcher(h.fetcher):
        outcome = asyncio.run(pipeline.run(ctx, store=h.store, build_llm=build_llm))
    assert outcome.swapped and h.resource["generation"] == 4 and h.resource["summary"] == "second summary"
    assert {e["url"] for e in h.store.live_entries(RID)} == first
    assert all(e["generation"] == 4 for e in h.store.live_entries(RID))


def test_a_failed_add_leaves_a_1x_error_card(tmp_path):
    """M1 (TD-18, D-25): an add whose job fails under the default policy, run through the job
    runner and this pipeline, leaves last_error and last_verified_at on the 1.x columns and the
    map as it was, so the 1.x tab shows an error card after a switch-off, never "verifying..."."""
    import functools
    from tradecraft import jobs
    from tradecraft.contract import JobStartBatch
    from tradecraft_doubles import FakeClock

    store = MemoryStore()
    url = "https://down.tc-fixture.test/"
    store.add_resource(OWNER, RID, url=url, storage_mode="live", sitemap={})
    store.add_job(OWNER, RID, JID)
    spec = json.loads(json.dumps(FIXTURE))
    spec.update(job_id=JID, user_id=OWNER, actor_user_id=OWNER, resource_id=RID, settings={})
    spec["resource"].update(url=url, storage_mode="live", model="openai/fake-small-model")
    clock = FakeClock()
    root = padded_sites(tmp_path)

    async def build_llm(owner, model):
        return PipelineModel()

    async def go():
        runner = jobs.JobRunner(store, instance="i", clock=clock, fetcher_factory=lambda: FixtureFetcher(root))
        runner._entry = functools.partial(pipeline.run, store=store, run_blocking=runner.run_blocking,
                                          build_llm=build_llm)
        await runner.submit(JobStartBatch.model_validate({"jobs": [spec]}))
        await asyncio.wait_for(runner._running[JID].task, timeout=10)
        await runner.close()

    asyncio.run(go())
    r = store.resources[RID]
    assert store.jobs[JID]["status"] == "failed" and store.jobs[JID]["error_code"] == "fetch_failed"
    assert r["last_error"] == "fetch_failed" and r["last_verified_at"] == clock.now()
    assert r["sitemap"] == {} and r["generation"] == 0 and r["active_job_id"] is None
