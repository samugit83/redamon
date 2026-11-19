"""Regenerate summary (T4.1, §6.9, R-164): a ``regenerate_summary`` job rebuilds the summary from
the saved map's titles and the start page read again, with no crawl, and swaps in only the
summary: the map, the generation and the stored pages stay as they were. A locked or
hand-written summary is never replaced and makes no model call; a failure changes nothing.

The jobs run through the real ``JobRunner`` on ``MemoryStore``; the web is ``FixtureFetcher``
over the fixture sites; the model is scripted and records its prompts.
"""

from __future__ import annotations

import asyncio
import functools
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from llm_budget import LlmBudgetExhausted  # noqa: E402
from tradecraft import jobs  # noqa: E402
from tradecraft.contract import JobStartBatch  # noqa: E402
from tradecraft.ingest import summary  # noqa: E402
from tradecraft_doubles import FakeClock, FixtureFetcher, ScriptedChatModel  # noqa: E402
from tradecraft_memory_store import MemoryStore, padded_sites  # noqa: E402

FIXTURE = json.loads((Path(__file__).resolve().parent / "fixtures" / "tradecraft_contract" /
                      "JobStartBatch.valid.json").read_text())["jobs"][0]
OWNER, RID, JID = "u1", "r1", "job-regen"
WIKI = "https://wiki.tc-fixture.test/"
PDF = "https://files.tc-fixture.test/guide.pdf"
NAV = {"nav": [{"title": "Union-based SQL injection", "path": "sqli/union-based/"},
               {"title": "Stored XSS", "path": "xss/stored/"}]}


class World:
    def __init__(self, tmp_path, *, url=WIKI, sitemap=None, resource_type="mkdocs-wiki", summary_text="old summary",
                 model=None, locked=False, source="generated", mode="live", has_login=False):
        self.store = MemoryStore()
        self.root = padded_sites(tmp_path)
        self.model = model if model is not None else ScriptedChatModel("A fresh summary of the wiki.")
        self.store.add_resource(OWNER, RID, url=url, storage_mode=mode, summary=summary_text, summary_source=source,
                                summary_locked=locked, sitemap=sitemap if sitemap is not None else NAV,
                                resource_type=resource_type, generation=2, has_login=has_login)
        for i, item in enumerate((sitemap if sitemap is not None else NAV).get("nav", [])):
            self.store.entries.append({"id": i + 1, "user_id": OWNER, "resource_id": RID, "generation": 2,
                                       "page_id": i + 1, "url": url + item["path"], "stored_bytes": 0})
        self.store.add_job(OWNER, RID, JID)
        self.fetchers: list = []
        spec = json.loads(json.dumps(FIXTURE))
        spec.update(job_id=JID, user_id=OWNER, actor_user_id=OWNER, resource_id=RID, kind="regenerate_summary",
                    settings={"summary.titles": 10})
        spec["resource"].update(url=url, storage_mode=mode, model="openai/fake-small-model", summary=summary_text,
                                summary_locked=locked, summary_source=source)
        self.batch = JobStartBatch.model_validate({"jobs": [spec]})

    def fetcher(self):
        f = FixtureFetcher(self.root)
        self.fetchers.append(f)
        return f

    def run(self, while_running=None):
        async def build_llm(owner, model_id):
            assert owner == OWNER
            return self.model

        async def go():
            runner = jobs.JobRunner(self.store, instance="inst-test", clock=FakeClock(), fetcher_factory=self.fetcher,
                                    regenerate=functools.partial(summary.regenerate, store=self.store, build_llm=build_llm),
                                    entry=self.no_pipeline)
            try:
                await runner.submit(self.batch)
                for _ in range(500):
                    await asyncio.sleep(0)
                    if while_running is not None:
                        while_running(self.store)
                    if self.store.jobs[JID]["status"] not in ("queued", "running"):
                        break
            finally:
                await runner.close()

        asyncio.run(go())
        return self.store.jobs[JID]

    @staticmethod
    async def no_pipeline(ctx):
        raise AssertionError("a regenerate_summary job never runs the ingestion pipeline")

    @property
    def resource(self):
        return self.store.resources[RID]


WRITES = ("begin_generation", "discard_generation", "write_entries", "write_sections", "write_tree",
          "allocate_page_ids", "purge_old_generations", "set_last_error", "set_error_without_fetch")


def test_keeps_map(tmp_path):
    w = World(tmp_path)
    entries_before = json.dumps(w.store.live_entries(RID), sort_keys=True, default=str)
    sitemap_before = json.dumps(w.resource["sitemap"], sort_keys=True)
    job = w.run()
    assert job["status"] == "succeeded" and job["error_code"] == ""
    assert w.resource["summary"] == "A fresh summary of the wiki." and w.resource["summary_source"] == "generated"
    assert w.resource["generation"] == 2 and w.resource["active_job_id"] is None
    assert json.dumps(w.store.live_entries(RID), sort_keys=True, default=str) == entries_before
    assert json.dumps(w.resource["sitemap"], sort_keys=True) == sitemap_before
    assert not set(w.store.names()) & set(WRITES)
    # Only the summary went through the swap.
    swaps = [args for name, args in w.store.calls if name == "swap"]
    # (owner, resource, job, generation, updates, status, code): the live generation, the summary only.
    assert len(swaps) == 1 and swaps[0][3] == 2 and swaps[0][4] == {
        "summary": "A fresh summary of the wiki.", "summary_source": "generated"}
    # One call, over the saved map's titles and the start page read again (no crawl).
    assert w.model.calls == 1
    system, user = w.model.prompts[0][0]["content"], w.model.prompts[0][1]["content"]
    assert "summarizing a security-knowledge website" in system
    assert "Union-based SQL injection" in user and "Stored XSS" in user and "About this library" in user
    requested = [u for f in w.fetchers for u, _h in f.requests]
    assert requested == [WIKI]


def test_locked_summary_untouched(tmp_path):
    for flags in ({"locked": True}, {"source": "manual"}):
        w = World(tmp_path / str(len(flags)) / next(iter(flags)), summary_text="my own words", **flags)
        job = w.run()
        assert job["status"] == "succeeded"
        assert w.resource["summary"] == "my own words" and w.model.calls == 0
        assert [args[4] for name, args in w.store.calls if name == "swap"] == [{}]
        assert not [u for f in w.fetchers for u, _h in f.requests]


def test_summary_locked_while_the_job_runs_is_kept(tmp_path):
    class LockedMeanwhile(ScriptedChatModel):
        def _next(self, messages):
            w.store.resources[RID].update(summary_locked=True, summary="edited meanwhile")
            return super()._next(messages)

    w = World(tmp_path, model=LockedMeanwhile("A fresh summary."))
    job = w.run()
    assert job["status"] == "succeeded" and w.resource["summary"] == "edited meanwhile"


def test_a_failure_changes_nothing(tmp_path):
    w = World(tmp_path, model=ScriptedChatModel(LlmBudgetExhausted("u1", 10, "yours")))
    job = w.run()
    assert job["status"] == "failed" and job["error_code"] == "llm_budget_exhausted"
    assert w.resource["summary"] == "old summary" and w.resource["generation"] == 2
    assert w.resource["last_error"] == "" and w.resource["active_job_id"] is None
    assert w.model.calls == 1  # never retried (TD-20)
    assert not set(w.store.names()) & set(WRITES) and "swap" not in w.store.names()

    empty = World(tmp_path / "empty", model=ScriptedChatModel(""))
    job = empty.run()
    assert job["status"] == "failed" and job["error_code"] == "internal_error" and empty.resource["summary"] == "old summary"


def test_a_deleted_or_changed_resource(tmp_path):
    from tradecraft.contract import JobContext
    from tradecraft.settings import EffectiveSettings

    gone = World(tmp_path / "gone")
    gone.store.delete_resource(RID)

    async def no_stage(*_a):
        pass

    async def not_cancelled():
        return False

    ctx = JobContext(request=gone.batch.jobs[0], settings=EffectiveSettings({}), target_generation=0,
                     is_cancelled=not_cancelled, set_stage=no_stage)
    outcome = asyncio.run(summary.regenerate(ctx, store=gone.store, build_llm=None))
    assert (outcome.status, outcome.error_code, outcome.swapped) == ("failed", "resource_deleted", False)

    # Deleted while the model answers: the swap finds no row and writes nothing (the job row
    # went with its resource).
    during = World(tmp_path / "during")

    def delete_it(store):
        if during.model.calls and RID in store.resources:
            store.delete_resource(RID)

    async def go():
        async def build_llm(owner, model_id):
            return during.model

        runner = jobs.JobRunner(during.store, instance="inst-test", clock=FakeClock(), fetcher_factory=during.fetcher,
                                regenerate=functools.partial(summary.regenerate, store=during.store, build_llm=build_llm))
        try:
            await runner.submit(during.batch)
            for _ in range(500):
                await asyncio.sleep(0)
                delete_it(during.store)
                if not runner.snapshot().get("running") and during.model.calls:
                    break
        finally:
            await runner.close()

    asyncio.run(go())
    assert RID not in during.store.resources and during.store.entries == []
    assert not set(during.store.names()) & set(WRITES)

    class EditsTheUrl(ScriptedChatModel):
        """The person edits the resource's URL while the model answers."""

        def _next(self, messages):
            moved.store.resources[RID]["url"] = "https://other.tc-fixture.test/"
            return super()._next(messages)

    moved = World(tmp_path / "moved", model=EditsTheUrl("A fresh summary."))
    job = moved.run()
    assert job["status"] == "failed" and job["error_code"] == "resource_changed"
    assert moved.resource["summary"] == "old summary"


def test_pdf_summary_from_its_stored_pages(tmp_path):
    pages = {"pages": [{"page": 1, "firstLine": "Guide"}, {"page": 2, "firstLine": "Chapter two"}]}
    w = World(tmp_path, url=PDF, sitemap=pages, resource_type="agentic-crawl", mode="stored",
              model=ScriptedChatModel("A guide."))
    for n, text in ((1, "First page text of the guide."), (2, "Second page text.")):
        w.store.entries.append({"id": 10 + n, "user_id": OWNER, "resource_id": RID, "generation": 2, "page_id": 10 + n,
                                "url": f"{PDF}#page={n}", "stored_bytes": len(text), "stored_text": text})
    job = w.run()
    assert job["status"] == "succeeded" and w.resource["summary"] == "A guide."
    user = w.model.prompts[0][1]["content"]
    assert "Detected type: pdf" in user and "First page text of the guide." in user and "Chapter two" in user
    assert not [u for f in w.fetchers for u, _h in f.requests]  # the PDF is not downloaded again


def test_a_login_resource_never_uses_the_browser(tmp_path):
    js = "https://blog.tc-fixture.test/posts/42-js-only/"
    w = World(tmp_path, url=js, resource_type="agentic-crawl", has_login=True)
    w.run()
    assert all(f.browser.renders == [] for f in w.fetchers)
    plain = World(tmp_path / "plain", url=js, resource_type="agentic-crawl")
    plain.run()
    assert [r for f in plain.fetchers for r in f.browser.renders] == [js]


def test_cancelled_before_the_call(tmp_path):
    w = World(tmp_path)
    w.store.jobs[JID]["cancel_requested"] = True
    job = w.run()
    assert job["status"] == "cancelled" and w.model.calls == 0 and w.resource["summary"] == "old summary"
