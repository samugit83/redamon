"""AC-11 on Postgres (T5.1, T5.2): a focus "SQL injection × payloads" keeps the matching pages of a
wiki, a GitHub repository and a website, drops the rest with their reason (kept in the entry
table for the Map view, outside search and the 1.x map), and the summary describes the subset.

Real runner, pipeline, store and search on the disposable database; the sites are the fixture
tree and the model is scripted (it judges by title and path, as a model would). Runs through
``tooling/scripts/tradecraft_pg_testdb.sh agent``; skips without ``TRADECRAFT_PG_TEST_URL``.
"""

from __future__ import annotations

import asyncio
import functools
import json
import os
import re
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

PG_URL = os.environ.get("TRADECRAFT_PG_TEST_URL", "")
pytestmark = pytest.mark.skipif(not PG_URL, reason="TRADECRAFT_PG_TEST_URL is not set (tradecraft_pg_testdb.sh agent)")

from test_tradecraft_ingest_pipeline_integration import FIXTURE, pg  # noqa: E402,F401
from tradecraft import jobs  # noqa: E402
from tradecraft.contract import IngestionReport, JobStartBatch, V2Catalog  # noqa: E402
from tradecraft.ingest import pipeline  # noqa: E402
from tradecraft.library import search  # noqa: E402
from tradecraft.store import Store  # noqa: E402
from tradecraft_doubles import FixtureFetcher  # noqa: E402
from tradecraft_memory_store import padded_sites  # noqa: E402

FOCUS = {"mode": "focused", "topics": ["sql_injection"], "kinds": ["payloads"], "keep": "SQL injection payloads",
         "skip": "news", "strictness": "balanced"}
SUBSET = "SQL injection subset of the site: payloads and bypasses."
ENTRY = re.compile(r"^(\d+)\. (.*) — (.*)$", re.M)
SETTINGS = {"fetching.browserEnabled": False, "crawl.minTextChars": 0, "crawl.maxPages": 40, "crawl.linksPerPage": 40}


def sqli(text: str) -> bool:
    return bool(re.search(r"sqli|sql", text, re.I))


class SiteModel:
    """The resource's model: the triage keeps SQL injection by title and path, the crawl follows
    every link and keeps the SQL injection posts, the summary says what it was asked to cover."""

    def __init__(self):
        self.triage = self.crawl = self.summaries = 0

    async def ainvoke(self, messages, config=None, **kwargs):
        from langchain_core.messages import AIMessage
        if not isinstance(messages, str):
            self.summaries += 1
            focused = "keeps only part of the site" in messages[0]["content"]
            return AIMessage(content=SUBSET if focused else "A whole library of web attacks.")
        if "The owner's focus:" in messages and "Entries (number. title — path)" in messages:
            self.triage += 1
            block = messages.split("Entries (number. title — path):", 1)[1]
            answer = [{"n": int(n), "decision": "keep" if sqli(t + p) else "drop",
                       "reason": "SQL injection payloads" if sqli(t + p) else "not SQL injection",
                       "topics": ["sql_injection"] if sqli(t + p) else [], "kinds": ["payloads"]}
                      for n, t, p in ENTRY.findall(block)]
            return AIMessage(content=json.dumps({"entries": answer}))
        if "Just visited:" in messages:
            self.crawl += 1
            current = re.search(r"Just visited: (\S+)", messages).group(1)
            offered = re.findall(r'^\s+(\d+)\. "', messages, re.M)
            keep = sqli(current)
            return AIMessage(content=json.dumps({"action": "follow", "indices": [int(n) for n in offered],
                                                 "keep": keep, "reason": "SQL injection post" if keep else "a hub"}))
        if "You tag the pages" in messages:
            return AIMessage(content='{"entries": []}')
        return AIMessage(content="{}")


async def ingest(pg, root, url, model):
    store = Store()
    uid = await pg.user()
    rid = await pg.resource(uid, url, "live")
    jid = await pg.job(uid, rid)

    async def build_llm(owner, model_id):
        return model

    spec = json.loads(json.dumps(FIXTURE))
    spec.update(job_id=jid, user_id=uid, actor_user_id=uid, resource_id=rid, settings=dict(SETTINGS))
    spec["resource"].update(url=url, storage_mode="live", model="openai/fake-small-model", focus=FOCUS)
    runner = jobs.JobRunner(store, instance=f"fc-{uuid.uuid4().hex[:6]}", fetcher_factory=lambda: FixtureFetcher(root))
    runner._entry = functools.partial(pipeline.run, store=store, run_blocking=runner.run_blocking, build_llm=build_llm)
    answer = await runner.submit(JobStartBatch.model_validate({"jobs": [spec]}))
    assert answer.accepted == [jid], answer
    await asyncio.wait_for(runner._running[jid].task, timeout=120)
    await runner.close()
    job = await pg.row("tradecraft_ingestion_jobs", jid)
    assert job["status"] == "succeeded", job["error_code"]
    return uid, rid


async def entries(pg, rid):
    return await pg.sql("SELECT e.url, e.title, e.status, e.drop_reason FROM tradecraft_entries e "
                        "JOIN user_tradecraft_resources r ON r.id = e.resource_id AND e.generation = r.generation "
                        "WHERE e.resource_id = %s", rid)


@pytest.mark.parametrize("url,triaged,crawled", [
    ("https://wiki.tc-fixture.test/", True, False),
    ("https://github.com/tc-fixture/payloads", True, False),
    ("https://blog.tc-fixture.test/", True, True),
])
async def test_a_focus_keeps_the_matches(pg, tmp_path, url, triaged, crawled):
    model = SiteModel()
    uid, rid = await ingest(pg, padded_sites(tmp_path), url, model)
    rows = await entries(pg, rid)
    kept = [r for r in rows if r["status"] == "kept"]
    dropped = [r for r in rows if r["status"] == "dropped"]
    assert kept and dropped
    assert all(sqli(r["url"] + r["title"]) for r in kept), [r["url"] for r in kept if not sqli(r["url"] + r["title"])]
    assert all(r["drop_reason"] for r in dropped)
    assert (model.triage > 0) == triaged and (model.crawl > 0) == crawled

    resource = await pg.row("user_tradecraft_resources", rid)
    assert resource["summary"] == SUBSET
    report = IngestionReport.model_validate(resource["ingestion_report"])
    assert report.focus["mode"] == "focused" and report.focus["dropped"] == len(dropped) == report.skipped.outsideFocus
    assert report.kept == len(kept) == report.focus["kept"]
    legacy = resource["sitemap"].get("nav") or resource["sitemap"].get("tree") or []
    assert legacy and all(sqli(i["path"] + i["title"]) for i in legacy)

    catalog = V2Catalog.model_validate({"v2": True, "owner_id": uid, "person_id": uid, "actor_id": None, "search": {},
                                        "resources": [{"id": rid, "slug": resource["slug"], "name": "Res", "url": url,
                                                       "type": resource["resource_type"], "storage_mode": "live",
                                                       "map_version": 3}]})
    found = await search.search(uid, catalog, "sql injection")
    assert found.hits and all(sqli(h.card.url + h.card.title) for h in found.hits)
    others = await search.search(uid, catalog, "xss")
    assert all(sqli(h.card.url + h.card.title) for h in others.hits)
    if crawled:
        home = next(r for r in dropped if r["url"].rstrip("/") == url.rstrip("/"))
        assert home["drop_reason"] == "a hub"
