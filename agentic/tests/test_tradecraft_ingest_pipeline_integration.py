"""The 2.0 ingestion end to end on Postgres (T1.8): job runner, pipeline and page store.

``test_defaults_match_1x`` (AC-01, R-005) runs 1.x ``verify_resource`` and a 2.0 job with the
default settings on the same fixture site, through the same ``FixtureFetcher`` and the same
scripted model: the same type, at least as many map entries, a summary. The fixture start
pages carry an article here (``padded_sites``): the generated ones are thin, which makes 1.x
type every site as a website.

Runs through ``tooling/scripts/tradecraft_pg_testdb.sh agent``; skips without
``TRADECRAFT_PG_TEST_URL``.
"""

from __future__ import annotations

import asyncio
import functools
import json
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

PG_URL = os.environ.get("TRADECRAFT_PG_TEST_URL", "")
pytestmark = pytest.mark.skipif(not PG_URL, reason="TRADECRAFT_PG_TEST_URL is not set (tradecraft_pg_testdb.sh agent)")

import psycopg  # noqa: E402
from psycopg.rows import dict_row  # noqa: E402

from orchestrator_helpers import tradecraft_crawl as legacy_crawl  # noqa: E402
from orchestrator_helpers import tradecraft_lookup as legacy  # noqa: E402
from tradecraft import db, jobs  # noqa: E402
from tradecraft.contract import JobStartBatch  # noqa: E402
from tradecraft.ingest import fetch, pipeline  # noqa: E402
from tradecraft.store import Store  # noqa: E402
from tradecraft_doubles import FixtureFetcher  # noqa: E402
from tradecraft_memory_store import PipelineModel, padded_sites  # noqa: E402

FIXTURE = json.loads((Path(__file__).resolve().parent / "fixtures" / "tradecraft_contract" /
                      "JobStartBatch.valid.json").read_text())["jobs"][0]
LEGACY_BOUNDS = {"max_pages": 30, "max_llm_calls": 20, "time_budget_sec": 180, "max_depth": 3}


class _HttpxAnswer:
    def __init__(self, resp):
        self.status_code, self.headers, self.text = resp.status, dict(resp.headers), resp.text

    def json(self):
        return json.loads(self.text)


def legacy_on(monkeypatch, fetcher):
    """1.x's fetch tiers, crawl fetch, GitHub client and URL check, on ``fetcher``."""

    async def tier1(url, *, timeout=30, github_token="", expect_text=True):
        url = legacy._rewrite_github_url(url)
        r = await fetcher.get(url)
        if r.error:
            return legacy.FetchResult(text="", content_type="", status=0, tier=1)
        if "application/pdf" in r.content_type or r.body[:5] == b"%PDF-":
            return legacy.FetchResult(text="", content_type="application/pdf", status=r.status, tier=1,
                                      raw_bytes=r.body, final_url=r.final_url)
        text = legacy._html_to_markdown(r.text) if (expect_text and "html" in r.content_type) else r.text
        return legacy.FetchResult(text=text, content_type=r.content_type, status=r.status, tier=1,
                                  raw_bytes=r.text.encode(), final_url=r.final_url)

    async def tier2(url, mcp_manager):
        rendered = await fetcher.render(url)
        if not rendered.html:
            return legacy.FetchResult(text="", content_type="", status=0, tier=2)
        return legacy.FetchResult(text=legacy._html_to_markdown(rendered.html), content_type="text/html",
                                  status=200, tier=2, raw_bytes=rendered.html.encode())

    async def crawl_fetch(url, mcp_manager, *, tier1_threshold_bytes=4000):
        r = await fetcher.get(url)
        html = r.text if (r.status == 200 and "html" in r.content_type) else ""
        if html and len(html) >= tier1_threshold_bytes:
            return html, 1, r.final_url
        rendered = await fetcher.render(url)
        return (rendered.html, 2, url) if rendered.html else ("", 0, url)

    class Client:
        def __init__(self, *args, headers=None, **kwargs):
            self._headers = headers or {}

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def get(self, url):
            return _HttpxAnswer(await fetcher.get(url, headers=self._headers))

    monkeypatch.setattr(legacy, "fetch_tier1", tier1)
    monkeypatch.setattr(legacy, "fetch_tier2", tier2)
    monkeypatch.setattr(legacy, "validate_url", lambda url: (True, ""))
    monkeypatch.setattr(legacy.httpx, "AsyncClient", Client)
    monkeypatch.setattr(legacy_crawl, "_crawl_fetch", crawl_fetch)


@pytest.fixture
async def pg(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", PG_URL)
    db.reset()
    conn = await psycopg.AsyncConnection.connect(PG_URL, autocommit=True, row_factory=dict_row)
    helper = Pg(conn)
    try:
        yield helper
    finally:
        await db.close()
        if helper.users:
            await conn.execute("DELETE FROM users WHERE id = ANY(%s)", (helper.users,))
        await conn.close()


class Pg:
    def __init__(self, conn):
        self.conn = conn
        self.users: list[str] = []

    async def sql(self, query, *params):
        cur = await self.conn.execute(query, params)
        return await cur.fetchall() if cur.description else []

    async def user(self):
        uid = f"tc-u-{uuid.uuid4().hex[:12]}"
        await self.sql("INSERT INTO users (id, name, email, updated_at) VALUES (%s, 'Ingest', %s, now())", uid,
                       f"{uid}@example.test")
        self.users.append(uid)
        return uid

    async def resource(self, uid, url, mode):
        rid = f"tc-r-{uuid.uuid4().hex[:12]}"
        await self.sql("INSERT INTO user_tradecraft_resources (id, user_id, name, slug, url, storage_mode, summary, "
                       "updated_at) VALUES (%s, %s, 'Res', %s, %s, %s, 'previous summary', now())",
                       rid, uid, f"res-{rid[-6:]}", url, mode)
        return rid

    async def job(self, uid, rid):
        jid = f"tc-j-{uuid.uuid4().hex[:12]}"
        await self.sql("INSERT INTO tradecraft_ingestion_jobs (id, user_id, resource_id, kind, lease_until) "
                       "VALUES (%s, %s, %s, 'refresh', %s)", jid, uid, rid,
                       datetime.now(timezone.utc) + timedelta(seconds=60))
        await self.sql("UPDATE user_tradecraft_resources SET active_job_id = %s WHERE id = %s", jid, rid)
        return jid

    async def row(self, table, key):
        return (await self.sql(f"SELECT * FROM {table} WHERE id = %s", key))[0]


async def ingest(pg, root, url, *, mode="live", settings=None, model=None, uid=None, rid=None):
    """One 2.0 job through the real runner, pipeline and store; returns (uid, rid, job row, model)."""
    store = Store()
    uid = uid or await pg.user()
    rid = rid or await pg.resource(uid, url, mode)
    jid = await pg.job(uid, rid)
    model = model or PipelineModel()

    async def build_llm(owner, model_id):
        assert owner == uid
        return model

    spec = json.loads(json.dumps(FIXTURE))
    spec.update(job_id=jid, user_id=uid, actor_user_id=uid, resource_id=rid, settings=dict(settings or {}))
    spec["resource"].update(url=url, storage_mode=mode, model="openai/fake-small-model")
    runner = jobs.JobRunner(store, instance=f"it-{uuid.uuid4().hex[:6]}", fetcher_factory=lambda: FixtureFetcher(root))
    runner._entry = functools.partial(pipeline.run, store=store, run_blocking=runner.run_blocking, build_llm=build_llm)
    answer = await runner.submit(JobStartBatch.model_validate({"jobs": [spec]}))
    assert answer.accepted == [jid], answer
    await asyncio.wait_for(runner._running[jid].task, timeout=60)
    await runner.close()
    return uid, rid, await pg.row("tradecraft_ingestion_jobs", jid), model


SITES = [
    ("https://wiki.tc-fixture.test/", "mkdocs-wiki"),
    ("https://docs.tc-fixture.test/", "sphinx-docs"),
    ("https://book.tc-fixture.test/", "gitbook"),
    ("https://github.com/tc-fixture/payloads", "github-repo"),
    ("https://github.com/tc-fixture/cve", "cve-poc-db"),
    ("https://blog.tc-fixture.test/", "agentic-crawl"),
    ("https://files.tc-fixture.test/guide.pdf", "agentic-crawl"),
]


@pytest.mark.parametrize("url,expected_type", SITES)
async def test_defaults_match_1x(pg, tmp_path, monkeypatch, url, expected_type):
    root = padded_sites(tmp_path)
    legacy_on(monkeypatch, FixtureFetcher(root))
    old = await legacy.verify_resource(url, llm=PipelineModel(), mcp_manager=None, bounds=LEGACY_BOUNDS)
    assert old["resource_type"] == expected_type and old["summary"]
    old_entries = {fetch.canonical_url(e["path"]) if e["path"].startswith("http") else e["path"]
                   for e in legacy._sitemap_entries(old["sitemap"])}
    if "pages" in old["sitemap"]:
        old_entries = {p["page"] for p in old["sitemap"]["pages"]}
    # Not a vacuous comparison: 1.x lists every site but the CVE archive (never listed).
    assert bool(old_entries) == (expected_type != "cve-poc-db") or url.endswith(".pdf")
    assert url.endswith(".pdf") is False or len(old_entries) == 3

    uid, rid, job, _model = await ingest(pg, root, url)
    assert job["status"] == "succeeded", job["error_code"]
    res = await pg.row("user_tradecraft_resources", rid)
    assert res["resource_type"] == old["resource_type"]
    assert res["summary"] and res["map_version"] == 3 and res["generation"] >= 1
    live = await pg.sql("SELECT url FROM tradecraft_entries WHERE resource_id = %s AND generation = %s",
                        rid, res["generation"])
    assert len(live) >= len(old_entries)
    if old["resource_type"] == "cve-poc-db":
        assert res["sitemap"] == {k: old["sitemap"][k] for k in ("owner", "repo", "branch")}


async def test_stored_row_content(pg, tmp_path):
    root = padded_sites(tmp_path)
    uid, rid, job, _ = await ingest(pg, root, "https://wiki.tc-fixture.test/", mode="stored")
    assert job["status"] == "succeeded"
    rows = await pg.sql("SELECT e.url, e.stored_text, e.stored_bytes, e.text_hash, e.fetched_at, e.size_chars, "
                        "e.search_vector IS NOT NULL AS indexed, e.user_id FROM tradecraft_entries e "
                        "JOIN user_tradecraft_resources r ON r.id = e.resource_id AND e.generation = r.generation "
                        "WHERE e.resource_id = %s", rid)
    stored = [r for r in rows if r["stored_text"]]
    assert stored and all(r["user_id"] == uid for r in rows)
    for r in stored:
        assert r["stored_bytes"] == len(r["stored_text"].encode()) and len(r["text_hash"]) == 64
        assert r["fetched_at"] is not None and r["size_chars"] == len(r["stored_text"])
        assert r["indexed"]  # the trigger of apply-tradecraft-search.mjs filled the vector
    report = (await pg.row("user_tradecraft_resources", rid))["ingestion_report"]
    assert report["stored"]["pages"] == len(stored)


async def test_refresh_replaces(pg, tmp_path):
    """R-193: a refresh rebuilds the map and replaces the stored pages; page IDs stay."""
    root = padded_sites(tmp_path)
    url = "https://wiki.tc-fixture.test/"
    uid, rid, job, _ = await ingest(pg, root, url, mode="stored")
    first = {r["url"]: r["page_id"] for r in await pg.sql(
        "SELECT url, page_id FROM tradecraft_entries WHERE resource_id = %s", rid)}
    _, _, job2, _ = await ingest(pg, root, url, mode="stored", uid=uid, rid=rid,
                                 model=PipelineModel(summary="the second summary"))
    assert job2["status"] == "succeeded"
    res = await pg.row("user_tradecraft_resources", rid)
    rows = await pg.sql("SELECT url, page_id, generation FROM tradecraft_entries WHERE resource_id = %s", rid)
    assert {r["generation"] for r in rows} == {res["generation"]} == {2}
    assert {r["url"]: r["page_id"] for r in rows} == first
    assert res["summary"] == "the second summary"


async def test_failed_refresh_keeps_previous(pg, tmp_path):
    """AC-37: a refresh that fails leaves the previous summary, map and pages."""
    root = padded_sites(tmp_path)
    url = "https://wiki.tc-fixture.test/"
    uid, rid, _, _ = await ingest(pg, root, url, mode="stored")
    before = await pg.row("user_tradecraft_resources", rid)
    count = (await pg.sql("SELECT count(*) AS n FROM tradecraft_entries WHERE resource_id = %s", rid))[0]["n"]
    # The site is gone: every request fails.
    _, _, job, _ = await ingest(pg, tmp_path / "empty", url, mode="stored", uid=uid, rid=rid)
    assert job["status"] == "failed" and job["error_code"] == "fetch_failed"
    after = await pg.row("user_tradecraft_resources", rid)
    for column in ("summary", "sitemap", "generation", "resource_type", "ingestion_report"):
        assert after[column] == before[column], column
    assert after["last_error"] == "fetch_failed" and after["active_job_id"] is None
    assert (await pg.sql("SELECT count(*) AS n FROM tradecraft_entries WHERE resource_id = %s", rid))[0]["n"] == count
