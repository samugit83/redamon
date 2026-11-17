"""Incremental refresh on a real Postgres (T6.2, R-342): two refreshes of a Stored wiki through the
job runner, the pipeline and the page store, and ``Store.copy_forward`` keyed by owner and resource.

Runs through ``tooling/scripts/tradecraft_pg_testdb.sh agent``; skips without ``TRADECRAFT_PG_TEST_URL``.
"""

from __future__ import annotations

import asyncio
import functools
import hashlib
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

from tradecraft import db, jobs  # noqa: E402
from tradecraft.contract import JobStartBatch  # noqa: E402
from tradecraft.ingest import pipeline  # noqa: E402
from tradecraft.net import Response  # noqa: E402
from tradecraft.store import ResourceGone, Store  # noqa: E402
from tradecraft_doubles import FixtureFetcher  # noqa: E402
from tradecraft_memory_store import PipelineModel, padded_sites  # noqa: E402

FIXTURE = json.loads((Path(__file__).resolve().parent / "fixtures" / "tradecraft_contract" /
                      "JobStartBatch.valid.json").read_text())["jobs"][0]
WIKI = "https://wiki.tc-fixture.test/"
UNION = WIKI + "sqli/union-based/"
PLAIN = {"fetching.browserEnabled": False}


class ValidatingSite(FixtureFetcher):
    """An ETag on every 200, and 304 when it comes back unchanged."""

    def __init__(self, root):
        super().__init__(root)
        self.full: list[str] = []
        self.not_modified: list[str] = []

    async def get(self, url, *, headers=None, **kw):
        resp = await super().get(url, headers=headers, **kw)
        if resp.status != 200:
            return resp
        etag = '"' + hashlib.sha256(resp.body).hexdigest()[:16] + '"'
        if {k.lower(): v for k, v in (headers or {}).items()}.get("if-none-match") == etag:
            self.not_modified.append(resp.final_url)
            return Response(url=resp.url, final_url=resp.final_url, status=304, headers={"etag": etag}, body=b"",
                            content_type="", redirects=resp.redirects)
        self.full.append(resp.final_url)
        resp.headers["etag"] = etag
        return resp


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
        await self.sql("INSERT INTO users (id, name, email, updated_at) VALUES (%s, 'Incr', %s, now())", uid,
                       f"{uid}@example.test")
        self.users.append(uid)
        return uid

    async def resource(self, uid, url=WIKI, mode="stored", generation=0):
        rid = f"tc-r-{uuid.uuid4().hex[:12]}"
        await self.sql("INSERT INTO user_tradecraft_resources (id, user_id, name, slug, url, storage_mode, generation, "
                       "updated_at) VALUES (%s, %s, 'Res', %s, %s, %s, %s, now())",
                       rid, uid, f"res-{rid[-6:]}", url, mode, generation)
        return rid

    async def job(self, uid, rid):
        jid = f"tc-j-{uuid.uuid4().hex[:12]}"
        await self.sql("INSERT INTO tradecraft_ingestion_jobs (id, user_id, resource_id, kind, lease_until) "
                       "VALUES (%s, %s, %s, 'refresh', %s)", jid, uid, rid,
                       datetime.now(timezone.utc) + timedelta(seconds=60))
        await self.sql("UPDATE user_tradecraft_resources SET active_job_id = %s WHERE id = %s", jid, rid)
        return jid

    async def live(self, rid):
        return {r["url"]: r for r in await self.sql(
            "SELECT e.* FROM tradecraft_entries e JOIN user_tradecraft_resources r ON r.id = e.resource_id "
            "AND r.user_id = e.user_id AND e.generation = r.generation WHERE e.resource_id = %s", rid)}

    async def sections(self, entry_id):
        return [(r["ord"], r["heading"], r["text"], r["indexed"]) for r in await self.sql(
            "SELECT ord, heading, text, search_vector IS NOT NULL AS indexed FROM tradecraft_sections "
            "WHERE entry_id = %s ORDER BY ord", entry_id)]


async def refresh(pg, fetcher, uid, rid, settings):
    store = Store()
    jid = await pg.job(uid, rid)
    model = PipelineModel()

    async def build_llm(owner, model_id):
        return model

    spec = json.loads(json.dumps(FIXTURE))
    spec.update(job_id=jid, user_id=uid, actor_user_id=uid, resource_id=rid, settings=dict(settings))
    spec["resource"].update(url=WIKI, storage_mode="stored", model="openai/fake-small-model")
    runner = jobs.JobRunner(store, instance=f"it-{uuid.uuid4().hex[:6]}", fetcher_factory=lambda: fetcher)
    runner._entry = functools.partial(pipeline.run, store=store, run_blocking=runner.run_blocking, build_llm=build_llm)
    answer = await runner.submit(JobStartBatch.model_validate({"jobs": [spec]}))
    assert answer.accepted == [jid], answer
    await asyncio.wait_for(runner._running[jid].task, timeout=60)
    await runner.close()
    job = (await pg.sql("SELECT status, error_code FROM tradecraft_ingestion_jobs WHERE id = %s", jid))[0]
    assert job["status"] == "succeeded", job


async def test_only_changed_rebuilt(pg, tmp_path):
    root = padded_sites(tmp_path)
    fetcher = ValidatingSite(root)
    uid = await pg.user()
    rid = await pg.resource(uid)
    await refresh(pg, fetcher, uid, rid, PLAIN)
    first = await pg.live(rid)
    pages = {u for u, e in first.items() if e["stored_text"]}
    first_sections = {u: await pg.sections(first[u]["id"]) for u in pages}
    assert len(pages) > 10 and all(first_sections[u] for u in pages)

    page = root / "wiki.tc-fixture.test" / "sqli" / "union-based" / "index.html"
    page.write_text(page.read_text().replace("</article>", "<h2>Fresh section</h2><p>" + "fresh words " * 30
                                             + "</p></article>", 1))
    fetcher.full.clear()
    fetcher.not_modified.clear()
    await refresh(pg, fetcher, uid, rid, PLAIN)
    second = await pg.live(rid)
    assert {u for u, e in second.items() if e["stored_text"]} == pages
    assert set(fetcher.not_modified) == pages - {UNION} and UNION in fetcher.full
    for url in pages - {UNION}:
        old, new = first[url], second[url]
        assert new["generation"] == old["generation"] + 1 and new["id"] != old["id"]
        assert (new["stored_text"], new["text_hash"], new["stored_bytes"], new["fetched_at"], new["etag"]) == \
               (old["stored_text"], old["text_hash"], old["stored_bytes"], old["fetched_at"], old["etag"])
        # The sections came across as rows of the new entry, indexed by the trigger like any write.
        assert await pg.sections(new["id"]) == first_sections[url]
    assert "fresh words" in second[UNION]["stored_text"]
    assert second[UNION]["fetched_at"] > first[UNION]["fetched_at"]
    assert any(h == "Fresh section" for _o, h, _t, _i in await pg.sections(second[UNION]["id"]))
    # The runner purged the old generation: the copies are rows of their own.
    old_rows = await pg.sql("SELECT count(*) AS n FROM tradecraft_entries WHERE resource_id = %s AND generation = %s",
                            rid, first[UNION]["generation"])
    assert old_rows[0]["n"] == 0
    report = (await pg.sql("SELECT ingestion_report FROM user_tradecraft_resources WHERE id = %s", rid))[0]
    assert report["ingestion_report"]["stored"]["pages"] == len(pages)


async def _seed(pg, store, uid, rid, gen, urls):
    ids = await store.allocate_page_ids(uid, rid, urls)
    rows = [{"page_id": ids[u], "url": u, "title": f"old {i}", "stored_text": f"text {i} of {rid}",
             "stored_bytes": len(f"text {i} of {rid}"), "text_hash": f"{i:064x}", "size_chars": 12,
             "fetched_at": "2026-11-01T00:00:00+00:00", "etag": f'"e{i}"'} for i, u in enumerate(urls)]
    entries = await store.write_entries(uid, rid, gen, rows)
    await store.write_sections(uid, rid, gen, [{"entry_id": entries[ids[u]], "ord": 0, "level": 1, "heading": "H",
                                                "text": f"section of {u}"} for u in urls])
    return ids


async def test_copy_forward_keyed(pg):
    store = Store()
    a, b = await pg.user(), await pg.user()
    ra, rb = await pg.resource(a, generation=1), await pg.resource(b, generation=1)
    urls = [WIKI + "p1/", WIKI + "p2/"]
    ids_a = await _seed(pg, store, a, ra, 1, urls)
    ids_b = await _seed(pg, store, b, rb, 1, urls)
    card = {"page_id": ids_a[urls[0]], "url": urls[0], "title": "new title", "title_source": "renamed",
            "status": "kept", "topics": ["sqli"], "etag": ""}

    copied = await store.copy_forward(a, ra, 1, 2, [card])
    assert list(copied) == [ids_a[urls[0]]]
    row = (await pg.sql("SELECT * FROM tradecraft_entries WHERE id = %s", copied[ids_a[urls[0]]]))[0]
    assert (row["generation"], row["user_id"], row["resource_id"]) == (2, a, ra)
    assert row["title"] == "new title" and row["title_source"] == "renamed" and row["topics"] == ["sqli"]
    assert row["stored_text"] == f"text 0 of {ra}" and row["etag"] == '"e0"' and row["text_hash"] == f"{0:064x}"
    assert [s[2] for s in await pg.sections(row["id"])] == [f"section of {urls[0]}"]

    # Another owner's resource: nothing copied, the resource is not this owner's.
    with pytest.raises(ResourceGone):
        await store.copy_forward(a, rb, 1, 2, [dict(card, page_id=ids_b[urls[0]])])
    # A page of another resource named in this one: refused, nothing written.
    with pytest.raises(ValueError):
        await store.copy_forward(a, ra, 1, 2, [dict(card, page_id=ids_b[urls[1]], url=urls[1])])
    # Its own generation, never: a copy needs a generation to come from.
    with pytest.raises(ValueError):
        await store.copy_forward(a, ra, 1, 1, [dict(card, page_id=ids_a[urls[1]], url=urls[1])])
    counts = await pg.sql("SELECT resource_id, generation, count(*) AS n FROM tradecraft_entries "
                          "WHERE resource_id = ANY(%s) GROUP BY 1, 2 ORDER BY 1, 2", [ra, rb])
    assert {(c["resource_id"], c["generation"]): c["n"] for c in counts} == {(ra, 1): 2, (ra, 2): 1, (rb, 1): 2}
    sections_b = await pg.sql("SELECT count(*) AS n FROM tradecraft_sections WHERE resource_id = %s", rb)
    assert sections_b[0]["n"] == 2


async def test_refresh_basis_holds_no_text(pg):
    store = Store()
    a = await pg.user()
    ra = await pg.resource(a, generation=1)
    await _seed(pg, store, a, ra, 1, [WIKI + "p1/"])
    basis = await store.refresh_basis(a, ra)
    assert len(basis) == 1 and "stored_text" not in basis[0]
    assert basis[0]["text_hash"] == f"{0:064x}" and basis[0]["generation"] == 1
    other = await pg.user()
    assert await store.refresh_basis(other, ra) == []
