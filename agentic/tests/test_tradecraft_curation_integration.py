"""Curation at ingestion on a real Postgres (T6.6): the curation rows the Map view writes, read by the
store keyed by owner; a refresh through the runner, the pipeline and the store that keeps pins,
blocks and renames; ``clear_blocked`` on the job's own generation.

Runs through ``tooling/scripts/tradecraft_pg_testdb.sh agent``; skips without ``TRADECRAFT_PG_TEST_URL``.
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

from tradecraft import db, jobs  # noqa: E402
from tradecraft.contract import JobStartBatch  # noqa: E402
from tradecraft.ingest import pipeline  # noqa: E402
from tradecraft.store import Store  # noqa: E402
from tradecraft_doubles import FixtureFetcher  # noqa: E402
from tradecraft_memory_store import PipelineModel, padded_sites  # noqa: E402

FIXTURE = json.loads((Path(__file__).resolve().parent / "fixtures" / "tradecraft_contract" /
                      "JobStartBatch.valid.json").read_text())["jobs"][0]
WIKI = "https://wiki.tc-fixture.test/"
UNION = WIKI + "sqli/union-based/"
ERROR = WIKI + "sqli/error-based/"
OTHER = "https://other.tc-fixture.test/landing.html"
PLAIN = {"fetching.browserEnabled": False}


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
        await self.sql("INSERT INTO users (id, name, email, updated_at) VALUES (%s, 'Cur', %s, now())", uid,
                       f"{uid}@example.test")
        self.users.append(uid)
        return uid

    async def resource(self, uid, generation=0):
        rid = f"tc-r-{uuid.uuid4().hex[:12]}"
        await self.sql("INSERT INTO user_tradecraft_resources (id, user_id, name, slug, url, storage_mode, generation, "
                       "updated_at) VALUES (%s, %s, 'Res', %s, %s, 'stored', %s, now())",
                       rid, uid, f"res-{rid[-6:]}", WIKI, generation)
        return rid

    async def curate(self, rid, url, **flags):
        """As the Map view writes a row (W/src/lib/tradecraft/curation.ts)."""
        cols = {"pinned": False, "blocked": False, "renamed_title": None, "restored_from_drop": False, **flags}
        await self.sql("INSERT INTO tradecraft_curations (id, resource_id, url, pinned, blocked, renamed_title, "
                       "restored_from_drop) VALUES (%s, %s, %s, %s, %s, %s, %s) ON CONFLICT (resource_id, url) DO UPDATE "
                       "SET pinned = EXCLUDED.pinned, blocked = EXCLUDED.blocked, renamed_title = EXCLUDED.renamed_title, "
                       "restored_from_drop = EXCLUDED.restored_from_drop",
                       f"c-{uuid.uuid4().hex[:12]}", rid, url, cols["pinned"], cols["blocked"], cols["renamed_title"],
                       cols["restored_from_drop"])

    async def live(self, rid):
        return {r["url"]: r for r in await self.sql(
            "SELECT e.* FROM tradecraft_entries e JOIN user_tradecraft_resources r ON r.id = e.resource_id "
            "AND r.user_id = e.user_id AND e.generation = r.generation WHERE e.resource_id = %s", rid)}


async def refresh(pg, root, uid, rid):
    store = Store()
    jid = f"tc-j-{uuid.uuid4().hex[:12]}"
    await pg.sql("INSERT INTO tradecraft_ingestion_jobs (id, user_id, resource_id, kind, lease_until) "
                 "VALUES (%s, %s, %s, 'refresh', %s)", jid, uid, rid, datetime.now(timezone.utc) + timedelta(seconds=60))
    await pg.sql("UPDATE user_tradecraft_resources SET active_job_id = %s WHERE id = %s", jid, rid)

    async def build_llm(owner, model_id):
        return PipelineModel()

    spec = json.loads(json.dumps(FIXTURE))
    spec.update(job_id=jid, user_id=uid, actor_user_id=uid, resource_id=rid, settings=dict(PLAIN))
    spec["resource"].update(url=WIKI, storage_mode="stored", model="openai/fake-small-model")
    runner = jobs.JobRunner(store, instance=f"it-{uuid.uuid4().hex[:6]}", fetcher_factory=lambda: FixtureFetcher(root))
    runner._entry = functools.partial(pipeline.run, store=store, run_blocking=runner.run_blocking, build_llm=build_llm)
    assert (await runner.submit(JobStartBatch.model_validate({"jobs": [spec]}))).accepted == [jid]
    await asyncio.wait_for(runner._running[jid].task, timeout=60)
    await runner.close()
    job = (await pg.sql("SELECT status, error_code FROM tradecraft_ingestion_jobs WHERE id = %s", jid))[0]
    assert job["status"] == "succeeded", job


async def test_a_refresh_keeps_the_curation(pg, tmp_path):
    root = padded_sites(tmp_path)
    uid = await pg.user()
    rid = await pg.resource(uid)
    await refresh(pg, root, uid, rid)
    await pg.curate(rid, ERROR, blocked=True)
    await pg.curate(rid, UNION, renamed_title="My union notes")
    await pg.curate(rid, OTHER, pinned=True)
    await refresh(pg, root, uid, rid)
    live = await pg.live(rid)
    assert ERROR not in live
    assert live[UNION]["title"] == "My union notes" and live[UNION]["title_source"] == "renamed"
    assert live[OTHER]["source"] == "pin" and live[OTHER]["stored_text"]
    res = (await pg.sql("SELECT sitemap FROM user_tradecraft_resources WHERE id = %s", rid))[0]["sitemap"]
    assert ERROR not in {e["path"] for e in res["nav"]}


async def test_curation_rows_are_the_owners(pg):
    store = Store()
    a, b = await pg.user(), await pg.user()
    ra = await pg.resource(a)
    await pg.curate(ra, UNION, renamed_title="x")
    rows = await store.curation_rows(a, ra)
    assert rows == [{"url": UNION, "pinned": False, "blocked": False, "renamed_title": "x", "restored_from_drop": False}]
    assert await store.curation_rows(b, ra) == []


async def test_clear_blocked_on_the_jobs_generation(pg):
    store = Store()
    a, b = await pg.user(), await pg.user()
    ra, rb = await pg.resource(a, generation=1), await pg.resource(b, generation=1)
    for uid, rid in ((a, ra), (b, rb)):
        ids = await store.allocate_page_ids(uid, rid, [UNION, ERROR])
        for gen in (1, 2):
            entries = await store.write_entries(uid, rid, gen, [
                {"page_id": ids[u], "url": u, "stored_text": f"text of {u}", "stored_bytes": 100, "text_hash": "h"}
                for u in (UNION, ERROR)])
            await store.write_sections(uid, rid, gen, [{"entry_id": entries[ids[u]], "ord": 0, "level": 1,
                                                        "text": "section"} for u in (UNION, ERROR)])
    # The Map view's block emptied ERROR's text in generation 2 before the job wrote its sections
    # (S10 review 2, finding 1): its sections must go all the same.
    await pg.sql("UPDATE tradecraft_entries SET stored_text = NULL, stored_bytes = 0 "
                 "WHERE resource_id = %s AND generation = 2 AND url = %s", ra, ERROR)
    assert sorted(await store.clear_blocked(a, ra, 2, [UNION, ERROR])) == sorted([UNION, ERROR])
    rows = await pg.sql("SELECT e.resource_id, e.generation, e.url, e.stored_text IS NULL AS cleared, "
                        "(SELECT count(*) FROM tradecraft_sections s WHERE s.entry_id = e.id) AS sections "
                        "FROM tradecraft_entries e WHERE e.resource_id = ANY(%s)", [ra, rb])
    cleared = {(r["resource_id"], r["generation"], r["url"]) for r in rows if r["cleared"]}
    assert cleared == {(ra, 2, UNION), (ra, 2, ERROR)}
    assert all(r["sections"] == (0 if (r["resource_id"], r["generation"], r["url"]) in cleared else 1) for r in rows)
    # Twice finds the rows and changes nothing more; another owner names no row of this resource.
    assert sorted(await store.clear_blocked(a, ra, 2, [UNION])) == [UNION]
    assert await store.clear_blocked(b, ra, 1, [UNION]) == []
    assert await store.clear_blocked(a, ra, 2, []) == []


async def test_restore_pinned_keeps_only_the_live_generation(pg):
    store = Store()
    a, b = await pg.user(), await pg.user()
    ra = await pg.resource(a, generation=2)
    ids = await store.allocate_page_ids(a, ra, [UNION, ERROR])
    for gen in (1, 2):
        await store.write_entries(a, ra, gen, [{"page_id": ids[u], "url": u, "status": "dropped",
                                                "drop_reason": "outside the focus"} for u in (UNION, ERROR)])
    assert await store.restore_pinned(a, ra, 2, [UNION]) == [UNION]
    rows = {(r["generation"], r["url"]): r for r in await pg.sql(
        "SELECT generation, url, status, drop_reason FROM tradecraft_entries WHERE resource_id = %s", ra)}
    assert (rows[(2, UNION)]["status"], rows[(2, UNION)]["drop_reason"]) == ("kept", "")
    assert rows[(2, ERROR)]["status"] == "dropped" and rows[(1, UNION)]["status"] == "dropped"
    # Not the live generation, another owner, nothing named: nothing written.
    assert await store.restore_pinned(a, ra, 1, [UNION]) == []
    assert await store.restore_pinned(b, ra, 2, [ERROR]) == []
    assert await store.restore_pinned(a, ra, 2, []) == []


async def test_curation_rows_come_in_one_order(pg):
    store = Store()
    a = await pg.user()
    ra = await pg.resource(a)
    for url in (WIKI + "b/", WIKI + "a/", "https://WIKI.tc-fixture.test"):
        await pg.curate(ra, url, pinned=True)
    # One order on every read (the merge does not depend on it, but a log or a test may).
    first = [r["url"] for r in await store.curation_rows(a, ra)]
    assert len(first) == 3
    for _ in range(3):
        assert [r["url"] for r in await store.curation_rows(a, ra)] == first


async def test_in_map_is_the_kept_map(pg):
    """S10 review 2, finding 2: a resource with a login reads only kept entries of its live map."""
    store = Store()
    a = await pg.user()
    ra = await pg.resource(a, generation=1)
    ids = await store.allocate_page_ids(a, ra, [UNION, ERROR])
    await store.write_entries(a, ra, 1, [{"page_id": ids[UNION], "url": UNION, "status": "kept"},
                                         {"page_id": ids[ERROR], "url": ERROR, "status": "dropped"}])
    assert await store.in_map(a, ra, UNION) is True
    assert await store.in_map(a, ra, ERROR) is False
    assert await store.in_map(await pg.user(), ra, UNION) is False
