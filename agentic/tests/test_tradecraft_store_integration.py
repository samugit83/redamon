"""The page store on a real Postgres with the 2.0 schema (T1.4).

Runs through ``tooling/scripts/tradecraft_pg_testdb.sh agent`` on the session's copy of the
pushed template; skips without ``TRADECRAFT_PG_TEST_URL``. Every test creates its own users
(random ids) and deletes them at the end, so tests share a database safely.
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

PG_URL = os.environ.get("TRADECRAFT_PG_TEST_URL", "")
pytestmark = pytest.mark.skipif(not PG_URL, reason="TRADECRAFT_PG_TEST_URL is not set (tradecraft_pg_testdb.sh agent)")

import psycopg  # noqa: E402
from psycopg.rows import dict_row  # noqa: E402

from tradecraft import db  # noqa: E402
from tradecraft.store import ResourceGone, Store  # noqa: E402

URL = "https://wiki.tc-fixture.test/"


@pytest.fixture
async def env(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", PG_URL)
    db.reset()
    created: list[str] = []
    conn = await psycopg.AsyncConnection.connect(PG_URL, autocommit=True, row_factory=dict_row)
    helper = Seed(conn, created)
    try:
        yield helper
    finally:
        await db.close()
        if created:
            await conn.execute("DELETE FROM users WHERE id = ANY(%s)", (created,))
        await conn.close()


class Seed:
    def __init__(self, conn, created):
        self.conn = conn
        self.created = created

    async def sql(self, query, *params):
        cur = await self.conn.execute(query, params)
        return await cur.fetchall() if cur.description else []

    async def user(self):
        uid = f"tc-u-{uuid.uuid4().hex[:12]}"
        await self.sql("INSERT INTO users (id, name, email, updated_at) VALUES (%s, %s, %s, now())",
                       uid, "Store Test", f"{uid}@example.test")
        self.created.append(uid)
        return uid

    async def resource(self, uid, url=URL, mode="stored", slug=None):
        rid = f"tc-r-{uuid.uuid4().hex[:12]}"
        await self.sql(
            "INSERT INTO user_tradecraft_resources (id, user_id, name, slug, url, storage_mode, updated_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, now())", rid, uid, "Wiki", slug or f"wiki-{rid[-6:]}", url, mode)
        return rid

    async def job(self, uid, rid, *, lease_s=60, status="queued", claim=True, lease_until="auto"):
        jid = f"tc-j-{uuid.uuid4().hex[:12]}"
        until = (datetime.now(timezone.utc) + timedelta(seconds=lease_s)) if lease_until == "auto" else lease_until
        await self.sql(
            "INSERT INTO tradecraft_ingestion_jobs (id, user_id, resource_id, kind, status, lease_until) "
            "VALUES (%s, %s, %s, 'refresh', %s, %s)", jid, uid, rid, status, until)
        if claim:
            await self.sql("UPDATE user_tradecraft_resources SET active_job_id = %s WHERE id = %s", jid, rid)
        return jid

    async def webapp_claim(self, uid, rid, jid):
        """The webapp's conditional claim (phase 1 design, "Jobs and the pipeline"): takes a
        free resource or one whose job's lease expired, and fails that job (agent_lost)."""
        async with self.conn.transaction():
            await self.sql(
                "INSERT INTO tradecraft_ingestion_jobs (id, user_id, resource_id, kind, lease_until) "
                "VALUES (%s, %s, %s, 'refresh', now() + interval '60 seconds')", jid, uid, rid)
            stale = await self.sql(
                "SELECT active_job_id FROM user_tradecraft_resources WHERE id = %s AND user_id = %s", rid, uid)
            taken = await self.sql(
                "UPDATE user_tradecraft_resources SET active_job_id = %s WHERE id = %s AND user_id = %s AND "
                "(active_job_id IS NULL OR active_job_id IN (SELECT id FROM tradecraft_ingestion_jobs WHERE "
                "status IN ('queued','running') AND (lease_until IS NULL OR lease_until < now()))) RETURNING id",
                jid, rid, uid)
            if not taken:
                await self.sql("DELETE FROM tradecraft_ingestion_jobs WHERE id = %s", jid)
                return False
            old = stale[0]["active_job_id"] if stale else None
            if old:
                await self.sql("UPDATE tradecraft_ingestion_jobs SET status = 'failed', error_code = 'agent_lost' "
                               "WHERE id = %s AND status IN ('queued','running')", old)
            return True

    async def running(self, store, uid, rid, jid, instance="inst-a"):
        until = datetime.now(timezone.utc) + timedelta(seconds=60)
        assert await store.accept_job(uid, jid, instance, until)
        assert await store.claim_job_for_run(uid, jid, instance, until)
        gen = await store.begin_generation(uid, rid, jid)
        assert gen is not None
        return gen

    async def count(self, table, rid, generation=None):
        q = f"SELECT count(*) AS n FROM {table} WHERE resource_id = %s"
        args = [rid]
        if generation is not None:
            q += " AND generation = %s"
            args.append(generation)
        return (await self.sql(q, *args))[0]["n"]


async def write_generation(store, uid, rid, gen, urls, *, text="body", sections=1):
    ids = await store.allocate_page_ids(uid, rid, urls)
    entries = [{"page_id": ids[u], "url": u, "title": f"T {u[-1]}", "stored_text": text,
                "stored_bytes": len(text.encode()), "headings": [{"level": 1, "text": "H"}],
                "topics": ["sql_injection"], "fetched_at": datetime.now(timezone.utc).isoformat()} for u in urls]
    entry_ids = await store.write_entries(uid, rid, gen, entries)
    secs = [{"entry_id": eid, "ord": i, "level": 2, "heading": f"S{i}", "text": text}
            for eid in entry_ids.values() for i in range(sections)]
    await store.write_sections(uid, rid, gen, secs)
    await store.write_tree(uid, rid, gen, [{"path": "/", "parent_path": "", "label": "root", "page_count": len(urls)}])
    return ids


PAGES = [f"{URL}p{i}" for i in range(1, 6)]


async def test_two_users_same_url(env):
    s = Store()
    u1, u2 = await env.user(), await env.user()
    r1, r2 = await env.resource(u1), await env.resource(u2)
    for uid, rid, body in ((u1, r1, "first user's text"), (u2, r2, "second user's text")):
        jid = await env.job(uid, rid)
        gen = await env.running(s, uid, rid, jid)
        await write_generation(s, uid, rid, gen, [URL + "p1"], text=body)
        assert await s.swap(uid, rid, jid, gen, URL, "stored", {}) == "swapped"

    e1 = await s.entry_by_url(u1, r1, URL + "p1")
    e2 = await s.entry_by_url(u2, r2, URL + "p1")
    assert e1["stored_text"] == "first user's text" and e2["stored_text"] == "second user's text"
    assert e1["page_id"] != e2["page_id"]
    # Another user's resource or page number answers nothing.
    assert await s.entry_by_url(u1, r2, URL + "p1") is None
    assert await s.entry_by_page_id(u1, e2["page_id"]) is None
    assert await s.lookup_page_id(u1, e2["page_id"]) is None
    assert (await s.lookup_page_id(u2, e2["page_id"])).resource_id == r2
    assert await s.resource(u1, r2) is None
    assert await s.in_map(u2, r1, URL + "p1") is False
    assert await s.user_stored_bytes(u1) == len("first user's text")


async def test_swap_and_failed_generation(env):
    s = Store()
    uid = await env.user()
    rid = await env.resource(uid)
    jid = await env.job(uid, rid)
    gen1 = await env.running(s, uid, rid, jid)
    await write_generation(s, uid, rid, gen1, PAGES[:3], text="v1")
    assert await s.swap(uid, rid, jid, gen1, URL, "stored", {"summary": "first", "map_version": 3,
                                                               "sitemap": {"pages": [{"title": "a"}]}}) == "swapped"
    row = await s.resource(uid, rid)
    assert row["generation"] == gen1 and row["active_job_id"] is None and row["summary"] == "first"
    assert row["map_version"] == 3
    job = (await env.sql("SELECT status, finished_at, lease_until FROM tradecraft_ingestion_jobs WHERE id = %s", jid))[0]
    assert job["status"] == "succeeded" and job["finished_at"] and job["lease_until"] is None

    # A refresh writes a new generation, then fails: it is discarded and the first stays live.
    jid2 = await env.job(uid, rid)
    gen2 = await env.running(s, uid, rid, jid2)
    assert gen2 == gen1 + 1
    await write_generation(s, uid, rid, gen2, PAGES, text="v2")
    assert await s.discard_generation(uid, rid, gen2) > 0
    assert await s.finish_job(uid, jid2, "failed", "fetch_failed")
    row = await s.resource(uid, rid)
    assert row["generation"] == gen1 and row["active_job_id"] is None and row["summary"] == "first"
    assert (await s.entry_by_url(uid, rid, PAGES[0]))["stored_text"] == "v1"
    assert await s.entry_by_url(uid, rid, PAGES[4]) is None
    assert await env.count("tradecraft_entries", rid, gen2) == 0
    assert await env.count("tradecraft_sections", rid, gen2) == 0
    # Discarding never touches the live generation.
    assert await s.discard_generation(uid, rid, gen1) == 0
    assert await env.count("tradecraft_entries", rid, gen1) == 3
    # The next job never reuses the discarded number.
    jid3 = await env.job(uid, rid)
    assert await env.running(s, uid, rid, jid3) == gen2 + 1


async def test_page_ids_survive_a_refresh(env):
    s = Store()
    uid = await env.user()
    rid = await env.resource(uid)
    first = await s.allocate_page_ids(uid, rid, PAGES[:2])
    again = await s.allocate_page_ids(uid, rid, PAGES[:3])
    assert again[PAGES[0]] == first[PAGES[0]] and again[PAGES[1]] == first[PAGES[1]]
    assert await s.min_page_id(uid, rid) == min(first.values())


async def test_writes_refused_after_delete(env):
    s = Store()
    uid = await env.user()
    rid = await env.resource(uid)
    jid = await env.job(uid, rid)
    gen = await env.running(s, uid, rid, jid)
    ids = await s.allocate_page_ids(uid, rid, PAGES[:2])
    await env.sql("DELETE FROM user_tradecraft_resources WHERE id = %s", rid)
    with pytest.raises(ResourceGone):
        await s.write_entries(uid, rid, gen, [{"page_id": ids[PAGES[0]], "url": PAGES[0]}])
    with pytest.raises(ResourceGone):
        await s.allocate_page_ids(uid, rid, PAGES[2:3])
    with pytest.raises(ResourceGone):
        await s.write_tree(uid, rid, gen, [{"path": "/", "parent_path": "", "label": "root"}])
    assert await s.swap(uid, rid, jid, gen, URL, "stored", {"summary": "late"}) == "gone"
    assert await s.cancel_requested(uid, jid) is True  # the job went with its resource
    assert await env.count("tradecraft_entries", rid) == 0
    assert await env.count("tradecraft_page_ids", rid) == 0


@pytest.mark.parametrize("column,value", [("url", "https://moved.tc-fixture.test/"), ("storage_mode", "live")])
async def test_swap_refused_after_a_change(env, column, value):
    """test_swap_refused_after_url_change and _after_storage_change: the previous generation
    stays live and nothing of the job's result is written (D-45)."""
    s = Store()
    uid = await env.user()
    rid = await env.resource(uid)
    jid = await env.job(uid, rid)
    gen1 = await env.running(s, uid, rid, jid)
    await write_generation(s, uid, rid, gen1, PAGES[:2])
    assert await s.swap(uid, rid, jid, gen1, URL, "stored", {"summary": "old"}) == "swapped"

    jid2 = await env.job(uid, rid)
    gen2 = await env.running(s, uid, rid, jid2)
    await write_generation(s, uid, rid, gen2, PAGES)
    await env.sql(f"UPDATE user_tradecraft_resources SET {column} = %s WHERE id = %s", value, rid)
    assert await s.swap(uid, rid, jid2, gen2, URL, "stored", {"summary": "new"}) == "changed"
    row = await s.resource(uid, rid)
    assert row["generation"] == gen1 and row["summary"] == "old" and row["active_job_id"] == jid2
    job = (await env.sql("SELECT status FROM tradecraft_ingestion_jobs WHERE id = %s", jid2))[0]
    assert job["status"] == "running"


@pytest.mark.parametrize("column,value", [("summary_locked", True), ("summary_source", "manual")])
async def test_swap_keeps_a_summary_protected_during_the_job(env, column, value):
    """Finding A: the person locks or writes the summary after the job started; the swap still
    makes the new generation live but leaves the summary as the row has it."""
    s = Store()
    uid = await env.user()
    rid = await env.resource(uid)
    jid = await env.job(uid, rid)
    gen = await env.running(s, uid, rid, jid)
    await env.sql(f"UPDATE user_tradecraft_resources SET summary = 'mine', {column} = %s WHERE id = %s", value, rid)
    answer = await s.swap(uid, rid, jid, gen, URL, "stored",
                          {"summary": "generated text", "summary_source": "generated", "map_version": 3})
    assert answer == "swapped"
    row = await s.resource(uid, rid)
    assert row["summary"] == "mine" and row[column] == value
    assert row["generation"] == gen and row["map_version"] == 3 and row["active_job_id"] is None


async def test_swap_refused_after_takeover(env):
    s = Store()
    uid = await env.user()
    rid = await env.resource(uid)
    jid = await env.job(uid, rid)
    gen = await env.running(s, uid, rid, jid)
    await env.sql("UPDATE tradecraft_ingestion_jobs SET lease_until = now() - interval '1 second' WHERE id = %s", jid)
    assert await env.webapp_claim(uid, rid, "tc-j-next-" + uuid.uuid4().hex[:6])
    assert await s.swap(uid, rid, jid, gen, URL, "stored", {"summary": "late"}) == "lost"
    assert (await s.resource(uid, rid))["generation"] == 0
    assert await s.cancel_requested(uid, jid) is True


async def test_old_generations_purged_in_batches(env):
    s = Store()
    uid = await env.user()
    rid = await env.resource(uid)
    jid = await env.job(uid, rid)
    gen1 = await env.running(s, uid, rid, jid)
    await write_generation(s, uid, rid, gen1, PAGES, sections=3)
    assert await s.swap(uid, rid, jid, gen1, URL, "stored", {}) == "swapped"

    jid2 = await env.job(uid, rid)
    gen2 = await env.running(s, uid, rid, jid2)
    await write_generation(s, uid, rid, gen2, PAGES[:2], sections=2)
    assert await s.swap(uid, rid, jid2, gen2, URL, "stored", {}) == "swapped"

    # A third job is writing its own generation while the purge runs: it is spared.
    jid3 = await env.job(uid, rid)
    gen3 = await env.running(s, uid, rid, jid3)
    await write_generation(s, uid, rid, gen3, PAGES[:1])

    deleted = await s.purge_old_generations(uid, rid, batch=2)
    # gen1: 15 sections, 1 tree node, 5 entries.
    assert deleted == 15 + 1 + 5
    assert await env.count("tradecraft_entries", rid, gen1) == 0
    assert await env.count("tradecraft_sections", rid, gen1) == 0
    assert await env.count("tradecraft_tree_nodes", rid, gen1) == 0
    assert await env.count("tradecraft_entries", rid, gen2) == 2
    assert await env.count("tradecraft_sections", rid, gen2) == 4
    assert await env.count("tradecraft_entries", rid, gen3) == 1
    assert await s.purge_old_generations(uid, rid, batch=2) == 0


async def test_updated_at_moves(env):
    s = Store()
    uid = await env.user()
    rid = await env.resource(uid)
    jid = await env.job(uid, rid)
    # timestamp(3) without a time zone, in UTC: naive on read.
    old = datetime(2020, 1, 1)
    await env.sql("UPDATE user_tradecraft_resources SET updated_at = %s WHERE id = %s", old, rid)
    await env.sql("UPDATE tradecraft_ingestion_jobs SET updated_at = %s WHERE id = %s", old, jid)
    gen = await env.running(s, uid, rid, jid)
    job = (await env.sql("SELECT updated_at FROM tradecraft_ingestion_jobs WHERE id = %s", jid))[0]
    assert job["updated_at"] > old
    await env.sql("UPDATE tradecraft_ingestion_jobs SET updated_at = %s WHERE id = %s", old, jid)
    await s.set_job_stage(uid, jid, "build_map", {"done": 1, "total": 2, "unit": "pages"})
    job = (await env.sql("SELECT updated_at, stage, progress FROM tradecraft_ingestion_jobs WHERE id = %s", jid))[0]
    assert job["updated_at"] > old and job["stage"] == "build_map" and job["progress"]["done"] == 1
    assert await s.set_last_error(uid, rid, jid, "fetch_failed", datetime.now(timezone.utc))
    res = (await env.sql("SELECT updated_at, last_error, last_verified_at FROM user_tradecraft_resources "
                         "WHERE id = %s", rid))[0]
    assert res["updated_at"] > old and res["last_error"] == "fetch_failed" and res["last_verified_at"] is not None
    await env.sql("UPDATE user_tradecraft_resources SET updated_at = %s WHERE id = %s", old, rid)
    assert await s.swap(uid, rid, jid, gen, URL, "stored", {}) == "swapped"
    res = (await env.sql("SELECT updated_at FROM user_tradecraft_resources WHERE id = %s", rid))[0]
    assert res["updated_at"] > old


async def test_claim_is_exclusive(env):
    s = Store()
    uid = await env.user()
    rid = await env.resource(uid)
    a = "tc-j-a-" + uuid.uuid4().hex[:6]
    b = "tc-j-b-" + uuid.uuid4().hex[:6]
    assert await env.webapp_claim(uid, rid, a)
    # While a holds a live lease, a second claim is refused and the agent will not take b.
    assert not await env.webapp_claim(uid, rid, b)
    await env.sql("INSERT INTO tradecraft_ingestion_jobs (id, user_id, resource_id, kind, lease_until) "
                  "VALUES (%s, %s, %s, 'refresh', now() + interval '60 seconds')", b, uid, rid)
    until = datetime.now(timezone.utc) + timedelta(seconds=60)
    assert not await s.accept_job(uid, b, "inst", until)
    assert await s.accept_job(uid, a, "inst", until)
    # Only the owner's id reaches its job.
    other = await env.user()
    assert not await s.accept_job(other, a, "inst", until)
    assert not await s.claim_job_for_run(uid, a, "other-instance", until)
    assert await s.claim_job_for_run(uid, a, "inst", until)
    assert await s.begin_generation(uid, rid, b) is None
    assert await s.begin_generation(other, rid, a) is None
    assert await s.begin_generation(uid, rid, a) == 1


async def test_renew_leases_only_for_this_instance(env):
    s = Store()
    uid = await env.user()
    rid1, rid2 = await env.resource(uid), await env.resource(uid, url=URL + "other/")
    j1, j2 = await env.job(uid, rid1), await env.job(uid, rid2)
    soon = datetime.now(timezone.utc) + timedelta(seconds=30)
    assert await s.accept_job(uid, j1, "inst-a", soon)
    assert await s.accept_job(uid, j2, "inst-b", soon)
    later = datetime.now(timezone.utc) + timedelta(seconds=90)
    assert await s.renew_leases("inst-a", later, [(uid, j1), (uid, j2)]) == {j1}
    leases = {r["id"]: r["lease_until"] for r in await env.sql(
        "SELECT id, lease_until FROM tradecraft_ingestion_jobs WHERE id = ANY(%s)", [j1, j2])}
    assert leases[j1] > leases[j2]


async def test_expired_lease_failed_at_boot(env):
    s = Store()
    uid = await env.user()
    r_run, r_queue, r_live = (await env.resource(uid, url=URL + "a/"), await env.resource(uid, url=URL + "b/"),
                              await env.resource(uid, url=URL + "c/"))
    j_run = await env.job(uid, r_run)
    gen = await env.running(s, uid, r_run, j_run)
    await write_generation(s, uid, r_run, gen, PAGES[:2])
    j_queue = await env.job(uid, r_queue)
    j_live = await env.job(uid, r_live, lease_s=600)
    past = datetime.now(timezone.utc) - timedelta(seconds=1)
    await env.sql("UPDATE tradecraft_ingestion_jobs SET lease_until = %s WHERE id = ANY(%s)", past, [j_run, j_queue])

    failed = await s.fail_expired_leases(datetime.now(timezone.utc))
    mine = {f["id"]: f for f in failed if f["user_id"] == uid}
    assert set(mine) == {j_run, j_queue}
    assert mine[j_run]["target_generation"] == gen and mine[j_run]["resource_id"] == r_run
    rows = {r["id"]: r for r in await env.sql(
        "SELECT id, status, error_code FROM tradecraft_ingestion_jobs WHERE id = ANY(%s)", [j_run, j_queue, j_live])}
    assert rows[j_run]["status"] == rows[j_queue]["status"] == "failed"
    assert rows[j_run]["error_code"] == "agent_restarted"
    assert rows[j_live]["status"] == "queued"
    claims = {r["id"]: r["active_job_id"] for r in await env.sql(
        "SELECT id, active_job_id FROM user_tradecraft_resources WHERE id = ANY(%s)", [r_run, r_queue, r_live])}
    assert claims == {r_run: None, r_queue: None, r_live: j_live}
    # The failed job's generation is discarded by the caller (jobs.recover_on_boot).
    assert await s.discard_generation(uid, r_run, gen) > 0
    assert await env.count("tradecraft_entries", r_run) == 0


async def test_null_lease_counts_as_expired(env):
    s = Store()
    uid = await env.user()
    rid = await env.resource(uid)
    jid = await env.job(uid, rid, lease_until=None)
    failed = await s.fail_expired_leases(datetime.now(timezone.utc))
    assert jid in {f["id"] for f in failed}
    assert (await s.resource(uid, rid))["active_job_id"] is None
    # And the webapp's next claim takes the resource.
    assert await env.webapp_claim(uid, rid, "tc-j-n-" + uuid.uuid4().hex[:6])


async def test_curation_and_legacy_reads_are_keyed(env):
    s = Store()
    u1, u2 = await env.user(), await env.user()
    r1 = await env.resource(u1)
    await env.sql("UPDATE user_tradecraft_resources SET sitemap = %s::jsonb, resource_type = 'mkdocs-wiki' "
                  "WHERE id = %s", json.dumps({"pages": [{"title": "Union", "path": "/sqli/union/"}]}), r1)
    await env.sql("INSERT INTO tradecraft_curations (id, resource_id, url, blocked, updated_at) "
                  "VALUES (%s, %s, %s, true, now())", "tc-c-" + uuid.uuid4().hex[:8], r1, URL + "secret")
    assert (await s.curation(u1, r1, URL + "secret"))["blocked"] is True
    assert await s.curation(u2, r1, URL + "secret") is None
    legacy = await s.legacy_sitemap(u1, r1)
    assert legacy["sitemap"]["pages"][0]["title"] == "Union" and legacy["resource_type"] == "mkdocs-wiki"
    assert await s.legacy_sitemap(u2, r1) is None


async def test_nul_bytes_and_large_text_are_stored(env):
    s = Store()
    uid = await env.user()
    rid = await env.resource(uid)
    jid = await env.job(uid, rid)
    gen = await env.running(s, uid, rid, jid)
    ids = await s.allocate_page_ids(uid, rid, [URL + "nul"])
    big = "x" * 300_000
    await s.write_entries(uid, rid, gen, [{"page_id": ids[URL + "nul"], "url": URL + "nul",
                                           "title": "a\x00b", "stored_text": "c\x00" + big}])
    assert await s.swap(uid, rid, jid, gen, URL, "stored", {}) == "swapped"
    entry = await s.entry_by_url(uid, rid, URL + "nul")
    assert entry["title"] == "ab" and entry["stored_text"] == "c" + big


async def test_a_job_that_ends_without_a_swap_leaves_a_1x_error_state(env):
    """M1 (TD-18, D-25): a failed add writes last_error and last_verified_at and nothing else of
    the 1.x state; a cancel marks only a resource never verified; boot recovery marks the
    resources whose claims it releases. A 1.x tab then shows an error card, never "verifying"."""
    s = Store()
    uid = await env.user()
    when = datetime.now(timezone.utc).replace(microsecond=0)
    # A failed first add.
    rid = await env.resource(uid)
    await env.sql("UPDATE user_tradecraft_resources SET sitemap = '{\"nav\": [1]}'::jsonb, summary = 'kept' "
                  "WHERE id = %s", rid)
    jid = await env.job(uid, rid)
    await env.running(s, uid, rid, jid)
    assert await s.set_last_error(uid, rid, jid, "fetch_failed", when)
    row = (await env.sql("SELECT last_error, last_verified_at, sitemap, summary FROM user_tradecraft_resources "
                         "WHERE id = %s", rid))[0]
    assert row["last_error"] == "fetch_failed" and row["last_verified_at"] == when.replace(tzinfo=None)
    assert row["sitemap"] == {"nav": [1]} and row["summary"] == "kept"
    # A cancel: a never-verified resource is marked, a verified one keeps its state.
    fresh = await env.resource(uid, url=URL + "fresh/")
    jf = await env.job(uid, fresh)
    assert await s.set_error_if_never_verified(uid, fresh, jf, "cancelled", when)
    verified = await env.resource(uid, url=URL + "verified/")
    before = datetime(2026, 1, 1)
    await env.sql("UPDATE user_tradecraft_resources SET last_verified_at = %s, last_error = '' WHERE id = %s",
                  before, verified)
    jv = await env.job(uid, verified)
    assert not await s.set_error_if_never_verified(uid, verified, jv, "cancelled", when)
    rows = {r["id"]: r for r in await env.sql(
        "SELECT id, last_error, last_verified_at FROM user_tradecraft_resources WHERE id = ANY(%s)", [fresh, verified])}
    assert rows[fresh]["last_error"] == "cancelled" and rows[fresh]["last_verified_at"] is not None
    assert rows[verified]["last_error"] == "" and rows[verified]["last_verified_at"] == before
    # Boot recovery: the released resource carries the error and the time.
    lost = await env.resource(uid, url=URL + "lost/")
    await env.job(uid, lost, lease_until=None)
    await s.fail_expired_leases(datetime.now(timezone.utc))
    row = (await env.sql("SELECT last_error, last_verified_at, active_job_id FROM user_tradecraft_resources "
                         "WHERE id = %s", lost))[0]
    assert row["last_error"] == "agent_restarted" and row["last_verified_at"] is not None and row["active_job_id"] is None
