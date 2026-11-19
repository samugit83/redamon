"""The job runner on a real Postgres (T1.5): a restart strands no job (AC-34), a live lease of
another copy is left alone (D-18), and a queued job whose agent is lost stops blocking its
resource once its lease runs out (D-42).

Runs through ``tooling/scripts/tradecraft_pg_testdb.sh agent``; skips without
``TRADECRAFT_PG_TEST_URL``. Each test creates its own users and deletes them at the end.
"""

from __future__ import annotations

import asyncio
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
from tradecraft.contract import JobOutcome, JobStartBatch  # noqa: E402
from tradecraft.store import Store  # noqa: E402
from tradecraft_doubles import FakeClock, FixtureFetcher  # noqa: E402

URL = "https://wiki.tc-fixture.test/"
FIXTURE = json.loads((Path(__file__).resolve().parent / "fixtures" / "tradecraft_contract" /
                      "JobStartBatch.valid.json").read_text())["jobs"][0]


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
        await self.sql("INSERT INTO users (id, name, email, updated_at) VALUES (%s, 'Jobs', %s, now())", uid,
                       f"{uid}@example.test")
        self.users.append(uid)
        return uid

    async def resource(self, uid, url=URL):
        rid = f"tc-r-{uuid.uuid4().hex[:12]}"
        await self.sql("INSERT INTO user_tradecraft_resources (id, user_id, name, slug, url, storage_mode, updated_at) "
                       "VALUES (%s, %s, 'Wiki', %s, %s, 'stored', now())", rid, uid, f"wiki-{rid[-6:]}", url)
        return rid

    async def job(self, uid, rid, *, status="queued", lease_until, instance="", target=0):
        jid = f"tc-j-{uuid.uuid4().hex[:12]}"
        await self.sql("INSERT INTO tradecraft_ingestion_jobs (id, user_id, resource_id, kind, status, lease_until, "
                       "owner_instance, target_generation) VALUES (%s, %s, %s, 'refresh', %s, %s, %s, %s)",
                       jid, uid, rid, status, lease_until, instance, target)
        await self.sql("UPDATE user_tradecraft_resources SET active_job_id = %s WHERE id = %s", jid, rid)
        return jid

    async def claim(self, uid, rid, now):
        """The webapp's conditional claim at time ``now`` (phase 1 design): takes a free
        resource or one whose job's lease expired, and fails that job with agent_lost."""
        jid = f"tc-j-next-{uuid.uuid4().hex[:8]}"
        async with self.conn.transaction():
            await self.sql("INSERT INTO tradecraft_ingestion_jobs (id, user_id, resource_id, kind, lease_until) "
                           "VALUES (%s, %s, %s, 'refresh', %s)", jid, uid, rid, now + timedelta(seconds=60))
            old = await self.sql("SELECT active_job_id FROM user_tradecraft_resources WHERE id = %s", rid)
            taken = await self.sql(
                "UPDATE user_tradecraft_resources SET active_job_id = %s WHERE id = %s AND user_id = %s AND "
                "(active_job_id IS NULL OR active_job_id IN (SELECT id FROM tradecraft_ingestion_jobs WHERE "
                "status IN ('queued','running') AND (lease_until IS NULL OR lease_until < %s))) RETURNING id",
                jid, rid, uid, now)
            if not taken:
                await self.sql("DELETE FROM tradecraft_ingestion_jobs WHERE id = %s", jid)
                return None
            if old and old[0]["active_job_id"]:
                await self.sql("UPDATE tradecraft_ingestion_jobs SET status = 'failed', error_code = 'agent_lost' "
                               "WHERE id = %s AND status IN ('queued','running')", old[0]["active_job_id"])
            return jid

    async def row(self, table, key):
        return (await self.sql(f"SELECT * FROM {table} WHERE id = %s", key))[0]


def utcnow():
    return datetime.now(timezone.utc)


async def test_restart(pg):
    """AC-34: a running and a queued job whose leases expired are failed with agent_restarted,
    the running one's generation is discarded, and the next claim of each resource succeeds."""
    store = Store()
    uid = await pg.user()
    r_run, r_queue = await pg.resource(uid, URL + "run/"), await pg.resource(uid, URL + "queue/")
    past = utcnow() - timedelta(seconds=5)
    j_run = await pg.job(uid, r_run, status="running", lease_until=past, instance="old-process", target=1)
    j_queue = await pg.job(uid, r_queue, lease_until=past, instance="old-process")
    ids = await store.allocate_page_ids(uid, r_run, [URL + "run/a"])
    await store.write_entries(uid, r_run, 1, [{"page_id": ids[URL + "run/a"], "url": URL + "run/a"}])

    runner = jobs.JobRunner(store, entry=lambda ctx: None, instance="new-process")
    assert await runner.recover() >= 2
    for jid in (j_run, j_queue):
        job = await pg.row("tradecraft_ingestion_jobs", jid)
        assert job["status"] == "failed" and job["error_code"] == "agent_restarted" and job["lease_until"] is None
    assert (await pg.sql("SELECT count(*) AS n FROM tradecraft_entries WHERE resource_id = %s", r_run))[0]["n"] == 0
    for rid in (r_run, r_queue):
        assert (await pg.row("user_tradecraft_resources", rid))["active_job_id"] is None
        assert await pg.claim(uid, rid, utcnow())
    await runner.close()


async def test_other_copy_lease(pg):
    """D-18: a job another copy still renews is never failed by this copy's boot."""
    uid = await pg.user()
    rid = await pg.resource(uid)
    jid = await pg.job(uid, rid, status="running", lease_until=utcnow() + timedelta(seconds=45), instance="copy-b")
    runner = jobs.JobRunner(Store(), entry=lambda ctx: None, instance="copy-a")
    await runner.recover()
    assert (await pg.row("tradecraft_ingestion_jobs", jid))["status"] == "running"
    assert (await pg.row("user_tradecraft_resources", rid))["active_job_id"] == jid
    assert await pg.claim(uid, rid, utcnow()) is None
    await runner.close()


async def test_lost_queued_job_does_not_block(pg):
    """D-42: an accepted job whose agent never renews it: after 60 s of fake clock the next
    claim takes the resource and fails the lost job."""
    uid = await pg.user()
    rid = await pg.resource(uid)
    clock = FakeClock(start=utcnow())
    jid = await pg.job(uid, rid, lease_until=clock.now() + timedelta(seconds=60))
    spec = dict(FIXTURE, job_id=jid, user_id=uid, actor_user_id=uid, resource_id=rid)
    spec["resource"] = dict(FIXTURE["resource"], url=URL)

    gate = asyncio.Event()

    async def blocked(ctx):
        await gate.wait()

    runner = jobs.JobRunner(Store(), entry=blocked, instance="lost-copy", clock=clock, fetcher_factory=FixtureFetcher,
                            max_running=1)
    # Another resource's job holds the only slot, so this one stays queued.
    other_rid = await pg.resource(uid, URL + "other/")
    other = await pg.job(uid, other_rid, lease_until=clock.now() + timedelta(seconds=60))
    first = dict(spec, job_id=other, resource_id=other_rid)
    answer = await runner.submit(JobStartBatch.model_validate({"jobs": [first, spec]}))
    assert answer.accepted == [other, jid]
    job = await pg.row("tradecraft_ingestion_jobs", jid)
    assert job["status"] == "queued" and job["owner_instance"] == "lost-copy"
    # The copy is lost: nothing renews. Before the lease ends the resource stays claimed...
    assert await pg.claim(uid, rid, clock.now() + timedelta(seconds=30)) is None
    # ...after it, the next claim takes it over and fails the lost job.
    taken = await pg.claim(uid, rid, clock.now() + timedelta(seconds=61))
    assert taken
    job = await pg.row("tradecraft_ingestion_jobs", jid)
    assert job["status"] == "failed" and job["error_code"] == "agent_lost"
    gate.set()
    await runner.close()


async def test_a_job_runs_end_to_end_on_the_store(pg):
    """The runner and the store together: the generation a job writes becomes live at its
    swap, the older one is purged, and the claim is released."""
    store = Store()
    uid = await pg.user()
    rid = await pg.resource(uid)
    jid = await pg.job(uid, rid, lease_until=utcnow() + timedelta(seconds=60))

    async def entry(ctx):
        r = ctx.request
        ids = await store.allocate_page_ids(r.user_id, r.resource_id, [URL + "p1"])
        await store.write_entries(r.user_id, r.resource_id, ctx.target_generation,
                                  [{"page_id": ids[URL + "p1"], "url": URL + "p1", "title": "P1"}])
        answer = await store.swap(r.user_id, r.resource_id, r.job_id, ctx.target_generation, r.resource.url,
                                  r.resource.storage_mode, {"summary": "fresh", "map_version": 3})
        assert answer == "swapped"
        return JobOutcome(status="succeeded", swapped=True)

    spec = dict(FIXTURE, job_id=jid, user_id=uid, actor_user_id=uid, resource_id=rid)
    spec["resource"] = dict(FIXTURE["resource"], url=URL, storage_mode="stored")
    runner = jobs.JobRunner(store, entry=entry, instance="copy-e2e", fetcher_factory=FixtureFetcher)
    await runner.submit(JobStartBatch.model_validate({"jobs": [spec]}))
    await asyncio.wait_for(runner._running[jid].task, timeout=20)
    job = await pg.row("tradecraft_ingestion_jobs", jid)
    res = await pg.row("user_tradecraft_resources", rid)
    assert job["status"] == "succeeded" and job["finished_at"] is not None
    assert res["generation"] == 1 and res["summary"] == "fresh" and res["active_job_id"] is None
    assert (await store.entry_by_url(uid, rid, URL + "p1"))["title"] == "P1"
    await runner.close()


async def test_a_failed_job_on_the_store_keeps_the_previous_generation(pg):
    store = Store()
    uid = await pg.user()
    rid = await pg.resource(uid)
    await pg.sql("UPDATE user_tradecraft_resources SET generation = 3, summary = 'kept' WHERE id = %s", rid)
    jid = await pg.job(uid, rid, lease_until=utcnow() + timedelta(seconds=60))

    async def entry(ctx):
        r = ctx.request
        ids = await store.allocate_page_ids(r.user_id, r.resource_id, [URL + "p9"])
        await store.write_entries(r.user_id, r.resource_id, ctx.target_generation,
                                  [{"page_id": ids[URL + "p9"], "url": URL + "p9"}])
        return JobOutcome(status="failed", error_code="fetch_failed")

    spec = dict(FIXTURE, job_id=jid, user_id=uid, actor_user_id=uid, resource_id=rid)
    spec["resource"] = dict(FIXTURE["resource"], url=URL, storage_mode="stored")
    runner = jobs.JobRunner(store, entry=entry, instance="copy-f", fetcher_factory=FixtureFetcher)
    await runner.submit(JobStartBatch.model_validate({"jobs": [spec]}))
    await asyncio.wait_for(runner._running[jid].task, timeout=20)
    res = await pg.row("user_tradecraft_resources", rid)
    assert res["generation"] == 3 and res["summary"] == "kept" and res["active_job_id"] is None
    assert res["last_error"] == "fetch_failed"
    assert (await pg.sql("SELECT count(*) AS n FROM tradecraft_entries WHERE resource_id = %s", rid))[0]["n"] == 0
    await runner.close()
