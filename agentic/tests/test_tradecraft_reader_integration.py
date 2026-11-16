"""The 2.0 read path on Postgres (T1.9): reading never writes (R-085, R-306), every read is
for one owner and one resource (R-301), and a refresh that swaps during a run is read at the
next call (D-46).

Runs through ``tooling/scripts/tradecraft_pg_testdb.sh agent``; skips without
``TRADECRAFT_PG_TEST_URL``.
"""

from __future__ import annotations

import asyncio
import contextvars
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

from tradecraft import db, net, runtime  # noqa: E402
from tradecraft.library import reader  # noqa: E402
from tradecraft.store import Store  # noqa: E402
from tradecraft_doubles import FixtureFetcher  # noqa: E402

WIKI = "https://wiki.tc-fixture.test/"
UNION = WIKI + "sqli/union-based/"
MAP = {"nav": [{"title": "Union based", "path": UNION}]}
TABLES = ("user_tradecraft_resources", "tradecraft_entries", "tradecraft_sections", "tradecraft_tree_nodes",
          "tradecraft_page_ids", "tradecraft_ingestion_jobs", "tradecraft_curations")


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
        await self.sql("INSERT INTO users (id, name, email, updated_at) VALUES (%s, 'Reader', %s, now())", uid,
                       f"{uid}@example.test")
        self.users.append(uid)
        return uid

    async def stored_resource(self, uid, text, *, slug="wiki"):
        """A Stored resource of ``uid`` whose live generation holds ``text`` for UNION."""
        rid = f"tc-r-{uuid.uuid4().hex[:12]}"
        await self.sql("INSERT INTO user_tradecraft_resources (id, user_id, name, slug, url, storage_mode, map_version, "
                       "resource_type, sitemap, generation, updated_at) VALUES (%s, %s, 'Wiki', %s, %s, 'stored', 3, "
                       "'mkdocs-wiki', %s::jsonb, 1, now())", rid, uid, f"{slug}-{rid[-6:]}", WIKI,
                       '{"nav": [{"title": "Union based", "path": "' + UNION + '"}]}')
        await self.write_generation(uid, rid, 1, text)
        return rid

    async def write_generation(self, uid, rid, generation, text):
        store = Store()
        ids = await store.allocate_page_ids(uid, rid, [UNION])
        await store.write_entries(uid, rid, generation, [{"page_id": ids[UNION], "url": UNION, "title": "Union based",
                                                          "stored_text": text, "stored_bytes": len(text),
                                                          "fetched_at": "2026-11-10T08:00:00+00:00"}])

    async def counts(self):
        out = {}
        for t in TABLES:
            out[t] = (await self.sql(f"SELECT count(*) AS n, max(updated_at) AS u FROM {t}"
                                     if t not in ("tradecraft_sections", "tradecraft_tree_nodes", "tradecraft_page_ids")
                                     else f"SELECT count(*) AS n FROM {t}"))[0]
        return out


def catalog_for(uid, rid, slug):
    return {"v2": True, "owner_id": uid, "person_id": uid, "actor_id": None, "search": {},
            "resources": [{"id": rid, "slug": slug, "name": "Wiki", "url": WIKI, "type": "mkdocs-wiki",
                           "storage_mode": "stored", "summary": "s", "map_version": 3,
                           "read_settings": {"fetching.browserEnabled": False}}]}


async def read_in_run(catalog, fetcher, **kw):
    """One lookup inside a run's own task, as the executor makes it."""

    async def run():
        with net.use_fetcher(fetcher):
            runtime.bind_run_catalog(catalog)
            return await reader.lookup(**kw)

    return await asyncio.create_task(run(), context=contextvars.Context())


async def test_read_never_writes(pg):
    uid = await pg.user()
    rid = await pg.stored_resource(uid, "stored union text")
    slug = (await pg.sql("SELECT slug FROM user_tradecraft_resources WHERE id = %s", rid))[0]["slug"]
    before = await pg.counts()
    fetcher = FixtureFetcher()
    stored = await read_in_run(catalog_for(uid, rid, slug), fetcher, resource_id=slug, query="union based")
    fresh = await read_in_run(catalog_for(uid, rid, slug), fetcher, resource_id=slug, query="union based",
                              force_refresh=True)
    assert "stored union text" in stored and "live" in fresh
    assert await pg.counts() == before


async def test_two_users(pg):
    """R-301 / AC-19: the same URL stored by two owners; each run reads its own owner's copy."""
    a, b = await pg.user(), await pg.user()
    ra = await pg.stored_resource(a, "text of owner a")
    rb = await pg.stored_resource(b, "text of owner b")
    sa = (await pg.sql("SELECT slug FROM user_tradecraft_resources WHERE id = %s", ra))[0]["slug"]
    sb = (await pg.sql("SELECT slug FROM user_tradecraft_resources WHERE id = %s", rb))[0]["slug"]
    fetcher = FixtureFetcher()
    assert "text of owner a" in await read_in_run(catalog_for(a, ra, sa), fetcher, resource_id=sa, query="union")
    assert "text of owner b" in await read_in_run(catalog_for(b, rb, sb), fetcher, resource_id=sb, query="union")
    # A catalog that names another owner's resource reads nothing of it.
    crossed = await read_in_run(catalog_for(a, rb, sb), fetcher, resource_id=sb, query="union")
    assert crossed == reader.DELETED.format(slug=sb) and fetcher.requests == []


async def test_swap_during_run(pg):
    """D-46: the run's catalog names no generation; after a refresh swaps, the next call reads
    the new generation."""
    uid = await pg.user()
    rid = await pg.stored_resource(uid, "version one")
    slug = (await pg.sql("SELECT slug FROM user_tradecraft_resources WHERE id = %s", rid))[0]["slug"]
    catalog = catalog_for(uid, rid, slug)
    fetcher = FixtureFetcher()

    async def run():
        with net.use_fetcher(fetcher):
            runtime.bind_run_catalog(catalog)
            first = await reader.lookup(resource_id=slug, query="union")
            # A refresh writes generation 2 and swaps it in while the run goes on.
            jid = f"tc-j-{uuid.uuid4().hex[:10]}"
            await pg.sql("INSERT INTO tradecraft_ingestion_jobs (id, user_id, resource_id, kind, status, lease_until, "
                         "owner_instance) VALUES (%s, %s, %s, 'refresh', 'running', %s, 'i')", jid, uid, rid,
                         datetime.now(timezone.utc) + timedelta(seconds=60))
            await pg.sql("UPDATE user_tradecraft_resources SET active_job_id = %s WHERE id = %s", jid, rid)
            await pg.write_generation(uid, rid, 2, "version two")
            assert await Store().swap(uid, rid, jid, 2, WIKI, "stored", {}) == "swapped"
            second = await reader.lookup(resource_id=slug, query="union")
            return first, second

    first, second = await asyncio.create_task(run(), context=contextvars.Context())
    assert "version one" in first and "version two" in second and "version one" not in second
