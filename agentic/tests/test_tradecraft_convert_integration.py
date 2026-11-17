"""The conversion of 1.x resources on a real Postgres (T9.1; R-011, R-215, AC-36, D-26, D-35): every
1.x shape converts without a download, twice is once, a 1.x map changed while the switch was off is
converted again, a PDF is downloaded once and becomes Stored, a converted resource answers a read with
no refresh, and a resource another job holds is skipped until the next sweep.

Runs through ``tooling/scripts/tradecraft_pg_testdb.sh agent``; skips without
``TRADECRAFT_PG_TEST_URL``. Each test creates its own users and deletes them at the end.
"""

from __future__ import annotations

import asyncio
import contextvars
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

from tradecraft import convert, db, jobs, net, runtime  # noqa: E402
from tradecraft.ingest import legacy_map  # noqa: E402
from tradecraft.library import reader  # noqa: E402
from tradecraft.store import Store  # noqa: E402
from tradecraft_doubles import FixtureFetcher  # noqa: E402

WIKI = "https://wiki.tc-fixture.test/"
PDF = "https://files.tc-fixture.test/guide.pdf"
WIKI_MAP = {"nav": [{"title": "Kerberoasting", "path": "kerberos/kerberoasting/"},
                    {"title": "Golden ticket CVE-2014-6324", "path": "kerberos/golden-ticket/"},
                    {"title": "SQL Injection cheat sheet", "path": "sqli/cheat-sheet/"}]}


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

    async def user(self, *, v2=True):
        uid = f"tc-u-{uuid.uuid4().hex[:12]}"
        await self.sql("INSERT INTO users (id, name, email, updated_at) VALUES (%s, 'Convert', %s, now())", uid,
                       f"{uid}@example.test")
        await self.sql("INSERT INTO tradecraft_user_settings (id, user_id, v2_enabled, updated_at) "
                       "VALUES (%s, %s, %s, now())", f"tc-s-{uid}", uid, v2)
        self.users.append(uid)
        return uid

    async def legacy(self, uid, url, sitemap, *, rtype="mkdocs-wiki", slug="wiki", has_login=False):
        """A 1.x resource as 7.7.2 left it: map_version 1, its map in ``sitemap``, Live."""
        rid = f"tc-r-{uuid.uuid4().hex[:12]}"
        await self.sql("INSERT INTO user_tradecraft_resources (id, user_id, name, slug, url, resource_type, sitemap, "
                       "has_login, updated_at) VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s, now())",
                       rid, uid, slug.title(), f"{slug}-{rid[-6:]}", url, rtype, json.dumps(sitemap), has_login)
        return rid

    async def row(self, rid):
        return (await self.sql("SELECT * FROM user_tradecraft_resources WHERE id = %s", rid))[0]

    async def entries(self, rid, generation=None):
        rows = await self.sql("SELECT e.* FROM tradecraft_entries e JOIN user_tradecraft_resources r ON r.id = e.resource_id "
                              "WHERE e.resource_id = %s AND e.generation = COALESCE(%s, r.generation) ORDER BY e.page_id",
                              rid, generation)
        return rows

    async def jobs(self, uid, kind):
        return await self.sql("SELECT * FROM tradecraft_ingestion_jobs WHERE user_id = %s AND kind = %s "
                              "ORDER BY created_at", uid, kind)


async def converted(runner, uid):
    """``convert.start`` and the background conversion it started, to its end."""
    queued = await convert.start(runner, uid)
    await settle(runner)
    return queued


async def settle(runner):
    for _ in range(200):
        pending = [t for t in runner._background if t.get_name().startswith("tradecraft-convert") and not t.done()]
        if not pending:
            return
        await asyncio.gather(*pending, return_exceptions=True)


@pytest.fixture
async def runner():
    fetcher = FixtureFetcher()
    r = jobs.JobRunner(Store(), fetcher_factory=lambda: fetcher)
    r.fetcher = fetcher
    try:
        yield r
    finally:
        await r.close()


async def test_every_shape_converts(pg, runner):
    uid = await pg.user()
    wiki = await pg.legacy(uid, WIKI, WIKI_MAP)
    repo = await pg.legacy(uid, "https://github.com/acme/payloads", {
        "tree": [{"title": "SQL Injection > MySQL", "path": "SQL Injection/MySQL.md"}],
        "owner": "acme", "repo": "payloads", "branch": "main"}, rtype="github-repo", slug="repo")
    links = await pg.legacy(uid, "https://blog.tc-fixture.test/", {"links": [{"title": "XSS notes", "path": "xss"}]},
                            rtype="agentic-crawl", slug="blog")
    cves = await pg.legacy(uid, "https://github.com/acme/cves", {"owner": "acme", "repo": "cves", "branch": "main"},
                           rtype="cve-poc-db", slug="cves")
    empty = await pg.legacy(uid, "https://other.tc-fixture.test/", {}, rtype="agentic-crawl", slug="other")

    assert await converted(runner, uid) == 5
    for rid in (wiki, repo, links, cves, empty):
        row = await pg.row(rid)
        assert row["map_version"] == 2 and row["active_job_id"] is None and row["storage_mode"] == "live"
        assert row["legacy_map_hash"] == legacy_map.map_hash(row["sitemap"])
        assert row["generation"] >= 1
    wiki_entries = await pg.entries(wiki)
    assert [e["title"] for e in wiki_entries] == [i["title"] for i in WIKI_MAP["nav"]]
    assert {e["source"] for e in wiki_entries} == {"legacy"}
    assert all(e["title_source"] == "guessed" and e["stored_text"] is None and e["headings"] == [] for e in wiki_entries)
    golden = next(e for e in wiki_entries if "Golden" in e["title"])
    assert "CVE-2014-6324" in golden["entities"]
    sqli = next(e for e in wiki_entries if "SQL" in e["title"])
    assert sqli["topics"], "the rules tag a title they know"
    assert [e["url"] for e in await pg.entries(repo)] == [
        "https://raw.githubusercontent.com/acme/payloads/main/SQL%20Injection/MySQL.md"]
    assert (await pg.entries(repo))[0]["breadcrumb"] == ["SQL Injection"]
    assert [e["url"] for e in await pg.entries(links)] == ["https://blog.tc-fixture.test/xss"]
    assert await pg.entries(cves) == []
    assert [e["title"] for e in await pg.entries(empty)] == ["other.tc-fixture.test (homepage)"]
    # Nothing was downloaded, and the account's one convert job ended.
    assert runner.fetcher.requests == []
    [job] = await pg.jobs(uid, "convert")
    assert (job["status"], job["error_code"], job["resource_id"], job["lease_until"]) == ("succeeded", "", None, None)


async def test_idempotent(pg, runner):
    uid = await pg.user()
    rid = await pg.legacy(uid, WIKI, WIKI_MAP)
    first, second = await asyncio.gather(convert.start(runner, uid), convert.start(runner, uid))
    await settle(runner)
    assert sorted([first, second]) == [0, 1], "two starts at once open one conversion"
    row = await pg.row(rid)
    ids = [(e["url"], e["page_id"]) for e in await pg.entries(rid)]
    assert await converted(runner, uid) == 0, "a converted resource needs nothing"
    assert await pg.row(rid) == row
    assert [(e["url"], e["page_id"]) for e in await pg.entries(rid)] == ids
    assert len(await pg.jobs(uid, "convert")) == 1


async def test_reconvert_on_hash_change(pg, runner):
    uid = await pg.user()
    rid = await pg.legacy(uid, WIKI, WIKI_MAP)
    assert await converted(runner, uid) == 1
    before = {e["url"]: e["page_id"] for e in await pg.entries(rid)}
    old_generation = (await pg.row(rid))["generation"]
    # A 1.x Refresh while the switch was off writes only the map (D-26).
    changed = {"nav": WIKI_MAP["nav"][:2] + [{"title": "Silver ticket", "path": "kerberos/silver-ticket/"}]}
    await pg.sql("UPDATE user_tradecraft_resources SET sitemap = %s::jsonb WHERE id = %s", json.dumps(changed), rid)
    assert await converted(runner, uid) == 1
    row = await pg.row(rid)
    assert row["generation"] > old_generation and row["legacy_map_hash"] == legacy_map.map_hash(changed)
    after = {e["url"]: e["page_id"] for e in await pg.entries(rid)}
    assert [e["title"] for e in await pg.entries(rid)] == ["Kerberoasting", "Golden ticket CVE-2014-6324", "Silver ticket"]
    kept = set(before) & set(after)
    assert len(kept) == 2 and all(before[u] == after[u] for u in kept), "a page keeps its ID"
    assert await pg.entries(rid, old_generation) == [], "the old generation is purged"
    # A resource 2.0 ingested (map_version 3) whose 1.x map changed is converted again too.
    await pg.sql("UPDATE user_tradecraft_resources SET map_version = 3, sitemap = %s::jsonb WHERE id = %s",
                 json.dumps(WIKI_MAP), rid)
    assert await converted(runner, uid) == 1
    assert (await pg.row(rid))["map_version"] == 2


async def test_pdf_enqueued_and_stored(pg, runner):
    uid = await pg.user()
    rid = await pg.legacy(uid, PDF, {"pages": [{"page": 1, "firstLine": "1 Introduction"},
                                               {"page": 3, "firstLine": "3 Kerberos"}]},
                          rtype="agentic-crawl", slug="guide")
    assert await converted(runner, uid) == 1
    row = await pg.row(rid)
    assert (row["map_version"], row["storage_mode"], row["active_job_id"]) == (2, "stored", None)
    entries = await pg.entries(rid)
    assert [e["url"] for e in entries] == [f"{PDF}#page=1", f"{PDF}#page=3"]
    assert [e["title"] for e in entries] == ["1 Introduction", "3 Kerberos"]
    assert "Kerberoasting requests service tickets" in entries[1]["stored_text"]
    assert all(e["source"] == "pdf" and e["stored_bytes"] > 0 for e in entries)
    sections = await pg.sql("SELECT count(*) AS n FROM tradecraft_sections WHERE resource_id = %s AND generation = %s",
                            rid, row["generation"])
    assert sections[0]["n"] >= 2
    assert [u for u, _h in runner.fetcher.requests] == [PDF], "the document is downloaded once"
    [pdf_job] = await pg.jobs(uid, "pdf_convert")
    assert (pdf_job["status"], pdf_job["resource_id"], pdf_job["target_generation"]) == ("succeeded", rid,
                                                                                          row["generation"])


async def test_pdf_with_a_login_or_unreachable_stays_live(pg, runner):
    uid = await pg.user()
    login = await pg.legacy(uid, PDF, {"pages": [{"page": 2, "firstLine": "2 SQL injection"}]}, rtype="agentic-crawl",
                            slug="guide", has_login=True)
    gone = await pg.legacy(uid, "https://down.tc-fixture.test/missing.pdf",
                           {"pages": [{"page": 1, "firstLine": "Intro"}]}, rtype="agentic-crawl", slug="missing")
    assert await converted(runner, uid) == 2
    for rid, url in ((login, PDF), (gone, "https://down.tc-fixture.test/missing.pdf")):
        row = await pg.row(rid)
        assert (row["map_version"], row["storage_mode"]) == (2, "live")
        assert [(e["url"], e["source"], e["stored_text"]) for e in await pg.entries(rid)][0][:2] == (
            f"{url}#page={1 if rid == gone else 2}", "legacy")
    assert all(PDF not in u for u, _h in runner.fetcher.requests), "a login's PDF is never fetched without it"
    [failed] = await pg.jobs(uid, "pdf_convert")
    assert failed["status"] == "failed" and failed["resource_id"] == gone


async def test_answers_without_refresh(pg, runner):
    """AC-36: right after the conversion, the read path finds the page by its ID and reads it live."""
    uid = await pg.user()
    rid = await pg.legacy(uid, WIKI, WIKI_MAP)
    assert await converted(runner, uid) == 1
    row = await pg.row(rid)
    page = next(e for e in await pg.entries(rid) if e["title"] == "Kerberoasting")
    catalog = {"v2": True, "owner_id": uid, "person_id": uid, "actor_id": None, "search": {},
               "resources": [{"id": rid, "slug": row["slug"], "name": "Wiki", "url": WIKI, "type": "mkdocs-wiki",
                              "storage_mode": "live", "summary": "", "map_version": 2,
                              "read_settings": {"fetching.browserEnabled": False}}]}
    fetcher = FixtureFetcher()

    async def run():
        with net.use_fetcher(fetcher):
            runtime.bind_run_catalog(catalog)
            by_id = await reader.lookup(page=f"{row['slug']}:{page['page_id']}")
            by_title = await reader.lookup(resource_id=row["slug"], query="kerberoasting")
            return by_id, by_title

    by_id, by_title = await asyncio.create_task(run(), context=contextvars.Context())
    assert "Kerberoast" in by_id and "source: live" in by_id, by_id
    assert "Kerberoast" in by_title, by_title
    assert all(u.startswith(f"{WIKI}kerberos/kerberoasting") for u, _h in fetcher.requests)


async def test_claim_respected(pg, runner):
    """A resource another job holds is skipped, its claim untouched; the next sweep converts it."""
    uid = await pg.user()
    held = await pg.legacy(uid, WIKI, WIKI_MAP)
    free = await pg.legacy(uid, "https://blog.tc-fixture.test/", {"links": [{"title": "A", "path": "a"}]},
                           rtype="agentic-crawl", slug="blog")
    jid = f"tc-j-{uuid.uuid4().hex[:12]}"
    until = datetime.now(timezone.utc) + timedelta(seconds=60)
    await pg.sql("INSERT INTO tradecraft_ingestion_jobs (id, user_id, resource_id, kind, status, lease_until) "
                 "VALUES (%s, %s, %s, 'refresh', 'running', %s)", jid, uid, held, until)
    await pg.sql("UPDATE user_tradecraft_resources SET active_job_id = %s WHERE id = %s", jid, held)
    assert await converted(runner, uid) == 2
    assert (await pg.row(held))["map_version"] == 1 and (await pg.row(held))["active_job_id"] == jid
    assert await pg.entries(held) == []
    assert (await pg.row(free))["map_version"] == 2
    await pg.sql("UPDATE tradecraft_ingestion_jobs SET status = 'succeeded', lease_until = NULL WHERE id = %s", jid)
    await pg.sql("UPDATE user_tradecraft_resources SET active_job_id = NULL WHERE id = %s", held)
    assert await jobs_sweep(runner) >= 1
    assert (await pg.row(held))["map_version"] == 2


async def jobs_sweep(runner):
    total = await convert.boot_sweep(runner)
    await settle(runner)
    return total


async def test_a_dead_conversions_claim_is_taken(pg, runner):
    uid = await pg.user()
    rid = await pg.legacy(uid, WIKI, WIKI_MAP)
    dead = f"tc-j-{uuid.uuid4().hex[:12]}"
    await pg.sql("INSERT INTO tradecraft_ingestion_jobs (id, user_id, kind, status, error_code) "
                 "VALUES (%s, %s, 'convert', 'failed', 'agent_restarted')", dead, uid)
    await pg.sql("UPDATE user_tradecraft_resources SET active_job_id = %s WHERE id = %s", dead, rid)
    assert await converted(runner, uid) == 1
    assert (await pg.row(rid))["map_version"] == 2


async def test_the_sweep_converts_every_account(pg, runner):
    """Since the cut-over (T9.2) every account has 2.0: the boot sweep converts each one, its
    old switch row (on, off, or none) aside."""
    on, off = await pg.user(v2=True), await pg.user(v2=False)
    bare = f"tc-u-{uuid.uuid4().hex[:12]}"
    await pg.sql("INSERT INTO users (id, name, email, updated_at) VALUES (%s, 'No row', %s, now())", bare,
                 f"{bare}@example.test")
    pg.users.append(bare)
    rows = [await pg.legacy(u, WIKI, WIKI_MAP) for u in (on, off, bare)]
    await jobs_sweep(runner)
    assert [(await pg.row(r))["map_version"] for r in rows] == [2, 2, 2]


async def test_a_map_written_during_the_conversion_is_not_lost(pg, runner, monkeypatch):
    """The swap holds only while the 1.x map is the one converted: a 1.x write that raced it leaves the
    resource unconverted (its new map read by the title match), and the next sweep converts it."""
    uid = await pg.user()
    rid = await pg.legacy(uid, WIKI, WIKI_MAP)
    real = convert._derive_and_write

    async def racing(state):
        await real(state)
        await pg.sql("UPDATE user_tradecraft_resources SET sitemap = %s::jsonb WHERE id = %s",
                     json.dumps({"nav": WIKI_MAP["nav"][:1]}), rid)

    monkeypatch.setattr(convert, "_derive_and_write", racing)
    assert await converted(runner, uid) == 1
    row = await pg.row(rid)
    assert (row["map_version"], row["active_job_id"]) == (1, None)
    assert await pg.sql("SELECT 1 FROM tradecraft_entries WHERE resource_id = %s", rid) == []
    monkeypatch.setattr(convert, "_derive_and_write", real)
    assert await converted(runner, uid) == 1
    assert [e["title"] for e in await pg.entries(rid)] == ["Kerberoasting"]
