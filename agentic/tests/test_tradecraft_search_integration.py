"""Library search and browse on Postgres (T2.4): stemming, weights, snippets, synonyms (AC-62),
trigram titles, browse on every type (AC-63), the separation of users and of resources outside
the run's catalog (R-324), hostile query text (D-56), and the live generation only (D-46).

Runs through ``tooling/scripts/tradecraft_pg_testdb.sh agent``; skips without
``TRADECRAFT_PG_TEST_URL``.
"""

from __future__ import annotations

import contextlib
import os
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

PG_URL = os.environ.get("TRADECRAFT_PG_TEST_URL", "")
pytestmark = pytest.mark.skipif(not PG_URL, reason="TRADECRAFT_PG_TEST_URL is not set (tradecraft_pg_testdb.sh agent)")

from test_tradecraft_ingest_pipeline_integration import ingest, pg  # noqa: E402,F401
from tradecraft import db  # noqa: E402
from tradecraft.contract import V2Catalog  # noqa: E402
from tradecraft.library import search, search_sql  # noqa: E402
from tradecraft.store import Store  # noqa: E402
from tradecraft_memory_store import padded_sites  # noqa: E402


async def seed(pg, uid, pages, *, slug=None, mode="stored", generation=1, rid=None, priority="normal"):
    """A resource of ``uid`` whose live generation holds ``pages`` (dicts of card columns, with
    ``sections`` as [(heading, text)]); returns its catalog entry."""
    store = Store()
    if rid is None:
        rid = f"tc-r-{uuid.uuid4().hex[:12]}"
        slug = slug or f"lib-{rid[-6:]}"
        await pg.sql("INSERT INTO user_tradecraft_resources (id, user_id, name, slug, url, storage_mode, map_version, "
                     "resource_type, summary, generation, priority, updated_at) VALUES (%s, %s, %s, %s, %s, %s, 3, "
                     "'mkdocs-wiki', %s, %s, %s, now())", rid, uid, slug.upper(), slug, f"https://{slug}.tc-fixture.test/",
                     mode, f"The {slug} library.", generation, priority)
    slug = (await pg.sql("SELECT slug FROM user_tradecraft_resources WHERE id = %s", rid))[0]["slug"]
    urls = [p["url"] for p in pages]
    ids = await store.allocate_page_ids(uid, rid, urls)
    rows = []
    for p in pages:
        card = {k: v for k, v in p.items() if k != "sections"}
        card.update(page_id=ids[p["url"]])
        if p.get("sections"):
            text = "\n\n".join(f"## {h}\n{t}" for h, t in p["sections"])
            card.update(stored_text=text, stored_bytes=len(text.encode()), size_chars=len(text),
                        fetched_at="2026-11-10T08:00:00+00:00")
        rows.append(card)
    entry_ids = await store.write_entries(uid, rid, generation, rows)
    sections = []
    for p in pages:
        for i, (heading, text) in enumerate(p.get("sections") or ()):
            sections.append({"entry_id": entry_ids[ids[p["url"]]], "ord": i, "heading": heading, "level": 2,
                             "anchor": heading.lower().replace(" ", "-"), "text": text, "chars": len(text)})
    if sections:
        await store.write_sections(uid, rid, generation, sections)
    return {"id": rid, "slug": slug, "name": slug.upper(), "url": f"https://{slug}.tc-fixture.test/",
            "type": "mkdocs-wiki", "storage_mode": mode, "summary": f"The {slug} library.", "priority": priority,
            "map_version": 3}


def catalog(uid, *resources, search_settings=None):
    return V2Catalog.model_validate({"v2": True, "owner_id": uid, "person_id": uid, "actor_id": None,
                                     "search": search_settings or {}, "resources": list(resources)})


def page(n, **cols):
    return {"url": f"https://lib.tc-fixture.test/p{n}/", "title": f"Page {n}", **cols}


def ids(answer):
    return [h.card.page_id.split(":")[1] for h in answer.hits]


async def test_stemming_ranking_snippets(pg):
    uid = await pg.user()
    res = await seed(pg, uid, [
        page(1, title="Kerberoasting"),
        page(2, title="Ticket attacks", description="Kerberoasting is mentioned here in passing."),
        page(3, title="Roasting AS-REP", sections=[("Intro", "Background words."),
                                                   ("Requesting hashes", "Ask the domain controller for hashes of "
                                                    "accounts without preauthentication, then crack them offline.")]),
        page(4, title="Unrelated SSRF basics"),
    ])
    cat = catalog(uid, res)
    answer = await search.search(uid, cat, "kerberoast")
    assert answer.verdict == "FOUND"
    titles = [h.card.title for h in answer.hits]
    assert titles[:2] == ["Kerberoasting", "Ticket attacks"]  # stemming; the title outranks the description
    assert "Unrelated SSRF basics" not in titles
    inside = await search.search(uid, cat, "preauthentication crack")
    hit = inside.hits[0]
    assert hit.card.title == "Roasting AS-REP" and hit.section == "Requesting hashes"
    assert "preauthentication" in hit.snippet and len(hit.snippet) <= 200 and "<b>" not in hit.snippet
    assert hit.card.stored and hit.card.page_id.startswith(res["slug"] + ":")


async def test_weights_synonyms_trigram(pg):
    uid = await pg.user()
    res = await seed(pg, uid, [
        page(1, title="Notes", description="smuggling appears in the description only"),
        page(2, title="Notes two", headings=[{"level": 2, "text": "Smuggling with CL.TE"}]),
        page(3, title="HTTP request smuggling"),
        page(4, title="Server-side request forgery"),
        page(5, title="Kerberos: Kerberoasting"),
    ])
    cat = catalog(uid, res)
    weighted = await search.search(uid, cat, "smuggling")
    assert [h.card.title for h in weighted.hits][:3] == ["HTTP request smuggling", "Notes two", "Notes"]
    synonym = await search.search(uid, cat, "ssrf")
    assert synonym.hits and synonym.hits[0].card.title == "Server-side request forgery"
    assert synonym.verdict == "FOUND" and any(w.startswith("synonyms:") for w in synonym.wordings)
    typo = await search.search(uid, cat, "kerberaosting")
    assert typo.hits and typo.hits[0].card.title == "Kerberos: Kerberoasting" and typo.verdict == "RELATED"


async def test_named_counts_the_title_and_the_breadcrumb_never_the_headings(pg):
    """FIX-ITER4: Library now's fit asks that the step be named where a page names itself, its title
    or its breadcrumb (a page whose stored title is only the site's name is named by its path); a
    heading says what a long page contains. The search's own strong share still reads headings."""
    uid = await pg.user()
    res = await seed(pg, uid, [
        page(1, title="Kerberoasting walkthrough"),
        page(2, title="HackTricks", breadcrumb=["windows hardening", "kerberoasting"]),
        page(3, title="Ticket notes", headings=[{"level": 2, "text": "Kerberoasting"}]),
        page(4, title="Domain notes", sections=[("Intro", "Kerberoasting is described here, in the text only.")]),
    ])
    fp = await search.free_first_pass(uid, catalog(uid, res), "kerberoasting")
    got = {c.row["title"]: (c.named, round(c.strong, 2), round(c.anywhere, 2)) for c in fp.candidates}
    assert got == {"Kerberoasting walkthrough": (1, 1.0, 1.0), "HackTricks": (1, 1.0, 1.0),
                   "Ticket notes": (0, 1.0, 1.0), "Domain notes": (0, 0.0, 1.0)}
    assert fp.total == 1


async def test_named_reads_the_pages_own_file_name_and_the_steps_vocabulary_topic(pg):
    """FIX-ITER4 review: a page stored under its site's name names itself in its file name (the
    URL's last segment, its extension dropped, a folder's name when the URL ends with a slash); and a
    step that names a vocabulary topic ("path traversal") names a page whose title says it in other
    words of that topic ("Directory Traversal")."""
    uid = await pg.user()
    res = await seed(pg, uid, [
        page(1, title="Directory Traversal > README", breadcrumb=["Directory Traversal"],
             url="https://lib.tc-fixture.test/Directory%20Traversal/README.md"),
        page(2, title="HackTricks", breadcrumb=["linux hardening"],
             url="https://lib.tc-fixture.test/en/linux-hardening/docker-breakout-privilege-escalation.html",
             sections=[("Intro", "Abusing the docker socket for a breakout.")]),
        page(3, title="Index", breadcrumb=["research"], url="https://lib.tc-fixture.test/research/container-escapes/",
             description="docker breakout research"),
        page(4, title="Ticket notes", headings=[{"level": 2, "text": "Path traversal"}],
             url="https://lib.tc-fixture.test/notes.html"),
    ])
    cat = catalog(uid, res)
    traversal = await search.free_first_pass(uid, cat, "check the path traversal on the download")
    got = {c.row["title"]: (c.named, c.named_topics) for c in traversal.candidates}
    assert got["Directory Traversal > README"] == (0, 1) and got["Ticket notes"] == (0, 0)
    breakout = await search.free_first_pass(uid, cat, "docker breakout to the host")
    got = {c.row["title"]: c.named for c in breakout.candidates}
    # docker and breakout in the first one's file name; container (the topic's word) in the folder's.
    assert got["HackTricks"] == 2 and got["Index"] == 0
    assert {c.row["title"]: c.named_topics for c in breakout.candidates}["Index"] == 1


async def test_synonyms_same_pages(pg):
    """AC-62: "sqli", "SQLi" and "SQL injection" find the same pages."""
    uid = await pg.user()
    res = await seed(pg, uid, [page(1, title="SQL Injection basics"), page(2, title="Blind SQLi"),
                               page(3, title="Union based SQL injection"), page(4, title="XSS polyglots")])
    cat = catalog(uid, res)
    found = {}
    for query in ("sqli", "SQLi", "SQL injection"):
        answer = await search.search(uid, cat, query)
        assert answer.verdict == "FOUND", query
        found[query] = sorted(ids(answer))
    assert found["sqli"] == found["SQLi"] == found["SQL injection"] and len(found["sqli"]) == 3


async def test_browse(pg, tmp_path):
    """R-372: one level of the tree with counts and descriptions; the root shows the summary."""
    root = padded_sites(tmp_path)
    uid, rid, job, _ = await ingest(pg, root, "https://wiki.tc-fixture.test/")
    assert job["status"] == "succeeded"
    cat = catalog(uid, await _entry(pg, rid))
    top = await search.browse(uid, cat, cat.resources[0].slug, "")
    assert top.summary and top.path == "" and top.page_count >= 28
    folders = {f.label: f for f in top.folders}
    assert folders["kerberos"].page_count == 7 and folders["kerberos"].path == "kerberos/"
    level = await search.browse(uid, cat, cat.resources[0].slug, "/kerberos")
    assert level.path == "kerberos/" and level.summary is None and level.page_count == 7
    assert len(level.pages) == 7 and level.folders == () and level.breadcrumb[1:] == ("kerberos",)
    assert all(p.page_id.startswith(cat.resources[0].slug + ":") for p in level.pages)
    with pytest.raises(search.SearchError):
        await search.browse(uid, cat, cat.resources[0].slug, "nowhere/")


async def _entry(pg, rid, **extra):
    r = (await pg.sql("SELECT * FROM user_tradecraft_resources WHERE id = %s", rid))[0]
    entry = {"id": r["id"], "slug": r["slug"], "name": r["name"], "url": r["url"],
             "type": r["resource_type"] or "agentic-crawl", "storage_mode": r["storage_mode"],
             "summary": r["summary"] or "", "priority": r["priority"], "map_version": r["map_version"]}
    entry.update(extra)
    return entry


@pytest.mark.parametrize("url,expect", [
    ("https://wiki.tc-fixture.test/", "folders"),
    ("https://docs.tc-fixture.test/", "folders"),
    ("https://book.tc-fixture.test/", "folders"),
    ("https://github.com/tc-fixture/payloads", "folders"),
    ("https://files.tc-fixture.test/guide.pdf", "pages"),
    ("https://github.com/tc-fixture/cve", "summary"),
])
async def test_browse_every_type(pg, tmp_path, url, expect):
    """AC-63 (the blog's virtual topic tree: ``test_browse_virtual_topic_tree``)."""
    uid, rid, job, _ = await ingest(pg, padded_sites(tmp_path), url, mode="live")
    assert job["status"] == "succeeded", job["error_code"]
    cat = catalog(uid, await _entry(pg, rid))
    top = await search.browse(uid, cat, cat.resources[0].slug, "")
    assert top.summary is not None
    if expect == "folders":
        assert top.folders and all(f.page_count >= 1 for f in top.folders)
        inner = await search.browse(uid, cat, cat.resources[0].slug, top.folders[0].path)
        assert inner.pages or inner.folders
    elif expect == "pages":
        assert top.folders == () and len(top.pages) == 3 and top.page_count == 3
    else:
        assert top.folders == () and top.pages == () and top.page_count == 0


async def test_browse_virtual_topic_tree(pg):
    uid = await pg.user()
    res = await seed(pg, uid, [page(i, title=f"Lab note {i}", topics=[t] if t else [])
                               for i, t in enumerate(["xss", "xss", "ssrf", None], start=1)])
    await Store().write_tree(uid, res["id"], 1, [
        {"path": "XSS/", "parent_path": "", "label": "XSS", "page_count": 2, "kind": "topic"},
        {"path": "SSRF/", "parent_path": "", "label": "SSRF", "page_count": 1, "kind": "topic"},
        {"path": "Other/", "parent_path": "", "label": "Other", "page_count": 1, "kind": "topic"}])
    cat = catalog(uid, res)
    top = await search.browse(uid, cat, res["slug"], "")
    assert [f.label for f in top.folders] == ["XSS", "Other", "SSRF"] and top.pages == ()
    xss = await search.browse(uid, cat, res["slug"], "XSS")
    assert sorted(p.title for p in xss.pages) == ["Lab note 1", "Lab note 2"]
    other = await search.browse(uid, cat, res["slug"], "Other/")
    assert [p.title for p in other.pages] == ["Lab note 4"]


async def test_two_users_same_url(pg):
    a, b = await pg.user(), await pg.user()
    res_a = await seed(pg, a, [page(1, title="Kerberoasting for user A")], slug="shared")
    res_b = await seed(pg, b, [page(1, title="Kerberoasting for user B")], slug="shared")
    got_a = await search.search(a, catalog(a, res_a), "kerberoasting")
    got_b = await search.search(b, catalog(b, res_b), "kerberoasting")
    assert [h.card.title for h in got_a.hits] == ["Kerberoasting for user A"]
    assert [h.card.title for h in got_b.hits] == ["Kerberoasting for user B"]
    # A's owner id with B's resource in the catalog still reads nothing of B's.
    crossed = await search.search(a, catalog(a, res_b), "kerberoasting")
    assert crossed.hits == () and crossed.verdict == "NOT FOUND"
    level = await search.browse(a, catalog(a, res_b), res_b["slug"], "")
    assert level.pages == () and level.page_count == 0


async def test_resource_outside_catalog_never_returned(pg):
    uid = await pg.user()
    inside = await seed(pg, uid, [page(1, title="XXE out of band")])
    outside = await seed(pg, uid, [page(2, title="XXE blind exfiltration")])
    cat = catalog(uid, inside)
    answer = await search.search(uid, cat, "xxe")
    assert [h.card.title for h in answer.hits] == ["XXE out of band"]
    with pytest.raises(search.SearchError):
        await search.search(uid, cat, "xxe", resource=outside["slug"])
    with pytest.raises(search.SearchError):
        await search.browse(uid, cat, outside["slug"], "")


@pytest.mark.parametrize("query", ["it's \"quoted\" o'brien", "kerb:* & !ssrf | (", "back\\slash \\\\ \\'", "x" * 10000,
                                   " ".join(["xxe"] * 3000), "'; DROP TABLE tradecraft_entries; --", "%s %(uid)s {}"])
async def test_hostile_query_text(pg, query):
    a, b = await pg.user(), await pg.user()
    res_a = await seed(pg, a, [page(1, title="XXE out of band", description="xxe kerb ssrf quoted")])
    await seed(pg, b, [page(1, title="XXE of user B", description="xxe kerb ssrf quoted")])
    answer = await search.search(a, catalog(a, res_a), query)
    assert all(h.card.resource_slug == res_a["slug"] for h in answer.hits)
    count = await pg.sql("SELECT count(*) AS n FROM tradecraft_entries WHERE user_id = ANY(%s)", [a, b])
    assert count[0]["n"] == 2


async def test_search_after_swap(pg):
    """D-46: search reads each resource's live generation at each call; a generation that is not
    live is never answered, before or after the swap."""
    uid = await pg.user()
    res = await seed(pg, uid, [page(1, title="Old title before the refresh")])
    cat = catalog(uid, res)
    assert ids(await search.search(uid, cat, "before refresh"))
    # The refresh writes generation 2 beside the live 1: nothing of it answers yet.
    await seed(pg, uid, [page(1, title="New title after the swap")], rid=res["id"], generation=2)
    assert (await search.search(uid, cat, "swap")).hits == ()
    await pg.sql("UPDATE user_tradecraft_resources SET generation = 2 WHERE id = %s", res["id"])
    after = await search.search(uid, cat, "swap")
    assert [h.card.title for h in after.hits] == ["New title after the swap"]
    assert (await search.search(uid, cat, "before refresh")).hits == ()


class SwapMidCall:
    """The page store's connections, with a refresh's swap committed on another connection just
    before the statement ``before`` first runs, and the old generation purged: a swap that lands
    in the middle of one search or browse (D-46)."""

    def __init__(self, pg, rid, before):
        self.pg, self.rid, self.before, self.swapped = pg, rid, before, False

    @contextlib.asynccontextmanager
    async def connect(self):
        async with db.connection() as conn:
            yield _SwapConn(conn, self)

    async def swap(self):
        self.swapped = True
        await self.pg.sql("UPDATE user_tradecraft_resources SET generation = 2 WHERE id = %s", self.rid)
        for table in ("tradecraft_sections", "tradecraft_entries"):
            await self.pg.sql(f"DELETE FROM {table} WHERE resource_id = %s AND generation = 1", self.rid)


class _SwapConn:
    def __init__(self, conn, owner):
        self._conn, self._owner = conn, owner

    async def execute(self, query, params=None):
        if not self._owner.swapped and query == search_sql.STATEMENTS[self._owner.before]:
            await self._owner.swap()
        return await self._conn.execute(query, params)


def _refreshed(n, title, words):
    return page(n, title=title, headings=[{"level": 2, "text": "Order by clause injection"}],
                sections=[("Order by clause injection", f"Inject into the order by clause with a case expression, "
                                                        f"{words}.")])


@pytest.mark.parametrize("before", ["sections_text", "assess", "section_snippets"])
async def test_a_swap_during_one_search_is_not_seen_by_it(pg, before):
    """S05 review (second reviewer), D-46: the statements of one search are tied together by entry
    ids, which differ in each generation; each ran in its own transaction, so a swap committing
    between them gave NOT FOUND (no coverage for the old ids), a page twice, or a page without
    its snippet. One search now reads one snapshot: the generation live when it started."""
    uid = await pg.user()
    res = await seed(pg, uid, [_refreshed(1, "Notes on databases", "old words")])
    await seed(pg, uid, [_refreshed(1, "Notes on databases, revised", "new words")], rid=res["id"], generation=2)
    cat = catalog(uid, res)
    swap = SwapMidCall(pg, res["id"], before)
    answer = await search.search(uid, cat, "order clause injection", index=search.LibraryIndex(swap.connect))
    assert swap.swapped
    assert answer.verdict == "FOUND"
    assert [h.card.title for h in answer.hits] == ["Notes on databases"]
    assert "old words" in answer.hits[0].snippet
    # The next call reads the new generation.
    after = await search.search(uid, cat, "order clause injection")
    assert [h.card.title for h in after.hits] == ["Notes on databases, revised"] and "new words" in after.hits[0].snippet


async def test_a_swap_during_one_browse_is_not_seen_by_it(pg):
    """D-46 for browse: the level's page count and its pages come from one generation."""
    uid = await pg.user()
    res = await seed(pg, uid, [page(1, title="Old page")])
    await seed(pg, uid, [page(n, title=f"New page {n}") for n in (1, 2, 3)], rid=res["id"], generation=2)
    cat = catalog(uid, res)
    swap = SwapMidCall(pg, res["id"], "pages_at")
    level = await search.browse(uid, cat, res["slug"], "", index=search.LibraryIndex(swap.connect))
    assert swap.swapped
    assert level.page_count == 1 and [c.title for c in level.pages] == ["Old page"]
    again = await search.browse(uid, cat, res["slug"], "")
    assert again.page_count == 3 and len(again.pages) == 3


def _ranked_sections(plan):
    """How many section rows the sections statement ranked: the rows that reach the sort its
    DISTINCT ON per entry reads (each carries its rank), over every loop of the sort's input (a
    nested loop may scan the sorted rows again without ranking them again)."""
    stack = [plan[0]["Plan"]]
    while stack:
        node = stack.pop()
        if node.get("Node Type") == "Sort" and str((node.get("Sort Key") or [""])[0]).startswith("s.entry_id"):
            source = node["Plans"][0]
            return source["Actual Rows"] * source["Actual Loops"]
        stack.extend(node.get("Plans") or [])
    raise AssertionError("no sort by entry in the plan")


async def test_a_filtered_wording_ranks_only_the_sections_of_its_own_pages(pg):
    """A topic or technology wording ranks the sections of the pages it can return, not every
    section the words match, and returns the rows that ranking them all and filtering after
    returns."""
    uid = await pg.user()
    res = await seed(pg, uid, [
        page(n, title=f"Page {n}", topics=["sql_injection"] if n <= 2 else ["xss"],
             technologies=["postgresql"] if n == 3 else [],
             sections=[(f"Part {n} one", "payload words for the probe"), (f"Part {n} two", "more payload text")])
        for n in range(1, 13)])
    base = {"uid": uid, "rids": [res["id"]], "q": "payload or probe", "topic": None, "kind": None, "tech": None,
            "techs": [], "limit": 20}
    sql = search_sql.STATEMENTS["sections_text"]

    async def rows(params):
        cur = await pg.conn.execute(sql, params)
        return [(r["page_id"], r["section"], r["rank"], tuple(r["topics"]), tuple(r["technologies"]))
                for r in await cur.fetchall()]

    async def ranked(params):
        cur = await pg.conn.execute("EXPLAIN (ANALYZE, FORMAT JSON) " + sql, params)
        return _ranked_sections((await cur.fetchall())[0]["QUERY PLAN"])

    every = await rows(base)
    assert len(every) == 12 and await ranked(base) == 24
    on_topic = await rows({**base, "topic": "sql_injection"})
    assert on_topic == [r for r in every if "sql_injection" in r[3]] and len(on_topic) == 2
    assert await ranked({**base, "topic": "sql_injection"}) == 4
    on_tech = await rows({**base, "techs": ["postgresql"]})
    assert on_tech == [r for r in every if "postgresql" in r[4]] and await ranked({**base, "techs": ["postgresql"]}) == 2
