"""Reading by page and section (T2.5, Q8): the new arguments beside the old ones (R-380), one
section per read within ``reading.charsPerRead`` with its parts and the other sections listed
(R-381, AC-66), a Live page split at read time with nothing kept (R-382), code blocks whole, an
old page ID after the resource was added again (R-138), and every page read recorded as seen.

The store is ``MemoryStore`` and the sites the fixture sites, through the library helper of
``test_tradecraft_reader.py``; a fake search index stands in for the free first pass.
"""

from __future__ import annotations

import asyncio
import contextvars
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from test_tradecraft_reader import OWNER, PAGES, WIKI, Library, header, no_browser  # noqa: E402
from tradecraft import net, run_state, runtime  # noqa: E402
from tradecraft.library import reader, split  # noqa: E402
from tradecraft.library.types import parse_read_section  # noqa: E402

UNION = PAGES["SQL injection: Union based"]
KERBEROAST = PAGES["Kerberos: Kerberoasting"]
PAGE = """Intro words.

## Error based

Use errors to leak data.

## Time based

Use pg_sleep for a delay on PostgreSQL.

## Stacked queries

Several statements at once.
"""


class FirstPass:
    """The search index the free first pass reads: every text query answers ``rows``."""

    def __init__(self, rows):
        self.rows_, self.calls = rows, []

    async def rows(self, name, params):
        self.calls.append(name)
        if name == "assess":
            return [{"id": i, "total": 1, "strong": 1, "anywhere": 1} for i in params["ids"]]
        return [dict(r) for r in self.rows_] if name == "entries_text" else []


def card_row(lib, rid, url):
    pid = lib.store.page_ids[(rid, url)]
    return {"id": pid, "page_id": pid, "resource_id": rid, "url": url, "title": "t", "title_source": "real",
            "breadcrumb": [], "headings": [], "description": "", "topics": [], "kinds": [], "technologies": [],
            "entities": [], "size_chars": 0, "fetched_at": None, "stored": True, "rank": 1.0}


def read(lib, state=None, index=None, search=None, **kw):
    """One lookup inside a run's task, with the run state bound as the executor binds it."""
    catalog = lib.catalog()
    if search:
        catalog["search"] = search

    async def go():
        with net.use_fetcher(lib.fetcher), runtime.use_store(lib.store):
            if index is not None:
                with runtime.use_index(index):
                    assert runtime.bind_run_catalog(catalog)
                    return await _with_state(state, **kw)
            assert runtime.bind_run_catalog(catalog)
            return await _with_state(state, **kw)

    before = lib.store.snapshot_counts()
    out = contextvars.Context().run(asyncio.run, go())
    assert lib.store.snapshot_counts() == before, "reading wrote to the store"
    return out


async def _with_state(state, **kw):
    if state is None:
        return await reader.lookup(**kw)
    with run_state.bound(state):
        out = await reader.lookup(**kw)
        state.update(run_state.drain())
        return out


def page_id(lib, rid, url, slug="wiki"):
    return f"{slug}:{lib.store.page_ids[(rid, url)]}"


def body(result):
    return result.split("\n---\n", 1)[1].rsplit("\n", 1)[0]


def section_line(result):
    return parse_read_section(header(result, "section").join(["section: ", ""]))


def test_args_compat():
    """The 1.x arguments still read: without a search index, today's title match; with one, the
    free first pass picks the page and the answer is one section."""
    lib = Library().add("r1", "wiki", WIKI, mode="stored", read_settings=no_browser())
    lib.entry("r1", UNION, PAGE).entry("r1", KERBEROAST, "kerberoast text")
    old = read(lib, resource_id="wiki", query="union based")
    assert header(old, "url") == UNION and header(old, "section_title") == "SQL injection: Union based"
    picked = read(lib, index=FirstPass([card_row(lib, "r1", UNION)]), resource_id="wiki", query="pg_sleep delay")
    assert header(picked, "page") == f"{page_id(lib, 'r1', UNION)} · wiki"
    assert section_line(picked)["section"] == "Time based"
    assert "pg_sleep" in body(picked) and "leak data" not in body(picked)
    # section_path, cve_id and force_refresh keep their meaning.
    forced = read(lib, index=FirstPass([]), resource_id="wiki", section_path=KERBEROAST)
    assert header(forced, "url") == KERBEROAST and "kerberoast text" in forced
    # A query the first pass does not find falls back to today's title match.
    fallback = read(lib, index=FirstPass([]), resource_id="wiki", query="kerberoasting")
    assert header(fallback, "url") == KERBEROAST


def test_section_read():
    lib = Library().add("r1", "wiki", WIKI, mode="stored", read_settings=no_browser())
    lib.entry("r1", UNION, PAGE)
    pid = page_id(lib, "r1", UNION)
    answer = read(lib, page=pid, section="time BASED")
    line = section_line(answer)
    assert line == {"section": "Time based", "part": 1, "parts": 1,
                    "others": ["(intro)", "Error based", "Stacked queries"]}
    assert body(answer).strip() == "Use pg_sleep for a delay on PostgreSQL."
    assert header(answer, "source") == "stored copy from 2026-11-10"
    by_query = read(lib, page=pid, query="several statements")
    assert section_line(by_query)["section"] == "Stacked queries"
    first = read(lib, page=pid)
    assert section_line(first)["section"] == "(intro)"
    missing = read(lib, page=pid, section="Out of band")
    assert missing.startswith("Error: page") and "Error based, Time based" in missing


def test_live_split():
    """A Live page is downloaded and split at read time; nothing is kept."""
    lib = Library().add("r1", "wiki", WIKI, read_settings=no_browser())
    lib.entry("r1", KERBEROAST, None)
    pid = page_id(lib, "r1", KERBEROAST)
    answer = read(lib, page=pid, section="How it works")
    assert header(answer, "source") == "live" and lib.requested() == [KERBEROAST]
    assert "The technique kerberoasting applies" in body(answer)
    assert "GetUserSPNs" not in body(answer)  # another section
    assert set(section_line(answer)["others"]) >= {"Kerberos: Kerberoasting", "Examples"}
    assert lib.store.sections == [] and lib.store.writes == 0


def test_chars_per_read():
    long_text = "## Big\n\n" + "\n\n".join(f"Paragraph {i} " + "x" * 480 for i in range(10))
    lib = Library().add("r1", "wiki", WIKI, mode="stored")
    lib.entry("r1", UNION, long_text)
    pid = page_id(lib, "r1", UNION)
    settings = {"reading.charsPerRead": 2000}
    first = read(lib, search=settings, page=pid, section="Big")
    assert section_line(first)["parts"] == 3 and len(body(first)) <= 2000
    assert header(first, "next") == f'tradecraft_lookup(page="{pid}", section="Big", part=2)'
    last = read(lib, search=settings, page=pid, section="Big", part=3)
    assert section_line(last)["part"] == 3 and header(last, "next") is None and "Paragraph 9" in body(last)
    assert read(lib, search=settings, page=pid, section="Big", part=9).startswith("Error: section 'Big'")
    # The default is 12,000 characters, and no setting reaches past 40,000.
    assert section_line(read(lib, page=pid, section="Big"))["parts"] == 1
    clamped = read(lib, search={"reading.charsPerRead": 10_000_000}, page=pid, section="Big")
    assert section_line(clamped)["parts"] == 1


def test_old_page_id_after_readd():
    lib = Library().add("r1", "wiki", WIKI, mode="stored")
    lib.entry("r1", UNION, PAGE)
    old = page_id(lib, "r1", UNION)
    lib.store.delete_resource("r1")
    lib.resources.clear()
    lib.add("r2", "wiki", WIKI, mode="stored")
    lib.store.page_ids[("r2", UNION)] = 5  # numbers only grow: the new copy's pages come later
    lib.entry("r2", UNION, PAGE)
    answer = read(lib, page=old)
    assert "the resource was added again" in answer and lib.requested() == []
    assert "Time based" in read(lib, page=page_id(lib, "r2", UNION), section="Time based")


def test_another_users_page_id_is_refused():
    lib = Library().add("r1", "wiki", WIKI, mode="stored")
    lib.entry("r1", UNION, PAGE)
    lib.store.resources["r1"]["user_id"] = "someone-else"
    assert read(lib, page=page_id(lib, "r1", UNION)).startswith("Error: page not found")


def test_code_blocks_whole():
    blocks = "\n\n".join(f"```sh\necho {i}\n{'# line ' * 3}\n```" for i in range(7))
    lib = Library().add("r1", "wiki", WIKI, mode="stored")
    lib.entry("r1", UNION, "## Code\n\n" + blocks)
    pid = page_id(lib, "r1", UNION)
    first = read(lib, page=pid, section="Code")
    assert section_line(first)["parts"] == 2 and body(first).count("```") == 10
    second = read(lib, page=pid, section="Code", part=2)
    assert body(second).count("```") == 4 and "echo 6" in body(second)
    big = "```\n" + "\n".join(f"line {i} of a long listing" for i in range(400)) + "\n```"
    pieces = split.parts("before\n\n" + big + "\n\nafter", 2000)
    assert any(p.startswith("```") and p.endswith("```") and len(p) > 2000 for p in pieces)
    assert all(p.count("```") % 2 == 0 for p in pieces)


def test_records_seen():
    lib = Library().add("r1", "wiki", WIKI, mode="stored")
    lib.entry("r1", UNION, PAGE).entry("r1", KERBEROAST, "k")
    state = {"session_id": "s1", "current_objective_index": 0}
    read(lib, state=state, page=page_id(lib, "r1", UNION))
    read(lib, state=state, page=page_id(lib, "r1", KERBEROAST))
    read(lib, state=state, page=page_id(lib, "r1", UNION), section="Error based")
    assert state["tradecraft_seen_pages"] == [page_id(lib, "r1", UNION), page_id(lib, "r1", KERBEROAST)]
    # A refused read is not a page returned.
    read(lib, state=state, page="wiki:999")
    assert len(state["tradecraft_seen_pages"]) == 2


def test_a_cve_archive_is_read_by_cve_id_not_page():
    lib = Library().add("r1", "cve", "https://github.com/tc-fixture/cve", type_="cve-poc-db", sitemap={})
    lib.entry("r1", "https://raw.githubusercontent.com/tc-fixture/cve/main/2024/CVE-2024-0001.md", "x")
    assert "cve_id" in read(lib, page=page_id(lib, "r1", "https://raw.githubusercontent.com/tc-fixture/cve/main/2024/"
                                                       "CVE-2024-0001.md", "cve"))


def test_a_page_removed_by_a_refresh():
    lib = Library().add("r1", "wiki", WIKI, mode="stored")
    lib.entry("r1", UNION, PAGE)
    pid = page_id(lib, "r1", UNION)
    lib.store.entries.clear()  # a refresh dropped the page; its number stays allocated
    assert read(lib, page=pid).startswith(f"Error: page {pid} is no longer in resource 'wiki'")
