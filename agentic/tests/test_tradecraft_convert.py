"""The conversion of 1.x resources (T9.1, §7.2): every 1.x map shape becomes entries without a
download, the resources that need it are found by version and map hash (D-26), and the cards are
title-only. The database half (claims, idempotence, the PDF's job, the read after conversion) is
``test_tradecraft_convert_integration.py``.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tradecraft import convert  # noqa: E402
from tradecraft.ingest import legacy_map  # noqa: E402
from tradecraft.ingest.builders import Candidate  # noqa: E402


def test_nav_map_converts():
    site, entries = convert.legacy_candidates(
        "mkdocs-wiki", "https://wiki.tc-fixture.test/",
        {"nav": [{"title": "SQL Injection", "path": "sqli/basics/"}, {"title": "", "path": "/xss/"},
                 {"title": "External", "path": "https://other.tc-fixture.test/x"}]})
    assert site == "mkdocs-wiki"
    assert [e.url for e in entries] == ["https://wiki.tc-fixture.test/sqli/basics/", "https://wiki.tc-fixture.test/xss/",
                                        "https://other.tc-fixture.test/x"]
    assert [e.title for e in entries] == ["SQL Injection", "/xss/", "External"]
    assert {e.source for e in entries} == {"legacy"}
    assert entries[0].path == "sqli/basics/"


def test_sphinx_nav_gets_html_like_1x():
    _site, entries = convert.legacy_candidates("sphinx-docs", "https://docs.tc-fixture.test/en/",
                                               {"nav": [{"title": "Intro", "path": "intro"}], "indexUrl": "x"})
    assert entries[0].url == "https://docs.tc-fixture.test/en/intro.html"


def test_tree_map_converts_to_raw_files_on_the_branch():
    site, entries = convert.legacy_candidates(
        "github-repo", "https://github.com/acme/payloads",
        {"tree": [{"title": "SQL Injection > MySQL", "path": "SQL Injection/MySQL.md"},
                  {"title": "XSS", "path": "XSS"}], "owner": "acme", "repo": "payloads", "branch": "dev"})
    assert site == "github-repo"
    assert entries[0].url == "https://raw.githubusercontent.com/acme/payloads/dev/SQL%20Injection/MySQL.md"
    # A folder path is read through its README, as 1.x reads it.
    assert entries[1].url == "https://raw.githubusercontent.com/acme/payloads/dev/XSS/README.md"


def test_links_map_converts():
    site, entries = convert.legacy_candidates("agentic-crawl", "https://blog.tc-fixture.test/",
                                              {"links": [{"title": "Post", "path": "posts/1"}]})
    assert site == "agentic-crawl"
    assert [e.url for e in entries] == ["https://blog.tc-fixture.test/posts/1"]


def test_pdf_pages_convert_with_their_first_lines():
    site, entries = convert.legacy_candidates(
        "agentic-crawl", "https://files.tc-fixture.test/guide.pdf",
        {"pages": [{"page": 2, "firstLine": "  Kerberos   roasting "}, {"page": 5, "firstLine": ""},
                   {"page": 0}, {"page": "3"}, {"page": True}, "junk"]})
    assert site == "pdf"
    assert [e.url for e in entries] == ["https://files.tc-fixture.test/guide.pdf#page=2",
                                        "https://files.tc-fixture.test/guide.pdf#page=5"]
    assert [e.title for e in entries] == ["Kerberos roasting", "Page 5"]
    assert entries[0].extra == {"page": 2, "first_line": "Kerberos roasting"}


def test_cve_metadata_has_no_entry():
    site, entries = convert.legacy_candidates("cve-poc-db", "https://github.com/acme/cves",
                                              {"owner": "acme", "repo": "cves", "branch": "main"})
    assert (site, entries) == ("cve-poc-db", [])


def test_empty_map_keeps_the_start_page_1x_read():
    site, entries = convert.legacy_candidates("agentic-crawl", "https://Blog.TC-fixture.test:443/start", {})
    assert site == "agentic-crawl"
    assert [(e.url, e.title) for e in entries] == [("https://blog.tc-fixture.test/start", "blog.tc-fixture.test (homepage)")]


def test_duplicates_bad_urls_and_unknown_types():
    site, entries = convert.legacy_candidates(
        "something-else", "https://wiki.tc-fixture.test/",
        {"nav": [{"title": "A", "path": "a"}, {"title": "A again", "path": "/a"}, {"title": "Too long", "path": "https://wiki.tc-fixture.test/" + "x" * 3000},
                 "not an entry"]})
    assert site == "agentic-crawl"
    assert [e.title for e in entries] == ["A"]


def test_needs_conversion():
    sitemap = {"nav": [{"title": "A", "path": "a"}]}
    assert convert.needs_conversion({"map_version": 1, "sitemap": sitemap, "legacy_map_hash": ""})
    current = legacy_map.map_hash(sitemap)
    assert not convert.needs_conversion({"map_version": 2, "sitemap": sitemap, "legacy_map_hash": current})
    assert not convert.needs_conversion({"map_version": 3, "sitemap": sitemap, "legacy_map_hash": current})
    # A 1.x refresh made while the switch was off (D-26).
    changed = {"nav": [{"title": "A", "path": "a"}, {"title": "B", "path": "b"}]}
    assert convert.needs_conversion({"map_version": 3, "sitemap": changed, "legacy_map_hash": current})


def test_title_cards_are_title_only():
    state = SimpleNamespace(site_type="github-repo", url="https://github.com/acme/payloads", entries=[
        Candidate("https://raw.githubusercontent.com/acme/payloads/main/SQL%20Injection/MySQL.md", "MySQL", "legacy",
                  "SQL Injection/MySQL.md"),
        Candidate("https://raw.githubusercontent.com/acme/payloads/main/Pinned.md", "Pinned", "pin",
                  "https://raw.githubusercontent.com/acme/payloads/main/Pinned.md", {"pinned": True})])
    cards = convert.title_cards(state)
    assert cards[0] == {"url": state.entries[0].url, "title": "MySQL", "title_source": "guessed", "source": "legacy",
                        "status": "kept", "drop_reason": "", "breadcrumb": ["SQL Injection"]}
    assert cards[1]["source"] == "pin"
    assert not any(k in c for c in cards for k in ("headings", "description", "stored_text"))


def test_no_model_and_no_page_range_in_a_conversion():
    assert convert._NO_MODEL == {"focus.tagEveryPage": "rules"}
    assert convert._EVERY_PAGE["type.pdf.mapBy"] == "pages"


def test_convert_user_asks_this_copys_runner(monkeypatch):
    from tradecraft import jobs

    seen = []

    async def fake_start(runner, user_id):
        seen.append((runner, user_id))
        return 3

    runner = jobs.JobRunner(store=object())
    monkeypatch.setattr(jobs, "get_runner", lambda: runner)
    monkeypatch.setattr(convert, "start", fake_start)
    assert asyncio.run(convert.convert_user("u1")) == 3
    assert seen == [(runner, "u1")]


def test_the_sweep_never_raises(monkeypatch):
    async def broken(_store):
        raise RuntimeError("no database")

    monkeypatch.setattr(convert, "sweep_users", broken)
    assert asyncio.run(convert.boot_sweep(SimpleNamespace(store=None))) == 0


def test_every_statement_but_the_sweep_is_keyed_by_the_owner():
    for name, sql in convert.STATEMENTS.items():
        if name in convert.UNKEYED_STATEMENTS or name == "lock_account":
            continue
        # An insert names the owner as its user_id value.
        assert ("user_id = %(uid)s" in sql) or (sql.startswith("INSERT") and "%(uid)s" in sql), name
