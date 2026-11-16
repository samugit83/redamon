"""Forced types and the type-specific options (T4.2, §6.5; R-144, R-145, R-147, R-148, R-149,
AC-06, AC-07): a forced type skips detection; a GitHub repository's branch or tag, folders in
and out, file types and one entry per README folder; a wiki's and a GitBook's sitemap URLs
(and the robots.txt line), language and size; a docs site's search index; a PDF's page range,
skipped pages and chapters from its bookmarks.

Jobs run through the pipeline on ``MemoryStore`` over a copy of the fixture sites
(``FixtureFetcher``); the model is scripted.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tradecraft import net  # noqa: E402
from tradecraft.contract import JobContext, JobStartRequest  # noqa: E402
from tradecraft.ingest import builders, pipeline  # noqa: E402
from tradecraft.settings import EffectiveSettings  # noqa: E402
from tradecraft_doubles import FixtureFetcher, run  # noqa: E402
from tradecraft_memory_store import MemoryStore, PipelineModel, padded_sites  # noqa: E402

FIXTURE = json.loads((Path(__file__).resolve().parent / "fixtures" / "tradecraft_contract" /
                      "JobStartBatch.valid.json").read_text())["jobs"][0]
OWNER, RID = "u1", "r1"
WIKI = "https://wiki.tc-fixture.test/"
BLOG = "https://blog.tc-fixture.test/"
PAYLOADS = "https://github.com/tc-fixture/payloads"
PDF = "https://files.tc-fixture.test/guide.pdf"
TEXT = "Synthetic technique text about payloads and bypasses. " * 20


def job(root, url, settings=None, *, forced_type="", mode="live"):
    """Runs one job; returns (store, outcome, state after the map was built)."""
    store = MemoryStore()
    spec = json.loads(json.dumps(FIXTURE))
    spec.update(job_id="j1", user_id=OWNER, actor_user_id=OWNER, resource_id=RID, settings=dict(settings or {}))
    spec["resource"].update(url=url, storage_mode=mode, model="openai/fake-small-model", forced_type=forced_type)
    spec["secrets"] = {"github_token": None, "credentials": None}
    req = JobStartRequest.model_validate(spec)
    store.add_resource(OWNER, RID, url=url, storage_mode=mode, generation=0)
    store.add_job(OWNER, RID, "j1", status="running")
    store.jobs["j1"]["target_generation"] = 1

    async def build_llm(owner, model):
        return PipelineModel()

    async def no(*_a):
        return False

    seen = {}
    original = pipeline.build_map

    async def keep(state):
        await original(state)
        seen["state"] = state

    ctx = JobContext(request=req, settings=EffectiveSettings(req.settings), target_generation=1, is_cancelled=no,
                     set_stage=no)
    with patch.object(pipeline, "build_map", keep), net.use_fetcher(FixtureFetcher(root)):
        outcome = asyncio.run(pipeline.run(ctx, store=store, build_llm=build_llm))
    return store, outcome, seen.get("state")


def paths(state):
    return [e.path for e in state.entries]


def add(root: Path, host: str, files: dict) -> Path:
    for path, text in files.items():
        target = root / host / path.lstrip("/")
        if path.endswith("/"):
            target = target / "index.html"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text if isinstance(text, str) else json.dumps(text), encoding="utf-8")
    return root


def urlset(urls):
    return ('<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            + "".join(f"<url><loc>{u}</loc></url>" for u in urls) + "</urlset>")


def mkdocs_home(host):
    return (f'<html><head><title>{host}</title><meta name="generator" content="mkdocs-1.5"></head>'
            f"<body><main><article><p>{TEXT}</p></article></main></body></html>")


# --------------------------------------------------------------------------------------

def test_forced_type_skips_detection(tmp_path):
    """AC-07: with a forced type the detector never runs, whatever the page looks like."""
    root = padded_sites(tmp_path)

    def no_detect(*_a, **_k):
        raise AssertionError("detection ran for a forced type")

    with patch.object(pipeline, "detect", no_detect):
        _store, outcome, state = job(root, WIKI, {"crawl.minTextChars": 0}, forced_type="agentic-crawl")
        assert outcome.status == "succeeded" and state.site_type == "agentic-crawl" and state.crawl is not None
        _store, _o, state = job(root, BLOG, forced_type="mkdocs-wiki")
        assert state.site_type == "mkdocs-wiki" and state.index_kind == "sitemap"
        # Even a start page too thin to classify keeps the forced type.
        _store, _o, state = job(FixtureFetcher().site.root, WIKI, forced_type="mkdocs-wiki")
        assert state.home_problem == "thin_homepage" and state.site_type == "mkdocs-wiki"
    # Without a forced type the same wiki is detected (the detector does run).
    _store, _o, state = job(root, WIKI)
    assert state.site_type == "mkdocs-wiki"


def test_a_forced_cve_archive_is_never_retyped(tmp_path):
    """Review finding 2 (R-144, R-193): a forced CVE archive with no year folder at its root
    (its files under http/cves/{year}/) is ingested as a CVE archive, not as a 5,000-entry
    file tree; detected, the same repository is a plain repository."""
    root = padded_sites(tmp_path)
    add(root, "api.github.com", {
        "/repos/tc-fixture/nested/index.json": {"default_branch": "main"},
        "/repos/tc-fixture/nested/contents/index.json": [{"name": "http", "path": "http", "type": "dir"}],
        "/repos/tc-fixture/nested/git/trees/main/index.json": {"tree": [
            {"path": "http/cves/2023/CVE-2023-1234.md", "type": "blob"}, {"path": "README.md", "type": "blob"}]},
    })
    add(root, "github.com", {"/tc-fixture/nested/": f"<html><body><article>{TEXT}</article></body></html>"})
    url = "https://github.com/tc-fixture/nested"
    store, outcome, state = job(root, url, {"type.cve.pathPatterns": ["http/cves/{year}/{cve}.md"]},
                                forced_type="cve-poc-db")
    assert outcome.status == "succeeded" and state.site_type == "cve-poc-db" and state.entries == []
    assert store.resources[RID]["resource_type"] == "cve-poc-db"
    assert store.resources[RID]["sitemap"] == {"owner": "tc-fixture", "repo": "nested", "branch": "main"}
    _s, _o, detected = job(root, url, {"detection.cveArchiveThreshold": 5}, forced_type="")
    assert detected.site_type == "github-repo"
    _s, _o, retyped = job(root, url)
    assert retyped.site_type == "github-repo" and len(retyped.entries) == 2


def test_github_options(tmp_path):
    root = padded_sites(tmp_path)
    tree = json.loads((root / "api.github.com/repos/tc-fixture/payloads/git/trees/main/index.json").read_text())
    add(root, "api.github.com", {"/repos/tc-fixture/payloads/git/trees/v1.0/index.json": tree})
    tagged = builders.build_github(PAYLOADS, EffectiveSettings({"type.github.branch": "v1.0"}))
    with net.use_fetcher(FixtureFetcher(root)):
        result = run(tagged)
    assert result.meta["branch"] == "v1.0" and result.entries
    assert all(e.url.startswith("https://raw.githubusercontent.com/tc-fixture/payloads/v1.0/") for e in result.entries)

    _s, _o, state = job(root, PAYLOADS, {"type.github.includeFolders": ["sqli", "xss/"],
                                         "type.github.excludeFolders": ["xss"]})
    assert paths(state) == ["sqli/README.md", "sqli/blind.md", "sqli/union.md"]
    _s, _o, state = job(root, PAYLOADS, {"knownTypes.githubFileTypes": [".yml", ".yar"]})
    assert paths(state) == ["recon/subdomains.yml", "rules/webshell.yar", "xss/filters.yml"]
    _s, _o, state = job(root, PAYLOADS, {"type.github.folderEntries": True})
    assert paths(state) == ["README.md", "rules/README.md", "sqli/README.md", "ssrf/README.md", "xss/README.md"]
    assert [e.title for e in state.entries][1:] == ["rules", "sqli", "ssrf", "xss"]
    _s, _o, state = job(root, PAYLOADS, {"type.github.folderEntries": True, "knownTypes.maxMapEntries.github": 100,
                                         "knownTypes.githubFileTypes": [".md", ".yml"]})
    assert "recon/subdomains.yml" in paths(state) and "xss/filters.yml" not in paths(state)


def test_folder_entries():
    files = ["top.md", "a/README.md", "a/x.md", "a/b/README.md", "a/b/y.md", "a/c/z.md", "d/w.md", "d/e/readme.rst"]
    assert builders.folder_entries(files) == ["top.md", "a/README.md", "a/b/README.md", "d/w.md", "d/e/readme.rst"]
    assert builders.folder_entries([]) == []


def test_wiki_options(tmp_path):
    host = "kb.tc-fixture.test"
    root = add(tmp_path, host, {
        "/": mkdocs_home(host),
        "/sitemap.xml": urlset([f"https://{host}/root-{i}/" for i in range(3)]),
        "/maps/main.xml": urlset([f"https://{host}/{lang}/p{i}/" for i in range(10) for lang in ("en", "fr")]),
        "/robots.txt": f"Sitemap: https://{host}/maps/main.xml\n",
    })
    # robots.txt names a sitemap: it is read before the one at the root.
    _s, _o, state = job(root, f"https://{host}/")
    assert state.index_kind == "sitemap" and len(state.entries) == 10 and all("/en/" in e.url for e in state.entries)
    # The resource's own sitemap URL replaces the root one; the robots line is still read.
    add(root, host, {"/maps/extra.xml": urlset([f"https://{host}/extra/{i}/" for i in range(4)]), "/robots.txt": ""})
    _s, _o, state = job(root, f"https://{host}/", {"type.wiki.sitemapUrls": ["/maps/extra.xml"]})
    assert [e.url for e in state.entries] == [f"https://{host}/extra/{i}/" for i in range(4)]
    _s, _o, state = job(root, f"https://{host}/", {"type.wiki.sitemapUrls": ["/maps/missing.xml"]})
    assert state.index_kind != "sitemap"  # no root sitemap fallback once the resource names its own
    # Language overridden for this resource, and its own size.
    add(root, host, {"/robots.txt": f"Sitemap: https://{host}/maps/main.xml\n"})
    _s, _o, state = job(root, f"https://{host}/", {"knownTypes.language": "preferred", "knownTypes.preferredLanguage": "fr"})
    assert len(state.entries) == 10 and all("/fr/" in e.url for e in state.entries)
    _s, _o, state = job(root, f"https://{host}/", {"knownTypes.language": "all"})
    assert len(state.entries) == 20
    # A GitBook reads the same way.
    book = "book2.tc-fixture.test"
    add(root, book, {"/": f'<html><head><meta name="generator" content="GitBook"><title>B</title></head><body>{TEXT}</body></html>',
                     "/robots.txt": f"Sitemap: https://{book}/s.xml\n", "/s.xml": urlset([f"https://{book}/a/", f"https://{book}/b/"])})
    _s, _o, state = job(root, f"https://{book}/")
    assert state.site_type == "gitbook" and [e.url for e in state.entries] == [f"https://{book}/a/", f"https://{book}/b/"]


def test_docs_options(tmp_path):
    host = "docs2.tc-fixture.test"
    index = json.dumps({"docnames": ["intro", "usage", "api"], "titles": ["Intro", "Usage", "API"]})
    root = add(tmp_path, host, {
        "/": '<html><head><meta name="generator" content="Docutils 0.20"><title>D</title></head>'
             f"<body><main><p>{TEXT}</p></main></body></html>",
        "/en/latest/searchindex.js": f"Search.setIndex({index})",
    })
    _s, _o, state = job(root, f"https://{host}/")
    assert state.site_type == "sphinx-docs" and state.index_kind == "none"  # nothing at the root
    _s, _o, state = job(root, f"https://{host}/", {"type.docs.searchIndexUrl": "/en/latest/searchindex.js"})
    assert [e.title for e in state.entries] == ["Intro", "Usage", "API"] and state.index_kind == "searchindex"


def test_pdf_options(tmp_path):
    root = padded_sites(tmp_path)
    _s, _o, state = job(root, PDF)
    assert [e.extra["page"] for e in state.entries] == [1, 2, 3]
    _s, _o, state = job(root, PDF, {"type.pdf.firstPage": 2, "type.pdf.lastPage": 3})
    assert [e.extra["page"] for e in state.entries] == [2, 3]
    _s, _o, state = job(root, PDF, {"type.pdf.skipPages": "1, 3"})
    assert [e.extra["page"] for e in state.entries] == [2]
    # Chapters from the bookmarks: one entry per top-level bookmark, titled by it.
    store, outcome, state = job(root, PDF, {"type.pdf.mapBy": "chapters"}, mode="stored")
    assert outcome.status == "succeeded"
    assert [(e.extra["page"], e.title) for e in state.entries] == [(1, "1 Introduction"), (2, "2 SQL injection"),
                                                                     (3, "3 Kerberos")]
    assert store.resources[RID]["sitemap"]["pages"] == [{"page": 1, "firstLine": "1 Introduction"},
                                                       {"page": 2, "firstLine": "2 SQL injection"},
                                                       {"page": 3, "firstLine": "3 Kerberos"}]
    with_range = job(root, PDF, {"type.pdf.mapBy": "chapters", "type.pdf.firstPage": 2})[2]
    assert [e.title for e in with_range.entries] == ["2 SQL injection", "3 Kerberos"]
    skipped = job(root, PDF, {"type.pdf.mapBy": "chapters", "type.pdf.skipPages": "2"})[2]
    assert [e.title for e in skipped.entries] == ["1 Introduction", "3 Kerberos"]


def _book_pdf() -> bytes:
    """A four-page PDF: a cover, chapter A over two pages, chapter B; bookmark titles differ
    from the pages' first lines. Written by the fixture generator's own PDF writer."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "tc_make_fixtures", Path(__file__).resolve().parent / "fixtures" / "tradecraft_sites" / "make_fixtures.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.PDF_PAGES = [("Cover", ["A synthetic book."]), ("A first page", ["Alpha one."]),
                     ("A second page", ["Alpha two."]), ("B only page", ["Beta."])]
    mod.PDF_OUTLINE = [("Chapter A", 1, [("A.1", 2)]), ("Chapter B", 3, [])]
    return mod.make_pdf()


def test_pdf_chapters_from_bookmarks(tmp_path):
    root = padded_sites(tmp_path)
    (root / "files.tc-fixture.test" / "book.pdf").write_bytes(_book_pdf())
    url = "https://files.tc-fixture.test/book.pdf"
    _s, _o, pages = job(root, url)
    assert [e.title for e in pages.entries] == ["Cover", "A first page", "A second page", "B only page"]
    store, outcome, state = job(root, url, {"type.pdf.mapBy": "chapters"}, mode="stored")
    assert outcome.status == "succeeded"
    assert [(e.extra["page"], e.title) for e in state.entries] == [(1, "Cover"), (2, "Chapter A"), (4, "Chapter B")]
    stored = {e["url"].rsplit("#", 1)[1]: e["stored_text"] for e in store.live_entries(RID)}
    assert "Alpha one." in stored["page=2"] and "Alpha two." in stored["page=2"] and "Beta." not in stored["page=2"]
    assert store.resources[RID]["sitemap"]["pages"][1] == {"page": 2, "firstLine": "Chapter A"}
    # A range that starts inside chapter A keeps the rest of it under its bookmark.
    _s, _o, ranged = job(root, url, {"type.pdf.mapBy": "chapters", "type.pdf.firstPage": 3})
    assert [(e.extra["page"], e.title) for e in ranged.entries] == [(3, "Chapter A"), (4, "Chapter B")]


def test_pdf_chapters_hold_their_pages():
    """A chapter's text is every page from its bookmark to the next one; pages before the first
    bookmark keep an entry of their own; no bookmarks means one entry per page."""

    class Page:
        def __init__(self, text):
            self.text = text

        def extract_text(self):
            return self.text

    class Item:
        def __init__(self, title, page):
            self.title, self.page = title, page

    class Reader:
        def __init__(self, pages, outline):
            self.pages = [Page(t) for t in pages]
            self.outline = outline

        def get_destination_page_number(self, item):
            return item.page

    reader = Reader(["cover", "one-a", "one-b", "two"], [Item("One", 1), [Item("One.1", 2)], Item("Two", 3)])
    pages = builders._pages(reader, 4, EffectiveSettings({}))
    chapters = builders._chapters(reader, pages)
    assert [(c["page"], c["first_line"], c["text"]) for c in chapters] == [
        (1, "cover", "cover"), (2, "One", "one-a\n\none-b"), (4, "Two", "two")]
    assert builders._chapters(Reader(["a"], []), builders._pages(Reader(["a"], []), 1, EffectiveSettings({}))) == []


def test_no_rule_breaking_entry(tmp_path):
    """AC-06 for a repository: no entry lies outside the included folders or inside an
    excluded one, with or without one entry per folder."""
    root = padded_sites(tmp_path)
    for by_folder in (False, True):
        _s, _o, state = job(root, PAYLOADS, {"type.github.includeFolders": ["sqli", "ssrf", "xss"],
                                             "type.github.excludeFolders": ["ssrf/"],
                                             "type.github.folderEntries": by_folder,
                                             "knownTypes.githubFileTypes": [".md", ".yml", ".yar"]})
        assert state.entries
        for p in paths(state):
            assert p.split("/")[0] in ("sqli", "xss") and not p.startswith("ssrf/"), (by_folder, p)
