"""Check URL in the agent (T4.1, §6.3, R-136, AC-09, R-082, R-146, D-52): what a URL is before
a resource is saved, with no model call and no write; the type (a forced one honoured), the
index ingestion would use (a sitemap named by robots.txt too, the GitHub tree with its branches,
tags and top folders, a PDF's pages), whether the page needs the browser and robots.txt allows
crawling, the recommended storage and an estimated size, a CVE archive's path pattern; every
URL it derives goes through the address guard like the start page; the call ends at its
deadline with ``timeout``.

The web is ``FixtureFetcher`` over a copy of the fixture sites (start pages carrying an article,
so they are not thin) plus files a test adds; no socket is opened.
"""

from __future__ import annotations

import ast
import asyncio
import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tradecraft import check_url as cu  # noqa: E402
from tradecraft import contract, jobs, net  # noqa: E402
from tradecraft.contract import CheckUrlRequest, CheckUrlResult  # noqa: E402
from tradecraft_doubles import FixtureFetcher, ScriptedChatModel, run  # noqa: E402
from tradecraft_memory_store import padded_sites  # noqa: E402

BLOG = "https://blog.tc-fixture.test/"
WIKI = "https://wiki.tc-fixture.test/"
DOCS = "https://docs.tc-fixture.test/"
BOOK = "https://book.tc-fixture.test/"
PAYLOADS = "https://github.com/tc-fixture/payloads"
CVE = "https://github.com/tc-fixture/cve"
PDF = "https://files.tc-fixture.test/guide.pdf"
TEXT = "Synthetic technique text about payloads and bypasses. " * 20


def req(url, **kw):
    return CheckUrlRequest(user_id="u1", url=url, **kw)


def check(root, url, fetcher=None, **kw):
    fetcher = fetcher or FixtureFetcher(root)
    with net.use_fetcher(fetcher):
        return run(cu.check_url(req(url, **kw)))


def add(root: Path, host: str, files: dict) -> Path:
    for path, text in files.items():
        target = root / host / path.lstrip("/")
        if path.endswith("/"):
            target = target / "index.html"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text if isinstance(text, str) else json.dumps(text), encoding="utf-8")
    return root


def page(title="Page", body=TEXT, links=()):
    anchors = "".join(f'<a href="{h}">{h}</a>' for h in links)
    return f"<html><head><title>{title}</title></head><body><main><article><p>{body}</p>{anchors}</article></main></body></html>"


def urlset(urls):
    return ('<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            + "".join(f"<url><loc>{u}</loc></url>" for u in urls) + "</urlset>")


@pytest.fixture
def sites(tmp_path):
    return padded_sites(tmp_path)


# --------------------------------------------------------------------------------------

def test_no_llm_no_write(sites):
    """AC-09: on every type, no model is built or called, nothing reaches the store, no crawl runs."""
    model = ScriptedChatModel()
    built, stores = [], []

    async def build_llm(owner, model_id):
        built.append(model_id)
        return model

    class NoStore:
        def __init__(self, *a, **kw):
            stores.append(1)
            raise AssertionError("Check URL opened the page store")

    async def no_crawl(*a, **kw):
        raise AssertionError("Check URL crawled")

    from tradecraft import models, store
    from tradecraft.ingest import crawl
    with patch.object(models, "build_ingest_llm", build_llm), patch.object(store, "Store", NoStore), \
            patch.object(crawl, "crawl", no_crawl), patch.object(crawl, "llm_decide", no_crawl):
        results = [check(sites, url) for url in (BLOG, WIKI, DOCS, BOOK, PAYLOADS, CVE, PDF)]
    assert all(r.ok for r in results)
    assert model.calls == 0 and built == [] and stores == []
    # The module cannot reach either: it imports no store, database or model builder.
    tree = ast.parse(Path(cu.__file__).read_text(encoding="utf-8"))
    imported = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    imported |= {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    assert not imported & {"tradecraft.store", "tradecraft.db", "tradecraft.models", "llm_builder", "psycopg"}


def test_detects_each_type_and_its_index(sites):
    expected = {
        WIKI: ("mkdocs-wiki", "sitemap"), DOCS: ("sphinx-docs", "searchindex"), BOOK: ("gitbook", "sitemap"),
        BLOG: ("agentic-crawl", "sitemap"), PAYLOADS: ("github-repo", "github_tree"), CVE: ("cve-poc-db", "none"),
        PDF: ("pdf", "pdf"),
    }
    for url, (site_type, index) in expected.items():
        r = check(sites, url)
        assert (r.detected_type, r.index.kind) == (site_type, index), url
        assert r.final_url and r.error_code == ""
        if index != "none":
            assert r.index.count > 0 and r.sample_entries, url
    pdf = check(sites, PDF)
    assert pdf.pdf_pages == 3 and pdf.index.count == 3 and [s.url.rsplit("#", 1)[1] for s in pdf.sample_entries] == [
        "page=1", "page=2", "page=3"]


def test_forced_type_is_honoured(sites):
    r = check(sites, WIKI, forced_type="agentic-crawl")
    assert r.detected_type == "agentic-crawl" and r.index.kind == "sitemap"
    assert check(sites, BLOG, forced_type="mkdocs-wiki").detected_type == "mkdocs-wiki"


def test_recommendation(sites):
    """§4.5: website, GitHub repository and PDF Stored; CVE archive Live; wiki, GitBook and docs
    Stored when they fit the per-resource limits, else Live."""
    assert check(sites, BLOG).recommended_storage == "stored"
    assert check(sites, PAYLOADS).recommended_storage == "stored"
    assert check(sites, PDF).recommended_storage == "stored"
    assert check(sites, CVE).recommended_storage == "live"
    wiki = check(sites, WIKI)
    assert wiki.recommended_storage == "stored" and 0 < wiki.estimated_bytes <= 50 * 1024 * 1024
    too_many = check(sites, WIKI, settings={"storage.maxPages": 5})
    assert too_many.index.count > 5 and too_many.recommended_storage == "live"
    for url in (DOCS, BOOK):
        assert check(sites, url).recommended_storage in ("stored", "live")


def test_estimated_size_from_three_samples(sites):
    host = "est.tc-fixture.test"
    urls = [f"https://{host}/notes/n{i}/" for i in range(40)]
    files = {"/": page("Home"), "/sitemap.xml": urlset(urls)}
    for i, u in enumerate(urls):
        files[u.split(host, 1)[1]] = page(f"N{i}", body="x" * 10_000)
    fetcher = FixtureFetcher(add(sites, host, files))
    r = check(sites, f"https://{host}/", fetcher)
    sampled = [u for u, _h in fetcher.requests if "/notes/" in u]
    assert len(sampled) == 3 and r.index.count == 40
    assert 40 * 10_000 <= r.estimated_bytes <= 40 * 10_200
    # Each sample counts at most the stored page limit.
    capped = check(sites, f"https://{host}/", settings={"storage.maxPageKb": 10})
    assert capped.estimated_bytes <= 40 * 10 * 1024


def test_github_metadata(sites):
    add(sites, "api.github.com", {
        "/repos/tc-fixture/payloads/branches/index.json": [{"name": "main"}, {"name": "dev"}],
        "/repos/tc-fixture/payloads/tags/index.json": [{"name": "v1.0"}, {"name": "v0.9"}],
    })
    r = check(sites, PAYLOADS)
    assert r.github.default_branch == "main" and r.github.branches == ["main", "dev"]
    assert r.github.tags == ["v1.0", "v0.9"]
    assert r.github.top_folders and set(r.github.top_folders) >= {"sqli", "xss", "rules"}
    assert r.index.kind == "github_tree" and r.index.url == PAYLOADS and r.index.count == len(r.sample_entries)
    assert all(s.url.startswith("https://raw.githubusercontent.com/tc-fixture/payloads/main/") for s in r.sample_entries)
    # No branch or tag list (the API answered 404): the default branch still comes back.
    cve = check(sites, CVE)
    assert cve.github.default_branch == "main" and cve.github.branches == [] and "2023" in cve.github.top_folders


def test_sitemap_from_robots(sites):
    host = "robots.tc-fixture.test"
    urls = [f"https://{host}/posts/p{i}/" for i in range(12)]
    add(sites, host, {"/": page("Home"), "/robots.txt": f"User-agent: *\nDisallow:\nSitemap: https://{host}/maps/posts.xml\n",
                      "/maps/posts.xml": urlset(urls), **{u.split(host, 1)[1]: page() for u in urls}})
    r = check(sites, f"https://{host}/")
    assert r.index.kind == "sitemap" and r.index.url == f"https://{host}/maps/posts.xml" and r.index.count == 12
    assert r.robots_allows is True
    # A wiki whose only sitemap is the one robots.txt names.
    wiki_host = "wiki2.tc-fixture.test"
    add(sites, wiki_host, {"/": '<html><head><meta name="generator" content="mkdocs-1.5"><title>W</title></head>'
                                f"<body><main><article><p>{TEXT}</p></article></main></body></html>",
                           "/robots.txt": f"Sitemap: https://{wiki_host}/en/sitemap.xml\n",
                           "/en/sitemap.xml": urlset([f"https://{wiki_host}/en/a/", f"https://{wiki_host}/en/b/"])})
    w = check(sites, f"https://{wiki_host}/")
    assert w.detected_type == "mkdocs-wiki" and w.index.kind == "sitemap" and w.index.count == 2
    assert w.index.url == f"https://{wiki_host}/en/sitemap.xml"


def test_robots_allows(sites):
    add(sites, "closed.tc-fixture.test", {"/": page(), "/robots.txt": "User-agent: *\nDisallow: /\n"})
    add(sites, "down5.tc-fixture.test", {"/": page(), "_status.json": {"/robots.txt": 503}})
    assert check(sites, "https://closed.tc-fixture.test/").robots_allows is False
    assert check(sites, "https://down5.tc-fixture.test/").robots_allows is False
    assert check(sites, BLOG).robots_allows is True  # it disallows /private/ only


def test_cve_pattern_probe(sites):
    """The fixture archive is laid out as {year}/{cve}.json: the probe finds it from the first
    year's listing; other layouts, and a README naming an id the archive lacks."""
    r = check(sites, CVE)
    assert r.detected_type == "cve-poc-db" and r.cve_pattern == "{year}/{cve}.json"

    def archive(name, files, readme="Archive."):
        listing = [{"name": "2024", "path": "2024", "type": "dir"},
                   {"name": "README.md", "path": "README.md", "type": "file",
                    "download_url": f"https://raw.githubusercontent.com/tc-fixture/{name}/main/README.md"}]
        add(sites, "api.github.com", {f"/repos/tc-fixture/{name}/index.json": {"default_branch": "main"},
                                      f"/repos/tc-fixture/{name}/contents/index.json": listing,
                                      f"/repos/tc-fixture/{name}/contents/2024/index.json": [
                                          {"name": "CVE-2024-1111", "type": "dir"}]})
        add(sites, "raw.githubusercontent.com", {f"/tc-fixture/{name}/main/README.md": readme,
                                                 **{f"/tc-fixture/{name}/main/{p}": "poc" for p in files}})
        add(sites, "github.com", {f"/tc-fixture/{name}/": page(name)})
        return check(sites, f"https://github.com/tc-fixture/{name}", forced_type="cve-poc-db")

    assert archive("dirs", ["2024/CVE-2024-1111/README.md"]).cve_pattern == "{year}/{cve}/README.md"
    assert archive("lower", ["2024/cve-2024-1111.md"]).cve_pattern == "{year}/{cve_lower}.md"
    # The README names CVE-2024-9999, which the archive lacks; the listing's id is still found.
    assert archive("readme", ["2024/CVE-2024-1111.md"], readme="See CVE-2024-9999.").cve_pattern == "{year}/{cve}.md"
    assert archive("none", []).cve_pattern is None


def test_needs_browser(sites):
    js = BLOG + "posts/42-js-only/"
    fetcher = FixtureFetcher(sites)
    r = check(sites, js, fetcher)
    assert r.ok and r.needs_browser is True and fetcher.browser.renders == [js]
    assert check(sites, WIKI).needs_browser is False
    off = FixtureFetcher(sites)
    assert check(sites, js, off, settings={"fetching.browserEnabled": False}).needs_browser is True
    assert off.browser.renders == []
    # A resource with a login never goes to the browser (§5); Check URL still says it would need it.
    login = FixtureFetcher(sites)
    r = check(sites, js, login, secrets={"credentials": {"cookie": "cookie=fake-session"}})
    assert r.needs_browser is True and login.browser.renders == []


def test_index_url_to_private_address_refused(sites):
    """A sitemap named by robots.txt, a sitemap index's child, a redirect and a GitHub README's
    download_url that point at internal addresses are refused like the start page."""
    host = "sneaky.tc-fixture.test"
    add(sites, host, {
        "/": page("Home"),
        "/robots.txt": "Sitemap: http://169.254.169.254/latest/sitemap.xml\nSitemap: https://sneaky.tc-fixture.test/index.xml\n"
                       "Sitemap: https://sneaky.tc-fixture.test/moved.xml\n",
        "/index.xml": '<?xml version="1.0"?><sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                      "<sitemap><loc>http://10.0.0.5/child.xml</loc></sitemap></sitemapindex>",
        "_redirects.json": {"/moved.xml": "http://127.0.0.1/sitemap.xml"},
    })
    fetcher = FixtureFetcher(sites)
    r = check(sites, f"https://{host}/", fetcher)
    assert r.ok and r.index.kind == "none" and r.sample_entries == []
    hosts = {u.split("/")[2] for u, _h in fetcher.requests}
    assert not hosts & {"169.254.169.254", "10.0.0.5", "127.0.0.1"}

    listing = [{"name": "2024", "path": "2024", "type": "dir"},
               {"name": "README.md", "type": "file", "download_url": "http://169.254.169.254/latest/meta-data/"}]
    add(sites, "api.github.com", {"/repos/tc-fixture/evil/index.json": {"default_branch": "main"},
                                  "/repos/tc-fixture/evil/contents/index.json": listing,
                                  "/repos/tc-fixture/evil/contents/2024/index.json": []})
    add(sites, "github.com", {"/tc-fixture/evil/": page("evil")})
    fetcher = FixtureFetcher(sites)
    r = check(sites, "https://github.com/tc-fixture/evil", fetcher, forced_type="cve-poc-db")
    assert r.ok and r.cve_pattern is None
    assert not any("169.254" in u for u, _h in fetcher.requests)
    # The start page itself: refused before anything else is read.
    blocked = FixtureFetcher(sites)
    r = check(sites, "http://169.254.169.254/", blocked)
    assert not r.ok and r.error_code == "blocked_private_address" and blocked.requests == []


@pytest.mark.parametrize("url, code", [("ftp://wiki.tc-fixture.test/", "bad_url"),
                                       ("https://user:pw@wiki.tc-fixture.test/", "userinfo_refused")])
def test_url_refused_before_any_request(sites, url, code):
    fetcher = FixtureFetcher(sites)
    r = check(sites, url, fetcher)
    assert r == CheckUrlResult(ok=False, error_code=code) and fetcher.requests == []


def test_unreachable_and_http_error(sites):
    assert check(sites, "https://down.tc-fixture.test/").error_code == "fetch_failed"
    add(sites, "err.tc-fixture.test", {"/": page(), "_status.json": {"/": 500}})
    assert check(sites, "https://err.tc-fixture.test/").error_code == "homepage_http_error"


def test_deadline(sites, monkeypatch):
    """D-52: the route ends the call at the contract's deadline with ``timeout``."""
    from tradecraft import api

    class Hanging(FixtureFetcher):
        async def get(self, url, **kw):
            await asyncio.Event().wait()

    monkeypatch.setitem(contract.DEADLINES_SEC, "check_url", 0.05)
    assert api.DEADLINES_SEC is contract.DEADLINES_SEC
    monkeypatch.setattr(jobs, "default_fetcher", lambda: Hanging(sites))
    answer = run(api.check_url(req(WIKI)))
    assert answer == {**CheckUrlResult(ok=False, error_code="timeout").model_dump()}
    assert contract.DEADLINES_SEC["check_url"] == 0.05


class _NoFetcher:
    """The context's default fetcher in the route tests: a route that reads it fails loudly."""

    async def get(self, url, **kw):
        raise AssertionError("the route used the context's default fetcher")

    async def render(self, url, **kw):
        raise AssertionError("the route used the context's default fetcher")


def test_the_route_reads_with_a_browser(sites, monkeypatch):
    """Review finding 1: the route binds the jobs' fetcher, whose browser goes through the
    agent's MCP manager; net's module default has no browser at all."""
    import contextvars

    from tradecraft import api

    js = BLOG + "posts/42-js-only/"
    used = []

    def route_fetcher():
        used.append(FixtureFetcher(sites))
        return used[-1]

    monkeypatch.setattr(net, "_current", contextvars.ContextVar("tradecraft_fetcher", default=_NoFetcher()))
    monkeypatch.setattr(jobs, "default_fetcher", route_fetcher)
    answer = run(api.check_url(req(js, settings={"fetching.alwaysBrowser": True})))
    assert answer["ok"] is True and answer["needs_browser"] is True
    assert len(used) == 1 and used[0].browser.renders == [js] and used[0].requests  # robots.txt, plain GETs
    detected = run(api.check_url(req(js)))
    assert detected["ok"] is True and used[1].browser.renders == [js]


def test_the_jobs_fetcher_renders_through_the_agents_browser(monkeypatch):
    """The fetcher the route and the jobs bind holds the agent's MCP manager: its render runs
    the guarded script in the sandbox (net's module default answers browser_unavailable)."""
    import types
    from unittest.mock import patch

    from orchestrator_helpers import fetch_guard
    from tradecraft_doubles import RecordingMcp

    mcp = RecordingMcp(reply="<html><body>rendered by the sandbox</body></html>")
    monkeypatch.setitem(sys.modules, "api", types.SimpleNamespace(orchestrator=types.SimpleNamespace(_mcp_manager=mcp)))
    with patch.object(fetch_guard, "_resolve_ips", lambda _host: ["93.184.216.34"]):
        rendered = run(jobs.default_fetcher().render(WIKI, clean=True))
        default = run(net.GuardedFetcher().render(WIKI))
    assert rendered.error == "" and "rendered by the sandbox" in rendered.html and len(mcp.calls) == 1
    assert default.error == "browser_unavailable"
