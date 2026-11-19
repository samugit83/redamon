"""A website resource's own fields and its fetching overrides (T4.3, §6.5 "Website (crawl)", §6.7;
R-150, R-162): extra start pages on the same site, the sitemap Auto reads first, pagination
followed, "always use the browser" (never with a login, §5) and "wait for element".

Sites are written into a temporary folder and served by ``FixtureFetcher``; the clock is
``FakeClock``; the model is scripted and raises when a test did not expect a call.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tradecraft import check_url, clock, net  # noqa: E402
from tradecraft.contract import CheckUrlRequest, Credentials, JobContext, JobStartRequest, Secrets  # noqa: E402
from tradecraft.ingest import crawl as c  # noqa: E402
from tradecraft.ingest import fetch, storage  # noqa: E402
from tradecraft.ingest.builders import Candidate  # noqa: E402
from tradecraft.ingest.pipeline import IngestState  # noqa: E402
from tradecraft.settings import EffectiveSettings  # noqa: E402
from tradecraft_doubles import FakeClock, FixtureFetcher, ScriptedChatModel, run  # noqa: E402
from tradecraft_memory_store import MemoryStore  # noqa: E402

HOST = "site.tc-fixture.test"
SITE = f"https://{HOST}"
TEXT = "Synthetic technique text for the website fields. " * 20
JS_ONLY = "https://blog.tc-fixture.test/posts/42-js-only/"


def s(**values):
    return EffectiveSettings(values)


def html(title, links=(), body=TEXT):
    anchors = "".join(f'<a href="{h}">{h}</a>' for h in links)
    return f"<html><head><title>{title}</title></head><body><main><article><p>{body}</p>{anchors}</article></main></body></html>"


def write(root: Path, host: str, files: dict) -> Path:
    for path, text in files.items():
        target = root / host / path.lstrip("/")
        if path.endswith("/"):
            target = target / "index.html"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    return root


def urlset(urls):
    return ('<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            + "".join(f"<url><loc>{u}</loc></url>" for u in urls) + "</urlset>")


def go(url, settings, fetcher, **kw):
    with clock.use_clock(FakeClock()), net.use_fetcher(fetcher):
        return run(c.crawl(url, settings, **kw))


# --------------------------------------------------------------------------------------

def test_start_pages(tmp_path):
    root = write(tmp_path, HOST, {
        "/": html("Home"),
        "/blog/": html("Blog", [f"{SITE}/blog/a/"]), "/blog/a/": html("A"),
        "/research/": html("Research", [f"{SITE}/research/b/"]), "/research/b/": html("B"),
    })
    write(root, f"www.{HOST}", {"/w/": html("W")})
    write(root, "other.tc-fixture.test", {"/x/": html("X")})
    fields = {"crawl.strategy": "rules", "type.website.startPages": [
        "/blog/", f"{SITE}/research/", "https://other.tc-fixture.test/x/", f"https://www.{HOST}/w/", "/blog/"]}
    fetcher = FixtureFetcher(root)
    result = go(SITE + "/", s(**fields), fetcher)
    urls = [e.url for e in result.entries]
    assert urls[:4] == [SITE + "/", SITE + "/blog/", SITE + "/research/", f"https://www.{HOST}/w/"]
    assert set(urls) == {SITE + "/", SITE + "/blog/", SITE + "/research/", f"https://www.{HOST}/w/",
                         SITE + "/blog/a/", SITE + "/research/b/"}
    # Another site is never a start page, and is never requested.
    assert not any("other.tc-fixture.test" in u for u, _h in fetcher.requests)
    assert c.start_pages(SITE + "/", s(**fields)) == [SITE + "/", SITE + "/blog/", SITE + "/research/",
                                                       f"https://www.{HOST}/w/"]
    # The starting folder is each start page's own.
    write(root, HOST, {"/blog/": html("Blog", [f"{SITE}/blog/a/", f"{SITE}/elsewhere/"]), "/elsewhere/": html("E")})
    folder = go(SITE + "/blog/", s(**{"crawl.strategy": "rules", "crawl.stayInFolder": True,
                                     "type.website.startPages": ["/research/"]}), FixtureFetcher(root))
    assert {e.url for e in folder.entries} == {SITE + "/blog/", SITE + "/blog/a/", SITE + "/research/", SITE + "/research/b/"}


def test_pagination_followed(tmp_path):
    pages = {"/": html("Home", [f"{SITE}/posts/1/", f"{SITE}/page/2/"]),
             "/page/2/": html("Older 2", [f"{SITE}/posts/2/", f"{SITE}/page/3/"]),
             "/page/3/": html("Older 3", [f"{SITE}/posts/3/"])}
    pages.update({f"/posts/{i}/": html(f"Post {i}") for i in (1, 2, 3)})
    root = write(tmp_path, HOST, pages)
    rules = {"crawl.strategy": "rules", "crawl.maxDepth": 5}
    off = go(SITE + "/", s(**rules), FixtureFetcher(root))
    assert {e.url for e in off.entries} == {SITE + "/", SITE + "/posts/1/"} and off.skipped["excluded"] == 1
    on = go(SITE + "/", s(**rules, **{"type.website.followPagination": True}), FixtureFetcher(root))
    assert {f"{SITE}/posts/{i}/" for i in (1, 2, 3)} <= {e.url for e in on.entries}
    assert SITE + "/page/3/" in {e.url for e in on.entries}
    # Only the page/N patterns leave the list; every other exclude still applies.
    assert "page/*" not in c.exclude_patterns(s(**{"type.website.followPagination": True}))
    assert c.exclude_patterns(s(**{"type.website.followPagination": True})) == [
        p for p in s().list("crawl.excludePaths") if p != "page/*"]
    assert c.exclude_patterns(s()) == s().list("crawl.excludePaths")


def test_sitemap_url(tmp_path):
    root = write(tmp_path, HOST, {
        "/": html("Home"),
        "/feeds/posts.xml": urlset([f"{SITE}/posts/{i}/" for i in range(5)]),
        "/robots.txt": f"Sitemap: {SITE}/from-robots.xml\n",
        "/from-robots.xml": urlset([f"{SITE}/notes/{i}/" for i in range(3)]),
    })
    auto = {"crawl.strategy": "auto"}
    configured = go(SITE + "/", s(**auto, **{"type.website.sitemapUrls": ["/feeds/posts.xml"]}), FixtureFetcher(root),
                    llm=ScriptedChatModel())
    assert [e.url for e in configured.entries] == [f"{SITE}/posts/{i}/" for i in range(5)]
    assert configured.stopped_because.startswith("auto: configured")
    robots_only = go(SITE + "/", s(**auto), FixtureFetcher(root), llm=ScriptedChatModel())
    assert [e.url for e in robots_only.entries] == [f"{SITE}/notes/{i}/" for i in range(3)]
    # A configured sitemap that gives nothing falls back to the robots line.
    empty = go(SITE + "/", s(**auto, **{"type.website.sitemapUrls": ["/missing.xml"]}), FixtureFetcher(root),
               llm=ScriptedChatModel())
    assert len(empty.entries) == 3
    # Check URL shows the same index.
    with net.use_fetcher(FixtureFetcher(root)):
        checked = run(check_url.check_url(CheckUrlRequest(user_id="u1", url=SITE + "/",
                                                          type_options={"type.website.sitemapUrls": ["/feeds/posts.xml"]})))
    assert checked.index.kind == "sitemap" and checked.index.count == 5 and checked.index.url == f"{SITE}/feeds/posts.xml"


def test_always_browser(tmp_path):
    root = write(tmp_path, HOST, {"/": html("Home", [f"{SITE}/a/"]), "/a/": html("A")})
    fetcher = FixtureFetcher(root)
    result = go(SITE + "/", s(**{"crawl.strategy": "rules", "fetching.alwaysBrowser": True}), fetcher)
    assert fetcher.requests == [] and fetcher.browser.renders == [SITE + "/", SITE + "/a/"]
    assert {e.url for e in result.entries} == {SITE + "/", SITE + "/a/"} and all(e.extra["tier"] == 2 for e in result.entries)
    # Off (the default): a page large enough is read with a plain GET only.
    plain = FixtureFetcher(root)
    go(SITE + "/", s(**{"crawl.strategy": "rules", "fetching.crawlBrowserBelowBytes": 0}), plain)
    assert plain.browser.renders == [] and len(plain.requests) == 2
    # The start page and stored pages go the same way (fetch.smart_fetch).
    single = FixtureFetcher(root)
    with net.use_fetcher(single):
        page = run(fetch.smart_fetch(SITE + "/a/", s(**{"fetching.alwaysBrowser": True})))
    assert page.tier == 2 and single.requests == []


def _store_state(url, settings, secrets):
    req = JobStartRequest.model_validate({
        "job_id": "j1", "user_id": "u1", "resource_id": "r1", "kind": "refresh", "actor_user_id": "u1",
        "settings": settings, "settings_snapshot": {"values": {}, "provenance": {}}, "settings_hash": "0" * 16,
        "resource": {"url": url, "slug": "site", "name": "site", "storage_mode": "stored"}, "secrets": secrets})

    async def nothing(*_a, **_k):
        return False

    ctx = JobContext(request=req, settings=EffectiveSettings(settings), target_generation=1, is_cancelled=nothing,
                     set_stage=nothing)
    store = MemoryStore()
    store.add_resource("u1", "r1", url=url, storage_mode="stored")
    return IngestState(ctx=ctx, store=store, blocking=lambda fn, *a: _now(fn, *a), build_llm=None, owner_id="u1",
                       resource_id="r1", storage_mode="stored", site_type="agentic-crawl",
                       entries=[Candidate(url, "post", "sitemap", url)])


async def _now(fn, *args):
    return fn(*args)


def test_always_browser_ignored_with_login(tmp_path):
    """§5: a resource with a login never uses the browser, "always use the browser" included."""
    root = write(tmp_path, HOST, {"/": html("Home", [f"{SITE}/a/"]), "/a/": html("A")})
    always = {"crawl.strategy": "rules", "fetching.alwaysBrowser": True}
    fetcher = FixtureFetcher(root)
    result = go(SITE + "/", s(**always), fetcher, allow_browser=False)
    assert fetcher.browser.renders == [] and [u for u, _h in fetcher.requests] == [SITE + "/", SITE + "/a/"]
    assert len(result.entries) == 2 and all(e.extra["tier"] == 1 for e in result.entries)
    single = FixtureFetcher(root)
    with net.use_fetcher(single):
        page = run(fetch.smart_fetch(SITE + "/a/", s(**{"fetching.alwaysBrowser": True}), allow_browser=False))
    assert page.tier == 1 and single.browser.renders == []

    # Storage reads a page of a login resource without the browser, even a JavaScript-only one.
    fixture = FixtureFetcher()
    login = Secrets(credentials=Credentials(cookie="cookie=fake-session"))
    assert fetch.has_login(login) and not fetch.has_login(Secrets()) and not fetch.has_login(Secrets(credentials=Credentials()))
    with net.use_fetcher(fixture):
        st = _store_state(JS_ONLY, {"fetching.alwaysBrowser": True}, login.model_dump())
        run(storage.store(st))
    assert fixture.browser.renders == []
    browser_ok = FixtureFetcher()
    with net.use_fetcher(browser_ok):
        run(storage.store(_store_state(JS_ONLY, {"fetching.alwaysBrowser": True}, {})))
    assert browser_ok.browser.renders == [JS_ONLY]


@pytest.mark.parametrize("always", [False, True])
def test_wait_for(tmp_path, always):
    """The element the browser waits for reaches every render: the crawl's (a thin page, or
    always), the start page's and a stored page's."""
    root = write(tmp_path, HOST, {"/": "<html><head><title>T</title></head><body><div id='app'></div></body></html>"})
    seen = []

    class Recording(FixtureFetcher):
        async def render(self, url, **kw):
            seen.append(kw.get("wait_for"))
            return await super().render(url, **kw)

    settings = s(**{"fetching.waitForSelector": "#app .loaded", "fetching.alwaysBrowser": always})
    with net.use_fetcher(Recording(root)):
        run(c.fetch_page_for(settings)(SITE + "/"))
        run(fetch.smart_fetch(SITE + "/", settings))
    assert seen == ["#app .loaded", "#app .loaded"]
    from orchestrator_helpers import fetch_guard
    script = fetch_guard.guarded_browser_script(SITE + "/", **{k: v for k, v in fetch.render_options(settings).items()
                                                               if k != "timeout"})
    assert "page.wait_for_selector('#app .loaded'" in script
