"""Fetching settings (T3.2, §4.1, R-070): one request timeout for every fetch, the user agent,
Accept-Language only when set, the browser on or off, the two thresholds that send a page to
the browser, and the browser's wait, timeout and size, which reach the guarded script together
with the in-browser cleaning (R-197). AC-10: a JavaScript-heavy page whose raw HTML is far above
the browser limit still comes back with its whole article and every link.

The web is ``FixtureFetcher`` (or a small fetcher of this file for the heavy page) and the
browser a double that honours ``clean`` with the cleaning's own selectors; nothing leaves the
process.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any, Optional
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from orchestrator_helpers import fetch_guard  # noqa: E402
from orchestrator_helpers.web_sources import BeautifulSoup  # noqa: E402
from tradecraft import net  # noqa: E402
from tradecraft.ingest import builders, crawl, fetch, robots  # noqa: E402
from tradecraft.net import GuardedFetcher, Rendered, Response  # noqa: E402
from tradecraft.settings import EffectiveSettings  # noqa: E402
from tradecraft_doubles import FixtureFetcher, RecordingMcp, run  # noqa: E402

WIKI = "https://wiki.tc-fixture.test/"
JS_ONLY = "https://blog.tc-fixture.test/posts/42-js-only/"
BOOK = "https://book.tc-fixture.test"


def s(**values):
    return EffectiveSettings(values)


class Recording(FixtureFetcher):
    """``FixtureFetcher`` that also records the options of every ``get`` and ``render``."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.gets: list[tuple[str, dict]] = []
        self.render_calls: list[tuple[str, dict]] = []

    async def get(self, url, **kw):
        self.gets.append((url, kw))
        return await super().get(url, **kw)

    async def render(self, url, **kw):
        self.render_calls.append((url, kw))
        return await super().render(url, **kw)


@pytest.fixture
def rec():
    f = Recording()
    with net.use_fetcher(f):
        yield f


def test_one_request_timeout_for_every_fetch(rec):
    settings = s(**{"fetching.requestTimeoutSec": 45, "fetching.browserBelowChars": 0})
    run(fetch.smart_fetch(WIKI, settings))
    run(fetch.fetch_raw(WIKI + "sitemap.xml", settings))
    run(crawl.fetch_page_for(settings)("https://blog.tc-fixture.test/"))
    run(robots.read(WIKI, settings))
    run(builders.build_wiki(WIKI, settings))
    assert len(rec.gets) >= 5 and {kw["timeout"] for _u, kw in rec.gets} == {45.0}
    # 1.x crawled pages with 15 s and the rest with 30 s; 2.0 has one value, 30 s by default.
    rec.gets.clear()
    run(crawl.fetch_page_for(s())("https://blog.tc-fixture.test/"))
    assert {kw["timeout"] for _u, kw in rec.gets} == {30.0}


def test_user_agent(rec):
    run(fetch.smart_fetch(WIKI, s(**{"fetching.userAgent": "Lab-Reader/2", "fetching.browserBelowChars": 0})))
    run(crawl.fetch_page_for(s(**{"fetching.userAgent": "Lab-Reader/2"}))("https://blog.tc-fixture.test/"))
    assert [h["user-agent"] for _u, h in rec.requests] == ["Lab-Reader/2", "Lab-Reader/2"]
    rec.requests.clear()
    run(fetch.fetch_raw(WIKI, s()))
    assert rec.requests[0][1]["user-agent"] == "RedAmon-Tradecraft/1.0"


def test_accept_language_only_when_set(rec):
    run(fetch.fetch_raw(WIKI, s()))
    assert "accept-language" not in rec.requests[-1][1]
    run(fetch.fetch_raw(WIKI, s(**{"fetching.acceptLanguage": "fr-FR, fr;q=0.8"})))
    assert rec.requests[-1][1]["accept-language"] == "fr-FR, fr;q=0.8"
    run(crawl.fetch_page_for(s(**{"fetching.acceptLanguage": "de"}))("https://blog.tc-fixture.test/"))
    assert rec.requests[-1][1]["accept-language"] == "de"


def test_browser_rendering_off(rec):
    off = s(**{"fetching.browserEnabled": False})
    page = run(fetch.smart_fetch(JS_ONLY, off))
    got = run(crawl.fetch_page_for(off)(JS_ONLY))
    menu = run(builders.build_gitbook(BOOK + "/nothing", off, home_html="<html></html>"))
    assert page.tier == 1 and got.tier == 1 and menu.entries == []
    assert rec.render_calls == []
    # On (the default), the same thin page goes to the browser in both paths.
    run(fetch.smart_fetch(JS_ONLY, s()))
    run(crawl.fetch_page_for(s())(JS_ONLY))
    assert [u for u, _kw in rec.render_calls] == [JS_ONLY, JS_ONLY]


def test_browser_below_chars(rec):
    # The wiki page's cleaned text is a few hundred characters.
    text_len = len(run(fetch.smart_fetch(WIKI, s(**{"fetching.browserBelowChars": 0}))).text)
    assert rec.render_calls == []
    run(fetch.smart_fetch(WIKI, s(**{"fetching.browserBelowChars": text_len})))
    assert rec.render_calls == []
    run(fetch.smart_fetch(WIKI, s(**{"fetching.browserBelowChars": text_len + 1})))
    assert [u for u, _kw in rec.render_calls] == [WIKI]


def test_crawl_browser_below_bytes(rec):
    blog = "https://blog.tc-fixture.test/"
    size = len(run(rec.get(blog)).body)
    rec.render_calls.clear()
    assert run(crawl.fetch_page_for(s(**{"fetching.crawlBrowserBelowBytes": size}))(blog)).tier == 1
    assert run(crawl.fetch_page_for(s(**{"fetching.crawlBrowserBelowBytes": size + 1}))(blog)).tier == 2
    assert [u for u, _kw in rec.render_calls] == [blog]


def test_browser_wait_page_timeout_and_size(rec):
    """Every 2.0 render (start page, crawl, GitBook menu) runs with the browser settings and
    the in-browser cleaning."""
    settings = s(**{"fetching.browserWaitUntil": "domcontentloaded", "fetching.browserTimeoutSec": 12,
                    "fetching.browserMaxChars": 250000, "fetching.waitForSelector": "#content"})
    run(fetch.smart_fetch(JS_ONLY, settings))
    run(crawl.fetch_page_for(settings)(JS_ONLY))
    run(builders.build_gitbook(BOOK + "/nothing", settings, home_html="<html></html>"))
    expected = {"timeout": 12.0, "wait_until": "domcontentloaded", "max_chars": 250000, "clean": True,
                "wait_for": "#content"}
    assert len(rec.render_calls) == 3 and all(kw == expected for _u, kw in rec.render_calls)
    assert fetch.render_options(s()) == {"timeout": 30.0, "wait_until": "networkidle", "max_chars": 40000,
                                         "clean": True, "wait_for": None}


def test_always_browser(rec):
    page = run(fetch.smart_fetch(WIKI, s(**{"fetching.alwaysBrowser": True})))
    assert page.tier == 2 and rec.gets == [] and [u for u, _kw in rec.render_calls] == [WIKI]


def test_the_options_reach_the_guarded_script():
    mcp = RecordingMcp()
    with patch.object(fetch_guard, "_resolve_ips", lambda _host: ["93.184.216.34"]):
        r = run(GuardedFetcher(mcp).render(WIKI, timeout=12.0, wait_until="load", max_chars=500000, clean=True,
                                           wait_for="#main"))
        assert r.error == ""
        assert mcp.calls == [{"script": fetch_guard.guarded_browser_script(
            WIKI, timeout_ms=12000, wait_until="load", max_chars=500000, clean=True, wait_for="#main")}]
        # The defaults still send the 1.x script.
        run(GuardedFetcher(mcp).render(WIKI))
        assert mcp.calls[-1] == {"script": fetch_guard.guarded_browser_script(WIKI)}
        # An option the script cannot take never reaches the browser.
        calls = len(mcp.calls)
        bad = run(GuardedFetcher(mcp).render(WIKI, wait_until="never"))
        assert bad.error == "browser_error" and bad.html == "" and len(mcp.calls) == calls


@pytest.mark.parametrize("reply", [
    fetch_guard.CLEAN_FAILED,
    "\n[STDERR]: Traceback (most recent call last):\n  File x\nError: boom",
    "<html><body>half a page</body></html>\n[STDERR]: Traceback (most recent call last): boom",
])
def test_a_failed_script_is_never_a_page(reply, caplog):
    """A cleaning the page broke, or a script that exited with an error, is a browser error
    with a [tradecraft] log line: its output is never stored or indexed as the page."""
    with patch.object(fetch_guard, "_resolve_ips", lambda _host: ["93.184.216.34"]), caplog.at_level("WARNING"):
        r = run(GuardedFetcher(RecordingMcp(reply=reply)).render(WIKI, clean=True))
    assert (r.html, r.error) == ("", "browser_error")
    assert "[tradecraft] net browser_error host=wiki.tc-fixture.test" in caplog.text
    with patch.object(fetch_guard, "_resolve_ips", lambda _host: ["93.184.216.34"]):
        ok = run(GuardedFetcher(RecordingMcp(reply="<html><body>[STDERR] in the text is fine</body></html>")).render(WIKI))
    assert ok.error == "" and "in the text is fine" in ok.html


# --------------------------------------------------------------------------------------
# AC-10: heavy pages come back whole
# --------------------------------------------------------------------------------------

HEAVY = "https://heavy.tc-fixture.test/post/"
PARAGRAPHS = 420
LINKS = 300


def heavy_page() -> str:
    """EX-2's page: about 500 KB of inline style and 500 KB of inline script before an article
    of 420 paragraphs and 300 links, an inline SVG and a noscript block."""
    style = "<style>" + ".c{color:#123456;margin:0 auto}" * 17000 + "</style>"
    script = "<script>" + "window.__STATE__.push({a:1,b:[2,3]});" * 13000 + "</script>"
    paragraphs = "".join(f"<p>Paragraph {i} of the heavy article.</p>" for i in range(PARAGRAPHS))
    links = "".join(f'<a href="/post/{i}/">post {i}</a> ' for i in range(LINKS))
    svg = '<svg>' + '<path d="M0 0"/>' * 500 + '</svg>'
    return (f'<html><head><title>Heavy</title><meta name="generator" content="mkdocs-1.5">{style}{script}'
            f'<script src="/app.js"></script></head><body>{svg}'
            f"<noscript>Enable JavaScript</noscript><main><article><h1>Heavy</h1>{paragraphs}{links}</article></main>"
            "</body></html>")


def _clean_like_the_browser(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    pairs = re.findall(r"querySelectorAll\('([^']+)'\)\) (?:s|n)(\.textContent = ''|\.remove\(\))", fetch_guard._CLEAN_JS)
    for selector, action in pairs:
        for el in soup.select(selector):
            if "textContent" in action:
                el.string = ""
            else:
                el.decompose()
    return str(soup)


class HeavySite:
    """A single-page app: the plain GET returns an empty shell; the browser renders the heavy
    page, cleaned in the page when asked, then cut at ``max_chars``."""

    def __init__(self) -> None:
        self.renders: list[dict[str, Any]] = []

    async def get(self, url: str, **kw: Any) -> Response:
        shell = b'<html><head><title>Loading</title></head><body><div id="root"></div></body></html>'
        return Response(url=url, final_url=url, status=200, headers={"content-type": "text/html"}, body=shell,
                        content_type="text/html")

    async def render(self, url: str, *, timeout: float = 30.0, wait_until: str = "networkidle",
                     max_chars: int = 40000, clean: bool = False, wait_for: Optional[str] = None) -> Rendered:
        self.renders.append({"clean": clean, "max_chars": max_chars})
        page = heavy_page()
        if clean:
            page = _clean_like_the_browser(page)
        return Rendered(url=url, html=page[:max_chars])


def test_heavy_page_whole():
    raw = heavy_page()
    assert len(raw) > 25 * 40000  # far above the browser limit
    site = HeavySite()
    with net.use_fetcher(site):
        page = run(fetch.smart_fetch(HEAVY, s()))
        got = run(crawl.fetch_page_for(s())(HEAVY))
        uncleaned = run(site.render(HEAVY))  # what the 1.x script returns for the same page
    assert site.renders[0] == {"clean": True, "max_chars": 40000} and page.tier == 2
    assert all(f"Paragraph {i} of the heavy article." in page.text for i in range(PARAGRAPHS))
    assert 'content="mkdocs-1.5"' in page.html and 'src="/app.js"' in page.html  # detection still sees them
    links = crawl.page_meta(got.html, HEAVY)["links"]
    assert len(links) == LINKS
    # Without the cleaning, the same limit returns the head of the page and no article at all.
    assert "Paragraph 0" not in uncleaned.html and "<a href" not in uncleaned.html


# --------------------------------------------------------------------------------------
# Review finding 7: plain pages are read up to a size, cut and counted (R-230, R-112)
# --------------------------------------------------------------------------------------

def test_every_plain_page_fetch_is_capped(rec):
    from tradecraft import check_url as cu
    from tradecraft.contract import CheckUrlRequest

    assert fetch.PAGE_MAX_BYTES == 1_000_000  # the ceiling EX-2 set for the browser's transfer
    run(fetch.smart_fetch(WIKI, s(**{"fetching.browserBelowChars": 0})))
    run(crawl.fetch_page_for(s())("https://blog.tc-fixture.test/"))
    assert [kw["max_bytes"] for _u, kw in rec.gets] == [fetch.PAGE_MAX_BYTES, fetch.PAGE_MAX_BYTES]
    rec.gets.clear()
    run(cu.check_url(CheckUrlRequest(user_id="u1", url="https://github.com/tc-fixture/payloads")))
    uncapped = [u for u, kw in rec.gets if kw.get("max_bytes") is None]
    # Only the GitHub tree, read by the same builder as ingestion, has no cap of its own here.
    assert all("/git/trees/" in u or u.endswith("/repos/tc-fixture/payloads") for u in uncapped), uncapped


def _big_site(tmp_path):
    host = "big.tc-fixture.test"
    body = "<p>" + "x" * 1_500_000 + "</p>"
    for path, text in {"/": f"<html><head><title>Big</title></head><body><main><a href='/b/'>b</a>{body}"
                            f"<a href='/lost/'>after the cut</a></main></body></html>",
                       "/b/": "<html><head><title>B</title></head><body><main><p>" + "y" * 600 + "</p></main></body></html>"}.items():
        target = tmp_path / host / path.lstrip("/") / "index.html"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    return tmp_path, f"https://{host}/"


def test_an_oversized_page_is_cut_and_counted(tmp_path):
    from tradecraft import clock
    from tradecraft_doubles import FakeClock

    root, url = _big_site(tmp_path)
    fetcher = Recording(root)
    with net.use_fetcher(fetcher), clock.use_clock(FakeClock()):
        result = run(crawl.crawl(url, s(**{"crawl.strategy": "rules"})))
    assert result.errors == {fetch.PAGE_TOO_LARGE: 1}
    big = next(e for e in result.entries if e.url == url)
    # What comes before the cut is read (the link to /b/), what comes after is not.
    assert len(big.extra["html"]) <= fetch.PAGE_MAX_BYTES and [e.url for e in result.entries] == [url, url + "b/"]
    assert not any("/lost/" in u for u, _kw in fetcher.gets)
    assert all(kw["max_bytes"] == fetch.PAGE_MAX_BYTES for _u, kw in fetcher.gets)
    with net.use_fetcher(Recording(root)):
        page = run(fetch.smart_fetch(url, s()))
    assert page.truncated and len(page.body) == fetch.PAGE_MAX_BYTES


def test_a_capped_pdf_is_read_whole():
    pdf = "https://files.tc-fixture.test/guide.pdf"
    fetcher = Recording()
    with net.use_fetcher(fetcher):
        page = run(fetch.smart_fetch(pdf, s(), max_bytes=500))
    full = (fetcher.site.root / "files.tc-fixture.test" / "guide.pdf").read_bytes()
    assert page.is_pdf and not page.truncated and page.body == full and len(full) > 500
    assert [kw.get("max_bytes") for _u, kw in fetcher.gets] == [500, None]
