"""Links found in a crawled page resolve the way a browser resolves them.

The base is the page's FINAL URL (after redirects), or its `<base href>`.
Joining against `page_url + "/"` put a sibling of `/a/page.html` under
`/a/page.html/`, so the crawl fetched pages that do not exist.

Hosts are RFC 2606 `.test` names; nothing here touches the network.
"""
from __future__ import annotations

import asyncio
import unittest
from unittest import mock

from orchestrator_helpers import tradecraft_crawl, tradecraft_lookup
from orchestrator_helpers.tradecraft_crawl import _extract_links_and_meta, agentic_crawl
from orchestrator_helpers.tradecraft_lookup import FetchResult
from orchestrator_helpers.web_sources import resolve_link

try:  # sibling-test helper; robust to namespace-package shadowing
    from tests.test_tradecraft_crawl import _ScriptedLLM, _StubMCP
except ModuleNotFoundError:
    from test_tradecraft_crawl import _ScriptedLLM, _StubMCP

DOCS = "https://docs.example.test"


def _page(links, base_href=None, filler=2500):
    base = f'<base href="{base_href}">' if base_href else ""
    anchors = "".join(f'<a href="{h}">{h}</a>' for h in links)
    return (f"<html><head><title>T</title>{base}</head><body><main><h1>T</h1>"
            f"<p>{'x ' * filler}</p>{anchors}</main></body></html>")


def _hrefs(html, page_url):
    return [link["href"] for link in _extract_links_and_meta(html, page_url)["links"]]


class ResolveLikeABrowser(unittest.TestCase):
    def test_file_like_page_resolves_sibling(self):
        self.assertEqual(_hrefs(_page(["other.html"]), f"{DOCS}/a/page.html"),
                         [f"{DOCS}/a/other.html"])

    def test_directory_page_resolves_child(self):
        self.assertEqual(_hrefs(_page(["intro"]), f"{DOCS}/docs/"), [f"{DOCS}/docs/intro"])

    def test_extensionless_page_resolves_like_a_browser(self):
        hrefs = _hrefs(_page(["../img/a.png", "next"]), f"{DOCS}/blog/post")
        self.assertEqual(hrefs, [f"{DOCS}/img/a.png", f"{DOCS}/blog/next"])

    def test_base_href_wins(self):
        self.assertEqual(_hrefs(_page(["c.html"], base_href="/root/"), f"{DOCS}/a/b.html"),
                         [f"{DOCS}/root/c.html"])

    def test_non_http_links_are_dropped(self):
        html = _page(["mailto:a@docs.example.test", "javascript:void(0)", "tel:+100",
                      "data:text/html,hi", "  ", "ok.html"])
        self.assertEqual(_hrefs(html, f"{DOCS}/a/"), [f"{DOCS}/a/ok.html"])
        for href in ("mailto:x", "JavaScript:alert(1)", "tel:1", "data:,x", "", "ftp://x.test/a"):
            self.assertIsNone(resolve_link(f"{DOCS}/", href), href)

    def test_fragment_is_dropped(self):
        self.assertEqual(resolve_link(f"{DOCS}/a/b.html", "c.html#top"), f"{DOCS}/a/c.html")


class CrawlLoopUsesFinalUrl(unittest.TestCase):
    def _run(self, routes, seed, script):
        fetched = []

        async def fake_http(url, timeout=15):
            fetched.append(url)
            html, final = routes.get(url, ("", url))
            return html, final

        llm = _ScriptedLLM(script)
        # The seed check would resolve these .test names through real DNS.
        with mock.patch.object(tradecraft_crawl, "_http_fetch", fake_http), \
             mock.patch("orchestrator_helpers.fetch_guard.is_safe_fetch_url", lambda _u: True):
            result = asyncio.run(agentic_crawl(
                seed,
                bounds={"max_pages": 10, "max_llm_calls": 5, "time_budget_sec": 60, "max_depth": 3},
                llm=llm, mcp_manager=_StubMCP({}),
            ))
        return result, fetched, llm

    def test_crawl_resolves_against_final_url_after_redirect(self):
        routes = {
            f"{DOCS}/docs": (_page(["intro"]), f"{DOCS}/docs/"),
            f"{DOCS}/docs/intro": (_page(["/docs/", "page2"]), f"{DOCS}/docs/intro"),
            f"{DOCS}/docs/page2": (_page([]), f"{DOCS}/docs/page2"),
        }
        _result, fetched, _llm = self._run(
            routes, f"{DOCS}/docs",
            ['{"action":"follow","indices":[1]}', '{"action":"follow","indices":[1,2]}'],
        )
        # `intro` on the redirected-to `/docs/` is `/docs/intro`, not `/intro`,
        # and the redirect target itself is never fetched a second time.
        self.assertEqual(fetched, [f"{DOCS}/docs", f"{DOCS}/docs/intro", f"{DOCS}/docs/page2"])

    def test_offsite_base_href_links_are_dropped_by_same_host_filter(self):
        routes = {f"{DOCS}/": (_page(["a.html", "b.html"], base_href="https://elsewhere.test/"),
                               f"{DOCS}/")}
        result, fetched, llm = self._run(routes, DOCS, ['{"action":"follow","indices":[1,2]}'])
        self.assertEqual(fetched, [f"{DOCS}/"])
        self.assertEqual(llm.calls, 0)  # no same-host candidate ever reached the LLM
        self.assertEqual(result.stats["pages_fetched"], 1)


class NavHarvestUsesFetchedPage(unittest.TestCase):
    NAV = '<html><body><nav><a href="guide/intro.html">Intro</a></nav></body></html>'

    def _fake_tier1(self, base):
        async def fake(url, **_kw):
            if url == base:
                return FetchResult(text=self.NAV, content_type="text/html", status=200, tier=1,
                                   final_url=f"{DOCS}/site/index.html")
            return FetchResult(text="", content_type="", status=404, tier=1)
        return fake

    def test_mkdocs_nav_harvest_resolves_against_fetched_page(self):
        base = f"{DOCS}/start"
        with mock.patch.object(tradecraft_lookup, "fetch_tier1", self._fake_tier1(base)):
            out = asyncio.run(tradecraft_lookup._build_sitemap_mkdocs(base))
        self.assertEqual([e["path"] for e in out["nav"]], [f"{DOCS}/site/guide/intro.html"])

    def test_gitbook_nav_harvest_resolves_against_fetched_page(self):
        base = f"{DOCS}/start"

        async def fake_tier2(url, mcp_manager):
            return FetchResult(text="rendered", content_type="text/html", status=200, tier=2)

        with mock.patch.object(tradecraft_lookup, "fetch_tier1", self._fake_tier1(base)), \
             mock.patch.object(tradecraft_lookup, "fetch_tier2", fake_tier2):
            out = asyncio.run(tradecraft_lookup._build_sitemap_gitbook(base))
        self.assertEqual([e["path"] for e in out["nav"]], [f"{DOCS}/site/guide/intro.html"])


if __name__ == "__main__":
    unittest.main()
