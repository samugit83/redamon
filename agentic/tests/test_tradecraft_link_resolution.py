"""Links found in a crawled page resolve the way a browser resolves them.

The base is the page's URL (its FINAL URL, after redirects), or its `<base href>`.
Joining against `page_url + "/"` put a sibling of `/a/page.html` under
`/a/page.html/`, so the crawl fetched pages that do not exist. Since the cut-over (T9.2)
these checks run on the 2.0 crawl's extractor (``tradecraft.ingest.crawl.page_meta``, the
port of 1.x's ``_extract_links_and_meta``); the crawl loop and the menu harvests are held to the
page's final URL below, with a page that redirects (review finding 4).

Hosts are RFC 2606 `.test` names; nothing here touches the network.
"""
from __future__ import annotations

import asyncio
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from orchestrator_helpers.web_sources import resolve_link  # noqa: E402
from tradecraft import net  # noqa: E402
from tradecraft.ingest import builders  # noqa: E402
from tradecraft.ingest.crawl import CrawlFetch, crawl, page_meta  # noqa: E402
from tradecraft.settings import EffectiveSettings  # noqa: E402
from tradecraft_doubles import FixtureFetcher  # noqa: E402

DOCS = "https://docs.example.test"


def _page(links, base_href=None, filler=2500):
    base = f'<base href="{base_href}">' if base_href else ""
    anchors = "".join(f'<a href="{h}">{h}</a>' for h in links)
    return (f"<html><head><title>T</title>{base}</head><body><main><h1>T</h1>"
            f"<p>{'x ' * filler}</p>{anchors}</main></body></html>")


def _hrefs(html, page_url):
    return [link["href"] for link in page_meta(html, page_url)["links"]]


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
    """The crawl resolves a page's links against the URL it was redirected to (``crawl.py``)."""

    def setUp(self):
        self.requested = []

    async def _fetch(self, url):
        self.requested.append(url)
        if url == f"{DOCS}/start":
            # /start redirects to /guide/index.html: "other.html" is /guide/other.html.
            return CrawlFetch(_page(["other.html", "/abs.html"]), f"{DOCS}/guide/index.html")
        if url in (f"{DOCS}/guide/other.html", f"{DOCS}/abs.html"):
            return CrawlFetch(_page([]), url)
        return CrawlFetch("", url, 0, "http_error")

    def test_crawl_resolves_against_final_url_after_redirect(self):
        settings = EffectiveSettings({"crawl.strategy": "rules", "fetching.browserEnabled": False})
        result = asyncio.run(crawl(f"{DOCS}/start", settings, fetch_page=self._fetch, allow_browser=False))
        self.assertIn(f"{DOCS}/guide/other.html", self.requested)
        self.assertIn(f"{DOCS}/abs.html", self.requested)
        self.assertNotIn(f"{DOCS}/start/other.html", self.requested)
        self.assertNotIn(f"{DOCS}/other.html", self.requested)
        self.assertIn(f"{DOCS}/guide/other.html", {e.url for e in result.entries})


class NavHarvestUsesFetchedPage(unittest.TestCase):
    """A wiki's or a GitBook's menu resolves against the start page's final URL (``builders.py``):
    the site has no sitemap and no mkdocs.yml, so the menu is the map."""

    HOST = "https://other.tc-fixture.test"
    MENU = ('<html><body><nav><a href="install/">Install</a><a href="../usage/">Usage</a></nav>'
            '<main><p>start</p></main></body></html>')

    def _build(self, build):
        with net.use_fetcher(FixtureFetcher()):
            return asyncio.run(build(f"{self.HOST}/", EffectiveSettings({}), home_html=self.MENU,
                                     home_final_url=f"{self.HOST}/en/latest/"))

    def test_mkdocs_nav_harvest_resolves_against_fetched_page(self):
        result = self._build(builders.build_wiki)
        self.assertEqual([e.url for e in result.entries], [f"{self.HOST}/en/latest/install/", f"{self.HOST}/en/usage/"])

    def test_gitbook_nav_harvest_resolves_against_fetched_page(self):
        result = self._build(builders.build_gitbook)
        self.assertEqual([e.url for e in result.entries], [f"{self.HOST}/en/latest/install/", f"{self.HOST}/en/usage/"])


if __name__ == "__main__":
    unittest.main()
