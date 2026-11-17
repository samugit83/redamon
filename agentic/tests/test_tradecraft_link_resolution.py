"""Links found in a crawled page resolve the way a browser resolves them.

The base is the page's URL (its FINAL URL, after redirects), or its `<base href>`.
Joining against `page_url + "/"` put a sibling of `/a/page.html` under
`/a/page.html/`, so the crawl fetched pages that do not exist. Since the cut-over (T9.2)
these checks run on the 2.0 crawl's extractor (``tradecraft.ingest.crawl.page_meta``, the
port of 1.x's ``_extract_links_and_meta``); the 1.x crawl loop's checks (it resolved against
the final URL, the same-host filter, the nav harvests) are 2.0's own:
test_tradecraft_ingest_crawl.py and test_tradecraft_ingest_builders.py.

Hosts are RFC 2606 `.test` names; nothing here touches the network.
"""
from __future__ import annotations

import unittest

from orchestrator_helpers.web_sources import resolve_link
from tradecraft.ingest.crawl import page_meta

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


if __name__ == "__main__":
    unittest.main()
