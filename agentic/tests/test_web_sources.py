"""Shared web helpers: Tradecraft and the workspace importer use the same objects."""
from __future__ import annotations

import io
import unittest

from orchestrator_helpers import web_sources as ws
from tradecraft.ingest import builders, crawl, fetch


class SharedObjects(unittest.TestCase):
    def test_tradecraft_names_are_the_shared_objects(self):
        # Tradecraft 1.x re-exported these under its own names until the cut-over (T9.2); its 2.0
        # modules import the shared objects themselves.
        pairs = [
            (fetch, "url_host"), (fetch, "is_github_token_url"), (fetch, "rewrite_github_url"),
            (fetch, "html_to_markdown"), (builders, "split_github_url"), (builders, "prefer_english"),
            (builders, "parse_sitemap_xml"), (builders, "resolve_link"), (crawl, "resolve_link"),
        ]
        for module, name in pairs:
            self.assertIs(getattr(module, name), getattr(ws, name), f"{module.__name__}.{name}")


class GithubUrls(unittest.TestCase):
    def test_split_github_url_keeps_names_ending_in_git_letters(self):
        self.assertEqual(ws.split_github_url("https://github.com/o/streamlit"), ("o", "streamlit"))
        self.assertEqual(ws.split_github_url("https://github.com/o/nuclei/tree/main"), ("o", "nuclei"))
        self.assertEqual(ws.split_github_url("https://github.com/o/r.git"), ("o", "r"))
        self.assertIsNone(ws.split_github_url("https://gitlab.example.test/o/r"))

    def test_rewrite_blob_to_raw(self):
        self.assertEqual(
            ws.rewrite_github_url("https://github.com/o/r/blob/main/docs/a.md"),
            "https://raw.githubusercontent.com/o/r/main/docs/a.md",
        )
        self.assertEqual(ws.rewrite_github_url("https://github.com/o/r"), "https://github.com/o/r")

    def test_token_url_requires_exact_github_host_and_https(self):
        for url in ("https://github.com/o/r", "https://api.github.com/repos/o/r",
                    "https://raw.githubusercontent.com/o/r/main/x"):
            self.assertTrue(ws.is_github_token_url(url), url)
        for url in ("http://github.com/o/r", "https://github.com.example.test/o/r",
                    "https://codeload.github.com/o/r/tar.gz/x", "https://gist.github.com/x",
                    "https://evilgithub.com/", "not a url"):
            self.assertFalse(ws.is_github_token_url(url), url)


class Sitemaps(unittest.TestCase):
    def test_prefer_english_threshold(self):
        urls = [f"https://d.example.test/{lang}/p" for lang in ("en", "fr", "de", "es")]
        self.assertEqual(ws.prefer_english(urls), ["https://d.example.test/en/p"])
        mixed = ["https://d.example.test/en/a"] + [f"https://d.example.test/p{i}" for i in range(5)]
        self.assertEqual(ws.prefer_english(mixed), mixed)  # only 1 of 6 is under a language

    def test_parse_sitemap_xml_urlset_index_and_garbage(self):
        urlset = ('<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                  '<url><loc>https://d.example.test/a</loc></url><url><loc> </loc></url></urlset>')
        self.assertEqual(ws.parse_sitemap_xml(urlset), ("urlset", ["https://d.example.test/a"]))
        index = ('<sitemapindex><sitemap><loc>https://d.example.test/s1.xml</loc></sitemap>'
                 '<sitemap><loc>https://d.example.test/s2.xml</loc></sitemap></sitemapindex>')
        self.assertEqual(ws.parse_sitemap_xml(index),
                         ("index", ["https://d.example.test/s1.xml", "https://d.example.test/s2.xml"]))
        for garbage in ("", "<html><body>not a sitemap</body></html>", "\x00\x01"):
            self.assertEqual(ws.parse_sitemap_xml(garbage), (None, []))

    def test_doctype_and_entity_sitemaps_refused(self):
        laughs = ('<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">'
                  '<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]>'
                  '<urlset><url><loc>&lol2;</loc></url></urlset>')
        external = ('<?xml version="1.0"?><!DOCTYPE u [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
                    '<urlset><url><loc>&x;</loc></url></urlset>')
        lower = '<!doctype x><urlset><url><loc>https://d.example.test/a</loc></url></urlset>'
        for doc in (laughs, external, lower):
            self.assertEqual(ws.parse_sitemap_xml(doc), (None, []))
            self.assertTrue(ws.sitemap_xml_refused(doc))

    def test_oversized_sitemap_refused(self):
        big = "<urlset>" + "<url><loc>https://d.example.test/a</loc></url>" * 250_000 + "</urlset>"
        self.assertGreater(len(big), ws.SITEMAP_MAX_BYTES)
        self.assertEqual(ws.parse_sitemap_xml(big), (None, []))


class PageText(unittest.TestCase):
    def test_html_to_markdown_strips_nav_and_script(self):
        html = ("<html><body><nav>MENU-LINKS</nav><script>alert('x')</script>"
                "<article><h1>Title</h1><p>" + "body text " * 40 + "</p></article>"
                "<footer>FOOTER</footer></body></html>")
        md = ws.html_to_markdown(html)
        self.assertIn("# Title", md)
        self.assertIn("body text", md)
        for gone in ("MENU-LINKS", "alert(", "FOOTER"):
            self.assertNotIn(gone, md)

    def test_extract_pdf_pages_returns_empty_on_invalid_bytes(self):
        meta, texts, err = ws.extract_pdf_pages(b"%PDF-1.4 not really a pdf")
        self.assertEqual((meta, texts), ([], []))
        self.assertTrue(err)
        self.assertEqual(ws.extract_pdf_pages(b"")[2], "empty pdf body")


if __name__ == "__main__":
    unittest.main()
