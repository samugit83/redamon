"""Website mirror: where each URL is saved, and which links a page names."""
from __future__ import annotations

import ast
import unittest
from pathlib import Path

from workspace_import import mirror_paths as mp

HTML = "text/html; charset=utf-8"
HOST = "example.test"


def rel(url, ct=HTML, mode="raw", scope=HOST):
    return mp.url_to_relpath(url, ct, mode=mode, scope_host=scope)


class PathMapping(unittest.TestCase):
    def test_root_and_trailing_slash_map_to_index(self):
        self.assertEqual(rel("https://example.test"), "index.html")
        self.assertEqual(rel("https://example.test/"), "index.html")
        self.assertEqual(rel("https://example.test/docs/"), "docs/index.html")
        self.assertEqual(rel("https://example.test/docs/", mode="readable"), "docs/index.md")

    def test_extensionless_html_becomes_dir_index(self):
        self.assertEqual(rel("https://example.test/a"), "a/index.html")
        self.assertEqual(rel("https://example.test/a/b"), "a/b/index.html")
        self.assertEqual(rel("https://example.test/a/page.html"), "a/page.html")
        # Not HTML: the bytes keep their own name.
        self.assertEqual(rel("https://example.test/LICENSE", "text/plain"), "LICENSE")

    def test_query_variant_suffix_is_stable(self):
        one = rel("https://example.test/list.php?b=2&a=1")
        self.assertEqual(one, rel("https://example.test/list.php?a=1&b=2"))
        self.assertRegex(one, r"^list__q[0-9a-f]{8}\.php$")
        self.assertNotEqual(one, rel("https://example.test/list.php?a=1&b=3"))
        self.assertRegex(rel("https://example.test/?page=2"), r"^index__q[0-9a-f]{8}\.html$")
        self.assertEqual(mp.canonical_url("HTTPS://Example.TEST:443/x?b=1&a=2#frag"),
                         "https://example.test/x?a=2&b=1")

    def test_traversal_and_control_chars_in_segments_neutralized(self):
        cases = [
            "https://example.test/%2e%2e/%2e%2e/etc/passwd",
            "https://example.test/a/%2E/b.txt",
            "https://example.test/a%2Fb/c.txt",
            "https://example.test/a%5Cb/c.txt",
            "https://example.test/x%00y/z%0Aw%1B.txt",
            "https://example.test/a//b.txt",
        ]
        for url in cases:
            out = rel(url, "text/plain")
            parts = out.split("/")
            self.assertNotIn("..", parts, url)
            self.assertNotIn(".", parts, url)
            self.assertNotIn("", parts, url)
            self.assertFalse(any(ord(c) < 32 or c == "\\" for c in out), url)
        self.assertEqual(rel("https://example.test/%2e%2e/%2e%2e/etc/passwd", "text/plain"), "_/_/etc/passwd")
        self.assertEqual(rel("https://example.test/a%2Fb/c.txt", "text/plain"), "a_b/c.txt")
        long_seg = rel("https://example.test/" + "é" * 200 + ".txt", "text/plain")
        self.assertLessEqual(len(long_seg.encode()), mp.SEGMENT_MAX_BYTES)
        self.assertTrue(long_seg.endswith("é.txt"))

    def test_readable_mode_extensions(self):
        self.assertEqual(rel("https://example.test/guide/page.html", mode="readable"), "guide/page.md")
        self.assertEqual(rel("https://example.test/guide/intro", mode="readable"), "guide/intro/index.md")
        self.assertEqual(rel("https://example.test/paper.pdf", "application/pdf", mode="readable"), "paper.txt")
        self.assertEqual(rel("https://example.test/notes.txt", "text/plain", mode="readable"), "notes.txt")
        self.assertEqual(rel("https://example.test/paper.pdf", "application/pdf"), "paper.pdf")

    def test_external_assets_prefix(self):
        self.assertEqual(rel("https://cdn.example.test/lib/app.js", "text/javascript"),
                         "_external/cdn.example.test/lib/app.js")
        self.assertEqual(rel("https://cdn.example.test:8443/a.css", "text/css"),
                         "_external/cdn.example.test_8443/a.css")
        both = {"example.test", "www.example.test"}
        self.assertEqual(rel("https://www.example.test/a.css", "text/css", scope=both), "a.css")

    def test_long_path_hashed(self):
        url = "https://example.test/" + "/".join(["segment-" + "x" * 100] * 12) + "/file.js"
        out = rel(url, "text/javascript")
        self.assertRegex(out, r"^_long/[0-9a-f]{40}\.js$")
        self.assertEqual(out, rel(url, "text/javascript"))

    def test_mirror_reserved_name_remapped(self):
        for name in (".import.json", "_manifest.jsonl"):
            out = rel(f"https://example.test/{name}", "application/json")
            self.assertRegex(out, r"^_reserved/[0-9a-f]{40}$", name)
            out = rel(f"https://example.test/sub/{name}", "application/json")
            self.assertTrue(out.startswith("_reserved/"), name)


class StdlibParserOnly(unittest.TestCase):
    def test_import_package_parses_html_with_stdlib_parser_only(self):
        package = Path(mp.__file__).resolve().parent
        files = sorted(package.glob("*.py"))
        self.assertIn("mirror_paths.py", [f.name for f in files])
        for f in files:
            tree = ast.parse(f.read_text(encoding="utf-8"), filename=str(f))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    self.assertFalse(any(a.name.split(".")[0] == "lxml" for a in node.names), f.name)
                elif isinstance(node, ast.ImportFrom):
                    self.assertNotEqual((node.module or "").split(".")[0], "lxml", f.name)
                elif isinstance(node, ast.Call):
                    fn = node.func
                    name = fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else ""
                    if name != "BeautifulSoup":
                        continue
                    parser = node.args[1] if len(node.args) > 1 else next(
                        (k.value for k in node.keywords if k.arg in ("features", "parser")), None)
                    self.assertTrue(isinstance(parser, ast.Constant) and parser.value == "html.parser",
                                    f"{f.name}:{node.lineno} parses HTML without html.parser")


class LinkExtraction(unittest.TestCase):
    def test_extract_links_pages_vs_assets_with_base_href(self):
        html = """<html><head>
          <base href="/docs/v2/">
          <link rel="stylesheet" href="css/site.css"><link rel="icon" href="/favicon.ico">
          <link rel="alternate" href="feed.xml"><link rel="preload modulepreload" href="m.js">
          <script src="js/app.js"></script>
          <style>body { background: url('img/bg.png') }</style>
        </head><body>
          <a href="intro.html#part">Intro</a><a href="intro.html">Again</a>
          <a href="mailto:someone@example.test">mail</a><a href="javascript:void(0)">js</a>
          <area href="/map.html"><iframe src="embed.html"></iframe>
          <img src="i.png"><video src="v.mp4" poster="p.jpg"></video><audio src="a.ogg"></audio>
          <track src="t.vtt"><object data="o.swf"></object><embed src="e.svg">
          <div style="background-image: url(&quot;img/inline.png&quot;)"></div>
          <a href="ftp://example.test/x">ftp</a>
        </body></html>"""
        pages, assets = mp.extract_links(html, "https://example.test/docs/v2/page")
        self.assertEqual(pages, ["https://example.test/docs/v2/intro.html", "https://example.test/map.html",
                                 "https://example.test/docs/v2/embed.html"])
        b = "https://example.test/docs/v2/"
        self.assertEqual(set(assets), {
            b + "css/site.css", "https://example.test/favicon.ico", b + "m.js", b + "js/app.js",
            b + "i.png", b + "v.mp4", b + "p.jpg", b + "a.ogg", b + "t.vtt", b + "o.swf", b + "e.svg",
            b + "img/bg.png", b + "img/inline.png",
        })
        self.assertNotIn(b + "feed.xml", assets)

    def test_links_resolve_against_final_url_without_base(self):
        pages, _ = mp.extract_links('<a href="sibling.html">s</a><a href="#top">top</a>',
                                    "https://example.test/a/page.html")
        self.assertEqual(pages, ["https://example.test/a/sibling.html"])

    def test_srcset_candidates(self):
        html = ('<img srcset="small.jpg 480w, large.jpg 1080w, data:image/png;base64,AAAA 2x">'
                '<picture><source srcset="/hero.webp 1x,/hero@2x.webp 2x"></picture>'
                '<img srcset="a.jpg 1x,b.jpg 2x"><img srcset="c,d.jpg 2x">')
        _, assets = mp.extract_links(html, "https://example.test/p/")
        # Per the HTML spec a URL ends at whitespace: "c,d.jpg" is one URL.
        self.assertEqual(assets, ["https://example.test/p/small.jpg", "https://example.test/p/large.jpg",
                                  "https://example.test/p/a.jpg", "https://example.test/p/b.jpg",
                                  "https://example.test/p/c,d.jpg",
                                  "https://example.test/hero.webp", "https://example.test/hero@2x.webp"])

    def test_css_urls_and_imports(self):
        css = """@import "base.css"; @import url('theme.css');
                 .a { background: url(img/a.png) } .b { background: url( "../img/b.png" ) }
                 .c { src: url(data:font/woff2;base64,AAAA) } .d { background: url(#svgfilter) }"""
        urls = mp.extract_css_urls(css, "https://example.test/static/css/site.css")
        self.assertEqual(set(urls), {
            "https://example.test/static/css/base.css", "https://example.test/static/css/theme.css",
            "https://example.test/static/css/img/a.png", "https://example.test/static/img/b.png",
        })


if __name__ == "__main__":
    unittest.main()
