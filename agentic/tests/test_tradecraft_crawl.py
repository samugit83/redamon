"""Tests for the agentic crawl loop.

Loop logic uses stubbed Playwright (returns canned HTML per URL) and a stubbed
LLM (returns scripted JSON decisions). No network or real LLM hit.
"""

from __future__ import annotations

import ast
import asyncio
import unittest
from unittest import mock
from typing import Dict, List

from orchestrator_helpers.tradecraft_crawl import (
    CrawlResult,
    _looks_like_noise,
    _same_host,
    _is_private_host,
    _extract_links_and_meta,
    agentic_crawl,
)


def run_async(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# ---------------------------------------------------------------------------
# Stubs
# ---------------------------------------------------------------------------

def _requested_url(args) -> str:
    """The URL an execute_playwright call navigates to: the page.goto() literal
    of the guarded script tradecraft sends (fetch_guard.guarded_browser_script)."""
    for node in ast.walk(ast.parse(args["script"])):
        if isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "goto":
            return node.args[0].value
    raise AssertionError("script has no page.goto() call")


class _StubPlaywrightTool:
    name = "execute_playwright"

    def __init__(self, html_map: Dict[str, str]):
        self.html_map = html_map
        self.calls: List[str] = []

    async def ainvoke(self, args):
        url = _requested_url(args)
        self.calls.append(url)
        return [{"text": self.html_map.get(url, "<html></html>")}]


class _StubMCP:
    def __init__(self, html_map):
        self.tool = _StubPlaywrightTool(html_map)

    async def get_tools(self):
        return [self.tool]


class _ScriptedLLM:
    """LLM stub that returns a sequence of canned JSON responses."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0

    async def ainvoke(self, prompt):
        class R:
            pass
        r = R()
        if self.calls < len(self.responses):
            r.content = self.responses[self.calls]
        else:
            r.content = '{"action":"stop","reason":"out of script"}'
        self.calls += 1
        return r


def _make_html(title: str, body: str, links: list[tuple[str, str]]) -> str:
    link_html = "".join(
        f'<a href="{href}">{anchor}</a>' for anchor, href in links
    )
    return (
        f'<html><head><title>{title}</title></head>'
        f'<body><main><h1>{title}</h1><p>{body}</p>{link_html}</main></body></html>'
    )


# ---------------------------------------------------------------------------
# Pure-function helpers
# ---------------------------------------------------------------------------

class TestCrawlHelpers(unittest.TestCase):
    def test_looks_like_noise_recognized(self):
        for h in [
            "mailto:foo", "javascript:void(0)", "/login", "/Privacy",
            "/tag/web", "/foo.png", "#section",
        ]:
            self.assertTrue(_looks_like_noise(h), f"expected noise: {h}")

    def test_looks_like_noise_passes_real(self):
        for h in [
            "/blog/post1", "/en/AD/Kerberoast.html",
            "https://x.com/posts/foo",
        ]:
            self.assertFalse(_looks_like_noise(h), f"expected non-noise: {h}")

    def test_same_host_strict(self):
        self.assertTrue(_same_host("https://x.com/a", "x.com"))
        self.assertFalse(_same_host("https://www.x.com/a", "x.com"))
        self.assertFalse(_same_host("https://twitter.com/a", "x.com"))

    def test_is_private_host(self):
        self.assertTrue(_is_private_host("localhost"))
        self.assertTrue(_is_private_host("internal.local"))
        self.assertFalse(_is_private_host("example.com"))


# ---------------------------------------------------------------------------
# DOM extraction
# ---------------------------------------------------------------------------

class TestExtractLinksAndMeta(unittest.TestCase):
    def test_extracts_links_and_title(self):
        html = _make_html("My Blog", "intro text", [
            ("Post 1", "/post1"),
            ("Post 2", "/post2"),
        ])
        meta = _extract_links_and_meta(html, "https://blog.example.com")
        self.assertEqual(meta["title"], "My Blog")
        self.assertEqual(len(meta["links"]), 2)
        self.assertEqual(meta["links"][0]["title"], "Post 1")

    def test_handles_empty_html(self):
        meta = _extract_links_and_meta("", "https://x.com")
        self.assertEqual(meta["links"], [])

    def test_dedupes_links(self):
        html = _make_html("X", "y", [
            ("A", "/foo"), ("A again", "/foo"),
        ])
        meta = _extract_links_and_meta(html, "https://x.com")
        self.assertEqual(len(meta["links"]), 1)


# ---------------------------------------------------------------------------
# Full loop
# ---------------------------------------------------------------------------

class TestAgenticCrawlLoop(unittest.TestCase):
    def test_follows_then_stops(self):
        base = "https://blog.example.com"
        html_map = {
            f"{base}/": _make_html("Sec Blog", "intro " * 200, [
                ("Kerberos Silver Tickets", "/post1"),
                ("SSRF Bypasses", "/post2"),
                ("Login", "/login"),
                ("Twitter", "https://twitter.com/foo"),
            ]),
            f"{base}/post1": _make_html("Kerberos Silver Tickets", "kerberoast " * 200, []),
            f"{base}/post2": _make_html("SSRF Bypasses", "ssrf " * 200, []),
        }
        # Iteration 1 (homepage): follow [1, 2]; iter 2/3 (posts) have no links so loop exits.
        llm = _ScriptedLLM(['{"action":"follow","indices":[1,2],"reason":"good"}'])
        mcp = _StubMCP(html_map)
        result = run_async(agentic_crawl(
            base,
            bounds={"max_pages": 5, "max_llm_calls": 3, "time_budget_sec": 60, "max_depth": 2},
            llm=llm,
            mcp_manager=mcp,
        ))
        self.assertIsInstance(result, CrawlResult)
        # Visited 3 pages: homepage + two children
        self.assertEqual(result.stats["pages_fetched"], 3)
        # Sitemap has 3 entries: homepage + each child's page (because content > 500 chars)
        self.assertGreaterEqual(len(result.sitemap_entries), 3)
        # No twitter or login in sitemap
        for e in result.sitemap_entries:
            self.assertNotIn("twitter", e["path"])
            self.assertNotIn("/login", e["path"])

    def test_stops_on_max_pages(self):
        base = "https://blog.example.com"
        # Homepage has 5 links, but max_pages=2 means we only fetch the home + 1 child.
        html_map = {
            f"{base}/": _make_html("Blog", "x " * 200, [
                ("Post 1", "/p1"),
                ("Post 2", "/p2"),
                ("Post 3", "/p3"),
                ("Post 4", "/p4"),
                ("Post 5", "/p5"),
            ]),
        }
        for i in range(1, 6):
            html_map[f"{base}/p{i}"] = _make_html(f"Post {i}", "content " * 200, [])
        llm = _ScriptedLLM(['{"action":"follow","indices":[1,2,3],"reason":"all"}'])
        mcp = _StubMCP(html_map)
        result = run_async(agentic_crawl(
            base,
            bounds={"max_pages": 2, "max_llm_calls": 5, "time_budget_sec": 60, "max_depth": 2},
            llm=llm,
            mcp_manager=mcp,
        ))
        self.assertEqual(result.stopped_because, "max pages")
        self.assertLessEqual(result.stats["pages_fetched"], 2)

    def test_stop_action_short_circuits(self):
        base = "https://blog.example.com"
        html_map = {
            f"{base}/": _make_html("Blog", "x " * 200, [
                ("Login", "/login"),
                ("Tag: web", "/tag/web"),
            ]),
        }
        # LLM says stop immediately because there are only low-signal links.
        llm = _ScriptedLLM(['{"action":"stop","reason":"only login + tags"}'])
        mcp = _StubMCP(html_map)
        result = run_async(agentic_crawl(
            base,
            bounds={"max_pages": 5, "max_llm_calls": 5, "time_budget_sec": 60, "max_depth": 2},
            llm=llm,
            mcp_manager=mcp,
        ))
        # Either "frontier empty" (because all candidate links were filtered as noise)
        # or "only login + tags" if the LLM decided.
        self.assertEqual(result.stats["pages_fetched"], 1)

    def test_no_llm_returns_single_page(self):
        base = "https://blog.example.com"
        html_map = {
            f"{base}/": _make_html("Blog", "x " * 200, [("P1", "/p1")]),
        }
        result = run_async(agentic_crawl(
            base,
            bounds={"max_pages": 5, "max_llm_calls": 5, "time_budget_sec": 60, "max_depth": 2},
            llm=None,
            mcp_manager=_StubMCP(html_map),
        ))
        self.assertEqual(result.stopped_because, "no llm available")
        self.assertEqual(result.stats["pages_fetched"], 1)

    def test_llm_malformed_json_retries_then_stops(self):
        base = "https://blog.example.com"
        html_map = {
            f"{base}/": _make_html("Blog", "x " * 200, [("P1", "/p1")]),
        }
        llm = _ScriptedLLM([
            "this is not json",
            "still not json",
        ])
        result = run_async(agentic_crawl(
            base,
            bounds={"max_pages": 5, "max_llm_calls": 5, "time_budget_sec": 60, "max_depth": 2},
            llm=llm,
            mcp_manager=_StubMCP(html_map),
        ))
        # Should have tried twice (initial + retry), then stopped with json parse failure.
        self.assertEqual(llm.calls, 2)
        self.assertIn("parse", result.stopped_because.lower())

    def test_filters_cross_host_and_private(self):
        base = "https://blog.example.com"
        html_map = {
            f"{base}/": _make_html("Blog", "x " * 200, [
                ("External", "https://other.com/x"),
                ("Internal", "https://blog.example.com/post1"),
                ("Private", "http://10.0.0.1/admin"),
            ]),
            f"{base}/post1": _make_html("Post 1", "p " * 200, []),
        }
        # LLM says follow the only candidate (Internal).
        llm = _ScriptedLLM(['{"action":"follow","indices":[1],"reason":"single internal"}'])
        result = run_async(agentic_crawl(
            base,
            bounds={"max_pages": 5, "max_llm_calls": 3, "time_budget_sec": 60, "max_depth": 2},
            llm=llm,
            mcp_manager=_StubMCP(html_map),
        ))
        # Visited only homepage + post1; external and private filtered before LLM saw them.
        for entry in result.sitemap_entries:
            self.assertNotIn("other.com", entry["path"])
            self.assertNotIn("10.0.0.1", entry["path"])


# ---------------------------------------------------------------------------
# Tier-1-first fetch behavior
# ---------------------------------------------------------------------------

class TestCrawlFetchTier1First(unittest.TestCase):
    def test_uses_tier1_when_response_is_thick(self):
        from orchestrator_helpers.tradecraft_crawl import _crawl_fetch
        async def fake_http(url, timeout=15):
            return "<html>" + ("X" * 10000) + "</html>", url  # well above threshold
        async def fake_playwright(url, mcp_manager):
            raise AssertionError("must not call playwright when tier 1 is good")
        with mock.patch("orchestrator_helpers.tradecraft_crawl._http_fetch", fake_http), \
             mock.patch("orchestrator_helpers.tradecraft_crawl._playwright_fetch", fake_playwright):
            html, tier, _final = run_async(_crawl_fetch("https://x.com/", None))
        self.assertEqual(tier, 1)
        self.assertGreater(len(html), 4000)

    def test_falls_back_to_tier2_when_response_is_thin(self):
        from orchestrator_helpers.tradecraft_crawl import _crawl_fetch
        async def fake_http(url, timeout=15):
            return "<html>tiny</html>", url  # under threshold
        async def fake_playwright(url, mcp_manager):
            return "<html>" + ("R" * 5000) + "</html>"
        with mock.patch("orchestrator_helpers.tradecraft_crawl._http_fetch", fake_http), \
             mock.patch("orchestrator_helpers.tradecraft_crawl._playwright_fetch", fake_playwright):
            html, tier, _final = run_async(_crawl_fetch("https://x.com/", object()))
        self.assertEqual(tier, 2)
        self.assertIn("RRR", html)

    def test_returns_tier_zero_when_both_fail(self):
        from orchestrator_helpers.tradecraft_crawl import _crawl_fetch
        async def fake_http(url, timeout=15):
            return "", url
        async def fake_playwright(url, mcp_manager):
            return ""
        with mock.patch("orchestrator_helpers.tradecraft_crawl._http_fetch", fake_http), \
             mock.patch("orchestrator_helpers.tradecraft_crawl._playwright_fetch", fake_playwright):
            html, tier, _final = run_async(_crawl_fetch("https://x.com/", object()))
        self.assertEqual(tier, 0)
        self.assertEqual(html, "")


if __name__ == "__main__":
    unittest.main()
