"""
STRIDE I18 — the tradecraft crawl must not be usable as an SSRF probe.

Part A: assert_safe_fetch_url blocks metadata / RFC-1918 / loopback / CGNAT /
link-local (incl. IPv4-mapped) and non-http(s), allows public + unresolvable.

Part B: _http_fetch follows redirects MANUALLY and re-validates each hop, so a
public page that 302s to 169.254.169.254 is refused before the second request.
The refusal is raised, not returned as '', so _crawl_fetch can tell it from a
thin page and never retries the URL in the browser (which follows redirects).

Run inside the agent container:
    python -m unittest tests.test_crawl_ssrf
"""
from __future__ import annotations

import asyncio
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx

_AGENTIC_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_AGENTIC_DIR))

from orchestrator_helpers.fetch_guard import assert_safe_fetch_url, UnsafeFetchURLError  # noqa: E402
from orchestrator_helpers import tradecraft_crawl  # noqa: E402

PUBLIC = "http://93.184.216.34/"


class GuardPolicy(unittest.TestCase):
    def test_allows_public(self):
        assert_safe_fetch_url(PUBLIC)  # no raise

    def test_allows_unresolvable(self):
        assert_safe_fetch_url("http://nonexistent.invalid.example/")  # DNS fails → allowed

    def test_blocks_metadata_and_private(self):
        for bad in [
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.5/",
            "http://127.0.0.1/",
            "http://192.168.1.10/",
            "http://172.16.0.1/",
            "http://100.100.100.200/",          # CGNAT (Alibaba metadata)
            "http://[::ffff:169.254.169.254]/",  # IPv4-mapped IPv6
        ]:
            with self.assertRaises(UnsafeFetchURLError, msg=bad):
                assert_safe_fetch_url(bad)

    def test_blocks_bad_scheme_and_no_host(self):
        for bad in ["file:///etc/passwd", "gopher://x/", "http://"]:
            with self.assertRaises(UnsafeFetchURLError, msg=bad):
                assert_safe_fetch_url(bad)


class _FakeClient:
    """Async-context httpx client stub driven by a url -> (status, headers, body) map."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_a):
        return False

    async def get(self, url):
        self.calls.append(str(url))
        status, headers, body = self.routes[str(url)]
        return httpx.Response(status, headers=headers, content=body.encode(),
                              request=httpx.Request("GET", url))


class HttpFetchRedirectGuard(unittest.TestCase):
    def _run(self, routes):
        fake = _FakeClient(routes)
        with patch("httpx.AsyncClient", return_value=fake):
            html, _final = asyncio.run(tradecraft_crawl._http_fetch(PUBLIC))
        return html, fake.calls

    def test_redirect_to_metadata_is_blocked(self):
        routes = {
            PUBLIC: (302, {"location": "http://169.254.169.254/latest/meta-data/"}, ""),
        }
        fake = _FakeClient(routes)
        with patch("httpx.AsyncClient", return_value=fake):
            with self.assertRaises(UnsafeFetchURLError):
                asyncio.run(tradecraft_crawl._http_fetch(PUBLIC))
        # The metadata hop was NEVER requested — blocked before the second GET.
        self.assertEqual(fake.calls, [PUBLIC])

    def test_public_html_is_returned(self):
        routes = {PUBLIC: (200, {"content-type": "text/html"}, "<html>ok</html>")}
        html, calls = self._run(routes)
        self.assertEqual(html, "<html>ok</html>")
        self.assertEqual(calls, [PUBLIC])


class CrawlFetchNoBrowserFallbackOnBlock(unittest.TestCase):
    """A blocked fetch must not fall through to Playwright with the same URL."""

    def _crawl_fetch_with(self, http_fetch):
        browser_calls = []

        async def fake_playwright(url, _mcp):
            browser_calls.append(url)
            return "<html>internal page rendered by the browser</html>"

        with patch.object(tradecraft_crawl, "_http_fetch", http_fetch), \
             patch.object(tradecraft_crawl, "_playwright_fetch", fake_playwright):
            result = asyncio.run(tradecraft_crawl._crawl_fetch(PUBLIC, object()))
        return result, browser_calls

    def test_blocked_redirect_skips_browser(self):
        async def blocked(_url):
            raise UnsafeFetchURLError("redirect to 169.254.169.254")

        result, browser_calls = self._crawl_fetch_with(blocked)
        self.assertEqual(result[:2], ("", 0))
        self.assertEqual(browser_calls, [])

    def test_thin_page_still_escalates(self):
        async def thin(_url):
            return "<html></html>", _url

        result, browser_calls = self._crawl_fetch_with(thin)
        self.assertEqual(browser_calls, [PUBLIC])
        self.assertEqual(result[1], 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
