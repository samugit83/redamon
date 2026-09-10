"""
Tests for browser_launch.capture_kwargs — the in-process chromium capture wiring
shared by the redamon SDK's `redamon.browser` and (constants only) by
playwright_server.

§20.2 tag-leak guard: the proxy flag and the X-Redamon-Ctx header are emitted
TOGETHER, only when the capture proxy is reachable; never the header on a direct
connection. A distinct `header_tag` (the browser lineage tag) overrides the value.

Run: python3 mcp/servers/tests/test_browser_launch.py
"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

SERVERS = Path(__file__).resolve().parents[1]
if str(SERVERS) not in sys.path:
    sys.path.insert(0, str(SERVERS))

import capture_routing  # noqa: E402
import browser_launch  # noqa: E402

_TEST_URL = "http://redamon-capture-proxy:8888"
_TAG = "eyJhIjoxfQ.c2ln"


class TestCaptureKwargs(unittest.TestCase):
    def setUp(self):
        self._orig_reach = capture_routing._reachable
        self._orig_env = os.environ.get("CAPTURE_PROXY_URL")
        os.environ["CAPTURE_PROXY_URL"] = _TEST_URL

    def tearDown(self):
        capture_routing._reachable = self._orig_reach
        if self._orig_env is None:
            os.environ.pop("CAPTURE_PROXY_URL", None)
        else:
            os.environ["CAPTURE_PROXY_URL"] = self._orig_env

    def _reachable(self, ok):
        capture_routing._reachable = lambda *a, **k: ok

    def test_routed_returns_proxy_and_header(self):
        self._reachable(True)
        proxy, headers = browser_launch.capture_kwargs(_TAG)
        self.assertEqual(proxy, {"server": _TEST_URL})
        self.assertEqual(headers, {"X-Redamon-Ctx": _TAG})

    def test_header_tag_overrides_value(self):
        self._reachable(True)
        proxy, headers = browser_launch.capture_kwargs(_TAG, header_tag="lineage-tag")
        self.assertEqual(proxy, {"server": _TEST_URL})
        self.assertEqual(headers, {"X-Redamon-Ctx": "lineage-tag"})

    def test_unreachable_leaks_nothing(self):
        self._reachable(False)
        self.assertEqual(browser_launch.capture_kwargs(_TAG), (None, {}))

    def test_empty_token_leaks_nothing(self):
        self._reachable(True)
        self.assertEqual(browser_launch.capture_kwargs(""), (None, {}))


if __name__ == "__main__":
    unittest.main()
