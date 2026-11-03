"""The website mirror through the REAL pinned transport: no page, asset or
redirect hop of a crawl reaches a private or loopback address.

Same harness as test_workspace_import_fetch_ssrf.py: a patched resolver plays
DNS, and a loopback server plays the site behind a dialer that records which
checked address it was asked to connect to.
"""
from __future__ import annotations

import asyncio
import http.server
import json
import shutil
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from orchestrator_helpers import fetch_guard
from workspace_import.fetch import GuardedFetcher
from workspace_import.mirror import MirrorOptions, mirror

try:  # sibling-test helper; robust to namespace-package shadowing
    from tests.test_workspace_import_fetch_ssrf import PUBLIC_IP, _LoopbackDialer, _resolver
except ModuleNotFoundError:
    from test_workspace_import_fetch_ssrf import PUBLIC_IP, _LoopbackDialer, _resolver

SEED = "http://site.example.test/docs/"
PAGE = (b'<html><body><a href="/docs/to-private.html">p</a><a href="/docs/two.html">2</a>'
        b'<img src="http://assets.example.test/i.png"></body></html>')


class _Site(http.server.BaseHTTPRequestHandler):
    requests: list = []

    def do_GET(self):
        type(self).requests.append((self.headers.get("Host", "").split(":")[0], self.path))
        if self.path == "/docs/to-private.html":
            self.send_response(302)
            self.send_header("Location", "http://internal.example.test/admin")
            self.end_headers()
            return
        body, ctype = {"/docs/": (PAGE, "text/html"), "/docs/two.html": (b"<p>two</p>", "text/html"),
                       "/i.png": (b"\x89PNG", "image/png")}.get(self.path, (None, None))
        if body is None:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_a):
        pass


class MirrorSSRF(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Site)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        _Site.requests = []
        self.dialer = _LoopbackDialer(self.server.server_address[1])
        self.dns = {"site.example.test": [PUBLIC_IP], "internal.example.test": ["10.1.2.3"],
                    "assets.example.test": ["192.168.1.5"]}
        self.tmp = Path(tempfile.mkdtemp(prefix="mirror-ssrf-"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def factory(self):
        transport = fetch_guard.pinned_async_transport()
        transport._pool._network_backend._inner = self.dialer
        return GuardedFetcher(transport=transport)

    async def crawl(self, resolver=None, **opts):
        async def no_wait(_s):
            await asyncio.sleep(0)
        with patch.object(fetch_guard, "_resolve_ips", resolver or _resolver(self.dns)):
            await mirror(SEED, self.tmp / "out", MirrorOptions(**opts), fetcher_factory=self.factory, sleep=no_wait)
        lines = (self.tmp / "out" / "_manifest.jsonl").read_text().splitlines()
        return {m["url"]: m for m in map(json.loads, lines)}

    async def test_page_redirect_into_private_address_refused(self):
        manifest = await self.crawl()
        self.assertEqual(manifest["http://site.example.test/docs/to-private.html"]["skipped"], "blocked_address")
        self.assertNotIn("internal.example.test", [h for h, _p in _Site.requests])
        self.assertEqual(set(self.dialer.dialed), {PUBLIC_IP})
        self.assertIsNone(manifest["http://site.example.test/docs/two.html"]["skipped"])

    async def test_asset_on_private_address_refused(self):
        manifest = await self.crawl(external_assets=True)
        self.assertEqual(manifest["http://assets.example.test/i.png"]["skipped"], "blocked_address")
        self.assertNotIn("192.168.1.5", self.dialer.dialed)
        self.assertNotIn("assets.example.test", [h for h, _p in _Site.requests])

    async def test_rebinding_between_pages_refused(self):
        # The seed's hop check and connect see a public answer; from then on
        # the host answers loopback, and every later request is refused.
        calls = {"n": 0}

        def rebinding(host):
            if host != "site.example.test":
                return _resolver(self.dns)(host)
            calls["n"] += 1
            return [PUBLIC_IP] if calls["n"] <= 2 else ["127.0.0.1"]
        manifest = await self.crawl(resolver=rebinding)
        self.assertEqual(_Site.requests, [("site.example.test", "/docs/")])
        self.assertEqual(self.dialer.dialed, [PUBLIC_IP])
        self.assertEqual(manifest["http://site.example.test/docs/two.html"]["skipped"], "blocked_address")


if __name__ == "__main__":
    unittest.main()
