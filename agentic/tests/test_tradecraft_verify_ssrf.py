"""
CVE-2026-111323 — /tradecraft/verify must not be an unauthenticated SSRF.

One class per layer of the fix:
  A. the route needs the internal key (401 without it, and verify never runs);
  B. the pinned network backend judges the address at connect time and dials
     exactly that address (DNS rebinding, metadata names, unresolvable hosts);
  C. fetch_tier1, through real httpx and a loopback server, refuses a public
     page's 302 into 169.254.169.254 before the second request is sent;
  D. the GitHub token goes only to exact GitHub hosts, over https;
  E. a refused fetch, by httpx or by the browser, never reaches the sitemap
     builders, the crawl or the LLM, and is reported as blocked;
  F. the browser guard script carries the URL inertly and applies the same
     address policy, and its [BLOCKED] verdict reaches the caller.

Run inside the agent container:
    python -m unittest tests.test_tradecraft_verify_ssrf
"""
from __future__ import annotations

import ast
import asyncio
import http.server
import os
import re
import socket
import sys
import threading
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import patch

import httpcore
import httpx

_AGENTIC_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_AGENTIC_DIR))

from orchestrator_helpers import fetch_guard  # noqa: E402
from orchestrator_helpers import tradecraft_lookup as tl  # noqa: E402
from orchestrator_helpers.fetch_guard import UnsafeFetchURLError  # noqa: E402

# Same stand-in public address as test_crawl_ssrf. No test here opens a socket
# to it: dials are recorded or redirected to a loopback server.
PUBLIC_IP = "93.184.216.34"
METADATA_URL = "http://169.254.169.254/latest/meta-data/"


def _resolver(table):
    """A fetch_guard._resolve_ips stand-in: names from `table`, else the real one."""
    real = fetch_guard._resolve_ips

    def resolve(host):
        if host in table:
            return list(table[host])
        return real(host)
    return resolve


class _RecordingBackend(httpcore.AsyncNetworkBackend):
    """Inner backend that records what it was asked to dial and opens nothing."""

    def __init__(self):
        self.dialed = []

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        self.dialed.append((host, port))
        raise httpcore.ConnectError("test backend opens no sockets")

    async def connect_unix_socket(self, path, timeout=None, socket_options=None):
        raise NotImplementedError

    async def sleep(self, seconds):
        await asyncio.sleep(seconds)


# =========================================================================
# A. Route authentication
# =========================================================================

class VerifyRouteRequiresInternalKey(unittest.TestCase):
    KEY = "test-internal-key-0123456789abcdef"

    @classmethod
    def setUpClass(cls):
        @asynccontextmanager
        async def fake_lifespan(_app):
            yield

        with patch("api.lifespan", fake_lifespan):
            import api as api_module
        cls.api = api_module
        from fastapi.testclient import TestClient
        cls.TestClient = TestClient

    def _post(self, headers):
        calls = []

        async def fake_verify(url, **_kw):
            calls.append(url)
            return {"summary": "s", "resource_type": "agentic-crawl", "sitemap": {},
                    "crawl_stopped_because": "", "crawl_stats": {}, "last_error": ""}

        # The route builds the named user's own client (RBAC HD-16), not orch.llm.
        with patch.dict(os.environ, {"INTERNAL_API_KEY": self.KEY}), \
             patch.object(self.api, "orchestrator") as orch, \
             patch.object(self.api, "_build_llm_for_user", return_value=object()), \
             patch("orchestrator_helpers.tradecraft_lookup.verify_resource", new=fake_verify), \
             patch("orchestrator_helpers.tradecraft_lookup.validate_url", return_value=(True, "")):
            orch._initialized = True
            orch._mcp_manager = None
            r = self.TestClient(self.api.app).post(
                "/tradecraft/verify",
                json={"url": "https://docs.example.test/", "user_id": "user-1"},
                headers=headers,
            )
        return r, calls

    def test_no_key_is_refused_before_any_fetch(self):
        r, calls = self._post({})
        self.assertEqual(r.status_code, 401)
        self.assertEqual(calls, [])

    def test_wrong_key_is_refused(self):
        r, calls = self._post({"x-internal-key": "not-the-key"})
        self.assertEqual(r.status_code, 401)
        self.assertEqual(calls, [])

    def test_right_key_reaches_verify(self):
        r, calls = self._post({"x-internal-key": self.KEY})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(calls, ["https://docs.example.test/"])


# =========================================================================
# B. Connect-time pinning
# =========================================================================

class PinnedBackend(unittest.TestCase):
    def _connect(self, host, table, port=443):
        inner = _RecordingBackend()
        backend = fetch_guard._PinnedNetworkBackend(inner)
        with patch.object(fetch_guard, "_resolve_ips", _resolver(table)):
            try:
                asyncio.run(backend.connect_tcp(host, port))
            except Exception as e:  # the outcome is asserted by each test
                return e, inner.dialed
        return None, inner.dialed

    def test_private_answer_is_refused_before_dialing(self):
        err, dialed = self._connect("docs.example.test", {"docs.example.test": ["10.0.0.5"]})
        self.assertIsInstance(err, UnsafeFetchURLError)
        self.assertEqual(dialed, [])

    def test_one_private_address_among_public_ones_is_refused(self):
        err, dialed = self._connect(
            "docs.example.test", {"docs.example.test": [PUBLIC_IP, "127.0.0.1"]})
        self.assertIsInstance(err, UnsafeFetchURLError)
        self.assertEqual(dialed, [])

    def test_public_answer_dials_the_checked_address_not_the_name(self):
        err, dialed = self._connect("docs.example.test", {"docs.example.test": [PUBLIC_IP]})
        self.assertIsInstance(err, httpcore.ConnectError)  # from the recording backend
        self.assertEqual(dialed, [(PUBLIC_IP, 443)])

    def test_rebinding_answer_after_validation_is_refused(self):
        # validate_url sees a public answer; the connection, resolving again,
        # gets an internal one. The connect-time check is the one that counts.
        public = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_IP, 0))]
        with patch.object(tl.socket, "getaddrinfo", return_value=public):
            ok, err = tl.validate_url("https://rebind.example.test/")
        self.assertTrue(ok, err)
        err, dialed = self._connect("rebind.example.test", {"rebind.example.test": ["169.254.169.254"]})
        self.assertIsInstance(err, UnsafeFetchURLError)
        self.assertEqual(dialed, [])

    def test_metadata_hostname_is_refused_without_resolving(self):
        looked_up = []

        def resolve(host):
            looked_up.append(host)
            return [PUBLIC_IP]

        inner = _RecordingBackend()
        backend = fetch_guard._PinnedNetworkBackend(inner)
        with patch.object(fetch_guard, "_resolve_ips", resolve):
            with self.assertRaises(UnsafeFetchURLError):
                asyncio.run(backend.connect_tcp("metadata.google.internal", 80))
        self.assertEqual(looked_up, [])
        self.assertEqual(inner.dialed, [])

    def test_unresolvable_name_is_never_handed_to_the_inner_backend(self):
        err, dialed = self._connect("gone.example.test", {"gone.example.test": []})
        self.assertIsInstance(err, httpcore.ConnectError)
        self.assertEqual(dialed, [])

    def test_unix_socket_is_refused(self):
        backend = fetch_guard._PinnedNetworkBackend(_RecordingBackend())
        with self.assertRaises(UnsafeFetchURLError):
            asyncio.run(backend.connect_unix_socket("/var/run/docker.sock"))

    def test_transport_dials_through_the_pinned_backend(self):
        # Fails loudly if an httpx/httpcore upgrade moves the pool's backend.
        transport = fetch_guard.pinned_async_transport()
        self.assertIsInstance(transport._pool._network_backend, fetch_guard._PinnedNetworkBackend)


# =========================================================================
# C. fetch_tier1 end to end (real httpx, loopback server)
# =========================================================================

class _LoopbackDialer(httpcore.AsyncNetworkBackend):
    """Stands in for the internet: dials the loopback test server whatever
    public address the pinned backend checked, and records that address."""

    def __init__(self, port):
        self._real = httpcore.AnyIOBackend()
        self._port = port
        self.dialed = []

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        self.dialed.append(host)
        return await self._real.connect_tcp(
            "127.0.0.1", self._port, timeout=timeout,
            local_address=local_address, socket_options=socket_options)

    async def connect_unix_socket(self, path, timeout=None, socket_options=None):
        raise NotImplementedError

    async def sleep(self, seconds):
        await self._real.sleep(seconds)


class _Handler(http.server.BaseHTTPRequestHandler):
    requests: list = []
    PAGE = "<html><body>" + ("tradecraft notes " * 100) + "</body></html>"

    def do_GET(self):
        type(self).requests.append(self.path)
        if self.path == "/redirect-to-metadata":
            self.send_response(302)
            self.send_header("Location", METADATA_URL)
            self.end_headers()
            return
        body = self.PAGE.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_a):
        pass


class FetchTier1EndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        _Handler.requests = []
        self.dialer = _LoopbackDialer(self.server.server_address[1])

        def transport():
            t = fetch_guard.pinned_async_transport()
            t._pool._network_backend._inner = self.dialer
            return t

        self._patches = [
            patch.object(tl, "pinned_async_transport", transport),
            patch.object(fetch_guard, "_resolve_ips", _resolver({"docs.example.test": [PUBLIC_IP]})),
        ]
        for p in self._patches:
            p.start()

    def tearDown(self):
        for p in self._patches:
            p.stop()

    def test_redirect_into_metadata_is_refused_before_the_second_request(self):
        r = asyncio.run(tl.fetch_tier1("http://docs.example.test/redirect-to-metadata"))
        self.assertIn("169.254.169.254", r.blocked)
        self.assertEqual(r.text, "")
        self.assertEqual(_Handler.requests, ["/redirect-to-metadata"])
        self.assertEqual(self.dialer.dialed, [PUBLIC_IP])

    def test_public_page_is_fetched_through_the_checked_address(self):
        r = asyncio.run(tl.fetch_tier1("http://docs.example.test/guide"))
        self.assertEqual(r.blocked, "")
        self.assertEqual(r.status, 200)
        self.assertIn("tradecraft notes", r.text)
        self.assertEqual(self.dialer.dialed, [PUBLIC_IP])

    def test_smart_fetch_never_hands_a_blocked_url_to_the_browser(self):
        browser_calls = []

        async def fake_tier2(url, _mcp):
            browser_calls.append(url)
            return tl.FetchResult(text="internal page", content_type="text/html", status=200, tier=2)

        with patch.object(tl, "fetch_tier2", fake_tier2):
            r = asyncio.run(tl.smart_fetch("http://docs.example.test/redirect-to-metadata",
                                           mcp_manager=object()))
        self.assertTrue(r.blocked)
        self.assertEqual(browser_calls, [])


# =========================================================================
# D. GitHub token scope
# =========================================================================

class GithubTokenScope(unittest.TestCase):
    def test_exact_github_hosts_over_https_only(self):
        allowed = [
            "https://github.com/o/r",
            "https://api.github.com/repos/o/r",
            "https://raw.githubusercontent.com/o/r/main/README.md",
            "https://GitHub.com/o/r",
        ]
        refused = [
            "https://github-docs.example.test/",
            "https://github.com.example.test/",
            "https://docs.example.test/github/readme",
            "https://docs.example.test/?ref=github.com",
            "http://github.com/o/r",
            "https://example.test@evil.example.test/github.com",
        ]
        for url in allowed:
            self.assertTrue(tl._is_github_token_url(url), url)
        for url in refused:
            self.assertFalse(tl._is_github_token_url(url), url)

    def _headers_sent(self, url):
        sent = []

        class _Client:
            def __init__(self, *_a, **kw):
                self.headers = kw.get("headers") or {}

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_a):
                return False

            async def get(self, u):
                sent.append(dict(self.headers))
                return httpx.Response(200, headers={"content-type": "text/plain"}, text="x",
                                      request=httpx.Request("GET", u))

        with patch.object(tl.httpx, "AsyncClient", _Client):
            asyncio.run(tl.fetch_tier1(url, github_token="ghp_secret"))
        return sent[0]

    def test_lookalike_host_gets_no_token(self):
        self.assertNotIn("Authorization", self._headers_sent("https://github-docs.example.test/page"))

    def test_github_blob_url_gets_the_token(self):
        headers = self._headers_sent("https://github.com/o/r/blob/main/README.md")
        self.assertEqual(headers.get("Authorization"), "token ghp_secret")


# =========================================================================
# E. A refused homepage stops verify
# =========================================================================

class VerifyStopsOnBlockedHomepage(unittest.TestCase):
    def test_no_sitemap_crawl_or_llm_after_a_block(self):
        touched = []

        async def blocked_fetch(url, **_kw):
            return tl.FetchResult(text="", content_type="", status=0, tier=1,
                                  blocked="refusing to connect to docs.example.test")

        async def crawl(*_a, **_kw):
            touched.append("crawl")
            return {"nav": []}

        class _LLM:
            async def ainvoke(self, *_a, **_kw):
                touched.append("llm")

        with patch.object(tl, "validate_url", return_value=(True, "")), \
             patch.object(tl, "smart_fetch", blocked_fetch), \
             patch.object(tl, "_build_sitemap_agentic_crawl", crawl):
            out = asyncio.run(tl.verify_resource("https://docs.example.test/", llm=_LLM()))
        self.assertTrue(out["last_error"].startswith("blocked:"), out)
        self.assertEqual(out["summary"], "")
        self.assertEqual(out["sitemap"], {})
        self.assertEqual(touched, [])


class BrowserBlockIsReported(unittest.TestCase):
    """httpx gets a thin page, the browser render of it is blocked: callers see
    the block, not tier 1's thin page (which read as "thin body" in the UI)."""

    REASON = "navigation reached a non-public address: http://127.0.0.1:8000/"

    def _tiers(self):
        async def thin_tier1(url, **_kw):
            return tl.FetchResult(text="", content_type="text/html", status=200, tier=1)

        async def blocked_tier2(url, _mcp):
            return tl.FetchResult(text="", content_type="", status=0, tier=2, blocked=self.REASON)

        return patch.object(tl, "fetch_tier1", thin_tier1), patch.object(tl, "fetch_tier2", blocked_tier2)

    def test_smart_fetch_returns_the_browser_block(self):
        tier1, tier2 = self._tiers()
        with tier1, tier2:
            r = asyncio.run(tl.smart_fetch("https://docs.example.test/", mcp_manager=object()))
        self.assertEqual(r.blocked, self.REASON)
        self.assertEqual(r.text, "")

    def test_verify_reports_the_block_and_never_crawls(self):
        crawled = []

        async def crawl(*_a, **_kw):
            crawled.append(True)
            return {"nav": []}

        tier1, tier2 = self._tiers()
        with tier1, tier2, patch.object(tl, "validate_url", return_value=(True, "")), \
             patch.object(tl, "_build_sitemap_agentic_crawl", crawl):
            out = asyncio.run(tl.verify_resource("https://docs.example.test/",
                                                 llm=object(), mcp_manager=object()))
        self.assertEqual(out["last_error"], "blocked: " + self.REASON)
        self.assertEqual(crawled, [])


# =========================================================================
# F. Browser guard script
# =========================================================================

def _fake_getaddrinfo(table):
    def fake(host, *_a, **_kw):
        if host not in table:
            raise socket.gaierror("not found")
        ip = table[host]
        if ":" in ip:
            return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", (ip, 0, 0, 0))]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]
    return fake


class BrowserGuardScript(unittest.TestCase):
    HOSTILE_URL = "https://docs.example.test/');import os;os.system('id');(' x"

    def test_url_is_one_inert_string_literal(self):
        script = fetch_guard.guarded_browser_script(self.HOSTILE_URL)
        goto_args = [
            node.args[0] for node in ast.walk(ast.parse(script))
            if isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "goto"
        ]
        self.assertEqual(len(goto_args), 1)
        self.assertIsInstance(goto_args[0], ast.Constant)
        self.assertEqual(goto_args[0].value, self.HOSTILE_URL)
        # The MCP wrapper re-indents with str.splitlines(); the URL must not add a line.
        self.assertEqual(len(script.splitlines()),
                         len(fetch_guard._BROWSER_GUARD_SCRIPT.splitlines()))

    def test_survives_the_script_mode_wrapper(self):
        # Mirrors playwright_server._execute_script_mode: each line goes in an
        # 8-space-indented try block, and these patterns are rejected outright.
        script = fetch_guard.guarded_browser_script("https://docs.example.test/")
        body = "\n".join(("        " + ln) if ln.strip() else "" for ln in script.splitlines())
        compile("with ctx:\n    try:\n" + body + "\n    finally:\n        pass\n", "<wrapped>", "exec")
        for pattern in (r"(?<![A-Za-z0-9_])await\s", r"(?<![A-Za-z0-9_])async\s+def\b",
                        r"(?m)^\s*import\s+asyncio\b", r"(?<![A-Za-z0-9_])sync_playwright\s*\("):
            self.assertIsNone(re.search(pattern, script), pattern)

    def test_address_policy(self):
        script = fetch_guard.guarded_browser_script("https://docs.example.test/")
        ns: dict = {}
        exec(script.split("page.route(")[0], ns)
        public = ns["_rd_public"]
        table = {
            "docs.example.test": PUBLIC_IP,
            "intranet.example.test": "10.1.2.3",
            "cgnat.example.test": "100.100.100.200",
            "mapped.example.test": "::ffff:169.254.169.254",
            "metadata.google.internal": PUBLIC_IP,  # refused by name, whatever DNS says
        }
        with patch("socket.getaddrinfo", _fake_getaddrinfo(table)):
            self.assertTrue(public("https://docs.example.test/page"))
            self.assertTrue(public("data:text/plain,hi"))
            for url in ("http://intranet.example.test/", "http://cgnat.example.test/",
                        "http://mapped.example.test/", "http://metadata.google.internal/",
                        "http://unknown.example.test/", "chrome-error://chromewebdata/",
                        "file:///etc/passwd"):
                self.assertFalse(public(url), url)

    def test_output_parsing(self):
        parse = fetch_guard.parse_guarded_browser_output
        self.assertEqual(parse("[BLOCKED] navigation reached a non-public address: http://10.0.0.1/"),
                         ("", "navigation reached a non-public address: http://10.0.0.1/"))
        self.assertEqual(parse("[ERROR] Navigation failed: timeout"), ("", ""))
        self.assertEqual(parse("<html>ok</html>"), ("<html>ok</html>", ""))

    def test_fetch_tier2_sends_the_guarded_script_and_reports_a_block(self):
        sent = []

        class _Tool:
            name = "execute_playwright"

            async def ainvoke(self, args):
                sent.append(args)
                return "[BLOCKED] navigation reached a non-public address: " + METADATA_URL

        class _Manager:
            async def get_tools(self):
                return [_Tool()]

        r = asyncio.run(tl.fetch_tier2("https://docs.example.test/", _Manager()))
        self.assertEqual(r.text, "")
        self.assertIn(METADATA_URL, r.blocked)
        self.assertEqual(list(sent[0]), ["script"])
        self.assertIn("'https://docs.example.test/'", sent[0]["script"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
