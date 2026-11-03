"""GuardedFetcher logic on httpx.MockTransport: hops, caps, token scope, redaction."""
from __future__ import annotations

import asyncio
import inspect
import logging
import shutil
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

import httpx

from workspace_import import fetch
from workspace_import.errors import ImportFailure
from workspace_import.fetch import GuardedFetcher, disposition_filename, redact_text, redact_url
from workspace_import.names import sanitize_name

TOKEN = "TEST-SENTINEL-TOKEN-0000"


def _no_dns(_url):
    return None


class FetchBase(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ws-fetch-"))
        self.seen: list[httpx.Request] = []

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def fetcher(self, routes, **kw):
        def handler(request: httpx.Request):
            self.seen.append(request)
            route = routes.get(str(request.url))
            if route is None:
                return httpx.Response(404)
            return route(request) if callable(route) else route

        kw.setdefault("assert_safe", _no_dns)
        return GuardedFetcher(transport=httpx.MockTransport(handler), **kw)

    async def assertCode(self, code, coro):
        with self.assertRaises(ImportFailure) as ctx:
            await coro
        self.assertEqual(ctx.exception.code, code)
        return ctx.exception


def redirect(location, status=302):
    return httpx.Response(status, headers={"location": location})


class Redirects(FetchBase):
    async def test_follows_redirects_by_hand_and_records_hops(self):
        routes = {
            "https://a.example.test/x": redirect("/y"),
            "https://a.example.test/y": redirect("https://b.example.test/z?sig=SECRET"),
            "https://b.example.test/z?sig=SECRET": httpx.Response(200, content=b"body"),
        }
        async with self.fetcher(routes) as f:
            p = await f.probe("https://a.example.test/x")
        self.assertEqual(p.status, 200)
        self.assertEqual(p.final_url, "https://b.example.test/z?sig=SECRET")
        self.assertEqual(p.hops, ["https://a.example.test/y", "https://b.example.test/z"])
        self.assertEqual(p.head, b"body")

    async def test_every_hop_is_checked(self):
        checked = []
        routes = {"https://a.example.test/x": redirect("https://b.example.test/y"),
                  "https://b.example.test/y": httpx.Response(200)}
        async with self.fetcher(routes, assert_safe=checked.append) as f:
            await f.probe("https://a.example.test/x")
        self.assertEqual(checked, ["https://a.example.test/x", "https://b.example.test/y"])

    async def test_hop_policy_runs_on_every_hop_and_can_refuse(self):
        calls = []

        async def policy(url, hop):
            calls.append((url, hop))
            if "b.example.test" in url:
                raise ImportFailure("blocked_address")

        routes = {"https://a.example.test/x": redirect("https://b.example.test/y")}
        async with self.fetcher(routes, hop_policy=policy) as f:
            await self.assertCode("blocked_address", f.probe("https://a.example.test/x"))
        self.assertEqual(calls, [("https://a.example.test/x", 0), ("https://b.example.test/y", 1)])
        self.assertEqual(len(self.seen), 1)  # the refused hop was never requested

    async def test_default_transport_and_guard_are_the_pinned_ones(self):
        seen = []

        def handler(request):
            seen.append(str(request.url))
            return httpx.Response(200, content=b"x")
        pinned = httpx.MockTransport(handler)
        with mock.patch.object(fetch, "pinned_async_transport", lambda: pinned):
            async with GuardedFetcher(assert_safe=_no_dns) as f:
                await f.probe("https://a.example.test/x")
        self.assertEqual(seen, ["https://a.example.test/x"])
        self.assertIs(inspect.signature(GuardedFetcher).parameters["assert_safe"].default,
                      fetch.assert_safe_fetch_url)

    async def test_per_request_policy_runs_after_the_fetchers_own(self):
        order = []

        def own(url, hop):
            order.append(("own", hop))

        async def per_request(url, hop):
            order.append(("request", hop))

        routes = {"https://a.example.test/x": redirect("/y"), "https://a.example.test/y": httpx.Response(200, text="ok")}
        async with self.fetcher(routes, hop_policy=own) as f:
            status, text, _final, _h = await f.get_text("https://a.example.test/x", max_bytes=100, policy=per_request)
            self.assertEqual((status, text), (200, "ok"))
            await f.get_text("https://a.example.test/y", max_bytes=100)
        self.assertEqual(order, [("own", 0), ("request", 0), ("own", 1), ("request", 1), ("own", 0)])

    async def test_check_response_refuses_before_any_byte_is_written(self):
        dest = self.tmp / "out.bin"

        def refuse(resp):
            if resp.headers.get("content-type") == "image/png":
                raise ImportFailure("unexpected_html")

        routes = {"https://a.example.test/i.png": httpx.Response(200, content=b"png", headers={"content-type": "image/png"})}
        async with self.fetcher(routes) as f:
            await self.assertCode("unexpected_html", f.download("https://a.example.test/i.png", dest, max_bytes=100,
                                                                 check_response=refuse))
        self.assertFalse(dest.exists())

    async def test_a_trickling_body_times_out(self):
        # A byte every 25 s never trips httpx's per-read timeout.
        clock = {"t": 0.0}

        def trickle():
            async def body():
                for _ in range(20):
                    clock["t"] += 25
                    yield b"x"
            return httpx.Response(200, content=body())
        routes = {"https://a.example.test/f": lambda r: trickle()}
        async with self.fetcher(routes, clock=lambda: clock["t"]) as f:
            await self.assertCode("timeout", f.download("https://a.example.test/f", self.tmp / "f", max_bytes=1000))
            await self.assertCode("timeout", f.get_text("https://a.example.test/f", max_bytes=1000))
        self.assertFalse((self.tmp / "f").exists())

    async def test_a_slow_but_steady_body_is_kept(self):
        clock = {"t": 0.0}

        async def body():
            for _ in range(5):
                clock["t"] += 50
                yield b"y" * (64 * 1024)
        routes = {"https://a.example.test/f": lambda r: httpx.Response(200, content=body())}
        async with self.fetcher(routes, clock=lambda: clock["t"]) as f:
            dl = await f.download("https://a.example.test/f", self.tmp / "f", max_bytes=10 * 1024 * 1024)
        self.assertEqual(dl.bytes, 5 * 64 * 1024)

    async def test_too_many_redirects(self):
        routes = {f"https://a.example.test/{i}": redirect(f"/{i + 1}") for i in range(10)}
        async with self.fetcher(routes) as f:
            await self.assertCode("too_many_redirects", f.probe("https://a.example.test/0"))
        self.assertEqual(len(self.seen), 6)

    async def test_non_http_location_refused(self):
        for loc in ("file:///etc/passwd", "gopher://a.example.test/", "ftp://a.example.test/x"):
            async with self.fetcher({"https://a.example.test/x": redirect(loc)}) as f:
                await self.assertCode("unsupported_scheme", f.probe("https://a.example.test/x"))

    async def test_unsafe_address_maps_to_blocked_address(self):
        from orchestrator_helpers.fetch_guard import UnsafeFetchURLError

        def refuse(_url):
            raise UnsafeFetchURLError("non-public")

        async with self.fetcher({}, assert_safe=refuse) as f:
            await self.assertCode("blocked_address", f.probe("https://a.example.test/x"))
        self.assertEqual(self.seen, [])


class Bodies(FetchBase):
    async def test_content_length_over_cap_refused_before_body(self):
        read = []

        def big(request):
            stream = httpx.ByteStream(b"x" * 10)
            read.append(True)
            return httpx.Response(200, headers={"content-length": "999999"}, stream=stream)

        async with self.fetcher({"https://a.example.test/f": big}) as f:
            await self.assertCode("too_large", f.download("https://a.example.test/f", self.tmp / "f", max_bytes=1000))
        self.assertFalse((self.tmp / "f").exists())

    async def test_stream_over_cap_aborts_and_removes_partial_file(self):
        async def chunks():
            for _ in range(50):
                yield b"y" * 65536

        routes = {"https://a.example.test/f": httpx.Response(200, content=chunks())}
        async with self.fetcher(routes) as f:
            await self.assertCode("too_large", f.download("https://a.example.test/f", self.tmp / "f", max_bytes=200_000))
        self.assertFalse((self.tmp / "f").exists())

    async def test_download_writes_hashes_and_names(self):
        routes = {"https://a.example.test/dl?x=1": httpx.Response(
            200, content=b"abc", headers={"content-type": "application/zip; charset=binary",
                                          "content-disposition": 'attachment; filename="../../evil\n.zip"'})}
        async with self.fetcher(routes) as f:
            d = await f.download("https://a.example.test/dl?x=1", self.tmp / "f", max_bytes=10)
        self.assertEqual((d.bytes, d.content_type, d.filename), (3, "application/zip", "_.._evil_.zip"))
        self.assertEqual(d.sha256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        self.assertEqual((self.tmp / "f").read_bytes(), b"abc")

    async def test_download_404_and_other_status(self):
        async with self.fetcher({"https://a.example.test/500": httpx.Response(500)}) as f:
            await self.assertCode("not_found", f.download("https://a.example.test/missing", self.tmp / "a", max_bytes=10))
            e = await self.assertCode("upstream_status", f.download("https://a.example.test/500", self.tmp / "b", max_bytes=10))
        self.assertEqual(e.detail, "500")

    async def test_cancel_event_stops_download(self):
        ev = threading.Event()

        async def chunks():
            yield b"1" * 1000
            ev.set()
            yield b"2" * 1000

        async with self.fetcher({"https://a.example.test/f": httpx.Response(200, content=chunks())}) as f:
            await self.assertCode("cancelled", f.download("https://a.example.test/f", self.tmp / "f",
                                                           max_bytes=10_000, cancel_event=ev))
        self.assertFalse((self.tmp / "f").exists())

    async def test_on_bytes_refusal_stops_download(self):
        def refuse(total):
            if total > 1000:
                raise ImportFailure("insufficient_storage")

        async with self.fetcher({"https://a.example.test/f": httpx.Response(200, content=b"z" * 5000)}) as f:
            await self.assertCode("insufficient_storage", f.download("https://a.example.test/f", self.tmp / "f",
                                                                      max_bytes=10_000, on_bytes=refuse))
        self.assertFalse((self.tmp / "f").exists())

    async def test_timeout_and_network_errors_map_to_codes(self):
        def slow(request):
            raise httpx.ReadTimeout("slow", request=request)

        def down(request):
            raise httpx.ConnectError("connection refused", request=request)

        def nxdomain(request):
            raise httpx.ConnectError("[Errno -2] Name or service not known", request=request)

        async with self.fetcher({"https://a.example.test/slow": slow, "https://a.example.test/down": down,
                                 "https://a.example.test/nx": nxdomain}) as f:
            await self.assertCode("timeout", f.probe("https://a.example.test/slow"))
            await self.assertCode("network_error", f.probe("https://a.example.test/down"))
            await self.assertCode("dns_failed", f.probe("https://a.example.test/nx"))

    async def test_get_json(self):
        routes = {"https://api.example.test/j": httpx.Response(200, json={"a": 1}),
                  "https://api.example.test/bad": httpx.Response(200, content=b"not json")}
        async with self.fetcher(routes) as f:
            status, obj, _h = await f.get_json("https://api.example.test/j")
            self.assertEqual((status, obj), (200, {"a": 1}))
            self.assertEqual((await f.get_json("https://api.example.test/bad"))[1], None)
            await self.assertCode("too_large", f.get_json("https://api.example.test/j", max_bytes=3))


class Names(unittest.TestCase):
    def test_redact_url_strips_userinfo_query_fragment(self):
        self.assertEqual(redact_url("https://user:pw@Example.TEST:8443/a/b?token=x#frag"),
                         "https://example.test:8443/a/b")
        self.assertEqual(redact_url("http://[::1]/x?y"), "http://[::1]/x")
        self.assertEqual(redact_url("not a url"), "<unparseable url>")
        text = "failed GET https://codeload.example.test/x?token=SECRET and git://h.test/r?k=v"
        self.assertEqual(redact_text(text), "failed GET https://codeload.example.test/x and git://h.test/r")

    def test_disposition_filename_sanitized(self):
        self.assertEqual(disposition_filename('attachment; filename="report.pdf"'), "report.pdf")
        self.assertEqual(disposition_filename("attachment; filename*=UTF-8''r%C3%A9sum%C3%A9.pdf"), "résumé.pdf")
        self.assertEqual(disposition_filename('attachment; filename="/etc/passwd"'), "_etc_passwd")
        self.assertEqual(disposition_filename(None), "")
        self.assertEqual(sanitize_name(" .. "), "download")
        self.assertEqual(sanitize_name("a\x00b\x1fc"), "a_b_c")
        self.assertEqual(len(sanitize_name("é" * 200).encode()), 120)


class TokenScope(FetchBase):
    async def test_token_sent_only_to_exact_github_hosts_over_https(self):
        urls = ["https://github.com/o/r", "https://api.github.com/repos/o/r",
                "https://raw.githubusercontent.com/o/r/m/x", "http://github.com/o/r",
                "https://github.com.example.test/o/r", "https://gist.githubusercontent.com/o/x",
                "https://codeload.github.com/o/r/tar.gz/x"]
        routes = {u: httpx.Response(200) for u in urls}
        async with self.fetcher(routes, github_token=TOKEN) as f:
            for u in urls:
                await f.probe(u)
        got = {str(r.url): r.headers.get("authorization") for r in self.seen}
        self.assertEqual(got["https://github.com/o/r"], f"token {TOKEN}")
        self.assertEqual(got["https://api.github.com/repos/o/r"], f"token {TOKEN}")
        self.assertEqual(got["https://raw.githubusercontent.com/o/r/m/x"], f"token {TOKEN}")
        for u in urls[3:]:
            self.assertIsNone(got[u], u)

    async def test_token_not_forwarded_to_codeload_after_redirect(self):
        routes = {
            "https://api.github.com/repos/o/r/tarball/abc": redirect("https://codeload.github.com/o/r/legacy.tar.gz/abc?token=TEMP"),
            "https://codeload.github.com/o/r/legacy.tar.gz/abc?token=TEMP": httpx.Response(200, content=b"t"),
        }
        async with self.fetcher(routes, github_token=TOKEN) as f:
            await f.download("https://api.github.com/repos/o/r/tarball/abc", self.tmp / "t", max_bytes=10)
        self.assertEqual(self.seen[0].headers.get("authorization"), f"token {TOKEN}")
        self.assertIsNone(self.seen[1].headers.get("authorization"))
        self.assertEqual(self.seen[1].headers["user-agent"], "RedAmon-WorkspaceImport/1.0")

    async def test_token_absent_from_results_exceptions_and_logs(self):
        routes = {"https://api.github.com/x": redirect("https://api.github.com/y"),
                  "https://api.github.com/y": httpx.Response(500)}
        with self.assertLogs(level=logging.DEBUG) as logs:
            logging.getLogger("probe").debug("start")
            async with self.fetcher(routes, github_token=TOKEN) as f:
                p = await f.probe("https://api.github.com/x")
                e = await self.assertCode("upstream_status", f.download("https://api.github.com/x", self.tmp / "d", max_bytes=9))
        for text in (repr(p), str(e), e.detail, repr(e.args), "\n".join(logs.output)):
            self.assertNotIn(TOKEN, text)

    async def test_unexpected_error_log_has_no_url_query(self):
        url = "https://codeload.example.test/x?token=SENTINEL"
        try:
            raise RuntimeError(f"boom while fetching {url}")
        except RuntimeError as e:
            from workspace_import.redact import safe_traceback
            logged = f"{type(e).__name__}\n{safe_traceback(e)}"
        self.assertNotIn("SENTINEL", logged)
        self.assertNotIn("SENTINEL", redact_text(f"boom while fetching {url}"))


if __name__ == "__main__":
    unittest.main()
