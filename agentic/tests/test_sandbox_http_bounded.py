"""Bounded reads of a Kali sandbox's answers (group 1, S12 review finding 1).

Whoever is root in a sandbox can make its ports answer anything (iptables with NET_ADMIN, or
another listener). The agent process is shared by every tenant, so an answer it reads must
never cost it more than a small, fixed amount of memory and time:

- the request asks for `Accept-Encoding: identity`, and an answer with any other
  Content-Encoding (a stacked `gzip, gzip` bomb of a few KB inflates to gigabytes, and httpx
  decompresses synchronously, out of reach of any timeout) is refused WITHOUT decoding it;
- the raw bytes are counted as they arrive and the answer is refused past the cap (a declared
  Content-Length over the cap is refused before reading);
- a wall-clock deadline bounds the whole read, a slow drip included;
- JSON is parsed only from the capped buffer.

`sandbox_http.read_answer` is the one helper: the hold watcher uses it, and S11's /sessions
fan-out and proxies must.

Run: ./agentic/run_tests.sh tests/test_sandbox_http_bounded.py
"""
import asyncio
import gzip
import json
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

_AGENTIC_DIR = Path(__file__).resolve().parents[1]
if str(_AGENTIC_DIR) not in sys.path:
    sys.path.insert(0, str(_AGENTIC_DIR))

import httpx  # noqa: E402
import httpx._decoders as httpx_decoders  # noqa: E402

import sandbox_http  # noqa: E402
from sandbox_http import SandboxAnswerRefused, read_answer  # noqa: E402

URL = "http://redamon-kali-0123456789abcdef-a1b2c3:8013/sessions"


def bomb(inflated: int) -> bytes:
    """A stacked gzip of `inflated` zero bytes: a few KB on the wire."""
    return gzip.compress(gzip.compress(b"\0" * inflated, compresslevel=9), compresslevel=9)


class Recorder:
    def __init__(self):
        self.requests = []


def resp(status, body=b"", headers=None):
    """An answer whose body is still unread, as a real transport hands it over (a Response
    built with content=bytes is read, and decoded, at construction)."""
    return httpx.Response(status, headers=headers or {}, stream=httpx.ByteStream(body))


def client_for(handler, recorder=None):
    async def wrapped(request):
        if recorder is not None:
            recorder.requests.append(request)
        result = handler(request)
        if asyncio.iscoroutine(result):
            result = await result
        return result
    return httpx.AsyncClient(transport=httpx.MockTransport(wrapped))


class DecoderSpy:
    """Fails the test if any httpx content decoder decodes a byte."""

    def __init__(self):
        self.calls = []

    def __enter__(self):
        self._patches = []
        for name in ("GZipDecoder", "DeflateDecoder", "BrotliDecoder", "ZStandardDecoder", "MultiDecoder"):
            cls = getattr(httpx_decoders, name, None)
            if cls is None:
                continue

            def spy(self_, data, _name=name, _calls=self.calls):
                _calls.append(_name)
                raise AssertionError(f"{_name} decoded a sandbox answer")

            p = mock.patch.object(cls, "decode", spy)
            p.start()
            self._patches.append(p)
        return self

    def __exit__(self, *exc):
        for p in reversed(self._patches):
            p.stop()


async def run_read(client, **kw):
    async with client:
        return await read_answer(client, "GET", URL, **kw)


class TestEncodings(unittest.IsolatedAsyncioTestCase):

    async def test_a_stacked_gzip_answer_is_never_decompressed(self):
        body = bomb(16 * 1024 * 1024)
        self.assertLess(len(body), 64 * 1024)
        rec = Recorder()
        client = client_for(lambda r: resp(
            200, body, {"content-encoding": "gzip, gzip", "content-type": "application/json"}), rec)
        with DecoderSpy() as spy:
            with self.assertRaises(SandboxAnswerRefused) as ctx:
                await run_read(client)
        self.assertEqual(ctx.exception.reason, "encoding")
        self.assertEqual(spy.calls, [], "no decoder ran")
        self.assertEqual(rec.requests[0].headers.get("accept-encoding"), "identity")

    async def test_the_spy_sees_what_a_plain_httpx_read_does(self):
        """Control: the unbounded read the watcher used (client.get, then .json()) decodes."""
        body = gzip.compress(gzip.compress(b'{"sessions": []}'))
        client = client_for(lambda r: resp(200, body, {"content-encoding": "gzip, gzip"}))
        with DecoderSpy() as spy:
            async with client:
                with self.assertRaises(AssertionError):
                    await client.get(URL)
        self.assertTrue(spy.calls)

    async def test_every_compressed_encoding_is_refused(self):
        for encoding in ("gzip", "GZIP", "deflate", "br", "zstd", "identity, gzip", "x-unknown"):
            with self.subTest(encoding=encoding):
                client = client_for(lambda r, e=encoding: resp(
                    200, b'{"sessions": []}', {"content-encoding": e}))
                with DecoderSpy() as spy, self.assertRaises(SandboxAnswerRefused) as ctx:
                    await run_read(client)
                self.assertEqual(ctx.exception.reason, "encoding")
                self.assertEqual(spy.calls, [])

    async def test_identity_or_no_encoding_is_read(self):
        for headers in ({}, {"content-encoding": "identity"}, {"content-encoding": "Identity"}):
            with self.subTest(headers=headers):
                client = client_for(lambda r, h=headers: resp(200, b'{"sessions": [1]}', h))
                answer = await run_read(client)
                self.assertEqual(answer.status, 200)
                self.assertEqual(answer.json(), {"sessions": [1]})

    async def test_the_callers_headers_cannot_ask_for_compression(self):
        rec = Recorder()
        client = client_for(lambda r: resp(200, b"{}"), rec)
        await run_read(client, headers={"Accept-Encoding": "gzip", "Authorization": "Bearer t"})
        sent = rec.requests[0].headers
        self.assertEqual(sent.get("accept-encoding"), "identity")
        self.assertEqual(sent.get("authorization"), "Bearer t")


class TestSize(unittest.IsolatedAsyncioTestCase):

    async def test_a_raw_body_over_the_cap_is_refused(self):
        big = b'{"sessions": [' + b'1,' * 400_000 + b'1]}'
        client = client_for(lambda r: resp(200, big))
        with self.assertRaises(SandboxAnswerRefused) as ctx:
            await run_read(client, max_bytes=64 * 1024)
        self.assertEqual(ctx.exception.reason, "too_large")

    async def test_an_endless_stream_without_length_stops_at_the_cap(self):
        sent = []

        async def endless():
            while True:
                sent.append(1)
                yield b"x" * 65536
                await asyncio.sleep(0)

        client = client_for(lambda r: httpx.Response(200, content=endless()))
        started = time.monotonic()
        with self.assertRaises(SandboxAnswerRefused) as ctx:
            await run_read(client, max_bytes=256 * 1024)
        self.assertEqual(ctx.exception.reason, "too_large")
        self.assertLess(time.monotonic() - started, 2.0)
        self.assertLess(len(sent), 16, "reading stopped at the cap, not at the end")

    async def test_a_declared_length_over_the_cap_is_refused_before_reading(self):
        async def never_read():
            raise AssertionError("the body was read")
            yield b""  # noqa: unreachable - makes this an async generator

        client = client_for(lambda r: httpx.Response(
            200, headers={"content-length": str(10 * 1024 * 1024)}, content=never_read()))
        with self.assertRaises(SandboxAnswerRefused) as ctx:
            await run_read(client, max_bytes=1024)
        self.assertEqual(ctx.exception.reason, "too_large")

    async def test_exactly_the_cap_is_read_one_more_byte_is_not(self):
        cap = 1000
        body = b'"' + b"a" * (cap - 2) + b'"'
        self.assertEqual(len(body), cap)
        client = client_for(lambda r: resp(200, body))
        self.assertEqual((await run_read(client, max_bytes=cap)).json(), "a" * (cap - 2))
        client = client_for(lambda r: resp(200, body + b" "))
        with self.assertRaises(SandboxAnswerRefused):
            await run_read(client, max_bytes=cap)

    async def test_the_default_cap(self):
        self.assertGreaterEqual(sandbox_http.MAX_ANSWER_BYTES, 256 * 1024)
        self.assertLessEqual(sandbox_http.MAX_ANSWER_BYTES, 1024 * 1024)


class TestDeadline(unittest.IsolatedAsyncioTestCase):

    async def test_a_slow_drip_is_bounded_by_the_wall_clock(self):
        async def drip():
            yield b'{"sessions": ['
            while True:
                await asyncio.sleep(0.05)
                yield b"1,"

        client = client_for(lambda r: httpx.Response(200, content=drip()))
        started = time.monotonic()
        with self.assertRaises(SandboxAnswerRefused) as ctx:
            await run_read(client, deadline_s=0.4)
        elapsed = time.monotonic() - started
        self.assertEqual(ctx.exception.reason, "deadline")
        self.assertLess(elapsed, 1.0)

    async def test_a_silent_peer_is_bounded_too(self):
        async def silent(request):
            await asyncio.Event().wait()

        client = client_for(silent)
        started = time.monotonic()
        with self.assertRaises(SandboxAnswerRefused) as ctx:
            await run_read(client, deadline_s=0.3)
        self.assertEqual(ctx.exception.reason, "deadline")
        self.assertLess(time.monotonic() - started, 1.0)


class TestJson(unittest.IsolatedAsyncioTestCase):

    async def test_status_and_body_are_kept(self):
        client = client_for(lambda r: resp(401, b'{"error": "unauthorized"}'))
        answer = await run_read(client)
        self.assertEqual(answer.status, 401)
        self.assertEqual(answer.json(), {"error": "unauthorized"})

    async def test_not_json_raises_value_error(self):
        for body in (b"not json", b"", b"\xff\xfe"):
            with self.subTest(body=body):
                client = client_for(lambda r, b=body: resp(200, b))
                answer = await run_read(client)
                with self.assertRaises(ValueError):
                    answer.json()

    async def test_a_post_body_is_sent_as_json(self):
        rec = Recorder()
        client = client_for(lambda r: resp(200, b'{"ok": true}'), rec)
        async with client:
            answer = await read_answer(client, "POST", URL, json={"command": "sysinfo"})
        self.assertEqual(json.loads(rec.requests[0].content), {"command": "sysinfo"})
        self.assertEqual(answer.json(), {"ok": True})


if __name__ == "__main__":
    unittest.main()
