"""GuardedFetcher through the REAL pinned transport: no hop of an import can
reach a private, loopback, metadata or CGNAT address.

Cloned from test_tradecraft_verify_ssrf.py: a patched resolver plays DNS, and
a loopback server plays "the internet" behind a dialer that records which
checked address it was asked to connect to.
"""
from __future__ import annotations

import asyncio
import http.server
import threading
import unittest
from unittest.mock import patch

import httpcore

from orchestrator_helpers import fetch_guard
from workspace_import.errors import ImportFailure
from workspace_import.fetch import GuardedFetcher

PUBLIC_IP = "93.184.216.34"


def _resolver(table):
    """Names from `table`; anything else (literal IPs) through the real resolver."""
    real = fetch_guard._resolve_ips

    def resolve(host):
        return list(table[host]) if host in table else real(host)
    return resolve


class _LoopbackDialer(httpcore.AsyncNetworkBackend):
    def __init__(self, port):
        self._real = httpcore.AnyIOBackend()
        self._port = port
        self.dialed = []

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        self.dialed.append(host)
        return await self._real.connect_tcp("127.0.0.1", self._port, timeout=timeout,
                                            local_address=local_address, socket_options=socket_options)

    async def connect_unix_socket(self, path, timeout=None, socket_options=None):
        raise NotImplementedError

    async def sleep(self, seconds):
        await self._real.sleep(seconds)


class _Handler(http.server.BaseHTTPRequestHandler):
    requests: list = []
    LOCATIONS = {
        "/to-metadata": "http://169.254.169.254/latest/meta-data/",
        "/to-private": "http://internal.example.test/admin",
        "/to-loopback": "http://127.0.0.1:8080/",
    }

    def do_GET(self):
        type(self).requests.append(self.path)
        if self.path in self.LOCATIONS:
            self.send_response(302)
            self.send_header("Location", self.LOCATIONS[self.path])
            self.end_headers()
            return
        body = b"public file"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_a):
        pass


class FetcherSSRF(unittest.TestCase):
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
        self.dns = {"files.example.test": [PUBLIC_IP], "internal.example.test": ["10.1.2.3"]}

    def transport(self):
        t = fetch_guard.pinned_async_transport()
        t._pool._network_backend._inner = self.dialer
        return t

    def probe(self, url, dns=None):
        async def go():
            async with GuardedFetcher(transport=self.transport()) as f:
                return await f.probe(url)

        with patch.object(fetch_guard, "_resolve_ips", _resolver(dns or self.dns)):
            try:
                return asyncio.run(go())
            except ImportFailure as e:
                return e

    def assertBlocked(self, result):
        self.assertIsInstance(result, ImportFailure)
        self.assertEqual(result.code, "blocked_address")

    def test_public_file_is_fetched_through_the_checked_address(self):
        p = self.probe("http://files.example.test/file.bin")
        self.assertEqual((p.status, p.head), (200, b"public file"))
        self.assertEqual(self.dialer.dialed, [PUBLIC_IP])

    def test_private_answer_refused(self):
        self.assertBlocked(self.probe("http://internal.example.test/x"))
        self.assertEqual(self.dialer.dialed, [])

    def test_rebinding_second_answer_refused(self):
        # The hop check sees a public answer; the connect-time resolve gets an
        # internal one, and that is the one that decides.
        answers = iter([[PUBLIC_IP], ["127.0.0.1"]])
        with patch.object(fetch_guard, "_resolve_ips", lambda _h: next(answers)):
            async def go():
                async with GuardedFetcher(transport=self.transport()) as f:
                    return await f.probe("http://rebind.example.test/x")
            with self.assertRaises(ImportFailure) as ctx:
                asyncio.run(go())
        self.assertEqual(ctx.exception.code, "blocked_address")
        self.assertEqual(self.dialer.dialed, [])

    def test_metadata_hostname_refused(self):
        self.assertBlocked(self.probe("http://metadata.google.internal/computeMetadata/v1/"))
        self.assertBlocked(self.probe("http://169.254.169.254/latest/meta-data/"))
        self.assertEqual(self.dialer.dialed, [])

    def test_ipv4_mapped_ipv6_refused(self):
        self.assertBlocked(self.probe("http://[::ffff:10.0.0.1]/x"))
        self.assertBlocked(self.probe("http://mapped.example.test/x", {"mapped.example.test": ["::ffff:192.168.1.1"]}))
        self.assertEqual(self.dialer.dialed, [])

    def test_redirect_into_metadata_refused_before_second_request(self):
        for path in ("/to-metadata", "/to-private", "/to-loopback"):
            with self.subTest(path=path):
                _Handler.requests = []
                self.dialer.dialed = []
                self.assertBlocked(self.probe(f"http://files.example.test{path}"))
                self.assertEqual(_Handler.requests, [path])
                self.assertEqual(self.dialer.dialed, [PUBLIC_IP])

    def test_unix_socket_refused(self):
        backend = fetch_guard._PinnedNetworkBackend(self.dialer)
        with self.assertRaises(fetch_guard.UnsafeFetchURLError):
            asyncio.run(backend.connect_unix_socket("/var/run/docker.sock"))

    def test_cgnat_refused(self):
        self.assertBlocked(self.probe("http://cgnat.example.test/x", {"cgnat.example.test": ["100.64.1.1"]}))
        self.assertBlocked(self.probe("http://100.100.100.100/x"))
        self.assertEqual(self.dialer.dialed, [])


if __name__ == "__main__":
    unittest.main()
