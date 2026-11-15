"""The fetcher contract on the real ``GuardedFetcher``: httpx, the pinned transport and
the egress guard, against a local ``http.server`` that serves the fixture sites.

No real network: the guard's resolver is patched so the test host names map to
127.0.0.1, every other name resolves to nothing, and 127.0.0.1 (the test server) is the
only address the guard lets through; everything else it judges as in production.
"""

from __future__ import annotations

import ast
import ipaddress
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from orchestrator_helpers import fetch_guard  # noqa: E402
from tradecraft.net import GuardedFetcher  # noqa: E402
from tradecraft_doubles import (  # noqa: E402
    CONTRACT_HOST,
    OTHER_HOST,
    ContractHarness,
    FakeBrowser,
    FetcherContractSuite,
    FixtureSite,
    RecordingMcp,
    RenderContractSuite,
    run,
)

SERVER_IP = "127.0.0.1"
_ORIGINAL_DISALLOWED = fetch_guard._is_disallowed_ip


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - http.server's naming
        srv = self.server
        host_header = self.headers.get("Host", "")
        srv.received.append((f"http://{host_header}{self.path}",
                             {k.lower(): v for k, v in self.headers.items()}))
        ans = srv.site.answer(host_header.split(":")[0], urlsplit(self.path).path)
        if ans is None:
            self.send_error(502)
            return
        self.send_response(ans.status)
        for k, v in ans.headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(ans.body)))
        self.end_headers()
        self.wfile.write(ans.body)

    def log_message(self, *_args):
        pass


class LocalSites:
    """A threaded local server for the fixture sites, plus the resolver patches."""

    def __init__(self, names=(CONTRACT_HOST, OTHER_HOST)):
        self.server = ThreadingHTTPServer((SERVER_IP, 0), _Handler)
        self.port = self.server.server_address[1]
        self.server.site = FixtureSite(port=self.port)
        self.server.received = []
        self.names = {n: [SERVER_IP] for n in names}
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.patches = [
            patch.object(fetch_guard, "_resolve_ips", self.resolve),
            patch.object(fetch_guard, "_is_disallowed_ip",
                         lambda ip: False if ip == SERVER_IP else _ORIGINAL_DISALLOWED(ip)),
        ]
        for p in self.patches:
            p.start()

    def resolve(self, host):
        h = host.lower().rstrip(".")
        if h in self.names:
            answers = self.names[h]
            return [answers.pop(0)] if len(answers) > 1 else list(answers)
        try:
            ipaddress.ip_address(h)
            return [h]
        except ValueError:
            return []

    def close(self):
        for p in self.patches:
            p.stop()
        self.server.shutdown()
        self.server.server_close()


def _browser_from_script(sites: LocalSites, calls: list):
    """An execute_playwright stand-in that renders the URL the guarded script navigates to."""
    browser = FakeBrowser(sites.server.site)

    async def reply(args):
        calls.append(args)
        m = re.search(r"page\.goto\((.+?), wait_until=", args["script"])
        rendered = await browser.render(ast.literal_eval(m.group(1)))
        return rendered.html or "[ERROR] Navigation failed: not found"

    return reply


def local_harness() -> ContractHarness:
    sites = LocalSites()
    calls: list = []
    fetcher = GuardedFetcher(RecordingMcp(reply=_browser_from_script(sites, calls)))
    return ContractHarness(
        fetcher=fetcher,
        base=lambda host: f"http://{host}:{sites.port}",
        requests=lambda: list(sites.server.received),
        browser_calls=lambda: len(calls),
        close=sites.close,
    )


class TestGuardedFetcherContract(FetcherContractSuite):
    def make_harness(self):
        return local_harness()


class TestGuardedFetcherRender(RenderContractSuite):
    def make_harness(self):
        return local_harness()


def test_rebinding_is_refused_at_connect():
    """The first answer passes the URL check, the second (at connect) is internal: the
    pinned transport judges the address it dials, so the request never leaves."""
    sites = LocalSites(names=())
    sites.names["rebind.tc-fixture.test"] = [SERVER_IP, "10.0.0.7"]
    try:
        r = run(GuardedFetcher().get(f"http://rebind.tc-fixture.test:{sites.port}/ok.html"))
    finally:
        sites.close()
    assert r.error == "unsafe_address"
    assert sites.server.received == []


def test_failure_logs_carry_code_and_host_only(caplog):
    sites = LocalSites()
    try:
        with caplog.at_level("WARNING"):
            run(GuardedFetcher().get(f"http://{CONTRACT_HOST}:{sites.port}/to-private?token=abc123"))
    finally:
        sites.close()
    lines = [r.getMessage() for r in caplog.records if "[tradecraft]" in r.getMessage()]
    assert lines and all("abc123" not in line and "meta-data" not in line for line in lines)
    assert any("unsafe_address" in line for line in lines)
