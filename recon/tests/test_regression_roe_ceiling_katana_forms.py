"""Regression: Katana's form fetch ignored the RoE ceiling (R-8, B-R8c).

After the crawlers, ``katana_helpers.fetch_forms_from_urls`` GETs up to 100
crawled HTML pages in-process (urllib) to extract their forms. It never took a
slot of recon's one request clock (recon/helpers/request_pacer.py): the FP lab
run with a 2 rps ceiling logged 12 of these GETs in 50 ms.

Now every request the fetcher puts on the wire takes a slot first, each
redirect hop included (a refused off-host hop takes none), and a 429 pushes
every in-process requester's next slot back by its Retry-After. With no
ceiling nothing waits and the wire is byte-for-byte what it was.

Real loopback servers answer the real fetcher; only the pacer's clock is
fake: it is frozen at T0 and a sleep records the slot it was handed, which
the server stamps on the next request it receives (the fetch is sequential).
"""
from __future__ import annotations

import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

_RECON = Path(__file__).resolve().parent.parent
_REPO = _RECON.parent
for _p in (str(_REPO), str(_RECON)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from recon.helpers import circuit_breaker, request_pacer  # noqa: E402
from recon.helpers.resource_enum import katana_helpers  # noqa: E402

T0 = 100.0
FORM = b"<html><body><form action='/s' method='post'><input name='%s'></form></body></html>"
NO_CEILING = [
    None,
    {},
    {"ROE_ENABLED": False, "ROE_GLOBAL_MAX_RPS": 2},
    {"ROE_ENABLED": True, "ROE_GLOBAL_MAX_RPS": 0},
]


class SlotClock:
    """Frozen at T0; a sleep is the wait for slot T0 + seconds. One shared
    value, not per thread: the server thread reads what the fetcher was handed."""

    def __init__(self):
        self.at = T0

    def now(self) -> float:
        return T0

    def sleep(self, seconds: float) -> None:
        self.at = T0 + seconds


class Lab:
    """127.0.0.1 serves the pages; 127.0.0.2 is another host (a refused hop)."""

    def __init__(self, clock: SlotClock):
        self.clock = clock
        self.wire: list = []     # (host:port, path, slot, raw header lines)
        lab = self

        class Page(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_a):
                pass

            def do_GET(self):
                lab.wire.append((self.headers.get("Host"), self.path, lab.clock.at,
                                 [f"{k}: {v}" for k, v in self.headers.items()]))
                if self.path == "/hop":
                    self._send(302, b"", {"Location": "/landing"})
                elif self.path == "/away":
                    self._send(302, b"", {"Location": f"http://127.0.0.2:{lab.other_port}/x"})
                elif self.path == "/busy":
                    self._send(429, b"slow down", {"Retry-After": "5", "Content-Type": "text/html"})
                else:
                    name = self.path.strip("/").encode() or b"root"
                    self._send(200, FORM % name, {"Content-Type": "text/html"})

            def _send(self, code, body, headers):
                self.send_response(code)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.page = ThreadingHTTPServer(("127.0.0.1", 0), Page)
        try:
            self.other = ThreadingHTTPServer(("127.0.0.2", 0), Page)
        except OSError as exc:
            self.page.server_close()
            pytest.skip(f"cannot bind 127.0.0.2 here: {exc}")
        self.port = self.page.server_address[1]
        self.other_port = self.other.server_address[1]
        for server in (self.page, self.other):
            threading.Thread(target=server.serve_forever, daemon=True).start()

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    def paths(self) -> list:
        return [path for _, path, _, _ in self.wire]

    def slots(self) -> list:
        return [slot for _, _, slot, _ in self.wire]

    def close(self):
        for server in (self.page, self.other):
            server.shutdown()
            server.server_close()


@pytest.fixture(autouse=True)
def _fresh_run():
    request_pacer.reset()
    circuit_breaker.reset_registry()
    yield
    request_pacer.reset()
    circuit_breaker.reset_registry()


@pytest.fixture
def clock():
    return SlotClock()


@pytest.fixture
def lab(clock):
    socket.setdefaulttimeout(5)
    lab = Lab(clock)
    yield lab
    lab.close()
    socket.setdefaulttimeout(None)


@pytest.fixture
def ceiling(clock, monkeypatch):
    def configure(rps):
        request_pacer.configure({"ROE_ENABLED": True, "ROE_GLOBAL_MAX_RPS": rps})
        monkeypatch.setattr(request_pacer._PACER, "_clock", clock.now)
        monkeypatch.setattr(request_pacer._PACER, "_sleep", clock.sleep)
    return configure


def _fields(forms) -> set:
    return {i.get("name") for f in forms for i in f.get("inputs", [])}


def test_the_form_fetch_holds_the_one_process_clock():
    """Imported under another name (helpers.request_pacer) it would be a second clock."""
    assert katana_helpers.request_pacer is sys.modules["recon.helpers.request_pacer"]


def test_every_form_fetch_takes_its_own_slot(ceiling, lab):
    ceiling(2)
    urls = [lab.url(f"/p{i}") for i in range(6)]

    forms = katana_helpers.fetch_forms_from_urls(urls)

    assert _fields(forms) == {f"p{i}" for i in range(6)}
    assert lab.paths() == [f"/p{i}" for i in range(6)]
    assert lab.slots() == pytest.approx([T0 + k / 2 for k in range(6)])


@pytest.mark.parametrize("settings", [
    {},                                                      # urllib's own redirect handler
    {"ROE_EXCLUDED_HOSTS": ["192.0.2.0/24"]},                # the same-host-only handler
], ids=["redirects_free", "redirects_contained"])
def test_each_redirect_hop_takes_a_slot(ceiling, lab, settings):
    ceiling(2)
    run = {"ROE_ENABLED": True, "ROE_GLOBAL_MAX_RPS": 2, **settings}

    forms = katana_helpers.fetch_forms_from_urls([lab.url("/hop"), lab.url("/p1")], settings=run)

    assert _fields(forms) == {"landing", "p1"}
    assert lab.paths() == ["/hop", "/landing", "/p1"]
    assert lab.slots() == pytest.approx([T0, T0 + 0.5, T0 + 1.0])


def test_a_refused_off_host_hop_takes_no_slot(ceiling, lab):
    ceiling(2)
    run = {"ROE_ENABLED": True, "ROE_GLOBAL_MAX_RPS": 2, "ROE_EXCLUDED_HOSTS": ["127.0.0.2"]}

    katana_helpers.fetch_forms_from_urls([lab.url("/away"), lab.url("/p1")], settings=run)

    assert lab.paths() == ["/away", "/p1"]
    assert lab.slots() == pytest.approx([T0, T0 + 0.5])
    # Two requests, two slots: the next free one is the third.
    assert request_pacer._PACER._next == pytest.approx(T0 + 1.0)


def test_a_429_backs_every_requester_off(ceiling, lab):
    ceiling(2)

    forms = katana_helpers.fetch_forms_from_urls([lab.url("/busy"), lab.url("/p1")])

    assert _fields(forms) == {"p1"}
    assert lab.paths() == ["/busy", "/p1"]
    # Retry-After: 5 pushed the shared clock, not just this fetcher's next request.
    assert lab.slots() == pytest.approx([T0, T0 + 5.0])
    assert request_pacer._PACER._next == pytest.approx(T0 + 5.5)


@pytest.mark.parametrize("settings", NO_CEILING, ids=["none", "empty", "roe-off", "rps-0"])
def test_no_ceiling_never_touches_the_clock_and_the_wire_is_unchanged(settings, lab, monkeypatch):
    request_pacer.configure(settings)
    touched = []
    monkeypatch.setattr(request_pacer._PACER, "_clock", lambda: touched.append("clock") or T0)
    monkeypatch.setattr(request_pacer._PACER, "_sleep", touched.append)

    forms = katana_helpers.fetch_forms_from_urls(
        [lab.url("/hop"), lab.url("/busy"), lab.url("/p1")], settings=settings)

    assert touched == []
    assert _fields(forms) == {"landing", "p1"}
    assert lab.paths() == ["/hop", "/landing", "/busy", "/p1"]
    host = f"127.0.0.1:{lab.port}"
    # urllib's request, header for header: nothing added, removed or reordered.
    for _, _, _, headers in lab.wire:
        assert headers == [
            "Accept-Encoding: identity",
            f"Host: {host}",
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Connection: close",
        ]
