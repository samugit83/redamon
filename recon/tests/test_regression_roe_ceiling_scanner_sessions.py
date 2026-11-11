"""Regression: the RoE ceiling never reached the scanners' own requests (R-8 part B1, D3).

Part A built one process-wide request clock (recon/helpers/request_pacer.py)
and put the security checks on it. The cache-poisoning scan (its 6-worker
confirmation pool), the GraphQL scan, the route exposure prober and the
takeover AI probe still sent their requests unpaced: under a 1 rps ceiling
each of them alone could send several requests a second, and together more.

Now every request they send takes a slot of that one clock first, each retry
and each redirect hop too; a 429 pushes every requester's next slot back; the
route exposure prober takes its own slot and the global one. With no ceiling
nothing waits.

Only the wire is fake: urllib3's ``HTTPConnectionPool._make_request`` (or the
prober's own transport seam), so each module's real session, adapter, redirect
loop and urllib3 retries run. The pacer's clock is frozen and a thread's sleep
is recorded as the slot it was handed, so the wire stamps every request with
its slot whatever order the threads run in. Hosts are under example.test and
example.com.
"""
from __future__ import annotations

import io
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from urllib3.connectionpool import HTTPConnectionPool
from urllib3.exceptions import NewConnectionError
from urllib3.response import HTTPResponse

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.cache_scan import scanner as cache_scanner  # noqa: E402
from recon.graphql_scan import scanner as gql_scanner  # noqa: E402
from recon.helpers import request_pacer  # noqa: E402
from recon.main_recon_modules import subdomain_takeover as takeover  # noqa: E402
from recon.route_exposure import prober  # noqa: E402

T0 = 100.0
CACHE_URL = "https://shop.example.test/home"
GQL = "https://api.example.com/graphql"
HTML = (200, {"Content-Type": "text/html"}, b"<html>plain page</html>")
SCHEMA = (200, {"Content-Type": "application/json"},
          b'{"data": {"__schema": {"queryType": {"name": "Query"}, "types": []}}}')
NO_CEILING = [
    {},
    {"ROE_ENABLED": False, "ROE_GLOBAL_MAX_RPS": 2},
    {"ROE_ENABLED": True, "ROE_GLOBAL_MAX_RPS": 0},
]


@pytest.fixture(autouse=True)
def _fresh_pacers():
    request_pacer.reset()
    prober._reset_pacer()
    yield
    request_pacer.reset()
    prober._reset_pacer()


class SlotClock:
    """A frozen clock. The pacer hands out T0, T0 + 1/C, ... and a thread sleeps
    its slot minus T0, which is kept per thread until the wire reads it."""

    def __init__(self):
        self._local = threading.local()

    def now(self) -> float:
        return T0

    def sleep(self, seconds: float) -> None:
        self._local.at = T0 + seconds

    def stamp(self) -> float:
        at = getattr(self._local, "at", T0)
        self._local.at = T0
        return at


class Wire:
    """Answers every request urllib3 puts on the wire, and records it."""

    def __init__(self, clock: SlotClock):
        self.clock = clock
        self.sent: list = []
        self._lock = threading.Lock()
        self.route = lambda method, url: SCHEMA if method == "POST" else HTML

    def answer(self, pool, method, path):
        url = f"{pool.scheme}://{pool.host}{path}"
        with self._lock:
            self.sent.append((self.clock.stamp(), method, url))
        outcome = self.route(method, url)
        if isinstance(outcome, Exception):
            raise outcome
        status, headers, body = outcome
        return HTTPResponse(body=io.BytesIO(body), headers=headers, status=status,
                            preload_content=False, decode_content=False,
                            request_method=method, request_url=url)

    def stamps(self) -> list:
        return [stamp for stamp, _, _ in self.sent]

    def urls(self) -> list:
        return [url for _, _, url in self.sent]


@pytest.fixture
def clock():
    return SlotClock()


@pytest.fixture
def ceiling(clock, monkeypatch):
    def configure(rps):
        request_pacer.configure({"ROE_ENABLED": True, "ROE_GLOBAL_MAX_RPS": rps})
        monkeypatch.setattr(request_pacer._PACER, "_clock", clock.now)
        monkeypatch.setattr(request_pacer._PACER, "_sleep", clock.sleep)
        return clock
    return configure


@pytest.fixture
def wire(clock, monkeypatch):
    w = Wire(clock)

    def _make_request(pool, conn, method, url, *args, **kwargs):
        return w.answer(pool, method, url)

    monkeypatch.setattr(HTTPConnectionPool, "_make_request", _make_request)
    return w


@pytest.fixture
def no_real_sleep(monkeypatch):
    """urllib3 sleeps a Retry-After itself (time.sleep); the pacer's clock is the fake."""
    import urllib3.util.retry as retry_module
    monkeypatch.setattr(retry_module.time, "sleep", lambda _s: None)


def _one_slot_each(stamps, rps):
    """Every request had a slot of its own on the one clock: T0, T0 + 1/C, ..."""
    assert stamps, "nothing was sent"
    assert sorted(stamps) == pytest.approx([T0 + k / rps for k in range(len(stamps))])


def _cache_scan_one(url=CACHE_URL):
    """One confirmation worker's whole job for one URL, on its own session."""
    return cache_scanner._scan_one_url(url, {}, {}, {}, 0.8, False, 5, False)


def _gql_test(session, endpoint=GQL):
    return gql_scanner.test_single_endpoint(endpoint, {}, 5, {"GRAPHQL_VERIFY_SSL": False},
                                            {}, session, 3)


@pytest.mark.parametrize("module", [cache_scanner, gql_scanner, prober, takeover],
                         ids=["cache_scan", "graphql_scan", "route_exposure", "takeover"])
def test_every_adopter_holds_the_one_process_clock(module):
    """Imported under another name (helpers.request_pacer) it would be a second clock."""
    assert module.request_pacer is sys.modules["recon.helpers.request_pacer"]


# ---------------------------------------------------------------------------
# Cache poisoning: the confirmation sessions
# ---------------------------------------------------------------------------

class TestCacheScan:
    def test_each_request_of_a_url_takes_a_slot(self, ceiling, wire):
        ceiling(2)
        _url, entry, _ = _cache_scan_one()
        assert len(wire.sent) >= 3 and set(wire.urls()) == {CACHE_URL}
        assert entry["oracle"]["cacheable"] is False
        _one_slot_each(wire.stamps(), 2)

    def test_the_confirmation_pool_holds_the_ceiling_together(self, ceiling, wire, monkeypatch):
        ceiling(4)
        urls = [f"https://h{i}.example.test/" for i in range(6)]
        combined = {"http_probe": {"by_url": {u: {"url": u, "status_code": 200} for u in urls}},
                    "resource_enum": {"endpoints": {}, "parameters": {}, "discovered_urls": []},
                    "metadata": {}}
        monkeypatch.setattr(cache_scanner.wcvs_runner, "run_wcvs", lambda *_a, **_k: [])
        out = cache_scanner.run_cache_scan(combined, {"WEB_CACHE_POISON_ENABLED": True,
                                                      "WEB_CACHE_POISON_CONFIRM_WORKERS": 6})
        assert out["cache_scan"]["summary"]["total_findings"] == 0
        assert {u.split("/")[2] for u in wire.urls()} == {f"h{i}.example.test" for i in range(6)}
        _one_slot_each(wire.stamps(), 4)

    def test_a_retried_request_takes_its_own_slot(self, ceiling, wire):
        ceiling(2)
        answers = iter([(503, {}, b"busy"), HTML])
        wire.route = lambda method, url: next(answers)
        session = cache_scanner._build_retry_session()
        try:
            response = session.get(CACHE_URL, timeout=5, verify=False, allow_redirects=False)
        finally:
            session.close()
        assert response.status_code == 200 and len(wire.sent) == 2
        assert wire.stamps() == pytest.approx([T0, T0 + 0.5])

    def test_each_redirect_hop_takes_a_slot(self, ceiling, wire):
        ceiling(2)
        answers = iter([(301, {"Location": "https://shop.example.test/next"}, b""), HTML])
        wire.route = lambda method, url: next(answers)
        session = cache_scanner._build_retry_session()
        try:
            session.get(CACHE_URL, timeout=5, verify=False)
        finally:
            session.close()
        assert wire.urls() == [CACHE_URL, "https://shop.example.test/next"]
        assert wire.stamps() == pytest.approx([T0, T0 + 0.5])

    def test_a_429_pushes_every_requesters_next_slot_back(self, ceiling, wire, no_real_sleep):
        ceiling(2)
        answers = iter([(429, {"Retry-After": "5"}, b""), HTML, HTML])
        wire.route = lambda method, url: next(answers)
        session = cache_scanner._build_retry_session()
        try:
            assert session.get(CACHE_URL, timeout=5, verify=False,
                               allow_redirects=False).status_code == 200
        finally:
            session.close()
        # Another module's next request queues behind the same back-off.
        takeover._probe_for_ai_disambiguation("other.example.test", timeout=3)
        assert wire.stamps() == pytest.approx([T0, T0 + 5, T0 + 5.5])


# ---------------------------------------------------------------------------
# GraphQL: the shared retry session
# ---------------------------------------------------------------------------

class TestGraphqlScan:
    def test_each_introspection_request_takes_a_slot(self, ceiling, wire):
        ceiling(2)
        result = _gql_test(gql_scanner._build_retry_session(0, 0))
        assert result["endpoint_data"]["introspection_enabled"] is True
        assert [m for _, m, _ in wire.sent] == ["POST", "POST", "POST"]
        _one_slot_each(wire.stamps(), 2)

    def test_a_retried_request_takes_its_own_slot(self, ceiling, wire):
        ceiling(2)
        answers = iter([(503, {}, b"busy"), SCHEMA, SCHEMA, SCHEMA])
        wire.route = lambda method, url: next(answers)
        _gql_test(gql_scanner._build_retry_session(1, 0))
        assert len(wire.sent) == 4
        _one_slot_each(wire.stamps(), 2)

    def test_a_final_429_backs_off_at_most_thirty_seconds(self, ceiling, wire):
        """Retry-After is the target's to set: it never stalls the whole run for a day."""
        ceiling(2)
        answers = iter([(429, {"Retry-After": "86400"}, b"")])
        wire.route = lambda method, url: next(answers, SCHEMA)
        _gql_test(gql_scanner._build_retry_session(0, 0))
        _cache_scan_one()
        assert wire.stamps()[:2] == pytest.approx([T0, T0 + 30])

    def test_the_endpoint_pool_holds_the_ceiling_together(self, ceiling, wire):
        ceiling(4)
        endpoints = [f"https://api{i}.example.com/graphql" for i in range(4)]
        combined = {"domain": "example.com",
                    "metadata": {"root_domain": "example.com", "scope_mode": "enumerate",
                                 "include_root_domain": True},
                    "http_probe": {"by_url": {}}}
        settings = {
            "GRAPHQL_SECURITY_ENABLED": True, "GRAPHQL_CONCURRENCY": 4, "GRAPHQL_RATE_LIMIT": 0,
            "GRAPHQL_RETRY_COUNT": 0, "GRAPHQL_VERIFY_SSL": False,
            "GRAPHQL_ENDPOINTS": ",".join(endpoints),
            "SCOPE_GROUPS": [{"scanRoot": "example.com", "orgDomain": "example.com",
                              "mode": "enumerate", "includeRoot": True, "exactHosts": []}],
        }
        out = gql_scanner.run_graphql_scan(combined, settings)
        assert out["graphql_scan"]["summary"]["endpoints_tested"] == 4
        assert set(wire.urls()) == set(endpoints)
        _one_slot_each(wire.stamps(), 4)


def test_cache_graphql_and_takeover_requests_interleave_on_one_clock(ceiling, wire):
    ceiling(5)
    session = gql_scanner._build_retry_session(0, 0)
    with ThreadPoolExecutor(max_workers=3) as pool:
        jobs = [pool.submit(_cache_scan_one), pool.submit(_gql_test, session),
                pool.submit(takeover._probe_for_ai_disambiguation, "dangling.example.test", 3)]
        for job in jobs:
            job.result()
    hosts = {u.split("/")[2] for u in wire.urls()}
    assert hosts == {"shop.example.test", "api.example.com", "dangling.example.test"}
    _one_slot_each(wire.stamps(), 5)


# ---------------------------------------------------------------------------
# Route exposure: its own pacer AND the process-wide one
# ---------------------------------------------------------------------------

class _Answer:
    def __init__(self, status=200, headers=None):
        self.status_code = status
        self.headers = headers or {}

    def iter_content(self, chunk_size=1):
        yield b"ok"

    def close(self):
        pass


def _prober(own_rps, own_clock, transport=None):
    return prober.Prober({}, guard=lambda _u: True, timeout=3, rps=own_rps,
                         pacer=prober._Pacer(own_rps, clock=own_clock.now, sleep=own_clock.sleep),
                         transport=transport)


class TestRouteExposure:
    def test_each_request_takes_its_own_slot_and_the_global_one(self, ceiling):
        clock, own = ceiling(2), SlotClock()
        stamps = []

        def transport(method, url, **kwargs):
            stamps.append((clock.stamp(), own.stamp()))
            return _Answer()

        probe = _prober(4, own, transport)
        for i in range(5):
            assert probe.send("GET", f"https://app.example.test/r{i}").status_code == 200
        assert [g for g, _ in stamps] == pytest.approx([T0 + k / 2 for k in range(5)])
        assert [o for _, o in stamps] == pytest.approx([T0 + k / 4 for k in range(5)])

    def test_its_workers_hold_the_ceiling_together(self, ceiling):
        clock, own = ceiling(3), SlotClock()
        stamps, lock = [], threading.Lock()

        def transport(method, url, **kwargs):
            with lock:
                stamps.append(clock.stamp())
            return _Answer()

        probe = _prober(10, own, transport)
        with ThreadPoolExecutor(max_workers=6) as pool:
            list(pool.map(lambda i: probe.send("GET", f"https://h{i % 3}.example.test/r{i}"),
                          range(12)))
        assert len(stamps) == 12
        _one_slot_each(stamps, 3)

    def test_a_429_backs_off_the_process_clock_too(self, ceiling):
        clock, own = ceiling(2), SlotClock()
        answers = [_Answer(429, {"retry-after": "7"}), _Answer(200)]
        stamps = []

        def transport(method, url, **kwargs):
            stamps.append(clock.stamp())
            return answers.pop(0)

        assert _prober(4, own, transport).send("GET", "https://app.example.test/x").status_code == 200
        assert stamps == pytest.approx([T0, T0 + 7])

    def test_a_connect_retry_takes_both_slots(self, ceiling, wire):
        ceiling(2)
        own = SlotClock()
        outcomes = iter([NewConnectionError(None, "connection refused"), HTML])
        wire.route = lambda method, url: next(outcomes)
        probe = _prober(4, own)
        answer = probe.send("GET", "https://app.example.test/x")
        assert answer.status_code == 200 and len(wire.sent) == 2
        assert wire.stamps() == pytest.approx([T0, T0 + 0.5])
        assert probe.pacer._next == pytest.approx(T0 + 2 * 0.25)


# ---------------------------------------------------------------------------
# Takeover AI probe
# ---------------------------------------------------------------------------

def test_the_takeover_ai_probe_takes_a_slot_per_scheme(ceiling, wire):
    ceiling(2)
    wire.route = lambda method, url: (NewConnectionError(None, "refused")
                                      if url.startswith("https://") else HTML)
    for host in ("a.example.test", "b.example.test"):
        status, _headers, _body = takeover._probe_for_ai_disambiguation(host, timeout=3)
        assert status == 200
    assert wire.urls() == ["https://a.example.test/", "http://a.example.test/",
                           "https://b.example.test/", "http://b.example.test/"]
    _one_slot_each(wire.stamps(), 2)


# ---------------------------------------------------------------------------
# No ceiling: nothing waits, a 429 holds nobody back
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("settings", NO_CEILING, ids=["no_keys", "roe_off", "zero"])
def test_no_ceiling_never_touches_the_clock(settings, wire, monkeypatch):
    request_pacer.configure(settings)
    touched = []
    monkeypatch.setattr(request_pacer._PACER, "_clock", lambda: touched.append("clock") or T0)
    monkeypatch.setattr(request_pacer._PACER, "_sleep", touched.append)
    throttled = (429, {"Retry-After": "9"}, b"")
    wire.route = lambda method, url: (throttled if "/limited" in url
                                      else SCHEMA if method == "POST" else HTML)

    _cache_scan_one()
    _gql_test(gql_scanner._build_retry_session(0, 0), "https://api.example.com/limited")
    _gql_test(gql_scanner._build_retry_session(0, 0))
    _prober(0, SlotClock()).send("GET", "https://app.example.test/limited")
    takeover._probe_for_ai_disambiguation("dangling.example.test", timeout=3)

    hosts = {u.split("/")[2] for u in wire.urls()}
    assert hosts == {"shop.example.test", "api.example.com", "app.example.test",
                     "dangling.example.test"}
    assert touched == []
