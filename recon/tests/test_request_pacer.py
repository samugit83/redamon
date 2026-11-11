"""The process-wide request pacer that holds the RoE ceiling in-process (R-8, decision D3).

`ROE_GLOBAL_MAX_RPS` capped the external tools' rate flags, but the requests
recon sends itself went out unpaced; OpenAPI discovery had the only clock, with
no lock, and it failed a fetch whose slot fell past the fetch's deadline. One
clock now serves every in-process requester, shared by every thread: N
requests at ceiling C take at least (N-1)/C seconds, whoever sends them. With
RoE off or no ceiling it is inert and never reads the clock.

The clock is a fake throughout (a list the fake sleep advances) except in the
thread-pool test, which reserves slots on a frozen clock. Hosts are under
example.test.
"""
from __future__ import annotations

import json
import math
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from recon.helpers import request_pacer
from recon.helpers.request_pacer import RequestPacer, ceiling_rps


@pytest.fixture(autouse=True)
def _fresh_process_pacer():
    request_pacer.reset()
    yield
    request_pacer.reset()


@pytest.fixture
def fake_time(monkeypatch):
    """time.monotonic / time.sleep on a fake clock; returns (now, sleeps)."""
    now = [100.0]
    sleeps = []

    def sleep(seconds):
        sleeps.append(seconds)
        now[0] += seconds

    monkeypatch.setattr(request_pacer.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(request_pacer.time, "sleep", sleep)
    return now, sleeps


def _forbidden(*_a, **_k):
    raise AssertionError("an inert pacer must not read the clock or sleep")


# ---------------------------------------------------------------------------
# The ceiling, read the way apply_roe_rate_cap reads it
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("settings, expected", [
    ({"ROE_ENABLED": True, "ROE_GLOBAL_MAX_RPS": 2}, 2.0),
    ({"ROE_ENABLED": True, "ROE_GLOBAL_MAX_RPS": 0.5}, 0.5),
    ({"ROE_ENABLED": False, "ROE_GLOBAL_MAX_RPS": 2}, 0.0),
    ({"ROE_GLOBAL_MAX_RPS": 2}, 0.0),
    ({"ROE_ENABLED": True, "ROE_GLOBAL_MAX_RPS": 0}, 0.0),
    ({"ROE_ENABLED": True, "ROE_GLOBAL_MAX_RPS": -3}, 0.0),
    ({"ROE_ENABLED": True, "ROE_GLOBAL_MAX_RPS": None}, 0.0),
    ({"ROE_ENABLED": True, "ROE_GLOBAL_MAX_RPS": True}, 0.0),
    ({"ROE_ENABLED": True, "ROE_GLOBAL_MAX_RPS": "fast"}, 0.0),
    ({"ROE_ENABLED": True, "ROE_GLOBAL_MAX_RPS": math.nan}, 0.0),
    ({"ROE_ENABLED": True, "ROE_GLOBAL_MAX_RPS": math.inf}, 0.0),
    ({}, 0.0),
    (None, 0.0),
])
def test_the_ceiling_follows_the_capper_rule(settings, expected):
    assert ceiling_rps(settings) == expected


# ---------------------------------------------------------------------------
# One pacer
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("n, rps", [(5, 2), (4, 1), (3, 0.5), (10, 7)])
def test_n_requests_at_ceiling_c_take_at_least_n_minus_1_over_c(fake_time, n, rps):
    now, _ = fake_time
    pacer = RequestPacer(rps)
    stamps = []
    for _ in range(n):
        pacer.acquire()
        stamps.append(now[0])
    assert stamps[-1] - stamps[0] >= (n - 1) / rps - 1e-9
    assert all(b - a == pytest.approx(1 / rps) for a, b in zip(stamps, stamps[1:]))


def test_the_first_request_goes_at_once_and_a_quiet_gap_is_not_banked(fake_time):
    now, sleeps = fake_time
    pacer = RequestPacer(2)
    assert pacer.acquire() == 0.0
    now[0] += 10  # nothing sent for ten seconds
    assert pacer.acquire() == 0.0
    assert pacer.acquire() == pytest.approx(0.5)
    assert sleeps == [pytest.approx(0.5)]


@pytest.mark.parametrize("rps", [0, 0.0, None])
def test_no_ceiling_never_reads_the_clock_or_sleeps(rps):
    pacer = RequestPacer(rps, clock=_forbidden, sleep=_forbidden)
    for _ in range(100):
        assert pacer.acquire() == 0.0
    pacer.back_off(30)
    assert not pacer.active and pacer.rps == 0.0


def test_the_slots_of_a_thread_pool_never_collide():
    """Reserved under the lock: 400 acquires from 8 threads get 400 distinct
    slots, one interval apart, on a clock that never moves."""
    frozen = 100.0

    def clock():
        time.sleep(0)  # give another thread the chance to interleave
        return frozen

    waits = []
    lock = threading.Lock()
    pacer = RequestPacer(4, clock=clock, sleep=lambda _s: None)

    def worker():
        for _ in range(50):
            wait = pacer.acquire()
            with lock:
                waits.append(wait)

    with ThreadPoolExecutor(max_workers=8) as pool:
        for future in [pool.submit(worker) for _ in range(8)]:
            future.result()

    assert sorted(waits) == pytest.approx([k * 0.25 for k in range(400)])


def test_a_real_thread_pool_holds_the_ceiling():
    """The same on the real clock: the k-th request starts no earlier than k/C."""
    rps, n = 40, 12
    pacer = RequestPacer(rps)
    stamps = []
    lock = threading.Lock()
    start = time.monotonic()

    def one(_):
        pacer.acquire()
        with lock:
            stamps.append(time.monotonic())

    with ThreadPoolExecutor(max_workers=10) as pool:
        list(pool.map(one, range(n)))

    for k, stamp in enumerate(sorted(stamps)):
        assert stamp - start >= k / rps - 0.005


def test_back_off_pushes_every_caller_back(fake_time):
    now, _ = fake_time
    pacer = RequestPacer(10)
    pacer.acquire()
    pacer.back_off(3)
    assert pacer.acquire() == pytest.approx(3.0)
    assert now[0] == pytest.approx(103.0)


def test_the_context_manager_takes_a_slot(fake_time):
    now, _ = fake_time
    pacer = RequestPacer(1)
    with pacer:
        pass
    with pacer:
        pass
    assert now[0] == pytest.approx(101.0)


@pytest.mark.parametrize("rps", [-1, math.nan, math.inf])
def test_an_invalid_rate_is_refused(rps):
    with pytest.raises(ValueError):
        RequestPacer(rps)


# ---------------------------------------------------------------------------
# The process-wide pacer
# ---------------------------------------------------------------------------

CEILING_2 = {"ROE_ENABLED": True, "ROE_GLOBAL_MAX_RPS": 2}


def test_unconfigured_the_process_pacer_is_inert():
    assert request_pacer.ceiling() == 0.0
    assert request_pacer.acquire() == 0.0


def test_configure_sets_the_ceiling_and_every_caller_shares_one_clock(fake_time):
    now, _ = fake_time
    request_pacer.configure(CEILING_2)
    assert request_pacer.ceiling() == 2.0
    assert request_pacer.pacer() is request_pacer.pacer(CEILING_2)
    request_pacer.acquire()
    with request_pacer.pacer():
        pass
    request_pacer.pacer().acquire()
    assert now[0] == pytest.approx(101.0)


def test_settings_configure_only_an_unconfigured_pacer():
    request_pacer.pacer(CEILING_2)
    assert request_pacer.ceiling() == 2.0
    # A module that read other settings does not move the run's ceiling...
    request_pacer.pacer({"ROE_ENABLED": False})
    assert request_pacer.ceiling() == 2.0
    # ...but the process start does, and RoE off makes the pacer inert again.
    request_pacer.configure({"ROE_ENABLED": False, "ROE_GLOBAL_MAX_RPS": 2})
    assert request_pacer.ceiling() == 0.0


def test_reset_keeps_the_object_a_module_holds():
    held = request_pacer.configure(CEILING_2)
    request_pacer.reset()
    assert held is request_pacer.pacer()
    assert not held.active


# ---------------------------------------------------------------------------
# OpenAPI document fetches use the process pacer
# ---------------------------------------------------------------------------

class _Response:
    status_code = 200
    headers = {}

    def __init__(self, body=b'{"openapi":"3.1.0","info":{"title":"t","version":"1"},"paths":{}}'):
        self.body = body

    def iter_content(self, chunk_size):
        yield self.body

    def close(self):
        pass


def test_openapi_discovery_paces_on_the_process_clock():
    from recon.helpers.openapi import discovery
    assert discovery._pacer_for(CEILING_2) is request_pacer.pacer()
    assert request_pacer.ceiling() == 2.0


def test_openapi_and_security_checks_share_one_clock(fake_time, monkeypatch):
    from unittest import mock

    from recon.helpers import security_checks as sc
    from recon.helpers.openapi.discovery import run_openapi_discovery
    now, _ = fake_time
    stamps = []
    monkeypatch.setattr("requests.Session.get",
                        lambda self, url, **kw: stamps.append(("openapi", now[0])) or _Response())
    request_pacer.configure(CEILING_2)

    run_openapi_discovery({}, {"TARGET_DOMAIN": "example.test", **CEILING_2,
                               "OPENAPI_AUTO_DISCOVER": False,
                               "OPENAPI_SOURCES": [{"url": "https://api.example.test/spec"}]}, [])

    def get(url, **kw):
        stamps.append(("security_check", now[0]))
        return mock.MagicMock(status_code=200)

    with mock.patch.object(sc.requests, "get", side_effect=get):
        sc._hh_get("https://app.example.test/", timeout=1)

    assert stamps == [("openapi", 100.0), ("security_check", 100.5)]


def test_a_queued_slot_does_not_eat_the_document_deadline(fake_time, monkeypatch):
    """The wait is the ceiling's, not the target's: the second document waits
    for its slot, then still gets its whole timeout."""
    from recon.helpers.openapi.fetch import Fetcher
    now, _ = fake_time
    calls = []
    monkeypatch.setattr("requests.Session.get",
                        lambda self, url, **kw: calls.append((url, now[0], kw["timeout"])) or _Response())
    pacer = RequestPacer(0.1)
    first, second = Fetcher(timeout=1, pacer=pacer), Fetcher(timeout=1, pacer=pacer)
    try:
        first.fetch("https://one.example.test/spec", {}, "https://one.example.test")
        url, text = second.fetch("https://two.example.test/spec", {}, "https://two.example.test")
    finally:
        first.close()
        second.close()
    assert json.loads(text)["openapi"] == "3.1.0"
    assert calls == [("https://one.example.test/spec", 100.0, 1.0),
                     ("https://two.example.test/spec", 110.0, 1.0)]
