"""Regression: a 429 to a security check never slowed the shared RoE clock (R-8, decision D3).

The security checks' requests (`_hh_get` / `_hh_post` / `_hh_request`) take a
slot of the process-wide pacer, but unlike cache_scan, graphql_scan,
route_exposure and origin_discovery they ignored a target's 429: the next
request of every in-process requester went out on its normal slot, into a
target that had just asked recon to slow down.

Now, with a ceiling, a 429 pushes every requester's next slot back by its
Retry-After seconds (1 s when absent or not a number), at most 30 s, because
the header is the target's to set. With no ceiling the pacer is inert and a
429 changes nothing.

HTTP and the clock are fakes. Hosts are under example.test.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

import pytest
from requests.structures import CaseInsensitiveDict

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers import request_pacer  # noqa: E402
from recon.helpers import security_checks as sc  # noqa: E402

HOST = "app.example.test"
URL = f"https://{HOST}/account/login"
# A 2 rps ceiling: one slot every 0.5 s, so a back-off is told apart from the interval.
CEILING_2 = {"ROE_ENABLED": True, "ROE_GLOBAL_MAX_RPS": 2}
NO_CEILING = [
    {},
    {"ROE_ENABLED": False, "ROE_GLOBAL_MAX_RPS": 2},
    {"ROE_ENABLED": True, "ROE_GLOBAL_MAX_RPS": 0},
]
START = 100.0


@pytest.fixture(autouse=True)
def _fresh_process_pacer():
    request_pacer.reset()
    yield
    request_pacer.reset()


@pytest.fixture
def fake_time(monkeypatch):
    now = [START]
    monkeypatch.setattr(request_pacer.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(request_pacer.time, "sleep", lambda s: now.__setitem__(0, now[0] + s))
    return now


def _resp(status=200, headers=None):
    r = mock.MagicMock()
    r.status_code = status
    r.headers = CaseInsensitiveDict(headers or {})
    r.text = ""
    r.content = b""
    r.cookies = None
    r.history = []
    return r


def _call(requester):
    if requester == "get":
        return sc._hh_get(URL, timeout=1)
    if requester == "post":
        return sc._hh_post(URL, data={}, timeout=1)
    return sc._hh_request("PURGE", URL, timeout=1)


def _answer(requester, response):
    target = {"get": "get", "post": "post", "request": "request"}[requester]
    return mock.patch.object(sc.requests, target, return_value=response)


def _next_slot_after(requester, response, fake_time):
    """Send one request answered by `response`, then take the next slot of the
    shared clock as an unrelated requester would; return when that slot fell."""
    with _answer(requester, response):
        returned = _call(requester)
    assert returned is response
    assert fake_time[0] == START
    request_pacer.acquire()
    return fake_time[0]


# ---------------------------------------------------------------------------
# A 429 holds every in-process requester back
# ---------------------------------------------------------------------------

class TestA429HoldsTheSharedClockBack:
    @pytest.mark.parametrize("requester", ["get", "post", "request"])
    def test_retry_after_delays_the_next_slot_by_its_seconds(self, fake_time, requester):
        request_pacer.configure(CEILING_2)
        slot = _next_slot_after(requester, _resp(429, {"Retry-After": "3"}), fake_time)
        assert slot == START + 3

    def test_the_next_security_check_request_waits_too(self, fake_time):
        request_pacer.configure(CEILING_2)
        stamps = []
        answers = iter([_resp(429, {"Retry-After": "3"}), _resp(200)])

        def get(url, **kwargs):
            stamps.append(fake_time[0])
            return next(answers)

        with mock.patch.object(sc.requests, "get", side_effect=get):
            sc._hh_get(URL, timeout=1)
            sc._hh_get(URL, timeout=1)
        assert stamps == [START, START + 3]

    def test_a_real_check_backs_off_through_the_wrapper(self, fake_time):
        """check_security_headers reaches the target through _get_on_host -> _hh_get."""
        request_pacer.configure(CEILING_2)
        with mock.patch.object(sc.requests, "get", return_value=_resp(429, {"Retry-After": "3"})) as get:
            sc.check_security_headers(HOST, timeout=1)
        assert get.call_count == 1
        request_pacer.acquire()
        assert fake_time[0] == START + 3

    @pytest.mark.parametrize("headers", [
        {},
        {"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"},
        {"Retry-After": "soon"},
        {"Retry-After": "0"},
    ], ids=["absent", "http_date", "garbage", "zero"])
    def test_no_usable_retry_after_backs_off_one_second(self, fake_time, headers):
        request_pacer.configure(CEILING_2)
        assert _next_slot_after("get", _resp(429, headers), fake_time) == START + 1

    def test_the_target_cannot_hold_recon_back_more_than_30_seconds(self, fake_time):
        request_pacer.configure(CEILING_2)
        slot = _next_slot_after("get", _resp(429, {"Retry-After": "3600"}), fake_time)
        assert slot == START + 30

    @pytest.mark.parametrize("status", [200, 403, 503])
    def test_other_statuses_keep_the_normal_interval(self, fake_time, status):
        request_pacer.configure(CEILING_2)
        slot = _next_slot_after("get", _resp(status, {"Retry-After": "3"}), fake_time)
        assert slot == START + 0.5


# ---------------------------------------------------------------------------
# No ceiling: a 429 changes nothing
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("settings", NO_CEILING, ids=["no_keys", "roe_off", "zero"])
@pytest.mark.parametrize("requester", ["get", "post", "request"])
def test_no_ceiling_a_429_never_waits(monkeypatch, settings, requester):
    request_pacer.configure(settings)

    def forbidden(*_a):
        raise AssertionError("no ceiling: the pacer must not read the clock or sleep")

    monkeypatch.setattr(request_pacer.time, "sleep", forbidden)
    monkeypatch.setattr(request_pacer.time, "monotonic", forbidden)
    response = _resp(429, {"Retry-After": "3"})
    with _answer(requester, response) as sent:
        for _ in range(5):
            assert _call(requester) is response
    assert sent.call_count == 5
    assert request_pacer.acquire() == 0.0
