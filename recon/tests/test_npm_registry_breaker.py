"""The `npm` breaker on the dependency-confusion registry check
(recon/helpers/js_recon/dependency.py).

10s per package with failures uncached used to mean the whole registry being
down cost 10s for every scoped package. A skipped/failed check returns None
("not checked"): an unreachable registry never invents a confusion finding,
and never reads as "published" either (R-47,
test_regression_npm_registry_outage_prune.py).
"""
from __future__ import annotations

from unittest import mock

import requests

from recon.helpers import circuit_breaker as cb
from recon.helpers.js_recon import dependency


def _resp(status):
    r = mock.MagicMock(status_code=status)
    r.json.return_value = {}
    return r


def _clear_cache():
    with dependency._npm_cache_lock:
        dependency._npm_cache.clear()


def test_three_failures_stop_the_registry_and_skips_are_not_checked():
    _clear_cache()
    with mock.patch.object(dependency.requests, "get",
                           side_effect=requests.ConnectionError("down")) as get:
        for i in range(3):
            assert dependency._check_npm_registry(f"@org/pkg{i}") is None
        # Registry is now paused: no more calls, still "not checked".
        assert dependency._check_npm_registry("@org/late") is None
    assert get.call_count == 3


def test_a_404_is_a_real_answer_and_is_cached():
    _clear_cache()
    with mock.patch.object(dependency.requests, "get", return_value=_resp(404)) as get:
        assert dependency._check_npm_registry("@org/missing") is False
        assert dependency._check_npm_registry("@org/missing") is False
    assert get.call_count == 1  # cached


def test_many_404s_never_trip_the_breaker():
    _clear_cache()
    with mock.patch.object(dependency.requests, "get", return_value=_resp(404)) as get:
        for i in range(10):
            assert dependency._check_npm_registry(f"@org/missing{i}") is False
    assert get.call_count == 10


def test_a_failure_is_not_cached():
    _clear_cache()
    ok = _resp(200)
    with mock.patch.object(dependency.requests, "get",
                           side_effect=[requests.ConnectionError("x"), ok]) as get:
        assert dependency._check_npm_registry("@org/pkg") is None   # failed, not cached
        assert dependency._check_npm_registry("@org/pkg") is True   # retried -> 200
    assert get.call_count == 2


def test_the_off_switch_keeps_calling(monkeypatch):
    _clear_cache()
    monkeypatch.setenv("RECON_CIRCUIT_BREAKERS", "off")
    with mock.patch.object(dependency.requests, "get",
                           side_effect=requests.ConnectionError("x")) as get:
        for i in range(10):
            assert dependency._check_npm_registry(f"@org/p{i}") is None
    assert get.call_count == 10
