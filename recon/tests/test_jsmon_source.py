"""Subdomains by Jsmon passive source (domain_recon.query_jsmon).

Every HTTP call is intercepted; nothing here opens a socket.
"""
from __future__ import annotations

import json
import threading
from unittest import mock

import pytest
import requests

from recon.helpers import circuit_breaker as cb
from recon.main_recon_modules import domain_recon as dr


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _Resp:
    """Minimal requests.Response stand-in."""

    def __init__(self, status=200, data=None):
        self.status_code = status
        self._data = data

    def json(self):
        if self._data is None:
            raise ValueError("No JSON")
        return self._data

    def close(self):
        pass


class _JsmonNet:
    """Intercepts ``session.get`` for subdomains.jsmon.sh calls."""

    def __init__(self, response=None):
        self.response = response or _Resp(200, {"domain": "example.com", "total": 0, "subdomains": []})
        self.calls: list[dict] = []
        self._lock = threading.Lock()

    def _session_factory(self):
        sess = mock.MagicMock(spec=requests.Session)
        sess.get.side_effect = self._get
        sess.close = mock.MagicMock()
        return sess

    def _get(self, url, headers=None, timeout=None, **kwargs):
        with self._lock:
            self.calls.append({"url": url, "headers": headers or {}, "timeout": timeout})
        if isinstance(self.response, BaseException):
            raise self.response
        return self.response

    def patch(self):
        return mock.patch.object(dr.requests, "Session", side_effect=self._session_factory)


def _settings(enabled=True, key="test-key-123", max_results=5000, **extra):
    s = {
        "JSMON_ENABLED": enabled,
        "JSMON_API_KEY": key,
        "JSMON_MAX_RESULTS": max_results,
    }
    s.update(extra)
    return s


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestJsmonHappyPath:
    def test_200_with_in_scope_names(self):
        net = _JsmonNet(_Resp(200, {
            "domain": "example.com",
            "total": 3,
            "subdomains": ["www.example.com", "api.example.com", "mail.example.com"],
        }))
        with net.patch():
            out = dr.query_jsmon("example.com", _settings())
        assert out == {
            "www.example.com": {"jsmon"},
            "api.example.com": {"jsmon"},
            "mail.example.com": {"jsmon"},
        }
        assert len(net.calls) == 1
        assert "Api-Key" in net.calls[0]["headers"]

    def test_root_domain_itself_is_kept(self):
        net = _JsmonNet(_Resp(200, {
            "domain": "example.com",
            "total": 1,
            "subdomains": ["example.com"],
        }))
        with net.patch():
            out = dr.query_jsmon("example.com", _settings())
        assert "example.com" in out

    def test_out_of_scope_names_are_dropped(self):
        net = _JsmonNet(_Resp(200, {
            "domain": "example.com",
            "total": 3,
            "subdomains": ["www.example.com", "evil.attacker.com", "notexample.com"],
        }))
        with net.patch():
            out = dr.query_jsmon("example.com", _settings())
        assert "www.example.com" in out
        assert "evil.attacker.com" not in out
        assert "notexample.com" not in out


class TestJsmonMaxResults:
    def test_cap_is_respected(self):
        subs = [f"sub{i}.example.com" for i in range(100)]
        net = _JsmonNet(_Resp(200, {
            "domain": "example.com",
            "total": 100,
            "subdomains": subs,
        }))
        with net.patch():
            out = dr.query_jsmon("example.com", _settings(max_results=10))
        assert len(out) == 10


class TestJsmonErrorResponses:
    def test_401_records_fatal(self):
        net = _JsmonNet(_Resp(401))
        with net.patch():
            out = dr.query_jsmon("example.com", _settings())
        assert out == {}

    def test_429_records_rate_limit(self):
        net = _JsmonNet(_Resp(429))
        with net.patch():
            out = dr.query_jsmon("example.com", _settings())
        assert out == {}

    def test_404_records_no_data(self):
        net = _JsmonNet(_Resp(404))
        with net.patch():
            out = dr.query_jsmon("example.com", _settings())
        assert out == {}

    def test_network_error_records_transient(self):
        net = _JsmonNet(requests.ConnectionError("DNS failure"))
        with net.patch():
            out = dr.query_jsmon("example.com", _settings())
        assert out == {}


class TestJsmonSkipConditions:
    def test_disabled_skips(self):
        net = _JsmonNet()
        with net.patch():
            out = dr.query_jsmon("example.com", _settings(enabled=False))
        assert out == {}
        assert len(net.calls) == 0

    def test_no_key_skips(self):
        net = _JsmonNet()
        with net.patch():
            out = dr.query_jsmon("example.com", _settings(key=""))
        assert out == {}
        assert len(net.calls) == 0

    def test_none_key_skips(self):
        net = _JsmonNet()
        with net.patch():
            out = dr.query_jsmon("example.com", _settings(key=None))
        assert out == {}
        assert len(net.calls) == 0

    def test_whitespace_only_key_skips(self):
        net = _JsmonNet()
        with net.patch():
            out = dr.query_jsmon("example.com", _settings(key="   "))
        assert out == {}
        assert len(net.calls) == 0
