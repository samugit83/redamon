"""Agent-side auth scope for replay sends (api._profile_auth_base).

The agent derives the scope inline from the project row, separately from recon's
default_scope_hosts. That copy was apex-only, so every replay against a
DISCOVERED subdomain came back unauthenticated — silently, because
_profile_auth_base swallows everything and returns {}. These tests pin the
behaviour that only an ad-hoc runtime check caught.

Own file: importing api.py is heavy, and the gate runs one process per file.
"""

import asyncio
import os
import sys
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import api  # noqa: E402
import requests  # noqa: E402

PROFILE = {"authType": "cookie", "authValue": "sid=abc"}


def _project(**kw):
    p = {"authProfile": PROFILE, "targetDomain": "example.test", "subdomainList": [],
         "ipMode": False, "targetIps": []}
    p.update(kw)
    return p


def _run(host, project, project_id="p1"):
    class _Resp:
        def raise_for_status(self):
            pass

        def json(self):
            return project

    api._AUTH_PROFILE_CACHE.clear()
    with mock.patch.object(requests, "get", return_value=_Resp()):
        return asyncio.run(api._profile_auth_base(project_id, {"host": host}))


class TestAgentAuthScope:
    def test_discovered_subdomain_is_authenticated(self):
        assert _run("app.example.test", _project()) == {"Cookie": "sid=abc"}

    def test_apex_is_authenticated(self):
        assert _run("example.test", _project()) == {"Cookie": "sid=abc"}

    def test_foreign_host_gets_nothing(self):
        assert _run("third-party.test", _project()) == {}
        assert _run("evilexample.test", _project()) == {}

    def test_explicit_scope_hosts_replace_the_default(self):
        p = _project(authProfile={**PROFILE, "scopeHosts": ["only.example.test"]})
        assert _run("only.example.test", p) == {"Cookie": "sid=abc"}
        assert _run("other.example.test", p) == {}

    def test_domain_batch_roots_are_in_scope(self):
        p = _project(targetDomain="", domainBatchGroups=[{"rootDomain": "b.test"}])
        assert _run("api.b.test", p) == {"Cookie": "sid=abc"}
        assert _run("c.test", p) == {}

    def test_ip_mode_uses_target_ips(self):
        p = _project(ipMode=True, targetIps=["10.0.0.5"], targetDomain="")
        assert _run("10.0.0.5", p) == {"Cookie": "sid=abc"}
        assert _run("10.0.0.6", p) == {}

    def test_no_profile_means_no_headers(self):
        assert _run("app.example.test", _project(authProfile=None)) == {}

    def test_missing_host_short_circuits(self):
        api._AUTH_PROFILE_CACHE.clear()
        assert asyncio.run(api._profile_auth_base("p1", {})) == {}

    def test_profile_is_cached_across_calls(self):
        calls = {"n": 0}

        class _Resp:
            def raise_for_status(self):
                pass

            def json(self):
                calls["n"] += 1
                return _project()

        api._AUTH_PROFILE_CACHE.clear()
        with mock.patch.object(requests, "get", return_value=_Resp()):
            asyncio.run(api._profile_auth_base("p-cache", {"host": "app.example.test"}))
            asyncio.run(api._profile_auth_base("p-cache", {"host": "app.example.test"}))
        assert calls["n"] == 1

    def test_fetch_failure_fails_open(self):
        api._AUTH_PROFILE_CACHE.clear()
        with mock.patch.object(requests, "get", side_effect=RuntimeError("webapp down")):
            assert asyncio.run(api._profile_auth_base("p1", {"host": "app.example.test"})) == {}
