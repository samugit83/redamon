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

    def test_apex_is_authenticated_only_when_it_is_a_target(self):
        # §4.6: `*.root` is strict subdomains; the root itself needs Root on (".").
        assert _run("example.test", _project()) == {}
        assert _run("example.test", _project(subdomainList=["."])) == {"Cookie": "sid=abc"}

    def test_foreign_host_gets_nothing(self):
        assert _run("third-party.test", _project()) == {}
        assert _run("evilexample.test", _project()) == {}

    def test_explicit_scope_hosts_narrow_the_default(self):
        p = _project(authProfile={**PROFILE, "scopeHosts": ["only.example.test"]})
        assert _run("only.example.test", p) == {"Cookie": "sid=abc"}
        assert _run("other.example.test", p) == {}

    def test_explicit_scope_hosts_never_widen_it(self):
        # D-22: explicit `*.example.test` on a project listing only www -> only www.
        p = _project(subdomainList=["www."], authProfile={**PROFILE, "scopeHosts": ["*.example.test", "evil.test"]})
        assert _run("www.example.test", p) == {"Cookie": "sid=abc"}
        assert _run("shop.example.test", p) == {}
        assert _run("evil.test", p) == {}

    def test_legacy_domain_batch_reads_root_and_prefixes(self):
        p = _project(targetDomain="", domainBatchMode=True, domainBatchGroups=[
            {"rootDomain": "b.test", "prefixes": ["*"], "hosts": ["*.b.test"]},
            {"rootDomain": "c.test", "prefixes": ["www."], "hosts": ["*.evil.test", "www.c.test"]},
        ])
        assert _run("api.b.test", p) == {"Cookie": "sid=abc"}
        assert _run("www.c.test", p) == {"Cookie": "sid=abc"}
        assert _run("api.c.test", p) == {}
        assert _run("x.evil.test", p) == {}

    def test_scope_groups_are_preferred_over_the_legacy_fields(self):
        p = _project(targetDomain="", domainBatchMode=True,
                     domainBatchGroups=[{"rootDomain": "legacy.test", "prefixes": ["*"]}],
                     scopeGroups=[
                         {"scanRoot": "api.b.test", "orgDomain": "b.test", "mode": "enumerate",
                          "includeRoot": False, "exactHosts": [], "entries": ["*.api.b.test"], "notes": []},
                         {"scanRoot": "c.test", "orgDomain": "c.test", "mode": "exact",
                          "includeRoot": False, "exactHosts": ["www.c.test"], "entries": ["www.c.test"], "notes": []},
                     ])
        assert _run("v1.api.b.test", p) == {"Cookie": "sid=abc"}
        assert _run("www.c.test", p) == {"Cookie": "sid=abc"}
        # EXACT never yields *.root, and the org above an enumerated root is not in scope.
        assert _run("api.c.test", p) == {}
        assert _run("www.b.test", p) == {}
        assert _run("x.legacy.test", p) == {}

    def test_an_roe_excluded_host_gets_nothing(self):
        p = _project(roeEnabled=True, roeExcludedHosts=["admin.example.test"])
        assert _run("admin.example.test", p) == {}
        assert _run("app.example.test", p) == {"Cookie": "sid=abc"}

    def test_ip_mode_uses_target_ips(self):
        p = _project(ipMode=True, targetIps=["10.0.0.5"], targetDomain="")
        assert _run("10.0.0.5", p) == {"Cookie": "sid=abc"}
        assert _run("10.0.0.6", p) == {}

    def test_a_hostname_mode_never_widens_the_ip_scope(self):
        # D-22: credentials go to the target IPs only, in every hostname mode. A
        # name the run scanned may move to another address after the scan, and
        # the session would follow it there.
        for mode in ("ip_only", "record_only", "record_filter", "scan_all"):
            p = _project(ipMode=True, targetIps=["10.0.0.0/30"], targetDomain="",
                         ipHostnameMode=mode, ipHostnameInclude=["*.example.test"],
                         ipHostnameScanAllConfirmed=True)
            assert _run("10.0.0.1", p) == {"Cookie": "sid=abc"}, mode
            assert _run("app.example.test", p) == {}, mode
            assert _run("example.test", p) == {}, mode

    def test_the_session_auth_scope_of_an_m4_project_is_its_target_ips(self):
        import project_settings
        import scope_groups

        token = project_settings._settings_ctx.set({
            "IP_MODE": True, "TARGET_IPS": ["10.0.0.5", "10.0.1.0/24"], "IP_HOSTNAME_MODE": "record_filter",
            "IP_HOSTNAME_INCLUDE": ["*.example.test"], "IP_HOSTNAME_EXCLUDE": []})
        try:
            project_settings.bind_ip_hostnames_scanned(["app.example.test"])
            assert project_settings.ip_hostnames_scanned() == ["app.example.test"]
            assert project_settings.auth_scope_patterns() == ["10.0.0.5", "10.0.1.0/24"]
        finally:
            project_settings._settings_ctx.reset(token)
        assert scope_groups.auth_scope_patterns([], ip_mode=True, target_ips=["10.0.0.5"]) == ["10.0.0.5"]

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

    def test_a_settings_load_that_saw_a_newer_project_drops_the_cached_row(self):
        import project_settings

        rows = [_project(updatedAt="v1"),
                _project(updatedAt="v2", authProfile={**PROFILE, "scopeHosts": ["only.example.test"]})]

        class _Resp:
            def raise_for_status(self):
                pass

            def json(self):
                return rows.pop(0)

        api._AUTH_PROFILE_CACHE.clear()
        project_settings._SEEN_UPDATED_AT.pop("p-rescope", None)
        with mock.patch.object(requests, "get", return_value=_Resp()):
            assert asyncio.run(api._profile_auth_base("p-rescope", {"host": "app.example.test"})) == {"Cookie": "sid=abc"}
            project_settings._SEEN_UPDATED_AT["p-rescope"] = "v2"
            assert asyncio.run(api._profile_auth_base("p-rescope", {"host": "app.example.test"})) == {}
        assert rows == []

    def test_fetch_failure_fails_open(self):
        api._AUTH_PROFILE_CACHE.clear()
        with mock.patch.object(requests, "get", side_effect=RuntimeError("webapp down")):
            assert asyncio.run(api._profile_auth_base("p1", {"host": "app.example.test"})) == {}
