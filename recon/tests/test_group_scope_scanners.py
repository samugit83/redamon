"""
Each scanner follows its group's scope (§4.6, release C): an EXACT group
reaches exactly its listed hosts even when certificates, JS or search engines
name siblings; a `*`-only group never touches its apex; a recon file written
before `scope_mode` existed behaves exactly as before.
"""
import sys
from pathlib import Path
from unittest import mock

import pytest

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO))
sys.path.insert(0, str(_REPO / "recon"))

from recon.helpers.recon_scope import recon_scope  # noqa: E402

ROOT_IP, WWW_IP, API_IP = "192.0.2.1", "192.0.2.2", "192.0.2.3"


def _dns():
    return {
        "domain": {"ips": {"ipv4": [ROOT_IP], "ipv6": []}, "has_records": True},
        "subdomains": {
            "www.example.test": {"ips": {"ipv4": [WWW_IP], "ipv6": []}, "has_records": True},
            "api.example.test": {"ips": {"ipv4": [API_IP], "ipv6": []}, "has_records": True},
        },
    }


def _recon(mode=None, include_root=None, subdomain_filter=None, org=None, **meta):
    metadata = dict(meta)
    if mode:
        metadata["scope_mode"] = mode
        metadata["filtered_mode"] = mode == "exact"
        metadata["wildcard_mode"] = mode == "enumerate"
    if include_root is not None:
        metadata["include_root_domain"] = include_root
    if subdomain_filter is not None:
        metadata["subdomain_filter"] = subdomain_filter
    if org:
        metadata["org_domain"] = org
    metadata.setdefault("root_domain", "example.test")
    return {"domain": "example.test", "metadata": metadata, "dns": _dns(),
            "subdomains": ["www.example.test", "api.example.test"]}


STAR_ONLY = dict(mode="enumerate", include_root=False)
EXACT_WWW = dict(mode="exact", include_root=False, subdomain_filter=["www.example.test"])
LEGACY = dict()                                    # no scope_mode: as before


class TestReconScope:
    def test_a_legacy_file_keeps_the_root_and_the_old_rule(self):
        s = recon_scope(_recon(**LEGACY))
        assert s.mode is None and s.include_root is True and s.may_inject
        assert s.admits("example.test") and s.admits("x.example.test")

    def test_a_star_only_group_never_admits_its_apex(self):
        s = recon_scope(_recon(**STAR_ONLY))
        assert not s.admits("example.test")
        assert s.admits("deep.x.example.test")
        assert not s.admits("example.test.evil.test")

    def test_an_exact_group_admits_its_list_only(self):
        s = recon_scope(_recon(mode="exact", include_root=True,
                               subdomain_filter=["www.example.test", "example.test"]))
        assert s.exact_hosts == frozenset({"www.example.test"})
        assert s.targets() == ["example.test", "www.example.test"]
        assert s.admits("www.example.test") and s.admits("example.test")
        assert not s.admits("api.example.test") and not s.may_inject

    def test_the_org_falls_back_to_the_scan_root(self):
        assert recon_scope(_recon(mode="enumerate", org="example.test")).org_domain == "example.test"
        assert recon_scope(_recon()).org_domain == "example.test"

    def test_ip_mode(self):
        s = recon_scope({"domain": "ip-targets.p1", "metadata": {"ip_mode": True}})
        assert s.ip_mode


class TestApexTargets:
    """REC-10: the apex (and its addresses) only when it is a target."""

    def test_port_scan(self):
        from recon.main_recon_modules.port_scan import extract_targets_from_recon
        ips, hosts, _ = extract_targets_from_recon(_recon(**STAR_ONLY))
        assert "example.test" not in hosts and ROOT_IP not in ips
        ips, hosts, _ = extract_targets_from_recon(_recon(**LEGACY))
        assert "example.test" in hosts and ROOT_IP in ips

    def test_masscan(self):
        from recon.main_recon_modules.masscan_scan import resolve_targets_to_ips
        ips, mapping = resolve_targets_to_ips(_recon(**STAR_ONLY))
        assert ROOT_IP not in ips
        ips, _ = resolve_targets_to_ips(_recon(**LEGACY))
        assert ROOT_IP in ips

    def test_http_probe_fallback(self):
        from recon.main_recon_modules.http_probe import build_targets_from_dns
        urls = build_targets_from_dns(_recon(**STAR_ONLY))
        assert not any("//example.test" in u for u in urls)
        assert any("//www.example.test" in u for u in urls)
        assert any("//example.test" in u for u in build_targets_from_dns(_recon(**LEGACY)))

    def test_vhost_ip_targets(self):
        from recon.main_recon_modules.vhost_sni_enum import _collect_ip_targets
        assert ROOT_IP not in _collect_ip_targets(_recon(**STAR_ONLY))
        assert ROOT_IP in _collect_ip_targets(_recon(**LEGACY))

    def test_security_checks(self):
        from recon.helpers import security_checks as sc
        seen = {}

        def tls(hostnames, **kw):
            seen["hosts"] = set(hostnames)
            return []

        def direct(ips, subdomains_to_ips, **kw):
            seen["ips"], seen["map"] = set(ips), dict(subdomains_to_ips)
            return []

        for recon, apex in ((_recon(**STAR_ONLY), False), (_recon(**LEGACY), True)):
            with mock.patch.object(sc, "run_tls_checks", side_effect=tls), \
                 mock.patch.object(sc, "run_direct_ip_checks", side_effect=direct), \
                 mock.patch.object(sc, "collect_reliable_edge_ips", return_value=set()), \
                 mock.patch.object(sc, "collect_asn_cdn_ips", return_value=set()), \
                 mock.patch.object(sc, "collect_prefix_cdn_ips", return_value=set()):
                sc._run_security_checks(recon, {"tls_expiring_soon": True, "direct_ip_http": True},
                                        5, 30, 2, False, "", "", "")
            assert ("example.test" in seen["hosts"]) is apex
            assert (ROOT_IP in seen["ips"]) is apex
            assert ("example.test" in seen["map"]) is apex


class TestHttpxScope:
    """REC-11."""

    def test_an_exact_list_is_authoritative_even_empty(self):
        from recon.main_recon_modules.http_probe import is_host_in_scope
        assert not is_host_in_scope("www.example.test", "example.test", [], exact=True)
        assert is_host_in_scope("www.example.test", "example.test", [])     # legacy: suffix scope
        assert is_host_in_scope("www.example.test", "example.test", ["www.example.test"], exact=True)
        assert not is_host_in_scope("api.example.test", "example.test", ["www.example.test"], exact=True)

    def test_the_root_needs_include_root(self):
        from recon.main_recon_modules.http_probe import is_host_in_scope
        assert not is_host_in_scope("example.test", "example.test", include_root=False)
        assert is_host_in_scope("a.example.test", "example.test", include_root=False)
        assert is_host_in_scope("example.test", "example.test")             # legacy default


class TestTakeover:
    """REC-13."""

    def test_star_only_skips_the_apex(self):
        from recon.main_recon_modules.subdomain_takeover import _collect_subdomains
        assert "example.test" not in _collect_subdomains(_recon(**STAR_ONLY))
        assert "example.test" in _collect_subdomains(_recon(**LEGACY))

    def test_exact_is_the_list(self):
        from recon.main_recon_modules.subdomain_takeover import _collect_subdomains
        assert sorted(_collect_subdomains(_recon(**EXACT_WWW))) == ["www.example.test"]

    def test_ip_mode_never_checks_the_synthetic_root(self):
        from recon.main_recon_modules.subdomain_takeover import _collect_subdomains
        r = {"domain": "ip-targets.p1", "metadata": {"ip_mode": True, "target": "ip-targets.p1"},
             "dns": {"domain": {}, "subdomains": {"192-0-2-1": {}}}}
        assert _collect_subdomains(r) == []


class TestVhost:
    """REC-14."""

    def test_exact_candidates_are_the_list(self):
        from recon.main_recon_modules.vhost_sni_enum import _build_candidate_scope, _candidate_in_scope
        scope = _build_candidate_scope(_recon(**EXACT_WWW), {})
        assert _candidate_in_scope("www.example.test", scope)
        assert not _candidate_in_scope("admin.example.test", scope)
        assert not _candidate_in_scope("example.test", scope)

    def test_star_only_excludes_the_apex(self):
        from recon.main_recon_modules.vhost_sni_enum import _build_candidate_scope, _candidate_in_scope
        scope = _build_candidate_scope(_recon(**STAR_ONLY), {})
        assert _candidate_in_scope("admin.example.test", scope)
        assert not _candidate_in_scope("example.test", scope)

    def test_a_legacy_file_is_unchanged(self):
        from recon.main_recon_modules.vhost_sni_enum import _build_candidate_scope, _candidate_in_scope
        scope = _build_candidate_scope(_recon(**LEGACY), {})
        assert scope.exact is None
        assert _candidate_in_scope("example.test", scope) and _candidate_in_scope("a.example.test", scope)

    def test_exact_drops_custom_lines_off_the_list(self):
        from recon.main_recon_modules import vhost_sni_enum as v
        scope = v._build_candidate_scope(_recon(**EXACT_WWW), {})
        candidates, skipped = v._scoped_candidates(
            None, ["admin"], ["admin.example.test", "www.example.test"], ["mail.example.test"], scope)
        assert candidates == ["www.example.test"] and skipped == 2

    def test_enumerate_keeps_wordlist_names_under_the_root(self):
        from recon.main_recon_modules import vhost_sni_enum as v
        scope = v._build_candidate_scope(_recon(**STAR_ONLY), {})
        candidates, _ = v._scoped_candidates("example.test", ["admin"], [], ["example.test"], scope)
        assert candidates == ["admin.example.test"]

    def test_ip_mode_has_no_apex_to_expand(self):
        from recon.main_recon_modules.vhost_sni_enum import _detect_apex_domain
        assert _detect_apex_domain({"domain": "ip-targets.p1", "metadata": {"ip_mode": True}}) is None
        assert _detect_apex_domain({"domain": "ip-targets.p1"}) is None


class TestUncover:
    """REC-16."""

    def test_the_org_query_comes_from_the_group_not_the_settings(self):
        from recon.main_recon_modules.uncover_enrich import _build_queries
        settings = {"_WHOIS_ORG": "Stale Org From Another Group"}
        assert _build_queries("example.test", settings, "Acme Ltd") == ["example.test", 'ssl:"Acme Ltd"']
        assert _build_queries("example.test", {}, "") == ["example.test"]

    def test_an_exact_group_merges_nothing(self):
        from recon.main_recon_modules.uncover_enrich import merge_uncover_into_pipeline
        recon = _recon(**EXACT_WWW)
        data = {"hosts": ["admin.example.test"], "ips": ["198.51.100.7"], "ip_ports": {"198.51.100.7": [443]},
                "urls": ["https://www.example.test/a", "https://admin.example.test/b"]}
        assert merge_uncover_into_pipeline(recon, data, "example.test") == 0
        assert data["hosts"] == [] and data["ips"] == [] and data["ip_ports"] == {}
        assert data["urls"] == ["https://www.example.test/a"]
        assert "admin.example.test" not in recon["dns"]["subdomains"]
        assert "expanded_ips" not in recon["metadata"]

    def test_ip_mode_never_searches_the_synthetic_root(self):
        from recon.main_recon_modules import uncover_enrich as u
        r = {"domain": "ip-targets.p1", "metadata": {"ip_mode": True}}
        with mock.patch.object(u, "_build_provider_config", return_value=({}, ["shodan"])), \
             mock.patch.object(u, "_run_uncover_docker", side_effect=AssertionError("searched")):
            assert u.run_uncover_expansion(r, {"UNCOVER_ENABLED": True}) == {}


class TestJsRecon:
    """REC-17."""

    def test_first_party_is_the_org(self):
        from recon.main_recon_modules.js_recon import _first_party_scope, _is_third_party_url
        r = _recon(mode="enumerate", include_root=False, org="example.test")
        r["domain"] = "api.example.test"
        r["metadata"]["root_domain"] = "api.example.test"
        fp = _first_party_scope(r)
        assert fp.roots == ("example.test",)
        assert not _is_third_party_url("https://www.example.test/app.js", fp)
        assert _is_third_party_url("https://vendor.test/x.js", fp)

    def test_a_legacy_file_keeps_its_scan_root(self):
        from recon.main_recon_modules.js_recon import _first_party_scope
        r = _recon()
        r["domain"] = "api.example.test"
        assert _first_party_scope(r).roots == ("api.example.test",)

    def test_an_org_sibling_is_neither_new_nor_external(self):
        from recon.main_recon_modules.js_recon import _extract_subdomains
        new, ext = _extract_subdomains(
            [{"full_url": "https://v2.api.example.test/x"}, {"full_url": "https://www.example.test/y"},
             {"full_url": "https://cdn.vendor.test/z"}],
            "api.example.test", set(), frozenset(), ("example.test",))
        assert new == ["v2.api.example.test"]
        assert [e["domain"] for e in ext] == ["cdn.vendor.test"]


class TestCrawlers:
    """REC-23."""

    def test_paramspider_exact_host_match(self):
        from recon.helpers.resource_enum.paramspider_helpers import merge_paramspider_into_by_base_url
        urls = ["https://www.example.test/a?x=1", "https://a.www.example.test/b?y=2"]
        _, stats = merge_paramspider_into_by_base_url(urls, {}, {"www.example.test"}, exact=True)
        assert stats["paramspider_out_of_scope"] == 1
        _, stats = merge_paramspider_into_by_base_url(urls, {}, {"www.example.test"})
        assert stats["paramspider_out_of_scope"] == 0


class TestOpenApiScope:
    """REC-21: the same hosts as the webapp's authScopePatterns."""

    def _settings(self, batch, groups):
        return {"DOMAIN_BATCH_MODE": batch, "SCOPE_GROUPS": groups, "TARGET_DOMAIN": "" if batch else groups[0]["scanRoot"]}

    def test_payload_per_group(self):
        from recon.helpers.openapi.discovery import scope_payload
        from recon.helpers.openapi.scope import Scope
        g_enum = {"scanRoot": "api.example.test", "orgDomain": "example.test", "mode": "enumerate",
                  "includeRoot": False, "exactHosts": []}
        g_exact = {"scanRoot": "example.test", "orgDomain": "example.test", "mode": "exact",
                   "includeRoot": True, "exactHosts": ["www.example.test"]}
        s = Scope.from_payload(scope_payload({}, g_enum))
        assert s.allows("https://v1.api.example.test/openapi.json")
        assert not s.allows("https://api.example.test/openapi.json")
        s = Scope.from_payload(scope_payload({}, g_exact))
        assert s.allows("https://www.example.test/openapi.json") and s.allows("https://example.test/x")
        assert not s.allows("https://shop.example.test/openapi.json")

    def test_operator_targets_are_the_listed_names(self):
        from recon.helpers.openapi.discovery import operator_targets
        groups = [{"scanRoot": "api.example.test", "orgDomain": "example.test", "mode": "enumerate",
                   "includeRoot": False, "exactHosts": ["v1.api.example.test"]},
                  {"scanRoot": "example.test", "orgDomain": "example.test", "mode": "exact",
                   "includeRoot": True, "exactHosts": ["www.example.test"]}]
        hosts, _ = operator_targets(self._settings(True, groups))
        assert hosts == {"v1.api.example.test", "example.test", "www.example.test"}
        single = [{"scanRoot": "example.test", "orgDomain": "example.test", "mode": "enumerate",
                   "includeRoot": False, "exactHosts": []}]
        hosts, _ = operator_targets(self._settings(False, single))
        assert hosts == {"example.test"}

    def test_own_group_is_matched_on_the_scan_root(self):
        from recon.helpers.openapi import discovery
        groups = [{"scanRoot": "api.example.test", "orgDomain": "example.test", "mode": "enumerate",
                   "includeRoot": False, "exactHosts": []}]
        result = {"diagnostics": discovery.Diagnostics(), "requests": []}
        settings = dict(self._settings(True, groups), OPENAPI_ENABLED=True, OPENAPI_SOURCES=[])
        with mock.patch("recon.main_recon_modules.ip_filter.is_address_safe_to_scan", return_value=True):
            discovery._discover({"domain": "other.test"}, settings, [], [], result)
        assert [d["code"] for d in result["diagnostics"]] == ["invalid_scope"]


class TestIpModeAuthScope:
    """D-22: an IP-mode project's session goes to its target IPs only, in every
    hostname mode. A scanned name never receives the credentials: it may move
    to another address after the scan. The agent (auth_scope_patterns) and the
    webapp (defaultRecordingScope) pin the same rule."""

    PROFILE = {"authType": "cookie", "authValue": "sid=abc"}

    @pytest.mark.parametrize("mode", ["ip_only", "record_only", "record_filter", "scan_all"])
    def test_the_scope_is_the_target_ips(self, mode):
        from recon.helpers.auth_profile import auth_header_lines, default_scope_hosts
        settings = {"IP_MODE": True, "TARGET_IPS": ["203.0.113.0/24", "198.51.100.7"],
                    "IP_HOSTNAME_MODE": mode, "IP_HOSTNAME_INCLUDE": ["*.example.test"],
                    "IP_HOSTNAME_SCAN_ALL_CONFIRMED": True, "TARGET_DOMAIN": "example.test"}
        assert default_scope_hosts(settings) == ["203.0.113.0/24", "198.51.100.7"]
        assert auth_header_lines(self.PROFILE, "203.0.113.9", settings) == ["Cookie: sid=abc"]
        assert auth_header_lines(self.PROFILE, "app.example.test", settings) == []
        assert auth_header_lines(self.PROFILE, "example.test", settings) == []
