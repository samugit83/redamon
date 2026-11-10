"""GraphQL discovery reads what the full pipeline writes, in scope, under the RoE (plan 12.12).

Discovery read resource_enum['endpoints'] (lists of POST {path, method}),
js_recon['findings'], urlscan['by_domain'] and a `content-type` header key.
The full pipeline writes none of those (resource_enum.by_base_url, a dict per
path; js_recon.endpoints; urlscan.urls_with_paths; a top-level content_type),
so in a full scan only the http_probe pattern guesses and the operator's list
were ever probed. And the scanner took the RoE list from metadata.roe, which
only partial recon's graph builder writes, so a full scan applied no exclusion.

The shapes below are copied from the writers: endpoint_helpers.organize_endpoints,
js_recon/endpoints.py, urlscan_enrich._parse_url_path, http_probe's by_url.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.graphql_scan import discovery  # noqa: E402
from recon.graphql_scan.discovery import discover_graphql_endpoints  # noqa: E402


def _full_recon(**sections):
    """A domain group's dict, as run_domain_recon builds it."""
    base = {
        "domain": "example.com",
        "metadata": {"root_domain": "example.com", "scope_mode": "enumerate",
                     "include_root_domain": True},
        "http_probe": {"by_url": {
            "https://www.example.com": {"status_code": 200, "content_type": "text/html"},
        }},
    }
    base.update(sections)
    return base


def _endpoint(path, methods=("GET",), query=(), body=()):
    return {"path": path, "methods": list(methods),
            "parameters": {"query": [{"name": n} for n in query],
                           "body": [{"name": n} for n in body], "path": []}}


class TestEachFullReconSource:
    def test_resource_enum_by_base_url_any_method(self):
        combined = _full_recon(resource_enum={"by_base_url": {
            "https://www.example.com": {"endpoints": {
                "/v3/graphql": _endpoint("/v3/graphql", methods=("GET",)),
                "/about": _endpoint("/about"),
            }, "summary": {}},
        }})
        found = discover_graphql_endpoints(combined, {})
        assert "https://www.example.com/v3/graphql" in found
        assert "https://www.example.com/about" not in found

    def test_graphql_parameters_add_their_own_endpoint_not_the_root(self):
        combined = _full_recon(resource_enum={"by_base_url": {
            "https://www.example.com": {"endpoints": {
                "/api/data": _endpoint("/api/data", body=("operationName", "variables")),
            }},
        }})
        found = discover_graphql_endpoints(combined, {})
        assert "https://www.example.com/api/data" in found
        assert "https://www.example.com" not in found

    def test_js_recon_endpoints_join_their_script_origin(self):
        combined = _full_recon(
            http_probe={"by_url": {
                "https://www.example.com": {"status_code": 200},
                "https://cdn.example.com": {"status_code": 200},
            }},
            js_recon={"endpoints": [
                {"type": "graphql", "path": "/internal/gql", "full_url": "/internal/gql",
                 "source_js": "https://cdn.example.com/static/app.js"},
                {"type": "graphql_introspection", "path": "/graphql", "full_url": "",
                 "source_js": "https://www.example.com/main.js"},
                {"type": "rest", "path": "/api/graphql/v2", "full_url": "https://www.example.com/api/graphql/v2",
                 "source_js": "https://www.example.com/main.js"},
                {"type": "rest", "path": "/api/users", "full_url": "https://www.example.com/api/users",
                 "source_js": "https://www.example.com/main.js"},
            ]})
        found = discover_graphql_endpoints(combined, {})
        assert "https://cdn.example.com/internal/gql" in found
        assert "https://www.example.com/internal/gql" not in found   # not every base URL
        assert "https://www.example.com/graphql" in found
        assert "https://www.example.com/api/graphql/v2" in found
        assert "https://www.example.com/api/users" not in found

    def test_urlscan_urls_with_paths_contribute_graphql_paths(self):
        combined = _full_recon(urlscan={"urls_with_paths": [
            {"full_url": "https://api.example.com/gql?x=1", "base_url": "https://api.example.com",
             "path": "/gql", "params": {"x": "1"}},
            {"full_url": "https://api.example.com/login", "base_url": "https://api.example.com",
             "path": "/login", "params": {}},
        ]})
        found = discover_graphql_endpoints(combined, {})
        assert "https://api.example.com/gql" in found
        assert "https://api.example.com/login" not in found

    def test_http_probe_content_type(self):
        combined = _full_recon(http_probe={"by_url": {
            "https://www.example.com/api": {"status_code": 405, "content_type": "application/graphql-response+json"},
        }})
        assert "https://www.example.com/api" in discover_graphql_endpoints(combined, {})


class TestScope:
    def test_an_out_of_scope_absolute_js_url_contributes_nothing(self):
        combined = _full_recon(js_recon={"endpoints": [
            {"type": "graphql", "path": "https://api.thirdparty.example.org/graphql",
             "full_url": "https://api.thirdparty.example.org/graphql",
             "source_js": "https://www.example.com/main.js"},
        ]})
        found = discover_graphql_endpoints(combined, {})
        assert not [u for u in found if "thirdparty" in u]

    def test_urlscan_entries_contribute_nothing(self):
        # `entries` holds every result, out-of-scope pages included.
        combined = _full_recon(urlscan={"entries": [
            {"url": "https://www.example.com/graphql-internal", "domain": "www.example.com"},
            {"url": "https://evil.example.net/graphql", "domain": "evil.example.net"},
        ], "by_domain": {"x": {"urls": [{"url": "https://evil.example.net/"}]}}})
        found = discover_graphql_endpoints(combined, {})
        assert "https://www.example.com/graphql-internal" not in found
        assert not [u for u in found if "evil" in u]

    def test_no_pattern_guess_on_a_urlscan_base_url(self):
        combined = _full_recon(urlscan={"urls_with_paths": [
            {"full_url": "https://shop.example.com/cart", "base_url": "https://shop.example.com",
             "path": "/cart", "params": {}},
        ]})
        found = discover_graphql_endpoints(combined, {})
        assert not [u for u in found if u.startswith("https://shop.example.com")]

    def test_an_exact_group_keeps_its_listed_hosts_only(self):
        combined = _full_recon(
            metadata={"root_domain": "example.com", "scope_mode": "exact",
                      "include_root_domain": False, "subdomain_filter": ["www.example.com"]},
            js_recon={"endpoints": [
                {"type": "graphql", "path": "https://admin.example.com/graphql",
                 "full_url": "https://admin.example.com/graphql",
                 "source_js": "https://www.example.com/main.js"},
            ]})
        found = discover_graphql_endpoints(combined, {})
        assert "https://admin.example.com/graphql" not in found

    def test_the_operators_own_endpoints_pass_the_project_scope(self):
        # R-43: they carry the GraphQL credential, so an off-project entry is refused.
        settings = {"GRAPHQL_ENDPOINTS": "https://gql.example.com/graphql,https://gql.example.net/graphql",
                    "SCOPE_GROUPS": [{"scanRoot": "example.com", "mode": "enumerate",
                                      "includeRoot": True, "exactHosts": []}]}
        found = discover_graphql_endpoints(_full_recon(), settings)
        assert "https://gql.example.com/graphql" in found
        assert "https://gql.example.net/graphql" not in found


class TestTheRoeListInFullRecon:
    def test_an_excluded_host_is_dropped_without_metadata_roe(self):
        from recon.graphql_scan import scanner
        combined = _full_recon(http_probe={"by_url": {
            "https://www.example.com": {"status_code": 200},
            "https://legacy.example.com": {"status_code": 200},
        }})
        assert "roe" not in combined["metadata"]
        tested = []

        def fake_test(endpoint, *a, **k):
            tested.append(endpoint)
            return {"endpoint_data": {"introspection_enabled": False}, "vulnerabilities": []}

        settings = {"GRAPHQL_SECURITY_ENABLED": True, "GRAPHQL_CONCURRENCY": 1, "GRAPHQL_RATE_LIMIT": 0,
                    "ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": ["legacy.example.com"]}
        with mock.patch.object(scanner, "test_single_endpoint", side_effect=fake_test):
            scanner.run_graphql_scan(combined, settings)
        assert tested
        assert not [u for u in tested if "legacy.example.com" in u]
        assert combined["graphql_scan"]["summary"]["endpoints_skipped"] > 0

    def test_the_pipeline_matcher_covers_cidrs_and_subdomains(self):
        kept = discovery.filter_by_roe(
            ["https://192.0.2.7/graphql", "https://a.b.example.com/graphql", "https://www.example.org/graphql"],
            {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": ["192.0.2.0/24", "example.com"]})
        assert kept == ["https://www.example.org/graphql"]

    def test_metadata_roe_is_still_the_fallback(self):
        assert discovery.roe_settings_for(
            {"metadata": {"roe": {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": ["x.example.com"]}}}, {},
        ) == {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": ["x.example.com"]}


class TestPartialParity:
    def test_the_partial_builders_shapes_yield_candidates(self):
        # What _build_graphql_data_from_graph returns (see its docstring).
        combined = {
            "domain": "example.com", "domains": ["example.com"],
            "http_probe": {"by_url": {"https://www.example.com": {
                "url": "https://www.example.com", "host": "www.example.com",
                "status_code": 200, "content_type": "text/html", "headers": {}}}},
            "resource_enum": {"by_base_url": {"https://www.example.com": {"endpoints": {
                "/data": {"path": "/data", "methods": ["POST"],
                          "parameters": {"query": [{"name": "query"}], "body": [], "path": []}},
            }}}, "discovered_urls": []},
            "js_recon": {"endpoints": [{"type": "graphql", "path": "/v2/graphql", "full_url": "",
                                        "source_js": "https://www.example.com"}]},
            "metadata": {"roe": {"ROE_ENABLED": False, "ROE_EXCLUDED_HOSTS": []}},
        }
        found = discover_graphql_endpoints(combined, {})
        assert "https://www.example.com/data" in found
        assert "https://www.example.com/v2/graphql" in found
