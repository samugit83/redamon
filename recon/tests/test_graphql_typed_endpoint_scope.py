"""The GraphQL credential never reaches a typed endpoint outside the project (R-43).

GRAPHQL_ENDPOINTS was kept "as given": discovery scoped every candidate it
found (plan 12.12) but added the operator's own list unchecked, and the
scanner sent the GraphQL auth header to every endpoint. One entry on a host
outside the project (a typo, or a value an MCP client with recon:settings
wrote) received the credential on the next scan.

These run the real scanner, discovery and introspection code; only the HTTP
session is replaced, so each test sees every request and the headers it carried.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from unittest import mock
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.graphql_scan import scanner  # noqa: E402
from recon.graphql_scan.discovery import discover_graphql_endpoints  # noqa: E402
from recon.helpers import circuit_breaker as cb  # noqa: E402

_TOKEN = "synthetic-gql-token-not-a-real-credential"
_AUTH = f"Bearer {_TOKEN}"


def _group(root, mode="enumerate", include_root=True, exact=()):
    return {"scanRoot": root, "orgDomain": root, "mode": mode,
            "includeRoot": include_root, "exactHosts": list(exact)}


def _settings(endpoints, groups=None, **extra):
    settings = {
        "GRAPHQL_SECURITY_ENABLED": True, "GRAPHQL_CONCURRENCY": 1, "GRAPHQL_RATE_LIMIT": 0,
        "GRAPHQL_RETRY_COUNT": 0, "GRAPHQL_INTROSPECTION_TEST": True,
        "GRAPHQL_AUTH_TYPE": "bearer", "GRAPHQL_AUTH_VALUE": _TOKEN,
        "GRAPHQL_ENDPOINTS": ",".join(endpoints),
        "SCOPE_GROUPS": [_group("example.com")] if groups is None else groups,
    }
    settings.update(extra)
    return settings


def _domain_run(root="example.com", live=("https://www.example.com",), **meta):
    """A domain group's dict, as run_domain_recon builds it."""
    metadata = {"root_domain": root, "scope_mode": "enumerate", "include_root_domain": True}
    metadata.update(meta)
    return {"domain": root, "metadata": metadata,
            "http_probe": {"by_url": {u: {"status_code": 404} for u in live}}}


def _ip_run(ips, hostnames=()):
    """The dict run_ip_recon builds: an exact scope over the listed addresses."""
    return {
        "domain": "ip-targets.p1",
        "metadata": {"root_domain": "ip-targets.p1", "ip_mode": True, "scope_mode": "exact",
                     "include_root_domain": False, "org_domain": "ip-targets.p1",
                     "subdomain_filter": list(ips) + list(hostnames)},
        "http_probe": {"by_url": {}},
    }


class _Response:
    status_code = 404
    content = b""

    def json(self):
        return {}


class _Session:
    """Stands in for the scanner's retry session: records every request."""

    def __init__(self):
        self.requests = []

    def post(self, url, json=None, headers=None, **kwargs):
        self.requests.append((url, dict(headers or {})))
        return _Response()


def _scan(combined, settings):
    session = _Session()
    with mock.patch.object(scanner, "_build_retry_session", return_value=session):
        scanner.run_graphql_scan(combined, settings)
    return session.requests


def _hosts(requests):
    return {urlparse(url).hostname for url, _ in requests}


def _gaps(source="roe_excluded"):
    return [g for g in cb.coverage_report().gaps if g["source"] == source]


class TestTheCredentialStaysInScope:
    def test_an_out_of_scope_typed_endpoint_never_receives_the_credential(self):
        requests = _scan(_domain_run(), _settings(
            ["https://api.example.com/graphql", "https://gql.example.net/graphql"]))

        assert "gql.example.net" not in _hosts(requests)
        typed = [h for url, h in requests if url == "https://api.example.com/graphql"]
        assert typed and all(h.get("Authorization") == _AUTH for h in typed)

    def test_no_request_to_the_refused_host_carries_any_header(self):
        requests = _scan(_domain_run(), _settings(["http://203.0.113.21/graphql"]))
        assert not [url for url, _ in requests if "203.0.113.21" in url]

    def test_an_exact_group_admits_only_its_listed_hosts(self):
        groups = [_group("example.com", mode="exact", include_root=False,
                         exact=["www.example.com"])]
        combined = _domain_run(scope_mode="exact", include_root_domain=False,
                               subdomain_filter=["www.example.com"])
        requests = _scan(combined, _settings(
            ["https://www.example.com/v2/graphql", "https://admin.example.com/graphql"], groups))

        assert "admin.example.com" not in _hosts(requests)
        assert "https://www.example.com/v2/graphql" in {url for url, _ in requests}

    def test_an_excluded_root_is_no_target(self):
        groups = [_group("example.com", include_root=False)]
        combined = _domain_run(include_root_domain=False)
        found = discover_graphql_endpoints(combined, _settings(
            ["https://example.com/graphql", "https://api.example.com/graphql"], groups))
        assert "https://example.com/graphql" not in found
        assert "https://api.example.com/graphql" in found


class TestTheRefusalIsSaid:
    def test_noted_as_a_coverage_gap_with_a_valid_token(self):
        _scan(_domain_run(), _settings(
            ["https://gql.example.net/graphql", "https://other.example.org/graphql"]))

        gaps = _gaps()
        assert len(gaps) == 1
        assert gaps[0]["module"] == "graphql_scan"
        assert gaps[0]["skipped"] == 2
        assert re.fullmatch(r"[a-z0-9_]{1,64}", gaps[0]["source"])
        # A refusal is no lost coverage of a finding source: nothing is kept from the prune.
        assert "graphql_scan" not in cb.coverage_report().degraded_sources

    def test_logged_and_noted_once_per_run_across_batch_groups(self, capsys):
        groups = [_group("example.com"), _group("example.org")]
        settings = _settings(["https://gql.example.net/graphql"], groups)
        discover_graphql_endpoints(_domain_run(), settings)
        discover_graphql_endpoints(
            _domain_run("example.org", live=("https://www.example.org",)), settings)

        out = capsys.readouterr().out
        assert out.count("gql.example.net") == 1
        assert _gaps()[0]["skipped"] == 1

    def test_in_scope_endpoints_note_nothing(self):
        _scan(_domain_run(), _settings(["https://api.example.com/graphql"]))
        assert _gaps() == []


class TestBatchGroups:
    def test_another_groups_endpoint_is_left_to_its_own_run(self):
        groups = [_group("example.com"), _group("example.org")]
        settings = _settings(["https://api.example.org/graphql"], groups)

        this_group = discover_graphql_endpoints(_domain_run(), settings)
        its_group = discover_graphql_endpoints(
            _domain_run("example.org", live=("https://www.example.org",)), settings)

        assert "https://api.example.org/graphql" not in this_group
        assert "https://api.example.org/graphql" in its_group
        assert _gaps() == []  # in the project: no refusal to report


class TestIpMode:
    def test_a_target_address_gets_the_credential_and_another_gets_no_request(self):
        settings = _settings(["http://192.0.2.10:8080/graphql", "http://192.0.2.21/graphql"],
                             groups=[], IP_MODE=True, TARGET_IPS=["192.0.2.10"])
        requests = _scan(_ip_run(["192.0.2.10"]), settings)

        assert "192.0.2.21" not in _hosts(requests)
        typed = [h for url, h in requests if url == "http://192.0.2.10:8080/graphql"]
        assert typed and all(h.get("Authorization") == _AUTH for h in typed)
        assert _gaps()[0]["skipped"] == 1

    def test_a_cidr_target_admits_its_addresses(self):
        settings = _settings(["http://192.0.2.10/graphql", "http://198.51.100.5/graphql"],
                             groups=[], IP_MODE=True, TARGET_IPS=["192.0.2.0/28"])
        # A partial run's dict: the synthetic root, no BaseURL on the address.
        combined = {"domain": "ip-targets.p1", "domains": ["ip-targets.p1"],
                    "http_probe": {"by_url": {}}, "metadata": {"roe": {}}}
        found = discover_graphql_endpoints(combined, settings)
        assert found == ["http://192.0.2.10/graphql"]


class TestPartialRecon:
    def _run_partial(self, settings, builder_result):
        from recon.partial_recon_modules.graphql_scanning import run_graphqlscan
        session = _Session()
        os.environ["USER_ID"], os.environ["PROJECT_ID"] = "u1", "p1"
        try:
            with mock.patch("recon.project_settings.get_settings", return_value=settings), \
                 mock.patch("recon.partial_recon_modules.graphql_scanning."
                            "_build_graphql_data_from_graph", return_value=builder_result), \
                 mock.patch.object(scanner, "_build_retry_session", return_value=session), \
                 mock.patch("graph_db.Neo4jClient"):
                run_graphqlscan({"tool_id": "GraphqlScan", "domains": ["example.com"],
                                 "include_graph_targets": True})
        finally:
            for key in ("USER_ID", "PROJECT_ID"):
                os.environ.pop(key, None)
        return session.requests

    def test_the_project_setting_is_scoped_in_a_partial_run(self):
        groups = [_group("example.com", mode="exact", include_root=False,
                         exact=["www.example.com"])]
        builder_result = {
            "domain": "example.com", "domains": ["example.com"],
            "http_probe": {"by_url": {"https://www.example.com": {"status_code": 404}}},
            "resource_enum": {"by_base_url": {}, "endpoints": {}, "discovered_urls": []},
            "js_recon": {"endpoints": []},
            "metadata": {"roe": {"ROE_ENABLED": False, "ROE_EXCLUDED_HOSTS": []}},
        }
        requests = self._run_partial(_settings(
            ["https://www.example.com/v2/graphql", "https://admin.example.com/graphql",
             "https://gql.example.net/graphql"], groups), builder_result)

        assert not {"admin.example.com", "gql.example.net"} & _hosts(requests)
        typed = [h for url, h in requests if url == "https://www.example.com/v2/graphql"]
        assert typed and all(h.get("Authorization") == _AUTH for h in typed)
