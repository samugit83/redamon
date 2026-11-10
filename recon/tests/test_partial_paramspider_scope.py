"""Partial ParamSpider keeps only the run's target hosts (R-15b).

``paramspider -d example.com`` returns every archived URL under the domain. The
full pipeline keeps a URL only when its host is one of the run's target hosts
and the RoE does not exclude it (R-15). Partial ParamSpider handed the raw URLs
to the merge, whose suffix match admits any subdomain of a target host and of
an included apex, with no EXACT flag and no RoE check: a sibling, a child of a
listed host or an RoE-excluded host became BaseURL / Endpoint / Parameter nodes
for hosts the run never scans. Both paths now share one filter.

Only the graph (Neo4j) and the archive search are mocked; the target hosts come
from the real graph_target_hosts over the mocked graph.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers.resource_enum import paramspider_helpers  # noqa: E402
from recon.partial_recon_modules import parameter_discovery  # noqa: E402

ROOT = "example.com"
HOST = "app.example.com"
EXCLUDED = "pay.example.com"

IN_SCOPE = f"https://{HOST}/search?q=FUZZ"
APEX = f"https://{ROOT}/index.php?page=FUZZ"
SIBLING = "https://www.example.com/item?id=FUZZ"
CHILD = f"https://dev.{HOST}/login?next=FUZZ"
FOREIGN = "https://cdn.example.org/asset?v=FUZZ"
ON_EXCLUDED = f"https://{EXCLUDED}/checkout?amount=FUZZ"

WILDCARD = [{"rootDomain": ROOT, "prefixes": ["*"], "batch": True}]
EXACT = [{"rootDomain": ROOT, "prefixes": ["app."], "batch": True}]


def _graph(monkeypatch, graph_hosts):
    session = MagicMock()
    session.__enter__.return_value = session
    session.run.side_effect = lambda cypher, **_p: (
        [{"root": ROOT, "sub": h} for h in graph_hosts] if "HAS_SUBDOMAIN" in cypher else [])
    client = MagicMock()
    client.__enter__.return_value = client
    client.verify_connection.return_value = True
    client.driver.session.return_value = session
    client.update_graph_from_resource_enum.return_value = {}
    module = MagicMock()
    module.Neo4jClient.return_value = client
    monkeypatch.setitem(sys.modules, "graph_db", module)
    return client


def _partial(monkeypatch, urls, groups=WILDCARD, graph_hosts=(HOST,), **settings):
    client = _graph(monkeypatch, graph_hosts)
    monkeypatch.setattr(paramspider_helpers, "run_paramspider_discovery",
                        lambda domains, *_a, **_k: (list(urls), {}))
    parameter_discovery.run_paramspider({
        "_settings": settings, "domains": [ROOT], "domain": ROOT, "domain_groups": groups,
    })
    return client.update_graph_from_resource_enum.call_args.kwargs["recon_data"]["resource_enum"]


def _hosts(resource_enum_out):
    return set(resource_enum_out["by_base_url"])


class TestPartialParamSpider:
    def test_a_sibling_under_the_apex_gets_no_endpoint(self, monkeypatch):
        # The apex is a target of a wildcard root, and the merge's suffix match
        # admitted every name under it, scanned or not.
        out = _partial(monkeypatch, [IN_SCOPE, APEX, SIBLING, FOREIGN])
        assert _hosts(out) == {f"https://{HOST}", f"https://{ROOT}"}

    def test_a_child_of_a_listed_host_gets_no_endpoint_on_an_exact_group(self, monkeypatch):
        out = _partial(monkeypatch, [IN_SCOPE, CHILD], groups=EXACT)
        assert _hosts(out) == {f"https://{HOST}"}

    def test_a_child_of_a_target_host_gets_no_endpoint_on_a_wildcard_group(self, monkeypatch):
        out = _partial(monkeypatch, [IN_SCOPE, CHILD])
        assert _hosts(out) == {f"https://{HOST}"}

    def test_an_roe_excluded_host_gets_no_endpoint(self, monkeypatch):
        out = _partial(monkeypatch, [IN_SCOPE, ON_EXCLUDED],
                       ROE_ENABLED=True, ROE_EXCLUDED_HOSTS=[EXCLUDED])
        assert EXCLUDED not in str(out["by_base_url"])
        assert _hosts(out) == {f"https://{HOST}"}

    def test_dropped_urls_are_counted_out_of_scope(self, monkeypatch):
        out = _partial(monkeypatch, [IN_SCOPE, SIBLING, CHILD, FOREIGN, ON_EXCLUDED])
        stats = out["scan_metadata"]["paramspider_stats"]
        assert stats["paramspider_total"] == 5
        assert stats["paramspider_out_of_scope"] == 4
        assert stats["paramspider_new"] == 1

    def test_in_scope_urls_are_unchanged(self, monkeypatch):
        second = f"http://{HOST}/old.php?page=FUZZ&lang=FUZZ"
        out = _partial(monkeypatch, [IN_SCOPE, second])
        assert _hosts(out) == {f"https://{HOST}", f"http://{HOST}"}
        endpoints = out["by_base_url"][f"https://{HOST}"]["endpoints"]
        assert endpoints["/search"]["sources"] == ["paramspider"]
        assert out["scan_metadata"]["paramspider_stats"]["paramspider_out_of_scope"] == 0


class TestSharedFilter:
    """paramspider_urls_in_scope: the one filter the full pipeline and partial
    recon both call before the merge."""

    def test_only_target_hosts_pass(self):
        kept = paramspider_helpers.paramspider_urls_in_scope(
            [IN_SCOPE, APEX, SIBLING, CHILD, FOREIGN], {HOST}, {})
        assert kept == [IN_SCOPE]

    def test_an_roe_excluded_target_host_is_dropped(self):
        settings = {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": [f"*.{ROOT}"]}
        kept = paramspider_helpers.paramspider_urls_in_scope(
            [IN_SCOPE, APEX], {HOST, ROOT}, settings)
        assert kept == [APEX]

    def test_the_roe_list_is_ignored_when_the_roe_is_off(self):
        settings = {"ROE_ENABLED": False, "ROE_EXCLUDED_HOSTS": [EXCLUDED]}
        kept = paramspider_helpers.paramspider_urls_in_scope(
            [IN_SCOPE, ON_EXCLUDED], {HOST, EXCLUDED}, settings)
        assert kept == [IN_SCOPE, ON_EXCLUDED]

    def test_host_match_ignores_case_and_port_on_both_sides(self):
        upper = "https://APP.Example.com:8443/view?id=FUZZ"
        kept = paramspider_helpers.paramspider_urls_in_scope([upper], {"App.Example.com"}, {})
        assert kept == [upper]

    @pytest.mark.parametrize("url", ["not a url", "https://[bad.example.com]/x?a=FUZZ", ""])
    def test_a_malformed_url_is_dropped_not_raised(self, url):
        assert paramspider_helpers.paramspider_urls_in_scope([url], {HOST}, {}) == []

    def test_no_target_hosts_keeps_nothing(self):
        assert paramspider_helpers.paramspider_urls_in_scope([IN_SCOPE], set(), {}) == []
