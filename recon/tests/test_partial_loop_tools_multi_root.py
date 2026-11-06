"""Phase 5: the partial tools that loop per root, over a Domain batch.

  - SubdomainDiscovery enumerates only wildcard roots; a literal group is
    skipped, and with no enumerable root the run exits 1.
  - Urlscan and Uncover run once per root; a 429 is rate_limited, an empty
    answer is no_results.
  - Gau and ParamSpider pass every root's in-scope hosts as targets in one run,
    filter a user subdomain to any root, and attach it to its own root.

Fixture roots are alpha.test / beta.test / gamma.test only.
"""
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.partial_recon_modules import (  # noqa: E402
    helpers, osint_enrichment, parameter_discovery, subdomain_discovery, web_crawling,
)
from recon.partial_recon_modules import graph_builders  # noqa: E402

ROOTS = ["alpha.test", "beta.test", "gamma.test"]
# alpha is literal (two listed hosts), beta and gamma are wildcards.
GROUPS = [
    {"rootDomain": "alpha.test", "prefixes": ["www.", "."], "batch": True},
    {"rootDomain": "beta.test", "prefixes": ["*"], "batch": True},
    {"rootDomain": "gamma.test", "prefixes": ["*"], "batch": True},
]
BASE = {"_settings": {}, "domains": ROOTS, "domain": ROOTS[0],
        "domain_groups": GROUPS, "batch_mode": True}


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(helpers.time, "sleep", lambda *_a, **_k: None)


class _Session:
    def __init__(self, rows_for):
        self.rows_for = rows_for
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, cypher, **params):
        self.calls.append((cypher, params))
        result = MagicMock()
        rows = self.rows_for(cypher, params)
        result.__iter__ = lambda s: iter(rows)
        result.single.return_value = rows[0] if rows else None
        return result


def _graph(monkeypatch, rows_for, sink=None):
    client = MagicMock()
    client.verify_connection.return_value = True
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)

    def _session():
        s = _Session(rows_for)
        if sink is not None:
            sink.append(s)
        return s

    client.driver.session.side_effect = _session
    for m in ("update_graph_from_urlscan_discovery", "update_graph_from_urlscan_enrichment",
              "update_graph_from_uncover", "update_graph_from_resource_enum",
              "update_graph_from_partial_discovery", "create_user_input_node",
              "update_user_input_status"):
        getattr(client, m).return_value = {}
    module = MagicMock()
    module.Neo4jClient.return_value = client
    monkeypatch.setitem(sys.modules, "graph_db", module)
    return client


class TestGraphTargetHosts:
    def _rows(self, cypher, params):
        if "HAS_SUBDOMAIN" in cypher:
            return [{"root": "alpha.test", "sub": "www.alpha.test"},
                    {"root": "alpha.test", "sub": "san-only.alpha.test"},
                    {"root": "beta.test", "sub": "api.beta.test"}]
        return []

    def test_literal_group_keeps_only_its_hosts_wildcard_keeps_all(self, monkeypatch):
        _graph(monkeypatch, self._rows)
        hosts = graph_builders.graph_target_hosts("u1", "p1", ROOTS, GROUPS)
        # alpha is literal: its apex (".") and www. are listed, san-only is not.
        # beta/gamma are wildcards: apex kept, api.beta.test kept.
        assert "www.alpha.test" in hosts
        assert "alpha.test" in hosts
        assert "san-only.alpha.test" not in hosts
        assert {"beta.test", "gamma.test", "api.beta.test"} <= set(hosts)

    def test_graph_down_returns_the_apexes_it_can(self, monkeypatch):
        client = _graph(monkeypatch, self._rows)
        client.verify_connection.return_value = False
        hosts = graph_builders.graph_target_hosts("u1", "p1", ROOTS, GROUPS)
        assert "san-only.alpha.test" not in hosts
        assert {"alpha.test", "beta.test", "gamma.test"} == set(hosts)


class TestSubdomainDiscovery:
    def test_only_wildcard_roots_enumerate(self):
        enum = subdomain_discovery._enumerable_roots(ROOTS, BASE, {"SUBDOMAIN_DISCOVERY_ENABLED": True})
        assert enum == ["beta.test", "gamma.test"]

    def test_a_single_domain_project_always_enumerates(self):
        cfg = {"domains": ["alpha.test"], "batch_mode": False,
               "domain_groups": [{"rootDomain": "alpha.test", "prefixes": ["www."], "batch": False}]}
        enum = subdomain_discovery._enumerable_roots(["alpha.test"], cfg, {"SUBDOMAIN_DISCOVERY_ENABLED": True})
        assert enum == ["alpha.test"]

    def test_all_literal_roots_exit_1(self, monkeypatch):
        _graph(monkeypatch, lambda c, p: [])
        cfg = {**BASE, "domain_groups": [
            {"rootDomain": r, "prefixes": ["www."], "batch": True} for r in ROOTS]}
        with pytest.raises(SystemExit):
            subdomain_discovery.run_subdomain_discovery(cfg)

    def test_the_loop_runs_each_wildcard_root(self, monkeypatch):
        _graph(monkeypatch, lambda c, p: [])
        seen = []
        with patch("recon.main_recon_modules.domain_recon.discover_subdomains",
                   side_effect=lambda domain, **kw: seen.append(domain) or {"subdomains": [f"x.{domain}"], "dns": {}}):
            statuses = subdomain_discovery.run_subdomain_discovery(dict(BASE))
        assert seen == ["beta.test", "gamma.test"]
        assert statuses["beta.test"] == "ok" and statuses["gamma.test"] == "ok"
        assert "literal" in statuses["alpha.test"]


class TestUrlscanPerRoot:
    def test_a_rate_limited_root_then_an_empty_root(self, monkeypatch):
        _graph(monkeypatch, lambda c, p: [])
        answers = {
            "alpha.test": {"results_count": 0, "rate_limited": True},
            "beta.test": {"results_count": 0, "rate_limited": True},
            "gamma.test": {"results_count": 0, "entries": []},
        }
        with patch("recon.main_recon_modules.urlscan_enrich.run_urlscan_discovery_only",
                   side_effect=lambda domain, settings, org_domain="": answers[domain]):
            statuses = osint_enrichment.run_urlscan(dict(BASE))
        # alpha is retried once and stays rate-limited; gamma has no results.
        assert statuses == {"alpha.test": "rate_limited", "beta.test": "rate_limited",
                            "gamma.test": "no_results"}

    def test_a_root_with_results_writes_the_graph_with_every_root(self, monkeypatch):
        sink = []
        _graph(monkeypatch, lambda c, p: [], sink=sink)
        good = {"results_count": 1, "entries": [{"domain": "api.beta.test", "ip": "10.0.2.1"}]}
        captured = {}
        client_written = []
        with patch("recon.main_recon_modules.urlscan_enrich.run_urlscan_discovery_only",
                   side_effect=lambda domain, settings, org_domain="": good if domain == "beta.test"
                   else {"results_count": 0}):
            import graph_db  # the mocked module
            graph_db.Neo4jClient.return_value.update_graph_from_urlscan_discovery.side_effect = \
                lambda recon_data, user_id, project_id: client_written.append(recon_data) or {}
            statuses = osint_enrichment.run_urlscan(dict(BASE))
        assert statuses["beta.test"] == "ok"
        assert client_written and client_written[0]["domains"] == ROOTS


class TestUncoverPerRoot:
    def test_each_root_is_expanded_and_empty_is_no_results(self, monkeypatch):
        _graph(monkeypatch, lambda c, p: [])
        seen = []

        def fake(combined, settings):
            seen.append(combined["domain"])
            return {"hosts": ["h.beta.test"], "ips": [], "total_deduped": 1} if combined["domain"] == "beta.test" else {}

        with patch("recon.main_recon_modules.uncover_enrich.run_uncover_expansion", side_effect=fake):
            statuses = osint_enrichment.run_uncover(dict(BASE))
        assert seen == ROOTS
        assert statuses == {"alpha.test": "no_results", "beta.test": "ok", "gamma.test": "no_results"}


def _resource_rows(cypher, params):
    if "HAS_SUBDOMAIN" in cypher:
        return [{"root": "beta.test", "sub": "api.beta.test"},
                {"root": "alpha.test", "sub": "san-only.alpha.test"}]
    return []


class TestGauParamSpiderAllRoots:
    @pytest.mark.parametrize("mod,runner,discovery,merge", [
        (web_crawling, "run_gau", "recon.helpers.resource_enum.run_gau_discovery",
         "recon.helpers.resource_enum.merge_gau_into_by_base_url"),
        (parameter_discovery, "run_paramspider",
         "recon.helpers.resource_enum.paramspider_helpers.run_paramspider_discovery",
         "recon.helpers.resource_enum.paramspider_helpers.merge_paramspider_into_by_base_url"),
    ])
    def test_targets_span_every_root_and_a_user_sub_attaches_to_its_root(
            self, monkeypatch, mod, runner, discovery, merge):
        sink = []
        _graph(monkeypatch, _resource_rows, sink=sink)
        seen = {}

        def fake_discovery(target_domains, *a, **kw):
            seen["targets"] = set(target_domains)
            return [], {}

        def fake_merge(*a, **kw):
            return {}, {"paramspider_total": 0, "paramspider_parsed": 0, "paramspider_new": 0,
                        "paramspider_overlap": 0, "paramspider_out_of_scope": 0,
                        "gau_parsed": 0, "gau_new": 0}

        cfg = {**BASE, "user_targets": {"subdomains": ["vhost.gamma.test", "x.other.example"]}}
        with patch(discovery, side_effect=fake_discovery, create=True), \
             patch(merge, side_effect=fake_merge, create=True):
            try:
                getattr(mod, runner)(cfg)
            except Exception:
                pass
        targets = seen.get("targets") or set()
        # apex of each wildcard root + graph host; literal alpha keeps only listed
        assert {"beta.test", "gamma.test", "api.beta.test"} <= targets
        assert "san-only.alpha.test" not in targets
        assert "vhost.gamma.test" in targets      # user sub under a root, accepted
        assert "x.other.example" not in targets    # under no root, rejected

    def test_a_user_sub_with_no_archive_still_attaches_to_its_root(self, monkeypatch):
        sink = []
        _graph(monkeypatch, lambda c, p: [], sink=sink)
        with patch("recon.helpers.resource_enum.run_gau_discovery",
                   side_effect=lambda *a, **kw: ([], {}), create=True):
            cfg = {**BASE, "include_graph_targets": False,
                   "user_targets": {"subdomains": ["vhost.gamma.test"]}}
            web_crawling.run_gau(cfg)
        merged = [(q, p) for s in sink for q, p in s.calls if "MERGE (d)-[:HAS_SUBDOMAIN]->(s)" in q]
        assert any(p.get("domain") == "gamma.test" and p.get("sub") == "vhost.gamma.test"
                   for _q, p in merged)
