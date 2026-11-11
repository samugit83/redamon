"""The legacy no-discovery path keeps what it did not re-check, and rebuilds what it cleared (plan 12.13).

With domain_discovery off, _run_pipeline clears the recon graph and
run_domain_group's legacy branch reloads the previous result file. Nothing
on that path wrote Domain or Subdomain nodes again; in a batch the prune
still ran, and deleted the findings of every recon source the path never
runs (Shodan, Netlas, takeover, vhost, GraphQL, cache poisoning, ...); it
never reset the graph writer, so the AI Surface and cert-hygiene writes were
dropped; and its RoE filter cleaned dns.subdomains only.

Every scanner and Neo4j is a fake.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers import circuit_breaker as cb  # noqa: E402
from recon.helpers.finding_sources import RECON_FINDING_SOURCES  # noqa: E402

NOT_RUN = {"shodan_api", "internetdb", "shodan", "shodan_host_lookup", "netlas", "criminalip",
           "nmap_nse", "graphql_scan", "graphql_cop", "takeover_scan", "vhost_sni_enum",
           "cache_poisoning", "wcvs", "origin_discovery", "serialized_scan", "route_exposure"}

SAVED = {
    "domain": "example.com",
    "metadata": {"root_domain": "example.com", "modules_executed": ["domain_discovery"]},
    "whois": {},
    "subdomains": ["www.example.com", "excluded.example.com"],
    "subdomain_status_map": {"www.example.com": "resolved", "excluded.example.com": "resolved"},
    "dns": {"domain": {"ips": {"ipv4": ["192.0.2.10"]}},
            "subdomains": {"www.example.com": {"ips": {"ipv4": ["192.0.2.11"]}},
                           "excluded.example.com": {"ips": {"ipv4": ["192.0.2.12"]}}}},
    # http_probe ran and found nothing: the active scans are skipped, so the
    # legacy path only runs what needs no live target (the org DNS checks are
    # faked below; there is no port scan for the port checks).
    "http_probe": {"by_url": {}, "summary": {"live_urls": 0, "total_hosts": 0}},
}


class _Graph:
    def __init__(self):
        self.calls = []

    def __call__(self, *a, **k):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def verify_connection(self):
        return True

    def __getattr__(self, name):
        if not name.startswith("update_graph"):
            raise AttributeError(name)

        def record(*args, **kwargs):
            self.calls.append((name, args[0] if args else None))
            return True
        return record


@pytest.fixture
def legacy(tmp_path, monkeypatch):
    stub = {
        'TARGET_DOMAIN': 'example.com', 'SUBDOMAIN_LIST': [], 'IP_MODE': False,
        'TARGET_IPS': [], 'DOMAIN_BATCH_MODE': False, 'DOMAIN_BATCH_GROUPS': [],
        'USE_BRUTEFORCE_FOR_SUBDOMAINS': False, 'SCAN_MODULES': ['vuln_scan'],
        'UPDATE_GRAPH_DB': True, 'USER_ID': 'u1', 'PROJECT_ID': 'p1',
        'VERIFY_DOMAIN_OWNERSHIP': False, 'STEALTH_MODE': False,
        'OWNERSHIP_TOKEN': '', 'OWNERSHIP_TXT_PREFIX': '',
        'ROE_ENABLED': True, 'ROE_EXCLUDED_HOSTS': ['excluded.example.com'],
        'AI_SURFACE_RECON_ENABLED': True, 'JS_RECON_ENABLED': False,
        'SECURITY_CHECK_ENABLED': True,
    }
    with mock.patch('recon.project_settings.get_settings', return_value=dict(stub)):
        for mod in [m for m in list(sys.modules) if m in ('recon.main', 'main')]:
            del sys.modules[mod]
        import recon.main as rm
    monkeypatch.setattr(rm, "OUTPUT_DIR", tmp_path)
    (tmp_path / "recon_p1.json").write_text(json.dumps(SAVED))
    graph = _Graph()
    monkeypatch.setattr("graph_db.Neo4jClient", graph)
    monkeypatch.setattr(rm, "_RUN_STARTED_AT", "2026-01-01T00:00:00+00:00")

    def ai_surface(result, output_file=None, settings=None):
        result["ai_surface_recon"] = {"findings": []}
        return result

    def cert_hygiene(result, enabled):
        return {"security_checks": {"findings": [{"check": "tls_expired", "host": "www.example.com"}]}}

    dns_checked = []

    def org_dns(result, enabled, **_kw):
        dns_checked.append(result.get("domain"))
        return []

    monkeypatch.setattr(rm, "run_ai_surface_recon", ai_surface)
    monkeypatch.setattr("recon.helpers.run_cert_hygiene_checks_only", cert_hygiene, raising=False)
    monkeypatch.setattr("recon.helpers.security_checks.run_dns_checks_only", org_dns)
    monkeypatch.setattr(rm, "_test_dns_checked", dns_checked, raising=False)
    group = rm.settings_scope_groups(rm._settings)[0]
    yield rm, graph, group
    rm._graph_wait_all()


def _written(graph, method):
    return [data for name, data in graph.calls if name == method]


class TestTheLegacyBranch:
    def test_the_sources_it_never_runs_are_kept_by_the_prune(self, legacy):
        rm, graph, group = legacy
        assert rm.run_domain_group(group) == 0
        degraded = cb.coverage_report().degraded_sources
        assert NOT_RUN <= degraded
        prunes = []
        graph.prune_unseen_findings = lambda u, p, sources, since, keep_hosts=(): prunes.append(set(sources))
        graph.backfill_passive_cve_hosts = lambda *a: None
        assert rm._COVERAGE_WRITE_FAILED is False
        rm._prune_recon_findings()
        assert prunes, "the prune did not run"
        assert not (NOT_RUN & set().union(*prunes))

    def test_the_ai_surface_and_cert_hygiene_writes_land(self, legacy):
        rm, graph, group = legacy
        rm.run_domain_group(group)
        rm._graph_wait_all()
        assert _written(graph, "update_graph_from_ai_surface_recon")
        assert _written(graph, "update_graph_from_vuln_scan")

    def test_it_rebuilds_the_domain_and_its_subdomains(self, legacy):
        rm, graph, group = legacy
        rm.run_domain_group(group)
        [data] = _written(graph, "update_graph_from_domain_discovery")
        assert data["domain"] == "example.com"
        assert "www.example.com" in data["subdomains"]
        assert _written(graph, "update_graph_coverage")
        assert rm._COVERAGE_WRITE_FAILED is False

    def test_an_roe_excluded_host_gets_no_subdomain_node(self, legacy):
        rm, graph, group = legacy
        rm.run_domain_group(group)
        [data] = _written(graph, "update_graph_from_domain_discovery")
        assert "excluded.example.com" not in data["subdomains"]
        assert "excluded.example.com" not in data["subdomain_status_map"]
        assert "excluded.example.com" not in data["dns"]["subdomains"]

    def test_the_skip_branch_runs_the_org_dns_checks(self, legacy):
        rm, _graph, group = legacy
        rm.run_domain_group(group)
        assert rm._test_dns_checked == ["example.com"]

    def test_the_rebuild_comes_before_the_coverage_record(self, legacy):
        rm, graph, group = legacy
        rm.run_domain_group(group)
        names = [name for name, _ in graph.calls]
        assert names.index("update_graph_from_domain_discovery") < names.index("update_graph_coverage")
