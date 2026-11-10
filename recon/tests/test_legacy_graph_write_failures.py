"""The legacy no-discovery path's own graph writes report their failures too (R-20).

With domain_discovery off, run_domain_group's legacy branch writes resource
enumeration, JS Recon and vuln_scan to the graph synchronously, each in its
own try/except. A write that raised, found Neo4j unreachable or reported an
item error on a finding was only printed, so the prune deleted the findings it
had not refreshed. Each now notes its sources degraded, as the background
writer does.

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

SAVED = {
    "domain": "example.com",
    "metadata": {"root_domain": "example.com", "modules_executed": ["domain_discovery"]},
    "whois": {},
    "subdomains": ["www.example.com"],
    "subdomain_status_map": {"www.example.com": "resolved"},
    "dns": {"domain": {"ips": {"ipv4": ["192.0.2.10"]}},
            "subdomains": {"www.example.com": {"ips": {"ipv4": ["192.0.2.11"]}}}},
    # A live URL: the legacy path runs its active scans (all fakes here).
    "http_probe": {"by_url": {"https://www.example.com": {"status_code": 200}},
                   "summary": {"live_urls": 1, "total_hosts": 1}},
}

WRITES = {
    "update_graph_from_resource_enum": {"resource_enum", "jsluice", "url_archive"},
    "update_graph_from_js_recon": {"js_recon"},
    "update_graph_from_vuln_scan": {"nuclei", "security_check", "vuln_scan"},
}


class _Graph:
    """`outcomes` maps a writer to an exception to raise or the stats to return."""

    def __init__(self):
        self.reachable = True
        self.outcomes = {}
        self.calls = []

    def __call__(self, *a, **k):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def verify_connection(self):
        return self.reachable

    def __getattr__(self, name):
        if not name.startswith("update_graph"):
            raise AttributeError(name)

        def write(*args, **kwargs):
            self.calls.append(name)
            outcome = self.outcomes.get(name)
            if isinstance(outcome, BaseException):
                raise outcome
            return outcome if outcome is not None else {"errors": []}
        return write


@pytest.fixture
def legacy(tmp_path, monkeypatch):
    stub = {
        'TARGET_DOMAIN': 'example.com', 'SUBDOMAIN_LIST': [], 'IP_MODE': False,
        'TARGET_IPS': [], 'DOMAIN_BATCH_MODE': False, 'DOMAIN_BATCH_GROUPS': [],
        'USE_BRUTEFORCE_FOR_SUBDOMAINS': False,
        'SCAN_MODULES': ['resource_enum', 'vuln_scan'],
        'UPDATE_GRAPH_DB': True, 'USER_ID': 'u1', 'PROJECT_ID': 'p1',
        'VERIFY_DOMAIN_OWNERSHIP': False, 'STEALTH_MODE': False,
        'OWNERSHIP_TOKEN': '', 'OWNERSHIP_TXT_PREFIX': '',
        'AI_SURFACE_RECON_ENABLED': False, 'JS_RECON_ENABLED': True, 'MITRE_ENABLED': False,
    }
    with mock.patch('recon.project_settings.get_settings', return_value=dict(stub)):
        for mod in [m for m in list(sys.modules) if m in ('recon.main', 'main')]:
            del sys.modules[mod]
        import recon.main as rm
    monkeypatch.setattr(rm, "OUTPUT_DIR", tmp_path)
    (tmp_path / "recon_p1.json").write_text(json.dumps(SAVED))
    graph = _Graph()
    monkeypatch.setattr("graph_db.Neo4jClient", graph)

    def scanner(key):
        def run(result, output_file=None, settings=None):
            result[key] = {"findings": []}
            return result
        return run

    monkeypatch.setattr(rm, "run_resource_enum", scanner("resource_enum"))
    monkeypatch.setattr(rm, "run_vuln_scan", scanner("vuln_scan"))
    monkeypatch.setattr("recon.main_recon_modules.js_recon.run_js_recon", scanner("js_recon"))
    group = rm.settings_scope_groups(rm._settings)[0]
    yield rm, graph, group
    rm._graph_wait_all()


def _degraded():
    return cb.coverage_report().degraded_sources


class TestTheLegacyWritesReportTheirFailures:
    @pytest.mark.parametrize("method", sorted(WRITES))
    def test_a_write_that_raises_keeps_its_sources(self, legacy, method):
        rm, graph, group = legacy
        graph.outcomes[method] = RuntimeError("deadlock detected")
        assert rm.run_domain_group(group) == 0
        assert method in graph.calls
        assert WRITES[method] <= _degraded()
        others = set().union(*(s for m, s in WRITES.items() if m != method))
        assert not others & _degraded()

    @pytest.mark.parametrize("method", sorted(WRITES))
    def test_a_write_reporting_an_item_error_keeps_its_sources(self, legacy, method):
        rm, graph, group = legacy
        graph.outcomes[method] = {"errors": ["Secret node creation failed: ConstraintError"]}
        assert rm.run_domain_group(group) == 0
        assert WRITES[method] <= _degraded()

    def test_an_unreachable_graph_keeps_every_legacy_writers_sources(self, legacy):
        rm, graph, group = legacy
        graph.reachable = False
        assert rm.run_domain_group(group) == 0
        assert set().union(*WRITES.values()) <= _degraded()

    def test_clean_writes_and_housekeeping_errors_degrade_nothing(self, legacy):
        rm, graph, group = legacy
        graph.outcomes["update_graph_from_vuln_scan"] = {"errors": ["Orphan BaseURL cleanup failed: x"]}
        assert rm.run_domain_group(group) == 0
        assert set(graph.calls) >= set(WRITES)
        # Only what the legacy path never runs is degraded (plan 12.13).
        assert not set().union(*WRITES.values()) & _degraded()

    def test_the_gap_says_the_graph_write_failed(self, legacy):
        rm, graph, group = legacy
        graph.outcomes["update_graph_from_js_recon"] = RuntimeError("boom")
        rm.run_domain_group(group)
        (gap,) = [g for g in cb.coverage_report().gaps if g["source"] == "js_recon"]
        assert gap["reason"] == "graph write failed (update_graph_from_js_recon)"
