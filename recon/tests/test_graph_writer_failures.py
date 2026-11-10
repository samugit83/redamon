"""A failed background graph write degrades the writer's finding sources (R-20, D1).

The background writer (`_graph_update_bg` in recon/main.py) catches every
exception so a Neo4j blip never fails the scan. Its findings then keep last
run's `updated_at`, and the end-of-run prune used to read them as gone. Now a
writer that raises, reports an item error, or finds the graph unreachable
notes its sources degraded, so the prune keeps them for this run, whatever the
modules recorded as checked. Housekeeping errors, a writer with nothing to
write, and writers of assets only change nothing.

Neo4j is a fake: these pin what main.py asks the graph to do.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers import circuit_breaker as cb  # noqa: E402
from recon.helpers.finding_sources import PASSIVE_CVE_SOURCES, RECON_FINDING_SOURCES  # noqa: E402

VULN_SOURCES = {"nuclei", "security_check", "vuln_scan"}
TOKEN = re.compile(r"^[a-z0-9_]{1,64}$")


@pytest.fixture
def recon_main():
    stub = {
        'TARGET_DOMAIN': 'example.com', 'SUBDOMAIN_LIST': [], 'IP_MODE': False, 'TARGET_IPS': [],
        'DOMAIN_BATCH_MODE': False, 'DOMAIN_BATCH_GROUPS': [],
        'USE_BRUTEFORCE_FOR_SUBDOMAINS': False, 'SCAN_MODULES': ['domain_discovery'],
        'UPDATE_GRAPH_DB': True, 'USER_ID': 'u1', 'PROJECT_ID': 'p1',
        'VERIFY_DOMAIN_OWNERSHIP': False, 'STEALTH_MODE': False,
        'OWNERSHIP_TOKEN': '', 'OWNERSHIP_TXT_PREFIX': '',
    }
    with mock.patch('recon.project_settings.get_settings', return_value=dict(stub)):
        for mod in [m for m in list(sys.modules) if m in ('recon.main', 'main')]:
            del sys.modules[mod]
        import recon.main as rm
        rm._RUN_STARTED_AT = "2026-01-01T00:00:00+00:00"
        rm._COVERAGE_WRITE_FAILED = False
        yield rm
        if rm._graph_executor is not None:
            rm._graph_wait_all()


class FakeGraph:
    """Neo4jClient stand-in. `writers` maps a writer name to what it does: an
    exception to raise, or the stats dict to return (default: a clean run)."""

    def __init__(self):
        self.reachable = True
        self.writers = {}
        self.written = []
        self.prunes = []
        self.coverage = []

    def __call__(self, *a, **kw):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def verify_connection(self):
        return self.reachable

    def backfill_passive_cve_hosts(self, user_id, project_id):
        return 0

    def backfill_security_check_domains(self, user_id, project_id):
        return 0

    def prune_unseen_findings(self, user_id, project_id, sources, since, keep_hosts=(),
                              only_hosts=None, types=None, exclude_types=None):
        self.prunes.append({"sources": list(sources), "only_hosts": only_hosts,
                            "types": types, "exclude_types": exclude_types})
        return {"pruned": 0, "stale": 0, "revived": 0}

    def update_graph_coverage(self, user_id, project_id, domain, record, run_started_at=None):
        self.coverage.append({"domain": domain, **record})
        return 1

    def __getattr__(self, name):
        if not name.startswith("update_graph_"):
            raise AttributeError(name)

        def write(data, user_id, project_id):
            self.written.append(name)
            outcome = self.writers.get(name)
            if isinstance(outcome, BaseException):
                raise outcome
            return outcome if outcome is not None else {"errors": []}
        return write


@pytest.fixture
def graph(monkeypatch):
    fake = FakeGraph()
    monkeypatch.setattr("graph_db.Neo4jClient", fake)
    return fake


def _write(rm, method, data=None):
    """Queue one background write the way the pipeline does, and land it."""
    rm._graph_reset()
    rm._graph_update_bg(method, data if data is not None else {"x": 1}, "u1", "p1")
    return rm._graph_wait_all()


def _pruned(graph) -> set:
    return {s for p in graph.prunes for s in p["sources"]}


class TestAFailedWriteKeepsItsFindings:
    def test_a_writer_that_raises_keeps_its_sources_out_of_the_prune(self, recon_main, graph):
        graph.writers["update_graph_from_vuln_scan"] = RuntimeError("deadlock detected")
        _write(recon_main, "update_graph_from_vuln_scan")
        recon_main._prune_recon_findings()
        assert graph.written == ["update_graph_from_vuln_scan"]
        assert not VULN_SOURCES & _pruned(graph)
        # Only that writer's sources: every other one still prunes.
        assert _pruned(graph) == set(RECON_FINDING_SOURCES) - VULN_SOURCES

    def test_a_writer_reporting_a_finding_error_keeps_its_sources(self, recon_main, graph):
        graph.writers["update_graph_from_vuln_scan"] = {
            "vulnerabilities_created": 3,
            "errors": ["Finding http-missing-security-headers processing failed: ConstraintError"],
        }
        _write(recon_main, "update_graph_from_vuln_scan")
        recon_main._prune_recon_findings()
        assert not VULN_SOURCES & _pruned(graph)

    def test_an_archive_leak_item_error_keeps_the_resource_sources(self, recon_main, graph):
        # The resource writer passes its archive-leak sub-writer's errors on.
        graph.writers["update_graph_from_resource_enum"] = {"errors": [
            "Archive leaks: urlscan finding leaked_link: ConstraintError"]}
        _write(recon_main, "update_graph_from_resource_enum")
        recon_main._prune_recon_findings()
        assert not {"resource_enum", "jsluice", "url_archive"} & _pruned(graph)

    def test_an_unreachable_graph_keeps_the_writers_sources(self, recon_main, graph):
        graph.reachable = False
        _write(recon_main, "update_graph_from_js_recon")
        graph.reachable = True
        recon_main._prune_recon_findings()
        assert graph.written == []
        assert "js_recon" not in _pruned(graph)
        assert "nuclei" in _pruned(graph)

    def test_a_graph_client_that_cannot_open_keeps_the_writers_sources(self, recon_main, graph,
                                                                        monkeypatch):
        def refuse(*a, **kw):
            raise OSError("connection refused")
        monkeypatch.setattr("graph_db.Neo4jClient", refuse)
        _write(recon_main, "update_graph_from_resource_enum")
        monkeypatch.setattr("graph_db.Neo4jClient", graph)
        recon_main._prune_recon_findings()
        assert not {"resource_enum", "jsluice", "url_archive"} & _pruned(graph)

    def test_a_write_dropped_after_the_writer_closed_keeps_its_sources(self, recon_main, graph):
        # A submit after _graph_wait_all tore the executor down never lands.
        assert recon_main._graph_executor is None
        recon_main._graph_update_bg("update_graph_from_graphql_scan", {"x": 1}, "u1", "p1")
        recon_main._prune_recon_findings()
        assert graph.written == []
        assert not {"graphql_scan", "graphql_cop"} & _pruned(graph)

    def test_a_failed_shodan_write_keeps_every_shodan_source_value(self, recon_main, graph):
        graph.writers["update_graph_from_shodan"] = RuntimeError("TransientError")
        _write(recon_main, "update_graph_from_shodan")
        recon_main._prune_recon_findings()
        assert not set(PASSIVE_CVE_SOURCES["shodan"]) & _pruned(graph)
        assert "netlas" in _pruned(graph)
        # One gap for the provider, as its own lookup failure records it.
        shodan_gaps = [g for g in cb.coverage_report().gaps if "shodan" in g["source"]]
        assert [g["source"] for g in shodan_gaps] == ["shodan"]

    @pytest.mark.parametrize("method,sources", [
        ("update_graph_from_graphql_scan", {"graphql_scan", "graphql_cop"}),
        ("update_graph_from_subdomain_takeover", {"takeover_scan"}),
        ("update_graph_from_vhost_sni", {"vhost_sni_enum"}),
        ("update_graph_from_cache_scan", {"cache_poisoning", "wcvs"}),
        ("update_graph_from_origin_discovery", {"origin_discovery"}),
        ("update_graph_from_route_exposure", {"route_exposure"}),
        ("update_graph_from_nmap", {"nmap_nse"}),
        ("update_graph_from_ai_surface_recon", {"ai_surface_recon"}),
        ("update_graph_from_serialized_scan", {"serialized_scan"}),
        ("update_graph_from_urlscan_findings", {"urlscan_leak", "urlscan"}),
        ("update_graph_from_urlscan_takeover", {"urlscan_leak", "urlscan"}),
        ("update_graph_from_netlas", {"netlas"}),
        ("update_graph_from_criminalip", {"criminalip"}),
    ])
    def test_each_finding_writer_keeps_its_own_sources(self, recon_main, graph, method, sources):
        graph.writers[method] = RuntimeError("boom")
        _write(recon_main, method)
        recon_main._prune_recon_findings()
        pruned = _pruned(graph)
        assert not sources & pruned
        assert pruned == set(RECON_FINDING_SOURCES) - recon_main._writer_sources(method)

    def test_degraded_wins_over_what_the_module_recorded_as_checked(self, recon_main, graph):
        cb.note_checked("nuclei", hosts=["a.example.com"], module="vuln_scan")
        graph.writers["update_graph_from_vuln_scan"] = RuntimeError("deadlock detected")
        _write(recon_main, "update_graph_from_vuln_scan")
        recon_main._prune_recon_findings()
        # Neither the source-level prune nor a per-host one touches nuclei.
        assert all("nuclei" not in p["sources"] for p in graph.prunes)


class TestWhatDegradesNothing:
    def test_a_clean_write_changes_nothing(self, recon_main, graph):
        _write(recon_main, "update_graph_from_vuln_scan")
        recon_main._prune_recon_findings()
        assert _pruned(graph) == set(RECON_FINDING_SOURCES)
        assert cb.coverage_report().gaps == ()

    def test_housekeeping_errors_degrade_nothing(self, recon_main, graph):
        graph.writers["update_graph_from_vuln_scan"] = {"errors": [
            "Orphan BaseURL cleanup failed: x", "Apex BaseURL cleanup failed: x",
            "Domain update failed: x", "Nuclei coverage stamp failed: x"]}
        graph.writers["update_graph_from_resource_enum"] = {"errors": [
            "OpenAPI source status update failed: x"]}
        graph.writers["update_graph_from_js_recon"] = {"errors": [
            "JS Recon coverage stamp failed: x"]}
        recon_main._graph_reset()
        for method in graph.writers:
            recon_main._graph_update_bg(method, {"x": 1}, "u1", "p1")
        recon_main._graph_wait_all()
        recon_main._prune_recon_findings()
        assert _pruned(graph) == set(RECON_FINDING_SOURCES)

    @pytest.mark.parametrize("method,error", [
        ("update_graph_from_vuln_scan", "No vuln_scan data found in recon_data"),
        ("update_graph_from_netlas", "No netlas results in recon_data"),
        ("update_graph_from_criminalip", "No criminalip data in recon_data"),
        ("update_graph_from_ai_surface_recon", "No ai_surface_recon data found"),
    ])
    def test_a_writer_with_nothing_to_write_degrades_nothing(self, recon_main, graph,
                                                             method, error):
        graph.writers[method] = {"errors": [error]}
        _write(recon_main, method)
        recon_main._prune_recon_findings()
        assert _pruned(graph) == set(RECON_FINDING_SOURCES)

    @pytest.mark.parametrize("method", [
        "update_graph_from_domain_discovery", "update_graph_from_port_scan",
        "update_graph_from_http_probe", "update_graph_from_tlsx",
    ])
    def test_an_asset_writer_failure_degrades_no_finding_source(self, recon_main, graph, method):
        graph.writers[method] = RuntimeError("boom")
        _write(recon_main, method)
        recon_main._prune_recon_findings()
        assert _pruned(graph) == set(RECON_FINDING_SOURCES)


class TestTheFailureIsReported:
    def test_the_pipeline_never_fails_on_a_graph_error(self, recon_main, graph):
        graph.writers["update_graph_from_js_recon"] = RuntimeError("boom")
        results = _write(recon_main, "update_graph_from_js_recon")
        (method, stats, failure), = results
        assert method == "update_graph_from_js_recon"
        assert stats is None
        assert "RuntimeError" in failure

    def test_wait_all_returns_each_writers_stats(self, recon_main, graph):
        graph.writers["update_graph_from_nmap"] = {"nse_vulns_created": 2, "errors": []}
        (method, stats, failure), = _write(recon_main, "update_graph_from_nmap")
        assert (method, stats, failure) == (
            "update_graph_from_nmap", {"nse_vulns_created": 2, "errors": []}, "")

    def test_the_gap_uses_valid_source_tokens(self, recon_main, graph):
        # The Recon Delta drops a run's whole gap list over one malformed source.
        for method in ("update_graph_from_vuln_scan", "update_graph_from_shodan",
                       "update_graph_from_cache_scan"):
            graph.writers[method] = RuntimeError("boom")
        recon_main._graph_reset()
        for method in list(graph.writers):
            recon_main._graph_update_bg(method, {"x": 1}, "u1", "p1")
        recon_main._graph_wait_all()
        gaps = cb.coverage_report().gaps
        assert gaps
        for gap in gaps:
            assert TOKEN.match(gap["source"]), gap
            assert "graph write failed" in gap["reason"]

    def test_the_groups_coverage_record_names_the_failed_write(self, recon_main, graph):
        group = cb.group_scope()
        graph.writers["update_graph_from_vuln_scan"] = RuntimeError("boom")
        _write(recon_main, "update_graph_from_vuln_scan")
        assert recon_main._write_coverage_record("example.com", group) is True
        (record,) = graph.coverage
        sources = {g["source"] for g in json.loads(record["gaps_json"])}
        assert VULN_SOURCES <= sources


class TestTheWriterTable:
    # Writers main.py queues that write no recon finding source: their
    # failure costs assets only (or, for supply chain, findings the recon
    # prune never touches), so it degrades nothing.
    ASSET_ONLY = {
        "update_graph_wildcard_zones", "update_graph_from_domain_discovery",
        "update_graph_from_ip_recon", "update_graph_from_port_scan",
        "update_graph_from_http_probe", "update_graph_from_tlsx",
        "update_graph_from_ip_attribution", "update_graph_from_uncover",
        "update_graph_from_external_domains", "update_graph_from_urlscan_discovery",
        "update_graph_from_urlscan_enrichment", "update_graph_from_censys",
        "update_graph_from_fofa", "update_graph_from_otx", "update_graph_from_virustotal",
        "update_graph_from_zoomeye", "update_graph_from_supply_chain_recon",
    }

    def _queued_writers(self) -> set:
        source = (PROJECT_ROOT / "recon" / "main.py").read_text()
        names = set(re.findall(r"""["'](update_graph_\w+)["']""", source))
        # GROUP 6 Phase A queues f"update_graph_from_{key}" for each tool key.
        names |= {f"update_graph_from_{k}" for k in re.findall(r"phase_a_tools\['(\w+)'\]", source)}
        return names

    def test_every_queued_writer_is_classified(self, recon_main):
        queued = self._queued_writers()
        assert "update_graph_from_route_exposure" in queued
        unclassified = queued - set(recon_main._WRITER_SOURCES) - self.ASSET_ONLY
        assert not unclassified, f"add these to _WRITER_SOURCES or ASSET_ONLY: {unclassified}"

    def test_every_writer_names_a_phase_and_a_real_graph_method(self, recon_main):
        mixins = "\n".join(p.read_text() for p in (PROJECT_ROOT / "graph_db").rglob("*.py"))
        for method, phase in recon_main._WRITER_SOURCES.items():
            assert phase in recon_main._PHASE_FINDING_SOURCES, method
            assert re.search(rf"def {method}\(", mixins), method
            assert recon_main._writer_sources(method) <= set(RECON_FINDING_SOURCES)

    def test_an_unknown_writer_has_no_sources(self, recon_main):
        assert recon_main._writer_sources("update_graph_from_port_scan") == set()
