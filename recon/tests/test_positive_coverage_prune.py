"""Positive-coverage prune (design decision D1, foundation F-D1).

Today "not reported this run" means "gone": a module that could not check
something must say so with `note_degraded`, and when it forgets, the prune
deletes good findings. D1 turns that around for a source that opts in: it
records the hosts it actually re-checked (`circuit_breaker.note_checked`), and
the prune deletes its stale findings only on those hosts. Degraded always wins
over checked. A source that never calls `note_checked` keeps today's rule
exactly, so this lands inert until a module adopts it.

Neo4j is a fake: these pin what the accumulator reports and what main.py asks
the graph to do. Hosts are example.com names and RFC 5737 / 3849 addresses.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers import circuit_breaker as cb  # noqa: E402
from recon.helpers.coverage_stamps import coverage_row, note_rows_checked  # noqa: E402
from recon.helpers.finding_sources import PASSIVE_CVE_SOURCES, RECON_FINDING_SOURCES  # noqa: E402

A, B, C = "a.example.com", "b.example.com", "c.example.com"


# ---------------------------------------------------------------------------
# The accumulator
# ---------------------------------------------------------------------------

class TestTheRecord:
    def test_a_source_that_records_nothing_keeps_today_s_rule(self):
        cb.note_degraded("vuln_scan", hosts=[f"{A}:443"], host_source="nuclei")
        report = cb.coverage_report()
        assert report.positive_sources == frozenset()
        assert report.checked == ()

    def test_note_checked_makes_the_source_positive(self):
        cb.note_checked("nuclei", hosts=[f"{A}:443", f"{A}:8443", B], module="vuln_scan")
        report = cb.coverage_report()
        assert report.positive_sources == frozenset({"nuclei"})
        assert report.checked_types("nuclei") == ("*",)
        assert report.checked_hostnames("nuclei") == (A, B)
        assert report.checked_hostnames("js_recon") == ()

    def test_a_check_record_is_not_a_coverage_gap(self):
        """The coverage record, the report's Coverage Limitations and the
        prune's keep sets list what was cut; a check cuts nothing."""
        cb.note_checked("nuclei", hosts=[f"{A}:443"])
        report = cb.coverage_report()
        assert not report.degraded
        assert report.gaps == () and report.skipped_hosts == ()
        assert report.degraded_sources == frozenset()
        assert report.keep_hostnames("nuclei") == ()

    def test_no_host_still_makes_the_source_positive_and_prunes_nothing(self):
        cb.note_checked("nuclei")
        report = cb.coverage_report()
        assert report.positive_sources == frozenset({"nuclei"})
        assert report.checked_hostnames("nuclei") == ()

    def test_hosts_are_normalised_and_unsafe_ones_dropped(self):
        cb.note_checked("nuclei", hosts=[f"{A.upper()}:443", "[2001:db8::1]:8443", "198.51.100.7",
                                         "evil host", "x'); DROP", f"https://{C}/x", "", None])
        assert cb.coverage_report().checked_hostnames("nuclei") == (
            "198.51.100.7", "2001:db8::1", A)

    def test_records_of_one_source_add_up(self):
        cb.note_checked("nuclei", hosts=[A])
        cb.note_checked("nuclei", hosts=[B], module="vuln_scan")
        assert cb.coverage_report().checked_hostnames("nuclei") == (A, B)

    def test_a_source_that_is_no_token_records_nothing(self):
        cb.note_checked("", hosts=[A])
        cb.note_checked("!!!", hosts=[A])
        assert cb.coverage_report().positive_sources == frozenset()

    def test_a_fault_fails_the_prune_closed(self):
        class Exploding:
            def __iter__(self):
                raise RuntimeError("boom")
        cb.note_checked("nuclei", hosts=Exploding())
        with pytest.raises(cb.CoverageUnknown):
            cb.coverage_report()

    def test_a_group_reports_only_its_own_checks(self):
        cb.note_checked("nuclei", hosts=[A])
        group = cb.group_scope()
        cb.note_checked("js_recon", hosts=[B])
        assert group.report().positive_sources == frozenset({"js_recon"})
        assert cb.coverage_report().positive_sources == frozenset({"nuclei", "js_recon"})


class TestDegradedAlwaysWins:
    def test_a_degraded_source_has_no_checked_host(self):
        cb.note_checked("nuclei", hosts=[A, B])
        cb.note_degraded("vuln_scan", sources=["nuclei"], reason="NUCLEI_MAX_RUNTIME reached")
        report = cb.coverage_report()
        assert report.checked_hostnames("nuclei") == ()
        assert "nuclei" in report.degraded_sources

    def test_an_alias_cut_with_its_provider_has_none_either(self):
        cb.note_checked("internetdb", hosts=["198.51.100.1"])
        cb.note_degraded("shodan_enrich", sources=["shodan"], aliases=["internetdb"])
        assert cb.coverage_report().checked_hostnames("internetdb") == ()

    def test_a_host_the_source_gave_up_on_is_not_checked(self):
        cb.note_checked("nuclei", hosts=[f"{A}:443", f"{B}:443"])
        cb.note_degraded("vuln_scan", hosts=[f"{A}:8443"], host_source="nuclei",
                         source_only_hosts=True)
        assert cb.coverage_report().checked_hostnames("nuclei") == (B,)

    def test_a_host_every_source_lost_is_not_checked(self):
        cb.note_checked("nuclei", hosts=[A, B])
        cb.note_degraded("security_checks", hosts=[f"{B}:443"], host_source="security_check")
        assert cb.coverage_report().checked_hostnames("nuclei") == (A,)

    def test_another_source_s_own_host_stays_checked(self):
        """js_recon giving up on B says nothing of what Nuclei re-checked there."""
        cb.note_checked("nuclei", hosts=[A, B])
        cb.note_degraded("js_recon", hosts=[f"{B}:443"], host_source="js_recon",
                         source_only_hosts=True)
        assert cb.coverage_report().checked_hostnames("nuclei") == (A, B)


class TestPerCheckCoverage:
    """security_check is one source made of many checks: a check skipped on a
    host keeps its own findings while the other checks there prune."""

    def test_a_check_covers_its_own_type_on_top_of_whole_source_hosts(self):
        cb.note_checked("security_check", hosts=[A], checks=["missing_hsts"])
        cb.note_checked("security_check", hosts=[B])
        report = cb.coverage_report()
        assert report.checked_types("security_check") == ("*", "missing_hsts")
        assert report.checked_hostnames("security_check") == (B,)
        assert report.checked_hostnames("security_check", "missing_hsts") == (A, B)

    def test_a_source_recorded_per_check_only_has_no_whole_source_hosts(self):
        cb.note_checked("security_check", hosts=[A], checks=["spf_missing", "dmarc_missing"])
        report = cb.coverage_report()
        assert report.checked_types("security_check") == ("dmarc_missing", "spf_missing")
        assert report.checked_hostnames("security_check") == ()
        assert report.checked_hostnames("security_check", "spf_missing") == (A,)


# ---------------------------------------------------------------------------
# 09.1's coverage rows feed the same record
# ---------------------------------------------------------------------------

class TestCoverageRows:
    ROWS = {
        f"https://{A}:443": coverage_row("complete", 3, 1),
        f"http://{A}:80": coverage_row("complete", 1, 0),
        f"https://{B}:443": coverage_row("partial", 2, 0, "file cap"),
        f"https://{C}:8443": coverage_row("failed", reason="host unreachable"),
        "https://d.example.com:443": coverage_row("no_input"),
        "https://e.example.com:443": {"status": "bogus"},
        "not a url": coverage_row("complete"),
    }

    def test_complete_is_checked_and_partial_or_failed_is_cut_for_that_source(self):
        note_rows_checked("js_recon", self.ROWS, module="js_recon")
        report = cb.coverage_report()
        assert report.positive_sources == frozenset({"js_recon"})
        assert report.checked_hostnames("js_recon") == (A,)
        assert report.keep_hostnames("js_recon") == (B, C)
        assert report.keep_hostnames("nuclei") == (), "the others re-checked those hosts"
        assert "js_recon" not in report.degraded_sources

    def test_no_input_is_neither_checked_nor_a_gap(self):
        """The row already says the module had nothing there; the host's
        earlier findings are kept, as for any host it did not re-check."""
        note_rows_checked("nuclei", {"https://d.example.com:443": coverage_row("no_input")})
        report = cb.coverage_report()
        assert report.checked_hostnames("nuclei") == ()
        assert report.gaps == ()

    def test_the_cut_hosts_reach_the_coverage_record_as_a_valid_token(self):
        note_rows_checked("js_recon", self.ROWS)
        (gap,) = cb.coverage_report().gaps
        assert re.fullmatch(r"[a-z0-9_]{1,64}", gap["source"])
        assert gap == {"source": "js_recon", "module": "js_recon",
                       "reason": "2 host(s) not fully covered", "skipped": 0, "hosts": 2}

    def test_an_empty_record_checked_nothing(self):
        note_rows_checked("nuclei", {})
        report = cb.coverage_report()
        assert report.positive_sources == frozenset({"nuclei"})
        assert report.checked_hostnames("nuclei") == ()

    def test_a_record_that_is_not_one_fails_the_prune_closed(self):
        note_rows_checked("nuclei", ["https://a.example.com:443"])
        with pytest.raises(cb.CoverageUnknown):
            cb.coverage_report()


# ---------------------------------------------------------------------------
# What main.py asks the graph to prune
# ---------------------------------------------------------------------------

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


class FakeGraph:
    def __init__(self):
        self.prunes = []
        self.backfill_fails = False

    def __call__(self, *a, **kw):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def verify_connection(self):
        return True

    def backfill_passive_cve_hosts(self, user_id, project_id):
        if self.backfill_fails:
            raise RuntimeError("backfill failed")
        return 0

    def prune_unseen_findings(self, user_id, project_id, sources, since, **kwargs):
        self.prunes.append({"sources": list(sources), "since": since, **kwargs})
        return {"pruned": 0, "stale": 0, "revived": 0}

    def positive(self):
        return [p for p in self.prunes if "only_hosts" in p]

    def legacy(self):
        return [p for p in self.prunes if "only_hosts" not in p]


@pytest.fixture
def graph(monkeypatch):
    fake = FakeGraph()
    monkeypatch.setattr("graph_db.Neo4jClient", fake)
    return fake


class TestThePrune:
    def test_a_run_with_no_positive_source_prunes_exactly_as_before(self, recon_main, graph):
        cb.note_degraded("security_checks", hosts=[f"{A}:443"], host_source="security_check")
        recon_main._prune_recon_findings()
        assert graph.prunes == [{"sources": list(RECON_FINDING_SOURCES),
                                 "since": "2026-01-01T00:00:00+00:00", "keep_hosts": (A,)}]

    def test_a_positive_source_prunes_only_the_hosts_it_re_checked(self, recon_main, graph, capsys):
        cb.note_checked("nuclei", hosts=[f"{A}:443", f"{B}:443"], module="vuln_scan")
        cb.note_degraded("nmap", hosts=[f"{B}:22"], host_source="nmap_nse")
        recon_main._prune_recon_findings()
        (legacy,) = graph.legacy()
        assert "nuclei" not in legacy["sources"]
        assert set(legacy["sources"]) == set(RECON_FINDING_SOURCES) - {"nuclei"}
        assert legacy["keep_hosts"] == (B,)
        assert graph.positive() == [{
            "sources": ["nuclei"], "since": "2026-01-01T00:00:00+00:00",
            "keep_hosts": (B,), "only_hosts": (A,), "types": None,
        }]
        assert "1 source(s) prune only the hosts they re-checked (nuclei)" in capsys.readouterr().out

    def test_a_degraded_positive_source_is_not_pruned_at_all(self, recon_main, graph):
        cb.note_checked("nuclei", hosts=[A])
        cb.note_degraded("vuln_scan", sources=["nuclei"], nuclei_truncated=True)
        recon_main._prune_recon_findings()
        assert all("nuclei" not in p["sources"] for p in graph.prunes)

    def test_each_check_type_is_pruned_on_its_own_hosts(self, recon_main, graph):
        cb.note_checked("security_check", hosts=[A], checks=["missing_hsts"])
        cb.note_checked("security_check", hosts=[B])
        recon_main._prune_recon_findings()
        calls = {p["types"]: p for p in graph.positive()}
        assert calls[None]["only_hosts"] == (B,)
        assert calls[("missing_hsts",)]["only_hosts"] == (A, B)
        assert all(p["sources"] == ["security_check"] for p in calls.values())

    def test_sources_with_the_same_record_share_one_call(self, recon_main, graph):
        for source in PASSIVE_CVE_SOURCES["shodan"]:
            cb.note_checked(source, hosts=["198.51.100.1"])
        recon_main._prune_recon_findings()
        (call,) = graph.positive()
        assert sorted(call["sources"]) == sorted(PASSIVE_CVE_SOURCES["shodan"])

    def test_nothing_checked_is_asked_with_no_host(self, recon_main, graph):
        """The graph prunes nothing for it (and still lifts `stale_since` from
        what it reported again)."""
        cb.note_checked("nuclei")
        recon_main._prune_recon_findings()
        (call,) = graph.positive()
        assert call["only_hosts"] == () and call["sources"] == ["nuclei"]

    def test_a_failed_passive_backfill_drops_positive_passive_sources_too(self, recon_main, graph):
        graph.backfill_fails = True
        cb.note_checked("netlas", hosts=["198.51.100.1"])
        cb.note_checked("nuclei", hosts=[A])
        recon_main._prune_recon_findings()
        passive = {s for group in PASSIVE_CVE_SOURCES.values() for s in group}
        assert not any(set(p["sources"]) & passive for p in graph.prunes)
        assert [p["sources"] for p in graph.positive()] == [["nuclei"]]

    def test_unknown_coverage_still_prunes_nothing(self, recon_main, graph, monkeypatch):
        cb.note_checked("nuclei", hosts=[A])
        monkeypatch.setattr(cb, "_accumulator_broken", True)
        recon_main._prune_recon_findings()
        assert graph.prunes == []
