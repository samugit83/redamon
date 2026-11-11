"""S-16: a host whose name carries an underscore keeps its coverage notes.

Underscores are legal in DNS names (`_dmarc.example.com`, `dev_api.example.com`)
and urlsplit, host_key and the graph's keep regexes all accept them. The
coverage accumulator did not: `_norm_host` and `_HOST_CHARS` dropped such a
host from every `note_degraded` / `note_checked`, for every module. Its
degraded note then never reached the prune, which deleted the findings the
run could not re-check, and it was missing from the coverage record
(`Domain.recon_skipped_hosts`) and from a positive source's checked set.

These go through the real path: the module-facing notes, the run's coverage
report, main.py's prune calls (Neo4j is a fake) and the regexes the graph
matches a finding's host fields with. Hosts are example.com names.
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
from graph_db.mixins.base_mixin import keep_host_patterns  # noqa: E402

UNDERSCORE = "dev_api.example.com"
DMARC = "_dmarc.example.com"
PLAIN = "www.example.com"


def _kept_by_graph(host_value: str, keep_hosts) -> bool:
    """What the graph's keep clause does: `=~` is a whole-value match."""
    return any(re.fullmatch(rx, host_value.lower()) for rx in keep_host_patterns(keep_hosts))


class TestTheNotesKeepTheHost:
    def test_a_degraded_underscore_host_is_kept_for_every_source(self):
        cb.note_degraded("http_probe", hosts=[cb.host_key(f"https://{UNDERSCORE}/login")],
                         reason="unreachable")
        report = cb.coverage_report()
        assert report.skipped_hosts == (f"{UNDERSCORE}:443",)
        assert report.skipped_hostnames() == (UNDERSCORE,)
        assert report.keep_hostnames("nuclei") == (UNDERSCORE,)
        assert report.stored_skipped_hosts() == [f"{UNDERSCORE}:443"]
        assert report.degraded

    def test_a_host_only_one_source_gave_up_on_is_kept_for_that_source(self):
        cb.note_degraded("js_recon", hosts=[cb.host_key(f"https://{UNDERSCORE}/app.js")],
                         host_source="js_recon", source_only_hosts=True, reason="file cap")
        report = cb.coverage_report()
        assert report.keep_hostnames("js_recon") == (UNDERSCORE,)
        assert report.keep_hostnames("nuclei") == ()

    def test_a_scope_s_skipped_host_reaches_the_report(self):
        scope = cb.scope("x", label="Probe")
        scope.note_host_skipped(cb.host_key(f"https://{DMARC}/"))
        scope.finish("security_checks", host_source="security_check", log=False)
        assert cb.coverage_report().keep_hostnames("security_check") == (DMARC,)

    def test_a_checked_underscore_host_is_pruned_on(self):
        cb.note_checked("nuclei", hosts=[f"{UNDERSCORE}:443", PLAIN], module="vuln_scan")
        assert cb.coverage_report().checked_hostnames("nuclei") == (UNDERSCORE, PLAIN)

    def test_a_coverage_record_s_cut_underscore_host_is_kept(self):
        note_rows_checked("graphql_scan", {
            f"https://{PLAIN}": coverage_row("complete", 1, 1),
            f"https://{UNDERSCORE}": coverage_row("partial", 2, 0, "timeout"),
        }, module="graphql_scan")
        report = cb.coverage_report()
        assert report.checked_hostnames("graphql_scan") == (PLAIN,)
        assert report.keep_hostnames("graphql_scan") == (UNDERSCORE,)

    def test_degraded_still_wins_over_checked(self):
        cb.note_checked("nuclei", hosts=[UNDERSCORE, PLAIN])
        cb.note_degraded("vuln_scan", hosts=[f"{UNDERSCORE}:443"], host_source="nuclei",
                         source_only_hosts=True)
        assert cb.coverage_report().checked_hostnames("nuclei") == (PLAIN,)


class TestStillRejected:
    """A host value is stored on the coverage record and becomes a prune regex:
    anything that is not a host name or address is still dropped."""

    @pytest.mark.parametrize("value", [
        "evil host", "a|b.example.com", "x'); DROP", "a*.example.com", "a\\b.example.com",
        "dev_api.example.com/path", "user@dev_api.example.com", "(dev_api).example.com",
        "dev_api.example.com\nx", "a" * 301,
    ])
    def test_a_value_that_is_no_host_is_dropped(self, value):
        cb.note_degraded("http_probe", hosts=[value])
        cb.note_checked("nuclei", hosts=[value])
        report = cb.coverage_report()
        assert report.skipped_hostnames() == ()
        assert report.checked_hostnames("nuclei") == ()

    def test_a_note_s_source_token_is_unchanged(self):
        cb.note_degraded("js_recon", hosts=[UNDERSCORE], host_source="js_recon",
                         source_only_hosts=True)
        (gap,) = cb.coverage_report().gaps
        assert re.fullmatch(r"[a-z0-9_]{1,64}", gap["source"])


class TestTheGraphMatchesIt:
    def test_the_keep_regex_matches_the_host_however_a_finding_stores_it(self):
        cb.note_degraded("http_probe", hosts=[f"{UNDERSCORE}:8443"])
        hosts = cb.coverage_report().keep_hostnames("nuclei")
        for value in (UNDERSCORE, f"{UNDERSCORE}:8443", f"https://{UNDERSCORE}/x?y=1",
                      f"https://user@{UNDERSCORE}:8443/"):
            assert _kept_by_graph(value, hosts), value

    def test_the_underscore_is_literal_in_the_regex(self):
        hosts = (UNDERSCORE,)
        assert not _kept_by_graph("devXapi.example.com", hosts)
        assert not _kept_by_graph("dev_api.example.com.evil.test", hosts)
        assert not _kept_by_graph("x.dev_api.example.com", hosts)


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

    def __call__(self, *a, **kw):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def verify_connection(self):
        return True

    def backfill_passive_cve_hosts(self, user_id, project_id):
        return 0

    def prune_unseen_findings(self, user_id, project_id, sources, since, **kwargs):
        self.prunes.append({"sources": list(sources), **kwargs})
        return {"pruned": 0, "stale": 0, "revived": 0}


@pytest.fixture
def graph(monkeypatch):
    fake = FakeGraph()
    monkeypatch.setattr("graph_db.Neo4jClient", fake)
    return fake


class TestThePrune:
    def test_the_prune_keeps_the_degraded_underscore_host(self, recon_main, graph):
        cb.note_degraded("js_recon", hosts=[cb.host_key(f"https://{UNDERSCORE}/app.js")],
                         host_source="js_recon", source_only_hosts=True, reason="file cap")
        recon_main._prune_recon_findings()
        js = [p for p in graph.prunes if "js_recon" in p["sources"]]
        assert [p["keep_hosts"] for p in js] == [(UNDERSCORE,)]
        assert _kept_by_graph(f"https://{UNDERSCORE}/static/app.js", js[0]["keep_hosts"])

    def test_a_positive_source_prunes_the_checked_underscore_host_only(self, recon_main, graph):
        cb.note_checked("nuclei", hosts=[f"{UNDERSCORE}:443", f"{DMARC}:443"], module="vuln_scan")
        cb.note_degraded("vuln_scan", hosts=[f"{DMARC}:443"], host_source="nuclei",
                         source_only_hosts=True)
        recon_main._prune_recon_findings()
        (positive,) = [p for p in graph.prunes if "only_hosts" in p]
        assert positive["sources"] == ["nuclei"]
        assert positive["only_hosts"] == (UNDERSCORE,)
        assert positive["keep_hosts"] == (DMARC,)
