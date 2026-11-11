"""Regression (R-23): the cache scan's cap and failures read as "no cache finding",
and the prune deleted the earlier cache_poisoning findings.

Four paths returned the same empty result as a clean test, with no
circuit_breaker call: a URL beyond the 200-URL target cap was never tested, a
URL whose confirmation raised became an empty entry (`_failed_url`), a URL
that never answered the cache oracle read as "not cached", and WCVS timing out,
writing no report or failing returned `[]` (a timeout parsed its partial
report as if it were complete). Each now keeps the cache findings of the hosts
it did not test, by host and for cache_poisoning (and its `wcvs` alias)
alone. A URL that answered, a run under the cap and a scan switched off note
nothing and prune as before.

Docker, the network and Neo4j are fakes; the scanner and the WCVS runner run
for real.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest
import requests

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.cache_scan import scanner, wcvs_runner  # noqa: E402
from recon.helpers import circuit_breaker as cb  # noqa: E402

A, B = "a.example.com", "b.example.com"
TOKEN = re.compile(r"^[a-z0-9_]{1,64}$")
SETTINGS = {"WEB_CACHE_POISON_ENABLED": True, "WEB_CACHE_POISON_CONFIRM_WORKERS": 1,
            "WEB_CACHE_POISON_BEHAVIORAL_ORACLE": False, "WEB_CACHE_POISON_TIMEOUT": 1800}


def _recon(probed):
    return {
        "domain": "example.com",
        "dns": {"domain": {}, "subdomains": {}},
        "http_probe": {"by_url": {u: {"url": u, "status_code": 200} for u in probed}},
        "resource_enum": {"by_base_url": {}, "discovered_urls": []},
        "metadata": {"include_root_domain": False},
    }


def _assert_kept_by_host(hosts):
    report = cb.coverage_report()
    assert report.keep_hostnames("cache_poisoning") == tuple(sorted(hosts))
    assert report.keep_hostnames("wcvs") == tuple(sorted(hosts))
    # By host, for the cache scan alone: the other modules reached these hosts.
    assert report.keep_hostnames("nuclei") == ()
    assert not {"cache_poisoning", "wcvs"} & report.degraded_sources
    assert report.gaps and all(TOKEN.match(g["source"]) and TOKEN.match(g["module"])
                               for g in report.gaps)


def _cache_gap():
    gap, = [g for g in cb.coverage_report().gaps if g["source"] == "cache_poisoning"]
    assert gap["module"] == "cache_scan"
    return gap


def _clean(url, *_args):
    return url, {"oracle": {"cacheable": False, "indicator": "", "signals": [],
                            "saw_hit": False}, "findings": []}, 0


# ---------------------------------------------------------------------------
# The target cap
# ---------------------------------------------------------------------------

class TestCap:
    def test_regression_hosts_beyond_the_cap_lost_their_findings(self):
        probed = [f"https://h{i:03d}.example.com" for i in range(scanner._MAX_URLS + 5)]
        urls = scanner._collect_target_urls(_recon(probed), {})
        assert len(urls) == scanner._MAX_URLS
        dropped = [f"h{i:03d}.example.com" for i in range(scanner._MAX_URLS, scanner._MAX_URLS + 5)]
        assert not any(h in u for h in dropped for u in urls)
        _assert_kept_by_host(dropped)
        assert f"target cap {scanner._MAX_URLS}" in _cache_gap()["reason"]

    def test_a_host_the_cap_cut_partly_is_kept_whole(self):
        # A finding is matched to its host, not its URL: the host's untested URL
        # keeps every cache finding on that host.
        probed = ([f"https://h{i:03d}.example.com" for i in range(scanner._MAX_URLS - 1)]
                  + [f"https://{A}", f"http://{A}"])
        urls = scanner._collect_target_urls(_recon(probed), {})
        assert f"https://{A}" in urls and f"http://{A}" not in urls
        _assert_kept_by_host([A])

    def test_at_or_under_the_cap_nothing_is_noted(self):
        scanner._collect_target_urls(_recon([f"https://{A}", f"https://{B}"]), {})
        assert not cb.coverage_report().degraded


# ---------------------------------------------------------------------------
# URLs that were not tested
# ---------------------------------------------------------------------------

@pytest.fixture
def no_wcvs(monkeypatch):
    monkeypatch.setattr(scanner.wcvs_runner, "run_wcvs", lambda urls, s, **k: [])


class _Session:
    def __init__(self, error=None):
        self.error = error
        self.gets = []

    def get(self, url, **kw):
        self.gets.append(url)
        if self.error:
            raise self.error
        return mock.Mock(status_code=200, headers={"Content-Type": "text/html"}, text="ok")

    def close(self):
        pass


class TestUntestedUrls:
    @pytest.mark.parametrize("workers", [1, 4])
    def test_regression_a_url_whose_confirmation_raised_lost_its_findings(
            self, no_wcvs, monkeypatch, workers):
        def scan(url, *args):
            if A in url:
                raise ValueError("bad vector")
            return _clean(url)
        monkeypatch.setattr(scanner, "_scan_one_url", scan)
        out = scanner.run_cache_scan(_recon([f"https://{A}", f"https://{B}"]),
                                     {**SETTINGS, "WEB_CACHE_POISON_CONFIRM_WORKERS": workers})
        assert out["cache_scan"]["by_target"][f"https://{A}"]["findings"] == []
        _assert_kept_by_host([A])
        assert "error" in _cache_gap()["reason"]

    def test_a_url_that_never_answered_the_oracle_keeps_its_findings(self, no_wcvs, monkeypatch):
        session = _Session(requests.ConnectTimeout("stalled"))
        monkeypatch.setattr(scanner, "_build_retry_session", lambda *a, **k: session)
        out = scanner.run_cache_scan(_recon([f"https://{A}"]), SETTINGS)
        assert session.gets == [f"https://{A}"]
        assert out["cache_scan"]["by_target"][f"https://{A}"]["unchecked"] == "no answer"
        _assert_kept_by_host([A])
        assert "no answer" in _cache_gap()["reason"]

    def test_a_url_that_answered_uncached_prunes_as_before(self, no_wcvs, monkeypatch):
        session = _Session()
        monkeypatch.setattr(scanner, "_build_retry_session", lambda *a, **k: session)
        out = scanner.run_cache_scan(_recon([f"https://{A}"]), SETTINGS)
        assert len(session.gets) >= 2
        assert "unchecked" not in out["cache_scan"]["by_target"][f"https://{A}"]
        assert not cb.coverage_report().degraded

    def test_the_scan_switched_off_notes_nothing(self, monkeypatch):
        monkeypatch.setattr(scanner, "_scan_one_url", mock.Mock(side_effect=AssertionError))
        scanner.run_cache_scan(_recon([f"https://{A}"]), {"WEB_CACHE_POISON_ENABLED": False})
        assert not cb.coverage_report().degraded


# ---------------------------------------------------------------------------
# WCVS
# ---------------------------------------------------------------------------

REPORT = {"websites": [{"url": f"https://{A}", "isVulnerable": True, "results": [{
    "technique": "Header Poisoning", "isVulnerable": True,
    "checks": [{"identifier": "X-Forwarded-Host", "reason": "reflected",
                "request": {"curlCommand": "", "request": "", "response": ""}}]}]}]}


def _wcvs(timeout=False, rc=0, report=None):
    calls = []

    def run(cmd, **kw):
        calls.append((cmd, kw))
        if report is not None:
            out_dir = next(Path(a.rsplit(":", 1)[0]) for a in cmd if a.endswith(":/output"))
            (out_dir / "WCVS_2026_x_Report.json").write_text(json.dumps(report))
        if timeout:
            raise subprocess.TimeoutExpired(cmd, kw["timeout"])
        return subprocess.CompletedProcess(cmd, rc, stdout="", stderr="")
    return run, calls


class TestWcvsRunner:
    URLS = [f"https://{A}", f"https://{B}"]

    def test_regression_a_timeout_read_its_partial_report_as_complete(self, tmp_path):
        run, calls = _wcvs(timeout=True, report=REPORT)
        outcome = {}
        with mock.patch.object(wcvs_runner.subprocess, "run", side_effect=run):
            found = wcvs_runner.run_wcvs(self.URLS, SETTINGS, work_dir=str(tmp_path), outcome=outcome)
        cmd, kw = calls[0]
        assert cmd[:4] == ["docker", "run", "--rm", "--net=host"] and "-gr" in cmd
        assert kw["timeout"] == 1800
        assert [c["vector_name"] for c in found] == ["X-Forwarded-Host"]
        assert outcome["incomplete"] == "timed out after 1800s"

    def test_no_report_is_incomplete(self, tmp_path):
        run, _ = _wcvs(rc=125)
        outcome = {}
        with mock.patch.object(wcvs_runner.subprocess, "run", side_effect=run):
            assert wcvs_runner.run_wcvs(self.URLS, SETTINGS, work_dir=str(tmp_path),
                                        outcome=outcome) == []
        assert outcome["incomplete"] == "produced no report"

    def test_an_error_is_incomplete_and_names_its_class_only(self, tmp_path):
        outcome = {}
        with mock.patch.object(wcvs_runner, "build_wcvs_command",
                               side_effect=RuntimeError(f"https://{A}/secret")):
            assert wcvs_runner.run_wcvs(self.URLS, SETTINGS, work_dir=str(tmp_path),
                                        outcome=outcome) == []
        assert outcome["incomplete"] == "failed (RuntimeError)"

    def test_a_complete_run_says_nothing(self, tmp_path):
        run, _ = _wcvs(report=REPORT)
        outcome = {}
        with mock.patch.object(wcvs_runner.subprocess, "run", side_effect=run):
            assert len(wcvs_runner.run_wcvs(self.URLS, SETTINGS, work_dir=str(tmp_path),
                                            outcome=outcome)) == 1
        assert outcome == {}

    def test_the_outcome_is_optional(self, tmp_path):
        run, _ = _wcvs(timeout=True)
        with mock.patch.object(wcvs_runner.subprocess, "run", side_effect=run):
            assert wcvs_runner.run_wcvs(self.URLS, SETTINGS, work_dir=str(tmp_path)) == []


class TestWcvsInTheScan:
    def test_regression_a_wcvs_timeout_pruned_every_target_hosts_findings(self, monkeypatch):
        run, _ = _wcvs(timeout=True)
        monkeypatch.setattr(scanner, "_scan_one_url", _clean)
        with mock.patch.object(wcvs_runner.subprocess, "run", side_effect=run):
            scanner.run_cache_scan(_recon([f"https://{A}", f"https://{B}"]), SETTINGS)
        _assert_kept_by_host([A, B])
        assert "WCVS timed out" in _cache_gap()["reason"]

    def test_a_complete_wcvs_run_notes_nothing(self, monkeypatch):
        run, _ = _wcvs(report=REPORT)
        monkeypatch.setattr(scanner, "_scan_one_url", _clean)
        with mock.patch.object(wcvs_runner.subprocess, "run", side_effect=run):
            scanner.run_cache_scan(_recon([f"https://{A}", f"https://{B}"]), SETTINGS)
        assert not cb.coverage_report().degraded


# ---------------------------------------------------------------------------
# What the end-of-run prune is asked to do
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


class _Graph:
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

    def keep_for(self, source):
        call, = [p for p in self.prunes if source in p["sources"]]
        return call.get("keep_hosts")


def test_the_prune_keeps_the_cache_findings_of_a_stalled_host(recon_main, monkeypatch):
    graph = _Graph()
    monkeypatch.setattr("graph_db.Neo4jClient", graph)
    monkeypatch.setattr(scanner.wcvs_runner, "run_wcvs", lambda urls, s, **k: [])
    session = _Session(requests.ReadTimeout("stalled"))
    monkeypatch.setattr(scanner, "_build_retry_session", lambda *a, **k: session)
    scanner.run_cache_scan(_recon([f"https://{A}"]), SETTINGS)
    recon_main._prune_recon_findings()
    assert graph.keep_for("cache_poisoning") == (A,)
    assert graph.keep_for("wcvs") == (A,)
    assert graph.keep_for("nuclei") == ()
