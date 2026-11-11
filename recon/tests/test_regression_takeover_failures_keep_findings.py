"""Regression (R-23): a takeover layer that failed read as "no takeover", and the
prune deleted the earlier takeover findings.

Subjack timing out or missing, the Nuclei takeover run timing out, exiting
non-zero or having no Docker, and BadDNS failing all returned the same `[]` as
a clean run, and the module made no circuit_breaker call, so the end-of-run
prune read "no takeover_scan finding on these hosts" as "gone". Each failure
now keeps the takeover findings of the hosts that layer did not check, by host
and for takeover_scan alone (the other tools reached those hosts). A layer
switched off by configuration, and a clean run, note nothing and prune as
before.

subprocess, Docker and DNS are fakes; the module's own runners run for real.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers import circuit_breaker as cb  # noqa: E402
from recon.main_recon_modules import subdomain_takeover as runner  # noqa: E402

APEX, APP, OLD = "example.com", "app.example.com", "old.example.com"
TOKEN = re.compile(r"^[a-z0-9_]{1,64}$")

SETTINGS = {
    "SUBDOMAIN_TAKEOVER_ENABLED": True,
    "SUBJACK_ENABLED": True,
    "NUCLEI_TAKEOVERS_ENABLED": False,
    "BADDNS_ENABLED": False,
    "TAKEOVER_CNAME_VALIDATION_ENABLED": False,
    "TAKEOVER_CERT_VALIDATION_ENABLED": False,
    "SUBJACK_RUN_TIMEOUT": 900,
}


def _recon(live=False):
    recon = {
        "domain": APEX,
        "dns": {"subdomains": {
            APP: {"has_records": True},
            OLD: {"has_records": True, "records": {"CNAME": "old-example.github.io."}},
        }},
    }
    if live:
        recon["http_probe"] = {"by_url": {f"https://{APP}": {"status_code": 200}}}
    return recon


def _run(settings=None, live=False):
    return runner.run_subdomain_takeover(_recon(live), settings={**SETTINGS, **(settings or {})})


def _report():
    return cb.coverage_report()


def _takeover_gaps():
    return [g for g in _report().gaps if g["source"] == "takeover_scan"]


def _assert_kept_by_host(hosts):
    report = _report()
    assert report.keep_hostnames("takeover_scan") == tuple(sorted(hosts))
    # By host, for takeover_scan alone: the other modules reached these hosts.
    assert report.keep_hostnames("nuclei") == ()
    assert "takeover_scan" not in report.degraded_sources
    assert all(TOKEN.match(g["source"]) and TOKEN.match(g["module"]) for g in report.gaps)


def _completed(cmd, rc=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(cmd, rc, stdout=stdout, stderr=stderr)


# ---------------------------------------------------------------------------
# Subjack
# ---------------------------------------------------------------------------

class TestSubjack:
    def test_regression_a_subjack_timeout_pruned_every_takeover_finding(self):
        calls = []

        def timed_out(cmd, **kw):
            calls.append((cmd, kw))
            # What subjack wrote before the cap is still read.
            out = Path(cmd[cmd.index("-o") + 1])
            out.write_text(json.dumps([{"subdomain": OLD, "vulnerable": True, "service": "Github"}]))
            raise subprocess.TimeoutExpired(cmd, kw["timeout"])

        with mock.patch.object(runner.shutil, "which", return_value="/usr/local/bin/subjack"), \
                mock.patch.object(runner.subprocess, "run", side_effect=timed_out):
            out = _run()

        cmd, kw = calls[0]
        assert cmd[0] == "subjack" and kw["timeout"] == 900
        targets = Path(cmd[cmd.index("-w") + 1])
        assert targets.name == "subjack_targets.txt"
        assert [f["hostname"] for f in out["subdomain_takeover"]["findings"]] == [OLD]
        _assert_kept_by_host([APEX, APP, OLD])
        gap, = _takeover_gaps()
        assert gap["module"] == "subdomain_takeover"
        assert "Subjack" in gap["reason"] and "timed out" in gap["reason"]

    def test_a_missing_subjack_binary_keeps_the_findings_too(self):
        with mock.patch.object(runner.shutil, "which", return_value=None), \
                mock.patch.object(runner.subprocess, "run") as run:
            _run()
        run.assert_not_called()
        _assert_kept_by_host([APEX, APP, OLD])
        assert "not found" in _takeover_gaps()[0]["reason"]

    def test_a_binary_that_vanished_before_the_run_keeps_them(self):
        with mock.patch.object(runner.shutil, "which", return_value="/usr/local/bin/subjack"), \
                mock.patch.object(runner.subprocess, "run", side_effect=FileNotFoundError("subjack")):
            _run()
        _assert_kept_by_host([APEX, APP, OLD])

    def test_a_layer_that_raises_costs_its_own_hosts_not_the_module(self, monkeypatch):
        def broken(subdomains, work_dir, settings):
            raise OSError("disk full")
        monkeypatch.setattr(runner, "_run_subjack", broken)
        out = _run()
        assert out["subdomain_takeover"]["findings"] == []
        _assert_kept_by_host([APEX, APP, OLD])
        assert "OSError" in _takeover_gaps()[0]["reason"]
        assert "disk full" not in _takeover_gaps()[0]["reason"]

    @pytest.mark.parametrize("rc", [0, 1])
    def test_a_clean_run_notes_nothing(self, rc):
        # Subjack exits non-zero on some versions when nothing is vulnerable.
        with mock.patch.object(runner.shutil, "which", return_value="/usr/local/bin/subjack"), \
                mock.patch.object(runner.subprocess, "run",
                                  side_effect=lambda cmd, **kw: _completed(cmd, rc)):
            out = _run()
        assert out["subdomain_takeover"]["findings"] == []
        assert not _report().degraded

    def test_subjack_switched_off_notes_nothing(self):
        with mock.patch.object(runner.subprocess, "run") as run:
            _run({"SUBJACK_ENABLED": False})
        run.assert_not_called()
        assert not _report().degraded

    def test_the_whole_module_switched_off_notes_nothing(self):
        out = runner.run_subdomain_takeover(_recon(), settings={"SUBDOMAIN_TAKEOVER_ENABLED": False})
        assert out["subdomain_takeover"]["findings"] == []
        assert not _report().degraded


# ---------------------------------------------------------------------------
# Nuclei takeover templates
# ---------------------------------------------------------------------------

NUCLEI_ON = {"SUBJACK_ENABLED": False, "NUCLEI_TAKEOVERS_ENABLED": True,
             "NUCLEI_TAKEOVER_RUN_TIMEOUT": 1800}
NUCLEI_ROW = {"template-id": "github-takeover", "matched-at": f"https://{APP}/",
              "info": {"name": "github-takeover", "severity": "high", "tags": ["takeover"]}}


@pytest.fixture
def docker_up():
    with mock.patch.object(runner, "is_docker_installed", return_value=True), \
            mock.patch.object(runner, "is_docker_running", return_value=True), \
            mock.patch.object(runner, "pull_nuclei_docker_image"), \
            mock.patch.object(runner, "ensure_templates_volume"), \
            mock.patch.object(runner, "fix_file_ownership"):
        yield


def _nuclei_run(rc=0, timeout=False, rows=()):
    calls = []

    def run(cmd, **kw):
        calls.append(cmd)
        if cmd[:2] == ["docker", "kill"]:
            return _completed(cmd)
        if rows:
            # Nuclei writes into the work dir build_nuclei_command mounts at /output.
            work_dir = next(Path(a.rsplit(":", 1)[0]) for a in cmd if a.endswith(":/output"))
            (work_dir / "nuclei_takeover_output.jsonl").write_text(
                "".join(json.dumps(r) + "\n" for r in rows))
        if timeout:
            raise subprocess.TimeoutExpired(cmd, kw["timeout"])
        return _completed(cmd, rc)
    return run, calls


class TestNucleiTakeover:
    def test_a_timeout_keeps_the_live_hosts_findings_and_its_partial_rows(self, docker_up):
        run, calls = _nuclei_run(timeout=True, rows=[NUCLEI_ROW])
        with mock.patch.object(runner.subprocess, "run", side_effect=run):
            out = runner.run_subdomain_takeover(_recon(live=True), settings={**SETTINGS, **NUCLEI_ON})
        assert calls[0][:3] == ["docker", "run", "--rm"]
        assert calls[1][:2] == ["docker", "kill"]
        assert [f["hostname"] for f in out["subdomain_takeover"]["findings"]] == [APP]
        _assert_kept_by_host([APP])
        assert "Nuclei" in _takeover_gaps()[0]["reason"]

    def test_a_non_zero_exit_keeps_them(self, docker_up):
        run, _ = _nuclei_run(rc=125)
        with mock.patch.object(runner.subprocess, "run", side_effect=run):
            runner.run_subdomain_takeover(_recon(live=True), settings={**SETTINGS, **NUCLEI_ON})
        _assert_kept_by_host([APP])
        assert "125" in _takeover_gaps()[0]["reason"]

    def test_no_docker_keeps_them(self):
        with mock.patch.object(runner, "is_docker_installed", return_value=False), \
                mock.patch.object(runner.subprocess, "run") as run:
            runner.run_subdomain_takeover(_recon(live=True), settings={**SETTINGS, **NUCLEI_ON})
        run.assert_not_called()
        _assert_kept_by_host([APP])

    def test_a_clean_run_notes_nothing(self, docker_up):
        run, _ = _nuclei_run(rc=0, rows=[NUCLEI_ROW])
        with mock.patch.object(runner.subprocess, "run", side_effect=run):
            out = runner.run_subdomain_takeover(_recon(live=True), settings={**SETTINGS, **NUCLEI_ON})
        assert [f["hostname"] for f in out["subdomain_takeover"]["findings"]] == [APP]
        assert not _report().degraded


# ---------------------------------------------------------------------------
# BadDNS
# ---------------------------------------------------------------------------

BADDNS_ON = {"SUBJACK_ENABLED": False, "BADDNS_ENABLED": True, "BADDNS_RUN_TIMEOUT": 1800}


def _baddns_run(rc=0, stderr="", inspect_rc=0, timeout=False):
    calls = []

    def run(cmd, **kw):
        calls.append(cmd)
        if cmd[:3] == ["docker", "image", "inspect"]:
            return _completed(cmd, inspect_rc)
        if cmd[:2] == ["docker", "kill"]:
            return _completed(cmd)
        if timeout:
            raise subprocess.TimeoutExpired(cmd, kw["timeout"])
        return _completed(cmd, rc, stdout="", stderr=stderr)
    return run, calls


class TestBadDns:
    @pytest.fixture(autouse=True)
    def _docker(self):
        with mock.patch.object(runner, "is_docker_installed", return_value=True), \
                mock.patch.object(runner, "is_docker_running", return_value=True):
            yield

    def test_a_per_target_timeout_keeps_that_host_only(self):
        stderr = (f"[baddns-batch] timeout after 90s on {OLD}\n"
                  "[baddns-batch] timeout after 90s on not-a-target.example.org\n"
                  "[baddns-batch] summary: scanned=3 skipped=0 findings=0\n")
        run, calls = _baddns_run(stderr=stderr)
        with mock.patch.object(runner.subprocess, "run", side_effect=run):
            _run(BADDNS_ON)
        assert calls[1][:3] == ["docker", "run", "--rm"]
        _assert_kept_by_host([OLD])
        assert "BadDNS" in _takeover_gaps()[0]["reason"]

    def test_a_missing_image_keeps_every_subdomain(self):
        run, calls = _baddns_run(inspect_rc=1)
        with mock.patch.object(runner.subprocess, "run", side_effect=run):
            _run(BADDNS_ON)
        assert len(calls) == 1
        _assert_kept_by_host([APEX, APP, OLD])

    def test_a_timeout_keeps_every_subdomain(self):
        run, calls = _baddns_run(timeout=True)
        with mock.patch.object(runner.subprocess, "run", side_effect=run):
            _run(BADDNS_ON)
        assert calls[-1][:2] == ["docker", "kill"]
        _assert_kept_by_host([APEX, APP, OLD])

    def test_a_non_zero_exit_keeps_every_subdomain(self):
        run, _ = _baddns_run(rc=137)
        with mock.patch.object(runner.subprocess, "run", side_effect=run):
            _run(BADDNS_ON)
        _assert_kept_by_host([APEX, APP, OLD])

    def test_a_clean_run_notes_nothing(self):
        run, _ = _baddns_run(stderr="[baddns-batch] summary: scanned=3 skipped=0 findings=0\n")
        with mock.patch.object(runner.subprocess, "run", side_effect=run):
            _run(BADDNS_ON)
        assert not _report().degraded


# ---------------------------------------------------------------------------
# What the end-of-run prune is asked to do
# ---------------------------------------------------------------------------

@pytest.fixture
def recon_main():
    stub = {
        'TARGET_DOMAIN': APEX, 'SUBDOMAIN_LIST': [], 'IP_MODE': False, 'TARGET_IPS': [],
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


def test_the_prune_keeps_the_takeover_findings_subjack_did_not_check(recon_main, monkeypatch):
    graph = _Graph()
    monkeypatch.setattr("graph_db.Neo4jClient", graph)
    with mock.patch.object(runner.shutil, "which", return_value=None):
        _run()
    recon_main._prune_recon_findings()
    assert graph.keep_for("takeover_scan") == tuple(sorted((APEX, APP, OLD)))
    # Every other source still prunes those hosts.
    assert graph.keep_for("nuclei") == ()
