"""Regression (R-9): a BadDNS run cut by its deadline threw away what it had found.

`_run_baddns` named the container and killed it on timeout, then returned `[]`:
every finding BadDNS had already printed for the names it finished was lost,
and every name was kept "not checked", the finished ones too. It now runs
through docker_helpers.run_tool_container, parses every complete JSON line
the tool printed, and keeps "not checked" only the names it may not have
finished: the batch entrypoint (scanners/baddns_scan/entrypoint.sh) checks the
targets file in order and prints a name's findings once it is done with it,
so the names before the last one with a printed finding are finished.

subprocess and Docker are fakes; the module's own runner runs for real.
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

APEX = "example.com"
A, B, C, D = (f"{n}.example.com" for n in "abcd")
# The order _run_baddns writes the targets file in, and BadDNS checks it in.
ORDER = sorted([APEX, A, B, C, D])

SETTINGS = {
    "SUBDOMAIN_TAKEOVER_ENABLED": True,
    "SUBJACK_ENABLED": False,
    "NUCLEI_TAKEOVERS_ENABLED": False,
    "BADDNS_ENABLED": True,
    "BADDNS_RUN_TIMEOUT": 1800,
    "TAKEOVER_CNAME_VALIDATION_ENABLED": False,
    "TAKEOVER_CERT_VALIDATION_ENABLED": False,
}


def _finding(target, module="CNAME"):
    return {"target": target, "module": module, "description": "Dangling CNAME",
            "confidence": "PROBABLE", "severity": "HIGH", "signature": "GitHub Pages",
            "indicator": "There isn't a GitHub Pages site here.",
            "trigger": f"{target.split('.')[0]}-example.github.io",
            "found_domains": [f"{target.split('.')[0]}-example.github.io"]}


def _line(target):
    return json.dumps(_finding(target)) + "\n"


class FakeDocker:
    """`docker image inspect` succeeds; `docker run` times out with `stdout`/`stderr`
    printed so far (bytes, as subprocess hands them over), or ends with `rc`."""

    def __init__(self, *, stdout=b"", stderr=b"", timeout=True, rc=0):
        self.calls, self.stdout, self.stderr = [], stdout, stderr
        self.timeout, self.rc = timeout, rc
        self.targets = None

    def __call__(self, cmd, **kw):
        self.calls.append((list(cmd), kw))
        if cmd[:2] == ["docker", "run"]:
            mount = cmd[cmd.index("-v") + 1].split(":", 1)[0]
            self.targets = Path(mount, "baddns_targets.txt").read_text().split()
            if self.timeout:
                raise subprocess.TimeoutExpired(cmd, kw["timeout"], output=self.stdout,
                                                stderr=self.stderr)
            return subprocess.CompletedProcess(cmd, self.rc, stdout=self.stdout.decode(),
                                               stderr=self.stderr.decode())
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    @property
    def run_argv(self):
        [argv] = [c for c, _ in self.calls if c[:2] == ["docker", "run"]]
        return argv

    @property
    def kills(self):
        return [c for c, _ in self.calls if c[:2] == ["docker", "kill"]]


def _scan(fake):
    recon = {"domain": APEX, "dns": {"subdomains": {h: {"has_records": True} for h in (A, B, C, D)}}}
    with mock.patch.object(runner, "is_docker_installed", return_value=True), \
            mock.patch.object(runner, "is_docker_running", return_value=True), \
            mock.patch.object(runner.subprocess, "run", side_effect=fake):
        return runner.run_subdomain_takeover(recon, settings=dict(SETTINGS))["subdomain_takeover"]


def _kept():
    return cb.coverage_report().keep_hostnames("takeover_scan")


class TestTimeout:
    def test_regression_the_findings_printed_before_the_cut_were_thrown_away(self):
        # b.example.com finished with a finding; the next name's line was cut mid-write.
        fake = FakeDocker(stdout=(_line(B) + _line(C)[:40]).encode())
        out = _scan(fake)
        assert [f["hostname"] for f in out["findings"]] == [B]
        assert out["findings"][0]["takeover_provider"] == "github-pages"

    def test_only_the_names_it_may_not_have_finished_stay_unchecked(self):
        fake = FakeDocker(stdout=(_line(B) + _line(C)[:40]).encode())
        _scan(fake)
        # a.example.com came before b's printed finding, so it was finished;
        # b itself may have had more lines cut, c onwards maybe never reached.
        assert fake.targets == ORDER == [A, B, C, D, APEX]
        assert _kept() == tuple(sorted([B, C, D, APEX]))
        gap, = [g for g in cb.coverage_report().gaps if g["source"] == "takeover_scan"]
        assert "BadDNS timed out after 1800s" in gap["reason"]

    def test_nothing_printed_keeps_every_name(self):
        fake = FakeDocker()
        out = _scan(fake)
        assert out["findings"] == []
        assert _kept() == tuple(sorted(ORDER))

    def test_a_finding_for_a_name_it_was_not_asked_about_moves_nothing(self):
        fake = FakeDocker(stdout=_line("elsewhere.example.org").encode())
        _scan(fake)
        assert _kept() == tuple(sorted(ORDER))

    def test_the_container_is_named_for_the_run_and_killed_by_that_name(self, monkeypatch):
        monkeypatch.setenv("RECON_RUN_ID", "run42")
        monkeypatch.delenv("PARTIAL_RECON_RUN_ID", raising=False)
        fake = FakeDocker(stdout=_line(B).encode())
        _scan(fake)
        argv = fake.run_argv
        name = argv[argv.index("--name") + 1]
        assert re.fullmatch(r"baddns-run42-[0-9a-f]{8}", name)
        assert argv.count("--name") == 1
        assert argv[:3] == ["docker", "run", "--rm"]
        assert fake.kills == [["docker", "kill", name]]
        timeout = next(kw["timeout"] for c, kw in fake.calls if c[:2] == ["docker", "run"])
        assert timeout == 1800

    def test_a_per_target_timeout_in_the_partial_stderr_is_still_noted(self):
        fake = FakeDocker(stdout=(_line(C)).encode(),
                          stderr=f"[baddns-batch] timeout after 90s on {A}\n".encode())
        _scan(fake)
        assert _kept() == tuple(sorted([A, C, D, APEX]))


class TestCompletedRun:
    def test_a_clean_run_returns_its_findings_and_notes_nothing(self):
        fake = FakeDocker(timeout=False, stdout=_line(B).encode(),
                          stderr=b"[baddns-batch] summary: scanned=5 skipped=0 findings=1\n")
        out = _scan(fake)
        assert [f["hostname"] for f in out["findings"]] == [B]
        assert fake.kills == []
        assert _kept() == ()
        assert not cb.coverage_report().degraded

    def test_a_non_zero_exit_keeps_every_name_and_its_findings(self):
        fake = FakeDocker(timeout=False, rc=137, stdout=_line(B).encode())
        out = _scan(fake)
        assert [f["hostname"] for f in out["findings"]] == [B]
        assert _kept() == tuple(sorted(ORDER))


class TestUnfinishedTargets:
    @pytest.mark.parametrize("printed, unfinished", [
        ([], ORDER),
        ([A], ORDER),
        ([B], [B, C, D, APEX]),
        ([A, D], [D, APEX]),
        ([APEX], [APEX]),
        (["B.EXAMPLE.COM"], [B, C, D, APEX]),
    ])
    def test_the_frontier_is_the_last_name_with_a_printed_finding(self, printed, unfinished):
        found = [_finding(t) for t in printed]
        assert runner._baddns_unfinished_targets(ORDER, found) == unfinished
