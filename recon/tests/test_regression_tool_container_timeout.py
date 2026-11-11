"""Regression (R-9): a tool timeout abandoned the docker CLI and left the container running.

`subprocess.run(["docker", "run", "--rm", ...], timeout=...)` kills only the
docker CLI on timeout; the daemon-owned container keeps scanning the target
after the run has moved on. WCVS and graphql-cop ran unnamed, so nothing could
stop them. Both now go through `docker_helpers.run_tool_container`, which names
the container, kills it by that name when the timeout fires, and hands back the
output collected so far. The caller parses it and records what it could not
finish: WCVS through R-23's outcome, graphql-cop as a gap for that host.

Docker is a fake (`subprocess.run`); the helper, the WCVS runner, the cache
scanner and the graphql-cop wrapper run for real.
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

from recon.cache_scan import scanner as cache_scanner, wcvs_runner  # noqa: E402
from recon.graphql_scan import misconfig  # noqa: E402
from recon.helpers import circuit_breaker as cb  # noqa: E402
from recon.helpers import docker_helpers  # noqa: E402

RUN_ID = "3f2b9c1e-0d4a-4c55-9a7e-1b2c3d4e5f60"
A, B = "a.example.com", "b.example.com"
TOKEN = re.compile(r"^[a-z0-9_]{1,64}$")


@pytest.fixture(autouse=True)
def _run_env(monkeypatch):
    monkeypatch.setenv("RECON_RUN_ID", RUN_ID)
    monkeypatch.delenv("PARTIAL_RECON_RUN_ID", raising=False)


class FakeDocker:
    """`subprocess.run` for docker: `docker run` answers or times out, `docker kill` is recorded."""

    def __init__(self, *, timeout=False, stdout="", stderr="", rc=0,
                 partial_out=None, partial_err=None, on_run=None):
        self.timeout = timeout
        self.stdout, self.stderr, self.rc = stdout, stderr, rc
        self.partial_out, self.partial_err = partial_out, partial_err
        self.on_run = on_run
        self.calls = []

    def __call__(self, cmd, **kw):
        self.calls.append((list(cmd), kw))
        if cmd[:2] == ["docker", "kill"]:
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if self.on_run:
            self.on_run(cmd)
        if self.timeout:
            # On POSIX, run() hands back what it read so far as bytes, text mode or not.
            raise subprocess.TimeoutExpired(cmd, kw.get("timeout"), output=self.partial_out,
                                            stderr=self.partial_err)
        return subprocess.CompletedProcess(cmd, self.rc, self.stdout, self.stderr)

    @property
    def runs(self):
        return [c for c, _ in self.calls if c[:2] == ["docker", "run"]]

    @property
    def kills(self):
        return [c for c, _ in self.calls if c[:2] == ["docker", "kill"]]

    def run_name(self, i=0):
        cmd = self.runs[i]
        assert "--name" in cmd, f"docker run has no --name, so nothing can stop it: {cmd}"
        return cmd[cmd.index("--name") + 1]


def _without_name(cmd):
    i = cmd.index("--name")
    return cmd[:i] + cmd[i + 2:]


# ---------------------------------------------------------------------------
# The helper
# ---------------------------------------------------------------------------

BASE = ["docker", "run", "--rm", "--net=host", "-v", "/tmp/redamon/x:/out", "img:1", "-t", "u"]


class TestRunToolContainer:
    def _run(self, fake, cmd=BASE, **kw):
        from recon.helpers.docker_helpers import run_tool_container
        with mock.patch.object(docker_helpers.subprocess, "run", side_effect=fake):
            return run_tool_container(cmd, **{"tool": "wcvs", "timeout": 30, **kw})

    def test_a_finished_run_builds_the_same_command_plus_its_name(self):
        fake = FakeDocker(stdout="out", stderr="err", rc=3)
        res = self._run(fake)
        name = fake.run_name()
        assert fake.runs[0] == [*BASE[:4], "--name", name, *BASE[4:]]
        assert re.fullmatch(rf"wcvs-{RUN_ID}-[0-9a-f]{{8}}", name)
        _, kw = fake.calls[0]
        assert kw["timeout"] == 30 and kw["capture_output"] and kw["text"]
        assert (res.name, res.returncode, res.stdout, res.stderr, res.timed_out) == \
            (name, 3, "out", "err", False)
        assert fake.kills == []

    def test_regression_a_timeout_kills_the_container_it_named(self):
        fake = FakeDocker(timeout=True, partial_out=b'{"row": 1}\n', partial_err=b"warn\r\n")
        res = self._run(fake)
        name = fake.run_name()
        assert fake.kills == [["docker", "kill", name]]
        assert [c[:2] for c, _ in fake.calls] == [["docker", "run"], ["docker", "kill"]]
        assert res.timed_out and res.returncode is None and res.name == name
        assert res.stdout == '{"row": 1}\n' and res.stderr == "warn\n"

    def test_a_timeout_with_nothing_read_returns_empty_text(self):
        res = self._run(FakeDocker(timeout=True))
        assert res.timed_out and res.stdout == "" and res.stderr == ""

    def test_a_kill_that_fails_does_not_raise(self):
        def run(cmd, **kw):
            if cmd[:2] == ["docker", "kill"]:
                raise subprocess.TimeoutExpired(cmd, 15)
            raise subprocess.TimeoutExpired(cmd, kw["timeout"])
        assert self._run(run).timed_out

    def test_a_missing_docker_binary_reaches_the_caller(self):
        def run(cmd, **kw):
            raise FileNotFoundError("docker")
        with pytest.raises(FileNotFoundError):
            self._run(run)

    def test_stdin_is_handed_to_the_tool(self):
        fake = FakeDocker()
        self._run(fake, input="a\nb\n")
        assert fake.calls[0][1]["input"] == "a\nb\n"

    def test_a_partial_recon_names_its_own_run(self, monkeypatch):
        monkeypatch.setenv("PARTIAL_RECON_RUN_ID", "partial-7")
        fake = FakeDocker()
        self._run(fake, tool="graphql-cop")
        assert re.fullmatch(r"graphql-cop-partial-7-[0-9a-f]{8}", fake.run_name())

    def test_outside_a_run_the_name_is_still_unique(self, monkeypatch):
        monkeypatch.delenv("RECON_RUN_ID")
        fake = FakeDocker()
        self._run(fake)
        self._run(fake)
        first, second = fake.run_name(0), fake.run_name(1)
        assert re.fullmatch(r"wcvs-[0-9a-f]{8}-[0-9a-f]{8}", first) and first != second

    def test_a_hostile_run_id_cannot_shape_the_name(self, monkeypatch):
        monkeypatch.setenv("RECON_RUN_ID", "x; rm -rf /" + "y" * 200)
        fake = FakeDocker()
        self._run(fake, tool="Tool Name!")
        name = fake.run_name()
        assert re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]+", name) and len(name) <= 100

    def test_a_caller_named_container_is_not_named_twice(self):
        cmd = ["docker", "run", "--rm", "--name", "mine-1", "img"]
        fake = FakeDocker(timeout=True)
        res = self._run(fake, cmd=cmd, name="mine-1")
        assert fake.runs[0] == cmd
        assert fake.kills == [["docker", "kill", "mine-1"]] and res.name == "mine-1"

    def test_the_name_never_splits_an_option_from_its_value(self):
        fake = FakeDocker()
        self._run(fake, cmd=["docker", "run", "-v", "/a:/b", "img"])
        assert fake.runs[0][:4] == ["docker", "run", "--name", fake.run_name()]

    @pytest.mark.parametrize("cmd", [["docker", "exec", "c", "ls"], ["naabu", "-host", "x"], []])
    def test_only_a_docker_run_is_accepted(self, cmd):
        from recon.helpers.docker_helpers import run_tool_container
        with pytest.raises(ValueError):
            run_tool_container(cmd, tool="x", timeout=1)


# ---------------------------------------------------------------------------
# WCVS
# ---------------------------------------------------------------------------

REPORT = {"websites": [{"url": f"https://{A}", "isVulnerable": True, "results": [{
    "technique": "Header Poisoning", "isVulnerable": True,
    "checks": [{"identifier": "X-Forwarded-Host", "reason": "reflected",
                "request": {"curlCommand": "", "request": "", "response": ""}}]}]}]}
WCVS_SETTINGS = {"WEB_CACHE_POISON_ENABLED": True, "WEB_CACHE_POISON_CONFIRM_WORKERS": 1,
                 "WEB_CACHE_POISON_BEHAVIORAL_ORACLE": False, "WEB_CACHE_POISON_TIMEOUT": 1800}


def _write_report(cmd):
    out_dir = next(Path(a.rsplit(":", 1)[0]) for a in cmd if a.endswith(":/output"))
    (out_dir / "WCVS_2026_x_Report.json").write_text(json.dumps(REPORT))


class TestWcvs:
    URLS = [f"https://{A}", f"https://{B}"]

    def test_regression_a_wcvs_timeout_left_its_container_scanning(self, tmp_path):
        fake = FakeDocker(timeout=True, on_run=_write_report)
        outcome = {}
        with mock.patch.object(docker_helpers.subprocess, "run", side_effect=fake):
            found = wcvs_runner.run_wcvs(self.URLS, WCVS_SETTINGS, work_dir=str(tmp_path),
                                         outcome=outcome)
        name = fake.run_name()
        assert fake.kills == [["docker", "kill", name]]
        assert name.startswith(f"wcvs-{RUN_ID}-")
        # The partial report is still read, and the run is still marked unfinished.
        assert [c["vector_name"] for c in found] == ["X-Forwarded-Host"]
        assert outcome == {"incomplete": "timed out after 1800s"}

    def test_a_finished_wcvs_run_builds_the_same_command_plus_its_name(self, tmp_path):
        fake = FakeDocker(on_run=_write_report)
        outcome = {}
        with mock.patch.object(docker_helpers.subprocess, "run", side_effect=fake):
            found = wcvs_runner.run_wcvs(self.URLS, WCVS_SETTINGS, work_dir=str(tmp_path),
                                         outcome=outcome)
        cmd = fake.runs[0]
        out_dir = next(a.rsplit(":", 1)[0] for a in cmd if a.endswith(":/output"))
        from recon.cache_scan.safety import is_cpdos_allowed, is_deception_allowed
        expected = wcvs_runner.build_wcvs_command(
            targets_file=f"{out_dir}/targets.txt", output_dir=out_dir,
            docker_image="redamon-wcvs:latest", threads=10, req_rate=0, cache_header="",
            skip_tests=wcvs_runner.safety_skip_tests(is_deception_allowed(WCVS_SETTINGS),
                                                     is_cpdos_allowed(WCVS_SETTINGS)))
        assert _without_name(cmd) == expected
        assert cmd[:4] == ["docker", "run", "--rm", "--net=host"]
        assert fake.calls[0][1]["timeout"] == 1800
        assert fake.kills == [] and outcome == {} and len(found) == 1

    def test_regression_the_scan_kills_wcvs_and_keeps_every_target_hosts_findings(self, monkeypatch):
        fake = FakeDocker(timeout=True)
        monkeypatch.setattr(cache_scanner, "_scan_one_url", lambda url, *a: (url, {
            "oracle": {"cacheable": False, "indicator": "", "signals": [], "saw_hit": False},
            "findings": []}, 0))
        recon = {
            "domain": "example.com", "dns": {"domain": {}, "subdomains": {}},
            "http_probe": {"by_url": {u: {"url": u, "status_code": 200} for u in self.URLS}},
            "resource_enum": {"by_base_url": {}, "discovered_urls": []},
            "metadata": {"include_root_domain": False},
        }
        with mock.patch.object(docker_helpers.subprocess, "run", side_effect=fake):
            cache_scanner.run_cache_scan(recon, WCVS_SETTINGS)
        assert fake.kills == [["docker", "kill", fake.run_name()]]
        report = cb.coverage_report()
        assert report.keep_hostnames("cache_poisoning") == (A, B)
        gap, = [g for g in report.gaps if g["source"] == "cache_poisoning"]
        assert "WCVS timed out after 1800s" in gap["reason"]


# ---------------------------------------------------------------------------
# graphql-cop
# ---------------------------------------------------------------------------

ENDPOINT = f"https://{A}/graphql"
COP_SETTINGS = {"GRAPHQL_COP_ENABLED": True, "GRAPHQL_COP_TIMEOUT": 120}
COP_ROWS = [{"title": "Alias Overloading", "result": True, "severity": "HIGH",
             "description": "", "impact": "", "color": "red", "curl_verify": ""}]


def _cop(fake, **kw):
    with mock.patch.object(docker_helpers.subprocess, "run", side_effect=fake):
        return misconfig.run_graphql_cop(ENDPOINT, kw.pop("headers", {}), COP_SETTINGS, **kw)


def _cop_gap():
    report = cb.coverage_report()
    gaps = [g for g in report.gaps if g["source"] == "graphql_cop"]
    return report, gaps


class TestGraphqlCop:
    def test_regression_a_graphql_cop_timeout_left_its_container_running(self):
        fake = FakeDocker(timeout=True, partial_out=b"")
        assert _cop(fake) is None
        name = fake.run_name()
        assert fake.kills == [["docker", "kill", name]]
        assert name.startswith(f"graphql-cop-{RUN_ID}-")

    def test_regression_a_timeout_pruned_the_hosts_earlier_graphql_cop_findings(self):
        _cop(FakeDocker(timeout=True))
        report, gaps = _cop_gap()
        # By host and for graphql-cop alone: the native GraphQL scan reached this host.
        assert report.keep_hostnames("graphql_cop") == (A,)
        assert report.keep_hostnames("graphql_scan") == ()
        assert not {"graphql_cop", "graphql_scan"} & report.degraded_sources
        assert len(gaps) == 1 and "graphql-cop timed out after 120s" in gaps[0]["reason"]
        assert all(TOKEN.match(g["source"]) and TOKEN.match(g["module"]) for g in report.gaps)

    def test_a_complete_report_read_before_the_kill_is_used(self):
        # graphql-cop prints its JSON array once, after its last test: an array
        # in a cut-short run's output is the whole report.
        fake = FakeDocker(timeout=True, partial_out=json.dumps(COP_ROWS).encode())
        out = _cop(fake)
        assert [f["vulnerability_type"] for f in out["findings"]] == ["graphql_alias_overloading"]
        assert fake.kills == [["docker", "kill", fake.run_name()]]
        assert not cb.coverage_report().degraded

    def test_output_with_no_report_keeps_the_hosts_findings(self):
        assert _cop(FakeDocker(rc=1, stdout="Traceback ...", stderr="boom")) is None
        report, gaps = _cop_gap()
        assert report.keep_hostnames("graphql_cop") == (A,) and len(gaps) == 1

    def test_a_missing_docker_binary_keeps_the_hosts_findings(self):
        def run(cmd, **kw):
            raise FileNotFoundError("docker")
        assert _cop(run) is None
        assert cb.coverage_report().keep_hostnames("graphql_cop") == (A,)

    def test_a_finished_run_builds_the_same_command_plus_its_name(self):
        fake = FakeDocker(stdout=json.dumps(COP_ROWS))
        out = _cop(fake, headers={"Authorization": "Bearer x"})
        cmd = fake.runs[0]
        assert _without_name(cmd) == [
            "docker", "run", "--rm", "--net=host", misconfig.DEFAULT_IMAGE,
            "-t", ENDPOINT, "-o", "json", "-H", json.dumps({"Authorization": "Bearer x"})]
        # Named before the image, where docker reads it as its own option.
        assert cmd.index("--name") < cmd.index(misconfig.DEFAULT_IMAGE)
        assert fake.calls[0][1]["timeout"] == 120
        assert len(out["findings"]) == 1 and fake.kills == []
        assert not cb.coverage_report().degraded

    def test_a_non_graphql_endpoint_is_checked_not_degraded(self):
        out = _cop(FakeDocker(stdout=f"{ENDPOINT} does not seem to be running GraphQL.\n[]\n"))
        assert out == {"findings": [], "raw": []}
        assert not cb.coverage_report().degraded
