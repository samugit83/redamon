"""Regression (R-9, part B2): naabu, tlsx, Nuclei and the template volume stop their container.

Killing the docker CLI, through a `communicate(timeout=...)` that times out or
a `subprocess.run` timeout, leaves the daemon-owned container scanning after
the run has moved on. Every site below names its container and kills it by
that name when its deadline fires, and keeps what the tool wrote before the
cut:

- naabu: the ports it wrote are kept, and the targets with none are recorded
  as not port-scanned (their findings kept for every source, and no port of
  theirs read as closed), never as "no open ports";
- tlsx: the rows it printed are kept (R-21), now with its container stopped;
- Nuclei: the takeover layer and the alpine cleanup of its root-owned files go
  through `run_tool_container`; the vuln-scan passes and httpx were named and
  killed already and are pinned here;
- the nuclei-templates volume: its template count is named and bounded too.

Docker is a fake (`subprocess.run`, `subprocess.Popen`); the modules run for real.
Reserved names and documentation ranges only.
"""
from __future__ import annotations

import json
import subprocess
import sys
import threading
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers import circuit_breaker as cb  # noqa: E402
from recon.helpers import docker_helpers  # noqa: E402
from recon.main_recon_modules import http_probe as hp  # noqa: E402
from recon.main_recon_modules import port_scan as ps  # noqa: E402
from recon.main_recon_modules import subdomain_takeover as st  # noqa: E402
from recon.main_recon_modules import tls_scan  # noqa: E402
from recon.main_recon_modules import vuln_scan as vs  # noqa: E402

RUN_ID = "5d1c0b7a-2e4f-4a1b-9c3d-7e6f5a4b3c2d"
A, A_IP = "a.example.test", "192.0.2.10"
B, B_IP = "b.example.test", "192.0.2.20"


@pytest.fixture(autouse=True)
def _run_env(monkeypatch):
    monkeypatch.setenv("RECON_RUN_ID", RUN_ID)
    monkeypatch.delenv("PARTIAL_RECON_RUN_ID", raising=False)
    cb.reset_registry()
    yield
    cb.reset_registry()


class FakeDocker:
    """`subprocess.run` for the docker CLI: `docker kill` is recorded and
    succeeds; ``answer(cmd, kw)`` answers every other command (default: exit 0)."""

    def __init__(self, answer=None):
        self.answer = answer
        self.calls = []

    def __call__(self, cmd, **kw):
        cmd = list(cmd)
        self.calls.append((cmd, kw))
        if cmd[:2] != ["docker", "kill"] and self.answer:
            return self.answer(cmd, kw)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    @property
    def kills(self):
        return [c for c, _ in self.calls if c[:2] == ["docker", "kill"]]

    def runs(self, marker):
        return [(c, kw) for c, kw in self.calls if c[:2] == ["docker", "run"] and marker in c]


def _docker(fake):
    return mock.patch.object(subprocess, "run", side_effect=fake)


def _name_of(cmd):
    assert cmd.count("--name") == 1, f"docker run has no --name, so nothing can stop it: {cmd}"
    return cmd[cmd.index("--name") + 1]


def _without_name(cmd):
    i = cmd.index("--name")
    return cmd[:i] + cmd[i + 2:]


def _mount(cmd, inside):
    """The host dir of the `-v <host>:<inside>[:ro]` bind in a docker argv."""
    for flag, spec in zip(cmd, cmd[1:]):
        if flag == "-v" and spec.split(":")[1] == inside:
            return Path(spec.split(":")[0])
    raise AssertionError(f"no {inside} mount in {cmd}")


def _jsonl(*rows):
    return "".join(json.dumps(r) + "\n" for r in rows)


class CliProc:
    """subprocess.Popen for a docker CLI read with communicate(): each call
    takes the next step (an exception is raised, a pair returned)."""

    def __init__(self, cmd, *steps, returncode=0):
        self.cmd, self.steps, self.returncode = list(cmd), list(steps), returncode
        self.killed = False

    def communicate(self, input=None, timeout=None):
        step = self.steps.pop(0) if len(self.steps) > 1 else self.steps[0]
        if isinstance(step, BaseException):
            raise step
        return step

    def kill(self):
        self.killed = True
        self.returncode = -9

    def wait(self, timeout=None):
        return self.returncode

    def poll(self):
        return self.returncode


# ---------------------------------------------------------------------------
# naabu (port_scan.run_port_scan)
# ---------------------------------------------------------------------------

def _naabu_recon():
    return {"domain": "example.test",
            "dns": {"domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
                    "subdomains": {A: {"has_records": True, "ips": {"ipv4": [A_IP], "ipv6": []}},
                                   B: {"has_records": True, "ips": {"ipv4": [B_IP], "ipv6": []}}}}}


def _naabu_proc(rows=None, cut=False):
    """A naabu docker CLI: ``rows`` are what it wrote into its output file
    (None: no file at all); ``cut``: its run outlives the 1800 s timeout."""
    def start(cmd):
        if rows is not None:
            out = _mount(cmd, "/output") / Path(cmd[cmd.index("-o") + 1]).name
            out.write_text(_jsonl(*rows))
        if cut:
            return CliProc(cmd, subprocess.TimeoutExpired(cmd, 1800), ("", ""), returncode=None)
        return CliProc(cmd, ("", ""))
    return start


NAABU = {"NAABU_SCAN_TYPE": "c"}


def _naabu(*starts, settings=None):
    started = []
    queue = list(starts)

    def popen(cmd, **_kw):
        started.append(queue.pop(0)(list(cmd)))
        return started[-1]

    fake = FakeDocker()
    with mock.patch.object(ps, "is_docker_installed", return_value=True), \
         mock.patch.object(ps, "is_docker_running", return_value=True), \
         mock.patch.object(ps, "pull_naabu_docker_image", return_value=True), \
         mock.patch.object(subprocess, "Popen", side_effect=popen), _docker(fake):
        recon = ps.run_port_scan(_naabu_recon(), settings={**NAABU, **(settings or {})})
    return recon, started, fake


class TestNaabu:
    def test_regression_a_naabu_timeout_stops_its_container_and_keeps_the_ports_it_wrote(self):
        recon, (proc,), fake = _naabu(_naabu_proc(rows=[{"ip": A_IP, "port": 443}], cut=True))
        name = _name_of(proc.cmd)
        assert name.startswith(f"naabu-{RUN_ID}-")
        assert fake.kills == [["docker", "kill", name]]
        port_scan = recon["port_scan"]
        assert set(port_scan["by_host"]) == {A, A_IP}
        assert port_scan["by_host"][A]["ports"] == [443]
        meta = port_scan["scan_metadata"]
        assert meta["timed_out"] is True and meta["unchecked_targets"] == 2

    def test_regression_the_targets_naabu_never_reached_are_not_read_as_no_open_ports(self):
        _naabu(_naabu_proc(rows=[{"ip": A_IP, "port": 443}], cut=True))
        report = cb.coverage_report()
        # No port of theirs reached httpx, Nuclei or the port checks: every
        # source keeps what it found there before.
        for source in ("nuclei", "security_check", "http_probe", "nmap_nse"):
            assert set(report.keep_hostnames(source)) == {B, B_IP}
        (gap,) = [g for g in report.gaps if g["source"] == "naabu"]
        assert gap["module"] == "port_scan" and gap["hosts"] == 2
        assert "timed out" in gap["reason"]

    def test_regression_a_cut_scan_calls_no_port_closed(self):
        from recon.helpers.port_coverage import port_scan_coverage
        settings = {"NAABU_CUSTOM_PORTS": "443,8443"}
        recon, _, _ = _naabu(_naabu_proc(rows=[{"ip": A_IP, "port": 443}], cut=True),
                             settings=settings)
        covers = port_scan_coverage(recon, {**NAABU, **settings})
        assert covers(A_IP, 443) is True
        # Never looked at, or looked at and not open: a cut scan cannot tell.
        assert covers(B_IP, 443) is None and covers(A_IP, 8443) is None

    def test_a_timeout_with_nothing_written_is_no_port_data_and_a_coverage_gap(self):
        recon, (proc,), fake = _naabu(_naabu_proc(rows=None, cut=True))
        assert fake.kills == [["docker", "kill", _name_of(proc.cmd)]]
        # As a failed scan: httpx falls back to DNS and nmap's findings are kept
        # by the pipeline, so no host keep here.
        assert "port_scan" not in recon
        report = cb.coverage_report()
        assert report.keep_hostnames("nuclei") == ()
        (gap,) = [g for g in report.gaps if g["source"] == "naabu"]
        assert gap["skipped"] == 4 and "timed out" in gap["reason"]

    def test_a_syn_scan_that_times_out_does_not_start_a_connect_scan(self):
        _, started, fake = _naabu(_naabu_proc(rows=None, cut=True), settings={"NAABU_SCAN_TYPE": "s"})
        assert len(started) == 1 and len(fake.kills) == 1

    def test_a_finished_scan_is_the_same_command_plus_its_name_and_kills_nothing(self):
        recon, (proc,), fake = _naabu(_naabu_proc(rows=[{"ip": A_IP, "port": 443},
                                                        {"ip": B_IP, "port": 80}]))
        d = _mount(proc.cmd, "/targets")
        assert _without_name(proc.cmd) == ps.build_naabu_command(
            f"{d}/targets.txt", f"{d}/naabu_output.json", dict(NAABU))
        assert fake.kills == []
        assert not cb.coverage_report().degraded
        meta = recon["port_scan"]["scan_metadata"]
        assert "timed_out" not in meta and meta["ports_config"] == "top-1000"
