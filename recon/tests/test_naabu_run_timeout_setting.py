"""naabu's run timeout is the project setting naabuRunTimeout (R-9).

run_port_scan reads the naabu docker CLI through `communicate(timeout=...)`
and, when that deadline fires, kills the container by its name. The deadline
was a hardcoded 1800 s; it is now NAABU_RUN_TIMEOUT, whose default (Prisma,
DEFAULT_SETTINGS and the module's own fallback) is the same 1800 s, so a project
that never set it runs exactly as before.

Docker is a fake (`subprocess.run`, `subprocess.Popen`); the module runs for
real. Reserved names and documentation ranges only.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers import circuit_breaker as cb  # noqa: E402
from recon.main_recon_modules import port_scan as ps  # noqa: E402

RUN_ID = "0f3c9a51-6b2d-4e8a-9c71-2d4b6e8f0a13"
A, A_IP = "a.example.test", "192.0.2.10"
B, B_IP = "b.example.test", "192.0.2.20"


@pytest.fixture(autouse=True)
def _run_env(monkeypatch):
    monkeypatch.setenv("RECON_RUN_ID", RUN_ID)
    monkeypatch.delenv("PARTIAL_RECON_RUN_ID", raising=False)
    cb.reset_registry()
    yield
    cb.reset_registry()


class _CliProc:
    """subprocess.Popen for the naabu docker CLI: records the timeout each
    communicate() is handed, and raises TimeoutExpired on the first one when
    the run is ``cut``."""

    def __init__(self, cmd, cut):
        self.cmd, self.cut = list(cmd), cut
        self.timeouts = []
        self.returncode = None if cut else 0

    def communicate(self, input=None, timeout=None):
        self.timeouts.append(timeout)
        if self.cut and len(self.timeouts) == 1:
            raise subprocess.TimeoutExpired(self.cmd, timeout)
        return "", ""

    def kill(self):
        self.returncode = -9

    def wait(self, timeout=None):
        return self.returncode

    def poll(self):
        return self.returncode


def _output_path(cmd):
    for flag, spec in zip(cmd, cmd[1:]):
        if flag == "-v" and spec.split(":")[1] == "/output":
            return Path(spec.split(":")[0]) / Path(cmd[cmd.index("-o") + 1]).name
    raise AssertionError(f"no /output mount in {cmd}")


def _recon():
    return {"domain": "example.test",
            "dns": {"domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
                    "subdomains": {A: {"has_records": True, "ips": {"ipv4": [A_IP], "ipv6": []}},
                                   B: {"has_records": True, "ips": {"ipv4": [B_IP], "ipv6": []}}}}}


def _run(settings, *, cut=False):
    """run_port_scan on two names; naabu writes one open port (A_IP:443)."""
    started = []
    kills = []

    def popen(cmd, **_kw):
        cmd = list(cmd)
        _output_path(cmd).write_text(json.dumps({"ip": A_IP, "port": 443}) + "\n")
        started.append(_CliProc(cmd, cut))
        return started[-1]

    def run(cmd, **_kw):
        cmd = list(cmd)
        if cmd[:2] == ["docker", "kill"]:
            kills.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    with mock.patch.object(ps, "is_docker_installed", return_value=True), \
         mock.patch.object(ps, "is_docker_running", return_value=True), \
         mock.patch.object(ps, "pull_naabu_docker_image", return_value=True), \
         mock.patch.object(subprocess, "Popen", side_effect=popen), \
         mock.patch.object(subprocess, "run", side_effect=run):
        recon = ps.run_port_scan(_recon(), settings={"NAABU_SCAN_TYPE": "c", **settings})
    return recon, started, kills


def test_regression_run_port_scan_waits_for_naabu_as_long_as_the_setting_says():
    recon, (proc,), kills = _run({"NAABU_RUN_TIMEOUT": 600})
    assert proc.timeouts == [600]
    assert kills == []
    assert recon["port_scan"]["by_host"][A]["ports"] == [443]


def test_without_the_setting_the_run_timeout_is_1800_seconds():
    _, (proc,), _ = _run({})
    assert proc.timeouts[0] == 1800


def test_a_run_cut_at_the_set_timeout_kills_its_container_and_says_so():
    recon, (proc,), kills = _run({"NAABU_RUN_TIMEOUT": 45}, cut=True)
    assert proc.timeouts[0] == 45
    name = proc.cmd[proc.cmd.index("--name") + 1]
    assert kills == [["docker", "kill", name]]
    assert recon["port_scan"]["scan_metadata"]["timed_out"] is True
    (gap,) = [g for g in cb.coverage_report().gaps if g["source"] == "naabu"]
    assert gap["reason"] == "naabu timed out after 45s"


@pytest.mark.parametrize("row, expected", [({}, 1800), ({"naabuRunTimeout": 600}, 600)])
def test_the_project_column_reaches_the_scan_settings(row, expected):
    """The Prisma column is fetched under NAABU_RUN_TIMEOUT, through the same
    get_settings path a scan takes (fetch, stealth, AI overrides, RoE cap)."""
    from recon import project_settings
    from recon.tests.golden_settings import cases
    from recon.tests.golden_settings_runner import resolve

    assert project_settings.DEFAULT_SETTINGS["NAABU_RUN_TIMEOUT"] == 1800
    base = {k: v for k, v in cases()["all_defaults"].items() if k != "naabuRunTimeout"}
    assert resolve({**base, **row})["NAABU_RUN_TIMEOUT"] == expected
