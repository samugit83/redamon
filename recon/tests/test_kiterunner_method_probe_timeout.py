"""Regression (R-9): Kiterunner's method probes left their httpx container running on a timeout.

`detect_kiterunner_methods` ran its OPTIONS and per-method httpx probes as
`subprocess.run(["docker", "run", "--rm", ...], timeout=300)`: the timeout
killed the docker CLI only, the unnamed container went on probing the target,
and what httpx had already written was thrown away. They now go through
`docker_helpers.run_tool_container`, which names the container and kills it by
that name, and the probe reads the output file httpx wrote before the kill.

Docker is a fake (`subprocess.run`); the helper and the probe run for real.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from unittest import mock

import pytest

from recon.helpers import circuit_breaker as cb
from recon.helpers.resource_enum import kiterunner_helpers as kr

RUN_ID = "5d1e2f3a-4b5c-4d6e-8f70-112233445566"
TOKEN = re.compile(r"^[a-z0-9_]{1,64}$")
API = "https://app.example.test/api/users"
ADMIN = "https://app.example.test/api/admin"


@pytest.fixture(autouse=True)
def _env(monkeypatch, tmp_path):
    monkeypatch.setenv("RECON_RUN_ID", RUN_ID)
    monkeypatch.delenv("PARTIAL_RECON_RUN_ID", raising=False)
    workdir = tmp_path / "kr_methods"
    workdir.mkdir()
    monkeypatch.setattr(kr, "_create_temp_dir", lambda prefix="kr": workdir)
    monkeypatch.setattr(kr, "_cleanup_temp_dir", lambda path: None)
    return workdir


class FakeDocker:
    """`subprocess.run` for docker: a `docker run` writes httpx's -o file, then answers or times out."""

    def __init__(self, workdir: Path, lines_by_method: dict, timeout_methods=()):
        self.workdir = workdir
        self.lines_by_method = lines_by_method
        self.timeout_methods = set(timeout_methods)
        self.calls = []

    def __call__(self, cmd, **kw):
        cmd = list(cmd)
        self.calls.append((cmd, kw))
        if cmd[:2] == ["docker", "kill"]:
            return subprocess.CompletedProcess(cmd, 0, "", "")
        method = cmd[cmd.index("-X") + 1]
        out = cmd[cmd.index("-o") + 1]
        assert out.startswith("/data/")
        (self.workdir / out[len("/data/"):]).write_text(self.lines_by_method.get(method, ""))
        if method in self.timeout_methods:
            raise subprocess.TimeoutExpired(cmd, kw.get("timeout"), output=b"", stderr=b"")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    @property
    def runs(self):
        return [c for c, _ in self.calls if c[:2] == ["docker", "run"]]

    @property
    def kills(self):
        return [c for c, _ in self.calls if c[:2] == ["docker", "kill"]]


def _name(cmd):
    assert "--name" in cmd, f"docker run has no --name, so nothing can stop it: {cmd}"
    return cmd[cmd.index("--name") + 1]


def _options_line(url, allow):
    return json.dumps({"url": url, "status_code": 200, "header": {"allow": allow}}) + "\n"


def _detect(mode="options", methods=("GET", "POST")):
    results = [{"url": API, "method": "GET"}, {"url": ADMIN, "method": "GET"}]
    return kr.detect_kiterunner_methods(results, "projectdiscovery/httpx:latest", True, mode,
                                        list(methods), 3, 5, 2)


def _kiterunner_gaps():
    return [g for g in cb.coverage_report().gaps if g["source"] == "kiterunner"]


def test_a_timed_out_options_probe_is_killed_by_name_and_its_partial_output_read(_env):
    # httpx answered for one endpoint, and was cut mid-line on the next.
    partial = _options_line(API, "GET, POST, DELETE") + '{"url": "' + ADMIN + '", "stat'
    docker = FakeDocker(_env, {"OPTIONS": partial}, timeout_methods={"OPTIONS"})
    with mock.patch("subprocess.run", side_effect=docker):
        out = _detect()

    (run,) = docker.runs
    name = _name(run)
    assert name.startswith(f"kiterunner-methods-{RUN_ID}-")
    assert docker.kills == [["docker", "kill", name]]
    assert run[run.index("-X") + 1] == "OPTIONS" and "--net=host" in run
    assert docker.calls[0][1]["timeout"] == 300

    assert out[API] == ["GET", "POST", "DELETE"]
    assert out[ADMIN] == ["GET"]
    (gap,) = _kiterunner_gaps()
    assert TOKEN.match(gap["source"]) and "timed out" in gap["reason"]
    report = cb.coverage_report()
    assert not report.degraded_sources and not report.skipped_hosts


def test_a_bruteforce_method_that_times_out_is_stopped_and_the_next_still_runs(_env):
    ok = json.dumps({"url": API, "status_code": 201}) + "\n"
    docker = FakeDocker(_env, {"GET": "", "POST": ok, "DELETE": ok},
                        timeout_methods={"POST"})
    with mock.patch("subprocess.run", side_effect=docker):
        out = _detect(mode="bruteforce", methods=("GET", "POST", "DELETE"))

    assert [r[r.index("-X") + 1] for r in docker.runs] == ["GET", "POST", "DELETE"]
    names = [_name(r) for r in docker.runs]
    assert len(set(names)) == 3
    assert docker.kills == [["docker", "kill", names[1]]]
    # POST was read from the cut-short run, DELETE from the one after it.
    assert out[API] == ["GET", "POST", "DELETE"]
    (gap,) = _kiterunner_gaps()
    assert "POST" in gap["reason"]


def test_a_probe_that_finishes_kills_nothing_and_notes_no_gap(_env):
    docker = FakeDocker(_env, {"OPTIONS": _options_line(ADMIN, "GET, PUT")})
    with mock.patch("subprocess.run", side_effect=docker):
        out = _detect()

    assert len(docker.runs) == 1 and docker.kills == []
    assert out[ADMIN] == ["GET", "PUT"] and out[API] == ["GET"]
    assert _kiterunner_gaps() == []


def test_no_docker_binary_is_logged_and_keeps_kiterunners_methods(_env):
    with mock.patch("subprocess.run", side_effect=FileNotFoundError("docker")):
        out = _detect()
    assert out == {API: ["GET"], ADMIN: ["GET"]}
