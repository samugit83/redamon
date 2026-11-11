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


# ---------------------------------------------------------------------------
# tlsx (tls_scan.run_tlsx_enrichment)
# ---------------------------------------------------------------------------

TLS_LINES = [f"{A_IP}:993", f"{B_IP}:636"]
TLS_META = {f"{A_IP}:993": A_IP, f"{B_IP}:636": B_IP}
TLS_ROW = {"host": A_IP, "ip": A_IP, "port": "993", "probe_status": True, "tls_version": "tls12",
           "subject_cn": A, "subject_an": [A], "not_after": "2099-01-01T00:00:00Z",
           "fingerprint_hash": {"sha256": "ab" * 32}}


def _tlsx(monkeypatch, *steps, settings=None):
    started = []

    def popen(cmd, **_kw):
        started.append(CliProc(cmd, *steps))
        return started[-1]

    monkeypatch.setattr(tls_scan, "_build_tlsx_targets",
                        lambda combined, s: (list(TLS_LINES), dict(TLS_META)))
    fake = FakeDocker()
    with mock.patch.object(subprocess, "Popen", side_effect=popen), _docker(fake):
        out = tls_scan.run_tlsx_enrichment({"metadata": {}, "port_scan": {"by_ip": {}, "by_host": {}}},
                                           settings or {})
    return out, started, fake


class TestTlsx:
    def test_regression_a_tlsx_timeout_stops_its_container(self, monkeypatch):
        out, (proc,), fake = _tlsx(monkeypatch, subprocess.TimeoutExpired("docker", 5),
                                   (_jsonl(TLS_ROW), ""), settings={"TLSX_RUN_TIMEOUT": 5})
        name = _name_of(proc.cmd)
        assert name.startswith(f"tlsx-{RUN_ID}-")
        assert fake.kills == [["docker", "kill", name]]
        # R-21 unchanged: the row printed before the cut is kept, the other
        # target is kept "not checked".
        assert f"{A_IP}:993" in out["tlsx"]["by_target"]
        meta = out["tlsx"]["scan_metadata"]
        assert meta["timed_out"] is True and meta["unchecked_targets"] == 1

    def test_a_finished_tlsx_run_is_the_same_command_plus_its_name(self, monkeypatch):
        out, (proc,), fake = _tlsx(monkeypatch, (_jsonl(TLS_ROW), ""))
        targets_file = proc.cmd[proc.cmd.index("-l") + 1]
        assert _without_name(proc.cmd) == tls_scan.build_tlsx_command(
            targets_file, str(Path(targets_file).parent), {})
        assert fake.kills == []
        assert "timed_out" not in out["tlsx"]["scan_metadata"]


# ---------------------------------------------------------------------------
# Nuclei
# ---------------------------------------------------------------------------

NUCLEI_ROW = {"template-id": "github-takeover", "matched-at": f"https://{A}/",
              "info": {"name": "github-takeover", "severity": "high", "tags": ["takeover"]}}


class TestNucleiTakeover:
    def _run(self, tmp_path, answer):
        fake = FakeDocker(answer)
        with mock.patch.object(st, "is_docker_installed", return_value=True), \
             mock.patch.object(st, "is_docker_running", return_value=True), \
             mock.patch.object(st, "pull_nuclei_docker_image", return_value=True), \
             mock.patch.object(st, "ensure_templates_volume", return_value=True), \
             mock.patch.object(st, "fix_file_ownership"), _docker(fake):
            rows = st._run_nuclei_takeover([f"https://{A}"], tmp_path,
                                           {"NUCLEI_TAKEOVER_RUN_TIMEOUT": 300})
        return rows, fake

    def test_a_takeover_timeout_kills_the_container_it_named_and_keeps_its_rows(self, tmp_path):
        def answer(cmd, kw):
            (_mount(cmd, "/output") / "nuclei_takeover_output.jsonl").write_text(_jsonl(NUCLEI_ROW))
            raise subprocess.TimeoutExpired(cmd, kw["timeout"])

        rows, fake = self._run(tmp_path, answer)
        ((cmd, kw),) = fake.runs("http/takeovers/")
        assert kw["timeout"] == 300
        assert fake.kills == [["docker", "kill", _name_of(cmd)]]
        assert _name_of(cmd).startswith("redamon-nuclei-takeover-")
        assert [r["template-id"] for r in rows] == ["github-takeover"]
        assert A in cb.coverage_report().keep_hostnames("takeover_scan")

    def test_a_finished_takeover_run_kills_nothing(self, tmp_path):
        rows, fake = self._run(tmp_path, lambda cmd, kw: subprocess.CompletedProcess(cmd, 0, "", ""))
        assert rows == [] and fake.kills == []
        assert not cb.coverage_report().degraded


class TestNucleiVulnScanPass:
    def test_the_runtime_cap_kills_the_container_by_the_name_in_its_command(self, tmp_path):
        killed = threading.Event()
        fake = FakeDocker()
        fake_kill = fake.__call__

        def run(cmd, **kw):
            result = fake_kill(cmd, **kw)
            if list(cmd)[:2] == ["docker", "kill"]:
                killed.set()
            return result

        class _Streaming:
            returncode = None

            def __init__(self, cmd, **_kw):
                self.cmd = list(cmd)

            @property
            def stdout(self):
                yield "[INF] running"
                killed.wait(timeout=5)
                self.returncode = 137

            def wait(self, timeout=None):
                return self.returncode

        started = []
        out = tmp_path / "nuclei_detection.jsonl"
        out.write_text(_jsonl({"template-id": "x", "matched-at": f"https://{A}",
                               "info": {"severity": "low"}}))
        name = "redamon-nuclei-detection-abc123"
        cmd = ["docker", "run", "--rm", "--net=host", "--name", name, "projectdiscovery/nuclei:latest"]
        with mock.patch.object(subprocess, "Popen",
                               side_effect=lambda c, **k: started.append(_Streaming(c)) or started[-1]), \
                mock.patch.object(subprocess, "run", side_effect=run):
            findings, _, _, _ = vs._execute_nuclei_pass(cmd, str(out), label="DETECTION",
                                                        runtime_cap=0.2, container_name=name)
        assert fake.kills == [["docker", "kill", name]]
        assert len(findings) == 1
        assert cb.coverage_report().nuclei_truncated is True


class TestNucleiCleanup:
    def test_regression_the_root_owned_file_cleanup_is_named_bounded_and_stopped(self, monkeypatch):
        real_unlink = Path.unlink

        def unlink(self, *a, **k):
            if ".nuclei_temp_" in str(self):
                raise PermissionError(13, "root-owned")
            return real_unlink(self, *a, **k)

        def answer(cmd, kw):
            raise subprocess.TimeoutExpired(cmd, kw.get("timeout"))

        fake = FakeDocker(answer)
        recon = {"domain": "example.test", "metadata": {"include_root_domain": True},
                 "dns": {"domain": {"ips": {"ipv4": [A_IP], "ipv6": []}, "has_records": True},
                         "subdomains": {}},
                 "http_probe": {"by_url": {f"https://{A}": {"url": f"https://{A}", "status_code": 200}}}}
        monkeypatch.setattr(Path, "unlink", unlink)
        with mock.patch.object(vs, "is_docker_installed", return_value=True), \
             mock.patch.object(vs, "is_docker_running", return_value=True), \
             mock.patch.object(vs, "pull_nuclei_docker_image", return_value=True), \
             mock.patch.object(vs, "ensure_templates_volume", return_value=True), \
             mock.patch.object(vs, "_execute_nuclei_pass", return_value=([], [], 1.0, 0)), \
             _docker(fake):
            out = vs.run_vuln_scan(recon, settings={
                "NUCLEI_ENABLED": True, "NUCLEI_TAGS": ["cve"], "NUCLEI_MAX_RUNTIME": 0,
                "CVE_LOOKUP_ENABLED": False, "SECURITY_CHECK_ENABLED": False})
        cleanups = fake.runs("alpine")
        assert cleanups, "no root-owned file was cleaned up"
        for cmd, kw in cleanups:
            assert kw.get("timeout"), f"the cleanup has no timeout: {cmd}"
        assert fake.kills == [["docker", "kill", _name_of(c)] for c, _ in cleanups]
        assert "vuln_scan" in out


# ---------------------------------------------------------------------------
# The nuclei-templates volume (docker_helpers.ensure_templates_volume)
# ---------------------------------------------------------------------------

class TestTemplatesVolume:
    def _ensure(self, answer, auto_update=False):
        def run(cmd, kw):
            if cmd[:3] == ["docker", "volume", "inspect"]:
                return subprocess.CompletedProcess(cmd, 0, "", "")
            return answer(cmd, kw)

        fake = FakeDocker(run)
        with _docker(fake):
            ok = docker_helpers.ensure_templates_volume("projectdiscovery/nuclei:latest", auto_update)
        return ok, fake

    def test_regression_a_template_count_timeout_stops_its_container(self):
        def answer(cmd, kw):
            raise subprocess.TimeoutExpired(cmd, kw["timeout"])

        ok, fake = self._ensure(answer)
        assert ok is False
        ((cmd, kw),) = fake.runs("alpine")
        assert kw["timeout"] == 30
        assert fake.kills == [["docker", "kill", _name_of(cmd)]]

    def test_an_update_timeout_still_kills_the_updater_by_its_name(self):
        def answer(cmd, kw):
            if "-ut" in cmd:
                raise subprocess.TimeoutExpired(cmd, kw["timeout"])
            return subprocess.CompletedProcess(cmd, 0, "5\n", "")

        ok, fake = self._ensure(answer, auto_update=True)
        assert ok is False
        ((cmd, kw),) = fake.runs("-ut")
        assert kw["timeout"] == 600
        assert _name_of(cmd).startswith("redamon-nuclei-update-")
        assert fake.kills == [["docker", "kill", _name_of(cmd)]]

    def test_a_healthy_volume_kills_nothing(self):
        ok, fake = self._ensure(lambda cmd, kw: subprocess.CompletedProcess(cmd, 0, "5\n", ""))
        assert ok is True and fake.kills == []


# ---------------------------------------------------------------------------
# httpx (http_probe.run_http_probe): named and killed already; pinned
# ---------------------------------------------------------------------------

class TestHttpx:
    def test_the_budget_kills_the_container_by_the_name_in_its_command(self):
        started = []

        def popen(cmd, **_kw):
            cmd = list(cmd)
            (_mount(cmd, "/output") / "httpx_output.json").write_text(
                _jsonl({"url": f"https://{A}", "input": f"https://{A}", "status_code": 200,
                        "host": A_IP}))
            started.append(CliProc(cmd, subprocess.TimeoutExpired(cmd, 60), ("", ""),
                                   returncode=None))
            return started[-1]

        fake = FakeDocker()
        recon = {"domain": "example.test", "metadata": {"include_root_domain": True},
                 "dns": {"domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
                         "subdomains": {}},
                 "port_scan": {"by_host": {A: {"host": A, "ip": A_IP, "ports": [443],
                                               "port_details": [{"port": 443, "service": "https"}]}},
                               "by_ip": {}}}
        with mock.patch.object(hp, "is_docker_installed", return_value=True), \
             mock.patch.object(hp, "is_docker_running", return_value=True), \
             mock.patch.object(hp, "pull_httpx_docker_image", return_value=True), \
             mock.patch.object(subprocess, "Popen", side_effect=popen), _docker(fake):
            hp.run_http_probe(recon, output_file=None, settings={"BANNER_GRAB_ENABLED": False,
                                                                 "WAPPALYZER_ENABLED": False})
        (proc,) = started
        assert fake.kills == [["docker", "kill", _name_of(proc.cmd)]]
        assert "http_probe" in cb.coverage_report().degraded_sources
