"""Regression (R-9, part B1): a tool's deadline stops its container, not just the docker CLI.

Killing the docker CLI, whether through `subprocess.run`'s timeout or a
streaming loop's `process.kill()`, leaves the daemon-owned container scanning
after the run has moved on. Every site below names its container, kills it by
that name when its deadline fires, and keeps what the tool printed before the
cut:

- through `docker_helpers.run_tool_container`: GAU and its two httpx probes,
  the jsluice verifier, subfinder, amass, puredns and its cleanup, uncover, and
  the ZAP Ajax Spider (named already, now through the helper);
- streaming loops (`tool_container_name` + `kill_container`): katana and
  hakrawler, on their deadline and on their URL cap;
- the TruffleHog sidecar already did both; it is pinned here with the rest.

Docker is a fake (`subprocess.run`, `subprocess.Popen`); the wrappers run for real.
"""
from __future__ import annotations

import io
import json
import shutil
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers import circuit_breaker as cb  # noqa: E402
from recon.helpers.js_recon import trufflehog_bridge  # noqa: E402
from recon.helpers.resource_enum import (  # noqa: E402
    gau_helpers, hakrawler_helpers, jsluice_helpers, katana_helpers, tool_health,
    zap_ajax_spider_helpers as zap,
)
from recon.main_recon_modules import domain_recon as dr  # noqa: E402
from recon.main_recon_modules import uncover_enrich  # noqa: E402

RUN_ID = "5d1c0b7a-2e4f-4a1b-9c3d-7e6f5a4b3c2d"
DOMAIN = "example.com"
A = f"app.{DOMAIN}"
U1, U2 = f"https://{A}/api/users", f"https://{A}/api/orders"
HTTPX_IMAGE = "projectdiscovery/httpx:latest"


@pytest.fixture(autouse=True)
def _run_env(monkeypatch):
    monkeypatch.setenv("RECON_RUN_ID", RUN_ID)
    monkeypatch.delenv("PARTIAL_RECON_RUN_ID", raising=False)
    tool_health.drain()
    yield
    tool_health.drain()


class FakeDocker:
    """`subprocess.run` for docker. Each `docker run` takes the next answer (the
    last one repeats); `docker kill` is recorded and calls ``on_kill``.

    An answer: ``write(argv)`` leaves files in a mounted dir first; ``timeout``
    raises TimeoutExpired carrying ``out`` (bytes, as run() hands back a cut
    run's output); otherwise exit ``rc`` with ``out`` as text.
    """

    def __init__(self, *answers, on_kill=None):
        self.answers = list(answers) or [{}]
        self.on_kill = on_kill
        self.calls = []

    def __call__(self, cmd, **kw):
        cmd = list(cmd)
        self.calls.append((cmd, kw))
        if cmd[:2] == ["docker", "kill"]:
            if self.on_kill:
                self.on_kill()
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if cmd[:2] != ["docker", "run"]:
            return subprocess.CompletedProcess(cmd, 0, "", "")
        answer = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        if answer.get("write"):
            answer["write"](cmd)
        if answer.get("timeout"):
            raise subprocess.TimeoutExpired(cmd, kw.get("timeout"), output=answer.get("out"))
        return subprocess.CompletedProcess(cmd, answer.get("rc", 0), answer.get("out", ""), "")

    @property
    def runs(self):
        return [c for c, _ in self.calls if c[:2] == ["docker", "run"]]

    @property
    def kills(self):
        return [c for c, _ in self.calls if c[:2] == ["docker", "kill"]]

    def run_name(self, i=0):
        cmd = self.runs[i]
        assert cmd.count("--name") == 1, f"docker run has no --name, so nothing can stop it: {cmd}"
        return cmd[cmd.index("--name") + 1]

    def assert_killed_by_name(self, *indexes, tool=None):
        names = [self.run_name(i) for i in indexes]
        assert self.kills == [["docker", "kill", n] for n in names]
        if tool:
            assert all(n.startswith(f"{tool}-{RUN_ID}-") for n in names), names


def _docker(fake):
    return mock.patch.object(subprocess, "run", side_effect=fake)


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


def _gaps(source_prefix):
    return [g for g in cb.coverage_report().gaps if g["source"].startswith(source_prefix)]


# ---------------------------------------------------------------------------
# GAU, and the httpx probes that verify its URLs and read their methods
# ---------------------------------------------------------------------------

GAU_IMAGE = "sxcurity/gau:latest"


class TestGau:
    def _gau(self, fake):
        with _docker(fake), mock.patch.object(gau_helpers, "_is_arm64_host", return_value=False):
            return gau_helpers._run_gau_docker(A, GAU_IMAGE, ["wayback", "otx"], 2, 45, ["png"],
                                               0, None, False, None)

    def test_regression_a_gau_timeout_stops_its_container_and_keeps_what_it_printed(self):
        # The last line is cut mid-URL by the kill: it is not a URL GAU found.
        out = f"https://{A}/one\nhttps://{A}/two?id=1\nhttps://{A}/thr".encode()
        fake = FakeDocker({"timeout": True, "out": out})
        assert self._gau(fake) == [f"https://{A}/one", f"https://{A}/two?id=1"]
        fake.assert_killed_by_name(0, tool="gau")
        assert fake.calls[0][1]["timeout"] == 45 * 2 + 120
        assert [(r.tool, r.verdict) for r in tool_health.drain()] == [("gau", tool_health.FAILURE)]

    def test_a_finished_gau_run_is_the_same_command_plus_its_name(self):
        fake = FakeDocker({"out": f"https://{A}/one\nhttps://{A}/logo.png\n"})
        assert self._gau(fake) == [f"https://{A}/one"]
        assert _without_name(fake.runs[0]) == [
            "docker", "run", "--rm", "--net=host", GAU_IMAGE, "--threads", "2", "--timeout", "45",
            "--providers", "wayback,otx", "--blacklist", "png", A]
        assert fake.kills == [] and tool_health.drain() == []

    def test_regression_a_verifier_timeout_stops_httpx_and_keeps_what_it_verified(self):
        def write(cmd):
            (_mount(cmd, "/data") / "verified.json").write_text(_jsonl({"url": U1, "status_code": 200}))

        fake = FakeDocker({"timeout": True, "write": write})
        with _docker(fake):
            assert gau_helpers.verify_gau_urls([U1, U2], HTTPX_IMAGE, 5, 10, 20, [200]) == {U1}
        fake.assert_killed_by_name(0, tool="gau-verify")
        assert fake.calls[0][1]["timeout"] == 300

    def test_regression_a_method_probe_timeout_keeps_the_methods_it_read(self):
        def write(cmd):
            (_mount(cmd, "/data") / "options_output.json").write_text(
                _jsonl({"url": U1, "status_code": 200, "header": {"allow": "GET, POST"}}))

        fake = FakeDocker({"timeout": True, "write": write})
        with _docker(fake):
            methods = gau_helpers.detect_gau_methods([U1, U2], HTTPX_IMAGE, 5, 10, 20, filter_dead=True)
        # U2 was never probed: kept, as GET, and no second run spends more time on it.
        assert methods == {U1: ["GET", "POST"], U2: ["GET"]}
        assert len(fake.runs) == 1
        fake.assert_killed_by_name(0, tool="gau-methods")

    def test_a_get_fallback_timeout_stops_its_container_and_keeps_every_unchecked_url(self):
        def write(cmd):
            (_mount(cmd, "/data") / "get_output.json").write_text(_jsonl({"url": U2, "status_code": 200}))

        fake = FakeDocker({}, {"timeout": True, "write": write})
        with _docker(fake):
            methods = gau_helpers.detect_gau_methods([U1, U2], HTTPX_IMAGE, 5, 10, 20, filter_dead=True)
        assert methods == {U1: ["GET"], U2: ["GET"]}
        assert len(fake.runs) == 2
        fake.assert_killed_by_name(1, tool="gau-methods")

    def test_finished_method_probes_drop_the_dead_url(self):
        def options(cmd):
            (_mount(cmd, "/data") / "options_output.json").write_text(
                _jsonl({"url": U1, "status_code": 200, "header": {"Allow": "GET, PUT"}}))

        def get(cmd):
            (_mount(cmd, "/data") / "get_output.json").write_text(_jsonl({"url": U2, "status_code": 404}))

        fake = FakeDocker({"write": options}, {"write": get})
        with _docker(fake):
            methods = gau_helpers.detect_gau_methods([U1, U2], HTTPX_IMAGE, 5, 10, 20, filter_dead=True)
        assert methods == {U1: ["GET", "PUT"]}
        assert fake.kills == []
        assert _without_name(fake.runs[1]) == [
            "docker", "run", "--rm", "--net=host", "-v", f"{_mount(fake.runs[1], '/data')}:/data",
            HTTPX_IMAGE, "-l", "/data/get_urls.txt", "-o", "/data/get_output.json", "-json",
            "-silent", "-nc", "-t", "5", "-timeout", "10", "-rl", "20"]


# ---------------------------------------------------------------------------
# The jsluice URL verifier
# ---------------------------------------------------------------------------

class TestJsluiceVerifier:
    def _verify(self, fake):
        with _docker(fake):
            return jsluice_helpers.verify_jsluice_urls([U1, U2], HTTPX_IMAGE, 5, 10, 20, [200])

    def test_regression_a_timeout_stops_httpx_and_publishes_only_what_it_verified(self):
        def write(cmd):
            (_mount(cmd, "/data") / "verified.json").write_text(_jsonl({"url": U1, "status_code": 200}))

        fake = FakeDocker({"timeout": True, "write": write})
        verified, stats = self._verify(fake)
        assert verified == {U1}
        assert (stats["jsluice_verified"], stats["jsluice_skipped_unverified"]) == (1, 1)
        fake.assert_killed_by_name(0, tool="jsluice-verify")
        gap, = _gaps("jsluice")
        assert "timed out" in gap["reason"] and gap["skipped"] == 1

    def test_a_timeout_with_nothing_verified_drops_every_url(self):
        verified, stats = self._verify(FakeDocker({"timeout": True}))
        assert verified == set() and stats["jsluice_skipped_unverified"] == 2
        gap, = _gaps("jsluice")
        assert gap["skipped"] == 2

    def test_a_failed_httpx_still_drops_every_url_and_kills_nothing(self):
        def write(cmd):
            (_mount(cmd, "/data") / "verified.json").write_text(_jsonl({"url": U1, "status_code": 200}))

        fake = FakeDocker({"rc": 2, "write": write})
        verified, stats = self._verify(fake)
        assert verified == set() and stats["jsluice_skipped_unverified"] == 2
        assert fake.kills == []
        assert _without_name(fake.runs[0])[:4] == ["docker", "run", "--rm", "--net=host"]


# ---------------------------------------------------------------------------
# Subdomain discovery: subfinder, amass, puredns
# ---------------------------------------------------------------------------

def _sources(fn, fake, *args, **settings):
    record = mock.MagicMock()
    with _docker(fake), mock.patch.object(dr, "_source_skipped", return_value=False), \
            mock.patch.object(dr, "_source_record", record):
        return fn(*args, settings=settings), record


class TestSubfinderAndAmass:
    def test_regression_a_subfinder_timeout_stops_it_and_keeps_the_names_it_printed(self):
        out = _jsonl({"host": f"a.{DOMAIN}"}, {"host": f"B.{DOMAIN}"}).encode() + b'{"host": "c.exa'
        fake = FakeDocker({"timeout": True, "out": out})
        found, record = _sources(dr.run_subfinder, fake, DOMAIN)
        assert found == {f"a.{DOMAIN}", f"b.{DOMAIN}"}
        fake.assert_killed_by_name(0, tool="subfinder")
        assert record.call_args_list == [mock.call("subfinder", cb.Outcome.TRANSIENT, detail="timeout")]

    def test_a_finished_subfinder_run_is_the_same_command_plus_its_name(self):
        fake = FakeDocker({"out": _jsonl({"host": f"a.{DOMAIN}"})})
        found, record = _sources(dr.run_subfinder, fake, DOMAIN)
        assert found == {f"a.{DOMAIN}"} and fake.kills == []
        assert _without_name(fake.runs[0]) == [
            "docker", "run", "--rm", "projectdiscovery/subfinder:latest", "-d", DOMAIN,
            "-json", "-silent", "-timeout", "30", "-max-time", "10"]
        assert fake.calls[0][1]["timeout"] == 720
        assert record.call_args_list == [mock.call("subfinder", cb.Outcome.OK)]

    def test_regression_an_amass_timeout_stops_it_and_keeps_the_names_it_printed(self):
        out = (f"a.{DOMAIN} (FQDN) --> a_record --> 192.0.2.1 (IPAddress)\n"
               f"b.{DOMAIN} (FQDN) --> cname_record --> c.{DOMAIN} (FQDN)\n"
               f"d.exa").encode()
        fake = FakeDocker({"timeout": True, "out": out})
        found, record = _sources(dr.run_amass, fake, DOMAIN, AMASS_ENABLED=True, AMASS_TIMEOUT=3)
        assert found == {f"a.{DOMAIN}", f"b.{DOMAIN}", f"c.{DOMAIN}"}
        fake.assert_killed_by_name(0, tool="amass")
        assert fake.calls[0][1]["timeout"] == 3 * 60 + 120
        assert record.call_args_list == [mock.call("amass", cb.Outcome.TRANSIENT, detail="timeout")]

    def test_a_finished_amass_run_is_the_same_command_plus_its_name(self):
        fake = FakeDocker({"out": f"a.{DOMAIN} (FQDN) --> a_record --> 192.0.2.1 (IPAddress)\n"})
        found, _ = _sources(dr.run_amass, fake, DOMAIN, AMASS_ENABLED=True)
        cmd = _without_name(fake.runs[0])
        assert found == {f"a.{DOMAIN}"} and fake.kills == []
        assert cmd[:4] == ["docker", "run", "--rm", "-v"]
        assert cmd[4].startswith("/tmp/redamon/.amass_temp_") and cmd[4].endswith(":/root/.config/amass")
        assert cmd[5:] == ["caffix/amass:latest", "enum", "-d", DOMAIN, "-timeout", "10"]


@pytest.fixture
def resolvers():
    shared = Path("/tmp/redamon/resolvers.txt")
    shared.parent.mkdir(parents=True, exist_ok=True)
    if not shared.exists():
        shared.write_text("192.0.2.53\n")
    yield
    for f in Path("/tmp/redamon").glob(f"puredns_*_{DOMAIN}_*.txt"):
        f.unlink(missing_ok=True)


SUBS = [f"a.{DOMAIN}", f"b.{DOMAIN}", f"c.{DOMAIN}"]


def _puredns_output(names):
    def write(cmd):
        out = Path("/tmp/redamon") / Path(cmd[cmd.index("--write") + 1]).name
        out.write_text("".join(n + "\n" for n in names))
    return write


class TestPuredns:
    def test_regression_a_puredns_timeout_stops_it_and_filters_nothing(self, resolvers):
        # puredns writes its list as it goes: a cut-short list would drop every
        # name it had not reached yet, so none of it is used.
        fake = FakeDocker({"timeout": True, "write": _puredns_output(SUBS[:1])})
        (names, status), record = _sources(dr.run_puredns_resolve, fake, list(SUBS), DOMAIN,
                                           PUREDNS_ENABLED=True)
        assert (names, status) == (SUBS, "skipped:timeout")
        fake.assert_killed_by_name(0, tool="puredns")
        assert record.call_args_list == [mock.call("puredns", cb.Outcome.TRANSIENT, detail="timeout")]
        gap, = _gaps("puredns")
        assert "timed out" in gap["reason"] and gap["skipped"] == 3

    def test_a_finished_puredns_run_is_the_same_command_plus_its_name(self, resolvers):
        fake = FakeDocker({"write": _puredns_output(SUBS[:2])})
        (names, status), _ = _sources(dr.run_puredns_resolve, fake, list(SUBS), DOMAIN,
                                      PUREDNS_ENABLED=True)
        assert (names, status) == (SUBS[:2], "filtered") and fake.kills == []
        cmd = _without_name(fake.runs[0])
        inp, out = cmd[cmd.index("resolve") + 1], cmd[cmd.index("--write") + 1]
        assert inp.startswith(f"/data/puredns_input_{DOMAIN}_") and out.startswith(f"/data/puredns_output_{DOMAIN}_")
        assert cmd == ["docker", "run", "--rm", "-v", "/tmp/redamon:/data", "frost19k/puredns:latest",
                       "resolve", inp, "-r", "/data/resolvers.txt", "--write", out, "-q"]
        assert fake.calls[0][1]["timeout"] == 600

    def test_a_hung_cleanup_container_is_stopped_by_its_name(self, resolvers):
        # Files the puredns container wrote as root are removed by an alpine
        # container, bounded at 60 s like any other.
        fake = FakeDocker({"write": _puredns_output(SUBS)}, {"timeout": True})
        with mock.patch.object(dr.Path, "unlink", side_effect=PermissionError("root-owned")):
            (names, _), _ = _sources(dr.run_puredns_resolve, fake, list(SUBS), DOMAIN,
                                     PUREDNS_ENABLED=True)
        assert names == SUBS
        cleanups = fake.runs[1:]
        assert [_without_name(c)[:-1] for c in cleanups] == [
            ["docker", "run", "--rm", "-v", "/tmp/redamon:/cleanup", "alpine", "rm", "-f"]] * 2
        assert sorted(c[-1].split("_")[1] for c in cleanups) == ["input", "output"]
        fake.assert_killed_by_name(1, 2)
        assert all(kw["timeout"] == 60 for c, kw in fake.calls[1:] if c[:2] == ["docker", "run"])


# ---------------------------------------------------------------------------
# uncover
# ---------------------------------------------------------------------------

class TestUncover:
    def _uncover(self, fake):
        temp = Path(tempfile.mkdtemp(prefix="redamon_uncover_t_", dir="/tmp/redamon"))
        try:
            with _docker(fake):
                return uncover_enrich._run_uncover_docker(
                    [DOMAIN], ["shodan"], str(temp / "provider-config.yaml"), 100, str(temp))
        finally:
            shutil.rmtree(temp, ignore_errors=True)

    ROW = {"ip": "192.0.2.10", "port": 443, "host": f"www.{DOMAIN}", "source": "shodan"}

    def test_regression_an_uncover_timeout_stops_it_keeps_its_rows_and_says_so(self):
        def write(cmd):
            (_mount(cmd, "/output") / "uncover_output.jsonl").write_text(_jsonl(self.ROW))

        fake = FakeDocker({"timeout": True, "write": write})
        assert self._uncover(fake) == [self.ROW]
        fake.assert_killed_by_name(0, tool="uncover")
        gap, = _gaps("uncover")
        assert f"timed out after {uncover_enrich.UNCOVER_TIMEOUT}s" in gap["reason"]

    def test_a_finished_uncover_run_is_the_same_command_plus_its_name(self):
        fake = FakeDocker({"out": _jsonl(self.ROW)})
        assert self._uncover(fake) == [self.ROW]
        cmd = _without_name(fake.runs[0])
        temp = _mount(cmd, "/output")
        assert cmd == [
            "docker", "run", "--rm", "-v", f"{temp}:/config:ro", "-v", f"{temp}:/output",
            uncover_enrich.UNCOVER_DOCKER_IMAGE_DEFAULT, "-pc", "/config/provider-config.yaml",
            "-e", "shodan", "-json", "-silent", "-l", "100", "-timeout", "60",
            "-o", "/output/uncover_output.jsonl", "-q", DOMAIN]
        assert fake.kills == [] and _gaps("uncover") == []


# ---------------------------------------------------------------------------
# ZAP Ajax Spider (named already; now through the helper)
# ---------------------------------------------------------------------------

def test_a_timed_out_zap_seed_is_stopped_by_its_name_and_its_export_is_kept():
    def write(cmd):
        (_mount(cmd, "/zap/wrk") / "zap_ajax_urls_0.txt").write_text(f"https://{A}/app/dashboard\n")

    fake = FakeDocker({"timeout": True, "write": write})
    with _docker(fake):
        urls, meta = zap.run_zap_ajax_spider(
            target_urls=[f"https://{A}/"], docker_image="ghcr.io/zaproxy/zaproxy:stable",
            allowed_hosts=[A], custom_headers=[], exclude_patterns=[], max_urls=1000,
            max_duration=10, max_crawl_depth=5, max_crawl_states=0, number_of_browsers=1,
            browser_id="firefox-headless", event_wait=1000, reload_wait=1000,
            click_default_elems=True, click_elems_once=True, random_inputs=False,
            logout_avoidance=True, scope_check="Strict", parallelism=1)
    fake.assert_killed_by_name(0)
    assert f"https://{A}/app/dashboard" in urls
    assert meta["seeds_failed"] == 1 and meta["errors"][0]["type"] == "timeout"


# ---------------------------------------------------------------------------
# Streaming crawlers: katana, hakrawler
# ---------------------------------------------------------------------------

class _StreamProc:
    """A Popen that prints `lines`, then stays alive and silent until killed."""

    def __init__(self, lines):
        self.lines = [line + "\n" for line in lines]
        self.cmd = None
        self.killed = threading.Event()
        self.returncode = None
        self.stdin = mock.MagicMock()
        self.stdout = mock.MagicMock()
        self.stdout.readline.side_effect = self._readline
        self.stderr = io.StringIO("")

    def _readline(self):
        if self.lines:
            return self.lines.pop(0)
        self.killed.wait(timeout=10)
        return ""

    def poll(self):
        if self.killed.is_set():
            self.returncode = -9
        return self.returncode

    def kill(self):
        self.killed.set()

    def wait(self, timeout=None):
        return self.poll()


def _popen(proc):
    def popen(cmd, **_kw):
        proc.cmd = list(cmd)
        return proc
    return mock.patch.object(subprocess, "Popen", side_effect=popen)


class TestKatana:
    def _crawl(self, proc, fake, max_urls=100):
        clock = {"t": 1000.0}

        def select(rlist, _w, _x, _timeout):
            if proc.lines:
                return rlist, [], []
            clock["t"] += 600  # a silent poll: the crawl's deadline passes
            return [], [], []

        with _popen(proc), _docker(fake), \
                mock.patch.object(katana_helpers.select, "select", side_effect=select), \
                mock.patch.object(katana_helpers, "time", SimpleNamespace(time=lambda: clock["t"])), \
                mock.patch("helpers.proxy_routing.get_capture_routing", return_value=(None, None),
                           create=True):
            return katana_helpers.run_katana_crawler(
                target_urls=[f"https://{A}"], docker_image="projectdiscovery/katana:latest",
                depth=2, max_urls=max_urls, rate_limit=10, timeout=30, js_crawl=False,
                params_only=False, allowed_hosts={A}, custom_headers=[], exclude_patterns=[])

    def _name(self, proc):
        assert proc.cmd.count("--name") == 1, proc.cmd
        return proc.cmd[proc.cmd.index("--name") + 1]

    def test_regression_a_katana_deadline_stops_its_container_and_keeps_its_urls(self, capsys):
        proc = _StreamProc([U1])
        fake = FakeDocker()
        urls, meta = self._crawl(proc, fake)
        assert urls == [U1] and not meta["failed"]
        assert "Overall timeout" in capsys.readouterr().out
        assert proc.killed.is_set()
        assert fake.kills == [["docker", "kill", self._name(proc)]]
        assert self._name(proc).startswith(f"katana-{RUN_ID}-")

    def test_the_url_cap_stops_the_container_too(self):
        proc = _StreamProc([U1, U2])
        fake = FakeDocker()
        urls, _ = self._crawl(proc, fake, max_urls=1)
        assert urls == [U1]
        assert fake.kills == [["docker", "kill", self._name(proc)]]

    def test_a_crawl_that_ends_by_itself_is_not_killed(self):
        proc = _StreamProc([U1])
        proc.lines.append("")  # EOF: katana exited on its own
        proc.returncode = 0
        fake = FakeDocker()
        urls, _ = self._crawl(proc, fake)
        assert urls == [U1] and fake.kills == [] and not proc.killed.is_set()
        assert proc.cmd[:6] == ["docker", "run", "--rm", "--net=host", "--name", self._name(proc)]


class TestHakrawler:
    def _crawl(self, proc, fake, max_urls=500):
        with _popen(proc), _docker(fake), \
                mock.patch.object(hakrawler_helpers, "per_url_budget", return_value=0.3):
            return hakrawler_helpers.run_hakrawler_crawler(
                target_urls=[f"https://{A}"], docker_image="jauderho/hakrawler:latest", depth=2,
                threads=5, timeout=30, max_urls=max_urls, include_subs=False, insecure=True,
                allowed_hosts={A}, custom_headers=[], exclude_patterns=[], parallelism=1)

    def _name(self, proc):
        assert proc.cmd.count("--name") == 1, proc.cmd
        return proc.cmd[proc.cmd.index("--name") + 1]

    def test_regression_a_hakrawler_watchdog_stops_its_container_and_keeps_its_urls(self, capsys):
        proc = _StreamProc([U1])
        fake = FakeDocker()
        try:
            urls, _ = self._crawl(proc, fake)
        finally:
            proc.kill()
        assert urls == [U1]
        assert "Overall timeout" in capsys.readouterr().out
        assert fake.kills == [["docker", "kill", self._name(proc)]]
        assert self._name(proc).startswith(f"hakrawler-{RUN_ID}-")

    def test_the_url_cap_stops_the_container_too(self):
        proc = _StreamProc([U1, U2])
        fake = FakeDocker()
        try:
            urls, _ = self._crawl(proc, fake, max_urls=1)
        finally:
            proc.kill()
        assert urls == [U1]
        assert fake.kills == [["docker", "kill", self._name(proc)]]

    def test_a_crawl_that_ends_by_itself_is_not_killed(self):
        proc = _StreamProc([U1])
        proc.lines.append("")
        proc.returncode = 0
        fake = FakeDocker()
        urls, _ = self._crawl(proc, fake)
        assert urls == [U1] and fake.kills == [] and not proc.killed.is_set()
        assert proc.cmd[:5] == ["docker", "run", "--rm", "--net=host", "-i"]


# ---------------------------------------------------------------------------
# TruffleHog sidecar (already named and killed on its budget: pinned)
# ---------------------------------------------------------------------------

class _SidecarProc:
    def __init__(self, stdout):
        self.stdout = io.StringIO(stdout)
        self.stderr = io.StringIO("")
        self.returncode = None
        self.killed = False

    def poll(self):
        if self.killed:
            self.returncode = 137
        return self.returncode

    def wait(self, timeout=None):
        return self.poll()


def test_a_spent_trufflehog_budget_stops_the_sidecar_by_its_name_and_keeps_its_results():
    name = trufflehog_bridge.container_name(RUN_ID)
    argv = trufflehog_bridge.build_argv("/tmp/redamon/th_stage", verify=False, concurrency=2,
                                        validation_timeout=5, name=name, memory="1073741824")
    row = {"DetectorName": "Generic", "Verified": False, "Raw": "synthetic-value-0001",
           "SourceMetadata": {"Data": {"Filesystem": {"file": "/scan/0001.js", "line": 1}}}}
    proc = _SidecarProc(_jsonl(row))
    fake = FakeDocker(on_kill=lambda: setattr(proc, "killed", True))
    clock = SimpleNamespace(t=0.0)

    def sleep(_s):
        clock.t += 2.0

    with _docker(fake), mock.patch.object(subprocess, "Popen", return_value=proc), \
            mock.patch.object(trufflehog_bridge, "_stop_requested", return_value=False):
        side = trufflehog_bridge.run_sidecar(argv, name=name, budget_s=8, clock=lambda: clock.t,
                                             sleep=sleep)
    assert side.status == "timed_out"
    assert fake.kills == [["docker", "kill", argv[argv.index("--name") + 1]]]
    results, bad = trufflehog_bridge.parse_ndjson(side.stdout)
    assert [r.raw for r in results] == ["synthetic-value-0001"] and bad == 0
