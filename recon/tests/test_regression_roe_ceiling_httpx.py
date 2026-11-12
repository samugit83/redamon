"""Regression: httpx and the banner grab ran over the RoE ceiling (R-8, B-R8c).

The FP lab run with a 2 rps ceiling saw 4-5 requests a second from the HTTP
probe phase: httpx's GET / and /favicon.ico, and connections to the Redis,
SMTP and TLS-mail ports.

- httpx got only ``-rl <ceiling>`` next to ``-t 50 -retries 2``. httpx v1.12
  counts -rl in fixed one-second windows (projectdiscovery/ratelimit), so two
  windows' worth can land within one second, and only its main request takes a
  token: retries, redirect hops, the favicon fetch and JARM's handshakes take
  none. Under a ceiling C the command now runs one URL at a time (``-t 1``),
  with no retries, ``-rl`` at half the ceiling (at least 1), a dispatch delay
  of 2/C seconds and no favicon or JARM probe. Measured on a loopback lab at
  C = 2: 7 connections in the busiest second before (11 seconds over 2), 2
  after (none over); keeping favicon and JARM would have left 3.
- The run says JARM and favicon were not collected, in its log and as a
  coverage gap (sources ``httpx_jarm``, ``httpx_favicon``), so a missing hash
  reads as "not checked" rather than "none". The graph writers skip absent
  values, so the hashes an earlier run stored stay; the root test
  tests/test_regression_roe_ceiling_httpx_writer.py (agent image) pins that.
- The banner grab (in-process raw sockets, 20 threads) took no slot of recon's
  request clock. Every connection it opens now takes one.

With no ceiling every httpx argv, domain and IP mode, is byte-identical to the
one built before, and the banner grab never touches the clock.
"""
from __future__ import annotations

import copy
import sys
import threading
from pathlib import Path
from unittest import mock

import pytest

_RECON = Path(__file__).resolve().parent.parent
_REPO = _RECON.parent
for _p in (str(_REPO), str(_RECON)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from recon.helpers import circuit_breaker, request_pacer  # noqa: E402
from recon.main_recon_modules import http_probe  # noqa: E402

T0 = 100.0
NO_CEILING = [
    {},
    {"ROE_ENABLED": False, "ROE_GLOBAL_MAX_RPS": 2},
    {"ROE_ENABLED": True, "ROE_GLOBAL_MAX_RPS": 0},
    {"ROE_ENABLED": True},
]
NO_CEILING_IDS = ["no-roe", "roe-off", "rps-0", "rps-unset"]


@pytest.fixture(autouse=True)
def _fresh_run():
    request_pacer.reset()
    circuit_breaker.reset_registry()
    yield
    request_pacer.reset()
    circuit_breaker.reset_registry()


def _ceiling(rps, **extra) -> dict:
    return {"ROE_ENABLED": True, "ROE_GLOBAL_MAX_RPS": rps, **extra}


def _cmd(settings, **kwargs) -> list:
    with mock.patch.object(http_probe, "system_resolvers", return_value=["192.0.2.53"]):
        return http_probe.build_httpx_command("/tmp/redamon/x/targets.txt", "/tmp/redamon/x/out.json",
                                              settings, container_name="c", **kwargs)


def _flag(cmd, name):
    return cmd[cmd.index(name) + 1]


def _paced(plain: list, threads: str, rate: str, delay: str) -> list:
    """``plain`` with the ceiling's pacing: -t, -retries and -rl values swapped,
    -delay right after -rl, no -favicon or -jarm, nothing else touched."""
    out = [a for a in plain if a not in ("-favicon", "-jarm")]
    out[out.index("-t") + 1] = threads
    out[out.index("-retries") + 1] = "0"
    i = out.index("-rl")
    out[i + 1] = rate
    out[i + 2:i + 2] = ["-delay", delay]
    return out


# --------------------------------------------------------------------------
# The httpx command
# --------------------------------------------------------------------------

@pytest.mark.parametrize("ip_mode", [False, True], ids=["domain", "ip"])
def test_under_a_ceiling_httpx_runs_paced(ip_mode):
    plain = _cmd({"HTTPX_RATE_LIMIT": 2}, ip_mode=ip_mode)
    paced = _cmd(_ceiling(2, HTTPX_RATE_LIMIT=2), ip_mode=ip_mode)

    assert "-favicon" in plain and "-jarm" in plain
    assert paced == _paced(plain, "1", "1", "1000ms")


def test_a_probe_the_project_turned_off_stays_off():
    project = {"HTTPX_RATE_LIMIT": 2, "HTTPX_PROBE_FAVICON": False, "HTTPX_PROBE_JARM": False}
    plain = _cmd(project)
    assert "-favicon" not in plain and "-jarm" not in plain
    assert _cmd(_ceiling(2, **project)) == _paced(plain, "1", "1", "1000ms")
    assert http_probe.httpx_ceiling_pacing(_ceiling(2, **project))["drop"] == []
    assert http_probe.httpx_ceiling_pacing(_ceiling(2, HTTPX_PROBE_JARM=False))["drop"] == ["favicon"]


@pytest.mark.parametrize("rps, configured, rate, delay", [
    (1, 1, "1", "2000ms"),
    (2, 2, "1", "1000ms"),
    (3, 3, "1", "667ms"),
    (5, 5, "2", "400ms"),
    (0.5, 0.5, "1", "4000ms"),
    (10, 3, "3", "200ms"),      # a project rate under half the ceiling stays
    (10, 0, "5", "200ms"),      # 0 (no limit) when the capper did not run
])
def test_the_pacing_follows_the_ceiling(rps, configured, rate, delay):
    cmd = _cmd(_ceiling(rps, HTTPX_RATE_LIMIT=configured, HTTPX_THREADS=50, HTTPX_RETRIES=2))
    assert _flag(cmd, "-t") == "1"
    assert _flag(cmd, "-retries") == "0"
    assert _flag(cmd, "-rl") == rate
    assert _flag(cmd, "-delay") == delay
    assert cmd.count("-rl") == cmd.count("-delay") == cmd.count("-t") == 1


@pytest.mark.parametrize("ip_mode", [False, True], ids=["domain", "ip"])
@pytest.mark.parametrize("roe", NO_CEILING, ids=NO_CEILING_IDS)
def test_no_ceiling_leaves_the_httpx_command_byte_identical(roe, ip_mode):
    settings = {"HTTPX_RATE_LIMIT": 50, "HTTPX_THREADS": 50, "HTTPX_RETRIES": 2}
    assert _cmd({**settings, **roe}, ip_mode=ip_mode) == _cmd(settings, ip_mode=ip_mode)
    assert "-delay" not in _cmd({**settings, **roe}, ip_mode=ip_mode)


# --------------------------------------------------------------------------
# run_http_probe: the budget and the log line
# --------------------------------------------------------------------------

RECON = {
    "domain": "example.com",
    "metadata": {"ip_mode": False, "root_domain": "example.com", "scope_mode": "enumerate",
                 "include_root_domain": True, "filtered_mode": False},
    "dns": {"domain": {"has_records": True, "ips": {"ipv4": ["203.0.113.10"], "ipv6": []}},
            "subdomains": {f"h{i}.example.com": {"has_records": True,
                                                 "ips": {"ipv4": [f"203.0.113.{20 + i}"], "ipv6": []}}
                           for i in range(4)}},
    "port_scan": {"by_host": {f"h{i}.example.com": {
        "host": f"h{i}.example.com", "ip": f"203.0.113.{20 + i}", "ports": [443],
        "port_details": [{"port": 443, "protocol": "tcp", "service": "https"}]} for i in range(4)},
        "by_ip": {}, "all_ports": [443]},
}


class _Stop(Exception):
    pass


def _fingerprint_gaps(report) -> list:
    """The gaps this fix records. (The fake run stops httpx, so the probe's own
    "httpx failed" gap is there too.)"""
    return [g for g in report.gaps if g["source"].startswith("httpx_")]


def _run(monkeypatch, settings):
    """run_http_probe until httpx would run; returns the command, the URLs and
    the budget it was given."""
    seen = {}

    class FakeProcess:
        def __init__(self, cmd, **_kw):
            seen["cmd"] = cmd

        def communicate(self, timeout=None):
            seen["budget"] = timeout
            raise _Stop

    def build(targets_file, *args, **kwargs):
        seen["urls"] = Path(targets_file).read_text().split()
        return real_build(targets_file, *args, **kwargs)

    real_build = http_probe.build_httpx_command
    monkeypatch.setattr(http_probe, "build_httpx_command", build)
    monkeypatch.setattr(http_probe, "is_docker_installed", lambda: True)
    monkeypatch.setattr(http_probe, "is_docker_running", lambda: True)
    monkeypatch.setattr(http_probe, "pull_httpx_docker_image", lambda *_a, **_k: True)
    monkeypatch.setattr(http_probe, "system_resolvers", lambda: ["192.0.2.53"])
    monkeypatch.setattr(http_probe.subprocess, "Popen", FakeProcess)
    http_probe.run_http_probe(copy.deepcopy(RECON), settings=dict(settings))
    return seen


def test_the_budget_covers_a_paced_run(monkeypatch, capsys):
    seen = _run(monkeypatch, _ceiling(2, HTTPX_RATE_LIMIT=2, HTTPX_THREADS=50,
                                      HTTPX_RETRIES=2, HTTPX_TIMEOUT=10))

    urls = len(seen["urls"])
    assert urls >= 4
    assert _flag(seen["cmd"], "-t") == "1"
    # One URL at a time, one attempt each, plus its 1 s dispatch delay.
    assert seen["budget"] == http_probe.httpx_budget(urls, 1, 10, 0, delay=1.0)
    assert seen["budget"] == urls * 10 + urls * 1 + 60
    assert "-favicon" not in seen["cmd"] and "-jarm" not in seen["cmd"]
    out = capsys.readouterr().out
    assert ("[*][httpx] Paced to the 2 rps RoE ceiling: one URL at a time, -rl 1, "
            "-delay 1000ms, no retries; its redirect hops take no token of httpx's "
            "limiter and can exceed it\n") in out
    assert ("[-][httpx] JARM and favicon not collected while the 2 rps RoE ceiling is "
            "in force: httpx's limiter does not count their requests\n") in out
    # A gap, not a cut finding source: nothing is kept from or added to the prune.
    report = circuit_breaker.coverage_report()
    assert not {"httpx_jarm", "httpx_favicon"} & report.degraded_sources
    assert _fingerprint_gaps(report) == [
        {"source": "httpx_favicon", "module": "http_probe",
         "reason": "not collected under the 2 rps RoE ceiling", "skipped": urls, "hosts": 0},
        {"source": "httpx_jarm", "module": "http_probe",
         "reason": "not collected under the 2 rps RoE ceiling", "skipped": urls, "hosts": 0},
    ]


def test_only_the_probes_the_ceiling_turned_off_are_gaps(monkeypatch, capsys):
    _run(monkeypatch, _ceiling(2, HTTPX_PROBE_JARM=False, HTTPX_FOLLOW_REDIRECTS=False))

    out = capsys.readouterr().out
    assert "-delay 1000ms, no retries\n" in out
    assert ("[-][httpx] favicon not collected while the 2 rps RoE ceiling is in force") in out
    assert [g["source"] for g in _fingerprint_gaps(circuit_breaker.coverage_report())] == ["httpx_favicon"]


@pytest.mark.parametrize("roe", NO_CEILING, ids=NO_CEILING_IDS)
def test_no_ceiling_keeps_the_budget_and_says_nothing(monkeypatch, capsys, roe):
    seen = _run(monkeypatch, {"HTTPX_RATE_LIMIT": 50, "HTTPX_THREADS": 50, "HTTPX_RETRIES": 2,
                              "HTTPX_TIMEOUT": 10, **roe})

    assert seen["budget"] == http_probe.httpx_budget(len(seen["urls"]), 50, 10, 2)
    assert "-favicon" in seen["cmd"] and "-jarm" in seen["cmd"]
    out = capsys.readouterr().out
    assert "Paced to the" not in out and "not collected" not in out
    assert _fingerprint_gaps(circuit_breaker.coverage_report()) == []


def test_httpx_budget_adds_the_dispatch_delay():
    assert http_probe.httpx_budget(10, 1, 10, 0, delay=2.0) == 10 * 10 + 20 + 60
    assert http_probe.httpx_budget(3, 1, 10, 0, delay=0.667) == 3 * 10 + 3 + 60
    assert http_probe.httpx_budget(1000, 50, 10, 2) == 20 * 30 + 60


# --------------------------------------------------------------------------
# The banner grab
# --------------------------------------------------------------------------

class SlotClock:
    """Frozen at T0; a thread's sleep is the slot it was handed, kept per
    thread until its connect reads it."""

    def __init__(self):
        self._local = threading.local()

    def now(self) -> float:
        return T0

    def sleep(self, seconds: float) -> None:
        self._local.at = T0 + seconds

    def stamp(self) -> float:
        at = getattr(self._local, "at", T0)
        self._local.at = T0
        return at


@pytest.fixture
def wire(monkeypatch):
    """Every connect the banner grab opens is recorded, with its slot, and refused."""
    clock = SlotClock()
    sent = []
    lock = threading.Lock()

    def connect(address, timeout=None):
        with lock:
            sent.append((address, clock.stamp()))
        raise ConnectionRefusedError

    monkeypatch.setattr(http_probe.socket, "create_connection", connect)
    return clock, sent


def _banner_recon(ports) -> dict:
    return {"metadata": {}, "port_scan": {"by_host": {
        f"h{i}.example.com": {"host": f"h{i}.example.com", "ip": f"192.0.2.{10 + i}",
                              "ports": list(ports)} for i in range(3)}}}


def test_every_banner_connection_takes_a_slot(wire, monkeypatch):
    clock, sent = wire
    request_pacer.configure(_ceiling(2))
    monkeypatch.setattr(request_pacer._PACER, "_clock", clock.now)
    monkeypatch.setattr(request_pacer._PACER, "_sleep", clock.sleep)

    # 6379 and 25: one plaintext connect each; 993 (TLS mail): plaintext, then TLS.
    http_probe.run_banner_grab(_banner_recon([6379, 25, 993]), {"BANNER_GRAB_THREADS": 20})

    assert len(sent) == 3 * (1 + 1 + 2)
    assert sorted(slot for _, slot in sent) == pytest.approx([T0 + k / 2 for k in range(len(sent))])


@pytest.mark.parametrize("roe", NO_CEILING, ids=NO_CEILING_IDS)
def test_no_ceiling_banner_grab_never_touches_the_clock(wire, monkeypatch, roe):
    _clock, sent = wire
    request_pacer.configure(roe)
    touched = []
    monkeypatch.setattr(request_pacer._PACER, "_clock", lambda: touched.append("clock") or T0)
    monkeypatch.setattr(request_pacer._PACER, "_sleep", touched.append)

    http_probe.run_banner_grab(_banner_recon([6379, 993]), {"BANNER_GRAB_THREADS": 20, **roe})

    assert len(sent) == 3 * (1 + 2)
    assert touched == []
