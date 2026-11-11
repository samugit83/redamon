"""Regression: the vhost/SNI probes ignored the RoE ceiling (R-8, D3).

The enumerator runs curl in-process, one subprocess per probe, from a pool of
VHOST_SNI_CONCURRENCY workers (20 by default). No probe took a slot of the
process-wide request clock (recon/helpers/request_pacer.py), so under a 1 rps
ceiling one IP's baseline, control and candidate probes alone went out by the
dozen each second, on top of every other in-process requester.

Now each curl request takes one slot first. Only ``subprocess.run`` (the wire)
is fake, so the real collection, baseline, control and candidate probes and
the worker pool run. The pacer's clock is frozen and a thread's sleep is
recorded as the slot it was handed, so the wire stamps every probe with its
slot whatever order the threads run in. With no ceiling nothing waits.
Reserved names and documentation ranges only; no network.
"""
from __future__ import annotations

import subprocess
import sys
import threading
from pathlib import Path

import pytest

_RECON = Path(__file__).resolve().parent.parent
_REPO = _RECON.parent
for _p in (str(_REPO), str(_RECON)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from recon.helpers import circuit_breaker  # noqa: E402
from recon.helpers import request_pacer  # noqa: E402
from recon.main_recon_modules import vhost_sni_enum as vsm  # noqa: E402

T0 = 100.0
IPS = ["192.0.2.10", "192.0.2.11"]
NO_CEILING = [
    {},
    {"ROE_ENABLED": False, "ROE_GLOBAL_MAX_RPS": 2},
    {"ROE_ENABLED": True, "ROE_GLOBAL_MAX_RPS": 0},
]


class SlotClock:
    """A frozen clock. The pacer hands out T0, T0 + 1/C, ... and a thread sleeps
    its slot minus T0, which is kept per thread until the wire reads it."""

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


class Wire:
    """Stands in for curl: answers every probe with the same page and records
    the slot each one was sent in."""

    def __init__(self, clock: SlotClock):
        self.clock = clock
        self.sent: list = []
        self._lock = threading.Lock()

    def run(self, cmd, *args, **kwargs):
        with self._lock:
            self.sent.append((self.clock.stamp(), cmd))
        out = b"<html>same page</html>" + vsm._PROBE_META_SENTINEL + b"200\t22\t\ttext/html"
        return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr=b"")

    def stamps(self) -> list:
        return [stamp for stamp, _ in self.sent]


@pytest.fixture(autouse=True)
def _fresh_run():
    request_pacer.reset()
    circuit_breaker.reset_registry()
    yield
    request_pacer.reset()
    circuit_breaker.reset_registry()


@pytest.fixture
def clock():
    return SlotClock()


@pytest.fixture
def wire(clock, monkeypatch):
    w = Wire(clock)
    monkeypatch.setattr(vsm.subprocess, "run", w.run)
    monkeypatch.setattr(vsm, "_is_curl_available", lambda: True)
    return w


@pytest.fixture
def ceiling(clock, monkeypatch):
    def configure(rps):
        request_pacer.configure({"ROE_ENABLED": True, "ROE_GLOBAL_MAX_RPS": rps})
        monkeypatch.setattr(request_pacer._PACER, "_clock", clock.now)
        monkeypatch.setattr(request_pacer._PACER, "_sleep", clock.sleep)
        return clock
    return configure


def _recon() -> dict:
    return {"domain": "example.com", "metadata": {},
            "port_scan": {"by_host": {ip: {"ip": ip, "ports": [{"port": 443}, {"port": 80}]}
                                      for ip in IPS}}}


def _settings(**extra) -> dict:
    wordlist = "\n".join(f"app{i:02d}.example.com" for i in range(12))
    return {
        "VHOST_SNI_ENABLED": True, "VHOST_SNI_TEST_L7": True, "VHOST_SNI_TEST_L4": True,
        "VHOST_SNI_USE_DEFAULT_WORDLIST": False, "VHOST_SNI_USE_GRAPH_CANDIDATES": False,
        "VHOST_SNI_CUSTOM_WORDLIST": wordlist, "VHOST_SNI_INJECT_DISCOVERED": False,
        "VHOST_SNI_CONCURRENCY": 20, "VHOST_SNI_TIMEOUT": 1, **extra,
    }


def _one_slot_each(stamps, rps):
    """Every probe had a slot of its own on the one clock: T0, T0 + 1/C, ...
    so no two are closer than 1/C."""
    assert stamps, "nothing was sent"
    assert sorted(stamps) == pytest.approx([T0 + k / rps for k in range(len(stamps))])


def test_vhost_holds_the_one_process_clock():
    """Imported under another name (helpers.request_pacer) it would be a second clock."""
    assert vsm.request_pacer is sys.modules["recon.helpers.request_pacer"]


def test_each_curl_probe_takes_a_slot(ceiling, wire):
    ceiling(2)
    for port in (443, 8443, 80):
        vsm._curl_probe("https" if port != 80 else "http", "admin.example.com", None,
                        IPS[0], port, timeout=1)

    assert len(wire.sent) == 3
    _one_slot_each(wire.stamps(), 2)


def test_the_probe_pool_holds_the_ceiling_together(ceiling, wire):
    """Twenty workers, two IPs, two ports each: baselines, controls, L7 and L4
    candidates all queue on the one clock."""
    ceiling(4)

    out = vsm.run_vhost_sni_enrichment_isolated(_recon(), _settings())

    assert set(out["by_ip"]) == set(IPS)
    assert len(wire.sent) > 40
    assert all(cmd[0] == "curl" for _, cmd in wire.sent)
    _one_slot_each(wire.stamps(), 4)


@pytest.mark.parametrize("settings", NO_CEILING, ids=["no-roe", "roe-off", "rps-0"])
def test_no_ceiling_never_touches_the_clock(settings, wire, monkeypatch):
    request_pacer.configure(settings)
    touched = []
    monkeypatch.setattr(request_pacer._PACER, "_clock", lambda: touched.append("clock") or T0)
    monkeypatch.setattr(request_pacer._PACER, "_sleep", touched.append)

    out = vsm.run_vhost_sni_enrichment_isolated(_recon(), _settings(**settings))

    assert set(out["by_ip"]) == set(IPS)
    assert len(wire.sent) > 40
    assert touched == []
