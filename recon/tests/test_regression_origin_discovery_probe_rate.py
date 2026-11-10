"""Regression (R-44): origin discovery's TCP and TLS probes bypassed its rate limiter.

Only the HTTP fetches and the no-SNI certificate dial waited on
``ctx.rate``. Each candidate's port check (a TCP connect on every web port)
and its certificate comparison (a TLS handshake to the candidate, plus one
to the fronted host for the reference certificate, repeated for every
candidate) went out unpaced, so ``ORIGIN_DISCOVERY_RATE`` (lowered by stealth
and capped by ``ROE_GLOBAL_MAX_RPS``) did not hold.

The run goes through the real entry point. Only I/O is faked: the candidate
sources, DNS, TCP connects, TLS handshakes and HTTP GETs, all on a fake clock
the module's rate limiter reads, so pacing is measured in fake seconds.
Names are example.com; candidate addresses are RFC 5737 (the SSRF filter,
not under test here, is opened for them).

Not lab-provable: origin discovery needs public DNS (lab README, "Not covered
here"), so these tests are the proof.
"""
from __future__ import annotations

import contextlib
import sys
import threading
import time as real_time
from collections import Counter
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers import circuit_breaker as cb  # noqa: E402
from recon.main_recon_modules import origin_discovery as od  # noqa: E402

HOST = "www.example.com"
EDGE = "104.16.1.1"
CANDIDATES = [f"203.0.113.{10 + i}" for i in range(5)]
CERT = {"serial": "4096", "cn": HOST, "sans": {HOST}}
PAGE = b"<html><body>Welcome to the example shop, est. 1999</body></html>"


class FakeClock:
    """The module's ``time``: sleeping advances it, nothing really waits."""

    def __init__(self):
        self._now = 1_000.0
        self.slept = 0.0
        self._lock = threading.Lock()

    def time(self):
        with self._lock:
            return self._now

    def sleep(self, seconds):
        with self._lock:
            self._now += max(0.0, seconds)
            self.slept += max(0.0, seconds)


class _Resp:
    def __init__(self, url):
        self.status_code = 200
        self.url = url
        self.headers = {"Server": "nginx"}
        self.raw = SimpleNamespace(read=lambda *_a, **_k: PAGE,
                                   headers=SimpleNamespace(get_all=lambda _name: []))

    def close(self):
        pass


class Wire:
    """Every packet the run sends, stamped with the fake clock."""

    def __init__(self, clock, open_ports, ref_tls_fails=False, ref_tls_delay=0.0):
        self.clock = clock
        self.open_ports = set(open_ports)
        self.ref_tls_fails = ref_tls_fails
        self.ref_tls_delay = ref_tls_delay
        self.events = []
        self._lock = threading.Lock()

    def _log(self, *event):
        with self._lock:
            self.events.append((self.clock.time(),) + event)

    def connect(self, address, timeout=None):
        ip, port = address
        self._log("tcp", ip, port)
        if port not in self.open_ports:
            raise ConnectionRefusedError(f"{ip}:{port} closed")
        return contextlib.nullcontext()

    def tls(self, host_or_ip, sni, port, timeout):
        self._log("tls", host_or_ip, sni, port)
        if host_or_ip == HOST:
            if self.ref_tls_delay:
                # Widen the window in which concurrent candidates reach the
                # reference dial, so a cache without single-flight shows.
                real_time.sleep(self.ref_tls_delay)
            if self.ref_tls_fails:
                raise OSError("handshake timed out")
        return dict(CERT)

    def get(self, url, **_kwargs):
        self._log("http", url)
        return _Resp(url)

    def reference_dials(self):
        return Counter((e[2], e[4]) for e in self.events if e[1] == "tls" and e[2] == HOST)

    def candidate_sni_dials(self):
        return Counter((e[2], e[4]) for e in self.events
                       if e[1] == "tls" and e[2] != HOST and e[3] == HOST)


@pytest.fixture(autouse=True)
def _fresh_registry():
    cb.reset_registry()
    yield
    cb.reset_registry()


def _settings(**over):
    s = {"ORIGIN_DISCOVERY_ENABLED": True, "ORIGIN_DISCOVERY_KEYLESS": True,
         "ORIGIN_DISCOVERY_SCANNERS": False, "ORIGIN_DISCOVERY_PASSIVE_DNS": False,
         "ORIGIN_DISCOVERY_URLSCAN": False, "URLSCAN_ENABLED": False,
         "ORIGIN_DISCOVERY_MAX_CANDIDATES": 25, "ORIGIN_DISCOVERY_MAX_SEARCH_CALLS": 50,
         "ORIGIN_DISCOVERY_THRESHOLD": 60, "ORIGIN_DISCOVERY_TIMEOUT": 3,
         "ORIGIN_DISCOVERY_WORKERS": 1, "ORIGIN_DISCOVERY_RATE": 1,
         "ROE_ENABLED": False, "ROE_EXCLUDED_HOSTS": []}
    s.update(over)
    return s


def _combined():
    return {"http_probe": {"by_url": {
        f"https://{HOST}": {"host": HOST, "ip": EDGE, "is_cdn": True, "cdn": "cloudflare",
                            "status_code": 200}}}}


def _run(wire, clock, settings):
    with mock.patch.multiple(
            od,
            _discover_via_subdomains=mock.Mock(return_value=[]),
            _discover_via_email_records=mock.Mock(return_value=[]),
            _discover_via_crtsh=mock.Mock(return_value=list(CANDIDATES)),
            _favicon_hash_for_host=mock.Mock(return_value=None),
            _resolve_ips=mock.Mock(return_value=set()),
            is_non_routable_ip=mock.Mock(return_value=False),
            _tls_handshake_cert=wire.tls,
            socket=SimpleNamespace(create_connection=wire.connect),
            time=clock), \
            mock.patch.object(od.requests, "get", side_effect=wire.get):
        return od.run_origin_discovery_enrichment(_combined(), settings)["origin_discovery"]


def _unpaced(events, rate):
    """Consecutive packets closer together than the rate allows."""
    gap = 1.0 / rate
    return [(a[1:], b[1:]) for a, b in zip(events, events[1:]) if b[0] - a[0] < gap - 1e-9]


class TestEveryCandidateProbeIsPaced:
    def test_regression_n_probes_at_rate_r_take_at_least_n_minus_one_over_r(self):
        rate = 2.0
        clock = FakeClock()
        wire = Wire(clock, open_ports={80, 443})
        out = _run(wire, clock, _settings(ORIGIN_DISCOVERY_RATE=rate))

        kinds = Counter(e[1] for e in wire.events)
        # Every web port of every candidate was asked: 8 connects each.
        assert kinds["tcp"] == len(CANDIDATES) * len(od.WEB_PORTS)
        assert kinds["tls"] and kinds["http"]
        assert _unpaced(wire.events, rate) == []
        span = wire.events[-1][0] - wire.events[0][0]
        assert span >= (len(wire.events) - 1) / rate - 1e-9
        # Pacing changed when the probes left, not what they found.
        assert sorted(f["matched_ip"] for f in out["confirmed"]) == CANDIDATES

    def test_regression_the_reference_certificate_is_dialled_once_per_port(self):
        clock = FakeClock()
        wire = Wire(clock, open_ports={80, 443, 8443})
        _run(wire, clock, _settings())
        assert wire.reference_dials() == {(HOST, 443): 1, (HOST, 8443): 1}
        # Each candidate is still compared on each of its TLS ports.
        assert wire.candidate_sni_dials() == {
            (ip, port): 1 for ip in CANDIDATES for port in (443, 8443)}
        assert _unpaced(wire.events, 1.0) == []

    def test_regression_concurrent_candidates_share_one_reference_dial(self):
        clock = FakeClock()
        wire = Wire(clock, open_ports={443}, ref_tls_delay=0.05)
        _run(wire, clock, _settings(ORIGIN_DISCOVERY_WORKERS=len(CANDIDATES),
                                    ORIGIN_DISCOVERY_RATE=0))
        assert wire.reference_dials() == {(HOST, 443): 1}

    def test_a_reference_dial_that_failed_is_not_repeated_per_candidate(self):
        clock = FakeClock()
        wire = Wire(clock, open_ports={443}, ref_tls_fails=True)
        out = _run(wire, clock, _settings())
        assert wire.reference_dials() == {(HOST, 443): 1}
        # With nothing to compare against, the candidate is not dialled for it.
        assert wire.candidate_sni_dials() == {}
        assert all(f["cert_match"] == 0.0 for f in out["confirmed"])

    def test_the_reference_certificate_is_cached_per_run_not_forever(self):
        clock = FakeClock()
        wire = Wire(clock, open_ports={443})
        _run(wire, clock, _settings())
        cb.reset_registry()  # the next scan: a new run context
        _run(wire, clock, _settings())
        assert wire.reference_dials() == {(HOST, 443): 2}

    def test_no_rate_set_means_no_wait(self):
        clock = FakeClock()
        wire = Wire(clock, open_ports={80, 443})
        _run(wire, clock, _settings(ORIGIN_DISCOVERY_RATE=0))
        assert clock.slept == 0.0
        assert Counter(e[1] for e in wire.events)["tcp"] == len(CANDIDATES) * len(od.WEB_PORTS)
