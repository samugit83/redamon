"""Regression: recon's own socket probes never shared the RoE clock (R-8 part B2a, D3).

Parts A and B1 put the security checks' HTTP requests and the scanners'
sessions on one process-wide request clock (recon/helpers/request_pacer.py).
These requesters still went out under ``ROE_GLOBAL_MAX_RPS`` unpaced, or paced
only by a clock of their own that let each of them use the whole ceiling while
every other in-process requester used it too:

- the security checks' raw sockets: the TLS certificate grab, the Redis PING,
  the SMTP relay dialogue and the zone-transfer (AXFR) query;
- origin discovery's TCP connects, TLS handshakes and HTTP GETs (its own
  ``ORIGIN_DISCOVERY_RATE`` limiter only), each redirect hop of the fronted
  host's reference page included;
- IP attribution's no-SNI handshakes and the wildcard-DNS control's queries,
  each on a pacer of its own;
- nmap: ``NMAP_PARALLELISM`` processes at once, each at ``--max-rate <ceiling>``.

Now each takes a slot of the one clock before every connect, handshake, command
or query (a module with its own pacer takes both slots), a 429 pushes every
requester's next slot back, and nmap runs one process at a time under a
ceiling. With no ceiling nothing waits.

Only the wire is fake: sockets, the TLS handshake, the resolver seam, nmap's
process and urllib3's ``_make_request`` (so requests' own redirect loop runs).
The clocks are frozen and a thread's sleep is recorded as the slot it was
handed (as in test_regression_roe_ceiling_scanner_sessions.py), so the wire
stamps each packet with its slot whatever order the threads run in. Names are
under example.com / example.test, addresses are RFC 5737.
"""
from __future__ import annotations

import io
import ssl as real_ssl
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest
from urllib3.connectionpool import HTTPConnectionPool
from urllib3.response import HTTPResponse

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers import circuit_breaker as cb  # noqa: E402
from recon.helpers import request_pacer  # noqa: E402
from recon.helpers import security_checks as sc  # noqa: E402
from recon.helpers import wildcard_control as wc  # noqa: E402
from recon.main_recon_modules import ip_attribution as ia  # noqa: E402
from recon.main_recon_modules import nmap_scan  # noqa: E402
from recon.main_recon_modules import origin_discovery as od  # noqa: E402

T0 = 100.0
HOST = "www.example.com"
DOMAIN = "example.com"
CANDIDATE = "203.0.113.10"
CERT = {"serial": "4096", "cn": HOST, "sans": {HOST}}
PAGE = b"<html><body>Welcome to the example shop, est. 1999</body></html>"
NO_CEILING = [
    {},
    {"ROE_ENABLED": False, "ROE_GLOBAL_MAX_RPS": 2},
    {"ROE_ENABLED": True, "ROE_GLOBAL_MAX_RPS": 0},
]


@pytest.fixture(autouse=True)
def _fresh_process():
    request_pacer.reset()
    cb.reset_registry()
    yield
    request_pacer.reset()
    cb.reset_registry()


class SlotClock:
    """A frozen clock. A pacer hands out T0, T0 + 1/C, ... and a thread sleeps
    its slot minus T0, which is kept per thread until the wire reads it."""

    def __init__(self):
        self._local = threading.local()

    def now(self) -> float:
        return T0

    # The names the modules' own pacers read from their ``time`` module.
    time = monotonic = now

    def sleep(self, seconds: float) -> None:
        self._local.at = T0 + seconds

    def stamp(self) -> float:
        at = getattr(self._local, "at", T0)
        self._local.at = T0
        return at


@pytest.fixture
def clock():
    return SlotClock()


@pytest.fixture
def own():
    """The clock a module's own pacer reads (its ``time`` module is patched)."""
    return SlotClock()


@pytest.fixture
def ceiling(clock, monkeypatch):
    def configure(rps):
        request_pacer.configure({"ROE_ENABLED": True, "ROE_GLOBAL_MAX_RPS": rps})
        monkeypatch.setattr(request_pacer._PACER, "_clock", clock.now)
        monkeypatch.setattr(request_pacer._PACER, "_sleep", clock.sleep)
        return clock
    return configure


def _one_slot_each(stamps, rps):
    """Every packet had a slot of its own on the clock: T0, T0 + 1/C, ..."""
    assert stamps, "nothing was sent"
    assert sorted(stamps) == pytest.approx([T0 + k / rps for k in range(len(stamps))])


# ---------------------------------------------------------------------------
# The wire: sockets, TLS, DNS and HTTP, each packet stamped with its slot
# ---------------------------------------------------------------------------

class _Sock:
    """A connected socket: ``greeting`` is readable at once, and each send
    queues the next of ``replies``."""

    def __init__(self, wire, peer, greeting=b"", replies=()):
        self.wire, self.peer = wire, peer
        self.inbox = greeting
        self.replies = list(replies)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def _sent(self, data: bytes) -> None:
        self.wire.log("send", self.peer, data.split(b" ")[0].strip().decode())
        if self.replies:
            self.inbox += self.replies.pop(0)

    def send(self, data):
        self._sent(data)
        return len(data)

    def sendall(self, data):
        self._sent(data)

    def recv(self, _size):
        data, self.inbox = self.inbox, b""
        return data

    def settimeout(self, _t):
        pass

    def close(self):
        pass


class _SslSock:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def getpeercert(self, binary_form=False):
        return b"\x30\x00" if binary_form else {"notAfter": "Jan  1 00:00:00 2099 GMT"}

    def cipher(self):
        return ("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128)

    def version(self):
        return "TLSv1.3"


class Wire:
    """Every packet any adopter puts on the wire, with the slots its thread
    was handed on the process clock (and on a module's own clock)."""

    def __init__(self, clock, own=None):
        self.clock, self.own = clock, own
        self.sent: list = []
        self._lock = threading.Lock()
        self.services: dict = {}          # port -> (greeting, replies)
        self.open_ports: set = set()      # for ports with no service: connect succeeds
        self.http = lambda method, url: (200, {"Server": "nginx"}, PAGE)

    def log(self, kind, *what):
        own = self.own.stamp() if self.own else None
        with self._lock:
            self.sent.append((self.clock.stamp(), own, kind) + what)

    def stamps(self, *kinds) -> list:
        return [e[0] for e in self.sent if not kinds or e[2] in kinds]

    def own_stamps(self, *kinds) -> list:
        return [e[1] for e in self.sent if not kinds or e[2] in kinds]

    def kinds(self) -> list:
        return [e[2] for e in self.sent]

    # sockets
    def create_connection(self, address, timeout=None, **_kw):
        host, port = address[0], address[1]
        self.log("connect", host, port)
        if port in self.services:
            greeting, replies = self.services[port]
            return _Sock(self, f"{host}:{port}", greeting, replies)
        if port in self.open_ports:
            return _Sock(self, f"{host}:{port}")
        raise ConnectionRefusedError(f"{host}:{port} closed")

    # TLS (the handshake helper the modules call)
    def tls(self, host_or_ip, sni, port, timeout):
        self.log("tls", host_or_ip, port)
        return dict(CERT)

    # DNS: AXFR
    def xfr(self, where, zone, **_kw):
        self.log("axfr", where)
        raise ConnectionRefusedError("transfer refused")

    # HTTP, at urllib3's last step (requests' sessions, adapters and redirects run)
    def make_request(self, pool, conn, method, url, *args, **kwargs):
        full = f"{pool.scheme}://{pool.host}{url}"
        self.log("http", full)
        status, headers, body = self.http(method, full)
        return HTTPResponse(body=io.BytesIO(body), headers=headers, status=status,
                            preload_content=False, decode_content=False,
                            request_method=method, request_url=full)


@pytest.fixture
def wire(clock, own, monkeypatch):
    w = Wire(clock, own)

    def _make_request(pool, conn, method, url, *args, **kwargs):
        return w.make_request(pool, conn, method, url)

    monkeypatch.setattr(HTTPConnectionPool, "_make_request", _make_request)
    monkeypatch.setattr(sc, "socket", SimpleNamespace(create_connection=w.create_connection))
    monkeypatch.setattr(od, "socket", SimpleNamespace(create_connection=w.create_connection))
    monkeypatch.setattr(sc, "ssl", SimpleNamespace(
        create_default_context=lambda: SimpleNamespace(
            check_hostname=True, verify_mode=None,
            wrap_socket=lambda sock, server_hostname=None: _SslSock()),
        CERT_NONE=real_ssl.CERT_NONE))
    monkeypatch.setattr(od, "_tls_handshake_cert", w.tls)
    monkeypatch.setattr(ia, "tls_handshake_cert", w.tls)
    monkeypatch.setattr(sc.dns.query, "xfr", w.xfr)
    return w


def _nameservers(monkeypatch, *addresses):
    """``example.com`` has one nameserver per address; each resolves to it."""
    names = {f"ns{i}.{DOMAIN}": addr for i, addr in enumerate(addresses, 1)}

    def resolve(name, rtype, *a, **k):
        if rtype == "NS":
            return [SimpleNamespace(target=f"{ns}.") for ns in names]
        if rtype == "A" and name in names:
            return [names[name]]
        raise sc.dns.resolver.NoAnswer()

    monkeypatch.setattr(sc.dns.resolver, "resolve", resolve)


SMTP_DIALOGUE = (b"220 mx.example.com ESMTP\r\n",
                 [b"250 mx.example.com\r\n", b"250 2.1.0 Ok\r\n",
                  b"554 5.7.1 Relay access denied\r\n", b"221 2.0.0 Bye\r\n"])


@pytest.mark.parametrize("module", [sc, od, ia, wc],
                         ids=["security_checks", "origin_discovery", "ip_attribution",
                              "wildcard_control"])
def test_every_adopter_holds_the_one_process_clock(module):
    """Imported under another name (helpers.request_pacer) it would be a second clock."""
    assert module.request_pacer is sys.modules["recon.helpers.request_pacer"]


# ---------------------------------------------------------------------------
# Security checks: the raw-socket probes
# ---------------------------------------------------------------------------

class TestSecurityCheckSockets:
    def test_each_tls_certificate_grab_takes_a_slot(self, ceiling, wire):
        ceiling(2)
        wire.open_ports = {443}
        for _ in range(3):
            info = sc.get_ssl_certificate(HOST, 443, timeout=3)
            assert info["version"] == "TLSv1.3"
        assert wire.kinds() == ["connect"] * 3
        assert wire.stamps() == pytest.approx([T0, T0 + 0.5, T0 + 1.0])

    def test_each_redis_probe_takes_a_slot(self, ceiling, wire):
        ceiling(2)
        wire.services[6379] = (b"", [b"+PONG\r\n"])
        for ip in ("192.0.2.20", "192.0.2.21", "192.0.2.22"):
            assert sc.check_redis_no_auth(ip, timeout=3)["type"] == "redis_no_auth"
        assert wire.stamps("connect") == pytest.approx([T0, T0 + 0.5, T0 + 1.0])

    def test_each_command_of_the_smtp_dialogue_takes_a_slot(self, ceiling, wire):
        ceiling(4)
        wire.services[25] = SMTP_DIALOGUE
        assert sc.check_smtp_open_relay("192.0.2.25", timeout=3) is None
        assert [e[2:] for e in wire.sent] == [
            ("connect", "192.0.2.25", 25),
            ("send", "192.0.2.25:25", "HELO"),
            ("send", "192.0.2.25:25", "MAIL"),
            ("send", "192.0.2.25:25", "RCPT"),
            ("send", "192.0.2.25:25", "QUIT"),
        ]
        assert wire.stamps() == pytest.approx([T0 + k / 4 for k in range(5)])

    def test_each_zone_transfer_query_takes_a_slot(self, ceiling, wire, monkeypatch):
        ceiling(2)
        _nameservers(monkeypatch, "192.0.2.53", "198.51.100.53", "203.0.113.53")
        assert sc.check_zone_transfer(DOMAIN, timeout=3) is None
        assert [e[3] for e in wire.sent] == ["192.0.2.53", "198.51.100.53", "203.0.113.53"]
        assert wire.stamps("axfr") == pytest.approx([T0, T0 + 0.5, T0 + 1.0])


# ---------------------------------------------------------------------------
# Origin discovery: its own limiter AND the process clock
# ---------------------------------------------------------------------------

def _od_settings(**over):
    s = {"ORIGIN_DISCOVERY_ENABLED": True, "ORIGIN_DISCOVERY_KEYLESS": True,
         "ORIGIN_DISCOVERY_SCANNERS": False, "ORIGIN_DISCOVERY_PASSIVE_DNS": False,
         "ORIGIN_DISCOVERY_URLSCAN": False, "URLSCAN_ENABLED": False,
         "ORIGIN_DISCOVERY_MAX_CANDIDATES": 25, "ORIGIN_DISCOVERY_MAX_SEARCH_CALLS": 50,
         "ORIGIN_DISCOVERY_THRESHOLD": 60, "ORIGIN_DISCOVERY_TIMEOUT": 3,
         "ORIGIN_DISCOVERY_WORKERS": 1, "ORIGIN_DISCOVERY_RATE": 0,
         "ROE_ENABLED": False, "ROE_EXCLUDED_HOSTS": []}
    s.update(over)
    return s


def _od_ctx(own, monkeypatch, **over):
    monkeypatch.setattr(od, "time", own)
    return od._RunCtx(_od_settings(**over))


class TestOriginDiscovery:
    def test_a_whole_run_takes_both_slots_for_every_probe(self, ceiling, wire, own, monkeypatch):
        """Connects, handshakes and GETs of a real run, three candidates."""
        ceiling(2)
        wire.open_ports = {80, 443}
        candidates = ["203.0.113.10", "203.0.113.11", "203.0.113.12"]
        monkeypatch.setattr(od, "time", own)
        combined = {"http_probe": {"by_url": {f"https://{HOST}": {
            "host": HOST, "ip": "104.16.1.1", "is_cdn": True, "cdn": "cloudflare",
            "status_code": 200}}}}
        with mock.patch.multiple(
                od,
                _discover_via_subdomains=mock.Mock(return_value=[]),
                _discover_via_email_records=mock.Mock(return_value=[]),
                _discover_via_crtsh=mock.Mock(return_value=list(candidates)),
                _favicon_hash_for_host=mock.Mock(return_value=None),
                _resolve_ips=mock.Mock(return_value=set()),
                is_non_routable_ip=mock.Mock(return_value=False)):
            out = od.run_origin_discovery_enrichment(
                combined, _od_settings(ORIGIN_DISCOVERY_RATE=4))["origin_discovery"]

        assert sorted(f["matched_ip"] for f in out["confirmed"]) == candidates
        kinds = set(wire.kinds())
        assert {"connect", "tls", "http"} <= kinds
        assert wire.kinds().count("connect") == len(candidates) * len(od.WEB_PORTS)
        _one_slot_each(wire.stamps(), 2)
        _one_slot_each(wire.own_stamps(), 4)

    def test_each_redirect_hop_of_the_reference_page_takes_a_slot(self, ceiling, wire, own,
                                                                  monkeypatch):
        ceiling(2)
        wire.http = lambda method, url: (
            (301, {"Location": f"https://{HOST}/home"}, b"") if url == f"https://{HOST}/"
            else (200, {"Content-Type": "text/html"}, PAGE))
        ref = od._reference(HOST, _od_ctx(own, monkeypatch, ORIGIN_DISCOVERY_RATE=4))
        assert ref["status"] == 200 and ref["final_url"] == f"https://{HOST}/home"
        assert [e[3] for e in wire.sent] == [f"https://{HOST}/", f"https://{HOST}/home"]
        assert wire.stamps() == pytest.approx([T0, T0 + 0.5])
        assert wire.own_stamps() == pytest.approx([T0, T0 + 0.25])

    def test_the_favicon_and_own_file_fetches_take_both_slots(self, ceiling, wire, own,
                                                             monkeypatch):
        ceiling(2)
        monkeypatch.setattr(od, "is_url_safe_to_probe", lambda _u: True)
        ctx = _od_ctx(own, monkeypatch, ORIGIN_DISCOVERY_RATE=4)
        od._favicon_hash_for_host(HOST, None, ctx)
        assert od._file_sha256(f"https://{CANDIDATE}/static/app.8f3a91c2.js", HOST, ctx)
        assert wire.kinds() == ["http", "http"]
        assert wire.stamps() == pytest.approx([T0, T0 + 0.5])
        assert wire.own_stamps() == pytest.approx([T0, T0 + 0.25])

    def test_a_429_pushes_every_requesters_next_slot_back(self, ceiling, wire, own,
                                                         monkeypatch):
        ceiling(2)
        answers = iter([(429, {"Retry-After": "7"}, b""), (200, {}, PAGE)])
        wire.http = lambda method, url: next(answers)
        ctx = _od_ctx(own, monkeypatch)
        assert od._fetch(f"https://{CANDIDATE}:443", HOST, ctx)["status"] == 429
        sc.get_ssl_certificate(HOST, 443, timeout=3)
        assert wire.stamps() == pytest.approx([T0, T0 + 7])

    def test_a_429_holds_back_at_most_thirty_seconds(self, ceiling, wire, own, monkeypatch):
        ceiling(2)
        wire.http = lambda method, url: (429, {"Retry-After": "86400"}, b"")
        od._fetch(f"https://{CANDIDATE}:443", HOST, _od_ctx(own, monkeypatch))
        sc.get_ssl_certificate(HOST, 443, timeout=3)
        assert wire.stamps() == pytest.approx([T0, T0 + 30])


# ---------------------------------------------------------------------------
# IP attribution and the wildcard control: their own pacer AND the process clock
# ---------------------------------------------------------------------------

class TestOwnPacerModules:
    def test_ip_attribution_handshakes_take_both_slots(self, ceiling, wire, own, monkeypatch):
        ceiling(2)
        monkeypatch.setattr(ia, "time", own)
        ips = [f"198.51.100.{i}" for i in range(1, 7)]
        out = ia._probe_all(ips, [DOMAIN], {"ROE_ENABLED": False})
        assert sorted(out) == ips
        assert all(status == ia.CERT_TARGET for status, _d, _n in out.values())
        assert wire.kinds() == ["tls"] * len(ips)
        _one_slot_each(wire.stamps(), 2)
        _one_slot_each(wire.own_stamps(), ia._TLS_RPS)

    def test_wildcard_queries_take_both_slots(self, ceiling, wire, own, monkeypatch):
        ceiling(8)
        monkeypatch.setattr(wc, "time", own)

        def query(name, rtype):
            wire.log("dns", name, rtype)
            return ("ok", ["203.0.113.80"]) if rtype == "A" else ("none", [])

        monkeypatch.setattr(wc, "_query", query)
        zone = wc.zone(DOMAIN, {"ROE_ENABLED": True, "ROE_GLOBAL_MAX_RPS": 4})
        assert zone.state == "wildcard" and zone.ips == {"203.0.113.80"}
        assert len(wire.sent) == 2 * wc.LABELS_PER_ZONE + 1
        _one_slot_each(wire.stamps(), 8)
        _one_slot_each(wire.own_stamps(), 4)


# ---------------------------------------------------------------------------
# Every adopter, at once, on the one clock
# ---------------------------------------------------------------------------

def test_every_adopter_interleaves_on_the_one_process_clock(ceiling, wire, own, monkeypatch):
    """An AXFR query, origin discovery's port connects, an SMTP dialogue, IP
    attribution's handshakes and the wildcard control's queries, from five
    threads: no two packets share a slot."""
    ceiling(5)
    _nameservers(monkeypatch, "192.0.2.53", "198.51.100.53")
    wire.services[25] = SMTP_DIALOGUE
    monkeypatch.setattr(ia, "time", own)
    monkeypatch.setattr(wc, "time", own)
    monkeypatch.setattr(wc, "_query", lambda name, rtype: wire.log("dns", name) or ("nx", []))
    ctx = _od_ctx(own, monkeypatch)
    reference = {"text": "page", "status": 200, "headers": {}, "cookies": ""}

    jobs = [
        lambda: sc.check_zone_transfer(DOMAIN, timeout=3),
        lambda: od._score_candidate(HOST, reference, CANDIDATE, ctx),
        lambda: sc.check_smtp_open_relay("192.0.2.25", timeout=3),
        lambda: ia._probe_all(["198.51.100.7", "198.51.100.8"], [DOMAIN], {}),
        lambda: wc.zone("example.test", {}),
    ]
    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        for job in [pool.submit(j) for j in jobs]:
            job.result()

    kinds = wire.kinds()
    assert kinds.count("axfr") == 2 and kinds.count("tls") == 2 and kinds.count("dns") == 1
    assert kinds.count("connect") == len(od.WEB_PORTS) + 1  # the candidate's ports + SMTP
    _one_slot_each(wire.stamps(), 5)


# ---------------------------------------------------------------------------
# No ceiling: nothing waits, nothing reads the clock
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("settings", NO_CEILING, ids=["no_keys", "roe_off", "zero"])
def test_no_ceiling_never_touches_the_clock(settings, wire, own, monkeypatch):
    request_pacer.configure(settings)
    touched = []
    monkeypatch.setattr(request_pacer._PACER, "_clock", lambda: touched.append("clock") or T0)
    monkeypatch.setattr(request_pacer._PACER, "_sleep", touched.append)
    _nameservers(monkeypatch, "192.0.2.53")
    wire.services[25] = SMTP_DIALOGUE
    wire.services[6379] = (b"", [b"+PONG\r\n"])
    monkeypatch.setattr(ia, "time", own)
    monkeypatch.setattr(wc, "time", own)
    monkeypatch.setattr(wc, "_query", lambda name, rtype: wire.log("dns", name) or ("nx", []))
    wire.http = lambda method, url: (429, {"Retry-After": "9"}, b"")

    sc.get_ssl_certificate(HOST, 443, timeout=3)
    sc.check_redis_no_auth("192.0.2.20", timeout=3)
    sc.check_smtp_open_relay("192.0.2.25", timeout=3)
    sc.check_zone_transfer(DOMAIN, timeout=3)
    od._fetch(f"https://{CANDIDATE}:443", HOST, _od_ctx(own, monkeypatch))
    ia._probe_all(["198.51.100.7"], [DOMAIN], settings)
    wc.zone("example.test", settings)

    assert {"connect", "axfr", "http", "tls", "dns"} <= set(wire.kinds())
    assert touched == []


# ---------------------------------------------------------------------------
# nmap: one process at a time under a ceiling
# ---------------------------------------------------------------------------

class _FakeNmap:
    """nmap's process: counts how many run at once. Each holds on until a
    second one is running (or a short while passes), so a pool of two shows."""

    def __init__(self):
        self.cmds: list = []
        self.in_flight = 0
        self.most = 0
        self._lock = threading.Lock()
        self._two = threading.Event()

    def __call__(self, cmd, **_kw):
        with self._lock:
            self.cmds.append(cmd)
            self.in_flight += 1
            self.most = max(self.most, self.in_flight)
            if self.in_flight >= 2:
                self._two.set()
        target = cmd[-1]
        Path(cmd[cmd.index("-oX") + 1]).write_text(
            '<?xml version="1.0"?><nmaprun scanner="nmap" version="7.93">'
            '<host><status state="up" reason="syn-ack"/>'
            f'<address addr="{target}" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/>'
            '<service name="https" product="nginx" version="1.25.0"/></port></ports>'
            '</host></nmaprun>')
        fake = self

        class _Proc:
            returncode = 0

            def communicate(self, timeout=None):
                fake._two.wait(timeout=0.3)
                with fake._lock:
                    fake.in_flight -= 1
                return "", ""

        return _Proc()


def _nmap_run(monkeypatch, settings):
    ips = [f"192.0.2.{i}" for i in range(10, 14)]
    pools: list = []
    real_pool = nmap_scan.ThreadPoolExecutor

    def pool(*args, **kwargs):
        pools.append(kwargs.get("max_workers", args[0] if args else None))
        return real_pool(*args, **kwargs)

    nmap = _FakeNmap()
    monkeypatch.setattr(nmap_scan, "ThreadPoolExecutor", pool)
    monkeypatch.setattr(nmap_scan, "is_nmap_installed", lambda: True)
    monkeypatch.setattr(nmap_scan.subprocess, "Popen", nmap)
    recon = {"port_scan": {"by_ip": {ip: {"ip": ip, "hostnames": [], "ports": [443]} for ip in ips},
                           "by_host": {}, "ip_to_hostnames": {}}}
    out = nmap_scan.run_nmap_scan(recon, settings={"NMAP_PARALLELISM": 4, **settings})
    scanned = sorted(entry["ip"] for entry in out["nmap_scan"]["by_host"].values())
    assert scanned == ips
    assert sorted(cmd[-1] for cmd in nmap.cmds) == ips
    return pools, nmap


def test_nmap_runs_one_process_at_a_time_under_a_ceiling(monkeypatch):
    pools, nmap = _nmap_run(monkeypatch, {"ROE_ENABLED": True, "ROE_GLOBAL_MAX_RPS": 2})
    assert pools == [1]
    assert nmap.most == 1
    assert all(cmd[cmd.index("--max-rate") + 1] == "2" for cmd in nmap.cmds)


@pytest.mark.parametrize("settings", NO_CEILING, ids=["no_keys", "roe_off", "zero"])
def test_nmap_keeps_its_parallelism_with_no_ceiling(settings, monkeypatch):
    pools, nmap = _nmap_run(monkeypatch, settings)
    assert pools == [4]
    assert nmap.most >= 2
    assert not any("--max-rate" in cmd for cmd in nmap.cmds)
