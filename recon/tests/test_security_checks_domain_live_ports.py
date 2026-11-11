"""Domain mode: a security check probes a host only on a port the run found live (S-28).

The hostname checks sent https://<name> to every subdomain and the direct-IP
checks sent http://<ip> to every address, whatever the port scan and httpx had
found there. On an HTTP-only subdomain three refused :443 connections marked
"<name>:443" unreachable (check_ip_api_exposed alone sends seven :80 requests
to an HTTPS-only or non-web address), and an unreachable host is kept by the
prune for every source, so a fixed finding on it never went away.

The evidence is the run's own: the port scan's open ports and httpx's live
URLs, for an address and for every name resolving to it. A host is probed only
on the web ports that evidence shows live, and a refusal there is a real
outage. A host with no evidence at all (a name the scanners never reached) is
not probed and keeps its security_check findings as not checked, never marked
unreachable; so does a host whose web port is unproven when the port scan or
httpx was cut short. A run that measured nothing live probes as before.

The network is faked at requests' Session and socket.create_connection: a
request to a live (host, port) gets a 200 page, any other is refused, as a
closed port refuses it. Documentation ranges and reserved names only.
"""
import socket
import sys
import time as _time
from pathlib import Path
from unittest import mock
from urllib.parse import urljoin, urlsplit

import pytest
import requests

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers import circuit_breaker  # noqa: E402
from recon.helpers import security_checks as sc  # noqa: E402

APEX = "example.com"
PLAIN, PLAIN_IP = "plain.example.com", "192.0.2.10"        # serves HTTP only
SECURE, SECURE_IP = "secure.example.com", "192.0.2.20"     # serves HTTPS only
LATE, LATE_IP = "late.example.com", "192.0.2.30"           # in DNS, never port-scanned or probed
SHARED = "shared.example.com"                              # no row of its own; its address serves HTTPS
_DEFAULT_PORT = {"http": 80, "https": 443}


class _Every(dict):
    """Every check on, except the org DNS checks, which would ask a real resolver."""

    def get(self, key, default=None):
        return key not in sc.DNS_CHECK_TYPES


def _sub(*ips):
    return {"has_records": True, "ips": {"ipv4": list(ips), "ipv6": []}}


def _domain(names, ports=None, urls=None):
    """A domain run, apex excluded: DNS for ``names``, plus the port scan
    (address -> open ports, hostnames from DNS) and httpx's live URLs when given."""
    recon = {
        "domain": APEX,
        "metadata": {"include_root_domain": False, "root_domain": APEX},
        "subdomains": list(names),
        "dns": {"domain": {}, "subdomains": {n: _sub(*a) for n, a in names.items()}},
    }
    if ports is not None:
        recon["port_scan"] = {"by_ip": {
            ip: {"ip": ip, "ports": list(p), "hostnames": [n for n, a in names.items() if ip in a]}
            for ip, p in ports.items()}}
    if urls is not None:
        recon["http_probe"] = {"by_url": {
            u: {"url": u, "host": urlsplit(u).hostname,
                "ip": (names.get(urlsplit(u).hostname) or [None])[0], "status_code": 200}
            for u in urls}}
    return recon


def _lab():
    """An HTTP-only and an HTTPS-only subdomain, both scanned and probed."""
    return _domain({PLAIN: [PLAIN_IP], SECURE: [SECURE_IP]},
                   ports={PLAIN_IP: [80, 6379], SECURE_IP: [443]},
                   urls=[f"http://{PLAIN}", f"https://{SECURE}"])


_LAB_LIVE = {(PLAIN, 80), (PLAIN_IP, 80), (SECURE, 443), (SECURE_IP, 443)}


def _response(url, location=None):
    resp = requests.Response()
    resp.status_code = 302 if location else 200
    resp.url = url
    resp.headers = requests.structures.CaseInsensitiveDict({"Content-Type": "text/html"})
    if location:
        resp.headers["Location"] = location
    resp._content = b"<html><body>ok</body></html>"
    resp.encoding = "utf-8"
    return resp


class _Sock:
    def __init__(self, reply):
        self.reply = reply

    def send(self, data):
        return len(data)

    sendall = send

    def recv(self, _n):
        return self.reply

    def settimeout(self, _t):
        pass

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        self.close()


def _endpoint(url):
    parts = urlsplit(url)
    return parts.hostname, parts.port or _DEFAULT_PORT[parts.scheme]


def _run(monkeypatch, recon, live, sockets=None, redirects=None, resolve=None, roe=None):
    """run_security_checks on a faked network. Returns (result, requests, sockets)."""
    sent, opened = [], []
    sockets, redirects, resolve = sockets or {}, redirects or {}, resolve or {}

    def request(self, method, url, *a, allow_redirects=True, **k):
        history = []
        while True:
            sent.append((method.upper(), url))
            if _endpoint(url) not in live:
                raise requests.exceptions.ConnectionError(f"refused: {url}")
            resp = _response(url, redirects.get(url))
            if not (allow_redirects and resp.is_redirect):
                resp.history = history
                return resp
            history.append(resp)
            url = urljoin(url, resp.headers["Location"])

    def getaddrinfo(host, *a, **k):
        if host in resolve:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in resolve[host]]
        raise socket.gaierror(f"no such name: {host}")

    def connect(address, *a, **k):
        host, port = address[0], address[1]
        opened.append((host, port))
        if (host, port) in sockets:
            return _Sock(sockets[(host, port)])
        raise ConnectionRefusedError(f"refused: {host}:{port}")

    monkeypatch.setattr(requests.sessions.Session, "request", request)
    monkeypatch.setattr(sc.socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(sc.socket, "create_connection", connect)
    for name in ("collect_reliable_edge_ips", "collect_asn_cdn_ips", "collect_prefix_cdn_ips"):
        monkeypatch.setattr(sc, name, lambda *a, **k: set())
    with mock.patch.object(sc, "time") as fake_time:
        fake_time.time.side_effect = _time.time
        fake_time.monotonic.side_effect = _time.monotonic
        fake_time.sleep = lambda *_a, **_k: None
        result = sc.run_security_checks(recon, _Every(), timeout=1, max_workers=2,
                                        roe_excluded_hosts=roe)
    return result, sent, opened


def _to(sent, opened, host, port):
    return ([url for _m, url in sent if _endpoint(url) == (host, port)]
            + [f"socket {h}:{p}" for h, p in opened if (h, p) == (host, port)])


def _reached(sent, opened, host):
    return ([url for _m, url in sent if urlsplit(url).hostname == host]
            + [f"socket {h}:{p}" for h, p in opened if h == host])


@pytest.fixture(autouse=True)
def _fresh_run():
    circuit_breaker.reset_registry()
    yield
    circuit_breaker.reset_registry()


# ---------------------------------------------------------------------------
# The S-28 case: an HTTP-only subdomain beside an HTTPS-only one
# ---------------------------------------------------------------------------

def test_http_only_subdomain_gets_no_https_probe_and_is_not_noted_unreachable(monkeypatch):
    result, sent, opened = _run(monkeypatch, _lab(), _LAB_LIVE,
                                sockets={(PLAIN_IP, 6379): b"-NOAUTH Authentication required.\r\n"})

    # Nothing the run never found live is probed, by name or by address.
    for host, port in ((PLAIN, 443), (PLAIN_IP, 443), (SECURE, 80), (SECURE_IP, 80)):
        assert _to(sent, opened, host, port) == [], f"{host}:{port} was probed blind"

    # Each host is still checked on what it serves.
    plain_paths = {urlsplit(u).path for u in _to(sent, opened, PLAIN, 80)}
    assert {"/login", "/"} <= plain_paths                     # login_no_https, basic_auth_no_tls
    assert ("GET", f"https://{SECURE}/") in sent              # header, cookie, CSP and form checks
    assert f"socket {SECURE}:443" in _to(sent, opened, SECURE, 443)   # the TLS expiry check
    assert ("GET", f"http://{PLAIN_IP}") in sent              # direct_ip_http
    assert ("GET", f"https://{SECURE_IP}") in sent            # direct_ip_https
    # The WAF bypass pairs only a name and an address both live on :443.
    assert any(_endpoint(u) == (SECURE_IP, 443) and "rdmnwafprobe" in u for _m, u in sent)

    # No failure was counted: nothing is unreachable, nothing is held back.
    assert circuit_breaker.host_health.unreachable() == []
    assert "unreachable_hosts" not in result["security_checks"]
    report = circuit_breaker.coverage_report()
    assert report.skipped_hosts == ()
    assert set(report.keep_hostnames("security_check")) == set()
    assert PLAIN_IP in report.checked_hostnames("security_check", "redis_no_auth")


def test_https_only_address_gets_none_of_the_seven_api_probes(monkeypatch):
    api_paths = {"/api", "/api/v1", "/api/v2", "/graphql", "/rest", "/v1", "/v2"}
    _result, sent, _opened = _run(monkeypatch, _lab(), _LAB_LIVE)

    # check_ip_api_exposed asks http://<ip><path>; the Kubernetes check's
    # https://<ip>:443/api on the open TLS port is evidence-based and stays.
    assert [u for _m, u in sent if _endpoint(u) == (SECURE_IP, 80)
            and urlsplit(u).path in api_paths] == []
    assert ("GET", f"https://{SECURE_IP}:443/api") in sent
    # The HTTP-only address is still asked for its API paths.
    assert {f"http://{PLAIN_IP}{p}" for p in api_paths} <= {u for _m, u in sent}


def test_a_port_live_on_an_address_is_live_on_every_name_resolving_to_it(monkeypatch):
    """A name the port scan lists under no row of its own reaches the same TCP
    endpoint as its address: a TLS port open there is one it serves."""
    recon = _domain({SECURE: [SECURE_IP], SHARED: [SECURE_IP]},
                    ports={SECURE_IP: [443]}, urls=[f"https://{SECURE}"])
    recon["port_scan"]["by_ip"][SECURE_IP]["hostnames"] = [SECURE]
    _result, sent, opened = _run(monkeypatch, recon, {(SECURE, 443), (SECURE_IP, 443), (SHARED, 443)})

    assert ("GET", f"https://{SHARED}/") in sent
    assert _to(sent, opened, SHARED, 80) == []
    assert circuit_breaker.coverage_report().skipped_hosts == ()


# ---------------------------------------------------------------------------
# No evidence for a host: not probed, kept as not checked
# ---------------------------------------------------------------------------

def test_a_name_with_no_evidence_is_not_probed_and_keeps_its_findings(monkeypatch):
    recon = _domain({PLAIN: [PLAIN_IP], LATE: [LATE_IP]},
                    ports={PLAIN_IP: [80]}, urls=[f"http://{PLAIN}"])
    result, sent, opened = _run(monkeypatch, recon, {(PLAIN, 80), (PLAIN_IP, 80)})

    assert _reached(sent, opened, LATE) == []
    assert _reached(sent, opened, LATE_IP) == []
    assert _to(sent, opened, PLAIN, 80), "the host with evidence was not checked"
    report = circuit_breaker.coverage_report()
    assert {LATE, LATE_IP} <= set(report.keep_hostnames("security_check"))
    # Kept for the security checks alone, and never reported as unreachable.
    assert {LATE, LATE_IP} & set(report.keep_hostnames("nuclei")) == set()
    assert PLAIN not in report.keep_hostnames("security_check")
    assert circuit_breaker.host_health.unreachable() == []
    assert "unreachable_hosts" not in result["security_checks"]


def _httpx_over_budget():
    circuit_breaker.note_degraded("http_probe", sources=["http_probe"],
                                  reason="httpx runtime budget reached")


def test_a_cut_source_keeps_a_host_whose_web_port_is_unproven(monkeypatch):
    """httpx reached plain's :80 and then hit its budget; the port scan failed.
    Plain's :443 was never measured, so its HTTPS findings are not judged."""
    recon = _domain({PLAIN: [PLAIN_IP]}, urls=[f"http://{PLAIN}"])
    recon["metadata"]["phase_errors"] = {"port_scan": "the phase failed"}
    _httpx_over_budget()
    result, sent, opened = _run(monkeypatch, recon, {(PLAIN, 80), (PLAIN_IP, 80)})

    assert _to(sent, opened, PLAIN, 443) == []
    assert _to(sent, opened, PLAIN, 80)
    report = circuit_breaker.coverage_report()
    assert {PLAIN, PLAIN_IP} <= set(report.keep_hostnames("security_check"))
    assert "unreachable_hosts" not in result["security_checks"]


def test_a_finished_port_scan_is_a_verdict_even_when_httpx_was_cut(monkeypatch):
    _httpx_over_budget()
    _result, sent, opened = _run(monkeypatch, _lab(), _LAB_LIVE)

    assert _to(sent, opened, PLAIN, 443) == []
    assert set(circuit_breaker.coverage_report().keep_hostnames("security_check")) == set()


def test_a_run_that_measured_nothing_live_probes_as_before(monkeypatch):
    """No port scan and no httpx data: nothing to steer by, so the checks run
    as they always did (a refused port there counts, as it always did)."""
    recon = _domain({SECURE: [SECURE_IP]})
    _result, sent, opened = _run(monkeypatch, recon, {(SECURE, 443), (SECURE_IP, 443)})

    assert ("GET", f"https://{SECURE}/") in sent
    assert _to(sent, opened, SECURE, 80), "the blind :80 probes are what this run always sent"
    assert sc._DOMAIN_LIVE_PORTS is None


# ---------------------------------------------------------------------------
# The evidence and the gate
# ---------------------------------------------------------------------------

def test_live_ports_come_from_open_ports_live_urls_and_dns():
    recon = _domain({PLAIN: [PLAIN_IP], SECURE: [SECURE_IP], SHARED: [SECURE_IP], LATE: [LATE_IP]},
                    ports={PLAIN_IP: [80, 6379]}, urls=[f"https://{SECURE}:8443/app"])
    recon["port_scan"]["by_host"] = {SECURE: {"ip": SECURE_IP, "ports": [443]}}
    live = {h: set(p) for h, p in sc._domain_live_ports(recon).items()}
    assert live[PLAIN] == live[PLAIN_IP] == {80, 6379}
    # naabu's 443 by name and httpx's 8443 both landed on SECURE_IP, so a name
    # sharing that address shares them.
    assert live[SECURE] == live[SECURE_IP] == live[SHARED] == {443, 8443}
    assert LATE not in live and LATE_IP not in live


def test_no_data_and_ip_mode_have_no_domain_evidence():
    assert sc._domain_live_ports(_domain({PLAIN: [PLAIN_IP]})) is None
    assert sc._domain_live_ports(_domain({PLAIN: [PLAIN_IP]}, ports={}, urls=[])) is None
    ip_mode = _domain({PLAIN: [PLAIN_IP]}, ports={PLAIN_IP: [80]})
    ip_mode["metadata"].update(ip_mode=True, expanded_ips=[PLAIN_IP])
    assert sc._domain_live_ports(ip_mode) is None


def test_the_gate_reads_names_and_addresses_in_any_spelling(monkeypatch):
    monkeypatch.setattr(sc, "_DOMAIN_LIVE_PORTS", {PLAIN: frozenset({80}), "2001:db8::5": frozenset({443})})
    assert sc._ip_port_live(PLAIN, 80)
    assert sc._ip_port_live("Plain.Example.com.", 80)
    assert not sc._ip_port_live(PLAIN, 443)
    assert not sc._ip_port_live(LATE, 80)
    assert sc._ip_port_live("[2001:0db8::5]", 443)
    monkeypatch.setattr(sc, "_DOMAIN_LIVE_PORTS", None)
    assert sc._ip_port_live(LATE, 443), "with no evidence map nothing is gated"


def test_a_domain_run_never_sets_the_ip_mode_gate_and_clears_its_own(monkeypatch):
    seen = {}
    real = sc.run_direct_ip_checks

    def spy(*a, **k):
        seen.update(ip_live=sc._IP_LIVE_PORTS, ip_admit=sc._IP_MODE_ADMIT, domain=sc._DOMAIN_LIVE_PORTS)
        return real(*a, **k)

    monkeypatch.setattr(sc, "run_direct_ip_checks", spy)
    _run(monkeypatch, _lab(), _LAB_LIVE)
    assert seen["ip_live"] is None and seen["ip_admit"] is None
    assert seen["domain"] is not None
    assert sc._DOMAIN_LIVE_PORTS is None, "the run's evidence leaked past run_security_checks"
