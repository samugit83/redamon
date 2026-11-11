"""IP mode: a security check probes a target address only on a port the run found live.

Since P0b (B-13) the hostname, header and TLS checks get each target as an IP
literal. They probed https://<ip> and http://<ip> blind: on an address that
serves HTTP only, three refused :443 connections marked "<ip>:443" unreachable,
and the prune then kept every source's findings on that address, so a fixed
redis_no_auth or a renewed certificate's tls_expired never went away.

The evidence is the run's own: the port scan's open ports and httpx's live URLs
for the address. A check whose port has neither is not sent, counts no failure
and notes nothing. Domain mode is untouched. Documentation addresses (RFC 5737,
RFC 3849) and reserved names only.
"""
import socket
import sys
import time as _time
from collections import Counter
from pathlib import Path
from unittest import mock
from urllib.parse import urljoin, urlsplit

import pytest
import requests

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers import circuit_breaker  # noqa: E402
from recon.helpers import security_checks as sc  # noqa: E402

T_HTTP, T_TLS, T_NONE = "203.0.113.10", "203.0.113.20", "203.0.113.30"
V6 = "2001:db8::5"
NAME, NAME_IP = "www.example.com", "198.51.100.7"
OUTSIDE, OUTSIDE_IP = "outside.example", "198.51.100.7"
PTR = "ptr.example.com"
_DEFAULT_PORT = {"http": 80, "https": 443}


class _Every(dict):
    """Every check on, except the org DNS checks, which would ask a real resolver."""

    def get(self, key, default=None):
        return key not in sc.DNS_CHECK_TYPES


def _mock_entry(ip):
    v6 = ":" in ip
    return {"has_records": True, "is_mock": True, "actual_ip": ip, "records": {},
            "ips": {"ipv4": [] if v6 else [ip], "ipv6": [ip] if v6 else []}}


def _ip_recon(targets, ports=None, urls=None):
    """GROUP 1's IP-mode shape, plus the port scan and httpx sections when given."""
    from recon.helpers.ip_placeholders import placeholder_for
    subs = {placeholder_for(ip): _mock_entry(ip) for ip in targets}
    recon = {
        "domain": "ip-targets.p1",
        "metadata": {"ip_mode": True, "expanded_ips": list(targets), "root_domain": "ip-targets.p1",
                     "scope_mode": "exact", "include_root_domain": False, "filtered_mode": True,
                     "subdomain_filter": [*targets, *subs]},
        "subdomains": list(subs),
        "dns": {"domain": {}, "subdomains": subs},
    }
    if ports is not None:
        recon["port_scan"] = {"by_ip": {ip: {"ip": ip, "ports": list(p), "hostnames": []}
                                        for ip, p in ports.items()}}
    if urls is not None:
        recon["http_probe"] = {"by_url": {
            u: (urls[u] if isinstance(urls, dict) else
                {"url": u, "host": urlsplit(u).hostname, "status_code": 200})
            for u in urls}}
    return recon


def _response(url, location=None):
    # No password field, no JSON, no cookie: nothing here triggers a catch-all
    # control probe, whose random path would make two runs differ.
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
    """run_security_checks with the network faked: a request to a live
    (host, port) gets a 200 page, or a 302 to ``redirects[url]``; any other one
    is refused, as a closed port refuses it. A call that lets requests follow
    redirects follows them here too, every hop recorded, since Session.request
    is the method replaced. Names resolve through ``resolve`` only. Returns
    (result, requests sent, sockets opened)."""
    sent, opened = [], []
    sockets, redirects, resolve = sockets or {}, redirects or {}, resolve or {}

    def request(self, method, url, *a, allow_redirects=True, **k):
        history = []
        while True:
            sent.append((method.upper(), url))   # requests.get passes "get"
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

    monkeypatch.setattr(sc.socket, "getaddrinfo", getaddrinfo)

    def connect(address, *a, **k):
        host, port = address[0], address[1]
        opened.append((host, port))
        if (host, port) in sockets:
            return _Sock(sockets[(host, port)])
        raise ConnectionRefusedError(f"refused: {host}:{port}")

    monkeypatch.setattr(requests.sessions.Session, "request", request)
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
    """Every request and socket the run sent to host:port."""
    return ([url for _m, url in sent if _endpoint(url) == (host, port)]
            + [f"socket {h}:{p}" for h, p in opened if (h, p) == (host, port)])


@pytest.fixture(autouse=True)
def _fresh_run():
    circuit_breaker.reset_registry()
    yield
    circuit_breaker.reset_registry()


# ---------------------------------------------------------------------------
# The lab case: an HTTP-only address beside a TLS address
# ---------------------------------------------------------------------------

def test_http_only_target_gets_no_https_probe_and_is_not_noted_unreachable(monkeypatch):
    recon = _ip_recon([T_HTTP, T_TLS],
                      ports={T_HTTP: [80, 6379], T_TLS: [443]},
                      urls=[f"http://{T_HTTP}", f"https://{T_TLS}"])
    result, sent, opened = _run(
        monkeypatch, recon, live={(T_HTTP, 80), (T_TLS, 443)},
        sockets={(T_HTTP, 6379): b"-NOAUTH Authentication required.\r\n"})

    # Nothing the run never found live is probed.
    assert _to(sent, opened, T_HTTP, 443) == []
    assert _to(sent, opened, T_TLS, 80) == []

    # Each address is still checked on what it serves.
    http_paths = {urlsplit(u).path for u in _to(sent, opened, T_HTTP, 80)}
    assert {"/login", "/"} <= http_paths            # login_no_https, basic_auth_no_tls
    assert f"socket {T_TLS}:443" in _to(sent, opened, T_TLS, 443)   # the TLS expiry check
    assert ("GET", f"https://{T_TLS}/") in sent     # header, cookie, CSP and form checks

    # No failure was counted, so no host is unreachable and nothing is kept.
    assert circuit_breaker.host_health.unreachable() == []
    assert "unreachable_hosts" not in result["security_checks"]
    report = circuit_breaker.coverage_report()
    assert report.skipped_hosts == ()
    assert T_HTTP not in report.keep_hostnames("security_check")
    # The RD-05 case: Redis answered with a verdict, so a stale redis_no_auth
    # on this address is pruned instead of kept behind a false :443 mark.
    assert T_HTTP in report.checked_hostnames("security_check", "redis_no_auth")
    assert sc._IP_LIVE_PORTS is None, "the run's evidence leaked past run_security_checks"


def test_target_with_no_live_port_or_url_is_not_probed_and_not_noted(monkeypatch):
    """No evidence for an address means the scanners that cover every target
    found nothing live there (a cut scan notes its own hosts): the web checks
    have nothing to probe, and like the port checks of an address the scan did
    not list they note nothing, so the prune applies its source-level rule."""
    recon = _ip_recon([T_HTTP, T_NONE], ports={T_HTTP: [80]}, urls=[f"http://{T_HTTP}"])
    result, sent, opened = _run(monkeypatch, recon, live={(T_HTTP, 80)})

    assert [u for _m, u in sent if urlsplit(u).hostname == T_NONE] == []
    assert [a for a in opened if a[0] == T_NONE] == []
    assert _to(sent, opened, T_HTTP, 80), "the address with a live port was not checked"
    assert circuit_breaker.host_health.unreachable() == []
    assert "unreachable_hosts" not in result["security_checks"]
    report = circuit_breaker.coverage_report()
    assert report.skipped_hosts == ()
    assert T_NONE not in report.keep_hostnames("security_check")


def test_run_with_no_port_or_url_data_probes_no_target_and_keeps_them(monkeypatch):
    """A naabu that fails outright returns no section and notes nothing, and
    httpx may be off: with neither section the evidence is unknown, not empty,
    so the targets are kept, as a cut source keeps them."""
    recon = _ip_recon([T_HTTP, T_TLS])
    result, sent, opened = _run(monkeypatch, recon, live={(T_HTTP, 80), (T_TLS, 443)})

    assert [u for _m, u in sent if urlsplit(u).hostname in (T_HTTP, T_TLS)] == []
    assert [a for a in opened if a[0] in (T_HTTP, T_TLS)] == []
    report = circuit_breaker.coverage_report()
    assert set(report.keep_hostnames("security_check")) == {T_HTTP, T_TLS}
    assert T_TLS not in report.keep_hostnames("nuclei")
    assert "unreachable_hosts" not in result["security_checks"]


# ---------------------------------------------------------------------------
# A cut evidence source: what it never reached is kept, not pruned
# ---------------------------------------------------------------------------

def _naabu_cut_before_writing(targets):
    from recon.main_recon_modules.port_scan import _note_naabu_cut
    _note_naabu_cut(list(targets), list(targets), False, "naabu timed out after 600s")


def _httpx_over_budget():
    # The note http_probe's over-budget stop records (and nothing per host).
    circuit_breaker.note_degraded("http_probe", sources=["http_probe"],
                                  reason="httpx runtime budget reached")


@pytest.mark.parametrize("cut", ["naabu-cut-and-httpx-over-budget", "port-scan-phase-error"])
def test_target_a_cut_source_left_without_evidence_is_kept_not_probed(monkeypatch, cut):
    """naabu stopped before writing a port, and httpx reached T_HTTP's port 80
    but never T_TLS. T_TLS is live and was never checked, so its findings must
    survive the prune; T_HTTP's :443 is unproven too, with no port scan to say
    it is closed."""
    recon = _ip_recon([T_HTTP, T_TLS], urls=[f"http://{T_HTTP}"])
    if cut == "port-scan-phase-error":
        recon["metadata"]["phase_errors"] = {"port_scan": "the phase failed"}
    else:
        _naabu_cut_before_writing([T_HTTP, T_TLS])
        _httpx_over_budget()
    result, sent, opened = _run(monkeypatch, recon, live={(T_HTTP, 80), (T_TLS, 443)})

    assert [u for _m, u in sent if urlsplit(u).hostname == T_TLS] == []
    assert [a for a in opened if a[0] == T_TLS] == []
    assert _to(sent, opened, T_HTTP, 80), "the evidence it has is still checked"
    report = circuit_breaker.coverage_report()
    assert {T_TLS, T_HTTP} <= set(report.keep_hostnames("security_check"))
    # Kept for security_check alone, and never reported as unreachable.
    assert T_TLS not in report.keep_hostnames("nuclei")
    assert "unreachable_hosts" not in result["security_checks"]


def test_httpx_over_budget_keeps_what_has_no_evidence_but_trusts_a_finished_port_scan(monkeypatch):
    """naabu finished: a port it did not list is closed, whatever httpx did.
    Only the target with no evidence at all is kept."""
    recon = _ip_recon([T_HTTP, T_TLS, T_NONE], ports={T_HTTP: [80, 6379], T_TLS: [443]},
                      urls=[f"http://{T_HTTP}"])
    _httpx_over_budget()
    _result, sent, opened = _run(
        monkeypatch, recon, live={(T_HTTP, 80), (T_TLS, 443)},
        sockets={(T_HTTP, 6379): b"-NOAUTH Authentication required.\r\n"})

    assert _to(sent, opened, T_HTTP, 443) == []
    assert ("GET", f"https://{T_TLS}/") in sent
    report = circuit_breaker.coverage_report()
    assert set(report.keep_hostnames("security_check")) == {T_NONE}
    assert T_HTTP in report.checked_hostnames("security_check", "redis_no_auth")


@pytest.mark.parametrize("ports, urls", [
    pytest.param({T_TLS: [443]}, None, id="port-scan-only"),
    pytest.param(None, [f"https://{T_TLS}"], id="httpx-only"),
])
def test_either_source_alone_is_evidence(monkeypatch, ports, urls):
    recon = _ip_recon([T_TLS], ports=ports, urls=urls)
    _result, sent, opened = _run(monkeypatch, recon, live={(T_TLS, 443)})

    assert ("GET", f"https://{T_TLS}/") in sent
    assert f"socket {T_TLS}:443" in _to(sent, opened, T_TLS, 443)
    assert _to(sent, opened, T_TLS, 80) == []
    assert circuit_breaker.coverage_report().skipped_hosts == ()


def test_ipv6_target_matches_its_port_scan_entry_in_any_spelling(monkeypatch):
    recon = _ip_recon([V6], ports={"2001:0db8:0000::5": [80]})
    _result, sent, opened = _run(monkeypatch, recon, live={(V6, 80)})

    assert ("GET", f"http://[{V6}]/login") in sent
    assert _to(sent, opened, V6, 443) == []
    assert circuit_breaker.coverage_report().skipped_hosts == ()


# ---------------------------------------------------------------------------
# Redirect hops (I-1): a chain the checks follow stays on the targets
# ---------------------------------------------------------------------------

def _direct_http_finding(result, ip):
    return next(f for f in result["security_checks"]["findings"]
                if f["type"] == "direct_ip_http" and f["matched_ip"] == ip)


@pytest.mark.parametrize("location, in_scope", [
    pytest.param(f"http://{OUTSIDE}/", False, id="unknown-name"),
    pytest.param(f"http://{OUTSIDE}/", True, id="scope-name-resolving-outside"),
    pytest.param(f"http://{OUTSIDE_IP}/", False, id="address-outside"),
])
def test_redirect_hop_outside_the_targets_is_never_sent(monkeypatch, location, in_scope):
    recon = _ip_recon([T_HTTP], ports={T_HTTP: [80]}, urls=[f"http://{T_HTTP}"])
    if in_scope:
        recon["metadata"]["subdomain_filter"].append(OUTSIDE)
    # The outside host answers, so a leak would show as a request, not a refusal.
    result, sent, opened = _run(
        monkeypatch, recon, live={(T_HTTP, 80), (OUTSIDE, 80), (OUTSIDE_IP, 80)},
        redirects={f"http://{T_HTTP}": location}, resolve={OUTSIDE: [OUTSIDE_IP]})

    assert [u for _m, u in sent if urlsplit(u).hostname in (OUTSIDE, OUTSIDE_IP)] == []
    assert [a for a in opened if a[0] in (OUTSIDE, OUTSIDE_IP)] == []
    # The check reports what it saw: the target redirects there.
    finding = _direct_http_finding(result, T_HTTP)
    assert finding["redirects"] is True
    assert finding["final_url"] == location
    assert circuit_breaker.host_health.unreachable() == []
    assert circuit_breaker.coverage_report().skipped_hosts == ()
    assert sc._IP_MODE_ADMIT is None, "the run's admission rule leaked past run_security_checks"


def test_a_chain_follows_admitted_hops_and_stops_at_the_first_refused_one(monkeypatch):
    recon = _ip_recon([T_HTTP], ports={T_HTTP: [80]}, urls=[f"http://{T_HTTP}"])
    recon["metadata"]["subdomain_filter"].append(PTR)
    result, sent, _opened = _run(
        monkeypatch, recon, live={(T_HTTP, 80), (PTR, 80), (OUTSIDE, 80)},
        redirects={f"http://{T_HTTP}": f"http://{PTR}/", f"http://{PTR}/": f"http://{OUTSIDE}/"},
        resolve={PTR: [T_HTTP], OUTSIDE: [OUTSIDE_IP]})

    # A scope name whose every address is a target is a hop like the target itself.
    assert ("GET", f"http://{PTR}/") in sent
    assert [u for _m, u in sent if urlsplit(u).hostname == OUTSIDE] == []
    finding = _direct_http_finding(result, T_HTTP)
    assert finding["final_url"] == f"http://{OUTSIDE}/"
    assert finding["redirects_to_hostname"] is True
    assert "(2 redirect(s))" in finding["evidence"]


def test_redirect_hop_to_a_name_the_roe_excludes_is_not_sent(monkeypatch, capsys):
    """ptr.example.com passes the target rule (its address is a target), but
    the Rules of Engagement exclude it by name (I-3)."""
    recon = _ip_recon([T_HTTP], ports={T_HTTP: [80]}, urls=[f"http://{T_HTTP}"])
    recon["metadata"]["subdomain_filter"].append(PTR)
    result, sent, _opened = _run(
        monkeypatch, recon, live={(T_HTTP, 80), (PTR, 80)},
        redirects={f"http://{T_HTTP}": f"http://{PTR}/"}, resolve={PTR: [T_HTTP]}, roe=[PTR])

    assert [u for _m, u in sent if urlsplit(u).hostname == PTR] == []
    assert _direct_http_finding(result, T_HTTP)["final_url"] == f"http://{PTR}/"
    assert circuit_breaker.host_health.unreachable() == []
    # The refusal is the security checks', in the log and in the coverage record.
    assert "[-][RoE] security_checks: not sent to 1 target(s)" in capsys.readouterr().out
    modules = {g["module"] for g in circuit_breaker.coverage_report().gaps
               if g["source"] == "roe_excluded"}
    assert modules == {"security_checks"}


@pytest.mark.parametrize("module, expected", [
    pytest.param({}, "js_recon", id="default"),
    pytest.param({"module": "security_checks"}, "security_checks", id="caller-named"),
])
def test_hop_refusal_records_an_roe_refusal_under_its_caller(module, expected):
    from recon.helpers.js_recon import hop_guard
    roe = {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": [PTR]}
    assert hop_guard.hop_refusal(f"http://{PTR}/", settings=roe, url_guard=lambda _u: True,
                                 **module) == hop_guard.ROE_EXCLUDED
    assert {g["module"] for g in circuit_breaker.coverage_report().gaps} == {expected}


def test_a_chain_that_stays_on_admitted_hosts_ends_where_requests_ended_it(monkeypatch):
    recon = _ip_recon([T_HTTP], ports={T_HTTP: [80]}, urls=[f"http://{T_HTTP}"])
    recon["metadata"]["subdomain_filter"].append(PTR)
    result, sent, _opened = _run(
        monkeypatch, recon, live={(T_HTTP, 80), (PTR, 80)},
        redirects={f"http://{T_HTTP}": f"http://{PTR}/"}, resolve={PTR: [T_HTTP]})

    finding = _direct_http_finding(result, T_HTTP)
    assert finding["final_url"] == f"http://{PTR}/"
    assert "(1 redirect(s))" in finding["evidence"]


# ---------------------------------------------------------------------------
# The evidence and the gate
# ---------------------------------------------------------------------------

def test_live_ports_come_from_open_ports_and_live_urls():
    recon = _ip_recon([T_HTTP, T_TLS, V6], ports={T_HTTP: [80, 6379]}, urls={
        f"https://{T_TLS}:8443/app": {"url": f"https://{T_TLS}:8443/app", "status_code": 403},
        # A name's URL proves the port on the address httpx reached.
        f"https://{NAME}": {"url": f"https://{NAME}", "host": NAME, "ip": T_TLS},
        "http://[2001:0db8::5]": {"url": "http://[2001:0db8::5]"},
        f"ftp://{T_HTTP}": {"url": f"ftp://{T_HTTP}"},
    })
    live = sc._ip_mode_live_ports(recon)
    assert {ip: set(ports) for ip, ports in live.items()} == {
        T_HTTP: {80, 6379}, T_TLS: {443, 8443}, V6: {80}}


def test_domain_mode_has_no_evidence_gate():
    recon = {"domain": "example.com", "metadata": {"ip_mode": False},
             "port_scan": {"by_ip": {NAME_IP: {"ip": NAME_IP, "ports": [80]}}}}
    assert sc._ip_mode_live_ports(recon) is None


def test_gate_refuses_only_an_unproven_port_of_an_ip_literal(monkeypatch):
    monkeypatch.setattr(sc, "_IP_LIVE_PORTS", {T_HTTP: frozenset({80}), V6: frozenset({443})})
    assert sc._ip_port_live(T_HTTP, 80)
    assert not sc._ip_port_live(T_HTTP, 443)
    assert not sc._ip_port_live(T_NONE, 80)
    assert sc._ip_port_live("2001:0db8::5", 443)
    assert sc._ip_port_live(f"[{V6}]", 443)
    assert sc._ip_port_live(NAME, 443), "a name is probed as before"
    monkeypatch.setattr(sc, "_IP_LIVE_PORTS", None)
    assert sc._ip_port_live(T_NONE, 443), "outside IP mode nothing is gated"


# ---------------------------------------------------------------------------
# Domain mode: never the IP-mode gate. Its own evidence rule (S-28) is pinned
# in test_security_checks_domain_live_ports.py.
# ---------------------------------------------------------------------------

def _domain_recon():
    return {
        "domain": "example.com",
        "metadata": {"ip_mode": False, "root_domain": "example.com"},
        "subdomains": [NAME],
        "dns": {"domain": {}, "subdomains": {NAME: {
            "has_records": True, "ips": {"ipv4": [NAME_IP], "ipv6": []}}}},
        # The scan and httpx found HTTP only.
        "port_scan": {"by_ip": {NAME_IP: {"ip": NAME_IP, "ports": [80], "hostnames": [NAME]}}},
        "http_probe": {"by_url": {f"http://{NAME}": {"url": f"http://{NAME}", "host": NAME,
                                                   "ip": NAME_IP, "status_code": 200}}},
    }


_EVERYTHING = {(NAME, 80), (NAME, 443), (NAME_IP, 80), (NAME_IP, 443), (OUTSIDE, 80)}


@pytest.mark.parametrize("redirects", [
    pytest.param({}, id="no-redirect"),
    pytest.param({f"http://{NAME_IP}": f"http://{OUTSIDE}/"}, id="ip-redirects-to-another-name"),
])
def test_domain_mode_never_runs_the_ip_mode_gate(monkeypatch, redirects):
    seen = []
    real = sc._run_security_checks

    def spy(*a, **k):
        seen.append((sc._IP_LIVE_PORTS, sc._IP_MODE_ADMIT))
        return real(*a, **k)

    monkeypatch.setattr(sc, "_run_security_checks", spy)
    _r, sent, opened = _run(monkeypatch, _domain_recon(), live=_EVERYTHING, redirects=redirects)
    circuit_breaker.reset_registry()
    # The same run with the IP-mode rule builders switched off outright.
    monkeypatch.setattr(sc, "_ip_mode_live_ports", lambda *_a, **_k: None)
    monkeypatch.setattr("recon.helpers.target_admission.ip_mode_url_admission",
                        lambda *_a, **_k: None)
    _r, sent_off, opened_off = _run(monkeypatch, _domain_recon(), live=_EVERYTHING,
                                    redirects=redirects)

    assert seen == [(None, None), (None, None)]
    assert Counter(sent) == Counter(sent_off)
    assert Counter(opened) == Counter(opened_off)
    # S-28: on HTTP-only evidence the name is checked over HTTP and never
    # probed blind on :443, so no refusal marks it unreachable.
    assert ("GET", f"http://{NAME}/login") in sent
    assert ("GET", f"https://{NAME}/") not in sent
    assert (NAME, 443) not in opened
    assert not any(_endpoint(u) == (NAME_IP, 443) for _m, u in sent)
    assert circuit_breaker.host_health.unreachable() == []


def test_domain_mode_still_lets_requests_follow_a_redirect_anywhere(monkeypatch):
    walked = []
    monkeypatch.setattr(sc, "_follow_admitted_redirects",
                        lambda *a, **_k: walked.append(a) or (a[0], 0), raising=False)
    result, sent, _opened = _run(monkeypatch, _domain_recon(), live=_EVERYTHING,
                                 redirects={f"http://{NAME_IP}": f"http://{OUTSIDE}/"})

    assert walked == []
    assert ("GET", f"http://{OUTSIDE}/") in sent
    finding = _direct_http_finding(result, NAME_IP)
    assert finding["final_url"] == f"http://{OUTSIDE}/"
    assert "(1 redirect(s))" in finding["evidence"]
