"""A deliberate refusal is not a cut of the live-port evidence (S-28, IP mode).

_evidence_cuts read every coverage gap whose source or module named an
evidence scanner as a cut. The RoE refusal naabu records for an excluded
target ({"source": "roe_excluded", "module": "naabu"}) is no cut: naabu
scanned every target it was allowed to, so its port list is still a verdict.
Counted as one, it denied the port scan that verdict, and every host without
both :80 and :443 live, an HTTP-only one among them, was kept as unproven: its
security_check findings were never pruned and the coverage record named the
whole host as skipped. The httpx fingerprint gaps the RoE ceiling records
(httpx_jarm, httpx_favicon) are the same: httpx still probed every URL.

Only the sources listed as deliberate refusals are exempt. Any other gap under
an evidence scanner, a new one included, still counts as a cut, so an unknown
gap keeps findings rather than pruning them.

The refusals are recorded by the real builders (port_scan's target
extraction through the RoE gate, http_probe's ceiling note); the network is
faked at requests' Session and socket.create_connection. Documentation ranges
and reserved names only.
"""
import socket
import sys
import time as _time
from pathlib import Path
from unittest import mock
from urllib.parse import urlsplit

import pytest
import requests

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers import circuit_breaker  # noqa: E402
from recon.helpers import security_checks as sc  # noqa: E402

APEX = "example.com"
PLAIN, PLAIN_IP = "plain.example.com", "192.0.2.10"        # serves HTTP only
SECURE, SECURE_IP = "secure.example.com", "192.0.2.20"     # serves HTTPS only
EDGE, EDGE_IP = "edge.example.com", "198.51.100.62"        # only an excluded address
EXCLUDED = f"{EDGE_IP}/32"
ROE = {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": [EXCLUDED]}

T_HTTP, T_TLS = "203.0.113.10", "203.0.113.20"             # IP mode: HTTP only, HTTPS only
_DEFAULT_PORT = {"http": 80, "https": 443}


class _Every(dict):
    """Every check on, except the org DNS checks, which would ask a real resolver."""

    def get(self, key, default=None):
        return key not in sc.DNS_CHECK_TYPES


def _sub(*ips):
    return {"has_records": True, "ips": {"ipv4": list(ips), "ipv6": []}}


def _domain_run(with_port_scan=True):
    """The nested-lab shape: an HTTP-only and an HTTPS-only subdomain the port
    scan and httpx reached, and a name on an address the RoE excludes, which
    naabu was never sent."""
    names = {PLAIN: [PLAIN_IP], SECURE: [SECURE_IP], EDGE: [EDGE_IP]}
    recon = {
        "domain": APEX,
        "metadata": {"include_root_domain": False, "root_domain": APEX},
        "subdomains": list(names),
        "dns": {"domain": {}, "subdomains": {n: _sub(*a) for n, a in names.items()}},
        "http_probe": {"by_url": {
            f"http://{PLAIN}": {"url": f"http://{PLAIN}", "host": PLAIN, "ip": PLAIN_IP,
                                "status_code": 200},
            f"https://{SECURE}": {"url": f"https://{SECURE}", "host": SECURE, "ip": SECURE_IP,
                                  "status_code": 200}}},
    }
    if with_port_scan:
        recon["port_scan"] = {"by_ip": {
            PLAIN_IP: {"ip": PLAIN_IP, "ports": [80], "hostnames": [PLAIN]},
            SECURE_IP: {"ip": SECURE_IP, "ports": [443], "hostnames": [SECURE]}}}
    return recon


def _mock_entry(ip):
    return {"has_records": True, "is_mock": True, "actual_ip": ip, "records": {},
            "ips": {"ipv4": [ip], "ipv6": []}}


def _ip_run():
    """IP mode: an HTTP-only and an HTTPS-only target, plus a name seen on a
    target whose other address the RoE excludes: naabu is not sent there."""
    from recon.helpers.ip_placeholders import placeholder_for
    targets = [T_HTTP, T_TLS]
    subs = {placeholder_for(ip): _mock_entry(ip) for ip in targets}
    subs[EDGE] = _sub(T_HTTP, EDGE_IP)
    return {
        "domain": "ip-targets.p1",
        "metadata": {"ip_mode": True, "expanded_ips": targets, "root_domain": "ip-targets.p1",
                     "scope_mode": "exact", "include_root_domain": False, "filtered_mode": True,
                     "subdomain_filter": [*targets, *subs]},
        "subdomains": list(subs),
        "dns": {"domain": {}, "subdomains": subs},
        "port_scan": {"by_ip": {T_HTTP: {"ip": T_HTTP, "ports": [80], "hostnames": []},
                                T_TLS: {"ip": T_TLS, "ports": [443], "hostnames": []}}},
        "http_probe": {"by_url": {
            f"http://{T_HTTP}": {"url": f"http://{T_HTTP}", "host": T_HTTP, "status_code": 200},
            f"https://{T_TLS}": {"url": f"https://{T_TLS}", "host": T_TLS, "status_code": 200}}},
    }


def _naabu_refusal(recon):
    """What port_scan records when its RoE gate refuses a target."""
    from recon.main_recon_modules.port_scan import extract_targets_from_recon
    ips, _names, _map = extract_targets_from_recon(recon, dict(ROE))
    assert EDGE_IP not in ips
    gaps = circuit_breaker.coverage_report().gaps
    assert any(g["source"] == "roe_excluded" and g["module"] == "naabu" for g in gaps), gaps


def _naabu_cut(targets):
    """What port_scan records when naabu times out before writing a port."""
    from recon.main_recon_modules.port_scan import _note_naabu_cut
    _note_naabu_cut(list(targets), list(targets), False, "naabu timed out after 600s")


def _fingerprints_not_collected():
    """What http_probe records when the RoE ceiling turns JARM and favicon off."""
    from recon.main_recon_modules.http_probe import _note_fingerprints_not_collected
    _note_fingerprints_not_collected({"ceiling": 5, "drop": ["jarm", "favicon"]}, 2)


def _response(url):
    resp = requests.Response()
    resp.status_code = 200
    resp.url = url
    resp.headers = requests.structures.CaseInsensitiveDict({"Content-Type": "text/html"})
    resp._content = b"<html><body>ok</body></html>"
    resp.encoding = "utf-8"
    return resp


def _endpoint(url):
    parts = urlsplit(url)
    return parts.hostname, parts.port or _DEFAULT_PORT[parts.scheme]


def _run(monkeypatch, recon, live, roe=(EXCLUDED,)):
    """run_security_checks on a faked network: a live (host, port) answers 200,
    any other is refused. Returns (result, requests sent, sockets opened)."""
    sent, opened = [], []

    def request(self, method, url, *a, **k):
        sent.append((method.upper(), url))
        if _endpoint(url) not in live:
            raise requests.exceptions.ConnectionError(f"refused: {url}")
        resp = _response(url)
        resp.history = []
        return resp

    def connect(address, *a, **k):
        opened.append((address[0], address[1]))
        raise ConnectionRefusedError(f"refused: {address[0]}:{address[1]}")

    def getaddrinfo(host, *a, **k):
        raise socket.gaierror(f"no resolver in this test: {host}")

    monkeypatch.setattr(requests.sessions.Session, "request", request)
    monkeypatch.setattr(sc.socket, "create_connection", connect)
    monkeypatch.setattr(sc.socket, "getaddrinfo", getaddrinfo)
    for name in ("collect_reliable_edge_ips", "collect_asn_cdn_ips", "collect_prefix_cdn_ips"):
        monkeypatch.setattr(sc, name, lambda *a, **k: set())
    with mock.patch.object(sc, "time") as fake_time:
        fake_time.time.side_effect = _time.time
        fake_time.monotonic.side_effect = _time.monotonic
        fake_time.sleep = lambda *_a, **_k: None
        result = sc.run_security_checks(recon, _Every(), timeout=1, max_workers=2,
                                        roe_excluded_hosts=list(roe))
    return result, sent, opened


def _to(sent, opened, host, port):
    return ([url for _m, url in sent if _endpoint(url) == (host, port)]
            + [f"socket {h}:{p}" for h, p in opened if (h, p) == (host, port)])


@pytest.fixture(autouse=True)
def _fresh_run():
    circuit_breaker.reset_registry()
    yield
    circuit_breaker.reset_registry()


_DOMAIN_LIVE = {(PLAIN, 80), (PLAIN_IP, 80), (SECURE, 443), (SECURE_IP, 443)}
_IP_LIVE = {(T_HTTP, 80), (T_TLS, 443)}


# ---------------------------------------------------------------------------
# Domain mode (S-28): the nested-lab case
# ---------------------------------------------------------------------------

def test_domain_an_roe_refusal_by_naabu_leaves_http_only_and_https_only_hosts_proven(monkeypatch, capsys):
    recon = _domain_run()
    _naabu_refusal(recon)
    assert sc._evidence_cuts(recon) == set()

    result, sent, opened = _run(monkeypatch, recon, _DOMAIN_LIVE)

    # Each host is checked on the port it serves, never probed blind.
    assert {"/login", "/"} <= {urlsplit(u).path for u in _to(sent, opened, PLAIN, 80)}
    assert ("GET", f"https://{SECURE}/") in sent
    for host, port in ((PLAIN, 443), (PLAIN_IP, 443), (SECURE, 80), (SECURE_IP, 80)):
        assert _to(sent, opened, host, port) == [], f"{host}:{port} was probed blind"
    # The finished port scan is a verdict: nothing it reached is kept as
    # unproven, so a fixed finding there is pruned and the coverage record
    # names none of these hosts.
    report = circuit_breaker.coverage_report()
    proven = {PLAIN, PLAIN_IP, SECURE, SECURE_IP}
    assert proven & set(report.keep_hostnames("security_check")) == set()
    assert proven & set(report.skipped_hostnames()) == set()
    assert "without live-port evidence" not in capsys.readouterr().out
    # The refusal itself is still reported, and the excluded host never reached.
    assert any(g["source"] == "roe_excluded" and g["module"] == "naabu" for g in report.gaps)
    assert [u for _m, u in sent if urlsplit(u).hostname in (EDGE, EDGE_IP)] == []
    assert "unreachable_hosts" not in result["security_checks"]


def test_domain_a_real_naabu_cut_beside_the_refusal_still_keeps_an_unproven_port(monkeypatch):
    """naabu timed out before writing a port and no port scan section exists:
    plain's :443 was never measured, so its findings are not judged."""
    recon = _domain_run(with_port_scan=False)
    _naabu_refusal(recon)
    _naabu_cut([PLAIN_IP, SECURE_IP])
    assert {"naabu", "port_scan"} <= sc._evidence_cuts(recon)

    _result, sent, opened = _run(monkeypatch, recon, _DOMAIN_LIVE)

    assert _to(sent, opened, PLAIN, 443) == []
    assert _to(sent, opened, PLAIN, 80)
    assert {PLAIN, PLAIN_IP} <= set(circuit_breaker.coverage_report().keep_hostnames("security_check"))


@pytest.mark.parametrize("module, source", [
    pytest.param("naabu", "naabu_new_failure", id="new-source-under-naabu"),
    pytest.param("port_scan", "some_future_gap", id="new-source-under-port-scan"),
    pytest.param("masscan", "roe_excluded_but_not_quite", id="lookalike-source-under-masscan"),
])
def test_domain_an_unknown_gap_under_a_port_scanner_still_counts_as_a_cut(monkeypatch, module, source):
    recon = _domain_run()
    _naabu_refusal(recon)
    circuit_breaker.note_degraded(module, entries=[{"source": source, "reason": "x", "skipped": 1}])
    assert module in sc._evidence_cuts(recon)

    _run(monkeypatch, recon, _DOMAIN_LIVE)

    kept = set(circuit_breaker.coverage_report().keep_hostnames("security_check"))
    assert {PLAIN, PLAIN_IP, SECURE, SECURE_IP} <= kept


def test_the_ceilings_fingerprint_gaps_are_no_cut():
    """Under the RoE ceiling httpx skips JARM and favicon, and still probes
    every URL: its live URLs are as complete as without the ceiling."""
    recon = _domain_run(with_port_scan=False)
    _fingerprints_not_collected()
    gaps = circuit_breaker.coverage_report().gaps
    assert {(g["source"], g["module"]) for g in gaps} == {
        ("httpx_jarm", "http_probe"), ("httpx_favicon", "http_probe")}
    assert sc._evidence_cuts(recon) == set()


def test_an_unknown_gap_under_httpx_still_counts_as_a_cut():
    circuit_breaker.note_degraded("http_probe", entries=[
        {"source": "httpx_new_probe", "reason": "x", "skipped": 1}])
    assert sc._evidence_cuts(_domain_run()) == {"http_probe"}


def test_the_refusal_sources_are_the_ones_the_recorders_write():
    from recon.helpers import target_admission
    assert target_admission.COVERAGE_SOURCE in sc._REFUSAL_GAP_SOURCES
    assert sc._REFUSAL_GAP_SOURCES == {"roe_excluded", "httpx_jarm", "httpx_favicon"}


# ---------------------------------------------------------------------------
# IP mode: the same rule
# ---------------------------------------------------------------------------

def test_ip_mode_an_roe_refusal_by_naabu_leaves_the_other_targets_proven(monkeypatch, capsys):
    recon = _ip_run()
    _naabu_refusal(recon)
    assert sc._evidence_cuts(recon) == set()

    result, sent, opened = _run(monkeypatch, recon, _IP_LIVE)

    assert {"/login", "/"} <= {urlsplit(u).path for u in _to(sent, opened, T_HTTP, 80)}
    assert ("GET", f"https://{T_TLS}/") in sent
    assert _to(sent, opened, T_HTTP, 443) == []
    assert _to(sent, opened, T_TLS, 80) == []
    report = circuit_breaker.coverage_report()
    assert {T_HTTP, T_TLS} & set(report.keep_hostnames("security_check")) == set()
    assert {T_HTTP, T_TLS} & set(report.skipped_hostnames()) == set()
    assert "IP-mode target(s) without live-port evidence" not in capsys.readouterr().out
    assert "unreachable_hosts" not in result["security_checks"]


def test_ip_mode_a_real_naabu_cut_beside_the_refusal_still_keeps(monkeypatch):
    recon = _ip_run()
    del recon["port_scan"]
    _naabu_refusal(recon)
    _naabu_cut([T_HTTP, T_TLS])

    _run(monkeypatch, recon, _IP_LIVE)

    assert {T_HTTP, T_TLS} <= set(circuit_breaker.coverage_report().keep_hostnames("security_check"))


@pytest.mark.parametrize("module", ["naabu", "masscan", "http_probe"])
def test_ip_mode_an_unknown_gap_under_an_evidence_scanner_still_keeps(monkeypatch, module):
    recon = _ip_run()
    del recon["port_scan"]
    _naabu_refusal(recon)
    circuit_breaker.note_degraded(module, entries=[{"source": "a_new_gap", "reason": "x", "skipped": 1}])

    _run(monkeypatch, recon, _IP_LIVE)

    assert {T_HTTP, T_TLS} <= set(circuit_breaker.coverage_report().keep_hostnames("security_check"))


def test_ip_mode_vhost_keeps_its_source_only_for_a_real_cut():
    """vhost_sni_enum reads the same cuts: a refusal leaves its unproven ports
    as closed, an unknown gap keeps its findings whole."""
    from recon.main_recon_modules import vhost_sni_enum as vs
    recon = _ip_run()
    _naabu_refusal(recon)
    assert {ip: sorted(p["port"] for p in plist)
            for ip, plist in vs._collect_ip_targets(recon).items()} == {T_HTTP: [80], T_TLS: [443]}
    assert "vhost_sni_enum" not in circuit_breaker.coverage_report().degraded_sources

    circuit_breaker.note_degraded("naabu", entries=[{"source": "a_new_gap", "reason": "x", "skipped": 1}])
    vs._collect_ip_targets(recon)
    assert "vhost_sni_enum" in circuit_breaker.coverage_report().degraded_sources
