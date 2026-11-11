"""Domain mode: the security checks never reach an address the Rules of Engagement exclude (R-2, D2).

A domain run hands run_security_checks its whole DNS block. The direct-IP
checks probe every address in it, the WAF-bypass check pairs every name with
every address it has, and the hostname checks (TLS, headers, auth, CSP, rate
limit) probe every name with records, which the HTTP stack resolves itself and
may land on any address the name has. None of the three lists was checked
against the RoE IP and CIDR entries, so a name resolving into an excluded range
was probed, and so was the excluded address itself.

The gate is target_admission's: an excluded address is never probed, a name
with any excluded address is never probed by name (its allowed addresses are
still checked as bare IPs), and a name an entry excludes by name is refused
with the addresses only it holds. Each refused host is logged once, noted under
roe_excluded and kept as not checked for security_check, so the prune never
reads it as clean. With no exclusion the run sends exactly what it sent before.

The network is faked at requests' Session and at socket.create_connection, so
every request and handshake the real checks build is recorded. Documentation
ranges and reserved names only.
"""
import socket
import sys
import time as _time
from collections import Counter
from pathlib import Path
from unittest import mock
from urllib.parse import urlsplit

import pytest
import requests

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers import circuit_breaker  # noqa: E402
from recon.helpers import security_checks as sc  # noqa: E402

APEX, APEX_IP = "example.com", "192.0.2.1"
EXCLUDED_RANGE = "198.51.100.0/24"
LEGACY, LEGACY_IP = "legacy.example.com", "198.51.100.20"          # only an excluded address
MIXED, MIXED_BAD, MIXED_OK = "mixed.example.com", "198.51.100.21", "192.0.2.7"
WWW, WWW_IP = "www.example.com", "192.0.2.6"
_DEFAULT_PORT = {"http": 80, "https": 443}


class _Every(dict):
    """Every check on, except the org DNS checks, which would ask a real resolver."""

    def get(self, key, default=None):
        return key not in sc.DNS_CHECK_TYPES


def _sub(*ips):
    return {"has_records": True, "ips": {"ipv4": list(ips), "ipv6": []}}


def _domain_run() -> dict:
    """A domain run whose port scan and httpx found :80 and :443 live on every
    host, so nothing here depends on which ports a check may probe."""
    names = {APEX: [APEX_IP], LEGACY: [LEGACY_IP], MIXED: [MIXED_BAD, MIXED_OK], WWW: [WWW_IP]}
    by_ip = {}
    for name, addrs in names.items():
        for addr in addrs:
            by_ip.setdefault(addr, {"ip": addr, "ports": [80, 443], "hostnames": []})["hostnames"].append(name)
    return {
        "domain": APEX,
        "metadata": {"include_root_domain": True, "root_domain": APEX},
        "subdomains": [LEGACY, MIXED, WWW],
        "dns": {
            "domain": {"ips": {"ipv4": [APEX_IP], "ipv6": []}, "has_records": True},
            "subdomains": {LEGACY: _sub(LEGACY_IP), MIXED: _sub(MIXED_BAD, MIXED_OK), WWW: _sub(WWW_IP)},
        },
        "port_scan": {"by_ip": by_ip},
        "http_probe": {"by_url": {
            f"{scheme}://{name}": {"url": f"{scheme}://{name}", "host": name, "ip": addrs[0],
                                   "status_code": 200}
            for name, addrs in names.items() for scheme in ("http", "https")}},
    }


def _response(url):
    # No password field, no JSON, no cookie: nothing here triggers a catch-all
    # control probe, whose random path would make two runs differ.
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


def _run(monkeypatch, recon, roe=None):
    """run_security_checks with every host answering 200 on every port.
    Returns (result, requests sent as (method, url, Host header), sockets opened)."""
    sent, opened = [], []

    def request(self, method, url, *a, allow_redirects=True, **k):
        host_header = ((k.get("headers") or {}).get("Host") or "").lower()
        sent.append((method.upper(), url, host_header))
        return _response(url)

    def connect(address, *a, **k):
        opened.append((address[0], address[1]))
        raise ConnectionRefusedError("no TLS here")

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
                                        roe_excluded_hosts=roe)
    return result, sent, opened


def _touching(sent, opened, host):
    """Every request or handshake that reached ``host``, by URL, by Host header or by socket."""
    return ([url for _m, url, _h in sent if urlsplit(url).hostname == host]
            + [f"Host: {h} -> {url}" for _m, url, h in sent if h == host]
            + [f"socket {h}:{p}" for h, p in opened if h == host])


@pytest.fixture(autouse=True)
def _fresh_run():
    circuit_breaker.reset_registry()
    yield
    circuit_breaker.reset_registry()


# ---------------------------------------------------------------------------
# An IP or CIDR entry: the addresses and every name holding one
# ---------------------------------------------------------------------------

def test_no_request_reaches_an_excluded_address_or_a_name_resolving_into_it(monkeypatch, capsys):
    _result, sent, opened = _run(monkeypatch, _domain_run(), roe=[EXCLUDED_RANGE])

    for host in (LEGACY_IP, MIXED_BAD, LEGACY, MIXED):
        assert _touching(sent, opened, host) == [], f"{host} was reached"
    # The mixed name's allowed address is still checked as a bare IP, and the
    # names wholly outside the range keep every check.
    assert ("GET", f"http://{MIXED_OK}", "") in sent
    assert ("GET", f"https://{WWW}/", "") in sent
    assert (WWW, 443) in opened
    assert ("GET", f"http://{APEX_IP}", "") in sent
    assert "[-][RoE] security_checks: not sent to" in capsys.readouterr().out


def test_the_waf_bypass_never_pairs_a_refused_name_with_its_allowed_address(monkeypatch):
    _result, sent, _opened = _run(monkeypatch, _domain_run(), roe=[EXCLUDED_RANGE])

    assert [u for _m, u, h in sent if h == MIXED] == []
    # The allowed pairs still run: the origin is asked with the name's Host header.
    assert any(h == WWW and urlsplit(u).hostname == WWW_IP for _m, u, h in sent)


def test_refused_hosts_are_noted_and_kept_as_not_checked(monkeypatch):
    result, _sent, _opened = _run(monkeypatch, _domain_run(), roe=[EXCLUDED_RANGE])

    report = circuit_breaker.coverage_report()
    kept = set(report.keep_hostnames("security_check"))
    assert {LEGACY, MIXED, LEGACY_IP, MIXED_BAD} <= kept
    # The checked hosts are not, and no other source is held back.
    assert {WWW, WWW_IP, MIXED_OK, APEX} & kept == set()
    assert {LEGACY, MIXED} & set(report.keep_hostnames("nuclei")) == set()
    assert any(g["source"] == "roe_excluded" and g["module"] == "security_checks"
               for g in report.gaps)
    # A refusal is not an outage.
    assert circuit_breaker.host_health.unreachable() == []
    assert "unreachable_hosts" not in result["security_checks"]
    findings = result["security_checks"]["findings"]
    touched = {f.get("hostname") or f.get("matched_ip") or f.get("subdomain") for f in findings}
    assert {LEGACY, MIXED, LEGACY_IP, MIXED_BAD}.isdisjoint(touched)


# ---------------------------------------------------------------------------
# A name entry: the name, and an address only it holds
# ---------------------------------------------------------------------------

def test_a_name_entry_refuses_the_name_and_the_address_only_it_holds(monkeypatch):
    _result, sent, opened = _run(monkeypatch, _domain_run(), roe=[WWW])

    assert _touching(sent, opened, WWW) == []
    assert _touching(sent, opened, WWW_IP) == []
    # No IP or CIDR entry: the names resolving into 198.51.100.0/24 are probed as before.
    assert ("GET", f"https://{LEGACY}/", "") in sent
    assert ("GET", f"https://{MIXED}/", "") in sent
    assert WWW in circuit_breaker.coverage_report().keep_hostnames("security_check")


# ---------------------------------------------------------------------------
# No exclusion: byte-identical
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("roe", [
    pytest.param([], id="empty-list"),
    pytest.param(["unrelated.example.org"], id="entry-matching-nothing"),
])
def test_without_a_matching_exclusion_the_run_sends_what_it_sent(monkeypatch, roe):
    _r, baseline, baseline_opened = _run(monkeypatch, _domain_run(), roe=None)
    circuit_breaker.reset_registry()
    _r, sent, opened = _run(monkeypatch, _domain_run(), roe=roe)

    assert Counter(sent) == Counter(baseline)
    assert Counter(opened) == Counter(baseline_opened)
    assert ("GET", f"https://{LEGACY}/", "") in baseline
    assert ("GET", f"http://{MIXED_BAD}", "") in baseline
    assert circuit_breaker.coverage_report().keep_hostnames("security_check") == ()


def test_the_partial_builders_stamp_is_honoured_when_the_caller_passes_no_list(monkeypatch):
    """A partial run's graph builder stamps the run's RoE in metadata.roe for a
    reader handed no settings: the checks read it too."""
    recon = _domain_run()
    recon["metadata"]["roe"] = {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": [EXCLUDED_RANGE]}
    _result, sent, opened = _run(monkeypatch, recon, roe=None)

    for host in (LEGACY_IP, MIXED_BAD, LEGACY, MIXED):
        assert _touching(sent, opened, host) == [], f"{host} was reached"
    assert ("GET", f"https://{WWW}/", "") in sent
