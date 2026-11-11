"""Partial SecurityChecks: a typed host the graph has no live-port data for is probed as before.

Since S-28 a domain run probes a host only on a web port its port scan or httpx
data shows live, and leaves a host with no evidence unprobed (kept as not
checked). A partial run's evidence is the graph's: open Port nodes and
BaseURLs. A subdomain or IP the operator types into the partial modal is
resolved and added to the DNS block, but the graph usually holds nothing live
for it, so it was silently skipped.

run_security_checks_partial now stamps the typed hosts (and a typed name's
resolved addresses) in metadata.typed_hosts, outside IP mode. A typed host with
no evidence is probed on both web ports, as every host was before the gate; one
the graph has evidence for follows the evidence rule; the RoE gate still
refuses an excluded typed host and a typed name with any excluded address. IP
mode ignores the stamp.

Neo4j is a fake answering from a fixed set of rows; the network is faked at
requests' Session and socket.create_connection, every port answering, so a
request that is not sent is one the checks chose not to send. Documentation
ranges and reserved names only.
"""
from __future__ import annotations

import re
import socket
import sys
import time as _time
from pathlib import Path
from unittest import mock
from urllib.parse import urlparse

import pytest
import requests

_RECON = Path(__file__).resolve().parent.parent
_REPO = _RECON.parent
for _p in (str(_REPO), str(_RECON)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from recon.helpers import circuit_breaker  # noqa: E402
from recon.helpers import security_checks as sc  # noqa: E402
from recon.partial_recon_modules import helpers as partial_helpers  # noqa: E402

APEX, APEX_IP = "example.com", "192.0.2.1"
WWW, WWW_IP = "www.example.com", "192.0.2.6"              # in the graph, HTTPS only
TYPED, TYPED_IP = "typed.example.com", "192.0.2.50"       # typed, nothing live in the graph
BARE = "192.0.2.60"                                        # a typed IP
BAD, BAD_IP = "bad.example.com", "198.51.100.30"          # typed, resolves into the excluded range
BAD_BARE = "198.51.100.31"
EXCLUDED_RANGE = "198.51.100.0/24"
RESOLVE = {TYPED: [TYPED_IP], BAD: [BAD_IP], WWW: [WWW_IP]}
_DEFAULT_PORT = {"http": 80, "https": 443}


class _Rows(list):
    def single(self):
        return self[0] if self else None


def _address_row(address):
    return {"address": address, "ip": address, "version": "IPv4", "is_cdn": False,
            "cdn_name": None, "asn": None}


class _Session:
    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def run(self, cypher, **params):
        rows = _Rows()
        if "AS host, i.address AS address" in cypher:
            rows.extend({"host": s, "address": a} for s, a in [(APEX, APEX_IP), (WWW, WWW_IP)])
        elif "$apex_roots" in cypher:
            rows.append({"root": APEX, **_address_row(APEX_IP)})
        elif re.search(r"AS sub\b", cypher):
            rows.append({"root": APEX, "sub": WWW})
        elif "collect(DISTINCT s.name)" in cypher:
            rows.append({"subdomains": [WWW]})
        elif "HAS_SUBDOMAIN" in cypher and "RESOLVES_TO" in cypher:
            rows.append({"root": APEX, "subdomain": WWW, **_address_row(WWW_IP)})
        elif "MATCH (p:Port" in cypher and "p.product" in cypher:
            pass
        elif "MATCH (p:Port" in cypher:
            # graph_open_ports: the graph knows only www's HTTPS port.
            rows.extend({"ip": ip, "ports": [443]} for ip in params.get("ips") or [] if ip == WWW_IP)
        elif "(e:Endpoint)" in cypher or "USES_TECHNOLOGY" in cypher:
            pass
        elif "MATCH (b:BaseURL" in cypher:
            rows.append({"url": f"https://{WWW}", "host": WWW, "status_code": 200,
                         "content_type": "text/html", "is_cdn": False, "cdn": None, "asn": None})
        return rows


class _Client:
    def __init__(self, *_a, **_k):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def verify_connection(self):
        return True

    @property
    def driver(self):
        driver = mock.MagicMock()
        driver.session.side_effect = lambda **_k: _Session()
        return driver

    def update_graph_from_vuln_scan(self, **_k):
        return {}


@pytest.fixture(autouse=True)
def _fresh_run(monkeypatch):
    circuit_breaker.reset_registry()
    partial_helpers.set_run_roe({})
    partial_helpers.set_run_ip_targets({})
    monkeypatch.setattr("graph_db.Neo4jClient", _Client)
    yield
    circuit_breaker.reset_registry()
    partial_helpers.set_run_roe({})
    partial_helpers.set_run_ip_targets({})


def _response(url):
    resp = requests.Response()
    resp.status_code = 200
    resp.url = url
    resp.headers = requests.structures.CaseInsensitiveDict({"Content-Type": "text/html"})
    resp._content = b"<html><body>ok</body></html>"
    resp.encoding = "utf-8"
    return resp


_NO_ORG_DNS = {f"SECURITY_CHECK_{t.upper()}": False
               for t in ("spf_missing", "dmarc_missing", "dnssec_missing", "zone_transfer")}


def _partial(monkeypatch, subdomains=(), ips=(), settings=None):
    """run_security_checks_partial with typed targets. Returns (requests sent
    as (method, url, Host header), sockets opened as (host, port))."""
    from recon.partial_recon_modules import vulnerability_scanning
    sent, opened = [], []

    def request(self, method, url, *a, allow_redirects=True, **k):
        sent.append((method.upper(), url, ((k.get("headers") or {}).get("Host") or "").lower()))
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
    monkeypatch.setattr(vulnerability_scanning, "_resolve_hostname",
                        lambda host: {"ipv4": list(RESOLVE.get(host, [])), "ipv6": []})
    run_settings = {"SUBDOMAIN_LIST": ["."], **_NO_ORG_DNS, **(settings or {})}
    # What partial_recon._prepare_scope does before any module runs.
    partial_helpers.set_run_roe(run_settings)
    config = {"_settings": run_settings, "domains": [APEX], "domain": APEX,
              "user_targets": {"subdomains": list(subdomains), "ips": list(ips)}}
    with mock.patch.object(sc, "time") as fake_time:
        fake_time.time.side_effect = _time.time
        fake_time.monotonic.side_effect = _time.monotonic
        fake_time.sleep = lambda *_a, **_k: None
        vulnerability_scanning.run_security_checks_partial(config)
    return sent, opened


def _to(sent, opened, host, port):
    return ([u for _m, u, _h in sent
             if (urlparse(u).hostname, urlparse(u).port or _DEFAULT_PORT[urlparse(u).scheme]) == (host, port)]
            + [f"socket {h}:{p}" for h, p in opened if (h, p) == (host, port)])


def _reached(sent, opened, host):
    return ([u for _m, u, h in sent if urlparse(u).hostname == host or h == host]
            + [f"socket {h}:{p}" for h, p in opened if h == host])


# ---------------------------------------------------------------------------
# A typed host with no graph evidence: probed as before
# ---------------------------------------------------------------------------

def test_a_typed_subdomain_with_no_graph_evidence_is_probed_on_both_web_ports(monkeypatch):
    sent, opened = _partial(monkeypatch, subdomains=[TYPED])

    assert ("GET", f"http://{TYPED}/login", "") in sent        # login_no_https
    assert ("GET", f"https://{TYPED}/", "") in sent            # header, cookie, CSP checks
    assert (TYPED, 443) in opened                              # TLS expiry
    # Its address, which the run resolved for it, gets the direct-IP checks.
    assert ("GET", f"http://{TYPED_IP}", "") in sent
    assert ("GET", f"https://{TYPED_IP}", "") in sent
    keep = set(circuit_breaker.coverage_report().keep_hostnames("security_check"))
    assert {TYPED, TYPED_IP} & keep == set()


def test_a_typed_ip_with_no_graph_evidence_is_probed_on_both_web_ports(monkeypatch):
    sent, opened = _partial(monkeypatch, ips=[BARE])

    assert ("GET", f"http://{BARE}", "") in sent               # direct_ip_http
    assert ("GET", f"https://{BARE}", "") in sent              # direct_ip_https
    assert ("GET", f"http://{BARE}/api", "") in sent           # ip_api_exposed
    assert BARE not in circuit_breaker.coverage_report().keep_hostnames("security_check")


# ---------------------------------------------------------------------------
# A host the graph has evidence for: the evidence rule
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("typed", [pytest.param([], id="graph-only"),
                                   pytest.param([WWW], id="typed-too")])
def test_a_host_with_graph_evidence_follows_it_even_when_typed(monkeypatch, typed):
    sent, opened = _partial(monkeypatch, subdomains=[TYPED, *typed])

    assert ("GET", f"https://{WWW}/", "") in sent
    assert _to(sent, opened, WWW, 80) == []
    assert _to(sent, opened, WWW_IP, 80) == []


def test_a_graph_host_with_no_evidence_is_still_not_probed(monkeypatch):
    """The apex has no live row in the graph and nobody typed it."""
    sent, opened = _partial(monkeypatch, subdomains=[TYPED])

    assert _reached(sent, opened, APEX) == []
    assert _reached(sent, opened, APEX_IP) == []
    assert APEX in circuit_breaker.coverage_report().keep_hostnames("security_check")


# ---------------------------------------------------------------------------
# The RoE gate still applies to typed hosts
# ---------------------------------------------------------------------------

def test_an_excluded_typed_host_is_never_probed(monkeypatch):
    sent, opened = _partial(monkeypatch, subdomains=[TYPED, BAD], ips=[BARE, BAD_BARE],
                            settings={"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": [EXCLUDED_RANGE]})

    for host in (BAD, BAD_IP, BAD_BARE):
        assert _reached(sent, opened, host) == [], f"{host} was reached"
    assert ("GET", f"https://{TYPED}/", "") in sent
    assert ("GET", f"http://{BARE}", "") in sent


# ---------------------------------------------------------------------------
# The stamp and the gate
# ---------------------------------------------------------------------------

def _domain(names, ports=None, typed=()):
    recon = {
        "domain": APEX,
        "metadata": {"include_root_domain": False, "root_domain": APEX, "typed_hosts": list(typed)},
        "subdomains": list(names),
        "dns": {"domain": {}, "subdomains": {
            n: {"has_records": True, "ips": {"ipv4": list(a), "ipv6": []}} for n, a in names.items()}},
    }
    if ports is not None:
        recon["port_scan"] = {"by_ip": {ip: {"ip": ip, "ports": list(p), "hostnames": []}
                                        for ip, p in ports.items()}}
    return recon


def test_typed_hosts_without_evidence_get_both_web_ports_and_nothing_else_does():
    recon = _domain({WWW: [WWW_IP], TYPED: [TYPED_IP], APEX: [TYPED_IP]},
                    ports={WWW_IP: [443]}, typed=[TYPED, TYPED_IP, "Www.Example.com."])
    live = {h: set(p) for h, p in sc._domain_live_ports(recon).items()}
    assert live[TYPED] == live[TYPED_IP] == {80, 443}
    # Evidence wins over the stamp, and a name sharing a typed address gains nothing.
    assert live[WWW] == live[WWW_IP] == {443}
    assert APEX not in live


def test_the_stamp_never_widens_ip_mode_or_a_run_with_no_evidence():
    no_evidence = _domain({TYPED: [TYPED_IP]}, typed=[TYPED, TYPED_IP])
    assert sc._domain_live_ports(no_evidence) is None
    ip_mode = _domain({TYPED: [TYPED_IP]}, ports={TYPED_IP: [80]}, typed=[TYPED, TYPED_IP])
    ip_mode["metadata"].update(ip_mode=True, expanded_ips=[TYPED_IP])
    assert sc._domain_live_ports(ip_mode) is None
