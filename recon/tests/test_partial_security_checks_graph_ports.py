"""Partial SecurityChecks: the graph's open Port nodes are web-port evidence even with the port checks off.

Since S-28 a domain run probes a host only on a web port its data shows live. A
partial run's data is the graph's: BaseURLs, and the open Port nodes that
run_security_checks_partial loads into port_scan.by_ip. It loaded them only
when one of the five port and service checks was on, so with those checks off
a graph host with an open :443 Port node and no BaseURL had no evidence and
was never probed.

In domain mode the graph's open ports are now always loaded: the web checks
read them as evidence, and the port and service checks still run only when
switched on. IP mode loads them as before, for the port checks alone.

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
WWW, WWW_IP = "www.example.com", "192.0.2.6"      # a BaseURL, no Port node
TLS, TLS_IP = "tls.example.com", "192.0.2.40"     # an open :443 Port node, no BaseURL
SSH, SSH_IP = "ssh.example.com", "192.0.2.41"     # only :22 open
GRAPH_DNS = [(WWW, WWW_IP), (TLS, TLS_IP), (SSH, SSH_IP)]
GRAPH_PORTS = {TLS_IP: [443], SSH_IP: [22]}
_DEFAULT_PORT = {"http": 80, "https": 443}
_PORT_CHECKS = ("ADMIN_PORT_EXPOSED", "DATABASE_EXPOSED", "REDIS_NO_AUTH",
                "KUBERNETES_API_EXPOSED", "SMTP_OPEN_RELAY")
_NO_ORG_DNS = {f"SECURITY_CHECK_{t}": False
               for t in ("SPF_MISSING", "DMARC_MISSING", "DNSSEC_MISSING", "ZONE_TRANSFER")}


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
            rows.extend({"host": s, "address": a} for s, a in [(APEX, APEX_IP), *GRAPH_DNS])
        elif "$apex_roots" in cypher:
            rows.append({"root": APEX, **_address_row(APEX_IP)})
        elif re.search(r"AS sub\b", cypher):
            rows.extend({"root": APEX, "sub": s} for s, _a in GRAPH_DNS)
        elif "collect(DISTINCT s.name)" in cypher:
            rows.append({"subdomains": [s for s, _a in GRAPH_DNS]})
        elif "HAS_SUBDOMAIN" in cypher and "RESOLVES_TO" in cypher:
            rows.extend({"root": APEX, "subdomain": s, **_address_row(a)} for s, a in GRAPH_DNS)
        elif "MATCH (p:Port" in cypher and "p.product" in cypher:
            pass
        elif "MATCH (p:Port" in cypher:
            rows.extend({"ip": ip, "ports": GRAPH_PORTS[ip]}
                        for ip in params.get("ips") or [] if ip in GRAPH_PORTS)
        elif "(e:Endpoint)" in cypher or "USES_TECHNOLOGY" in cypher:
            pass
        elif "MATCH (b:BaseURL" in cypher:
            rows.append({"url": f"https://{WWW}", "host": WWW, "status_code": 200,
                         "content_type": "text/html", "is_cdn": False, "cdn": None, "asn": None})
        return rows


_WRITTEN: list = []


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

    def update_graph_from_vuln_scan(self, recon_data=None, **_k):
        _WRITTEN.append(recon_data)
        return {}


@pytest.fixture(autouse=True)
def _fresh_run(monkeypatch):
    circuit_breaker.reset_registry()
    partial_helpers.set_run_roe({})
    partial_helpers.set_run_ip_targets({})
    _WRITTEN.clear()
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


def _partial(monkeypatch, port_checks_on, domains=(APEX,)):
    """run_security_checks_partial; returns (requests sent, sockets opened, findings)."""
    from recon.partial_recon_modules import vulnerability_scanning
    sent, opened = [], []

    def request(self, method, url, *a, allow_redirects=True, **k):
        sent.append((method.upper(), url))
        return _response(url)

    def connect(address, *a, **k):
        opened.append((address[0], address[1]))
        raise ConnectionRefusedError("no service here")

    def getaddrinfo(host, *a, **k):
        raise socket.gaierror(f"no resolver in this test: {host}")

    monkeypatch.setattr(requests.sessions.Session, "request", request)
    monkeypatch.setattr(sc.socket, "create_connection", connect)
    monkeypatch.setattr(sc.socket, "getaddrinfo", getaddrinfo)
    for name in ("collect_reliable_edge_ips", "collect_asn_cdn_ips", "collect_prefix_cdn_ips"):
        monkeypatch.setattr(sc, name, lambda *a, **k: set())
    run_settings = {"SUBDOMAIN_LIST": ["."], **_NO_ORG_DNS,
                    **{f"SECURITY_CHECK_{c}": port_checks_on for c in _PORT_CHECKS}}
    partial_helpers.set_run_roe(run_settings)
    with mock.patch.object(sc, "time") as fake_time:
        fake_time.time.side_effect = _time.time
        fake_time.monotonic.side_effect = _time.monotonic
        fake_time.sleep = lambda *_a, **_k: None
        vulnerability_scanning.run_security_checks_partial(
            {"_settings": run_settings, "domains": list(domains), "domain": domains[0]})
    findings = (((_WRITTEN[-1] or {}).get("vuln_scan") or {}).get("security_checks") or {}).get("findings") or []
    return sent, opened, findings


def _to(sent, opened, host, port):
    return ([u for _m, u in sent
             if (urlparse(u).hostname, urlparse(u).port or _DEFAULT_PORT[urlparse(u).scheme]) == (host, port)]
            + [f"socket {h}:{p}" for h, p in opened if (h, p) == (host, port)])


@pytest.mark.parametrize("port_checks_on", [pytest.param(False, id="port-checks-off"),
                                            pytest.param(True, id="port-checks-on")])
def test_an_open_web_port_node_is_evidence_whatever_the_port_checks(monkeypatch, port_checks_on):
    sent, opened, _findings = _partial(monkeypatch, port_checks_on)

    # The :443 Port node with no BaseURL: the HTTPS checks run, by name and by address.
    assert ("GET", f"https://{TLS}/") in sent
    assert (TLS, 443) in opened
    assert ("GET", f"https://{TLS_IP}") in sent
    assert _to(sent, opened, TLS, 80) == [] and _to(sent, opened, TLS_IP, 80) == []
    # Only :22 open: no web probe at all.
    for host in (SSH, SSH_IP):
        assert _to(sent, opened, host, 80) == [] and _to(sent, opened, host, 443) == [], host
    # The BaseURL host is still checked on what it serves.
    assert ("GET", f"https://{WWW}/") in sent
    assert _to(sent, opened, WWW, 80) == []


def test_the_port_checks_still_run_only_when_switched_on(monkeypatch):
    _sent, _opened, off = _partial(monkeypatch, port_checks_on=False)
    circuit_breaker.reset_registry()
    _sent, _opened, on = _partial(monkeypatch, port_checks_on=True)

    assert [f for f in off if f["type"] == "admin_port_exposed"] == []
    assert [(f["ip"], f["port"]) for f in on if f["type"] == "admin_port_exposed"] == [(SSH_IP, 22)]


@pytest.mark.parametrize("port_checks_on, loaded", [pytest.param(False, False, id="port-checks-off"),
                                                    pytest.param(True, True, id="port-checks-on")])
def test_ip_mode_loads_the_graph_ports_for_the_port_checks_alone(monkeypatch, port_checks_on, loaded):
    """IP mode keeps 65365856's rule: the Port nodes reach the run only with a
    port check on."""
    from recon.helpers.ip_placeholders import placeholder_for
    from recon.partial_recon_modules import vulnerability_scanning
    label = placeholder_for(TLS_IP)
    ip_recon = {
        "domain": "ip-targets.p1", "domains": ["ip-targets.p1"], "subdomains": [label],
        "dns": {"domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
                "subdomains": {label: {"has_records": True, "is_mock": True, "actual_ip": TLS_IP,
                                       "ips": {"ipv4": [TLS_IP], "ipv6": []}}}},
        "metadata": {"ip_mode": True, "expanded_ips": [TLS_IP], "include_root_domain": False},
        "http_probe": {"by_url": {}},
        "port_scan": {"by_ip": {TLS_IP: {"ip": TLS_IP, "hostnames": [], "ports": [],
                                         "is_cdn": False, "cdn": None, "asn": None}}},
        "resource_enum": {"by_base_url": {}, "discovered_urls": []},
    }
    asked = []
    monkeypatch.setattr(vulnerability_scanning, "_build_vuln_scan_data_from_graph",
                        lambda *a, **k: ip_recon)
    monkeypatch.setattr(vulnerability_scanning, "graph_open_ports",
                        lambda ips, *a, **k: asked.append(list(ips)) or {TLS_IP: [443]})
    _partial(monkeypatch, port_checks_on, domains=("ip-targets.p1",))

    assert bool(asked) is loaded
