"""The partial vuln-scan graph builder keeps a name's RoE-excluded address where the gates read it (R-2).

_build_vuln_scan_data_from_graph feeds partial Nuclei, partial takeover,
partial security checks, partial vhost/SNI and partial origin discovery. It
dropped a name's excluded address from its DNS block, so the admission gate
saw a name with one excluded and one allowed address as wholly allowed and
handed it by name to tools that resolve it themselves. A name whose only
address is excluded was left in the block with no address and records still
on, and reached the partial security checks' hostname checks.

The excluded address now stays in the DNS block, which every gate reads, and
stays out of port_scan.by_ip and the nmap services, which tools connect to or
report on; the run's RoE is stamped in metadata.roe (eb17d80a's pattern for
the port-scan builder). With no exclusion the builder's output is unchanged.

Neo4j is a fake answering from a fixed set of rows; the network is faked at
requests' Session and socket.create_connection. Documentation ranges and
reserved names only.
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
from recon.partial_recon_modules import helpers as partial_helpers  # noqa: E402

APEX, APEX_IP = "example.com", "192.0.2.1"
EXCLUDED_RANGE = "198.51.100.0/24"
LEGACY, LEGACY_IP = "legacy.example.com", "198.51.100.20"          # only an excluded address
MIXED, MIXED_BAD, MIXED_OK = "mixed.example.com", "198.51.100.21", "192.0.2.7"
WWW, WWW_IP = "www.example.com", "192.0.2.6"

GRAPH_DNS = [(LEGACY, LEGACY_IP), (MIXED, MIXED_BAD), (MIXED, MIXED_OK), (WWW, WWW_IP)]
GRAPH_SUBDOMAINS = [LEGACY, MIXED, WWW]
GRAPH_BASEURLS = [f"https://{WWW}", f"https://{MIXED}", f"https://{LEGACY}"]

NO_ROE = [
    pytest.param({"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": []}, id="enabled-empty"),
    pytest.param({"ROE_ENABLED": False, "ROE_EXCLUDED_HOSTS": [EXCLUDED_RANGE, WWW]}, id="disabled"),
]


def _roe(*entries):
    return {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": list(entries)}


class _Rows(list):
    def single(self):
        return self[0] if self else None


def _address_row(address):
    return {"address": address, "ip": address, "version": "IPv4", "is_cdn": False,
            "cdn_name": None, "asn": None}


_NMAP_QUERIES: list = []


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
            rows.extend({"root": APEX, "sub": s} for s in GRAPH_SUBDOMAINS)
        elif "collect(DISTINCT s.name)" in cypher:
            rows.append({"subdomains": list(GRAPH_SUBDOMAINS)})
        elif "HAS_SUBDOMAIN" in cypher and "RESOLVES_TO" in cypher:
            rows.extend({"root": APEX, "subdomain": s, **_address_row(a)} for s, a in GRAPH_DNS)
        elif "MATCH (p:Port" in cypher and "p.product" in cypher:
            _NMAP_QUERIES.append(list(params.get("ips") or []))
            rows.extend({"ip": ip, "port": 22, "product": "OpenSSH", "version": "9.6", "cpe": ""}
                        for ip in params.get("ips") or [])
        elif "MATCH (p:Port" in cypher:
            # graph_open_ports: every address the builder handed it serves the web.
            rows.extend({"ip": ip, "ports": [80, 443]} for ip in params.get("ips") or [])
        elif "(e:Endpoint)" in cypher or "USES_TECHNOLOGY" in cypher:
            pass
        elif "MATCH (b:BaseURL" in cypher:
            rows.extend({"url": u, "host": urlparse(u).hostname, "status_code": 200,
                         "content_type": "text/html", "is_cdn": False, "cdn": None, "asn": None}
                        for u in GRAPH_BASEURLS)
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
    _NMAP_QUERIES.clear()
    monkeypatch.setattr("graph_db.Neo4jClient", _Client)
    yield
    circuit_breaker.reset_registry()
    partial_helpers.set_run_roe({})
    partial_helpers.set_run_ip_targets({})


def _run_settings(settings: dict) -> dict:
    run_settings = {"SUBDOMAIN_LIST": ["."], **settings}
    # What partial_recon._prepare_scope does before any module runs.
    partial_helpers.set_run_roe(run_settings)
    return run_settings


def _build(settings: dict) -> dict:
    from recon.partial_recon_modules.graph_builders import _build_vuln_scan_data_from_graph
    _run_settings(settings)
    return _build_vuln_scan_data_from_graph([APEX], "u1", "p1", include_root_domain=True)


def _ips(entry) -> list:
    return entry["ips"]["ipv4"] + entry["ips"]["ipv6"]


# --------------------------------------------------------------------------
# The builder's output
# --------------------------------------------------------------------------

def test_an_excluded_address_stays_in_dns_for_the_gates():
    data = _build(_roe(EXCLUDED_RANGE))
    subs = data["dns"]["subdomains"]
    assert _ips(subs[LEGACY]) == [LEGACY_IP]
    assert sorted(_ips(subs[MIXED])) == sorted([MIXED_BAD, MIXED_OK])
    assert data["metadata"]["roe"] == _roe(EXCLUDED_RANGE)


def test_an_excluded_address_stays_out_of_what_tools_connect_to_or_report_on():
    data = _build(_roe(EXCLUDED_RANGE))
    assert {LEGACY_IP, MIXED_BAD}.isdisjoint(data["port_scan"]["by_ip"])
    assert {LEGACY_IP, MIXED_BAD}.isdisjoint(s["host"] for s in data["nmap_scan"]["services_detected"])
    assert {LEGACY_IP, MIXED_BAD}.isdisjoint(_NMAP_QUERIES[-1])
    # The names it resolves for are no BaseURL a check may read either (graph_url_scope).
    assert {urlparse(u).hostname for u in data["http_probe"]["by_url"]} == {WWW}


@pytest.mark.parametrize("settings", NO_ROE)
def test_without_an_exclusion_the_output_is_unchanged(settings):
    baseline = _build({})
    _NMAP_QUERIES.clear()
    assert _build(settings) == baseline
    assert "roe" not in baseline["metadata"]
    assert LEGACY_IP in _ips(baseline["dns"]["subdomains"][LEGACY])
    assert LEGACY_IP in baseline["port_scan"]["by_ip"]


# --------------------------------------------------------------------------
# Partial security checks: no graph name holding an excluded address is probed
# --------------------------------------------------------------------------

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


def _partial_security_checks(settings, monkeypatch):
    """run_security_checks_partial on the fake graph; returns every host a
    request, a Host header or a handshake reached."""
    from recon.helpers import security_checks as sc
    from recon.partial_recon_modules import vulnerability_scanning
    reached = set()

    def request(self, method, url, *a, allow_redirects=True, **k):
        reached.add(urlparse(url).hostname)
        reached.add(((k.get("headers") or {}).get("Host") or "").lower())
        return _response(url)

    def connect(address, *a, **k):
        reached.add(address[0])
        raise ConnectionRefusedError("no TLS here")

    def getaddrinfo(host, *a, **k):
        raise socket.gaierror(f"no resolver in this test: {host}")

    monkeypatch.setattr(requests.sessions.Session, "request", request)
    monkeypatch.setattr(sc.socket, "create_connection", connect)
    monkeypatch.setattr(sc.socket, "getaddrinfo", getaddrinfo)
    for name in ("collect_reliable_edge_ips", "collect_asn_cdn_ips", "collect_prefix_cdn_ips"):
        monkeypatch.setattr(sc, name, lambda *a, **k: set())
    run_settings = _run_settings({**_NO_ORG_DNS, **settings})
    with mock.patch.object(sc, "time") as fake_time:
        fake_time.time.side_effect = _time.time
        fake_time.monotonic.side_effect = _time.monotonic
        fake_time.sleep = lambda *_a, **_k: None
        vulnerability_scanning.run_security_checks_partial(
            {"_settings": run_settings, "domains": [APEX], "domain": APEX})
    reached.discard("")
    return reached


def test_partial_security_checks_never_reach_a_graph_name_with_an_excluded_address(monkeypatch):
    reached = _partial_security_checks(_roe(EXCLUDED_RANGE), monkeypatch)
    # LEGACY's only address is excluded; MIXED has one excluded and one allowed.
    assert {LEGACY, MIXED, LEGACY_IP, MIXED_BAD}.isdisjoint(reached)
    assert {WWW, MIXED_OK} <= reached
    keep = set(circuit_breaker.coverage_report().keep_hostnames("security_check"))
    assert {LEGACY, MIXED, LEGACY_IP, MIXED_BAD} <= keep


@pytest.mark.parametrize("settings", NO_ROE)
def test_partial_security_checks_reach_every_graph_host_without_an_exclusion(settings, monkeypatch):
    reached = _partial_security_checks(settings, monkeypatch)
    assert {LEGACY, MIXED, LEGACY_IP, MIXED_BAD, MIXED_OK, WWW, APEX} <= reached
