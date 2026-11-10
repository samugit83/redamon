"""Partial OSINT enrichers skip the CDN edges the graph knows (L-10).

The OSINT CDN filter (ip_filter.collect_cdn_ips / filter_ips_for_enrichment)
reads ``port_scan.by_ip[ip].is_cdn``, which a full run fills from naabu and
httpx. A partial Shodan or OsintEnrichment run has no port scan: its recon dict
came from the graph's DNS block only, so every CDN edge an earlier run flagged
(``IP.is_cdn``) outside the published prefixes was sent to Shodan, Censys,
FOFA, OTX and the others, which the full pipeline never does. _root_recon_data
now loads the graph's CDN flag of the run's IPs, in the shape the vuln builder
uses (port_scan.by_ip[ip] with is_cdn / cdn / asn).

Only the graph (Neo4j) and the providers' HTTP layer are mocked. The addresses
are routable (the filter drops documentation ranges as reserved) and outside
every published CDN prefix, so only the graph's flag can mark the edge.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.main_recon_modules import ip_filter, otx_enrich, shodan_enrich  # noqa: E402
from recon.partial_recon_modules import helpers, osint_enrichment  # noqa: E402

ROOT = "example.com"
ORIGIN_IP = "93.184.216.34"
EDGE_IP = "93.184.216.35"
DNS = {"www.example.com": ORIGIN_IP, "cdn.example.com": EDGE_IP}
GRAPH_IPS = {
    ORIGIN_IP: {"is_cdn": False, "cdn_name": None, "asn": "AS64500"},
    EDGE_IP: {"is_cdn": True, "cdn_name": "examplecdn", "asn": "AS64501"},
}


class _Session:
    def __init__(self, log, fail):
        self.log, self.fail = log, fail

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, cypher, **params):
        self.log.append((cypher, params))
        if "is_cdn" in cypher:
            if self.fail:
                raise RuntimeError("graph down")
            rows = [{"ip": ip, **GRAPH_IPS[ip]} for ip in params.get("ips") or []
                    if GRAPH_IPS.get(ip, {}).get("is_cdn")]
        elif "RESOLVES_TO" in cypher:
            rows = [{"root": ROOT, "subdomain": sub, "address": ip, "version": "ipv4"}
                    for sub, ip in DNS.items()]
        else:
            rows = []
        result = MagicMock()
        result.__iter__ = lambda _s: iter(rows)
        result.single.return_value = rows[0] if rows else None
        return result


@pytest.fixture
def graph(monkeypatch):
    log, state = [], {"fail": False}
    client = MagicMock()
    client.__enter__.return_value = client
    client.verify_connection.return_value = True
    client.driver.session.side_effect = lambda: _Session(log, state["fail"])
    client.active_open_ports.return_value = {}
    for method in ("update_graph_from_shodan", "update_graph_from_otx"):
        getattr(client, method).return_value = {}
    module = MagicMock()
    module.Neo4jClient.return_value = client
    monkeypatch.setitem(sys.modules, "graph_db", module)
    monkeypatch.setattr(helpers.time, "sleep", lambda *_: None)
    return log, state


def _recon(**config):
    return osint_enrichment._root_recon_data(
        ROOT, [ROOT], {"domain": ROOT, "domains": [ROOT], **config}, {}, "u1", "p1")


class TestRootReconData:
    def test_the_graphs_cdn_edge_reaches_the_osint_filter(self, graph):
        recon = _recon()
        assert ip_filter.collect_cdn_ips(recon) == {EDGE_IP}
        assert ip_filter.filter_ips_for_enrichment([ORIGIN_IP, EDGE_IP], recon) == [ORIGIN_IP]

    def test_the_edge_carries_its_cdn_name_and_asn(self, graph):
        entry = _recon()["port_scan"]["by_ip"][EDGE_IP]
        assert (entry["is_cdn"], entry["cdn"], entry["asn"]) == (True, "examplecdn", "AS64501")

    def test_only_the_runs_ips_are_read_and_only_edges_are_added(self, graph):
        log, _state = graph
        recon = _recon()
        (_cypher, params), = [(c, p) for c, p in log if "is_cdn" in c]
        assert sorted(params["ips"]) == sorted(DNS.values())
        assert (params["uid"], params["pid"]) == ("u1", "p1")
        assert set(recon["port_scan"]["by_ip"]) == {EDGE_IP}

    def test_the_dns_block_and_roots_are_unchanged(self, graph):
        recon = _recon()
        assert recon["domains"] == [ROOT]
        assert {sub: e["ips"]["ipv4"] for sub, e in recon["dns"]["subdomains"].items()} == {
            sub: [ip] for sub, ip in DNS.items()}

    def test_a_failed_read_leaves_the_published_prefix_check_only(self, graph):
        _log, state = graph
        state["fail"] = True
        recon = _recon()
        assert "port_scan" not in recon
        assert ip_filter.filter_ips_for_enrichment([ORIGIN_IP, EDGE_IP], recon) == [ORIGIN_IP, EDGE_IP]

    def test_no_graph_targets_reads_nothing(self, graph):
        log, _state = graph
        recon = _recon(include_graph_targets=False)
        assert "port_scan" not in recon
        assert not [c for c, _p in log if "is_cdn" in c]


class TestEnrichersSkipTheEdge:
    def test_partial_shodan_never_looks_the_edge_up(self, graph, monkeypatch):
        looked_up = []

        def fake_lookup(ips, api_key, key_rotator=None, max_workers=5, answered=None):
            looked_up.extend(ips)
            return []

        monkeypatch.setattr(shodan_enrich, "_run_host_lookup", fake_lookup)
        osint_enrichment.run_shodan({
            "_settings": {"SHODAN_API_KEY": "k", "SHODAN_HOST_LOOKUP": True},
            "domain": ROOT, "domains": [ROOT],
        })
        assert looked_up == [ORIGIN_IP]

    def test_partial_osint_enrichment_never_sends_the_edge(self, graph, monkeypatch):
        urls = []

        def fake_get(url, **_kw):
            urls.append(url)
            resp = MagicMock(status_code=404, ok=False, text="", headers={})
            resp.json.return_value = {}
            return resp

        monkeypatch.setattr(otx_enrich.requests, "get", fake_get)
        monkeypatch.setattr(otx_enrich._RateLimiter, "wait", lambda self: None)
        osint_enrichment.run_osint_enrichment({
            "_settings": {"OTX_ENABLED": True, "OTX_WORKERS": 1},
            "domain": ROOT, "domains": [ROOT],
        })
        assert any(f"/IPv4/{ORIGIN_IP}/" in u for u in urls)
        assert not any(EDGE_IP in u for u in urls)
