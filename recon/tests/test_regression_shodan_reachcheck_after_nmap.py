"""Regression: a Shodan CVE on a port only nmap confirmed was marked closed (R-39).

`_reachcheck_shodan_cves` sets each Shodan CVE's `port_confirmed` from this
run's port scan. It ran at GROUP 3, right after naabu, so it never saw the open
ports nmap adds at GROUP 3.5 (`_add_nmap_confirmed_ports`: nmap probes every IP
with the union of all IPs' ports and can confirm one naabu dropped). A CVE on
such a port was written `port_confirmed = false`, and the Priority Board read it
as "the port scan found the port closed". The CVEs are held back until
`_write_shodan_cves`, after IP attribution, so the check now runs there, after
the nmap merge, in both pipelines.

Every scanner and Neo4j is a fake; run_ip_recon and the merge are real.
"""
from __future__ import annotations

import inspect
import sys
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.main_recon_modules import nmap_scan, shodan_enrich  # noqa: E402

IP = "198.51.100.21"
CVE = {"cve_id": "CVE-2018-15473", "ip": IP, "port": 22, "source": "shodan_api"}

# Only Shodan, naabu and nmap run, so the run reaches the CVE write with fakes.
SETTINGS = {
    "DNS_ENABLED": False, "WHOIS_ENABLED": False,
    "SHODAN_ENABLED": True, "SHODAN_PASSIVE_CVES": True,
    "NAABU_ENABLED": True, "MASSCAN_ENABLED": False, "NMAP_ENABLED": True,
    "TLSX_ENABLED": False, "OSINT_ENRICHMENT_ENABLED": False, "UNCOVER_ENABLED": False,
    "HTTPX_ENABLED": False, "IP_ATTRIBUTION_ENABLED": False,
    "SECURITY_CHECK_ENABLED": False, "AI_SURFACE_RECON_ENABLED": False,
    "JS_RECON_ENABLED": False, "SUPPLY_CHAIN_RECON_ENABLED": False, "MITRE_ENABLED": False,
    "GRAPHQL_SECURITY_ENABLED": False, "SUBDOMAIN_TAKEOVER_ENABLED": False,
    "VHOST_SNI_ENABLED": False, "WEB_CACHE_POISON_ENABLED": False,
    "ORIGIN_DISCOVERY_ENABLED": False, "ROUTE_EXPOSURE_ENABLED": False, "ROE_ENABLED": False,
}


def _port_scan(ports):
    """naabu's answer: it scanned 22 and 80 on the IP and reported only `ports`."""
    return {"scan_metadata": {"ports_config": "22,80"}, "by_host": {}, "all_ports": list(ports),
            "summary": {},
            "by_ip": {IP: {"ip": IP, "hostnames": [], "ports": list(ports), "port_details": []}},
            "ip_to_hostnames": {}}


def _shodan(_combined, _settings):
    return {"hosts": [{"ip": IP, "services": [{"port": 22, "transport": "tcp"}]}],
            "reverse_dns": {}, "cves": [dict(CVE)]}


@pytest.fixture
def recon_main(tmp_path, monkeypatch):
    stub = {
        'TARGET_DOMAIN': '', 'SUBDOMAIN_LIST': [], 'IP_MODE': True, 'TARGET_IPS': [IP],
        'DOMAIN_BATCH_MODE': False, 'DOMAIN_BATCH_GROUPS': [],
        'USE_BRUTEFORCE_FOR_SUBDOMAINS': False, 'SCAN_MODULES': ['port_scan'],
        'UPDATE_GRAPH_DB': False, 'USER_ID': 'u1', 'PROJECT_ID': 'p1',
        'VERIFY_DOMAIN_OWNERSHIP': False, 'STEALTH_MODE': False,
        'OWNERSHIP_TOKEN': '', 'OWNERSHIP_TXT_PREFIX': '',
    }
    with mock.patch('recon.project_settings.get_settings', return_value=dict(stub)):
        for mod in [m for m in list(sys.modules) if m in ('recon.main', 'main')]:
            del sys.modules[mod]
        import recon.main as rm
        monkeypatch.setattr(rm, "OUTPUT_DIR", tmp_path)
        monkeypatch.setattr(rm, "SCAN_MODULES", ["port_scan"])
        yield rm


def _nmap_confirms(open_ports):
    def fake_nmap(recon_data, output_file=None, settings=None):
        recon_data["nmap_scan"] = {"by_host": {IP: {"ip": IP, "port_details": [
            {"port": p, "state": "open", "protocol": "tcp", "service": "ssh"}
            for p in open_ports]}}}
        return recon_data
    return fake_nmap


def _written_cves(rm, monkeypatch, naabu_ports, nmap_ports, settings=None):
    """The Shodan CVEs the run hands the graph writer."""
    written = []

    def queue(method, data, *_a):
        if method == "update_graph_from_shodan" and (data.get("shodan") or {}).get("cves"):
            written.extend(dict(c) for c in data["shodan"]["cves"])

    monkeypatch.setattr(shodan_enrich, "run_shodan_enrichment_isolated", _shodan)
    monkeypatch.setattr(rm, "run_port_scan_isolated", lambda *a, **k: _port_scan(naabu_ports))
    monkeypatch.setattr(nmap_scan, "run_nmap_scan", _nmap_confirms(nmap_ports))
    monkeypatch.setattr(rm, "_graph_update_bg", queue)
    result = rm.run_ip_recon([IP], dict(SETTINGS, **(settings or {})))
    return written, result


class TestRegressionNmapConfirmedPort:
    def test_regression_a_port_only_nmap_confirmed_reads_closed(self, recon_main, monkeypatch):
        # naabu dropped 22; nmap, probing the union of ports, confirms it open.
        written, result = _written_cves(recon_main, monkeypatch, naabu_ports=[80],
                                        nmap_ports=[22])
        assert result["nmap_scan"]["new_open_ports"] == [
            {"ip": IP, "port": 22, "protocol": "tcp", "service": "ssh"}]
        assert [c["port_confirmed"] for c in written] == [True]

    def test_a_port_neither_scan_found_still_reads_closed(self, recon_main, monkeypatch):
        written, _ = _written_cves(recon_main, monkeypatch, naabu_ports=[80], nmap_ports=[])
        assert [c["port_confirmed"] for c in written] == [False]

    def test_a_port_naabu_found_reads_open(self, recon_main, monkeypatch):
        written, _ = _written_cves(recon_main, monkeypatch, naabu_ports=[22, 80],
                                   nmap_ports=[22])
        assert [c["port_confirmed"] for c in written] == [True]

    def test_nmap_off_keeps_the_port_scan_verdict(self, recon_main, monkeypatch):
        written, _ = _written_cves(recon_main, monkeypatch, naabu_ports=[80], nmap_ports=[22],
                                   settings={"NMAP_ENABLED": False})
        assert [c["port_confirmed"] for c in written] == [False]


@pytest.mark.parametrize("name", ["run_ip_recon", "run_domain_recon"])
def test_both_pipelines_check_the_ports_after_the_nmap_merge(recon_main, name):
    body = inspect.getsource(getattr(recon_main, name))
    merge = body.index("merge_nmap_into_port_scan(combined_result)")
    check = body.index("_reachcheck_shodan_cves(combined_result,")
    write = body.index("_write_shodan_cves(combined_result)")
    assert merge < check < write
    assert body.count("_reachcheck_shodan_cves(") == 1
