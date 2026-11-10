"""Regression: a fan-out worker deep-copied combined_result while it was being merged (R-31).

Each `_isolated` wrapper deep-copies its input in its own worker thread. The
fan-outs (GROUP 3, the GROUP 3b OSINT enrichers and GROUP 6 Phase A, in both
modes) handed every worker the live combined_result and merged each finished
tool's answer into that same dict while other workers were still copying it,
so a slow copy could raise "dictionary changed size during iteration": that
tool's result was lost and its findings were kept as a phase error. Phase A
merges in completion order, and the OSINT pool starts its sixth and seventh
tools only when an earlier one finishes, so the window is real.

Every scanner and Neo4j is a fake; the fan-outs and the wrappers are real.
"""
from __future__ import annotations

import ast
import copy
import importlib
import re
import sys
import threading
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.main_recon_modules import origin_discovery as od  # noqa: E402
from recon.main_recon_modules import vuln_scan as vs  # noqa: E402

IP = "192.0.2.10"
VULN = {"findings": ["marker"], "summary": {"total_findings": 1}}
PORT_SCAN = {"scan_metadata": {}, "by_host": {}, "all_ports": [80], "summary": {},
             "by_ip": {IP: {"ip": IP, "hostnames": [], "ports": [80], "port_details": []}},
             "ip_to_hostnames": {}}

# Everything that is not a fan-out switched off, so a run reaches GROUP 3, the
# OSINT enrichers and Phase A with fakes only.
QUIET = {
    "DNS_ENABLED": False, "WHOIS_ENABLED": False, "URLSCAN_ENABLED": False,
    "SUBDOMAIN_DISCOVERY_ENABLED": False, "UNCOVER_ENABLED": False,
    "NMAP_ENABLED": False, "TLSX_ENABLED": False, "HTTPX_ENABLED": False,
    "SECURITY_CHECK_ENABLED": False, "AI_SURFACE_RECON_ENABLED": False,
    "JS_RECON_ENABLED": False, "SUPPLY_CHAIN_RECON_ENABLED": False, "MITRE_ENABLED": False,
    "CERT_HYGIENE_ENABLED": False, "SUBDOMAIN_TAKEOVER_ENABLED": False,
    "VHOST_SNI_ENABLED": False, "WEB_CACHE_POISON_ENABLED": False,
    "ROUTE_EXPOSURE_ENABLED": False, "ROE_ENABLED": False,
}
FAN_OUTS = {
    "SHODAN_ENABLED": True, "SHODAN_HOST_LOOKUP": True,
    "NAABU_ENABLED": True, "MASSCAN_ENABLED": True,
    "OSINT_ENRICHMENT_ENABLED": True, "CENSYS_ENABLED": True,
    "CENSYS_API_KEY": "synthetic-key", "OTX_ENABLED": True,
    "GRAPHQL_SECURITY_ENABLED": True, "ORIGIN_DISCOVERY_ENABLED": True,
}


@pytest.fixture
def recon_main(tmp_path, monkeypatch):
    stub = {
        'TARGET_DOMAIN': 'example.com', 'SUBDOMAIN_LIST': [], 'IP_MODE': False,
        'TARGET_IPS': [], 'DOMAIN_BATCH_MODE': False, 'DOMAIN_BATCH_GROUPS': [],
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
        monkeypatch.setattr(rm, "UPDATE_GRAPH_DB", False)
        yield rm


class _CopyHold:
    """Parks a deep copy made in one marked worker thread until released.

    Any other thread (the main thread, the fast worker) copies it at once, and
    every copy is this same object, so a copy of a copy still parks.
    """

    def __init__(self):
        self.thread = None
        self.parked = threading.Event()
        self.release = threading.Event()

    def __deepcopy__(self, memo):
        if threading.get_ident() == self.thread:
            self.parked.set()
            self.release.wait(timeout=5)
        return self


class TestPhaseAMergesWhileAWorkerCopies:
    def test_regression_a_merge_mid_copy_lost_the_slow_tool(self, recon_main, monkeypatch):
        rm, hold = recon_main, _CopyHold()

        def fast_origin(snapshot, settings):
            # Nothing CDN-fronted: origin discovery returns right after its copy,
            # once Nuclei's copy is under way.
            hold.parked.wait(timeout=5)
            snapshot["origin_discovery"] = {"candidates": []}
            return snapshot

        def slow_nuclei(snapshot, output_file=None, settings=None):
            snapshot["vuln_scan"] = dict(VULN)
            return snapshot

        def nuclei_thread(combined, settings):
            hold.thread = threading.get_ident()
            return vs.run_vuln_scan_isolated(combined, settings)

        def save(data, _out):
            if "origin_discovery" in data:
                hold.release.set()

        monkeypatch.setattr(od, "run_origin_discovery_enrichment", fast_origin)
        monkeypatch.setattr(vs, "run_vuln_scan", slow_nuclei)
        monkeypatch.setattr(rm, "save_recon_file", save)
        queued = []
        monkeypatch.setattr(rm, "_graph_update_bg", lambda name, *a: queued.append(name))
        combined = {"domain": "example.com", "hold": hold,
                    "metadata": {"modules_executed": []}}

        rm._run_phase_a_fan_out(
            {"origin_discovery": od.run_origin_discovery_enrichment_isolated,
             "vuln_scan": nuclei_thread},
            combined, {}, None)

        assert combined["metadata"].get("phase_errors", {}) == {}
        assert combined["vuln_scan"] == VULN
        assert combined["origin_discovery"] == {"candidates": []}
        assert sorted(combined["metadata"]["modules_executed"]) == ["origin_discovery", "vuln_scan"]
        assert sorted(queued) == ["update_graph_from_origin_discovery",
                                  "update_graph_from_vuln_scan"]

    def test_a_crashed_worker_is_still_a_phase_error(self, recon_main, monkeypatch):
        rm = recon_main
        noted = []
        monkeypatch.setattr(rm, "_note_phase_error", lambda phase, **k: noted.append(phase))
        monkeypatch.setattr(rm, "save_recon_file", lambda *a, **k: None)
        monkeypatch.setattr(rm, "_graph_update_bg", lambda *a, **k: None)

        def boom(*_a, **_k):
            raise RuntimeError("nuclei exploded")

        combined = {"domain": "example.com", "metadata": {"modules_executed": []}}
        rm._run_phase_a_fan_out({"vuln_scan": boom}, combined, {}, None)
        assert noted == ["vuln_scan"]
        assert combined["metadata"]["phase_errors"] == {"vuln_scan": "nuclei exploded"}


class _Recorder:
    """A fake `_isolated` wrapper: keeps what it was handed and a copy of it."""

    def __init__(self, calls, key, answer):
        self.calls, self.key, self.answer = calls, key, answer

    def __call__(self, combined, settings=None):
        self.calls.append((self.key, combined, copy.deepcopy(combined)))
        return copy.deepcopy(self.answer)


def _fake_wrappers(monkeypatch, rm):
    """Replace every wrapper the three fan-outs start; returns their call log."""
    from recon import graphql_scan
    from recon.main_recon_modules import censys_enrich, otx_enrich, shodan_enrich

    calls = []
    monkeypatch.setattr(shodan_enrich, "run_shodan_enrichment_isolated",
                        _Recorder(calls, "shodan", {}))
    monkeypatch.setattr(rm, "run_port_scan_isolated", _Recorder(calls, "port_scan", PORT_SCAN))
    monkeypatch.setattr(rm, "run_masscan_scan_isolated", _Recorder(calls, "masscan_scan", {}))
    monkeypatch.setattr(censys_enrich, "run_censys_enrichment_isolated",
                        _Recorder(calls, "censys", {"hosts": [IP]}))
    monkeypatch.setattr(otx_enrich, "run_otx_enrichment_isolated",
                        _Recorder(calls, "otx", {"pulses": [IP]}))
    monkeypatch.setattr(graphql_scan, "run_graphql_scan_isolated",
                        _Recorder(calls, "graphql_scan", {"endpoints": {}}))
    monkeypatch.setattr(od, "run_origin_discovery_enrichment_isolated",
                        _Recorder(calls, "origin_discovery", {"candidates": []}))
    monkeypatch.setattr(vs, "run_vuln_scan_isolated", _Recorder(calls, "vuln_scan", VULN))
    return calls


def _assert_every_worker_got_a_copy(calls, result, expected):
    assert sorted(key for key, *_ in calls) == sorted(expected)
    for key, handed, at_call in calls:
        assert handed is not result, f"{key} was handed the live combined_result"
        # The run went on merging into combined_result: what a worker was
        # handed must not have moved under it.
        assert handed == at_call, f"{key}'s input changed after it was handed over"


class TestEveryFanOutSiteHandsOverACopy:
    def test_ip_mode(self, recon_main, monkeypatch):
        rm = recon_main
        calls = _fake_wrappers(monkeypatch, rm)
        result = rm.run_ip_recon([IP], dict(QUIET, **FAN_OUTS))
        _assert_every_worker_got_a_copy(calls, result, [
            "shodan", "port_scan", "masscan_scan", "censys", "otx",
            "graphql_scan", "origin_discovery"])
        assert result["metadata"].get("phase_errors", {}) == {}
        for module in ("port_scan", "censys_enrich", "otx_enrich",
                       "graphql_scan", "origin_discovery"):
            assert module in result["metadata"]["modules_executed"], module

    def test_domain_mode(self, recon_main, monkeypatch):
        rm = recon_main
        calls = _fake_wrappers(monkeypatch, rm)
        monkeypatch.setattr(rm, "_settings", dict(QUIET, **FAN_OUTS))
        monkeypatch.setattr(rm, "SCAN_MODULES", ["port_scan", "vuln_scan"])
        target_info = rm.parse_target("example.com", ["www."])
        result = rm.run_domain_recon("example.com", target_info=target_info,
                                     discovery_enabled=False)
        _assert_every_worker_got_a_copy(calls, result, [
            "shodan", "port_scan", "masscan_scan", "censys", "otx",
            "vuln_scan", "graphql_scan", "origin_discovery"])
        assert result["metadata"].get("phase_errors", {}) == {}
        for module in ("port_scan", "censys_enrich", "otx_enrich",
                       "vuln_scan", "graphql_scan", "origin_discovery"):
            assert module in result["metadata"]["modules_executed"], module


#: Every `_isolated` wrapper main.py fans out, with the module that defines it;
#: its module function is the wrapper's name without `_isolated`.
FAN_OUT_WRAPPERS = {
    "run_shodan_enrichment_isolated": "recon.main_recon_modules.shodan_enrich",
    "run_port_scan_isolated": "recon.main_recon_modules.port_scan",
    "run_masscan_scan_isolated": "recon.main_recon_modules.masscan_scan",
    "run_censys_enrichment_isolated": "recon.main_recon_modules.censys_enrich",
    "run_fofa_enrichment_isolated": "recon.main_recon_modules.fofa_enrich",
    "run_otx_enrichment_isolated": "recon.main_recon_modules.otx_enrich",
    "run_netlas_enrichment_isolated": "recon.main_recon_modules.netlas_enrich",
    "run_virustotal_enrichment_isolated": "recon.main_recon_modules.virustotal_enrich",
    "run_zoomeye_enrichment_isolated": "recon.main_recon_modules.zoomeye_enrich",
    "run_criminalip_enrichment_isolated": "recon.main_recon_modules.criminalip_enrich",
    "run_vuln_scan_isolated": "recon.main_recon_modules.vuln_scan",
    "run_graphql_scan_isolated": "recon.graphql_scan.scanner",
    "run_subdomain_takeover_isolated": "recon.main_recon_modules.subdomain_takeover",
    "run_vhost_sni_enrichment_isolated": "recon.main_recon_modules.vhost_sni_enum",
    "run_cache_scan_isolated": "recon.cache_scan.scanner",
    "run_origin_discovery_enrichment_isolated": "recon.main_recon_modules.origin_discovery",
    "run_route_exposure_isolated": "recon.route_exposure.scanner",
}


def test_the_wrapper_table_lists_every_wrapper_main_fans_out():
    source = (PROJECT_ROOT / "recon" / "main.py").read_text()
    assert set(re.findall(r"run_[a-z_]+_isolated", source)) == set(FAN_OUT_WRAPPERS)


@pytest.mark.parametrize("wrapper", sorted(FAN_OUT_WRAPPERS))
def test_a_wrapper_never_writes_into_what_it_was_handed(wrapper, monkeypatch):
    """All the workers of a fan-out share one copy, so a write into it at any
    depth would race another worker's deep copy of it."""
    module = importlib.import_module(FAN_OUT_WRAPPERS[wrapper])

    def module_run(data, *_a, **_k):
        data["metadata"]["modules_executed"].append("written")
        data["dns"]["subdomains"]["www.example.com"]["ips"]["ipv4"].append("198.51.100.7")
        data["written"] = True
        return data

    monkeypatch.setattr(module, wrapper[:-len("_isolated")], module_run)
    handed = {"domain": "example.com", "metadata": {"modules_executed": []},
              "dns": {"subdomains": {"www.example.com": {"ips": {"ipv4": [IP]}}}}}
    before = copy.deepcopy(handed)
    getattr(module, wrapper)(handed, {})
    assert handed == before


def test_no_fan_out_in_main_submits_the_live_result():
    """A new fan-out that hands a worker combined_result itself fails here."""
    tree = ast.parse((PROJECT_ROOT / "recon" / "main.py").read_text())
    offenders = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "submit"):
            args = list(node.args) + [kw.value for kw in node.keywords]
            if any(isinstance(a, ast.Name) and a.id == "combined_result" for a in args):
                offenders.append(node.lineno)
    assert offenders == [], f"submit(..., combined_result, ...) at main.py lines {offenders}"
