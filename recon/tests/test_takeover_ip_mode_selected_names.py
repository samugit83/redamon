"""Subdomain takeover in IP mode checks the selected hostnames only (P4, matrix §1).

A takeover is a dangling NAME. An IP-mode run's targets are addresses, so its
labels, its address literals and the URLs on them are nothing to take over,
and a recorded hostname is no target (I-4). The names to check are exactly the
ones the selection rule scanned (metadata.ip_mode_hosts): none in IP only and
record only, the selected set in record_filter and scan_all. The live URLs
nuclei's takeover templates get are those names' URLs.

Before P4 the collectors handed IP-mode runs their address literals (they
contain dots) and every live IP URL. Documentation ranges and reserved names
only.
"""
from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.main_recon_modules import subdomain_takeover as st  # noqa: E402

T1, T2 = "203.0.113.10", "203.0.113.11"
APP, OLD = "app.example.com", "old.example.com"


def _recon(hosts=None):
    labels = {T1: "203-0-113-10", T2: "203-0-113-11"}
    subs = {label: {"is_mock": True, "actual_ip": ip, "has_records": True,
                    "ips": {"ipv4": [ip], "ipv6": []}} for ip, label in labels.items()}
    run = {
        "domain": "ip-targets.cmtakeoveripmode0000000001",
        "metadata": {"ip_mode": True, "expanded_ips": [T1, T2], "scope_mode": "exact",
                     "include_root_domain": False, "root_domain": "ip-targets.cmtakeoveripmode0000000001",
                     "subdomain_filter": [T1, T2, *labels.values()]},
        "subdomains": list(labels.values()),
        "dns": {"domain": {}, "subdomains": subs},
        "http_probe": {"by_url": {f"https://{T1}": {"status_code": 200},
                                  f"http://{T2}:8080": {"status_code": 200}},
                       "by_host": {T1: {"live_urls": [f"https://{T1}"]}}},
        "ip_hostnames": {"candidates": {OLD: {"reason": "filter_no_match", "ips_seen": [T1]}}},
    }
    for name, org in (hosts or {}).items():
        subs[name] = {"has_records": True, "ips": {"ipv4": [T1], "ipv6": []}, "source": "ip_hostname_selection"}
        run["subdomains"].append(name)
        run["metadata"]["subdomain_filter"].append(name)
        run["metadata"].setdefault("ip_mode_hosts", {})[name] = org
        run["http_probe"]["by_url"][f"https://{name}"] = {"host": name, "status_code": 404}
    return run


def test_without_selected_names_ip_mode_checks_nothing():
    run = _recon()
    assert st._collect_subdomains(run, {"IP_MODE": True}) == []
    assert st._collect_alive_urls(run, {"IP_MODE": True}) == []


def test_the_selected_names_and_their_urls_only():
    run = _recon({APP: "example.com"})
    assert st._collect_subdomains(run, {"IP_MODE": True}) == [APP]
    assert st._collect_alive_urls(run, {"IP_MODE": True}) == [f"https://{APP}"]


def test_a_recorded_name_in_the_dns_block_is_still_not_checked():
    run = _recon({APP: "example.com"})
    run["dns"]["subdomains"][OLD] = {"has_records": True, "ips": {"ipv4": [T1], "ipv6": []}}
    run["http_probe"]["by_url"][f"https://{OLD}"] = {"host": OLD, "status_code": 200}
    assert st._collect_subdomains(run, {"IP_MODE": True}) == [APP]
    assert f"https://{OLD}" not in st._collect_alive_urls(run, {"IP_MODE": True})


def test_the_roe_still_applies_to_a_selected_name():
    run = _recon({APP: "example.com"})
    settings = {"IP_MODE": True, "ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": [APP]}
    assert st._collect_subdomains(run, settings) == []
    assert st._collect_alive_urls(run, settings) == []


def test_the_run_reports_no_targets_in_record_only():
    out = st.run_subdomain_takeover(_recon(), settings={"SUBDOMAIN_TAKEOVER_ENABLED": True, "IP_MODE": True})
    assert out["subdomain_takeover"]["scan_metadata"]["skipped_reason"] == "no_targets"
