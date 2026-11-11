"""VHost/SNI in IP mode: live ports only, and the selected hostnames as candidates (P4).

Live ports. _collect_ip_targets added a default 80 and 443 for every address
the DNS block knew, and in IP mode every target is there (its placeholder). On
an HTTP-only target the :443 baseline then failed, the port was recorded as a
skipped host ("<ip>:443"), and the triage, which reads skipped hosts by
address, counted the whole IP as unchecked (Shodan CVEs reachable_now null).
In IP mode an address is now probed only on a port this run found live (the
port scan's open ports, a live httpx URL, the evidence security_checks reads);
a port with no evidence is neither probed nor recorded. When an evidence
source was cut, an unproven port may still be live, so the source is kept
whole (a source-level note, never a host). Domain mode is unchanged.

Candidates. A hostname the selection rule scanned may be tried on the target
IPs it was seen on and on those its pinned answer names, never on a shared CDN
edge (the edge rule recorded names follow, B-31).

curl and the probe are stubbed. Documentation ranges and reserved names only.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers import circuit_breaker  # noqa: E402
from recon.main_recon_modules import vhost_sni_enum as vs  # noqa: E402

T1, T2, T3 = "203.0.113.10", "203.0.113.11", "203.0.113.12"
APP, OLD = "app.example.com", "old.example.com"


@pytest.fixture(autouse=True)
def _fresh_run():
    circuit_breaker.reset_registry()
    yield
    circuit_breaker.reset_registry()


def _recon(**extra):
    labels = {ip: ip.replace(".", "-") for ip in (T1, T2, T3)}
    run = {
        "domain": "ip-targets.cmvhostipmodetargets0000001",
        "metadata": {"ip_mode": True, "expanded_ips": [T1, T2, T3]},
        "dns": {"domain": {}, "subdomains": {
            label: {"is_mock": True, "actual_ip": ip, "has_records": True,
                    "ips": {"ipv4": [ip], "ipv6": []}} for ip, label in labels.items()}},
        # T1 serves HTTP only; T2 has nothing in the port scan; T3 serves 443.
        "port_scan": {"by_host": {T1: {"ip": T1, "ports": [80]}, T3: {"ip": T3, "ports": [443]}},
                      "by_ip": {T1: {"ports": [80]}, T3: {"ports": [443]}}},
    }
    run.update(extra)
    return run


def _ports(targets):
    return {ip: sorted(p["port"] for p in plist) for ip, plist in targets.items()}


# ---------------------------------------------------------------------------
# Live ports
# ---------------------------------------------------------------------------

def test_an_http_only_target_gets_no_443_probe():
    assert _ports(vs._collect_ip_targets(_recon())) == {T1: [80], T3: [443]}


def test_a_live_httpx_url_is_evidence_too():
    run = _recon(http_probe={"by_url": {f"https://{T2}/": {"url": f"https://{T2}/", "ip": T2,
                                                           "status_code": 404}}})
    assert _ports(vs._collect_ip_targets(run))[T2] == [443]


def test_a_target_with_no_evidence_is_neither_probed_nor_noted():
    targets = vs._collect_ip_targets(_recon())
    assert T2 not in targets
    report = circuit_breaker.coverage_report()
    assert not report.skipped_hosts and not report.degraded_sources


def test_a_cut_evidence_source_keeps_the_vhost_source_whole_without_naming_a_host():
    run = _recon()
    run["metadata"]["phase_errors"] = {"port_scan": "naabu crashed"}
    targets = vs._collect_ip_targets(run)
    assert T2 not in targets
    report = circuit_breaker.coverage_report()
    assert "vhost_sni_enum" in report.degraded_sources
    assert not report.skipped_hosts


def test_domain_mode_keeps_the_default_web_ports():
    run = _recon()
    run["metadata"] = {"ip_mode": False}
    run["dns"]["subdomains"]["www.example.org"] = {"ips": {"ipv4": [T2], "ipv6": []}}
    assert _ports(vs._collect_ip_targets(run))[T2] == [80, 443]


def test_the_run_records_no_skipped_host_for_an_unproven_port(monkeypatch):
    probed = []

    def probe(*, ip, ports, **_k):
        probed.append((ip, sorted(p["port"] for p in ports)))
        return {"ports_tested": 1, "candidates_tested": 0, "anomalies": [],
                "unreachable_ports": [], "unchecked_ports": []}

    monkeypatch.setattr(vs, "_probe_single_ip", probe)
    monkeypatch.setattr(vs, "_is_curl_available", lambda: True)
    vs.run_vhost_sni_enrichment(_recon(), {"VHOST_SNI_ENABLED": True, "IP_MODE": True,
                                           "IP_HOSTNAME_MODE": "ip_only"})
    assert sorted(probed) == [(T1, [80]), (T3, [443])]
    assert not any(h.endswith(":443") and h.startswith(T1)
                   for h in circuit_breaker.coverage_report().skipped_hosts)


# ---------------------------------------------------------------------------
# Selected names as candidates
# ---------------------------------------------------------------------------

def _named(edge=()):
    by_ip = {ip: {"ownership": "shared_edge" if ip in edge else "dedicated", "ownership_reasons": []}
             for ip in (T1, T2, T3)}
    return _recon(ip_attribution={"by_ip": by_ip}, ip_hostnames={"candidates": {
        APP: {"ips_seen": [T1], "reason": "scanned", "resolves_to_now": [T3]},
        OLD: {"ips_seen": [T1], "reason": "filter_no_match"},
    }})


def test_a_selected_name_is_tried_where_it_was_seen_and_where_it_resolves():
    names = vs._ip_mode_names(_named(), {"IP_HOSTNAME_MODE": "record_filter"}, [T1, T2, T3])
    assert names == {T1: [APP, OLD], T3: [APP]}


def test_a_selected_name_never_reaches_a_shared_edge():
    names = vs._ip_mode_names(_named(edge=[T3]), {"IP_HOSTNAME_MODE": "record_filter"}, [T1, T2, T3])
    assert names == {T1: [APP, OLD]}


def test_an_answer_off_the_probed_ips_adds_nothing():
    run = _named()
    run["ip_hostnames"]["candidates"][APP]["resolves_to_now"] = ["198.51.100.7"]
    assert vs._ip_mode_names(run, {"IP_HOSTNAME_MODE": "scan_all"}, [T1, T2, T3]) == {T1: [APP, OLD]}
