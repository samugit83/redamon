"""A late name on an RoE-excluded address never joins the scan (D2, R-2).

merge_discovered_hostnames feeds certificate SANs (tlsx, the httpx SAN
feedback), JS Recon and Uncover names into the late-name scan. It checked the
RoE by name only: a name resolving into an excluded range was added, the
late-name DNS step wrote it as a Subdomain with RESOLVES_TO to the excluded
address (which partial runs read back as a target), and the report never said
the RoE had kept it out.

In domain mode the merge now admits its names through the target-admission
gate, on the addresses its own resolve-and-check lookup already saw (no new
DNS query) and those the run's DNS data holds: a name with any excluded
address is refused, a name with no address is refused while IP or CIDR entries
exist (kept as not checked), and each such refusal is noted under
`roe_excluded`. A refusal by name stays a log line, as discovery's do. IP mode
is unchanged: its late names are the hostname rule's pinned answers.

The real merge, late-name step and graph writer run; DNS, the run's file and
Neo4j are the fakes. Only example.com names and RFC 5737 addresses.
"""
from __future__ import annotations

import copy
import ipaddress
import re
import socket
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_RECON = Path(__file__).resolve().parent.parent
_REPO = _RECON.parent
for _p in (str(_REPO), str(_RECON)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from recon.helpers import circuit_breaker  # noqa: E402
from recon.helpers.target_helpers import merge_discovered_hostnames  # noqa: E402

ROOT = "example.com"
EXCLUDED_RANGE = "198.51.100.0/24"
LEGACY, LEGACY_IP = "legacy.example.com", "198.51.100.20"            # an excluded address only
MIXED, MIXED_BAD, MIXED_OK = "mixed.example.com", "198.51.100.21", "192.0.2.7"
KEPT, KEPT_IP = "api.example.com", "192.0.2.6"
NAMED, NAMED_IP = "shop.example.com", "192.0.2.8"                    # excluded by name
GHOST = "ghost.example.com"                                          # no address at all

ADDRESSES = {LEGACY: [LEGACY_IP], MIXED: [MIXED_BAD, MIXED_OK], KEPT: [KEPT_IP], NAMED: [NAMED_IP]}
SANS = [KEPT, LEGACY, MIXED, NAMED, GHOST]
ROE = {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": [EXCLUDED_RANGE, NAMED]}
NO_ROE = [
    {},
    {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": []},
    {"ROE_ENABLED": False, "ROE_EXCLUDED_HOSTS": [EXCLUDED_RANGE, NAMED]},
]
TOKEN = re.compile(r"^[a-z0-9_]{1,64}$")


@pytest.fixture(autouse=True)
def _dns(monkeypatch):
    """The merge's own getaddrinfo, the late-name DNS step's lookup and the
    wildcard control's probe, answered from ADDRESSES. Every getaddrinfo is
    recorded, so a test can see the gate sends no query of its own."""
    from recon.helpers import wildcard_control
    from recon.main_recon_modules import domain_recon, ip_filter

    asked = []
    # The RFC 5737 ranges stand in for public addresses here; the merge's and
    # the DNS step's routability guard reads them as reserved and would drop
    # every name before the RoE gate is reached.
    documentation = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24")]
    routable = ip_filter.is_non_routable_ip
    monkeypatch.setattr(ip_filter, "is_non_routable_ip", lambda a: (
        False if any(ipaddress.ip_address(a) in n for n in documentation) else routable(a)))

    def getaddrinfo(host, *_a, **_k):
        asked.append(host)
        if host not in ADDRESSES:
            raise socket.gaierror(socket.EAI_NONAME, "unknown name")
        return [(socket.AF_INET6 if ":" in a else socket.AF_INET, 1, 6, "", (a, 0))
                for a in ADDRESSES[host]]

    def dns_lookup(host, *_a, **_k):
        v4 = [a for a in ADDRESSES.get(host, []) if ":" not in a]
        return {"records": {"A": v4} if v4 else {}, "ips": {"ipv4": v4, "ipv6": []},
                "has_records": bool(v4)}

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(domain_recon, "dns_lookup", dns_lookup)
    monkeypatch.setattr(wildcard_control, "_query", lambda name, rtype: ("nx", []))
    domain_recon.resolver_breaker.reset()
    circuit_breaker.reset_registry()
    yield asked
    circuit_breaker.reset_registry()


def _group(ip_mode: bool = False) -> dict:
    """One scope group's recon dict at GROUP 3.6 (after the port scan)."""
    metadata = {"root_domain": ROOT, "org_domain": ROOT, "scope_mode": "enumerate",
                "include_root_domain": False}
    if ip_mode:
        metadata.update(ip_mode=True, expanded_ips=[KEPT_IP, MIXED_OK, LEGACY_IP])
    return {"domain": ROOT, "metadata": metadata,
            "dns": {"domain": {}, "subdomains": {}},
            "port_scan": {"by_ip": {ip: {"ip": ip, "hostnames": [], "ports": [443]}
                                    for ip in (KEPT_IP, MIXED_OK, MIXED_BAD, LEGACY_IP, NAMED_IP)},
                          "by_host": {}, "all_ports": [443]}}


def _merge(combined: dict, settings: dict, names=SANS, source: str = "tlsx") -> dict:
    return merge_discovered_hostnames(combined, list(names), source=source, root_domain=ROOT,
                                      settings=settings, max_injected=200)


def _merged(combined: dict) -> set:
    return set(combined["dns"]["subdomains"])


def _roe_gaps() -> list:
    return [dict(g) for g in circuit_breaker.coverage_report().gaps if g["source"] == "roe_excluded"]


# --------------------------------------------------------------------------
# The merge
# --------------------------------------------------------------------------

def test_a_name_on_an_excluded_address_only_is_refused():
    combined = _merge(_group(), ROE)
    assert LEGACY not in _merged(combined)


def test_a_name_with_one_excluded_address_is_refused():
    # httpx, Nuclei and the crawlers resolve a name themselves and could reach
    # it on the excluded address: refused whole, not narrowed.
    combined = _merge(_group(), ROE)
    assert MIXED not in _merged(combined)


def test_an_allowed_name_is_still_admitted_with_its_source():
    combined = _merge(_group(), ROE)
    assert KEPT in _merged(combined)
    assert combined["dns"]["subdomains"][KEPT]["source"] == "tlsx"


def test_a_name_the_roe_excludes_by_name_is_refused():
    combined = _merge(_group(), ROE)
    assert NAMED not in _merged(combined)


def test_every_address_refusal_is_noted_as_roe_excluded_coverage(capsys):
    _merge(_group(), ROE)

    gaps = _roe_gaps()
    assert gaps, "no roe_excluded coverage note"
    assert {g["module"] for g in gaps} == {"tlsx"}
    assert all(TOKEN.match(g["source"]) and TOKEN.match(g["module"]) for g in gaps)
    excluded = [g for g in gaps if g["reason"].startswith("RoE exclusion")]
    # Each excluded address (with its name) and each refused name: legacy's
    # address and name, mixed's excluded address and name.
    assert [g["skipped"] for g in excluded] == [4]
    log = capsys.readouterr().out
    refusal_lines = [line for line in log.splitlines() if line.startswith("[-][RoE] tlsx:")]
    for refused in (LEGACY, LEGACY_IP, MIXED, MIXED_BAD, GHOST):
        assert any(refused in line for line in refusal_lines), refused
    assert not any(KEPT in line or MIXED_OK in line for line in refusal_lines)


def test_a_refusal_by_name_stays_a_log_line_as_discoverys_do(capsys):
    # The operator typed that name: like discovery's, the by-name refusal is
    # logged, never a coverage gap (a partial root would read as degraded).
    combined = _merge(_group(), ROE, names=[KEPT, NAMED])
    assert _merged(combined) == {KEPT}
    assert _roe_gaps() == []
    assert "[RoE] Excluded 1 SAN hostname(s) per Rules of Engagement" in capsys.readouterr().out


def test_the_note_names_the_source_that_offered_the_name():
    _merge(_group(), ROE, names=[LEGACY], source="certificate_san")
    assert {g["module"] for g in _roe_gaps()} == {"certificate_san"}


def test_an_excluded_address_is_a_report_gap_only():
    # The excluded asset is out of the run by decision: nothing is kept from
    # the prune for it.
    _merge(_group(), {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": [EXCLUDED_RANGE]},
           names=[KEPT, LEGACY, MIXED])
    report = circuit_breaker.coverage_report()
    assert not report.degraded_sources
    assert not report.skipped_hostnames()


def test_an_unresolved_name_is_refused_while_ip_entries_exist_and_kept_as_not_checked():
    combined = _merge(_group(), ROE)
    assert GHOST not in _merged(combined)
    assert GHOST in circuit_breaker.coverage_report().skipped_hostnames()


def test_with_host_entries_only_names_are_judged_by_name():
    combined = _merge(_group(), {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": [NAMED]})
    assert _merged(combined) == {KEPT, LEGACY, MIXED, GHOST}
    assert _roe_gaps() == []


def test_the_gate_reads_the_runs_dns_data_too():
    # A name the run already resolved: its stored addresses count, even when
    # the merge's lookup sees only an allowed one.
    combined = _group()
    combined["port_scan"]["ip_to_hostnames"] = {LEGACY_IP: [KEPT]}
    _merge(combined, ROE, names=[KEPT])
    assert KEPT not in _merged(combined)


def test_partial_js_recons_list_of_subdomains_never_breaks_the_merge():
    # Partial JS Recon builds dns.subdomains as a list of graph rows; a raise
    # here would abort run_js_recon and drop every finding it made.
    combined = {"domain": ROOT, "domains": [ROOT], "metadata": {"project_id": "p1"},
                "dns": {"subdomains": [{"subdomain": KEPT, "source": "graph"}]}}
    merge_discovered_hostnames(combined, [LEGACY, KEPT], source="js_recon", root_domain=[ROOT],
                               settings=ROE, max_injected=200)
    assert _merged(combined) == {KEPT}
    assert {g["module"] for g in _roe_gaps()} == {"js_recon"}


def test_the_gate_sends_no_dns_query_of_its_own(_dns):
    _merge(_group(), ROE)
    # One lookup per name the RoE did not exclude by name, as before the gate.
    assert sorted(_dns) == sorted([KEPT, LEGACY, MIXED, GHOST])


@pytest.mark.parametrize("settings", NO_ROE, ids=["no_keys", "empty", "off"])
def test_without_an_exclusion_the_merge_is_unchanged(settings):
    baseline = _merge(_group(), {})
    combined = _merge(_group(), settings)
    assert combined == baseline
    assert _merged(combined) == {KEPT, LEGACY, MIXED, NAMED, GHOST}
    assert _roe_gaps() == []


# --------------------------------------------------------------------------
# The late-name scan and its graph write (main._late_names, the real writer)
# --------------------------------------------------------------------------

class _Session:
    def __init__(self):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def run(self, cypher, **params):
        self.calls.append((cypher, params))
        result = MagicMock()
        result.single.return_value = None
        result.__iter__ = lambda _s: iter([])
        return result


def _write_domain_discovery(sub: dict):
    from graph_db.mixins.recon.domain_mixin import DomainMixin

    session = _Session()
    writer = DomainMixin()
    writer.driver = MagicMock()
    writer.driver.session.return_value = session
    stats = writer.update_graph_from_domain_discovery(sub, "u1", "p1")
    return session, stats


def _group_3_6(monkeypatch, settings: dict) -> list:
    """GROUP 3.6 in run_domain_recon: the merge, then _late_names. Returns the
    queued graph writes."""
    import main as recon_main

    queued = []
    monkeypatch.setattr(recon_main, "save_recon_file", lambda *_a, **_k: None)
    monkeypatch.setattr(recon_main, "_graph_update_bg",
                        lambda method, data, *_a, **_k: queued.append((method, copy.deepcopy(data))))
    combined = _group()
    before = recon_main._dns_names(combined)
    _merge(combined, settings)
    recon_main._late_names(combined, before, settings, None, after_port_scan=True,
                           probe_http=False, label="tlsx")
    return queued


def test_the_late_name_write_holds_no_refused_name_and_no_excluded_address(monkeypatch):
    queued = _group_3_6(monkeypatch, ROE)
    discovery = [data for method, data in queued if method == "update_graph_from_domain_discovery"]
    assert discovery, "the late-name step wrote nothing"

    session, stats = _write_domain_discovery(discovery[0])
    assert stats["errors"] == []
    minted = {p["name"] for c, p in session.calls if "MERGE (s:Subdomain" in c}
    assert minted == {KEPT}
    resolves = {(p["subdomain"], p["ip"]) for c, p in session.calls if "RESOLVES_TO" in c}
    assert resolves == {(KEPT, KEPT_IP)}
    ips = {p["address"] for c, p in session.calls if "MERGE (i:IP" in c}
    assert not ips & {LEGACY_IP, MIXED_BAD}


def test_without_an_exclusion_the_late_name_write_is_unchanged(monkeypatch):
    queued = _group_3_6(monkeypatch, {})
    discovery = [data for method, data in queued if method == "update_graph_from_domain_discovery"]
    session, _stats = _write_domain_discovery(discovery[0])
    minted = {p["name"] for c, p in session.calls if "MERGE (s:Subdomain" in c}
    assert minted == {KEPT, LEGACY, MIXED, NAMED}


# --------------------------------------------------------------------------
# IP mode: unchanged (its late names are the hostname rule's pinned answers)
# --------------------------------------------------------------------------

def test_ip_mode_merge_is_unchanged():
    combined = _merge(_group(ip_mode=True), ROE)
    # By name only, as before: the IP-mode late scan judges the addresses.
    assert _merged(combined) == {KEPT, LEGACY, MIXED, GHOST}
    assert _roe_gaps() == []
