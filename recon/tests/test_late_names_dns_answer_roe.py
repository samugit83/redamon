"""The late-name DNS step never stores an RoE-excluded address for a name (R-2, D2).

merge_discovered_hostnames admits a late name (tlsx, certificate SAN, JS Recon,
Uncover) on the addresses its own getaddrinfo saw (93a0b5bf). The late-name
step then resolves the name again with the domain step's resolver (dnspython),
and stores THAT answer: when it differs (round-robin DNS, a record that changed,
a split-horizon resolver), an admitted name could carry an excluded address
into dns.subdomains, and the late write minted a Subdomain with RESOLVES_TO to
it. The traffic builders refuse such a name, but the graph held it.

give_dns now re-checks the answer it stores: in domain mode, with RoE IP or
CIDR entries, a name with any excluded address is refused (dropped, never
narrowed) and noted as roe_excluded under the source that offered it. An answer
with no address is stored as before (the builders refuse it, kept as not
checked). With no address rule in force, and in IP mode, nothing changes.

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
from recon.helpers import late_names  # noqa: E402
from recon.helpers.target_helpers import merge_discovered_hostnames  # noqa: E402

ROOT = "example.com"
EXCLUDED_RANGE = "198.51.100.0/24"
# The merge's getaddrinfo sees an allowed address; the late step's lookup sees
# another answer.
DRIFT, DRIFT_OK, DRIFT_BAD = "drift.example.com", "192.0.2.6", "198.51.100.20"
MIXED, MIXED_OK, MIXED_BAD = "drift-mixed.example.com", "192.0.2.7", "198.51.100.21"
STEADY, STEADY_IP = "api.example.com", "192.0.2.8"
GONE, GONE_IP = "gone.example.com", "192.0.2.9"           # the second lookup finds nothing

GETADDRINFO = {DRIFT: [DRIFT_OK], MIXED: [MIXED_OK], STEADY: [STEADY_IP], GONE: [GONE_IP]}
DNS_LOOKUP = {DRIFT: [DRIFT_BAD], MIXED: [MIXED_OK, MIXED_BAD], STEADY: [STEADY_IP], GONE: []}
NAMES = [STEADY, DRIFT, MIXED, GONE]

ROE = {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": [EXCLUDED_RANGE]}
NO_ADDRESS_RULE = [
    {},
    {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": []},
    {"ROE_ENABLED": False, "ROE_EXCLUDED_HOSTS": [EXCLUDED_RANGE]},
    {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": ["shop.example.com"]},
]
TOKEN = re.compile(r"^[a-z0-9_]{1,64}$")


@pytest.fixture(autouse=True)
def _dns(monkeypatch):
    """getaddrinfo (the merge) answers GETADDRINFO; dns_lookup (the late step)
    answers DNS_LOOKUP; the wildcard control finds no wildcard."""
    from recon.helpers import wildcard_control
    from recon.main_recon_modules import domain_recon, ip_filter

    # RFC 5737 ranges stand in for public addresses: the routability guards
    # read them as reserved and would drop every name before the RoE gate.
    documentation = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24")]
    routable = ip_filter.is_non_routable_ip
    monkeypatch.setattr(ip_filter, "is_non_routable_ip", lambda a: (
        False if any(ipaddress.ip_address(a) in n for n in documentation) else routable(a)))

    def getaddrinfo(host, *_a, **_k):
        if host not in GETADDRINFO:
            raise socket.gaierror(socket.EAI_NONAME, "unknown name")
        return [(socket.AF_INET, 1, 6, "", (a, 0)) for a in GETADDRINFO[host]]

    def dns_lookup(host, *_a, **_k):
        v4 = list(DNS_LOOKUP.get(host, []))
        return {"records": {"A": v4} if v4 else {}, "ips": {"ipv4": v4, "ipv6": []},
                "has_records": bool(v4)}

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(domain_recon, "dns_lookup", dns_lookup)
    monkeypatch.setattr(wildcard_control, "_query", lambda name, rtype: ("nx", []))
    domain_recon.resolver_breaker.reset()
    circuit_breaker.reset_registry()
    yield
    circuit_breaker.reset_registry()


def _group() -> dict:
    """One scope group's recon dict at GROUP 3.6 (after the port scan)."""
    return {"domain": ROOT,
            "metadata": {"root_domain": ROOT, "org_domain": ROOT, "scope_mode": "enumerate",
                         "include_root_domain": False},
            "dns": {"domain": {}, "subdomains": {}},
            "port_scan": {"by_ip": {ip: {"ip": ip, "hostnames": [], "ports": [443]}
                                    for ip in (DRIFT_OK, DRIFT_BAD, MIXED_OK, MIXED_BAD, STEADY_IP,
                                               GONE_IP)},
                          "by_host": {}, "all_ports": [443]}}


def _merged_group(settings: dict, source: str = "tlsx") -> dict:
    combined = _group()
    merge_discovered_hostnames(combined, list(NAMES), source=source, root_domain=ROOT,
                               settings=settings, max_injected=200)
    return combined


def _roe_gaps() -> list:
    return [dict(g) for g in circuit_breaker.coverage_report().gaps if g["source"] == "roe_excluded"]


def _addresses(combined: dict, name: str) -> list:
    ips = (combined["dns"]["subdomains"].get(name) or {}).get("ips") or {}
    return list(ips.get("ipv4") or []) + list(ips.get("ipv6") or [])


def test_the_merge_admits_every_name_on_getaddrinfos_answer():
    # The precondition: the merge's own lookup saw allowed addresses only.
    assert set(_merged_group(ROE)["dns"]["subdomains"]) == set(NAMES)


# --------------------------------------------------------------------------
# give_dns
# --------------------------------------------------------------------------

def test_a_name_whose_stored_answer_is_excluded_is_dropped():
    combined = _merged_group(ROE)
    resolved = late_names.give_dns(combined, list(NAMES), ROE)
    assert DRIFT not in resolved
    assert DRIFT not in combined["dns"]["subdomains"]


def test_a_name_with_one_excluded_address_in_its_answer_is_dropped_not_narrowed():
    combined = _merged_group(ROE)
    resolved = late_names.give_dns(combined, list(NAMES), ROE)
    assert MIXED not in resolved
    assert MIXED not in combined["dns"]["subdomains"]


def test_an_allowed_answer_is_stored_with_its_source():
    combined = _merged_group(ROE)
    resolved = late_names.give_dns(combined, list(NAMES), ROE)
    assert STEADY in resolved
    assert _addresses(combined, STEADY) == [STEADY_IP]
    assert combined["dns"]["subdomains"][STEADY]["source"] == "tlsx"


def test_no_stored_address_is_ever_excluded():
    combined = _merged_group(ROE)
    late_names.give_dns(combined, list(NAMES), ROE)
    net = ipaddress.ip_network(EXCLUDED_RANGE)
    stored = [a for n in combined["dns"]["subdomains"] for a in _addresses(combined, n)]
    assert not [a for a in stored if ipaddress.ip_address(a) in net]


def test_an_answer_with_no_address_is_kept_as_before():
    # Nothing excluded is stored; the builders refuse an address-less name
    # under IP entries and keep it as not checked.
    combined = _merged_group(ROE)
    resolved = late_names.give_dns(combined, list(NAMES), ROE)
    assert GONE not in resolved
    assert combined["dns"]["subdomains"][GONE]["has_records"] is True
    assert _addresses(combined, GONE) == []


def test_each_refusal_is_noted_as_roe_excluded_under_the_offering_source(capsys):
    combined = _merged_group(ROE, source="certificate_san")
    capsys.readouterr()
    late_names.give_dns(combined, list(NAMES), ROE)
    gaps = _roe_gaps()
    assert gaps, "no roe_excluded coverage note"
    assert {g["module"] for g in gaps} == {"certificate_san"}
    assert all(TOKEN.match(g["module"]) and TOKEN.match(g["source"]) for g in gaps)
    log = capsys.readouterr().out
    lines = [line for line in log.splitlines() if line.startswith("[-][RoE] certificate_san:")]
    for refused in (DRIFT, DRIFT_BAD, MIXED, MIXED_BAD):
        assert any(refused in line for line in lines), refused
    assert not any(STEADY in line or MIXED_OK in line for line in lines)


def test_an_excluded_answer_is_a_report_gap_only():
    combined = _merged_group(ROE)
    late_names.give_dns(combined, list(NAMES), ROE)
    report = circuit_breaker.coverage_report()
    assert not report.degraded_sources
    assert DRIFT not in report.skipped_hostnames()


@pytest.mark.parametrize("settings", NO_ADDRESS_RULE, ids=["no_keys", "empty", "off", "names_only"])
def test_without_an_address_rule_give_dns_is_unchanged(settings):
    baseline = _merged_group({})
    late_names.give_dns(baseline, list(NAMES), {})
    combined = _merged_group(settings)
    late_names.give_dns(combined, list(NAMES), settings)
    assert combined == baseline
    assert _addresses(combined, DRIFT) == [DRIFT_BAD]
    assert _roe_gaps() == []


# --------------------------------------------------------------------------
# main._late_names and the real domain-discovery writer
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


def _late(monkeypatch, settings: dict, *, after_port_scan: bool):
    import main as recon_main

    queued = []
    monkeypatch.setattr(recon_main, "save_recon_file", lambda *_a, **_k: None)
    monkeypatch.setattr(recon_main, "_graph_update_bg",
                        lambda method, data, *_a, **_k: queued.append((method, copy.deepcopy(data))))
    combined = _group()
    before = recon_main._dns_names(combined)
    merge_discovered_hostnames(combined, list(NAMES), source="tlsx", root_domain=ROOT,
                               settings=settings, max_injected=200)
    recon_main._late_names(combined, before, settings, None, after_port_scan=after_port_scan,
                           probe_http=False, label="tlsx")
    return combined, queued


def test_the_late_write_holds_no_refused_name_and_no_excluded_address(monkeypatch):
    _combined, queued = _late(monkeypatch, ROE, after_port_scan=True)
    discovery = [data for method, data in queued if method == "update_graph_from_domain_discovery"]
    assert discovery, "the late-name step wrote nothing"
    session, stats = _write_domain_discovery({**discovery[0], "whois": {}})
    assert stats["errors"] == []
    minted = {p["name"] for c, p in session.calls if "MERGE (s:Subdomain" in c}
    assert DRIFT not in minted and MIXED not in minted and STEADY in minted
    resolves = {p["ip"] for c, p in session.calls if "RESOLVES_TO" in c}
    assert not resolves & {DRIFT_BAD, MIXED_BAD}


def test_before_the_port_scan_the_run_keeps_no_excluded_address(monkeypatch):
    # Uncover's names: DNS only, before the port scan reads dns.subdomains.
    combined, _queued = _late(monkeypatch, ROE, after_port_scan=False)
    assert DRIFT not in combined["dns"]["subdomains"]
    assert MIXED not in combined["dns"]["subdomains"]
    assert _addresses(combined, STEADY) == [STEADY_IP]


def test_without_an_exclusion_the_late_write_is_unchanged(monkeypatch):
    _combined, queued = _late(monkeypatch, {}, after_port_scan=True)
    discovery = [data for method, data in queued if method == "update_graph_from_domain_discovery"]
    session, _stats = _write_domain_discovery({**discovery[0], "whois": {}})
    minted = {p["name"] for c, p in session.calls if "MERGE (s:Subdomain" in c}
    assert {STEADY, DRIFT, MIXED} <= minted
