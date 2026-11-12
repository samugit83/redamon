"""GROUP 1 never keeps a discovered name on an RoE-excluded address (R-2, D2).

merge_group_hosts applied the RoE by name only (_filter_roe_excluded and
_drop_roe_excluded_subdomains): a discovered name that resolves into an
excluded IP or CIDR stayed in the subdomain list and dns.subdomains, and the
GROUP 1 write minted it as a Subdomain with RESOLVES_TO to the excluded
address. The traffic builders refuse such a name, but the graph held it, and
partial runs read it back.

The merge now passes each discovered name that has an address through the
admission gate, on the addresses discovery's DNS pass already resolved (no new
query): a name with any excluded address is refused, dropped from the list,
the DNS map and the status map (never narrowed), and noted as roe_excluded.
A discovered name with no address is kept as before (the builders refuse it
as not checked under IP entries). The scan root and the hosts the operator
listed are not judged here, as for the SSRF guard: the builders' gate refuses
them as targets. With no address rule in force the merge is byte-identical.

The real merge and graph writer run; the resolver and Neo4j are the fakes.
Only example.test names and RFC 5737 addresses.
"""
from __future__ import annotations

import copy
import re
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
from recon.main import merge_group_hosts  # noqa: E402

ROOT = "example.test"
EXCLUDED_RANGE = "198.51.100.0/24"
APP, APP_IP = "app.example.test", "192.0.2.10"
LEGACY, LEGACY_IP = "legacy.example.test", "198.51.100.20"        # an excluded address only
MIXED, MIXED_OK, MIXED_BAD = "mixed.example.test", "192.0.2.11", "198.51.100.21"
GHOST = "ghost.example.test"                                       # no address
LISTED, LISTED_IP = "listed.example.test", "198.51.100.30"         # the operator's host
HIST, HIST_IP = "hist.example.test", "198.51.100.40"               # urlscan-injected

ROE = {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": [EXCLUDED_RANGE]}
NO_ADDRESS_RULE = [
    {},
    {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": []},
    {"ROE_ENABLED": False, "ROE_EXCLUDED_HOSTS": [EXCLUDED_RANGE]},
    {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": ["shop.example.test"]},
]
TOKEN = re.compile(r"^[a-z0-9_]{1,64}$")


@pytest.fixture(autouse=True)
def _fresh_run(monkeypatch):
    # RFC 5737 ranges stand in for public addresses: the injected-name guard
    # reads them as reserved and would drop an urlscan name before the gate.
    import ipaddress

    from recon.main_recon_modules import ip_filter
    documentation = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24")]
    routable = ip_filter.is_non_routable_ip
    monkeypatch.setattr(ip_filter, "is_non_routable_ip", lambda a: (
        False if any(ipaddress.ip_address(a) in n for n in documentation) else routable(a)))
    circuit_breaker.reset_registry()
    yield
    circuit_breaker.reset_registry()


def _dns(*ips):
    return {"ips": {"ipv4": list(ips), "ipv6": []}, "has_records": bool(ips)}


def _discovery() -> dict:
    return {
        "subdomains": [APP, LEGACY, MIXED, GHOST],
        "dns": {"domain": {}, "subdomains": {
            APP: _dns(APP_IP), LEGACY: _dns(LEGACY_IP), MIXED: _dns(MIXED_OK, MIXED_BAD),
            GHOST: _dns(),
        }},
        "subdomain_status_map": {APP: "resolved", LEGACY: "resolved", MIXED: "resolved",
                                 GHOST: "unresolved"},
    }


def _info(**kw) -> dict:
    base = {"include_root_domain": False, "full_subdomains": [], "root_domain": ROOT,
            "mode": "enumerate"}
    base.update(kw)
    return base


def _merge(settings: dict, **kw) -> dict:
    return merge_group_hosts(_discovery(), _info(**kw.pop("info", {})), ROOT, settings,
                             dns_enabled=kw.pop("dns_enabled", False), **kw)


def _roe_gaps() -> list:
    return [dict(g) for g in circuit_breaker.coverage_report().gaps if g["source"] == "roe_excluded"]


def test_a_discovered_name_on_an_excluded_address_only_is_refused():
    out = _merge(ROE)
    assert LEGACY not in out["subdomains"]
    assert LEGACY not in out["dns"]["subdomains"]
    assert LEGACY not in out["status_map"]


def test_a_discovered_name_with_one_excluded_address_is_refused_not_narrowed():
    out = _merge(ROE)
    assert MIXED not in out["subdomains"]
    assert MIXED not in out["dns"]["subdomains"]


def test_allowed_and_address_less_names_are_kept():
    out = _merge(ROE)
    assert APP in out["subdomains"] and out["dns"]["subdomains"][APP]["ips"]["ipv4"] == [APP_IP]
    assert GHOST in out["subdomains"] and GHOST in out["dns"]["subdomains"]


def test_each_refusal_is_noted_as_roe_excluded(capsys):
    _merge(ROE)
    gaps = _roe_gaps()
    assert gaps, "no roe_excluded coverage note"
    assert {g["module"] for g in gaps} == {"domain_recon"}
    assert all(TOKEN.match(g["module"]) and TOKEN.match(g["source"]) for g in gaps)
    lines = [line for line in capsys.readouterr().out.splitlines()
             if line.startswith("[-][RoE] domain_recon:")]
    for refused in (LEGACY, LEGACY_IP, MIXED, MIXED_BAD):
        assert any(refused in line for line in lines), refused
    assert not any(APP in line or MIXED_OK in line for line in lines)


def test_an_excluded_address_is_a_report_gap_only():
    _merge(ROE)
    report = circuit_breaker.coverage_report()
    assert not report.degraded_sources
    assert not report.skipped_hostnames()


def test_a_name_resolved_by_the_merge_itself_is_judged_too():
    # A host discovery listed without DNS is resolved by the merge; its answer
    # is judged the same way.
    def resolver(root, hosts, **_kw):
        return {"subdomains": {h: _dns(LEGACY_IP) for h in hosts}}

    discovery = {"subdomains": ["late.example.test"], "dns": {"domain": {}, "subdomains": {}}}
    out = merge_group_hosts(discovery, _info(), ROOT, ROE, dns_enabled=True, resolver=resolver)
    assert "late.example.test" not in out["subdomains"]
    assert "late.example.test" not in out["dns"]["subdomains"]


def test_an_urlscan_name_on_an_excluded_address_is_refused_under_its_source():
    def resolver(root, hosts, **_kw):
        return {"subdomains": {h: _dns(HIST_IP) for h in hosts}}

    out = merge_group_hosts(_discovery(), _info(), ROOT, ROE, dns_enabled=True, resolver=resolver,
                            extra_hosts=[(HIST, "urlscan")], wildcard_filter=lambda names: names)
    assert HIST not in out["subdomains"] and HIST not in out["dns"]["subdomains"]
    assert HIST not in out["injected"]
    assert "urlscan" in {g["module"] for g in _roe_gaps()}


def test_the_operators_listed_host_and_the_root_are_left_to_the_builders_gate():
    # As for the SSRF guard: what the operator named is not judged here.
    def resolver(root, hosts, **_kw):
        return {"subdomains": {h: _dns(LISTED_IP) for h in hosts},
                "domain": _dns(LEGACY_IP)}

    out = merge_group_hosts(_discovery(), _info(full_subdomains=[LISTED], include_root_domain=True),
                            ROOT, ROE, dns_enabled=True, resolver=resolver)
    assert LISTED in out["subdomains"] and LISTED in out["dns"]["subdomains"]
    assert ROOT in out["subdomains"]


@pytest.mark.parametrize("settings", NO_ADDRESS_RULE, ids=["no_keys", "empty", "off", "names_only"])
def test_without_an_address_rule_the_merge_is_unchanged(settings):
    baseline = _merge({})
    out = _merge(settings)
    assert out == baseline
    assert {APP, LEGACY, MIXED, GHOST} <= set(out["subdomains"])
    assert _roe_gaps() == []


# --------------------------------------------------------------------------
# The GROUP 1 write (the real domain-discovery writer)
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


def _write(out: dict):
    """The GROUP 1 fan-in as run_domain_recon builds combined_result, then
    update_graph_from_domain_discovery."""
    from graph_db.mixins.recon.domain_mixin import DomainMixin

    combined = {"domain": ROOT, "whois": {},
                "metadata": {"root_domain": ROOT, "org_domain": ROOT, "scope_mode": "enumerate",
                             "include_root_domain": out["include_root"]},
                "subdomains": out["subdomains"], "subdomain_count": len(out["subdomains"]),
                "dns": copy.deepcopy(out["dns"]), "subdomain_status_map": out["status_map"]}
    session = _Session()
    writer = DomainMixin()
    writer.driver = MagicMock()
    writer.driver.session.return_value = session
    stats = writer.update_graph_from_domain_discovery(combined, "u1", "p1")
    return session, stats


def test_the_group_1_write_holds_no_refused_name_and_no_excluded_address():
    session, stats = _write(_merge(ROE))
    assert stats["errors"] == []
    minted = {p["name"] for c, p in session.calls if "MERGE (s:Subdomain" in c}
    assert APP in minted and LEGACY not in minted and MIXED not in minted
    resolves = {p["ip"] for c, p in session.calls if "RESOLVES_TO" in c}
    assert not resolves & {LEGACY_IP, MIXED_BAD}


def test_without_an_exclusion_the_group_1_write_is_unchanged():
    session, _stats = _write(_merge({}))
    minted = {p["name"] for c, p in session.calls if "MERGE (s:Subdomain" in c}
    assert {APP, LEGACY, MIXED} <= minted
