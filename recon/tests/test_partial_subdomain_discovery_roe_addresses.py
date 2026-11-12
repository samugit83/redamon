"""Partial discovery never writes a discovered name on an RoE-excluded address (R-2, D2).

Partial SubdomainDiscovery applied the RoE by name only
(_drop_roe_excluded_discoveries): a discovered name resolving into an excluded
IP or CIDR was handed to update_graph_from_partial_discovery and written as a
Subdomain with RESOLVES_TO to the excluded address. Partial Naabu, httpx and
Nuclei read their targets back from the graph.

The full pipeline's merge_group_hosts (_roe_refused_discoveries) and the
late-name step refuse such a name through the admission gate, on the addresses
the run's DNS already resolved (no new query): any excluded address refuses the
name whole (never narrowed), dropped from the list, the DNS map and the status
map, and noted roe_excluded. A name with no address is kept (the builders'
gate judges it); the scan root and the operator's hosts are not judged here,
as for the SSRF guard. With no RoE IP or CIDR entry nothing changes.

The real module runs, and in one test the real graph writer; discovery, DNS
and Neo4j are the fakes. Only example.test names and RFC 5737 addresses.
"""
from __future__ import annotations

import copy
import re
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers import circuit_breaker  # noqa: E402
from recon.partial_recon_modules import helpers, subdomain_discovery  # noqa: E402

ROOT, ROOT_IP = "example.test", "198.51.100.5"
EXCLUDED_RANGE = "198.51.100.0/24"
APP, APP_IP = "app.example.test", "192.0.2.10"
LEGACY, LEGACY_IP = "legacy.example.test", "198.51.100.20"        # an excluded address only
MIXED, MIXED_OK, MIXED_BAD = "mixed.example.test", "192.0.2.11", "198.51.100.21"
GHOST = "ghost.example.test"                                       # no address
LISTED, LISTED_IP = "listed.example.test", "198.51.100.30"         # the group's listed host
SHOP, SHOP_IP = "shop.example.test", "192.0.2.13"                  # excluded by name

ROE = {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": [EXCLUDED_RANGE]}
NO_ADDRESS_RULE = [
    {},
    {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": []},
    {"ROE_ENABLED": False, "ROE_EXCLUDED_HOSTS": [EXCLUDED_RANGE]},
    {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": ["other.example.test"]},
]
TOKEN = re.compile(r"^[a-z0-9_]{1,64}$")
ADDRESSES = {APP: [APP_IP], LEGACY: [LEGACY_IP], MIXED: [MIXED_OK, MIXED_BAD], GHOST: [],
             LISTED: [LISTED_IP], SHOP: [SHOP_IP], ROOT: [ROOT_IP]}
DISCOVERED = [ROOT, APP, LEGACY, MIXED, GHOST, LISTED]


@pytest.fixture(autouse=True)
def _fresh_run(monkeypatch):
    monkeypatch.setattr(helpers.time, "sleep", lambda *_a, **_k: None)
    monkeypatch.setenv("USER_ID", "u1")
    monkeypatch.setenv("PROJECT_ID", "p1")
    circuit_breaker.reset_registry()
    yield
    circuit_breaker.reset_registry()


@pytest.fixture
def graph(monkeypatch):
    client = MagicMock()
    client.verify_connection.return_value = True
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)
    client.update_graph_from_partial_discovery.return_value = {}
    monkeypatch.setattr("graph_db.Neo4jClient", MagicMock(return_value=client))
    return client


def _entry(addresses):
    return {"ips": {"ipv4": [a for a in addresses if ":" not in a],
                    "ipv6": [a for a in addresses if ":" in a]},
            "has_records": bool(addresses)}


def _dns(names, addresses=None):
    addresses = addresses or ADDRESSES
    return {"domain": _entry(addresses[ROOT]),
            "subdomains": {n: _entry(addresses[n]) for n in names}}


def _discovery_result(names=DISCOVERED):
    names = list(names)
    return {"domain": ROOT, "subdomains": names, "subdomain_count": len(names),
            "dns": _dns(names), "external_domains": [],
            "subdomain_status_map": {n: "resolved" for n in names if ADDRESSES[n]}}


def _run(settings, user_inputs=(), result=None, redns=None):
    """The real run_subdomain_discovery on one root. ``redns``: the addresses
    the re-resolution (user inputs present) answers with."""
    cfg = {"_settings": dict(settings), "domains": [ROOT], "domain": ROOT, "batch_mode": False,
           "domain_groups": [{"rootDomain": ROOT, "prefixes": ["*"], "batch": False,
                              "exactHosts": [LISTED]}],
           "user_inputs": list(user_inputs)}
    with patch("recon.main_recon_modules.domain_recon.discover_subdomains",
               return_value=result if result is not None else _discovery_result()), \
         patch("recon.main_recon_modules.domain_recon.run_puredns_resolve",
               side_effect=lambda subs, domain, s: (list(subs), "filtered")), \
         patch("recon.main_recon_modules.domain_recon.resolve_all_dns",
               side_effect=lambda domain, subs, **kw: _dns(subs, redns)):
        return subdomain_discovery.run_subdomain_discovery(cfg)


def _written(graph):
    return graph.update_graph_from_partial_discovery.call_args.kwargs["recon_data"]


def _roe_gaps() -> list:
    return [dict(g) for g in circuit_breaker.coverage_report().gaps if g["source"] == "roe_excluded"]


def test_a_discovered_name_on_an_excluded_address_only_is_not_written(graph):
    _run(ROE)
    written = _written(graph)
    assert LEGACY not in written["subdomains"]
    assert LEGACY not in written["dns"]["subdomains"]
    assert LEGACY not in written["subdomain_status_map"]


def test_a_discovered_name_with_one_excluded_address_is_refused_not_narrowed(graph):
    _run(ROE)
    written = _written(graph)
    assert MIXED not in written["subdomains"]
    assert MIXED not in written["dns"]["subdomains"]
    assert MIXED not in written["subdomain_status_map"]


def test_allowed_and_address_less_names_are_kept(graph):
    _run(ROE)
    written = _written(graph)
    assert APP in written["subdomains"]
    assert written["dns"]["subdomains"][APP]["ips"]["ipv4"] == [APP_IP]
    assert GHOST in written["subdomains"] and GHOST in written["dns"]["subdomains"]
    assert written["subdomain_count"] == len(written["subdomains"])


def test_the_root_and_the_operators_hosts_are_left_to_the_builders_gate(graph):
    # As for the SSRF guard: what the operator named is not judged here. A
    # typed host was already checked on its addresses by _prepare_scope.
    typed, typed_ip = "typed.example.test", "198.51.100.31"
    addresses = dict(ADDRESSES, **{typed: [typed_ip]})
    _run(ROE, user_inputs=[typed], redns=addresses)
    written = _written(graph)
    for kept in (ROOT, LISTED, typed):
        assert kept in written["subdomains"], kept
    assert written["dns"]["subdomains"][LISTED]["ips"]["ipv4"] == [LISTED_IP]
    assert written["dns"]["subdomains"][typed]["ips"]["ipv4"] == [typed_ip]
    assert LEGACY not in written["subdomains"] and MIXED not in written["subdomains"]


def test_the_answer_that_is_written_is_the_one_judged(graph):
    # With typed inputs the run resolves every name again and writes that
    # answer: a name clean in discovery's DNS but excluded in the new one goes.
    late = "late.example.test"
    first = dict(ADDRESSES, **{late: ["192.0.2.12"]})
    again = dict(ADDRESSES, **{late: ["198.51.100.22"], "new.example.test": ["192.0.2.14"]})
    result = {"domain": ROOT, "subdomains": [APP, late], "subdomain_count": 2,
              "dns": _dns([APP, late], first), "external_domains": [],
              "subdomain_status_map": {APP: "resolved", late: "resolved"}}
    _run(ROE, user_inputs=["new.example.test"], result=result, redns=again)
    written = _written(graph)
    assert late not in written["subdomains"]
    assert late not in written["dns"]["subdomains"]
    assert late not in written["subdomain_status_map"]
    assert {APP, "new.example.test"} <= set(written["subdomains"])


def test_the_by_name_exclusion_keeps_working_beside_the_address_rule(graph, capsys):
    result = _discovery_result(DISCOVERED + [SHOP])
    _run({"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": [SHOP, EXCLUDED_RANGE]}, result=result)
    written = _written(graph)
    assert SHOP not in written["subdomains"] and SHOP not in written["dns"]["subdomains"]
    assert LEGACY not in written["subdomains"]
    assert "[RoE] Excluded 1 discovered subdomain(s) per Rules of Engagement" in capsys.readouterr().out


def test_each_refusal_is_noted_as_roe_excluded(graph, capsys):
    statuses = _run(ROE)
    gaps = _roe_gaps()
    assert gaps, "no roe_excluded coverage note"
    assert {g["module"] for g in gaps} == {"partial_recon"}
    assert all(TOKEN.match(g["module"]) and TOKEN.match(g["source"]) for g in gaps)
    lines = [line for line in capsys.readouterr().out.splitlines()
             if line.startswith("[-][RoE] partial_recon:")]
    for refused in (LEGACY, LEGACY_IP, MIXED, MIXED_BAD):
        assert any(refused in line for line in lines), refused
    assert not any(APP in line or MIXED_OK in line or LISTED in line for line in lines)
    # The root recorded a new coverage gap, so run_per_root reports it as the
    # partial graph builders' RoE refusals are reported.
    assert statuses[ROOT] == helpers.STATUS_DEGRADED


def test_an_excluded_address_is_a_report_gap_only(graph):
    _run(ROE)
    report = circuit_breaker.coverage_report()
    assert not report.degraded_sources
    assert not report.skipped_hostnames()


@pytest.mark.parametrize("settings", NO_ADDRESS_RULE, ids=["no_keys", "empty", "off", "names_only"])
def test_without_an_address_rule_the_written_result_is_unchanged(graph, settings):
    result = _discovery_result()
    expected = copy.deepcopy(result)
    statuses = _run(settings, result=result)
    written = _written(graph)
    assert written is result
    assert {k: written[k] for k in expected} == expected
    assert _roe_gaps() == []
    assert statuses[ROOT] == helpers.STATUS_OK


# --------------------------------------------------------------------------
# The real partial-discovery writer
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
        result.single.return_value = {"exists": False, "seeded": 1}
        result.__iter__ = lambda _s: iter([])
        return result


def test_the_graph_holds_no_refused_name_and_no_excluded_address(monkeypatch):
    from graph_db import Neo4jClient

    session = _Session()

    class _Client(Neo4jClient):
        def __init__(self, *_a, **_k):
            self.driver = MagicMock()
            self.driver.session.return_value = session

        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

        def verify_connection(self):
            return True

    monkeypatch.setattr("graph_db.Neo4jClient", _Client)
    _run(ROE)
    minted = {p["name"] for c, p in session.calls if "MERGE (s:Subdomain" in c}
    assert APP in minted and LEGACY not in minted and MIXED not in minted
    resolves = {p["ip"] for c, p in session.calls if "MERGE (s)-[r:RESOLVES_TO]" in c}
    assert APP_IP in resolves and MIXED_OK not in resolves
    assert not resolves & {LEGACY_IP, MIXED_BAD}
