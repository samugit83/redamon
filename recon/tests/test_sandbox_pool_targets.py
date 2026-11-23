"""G-05: the Kali sandbox pool is never a recon target, whoever typed it.

Recon and its tools run on the host network, which reaches every per-user
sandbox bridge (10.214.0.0/16, a /28 each). Before this fix no gate refused
that range: a member could type an address there, a CIDR over it, or a name
that resolves into it, and scan another person's sandbox. The pool is now
refused by the never-scannable rule, ahead of the operator's own hosts in the
address guard and the group merge, on IP mode's expanded targets, and by the
target-admission gate in every mode. ``socket.getaddrinfo`` is patched where a
name is resolved: no DNS is used. Documentation ranges and reserved names only.
"""
from __future__ import annotations

import importlib.util
import inspect
import ipaddress
import socket
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import recon.main as recon_main  # noqa: E402
from recon.helpers import circuit_breaker  # noqa: E402
from recon.helpers.target_admission import (  # noqa: E402
    REASON_SANDBOX_POOL,
    admit_host_targets,
    admit_ip_map,
    admit_targets,
    admit_urls,
)
from recon.main import _drop_sandbox_pool_targets, merge_group_hosts  # noqa: E402
from recon.main_recon_modules import ip_filter  # noqa: E402
from recon_settings import ip_hostnames as ih  # noqa: E402

IN_POOL = ["10.214.0.0", "10.214.0.4", "10.214.13.37", "10.214.255.255", "::ffff:10.214.0.4"]
NEAR_POOL = ["10.213.255.255", "10.215.0.0", "10.0.0.5", "192.0.2.6"]


@pytest.fixture(autouse=True)
def _fresh_run():
    circuit_breaker.reset_registry()
    yield
    circuit_breaker.reset_registry()


def _resolver(table):
    def getaddrinfo(host, *args, **kwargs):
        if host not in table:
            raise socket.gaierror("unresolvable")
        return [(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))
                for ip in table[host]]
    return getaddrinfo


@pytest.fixture
def dns(monkeypatch):
    table = {}
    monkeypatch.setattr(socket, "getaddrinfo", _resolver(table))
    return table


def _contract(rel):
    # Standard library only, so it loads by path; registered first because its
    # dataclasses look their module up in sys.modules.
    name = f"_contract_{rel.replace('/', '_').removesuffix('.py')}"
    spec = importlib.util.spec_from_file_location(name, PROJECT_ROOT / rel)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# --------------------------------------------------------------------------
# One pool everywhere
# --------------------------------------------------------------------------

def test_the_pool_constants_match_the_sandbox_contract():
    for rel in ("recon_orchestrator/sandbox_contract.py", "agentic/sandbox_contract.py"):
        pool = ipaddress.ip_network(_contract(rel).SUBNET_POOL)
        assert ip_filter.SANDBOX_POOL_NETWORK == pool, rel
        assert ih.SANDBOX_POOL == pool, rel


@pytest.mark.parametrize("address", IN_POOL)
def test_a_pool_address_is_never_scannable_in_both_copies(address):
    assert ip_filter.is_never_scannable_ip(address) is True
    assert ih.is_never_scannable_ip(address) is True
    assert ip_filter.in_sandbox_pool(address) is True
    assert ih.in_sandbox_pool(address) is True


@pytest.mark.parametrize("address", NEAR_POOL + ["not-an-address", "", "2001:db8::1"])
def test_addresses_next_to_the_pool_are_not_in_it(address):
    assert ip_filter.in_sandbox_pool(address) is False
    assert ih.in_sandbox_pool(address) is False


@pytest.mark.parametrize("address", NEAR_POOL)
def test_private_neighbours_stay_scannable(address):
    assert ip_filter.is_never_scannable_ip(address) is False
    assert ih.is_never_scannable_ip(address) is False


def test_the_ip_mode_selection_rule_refuses_a_name_resolving_into_the_pool():
    targets = ih.TargetSet.from_entries(["10.214.0.0/24", "192.0.2.0/24"])
    assert ih.address_verdict(["10.214.0.4"], targets) == "never_scannable_address"
    assert ih.address_verdict(["192.0.2.6"], targets) is None


# --------------------------------------------------------------------------
# The per-request address guard: the pool comes before the operator's hosts
# --------------------------------------------------------------------------

def test_a_typed_pool_address_is_refused_although_the_operator_listed_it(dns):
    assert ip_filter.is_address_safe_to_scan("10.214.0.4", operator_hosts={"10.214.0.4"}) is False


def test_an_operator_network_over_the_pool_does_not_admit_its_addresses(dns):
    nets = (ipaddress.ip_network("10.0.0.0/8"),)
    assert ip_filter.is_address_safe_to_scan("10.214.0.4", operator_networks=nets) is False
    assert ip_filter.is_address_safe_to_scan("10.1.2.3", operator_networks=nets) is True


def test_a_typed_name_resolving_into_the_pool_is_refused(dns):
    dns["sandbox.example.com"] = ["10.214.0.4"]
    dns["intranet.example.com"] = ["10.0.0.5"]
    assert ip_filter.is_address_safe_to_scan("sandbox.example.com",
                                             operator_hosts={"sandbox.example.com"}) is False
    assert ip_filter.is_address_safe_to_scan("intranet.example.com",
                                             operator_hosts={"intranet.example.com"}) is True


def test_a_typed_name_that_does_not_resolve_keeps_the_operator_s_choice(dns):
    assert ip_filter.is_address_safe_to_scan("gone.example.com", operator_hosts={"gone.example.com"}) is True


def test_a_discovered_name_resolving_into_the_pool_is_refused(dns):
    dns["x.example.com"] = ["198.51.100.7", "10.214.0.4"]
    assert ip_filter.is_address_safe_to_scan("x.example.com") is False


# --------------------------------------------------------------------------
# The group merge: typed and root names too
# --------------------------------------------------------------------------

def _dns(ip):
    return {"ips": {"ipv4": [ip], "ipv6": []}, "has_records": True}


def test_a_listed_host_resolving_into_the_pool_is_dropped(capsys):
    def resolver(root, hosts, **_kw):
        return {"subdomains": {h: _dns("10.214.0.4" if h.startswith("sbx") else "198.51.100.30")
                               for h in hosts}}
    info = {"include_root_domain": False, "root_domain": "example.test",
            "full_subdomains": ["sbx.example.test", "app.example.test"]}
    out = merge_group_hosts({"subdomains": [], "dns": {}}, info, "example.test", {},
                            dns_enabled=True, resolver=resolver)
    assert "sbx.example.test" not in out["subdomains"]
    assert "sbx.example.test" not in out["dns"]["subdomains"]
    assert "app.example.test" in out["subdomains"]
    assert "Kali sandbox address pool" in capsys.readouterr().out


def test_a_root_resolving_into_the_pool_is_left_out_like_include_root_off():
    discovery = {"subdomains": ["app.example.test"],
                 "dns": {"domain": _dns("10.214.0.9"),
                         "subdomains": {"app.example.test": _dns("198.51.100.10")}}}
    info = {"include_root_domain": True, "root_domain": "example.test", "full_subdomains": []}
    out = merge_group_hosts(discovery, info, "example.test", {}, dns_enabled=False)
    assert "example.test" not in out["subdomains"]
    assert out["dns"]["domain"] == {}
    assert out["include_root"] is False
    assert "app.example.test" in out["subdomains"]


def test_a_discovered_host_resolving_into_the_pool_is_dropped():
    discovery = {"subdomains": ["sbx.example.test", "app.example.test"],
                 "dns": {"domain": {}, "subdomains": {"sbx.example.test": _dns("10.214.0.4"),
                                                      "app.example.test": _dns("198.51.100.10")}}}
    info = {"include_root_domain": False, "root_domain": "example.test", "full_subdomains": []}
    out = merge_group_hosts(discovery, info, "example.test", {}, dns_enabled=False)
    assert out["subdomains"] == ["app.example.test"]


# --------------------------------------------------------------------------
# IP mode's expansion
# --------------------------------------------------------------------------

def test_the_expanded_targets_lose_the_pool_and_keep_their_order(capsys):
    ips = ["192.0.2.6", "10.214.0.4", "10.0.0.5", "10.214.255.254"]
    assert _drop_sandbox_pool_targets(ips) == ["192.0.2.6", "10.0.0.5"]
    assert "Dropped 2 target IP(s)" in capsys.readouterr().out


def test_ip_recon_drops_the_pool_right_after_the_roe_filter():
    source = inspect.getsource(recon_main.run_ip_recon)
    roe = source.index('expanded_ips = _filter_roe_excluded(expanded_ips, settings, label="IP")')
    pool = source.index("expanded_ips = _drop_sandbox_pool_targets(expanded_ips)")
    assert roe < pool < source.index("ip_to_hostname = {")


# --------------------------------------------------------------------------
# The target-admission gate: in every mode, never inert on the pool
# --------------------------------------------------------------------------

def _refused(adm):
    return [[r.target, r.reason] for r in adm.refusals]


def test_an_inert_gate_still_refuses_a_pool_address(capsys):
    adm = admit_targets({}, {}, names={"app.example.com": ["198.51.100.7"]},
                        ips=["192.0.2.6", "10.214.0.4"], module="naabu")
    assert adm.ips == ["192.0.2.6"]
    assert adm.names == {"app.example.com": ["198.51.100.7"]}
    assert _refused(adm) == [["10.214.0.4", REASON_SANDBOX_POOL]]
    assert "Kali sandbox address pool" in capsys.readouterr().out
    assert [dict(g) for g in circuit_breaker.coverage_report().gaps] == []


def test_a_name_resolving_into_the_pool_is_never_handed_to_a_resolving_tool():
    adm = admit_targets({}, {}, names={"sbx.example.com": ["198.51.100.7", "10.214.0.4"],
                                       "all.example.com": ["10.214.0.5"]},
                        module="httpx", resolves_names=True)
    assert "sbx.example.com" not in adm.names and "all.example.com" not in adm.names
    assert adm.split == {"sbx.example.com": ["198.51.100.7"]}
    assert ["sbx.example.com", REASON_SANDBOX_POOL] in _refused(adm)
    assert ["all.example.com", REASON_SANDBOX_POOL] in _refused(adm)


def test_an_ip_mode_target_in_the_pool_is_refused_although_it_is_listed():
    recon = {"metadata": {"ip_mode": True, "expanded_ips": ["10.214.0.4", "192.0.2.6"]}}
    adm = admit_targets({}, recon, ips=["10.214.0.4", "192.0.2.6"], module="naabu")
    assert adm.ips == ["192.0.2.6"]
    assert _refused(adm) == [["10.214.0.4", REASON_SANDBOX_POOL]]


def test_the_adapters_drop_the_pool_when_otherwise_inert():
    ips = ["192.0.2.6", "10.214.0.4"]
    ip_map = {"192.0.2.6": ["www.example.com"], "10.214.0.4": ["sbx.example.com"]}
    got_ips, got_map, _ = admit_ip_map({}, {}, ips, ip_map, module="masscan")
    assert got_ips == ["192.0.2.6"] and got_map == {"192.0.2.6": ["www.example.com"]}

    got = admit_host_targets({}, {}, set(ips), {"www.example.com", "sbx.example.com"}, ip_map,
                             module="dns_targets")
    assert got[0] == {"192.0.2.6"}
    assert got[1] == {"www.example.com"}
    assert got[2] == {"192.0.2.6": ["www.example.com"]}

    recon = {"domain": "example.com",
             "dns": {"domain": {}, "subdomains": {"sbx.example.com": _dns("10.214.0.4")}}}
    urls = ["http://10.214.0.4:4444/", "https://sbx.example.com/", "https://www.example.com/"]
    kept, _ = admit_urls({}, recon, urls, module="httpx")
    assert kept == ["https://www.example.com/"]


def test_without_a_pool_address_the_gate_stays_inert_and_hands_back_the_same_objects(capsys):
    ips = ["192.0.2.6", "10.0.0.5"]
    ip_map = {"192.0.2.6": ["www.example.com"]}
    urls = ["https://www.example.com/", "http://10.0.0.5/"]
    got_ips, got_map, _ = admit_ip_map({}, {}, ips, ip_map, module="masscan")
    got_urls, _ = admit_urls({}, {}, urls, module="httpx")
    assert got_ips is ips and got_map is ip_map and got_urls is urls
    assert capsys.readouterr().out == ""
