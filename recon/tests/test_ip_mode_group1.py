"""GROUP 1 of run_ip_recon: the PTR names an IP-mode run keeps (step P0b).

Every listed address keeps its dashed label entry (R-4), whatever its PTR says:
the label carries the address to naabu, httpx's DNS fallback, GVM and the
graph. A PTR name is added (and later scanned by name) only when its forward
answer is non-empty and every address in it is a target (I-1, B-01); a name
two addresses share is resolved and added once (B-27). Everything else is
logged with the selection rule's reason and left out of every scope list.

Real run_ip_recon code with every later phase off; only DNS is a fake.
Documentation ranges (RFC 5737 / RFC 3849) and reserved names only.
"""
import sys
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

PID = "cmipmodegroup100000000001"
T1, T2, FOREIGN, V6 = "203.0.113.1", "203.0.113.2", "198.51.100.7", "2001:db8::1"

PHASES_OFF = {
    "DNS_ENABLED": True, "DNS_MAX_RETRIES": 1, "WHOIS_ENABLED": False,
    "SHODAN_ENABLED": False, "NAABU_ENABLED": False, "MASSCAN_ENABLED": False,
    "NMAP_ENABLED": False, "TLSX_ENABLED": False, "OSINT_ENRICHMENT_ENABLED": False,
    "UNCOVER_ENABLED": False, "HTTPX_ENABLED": False, "SECURITY_CHECK_ENABLED": False,
    "AI_SURFACE_RECON_ENABLED": False, "JS_RECON_ENABLED": False,
    "SUPPLY_CHAIN_RECON_ENABLED": False, "MITRE_ENABLED": False,
    "GRAPHQL_SECURITY_ENABLED": False, "SUBDOMAIN_TAKEOVER_ENABLED": False,
    "VHOST_SNI_ENABLED": False, "WEB_CACHE_POISON_ENABLED": False,
    "ORIGIN_DISCOVERY_ENABLED": False, "ROE_ENABLED": False,
    "IP_ATTRIBUTION_ENABLED": False, "SERIALIZED_SCAN_ENABLED": False,
}


@pytest.fixture
def rm(tmp_path, monkeypatch):
    stub = {
        "TARGET_DOMAIN": "", "SUBDOMAIN_LIST": [], "IP_MODE": True, "TARGET_IPS": [T1, T2],
        "DOMAIN_BATCH_MODE": False, "DOMAIN_BATCH_GROUPS": [],
        "USE_BRUTEFORCE_FOR_SUBDOMAINS": False, "SCAN_MODULES": [],
        "UPDATE_GRAPH_DB": False, "USER_ID": "u1", "PROJECT_ID": PID,
        "VERIFY_DOMAIN_OWNERSHIP": False, "STEALTH_MODE": False,
        "OWNERSHIP_TOKEN": "", "OWNERSHIP_TXT_PREFIX": "",
    }
    with mock.patch("recon.project_settings.get_settings", return_value=dict(stub)):
        for name in [m for m in list(sys.modules) if m in ("recon.main", "main")]:
            del sys.modules[name]
        import recon.main as module
        monkeypatch.setattr(module, "OUTPUT_DIR", tmp_path)
        monkeypatch.setattr(module, "SCAN_MODULES", [])
        monkeypatch.setattr(module, "UPDATE_GRAPH_DB", False)
        yield module


def _run(rm, monkeypatch, ptr=None, forward=None, targets=(T1, T2), **settings):
    """run_ip_recon's GROUP 1; returns (recon, forward lookups made, graph writes)."""
    from recon.main_recon_modules import domain_recon
    ptr, forward = dict(ptr or {}), dict(forward or {})
    looked_up, writes = [], []

    def reverse(ip, *_a, **_k):
        return ptr.get(ip)

    def lookup(name, *_a, **_k):
        looked_up.append(name)
        answer = forward.get(name, [])
        v4 = [a for a in answer if ":" not in a]
        v6 = [a for a in answer if ":" in a]
        return {"records": {"A": v4 or None, "AAAA": v6 or None},
                "ips": {"ipv4": v4, "ipv6": v6}, "has_records": bool(answer)}

    monkeypatch.setattr(rm, "reverse_dns_lookup", reverse)
    monkeypatch.setattr(domain_recon, "reverse_dns_lookup", reverse)
    monkeypatch.setattr(domain_recon, "dns_lookup", lookup)
    monkeypatch.setattr(rm, "_graph_update_bg", lambda name, data, *_a, **_k: writes.append(name))
    recon = rm.run_ip_recon(list(targets), dict(PHASES_OFF, **settings))
    return recon, looked_up, writes


def _labels(recon):
    return {k for k, v in recon["dns"]["subdomains"].items() if v.get("is_mock")}


def test_a_ptr_name_whose_every_address_is_a_target_is_kept_beside_the_labels(rm, monkeypatch, capsys):
    recon, _, writes = _run(rm, monkeypatch, ptr={T1: "www.example.com"},
                            forward={"www.example.com": [T1, T2]})
    subs = recon["dns"]["subdomains"]
    assert _labels(recon) == {"203-0-113-1", "203-0-113-2"}
    assert subs["203-0-113-1"]["actual_ip"] == T1
    assert subs["www.example.com"]["ips"]["ipv4"] == [T1, T2]
    assert recon["subdomains"] == ["203-0-113-1", "203-0-113-2", "www.example.com"]
    meta = recon["metadata"]
    assert meta["subdomain_filter"] == [T1, T2, "203-0-113-1", "203-0-113-2", "www.example.com"]
    assert meta["ip_to_hostname"] == {T1: "203-0-113-1", T2: "203-0-113-2"}
    assert "update_graph_from_ip_recon" in writes
    out = capsys.readouterr().out
    assert f"[+][DNS] www.example.com: every address is a target ({T1}, {T2})" in out
    assert "[+][Pipeline] PTR names scanned (every address a target): 1" in out
    assert "PTR names not scanned" not in out


@pytest.mark.parametrize("answer, reason", [
    ([FOREIGN], "resolves_outside_targets"),
    ([T1, FOREIGN], "resolves_outside_targets"),
    ([], "no_current_resolution"),
    (["127.0.0.1"], "never_scannable_address"),
])
def test_a_ptr_name_not_wholly_on_the_targets_is_left_out(rm, monkeypatch, capsys, answer, reason):
    recon, _, _ = _run(rm, monkeypatch, ptr={T1: "www.example.com"},
                       forward={"www.example.com": answer})
    assert "www.example.com" not in recon["dns"]["subdomains"]
    assert "www.example.com" not in recon["subdomains"]
    assert "www.example.com" not in recon["metadata"]["subdomain_filter"]
    assert _labels(recon) == {"203-0-113-1", "203-0-113-2"}
    out = capsys.readouterr().out
    assert f"[-][DNS] www.example.com (PTR of {T1}) not scanned: {reason}" in out
    assert "[-][Pipeline] PTR names not scanned (an address outside the targets, or none): 1" in out


def test_a_name_two_targets_share_is_resolved_and_added_once(rm, monkeypatch):
    recon, looked_up, _ = _run(rm, monkeypatch, ptr={T1: "shared.example.com", T2: "shared.example.com"},
                               forward={"shared.example.com": [T1, T2]})
    assert looked_up == ["shared.example.com"]
    assert recon["subdomains"].count("shared.example.com") == 1
    assert recon["metadata"]["subdomain_filter"].count("shared.example.com") == 1


def test_an_ipv6_target_keeps_its_label(rm, monkeypatch):
    recon, _, _ = _run(rm, monkeypatch, targets=(V6,), ptr={V6: "v6.example.com"},
                       forward={"v6.example.com": ["2001:DB8:0::1"]})
    assert recon["dns"]["subdomains"]["2001-db8--1"]["ips"] == {"ipv4": [], "ipv6": [V6]}
    # A different spelling of the same address is still the target.
    assert "v6.example.com" in recon["subdomains"]


def test_a_numeric_ptr_answer_is_no_name(rm, monkeypatch, capsys):
    recon, looked_up, _ = _run(rm, monkeypatch, ptr={T1: "203.0.113.1"})
    assert looked_up == []
    assert recon["subdomains"] == ["203-0-113-1", "203-0-113-2"]
    assert f"[-][DNS] {T1} -> no PTR (using 203-0-113-1)" in capsys.readouterr().out


def test_dns_off_makes_labels_only_and_asks_nothing(rm, monkeypatch, capsys):
    recon, looked_up, _ = _run(rm, monkeypatch, ptr={T1: "www.example.com"},
                               forward={"www.example.com": [T1]}, DNS_ENABLED=False)
    assert looked_up == []
    assert recon["subdomains"] == ["203-0-113-1", "203-0-113-2"]
    assert recon["metadata"]["subdomain_filter"] == [T1, T2, "203-0-113-1", "203-0-113-2"]
    out = capsys.readouterr().out
    assert "IP STEP 1: Reverse DNS Lookup — SKIPPED (disabled)" in out
    assert "IP STEP 2: DNS Resolution — SKIPPED (disabled)" in out
    assert "[+][Pipeline] PTR names scanned (every address a target): 0" in out
