"""GROUP 1 of run_ip_recon: labels for every target, PTR answers as evidence (P0b, P3).

Every listed address keeps its dashed label entry (R-4), whatever its PTR says:
the label carries the address to naabu, httpx's DNS fallback, GVM and the
graph. A PTR answer is a hostname candidate, never a scope entry: in the
record modes every answer of every target is kept in ``ip_hostnames.ptr`` for
the hostnames hook, and GROUP 1 resolves no name (a forward answer can point
outside the targets, B-01; a name two targets share is one candidate, B-27).
IP only asks no PTR at all (I-7). A listed IPv6 address is written in its
canonical spelling, so every tool's report of it meets the same IP node.

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


def _run(rm, monkeypatch, ptr=None, forward=None, targets=(T1, T2), mode="record_only", **settings):
    """run_ip_recon's GROUP 1; returns (recon, forward lookups made, graph writes)."""
    from recon.main_recon_modules import domain_recon
    ptr, forward = dict(ptr or {}), dict(forward or {})
    looked_up, writes = [], []

    def reverse_all(ip, *_a, **_k):
        answer = ptr.get(ip)
        return [answer] if isinstance(answer, str) else list(answer or [])

    def lookup(name, *_a, **_k):
        looked_up.append(name)
        answer = forward.get(name, [])
        v4 = [a for a in answer if ":" not in a]
        v6 = [a for a in answer if ":" in a]
        return {"records": {"A": v4 or None, "AAAA": v6 or None},
                "ips": {"ipv4": v4, "ipv6": v6}, "has_records": bool(answer)}

    monkeypatch.setattr(domain_recon, "reverse_dns_lookup_all", reverse_all)
    monkeypatch.setattr(domain_recon, "dns_lookup", lookup)
    monkeypatch.setattr(rm, "_graph_update_bg", lambda name, data, *_a, **_k: writes.append(name))
    recon = rm.run_ip_recon(list(targets), dict(PHASES_OFF, IP_HOSTNAME_MODE=mode, **settings))
    return recon, looked_up, writes


def _labels(recon):
    return {k for k, v in recon["dns"]["subdomains"].items() if v.get("is_mock")}


def _labels_only(recon, targets=(T1, T2)):
    labels = [ip.replace(".", "-").replace(":", "-") for ip in targets]
    assert set(recon["dns"]["subdomains"]) == set(labels)
    assert recon["subdomains"] == labels
    assert recon["metadata"]["subdomain_filter"] == [*targets, *labels]
    assert recon["metadata"]["ip_to_hostname"] == dict(zip(targets, labels))


def test_a_ptr_name_is_a_candidate_never_a_scope_entry(rm, monkeypatch, capsys):
    recon, looked_up, writes = _run(rm, monkeypatch, ptr={T1: ["www.example.com", "app.example.com"]},
                                    forward={"www.example.com": [T1, T2]})
    _labels_only(recon)
    assert recon["dns"]["subdomains"]["203-0-113-1"]["actual_ip"] == T1
    assert recon["ip_hostnames"]["mode"] == "record_only"
    assert recon["ip_hostnames"]["ptr"] == {T1: ["www.example.com", "app.example.com"]}
    # The forward answer belongs to the name selection, never to GROUP 1.
    assert looked_up == []
    assert "update_graph_from_ip_recon" in writes
    out = capsys.readouterr().out
    assert f"[+][DNS] {T1} -> www.example.com, app.example.com" in out
    assert f"[-][DNS] {T2} -> no PTR (using 203-0-113-2)" in out
    assert "IP STEP 2" not in out


@pytest.mark.parametrize("answer", [[FOREIGN], [T1, FOREIGN], [], ["127.0.0.1"], [T1]])
def test_no_forward_answer_puts_a_ptr_name_in_scope(rm, monkeypatch, answer):
    recon, looked_up, _ = _run(rm, monkeypatch, ptr={T1: "www.example.com"},
                               forward={"www.example.com": answer})
    _labels_only(recon)
    assert looked_up == []


def test_a_name_two_targets_share_is_kept_for_both(rm, monkeypatch):
    recon, looked_up, _ = _run(rm, monkeypatch, ptr={T1: "shared.example.com", T2: "shared.example.com"})
    assert looked_up == []
    assert recon["ip_hostnames"]["ptr"] == {T1: ["shared.example.com"], T2: ["shared.example.com"]}
    _labels_only(recon)


def test_an_ipv6_target_keeps_its_label(rm, monkeypatch):
    recon, _, _ = _run(rm, monkeypatch, targets=(V6,), ptr={V6: "v6.example.com"})
    assert recon["dns"]["subdomains"]["2001-db8--1"]["ips"] == {"ipv4": [], "ipv6": [V6]}
    assert recon["ip_hostnames"]["ptr"] == {V6: ["v6.example.com"]}


def test_a_listed_ipv6_spelling_is_made_canonical(rm, monkeypatch):
    recon, _, _ = _run(rm, monkeypatch, targets=("2001:DB8:0::1",), ptr={V6: "v6.example.com"})
    assert recon["metadata"]["expanded_ips"] == [V6]
    assert recon["metadata"]["target_ips"] == ["2001:DB8:0::1"]
    assert recon["dns"]["subdomains"]["2001-db8--1"]["actual_ip"] == V6
    assert recon["ip_hostnames"]["ptr"] == {V6: ["v6.example.com"]}


def test_a_numeric_ptr_answer_is_no_name(rm, monkeypatch, capsys):
    recon, looked_up, _ = _run(rm, monkeypatch, ptr={T1: "203.0.113.1"})
    assert looked_up == []
    assert recon["ip_hostnames"]["ptr"] == {}
    _labels_only(recon)
    assert f"[-][DNS] {T1} -> no PTR (using 203-0-113-1)" in capsys.readouterr().out


def test_ip_only_asks_no_ptr_and_says_so_at_the_end(rm, monkeypatch, capsys):
    recon, _, _ = _run(rm, monkeypatch, ptr={T1: "www.example.com"}, mode="ip_only")
    _labels_only(recon)
    assert recon["ip_hostnames"]["mode"] == "ip_only"
    out = capsys.readouterr().out
    assert "IP STEP 1: Reverse DNS Lookup — SKIPPED (IP only: no hostname is looked up)" in out
    assert "[-][Pipeline] Hostnames on target IPs: not looked up (IP only)" in out


def test_the_end_summary_counts_the_recorded_names(rm, monkeypatch, capsys):
    _run(rm, monkeypatch, ptr={T1: ["www.example.com", "app.example.com"], T2: "www.example.com"})
    out = capsys.readouterr().out
    assert "[+][Pipeline] IPs scanned: 2" in out
    assert "[+][Pipeline] Hostnames on target IPs (record_only): 2 found, 0 scanned, 2 recorded" in out


def test_dns_off_makes_labels_only_and_asks_nothing(rm, monkeypatch, capsys):
    recon, looked_up, _ = _run(rm, monkeypatch, ptr={T1: "www.example.com"},
                               forward={"www.example.com": [T1]}, DNS_ENABLED=False)
    assert looked_up == []
    _labels_only(recon)
    assert recon["ip_hostnames"]["ptr"] == {}
    out = capsys.readouterr().out
    assert "IP STEP 1: Reverse DNS Lookup — SKIPPED (disabled)" in out
