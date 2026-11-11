"""What each hostname mode lets a module look up or send (P3, invariant I-7).

M2 (ip_only) sends nothing name-related: no PTR query, no Shodan reverse DNS,
no InternetDB hostnames kept, no OTX passive-DNS call, no tlsx -rps, no PTR
hidden inside the IP WHOIS, and vhost/SNI tries only the operator's custom
FQDN lines (D-09). M3 looks the names up and records them; vhost/SNI may try a
recorded name on the target IP it was seen on, never on a shared CDN edge and
not at all when IP attribution did not run (B-31). Asserted with mocks that
count the calls. Documentation ranges and reserved names only.
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

T1, T2 = "203.0.113.10", "203.0.113.11"
MODES = ("ip_only", "record_only", "record_filter", "scan_all")
RECORDING = MODES[1:]


def _ip_recon(**parts):
    return {"domain": "ip-targets.cmgates", "metadata": {"ip_mode": True, "expanded_ips": [T1, T2],
                                                         "root_domain": "ip-targets.cmgates"},
            **parts}


# ---------------------------------------------------------------------------
# GROUP 1: the PTR lookup
# ---------------------------------------------------------------------------

PHASES_OFF = {
    "DNS_ENABLED": True, "DNS_MAX_RETRIES": 1, "WHOIS_ENABLED": False,
    "SHODAN_ENABLED": False, "NAABU_ENABLED": False, "MASSCAN_ENABLED": False,
    "NMAP_ENABLED": False, "TLSX_ENABLED": False, "OSINT_ENRICHMENT_ENABLED": False,
    "UNCOVER_ENABLED": False, "HTTPX_ENABLED": False, "IP_ATTRIBUTION_ENABLED": False,
    "AI_SURFACE_RECON_ENABLED": False, "JS_RECON_ENABLED": False, "SERIALIZED_SCAN_ENABLED": False,
    "SUPPLY_CHAIN_RECON_ENABLED": False, "VHOST_SNI_ENABLED": False, "ROE_ENABLED": False,
}


@pytest.fixture
def rm(tmp_path, monkeypatch):
    stub = {
        "TARGET_DOMAIN": "", "SUBDOMAIN_LIST": [], "IP_MODE": True, "TARGET_IPS": [T1, T2],
        "DOMAIN_BATCH_MODE": False, "DOMAIN_BATCH_GROUPS": [],
        "USE_BRUTEFORCE_FOR_SUBDOMAINS": False, "SCAN_MODULES": [],
        "UPDATE_GRAPH_DB": False, "USER_ID": "u1", "PROJECT_ID": "cmgates",
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


def _group1(rm, monkeypatch, mode, **settings):
    from recon.main_recon_modules import domain_recon
    asked, forward = [], []
    monkeypatch.setattr(domain_recon, "reverse_dns_lookup_all",
                        lambda ip, *_a, **_k: asked.append(ip) or ["www.example.com"])
    monkeypatch.setattr(domain_recon, "reverse_dns_lookup",
                        lambda ip, *_a, **_k: asked.append(ip) or "www.example.com")
    monkeypatch.setattr(domain_recon, "dns_lookup", lambda name, *_a, **_k: forward.append(name) or {})
    recon = rm.run_ip_recon([T1, T2], dict(PHASES_OFF, IP_HOSTNAME_MODE=mode, **settings))
    return recon, asked, forward


def test_ip_only_asks_no_ptr(rm, monkeypatch, capsys):
    recon, asked, forward = _group1(rm, monkeypatch, "ip_only")
    assert asked == [] and forward == []
    assert "IP STEP 1: Reverse DNS Lookup — SKIPPED (IP only: no hostname is looked up)" \
        in capsys.readouterr().out
    assert recon["ip_hostnames"]["mode"] == "ip_only"
    assert "reverse_dns" not in recon["metadata"]["modules_executed"]


@pytest.mark.parametrize("mode", RECORDING)
def test_the_record_modes_ask_every_target_once_and_resolve_no_name(rm, monkeypatch, mode):
    recon, asked, forward = _group1(rm, monkeypatch, mode)
    assert sorted(asked) == [T1, T2]
    # The forward lookup of a PTR name belongs to the selection, never to GROUP 1.
    assert forward == []
    assert recon["ip_hostnames"]["ptr"] == {T1: ["www.example.com"], T2: ["www.example.com"]}
    assert "www.example.com" not in recon["subdomains"]
    assert "reverse_dns" in recon["metadata"]["modules_executed"]


def test_dns_off_asks_no_ptr_in_any_mode(rm, monkeypatch):
    _, asked, _ = _group1(rm, monkeypatch, "record_only", DNS_ENABLED=False)
    assert asked == []


# ---------------------------------------------------------------------------
# Shodan: reverse DNS and InternetDB hostnames
# ---------------------------------------------------------------------------

def _shodan(monkeypatch, mode, ip_mode=True, **settings):
    from recon.main_recon_modules import shodan_enrich as se
    rdns = []
    monkeypatch.setattr(se, "filter_ips_for_enrichment", lambda ips, *_a: list(ips))
    monkeypatch.setattr(se, "_run_host_lookup", lambda ips, *_a, **_k: [
        {"ip": T1, "ports": [443], "hostnames": ["idb.example.com"], "source": "internetdb"}])
    monkeypatch.setattr(se, "_run_reverse_dns",
                        lambda ips, *_a, **_k: rdns.append(list(ips)) or {T1: ["rdns.example.com"]})
    recon = _ip_recon() if ip_mode else {"domain": "example.com", "metadata": {},
                                         "dns": {"domain": {"ips": {"ipv4": [T1]}}, "subdomains": {}}}
    se.run_shodan_enrichment(recon, {"SHODAN_HOST_LOOKUP": True, "SHODAN_REVERSE_DNS": True,
                                     "IP_MODE": ip_mode, "IP_HOSTNAME_MODE": mode, **settings})
    return recon["shodan"], rdns


def test_shodan_ip_only_asks_no_reverse_dns_and_keeps_no_hostname(monkeypatch):
    data, rdns = _shodan(monkeypatch, "ip_only")
    assert rdns == []
    assert data["reverse_dns"] == {}
    assert data["hosts"][0]["hostnames"] == []
    assert data["hosts"][0]["ports"] == [443]


@pytest.mark.parametrize("mode", RECORDING)
def test_shodan_record_modes_keep_both(monkeypatch, mode):
    data, rdns = _shodan(monkeypatch, mode)
    assert rdns == [[T1, T2]]
    assert data["reverse_dns"] == {T1: ["rdns.example.com"]}
    assert data["hosts"][0]["hostnames"] == ["idb.example.com"]


def test_shodan_domain_mode_is_unchanged(monkeypatch):
    # A domain project carries the default mode, ip_only: it must not matter there.
    data, rdns = _shodan(monkeypatch, "ip_only", ip_mode=False)
    assert rdns == [[T1]]
    assert data["hosts"][0]["hostnames"] == ["idb.example.com"]


# ---------------------------------------------------------------------------
# OTX: the per-IP passive DNS call
# ---------------------------------------------------------------------------

def _otx(monkeypatch, mode, ip_mode=True):
    from recon.main_recon_modules import otx_enrich as oe
    paths = []

    def call(_breaker, path, _keys, **_k):
        paths.append(path)
        data = {"passive_dns": [{"hostname": "p.example.com"}]} if path.endswith("/passive_dns") else {}
        return SimpleNamespace(ok=True, answered=True, data=data, outcome=None, detail="")

    monkeypatch.setattr(oe, "filter_ips_for_enrichment", lambda ips, *_a: list(ips))
    monkeypatch.setattr(oe, "_otx_call", call)
    monkeypatch.setattr(oe._RateLimiter, "wait", lambda self: None)
    recon = _ip_recon() if ip_mode else {"domain": "", "metadata": {},
                                         "dns": {"domain": {"ips": {"ipv4": [T1]}}, "subdomains": {}}}
    oe.run_otx_enrichment(recon, {"OTX_ENABLED": True, "OTX_WORKERS": 1, "IP_MODE": ip_mode,
                                  "IP_HOSTNAME_MODE": mode})
    return recon["otx"], paths


def test_otx_ip_only_never_asks_passive_dns(monkeypatch):
    data, paths = _otx(monkeypatch, "ip_only")
    assert {p for p in paths if p.endswith("/general")} == {f"/IPv4/{T1}/general", f"/IPv4/{T2}/general"}
    assert [p for p in paths if "passive_dns" in p] == []
    assert all(r["passive_dns"] == [] and r["passive_dns_hostnames"] == [] for r in data["ip_reports"])


@pytest.mark.parametrize("mode", RECORDING)
def test_otx_record_modes_ask_passive_dns(monkeypatch, mode):
    data, paths = _otx(monkeypatch, mode)
    assert sorted(p for p in paths if "passive_dns" in p) == [f"/IPv4/{T1}/passive_dns",
                                                             f"/IPv4/{T2}/passive_dns"]
    assert {r["passive_dns_hostnames"][0] for r in data["ip_reports"]} == {"p.example.com"}


def test_otx_domain_mode_still_asks_passive_dns(monkeypatch):
    _, paths = _otx(monkeypatch, "ip_only", ip_mode=False)
    assert f"/IPv4/{T1}/passive_dns" in paths


# ---------------------------------------------------------------------------
# tlsx: -rps (the PTR answer as SNI) is off in every IP mode
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("mode", MODES)
def test_tlsx_never_sends_the_ptr_as_sni_in_ip_mode(mode):
    from recon.main_recon_modules.tls_scan import build_tlsx_command
    from recon.project_settings import apply_ip_hostname_overrides
    settings = apply_ip_hostname_overrides({"IP_MODE": True, "IP_HOSTNAME_MODE": mode,
                                            "TLSX_REV_PTR_SNI": True})
    assert "-rps" not in build_tlsx_command("/t/targets.txt", "/t", settings)


def test_tlsx_domain_mode_keeps_the_setting():
    from recon.main_recon_modules.tls_scan import build_tlsx_command
    from recon.project_settings import apply_ip_hostname_overrides
    settings = apply_ip_hostname_overrides({"IP_MODE": False, "TLSX_REV_PTR_SNI": True})
    assert "-rps" in build_tlsx_command("/t/targets.txt", "/t", settings)


# ---------------------------------------------------------------------------
# WHOIS: python-whois resolves an IP's PTR before asking; the IP query must not
# ---------------------------------------------------------------------------

def test_ip_whois_asks_the_registry_with_the_address_and_no_ptr(monkeypatch):
    import socket
    from whois.whois import NICClient
    from recon.main_recon_modules import whois_recon as wr

    asked = []
    monkeypatch.setattr(socket, "gethostbyaddr",
                        lambda *a: pytest.fail("the IP WHOIS made a PTR query"))
    monkeypatch.setattr(NICClient, "whois", lambda self, query, host, flags, **k: asked.append(
        (query, host, flags)) or "NetRange: 203.0.113.0 - 203.0.113.255\nOrgName: Example Org\n")
    monkeypatch.setattr(wr.whois, "whois", lambda *a, **k: pytest.fail("python-whois on an IP"))
    result, queried = wr.get_whois_data(T1, max_retries=1)
    assert queried == T1
    # Asked once, at ARIN, without the library's own recursion: a referral is
    # followed by whois_recon itself, and only to a regional registry.
    assert asked == [(T1, NICClient.ANICHOST, 0)]
    assert result == {"org": "Example Org"}


def test_ipv6_whois_also_asks_the_registry(monkeypatch):
    from whois.whois import NICClient
    from recon.main_recon_modules import whois_recon as wr
    asked = []
    monkeypatch.setattr(NICClient, "whois",
                        lambda self, query, host, flags, **k: asked.append(query) or "inet6num: 2001:db8::/32\n")
    wr.get_whois_data("2001:db8::10", max_retries=1)
    assert asked == ["2001:db8::10"]


def test_an_empty_registry_answer_is_no_data(monkeypatch):
    from whois.whois import NICClient
    from recon.main_recon_modules import whois_recon as wr
    monkeypatch.setattr(NICClient, "whois", lambda self, *a, **k: "")
    result, _ = wr.get_whois_data(T1, max_retries=1)
    assert result == {}


def test_a_dead_registry_is_a_transient_failure(monkeypatch):
    from whois.whois import NICClient
    from recon.main_recon_modules import whois_recon as wr

    def dead(self, *a, **k):
        raise ConnectionRefusedError("refused")

    monkeypatch.setattr(NICClient, "whois", dead)
    with pytest.raises(Exception, match="WHOIS lookup failed"):
        wr.get_whois_data(T1, max_retries=1)


def test_a_domain_whois_is_unchanged(monkeypatch):
    from recon.main_recon_modules import whois_recon as wr
    entry = mock.MagicMock(domain_name="example.com", registrar="r", creation_date=None)
    with mock.patch.object(wr.whois, "whois", return_value=entry) as call:
        result, _ = wr.get_whois_data("example.com", max_retries=1)
    assert result is entry
    assert call.call_args.args == ("example.com",)


# ---------------------------------------------------------------------------
# vhost/SNI: which names reach a target IP
# ---------------------------------------------------------------------------

def _vhost(monkeypatch, mode, ip_mode=True, **parts):
    from recon.main_recon_modules import vhost_sni_enum as vs
    tried = {}

    def probe(**kwargs):
        tried[kwargs["ip"]] = {"graph": sorted(kwargs["graph_candidates"]),
                               "custom": list(kwargs["custom_lines"]),
                               "default": list(kwargs["default_prefixes"])}
        return {"ports_tested": 0}

    monkeypatch.setattr(vs, "_is_curl_available", lambda: True)
    monkeypatch.setattr(vs, "_probe_single_ip", probe)
    monkeypatch.setattr(vs, "_load_default_wordlist", lambda: ["admin"])
    recon = _ip_recon(port_scan={"by_host": {T1: {"ip": T1, "ports": [443]},
                                             T2: {"ip": T2, "ports": [443]}}}, **parts)
    if not ip_mode:
        recon["metadata"] = {}
    vs.run_vhost_sni_enrichment(recon, {
        "VHOST_SNI_ENABLED": True, "IP_MODE": ip_mode, "IP_HOSTNAME_MODE": mode,
        "VHOST_SNI_USE_GRAPH_CANDIDATES": True, "VHOST_SNI_USE_DEFAULT_WORDLIST": True,
        "VHOST_SNI_CUSTOM_WORDLIST": "typed.example.com\nprefixonly"})
    return tried


RECORDED = {"candidates": {
    "seen1.example.com": {"ips_seen": [T1], "reason": "record_only"},
    "seen2.example.com": {"ips_seen": [T2], "reason": "record_only"},
    "both.example.com": {"ips_seen": [T1, T2], "reason": "record_only"},
    "gov.example.com": {"ips_seen": [T1], "reason": "hard_blocked"},
    "roe.example.com": {"ips_seen": [T1], "reason": "roe_excluded"},
}}
ATTRIBUTED = {"by_ip": {T1: {"ownership": "unknown"}, T2: {"ownership": "dedicated"}}}


def test_vhost_ip_only_tries_the_custom_fqdn_lines_only(monkeypatch):
    tried = _vhost(monkeypatch, "ip_only", ip_hostnames=RECORDED, ip_attribution=ATTRIBUTED,
                   http_probe={"by_url": {f"https://{T1}": {"ip": T1, "tls": {"certificate": {
                       "san": ["san.example.com"]}}}}})
    assert tried[T1] == {"graph": [], "custom": ["typed.example.com", "prefixonly"], "default": []}
    assert tried[T2]["graph"] == []


@pytest.mark.parametrize("mode", RECORDING)
def test_vhost_record_modes_try_a_recorded_name_on_the_ip_it_was_seen_on(monkeypatch, mode):
    tried = _vhost(monkeypatch, mode, ip_hostnames=RECORDED, ip_attribution=ATTRIBUTED)
    assert tried[T1]["graph"] == ["both.example.com", "seen1.example.com"]
    assert tried[T2]["graph"] == ["both.example.com", "seen2.example.com"]


def test_vhost_never_sends_a_recorded_name_to_a_shared_edge(monkeypatch, capsys):
    tried = _vhost(monkeypatch, "record_only", ip_hostnames=RECORDED, ip_attribution={"by_ip": {
        T1: {"ownership": "shared_edge"}, T2: {"ownership": "unknown"}}})
    assert tried[T1]["graph"] == []
    assert tried[T2]["graph"] == ["both.example.com", "seen2.example.com"]
    assert "[-][VhostSni] Recorded hostnames are not tried on 1 shared CDN edge IP(s)" \
        in capsys.readouterr().out


def test_vhost_tries_no_recorded_name_when_attribution_did_not_run(monkeypatch, capsys):
    tried = _vhost(monkeypatch, "record_only", ip_hostnames=RECORDED)
    assert tried[T1]["graph"] == [] and tried[T2]["graph"] == []
    assert "[-][VhostSni] IP attribution did not run: no recorded hostname is tried" \
        in capsys.readouterr().out


def test_vhost_tries_no_recorded_name_on_an_ip_whose_attribution_failed(monkeypatch):
    tried = _vhost(monkeypatch, "record_only", ip_hostnames=RECORDED, ip_attribution={"by_ip": {
        T1: {"ownership": "unknown", "ownership_reasons": ["attribution failed"]}}})
    assert tried[T1]["graph"] == [] and tried[T2]["graph"] == []


def test_vhost_without_the_hook_data_tries_no_name(monkeypatch):
    tried = _vhost(monkeypatch, "record_only", ip_attribution=ATTRIBUTED)
    assert tried[T1]["graph"] == []


def test_vhost_graph_candidates_switch_still_applies(monkeypatch):
    from recon.main_recon_modules import vhost_sni_enum as vs
    seen = {}

    def probe(**kwargs):
        seen[kwargs["ip"]] = kwargs["graph_candidates"]
        return {"ports_tested": 0}

    monkeypatch.setattr(vs, "_is_curl_available", lambda: True)
    monkeypatch.setattr(vs, "_probe_single_ip", probe)
    recon = _ip_recon(port_scan={"by_host": {T1: {"ip": T1, "ports": [443]}}},
                      ip_hostnames=RECORDED, ip_attribution=ATTRIBUTED)
    vs.run_vhost_sni_enrichment(recon, {"VHOST_SNI_ENABLED": True, "IP_MODE": True,
                                        "IP_HOSTNAME_MODE": "record_only",
                                        "VHOST_SNI_USE_GRAPH_CANDIDATES": False})
    assert seen[T1] == []
