"""Characterisation tests: the scope leaks of an IP-mode full pipeline run.

An IP-mode project's targets are addresses. Every test below states what the
pipeline MUST do (no packet to an address outside the target list, no dashed
placeholder used as a hostname, no cross-host redirect followed) and is marked
``xfail(strict=True)`` with the id of the bug that breaks it today, so the gate
stays green and the fix that lands must remove the marker (an XPASS fails the
run). The ids are those of the IP-mode plan's bug catalogue (B-01 ... B-31).

The fixture: two listed targets. 203.0.113.1 has a PTR name, www.example.com,
whose A record points at 198.51.100.7, an address in no target list (B-01 as
reproduced on master: naabu's target list was ['198.51.100.7', '203-0-113-2',
'203.0.113.2', 'www.example.com'] and never the listed 203.0.113.1).
203.0.113.2 has no PTR and gets the dashed placeholder 203-0-113-2.

Everything runs the real code (GROUP 1 of run_ip_recon, run_port_scan,
run_http_probe, run_vuln_scan, the real target builders); only DNS, the tool
subprocesses, HTTP and Neo4j are fakes. Two tests at the bottom are plain
asserts, not xfails: the domain-mode httpx and Nuclei commands, which the IP-mode
fix must leave byte-identical.

Only documentation addresses (RFC 5737, RFC 3849) and reserved names are used.
"""
from __future__ import annotations

import copy
import ipaddress
import json
import re
import sys
from collections import Counter
from pathlib import Path
from unittest import mock
from urllib.parse import urlparse

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

# cuid-shaped, so the synthetic root "ip-targets.<PID>" looks like a real one.
PID = "cmipmodeleak0000000000001"
LISTED = "203.0.113.1"
NO_PTR = "203.0.113.2"
TARGETS = [LISTED, NO_PTR]
FOREIGN = "198.51.100.7"
PTR_NAME = "www.example.com"
TARGET_V6 = "2001:db8::1"

# GROUP 1 alone: every later phase is switched off, so run_ip_recon returns
# the recon dict the pipeline hands to the port scanners.
GROUP1_ONLY = {
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

IP_MODE_SETTINGS = {"IP_MODE": True, "TARGET_IPS": list(TARGETS)}

# Documentation ranges are "private" to Python's ipaddress, so every
# is_non_routable_ip guard would refuse them before the code under test is
# reached. Here they stand in for public internet addresses.
_DOC_NETS = [ipaddress.ip_network(n) for n in
             ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]


class _Stop(Exception):
    """Raised by a wrapped command builder once the command is captured."""


class FakeDns:
    """PTR and forward answers for GROUP 1, and what naabu would resolve."""

    def __init__(self, ptr=None, forward=None):
        self.ptr = dict(ptr or {})
        self.forward = {k: list(v) for k, v in (forward or {}).items()}

    def addresses(self, host: str) -> list:
        try:
            return [str(ipaddress.ip_address(host))]
        except ValueError:
            return list(self.forward.get(host, []))

    def _split(self, name):
        answers = self.forward.get(name, [])
        return [a for a in answers if ":" not in a], [a for a in answers if ":" in a]

    def install(self, monkeypatch, rm):
        from recon.main_recon_modules import domain_recon

        def reverse(ip, *_a, **_k):
            return self.ptr.get(ip)

        def lookup(name, *_a, **_k):
            v4, v6 = self._split(name)
            return {"records": {"A": v4 or None, "AAAA": v6 or None},
                    "ips": {"ipv4": v4, "ipv6": v6}, "has_records": bool(v4 or v6)}

        def lookup_single(name, rtype, *_a, **_k):
            v4, v6 = self._split(name)
            return (v4 if rtype == "A" else v6 if rtype == "AAAA" else []) or None

        monkeypatch.setattr(rm, "reverse_dns_lookup", reverse)
        monkeypatch.setattr(domain_recon, "reverse_dns_lookup", reverse)
        monkeypatch.setattr(domain_recon, "dns_lookup", lookup)
        monkeypatch.setattr(domain_recon, "dns_lookup_single", lookup_single)


class _FakePopen:
    returncode = 0

    def __init__(self, cmd, *_a, **_k):
        self.cmd = cmd

    def communicate(self, timeout=None):
        return "", ""

    def kill(self):
        pass

    def wait(self, timeout=None):
        return 0

    def poll(self):
        return 0


@pytest.fixture
def recon_main(tmp_path, monkeypatch):
    stub = {
        "TARGET_DOMAIN": "", "SUBDOMAIN_LIST": [], "IP_MODE": True, "TARGET_IPS": list(TARGETS),
        "DOMAIN_BATCH_MODE": False, "DOMAIN_BATCH_GROUPS": [],
        "USE_BRUTEFORCE_FOR_SUBDOMAINS": False, "SCAN_MODULES": [],
        "UPDATE_GRAPH_DB": False, "USER_ID": "u1", "PROJECT_ID": PID,
        "VERIFY_DOMAIN_OWNERSHIP": False, "STEALTH_MODE": False,
        "OWNERSHIP_TOKEN": "", "OWNERSHIP_TXT_PREFIX": "",
    }
    with mock.patch("recon.project_settings.get_settings", return_value=dict(stub)):
        for mod in [m for m in list(sys.modules) if m in ("recon.main", "main")]:
            del sys.modules[mod]
        import recon.main as rm
        monkeypatch.setattr(rm, "OUTPUT_DIR", tmp_path)
        monkeypatch.setattr(rm, "SCAN_MODULES", [])
        monkeypatch.setattr(rm, "UPDATE_GRAPH_DB", False)
        yield rm


@pytest.fixture
def doc_ranges_public(monkeypatch):
    # Loaded first: a module imported after the patch would keep the real guard.
    import recon.main_recon_modules.ip_filter  # noqa: F401
    for name in ("recon.main_recon_modules.ip_filter", "main_recon_modules.ip_filter", "ip_filter"):
        module = sys.modules.get(name)
        if module is None:
            continue
        real = module.is_non_routable_ip

        def routable_doc(ip_str, _real=real):
            try:
                addr = ipaddress.ip_address(ip_str)
            except ValueError:
                return _real(ip_str)
            if any(addr in net for net in _DOC_NETS if net.version == addr.version):
                return False
            return _real(ip_str)

        monkeypatch.setattr(module, "is_non_routable_ip", routable_doc)


def _group1(rm, monkeypatch, dns, targets=TARGETS, **settings):
    """run_ip_recon's GROUP 1 through the real code; returns (recon, graph writes)."""
    dns.install(monkeypatch, rm)
    writes = []
    monkeypatch.setattr(rm, "_graph_update_bg",
                        lambda name, data, *_a, **_k: writes.append((name, copy.deepcopy(data))))
    result = rm.run_ip_recon(list(targets), dict(GROUP1_ONLY, **settings))
    return result, writes


def _naabu(monkeypatch, recon_data, dns, ports=(443,)):
    """run_port_scan with a fake naabu that reports `ports` open on every address
    it was given (directly, or by a name it resolves). Returns (target lines,
    port_scan section)."""
    from recon.main_recon_modules import port_scan
    seen = {"targets": []}
    real_build = port_scan.build_naabu_command

    def build(targets_file, output_file, *args, **kwargs):
        lines = Path(targets_file).read_text().split()
        seen["targets"] = lines
        rows = [json.dumps({"ip": ip, "port": port})
                for target in lines for ip in dns.addresses(target) for port in ports]
        Path(output_file).write_text("\n".join(dict.fromkeys(rows)) + "\n")
        return real_build(targets_file, output_file, *args, **kwargs)

    monkeypatch.setattr(port_scan, "build_naabu_command", build)
    monkeypatch.setattr(port_scan, "is_docker_installed", lambda: True)
    monkeypatch.setattr(port_scan, "is_docker_running", lambda: True)
    monkeypatch.setattr(port_scan, "pull_naabu_docker_image", lambda *_a, **_k: True)
    monkeypatch.setattr(port_scan.subprocess, "Popen", _FakePopen)
    snapshot = copy.deepcopy(recon_data)
    port_scan.run_port_scan(snapshot, settings=dict(IP_MODE_SETTINGS, NAABU_ENABLED=True,
                                                    NAABU_SCAN_TYPE="c"))
    return seen["targets"], snapshot.get("port_scan", {})


def _httpx(monkeypatch, recon_data, settings):
    """run_http_probe up to the docker command; returns {'urls', 'cmd'}."""
    from recon.main_recon_modules import http_probe
    seen = {}
    real_build = http_probe.build_httpx_command

    def build(targets_file, output_file, *args, **kwargs):
        seen["urls"] = Path(targets_file).read_text().split()
        seen["cmd"] = real_build(targets_file, output_file, *args, **kwargs)
        raise _Stop

    monkeypatch.setattr(http_probe, "build_httpx_command", build)
    monkeypatch.setattr(http_probe, "is_docker_installed", lambda: True)
    monkeypatch.setattr(http_probe, "is_docker_running", lambda: True)
    monkeypatch.setattr(http_probe, "pull_httpx_docker_image", lambda *_a, **_k: True)
    # /etc/resolv.conf differs between hosts; the command must not.
    monkeypatch.setattr(http_probe, "system_resolvers", lambda: ["192.0.2.53"])
    http_probe.run_http_probe(copy.deepcopy(recon_data), settings=dict(settings))
    return seen


def _nuclei(monkeypatch, recon_data, settings):
    """run_vuln_scan up to the detection command; returns {'urls', 'cmd'}."""
    from recon.main_recon_modules import vuln_scan
    seen = {}
    real_build = vuln_scan.build_nuclei_command

    def build(*args, **kwargs):
        targets_file = kwargs.get("targets_file") or args[0]
        seen["urls"] = Path(targets_file).read_text().split()
        seen["cmd"] = real_build(*args, **kwargs)
        raise _Stop

    monkeypatch.setattr(vuln_scan, "build_nuclei_command", build)
    monkeypatch.setattr(vuln_scan, "is_docker_installed", lambda: True)
    monkeypatch.setattr(vuln_scan, "is_docker_running", lambda: True)
    monkeypatch.setattr(vuln_scan, "pull_nuclei_docker_image", lambda *_a, **_k: True)
    monkeypatch.setattr(vuln_scan, "ensure_templates_volume", lambda *_a, **_k: True)
    monkeypatch.setattr("helpers.proxy_routing.get_capture_routing", lambda *_a, **_k: (None, None))
    with pytest.raises(_Stop):
        vuln_scan.run_vuln_scan(copy.deepcopy(recon_data), output_file=None,
                                settings=dict(settings, CVE_LOOKUP_ENABLED=False,
                                              SECURITY_CHECK_ENABLED=False))
    return seen


def _is_placeholder(host) -> bool:
    """The dashed name run_ip_recon gives an address with no PTR."""
    host = str(host or "")
    if not host or "." in host or "-" not in host:
        return False
    for sep in (".", ":"):
        try:
            ipaddress.ip_address(host.replace("-", sep))
            return True
        except ValueError:
            continue
    return False


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _outside(values, allowed=TARGETS) -> list:
    return sorted({str(v) for v in values} - set(allowed))


def _ip_recon_writer_addresses(recon_data: dict) -> set:
    """The IP nodes the real update_graph_from_ip_recon MERGEs for this recon dict."""
    from graph_db.mixins.recon.domain_mixin import DomainMixin
    calls = []

    class _Result:
        def single(self):
            return None

        def __iter__(self):
            return iter([])

    class _Session:
        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def run(self, query, **params):
            calls.append((query, params))
            return _Result()

    class _Driver:
        def session(self, **_k):
            return _Session()

    writer = type("Writer", (DomainMixin,), {})
    obj = writer.__new__(writer)
    obj.driver = _Driver()
    obj.update_graph_from_ip_recon(recon_data, "u1", PID)
    return {p.get("addr") for q, p in calls if "MERGE (i:IP" in q and p.get("addr")}


def _ptr_leak(rm, monkeypatch, ports=(443,)):
    """GROUP 1 + today's naabu for the B-01 fixture: (dns, recon with port_scan, writes)."""
    dns = FakeDns(ptr={LISTED: PTR_NAME}, forward={PTR_NAME: [FOREIGN]})
    result, writes = _group1(rm, monkeypatch, dns)
    _, port_scan = _naabu(monkeypatch, result, dns, ports=ports)
    return dns, dict(result, port_scan=port_scan), writes


# ---------------------------------------------------------------------------
# B-01 / B-02 / B-03: GROUP 1 and naabu
# ---------------------------------------------------------------------------

@pytest.mark.xfail(strict=True, raises=AssertionError, reason="B-01: a PTR name's forward A record replaces the listed IP as the naabu target")
def test_ptr_forward_ip_outside_targets_is_never_a_naabu_target(recon_main, monkeypatch):
    from recon.main_recon_modules import port_scan
    dns = FakeDns(ptr={LISTED: PTR_NAME}, forward={PTR_NAME: [FOREIGN]})
    result, _ = _group1(recon_main, monkeypatch, dns)

    ips, _, ip_to_hostnames = port_scan.extract_targets_from_recon(result)
    targets, _ = _naabu(monkeypatch, result, dns)

    assert _outside(ips) == [] and LISTED in ips
    assert _outside(ip_to_hostnames) == []
    # The naabu target list is the listed addresses themselves.
    assert _outside(targets) == [] and LISTED in targets


@pytest.mark.xfail(strict=True, raises=AssertionError, reason="B-01: a PTR name with no A record drops its listed IP from naabu, httpx and the graph")
def test_listed_ip_survives_a_ptr_name_without_forward_record(recon_main, monkeypatch):
    dns = FakeDns(ptr={LISTED: "ghost.example.com"}, forward={})
    result, writes = _group1(recon_main, monkeypatch, dns)

    targets, _ = _naabu(monkeypatch, result, dns)
    assert LISTED in targets

    # No port scan data: httpx falls back to the DNS section.
    fallback = _httpx(monkeypatch, result, IP_MODE_SETTINGS)
    assert f"http://{LISTED}" in fallback["urls"]

    written = dict(writes)["update_graph_from_ip_recon"]
    assert LISTED in _ip_recon_writer_addresses(written)


@pytest.mark.xfail(strict=True, raises=AssertionError, reason="B-02: the dashed placeholder reaches naabu, by_host and httpx as a hostname")
def test_placeholder_is_never_a_hostname_target(recon_main, monkeypatch):
    dns = FakeDns()
    result, _ = _group1(recon_main, monkeypatch, dns)
    targets, port_scan = _naabu(monkeypatch, result, dns, ports=(80,))
    probe = _httpx(monkeypatch, dict(result, port_scan=port_scan), IP_MODE_SETTINGS)

    used_as_host = [*targets, *port_scan.get("by_host", {}), *map(_host, probe["urls"])]
    assert [h for h in used_as_host if _is_placeholder(h)] == []
    # The addresses themselves are still probed.
    assert {f"http://{ip}" for ip in TARGETS} <= set(probe["urls"])


@pytest.mark.xfail(strict=True, raises=AssertionError, reason="B-03: naabu's dedupe is a no-op, so an IP is scanned by name and by address")
def test_naabu_target_list_has_no_duplicates(recon_main, monkeypatch):
    # A PTR name that resolves back to its own listed address.
    dns = FakeDns(ptr={LISTED: PTR_NAME}, forward={PTR_NAME: [LISTED]})
    result, _ = _group1(recon_main, monkeypatch, dns)
    targets, _ = _naabu(monkeypatch, result, dns)

    per_address = Counter(a for t in targets for a in dns.addresses(t))
    assert {a: n for a, n in per_address.items() if n > 1} == {}
    assert set(per_address) == set(TARGETS)


# ---------------------------------------------------------------------------
# B-05 / B-06 / B-07: redirects and the TLS probe
# ---------------------------------------------------------------------------

# Flag spellings recorded from the pinned images (R-13), `-h` on 2026-11-10:
#   projectdiscovery/httpx:latest  v1.12.0  sha256:f8275a7c6aae...
#     -fr, -follow-redirects        follow http redirects
#     -fhr, -follow-host-redirects  follow redirects on the same host
#     -maxr, -max-redirects int     max number of redirects to follow per host
#     -tls-probe                    send http probes on the extracted TLS domains (dns_name)
#     -tls-grab                     perform TLS(SSL) data grabbing
#   projectdiscovery/nuclei:latest  v3.11.1  sha256:582d5546902e...
#     -fr, -follow-redirects        enable following redirects for http templates
#     -fhr, -follow-host-redirects  follow redirects on the same host
#     -mr, -max-redirects int       max number of redirects to follow for http templates

@pytest.mark.xfail(strict=True, raises=AssertionError, reason="B-05/B-06: IP-mode httpx follows cross-host redirects (-fr) and probes cert SAN names (-tls-probe)")
def test_ip_mode_httpx_command_has_no_cross_host_redirect_or_tls_probe(recon_main, monkeypatch):
    dns = FakeDns()
    result, _ = _group1(recon_main, monkeypatch, dns)
    _, port_scan = _naabu(monkeypatch, result, dns)
    settings = dict(IP_MODE_SETTINGS, HTTPX_FOLLOW_REDIRECTS=True,
                    HTTPX_PROBE_TLS_INFO=True, HTTPX_PROBE_TLS_GRAB=True)
    cmd = _httpx(monkeypatch, dict(result, port_scan=port_scan), settings)["cmd"]

    assert "-fhr" in cmd
    assert "-fr" not in cmd and "-follow-redirects" not in cmd
    assert "-tls-probe" not in cmd
    assert "-tls-grab" in cmd


@pytest.mark.xfail(strict=True, raises=AssertionError, reason="B-07: IP-mode Nuclei follows cross-host redirects (-follow-redirects)")
def test_ip_mode_nuclei_follows_host_redirects_only(recon_main, monkeypatch):
    result, _ = _group1(recon_main, monkeypatch, FakeDns())
    result["http_probe"] = {"by_url": {f"http://{ip}": {"url": f"http://{ip}", "status_code": 200}
                                       for ip in TARGETS}}
    cmd = _nuclei(monkeypatch, result, dict(IP_MODE_SETTINGS, NUCLEI_FOLLOW_REDIRECTS=True))["cmd"]

    assert "-follow-host-redirects" in cmd
    assert "-follow-redirects" not in cmd and "-fr" not in cmd


# ---------------------------------------------------------------------------
# B-08 .. B-13: the modules that pick their own targets
# ---------------------------------------------------------------------------

@pytest.mark.xfail(strict=True, raises=AssertionError, reason="B-08: origin discovery probes candidate origins that are by design not targets")
def test_origin_discovery_skips_ip_mode(recon_main, monkeypatch):
    from recon.main_recon_modules import origin_discovery as od
    result, _ = _group1(recon_main, monkeypatch, FakeDns(ptr={LISTED: PTR_NAME}, forward={PTR_NAME: [LISTED]}))
    # The PTR name httpx probed, behind a CDN: what origin discovery would unmask.
    result["http_probe"] = {"by_url": {f"https://{PTR_NAME}": {
        "url": f"https://{PTR_NAME}", "host": PTR_NAME, "ip": LISTED, "status_code": 200,
        "is_cdn": True, "cdn": "cloudflare"}}}
    probes = []
    monkeypatch.setattr(od, "_resolve_ips", lambda host: set())
    monkeypatch.setattr(od, "_process_host",
                        lambda host, *a, **k: probes.append(host) or ([], {}))
    monkeypatch.setattr(od.requests, "get", lambda url, *a, **k: probes.append(url))

    od.run_origin_discovery_enrichment_isolated(
        result, dict(IP_MODE_SETTINGS, ORIGIN_DISCOVERY_ENABLED=True))

    assert probes == []


@pytest.mark.xfail(strict=True, raises=AssertionError, reason="B-09: masscan keys a PTR'd IP by its name only, so by_host[ip] is missing")
def test_masscan_keeps_ip_key_with_real_name(monkeypatch):
    from recon.main_recon_modules import masscan_scan
    # GROUP 1's IP-mode metadata as run_ip_recon writes it for a PTR'd target.
    recon_data = {"metadata": {"ip_mode": True, "expanded_ips": [LISTED],
                               "ip_to_hostname": {LISTED: PTR_NAME}}}
    real_build = masscan_scan.build_masscan_command

    def build(targets_file, output_file, *args, **kwargs):
        Path(output_file).write_text(json.dumps({
            "ip": LISTED, "port": 443, "proto": "tcp", "rec_type": "status",
            "data": {"status": "open"}}) + "\n")
        return real_build(targets_file, output_file, *args, **kwargs)

    monkeypatch.setattr(masscan_scan, "is_masscan_installed", lambda: True)
    monkeypatch.setattr(masscan_scan, "build_masscan_command", build)
    monkeypatch.setattr(masscan_scan.subprocess, "Popen", _FakePopen)
    masscan_scan.run_masscan_scan(recon_data, settings=dict(IP_MODE_SETTINGS, MASSCAN_ENABLED=True))

    by_host = recon_data["masscan_scan"]["by_host"]
    assert LISTED in by_host and by_host[LISTED]["ports"] == [443]


class _Resp:
    def __init__(self, status, headers=None, text=""):
        self.status_code = status
        self.headers = headers or {}
        self.text = text
        self.content = text.encode()


@pytest.mark.xfail(strict=True, raises=AssertionError, reason="B-10: JS recon follows a target's redirect to a non-target host")
def test_js_recon_does_not_follow_redirect_to_non_target(recon_main, monkeypatch, doc_ranges_public):
    from recon.main_recon_modules import js_recon
    result, _ = _group1(recon_main, monkeypatch, FakeDns())
    bundle = f"http://{LISTED}/static/app.js"
    result["http_probe"] = {"by_url": {bundle: {
        "url": bundle, "host": LISTED, "status_code": 200,
        "content_type": "application/javascript"}}}
    requested = []

    def get(url, *a, **k):
        requested.append(url)
        if _host(url) == LISTED:
            return _Resp(302, {"Location": f"http://{FOREIGN}/app.js"})
        return _Resp(200, {"Content-Type": "application/javascript"}, "var a = 1;\n")

    monkeypatch.setattr(js_recon.requests, "get", get)
    # Only the downloads are under test; the analysis is not.
    monkeypatch.setattr(js_recon, "_run_analysis", mock.Mock(side_effect=_Stop))

    js_recon.run_js_recon(result, dict(IP_MODE_SETTINGS, JS_RECON_ENABLED=True,
                                       JS_RECON_CONCURRENCY=1, JS_RECON_TIMEOUT=60))

    assert bundle in requested
    assert [u for u in requested if _host(u) not in TARGETS] == []


class _Session:
    def __init__(self):
        self.urls = []

    def get(self, url, *a, **k):
        self.urls.append(url)
        return _Resp(404)


@pytest.mark.xfail(strict=True, raises=AssertionError, reason="B-11: the AI-surface vector-DB read is sent to the by_host key (the placeholder)")
def test_ai_surface_vector_db_uses_ip(recon_main, monkeypatch):
    from recon.main_recon_modules import ai_surface_recon
    dns = FakeDns()
    result, _ = _group1(recon_main, monkeypatch, dns)
    # 6333 is Qdrant's port in the AI port catalogue.
    _, port_scan = _naabu(monkeypatch, result, dns, ports=(6333,))
    session = _Session()
    ai_surface_recon._confirm_vector_dbs(dict(result, port_scan=port_scan), session, 1)

    assert session.urls
    assert _outside(map(_host, session.urls)) == []


@pytest.mark.xfail(strict=True, raises=AssertionError, reason="B-12: IPv6 target URLs are built without brackets")
def test_ipv6_target_urls_are_bracketed(recon_main, monkeypatch):
    from recon.main_recon_modules import ai_surface_recon
    dns = FakeDns()
    result, _ = _group1(recon_main, monkeypatch, dns, targets=[TARGET_V6])
    settings = dict(IP_MODE_SETTINGS, TARGET_IPS=[TARGET_V6])

    def well_formed(url):
        try:
            parsed = urlparse(url)
            parsed.port  # raises on an unbracketed IPv6 literal
        except ValueError:
            return False
        return parsed.hostname == TARGET_V6

    fallback = _httpx(monkeypatch, result, settings)["urls"]
    assert f"https://[{TARGET_V6}]:8443" in fallback
    assert [u for u in fallback if not well_formed(u)] == []

    _, port_scan = _naabu(monkeypatch, result, dns, ports=(6333, 8443))
    scanned = dict(result, port_scan=port_scan)
    probed = _httpx(monkeypatch, scanned, settings)["urls"]
    assert f"https://[{TARGET_V6}]:8443" in probed
    assert [u for u in probed if not well_formed(u)] == []

    session = _Session()
    ai_surface_recon._confirm_vector_dbs(scanned, session, 1)
    assert session.urls and all(u.startswith(f"http://[{TARGET_V6}]:6333") or
                                u.startswith(f"https://[{TARGET_V6}]:6333") for u in session.urls)


@pytest.mark.xfail(strict=True, raises=AssertionError, reason="B-13: a pure-IP run gives the header/auth/app/TLS checks no host at all")
def test_pure_ip_run_gets_hostname_security_checks_on_ip_literals(recon_main, monkeypatch):
    from recon.helpers import security_checks as sc
    result, _ = _group1(recon_main, monkeypatch, FakeDns())
    received = {}

    def record(name):
        def check(*_a, hostnames=None, **_k):
            received[name] = sorted(hostnames or [])
            return []
        return check

    hostname_checks = ("run_tls_checks", "run_security_headers_checks", "run_auth_checks",
                       "run_app_security_checks", "run_rate_limit_checks")
    for name in hostname_checks:
        monkeypatch.setattr(sc, name, record(name))
    for name in ("run_direct_ip_checks", "run_port_service_checks", "run_dns_checks",
                 "run_tls_data_checks", "run_page_content_checks"):
        monkeypatch.setattr(sc, name, lambda *a, **k: [])

    sc.run_security_checks(result, {c: True for c in (
        "tls_expiring_soon", "missing_referrer_policy", "login_no_https",
        "csp_unsafe_inline", "no_rate_limiting")}, timeout=1)

    assert {name: received.get(name) for name in hostname_checks} == {
        name: sorted(TARGETS) for name in hostname_checks}


# ---------------------------------------------------------------------------
# B-01 / B-26: every builder of a scan target list, on the PTR-leak input
# ---------------------------------------------------------------------------

@pytest.mark.xfail(strict=True, raises=AssertionError, reason="B-01/B-26: the PTR name's foreign address reaches every downstream target builder")
def test_nmap_tlsx_banner_vhost_attribution_gvm_use_targets_only(recon_main, monkeypatch, doc_ranges_public):
    """The GVM half (gvm_scanner.extract_targets_from_recon) runs in the agent
    image: tests/test_regression_gvm_ip_mode.py."""
    import importlib
    from recon.cache_scan import scanner as cache_scanner
    from recon.helpers import security_checks as sc
    from recon.helpers import target_helpers
    from recon.main_recon_modules import http_probe, ip_attribution, nmap_scan, port_scan, tls_scan
    from recon.main_recon_modules import vhost_sni_enum

    _, recon_data, writes = _ptr_leak(recon_main, monkeypatch, ports=(22, 443, 993))
    settings = dict(IP_MODE_SETTINGS)
    leaks = {}

    def check(name, values):
        bad = _outside(values)
        if bad:
            leaks[name] = bad

    ips, _, ip_map = port_scan.extract_targets_from_recon(recon_data)
    check("port_scan.extract_targets_from_recon", [*ips, *ip_map])
    ips, _, ip_map = target_helpers.extract_targets_from_recon(recon_data)
    check("target_helpers.extract_targets_from_recon", [*ips, *ip_map])

    check("nmap", nmap_scan.build_nmap_targets(recon_data, settings)[0])

    lines, meta = tls_scan._build_tlsx_targets(recon_data, settings)
    check("tlsx", [*meta.values(), *(line.rsplit(":", 1)[0].strip("[]") for line in lines)])

    grabbed = []
    monkeypatch.setattr(http_probe, "grab_banner_for_target",
                        lambda target, *a, **k: grabbed.append(target) or {"host": target[2], "port": target[1]})
    http_probe.run_banner_grab(recon_data, settings)
    check("banner_grab", [t[0] for t in grabbed])

    check("vhost_sni", vhost_sni_enum._collect_ip_targets(recon_data))
    check("ip_attribution", ip_attribution._run_ips(recon_data, {}))

    for tool in ("shodan", "censys", "fofa", "otx", "netlas", "virustotal", "zoomeye", "criminalip"):
        module = importlib.import_module(f"recon.main_recon_modules.{tool}_enrich")
        check(f"{tool}._extract_ips_from_recon", module._extract_ips_from_recon(recon_data))

    direct = []
    monkeypatch.setattr(sc, "run_direct_ip_checks",
                        lambda *a, ips=None, **k: direct.extend(ips or []) or [])
    for name in ("run_tls_checks", "run_security_headers_checks", "run_auth_checks",
                 "run_app_security_checks", "run_rate_limit_checks", "run_port_service_checks",
                 "run_dns_checks", "run_tls_data_checks", "run_page_content_checks"):
        monkeypatch.setattr(sc, name, lambda *a, **k: [])
    sc.run_security_checks(recon_data, {"direct_ip_http": True}, timeout=1)
    check("security_checks.ips", direct)

    check("cache_scan targets", map(_host, cache_scanner._collect_target_urls(recon_data, settings)))

    check("update_graph_from_ip_recon IP nodes",
          _ip_recon_writer_addresses(dict(writes)["update_graph_from_ip_recon"]))

    assert leaks == {}, json.dumps(leaks, indent=1, sort_keys=True)


# ---------------------------------------------------------------------------
# Domain mode must not change: plain asserts, green today and after the fix.
# ---------------------------------------------------------------------------

DOMAIN_RECON = {
    "domain": "example.com",
    "metadata": {"ip_mode": False, "root_domain": "example.com", "scope_mode": "enumerate",
                 "include_root_domain": True, "filtered_mode": False},
    "dns": {"domain": {"has_records": True, "ips": {"ipv4": ["203.0.113.10"], "ipv6": []}},
            "subdomains": {"www.example.com": {"has_records": True,
                                               "ips": {"ipv4": ["203.0.113.11"], "ipv6": []}}}},
    "port_scan": {"by_host": {"www.example.com": {
        "host": "www.example.com", "ip": "203.0.113.11", "ports": [443],
        "port_details": [{"port": 443, "protocol": "tcp", "service": "https"}]}},
        "by_ip": {}, "all_ports": [443]},
    "http_probe": {"by_url": {"https://www.example.com": {"url": "https://www.example.com",
                                                          "status_code": 200}}},
}


def _normalised(cmd: list) -> list:
    """A run's command with its per-run container name and temp dir replaced."""
    out, skip_next = [], False
    for i, arg in enumerate(cmd):
        if skip_next:
            out.append("<name>")
            skip_next = False
            continue
        if arg == "--name":
            skip_next = True
        out.append(re.sub(r"/tmp/redamon/\.(httpx|nuclei)_temp_[0-9a-f]+", "<tmp>", arg))
    return out


def test_domain_mode_httpx_command_is_unchanged(monkeypatch):
    cmd = _httpx(monkeypatch, DOMAIN_RECON, {"IP_MODE": False})["cmd"]
    assert _normalised(cmd) == [
        "docker", "run", "--rm", "--net=host", "--name", "<name>",
        "-v", "<tmp>:/targets:ro", "-v", "<tmp>:/output",
        "projectdiscovery/httpx:latest",
        "-l", "/targets/targets.txt", "-o", "/output/httpx_output.json",
        "-json", "-silent", "-nc", "-t", "50", "-timeout", "10", "-retries", "2", "-rl", "50",
        "-fr", "-maxr", "10",
        "-sc", "-cl", "-ct", "-title", "-server", "-rt", "-wc", "-lc", "-td", "-ip", "-cname",
        "-tls-probe", "-tls-grab", "-favicon", "-jarm", "-hash", "sha256", "-irr", "-irh",
        "-asn", "-cdn", "-r", "192.0.2.53",
    ]


def test_domain_mode_nuclei_command_is_unchanged(monkeypatch):
    monkeypatch.delenv("HOST_CUSTOM_TEMPLATES_PATH", raising=False)
    cmd = _nuclei(monkeypatch, DOMAIN_RECON, {"IP_MODE": False})["cmd"]
    assert _normalised(cmd) == [
        "docker", "run", "--rm", "--net=host", "--name", "<name>",
        "-v", "<tmp>:/targets:ro", "-v", "<tmp>:/output",
        "-v", "nuclei-templates:/root/nuclei-templates",
        "projectdiscovery/nuclei:latest",
        "-l", "/targets/targets_detection.txt", "-jsonl", "-o", "/output/nuclei_detection.jsonl",
        "-silent", "-nc", "-duc", "-stats", "-stats-interval", "30",
        "-severity", "critical,high,medium,low",
        "-t", "/root/nuclei-templates/",
        "-tags", "cve,xss,sqli,rce,lfi,ssrf,xxe,ssti", "-exclude-tags", "dos,fuzz",
        "-rate-limit", "100", "-bulk-size", "25", "-concurrency", "25",
        "-timeout", "10", "-retries", "1", "-mhe", "30",
        "-system-resolvers", "-follow-redirects", "-max-redirects", "10",
    ]
