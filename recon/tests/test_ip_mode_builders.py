"""Every target builder the IP-mode fix (step P0b) changed, one by one.

An IP-mode run's targets are addresses (``metadata.expanded_ips``). Each builder
below reads them from a different structure, and each must keep to them: a
DNS answer that is not a target, an IP-mode label (``203-0-113-1``) or a name
whose address is outside the list never reaches a tool. The same builders in
domain mode must not move, so each block also pins the domain-mode answer.

The run-level sweep over the same builders, from GROUP 1's real output, is
test_regression_ip_mode_scope_leaks.py. Documentation ranges (RFC 5737 /
RFC 3849), the private 10.0.0.0/8 and reserved names only.
"""
import importlib
import json
import sys
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers import circuit_breaker  # noqa: E402

T1, T2, FOREIGN, V6 = "203.0.113.1", "203.0.113.2", "198.51.100.7", "2001:db8::1"
NAME = "www.example.com"


@pytest.fixture(autouse=True)
def _fresh_run():
    circuit_breaker.reset_registry()
    yield
    circuit_breaker.reset_registry()


def _mock_entry(ip):
    v6 = ":" in ip
    return {"has_records": True, "is_mock": True, "actual_ip": ip, "records": {},
            "ips": {"ipv4": [] if v6 else [ip], "ipv6": [ip] if v6 else []}}


def _ip_recon(expanded=(T1, T2), names=None, **extra):
    """run_ip_recon's GROUP 1 shape: one label per address, plus PTR names."""
    from recon.helpers.ip_placeholders import placeholder_for
    subs = {placeholder_for(ip): _mock_entry(ip) for ip in expanded}
    for name, addrs in (names or {}).items():
        subs[name] = {"has_records": True, "ips": {"ipv4": [a for a in addrs if ":" not in a],
                                                    "ipv6": [a for a in addrs if ":" in a]}}
    recon = {
        "domain": "ip-targets.p1",
        "metadata": {"ip_mode": True, "expanded_ips": list(expanded), "root_domain": "ip-targets.p1",
                     "scope_mode": "exact", "include_root_domain": False, "filtered_mode": True,
                     "subdomain_filter": [*expanded, *subs]},
        "subdomains": list(subs),
        "dns": {"domain": {}, "subdomains": subs},
    }
    recon.update(extra)
    return recon


# ---------------------------------------------------------------------------
# naabu
# ---------------------------------------------------------------------------

def test_naabu_takes_addresses_only_and_keeps_a_target_name_for_its_ports():
    from recon.main_recon_modules import port_scan
    recon = _ip_recon(names={NAME: [T1], "away.example.com": [FOREIGN]})
    ips, hostnames, ip_map = port_scan.extract_targets_from_recon(recon)
    assert ips == {T1, T2}
    assert hostnames == set()
    assert ip_map == {T1: [NAME]}


def test_naabu_output_is_keyed_by_address_with_no_label(tmp_path):
    from recon.main_recon_modules import port_scan
    out = tmp_path / "naabu.json"
    out.write_text("\n".join(json.dumps({"ip": ip, "port": 443}) for ip in (T1, T2)) + "\n")
    parsed = port_scan.parse_naabu_output(str(out), ip_to_hostnames={T1: [NAME]})
    assert set(parsed["by_host"]) == {T1, T2, NAME}
    assert parsed["by_host"][NAME]["ip"] == T1
    assert parsed["by_ip"][T1]["hostnames"] == [NAME]


# ---------------------------------------------------------------------------
# httpx: URL builders and the command
# ---------------------------------------------------------------------------

def test_url_authority_brackets_ipv6_only():
    from recon.main_recon_modules.http_probe import _url_authority
    assert _url_authority(V6) == f"[{V6}]"
    assert _url_authority(T1) == T1
    assert _url_authority(NAME) == NAME
    assert _url_authority(f"[{V6}]") == f"[{V6}]"


def test_naabu_path_urls_bracket_an_ipv6_key():
    from recon.main_recon_modules.http_probe import build_targets_from_naabu
    recon = {"port_scan": {"by_host": {
        V6: {"host": V6, "port_details": [{"port": 443, "service": "https"},
                                          {"port": 8080, "service": ""},
                                          {"port": 6333, "service": ""}]},
        T1: {"host": T1, "port_details": [{"port": 80, "service": "http"}]}}}}
    assert sorted(build_targets_from_naabu(recon, {})) == sorted([
        f"https://[{V6}]", f"http://[{V6}]:8080", f"http://[{V6}]:6333", f"https://[{V6}]:6333",
        f"http://{T1}"])


@pytest.mark.parametrize("settings, expected", [
    ({}, {f"http://[{V6}]", f"https://[{V6}]", f"https://[{V6}]:8443", f"http://[{V6}]:8080"}),
    ({"NAABU_CUSTOM_PORTS": "443,8443"}, {f"https://[{V6}]", f"https://[{V6}]:8443"}),
])
def test_dns_fallback_brackets_an_ipv6_target(settings, expected):
    from recon.main_recon_modules.http_probe import build_targets_from_dns
    urls = set(build_targets_from_dns(_ip_recon(expanded=(V6,)), settings))
    assert expected <= urls
    assert not [u for u in urls if f"//{V6}" in u]


def _httpx_cmd(settings, **kwargs):
    from recon.main_recon_modules.http_probe import build_httpx_command
    with mock.patch("recon.main_recon_modules.http_probe.system_resolvers", return_value=["192.0.2.53"]):
        return build_httpx_command("/tmp/redamon/x/targets.txt", "/tmp/redamon/x/out.json",
                                   settings, container_name="c", **kwargs)


@pytest.mark.parametrize("how", ["setting", "argument"])
def test_ip_mode_httpx_stays_on_the_host_and_never_probes_cert_names(how):
    settings = {"IP_MODE": True} if how == "setting" else {}
    cmd = _httpx_cmd(settings, **({} if how == "setting" else {"ip_mode": True}))
    assert "-fhr" in cmd and "-fr" not in cmd
    assert "-tls-probe" not in cmd and "-tls-grab" in cmd


def test_ip_mode_httpx_differs_from_domain_mode_in_those_two_flags_only():
    domain = _httpx_cmd({})
    assert domain == _httpx_cmd({"IP_MODE": False}) == _httpx_cmd({}, ip_mode=False)
    expected = [("-fhr" if a == "-fr" else a) for a in domain if a != "-tls-probe"]
    assert _httpx_cmd({}, ip_mode=True) == expected


def test_ip_mode_httpx_follows_nothing_when_redirects_are_off():
    cmd = _httpx_cmd({"HTTPX_FOLLOW_REDIRECTS": False}, ip_mode=True)
    assert "-fhr" not in cmd and "-fr" not in cmd


def test_run_http_probe_reads_ip_mode_from_the_recon_dict(monkeypatch):
    from recon.main_recon_modules import http_probe
    seen = {}

    class _Stop(Exception):
        pass

    def build(targets_file, output_file, settings, **kwargs):
        seen["settings"], seen["kwargs"] = settings, kwargs
        raise _Stop

    monkeypatch.setattr(http_probe, "build_httpx_command", build)
    monkeypatch.setattr(http_probe, "is_docker_installed", lambda: True)
    monkeypatch.setattr(http_probe, "is_docker_running", lambda: True)
    monkeypatch.setattr(http_probe, "pull_httpx_docker_image", lambda *_a, **_k: True)
    given = {}
    http_probe.run_http_probe(_ip_recon(), settings=given)
    assert seen["settings"]["IP_MODE"] is True
    assert given == {}                                   # the caller's dict is not changed
    # The call keeps the keyword set every existing caller and fake knows.
    assert set(seen["kwargs"]) == {"probe_hosts", "container_name"}


# ---------------------------------------------------------------------------
# Nuclei and its target URLs
# ---------------------------------------------------------------------------

def _nuclei_cmd(**kwargs):
    from recon.helpers.nuclei_helpers import build_nuclei_command
    with mock.patch("helpers.proxy_routing.get_capture_routing", return_value=(None, None)):
        return build_nuclei_command("/tmp/redamon/n/t.txt", "/tmp/redamon/n/o.jsonl",
                                    "projectdiscovery/nuclei:latest", **kwargs)


def test_ip_mode_nuclei_follows_same_host_redirects_only():
    cmd = _nuclei_cmd(follow_redirects=True, max_redirects=10, ip_mode=True)
    assert "-follow-host-redirects" in cmd and "-follow-redirects" not in cmd
    assert cmd[cmd.index("-max-redirects") + 1] == "10"


def test_domain_mode_nuclei_redirect_flags_are_unchanged():
    assert _nuclei_cmd(follow_redirects=True) == _nuclei_cmd(follow_redirects=True, ip_mode=False)
    assert "-follow-redirects" in _nuclei_cmd(follow_redirects=True)
    assert "-follow-host-redirects" in _nuclei_cmd(follow_redirects=True, auth_headers=["Cookie: a=b"])
    assert not {"-follow-redirects", "-follow-host-redirects"} & set(_nuclei_cmd(ip_mode=True))


def test_ip_mode_target_urls_add_no_unprobed_name():
    from recon.helpers.target_helpers import build_target_urls
    recon = _ip_recon(http_probe={"by_url": {f"http://{T1}": {"url": f"http://{T1}", "status_code": 200}}})
    assert build_target_urls({NAME, "203-0-113-2"}, set(), recon, False) == [f"http://{T1}"]
    domain = dict(recon, metadata={"ip_mode": False})
    assert f"https://{NAME}" in build_target_urls({NAME}, set(), domain, False)


# ---------------------------------------------------------------------------
# tlsx
# ---------------------------------------------------------------------------

def _tlsx_recon(by_ip, **kwargs):
    recon = _ip_recon(**kwargs)
    recon["port_scan"] = {"by_ip": by_ip}
    return recon


def test_tlsx_handshakes_a_private_target_in_ip_mode():
    from recon.main_recon_modules.tls_scan import _build_tlsx_targets
    recon = _tlsx_recon({"10.0.0.5": {"ports": [993]}, "10.0.0.6": {"ports": [993]}},
                        expanded=("10.0.0.5",))
    lines, meta = _build_tlsx_targets(recon, {})
    assert lines == ["10.0.0.5:993"] and meta == {"10.0.0.5:993": "10.0.0.5"}


def test_tlsx_skips_a_non_target_and_a_name_that_resolves_outside():
    from recon.main_recon_modules.tls_scan import _build_tlsx_targets
    recon = _tlsx_recon({T1: {"ports": [993], "hostnames": ["away.example.com"]},
                         T2: {"ports": [993], "hostnames": [NAME, "203-0-113-2"]},
                         FOREIGN: {"ports": [993]}},
                        names={NAME: [T2], "away.example.com": [FOREIGN]})
    with mock.patch("recon.main_recon_modules.ip_filter.is_non_routable_ip", return_value=False):
        lines, _ = _build_tlsx_targets(recon, {})
    assert lines == [f"{T1}:993", f"{NAME}:993"]


def test_tlsx_domain_mode_still_skips_private_addresses():
    from recon.main_recon_modules.tls_scan import _build_tlsx_targets
    recon = {"port_scan": {"by_ip": {"10.0.0.5": {"ports": [993]}}}}
    assert _build_tlsx_targets(recon, {}) == ([], {})


# ---------------------------------------------------------------------------
# Address-only readers: attribution, vhost, OSINT, security checks, GVM-side
# ---------------------------------------------------------------------------

def test_attribution_attributes_targets_only_in_ip_mode():
    from recon.main_recon_modules.ip_attribution import _run_ips
    recon = _ip_recon(names={NAME: [FOREIGN]})
    assert _run_ips(recon, {FOREIGN: {}}) == [T1, T2]
    domain = {"metadata": {"ip_mode": False}, "dns": recon["dns"]}
    assert FOREIGN in _run_ips(domain, {})


def test_vhost_probes_target_addresses_only_in_ip_mode():
    from recon.main_recon_modules.vhost_sni_enum import _collect_ip_targets
    recon = _ip_recon(names={NAME: [FOREIGN]})
    recon["port_scan"] = {"by_host": {FOREIGN: {"ip": FOREIGN, "ports": [443]},
                                      T1: {"ip": T1, "ports": [8443]}}}
    assert set(_collect_ip_targets(recon)) == {T1, T2}
    domain = dict(recon, metadata={"ip_mode": False})
    assert FOREIGN in _collect_ip_targets(domain)


@pytest.mark.parametrize("tool", ["shodan", "censys", "fofa", "otx", "netlas", "virustotal",
                                  "zoomeye", "criminalip"])
def test_osint_ip_list_is_the_target_list_in_ip_mode(tool):
    module = importlib.import_module(f"recon.main_recon_modules.{tool}_enrich")
    recon = _ip_recon(names={NAME: [FOREIGN]})
    assert module._extract_ips_from_recon(recon) == [T1, T2]
    # A dict that declares no target list keeps the DNS addresses.
    legacy = {"metadata": {"ip_mode": True}, "dns": recon["dns"]}
    assert FOREIGN in module._extract_ips_from_recon(legacy)


def test_security_checks_get_target_literals_and_target_names_only():
    from recon.helpers.security_checks import _ip_mode_hosts
    recon = _ip_recon()
    hosts, ips = _ip_mode_hosts(recon, [NAME, "away.example.com"], [T1, FOREIGN, T2],
                                {NAME: [T2], "away.example.com": [FOREIGN]})
    assert hosts == [NAME, T1, T2]
    assert ips == [T1, T2]
    domain = {"metadata": {"ip_mode": False}}
    assert _ip_mode_hosts(domain, [NAME], [FOREIGN], {}) == ([NAME], [FOREIGN])


def test_a_hostname_check_brackets_an_ipv6_literal(monkeypatch):
    from recon.helpers import security_checks as sc
    asked = []

    def get(url, timeout):
        asked.append(url)
        raise sc.requests.RequestException("offline")

    monkeypatch.setattr(sc, "_get_on_host", get)
    sc.check_csp_unsafe_inline(V6, timeout=1)
    sc.check_csp_unsafe_inline(NAME, timeout=1)
    assert asked == [f"https://[{V6}]/", f"https://{NAME}/"]


# ---------------------------------------------------------------------------
# AI surface vector-DB read
# ---------------------------------------------------------------------------

class _Session:
    def __init__(self):
        self.urls = []

    def get(self, url, *a, **k):
        self.urls.append(url)
        return mock.Mock(status_code=404, text="")


def test_vector_db_read_goes_to_the_target_address_in_ip_mode():
    from recon.main_recon_modules.ai_surface_recon import _confirm_vector_dbs
    recon = _ip_recon()
    recon["port_scan"] = {"by_host": {"203-0-113-1": {"ip": T1, "ports": [6333]},
                                      FOREIGN: {"ip": FOREIGN, "ports": [6333]}}}
    session = _Session()
    _confirm_vector_dbs(recon, session, 1)
    assert session.urls and all(u.split("//")[1].startswith(f"{T1}:6333") for u in session.urls)


def test_vector_db_read_keeps_the_host_name_in_domain_mode():
    from recon.main_recon_modules.ai_surface_recon import _confirm_vector_dbs
    recon = {"metadata": {"ip_mode": False},
             "port_scan": {"by_host": {NAME: {"ip": T1, "ports": [6333]}}}}
    session = _Session()
    _confirm_vector_dbs(recon, session, 1)
    assert session.urls and all(u.split("//")[1].startswith(f"{NAME}:6333") for u in session.urls)


# ---------------------------------------------------------------------------
# Origin discovery
# ---------------------------------------------------------------------------

def test_origin_discovery_never_runs_in_ip_mode(monkeypatch, capsys):
    from recon.main_recon_modules import origin_discovery as od
    monkeypatch.setattr(od, "_select_fronted_hosts", mock.Mock(side_effect=AssertionError("ran")))
    out = od.run_origin_discovery_enrichment_isolated(
        {"metadata": {}}, {"ORIGIN_DISCOVERY_ENABLED": True, "IP_MODE": True})
    assert out == {"confirmed": [], "candidates_meta": {}}
    assert "[-][OriginDiscovery] skipped in IP mode" in capsys.readouterr().out


def test_origin_discovery_still_runs_in_domain_mode(monkeypatch):
    from recon.main_recon_modules import origin_discovery as od
    selected = mock.Mock(return_value={})
    monkeypatch.setattr(od, "_select_fronted_hosts", selected)
    od.run_origin_discovery_enrichment_isolated({"metadata": {"ip_mode": False}},
                                                {"ORIGIN_DISCOVERY_ENABLED": True})
    assert selected.called


# ---------------------------------------------------------------------------
# JS recon: the run's admit rule
# ---------------------------------------------------------------------------

def test_js_endpoint_probe_is_refused_when_not_admitted(monkeypatch):
    from recon.main_recon_modules import js_recon
    monkeypatch.setattr(js_recon, "_ADMIT", lambda url: f"//{T1}" in url)
    sent = []
    scope = js_recon._ProbeScope(hosts=frozenset({T1, "api.example.com"}))
    endpoints = [{"full_url": f"http://{T1}/api", "method": "GET"},
                 {"full_url": "http://api.example.com/api", "method": "GET"}]
    js_recon._validate_extracted_endpoints(
        endpoints, {"JS_RECON_VALIDATE_ENDPOINTS": True}, scope,
        request_func=lambda method, url, **k: sent.append(url) or mock.Mock(status_code=404))
    assert endpoints[1]["validation_error"] == "not_admitted"
    assert "http://api.example.com/api" not in sent


def test_js_downloads_and_source_maps_get_the_run_rule(monkeypatch):
    from recon.main_recon_modules import js_recon
    seen = {}

    def fetch(method, url, **kwargs):
        seen["download"] = kwargs["admit"]
        return None

    monkeypatch.setattr(js_recon, "fetch_hop_by_hop", fetch)
    rule = lambda url: False  # noqa: E731
    monkeypatch.setattr(js_recon, "_ADMIT", rule)
    js_recon._safe_redirect_get(f"http://{T1}/a.js", timeout=1, headers={})
    assert seen["download"] is rule

    def maps(*_a, **kwargs):
        seen["maps"] = kwargs["admit"]
        return []

    monkeypatch.setattr(js_recon, "discover_and_analyze_sourcemaps", maps)
    js_recon._run_analysis([], {"JS_RECON_SOURCE_MAPS": True, "JS_RECON_TIMEOUT": 5,
                                "JS_RECON_REGEX_PATTERNS": False, "JS_RECON_EXTRACT_ENDPOINTS": False,
                                "JS_RECON_DEPENDENCY_CHECK": False, "JS_RECON_FRAMEWORK_DETECT": False,
                                "JS_RECON_DOM_SINKS": False, "JS_RECON_DEV_COMMENTS": False})
    assert seen["maps"] is rule


def test_js_run_rule_is_admit_any_outside_ip_mode_and_the_target_check_inside():
    from recon.helpers.js_recon.hop_guard import admit_any
    from recon.main_recon_modules import js_recon
    assert js_recon._ADMIT is admit_any
    with mock.patch.object(js_recon, "_collect_js_urls", side_effect=AssertionError("stop")):
        captured = {}
        real = js_recon.ip_mode_url_admission

        def spy(recon, **kw):
            captured["rule"] = real(recon, **kw)
            return captured["rule"]

        with mock.patch.object(js_recon, "ip_mode_url_admission", side_effect=spy):
            js_recon.run_js_recon({"metadata": {"ip_mode": False}}, {"JS_RECON_ENABLED": True})
            assert captured["rule"] is None
            js_recon.run_js_recon(_ip_recon(), {"JS_RECON_ENABLED": True})
            assert captured["rule"](f"http://{T1}/") is True
            assert captured["rule"](f"http://{FOREIGN}/") is False
    assert js_recon._ADMIT is admit_any


def test_js_run_rule_fails_closed_when_the_check_cannot_be_built(monkeypatch, capsys):
    from recon.main_recon_modules import js_recon
    seen = {}

    def collect(*_a, **_k):
        seen["rule"] = js_recon._ADMIT
        raise AssertionError("stop")

    monkeypatch.setattr(js_recon, "_collect_js_urls", collect)
    monkeypatch.setattr(js_recon, "ip_mode_url_admission", mock.Mock(side_effect=ImportError("x")))
    js_recon.run_js_recon(_ip_recon(), {"JS_RECON_ENABLED": True})
    assert seen["rule"] is js_recon._admit_none and seen["rule"](f"http://{T1}/") is False
    assert "[!][JsRecon] Target check unavailable (ImportError)" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Banner grab: one connection per address and port in IP mode
# ---------------------------------------------------------------------------

def _banner_recon(ip_mode):
    by_host = {
        NAME: {"host": NAME, "ip": T1, "ports": [22], "port_details": [{"port": 22}]},
        T1: {"host": T1, "ip": T1, "ports": [22], "port_details": [{"port": 22}]},
        T2: {"host": T2, "ip": T2, "ports": [22, 443], "port_details": [{"port": 22}]},
    }
    recon = _ip_recon(names={NAME: [T1]}) if ip_mode else {"metadata": {"ip_mode": False}}
    recon["port_scan"] = {"by_host": by_host}
    return recon


def _grab(recon):
    from recon.main_recon_modules import http_probe
    grabbed = []

    def grab(target, *_a, **_k):
        grabbed.append(target)
        address, port, host = target
        return {"host": host, "ip": address if address != host else None, "port": port,
                "banner": f"SSH-2.0-{address}", "service": "ssh", "version": "OpenSSH"}

    with mock.patch.object(http_probe, "grab_banner_for_target", side_effect=grab):
        http_probe.run_banner_grab(recon, {"BANNER_GRAB_THREADS": 1})
    return sorted(grabbed)


def test_ip_mode_grabs_each_address_port_once_and_the_name_takes_its_banner():
    recon = _banner_recon(ip_mode=True)
    assert _grab(recon) == [(T1, 22, T1), (T2, 22, T2)]
    details = recon["port_scan"]["by_host"][NAME]["port_details"][0]
    assert details["banner"] == f"SSH-2.0-{T1}"


def test_ip_mode_keeps_the_address_entry_whatever_the_order():
    from recon.main_recon_modules.http_probe import _one_grab_per_address
    assert _one_grab_per_address([(T1, 22, NAME), (T1, 22, T1), (V6, 22, "x.example.com"),
                                  ("2001:DB8::1", 22, "2001:DB8::1")]) == [
        (T1, 22, T1), ("2001:DB8::1", 22, "2001:DB8::1")]
    # Two names on one address and no address entry: the first name is kept.
    assert _one_grab_per_address([(T1, 22, NAME), (T1, 22, "b.example.com")]) == [(T1, 22, NAME)]


def test_domain_mode_banner_grab_is_unchanged():
    recon = _banner_recon(ip_mode=False)
    assert _grab(recon) == [(T1, 22, T1), (T1, 22, NAME), (T2, 22, T2)]
    details = recon["port_scan"]["by_host"][NAME]["port_details"][0]
    assert details["banner"] == f"SSH-2.0-{T1}"


# ---------------------------------------------------------------------------
# Subdomain takeover's Nuclei layer
# ---------------------------------------------------------------------------

def _takeover_cmd(tmp_path, settings):
    from recon.main_recon_modules import subdomain_takeover as st
    sent = []

    def run(cmd, *_a, **_k):
        sent.append(list(cmd))
        return mock.Mock(returncode=0, stdout="", stderr="")

    with mock.patch.object(st, "is_docker_installed", return_value=True), \
            mock.patch.object(st, "is_docker_running", return_value=True), \
            mock.patch.object(st, "pull_nuclei_docker_image", return_value=True), \
            mock.patch.object(st, "ensure_templates_volume", return_value=True), \
            mock.patch("helpers.proxy_routing.get_capture_routing", return_value=(None, None)), \
            mock.patch.object(st.subprocess, "run", side_effect=run):
        st._run_nuclei_takeover([f"https://{T1}"], tmp_path, dict(settings, NUCLEI_FOLLOW_REDIRECTS=True))
    return [a for a in sent[0] if not a.startswith("redamon-nuclei-takeover-")]


def test_ip_mode_takeover_nuclei_follows_same_host_redirects_only(tmp_path):
    cmd = _takeover_cmd(tmp_path, {"IP_MODE": True})
    assert "-follow-host-redirects" in cmd and "-follow-redirects" not in cmd


def test_domain_mode_takeover_nuclei_command_is_unchanged(tmp_path):
    from recon.helpers.nuclei_helpers import build_nuclei_command
    cmd = _takeover_cmd(tmp_path, {"IP_MODE": False})
    assert "-follow-redirects" in cmd and "-follow-host-redirects" not in cmd
    assert cmd == _takeover_cmd(tmp_path, {})
    with mock.patch("helpers.proxy_routing.get_capture_routing", return_value=(None, None)):
        expected = build_nuclei_command(
            targets_file=str(tmp_path / "nuclei_takeover_targets.txt"),
            output_file=str(tmp_path / "nuclei_takeover_output.jsonl"),
            docker_image="projectdiscovery/nuclei:latest", severity=["critical", "high", "medium"],
            templates=["http/takeovers/", "dns/"], rate_limit=50, bulk_size=25, concurrency=25,
            timeout=10, retries=1, exclude_tags=[], system_resolvers=True, follow_redirects=True,
            max_redirects=10, interactsh=False, container_name="c", max_host_error=30)
    assert cmd == [a for a in expected if a != "c"]
