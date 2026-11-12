"""No tool follows a redirect into a host the Rules of Engagement exclude (R-2).

The target lists are admitted (target_admission), but a redirect is not: an
admitted host whose root answers 302 to an excluded one had that host
requested by every tool that follows redirects inside its own client. Seen on
the nested lab (domain mode, 192.88.99.62/32 excluded, a bare-IP root 302ing to
a name on .62): Nuclei (about 2,700 requests), httpx (the excluded page stored
as the admitted URL's title), nmap's NSE http scripts and Arjun all reached .62.

So under RoE exclusions each tool keeps its redirects on the host it was given,
the way IP mode already does (B-05, B-07). With no exclusion in force every argv
is the one built before; the byte-for-byte domain-mode pins live in
test_regression_ip_mode_scope_leaks.py.

Only Docker, the tool processes and the file system's temp paths are faked; the
real runners and command builders run. Reserved names and RFC 5737 addresses.
"""
from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

_RECON = Path(__file__).resolve().parent.parent
_REPO = _RECON.parent
for _p in (str(_REPO), str(_RECON)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from recon.helpers import circuit_breaker  # noqa: E402

ADMITTED_IP = "203.0.113.63"
EXCLUDED_IP = "198.51.100.62"
WWW, EDGE = "www.example.com", "edge.example.com"

#: Every way an exclusion is written: an address, a range, a name.
EXCLUSIONS = [f"{EXCLUDED_IP}/32", "198.51.100.0/24", EXCLUDED_IP, EDGE]

#: Settings with no exclusion in force: RoE on with nothing listed, entries
#: listed with RoE off, or no RoE keys at all.
INACTIVE = [
    {},
    {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": []},
    {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": ["", "  "]},
    {"ROE_ENABLED": False, "ROE_EXCLUDED_HOSTS": [EXCLUDED_IP, EDGE]},
]

#: A domain run: www resolves to an admitted address, edge to the excluded
#: one; httpx found the admitted bare IP (its root 302s to edge) and www.
DOMAIN_RECON = {
    "domain": "example.com",
    "metadata": {"ip_mode": False, "root_domain": "example.com", "scope_mode": "enumerate",
                 "include_root_domain": True, "filtered_mode": False},
    "dns": {"domain": {"has_records": True, "ips": {"ipv4": ["203.0.113.10"], "ipv6": []}},
            "subdomains": {
                WWW: {"has_records": True, "ips": {"ipv4": ["203.0.113.11"], "ipv6": []}},
                EDGE: {"has_records": True, "ips": {"ipv4": [EXCLUDED_IP], "ipv6": []}}}},
    "port_scan": {"by_host": {WWW: {
        "host": WWW, "ip": "203.0.113.11", "ports": [443],
        "port_details": [{"port": 443, "protocol": "tcp", "service": "https"}]}},
        "by_ip": {ADMITTED_IP: {"ports": [80], "hostnames": []}}, "all_ports": [80, 443]},
    "http_probe": {"by_url": {
        f"https://{WWW}": {"url": f"https://{WWW}", "status_code": 200},
        f"http://{ADMITTED_IP}": {"url": f"http://{ADMITTED_IP}", "status_code": 302}}},
    "resource_enum": {"discovered_urls": [f"https://{WWW}/search?q=1"],
                      "by_base_url": {}},
}


def _roe(*entries) -> dict:
    return {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": list(entries)}


class _Stop(Exception):
    """Raised once the commands under test are captured."""


@pytest.fixture(autouse=True)
def _fresh_run():
    circuit_breaker.reset_registry()
    yield
    circuit_breaker.reset_registry()


# --------------------------------------------------------------------------
# Nuclei: run_vuln_scan's detection and DAST passes, and the takeover layer
# --------------------------------------------------------------------------

def _nuclei_passes(monkeypatch, settings: dict, recon_data: dict = None) -> dict:
    """run_vuln_scan up to the DAST pass; returns {label: (argv, kwargs)}."""
    from recon.main_recon_modules import vuln_scan
    seen = {}
    real_build = vuln_scan.build_nuclei_command

    def build(*args, **kwargs):
        cmd = real_build(*args, **kwargs)
        seen["DAST" if kwargs.get("force_dast_pass") else "DETECTION"] = (cmd, kwargs)
        return cmd

    def execute(cmd, output_file, label, **_k):
        if label == "DAST":
            raise _Stop
        return [], [], 0, 0

    monkeypatch.setattr(vuln_scan, "build_nuclei_command", build)
    monkeypatch.setattr(vuln_scan, "_execute_nuclei_pass", execute)
    monkeypatch.setattr(vuln_scan, "is_docker_installed", lambda: True)
    monkeypatch.setattr(vuln_scan, "is_docker_running", lambda: True)
    monkeypatch.setattr(vuln_scan, "pull_nuclei_docker_image", lambda *_a, **_k: True)
    monkeypatch.setattr(vuln_scan, "ensure_templates_volume", lambda *_a, **_k: True)
    monkeypatch.setattr("helpers.proxy_routing.get_capture_routing", lambda *_a, **_k: (None, None))
    with pytest.raises(_Stop):
        vuln_scan.run_vuln_scan(copy.deepcopy(recon_data or DOMAIN_RECON), output_file=None,
                                settings=dict(settings, CVE_LOOKUP_ENABLED=False,
                                              SECURITY_CHECK_ENABLED=False,
                                              NUCLEI_DAST_MODE=True))
    return seen


def _redirect_flags(cmd: list) -> list:
    return [a for a in cmd if a in ("-follow-redirects", "-follow-host-redirects")]


@pytest.mark.parametrize("entry", EXCLUSIONS)
def test_nuclei_follows_same_host_redirects_only_under_roe_exclusions(monkeypatch, entry):
    seen = _nuclei_passes(monkeypatch, _roe(entry))
    assert set(seen) == {"DETECTION", "DAST"}
    for label, (cmd, _kwargs) in seen.items():
        assert _redirect_flags(cmd) == ["-follow-host-redirects"], label
        assert cmd[cmd.index("-follow-host-redirects") + 1:][:2] == ["-max-redirects", "10"], label


@pytest.mark.parametrize("settings", INACTIVE)
def test_nuclei_follows_every_redirect_without_an_exclusion(monkeypatch, settings):
    seen = _nuclei_passes(monkeypatch, settings)
    for label, (cmd, _kwargs) in seen.items():
        assert _redirect_flags(cmd) == ["-follow-redirects"], label


def test_nuclei_partial_run_reads_the_exclusions_from_the_recon_dict(monkeypatch):
    """A partial builder stamps the RoE into metadata.roe; its settings may
    carry no RoE keys at all."""
    recon = copy.deepcopy(DOMAIN_RECON)
    recon["metadata"]["roe"] = _roe(f"{EXCLUDED_IP}/32")
    seen = _nuclei_passes(monkeypatch, {}, recon)
    for label, (cmd, _kwargs) in seen.items():
        assert _redirect_flags(cmd) == ["-follow-host-redirects"], label


def test_nuclei_without_redirects_stays_without_them(monkeypatch):
    seen = _nuclei_passes(monkeypatch, dict(_roe(EXCLUDED_IP), NUCLEI_FOLLOW_REDIRECTS=False))
    for label, (cmd, _kwargs) in seen.items():
        assert _redirect_flags(cmd) == [] and "-max-redirects" not in cmd, label


def test_nuclei_ip_mode_argv_is_unchanged_by_exclusions():
    from recon.helpers.nuclei_helpers import build_nuclei_command
    common = dict(targets_file="/tmp/redamon/t/targets.txt", output_file="/tmp/redamon/t/o.jsonl",
                  docker_image="projectdiscovery/nuclei:latest", follow_redirects=True,
                  max_redirects=10, ip_mode=True)
    assert (build_nuclei_command(**common, roe_exclusions=True)
            == build_nuclei_command(**common))


def _takeover_cmd(monkeypatch, tmp_path, settings: dict) -> list:
    from recon.main_recon_modules import subdomain_takeover as st
    seen = {}

    def run(cmd, **_k):
        seen["cmd"] = cmd
        raise _Stop

    monkeypatch.setattr(st, "is_docker_installed", lambda: True)
    monkeypatch.setattr(st, "is_docker_running", lambda: True)
    monkeypatch.setattr(st, "pull_nuclei_docker_image", lambda *_a, **_k: True)
    monkeypatch.setattr(st, "ensure_templates_volume", lambda *_a, **_k: True)
    monkeypatch.setattr(st, "run_tool_container", run)
    with pytest.raises(_Stop):
        st._run_nuclei_takeover([f"http://{ADMITTED_IP}"], tmp_path, dict(settings))
    return seen["cmd"]


def test_takeover_nuclei_follows_same_host_redirects_only_under_roe_exclusions(monkeypatch, tmp_path):
    assert _redirect_flags(_takeover_cmd(monkeypatch, tmp_path, _roe(EDGE))) == [
        "-follow-host-redirects"]


@pytest.mark.parametrize("settings", INACTIVE)
def test_takeover_nuclei_unchanged_without_an_exclusion(monkeypatch, tmp_path, settings):
    assert _redirect_flags(_takeover_cmd(monkeypatch, tmp_path, settings)) == ["-follow-redirects"]


# --------------------------------------------------------------------------
# httpx: run_http_probe's command, and what it stores for an unfollowed 302
# --------------------------------------------------------------------------

def _httpx(monkeypatch, settings: dict, recon_data: dict = None) -> dict:
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
    monkeypatch.setattr(http_probe, "system_resolvers", lambda: ["192.0.2.53"])
    try:
        http_probe.run_http_probe(copy.deepcopy(recon_data or DOMAIN_RECON), settings=dict(settings))
    except _Stop:
        pass
    assert "cmd" in seen, "run_http_probe never built the httpx command"
    return seen


@pytest.mark.parametrize("entry", EXCLUSIONS)
def test_httpx_follows_same_host_redirects_only_under_roe_exclusions(monkeypatch, entry):
    seen = _httpx(monkeypatch, _roe(entry))
    cmd = seen["cmd"]
    assert "-fhr" in cmd and "-fr" not in cmd
    assert cmd[cmd.index("-fhr") + 1:][:2] == ["-maxr", "10"]
    # -tls-probe requests every name the certificate lists, an excluded one
    # included; -tls-grab reads the certificate of the connection httpx made.
    assert "-tls-probe" not in cmd and "-tls-grab" in cmd
    assert seen["urls"] == [f"https://{WWW}"]


@pytest.mark.parametrize("settings", INACTIVE)
def test_httpx_command_unchanged_without_an_exclusion(monkeypatch, settings):
    cmd = _httpx(monkeypatch, settings)["cmd"]
    assert "-fr" in cmd and "-fhr" not in cmd
    assert "-tls-probe" in cmd


def test_httpx_partial_run_reads_the_exclusions_from_the_recon_dict(monkeypatch):
    recon = copy.deepcopy(DOMAIN_RECON)
    recon["metadata"]["roe"] = _roe(f"{EXCLUDED_IP}/32")
    cmd = _httpx(monkeypatch, {}, recon)["cmd"]
    assert "-fhr" in cmd and "-fr" not in cmd and "-tls-probe" not in cmd


def test_httpx_without_redirects_stays_without_them(monkeypatch):
    cmd = _httpx(monkeypatch, dict(_roe(EXCLUDED_IP), HTTPX_FOLLOW_REDIRECTS=False))["cmd"]
    assert not {"-fr", "-fhr", "-maxr"} & set(cmd)


def test_httpx_ip_mode_argv_is_unchanged_by_exclusions():
    from recon.main_recon_modules.http_probe import build_httpx_command
    paths = ("/tmp/redamon/t/targets.txt", "/tmp/redamon/t/out.json")
    assert (build_httpx_command(*paths, dict(_roe(EXCLUDED_IP), IP_MODE=True))
            == build_httpx_command(*paths, {"IP_MODE": True}))


def test_httpx_builder_reads_the_exclusions_from_its_settings():
    from recon.main_recon_modules.http_probe import build_httpx_command
    cmd = build_httpx_command("/tmp/redamon/t/targets.txt", "/tmp/redamon/t/out.json", _roe(EDGE))
    assert "-fhr" in cmd and "-tls-probe" not in cmd


def test_the_admitted_hosts_own_302_is_what_is_stored(tmp_path):
    """The JSON httpx 1.x writes with -fhr for a 302 to another host (run
    against two loopback servers): the 302 itself, no final_url, no page. The
    probed URL keeps its own answer; nothing of the other host's page is
    stored on it. With -fr the same probe reported status 200, the other host
    as final_url and its title."""
    from recon.main_recon_modules.http_probe import parse_httpx_output
    out = tmp_path / "httpx.json"
    out.write_text(
        '{"url": "http://203.0.113.63", "input": "http://203.0.113.63", "status_code": 302,'
        ' "location": "http://edge.example.com/", "host": "203.0.113.63", "webserver": "nginx"}\n')
    by_url = parse_httpx_output(str(out), root_domain="example.com",
                                run_addresses=(ADMITTED_IP,))["by_url"]
    entry = by_url[f"http://{ADMITTED_IP}"]
    assert entry["status_code"] == 302 and entry["first_status_code"] == 302
    assert entry["final_url"] == f"http://{ADMITTED_IP}"
    assert entry["redirected_off_host"] is False
    assert entry["title"] is None


# --------------------------------------------------------------------------
# nmap: the NSE scripts run_nmap_scan asks for, and -n
# --------------------------------------------------------------------------

_EMPTY_NMAP_XML = '<?xml version="1.0"?><nmaprun scanner="nmap" version="7.93"></nmaprun>'


class _NmapProc:
    returncode = 0

    def communicate(self, timeout=None):
        return "", ""


def _nmap_cmds(monkeypatch, settings: dict, recon_data: dict = None) -> list:
    from recon.main_recon_modules import nmap_scan
    cmds = []

    def popen(cmd, **_k):
        cmds.append(cmd)
        Path(cmd[cmd.index("-oX") + 1]).write_text(_EMPTY_NMAP_XML)
        return _NmapProc()

    monkeypatch.setattr(nmap_scan, "is_nmap_installed", lambda: True)
    monkeypatch.setattr(nmap_scan.subprocess, "Popen", popen)
    nmap_scan.run_nmap_scan(copy.deepcopy(recon_data or DOMAIN_RECON),
                            settings=dict(settings, NMAP_PARALLELISM=1))
    assert cmds, "run_nmap_scan never started nmap"
    return cmds


def _script(cmd: list):
    return cmd[cmd.index("--script") + 1] if "--script" in cmd else None


@pytest.mark.parametrize("entry", EXCLUSIONS)
def test_nse_stays_on_the_address_under_roe_exclusions(monkeypatch, capsys, entry):
    """Proved on the recon image's nmap 7.93 (a loopback target whose PTR is
    a.<lab> answering 302 to b.<lab>): http.lua's default rule follows a
    redirect to any host in the PTR name's domain, --exclude does not bind
    NSE, and -n (no name: same-IP redirects only) stops it for every vuln
    script but http-cross-domain-policy, whose own redirect_ok follows any
    host."""
    cmds = _nmap_cmds(monkeypatch, _roe(entry))
    for cmd in cmds:
        assert _script(cmd) == "vuln and not http-cross-domain-policy"
        assert cmd.count("-n") == 1 and cmd.index("-n") < len(cmd) - 1
    assert sorted(cmd[-1] for cmd in cmds) == ["203.0.113.11", ADMITTED_IP]
    assert "[*][Nmap] NSE redirects kept on the target address" in capsys.readouterr().out


@pytest.mark.parametrize("settings", INACTIVE)
def test_nmap_command_unchanged_without_an_exclusion(monkeypatch, settings):
    from recon.main_recon_modules.nmap_scan import build_nmap_command
    for cmd in _nmap_cmds(monkeypatch, settings):
        assert _script(cmd) == "vuln" and "-n" not in cmd
        assert cmd == build_nmap_command(cmd[-1], cmd[cmd.index("-p") + 1],
                                         cmd[cmd.index("-oX") + 1], {})


def test_nmap_partial_run_reads_the_exclusions_from_the_recon_dict(monkeypatch):
    recon = copy.deepcopy(DOMAIN_RECON)
    recon["metadata"]["roe"] = _roe(f"{EXCLUDED_IP}/32")
    for cmd in _nmap_cmds(monkeypatch, {}, recon):
        assert _script(cmd) == "vuln and not http-cross-domain-policy" and "-n" in cmd


def test_nmap_without_scripts_still_skips_reverse_dns_under_exclusions(monkeypatch):
    for cmd in _nmap_cmds(monkeypatch, dict(_roe(EDGE), NMAP_SCRIPT_SCAN=False)):
        assert "--script" not in cmd and cmd.count("-n") == 1


def test_nmap_ip_mode_argv_is_unchanged_by_exclusions():
    from recon.main_recon_modules.nmap_scan import build_nmap_command
    settings = {"IP_MODE": True, "NMAP_TIMING_TEMPLATE": "T3", "NMAP_HOST_TIMEOUT": 300}
    assert (build_nmap_command(ADMITTED_IP, "80", "/tmp/o.xml", settings, roe_exclusions=True)
            == build_nmap_command(ADMITTED_IP, "80", "/tmp/o.xml", settings))
