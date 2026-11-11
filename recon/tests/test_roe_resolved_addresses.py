"""RoE IP and CIDR exclusions apply to the addresses names resolve to (R-2).

An exclusion such as `198.51.100.0/24` matched only a host that was itself an
IP, so a name resolving into the range was port-scanned, probed and
Nuclei-scanned. The naabu, masscan and nmap target builders and the shared DNS
extractor now pass their lists through the admission gate
(recon/helpers/target_admission.py): the excluded address is
never a target, a name left with no address is dropped, a name with one
excluded address is reached only on its others, and a name with no known
address is refused while IP entries exist.

Each test reads what the tool would really be handed: the target file naabu
and masscan are given (subprocess mocked), the IPs nmap builds a command for,
and the hosts and URLs the shared DNS extractor hands Nuclei and the crawlers
(given the settings, or the RoE a partial builder stamps). With no RoE
exclusion every list is byte-identical to the one built without RoE keys at
all.
Reserved names and documentation ranges only; no Docker, no network.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest import mock

import pytest

_RECON = Path(__file__).resolve().parent.parent
_REPO = _RECON.parent
for _p in (str(_REPO), str(_RECON)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from recon.helpers import circuit_breaker  # noqa: E402
from recon.helpers.target_helpers import build_target_urls, extract_targets_from_recon  # noqa: E402
from recon.main_recon_modules import masscan_scan as ms  # noqa: E402
from recon.main_recon_modules import nmap_scan as nm  # noqa: E402
from recon.main_recon_modules import port_scan as ps  # noqa: E402

APEX = "example.com"
EXCLUDED_RANGE = "198.51.100.0/24"
LEGACY, LEGACY_IP = "legacy.example.com", "198.51.100.20"          # only an excluded address
MIXED, MIXED_BAD, MIXED_OK = "mixed.example.com", "198.51.100.21", "192.0.2.7"
WWW, WWW_IP = "www.example.com", "192.0.2.6"
TXT = "txt.example.com"                                             # records, no address
APEX_IP = "192.0.2.1"

NO_ROE = [
    {},
    {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": []},
    {"ROE_ENABLED": False, "ROE_EXCLUDED_HOSTS": [EXCLUDED_RANGE, WWW]},
]


def _roe(*entries):
    return {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": list(entries)}


def _sub(*ips):
    v4 = [i for i in ips if ":" not in i]
    return {"has_records": True, "ips": {"ipv4": v4, "ipv6": [i for i in ips if ":" in i]}}


def _recon() -> dict:
    return {
        "domain": APEX,
        "metadata": {"include_root_domain": True},
        "dns": {
            "domain": {"ips": {"ipv4": [APEX_IP], "ipv6": []}, "has_records": True},
            "subdomains": {
                LEGACY: _sub(LEGACY_IP),
                MIXED: _sub(MIXED_BAD, MIXED_OK),
                WWW: _sub(WWW_IP),
                TXT: _sub(),
            },
        },
    }


@pytest.fixture(autouse=True)
def _fresh_run():
    circuit_breaker.reset_registry()
    yield
    circuit_breaker.reset_registry()


def _gap_modules():
    return {g["module"] for g in circuit_breaker.coverage_report().gaps if g["source"] == "roe_excluded"}


# --------------------------------------------------------------------------
# naabu
# --------------------------------------------------------------------------

class _FakeNaabu:
    def __init__(self, open_ip=MIXED_OK):
        self.targets = None
        self.open_ip = open_ip

    def __call__(self, cmd, **_kw):
        mounts = {}
        for i, tok in enumerate(cmd):
            if tok == "-v":
                host, container = cmd[i + 1].split(":")[:2]
                mounts[container] = host
        targets = Path(mounts["/targets"]) / Path(cmd[cmd.index("-list") + 1]).name
        output = Path(mounts["/output"]) / Path(cmd[cmd.index("-o") + 1]).name
        self.targets = targets.read_text()
        output.write_text(json.dumps({"ip": self.open_ip, "port": 443, "protocol": "tcp"}) + "\n")
        proc = mock.MagicMock()
        proc.communicate.return_value = ("", "")
        proc.returncode = 0
        return proc


def _naabu(settings, recon=None):
    fake = _FakeNaabu()
    with mock.patch.object(ps, "is_docker_installed", return_value=True), \
            mock.patch.object(ps, "is_docker_running", return_value=True), \
            mock.patch.object(ps, "pull_naabu_docker_image", return_value=True), \
            mock.patch.object(ps.subprocess, "Popen", side_effect=fake):
        out = ps.run_port_scan(recon or _recon(), output_file=None,
                               settings={"NAABU_SCAN_TYPE": "c", "NAABU_CUSTOM_PORTS": "443", **settings})
    assert fake.targets is not None, "naabu was never run"
    return out, fake.targets


def test_naabu_never_gets_an_address_in_an_excluded_range():
    out, targets = _naabu(_roe(EXCLUDED_RANGE))
    lines = targets.split()
    assert LEGACY_IP not in lines and MIXED_BAD not in lines
    assert {APEX_IP, WWW_IP, MIXED_OK} <= set(lines)
    # naabu resolves a name itself, so with IP entries it is handed addresses only.
    assert not [t for t in lines if not t[0].isdigit()]
    # The open port on the allowed address still reaches the name behind it.
    by_host = out["port_scan"]["by_host"]
    assert MIXED in by_host and LEGACY not in by_host
    assert "naabu" in _gap_modules()


def test_naabu_with_host_entries_only_keeps_names():
    _, targets = _naabu(_roe(LEGACY))
    lines = targets.split()
    assert LEGACY not in lines and LEGACY_IP not in lines
    assert {APEX, WWW, MIXED, MIXED_BAD, MIXED_OK} <= set(lines)


@pytest.mark.parametrize("settings", NO_ROE, ids=["no_keys", "empty", "off"])
def test_naabu_targets_are_unchanged_without_an_exclusion(settings):
    _, baseline = _naabu({})
    assert _naabu(settings)[1] == baseline
    assert LEGACY in baseline.split() and LEGACY_IP in baseline.split()


# --------------------------------------------------------------------------
# masscan
# --------------------------------------------------------------------------

def _masscan(settings):
    seen = {}

    def _popen(cmd, **_kw):
        seen["targets"] = Path(cmd[cmd.index("-iL") + 1]).read_text()
        proc = mock.MagicMock()
        proc.communicate.return_value = ("", "")
        proc.returncode = 1
        return proc

    with mock.patch.object(ms, "is_masscan_installed", return_value=True), \
            mock.patch.object(ms.subprocess, "Popen", side_effect=_popen):
        ms.run_masscan_scan(_recon(), output_file=None, settings={"MASSCAN_ENABLED": True, **settings})
    assert "targets" in seen, "masscan was never run"
    return seen["targets"]


def test_masscan_never_gets_an_address_in_an_excluded_range():
    lines = _masscan(_roe(EXCLUDED_RANGE)).split()
    assert sorted(lines) == sorted([APEX_IP, MIXED_OK, WWW_IP])


def test_masscan_drops_the_addresses_of_an_excluded_name():
    lines = _masscan(_roe(LEGACY)).split()
    assert LEGACY_IP not in lines and MIXED_BAD in lines


@pytest.mark.parametrize("settings", NO_ROE, ids=["no_keys", "empty", "off"])
def test_masscan_targets_are_unchanged_without_an_exclusion(settings):
    assert _masscan(settings) == _masscan({})


def test_resolve_targets_to_ips_filters_the_name_map():
    ips, ip_map = ms.resolve_targets_to_ips(_recon(), settings=_roe(EXCLUDED_RANGE))
    assert sorted(ips) == sorted([APEX_IP, MIXED_OK, WWW_IP])
    assert ip_map == {APEX_IP: [APEX], MIXED_OK: [MIXED], WWW_IP: [WWW]}


# --------------------------------------------------------------------------
# nmap
# --------------------------------------------------------------------------

def _port_scanned():
    recon = _recon()
    by_ip = {ip: {"ip": ip, "hostnames": [name], "ports": [443]}
             for ip, name in ((APEX_IP, APEX), (LEGACY_IP, LEGACY), (MIXED_BAD, MIXED),
                              (MIXED_OK, MIXED), (WWW_IP, WWW))}
    by_ip["192.0.2.50"] = {"ip": "192.0.2.50", "hostnames": [], "ports": [22]}
    recon["port_scan"] = {"by_ip": by_ip, "by_host": {}, "ip_to_hostnames": {}}
    return recon


def test_nmap_targets_skip_excluded_addresses():
    ips, ports, ip_map = nm.build_nmap_targets(_port_scanned(), _roe(EXCLUDED_RANGE))
    assert ips == sorted([APEX_IP, MIXED_OK, WWW_IP, "192.0.2.50"])
    assert LEGACY_IP not in ip_map and MIXED_BAD not in ip_map
    assert ip_map[MIXED_OK] == [MIXED]
    assert ports == "22,443"


def test_nmap_builds_no_command_for_an_excluded_address():
    scanned = []

    def _popen(cmd, **_kw):
        scanned.append(cmd[-1])
        proc = mock.MagicMock()
        proc.communicate.return_value = ("", "")
        proc.returncode = 1
        return proc

    with mock.patch.object(nm, "is_nmap_installed", return_value=True), \
            mock.patch.object(nm.subprocess, "Popen", side_effect=_popen):
        nm.run_nmap_scan(_port_scanned(), output_file=None,
                         settings={"NMAP_ENABLED": True, **_roe(EXCLUDED_RANGE)})
    assert scanned and not any(t.startswith("198.51.100.") for t in scanned), scanned


@pytest.mark.parametrize("settings", NO_ROE, ids=["no_keys", "empty", "off"])
def test_nmap_targets_are_unchanged_without_an_exclusion(settings):
    assert nm.build_nmap_targets(_port_scanned(), settings) == nm.build_nmap_targets(_port_scanned(), {})


# --------------------------------------------------------------------------
# Nuclei and the crawlers (shared DNS extraction)
# --------------------------------------------------------------------------

def test_dns_targets_drop_names_a_tool_could_resolve_into_an_exclusion():
    ips, names, ip_map = extract_targets_from_recon(_recon(), settings=_roe(EXCLUDED_RANGE))
    assert names == {APEX, WWW}                       # mixed: by address only; txt: no address
    assert ips == {APEX_IP, WWW_IP, MIXED_OK}
    assert LEGACY_IP not in ip_map and MIXED_BAD not in ip_map
    urls = build_target_urls(names, ips, {}, scan_all_ips=True)
    assert not any(h in u for u in urls for h in (LEGACY, MIXED, TXT, "198.51.100."))
    assert f"http://{MIXED_OK}" in urls


def test_dns_targets_read_the_roe_a_partial_builder_stamps():
    recon = _recon()
    recon["metadata"]["roe"] = _roe(EXCLUDED_RANGE)
    ips, names, _ = extract_targets_from_recon(recon)
    assert LEGACY not in names and LEGACY_IP not in ips


@pytest.mark.parametrize("settings", NO_ROE, ids=["no_keys", "empty", "off"])
def test_dns_targets_are_unchanged_without_an_exclusion(settings):
    assert extract_targets_from_recon(_recon(), settings=settings) == extract_targets_from_recon(_recon())
    assert TXT in extract_targets_from_recon(_recon())[1]
