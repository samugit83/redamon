"""naabu is handed every DNS address of every name, so port_coverage may count them scanned.

The Shodan port check (recon/helpers/port_coverage.py) calls a passive port
"closed" when this run's port scan looked at that exact IP and port and did not
find it open. It takes the looked-at IPs from extract_targets_from_recon: every
A/AAAA address of every name. naabu, given only a hostname, probes the name's
first address (RedAmon never passes -scan-all-ips), so that is right only while
run_port_scan also writes each address to naabu's target list as its own line.

The scan targets are read from the file naabu is given (subprocess mocked);
no Docker, no network.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest import mock

_RECON = Path(__file__).resolve().parent.parent
_REPO = _RECON.parent
for _p in (str(_REPO), str(_RECON)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from recon.helpers.port_coverage import port_scan_coverage  # noqa: E402
from recon.main_recon_modules import port_scan as ps  # noqa: E402

APEX = "example.test"
WWW = "www.example.test"
API = "api.example.test"
APEX_IPS = ["192.0.2.10", "192.0.2.11"]
WWW_IPS = ["192.0.2.11", "192.0.2.12", "192.0.2.13"]
API_V6 = ["2001:db8::20"]


def _recon() -> dict:
    return {
        "domain": APEX,
        "metadata": {"include_root_domain": True},
        "dns": {
            "domain": {"ips": {"ipv4": list(APEX_IPS), "ipv6": []}, "has_records": True},
            "subdomains": {
                WWW: {"ips": {"ipv4": list(WWW_IPS), "ipv6": []}, "has_records": True},
                API: {"ips": {"ipv4": [], "ipv6": list(API_V6)}, "has_records": True},
            },
        },
    }


class _FakeNaabu:
    """Popen stand-in: records the command and the targets file it was given,
    and reports 443 open on the first address only."""

    def __init__(self):
        self.cmd = None
        self.targets = None

    def __call__(self, cmd, **_kw):
        self.cmd = list(cmd)
        mounts = {}
        for i, tok in enumerate(cmd):
            if tok == "-v":
                host, container = cmd[i + 1].split(":")[:2]
                mounts[container] = host
        targets = Path(mounts["/targets"]) / Path(cmd[cmd.index("-list") + 1]).name
        output = Path(mounts["/output"]) / Path(cmd[cmd.index("-o") + 1]).name
        self.targets = targets.read_text().split()
        output.write_text(json.dumps({"ip": APEX_IPS[0], "port": 443, "protocol": "tcp"}) + "\n")
        proc = mock.MagicMock()
        proc.communicate.return_value = ("", "")
        proc.returncode = 0
        return proc


def _scan(recon: dict) -> tuple[dict, _FakeNaabu]:
    fake = _FakeNaabu()
    with mock.patch.object(ps, "is_docker_installed", return_value=True), \
            mock.patch.object(ps, "is_docker_running", return_value=True), \
            mock.patch.object(ps, "pull_naabu_docker_image", return_value=True), \
            mock.patch.object(ps.subprocess, "Popen", side_effect=fake):
        out = ps.run_port_scan(recon, output_file=None,
                               settings={"NAABU_SCAN_TYPE": "c", "NAABU_CUSTOM_PORTS": "443,8443"})
    return out, fake


def test_every_address_of_a_multi_a_name_is_its_own_naabu_target():
    _, fake = _scan(_recon())
    assert fake.targets is not None, "naabu was never run"
    for ip in APEX_IPS + WWW_IPS + API_V6:
        assert ip in fake.targets, f"{ip} reaches naabu only through a hostname: {fake.targets}"
    for name in (APEX, WWW, API):
        assert name in fake.targets
    assert len(fake.targets) == len(set(fake.targets))
    assert "-scan-all-ips" not in fake.cmd


def test_coverage_counts_scanned_exactly_the_addresses_naabu_was_given():
    out, fake = _scan(_recon())
    ips_on_the_list = {t for t in fake.targets if t[0].isdigit() or ":" in t}
    covers = port_scan_coverage(out, {})
    for ip in APEX_IPS + WWW_IPS + API_V6:
        assert ip in ips_on_the_list
        expected = True if ip == APEX_IPS[0] else False
        assert covers(ip, 443) is expected, ip
    # A port outside the scanned list stays unknown, never closed.
    assert covers(WWW_IPS[2], 22) is None
    # An address no name resolves to was never a target.
    assert covers("192.0.2.99", 443) is None
