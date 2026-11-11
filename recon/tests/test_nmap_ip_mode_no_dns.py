"""nmap sends no PTR query in IP mode (P3 fix 3, invariant I-7).

Without -n nmap reverse-resolves every target that answers, so an IP-only run
(which must ask nothing about names) still sent one PTR query per live
address. nmap's own hostnames are not parsed, so -n loses nothing. Domain mode
keeps its exact command.
"""
from __future__ import annotations

import pytest

from recon.main_recon_modules.nmap_scan import build_nmap_command

BASE = {"NMAP_VERSION_DETECTION": True, "NMAP_SCRIPT_SCAN": True, "NMAP_TIMING_TEMPLATE": "T3",
        "NMAP_HOST_TIMEOUT": 300}


@pytest.mark.parametrize("target", ["203.0.113.10", "2001:db8::10"])
@pytest.mark.parametrize("mode", ["ip_only", "record_only", "record_filter", "scan_all"])
def test_ip_mode_asks_no_reverse_dns(target, mode):
    cmd = build_nmap_command(target, "22,443", "/tmp/o.xml",
                             dict(BASE, IP_MODE=True, IP_HOSTNAME_MODE=mode))
    assert cmd.count("-n") == 1
    assert cmd[-1] == target
    assert cmd.index("-n") < len(cmd) - 1


@pytest.mark.parametrize("settings", [dict(BASE), dict(BASE, IP_MODE=False)])
def test_domain_mode_command_is_unchanged(settings):
    assert build_nmap_command("203.0.113.10", "22,443", "/tmp/o.xml", settings) == [
        "nmap", "-sV", "--script", "vuln", "-oX", "/tmp/o.xml", "-p", "22,443",
        "-T3", "--host-timeout", "300s", "203.0.113.10"]
