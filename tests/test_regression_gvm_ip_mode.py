"""Characterisation test: GVM's targets in an IP-mode project (B-01 / B-26 of
the IP-mode plan, decision D-15: IP mode scans the expanded target IPs only).

GVM reads the recon file (recon_<pid>.json), not the graph, and takes every
dns.subdomains entry with records plus its addresses. In IP mode that is the
dashed placeholders, the PTR names, and the PTR names' forward addresses, which
need not be targets at all. The recon dict below is what run_ip_recon's GROUP 1
writes today for two listed targets, 203.0.113.1 (PTR www.example.com, whose A
record is 198.51.100.7) and 203.0.113.2 (no PTR).

The recon-side half of the same sweep (naabu, nmap, tlsx, banner grab, vhost,
IP attribution, OSINT, security checks) is
recon/tests/test_regression_ip_mode_scope_leaks.py.
Only documentation addresses (RFC 5737) and reserved names are used.
"""
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "scanners"))

from gvm_scan import gvm_scanner as gvm_mod  # noqa: E402

ROOT = "ip-targets.cmipmodeleak0000000000004"
TARGETS = ["203.0.113.1", "203.0.113.2"]

IP_MODE_RECON = {
    "domain": ROOT,
    "metadata": {
        "ip_mode": True, "target": ROOT, "root_domain": ROOT, "org_domain": ROOT,
        "target_ips": list(TARGETS), "expanded_ips": list(TARGETS), "original_cidrs": [],
        "ip_to_hostname": {"203.0.113.1": "www.example.com", "203.0.113.2": "203-0-113-2"},
        "scope_mode": "exact", "include_root_domain": False, "filtered_mode": True,
        "subdomain_filter": ["203.0.113.1", "203.0.113.2", "www.example.com", "203-0-113-2"],
    },
    "subdomains": ["www.example.com", "203-0-113-2"],
    "dns": {
        "domain": {},
        "subdomains": {
            "www.example.com": {"has_records": True, "records": {"A": ["198.51.100.7"]},
                                "ips": {"ipv4": ["198.51.100.7"], "ipv6": []}},
            "203-0-113-2": {"has_records": True, "records": {}, "is_mock": True,
                            "actual_ip": "203.0.113.2",
                            "ips": {"ipv4": ["203.0.113.2"], "ipv6": []}},
        },
    },
}


@pytest.mark.xfail(strict=True, raises=AssertionError,
                   reason="B-26: IP-mode GVM scans placeholders, PTR names and their forward (foreign) addresses")
def test_gvm_ip_mode_targets_are_expanded_ips_only():
    ips, hostnames = gvm_mod.extract_targets_from_recon(IP_MODE_RECON)

    assert sorted(ips) == TARGETS
    assert hostnames == set()
