"""The orchestrator's check of a partial run's typed inputs in an IP-mode
project (B-20 / B-22 of the IP-mode plan).

The job queue and the scan scheduler post partial runs to the orchestrator
directly (webapp/src/lib/startScan.ts), past the modal and the webapp route, so
filter_partial_user_input here is a control, not a convenience: a typed address
must be one of the project's targets (CIDR-aware, IPv6 canonical), and IPs may
be attached only to a target's own placeholder.

The container-side mirror is pinned in
recon/tests/test_regression_partial_ip_mode_leaks.py and
recon/tests/test_partial_ip_mode_scope.py.
Only documentation addresses (RFC 5737, RFC 3849) and reserved names are used.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from batch_scope import filter_partial_user_input  # noqa: E402

ROOT = "ip-targets.cmipmodeleak0000000000003"
PROJECT = {"ipMode": True, "targetIps": ["203.0.113.0/30", "203.0.113.9", "2001:db8::1"]}
FOREIGN = "198.51.100.7"


def test_partial_typed_ip_outside_targets_refused():
    _, targets, refused = filter_partial_user_input(PROJECT, [ROOT], [], {
        "ips": ["203.0.113.1", FOREIGN, "198.51.100.0/30", "203.0.113.9"],
        "urls": ["http://203.0.113.2:8080/", f"http://{FOREIGN}/",
                 "http://[2001:db8:0:0:0:0:0:1]/", "http://203.0.113.9/"],
        "ip_attach_to": "www.example.com",
    })

    assert targets["ips"] == ["203.0.113.1", "203.0.113.9"]
    # 203.0.113.2 is inside 203.0.113.0/30; the IPv6 literal is the target in
    # its uncompressed spelling.
    assert targets["urls"] == ["http://203.0.113.2:8080/", "http://[2001:db8:0:0:0:0:0:1]/",
                               "http://203.0.113.9/"]
    # A PTR name is no target placeholder: IPs typed for it would become a
    # source-less RESOLVES_TO that later partial runs read as forward DNS.
    assert targets["ip_attach_to"] is None
    assert any(FOREIGN in r for r in refused)


def _filter(user_targets, project=PROJECT):
    return filter_partial_user_input(project, [ROOT], [], user_targets)


def test_a_typed_cidr_keeps_its_target_hosts_only():
    _, targets, refused = _filter({"ips": ["203.0.113.0/30", "203.0.113.0/29", "198.51.100.0/30"]})
    # Kept whole when wholly inside; else its target hosts, as the container does.
    assert targets["ips"] == ["203.0.113.0/30", "203.0.113.1", "203.0.113.2"]
    assert len(refused) == 2 and all("not one of the project's target IPs" in r for r in refused)


def test_an_excluded_target_is_refused_by_the_roe():
    project = dict(PROJECT, roeExcludedHosts=["203.0.113.2"], roeMaxRps=10)
    _, targets, refused = _filter({"ips": ["203.0.113.2", "203.0.113.9"]}, project)
    assert targets["ips"] == ["203.0.113.9"]
    assert refused == ["ip '203.0.113.2' (excluded by the Rules of Engagement)"]


def _ip_placeholders():
    """recon/helpers/ip_placeholders.py, loaded by path: the orchestrator image
    has no recon package dependencies, and this module needs none."""
    import importlib.util
    from pathlib import Path
    path = Path(__file__).resolve().parents[2] / "recon" / "helpers" / "ip_placeholders.py"
    spec = importlib.util.spec_from_file_location("_ip_placeholders_pin", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_label_rule_matches_the_recon_spelling():
    from batch_scope import _is_target_label
    from recon_settings.ip_hostnames import TargetSet
    placeholders = _ip_placeholders()
    targets = TargetSet.from_entries(PROJECT["targetIps"])
    for address in ("203.0.113.1", "203.0.113.2", "203.0.113.9", "2001:db8::1"):
        label = placeholders.placeholder_for(address)
        assert placeholders.is_placeholder(label) and _is_target_label(label, targets), label
        assert _is_target_label(label.upper(), targets)
    for name in ("203-0-113-3", "198-51-100-7", "www.example.com", "203-0-113-2.ip-targets.p1",
                 "mail01", "1-2-3", None, 42):
        assert not _is_target_label(name, targets), name
