"""Characterisation test: the orchestrator's check of a partial run's typed
inputs in an IP-mode project (B-20 / B-22 of the IP-mode plan).

The job queue and the scan scheduler post partial runs to the orchestrator
directly (webapp/src/lib/startScan.ts), past the modal and the webapp route, so
filter_partial_user_input here is a control, not a convenience: a typed address
must be one of the project's targets (CIDR-aware, IPv6 canonical), and IPs may
be attached only to a target's own placeholder.

Marked ``xfail(strict=True)`` until the fix: the container-side mirror is
pinned in recon/tests/test_regression_partial_ip_mode_leaks.py.
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


@pytest.mark.xfail(strict=True, raises=AssertionError,
                   reason="B-20/B-22: typed IPs are never checked against the targets, URL hosts not CIDR-aware, ip_attach_to unchecked")
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
