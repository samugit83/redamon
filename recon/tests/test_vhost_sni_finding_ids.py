"""VHost/SNI finding ids never collide (R-46).

The id used to fold every non-alphanumeric character to "_", so
dev-api.example.com and dev.api.example.com (and any two IPv6 addresses that
share their digits) were one Vulnerability node. It is now a hash of the exact
hostname, IP, port and layer; tooling/scripts/vhost_finding_rekey.py moves the
old ids and must compute the same ones (pinned below).
"""
from __future__ import annotations

import re

from recon.main_recon_modules import vhost_sni_enum as v

#: The Priority Board and the MCP tools refuse any other finding id.
_FINDING_ID_RE = re.compile(r"[A-Za-z0-9_.:-]{1,200}")


# ---------------------------------------------------------------------------
# Finding ids
# ---------------------------------------------------------------------------
def _id(hostname="admin.example.com", ip="192.0.2.10", port=443, layer="L7"):
    anomaly = {
        "hostname": hostname, "ip": ip, "port": port, "scheme": "https", "layer": layer,
        "baseline_status": 404, "baseline_size": 10, "observed_status": 200,
        "observed_size": 900, "size_delta": 890, "severity": "low",
    }
    return v._build_finding_record(anomaly, ip, {})["id"]


def test_names_that_differ_only_in_punctuation_get_distinct_ids():
    assert _id("dev-api.example.com") != _id("dev.api.example.com")
    assert _id("a-b.example.com") != _id("a.b.example.com") != _id("ab.example.com")


def test_distinct_ipv6_addresses_get_distinct_ids():
    assert _id(ip="2001:db8::a") != _id(ip="2001:db8::b")
    assert _id(ip="2001:db8::a") != _id(ip="2001:db8::1:a")


def test_one_address_spelled_two_ways_is_one_finding():
    assert _id(ip="2001:DB8:0::A") == _id(ip="2001:db8::a")
    assert _id(hostname="Admin.Example.COM") == _id(hostname="admin.example.com")


def test_the_id_still_separates_port_layer_and_ip():
    ids = {_id(), _id(port=8443), _id(layer="L4"), _id(layer="both"), _id(ip="192.0.2.11")}
    assert len(ids) == 5
    assert _id() == _id()


def test_the_id_fits_what_the_board_and_mcp_accept():
    longest = ".".join(["a" * 63] * 3 + ["b" * 61])
    assert len(longest) == 253
    for fid in (_id(longest), _id(ip="2001:db8:1234:5678:9abc:def0:1234:5678"), _id()):
        assert _FINDING_ID_RE.fullmatch(fid), fid
        assert fid.startswith("vhost_sni_")


def test_the_rekey_script_computes_the_writers_ids():
    from tooling.scripts import vhost_finding_rekey as rk
    cases = [("dev-api.example.com", "192.0.2.10", 443, "L7"),
             ("dev.api.example.com", "192.0.2.10", 443, "L4"),
             ("wiki.example.com", "2001:db8::a", 8443, "both")]
    for hostname, ip, port, layer in cases:
        assert rk.new_finding_id(hostname, ip, port, layer) == _id(hostname, ip, port, layer)
        before = "vhost_sni_{h}_{i}_{p}_{l}".format(
            h=re.sub(r"[^a-z0-9]", "_", hostname.lower()), i=re.sub(r"[^0-9.]", "_", ip),
            p=port, l=layer.lower())
        assert rk.old_finding_id(hostname, ip, port, layer) == before
        assert before != _id(hostname, ip, port, layer)
