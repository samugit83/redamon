"""In IP mode the OSINT writers leave hostnames to the hostnames hook (P3, B-14, B-15).

A name a passive source saw on a target address was written by each source its
own way: Shodan's rDNS as an ExternalDomain DISCOVERED_BY the mock root, OTX's
passive DNS through HAS_EXTERNAL_DOMAIN without its dates, Censys, FOFA and
ZoomEye dropped it. In IP mode the hook collects every one of them and
update_graph_from_ip_hostnames records each with its evidence, so these
writers write no name there: no Subdomain, no ExternalDomain. Everything else
they write about the address is unchanged, and so is domain mode.

The Neo4j session is a fake that records each statement. Documentation ranges
and reserved names only.

Run: ./redamon.sh test unit (root-agent section), or one file in the agent image.
"""
import os
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO)

from graph_db.mixins.osint_mixin import OsintMixin  # noqa: E402

IP = "203.0.113.10"
MOCK = "ip-targets.cmosintnames000000000001"


class _Session:
    def __init__(self):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        self.calls.append((query, params))
        result = MagicMock()
        result.single.return_value = None
        result.__iter__ = lambda s: iter([])
        return result


class _Writer(OsintMixin):
    def __init__(self):
        self.session = _Session()
        self.driver = MagicMock()
        self.driver.session.return_value = self.session

    def names_written(self):
        return [q for q, _ in self.session.calls
                if "MERGE (s:Subdomain" in q or "MERGE (ed:ExternalDomain" in q]

    def ip_writes(self):
        return [q for q, p in self.session.calls if "(i:IP {address: $address" in q]


def _ip_mode(key, payload):
    return {"domain": MOCK, "metadata": {"ip_mode": True, "root_domain": MOCK}, key: payload}


def _domain_mode(key, payload):
    return {"domain": "example.com", key: payload}


SOURCES = {
    "shodan": ("update_graph_from_shodan", {
        "hosts": [{"ip": IP, "os": "Linux"}], "reverse_dns": {IP: ["ptr.example.com", "ptr.example.net"]}}),
    "otx": ("update_graph_from_otx", {"ip_reports": [{
        "ip": IP, "pulse_count": 0,
        "passive_dns": [{"hostname": "www.example.com", "first": "2024-01-01", "last": "2025-01-01"},
                        {"hostname": "other.example.net", "first": "", "last": ""}]}]}),
    "censys": ("update_graph_from_censys", {"hosts": [{
        "ip": IP, "reverse_dns_names": ["c.example.com"], "services": []}]}),
    "fofa": ("update_graph_from_fofa", {"results": [{"ip": IP, "port": 443, "host": "f.example.com:443"}]}),
    "zoomeye": ("update_graph_from_zoomeye", {"results": [{
        "ip": IP, "hostname": "z.example.com", "rdns": "zr.example.com"}]}),
}


class TestIpModeWritesNoName(unittest.TestCase):
    def _run(self, key, recon):
        method, _ = SOURCES[key]
        w = _Writer()
        getattr(w, method)(recon, "u1", "p1")
        return w

    def test_every_writer_skips_its_names_in_ip_mode(self):
        for key, (_, payload) in SOURCES.items():
            with self.subTest(source=key):
                w = self._run(key, _ip_mode(key, payload))
                self.assertEqual(w.names_written(), [])

    def test_the_address_is_still_enriched(self):
        for key in ("shodan", "otx", "zoomeye"):
            with self.subTest(source=key):
                w = self._run(key, _ip_mode(key, SOURCES[key][1]))
                self.assertTrue(w.ip_writes(), key)

    def test_domain_mode_still_writes_the_names(self):
        # In scope (under example.com) or ExternalDomain: either way a name node.
        for key, (_, payload) in SOURCES.items():
            with self.subTest(source=key):
                w = self._run(key, _domain_mode(key, payload))
                self.assertTrue(w.names_written(), key)


if __name__ == "__main__":
    unittest.main()
