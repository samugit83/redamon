"""update_graph_from_port_scan never lowers what it did not measure (D5, R-26).

A full run clears the assets first, so the port write lands on fresh nodes and
sets what naabu or masscan reported. A partial run, and a late write in the
same full run, land on nodes other tools already tagged. So the writer:

  * never takes IP.is_cdn from true to false, and keeps the first cdn_name;
  * sets Port.passive_only false only for a port the caller actively saw: a
    port detail carrying a passive_only other than false (rebuilt from the
    graph) is none;
  * writes each port under the IP its detail names, or the host's IP.

Fake Neo4j session: these pin the Cypher and its parameters. The live
counterpart, tests/test_port_scan_writer_graph_live.py, proves the values.
"""

import os
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO)

from graph_db.mixins.recon.port_mixin import PortMixin  # noqa: E402

IP_A, IP_B = "198.51.100.10", "198.51.100.20"


class _Result(list):
    def single(self):
        return self[0] if self else None


class _Session:
    def __init__(self):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        self.calls.append((query, params))
        return _Result()


class _Writer(PortMixin):
    def __init__(self):
        self.session = _Session()
        self.driver = MagicMock()
        self.driver.session.return_value = self.session


def _write(by_host, by_ip=None):
    w = _Writer()
    w.update_graph_from_port_scan({"domain": "example.com", "port_scan": {
        "by_ip": by_ip or {}, "by_host": by_host}}, "u1", "p1")
    return w.session.calls


def _ip_writes(calls):
    return [(q, p) for q, p in calls if "MERGE (i:IP" in q and "MERGE (p:Port" not in q]


def _port_writes(calls):
    return [(q, p) for q, p in calls if "MERGE (p:Port" in q]


def _naabu_host(is_cdn=False, cdn=None, **detail):
    return {"www.example.com": {"host": "www.example.com", "ip": IP_A, "ports": [443],
                                "is_cdn": is_cdn, "cdn": cdn,
                                "port_details": [{"port": 443, "protocol": "tcp",
                                                  "service": "https", **detail}]}}


class TestCdnTag(unittest.TestCase):
    def test_the_ip_tag_only_ever_goes_up(self):
        calls = _write(_naabu_host(), by_ip={IP_A: {"ports": [443], "is_cdn": False}})
        writes = _ip_writes(calls)
        self.assertEqual(len(writes), 2)  # by_ip, then the host's IP
        for query, params in writes:
            self.assertIn("i.is_cdn = coalesce(i.is_cdn, false) OR $is_cdn", query)
            self.assertIn("i.cdn_name = coalesce(i.cdn_name, $cdn_name)", query)
            self.assertNotIn("SET i.is_cdn = $is_cdn", query)
            self.assertIs(params["is_cdn"], False)

    def test_naabus_tag_is_passed_as_it_reported_it(self):
        calls = _write(_naabu_host(is_cdn=True, cdn="cloudflare"))
        _, params = _ip_writes(calls)[0]
        self.assertEqual((params["is_cdn"], params["cdn_name"]), (True, "cloudflare"))

    def test_a_missing_or_null_tag_is_a_boolean_false(self):
        # `false OR null` is null in Cypher, which would remove a stored true.
        calls = _write({"h": {"ip": IP_A, "is_cdn": None, "port_details": []}},
                       by_ip={IP_A: {"ports": [80]}})
        for _, params in _ip_writes(calls):
            self.assertIs(params["is_cdn"], False)


class TestPassiveOnly(unittest.TestCase):
    def test_a_port_the_scanner_reported_is_an_active_hit(self):
        query, params = _port_writes(_write(_naabu_host()))[0]
        self.assertIs(params["active"], True)
        self.assertIn("WITH p WHERE $active", query)
        self.assertIn("p.passive_only = false", query.split("WITH p WHERE $active", 1)[1])

    def test_a_port_carried_as_passive_is_not(self):
        _, params = _port_writes(_write(_naabu_host(passive_only=True)))[0]
        self.assertIs(params["active"], False)

    def test_a_port_carried_as_active_stays_active(self):
        _, params = _port_writes(_write(_naabu_host(passive_only=False)))[0]
        self.assertIs(params["active"], True)

    def test_a_port_carried_without_a_mark_is_not_an_active_hit(self):
        # Rebuilt from a Port written before the mark existed: leave it as stored.
        _, params = _port_writes(_write(_naabu_host(passive_only=None)))[0]
        self.assertIs(params["active"], False)

    def test_state_and_timestamp_are_written_either_way(self):
        query, _ = _port_writes(_write(_naabu_host(passive_only=True)))[0]
        head = query.split("WITH p WHERE $active", 1)[0]
        self.assertIn("p.state = 'open'", head)
        self.assertIn("p.updated_at = datetime()", head)


class TestPortOwner(unittest.TestCase):
    def test_a_detail_naming_its_ip_is_written_there(self):
        host = {"www.example.com": {"host": "www.example.com", "ip": IP_A, "ports": [80, 8080],
                                    "port_details": [
                                        {"port": 80, "protocol": "tcp", "service": "http"},
                                        {"port": 8080, "protocol": "tcp", "service": "http-alt",
                                         "ip": IP_B}]}}
        calls = _write(host)
        owners = {p["port_number"]: p["ip_addr"] for _, p in _port_writes(calls)}
        self.assertEqual(owners, {80: IP_A, 8080: IP_B})
        edges = {p["port_number"]: p["ip_addr"] for q, p in calls if "MERGE (i)-[:HAS_PORT]" in q}
        self.assertEqual(edges, {80: IP_A, 8080: IP_B})
        services = {p["port_number"]: p["ip_addr"] for q, p in calls if "MERGE (svc:Service" in q}
        self.assertEqual(services, {80: IP_A, 8080: IP_B})


if __name__ == "__main__":
    unittest.main()
