"""A GVM-detected service on a passive port marks it found by an active scan.

GVM writes the Port its scan detected a product on (OpenSSH on 22, Apache on
8080) with state 'open', but left `passive_only`: a Port Shodan or InternetDB
created stayed "passive" on the Priority Board after GVM's active scan had
confirmed it. The write now sets `passive_only = false`. The Port it MERGEs
carries the protocol GVM reported in its key, so a TCP detection leaves the
UDP Port of the same number as it was (the S-22 rule for nmap).

Fake Neo4j session: these pin the Cypher. The live counterpart is
tests/test_gvm_port_passive_only_graph_live.py.
"""
import os
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

sys.modules.setdefault("neo4j", MagicMock())
sys.modules.setdefault("dotenv", MagicMock())

from graph_db.mixins.gvm_mixin import GvmMixin  # noqa: E402

IP = "198.51.100.14"


class _Result(list):
    def single(self):
        return self[0] if self else None


class _Session:
    def __init__(self):
        self.queries = []

    def run(self, query, **params):
        self.queries.append((" ".join(query.split()), params))
        return _Result()


def _port_writes(tech):
    session = _Session()
    stats = {"technologies_created": 0, "ports_created": 0, "relationships_created": 0}
    GvmMixin()._merge_gvm_technology(session, tech, "u1", "p1", stats)
    return [(q, p) for q, p in session.queries if q.startswith("MERGE (p:Port")]


def _tech(**extra):
    return {"name": "OpenSSH", "version": "9.6", "cpe": "cpe:/a:openbsd:openssh:9.6",
            "target_ip": IP, "port": 22, "protocol": "tcp", **extra}


class TestGvmPortWrite(unittest.TestCase):
    def test_a_port_gvm_detected_a_service_on_is_no_longer_passive(self):
        writes = _port_writes(_tech())
        self.assertEqual(len(writes), 1)
        query, params = writes[0]
        self.assertIn("SET p.state = 'open', p.passive_only = false,", query)
        self.assertIn("MERGE (p:Port {number: $port_number, protocol: $protocol, ip_address: $ip_addr, "
                      "user_id: $user_id, project_id: $project_id})", query)
        self.assertEqual((params["port_number"], params["protocol"], params["ip_addr"]), (22, "tcp", IP))

    def test_the_protocol_gvm_reported_is_the_ports(self):
        _, params = _port_writes(_tech(port=161, protocol="udp", name="net-snmp", version="5.9"))[0]
        self.assertEqual(params["protocol"], "udp")

    def test_an_os_detection_writes_no_port(self):
        self.assertEqual(_port_writes(_tech(port=None, categories=["Operating systems"])), [])


if __name__ == "__main__":
    unittest.main()
