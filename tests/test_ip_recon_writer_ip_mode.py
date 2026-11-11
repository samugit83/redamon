"""update_graph_from_ip_recon writes the target IPs, never a PTR name's answer.

IP mode stored a PTR name's forward answer in place of the listed address
(R-4, B-01): the foreign address became an IP node with a RESOLVES_TO, and the
listed one was missing whenever the PTR name did not resolve back to it. Now
every target IP gets its node from its label's ``actual_ip``, and when the
recon dict declares ``metadata.expanded_ips`` no address outside that list is
written. A dict that declares no list (an older file) is written as before.

The Neo4j session is a fake that records each query and its parameters.
Documentation ranges (RFC 5737 / RFC 3849) and reserved names only.

Run: ./redamon.sh test unit (root-agent section), or one file in the agent image.
"""
import os
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO)

from graph_db.mixins.recon.domain_mixin import DomainMixin  # noqa: E402

T1, T2, FOREIGN, V6 = "203.0.113.1", "203.0.113.2", "198.51.100.7", "2001:db8::1"


class _Session:
    def __init__(self):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        self.calls.append((query, params))
        return MagicMock()


class _Writer(DomainMixin):
    def __init__(self):
        self.session = _Session()
        self.driver = MagicMock()
        self.driver.session.return_value = self.session

    def ip_nodes(self):
        return [p["addr"] for q, p in self.session.calls if "MERGE (i:IP" in q]

    def resolves_to(self):
        return [(p["sub"], p["ip"]) for q, p in self.session.calls if "RESOLVES_TO" in q]


def _mock(ip, listed=None):
    v6 = ":" in ip
    return {"has_records": True, "is_mock": True, "actual_ip": ip, "records": {},
            "ips": {"ipv4": [] if v6 else [listed or ip], "ipv6": [listed or ip] if v6 else []}}


def _recon(subs, expanded=(T1, T2)):
    meta = {"root_domain": "ip-targets.p1", "ip_mode": True}
    if expanded is not None:
        meta["expanded_ips"] = list(expanded)
    return {"metadata": meta, "subdomains": list(subs), "dns": {"subdomains": subs}}


def _write(recon):
    writer = _Writer()
    writer.update_graph_from_ip_recon(recon, "u1", "p1")
    return writer


class TestIpReconWriterIpMode(unittest.TestCase):
    def test_every_target_ip_comes_from_its_label(self):
        writer = _write(_recon({"203-0-113-1": _mock(T1), "203-0-113-2": _mock(T2)}))
        self.assertEqual(writer.ip_nodes(), [T1, T2])
        self.assertEqual(writer.resolves_to(), [("203-0-113-1", T1), ("203-0-113-2", T2)])

    def test_a_label_writes_its_actual_ip_not_its_dns_list(self):
        writer = _write(_recon({"203-0-113-1": _mock(T1, listed=FOREIGN)}))
        self.assertEqual(writer.ip_nodes(), [T1])

    def test_a_ptr_names_foreign_answer_is_never_an_ip_node(self):
        subs = {"203-0-113-1": _mock(T1), "203-0-113-2": _mock(T2),
                "www.example.com": {"has_records": True, "ips": {"ipv4": [FOREIGN, T1], "ipv6": []}}}
        writer = _write(_recon(subs))
        self.assertNotIn(FOREIGN, writer.ip_nodes())
        self.assertIn(("www.example.com", T1), writer.resolves_to())
        self.assertNotIn(("www.example.com", FOREIGN), writer.resolves_to())

    def test_a_target_spelt_differently_still_matches(self):
        subs = {"2001-db8--1": _mock(V6),
                "v6.example.com": {"has_records": True, "ips": {"ipv4": [], "ipv6": ["2001:DB8:0::1"]}}}
        writer = _write(_recon(subs, expanded=(V6,)))
        self.assertEqual(writer.resolves_to(), [("2001-db8--1", V6), ("v6.example.com", "2001:DB8:0::1")])

    def test_a_declared_empty_list_writes_no_ip(self):
        writer = _write(_recon({"203-0-113-1": _mock(T1)}, expanded=()))
        self.assertEqual(writer.ip_nodes(), [])

    def test_a_dict_without_a_target_list_is_written_as_before(self):
        subs = {"www.example.com": {"has_records": True, "ips": {"ipv4": [FOREIGN], "ipv6": []}}}
        writer = _write(_recon(subs, expanded=None))
        self.assertEqual(writer.ip_nodes(), [FOREIGN])

    def test_every_ip_merge_stays_tenant_scoped(self):
        writer = _write(_recon({"203-0-113-1": _mock(T1), "203-0-113-2": _mock(T2)}))
        merges = [(q, p) for q, p in writer.session.calls if "MERGE (i:IP" in q]
        self.assertEqual(len(merges), 2)
        for query, params in merges:
            self.assertIn("user_id: $uid, project_id: $pid", query)
            self.assertEqual((params["uid"], params["pid"]), ("u1", "p1"))


if __name__ == "__main__":
    unittest.main()
