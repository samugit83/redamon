"""The triage "no current DNS name" fact never fires for an IP-mode target (P3, D-10).

`current_dns_names` on an IP-mode IP counts the hostnames recorded on it in the
record modes, and is 0 in IP only (decision D-10). Neither number says the
address left the target: the operator listed it. The fact that drops a
finding's score when no name points at its address must therefore keep
ignoring every IP-mode IP, with or without recorded names, and keep firing
for a domain-mode address no current name resolves to.

Run: ./agentic/run_tests.sh tests/test_fact_queries_ip_mode.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cypherfix_triage.fact_queries import PROJECT_FACT_QUERIES, build_project_facts  # noqa: E402

M2_IP, M3_IP, GONE, NAMED = "203.0.113.10", "203.0.113.11", "198.51.100.20", "198.51.100.21"


class TestNoDnsNameFactInIpMode(unittest.TestCase):
    def setUp(self):
        self.facts = build_project_facts({"ip_ownership": [
            # IP only: nothing looked up, so no name is counted.
            {"ip": M2_IP, "ownership": "unknown", "dns_names": 0, "ip_mode": True},
            # Record hostnames: the names recorded on the address.
            {"ip": M3_IP, "ownership": "unknown", "dns_names": 4, "ip_mode": True},
            {"ip": GONE, "ownership": "unknown", "dns_names": 0, "ip_mode": False},
            {"ip": NAMED, "ownership": "dedicated", "dns_names": 2, "ip_mode": False},
        ]})

    def test_an_ip_mode_target_is_never_a_host_without_a_name(self):
        self.assertNotIn(M2_IP, self.facts.no_dns_name_hosts)
        self.assertNotIn(M3_IP, self.facts.no_dns_name_hosts)

    def test_a_domain_mode_address_without_a_current_name_still_is(self):
        self.assertEqual(self.facts.no_dns_name_hosts, {GONE})

    def test_the_ownership_tag_is_read_in_every_mode(self):
        self.assertEqual(self.facts.ip_ownership, {M2_IP: "unknown", M3_IP: "unknown",
                                                   GONE: "unknown", NAMED: "dedicated"})

    def test_the_query_returns_the_ip_mode_flag_it_relies_on(self):
        query = next(q for q in PROJECT_FACT_QUERIES if q["name"] == "ip_ownership")["query"]
        self.assertIn("coalesce(ip.ip_mode, false) AS ip_mode", query)
        self.assertIn("ip.current_dns_names AS dns_names", query)


if __name__ == "__main__":
    unittest.main()
