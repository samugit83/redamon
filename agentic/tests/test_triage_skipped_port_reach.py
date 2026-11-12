"""A skipped port leaves only that port's findings unknown on the Priority Board.

A tripped breaker writes its target to the Domain's coverage record
(`recon_skipped_hosts`) as circuit_breaker.host_key spells it: `host:port`,
`[v6]:port`, or a bare host. The reachable-now gate used to strip the port, so
one dead `<ip>:443` turned every finding on that address "unknown: reachable
now". The rule now (maintainer decision): a `host:port` key covers the findings
on that host AND port; a bare host key covers the whole host; a host-level
finding with no port is covered only by a bare key. Keys written before the
change carry the same meaning they always had.

The gone query keeps sparing a host with ANY skipped key: gone takes every
finding of the host off the board, and an unchecked port proves nothing.

These go through the real run: TriageOrchestrator._score with the real
PROJECT_FACT_QUERIES and FINDING_QUERIES, Neo4j replaced by the rows each
query returns. The Cypher itself runs in tests/test_fix_fact_queries_graph_live.py.

Run: ./agentic/run_tests.sh tests/test_triage_skipped_port_reach.py
"""

import asyncio
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cypherfix_triage import score_model  # noqa: E402
from cypherfix_triage.fact_queries import (FINDING_QUERIES,  # noqa: E402
                                           PROJECT_FACT_QUERIES, build_project_facts)
from cypherfix_triage.orchestrator import TriageOrchestrator  # noqa: E402

IP, IP_WHOLE, V6, NAME = "203.0.113.5", "198.51.100.7", "2001:db8::5", "app.example.test"

#: What the skipped_hosts query hands back: the coverage record's keys as stored.
SKIPPED_KEYS = [f"{IP}:443", f"[{V6.upper()}]:8443", "App.Example.Test:443", IP_WHOLE]


def _query(name):
    return next(q for q in PROJECT_FACT_QUERIES if q["name"] == name)["query"]


def vuln(fid, host, port=None):
    return {"id": fid, "label": "Vulnerability", "source": "nuclei", "name": fid,
            "severity": "high", "triage_host": host, "target_port": port}


FINDINGS = [
    vuln("ip-443", IP, 443),
    vuln("ip-22", IP, 22),
    vuln("ip-host", IP),
    vuln("whole-22", IP_WHOLE, 22),
    vuln("whole-host", IP_WHOLE),
    vuln("v6-8443", V6, 8443),
    vuln("v6-22", V6, 22),
    vuln("url-https", f"https://{NAME}"),
    vuln("url-http", f"http://{NAME}"),
    vuln("name-host", NAME),
]


def score_run(skipped_keys):
    """Run Step A over FINDINGS with `skipped_keys` in the coverage record."""
    fact_rows = {
        "skipped_hosts": [{"hosts": list(skipped_keys)}],
        "port_hosts": [{"host": h, "how": "active", "ports": [22, 443, 8443]}
                       for h in (IP, IP_WHOLE, V6)],
        "live_hosts": [{"hosts": [f"https://{NAME}", f"http://{NAME}", NAME]}],
    }
    by_query = {q["query"]: fact_rows.get(q["name"], []) for q in PROJECT_FACT_QUERIES}
    vulnerabilities = next(q for q in FINDING_QUERIES if q["name"] == "vulnerabilities")
    by_query[vulnerabilities["query"]] = FINDINGS

    async def fake_static_query(query, params=None):
        return by_query.get(query, [])

    orch = TriageOrchestrator("u1", "p1", callback=None)
    with mock.patch.object(orch.neo4j, "run_static_query", fake_static_query):
        rows = asyncio.run(orch._score({"settings": {}}))
    return {row["id"]: row for row in rows}


class TestTheGateIsPortGranular(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = score_run(SKIPPED_KEYS)

    def reachable(self, fid):
        return self.rows[fid]["base"].inputs.gates["reachable_now"]

    def blocker(self, fid):
        row = self.rows[fid]
        return score_model.combine_layers(row["base"], None, None, row["evidence_hash"]).blocker

    def test_a_finding_on_the_skipped_port_is_unknown(self):
        self.assertIsNone(self.reachable("ip-443"))
        self.assertEqual(self.blocker("ip-443"), "unknown: reachable now")

    def test_another_port_of_the_same_address_keeps_its_own_evidence(self):
        self.assertIs(self.reachable("ip-22"), True)
        self.assertNotEqual(self.blocker("ip-22"), "unknown: reachable now")

    def test_a_host_level_finding_is_not_covered_by_a_port_key(self):
        self.assertIs(self.reachable("ip-host"), True)

    def test_a_bare_host_key_still_covers_every_finding_of_the_host(self):
        self.assertIsNone(self.reachable("whole-22"))
        self.assertIsNone(self.reachable("whole-host"))

    def test_an_ipv6_key_is_matched_inside_its_brackets_and_by_port(self):
        self.assertIsNone(self.reachable("v6-8443"))
        self.assertIs(self.reachable("v6-22"), True)

    def test_a_url_finding_takes_its_schemes_default_port(self):
        # circuit_breaker.host_key keys https://host as host:443, http://host as host:80.
        self.assertIsNone(self.reachable("url-https"))
        self.assertIs(self.reachable("url-http"), True)

    def test_a_name_level_finding_is_not_covered_by_its_names_port_key(self):
        self.assertIs(self.reachable("name-host"), True)

    def test_the_skip_moves_no_score(self):
        # The gate names a blocker; tier and score never read it.
        clean = score_run([])
        for fid, row in self.rows.items():
            with self.subTest(finding=fid):
                self.assertEqual((row["score"], row["tier"]),
                                 (clean[fid]["score"], clean[fid]["tier"]))
                self.assertIsNot(clean[fid]["base"].inputs.gates["reachable_now"], None)


class TestTheSkippedKeysAreReadWhole(unittest.TestCase):
    def test_the_reducer_splits_port_keys_from_bare_hosts(self):
        facts = build_project_facts({"skipped_hosts": [{"hosts": [
            f"{IP}:443", f"[{V6.upper()}]:8443", " App.Example.Test ", "2001:db8::9",
            "[2001:db8::7]", "odd.example.test:http", "big.example.test:70000", None, ""]}]})
        self.assertEqual(facts.skipped_ports, {(IP, 443), (V6, 8443)})
        # A key whose port does not parse keeps the whole-host reading it always had.
        self.assertEqual(facts.skipped_hosts, {"app.example.test", "2001:db8::9", "2001:db8::7",
                                               "odd.example.test", "big.example.test"})

    def test_the_skipped_query_returns_the_keys_with_their_ports(self):
        query = _query("skipped_hosts")
        self.assertIn("(d:Domain {user_id: $userId, project_id: $projectId})", query)
        self.assertIn("d.recon_skipped_hosts", query)
        self.assertNotIn("split(k, ':')", query)
        self.assertRegex(query, r"RETURN keys AS hosts\s*$")

    def test_the_gone_query_still_spares_a_host_with_any_skipped_port(self):
        gone = _query("gone_hosts")
        self.assertIn("WHEN size(split(k, ':')) = 2 THEN split(k, ':')[0]", gone)
        self.assertRegex(gone, r"NOT toLower\(coalesce\(n\.name, n\.address, ''\)\) IN skipped")

    def test_the_model_version_moved(self):
        # The stored gates and disposition change for a skipped port.
        self.assertNotIn(score_model.SCORE_MODEL_VERSION, ("v3.11.0",))


if __name__ == "__main__":
    unittest.main()
