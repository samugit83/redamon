"""A passive CVE on an IP that left the run reads reach UNKNOWN on the board.

Since the positive-coverage prune (design decision D1, commit 5ec9ac12), a
Shodan / InternetDB / Netlas / CriminalIP CVE on an IP no longer among the
run's targets is KEPT until a run re-checks it. `clear_recon_data` rebuilds the
assets at the start of every full run, so that CVE has no `IP` node any more:

- `gone_hosts` needs the IP node, so the finding is not "gone" (right: nobody
  looked);
- its `port_confirmed` is the verdict of the last run that still had the IP.
  A stored `true` made the reachable-now gate pass and lifted the cap a "real"
  review is held to, so a KEV CVE could reach "Act now" on an address nobody
  scanned this run.

The board now reads such a CVE as reach unknown: the gate is unknown, R is
capped below the 0.7 the KEV and "Act soon" rules need, the review cap holds,
and R's evidence (what the reviewer is shown, outside the hashed bundle) says
why. A row without the new column (an older reader) keeps today's reading.

Hosts are RFC 5737 addresses.

Run: ./agentic/run_tests.sh tests/test_passive_cve_orphan_reach.py
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cypherfix_triage import evidence, score_model as sm  # noqa: E402
from cypherfix_triage.fact_queries import (  # noqa: E402
    FINDING_QUERIES, build_project_facts, finding_query_by_id, normalise_finding_row)

LEFT = "198.51.100.40"
STILL_HERE = "198.51.100.41"
HASH = "e" * 64
PASSIVE = ("shodan_api", "internetdb", "shodan", "shodan_host_lookup", "netlas", "criminalip")


def _facts():
    """This run's facts: STILL_HERE was scanned again, LEFT is in none of them,
    as after clear_recon_data rebuilt the assets without it."""
    return build_project_facts({
        "live_hosts": [{"hosts": ["https://www.example.com", "www.example.com"]}],
        "port_hosts": [{"host": STILL_HERE, "how": "active", "ports": [22, 443]}],
        "ip_ownership": [{"ip": STILL_HERE, "ownership": "dedicated", "dns_names": 1,
                          "ip_mode": False}],
        "gone_hosts": [{"hosts": []}],
    })


def _row(ip=LEFT, in_graph=False, **kw):
    """A passive CVE row as the board's vulnerabilities query returns it. Its
    IP parent is gone, so the host resolves from `target_ip`."""
    row = {"id": f"shodan-CVE-2021-23017-{ip}", "label": "Vulnerability",
           "source": "shodan_api", "name": "CVE-2021-23017",
           "cve_ids": ["CVE-2021-23017"], "cisa_kev": True, "severity": "critical",
           "cvss_score": 9.8, "detection_method": "passive_version_match",
           "target_ip": ip, "target_port": 22, "triage_host": ip,
           "port_confirmed": True, "target_ip_in_graph": in_graph}
    row.update(kw)
    return normalise_finding_row(row)


def _final(row, review=None, decision=None):
    base = sm.BaseLayer.from_result(sm.score(row, _facts()))
    return sm.combine_layers(base, review, decision, HASH)


class TestTheBoardReadsTheIpNode(unittest.TestCase):
    QUERY = next(q for q in FINDING_QUERIES if q["name"] == "vulnerabilities")

    def test_the_row_says_whether_its_ip_is_still_in_the_graph(self):
        self.assertIn("AS target_ip_in_graph", self.QUERY["query"])

    def test_the_lookup_is_tenant_scoped_and_spelled_as_the_writers_link(self):
        # The passive writers link IP -[:HAS_VULNERABILITY]-> by exact address.
        self.assertIn("(:IP {address: v.target_ip, user_id: $userId, project_id: $projectId})",
                      self.QUERY["query"])

    def test_a_cve_with_no_target_ip_is_not_judged(self):
        self.assertIn("WHEN coalesce(v.target_ip, '') = '' THEN null", self.QUERY["query"])

    def test_the_single_finding_read_still_narrows_by_id(self):
        query = finding_query_by_id(self.QUERY)
        self.assertIn("WHERE v.id = $findingId AND NOT v:Muted", query)
        self.assertIn("AS target_ip_in_graph", query)


class TestAPassiveCveOnAnIpThatLeftTheRun(unittest.TestCase):
    def test_the_reachable_now_gate_is_unknown_not_its_old_port_verdict(self):
        gates = sm.gate_facts(_row(), _facts(), proven=False)
        self.assertIsNone(gates["reachable_now"])

    def test_it_is_not_gone(self):
        result = sm.score(_row(), _facts())
        self.assertEqual(result.state, sm.STATE_OPEN)

    def test_reach_is_capped_below_the_act_soon_bar_and_says_why(self):
        r = sm.reach(_row(), _facts(), sm.parse_cvss_vector(None))
        self.assertEqual(r.value, sm.LEFT_TARGET_MAX_REACH)
        self.assertLess(r.value, sm.REACHABLE_NOW_MIN_REACH)
        self.assertIn("no longer among this run's targets", r.evidence)
        self.assertIn("reach unknown", r.evidence)

    def test_a_lower_reach_is_never_raised(self):
        vector = sm.parse_cvss_vector("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        r = sm.reach(_row(), _facts(), vector)
        self.assertEqual(r.value, 0.3)
        self.assertIn("reach unknown", r.evidence)

    def test_its_old_port_verdict_no_longer_lifts_the_review_cap(self):
        self.assertTrue(sm.score(_row(), _facts()).tier_inputs.passive_unconfirmed)

    def test_a_real_review_of_a_kev_cve_is_not_act_now(self):
        final = _final(_row(), review=sm.ReviewLayer("real", HASH))
        self.assertNotIn(final.tier, ("T1", "T2"))
        self.assertEqual(final.factors["C"]["value"], sm.PASSIVE_REVIEW_MAX_CONFIDENCE)

    def test_a_persons_real_is_not_act_now_by_reach(self):
        final = _final(_row(), decision=sm.DecisionLayer("confirmed"))
        self.assertEqual(final.factors["C"]["value"], 1.0)
        self.assertNotIn(final.tier, ("T1", "T2"))

    def test_proof_still_wins(self):
        facts = _facts()
        facts.proven_cve_ids.add("CVE-2021-23017")
        base = sm.BaseLayer.from_result(sm.score(_row(), facts))
        self.assertEqual(sm.combine_layers(base, None, None, HASH).tier, "T1")

    def test_every_passive_source_is_covered(self):
        for source in PASSIVE:
            with self.subTest(source=source):
                row = _row(source=source)
                self.assertIsNone(sm.gate_facts(row, _facts(), False)["reachable_now"])
                self.assertEqual(sm.reach(row, _facts(), sm.parse_cvss_vector(None)).value,
                                 sm.LEFT_TARGET_MAX_REACH)

    def test_a_port_found_closed_before_it_left_stays_inactive(self):
        # The last measurement there is: it keeps the finding resolved rather
        # than bringing it back as an open lead.
        row = _row(port_confirmed=False)
        self.assertEqual(sm.score(row, _facts()).state, sm.STATE_INACTIVE)
        self.assertIs(sm.gate_facts(row, _facts(), False)["reachable_now"], False)

    def test_an_unknown_port_verdict_stays_unknown(self):
        row = _row(port_confirmed=None)
        self.assertIsNone(sm.gate_facts(row, _facts(), False)["reachable_now"])
        self.assertEqual(sm.score(row, _facts()).state, sm.STATE_OPEN)


class TestWhatDoesNotChange(unittest.TestCase):
    def test_an_ip_still_in_the_graph_keeps_its_port_verdict(self):
        row = _row(ip=STILL_HERE, in_graph=True)
        self.assertIs(sm.gate_facts(row, _facts(), False)["reachable_now"], True)
        self.assertEqual(sm.reach(row, _facts(), sm.parse_cvss_vector(None)).value, 1.0)
        self.assertFalse(sm.score(row, _facts()).tier_inputs.passive_unconfirmed)

    def test_a_row_without_the_column_reads_as_before(self):
        row = _row()
        del row["target_ip_in_graph"]
        self.assertIs(sm.gate_facts(row, _facts(), False)["reachable_now"], True)
        self.assertEqual(sm.reach(row, _facts(), sm.parse_cvss_vector(None)).value, 0.7)
        row["target_ip_in_graph"] = None
        self.assertIs(sm.gate_facts(row, _facts(), False)["reachable_now"], True)

    def test_an_active_scanners_finding_is_not_touched(self):
        row = _row(source="nuclei")
        self.assertEqual(sm.reach(row, _facts(), sm.parse_cvss_vector(None)).value,
                         sm.REACH_UNKNOWN)

    def test_the_evidence_bundle_does_not_carry_it(self):
        # The reviewer reads it in R's evidence, outside the hash: no review expires.
        left, here = _row(), _row(in_graph=True)
        self.assertEqual(evidence.build_bundle(left), evidence.build_bundle(here))
        self.assertEqual(evidence.build_bundle_legacy(left), evidence.build_bundle_legacy(here))

    def test_the_model_version_moved(self):
        self.assertNotIn(sm.SCORE_MODEL_VERSION, ("v3.10.0",))


if __name__ == "__main__":
    unittest.main()
