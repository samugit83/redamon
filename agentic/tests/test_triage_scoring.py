"""The deterministic Priority Board scorer.

This is the load-bearing test file for the prioritisation redesign: the whole
point is that ranking is decided HERE, in pure code, not by an LLM. So the order
relationships between signal classes are pinned exactly (exploit-proof outranks
KEV outranks DAST outranks a bare medium), the demotions are pinned (a patched or
agent-failed finding sinks below its raw severity), and the "which findings never
touch an LLM" contract is pinned (deterministic facts get an auto-verdict).

Pure Python, no Neo4j: `score_finding` takes the flat signal dict the collection
query produces. The Cypher that produces that dict is proved separately against a
live database.

Run: python -m pytest agentic/tests/test_triage_scoring.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cypherfix_triage.scoring import (  # noqa: E402
    CVSS_MAX_POINTS,
    DEMOTIONS,
    SEVERITY_WEIGHT,
    SIGNAL_WEIGHTS,
    rank_findings,
    score_finding,
    tier_for_score,
)


def score(**row):
    """score_finding for a row given as kwargs; label defaults out of the row."""
    label = row.pop("label", "")
    return score_finding(row, label)


class TestEachSignalFiresItsWeight(unittest.TestCase):
    def test_a_bare_medium_scores_only_its_severity(self):
        s = score(severity="medium")
        self.assertEqual(s.score, SEVERITY_WEIGHT["medium"])
        self.assertIn("severity_medium", s.signals)

    def test_cvss_contributes_ten_times_capped(self):
        self.assertEqual(score(severity="info", cvss_score=7.5).score, 75)
        # capped at 100 even for a 10.0
        self.assertEqual(score(severity="info", cvss_score=10.0).score, CVSS_MAX_POINTS)

    def test_kev_adds_its_weight(self):
        s = score(severity="high", cisa_kev=True)
        self.assertEqual(s.score, SEVERITY_WEIGHT["high"] + SIGNAL_WEIGHTS["cisa_kev"])
        self.assertIn("cisa_kev", s.signals)

    def test_a_public_exploit_counts_as_kev(self):
        # netlas has_exploit is the same class of signal as cisa_kev.
        self.assertIn("cisa_kev", score(severity="high", has_exploit=True).signals)

    def test_confirmed_exploit_fires_and_is_proven(self):
        s = score(severity="critical", confirmed_exploits=1)
        self.assertIn("confirmed_exploit", s.signals)
        self.assertTrue(s.proven)

    def test_chain_exploit_success_is_the_top_weight(self):
        s = score(severity="critical", chain_proofs=["exploit_success"])
        self.assertIn("chain_exploit_success", s.signals)
        self.assertTrue(s.proven)

    def test_dast_needs_both_the_flag_and_a_match(self):
        self.assertIn("dast_confirmed",
                      score(severity="low", is_dast_finding=True, matcher_status=True).signals)
        # a DAST finding with no matcher status is not a confirmed match
        self.assertNotIn("dast_confirmed",
                         score(severity="low", is_dast_finding=True).signals)

    def test_injectable_and_qod(self):
        self.assertIn("injectable_param", score(severity="low", injectable=True).signals)
        self.assertIn("gvm_qod", score(severity="low", qod=99).signals)
        self.assertNotIn("gvm_qod", score(severity="low", qod=40).signals)


class TestTheOrderingThatMakesItUseful(unittest.TestCase):
    """The relationships an operator relies on to read the list top-down."""

    def test_exploit_proof_outranks_kev_outranks_dast_outranks_bare(self):
        proven = score(severity="high", chain_proofs=["exploit_success"]).score
        kev = score(severity="high", cisa_kev=True).score
        dast = score(severity="high", is_dast_finding=True, matcher_status=True).score
        bare = score(severity="high").score
        self.assertGreater(proven, kev)
        self.assertGreater(kev, dast)
        self.assertGreater(dast, bare)

    def test_a_kev_medium_outranks_a_plain_critical(self):
        # This is the whole value: a "medium" the world is actively exploiting
        # must beat a "critical" with nothing behind it.
        kev_medium = score(severity="medium", cisa_kev=True).score
        plain_critical = score(severity="critical").score
        self.assertGreater(kev_medium, plain_critical)

    def test_rank_findings_orders_worst_first_and_stamps_rank(self):
        rows = [
            {"id": "a", "severity": "critical", "score": 50},
            {"id": "b", "severity": "medium", "score": 850},   # KEV medium
            {"id": "c", "severity": "info", "score": 0},
        ]
        ordered = rank_findings(rows)
        self.assertEqual([r["id"] for r in ordered], ["b", "a", "c"])
        self.assertEqual([r["rank"] for r in ordered], [1, 2, 3])

    def test_ordering_is_deterministic_on_a_tie(self):
        rows = [{"id": "z", "severity": "high", "score": 100},
                {"id": "a", "severity": "high", "score": 100}]
        self.assertEqual([r["id"] for r in rank_findings(rows)], ["a", "z"])


class TestReachabilityDoesNotFireForEveryFinding(unittest.TestCase):
    """Regression: chain_reachability used to fire on `not is_cdn and host`,
    i.e. for almost every finding, making a +200 signal a constant offset that
    added nothing to the ranking. It must fire only on positive exposure."""

    def test_a_plain_host_is_not_reachability(self):
        # has a host, not behind a CDN -> used to (wrongly) fire.
        s = score(severity="high", host="10.0.0.1", is_cdn=False)
        self.assertNotIn("chain_reachability", s.signals)

    def test_a_live_baseurl_is_reachability(self):
        self.assertIn("chain_reachability", score(severity="high", is_live=True).signals)

    def test_an_unmasked_origin_is_reachability(self):
        self.assertIn("chain_reachability",
                      score(severity="high", is_cdn=True, is_origin=True).signals)

    def test_two_findings_on_plain_hosts_are_not_tied_by_a_constant(self):
        # The point of the fix: reachability must DISCRIMINATE. A live finding
        # outscores a non-live one of the same severity.
        live = score(severity="medium", is_live=True).score
        not_live = score(severity="medium", host="x").score
        self.assertGreater(live, not_live)


class TestDemotions(unittest.TestCase):
    def test_a_patched_finding_sinks_below_its_severity(self):
        patched = score(severity="critical", cvss_score=9.8, remediated=True)
        self.assertIn("gvm_remediated", patched.signals)
        self.assertLess(patched.score, 0)          # dropped well below a live info finding
        self.assertEqual(patched.auto_verdict, "likely_noise")

    def test_agent_tried_and_failed_demotes(self):
        failed = score(severity="high", exploit_failures=1).score
        clean = score(severity="high").score
        self.assertLess(failed, clean)

    def test_host_compromise_is_adjacency_not_proof(self):
        # The agent popped the HOST but not via this finding: a real signal
        # (findings on a popped box matter more) but NOT proof of this one, so no
        # `proven` and no auto-confirm. This is the fix for the over-attribution
        # where a chain success on an IP was credited to every vuln on it.
        s = score(severity="high", host_compromised=1)
        self.assertIn("host_compromised", s.signals)
        self.assertFalse(s.proven)
        self.assertIsNone(s.auto_verdict)
        # weaker than a precise CVE-matched proof
        proven = score(severity="high", chain_proofs=["exploit_success"]).score
        self.assertGreater(proven, s.score)

    def test_a_proven_finding_is_not_demoted_by_a_failure(self):
        # If the agent BOTH failed once AND later succeeded, success wins.
        s = score(severity="high", chain_proofs=["exploit_success"], exploit_failures=1)
        self.assertNotIn("chain_exploit_failed", s.signals)
        self.assertTrue(s.proven)

    def test_a_dead_credential_is_demoted(self):
        s = score(severity="high", label="Secret", validation_status="unvalidated")
        self.assertIn("secret_unvalidated", s.signals)

    def test_cdn_fronted_with_no_origin_is_slightly_demoted(self):
        self.assertIn("cdn_fronted_only", score(severity="high", is_cdn=True, host="x").signals)
        # ...but once the origin is found, the demotion is gone
        self.assertNotIn("cdn_fronted_only",
                         score(severity="high", is_cdn=True, is_origin=True, host="x").signals)


class TestTheAutoVerdictContract(unittest.TestCase):
    """Which findings the graph settles, so the LLM never sees them."""

    def test_exploit_proven_is_auto_confirmed(self):
        s = score(severity="high", confirmed_exploits=1)
        self.assertEqual(s.auto_verdict, "confirmed")
        self.assertEqual(s.auto_confidence, 1.0)

    def test_a_security_check_fact_is_auto_confirmed_never_llm(self):
        # The DMARC/header/direct-IP facts that produced the "needs verification"
        # wall. They are true by construction: confirmed, low score, no LLM.
        s = score(severity="medium", source="security_check")
        self.assertEqual(s.auto_verdict, "confirmed")
        self.assertEqual(s.auto_confidence, 0.9)
        # and it carries no exploitation signal, so it stays low and buried
        self.assertFalse(s.proven)

    def test_a_validated_live_secret_is_proven(self):
        s = score(severity="high", label="MultiscannerFinding", validation_status="validated")
        self.assertTrue(s.proven)
        self.assertEqual(s.auto_verdict, "confirmed")

    def test_an_ambiguous_finding_has_no_auto_verdict(self):
        # A nuclei DAST match with a response body: genuinely worth an LLM look.
        s = score(severity="high", source="nuclei", is_dast_finding=True,
                  matcher_status=True, has_poc=True)
        self.assertIsNone(s.auto_verdict)

    def test_agent_failed_is_auto_likely_noise(self):
        s = score(severity="high", exploit_failures=1)
        self.assertEqual(s.auto_verdict, "likely_noise")


class TestRobustness(unittest.TestCase):
    def test_an_empty_row_does_not_raise(self):
        s = score_finding({}, "")
        self.assertEqual(s.score, 0.0)
        self.assertIsNone(s.auto_verdict)

    def test_garbage_numeric_fields_are_ignored(self):
        s = score(severity="high", cvss_score="not a number", qod="lots",
                  confirmed_exploits=None, exploit_failures="x")
        self.assertEqual(s.score, SEVERITY_WEIGHT["high"])

    def test_unknown_severity_contributes_nothing(self):
        self.assertEqual(score(severity="apocalyptic").score, 0.0)

    def test_none_row(self):
        self.assertEqual(score_finding(None, "").score, 0.0)


class TestTiers(unittest.TestCase):
    def test_bands(self):
        self.assertEqual(tier_for_score(1300), "Critical")
        self.assertEqual(tier_for_score(600), "High")
        self.assertEqual(tier_for_score(200), "Medium")
        self.assertEqual(tier_for_score(45), "Low")
        self.assertEqual(tier_for_score(0), "Info")
        self.assertEqual(tier_for_score(-500), "Info")


class TestTheWeightTableMatchesTheDoc(unittest.TestCase):
    """The weights are the contract with prompts/system.py; pin the load-bearing
    ones so an accidental edit is caught."""

    def test_the_exploitation_ladder_is_monotone(self):
        w = SIGNAL_WEIGHTS
        self.assertGreater(w["chain_exploit_success"], w["confirmed_exploit"])
        self.assertGreater(w["confirmed_exploit"], w["chain_access_gained"])
        self.assertGreater(w["chain_access_gained"], w["cisa_kev"])
        self.assertGreater(w["cisa_kev"], w["secret_exposed"])
        self.assertGreater(w["secret_exposed"], w["dast_confirmed"])

    def test_remediated_is_the_hardest_demotion(self):
        self.assertLessEqual(DEMOTIONS["gvm_remediated"], min(DEMOTIONS.values()))


if __name__ == "__main__":
    unittest.main()
