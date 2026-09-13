"""The ranking-quality harness that gates the score model (Phase 0c).

`tooling/scripts/triage_eval.py` is what says whether a change to the score
model made the board better or worse. If its own arithmetic is wrong, every
later calibration decision is wrong with it, so the metric functions and the
truth-file matching are pinned here.

The one judgement encoded in the metrics: a false positive that got ranked
counts as NEGATIVE gain, not zero. Putting noise on the board is worse than
leaving a finding off it, because noise at the top is what makes an operator
stop reading the board at all.

Run: ./agentic/run_tests.sh tests/test_triage_eval_harness.py
"""

import os
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tooling" / "scripts"))

import triage_eval  # noqa: E402


class TestGrading(unittest.TestCase):
    ENTRIES = [
        {"cve": "CVE-2021-41773", "grade": 3},
        {"template": "apache-detect", "grade": 0},
        {"advisory": "PYSEC-", "match": "prefix", "grade": 0},
        {"detector": "IP Address (Private)", "grade": -1},
    ]

    def test_a_cve_matches_through_the_cve_ids_list(self):
        finding = {"id": "gvm-1", "cve_ids": ["CVE-2021-41773"], "name": "Apache"}
        self.assertEqual(triage_eval.grade_of(finding, self.ENTRIES), 3)

    def test_a_cve_matches_through_the_name(self):
        finding = {"id": "x", "name": "Apache HTTP Server CVE-2021-41773 traversal"}
        self.assertEqual(triage_eval.grade_of(finding, self.ENTRIES), 3)

    def test_a_template_id_matches(self):
        finding = {"id": "n1", "template_id": "apache-detect", "name": "Apache"}
        self.assertEqual(triage_eval.grade_of(finding, self.ENTRIES), 0)

    def test_a_prefix_entry_matches_only_the_id(self):
        self.assertEqual(
            triage_eval.grade_of({"id": "PYSEC-2021-0001"}, self.ENTRIES), 0)

    def test_a_prefix_entry_does_not_match_a_mention_in_prose(self):
        """Otherwise 'similar to PYSEC-2021-1' in a description would grade an
        unrelated finding as an ungraded advisory."""
        finding = {"id": "nuclei-abc", "name": "see also PYSEC-2021-0001"}
        self.assertIsNone(triage_eval.grade_of(finding, self.ENTRIES))

    def test_an_unknown_finding_is_excluded_not_graded_zero(self):
        self.assertIsNone(triage_eval.grade_of({"id": "unknown"}, self.ENTRIES))

    def test_a_false_positive_grades_negative(self):
        finding = {"id": "s1", "detector_name": "IP Address (Private)"}
        self.assertEqual(triage_eval.grade_of(finding, self.ENTRIES), -1)


class TestMetrics(unittest.TestCase):
    def test_the_ideal_order_scores_one(self):
        self.assertAlmostEqual(triage_eval.ndcg_at([3, 2, 2, 1, 0], 25), 1.0)

    def test_a_reversed_order_scores_less_than_the_ideal(self):
        self.assertLess(triage_eval.ndcg_at([0, 1, 2, 2, 3], 25),
                        triage_eval.ndcg_at([3, 2, 2, 1, 0], 25))

    def test_a_false_positive_at_the_top_scores_worse_than_omitting_it(self):
        with_noise = triage_eval.ndcg_at([-1, 3, 2], 25)
        without = triage_eval.ndcg_at([3, 2], 25)
        self.assertLess(with_noise, without)

    def test_nothing_graded_is_unmeasured_not_zero(self):
        """0.0 means "the worst possible ordering". A project the truth file
        says nothing about is UNMEASURED, and the release gate has to be able
        to tell those apart or it reads silence as a catastrophic regression."""
        self.assertIsNone(triage_eval.ndcg_at([], 25))

    def test_a_board_of_only_noise_is_also_unmeasured(self):
        """There is no "right" order for a list with no gain in it."""
        self.assertIsNone(triage_eval.ndcg_at([0, 0, 0], 25))

    def test_precision_counts_only_actionable_grades(self):
        self.assertAlmostEqual(triage_eval.precision_at([3, 2, 1, 0], 4), 0.5)

    def test_precision_of_an_empty_ranking_is_zero(self):
        self.assertEqual(triage_eval.precision_at([], 10), 0.0)


class TestEvaluate(unittest.TestCase):
    ENTRIES = [
        {"cve": "CVE-2021-41773", "grade": 3},
        {"detector": "IP Address (Private)", "grade": -1},
    ]

    def test_a_real_finding_flagged_false_is_counted_as_the_gate_failure(self):
        findings = [
            {"id": "v1", "cve_ids": ["CVE-2021-41773"],
             "triage_ai_verdict": "false_positive"},
        ]
        report = triage_eval.evaluate(findings, self.ENTRIES)
        self.assertEqual(report["real_flagged_as_false"], 1)

    def test_catching_a_known_false_positive_is_credited(self):
        findings = [
            {"id": "s1", "detector_name": "IP Address (Private)",
             "triage_status": "likely_noise"},
        ]
        report = triage_eval.evaluate(findings, self.ENTRIES)
        self.assertEqual(report["known_false_positives_caught"], 1)
        self.assertEqual(report["real_flagged_as_false"], 0)

    def test_coverage_reports_how_much_of_the_board_was_graded(self):
        findings = [
            {"id": "v1", "cve_ids": ["CVE-2021-41773"]},
            {"id": "unknown-1"},
            {"id": "unknown-2"},
            {"id": "unknown-3"},
        ]
        self.assertEqual(triage_eval.evaluate(findings, self.ENTRIES)["coverage"],
                         0.25)

    def test_an_empty_board_does_not_raise(self):
        report = triage_eval.evaluate([], self.ENTRIES)
        self.assertEqual(report["findings"], 0)
        self.assertIsNone(report["ndcg@25"])

    def test_a_board_with_no_graded_findings_reports_unmeasured(self):
        report = triage_eval.evaluate([{"id": "unknown-1"}], self.ENTRIES)
        self.assertIsNone(report["ndcg@25"])
        self.assertEqual(report["graded"], 0)


class TestTruthFile(unittest.TestCase):
    """The truth file is data the gate depends on; a typo there is silent."""

    @classmethod
    def setUpClass(cls):
        cls.truth = triage_eval.load_truth()

    def test_it_parses_and_has_every_guinea_pig_the_plan_names(self):
        for name in ("apache_2.4.49", "apache_2.4.25", "dvws-node",
                     "supply_chain_target", "web-cache-poisoning",
                     "ai_surface_target", "synthetic_dev_shape"):
            self.assertIn(name, self.truth)

    def test_every_entry_has_a_known_key_and_an_integer_grade(self):
        for name, section in self.truth.items():
            for entry in section.get("findings", []):
                with self.subTest(project=name, entry=entry):
                    keys = set(entry) & set(triage_eval.KEY_FIELDS)
                    self.assertTrue(keys, "entry names no matchable key")
                    self.assertIsInstance(entry["grade"], int)
                    self.assertGreaterEqual(entry["grade"], -1)
                    self.assertLessEqual(entry["grade"], 3)

    def test_no_entry_is_keyed_by_target_data(self):
        """Hostnames, URLs and IPs must never enter the repository."""
        import re
        host_like = re.compile(r"https?://|\b\d{1,3}(\.\d{1,3}){3}\b")
        for name, section in self.truth.items():
            for entry in section.get("findings", []):
                for key in triage_eval.KEY_FIELDS:
                    value = str(entry.get(key) or "")
                    with self.subTest(project=name, key=key):
                        self.assertIsNone(host_like.search(value))


class TestSyntheticFixture(unittest.TestCase):
    def test_it_mirrors_the_dev_graph_shape_and_touches_nothing(self):
        findings = triage_eval.synthetic_findings()
        osv = sum(1 for f in findings if f["source"] == "osv")
        private_ips = sum(
            1 for f in findings if f.get("detector_name") == "IP Address (Private)")
        self.assertGreater(osv / len(findings), 0.7)
        self.assertEqual(private_ips, 119)

    def test_it_is_deterministic(self):
        self.assertEqual(
            [f["id"] for f in triage_eval.synthetic_findings()],
            [f["id"] for f in triage_eval.synthetic_findings()],
        )


if __name__ == "__main__":
    unittest.main()
