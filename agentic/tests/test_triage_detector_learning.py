"""The board learns from Real / False positive clicks (Phase 8a).

WHAT IT IS FOR
A detector that is right everywhere is wrong on somebody's estate. The GitHub
hunt's "secret" rule flags private IP addresses, and on a graph full of internal
ranges that is 119 findings of pure noise, all of them scoring the same as they
would anywhere else. Nothing in the model could ever learn that, so the operator
re-muted the same class of thing after every scan.

Now every Real / False positive click is a label for the DETECTOR that produced
the finding, and C for that detector becomes a Beta posterior over this
operator's own verdicts:

    C = (10 x C_rule + real) / (10 + real + fp)

THE THREE WAYS TO GET THIS CATASTROPHICALLY WRONG, each pinned below:

1. Learning across users. One account's clicks must never re-rank another's
   board, so the query is scoped to `user_id` and nothing wider.
2. Learning a detector into silence. Bounded at 0.1, because a detector nobody
   can see is a detector nobody ever finds out was right.
3. Talking down a proven finding. An exploit ran. No number of clicks about
   other findings changes that, and this is the same rule the AI review obeys.

Run: ./agentic/run_tests.sh tests/test_triage_detector_learning.py
"""

import os
import sys
import unittest

_AGENTIC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _AGENTIC)

from cypherfix_triage import fact_queries as fq  # noqa: E402
from cypherfix_triage import score_model as sm  # noqa: E402


def finding(**kwargs):
    base = {"id": "f1", "label": "Vulnerability", "source": "nuclei",
            "template_id": "tech-detect", "severity": "medium", "host": "h1"}
    base.update(kwargs)
    return base


def facts_with(labels):
    return sm.ProjectFacts(detector_labels=labels)


class TestTheDetectorKey(unittest.TestCase):
    """The key is what a click is attached to, so two findings sharing one must
    genuinely share a detector."""

    def test_nuclei_keys_on_the_template(self):
        self.assertEqual(sm.detector_key(finding(template_id="CVE-2021-1234")),
                         "nuclei:cve-2021-1234")

    def test_two_templates_are_two_detectors(self):
        self.assertNotEqual(sm.detector_key(finding(template_id="a")),
                            sm.detector_key(finding(template_id="b")))

    def test_gvm_keys_on_the_nvt(self):
        self.assertEqual(
            sm.detector_key({"source": "gvm", "oid": "1.3.6.1.4.1.25623.1.0.1"}),
            "gvm:1.3.6.1.4.1.25623.1.0.1")

    def test_a_secret_keys_on_its_detector_not_its_value(self):
        """The whole point: 'AWS keys here are always real, Slack ones never'."""
        aws = sm.detector_key({"label": "MultiscannerFinding",
                               "source": "trufflehog", "detector_name": "AWS"})
        slack = sm.detector_key({"label": "MultiscannerFinding",
                                 "source": "trufflehog", "detector_name": "Slack"})
        self.assertNotEqual(aws, slack)
        self.assertIn("aws", aws)

    def test_an_advisory_does_not_key_per_cve(self):
        """A verdict on CVE-2021-23337 says nothing about CVE-2022-1. Learning
        per advisory would collect one label per key and never learn anything."""
        one = sm.detector_key({"source": "osv", "id": "osv:pkg:npm/a:GHSA-1"})
        other = sm.detector_key({"source": "osv", "id": "osv:pkg:npm/b:GHSA-2"})
        self.assertEqual(one, other)

    def test_it_is_not_the_group_key(self):
        """Grouping merges by CVE because one upgrade fixes them all. A detector
        key must NOT, or one CVE found by two tools would pool their labels."""
        from cypherfix_triage.grouping import group_key
        row = finding(cve_ids=["CVE-2021-1234"])
        self.assertNotEqual(sm.detector_key(row), group_key(row))

    def test_it_never_raises_and_never_returns_empty(self):
        for row in ({}, None, {"source": None}, {"label": None},
                    {"source": "  "}, {"source": "x" * 500},
                    {"source": "nuclei", "template_id": None},
                    {"source": "gvm", "oid": ""}):
            with self.subTest(row=row):
                key = sm.detector_key(row)
                self.assertTrue(key)
                self.assertIsInstance(key, str)

    def test_a_hostile_template_id_cannot_shape_the_key(self):
        """The key is written to the graph and read back in a query, so a
        template id carrying separators must not be able to forge another
        detector's key."""
        key = sm.detector_key(finding(template_id="a b/../../gvm:1.2.3"))
        self.assertFalse(key.startswith("gvm:"))
        self.assertTrue(key.startswith("nuclei:"))

    def test_the_key_is_stable_across_calls(self):
        row = finding(template_id="Some-Template")
        self.assertEqual(sm.detector_key(row), sm.detector_key(dict(row)))


class TestThePosterior(unittest.TestCase):
    def test_no_labels_means_no_opinion(self):
        self.assertIsNone(sm.learned_confidence(0.75, 0, 0))

    def test_one_label_barely_moves_it(self):
        """Ten pseudo-counts: a single unlucky click must not re-rank a board."""
        moved = sm.learned_confidence(0.8, 0, 1)
        self.assertLess(moved, 0.8)
        self.assertGreater(moved, 0.7)

    def test_many_false_positives_drive_it_down(self):
        self.assertLess(sm.learned_confidence(0.8, 0, 40), 0.25)

    def test_many_real_verdicts_drive_it_up(self):
        self.assertGreater(sm.learned_confidence(0.3, 40, 0), 0.75)

    def test_it_is_never_learned_into_silence(self):
        """A detector at 0 is invisible, and an invisible detector can never be
        shown to have been right after all."""
        self.assertGreaterEqual(sm.learned_confidence(0.5, 0, 10_000),
                                sm.DETECTOR_MIN_CONFIDENCE)

    def test_it_is_never_learned_into_certainty(self):
        """1.0 means PROVEN. Clicks are evidence, not proof."""
        self.assertLessEqual(sm.learned_confidence(0.9, 10_000, 0),
                             sm.DETECTOR_MAX_CONFIDENCE)
        self.assertLess(sm.learned_confidence(0.9, 10_000, 0), 1.0)

    def test_it_is_monotonic_in_both_directions(self):
        previous = sm.learned_confidence(0.5, 0, 1)
        for fp in range(2, 60):
            current = sm.learned_confidence(0.5, 0, fp)
            self.assertLessEqual(current, previous)
            previous = current

        previous = sm.learned_confidence(0.5, 1, 0)
        for real in range(2, 60):
            current = sm.learned_confidence(0.5, real, 0)
            self.assertGreaterEqual(current, previous)
            previous = current

    def test_equal_evidence_leaves_it_near_the_prior(self):
        """Half real and half noise is not information about the detector."""
        self.assertAlmostEqual(sm.learned_confidence(0.5, 25, 25), 0.5, places=2)

    def test_a_negative_or_nonsense_count_cannot_produce_a_nonsense_c(self):
        for real, fp in ((-5, 0), (0, -5), ("x", "y"), (None, None), (-1, -1)):
            with self.subTest(real=real, fp=fp):
                value = sm.learned_confidence(0.5, real, fp)
                if value is not None:
                    self.assertGreaterEqual(value, 0.0)
                    self.assertLessEqual(value, 1.0)


class TestItChangesTheScore(unittest.TestCase):
    def test_a_detector_this_operator_calls_noise_ranks_lower(self):
        row = finding()
        key = sm.detector_key(row)
        before = sm.score(row, sm.ProjectFacts(), {})
        after = sm.score(row, facts_with({key: {"real": 0, "fp": 30}}), {})
        self.assertLess(after.score, before.score)

    def test_a_detector_this_operator_trusts_ranks_higher_or_equal(self):
        row = finding(source="guarddog", label="MalPackageFinding")
        key = sm.detector_key(row)
        before = sm.score(row, sm.ProjectFacts(), {})
        after = sm.score(row, facts_with({key: {"real": 30, "fp": 0}}), {})
        self.assertGreaterEqual(after.score, before.score)

    def test_another_detectors_labels_change_nothing(self):
        row = finding(template_id="a")
        before = sm.score(row, sm.ProjectFacts(), {})
        after = sm.score(row, facts_with({"nuclei:b": {"real": 0, "fp": 99}}), {})
        self.assertEqual(after.score, before.score)

    def test_a_proven_finding_cannot_be_talked_down(self):
        """An exploit ran. This is the same rule the AI review obeys."""
        row = finding(validation_status="validated")
        key = sm.detector_key(row)
        factor = sm.confidence(row, facts_with({key: {"real": 0, "fp": 500}}))
        self.assertEqual(factor.value, 1.0)

    def test_the_operator_can_see_why_it_moved(self):
        """A number that changed with no visible reason is one nobody can
        disagree with, which is how a ranking loses its users."""
        row = finding()
        factor = sm.confidence(row, facts_with(
            {sm.detector_key(row): {"real": 2, "fp": 8}}))
        self.assertIn("you judged 2 of 10", factor.evidence)

    def test_an_empty_label_set_leaves_the_rules_exactly_as_they_were(self):
        row = finding()
        self.assertEqual(sm.confidence(row, sm.ProjectFacts()).value,
                         sm.confidence(row, facts_with({})).value)

    def test_the_model_version_moved_with_the_rule(self):
        """Two runs are only comparable when this matches, and a rule changed."""
        self.assertNotEqual(sm.SCORE_MODEL_VERSION, "v3.0.0")


class TestTheLabelsComeFromTheRightPlace(unittest.TestCase):
    QUERY = next(q for q in fq.PROJECT_FACT_QUERIES
                 if q["name"] == "detector_labels")["query"]

    def test_it_reads_only_this_users_verdicts(self):
        self.assertIn("user_id: $userId", self.QUERY)

    def test_it_is_deliberately_not_scoped_to_one_project(self):
        """A detector that is noise on one of your projects is noise on the
        next, and this is the only fact query that crosses a project."""
        self.assertNotIn("$projectId", self.QUERY)

    def test_it_counts_only_what_a_person_decided(self):
        """An AI verdict is the thing being corrected. Counting it would make
        the model learn from itself."""
        self.assertIn("n.triage_source = 'human'", self.QUERY)

    def test_it_counts_both_directions(self):
        self.assertIn("'confirmed'", self.QUERY)
        self.assertIn("'likely_noise'", self.QUERY)

    def test_it_only_reads_findings(self):
        from graph_db.mixins.recon.triage_mixin import MUTEABLE_LABELS
        for label in MUTEABLE_LABELS:
            with self.subTest(label=label):
                self.assertIn(label, self.QUERY)

    def test_the_counts_reach_the_facts(self):
        facts = fq.build_project_facts({"detector_labels": [
            {"detector": "nuclei:a", "real": 3, "fp": 1},
        ]})
        self.assertEqual(facts.detector_labels["nuclei:a"],
                         {"real": 3, "fp": 1})

    def test_a_broken_row_is_dropped_rather_than_scoring_wrongly(self):
        facts = fq.build_project_facts({"detector_labels": [
            {"detector": "", "real": 5, "fp": 0},
            {"detector": None, "real": 5, "fp": 0},
            {"detector": "ok", "real": None, "fp": None},
            {"detector": "good", "real": 2, "fp": 0},
        ]})
        self.assertEqual(set(facts.detector_labels), {"good"})

    def test_a_failed_query_leaves_the_model_exactly_as_it_was(self):
        """Every fact set degrades to 'unknown', never to 'it is not true'."""
        self.assertEqual(fq.build_project_facts({}).detector_labels, {})


class TestTheDetectorReachesTheGraph(unittest.TestCase):
    """Without the stored key there is nothing to group the clicks by, so the
    learning would silently never happen."""

    def _source(self, relative):
        repo = os.path.dirname(_AGENTIC)
        with open(os.path.join(repo, relative)) as handle:
            return handle.read()

    def test_the_publish_writes_it(self):
        mixin = self._source("graph_db/mixins/recon/triage_mixin.py")
        self.assertIn("n.triage_detector       = row.detector", mixin)
        self.assertIn('"triage_detector"', mixin)

    def test_the_orchestrator_puts_it_on_the_row(self):
        orchestrator = self._source("agentic/cypherfix_triage/orchestrator.py")
        self.assertIn("score_model.detector_key(row)", orchestrator)
        self.assertIn('"detector": row.get("detector")', orchestrator)

    def test_unmuting_does_not_forget_it(self):
        """Unmute means 'show me this again', not 'forget what we learned'."""
        from graph_db.mixins.recon.triage_mixin import TRIAGE_PROPS
        self.assertIn("triage_detector", TRIAGE_PROPS)


if __name__ == "__main__":
    unittest.main()
