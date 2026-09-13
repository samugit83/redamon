"""A rescan no longer deletes the operator's work (X7).

WHAT IT USED TO DO
Every scanner DELETED its findings up front and re-created them. That deleted
everything a person had put on those nodes along with them: the mute they
applied, the verdict they recorded, the AI's cached review, and the link from a
fix item back to the finding it was written for. Re-muting the same noise after
every scan was the visible symptom. The invisible one was a fix item pointing at
a finding id that no longer existed.

WHAT IT DOES NOW
A scan MERGEs its findings, which refreshes `updated_at`, and afterwards removes
the ones it did not touch. No new "last seen" property was needed: `updated_at`
is already stamped by every node write and already has a test asserting that, so
"not seen in this run" is exactly "older than the run started".

THE TWO RULES THAT MAKE IT SAFE, and the two ways to get it catastrophically
wrong:

1. A finding a PERSON touched is never deleted, only stamped `stale_since`.
2. The prune runs ONLY after an ingest that actually produced findings. A scan
   that failed halfway reported nothing, and pruning on that would empty the
   project. That is why the caller decides, not the prune.

The live behaviour (three duplicates collapsing, a mute surviving) was verified
against Neo4j during development; what is pinned here is everything that can
regress from an edit to these files alone.

Run: python -m pytest tests/test_ingest_then_prune.py
"""

import os
import sys
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from graph_db.mixins.base_mixin import FINDING_LABELS  # noqa: E402


def source(relative: str) -> str:
    with open(os.path.join(_REPO, relative)) as handle:
        return handle.read()


def method_body(src: str, name: str) -> str:
    """One method's source, by name. Handles the LAST method in a class too."""
    start = src.index(f"def {name}")
    rest = src[start:]
    end = rest.find("\n    def ", 10)
    return rest if end == -1 else rest[:end]


class TestThePruneItself(unittest.TestCase):
    SRC = source("graph_db/mixins/base_mixin.py")

    def test_it_never_deletes_something_a_person_touched(self):
        """The single most important line in the change."""
        self.assertIn("n:Muted OR coalesce(n.triage_source, '') = 'human'",
                      self.SRC)

    def test_a_kept_finding_is_stamped_stale_rather_than_left_looking_live(self):
        self.assertIn("SET n.stale_since = coalesce(n.stale_since, datetime())",
                      self.SRC)

    def test_it_only_touches_the_sources_it_was_asked_about(self):
        """Otherwise a recon run would prune GVM's findings, and vice versa."""
        self.assertIn("coalesce(n.source, '') IN $sources", self.SRC)

    def test_it_refuses_to_run_with_no_source_or_no_timestamp(self):
        """Either missing would turn the query into 'delete everything'."""
        self.assertIn("if not sources or not run_started_at:", self.SRC)

    def test_it_only_touches_finding_labels(self):
        self.assertIn("_FINDING_LABEL_PREDICATE", self.SRC)

    def test_the_finding_labels_match_the_muteable_ones(self):
        """These are the labels carrying operator state; the two lists drifting
        apart would leave a muteable finding unprotected."""
        from graph_db.mixins.recon.triage_mixin import MUTEABLE_LABELS
        self.assertEqual(set(FINDING_LABELS), set(MUTEABLE_LABELS))

    def test_the_run_timestamp_is_taken_before_the_ingest(self):
        """Taken after, everything the ingest wrote would look older than the
        run and the prune would delete the results it had just produced."""
        self.assertIn("Taken BEFORE the ingest", self.SRC)


class TestTheRecalcClearsSpareFindings(unittest.TestCase):
    SRC = source("graph_db/mixins/base_mixin.py")

    def test_the_recon_clear_no_longer_deletes_findings(self):
        clear = method_body(self.SRC, "clear_recon_data")
        self.assertIn("AND NOT ({_FINDING_LABEL_PREDICATE})", clear)

    def test_it_still_clears_the_assets(self):
        """Guards the opposite mistake: a clear that now deletes nothing would
        leave every stale host and port in the graph for ever."""
        self.assertIn("DETACH DELETE n", method_body(self.SRC, "clear_recon_data"))


class TestReconPrunesOnlyAfterSuccess(unittest.TestCase):
    SRC = source("recon/main.py")

    def test_the_prune_runs_on_the_success_path(self):
        self.assertIn("_prune_recon_findings()", self.SRC)

    def test_it_does_nothing_when_the_clear_never_ran(self):
        """A run that failed before the clear has no run timestamp, and
        pruning against no timestamp would be 'delete everything'."""
        self.assertIn("if not UPDATE_GRAPH_DB or not _RUN_STARTED_AT:", self.SRC)

    def test_it_only_names_recon_s_own_sources(self):
        """A recon run must never prune a GVM or supply-chain finding."""
        self.assertIn("RECON_FINDING_SOURCES", self.SRC)
        for foreign in ("gvm", "github_hunt", "osv", "trufflehog"):
            block = self.SRC[self.SRC.index("RECON_FINDING_SOURCES = ("):]
            block = block[:block.index(")")]
            with self.subTest(source=foreign):
                self.assertNotIn(f'"{foreign}"', block)

    def test_a_housekeeping_failure_does_not_fail_a_completed_scan(self):
        prune = self.SRC[self.SRC.index("def _prune_recon_findings"):]
        prune = prune[:prune.index("\ndef ", 10)]
        self.assertIn("except Exception", prune)


class TestTheGithubHuntKeepsWhatAPersonJudged(unittest.TestCase):
    SRC = source("graph_db/mixins/secret_mixin.py")

    def test_its_findings_carry_a_source_so_they_can_be_pruned_at_all(self):
        """The prune is scoped by source. A finding with none could never be
        pruned, so the fix for one bug would have created a leak."""
        self.assertIn('"source": "github_hunt"', self.SRC)

    def test_the_clear_spares_muted_and_human_judged_findings(self):
        clear = method_body(self.SRC, "clear_github_hunt_data")
        self.assertEqual(clear.count("NOT gs:Muted"), 1)
        self.assertEqual(clear.count("NOT gsf:Muted"), 1)
        self.assertIn("coalesce(gs.triage_source, '') <> 'human'", clear)

    def test_a_path_holding_a_preserved_finding_is_not_deleted(self):
        """Deleting it would orphan the finding, and the orphan sweep would
        take it on the next run - undoing the whole fix."""
        clear = method_body(self.SRC, "clear_github_hunt_data")
        self.assertIn("CONTAINS_SECRET|CONTAINS_SENSITIVE_FILE", clear)

    def test_it_prunes_only_when_the_ingest_actually_produced_findings(self):
        """A scan that wrote nothing is evidence the scan failed, not evidence
        the findings are gone."""
        self.assertIn(
            'if stats["secrets_created"] or stats["sensitive_files_created"]:',
            self.SRC)

    def test_the_prune_is_scoped_to_the_hunt(self):
        self.assertIn('["github_hunt"], run_started_at', self.SRC)


class TestGvmKeepsWhatAPersonJudged(unittest.TestCase):
    BASE = source("graph_db/mixins/base_mixin.py")
    MAIN = source("scanners/gvm_scan/main.py")

    def test_the_clear_spares_muted_and_human_judged_findings(self):
        clear = method_body(self.BASE, "clear_gvm_data")
        self.assertIn("NOT v:Muted", clear)
        self.assertIn("NOT e:Muted", clear)

    def test_an_exploit_is_treated_as_the_finding_it_is(self):
        """ExploitGvm is what makes something "proven" on the board, so losing
        a decision about one matters more than any other finding type."""
        clear = method_body(self.BASE, "clear_gvm_data")
        self.assertIn("coalesce(e.triage_source, '') <> 'human'", clear)

    def test_it_prunes_only_when_the_scan_actually_found_something(self):
        """A GVM run that produced no vulnerabilities is far more often a scan
        that failed than a target that became clean."""
        self.assertIn('if not graph_stats.get("vulnerabilities_created"):',
                      self.MAIN)

    def test_it_does_nothing_when_the_clear_never_ran(self):
        self.assertIn("if not _GVM_RUN_STARTED_AT", self.MAIN)

    def test_gvm_ports_carry_a_source(self):
        """K20: with none, nothing could tell a port an ACTIVE scan confirmed
        from one a passive feed reported, and reachability reads that."""
        self.assertIn("p.source = coalesce(p.source, 'gvm')",
                      source("graph_db/mixins/gvm_mixin.py"))


class TestTrufflehogKeepsWhatAPersonJudged(unittest.TestCase):
    SRC = source("graph_db/mixins/secret_mixin.py")

    def _clear(self):
        return method_body(self.SRC, "clear_trufflehog_data")

    def test_the_clear_spares_muted_and_human_judged_findings(self):
        self.assertIn("NOT n:Muted", self._clear())
        self.assertIn("coalesce(n.triage_source, '') <> 'human'", self._clear())

    def test_an_asset_holding_a_preserved_finding_survives(self):
        """Deleting it would orphan the finding, and the board could no longer
        say where it was found."""
        self.assertIn("MATCH (n)-[:HAS_FINDING]->(f:MultiscannerFinding)",
                      self._clear())

    def test_it_is_still_scoped_to_one_source(self):
        """A Docker scan finishing must not wipe the HuggingFace results."""
        self.assertIn("{where}", self._clear())


class TestAFindingThatComesBackIsNoLongerStale(unittest.TestCase):
    """Regression. `stale_since` was only ever SET. The ingest MERGE refreshes
    `updated_at` and nothing else, so a human-confirmed finding the scanner
    reported again stayed "Resolved" for ever. The prune now lifts the stamp
    from anything of its sources that this run touched."""

    SRC = source("graph_db/mixins/base_mixin.py")

    def test_the_prune_revives_what_this_run_saw_again(self):
        prune = method_body(self.SRC, "prune_unseen_findings")
        self.assertIn("REMOVE n.stale_since", prune)
        self.assertIn("n.updated_at >= datetime($since)", prune)

    def test_it_reports_how_many_it_revived(self):
        self.assertIn('"revived"', method_body(self.SRC, "prune_unseen_findings"))


class TestTrufflehogPrunesAfterASuccessfulIngest(unittest.TestCase):
    """Regression. The clear spared muted and human-judged findings, and then
    NOTHING ever marked one of them resolved when its secret was gone: a
    human-confirmed TruffleHog finding stayed open and ranked indefinitely."""

    SRC = source("graph_db/mixins/secret_mixin.py")

    def _ingest(self):
        return method_body(self.SRC, "update_graph_from_trufflehog")

    def test_it_prunes_by_its_own_source_id(self):
        """`MultiscannerFinding.source` is the per-source id (docker, github),
        so a Docker run cannot touch the HuggingFace findings."""
        self.assertIn("[source], run_started_at", self._ingest())

    def test_it_prunes_only_when_the_ingest_produced_findings(self):
        self.assertIn('if stats["findings_created"]:', self._ingest())

    def test_the_timestamp_is_taken_before_the_clear(self):
        body = self._ingest()
        self.assertLess(body.index("run_started_at = run_timestamp()"),
                        body.index("self.clear_trufflehog_data("))


class TestEverySannerGotTheSameTreatment(unittest.TestCase):
    """The half-fix this guards against: leaving two of four scanners still
    deleting the operator's work, so whether a mute survived depended on which
    scanner found the thing."""

    def test_all_four_clears_spare_a_persons_decision(self):
        checks = [
            ("recon", "graph_db/mixins/base_mixin.py", "_FINDING_LABEL_PREDICATE"),
            ("gvm", "graph_db/mixins/base_mixin.py", "NOT v:Muted"),
            ("github hunt", "graph_db/mixins/secret_mixin.py", "NOT gs:Muted"),
            ("trufflehog", "graph_db/mixins/secret_mixin.py", "NOT n:Muted"),
        ]
        for name, path, marker in checks:
            with self.subTest(scanner=name):
                self.assertIn(marker, source(path))


if __name__ == "__main__":
    unittest.main()
