"""Each scanner's clear must delete its OWN data and nothing else.

Two classes of regression are guarded here, both of which destroyed data with no
error anywhere:

- a recon re-run called `clear_project_data`, a bare `MATCH (n) WHERE
  n.user_id AND n.project_id DETACH DELETE n`. That deleted the GitHub hunt, the
  Secret Multiscanner findings, the supply-chain packages, the GVM results and
  the agent's attack chains along with recon's own nodes.
- CVE/MitreData/Capec are GLOBAL reference nodes shared by every project that
  finds them, so any project-scoped delete removed other projects' links too.

Uses a fake Neo4j session (no live DB), mirroring test_supply_chain_mixin.

Run: python -m unittest tests.test_scan_ownership_clears
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

from graph_db.schema import (  # noqa: E402
    GLOBAL_REFERENCE_LABELS, NON_RECON_LABELS, NON_RECON_SOURCES,
)


class FakeResult:
    def __init__(self, single=None):
        self._single = single

    def single(self):
        return self._single


class FakeSession:
    def __init__(self):
        self.queries = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **kwargs):
        self.queries.append((query, kwargs))
        # Longest first: "as deleted" is a substring of "as deleted_count", and
        # answering the wrong key raises KeyError in the caller.
        for key in ("deleted_count", "deleted", "cleaned", "kept"):
            if f"as {key}" in query or f"AS {key}" in query:
                return FakeResult({key: 0})
        return FakeResult()


class FakeDriver:
    def __init__(self, session):
        self._session = session

    def session(self):
        return self._session


def _client(session):
    """A BaseMixin bound to the fake driver, without touching __init__ (which
    would open a real connection and run the schema DDL)."""
    from graph_db.mixins.base_mixin import BaseMixin
    client = BaseMixin.__new__(BaseMixin)
    client.driver = FakeDriver(session)
    return client


def _run(method, *args):
    session = FakeSession()
    getattr(_client(session), method)(*args)
    return session.queries


class TestReferenceNodesSurviveAProjectWipe(unittest.TestCase):
    def test_clear_project_data_excludes_the_reference_labels(self):
        queries = [q for q, _ in _run("clear_project_data", "u1", "p1")]
        wipe = next(q for q in queries if "deleted_count" in q)
        for label in GLOBAL_REFERENCE_LABELS:
            self.assertIn(f"n:`{label}`", wipe,
                          f"{label} is shared with every other project")
        self.assertIn("AND NOT (", wipe)

    def test_clear_project_data_sweeps_unreachable_reference_nodes(self):
        # Excluding them alone would leak: a CVE no project can reach any more
        # must go, or reference nodes accumulate forever.
        queries = [q for q, _ in _run("clear_project_data", "u1", "p1")]
        sweep = [q for q in queries if "NOT EXISTS" in q and "-[*1..3]-" in q]
        self.assertEqual(len(sweep), 1, "no orphan sweep ran")
        for label in GLOBAL_REFERENCE_LABELS:
            self.assertIn(f"n:`{label}`", sweep[0])
            self.assertIn(f"x:`{label}`", sweep[0])

    def test_the_sweep_tests_reachability_not_degree(self):
        # A degree test never fires: the catalogue is internally linked as
        # CVE -> MitreData -> Capec, so an unreferenced CVE still holds its CWE.
        # Live-proven — tests/test_scan_ownership_graph_live.py.
        queries = [q for q, _ in _run("clear_project_data", "u1", "p1")]
        sweep = next(q for q in queries if "NOT EXISTS" in q)
        self.assertNotIn("NOT (n)--()", sweep,
                         "a degree-zero test leaves the whole chain undeletable")

    def test_gvm_clear_no_longer_deletes_cve_by_project(self):
        # It used to run `MATCH (c:CVE {user_id, project_id, source:'gvm'})
        # DETACH DELETE c` against a node shared database-wide.
        queries = [q for q, _ in _run("clear_gvm_data", "u1", "p1")]
        for query in queries:
            if ":CVE" in query and "DELETE" in query:
                self.assertIn("NOT EXISTS", query,
                              "the only CVE delete left may be the orphan sweep")

    def test_gvm_clear_still_removes_its_own_labels(self):
        queries = [q for q, _ in _run("clear_gvm_data", "u1", "p1")]
        joined = "\n".join(queries)
        for label in ("Vulnerability", "Traceroute", "Certificate", "ExploitGvm"):
            self.assertIn(f":{label}", joined, f"{label} must still be cleared")
        self.assertIn("v.source = 'gvm'", joined)


class TestReconClearLeavesOtherScannersAlone(unittest.TestCase):
    def setUp(self):
        self.queries = _run("clear_recon_data", "u1", "p1")
        self.wipe, self.params = next(
            (q, p) for q, p in self.queries if "AS deleted" in q and "MATCH (n)" in q)

    def test_every_other_scanner_label_is_excluded(self):
        for label in NON_RECON_LABELS:
            self.assertIn(f"n:`{label}`", self.wipe, f"{label} would be destroyed")

    def test_the_scanners_that_actually_lost_data_are_covered(self):
        # Named individually so a careless edit to NON_RECON_LABELS still fails.
        for label in ("GithubSecret", "MultiscannerFinding", "Package",
                      "ChainFinding", "ExploitGvm", "SbomDocument"):
            self.assertIn(label, NON_RECON_LABELS)

    def test_shared_labels_are_excluded_by_source(self):
        # Vulnerability is written by recon, GVM, the supply-chain scanner and
        # the AI attack-surface scanner. Label alone cannot separate them.
        self.assertIn("coalesce(n.source, '') IN $keep_sources", self.wipe)
        self.assertEqual(self.params["keep_sources"], list(NON_RECON_SOURCES))
        for source in ("gvm", "osv", "garak", "promptfoo"):
            self.assertIn(source, NON_RECON_SOURCES)

    def test_ai_attack_synthetic_targets_survive(self):
        # The AI scan invents BaseURL/Endpoint anchors for targets recon never
        # found; deleting them orphans its findings.
        self.assertIn("ai_attack_synthetic", self.wipe)

    def test_a_technology_gvm_also_detected_is_kept(self):
        # Deleting it would orphan the GVM vulnerabilities hanging off it. Recon
        # re-MERGEs the node on its next pass anyway.
        self.assertIn("n:Technology", self.wipe)
        self.assertIn("CONTAINS 'gvm'", self.wipe)

    def test_it_is_still_scoped_to_one_project(self):
        self.assertIn("n.user_id = $uid", self.wipe)
        self.assertIn("n.project_id = $pid", self.wipe)
        self.assertEqual(self.params["uid"], "u1")
        self.assertEqual(self.params["pid"], "p1")

    def test_reference_nodes_are_excluded_here_too(self):
        for label in GLOBAL_REFERENCE_LABELS:
            self.assertIn(f"n:`{label}`", self.wipe)

    def test_recon_still_deletes_its_own_assets(self):
        # The exclusion list must not have grown into "delete nothing".
        for label in ("Domain", "Subdomain", "Endpoint"):
            self.assertNotIn(f"n:`{label}`", self.wipe, f"{label} is recon's own")

    def test_it_no_longer_deletes_its_own_FINDINGS(self):
        # X7. `Secret` and `JsReconFinding` ARE recon's own, and used to be
        # deleted here. Deleting them deleted the operator's work with them:
        # the mute they applied, the verdict they recorded, the AI's cached
        # review, and the link from a fix item back to the finding.
        #
        # They are pruned AFTER a successful ingest instead
        # (`prune_unseen_findings`), which keeps anything a person touched and
        # stamps it stale rather than removing it.
        for label in ("Secret", "JsReconFinding", "Vulnerability"):
            self.assertIn(f"n:`{label}`", self.wipe,
                          f"{label} is a finding and must not be cleared here")


if __name__ == "__main__":
    unittest.main()
