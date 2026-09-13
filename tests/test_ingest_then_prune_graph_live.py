"""LIVE-Neo4j proof of ingest-then-prune (X7), and of a finding coming back.

Strategy row 11, plus the regression for the bug the review found:

  * a muted Vulnerability survives clear_gvm_data and the prune, and comes out
    stamped `stale_since`; a plain unseen one is deleted (row 11);
  * a stale finding the scanner reports AGAIN loses its stamp. Nothing else
    ever cleared `stale_since`, so a human-confirmed finding that came back
    stayed "Resolved" on the board for ever (regression).

Self-skips unless the neo4j driver imports AND a database answers. To run it:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m pytest tests/test_ingest_then_prune_graph_live.py -v
"""

import os
import sys
import time
import unittest
import uuid

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

_SKIP_REASON = None
try:
    import neo4j as _neo4j  # noqa: F401
except ImportError:
    _SKIP_REASON = "neo4j driver not installed"

_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
_USER = os.getenv("NEO4J_USER", "neo4j")
_PASSWORD = os.getenv("NEO4J_PASSWORD")
if _SKIP_REASON is None and not _PASSWORD:
    _SKIP_REASON = "NEO4J_PASSWORD not set"


def _probe():
    if _SKIP_REASON:
        return False
    try:
        drv = _neo4j.GraphDatabase.driver(_URI, auth=(_USER, _PASSWORD))
        with drv.session() as s:
            s.run("RETURN 1").single()
        drv.close()
        return True
    except Exception:
        return False


_ALIVE = _probe()


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class TestIngestThenPruneGraphLive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from graph_db.neo4j_client import Neo4jClient
        cls.client = Neo4jClient(_URI, _USER, _PASSWORD)

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def setUp(self):
        run = uuid.uuid4().hex[:8]
        self.uid = f"prune-{run}"
        self.pid = f"PRUNE_{run}"
        with self.client.driver.session() as s:
            # Three GVM findings from a PREVIOUS run (updated_at an hour ago),
            # each attached to a host so the orphan sweep leaves them alone.
            s.run(
                """
                CREATE (t:Technology {name: 'nginx', user_id: $u, project_id: $p})
                CREATE (m:Vulnerability:Muted {id: 'v-muted', user_id: $u, project_id: $p,
                        source: 'gvm', updated_at: datetime() - duration('PT1H')})
                CREATE (h:Vulnerability {id: 'v-human', user_id: $u, project_id: $p,
                        source: 'gvm', triage_source: 'human', triage_status: 'confirmed',
                        updated_at: datetime() - duration('PT1H')})
                CREATE (x:Vulnerability {id: 'v-plain', user_id: $u, project_id: $p,
                        source: 'gvm', updated_at: datetime() - duration('PT1H')})
                CREATE (t)-[:HAS_VULNERABILITY]->(m)
                CREATE (t)-[:HAS_VULNERABILITY]->(h)
                CREATE (t)-[:HAS_VULNERABILITY]->(x)
                """, u=self.uid, p=self.pid)

    def tearDown(self):
        with self.client.driver.session() as s:
            s.run("MATCH (n) WHERE n.user_id = $u DETACH DELETE n", u=self.uid)

    def _row(self, vid):
        with self.client.driver.session() as s:
            rec = s.run(
                "MATCH (v:Vulnerability {id: $id, user_id: $u}) "
                "RETURN v.stale_since AS stale, v:Muted AS muted, v.triage_status AS status",
                id=vid, u=self.uid).single()
        return dict(rec) if rec else None

    def _rescan_seeing(self, ids):
        """One GVM run: timestamp, clear, ingest (MERGE refreshes updated_at), prune."""
        from graph_db.mixins.base_mixin import run_timestamp
        since = run_timestamp()
        time.sleep(0.05)
        self.client.clear_gvm_data(self.uid, self.pid)
        with self.client.driver.session() as s:
            for vid in ids:
                s.run(
                    "MERGE (v:Vulnerability {id: $id, user_id: $u, project_id: $p}) "
                    "SET v.source = 'gvm', v.updated_at = datetime()",
                    id=vid, u=self.uid, p=self.pid)
        return self.client.prune_unseen_findings(self.uid, self.pid, ["gvm"], since)

    # -- row 11 ------------------------------------------------------------
    def test_a_rescan_that_no_longer_reports_them_keeps_what_a_person_touched(self):
        stats = self._rescan_seeing([])
        self.assertIsNone(self._row("v-plain"), "an unseen plain finding is deleted")
        muted, human = self._row("v-muted"), self._row("v-human")
        self.assertIsNotNone(muted, "the muted finding was deleted")
        self.assertIsNotNone(human, "the human-judged finding was deleted")
        self.assertTrue(muted["muted"], "the mute itself was lost")
        self.assertEqual(human["status"], "confirmed", "the verdict was lost")
        self.assertIsNotNone(muted["stale"], "kept but not marked stale")
        self.assertIsNotNone(human["stale"], "kept but not marked stale")
        self.assertEqual((stats["pruned"], stats["stale"]), (1, 2))

    def test_a_finding_the_scan_still_reports_is_untouched(self):
        self._rescan_seeing(["v-plain", "v-human"])
        self.assertIsNotNone(self._row("v-plain"))
        self.assertIsNone(self._row("v-human")["stale"])

    # -- regression: a stale finding that comes back -----------------------
    def test_a_finding_that_comes_back_is_no_longer_stale(self):
        self._rescan_seeing([])
        self.assertIsNotNone(self._row("v-human")["stale"], "precondition: went stale")

        stats = self._rescan_seeing(["v-human"])
        self.assertIsNone(self._row("v-human")["stale"],
                          "the scanner reports it again, so it is not resolved")
        self.assertEqual(stats["revived"], 1)
        # The one that did NOT come back stays stale.
        self.assertIsNotNone(self._row("v-muted")["stale"])


if __name__ == "__main__":
    unittest.main()
