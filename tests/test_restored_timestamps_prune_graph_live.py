"""LIVE-Neo4j proof that a restored finding is pruned like any other (R-38).

A project export and a Scan Timeline snapshot flatten every Neo4j DateTime to
an ISO string (`webapp/src/lib/graphSerialize.ts`), and a restore used to write
that string back as it was. The prune compared `n.updated_at <
datetime($since)`, and a string against a DateTime is null in Cypher, so a
restored finding the scanners stopped reporting was never deleted nor stamped
stale, and a restored stale one never revived. Graphs restored before the
restore wrote DateTimes keep their strings, so the prune and the revive read
those too; a string that is no timestamp at all keeps its finding rather than
failing the whole prune.

Self-skips unless the neo4j driver imports AND a database answers. To run it
against the dev stack, with NEO4J_PASSWORD exported from the repo .env:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m pytest tests/test_restored_timestamps_prune_graph_live.py -v
"""

import os
import sys
import time
import unittest
import uuid
from datetime import datetime, timedelta, timezone

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


def _exported(moment: datetime) -> str:
    """A DateTime as graphSerialize.ts writes it: whole seconds, `Z`."""
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class TestRestoredTimestampsPruneGraphLive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from graph_db.neo4j_client import Neo4jClient
        cls.client = Neo4jClient(_URI, _USER, _PASSWORD)

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def setUp(self):
        run = uuid.uuid4().hex[:8]
        self.uid, self.pid = f"r38-{run}", f"R38_{run}"
        hour_ago = _exported(datetime.now(timezone.utc) - timedelta(hours=1))
        with self.client.driver.session() as s:
            s.run(
                """
                CREATE (:Vulnerability {id: 'restored-plain', user_id: $u, project_id: $p,
                        source: 'nuclei', updated_at: $old})
                CREATE (:Vulnerability:Muted {id: 'restored-muted', user_id: $u, project_id: $p,
                        source: 'nuclei', muted_by: 'user-1', updated_at: $old})
                CREATE (:Vulnerability {id: 'restored-python-iso', user_id: $u, project_id: $p,
                        source: 'nuclei', updated_at: $old_iso})
                CREATE (:Vulnerability {id: 'not-a-timestamp', user_id: $u, project_id: $p,
                        source: 'nuclei', updated_at: 'unknown'})
                CREATE (:Vulnerability {id: 'native-old', user_id: $u, project_id: $p,
                        source: 'nuclei', updated_at: datetime() - duration('PT1H')})
                """,
                u=self.uid, p=self.pid, old=hour_ago,
                old_iso=(datetime.now(timezone.utc) - timedelta(hours=1)).isoformat())

    def tearDown(self):
        with self.client.driver.session() as s:
            s.run("MATCH (n) WHERE n.user_id = $u DETACH DELETE n", u=self.uid)

    def _row(self, vid):
        with self.client.driver.session() as s:
            rec = s.run(
                "MATCH (v:Vulnerability {id: $id, user_id: $u, project_id: $p}) "
                "RETURN v.stale_since AS stale",
                id=vid, u=self.uid, p=self.pid).single()
        return dict(rec) if rec else None

    def _prune(self):
        from graph_db.mixins.base_mixin import run_timestamp
        since = run_timestamp()
        time.sleep(0.05)
        return self.client.prune_unseen_findings(self.uid, self.pid, ["nuclei"], since)

    def test_a_restored_finding_no_longer_reported_is_pruned(self):
        stats = self._prune()
        self.assertIsNone(self._row("restored-plain"), "a restored stale finding is deleted")
        self.assertIsNone(self._row("restored-python-iso"))
        self.assertIsNone(self._row("native-old"), "a native DateTime prunes as before")
        self.assertEqual(stats["pruned"], 3)

    def test_a_restored_muted_finding_is_stamped_stale(self):
        stats = self._prune()
        row = self._row("restored-muted")
        self.assertIsNotNone(row, "an operator's mute is never deleted")
        self.assertIsNotNone(row["stale"], "and it shows as resolved")
        self.assertEqual(stats["stale"], 1)

    def test_a_value_that_is_no_timestamp_keeps_its_finding(self):
        self._prune()
        row = self._row("not-a-timestamp")
        self.assertIsNotNone(row, "an unreadable updated_at is not read as 'gone'")
        self.assertIsNone(row["stale"])

    def test_a_restored_stale_finding_reported_again_revives(self):
        from graph_db.mixins.base_mixin import run_timestamp
        since = run_timestamp()
        time.sleep(1.1)  # the exported form has whole seconds only
        with self.client.driver.session() as s:
            s.run(
                """
                MATCH (v:Vulnerability {id: 'restored-muted', user_id: $u, project_id: $p})
                SET v.stale_since = datetime() - duration('PT1H'), v.updated_at = $now
                """,
                u=self.uid, p=self.pid, now=_exported(datetime.now(timezone.utc)))
        stats = self.client.prune_unseen_findings(self.uid, self.pid, ["nuclei"], since)
        self.assertIsNone(self._row("restored-muted")["stale"])
        self.assertEqual(stats["revived"], 1)


if __name__ == "__main__":
    unittest.main()
