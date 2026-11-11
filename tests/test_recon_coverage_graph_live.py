"""LIVE-Neo4j proof that a degraded recon run keeps what it could not re-check.

  * prune_unseen_findings(keep_hosts=...) leaves every finding about a skipped
    host untouched (not deleted, not stamped stale), however the writer stored
    the host, and still prunes the same source's findings on other hosts;
  * update_graph_coverage stamps only this project's Domain, and tags each
    gap with the scan root whose group cut it (21a4c69f, one Domain per
    registrable domain: several roots share that record).

Self-skips unless the neo4j driver imports AND a database answers. To run it:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m pytest tests/test_recon_coverage_graph_live.py -v
"""

import json
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

# (id, source, host-bearing properties) - one per writer shape, on the skipped
# host (a.example.test) and on a healthy one (b.example.test).
_FINDINGS = [
    ("nuc-a-host", "nuclei", {"host": "a.example.test", "matched_at": "https://a.example.test/x"}),
    ("nuc-a-url", "nuclei", {"host": "https://a.example.test:8443"}),
    ("sec-a", "security_check", {"url": "https://a.example.test/admin", "hostname": "a.example.test"}),
    ("js-a", "js_recon", {"source_url": "https://a.example.test/app.js",
                          "base_url": "https://a.example.test"}),
    ("gql-a", "graphql_scan", {"endpoint": "https://a.example.test/graphql"}),
    ("ip-a", "security_check", {"url": "https://198.51.100.7", "matched_ip": "198.51.100.7"}),
    ("list-host", "nuclei", {"host": ["a.example.test"]}),  # a non-string never breaks the query
    ("nuc-b", "nuclei", {"host": "b.example.test", "matched_at": "https://b.example.test/"}),
    ("sec-b", "security_check", {"url": "https://b.example.test/admin"}),
    ("lookalike", "nuclei", {"host": "xa.example.test"}),
]


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class TestReconCoverageGraphLive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from graph_db.neo4j_client import Neo4jClient
        cls.client = Neo4jClient(_URI, _USER, _PASSWORD)

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def setUp(self):
        run = uuid.uuid4().hex[:8]
        self.uid = f"coverage-{run}"
        self.pid = f"COVERAGE_{run}"
        self.other_pid = f"COVERAGE_OTHER_{run}"
        with self.client.driver.session() as s:
            s.run("CREATE (:Domain {name: 'example.test', user_id: $u, project_id: $p})",
                  u=self.uid, p=self.pid)
            s.run("CREATE (:Domain {name: 'example.test', user_id: $u, project_id: $p})",
                  u=self.uid, p=self.other_pid)
            for vid, source, props in _FINDINGS:
                s.run(
                    """
                    CREATE (t:Technology {name: $vid, user_id: $u, project_id: $p})
                    CREATE (v:Vulnerability {id: $vid, user_id: $u, project_id: $p,
                            source: $source, updated_at: datetime() - duration('PT1H')})
                    SET v += $props
                    CREATE (t)-[:HAS_VULNERABILITY]->(v)
                    """, vid=vid, source=source, props=props, u=self.uid, p=self.pid)

    def tearDown(self):
        with self.client.driver.session() as s:
            s.run("MATCH (n) WHERE n.user_id = $u DETACH DELETE n", u=self.uid)

    def _surviving(self):
        with self.client.driver.session() as s:
            rows = s.run("MATCH (v:Vulnerability {user_id: $u, project_id: $p}) "
                         "RETURN v.id AS id, v.stale_since AS stale", u=self.uid, p=self.pid)
            return {r["id"]: r["stale"] for r in rows}

    def test_findings_on_a_skipped_host_survive_the_prune(self):
        from graph_db.mixins.base_mixin import run_timestamp
        since = run_timestamp()
        time.sleep(0.05)
        self.client.prune_unseen_findings(
            self.uid, self.pid, ["nuclei", "security_check", "js_recon", "graphql_scan"], since,
            keep_hosts=["a.example.test", "198.51.100.7"])
        left = self._surviving()
        self.assertEqual(set(left), {"nuc-a-host", "nuc-a-url", "sec-a", "js-a", "gql-a", "ip-a"})
        self.assertTrue(all(stale is None for stale in left.values()))

    def test_without_keep_hosts_everything_unseen_is_pruned(self):
        from graph_db.mixins.base_mixin import run_timestamp
        since = run_timestamp()
        time.sleep(0.05)
        self.client.prune_unseen_findings(
            self.uid, self.pid, ["nuclei", "security_check", "js_recon", "graphql_scan"], since)
        self.assertEqual(self._surviving(), {})

    def test_coverage_is_stamped_on_this_projects_domain_only(self):
        record = {"at": "2026-01-01T00:00:00+00:00",
                  "gaps_json": '[{"source":"nuclei"}]',
                  "skipped_hosts": ["a.example.test:443"], "nuclei_truncated": True}
        self.assertEqual(self.client.update_graph_coverage(self.uid, self.pid, "example.test", record), 1)
        self.assertEqual(self.client.update_graph_coverage(
            self.uid, self.pid, "not-a-domain.test", record), 0)
        with self.client.driver.session() as s:
            rows = {r["p"]: r for r in s.run(
                "MATCH (d:Domain {user_id: $u}) RETURN d.project_id AS p, "
                "d.recon_coverage_gaps AS gaps, d.recon_skipped_hosts AS hosts, "
                "d.recon_nuclei_truncated AS truncated, d.recon_coverage_at AS at, "
                "d.recon_coverage_roots AS roots", u=self.uid)}
        mine, other = rows[self.pid], rows[self.other_pid]
        self.assertEqual(json.loads(mine["gaps"]), [{"source": "nuclei", "root": "example.test"}])
        self.assertEqual(list(mine["roots"]), ["example.test"])
        self.assertEqual(list(mine["hosts"]), ["a.example.test:443"])
        self.assertIs(mine["truncated"], True)
        self.assertIsNotNone(mine["at"])
        self.assertIsNone(other["gaps"])
        self.assertIsNone(other["roots"])
        self.assertIsNone(other["at"])


if __name__ == "__main__":
    unittest.main()
