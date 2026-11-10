"""LIVE-Neo4j: a finding whose graph write failed survives the prune (R-20).

The pipeline's background writer is made to fail (Nuclei's
`update_graph_from_vuln_scan` raises, or reports an item error), then the real
end-of-run prune runs: the Nuclei finding written by an earlier run is kept,
while a stale finding of a source whose writer did not fail is deleted as
before, so the prune did run. A writer failure cannot be forced on the shared
stack's scans, so this is the proof of the failure path.

Self-skips unless the neo4j driver imports AND a database answers. To run it:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo/recon \\
    -e PYTHONPATH=/repo/recon:/repo -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD -e HOME=/tmp --entrypoint sh \\
    redamon-recon -c 'python -m pytest -q tests/test_graph_writer_failure_live.py'

Everything it creates is scoped to a throwaway tenant and deleted in tearDown.
"""

import os
import sys
import unittest
import uuid
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

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

NUCLEI_ID = "nuclei-live-r20"
GRAPHQL_ID = "graphql-live-r20"


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class LiveWriterFailureCase(unittest.TestCase):
    def setUp(self):
        run = uuid.uuid4().hex[:8]
        self.uid, self.pid = f"r20-{run}", f"R20_{run}"
        self.driver = _neo4j.GraphDatabase.driver(_URI, auth=(_USER, _PASSWORD))
        # Two findings an earlier run wrote: neither is re-written below.
        with self.driver.session() as s:
            s.run("""
                UNWIND $rows AS row
                CREATE (v:Vulnerability {id: row.id, source: row.source,
                        user_id: $u, project_id: $p, host: 'a.example.com',
                        name: row.id, updated_at: datetime('2020-01-01T00:00:00Z')})
                """, rows=[{"id": NUCLEI_ID, "source": "nuclei"},
                           {"id": GRAPHQL_ID, "source": "graphql_scan"}],
                  u=self.uid, p=self.pid).consume()

        from recon.helpers import circuit_breaker
        circuit_breaker.reset_registry()
        stub = {
            'TARGET_DOMAIN': 'example.com', 'SUBDOMAIN_LIST': [], 'IP_MODE': False,
            'TARGET_IPS': [], 'DOMAIN_BATCH_MODE': False, 'DOMAIN_BATCH_GROUPS': [],
            'USE_BRUTEFORCE_FOR_SUBDOMAINS': False, 'SCAN_MODULES': ['domain_discovery'],
            'UPDATE_GRAPH_DB': True, 'USER_ID': self.uid, 'PROJECT_ID': self.pid,
            'VERIFY_DOMAIN_OWNERSHIP': False, 'STEALTH_MODE': False,
            'OWNERSHIP_TOKEN': '', 'OWNERSHIP_TXT_PREFIX': '',
        }
        with mock.patch('recon.project_settings.get_settings', return_value=stub):
            for mod in [m for m in list(sys.modules) if m in ('recon.main', 'main')]:
                del sys.modules[mod]
            import recon.main as rm
        from graph_db.mixins.base_mixin import run_timestamp
        rm._RUN_STARTED_AT = run_timestamp()
        rm._COVERAGE_WRITE_FAILED = False
        self.rm = rm

    def tearDown(self):
        with self.driver.session() as s:
            s.run("MATCH (n) WHERE n.user_id = $u AND n.project_id = $p DETACH DELETE n",
                  u=self.uid, p=self.pid).consume()
        self.driver.close()
        from recon.helpers import circuit_breaker
        circuit_breaker.reset_registry()

    def _ids(self) -> set:
        with self.driver.session() as s:
            rows = s.run("MATCH (v:Vulnerability {user_id: $u, project_id: $p}) RETURN v.id AS id",
                         u=self.uid, p=self.pid)
            return {r["id"] for r in rows}

    def _run_vuln_writer(self, **behaviour):
        from graph_db.neo4j_client import Neo4jClient
        with mock.patch.object(Neo4jClient, "update_graph_from_vuln_scan", **behaviour):
            self.rm._graph_reset()
            self.rm._graph_update_bg("update_graph_from_vuln_scan", {"vuln_scan": {}},
                                     self.uid, self.pid)
            return self.rm._graph_wait_all()

    def test_a_finding_whose_write_raised_survives_the_prune(self):
        (result,) = self._run_vuln_writer(side_effect=RuntimeError("forced write failure"))
        self.assertIn("RuntimeError", result[2])
        self.rm._prune_recon_findings()
        self.assertEqual(self._ids(), {NUCLEI_ID})

    def test_a_finding_whose_write_reported_an_item_error_survives_the_prune(self):
        self._run_vuln_writer(return_value={
            "errors": [f"Finding {NUCLEI_ID} processing failed: ConstraintError"]})
        self.rm._prune_recon_findings()
        self.assertEqual(self._ids(), {NUCLEI_ID})

    def test_a_clean_write_prunes_both_as_before(self):
        self._run_vuln_writer(return_value={"errors": []})
        self.rm._prune_recon_findings()
        self.assertEqual(self._ids(), set())


if __name__ == "__main__":
    unittest.main()
