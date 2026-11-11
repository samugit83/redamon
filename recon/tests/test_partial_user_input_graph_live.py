"""LIVE-Neo4j: a partial run's UserInput reads its final status, and survives a
concurrent run's cleanup (L-11).

recon/tests/test_partial_user_input_cleanup.py pins which orphans the cleanup
picks and that every caller passes the tenant; tests/test_user_input_status_writer.py
pins the writer's MATCH key. Only a real graph shows the Cypher does it: the real
create_user_input_node, update_user_input_status and _cleanup_orphan_user_inputs
run against Neo4j, with "another run" played by a node this process did not make.

Self-skips unless the neo4j driver imports AND a database answers. To run it:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo/recon \\
    -e PYTHONPATH=/repo/recon:/repo -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD -e HOME=/tmp --entrypoint python \\
    redamon-recon:latest -m pytest tests/test_partial_user_input_graph_live.py -v

Everything is scoped to throwaway project ids and DETACH DELETEd in teardown.
Addresses are TEST-NET only.
"""
from __future__ import annotations

import json
import os
import sys
import unittest
import uuid

_RECON = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_REPO = os.path.dirname(_RECON)
for _p in (_REPO, _RECON):
    if _p not in sys.path:
        sys.path.insert(0, _p)

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

ROOT = "example.test"
USER = "l11-live-user"


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class TestPartialUserInputGraphLive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.setdefault("NEO4J_USER", _USER)
        os.environ.setdefault("NEO4J_URI", _URI)
        from graph_db.neo4j_client import Neo4jClient
        cls.client = Neo4jClient(_URI, _USER, _PASSWORD)

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def setUp(self):
        from graph_db.mixins.recon import user_input_mixin as uim
        self.uim = uim
        self._saved_ids = set(uim._CREATED_THIS_RUN)
        uim._CREATED_THIS_RUN.clear()
        self.pid = f"l11-live-{uuid.uuid4().hex[:10]}"
        self.other_pid = f"{self.pid}-other"

    def tearDown(self):
        self.uim._CREATED_THIS_RUN.clear()
        self.uim._CREATED_THIS_RUN.update(self._saved_ids)
        with self.client.driver.session() as s:
            s.run("MATCH (n) WHERE n.user_id = $uid AND n.project_id IN $pids DETACH DELETE n",
                  uid=USER, pids=[self.pid, self.other_pid]).consume()

    # -- helpers ---------------------------------------------------------------

    def _create(self, ui_id, values, project_id=None, another_run=False):
        """create_user_input_node as this run, or as a concurrent run (a node this
        process did not make)."""
        self.client.create_user_input_node(
            ROOT, {"id": ui_id, "input_type": "ips", "values": values, "tool_id": "Httpx"},
            USER, project_id or self.pid)
        if another_run:
            self.uim._CREATED_THIS_RUN.discard(ui_id)

    def _produce(self, ui_id, address):
        with self.client.driver.session() as s:
            s.run(
                """
                MERGE (i:IP {address: $addr, user_id: $uid, project_id: $pid})
                WITH i
                MATCH (ui:UserInput {id: $ui_id, user_id: $uid, project_id: $pid})
                MERGE (ui)-[:PRODUCED]->(i)
                """,
                addr=address, uid=USER, pid=self.pid, ui_id=ui_id,
            ).consume()

    def _node(self, ui_id, project_id=None):
        with self.client.driver.session() as s:
            rec = s.run(
                "MATCH (ui:UserInput {id: $id, user_id: $uid, project_id: $pid}) "
                "RETURN ui.status AS status, ui.stats AS stats, ui.completed_at IS NOT NULL AS done",
                id=ui_id, uid=USER, pid=project_id or self.pid,
            ).single()
        return dict(rec) if rec else None

    def _cleanup(self, project_id=None):
        from recon.partial_recon_modules.user_inputs import _cleanup_orphan_user_inputs
        return _cleanup_orphan_user_inputs(USER, project_id or self.pid)

    # -- the status update -----------------------------------------------------

    def test_the_status_update_reaches_the_node(self):
        self._create("ui-done", ["192.0.2.10"])
        self.assertEqual(self._node("ui-done")["status"], "running")
        self._produce("ui-done", "192.0.2.10")
        self.assertTrue(self.client.update_user_input_status(
            "ui-done", "completed", {"probed": 1}, user_id=USER, project_id=self.pid))
        node = self._node("ui-done")
        self.assertEqual(node["status"], "completed")
        self.assertTrue(node["done"])
        self.assertEqual(json.loads(node["stats"]), {"probed": 1})

    def test_a_failed_run_reads_error_without_completed_at(self):
        self._create("ui-failed", ["192.0.2.11"])
        self.client.update_user_input_status(
            "ui-failed", "error", {"error": "httpx crashed"}, user_id=USER, project_id=self.pid)
        node = self._node("ui-failed")
        self.assertEqual(node["status"], "error")
        self.assertFalse(node["done"])

    def test_another_projects_node_with_the_same_id_is_untouched(self):
        self._create("ui-shared-id", ["192.0.2.12"])
        self._create("ui-shared-id", ["192.0.2.12"], project_id=self.other_pid)
        self.client.update_user_input_status(
            "ui-shared-id", "completed", None, user_id=USER, project_id=self.pid)
        self.assertEqual(self._node("ui-shared-id")["status"], "completed")
        self.assertEqual(self._node("ui-shared-id", self.other_pid)["status"], "running")

    # -- the cleanup -----------------------------------------------------------

    def test_a_concurrent_runs_node_survives_this_runs_cleanup(self):
        # Run B (httpx, typed IPs) made its node before scanning and is still scanning.
        self._create("ui-run-b", ["192.0.2.20"], another_run=True)
        # This run (A) made a node and found nothing for it.
        self._create("ui-run-a", ["192.0.2.21"])
        self.assertEqual(self._cleanup(), 1)
        self.assertIsNone(self._node("ui-run-a"))
        self.assertIsNotNone(self._node("ui-run-b"))
        # B finishes: its results link to its node and it reads completed.
        self._produce("ui-run-b", "192.0.2.20")
        self.client.update_user_input_status(
            "ui-run-b", "completed", {"probed": 1}, user_id=USER, project_id=self.pid)
        self.assertEqual(self._node("ui-run-b")["status"], "completed")

    def test_a_finished_runs_orphan_is_deleted_by_any_run(self):
        self._create("ui-finished", ["192.0.2.30"], another_run=True)
        self.client.update_user_input_status(
            "ui-finished", "completed", None, user_id=USER, project_id=self.pid)
        self.assertEqual(self._cleanup(), 1)
        self.assertIsNone(self._node("ui-finished"))

    def test_a_node_with_results_is_never_deleted(self):
        self._create("ui-linked", ["192.0.2.40"])
        self._produce("ui-linked", "192.0.2.40")
        self.assertEqual(self._cleanup(), 0)
        self.assertIsNotNone(self._node("ui-linked"))

    def test_the_cleanup_stays_in_its_project(self):
        self._create("ui-elsewhere", ["192.0.2.50"], project_id=self.other_pid)
        self.assertEqual(self._cleanup(), 0)
        self.assertIsNotNone(self._node("ui-elsewhere", self.other_pid))


if __name__ == "__main__":
    unittest.main()
