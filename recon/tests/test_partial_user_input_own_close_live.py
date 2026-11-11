"""LIVE-Neo4j: a completed partial run leaves none of its own UserInput nodes
'running' (L-11).

recon/tests/test_partial_user_input_own_close.py pins the selection against an
in-memory graph; this runs the real create_user_input_node,
update_user_input_status and _cleanup_orphan_user_inputs against Neo4j, with
"another run" played by a node this process did not make.

Self-skips unless the neo4j driver imports AND a database answers. To run it:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo/recon \\
    -e PYTHONPATH=/repo/recon:/repo -e NEO4J_URI=bolt://neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD -e HOME=/tmp --entrypoint python \\
    redamon-recon:latest -m pytest tests/test_partial_user_input_own_close_live.py -v

Everything is scoped to throwaway project ids and DETACH DELETEd in teardown.
Addresses are TEST-NET only.
"""
from __future__ import annotations

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
USER = "l11-close-live-user"


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class TestOwnUserInputCloseLive(unittest.TestCase):
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
        self.pid = f"l11-close-{uuid.uuid4().hex[:10]}"
        self.other_pid = f"{self.pid}-other"

    def tearDown(self):
        self.uim._CREATED_THIS_RUN.clear()
        self.uim._CREATED_THIS_RUN.update(self._saved_ids)
        with self.client.driver.session() as s:
            s.run("MATCH (n) WHERE n.user_id = $uid AND n.project_id IN $pids DETACH DELETE n",
                  uid=USER, pids=[self.pid, self.other_pid]).consume()

    def _create(self, ui_id, address, project_id=None, another_run=False, linked=True):
        pid = project_id or self.pid
        self.client.create_user_input_node(
            ROOT, {"id": ui_id, "input_type": "ips", "values": [address], "tool_id": "Tlsx"},
            USER, pid)
        if another_run:
            self.uim._CREATED_THIS_RUN.discard(ui_id)
        if linked:
            with self.client.driver.session() as s:
                s.run(
                    """
                    MERGE (i:IP {address: $addr, user_id: $uid, project_id: $pid})
                    WITH i
                    MATCH (ui:UserInput {id: $ui_id, user_id: $uid, project_id: $pid})
                    MERGE (ui)-[:PRODUCED]->(i)
                    """,
                    addr=address, uid=USER, pid=pid, ui_id=ui_id,
                ).consume()

    def _node(self, ui_id, project_id=None):
        with self.client.driver.session() as s:
            rec = s.run(
                "MATCH (ui:UserInput {id: $id, user_id: $uid, project_id: $pid}) "
                "RETURN ui.status AS status, ui.completed_at IS NOT NULL AS done",
                id=ui_id, uid=USER, pid=project_id or self.pid,
            ).single()
        return dict(rec) if rec else None

    def _cleanup(self):
        from recon.partial_recon_modules.user_inputs import _cleanup_orphan_user_inputs
        return _cleanup_orphan_user_inputs(USER, self.pid)

    def test_own_node_with_results_reads_completed(self):
        self._create("ui-own", "192.0.2.60")
        self.assertEqual(self._node("ui-own"), {"status": "running", "done": False})
        self.assertEqual(self._cleanup(), 0)
        self.assertEqual(self._node("ui-own"), {"status": "completed", "done": True})

    def test_another_runs_node_stays_running(self):
        self._create("ui-own", "192.0.2.61")
        self._create("ui-other", "192.0.2.62", another_run=True)
        self._cleanup()
        self.assertEqual(self._node("ui-own")["status"], "completed")
        self.assertEqual(self._node("ui-other"), {"status": "running", "done": False})

    def test_an_error_the_module_set_is_kept(self):
        self._create("ui-failed", "192.0.2.63")
        self.client.update_user_input_status(
            "ui-failed", "error", {"error": "tlsx crashed"}, user_id=USER, project_id=self.pid)
        self._cleanup()
        self.assertEqual(self._node("ui-failed"), {"status": "error", "done": False})

    def test_own_orphan_is_deleted_not_closed(self):
        self._create("ui-empty", "192.0.2.64", linked=False)
        self.assertEqual(self._cleanup(), 1)
        self.assertIsNone(self._node("ui-empty"))

    def test_the_same_id_in_another_project_is_untouched(self):
        self._create("ui-shared-id", "192.0.2.65")
        self._create("ui-shared-id", "192.0.2.65", project_id=self.other_pid)
        self._cleanup()
        self.assertEqual(self._node("ui-shared-id")["status"], "completed")
        self.assertEqual(self._node("ui-shared-id", self.other_pid),
                         {"status": "running", "done": False})


if __name__ == "__main__":
    unittest.main()
