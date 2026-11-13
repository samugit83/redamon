"""
The agent's half of an ownership transfer (RBAC step 5.12, SH-15): the master-key
`POST /graph/retenant` that moves a project's graph to its new owner, and
`GET /agent-sessions/project-work`, which tells the webapp what the agent itself
is running on a project (agent runs, the triage run, CodeFix runs) before it
accepts a transfer.

A run keeps the tenant it started with (a ticket's `ten`, a triage run's
owner), so moving the graph under it would split the project between two
owners. The webapp checks first and holds the project lock; the route refuses
again with what it sees, and never touches the graph then. The graph work is
`TenancyMixin.retenant_project` (tested in tests/test_graph_retenant.py); here
its client is a double and the route's mapping of its outcomes is what is
asserted: invalid 400, a key collision 409, a failed move (graph as it was) or
a failed run back (project split) 500 with the code, an unreachable graph 503.

Run: ./agentic/run_tests.sh tests/test_graph_retenant_route.py
"""
import asyncio
import os
import sys
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from unittest import mock

_AGENTIC_DIR = str(Path(__file__).resolve().parents[1])
if _AGENTIC_DIR not in sys.path:
    sys.path.insert(0, _AGENTIC_DIR)

try:
    import websocket_api  # noqa: F401
    _HAVE = True
except Exception:  # pragma: no cover - only outside the agent image
    _HAVE = False

if _HAVE:
    from websocket_api import PROXIED_SOCKETS, WebSocketManager  # noqa: E402
    from graph_db.mixins.tenancy_mixin import RetenantError  # noqa: E402

MASTER = "master-key-for-retenant-test"
SCANNER = "scanner-key-for-retenant-test"
BODY = {"project_id": "proj-1", "from_user_id": "user-old", "to_user_id": "user-new"}
RESULT = {
    "project_id": "proj-1", "from_user_id": "user-old", "to_user_id": "user-new",
    "nodes": {"Domain": 1, "Vulnerability": 3}, "unlisted": {}, "relationships": 0,
    "total_nodes": 4, "already_at_target": {}, "elapsed_ms": 12,
}


class _FakeTask:
    def __init__(self, done=False):
        self._done = done

    def done(self):
        return self._done

    def cancel(self):
        self._done = True
        return True


class _FakeWS:
    async def close(self, code=1000, reason=""):
        pass


def _claims(sub, pid, ten=None):
    return {"sub": sub, "pid": pid, "sid": "sock", **({"ten": ten} if ten else {})}


@unittest.skipUnless(_HAVE, "agent deps unavailable (run in-container)")
class _Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient

        @asynccontextmanager
        async def fake_lifespan(_app):
            yield

        with mock.patch("api.lifespan", fake_lifespan):
            import api as api_module
        cls.api = api_module
        cls.client = TestClient(api_module.app)

    def setUp(self):
        env = mock.patch.dict(os.environ, {"INTERNAL_API_KEY": MASTER, "SCANNER_API_KEY": SCANNER})
        env.start()
        self.addCleanup(env.stop)
        self.mgr = WebSocketManager()
        patch = mock.patch.object(self.api, "ws_manager", self.mgr)
        patch.start()
        self.addCleanup(patch.stop)
        self.graph = mock.MagicMock()
        self.graph.retenant_project.return_value = RESULT
        client = mock.patch.object(self.api, "_triage_graph_client", return_value=self.graph)
        client.start()
        self.addCleanup(client.stop)
        self.sockets = []
        self.addCleanup(self._drop_sockets)
        from cypherfix_triage import websocket_handler
        self.triage_runs = websocket_handler._RUNS
        saved = dict(self.triage_runs)
        self.addCleanup(lambda: (self.triage_runs.clear(), self.triage_runs.update(saved)))

    def _drop_sockets(self):
        for ws in self.sockets:
            PROXIED_SOCKETS.remove(ws)

    def _socket(self, kind, sub, pid):
        ws = _FakeWS()
        self.sockets.append(ws)
        PROXIED_SOCKETS.add(ws, kind, _claims(sub, pid))
        return ws

    def _triage_run(self, pid, active=True):
        run = mock.MagicMock()
        run.is_active = active
        self.triage_runs[pid] = run

    def _deps(self, method, path):
        for r in self.api.app.routes:
            if getattr(r, "path", "") == path and method in (getattr(r, "methods", None) or ()):
                return [d.dependency for d in getattr(r, "dependencies", [])]
        self.fail(f"{method} {path} is not registered")


class RetenantRoute(_Base):
    def _post(self, body=None, key=MASTER):
        headers = {"x-internal-key": key} if key else {}
        return self.client.post("/graph/retenant", json=BODY if body is None else body, headers=headers)

    def test_master_key_only_and_fail_closed(self):
        from llm_guard import require_master_internal_auth
        self.assertEqual(self._deps("POST", "/graph/retenant"), [require_master_internal_auth])
        self.assertEqual(self._post(key=None).status_code, 401)
        self.assertEqual(self._post(key=SCANNER).status_code, 401)
        with mock.patch.dict(os.environ, {"INTERNAL_API_KEY": ""}):
            self.assertEqual(self._post().status_code, 503)
        self.graph.retenant_project.assert_not_called()

    def test_moves_the_project_to_the_new_owner_and_answers_the_counts(self):
        res = self._post()
        self.assertEqual(res.status_code, 200, res.text)
        self.assertEqual(res.json(), RESULT)
        self.graph.retenant_project.assert_called_once_with("proj-1", "user-old", "user-new")

    def test_a_repeated_call_is_passed_on_again_the_mixin_is_idempotent(self):
        self.assertEqual(self._post().status_code, 200)
        self.graph.retenant_project.return_value = {**RESULT, "nodes": {}, "total_nodes": 0}
        res = self._post()
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["total_nodes"], 0)
        self.assertEqual(self.graph.retenant_project.call_count, 2)

    def test_the_reverse_call_runs_the_move_back(self):
        res = self._post({"project_id": "proj-1", "from_user_id": "user-new", "to_user_id": "user-old"})
        self.assertEqual(res.status_code, 200)
        self.graph.retenant_project.assert_called_once_with("proj-1", "user-new", "user-old")

    def test_malformed_ids_are_refused_before_the_graph(self):
        for body in (
            {**BODY, "project_id": ""},
            {**BODY, "to_user_id": "a b"},
            {**BODY, "from_user_id": "x" * 65},
            {**BODY, "from_user_id": "user/../x"},
            {"project_id": "proj-1", "from_user_id": "user-old"},
        ):
            res = self._post(body)
            self.assertIn(res.status_code, (400, 422), body)
        self.graph.retenant_project.assert_not_called()

    def test_refused_while_an_agent_run_of_the_project_is_live(self):
        self.mgr.register_task("user-collab:proj-1:sess-a", _FakeTask())
        res = self._post()
        self.assertEqual(res.status_code, 409)
        self.assertEqual(res.json()["code"], "project_busy")
        self.assertEqual(res.json()["busy"], ["agent_run"])
        self.graph.retenant_project.assert_not_called()

    def test_a_finished_run_or_another_projects_run_does_not_hold_it(self):
        self.mgr.register_task("user-old:proj-1:sess-done", _FakeTask(done=True))
        self.mgr.register_task("user-old:proj-2:sess-b", _FakeTask())
        self._socket("cypherfix-codefix", "user-old", "proj-2")
        self._triage_run("proj-2")
        self._triage_run("proj-1", active=False)
        self.assertEqual(self._post().status_code, 200)

    def test_refused_while_a_codefix_run_of_the_project_is_open(self):
        self._socket("cypherfix-codefix", "user-old", "proj-1")
        res = self._post()
        self.assertEqual(res.status_code, 409)
        self.assertEqual(res.json()["busy"], ["codefix_run"])
        self.graph.retenant_project.assert_not_called()

    def test_refused_while_the_projects_triage_run_works(self):
        self._triage_run("proj-1")
        res = self._post()
        self.assertEqual(res.status_code, 409)
        self.assertEqual(res.json()["busy"], ["triage_run"])
        self.graph.retenant_project.assert_not_called()

    def test_an_open_terminal_or_triage_socket_alone_does_not_hold_it(self):
        # Neither runs anything that writes under the old tenant by itself; the webapp closes
        # every socket of the project before it calls, so none survives the transfer.
        self._socket("kali-terminal", "user-old", "proj-1")
        self._socket("cypherfix-triage", "user-old", "proj-1")
        self.assertEqual(self._post().status_code, 200)

    def test_no_session_manager_answers_503_and_moves_nothing(self):
        with mock.patch.object(self.api, "ws_manager", None):
            res = self._post()
        self.assertEqual(res.status_code, 503)
        self.assertEqual(res.json()["code"], "agent_not_ready")
        self.graph.retenant_project.assert_not_called()

    def test_the_mixins_refusals_and_failures_keep_their_codes(self):
        cases = (
            (RetenantError("retenant_invalid", "same user"), 400, {}),
            (RetenantError("retenant_conflict", "collide", conflicts={"Domain": 2}), 409, {"conflicts": {"Domain": 2}}),
            (RetenantError("retenant_failed", "write failed"), 500, {}),
            (RetenantError("retenant_rollback_failed", "split", moved={"nodes": {"Domain": 1}}), 500,
             {"moved": {"nodes": {"Domain": 1}}}),
        )
        for exc, status, extra in cases:
            self.graph.retenant_project.side_effect = exc
            with self.assertLogs("api", level="ERROR") if status == 500 else _no_logs():
                res = self._post()
            self.assertEqual(res.status_code, status, exc.code)
            body = res.json()
            self.assertEqual(body["code"], exc.code)
            for key, value in extra.items():
                self.assertEqual(body[key], value)
            # The mixin's message can name labels and counts, never target data; still the
            # answer keeps to a fixed sentence per code.
            self.assertNotIn("write failed", body["error"])

    def test_an_unreachable_graph_answers_503_graph_unavailable(self):
        self.graph.retenant_project.side_effect = OSError("connection refused")
        with self.assertLogs("api", level="ERROR"):
            res = self._post()
        self.assertEqual(res.status_code, 503)
        self.assertEqual(res.json()["code"], "graph_unavailable")
        self.assertNotIn("refused", res.json()["error"])


class ProjectWorkRoute(_Base):
    def _get(self, pid="proj-1", key=MASTER):
        headers = {"x-internal-key": key} if key else {}
        return self.client.get("/agent-sessions/project-work", params={"project_id": pid} if pid else {}, headers=headers)

    def test_master_key_only_and_fail_closed(self):
        from llm_guard import require_master_internal_auth
        self.assertEqual(self._deps("GET", "/agent-sessions/project-work"), [require_master_internal_auth])
        self.assertEqual(self._get(key=None).status_code, 401)
        self.assertEqual(self._get(key=SCANNER).status_code, 401)
        with mock.patch.dict(os.environ, {"INTERNAL_API_KEY": ""}):
            self.assertEqual(self._get().status_code, 503)

    def test_an_idle_project_answers_nothing_running(self):
        res = self._get()
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json(), {
            "project_id": "proj-1", "session_ids": [], "codefix_sockets": 0, "triage_run": False})

    def test_names_the_agent_runs_codefix_runs_and_triage_run_of_that_project_only(self):
        self.mgr.register_task("user-a:proj-1:sess-a", _FakeTask())
        self.mgr.register_task("user-b:proj-1:sess-b", _FakeTask())
        self.mgr.register_task("user-a:proj-2:sess-c", _FakeTask())
        self.mgr.register_task("user-a:proj-1:sess-d", _FakeTask(done=True))
        self._socket("cypherfix-codefix", "user-a", "proj-1")
        self._socket("cypherfix-codefix", "user-b", "proj-1")
        self._socket("cypherfix-codefix", "user-a", "proj-2")
        self._socket("kali-terminal", "user-a", "proj-1")
        self._triage_run("proj-1")
        body = self._get().json()
        self.assertEqual(sorted(body["session_ids"]), ["sess-a", "sess-b"])
        self.assertEqual(body["codefix_sockets"], 2)
        self.assertTrue(body["triage_run"])

    def test_a_project_is_required(self):
        self.assertEqual(self._get(pid=None).status_code, 422)
        self.assertEqual(self._get(pid="").status_code, 422)

    def test_no_session_manager_answers_503(self):
        with mock.patch.object(self.api, "ws_manager", None):
            res = self._get()
        self.assertEqual(res.status_code, 503)


class _no_logs:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


if __name__ == "__main__":
    asyncio.set_event_loop(asyncio.new_event_loop())
    unittest.main(verbosity=2)
