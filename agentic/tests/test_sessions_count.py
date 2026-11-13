"""
The agent counts one person's agent runs in progress for the agent-run quota
(step 6.8; GV-11): `WebSocketManager.live_run_count()` and the master-key
`GET /agent-sessions/count?user_id`.

A run counts when its key "<user>:<project>:<session>" names the person as its
user (after 5.3 the session's person, so a collaborator's run on a shared
project is theirs, and an admin's act-as run is the member's) and its task is
still running; an open socket with no run, a finished run and another person's
run do not. The route is master-key only and fail-closed, refuses a missing or
empty user, and answers 503 while the manager is not up.

Run: ./agentic/run_tests.sh tests/test_sessions_count.py
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

# Outside the guard: a name missing from websocket_api is a failure, never a skip.
if _HAVE:
    from websocket_api import WebSocketConnection, WebSocketManager  # noqa: E402

MASTER = "master-key-for-test"
SCANNER = "scanner-key-for-test"


class _FakeWS:
    def __init__(self):
        self.client = "test"

    async def close(self, code=1000, reason=""):
        pass

    async def send_json(self, msg):
        pass


class _FakeTask:
    def __init__(self, done=False):
        self._done = done

    def done(self):
        return self._done

    def cancel(self):
        self._done = True
        return True


@unittest.skipUnless(_HAVE, "agent deps unavailable (run in-container)")
class LiveRunCount(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.mgr = WebSocketManager()
        self.tasks = []

    async def asyncTearDown(self):
        for t in self.tasks:
            t.cancel()
        await asyncio.sleep(0)

    def _run(self, key, actor_id=None):
        task = asyncio.create_task(asyncio.sleep(3600))
        self.tasks.append(task)
        self.mgr.register_task(key, task, actor_id=actor_id)
        return task

    async def test_counts_only_that_persons_running_runs(self):
        self._run("uA:p1:s1")
        self._run("uA:p2:s2")
        self._run("uB:p1:s3")
        self.assertEqual(self.mgr.live_run_count("uA"), 2)
        self.assertEqual(self.mgr.live_run_count("uB"), 1)
        self.assertEqual(self.mgr.live_run_count("nobody"), 0)
        self.assertEqual(self.mgr.live_run_count(""), 0)

    async def test_a_finished_run_and_an_idle_socket_do_not_count(self):
        done = self._run("uA:p1:s1")
        self._run("uA:p1:s2")
        conn = WebSocketConnection(_FakeWS())
        await self.mgr.authenticate(conn, "uA", "p3", "s3", verified=True)
        done.cancel()
        await asyncio.sleep(0)
        self.assertEqual(self.mgr.live_run_count("uA"), 1)

    async def test_an_act_as_run_is_the_members(self):
        self._run("mem:p1:s1", actor_id="adm")
        self.assertEqual(self.mgr.live_run_count("mem"), 1)
        self.assertEqual(self.mgr.live_run_count("adm"), 0)

    async def test_the_user_is_the_whole_first_part_of_the_key(self):
        self._run("uA:p1:s1")
        self._run("uAB:p1:s2")
        self.assertEqual(self.mgr.live_run_count("uA"), 1)


@unittest.skipUnless(_HAVE, "agent deps unavailable (run in-container)")
class Route(unittest.TestCase):
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
        self.mgr.register_task("uA:p1:s1", _FakeTask())
        self.mgr.register_task("uA:p2:s2", _FakeTask())
        self.mgr.register_task("uA:p2:s9", _FakeTask(done=True))
        self.mgr.register_task("uB:p1:s3", _FakeTask())
        mgr = mock.patch.object(self.api, "ws_manager", self.mgr)
        mgr.start()
        self.addCleanup(mgr.stop)

    def _get(self, params, key=MASTER):
        headers = {"x-internal-key": key} if key else {}
        return self.client.get("/agent-sessions/count", params=params, headers=headers)

    def test_declares_the_configured_master_gate(self):
        from llm_guard import require_configured_master_auth
        deps = {}
        for r in self.api.app.routes:
            for m in getattr(r, "methods", None) or ():
                deps[(m, r.path)] = [d.dependency for d in getattr(r, "dependencies", [])]
        self.assertEqual(deps[("GET", "/agent-sessions/count")], [require_configured_master_auth])

    def test_master_only_and_fail_closed(self):
        params = {"user_id": "uA"}
        self.assertEqual(self._get(params, key=None).status_code, 401)
        self.assertEqual(self._get(params, key=SCANNER).status_code, 401)
        with mock.patch.dict(os.environ, {"INTERNAL_API_KEY": ""}):
            self.assertEqual(self._get(params).status_code, 503)

    def test_counts_the_persons_running_runs(self):
        res = self._get({"user_id": "uA"})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json(), {"user_id": "uA", "count": 2})
        self.assertEqual(self._get({"user_id": "nobody"}).json(), {"user_id": "nobody", "count": 0})

    def test_a_user_is_required(self):
        self.assertEqual(self._get({}).status_code, 422)
        self.assertEqual(self._get({"user_id": ""}).status_code, 422)

    def test_no_manager_answers_503(self):
        with mock.patch.object(self.api, "ws_manager", None):
            res = self._get({"user_id": "uA"})
        self.assertEqual(res.status_code, 503)
        self.assertEqual(res.json(), {"error": "agent not ready"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
