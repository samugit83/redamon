"""
The agent stops the runs of one user (DV-22), so a member's emergency stop ends
their own runs and nobody else's (HD-07, F-06).

Every run is registered under "<user>:<project>:<session>" (WebSocketManager),
where <user> is the ticket's subject: the EFFECTIVE user, so a run an admin
started acting as a member is the member's. `stop_for_user` parses those keys
exactly as `live_session_ids` does and stops each match with `stop_session`, which
also cancels the run's in-flight tool tasks; the global emergency stop now goes
through `stop_session` too. The master-key `POST /agent-sessions/stop-for`
exposes it to the webapp.

Run: ./agentic/run_tests.sh tests/test_stop_for_user.py
"""
import asyncio
import logging
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
    from websocket_api import (  # noqa: E402
        EMERGENCY_STOP_ALL_MESSAGE, EMERGENCY_STOP_OWN_MESSAGE, MessageType, WebSocketConnection,
        WebSocketManager,
    )

MASTER = "master-key-for-test"
SCANNER = "scanner-key-for-test"


class _FakeWS:
    def __init__(self):
        self.client = "test"
        self.sent = []

    async def close(self, code=1000, reason=""):
        pass

    async def send_json(self, msg):
        self.sent.append(msg)


class _FakeTask:
    """A run seen from another event loop (the route tests): only done() and cancel()."""

    def __init__(self, done=False):
        self._done = done
        self.cancelled = False

    def done(self):
        return self._done or self.cancelled

    def cancel(self):
        self.cancelled = True
        return True


def _stopped_frames(ws):
    return [m for m in ws.sent if m.get("type") == MessageType.STOPPED.value]


@unittest.skipUnless(_HAVE, "agent deps unavailable (run in-container)")
class StopForUser(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.mgr = WebSocketManager()
        self.tasks = {}
        self.sockets = {}
        self.conv = mock.AsyncMock()
        patcher = mock.patch("websocket_api.update_conversation", self.conv)
        patcher.start()
        self.addCleanup(patcher.stop)

    async def asyncTearDown(self):
        for t in self.tasks.values():
            t.cancel()
        await asyncio.sleep(0)

    async def _run(self, key, *, socket=True, actor_id=None):
        task = asyncio.create_task(asyncio.sleep(3600))
        self.tasks[key] = task
        self.mgr.register_task(key, task, actor_id=actor_id)
        if socket:
            user, project, session = key.split(":", 2)
            ws = _FakeWS()
            conn = WebSocketConnection(ws)
            await self.mgr.authenticate(conn, user, project, session, verified=True)
            self.sockets[key] = ws
        return task

    async def test_stops_only_that_users_sessions(self):
        await self._run("uA:p1:s1")
        await self._run("uA:p2:s2", socket=False)
        await self._run("uB:p1:s3")

        self.assertEqual(await self.mgr.stop_for_user("uA"), 2)
        await asyncio.sleep(0)

        self.assertTrue(self.tasks["uA:p1:s1"].cancelled())
        self.assertTrue(self.tasks["uA:p2:s2"].cancelled())
        self.assertFalse(self.tasks["uB:p1:s3"].done())
        self.assertEqual(self.mgr.live_session_ids("p1"), ["s3"])
        self.assertEqual(self.mgr.live_session_ids("p2"), [])
        frames = _stopped_frames(self.sockets["uA:p1:s1"])
        self.assertEqual([f["payload"]["message"] for f in frames], [EMERGENCY_STOP_OWN_MESSAGE])
        self.assertEqual(_stopped_frames(self.sockets["uB:p1:s3"]), [])

    async def test_project_filter(self):
        await self._run("uA:p1:s1")
        await self._run("uA:p2:s2")
        await self._run("uA:p3:s3")

        self.assertEqual(await self.mgr.stop_for_user("uA", ["p2", "p3"]), 2)
        await asyncio.sleep(0)

        self.assertFalse(self.tasks["uA:p1:s1"].done())
        self.assertTrue(self.tasks["uA:p2:s2"].cancelled())
        self.assertTrue(self.tasks["uA:p3:s3"].cancelled())
        self.assertEqual(_stopped_frames(self.sockets["uA:p1:s1"]), [])

    async def test_unknown_user_is_a_noop(self):
        await self._run("uA:p1:s1")

        self.assertEqual(await self.mgr.stop_for_user("nobody"), 0)
        self.assertEqual(await self.mgr.stop_for_user(""), 0)
        await asyncio.sleep(0)

        self.assertFalse(self.tasks["uA:p1:s1"].done())
        self.assertEqual(_stopped_frames(self.sockets["uA:p1:s1"]), [])
        self.conv.assert_not_called()

    async def test_the_user_is_the_whole_first_part_of_the_key(self):
        await self._run("u1:p1:s1")
        await self._run("u10:p1:s2")
        await self._run("x:u1:s3")

        self.assertEqual(await self.mgr.stop_for_user("u1"), 1)
        await asyncio.sleep(0)

        self.assertTrue(self.tasks["u1:p1:s1"].cancelled())
        self.assertFalse(self.tasks["u10:p1:s2"].done())
        self.assertFalse(self.tasks["x:u1:s3"].done())

    async def test_its_in_flight_tool_tasks_are_cancelled_too(self):
        await self._run("uA:p1:s1")
        await self._run("uB:p1:s2")
        mine = asyncio.create_task(asyncio.sleep(3600))
        theirs = asyncio.create_task(asyncio.sleep(3600))
        self.tasks["tool-mine"], self.tasks["tool-theirs"] = mine, theirs
        self.mgr.register_tool_task("uA:p1:s1", "execute_nmap", None, None, mine)
        self.mgr.register_tool_task("uB:p1:s2", "execute_nmap", None, None, theirs)

        await self.mgr.stop_for_user("uA")
        await asyncio.sleep(0)

        self.assertTrue(mine.cancelled())
        self.assertFalse(theirs.done())

    async def test_an_act_as_run_is_the_members_and_stops_with_theirs(self):
        # The ticket's subject is the effective user: the admin's act-as run is keyed
        # under the member, the admin only recorded as its starter.
        await self._run("member:p1:s1", actor_id="admin")

        self.assertEqual(await self.mgr.stop_for_user("admin"), 0)
        self.assertEqual(await self.mgr.stop_for_user("member"), 1)
        await asyncio.sleep(0)
        self.assertTrue(self.tasks["member:p1:s1"].cancelled())

    async def test_a_finished_run_is_neither_counted_nor_told(self):
        await self._run("uA:p1:s1")
        self.tasks["uA:p1:s1"].cancel()
        await asyncio.sleep(0)

        self.assertEqual(await self.mgr.stop_for_user("uA"), 0)
        self.assertEqual(_stopped_frames(self.sockets["uA:p1:s1"]), [])
        self.conv.assert_not_called()

    async def test_each_stopped_conversation_is_marked_not_running(self):
        # The run's own `finally` clears the flag too, but a run cancelled before its
        # first step never executes it; a headless run has no socket to ask.
        await self._run("uA:p1:s1")
        await self._run("uA:p2:s2", socket=False)
        await self._run("uB:p1:s3")

        await self.mgr.stop_for_user("uA")
        await asyncio.sleep(0)

        calls = sorted(c.args for c in self.conv.call_args_list)
        self.assertEqual(calls, [("s1", {"agentRunning": False}), ("s2", {"agentRunning": False})])

    async def test_the_global_stop_also_goes_through_stop_session(self):
        await self._run("uA:p1:s1")
        await self._run("uB:p2:s2", socket=False)
        tool = asyncio.create_task(asyncio.sleep(3600))
        self.tasks["tool"] = tool
        self.mgr.register_tool_task("uB:p2:s2", "execute_curl", "w1", 0, tool)

        with mock.patch.object(self.mgr, "stop_session", wraps=self.mgr.stop_session) as spy:
            self.assertEqual(await self.mgr.stop_all(), 2)
        await asyncio.sleep(0)

        self.assertEqual(sorted(c.args[0] for c in spy.call_args_list), ["uA:p1:s1", "uB:p2:s2"])
        self.assertTrue(self.tasks["uA:p1:s1"].cancelled())
        self.assertTrue(self.tasks["uB:p2:s2"].cancelled())
        self.assertTrue(tool.cancelled())
        frames = _stopped_frames(self.sockets["uA:p1:s1"])
        self.assertEqual([f["payload"]["message"] for f in frames], [EMERGENCY_STOP_ALL_MESSAGE])
        self.assertEqual(sorted(c.args[0] for c in self.conv.call_args_list), ["s1", "s2"])
        self.assertEqual(self.mgr.live_session_ids("p1") + self.mgr.live_session_ids("p2"), [])


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
        conv = mock.patch("websocket_api.update_conversation", mock.AsyncMock())
        conv.start()
        self.addCleanup(conv.stop)
        self.mgr = WebSocketManager()
        self.runs = {}
        for key in ("uA:p1:s1", "uA:p2:s2", "uB:p1:s3"):
            self.runs[key] = _FakeTask()
            self.mgr.register_task(key, self.runs[key])
        mgr = mock.patch.object(self.api, "ws_manager", self.mgr)
        mgr.start()
        self.addCleanup(mgr.stop)

    def _post(self, body, key=MASTER):
        headers = {"x-internal-key": key} if key else {}
        return self.client.post("/agent-sessions/stop-for", json=body, headers=headers)

    def _cancelled(self):
        return sorted(k for k, t in self.runs.items() if t.cancelled)

    def test_declares_the_configured_master_gate(self):
        from llm_guard import require_configured_master_auth
        deps = {}
        for r in self.api.app.routes:
            for m in getattr(r, "methods", None) or ():
                deps[(m, r.path)] = [d.dependency for d in getattr(r, "dependencies", [])]
        self.assertEqual(deps[("POST", "/agent-sessions/stop-for")], [require_configured_master_auth])

    def test_refused_without_the_master_key(self):
        body = {"user_id": "uA"}
        self.assertEqual(self._post(body, key=None).status_code, 401)
        self.assertEqual(self._post(body, key=SCANNER).status_code, 401)
        self.assertEqual(self._post(body, key="wrong").status_code, 401)
        with mock.patch.dict(os.environ, {"INTERNAL_API_KEY": ""}):
            self.assertEqual(self._post(body).status_code, 503)
        with mock.patch.dict(os.environ, {"INTERNAL_API_KEY": "changeme"}):
            self.assertEqual(self._post(body, key="changeme").status_code, 503)
        self.assertEqual(self._cancelled(), [])

    def test_stops_only_that_users_runs(self):
        res = self._post({"user_id": "uA"})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json(), {"stopped": 2})
        self.assertEqual(self._cancelled(), ["uA:p1:s1", "uA:p2:s2"])

    def test_project_filter(self):
        res = self._post({"user_id": "uA", "project_ids": ["p2"]})
        self.assertEqual(res.json(), {"stopped": 1})
        self.assertEqual(self._cancelled(), ["uA:p2:s2"])

    def test_unknown_user_is_a_noop(self):
        res = self._post({"user_id": "nobody"})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json(), {"stopped": 0})
        self.assertEqual(self._cancelled(), [])

    def test_the_body_must_name_a_user_and_any_projects(self):
        for body in ({}, {"user_id": ""}, {"user_id": "uA", "project_ids": []},
                     {"user_id": "uA", "project_ids": [""]}, {"user_id": ["uA"]}):
            with self.subTest(body=body):
                self.assertEqual(self._post(body).status_code, 422)
        self.assertEqual(self._cancelled(), [])

    def test_no_manager_answers_503(self):
        with mock.patch.object(self.api, "ws_manager", None):
            self.assertEqual(self._post({"user_id": "uA"}).status_code, 503)

    def test_logs_who_and_how_many(self):
        with self.assertLogs(self.api.logger, level=logging.WARNING) as logs:
            self._post({"user_id": "uA", "project_ids": ["p1", "p2"]})
        self.assertIn("[rbac] stop-for user=uA projects=2 stopped=2", "\n".join(logs.output))

    def test_the_global_stop_still_stops_every_users_runs(self):
        res = self.client.post("/emergency-stop-all", headers={"x-internal-key": MASTER})
        self.assertEqual(res.json(), {"stopped": 3})
        self.assertEqual(self._cancelled(), ["uA:p1:s1", "uA:p2:s2", "uB:p1:s3"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
