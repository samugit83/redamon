"""
The agent lists every agent session of the instance for the admin operations view
(step 6.5; GV-06): `WebSocketManager.all_sessions()` and the master-key
`GET /agent-sessions/all`.

Each session is one key "<user>:<project>:<session>" of the open sockets or the
registered runs, parsed as `live_session_ids` parses it: its person, project and
session, whether a run is in progress (a finished task is not), whether a socket
is open, and the admin behind an act-as run (the run's actor, else the open
socket's). Ids and flags only: never a message, a title, a ticket or the tenant.
The route lists another tenant's sessions, so it is master-key only and
fail-closed (`require_configured_master_auth`): the scanner token, no key and a
wrong key are refused, an agent with no master key answers 503, and so does one
whose manager is not up.

Run: ./agentic/run_tests.sh tests/test_sessions_all.py
"""
import asyncio
import os
import re
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
FIELDS = {"user_id", "project_id", "session_id", "running", "connected", "actor_id"}


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

    def done(self):
        return self._done

    def cancel(self):
        self._done = True
        return True


@unittest.skipUnless(_HAVE, "agent deps unavailable (run in-container)")
class AllSessions(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.mgr = WebSocketManager()
        self.tasks = []

    async def asyncTearDown(self):
        for t in self.tasks:
            t.cancel()
        await asyncio.sleep(0)

    async def _socket(self, key, actor_id=None):
        user, project, session = key.split(":", 2)
        conn = WebSocketConnection(_FakeWS())
        conn.actor_id = actor_id
        await self.mgr.authenticate(conn, user, project, session, verified=True)
        # authenticate() leaves actor_id as it found it; keep the act-as admin on the socket.
        conn.actor_id = actor_id
        return conn

    def _run(self, key, actor_id=None):
        task = asyncio.create_task(asyncio.sleep(3600))
        self.tasks.append(task)
        self.mgr.register_task(key, task, actor_id=actor_id)
        return task

    async def test_nothing_open_lists_nothing(self):
        self.assertEqual(self.mgr.all_sessions(), [])

    async def test_runs_and_idle_sockets_each_once_sorted_by_key(self):
        self._run("uB:p1:s2")
        await self._socket("uB:p1:s2")
        self._run("uA:p2:s1")
        await self._socket("uC:p1:s3")
        self.assertEqual(self.mgr.all_sessions(), [
            {"user_id": "uA", "project_id": "p2", "session_id": "s1", "running": True, "connected": False, "actor_id": None},
            {"user_id": "uB", "project_id": "p1", "session_id": "s2", "running": True, "connected": True, "actor_id": None},
            {"user_id": "uC", "project_id": "p1", "session_id": "s3", "running": False, "connected": True, "actor_id": None},
        ])

    async def test_an_act_as_run_names_its_admin_from_the_run_or_the_socket(self):
        self._run("mem:p1:s1", actor_id="adm")
        await self._socket("mem:p2:s2", actor_id="adm2")
        by_session = {s["session_id"]: s for s in self.mgr.all_sessions()}
        self.assertEqual(by_session["s1"]["actor_id"], "adm")
        self.assertEqual(by_session["s1"]["user_id"], "mem")
        self.assertEqual(by_session["s2"]["actor_id"], "adm2")

    async def test_a_finished_run_reads_not_running_and_without_a_socket_drops(self):
        task = self._run("uA:p1:s1", actor_id="adm")
        await self._socket("uA:p1:s1")
        self._run("uB:p1:s2")
        task.cancel()
        await asyncio.sleep(0)
        sessions = self.mgr.all_sessions()
        self.assertEqual([(s["session_id"], s["running"], s["actor_id"]) for s in sessions], [("s1", False, None), ("s2", True, None)])
        await self.mgr.disconnect(self.mgr.active_connections["uA:p1:s1"])
        self.assertEqual([s["session_id"] for s in self.mgr.all_sessions()], ["s2"])

    async def test_the_session_part_keeps_its_colons(self):
        self._run("uA:p1:loop:s1")
        self.assertEqual(self.mgr.all_sessions()[0]["session_id"], "loop:s1")

    async def test_a_malformed_key_is_left_out(self):
        self._run("no-colons")
        self._run("uA::s1")
        self.assertEqual(self.mgr.all_sessions(), [])

    async def test_only_ids_and_flags(self):
        self._run("uA:p1:s1")
        await self._socket("uA:p1:s1")
        for s in self.mgr.all_sessions():
            self.assertEqual(set(s), FIELDS)


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
        self.mgr.register_task("uA:p1:s1", _FakeTask(), actor_id="adm")
        self.mgr.register_task("uB:p2:s2", _FakeTask(done=True))
        self.mgr.register_task("uB:p2:s3", _FakeTask())
        mgr = mock.patch.object(self.api, "ws_manager", self.mgr)
        mgr.start()
        self.addCleanup(mgr.stop)

    def _get(self, key=MASTER):
        headers = {"x-internal-key": key} if key else {}
        return self.client.get("/agent-sessions/all", headers=headers)

    def test_declares_the_configured_master_gate(self):
        from llm_guard import require_configured_master_auth
        deps = {}
        for r in self.api.app.routes:
            for m in getattr(r, "methods", None) or ():
                deps[(m, r.path)] = [d.dependency for d in getattr(r, "dependencies", [])]
        self.assertEqual(deps[("GET", "/agent-sessions/all")], [require_configured_master_auth])

    def test_agent_route_master_only(self):
        self.assertEqual(self._get(key=None).status_code, 401)
        self.assertEqual(self._get(key=SCANNER).status_code, 401)
        self.assertEqual(self._get(key="wrong").status_code, 401)
        with mock.patch.dict(os.environ, {"INTERNAL_API_KEY": ""}):
            self.assertEqual(self._get().status_code, 503)
        with mock.patch.dict(os.environ, {"INTERNAL_API_KEY": "changeme"}):
            self.assertEqual(self._get(key="changeme").status_code, 503)

    def test_lists_every_users_sessions_with_the_run_state_and_the_actor(self):
        res = self._get()
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json(), {"sessions": [
            {"user_id": "uA", "project_id": "p1", "session_id": "s1", "running": True, "connected": False, "actor_id": "adm"},
            {"user_id": "uB", "project_id": "p2", "session_id": "s3", "running": True, "connected": False, "actor_id": None},
        ]})

    def test_no_manager_answers_503(self):
        with mock.patch.object(self.api, "ws_manager", None):
            res = self._get()
        self.assertEqual(res.status_code, 503)
        self.assertEqual(res.json(), {"error": "agent not ready"})


_CONSUMER = Path(__file__).resolve().parents[2] / "webapp" / "src" / "lib" / "authz" / "adminOperations.ts"


class TheWebappReadsWhatTheAgentWrites(unittest.TestCase):
    """The operations view's reader (webapp lib/authz/adminOperations.ts) asks this path with
    agentFetch (the master key) and reads exactly these fields; a rename on one side fails here."""

    def setUp(self):
        if not _CONSUMER.is_file():
            self.skipTest(f"webapp source not mounted at {_CONSUMER}")
        self.src = _CONSUMER.read_text()

    def test_path_and_fields_match_the_consumer(self):
        self.assertRegex(self.src, r"agentRead\('/agent-sessions/all'\)")
        self.assertRegex(self.src, r"agentFetch\(path,")
        self.assertIn("body.sessions", self.src)
        for field in FIELDS:
            self.assertRegex(self.src, rf"\br\.{field}\b", field)

    def test_the_stop_names_the_run_as_the_stop_route_reads_it(self):
        self.assertRegex(self.src, r"agentFetch\('/agent-session/stop'")
        m = re.search(r"JSON\.stringify\(\{ (user_id: target\.userId, project_id: target\.projectId, session_id: target\.sessionId) \}\)", self.src)
        self.assertIsNotNone(m, "the stop body no longer sends user_id, project_id and session_id")


if __name__ == "__main__":
    unittest.main(verbosity=2)
