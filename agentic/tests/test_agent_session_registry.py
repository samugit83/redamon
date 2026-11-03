"""
C-8: the webapp checks a set Conversation.agentRunning flag against the agent's
own task registry, so a flag left behind by a restarted agent stops locking the
project (preset apply, rescope, graph activation, the queued-scan dispatcher).

These tests pin the two halves the webapp relies on: the registry reports only
this project's still-running sessions, and the endpoint is internal-auth gated
and answers 503 (the webapp then stays busy) before the manager exists.

Run in-container: ./agentic/run_tests.sh tests/test_agent_session_registry.py
"""
import asyncio
import inspect
import importlib.util
import os
import re
import sys
import unittest
from pathlib import Path
from unittest import mock

_AGENTIC_DIR = str(Path(__file__).resolve().parents[1])
if _AGENTIC_DIR not in sys.path:
    sys.path.insert(0, _AGENTIC_DIR)

from websocket_api import WebSocketManager  # noqa: E402
import api  # noqa: E402


async def _busy():
    await asyncio.sleep(30)


async def _done():
    return None


class LiveSessionIds(unittest.TestCase):
    def test_lists_only_this_projects_running_sessions(self):
        async def scenario():
            mgr = WebSocketManager()
            mine = asyncio.ensure_future(_busy())
            other_project = asyncio.ensure_future(_busy())
            mgr.register_task("u1:p1:sess-a", mine)
            mgr.register_task("u1:p2:sess-b", other_project)
            try:
                self.assertEqual(mgr.live_session_ids("p1"), ["sess-a"])
                self.assertEqual(mgr.live_session_ids("p2"), ["sess-b"])
                self.assertEqual(mgr.live_session_ids("p3"), [])
            finally:
                mine.cancel()
                other_project.cancel()

        asyncio.run(scenario())

    def test_a_finished_task_is_not_live_and_is_dropped(self):
        # The finally block of a run clears its task, but a crash between the
        # run ending and that clear leaves a done task behind.
        async def scenario():
            mgr = WebSocketManager()
            finished = asyncio.ensure_future(_done())
            await finished
            mgr.register_task("u1:p1:sess-a", finished)
            self.assertEqual(mgr.live_session_ids("p1"), [])
            self.assertIsNone(mgr.get_task("u1:p1:sess-a"))

        asyncio.run(scenario())

    def test_a_session_id_containing_colons_is_returned_whole(self):
        async def scenario():
            mgr = WebSocketManager()
            task = asyncio.ensure_future(_busy())
            mgr.register_task("u1:p1:sess:with:colons", task)
            try:
                self.assertEqual(mgr.live_session_ids("p1"), ["sess:with:colons"])
            finally:
                task.cancel()

        asyncio.run(scenario())

    def test_a_project_id_is_matched_exactly_not_as_a_prefix(self):
        async def scenario():
            mgr = WebSocketManager()
            task = asyncio.ensure_future(_busy())
            mgr.register_task("u1:p10:sess-a", task)
            try:
                self.assertEqual(mgr.live_session_ids("p1"), [])
            finally:
                task.cancel()

        asyncio.run(scenario())


class LiveSessionsEndpoint(unittest.TestCase):
    def _route(self):
        for r in api.app.routes:
            if getattr(r, "path", "") == "/agent-sessions/live":
                return r
        self.fail("/agent-sessions/live is not registered")

    def test_scanner_key_cannot_enumerate_live_sessions(self):
        # The kali sandbox holds SCANNER_API_KEY and faces the target. A live
        # session id is what /agent-session/stop takes to cancel an operator's
        # run, so only the master key may list them.
        from fastapi.testclient import TestClient

        mgr = WebSocketManager()
        saved = api.ws_manager
        api.ws_manager = mgr
        env = {"INTERNAL_API_KEY": "master-key-for-test", "SCANNER_API_KEY": "scanner-key-for-test"}
        try:
            with mock.patch.dict(os.environ, env, clear=False):
                client = TestClient(api.app)
                url = "/agent-sessions/live?project_id=p1"
                scanner = client.get(url, headers={"x-internal-key": "scanner-key-for-test"})
                master = client.get(url, headers={"x-internal-key": "master-key-for-test"})
        finally:
            api.ws_manager = saved
        self.assertEqual(scanner.status_code, 401)
        self.assertEqual(master.status_code, 200)
        self.assertEqual(master.json(), {"project_id": "p1", "session_ids": []})

    def test_returns_the_projects_live_session_ids(self):
        async def scenario():
            mgr = WebSocketManager()
            task = asyncio.ensure_future(_busy())
            mgr.register_task("u1:p1:sess-a", task)
            saved = api.ws_manager
            api.ws_manager = mgr
            try:
                body = await api.live_agent_sessions(project_id="p1")
            finally:
                api.ws_manager = saved
                task.cancel()
            self.assertEqual(body, {"project_id": "p1", "session_ids": ["sess-a"]})

        asyncio.run(scenario())

    def test_answers_503_before_the_manager_exists(self):
        saved = api.ws_manager
        api.ws_manager = None
        try:
            resp = asyncio.run(api.live_agent_sessions(project_id="p1"))
        finally:
            api.ws_manager = saved
        self.assertEqual(resp.status_code, 503)


_REPO = Path(__file__).resolve().parents[2]
_WEBAPP_LIB = _REPO / "webapp" / "src" / "lib"


class RunsInTheUnitGate(unittest.TestCase):
    def test_file_name_does_not_opt_it_out_of_the_unit_gate(self):
        # A name holding `live_`, `_live`, `_smoke` or `smoke_` moves the whole
        # file to the live tier, and the unit gate then never runs any of it.
        runner = _REPO / "tooling" / "scripts" / "pytest_isolated.py"
        if not runner.is_file():
            self.skipTest(f"gate runner not mounted at {runner}")
        spec = importlib.util.spec_from_file_location("pytest_isolated", runner)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(module.tier_of(Path(__file__).name), "unit")


class WebappConsumerContract(unittest.TestCase):
    """The webapp half (lib/agentSessions.ts) and this endpoint share no schema,
    so each side's unit tests pass on their own assumption. A rename on one side
    alone makes the webapp read every set flag as unverified, i.e. the project
    stays locked for good, which is the bug the endpoint exists to fix."""

    def setUp(self):
        consumer = _WEBAPP_LIB / "agentSessions.ts"
        if not consumer.is_file():
            self.skipTest(f"webapp source not mounted at {consumer}")
        self.src = consumer.read_text()

    def _consumer(self, pattern):
        m = re.search(pattern, self.src)
        self.assertIsNotNone(m, f"agentSessions.ts no longer matches {pattern!r}")
        return m.groups()

    def test_path_method_param_and_key_match_the_consumer(self):
        path, param = self._consumer(r"`(/[\w/-]+)\?(\w+)=\$\{encodeURIComponent\(projectId\)\}`")
        (method,) = self._consumer(r"method: '(\w+)'")
        (key,) = self._consumer(r"ids = body\?\.(\w+)")
        (loop_key,) = self._consumer(r"loopStates = body\?\.(\w+)")
        self.assertIn(f'answer["{loop_key}"]', inspect.getsource(api.live_agent_sessions),
                      "the webapp reads loop states under a key the endpoint never writes")

        route = next((r for r in api.app.routes if getattr(r, "path", "") == path), None)
        self.assertIsNotNone(route, f"the webapp calls {path}, which the agent does not serve")
        self.assertIn(method, route.methods)
        self.assertIn(param, [q.name for q in route.dependant.query_params])

        async def scenario():
            mgr = WebSocketManager()
            task = asyncio.ensure_future(_busy())
            mgr.register_task("u1:p1:sess-a", task)
            saved = api.ws_manager
            api.ws_manager = mgr
            try:
                return await route.endpoint(**{param: "p1"})
            finally:
                api.ws_manager = saved
                task.cancel()

        self.assertEqual(asyncio.run(scenario())[key], ["sess-a"])

    def test_the_consumer_sends_the_master_key_the_endpoint_requires(self):
        self._consumer(r"agentFetch\(\s*`/agent-sessions/live")
        auth = (_WEBAPP_LIB / "agentAuth.ts").read_text()
        self.assertIn("'x-internal-key': process.env.INTERNAL_API_KEY", auth)


if __name__ == "__main__":
    unittest.main(verbosity=2)
