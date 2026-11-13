"""
A tool confirmation that answers a Fireteam member's escalation needs agent:fireteam too
(step 5.4 review, finding 3).

When a member escalates a dangerous call, the parent run pauses on an ordinary tool confirmation
whose mode in the run's state is `fireteam_escalation`; approving it redeploys the member
(`fireteam_redeploy`). The answer was checked for `agent:approve_dangerous` alone, while the
member's own confirmation path asks `agent:fireteam` and `agent:approve_dangerous`. Now the socket
reads the mode from the run's state (never from the frame), asks both permissions of the ticket's
`cap`, and sends the mode to the decision-time check, whose route maps
`tool_confirmation` + `fireteam_escalation` to both. A mode it cannot read asks for both.

Run: ./agentic/run_tests.sh tests/test_fireteam_escalation_confirmation.py
"""
import asyncio
import json
import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

os.environ.setdefault("WEBAPP_API_URL", "http://fake-webapp")

_AGENTIC_DIR = Path(__file__).resolve().parents[1]
if str(_AGENTIC_DIR) not in sys.path:
    sys.path.insert(0, str(_AGENTIC_DIR))

import httpx  # noqa: E402

_RealAsyncClient = httpx.AsyncClient

import decision_check  # noqa: E402
from decision_check import DecisionCheck, authorize_decision  # noqa: E402
from writer_check import WriterCheck  # noqa: E402

try:
    import websocket_api  # noqa: E402
    from orchestrator import AgentOrchestrator  # noqa: E402
    from websocket_api import WebSocketConnection, WebSocketHandler, WebSocketManager  # noqa: E402
    _HAVE = True
except Exception:  # pragma: no cover - only outside the agent image
    _HAVE = False

KEY = "uB:pB:sB"
ALLOWED = DecisionCheck(allowed=True)
BOTH = ("agent:approve_dangerous", "agent:fireteam")


class TheClientSendsTheMode(unittest.TestCase):

    def _send(self, **kw):
        bodies = []

        def handler(request):
            bodies.append(json.loads(request.content))
            return httpx.Response(200, json={"allowed": True})

        def client(*a, **k):
            return _RealAsyncClient(transport=httpx.MockTransport(handler))

        with mock.patch.object(decision_check.httpx, "AsyncClient", client), \
                mock.patch.dict(decision_check.INTERNAL_HEADERS, {"X-Internal-Key": "k" * 16}):
            got = asyncio.run(authorize_decision(kind="tool_confirmation", user_id="uB", project_id="pB",
                                                 session_id="sB", **kw))
        return got, bodies

    def test_a_mode_rides_in_the_body_and_none_sends_none(self):
        got, bodies = self._send(mode="fireteam_escalation", permissions=BOTH)
        self.assertEqual(got, ALLOWED)
        self.assertEqual(bodies, [{"kind": "tool_confirmation", "userId": "uB", "projectId": "pB",
                                   "sessionId": "sB", "mode": "fireteam_escalation"}])
        _, plain = self._send()
        self.assertNotIn("mode", plain[0])

    def test_a_mode_the_kind_does_not_have_is_a_programming_error(self):
        for kind, mode in (("tool_confirmation", "plan"), ("approval", "fireteam_escalation")):
            with self.subTest(kind=kind, mode=mode), self.assertRaises(ValueError):
                asyncio.run(authorize_decision(kind=kind, user_id="u", project_id="p", session_id="s", mode=mode))

    def test_the_modes_are_the_webapp_s(self):
        route = _AGENTIC_DIR.parent / "webapp/src/app/api/internal/agent/authorize-decision/route.ts"
        if not route.exists():
            self.skipTest("webapp source not mounted in this image")
        modes = route.read_text().split("const MODES")[1].split("})")[0]
        for kind, names in decision_check.DECISION_MODES.items():
            self.assertIn(f"\n  {kind}: {{", modes, kind)
            for name in names:
                self.assertIn(f"{name}:", modes, name)


class _Graph:
    def __init__(self, values, raises=None):
        self.values, self.raises, self.configs = values, raises, []

    async def aget_state(self, config):
        self.configs.append(config)
        if self.raises:
            raise self.raises
        return SimpleNamespace(values=self.values)


@unittest.skipUnless(_HAVE, "agent deps unavailable (run in-container)")
class TheOrchestratorReadsTheMode(unittest.TestCase):

    def _mode(self, values):
        orch = AgentOrchestrator.__new__(AgentOrchestrator)
        orch.graph = _Graph(values)
        got = asyncio.run(orch.pending_tool_confirmation_mode(user_id="uB", project_id="pB", session_id="sB"))
        return got, orch.graph.configs

    def test_an_escalation_a_plain_confirmation_and_none(self):
        pending = {"mode": "single", "tools": [{"tool_name": "kali_shell"}]}
        self.assertEqual(self._mode({"tool_confirmation_pending": pending,
                                     "_tool_confirmation_mode": "fireteam_escalation"})[0], "fireteam_escalation")
        self.assertEqual(self._mode({"tool_confirmation_pending": pending})[0], "single")
        self.assertEqual(self._mode({"tool_confirmation_pending": {**pending, "mode": "plan"}})[0], "plan")
        self.assertIsNone(self._mode({"tool_confirmation_pending": None,
                                      "_tool_confirmation_mode": "fireteam_escalation"})[0])
        self.assertIsNone(self._mode({})[0])

    def test_it_reads_the_person_s_thread(self):
        _, configs = self._mode({})
        self.assertEqual(configs[0]["configurable"]["thread_id"], "uB:pB:sB")


class _WS:
    def __init__(self):
        self.sent = []
        self.client = "test"

    async def send_json(self, msg):
        self.sent.append(msg)


class _Orchestrator:
    def __init__(self, mode=None, raises=None):
        self.mode, self.raises, self.calls = mode, raises, []

    async def pending_tool_confirmation_mode(self, **_kw):
        if self.raises:
            raise self.raises
        return self.mode

    async def resume_after_tool_confirmation_with_streaming(self, **kw):
        self.calls.append(kw)
        kw["on_admitted"]()


@unittest.skipUnless(_HAVE, "agent deps unavailable (run in-container)")
class TheSocketAsksBoth(unittest.TestCase):

    def setUp(self):
        self.check = mock.AsyncMock(return_value=ALLOWED)
        for p in (
            mock.patch.object(websocket_api, "authorize_decision", self.check),
            # The per-run writer check (step 5.11 follow-up) is test_run_writer_check.py's; here it allows.
            mock.patch.object(websocket_api, "second_writer_check", mock.AsyncMock(return_value=WriterCheck(allowed=True))),
            mock.patch.object(websocket_api, "save_chat_message", mock.AsyncMock(return_value=None)),
            mock.patch.object(websocket_api, "post_agent_decision", mock.AsyncMock(return_value=True)),
            mock.patch.object(websocket_api, "update_conversation", mock.AsyncMock()),
        ):
            p.start()
            self.addCleanup(p.stop)

    def _confirm(self, orch, cap):
        async def main():
            mgr = WebSocketManager()
            handler = WebSocketHandler(orchestrator=orch, ws_manager=mgr)
            conn = WebSocketConnection(_WS())
            conn.cap = cap
            await mgr.authenticate(conn, "uB", "pB", "sB", verified=True)
            conn.tenant_id = "owner-A"
            await handler.handle_tool_confirmation(conn, {"decision": "approve"})
            started = mgr.get_task(KEY)
            if conn._active_task is not None:
                await asyncio.wait_for(conn._active_task, 5)
            return conn, started

        conn, started = asyncio.run(main())
        errors = [m["payload"] for m in conn.websocket.sent if m["type"] == "error"]
        return errors, started

    def test_an_escalation_without_agent_fireteam_is_refused_and_redeploys_nothing(self):
        orch = _Orchestrator("fireteam_escalation")
        errors, started = self._confirm(orch, frozenset({"agent:approve_dangerous"}))
        self.assertIsNone(started)
        self.assertEqual(orch.calls, [])
        self.check.assert_not_awaited()
        self.assertEqual((errors[0]["code"], errors[0]["permission"], errors[0]["answer"]),
                         ("permission_required", "agent:fireteam", "tool_confirmation"))

    def test_an_escalation_with_both_asks_the_webapp_for_both_with_the_mode(self):
        orch = _Orchestrator("fireteam_escalation")
        errors, started = self._confirm(orch, frozenset(BOTH))
        self.assertEqual(errors, [])
        self.assertIsNotNone(started)
        self.check.assert_awaited_once_with(kind="tool_confirmation", user_id="uB", project_id="pB",
                                            session_id="sB", actor_id=None, permissions=BOTH,
                                            mode="fireteam_escalation")

    def test_a_plain_confirmation_asks_approve_dangerous_alone(self):
        for mode in ("single", "plan", None):
            with self.subTest(mode=mode):
                self.check.reset_mock()
                orch = _Orchestrator(mode)
                errors, _ = self._confirm(orch, frozenset({"agent:approve_dangerous"}))
                self.assertEqual(errors, [])
                self.check.assert_awaited_once_with(kind="tool_confirmation", user_id="uB", project_id="pB",
                                                    session_id="sB", actor_id=None,
                                                    permissions=("agent:approve_dangerous",))

    def test_an_unreadable_mode_asks_for_both(self):
        orch = _Orchestrator(raises=RuntimeError("checkpointer down"))
        with self.assertLogs("websocket_api", "WARNING") as logs:
            errors, started = self._confirm(orch, frozenset({"agent:approve_dangerous"}))
        self.assertIsNone(started)
        self.assertEqual(errors[0]["permission"], "agent:fireteam")
        self.assertIn("[rbac] tool confirmation mode unreadable", "\n".join(logs.output))
        self.check.reset_mock()
        self._confirm(_Orchestrator(raises=RuntimeError("x")), frozenset(BOTH))
        self.assertEqual(self.check.await_args.kwargs["mode"], "fireteam_escalation")


if __name__ == "__main__":
    unittest.main()
