"""Run scopes around the graph, the live loop status, and the loop_status frame."""
from __future__ import annotations

import asyncio
import inspect
import unittest
from unittest import mock

import orchestrator as orchestrator_mod
import project_settings
import websocket_api
from agent_context import current_llm
from agent_in_the_loop import LoopSettings, broker as broker_mod
from agent_in_the_loop.broker import StepBroker
from agent_in_the_loop.model import LoopChatModel
from websocket_api import MessageType, StreamingCallback, WebSocketConnection


def cfg():
    return LoopSettings(step_deadline_s=900, lease_s=90, wait_max_s=55, page_chars=40000,
                        answer_max_chars=262144, max_open_steps_per_user=16,
                        no_driver_grace_s=300, driver_seen_s=60, state_ttl_s=3600)


class _FakeWS:
    def __init__(self):
        self.sent, self.client = [], "test"

    async def send_json(self, msg):
        self.sent.append(msg)

    async def close(self, code=1000, reason=""):
        pass


def _callback():
    conn = WebSocketConnection(_FakeWS())
    conn.user_id, conn.project_id, conn.session_id = "u", "p", "s"
    conn.authenticated = True
    return StreamingCallback(conn), conn.websocket


def _loop_frames(ws):
    return [m["payload"] for m in ws.sent if m["type"] == MessageType.LOOP_STATUS.value]


class FakeGraph:
    def __init__(self, states, exc=None, block=False):
        self.states, self.exc, self.block = states, exc, block

    async def astream(self, _input, _config, stream_mode="values"):
        for state in self.states:
            yield state
        if self.block:
            await asyncio.sleep(10)
        if self.exc is not None:
            raise self.exc


class ScopeCase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.broker = StepBroker(config=cfg(), poll_s=0.01)
        patcher = mock.patch.object(broker_mod, "_broker", self.broker)
        patcher.start()
        self.addCleanup(patcher.stop)
        for target, name in ((orchestrator_mod, "emit_streaming_events"),
                             (websocket_api, "save_chat_message")):
            patcher = mock.patch.object(target, name, new=mock.AsyncMock(return_value=None))
            patcher.start()
            self.addCleanup(patcher.stop)

    async def stream(self, graph, llm):
        fake = mock.MagicMock()
        fake.graph, fake.llm = graph, llm
        callback, ws = _callback()
        token = current_llm.set(llm)
        try:
            final = await orchestrator_mod.AgentOrchestrator._stream_graph(
                fake, {}, {}, callback, "u", "p", "s")
        finally:
            current_llm.reset(token)
        await asyncio.sleep(0)
        return final, ws

    async def test_exit_states_reach_the_browser(self):
        cases = [
            ([{"awaiting_tool_confirmation": True}], "awaiting_human", "tool_confirmation"),
            ([{"awaiting_user_question": True}], "awaiting_human", "question"),
            ([{"task_complete": True}], "finished", None),
        ]
        for states, state, kind in cases:
            with self.subTest(state=state, kind=kind):
                final, ws = await self.stream(FakeGraph(states), LoopChatModel())
                self.assertEqual(final, states[-1])
                frames = _loop_frames(ws)
                self.assertEqual(frames[0]["state"], "thinking")
                self.assertEqual(frames[-1]["state"], state)
                self.assertEqual(frames[-1]["detail"].get("kind"), kind)
                self.assertIsNone(self.broker.scope_for_session("s"))

    async def test_an_exception_ends_in_error(self):
        with self.assertRaises(RuntimeError):
            await self.stream(FakeGraph([{}], exc=RuntimeError("x")), LoopChatModel())
        await asyncio.sleep(0)
        self.assertEqual(self.broker.status_payload("u:p:s")["state"], "error")

    async def test_a_cancelled_run_is_stopped(self):
        task = asyncio.create_task(self.stream(FakeGraph([{}], block=True), LoopChatModel()))
        await asyncio.sleep(0.02)
        self.assertIsNotNone(self.broker.scope_for_session("s"))
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(self.broker.status_payload("u:p:s")["state"], "stopped")

    async def test_the_frame_carries_the_runs_tool_confirmation(self):
        for setting in (False, True):
            with self.subTest(setting=setting):
                token = project_settings._settings_ctx.set({"REQUIRE_TOOL_CONFIRMATION": setting})
                try:
                    _, ws = await self.stream(FakeGraph([{"task_complete": True}]), LoopChatModel())
                finally:
                    project_settings._settings_ctx.reset(token)
                frames = _loop_frames(ws)
                self.assertTrue(frames)
                self.assertEqual({f["toolConfirmation"] for f in frames}, {setting})

    async def test_a_project_without_the_setting_reports_confirmation_on(self):
        token = project_settings._settings_ctx.set({})
        try:
            _, ws = await self.stream(FakeGraph([{"task_complete": True}]), LoopChatModel())
        finally:
            project_settings._settings_ctx.reset(token)
        self.assertEqual({f["toolConfirmation"] for f in _loop_frames(ws)}, {True})

    async def test_a_provider_run_sends_no_loop_frame(self):
        llm = mock.MagicMock()
        _, ws = await self.stream(FakeGraph([{"task_complete": True}]), llm)
        self.assertEqual(_loop_frames(ws), [])
        self.assertIsNone(self.broker.status_payload("u:p:s"))

    async def test_uses_loop_is_decided_per_run(self):
        _, ws = await self.stream(FakeGraph([{}]), mock.MagicMock())
        self.assertEqual(_loop_frames(ws), [])
        _, ws = await self.stream(FakeGraph([{}]), LoopChatModel())
        self.assertTrue(_loop_frames(ws))

    def test_every_streaming_entry_point_uses_the_scope(self):
        src = inspect.getsource(orchestrator_mod.AgentOrchestrator)
        self.assertEqual(src.count("self.graph.astream("), 1)
        self.assertEqual(src.count("await self._stream_graph("), 5)


class CallbackFrames(ScopeCase):
    async def test_tool_start_sends_running_tool_and_is_not_persisted(self):
        callback, ws = _callback()
        queued = []
        callback._persist = lambda msg_type, data, **kw: queued.append(msg_type)
        async with self.broker.run_scope("u", "p", "s", callback, uses_loop=True):
            await callback.on_tool_start("execute_nmap", {"target": "SECRET-ARG"})
            await asyncio.sleep(0)
            frames = _loop_frames(ws)
            self.assertEqual(frames[-1]["state"], "running_tool")
            self.assertEqual(frames[-1]["detail"], {"tool": "execute_nmap"})
            self.assertNotIn("loop_status", queued)
            self.assertIn("tool_start", queued)
            for frame in frames:
                self.assertNotIn("SECRET", repr(frame))

    async def test_approval_and_completion(self):
        callback, ws = _callback()
        async with self.broker.run_scope("u", "p", "s", callback, uses_loop=True):
            await callback.on_approval_request({"from_phase": "a", "to_phase": "b"})
            await asyncio.sleep(0)
            self.assertEqual(_loop_frames(ws)[-1]["detail"], {"kind": "approval"})
            await callback.on_task_complete("done", "informational", 3)
            await asyncio.sleep(0)
            self.assertEqual(_loop_frames(ws)[-1]["state"], "finished")

    async def test_a_provider_run_notes_nothing(self):
        callback, ws = _callback()
        async with self.broker.run_scope("u", "p", "s", callback, uses_loop=False):
            await callback.on_tool_start("execute_nmap", {})
            await callback.on_task_complete("done", "informational", 3)
            await asyncio.sleep(0)
        self.assertEqual(_loop_frames(ws), [])

    async def test_thinking_carries_who_answered(self):
        callback, ws = _callback()
        async with self.broker.run_scope("u", "p", "s", callback, uses_loop=True) as scope:
            step = self.broker.new_step(scope, purpose="think", meta={}, messages=[],
                                        answer_format="json", last_instruction="")
            await self.broker.open_step(step, scope)
            await self.broker.answer("u", ["p"], step.id, text="{}",
                                     answered_by={"token_prefix": "rdm_ab", "token_name": "laptop"})
            await callback.on_thinking(1, "informational", "t", "r")
            await callback.on_thinking(2, "informational", "t", "r")
        thinking = [m["payload"] for m in ws.sent if m["type"] == MessageType.THINKING.value]
        self.assertEqual(thinking[0]["answeredBy"], {"token_prefix": "rdm_ab", "token_name": "laptop"})
        self.assertNotIn("answeredBy", thinking[1])

    def test_connected_carries_loop_state_only_when_a_status_exists(self):
        src = inspect.getsource(websocket_api)
        self.assertIn('loop_state = get_broker().status_payload(connection.get_key())', src)
        self.assertIn('connected["loop_state"] = loop_state', src)
        self.assertIsNone(StepBroker(config=cfg()).status_payload("u:p:none"))


if __name__ == "__main__":
    unittest.main()
