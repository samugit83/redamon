"""End-to-end reconnect behaviour of /ws/agent, through the real endpoint.

Recreates the UI half of the "agent stuck" incident with real WebSocket
connections (Starlette TestClient) into the production websocket_endpoint,
WebSocketHandler, StreamingCallback and persist queue; only the LLM-driven
orchestrator is scripted. In the incident the browser socket dropped while a
run was going (closing the AI drawer or leaving the page closes it on purpose),
the run kept emitting into the dead socket, and the reconnected page had no way
to learn what it missed: the tool card stayed "Running" and the spinner never
stopped, even after the run had finished or been stopped.

Every CONNECTED now carries agent_running, the server's live answer, and a run
releases its registration before it drains its persist queue.

Run: ./agentic/run_tests.sh integration   (or this file alone)
"""
import asyncio
import base64
import hashlib
import hmac
import json
import os
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

try:
    from fastapi import FastAPI, WebSocket
    from starlette.testclient import TestClient

    import websocket_api
    from websocket_api import WebSocketManager, websocket_endpoint
    _HAVE = True
except Exception:  # pragma: no cover - only outside the agent image
    _HAVE = False

SECRET = "1" * 64
KEY = "u:p:s"


def _ticket(user="u", project="p", session="s") -> str:
    def b64(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    head = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = b64(json.dumps({"sub": user, "pid": project, "sid": session, "aud": "agent",
                           "iat": int(time.time()), "exp": int(time.time()) + 300}).encode())
    sig = hmac.new(SECRET.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()
    return f"{head}.{body}.{b64(sig)}"


class _ScriptedRun:
    """Stands in for AgentOrchestrator: one tool call that the test holds open."""

    def __init__(self):
        self.release = threading.Event()
        self.started = threading.Event()
        self.graph = mock.MagicMock()
        self.graph.aget_state = mock.AsyncMock(return_value=None)

    async def invoke_with_streaming(self, *, question, user_id, project_id, session_id,
                                    streaming_callback, guidance_queue=None,
                                    graph_view_cypher=None, tenant_user_id=None):
        cb = streaming_callback
        await cb.on_tool_start("execute_code", {"code": "print(1)"}, step_id="step0001")
        self.started.set()
        await asyncio.to_thread(self.release.wait, 30)
        await cb.on_tool_output_chunk("execute_code", "uid=0(root)", is_final=True, step_id="step0001")
        await cb.on_tool_finished("execute_code", True, duration_ms=1500, step_id="step0001")
        await cb.on_tool_complete("execute_code", True, "root shell", duration_ms=1500, step_id="step0001")
        await cb.on_response("done", 1, "exploitation", True)
        await cb.on_task_complete("done", "exploitation", 1)


def _wait_until(predicate, timeout=10.0, what="condition"):
    end = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > end:
            raise AssertionError(f"timed out waiting for {what}")
        time.sleep(0.02)


@unittest.skipUnless(_HAVE, "agent image deps unavailable")
class ReconnectTellsTheTruth(unittest.TestCase):
    def setUp(self):
        self.saved = []
        self.save_delay = 0.0

        async def fake_save(**kw):
            if self.save_delay:
                await asyncio.sleep(self.save_delay)
            self.saved.append(kw["msg_type"])

        patches = [
            mock.patch.dict(os.environ, {"AGENT_WS_TICKET_SECRET": SECRET}),
            mock.patch.object(websocket_api, "save_chat_message", side_effect=fake_save),
            mock.patch.object(websocket_api, "update_conversation", new=mock.AsyncMock()),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

        self.run = _ScriptedRun()
        self.addCleanup(self.run.release.set)
        self.mgr = WebSocketManager()
        app = FastAPI()

        @app.websocket("/ws/agent")
        async def agent_ws(websocket: WebSocket):
            await websocket_endpoint(websocket, self.run, self.mgr)

        self.client = TestClient(app)
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)

    # -- helpers -------------------------------------------------------------

    def _connect(self):
        ws = self.client.websocket_connect("/ws/agent").__enter__()
        ws.send_json({"type": "init", "payload": {
            "user_id": "u", "project_id": "p", "session_id": "s", "ticket": _ticket()}})
        msg = ws.receive_json()
        self.assertEqual(msg["type"], "connected")
        return ws, msg["payload"]

    @staticmethod
    def _drop(ws):
        ws.__exit__(None, None, None)

    @staticmethod
    def _receive_until(ws, msg_type, limit=50):
        seen = []
        for _ in range(limit):
            msg = ws.receive_json()
            seen.append(msg["type"])
            if msg["type"] == msg_type:
                return msg["payload"], seen
        raise AssertionError(f"{msg_type} never arrived; got {seen}")

    def _start_run(self):
        ws, hello = self._connect()
        self.assertIs(hello["agent_running"], False)
        ws.send_json({"type": "query", "payload": {"question": "exploit it"}})
        start, _ = self._receive_until(ws, "tool_start")
        self.assertEqual(start["step_id"], "step0001")
        self.assertTrue(self.run.started.wait(5))
        return ws

    # -- scenarios ------------------------------------------------------------

    def test_run_finishing_while_the_page_is_away_is_reported_on_reconnect(self):
        """The incident: drop mid-tool, the run ends into a dead socket, the page
        comes back. It must learn the run is over and find the gap persisted."""
        ws = self._start_run()
        self._drop(ws)
        self.run.release.set()
        _wait_until(lambda: self.mgr.get_task(KEY) is None and self.mgr.get_callback(KEY) is None,
                    what="the run to finish")

        ws2, hello = self._connect()
        self.assertIs(hello["agent_running"], False,
                      "a finished run must not leave the reconnected page spinning")
        for missed in ("tool_finished", "tool_complete", "assistant_message", "task_complete"):
            self.assertIn(missed, self.saved, f"{missed} lost while the page was away")
        self._drop(ws2)

    def test_reconnect_mid_run_resumes_the_live_stream(self):
        ws = self._start_run()
        self._drop(ws)
        ws2, hello = self._connect()
        self.assertIs(hello["agent_running"], True)
        self.run.release.set()
        finished, _ = self._receive_until(ws2, "tool_finished")
        self.assertEqual(finished["step_id"], "step0001")
        complete, _ = self._receive_until(ws2, "tool_complete")
        self.assertEqual(complete["step_id"], "step0001")
        self._receive_until(ws2, "task_complete")
        self._drop(ws2)

    def test_reconnect_while_the_final_messages_are_still_persisting(self):
        """The run already sent response/task_complete; a page reconnecting
        during the persist drain must be told the run is over."""
        self.save_delay = 0.4
        ws = self._start_run()
        self._drop(ws)
        self.run.release.set()
        _wait_until(lambda: self.mgr.get_task(KEY) is None, what="the run to release its task")
        self.assertIsNotNone(self.mgr.get_callback(KEY), "drain already over; the window was missed")
        ws2, hello = self._connect()
        self.assertIs(hello["agent_running"], False)
        self._drop(ws2)
        _wait_until(lambda: self.mgr.get_callback(KEY) is None, timeout=20, what="the drain")

    def test_stop_then_reconnect_reports_idle(self):
        ws = self._start_run()
        ws.send_json({"type": "stop", "payload": {}})
        self._receive_until(ws, "stopped")
        self._drop(ws)
        _wait_until(lambda: self.mgr.get_callback(KEY) is None, what="the stopped run to clean up")
        ws2, hello = self._connect()
        self.assertIs(hello["agent_running"], False)
        self._drop(ws2)


@unittest.skipUnless(_HAVE, "agent image deps unavailable")
class RegistryOwnership(unittest.IsolatedAsyncioTestCase):
    async def test_a_finishing_run_never_clears_a_newer_run(self):
        mgr = WebSocketManager()
        old = asyncio.ensure_future(asyncio.sleep(10))
        new = asyncio.ensure_future(asyncio.sleep(10))
        cb_old, cb_new = object(), object()
        mgr.register_task(KEY, old)
        mgr.register_callback(KEY, cb_old)
        # A new query registers while the old run is still draining.
        mgr.register_task(KEY, new)
        mgr.register_callback(KEY, cb_new)
        mgr.release_task(KEY, old)
        mgr.release_callback(KEY, cb_old)
        self.assertIs(mgr.get_task(KEY), new)
        self.assertIs(mgr.get_callback(KEY), cb_new)
        mgr.release_task(KEY, new)
        mgr.release_callback(KEY, cb_new)
        self.assertIsNone(mgr.get_task(KEY))
        self.assertIsNone(mgr.get_callback(KEY))
        old.cancel()
        new.cancel()


if __name__ == "__main__":
    unittest.main()
