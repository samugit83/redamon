"""A socket that closes while its run goes on gives its session-cap slot back when the run ends.

The agent caps live sessions (`_governed_max_sessions`): every registered socket's key and every
running task's key holds a slot. websocket_endpoint leaves a socket registered when it closes during
its run, so that a reconnect finds the run and takes it over. Once that run ends the closed socket
must go, or it holds its slot until the agent restarts: a client that closes on `task_complete`
(the run is still saving its last messages then), or a tab closed mid-run, would each leak one,
and after enough of them every new chat is refused with 1013.

These drive the real websocket_endpoint, WebSocketHandler, StreamingCallback and persist queue;
only the orchestrator, the chat store and the webapp's checks are stand-ins.

Run: ./agentic/run_tests.sh tests/test_ws_closed_socket_slot.py
"""
import asyncio
import base64
import contextlib
import gc
import hashlib
import hmac
import json
import os
import sys
import time
import unittest
import weakref
from pathlib import Path
from unittest import mock

_AGENTIC_DIR = str(Path(__file__).resolve().parents[1])
if _AGENTIC_DIR not in sys.path:
    sys.path.insert(0, _AGENTIC_DIR)

import websocket_api  # noqa: E402
import ws_ticket  # noqa: E402
from websocket_api import WebSocketConnection, WebSocketManager, websocket_endpoint  # noqa: E402
from writer_check import WriterCheck  # noqa: E402

SECRET = "2" * 64
KEY = "u:p:s"


def _ticket(session: str) -> str:
    def b64(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    head = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = b64(json.dumps({"sub": "u", "pid": "p", "sid": session, "aud": "agent",
                           "iat": int(time.time()), "exp": int(time.time()) + 300}).encode())
    sig = hmac.new(SECRET.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()
    return f"{head}.{body}.{b64(sig)}"


class _Tab:
    """One browser tab's socket, as websocket_endpoint sees it. `close_on` names a frame
    on whose arrival the client closes at once, as the e2e runner does on task_complete."""

    def __init__(self, close_on: str = ""):
        self.client = "test"
        self.close_on = close_on
        self.inbox: asyncio.Queue = asyncio.Queue()
        self.frames: list = []
        self.gone = False
        self.close_code = None
        self.endpoint = None

    async def accept(self):
        pass

    async def receive(self):
        return await self.inbox.get()

    async def send_json(self, msg):
        if self.gone:
            raise RuntimeError("the socket is closed")
        self.frames.append(msg)
        if msg["type"] == self.close_on:
            self.hang_up()

    async def close(self, code=1000, reason=""):
        self.close_code = code
        self.hang_up()

    def send(self, msg_type: str, payload: dict = None):
        self.inbox.put_nowait({"type": "websocket.receive",
                               "text": json.dumps({"type": msg_type, "payload": payload or {}})})

    def hang_up(self):
        if not self.gone:
            self.gone = True
            self.inbox.put_nowait({"type": "websocket.disconnect", "code": 1000})

    def types(self) -> list:
        return [f["type"] for f in self.frames]

    def frame(self, msg_type: str) -> dict:
        return next(f["payload"] for f in self.frames if f["type"] == msg_type)


class _Run:
    """Stands in for AgentOrchestrator: a run that answers and ends when the test says so."""

    def __init__(self):
        self.release = asyncio.Event()
        self.started = asyncio.Event()
        self.graph = mock.MagicMock()
        self.graph.aget_state = mock.AsyncMock(return_value=None)

    async def invoke_with_streaming(self, *, streaming_callback, **_kwargs):
        self.started.set()
        await self.release.wait()
        await streaming_callback.on_response("done", 1, "informational", True)
        await streaming_callback.on_task_complete("done", "informational", 1)


class ClosedSocketSlot(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        # Cleared, the run's last messages stay unsaved, so the run is still ending.
        self.saving = asyncio.Event()
        self.saving.set()
        self.saved = []

        async def save(**kw):
            await self.saving.wait()
            self.saved.append(kw["msg_type"])

        for patcher in (
            mock.patch.dict(os.environ, {"AGENT_WS_TICKET_SECRET": SECRET}),
            mock.patch.object(ws_ticket, "ticket_tenancy_refusal", return_value=None),
            mock.patch.object(websocket_api, "second_writer_check",
                              new=mock.AsyncMock(return_value=WriterCheck(allowed=True))),
            mock.patch.object(websocket_api, "save_chat_message", side_effect=save),
            mock.patch.object(websocket_api, "update_conversation", new=mock.AsyncMock()),
            mock.patch.object(websocket_api, "schedule_sandbox_stop"),
            # One slot: a session left behind refuses the next new one.
            mock.patch.object(websocket_api, "_governed_max_sessions", return_value=1),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.mgr = WebSocketManager()
        self.run = _Run()
        self.tabs: list = []
        self.runs: list = []

    async def asyncTearDown(self):
        self.saving.set()
        self.run.release.set()
        for tab in self.tabs:
            tab.hang_up()
        pending = [t.endpoint for t in self.tabs] + self.runs
        await asyncio.wait_for(asyncio.gather(*pending, return_exceptions=True), 5)

    # -- helpers ----------------------------------------------------------------

    def open_tab(self, session: str = "s", close_on: str = "") -> _Tab:
        tab = _Tab(close_on)
        tab.endpoint = asyncio.create_task(websocket_endpoint(tab, self.run, self.mgr))
        self.tabs.append(tab)
        tab.send("init", {"user_id": "u", "project_id": "p", "session_id": session,
                          "ticket": _ticket(session)})
        return tab

    async def until(self, predicate, what: str, timeout: float = 3.0):
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while not predicate():
            if loop.time() > deadline:
                self.fail(f"timed out waiting for {what}")
            await asyncio.sleep(0.01)

    async def connected(self, tab: _Tab) -> dict:
        await self.until(lambda: "connected" in tab.types() or tab.gone, "the init's answer")
        self.assertIn("connected", tab.types(), f"init refused (close code {tab.close_code})")
        return tab.frame("connected")

    async def refused(self, tab: _Tab):
        await self.until(lambda: tab.gone, "the init's answer")
        self.assertNotIn("connected", tab.types())
        self.assertEqual(tab.close_code, 1013)

    async def start_run(self, tab: _Tab) -> asyncio.Task:
        await self.connected(tab)
        tab.send("query", {"question": "q"})
        await asyncio.wait_for(self.run.started.wait(), 3)
        run = self.mgr.get_task(KEY)
        self.assertIsNotNone(run)
        self.runs.append(run)
        return run

    async def close(self, tab: _Tab):
        """The client closes; returns once the endpoint has run its `finally`."""
        tab.hang_up()
        await asyncio.wait_for(tab.endpoint, 3)

    async def ping(self, tab: _Tab):
        tab.send("ping")
        await self.until(lambda: "pong" in tab.types(), "pong")

    def registered(self):
        conn = self.mgr.active_connections.get(KEY)
        return conn.websocket if conn is not None else None

    # -- a socket closed during its run -----------------------------------------

    async def test_closing_on_task_complete_gives_the_slot_back_once_the_run_ends(self):
        """The e2e matrix's path: the client closes on task_complete while the run is still
        saving its last messages, so the endpoint keeps the socket for the run."""
        self.saving.clear()
        tab = self.open_tab(close_on="task_complete")
        run = await self.start_run(tab)
        with self.assertLogs("websocket_api", "INFO") as logs:
            self.run.release.set()
            await asyncio.wait_for(tab.endpoint, 3)
        self.assertFalse(run.done(), "the run ended before the socket closed: not the path under test")
        self.assertTrue(any("WebSocket closed but agent task still running" in line for line in logs.output))

        self.saving.set()
        await asyncio.wait_for(run, 3)
        await self.until(lambda: not self.mgr.all_sessions(), "the closed socket's session to go")
        self.assertEqual(self.mgr.active_connections, {})
        self.assertIn("task_complete", self.saved)
        await self.connected(self.open_tab(session="s2"))

    async def test_a_tab_closed_mid_run_holds_its_slot_until_the_run_ends(self):
        tab = self.open_tab()
        run = await self.start_run(tab)
        await self.close(tab)
        self.assertEqual([(s["session_id"], s["running"]) for s in self.mgr.all_sessions()], [("s", True)])
        await self.refused(self.open_tab(session="s2"))

        self.run.release.set()
        await asyncio.wait_for(run, 3)
        await self.until(lambda: not self.mgr.all_sessions(), "the closed socket's session to go")
        self.assertIn("task_complete", self.saved)
        await self.connected(self.open_tab(session="s3"))

    async def test_a_stopped_headless_run_gives_the_slot_back(self):
        tab = self.open_tab()
        run = await self.start_run(tab)
        await self.close(tab)
        self.assertTrue(await self.mgr.stop_session(KEY, message="Session stopped (access revoked)"))
        await asyncio.wait_for(run, 3)
        await self.until(lambda: not self.mgr.all_sessions(), "the stopped run's socket to go")
        await self.connected(self.open_tab(session="s2"))

    # -- a reconnect ------------------------------------------------------------

    async def test_a_reconnect_during_the_run_takes_it_over_and_stays(self):
        first = self.open_tab()
        run = await self.start_run(first)
        await self.close(first)
        second = self.open_tab()
        self.assertIs((await self.connected(second))["agent_running"], True)

        self.run.release.set()
        await self.until(lambda: "task_complete" in second.types(), "the run's end on the new socket")
        await asyncio.wait_for(run, 3)
        await asyncio.sleep(0.05)
        self.assertIs(self.registered(), second)
        self.assertTrue(self.mgr.active_connections[KEY].authenticated)
        await self.ping(second)
        await self.close(second)
        self.assertEqual(self.mgr.active_connections, {})

    async def test_a_reconnected_tab_closed_before_the_run_ends_gives_the_slot_back(self):
        first = self.open_tab()
        run = await self.start_run(first)
        await self.close(first)
        second = self.open_tab()
        await self.connected(second)
        await self.close(second)

        self.run.release.set()
        await asyncio.wait_for(run, 3)
        await self.until(lambda: not self.mgr.all_sessions(), "the reconnected socket's session to go")
        await self.connected(self.open_tab(session="s2"))

    async def test_a_socket_a_reconnect_replaced_is_freed_before_the_run_ends(self):
        """A long run sees many reconnects (reloads, pong timeouts, two tabs taking turns);
        none of the replaced sockets may live on until the run ends."""
        first = self.open_tab()
        run = await self.start_run(first)
        second = self.open_tab()
        await self.connected(second)
        await asyncio.wait_for(first.endpoint, 3)
        second_conn = weakref.ref(self.mgr.active_connections[KEY])
        with self.assertLogs("websocket_api", "INFO") as logs:
            third = self.open_tab()
            await self.connected(third)
            await asyncio.wait_for(second.endpoint, 3)  # replaced and closed: its cleanup waits for the run
        self.assertEqual(sum("agent task still running" in line for line in logs.output), 1)

        gc.collect()
        self.assertIsNone(second_conn(), "the run's pending cleanup keeps the replaced socket alive")
        self.assertFalse(run.done())
        self.run.release.set()
        await asyncio.wait_for(run, 3)
        await asyncio.sleep(0.05)
        self.assertIs(self.registered(), third)
        self.assertEqual(self.mgr._deferred_disconnects, set())

    async def test_a_reconnect_while_the_run_is_ending_keeps_its_entry(self):
        """The old socket closed on task_complete; the new one registers while the run is still
        saving, and the run's end must not drop it."""
        self.saving.clear()
        first = self.open_tab(close_on="task_complete")
        run = await self.start_run(first)
        self.run.release.set()
        await asyncio.wait_for(first.endpoint, 3)
        self.assertFalse(run.done())

        second = self.open_tab()
        await self.until(lambda: self.registered() is second, "the reconnect's registration")
        self.saving.set()
        self.assertIs((await self.connected(second))["agent_running"], False)
        await asyncio.wait_for(run, 3)
        await asyncio.sleep(0.05)
        self.assertIs(self.registered(), second)
        await self.ping(second)
        await self.close(second)
        self.assertEqual(self.mgr.active_connections, {})

    # -- a socket open at the run's end ----------------------------------------

    async def test_a_tab_open_at_the_runs_end_stays_and_its_close_disconnects(self):
        tab = self.open_tab()
        run = await self.start_run(tab)
        self.run.release.set()
        await self.until(lambda: "task_complete" in tab.types(), "task_complete")
        await asyncio.wait_for(run, 3)
        await asyncio.sleep(0.05)
        self.assertIs(self.registered(), tab)
        await self.ping(tab)

        with self.assertLogs("websocket_api", "INFO") as logs:
            await self.close(tab)
        self.assertIn(f"INFO:websocket_api:Disconnected session: {KEY}", logs.output)
        self.assertFalse(any("still running" in line for line in logs.output))
        self.assertEqual(self.mgr.active_connections, {})


class DeferredDisconnect(unittest.IsolatedAsyncioTestCase):
    """The cleanup a closed socket's run leaves behind removes that socket only."""

    async def asyncSetUp(self):
        patcher = mock.patch.object(websocket_api, "_governed_max_sessions", return_value=1)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.mgr = WebSocketManager()

    async def socket(self) -> WebSocketConnection:
        conn = WebSocketConnection(_Tab())
        await self.mgr.authenticate(conn, "u", "p", "s", verified=True)
        self.assertTrue(conn.authenticated)
        return conn

    async def test_a_reconnect_landing_as_the_run_ends_keeps_its_entry(self):
        old = await self.socket()
        run = asyncio.get_running_loop().create_future()
        self.mgr.disconnect_when_done(old, run)
        run.set_result(None)  # the run has ended; the old socket's cleanup is queued, not yet run
        new = await self.socket()
        self.assertEqual(old.websocket.close_code, 1000, "the reconnect did not replace the old socket")
        await asyncio.sleep(0.05)
        self.assertIs(self.mgr.active_connections.get(KEY), new)
        self.assertEqual(self.mgr._deferred_disconnects, set())

    async def test_a_reconnect_after_the_cleanup_is_admitted_as_a_new_session(self):
        old = await self.socket()
        run = asyncio.get_running_loop().create_future()
        self.mgr.disconnect_when_done(old, run)
        run.set_result(None)
        await asyncio.sleep(0.05)
        self.assertEqual(self.mgr.active_connections, {})
        self.assertEqual(self.mgr._deferred_disconnects, set())
        new = await self.socket()
        self.assertIsNone(old.websocket.close_code)
        self.assertIs(self.mgr.active_connections.get(KEY), new)

    async def test_nothing_is_removed_while_the_run_goes_on(self):
        old = await self.socket()
        run = asyncio.get_running_loop().create_future()
        self.mgr.disconnect_when_done(old, run)
        await asyncio.sleep(0.05)
        self.assertIs(self.mgr.active_connections.get(KEY), old)
        self.assertEqual(self.mgr._deferred_disconnects, set())

    async def test_the_socket_goes_however_the_run_ends(self):
        endings = {
            "done": lambda run: run.set_result(None),
            "exception": lambda run: run.set_exception(RuntimeError("the run failed")),
            "cancelled": lambda run: run.cancel(),  # a stopped run
        }
        for name, end in endings.items():
            with self.subTest(name):
                old = await self.socket()
                run = asyncio.get_running_loop().create_future()
                self.mgr.disconnect_when_done(old, run)
                end(run)
                await asyncio.sleep(0.05)
                self.assertEqual(self.mgr.active_connections, {})
                self.assertEqual(self.mgr._deferred_disconnects, set())
                if name == "exception":
                    self.assertIsInstance(run.exception(), RuntimeError)

    async def test_a_cleanup_task_leaves_the_set_however_it_ends(self):
        async def failing_disconnect(connection):
            async with self.mgr.lock:
                raise RuntimeError("the cleanup failed")

        for name in ("done", "exception", "cancelled"):
            with self.subTest(name):
                self.mgr = WebSocketManager()
                old = await self.socket()
                run = asyncio.get_running_loop().create_future()
                self.mgr.disconnect_when_done(old, run)
                with mock.patch.object(self.mgr, "disconnect", new=failing_disconnect) \
                        if name == "exception" else contextlib.nullcontext():
                    async with self.mgr.lock:  # the cleanup task waits here
                        run.set_result(None)
                        await asyncio.sleep(0.05)
                        (cleanup,) = self.mgr._deferred_disconnects
                        if name == "cancelled":
                            cleanup.cancel()
                    await asyncio.sleep(0.05)
                self.assertTrue(cleanup.done())
                self.assertEqual(self.mgr._deferred_disconnects, set())
                if name == "done":
                    self.assertIsNone(cleanup.exception())
                    self.assertEqual(self.mgr.active_connections, {})
                elif name == "exception":
                    self.assertIsInstance(cleanup.exception(), RuntimeError)
                else:
                    self.assertTrue(cleanup.cancelled())

    async def test_a_replaced_socket_is_not_kept_alive_by_its_runs_cleanup(self):
        old = await self.socket()
        run = asyncio.get_running_loop().create_future()
        self.mgr.disconnect_when_done(old, run)
        new = await self.socket()  # a reconnect replaces it
        replaced = weakref.ref(old)
        del old
        gc.collect()
        self.assertIsNone(replaced(), "the run's pending cleanup keeps the replaced socket alive")
        run.set_result(None)
        await asyncio.sleep(0.05)
        self.assertIs(self.mgr.active_connections.get(KEY), new)
        self.assertEqual(self.mgr._deferred_disconnects, set())

    async def test_a_run_cancelled_before_its_first_step_still_frees_the_socket(self):
        """Its coroutine never runs, so neither does its `finally` (_finish_run)."""
        old = await self.socket()
        steps = []

        async def body():
            steps.append("started")
            await asyncio.sleep(10)

        run = asyncio.ensure_future(body())
        self.mgr.disconnect_when_done(old, run)
        run.cancel()
        await asyncio.sleep(0.05)
        self.assertEqual(steps, [])
        self.assertEqual(self.mgr.active_connections, {})
        self.assertEqual(self.mgr._deferred_disconnects, set())


if __name__ == "__main__":
    unittest.main()
