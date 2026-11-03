"""The memory governor's session cap counts live runs as well as connections.

A run whose browser tab closed keeps all its memory (Agent in the Loop runs are
long and often headless), so it must still hold a slot.
"""
from __future__ import annotations

import asyncio
import unittest
from unittest import mock

import websocket_api
from websocket_api import WebSocketConnection, WebSocketManager


class _FakeWS:
    def __init__(self):
        self.closed, self.close_code, self.client = False, None, "test"

    async def close(self, code=1000, reason=""):
        self.closed, self.close_code = True, code

    async def send_json(self, msg):
        pass


async def _busy():
    await asyncio.sleep(5)


class SessionCap(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        patcher = mock.patch.object(websocket_api, "_governed_max_sessions", return_value=2)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.mgr = WebSocketManager()
        self.tasks = []

    async def asyncTearDown(self):
        for task in self.tasks:
            task.cancel()

    async def connect(self, session, verified=True):
        conn = WebSocketConnection(_FakeWS())
        await self.mgr.authenticate(conn, "u", "p", session, verified=verified)
        return conn

    def headless_run(self, session):
        """A run whose connection went away: task registered, no connection."""
        task = asyncio.ensure_future(_busy())
        self.tasks.append(task)
        self.mgr.register_task(f"u:p:{session}", task)
        return task

    async def test_two_connections_refuse_a_third_new_key(self):
        await self.connect("a")
        await self.connect("b")
        third = await self.connect("c")
        self.assertFalse(third.authenticated)
        self.assertEqual(third.websocket.close_code, 1013)

    async def test_a_headless_run_holds_its_slot(self):
        await self.connect("a")
        self.headless_run("b")
        new = await self.connect("c")
        self.assertFalse(new.authenticated)
        self.assertEqual(new.websocket.close_code, 1013)

    async def test_the_headless_run_itself_may_reconnect(self):
        await self.connect("a")
        task = self.headless_run("b")
        back = await self.connect("b", verified=True)
        self.assertTrue(back.authenticated)
        self.assertIs(self.mgr.active_connections["u:p:b"], back)
        self.assertIs(self.mgr.get_task("u:p:b"), task)

    async def test_an_unverified_peer_on_a_run_only_key_is_a_new_session(self):
        await self.connect("a")
        self.headless_run("b")
        peer = await self.connect("b", verified=False)
        self.assertFalse(peer.authenticated)
        self.assertEqual(peer.websocket.close_code, 1013)

    async def test_s6_still_refuses_an_unverified_takeover_of_a_live_connection(self):
        victim = await self.connect("a")
        attacker = await self.connect("a", verified=False)
        self.assertFalse(attacker.authenticated)
        self.assertEqual(attacker.websocket.close_code, 1008)
        self.assertIs(self.mgr.active_connections["u:p:a"], victim)

    async def test_a_finished_run_no_longer_counts(self):
        await self.connect("a")
        task = self.headless_run("b")
        task.cancel()
        await asyncio.sleep(0)
        new = await self.connect("c")
        self.assertTrue(new.authenticated)


if __name__ == "__main__":
    unittest.main()
