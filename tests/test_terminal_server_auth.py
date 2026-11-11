"""
The Kali terminal server trusts only the agent's authenticated identity (NF-04).

It checked nothing: any container on redamon-network or pentest-net got a root
shell with a raw WebSocket upgrade (step 0.2, E3), and the shell took its user
and project from the browser's init frame. Now the upgrade must carry the bearer
MCP_AUTH_TOKEN that only the agent's /ws/kali-terminal proxy holds (fail closed
when it is unset), and the identity comes from the proxy's query parameters; the
init frame is still consumed but its ids are ignored.

Runs a real websockets server on loopback in the agent image.
Run: python -m pytest tests/test_terminal_server_auth.py   (root-agent section)
"""
import asyncio
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "mcp", "servers"))

import terminal_server as ts  # noqa: E402

try:
    import websockets
    from websockets.exceptions import InvalidStatus
    _HAVE_WS = True
except Exception:  # pragma: no cover - the agent image has websockets
    _HAVE_WS = False

TOKEN = "terminal-test-token"
GOOD_QUERY = "/?user_id=proxy-user&project_id=proxy-project&session_id=s1"


class _NoPty(Exception):
    pass


def _no_pty(*_a, **_k):
    raise _NoPty("a PTY was forked")


@unittest.skipUnless(_HAVE_WS, "websockets unavailable")
class UpgradeNeedsTheAgentsBearer(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.started = []

        async def capture(ws, tenant_env=None):
            self.started.append(tenant_env)
            first = await ws.recv()
            await ws.send(json.dumps({"env": tenant_env, "first": first}))

        self._patches = [
            mock.patch.object(ts, "_run_pty_session", capture),
            mock.patch.object(ts.os, "fork", side_effect=_no_pty),
            mock.patch.object(ts.pty, "openpty", side_effect=_no_pty),
        ]
        for p in self._patches:
            p.start()
        self.server = await ts.serve("127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        self.server.close()
        await self.server.wait_closed()
        for p in self._patches:
            p.stop()

    async def _status(self, path=GOOD_QUERY, headers=None):
        try:
            async with websockets.connect(f"ws://127.0.0.1:{self.port}{path}",
                                          additional_headers=headers or {}, open_timeout=5):
                return 101
        except InvalidStatus as e:
            return e.response.status_code

    async def test_upgrade_without_bearer_refused_before_any_pty_is_forked(self):
        with mock.patch.dict(os.environ, {"MCP_AUTH_TOKEN": TOKEN}):
            self.assertEqual(await self._status(), 401)
        self.assertEqual(self.started, [])
        self.assertEqual(ts._active_sessions, 0)
        ts.os.fork.assert_not_called()
        ts.pty.openpty.assert_not_called()

    async def test_no_bearer_refused(self):
        with mock.patch.dict(os.environ, {"MCP_AUTH_TOKEN": TOKEN}):
            for headers in ({"Authorization": "Bearer wrong-token"}, {"Authorization": TOKEN},
                            {"Authorization": "Basic " + TOKEN}, {"X-Internal-Key": TOKEN}):
                with self.subTest(headers=list(headers)):
                    self.assertEqual(await self._status(headers=headers), 401)
        self.assertEqual(self.started, [])

    async def test_unset_token_refuses_all(self):
        for value in ("", None):
            env = {k: v for k, v in os.environ.items() if k != "MCP_AUTH_TOKEN"}
            if value is not None:
                env["MCP_AUTH_TOKEN"] = value
            with mock.patch.dict(os.environ, env, clear=True):
                for headers in ({}, {"Authorization": "Bearer "}, {"Authorization": "Bearer " + TOKEN}):
                    with self.subTest(token=value, headers=headers):
                        self.assertEqual(await self._status(headers=headers), 401)
        self.assertEqual(self.started, [])

    async def test_the_proxy_must_name_the_user_and_the_project(self):
        with mock.patch.dict(os.environ, {"MCP_AUTH_TOKEN": TOKEN}):
            for path in ("/", "/?user_id=u", "/?project_id=p", "/?user_id=&project_id=p"):
                with self.subTest(path=path):
                    self.assertEqual(await self._status(path, {"Authorization": f"Bearer {TOKEN}"}), 400)
        self.assertEqual(self.started, [])

    async def test_identity_from_the_proxy_not_the_init_frame(self):
        spoof = json.dumps({"type": "init", "user_id": "victim", "project_id": "victim-project"})
        with mock.patch.dict(os.environ, {"MCP_AUTH_TOKEN": TOKEN}):
            async with websockets.connect(f"ws://127.0.0.1:{self.port}{GOOD_QUERY}",
                                          additional_headers={"Authorization": f"Bearer {TOKEN}"}) as ws:
                await ws.send(spoof)
                answer = json.loads(await ws.recv())
        self.assertEqual(answer["env"], {"REDAMON_USER_ID": "proxy-user", "REDAMON_PROJECT_ID": "proxy-project"})


class TenantFromTheQuery(unittest.TestCase):
    def test_reads_both_ids(self):
        self.assertEqual(ts._tenant_env("/?user_id=u1&project_id=p1&session_id=s"),
                         {"REDAMON_USER_ID": "u1", "REDAMON_PROJECT_ID": "p1"})

    def test_missing_or_blank_is_none(self):
        for path in ("/", "/?user_id=u1", "/?project_id=p1", "/?user_id=%20&project_id=p1", ""):
            with self.subTest(path=path):
                self.assertIsNone(ts._tenant_env(path))


class InitFrameIdsAreIgnored(unittest.TestCase):
    """End to end over a real PTY: the shell's ids are the proxy's, whatever the frame says."""

    def test_the_shell_sees_the_proxy_identity(self):
        expected = b"ID=proxy-user:proxy-project:END"
        frames = ["echo ID=$REDAMON_USER_ID:$REDAMON_PROJECT_ID:END\r"]

        class FakeWs:
            def __init__(self):
                self.sent = []
                self._frames = list(frames)

            async def recv(self):
                return json.dumps({"type": "init", "user_id": "victim", "project_id": "victim-project"})

            def __aiter__(self):
                return self

            async def __anext__(self):
                if self._frames:
                    return self._frames.pop(0)
                for _ in range(200):
                    if expected in b"".join(self.sent):
                        break
                    await asyncio.sleep(0.05)
                raise StopAsyncIteration

            async def send(self, data):
                self.sent.append(data)

        ws = FakeWs()
        tenant = {"REDAMON_USER_ID": "proxy-user", "REDAMON_PROJECT_ID": "proxy-project"}
        asyncio.run(asyncio.wait_for(ts._run_pty_session(ws, tenant), timeout=20))
        output = b"".join(ws.sent)
        self.assertIn(expected, output, output[-500:])
        # The init frame is consumed, never typed into the shell.
        self.assertNotIn(b"victim", output)


if __name__ == "__main__":
    unittest.main(verbosity=2)
