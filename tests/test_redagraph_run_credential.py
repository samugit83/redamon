"""
redagraph presents the terminal's run credential, never the scanner key (HD-19, NF-01).

The sandbox no longer holds SCANNER_API_KEY. The agent's /ws/kali-terminal proxy
mints a 12-hour `graph` credential per connection and sends it on the upgrade as
X-Redamon-Run; the terminal server puts it into the shell as
REDAMON_RUN_CREDENTIAL; redagraph sends it on both of its calls (/graph/exec and
/text-to-cypher). A shell without one, or with an expired one, gets a message that
says what to do instead of a bare 401.

Runs in the agent image (root-agent section).
Run: python -m pytest tests/test_redagraph_run_credential.py
"""
import io
import json
import os
import sys
import types
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "mcp" / "servers"))

import redagraph  # noqa: E402
import terminal_server  # noqa: E402

try:
    import websockets
    _HAVE_WS = True
except Exception:  # pragma: no cover - the agent image has websockets
    _HAVE_WS = False

CRED = "eyJhdWQiOiJncmFwaCJ9.c2lnbmF0dXJl"


def _resp(status, payload):
    r = mock.MagicMock()
    r.status_code = status
    r.json.return_value = payload
    r.text = json.dumps(payload)
    return r


def _ask_args():
    return types.SimpleNamespace(question=["list", "domains"], show=False, format="plain")


class Forwarding(unittest.TestCase):
    def test_forwards_the_header_on_exec_and_ask(self):
        posts = []

        def fake_post(url, json=None, headers=None, timeout=None):
            posts.append((url, dict(headers or {})))
            if url.endswith("/text-to-cypher"):
                return _resp(200, {"cypher": "MATCH (d:Domain) RETURN d.name AS name"})
            return _resp(200, {"records": []})

        env = {"REDAMON_RUN_CREDENTIAL": CRED, "SCANNER_API_KEY": "rbac-fake-scanner", "INTERNAL_API_KEY": "rbac-fake"}
        with mock.patch.dict(os.environ, env), mock.patch("requests.post", side_effect=fake_post), \
                mock.patch("sys.stdout", new_callable=io.StringIO):
            redagraph._agent_post({"op": "types", "user_id": "u", "project_id": "p"})
            self.assertEqual(redagraph.cmd_ask(_ask_args(), "u", "p"), 0)
        self.assertEqual([u.rsplit("/", 1)[-1] for u, _ in posts], ["exec", "text-to-cypher", "exec"])
        for _url, headers in posts:
            self.assertEqual(headers, {"X-Redamon-Run": CRED})

    def test_no_credential_clear_error(self):
        env = {k: v for k, v in os.environ.items() if k != "REDAMON_RUN_CREDENTIAL"}
        for call in (lambda: redagraph._agent_post({"op": "types", "user_id": "u", "project_id": "p"}),
                     lambda: redagraph.cmd_ask(_ask_args(), "u", "p")):
            err = io.StringIO()
            with mock.patch.dict(os.environ, env, clear=True), mock.patch("requests.post") as post, \
                    redirect_stderr(err), self.assertRaises(SystemExit) as cm:
                call()
            post.assert_not_called()
            self.assertEqual(cm.exception.code, 2)
            self.assertIn("no graph credential", err.getvalue())
            self.assertIn("Graph -> Terminal", err.getvalue())

    def test_expired_reopen_message(self):
        expired = _resp(401, {"detail": {"error": "run credential expired", "code": "run_credential_expired"}})
        for call in (lambda: redagraph._agent_post({"op": "types", "user_id": "u", "project_id": "p"}),
                     lambda: redagraph.cmd_ask(_ask_args(), "u", "p")):
            err = io.StringIO()
            with mock.patch.dict(os.environ, {"REDAMON_RUN_CREDENTIAL": CRED}), \
                    mock.patch("requests.post", return_value=expired), redirect_stderr(err), \
                    self.assertRaises(SystemExit) as cm:
                call()
            self.assertEqual(cm.exception.code, 2)
            self.assertIn("the terminal session expired: reopen the terminal", err.getvalue())

    def test_another_refusal_also_says_to_reopen(self):
        refused = _resp(401, {"detail": {"error": "run credential refused", "code": "run_credential_bad_signature"}})
        err = io.StringIO()
        with mock.patch.dict(os.environ, {"REDAMON_RUN_CREDENTIAL": CRED}), \
                mock.patch("requests.post", return_value=refused), redirect_stderr(err), \
                self.assertRaises(SystemExit) as cm:
            redagraph._agent_post({"op": "types", "user_id": "u", "project_id": "p"})
        self.assertEqual(cm.exception.code, 2)
        self.assertIn("reopen the terminal", err.getvalue())
        self.assertNotIn(CRED, err.getvalue())


@unittest.skipUnless(_HAVE_WS, "websockets unavailable")
class TheTerminalServerHandsItToTheShell(unittest.IsolatedAsyncioTestCase):
    """The proxy's header becomes REDAMON_RUN_CREDENTIAL in the shell (real server, no PTY)."""

    async def asyncSetUp(self):
        self.started = []

        async def capture(ws, tenant_env=None):
            self.started.append(tenant_env)
            await ws.send("ok")

        self._p = mock.patch.object(terminal_server, "_run_pty_session", capture)
        self._p.start()
        self._e = mock.patch.dict(os.environ, {"MCP_AUTH_TOKEN": "terminal-test-token"})
        self._e.start()
        self.server = await terminal_server.serve("127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        self.server.close()
        await self.server.wait_closed()
        self._e.stop()
        self._p.stop()

    async def _open(self, extra):
        headers = {"Authorization": "Bearer terminal-test-token", **extra}
        async with websockets.connect(f"ws://127.0.0.1:{self.port}/?user_id=uT&project_id=pT",
                                      additional_headers=headers, open_timeout=5) as ws:
            await ws.recv()
        return self.started[-1]

    async def test_the_credential_reaches_the_shell_environment(self):
        env = await self._open({"X-Redamon-Run": CRED})
        self.assertEqual(env, {"REDAMON_USER_ID": "uT", "REDAMON_PROJECT_ID": "pT", "REDAMON_RUN_CREDENTIAL": CRED})

    async def test_a_malformed_value_is_dropped(self):
        for bad in ("not a token", "a.b.c", "x" * 5000 + ".y", "a.b;rm -rf"):
            with self.subTest(value=bad[:20]):
                env = await self._open({"X-Redamon-Run": bad})
                self.assertNotIn("REDAMON_RUN_CREDENTIAL", env)

    async def test_without_the_header_the_shell_has_none(self):
        env = await self._open({})
        self.assertEqual(env, {"REDAMON_USER_ID": "uT", "REDAMON_PROJECT_ID": "pT"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
