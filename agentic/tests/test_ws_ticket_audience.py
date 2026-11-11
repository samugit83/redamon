"""
A WebSocket ticket names the socket it opens (HD-25, F-20).

One ticket used to open every agent socket: a ticket minted for the chat drawer
opened the Kali terminal's root shell as well. The webapp now writes the socket
into `aud` (`agent`, `kali-terminal`, `cypherfix-triage`, `cypherfix-codefix`),
and each socket refuses a ticket without `aud` or with another socket's.

Part A drives verify_ws_ticket / authorize_ws directly. Part B drives each of the
four real endpoints through the FastAPI app with a ticket of every audience.

Run: ./agentic/run_tests.sh tests/test_ws_ticket_audience.py
"""
import asyncio
import base64
import hashlib
import hmac
import json
import os
import sys
import time
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from unittest import mock

_AGENTIC_DIR = str(Path(__file__).resolve().parents[1])
if _AGENTIC_DIR not in sys.path:
    sys.path.insert(0, _AGENTIC_DIR)

from ws_ticket import WS_AUDIENCES, authorize_ws, verify_ws_ticket  # noqa: E402

SECRET = "a" * 64
SOCKETS = ("agent", "kali-terminal", "cypherfix-triage", "cypherfix-codefix")
MISSING = object()


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _ticket(aud=MISSING, secret=SECRET, **over) -> str:
    claims = {"sub": "u1", "pid": "p1", "sid": "s1",
              "iat": int(time.time()), "exp": int(time.time()) + 60}
    if aud is not MISSING:
        claims["aud"] = aud
    claims.update(over)
    head = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = _b64url(json.dumps(claims).encode())
    sig = hmac.new(secret.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()
    return f"{head}.{body}.{_b64url(sig)}"


class VerifyAudience(unittest.TestCase):
    def test_the_four_sockets(self):
        self.assertEqual(tuple(WS_AUDIENCES), SOCKETS)

    def test_each_socket_accepts_its_own_audience(self):
        for socket in SOCKETS:
            claims = verify_ws_ticket(_ticket(socket), SECRET, expected_aud=socket)
            self.assertIsNotNone(claims, socket)
            self.assertEqual(claims["aud"], socket)

    def test_each_socket_refuses_the_other_three_and_a_missing_aud(self):
        for socket in SOCKETS:
            for other in SOCKETS:
                if other == socket:
                    continue
                with self.subTest(socket=socket, presented=other):
                    self.assertIsNone(verify_ws_ticket(_ticket(other), SECRET, expected_aud=socket))
            with self.subTest(socket=socket, presented="none"):
                self.assertIsNone(verify_ws_ticket(_ticket(), SECRET, expected_aud=socket))

    def test_an_aud_that_is_not_a_plain_name_is_refused(self):
        # jose's setAudience writes a list; the webapp writes a plain claim.
        for aud in (["kali-terminal"], "", None, "KALI-TERMINAL", 1):
            with self.subTest(aud=aud):
                self.assertIsNone(verify_ws_ticket(_ticket(aud), SECRET, expected_aud="kali-terminal"))

    def test_an_unknown_expected_audience_refuses_every_ticket(self):
        self.assertIsNone(verify_ws_ticket(_ticket("shell"), SECRET, expected_aud="shell"))

    def test_the_audience_is_a_required_argument(self):
        with self.assertRaises(TypeError):
            verify_ws_ticket(_ticket("agent"), SECRET)  # noqa: the call must not compile to "any socket"

    def test_a_refused_audience_logs_the_rbac_line(self):
        with self.assertLogs("ws_ticket", level="WARNING") as logs:
            verify_ws_ticket(_ticket("agent"), SECRET, expected_aud="kali-terminal")
        self.assertIn("[rbac] ticket refused aud=kali-terminal presented=agent", "\n".join(logs.output))

    def test_a_missing_audience_logs_none(self):
        with self.assertLogs("ws_ticket", level="WARNING") as logs:
            verify_ws_ticket(_ticket(), SECRET, expected_aud="agent")
        self.assertIn("[rbac] ticket refused aud=agent presented=none", "\n".join(logs.output))

    def test_a_forged_ticket_never_reaches_the_rbac_log(self):
        # Only a ticket the webapp signed may put its claim in the log.
        forged = _ticket("bogus\nINJECTED", secret="b" * 64)
        with mock.patch("ws_ticket.logger") as log:
            self.assertIsNone(verify_ws_ticket(forged, SECRET, expected_aud="agent"))
        log.warning.assert_not_called()

    def test_an_unexpected_presented_value_is_logged_as_other(self):
        with self.assertLogs("ws_ticket", level="WARNING") as logs:
            verify_ws_ticket(_ticket("bogus\nINJECTED"), SECRET, expected_aud="agent")
        text = "\n".join(logs.output)
        self.assertIn("presented=other", text)
        self.assertNotIn("INJECTED", text)

    def test_an_expired_ticket_of_the_right_audience_is_still_refused(self):
        stale = _ticket("agent", exp=int(time.time()) - 120)
        self.assertIsNone(verify_ws_ticket(stale, SECRET, expected_aud="agent"))


class AuthorizeAudience(unittest.TestCase):
    def setUp(self):
        self._env = mock.patch.dict(os.environ, {"AGENT_WS_TICKET_SECRET": SECRET})
        self._env.start()

    def tearDown(self):
        self._env.stop()

    def test_authorize_passes_the_audience_through(self):
        ok, claims, _ = authorize_ws("https://good", "good", _ticket("cypherfix-triage"), [], aud="cypherfix-triage")
        self.assertTrue(ok)
        self.assertEqual(claims["aud"], "cypherfix-triage")
        ok, claims, reason = authorize_ws("https://good", "good", _ticket("agent"), [], aud="cypherfix-triage")
        self.assertFalse(ok)
        self.assertIsNone(claims)
        self.assertEqual(reason, "missing or invalid ticket")

    def test_authorize_needs_an_audience(self):
        with self.assertRaises(TypeError):
            authorize_ws("https://good", "good", _ticket("agent"), [])


# --- Part B: the four endpoints ------------------------------------------------
try:
    from fastapi.testclient import TestClient
    from starlette.websockets import WebSocketDisconnect
    _HAVE_APP = True
except Exception:  # pragma: no cover - only outside the agent image
    _HAVE_APP = False


@unittest.skipUnless(_HAVE_APP, "agent deps unavailable (run in-container)")
class ProxiedEndpointsCheckTheirAudience(unittest.TestCase):
    """The three proxied sockets (`authorize_ws` before accept)."""

    @classmethod
    def setUpClass(cls):
        @asynccontextmanager
        async def fake_lifespan(_app):
            yield

        with mock.patch("api.lifespan", fake_lifespan):
            import api as api_module
        cls.api = api_module
        cls.client = TestClient(api_module.app)

    def setUp(self):
        self._env = mock.patch.dict(os.environ, {"AGENT_WS_TICKET_SECRET": SECRET})
        self._env.start()

    def tearDown(self):
        self._env.stop()

    def _terminal_state(self, ticket):
        """'refused' when the proxy closes before accept, 'admitted' when it dials the sandbox."""
        dialed = []

        def refuse(*a, **k):
            dialed.append(a)
            raise ConnectionRefusedError("kali down")

        with mock.patch.object(self.api.websockets, "connect", side_effect=refuse):
            try:
                with self.client.websocket_connect(f"/ws/kali-terminal?ticket={ticket}") as ws:
                    with self.assertRaises(WebSocketDisconnect) as caught:
                        ws.receive_text()
            except WebSocketDisconnect as e:
                self.assertEqual(e.code, 1008)
                self.assertEqual(dialed, [])
                return "refused"
        self.assertEqual(caught.exception.code, 1011)
        self.assertEqual(len(dialed), 1)
        return "admitted"

    def _cypherfix_state(self, path, ticket):
        with self.client.websocket_connect(f"{path}?ticket={ticket}") as ws:
            ws.send_text(json.dumps({"type": "ping"}))
            try:
                frame = json.loads(ws.receive_text())
            except WebSocketDisconnect as e:
                self.assertEqual(e.code, 1008)
                return "refused"
        self.assertEqual(frame, {"type": "pong"})
        return "admitted"

    def _check(self, socket, state_of):
        for presented in SOCKETS:
            with self.subTest(socket=socket, presented=presented):
                want = "admitted" if presented == socket else "refused"
                self.assertEqual(state_of(_ticket(presented)), want)
        with self.subTest(socket=socket, presented="none"):
            self.assertEqual(state_of(_ticket()), "refused")

    def test_kali_terminal_refuses_the_other_three_and_a_missing_aud(self):
        self._check("kali-terminal", self._terminal_state)

    def test_cypherfix_triage_refuses_the_other_three_and_a_missing_aud(self):
        self._check("cypherfix-triage", lambda t: self._cypherfix_state("/ws/cypherfix-triage", t))

    def test_cypherfix_codefix_refuses_the_other_three_and_a_missing_aud(self):
        self._check("cypherfix-codefix", lambda t: self._cypherfix_state("/ws/cypherfix-codefix", t))


class _FakeWS:
    def __init__(self):
        self.closed = None
        self.client = "test"
        self.sent = []

    async def close(self, code=1000, reason=""):
        self.closed = (code, reason)

    async def send_json(self, msg):
        self.sent.append(msg)


@unittest.skipUnless(_HAVE_APP, "agent deps unavailable (run in-container)")
class AgentSocketChecksItsAudience(unittest.TestCase):
    """`/ws/agent` reads the ticket from its init frame (handle_init)."""

    def _init(self, ticket):
        from websocket_api import WebSocketConnection, WebSocketHandler, WebSocketManager

        async def scenario():
            mgr = WebSocketManager()
            conn = WebSocketConnection(_FakeWS())
            await WebSocketHandler(orchestrator=None, ws_manager=mgr).handle_init(
                conn, {"user_id": "spoof", "project_id": "spoof", "session_id": "s1", "ticket": ticket})
            return conn

        with mock.patch.dict(os.environ, {"AGENT_WS_TICKET_SECRET": SECRET}):
            return asyncio.run(scenario())

    def test_agent_refuses_the_other_three_and_a_missing_aud(self):
        for presented in [s for s in SOCKETS if s != "agent"] + [MISSING]:
            with self.subTest(presented=presented if presented is not MISSING else "none"):
                conn = self._init(_ticket(presented))
                self.assertFalse(conn.authenticated)
                self.assertEqual(conn.websocket.closed, (1008, "Invalid or missing ticket"))

    def test_agent_accepts_its_own_audience_and_keeps_the_real_actor(self):
        conn = self._init(_ticket("agent", act="admin-1"))
        self.assertTrue(conn.authenticated)
        self.assertEqual((conn.user_id, conn.project_id), ("u1", "p1"))
        self.assertEqual(conn.actor_id, "admin-1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
