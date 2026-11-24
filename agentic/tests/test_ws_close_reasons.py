"""
The close code and reason the browser gets from the agent's sockets.

A close sent before accept() refuses the handshake: the browser sees a bare
1006 and the drawer can only say "Connection failed". /ws/agent accepts first
when it cannot serve, so its 1011 reason reaches the drawer; the Kali terminal
proxy closes with 1011 and the exception's class when the sandbox's terminal
cannot be reached, instead of a plain close that reads like a normal logout.

Run: ./agentic/run_tests.sh tests/test_ws_close_reasons.py
"""
import sys
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import patch

_AGENTIC_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_AGENTIC_DIR))


class _AppTestBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        @asynccontextmanager
        async def fake_lifespan(_app):
            yield

        with patch("api.lifespan", fake_lifespan):
            import api as api_module
            cls.api = api_module
            from fastapi.testclient import TestClient
            from starlette.websockets import WebSocketDisconnect
            cls.client = TestClient(api_module.app)
            cls.Disconnect = WebSocketDisconnect


class AgentSocketNotReady(_AppTestBase):
    def test_orchestrator_missing_is_accepted_then_closed_with_its_reason(self):
        with patch.object(self.api, "orchestrator", None):
            # Entering the block means the handshake was accepted (a close
            # before accept raises right here instead).
            with self.client.websocket_connect("/ws/agent") as ws:
                with self.assertRaises(self.Disconnect) as caught:
                    ws.receive_text()
        self.assertEqual(caught.exception.code, 1011)
        self.assertEqual(caught.exception.reason, "Orchestrator not initialized")


class KaliTerminalUnavailable(_AppTestBase):
    def setUp(self):
        import sandbox_router
        from one_sandbox import route_to

        # The terminal opens on its person's own sandbox (one_sandbox's handle).
        sandbox_router._reset()
        self.addCleanup(sandbox_router._reset)
        route_to(self, {})

    def test_an_unreachable_sandbox_closes_1011_with_the_class(self):
        claims = {"sub": "u", "pid": "p", "sid": "s"}

        def refuse(*_a, **_k):
            raise ConnectionRefusedError("ws://kali-sandbox:8016?user_id=u&project_id=p")

        with patch("ws_ticket.authorize_ws", return_value=(True, claims, "ok")), \
                patch.object(self.api.websockets, "connect", side_effect=refuse):
            with self.client.websocket_connect("/ws/kali-terminal?ticket=t") as ws:
                with self.assertRaises(self.Disconnect) as caught:
                    ws.receive_text()
        self.assertEqual(caught.exception.code, 1011)
        self.assertEqual(caught.exception.reason, "Kali sandbox terminal unavailable (ConnectionRefusedError)")
        self.assertNotIn("kali-sandbox:8016", caught.exception.reason)


if __name__ == "__main__":
    unittest.main(verbosity=2)
