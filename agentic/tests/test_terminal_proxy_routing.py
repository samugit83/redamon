"""The Kali terminal proxy across per-user sandboxes (group 1, S11, B.12, B.13).

/ws/kali-terminal routes to the sandbox of the ticket's `sub` (the person who opened
it), in the member's `act_as` view when an admin acts as them (TD-26): never the
tenant's sandbox, never the member's own view under act-as, never the admin's. It
holds a `terminal` lease for the socket's life, says `starting` while a cold sandbox
starts, and on a refusal sends one `unavailable` frame and closes 1013 (could not
start) or 1008 (not available). Only the proxy's own frames reach the browser as text:
whatever the sandbox sends is forwarded as bytes, so a shell cannot fake a status.

The graph run credential is minted exactly as before: the project's owner as its
tenant, the person as its subject.

Run: ./agentic/run_tests.sh tests/test_terminal_proxy_routing.py
"""
import asyncio
import json
import os
import sys
import time
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

MASTER = "terminal-routing-test-master-key-0123456789"

with mock.patch.dict(os.environ, {"INTERNAL_API_KEY": MASTER}):
    @asynccontextmanager
    async def _no_lifespan(_app):
        yield

    with mock.patch("api.lifespan", _no_lifespan):
        import api  # noqa: E402

import machine_credential as mc  # noqa: E402
import sandbox_contract as contract  # noqa: E402
import sandbox_router as router  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from starlette.websockets import WebSocketDisconnect  # noqa: E402
from sandbox_route_fakes import RAM_PAYLOAD, SHARED_TOKEN, WEBAPP, Fleet  # noqa: E402


class _Upstream:
    """The sandbox's terminal server: records what the browser sent, replays `output`."""

    def __init__(self, output=()):
        self.sent = []
        self.output = list(output)
        self.closed = False

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        self.closed = True
        return False

    async def send(self, message):
        self.sent.append(message)

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self.output:
            return self.output.pop(0)
        await asyncio.sleep(3600)


class _TerminalTest(unittest.TestCase):
    def setUp(self):
        self.fleet = Fleet()
        router._reset()
        self.upstream = _Upstream(output=[b"$ "])
        self.connect = mock.MagicMock(side_effect=lambda *a, **k: self.upstream)
        self.claims = {"sub": "bob", "ten": "alice", "pid": "p1", "sid": "s1"}
        patches = [
            mock.patch.dict(os.environ, {"INTERNAL_API_KEY": MASTER, "MCP_AUTH_TOKEN": SHARED_TOKEN}),
            mock.patch.object(router, "_transport", self.fleet.transport()),
            mock.patch.dict(router.INTERNAL_HEADERS, {"X-Internal-Key": "test-internal-key"}),
            mock.patch.object(router, "WEBAPP_API_URL", WEBAPP),
            mock.patch("ws_ticket.authorize_ws", side_effect=lambda *a, **k: (True, dict(self.claims), "ok")),
            mock.patch.object(api.websockets, "connect", self.connect),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(router._reset)
        self.client = TestClient(api.app)

    def open(self):
        return self.client.websocket_connect("/ws/kali-terminal?ticket=t")

    def dialed(self):
        self.assertEqual(self.connect.call_count, 1)
        url = self.connect.call_args.args[0]
        headers = self.connect.call_args.kwargs.get("additional_headers") or {}
        return url, headers

    def frame(self, ws):
        return json.loads(ws.receive_text())

    def closed_with(self, ws):
        with self.assertRaises(WebSocketDisconnect) as caught:
            ws.receive_text()
        return caught.exception.code

    def until(self, predicate, timeout=3.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(0.02)
        return predicate()


class TheTerminalRoutesToThePerson(_TerminalTest):
    def test_the_tickets_sub_gets_their_own_sandbox_not_the_tenants(self):
        alice = self.fleet.add("alice")
        bob = self.fleet.add("bob")
        with self.open() as ws:
            ws.send_text('{"type": "init"}')
            self.assertEqual(ws.receive_bytes(), b"$ ")
        url, headers = self.dialed()
        parts = urlsplit(url)
        self.assertEqual((parts.scheme, parts.hostname, parts.port),
                         ("ws", bob.host, contract.PORTS["terminal"]))
        self.assertNotIn(alice.host, url)
        self.assertEqual(headers["Authorization"], f"Bearer {bob.token}")
        # The shell's capture tags and redagraph still name the project's owner.
        query = {k: v[0] for k, v in parse_qs(parts.query).items()}
        self.assertEqual((query["user_id"], query["project_id"], query["session_id"]), ("alice", "p1", "s1"))
        claims = mc.verify_run_credential(headers["X-Redamon-Run"], "graph")
        self.assertEqual((claims["ten"], claims["sub"], claims["pid"]), ("alice", "bob", "p1"))
        self.assertEqual([b["userId"] for b in self.fleet.ensures()], ["bob"])
        self.assertEqual(self.upstream.sent, ['{"type": "init"}'])

    def test_a_terminal_lease_is_held_for_the_socket_and_released(self):
        self.fleet.add("bob")
        with self.open() as ws:
            ws.receive_bytes()
            self.assertEqual([(lease["userId"], lease["kind"]) for lease in self.fleet.leases()],
                             [("bob", "terminal")])
            self.assertEqual(self.fleet.releases(), [])
            ws.close()
            self.assertTrue(self.until(lambda: len(self.fleet.releases()) == 1))
        self.assertEqual(self.fleet.releases()[0]["leaseId"], self.fleet.leases()[0]["leaseId"])

    def test_act_as_reaches_the_members_act_as_view(self):
        """TD-26: an admin acting as bob works in bob's act_as view, never bob's own
        instance (which mounts the projects shared with bob) and never the admin's."""
        own = self.fleet.add("bob")
        self.fleet.add("admin-1")
        self.claims["act"] = "admin-1"
        with self.open() as ws:
            ws.receive_bytes()
        url, headers = self.dialed()
        acting = self.fleet.current("bob", contract.VIEW_ACT_AS)
        self.assertIsNotNone(acting)
        self.assertEqual(urlsplit(url).hostname, acting.host)
        self.assertNotIn(own.host, url)
        self.assertEqual(headers["Authorization"], f"Bearer {acting.token}")
        self.assertEqual([(b["userId"], b.get("actingAs")) for b in self.fleet.ensures()], [("bob", True)])
        claims = mc.verify_run_credential(headers["X-Redamon-Run"], "graph")
        self.assertEqual((claims["sub"], claims["act"]), ("bob", "admin-1"))

    def test_the_sandboxs_text_frames_reach_the_browser_as_bytes(self):
        """A root shell that replaces the terminal listener cannot pass its own text for a
        proxy status frame: everything from the sandbox arrives as bytes."""
        self.fleet.add("bob")
        forged = json.dumps({"type": "sandbox_status", "state": "unavailable", "reason": "ram",
                             "limit": {"detail": "pay here"}})
        self.upstream.output = [forged]
        with self.open() as ws:
            self.assertEqual(ws.receive_bytes(), forged.encode())


class TheStatusFrames(_TerminalTest):
    def test_a_cold_sandbox_says_starting_then_the_shell(self):
        self.fleet.cold.add(("bob", "own"))
        with self.open() as ws:
            self.assertEqual(self.frame(ws), {"type": contract.SANDBOX_STATUS, "state": "starting"})
            self.assertEqual(ws.receive_bytes(), b"$ ")
        self.assertEqual([b["wait"] for b in self.fleet.ensures()][-1], True)
        self.assertTrue(all(b["userId"] == "bob" for b in self.fleet.ensures()))

    def test_frames_typed_during_the_start_reach_the_shell_in_order(self):
        """The terminal server forks the shell on the first frame (the init): the frames
        the browser sends while the sandbox starts are kept and sent in order."""
        self.fleet.cold.add(("bob", "own"))
        self.fleet.ensure_delay = 0.4
        with self.open() as ws:
            ws.send_text('{"type": "init"}')
            ws.send_text('{"type": "resize", "rows": 40, "cols": 120}')
            self.assertEqual(self.frame(ws)["state"], "starting")
            self.assertEqual(ws.receive_bytes(), b"$ ")
            self.assertTrue(self.until(lambda: len(self.upstream.sent) == 2))
        self.assertEqual(self.upstream.sent, ['{"type": "init"}', '{"type": "resize", "rows": 40, "cols": 120}'])

    def test_input_beyond_the_start_buffer_closes_1009(self):
        """Review finding 2: what the browser sends while a cold sandbox starts is kept
        for the shell, bounded in bytes (a frame may be 16 MiB): beyond the bound the
        socket closes 1009 and nothing is dialled."""
        self.fleet.cold.add(("bob", "own"))
        self.fleet.ensure_delay = 1.0
        chunk = "x" * (api._TERMINAL_PENDING_MAX_BYTES // 2 + 1)
        with self.open() as ws:
            self.assertEqual(self.frame(ws)["state"], "starting")
            ws.send_text(chunk)
            ws.send_text(chunk)
            self.assertEqual(self.closed_with(ws), 1009)
        time.sleep(1.2)
        self.connect.assert_not_called()

    def test_not_enough_memory_is_one_frame_then_1013(self):
        self.fleet.ensure_answer = (409, {"code": contract.ERR_RAM, **RAM_PAYLOAD})
        with self.open() as ws:
            frame = self.frame(ws)
            self.assertEqual((frame["type"], frame["state"], frame["reason"]),
                             (contract.SANDBOX_STATUS, "unavailable", "ram"))
            self.assertEqual(frame["limit"]["ceiling"], RAM_PAYLOAD["ceiling"])
            self.assertEqual(self.closed_with(ws), contract.TERMINAL_CLOSE_UNAVAILABLE)
        self.connect.assert_not_called()

    def test_a_refused_person_is_one_frame_then_1008(self):
        self.fleet.ensure_answer = (403, {"code": contract.ERR_PROJECT_REFUSED})
        with self.open() as ws:
            self.assertEqual(self.frame(ws), {"type": contract.SANDBOX_STATUS, "state": "unavailable",
                                              "reason": "refused"})
            self.assertEqual(self.closed_with(ws), contract.TERMINAL_CLOSE_REFUSED)
        self.connect.assert_not_called()

    def test_a_start_error_is_one_frame_then_1013(self):
        self.fleet.ensure_answer = (503, {"code": contract.ERR_START_FAILED})
        with self.open() as ws:
            frame = self.frame(ws)
            self.assertEqual((frame["state"], frame["reason"]), ("unavailable", "error"))
            self.assertNotIn("limit", frame)
            self.assertEqual(self.closed_with(ws), contract.TERMINAL_CLOSE_UNAVAILABLE)

    def test_a_browser_gone_during_the_start_dials_nothing(self):
        self.fleet.cold.add(("bob", "own"))
        self.fleet.ensure_delay = 0.6
        with self.open() as ws:
            self.assertEqual(self.frame(ws)["state"], "starting")
            ws.close()
            time.sleep(1.0)
        self.connect.assert_not_called()


class TheOldAddressIsNeverDialled(_TerminalTest):
    def test_the_old_address_and_token_in_the_environment_are_never_used(self):
        # MCP_AUTH_TOKEN is set in _TerminalTest; the old address too, here.
        with mock.patch.dict(os.environ, {"KALI_TERMINAL_WS_URL": "ws://kali-sandbox:8016"}):
            with self.open() as ws:
                ws.receive_bytes()
        url, headers = self.dialed()
        box = self.fleet.current("bob")
        self.assertTrue(url.startswith(f"ws://{box.host}:{contract.PORTS['terminal']}?"), url)
        self.assertNotIn("kali-sandbox", url)
        self.assertEqual(headers["Authorization"], f"Bearer {box.token}")
        self.assertNotIn(SHARED_TOKEN, json.dumps(headers))


if __name__ == "__main__":
    unittest.main()
