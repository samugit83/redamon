"""
No agent route sends anything to the old shared Kali container or with its tokens (group 1, S20).

Docker makes a container's hostname a DNS name on each of its networks, and the agent joins
every person's sandbox network: once the shared `kali-sandbox` service is gone, a bare
`kali-sandbox` could answer from one person's sandbox. And an old `.env` still hands the
agent the shared container's MCP_AUTH_TOKEN and TUNNEL_AUTH_TOKEN. So every route that talks
to a sandbox is driven here with both tokens and the old compose addresses in the
environment, and the old container still answering at `kali-sandbox`: the session list and
every session drive (`?sandbox=` naming a person's instance, `shared`, or nothing), the
terminal proxy, the tunnel push and status, and a run's stop and the emergency stop. Every
outbound request is recorded: none may name the old host (or host.docker.internal) or carry
either old token, and each goes to the person's own instance with its own bearer.

Run: ./agentic/run_tests.sh tests/test_no_path_reaches_the_shared_container.py
"""
import asyncio
import json
import os
import sys
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from unittest import mock
from urllib.parse import urlsplit

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

MASTER = "no-shared-path-master-key-0123456789"
OLD_MCP_TOKEN = "old-shared-mcp-token-0123456789"
OLD_TUNNEL_TOKEN = "old-shared-tunnel-token-0123456789"
OLD_ENV = {
    "INTERNAL_API_KEY": MASTER,
    "MCP_AUTH_TOKEN": OLD_MCP_TOKEN,
    "TUNNEL_AUTH_TOKEN": OLD_TUNNEL_TOKEN,
    "MCP_NETWORK_RECON_URL": "http://kali-sandbox:8000/sse",
    "MCP_METASPLOIT_PROGRESS_URL": "http://kali-sandbox:8013/progress",
    "MCP_HYDRA_PROGRESS_URL": "http://kali-sandbox:8014/progress",
    "KALI_TERMINAL_WS_URL": "ws://kali-sandbox:8016",
}
OLD_HOSTS = ("kali-sandbox", "host.docker.internal")

with mock.patch.dict(os.environ, {"INTERNAL_API_KEY": MASTER}):
    @asynccontextmanager
    async def _no_lifespan(_app):
        yield

    with mock.patch("api.lifespan", _no_lifespan):
        import api  # noqa: E402

import sandbox_contract as contract  # noqa: E402
import sandbox_router as router  # noqa: E402
import sandbox_runs  # noqa: E402
import utils  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sandbox_route_fakes import WEBAPP, Fleet  # noqa: E402

KEY = {"x-internal-key": MASTER}


class _Upstream:
    """A terminal server that answers one prompt and then waits."""

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def send(self, message):
        pass

    def __aiter__(self):
        return self

    async def __anext__(self):
        if not getattr(self, "_said", False):
            self._said = True
            return b"$ "
        await asyncio.sleep(3600)


class NoPathReachesTheOldContainer(unittest.TestCase):

    def setUp(self):
        self.fleet = Fleet()
        self.fleet.shared.running = True
        self.bob = self.fleet.add("bob")
        self.bob.sessions = {"sessions": [{"id": 1, "type": "shell"}], "jobs": [{"id": 1}],
                             "non_msf_sessions": []}
        self.sent = []   # (url, headers) of every request the agent made
        router._reset()
        sandbox_runs._reset()
        real_client = httpx.AsyncClient

        async def recording(request):
            self.sent.append((str(request.url), dict(request.headers)))
            return await self.fleet.handle(request)

        transport = httpx.MockTransport(recording)

        def client(*a, **k):
            k["transport"] = transport
            return real_client(*a, **k)

        self.dialled = []

        def connect(url, *a, **k):
            self.dialled.append((url, dict(k.get("additional_headers") or {})))
            return _Upstream()

        claims = {"sub": "bob", "ten": "alice", "pid": "p1", "sid": "s1"}
        patches = [
            mock.patch.dict(os.environ, OLD_ENV),
            mock.patch.object(router, "_transport", transport),
            mock.patch.object(api, "_sandbox_transport", transport),
            mock.patch.object(utils, "_async_transport", transport),
            mock.patch.dict(router.INTERNAL_HEADERS, {"X-Internal-Key": "test-internal-key"}),
            mock.patch.object(router, "WEBAPP_API_URL", WEBAPP),
            mock.patch("httpx.AsyncClient", client),
            mock.patch("ws_ticket.authorize_ws", side_effect=lambda *a, **k: (True, dict(claims), "ok")),
            mock.patch.object(api.websockets, "connect", connect),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(router._reset)
        self.addCleanup(sandbox_runs._reset)
        self.client = TestClient(api.app)

    def tearDown(self):
        self.assertNothingOld(self.sent + self.dialled)

    def assertNothingOld(self, calls):
        for url, headers in calls:
            host = urlsplit(url).hostname or ""
            self.assertNotIn(host, OLD_HOSTS, url)
            text = json.dumps(headers)
            self.assertNotIn(OLD_MCP_TOKEN, text, url)
            self.assertNotIn(OLD_TUNNEL_TOKEN, text, url)
        self.assertEqual(self.fleet.shared.requests, [], "the old shared container was asked")

    def sandbox_calls(self):
        return [(url, h) for url, h in self.sent if urlsplit(url).hostname != "webapp.test"]

    def assertOnlyBobsSandbox(self, calls):
        self.assertTrue(calls, "nothing reached a sandbox")
        for url, headers in calls:
            self.assertEqual(urlsplit(url).hostname, self.bob.host, url)
            self.assertIn(headers.get("authorization") or headers.get("Authorization"),
                          (f"Bearer {self.bob.token}", f"Bearer {self.bob.tunnel_token}"), url)

    def test_the_session_list(self):
        resp = self.client.get("/sessions", headers=KEY)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual([r["sandbox"] for r in resp.json()["sessions"]], [self.bob.instance])
        self.assertOnlyBobsSandbox(self.sandbox_calls())

    def test_every_session_drive(self):
        inst = self.bob.instance
        for method, path, body in (("POST", "/sessions/1/interact", {"command": "id"}),
                                   ("POST", "/sessions/1/kill", None),
                                   ("POST", "/jobs/1/kill", None),
                                   ("POST", "/session-chat-map", {"msf_session_id": 1, "chat_session_id": "c"}),
                                   ("POST", "/non-msf-sessions", {"type": "listener"})):
            for sandbox in (inst, "shared", None):
                with self.subTest(path=path, sandbox=sandbox):
                    query = f"?sandbox={sandbox}" if sandbox else ""
                    resp = self.client.request(method, f"{path}{query}", headers=KEY, json=body)
                    self.assertEqual(resp.status_code, 200 if sandbox == inst else 400, resp.text)
        self.assertOnlyBobsSandbox(self.sandbox_calls())

    def test_the_terminal(self):
        with self.client.websocket_connect("/ws/kali-terminal?ticket=t") as ws:
            self.assertEqual(ws.receive_bytes(), b"$ ")
        [(url, headers)] = self.dialled
        self.assertEqual((urlsplit(url).hostname, urlsplit(url).port), (self.bob.host, contract.PORTS["terminal"]))
        self.assertEqual(headers["Authorization"], f"Bearer {self.bob.token}")

    def test_the_tunnel_push_and_status(self):
        resp = self.client.post("/sandboxes/bob/tunnel", headers=KEY,
                                json={"ngrokAuthtoken": "ngrok-token-0123456789"})
        self.assertEqual(resp.status_code, 200, resp.text)
        resp = self.client.post("/sandboxes/bob/tunnel", headers=KEY, json={})
        self.assertEqual(resp.status_code, 200, resp.text)
        resp = self.client.get("/tunnel-status?user_id=bob", headers=KEY)
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertEqual(self.client.get("/tunnel-status").status_code, 401)
        self.assertOnlyBobsSandbox(self.sandbox_calls())

    def test_a_runs_stop_and_the_emergency_stop(self):
        handle = router.SandboxHandle(
            user_id="bob", view="own", instance=self.bob.instance, host=self.bob.host,
            token=self.bob.token, tunnel_token="", ports=contract.PORTS, reverse_port=4444)
        sandbox_runs.note_run_sandbox("sess-bob", handle)
        self.assertEqual(asyncio.run(sandbox_runs.stop_sandbox_run("sess-bob")), 1)
        self.assertIsNone(asyncio.run(sandbox_runs.stop_sandbox_run("sess-nobody")))
        result = asyncio.run(sandbox_runs.stop_all_runs())
        self.assertEqual((result["asked"], result["answered"]), (1, 1))
        self.assertOnlyBobsSandbox(self.sandbox_calls())


if __name__ == "__main__":
    unittest.main()
