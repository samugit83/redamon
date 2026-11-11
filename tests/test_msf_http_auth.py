"""
The Kali sandbox's two stdlib HTTP servers need the agent's bearer on every route
(NF-03): the Metasploit progress/session manager on :8013 and the Hydra progress
server on :8014.

Before this, any container on `redamon-network` or on the guinea-pig network
`pentest-net` (step 0.2, E3), and anything on host loopback, could list every
Metasploit session, type into one, kill it, or re-tag it onto its own chat with
`POST /session-chat-map`; :8014 streamed brute-force output (cracked passwords).
They are `http.server` servers, not ASGI, so `BearerAuthASGI` cannot wrap them:
`_auth_middleware.BearerAuthHTTPHandlerMixin` checks the same token in
`parse_request`, before any `do_*` handler runs.

Real servers on loopback, the console replaced by a recorder, so a refused
request is proven to reach no handler.

Run (root-agent section, agent image): python -m pytest tests/test_msf_http_auth.py
"""
import http.client
import json
import logging
import os
import sys
import threading
import types
import unittest
from http.server import HTTPServer
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
SERVERS = REPO / "mcp" / "servers"
if str(SERVERS) not in sys.path:
    sys.path.insert(0, str(SERVERS))

# fastmcp only ships in the kali image: an identity @mcp.tool() is enough here.
if "fastmcp" not in sys.modules:
    _fm = types.ModuleType("fastmcp")

    class _StubMCP:
        def __init__(self, *a, **k):
            pass

        def tool(self, *a, **k):
            return lambda fn: fn

        def run(self, *a, **k):
            pass

    _fm.FastMCP = _StubMCP
    sys.modules["fastmcp"] = _fm

import _auth_middleware  # noqa: E402
import metasploit_server  # noqa: E402
import network_recon_server  # noqa: E402

TOKEN = "test-mcp-auth-token-0123456789"

# Every route :8013 serves, plus paths and methods it does not, so "every route"
# also covers the 404 and 501 answers an unauthenticated prober used to get.
MSF_ROUTES = [
    ("GET", "/progress", None),
    ("GET", "/sessions", None),
    ("GET", "/health", None),
    ("GET", "/not-a-route", None),
    ("POST", "/sessions/1/interact", {"command": "id"}),
    ("POST", "/sessions/1/kill", None),
    ("POST", "/jobs/1/kill", None),
    ("POST", "/session-chat-map", {"msf_session_id": 1, "chat_session_id": "attacker-chat"}),
    ("POST", "/non-msf-sessions", {"type": "listener", "chat_session_id": "attacker-chat"}),
    ("POST", "/not-a-route", None),
    ("DELETE", "/non-msf-sessions/1", None),
    ("DELETE", "/not-a-route", None),
    ("OPTIONS", "/sessions", None),
    ("PUT", "/sessions", None),
    ("HEAD", "/progress", None),
]

HYDRA_ROUTES = [
    ("GET", "/progress", None),
    ("GET", "/health", None),
    ("GET", "/not-a-route", None),
    ("POST", "/progress", None),
    ("HEAD", "/progress", None),
]


class _RecordingConsole:
    """Stands in for PersistentMsfConsole: records every call a handler makes."""

    def __init__(self):
        self.calls = []
        self._chat_session_map = {}
        self._non_msf_sessions = {"raw-1": {"id": "raw-1"}}

    def get_progress(self):
        self.calls.append("progress")
        return {"active": False, "output": "secret progress"}

    def get_sessions_data(self):
        self.calls.append("sessions")
        return {"sessions": [{"id": 1}], "jobs": [], "non_msf_sessions": []}

    def interact_session(self, sid, command):
        self.calls.append(("interact", sid, command))
        return {"busy": False, "output": "uid=0(root)"}

    def kill_session(self, sid):
        self.calls.append(("kill", sid))
        return {"busy": False, "output": ""}

    def kill_job(self, jid):
        self.calls.append(("kill_job", jid))
        return {"busy": False, "output": ""}

    def link_chat_session(self, msf_session_id, chat_session_id):
        self.calls.append(("link", msf_session_id, chat_session_id))
        self._chat_session_map[msf_session_id] = chat_session_id


class _Served:
    """One handler class served on 127.0.0.1:<free port> in a daemon thread."""

    def __init__(self, handler_cls):
        self.server = HTTPServer(("127.0.0.1", 0), handler_cls)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            data = json.dumps(body).encode() if body is not None else None
            hdrs = dict(headers or {})
            if data is not None:
                hdrs["Content-Type"] = "application/json"
            conn.request(method, path, body=data, headers=hdrs)
            resp = conn.getresponse()
            payload = resp.read()
            return resp.status, dict(resp.getheaders()), payload
        finally:
            conn.close()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def _env(token):
    """MCP_AUTH_TOKEN set to `token`, or removed when None."""
    if token is None:
        env = {k: v for k, v in os.environ.items() if k != "MCP_AUTH_TOKEN"}
        return mock.patch.dict(os.environ, env, clear=True)
    return mock.patch.dict(os.environ, {"MCP_AUTH_TOKEN": token})


class _ServerCase(unittest.TestCase):
    handler = None
    routes = ()

    def setUp(self):
        self.served = _Served(self.handler)
        self.addCleanup(self.served.close)

    def assertRefusedEverywhere(self, headers, token=TOKEN):
        with _env(token):
            for method, path, body in self.routes:
                with self.subTest(method=method, path=path):
                    status, hdrs, payload = self.served.request(method, path, body, headers)
                    self.assertEqual(status, 401)
                    if method != "HEAD":
                        self.assertEqual(json.loads(payload)["error"], "unauthorized")
                    self.assertEqual(hdrs.get("WWW-Authenticate"), "Bearer")


class MetasploitManagerAuth(_ServerCase):
    handler = metasploit_server.SessionProgressHandler
    routes = MSF_ROUTES

    def setUp(self):
        super().setUp()
        self.console = _RecordingConsole()
        patcher = mock.patch.object(metasploit_server, "get_msf_console", return_value=self.console)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_no_token_401_on_every_route_of_8013(self):
        self.assertRefusedEverywhere(headers={})
        self.assertEqual(self.console.calls, [], "a refused request reached the console")
        self.assertEqual(self.console._chat_session_map, {})

    def test_wrong_or_misplaced_credential_401(self):
        for headers in (
            {"Authorization": "Bearer wrong-token"},
            {"Authorization": f"Bearer {TOKEN}x"},
            {"Authorization": TOKEN},
            {"Authorization": f"Basic {TOKEN}"},
            {"Authorization": "Bearer "},
            {"X-Internal-Key": TOKEN},
            {"Authorization": "Bearer tést"},
        ):
            with self.subTest(headers=headers):
                self.assertRefusedEverywhere(headers=headers)
        self.assertEqual(self.console.calls, [])

    def test_unset_token_refuses_all(self):
        # Fail closed, as BearerAuthASGI: no configured token means nobody gets in.
        for token in (None, ""):
            with self.subTest(token=token):
                self.assertRefusedEverywhere(headers={"Authorization": "Bearer anything"}, token=token)
                self.assertRefusedEverywhere(headers={"Authorization": "Bearer "}, token=token)
        self.assertEqual(self.console.calls, [])

    def test_a_refused_session_chat_map_never_retags_a_session(self):
        self.console._chat_session_map[1] = "owners-chat"
        with _env(TOKEN):
            status, _, _ = self.served.request(
                "POST", "/session-chat-map", {"msf_session_id": 1, "chat_session_id": "attacker-chat"})
        self.assertEqual(status, 401)
        self.assertEqual(self.console._chat_session_map, {1: "owners-chat"})

    def test_right_token_200(self):
        auth = {"Authorization": f"Bearer {TOKEN}"}
        with _env(TOKEN):
            got = {(m, p): self.served.request(m, p, b, auth)[0] for m, p, b in MSF_ROUTES}
        self.assertEqual(got[("GET", "/progress")], 200)
        self.assertEqual(got[("GET", "/sessions")], 200)
        self.assertEqual(got[("GET", "/health")], 200)
        self.assertEqual(got[("POST", "/sessions/1/interact")], 200)
        self.assertEqual(got[("POST", "/sessions/1/kill")], 200)
        self.assertEqual(got[("POST", "/jobs/1/kill")], 200)
        self.assertEqual(got[("POST", "/session-chat-map")], 200)
        self.assertEqual(got[("POST", "/non-msf-sessions")], 200)
        self.assertEqual(got[("DELETE", "/non-msf-sessions/1")], 200)
        self.assertEqual(got[("OPTIONS", "/sessions")], 204)
        # Unknown paths and methods answer as before once authenticated.
        self.assertEqual(got[("GET", "/not-a-route")], 404)
        self.assertEqual(got[("POST", "/not-a-route")], 404)
        self.assertEqual(got[("PUT", "/sessions")], 501)
        self.assertIn(("interact", 1, "id"), self.console.calls)
        self.assertIn(("link", 1, "attacker-chat"), self.console.calls)

    def test_the_scheme_is_case_insensitive_as_on_the_mcp_ports(self):
        with _env(TOKEN):
            status, _, payload = self.served.request(
                "GET", "/sessions", headers={"Authorization": f"bearer {TOKEN}"})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(payload)["sessions"], [{"id": 1}])

    def test_a_refusal_is_logged_without_the_presented_credential(self):
        _auth_middleware._reset_http_refusal_log_for_tests()
        with _env(TOKEN), self.assertLogs("mcp-auth", level="WARNING") as logs:
            self.served.request("GET", "/sessions", headers={"Authorization": "Bearer leaked-guess"})
        text = "\n".join(logs.output)
        self.assertIn("[rbac]", text)
        self.assertNotIn("leaked-guess", text)
        self.assertNotIn(TOKEN, text)


class HydraProgressAuth(_ServerCase):
    handler = network_recon_server.HydraProgressHandler
    routes = HYDRA_ROUTES

    def setUp(self):
        super().setUp()
        self.reads = []

        def _progress():
            self.reads.append(1)
            return {"active": True, "output": "[22][ssh] host: t login: root password: hunter2"}

        patcher = mock.patch.object(network_recon_server, "get_hydra_progress", side_effect=_progress)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_no_token_401_on_every_route_of_8014(self):
        self.assertRefusedEverywhere(headers={})
        self.assertRefusedEverywhere(headers={"Authorization": "Bearer wrong-token"})
        self.assertEqual(self.reads, [], "a refused request read the brute-force output")

    def test_unset_token_refuses_all(self):
        for token in (None, ""):
            with self.subTest(token=token):
                self.assertRefusedEverywhere(headers={"Authorization": "Bearer anything"}, token=token)
        self.assertEqual(self.reads, [])

    def test_right_token_200(self):
        auth = {"Authorization": f"Bearer {TOKEN}"}
        with _env(TOKEN):
            status, _, payload = self.served.request("GET", "/progress", headers=auth)
            health, _, _ = self.served.request("GET", "/health", headers=auth)
            missing, _, _ = self.served.request("GET", "/not-a-route", headers=auth)
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(payload)["active"])
        self.assertEqual(health, 200)
        self.assertEqual(missing, 404)


class BothHandlersCarryTheGate(unittest.TestCase):
    def test_the_two_progress_handlers_use_the_shared_bearer_check(self):
        for handler in (metasploit_server.SessionProgressHandler,
                        network_recon_server.HydraProgressHandler):
            with self.subTest(handler=handler.__name__):
                self.assertTrue(issubclass(handler, _auth_middleware.BearerAuthHTTPHandlerMixin))
                # The check sits in parse_request, so no do_* override can skip it.
                self.assertIs(handler.parse_request,
                              _auth_middleware.BearerAuthHTTPHandlerMixin.parse_request)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    unittest.main()
