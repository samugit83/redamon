"""
The agent closes open sockets by user, project and socket kind (DV-21, T16).

A revoke, a disabled account or a removed legacy grant must end the sockets the
person already holds open: a ticket is checked once, at the handshake. Only
`/ws/agent` was registered (WebSocketManager); the Kali terminal and both
CypherFix sockets were raw proxies nobody could find again. They now register in
PROXIED_SOCKETS, and the master-key `POST /ws/close` closes what matches, from
both registries. An agent run outlives its socket by design, so closing an
`agent` socket also stops its run.

An admin acting as a member opens sockets as the member (`act` = the admin).
They rest on the admin's role and grants: a close for what the member's own
access gave (a removed grant) leaves them open, a close of either account, or
of the member's access to the project, ends them. A run is matched by who
started it, recorded when it starts, so it is found after its tab closes.

Run: ./agentic/run_tests.sh tests/test_close_sockets.py
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

try:
    import websocket_api  # noqa: F401
    _HAVE = True
except Exception:  # pragma: no cover - only outside the agent image
    _HAVE = False

# Outside the guard: a name missing from websocket_api is a failure, never a skip.
if _HAVE:
    from websocket_api import (  # noqa: E402
        PROXIED_SOCKETS, ProxiedSocketRegistry, WebSocketConnection, WebSocketHandler, WebSocketManager,
        close_sockets,
    )

MASTER = "master-key-for-test"
SCANNER = "scanner-key-for-test"
SECRET = "c" * 64


class _FakeWS:
    def __init__(self, fail_close=False):
        self.closed = None
        self.client = "test"
        self.sent = []
        self._fail_close = fail_close

    async def close(self, code=1000, reason=""):
        if self._fail_close:
            raise RuntimeError("socket already gone")
        self.closed = (code, reason)

    async def send_json(self, msg):
        self.sent.append(msg)


_SAME = object()


def _claims(sub, pid, sid="s", act=None):
    out = {"sub": sub, "pid": pid, "sid": sid}
    if act:
        out["act"] = act
    return out


@unittest.skipUnless(_HAVE, "agent deps unavailable (run in-container)")
class Registry(unittest.TestCase):
    def test_a_terminal_socket_is_found_through_the_registry(self):
        reg = ProxiedSocketRegistry()
        ws = _FakeWS()
        reg.add(ws, "kali-terminal", _claims("uA", "p1", "s9", act="admin-1"))
        [entry] = reg.matching(kinds=["kali-terminal"], user_id="uA", scope="account")
        self.assertIs(entry.ws, ws)
        self.assertEqual((entry.kind, entry.sub, entry.act, entry.pid, entry.sid),
                         ("kali-terminal", "uA", "admin-1", "p1", "s9"))
        self.assertGreater(entry.opened_at, 0)

    def test_the_registry_forgets_a_closed_socket(self):
        reg = ProxiedSocketRegistry()
        ws = _FakeWS()
        reg.add(ws, "cypherfix-codefix", _claims("uA", "p1"))
        reg.remove(ws)
        reg.remove(ws)  # the handler's finally and /ws/close may both remove it
        self.assertEqual(reg.matching(kinds=["cypherfix-codefix"], user_id="uA"), [])
        self.assertEqual(len(reg), 0)

    def test_only_the_three_proxied_kinds_register(self):
        reg = ProxiedSocketRegistry()
        for kind in ("agent", "shell", ""):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                reg.add(_FakeWS(), kind, _claims("uA", "p1"))


@unittest.skipUnless(_HAVE, "agent deps unavailable (run in-container)")
class CloseSockets(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.reg = ProxiedSocketRegistry()
        self.mgr = WebSocketManager()
        self.tasks = []
        self.ws = {name: _FakeWS() for name in ("a_term", "a_triage", "a_fix", "b_term", "a_term_p2")}
        self.reg.add(self.ws["a_term"], "kali-terminal", _claims("uA", "p1"))
        self.reg.add(self.ws["a_triage"], "cypherfix-triage", _claims("uA", "p1"))
        self.reg.add(self.ws["a_fix"], "cypherfix-codefix", _claims("uA", "p1"))
        self.reg.add(self.ws["b_term"], "kali-terminal", _claims("uB", "p1"))
        self.reg.add(self.ws["a_term_p2"], "kali-terminal", _claims("uA", "p2"))

    async def asyncTearDown(self):
        for t in self.tasks:
            t.cancel()

    async def _agent_session(self, user, project, session, *, act=None, run_act=_SAME,
                             with_socket=True):
        # By default the tab that holds the socket started the run, as the handler records it.
        task = asyncio.ensure_future(asyncio.sleep(3600))
        self.tasks.append(task)
        key = f"{user}:{project}:{session}"
        self.mgr.register_task(key, task, actor_id=act if run_act is _SAME else run_act)
        conn = None
        if with_socket:
            conn = WebSocketConnection(_FakeWS())
            conn.actor_id = act
            conn._active_task = task
            await self.mgr.authenticate(conn, user, project, session, verified=True)
        return key, task, conn

    async def test_closes_only_matching_kinds_and_user(self):
        out = await close_sockets(self.mgr, self.reg, kinds=["kali-terminal"], user_id="uA")
        self.assertEqual(out["closed"], 2)
        self.assertEqual(out["by_kind"], {"kali-terminal": 2})
        self.assertEqual(self.ws["a_term"].closed, (4403, "Access revoked"))
        self.assertEqual(self.ws["a_term_p2"].closed, (4403, "Access revoked"))
        for untouched in ("a_triage", "a_fix", "b_term"):
            self.assertIsNone(self.ws[untouched].closed, untouched)
        self.assertEqual(len(self.reg), 3)

    async def test_project_filter(self):
        out = await close_sockets(self.mgr, self.reg, kinds=["kali-terminal", "cypherfix-triage"],
                                  user_id="uA", project_id="p1")
        self.assertEqual(out["by_kind"], {"kali-terminal": 1, "cypherfix-triage": 1})
        self.assertIsNotNone(self.ws["a_term"].closed)
        self.assertIsNone(self.ws["a_term_p2"].closed)
        self.assertIsNone(self.ws["a_fix"].closed)

    async def test_a_project_without_a_user_closes_every_users_socket_there(self):
        out = await close_sockets(self.mgr, self.reg, kinds=["kali-terminal"], project_id="p1")
        self.assertEqual(out["closed"], 2)
        self.assertIsNotNone(self.ws["b_term"].closed)
        self.assertIsNone(self.ws["a_term_p2"].closed)

    async def test_an_agent_close_also_stops_the_run(self):
        key, task, conn = await self._agent_session("uA", "p1", "s1")
        other_key, other_task, other_conn = await self._agent_session("uB", "p1", "s2")
        out = await close_sockets(self.mgr, self.reg, kinds=["agent"], user_id="uA")
        await asyncio.sleep(0)
        self.assertEqual(out["by_kind"], {"agent": 1})
        self.assertEqual(out["stopped_runs"], 1)
        self.assertTrue(task.cancelled())
        self.assertEqual(conn.websocket.closed, (4403, "Access revoked"))
        self.assertNotIn(key, self.mgr.active_connections)
        self.assertTrue(conn._is_stopped)
        stopped = [m for m in conn.websocket.sent if m.get("type") == "stopped"]
        self.assertEqual(stopped[0]["payload"]["message"], "Session stopped (access revoked)")
        # The other user's run and socket, and every proxied socket, are untouched.
        self.assertFalse(other_task.done())
        self.assertIsNone(other_conn.websocket.closed)
        self.assertIs(self.mgr.active_connections[other_key], other_conn)
        self.assertEqual(len(self.reg), 5)

    async def test_a_headless_run_of_the_user_is_stopped_too(self):
        # A run whose tab is gone has no socket left, and keeps going by design.
        key, task, _ = await self._agent_session("uA", "p1", "s1", with_socket=False)
        out = await close_sockets(self.mgr, self.reg, kinds=["agent"], user_id="uA", project_id="p1")
        await asyncio.sleep(0)
        self.assertEqual(out["stopped_runs"], 1)
        self.assertEqual(out["closed"], 0)
        self.assertTrue(task.cancelled())

    async def test_the_real_signed_in_user_matches_an_act_as_socket(self):
        # An admin acting as uC opened these: closing the admin's sockets ends them.
        acted = _FakeWS()
        self.reg.add(acted, "kali-terminal", _claims("uC", "p3", act="admin-1"))
        key, task, conn = await self._agent_session("uC", "p3", "s3", act="admin-1")
        out = await close_sockets(self.mgr, self.reg, kinds=["kali-terminal", "agent"], user_id="admin-1")
        await asyncio.sleep(0)
        self.assertEqual(out["by_kind"], {"kali-terminal": 1, "agent": 1})
        self.assertIsNotNone(acted.closed)
        self.assertTrue(task.cancelled())
        self.assertIsNone(self.ws["a_term"].closed)

    async def test_a_socket_that_fails_to_close_is_still_forgotten(self):
        broken = _FakeWS(fail_close=True)
        reg = ProxiedSocketRegistry()
        reg.add(broken, "kali-terminal", _claims("uA", "p1"))
        out = await close_sockets(self.mgr, reg, kinds=["kali-terminal"], user_id="uA")
        self.assertEqual(out["closed"], 1)
        self.assertEqual(len(reg), 0)

    async def test_nothing_matches_nothing_closes(self):
        out = await close_sockets(self.mgr, self.reg, kinds=["kali-terminal", "agent"], user_id="nobody")
        self.assertEqual(out, {"closed": 0, "by_kind": {}, "stopped_runs": 0})

    # --- a run is matched by who started it ----------------------------------

    async def test_a_headless_run_started_while_acting_is_stopped_with_the_admin(self):
        # admin-1 started it acting as uC, then closed the tab: no socket names admin-1 any more.
        key, task, _ = await self._agent_session("uC", "p3", "s3", act="admin-1", with_socket=False)
        out = await close_sockets(self.mgr, self.reg, kinds=["agent"], user_id="admin-1")
        await asyncio.sleep(0)
        self.assertEqual(out, {"closed": 0, "by_kind": {}, "stopped_runs": 1})
        self.assertTrue(task.cancelled())
        self.assertIsNone(self.mgr.get_task(key))

    async def test_a_run_the_admin_started_stops_while_the_members_own_tab_stays(self):
        # uC's own tab (no act) watches the run admin-1 started acting as uC.
        key, task, conn = await self._agent_session("uC", "p3", "s3", act=None, run_act="admin-1")
        out = await close_sockets(self.mgr, self.reg, kinds=["agent"], user_id="admin-1")
        await asyncio.sleep(0)
        self.assertEqual(out["stopped_runs"], 1)
        self.assertTrue(task.cancelled())
        self.assertIsNone(conn.websocket.closed)
        self.assertIs(self.mgr.active_connections[key], conn)
        stopped = [m for m in conn.websocket.sent if m.get("type") == "stopped"]
        self.assertEqual(stopped[0]["payload"]["message"], "Session stopped (access revoked)")

    async def test_the_members_own_tab_closes_while_the_run_the_admin_started_goes_on(self):
        key, task, conn = await self._agent_session("uC", "p3", "s3", act=None, run_act="admin-1")
        out = await close_sockets(self.mgr, self.reg, kinds=["agent"], user_id="uC")
        await asyncio.sleep(0)
        self.assertEqual(out, {"closed": 1, "by_kind": {"agent": 1}, "stopped_runs": 0})
        self.assertEqual(conn.websocket.closed, (4403, "Access revoked"))
        self.assertNotIn(key, self.mgr.active_connections)
        self.assertFalse(task.done())

    async def test_a_run_the_member_started_goes_on_when_the_admin_watching_it_is_closed(self):
        key, task, conn = await self._agent_session("uC", "p3", "s3", act="admin-1", run_act=None)
        out = await close_sockets(self.mgr, self.reg, kinds=["agent"], user_id="admin-1")
        await asyncio.sleep(0)
        self.assertEqual(out, {"closed": 1, "by_kind": {"agent": 1}, "stopped_runs": 0})
        self.assertEqual(conn.websocket.closed, (4403, "Access revoked"))
        self.assertFalse(task.done())

    # --- whose access an act-as socket rests on -------------------------------

    async def _acting(self):
        """admin-1 acting as uC on p3 (a terminal and a chat run), and uC's own terminal there."""
        acted_term = _FakeWS()
        own_term = _FakeWS()
        self.reg.add(acted_term, "kali-terminal", _claims("uC", "p3", act="admin-1"))
        self.reg.add(own_term, "kali-terminal", _claims("uC", "p3"))
        key, task, conn = await self._agent_session("uC", "p3", "s3", act="admin-1")
        return acted_term, own_term, task, conn

    async def test_removing_the_members_grant_leaves_the_admins_acting_sockets_open(self):
        # The admin's terminal and run rest on the admin's own role and grant, not on uC's.
        acted_term, own_term, task, conn = await self._acting()
        out = await close_sockets(self.mgr, self.reg, kinds=["kali-terminal", "agent"], user_id="uC")
        await asyncio.sleep(0)
        self.assertEqual(out, {"closed": 1, "by_kind": {"kali-terminal": 1}, "stopped_runs": 0})
        self.assertEqual(own_term.closed, (4403, "Access revoked"))
        self.assertIsNone(acted_term.closed)
        self.assertFalse(task.done())
        self.assertIsNone(conn.websocket.closed)

    async def test_disabling_the_admin_closes_the_acting_sockets(self):
        acted_term, own_term, task, conn = await self._acting()
        out = await close_sockets(self.mgr, self.reg, kinds=["kali-terminal", "agent"],
                                  user_id="admin-1", scope="account")
        await asyncio.sleep(0)
        self.assertEqual(out, {"closed": 2, "by_kind": {"kali-terminal": 1, "agent": 1},
                               "stopped_runs": 1})
        self.assertIsNotNone(acted_term.closed)
        self.assertTrue(task.cancelled())
        self.assertIsNone(own_term.closed)

    async def test_deleting_the_acted_as_member_closes_the_acting_sockets(self):
        acted_term, own_term, task, conn = await self._acting()
        out = await close_sockets(self.mgr, self.reg, kinds=["kali-terminal", "agent"],
                                  user_id="uC", scope="account")
        await asyncio.sleep(0)
        self.assertEqual(out, {"closed": 3, "by_kind": {"kali-terminal": 2, "agent": 1},
                               "stopped_runs": 1})
        self.assertIsNotNone(acted_term.closed)
        self.assertIsNotNone(own_term.closed)
        self.assertTrue(task.cancelled())
        self.assertIsNone(self.ws["a_term"].closed)

    async def test_the_members_access_to_the_project_ending_closes_the_acting_sockets(self):
        # The ticket route checked p3 for uC, the acted-as user: the act-as sockets used it.
        acted_term, own_term, task, conn = await self._acting()
        out = await close_sockets(self.mgr, self.reg, kinds=["kali-terminal", "agent"],
                                  user_id="uC", project_id="p3")
        await asyncio.sleep(0)
        self.assertEqual(out["by_kind"], {"kali-terminal": 2, "agent": 1})
        self.assertTrue(task.cancelled())

    async def test_closing_the_members_project_closes_the_acting_sockets(self):
        acted_term, own_term, task, conn = await self._acting()
        out = await close_sockets(self.mgr, self.reg, kinds=["kali-terminal", "agent"], project_id="p3")
        await asyncio.sleep(0)
        self.assertEqual(out["by_kind"], {"kali-terminal": 2, "agent": 1})
        self.assertIsNotNone(acted_term.closed)
        self.assertTrue(task.cancelled())

    async def test_an_unknown_scope_is_refused(self):
        with self.assertRaises(ValueError):
            await close_sockets(self.mgr, self.reg, kinds=["kali-terminal"], user_id="uA", scope="all")
        with self.assertRaises(ValueError):
            self.reg.matching(kinds=["kali-terminal"], user_id="uA", scope="")
        self.assertIsNone(self.ws["a_term"].closed)


@unittest.skipUnless(_HAVE, "agent deps unavailable (run in-container)")
class EveryRunStartRecordsTheActor(unittest.IsolatedAsyncioTestCase):
    """Each handler that starts a run records the starting socket's `act` with it."""

    STARTS = (
        ("handle_query", {"question": "q"}, "_run_orchestrator_query"),
        ("handle_approval", {"decision": "approve"}, "_run_orchestrator_approval"),
        ("handle_answer", {"answer": "a"}, "_run_orchestrator_answer"),
        ("handle_tool_confirmation", {"decision": "approve"}, "_run_orchestrator_tool_confirmation"),
        ("handle_resume", {}, "_run_orchestrator_resume"),
    )

    async def _start(self, method, payload, runner, *, act):
        mgr = WebSocketManager()
        handler = WebSocketHandler(orchestrator=None, ws_manager=mgr)
        conn = WebSocketConnection(_FakeWS())
        conn.actor_id = act
        await mgr.authenticate(conn, "uC", "p3", "s3", verified=True)
        conn._is_stopped = True  # handle_resume restarts only a stopped run

        async def _runs_until_cancelled(*_args):
            await asyncio.sleep(3600)

        with mock.patch.object(handler, runner, _runs_until_cancelled), \
                mock.patch.object(websocket_api, "update_conversation", new=mock.AsyncMock()), \
                mock.patch.object(websocket_api, "save_chat_message", new=mock.AsyncMock(return_value=None)):
            await getattr(handler, method)(conn, dict(payload))
        task = mgr.get_task("uC:p3:s3")
        self.assertIsNotNone(task, method)
        self.addCleanup(task.cancel)
        await mgr.disconnect(conn)  # the tab closes; the run goes on by design
        return mgr, task

    async def test_a_run_started_acting_is_found_by_the_admin_after_the_tab_closes(self):
        for method, payload, runner in self.STARTS:
            with self.subTest(method=method):
                mgr, task = await self._start(method, payload, runner, act="admin-1")
                out = await close_sockets(mgr, ProxiedSocketRegistry(), kinds=["agent"], user_id="admin-1")
                await asyncio.sleep(0)
                self.assertEqual(out["stopped_runs"], 1)
                self.assertTrue(task.cancelled())

    async def test_a_run_the_member_started_is_not_the_admins(self):
        for method, payload, runner in self.STARTS:
            with self.subTest(method=method):
                mgr, task = await self._start(method, payload, runner, act=None)
                out = await close_sockets(mgr, ProxiedSocketRegistry(), kinds=["agent"], user_id="admin-1")
                await asyncio.sleep(0)
                self.assertEqual(out["stopped_runs"], 0)
                self.assertFalse(task.done())


# --- the route and the real proxies -------------------------------------------
try:
    from fastapi.testclient import TestClient
    from starlette.websockets import WebSocketDisconnect
    _HAVE_APP = _HAVE
except Exception:  # pragma: no cover
    _HAVE_APP = False


def _ticket(aud, sub="uT", pid="pT", sid="sT"):
    def b64(raw):
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    head = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = b64(json.dumps({"sub": sub, "pid": pid, "sid": sid, "aud": aud,
                           "iat": int(time.time()), "exp": int(time.time()) + 60}).encode())
    sig = hmac.new(SECRET.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()
    return f"{head}.{body}.{b64(sig)}"


class _EchoKali:
    """Stands in for the sandbox's terminal server: echoes what the proxy sends it."""

    def __init__(self):
        self.queue = None

    async def __aenter__(self):
        self.queue = asyncio.Queue()
        return self

    async def __aexit__(self, *exc):
        return False

    async def send(self, message):
        await self.queue.put(message)

    def __aiter__(self):
        return self

    async def __anext__(self):
        return await self.queue.get()


@unittest.skipUnless(_HAVE_APP, "agent deps unavailable (run in-container)")
class Route(unittest.TestCase):
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
        self._env = mock.patch.dict(os.environ, {
            "INTERNAL_API_KEY": MASTER, "SCANNER_API_KEY": SCANNER,
            "AGENT_WS_TICKET_SECRET": SECRET, "MCP_AUTH_TOKEN": "mcp-token-for-test",
        })
        self._env.start()

    def tearDown(self):
        self._env.stop()

    def _post(self, body, key=MASTER):
        headers = {"x-internal-key": key} if key else {}
        return self.client.post("/ws/close", json=body, headers=headers)

    def test_declares_the_configured_master_gate(self):
        from llm_guard import require_configured_master_auth
        deps = {}
        for r in self.api.app.routes:
            for m in getattr(r, "methods", None) or ():
                deps[(m, r.path)] = [d.dependency for d in getattr(r, "dependencies", [])]
        self.assertIn(require_configured_master_auth, deps[("POST", "/ws/close")])

    def test_refused_without_the_master_key(self):
        body = {"user_id": "uA", "kinds": ["kali-terminal"]}
        self.assertEqual(self._post(body, key=None).status_code, 401)
        self.assertEqual(self._post(body, key=SCANNER).status_code, 401)
        with mock.patch.dict(os.environ, {"INTERNAL_API_KEY": ""}):
            self.assertEqual(self._post(body).status_code, 503)

    def test_needs_a_user_or_a_project_and_known_kinds(self):
        with mock.patch.object(self.api, "ws_manager", WebSocketManager()):
            self.assertEqual(self._post({"kinds": ["kali-terminal"]}).status_code, 400)
            self.assertEqual(self._post({"user_id": "uA", "kinds": []}).status_code, 422)
            self.assertEqual(self._post({"user_id": "uA", "kinds": ["shell"]}).status_code, 422)
            self.assertEqual(self._post({"user_id": "uA"}).status_code, 422)

    def test_closes_through_both_registries(self):
        mgr = WebSocketManager()
        ws = _FakeWS()
        PROXIED_SOCKETS.add(ws, "cypherfix-triage", _claims("uR", "pR"))
        try:
            with mock.patch.object(self.api, "ws_manager", mgr):
                res = self._post({"user_id": "uR", "kinds": ["cypherfix-triage", "agent"]})
        finally:
            PROXIED_SOCKETS.remove(ws)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json(), {"closed": 1, "by_kind": {"cypherfix-triage": 1}, "stopped_runs": 0})
        self.assertEqual(ws.closed, (4403, "Access revoked"))

    def test_the_scope_decides_whether_an_admins_acting_socket_closes(self):
        ws = _FakeWS()
        PROXIED_SOCKETS.add(ws, "kali-terminal", _claims("uQ", "pQ", act="admin-Q"))
        try:
            with mock.patch.object(self.api, "ws_manager", WebSocketManager()):
                grant = self._post({"user_id": "uQ", "kinds": ["kali-terminal"]})
                self.assertEqual(grant.status_code, 200)
                self.assertEqual(grant.json()["closed"], 0)
                self.assertIsNone(ws.closed)
                self.assertEqual(self._post({"user_id": "uQ", "kinds": ["kali-terminal"],
                                             "scope": "everything"}).status_code, 422)
                self.assertIsNone(ws.closed)
                account = self._post({"user_id": "uQ", "kinds": ["kali-terminal"], "scope": "account"})
        finally:
            PROXIED_SOCKETS.remove(ws)
        self.assertEqual(account.json(), {"closed": 1, "by_kind": {"kali-terminal": 1}, "stopped_runs": 0})
        self.assertEqual(ws.closed, (4403, "Access revoked"))

    def test_the_terminal_proxy_registers_its_socket_and_forgets_it(self):
        echo = _EchoKali()
        connect = mock.MagicMock(return_value=echo)
        with mock.patch.object(self.api.websockets, "connect", connect):
            with self.client.websocket_connect(f"/ws/kali-terminal?ticket={_ticket('kali-terminal')}") as ws:
                ws.send_text("hello")
                self.assertEqual(ws.receive_text(), "hello")  # the proxy is bridging: it registered first
                [entry] = PROXIED_SOCKETS.matching(kinds=["kali-terminal"], user_id="uT")
                self.assertEqual((entry.pid, entry.sid), ("pT", "sT"))
        # The sandbox is dialled with the agent's bearer and the verified identity.
        url = connect.call_args.args[0]
        self.assertIn("user_id=uT", url)
        self.assertIn("project_id=pT", url)
        # Plus the shell's graph run credential (step 1.15, test_run_credential.py).
        headers = connect.call_args.kwargs["additional_headers"]
        self.assertEqual(headers["Authorization"], "Bearer mcp-token-for-test")
        self.assertEqual(sorted(headers), ["Authorization", "X-Redamon-Run"])
        for _ in range(50):
            if not PROXIED_SOCKETS.matching(kinds=["kali-terminal"], user_id="uT"):
                break
            time.sleep(0.02)
        self.assertEqual(PROXIED_SOCKETS.matching(kinds=["kali-terminal"], user_id="uT"), [])

    def test_the_terminal_proxy_sends_no_bearer_when_none_is_set(self):
        # The terminal server then refuses the upgrade (fail closed there).
        connect = mock.MagicMock(side_effect=ConnectionRefusedError("refused"))
        with mock.patch.dict(os.environ, {"MCP_AUTH_TOKEN": ""}), \
                mock.patch.object(self.api.websockets, "connect", connect):
            with self.client.websocket_connect(f"/ws/kali-terminal?ticket={_ticket('kali-terminal')}") as ws:
                with self.assertRaises(WebSocketDisconnect):
                    ws.receive_text()
        self.assertEqual(connect.call_args.kwargs["additional_headers"], {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
