"""
The agent's per-user sandbox router (group 1, S09: T5, I10, S5, T7, I11).

Kali work runs in the sandbox of the PERSON doing it (the ticket's `sub`, the MCP token's
owner, who started a triage run), never the tenant's (the project's owner): a collaborator's
run on alice's project uses the collaborator's own sandbox. An admin acting as a member works
in the member's separate `act_as` view (TD-26), never the member's `own` one and never the
admin's. Each instance has its own bearer, so each person's MCP client carries only its own
handle's token, never the shared MCP_AUTH_TOKEN.

The mode comes from the gateway's answers (TD-6): before any answer an unreachable gateway
falls back to the contract's DEFAULT_MODE; once `per_user` was answered, an unreachable
gateway refuses (`error`) and never hands out the shared sandbox. In `per_user` mode no
person means `no_user`, never someone else's sandbox or the shared one.

The webapp gateway is stubbed with httpx.MockTransport; every test sets the router's mode
explicitly (`sandbox_router._reset(mode=...)`, None = no answer yet).

Run: ./agentic/run_tests.sh tests/test_sandbox_router.py
"""
import asyncio
import gc
import json
import os
import secrets
import sys
import unittest
import weakref
from pathlib import Path
from unittest import mock

_AGENTIC_DIR = Path(__file__).resolve().parents[1]
if str(_AGENTIC_DIR) not in sys.path:
    sys.path.insert(0, str(_AGENTIC_DIR))

import httpx  # noqa: E402

import kali_auth  # noqa: E402
import sandbox_contract as contract  # noqa: E402
import sandbox_router as router  # noqa: E402
from decision_check import RunActor, current_run_actor  # noqa: E402
from sandbox_router import SandboxUnavailable  # noqa: E402

SHARED_TOKEN = "shared-mcp-token-must-never-reach-a-per-user-client"
COMPOSE_ENV = {
    "MCP_NETWORK_RECON_URL": "http://kali-sandbox:8000/sse",
    "MCP_NUCLEI_URL": "http://kali-sandbox:8002/sse",
    "MCP_NMAP_URL": "http://kali-sandbox:8004/sse",
    "MCP_METASPLOIT_URL": "http://kali-sandbox:8003/sse",
    "MCP_PLAYWRIGHT_URL": "http://kali-sandbox:8005/sse",
    "MCP_METASPLOIT_PROGRESS_URL": "http://kali-sandbox:8013/progress",
    "MCP_HYDRA_PROGRESS_URL": "http://kali-sandbox:8014/progress",
    "KALI_TERMINAL_WS_URL": "ws://kali-sandbox:8016",
    "MCP_AUTH_TOKEN": SHARED_TOKEN,
}
RAM_PAYLOAD = {
    "admitted": False, "limitType": "ram", "resource": "kali_sandbox",
    "current": 7_500_000_000, "ceiling": 8_000_000_000,
    "settingName": "RECON_MEMORY_POOL_BYTES",
    "detail": "not enough memory: 0.5 GB free, a sandbox needs 1.0 GB",
}


class Gateway:
    """The webapp's internal sandbox routes behind httpx.MockTransport.

    Per-user by default: each (person, view) has one running instance with its own random
    tokens. `script` overrides an answer per route; `raises` makes every call fail at
    transport level."""

    def __init__(self, mode=contract.MODE_PER_USER):
        self.mode = mode
        self.requests = []
        self.instances = {}
        self.cold = set()          # (person, view) whose next start answers 202 first
        self.script = {}           # path -> callable(body) -> (status, json) | None
        self.raises = None
        self.lease_answer = None   # (status, json) for every lease call when set

    # --- the routes -------------------------------------------------------------
    def handler(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        self.requests.append((request.method, request.url.path, body, dict(request.headers)))
        if self.raises is not None:
            raise self.raises(request)
        path = request.url.path
        scripted = self.script.get(path)
        if scripted is not None:
            answer = scripted(body)
            if answer is not None:
                status, data = answer
                return httpx.Response(status, json=data)
        if path == contract.INTERNAL_ROUTE_ENSURE:
            status, data = self._ensure(body)
            return httpx.Response(status, json=data)
        if path == contract.INTERNAL_ROUTE_LEASE:
            if self.lease_answer is not None:
                return httpx.Response(self.lease_answer[0], json=self.lease_answer[1])
            return httpx.Response(200, json={"expires_at": 1e10, "state": "running",
                                             "stop_at": 2e10, "warn": False})
        if path == contract.INTERNAL_ROUTE_RELEASE:
            return httpx.Response(204)
        if path == contract.INTERNAL_ROUTE_LIST:
            return httpx.Response(200, json=self.listing())
        return httpx.Response(404)

    def _ensure(self, body):
        if self.mode == contract.MODE_SHARED:
            return 200, {"mode": "shared"}
        person = body["userId"]
        view = contract.VIEW_ACT_AS if body.get("actingAs") else contract.VIEW_OWN
        key = (person, view)
        if key not in self.instances:
            self.instances[key] = {
                "instance": contract.new_instance(),
                "token": secrets.token_urlsafe(32),
                "tunnel_token": secrets.token_urlsafe(32),
                "projects": ["p1", "p2"],
            }
            if key in self.cold and not body.get("wait"):
                self.cold.discard(key)
                return 202, {"mode": "per_user", "state": "starting",
                             "instance": self.instances[key]["instance"], "fresh": True}
        return 200, self.running_answer(person, view)

    def running_answer(self, person, view, **override):
        inst = self.instances[(person, view)]
        answer = {
            "mode": "per_user", "user_id": person, "view": view,
            "instance": inst["instance"],
            "host": contract.container_name(person, view, inst["instance"]),
            "token": inst["token"], "tunnel_token": inst["tunnel_token"],
            "ports": dict(contract.PORTS), "reverse_port": 4444,
            "projects": inst["projects"], "state": "running", "fresh": False,
            "stop_at": 2e10, "stop_reason": None, "warn": False,
        }
        answer.update(override)
        return answer

    def listing(self):
        if self.mode == contract.MODE_SHARED:
            return {"mode": "shared", "sandboxes": []}
        return {"mode": "per_user", "sandboxes": [
            {"user_id": person, "view": view, "instance": inst["instance"],
             "host": contract.container_name(person, view, inst["instance"]),
             "token": inst["token"], "state": "running"}
            for (person, view), inst in self.instances.items()]}

    # --- what the agent sent ----------------------------------------------------
    def calls(self, path):
        return [body for _m, p, body, _h in self.requests if p == path]

    def ensures(self):
        return self.calls(contract.INTERNAL_ROUTE_ENSURE)

    def leases(self):
        return self.calls(contract.INTERNAL_ROUTE_LEASE)

    def releases(self):
        return self.calls(contract.INTERNAL_ROUTE_RELEASE)

    def token(self, person, view=contract.VIEW_OWN):
        return self.instances[(person, view)]["token"]


def _connect_refused(request):
    return httpx.ConnectError("connection refused", request=request)


def _read_timeout(request):
    return httpx.ReadTimeout("slow", request=request)


class _Tool:
    def __init__(self, name):
        self.name = name


def _fake_get_tools(self, max_retries=5, retry_delay=10.0):
    """MCPToolsManager.get_tools without a network: what a live sandbox would load."""
    async def _load():
        tools = [_Tool("kali_shell"), _Tool("execute_nmap"), _Tool("metasploit_console")]
        self._tools_cache = {t.name: t for t in tools}
        self._generation += 1
        return tools
    return _load()


class RouterTest(unittest.IsolatedAsyncioTestCase):
    """Each test: a fresh router state, a stubbed gateway, the internal key set."""

    mode = contract.MODE_PER_USER

    async def asyncSetUp(self):
        self.gateway = Gateway(mode=self.mode if self.mode else contract.MODE_PER_USER)
        router._reset(mode=self.mode)
        self._patches = [
            mock.patch.object(router, "_transport", httpx.MockTransport(self.gateway.handler)),
            mock.patch.dict(router.INTERNAL_HEADERS, {"X-Internal-Key": "test-internal-key"}),
            mock.patch.object(router, "WEBAPP_API_URL", "http://webapp.test:3000"),
            mock.patch.dict(os.environ, COMPOSE_ENV),
        ]
        for p in self._patches:
            p.start()
        self.events = []
        router.add_status_listener(self.events.append)

    async def asyncTearDown(self):
        await router._shutdown()
        for p in reversed(self._patches):
            p.stop()
        router._reset(mode=None)

    def actor(self, user_id, tenant_id, actor_id=None, project_id="p1", session_id="sess-1"):
        token = current_run_actor.set(RunActor(user_id=user_id, tenant_id=tenant_id,
                                               project_id=project_id, session_id=session_id,
                                               actor_id=actor_id))
        self.addCleanup(current_run_actor.reset, token)


# =============================================================================
# Person, never tenant; the act-as view; the explicit entry-point person
# =============================================================================

class TestWhoseSandbox(RouterTest):

    async def test_person_not_tenant_routes(self):
        """bob's run on alice's project: bob's sandbox, and alice is named nowhere."""
        self.actor("bob", "alice")
        self.assertEqual(router.sandbox_user(), "bob")
        self.assertEqual(router.sandbox_view(), contract.VIEW_OWN)
        handle = await router.acquire(router.sandbox_user(), project_id="p1", kind="run")
        try:
            self.assertEqual([b["userId"] for b in self.gateway.ensures()], ["bob"])
            self.assertEqual(handle.user_id, "bob")
            self.assertEqual(handle.host, contract.container_name("bob", "own", handle.instance))
            self.assertEqual(handle.token, self.gateway.token("bob"))
            for _m, _p, body, _h in self.gateway.requests:
                self.assertNotIn("alice", json.dumps(body))
        finally:
            await router.release(handle)

    async def test_act_as_routes_to_member(self):
        """An admin acting as bob gets bob's act_as view: not bob's own, not the admin's."""
        own = await router.acquire("bob", project_id="p1", kind="run")
        self.actor("bob", "bob", actor_id="admin-1")
        self.assertEqual(router.sandbox_view(), contract.VIEW_ACT_AS)
        acting = await router.acquire(router.sandbox_user(), project_id="p1", kind="run")
        try:
            last = self.gateway.ensures()[-1]
            self.assertEqual(last["userId"], "bob")
            self.assertIs(last.get("actingAs"), True)
            self.assertNotIn("actingAs", self.gateway.ensures()[0])
            self.assertEqual(acting.view, contract.VIEW_ACT_AS)
            self.assertEqual(acting.host, contract.container_name("bob", "act_as", acting.instance))
            self.assertNotEqual(acting.instance, own.instance)
            self.assertNotEqual(acting.token, own.token)
            self.assertEqual(acting.token, self.gateway.token("bob", "act_as"))
            for _m, _p, body, _h in self.gateway.requests:
                self.assertNotIn("admin-1", json.dumps(body))
        finally:
            await router.release(own)
            await router.release(acting)

    async def test_act_as_work_cannot_ask_for_the_own_view(self):
        """An explicit view never takes act-as work into the member's own view."""
        self.actor("bob", "bob", actor_id="admin-1")
        with self.assertRaises(SandboxUnavailable) as ctx:
            await router.acquire("bob", project_id="p1", kind="run", view="own")
        self.assertEqual(ctx.exception.reason, "refused")
        with router.for_person("bob", acting=True):
            with self.assertRaises(SandboxUnavailable):
                await router.acquire("bob", project_id="p1", kind="exec", view="own")
        self.assertEqual(self.gateway.ensures(), [])
        # The act_as view may be named by act-as work only (S10, review item b).
        current_run_actor.set(None)
        with router.for_person("bob", acting=True):
            handle = await router.acquire("bob", project_id="p1", kind="exec", view="act_as")
        self.assertEqual(handle.view, contract.VIEW_ACT_AS)
        await router.release(handle)

    async def test_act_as_answer_for_own_view_is_refused(self):
        """A gateway that answers the own view to an act_as request is never trusted."""
        self.actor("bob", "bob", actor_id="admin-1")
        self.gateway.script[contract.INTERNAL_ROUTE_ENSURE] = lambda body: (
            self.gateway._ensure({**body, "actingAs": False}))
        with self.assertRaises(SandboxUnavailable) as ctx:
            await router.acquire("bob", project_id="p1", kind="run")
        self.assertEqual(ctx.exception.reason, "error")
        self.assertEqual(self.gateway.leases(), [])

    async def test_current_sandbox_user_wins_over_run_actor(self):
        self.actor("bob", "alice")
        with router.for_person("carol"):
            self.assertEqual(router.sandbox_user(), "carol")
            handle = await router.acquire(router.sandbox_user(), project_id="p1", kind="exec")
        self.assertEqual(router.sandbox_user(), "bob")
        try:
            self.assertEqual([b["userId"] for b in self.gateway.ensures()], ["carol"])
            self.assertEqual(handle.user_id, "carol")
        finally:
            await router.release(handle)

    async def test_acting_flag_selects_the_act_as_view(self):
        with router.for_person("bob", acting=True):
            self.assertEqual(router.sandbox_view(), contract.VIEW_ACT_AS)
        self.assertEqual(router.sandbox_view(), contract.VIEW_OWN)

    async def test_no_person_is_empty_never_the_tenant(self):
        self.assertEqual(router.sandbox_user(), "")
        self.actor("", "alice")
        self.assertEqual(router.sandbox_user(), "")

    async def test_entry_point_person_does_not_leak_to_the_parent_task(self):
        async def child():
            router.current_sandbox_user.set("carol")
            router.current_sandbox_acting.set(True)
            return router.sandbox_user(), router.sandbox_view()

        self.assertEqual(await asyncio.create_task(child()), ("carol", contract.VIEW_ACT_AS))
        self.assertEqual(router.sandbox_user(), "")
        self.assertEqual(router.sandbox_view(), contract.VIEW_OWN)


# =============================================================================
# Refusals: no person, the gateway's 403 and 409, errors
# =============================================================================

class TestRefusals(RouterTest):

    async def test_no_person_refuses_in_per_user_mode(self):
        for person in ("", "has space", "../etc", "x" * 65):
            with self.subTest(person=person):
                with self.assertRaises(SandboxUnavailable) as ctx:
                    await router.acquire(person, project_id="p1", kind="run")
                self.assertEqual(ctx.exception.reason, "no_user")
        self.assertEqual(self.gateway.ensures(), [])
        self.assertEqual(self.events, [], "no_user never reaches a browser")
        # Unreachable too: never a shared handle in per-user mode.
        self.gateway.raises = _connect_refused
        with self.assertRaises(SandboxUnavailable) as ctx:
            await router.acquire("", project_id="p1", kind="run")
        self.assertEqual(ctx.exception.reason, "no_user")

    async def test_gateway_403_is_refused_and_emits_it(self):
        for code in (contract.ERR_USER_REFUSED, contract.ERR_PROJECT_REFUSED):
            with self.subTest(code=code):
                self.events.clear()
                self.gateway.script[contract.INTERNAL_ROUTE_ENSURE] = lambda body, c=code: (403, {"code": c})
                with self.assertRaises(SandboxUnavailable) as ctx:
                    await router.acquire("bob", project_id="p1", kind="run")
                self.assertEqual(ctx.exception.reason, "refused")
                self.assertEqual(len(self.events), 1)
                event = self.events[0]
                self.assertEqual((event["state"], event["reason"]), ("unavailable", "refused"))
                self.assertEqual((event["user_id"], event["project_id"]), ("bob", "p1"))
        self.assertEqual(self.gateway.leases(), [])

    async def test_403_without_a_sandbox_code_is_an_error(self):
        self.gateway.script[contract.INTERNAL_ROUTE_ENSURE] = lambda body: (403, {"error": "Forbidden"})
        with self.assertRaises(SandboxUnavailable) as ctx:
            await router.acquire("bob", project_id="p1", kind="run")
        self.assertEqual(ctx.exception.reason, "error")

    async def test_ram_refusal_raises_sandbox_unavailable_with_limit(self):
        for wrapped in (False, True):
            with self.subTest(wrapped=wrapped):
                self.events.clear()
                payload = {**RAM_PAYLOAD, "code": contract.ERR_RAM}
                body = {"detail": payload} if wrapped else payload
                self.gateway.script[contract.INTERNAL_ROUTE_ENSURE] = lambda b, x=body: (409, x)
                with self.assertRaises(SandboxUnavailable) as ctx:
                    await router.acquire("bob", project_id="p1", kind="run")
                exc = ctx.exception
                self.assertEqual(exc.reason, "ram")
                self.assertEqual(exc.limit, RAM_PAYLOAD)
                self.assertEqual(exc.detail, RAM_PAYLOAD["detail"])
                self.assertEqual(len(self.events), 1)
                self.assertEqual(self.events[0]["state"], "unavailable")
                self.assertEqual(self.events[0]["reason"], "ram")
                self.assertEqual(self.events[0]["limit"], RAM_PAYLOAD)
        self.assertEqual(router.current_mode(), contract.MODE_PER_USER)

    async def test_hard_refusal(self):
        payload = {**RAM_PAYLOAD, "limitType": "hard", "settingName": "KALI_SANDBOX_MAX_CONCURRENT",
                   "detail": "the sandbox limit is reached", "code": contract.ERR_HARD}
        self.gateway.script[contract.INTERNAL_ROUTE_ENSURE] = lambda b: (409, payload)
        with self.assertRaises(SandboxUnavailable) as ctx:
            await router.acquire("bob", project_id="p1", kind="run")
        self.assertEqual(ctx.exception.reason, "hard")
        self.assertEqual(ctx.exception.limit["settingName"], "KALI_SANDBOX_MAX_CONCURRENT")

    async def test_5xx_and_timeout_are_errors(self):
        """per_user known: a start error, an outage (503 orchestrator_unavailable, a
        code-less 5xx) and a read timeout all refuse; none is a shared handle."""
        self.gateway.script[contract.INTERNAL_ROUTE_ENSURE] = lambda b: (503, {"code": contract.ERR_START_FAILED})
        with self.assertRaises(SandboxUnavailable) as ctx:
            await router.acquire("bob", project_id="p1", kind="run")
        self.assertEqual(ctx.exception.reason, "error")
        self.assertIn(contract.ERR_START_FAILED, ctx.exception.detail)
        for answer in ((503, {"code": "orchestrator_unavailable"}), (502, {"error": "bad gateway"})):
            with self.subTest(answer=answer):
                self.gateway.script[contract.INTERNAL_ROUTE_ENSURE] = lambda b, a=answer: a
                with self.assertRaises(SandboxUnavailable) as ctx:
                    await router.acquire("bob", project_id="p1", kind="run")
                self.assertEqual(ctx.exception.reason, "error")
                self.assertIn("gateway_error", ctx.exception.detail)
        self.gateway.script.clear()
        self.gateway.raises = _read_timeout
        with self.assertRaises(SandboxUnavailable) as ctx:
            await router.acquire("bob", project_id="p1", kind="run")
        self.assertEqual(ctx.exception.reason, "error")
        self.assertEqual([e["reason"] for e in self.events], ["error"] * 4)
        self.assertEqual(router.current_mode(), contract.MODE_PER_USER)

    async def test_invalid_project_id_is_never_sent(self):
        for project_id in ("..", ".staging", "a/b", "p1\n", "CON", ""):
            with self.subTest(project_id=project_id):
                with self.assertRaises(SandboxUnavailable) as ctx:
                    await router.acquire("bob", project_id=project_id, kind="run")
                self.assertEqual(ctx.exception.reason, "error")
        self.assertEqual(self.gateway.ensures(), [])

    async def test_unknown_lease_kind_is_a_programming_error(self):
        with self.assertRaises(ValueError):
            await router.acquire("bob", project_id="p1", kind="admin")
        self.assertEqual(self.gateway.requests, [])

    async def test_answer_naming_another_person_is_refused(self):
        """A gateway answer for alice to bob's request never becomes bob's handle."""
        self.gateway._ensure({"userId": "alice", "wait": True})
        self.gateway._ensure({"userId": "bob", "wait": True})
        alice = self.gateway.running_answer("alice", "own")

        def bob(**override):
            return {**self.gateway.running_answer("bob", "own"), **override}

        cases = {
            "other person": alice,
            "other host": {**alice, "user_id": "bob"},
            "another person's id": bob(user_id="alice"),
            "a service as host": bob(host="redamon-postgres"),
            "other view": bob(view="act_as"),
            "no token": bob(token=""),
            "token with a newline": bob(token="t" * 20 + "\nX-Evil: 1"),
            "project not mounted": bob(projects=["p9"]),
            "projects not a list": bob(projects="p1"),
            "not running": bob(state="starting"),
            "malformed instance": bob(instance="../x"),
        }
        for name, answer in cases.items():
            with self.subTest(name=name):
                self.gateway.script[contract.INTERNAL_ROUTE_ENSURE] = lambda b, a=answer: (200, a)
                with self.assertRaises(SandboxUnavailable) as ctx:
                    await router.acquire("bob", project_id="p1", kind="run")
                self.assertEqual(ctx.exception.reason, "error")
        self.assertEqual(self.gateway.leases(), [])

    async def test_tokens_never_in_repr_or_exception(self):
        handle = await router.acquire("bob", project_id="p1", kind="run")
        try:
            for text in (repr(handle), str(handle)):
                self.assertNotIn(handle.token, text)
                self.assertNotIn(handle.tunnel_token, text)
            self.gateway.script[contract.INTERNAL_ROUTE_ENSURE] = lambda b: (
                500, {"error": "boom", "token": handle.token})
            with self.assertRaises(SandboxUnavailable) as ctx:
                await router.acquire("bob", project_id="p2", kind="run")
            for text in (str(ctx.exception), repr(ctx.exception), ctx.exception.detail):
                self.assertNotIn(handle.token, text)
            for event in self.events:
                self.assertNotIn(handle.token, json.dumps(event, default=str))
        finally:
            await router.release(handle)


# =============================================================================
# Per-instance clients and tokens (I10, S5, T7, I11)
# =============================================================================

class TestClients(RouterTest):

    async def test_two_users_distinct_clients_and_tokens(self):
        alice = await router.acquire("alice", project_id="p1", kind="run")
        bob = await router.acquire("bob", project_id="p1", kind="run")
        try:
            import tools
            with mock.patch.object(tools.MCPToolsManager, "get_tools", _fake_get_tools):
                client_a = await router.client_for(alice)
                client_b = await router.client_for(bob)
                self.assertIsNot(client_a, client_b)
                self.assertIs(await router.client_for(alice), client_a, "cached per instance")
                tool = await router.tool_for("kali_shell", bob)
                self.assertEqual(tool.name, "kali_shell")
                self.assertIsNone(await router.tool_for("no_such_tool", bob))
            for handle, client in ((alice, client_a), (bob, client_b)):
                configs = client._server_configs
                self.assertEqual(set(configs), {"network_recon", "nmap", "metasploit", "nuclei", "playwright"})
                for sid, cfg in configs.items():
                    self.assertEqual(cfg["headers"], {"Authorization": f"Bearer {handle.token}"})
                    self.assertEqual(cfg["url"], f"http://{handle.host}:{contract.PORTS[sid]}/sse")
                    self.assertNotIn(SHARED_TOKEN, json.dumps(cfg))
                self.assertEqual(router.headers_for(handle), {"Authorization": f"Bearer {handle.token}"})
            self.assertNotEqual(alice.token, bob.token)
            # The same connect and read timeouts as today's system servers.
            today = {s.id: (s.connect_timeout, s.read_timeout) for s in tools._build_system_mcp_servers()}
            self.assertEqual({sid: (c["timeout"], c["sse_read_timeout"]) for sid, c in client_a._server_configs.items()},
                             today)
        finally:
            await router.release(alice)
            await router.release(bob)

    async def test_url_and_headers_per_port(self):
        handle = await router.acquire("bob", project_id="p1", kind="run")
        try:
            host = handle.host
            self.assertEqual(router.url_for(handle, "sessions", "/sessions"), f"http://{host}:8013/sessions")
            self.assertEqual(router.url_for(handle, "hydra", "/progress"), f"http://{host}:8014/progress")
            self.assertEqual(router.url_for(handle, "terminal", ""), f"ws://{host}:8016")
            self.assertEqual(router.url_for(handle, "network_recon", "/redamon/runs/stop"),
                             f"http://{host}:8000/redamon/runs/stop")
            self.assertEqual(router.headers_for(handle, "tunnel"),
                             {"Authorization": f"Bearer {handle.tunnel_token}"})
            self.assertEqual(router.headers_for(handle, "ngrok_api"), {})
            for bad in ("no-slash", "/a b", "/x\r\nHost: evil", "/x\\y"):
                with self.subTest(path=bad), self.assertRaises(ValueError):
                    router.url_for(handle, "sessions", bad)
            with self.assertRaises(ValueError):
                router.url_for(handle, "docker", "/")
        finally:
            await router.release(handle)

    async def test_failed_connect_is_not_cached(self):
        handle = await router.acquire("bob", project_id="p1", kind="run")
        try:
            import tools

            async def _none(self, max_retries=5, retry_delay=10.0):
                return []
            with mock.patch.object(tools.MCPToolsManager, "get_tools", _none):
                with self.assertRaises(SandboxUnavailable) as ctx:
                    await router.client_for(handle)
            self.assertEqual(ctx.exception.reason, "error")
            self.assertEqual(router._clients, {})
        finally:
            await router.release(handle)

    async def test_drop_forgets_both_views(self):
        own = await router.acquire("bob", project_id="p1", kind="run")
        with router.for_person("bob", acting=True):
            acting = await router.acquire("bob", project_id="p1", kind="run", view="act_as")
        alice = await router.acquire("alice", project_id="p1", kind="run")
        import tools
        with mock.patch.object(tools.MCPToolsManager, "get_tools", _fake_get_tools):
            for h in (own, acting, alice):
                await router.client_for(h)
        await router.drop("bob")
        self.assertTrue(own.stale and acting.stale)
        self.assertFalse(alice.stale)
        self.assertEqual({k[0] for k in router._clients}, {"alice"})
        for h in (own, acting):
            self.assertTrue(h._renew_task is None or h._renew_task.done())
            with self.assertRaises(SandboxUnavailable) as ctx:
                await router.client_for(h)
            self.assertEqual(ctx.exception.reason, "stopped")
        await router.release(alice)


# =============================================================================
# Leases and status events
# =============================================================================

class TestLeases(RouterTest):

    async def asyncSetUp(self):
        await super().asyncSetUp()
        p = mock.patch.object(router, "LEASE_RENEW_S", 0.01)
        p.start()
        self.addCleanup(p.stop)

    async def _until(self, predicate, timeout=2.0):
        deadline = asyncio.get_running_loop().time() + timeout
        while not predicate():
            if asyncio.get_running_loop().time() > deadline:
                self.fail("condition not reached")
            await asyncio.sleep(0.005)

    async def test_lease_renewed_and_released(self):
        handle = await router.acquire("bob", project_id="p1", kind="exec")
        await self._until(lambda: len(self.gateway.leases()) >= 3)
        leases = self.gateway.leases()
        self.assertEqual({b["leaseId"] for b in leases}, {leases[0]["leaseId"]}, "one id, renewed")
        self.assertEqual({(b["userId"], b["instance"], b["kind"]) for b in leases},
                         {("bob", handle.instance, "exec")})
        task = handle._renew_task
        await router.release(handle)
        self.assertTrue(task.done())
        self.assertEqual(self.gateway.releases(), [{"userId": "bob", "leaseId": leases[0]["leaseId"]}])
        count = len(self.gateway.leases())
        await asyncio.sleep(0.05)
        self.assertEqual(len(self.gateway.leases()), count, "no renewal after release")
        await router.release(handle)
        self.assertEqual(len(self.gateway.releases()), 1, "release is idempotent")

    async def test_renewal_runs_outside_the_acquirers_context(self):
        """No run scope, run actor or entry-point person reaches the renewal task."""
        seen = []
        original = router._lease_call

        async def spy(*args, **kwargs):
            seen.append((router._current_scope.get(), current_run_actor.get(),
                         router.current_sandbox_user.get()))
            return await original(*args, **kwargs)

        self.actor("bob", "alice", session_id="sess-c")
        with mock.patch.object(router, "_lease_call", spy):
            async with router.run_scope("sess-c"):
                with router.for_person("bob"):
                    handle = await router.acquire("bob", project_id="p1", kind="exec")
                    await self._until(lambda: len(seen) >= 3)
                    await router.release(handle)
        self.assertIsNotNone(seen[0][0], "the first take runs in the acquirer's task")
        self.assertTrue(all(entry == (None, None, None) for entry in seen[1:]), seen[1:])

    async def test_renew_refused_drops_client(self):
        self.actor("bob", "alice", session_id="sess-r")
        handle = await router.acquire("bob", project_id="p1", kind="run")
        import tools
        with mock.patch.object(tools.MCPToolsManager, "get_tools", _fake_get_tools):
            await router.client_for(handle)
        self.assertIn(handle.key, router._clients)
        self.gateway.lease_answer = (409, {"code": contract.ERR_NOT_RUNNING})
        await self._until(lambda: handle.stale)
        self.assertNotIn(handle.key, router._clients)
        self.assertTrue(handle._renew_task is None or handle._renew_task.done())
        self.assertEqual(self.events[-1]["state"], "unavailable")
        self.assertEqual(self.events[-1]["reason"], "stopped")
        self.assertEqual(self.events[-1]["session_id"], "sess-r", "the renewal names its run")
        # The next acquire re-ensures and gets the new instance.
        self.gateway.lease_answer = None
        del self.gateway.instances[("bob", "own")]
        again = await router.acquire("bob", project_id="p1", kind="run")
        self.assertEqual(len(self.gateway.ensures()), 2)
        self.assertNotEqual(again.instance, handle.instance)
        await router.release(handle)
        await router.release(again)

    async def test_draining_refusal_also_marks_stale(self):
        handle = await router.acquire("bob", project_id="p1", kind="run")
        self.gateway.lease_answer = (409, {"code": contract.ERR_DRAINING})
        await self._until(lambda: handle.stale)
        await router.release(handle)

    async def test_transient_renew_failure_keeps_the_handle(self):
        handle = await router.acquire("bob", project_id="p1", kind="run")
        self.gateway.lease_answer = (502, {"error": "bad gateway"})
        before = len(self.gateway.leases())
        await self._until(lambda: len(self.gateway.leases()) >= before + 3)
        self.assertFalse(handle.stale)
        await router.release(handle)

    async def test_refused_first_lease_re_ensures_once(self):
        answers = iter([(409, {"code": contract.ERR_NOT_RUNNING})])
        self.gateway.script[contract.INTERNAL_ROUTE_LEASE] = lambda b: next(answers, None)
        handle = await router.acquire("bob", project_id="p1", kind="run")
        self.assertEqual(len(self.gateway.ensures()), 2)
        self.assertFalse(handle.stale)
        await router.release(handle)

    async def test_renew_task_never_outlives_its_handle(self):
        handle = await router.acquire("bob", project_id="p1", kind="run")
        task = handle._renew_task
        ref = weakref.ref(handle)
        del handle
        gc.collect()
        self.assertIsNone(ref(), "the renew task holds no reference to its handle")
        await self._until(task.done)

    async def test_starting_then_ready_status_events(self):
        self.gateway.cold.add(("bob", "own"))
        self.actor("bob", "alice", session_id="sess-42")
        handle = await router.acquire("bob", project_id="p1", kind="run")
        try:
            self.assertEqual([e["state"] for e in self.events], ["starting", "ready"])
            for event in self.events:
                self.assertEqual((event["user_id"], event["project_id"], event["session_id"]),
                                 ("bob", "p1", "sess-42"))
            self.assertEqual([b["wait"] for b in self.gateway.ensures()], [False, True])
            self.assertTrue(handle.fresh)
            self.assertEqual(handle.state, "running")
        finally:
            await router.release(handle)

    async def test_warm_sandbox_emits_nothing(self):
        handle = await router.acquire("bob", project_id="p1", kind="run")
        self.assertEqual(self.events, [])
        await router.release(handle)

    async def test_wait_false_returns_a_starting_handle_without_lease(self):
        self.gateway.cold.add(("bob", "own"))
        handle = await router.acquire("bob", project_id="p1", kind="exec", wait=False)
        self.assertEqual(handle.state, "starting")
        self.assertFalse(handle.usable)
        self.assertEqual(self.gateway.leases(), [])
        self.assertEqual([e["state"] for e in self.events], ["starting"])
        with self.assertRaises(SandboxUnavailable):
            await router.client_for(handle)
        await router.release(handle)

    async def test_failing_listener_does_not_break_acquire(self):
        def broken(event):
            raise RuntimeError("listener down")

        async def slow(event):
            await asyncio.sleep(0)
            self.events.append({"async": event["state"]})

        router.add_status_listener(broken)
        router.add_status_listener(slow)
        self.gateway.cold.add(("bob", "own"))
        handle = await router.acquire("bob", project_id="p1", kind="run")
        self.assertIn({"async": "ready"}, self.events)
        router.remove_status_listener(broken)
        await router.release(handle)


# =============================================================================
# The mode: TD-6
# =============================================================================

class TestModeNoAnswerYet(RouterTest):
    """No answer yet: the default is per_user, so an outage fails closed, never the
    shared sandbox (an outage after a shared answer is TestSharedMode)."""
    mode = None

    async def test_gateway_unreachable_fails_closed(self):
        self.gateway.raises = _connect_refused
        with self.assertRaises(SandboxUnavailable) as ctx:
            await router.acquire("bob", project_id="p1", kind="run")
        self.assertEqual(ctx.exception.reason, "error")
        self.assertEqual(router.current_mode(), contract.MODE_PER_USER)

    async def test_gateway_outage_before_any_answer_fails_closed(self):
        self.gateway.script[contract.INTERNAL_ROUTE_ENSURE] = lambda b: (503, {"code": "orchestrator_unavailable"})
        with self.assertRaises(SandboxUnavailable) as ctx:
            await router.acquire("bob", project_id="p1", kind="run")
        self.assertEqual(ctx.exception.reason, "error")
        self.assertEqual([p for _m, p, _b, _h in self.gateway.requests], [contract.INTERNAL_ROUTE_ENSURE])

    async def test_no_internal_key_reads_as_unreachable(self):
        with mock.patch.dict(router.INTERNAL_HEADERS, {"X-Internal-Key": ""}):
            with self.assertRaises(SandboxUnavailable) as ctx:
                await router.acquire("bob", project_id="p1", kind="run")
        self.assertEqual(ctx.exception.reason, "error")
        self.assertEqual(self.gateway.requests, [], "no call without the key")

    async def test_no_person_asks_the_mode_first(self):
        """No answer yet and no person: the list tells the mode; per_user refuses."""
        with self.assertRaises(SandboxUnavailable) as ctx:
            await router.acquire("", project_id="p1", kind="run")
        self.assertEqual(ctx.exception.reason, "no_user")
        self.assertEqual([p for _m, p, _b, _h in self.gateway.requests], [contract.INTERNAL_ROUTE_LIST])
        self.assertEqual(router.current_mode(), contract.MODE_PER_USER)


class TestModePerUserSeen(RouterTest):
    mode = contract.MODE_PER_USER

    async def test_gateway_unreachable_after_per_user_answer_refuses(self):
        router._reset(mode=None)
        handle = await router.acquire("bob", project_id="p1", kind="run")
        self.assertEqual(handle.mode, contract.MODE_PER_USER)
        await router.release(handle)
        self.assertEqual(router.current_mode(), contract.MODE_PER_USER)
        for raises in (_connect_refused, lambda r: httpx.ConnectTimeout("t", request=r)):
            with self.subTest(raises=raises):
                self.gateway.raises = raises
                with self.assertRaises(SandboxUnavailable) as ctx:
                    await router.acquire("bob", project_id="p1", kind="run")
                self.assertEqual(ctx.exception.reason, "error")
        self.gateway.raises = None
        with mock.patch.dict(router.INTERNAL_HEADERS, {"X-Internal-Key": ""}):
            with self.assertRaises(SandboxUnavailable) as ctx:
                await router.acquire("bob", project_id="p1", kind="run")
            self.assertEqual(ctx.exception.reason, "error")
        # A route that is not there yet (404 without a code) reads as unreachable too.
        self.gateway.script[contract.INTERNAL_ROUTE_ENSURE] = lambda b: (404, {})
        with self.assertRaises(SandboxUnavailable) as ctx:
            await router.acquire("bob", project_id="p1", kind="run")
        self.assertEqual(ctx.exception.reason, "error")

    async def test_is_running_and_running_sandboxes(self):
        self.assertFalse(await router.is_running("bob"))
        handle = await router.acquire("bob", project_id="p1", kind="run")
        self.assertTrue(await router.is_running("bob"))
        self.assertFalse(await router.is_running("bob", view="act_as"))
        self.assertFalse(await router.is_running("alice"))
        listed = await router.running_sandboxes()
        self.assertEqual([(h.user_id, h.view, h.instance, h.token) for h in listed],
                         [("bob", "own", handle.instance, handle.token)])
        # An entry whose host is not its person's container is skipped, never used.
        self.gateway.script[contract.INTERNAL_ROUTE_LIST] = lambda b: (200, {
            "mode": "per_user", "sandboxes": [
                {"user_id": "bob", "view": "own", "instance": handle.instance,
                 "host": "redamon-postgres", "token": handle.token, "state": "running"}]})
        self.assertEqual(await router.running_sandboxes(), [])
        self.gateway.raises = _connect_refused
        self.assertFalse(await router.is_running("bob"))
        with self.assertRaises(SandboxUnavailable):
            await router.running_sandboxes()
        await router.release(handle)


class TestSharedMode(RouterTest):
    mode = contract.MODE_SHARED

    async def test_shared_mode_uses_compose_addresses(self):
        handle = await router.acquire("bob", project_id="p1", kind="run")
        self.assertEqual(handle.mode, contract.MODE_SHARED)
        self.assertEqual(handle.instance, contract.SHARED_INSTANCE)
        self.assertEqual(self.gateway.leases(), [], "no lease in shared mode")
        self.assertEqual(router.url_for(handle, "network_recon", "/redamon/runs/stop"),
                         "http://kali-sandbox:8000/redamon/runs/stop")
        self.assertEqual(router.url_for(handle, "sessions", "/sessions"), "http://kali-sandbox:8013/sessions")
        self.assertEqual(router.url_for(handle, "hydra", "/progress"), "http://kali-sandbox:8014/progress")
        self.assertEqual(router.url_for(handle, "terminal", ""), "ws://kali-sandbox:8016")
        self.assertEqual(router.url_for(handle, "tunnel", "/tunnel/configure"),
                         "http://kali-sandbox:8015/tunnel/configure")
        self.assertEqual(router.url_for(handle, "ngrok_api", "/api/tunnels"), "http://kali-sandbox:4040/api/tunnels")
        self.assertEqual(router.headers_for(handle), {"Authorization": f"Bearer {SHARED_TOKEN}"})
        import tools
        with mock.patch.object(tools.MCPToolsManager, "get_tools", _fake_get_tools):
            client = await router.client_for(handle)
        from mcp_registry import to_mcp_servers_dict
        today, _ = to_mcp_servers_dict(tools._build_system_mcp_servers())
        self.assertEqual(client._server_configs, today)
        await router.release(handle)
        self.assertEqual(self.gateway.releases(), [])
        self.assertTrue(await router.is_running("bob"))
        self.assertEqual(await router.running_sandboxes(), [])

    async def test_no_person_in_shared_mode_keeps_today(self):
        handle = await router.acquire("", project_id="p1", kind="run")
        self.assertEqual(handle.mode, contract.MODE_SHARED)
        self.assertEqual([p for _m, p, _b, _h in self.gateway.requests], [contract.INTERNAL_ROUTE_LIST])
        self.gateway.raises = _connect_refused
        handle = await router.acquire("", project_id="p1", kind="run")
        self.assertEqual(handle.mode, contract.MODE_SHARED, "unreachable: the last answer")

    async def test_no_person_after_a_switch_to_per_user_refuses(self):
        """A remembered `shared` never serves a call with no person once the switch says per_user."""
        self.assertEqual(router.current_mode(), contract.MODE_SHARED)
        self.gateway.mode = contract.MODE_PER_USER
        with self.assertRaises(SandboxUnavailable) as ctx:
            await router.acquire("", project_id="p1", kind="run")
        self.assertEqual(ctx.exception.reason, "no_user")
        self.assertEqual(router.current_mode(), contract.MODE_PER_USER)

    async def test_gateway_outage_keeps_shared_mode(self):
        """TD-6: the webapp answers 503 orchestrator_unavailable on an outage and never
        invents a mode; shared mode keeps working through it."""
        outages = {
            "orchestrator_unavailable": lambda b: (503, {"code": "orchestrator_unavailable"}),
            "a code-less 502": lambda b: (502, {"error": "bad gateway"}),
            "a 500 page": lambda b: (500, None),
        }
        for name, answer in outages.items():
            with self.subTest(name=name):
                self.gateway.script[contract.INTERNAL_ROUTE_ENSURE] = answer
                handle = await router.acquire("bob", project_id="p1", kind="run")
                self.assertEqual(handle.mode, contract.MODE_SHARED)
        self.gateway.script.clear()
        self.gateway.raises = _read_timeout
        handle = await router.acquire("bob", project_id="p1", kind="run")
        self.assertEqual(handle.mode, contract.MODE_SHARED)
        self.assertEqual(self.events, [])
        self.assertTrue(await router.is_running("bob"))
        self.assertEqual(await router.running_sandboxes(), [])

    async def test_a_per_user_start_error_is_never_an_outage(self):
        """Only the per-user manager answers these: they refuse and prove per-user mode,
        even while the agent still remembers shared."""
        for code in (contract.ERR_IMAGE_MISSING, contract.ERR_START_FAILED, contract.ERR_START_TIMEOUT):
            with self.subTest(code=code):
                router._reset(mode=contract.MODE_SHARED)
                status = contract.ERROR_STATUS[code]
                self.gateway.script[contract.INTERNAL_ROUTE_ENSURE] = lambda b, s=status, c=code: (s, {"code": c})
                with self.assertRaises(SandboxUnavailable) as ctx:
                    await router.acquire("bob", project_id="p1", kind="run")
                self.assertEqual(ctx.exception.reason, "error")
                self.assertEqual(router.current_mode(), contract.MODE_PER_USER)

    async def test_shared_handle_retired_once_per_user_is_answered(self):
        """A shared handle held by a run scope never serves again once the switch says
        per_user, a drop included: the next acquire gets the person's own sandbox."""
        import tools
        with mock.patch.object(tools.MCPToolsManager, "get_tools", _fake_get_tools):
            async with router.run_scope("sess-s"):
                shared = await router.acquire("bob", project_id="p1", kind="run")
                self.assertEqual(shared.mode, contract.MODE_SHARED)
                await router.client_for(shared)
                self.assertIn(router._SHARED_CLIENT_KEY, router._clients)
                self.gateway.mode = contract.MODE_PER_USER
                carol = await router.acquire("carol", project_id="p1", kind="exec")
                self.assertEqual(router.current_mode(), contract.MODE_PER_USER)
                self.assertNotIn(router._SHARED_CLIENT_KEY, router._clients)
                await router.drop("bob")
                again = await router.acquire("bob", project_id="p1", kind="run")
                self.assertIsNot(again, shared)
                self.assertEqual(again.mode, contract.MODE_PER_USER)
                self.assertFalse(shared.usable)
                await self._assert_retired(shared)
                await router.release(carol)

    async def test_fallback_shared_handle_retired_when_per_user_answers(self):
        """A shared handle from an outage fallback stops serving once per_user is answered."""
        self.gateway.raises = _connect_refused
        shared = await router.acquire("bob", project_id="p1", kind="run")
        self.assertEqual(shared.mode, contract.MODE_SHARED)
        self.assertEqual(router.url_for(shared, "terminal", ""), "ws://kali-sandbox:8016")
        self.gateway.raises = None
        self.gateway.mode = contract.MODE_PER_USER
        own = await router.acquire("bob", project_id="p1", kind="exec")
        self.assertEqual(own.mode, contract.MODE_PER_USER)
        await self._assert_retired(shared)
        await router.release(own)

    async def _assert_retired(self, handle):
        """No client, address or bearer of the shared container for this handle."""
        for call in (lambda: router.url_for(handle, "terminal", ""),
                     lambda: router.url_for(handle, "sessions", "/sessions"),
                     lambda: router.headers_for(handle),
                     lambda: router.headers_for(handle, "tunnel")):
            with self.assertRaises(SandboxUnavailable) as ctx:
                call()
            self.assertEqual(ctx.exception.reason, "stopped")
        import tools
        with mock.patch.object(tools.MCPToolsManager, "get_tools", _fake_get_tools):
            with self.assertRaises(SandboxUnavailable) as ctx:
                await router.client_for(handle)
        self.assertEqual(ctx.exception.reason, "stopped")
        self.assertNotIn(router._SHARED_CLIENT_KEY, router._clients)

    async def test_a_per_user_answer_switches_the_mode(self):
        self.gateway.mode = contract.MODE_PER_USER
        handle = await router.acquire("bob", project_id="p1", kind="run")
        self.assertEqual(handle.mode, contract.MODE_PER_USER)
        self.assertEqual(router.current_mode(), contract.MODE_PER_USER)
        await router.release(handle)


# =============================================================================
# run_scope: one lazy run lease shared by the run's calls and its Fireteam members
# =============================================================================

class TestRunScope(RouterTest):

    async def test_run_scope_acquires_lazily_and_releases(self):
        # current_handle() answers only the run's person (S10, review item a).
        self.actor("bob", "alice")
        async with router.run_scope("sess-9"):
            self.assertIsNone(router.current_handle())
            self.assertEqual(self.gateway.requests, [], "no sandbox for a run that uses no Kali tool")

            async def member():
                return await router.acquire("bob", project_id="p1", kind="run")

            first, second = await asyncio.gather(member(), member())
            third = await router.acquire("bob", project_id="p1", kind="run")
            self.assertIs(first, second)
            self.assertIs(first, third)
            self.assertIs(router.current_handle(), first)
            self.assertEqual(len(self.gateway.ensures()), 1)
            self.assertEqual(len(self.gateway.leases()), 1)
            self.assertEqual(self.gateway.leases()[0]["kind"], "run")
            await router.release(first)
            self.assertEqual(self.gateway.releases(), [], "the scope releases it")
            # Another kind inside the scope takes its own lease.
            job = await router.acquire("bob", project_id="p1", kind="job")
            self.assertIsNot(job, first)
            await router.release(job)
        self.assertEqual(len(self.gateway.releases()), 2)
        self.assertTrue(first.released)
        self.assertTrue(first._renew_task is None or first._renew_task.done())
        self.assertIsNone(router.current_handle())

    async def test_run_lease_acquired_while_the_scope_closes_is_released(self):
        """The scope closes while a member's run acquire waits: the handle comes back
        unscoped, the caller's release() ends it, and nothing renews it afterwards."""
        with mock.patch.object(router, "LEASE_RENEW_S", 0.01):
            gate = asyncio.Event()
            original = router._acquire

            async def held(*args, **kwargs):
                await gate.wait()
                return await original(*args, **kwargs)

            with mock.patch.object(router, "_acquire", held):
                async with router.run_scope("sess-7"):
                    pending = asyncio.create_task(router.acquire("bob", project_id="p1", kind="run"))
                    await asyncio.sleep(0.01)
                gate.set()
                handle = await pending
            self.assertFalse(handle.scoped)
            await router.release(handle)
            self.assertTrue(handle.released)
            self.assertEqual(len(self.gateway.releases()), 1)
            count = len(self.gateway.leases())
            await asyncio.sleep(0.1)
            self.assertEqual(len(self.gateway.leases()), count, "no renewal after release")

    async def test_unreleased_handle_of_a_closed_scope_stops_renewing_when_dropped(self):
        """The renewal holds neither the handle nor the acquirer's context (whose run scope
        would keep the handle alive): a handle nobody holds stops renewing."""
        with mock.patch.object(router, "LEASE_RENEW_S", 0.01):
            gate = asyncio.Event()
            original = router._acquire

            async def held(*args, **kwargs):
                await gate.wait()
                return await original(*args, **kwargs)

            with mock.patch.object(router, "_acquire", held):
                async with router.run_scope("sess-8"):
                    pending = asyncio.create_task(router.acquire("bob", project_id="p1", kind="run"))
                    await asyncio.sleep(0.01)
                gate.set()
                renew = (await pending)._renew_task
            del pending
            gc.collect()
            deadline = asyncio.get_running_loop().time() + 2
            while not renew.done():
                self.assertLess(asyncio.get_running_loop().time(), deadline, "still renewing")
                await asyncio.sleep(0.01)
            count = len(self.gateway.leases())
            await asyncio.sleep(0.05)
            self.assertEqual(len(self.gateway.leases()), count)

    async def test_release_ends_a_scoped_handle_once_its_scope_closed(self):
        async with router.run_scope("sess-9") as scope:
            handle = await router.acquire("bob", project_id="p1", kind="run")
            await router.release(handle)
            self.assertFalse(handle.released, "an open scope keeps it")
            scope.closed = True
            await router.release(handle)
            self.assertTrue(handle.released)
        self.assertEqual(len(self.gateway.releases()), 1)

    async def test_empty_run_scope_calls_nothing(self):
        async with router.run_scope("sess-0"):
            pass
        self.assertEqual(self.gateway.requests, [])

    async def test_scope_never_hands_one_persons_handle_to_another(self):
        async with router.run_scope("sess-1"):
            bob = await router.acquire("bob", project_id="p1", kind="run")
            carol = await router.acquire("carol", project_id="p1", kind="run")
            with router.for_person("bob", acting=True):
                acting = await router.acquire("bob", project_id="p1", kind="run", view="act_as")
            self.assertEqual((carol.user_id, acting.view), ("carol", "act_as"))
            self.assertEqual(len({bob.token, carol.token, acting.token}), 3)

    async def test_stale_scope_handle_is_replaced(self):
        async with router.run_scope("sess-2"):
            first = await router.acquire("bob", project_id="p1", kind="run")
            await router.drop("bob")
            del self.gateway.instances[("bob", "own")]
            second = await router.acquire("bob", project_id="p1", kind="run")
            self.assertIsNot(first, second)
            self.assertFalse(second.stale)

    async def test_scope_exit_on_cancel_stops_renewing(self):
        with mock.patch.object(router, "LEASE_RENEW_S", 0.01):
            holder = {}

            async def run():
                async with router.run_scope("sess-3"):
                    holder["h"] = await router.acquire("bob", project_id="p1", kind="run")
                    await asyncio.sleep(10)

            task = asyncio.create_task(run())
            while "h" not in holder:
                self.assertFalse(task.done(), "the run ended before it acquired")
                await asyncio.sleep(0.005)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            renew = holder["h"]._renew_task
            self.assertTrue(renew is None or renew.done())


# =============================================================================
# The job map (TD-9) and the job phase overlay (TD-10)
# =============================================================================

class TestJobs(RouterTest):

    async def test_job_sandbox_user_map_and_phase(self):
        self.assertTrue(router.note_job("job-1", "bob"))
        self.assertTrue(router.note_job("job-2", "bob"))
        self.assertTrue(router.note_job("job-3", "alice"))
        self.assertFalse(router.note_job("job-4", ""))
        self.assertFalse(router.note_job("job-5", "../x"))
        self.assertEqual(router.job_sandbox_user("job-1"), "bob")
        self.assertEqual(router.job_sandbox_user("nope"), "")
        self.assertEqual(router.jobs_by_sandbox_user(), {"bob": ["job-1", "job-2"], "alice": ["job-3"]})

        self.assertIsNone(router.job_phase("job-1"))
        router.set_job_phase("job-1", "starting")
        self.assertEqual(router.job_phase("job-1").phase, "starting")
        router.set_job_phase("job-1", "running")
        self.assertEqual(router.job_phase("job-1").phase, "running")
        router.job_failed("job-2", SandboxUnavailable("ram", limit=RAM_PAYLOAD, detail=RAM_PAYLOAD["detail"]))
        phase = router.job_phase("job-2")
        self.assertEqual((phase.phase, phase.error_code, phase.message),
                         ("failed", "ram", RAM_PAYLOAD["detail"]))
        expected = {"hard": "hard", "error": "sandbox_error", "refused": "sandbox_refused",
                    "stopped": "sandbox_stopped", "no_user": "sandbox_error"}
        for reason, code in expected.items():
            router.job_failed("job-3", SandboxUnavailable(reason))
            self.assertEqual(router.job_phase("job-3").error_code, code)
            self.assertIn(code, contract.KALI_EXEC_ERROR_CODES)
        self.assertEqual(router.job_phase("job-3").message, contract.SANDBOX_UNAVAILABLE_ERROR)
        router.job_failed("job-3", SandboxUnavailable("refused"))
        self.assertEqual(router.job_phase("job-3").message, contract.SANDBOX_REFUSED)
        with self.assertRaises(ValueError):
            router.set_job_phase("job-1", "done")
        router.forget_job("job-1")
        self.assertEqual(router.job_sandbox_user("job-1"), "")
        self.assertIsNone(router.job_phase("job-1"))

    async def test_job_map_is_bounded(self):
        with mock.patch.object(router, "JOBS_MAX", 3):
            for i in range(5):
                router.note_job(f"job-{i}", "bob")
            self.assertEqual(router.jobs_by_sandbox_user(), {"bob": ["job-2", "job-3", "job-4"]})


class TestMessages(unittest.TestCase):

    def test_unavailable_message_for_the_model(self):
        cases = {"ram": contract.SANDBOX_UNAVAILABLE_RAM, "hard": contract.SANDBOX_UNAVAILABLE_HARD,
                 "error": contract.SANDBOX_UNAVAILABLE_ERROR, "no_user": contract.SANDBOX_UNAVAILABLE_ERROR,
                 "refused": contract.SANDBOX_REFUSED, "stopped": contract.SANDBOX_STOPPED}
        for reason, text in cases.items():
            self.assertEqual(router.unavailable_message(SandboxUnavailable(reason)), text)

    def test_reason_must_be_a_contract_reason(self):
        with self.assertRaises(ValueError):
            SandboxUnavailable("starting")


class TestKaliAuth(unittest.TestCase):

    def test_kali_auth_headers_for(self):
        token = secrets.token_urlsafe(32)
        self.assertEqual(kali_auth.kali_auth_headers_for(token), {"Authorization": f"Bearer {token}"})
        for bad in ("", None, "a b", "tok\r\nX-Evil: 1", "tök"):
            self.assertEqual(kali_auth.kali_auth_headers_for(bad), {})

    def test_shared_headers_unchanged(self):
        with mock.patch.dict(os.environ, {"MCP_AUTH_TOKEN": SHARED_TOKEN}):
            self.assertEqual(kali_auth.kali_auth_headers(), {"Authorization": f"Bearer {SHARED_TOKEN}"})
        with mock.patch.dict(os.environ, {"MCP_AUTH_TOKEN": ""}):
            self.assertEqual(kali_auth.kali_auth_headers(), {})


if __name__ == "__main__":
    unittest.main()
