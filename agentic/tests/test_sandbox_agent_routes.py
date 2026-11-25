"""The agent's per-user sandbox routes and hints (group 1, S11, B.12, B.16).

  - POST /sandboxes/{user_id}/drop forgets the person's clients and handles;
  - POST /sandboxes/{user_id}/tunnel pushes the person's own config to their own view
    with the instance's tunnel token, and an empty config stops every own-view
    instance's tunnels (draining ones too) without starting anything or counting as use;
  - GET /tunnel-status needs the master key and `?user_id=`, reports that person's
    current instance only, and never starts a sandbox;
  - the emergency stop asks every sandbox to stop the agent's runs BEFORE it cancels
    them (D22);
  - /mcp/test refuses a draft that names a sandbox address (R1-F6);
  - the agent's shutdown cancels the router's lease renewals;
  - the LHOST/LPORT hints read the run's own sandbox, never another address.

Runs in the agent image: ./agentic/run_tests.sh tests/test_sandbox_agent_routes.py
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

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

MASTER = "sandbox-agent-routes-master-key-0123456789"

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
NGROK_TOKEN = "2abcNGROKsecretTOKEN0123456789"
CHISEL_AUTH = "user:chisel-secret-pass"


def _dep_names(path, method):
    for r in api.app.routes:
        if getattr(r, "path", "") == path and method in (getattr(r, "methods", set()) or set()):
            return [getattr(d.dependency, "__name__", "") for d in r.dependencies]
    return None


class _Base(unittest.TestCase):
    def setUp(self):
        self.fleet = Fleet()
        # The old shared container still answers at its old address: nothing may ask it.
        self.fleet.shared.running = True
        self.addCleanup(lambda: self.assertEqual(self.fleet.shared.requests, [], "the old shared container was asked"))
        router._reset()
        transport = self.fleet.transport()
        real_client = httpx.AsyncClient

        def client(*a, **k):
            k["transport"] = k.get("transport") or transport
            return real_client(*a, **k)

        patches = [
            mock.patch.dict(os.environ, {"INTERNAL_API_KEY": MASTER}),
            mock.patch.object(router, "_transport", transport),
            mock.patch.object(api, "_sandbox_transport", transport),
            mock.patch.dict(router.INTERNAL_HEADERS, {"X-Internal-Key": "test-internal-key"}),
            mock.patch.object(router, "WEBAPP_API_URL", WEBAPP),
            # sandbox_runs opens its own clients: route them to the same sandboxes.
            mock.patch("httpx.AsyncClient", client),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(router._reset)
        self.addCleanup(sandbox_runs._reset)
        self.client = TestClient(api.app)

    def tunnel_calls(self, box):
        return [(path, headers.get("authorization"), body) for _m, path, headers, body in box.requests
                if path.startswith("/tunnel/")]


# =============================================================================
# drop
# =============================================================================

class TheDropRoute(_Base):
    def test_drop_forgets_the_persons_handles(self):
        self.fleet.add("bob")

        async def scenario():
            handle = await router.acquire("bob", project_id="p1", kind="exec")
            await api.drop_sandbox_clients("bob")
            stale = handle.stale
            await router.release(handle)
            await router._shutdown()
            return stale

        self.assertTrue(asyncio.run(scenario()))

    def test_a_drop_of_one_view_leaves_the_other_views_handles(self):
        """An admin's emergency stop of a member's act_as view (G-18): the member's own
        handles stay usable, so their own background jobs do not end."""
        self.fleet.add("bob")
        self.fleet.add("bob", contract.VIEW_ACT_AS)

        async def scenario():
            own = await router.acquire("bob", project_id="p1", kind="exec", view=contract.VIEW_OWN)
            with router.for_person("bob", acting=True):
                acting = await router.acquire("bob", project_id="p1", kind="exec")
            since = time.monotonic()
            await api.drop_sandbox_clients("bob", view=contract.VIEW_ACT_AS)
            out = (own.stale, own.stop_requested, acting.stale, acting.stop_requested,
                   router.stop_requested_since("bob", since, view=contract.VIEW_OWN),
                   router.stop_requested_since("bob", since, view=contract.VIEW_ACT_AS))
            await router.release(own)
            await router.release(acting)
            await router._shutdown()
            return out

        self.assertEqual(asyncio.run(scenario()), (False, False, True, True, False, True))

    def test_a_drop_names_a_view_of_the_contract(self):
        self.assertEqual(self.client.post("/sandboxes/bob/drop?view=act_as", headers=KEY).status_code, 200)
        self.assertEqual(self.client.post("/sandboxes/bob/drop?view=both", headers=KEY).status_code, 400)

    def test_drop_needs_the_master_key_and_a_user_id(self):
        self.assertIn("require_configured_master_auth", _dep_names(contract.AGENT_ROUTE_DROP, "POST"))
        self.assertEqual(self.client.post("/sandboxes/bob/drop").status_code, 401)
        self.assertEqual(self.client.post("/sandboxes/bob/drop", headers=KEY).status_code, 200)
        self.assertEqual(self.client.post("/sandboxes/a%20b/drop", headers=KEY).status_code, 400)


# =============================================================================
# the tunnel push
# =============================================================================

class TheTunnelPush(_Base):
    def push(self, user, body, headers=KEY):
        return self.client.post(f"/sandboxes/{user}/tunnel", json=body, headers=headers)

    def test_a_push_uses_the_tunnel_token_and_the_persons_own_handle(self):
        bob = self.fleet.add("bob")
        acting = self.fleet.add("bob", contract.VIEW_ACT_AS)
        alice = self.fleet.add("alice")
        config = {"ngrokAuthtoken": NGROK_TOKEN, "chiselServerUrl": None, "chiselAuth": None}
        with mock.patch.object(api.sandbox_hold, "note_tunnel") as noted:
            resp = self.push("bob", config)
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertEqual(resp.json(), {"ok": True, "ngrok": True, "chisel": False})
        self.assertNotIn(NGROK_TOKEN, resp.text)
        [(path, bearer, body)] = self.tunnel_calls(bob)
        self.assertEqual(path, "/tunnel/configure")
        self.assertEqual(bearer, f"Bearer {bob.tunnel_token}")
        self.assertEqual(body["ngrokAuthtoken"], NGROK_TOKEN)
        self.assertEqual(self.tunnel_calls(acting) + self.tunnel_calls(alice), [])
        self.assertEqual([(e["userId"], e.get("actingAs")) for e in self.fleet.ensures()], [("bob", None)])
        self.assertEqual([lease["kind"] for lease in self.fleet.leases()], ["interact"])
        self.assertEqual(len(self.fleet.releases()), 1, "the push's lease is short")
        [handle] = noted.call_args.args
        self.assertEqual((handle.user_id, handle.view, handle.instance), ("bob", "own", bob.instance))

    def test_an_empty_config_stops_every_own_instance_and_starts_nothing(self):
        current = self.fleet.add("bob")
        draining = self.fleet.add("bob", state="draining")
        acting = self.fleet.add("bob", contract.VIEW_ACT_AS)
        alice = self.fleet.add("alice")
        resp = self.push("bob", {"ngrokAuthtoken": "", "chiselServerUrl": None, "chiselAuth": None})
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertEqual(resp.json()["stopped"], 2)
        for box in (current, draining):
            [(path, bearer, body)] = self.tunnel_calls(box)
            self.assertEqual(path, "/tunnel/configure")
            self.assertEqual(body, {"ngrokAuthtoken": "", "chiselServerUrl": "", "chiselAuth": ""})
            # The list carries no tunnel token: the instance's own MCP token stops it.
            self.assertEqual(bearer, f"Bearer {box.token}")
        self.assertEqual(self.tunnel_calls(acting) + self.tunnel_calls(alice), [])
        self.assertEqual(self.fleet.ensures(), [], "a stop never starts a sandbox")
        self.assertEqual(self.fleet.leases(), [], "a stop takes no lease, so it is no use")

    def test_an_empty_config_with_no_sandbox_is_a_no_op(self):
        resp = self.push("bob", {})
        self.assertEqual(resp.json(), {"ok": True, "stopped": 0})
        self.assertEqual(self.fleet.ensures(), [])

    def test_a_stop_one_instance_refuses_is_reported(self):
        box = self.fleet.add("bob")
        box.answer = lambda request: httpx.Response(500, json={"error": "boom"})
        resp = self.push("bob", {})
        self.assertEqual(resp.status_code, 502)
        self.assertEqual(resp.json()["unavailable"], [box.instance])

    def test_a_malformed_config_is_refused_and_never_echoed(self):
        self.fleet.add("bob")
        for body in ({"ngrokAuthtoken": NGROK_TOKEN * 200}, {"ngrokAuthtoken": 7},
                     {"ngrokAuthtoken": NGROK_TOKEN, "extra": 1}, ["x"]):
            resp = self.push("bob", body)
            self.assertEqual(resp.status_code, 400, body)
            self.assertNotIn(NGROK_TOKEN, resp.text)
        self.assertEqual(self.fleet.ensures(), [])

    def test_a_refused_person_gets_no_push(self):
        self.fleet.ensure_answer = (403, {"code": contract.ERR_USER_REFUSED})
        resp = self.push("bob", {"chiselServerUrl": "https://vps.example:8443", "chiselAuth": CHISEL_AUTH})
        self.assertEqual(resp.status_code, 403)
        self.assertNotIn(CHISEL_AUTH, resp.text)

    def test_the_push_needs_the_master_key(self):
        self.assertIn("require_configured_master_auth", _dep_names(contract.AGENT_ROUTE_TUNNEL, "POST"))
        self.assertEqual(self.push("bob", {}, headers={}).status_code, 401)


class TheTunnelPushWithoutATunnelToken(_Base):
    def test_a_handle_without_a_tunnel_token_pushes_nothing(self):
        def no_tunnel_token(body):
            box = self.fleet.current(body["userId"]) or self.fleet.add(body["userId"])
            return 200, {"user_id": box.person, "view": box.view, "instance": box.instance,
                         "host": box.host, "token": box.token, "tunnel_token": "",
                         "ports": dict(contract.PORTS), "reverse_port": 4444, "projects": box.projects,
                         "state": "running", "fresh": False, "stop_at": 2e10, "stop_reason": None,
                         "warn": False}

        self.fleet.ensure_answer = no_tunnel_token
        resp = self.client.post("/sandboxes/bob/tunnel", json={"ngrokAuthtoken": NGROK_TOKEN}, headers=KEY)
        self.assertEqual(resp.status_code, 502)
        self.assertEqual(resp.json()["code"], "tunnel_push_failed")
        self.assertEqual(self.tunnel_calls(self.fleet.current("bob")), [])
        self.assertNotIn(NGROK_TOKEN, resp.text)


# =============================================================================
# /tunnel-status
# =============================================================================

class TheTunnelStatus(_Base):
    def status(self, query="?user_id=bob", headers=KEY):
        return self.client.get(f"/tunnel-status{query}", headers=headers)

    def test_it_needs_the_key_and_the_person(self):
        self.fleet.add("bob")
        self.assertEqual(self.status("", headers={}).status_code, 401)
        self.assertEqual(self.status(headers={}).status_code, 401)
        self.assertEqual(self.status("").status_code, 400)
        self.assertEqual(self.status("?user_id=../x").status_code, 400)

    def test_an_unauthenticated_caller_never_reaches_the_gateway(self):
        """Review finding 3: a request without the key is refused before the webapp (and
        the orchestrator behind it) is asked anything."""
        self.fleet.add("bob")
        self.status(headers=KEY)
        before = len(self.fleet.gateway_requests)
        for headers in ({}, {"x-internal-key": "wrong"}):
            for query in ("", "?user_id=bob"):
                for _ in range(5):
                    self.assertEqual(self.status(query, headers=headers).status_code, 401)
        self.assertEqual(len(self.fleet.gateway_requests), before)

    def test_no_running_sandbox_reads_inactive_and_starts_none(self):
        resp = self.status()
        self.assertEqual(resp.json(), {"ngrok": {"active": False, "status": "off"},
                                       "chisel": {"active": False, "status": "off"}})
        self.assertEqual(self.fleet.ensures(), [], "a status read never ensures")
        self.assertEqual(self.fleet.leases(), [])

    def test_the_persons_current_instance_tunnel(self):
        bob = self.fleet.add("bob")
        bob.tunnel = {"ngrok": {"active": True, "pid": 7, "host": "0.tcp.ngrok.io", "port": 12345},
                      "chisel": {"active": True, "pid": 8, "host": "vps.example"}}
        resp = self.status()
        self.assertEqual(resp.json(), {
            "ngrok": {"active": True, "host": "0.tcp.ngrok.io", "port": 12345},
            "chisel": {"active": True, "host": "vps.example", "port": 4444}})
        [(path, bearer, _b)] = self.tunnel_calls(bob)
        self.assertEqual((path, bearer), ("/tunnel/status", f"Bearer {bob.token}"))
        self.assertEqual(self.fleet.ensures(), [])

    def test_never_another_persons_tunnel(self):
        bob = self.fleet.add("bob")
        bob.tunnel = {"ngrok": {"active": True, "host": "0.tcp.ngrok.io", "port": 12345}, "chisel": {}}
        acting = self.fleet.add("alice", contract.VIEW_ACT_AS)
        acting.tunnel = bob.tunnel
        draining = self.fleet.add("alice", state="draining")
        draining.tunnel = bob.tunnel
        resp = self.status("?user_id=alice")
        self.assertEqual(resp.json(), {"ngrok": {"active": False, "status": "off"},
                                       "chisel": {"active": False, "status": "off"}})
        self.assertEqual(self.tunnel_calls(bob) + self.tunnel_calls(acting) + self.tunnel_calls(draining), [])

    def test_active_is_the_process_and_status_says_whether_it_forwards(self):
        """The webapp reads `active` as "the tunnel process runs" (personTunnelRuns): a
        chisel still connecting or refused is active, with its status and no endpoint;
        only "on" carries host and port. The manager's reason reaches it printable and short."""
        bob = self.fleet.add("bob")
        bob.tunnel = {"ngrok": {"active": True, "status": "connecting"},
                      "chisel": {"active": True, "status": "error: remote port 4444 refused\x1b[31m" + "x" * 400,
                                 "host": "vps.example"}}
        answer = self.status().json()
        self.assertEqual(answer["ngrok"], {"active": True, "status": "connecting"})
        self.assertEqual(answer["chisel"]["active"], True)
        self.assertNotIn("host", answer["chisel"])
        self.assertTrue(answer["chisel"]["status"].startswith("error: remote port 4444 refused[31m"))
        self.assertNotIn("\x1b", answer["chisel"]["status"])
        self.assertLessEqual(len(answer["chisel"]["status"]), len("error: ") + 160)
        bob.tunnel = {"ngrok": {"active": True, "status": "on", "host": "0.tcp.ngrok.io", "port": 12345},
                      "chisel": {"active": False, "status": "off"}}
        self.assertEqual(self.status().json(), {
            "ngrok": {"active": True, "status": "on", "host": "0.tcp.ngrok.io", "port": 12345},
            "chisel": {"active": False, "status": "off"}})
        bob.tunnel = {"ngrok": {"active": True, "status": "on", "host": "<script>", "port": 1},
                      "chisel": {"active": True, "status": "rm -rf /"}}
        self.assertEqual(self.status().json(), {
            "ngrok": {"active": True, "status": "error: unreadable endpoint"},
            "chisel": {"active": True, "status": "error: unreadable status"}})

    def test_a_tunnel_answer_outside_its_shape_reads_inactive(self):
        bob = self.fleet.add("bob")
        bob.tunnel = {"ngrok": {"active": True, "host": "evil.example\r\nX: y", "port": 99999},
                      "chisel": {"active": True, "host": "<script>"}}
        self.assertEqual(self.status().json(),
                         {"ngrok": {"active": False}, "chisel": {"active": False}})


class TheTunnelStatusWithoutAKey(_Base):
    def test_a_fresh_agent_checks_the_key_before_asking_anything(self):
        # No answer has arrived since the agent started: still refused before the gateway
        # is asked, and the old shared tunnel is never read (_Base checks the container).
        resp = self.client.get("/tunnel-status")
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(self.fleet.gateway_requests, [])


# =============================================================================
# the emergency stop
# =============================================================================

class TheEmergencyStop(_Base):
    def test_the_sandboxes_are_asked_before_the_runs_are_cancelled(self):
        order = []

        async def stop_all_runs():
            order.append("sandboxes")
            return {"sandboxes": 2, "asked": 2, "answered": 2, "unavailable": []}

        async def stop_all():
            order.append("runs")
            return 3

        manager = mock.Mock(stop_all=stop_all)
        with mock.patch.object(api.sandbox_runs, "stop_all_runs", stop_all_runs), \
                mock.patch.object(api, "ws_manager", manager):
            resp = self.client.post("/emergency-stop-all", headers=KEY)
        self.assertEqual(order, ["sandboxes", "runs"])
        self.assertEqual(resp.json(), {"stopped": 3, "navigator": 0, "jobs": 0})

    def test_the_emergency_stop_reaches_every_sandbox(self):
        alice, bob = self.fleet.add("alice"), self.fleet.add("bob")

        async def scenario():
            handles = await router.running_sandboxes()
            for handle in handles:
                sandbox_runs.note_run_sandbox(f"run-{handle.user_id}", handle)

            async def stop_all():
                return 0

            with mock.patch.object(api, "ws_manager", mock.Mock(stop_all=stop_all)):
                body = await api.emergency_stop_all()
            return handles, body

        handles, body = asyncio.run(scenario())
        self.assertEqual(len(handles), 2)
        for box in (alice, bob):
            stops = [(headers["authorization"], b) for _m, path, headers, b in box.requests
                     if path == sandbox_runs.STOP_PATH]
            self.assertEqual(stops, [(f"Bearer {box.token}", {"run": f"run-{box.person}"})])


# =============================================================================
# /mcp/test and the shutdown
# =============================================================================

class TheMcpTestRoute(_Base):
    def test_a_draft_on_the_sandbox_pool_is_refused_before_any_connection(self):
        with mock.patch("langchain_mcp_adapters.client.MultiServerMCPClient") as mcp_client:
            resp = self.client.post("/mcp/test", headers=KEY, json={
                "id": "pool-draft", "name": "Pool", "transport": "streamable_http",
                "url": "http://10.214.0.5:8015/mcp", "tools": []})
        body = resp.json()
        self.assertFalse(body["ok"])
        self.assertEqual(body["code"], "sandbox_address_refused")
        mcp_client.assert_not_called()


class TheShutdown(unittest.IsolatedAsyncioTestCase):
    async def test_the_lifespan_cancels_the_routers_lease_renewals(self):
        fleet = Fleet()
        fleet.add("bob")
        router._reset()

        class _Orchestrator:
            async def initialize(self):
                pass

            async def close(self):
                pass

        registry = mock.Mock()
        patches = [
            mock.patch.object(router, "_transport", fleet.transport()),
            mock.patch.dict(router.INTERNAL_HEADERS, {"X-Internal-Key": "test-internal-key"}),
            mock.patch.object(router, "WEBAPP_API_URL", WEBAPP),
            mock.patch.object(api, "check_single_worker"),
            mock.patch.object(api.os, "umask"),
            mock.patch.object(api, "AgentOrchestrator", _Orchestrator),
            mock.patch.object(api, "WebSocketManager", mock.Mock),
            mock.patch.object(api.job_runner, "get_registry", return_value=registry),
            mock.patch.object(api, "tradecraft_recover_on_boot", mock.AsyncMock()),
            mock.patch.object(api._ws_staging, "recover_swaps"),
            mock.patch.object(api._ws_staging, "sweep_all"),
            mock.patch.object(api._ws_upload_sessions, "sweep_idle_forever", mock.AsyncMock()),
            mock.patch.object(api.ws_job_emitter, "set_ws_manager"),
        ]
        for name in ("subscribe_sandbox_status", "unsubscribe_sandbox_status"):
            if hasattr(api, name):
                patches.append(mock.patch.object(api, name))
        if hasattr(api, "sandbox_hold"):
            patches += [mock.patch.object(api.sandbox_hold, "start"),
                        mock.patch.object(api.sandbox_hold, "stop", mock.AsyncMock())]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(router._reset)

        async with api.lifespan(api.app):
            handle = await router.acquire("bob", project_id="p1", kind="terminal")
            renewal = handle._renew_task
            self.assertFalse(renewal.done())
        self.assertTrue(renewal.done(), "the renewal outlived the agent's shutdown")


# =============================================================================
# the router's fixes (S05's review: draining; S11: a lease on a listed instance)
# =============================================================================

class TheRouterFixes(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.fleet = Fleet()
        router._reset()
        self._patches = [
            mock.patch.object(router, "_transport", self.fleet.transport()),
            mock.patch.dict(router.INTERNAL_HEADERS, {"X-Internal-Key": "test-internal-key"}),
            mock.patch.object(router, "WEBAPP_API_URL", WEBAPP),
        ]
        for p in self._patches:
            p.start()

    async def asyncTearDown(self):
        await router.shutdown()
        for p in reversed(self._patches):
            p.stop()
        router._reset()

    async def test_an_instance_that_drains_before_its_first_lease_is_ensured_again(self):
        """Handed an instance that turned draining (replaced while it started): the lease
        is refused with sandbox_draining and the router asks for the current one."""
        answers = iter([(409, {"code": contract.ERR_DRAINING})])
        real = self.fleet._gateway

        async def gateway(request):
            if request.url.path == contract.INTERNAL_ROUTE_LEASE:
                scripted = next(answers, None)
                if scripted is not None:
                    self.fleet.gateway_requests.append(("POST", request.url.path, json.loads(request.content)))
                    return httpx.Response(scripted[0], json=scripted[1])
            return await real(request)

        self.fleet._gateway = gateway
        handle = await router.acquire("bob", project_id="p1", kind="exec")
        self.assertEqual(len(self.fleet.ensures()), 2)
        self.assertEqual(len(self.fleet.leases()), 2)
        self.assertTrue(handle.usable)
        await router.release(handle)

    async def test_a_lease_on_a_listed_instance_ensures_nothing(self):
        bob = self.fleet.add("bob", state="draining")
        [listed] = await router.running_sandboxes()
        self.assertIsNone(await router.lease_listed(listed, "interact"),
                          "a draining instance's answer to a new lease id is honoured")
        bob.state = "running"
        self.fleet.lease_answer = None
        leased = await router.lease_listed(listed, "interact")
        self.assertIsNotNone(leased)
        self.assertEqual((leased.instance, leased.kind), (bob.instance, "interact"))
        await router.release(leased)
        self.assertEqual(self.fleet.ensures(), [])
        self.assertEqual([r["leaseId"] for r in self.fleet.releases()], [leased.lease_id])


# =============================================================================
# the LHOST/LPORT hints and the tunnel lookups (agentic/utils.py)
# =============================================================================

def _handle(person="bob", view=contract.VIEW_OWN, reverse_port=4444, tunnel_token="tun-token-0123456789abcdef"):
    instance = "a1b2c3"
    return router.SandboxHandle(
        user_id=person, view=view, instance=instance,
        host=contract.container_name(person, view, instance), token="mcp-token-0123456789abcdef",
        tunnel_token=tunnel_token, ports=contract.PORTS, reverse_port=reverse_port)


class TheTunnelLookups(unittest.IsolatedAsyncioTestCase):
    """A prompt is built on the event loop every run shares, and a sandbox's root sets the
    pace of its answers: building one never dials a sandbox. It reads the last status
    the agent got from the run's own sandbox, and a stale or missing one is refreshed
    in the background, bounded (review finding 1)."""

    async def asyncSetUp(self):
        router._reset()
        utils._forget_all_tunnel_status()
        self.requests = []
        self.status = {"ngrok": {"active": True, "host": "0.tcp.ngrok.io", "port": 14444},
                       "chisel": {"active": False}}

        def handler(request):
            self.requests.append(request)
            return httpx.Response(200, json=self.status)

        self._patches = [
            mock.patch.object(utils, "_async_transport", httpx.MockTransport(handler)),
            mock.patch("requests.get", side_effect=AssertionError("today's shared address was dialled")),
        ]
        self.legacy = None
        for p in self._patches:
            started = p.start()
            if p is self._patches[1]:
                self.legacy = started

    async def asyncTearDown(self):
        await utils._settle_tunnel_refreshes()
        for p in reversed(self._patches):
            p.stop()
        utils._forget_all_tunnel_status()
        router._reset()

    async def test_ngrok_is_read_from_the_runs_sandbox_through_its_tunnel_manager(self):
        handle = _handle()
        with mock.patch.object(router, "current_handle", return_value=handle):
            self.assertIsNone(utils._query_ngrok_tunnel(), "the first build dials nothing")
            await utils._settle_tunnel_refreshes()
            info = utils._query_ngrok_tunnel()
        self.assertEqual((info["host"], info["port"]), ("0.tcp.ngrok.io", 14444))
        [request] = self.requests
        self.assertEqual((request.url.host, request.url.port, request.url.path),
                         (handle.host, contract.PORTS["tunnel"], "/tunnel/status"))
        self.assertEqual(request.headers["authorization"], f"Bearer {handle.tunnel_token}")
        self.assertEqual(request.headers["accept-encoding"], "identity")

    async def test_a_dripping_tunnel_manager_never_holds_the_event_loop(self):
        """Repro of the review: a listener on 8015 that drips its headers. The prompt comes
        back at once, the loop keeps ticking, and the background read ends within its
        bound."""
        async def drip(reader, writer):
            try:
                for byte in b"HTTP/1.1 200 OK\r\n":
                    writer.write(bytes([byte]))
                    await writer.drain()
                    await asyncio.sleep(1.0)
            except (ConnectionError, asyncio.CancelledError):
                pass
            finally:
                writer.close()

        server = await asyncio.start_server(drip, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        self.addAsyncCleanup(server.wait_closed)
        self.addCleanup(server.close)
        ticks = 0

        async def tick():
            nonlocal ticks
            while True:
                await asyncio.sleep(0.05)
                ticks += 1

        ticker = asyncio.create_task(tick())
        settings = dict(TheReverseShellHints.SETTINGS, NGROK_TUNNEL_ENABLED=True)
        handle = _handle()
        with mock.patch.object(utils, "_async_transport", None), \
                mock.patch.object(router, "current_handle", return_value=handle), \
                mock.patch.object(router, "url_for",
                                  side_effect=lambda h, name, path="": f"http://127.0.0.1:{port}{path}"), \
                mock.patch.object(utils, "get_setting", side_effect=lambda k, d=None: settings.get(k, d)):
            started = time.monotonic()
            utils.get_session_config_prompt()
            self.assertLess(time.monotonic() - started, 0.5, "building the prompt dialled the sandbox")
            await asyncio.sleep(0)
            ticks_before = ticks
            await asyncio.wait_for(utils._settle_tunnel_refreshes(), timeout=utils._TUNNEL_READ_S + 2)
        elapsed = time.monotonic() - started
        ticker.cancel()
        self.assertLess(elapsed, utils._TUNNEL_READ_S + 2)
        self.assertGreater(ticks - ticks_before, 20, "the loop stopped while the sandbox dripped")

    async def test_a_per_user_run_without_a_sandbox_reads_no_tunnel_anywhere(self):
        with mock.patch.object(router, "current_handle", return_value=None):
            self.assertIsNone(utils._query_ngrok_tunnel())
            self.assertIsNone(utils._query_chisel_tunnel())
        await utils._settle_tunnel_refreshes()
        self.assertEqual(self.requests, [])
        self.legacy.assert_not_called()

    async def test_an_act_as_sandbox_has_no_tunnel(self):
        handle = _handle(view=contract.VIEW_ACT_AS)
        with mock.patch.object(router, "current_handle", return_value=handle):
            self.assertIsNone(utils._query_ngrok_tunnel())
            self.assertIsNone(utils._query_chisel_tunnel())
        await utils._settle_tunnel_refreshes()
        self.assertEqual(self.requests, [])

    async def test_chisel_is_read_from_the_runs_sandbox_through_its_tunnel_manager(self):
        """Chisel is ACTIVE when the sandbox says so (FU-15), never because the person's
        stored settings name a server: the webapp is not asked."""
        handle = _handle()
        self.status = {"ngrok": {"active": False},
                       "chisel": {"active": True, "status": "on", "host": "vps.example"}}
        with mock.patch.object(router, "current_handle", return_value=handle):
            self.assertIsNone(utils._query_chisel_tunnel(), "the first build dials nothing")
            await utils._settle_tunnel_refreshes()
            info = utils._query_chisel_tunnel()
        self.assertEqual(info, {"host": "vps.example", "port": 4444, "hostname": "vps.example"},
                         "chisel forwards the handler port only (tunnel_manager.py: R:4444)")
        self.legacy.assert_not_called()

    async def test_a_chisel_that_failed_to_connect_is_not_active(self):
        handle = _handle()
        self.status = {"chisel": {"active": True, "status": "error: remote port 4444 refused",
                                  "host": "vps.example"}}
        with mock.patch.object(router, "current_handle", return_value=handle):
            utils._query_chisel_tunnel()
            await utils._settle_tunnel_refreshes()
            self.assertIsNone(utils._query_chisel_tunnel())
        self.legacy.assert_not_called()


class TheReverseShellHints(unittest.TestCase):
    SETTINGS = {"LHOST": "", "LPORT": None, "BIND_PORT_ON_TARGET": None, "PAYLOAD_USE_HTTPS": False,
                "NGROK_TUNNEL_ENABLED": False, "CHISEL_TUNNEL_ENABLED": False}

    def setUp(self):
        router._reset()
        self.addCleanup(router._reset)
        patches = [mock.patch.object(utils, "get_setting", side_effect=lambda k, d=None: self.SETTINGS.get(k, d)),
                   mock.patch.dict(os.environ, {"HOST_LAN_IP": "192.168.1.50"})]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def prompt(self, handle):
        with mock.patch.object(router, "current_handle", return_value=handle):
            return utils.get_session_config_prompt()

    def test_a_pool_port_is_the_published_reverse_port(self):
        text = self.prompt(_handle(reverse_port=45002))
        self.assertIn("45002", text)
        self.assertIn("192.168.1.50", text)
        self.assertNotIn("from the host into the container", text)

    def test_without_a_pool_or_tunnel_no_direct_reverse_shell_is_offered(self):
        text = self.prompt(_handle())
        self.assertNotIn("192.168.1.50", text)
        self.assertNotIn("from the host into the container", text)
        self.assertIn("tunnel", text.lower())

    def test_chisel_tunnels_the_handler_port_only(self):
        # The tunnel manager maps R:4444 alone: no web-delivery port is offered (x).
        settings = dict(self.SETTINGS, CHISEL_TUNNEL_ENABLED=True)
        chisel = {"host": "vps.example", "port": 4444, "hostname": "vps.example"}
        with mock.patch.object(utils, "get_setting", side_effect=lambda k, d=None: settings.get(k, d)), \
                mock.patch.object(utils, "_query_chisel_tunnel", return_value=chisel):
            text = self.prompt(_handle())
        self.assertIn("Chisel Tunnel: ACTIVE", text)
        self.assertIn("chisel forwards only `vps.example:4444`", text)
        self.assertNotIn("8080", text)
        # SRVPORT is named only to forbid it (one reachable port): never given a value.
        self.assertNotRegex(text, r"set SRVPORT\s+\S")
        self.assertIn("Never set SRVHOST/SRVPORT", text)
        self.assertNotIn("kali-sandbox:", text)

    def test_a_run_without_a_sandbox_yet_gets_no_lan_ip_hint(self):
        # A sandbox not known yet is not one without a port (D-E): no LAN IP, no question.
        text = self.prompt(None)
        self.assertNotIn("192.168.1.50", text)
        self.assertNotIn("from the host into the container", text)
        self.assertIn("not known yet", text)
        self.assertNotIn("NO DIRECT REVERSE SHELL", text)



# =============================================================================
# The emergency stops end the Kali background jobs too
# =============================================================================

class TheEmergencyStopsEndTheJobs(_Base):
    """A job's sandbox stops after these routes answer: its job must end now, or it would
    find the sandbox gone and run its command again in a new one."""

    def setUp(self):
        super().setUp()
        self.registry = mock.Mock()
        self.registry.cancel_sandbox_jobs = mock.AsyncMock(return_value=2)
        for p in (mock.patch.object(api.job_runner, "get_registry", return_value=self.registry),
                  mock.patch.object(api.sandbox_runs, "stop_all_runs", mock.AsyncMock(return_value={})),
                  mock.patch.object(api, "ws_manager", None)):
            p.start()
            self.addCleanup(p.stop)

    def test_stop_all_cancels_every_persons_jobs_and_marks_every_sandbox(self):
        with mock.patch.object(router, "note_stop_requested_all") as marked:
            resp = self.client.post("/emergency-stop-all", headers=KEY)
        self.assertEqual(resp.json().get("jobs"), 2)
        self.registry.cancel_sandbox_jobs.assert_awaited_once_with(None)
        marked.assert_called_once_with()

    def test_a_persons_stop_cancels_their_jobs_only(self):
        with mock.patch.object(router, "note_stop_requested") as marked:
            resp = self.client.post("/agent-sessions/stop-for", headers=KEY, json={"user_id": "bob"})
        self.assertEqual(resp.json().get("jobs"), 2)
        self.registry.cancel_sandbox_jobs.assert_awaited_once_with("bob")
        marked.assert_called_once_with("bob")

    def test_a_stop_of_some_projects_leaves_the_jobs(self):
        """An access loss on one project reconciles the sandbox instead of stopping it."""
        with mock.patch.object(router, "note_stop_requested") as marked:
            resp = self.client.post("/agent-sessions/stop-for", headers=KEY,
                                    json={"user_id": "bob", "project_ids": ["p1"]})
        self.assertEqual(resp.json().get("jobs"), 0)
        self.registry.cancel_sandbox_jobs.assert_not_awaited()
        marked.assert_not_called()

    def test_a_failing_cancel_never_fails_the_stop(self):
        self.registry.cancel_sandbox_jobs = mock.AsyncMock(side_effect=RuntimeError("boom"))
        resp = self.client.post("/emergency-stop-all", headers=KEY)
        self.assertEqual(resp.json().get("jobs"), 0)


# =============================================================================
# The drawer's job routes, with the viewer named
# =============================================================================

class TheDrawerJobRoutes(_Base):

    def setUp(self):
        super().setUp()
        self.registry = mock.Mock()
        self.registry.list_async = mock.AsyncMock(return_value=[
            {"job_id": "a" * 32, "owner_user": "alice"}, {"job_id": "b" * 32, "owner_user": "bob"},
            {"job_id": "c" * 32}])
        self.registry.status = mock.Mock(return_value={"job_id": "a" * 32, "owner_user": "alice"})
        self.registry.cancel = mock.AsyncMock(return_value={"status": "cancelled"})
        p = mock.patch.object(api.job_runner, "get_registry", return_value=self.registry)
        p.start()
        self.addCleanup(p.stop)

    def test_the_list_leaves_out_another_persons_jobs(self):
        resp = self.client.get("/workspace/jobs", headers=KEY, params={"projectId": "p1", "userId": "bob"})
        self.assertEqual([j["job_id"] for j in resp.json()["jobs"]], ["b" * 32, "c" * 32])

    def test_without_a_viewer_the_list_is_the_projects(self):
        resp = self.client.get("/workspace/jobs", headers=KEY, params={"projectId": "p1"})
        self.assertEqual(len(resp.json()["jobs"]), 3)

    def test_another_persons_job_cannot_be_cancelled(self):
        resp = self.client.post(f"/workspace/jobs/{'a' * 32}/cancel", headers=KEY,
                                params={"projectId": "p1", "userId": "bob"})
        self.assertIn("unknown job", resp.json().get("error", ""))
        self.registry.cancel.assert_not_awaited()
        resp = self.client.post(f"/workspace/jobs/{'a' * 32}/cancel", headers=KEY,
                                params={"projectId": "p1", "userId": "alice"})
        self.assertEqual(resp.json(), {"status": "cancelled"})


if __name__ == "__main__":
    unittest.main()
