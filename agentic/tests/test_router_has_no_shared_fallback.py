"""
No path of the agent's sandbox router leads to a shared Kali container (group 1, S20).

The shared `kali-sandbox` service, its fixed addresses and its one MCP_AUTH_TOKEN are
gone, and so is the switch that chose it. Whatever the gateway answers (nothing yet, an
outage, an error, an answer in an old shape that names `shared`), the router hands out
only the person's own per-user container, with that instance's own token, or refuses.
The compose variables that once named the shared container are set in every test, so a
path that still read them would show.

Run: ./agentic/run_tests.sh tests/test_router_has_no_shared_fallback.py
"""
import inspect
import json
import os
import secrets
import sys
import unittest
from dataclasses import fields
from pathlib import Path
from unittest import mock

_AGENTIC_DIR = Path(__file__).resolve().parents[1]
if str(_AGENTIC_DIR) not in sys.path:
    sys.path.insert(0, str(_AGENTIC_DIR))

import httpx  # noqa: E402

import kali_auth  # noqa: E402
import sandbox_contract as contract  # noqa: E402
import sandbox_router as router  # noqa: E402
import sandbox_runs  # noqa: E402
from sandbox_router import SandboxUnavailable  # noqa: E402

OLD_TOKEN = "old-shared-mcp-token-0123456789abcdef"
#: What compose gave the agent while the shared container existed.
OLD_ENV = {
    "MCP_NETWORK_RECON_URL": "http://kali-sandbox:8000/sse",
    "MCP_NUCLEI_URL": "http://kali-sandbox:8002/sse",
    "MCP_NMAP_URL": "http://kali-sandbox:8004/sse",
    "MCP_METASPLOIT_URL": "http://kali-sandbox:8003/sse",
    "MCP_PLAYWRIGHT_URL": "http://kali-sandbox:8005/sse",
    "MCP_METASPLOIT_PROGRESS_URL": "http://kali-sandbox:8013/progress",
    "MCP_HYDRA_PROGRESS_URL": "http://kali-sandbox:8014/progress",
    "KALI_TERMINAL_WS_URL": "ws://kali-sandbox:8016",
    "MCP_AUTH_TOKEN": OLD_TOKEN,
}
SHARED_MARKERS = ("kali-sandbox:", "host.docker.internal", OLD_TOKEN)


class Gateway:
    """The webapp's internal sandbox routes, answering without any mode (S20)."""

    def __init__(self):
        self.requests = []
        self.override = None    # (status, json) for every ensure and list when set
        self.raises = None
        self.cold = False
        self.instances = {}

    def handler(self, request):
        body = json.loads(request.content) if request.content else None
        self.requests.append((request.url.path, body, dict(request.headers)))
        if self.raises is not None:
            raise self.raises(request)
        path = request.url.path
        if self.override is not None and path in (contract.INTERNAL_ROUTE_ENSURE, contract.INTERNAL_ROUTE_LIST):
            status, data = self.override
            return httpx.Response(status, json=data)
        if path == contract.INTERNAL_ROUTE_ENSURE:
            person = body["userId"]
            view = contract.VIEW_ACT_AS if body.get("actingAs") else contract.VIEW_OWN
            inst = self.instances.setdefault((person, view), {
                "instance": contract.new_instance(), "token": secrets.token_urlsafe(32),
                "tunnel_token": secrets.token_urlsafe(32)})
            if self.cold and not body.get("wait"):
                self.cold = False
                return httpx.Response(202, json={"state": "starting", "instance": inst["instance"],
                                                 "fresh": True})
            return httpx.Response(200, json={
                "user_id": person, "view": view, "instance": inst["instance"],
                "host": contract.container_name(person, view, inst["instance"]),
                "token": inst["token"], "tunnel_token": inst["tunnel_token"],
                "ports": dict(contract.PORTS), "reverse_port": 4444, "projects": ["p1"],
                "state": "running", "fresh": False, "stop_at": 2e10, "stop_reason": None,
                "warn": False})
        if path == contract.INTERNAL_ROUTE_LEASE:
            return httpx.Response(200, json={"expires_at": 1e10, "state": "running",
                                             "stop_at": 2e10, "warn": False})
        if path == contract.INTERNAL_ROUTE_RELEASE:
            return httpx.Response(204)
        if path == contract.INTERNAL_ROUTE_LIST:
            return httpx.Response(200, json={"sandboxes": [
                {"user_id": person, "view": view, "instance": inst["instance"],
                 "host": contract.container_name(person, view, inst["instance"]),
                 "token": inst["token"], "state": "running"}
                for (person, view), inst in self.instances.items()]})
        return httpx.Response(404)


def _refused(request):
    return httpx.ConnectError("connection refused", request=request)


def _slow(request):
    return httpx.ReadTimeout("slow", request=request)


class NoSharedFallbackTest(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        self.gateway = Gateway()
        router._reset()
        self._patches = [
            mock.patch.object(router, "_transport", httpx.MockTransport(self.gateway.handler)),
            mock.patch.dict(router.INTERNAL_HEADERS, {"X-Internal-Key": "test-internal-key"}),
            mock.patch.object(router, "WEBAPP_API_URL", "http://webapp.test:3000"),
            mock.patch.dict(os.environ, OLD_ENV),
        ]
        for p in self._patches:
            p.start()

    async def asyncTearDown(self):
        await router.shutdown()
        for p in reversed(self._patches):
            p.stop()
        router._reset()

    def assert_own(self, handle, person="alice", view=contract.VIEW_OWN):
        self.assertEqual(handle.user_id, person)
        self.assertEqual(handle.view, view)
        self.assertEqual(handle.host, contract.container_name(person, view, handle.instance))
        self.assertEqual(handle.token, self.gateway.instances[(person, view)]["token"])
        self.assertNotEqual(handle.token, OLD_TOKEN)

    async def refused(self, reason, person="alice"):
        with self.assertRaises(SandboxUnavailable) as caught:
            handle = await router.acquire(person, project_id="p1", kind="run")
            await router.release(handle)
        self.assertEqual(caught.exception.reason, reason)

    # --- what the gateway answers ------------------------------------------------

    async def test_an_answer_without_a_mode_is_the_persons_own_sandbox(self):
        handle = await router.acquire("alice", project_id="p1", kind="run")
        try:
            self.assert_own(handle)
            for port in ("network_recon", "sessions", "hydra", "terminal", "tunnel", "ngrok_api"):
                url = router.url_for(handle, port, "/x")
                self.assertTrue(url.split("://", 1)[1].startswith(handle.host + ":"), url)
                self.assertFalse(any(m in url for m in SHARED_MARKERS), url)
            self.assertEqual(router.headers_for(handle), {"Authorization": f"Bearer {handle.token}"})
            self.assertEqual(router.headers_for(handle, "tunnel"),
                             {"Authorization": f"Bearer {handle.tunnel_token}"})
        finally:
            await router.release(handle)

    async def test_a_cold_start_without_a_mode_starts_then_runs(self):
        self.gateway.cold = True
        handle = await router.acquire("alice", project_id="p1", kind="run")
        try:
            self.assert_own(handle)
            self.assertTrue(handle.fresh)
        finally:
            await router.release(handle)

    async def test_an_old_shared_answer_is_refused(self):
        # An old webapp or orchestrator naming the shared container: never served.
        for answer in ({"mode": "shared"}, {"mode": "shared", "sandboxes": []}):
            self.gateway.override = (200, answer)
            await self.refused("error")

    async def test_outages_and_odd_answers_are_refused_before_any_answer(self):
        cases = [("raises", _refused), ("raises", _slow),
                 ("answer", (404, {})), ("answer", (500, {})), ("answer", (401, {})),
                 ("answer", (503, {"code": "orchestrator_unavailable"})),
                 ("answer", (200, {})), ("answer", (200, {"state": "running"})),
                 ("answer", (202, {"state": "starting", "instance": "../x"})), ("answer", (418, None))]
        for kind, value in cases:
            with self.subTest(case=value):
                router._reset()
                self.gateway.raises = value if kind == "raises" else None
                self.gateway.override = value if kind == "answer" else None
                await self.refused("error")

    async def test_an_outage_after_a_running_answer_is_still_refused(self):
        handle = await router.acquire("alice", project_id="p1", kind="run")
        await router.release(handle)
        self.gateway.raises = _refused
        await self.refused("error")
        await self.refused("error", person="bob")

    async def test_no_person_is_refused_whatever_the_gateway_says(self):
        for raises in (None, _refused):
            self.gateway.raises = raises
            for person in ("", "not a valid id", None):
                with self.subTest(person=person, raises=raises):
                    await self.refused("no_user", person=person)
        self.gateway.raises = None
        self.gateway.override = (200, {"mode": "shared", "sandboxes": []})
        await self.refused("no_user", person="")

    # --- the list and the running check ------------------------------------------

    async def test_the_list_without_a_mode_names_each_persons_own_container(self):
        for person in ("alice", "bob"):
            await router.release(await router.acquire(person, project_id="p1", kind="run"))
        listed = await router.running_sandboxes()
        self.assertEqual(sorted(h.user_id for h in listed), ["alice", "bob"])
        for handle in listed:
            self.assertEqual(handle.host, contract.container_name(handle.user_id, handle.view, handle.instance))
        self.assertTrue(await router.is_running("alice", contract.VIEW_OWN))
        self.assertFalse(await router.is_running("carol", contract.VIEW_OWN))

    async def test_the_list_never_reads_as_empty_on_an_outage_or_a_malformed_answer(self):
        for kind, value in (("raises", _refused), ("answer", (200, {})), ("answer", (200, {"sandboxes": "x"})),
                            ("answer", (503, {"code": "orchestrator_unavailable"}))):
            with self.subTest(case=value):
                router._reset()
                self.gateway.raises = value if kind == "raises" else None
                self.gateway.override = value if kind == "answer" else None
                with self.assertRaises(SandboxUnavailable) as caught:
                    await router.running_sandboxes()
                self.assertEqual(caught.exception.reason, "error")
                self.assertFalse(await router.is_running("alice", contract.VIEW_OWN))

    # --- clients, URLs, headers ---------------------------------------------------

    async def test_the_servers_are_the_handles_own_with_its_own_bearer(self):
        handle = await router.acquire("alice", project_id="p1", kind="run")
        try:
            configs = router.server_configs_for(handle)
            self.assertEqual(sorted(configs), ["metasploit", "network_recon", "nmap", "nuclei", "playwright"])
            for server_id, config in configs.items():
                self.assertEqual(config["url"], f"http://{handle.host}:{contract.PORTS[server_id]}/sse")
                text = json.dumps(config, default=repr)
                self.assertFalse(any(m in text for m in SHARED_MARKERS), text)
        finally:
            await router.release(handle)

    async def test_nothing_sent_to_the_gateway_carries_the_old_token(self):
        handle = await router.acquire("alice", project_id="p1", kind="run")
        await router.release(handle)
        self.assertTrue(self.gateway.requests)
        for _path, body, headers in self.gateway.requests:
            self.assertNotIn(OLD_TOKEN, json.dumps(body) + json.dumps(headers))

    async def test_a_released_or_stale_handle_never_serves_again(self):
        handle = await router.acquire("alice", project_id="p1", kind="run")
        await router.release(handle)
        with self.assertRaises(SandboxUnavailable) as caught:
            await router.client_for(handle)
        self.assertEqual(caught.exception.reason, "stopped")


class NoSharedNamesTest(unittest.TestCase):
    """The shared path's names are gone, so nothing can call them by mistake."""

    def test_the_router_has_no_mode_and_no_shared_handle(self):
        for name in ("_SHARED_BASES", "_shared_base", "_shared_handle", "_SHARED_CLIENT_KEY",
                     "_retired_shared", "_last_mode", "_note_mode", "current_mode", "ask_mode",
                     "_mode_without_person"):
            self.assertFalse(hasattr(router, name), name)
        self.assertNotIn("mode", {f.name for f in fields(router.SandboxHandle)})
        self.assertNotIn("mode", inspect.signature(router._reset).parameters)

    def test_no_helper_reads_the_old_token_or_address(self):
        self.assertFalse(hasattr(kali_auth, "kali_auth_headers"))
        self.assertFalse(hasattr(sandbox_runs, "stop_url"))
        for module in (router, kali_auth, sandbox_runs):
            source = inspect.getsource(module)
            for marker in ("kali-sandbox:", "host.docker.internal", 'environ.get("MCP_'):
                self.assertNotIn(marker, source, f"{module.__name__}: {marker}")

    def test_the_run_stop_never_falls_back_to_a_fixed_address(self):
        sandbox_runs._reset()
        with mock.patch.dict(os.environ, OLD_ENV):
            self.assertEqual(sandbox_runs._stop_targets("run-1"), [])


if __name__ == "__main__":
    unittest.main()
