"""Doubles for the agent's per-user sandbox routes (group 1, S11): the webapp's internal
sandbox routes and every sandbox's own HTTP servers (the session manager on 8013, the
tunnel manager on 8015), behind one ``httpx.MockTransport``. An old shared container
still answers at the ``kali-sandbox`` address with its old token, so a test can prove
nothing reaches it. Not a test file (no ``test_`` prefix).

A ``Fleet`` holds the instances; the gateway answers from it exactly as B.9/B.10 say
(``ensure`` 200/202, ``lease``, ``release``, ``list`` with the MCP token and no tunnel
token), and each instance answers only a request that carries its own bearer.
"""
from __future__ import annotations

import asyncio
import json
import secrets
from typing import Callable, Dict, List, Optional
from urllib.parse import parse_qs

import httpx

import sandbox_contract as contract

WEBAPP = "http://webapp.test:3000"
SHARED_HOST = "kali-sandbox"
SHARED_TOKEN = "shared-mcp-token-0123456789"

#: A governor sentence exactly as recon_orchestrator/admission_ledger.py words it.
RAM_SENTENCE = "not enough free memory to start a Kali sandbox now"
RAM_PAYLOAD = {
    "admitted": False, "limitType": "ram", "resource": "kali_sandbox",
    "current": 700_000_000, "ceiling": 8_000_000_000,
    "settingName": None, "detail": RAM_SENTENCE,
}
HARD_PAYLOAD = {
    "admitted": False, "limitType": "hard", "resource": "kali_sandbox",
    "current": 3, "ceiling": 3, "settingName": "KALI_SANDBOX_MAX_CONCURRENT",
    "detail": "3 of 3 Kali sandboxes allowed",
}


def _bearer(request: httpx.Request) -> str:
    header = request.headers.get("authorization", "")
    return header[7:] if header.lower().startswith("bearer ") else ""


class Sandbox:
    """One per-user instance: what its session manager and tunnel manager answer."""

    def __init__(self, person: str, view: str = contract.VIEW_OWN, *, state: str = "running",
                 projects=("p1", "p2")):
        self.person = person
        self.view = view
        self.instance = contract.new_instance()
        self.token = secrets.token_urlsafe(32)
        self.tunnel_token = secrets.token_urlsafe(32)
        self.state = state
        self.projects = list(projects)
        self.reverse_port = contract.DEFAULT_REVERSE_PORT
        self.sessions: Dict[str, list] = {"sessions": [], "jobs": [], "non_msf_sessions": []}
        self.tunnel: dict = {"ngrok": {"active": False}, "chisel": {"active": False}}
        self.requests: List[tuple] = []
        #: callable(request) -> httpx.Response (or an awaitable of one), overriding every answer.
        self.answer: Optional[Callable] = None
        self.hang = False
        self.starting = False
        self.leases: set = set()

    @property
    def host(self) -> str:
        return contract.container_name(self.person, self.view, self.instance)

    def bodies(self, path: str) -> list:
        return [body for _m, p, _h, body in self.requests if p == path]

    async def handle(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        self.requests.append((request.method, request.url.path, dict(request.headers), body))
        if self.hang:
            await asyncio.sleep(3600)
        if self.answer is not None:
            answer = self.answer(request)
            return await answer if asyncio.iscoroutine(answer) else answer
        port = request.url.port
        if port == contract.PORTS["tunnel"]:
            # The tunnel manager: its own tunnel token, or the instance's MCP token to read
            # the status or to stop (a config that starts nothing).
            bearer = _bearer(request)
            starts = bool(body and (body.get("ngrokAuthtoken") or body.get("chiselServerUrl")))
            allowed = {self.tunnel_token} | ({self.token} if not starts else set())
            if bearer not in allowed:
                return httpx.Response(401, json={"error": "unauthorized"})
            if request.url.path == "/tunnel/status":
                return httpx.Response(200, json=self.tunnel)
            if request.url.path == "/tunnel/configure":
                return httpx.Response(200, json={"status": "ok", "ngrok": bool(body.get("ngrokAuthtoken")),
                                                  "chisel": bool(body.get("chiselServerUrl"))})
            return httpx.Response(404)
        if _bearer(request) != self.token:
            return httpx.Response(401, json={"error": "unauthorized"})
        path = request.url.path
        if port == contract.PORTS["sessions"]:
            if path == "/sessions" and request.method == "GET":
                return httpx.Response(200, json=self.sessions)
            return httpx.Response(200, json={"ok": True, "busy": False, "output": f"ran on {self.instance}"})
        if port == contract.PORTS["network_recon"]:
            return httpx.Response(200, json={"signalled": 1})
        return httpx.Response(404)


class SharedContainer(Sandbox):
    """The old ``redamon-kali`` (``kali-sandbox``) with its shared MCP token: nothing may
    reach it."""

    def __init__(self):
        super().__init__("shared-container")
        self.token = SHARED_TOKEN
        self.running = True

    @property
    def host(self) -> str:
        return SHARED_HOST


class Fleet:
    """The webapp gateway and every sandbox behind it."""

    def __init__(self):
        self.sandboxes: List[Sandbox] = []
        self.shared = SharedContainer()
        self.gateway_requests: List[tuple] = []
        #: (person, view) whose next start answers 202 first.
        self.cold = set()
        #: (status, json) for every ensure, or a callable(body) -> (status, json) | None.
        self.ensure_answer = None
        self.lease_answer = None
        self.list_answer = None
        self.hang_list = False
        #: seconds a waiting ensure takes (a cold start in progress)
        self.ensure_delay = 0.0

    # --- the instances ---------------------------------------------------------------
    def add(self, person: str, view: str = contract.VIEW_OWN, **kw) -> Sandbox:
        box = Sandbox(person, view, **kw)
        self.sandboxes.append(box)
        return box

    def current(self, person: str, view: str = contract.VIEW_OWN) -> Optional[Sandbox]:
        for box in self.sandboxes:
            if (box.person, box.view, box.state) == (person, view, "running"):
                return box
        return None

    def by_host(self, host: str) -> Optional[Sandbox]:
        if host == SHARED_HOST:
            return self.shared
        return next((b for b in self.sandboxes if b.host == host), None)

    # --- what the agent asked the gateway ---------------------------------------------
    def calls(self, route: str) -> list:
        return [body for _m, p, body in self.gateway_requests if p == route]

    def ensures(self) -> list:
        return self.calls(contract.INTERNAL_ROUTE_ENSURE)

    def leases(self) -> list:
        return self.calls(contract.INTERNAL_ROUTE_LEASE)

    def releases(self) -> list:
        return self.calls(contract.INTERNAL_ROUTE_RELEASE)

    # --- the transport ----------------------------------------------------------------
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    async def handle(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        if f"http://{host}:{request.url.port}" == WEBAPP:
            return await self._gateway(request)
        box = self.by_host(host)
        if box is None or (box is self.shared and not self.shared.running):
            raise httpx.ConnectError("name or service not known", request=request)
        return await box.handle(request)

    async def _gateway(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        path = request.url.path
        self.gateway_requests.append((request.method, path, body))
        if path == contract.INTERNAL_ROUTE_ENSURE:
            if body.get("wait") and self.ensure_delay:
                await asyncio.sleep(self.ensure_delay)
            status, data = self._ensure(body)
            return httpx.Response(status, json=data)
        if path == contract.INTERNAL_ROUTE_LEASE:
            if self.lease_answer is not None:
                return httpx.Response(self.lease_answer[0], json=self.lease_answer[1])
            box = next((b for b in self.sandboxes
                        if b.person == body["userId"] and b.instance == body["instance"]), None)
            if box is None:
                return httpx.Response(409, json={"code": contract.ERR_NOT_RUNNING})
            if box.state == "draining" and body["leaseId"] not in box.leases:
                return httpx.Response(409, json={"code": contract.ERR_DRAINING})
            box.leases.add(body["leaseId"])
            return httpx.Response(200, json={"expires_at": 1e10, "state": box.state,
                                             "stop_at": 2e10, "warn": False})
        if path == contract.INTERNAL_ROUTE_RELEASE:
            return httpx.Response(204)
        if path == contract.INTERNAL_ROUTE_LIST:
            if self.hang_list:
                await asyncio.sleep(3600)
            if self.list_answer is not None:
                return httpx.Response(self.list_answer[0], json=self.list_answer[1])
            return httpx.Response(200, json=self.listing())
        return httpx.Response(404)

    def _ensure(self, body):
        if self.ensure_answer is not None:
            answer = self.ensure_answer(body) if callable(self.ensure_answer) else self.ensure_answer
            if answer is not None:
                return answer
        person = body["userId"]
        view = contract.VIEW_ACT_AS if body.get("actingAs") else contract.VIEW_OWN
        box = self.current(person, view)
        if box is None:
            box = self.add(person, view)
            if (person, view) in self.cold:
                self.cold.discard((person, view))
                box.starting = True
        if box.starting:
            # A cold start: every non-waiting ensure answers 202 until a waiting one
            # sees the instance healthy.
            if not body.get("wait"):
                return 202, {"state": "starting", "instance": box.instance, "fresh": True}
            box.starting = False
        return 200, {
            "user_id": person, "view": view, "instance": box.instance,
            "host": box.host, "token": box.token, "tunnel_token": box.tunnel_token,
            "ports": dict(contract.PORTS), "reverse_port": box.reverse_port,
            "projects": box.projects, "state": "running", "fresh": False,
            "stop_at": 2e10, "stop_reason": None, "warn": False}

    def listing(self) -> dict:
        return {"sandboxes": [
            {"user_id": b.person, "view": b.view, "instance": b.instance, "host": b.host,
             "token": b.token, "state": b.state}
            for b in self.sandboxes]}


def query(request_or_url) -> dict:
    url = request_or_url.url if isinstance(request_or_url, httpx.Request) else request_or_url
    return {k: v[0] for k, v in parse_qs(httpx.URL(str(url)).query.decode()).items()}
