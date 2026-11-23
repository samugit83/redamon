"""The drawer's `sandbox_status` frame (group 1, S12, WI-S12-1; contract B.13).

The sandbox router emits `{user_id, project_id, session_id, state, reason, limit, detail}` (and,
from S10, `kind` and `view`) when a person's sandbox is starting, ready or unavailable. The
WebSocket layer subscribes ONE listener, at start-up, that delivers each event only to the
socket of the run whose session id it carries:

- the same person: the socket's user (the ticket's `sub`, the member under act-as) equals the
  event's `user_id`, so a memory refusal with the instance's figures never reaches anyone else;
- the same session, and the same project when the event names one;
- the same view when the event names one (an act-as run's frames reach only the admin's act-as
  socket, never the member's own);
- only `run`-kind events: a job's, a Tradecraft fetch's or a triage refresh's lease taken
  inside a run (and its renewal's `unavailable/stopped`) carries the run's session id but is
  not the run's sandbox call; jobs report through `job_update`. An event with no `kind` is
  dropped (fail closed).

The payload is exactly B.13's: `{state, reason?, detail?, limit?}`, with `limit` reduced to the
governor's payload keys; never the user, project or session ids, the kind or the view. A
`no_user` refusal is never sent. A socket that fails to send never raises into the router.

Run: ./agentic/run_tests.sh tests/test_sandbox_status_event.py
"""
import asyncio
import ast
import json
import secrets
import sys
import unittest
from pathlib import Path
from unittest import mock

_AGENTIC_DIR = Path(__file__).resolve().parents[1]
if str(_AGENTIC_DIR) not in sys.path:
    sys.path.insert(0, str(_AGENTIC_DIR))

import httpx  # noqa: E402

import sandbox_contract as contract  # noqa: E402
import sandbox_router as router  # noqa: E402
import websocket_api  # noqa: E402
from decision_check import RunActor, current_run_actor  # noqa: E402
from websocket_api import MessageType, WebSocketConnection, WebSocketManager  # noqa: E402

RAM_LIMIT = {
    "admitted": False, "limitType": "ram", "resource": "kali_sandbox",
    "current": 7_500_000_000, "ceiling": 8_000_000_000,
    "settingName": "RECON_MEMORY_POOL_BYTES",
    "detail": "not enough memory: 0.5 GB free, a sandbox needs 1.0 GB",
}


class _FakeWS:
    def __init__(self, fail=False):
        self.client = "test"
        self.sent = []
        self.fail = fail

    async def close(self, code=1000, reason=""):
        pass

    async def send_json(self, msg):
        if self.fail:
            raise RuntimeError("socket gone")
        self.sent.append(msg)


def event(**over):
    base = {"user_id": "alice", "project_id": "p1", "session_id": "s1", "state": "starting",
            "reason": None, "limit": None, "detail": None, "kind": "run", "view": "own"}
    base.update(over)
    return base


class StatusTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        router._reset()
        self.mgr = WebSocketManager()
        websocket_api.subscribe_sandbox_status(self.mgr)

    async def asyncTearDown(self):
        websocket_api.unsubscribe_sandbox_status()
        router._reset()

    async def socket(self, user, project, session, actor_id=None, fail=False):
        conn = WebSocketConnection(_FakeWS(fail=fail))
        await self.mgr.authenticate(conn, user, project, session, verified=True)
        conn.actor_id = actor_id
        return conn

    async def emit(self, ev):
        """What the router does with an event: call every listener, await a coroutine."""
        for fn in list(router._listeners):
            result = fn(dict(ev))
            if asyncio.iscoroutine(result):
                await result

    @staticmethod
    def frames(conn):
        return [m for m in conn.websocket.sent if m["type"] == contract.SANDBOX_STATUS]


class TestOnlyTheRunsSocket(StatusTest):

    async def test_message_type_is_the_contracts(self):
        self.assertEqual(MessageType.SANDBOX_STATUS.value, contract.SANDBOX_STATUS)
        self.assertEqual(MessageType.SANDBOX_STATUS.value, "sandbox_status")

    async def test_event_reaches_only_the_socket_of_its_run(self):
        target = await self.socket("alice", "p1", "s1")
        other_session = await self.socket("alice", "p1", "s2")
        other_person = await self.socket("bob", "p1", "s1")      # bob reusing alice's session id
        other_project = await self.socket("alice", "p2", "s1")
        await self.emit(event())
        self.assertEqual([f["payload"] for f in self.frames(target)], [{"state": "starting"}])
        for conn in (other_session, other_person, other_project):
            self.assertEqual(self.frames(conn), [], conn.get_key())

    async def test_memory_refusal_with_its_figures_reaches_no_other_person(self):
        alice = await self.socket("alice", "p1", "s1")
        bob = await self.socket("bob", "p1", "s1")
        carol = await self.socket("carol", "p9", "s9")
        await self.emit(event(state="unavailable", reason="ram", limit=RAM_LIMIT,
                              detail=RAM_LIMIT["detail"]))
        self.assertEqual(len(self.frames(alice)), 1)
        self.assertEqual(self.frames(bob), [])
        self.assertEqual(self.frames(carol), [])

    async def test_an_event_without_a_session_reaches_nobody(self):
        conn = await self.socket("alice", "p1", "s1")
        for session in ("", None):
            await self.emit(event(session_id=session))
        self.assertEqual(self.frames(conn), [])

    async def test_an_event_without_a_person_reaches_nobody(self):
        conn = await self.socket("alice", "p1", "s1")
        for person in ("", None):
            await self.emit(event(user_id=person))
        self.assertEqual(self.frames(conn), [])

    async def test_an_event_naming_no_project_still_needs_person_and_session(self):
        mine = await self.socket("alice", "p1", "s1")
        bobs = await self.socket("bob", "p1", "s1")
        await self.emit(event(project_id=None))
        self.assertEqual(len(self.frames(mine)), 1)
        self.assertEqual(self.frames(bobs), [])

    async def test_unauthenticated_socket_gets_nothing(self):
        conn = await self.socket("alice", "p1", "s1")
        conn.authenticated = False
        await self.emit(event())
        self.assertEqual(self.frames(conn), [])


class TestOnlyRunKind(StatusTest):

    async def test_other_kinds_never_reach_a_drawer(self):
        """A job's renewal answered `stopped` carries the run's session id (the job was
        acquired in the run's context): the drawer must not show the run's sandbox as gone."""
        conn = await self.socket("alice", "p1", "s1")
        for kind in contract.LEASE_KINDS:
            if kind == "run":
                continue
            await self.emit(event(kind=kind, state="unavailable", reason="stopped"))
            await self.emit(event(kind=kind, state="starting"))
        self.assertEqual(self.frames(conn), [])

    async def test_an_event_without_kind_is_dropped(self):
        conn = await self.socket("alice", "p1", "s1")
        ev = event()
        del ev["kind"]
        await self.emit(ev)
        await self.emit(event(kind=None))
        await self.emit(event(kind="RUN"))
        self.assertEqual(self.frames(conn), [])

    async def test_run_kind_starting_then_ready(self):
        conn = await self.socket("alice", "p1", "s1")
        await self.emit(event(state="starting"))
        await self.emit(event(state="ready"))
        self.assertEqual([f["payload"] for f in self.frames(conn)],
                         [{"state": "starting"}, {"state": "ready"}])


class TestView(StatusTest):

    async def test_act_as_event_reaches_only_the_act_as_socket(self):
        """An admin acting as the member: the socket's user is the member, its actor the admin."""
        admin_as_member = await self.socket("member", "p1", "s1", actor_id="admin")
        await self.emit(event(user_id="member", view="act_as"))
        self.assertEqual(len(self.frames(admin_as_member)), 1)

    async def test_act_as_event_never_reaches_the_members_own_socket(self):
        member_own = await self.socket("member", "p1", "s1")
        await self.emit(event(user_id="member", view="act_as"))
        self.assertEqual(self.frames(member_own), [])

    async def test_own_event_never_reaches_an_act_as_socket(self):
        admin_as_member = await self.socket("member", "p1", "s1", actor_id="admin")
        await self.emit(event(user_id="member", view="own"))
        self.assertEqual(self.frames(admin_as_member), [])

    async def test_the_admins_own_socket_never_hears_the_members_sandbox(self):
        admin_own = await self.socket("admin", "p1", "s1")
        await self.emit(event(user_id="member", view="act_as"))
        self.assertEqual(self.frames(admin_own), [])

    async def test_an_event_without_view_is_matched_on_person_and_session(self):
        """Until the router names the view, the person and the session decide alone."""
        conn = await self.socket("alice", "p1", "s1")
        ev = event()
        del ev["view"]
        await self.emit(ev)
        self.assertEqual(len(self.frames(conn)), 1)

    async def test_an_unknown_view_is_dropped(self):
        conn = await self.socket("alice", "p1", "s1")
        await self.emit(event(view="other"))
        self.assertEqual(self.frames(conn), [])


class TestPayload(StatusTest):

    async def test_memory_refusal_payload_equals_the_contract(self):
        conn = await self.socket("alice", "p1", "s1")
        leaky_limit = dict(RAM_LIMIT, token="tok-never-sent", user_id="alice", host="redamon-kali-x")
        await self.emit(event(state="unavailable", reason="ram", limit=leaky_limit,
                              detail=RAM_LIMIT["detail"]))
        (frame,) = self.frames(conn)
        self.assertEqual(frame["type"], "sandbox_status")
        self.assertEqual(frame["payload"], {
            "state": "unavailable", "reason": "ram", "detail": RAM_LIMIT["detail"],
            "limit": RAM_LIMIT,
        })
        self.assertEqual(set(frame["payload"]["limit"]), set(contract.LIMIT_PAYLOAD_KEYS))

    async def test_payload_never_carries_ids_kind_or_view(self):
        conn = await self.socket("alice", "p1", "s1")
        await self.emit(event(state="unavailable", reason="hard", limit=dict(RAM_LIMIT, limitType="hard"),
                              detail="the instance's sandbox limit is reached"))
        await self.emit(event(state="unavailable", reason="refused", detail="sandbox_project_refused"))
        await self.emit(event(state="unavailable", reason="stopped"))
        for frame in self.frames(conn):
            payload = frame["payload"]
            self.assertLessEqual(set(payload), {"state", "reason", "detail", "limit"}, payload)
            self.assertNotIn("alice", repr(payload))
            self.assertNotIn("s1", repr(payload))

    async def test_limit_only_for_memory_and_count_refusals(self):
        conn = await self.socket("alice", "p1", "s1")
        await self.emit(event(state="unavailable", reason="error", limit=RAM_LIMIT, detail="x"))
        await self.emit(event(state="starting", limit=RAM_LIMIT, detail="y"))
        payloads = [f["payload"] for f in self.frames(conn)]
        self.assertEqual(payloads, [{"state": "unavailable", "reason": "error", "detail": "x"},
                                    {"state": "starting"}])

    async def test_no_user_and_unknown_values_are_never_sent(self):
        conn = await self.socket("alice", "p1", "s1")
        await self.emit(event(state="unavailable", reason="no_user"))
        await self.emit(event(state="unavailable", reason=None))
        await self.emit(event(state="unavailable", reason="other"))
        await self.emit(event(state="exploded"))
        await self.emit(event(state=None))
        self.assertEqual(self.frames(conn), [])

    async def test_every_contract_reason_is_sent(self):
        conn = await self.socket("alice", "p1", "s1")
        for reason in contract.SANDBOX_STATUS_REASONS:
            await self.emit(event(state="unavailable", reason=reason))
        self.assertEqual([f["payload"]["reason"] for f in self.frames(conn)],
                         list(contract.SANDBOX_STATUS_REASONS))


class TestListener(StatusTest):

    async def test_one_listener_however_often_it_is_subscribed(self):
        websocket_api.subscribe_sandbox_status(self.mgr)
        websocket_api.subscribe_sandbox_status(WebSocketManager())
        ours = [fn for fn in router._listeners if fn is websocket_api._on_sandbox_status]
        self.assertEqual(len(ours), 1)
        conn = await self.socket("alice", "p1", "s1")
        await self.emit(event())
        self.assertEqual(len(self.frames(conn)), 1, "one frame, not one per subscription")

    async def test_unsubscribe_removes_the_listener(self):
        conn = await self.socket("alice", "p1", "s1")
        websocket_api.unsubscribe_sandbox_status()
        self.assertNotIn(websocket_api._on_sandbox_status, router._listeners)
        await self.emit(event())
        self.assertEqual(self.frames(conn), [])

    async def test_a_failing_socket_never_raises_into_the_router(self):
        broken = await self.socket("alice", "p1", "s1", fail=True)
        await websocket_api._on_sandbox_status(event())   # must not raise
        self.assertEqual(broken.websocket.sent, [])

    async def test_a_malformed_event_never_raises(self):
        await self.socket("alice", "p1", "s1")
        for bad in (None, [], "x", {"state": "starting"}, {"kind": "run", "user_id": 5}):
            await websocket_api._on_sandbox_status(bad)

    async def test_the_listener_is_a_coroutine_function(self):
        """The router awaits a coroutine listener (for at most FANOUT_TIMEOUT_S), so the frame
        is on the socket before the acquire goes on: `starting` always precedes `ready`."""
        self.assertTrue(asyncio.iscoroutinefunction(websocket_api._on_sandbox_status))


class Gateway:
    """The webapp's internal sandbox routes behind httpx.MockTransport: a cold
    start answers 202 to the first, non-waiting ensure, then 200 with the running instance."""

    def __init__(self):
        self.instances = {}
        self.refuse_ram = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else {}
        path = request.url.path
        if path == contract.INTERNAL_ROUTE_ENSURE:
            if self.refuse_ram:
                return httpx.Response(409, json=dict(RAM_LIMIT, code=contract.ERR_RAM))
            person = body["userId"]
            view = contract.VIEW_ACT_AS if body.get("actingAs") else contract.VIEW_OWN
            key = (person, view)
            if key not in self.instances:
                self.instances[key] = {"instance": contract.new_instance(),
                                       "token": secrets.token_urlsafe(32)}
                if not body.get("wait"):
                    return httpx.Response(202, json={"state": "starting",
                                                     "instance": self.instances[key]["instance"],
                                                     "fresh": True})
            inst = self.instances[key]
            return httpx.Response(200, json={
                "user_id": person, "view": view, "instance": inst["instance"],
                "host": contract.container_name(person, view, inst["instance"]),
                "token": inst["token"], "tunnel_token": secrets.token_urlsafe(32),
                "ports": dict(contract.PORTS), "reverse_port": 4444, "projects": ["p1", "p2"],
                "state": "running", "fresh": False, "stop_at": 2e10, "stop_reason": None, "warn": False})
        if path == contract.INTERNAL_ROUTE_LEASE:
            return httpx.Response(200, json={"expires_at": 1e10, "state": "running",
                                             "stop_at": 2e10, "warn": False})
        if path == contract.INTERNAL_ROUTE_RELEASE:
            return httpx.Response(204)
        if path == contract.INTERNAL_ROUTE_LIST:
            return httpx.Response(200, json={"sandboxes": []})
        return httpx.Response(404)


class TestThroughTheRouter(unittest.IsolatedAsyncioTestCase):
    """Review finding 2: the router's own events (a run's acquire inside its run scope, the
    run actor bound) reach the run's socket and no other."""

    async def asyncSetUp(self):
        self.gateway = Gateway()
        router._reset()
        self._patches = [
            mock.patch.object(router, "_transport", httpx.MockTransport(self.gateway.handler)),
            mock.patch.dict(router.INTERNAL_HEADERS, {"X-Internal-Key": "test-internal-key"}),
            mock.patch.object(router, "WEBAPP_API_URL", "http://webapp.test:3000"),
        ]
        for p in self._patches:
            p.start()
        self.mgr = WebSocketManager()
        websocket_api.subscribe_sandbox_status(self.mgr)
        self.run_socket = await self.socket("alice", "p1", "s1")
        self.others = [await self.socket("alice", "p1", "s2"), await self.socket("bob", "p1", "s1"),
                       await self.socket("alice", "p2", "s1")]

    async def asyncTearDown(self):
        websocket_api.unsubscribe_sandbox_status()
        await router._shutdown()
        for p in reversed(self._patches):
            p.stop()
        router._reset()

    async def socket(self, user, project, session, actor_id=None):
        conn = WebSocketConnection(_FakeWS())
        await self.mgr.authenticate(conn, user, project, session, verified=True)
        conn.actor_id = actor_id
        return conn

    def run_actor(self):
        token = current_run_actor.set(RunActor(user_id="alice", tenant_id="owner", project_id="p1",
                                               session_id="s1"))
        self.addCleanup(current_run_actor.reset, token)

    async def test_a_cold_start_in_a_run_reaches_only_that_runs_socket(self):
        self.run_actor()
        async with router.run_scope("s1"):
            handle = await router.acquire("alice", project_id="p1", kind="run")
            self.assertEqual(handle.user_id, "alice")
        self.assertEqual([f["payload"] for f in StatusTest.frames(self.run_socket)],
                         [{"state": "starting"}, {"state": "ready"}])
        for conn in self.others:
            self.assertEqual(StatusTest.frames(conn), [], conn.get_key())

    async def test_a_memory_refusal_in_a_run_reaches_only_that_runs_socket(self):
        self.run_actor()
        self.gateway.refuse_ram = True
        async with router.run_scope("s1"):
            with self.assertRaises(router.SandboxUnavailable):
                await router.acquire("alice", project_id="p1", kind="run")
        (frame,) = StatusTest.frames(self.run_socket)
        self.assertEqual(frame["payload"]["state"], "unavailable")
        self.assertEqual(frame["payload"]["reason"], "ram")
        self.assertEqual(frame["payload"]["limit"], RAM_LIMIT)
        for conn in self.others:
            self.assertEqual(StatusTest.frames(conn), [], conn.get_key())

    async def test_a_job_lease_taken_inside_the_run_reaches_no_drawer(self):
        self.run_actor()
        async with router.run_scope("s1"):
            handle = await router.acquire("alice", project_id="p1", kind="job")
            await router.release(handle)
        self.assertEqual(StatusTest.frames(self.run_socket), [])
        for conn in self.others:
            self.assertEqual(StatusTest.frames(conn), [])


class TestStartupWiring(unittest.TestCase):
    """The listener is subscribed where the agent starts, with the WebSocket manager, and
    removed at shutdown (agentic/api.py lifespan)."""

    def test_lifespan_subscribes_after_the_manager_and_unsubscribes_at_shutdown(self):
        source = (_AGENTIC_DIR / "api.py").read_text()
        tree = ast.parse(source)
        lifespan = next(n for n in ast.walk(tree)
                        if isinstance(n, ast.AsyncFunctionDef) and n.name == "lifespan")
        body = ast.get_source_segment(source, lifespan)
        made = body.index("ws_manager = WebSocketManager()")
        subscribed = body.index("subscribe_sandbox_status(ws_manager)")
        served = body.index("yield")
        unsubscribed = body.index("unsubscribe_sandbox_status()")
        closed = body.index("await orchestrator.close()")
        self.assertLess(made, subscribed)
        self.assertLess(subscribed, served)
        self.assertLess(served, unsubscribed)
        self.assertLess(unsubscribed, closed)

    def test_subscribe_never_raises_into_start_up(self):
        router._reset()
        original = router.add_status_listener
        try:
            def boom(fn):
                raise RuntimeError("router broken")
            router.add_status_listener = boom
            websocket_api.subscribe_sandbox_status(WebSocketManager())   # must not raise
        finally:
            router.add_status_listener = original
            websocket_api.unsubscribe_sandbox_status()
            router._reset()


if __name__ == "__main__":
    unittest.main()
