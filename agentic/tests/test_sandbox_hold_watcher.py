"""The hold watcher: live sessions and an active tunnel hold their sandbox (group 1, S12,
WI-S12-6; D24, B.8 `hold`, OD-G1-f).

A sandbox stops after its idle minutes without a lease, but a Metasploit session, a job (a
listener), a non-MSF session or a tunnel lives there with no unit of work holding it. The
watcher (agentic/sandbox_hold.py) reads every live instance and holds the ones that have any
with ONE `hold` lease per instance (a fixed lease id), released when none remain. A hold is
not use, so the orchestrator's 8-hour no-use cap still applies; the watcher never calls
`ensure`, which would mark use (and could start a sandbox).

- Every instance at once, each read bounded: a hung sandbox never delays another's hold.
- A failed read justifies nothing: nothing is taken on it, and a hold is renewed only while
  its last good read is at most LEASE_TTL_S old, then left to expire.
- Renewals run on their own every LEASE_TTL_S / 3 (S01 review R2-F4), so one failed or slow
  read never lets a held sandbox's lease lapse.
- The tunnel manager is read only with the instance's own tunnel token (the gateway's list
  carries none: the tunnel push hands it over through note_tunnel); the session manager only
  with the instance's own MCP token.
- No token, user id or session content is logged.

The webapp gateway and the sandboxes are stubbed with one httpx.MockTransport; time is a
fake monotonic clock unless a test needs the real loop.

Run: ./agentic/run_tests.sh tests/test_sandbox_hold_watcher.py
"""
import asyncio
import ast
import gzip
import json
import logging
import os
import secrets
import sys
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock

_AGENTIC_DIR = Path(__file__).resolve().parents[1]
if str(_AGENTIC_DIR) not in sys.path:
    sys.path.insert(0, str(_AGENTIC_DIR))

import httpx  # noqa: E402
import httpx._decoders as httpx_decoders  # noqa: E402

import sandbox_contract as contract  # noqa: E402
import sandbox_hold  # noqa: E402
import sandbox_http  # noqa: E402
import sandbox_router as router  # noqa: E402

TTL = contract.LEASE_TTL_S
SESSION = {"id": 1, "type": "meterpreter", "info": "SECRET-SESSION-CONTENT on target"}
JOB = {"id": 0, "name": "Exploit: multi/handler", "payload": "linux/x64/meterpreter/reverse_tcp", "port": 4444}
NON_MSF = {"id": "nc-1", "type": "netcat", "info": "SECRET-NON-MSF-CONTENT"}


class World:
    """The webapp's internal sandbox routes and every sandbox's session and tunnel managers."""

    def __init__(self):
        self.instances = {}
        self.requests = []      # (method, host, port, path, body, headers, t)
        self.lease_answer = None
        self.list_fails = False
        self.t0 = time.monotonic()

    def add(self, person, view=contract.VIEW_OWN, *, sessions=(), jobs=(), non_msf=(), tunnel=False):
        inst = contract.new_instance()
        self.instances[(person, view, inst)] = {
            "token": secrets.token_urlsafe(32), "tunnel_token": secrets.token_urlsafe(32),
            "sessions": list(sessions), "jobs": list(jobs), "non_msf": list(non_msf),
            "tunnel": tunnel, "hang": False, "fail": None, "state": "running",
        }
        return (person, view, inst)

    def inst(self, key):
        return self.instances[key]

    def handle(self, key):
        """The lease-less handle running_sandboxes() gives, plus the tunnel token the push has."""
        person, view, instance = key
        return router.SandboxHandle(
            user_id=person, view=view, instance=instance,
            host=contract.container_name(person, view, instance),
            token=self.inst(key)["token"], tunnel_token=self.inst(key)["tunnel_token"],
            ports=contract.PORTS, reverse_port=4444)

    def by_host(self, host):
        for key, data in self.instances.items():
            if contract.container_name(*key) == host:
                return key, data
        return None, None

    async def handler(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        url = request.url
        self.requests.append((request.method, url.host, url.port, url.path, body,
                              dict(request.headers), time.monotonic() - self.t0))
        if url.host == "webapp.test":
            return self.gateway(url.path, body)
        key, data = self.by_host(url.host)
        if data is None:
            return httpx.Response(502)
        if data["hang"]:
            await asyncio.Event().wait()
        if data["fail"] == "connect":
            raise httpx.ConnectError("refused", request=request)
        if data["fail"] == "500":
            return httpx.Response(500, json={"error": "boom"})
        if data["fail"] == "garbage":
            return httpx.Response(200, content=b"not json")
        if url.port == contract.PORTS["sessions"] and url.path == "/sessions":
            if request.headers.get("authorization") != f"Bearer {data['token']}":
                return httpx.Response(401)
            return httpx.Response(200, json={
                "sessions": data["sessions"], "jobs": data["jobs"],
                "non_msf_sessions": data["non_msf"], "cache_age_seconds": 1.0, "agent_busy": False})
        if url.port == contract.PORTS["tunnel"] and url.path == "/tunnel/status":
            if request.headers.get("authorization") != f"Bearer {data['tunnel_token']}":
                return httpx.Response(401, json={"error": "unauthorized"})
            active = data["tunnel"]
            return httpx.Response(200, json={"ngrok": {"active": active == "ngrok"},
                                             "chisel": {"active": active == "chisel"}})
        return httpx.Response(404)

    def gateway(self, path, body):
        if path == contract.INTERNAL_ROUTE_LIST:
            if self.list_fails:
                return httpx.Response(503, json={"code": "orchestrator_unavailable"})
            return httpx.Response(200, json={"sandboxes": [
                {"user_id": p, "view": v, "instance": i, "host": contract.container_name(p, v, i),
                 "token": d["token"], "state": d["state"]}
                for (p, v, i), d in self.instances.items()]})
        if path == contract.INTERNAL_ROUTE_LEASE:
            if self.lease_answer is not None:
                status, data = self.lease_answer
                return httpx.Response(status, json=data)
            return httpx.Response(200, json={"expires_at": 1e10, "state": "running",
                                             "stop_at": 2e10, "warn": False})
        if path == contract.INTERNAL_ROUTE_RELEASE:
            return httpx.Response(204)
        if path == contract.INTERNAL_ROUTE_ENSURE:
            return httpx.Response(500, json={"error": "the watcher must never ensure"})
        return httpx.Response(404)

    # --- what was asked ------------------------------------------------------------------
    def gateway_calls(self, path):
        return [(b, t) for m, h, _p, pa, b, _hd, t in self.requests if h == "webapp.test" and pa == path]

    def leases(self):
        return [b for b, _t in self.gateway_calls(contract.INTERNAL_ROUTE_LEASE)]

    def lease_times(self):
        return [t for _b, t in self.gateway_calls(contract.INTERNAL_ROUTE_LEASE)]

    def releases(self):
        return [b for b, _t in self.gateway_calls(contract.INTERNAL_ROUTE_RELEASE)]

    def reads(self, port_name):
        port = contract.PORTS[port_name]
        return [r for r in self.requests if r[1] != "webapp.test" and r[2] == port]


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class HoldTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.world = World()
        transport = httpx.MockTransport(self.world.handler)
        router._reset()
        self._patches = [
            mock.patch.object(router, "_transport", transport),
            mock.patch.object(sandbox_hold, "_transport", transport),
            mock.patch.dict(router.INTERNAL_HEADERS, {"X-Internal-Key": "test-internal-key"}),
            mock.patch.object(router, "WEBAPP_API_URL", "http://webapp.test:3000"),
        ]
        for p in self._patches:
            p.start()
        self.clock = Clock()
        self.watcher = sandbox_hold.HoldWatcher(clock=self.clock)

    async def asyncTearDown(self):
        await self.watcher.stop()
        await router._shutdown()
        for p in reversed(self._patches):
            p.stop()
        router._reset()

    def lease_id(self, key):
        return sandbox_hold.hold_lease_id(self.world.handle(key))


class TestHoldFollowsWhatLives(HoldTest):

    async def test_a_live_session_takes_one_hold_lease(self):
        key = self.world.add("alice", sessions=[SESSION])
        await self.watcher.watch_once()
        self.assertEqual(self.world.leases(), [{
            "userId": "alice", "instance": key[2], "leaseId": self.lease_id(key), "kind": "hold"}])
        self.assertEqual(self.world.gateway_calls(contract.INTERNAL_ROUTE_ENSURE), [],
                         "an ensure marks use: the watcher never calls it")

    async def test_jobs_non_msf_sessions_and_tunnels_each_hold(self):
        cases = {"job": dict(jobs=[JOB]), "non_msf": dict(non_msf=[NON_MSF]),
                 "ngrok": dict(tunnel="ngrok"), "chisel": dict(tunnel="chisel")}
        for name, what in cases.items():
            with self.subTest(name):
                self.world.instances.clear()
                self.world.requests.clear()
                watcher = sandbox_hold.HoldWatcher(clock=self.clock)
                key = self.world.add("alice", **what)
                watcher.note_tunnel(self.world.handle(key))
                await watcher.watch_once()
                self.assertEqual([b["leaseId"] for b in self.world.leases()], [self.lease_id(key)])
                self.assertEqual(self.world.leases()[0]["kind"], "hold")

    async def test_an_instance_with_nothing_gets_no_hold(self):
        key = self.world.add("alice")
        self.watcher.note_tunnel(self.world.handle(key))
        await self.watcher.watch_once()
        await self.watcher.renew_once()
        self.assertEqual(self.world.leases(), [])
        self.assertEqual(self.world.releases(), [])

    async def test_released_when_none_remain_and_never_renewed_after(self):
        key = self.world.add("alice", sessions=[SESSION], jobs=[JOB])
        await self.watcher.watch_once()
        self.world.inst(key).update(sessions=[], jobs=[])
        self.clock.now += sandbox_hold.HOLD_WATCH_S
        await self.watcher.watch_once()
        self.assertEqual(self.world.releases(), [{"userId": "alice", "leaseId": self.lease_id(key)}])
        before = len(self.world.leases())
        self.clock.now += sandbox_hold.HOLD_RENEW_S
        await self.watcher.renew_once()
        self.assertEqual(len(self.world.leases()), before, "a released hold is not renewed")

    async def test_only_the_instances_that_hold_something(self):
        busy = self.world.add("alice", sessions=[SESSION])
        idle = self.world.add("bob")
        await self.watcher.watch_once()
        self.assertEqual([b["instance"] for b in self.world.leases()], [busy[2]])
        self.assertNotIn(idle[2], [b["instance"] for b in self.world.leases()])

    async def test_a_stopped_instance_is_forgotten(self):
        key = self.world.add("alice", sessions=[SESSION])
        await self.watcher.watch_once()
        del self.world.instances[key]
        self.clock.now += sandbox_hold.HOLD_WATCH_S
        await self.watcher.watch_once()
        n = len(self.world.leases())
        self.clock.now += sandbox_hold.HOLD_RENEW_S
        await self.watcher.renew_once()
        self.assertEqual(len(self.world.leases()), n)


class TestFailedReads(HoldTest):

    async def test_a_failed_first_read_takes_nothing(self):
        for fail in ("connect", "500", "garbage"):
            with self.subTest(fail=fail):
                self.world.instances.clear()
                self.world.requests.clear()
                watcher = sandbox_hold.HoldWatcher(clock=self.clock)
                key = self.world.add("alice", sessions=[SESSION])
                self.world.inst(key)["fail"] = fail
                await watcher.watch_once()
                await watcher.renew_once()
                self.assertEqual(self.world.leases(), [])

    async def test_a_session_manager_without_the_three_lists_is_a_failed_read(self):
        key = self.world.add("alice", sessions=[SESSION])
        original = self.world.handler

        async def partial(request):
            if request.url.port == contract.PORTS["sessions"]:
                return httpx.Response(200, json={"sessions": []})
            return await original(request)

        transport = httpx.MockTransport(partial)
        with mock.patch.object(sandbox_hold, "_transport", transport):
            await self.watcher.watch_once()
        self.assertEqual(self.world.leases(), [])
        self.assertIsNotNone(key)

    async def test_a_failed_read_renews_nothing_beyond_its_last_good_read(self):
        """Reads fail after the first: renewals go on while the last good read is at most one
        lease lifetime old, then stop; nothing is released (the lease is left to expire)."""
        key = self.world.add("alice", sessions=[SESSION])
        await self.watcher.watch_once()                       # t=0: good read, hold taken
        self.world.inst(key)["fail"] = "500"
        renewed_at = []
        for step in range(1, 8):                               # t = 30, 60, ... 210
            self.clock.now += sandbox_hold.HOLD_RENEW_S
            if step % 2 == 0:
                await self.watcher.watch_once()                # every HOLD_WATCH_S: a failed read
            n = len(self.world.leases())
            await self.watcher.renew_once()
            if len(self.world.leases()) > n:
                renewed_at.append(step * sandbox_hold.HOLD_RENEW_S)
        self.assertEqual(renewed_at, [30, 60, 90])
        self.assertTrue(all(t <= TTL for t in renewed_at))
        self.assertEqual(self.world.releases(), [], "a failed read releases nothing either")

    async def test_a_list_outage_keeps_fresh_holds_only(self):
        key = self.world.add("alice", sessions=[SESSION])
        await self.watcher.watch_once()
        self.world.list_fails = True
        renewed = []
        for step in range(1, 6):
            self.clock.now += sandbox_hold.HOLD_RENEW_S
            if step % 2 == 0:
                await self.watcher.watch_once()
            n = len(self.world.leases())
            await self.watcher.renew_once()
            renewed.append(len(self.world.leases()) > n)
        self.assertEqual(renewed, [True, True, True, False, False])
        self.assertIsNotNone(key)

    async def test_one_failed_read_never_lets_the_hold_lapse(self):
        """S01 review R2-F4: reads every HOLD_WATCH_S against a 90 s lease, so renewing only on
        a read let one failed read expire the hold. The lease is always renewed before it ends."""
        key = self.world.add("alice", sessions=[SESSION])
        taken = []

        async def tick(read: bool):
            n = len(self.world.leases())
            if read:
                await self.watcher.watch_once()
            await self.watcher.renew_once()
            if len(self.world.leases()) > n:
                taken.append(self.clock.now)

        await tick(read=True)                                   # t=0
        for step in range(1, 9):                                # t = 30 ... 240
            self.clock.now += sandbox_hold.HOLD_RENEW_S
            read = step % 2 == 0
            self.world.inst(key)["fail"] = "connect" if step == 2 else None   # the read at t=60 fails
            await tick(read)
        gaps = [b - a for a, b in zip(taken, taken[1:])]
        self.assertTrue(gaps, taken)
        self.assertLess(max(gaps), TTL, f"the lease lapsed between renewals: {taken}")

    async def test_renewals_three_times_per_lease_lifetime(self):
        self.assertLessEqual(sandbox_hold.HOLD_RENEW_S, TTL / 3)
        self.assertLessEqual(sandbox_hold.HOLD_JUSTIFIED_S, TTL)
        self.assertEqual(sandbox_hold.HOLD_WATCH_S, contract.HOLD_WATCH_S)

    async def test_renewals_run_on_their_own_between_reads(self):
        """The real loops: with reads far apart, the hold is still renewed every HOLD_RENEW_S."""
        self.world.add("alice", sessions=[SESSION])
        watcher = sandbox_hold.HoldWatcher()
        with mock.patch.object(sandbox_hold, "HOLD_RENEW_S", 0.05), \
                mock.patch.object(sandbox_hold, "HOLD_WATCH_S", 3600):
            self.assertTrue(watcher.start())
            await asyncio.sleep(0.4)
            await watcher.stop()
        self.assertEqual(len(self.world.reads("sessions")), 1, "one read in the window")
        self.assertGreaterEqual(len(self.world.leases()), 4, "the take plus several renewals")


class TestLeaseIds(HoldTest):

    async def test_one_lease_id_per_instance(self):
        a_own = self.world.add("alice", sessions=[SESSION])
        a_act = self.world.add("alice", contract.VIEW_ACT_AS, sessions=[SESSION])
        b_own = self.world.add("bob", jobs=[JOB])
        await self.watcher.watch_once()
        self.clock.now += sandbox_hold.HOLD_RENEW_S
        await self.watcher.renew_once()
        self.clock.now += sandbox_hold.HOLD_RENEW_S
        await self.watcher.watch_once()
        by_instance = {}
        for body in self.world.leases():
            by_instance.setdefault(body["instance"], set()).add(body["leaseId"])
        self.assertEqual({k: len(v) for k, v in by_instance.items()},
                         {a_own[2]: 1, a_act[2]: 1, b_own[2]: 1})
        ids = {next(iter(v)) for v in by_instance.values()}
        self.assertEqual(len(ids), 3)
        for lease_id in ids:
            self.assertEqual(str(uuid.UUID(lease_id)), lease_id)

    async def test_a_restarted_agent_renews_the_same_lease(self):
        """The id is derived from the instance, so a new watcher renews what the last one held
        (a draining instance accepts renewals of existing ids only)."""
        key = self.world.add("alice", sessions=[SESSION])
        await self.watcher.watch_once()
        await sandbox_hold.HoldWatcher(clock=self.clock).watch_once()
        self.assertEqual({b["leaseId"] for b in self.world.leases()}, {self.lease_id(key)})

    async def test_a_draining_refusal_is_not_retried(self):
        self.world.add("alice", sessions=[SESSION])
        self.world.lease_answer = (409, {"code": contract.ERR_DRAINING})
        await self.watcher.watch_once()
        for _ in range(4):
            self.clock.now += sandbox_hold.HOLD_RENEW_S
            await self.watcher.renew_once()
        self.clock.now += sandbox_hold.HOLD_WATCH_S
        await self.watcher.watch_once()
        self.assertEqual(len(self.world.leases()), 1)

    async def test_a_gone_instance_is_not_retried(self):
        self.world.add("alice", sessions=[SESSION])
        self.world.lease_answer = (409, {"detail": {"code": contract.ERR_NOT_RUNNING}})
        await self.watcher.watch_once()
        for _ in range(3):
            self.clock.now += sandbox_hold.HOLD_RENEW_S
            await self.watcher.renew_once()
        self.assertEqual(len(self.world.leases()), 1)

    async def test_a_transient_lease_failure_is_retried_at_the_next_renewal(self):
        self.world.add("alice", sessions=[SESSION])
        self.world.lease_answer = (503, {"code": "orchestrator_unavailable"})
        await self.watcher.watch_once()
        self.world.lease_answer = None
        self.clock.now += sandbox_hold.HOLD_RENEW_S
        await self.watcher.renew_once()
        self.assertEqual(len(self.world.leases()), 2)


class TestHungSandbox(HoldTest):

    async def test_a_hung_instance_does_not_delay_the_others(self):
        hung = self.world.add("alice", sessions=[SESSION])
        fine = self.world.add("bob", sessions=[SESSION])
        also = self.world.add("carol", jobs=[JOB])
        self.world.inst(hung)["hang"] = True
        with mock.patch.object(sandbox_hold, "READ_TIMEOUT_S", 0.6):
            started = time.monotonic()
            await self.watcher.watch_once()
            elapsed = time.monotonic() - started
        self.assertLess(elapsed, 0.6 + 0.5, "one tick is bounded by the read timeout")
        by_instance = {b["instance"]: t for b, t in self.world.gateway_calls(contract.INTERNAL_ROUTE_LEASE)}
        self.assertEqual(set(by_instance), {fine[2], also[2]}, "the hung one gets no hold")
        list_done = self.world.gateway_calls(contract.INTERNAL_ROUTE_LIST)[0][1]
        for instance, t in by_instance.items():
            self.assertLess(t - list_done, 0.3, f"{instance} waited for the hung sandbox")

    async def test_a_hung_tunnel_read_does_not_hide_live_sessions(self):
        key = self.world.add("alice", sessions=[SESSION])
        self.watcher.note_tunnel(self.world.handle(key))
        original = self.world.handler

        async def tunnel_hangs(request):
            if request.url.port == contract.PORTS["tunnel"]:
                await asyncio.Event().wait()
            return await original(request)

        with mock.patch.object(sandbox_hold, "_transport", httpx.MockTransport(tunnel_hangs)), \
                mock.patch.object(sandbox_hold, "READ_TIMEOUT_S", 0.3):
            await self.watcher.watch_once()
        self.assertEqual(len(self.world.leases()), 1)


class TestHostileAnswers(HoldTest):
    """Review finding 1: a sandbox's root can make 8013 or 8015 answer anything. A compressed,
    oversized or dripping answer is a failed read (no hold, no release), never inflated or
    buffered whole in the agent that every tenant shares."""

    async def _watch_with(self, port_name, make):
        """One read round in which the instance's `port_name` answers with `make(request)`."""
        original = self.world.handler
        port = contract.PORTS[port_name]

        async def hostile(request):
            if request.url.port == port:
                return make(request)
            return await original(request)

        with mock.patch.object(sandbox_hold, "_transport", httpx.MockTransport(hostile)):
            await self.watcher.watch_once()

    async def _answer_sessions_with(self, make):
        key = self.world.add("alice", sessions=[SESSION])
        await self._watch_with("sessions", make)
        return key

    @staticmethod
    def _unread(status, body, headers=None):
        return httpx.Response(status, headers=headers or {}, stream=httpx.ByteStream(body))

    async def test_a_stacked_gzip_sessions_answer_is_never_inflated(self):
        live = json.dumps({"sessions": [SESSION], "jobs": [], "non_msf_sessions": []}).encode()
        body = gzip.compress(gzip.compress(live + b" " * (8 * 1024 * 1024)))
        decoded = []
        real_decode = httpx_decoders.GZipDecoder.decode

        def spy(self_, data):
            decoded.append(len(data))
            return real_decode(self_, data)

        with mock.patch.object(httpx_decoders.GZipDecoder, "decode", spy):
            await self._answer_sessions_with(
                lambda r: self._unread(200, body, {"content-encoding": "gzip, gzip"}))
        self.assertEqual(decoded, [], "the bomb was inflated")
        self.assertEqual(self.world.leases(), [], "a refused answer justifies nothing")
        self.assertEqual(self.world.releases(), [])
        sent = [r for r in self.world.requests if r[2] == contract.PORTS["sessions"]]
        self.assertEqual(sent, [], "the hostile transport answered, the world saw nothing")

    async def test_the_watcher_asks_for_identity(self):
        seen = []

        def capture(request):
            seen.append(request.headers.get("accept-encoding"))
            return self._unread(200, json.dumps(
                {"sessions": [SESSION], "jobs": [], "non_msf_sessions": []}).encode())

        await self._answer_sessions_with(capture)
        self.assertEqual(seen, ["identity"])
        self.assertEqual(len(self.world.leases()), 1)

    async def test_an_oversized_sessions_answer_is_a_failed_read(self):
        huge = json.dumps({"sessions": [SESSION] * 20_000, "jobs": [], "non_msf_sessions": []}).encode()
        self.assertGreater(len(huge), sandbox_http.MAX_ANSWER_BYTES)
        await self._answer_sessions_with(lambda r: self._unread(200, huge))
        self.assertEqual(self.world.leases(), [])

    async def test_a_dripping_sessions_answer_is_bounded(self):
        async def drip():
            yield b'{"sessions": ['
            while True:
                await asyncio.sleep(0.05)
                yield b"{},"

        with mock.patch.object(sandbox_hold, "READ_TIMEOUT_S", 0.4):
            started = time.monotonic()
            await self._answer_sessions_with(lambda r: httpx.Response(200, content=drip()))
            elapsed = time.monotonic() - started
        self.assertLess(elapsed, 1.5)
        self.assertEqual(self.world.leases(), [])

    async def test_a_compressed_tunnel_answer_is_a_failed_read(self):
        """A compressed tunnel answer is unknown: with no session it neither takes nor releases
        a hold, and a live session still holds by itself."""
        body = gzip.compress(json.dumps({"ngrok": {"active": True}, "chisel": {"active": False}}).encode())
        gzipped = lambda r: self._unread(200, body, {"content-encoding": "gzip"})  # noqa: E731
        key = self.world.add("alice", sessions=[SESSION], tunnel="ngrok")
        self.watcher.note_tunnel(self.world.handle(key))
        await self._watch_with("tunnel", gzipped)
        self.assertEqual(len(self.world.leases()), 1, "the live session holds by itself")
        self.world.inst(key)["sessions"] = []
        self.clock.now += sandbox_hold.HOLD_WATCH_S
        await self._watch_with("tunnel", gzipped)
        self.assertEqual(self.world.releases(), [], "an unreadable tunnel answer releases nothing")
        self.assertEqual(len(self.world.leases()), 1, "and takes nothing")


class TestTokens(HoldTest):

    async def test_each_read_uses_that_instances_own_token(self):
        a = self.world.add("alice", sessions=[SESSION], tunnel="ngrok")
        b = self.world.add("bob", tunnel="chisel")
        for key in (a, b):
            self.watcher.note_tunnel(self.world.handle(key))
        await self.watcher.watch_once()
        for _m, host, port, _p, _b, headers, _t in self.world.requests:
            if host == "webapp.test":
                self.assertEqual(headers.get("x-internal-key"), "test-internal-key")
                continue
            key, data = self.world.by_host(host)
            want = data["tunnel_token"] if port == contract.PORTS["tunnel"] else data["token"]
            self.assertEqual(headers.get("authorization"), f"Bearer {want}", (host, port))
        self.assertEqual(len(self.world.leases()), 2)

    async def test_no_tunnel_token_no_tunnel_read(self):
        """The gateway's list carries no tunnel token: until the push hands it over, the tunnel
        manager is not asked (and an active tunnel justifies nothing)."""
        self.world.add("alice", tunnel="ngrok")
        await self.watcher.watch_once()
        self.assertEqual(self.world.reads("tunnel"), [])
        self.assertEqual(self.world.leases(), [])

    async def test_note_tunnel_ignores_malformed_handles(self):
        key = self.world.add("alice", tunnel="ngrok")
        bad = self.world.handle(key)
        bad.tunnel_token = "has space\r\n"
        self.watcher.note_tunnel(bad)
        self.watcher.note_tunnel(None)
        await self.watcher.watch_once()
        self.assertEqual(self.world.reads("tunnel"), [])

    async def test_nothing_secret_is_logged(self):
        key = self.world.add("alice", sessions=[SESSION], non_msf=[NON_MSF], tunnel="ngrok")
        self.watcher.note_tunnel(self.world.handle(key))
        with self.assertLogs(sandbox_hold.logger, level="DEBUG") as logs:
            sandbox_hold.logger.debug("start")
            await self.watcher.watch_once()
            self.world.inst(key).update(sessions=[], non_msf=[], tunnel=False)
            self.clock.now += sandbox_hold.HOLD_WATCH_S
            await self.watcher.watch_once()
            self.world.inst(key)["fail"] = "500"
            await self.watcher.watch_once()
        text = "\n".join(logs.output)
        data = self.world.inst(key)
        for secret in (data["token"], data["tunnel_token"], "alice", "SECRET-SESSION-CONTENT",
                       "SECRET-NON-MSF-CONTENT", self.lease_id(key)):
            self.assertNotIn(secret, text)


class TestGatewayDown(HoldTest):

    async def test_a_gateway_that_is_down_raises_nothing(self):
        with mock.patch.dict(router.INTERNAL_HEADERS, {"X-Internal-Key": ""}):
            await self.watcher.watch_once()
            await self.watcher.renew_once()
        self.world.add("alice", sessions=[SESSION])
        self.world.list_fails = True
        router._reset()
        await self.watcher.watch_once()
        self.assertEqual(self.world.leases(), [])


class TestStartStop(unittest.IsolatedAsyncioTestCase):

    async def asyncTearDown(self):
        await sandbox_hold.stop()

    async def test_start_and_stop_are_idempotent(self):
        with mock.patch.dict(router.INTERNAL_HEADERS, {"X-Internal-Key": ""}):
            self.assertTrue(sandbox_hold.start())
            self.assertFalse(sandbox_hold.start(), "a second start starts nothing")
            await sandbox_hold.stop()
            await sandbox_hold.stop()
            self.assertTrue(sandbox_hold.start(), "a start after a stop starts again")
            await sandbox_hold.stop()

    async def test_the_loops_run_in_a_context_of_their_own(self):
        """No request's or run's person leaks into the watcher."""
        seen = []
        real_watch = sandbox_hold.HoldWatcher.watch_once

        async def spy(self):
            seen.append(router.sandbox_user())
            await real_watch(self)

        with mock.patch.dict(router.INTERNAL_HEADERS, {"X-Internal-Key": ""}), \
                mock.patch.object(sandbox_hold.HoldWatcher, "watch_once", spy), \
                router.for_person("alice"):
            sandbox_hold.start()
            await asyncio.sleep(0.05)
            await sandbox_hold.stop()
        self.assertEqual(seen, [""])

    async def test_stop_never_raises(self):
        watcher = sandbox_hold.HoldWatcher()

        async def boom(self):
            raise RuntimeError("bug")

        with mock.patch.object(sandbox_hold.HoldWatcher, "watch_once", boom), \
                mock.patch.dict(router.INTERNAL_HEADERS, {"X-Internal-Key": ""}):
            watcher.start()
            await asyncio.sleep(0.02)
            await watcher.stop()


class TestStartupWiring(unittest.TestCase):

    def test_start_outside_a_loop_never_raises(self):
        self.assertFalse(sandbox_hold.start())

    def test_lifespan_starts_the_watcher_and_stops_it_at_shutdown(self):
        source = (_AGENTIC_DIR / "api.py").read_text()
        tree = ast.parse(source)
        lifespan = next(n for n in ast.walk(tree)
                        if isinstance(n, ast.AsyncFunctionDef) and n.name == "lifespan")
        body = ast.get_source_segment(source, lifespan)
        made = body.index("ws_manager = WebSocketManager()")
        started = body.index("sandbox_hold.start()")
        served = body.index("yield")
        stopped = body.index("await sandbox_hold.stop()")
        closed = body.index("await orchestrator.close()")
        self.assertLess(made, started)
        self.assertLess(started, served)
        self.assertLess(served, stopped)
        self.assertLess(stopped, closed)


if __name__ == "__main__":
    unittest.main()
