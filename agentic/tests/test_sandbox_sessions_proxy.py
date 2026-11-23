"""The agent's Metasploit session routes across per-user Kali sandboxes (group 1, S11, B.12).

Every per-user sandbox runs its own console, which numbers its sessions from 1, so a
session is the pair (instance, number):

  - GET /sessions asks every running sandbox at once, each bounded, and tags every row
    with its instance and, from the agent's own handle, the sandbox's person and view
    (set after the sandbox's row, so a sandbox cannot claim another's); a sandbox that
    does not answer is named in `unavailable` and never delays the others (D22);
  - the drive routes take `?sandbox=<instance>` and reach that instance only (E3); the
    old shared container (`shared`, `kali-sandbox`) is never asked, even when it answers;
  - no token reaches an answer, and an answer is read bounded (identity encoding only).

Runs in the agent image: ./agentic/run_tests.sh tests/test_sandbox_sessions_proxy.py
"""
import asyncio
import gzip
import json
import os
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import api  # noqa: E402
import sandbox_contract as contract  # noqa: E402
import sandbox_router as router  # noqa: E402
from sandbox_route_fakes import SHARED_TOKEN, WEBAPP, Fleet  # noqa: E402

PERSON, VIEW = "sandbox_user", "sandbox_view"


def _body(resp):
    return json.loads(bytes(resp.body).decode())


def _session(n, **extra):
    return {"id": n, "type": "shell", "target": f"10.0.0.{n}", **extra}


class _Base(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.fleet = Fleet()
        # The old shared container still answers at its old address: nothing may ask it.
        self.fleet.shared.running = True
        router._reset()
        transport = self.fleet.transport()
        self._patches = [
            mock.patch.object(router, "_transport", transport),
            mock.patch.object(api, "_sandbox_transport", transport),
            mock.patch.dict(router.INTERNAL_HEADERS, {"X-Internal-Key": "test-internal-key"}),
            mock.patch.object(router, "WEBAPP_API_URL", WEBAPP),
            mock.patch.dict(os.environ, {"MCP_AUTH_TOKEN": SHARED_TOKEN,
                                         "MCP_METASPLOIT_PROGRESS_URL": "http://kali-sandbox:8013/progress"}),
        ]
        for p in self._patches:
            p.start()

    async def asyncTearDown(self):
        await router._shutdown()
        for p in reversed(self._patches):
            p.stop()
        self.assertEqual(self.fleet.shared.requests, [], "the old shared container was asked")
        router._reset()

    def tokens(self):
        out = {SHARED_TOKEN}
        for box in self.fleet.sandboxes:
            out |= {box.token, box.tunnel_token}
        return out

    def assertNoToken(self, payload):
        text = json.dumps(payload)
        for token in self.tokens():
            self.assertNotIn(token, text)


class TheListAcrossSandboxes(_Base):
    async def test_every_sandbox_is_listed_with_its_instance_under_todays_keys(self):
        alice = self.fleet.add("alice")
        bob = self.fleet.add("bob", contract.VIEW_ACT_AS)
        alice.sessions = {"sessions": [_session(1)], "jobs": [{"id": 0, "name": "handler"}],
                          "non_msf_sessions": [{"id": "raw-1700000000000", "type": "netcat"}]}
        bob.sessions = {"sessions": [_session(1), _session(2)], "jobs": [], "non_msf_sessions": []}
        body = _body(await api.get_sessions())
        self.assertEqual(set(body), {"sessions", "jobs", "non_msf_sessions", "unavailable", "busy"})
        self.assertEqual(body["unavailable"], [])
        self.assertEqual(body["busy"], [])
        by_instance = {}
        for row in body["sessions"]:
            by_instance.setdefault(row["sandbox"], []).append(row["id"])
        self.assertEqual(by_instance, {alice.instance: [1], bob.instance: [1, 2]})
        for name in ("sessions", "jobs", "non_msf_sessions"):
            for row in body[name]:
                box = alice if row["sandbox"] == alice.instance else bob
                self.assertEqual((row[PERSON], row[VIEW]), (box.person, box.view))
        self.assertEqual(body["non_msf_sessions"][0]["id"], "raw-1700000000000")
        self.assertNoToken(body)

    async def test_a_busy_console_is_named_by_its_instance(self):
        """Each person has their own console: the session terminal's "the agent is running a
        command" banner needs to know which one is busy, never one flag for all."""
        alice = self.fleet.add("alice")
        bob = self.fleet.add("bob")
        alice.sessions = {"sessions": [_session(1)], "jobs": [], "non_msf_sessions": [],
                          "agent_busy": True}
        bob.sessions = {"sessions": [_session(1)], "jobs": [], "non_msf_sessions": [],
                        "agent_busy": False}
        body = _body(await api.get_sessions())
        self.assertEqual(body["busy"], [alice.instance])
        for row in body["sessions"]:
            self.assertNotIn("busy", row)

    async def test_only_a_true_flag_counts_as_busy(self):
        alice = self.fleet.add("alice")
        alice.sessions = {"sessions": [], "jobs": [], "non_msf_sessions": [], "agent_busy": "yes"}
        self.assertEqual(_body(await api.get_sessions())["busy"], [])

    async def test_the_agents_tags_are_set_after_the_sandboxs_row(self):
        """A sandbox's root writes its session manager's answer: whatever instance or
        person it claims, the row carries its own."""
        alice = self.fleet.add("alice")
        bob = self.fleet.add("bob")
        alice.sessions = {"sessions": [_session(1, sandbox=bob.instance, **{PERSON: "bob", VIEW: "act_as"})],
                          "jobs": [], "non_msf_sessions": []}
        body = _body(await api.get_sessions())
        [row] = body["sessions"]
        self.assertEqual((row["sandbox"], row[PERSON], row[VIEW]), (alice.instance, "alice", "own"))

    async def test_rows_whose_id_is_not_the_session_managers_shape_are_dropped(self):
        alice = self.fleet.add("alice")
        alice.sessions = {
            "sessions": [_session(1), {"id": "2"}, {"id": -1}, {"id": True}, {"id": "1;rm"},
                         {"id": "../x"}, {"id": 1.5}, {"id": "raw-5"}, "not-a-row", {"no": "id"}],
            "jobs": [{"id": 3}, {"id": "<script>"}],
            "non_msf_sessions": [{"id": "raw-12"}, {"id": 7}, {"id": "raw-x"}, {"id": "raw-1/2"}]}
        body = _body(await api.get_sessions())
        self.assertEqual([r["id"] for r in body["sessions"]], [1, "2"])
        self.assertEqual([r["id"] for r in body["jobs"]], [3])
        self.assertEqual([r["id"] for r in body["non_msf_sessions"]], ["raw-12"])

    async def test_the_rows_taken_from_one_sandbox_are_capped(self):
        alice = self.fleet.add("alice")
        alice.sessions = {"sessions": [_session(i) for i in range(api._SESSION_ROWS_MAX + 50)],
                          "jobs": [], "non_msf_sessions": []}
        bob = self.fleet.add("bob")
        bob.sessions = {"sessions": [_session(1)], "jobs": [], "non_msf_sessions": []}
        body = _body(await api.get_sessions())
        rows = [r for r in body["sessions"] if r["sandbox"] == alice.instance]
        self.assertEqual(len(rows), api._SESSION_ROWS_MAX)
        self.assertEqual([r["id"] for r in body["sessions"] if r["sandbox"] == bob.instance], [1])

    async def test_hung_sandbox_does_not_stall_the_list(self):
        """D22: one sandbox never answers; the list comes back within the fan-out bound
        with everybody else's sessions, and the hung one named."""
        self.assertEqual(api._SESSIONS_FANOUT_S, contract.FANOUT_TIMEOUT_S)
        alice = self.fleet.add("alice")
        alice.sessions = {"sessions": [_session(1)], "jobs": [], "non_msf_sessions": []}
        hung = self.fleet.add("bob")
        hung.hang = True
        with mock.patch.object(api, "_SESSIONS_FANOUT_S", 0.5):
            started = time.monotonic()
            body = _body(await api.get_sessions())
            elapsed = time.monotonic() - started
        self.assertLess(elapsed, 0.5 + 1.5)
        self.assertEqual([r["sandbox"] for r in body["sessions"]], [alice.instance])
        self.assertEqual(body["unavailable"], [hung.instance])

    async def test_a_compressed_or_malformed_answer_reads_as_unavailable(self):
        alice = self.fleet.add("alice")
        alice.answer = lambda request: httpx.Response(
            200, content=gzip.compress(json.dumps({"sessions": []}).encode()),
            headers={"Content-Encoding": "gzip"})
        bob = self.fleet.add("bob")
        bob.answer = lambda request: httpx.Response(200, json={"sessions": "not-a-list"})
        carol = self.fleet.add("carol")
        carol.sessions = {"sessions": [_session(4)], "jobs": [], "non_msf_sessions": []}
        body = _body(await api.get_sessions())
        self.assertEqual(sorted(body["unavailable"]), sorted([alice.instance, bob.instance]))
        self.assertEqual([r["id"] for r in body["sessions"]], [4])
        for _m, _p, headers, _b in alice.requests:
            self.assertEqual(headers.get("accept-encoding"), "identity")

    async def test_each_sandbox_is_asked_with_its_own_token(self):
        alice, bob = self.fleet.add("alice"), self.fleet.add("bob")
        await api.get_sessions()
        for box in (alice, bob):
            [(method, path, headers, _b)] = box.requests
            self.assertEqual((method, path), ("GET", "/sessions"))
            self.assertEqual(headers["authorization"], f"Bearer {box.token}")

    async def test_the_list_unreadable_is_an_error_not_an_empty_list(self):
        self.fleet.add("alice")
        self.fleet.list_answer = (500, {"error": "boom"})
        resp = await api.get_sessions()
        self.assertEqual(resp.status_code, 503)


class TheOldSharedContainerIsNeverAsked(_Base):
    async def test_its_sessions_are_not_listed_and_shared_names_no_sandbox(self):
        """The old shared container still answers with a session: the list is the per-user
        sandboxes' alone, and `?sandbox=shared` names no instance (400), reaching nothing.
        _Base's tear-down checks the container got no request at all."""
        alice = self.fleet.add("alice")
        alice.sessions = {"sessions": [_session(1)], "jobs": [], "non_msf_sessions": []}
        self.fleet.shared.sessions = {"sessions": [_session(7)], "jobs": [], "non_msf_sessions": []}
        body = _body(await api.get_sessions())
        self.assertEqual([(r["sandbox"], r["id"]) for r in body["sessions"]], [(alice.instance, 1)])
        self.assertEqual(body["unavailable"], [])
        self.assertNoToken(body)
        for call in (lambda: api.kill_session(1, sandbox="shared"),
                     lambda: api.interact_session(1, {"command": "id"}, sandbox="shared"),
                     lambda: api.kill_job(1, sandbox="shared")):
            resp = await call()
            self.assertEqual(resp.status_code, 400)
            self.assertEqual(_body(resp)["code"], "invalid_sandbox")
        self.assertEqual([r for r in alice.requests if r[0] == "POST"], [])


class TheDrives(_Base):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.alice = self.fleet.add("alice")
        self.bob = self.fleet.add("bob")
        for box in (self.alice, self.bob):
            box.sessions = {"sessions": [_session(1)], "jobs": [{"id": 1}], "non_msf_sessions": []}

    def drives(self, box):
        return [r for r in box.requests if r[0] == "POST"]

    async def test_interact_goes_only_to_named_instance(self):
        """E3: session 1 exists in both sandboxes; the drive names bob's instance and
        reaches bob's console only, with bob's token."""
        resp = await api.interact_session(1, {"command": "id"}, sandbox=self.bob.instance)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(_body(resp)["output"], f"ran on {self.bob.instance}")
        [(method, path, headers, body)] = self.drives(self.bob)
        self.assertEqual((path, body), ("/sessions/1/interact", {"command": "id"}))
        self.assertEqual(headers["authorization"], f"Bearer {self.bob.token}")
        self.assertEqual(self.drives(self.alice), [])
        # A short `interact` lease on that very instance, taken and released; no ensure.
        self.assertEqual([(lease["userId"], lease["instance"], lease["kind"]) for lease in self.fleet.leases()],
                         [("bob", self.bob.instance, "interact")])
        self.assertEqual(len(self.fleet.releases()), 1)
        self.assertEqual(self.fleet.ensures(), [])
        self.assertNoToken(_body(resp))

    async def test_each_drive_route_reaches_the_named_instance_only(self):
        inst = self.bob.instance
        await api.kill_session(1, sandbox=inst)
        await api.kill_job(1, sandbox=inst)
        await api.session_chat_map({"msf_session_id": 1, "chat_session_id": "c1"}, sandbox=inst)
        await api.register_non_msf_session({"type": "netcat"}, sandbox=inst)
        self.assertEqual([r[1] for r in self.drives(self.bob)],
                         ["/sessions/1/kill", "/jobs/1/kill", "/session-chat-map", "/non-msf-sessions"])
        self.assertEqual(self.drives(self.alice), [])
        self.assertEqual(self.fleet.shared.requests, [])

    async def test_a_missing_instance_is_refused(self):
        for call in (lambda: api.interact_session(1, {"command": "id"}),
                     lambda: api.kill_session(1),
                     lambda: api.kill_job(1),
                     lambda: api.session_chat_map({"msf_session_id": 1, "chat_session_id": "c"}),
                     lambda: api.register_non_msf_session({"type": "netcat"})):
            resp = await call()
            self.assertEqual(resp.status_code, 400)
            self.assertEqual(_body(resp)["code"], "sandbox_required")
        self.assertEqual(self.drives(self.alice) + self.drives(self.bob), [])

    async def test_an_unknown_instance_is_not_found(self):
        resp = await api.kill_session(1, sandbox="abcdef")
        self.assertEqual(resp.status_code, 404)
        self.assertEqual(_body(resp)["code"], contract.ERR_UNKNOWN_INSTANCE)

    async def test_an_instance_that_is_not_one_is_refused(self):
        for bad in ("../x", "ABCDEF", "abcdefg", "", "shared2"):
            resp = await api.kill_session(1, sandbox=bad)
            self.assertEqual(resp.status_code, 400, bad)

    async def test_the_lookup_is_by_person_and_instance_never_instance_alone(self):
        """Instance ids are unique per person only: two people's instances with the same
        id are never told apart by the id; the person (and view) decide, or nothing."""
        self.bob.instance = self.alice.instance
        resp = await api.kill_session(1, sandbox=self.alice.instance)
        self.assertEqual(resp.status_code, 409)
        self.assertEqual(self.drives(self.alice) + self.drives(self.bob), [])
        resp = await api.kill_session(1, sandbox=self.alice.instance, sandbox_user="bob")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual([r[1] for r in self.drives(self.bob)], ["/sessions/1/kill"])
        self.assertEqual(self.drives(self.alice), [])
        resp = await api.kill_session(1, sandbox=self.alice.instance, sandbox_user="bob",
                                      sandbox_view="act_as")
        self.assertEqual(resp.status_code, 404)

    async def test_a_drive_answer_carries_no_token(self):
        self.bob.answer = lambda request: httpx.Response(
            200, json={"ok": True, "echo": request.headers.get("authorization")})
        resp = await api.kill_session(1, sandbox=self.bob.instance)
        self.assertEqual(resp.status_code, 200)
        # The sandbox's own answer passes through: the agent adds no token of its own.
        self.assertNotIn(SHARED_TOKEN, json.dumps(_body(resp)))
        self.assertNotIn(self.alice.token, json.dumps(_body(resp)))

    async def test_a_refused_bearer_is_a_502_naming_the_cause(self):
        # A sandbox's 401 passed through as 401 would read as "the webapp's key was refused".
        self.bob.answer = lambda request: httpx.Response(401, json={"error": "unauthorized"})
        with self.assertLogs(level="ERROR") as logs:
            resp = await api.kill_session(1, sandbox=self.bob.instance)
        self.assertEqual(resp.status_code, 502)
        self.assertEqual(_body(resp)["code"], "session_manager_unauthorized")
        self.assertTrue(any("[rbac]" in line for line in logs.output))

    async def test_a_hung_instance_drive_times_out_bounded(self):
        self.bob.hang = True
        with mock.patch.object(api, "_SESSION_DRIVE_S", {"kill": 0.3, "interact": 0.3, "map": 0.3}):
            started = time.monotonic()
            resp = await api.kill_session(1, sandbox=self.bob.instance)
        self.assertLess(time.monotonic() - started, 2.0)
        self.assertEqual(resp.status_code, 504)


if __name__ == "__main__":
    unittest.main()
