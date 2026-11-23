"""
Every system Kali tool call goes to the run's person's sandbox (group 1, S10: T5, T7, S5,
I11, D24, D22).

PhaseAwareToolExecutor.execute() is the one chokepoint every path reaches: the single
tool node, the plan wave, a Fireteam member (which reuses those nodes) and a background
job's runner. It takes the run's handle from the sandbox router (one `run` lease per
chat run, acquired lazily), or a job's own `job` lease, and calls the tool on that
person's own MCP client: never the shared manager, never another person's client. The owner's keys injected into a call (WPScan, URLScan, PDCP), the capture tag
and proxy_brain's run credential therefore reach only the sandbox of the person running
the agent (I11, T7, S5). Both nodes read the Hydra and Metasploit progress and post the
session-manager links to that same sandbox with its own bearer. Stopping a run asks the
sandboxes it used; the emergency stop asks every running sandbox at once and is never
held by a hung one (D22).

The webapp gateway is the httpx.MockTransport stub of test_sandbox_router.py; each
person's MCP client is a fake that records what it was sent.

Run: ./agentic/run_tests.sh tests/test_sandbox_executor_routing.py
"""
import asyncio
import importlib
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

_TESTS_DIR = Path(__file__).resolve().parent
_AGENTIC_DIR = _TESTS_DIR.parent
for _p in (str(_AGENTIC_DIR), str(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import httpx  # noqa: E402

import job_runner  # noqa: E402
import output_offload  # noqa: E402
import project_settings  # noqa: E402
import sandbox_contract as contract  # noqa: E402
import sandbox_router as router  # noqa: E402
import sandbox_runs  # noqa: E402
import tools  # noqa: E402
from agent_context import current_log_session_id, set_tenant_context  # noqa: E402
from decision_check import RunActor, bind_run_actor  # noqa: E402
from orchestrator_helpers import roe_gate  # noqa: E402
# The package re-exports the node functions under the modules' names.
plan_mod = importlib.import_module("orchestrator_helpers.nodes.execute_plan_node")
tool_mod = importlib.import_module("orchestrator_helpers.nodes.execute_tool_node")
from test_sandbox_router import COMPOSE_ENV, RAM_PAYLOAD, SHARED_TOKEN, Gateway  # noqa: E402

MSF_OUTPUT = "[*] Meterpreter session 3 opened (10.0.0.2:4444 -> 10.0.0.9:51000)"
INTERNAL_KEY = "test-internal-key-for-tags"


# =============================================================================
# Fakes: one MCP client per sandbox instance, and the shared manager
# =============================================================================

class FakeTool:
    def __init__(self, name, client):
        self.name = name
        self.client = client
        self.args_schema = {"type": "object", "properties": {}}

    async def ainvoke(self, args):
        client = self.client
        client.calls.append({"tool": self.name, "args": args, "run": sandbox_runs.current_run_key()})
        if client.failures:
            raise client.failures.pop(0)
        if client.gate is not None:
            try:
                await client.gate.wait()
            except asyncio.CancelledError:
                client.cancelled += 1
                raise
            if client.failures:
                raise client.failures.pop(0)
        if self.name == "metasploit_console":
            return MSF_OUTPUT
        return f"ok from {client.label}"


class FakeClient:
    """A sandbox instance's MCPToolsManager: what it was sent, and its reconnects."""

    def __init__(self, label, token=""):
        self.label = label
        self.token = token
        self.calls = []
        self.failures = []
        self.gate = None
        self.cancelled = 0
        self.generation = 1
        self.reconnects = 0
        self.reconnect_fails = False
        self.tools = {n: FakeTool(n, self) for n in tools.SYSTEM_MCP_TOOL_NAMES | {"create_issue"}}

    def list_tools(self):
        return list(self.tools.values())

    async def reconnect(self, seen_generation, reason="", force=False):
        self.reconnects += 1
        if self.reconnect_fails:
            return self.generation, []
        self.generation += 1
        self.tools = {n: FakeTool(n, self) for n in self.tools}
        return self.generation, self.list_tools()

    def sent(self):
        return json.dumps([c["args"] for c in self.calls], default=str)


class Clients:
    """router.client_for, over fake clients keyed by instance."""

    def __init__(self):
        self.by_key = {}

    async def client_for(self, handle):
        if handle.stale or handle.released:
            raise router.SandboxUnavailable("stopped", detail="sandbox_stopped")
        if handle.key not in self.by_key:
            self.by_key[handle.key] = FakeClient(f"{handle.user_id}/{handle.view}/{handle.instance}",
                                                 handle.token)
        return self.by_key[handle.key]

    def of(self, person, view="own"):
        found = [c for k, c in self.by_key.items() if k[:2] == (person, view)]
        return found[-1] if found else None


class Recorder:
    """httpx.AsyncClient for the node posts and the progress polls."""

    calls = []

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, json=None, headers=None):
        Recorder.calls.append(("POST", url, json, dict(headers or {})))
        return SimpleNamespace(status_code=200)

    async def get(self, url, headers=None):
        Recorder.calls.append(("GET", url, None, dict(headers or {})))
        return SimpleNamespace(status_code=200, json=lambda: {
            "active": True, "output": "line", "line_count": 1, "elapsed_seconds": 1})


FAKE_HTTPX = SimpleNamespace(AsyncClient=Recorder, TimeoutException=httpx.TimeoutException,
                             HTTPError=httpx.HTTPError)


class Registry:
    """job_runner's registry: spawns the runner in its own task, as spawn() does."""

    def __init__(self):
        self.tasks = {}
        self.results = {}

    async def spawn(self, project_id, tool_name, args, runner, label=None):
        job_id = f"job-{len(self.tasks) + 1}"

        async def append_log(chunk):
            return None

        async def run():
            job_runner._current_job.set((self, SimpleNamespace(job_id=job_id)))
            self.results[job_id] = await runner(tool_name, args or {}, append_log)

        self.tasks[job_id] = asyncio.create_task(run())
        return {"job_id": job_id, "status": "running"}


# =============================================================================
# The harness
# =============================================================================

class Routing(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.gateway = Gateway()
        router._reset()
        self.clients = Clients()
        self.shared = FakeClient("shared", SHARED_TOKEN)
        Recorder.calls = []
        self.events = []
        router.add_status_listener(self.events.append)
        patches = [
            mock.patch.object(router, "_transport", httpx.MockTransport(self.gateway.handler)),
            mock.patch.dict(router.INTERNAL_HEADERS, {"X-Internal-Key": "test-internal-key"}),
            mock.patch.object(router, "WEBAPP_API_URL", "http://webapp.test:3000"),
            mock.patch.dict(os.environ, {**COMPOSE_ENV, "INTERNAL_API_KEY": INTERNAL_KEY}),
            mock.patch.object(router, "client_for", self.clients.client_for),
            mock.patch("tools.is_tool_allowed_in_phase", return_value=True),
            mock.patch.object(roe_gate, "check_tool_call", return_value=None),
            mock.patch.object(roe_gate, "check_unasked_call", mock.AsyncMock(return_value=None)),
            mock.patch.object(tool_mod, "httpx", FAKE_HTTPX),
            mock.patch.object(plan_mod, "httpx", FAKE_HTTPX),
            mock.patch.object(tools, "httpx", FAKE_HTTPX),
        ]
        for p in patches:
            p.start()
            self.addAsyncCleanup(self._stop, p)
        self.executor = tools.PhaseAwareToolExecutor(self.shared, None)
        self.executor.register_mcp_tools(self.shared.list_tools())

    async def _stop(self, p):
        p.stop()

    async def asyncTearDown(self):
        await router._shutdown()
        router._reset()
        getattr(sandbox_runs, "_reset", lambda: None)()

    async def run_as(self, person, body, *, tenant=None, project="p1", session=None,
                     actor_id=None, settings=None):
        """`body()` inside a chat run of `person` on `tenant`'s project, as websocket_api
        and the orchestrator set it up: its own task, the run actor, the tenant context,
        the run's own settings and the sandbox run scope."""
        session = session or f"sess-{person}"

        async def task():
            bind_run_actor(RunActor(user_id=person, tenant_id=tenant or person, project_id=project,
                                    session_id=session, actor_id=actor_id))
            set_tenant_context(tenant or person, project, session)
            current_log_session_id.set(session)
            project_settings._settings_ctx.set({**project_settings.DEFAULT_AGENT_SETTINGS,
                                                **(settings or {})})
            async with router.run_scope(session):
                return await body()

        return await asyncio.create_task(task())

    def call(self, name, args=None):
        return self.executor.execute(name, dict(args or {"command": "id"}), "exploitation")


# =============================================================================
# Routing by person
# =============================================================================

class TestRoutesToThePerson(Routing):

    async def test_execute_routes_mcp_tool_to_run_persons_sandbox(self):
        async def alice():
            return [await self.call("kali_shell"), await self.call("execute_nmap", {"args": "-sV x"})]

        async def bob():
            return [await self.call("kali_shell"),
                    await self.call("execute_nuclei", {"args": "-u x", "output_mode": "inline"})]

        a, b = await asyncio.gather(self.run_as("alice", alice), self.run_as("bob", bob, tenant="alice"))
        self.assertTrue(all(r["success"] for r in a + b), a + b)
        self.assertEqual({r["output"] for r in a}, {f"ok from {self.clients.of('alice').label}"})
        self.assertEqual({r["output"] for r in b}, {f"ok from {self.clients.of('bob').label}"})
        self.assertEqual([c["tool"] for c in self.clients.of("alice").calls], ["kali_shell", "execute_nmap"])
        self.assertEqual([c["tool"] for c in self.clients.of("bob").calls], ["kali_shell", "execute_nuclei"])
        self.assertEqual(self.clients.of("alice").token, self.gateway.token("alice"))
        self.assertEqual(self.clients.of("bob").token, self.gateway.token("bob"))
        self.assertEqual(self.shared.calls, [], "the shared manager served a per-user call")
        self.assertEqual(sorted(b["userId"] for b in self.gateway.ensures()), ["alice", "bob"])
        self.assertEqual([b["kind"] for b in self.gateway.leases()], ["run", "run"])
        self.assertEqual(len(self.gateway.releases()), 2, "each run scope released its lease")

    async def test_plan_wave_routes_each_call_to_its_person(self):
        steps = [{"tool_name": "kali_shell", "tool_args": {"command": "id"}},
                 {"tool_name": "execute_nmap", "tool_args": {"args": "-sV x"}}]

        def wave(person):
            async def body():
                state = {"messages": [], "current_iteration": 1, "current_phase": "exploitation",
                         "execution_trace": [], "_current_plan": {"steps": [dict(s) for s in steps]}}
                config = {"configurable": {"user_id": person, "project_id": "p1",
                                           "session_id": f"sess-{person}", "tenant_user_id": "alice"}}
                return await plan_mod.execute_plan_node(
                    state, config, tool_executor=self.executor, streaming_callbacks={})
            return body

        a, b = await asyncio.gather(self.run_as("alice", wave("alice")),
                                    self.run_as("bob", wave("bob"), tenant="alice"))
        for out, person in ((a, "alice"), (b, "bob")):
            self.assertTrue(all(s["success"] for s in out["_current_plan"]["steps"]), out)
            self.assertEqual(sorted(c["tool"] for c in self.clients.of(person).calls),
                             ["execute_nmap", "kali_shell"])
        self.assertEqual(self.shared.calls, [])
        self.assertEqual(len(self.gateway.leases()), 2, "one run lease per run, shared by the wave")

    async def test_fireteam_member_inherits_person(self):
        async def run():
            async def member(i):
                return await self.call("kali_shell", {"command": f"member {i}"})
            return await asyncio.gather(*(asyncio.create_task(member(i)) for i in range(3)))

        results = await self.run_as("bob", run, tenant="alice")
        self.assertTrue(all(r["success"] for r in results))
        self.assertEqual(len(self.clients.of("bob").calls), 3)
        self.assertIsNone(self.clients.of("alice"))
        self.assertEqual([b["userId"] for b in self.gateway.ensures()], ["bob"])
        self.assertEqual(len(self.gateway.leases()), 1)

    async def test_user_mcp_servers_unaffected(self):
        async def run():
            return await self.call("create_issue", {"title": "x"})

        result = await self.run_as("bob", run, tenant="alice")
        self.assertTrue(result["success"], result)
        self.assertEqual([c["tool"] for c in self.shared.calls], ["create_issue"])
        self.assertEqual(self.gateway.requests, [], "a user MCP tool never asks for a sandbox")


# =============================================================================
# The owner's keys, the capture tag and the run credential (I11, T7, S5)
# =============================================================================

class TestSecretsGoOnlyToTheRunsSandbox(Routing):

    async def test_wpscan_key_goes_only_to_runs_sandbox(self):
        keys = {"wpscanApiToken": "alice-wpscan-key", "urlscanApiKey": "alice-urlscan-key",
                "pdcpApiKey": "alice-pdcp-key"}

        async def bob():
            await self.call("execute_wpscan", {"args": "--url https://wp.test"})
            await self.call("execute_gau", {"args": "x.test"})
            await self.call("cve_intel", {"cve_id": "CVE-2024-0001"})

        async def alice_elsewhere():
            await self.call("execute_wpscan", {"args": "--url https://wp.test"})

        await asyncio.gather(
            self.run_as("bob", bob, tenant="alice", settings={"USER_SETTINGS": keys}),
            self.run_as("alice", alice_elsewhere, project="p2", settings={"USER_SETTINGS": {}}))
        bob_sent = self.clients.of("bob").sent()
        for key in keys.values():
            self.assertIn(key, bob_sent)
            self.assertNotIn(key, self.clients.of("alice").sent())
            self.assertNotIn(key, self.shared.sent())
        args = {c["tool"]: c["args"] for c in self.clients.of("bob").calls}
        self.assertEqual(args["execute_wpscan"]["api_token"], "alice-wpscan-key")
        self.assertEqual(args["execute_gau"]["urlscan_api_key"], "alice-urlscan-key")
        self.assertEqual(args["cve_intel"]["api_key"], "alice-pdcp-key")

    async def test_proxy_brain_credential_only_in_runs_sandbox(self):
        async def bob():
            return await self.call("proxy_brain", {"code": "print(1)"})

        async def alice():
            return await self.call("kali_shell")

        rb, ra = await asyncio.gather(self.run_as("bob", bob, tenant="alice"), self.run_as("alice", alice))
        self.assertTrue(rb["success"] and ra["success"], (rb, ra))
        sent = self.clients.of("bob").calls[0]["args"]
        self.assertTrue(sent.get("_redamon_run") and sent.get("_redamon_ctx"))
        self.assertNotIn(sent["_redamon_run"], self.clients.of("alice").sent())
        self.assertNotIn("_redamon_run", self.clients.of("alice").sent())

    async def test_capture_tag_reaches_only_the_runs_sandbox(self):
        async def bob():
            return await self.call("execute_curl", {"args": "-s https://t.test/"})

        async def alice():
            return await self.call("kali_shell")

        await asyncio.gather(
            self.run_as("bob", bob, tenant="alice", settings={"CAPTURE_PROXY_ENABLED": True}),
            self.run_as("alice", alice, settings={"CAPTURE_PROXY_ENABLED": True}))
        tag = self.clients.of("bob").calls[0]["args"].get("_redamon_ctx")
        self.assertTrue(tag)
        self.assertNotIn(tag, self.clients.of("alice").sent())
        self.assertNotIn("_redamon_ctx", self.clients.of("alice").sent())
        self.assertEqual(self.clients.of("bob").calls[0]["run"], "sess-bob")


# =============================================================================
# Refusals, reconnects, a stopped sandbox
# =============================================================================

class TestRefusalsAndFailures(Routing):

    async def test_unavailable_returns_model_string_and_emits_event(self):
        self.gateway.script[contract.INTERNAL_ROUTE_ENSURE] = lambda b: (409, {**RAM_PAYLOAD, "code": contract.ERR_RAM})

        async def bob():
            return await self.call("kali_shell")

        result = await self.run_as("bob", bob, tenant="alice", session="sess-ram")
        self.assertEqual(result, {"success": False, "output": None, "error": contract.SANDBOX_UNAVAILABLE_RAM})
        self.assertEqual(len(self.events), 1)
        event = self.events[0]
        self.assertEqual((event["state"], event["reason"], event["session_id"], event["kind"], event["view"]),
                         ("unavailable", "ram", "sess-ram", "run", "own"))
        self.assertEqual(event["limit"], RAM_PAYLOAD)
        self.assertEqual(self.shared.calls, [])

    async def test_refused_returns_the_refused_model_string(self):
        self.gateway.script[contract.INTERNAL_ROUTE_ENSURE] = lambda b: (403, {"code": contract.ERR_PROJECT_REFUSED})

        async def bob():
            return await self.call("kali_shell")

        result = await self.run_as("bob", bob, tenant="alice")
        self.assertEqual(result["error"], contract.SANDBOX_REFUSED)
        self.gateway.script.clear()
        # No person at all (a call outside any run, before an entry point names one).
        result = await self.call("kali_shell")
        self.assertEqual(result["error"], contract.SANDBOX_REFUSED)
        self.assertEqual(self.shared.calls, [])

    async def test_reconnect_rebuilds_only_that_users_client(self):
        gate = asyncio.Event()

        async def alice():
            first = await self.call("kali_shell")
            self.clients.of("alice").failures.append(RuntimeError("Connection closed"))
            gate.set()
            return first, await self.call("kali_shell")

        async def bob():
            first = await self.call("kali_shell")
            await gate.wait()
            return first, await self.call("kali_shell")

        (a1, a2), (b1, b2) = await asyncio.gather(self.run_as("alice", alice), self.run_as("bob", bob))
        self.assertTrue(all(r["success"] for r in (a1, a2, b1, b2)), (a1, a2, b1, b2))
        self.assertEqual(self.clients.of("alice").reconnects, 1)
        self.assertEqual(self.clients.of("bob").reconnects, 0)
        self.assertEqual(self.shared.reconnects, 0)
        self.assertEqual(len(self.gateway.ensures()), 2, "a reconnect that works asks for no new sandbox")

    async def test_stopped_sandbox_retried_once_after_reacquire(self):
        async def bob():
            await self.call("kali_shell")
            client = self.clients.of("bob")
            client.failures.append(RuntimeError("Connection closed"))
            client.reconnect_fails = True
            # The orchestrator started a new instance in place of the stopped one.
            del self.gateway.instances[("bob", "own")]
            return await self.call("kali_shell", {"command": "again"})

        result = await self.run_as("bob", bob)
        self.assertTrue(result["success"], result)
        instances = {k[2] for k in self.clients.by_key}
        self.assertEqual(len(instances), 2)
        self.assertEqual(result["output"], f"ok from {self.clients.of('bob').label}")
        self.assertEqual(self.clients.of("bob").token, self.gateway.token("bob"))
        self.assertEqual(len(self.gateway.ensures()), 2)

    async def test_a_second_loss_is_sandbox_stopped(self):
        async def bob():
            await self.call("kali_shell")
            first = self.clients.of("bob")
            first.failures.append(RuntimeError("Connection closed"))
            first.reconnect_fails = True
            del self.gateway.instances[("bob", "own")]
            original = self.clients.client_for

            async def broken(handle):
                client = await original(handle)
                if client is not first:
                    client.failures.append(RuntimeError("Connection closed"))
                    client.reconnect_fails = True
                return client

            with mock.patch.object(router, "client_for", broken):
                return await self.call("kali_shell", {"command": "again"})

        result = await self.run_as("bob", bob)
        self.assertEqual(result, {"success": False, "output": None, "error": contract.SANDBOX_STOPPED})
        self.assertEqual(len(self.gateway.ensures()), 2, "one re-acquire, never a loop")


# =============================================================================
# A sandbox call's deadline and output offload (_call_in_sandbox, _tool_success)
# =============================================================================

class _HugeAnswer:
    def __init__(self, name):
        self.name = name

    async def ainvoke(self, args):
        return "X" * 100_000


class TestTheSandboxCallIsBounded(Routing):
    """The per-user path keeps the shared path's tool deadline and output offload."""

    async def test_a_lost_answer_ends_in_a_failure_without_a_reconnect(self):
        async def alice():
            await self.call("execute_code", {"code": "print(1)"})
            client = self.clients.of("alice")
            client.gate = asyncio.Event()  # never set: the answer is lost
            with mock.patch.dict(tools.TOOL_DEADLINES_S, {"execute_code": 0.3}):
                result = await asyncio.wait_for(self.call("execute_code", {"code": "print(2)"}), 5)
            return client, result

        client, result = await self.run_as("alice", alice)
        self.assertFalse(result["success"])
        self.assertIsNone(result["output"])
        self.assertIn("gave no answer", result["error"])
        self.assertEqual((client.cancelled, client.reconnects), (1, 0))
        self.assertEqual(self.shared.calls, [])

    async def _nuclei(self, args):
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(output_offload, "WORKSPACE_ROOT", Path(tmp)):
            async def alice():
                await self.call("kali_shell")
                self.clients.of("alice").tools["execute_nuclei"] = _HugeAnswer("execute_nuclei")
                return await self.call("execute_nuclei", args)

            result = await self.run_as("alice", alice)
            outputs = Path(tmp) / "p1" / "tool-outputs"
            sizes = [f.stat().st_size for f in outputs.iterdir()] if outputs.is_dir() else []
        self.assertTrue(result["success"], result)
        self.assertEqual(self.shared.calls, [])
        return result["output"], sizes

    async def test_a_huge_answer_is_offloaded_to_the_runs_project(self):
        output, sizes = await self._nuclei({"target": "example.com"})
        self.assertIn("[Output offloaded:", output)
        self.assertLess(len(output), 10_000)
        self.assertEqual(sizes, [100_000])

    async def test_inline_keeps_the_whole_answer(self):
        output, sizes = await self._nuclei({"target": "example.com", "output_mode": "inline"})
        self.assertNotIn("[Output offloaded:", output)
        self.assertEqual(len(output), 100_000)
        self.assertEqual(sizes, [])


# =============================================================================
# A call that outlives its run (review F1)
# =============================================================================

class TestACallOutlivingItsRun(Routing):

    def _msf_calls(self):
        return [c for client in self.clients.by_key.values() for c in client.calls
                if c["tool"] == "metasploit_console"]

    async def test_it_is_never_sent_again_after_the_run_ended(self):
        holder = {}

        async def bob():
            await self.call("kali_shell")
            client = self.clients.of("bob")
            client.gate = asyncio.Event()
            holder["task"] = asyncio.create_task(self.call("metasploit_console", {"command": "exploit"}))
            while not self._msf_calls():
                await asyncio.sleep(0)

        await self.run_as("bob", bob)          # the run ends; its call is still running
        client = self.clients.of("bob")
        client.failures.append(RuntimeError("Connection closed"))
        client.reconnect_fails = True
        del self.gateway.instances[("bob", "own")]
        client.gate.set()
        result = await holder["task"]
        self.assertEqual(result, {"success": False, "output": None, "error": contract.SANDBOX_STOPPED})
        self.assertEqual([b["kind"] for b in self.gateway.leases()], ["run"], "a new lease after the run")
        self.assertEqual(len(self.gateway.ensures()), 1, "a new sandbox after the run")
        self.assertEqual(len(self._msf_calls()), 1, "the command was sent again")

    async def test_a_cancelled_progress_poller_cancels_its_call(self):
        async def progress(*args, **kwargs):
            return None

        async def bob():
            await self.call("kali_shell")
            client = self.clients.of("bob")
            client.gate = asyncio.Event()
            poller = asyncio.create_task(self.executor.execute_with_progress(
                "metasploit_console", {"command": "exploit"}, "exploitation",
                progress_callback=progress, poll_interval=0.01))
            while not self._msf_calls():
                await asyncio.sleep(0)
            await asyncio.sleep(0.05)
            poller.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await poller
            for _ in range(10):
                await asyncio.sleep(0)
            return client

        client = await self.run_as("bob", bob)
        self.assertEqual(client.cancelled, 1, "the call ran on after its poller was cancelled")


# =============================================================================
# Act-as, background jobs
# =============================================================================

class TestViewsAndJobs(Routing):

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.registry = Registry()
        p = mock.patch.object(job_runner, "get_registry", return_value=self.registry)
        p.start()
        self.addAsyncCleanup(self._stop, p)

    async def test_background_job_holds_its_own_lease(self):
        async def bob():
            await self.call("kali_shell")
            spawned = await self.call("job_spawn", {"tool_name": "kali_shell",
                                                    "args": {"command": "long scan"}})
            self.assertTrue(spawned["success"], spawned)
            return spawned

        await self.run_as("bob", bob, tenant="alice")
        job_id, task = next(iter(self.registry.tasks.items()))
        await task
        leases = self.gateway.leases()
        self.assertEqual(sorted(b["kind"] for b in leases), ["job", "run"])
        job_lease = next(b for b in leases if b["kind"] == "job")
        run_lease = next(b for b in leases if b["kind"] == "run")
        self.assertEqual(job_lease["userId"], "bob")
        released = [b["leaseId"] for b in self.gateway.releases()]
        self.assertIn(run_lease["leaseId"], released)
        self.assertIn(job_lease["leaseId"], released)
        self.assertTrue(self.registry.results[job_id]["success"])
        self.assertEqual(router.job_sandbox(job_id), ("bob", "own"))
        self.assertEqual([c["args"].get("command") for c in self.clients.of("bob").calls],
                         ["id", "long scan"])

    async def test_a_job_outlives_its_run(self):
        async def bob():
            await self.call("kali_shell")
            self.clients.of("bob").gate = asyncio.Event()
            spawned = await self.call("job_spawn", {"tool_name": "kali_shell",
                                                    "args": {"command": "long scan"}})
            await asyncio.sleep(0.05)
            return spawned

        await self.run_as("bob", bob)
        job_id, task = next(iter(self.registry.tasks.items()))
        self.assertFalse(task.done())
        job_lease = next(b for b in self.gateway.leases() if b["kind"] == "job")
        self.assertNotIn(job_lease["leaseId"], [b["leaseId"] for b in self.gateway.releases()],
                         "the run's end released the job's sandbox")
        self.assertEqual(len(self.gateway.releases()), 1)
        self.clients.of("bob").gate.set()
        await task
        self.assertIn(job_lease["leaseId"], [b["leaseId"] for b in self.gateway.releases()])

    async def test_act_as_run_and_its_job_use_the_act_as_view(self):
        async def run():
            await self.call("kali_shell")
            return await self.call("job_spawn", {"tool_name": "kali_shell", "args": {"command": "bg"}})

        await self.run_as("bob", run, actor_id="admin-1")
        job_id, task = next(iter(self.registry.tasks.items()))
        await task
        self.assertEqual([b.get("actingAs") for b in self.gateway.ensures()], [True, True])
        self.assertEqual({b["userId"] for b in self.gateway.ensures()}, {"bob"})
        self.assertIsNone(self.clients.of("bob", "own"))
        self.assertEqual(len(self.clients.of("bob", "act_as").calls), 2)
        self.assertEqual(router.job_sandbox(job_id), ("bob", "act_as"))
        self.assertNotIn("admin-1", json.dumps(self.gateway.ensures()))

    async def test_a_refused_job_fails_with_the_model_string(self):
        async def bob():
            await self.call("kali_shell")
            self.gateway.script[contract.INTERNAL_ROUTE_ENSURE] = lambda b: (409, {**RAM_PAYLOAD, "code": contract.ERR_RAM})
            return await self.call("job_spawn", {"tool_name": "kali_shell", "args": {"command": "bg"}})

        await self.run_as("bob", bob)
        job_id, task = next(iter(self.registry.tasks.items()))
        await task
        result = self.registry.results[job_id]
        self.assertEqual((result["success"], result["error"]), (False, contract.SANDBOX_UNAVAILABLE_RAM))
        self.assertEqual(router.job_phase(job_id).error_code, "ram")


# =============================================================================
# Progress polls and session-manager posts, both nodes
# =============================================================================

class TestNodesFollowTheHandle(Routing):

    def _cb(self):
        async def chunk(*args, **kwargs):
            return None
        return SimpleNamespace(on_tool_output_chunk=chunk, on_tool_start=chunk, on_tool_complete=chunk,
                               on_plan_start=chunk, on_plan_complete=chunk)

    async def _single(self, person, tool_name, tool_args):
        session = f"sess-{person}"
        state = {"messages": [], "current_iteration": 1, "current_phase": "exploitation",
                 "execution_trace": [], "_current_step": {"tool_name": tool_name, "tool_args": tool_args}}
        config = {"configurable": {"user_id": person, "project_id": "p1", "session_id": session,
                                   "tenant_user_id": "alice"}}
        return await tool_mod.execute_tool_node(
            state, config, tool_executor=self.executor, streaming_callbacks={session: self._cb()})

    async def _plan(self, person, tool_name, tool_args):
        session = f"sess-{person}"
        state = {"messages": [], "current_iteration": 1, "current_phase": "exploitation",
                 "execution_trace": [], "_current_plan": {"steps": [{"tool_name": tool_name, "tool_args": tool_args}]}}
        config = {"configurable": {"user_id": person, "project_id": "p1", "session_id": session,
                                   "tenant_user_id": "alice"}}
        return await plan_mod.execute_plan_node(
            state, config, tool_executor=self.executor, streaming_callbacks={session: self._cb()})

    def _host(self, person):
        handle_key = next(k for k in self.clients.by_key if k[0] == person)
        return contract.container_name(person, handle_key[1], handle_key[2])

    async def test_progress_urls_follow_handle_in_both_nodes(self):
        for node in (self._single, self._plan):
            with self.subTest(node=node.__name__):
                Recorder.calls = []
                self.clients = Clients()
                with mock.patch.object(router, "client_for", self.clients.client_for):
                    async def bob():
                        await self.call("kali_shell")
                        self.clients.of("bob").gate = asyncio.Event()

                        async def release():
                            await asyncio.sleep(0.2)
                            self.clients.of("bob").gate.set()

                        asyncio.create_task(release())
                        await node("bob", "execute_hydra", {"args": "-l a -P p ssh://t"})
                        self.clients.of("bob").gate = asyncio.Event()
                        asyncio.create_task(release())
                        await node("bob", "metasploit_console", {"command": "run"})

                    with mock.patch.object(tools, "PROGRESS_POLL_S", 0.01, create=True):
                        await self.run_as("bob", bob, tenant="alice")
                host = self._host("bob")
                token = self.gateway.token("bob")
                gets = [(u, h) for m, u, _j, h in Recorder.calls if m == "GET"]
                self.assertIn(f"http://{host}:8014/progress", {u for u, _h in gets})
                self.assertIn(f"http://{host}:8013/progress", {u for u, _h in gets})
                posts = [(u, j, h) for m, u, j, h in Recorder.calls if m == "POST"]
                self.assertEqual([u for u, _j, _h in posts], [f"http://{host}:8013/session-chat-map"])
                self.assertEqual(posts[0][1], {"msf_session_id": 3, "chat_session_id": "sess-bob"})
                for headers in [h for _u, h in gets] + [h for _u, _j, h in posts]:
                    self.assertEqual(headers.get("Authorization"), f"Bearer {token}")
                self.assertNotIn(SHARED_TOKEN, json.dumps(Recorder.calls))
                self.assertFalse(any("kali-sandbox" in u for _m, u, _j, _h in Recorder.calls))

    async def test_listener_post_follows_the_handle_in_both_nodes(self):
        for node in (self._single, self._plan):
            with self.subTest(node=node.__name__):
                Recorder.calls = []

                async def bob():
                    await node("bob", "kali_shell", {"command": "nc -lvnp 4444"})

                await self.run_as("bob", bob)
                host = self._host("bob")
                posts = [(u, h) for m, u, _j, h in Recorder.calls if m == "POST"]
                self.assertEqual(posts, [(f"http://{host}:8013/non-msf-sessions",
                                          {"Authorization": f"Bearer {self.gateway.token('bob')}"})])

    async def test_no_handle_means_no_post_in_per_user_mode(self):
        self.gateway.script[contract.INTERNAL_ROUTE_ENSURE] = lambda b: (403, {"code": contract.ERR_USER_REFUSED})

        async def bob():
            await self._single("bob", "kali_shell", {"command": "nc -lvnp 4444"})
            await self._plan("bob", "kali_shell", {"command": "nc -lvnp 4444"})

        await self.run_as("bob", bob)
        self.assertEqual(Recorder.calls, [], "a per-user run without a sandbox posted somewhere")


# =============================================================================
# Run stop and the emergency stop (D22)
# =============================================================================

class TestRunStop(Routing):

    def _kali(self, answer):
        real = httpx.AsyncClient
        transport = httpx.MockTransport(answer)

        def client(*args, **kwargs):
            kwargs.setdefault("transport", transport)
            if kwargs["transport"] is None:
                kwargs["transport"] = transport
            return real(*args, **kwargs)

        return mock.patch.object(httpx, "AsyncClient", client)

    async def _live_runs(self, people, during):
        """Each person's run made a Kali call and is still live while `during()` runs."""
        ready = {p: asyncio.Event() for p in people}
        done = asyncio.Event()

        def body(person):
            async def run():
                await self.call("kali_shell")
                ready[person].set()
                await done.wait()
            return run

        runs = [asyncio.create_task(self.run_as(p, body(p))) for p in people]
        for event in ready.values():
            await event.wait()
        try:
            return await during()
        finally:
            done.set()
            await asyncio.gather(*runs)

    async def test_stop_run_hits_runs_sandbox(self):
        seen = []

        def answer(request):
            seen.append((request.url.host, request.url.path, request.headers.get("authorization"),
                         json.loads(request.content)))
            return httpx.Response(200, json={"signalled": 2})

        async def during():
            with self._kali(answer):
                return await sandbox_runs.stop_sandbox_run("sess-bob")

        signalled = await self._live_runs(["alice", "bob"], during)
        self.assertEqual(signalled, 2)
        self.assertEqual(seen, [(self._host_of("bob"), sandbox_runs.STOP_PATH,
                                 f"Bearer {self.gateway.token('bob')}", {"run": "sess-bob"})])

    def _host_of(self, person):
        inst = self.gateway.instances[(person, "own")]["instance"]
        return contract.container_name(person, "own", inst)

    async def test_schedule_snapshots_the_sandboxes_before_the_run_ends(self):
        seen = []

        def answer(request):
            seen.append(request.url.host)
            return httpx.Response(200, json={"signalled": 1})

        async def during():
            return sandbox_runs.schedule_sandbox_stop("sess-bob")

        with self._kali(answer):
            task = await self._live_runs(["bob"], during)
            await task
        self.assertEqual(seen, [self._host_of("bob")])

    async def test_stop_all_hits_every_sandbox(self):
        seen = []

        def answer(request):
            seen.append((request.url.host, request.headers.get("authorization"), json.loads(request.content)))
            return httpx.Response(200, json={"signalled": 1})

        async def during():
            with self._kali(answer):
                return await sandbox_runs.stop_all_runs()

        result = await self._live_runs(["alice", "bob"], during)
        self.assertEqual((result["asked"], result["answered"], result["unavailable"]), (2, 2, []))
        self.assertEqual(sorted(seen), sorted([
            (self._host_of("alice"), f"Bearer {self.gateway.token('alice')}", {"run": "sess-alice"}),
            (self._host_of("bob"), f"Bearer {self.gateway.token('bob')}", {"run": "sess-bob"})]))

    async def test_stop_all_is_not_held_by_a_hung_sandbox(self):
        async def answer(request):
            if request.url.host == self._host_of("bob"):
                await asyncio.sleep(3600)
            return httpx.Response(200, json={"signalled": 1})

        async def during():
            with self._kali(answer), mock.patch.object(sandbox_runs, "FANOUT_TIMEOUT_S", 0.2):
                start = time.monotonic()
                result = await sandbox_runs.stop_all_runs()
                return result, time.monotonic() - start

        (result, elapsed) = await self._live_runs(["alice", "bob"], during)
        self.assertLess(elapsed, 0.2 + 1.0)
        bob_instance = self.gateway.instances[("bob", "own")]["instance"]
        self.assertEqual((result["asked"], result["answered"], result["unavailable"]), (2, 1, [bob_instance]))


# =============================================================================
# The shared manager holds the user servers only (WI-S10-1)
# =============================================================================

class LoadedTool:
    def __init__(self, name, server):
        self.name = name
        self.server = server

    async def ainvoke(self, args):
        return f"ok from {self.server}"


class SharedManager:
    """The orchestrator's MCPToolsManager over fake servers: what each load connected."""

    TOOLS = {"srv-a": ["create_issue"]}

    def __init__(self):
        self.generation = 0
        self.configs = {}
        self.loads = []
        self.disconnects = 0

    def replace_server_configs(self, configs):
        self.configs = dict(configs)

    async def reconnect(self, seen, reason="", force=False):
        ids = sorted(self.configs)
        self.loads.append(ids)
        self.generation += 1
        return self.generation, self.loaded_tools()

    def loaded_tools(self):
        return [LoadedTool(n, i) for i in sorted(self.configs) for n in self.TOOLS.get(i, [])]

    async def get_tools(self, *a, **k):
        return self.loaded_tools()

    async def disconnect(self):
        self.disconnects += 1
        self.configs = {}


SRV_A = {"id": "srv-a", "name": "A", "transport": "streamable_http", "url": "http://srv-a.invalid/mcp",
         "tools": [{"name": "create_issue", "purpose": "p", "when_to_use": "w", "args_format": "a",
                    "description": "d"}]}


class TestSharedManagerHoldsNoSystemServer(Routing):

    async def asyncSetUp(self):
        await super().asyncSetUp()
        import mcp_toolset_guard
        from orchestrator import AgentOrchestrator
        patches = [
            mock.patch("prompts.tool_registry.apply_mcp_manifests_to_registry",
                       side_effect=lambda servers: {t.name for srv in servers for t in srv.tools}),
            mock.patch("orchestrator_helpers.llm_url_guard._resolve_ips", return_value=[]),
            mock.patch.object(mcp_toolset_guard, "_guard", mcp_toolset_guard.McpToolsetGuard()),
        ]
        for p in patches:
            p.start()
            self.addAsyncCleanup(self._stop, p)
        orch = AgentOrchestrator.__new__(AgentOrchestrator)
        orch._initialized = True
        orch._mcp_manager = SharedManager()
        orch.tool_executor = tools.PhaseAwareToolExecutor(orch._mcp_manager, None)
        self.orch = orch

    async def test_it_loads_the_user_servers_only(self):
        out = await self.orch.reload_mcp_manifests([SRV_A], "owner-a")
        self.assertTrue(out["loaded"])
        self.assertEqual(self.orch._mcp_manager.loads, [["srv-a"]])
        self.assertIn("create_issue", self.orch.tool_executor._all_tools)
        self.assertNotIn("kali_shell", self.orch.tool_executor._all_tools)
        self.assertEqual({s["id"] for s in out["servers"]}, {"srv-a"})

    async def test_without_a_user_server_it_holds_nothing(self):
        out = await self.orch.reload_mcp_manifests([], "owner-a")
        self.assertTrue(out["loaded"])
        self.assertEqual((self.orch._mcp_manager.loads, self.orch._mcp_manager.disconnects), ([], 1))

    async def test_the_loaded_set_is_kept_across_runs(self):
        await self.orch._ensure_mcp_toolset([SRV_A], "owner-a")
        await self.orch._ensure_mcp_toolset([SRV_A], "owner-a")
        self.assertEqual(self.orch._mcp_manager.loads, [["srv-a"]])

    async def test_a_kali_call_never_loads_a_system_server_here(self):
        await self.orch._ensure_mcp_toolset([SRV_A], "owner-a")
        self.executor = self.orch.tool_executor

        async def bob():
            return await self.call("kali_shell")

        result = await self.run_as("bob", bob)
        self.assertEqual(result["output"], f"ok from {self.clients.of('bob').label}")
        self.assertEqual(self.orch._mcp_manager.loads, [["srv-a"]])

    async def test_tradecraft_s_browser_renders_in_the_persons_own_sandbox(self):
        from tradecraft import jobs, net

        await self.orch._ensure_mcp_toolset([SRV_A], "owner-a")
        with mock.patch.dict(sys.modules, {"api": SimpleNamespace(orchestrator=self.orch)}):
            with jobs.sandbox_person("bob"):
                rendered = await net.GuardedFetcher(jobs._agent_mcp_manager()).run_browser_script("print(1)")
        bob = self.clients.of("bob")
        self.assertEqual(rendered, (f"ok from {bob.label}", ""))
        self.assertEqual([c["tool"] for c in bob.calls], ["execute_playwright"])
        self.assertEqual(self.orch._mcp_manager.loads, [["srv-a"]])


if __name__ == "__main__":
    unittest.main()
