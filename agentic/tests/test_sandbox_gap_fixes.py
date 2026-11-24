"""Per-user sandbox gaps closed after the group 1 audit (gap_audit_all.md, agent side).

- A call that finds its sandbox gone is sent again at most once, and never for a background
  job or after a stop someone asked for (an emergency or operator stop): the command must
  not start a new sandbox and run again.
- The emergency stop cancels the Kali background jobs (all, or one person's).
- A job remembers who started it: another person neither sees nor stops it, and each
  person's sandbox jobs are capped on their own, not against every tenant's.
- Triage's CVE lookup checks the project without asking for it to be mounted.
- A sandbox restart is told to each Fireteam member and to the chat, each once.
- Tool servers that fail to load in a running sandbox are not read as the sandbox stopping.
- The bookkeeping posts to a sandbox and the run stop read their answers bounded.
- A run without the payload-settings block still learns its one reachable port.

Run: ./agentic/run_tests.sh tests/test_sandbox_gap_fixes.py
"""
import asyncio
import gzip
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

_TESTS_DIR = Path(__file__).resolve().parent
for _p in (str(_TESTS_DIR.parent), str(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import httpx  # noqa: E402

import job_runner  # noqa: E402
import sandbox_contract as contract  # noqa: E402
import sandbox_router as router  # noqa: E402
import sandbox_runs  # noqa: E402
import tools  # noqa: E402
import utils  # noqa: E402
from decision_check import RunActor, current_run_actor  # noqa: E402
from test_sandbox_executor_routing import Registry, Routing  # noqa: E402


def _gone(client):
    """The sandbox's connection closes mid-call and cannot be rebuilt."""
    client.failures.append(RuntimeError("Connection closed"))
    client.reconnect_fails = True


# =============================================================================
# No command sent again after its sandbox went away
# =============================================================================

class TestNoResend(Routing):

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.registry = Registry()
        p = mock.patch.object(job_runner, "get_registry", return_value=self.registry)
        p.start()
        self.addAsyncCleanup(self._stop, p)

    async def test_a_job_whose_sandbox_goes_away_fails_and_starts_no_sandbox(self):
        async def bob():
            await self.call("kali_shell")
            client = self.clients.of("bob")
            client.gate = asyncio.Event()
            await self.call("job_spawn", {"tool_name": "kali_shell", "args": {"command": "long scan"}})
            return client

        client = await self.run_as("bob", bob)
        job_id, task = next(iter(self.registry.tasks.items()))
        while len(client.calls) < 2:
            await asyncio.sleep(0.01)
        _gone(client)
        del self.gateway.instances[("bob", "own")]
        client.gate.set()
        await task
        result = self.registry.results[job_id]
        self.assertEqual((result["success"], result["error"]), (False, contract.SANDBOX_STOPPED))
        self.assertEqual([b["userId"] for b in self.gateway.ensures()], ["bob", "bob"],
                         "the run's and the job's ensure only: the job never started a new sandbox")
        self.assertEqual([c["args"].get("command") for c in client.calls], ["id", "long scan"])

    async def test_a_runs_call_is_not_sent_again_after_a_requested_stop(self):
        async def bob():
            await self.call("kali_shell")
            client = self.clients.of("bob")
            client.gate = asyncio.Event()
            call = asyncio.create_task(self.call("kali_shell", {"command": "again"}))
            while len(client.calls) < 2:
                await asyncio.sleep(0.01)
            # The webapp stops the sandbox (an operator's stop), then drops the person.
            del self.gateway.instances[("bob", "own")]
            await router.drop("bob")
            _gone(client)
            client.gate.set()
            return await call

        result = await self.run_as("bob", bob)
        self.assertEqual(result, {"success": False, "output": None, "error": contract.SANDBOX_STOPPED})
        self.assertEqual(len(self.gateway.ensures()), 1, "a stopped sandbox was started again")

    async def test_a_stop_marked_before_the_loss_is_honoured_too(self):
        """The emergency stop marks the person first; the webapp's own stop follows."""
        async def bob():
            await self.call("kali_shell")
            client = self.clients.of("bob")
            client.gate = asyncio.Event()
            call = asyncio.create_task(self.call("kali_shell", {"command": "again"}))
            while len(client.calls) < 2:
                await asyncio.sleep(0.01)
            router.note_stop_requested_all()
            del self.gateway.instances[("bob", "own")]
            _gone(client)
            client.gate.set()
            return await call

        result = await self.run_as("bob", bob)
        self.assertEqual(result["error"], contract.SANDBOX_STOPPED)
        self.assertEqual(len(self.gateway.ensures()), 1)

    async def test_the_next_unit_of_work_after_a_stop_starts_fresh(self):
        """A stop marks the calls in flight, not the person forever."""
        async def bob():
            await self.call("kali_shell")
            del self.gateway.instances[("bob", "own")]
            await router.drop("bob")
            return await self.call("kali_shell", {"command": "later"})

        result = await self.run_as("bob", bob)
        self.assertTrue(result["success"], result)
        self.assertEqual(len(self.gateway.ensures()), 2)


# =============================================================================
# Tool servers that do not load in a running sandbox
# =============================================================================

class TestToolServersDown(Routing):

    async def _with_unloadable_servers(self, running):
        async def client_for(handle):
            raise router.SandboxUnavailable("error", detail="mcp_connect_failed")

        async def bob():
            with mock.patch.object(router, "client_for", client_for), \
                    mock.patch.object(router, "instance_running", mock.AsyncMock(return_value=running)):
                return await self.call("kali_shell")

        return await self.run_as("bob", bob)

    async def test_a_running_sandbox_is_not_retired_and_the_model_is_not_told_stopped(self):
        result = await self._with_unloadable_servers(True)
        self.assertEqual(result, {"success": False, "output": None,
                                  "error": contract.SANDBOX_UNAVAILABLE_ERROR})
        self.assertEqual(len(self.gateway.ensures()), 1, "the running instance was not asked for again")

    async def test_a_sandbox_that_is_gone_still_takes_the_one_retry(self):
        result = await self._with_unloadable_servers(False)
        self.assertEqual(result["error"], contract.SANDBOX_STOPPED)
        self.assertEqual(len(self.gateway.ensures()), 2)

    async def test_instance_running_reads_the_list_and_starts_nothing(self):
        async def bob():
            await self.call("kali_shell")
            handle = router.current_handle()
            first = await router.instance_running(handle)
            del self.gateway.instances[("bob", "own")]
            return first, await router.instance_running(handle)

        self.assertEqual(await self.run_as("bob", bob), (True, False))
        self.assertEqual(len(self.gateway.ensures()), 1)


# =============================================================================
# Triage: checked, never mounted
# =============================================================================

class TestCheckProject(Routing):

    async def test_check_project_is_sent_and_no_mount_is_asked(self):
        with router.for_person("bob"):
            handle = await router.acquire("bob", project_id=None, kind="triage", check_project="p7")
        await router.release(handle)
        (body,) = self.gateway.ensures()
        self.assertEqual(body.get("checkProjectId"), "p7")
        self.assertNotIn("projectId", body)

    async def test_a_malformed_project_is_refused_before_any_ensure(self):
        with router.for_person("bob"):
            with self.assertRaises(router.SandboxUnavailable) as caught:
                await router.acquire("bob", project_id=None, kind="triage", check_project="../x")
        self.assertEqual(caught.exception.detail, contract.ERR_INVALID_PROJECT_ID)
        self.assertEqual(self.gateway.ensures(), [])

    async def test_a_refused_project_is_a_refusal(self):
        self.gateway.script[contract.INTERNAL_ROUTE_ENSURE] = lambda b: (403, {"code": contract.ERR_PROJECT_REFUSED})
        with router.for_person("bob"):
            with self.assertRaises(router.SandboxUnavailable) as caught:
                await router.acquire("bob", project_id=None, kind="triage", check_project="p7")
        self.assertEqual(caught.exception.reason, "refused")


# =============================================================================
# The restart note, once per Fireteam member and once for the chat
# =============================================================================

def _handle(instance):
    return router.SandboxHandle(
        user_id="bob", view=contract.VIEW_OWN, instance=instance,
        host=contract.container_name("bob", contract.VIEW_OWN, instance),
        token="t" * 24, tunnel_token="", ports=contract.PORTS, reverse_port=4444)


class TestRestartNotePerMember(unittest.TestCase):

    def setUp(self):
        router._reset()
        self.addCleanup(router._reset)
        self.token = current_run_actor.set(RunActor(user_id="bob", tenant_id="bob", project_id="p1",
                                                    session_id="chat-1"))
        self.addCleanup(current_run_actor.reset, self.token)

    def test_each_member_and_the_chat_are_told_once(self):
        old, new = _handle("aaaaaa"), _handle("bbbbbb")
        self.assertEqual(router.new_instance_note(old), "")
        with router.note_unit("w1:m1"):
            note = router.new_instance_note(new)
            self.assertTrue(note.startswith("[Kali sandbox restarted]"), note)
            self.assertEqual(router.new_instance_note(new), "")
        with router.note_unit("w1:m2"):
            self.assertTrue(router.new_instance_note(new).startswith("[Kali sandbox restarted]"))
        # The chat still holds the old instance: the members did not use up its note.
        self.assertTrue(router.new_instance_note(new).startswith("[Kali sandbox restarted]"))
        self.assertEqual(router.new_instance_note(new), "")

    def test_a_member_on_the_instance_the_chat_knows_is_told_nothing(self):
        same = _handle("aaaaaa")
        self.assertEqual(router.new_instance_note(same), "")
        with router.note_unit("w1:m1"):
            self.assertEqual(router.new_instance_note(same), "")

    def test_the_deploy_node_scopes_each_member(self):
        import importlib
        import inspect
        deploy = importlib.import_module("orchestrator_helpers.nodes.fireteam_deploy_node")
        self.assertIn("sandbox_router.note_unit(", inspect.getsource(deploy))


# =============================================================================
# Jobs: their owner, their cap, the emergency stop
# =============================================================================

class _Store(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patches = [mock.patch.object(job_runner, "WORKSPACE_ROOT", Path(self.tmp.name)),
                   mock.patch.object(job_runner, "_governed_max_jobs", return_value=1)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.reg = job_runner.JobRegistry()
        self.gate = asyncio.Event()

    async def asyncTearDown(self):
        self.gate.set()
        for h in list(self.reg._jobs.values()):
            if h.task is not None:
                await asyncio.gather(h.task, return_exceptions=True)

    def runner(self):
        async def run(name, args, append_log):
            await self.gate.wait()
            return {"success": True, "output": "done"}
        return run

    async def spawn(self, owner, *, in_sandbox=True, project="p1"):
        return await self.reg.spawn(project, "kali_shell", {"command": "x"}, self.runner(),
                                    owner_user=owner, owner_view="own", in_sandbox=in_sandbox)


class TestJobCapPerPerson(_Store):

    async def test_one_persons_jobs_never_refuse_another_persons(self):
        first = await self.spawn("alice")
        self.assertIn("job_id", first)
        second = await self.spawn("alice")
        self.assertIn("your Kali sandbox", second.get("error", ""))
        self.assertIn("job_id", await self.spawn("bob"), "bob was refused for alice's job")

    async def test_jobs_in_the_agent_keep_their_own_count(self):
        await self.spawn("alice")
        self.assertIn("job_id", await self.spawn("alice", in_sandbox=False))
        self.assertIn("error", await self.spawn("bob", in_sandbox=False))

    async def test_the_sandbox_jobs_together_are_bounded(self):
        with mock.patch.object(job_runner, "_governed_max_jobs", return_value=10), \
                mock.patch.object(job_runner, "SANDBOX_JOBS_MAX", 2):
            await self.spawn("alice")
            await self.spawn("bob")
            refused = await self.spawn("carol")
        self.assertIn("error", refused)


class TestJobOwner(_Store):

    async def test_the_owner_is_kept_in_the_record_and_survives_a_restart(self):
        job_id = (await self.spawn("alice"))["job_id"]
        self.gate.set()
        await self.reg._jobs[job_id].task
        restarted = job_runner.JobRegistry()
        row = restarted.status("p1", job_id)
        self.assertEqual(row.get("owner_user"), "alice")
        self.assertTrue(job_runner.owned_by_another(row, "bob"))
        self.assertFalse(job_runner.owned_by_another(row, "alice"))

    def test_a_row_naming_no_one_or_not_a_person_stays_the_projects(self):
        for row in ({}, {"owner_user": None}, {"owner_user": "../x"}, {"owner_user": 7}, "x"):
            self.assertFalse(job_runner.owned_by_another(row, "bob"), row)
        self.assertTrue(job_runner.owned_by_another({"owner_user": "alice"}, ""))

    async def test_a_malformed_owner_is_not_kept(self):
        job_id = (await self.reg.spawn("p1", "kali_shell", {}, self.runner(),
                                       owner_user="a b", in_sandbox=True))["job_id"]
        handle = self.reg._jobs[job_id]
        self.assertEqual((handle.owner_user, handle.in_sandbox), (None, False))


class TestEmergencyCancelsJobs(_Store):

    async def test_one_person_or_everyone_and_never_the_agents_own(self):
        with mock.patch.object(job_runner, "_governed_max_jobs", return_value=None):
            a = (await self.spawn("alice"))["job_id"]
            b = (await self.spawn("bob"))["job_id"]
            agent = (await self.spawn("alice", in_sandbox=False))["job_id"]
        await asyncio.sleep(0)
        self.assertEqual(await self.reg.cancel_sandbox_jobs("alice"), 1)
        status = lambda jid: self.reg._jobs[jid].status
        self.assertEqual((status(a), status(b), status(agent)), ("cancelled", "running", "running"))
        self.assertEqual(await self.reg.cancel_sandbox_jobs(None), 1)
        self.assertEqual((status(b), status(agent)), ("cancelled", "running"))


class TestChatJobToolsAreTheStartersOwn(Routing):

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.registry = job_runner.JobRegistry()
        for p in (mock.patch.object(job_runner, "WORKSPACE_ROOT", Path(self.tmp.name)),
                  mock.patch.object(job_runner, "get_registry", return_value=self.registry),
                  mock.patch.object(job_runner, "_governed_max_jobs", return_value=None)):
            p.start()
            self.addAsyncCleanup(self._stop, p)

    async def asyncTearDown(self):
        await self.registry.cancel_sandbox_jobs(None)
        await super().asyncTearDown()

    async def test_another_person_neither_sees_nor_stops_the_job(self):
        async def alice():
            await self.call("kali_shell")
            self.clients.of("alice").gate = asyncio.Event()
            spawned = await self.call("job_spawn", {"tool_name": "kali_shell", "args": {"command": "scan"}})
            return eval(spawned["output"])["job_id"]  # noqa: S307 - the tool's own dict repr

        job_id = await self.run_as("alice", alice, tenant="owner")

        async def bob():
            return (await self.call("job_status", {"job_id": job_id}),
                    await self.call("job_cancel", {"job_id": job_id}),
                    await self.call("job_list", {}))

        status, cancel, listing = await self.run_as("bob", bob, tenant="owner")
        self.assertIn("unknown job", status["output"])
        self.assertIn("unknown job", cancel["output"])
        self.assertNotIn(job_id, listing["output"])
        self.assertEqual(self.registry._jobs[job_id].status, "running", "bob stopped alice's job")

        async def alice_again():
            return await self.call("job_list", {})

        self.assertIn(job_id, (await self.run_as("alice", alice_again, tenant="owner"))["output"])
        handle = self.registry._jobs[job_id]
        self.assertEqual((handle.owner_user, handle.owner_view, handle.in_sandbox), ("alice", "own", True))


# =============================================================================
# Bounded reads: the bookkeeping posts and the run stop
# =============================================================================

def _client_with(answer):
    real = httpx.AsyncClient
    transport = httpx.MockTransport(answer)

    def client(*args, **kwargs):
        kwargs["transport"] = transport
        return real(*args, **kwargs)

    return client


class TestBoundedReads(unittest.IsolatedAsyncioTestCase):

    def handle(self):
        return _handle("cccccc")

    async def test_a_compressed_answer_to_a_bookkeeping_post_is_never_inflated(self):
        bomb = gzip.compress(b"0" * (8 * 1024 * 1024))
        seen = []

        def answer(request):
            seen.append(dict(request.headers))
            return httpx.Response(200, content=bomb, headers={"content-encoding": "gzip"})

        with mock.patch.object(tools.httpx, "AsyncClient", _client_with(answer)), \
                mock.patch.object(tools, "note_kali_refusal") as noted:
            await tools.post_session_manager(self.handle(), "/session-chat-map", {"msf_session_id": 1})
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0].get("accept-encoding"), "identity")
        self.assertEqual(seen[0].get("authorization"), f"Bearer {'t' * 24}")
        noted.assert_not_called()

    async def test_an_oversized_answer_is_refused_and_never_raises(self):
        def answer(request):
            return httpx.Response(200, content=b"x" * (tools.SESSION_POST_MAX_BYTES + 1))

        with mock.patch.object(tools.httpx, "AsyncClient", _client_with(answer)):
            await tools.post_session_manager(self.handle(), "/non-msf-sessions", {"type": "listener"})

    async def test_no_handle_no_post(self):
        with mock.patch.object(tools.httpx, "AsyncClient") as client:
            await tools.post_session_manager(None, "/session-chat-map", {})
        client.assert_not_called()

    async def test_the_run_stop_reads_its_answer_bounded(self):
        def huge(request):
            return httpx.Response(200, content=b"{" + b" " * (sandbox_runs.STOP_ANSWER_MAX_BYTES + 1) + b"}")

        def compressed(request):
            return httpx.Response(200, content=gzip.compress(b'{"signalled": 3}'),
                                  headers={"content-encoding": "gzip"})

        def fine(request):
            return httpx.Response(200, json={"signalled": 2})

        for answer, want in ((huge, None), (compressed, None), (fine, 2)):
            with mock.patch("httpx.AsyncClient", _client_with(answer)):
                got = await sandbox_runs._post_stop("http://sbx.test:8000/runs/stop", {}, "run-1", 2.0)
            self.assertEqual(got, want, answer.__name__)


# =============================================================================
# The one reachable port, without the full payload-settings block
# =============================================================================

def _plan(**fields):
    base = dict(mode="bind", lhost=None, lport=None, bind_port=None, project_lport=None, tunnel=None,
                pool_port=None, port_state="no_pool", unknown="", ngrok="disabled", chisel="disabled",
                https=False)
    base.update(fields)
    return utils.PayloadPlan(**base)


class TestReachablePortNote(unittest.TestCase):

    def note(self, **fields):
        with mock.patch.object(utils, "payload_plan", return_value=_plan(**fields)):
            return utils.get_reachable_port_note()

    def test_each_mode_names_what_a_target_can_reach(self):
        pool = self.note(mode="reverse", lhost="203.0.113.5", lport=40001, pool_port=40001,
                         port_state="assigned")
        self.assertIn("`40001`", pool)
        self.assertIn("`203.0.113.5:40001`", pool)
        tunnel = self.note(mode="reverse", tunnel="ngrok", lhost="0.tcp.ngrok.io", lport=12345, ngrok="on")
        self.assertIn("`4444`", tunnel)
        self.assertIn("`0.tcp.ngrok.io:12345`", tunnel)
        self.assertIn("ngrok", tunnel)
        self.assertIn("no LHOST", self.note(mode="ask_lhost", lport=40001, pool_port=40001))
        self.assertIn("$MSF_REVERSE_PORT", self.note(mode="unknown", port_state="unknown"))
        for mode in ("bind", "ask_bind"):
            self.assertIn("never serve a file", self.note(mode=mode))
        for text in (pool, tunnel):
            self.assertTrue(text.startswith("### Pre-Configured Payload Settings"), text)

    def test_when_the_summary_is_shown(self):
        from prompts import reachable_port_note_needed as needed
        self.assertFalse(needed("exploitation", True, "cve_exploit"), "the full block is shown")
        self.assertTrue(needed("exploitation", False, "cve_exploit"), "stateless mode")
        self.assertTrue(needed("informational", True, "xxe"))
        self.assertTrue(needed("informational", True, "path_traversal"))
        self.assertFalse(needed("informational", True, "sql_injection"))
        self.assertFalse(needed("informational", True, "phishing_social_engineering"), "full block")
        with mock.patch("prompts.resolve_user_skill",
                        return_value={"content": 'serve it on the "Pre-Configured Payload Settings" port'}):
            self.assertTrue(needed("informational", True, "user_skill:abc"))
        with mock.patch("prompts.resolve_user_skill", return_value={"content": "plain recon"}):
            self.assertFalse(needed("informational", True, "user_skill:abc"))

    def test_the_think_node_renders_it_when_the_block_is_off(self):
        import importlib
        import inspect
        # The package re-exports the node functions under the modules' names.
        think_node = importlib.import_module("orchestrator_helpers.nodes.think_node")
        src = inspect.getsource(think_node.think_node)
        self.assertIn("reachable_port_note_needed(phase", src)
        self.assertIn("get_reachable_port_note()", src)


if __name__ == "__main__":
    unittest.main()
