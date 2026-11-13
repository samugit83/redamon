"""RBAC OQ-41 / NF-06: the agent holds ONE user MCP toolset for the whole process.

A run whose owner's MCP server set differs from the loaded one is refused with
`mcp_toolset_busy` while another owner's run on a different set is live; otherwise
the owner's set is loaded, and the run streams only once it is loaded. The reload
a member's MCP save triggers goes through the same guard (deferred, never applied
under another owner's live run). A set is recorded as loaded only after it loaded:
a load that fails drops every user MCP tool, so no call reaches the previous
owner's servers, and the next admission loads again.
"""
import asyncio
import os
import unittest
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest import mock

os.environ.setdefault("WEBAPP_API_URL", "http://fake-webapp")

import project_settings as ps
import agent_context as ac
import mcp_toolset_guard as guard_mod
from mcp_toolset_guard import McpToolsetBusy, McpToolsetGuard, server_set_hash

MASTER = "mcp-guard-master-key"


def _tool(name):
    return {"name": name, "purpose": "p", "when_to_use": "w", "args_format": "a", "description": "d"}


# Two owners' servers that both declare `create_issue`: a call by that name must reach
# the server of the run's own owner, never the other one's (with its token).
SRV_A = {"id": "srv-a", "name": "A", "transport": "streamable_http",
         "url": "http://a.example/mcp", "tools": [_tool("create_issue")]}
SRV_B = {"id": "srv-b", "name": "B", "transport": "streamable_http",
         "url": "http://b.example/mcp", "tools": [_tool("create_issue")]}


class _FreshGuard(unittest.TestCase):
    def setUp(self):
        self.guard = McpToolsetGuard()
        patcher = mock.patch.object(guard_mod, "_guard", self.guard)
        patcher.start()
        self.addCleanup(patcher.stop)


class GuardRules(_FreshGuard):
    def test_different_set_refused_while_another_owners_run_is_live(self):
        self.guard.admit_run("owner-a", [SRV_A])
        with self.assertLogs("mcp_toolset_guard", "WARNING") as logs, \
                self.assertRaises(McpToolsetBusy) as ctx:
            self.guard.admit_run("owner-b", [SRV_B])
        self.assertEqual(ctx.exception.code, "mcp_toolset_busy")
        self.assertIn("[rbac] mcp toolset busy", "\n".join(logs.output))

    def test_an_empty_set_is_a_different_set(self):
        # A member with no servers must not run on another owner's servers (and tokens).
        self.guard.admit_run("owner-a", [SRV_A])
        with self.assertRaises(McpToolsetBusy):
            self.guard.admit_run("owner-b", [])

    def test_same_set_allowed(self):
        self.guard.admit_run("owner-a", [SRV_A])
        self.guard.admit_run("owner-b", [dict(SRV_A)])

    def test_no_live_run_admits_another_set(self):
        lease = self.guard.admit_run("owner-a", [SRV_A])
        self.guard.release_run(lease)
        self.guard.admit_run("owner-b", [SRV_B])

    def test_the_owner_may_change_its_own_set_while_its_own_run_is_live(self):
        self.guard.admit_run("owner-a", [SRV_A])
        self.guard.admit_run("owner-a", [SRV_A, SRV_B])

    def test_admission_records_nothing_only_a_finished_load_does(self):
        self.guard.admit_run("owner-a", [SRV_A])
        self.assertIsNone(self.guard.loaded_hash)
        self.assertTrue(self.guard.admit_reload("owner-a", [SRV_A]))
        self.assertIsNone(self.guard.loaded_hash)
        self.guard.record_loaded([SRV_A], "owner-a")
        self.assertEqual(self.guard.loaded_hash, server_set_hash([SRV_A]))
        self.assertEqual(self.guard.loaded_servers, [SRV_A])

    def test_a_failed_load_leaves_no_set_recorded(self):
        self.guard.record_loaded([SRV_A], "owner-a")
        self.guard.clear_loaded()
        self.assertIsNone(self.guard.loaded_hash)
        self.assertIsNone(self.guard.loaded_servers)

    def test_releasing_twice_is_harmless(self):
        lease = self.guard.admit_run("owner-a", [SRV_A])
        self.guard.release_run(lease)
        self.guard.release_run(lease)
        self.guard.admit_run("owner-b", [SRV_B])

    def test_a_save_triggered_reload_is_deferred_while_another_owners_run_is_live(self):
        self.guard.admit_run("owner-a", [SRV_A])
        with self.assertLogs("mcp_toolset_guard", "WARNING") as logs:
            self.assertFalse(self.guard.admit_reload("owner-b", [SRV_B]))
        self.assertIn("[rbac] mcp toolset busy", "\n".join(logs.output))
        self.assertIsNone(self.guard.loaded_hash)

    def test_a_reload_with_no_owner_is_deferred_under_any_live_run_on_another_set(self):
        self.guard.admit_run("owner-a", [SRV_A])
        self.assertFalse(self.guard.admit_reload(None, [SRV_B]))

    def test_a_reload_of_the_loaded_set_is_never_deferred(self):
        self.guard.admit_run("owner-a", [SRV_A])
        self.assertTrue(self.guard.admit_reload(None, [SRV_A]))

    def test_a_disabled_server_does_not_make_a_different_set(self):
        # A disabled server loads no tool and opens no connection: its owner's toolset
        # is the empty one, so it must not refuse an owner with no server at all.
        disabled = {**SRV_A, "enabled": False}
        self.assertEqual(server_set_hash([disabled]), server_set_hash([]))
        self.assertNotEqual(server_set_hash([disabled, SRV_B]), server_set_hash([]))
        self.guard.admit_run("owner-a", [disabled])
        self.guard.admit_run("owner-b", [])

    def test_the_hash_ignores_key_order(self):
        self.assertEqual(server_set_hash([{"a": 1, "b": 2}]), server_set_hash([{"b": 2, "a": 1}]))
        self.assertEqual(server_set_hash(None), server_set_hash([]))


def _orchestrator():
    from orchestrator import AgentOrchestrator
    orch = AgentOrchestrator.__new__(AgentOrchestrator)
    orch._initialized = True
    orch._streaming_callbacks, orch._guidance_queues, orch._graph_view_cyphers = {}, {}, {}
    return orch


class _McpManager:
    """An MCP client over fake servers: each configured server exposes the tools in
    TOOLS, each tool remembering its server. A server in `down` fails the whole load
    (as MultiServerMCPClient.get_tools does); `gate`, when set, holds every load open."""

    TOOLS = {"nmap": ["execute_nmap"], "srv-a": ["create_issue"], "srv-b": ["create_issue"]}

    def __init__(self):
        self.generation = 0
        self.configs = {}
        self.down = set()
        self.loads = []
        self.gate = None

    def replace_server_configs(self, configs):
        self.configs = dict(configs)

    async def reconnect(self, seen, reason="", force=False):
        ids = sorted(self.configs)
        self.loads.append(ids)
        if self.gate is not None:
            await self.gate.wait()
        # A real load takes time: a run that does not wait for it starts first.
        await asyncio.sleep(0.01)
        if self.down & set(ids):
            return self.generation, []
        self.generation += 1
        return self.generation, [SimpleNamespace(name=n, server=i) for i in ids for n in self.TOOLS.get(i, [])]


def _tool_server(orch, name):
    tool = orch.tool_executor._all_tools.get(name)
    return getattr(tool, "server", None)


class _Loading(_FreshGuard):
    """A real orchestrator reload over a fake MCP client and the real tool executor."""

    def setUp(self):
        super().setUp()
        from mcp_registry import MCPServer
        system = [MCPServer(id="nmap", name="nmap", transport="sse", url="http://kali.test/sse")]
        for target, kw in (
                ("tools._build_system_mcp_servers", {"return_value": system}),
                ("prompts.tool_registry.apply_mcp_manifests_to_registry",
                 {"side_effect": lambda servers: {t.name for s in servers for t in s.tools}})):
            patcher = mock.patch(target, **kw)
            patcher.start()
            self.addCleanup(patcher.stop)

    def _orch(self):
        from tools import PhaseAwareToolExecutor
        orch = _orchestrator()
        orch._mcp_manager = _McpManager()
        orch.tool_executor = PhaseAwareToolExecutor(orch._mcp_manager, None)
        return orch


def _api():
    @asynccontextmanager
    async def fake_lifespan(_app):
        yield

    with mock.patch("api.lifespan", fake_lifespan):
        import api as api_module
        from fastapi.testclient import TestClient
    return api_module, TestClient(api_module.app, headers={"x-internal-key": MASTER})


class ReloadRoute(_Loading):
    def setUp(self):
        super().setUp()
        env = mock.patch.dict(os.environ, {"INTERNAL_API_KEY": MASTER})
        env.start()
        self.addCleanup(env.stop)
        self.api, self.client = _api()
        self.orch = self._orch()
        patcher = mock.patch.object(self.api, "orchestrator", self.orch)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_members_save_triggered_reload_is_deferred_while_another_owners_run_is_live(self):
        self.guard.admit_run("owner-a", [SRV_A])
        with self.assertLogs("mcp_toolset_guard", "WARNING") as logs:
            r = self.client.post("/mcp/reload", json={"ownerId": "owner-b", "userMcpServers": [SRV_B]})
        self.assertEqual(r.status_code, 202, r.text)
        body = r.json()
        self.assertEqual((body["deferred"], body["code"]), (True, "mcp_toolset_busy"))
        self.assertEqual(self.orch._mcp_manager.loads, [])
        self.assertIn("owner=owner-b", "\n".join(logs.output))
        self.assertIsNone(self.guard.loaded_hash)

    def test_the_owners_own_save_reloads_while_only_their_run_is_live(self):
        self.guard.admit_run("owner-a", [SRV_A])
        r = self.client.post("/mcp/reload", json={"ownerId": "owner-a", "userMcpServers": [SRV_B]})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(self.orch._mcp_manager.loads, [["nmap", "srv-b"]])
        self.assertEqual(self.guard.loaded_hash, server_set_hash([SRV_B]))

    def test_no_live_run_reloads_the_saved_set(self):
        r = self.client.post("/mcp/reload", json={"ownerId": "owner-b", "userMcpServers": [SRV_B]})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(self.orch._mcp_manager.loads, [["nmap", "srv-b"]])
        self.assertEqual(self.guard.loaded_hash, server_set_hash([SRV_B]))
        self.assertEqual(_tool_server(self.orch, "create_issue"), "srv-b")

    def test_an_admins_reload_with_no_body_reloads_the_loaded_set_even_under_a_live_run(self):
        r = self.client.post("/mcp/reload", json={"ownerId": "owner-a", "userMcpServers": [SRV_A]})
        self.assertEqual(r.status_code, 200, r.text)
        self.guard.admit_run("owner-a", [SRV_A])
        r = self.client.post("/mcp/reload", json={})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(self.orch._mcp_manager.loads, [["nmap", "srv-a"], ["nmap", "srv-a"]])
        self.assertEqual(self.guard.loaded_hash, server_set_hash([SRV_A]))

    def test_a_save_that_fails_to_load_is_not_recorded_and_says_so(self):
        self.orch._mcp_manager.down = {"srv-b"}
        r = self.client.post("/mcp/reload", json={"ownerId": "owner-b", "userMcpServers": [SRV_B]})
        self.assertEqual(r.status_code, 502, r.text)
        self.assertEqual((r.json()["code"], r.json()["loaded"]), ("mcp_toolset_load_failed", False))
        self.assertIsNone(self.guard.loaded_hash)


class ReloadRecordsTheSet(_Loading):
    def _reload(self, orch, raw, owner=None):
        return asyncio.run(orch.reload_mcp_manifests(raw, owner))

    def test_every_reload_updates_the_stored_hash(self):
        orch = self._orch()
        self._reload(orch, [SRV_A])
        self.assertEqual(self.guard.loaded_hash, server_set_hash([SRV_A]))
        self._reload(orch, [SRV_B])
        self.assertEqual(self.guard.loaded_hash, server_set_hash([SRV_B]))
        self.assertEqual(self.guard.loaded_servers, [SRV_B])

    def test_a_reload_with_no_list_reloads_the_loaded_set_not_another_projects_settings(self):
        orch = self._orch()
        self._reload(orch, [SRV_A])
        # The module-global settings are the last-loaded project's, possibly another owner's.
        ps._settings = {**ps.DEFAULT_AGENT_SETTINGS, "USER_MCP_SERVERS": [SRV_B]}
        self.addCleanup(setattr, ps, "_settings", None)
        out = self._reload(orch, None)
        self.assertEqual(self.guard.loaded_hash, server_set_hash([SRV_A]))
        self.assertEqual([s["id"] for s in out["servers"] if s["id"] != "nmap"], ["srv-a"])

    def test_a_failed_load_drops_the_previous_owners_tools_and_records_nothing(self):
        orch = self._orch()
        self._reload(orch, [SRV_A], "owner-a")
        self.assertEqual(_tool_server(orch, "create_issue"), "srv-a")
        # owner-b saves a server that cannot be reached but declares the same tool name.
        orch._mcp_manager.down = {"srv-b"}
        self._reload(orch, [SRV_B], "owner-b")
        self.assertIsNone(orch.tool_executor._all_tools.get("create_issue"),
                          "a call by that name would reach owner-a's server with owner-a's token")
        self.assertIsNone(self.guard.loaded_hash)
        # The system tools stay: the fallback loads the system servers alone.
        self.assertEqual(_tool_server(orch, "execute_nmap"), "nmap")

    def test_a_load_cut_short_records_nothing(self):
        # A stopped run can cancel its own load midway: the client then holds the new
        # configs, so the previous record must not let the next run skip its load.
        orch = self._orch()
        self._reload(orch, [SRV_A], "owner-a")
        orch._mcp_manager.gate = asyncio.Event()

        async def main():
            task = asyncio.create_task(orch.reload_mcp_manifests([SRV_B], "owner-b"))
            while len(orch._mcp_manager.loads) < 2:
                await asyncio.sleep(0)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

        asyncio.run(main())
        self.assertIsNone(self.guard.loaded_hash)

    def test_a_failed_load_counts_only_the_servers_it_tried_to_load(self):
        # A disabled server is never part of the load (server_set_hash leaves it out),
        # so the warning names only the enabled servers that did not load.
        orch = self._orch()
        orch._mcp_manager.down = {"srv-b"}
        disabled = {**SRV_A, "id": "srv-c", "name": "C", "tools": [_tool("list_issues")], "enabled": False}
        with self.assertLogs("orchestrator", "WARNING") as logs:
            self._reload(orch, [disabled, SRV_B], "owner-b")
        self.assertIn("MCP manifest reload failed: 1 user server(s) not loaded", "\n".join(logs.output))

    def test_a_failed_load_with_the_system_servers_down_leaves_no_mcp_tool(self):
        orch = self._orch()
        self._reload(orch, [SRV_A], "owner-a")
        orch._mcp_manager.down = {"srv-b", "nmap"}
        self._reload(orch, [SRV_B], "owner-b")
        self.assertIsNone(orch.tool_executor._all_tools.get("create_issue"))
        self.assertIsNone(orch.tool_executor._all_tools.get("execute_nmap"))
        self.assertIsNone(self.guard.loaded_hash)


class _Graph:
    """A graph whose run stays live until released. It records, as the run starts,
    which server would answer each tool name: what the run's first tool call reaches."""

    def __init__(self, orch=None, release=False, state=None):
        self.orch = orch
        self.release = asyncio.Event()
        if release:
            self.release.set()
        self.started = asyncio.Event()
        self.seen = None
        self.state = state or {"messages": []}

    async def aget_state(self, _config):
        return SimpleNamespace(values=self.state)

    async def astream(self, _input, _config, stream_mode="values"):
        if self.orch is not None:
            self.seen = {"create_issue": _tool_server(self.orch, "create_issue"),
                         "loaded": guard_mod.toolset_guard().loaded_hash}
        self.started.set()
        await self.release.wait()
        yield {"task_complete": True}


class _Callback:
    def __init__(self):
        self.errors = []
        self.resent = []

    async def on_error(self, message, recoverable=True, **details):
        self.errors.append({"message": message, "recoverable": recoverable, **details})

    async def on_response(self, *a, **k):
        pass

    async def resend_pending_request(self, kind, request):
        self.resent.append((kind, request))


def _broker():
    @asynccontextmanager
    async def run_scope(*_a, **_k):
        yield SimpleNamespace(final_state=None)
    return SimpleNamespace(run_scope=run_scope)


# A wait that a broken guard would make endless fails the test instead.
BOUND_S = 10


class _Runs(_Loading):
    def setUp(self):
        super().setUp()
        for target, value in (("orchestrator.get_broker", _broker),
                              ("orchestrator.emit_streaming_events", mock.AsyncMock())):
            patcher = mock.patch(target, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.addCleanup(ps._settings_ctx.set, None)

    def _as_owner(self, orch, owner, servers, graph):
        def apply(_project_id):
            ps._settings_ctx.set({**ps.DEFAULT_AGENT_SETTINGS, "USER_MCP_SERVERS": servers})
            ac.current_llm.set(object())
        orch._apply_project_settings = apply
        orch.graph = graph

    def _owner_run(self, orch, owner, servers, graph):
        self._as_owner(orch, owner, servers, graph)
        cb = _Callback()
        coro = orch.invoke_with_streaming("q", owner, f"p-{owner}", f"s-{owner}", cb)
        return coro, cb


class RunAdmission(_Runs):
    """The guard at run start, through the orchestrator's streaming entry points."""

    def test_a_run_on_another_set_is_refused_while_another_owners_run_is_live(self):
        orch = self._orch()

        async def main():
            graph_a = _Graph()
            run_a, _ = self._owner_run(orch, "owner-a", [SRV_A], graph_a)
            task_a = asyncio.create_task(run_a)
            await asyncio.wait_for(graph_a.started.wait(), BOUND_S)
            run_b, cb_b = self._owner_run(orch, "owner-b", [SRV_B], _Graph())
            try:
                with self.assertLogs("mcp_toolset_guard", "WARNING") as logs:
                    resp_b = await asyncio.wait_for(run_b, BOUND_S)
            finally:
                graph_a.release.set()
                await asyncio.wait_for(task_a, BOUND_S)
            return resp_b, cb_b, logs

        resp_b, cb_b, logs = asyncio.run(main())
        [err] = cb_b.errors
        self.assertEqual((err["code"], err["recoverable"]), ("mcp_toolset_busy", False))
        self.assertEqual(resp_b.error, err["message"])
        self.assertNotIn("owner-a", err["message"])
        self.assertIn("[rbac] mcp toolset busy", "\n".join(logs.output))
        self.assertEqual(orch._mcp_manager.loads, [["nmap", "srv-a"]])

    def test_the_run_streams_only_after_its_owners_set_is_loaded(self):
        orch = self._orch()

        async def main():
            graph = _Graph(orch, release=True)
            run, cb = self._owner_run(orch, "owner-a", [SRV_A], graph)
            await asyncio.wait_for(run, BOUND_S)
            return graph, cb

        graph, cb = asyncio.run(main())
        self.assertEqual(cb.errors, [])
        self.assertEqual(graph.seen, {"create_issue": "srv-a", "loaded": server_set_hash([SRV_A])})
        self.assertEqual(self.guard.loaded_hash, server_set_hash([SRV_A]))

    def test_a_run_waits_for_a_reload_in_progress_and_streams_on_its_own_set(self):
        # owner-b's save reload is connecting when owner-a's run starts: the run must
        # not reach owner-b's tools (and token) while its own set waits in the queue.
        orch = self._orch()
        orch._mcp_manager.gate = asyncio.Event()

        async def main():
            save_b = asyncio.create_task(orch.reload_mcp_manifests([SRV_B], "owner-b"))
            while not orch._mcp_manager.loads:
                await asyncio.sleep(0)
            graph = _Graph(orch, release=True)
            run, cb = self._owner_run(orch, "owner-a", [SRV_A], graph)
            task = asyncio.create_task(run)
            await asyncio.sleep(0.05)
            orch._mcp_manager.gate.set()
            await asyncio.wait_for(task, BOUND_S)
            await asyncio.wait_for(save_b, BOUND_S)
            return graph, cb

        graph, cb = asyncio.run(main())
        self.assertEqual(cb.errors, [])
        self.assertEqual(graph.seen["create_issue"], "srv-a")
        self.assertEqual(orch._mcp_manager.loads, [["nmap", "srv-b"], ["nmap", "srv-a"]])

    def test_a_resumed_run_executes_on_its_own_set_not_the_last_runs(self):
        # owner-a pauses for a dangerous-tool confirmation (no lease while paused);
        # owner-b's run loads owner-b's set and ends; owner-a confirms.
        orch = self._orch()

        async def main():
            run_a, _ = self._owner_run(orch, "owner-a", [SRV_A], _Graph(release=True))
            await asyncio.wait_for(run_a, BOUND_S)
            run_b, _ = self._owner_run(orch, "owner-b", [SRV_B], _Graph(release=True))
            await asyncio.wait_for(run_b, BOUND_S)
            graph = _Graph(orch, release=True, state={"awaiting_tool_confirmation": True,
                                                      "tool_confirmation_pending": _PENDING})
            self._as_owner(orch, "owner-a", [SRV_A], graph)
            cb = _Callback()
            await asyncio.wait_for(orch.resume_after_tool_confirmation_with_streaming(
                "s-owner-a", "owner-a", "p-owner-a", "approve", None, cb), BOUND_S)
            return graph, cb

        graph, cb = asyncio.run(main())
        self.assertEqual(cb.errors, [])
        self.assertEqual(graph.seen["create_issue"], "srv-a")

    def test_a_run_whose_set_failed_to_load_reaches_no_other_owners_tool_and_retries(self):
        orch = self._orch()

        async def main():
            run_a, _ = self._owner_run(orch, "owner-a", [SRV_A], _Graph(release=True))
            await asyncio.wait_for(run_a, BOUND_S)
            orch._mcp_manager.down = {"srv-b"}
            graph = _Graph(orch, release=True)
            run_b, _ = self._owner_run(orch, "owner-b", [SRV_B], graph)
            await asyncio.wait_for(run_b, BOUND_S)
            loads_after_first = len(orch._mcp_manager.loads)
            run_b2, _ = self._owner_run(orch, "owner-b", [SRV_B], _Graph(release=True))
            await asyncio.wait_for(run_b2, BOUND_S)
            return graph, loads_after_first

        graph, loads_after_first = asyncio.run(main())
        self.assertIsNone(graph.seen["create_issue"])
        self.assertIsNone(graph.seen["loaded"])
        self.assertGreater(len(orch._mcp_manager.loads), loads_after_first,
                           "the next admission of the same set must try to load it again")

    def test_a_finished_or_failed_run_no_longer_holds_the_toolset(self):
        orch = self._orch()

        class Boom:
            async def astream(self, *_a, **_k):
                raise RuntimeError("graph failed")
                yield  # pragma: no cover

        async def main():
            run_a, cb_a = self._owner_run(orch, "owner-a", [SRV_A], Boom())
            await asyncio.wait_for(run_a, BOUND_S)
            run_b, cb_b = self._owner_run(orch, "owner-b", [SRV_B], _Graph(release=True))
            await asyncio.wait_for(run_b, BOUND_S)
            return cb_a, cb_b

        cb_a, cb_b = asyncio.run(main())
        self.assertEqual(cb_a.errors[0]["code"], "agent_run_failed")
        self.assertEqual(cb_b.errors, [])
        self.assertEqual(self.guard.loaded_hash, server_set_hash([SRV_B]))


# Each way a paused run is resumed: the orchestrator call, the state it is paused in,
# the request the person answered, and the persisted row of their answer.
_PENDING = {"confirmation_id": "c1", "mode": "single",
            "tools": [{"tool_name": "create_issue", "tool_args": {}}]}
RESUMES = (
    ("tool_confirmation", "resume_after_tool_confirmation_with_streaming", ("approve", None),
     {"awaiting_tool_confirmation": True, "tool_confirmation_pending": _PENDING}, _PENDING),
    ("approval", "resume_after_approval_with_streaming", ("approve", None),
     {"awaiting_user_approval": True,
      "phase_transition_pending": {"from_phase": "informational", "to_phase": "exploitation"}},
     {"from_phase": "informational", "to_phase": "exploitation"}),
    ("question", "resume_after_answer_with_streaming", ("yes",),
     {"awaiting_user_question": True, "pending_question": {"question": "Which port?", "format": "text"}},
     {"question": "Which port?", "format": "text"}),
)


class RefusedResume(_Runs):
    """A paused run whose resume is refused stays answerable: the person's answer is
    neither applied nor saved, the refusal is recoverable, and the request is shown
    again."""

    def test_a_refused_resume_keeps_the_request_answerable(self):
        for kind, method, args, state, pending in RESUMES:
            with self.subTest(kind=kind):
                orch = self._orch()
                saved = []

                async def resume(graph, cb):
                    self._as_owner(orch, "owner-b", [SRV_B], graph)
                    return await asyncio.wait_for(getattr(orch, method)(
                        "s-owner-b", "owner-b", "p-owner-b", *args, cb,
                        on_admitted=lambda: saved.append(kind)), BOUND_S)

                async def main():
                    graph_a = _Graph()
                    run_a, _ = self._owner_run(orch, "owner-a", [SRV_A], graph_a)
                    task_a = asyncio.create_task(run_a)
                    await asyncio.wait_for(graph_a.started.wait(), BOUND_S)
                    refused = _Callback()
                    try:
                        await resume(_Graph(state=state, release=True), refused)
                    finally:
                        graph_a.release.set()
                        await asyncio.wait_for(task_a, BOUND_S)
                    saved_while_refused = list(saved)
                    admitted = _Callback()
                    await resume(_Graph(state=state, release=True), admitted)
                    return refused, saved_while_refused, admitted

                refused, saved_while_refused, admitted = asyncio.run(main())
                [err] = refused.errors
                self.assertEqual((err["code"], err["recoverable"]), ("mcp_toolset_busy", True))
                self.assertIn("not applied", err["message"])
                self.assertEqual(refused.resent, [(kind, pending)])
                self.assertEqual(saved_while_refused, [], "an answer that was not applied must not be saved")
                self.assertEqual((admitted.errors, saved), ([], [kind]))


class _WS:
    def __init__(self):
        self.sent = []
        self.client = "test"

    async def send_json(self, msg):
        self.sent.append(msg)

    async def close(self, code=1000, reason=""):
        pass


class _ResumingOrchestrator:
    """Answers each resume as the real one does: `admit` decides whether the run is
    admitted (it then calls on_admitted) or refused."""

    def __init__(self, admit):
        self.admit = admit

    async def _resume(self, **kw):
        if self.admit:
            kw["on_admitted"]()

    resume_after_approval_with_streaming = _resume
    resume_after_answer_with_streaming = _resume
    resume_after_tool_confirmation_with_streaming = _resume


class AnswerSavedOnlyOnceAdmitted(unittest.TestCase):
    HANDLERS = (
        ("handle_tool_confirmation", {"decision": "approve"}, "tool_confirmation_response"),
        ("handle_approval", {"decision": "approve"}, "approval_response"),
        ("handle_answer", {"answer": "443"}, "answer_response"),
    )

    def _answer(self, method, payload, admit):
        import websocket_api
        from websocket_api import WebSocketConnection, WebSocketHandler, WebSocketManager
        saved = mock.AsyncMock(return_value=None)

        async def main():
            mgr = WebSocketManager()
            handler = WebSocketHandler(orchestrator=_ResumingOrchestrator(admit), ws_manager=mgr)
            conn = WebSocketConnection(_WS())
            await mgr.authenticate(conn, "uB", "pB", "sB", verified=True)
            await getattr(handler, method)(conn, dict(payload))
            await asyncio.wait_for(conn._active_task, BOUND_S)

        from decision_check import DecisionCheck
        # The decision-time check (step 5.4) is test_decision_check.py's; here it allows.
        with mock.patch.object(websocket_api, "save_chat_message", saved), \
                mock.patch.object(websocket_api, "authorize_decision", mock.AsyncMock(return_value=DecisionCheck(allowed=True))), \
                mock.patch.object(websocket_api, "update_conversation", new=mock.AsyncMock()):
            asyncio.run(main())
        return [c.kwargs.get("msg_type") for c in saved.await_args_list]

    def test_a_refused_resume_saves_no_answer_and_an_admitted_one_saves_it(self):
        for method, payload, row in self.HANDLERS:
            with self.subTest(method=method):
                self.assertNotIn(row, self._answer(method, payload, admit=False))
                self.assertEqual(self._answer(method, payload, admit=True).count(row), 1)

    def test_a_request_shown_again_is_sent_and_never_saved(self):
        import websocket_api
        from websocket_api import StreamingCallback, WebSocketConnection, WebSocketManager

        async def main():
            mgr = WebSocketManager()
            conn = WebSocketConnection(_WS())
            await mgr.authenticate(conn, "uB", "pB", "sB", verified=True)
            cb = StreamingCallback(conn, mgr)
            for kind in ("tool_confirmation", "approval", "question"):
                await cb.resend_pending_request(kind, {"k": kind})
            return conn, cb

        conn, cb = asyncio.run(main())
        self.assertEqual([(m["type"], m["payload"]) for m in conn.websocket.sent], [
            ("tool_confirmation_request", {"k": "tool_confirmation"}),
            ("approval_request", {"k": "approval"}),
            ("question_request", {"k": "question"}),
        ])
        self.assertEqual(cb._persist_queue.qsize(), 0)


if __name__ == "__main__":
    unittest.main()
