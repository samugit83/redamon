"""RBAC OQ-41 / NF-06: the agent holds ONE user MCP toolset for the whole process.

A run whose owner's MCP server set differs from the loaded one is refused with
`mcp_toolset_busy` while another owner's run on a different set is live; otherwise
the set is reloaded as before. The reload a member's MCP save triggers goes through
the same guard (deferred, never applied under another owner's live run), and every
reload records the set it loaded.
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

SRV_A = {"id": "srv-a", "name": "A", "transport": "streamable_http",
         "url": "http://a.example/mcp", "tools": []}
SRV_B = {"id": "srv-b", "name": "B", "transport": "streamable_http",
         "url": "http://b.example/mcp", "tools": []}


class _FreshGuard(unittest.TestCase):
    def setUp(self):
        self.guard = McpToolsetGuard()
        patcher = mock.patch.object(guard_mod, "_guard", self.guard)
        patcher.start()
        self.addCleanup(patcher.stop)


class GuardRules(_FreshGuard):
    def test_different_set_refused_while_another_owners_run_is_live(self):
        lease, reload = self.guard.admit_run("owner-a", [SRV_A])
        self.assertTrue(reload)
        with self.assertLogs("mcp_toolset_guard", "WARNING") as logs, \
                self.assertRaises(McpToolsetBusy) as ctx:
            self.guard.admit_run("owner-b", [SRV_B])
        self.assertEqual(ctx.exception.code, "mcp_toolset_busy")
        self.assertIn("[rbac] mcp toolset busy", "\n".join(logs.output))
        self.assertEqual(self.guard.loaded_hash, server_set_hash([SRV_A]))

    def test_an_empty_set_is_a_different_set(self):
        # A member with no servers must not run on another owner's servers (and tokens).
        self.guard.admit_run("owner-a", [SRV_A])
        with self.assertRaises(McpToolsetBusy):
            self.guard.admit_run("owner-b", [])

    def test_same_set_allowed(self):
        self.guard.admit_run("owner-a", [SRV_A])
        _, reload = self.guard.admit_run("owner-b", [dict(SRV_A)])
        self.assertFalse(reload)

    def test_no_live_run_reloads(self):
        lease, _ = self.guard.admit_run("owner-a", [SRV_A])
        self.guard.release_run(lease)
        _, reload = self.guard.admit_run("owner-b", [SRV_B])
        self.assertTrue(reload)
        self.assertEqual(self.guard.loaded_hash, server_set_hash([SRV_B]))
        self.assertEqual(self.guard.loaded_servers, [SRV_B])

    def test_the_owner_may_change_its_own_set_while_its_own_run_is_live(self):
        self.guard.admit_run("owner-a", [SRV_A])
        _, reload = self.guard.admit_run("owner-a", [SRV_A, SRV_B])
        self.assertTrue(reload)

    def test_the_first_run_after_start_loads_its_set(self):
        _, reload = self.guard.admit_run("owner-a", [])
        self.assertTrue(reload)
        self.assertEqual(self.guard.loaded_hash, server_set_hash([]))

    def test_releasing_twice_is_harmless(self):
        lease, _ = self.guard.admit_run("owner-a", [SRV_A])
        self.guard.release_run(lease)
        self.guard.release_run(lease)
        self.guard.admit_run("owner-b", [SRV_B])

    def test_a_save_triggered_reload_is_deferred_while_another_owners_run_is_live(self):
        self.guard.admit_run("owner-a", [SRV_A])
        with self.assertLogs("mcp_toolset_guard", "WARNING") as logs:
            self.assertFalse(self.guard.admit_reload("owner-b", [SRV_B]))
        self.assertIn("[rbac] mcp toolset busy", "\n".join(logs.output))
        self.assertEqual(self.guard.loaded_hash, server_set_hash([SRV_A]))

    def test_a_reload_with_no_owner_is_deferred_under_any_live_run_on_another_set(self):
        self.guard.admit_run("owner-a", [SRV_A])
        self.assertFalse(self.guard.admit_reload(None, [SRV_B]))

    def test_a_reload_of_the_loaded_set_is_never_deferred(self):
        self.guard.admit_run("owner-a", [SRV_A])
        self.assertTrue(self.guard.admit_reload(None, [SRV_A]))

    def test_the_hash_ignores_key_order(self):
        self.assertEqual(server_set_hash([{"a": 1, "b": 2}]), server_set_hash([{"b": 2, "a": 1}]))
        self.assertEqual(server_set_hash(None), server_set_hash([]))


def _api():
    @asynccontextmanager
    async def fake_lifespan(_app):
        yield

    with mock.patch("api.lifespan", fake_lifespan):
        import api as api_module
        from fastapi.testclient import TestClient
    return api_module, TestClient(api_module.app, headers={"x-internal-key": MASTER})


class _Reloads:
    def __init__(self):
        self.calls = []

    async def reload_mcp_manifests(self, user_servers_raw=None):
        self.calls.append(user_servers_raw)
        return {"servers": [], "errors": [], "warnings": [], "declared_user_tool_names": []}


class ReloadRoute(_FreshGuard):
    def setUp(self):
        super().setUp()
        env = mock.patch.dict(os.environ, {"INTERNAL_API_KEY": MASTER})
        env.start()
        self.addCleanup(env.stop)
        self.api, self.client = _api()
        self.orch = _Reloads()
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
        self.assertEqual(self.orch.calls, [])
        self.assertIn("owner=owner-b", "\n".join(logs.output))
        self.assertEqual(self.guard.loaded_hash, server_set_hash([SRV_A]))

    def test_the_owners_own_save_reloads_while_only_their_run_is_live(self):
        self.guard.admit_run("owner-a", [SRV_A])
        r = self.client.post("/mcp/reload", json={"ownerId": "owner-a", "userMcpServers": [SRV_B]})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(self.orch.calls, [[SRV_B]])
        self.assertEqual(self.guard.loaded_hash, server_set_hash([SRV_B]))

    def test_no_live_run_reloads_the_saved_set(self):
        r = self.client.post("/mcp/reload", json={"ownerId": "owner-b", "userMcpServers": [SRV_B]})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(self.orch.calls, [[SRV_B]])
        self.assertEqual(self.guard.loaded_hash, server_set_hash([SRV_B]))

    def test_an_admins_reload_with_no_body_reloads_the_loaded_set_even_under_a_live_run(self):
        self.guard.admit_run("owner-a", [SRV_A])
        r = self.client.post("/mcp/reload", json={})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(self.orch.calls, [None])


def _orchestrator():
    from orchestrator import AgentOrchestrator
    orch = AgentOrchestrator.__new__(AgentOrchestrator)
    orch._initialized = True
    orch._streaming_callbacks, orch._guidance_queues, orch._graph_view_cyphers = {}, {}, {}
    return orch


class _McpManager:
    def __init__(self):
        self.generation = 0
        self.configs = None

    def replace_server_configs(self, configs):
        self.configs = configs

    async def reconnect(self, seen, reason=""):
        self.generation += 1
        return self.generation, []


class ReloadRecordsTheSet(_FreshGuard):
    def _reloading_orchestrator(self):
        orch = _orchestrator()
        orch._mcp_manager = _McpManager()
        orch.tool_executor = mock.MagicMock()
        return orch

    def _reload(self, orch, raw):
        with mock.patch("tools._build_system_mcp_servers", return_value=[]), \
                mock.patch("prompts.tool_registry.apply_mcp_manifests_to_registry", return_value=set()):
            return asyncio.run(orch.reload_mcp_manifests(raw))

    def test_every_reload_updates_the_stored_hash(self):
        orch = self._reloading_orchestrator()
        self._reload(orch, [SRV_A])
        self.assertEqual(self.guard.loaded_hash, server_set_hash([SRV_A]))
        self._reload(orch, [SRV_B])
        self.assertEqual(self.guard.loaded_hash, server_set_hash([SRV_B]))
        self.assertEqual(self.guard.loaded_servers, [SRV_B])

    def test_a_reload_with_no_list_reloads_the_loaded_set_not_another_projects_settings(self):
        orch = self._reloading_orchestrator()
        self._reload(orch, [SRV_A])
        # The module-global settings are the last-loaded project's, possibly another owner's.
        ps._settings = {**ps.DEFAULT_AGENT_SETTINGS, "USER_MCP_SERVERS": [SRV_B]}
        self.addCleanup(setattr, ps, "_settings", None)
        out = self._reload(orch, None)
        self.assertEqual(self.guard.loaded_hash, server_set_hash([SRV_A]))
        self.assertEqual([s["id"] for s in out["servers"]], ["srv-a"])


class _Graph:
    """A graph whose run stays live until released."""

    def __init__(self):
        self.release = asyncio.Event()
        self.started = asyncio.Event()

    async def astream(self, _input, _config, stream_mode="values"):
        self.started.set()
        await self.release.wait()
        yield {"task_complete": True}


class _Callback:
    def __init__(self):
        self.errors = []

    async def on_error(self, message, recoverable=True, **details):
        self.errors.append({"message": message, "recoverable": recoverable, **details})

    async def on_response(self, *a, **k):
        pass


def _broker():
    @asynccontextmanager
    async def run_scope(*_a, **_k):
        yield SimpleNamespace(final_state=None)
    return SimpleNamespace(run_scope=run_scope)


class RunAdmission(_FreshGuard):
    """The guard at run start, through the orchestrator's streaming entry point."""

    def setUp(self):
        super().setUp()
        for target, value in (("orchestrator.get_broker", _broker),
                              ("orchestrator.emit_streaming_events", mock.AsyncMock())):
            patcher = mock.patch(target, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.addCleanup(ps._settings_ctx.set, None)

    def _owner_run(self, orch, owner, servers, graph):
        def apply(_project_id):
            ps._settings_ctx.set({**ps.DEFAULT_AGENT_SETTINGS, "USER_MCP_SERVERS": servers})
            ac.current_llm.set(object())
        orch._apply_project_settings = apply
        orch.graph = graph
        cb = _Callback()
        coro = orch.invoke_with_streaming("q", owner, f"p-{owner}", f"s-{owner}", cb)
        return coro, cb

    def test_a_run_on_another_set_is_refused_while_another_owners_run_is_live(self):
        orch = _orchestrator()
        orch.reload_mcp_manifests = mock.AsyncMock(return_value={})

        async def main():
            graph_a = _Graph()
            run_a, _ = self._owner_run(orch, "owner-a", [SRV_A], graph_a)
            task_a = asyncio.create_task(run_a)
            await graph_a.started.wait()
            run_b, cb_b = self._owner_run(orch, "owner-b", [SRV_B], _Graph())
            with self.assertLogs("mcp_toolset_guard", "WARNING") as logs:
                resp_b = await run_b
            graph_a.release.set()
            await task_a
            return resp_b, cb_b, logs

        resp_b, cb_b, logs = asyncio.run(main())
        [err] = cb_b.errors
        self.assertEqual((err["code"], err["recoverable"]), ("mcp_toolset_busy", False))
        self.assertEqual(resp_b.error, err["message"])
        self.assertNotIn("owner-a", err["message"])
        self.assertIn("[rbac] mcp toolset busy", "\n".join(logs.output))
        orch.reload_mcp_manifests.assert_awaited_once_with([SRV_A])

    def test_run_start_schedules_the_reload_and_records_the_set(self):
        orch = _orchestrator()
        orch.reload_mcp_manifests = mock.AsyncMock(return_value={})

        async def main():
            graph = _Graph()
            graph.release.set()
            run, cb = self._owner_run(orch, "owner-a", [SRV_A], graph)
            await run
            await asyncio.sleep(0)
            return cb

        cb = asyncio.run(main())
        self.assertEqual(cb.errors, [])
        orch.reload_mcp_manifests.assert_awaited_once_with([SRV_A])
        self.assertEqual(self.guard.loaded_hash, server_set_hash([SRV_A]))

    def test_a_finished_or_failed_run_no_longer_holds_the_toolset(self):
        orch = _orchestrator()
        orch.reload_mcp_manifests = mock.AsyncMock(return_value={})

        class Boom:
            async def astream(self, *_a, **_k):
                raise RuntimeError("graph failed")
                yield  # pragma: no cover

        async def main():
            run_a, cb_a = self._owner_run(orch, "owner-a", [SRV_A], Boom())
            await run_a
            graph_b = _Graph()
            graph_b.release.set()
            run_b, cb_b = self._owner_run(orch, "owner-b", [SRV_B], graph_b)
            await run_b
            return cb_a, cb_b

        cb_a, cb_b = asyncio.run(main())
        self.assertEqual(cb_a.errors[0]["code"], "agent_run_failed")
        self.assertEqual(cb_b.errors, [])
        self.assertEqual(self.guard.loaded_hash, server_set_hash([SRV_B]))


if __name__ == "__main__":
    unittest.main()
