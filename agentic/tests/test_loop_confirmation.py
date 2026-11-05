"""Dangerous tools in an Agent in the Loop run follow the project's
REQUIRE_TOOL_CONFIRMATION like a provider run (off: no person is asked, and the
drawer marks the run), a dangerous tool started through job_spawn counts as
dangerous, and the agent's own graph reads run read-only."""
from __future__ import annotations

import inspect
import json
import sys
import unittest
from unittest import mock

import agent_in_the_loop
import project_settings
from agent_context import current_log_session_id, current_project_id, current_user_id
from agent_in_the_loop import LoopSettings, broker as broker_mod
from agent_in_the_loop.broker import StepBroker
from agent_in_the_loop.errors import LoopStepDeclined

import orchestrator_helpers.nodes.think_node  # noqa: F401
import orchestrator_helpers.nodes.fireteam_member_think_node  # noqa: F401

think_mod = sys.modules["orchestrator_helpers.nodes.think_node"]
member_mod = sys.modules["orchestrator_helpers.nodes.fireteam_member_think_node"]


def cfg():
    return LoopSettings(step_deadline_s=900, lease_s=90, wait_max_s=55, page_chars=40000,
                        answer_max_chars=262144, max_open_steps_per_user=16,
                        no_driver_grace_s=300, driver_seen_s=60, state_ttl_s=3600)


def member_state():
    return {
        "messages": [], "current_iteration": 1, "max_iterations": 10,
        "task_complete": False, "completion_reason": None,
        "current_phase": "informational", "attack_path_type": "cve_exploit",
        "user_id": "u", "project_id": "p", "session_id": "s",
        "parent_target_info": {}, "member_name": "Recon", "member_id": "member-0-abc",
        "fireteam_id": "fteam-1", "tools": [], "task": "map the open ports",
        "execution_trace": [], "target_info": {}, "chain_findings_memory": [],
        "chain_failures_memory": [], "_pending_confirmation": None, "_current_plan": None,
        "tokens_used": 0, "_decision": None, "_current_step": None,
        "_last_chain_step_id": None, "_guardrail_blocked": False,
    }


NMAP_DECISION = json.dumps({
    "thought": "map the ports", "reasoning": "first step", "action": "use_tool",
    "tool_name": "execute_nmap", "tool_args": {"args": "-sV 10.0.0.1"},
})


class ToolConfirmationFollowsTheProject(unittest.IsolatedAsyncioTestCase):
    """The real Fireteam member node, inside a live run scope of its session."""

    async def asyncSetUp(self):
        self.broker = StepBroker(config=cfg())
        patcher = mock.patch.object(broker_mod, "_broker", self.broker)
        patcher.start()
        self.addCleanup(patcher.stop)
        for name in ("fire_record_step", "fire_record_failure", "fire_record_finding"):
            patcher = mock.patch.object(member_mod.chain_graph, name, return_value=None)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.token = current_log_session_id.set("s")

    async def asyncTearDown(self):
        current_log_session_id.reset(self.token)

    async def member_picks_nmap(self, *, require_confirmation: bool, uses_loop: bool) -> dict:
        settings = dict(project_settings.DEFAULT_AGENT_SETTINGS,
                        REQUIRE_TOOL_CONFIRMATION=require_confirmation)
        settings_token = project_settings._settings_ctx.set(settings)
        llm = mock.MagicMock()
        llm.ainvoke = mock.AsyncMock(return_value=mock.MagicMock(content=NMAP_DECISION))
        try:
            async with self.broker.run_scope("u", "p", "s", None, uses_loop=uses_loop,
                                             tool_confirmation=require_confirmation):
                if uses_loop:
                    self.assertIsNotNone(self.broker.scope_for_session("s"))
                return await member_mod.fireteam_member_think_node(
                    member_state(), None, llm=llm, neo4j_creds=("bolt://x", "u", "p"),
                    streaming_callbacks=None)
        finally:
            project_settings._settings_ctx.reset(settings_token)

    async def test_a_loop_run_with_confirmation_off_runs_the_tool_unasked(self):
        update = await self.member_picks_nmap(require_confirmation=False, uses_loop=True)
        self.assertIsNone(update.get("_pending_confirmation"))
        self.assertEqual(update["_decision"]["tool_name"], "execute_nmap")

    async def test_a_loop_run_with_confirmation_on_asks_the_person(self):
        update = await self.member_picks_nmap(require_confirmation=True, uses_loop=True)
        pending = update["_pending_confirmation"]
        self.assertIsNotNone(pending)
        self.assertEqual(update["_current_step"]["tool_name"], "execute_nmap")

    async def test_a_provider_run_behaves_the_same(self):
        off = await self.member_picks_nmap(require_confirmation=False, uses_loop=False)
        self.assertIsNone(off.get("_pending_confirmation"))
        on = await self.member_picks_nmap(require_confirmation=True, uses_loop=False)
        self.assertIsNotNone(on["_pending_confirmation"])

    def test_no_loop_override_remains(self):
        # think_node has no runnable harness; its gate must read the setting itself.
        self.assertFalse(hasattr(agent_in_the_loop, "confirmation_required"))
        think_src = inspect.getsource(think_mod.think_node)
        self.assertIn("if (get_setting('REQUIRE_TOOL_CONFIRMATION', True)", think_src)
        self.assertNotIn("confirmation_required", think_src)
        member_src = inspect.getsource(member_mod)
        self.assertIn('tool_confirmation_enabled = get_setting("REQUIRE_TOOL_CONFIRMATION", True)', member_src)
        self.assertNotIn("confirmation_required", member_src)


class JobSpawnNeedsConfirmation(unittest.TestCase):
    """A dangerous tool started as a background job asks the person like a direct
    call: the phase check and the RoE gate already look through job_spawn."""

    def test_the_helper_looks_through_job_spawn(self):
        from project_settings import is_dangerous_call
        self.assertTrue(is_dangerous_call("execute_naabu", {"args": "-host 10.0.0.1"}))
        self.assertTrue(is_dangerous_call("job_spawn", {"tool_name": "execute_ffuf", "args": {}}))
        self.assertFalse(is_dangerous_call("job_spawn", {"tool_name": "query_graph", "args": {}}))
        self.assertFalse(is_dangerous_call("job_spawn", "execute_ffuf"))
        self.assertFalse(is_dangerous_call("job_status", {"job_id": "x"}))
        self.assertFalse(is_dangerous_call(None))

    def test_a_member_plan_with_a_spawned_scan_escalates(self):
        from state import LLMDecision, ToolPlan, ToolPlanStep
        decision = LLMDecision(thought="t", reasoning="r", action="plan_tools", tool_plan=ToolPlan(steps=[
            ToolPlanStep(tool_name="job_spawn", tool_args={"tool_name": "execute_naabu", "args": {"args": "-p -"}}),
            ToolPlanStep(tool_name="query_graph", tool_args={"question": "q"}),
        ]))
        self.assertTrue(member_mod._plan_has_dangerous_tool(decision))

    def test_a_lats_probe_spawning_a_dangerous_tool_is_dangerous(self):
        from orchestrator_helpers import lats
        from state import ExploitTreeNode
        node = ExploitTreeNode(tool_name="job_spawn", tool_args={"tool_name": "execute_curl", "args": {}})
        self.assertTrue(lats._is_dangerous(node))
        self.assertFalse(lats._is_dangerous(ExploitTreeNode(tool_name="job_spawn", tool_args={"tool_name": "fs_read"})))

    def test_the_root_gate_uses_it_for_single_calls_and_plans(self):
        src = inspect.getsource(think_mod.think_node)
        self.assertIn("is_dangerous_call(decision.tool_name, decision.tool_args)", src)
        self.assertIn("if is_dangerous_call(s.tool_name, s.tool_args)", src)
        self.assertNotIn("in DANGEROUS_TOOLS", src)

class ReadOnlyGraphQuery(unittest.IsolatedAsyncioTestCase):
    async def run_query_graph(self, generate):
        import tools
        graph = mock.MagicMock()
        graph.query.return_value = [{"d.name": "example.com"}]
        with mock.patch.object(tools, "Neo4jGraph", return_value=graph):
            manager = tools.Neo4jToolManager("bolt://x", "u", "p", llm=mock.MagicMock())
            query_graph = manager.get_tool()
        manager._generate_cypher = generate
        tokens = [current_user_id.set("u1"), current_project_id.set("p1")]
        try:
            out = await query_graph.ainvoke({"question": "list domains"})
        finally:
            current_user_id.reset(tokens[0])
            current_project_id.reset(tokens[1])
        return out, graph

    async def test_the_read_runs_in_a_read_access_session(self):
        out, graph = await self.run_query_graph(
            mock.AsyncMock(return_value="MATCH (d:Domain) RETURN d.name LIMIT 5"))
        self.assertIn("example.com", out)
        kwargs = graph.query.call_args.kwargs
        self.assertEqual(kwargs["session_params"], {"default_access_mode": "READ"})
        self.assertEqual(kwargs["params"], {"tenant_user_id": "u1", "tenant_project_id": "p1"})

    async def test_a_loop_failure_is_not_asked_again(self):
        generate = mock.AsyncMock(side_effect=LoopStepDeclined("no"))
        out, graph = await self.run_query_graph(generate)
        self.assertEqual(generate.await_count, 1)
        self.assertTrue(out.startswith("Error querying graph:"))
        graph.query.assert_not_called()

    async def test_other_failures_still_retry(self):
        generate = mock.AsyncMock(side_effect=RuntimeError("bad cypher"))
        out, _ = await self.run_query_graph(generate)
        self.assertEqual(generate.await_count, 3)
        self.assertIn("after 3 attempts", out)


if __name__ == "__main__":
    unittest.main()
