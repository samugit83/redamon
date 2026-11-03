"""Hardening an outside brain needs: dangerous tools always ask a person in an
Agent in the Loop run (also when started through job_spawn), and the agent's own
graph reads run read-only."""
from __future__ import annotations

import inspect
import sys
import unittest
from unittest import mock

from agent_context import current_log_session_id, current_project_id, current_user_id
from agent_in_the_loop import LoopSettings, broker as broker_mod, confirmation_required
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


class ForcedConfirmation(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.broker = StepBroker(config=cfg())
        patcher = mock.patch.object(broker_mod, "_broker", self.broker)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.token = current_log_session_id.set("s1")

    async def asyncTearDown(self):
        current_log_session_id.reset(self.token)

    async def test_a_loop_run_always_asks(self):
        async with self.broker.run_scope("u1", "p1", "s1", None, uses_loop=True):
            self.assertTrue(confirmation_required(False))
            self.assertTrue(confirmation_required(True))

    async def test_a_provider_run_keeps_the_setting(self):
        async with self.broker.run_scope("u1", "p1", "s1", None, uses_loop=False):
            self.assertFalse(confirmation_required(False))
            self.assertTrue(confirmation_required(True))
        self.assertFalse(confirmation_required(False))

    def test_both_confirmation_reads_go_through_it(self):
        think_src = inspect.getsource(think_mod.think_node)
        self.assertIn("confirmation_required(get_setting('REQUIRE_TOOL_CONFIRMATION', True))", think_src)
        self.assertNotIn("if (get_setting('REQUIRE_TOOL_CONFIRMATION'", think_src)
        member_src = inspect.getsource(member_mod)
        self.assertIn('confirmation_required(get_setting("REQUIRE_TOOL_CONFIRMATION", True))', member_src)



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
