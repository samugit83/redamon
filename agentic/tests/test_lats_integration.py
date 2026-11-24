"""Integration tests that drive the REAL think_node with LATS live, using real
pydantic LLMDecision objects (not dict stand-ins), so type/coercion bugs that
unit tests with dicts mask are caught.

See internal/LATS_integration.md §19 Step 2/6 (two-visit + convergence).
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import project_settings  # noqa: E402
from state import ExploitTree, ExploitTreeNode  # noqa: E402


class _FakeLLMResp:
    def __init__(self, content):
        self.content = content
        self.usage_metadata = {"input_tokens": 10, "output_tokens": 5}
        self.response_metadata = {}


# A minimal, parseable think decision: a single use_tool with an inline analysis.
_USE_TOOL_JSON = json.dumps({
    "thought": "probe",
    "reasoning": "r",
    "action": "use_tool",
    "tool_name": "execute_curl",
    "tool_args": {"url": "https://t/login"},
    "output_analysis": {
        "interpretation": "i",
        "productivity": {"verdict": "new_info"},
    },
})


def _settings(**over):
    s = dict(project_settings.DEFAULT_AGENT_SETTINGS)
    s["LATS_ENABLED"] = True
    s["LATS_SHADOW_MODE"] = False           # DRIVE
    s["REQUIRE_TOOL_CONFIRMATION"] = False  # isolate the drive path from the gate
    s.update(over)
    return s


def _seed_hot_tree(objective: str) -> dict:
    """A live tree with one evaluated, expandable hot node under the root."""
    root = ExploitTreeNode(id="root", status="evaluated", depth=0, probe_rationale="root")
    c1 = ExploitTreeNode(id="c1", parent_id="root", depth=1, status="evaluated",
                         value=0.8, local_value=0.8, visits=1, tool_name="execute_curl")
    root.children = ["c1"]
    tree = ExploitTree(root_id="root", nodes={"root": root, "c1": c1},
                       active_node_id="root", rollouts=1, objective=objective)
    return tree.model_dump()


class TestDriveThroughThinkNode(unittest.IsolatedAsyncioTestCase):
    """The regression that dict-based unit tests could not catch: a drive-mode
    wave must set decision.tool_plan to a real ToolPlan so think_node's
    `decision.tool_plan.model_dump()` does not crash."""

    async def _run(self, probes):
        import orchestrator_helpers.nodes.think_node  # noqa: F401
        tn = sys.modules["orchestrator_helpers.nodes.think_node"]
        import orchestrator_helpers.lats as lats

        objective = "find the flag"
        state = {
            "attack_path_type": "cve_exploit",
            "current_phase": "exploitation",
            "current_iteration": 3, "max_iterations": 300,
            "messages": [], "todo_list": [], "execution_trace": [],
            "conversation_objectives": [{"objective": objective, "status": "in_progress"}],
            "current_objective_index": 0, "objective_history": [],
            "target_info": {"services": ["http"]},
            "chain_findings_memory": [],
            "session_id": "s",
            "_exploit_tree": _seed_hot_tree(objective),
            "_reject_tool": False,
            "_current_plan": None, "_current_step": None,
        }
        config = {"configurable": {"thread_id": "u/p/s", "user_id": "u",
                                   "project_id": "p", "session_id": "s"}}
        resp = _FakeLLMResp(_USE_TOOL_JSON)
        with patch.object(tn, "retry_llm_call", new=AsyncMock(return_value=resp)), \
             patch.object(lats, "lats_expand", new=AsyncMock(return_value=probes)):
            return await tn.think_node(
                state, config, llm=MagicMock(), guidance_queues={},
                neo4j_creds=("", "", ""), streaming_callbacks=None,
                graph_view_cyphers=None,
            )

    async def test_drive_wave_sets_a_real_toolplan(self):
        project_settings._settings = _settings()
        try:
            probes = [
                {"tool_name": "execute_curl", "tool_args": {"url": "a"}, "rationale": "reuse token"},
                {"tool_name": "execute_httpx", "tool_args": {"url": "b"}, "rationale": "enum"},
            ]
            updates = await self._run(probes)
            # The hook drove a plan_tools wave; think_node must have serialized it.
            self.assertEqual(updates["_decision"]["action"], "plan_tools")
            plan = updates["_current_plan"]
            self.assertIsInstance(plan, dict)
            self.assertEqual(len(plan["steps"]), 2)
            names = sorted(s["tool_name"] for s in plan["steps"])
            self.assertEqual(names, ["execute_curl", "execute_httpx"])
            # The tree was persisted with the wave marked executing.
            tree = ExploitTree(**updates["_exploit_tree"])
            self.assertEqual(len([n for n in tree.nodes.values() if n.status == "executing"]), 2)
        finally:
            project_settings._settings = None

    async def test_drive_single_probe_sets_use_tool(self):
        project_settings._settings = _settings()
        try:
            probes = [{"tool_name": "execute_curl", "tool_args": {"url": "x"}, "rationale": "x"}]
            # single probe -> use_tool override, tool_name propagated
            updates = await self._run(probes)
            self.assertEqual(updates["_decision"]["action"], "use_tool")
            self.assertEqual(updates["_decision"]["tool_name"], "execute_curl")
        finally:
            project_settings._settings = None

    async def test_metasploit_probe_without_session_reroutes_to_ask_user(self):
        # §20.4: a bare metasploit_console probe under cve_exploit is re-routed to
        # ask_user by think_node's pre-exploitation forcing when nothing can carry a
        # session: a known sandbox with no reverse port, no tunnel and no bind port
        # (payload_plan's ask_bind). LATS proposed it; the forcing runs AFTER the hook,
        # so this proves the hook does not bypass it.
        import utils
        project_settings._settings = _settings()
        try:
            probes = [{"tool_name": "metasploit_console", "tool_args": {"a": 1}, "rationale": "x"}]
            with patch.object(utils, "_reverse_port_facts", return_value=("no_pool", None)):
                updates = await self._run(probes)
            self.assertEqual(updates["_decision"]["action"], "ask_user")
            self.assertIn("BIND_PORT_ON_TARGET", updates["pending_question"]["question"])
        finally:
            project_settings._settings = None

    async def test_metasploit_probe_before_the_sandbox_is_known_is_not_rerouted(self):
        # Before any Kali call the sandbox's reverse port is not known, and the
        # forcing never asks for a value the next step may already show.
        project_settings._settings = _settings()
        try:
            probes = [{"tool_name": "metasploit_console", "tool_args": {"a": 1}, "rationale": "x"}]
            updates = await self._run(probes)
            self.assertEqual(updates["_decision"]["action"], "use_tool")
            self.assertEqual(updates["_decision"]["tool_name"], "metasploit_console")
        finally:
            project_settings._settings = None


if __name__ == "__main__":
    unittest.main()
