"""
Tests for Tool Confirmation feature — Pydantic models, confirmation nodes,
routing logic, and DANGEROUS_TOOLS classification.

Run with: python -m pytest tests/test_tool_confirmation.py -v
"""

import asyncio
import json
import os
import sys
import unittest
from unittest.mock import patch, MagicMock, AsyncMock

# Add parent dir to path so we can import from agentic modules
_agentic_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _agentic_dir)

# Stub out heavy dependencies not available outside Docker
# Must be done before any agentic module imports since state.py imports langgraph

class FakeAIMessage:
    def __init__(self, content="", **kwargs):
        self.content = content
        self.type = "ai"

class FakeHumanMessage:
    def __init__(self, content="", **kwargs):
        self.content = content
        self.type = "human"

# Provide a fake add_messages reducer
def _fake_add_messages(left, right):
    if left is None:
        left = []
    return left + right

_stubs = {}
_stub_modules = [
    'langchain_core', 'langchain_core.tools', 'langchain_core.messages',
    'langchain_core.language_models', 'langchain_core.runnables',
    'langchain_mcp_adapters', 'langchain_mcp_adapters.client',
    'langchain_neo4j',
    'langgraph', 'langgraph.graph', 'langgraph.graph.message',
    'langgraph.graph.state', 'langgraph.checkpoint',
    'langgraph.checkpoint.memory',
]
for mod_name in _stub_modules:
    if mod_name not in sys.modules:
        _stubs[mod_name] = MagicMock()
        sys.modules[mod_name] = _stubs[mod_name]

sys.modules['langchain_core.messages'].AIMessage = FakeAIMessage
sys.modules['langchain_core.messages'].HumanMessage = FakeHumanMessage
sys.modules['langgraph.graph.message'].add_messages = _fake_add_messages


# Stub langchain_openai so orchestrator_helpers.__init__ doesn't blow up
for mod_name in [
    'langchain_openai', 'langchain_openai.chat_models',
    'langchain_openai.chat_models.azure', 'langchain_openai.chat_models.base',
    'langchain_anthropic',
    'langchain_core.language_models.chat_models',
    'langchain_core.callbacks', 'langchain_core.outputs',
]:
    if mod_name not in sys.modules:
        _stubs[mod_name] = MagicMock()
        sys.modules[mod_name] = _stubs[mod_name]

from state import ToolConfirmationRequest, ExecutionStep
from project_settings import DANGEROUS_TOOLS, DEFAULT_AGENT_SETTINGS
from orchestrator_helpers.nodes.tool_confirmation_nodes import (
    await_tool_confirmation_node,
    process_tool_confirmation_node,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_config(user_id="u1", project_id="p1", session_id="s1"):
    return {
        "configurable": {
            "user_id": user_id,
            "project_id": project_id,
            "session_id": session_id,
        }
    }


def _base_state(**overrides):
    """Minimal AgentState dict with tool confirmation fields."""
    state = {
        "messages": [],
        "current_iteration": 3,
        "current_phase": "informational",
        "execution_trace": [],
        "awaiting_tool_confirmation": False,
        "tool_confirmation_pending": None,
        "tool_confirmation_response": None,
        "tool_confirmation_modification": None,
        "_reject_tool": False,
        "_current_step": None,
        "_current_plan": None,
        "task_complete": False,
    }
    state.update(overrides)
    return state


# ===========================================================================
# 1. ToolConfirmationRequest Pydantic model
# ===========================================================================

class TestToolConfirmationRequest(unittest.TestCase):
    """Test ToolConfirmationRequest model validation and defaults."""

    def test_single_mode_minimal(self):
        req = ToolConfirmationRequest(
            mode="single",
            tools=[{"tool_name": "execute_nmap", "tool_args": {"target": "10.0.0.1"}}],
            reasoning="Need to scan the target",
            phase="informational",
            iteration=1,
        )
        self.assertEqual(req.mode, "single")
        self.assertEqual(len(req.tools), 1)
        self.assertEqual(req.tools[0]["tool_name"], "execute_nmap")
        # confirmation_id auto-generated
        self.assertTrue(len(req.confirmation_id) > 0)

    def test_plan_mode_multiple_tools(self):
        req = ToolConfirmationRequest(
            mode="plan",
            tools=[
                {"tool_name": "execute_nmap", "tool_args": {}},
                {"tool_name": "execute_nuclei", "tool_args": {"target": "x"}},
            ],
            reasoning="Parallel scan wave",
            phase="informational",
            iteration=2,
        )
        self.assertEqual(req.mode, "plan")
        self.assertEqual(len(req.tools), 2)

    def test_model_dump_roundtrip(self):
        req = ToolConfirmationRequest(
            mode="single",
            tools=[{"tool_name": "kali_shell", "tool_args": {"command": "id"}}],
            reasoning="Test",
            phase="exploitation",
            iteration=5,
        )
        d = req.model_dump()
        self.assertIn("confirmation_id", d)
        self.assertEqual(d["mode"], "single")
        self.assertEqual(d["phase"], "exploitation")
        # Reconstruct
        req2 = ToolConfirmationRequest(**d)
        self.assertEqual(req2.confirmation_id, req.confirmation_id)

    def test_unique_confirmation_ids(self):
        ids = set()
        for _ in range(20):
            req = ToolConfirmationRequest(
                mode="single", tools=[], reasoning="", phase="informational", iteration=1,
            )
            ids.add(req.confirmation_id)
        # All should be unique (20 UUID prefixes)
        self.assertEqual(len(ids), 20)


# ===========================================================================
# 2. DANGEROUS_TOOLS constant
# ===========================================================================

class TestDangerousTools(unittest.TestCase):
    """Test DANGEROUS_TOOLS classification."""

    def test_expected_dangerous_tools(self):
        expected = {
            'execute_nmap', 'execute_naabu', 'execute_nuclei', 'execute_curl',
            'msf_restart', 'kali_shell', 'metasploit_console', 'execute_code',
            'execute_hydra', 'execute_playwright', 'execute_wpscan',
            'execute_ffuf', 'execute_arjun', 'execute_amass', 'execute_httpx',
            'execute_gau', 'execute_katana',
        }
        self.assertEqual(DANGEROUS_TOOLS, expected)

    def test_safe_tools_not_included(self):
        safe = ['query_graph', 'web_search', 'google_dork', 'shodan']
        for tool in safe:
            self.assertNotIn(tool, DANGEROUS_TOOLS)

    def test_is_frozenset(self):
        self.assertIsInstance(DANGEROUS_TOOLS, frozenset)

    def test_default_setting_enabled(self):
        self.assertTrue(DEFAULT_AGENT_SETTINGS['REQUIRE_TOOL_CONFIRMATION'])


# ===========================================================================
# 3. await_tool_confirmation_node
# ===========================================================================

class TestAwaitToolConfirmationNode(unittest.TestCase):
    """Test await_tool_confirmation_node output."""

    def _run(self, state):
        return asyncio.run(await_tool_confirmation_node(state, _make_config()))

    def test_single_tool_sets_awaiting(self):
        pending = ToolConfirmationRequest(
            mode="single",
            tools=[{
                "tool_name": "execute_nmap",
                "tool_args": {"target": "10.0.0.1", "args": "-sV"},
                "rationale": "Port scan needed",
            }],
            reasoning="Must identify open services",
            phase="informational",
            iteration=1,
        ).model_dump()

        state = _base_state(tool_confirmation_pending=pending)
        result = self._run(state)

        self.assertTrue(result["awaiting_tool_confirmation"])

    def test_plan_multiple_tools_sets_awaiting(self):
        pending = ToolConfirmationRequest(
            mode="plan",
            tools=[
                {"tool_name": "execute_nmap", "tool_args": {}, "rationale": ""},
                {"tool_name": "kali_shell", "tool_args": {"command": "whoami"}, "rationale": "Check user"},
            ],
            reasoning="Recon wave",
            phase="informational",
            iteration=2,
        ).model_dump()

        state = _base_state(tool_confirmation_pending=pending)
        result = self._run(state)

        self.assertTrue(result["awaiting_tool_confirmation"])

    def test_empty_tool_list(self):
        """Edge case: empty tools list still produces a message."""
        pending = ToolConfirmationRequest(
            mode="single", tools=[], reasoning="No tools", phase="informational", iteration=1,
        ).model_dump()
        state = _base_state(tool_confirmation_pending=pending)
        result = self._run(state)
        self.assertTrue(result["awaiting_tool_confirmation"])


# ===========================================================================
# 4. process_tool_confirmation_node — approve
# ===========================================================================

class TestProcessToolConfirmationApprove(unittest.TestCase):
    """Test approve branch of process_tool_confirmation_node."""

    def _run(self, state):
        return asyncio.run(process_tool_confirmation_node(state, _make_config()))

    def test_approve_clears_state(self):
        pending = ToolConfirmationRequest(
            mode="single",
            tools=[{"tool_name": "execute_nmap", "tool_args": {}}],
            reasoning="scan", phase="informational", iteration=1,
        ).model_dump()

        state = _base_state(
            tool_confirmation_pending=pending,
            tool_confirmation_response="approve",
        )
        result = self._run(state)

        self.assertFalse(result["awaiting_tool_confirmation"])
        self.assertIsNone(result["tool_confirmation_pending"])
        self.assertIsNone(result["tool_confirmation_response"])
        self.assertIsNone(result["tool_confirmation_modification"])
        self.assertFalse(result["_reject_tool"])

    def test_approve_clears_confirmation_state(self):
        pending = ToolConfirmationRequest(
            mode="single",
            tools=[{"tool_name": "execute_nuclei", "tool_args": {}}],
            reasoning="vuln scan", phase="informational", iteration=1,
        ).model_dump()

        state = _base_state(
            tool_confirmation_pending=pending,
            tool_confirmation_response="approve",
        )
        result = self._run(state)
        self.assertFalse(result["_reject_tool"])
        self.assertIsNone(result["tool_confirmation_pending"])

    def test_approve_multiple_tools_preserves_mode(self):
        pending = ToolConfirmationRequest(
            mode="plan",
            tools=[
                {"tool_name": "execute_nmap", "tool_args": {}},
                {"tool_name": "execute_hydra", "tool_args": {}},
            ],
            reasoning="", phase="exploitation", iteration=3,
        ).model_dump()

        state = _base_state(
            tool_confirmation_pending=pending,
            tool_confirmation_response="approve",
        )
        result = self._run(state)
        self.assertFalse(result["_reject_tool"])
        self.assertEqual(result["_tool_confirmation_mode"], "plan")


# ===========================================================================
# 5. process_tool_confirmation_node — reject
# ===========================================================================

class TestProcessToolConfirmationReject(unittest.TestCase):
    """Test reject branch of process_tool_confirmation_node."""

    def _run(self, state):
        return asyncio.run(process_tool_confirmation_node(state, _make_config()))

    def test_reject_sets_flag(self):
        pending = ToolConfirmationRequest(
            mode="single",
            tools=[{"tool_name": "kali_shell", "tool_args": {"command": "rm -rf /"}}],
            reasoning="dangerous", phase="exploitation", iteration=2,
        ).model_dump()

        state = _base_state(
            tool_confirmation_pending=pending,
            tool_confirmation_response="reject",
        )
        result = self._run(state)

        self.assertTrue(result["_reject_tool"])
        self.assertIsNone(result["_current_step"])
        self.assertIsNone(result["_current_plan"])

    def test_reject_adds_execution_trace(self):
        pending = ToolConfirmationRequest(
            mode="single",
            tools=[{"tool_name": "execute_code", "tool_args": {}}],
            reasoning="test", phase="informational", iteration=1,
        ).model_dump()

        state = _base_state(
            tool_confirmation_pending=pending,
            tool_confirmation_response="reject",
            execution_trace=[{"tool_name": "query_graph", "success": True}],
        )
        result = self._run(state)

        trace = result["execution_trace"]
        self.assertEqual(len(trace), 2)  # original + rejection
        last = trace[-1]
        self.assertEqual(last["tool_name"], "tool_rejection")
        self.assertFalse(last["success"])
        self.assertIn("execute_code", last["tool_output"])

    def test_reject_message_is_human(self):
        """Rejection sends a HumanMessage so the LLM sees the user's refusal."""
        pending = ToolConfirmationRequest(
            mode="single",
            tools=[{"tool_name": "msf_restart", "tool_args": {}}],
            reasoning="", phase="exploitation", iteration=1,
        ).model_dump()

        state = _base_state(
            tool_confirmation_pending=pending,
            tool_confirmation_response="reject",
        )
        result = self._run(state)
        msg = result["messages"][0]
        self.assertEqual(msg.type, "human")
        self.assertIn("rejected", msg.content)


# ===========================================================================
# 6. process_tool_confirmation_node — modify (single)
# ===========================================================================

class TestProcessToolConfirmationModifySingle(unittest.TestCase):
    """Test modify branch for single tool mode."""

    def _run(self, state):
        return asyncio.run(process_tool_confirmation_node(state, _make_config()))

    def test_modify_patches_current_step(self):
        pending = ToolConfirmationRequest(
            mode="single",
            tools=[{"tool_name": "execute_nmap", "tool_args": {"target": "10.0.0.1", "args": "-sV"}}],
            reasoning="scan", phase="informational", iteration=1,
        ).model_dump()

        current_step = {
            "tool_name": "execute_nmap",
            "tool_args": {"target": "10.0.0.1", "args": "-sV"},
        }

        state = _base_state(
            tool_confirmation_pending=pending,
            tool_confirmation_response="modify",
            tool_confirmation_modification={"args": "-sS -T2"},
            _current_step=current_step,
        )
        result = self._run(state)

        self.assertFalse(result["_reject_tool"])
        patched = result["_current_step"]
        self.assertEqual(patched["tool_args"]["args"], "-sS -T2")
        # Original target preserved
        self.assertEqual(patched["tool_args"]["target"], "10.0.0.1")

    def test_modify_no_current_step(self):
        """Modify with no _current_step should not crash."""
        pending = ToolConfirmationRequest(
            mode="single",
            tools=[{"tool_name": "execute_nmap", "tool_args": {}}],
            reasoning="", phase="informational", iteration=1,
        ).model_dump()

        state = _base_state(
            tool_confirmation_pending=pending,
            tool_confirmation_response="modify",
            tool_confirmation_modification={"args": "-sS"},
            _current_step=None,
        )
        result = self._run(state)
        self.assertFalse(result["_reject_tool"])
        # Should not have _current_step in result (wasn't patched)
        self.assertNotIn("_current_step", result)


# ===========================================================================
# 7. process_tool_confirmation_node — modify (plan)
# ===========================================================================

class TestProcessToolConfirmationModifyPlan(unittest.TestCase):
    """Test modify branch for plan mode."""

    def _run(self, state):
        return asyncio.run(process_tool_confirmation_node(state, _make_config()))

    def test_modify_patches_matching_plan_steps(self):
        pending = ToolConfirmationRequest(
            mode="plan",
            tools=[
                {"tool_name": "execute_nmap", "tool_args": {"target": "10.0.0.1"}},
                {"tool_name": "execute_nuclei", "tool_args": {"target": "10.0.0.1"}},
            ],
            reasoning="scan wave", phase="informational", iteration=1,
        ).model_dump()

        current_plan = {
            "steps": [
                {"tool_name": "execute_nmap", "tool_args": {"target": "10.0.0.1", "args": "-sV"}},
                {"tool_name": "query_graph", "tool_args": {"query": "MATCH (n) RETURN n"}},
                {"tool_name": "execute_nuclei", "tool_args": {"target": "10.0.0.1", "templates": "cves"}},
            ]
        }

        modification = {
            "execute_nmap": {"args": "-sS -T1"},
            "execute_nuclei": {"templates": "exposures"},
        }

        state = _base_state(
            tool_confirmation_pending=pending,
            tool_confirmation_response="modify",
            tool_confirmation_modification=modification,
            _current_plan=current_plan,
        )
        result = self._run(state)

        steps = result["_current_plan"]["steps"]
        # nmap patched
        self.assertEqual(steps[0]["tool_args"]["args"], "-sS -T1")
        self.assertEqual(steps[0]["tool_args"]["target"], "10.0.0.1")
        # query_graph untouched
        self.assertEqual(steps[1]["tool_args"]["query"], "MATCH (n) RETURN n")
        # nuclei patched
        self.assertEqual(steps[2]["tool_args"]["templates"], "exposures")


# ===========================================================================
# 8. Routing logic — _route_after_tool_confirmation
# ===========================================================================

class TestRouteAfterToolConfirmation(unittest.TestCase):
    """Test the orchestrator's _route_after_tool_confirmation logic."""

    def _route(self, state):
        """Replicate _route_after_tool_confirmation from orchestrator.py."""
        if state.get("task_complete"):
            return "generate_response"
        if state.get("_reject_tool"):
            return "think"
        if state.get("_tool_confirmation_mode") == "plan":
            return "execute_plan"
        return "execute_tool"

    def test_task_complete(self):
        self.assertEqual(self._route({"task_complete": True}), "generate_response")

    def test_reject_routes_to_think(self):
        self.assertEqual(self._route({"_reject_tool": True, "task_complete": False}), "think")

    def test_plan_mode_routes_to_execute_plan(self):
        state = {
            "task_complete": False,
            "_reject_tool": False,
            "_tool_confirmation_mode": "plan",
        }
        self.assertEqual(self._route(state), "execute_plan")

    def test_single_mode_routes_to_execute_tool(self):
        state = {
            "task_complete": False,
            "_reject_tool": False,
            "_tool_confirmation_mode": "single",
        }
        self.assertEqual(self._route(state), "execute_tool")

    def test_no_pending_routes_to_execute_tool(self):
        state = {"task_complete": False, "_reject_tool": False, "_tool_confirmation_mode": None}
        self.assertEqual(self._route(state), "execute_tool")


# ===========================================================================
# 9. Think node confirmation gate logic
# ===========================================================================

class TestThinkNodeConfirmationGate(unittest.TestCase):
    """Test the confirmation gate logic extracted from think_node."""

    def _apply_gate(self, action, tool_name=None, tool_plan_steps=None,
                    require_confirmation=True, awaiting_approval=False,
                    awaiting_question=False):
        """
        Replicate the confirmation gate logic from think_node.py lines 1087-1123.
        Returns (awaiting_tool_confirmation, pending_dict_or_None).
        """
        updates = {
            "awaiting_user_approval": awaiting_approval,
            "awaiting_user_question": awaiting_question,
        }

        if (require_confirmation
                and not updates.get("awaiting_user_approval")
                and not updates.get("awaiting_user_question")):

            if action == "use_tool" and tool_name in DANGEROUS_TOOLS:
                return True, "single"

            elif action == "plan_tools" and tool_plan_steps:
                dangerous = [s for s in tool_plan_steps if s["tool_name"] in DANGEROUS_TOOLS]
                if dangerous:
                    return True, "plan"

        return False, None

    def test_single_dangerous_tool_triggers(self):
        triggered, mode = self._apply_gate("use_tool", tool_name="execute_nmap")
        self.assertTrue(triggered)
        self.assertEqual(mode, "single")

    def test_safe_tool_does_not_trigger(self):
        triggered, _ = self._apply_gate("use_tool", tool_name="query_graph")
        self.assertFalse(triggered)

    def test_plan_with_dangerous_tools_triggers(self):
        steps = [
            {"tool_name": "execute_nmap"},
            {"tool_name": "query_graph"},
        ]
        triggered, mode = self._apply_gate("plan_tools", tool_plan_steps=steps)
        self.assertTrue(triggered)
        self.assertEqual(mode, "plan")

    def test_plan_with_only_safe_tools_no_trigger(self):
        steps = [
            {"tool_name": "query_graph"},
            {"tool_name": "web_search"},
        ]
        triggered, _ = self._apply_gate("plan_tools", tool_plan_steps=steps)
        self.assertFalse(triggered)

    def test_setting_disabled_skips_gate(self):
        triggered, _ = self._apply_gate(
            "use_tool", tool_name="execute_nmap", require_confirmation=False
        )
        self.assertFalse(triggered)

    def test_gate_skipped_when_awaiting_approval(self):
        triggered, _ = self._apply_gate(
            "use_tool", tool_name="execute_nmap", awaiting_approval=True
        )
        self.assertFalse(triggered)

    def test_gate_skipped_when_awaiting_question(self):
        triggered, _ = self._apply_gate(
            "use_tool", tool_name="execute_nmap", awaiting_question=True
        )
        self.assertFalse(triggered)

    def test_non_tool_action_no_trigger(self):
        triggered, _ = self._apply_gate("ask_user", tool_name="execute_nmap")
        self.assertFalse(triggered)

    def test_all_dangerous_tools_trigger(self):
        """Every tool in DANGEROUS_TOOLS should trigger confirmation."""
        for tool in DANGEROUS_TOOLS:
            triggered, mode = self._apply_gate("use_tool", tool_name=tool)
            self.assertTrue(triggered, f"{tool} should trigger confirmation")
            self.assertEqual(mode, "single")


if __name__ == "__main__":
    unittest.main()
