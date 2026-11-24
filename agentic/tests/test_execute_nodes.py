"""Unit tests for the orchestration execute nodes (D2).

Targets the low-coverage execute_tool_node (13%) / execute_plan_node (15%).
Follows the canonical test_tool_confirmation.py pattern: pre-import langgraph /
langchain stubs into sys.modules, plain-dict state fixtures, AsyncMock executor.

The highest-value / lowest-risk targets are the pure helpers, tested directly:
  * _detect_embedded_tool_error   (execute_tool_node)
  * _validate_plan_mutex_groups   (execute_plan_node)
  * roe_block_reason              (roe_gate, shared by both nodes)
plus one happy-path invocation each of execute_tool_node / execute_plan_node with
an AsyncMock tool_executor and streaming_callbacks={} (short-circuits the
progress/httpx branches).

Run: pytest tests/test_execute_nodes.py
"""
import asyncio
import os
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock

_agentic_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _agentic_dir)

# --- Stub heavy deps before importing agent modules (same as test_tool_confirmation) ---

class FakeAIMessage:
    def __init__(self, content="", **kwargs):
        self.content = content
        self.type = "ai"

class FakeHumanMessage:
    def __init__(self, content="", **kwargs):
        self.content = content
        self.type = "human"

def _fake_add_messages(left, right):
    if left is None:
        left = []
    return left + right

_stub_modules = [
    'langchain_core', 'langchain_core.tools', 'langchain_core.messages',
    'langchain_core.language_models', 'langchain_core.runnables',
    'langchain_core.callbacks', 'langchain_core.outputs',
    'langchain_mcp_adapters', 'langchain_mcp_adapters.client', 'langchain_neo4j',
    'langchain_openai', 'langchain_openai.chat_models',
    'langchain_openai.chat_models.azure', 'langchain_openai.chat_models.base',
    'langchain_anthropic',
    'langgraph', 'langgraph.graph', 'langgraph.graph.message',
    'langgraph.graph.state', 'langgraph.checkpoint', 'langgraph.checkpoint.memory',
]
for mod_name in _stub_modules:
    if mod_name not in sys.modules:
        sys.modules[mod_name] = MagicMock()

sys.modules['langchain_core.messages'].AIMessage = FakeAIMessage
sys.modules['langchain_core.messages'].HumanMessage = FakeHumanMessage
sys.modules['langgraph.graph.message'].add_messages = _fake_add_messages

def _identity_tool(fn=None, **_kw):
    if callable(fn):
        return fn
    return lambda f: f
sys.modules['langchain_core.tools'].tool = _identity_tool

from orchestrator_helpers.nodes.execute_tool_node import (  # noqa: E402
    _detect_embedded_tool_error,
    execute_tool_node,
)
from orchestrator_helpers.nodes.execute_plan_node import (  # noqa: E402
    _validate_plan_mutex_groups,
    execute_plan_node,
)
from orchestrator_helpers.roe_gate import roe_block_reason  # noqa: E402


def _make_config(user_id="u1", project_id="p1", session_id="s1"):
    return {"configurable": {"user_id": user_id, "project_id": project_id,
                             "session_id": session_id}}


def _base_state(**overrides):
    state = {
        "messages": [],
        "current_iteration": 0,
        "current_phase": "informational",
        "execution_trace": [],
        "_current_step": None,
        "_current_plan": None,
    }
    state.update(overrides)
    return state


# ===========================================================================
# _detect_embedded_tool_error  (pure)
# ===========================================================================
class TestDetectEmbeddedToolError(unittest.TestCase):
    def test_none_and_empty_return_none(self):
        self.assertIsNone(_detect_embedded_tool_error(""))
        self.assertIsNone(_detect_embedded_tool_error(None))

    def test_clean_output_returns_none(self):
        self.assertIsNone(_detect_embedded_tool_error("HTTP/1.1 200 OK\nbody ok\n"))

    def test_bracket_error_marker_detected(self):
        out = _detect_embedded_tool_error("some log\n[ERROR] boom happened\nmore")
        self.assertIsNotNone(out)
        self.assertIn("[ERROR]", out)

    def test_playwright_navigation_failure_detected(self):
        out = _detect_embedded_tool_error("Navigation failed: Page.goto: Timeout 30000ms exceeded")
        self.assertIsNotNone(out)
        self.assertIn("Navigation failed", out)

    def test_tool_execution_failed_wrapper_detected(self):
        out = _detect_embedded_tool_error("Tool execution failed: connection refused")
        self.assertIsNotNone(out)

    def test_match_is_truncated_to_500_chars(self):
        long_tail = "x" * 2000
        out = _detect_embedded_tool_error("ConnectionError: " + long_tail)
        self.assertIsNotNone(out)
        self.assertLessEqual(len(out), 500)

    def test_error_beyond_head_window_is_ignored(self):
        # Only the first 4000 chars are scanned; an error after that is not flagged.
        out = _detect_embedded_tool_error(("ok " * 2000) + "\n[ERROR] late error")
        self.assertIsNone(out)


# ===========================================================================
# _validate_plan_mutex_groups  (pure)
# ===========================================================================
class TestValidatePlanMutexGroups(unittest.TestCase):
    def test_no_conflict_returns_none(self):
        steps = [{"tool_name": "execute_httpx"}, {"tool_name": "execute_nmap"}]
        self.assertIsNone(_validate_plan_mutex_groups(steps))

    def test_two_metasploit_steps_conflict(self):
        # metasploit_console is a singleton mutex-group tool in project_settings.
        from project_settings import TOOL_MUTEX_GROUPS
        # find a group with >=1 tool and stack two of the same tool
        some_tool = None
        for _group, tools in TOOL_MUTEX_GROUPS.items():
            if tools:
                some_tool = list(tools)[0]
                break
        self.assertIsNotNone(some_tool, "expected at least one mutex group tool")
        steps = [{"tool_name": some_tool}, {"tool_name": some_tool}]
        msg = _validate_plan_mutex_groups(steps)
        self.assertIsNotNone(msg)
        self.assertIn(some_tool, msg)

    def test_empty_plan_is_fine(self):
        self.assertIsNone(_validate_plan_mutex_groups([]))


# ===========================================================================
# roe_block_reason  (pure)
# ===========================================================================
class TestCheckRoeBlocked(unittest.TestCase):
    def setUp(self):
        import project_settings as ps
        self._ps = ps
        self._orig = ps._settings if hasattr(ps, "_settings") else None

    def tearDown(self):
        if hasattr(self._ps, "_settings"):
            self._ps._settings = self._orig

    def _set(self, **kv):
        # Force a settings snapshot with the given overrides.
        base = dict(self._ps.DEFAULT_AGENT_SETTINGS)
        base.update(kv)
        self._ps._settings = base

    def test_returns_none_when_roe_disabled(self):
        self._set(ROE_ENABLED=False)
        self.assertIsNone(roe_block_reason("execute_hydra", "exploitation"))

    def test_forbidden_tool_blocked(self):
        self._set(ROE_ENABLED=True, ROE_FORBIDDEN_TOOLS=["execute_hydra"],
                  ROE_FORBIDDEN_CATEGORIES=[], ROE_ALLOW_ACCOUNT_LOCKOUT=True,
                  ROE_ALLOW_DOS=True, ROE_MAX_SEVERITY_PHASE="post_exploitation")
        msg = roe_block_reason("execute_hydra", "informational")
        self.assertIsNotNone(msg)
        self.assertIn("execute_hydra", msg)

    def test_account_lockout_default_blocks_hydra(self):
        # ROE on, hydra not explicitly forbidden, but lockout not allowed -> blocked.
        self._set(ROE_ENABLED=True, ROE_FORBIDDEN_TOOLS=[], ROE_FORBIDDEN_CATEGORIES=[],
                  ROE_ALLOW_ACCOUNT_LOCKOUT=False, ROE_ALLOW_DOS=True,
                  ROE_MAX_SEVERITY_PHASE="post_exploitation")
        self.assertIsNotNone(roe_block_reason("execute_hydra", "informational"))

    def test_phase_cap_blocks_beyond_max_severity(self):
        self._set(ROE_ENABLED=True, ROE_FORBIDDEN_TOOLS=[], ROE_FORBIDDEN_CATEGORIES=[],
                  ROE_ALLOW_ACCOUNT_LOCKOUT=True, ROE_ALLOW_DOS=True,
                  ROE_MAX_SEVERITY_PHASE="informational")
        msg = roe_block_reason("execute_httpx", "exploitation")
        self.assertIsNotNone(msg)
        self.assertIn("exceeds maximum", msg)

    def test_allowed_tool_within_phase_ok(self):
        self._set(ROE_ENABLED=True, ROE_FORBIDDEN_TOOLS=[], ROE_FORBIDDEN_CATEGORIES=[],
                  ROE_ALLOW_ACCOUNT_LOCKOUT=True, ROE_ALLOW_DOS=True,
                  ROE_MAX_SEVERITY_PHASE="post_exploitation")
        self.assertIsNone(roe_block_reason("execute_httpx", "informational"))


# ===========================================================================
# execute_tool_node — happy path
# ===========================================================================
class TestExecuteToolNodeHappyPath(unittest.TestCase):
    def test_successful_tool_updates_step_and_returns_result(self):
        executor = AsyncMock()
        executor.execute.return_value = {"success": True, "output": "scan complete"}

        state = _base_state(_current_step={
            "tool_name": "execute_httpx",
            "tool_args": {"target": "example.com"},
        })
        out = asyncio.run(execute_tool_node(
            state, _make_config(),
            tool_executor=executor,
            streaming_callbacks={},              # no callback -> skips streaming/httpx
        ))
        self.assertTrue(out["_current_step"]["success"])
        self.assertEqual(out["_current_step"]["tool_output"], "scan complete")
        self.assertEqual(out["_tool_result"]["output"], "scan complete")
        executor.execute.assert_awaited_once()

    def test_missing_tool_name_short_circuits(self):
        executor = AsyncMock()
        state = _base_state(_current_step={"tool_name": None, "tool_args": {}})
        out = asyncio.run(execute_tool_node(
            state, _make_config(),
            tool_executor=executor,
            streaming_callbacks={},
        ))
        self.assertFalse(out["_current_step"]["success"])
        self.assertFalse(out["_tool_result"]["success"])
        executor.execute.assert_not_called()

    def test_embedded_error_flips_success_to_false(self):
        executor = AsyncMock()
        executor.execute.return_value = {
            "success": True,
            "output": "[ERROR] Navigation failed: Page.goto: Timeout 30000ms exceeded",
        }
        state = _base_state(_current_step={
            "tool_name": "execute_playwright", "tool_args": {}})
        out = asyncio.run(execute_tool_node(
            state, _make_config(),
            tool_executor=executor,
            streaming_callbacks={},
        ))
        self.assertFalse(out["_current_step"]["success"])
        self.assertTrue(out["_current_step"].get("error_embedded"))


# ===========================================================================
# execute_plan_node — happy path + mutex rejection
# ===========================================================================
class TestExecutePlanNode(unittest.TestCase):
    def test_no_plan_returns_cleared_plan(self):
        out = asyncio.run(execute_plan_node(
            _base_state(_current_plan=None), _make_config(),
            tool_executor=AsyncMock(), streaming_callbacks={},
        ))
        self.assertIsNone(out["_current_plan"])

    def test_parallel_wave_executes_all_steps(self):
        executor = AsyncMock()
        executor.execute.return_value = {"success": True, "output": "ok"}
        plan = {"steps": [
            {"tool_name": "execute_httpx", "tool_args": {}},
            {"tool_name": "execute_nmap", "tool_args": {}},
        ]}
        out = asyncio.run(execute_plan_node(
            _base_state(_current_plan=plan), _make_config(),
            tool_executor=executor, streaming_callbacks={},
        ))
        steps = out["_current_plan"]["steps"]
        self.assertTrue(all(s["success"] for s in steps))
        self.assertEqual(executor.execute.await_count, 2)

    def test_mutex_conflict_rejects_plan_without_executing(self):
        from project_settings import TOOL_MUTEX_GROUPS
        dup = None
        for _g, tools in TOOL_MUTEX_GROUPS.items():
            if tools:
                dup = list(tools)[0]
                break
        if dup is None:
            self.skipTest("no mutex-group tool to test with")
        executor = AsyncMock()
        plan = {"steps": [
            {"tool_name": dup, "tool_args": {}},
            {"tool_name": dup, "tool_args": {}},
        ]}
        out = asyncio.run(execute_plan_node(
            _base_state(_current_plan=plan), _make_config(),
            tool_executor=executor, streaming_callbacks={},
        ))
        steps = out["_current_plan"]["steps"]
        self.assertTrue(all(not s["success"] for s in steps))
        self.assertTrue(all("rejected" in (s["tool_output"] or "").lower() for s in steps))
        executor.execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
