"""
Tests for the per-tool Stop feature:

- WebSocketManager tool-task registry (register / unregister / cancel / key derivation)
- ToolStopMessage Pydantic validation
- Cancellation semantics inside execute_plan_node._execute_single_step
  (inner-task cancel = mark failed, flow continues; outer-task cancel = re-raise)
- Cancellation semantics inside execute_tool_node (same rules, no wave_id)

Run with:
    cd agentic && python -m pytest tests/test_tool_stop.py -v
"""

import asyncio
import os
import sys
import unittest
from unittest.mock import MagicMock, AsyncMock

# Add parent dir to path so we can import agentic modules.
_agentic_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _agentic_dir)


# ---------------------------------------------------------------------------
# Stub heavy dependencies — mirrors test_tool_confirmation.py. Must happen
# before importing any agentic module so langgraph/langchain aren't needed.
# ---------------------------------------------------------------------------

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


_stubs = {}
_stub_modules = [
    'langchain_core', 'langchain_core.tools', 'langchain_core.messages',
    'langchain_core.language_models', 'langchain_core.runnables',
    'langchain_mcp_adapters', 'langchain_mcp_adapters.client',
    'langchain_neo4j',
    'langgraph', 'langgraph.graph', 'langgraph.graph.message',
    'langgraph.graph.state', 'langgraph.checkpoint',
    'langgraph.checkpoint.memory',
    'langchain_openai', 'langchain_openai.chat_models',
    'langchain_openai.chat_models.azure', 'langchain_openai.chat_models.base',
    'langchain_anthropic',
    'langchain_core.language_models.chat_models',
    'langchain_core.callbacks', 'langchain_core.outputs',
    # Heavy deps used by websocket_api only; stub them so the import works.
    'fastapi', 'httpx',
]
for mod_name in _stub_modules:
    if mod_name not in sys.modules:
        _stubs[mod_name] = MagicMock()
        sys.modules[mod_name] = _stubs[mod_name]

sys.modules['langchain_core.messages'].AIMessage = FakeAIMessage
sys.modules['langchain_core.messages'].HumanMessage = FakeHumanMessage
sys.modules['langgraph.graph.message'].add_messages = _fake_add_messages


# chat_persistence has a Prisma dependency — stub it so websocket_api imports.
if 'chat_persistence' not in sys.modules:
    _cp = MagicMock()
    _cp.save_chat_message = AsyncMock()
    _cp.update_conversation = AsyncMock()
    sys.modules['chat_persistence'] = _cp


from websocket_api import WebSocketManager, ToolStopMessage, MessageType
from pydantic import ValidationError


# ---------------------------------------------------------------------------
# WebSocketManager tool-task registry
# ---------------------------------------------------------------------------

class TestToolTaskKey(unittest.TestCase):
    """Pure helper — verifies key construction is deterministic and
    disambiguates same-name tools across waves / step_indices."""

    def test_wave_and_step_present(self):
        k = WebSocketManager._tool_task_key(
            session_key="u:p:s", tool_name="shodan",
            wave_id="wave-1-abc", step_index=0,
        )
        self.assertEqual(k, "u:p:s|wave-1-abc|0|shodan")

    def test_standalone_tool_sentinel(self):
        k = WebSocketManager._tool_task_key(
            session_key="u:p:s", tool_name="shodan",
            wave_id=None, step_index=None,
        )
        self.assertEqual(k, "u:p:s|__standalone__|-1|shodan")

    def test_same_name_different_step_produces_different_key(self):
        k1 = WebSocketManager._tool_task_key("u:p:s", "shodan", "wave-1", 0)
        k2 = WebSocketManager._tool_task_key("u:p:s", "shodan", "wave-1", 1)
        self.assertNotEqual(k1, k2)

    def test_same_name_different_wave_produces_different_key(self):
        k1 = WebSocketManager._tool_task_key("u:p:s", "shodan", "wave-1", 0)
        k2 = WebSocketManager._tool_task_key("u:p:s", "shodan", "wave-2", 0)
        self.assertNotEqual(k1, k2)


class TestToolTaskRegistry(unittest.IsolatedAsyncioTestCase):
    """Tests for register/unregister/cancel_tool_task on WebSocketManager."""

    def setUp(self):
        self.mgr = WebSocketManager()

    async def _make_task(self, *, hang_seconds: float = 5.0) -> asyncio.Task:
        async def _coro():
            await asyncio.sleep(hang_seconds)
            return "ok"
        return asyncio.ensure_future(_coro())

    async def asyncTearDown(self):
        # Cancel any still-running tasks we created so the test loop doesn't
        # warn about dangling coroutines.
        for t in list(self.mgr._tool_tasks.values()):
            if not t.done():
                t.cancel()
                try:
                    await t
                except BaseException:
                    pass

    async def test_register_then_cancel_cancels_task(self):
        task = await self._make_task()
        self.mgr.register_tool_task("u:p:s", "shodan", "wave-1", 0, task)

        ok = self.mgr.cancel_tool_task("u:p:s", "shodan", "wave-1", 0)
        self.assertTrue(ok, "cancel_tool_task should have found and cancelled the task")

        # Give the cancellation a chance to land.
        try:
            await task
        except asyncio.CancelledError:
            pass
        self.assertTrue(task.cancelled())

    async def test_cancel_missing_tool_returns_false(self):
        ok = self.mgr.cancel_tool_task("u:p:s", "nonexistent", None, None)
        self.assertFalse(ok)

    async def test_cancel_already_done_task_returns_false(self):
        # Create a task that finishes immediately.
        async def _fast():
            return "done"
        t = asyncio.ensure_future(_fast())
        await t  # drain so it's .done()

        self.mgr.register_tool_task("u:p:s", "shodan", None, None, t)
        ok = self.mgr.cancel_tool_task("u:p:s", "shodan", None, None)
        self.assertFalse(ok, "done tasks should not count as cancellable")

    async def test_unregister_removes_key(self):
        task = await self._make_task()
        self.mgr.register_tool_task("u:p:s", "shodan", None, None, task)
        self.mgr.unregister_tool_task("u:p:s", "shodan", None, None)

        ok = self.mgr.cancel_tool_task("u:p:s", "shodan", None, None)
        self.assertFalse(ok)

    async def test_standalone_fallback_matches_by_tool_name(self):
        """If the frontend sent neither wave_id nor step_index and the exact
        key doesn't match (e.g. registered with a different step_index),
        the fallback should still cancel by tool_name within the session."""
        task = await self._make_task()
        # Registered with step_index that the client won't know
        self.mgr.register_tool_task("u:p:s", "shodan", None, 0, task)

        # Client sends no identifiers at all — fallback should hit
        ok = self.mgr.cancel_tool_task("u:p:s", "shodan", None, None)
        self.assertTrue(ok)

    async def test_wave_scoped_task_is_not_matched_by_standalone_fallback(self):
        """Fallback should NOT cross the wave boundary. A wave-scoped tool
        shouldn't be cancellable via a standalone stop request."""
        task = await self._make_task()
        self.mgr.register_tool_task("u:p:s", "shodan", "wave-1", 0, task)

        ok = self.mgr.cancel_tool_task("u:p:s", "shodan", None, None)
        self.assertFalse(ok)

    async def test_cancel_does_not_affect_other_tools_in_same_session(self):
        t1 = await self._make_task()
        t2 = await self._make_task()
        self.mgr.register_tool_task("u:p:s", "shodan", "w", 0, t1)
        self.mgr.register_tool_task("u:p:s", "nmap", "w", 1, t2)

        self.mgr.cancel_tool_task("u:p:s", "shodan", "w", 0)
        await asyncio.sleep(0)  # let scheduler process cancellation
        self.assertTrue(t1.cancelled() or t1.done())
        self.assertFalse(t2.cancelled())
        self.assertFalse(t2.done())


# ---------------------------------------------------------------------------
# ToolStopMessage Pydantic model
# ---------------------------------------------------------------------------

class TestToolStopMessage(unittest.TestCase):

    def test_minimal_valid(self):
        msg = ToolStopMessage(tool_name="shodan")
        self.assertEqual(msg.tool_name, "shodan")
        self.assertIsNone(msg.wave_id)
        self.assertIsNone(msg.step_index)

    def test_full_payload(self):
        msg = ToolStopMessage(tool_name="shodan", wave_id="wave-1", step_index=3)
        self.assertEqual(msg.wave_id, "wave-1")
        self.assertEqual(msg.step_index, 3)

    def test_requires_tool_name(self):
        with self.assertRaises(ValidationError):
            ToolStopMessage()  # missing tool_name

    def test_tool_stop_is_in_message_type_enum(self):
        self.assertEqual(MessageType.TOOL_STOP.value, "tool_stop")


# ---------------------------------------------------------------------------
# Cancellation semantics inside a tool-execution wrapper
#
# We reproduce the wrapper pattern used in execute_plan_node and
# execute_tool_node (inner asyncio.Task around the tool coroutine, catch
# CancelledError, distinguish inner-cancel from outer-cancel). This lets us
# validate the semantic contract without importing the full LangGraph
# machinery those nodes depend on.
# ---------------------------------------------------------------------------

async def _tool_stop_wrapper(tool_coro, *, on_register=None, on_unregister=None):
    """Replica of the wrapper inside execute_tool_node / execute_plan_node.

    Returns (result_dict, user_stopped_flag). If the outer task itself is
    being cancelled, CancelledError propagates — callers see it.

    Distinguishes per-tool Stop (only the inner _tool_task is cancelled) from
    outer-cancel (global Stop / orchestrator shutdown) via current_task().cancelling().
    Python's asyncio propagates an outer cancel down to awaited tasks, so
    checking _tool_task.cancelled() alone can't tell the two cases apart.
    """
    user_stopped = False
    _tool_task = asyncio.ensure_future(tool_coro)
    if on_register:
        on_register(_tool_task)
    try:
        try:
            result = await _tool_task
        except asyncio.CancelledError:
            _cur = asyncio.current_task()
            outer_being_cancelled = bool(_cur and _cur.cancelling())
            if outer_being_cancelled:
                if not _tool_task.done():
                    _tool_task.cancel()
                raise
            user_stopped = True
            result = {
                "success": False,
                "error": "Stopped by user",
                "output": "Stopped by user",
            }
    finally:
        if on_unregister:
            on_unregister()
    return result, user_stopped


class TestToolExecutionWrapper(unittest.IsolatedAsyncioTestCase):
    """Validates the wrapper's cancellation semantics used in both nodes."""

    async def test_happy_path_returns_result_and_unregisters(self):
        async def _ok():
            return {"success": True, "output": "hello"}

        registered = {}
        unreg_called = {"n": 0}
        def on_reg(t): registered["t"] = t
        def on_unreg(): unreg_called["n"] += 1

        result, stopped = await _tool_stop_wrapper(
            _ok(), on_register=on_reg, on_unregister=on_unreg,
        )
        self.assertEqual(result, {"success": True, "output": "hello"})
        self.assertFalse(stopped)
        self.assertIsNotNone(registered.get("t"))
        self.assertEqual(unreg_called["n"], 1)

    async def test_inner_cancel_marks_user_stopped_and_continues(self):
        """When the inner tool task is cancelled by per-tool Stop, the
        wrapper should recover — NOT re-raise — and return a failure dict
        so the surrounding wave/iteration proceeds normally."""
        async def _slow():
            await asyncio.sleep(10)
            return {"success": True}

        inner_ref = {}
        def on_reg(t):
            inner_ref["t"] = t

        async def _canceller():
            # Let the wrapper schedule the inner task, then cancel just it.
            await asyncio.sleep(0.05)
            inner_ref["t"].cancel()

        canceller = asyncio.ensure_future(_canceller())
        result, stopped = await _tool_stop_wrapper(_slow(), on_register=on_reg)
        await canceller

        self.assertTrue(stopped)
        self.assertEqual(result["success"], False)
        self.assertEqual(result["output"], "Stopped by user")

    async def test_outer_cancel_propagates(self):
        """When the outer wrapper task itself is cancelled (global Stop
        or orchestrator shutdown), CancelledError must propagate — we
        must NOT swallow it and pretend the tool just failed."""
        async def _slow():
            await asyncio.sleep(10)
            return {"success": True}

        async def _run_wrapper():
            return await _tool_stop_wrapper(_slow())

        outer = asyncio.ensure_future(_run_wrapper())
        # Yield to let the wrapper start the inner task.
        await asyncio.sleep(0.05)
        outer.cancel()

        with self.assertRaises(asyncio.CancelledError):
            await outer

    async def test_tool_failure_does_not_register_as_user_stopped(self):
        """A tool that raises an exception internally should not look like
        user_stopped. (Exceptions bubble out of the inner await; wrapper
        doesn't catch them — the caller's outer try/except handles them.)"""
        async def _boom():
            raise RuntimeError("bad tool")

        with self.assertRaises(RuntimeError):
            await _tool_stop_wrapper(_boom())


if __name__ == "__main__":
    unittest.main()
