"""Per-tool wall-clock deadline in PhaseAwareToolExecutor.execute().

Regression for the "agent stuck" incident: an execute_code card sat at
"Running... (1837s)" for a script kali-sandbox kills after 120s. The answer was
lost on the MCP SSE transport, and nothing on the agent side bounded the wait:
the server's 15s SSE keep-alive resets the read timeout, so sse_read_timeout
never fires. These tests pin the bound that now ends such a call, and the
real-transport reproduction lives in test_tool_deadline_mcp_integration.py.

Run: ./agentic/run_tests.sh tests/test_tool_deadline.py
"""
import asyncio
import os
import re
import sys
import time
import unittest
from pathlib import Path
from unittest import mock
from unittest.mock import AsyncMock, MagicMock

_AGENTIC_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_AGENTIC_DIR))

import tools  # noqa: E402
from tools import (  # noqa: E402
    MCPToolsManager,
    PhaseAwareToolExecutor,
    TOOL_DEADLINE_DEFAULT_S,
    TOOL_DEADLINES_S,
    ToolDeadlineExceeded,
    tool_deadline_seconds,
)

_MCP_SERVERS_DIR = _AGENTIC_DIR.parent / "mcp" / "servers"


def _server_tool_limits() -> dict:
    """{tool_name: largest timeout=N inside its @mcp.tool() body} for kali servers."""
    limits = {}
    for path in sorted(_MCP_SERVERS_DIR.glob("*_server.py")):
        src = path.read_text(encoding="utf-8")
        # Split on tool definitions; each chunk runs to the next top-level def.
        for m in re.finditer(r"@mcp\.tool\(\)\s*\ndef (\w+)\(", src):
            body_start = m.end()
            nxt = re.search(r"\n(?:@mcp\.tool\(\)|def |async def |class )", src[body_start:])
            body = src[body_start: body_start + (nxt.start() if nxt else len(src))]
            found = [int(x) for x in re.findall(r"timeout\s*=\s*(\d+)", body)]
            if found:
                limits[m.group(1)] = max(found)
    return limits


class _NeverAnswers:
    """An MCP tool whose answer never comes back (the lost-response case)."""

    def __init__(self, name):
        self.name = name
        self.started = asyncio.Event()

    async def ainvoke(self, args):
        self.started.set()
        await asyncio.Event().wait()


class _Answers:
    def __init__(self, name, text="[INFO] ok"):
        self.name = name
        self.text = text

    async def ainvoke(self, args):
        return self.text


_built: dict = {}


def _executor(*mcp_tools):
    """An executor whose system tools run in the person's sandbox (_InASandbox): its
    client serves these tools, and its reconnect is the test's `mcp_manager.reconnect`."""
    mgr = MCPToolsManager({"fake": {"url": "http://x/sse", "transport": "sse",
                                    "timeout": 60, "sse_read_timeout": 60}})
    mgr.reconnect = AsyncMock(return_value=(0, []))
    ex = PhaseAwareToolExecutor(mgr, graph_tool=None)
    ex.register_mcp_tools(list(mcp_tools))
    _built["ex"] = ex
    return ex


class _InASandbox(unittest.IsolatedAsyncioTestCase):
    """The Kali tools run in one person's sandbox (one_sandbox), serving the last
    executor's tools."""

    def setUp(self):
        from one_sandbox import route_to

        async def reconnect(seen, reason="", force=False):
            return await _built["ex"].mcp_manager.reconnect(seen, reason=reason)

        route_to(self, lambda: _built["ex"]._all_tools, reconnect=reconnect)


class DeadlineTable(unittest.TestCase):
    def test_execute_code_deadline_is_its_server_limit_plus_margin(self):
        # kali runs C/C++ as 60s compile + 120s run; the agent waits 60s more.
        self.assertEqual(tool_deadline_seconds("execute_code"), 240.0)

    def test_every_kali_tool_deadline_exceeds_its_server_limit(self):
        """Drift guard: a tool must never be abandoned before the limit kali
        itself enforces, or a slow-but-working call would be cut short."""
        limits = _server_tool_limits()
        self.assertIn("execute_code", limits, "server parser found no tools")
        self.assertGreaterEqual(len(limits), 15)
        for name, limit in limits.items():
            with self.subTest(tool=name):
                self.assertIn(name, TOOL_DEADLINES_S,
                              f"{name} has a server timeout but no agent deadline entry")
                self.assertGreater(TOOL_DEADLINES_S[name], limit)

    def test_unknown_tool_gets_the_long_default(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("TOOL_DEADLINE_DEFAULT", None)
            self.assertEqual(tool_deadline_seconds("user_custom_mcp_tool"), TOOL_DEADLINE_DEFAULT_S)
        self.assertGreater(TOOL_DEADLINE_DEFAULT_S, max(_server_tool_limits().values()))

    def test_default_env_override_and_invalid_value(self):
        with mock.patch.dict(os.environ, {"TOOL_DEADLINE_DEFAULT": "90"}):
            self.assertEqual(tool_deadline_seconds("user_custom_mcp_tool"), 90.0)
            # The table still wins for known tools.
            self.assertEqual(tool_deadline_seconds("execute_code"), 240.0)
        with mock.patch.dict(os.environ, {"TOOL_DEADLINE_DEFAULT": "soon"}):
            self.assertEqual(tool_deadline_seconds("user_custom_mcp_tool"), TOOL_DEADLINE_DEFAULT_S)
        with mock.patch.dict(os.environ, {"TOOL_DEADLINE_DEFAULT": "0"}):
            self.assertEqual(tool_deadline_seconds("user_custom_mcp_tool"), 0.0)


class DeadlineEnforcement(_InASandbox):
    async def test_lost_answer_returns_a_failure_instead_of_hanging(self):
        tool = _NeverAnswers("execute_code")
        ex = _executor(tool)
        with mock.patch.dict(TOOL_DEADLINES_S, {"execute_code": 0.3}):
            t0 = time.monotonic()
            result = await asyncio.wait_for(
                ex.execute("execute_code", {"code": "print(1)"}, "exploitation",
                           skip_phase_check=True),
                timeout=5,
            )
            elapsed = time.monotonic() - t0
        self.assertTrue(tool.started.is_set())
        self.assertFalse(result["success"])
        self.assertIsNone(result["output"])
        self.assertIn("gave no answer within 0s", result["error"])
        self.assertIn("Do not assume", result["error"])
        self.assertLess(elapsed, 2.0)

    async def test_deadline_does_not_trigger_mcp_reconnect_or_retry(self):
        tool = _NeverAnswers("execute_code")
        ex = _executor(tool)
        with mock.patch.dict(TOOL_DEADLINES_S, {"execute_code": 0.2}):
            await ex.execute("execute_code", {}, "exploitation", skip_phase_check=True)
        ex.mcp_manager.reconnect.assert_not_called()

    async def test_fast_tool_is_unaffected(self):
        ex = _executor(_Answers("execute_code", "uid=0(root)"))
        with mock.patch.dict(TOOL_DEADLINES_S, {"execute_code": 5}):
            result = await ex.execute("execute_code", {}, "exploitation", skip_phase_check=True)
        self.assertTrue(result["success"])
        self.assertIn("uid=0(root)", result["output"])

    async def test_timeout_raised_by_the_tool_itself_is_not_a_missed_deadline(self):
        class _OwnTimeout:
            name = "execute_curl"

            async def ainvoke(self, args):
                raise TimeoutError("upstream read timed out")

        ex = _executor(_OwnTimeout())
        result = await ex.execute("execute_curl", {}, "exploitation", skip_phase_check=True)
        self.assertFalse(result["success"])
        self.assertIn("upstream read timed out", result["error"])
        self.assertNotIn("gave no answer", result["error"])

    async def test_outer_cancel_still_propagates(self):
        """The per-tool Stop logic in execute_tool_node relies on a cancel of the
        surrounding task arriving as CancelledError, never as a deadline."""
        tool = _NeverAnswers("execute_code")
        ex = _executor(tool)
        task = asyncio.ensure_future(
            ex.execute("execute_code", {}, "exploitation", skip_phase_check=True))
        await tool.started.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task

    async def test_deadline_of_zero_means_unbounded(self):
        ex = _executor(_Answers("execute_code", "done"))
        with mock.patch.dict(TOOL_DEADLINES_S, {"execute_code": 0.0}):
            result = await ex.execute("execute_code", {}, "exploitation", skip_phase_check=True)
        self.assertTrue(result["success"])

    async def test_retry_after_reconnect_is_bounded_too(self):
        """A dead transport triggers one rebuild + retry; the retried call must
        not be able to hang either."""

        class _Dead:
            name = "execute_code"

            async def ainvoke(self, args):
                raise RuntimeError("Connection closed")

        retry_tool = _NeverAnswers("execute_code")
        ex = _executor(_Dead())
        ex.mcp_manager.reconnect = AsyncMock(return_value=(1, [retry_tool]))
        with mock.patch.dict(TOOL_DEADLINES_S, {"execute_code": 0.3}):
            result = await asyncio.wait_for(
                ex.execute("execute_code", {}, "exploitation", skip_phase_check=True), 5)
        self.assertTrue(retry_tool.started.is_set())
        self.assertFalse(result["success"])
        self.assertIn("gave no answer", result["error"])


class ToolNodeSurfacesTheDeadline(_InASandbox):
    """End-to-end through execute_tool_node: the step gets a terminal verdict,
    so the next think turn can emit tool_complete and the card stops running."""

    async def test_execute_tool_node_marks_the_step_failed(self):
        from orchestrator_helpers.nodes.execute_tool_node import execute_tool_node

        ex = _executor(_NeverAnswers("execute_code"))
        state = {
            "user_id": "u", "project_id": "p", "session_id": "s",
            "current_phase": "exploitation", "current_iteration": 17,
            "_current_step": {"step_id": "abc12345", "tool_name": "execute_code",
                              "tool_args": {"code": "print(1)"}, "tool_output": None},
        }
        with mock.patch.dict(TOOL_DEADLINES_S, {"execute_code": 0.3}), \
                mock.patch.object(tools, "is_tool_allowed_in_phase", return_value=True):
            update = await asyncio.wait_for(
                execute_tool_node(state, {"configurable": {}}, tool_executor=ex,
                                  streaming_callbacks={}),
                timeout=5,
            )
        step = update["_current_step"]
        self.assertFalse(step["success"])
        self.assertIn("gave no answer", step["error_message"])
        self.assertEqual(step["tool_output"], "")
        self.assertIsNotNone(step["duration_ms"])


if __name__ == "__main__":
    unittest.main()
