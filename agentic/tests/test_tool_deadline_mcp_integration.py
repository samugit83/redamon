"""Real-transport reproduction of the hung execute_code card.

A real MCP SSE server (mcp's FastMCP behind uvicorn, the same stack kali-sandbox
runs) exposes an execute_code tool whose answer never comes back, while the SSE
stream keeps sending keep-alive pings. The agent side is the real
MCPToolsManager + langchain-mcp-adapters + PhaseAwareToolExecutor.

1. Reproduces the bug: with no agent-side deadline the call is still pending
   long after sse_read_timeout, because every ping resets httpx's read timer.
   That is why the card in the incident kept "Running" for 1837s.
2. Demonstrates the fix: the per-tool deadline returns a clear failure.
3. Shows normal calls through the same transport are unaffected, including the
   call right after an abandoned one.

Run: ./agentic/run_tests.sh integration   (or this file alone)
"""
import asyncio
import socket
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

try:
    import uvicorn
    from mcp.server.fastmcp import FastMCP
    from sse_starlette.sse import EventSourceResponse

    from tools import MCPToolsManager, PhaseAwareToolExecutor, TOOL_DEADLINES_S
    _HAVE = True
except Exception as _exc:  # pragma: no cover - only outside the agent image
    _HAVE = False
    _WHY = repr(_exc)

PING_S = 1          # server keep-alive interval (kali uses sse-starlette's 15s)
READ_TIMEOUT_S = 3  # agent sse_read_timeout; > PING_S so pings keep resetting it


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _build_server():
    srv = FastMCP("fake-kali-network-recon")

    @srv.tool()
    async def execute_code(code: str, language: str = "python", filename: str = "exploit") -> str:
        """Fake kali execute_code: 'HANG' in the code means the answer is lost."""
        if "HANG" in code:
            await asyncio.sleep(3600)
        return "uid=0(root) gid=0(root)"

    return srv.sse_app()


@unittest.skipUnless(_HAVE, "agent image deps unavailable")
class LostMcpAnswer(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls._ping_patch = mock.patch.object(EventSourceResponse, "DEFAULT_PING_INTERVAL", PING_S)
        cls._ping_patch.start()
        cls.port = _free_port()
        config = uvicorn.Config(_build_server(), host="127.0.0.1", port=cls.port,
                                log_level="warning", lifespan="off")
        cls.server = uvicorn.Server(config)
        cls.thread = threading.Thread(target=cls.server.run, daemon=True)
        cls.thread.start()
        deadline = time.monotonic() + 15
        while not cls.server.started:
            if time.monotonic() > deadline:
                raise RuntimeError("fake MCP server did not start")
            time.sleep(0.05)

    @classmethod
    def tearDownClass(cls):
        cls.server.should_exit = True
        cls.thread.join(timeout=10)
        cls._ping_patch.stop()

    async def asyncSetUp(self):
        import sandbox_contract
        import sandbox_router

        # The fake server stands in for the shared sandbox (no person is bound). No
        # gateway answers and the default mode is per_user, so shared mode is named.
        sandbox_router._reset(mode=sandbox_contract.MODE_SHARED)
        self.addCleanup(sandbox_router._reset)
        self.mgr = MCPToolsManager({
            "network_recon": {
                "url": f"http://127.0.0.1:{self.port}/sse",
                "transport": "sse",
                "timeout": 5,
                "sse_read_timeout": READ_TIMEOUT_S,
            }
        })
        tools = await self.mgr.get_tools(max_retries=2, retry_delay=0.5)
        self.assertEqual([t.name for t in tools], ["execute_code"])
        self.ex = PhaseAwareToolExecutor(self.mgr, graph_tool=None)
        self.ex.register_mcp_tools(tools)

    async def _call(self, code: str):
        return await self.ex.execute("execute_code", {"code": code}, "exploitation",
                                     skip_phase_check=True)

    async def test_0_control_without_pings_the_read_timeout_does_fire(self):
        """Isolates the cause: the same lost answer with keep-alives off ends by
        itself at sse_read_timeout. So it is the pings that defeat the timeout."""
        with mock.patch.dict(TOOL_DEADLINES_S, {"execute_code": 0.0}), \
                mock.patch.object(EventSourceResponse, "DEFAULT_PING_INTERVAL", 3600):
            t0 = time.monotonic()
            result = await asyncio.wait_for(self._call("HANG"), timeout=READ_TIMEOUT_S * 10)
            elapsed = time.monotonic() - t0
        self.assertFalse(result["success"])
        self.assertGreaterEqual(elapsed, READ_TIMEOUT_S)

    async def test_1_bug_reproduction_transport_timeout_never_fires(self):
        """Without an agent deadline, the lost answer is waited on forever: the
        call is still pending at 3x sse_read_timeout because of the pings."""
        with mock.patch.dict(TOOL_DEADLINES_S, {"execute_code": 0.0}):
            call = asyncio.ensure_future(self._call("HANG"))
            done, _ = await asyncio.wait({call}, timeout=READ_TIMEOUT_S * 3)
            self.assertFalse(done, "the call ended on its own; the hang no longer reproduces")
            call.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await call

    async def test_2_fix_deadline_ends_the_call_with_a_clear_failure(self):
        with mock.patch.dict(TOOL_DEADLINES_S, {"execute_code": 4.0}):
            t0 = time.monotonic()
            result = await asyncio.wait_for(self._call("HANG"), timeout=30)
            elapsed = time.monotonic() - t0
        self.assertFalse(result["success"])
        self.assertIn("gave no answer within 4s", result["error"])
        self.assertGreaterEqual(elapsed, 4.0)
        self.assertLess(elapsed, 10.0)

    async def test_3_normal_calls_still_work_after_an_abandoned_one(self):
        with mock.patch.dict(TOOL_DEADLINES_S, {"execute_code": 2.0}):
            lost = await self._call("HANG")
            ok = await self._call("print('id')")
        self.assertFalse(lost["success"])
        self.assertTrue(ok["success"], ok)
        self.assertIn("uid=0(root)", ok["output"])


if __name__ == "__main__":
    unittest.main()
