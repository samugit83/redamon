"""
Integration tests for PhaseAwareToolExecutor's workspace + offload + job wiring.

Covers:
  - executor.execute("fs_write", ...) routes to workspace_fs.DISPATCH
  - executor.execute("fs_*") bypasses phase check (foundational tool)
  - output_mode='inline' arg is stripped before any other handling
  - MCP-style tool with huge output gets offloaded (executor calls maybe_offload)
  - job_spawn enforces phase restriction on the TARGET tool, not on itself
  - job_spawn then job_status returns sensible status

Heavy MCP/langchain deps are stubbed so this runs on the host without the
agent container.

Run with: python3 -m unittest tests.test_executor_workspace_wiring -v
"""
from __future__ import annotations

import asyncio
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock

_AGENTIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _AGENTIC_DIR)

# Stub the heavy langchain / neo4j / mcp dependencies BEFORE importing tools.
_STUBS = [
    "httpx",
    "langchain_core", "langchain_core.tools", "langchain_core.language_models",
    "langchain_core.messages",
    "langchain_mcp_adapters", "langchain_mcp_adapters.client",
    "langchain_neo4j",
    "graph_db", "graph_db.tenant_filter",
    "prompts",
]
for mod_name in _STUBS:
    if mod_name not in sys.modules:
        sys.modules[mod_name] = MagicMock()

sys.modules["graph_db.tenant_filter"].find_disallowed_write_operation = lambda *a, **kw: None
sys.modules["graph_db.tenant_filter"].inject_tenant_filter = lambda c, *a, **kw: c
sys.modules["prompts"].TEXT_TO_CYPHER_SYSTEM = ""

# When graph_db is stubbed with a bare MagicMock, project_settings'
# apply_memory_governor() does `from graph_db import resource_governor` and then
# compares a MagicMock cap with an int (`eff < val`), raising TypeError. Keep the
# governor inert so it short-circuits. Only touch the stub, never a real module.
if isinstance(sys.modules.get("graph_db"), MagicMock):
    sys.modules["graph_db"].resource_governor.governor_enabled = lambda: False

# Stub the `tool` decorator so module-level `@tool` definitions don't blow up.
def _identity_tool(fn=None, **_kw):
    if callable(fn):
        return fn
    return lambda f: f
sys.modules["langchain_core.tools"].tool = _identity_tool

import tools as tools_module  # noqa: E402  (after stubs)
import workspace_fs  # noqa: E402
import job_runner  # noqa: E402
import output_offload  # noqa: E402


class ExecutorWiringTestBase(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="redamon-exec-")
        # Point all workspace modules at the temp root.
        self._orig_ws = workspace_fs.WORKSPACE_ROOT
        self._orig_off = output_offload.WORKSPACE_ROOT
        self._orig_jr = job_runner.WORKSPACE_ROOT
        workspace_fs.WORKSPACE_ROOT = Path(self.tmp)
        output_offload.WORKSPACE_ROOT = Path(self.tmp)
        job_runner.WORKSPACE_ROOT = Path(self.tmp)
        workspace_fs._edit_stack.clear()
        workspace_fs._last_read_contents.clear()
        workspace_fs._last_read_hashes.clear()
        job_runner._registry = None
        # Both tools.py and workspace_fs/job_runner now share these contextvars
        # via agent_context, so setting either side has the same effect.
        import agent_context
        agent_context.current_project_id.set("proj-exec")
        agent_context.current_phase.set("informational")
        self.root = Path(self.tmp) / "proj-exec"
        self.root.mkdir(parents=True, exist_ok=True)

        # Build a minimal executor. MCPToolsManager + graph_tool can be MagicMocks
        # since we never exercise their dispatch paths in these tests.
        self.executor = tools_module.PhaseAwareToolExecutor(
            mcp_manager=MagicMock(),
            graph_tool=None,
        )
        from one_sandbox import route_to

        # A system tool runs in the person's sandbox, whose client serves this table.
        route_to(self, lambda: self.executor._all_tools)

    async def asyncTearDown(self):
        # Cancel any in-flight jobs before restoring WORKSPACE_ROOT.
        if job_runner._registry is not None:
            tasks = [h.task for h in job_runner._registry._jobs.values()
                     if h.task and not h.task.done()]
            for t in tasks:
                t.cancel()
            for t in tasks:
                try:
                    await t
                except (asyncio.CancelledError, Exception):
                    pass
        workspace_fs.WORKSPACE_ROOT = self._orig_ws
        output_offload.WORKSPACE_ROOT = self._orig_off
        job_runner.WORKSPACE_ROOT = self._orig_jr
        job_runner._registry = None
        import agent_context
        agent_context.current_project_id.set("")
        shutil.rmtree(self.tmp, ignore_errors=True)

    def tearDown(self):
        pass  # async version does the work


# =============================================================================
# fs_* dispatch
# =============================================================================

class TestFSDispatch(ExecutorWiringTestBase):
    async def test_fs_write_routes_to_workspace_fs(self):
        result = await self.executor.execute(
            "fs_write", {"path": "hello.txt", "content": "world"}, "informational"
        )
        self.assertTrue(result["success"], msg=str(result))
        self.assertIn("Wrote", result["output"])
        self.assertEqual((self.root / "hello.txt").read_text(), "world")

    async def test_fs_read_roundtrip_via_executor(self):
        await self.executor.execute("fs_write", {"path": "x.txt", "content": "hi"}, "informational")
        result = await self.executor.execute("fs_read", {"path": "x.txt"}, "informational")
        self.assertTrue(result["success"])
        self.assertIn("hi", result["output"])

    async def test_fs_tool_bypasses_phase_check(self):
        # fs_* is foundational - should be allowed even in a phase where
        # arbitrary tools are denied.
        result = await self.executor.execute("fs_list", {"path": "."}, "exploitation")
        self.assertTrue(result["success"])
        # And in post-exploitation
        result = await self.executor.execute("fs_list", {"path": "."}, "post_exploitation")
        self.assertTrue(result["success"])

    async def test_fs_tool_bad_args_surfaces_clean_error(self):
        # fs_read takes `path`, not `pathh`. Should not crash.
        result = await self.executor.execute("fs_read", {"pathh": "x"}, "informational")
        self.assertFalse(result["success"])
        self.assertIn("bad arguments", result["error"])

    async def test_fs_tool_internal_error_caught(self):
        # Force an unhandled exception inside the fs coroutine by monkeypatching
        # the dispatch entry to raise.
        async def boom(**kw):
            raise RuntimeError("simulated internal error")
        orig = workspace_fs.DISPATCH["fs_read"]
        workspace_fs.DISPATCH["fs_read"] = boom
        try:
            result = await self.executor.execute("fs_read", {"path": "x"}, "informational")
            self.assertFalse(result["success"])
            self.assertIn("simulated internal error", result["error"])
        finally:
            workspace_fs.DISPATCH["fs_read"] = orig


# =============================================================================
# output_mode override stripping + offload integration
# =============================================================================

class TestOutputModeStripping(ExecutorWiringTestBase):
    async def test_output_mode_stripped_before_dispatch(self):
        # The fs_write tool would crash with TypeError if output_mode reached
        # it (it doesn't accept that kwarg). After stripping it should work.
        result = await self.executor.execute(
            "fs_write",
            {"path": "z.txt", "content": "v", "output_mode": "inline"},
            "informational",
        )
        self.assertTrue(result["success"], msg=str(result))


# =============================================================================
# job_* dispatch
# =============================================================================

class TestJobDispatch(ExecutorWiringTestBase):
    async def test_job_spawn_requires_tool_name(self):
        result = await self.executor.execute(
            "job_spawn", {"args": {}}, "informational"
        )
        self.assertFalse(result["success"])
        self.assertIn("tool_name", result["error"])

    async def test_job_spawn_enforces_target_phase(self):
        # execute_hydra is only allowed in exploitation/post_exploitation.
        # Spawning it in informational must be rejected.
        import agent_context
        agent_context.current_phase.set("informational")
        result = await self.executor.execute(
            "job_spawn",
            {"tool_name": "execute_hydra", "args": {}},
            "informational",
        )
        self.assertFalse(result["success"])
        self.assertIn("not allowed", result["error"])

    async def test_job_spawn_then_status_for_fs_tool_target(self):
        # job_spawn an fs_write (legal in any phase) and verify status flow.
        result = await self.executor.execute(
            "job_spawn",
            {
                "tool_name": "fs_write",
                "args": {"path": "bgwrite.txt", "content": "from-job"},
            },
            "informational",
        )
        self.assertTrue(result["success"], msg=str(result))
        # Spawn output is the str() of a dict
        self.assertIn("job_id", result["output"])
        # Parse out the job_id (it's a uuid hex in the dict-string)
        import re as _re
        m = _re.search(r"'job_id':\s*'([0-9a-f]{32})'", result["output"])
        self.assertIsNotNone(m, f"no job_id in {result['output']}")
        job_id = m.group(1)

        # Wait briefly for it to complete
        for _ in range(50):
            status = await self.executor.execute(
                "job_status", {"job_id": job_id}, "informational"
            )
            if "'done'" in status["output"] or "'failed'" in status["output"]:
                break
            await asyncio.sleep(0.02)
        self.assertIn("'done'", status["output"])
        # File should exist
        self.assertEqual((self.root / "bgwrite.txt").read_text(), "from-job")

    async def test_job_status_unknown_job(self):
        result = await self.executor.execute(
            "job_status", {"job_id": "nonexistent"}, "informational"
        )
        self.assertTrue(result["success"])  # job_status doesn't fail on unknown
        self.assertIn("unknown job", result["output"])

    async def test_job_list_returns_list_repr(self):
        result = await self.executor.execute(
            "job_list", {}, "informational"
        )
        self.assertTrue(result["success"])
        # Empty project -> empty list
        self.assertIn("[]", result["output"])

    async def test_job_wait_via_executor(self):
        # Spawn an fs_write job, then job_wait for it.
        spawn = await self.executor.execute(
            "job_spawn",
            {"tool_name": "fs_write", "args": {"path": "waited.txt", "content": "v"}},
            "informational",
        )
        self.assertTrue(spawn["success"])
        import re as _re
        m = _re.search(r"'job_id':\s*'([0-9a-f]{32})'", spawn["output"])
        self.assertIsNotNone(m)
        job_id = m.group(1)
        result = await self.executor.execute(
            "job_wait", {"job_id": job_id, "timeout_sec": 5.0}, "informational"
        )
        self.assertTrue(result["success"])
        self.assertIn("'done'", result["output"])

    async def test_job_cancel_via_executor(self):
        # Spawn a job that hangs longer than our cancel window. The patched
        # DISPATCH entry must accept the fs-tool kwargs (path, content) since
        # that's what _dispatch_fs_tool calls it with.
        async def slow_runner(**kw):
            await asyncio.sleep(5.0)
            return "would-not-reach"
        orig_write = workspace_fs.DISPATCH["fs_write"]
        workspace_fs.DISPATCH["fs_write"] = slow_runner
        try:
            spawn = await self.executor.execute(
                "job_spawn",
                {"tool_name": "fs_write", "args": {"path": "x", "content": "y"}},
                "informational",
            )
            self.assertTrue(spawn["success"])
            import re as _re
            m = _re.search(r"'job_id':\s*'([0-9a-f]{32})'", spawn["output"])
            job_id = m.group(1)
            await asyncio.sleep(0.05)  # let it enter the sleep
            result = await self.executor.execute(
                "job_cancel", {"job_id": job_id}, "informational"
            )
            self.assertTrue(result["success"])
            self.assertIn("'cancelled'", result["output"])
        finally:
            workspace_fs.DISPATCH["fs_write"] = orig_write

    async def test_job_list_active_filter_via_executor(self):
        # Spawn one quick (already done) and one slow (still running) job.
        slow_done = asyncio.Event()

        async def slow_runner(**kw):
            try:
                await asyncio.wait_for(slow_done.wait(), timeout=10)
            except asyncio.TimeoutError:
                pass
            return "slow-done"

        # Monkeypatch fs_write to be slow for this test.
        orig = workspace_fs.DISPATCH["fs_write"]
        workspace_fs.DISPATCH["fs_write"] = slow_runner
        try:
            # Quick job: fs_mkdir (still real, returns fast)
            await self.executor.execute(
                "job_spawn", {"tool_name": "fs_mkdir", "args": {"path": "quick-dir"}},
                "informational",
            )
            await asyncio.sleep(0.05)
            # Slow job
            await self.executor.execute(
                "job_spawn", {"tool_name": "fs_write", "args": {"path": "slow.txt", "content": "x"}},
                "informational",
            )
            await asyncio.sleep(0.05)

            all_result = await self.executor.execute("job_list", {}, "informational")
            self.assertTrue(all_result["success"])
            # Both jobs visible in unfiltered list
            self.assertIn("fs_mkdir", all_result["output"])
            self.assertIn("fs_write", all_result["output"])

            active_result = await self.executor.execute(
                "job_list", {"active": True}, "informational"
            )
            self.assertTrue(active_result["success"])
            # Only the slow one is still running
            self.assertIn("fs_write", active_result["output"])
            self.assertNotIn("fs_mkdir", active_result["output"])
        finally:
            slow_done.set()  # let the runner exit cleanly
            workspace_fs.DISPATCH["fs_write"] = orig

    async def test_job_spawn_with_mcp_style_target_tees_full_output(self):
        # Realistic scenario: agent spawns a long MCP-style scan in the
        # background. The runner forces output_mode='inline' so the executor
        # does NOT offload inside the spawned call - the full output stays
        # complete in the job log, where fs_grep can find it later.
        class FakeNuclei:
            name = "execute_nuclei"

            async def ainvoke(self, args):
                # Return enough content to trip the offload threshold normally.
                return "[INFO] finding-A\n" * 5000  # ~85KB

        self.executor._all_tools["execute_nuclei"] = FakeNuclei()

        spawn = await self.executor.execute(
            "job_spawn",
            {"tool_name": "execute_nuclei", "args": {"target": "example.com"}},
            "informational",
        )
        self.assertTrue(spawn["success"], msg=str(spawn))
        import re as _re
        m = _re.search(r"'job_id':\s*'([0-9a-f]{32})'", spawn["output"])
        self.assertIsNotNone(m)
        job_id = m.group(1)
        # Wait for completion
        result = await self.executor.execute(
            "job_wait", {"job_id": job_id, "timeout_sec": 5.0}, "informational"
        )
        self.assertTrue(result["success"])
        # Full content must have landed in the log file - not a stub.
        log_path = self.root / "jobs" / f"{job_id}.log"
        log_content = log_path.read_text()
        self.assertNotIn("[Output offloaded:", log_content,
                         "runner should have forced inline so log gets full content")
        # Should contain many copies of the finding string
        self.assertGreaterEqual(log_content.count("finding-A"), 1000)

    async def test_job_runner_propagates_target_failure(self):
        # Plant a target that always fails - the job should end up as 'failed'
        # with the underlying error surfaced.
        async def always_fails(**kw):
            return "Error: nope"  # fs tools return error strings, not exceptions
        # Actually our fs tools return strings via success=True - the runner
        # treats success as the executor.execute() return. So a fake target
        # that raises is a better test of failure propagation.
        async def raises(**kw):
            raise RuntimeError("target tool exploded")
        orig = workspace_fs.DISPATCH["fs_read"]
        workspace_fs.DISPATCH["fs_read"] = raises
        try:
            spawn = await self.executor.execute(
                "job_spawn",
                {"tool_name": "fs_read", "args": {"path": "anything"}},
                "informational",
            )
            self.assertTrue(spawn["success"])
            import re as _re
            m = _re.search(r"'job_id':\s*'([0-9a-f]{32})'", spawn["output"])
            job_id = m.group(1)
            result = await self.executor.execute(
                "job_wait", {"job_id": job_id, "timeout_sec": 2.0}, "informational"
            )
            self.assertTrue(result["success"])
            # Status should be failed; error string should mention our exception
            self.assertIn("'failed'", result["output"])
            self.assertIn("target tool exploded", result["output"])
        finally:
            workspace_fs.DISPATCH["fs_read"] = orig


# =============================================================================
# Offload integration on a synthetic MCP-style tool
# =============================================================================

class TestOffloadInExecutor(ExecutorWiringTestBase):
    async def test_huge_output_from_synthetic_tool_offloaded(self):
        # Plant a synthetic tool that returns a huge string. Register it
        # in the executor's `_all_tools` so the existing dispatch path picks
        # it up, but mark it as MCP-named so it goes through _invoke().
        class FakeTool:
            name = "execute_nuclei"  # 'always' offload policy

            async def ainvoke(self, args):
                return "X" * 100_000

        self.executor._all_tools["execute_nuclei"] = FakeTool()
        # Patch the phase check so execute_nuclei is allowed in informational
        # (the default project map allows it - but our test runs without the
        # real project_settings loaded, so we patch).
        result = await self.executor.execute(
            "execute_nuclei",
            {"target": "example.com"},
            "informational",
            skip_phase_check=True,  # bypass the unfamiliar test-env phase map
        )
        self.assertTrue(result["success"], msg=str(result))
        # Should have been offloaded - output is a stub, not the 100k blob
        self.assertIn("[Output offloaded:", result["output"])
        self.assertLess(len(result["output"]), 10_000)
        # The full content should be on disk
        outputs_dir = self.root / "tool-outputs"
        files = list(outputs_dir.iterdir())
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0].stat().st_size, 100_000)

    async def test_inline_override_prevents_offload(self):
        class FakeTool:
            name = "execute_nuclei"

            async def ainvoke(self, args):
                return "X" * 100_000

        self.executor._all_tools["execute_nuclei"] = FakeTool()
        result = await self.executor.execute(
            "execute_nuclei",
            {"target": "example.com", "output_mode": "inline"},
            "informational",
            skip_phase_check=True,
        )
        self.assertTrue(result["success"])
        self.assertNotIn("[Output offloaded:", result["output"])
        self.assertEqual(len(result["output"]), 100_000)


# =============================================================================
# Result-shape consistency: every executor return path uses {success,output,error}
# =============================================================================

class TestResultShapeConsistency(ExecutorWiringTestBase):
    SHAPE_KEYS = {"success", "output", "error"}

    def _check_shape(self, result, label):
        self.assertIsInstance(result, dict, f"{label}: not a dict")
        self.assertEqual(set(result.keys()), self.SHAPE_KEYS,
                         f"{label}: keys = {set(result.keys())}")
        self.assertIsInstance(result["success"], bool, f"{label}: success not bool")

    async def test_fs_dispatch_shape(self):
        ok = await self.executor.execute("fs_write", {"path": "a.txt", "content": "v"}, "informational")
        self._check_shape(ok, "fs_write happy")
        bad = await self.executor.execute("fs_read", {"wrong_kwarg": "x"}, "informational")
        self._check_shape(bad, "fs_read bad args")

    async def test_job_dispatch_shape(self):
        for name, args in [
            ("job_list", {}),
            ("job_status", {"job_id": "nope"}),
            ("job_spawn", {}),  # missing tool_name -> error
        ]:
            r = await self.executor.execute(name, args, "informational")
            self._check_shape(r, f"{name}({args})")

    async def test_phase_rejection_shape(self):
        # Tool not in TOOL_PHASE_MAP, not in manifest -> rejected. Should
        # still return the canonical shape (not raise).
        r = await self.executor.execute(
            "unknown_random_tool", {}, "informational"
        )
        self._check_shape(r, "phase-rejected unknown tool")
        self.assertFalse(r["success"])

    async def test_unknown_tool_shape(self):
        # Bypass phase check so we hit the 'tool not found' branch.
        r = await self.executor.execute(
            "fully_unregistered_tool", {}, "informational", skip_phase_check=True
        )
        self._check_shape(r, "unknown tool")
        self.assertFalse(r["success"])
        self.assertIn("not found", r["error"])


if __name__ == "__main__":
    unittest.main()
