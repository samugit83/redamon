"""
Unit tests for PLAN_MAX_PARALLEL_TOOLS — the per-wave concurrency cap enforced
in execute_plan_node. Both the root agent and every fireteam member funnel
through that node, so the cap applies uniformly to both paths.

Core contract:
  * A wave of N > cap steps must never see more than `cap` tools running
    concurrently at any instant.
  * ALL steps eventually execute (nothing is dropped).
  * Step results are correctly placed back into the plan in index order.
  * Failures / exceptions in one step do not deprive the semaphore of permits.
  * Setting plumbing: default 10, overridable via project.agentPlanMaxParallelTools.

Run with: python -m pytest tests/test_plan_parallelism.py -v
"""
import asyncio
import os
import sys
import unittest
from unittest.mock import MagicMock, AsyncMock, patch

_agentic_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _agentic_dir)

# Only stub heavy deps when they're genuinely missing (running outside Docker).
# If they ARE installed (e.g. inside the agent container), use the real thing —
# stubbing with MagicMock breaks submodule imports like `langchain_core.messages`.
_stub_modules = [
    'langchain_core', 'langchain_core.tools', 'langchain_core.language_models',
    'langchain_mcp_adapters', 'langchain_mcp_adapters.client',
    'langchain_neo4j',
]
for mod_name in _stub_modules:
    if mod_name in sys.modules:
        continue
    try:
        __import__(mod_name)
    except ImportError:
        sys.modules[mod_name] = MagicMock()

import functools
def _fake_tool(fn):
    @functools.wraps(fn)
    async def wrapper(*args, **kwargs):
        return await fn(*args, **kwargs)
    wrapper.name = fn.__name__
    wrapper.ainvoke = lambda args_dict: fn(**args_dict)
    return wrapper
# Only install the fake decorator when the real one is missing.
if isinstance(sys.modules.get('langchain_core.tools'), MagicMock):
    sys.modules['langchain_core.tools'].tool = _fake_tool
if 'httpx' not in sys.modules:
    try:
        __import__('httpx')
    except ImportError:
        sys.modules['httpx'] = MagicMock()


# ---------------------------------------------------------------------------
# Setting plumbing
# ---------------------------------------------------------------------------

class PlanMaxParallelToolsSettingTests(unittest.TestCase):
    """Default, per-project override, and clamp/parse behaviour.

    The real plumbing lives in fetch_agent_settings() which fetches the
    project JSON from the webapp API and maps camelCase → SCREAMING_SNAKE.
    We mock the HTTP call and assert the mapping + coercion.
    """

    def test_default_is_ten(self):
        from project_settings import DEFAULT_AGENT_SETTINGS
        self.assertEqual(DEFAULT_AGENT_SETTINGS['PLAN_MAX_PARALLEL_TOOLS'], 10)

    def _mock_project_fetch(self, project_payload):
        """
        Stub the `requests` module so fetch_agent_settings (which does
        `import requests` locally and then requests.get(...)) receives our
        fake response without touching the network.
        """
        resp = MagicMock()
        resp.status_code = 200
        resp.raise_for_status = MagicMock()
        resp.json.return_value = project_payload
        fake_requests = MagicMock()
        fake_requests.get = MagicMock(return_value=resp)
        return patch.dict(sys.modules, {"requests": fake_requests})

    def test_fetch_agent_settings_reads_project_field(self):
        from project_settings import fetch_agent_settings
        payload = {
            # Only the field we care about — fetch_agent_settings uses .get()
            # with DEFAULT_AGENT_SETTINGS fallbacks for everything else.
            "agentPlanMaxParallelTools": 4,
        }
        with self._mock_project_fetch(payload):
            settings = fetch_agent_settings("proj-1", "http://unused")
        self.assertEqual(settings["PLAN_MAX_PARALLEL_TOOLS"], 4)

    def test_fetch_agent_settings_uses_default_when_field_absent(self):
        from project_settings import fetch_agent_settings
        with self._mock_project_fetch({}):
            settings = fetch_agent_settings("proj-1", "http://unused")
        self.assertEqual(settings["PLAN_MAX_PARALLEL_TOOLS"], 10)

    def test_fetch_agent_settings_coerces_to_int(self):
        """JSON-over-HTTP sometimes arrives with string-typed numbers."""
        from project_settings import fetch_agent_settings
        with self._mock_project_fetch({"agentPlanMaxParallelTools": "7"}):
            settings = fetch_agent_settings("proj-1", "http://unused")
        self.assertEqual(settings["PLAN_MAX_PARALLEL_TOOLS"], 7)
        self.assertIsInstance(settings["PLAN_MAX_PARALLEL_TOOLS"], int)


# ---------------------------------------------------------------------------
# execute_plan_node enforcement
# ---------------------------------------------------------------------------

class ConcurrencyCapEnforcementTests(unittest.IsolatedAsyncioTestCase):
    """
    The heart of the fix: verify the semaphore actually caps in-flight work.
    We fake the tool executor with a coroutine that atomically tracks how
    many calls are live at any instant; `peak_concurrency` is the ground
    truth the semaphore must not let exceed `cap`.
    """

    def _build_node_with_tracked_executor(self, cap, n_steps,
                                          failing_indices=None,
                                          slow_indices=None):
        """
        Build the args needed to call execute_plan_node directly with a
        MagicMock tool_executor whose .execute() increments a live-counter,
        sleeps briefly, decrements, and returns success/failure.
        """
        failing_indices = set(failing_indices or [])
        slow_indices = set(slow_indices or [])

        live = 0
        peak = 0
        lock = asyncio.Lock()
        call_log = []  # ordered list of (index, kind) for debug

        async def fake_execute(tool_name, tool_args, phase, skip_phase_check=False):
            nonlocal live, peak
            idx = tool_args.get("_idx")
            async with lock:
                live += 1
                if live > peak:
                    peak = live
                call_log.append((idx, "enter"))
            # Slow tools force the semaphore to actually hold others waiting.
            if idx in slow_indices:
                await asyncio.sleep(0.05)
            else:
                await asyncio.sleep(0.01)
            async with lock:
                live -= 1
                call_log.append((idx, "exit"))
            if idx in failing_indices:
                return {"success": False, "output": None, "error": f"boom-{idx}"}
            return {"success": True, "output": f"ok-{idx}", "error": None}

        tool_executor = MagicMock()
        tool_executor.execute = AsyncMock(side_effect=fake_execute)
        # execute_with_progress is only used for progress-streaming tools;
        # our fake won't take that branch, but set it anyway.
        tool_executor.execute_with_progress = AsyncMock(side_effect=fake_execute)

        steps = [
            {"tool_name": "execute_curl", "tool_args": {"_idx": i}, "rationale": f"step-{i}"}
            for i in range(n_steps)
        ]
        state = {
            "_current_plan": {"steps": steps, "plan_rationale": f"wave-of-{n_steps}"},
            "current_phase": "informational",
            "current_iteration": 1,
        }
        config = {"configurable": {"user_id": "u", "project_id": "p", "thread_id": "t"}}

        return state, config, tool_executor, steps, lambda: peak, call_log

    async def _run(self, cap, n_steps, **kwargs):
        """Helper: patch the get_setting lookup to `cap` and run the node."""
        state, config, tool_executor, steps, get_peak, call_log = \
            self._build_node_with_tracked_executor(cap, n_steps, **kwargs)

        from orchestrator_helpers.nodes.execute_plan_node import execute_plan_node as node_fn

        # Patch get_setting key-aware: return `cap` for our new knob, delegate
        # to the real function for everything else (RoE checks, etc., need
        # their real defaults — a blanket return_value=N breaks `set(N)` calls).
        from project_settings import get_setting as real_get_setting
        def _fake_get_setting(key, default=None):
            if key == 'PLAN_MAX_PARALLEL_TOOLS':
                return cap
            return real_get_setting(key, default)

        with patch("project_settings.get_setting", side_effect=_fake_get_setting):
            result = await node_fn(
                state, config,
                tool_executor=tool_executor,
                streaming_callbacks={},
                session_manager_base="http://unused",
                graph_view_cyphers=None,
            )
        return result, steps, get_peak(), call_log

    async def test_cap_respected_for_large_wave(self):
        """20 steps with cap=4 — peak concurrency must be exactly 4 (or less)."""
        result, steps, peak, _ = await self._run(cap=4, n_steps=20,
                                                  slow_indices=set(range(20)))
        self.assertLessEqual(peak, 4, f"Semaphore leaked permits, peak={peak}")
        # All 20 ran to completion
        self.assertEqual(sum(1 for s in steps if s.get("success")), 20)

    async def test_cap_one_forces_strict_serialisation(self):
        """cap=1 must never let two tools overlap."""
        _, steps, peak, call_log = await self._run(cap=1, n_steps=8,
                                                    slow_indices=set(range(8)))
        self.assertEqual(peak, 1)
        # Validate the log: every enter must be preceded by a matching exit
        # (except the very first), i.e. strictly serial.
        live = 0
        for _idx, kind in call_log:
            live += 1 if kind == "enter" else -1
            self.assertIn(live, (0, 1), f"live={live} unexpected under cap=1")
        self.assertEqual(sum(1 for s in steps if s.get("success")), 8)

    async def test_small_wave_under_cap_runs_fully_parallel(self):
        """If the wave fits under the cap, nothing should be throttled."""
        _, steps, peak, _ = await self._run(cap=10, n_steps=5,
                                             slow_indices=set(range(5)))
        # Peak should equal n_steps (all started concurrently) — semaphore is
        # big enough that no task waited.
        self.assertEqual(peak, 5)
        self.assertEqual(sum(1 for s in steps if s.get("success")), 5)

    async def test_all_steps_complete_and_results_in_index_order(self):
        """
        Throttling must not reorder results: steps[i].success must reflect
        the i-th planned step, not whichever finished first.
        """
        failing = {3, 7, 11}
        _, steps, peak, _ = await self._run(cap=4, n_steps=15,
                                             failing_indices=failing)
        self.assertLessEqual(peak, 4)
        for i, s in enumerate(steps):
            expected_ok = i not in failing
            self.assertEqual(s["success"], expected_ok,
                             f"step[{i}] success={s['success']} expected {expected_ok}")

    async def test_failing_step_does_not_leak_semaphore_permit(self):
        """
        If an early batch of steps all fail, the semaphore must still release
        its permits so the queued steps can run. With cap=2 and every step
        failing, all 10 must eventually complete (no hang).
        """
        result, steps, peak, _ = await self._run(
            cap=2, n_steps=10,
            failing_indices=set(range(10)),
        )
        self.assertLessEqual(peak, 2)
        # All ran (just with success=False) — this proves no permit leak.
        # If the semaphore leaked, some steps would have never started and
        # success would still be None (unset).
        self.assertEqual(len(steps), 10)
        for i, s in enumerate(steps):
            self.assertIn("success", s, f"step[{i}] was never executed")
            self.assertFalse(s["success"])

    async def test_cap_zero_does_not_deadlock(self):
        """
        Edge case: a misconfigured cap of 0 must never hang forever. The node
        treats 0 as "use default 10" (via `int(x) or 10`) then clamps with
        max(1, _). We only assert that all steps complete — the exact fallback
        value is implementation detail.
        """
        _, steps, peak, _ = await self._run(cap=0, n_steps=3)
        self.assertEqual(sum(1 for s in steps if s.get("success")), 3)
        self.assertGreaterEqual(peak, 1, "At least one step must have run")

    async def test_twenty_steps_cap_ten_matches_user_scenario(self):
        """
        The exact scenario the user asked about: a 20-tool plan with cap=10.
        Expect peak=10 and all 20 to complete.
        """
        _, steps, peak, _ = await self._run(cap=10, n_steps=20,
                                             slow_indices=set(range(20)))
        self.assertLessEqual(peak, 10)
        # With 20 uniformly-slow tools and cap=10, two batches worth —
        # the first 10 start concurrently, driving peak to exactly 10.
        self.assertEqual(peak, 10,
                         f"Expected peak=10 for 20 slow steps with cap=10, got {peak}")
        self.assertEqual(sum(1 for s in steps if s.get("success")), 20)


# ---------------------------------------------------------------------------
# Regression guards around surrounding node behaviour
# ---------------------------------------------------------------------------

class NodeBehaviourPreservedTests(unittest.IsolatedAsyncioTestCase):
    """
    The semaphore addition must not break:
      - the plan_data dict returned to the graph state,
      - the per-step `tool_output` population,
      - the counts printed to the log.
    """

    async def test_plan_data_returned_intact(self):
        from orchestrator_helpers.nodes.execute_plan_node import execute_plan_node as node_fn
        steps = [
            {"tool_name": "execute_curl", "tool_args": {"_idx": i}, "rationale": f"s{i}"}
            for i in range(3)
        ]
        state = {
            "_current_plan": {"steps": steps, "plan_rationale": "r"},
            "current_phase": "informational",
            "current_iteration": 0,
        }
        config = {"configurable": {"user_id": "u", "project_id": "p", "thread_id": "t"}}

        tool_executor = MagicMock()
        tool_executor.execute = AsyncMock(return_value={
            "success": True, "output": "yo", "error": None,
        })

        from project_settings import get_setting as real_get_setting
        def _fake_get_setting(key, default=None):
            if key == 'PLAN_MAX_PARALLEL_TOOLS':
                return 10
            return real_get_setting(key, default)
        with patch("project_settings.get_setting", side_effect=_fake_get_setting):
            out = await node_fn(
                state, config,
                tool_executor=tool_executor,
                streaming_callbacks={},
                session_manager_base="http://unused",
            )
        self.assertIn("_current_plan", out)
        self.assertIn("wave_id", out["_current_plan"])
        # Every step must have been filled in with tool_output / success
        for s in out["_current_plan"]["steps"]:
            self.assertIn("success", s)
            self.assertIn("tool_output", s)

    async def test_empty_plan_is_noop(self):
        from orchestrator_helpers.nodes.execute_plan_node import execute_plan_node as node_fn
        state = {
            "_current_plan": {"steps": [], "plan_rationale": "empty"},
            "current_phase": "informational",
            "current_iteration": 0,
        }
        config = {"configurable": {"user_id": "u", "project_id": "p", "thread_id": "t"}}
        tool_executor = MagicMock()
        from project_settings import get_setting as real_get_setting
        def _fake_get_setting(key, default=None):
            if key == 'PLAN_MAX_PARALLEL_TOOLS':
                return 10
            return real_get_setting(key, default)
        with patch("project_settings.get_setting", side_effect=_fake_get_setting):
            out = await node_fn(
                state, config,
                tool_executor=tool_executor,
                streaming_callbacks={},
                session_manager_base="http://unused",
            )
        self.assertEqual(out, {"_current_plan": None})


if __name__ == "__main__":
    unittest.main()
