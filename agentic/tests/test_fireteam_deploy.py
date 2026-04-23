"""Integration-style tests for fireteam_deploy_node with a mocked member graph.

Exercises the concurrency semaphore, wall-clock timeout, exception isolation,
and cancellation propagation paths without spinning up a real Kali sandbox
or LLM. Uses an in-memory fake graph that emits a controllable sequence of
state updates per member.

Run (inside agent container with /app bind-mounted or live code):
    docker compose exec agent python -m unittest tests.test_fireteam_deploy -v
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

_agentic_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _agentic_dir)


class _FakeMemberGraph:
    """Minimal stand-in for a compiled LangGraph StateGraph.

    Each instance emits one state update dict per astream call, optionally
    with a delay and a completion_reason to drive the result-status path.
    """

    def __init__(self, *, completion_reason="complete", delay_s: float = 0.0,
                 raise_exc: BaseException | None = None):
        self.completion_reason = completion_reason
        self.delay_s = delay_s
        self.raise_exc = raise_exc
        self.invocations = 0

    async def astream(self, member_state, config=None):
        self.invocations += 1
        if self.delay_s > 0:
            await asyncio.sleep(self.delay_s)
        if self.raise_exc is not None:
            raise self.raise_exc
        # One yield that fills out the terminal state; deploy node's loop
        # collects via final_state.update(...).
        yield {
            "fireteam_complete": {
                "task_complete": True,
                "completion_reason": self.completion_reason,
                "current_iteration": 3,
                "tokens_used": 500,
                "execution_trace": [],
                "target_info": {},
                "chain_findings_memory": [],
            }
        }


def _make_parent_state(n_members: int = 3, phase: str = "informational") -> dict:
    return {
        "user_id": "u",
        "project_id": "p",
        "session_id": "s-1",
        "current_phase": phase,
        "attack_path_type": "cve_exploit",
        "target_info": {},
        "current_iteration": 5,
        "_current_fireteam_plan": {
            "plan_rationale": "test plan",
            "members": [
                {"name": f"M{i}", "task": f"do task {i}", "skills": [], "max_iterations": 10}
                for i in range(n_members)
            ],
        },
    }


class DeployNodeExceptionIsolationTests(unittest.IsolatedAsyncioTestCase):
    async def test_one_member_crash_does_not_kill_wave(self):
        """If one member raises mid-astream, others still return normally."""
        from orchestrator_helpers.nodes.fireteam_deploy_node import fireteam_deploy_node

        # Patch the persist helpers so they don't try HTTP calls.
        with patch(
            "orchestrator_helpers.nodes.fireteam_deploy_node._persist_deploy", new=AsyncMock(return_value="id")
        ), patch(
            "orchestrator_helpers.nodes.fireteam_deploy_node._patch_member", new=AsyncMock()
        ), patch(
            "orchestrator_helpers.nodes.fireteam_deploy_node._patch_fireteam", new=AsyncMock()
        ):
            # Three members: one raises, two succeed.
            graphs = [
                _FakeMemberGraph(completion_reason="complete"),
                _FakeMemberGraph(raise_exc=RuntimeError("crash")),
                _FakeMemberGraph(completion_reason="complete"),
            ]
            graph_iter = iter(graphs)

            class _MultiGraph:
                def astream(self, s, config=None):
                    return next(graph_iter).astream(s, config)

            state = _make_parent_state(n_members=3)
            result = await fireteam_deploy_node(
                state, None,
                member_graph=_MultiGraph(),
                streaming_callbacks={},
                neo4j_creds=None,
            )
            results = result["_current_fireteam_results"]
            self.assertEqual(len(results), 3)
            statuses = [r["status"] for r in results]
            # Exactly one error, two success
            self.assertEqual(statuses.count("error"), 1)
            self.assertEqual(statuses.count("success"), 2)


class DeployNodeTimeoutTests(unittest.IsolatedAsyncioTestCase):
    async def test_wave_timeout_cancels_outstanding_members(self):
        """When FIRETEAM_TIMEOUT_SEC fires, in-flight members get marked timeout."""
        from orchestrator_helpers.nodes.fireteam_deploy_node import fireteam_deploy_node

        with patch(
            "orchestrator_helpers.nodes.fireteam_deploy_node._persist_deploy", new=AsyncMock(return_value="id")
        ), patch(
            "orchestrator_helpers.nodes.fireteam_deploy_node._patch_member", new=AsyncMock()
        ), patch(
            "orchestrator_helpers.nodes.fireteam_deploy_node._patch_fireteam", new=AsyncMock()
        ), patch(
            "orchestrator_helpers.nodes.fireteam_deploy_node.get_setting",
            side_effect=lambda k, d=None: {
                "FIRETEAM_MAX_CONCURRENT": 3,
                "FIRETEAM_MAX_MEMBERS": 8,
                "FIRETEAM_TIMEOUT_SEC": 1,  # 1 second — fast trigger
                "FIRETEAM_MEMBER_MAX_ITERATIONS": 10,
            }.get(k, d),
        ):
            # Two members that sleep longer than the timeout.
            class _SlowGraph:
                def astream(self, s, config=None):
                    return _FakeMemberGraph(delay_s=5.0).astream(s, config)

            state = _make_parent_state(n_members=2)
            t0 = time.monotonic()
            result = await fireteam_deploy_node(
                state, None,
                member_graph=_SlowGraph(),
                streaming_callbacks={},
                neo4j_creds=None,
            )
            elapsed = time.monotonic() - t0
            self.assertLess(elapsed, 3.0, "timeout did not trigger")
            statuses = [r["status"] for r in result["_current_fireteam_results"]]
            self.assertTrue(all(s == "timeout" for s in statuses), f"got {statuses}")


class DeployNodeConcurrencyTests(unittest.IsolatedAsyncioTestCase):
    async def test_semaphore_caps_concurrent_members(self):
        """With FIRETEAM_MAX_CONCURRENT=2 and 5 members, at most 2 members
        run astream simultaneously."""
        from orchestrator_helpers.nodes.fireteam_deploy_node import fireteam_deploy_node

        in_flight = 0
        max_observed = 0
        lock = asyncio.Lock()

        class _CountingGraph:
            async def _run(self, s, config=None):
                nonlocal in_flight, max_observed
                async with lock:
                    in_flight += 1
                    max_observed = max(max_observed, in_flight)
                try:
                    await asyncio.sleep(0.2)
                    yield {
                        "fireteam_complete": {
                            "task_complete": True, "completion_reason": "complete",
                            "current_iteration": 1, "tokens_used": 10,
                            "execution_trace": [], "target_info": {},
                            "chain_findings_memory": [],
                        }
                    }
                finally:
                    async with lock:
                        in_flight -= 1

            def astream(self, s, config=None):
                return self._run(s, config)

        with patch(
            "orchestrator_helpers.nodes.fireteam_deploy_node._persist_deploy", new=AsyncMock(return_value="id")
        ), patch(
            "orchestrator_helpers.nodes.fireteam_deploy_node._patch_member", new=AsyncMock()
        ), patch(
            "orchestrator_helpers.nodes.fireteam_deploy_node._patch_fireteam", new=AsyncMock()
        ), patch(
            "orchestrator_helpers.nodes.fireteam_deploy_node.get_setting",
            side_effect=lambda k, d=None: {
                "FIRETEAM_MAX_CONCURRENT": 2,
                "FIRETEAM_MAX_MEMBERS": 8,
                "FIRETEAM_TIMEOUT_SEC": 30,
            }.get(k, d),
        ):
            state = _make_parent_state(n_members=5)
            await fireteam_deploy_node(
                state, None,
                member_graph=_CountingGraph(),
                streaming_callbacks={},
                neo4j_creds=None,
            )
            self.assertLessEqual(max_observed, 2, f"semaphore breached: {max_observed}")
            self.assertGreater(max_observed, 0)


class DeployNodeMutexRejectionTests(unittest.IsolatedAsyncioTestCase):
    async def test_two_metasploit_members_reject_plan(self):
        """Plan with two metasploit-claiming members must be rejected before
        any member runs."""
        from orchestrator_helpers.nodes.fireteam_deploy_node import fireteam_deploy_node

        with patch(
            "orchestrator_helpers.nodes.fireteam_deploy_node._persist_deploy", new=AsyncMock(return_value="id")
        ), patch(
            "orchestrator_helpers.nodes.fireteam_deploy_node._patch_member", new=AsyncMock()
        ), patch(
            "orchestrator_helpers.nodes.fireteam_deploy_node._patch_fireteam", new=AsyncMock()
        ):
            state = _make_parent_state(n_members=0)
            state["_current_fireteam_plan"] = {
                "plan_rationale": "test",
                "members": [
                    {"name": "M1", "task": "x", "skills": ["metasploit"], "max_iterations": 10},
                    {"name": "M2", "task": "y", "skills": ["metasploit"], "max_iterations": 10},
                ],
            }
            graph = MagicMock()
            graph.astream.side_effect = AssertionError("should not be called")
            result = await fireteam_deploy_node(
                state, None,
                member_graph=graph,
                streaming_callbacks={},
                neo4j_creds=None,
            )
            self.assertEqual(result["_current_fireteam_results"], [])
            self.assertIsNone(result["_current_fireteam_plan"])


if __name__ == "__main__":
    unittest.main()
