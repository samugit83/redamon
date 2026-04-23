"""Regression test: execute_plan_node must reject plans that stack singleton
tools (e.g. two metasploit_console steps in one parallel wave).

Pre-fix gap: the fireteam deploy node enforced TOOL_MUTEX_GROUPS, but
execute_plan_node fanned steps out with asyncio.gather unconditionally. An
LLM plan with two metasploit_console steps would run both against the single
persistent msfconsole, interleaving stdin/stdout and racing session tracking.

Run:
    docker run --rm -v "/home/samuele/Progetti didattici/redamon/agentic:/app" \
        -w /app redamon-agent python -m unittest tests.test_plan_mutex -v
"""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock

_agentic_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _agentic_dir)


class PlanMutexValidatorTests(unittest.TestCase):
    def setUp(self):
        from orchestrator_helpers.nodes.execute_plan_node import _validate_plan_mutex_groups
        self._validate = _validate_plan_mutex_groups

    def test_disjoint_tools_pass(self):
        steps = [
            {"tool_name": "execute_ffuf"},
            {"tool_name": "execute_curl"},
            {"tool_name": "execute_playwright"},
        ]
        self.assertIsNone(self._validate(steps))

    def test_two_playwright_steps_pass_after_browser_mutex_removal(self):
        # Regression pin for the earlier browser-mutex removal: plan_tools must
        # also allow concurrent playwright steps now that the server is not a
        # singleton.
        steps = [
            {"tool_name": "execute_playwright", "tool_args": {"url": "https://a"}},
            {"tool_name": "execute_playwright", "tool_args": {"url": "https://b"}},
        ]
        self.assertIsNone(self._validate(steps))

    def test_two_metasploit_steps_rejected(self):
        steps = [
            {"tool_name": "metasploit_console", "tool_args": {"command": "sessions -l"}},
            {"tool_name": "metasploit_console", "tool_args": {"command": "jobs"}},
        ]
        err = self._validate(steps)
        self.assertIsNotNone(err)
        self.assertIn("metasploit", err)
        self.assertIn("metasploit_console", err)

    def test_metasploit_plus_msf_restart_rejected(self):
        # Both tools share the 'metasploit' mutex group.
        steps = [
            {"tool_name": "metasploit_console", "tool_args": {"command": "sessions -l"}},
            {"tool_name": "msf_restart", "tool_args": {}},
        ]
        err = self._validate(steps)
        self.assertIsNotNone(err)
        self.assertIn("metasploit", err)


class PlanNodeMutexRejectionTests(unittest.IsolatedAsyncioTestCase):
    async def test_plan_with_two_metasploit_steps_is_rejected_and_marks_all_steps_failed(self):
        """End-to-end: execute_plan_node must short-circuit before gather when
        the plan stacks singleton tools, mark every step as failed with a
        rejection message, and emit plan_complete with failed=total so the UI
        renders a proper rejection card."""
        import importlib
        mod = importlib.import_module("orchestrator_helpers.nodes.execute_plan_node")

        # tool_executor must never be reached on the reject path.
        tool_executor = AsyncMock(side_effect=AssertionError("tool_executor must not run on mutex reject"))
        streaming_cb = MagicMock()
        streaming_cb.on_plan_start = AsyncMock()
        streaming_cb.on_plan_complete = AsyncMock()

        import orchestrator_helpers.member_streaming as ms_mod
        original_resolve = ms_mod.resolve_streaming_callback
        ms_mod.resolve_streaming_callback = lambda cbs, sid: streaming_cb

        try:
            state = {
                "user_id": "u", "project_id": "p", "session_id": "s",
                "current_phase": "exploitation",
                "current_iteration": 1,
                "_current_plan": {
                    "steps": [
                        {"tool_name": "metasploit_console", "tool_args": {"command": "sessions -l"}},
                        {"tool_name": "metasploit_console", "tool_args": {"command": "jobs"}},
                    ],
                    "plan_rationale": "two msf ops",
                },
            }
            update = await mod.execute_plan_node(
                state, None,
                tool_executor=tool_executor,
                streaming_callbacks={},
                session_manager_base=None,
            )
        finally:
            ms_mod.resolve_streaming_callback = original_resolve

        # gather never ran — tool_executor stays untouched.
        self.assertFalse(tool_executor.called)

        # Every step carries the rejection reason.
        steps = update["_current_plan"]["steps"]
        self.assertEqual(len(steps), 2)
        for step in steps:
            self.assertFalse(step["success"])
            self.assertIn("Plan rejected", step["tool_output"])
            self.assertIn("metasploit", step["error_message"])

        # plan_complete fires with failed=all so the UI closes the card.
        streaming_cb.on_plan_start.assert_awaited_once()
        streaming_cb.on_plan_complete.assert_awaited_once()
        kw = streaming_cb.on_plan_complete.await_args.kwargs
        self.assertEqual(kw["total"], 2)
        self.assertEqual(kw["failed"], 2)
        self.assertEqual(kw["successful"], 0)


if __name__ == "__main__":
    unittest.main()
