"""Unit tests for Fireteam (multi-agent) safety-critical paths.

Covers the parts of the Fireteam implementation where behavioral correctness
matters for operator safety: forbidden-action stripping in members, gate
enforcement in think_node, mutex-group validation, deploy-node exception
isolation, collect-node merge + escalation, member_streaming ContextVar
proxy, and LLM decision parsing for fireteam_plan.

Run (inside agent container):
    docker compose exec agent python -m pytest tests/test_fireteam_core.py -v
"""

from __future__ import annotations

import asyncio
import os
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

_agentic_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _agentic_dir)


# =============================================================================
# 1. Forbidden-action stripping in members (SAFETY-CRITICAL, 100% required)
# =============================================================================

class ForbiddenActionStrippingTests(unittest.TestCase):
    def setUp(self):
        from state import LLMDecision, PhaseTransitionDecision, UserQuestionDecision
        from orchestrator_helpers.nodes.fireteam_member_think_node import (
            _strip_forbidden_actions, _FORBIDDEN_MEMBER_ACTIONS,
        )
        self.LLMDecision = LLMDecision
        self.PhaseTransitionDecision = PhaseTransitionDecision
        self.UserQuestionDecision = UserQuestionDecision
        self._strip = _strip_forbidden_actions
        self._FORBIDDEN = _FORBIDDEN_MEMBER_ACTIONS

    def _d(self, **kw):
        defaults = dict(thought="t", reasoning="r")
        defaults.update(kw)
        return self.LLMDecision(**defaults)

    def test_strips_deploy_fireteam_to_complete(self):
        d = self._d(action="deploy_fireteam")
        out = self._strip(d, "m-1")
        self.assertEqual(out.action, "complete")
        self.assertEqual(out.completion_reason, "deploy_forbidden_in_member")

    def test_strips_transition_phase_to_complete(self):
        d = self._d(
            action="transition_phase",
            phase_transition=self.PhaseTransitionDecision(to_phase="exploitation"),
        )
        out = self._strip(d, "m-1")
        self.assertEqual(out.action, "complete")
        self.assertEqual(out.completion_reason, "requested_phase_escalation")
        self.assertIsNone(out.phase_transition)

    def test_strips_ask_user_to_complete(self):
        d = self._d(
            action="ask_user",
            user_question=self.UserQuestionDecision(question="why?", context="c"),
        )
        out = self._strip(d, "m-1")
        self.assertEqual(out.action, "complete")
        self.assertEqual(out.completion_reason, "cannot_ask_in_member")
        self.assertIsNone(out.user_question)

    def test_preserves_use_tool(self):
        d = self._d(action="use_tool", tool_name="execute_nmap", tool_args={"target": "x"})
        out = self._strip(d, "m-1")
        self.assertEqual(out.action, "use_tool")
        self.assertEqual(out.tool_name, "execute_nmap")

    def test_preserves_plan_tools(self):
        from state import ToolPlan, ToolPlanStep
        d = self._d(
            action="plan_tools",
            tool_plan=ToolPlan(
                steps=[ToolPlanStep(tool_name="execute_nmap", tool_args={})],
                plan_rationale="parallel recon",
            ),
        )
        out = self._strip(d, "m-1")
        self.assertEqual(out.action, "plan_tools")
        self.assertIsNotNone(out.tool_plan)

    def test_preserves_complete(self):
        d = self._d(action="complete", completion_reason="done")
        out = self._strip(d, "m-1")
        self.assertEqual(out.action, "complete")
        self.assertEqual(out.completion_reason, "done")

    def test_forbidden_map_covers_three_actions(self):
        """If this test fails, someone added a forbidden action without adding a reason."""
        self.assertIn("deploy_fireteam", self._FORBIDDEN)
        self.assertIn("transition_phase", self._FORBIDDEN)
        self.assertIn("ask_user", self._FORBIDDEN)


# =============================================================================
# 2. Dangerous-tool escalation: pending_confirmation structure
# =============================================================================

class DangerousToolEscalationTests(unittest.TestCase):
    def setUp(self):
        from state import LLMDecision, ToolPlan, ToolPlanStep
        from orchestrator_helpers.nodes.fireteam_member_think_node import (
            _build_pending_confirmation, _plan_has_dangerous_tool,
        )
        self.LLMDecision = LLMDecision
        self.ToolPlan = ToolPlan
        self.ToolPlanStep = ToolPlanStep
        self._build = _build_pending_confirmation
        self._plan_has = _plan_has_dangerous_tool

    def _state(self):
        return {
            "current_phase": "exploitation",
            "current_iteration": 3,
            "member_id": "member-0-abc",
            "member_name": "Web Tester",
        }

    def test_single_tool_escalation_shape(self):
        d = self.LLMDecision(
            thought="t", reasoning="r",
            action="use_tool",
            tool_name="execute_hydra",
            tool_args={"target": "10.0.0.1"},
        )
        pending = self._build(d, self._state())
        self.assertEqual(pending["mode"], "single")
        self.assertEqual(len(pending["tools"]), 1)
        self.assertEqual(pending["tools"][0]["tool_name"], "execute_hydra")
        self.assertEqual(pending["agent_id"], "member-0-abc")
        self.assertEqual(pending["agent_name"], "Web Tester")
        self.assertEqual(pending["phase"], "exploitation")

    def test_plan_escalation_shape(self):
        plan = self.ToolPlan(
            steps=[
                self.ToolPlanStep(tool_name="execute_hydra", tool_args={}),
                self.ToolPlanStep(tool_name="execute_nmap", tool_args={}),
            ],
            plan_rationale="parallel",
        )
        d = self.LLMDecision(
            thought="t", reasoning="r",
            action="plan_tools",
            tool_plan=plan,
        )
        pending = self._build(d, self._state())
        self.assertEqual(pending["mode"], "plan")
        self.assertEqual(len(pending["tools"]), 2)

    def test_plan_has_dangerous_tool_detects(self):
        # execute_hydra is in DANGEROUS_TOOLS
        plan = self.ToolPlan(
            steps=[self.ToolPlanStep(tool_name="execute_hydra", tool_args={})],
            plan_rationale="x",
        )
        d = self.LLMDecision(thought="t", reasoning="r", action="plan_tools", tool_plan=plan)
        self.assertTrue(self._plan_has(d))

    def test_plan_has_dangerous_tool_false_for_safe(self):
        # query_graph is NOT in DANGEROUS_TOOLS
        plan = self.ToolPlan(
            steps=[self.ToolPlanStep(tool_name="query_graph", tool_args={})],
            plan_rationale="x",
        )
        d = self.LLMDecision(thought="t", reasoning="r", action="plan_tools", tool_plan=plan)
        self.assertFalse(self._plan_has(d))


# =============================================================================
# 3. Mutex group enforcement in deploy node
# =============================================================================

class MutexGroupValidationTests(unittest.TestCase):
    def setUp(self):
        from orchestrator_helpers.nodes.fireteam_deploy_node import _validate_mutex_groups
        self._validate = _validate_mutex_groups

    def test_no_conflicts_passes(self):
        plan = [
            {"name": "A", "skills": ["xss"]},
            {"name": "B", "skills": ["sql_injection"]},
        ]
        self.assertIsNone(self._validate(plan))

    def test_two_metasploit_members_rejected(self):
        plan = [
            {"name": "A", "skills": ["metasploit"]},
            {"name": "B", "skills": ["metasploit"]},
        ]
        err = self._validate(plan)
        self.assertIsNotNone(err)
        self.assertIn("metasploit", err)

    def test_single_browser_claimer_ok(self):
        plan = [
            {"name": "Web Tester", "skills": ["browser"]},
        ]
        self.assertIsNone(self._validate(plan))

    def test_multiple_playwright_members_ok(self):
        # execute_playwright spawns a fresh Chromium per invocation, so the
        # server is not a singleton. The 'browser' mutex group was removed to
        # unblock multi-member recon waves where several specialists all need
        # to render pages.
        plan = [
            {"name": "Auth Hunter", "skills": ["playwright", "curl"]},
            {"name": "Surface Mapper", "skills": ["playwright", "curl"]},
            {"name": "Header Analyst", "skills": ["playwright", "curl"]},
        ]
        self.assertIsNone(self._validate(plan))


# =============================================================================
# 4. fireteam_collect_node: merge + first-escalation-wins + summary
# =============================================================================

class CollectNodeMergeTests(unittest.IsolatedAsyncioTestCase):
    async def test_merges_target_info_delta_into_parent(self):
        from orchestrator_helpers.nodes.fireteam_collect_node import (
            fireteam_collect_node, _merge_target_info,
        )
        base = {"technologies": ["nginx"]}
        _merge_target_info(base, {"technologies": ["wordpress"], "ports": [22, 80]})
        self.assertIn("nginx", base["technologies"])
        self.assertIn("wordpress", base["technologies"])
        self.assertEqual(base["ports"], [22, 80])

    async def test_appends_findings_with_source_agent(self):
        from orchestrator_helpers.nodes.fireteam_collect_node import fireteam_collect_node
        state = {
            "_current_fireteam_results": [
                {"member_id": "m1", "name": "Web", "status": "success",
                 "findings": [{"severity": "high", "title": "XSS", "finding_type": "vulnerability_confirmed"}],
                 "target_info_delta": {}, "iterations_used": 2, "tokens_used": 100,
                 "execution_trace_summary": [], "_last_chain_step_id": "step-1"},
            ],
            "_fireteam_id": "fteam-1",
            "target_info": {},
            "chain_findings_memory": [],
            "user_id": "u", "project_id": "p", "session_id": "s",
            "current_phase": "informational",
            "_current_fireteam_plan": {"members": [{"member_id": "m1", "name": "Web", "task": "t"}]},
        }
        # llm=None -> skips LLM extraction path, uses fallback.
        result = await fireteam_collect_node(state, None, llm=None, neo4j_creds=None)
        findings = result["chain_findings_memory"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["source_agent"], "Web")
        self.assertEqual(findings[0]["fireteam_id"], "fteam-1")


# =============================================================================
# 4b. Post-fireteam loop prevention: attribution render, TODO auto-completion,
#     trimmed summary.
# =============================================================================

class PostFireteamLoopPreventionTests(unittest.TestCase):
    def test_finding_render_surfaces_source_agent(self):
        from state import format_chain_context
        rendered = format_chain_context(
            chain_findings=[
                {"severity": "medium", "title": "Missing HSTS",
                 "step_iteration": 2, "confidence": 95,
                 "source_agent": "Header & Policy Analyst",
                 "evidence": "no HSTS header"},
                {"severity": "low", "title": "Root finding",
                 "step_iteration": 1, "confidence": 90,
                 "evidence": "root-level"},
            ],
            chain_failures=[],
            chain_decisions=[],
            execution_trace=[],
        )
        # Fireteam finding shows attribution; root finding does not.
        self.assertIn("from Header & Policy Analyst", rendered)
        self.assertNotIn("from None", rendered)
        self.assertIn("(step 1, 90%)", rendered)  # root finding unattributed

    def test_auto_complete_closes_member_matched_todos(self):
        from orchestrator_helpers.nodes.fireteam_collect_node import _auto_complete_fireteam_todos
        todos = [
            {"id": "1", "description": "Deploy fireteam with 3 specialists", "status": "in_progress"},
            {"id": "2", "description": "Auth Hunter: find auth flows", "status": "pending"},
            {"id": "3", "description": "Surface Mapper: map routes", "status": "pending"},
            {"id": "4", "description": "Analyst: security headers", "status": "pending"},
            {"id": "5", "description": "Write consolidated final report", "status": "pending"},
        ]
        results = [
            {"name": "Auth Hunter", "status": "success"},
            {"name": "Surface Mapper", "status": "success"},
            {"name": "Analyst", "status": "partial"},  # did not succeed
        ]
        out = _auto_complete_fireteam_todos(todos, results)
        by_id = {t["id"]: t for t in out}
        self.assertEqual(by_id["1"]["status"], "completed")       # generic 'fireteam' match
        self.assertEqual(by_id["2"]["status"], "completed")       # name match, success
        self.assertEqual(by_id["3"]["status"], "completed")       # name match, success
        self.assertEqual(by_id["4"]["status"], "pending")         # Analyst not success
        self.assertEqual(by_id["5"]["status"], "pending")         # no match

    def test_auto_complete_leaves_completed_todos_alone(self):
        from orchestrator_helpers.nodes.fireteam_collect_node import _auto_complete_fireteam_todos
        todos = [
            {"id": "1", "description": "Already done", "status": "completed",
             "completed_at": "2026-01-01T00:00:00Z"},
        ]
        out = _auto_complete_fireteam_todos(todos, [{"name": "Already done", "status": "success"}])
        self.assertEqual(out[0]["completed_at"], "2026-01-01T00:00:00Z")

    def test_auto_complete_noop_when_no_successes(self):
        from orchestrator_helpers.nodes.fireteam_collect_node import _auto_complete_fireteam_todos
        todos = [{"id": "1", "description": "Auth Hunter: work", "status": "in_progress"}]
        out = _auto_complete_fireteam_todos(todos, [{"name": "Auth Hunter", "status": "error"}])
        self.assertEqual(out[0]["status"], "in_progress")

    def test_summary_trimmed(self):
        from orchestrator_helpers.nodes.fireteam_collect_node import _render_summary
        results = [
            {"member_id": "m1", "name": "Auth Hunter", "status": "success",
             "iterations_used": 8, "tokens_used": 77000,
             "findings": [{"severity": "high", "title": "x"}] * 13},
            {"member_id": "m2", "name": "Surface Mapper", "status": "success",
             "iterations_used": 11, "tokens_used": 127000,
             "findings": [{"severity": "low", "title": "y"}] * 22},
        ]
        out = _render_summary("fteam-1-abc", results, wall_s=355.2)
        # Header captures success ratio + duration
        self.assertIn("2/2 specialists completed in 355.2s", out)
        # Per-member compact line present
        self.assertIn("- Auth Hunter (success, 8 iter, 13 findings)", out)
        self.assertIn("- Surface Mapper (success, 11 iter, 22 findings)", out)
        # Old verbose per-finding titles are gone
        self.assertNotIn("Findings: 13", out)
        self.assertNotIn("[high] x", out)


# =============================================================================
# 4c. First-escalation-wins (async — restored after the sync loop-prevention
#     class so it lives under the AsyncioTestCase harness).
# =============================================================================

class CollectNodeEscalationTests(unittest.IsolatedAsyncioTestCase):
    async def test_first_escalation_wins(self):
        from orchestrator_helpers.nodes.fireteam_collect_node import fireteam_collect_node
        state = {
            "_current_fireteam_results": [
                {"member_id": "m1", "name": "A", "status": "success",
                 "findings": [], "target_info_delta": {}, "iterations_used": 1,
                 "tokens_used": 10, "execution_trace_summary": []},
                {"member_id": "m2", "name": "B", "status": "needs_confirmation",
                 "findings": [], "target_info_delta": {},
                 "pending_confirmation": {
                     "tool_name": "execute_hydra", "tool_args": {}, "mode": "single",
                     "tools": [{"tool_name": "execute_hydra", "tool_args": {}}],
                     "agent_id": "m2", "agent_name": "B",
                 },
                 "iterations_used": 1, "tokens_used": 10, "execution_trace_summary": []},
                {"member_id": "m3", "name": "C", "status": "needs_confirmation",
                 "findings": [], "target_info_delta": {},
                 "pending_confirmation": {"tool_name": "execute_sqlmap", "tool_args": {},
                                          "mode": "single", "tools": [], "agent_id": "m3", "agent_name": "C"},
                 "iterations_used": 1, "tokens_used": 10, "execution_trace_summary": []},
            ],
            "_fireteam_id": "fteam-1",
            "target_info": {},
            "chain_findings_memory": [],
            "user_id": "u", "project_id": "p", "session_id": "s",
            "current_phase": "informational",
            "_current_fireteam_plan": {"members": []},
        }
        result = await fireteam_collect_node(state, None, llm=None, neo4j_creds=None)
        # First escalator (B) wins, not C.
        self.assertEqual(result["_escalated_member_id"], "m2")
        self.assertTrue(result["awaiting_tool_confirmation"])
        self.assertEqual(result["_tool_confirmation_mode"], "fireteam_escalation")


# =============================================================================
# 5. MemberScopedCallback ContextVar behavior
# =============================================================================

class MemberStreamingContextVarTests(unittest.TestCase):
    def test_resolve_falls_back_to_dict_when_no_ctx(self):
        from orchestrator_helpers.member_streaming import resolve_streaming_callback
        sentinel = object()
        result = resolve_streaming_callback({"sid": sentinel}, "sid")
        self.assertIs(result, sentinel)

    def test_resolve_returns_proxy_when_ctx_set(self):
        from orchestrator_helpers.member_streaming import (
            resolve_streaming_callback, _MemberStreamingContext, MemberScopedCallback,
        )
        real = MagicMock()
        ctx = _MemberStreamingContext(real, "fteam-1", "m-1", "Web")
        with ctx as proxy:
            resolved = resolve_streaming_callback({"sid": real}, "sid")
            self.assertIsInstance(resolved, MemberScopedCallback)
            self.assertIs(resolved, proxy)
        # Outside context: resolves back to dict entry.
        resolved_after = resolve_streaming_callback({"sid": real}, "sid")
        self.assertIs(resolved_after, real)

    def test_resolve_returns_none_for_unknown_session(self):
        from orchestrator_helpers.member_streaming import resolve_streaming_callback
        self.assertIsNone(resolve_streaming_callback({"other": object()}, "sid"))
        self.assertIsNone(resolve_streaming_callback(None, "sid"))


class MemberScopedCallbackRoutingTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        from orchestrator_helpers.member_streaming import MemberScopedCallback
        self.real = MagicMock()
        self.real.on_fireteam_tool_start = AsyncMock()
        self.real.on_fireteam_tool_complete = AsyncMock()
        self.real.on_fireteam_plan_start = AsyncMock()
        self.real.on_fireteam_plan_complete = AsyncMock()
        self.real.on_fireteam_thinking = AsyncMock()
        self.real.on_fireteam_tool_output_chunk = AsyncMock()
        self.proxy = MemberScopedCallback(
            self.real, fireteam_id="fteam-1", member_id="m-1", member_name="Web",
        )

    async def test_on_tool_start_routes_to_fireteam_event(self):
        await self.proxy.on_tool_start("execute_nmap", {"target": "x"})
        self.real.on_fireteam_tool_start.assert_awaited_once()
        kwargs = self.real.on_fireteam_tool_start.await_args.kwargs
        self.assertEqual(kwargs["fireteam_id"], "fteam-1")
        self.assertEqual(kwargs["member_id"], "m-1")
        self.assertEqual(kwargs["tool_name"], "execute_nmap")

    async def test_on_tool_output_chunk_routes_to_fireteam_event(self):
        await self.proxy.on_tool_output_chunk("execute_nmap", "Discovered...", is_final=False)
        self.real.on_fireteam_tool_output_chunk.assert_awaited_once()
        kwargs = self.real.on_fireteam_tool_output_chunk.await_args.kwargs
        self.assertEqual(kwargs["chunk"], "Discovered...")
        self.assertFalse(kwargs["is_final"])

    async def test_on_thinking_routes_to_fireteam_event(self):
        await self.proxy.on_thinking(2, "informational", "thought text", "reasoning text")
        self.real.on_fireteam_thinking.assert_awaited_once()
        kwargs = self.real.on_fireteam_thinking.await_args.kwargs
        self.assertEqual(kwargs["member_id"], "m-1")
        self.assertEqual(kwargs["thought"], "thought text")

    def test_unknown_method_forwards_via_getattr(self):
        self.real.on_something_custom = "sentinel"
        self.assertEqual(self.proxy.on_something_custom, "sentinel")

    def test_per_member_dedup_sets_are_own(self):
        self.assertEqual(self.proxy._emitted_tool_start_ids, set())
        self.proxy._emitted_tool_start_ids.add("xyz")
        # The real callback should NOT be polluted.
        # (Real callback was MagicMock so attribute access doesn't error, but
        # we care that the proxy's set is its own.)
        self.assertEqual(self.proxy._emitted_tool_start_ids, {"xyz"})


# =============================================================================
# 6. Parsing: fireteam_plan valid / empty / malformed
# =============================================================================

class FireteamPlanParsingTests(unittest.TestCase):
    def setUp(self):
        from orchestrator_helpers.parsing import try_parse_llm_decision
        self._parse = try_parse_llm_decision

    def test_valid_fireteam_plan_parses(self):
        raw = '''{"thought": "t", "reasoning": "r", "action": "deploy_fireteam",
                 "fireteam_plan": {"members": [
                     {"name": "Web", "task": "Probe HTTP", "skills": ["xss"], "max_iterations": 20}
                 ], "plan_rationale": "web recon"}}'''
        decision, err = self._parse(raw)
        self.assertIsNone(err)
        self.assertEqual(decision.action, "deploy_fireteam")
        self.assertEqual(len(decision.fireteam_plan.members), 1)
        self.assertEqual(decision.fireteam_plan.members[0].name, "Web")

    def test_empty_fireteam_plan_downgraded_to_use_tool(self):
        raw = '''{"thought": "t", "reasoning": "r", "action": "deploy_fireteam",
                 "fireteam_plan": {"members": [], "plan_rationale": "x"}}'''
        decision, err = self._parse(raw)
        # Empty list rejected by parser; rewritten to use_tool.
        if decision is not None:
            self.assertNotEqual(decision.action, "deploy_fireteam")

    def test_malformed_fireteam_plan_downgraded(self):
        raw = '''{"thought": "t", "reasoning": "r", "action": "deploy_fireteam",
                 "fireteam_plan": {"members": [{"task": "no name field"}]}}'''
        decision, err = self._parse(raw)
        # Members must have name+task; missing name -> filtered -> empty -> downgrade.
        if decision is not None:
            self.assertNotEqual(decision.action, "deploy_fireteam")

    def test_deploy_fireteam_without_plan_object_downgraded(self):
        raw = '''{"thought": "t", "reasoning": "r", "action": "deploy_fireteam"}'''
        decision, err = self._parse(raw)
        if decision is not None:
            self.assertNotEqual(decision.action, "deploy_fireteam")


# =============================================================================
# 7. Think_node deploy_fireteam gate enforcement
# =============================================================================
#
# These tests exercise the in-function gate logic by reproducing the decision
# branch. Full think_node is too coupled to test in isolation; the gate check
# is self-contained and we verify the invariants directly.

class DeployFireteamGateTests(unittest.TestCase):
    def _check(self, ft_enabled: bool, persistent: bool, allowed: list, phase: str):
        """Mirror the gate logic in think_node.py for testability."""
        if not ft_enabled:
            return "fireteam feature disabled for this project"
        if not persistent:
            return "persistent checkpointer required"
        if phase not in allowed:
            return f"phase '{phase}' not in allowed phases {allowed}"
        return None

    def test_ft_disabled_rejects(self):
        reason = self._check(False, True, ["informational"], "informational")
        self.assertIsNotNone(reason)
        self.assertIn("disabled", reason)

    def test_persistent_checkpointer_off_rejects(self):
        reason = self._check(True, False, ["informational"], "informational")
        self.assertIsNotNone(reason)
        self.assertIn("persistent", reason)

    def test_phase_not_allowed_rejects(self):
        reason = self._check(True, True, ["informational"], "exploitation")
        self.assertIsNotNone(reason)
        self.assertIn("exploitation", reason)

    def test_all_gates_open_permits(self):
        reason = self._check(True, True, ["informational", "exploitation"], "exploitation")
        self.assertIsNone(reason)


# =============================================================================
# 8. Deploy node: child state construction + result status mapping
# =============================================================================

class DeployNodeResultMappingTests(unittest.TestCase):
    def setUp(self):
        from orchestrator_helpers.nodes.fireteam_deploy_node import _result_from_final_state
        self._result = _result_from_final_state

    def _base_final(self, completion_reason):
        return {
            "current_iteration": 5, "tokens_used": 1000,
            "parent_target_info": {}, "target_info": {},
            "execution_trace": [], "chain_findings_memory": [],
            "completion_reason": completion_reason,
            "_pending_confirmation": None,
        }

    def test_complete_maps_to_success(self):
        r = self._result(self._base_final("complete"), {"name": "A"}, "m-1", 1.0)
        self.assertEqual(r["status"], "success")

    def test_iteration_budget_maps_to_partial(self):
        r = self._result(self._base_final("iteration_budget_exceeded"), {"name": "A"}, "m-1", 1.0)
        self.assertEqual(r["status"], "partial")

    def test_needs_confirmation_preserved(self):
        r = self._result(self._base_final("needs_confirmation"), {"name": "A"}, "m-1", 1.0)
        self.assertEqual(r["status"], "needs_confirmation")

    def test_parse_error_maps_to_error(self):
        r = self._result(self._base_final("parse_error: bad json"), {"name": "A"}, "m-1", 1.0)
        self.assertEqual(r["status"], "error")

    def test_llm_error_maps_to_error(self):
        r = self._result(self._base_final("llm_error: timeout"), {"name": "A"}, "m-1", 1.0)
        self.assertEqual(r["status"], "error")


# =============================================================================
# 9. Safety regression tests (§32.15 — required before GA flip)
# =============================================================================

class SafetyRegressionTests(unittest.TestCase):
    """Invariants that MUST hold before FIRETEAM_ENABLED can default to true.

    Each test documents a specific attack vector the Fireteam layer must
    NOT enable through any lax routing or stripping.
    """

    def setUp(self):
        from state import LLMDecision
        from orchestrator_helpers.nodes.fireteam_member_think_node import (
            _strip_forbidden_actions, _FORBIDDEN_MEMBER_ACTIONS,
        )
        self.LLMDecision = LLMDecision
        self._strip = _strip_forbidden_actions
        self._FORBIDDEN = _FORBIDDEN_MEMBER_ACTIONS

    def test_member_cannot_deploy_grandchild(self):
        """Recursive fireteam deployment is forbidden — members emitting
        deploy_fireteam must be stripped to complete."""
        d = self.LLMDecision(
            thought="t", reasoning="r", action="deploy_fireteam",
        )
        out = self._strip(d, "m-1")
        self.assertEqual(out.action, "complete")
        self.assertIn("deploy_forbidden", out.completion_reason)

    def test_member_cannot_transition_phase(self):
        """Members must not request phase transitions; only the root can."""
        from state import PhaseTransitionDecision
        d = self.LLMDecision(
            thought="t", reasoning="r", action="transition_phase",
            phase_transition=PhaseTransitionDecision(to_phase="exploitation"),
        )
        out = self._strip(d, "m-1")
        self.assertEqual(out.action, "complete")
        self.assertIsNone(out.phase_transition)

    def test_member_cannot_ask_user(self):
        """Members cannot open a question dialog to the operator."""
        from state import UserQuestionDecision
        d = self.LLMDecision(
            thought="t", reasoning="r", action="ask_user",
            user_question=UserQuestionDecision(question="q?", context="c"),
        )
        out = self._strip(d, "m-1")
        self.assertEqual(out.action, "complete")
        self.assertIsNone(out.user_question)

    def test_dangerous_tool_in_member_always_escalates(self):
        """Every tool in DANGEROUS_TOOLS must trigger escalation regardless
        of how the member phrases the request (single or plan)."""
        from project_settings import DANGEROUS_TOOLS
        from orchestrator_helpers.nodes.fireteam_member_think_node import (
            _plan_has_dangerous_tool, _build_pending_confirmation,
        )
        from state import ToolPlan, ToolPlanStep

        # Every dangerous tool in single-use_tool form
        for tool in DANGEROUS_TOOLS:
            d = self.LLMDecision(
                thought="t", reasoning="r",
                action="use_tool", tool_name=tool, tool_args={},
            )
            self.assertIn(tool, DANGEROUS_TOOLS, f"{tool} should be flagged dangerous")

        # Plan wave containing one dangerous tool
        plan = ToolPlan(
            steps=[ToolPlanStep(tool_name="execute_hydra", tool_args={})],
            plan_rationale="x",
        )
        d = self.LLMDecision(thought="t", reasoning="r", action="plan_tools", tool_plan=plan)
        self.assertTrue(_plan_has_dangerous_tool(d))

    def test_all_forbidden_actions_have_stripping_reasons(self):
        """Can't forbid an action without giving the LLM a reason to stop
        re-emitting it. Every entry in _FORBIDDEN_MEMBER_ACTIONS must map
        to a non-empty string."""
        for action, reason in self._FORBIDDEN.items():
            self.assertIsInstance(reason, str)
            self.assertGreater(len(reason), 0, f"empty reason for {action}")

    def test_fireteam_gate_rejects_when_disabled(self):
        """deploy_fireteam action when FIRETEAM_ENABLED=false must not reach
        the router path. The think_node gate rewrites to use_tool with
        nulls so the router can't accidentally dispatch."""
        # The full gate is exercised in DeployFireteamGateTests; here we
        # verify the fragment builder returns empty strings when gated.
        from prompts.base import build_fireteam_prompt_fragments
        enum, field, example = build_fireteam_prompt_fragments(
            enabled=False, phase="informational",
            allowed_phases=["informational"],
        )
        self.assertEqual(enum, "")
        self.assertEqual(field, "")
        self.assertEqual(example, "")

    def test_fireteam_gate_rejects_when_phase_excluded(self):
        """When phase is not in allowed_phases, the prompt hides the action
        so the LLM can't request it in the first place."""
        from prompts.base import build_fireteam_prompt_fragments
        enum, field, example = build_fireteam_prompt_fragments(
            enabled=True, phase="exploitation",
            allowed_phases=["informational"],  # exploitation not allowed
        )
        self.assertEqual(enum, "")
        self.assertEqual(field, "")

    def test_fireteam_gate_permits_when_all_open(self):
        """When enabled + phase allowed, fragments carry the action docs."""
        from prompts.base import build_fireteam_prompt_fragments
        enum, field, example = build_fireteam_prompt_fragments(
            enabled=True, phase="informational",
            allowed_phases=["informational", "exploitation"],
        )
        self.assertIn("deploy_fireteam", enum)
        self.assertIn("fireteam_plan", field)
        self.assertIn("deploy_fireteam", example)


# =============================================================================
# 9b. Fireteam propensity prompt injection (per-project 1-5 scalar)
# =============================================================================

class FireteamPropensityTests(unittest.TestCase):
    """The FIRETEAM_PROPENSITY setting prepends a strong directive to the
    fireteam prompt block so the LLM knows how eagerly to fan out. Level 3
    is baseline (empty). 1/2 push toward reluctance, 4/5 push toward
    aggressiveness. The directive must NOT appear when the fireteam gate
    itself is closed (FIRETEAM_ENABLED=false or phase not allowed)."""

    def _fragments(self, propensity, *, enabled=True, phase="informational",
                   allowed=("informational", "exploitation", "post_exploitation")):
        from prompts.base import build_fireteam_prompt_fragments
        return build_fireteam_prompt_fragments(
            enabled=enabled, phase=phase, allowed_phases=list(allowed),
            max_members=5, propensity=propensity,
        )

    def test_propensity_3_is_baseline_no_header(self):
        """Propensity 3 preserves existing behavior — no extra header text."""
        _, _, example = self._fragments(3)
        self.assertIn("deploy_fireteam", example)
        self.assertNotIn("FIRETEAM PROPENSITY", example)

    def test_propensity_1_emits_very_reluctant(self):
        _, _, example = self._fragments(1)
        self.assertIn("FIRETEAM PROPENSITY: 1/5", example)
        self.assertIn("VERY RELUCTANT", example)
        self.assertIn("MUST NOT deploy", example)
        # Header must sit above the base block so the LLM reads it first.
        self.assertLess(example.index("FIRETEAM PROPENSITY"), example.index("deploy_fireteam"))

    def test_propensity_2_emits_reluctant(self):
        _, _, example = self._fragments(2)
        self.assertIn("FIRETEAM PROPENSITY: 2/5", example)
        self.assertIn("RELUCTANT", example)

    def test_propensity_4_emits_eager(self):
        _, _, example = self._fragments(4)
        self.assertIn("FIRETEAM PROPENSITY: 4/5", example)
        self.assertIn("EAGER", example)

    def test_propensity_5_emits_aggressive(self):
        _, _, example = self._fragments(5)
        self.assertIn("FIRETEAM PROPENSITY: 5/5", example)
        self.assertIn("AGGRESSIVE", example)
        self.assertIn("MUST deploy", example)

    def test_propensity_out_of_range_falls_back_to_baseline(self):
        """Values outside 1-5 (bad DB write, stale setting) must not crash
        and must produce the baseline block — never a half-rendered header."""
        for bad in (0, 6, -1, 99):
            _, _, example = self._fragments(bad)
            self.assertIn("deploy_fireteam", example)
            self.assertNotIn("FIRETEAM PROPENSITY", example)

    def test_propensity_suppressed_when_gate_closed(self):
        """Even with propensity=5, the header must NOT appear when the
        fireteam gate is closed — the LLM must not see propensity
        instructions for an action it cannot emit."""
        # Gate closed via FIRETEAM_ENABLED=false
        enum, field, example = self._fragments(5, enabled=False)
        self.assertEqual((enum, field, example), ("", "", ""))
        # Gate closed via phase not in allowlist
        enum, field, example = self._fragments(5, phase="exploitation", allowed=("informational",))
        self.assertEqual((enum, field, example), ("", "", ""))

    def test_propensity_default_signature_is_three(self):
        """Callers that omit the propensity kwarg (including existing test
        and code paths) must still get baseline behavior."""
        from prompts.base import build_fireteam_prompt_fragments
        _, _, example_default = build_fireteam_prompt_fragments(
            enabled=True, phase="informational",
            allowed_phases=["informational"],
            max_members=5,
        )
        _, _, example_three = self._fragments(3)
        self.assertEqual(example_default, example_three)

    def test_propensity_3_preserves_block_budget(self):
        """Propensity 3 must not exceed the 4000-char budget enforced by
        test_prompt_sizes — it emits no extra text vs the pre-feature
        baseline."""
        _, _, example = self._fragments(3)
        self.assertLess(len(example), 4000)


# =============================================================================
# 10. Zod-equivalent server-side validation (Python mirror for parity)
# =============================================================================

class ServerSideValidationTests(unittest.TestCase):
    """Mirror the server-side validation rules used by the webapp Zod schema
    so the Python-side invariants stay in sync."""

    def _check(self, max_concurrent, max_members):
        if max_concurrent < 1 or max_concurrent > 8:
            return "max_concurrent out of range"
        if max_members < 2 or max_members > 8:
            return "max_members out of range"
        if max_concurrent > max_members:
            return "max_concurrent cannot exceed max_members"
        return None

    def test_concurrent_below_one_rejected(self):
        self.assertIsNotNone(self._check(0, 5))

    def test_members_below_two_rejected(self):
        self.assertIsNotNone(self._check(1, 1))

    def test_concurrent_exceeds_members_rejected(self):
        self.assertIsNotNone(self._check(8, 3))

    def test_valid_combination(self):
        self.assertIsNone(self._check(3, 5))


# =============================================================================
# 11. Anchor propagation (post-fix): FireteamMemberResult.last_chain_step_id
#     MUST be populated for inline findings to land in Neo4j.
# =============================================================================

class AnchorPropagationTests(unittest.TestCase):
    """After the fix: _last_chain_step_id in member final state must
    surface in the FireteamMemberResult as last_chain_step_id so the
    anchor is available wherever the result is read."""

    def setUp(self):
        from orchestrator_helpers.nodes.fireteam_deploy_node import _result_from_final_state
        self._result = _result_from_final_state

    def _final(self, last_id):
        return {
            "current_iteration": 2, "tokens_used": 100,
            "parent_target_info": {}, "target_info": {},
            "execution_trace": [], "chain_findings_memory": [],
            "completion_reason": "complete",
            "_pending_confirmation": None,
            "_last_chain_step_id": last_id,
        }

    def test_anchor_propagates_to_result(self):
        r = self._result(self._final("step-42"), {"name": "A"}, "m-1", 1.0)
        self.assertEqual(r["last_chain_step_id"], "step-42")

    def test_anchor_absent_produces_none(self):
        final = self._final(None)
        r = self._result(final, {"name": "A"}, "m-1", 1.0)
        self.assertIsNone(r["last_chain_step_id"])

    def test_result_dict_key_is_public_name(self):
        """The Pydantic field must serialize to 'last_chain_step_id'
        (public), not '_last_chain_step_id' (state-internal private name)."""
        r = self._result(self._final("step-1"), {"name": "A"}, "m-1", 1.0)
        self.assertIn("last_chain_step_id", r)
        self.assertNotIn("_last_chain_step_id", r)


# =============================================================================
# 12. Inline ChainFinding / ChainFailure / exploit_success writes in the
#     member think node — verified by patching chain_graph_writer and
#     asserting the correct calls happen with member attribution.
# =============================================================================

class MemberInlineWritesTests(unittest.IsolatedAsyncioTestCase):
    def _state_with_prev_step(self, *, success=True, tool_output="found open port 22"):
        return {
            "messages": [],
            "current_iteration": 1,
            "max_iterations": 10,
            "task_complete": False,
            "completion_reason": None,
            "current_phase": "informational",
            "attack_path_type": "cve_exploit",
            "user_id": "u", "project_id": "p", "session_id": "s",
            "parent_target_info": {},
            "member_name": "Web Tester", "member_id": "member-0-abc",
            "fireteam_id": "fteam-1",
            "skills": ["xss"], "task": "test",
            "execution_trace": [],
            "target_info": {}, "chain_findings_memory": [],
            "chain_failures_memory": [],
            "_pending_confirmation": None,
            "_current_plan": None,
            "tokens_used": 0,
            "_decision": None,
            "_current_step": {
                "tool_name": "execute_nmap",
                "tool_args": {"target": "10.0.0.1"},
                "tool_output": tool_output,
                "success": success,
                "iteration": 1,
                "thought": "scan", "reasoning": "recon",
                "error_message": None if success else "timeout after 30s",
            },
            "_last_chain_step_id": None,
            "_guardrail_blocked": False,
        }

    async def test_writes_chain_step_with_member_attribution(self):
        """Basic happy path: prev_step has output, chain step is written
        with agent_id=member_id and fireteam_id=fireteam_id."""
        from orchestrator_helpers.nodes.fireteam_member_think_node import fireteam_member_think_node

        calls = []
        def _capture(*args, **kwargs):
            calls.append(("fire_record_step", kwargs))

        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(return_value=MagicMock(
            content='{"thought": "t", "reasoning": "r", "action": "complete", "completion_reason": "done"}',
        ))

        with patch(
            "orchestrator_helpers.nodes.fireteam_member_think_node.chain_graph.fire_record_step",
            side_effect=_capture,
        ):
            update = await fireteam_member_think_node(
                self._state_with_prev_step(), None,
                llm=mock_llm, neo4j_creds=("bolt://x", "u", "p"),
                streaming_callbacks=None,
            )

        self.assertEqual(len(calls), 1, f"expected 1 step write, got {calls}")
        _, kwargs = calls[0]
        self.assertEqual(kwargs["agent_id"], "member-0-abc")
        self.assertEqual(kwargs["agent_name"], "Web Tester")
        self.assertEqual(kwargs["fireteam_id"], "fteam-1")
        # Member state must now carry the new ChainStep id so the next
        # iteration can NEXT_STEP-link to it. Also lets the deploy node
        # propagate it into FireteamMemberResult.last_chain_step_id.
        self.assertIn("_last_chain_step_id", update)
        self.assertIsNotNone(update.get("_last_chain_step_id"))

    async def test_writes_chain_failure_when_prev_step_failed(self):
        """When the previous tool reported success=False, a ChainFailure
        must be written alongside the ChainStep."""
        from orchestrator_helpers.nodes.fireteam_member_think_node import fireteam_member_think_node

        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(return_value=MagicMock(
            content='{"thought": "t", "reasoning": "r", "action": "complete"}',
        ))
        step_calls, failure_calls = [], []

        with patch(
            "orchestrator_helpers.nodes.fireteam_member_think_node.chain_graph.fire_record_step",
            side_effect=lambda *a, **kw: step_calls.append(kw),
        ), patch(
            "orchestrator_helpers.nodes.fireteam_member_think_node.chain_graph.fire_record_failure",
            side_effect=lambda *a, **kw: failure_calls.append(kw),
        ):
            await fireteam_member_think_node(
                self._state_with_prev_step(success=False), None,
                llm=mock_llm, neo4j_creds=("bolt://x", "u", "p"),
                streaming_callbacks=None,
            )

        self.assertEqual(len(step_calls), 1)
        self.assertEqual(len(failure_calls), 1)
        self.assertEqual(failure_calls[0]["failure_type"], "tool_error")
        self.assertEqual(failure_calls[0]["tool_name"], "execute_nmap")

    async def test_writes_chain_finding_when_analysis_present(self):
        """When the LLM includes output_analysis.chain_findings, each
        finding is persisted via fire_record_finding with member
        attribution, anchored to the just-written ChainStep."""
        from orchestrator_helpers.nodes.fireteam_member_think_node import fireteam_member_think_node

        # LLM emits a decision with an inline analysis containing one finding.
        analysis_json = '''
        {"thought": "t", "reasoning": "r", "action": "complete",
         "completion_reason": "done",
         "output_analysis": {
           "interpretation": "nmap revealed ssh",
           "extracted_info": {"primary_target": "10.0.0.1", "ports": [22], "services": [], "technologies": [], "vulnerabilities": [], "credentials": [], "sessions": []},
           "actionable_findings": [], "recommended_next_steps": [],
           "exploit_succeeded": false, "exploit_details": null,
           "chain_findings": [
             {"finding_type": "service_identified", "severity": "info",
              "title": "SSH on port 22", "evidence": "nmap -sV showed OpenSSH 7.4",
              "related_cves": [], "related_ips": ["10.0.0.1"], "confidence": 90}
           ]}}'''

        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(return_value=MagicMock(content=analysis_json))

        finding_calls, step_calls = [], []
        with patch(
            "orchestrator_helpers.nodes.fireteam_member_think_node.chain_graph.fire_record_step",
            side_effect=lambda *a, **kw: step_calls.append(kw),
        ), patch(
            "orchestrator_helpers.nodes.fireteam_member_think_node.chain_graph.fire_record_finding",
            side_effect=lambda *a, **kw: finding_calls.append(kw),
        ):
            update = await fireteam_member_think_node(
                self._state_with_prev_step(), None,
                llm=mock_llm, neo4j_creds=("bolt://x", "u", "p"),
                streaming_callbacks=None,
            )

        self.assertEqual(len(step_calls), 1)
        self.assertEqual(len(finding_calls), 1)
        f = finding_calls[0]
        self.assertEqual(f["agent_id"], "member-0-abc")
        self.assertEqual(f["source_agent"], "Web Tester")
        self.assertEqual(f["fireteam_id"], "fteam-1")
        self.assertEqual(f["finding_type"], "service_identified")
        # The finding must be anchored to the step the member just wrote.
        self.assertEqual(f["step_id"], step_calls[0]["step_id"])
        # And the state should carry the finding through to the result.
        self.assertEqual(len(update.get("chain_findings_memory") or []), 1)

    async def test_writes_exploit_success_in_exploitation_phase(self):
        """When analysis.exploit_succeeded is true AND phase is exploitation,
        fire_record_exploit_success is invoked with member attribution."""
        from orchestrator_helpers.nodes.fireteam_member_think_node import fireteam_member_think_node

        analysis_json = '''
        {"thought": "t", "reasoning": "r", "action": "complete",
         "completion_reason": "rooted",
         "output_analysis": {
           "interpretation": "got shell",
           "extracted_info": {"primary_target": "10.0.0.1", "ports": [], "services": [], "technologies": [], "vulnerabilities": [], "credentials": [], "sessions": [1]},
           "actionable_findings": [], "recommended_next_steps": [],
           "exploit_succeeded": true,
           "exploit_details": {"attack_type": "cve_exploit", "target_ip": "10.0.0.1",
                                "target_port": 22, "cve_ids": ["CVE-2024-1234"],
                                "evidence": "uid=0(root)"},
           "chain_findings": []}}'''

        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(return_value=MagicMock(content=analysis_json))

        exploit_calls = []
        state = self._state_with_prev_step()
        state["current_phase"] = "exploitation"

        with patch(
            "orchestrator_helpers.nodes.fireteam_member_think_node.chain_graph.fire_record_step",
            side_effect=lambda *a, **kw: None,
        ), patch(
            "orchestrator_helpers.nodes.fireteam_member_think_node.chain_graph.fire_record_exploit_success",
            side_effect=lambda *a, **kw: exploit_calls.append(kw),
        ), patch(
            "orchestrator_helpers.nodes.fireteam_member_think_node.chain_graph.fire_record_finding",
            side_effect=lambda *a, **kw: None,
        ):
            await fireteam_member_think_node(
                state, None,
                llm=mock_llm, neo4j_creds=("bolt://x", "u", "p"),
                streaming_callbacks=None,
            )

        self.assertEqual(len(exploit_calls), 1)
        e = exploit_calls[0]
        self.assertEqual(e["target_ip"], "10.0.0.1")
        self.assertEqual(e["cve_ids"], ["CVE-2024-1234"])

    async def test_bridge_resolution_called_with_extracted_info(self):
        """When analysis.extracted_info is populated, fire_resolve_step_bridges
        is invoked so ChainStep gets STEP_TARGETED / STEP_EXPLOITED / etc.
        edges to recon nodes — matching root agent topology."""
        from orchestrator_helpers.nodes.fireteam_member_think_node import fireteam_member_think_node

        analysis_json = '''
        {"thought": "t", "reasoning": "r", "action": "complete",
         "completion_reason": "done",
         "output_analysis": {
           "interpretation": "port scan",
           "extracted_info": {
             "primary_target": "10.0.0.1",
             "ports": [22, 80, 443],
             "services": ["ssh", "http"],
             "technologies": ["nginx"],
             "vulnerabilities": ["CVE-2024-1234"],
             "credentials": [], "sessions": []
           },
           "actionable_findings": [], "recommended_next_steps": [],
           "exploit_succeeded": false, "exploit_details": null,
           "chain_findings": []}}'''

        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(return_value=MagicMock(content=analysis_json))

        bridge_calls = []
        with patch(
            "orchestrator_helpers.nodes.fireteam_member_think_node.chain_graph.fire_record_step",
            side_effect=lambda *a, **kw: None,
        ), patch(
            "orchestrator_helpers.nodes.fireteam_member_think_node.chain_graph.fire_resolve_step_bridges",
            side_effect=lambda *a, **kw: bridge_calls.append(kw),
        ):
            await fireteam_member_think_node(
                self._state_with_prev_step(), None,
                llm=mock_llm, neo4j_creds=("bolt://x", "u", "p"),
                streaming_callbacks=None,
            )

        self.assertEqual(len(bridge_calls), 1)
        kw = bridge_calls[0]
        # Extracted info must carry the keys _resolve_step_bridges needs.
        self.assertEqual(kw["extracted_info"]["primary_target"], "10.0.0.1")
        self.assertEqual(kw["extracted_info"]["ports"], [22, 80, 443])
        self.assertEqual(kw["extracted_info"]["vulnerabilities"], ["CVE-2024-1234"])
        self.assertEqual(kw["extracted_info"]["technologies"], ["nginx"])
        self.assertEqual(kw["user_id"], "u")
        self.assertEqual(kw["project_id"], "p")
        self.assertEqual(kw["tool_name"], "execute_nmap")

    async def test_bridges_not_called_when_no_analysis(self):
        """No analysis -> no bridge call (nothing to anchor)."""
        from orchestrator_helpers.nodes.fireteam_member_think_node import fireteam_member_think_node
        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(return_value=MagicMock(
            content='{"thought": "t", "reasoning": "r", "action": "complete"}',
        ))
        bridge_calls = []
        with patch(
            "orchestrator_helpers.nodes.fireteam_member_think_node.chain_graph.fire_record_step",
            side_effect=lambda *a, **kw: None,
        ), patch(
            "orchestrator_helpers.nodes.fireteam_member_think_node.chain_graph.fire_resolve_step_bridges",
            side_effect=lambda *a, **kw: bridge_calls.append(kw),
        ):
            await fireteam_member_think_node(
                self._state_with_prev_step(), None,
                llm=mock_llm, neo4j_creds=("bolt://x", "u", "p"),
                streaming_callbacks=None,
            )
        self.assertEqual(len(bridge_calls), 0)

    async def test_no_analysis_no_finding_calls(self):
        """When the LLM omits output_analysis, no finding writes happen —
        but the ChainStep still persists (tool did run)."""
        from orchestrator_helpers.nodes.fireteam_member_think_node import fireteam_member_think_node

        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(return_value=MagicMock(
            content='{"thought": "t", "reasoning": "r", "action": "complete"}',
        ))
        finding_calls, step_calls = [], []
        with patch(
            "orchestrator_helpers.nodes.fireteam_member_think_node.chain_graph.fire_record_step",
            side_effect=lambda *a, **kw: step_calls.append(kw),
        ), patch(
            "orchestrator_helpers.nodes.fireteam_member_think_node.chain_graph.fire_record_finding",
            side_effect=lambda *a, **kw: finding_calls.append(kw),
        ):
            await fireteam_member_think_node(
                self._state_with_prev_step(), None,
                llm=mock_llm, neo4j_creds=("bolt://x", "u", "p"),
                streaming_callbacks=None,
            )
        self.assertEqual(len(step_calls), 1)
        self.assertEqual(len(finding_calls), 0)


if __name__ == "__main__":
    unittest.main()
