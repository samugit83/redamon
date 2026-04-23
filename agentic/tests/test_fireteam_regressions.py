"""Fireteam regression tests — pins four bugs found in the 2026-04-18 deep review.

Covers: member target_info merge, execution_trace append, plan-wave output
handoff + ChainStep writes, and per-turn token accounting.

Run:
    docker run --rm -v "/home/samuele/Progetti didattici/redamon/agentic:/app" \
        -w /app redamon-agent python -m unittest tests.test_fireteam_regressions -v
"""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

_agentic_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _agentic_dir)


def _base_member_state(**overrides):
    """Minimal FireteamMemberState with prev tool step populated."""
    base = {
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
        "skills": ["xss"], "task": "scan target",
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
            "tool_output": "PORT 22/tcp open ssh OpenSSH 7.4\nPORT 80/tcp open http nginx 1.18",
            "success": True,
            "iteration": 1,
            "thought": "scan", "reasoning": "recon",
            "error_message": None,
        },
        "_last_chain_step_id": None,
        "_guardrail_blocked": False,
    }
    base.update(overrides)
    return base


# =============================================================================
# BUG 1: Member target_info never updated from analysis.extracted_info.
# =============================================================================
#
# Root's think_node merges analysis.extracted_info (ports, services, techs,
# vulns, creds, sessions) into state["target_info"] via TargetInfo.merge_from.
# The member think node does NOT. Consequence: FireteamMemberResult.target_info_delta
# (computed as final_ti - parent_ti in _result_from_final_state) is ALWAYS
# empty for members, and the collect_node's _merge_target_info call does
# nothing useful. Parent's structured target_info is starved of member
# discoveries; only the SystemMessage narrative surfaces them.

class MemberTargetInfoMergeRegression(unittest.IsolatedAsyncioTestCase):
    async def test_member_analysis_updates_target_info(self):
        from orchestrator_helpers.nodes.fireteam_member_think_node import fireteam_member_think_node

        analysis_json = '''
        {"thought": "t", "reasoning": "r", "action": "complete",
         "completion_reason": "done",
         "output_analysis": {
           "interpretation": "nmap found ssh+http",
           "extracted_info": {"primary_target": "10.0.0.1",
                              "ports": [22, 80],
                              "services": ["ssh", "http"],
                              "technologies": ["nginx 1.18"],
                              "vulnerabilities": [],
                              "credentials": [], "sessions": []},
           "actionable_findings": [], "recommended_next_steps": [],
           "exploit_succeeded": false, "exploit_details": null,
           "chain_findings": []}}'''

        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(return_value=MagicMock(content=analysis_json))

        with patch(
            "orchestrator_helpers.nodes.fireteam_member_think_node.chain_graph.fire_record_step",
            side_effect=lambda *a, **kw: None,
        ), patch(
            "orchestrator_helpers.nodes.fireteam_member_think_node.chain_graph.fire_resolve_step_bridges",
            side_effect=lambda *a, **kw: None,
        ):
            update = await fireteam_member_think_node(
                _base_member_state(), None,
                llm=mock_llm, neo4j_creds=("bolt://x", "u", "p"),
                streaming_callbacks=None,
            )

        # The member SHOULD merge extracted_info into target_info so the deploy
        # node can compute a non-empty target_info_delta for the parent's merge.
        ti = update.get("target_info") or {}
        self.assertIn(22, ti.get("ports") or [], "ports from analysis must land in target_info")
        self.assertIn("ssh", ti.get("services") or [])
        self.assertIn("nginx 1.18", ti.get("technologies") or [])


# =============================================================================
# BUG 2: Member execution_trace never populated.
# =============================================================================
#
# Root appends each completed step to state["execution_trace"] after output
# analysis. The member think node does not. Consequences:
#   - FireteamMemberResult.execution_trace_summary is always [] — the UI can't
#     render a per-member tool timeline summary (must query Neo4j instead).
#   - The member's own next-turn prompt's "Your execution trace so far" block
#     stays stuck on "(no steps yet)" because _build_member_prompt reads from
#     state["execution_trace"]. Members are effectively amnesiac beyond the
#     single _current_step the previous execute node left behind.

class MemberExecutionTraceRegression(unittest.IsolatedAsyncioTestCase):
    async def test_member_execution_trace_gets_completed_step(self):
        from orchestrator_helpers.nodes.fireteam_member_think_node import fireteam_member_think_node

        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(return_value=MagicMock(
            content='{"thought":"t","reasoning":"r","action":"complete","completion_reason":"done"}'
        ))
        with patch(
            "orchestrator_helpers.nodes.fireteam_member_think_node.chain_graph.fire_record_step",
            side_effect=lambda *a, **kw: None,
        ):
            update = await fireteam_member_think_node(
                _base_member_state(), None,
                llm=mock_llm, neo4j_creds=("bolt://x", "u", "p"),
                streaming_callbacks=None,
            )

        trace = update.get("execution_trace")
        self.assertIsNotNone(trace, "execution_trace must be emitted as an update")
        self.assertEqual(len(trace), 1, "the just-completed tool step must be appended")
        self.assertEqual(trace[0]["tool_name"], "execute_nmap")


# =============================================================================
# BUG 3: Plan wave output is never fed back to the member LLM.
# =============================================================================
#
# When a member emits plan_tools, execute_plan_node fills
# _current_plan["steps"][i]["tool_output"] for each step but does NOT populate
# _current_step. On the next think call, _build_member_prompt only reads
# _current_step, so the LLM has no visibility into any plan step's output.
# The member loops blind — re-plans, hallucinates, or gives up with no
# findings. Root's think_node has a has_pending_plan_outputs branch that
# handles this; the member does not.

class MemberPlanWaveOutputRegression(unittest.IsolatedAsyncioTestCase):
    async def test_plan_wave_outputs_surface_in_next_prompt(self):
        from orchestrator_helpers.nodes.fireteam_member_think_node import _build_member_prompt

        state = _base_member_state(
            _current_step=None,  # plan_tools path never populates _current_step
            _current_plan={
                "steps": [
                    {"tool_name": "execute_nmap", "tool_args": {"target": "x"},
                     "tool_output": "PORT 22/tcp open ssh",
                     "success": True},
                    {"tool_name": "execute_httpx", "tool_args": {"url": "http://x"},
                     "tool_output": "HTTP/1.1 200 OK Server: nginx/1.18",
                     "success": True},
                ],
                "wave_id": "wave-abc",
            },
        )
        prompt = _build_member_prompt(state)

        # The member's next LLM call must see the plan wave outputs. Without
        # this, the member can't reason about what just ran.
        self.assertIn("22/tcp open ssh", prompt,
                      "plan step output must appear in the next member prompt")
        self.assertIn("nginx/1.18", prompt,
                      "plan step output must appear in the next member prompt")

    async def test_plan_wave_writes_chain_steps_per_step(self):
        """Each plan wave tool invocation should produce its own ChainStep in
        Neo4j with member attribution. Uses sync_record_step (same as root's
        plan wave path) so prev_step_id chain linkage is sequential."""
        from orchestrator_helpers.nodes.fireteam_member_think_node import fireteam_member_think_node

        # Analysis present so plan-wave writes happen.
        analysis_json = '''
        {"thought":"t","reasoning":"r","action":"complete","completion_reason":"done",
         "output_analysis":{
           "interpretation":"two-tool recon wave",
           "extracted_info":{"primary_target":"10.0.0.1","ports":[22,80],"services":[],"technologies":[],"vulnerabilities":[],"credentials":[],"sessions":[]},
           "actionable_findings":[],"recommended_next_steps":[],
           "exploit_succeeded":false,"exploit_details":null,"chain_findings":[]
         }}'''
        mock_llm = MagicMock()
        mock_llm.ainvoke = AsyncMock(return_value=MagicMock(content=analysis_json))

        state = _base_member_state(
            _current_step=None,
            _current_plan={
                "steps": [
                    {"tool_name": "execute_nmap", "tool_args": {},
                     "tool_output": "open 22", "success": True, "iteration": 1},
                    {"tool_name": "execute_httpx", "tool_args": {},
                     "tool_output": "nginx 1.18", "success": True, "iteration": 1},
                ],
                "wave_id": "wave-abc",
            },
        )
        step_calls = []
        with patch(
            "orchestrator_helpers.nodes.fireteam_member_think_node.chain_graph.sync_record_step",
            side_effect=lambda *a, **kw: step_calls.append(kw),
        ):
            update = await fireteam_member_think_node(
                state, None,
                llm=mock_llm, neo4j_creds=("bolt://x", "u", "p"),
                streaming_callbacks=None,
            )

        # One ChainStep per plan step.
        self.assertEqual(len(step_calls), 2,
                         "plan waves must record one ChainStep per tool")
        # Each must carry member attribution.
        self.assertEqual(step_calls[0]["agent_id"], "member-0-abc")
        self.assertEqual(step_calls[0]["fireteam_id"], "fteam-1")
        # Sequential chain linkage: step 2's prev == step 1's step_id.
        self.assertEqual(step_calls[1]["prev_step_id"], step_calls[0]["step_id"])
        # execution_trace grows by N.
        self.assertEqual(len(update.get("execution_trace") or []), 2)
        # target_info merged from combined extracted_info.
        self.assertIn(22, (update.get("target_info") or {}).get("ports") or [])


# =============================================================================
# BUG 4: tokens_used accumulates the entire history every turn (quadratic).
# =============================================================================
#
# fireteam_member_think_node uses get_num_tokens_from_messages(llm_messages +
# [AIMessage]) — which returns the token count of the FULL conversation so
# far — and then adds that to state["tokens_used"]. After N turns this gives
# O(N^2) instead of O(N). Not a safety issue (no budget gate on tokens
# anymore), but Postgres metrics, the UI's "12345 tokens" chip, and logs
# over-report by an order of magnitude on long member runs.

class MemberTokenAccountingRegression(unittest.IsolatedAsyncioTestCase):
    async def test_tokens_used_delta_excludes_prior_history(self):
        """The per-turn token delta must depend only on the system prompt +
        LLM response, NOT on prior message history. Pre-fix the delta grew
        quadratically with conversation length because the code counted
        ``llm_messages + [response]`` which includes all history."""
        from orchestrator_helpers.nodes.fireteam_member_think_node import fireteam_member_think_node
        from langchain_core.messages import AIMessage, HumanMessage

        mock_llm = MagicMock()
        def _count(messages):
            return sum(len(getattr(m, "content", "") or "") for m in messages) // 4
        mock_llm.get_num_tokens_from_messages = _count
        mock_llm.ainvoke = AsyncMock(return_value=MagicMock(
            content='{"thought":"t","reasoning":"r","action":"complete","completion_reason":"done"}'
        ))

        async def _run(history_len: int) -> int:
            history = []
            for _ in range(history_len):
                history.append(HumanMessage(content="H" * 500))
                history.append(AIMessage(content="A" * 500))
            st = _base_member_state(messages=history, tokens_used=0)
            with patch(
                "orchestrator_helpers.nodes.fireteam_member_think_node.chain_graph.fire_record_step",
                side_effect=lambda *a, **kw: None,
            ):
                upd = await fireteam_member_think_node(
                    st, None,
                    llm=mock_llm, neo4j_creds=("bolt://x", "u", "p"),
                    streaming_callbacks=None,
                )
            return upd["tokens_used"]

        delta_empty = await _run(0)
        delta_long = await _run(20)  # ~20000 chars of extra history

        # The delta must be identical regardless of history length. Pre-fix,
        # the long-history run would be ~5000 tokens bigger because the
        # tokenizer counted all prior messages.
        self.assertEqual(delta_empty, delta_long,
                         f"per-turn delta must ignore history; "
                         f"empty={delta_empty}, long={delta_long}")


# =============================================================================
# BUG 5: step_iteration silently dropped by ChainFindingExtract Pydantic model.
# =============================================================================
#
# fireteam_member_think_node tags each finding dict with ``step_iteration`` so
# the parent's format_chain_context renders "(step N)" instead of "(step ?)".
# But _result_from_final_state rebuilds those dicts into ChainFindingExtract
# objects, and pre-fix the model did not declare step_iteration — Pydantic's
# extra-ignore silently dropped the key. Result: fireteam-sourced findings in
# the parent's chain_findings_memory rolled up with no step tag, rendered as
# "(step ?)" in every subsequent root think prompt.

class FindingStepIterationPreservedRegression(unittest.TestCase):
    def test_step_iteration_survives_roundtrip(self):
        from orchestrator_helpers.nodes.fireteam_deploy_node import _result_from_final_state

        final_state = {
            "current_iteration": 3,
            "tokens_used": 1000,
            "input_tokens_used": 700,
            "output_tokens_used": 300,
            "task_complete": True,
            "completion_reason": "complete",
            "target_info": {},
            "chain_findings_memory": [
                {
                    "finding_type": "vulnerability_confirmed",
                    "severity": "high",
                    "title": "SSRF in /api/render",
                    "evidence": "200 OK with external host body",
                    "confidence": 95,
                    "step_iteration": 2,
                },
                {
                    "finding_type": "configuration_found",
                    "severity": "info",
                    "title": "nginx version disclosure",
                    "evidence": "Server: nginx/1.18",
                    "confidence": 100,
                    "step_iteration": 1,
                },
            ],
            "execution_trace": [],
        }
        spec = {"name": "API Fuzzer", "task": "t", "skills": ["ffuf"], "max_iterations": 10}

        result = _result_from_final_state(final_state, spec, "member-0-abc", 12.3)
        findings = result.get("findings") or []
        self.assertEqual(len(findings), 2)
        # Pre-fix: both entries had no step_iteration (Pydantic dropped it).
        # Post-fix: both round-trip intact.
        self.assertEqual(findings[0].get("step_iteration"), 2)
        self.assertEqual(findings[1].get("step_iteration"), 1)

    def test_model_declares_step_iteration_field(self):
        from state import ChainFindingExtract
        self.assertIn("step_iteration", ChainFindingExtract.model_fields)


if __name__ == "__main__":
    unittest.main()
