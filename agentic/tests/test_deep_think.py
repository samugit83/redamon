"""Tests for Deep Think feature — trigger conditions, parsing, and state management."""

import unittest
import json
from unittest.mock import patch

from state import DeepThinkResult, LLMDecision
from orchestrator_helpers.parsing import try_parse_llm_decision


class TestDeepThinkResult(unittest.TestCase):
    """Test DeepThinkResult Pydantic model parsing."""

    def test_parse_valid_json(self):
        raw = json.dumps({
            "situation_assessment": "Target has port 80 open",
            "attack_vectors_identified": ["SQLi", "XSS"],
            "recommended_approach": "Start with SQLi on login form",
            "priority_order": ["SQLi", "XSS", "SSRF"],
            "risks_and_mitigations": "WAF may block payloads"
        })
        result = DeepThinkResult.model_validate_json(raw)
        self.assertEqual(result.situation_assessment, "Target has port 80 open")
        self.assertEqual(len(result.attack_vectors_identified), 2)
        self.assertEqual(result.priority_order[0], "SQLi")

    def test_parse_with_markdown_fences(self):
        """LLMs often wrap JSON in ```json ... ``` fences."""
        inner = json.dumps({
            "situation_assessment": "Test",
            "attack_vectors_identified": [],
            "recommended_approach": "Test approach",
            "priority_order": [],
            "risks_and_mitigations": "None"
        })
        raw = f"```json\n{inner}\n```"
        # Strip fences (same logic as think_node)
        if raw.startswith("```"):
            raw = raw.split("\n", 1)[1] if "\n" in raw else raw[3:]
            if raw.endswith("```"):
                raw = raw[:-3].strip()
        result = DeepThinkResult.model_validate_json(raw)
        self.assertEqual(result.situation_assessment, "Test")

    def test_parse_minimal_fields(self):
        """Only required fields, defaults for lists."""
        raw = json.dumps({
            "situation_assessment": "Minimal",
            "recommended_approach": "Do something",
            "risks_and_mitigations": "Low risk"
        })
        result = DeepThinkResult.model_validate_json(raw)
        self.assertEqual(result.attack_vectors_identified, [])
        self.assertEqual(result.priority_order, [])


class TestLLMDecisionNeedDeepThink(unittest.TestCase):
    """Test need_deep_think field in LLMDecision."""

    def test_default_false_when_absent(self):
        """need_deep_think defaults to False when not in JSON."""
        decision, error = try_parse_llm_decision(json.dumps({
            "thought": "Scanning target",
            "reasoning": "Need port info",
            "action": "use_tool",
            "tool_name": "execute_nmap",
            "tool_args": {"target": "10.0.0.1", "args": "-sV"},
        }))
        self.assertIsNotNone(decision)
        self.assertFalse(decision.need_deep_think)

    def test_explicit_true(self):
        """LLM explicitly sets need_deep_think: true."""
        decision, error = try_parse_llm_decision(json.dumps({
            "thought": "I keep trying the same approach",
            "reasoning": "Not making progress, need to rethink",
            "action": "use_tool",
            "tool_name": "execute_command",
            "tool_args": {"command": "nmap -sV 10.0.0.1"},
            "need_deep_think": True,
        }))
        self.assertIsNotNone(decision)
        self.assertTrue(decision.need_deep_think)

    def test_explicit_false(self):
        """LLM explicitly sets need_deep_think: false."""
        decision, error = try_parse_llm_decision(json.dumps({
            "thought": "Making good progress",
            "reasoning": "Found open ports",
            "action": "use_tool",
            "tool_name": "execute_nmap",
            "tool_args": {"target": "10.0.0.1", "args": "-sC"},
            "need_deep_think": False,
        }))
        self.assertIsNotNone(decision)
        self.assertFalse(decision.need_deep_think)


class TestDeepThinkTriggerConditions(unittest.TestCase):
    """Test the trigger detection logic (extracted from think_node)."""

    def _detect_trigger(self, iteration, just_transitioned, exec_trace, need_deep_think):
        """Replicate the trigger detection logic from think_node."""
        trigger_reason = None

        # Condition 1: first iteration
        if iteration == 1:
            trigger_reason = "First iteration — establishing initial strategy"

        # Condition 2: phase transition
        elif just_transitioned:
            trigger_reason = f"Phase transition to {just_transitioned} — re-evaluating strategy"

        # Condition 3: failure loop (3+ consecutive failures)
        if not trigger_reason and len(exec_trace) >= 3:
            consecutive = 0
            for step in reversed(exec_trace[-6:]):
                out = ((step.get("tool_output") or "")[:500]).lower()
                is_fail = (
                    not step.get("success", True)
                    or "failed" in out
                    or "error" in out
                    or "exploit completed, but no session" in out
                )
                if is_fail:
                    consecutive += 1
                else:
                    break
            if consecutive >= 3:
                trigger_reason = f"Failure loop detected ({consecutive} consecutive failures) — pivoting strategy"

        # Condition 4: LLM self-requested
        if not trigger_reason and need_deep_think:
            trigger_reason = "Agent self-assessed stagnation — strategic re-evaluation requested"

        return trigger_reason

    def test_trigger_first_iteration(self):
        reason = self._detect_trigger(iteration=1, just_transitioned=None, exec_trace=[], need_deep_think=False)
        self.assertIn("First iteration", reason)

    def test_trigger_phase_transition(self):
        reason = self._detect_trigger(iteration=5, just_transitioned="exploitation", exec_trace=[], need_deep_think=False)
        self.assertIn("Phase transition to exploitation", reason)

    def test_trigger_failure_loop_3(self):
        trace = [
            {"success": False, "tool_output": "Connection refused"},
            {"success": False, "tool_output": "Error: timeout"},
            {"success": False, "tool_output": "Failed to connect"},
        ]
        reason = self._detect_trigger(iteration=5, just_transitioned=None, exec_trace=trace, need_deep_think=False)
        self.assertIn("Failure loop detected", reason)
        self.assertIn("3 consecutive failures", reason)

    def test_trigger_failure_loop_keyword_error(self):
        """success=True but output contains 'error' keyword."""
        trace = [
            {"success": True, "tool_output": "error: permission denied"},
            {"success": True, "tool_output": "Error occurred during scan"},
            {"success": True, "tool_output": "Command failed with error code 1"},
        ]
        reason = self._detect_trigger(iteration=5, just_transitioned=None, exec_trace=trace, need_deep_think=False)
        self.assertIn("Failure loop detected", reason)

    def test_trigger_failure_loop_broken_by_success(self):
        """2 failures then 1 success — should NOT trigger."""
        trace = [
            {"success": True, "tool_output": "Found open port 80"},
            {"success": False, "tool_output": "Failed"},
            {"success": False, "tool_output": "Failed"},
        ]
        reason = self._detect_trigger(iteration=5, just_transitioned=None, exec_trace=trace, need_deep_think=False)
        self.assertIsNone(reason)

    def test_trigger_self_request(self):
        """Condition 4: LLM self-requested deep think."""
        trace = [
            {"success": True, "tool_output": "Found some info"},
            {"success": True, "tool_output": "Scan complete"},
        ]
        reason = self._detect_trigger(iteration=5, just_transitioned=None, exec_trace=trace, need_deep_think=True)
        self.assertIn("Agent self-assessed stagnation", reason)

    def test_self_request_not_triggered_when_first_iteration(self):
        """Condition 1 takes priority over condition 4."""
        reason = self._detect_trigger(iteration=1, just_transitioned=None, exec_trace=[], need_deep_think=True)
        self.assertIn("First iteration", reason)
        self.assertNotIn("stagnation", reason)

    def test_self_request_not_triggered_when_phase_transition(self):
        """Condition 2 takes priority over condition 4."""
        reason = self._detect_trigger(iteration=5, just_transitioned="exploitation", exec_trace=[], need_deep_think=True)
        self.assertIn("Phase transition", reason)
        self.assertNotIn("stagnation", reason)

    def test_self_request_not_triggered_when_failure_loop(self):
        """Condition 3 takes priority over condition 4."""
        trace = [
            {"success": False, "tool_output": "error"},
            {"success": False, "tool_output": "error"},
            {"success": False, "tool_output": "error"},
        ]
        reason = self._detect_trigger(iteration=5, just_transitioned=None, exec_trace=trace, need_deep_think=True)
        self.assertIn("Failure loop", reason)
        self.assertNotIn("stagnation", reason)

    def test_no_trigger(self):
        """Normal operation — no trigger."""
        trace = [
            {"success": True, "tool_output": "Scan complete"},
            {"success": True, "tool_output": "Found services"},
        ]
        reason = self._detect_trigger(iteration=3, just_transitioned=None, exec_trace=trace, need_deep_think=False)
        self.assertIsNone(reason)

    def test_metasploit_no_session_trigger(self):
        """'exploit completed, but no session' counts as failure."""
        trace = [
            {"success": True, "tool_output": "Exploit completed, but no session was created"},
            {"success": True, "tool_output": "Exploit completed, but no session was created"},
            {"success": True, "tool_output": "Exploit completed, but no session was created"},
        ]
        reason = self._detect_trigger(iteration=5, just_transitioned=None, exec_trace=trace, need_deep_think=False)
        self.assertIn("Failure loop detected", reason)


class TestDeepThinkFormatting(unittest.TestCase):
    """Test the formatting of DeepThinkResult into markdown."""

    def test_format_as_markdown(self):
        """Verify the formatted output matches what think_node produces."""
        dt = DeepThinkResult(
            situation_assessment="Port 80 is open running Apache 2.4.49",
            attack_vectors_identified=["CVE-2021-41773", "CVE-2021-42013"],
            recommended_approach="Try path traversal RCE",
            priority_order=["CVE-2021-41773", "CVE-2021-42013", "brute force SSH"],
            risks_and_mitigations="Target may be patched"
        )
        # Same formatting as think_node.py
        formatted = (
            f"**Situation:** {dt.situation_assessment}\n\n"
            f"**Attack Vectors:** {', '.join(dt.attack_vectors_identified)}\n\n"
            f"**Approach:** {dt.recommended_approach}\n\n"
            f"**Priority:** {' → '.join(dt.priority_order)}\n\n"
            f"**Risks:** {dt.risks_and_mitigations}"
        )
        self.assertIn("**Situation:** Port 80 is open", formatted)
        self.assertIn("CVE-2021-41773, CVE-2021-42013", formatted)
        self.assertIn("CVE-2021-41773 → CVE-2021-42013 → brute force SSH", formatted)


if __name__ == "__main__":
    unittest.main()
