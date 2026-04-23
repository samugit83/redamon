"""Tests for chain context formatting — _group_trace_by_iteration and format_chain_context."""

import unittest

from state import (
    _group_trace_by_iteration,
    _dedup_findings,
    _severity_rank,
    format_chain_context,
)


# ---------------------------------------------------------------------------
# Helpers to build test data
# ---------------------------------------------------------------------------

def _tool(iteration, tool_name, *, phase="informational", success=True,
          args=None, thought="", reasoning="", output="", analysis="",
          error_message=None):
    """Build a single execution_trace entry."""
    return {
        "iteration": iteration,
        "phase": phase,
        "tool_name": tool_name,
        "tool_args": args or {},
        "success": success,
        "thought": thought,
        "reasoning": reasoning,
        "tool_output": output,
        "output_analysis": analysis,
        "error_message": error_message,
    }


def _finding(title, severity="info", step=1, finding_type="custom",
             evidence="", confidence=None, related_cves=None, related_ips=None):
    d = {
        "finding_type": finding_type,
        "severity": severity,
        "title": title,
        "step_iteration": step,
    }
    if evidence:
        d["evidence"] = evidence
    if confidence is not None:
        d["confidence"] = confidence
    if related_cves:
        d["related_cves"] = related_cves
    if related_ips:
        d["related_ips"] = related_ips
    return d


def _failure(step, error, lesson="", failure_type="tool_error"):
    return {
        "step_iteration": step,
        "failure_type": failure_type,
        "error_message": error,
        "lesson_learned": lesson,
    }


def _decision(step, from_s, to_s, approved=True, made_by="user"):
    return {
        "step_iteration": step,
        "decision_type": "phase_transition",
        "from_state": from_s,
        "to_state": to_s,
        "approved": approved,
        "made_by": made_by,
    }


# ===================================================================
# _group_trace_by_iteration
# ===================================================================

class TestGroupTraceByIteration(unittest.TestCase):

    def test_empty_trace(self):
        self.assertEqual(_group_trace_by_iteration([]), [])

    def test_single_tool(self):
        trace = [_tool(1, "execute_curl")]
        groups = _group_trace_by_iteration(trace)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["iteration"], 1)
        self.assertEqual(len(groups[0]["tools"]), 1)
        self.assertFalse(groups[0]["is_wave"])

    def test_wave_grouped(self):
        trace = [
            _tool(1, "execute_curl", analysis="shared"),
            _tool(1, "query_graph", analysis="shared"),
            _tool(1, "execute_nmap", analysis="shared"),
        ]
        groups = _group_trace_by_iteration(trace)
        self.assertEqual(len(groups), 1)
        self.assertEqual(len(groups[0]["tools"]), 3)
        self.assertTrue(groups[0]["is_wave"])

    def test_multiple_iterations_ordered(self):
        trace = [
            _tool(1, "query_graph"),
            _tool(1, "execute_curl"),
            _tool(2, "execute_curl"),
            _tool(3, "kali_shell"),
            _tool(3, "execute_curl"),
            _tool(3, "execute_curl"),
        ]
        groups = _group_trace_by_iteration(trace)
        self.assertEqual(len(groups), 3)
        self.assertEqual(groups[0]["iteration"], 1)
        self.assertEqual(groups[1]["iteration"], 2)
        self.assertEqual(groups[2]["iteration"], 3)
        self.assertTrue(groups[0]["is_wave"])   # 2 tools
        self.assertFalse(groups[1]["is_wave"])  # 1 tool
        self.assertTrue(groups[2]["is_wave"])   # 3 tools

    def test_phase_from_first_entry(self):
        trace = [
            _tool(1, "execute_curl", phase="exploitation"),
            _tool(1, "kali_shell", phase="informational"),  # different phase
        ]
        groups = _group_trace_by_iteration(trace)
        self.assertEqual(groups[0]["phase"], "exploitation")

    def test_analysis_from_first_entry(self):
        trace = [
            _tool(1, "a", analysis="first analysis"),
            _tool(1, "b", analysis="same but taken from first"),
        ]
        groups = _group_trace_by_iteration(trace)
        self.assertEqual(groups[0]["output_analysis"], "first analysis")

    def test_missing_iteration_defaults_to_zero(self):
        trace = [{"tool_name": "x", "phase": "info"}]
        groups = _group_trace_by_iteration(trace)
        self.assertEqual(groups[0]["iteration"], 0)


# ===================================================================
# format_chain_context — empty / minimal
# ===================================================================

class TestFormatChainContextEmpty(unittest.TestCase):

    def test_all_empty(self):
        result = format_chain_context([], [], [], [])
        self.assertEqual(result, "No steps executed yet.")

    def test_findings_only_no_trace(self):
        """Findings without execution_trace should still render."""
        result = format_chain_context(
            [_finding("Something found")], [], [], []
        )
        self.assertIn("Findings", result)
        self.assertIn("Something found", result)
        self.assertNotIn("Steps", result)

    def test_failures_only_no_trace(self):
        result = format_chain_context(
            [], [_failure(1, "timeout")], [], []
        )
        self.assertIn("Failed Attempts", result)
        self.assertIn("timeout", result)


# ===================================================================
# format_chain_context — findings / failures / decisions
# ===================================================================

class TestFormatChainContextSections(unittest.TestCase):

    def test_findings_rendered(self):
        findings = [
            _finding("Service found", severity="info", step=1),
            _finding("SQLi confirmed", severity="high", step=3),
        ]
        result = format_chain_context(findings, [], [], [_tool(1, "x")])
        self.assertIn("[INFO] Service found (step 1)", result)
        self.assertIn("[HIGH] SQLi confirmed (step 3)", result)

    def test_failures_with_lesson(self):
        failures = [_failure(2, "Connection refused", lesson="Use correct hostname")]
        result = format_chain_context([], failures, [], [_tool(1, "x")])
        self.assertIn("Connection refused", result)
        self.assertIn("Lesson: Use correct hostname", result)

    def test_decisions_rendered(self):
        decisions = [_decision(3, "informational", "exploitation")]
        result = format_chain_context([], [], decisions, [_tool(1, "x")])
        self.assertIn("Decisions", result)
        self.assertIn("informational", result)
        self.assertIn("exploitation", result)

    def test_finding_severity_defaults(self):
        result = format_chain_context(
            [{"title": "test", "step_iteration": 1}], [], [], [_tool(1, "x")]
        )
        self.assertIn("[INFO]", result)

    def test_finding_missing_title_uses_finding_type(self):
        result = format_chain_context(
            [{"finding_type": "vulnerability_confirmed", "step_iteration": 1}],
            [], [], [_tool(1, "x")]
        )
        self.assertIn("vulnerability_confirmed", result)


# ===================================================================
# format_chain_context — single tool steps
# ===================================================================

class TestFormatSingleTool(unittest.TestCase):

    def test_single_tool_format(self):
        trace = [_tool(1, "execute_curl", thought="Check homepage",
                       args={"args": "-s http://target/"},
                       analysis="Found Express server")]
        result = format_chain_context([], [], [], trace)
        self.assertIn("Step 1 [informational]: execute_curl", result)
        self.assertIn("Thought: Check homepage", result)
        self.assertIn("Args:", result)
        self.assertIn("OK | Found Express server", result)

    def test_single_tool_failed(self):
        trace = [_tool(1, "execute_nmap", success=False,
                       error_message="Host unreachable")]
        result = format_chain_context([], [], [], trace)
        self.assertIn("FAILED | Host unreachable", result)
        self.assertNotIn("OK", result)

    def test_single_tool_no_analysis_falls_back_to_output(self):
        trace = [_tool(1, "kali_shell", output="uid=0(root)", analysis="")]
        result = format_chain_context([], [], [], trace)
        self.assertIn("OK | uid=0(root)", result)

    def test_last_step_full_output(self):
        trace = [_tool(1, "kali_shell", output="full output here")]
        result = format_chain_context([], [], [], trace)
        self.assertIn("Output (last tool):", result)
        self.assertIn("full output here", result)

    def test_last_step_output_truncated(self):
        big_output = "X" * 6000
        trace = [_tool(1, "kali_shell", output=big_output, analysis="short")]
        result = format_chain_context([], [], [], trace)
        self.assertIn("...", result)
        # Output block should be truncated to 5000 chars
        output_section = result.split("Output (last tool):\n")[1]
        # The truncated output ends with "..." so strip that
        self.assertTrue(output_section.rstrip().endswith("..."))
        self.assertLessEqual(output_section.count("X"), 5000)


# ===================================================================
# format_chain_context — wave steps
# ===================================================================

class TestFormatWave(unittest.TestCase):

    def test_wave_header(self):
        trace = [
            _tool(1, "execute_curl", success=True),
            _tool(1, "execute_curl", success=True),
            _tool(1, "query_graph", success=True),
        ]
        result = format_chain_context([], [], [], trace)
        self.assertIn("Wave [2 execute_curl, 1 query_graph]", result)
        self.assertIn("(3 OK)", result)

    def test_wave_with_failures(self):
        trace = [
            _tool(1, "execute_curl", success=True),
            _tool(1, "execute_curl", success=False, error_message="timeout"),
            _tool(1, "kali_shell", success=True),
        ]
        result = format_chain_context([], [], [], trace)
        self.assertIn("2 OK, 1 FAILED", result)
        self.assertIn("FAILED | execute_curl: timeout", result)

    def test_wave_analysis_shown_once(self):
        shared_analysis = "All endpoints returned 200"
        trace = [
            _tool(1, "execute_curl", analysis=shared_analysis),
            _tool(1, "execute_curl", analysis=shared_analysis),
            _tool(1, "execute_curl", analysis=shared_analysis),
        ]
        result = format_chain_context([], [], [], trace)
        # Analysis should appear exactly once (not 3 times)
        self.assertEqual(result.count(shared_analysis), 1)

    def test_wave_rationale_from_reasoning(self):
        trace = [
            _tool(1, "execute_curl", reasoning="Testing endpoints",
                  thought="[Wave] curl test"),
            _tool(1, "kali_shell", reasoning="Testing endpoints"),
        ]
        result = format_chain_context([], [], [], trace)
        self.assertIn("Rationale: Testing endpoints", result)

    def test_wave_rationale_strips_wave_prefix(self):
        trace = [
            _tool(1, "execute_curl", reasoning="",
                  thought="[Wave] Check login endpoint"),
            _tool(1, "execute_curl", reasoning=""),
        ]
        result = format_chain_context([], [], [], trace)
        self.assertIn("Rationale: Check login endpoint", result)
        self.assertNotIn("[Wave]", result)

    def test_wave_tool_args_listed(self):
        trace = [
            _tool(1, "execute_curl", args={"args": "-s http://target/login"}),
            _tool(1, "execute_curl", args={"args": "-s http://target/users"}),
        ]
        result = format_chain_context([], [], [], trace)
        self.assertIn("Tools:", result)
        self.assertIn("- execute_curl:", result)
        self.assertIn("/login", result)
        self.assertIn("/users", result)

    def test_wave_last_iteration_gets_output(self):
        trace = [
            _tool(1, "execute_curl", output="step1_unique_output",
                  analysis="step1 analysis only"),
            _tool(2, "execute_curl", output="wave tool 1"),
            _tool(2, "kali_shell", output="wave_tool_2_unique_output"),
        ]
        result = format_chain_context([], [], [], trace)
        self.assertIn("Output (last tool):", result)
        self.assertIn("wave_tool_2_unique_output", result)
        # Only one "Output (last tool):" block should exist (for the last iteration)
        self.assertEqual(result.count("Output (last tool):"), 1)
        # step1's output should NOT appear in the Output block
        output_section = result.split("Output (last tool):")[1]
        self.assertNotIn("step1_unique_output", output_section)


# ===================================================================
# format_chain_context — iteration count header
# ===================================================================

class TestFormatHeader(unittest.TestCase):

    def test_header_all_shown(self):
        trace = [_tool(1, "a"), _tool(2, "b"), _tool(2, "c")]
        result = format_chain_context([], [], [], trace)
        self.assertIn("2 iterations, 3 tool calls", result)

    def test_header_truncated(self):
        # 25 iterations, limit=20
        trace = []
        for i in range(1, 26):
            trace.append(_tool(i, "execute_curl"))
        result = format_chain_context([], [], [], trace, recent_iterations=20)
        self.assertIn("last 20 of 25 iterations", result)
        self.assertIn("25 tool calls", result)


# ===================================================================
# format_chain_context — recent_iterations limit
# ===================================================================

class TestFormatRecentLimit(unittest.TestCase):

    def test_default_limit_is_20(self):
        """With 25 iterations, last 20 in recent detail, first 5 in summary tier."""
        trace = []
        for i in range(1, 26):
            trace.append(_tool(i, "execute_curl", analysis=f"analysis_iter_{i}_end"))
        result = format_chain_context([], [], [], trace)
        # First 5 iterations should appear in summary tier (not in recent steps detail)
        self.assertIn("Earlier Steps", result)
        self.assertIn("analysis_iter_1_end", result)
        self.assertIn("analysis_iter_5_end", result)
        # They should be in summary format (one-liner), not detailed format
        self.assertNotIn("Step 1 [informational]", result)
        self.assertNotIn("Step 5 [informational]", result)
        # Last iterations should be present in recent detail
        self.assertIn("analysis_iter_25_end", result)
        self.assertIn("Step 6 [informational]", result)
        self.assertIn("Step 25 [informational]", result)

    def test_wave_counts_as_one_iteration(self):
        """A wave of 5 tools = 1 iteration, not 5."""
        trace = [
            _tool(1, "a"),
            _tool(2, "b"), _tool(2, "c"), _tool(2, "d"), _tool(2, "e"), _tool(2, "f"),
            _tool(3, "g"),
        ]
        result = format_chain_context([], [], [], trace, recent_iterations=2)
        # Only last 2 iterations (2 and 3) shown
        self.assertIn("last 2 of 3 iterations", result)
        # Iteration 1 should NOT be in the steps section
        steps_section = result.split("iterations")[2] if result.count("iterations") > 1 else result
        self.assertNotIn("Step 1", steps_section)
        self.assertIn("Step 2", result)
        self.assertIn("Step 3", result)


# ===================================================================
# format_chain_context — real-world-like scenario
# ===================================================================

class TestFormatRealWorld(unittest.TestCase):

    def test_full_nosql_session(self):
        """Simulate the NQL-ZBIKC session structure."""
        trace = [
            # Iter 1: wave of 2 (recon)
            _tool(1, "query_graph", thought="[Wave] Check recon data",
                  reasoning="Recon first",
                  analysis="Target gpigs.devergolabs.com found"),
            _tool(1, "execute_curl", thought="[Wave] Probe homepage",
                  reasoning="Recon first",
                  analysis="Target gpigs.devergolabs.com found"),
            # Iter 2: wave of 3 (endpoint enum)
            _tool(2, "execute_curl", thought="[Wave] Check /api/v2/",
                  analysis="Express API confirmed on port 80"),
            _tool(2, "execute_curl", thought="[Wave] Check root",
                  analysis="Express API confirmed on port 80"),
            _tool(2, "query_graph", thought="[Wave] Get endpoints",
                  analysis="Express API confirmed on port 80"),
            # Iter 3: wave of 5 (endpoint probing)
            _tool(3, "execute_curl", thought="[Wave] Check login",
                  analysis="Login at /api/v2/login, test/test works",
                  args={"args": "-s http://target/api/v2/login"}),
            _tool(3, "execute_curl", thought="[Wave] POST login",
                  analysis="Login at /api/v2/login, test/test works",
                  args={"args": "-X POST ... test/test"}),
            _tool(3, "execute_curl", thought="[Wave] Check users",
                  analysis="Login at /api/v2/login, test/test works",
                  args={"args": "-s http://target/api/v2/users"}),
            _tool(3, "execute_curl", thought="[Wave] Check notes",
                  analysis="Login at /api/v2/login, test/test works",
                  args={"args": "-s http://target/api/v2/notes"}),
            _tool(3, "execute_curl", thought="[Wave] Check notesearch",
                  analysis="Login at /api/v2/login, test/test works",
                  args={"args": "-s http://target/api/v2/notesearch"}),
            # Iter 4: wave of 4 (NoSQL injection)
            _tool(4, "execute_curl", thought="[Wave] $ne on both fields",
                  analysis="All 4 returned 500 - bcrypt crashes on operator objects",
                  args={"args": '-d \'{"username":{"$ne":""},...}\''}),
            _tool(4, "execute_curl", thought="[Wave] $gt on both",
                  analysis="All 4 returned 500 - bcrypt crashes on operator objects",
                  args={"args": '-d \'{"username":{"$gt":""},...}\''}),
            _tool(4, "execute_curl", thought="[Wave] admin + $ne password",
                  analysis="All 4 returned 500 - bcrypt crashes on operator objects",
                  args={"args": '-d \'{"username":"admin",...}\''}),
            _tool(4, "execute_curl", thought="[Wave] $regex username",
                  analysis="All 4 returned 500 - bcrypt crashes on operator objects",
                  args={"args": '-d \'{"username":{"$regex":"^a"},...}\''}),
            # Iter 5: wave of 5 (pivot - username injection + data extraction)
            _tool(5, "execute_curl", thought="[Wave] $ne username + string password",
                  analysis="Pivot successful - operators on username work",
                  args={"args": '-d \'{"username":{"$ne":""},"password":"test"}\''}),
            _tool(5, "execute_curl", thought="[Wave] $gt username",
                  analysis="Pivot successful - operators on username work",
                  args={"args": '-d \'{"username":{"$gt":""},"password":"test"}\''}),
            _tool(5, "execute_curl", thought="[Wave] $regex .* + test",
                  analysis="Pivot successful - operators on username work",
                  args={"args": '-d \'{"username":{"$regex":".*"},...}\''}),
            _tool(5, "execute_curl", thought="[Wave] $regex ^admin + test",
                  analysis="Pivot successful - operators on username work",
                  args={"args": '-d \'{"username":{"$regex":"^admin"},...}\''}),
            _tool(5, "kali_shell", thought="[Wave] Get JWT + dump users",
                  analysis="Pivot successful - operators on username work",
                  output='TOKEN: eyJhbG...\n{"status":200,"result":[{"username":"admin","password":"$2b$10$..."}]}'),
        ]

        findings = [
            _finding("Multiple services identified", step=1),
            _finding("Express REST API confirmed", step=2),
            _finding("Password hash disclosure", severity="high", step=3),
            _finding("NoSQL operators processed without sanitization", severity="high", step=4),
        ]

        result = format_chain_context(findings, [], [], trace)

        # Header should show iterations, not individual tools
        self.assertIn("5 iterations, 19 tool calls", result)

        # All 5 iterations should be present
        self.assertIn("Step 1", result)
        self.assertIn("Step 2", result)
        self.assertIn("Step 3", result)
        self.assertIn("Step 4", result)
        self.assertIn("Step 5", result)

        # Waves should show tool counts
        self.assertIn("Wave [1 query_graph, 1 execute_curl]", result)
        self.assertIn("Wave [5 execute_curl]", result)
        self.assertIn("Wave [4 execute_curl]", result)
        self.assertIn("Wave [4 execute_curl, 1 kali_shell]", result)

        # Analysis should appear once per wave, not per tool
        self.assertEqual(
            result.count("All 4 returned 500 - bcrypt crashes on operator objects"), 1
        )
        self.assertEqual(
            result.count("Pivot successful - operators on username work"), 1
        )

        # Last iteration should have full output
        self.assertIn("Output (last tool):", result)
        self.assertIn("TOKEN: eyJhbG", result)

        # Findings section
        self.assertIn("[HIGH] Password hash disclosure", result)
        self.assertIn("[HIGH] NoSQL operators processed", result)

    def test_mixed_single_and_wave(self):
        """Mix of single tool steps and waves."""
        trace = [
            _tool(1, "query_graph", analysis="Recon done"),
            _tool(2, "execute_curl", analysis="Login found"),
            _tool(2, "execute_curl", analysis="Login found"),
            _tool(3, "kali_shell", analysis="Hash cracked",
                  output="letmein"),
        ]
        result = format_chain_context([], [], [], trace)

        # Step 1: single tool
        self.assertIn("Step 1 [informational]: query_graph", result)
        # Step 2: wave
        self.assertIn("Step 2 [informational] Wave [2 execute_curl]", result)
        # Step 3: single tool
        self.assertIn("Step 3 [informational]: kali_shell", result)
        # Last output
        self.assertIn("Output (last tool):", result)
        self.assertIn("letmein", result)


# ===================================================================
# Edge cases
# ===================================================================

class TestEdgeCases(unittest.TestCase):

    def test_tool_with_no_args(self):
        trace = [_tool(1, "query_graph", args={})]
        result = format_chain_context([], [], [], trace)
        self.assertNotIn("Args:", result)

    def test_wave_all_failures(self):
        trace = [
            _tool(1, "execute_curl", success=False, error_message="timeout"),
            _tool(1, "execute_curl", success=False, error_message="refused"),
        ]
        result = format_chain_context([], [], [], trace)
        self.assertIn("0 OK, 2 FAILED", result)
        self.assertIn("FAILED | execute_curl: timeout", result)
        self.assertIn("FAILED | execute_curl: refused", result)

    def test_empty_tool_name_single(self):
        trace = [{"iteration": 1, "phase": "info", "tool_name": None, "success": True}]
        result = format_chain_context([], [], [], trace)
        self.assertIn("none", result)  # single tool path uses "none"

    def test_empty_tool_name_wave(self):
        trace = [
            {"iteration": 1, "phase": "info", "tool_name": None, "success": True},
            {"iteration": 1, "phase": "info", "tool_name": None, "success": True},
        ]
        result = format_chain_context([], [], [], trace)
        self.assertIn("unknown", result)  # wave path uses "unknown"

    def test_no_wave_prefix_in_thought(self):
        trace = [
            _tool(1, "a", thought="Regular thought no prefix"),
            _tool(1, "b", thought="Another thought"),
        ]
        result = format_chain_context([], [], [], trace)
        self.assertIn("Rationale: Regular thought no prefix", result)

    def test_args_truncation(self):
        long_args = {"args": "A" * 500}
        trace = [_tool(1, "execute_curl", args=long_args)]
        result = format_chain_context([], [], [], trace)
        # Args should be truncated to 300 chars
        args_line = [l for l in result.split("\n") if "Args:" in l][0]
        self.assertLessEqual(len(args_line), 350)  # 300 + prefix

    def test_wave_args_truncation(self):
        long_args = {"args": "B" * 500}
        trace = [
            _tool(1, "execute_curl", args=long_args),
            _tool(1, "execute_curl", args=long_args),
        ]
        result = format_chain_context([], [], [], trace)
        tool_lines = [l for l in result.split("\n") if "- execute_curl:" in l]
        for line in tool_lines:
            self.assertLessEqual(len(line), 350)  # 300 + prefix


# ===================================================================
# _severity_rank and _dedup_findings
# ===================================================================

class TestSeverityRank(unittest.TestCase):

    def test_ordering(self):
        self.assertLess(_severity_rank("critical"), _severity_rank("high"))
        self.assertLess(_severity_rank("high"), _severity_rank("medium"))
        self.assertLess(_severity_rank("medium"), _severity_rank("low"))
        self.assertLess(_severity_rank("low"), _severity_rank("info"))

    def test_case_insensitive(self):
        self.assertEqual(_severity_rank("CRITICAL"), _severity_rank("critical"))
        self.assertEqual(_severity_rank("High"), _severity_rank("high"))

    def test_none_defaults_to_info(self):
        self.assertEqual(_severity_rank(None), _severity_rank("info"))

    def test_unknown_defaults_to_info(self):
        self.assertEqual(_severity_rank("banana"), _severity_rank("info"))


class TestDedupFindings(unittest.TestCase):

    def test_no_duplicates_unchanged(self):
        findings = [
            _finding("Finding A", severity="high"),
            _finding("Finding B", severity="info"),
        ]
        result = _dedup_findings(findings)
        self.assertEqual(len(result), 2)

    def test_exact_duplicate_removed(self):
        findings = [
            _finding("Password hash leaked", severity="high", step=5),
            _finding("Password hash leaked", severity="high", step=7),
        ]
        result = _dedup_findings(findings)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["step_iteration"], 5)  # keeps earliest

    def test_case_insensitive_dedup(self):
        findings = [
            _finding("SQL Injection Found", severity="high"),
            _finding("sql injection found", severity="medium"),
        ]
        result = _dedup_findings(findings)
        self.assertEqual(len(result), 1)

    def test_severity_upgraded_from_later_duplicate(self):
        findings = [
            _finding("Vuln found", severity="medium", step=1),
            _finding("Vuln found", severity="high", step=5),
        ]
        result = _dedup_findings(findings)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["severity"], "high")  # upgraded
        self.assertEqual(result[0]["step_iteration"], 1)  # still earliest

    def test_confidence_upgraded_from_later_duplicate(self):
        findings = [
            _finding("Vuln found", confidence=60, step=1),
            _finding("Vuln found", confidence=90, step=5),
        ]
        result = _dedup_findings(findings)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["confidence"], 90)  # upgraded

    def test_empty_title_uses_finding_type(self):
        findings = [
            {"finding_type": "vulnerability_confirmed", "severity": "high", "step_iteration": 1},
            {"finding_type": "vulnerability_confirmed", "severity": "high", "step_iteration": 3},
        ]
        result = _dedup_findings(findings)
        self.assertEqual(len(result), 1)  # deduped by finding_type fallback


# ===================================================================
# format_chain_context — enriched findings
# ===================================================================

class TestEnrichedFindings(unittest.TestCase):

    def test_severity_sorting(self):
        findings = [
            _finding("Info thing", severity="info", step=1),
            _finding("Critical vuln", severity="critical", step=3),
            _finding("Medium issue", severity="medium", step=2),
        ]
        result = format_chain_context(findings, [], [], [_tool(1, "x")])
        # Critical should appear before medium, medium before info
        crit_pos = result.index("Critical vuln")
        med_pos = result.index("Medium issue")
        info_pos = result.index("Info thing")
        self.assertLess(crit_pos, med_pos)
        self.assertLess(med_pos, info_pos)

    def test_confidence_shown(self):
        findings = [_finding("Test finding", confidence=95, step=1)]
        result = format_chain_context(findings, [], [], [_tool(1, "x")])
        self.assertIn("95%", result)

    def test_confidence_zero_shown(self):
        findings = [_finding("Test finding", confidence=0, step=1)]
        result = format_chain_context(findings, [], [], [_tool(1, "x")])
        self.assertIn("0%", result)

    def test_confidence_none_not_shown(self):
        findings = [_finding("Test finding", step=1)]
        result = format_chain_context(findings, [], [], [_tool(1, "x")])
        self.assertNotIn("%", result)

    def test_evidence_shown(self):
        findings = [_finding("SQLi found", evidence="Parameter id is injectable", step=1)]
        result = format_chain_context(findings, [], [], [_tool(1, "x")])
        self.assertIn("Evidence: Parameter id is injectable", result)

    def test_evidence_truncated(self):
        findings = [_finding("SQLi found", evidence="X" * 200, step=1)]
        result = format_chain_context(findings, [], [], [_tool(1, "x")])
        evidence_line = [l for l in result.split("\n") if "Evidence:" in l][0]
        # Should be truncated to 150 + prefix
        self.assertLessEqual(len(evidence_line.strip()) - len("Evidence: "), 150)

    def test_empty_evidence_not_shown(self):
        findings = [_finding("Test", evidence="", step=1)]
        result = format_chain_context(findings, [], [], [_tool(1, "x")])
        self.assertNotIn("Evidence:", result)

    def test_cves_shown(self):
        findings = [_finding("RCE", related_cves=["CVE-2021-41773", "CVE-2023-1234"], step=1)]
        result = format_chain_context(findings, [], [], [_tool(1, "x")])
        self.assertIn("CVEs: CVE-2021-41773, CVE-2023-1234", result)

    def test_ips_shown(self):
        findings = [_finding("Service found", related_ips=["10.10.10.5"], step=1)]
        result = format_chain_context(findings, [], [], [_tool(1, "x")])
        self.assertIn("IPs: 10.10.10.5", result)

    def test_cves_and_ips_combined(self):
        findings = [_finding("RCE", related_cves=["CVE-2021-41773"],
                             related_ips=["10.10.10.5"], step=1)]
        result = format_chain_context(findings, [], [], [_tool(1, "x")])
        self.assertIn("CVEs: CVE-2021-41773 | IPs: 10.10.10.5", result)

    def test_no_cves_no_ips_no_meta_line(self):
        findings = [_finding("Plain finding", step=1)]
        result = format_chain_context(findings, [], [], [_tool(1, "x")])
        self.assertNotIn("CVEs:", result)
        self.assertNotIn("IPs:", result)

    def test_duplicates_removed_in_output(self):
        findings = [
            _finding("Password hash leaked", severity="high", step=5),
            _finding("Password hash leaked", severity="high", step=7),
        ]
        result = format_chain_context(findings, [], [], [_tool(1, "x")])
        self.assertEqual(result.count("Password hash leaked"), 1)


# ===================================================================
# format_chain_context — summary tier
# ===================================================================

class TestSummaryTier(unittest.TestCase):

    def test_summary_appears_when_over_limit(self):
        """With 25 iterations and limit=20, first 5 should appear in summary."""
        trace = [_tool(i, "execute_curl", analysis=f"analysis_{i}") for i in range(1, 26)]
        result = format_chain_context([], [], [], trace, recent_iterations=20)
        self.assertIn("Earlier Steps", result)
        self.assertIn("1 [info]: execute_curl -> analysis_1", result)
        self.assertIn("5 [info]: execute_curl -> analysis_5", result)

    def test_summary_not_shown_when_under_limit(self):
        """With 10 iterations and limit=20, no summary tier."""
        trace = [_tool(i, "execute_curl") for i in range(1, 11)]
        result = format_chain_context([], [], [], trace, recent_iterations=20)
        self.assertNotIn("Earlier Steps", result)

    def test_summary_wave_format(self):
        """Waves in summary tier show tool counts."""
        trace = [
            _tool(1, "execute_curl", analysis="shared analysis"),
            _tool(1, "kali_shell", analysis="shared analysis"),
        ]
        # Add enough iterations to push iter 1 into summary
        for i in range(2, 25):
            trace.append(_tool(i, "execute_curl", analysis=f"a_{i}"))
        result = format_chain_context([], [], [], trace, recent_iterations=20)
        self.assertIn("Earlier Steps", result)
        self.assertIn("Wave[1 execute_curl, 1 kali_shell]", result)

    def test_summary_failed_marker(self):
        """Failed steps in summary tier show FAILED marker."""
        trace = [_tool(1, "execute_nmap", success=False, analysis="Host down")]
        for i in range(2, 25):
            trace.append(_tool(i, "execute_curl", analysis=f"a_{i}"))
        result = format_chain_context([], [], [], trace, recent_iterations=20)
        self.assertIn("FAILED |", result)
        self.assertIn("Host down", result)

    def test_summary_success_no_failed_marker(self):
        """Successful steps in summary tier don't show FAILED marker."""
        trace = [_tool(1, "execute_curl", success=True, analysis="All good")]
        for i in range(2, 25):
            trace.append(_tool(i, "execute_curl", analysis=f"a_{i}"))
        result = format_chain_context([], [], [], trace, recent_iterations=20)
        summary_section = result.split("Recent Steps")[0]
        self.assertNotIn("FAILED |", summary_section)

    def test_summary_max_50_with_omit_message(self):
        """More than 50 old iterations: oldest are omitted with message."""
        trace = [_tool(i, "execute_curl", analysis=f"analysis_unique_{i}_end") for i in range(1, 80)]
        result = format_chain_context([], [], [], trace, recent_iterations=20)
        # 79 total, 20 recent, 59 older. summary_max=50, so 9 omitted.
        self.assertIn("omitted", result)
        self.assertIn("findings preserved above", result)
        # Iteration 1 should NOT be in summary (omitted) - use unique suffix to avoid substring match
        self.assertNotIn("analysis_unique_1_end", result)
        self.assertNotIn("analysis_unique_9_end", result)
        # Iteration 10 should be in summary (within the 50 window)
        self.assertIn("analysis_unique_10_end", result)

    def test_summary_analysis_truncated_to_100(self):
        """Summary tier truncates analysis to 100 chars."""
        long_analysis = "A" * 200
        trace = [_tool(1, "execute_curl", analysis=long_analysis)]
        for i in range(2, 25):
            trace.append(_tool(i, "execute_curl", analysis=f"a_{i}"))
        result = format_chain_context([], [], [], trace, recent_iterations=20)
        summary_lines = [l for l in result.split("\n") if "1 [info]:" in l]
        self.assertEqual(len(summary_lines), 1)
        # The line should contain at most 100 A's
        self.assertLessEqual(summary_lines[0].count("A"), 100)

    def test_summary_phase_abbreviations(self):
        """Summary tier uses abbreviated phase names."""
        trace = [
            _tool(1, "x", phase="informational", analysis="a"),
            _tool(2, "x", phase="exploitation", analysis="b"),
            _tool(3, "x", phase="post_exploitation", analysis="c"),
        ]
        for i in range(4, 26):
            trace.append(_tool(i, "execute_curl", analysis=f"a_{i}"))
        result = format_chain_context([], [], [], trace, recent_iterations=20)
        self.assertIn("[info]", result)
        self.assertIn("[exploit]", result)
        self.assertIn("[post-ex]", result)


if __name__ == "__main__":
    unittest.main()
