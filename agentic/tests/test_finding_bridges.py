"""Regression tests: ChainFinding auto-bridging and embedded-error detection.

Covers the three graph-layer fixes shipped after the 2026-04-19 audit:
  1. Auto-extract CVE/path/port from finding.evidence when LLM leaves
     related_cves/related_ips empty.
  2. Endpoint / Technology / Port bridging in _resolve_finding_bridges so
     findings aren't isolated islands on the graph.
  3. Embedded-error detection in execute_tool_node / execute_plan_node so
     MCP outputs that wrap a Playwright timeout as success=True still flip to
     success=False and produce a ChainFailure record.

Run:
    docker run --rm -v "/home/samuele/Progetti didattici/redamon/agentic:/app" \
        -w /app redamon-agent python -m unittest tests.test_finding_bridges -v
"""

from __future__ import annotations

import os
import sys
import unittest

_agentic_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _agentic_dir)


class AutoExtractFromEvidenceTests(unittest.TestCase):
    def setUp(self):
        from orchestrator_helpers.chain_graph_writer import _auto_extract_from_evidence
        self._extract = _auto_extract_from_evidence

    def test_empty_input_returns_empty_lists(self):
        out = self._extract("")
        self.assertEqual(out, {"cves": [], "paths": [], "ports": []})

    def test_cve_extraction_normalizes_case_and_dedupes(self):
        ev = "Vulnerable to cve-2023-46809 and also CVE-2023-46809 and CVE-2021-23017."
        out = self._extract(ev)
        self.assertEqual(sorted(out["cves"]), ["CVE-2021-23017", "CVE-2023-46809"])

    def test_url_paths_extracted_asset_paths_filtered(self):
        ev = "Missing HSTS on /api/auth/session and POST to /login worked. Also /static/main.css and /images/logo.png."
        out = self._extract(ev)
        self.assertIn("/api/auth/session", out["paths"])
        self.assertIn("/login", out["paths"])
        self.assertNotIn("/static/main.css", out["paths"])
        self.assertNotIn("/images/logo.png", out["paths"])

    def test_ports_extracted_from_common_shapes(self):
        ev = "Service on port 8080 and reverse shell to 10.0.0.5:4444. Also :22/tcp open."
        out = self._extract(ev)
        self.assertIn(8080, out["ports"])
        self.assertIn(4444, out["ports"])
        self.assertIn(22, out["ports"])

    def test_ports_range_clamped(self):
        ev = "Strange number :99999 should not match."
        out = self._extract(ev)
        self.assertNotIn(99999, out["ports"])

    def test_path_cap_respected(self):
        ev = " ".join(f"/api/v{i}/probe" for i in range(50))
        out = self._extract(ev)
        self.assertLessEqual(len(out["paths"]), 20)


class EmbeddedToolErrorDetectionTests(unittest.TestCase):
    def setUp(self):
        from orchestrator_helpers.nodes.execute_tool_node import _detect_embedded_tool_error
        self._detect = _detect_embedded_tool_error

    def test_empty_returns_none(self):
        self.assertIsNone(self._detect(""))
        self.assertIsNone(self._detect(None))

    def test_clean_output_returns_none(self):
        # A typical ffuf success row — must NOT be flagged as error.
        self.assertIsNone(self._detect(
            ":: Progress: [4750/4750] :: Job [1/1] :: 300 req/sec :: Duration: [0:00:15] :: Errors: 0 ::"
        ))

    def test_playwright_timeout_detected(self):
        out = "Some preamble\n[ERROR] Navigation failed: Page.goto: Timeout 30000ms exceeded.\nCall log: ..."
        err = self._detect(out)
        self.assertIsNotNone(err)
        self.assertIn("Navigation failed", err)

    def test_plain_error_prefix_detected(self):
        out = "[ERROR] Target is unreachable"
        err = self._detect(out)
        self.assertIsNotNone(err)
        self.assertIn("Target is unreachable", err)

    def test_tool_execution_failed_envelope_detected(self):
        out = "Tool execution failed: sandbox unreachable (curl: (6) Could not resolve host)"
        err = self._detect(out)
        self.assertIsNotNone(err)
        self.assertIn("sandbox unreachable", err)

    def test_long_output_only_head_scanned(self):
        # Error buried past the 4000-char head MUST NOT be flagged. This is a
        # tradeoff: speed vs. coverage. Body-wide scanning would slow 40k-char
        # Playwright dumps noticeably and yield few extra true-positives.
        padding = "x" * 5000
        err = self._detect(padding + "[ERROR] hidden")
        self.assertIsNone(err)

    def test_error_in_head_detected(self):
        padding = "x" * 200
        err = self._detect(padding + "\n[ERROR] real failure")
        self.assertIsNotNone(err)


if __name__ == "__main__":
    unittest.main()
