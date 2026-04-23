"""
Unit tests for execute_arjun MCP tool.

Tests the tool function directly with mocked subprocess calls.
No real arjun binary or network access required.

Run with: python -m pytest mcp/servers/test_arjun_tool.py -v
"""

import json
import os
import subprocess
import sys
import tempfile
from unittest import mock

import pytest

# Add servers dir to path so we can import the module
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Stub out fastmcp (only available inside Docker container).
# The @mcp.tool() decorator must be a no-op passthrough so the real
# function is importable for testing.
class _FakeMCP:
    def __init__(self, *a, **kw):
        pass
    def tool(self, *a, **kw):
        """Return identity decorator so decorated functions stay callable."""
        def _identity(fn):
            return fn
        return _identity
    def __getattr__(self, name):
        return mock.MagicMock()

_fastmcp_mod = mock.MagicMock()
_fastmcp_mod.FastMCP = _FakeMCP
sys.modules["fastmcp"] = _fastmcp_mod

# Force fresh import (clear any cached version)
sys.modules.pop("network_recon_server", None)
from network_recon_server import execute_arjun


# ---------------------------------------------------------------------------
# Helper: build a mock subprocess.CompletedProcess
# ---------------------------------------------------------------------------
def _mock_result(stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(
        args=["arjun"], returncode=returncode, stdout=stdout, stderr=stderr
    )


# ===========================================================================
# Basic execution tests
# ===========================================================================

class TestExecuteArjunBasic:
    """Tests for argument parsing, subprocess invocation, and output handling."""

    @mock.patch("network_recon_server.subprocess.run")
    def test_basic_invocation(self, mock_run):
        """Tool passes args correctly to subprocess."""
        mock_run.return_value = _mock_result(stdout="[~] Probing...\n")
        result = execute_arjun("-u http://10.0.0.5/api")
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert cmd == ["arjun", "-u", "http://10.0.0.5/api"]

    @mock.patch("network_recon_server.subprocess.run")
    def test_timeout_is_300s(self, mock_run):
        """Tool uses 300s timeout."""
        mock_run.return_value = _mock_result()
        execute_arjun("-u http://target")
        assert mock_run.call_args[1]["timeout"] == 300

    @mock.patch("network_recon_server.subprocess.run")
    def test_complex_args_parsed(self, mock_run):
        """Multi-flag arguments are parsed correctly via shlex."""
        mock_run.return_value = _mock_result(stdout="done\n")
        execute_arjun("-u http://10.0.0.5/ -m POST --rate-limit 10 --stable")
        cmd = mock_run.call_args[0][0]
        assert cmd == [
            "arjun", "-u", "http://10.0.0.5/", "-m", "POST",
            "--rate-limit", "10", "--stable"
        ]

    @mock.patch("network_recon_server.subprocess.run")
    def test_no_output_returns_info(self, mock_run):
        """Empty stdout+stderr returns informational message."""
        mock_run.return_value = _mock_result(stdout="", stderr="")
        result = execute_arjun("-u http://target")
        assert result == "[INFO] No parameters discovered."

    @mock.patch("network_recon_server.subprocess.run")
    def test_stdout_returned(self, mock_run):
        """Normal stdout is returned."""
        mock_run.return_value = _mock_result(
            stdout="[~] Probing http://target\n[+] Found: id, debug\n"
        )
        result = execute_arjun("-u http://target")
        assert "[+] Found: id, debug" in result


# ===========================================================================
# ANSI stripping tests
# ===========================================================================

class TestAnsiStripping:
    """Verify ANSI escape codes are stripped from output."""

    @mock.patch("network_recon_server.subprocess.run")
    def test_ansi_codes_stripped_from_stdout(self, mock_run):
        """ANSI color codes in stdout are removed."""
        mock_run.return_value = _mock_result(
            stdout="\x1b[32m[+] Found params\x1b[0m\n"
        )
        result = execute_arjun("-u http://target")
        assert "\x1b[" not in result
        assert "[+] Found params" in result

    @mock.patch("network_recon_server.subprocess.run")
    def test_ansi_codes_stripped_from_stderr(self, mock_run):
        """ANSI color codes in stderr are removed."""
        mock_run.return_value = _mock_result(
            stdout="ok\n",
            stderr="\x1b[31m[ERROR] Connection refused\x1b[0m\n"
        )
        result = execute_arjun("-u http://target")
        assert "\x1b[" not in result
        assert "Connection refused" in result


# ===========================================================================
# Stderr filtering tests
# ===========================================================================

class TestStderrFiltering:
    """Verify progress lines ([*]) are filtered, errors are kept."""

    @mock.patch("network_recon_server.subprocess.run")
    def test_progress_lines_filtered(self, mock_run):
        """Lines starting with [*] are filtered out of stderr."""
        mock_run.return_value = _mock_result(
            stdout="",
            stderr="[*] Probing...\n[*] Testing 25000 params\n[ERROR] timeout\n"
        )
        result = execute_arjun("-u http://target")
        assert "[*] Probing" not in result
        assert "[*] Testing" not in result
        assert "[ERROR] timeout" in result

    @mock.patch("network_recon_server.subprocess.run")
    def test_only_progress_lines_no_stderr_section(self, mock_run):
        """If stderr has only [*] lines, no [STDERR] section appears."""
        mock_run.return_value = _mock_result(
            stdout="done\n",
            stderr="[*] Probing...\n[*] Done\n"
        )
        result = execute_arjun("-u http://target")
        assert "[STDERR]" not in result


# ===========================================================================
# JSON output auto-read tests
# ===========================================================================

class TestJsonAutoRead:
    """Verify the -oJ flag triggers automatic file reading."""

    @mock.patch("network_recon_server.subprocess.run")
    def test_json_output_read(self, mock_run):
        """When -oJ is used, the JSON file is read and appended."""
        json_data = {
            "http://10.0.0.5/api/users": {
                "method": "GET",
                "params": ["id", "debug", "admin"]
            }
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(json_data, f)
            json_path = f.name

        try:
            mock_run.return_value = _mock_result(
                stdout="[~] Probing target\n",
                stderr="[*] Testing params\n"
            )
            result = execute_arjun(f"-u http://10.0.0.5/api/users -oJ {json_path}")
            assert "[JSON RESULTS]" in result
            assert '"debug"' in result
            assert '"admin"' in result
        finally:
            os.unlink(json_path)

    @mock.patch("network_recon_server.subprocess.run")
    def test_json_file_not_found(self, mock_run):
        """When -oJ file doesn't exist, show info message."""
        mock_run.return_value = _mock_result(stdout="done\n")
        result = execute_arjun("-u http://target -oJ /tmp/nonexistent_arjun_test.json")
        assert "No JSON output file generated" in result

    @mock.patch("network_recon_server.subprocess.run")
    def test_json_empty_file(self, mock_run):
        """When -oJ file is empty, no JSON RESULTS section."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            f.write("")
            json_path = f.name

        try:
            mock_run.return_value = _mock_result(stdout="done\n")
            result = execute_arjun(f"-u http://target -oJ {json_path}")
            assert "[JSON RESULTS]" not in result
        finally:
            os.unlink(json_path)

    @mock.patch("network_recon_server.subprocess.run")
    def test_no_oj_flag_no_file_read(self, mock_run):
        """Without -oJ, no file reading is attempted."""
        mock_run.return_value = _mock_result(stdout="[+] Found: id\n")
        result = execute_arjun("-u http://target")
        assert "[JSON RESULTS]" not in result
        assert "[+] Found: id" in result


# ===========================================================================
# Error handling tests
# ===========================================================================

class TestErrorHandling:
    """Tests for timeout, missing binary, and generic errors."""

    @mock.patch("network_recon_server.subprocess.run")
    def test_timeout_error(self, mock_run):
        """TimeoutExpired returns proper error message."""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="arjun", timeout=300)
        result = execute_arjun("-u http://target")
        assert "[ERROR]" in result
        assert "300 seconds" in result

    @mock.patch("network_recon_server.subprocess.run")
    def test_binary_not_found(self, mock_run):
        """FileNotFoundError returns proper error message."""
        mock_run.side_effect = FileNotFoundError()
        result = execute_arjun("-u http://target")
        assert "[ERROR]" in result
        assert "arjun not found" in result

    @mock.patch("network_recon_server.subprocess.run")
    def test_generic_exception(self, mock_run):
        """Unexpected exceptions are caught and returned as errors."""
        mock_run.side_effect = RuntimeError("something broke")
        result = execute_arjun("-u http://target")
        assert "[ERROR]" in result
        assert "something broke" in result


# ===========================================================================
# Integration with project_settings / tool_registry consistency
# ===========================================================================

class TestRegistrationConsistency:
    """Verify execute_arjun is registered consistently across all layers."""

    def test_in_tool_registry(self):
        """execute_arjun is in TOOL_REGISTRY."""
        agentic_dir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..", "..", "agentic"
        )
        sys.path.insert(0, agentic_dir)
        from prompts.tool_registry import TOOL_REGISTRY
        assert "execute_arjun" in TOOL_REGISTRY
        entry = TOOL_REGISTRY["execute_arjun"]
        assert "purpose" in entry
        assert "args_format" in entry
        assert "description" in entry

    def test_in_dangerous_tools(self):
        """execute_arjun is in DANGEROUS_TOOLS."""
        agentic_dir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..", "..", "agentic"
        )
        sys.path.insert(0, agentic_dir)
        from project_settings import DANGEROUS_TOOLS
        assert "execute_arjun" in DANGEROUS_TOOLS

    def test_in_tool_phase_map(self):
        """execute_arjun is in DEFAULT_AGENT_SETTINGS TOOL_PHASE_MAP."""
        agentic_dir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..", "..", "agentic"
        )
        sys.path.insert(0, agentic_dir)
        from project_settings import DEFAULT_AGENT_SETTINGS
        phase_map = DEFAULT_AGENT_SETTINGS["TOOL_PHASE_MAP"]
        assert "execute_arjun" in phase_map
        assert phase_map["execute_arjun"] == ["informational", "exploitation"]

    def test_in_stealth_rules(self):
        """execute_arjun has a stealth constraint defined."""
        agentic_dir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..", "..", "agentic"
        )
        sys.path.insert(0, agentic_dir)
        from prompts.stealth_rules import STEALTH_MODE_RULES
        assert "execute_arjun" in STEALTH_MODE_RULES
        assert "FORBIDDEN" in STEALTH_MODE_RULES
