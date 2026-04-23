"""
Unit tests for httpx agentic integration -- MCP tool function, tool registry,
project settings, stealth rules, and cross-layer consistency.

Run with: python -m pytest tests/test_httpx_integration.py -v
"""

import json
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

# Add parent dir to path so we can import from agentic modules
_agentic_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _agentic_dir)

# Add MCP servers dir to path for importing execute_httpx
_mcp_servers_dir = os.path.join(
    os.path.dirname(_agentic_dir), 'mcp', 'servers'
)
sys.path.insert(0, _mcp_servers_dir)

# Stub out heavy dependencies not available outside Docker
_stubs = {}
_stub_modules = [
    'langchain_core', 'langchain_core.tools', 'langchain_core.messages',
    'langchain_core.language_models', 'langchain_core.runnables',
    'langchain_mcp_adapters', 'langchain_mcp_adapters.client',
    'langchain_neo4j',
    'langgraph', 'langgraph.graph', 'langgraph.graph.message',
    'langgraph.graph.state', 'langgraph.checkpoint',
    'langgraph.checkpoint.memory',
    'langchain_openai', 'langchain_openai.chat_models',
    'langchain_openai.chat_models.azure', 'langchain_openai.chat_models.base',
    'langchain_anthropic',
    'langchain_core.language_models.chat_models',
    'langchain_core.callbacks', 'langchain_core.outputs',
]
for mod_name in _stub_modules:
    if mod_name not in sys.modules:
        _stubs[mod_name] = MagicMock()
        sys.modules[mod_name] = _stubs[mod_name]


class FakeAIMessage:
    def __init__(self, content="", **kwargs):
        self.content = content
        self.type = "ai"


class FakeHumanMessage:
    def __init__(self, content="", **kwargs):
        self.content = content
        self.type = "human"


def _fake_add_messages(left, right):
    if left is None:
        left = []
    return left + right


sys.modules['langchain_core.messages'].AIMessage = FakeAIMessage
sys.modules['langchain_core.messages'].HumanMessage = FakeHumanMessage
sys.modules['langgraph.graph.message'].add_messages = _fake_add_messages


# ===========================================================================
# 1. MCP Tool Function -- execute_httpx
# ===========================================================================

class TestExecuteHttpxMCPTool(unittest.TestCase):
    """Test the execute_httpx MCP tool function in network_recon_server.py."""

    def _import_execute_httpx(self):
        """Import execute_httpx, stubbing FastMCP."""
        fake_mcp = MagicMock()
        fake_mcp.tool.return_value = lambda fn: fn  # decorator passthrough
        with patch.dict(sys.modules, {'fastmcp': MagicMock()}):
            import importlib
            if 'network_recon_server' in sys.modules:
                del sys.modules['network_recon_server']
            with patch('fastmcp.FastMCP', return_value=fake_mcp):
                import network_recon_server
                return network_recon_server.execute_httpx

    @patch('subprocess.run')
    def test_basic_single_target(self, mock_run):
        """Test basic single-target probe returns stdout."""
        execute_httpx = self._import_execute_httpx()

        mock_run.return_value = MagicMock(
            stdout="http://10.0.0.5 [200] [Apache/2.4.41] [Ubuntu Default Page]",
            stderr="",
            returncode=0,
        )

        result = execute_httpx("-u http://10.0.0.5 -sc -title -server -silent")

        self.assertIn("http://10.0.0.5", result)
        self.assertIn("200", result)
        self.assertIn("Apache", result)

        # Verify subprocess was called with correct args
        call_args = mock_run.call_args
        cmd = call_args[0][0]
        self.assertEqual(cmd[0], "httpx")
        self.assertIn("-sc", cmd)
        self.assertIn("-silent", cmd)

    @patch('subprocess.run')
    def test_json_output(self, mock_run):
        """Test JSON output mode works."""
        execute_httpx = self._import_execute_httpx()

        json_line = '{"url":"http://10.0.0.5","status_code":200,"title":"Test"}'
        mock_run.return_value = MagicMock(
            stdout=json_line + "\n",
            stderr="",
            returncode=0,
        )

        result = execute_httpx("-u http://10.0.0.5 -sc -title -j")

        self.assertIn("status_code", result)
        self.assertIn("200", result)

    @patch('subprocess.run')
    def test_timeout_is_300_seconds(self, mock_run):
        """Verify the subprocess timeout is set to 300 seconds."""
        execute_httpx = self._import_execute_httpx()

        mock_run.return_value = MagicMock(
            stdout="output", stderr="", returncode=0,
        )

        execute_httpx("-u http://10.0.0.5 -sc -silent")

        self.assertEqual(mock_run.call_args[1]['timeout'], 300)
        self.assertTrue(mock_run.call_args[1]['capture_output'])
        self.assertTrue(mock_run.call_args[1]['text'])

    @patch('subprocess.run')
    def test_stderr_inf_lines_filtered(self, mock_run):
        """Test that [INF] info lines from stderr are filtered out."""
        execute_httpx = self._import_execute_httpx()

        mock_run.return_value = MagicMock(
            stdout="http://10.0.0.5 [200]",
            stderr=(
                "[INF] Current httpx version v1.6.0\n"
                "[INF] Using default provider config\n"
                "REAL ERROR: connection failed\n"
            ),
            returncode=0,
        )

        result = execute_httpx("-u http://10.0.0.5 -sc")

        # [INF] lines should be filtered
        self.assertNotIn("[INF]", result)
        self.assertNotIn("Current httpx version", result)
        # Real errors should come through
        self.assertIn("REAL ERROR", result)

    @patch('subprocess.run')
    def test_empty_output_returns_info(self, mock_run):
        """Test empty output returns no-live-hosts message."""
        execute_httpx = self._import_execute_httpx()

        mock_run.return_value = MagicMock(
            stdout="", stderr="", returncode=0,
        )

        result = execute_httpx("-u http://10.0.0.5 -sc -silent")

        self.assertIn("[INFO]", result)
        self.assertIn("No live hosts found", result)

    @patch('subprocess.run')
    def test_timeout_returns_error(self, mock_run):
        """Test timeout returns descriptive error."""
        execute_httpx = self._import_execute_httpx()

        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="httpx", timeout=300)

        result = execute_httpx("-l /tmp/big_list.txt -sc -silent")

        self.assertIn("[ERROR]", result)
        self.assertIn("timed out", result)
        self.assertIn("300", result)

    @patch('subprocess.run')
    def test_file_not_found_returns_error(self, mock_run):
        """Test missing binary returns descriptive error."""
        execute_httpx = self._import_execute_httpx()

        mock_run.side_effect = FileNotFoundError()

        result = execute_httpx("-u http://10.0.0.5 -sc")

        self.assertIn("[ERROR]", result)
        self.assertIn("httpx not found", result)

    @patch('subprocess.run')
    def test_ansi_codes_stripped(self, mock_run):
        """Test ANSI escape codes are removed from output."""
        execute_httpx = self._import_execute_httpx()

        mock_run.return_value = MagicMock(
            stdout="\x1b[32mhttp://10.0.0.5\x1b[0m [200]",
            stderr="",
            returncode=0,
        )

        result = execute_httpx("-u http://10.0.0.5 -sc")

        self.assertNotIn("\x1b[", result)
        self.assertIn("http://10.0.0.5", result)

    @patch('subprocess.run')
    def test_ansi_codes_stripped_from_stderr(self, mock_run):
        """Test ANSI escape codes are also stripped from stderr."""
        execute_httpx = self._import_execute_httpx()

        mock_run.return_value = MagicMock(
            stdout="output",
            stderr="\x1b[31mERROR: bad host\x1b[0m\n",
            returncode=0,
        )

        result = execute_httpx("-u http://bad-host -sc")

        self.assertNotIn("\x1b[", result)
        self.assertIn("ERROR: bad host", result)

    @patch('subprocess.run')
    def test_generic_exception_returns_error(self, mock_run):
        """Test generic exception returns error message."""
        execute_httpx = self._import_execute_httpx()

        mock_run.side_effect = OSError("Permission denied")

        result = execute_httpx("-u http://10.0.0.5 -sc")

        self.assertIn("[ERROR]", result)
        self.assertIn("Permission denied", result)

    @patch('subprocess.run')
    def test_shlex_parsing(self, mock_run):
        """Test that quoted arguments are correctly parsed via shlex."""
        execute_httpx = self._import_execute_httpx()

        mock_run.return_value = MagicMock(
            stdout="output", stderr="", returncode=0,
        )

        execute_httpx("-u http://10.0.0.5 -path '/admin,/login,/api' -sc -silent")

        cmd = mock_run.call_args[0][0]
        self.assertIn("/admin,/login,/api", cmd)
        self.assertIn("-sc", cmd)

    @patch('subprocess.run')
    def test_command_starts_with_httpx_binary(self, mock_run):
        """Test that the subprocess command starts with httpx."""
        execute_httpx = self._import_execute_httpx()

        mock_run.return_value = MagicMock(
            stdout="output", stderr="", returncode=0,
        )

        execute_httpx("-u http://10.0.0.5 -sc -title -server -td -fr -silent -j")

        cmd = mock_run.call_args[0][0]
        self.assertEqual(cmd[0], "httpx")
        self.assertIn("-td", cmd)
        self.assertIn("-fr", cmd)
        self.assertIn("-j", cmd)

    @patch('subprocess.run')
    def test_stderr_only_no_stdout(self, mock_run):
        """Test output when only stderr present (no stdout)."""
        execute_httpx = self._import_execute_httpx()

        mock_run.return_value = MagicMock(
            stdout="",
            stderr="FATAL: invalid flag\n",
            returncode=1,
        )

        result = execute_httpx("-u http://10.0.0.5 --bad-flag")

        self.assertIn("FATAL: invalid flag", result)


# ===========================================================================
# 2. Tool Registry
# ===========================================================================

class TestHttpxToolRegistry(unittest.TestCase):
    """Test execute_httpx entry in TOOL_REGISTRY."""

    def test_execute_httpx_in_registry(self):
        from prompts.tool_registry import TOOL_REGISTRY
        self.assertIn("execute_httpx", TOOL_REGISTRY)

    def test_registry_has_required_keys(self):
        from prompts.tool_registry import TOOL_REGISTRY
        entry = TOOL_REGISTRY["execute_httpx"]
        self.assertIn("purpose", entry)
        self.assertIn("when_to_use", entry)
        self.assertIn("args_format", entry)
        self.assertIn("description", entry)

    def test_registry_purpose_mentions_probing(self):
        from prompts.tool_registry import TOOL_REGISTRY
        entry = TOOL_REGISTRY["execute_httpx"]
        purpose = entry["purpose"].lower()
        self.assertTrue(
            "probing" in purpose or "fingerprint" in purpose,
            f"Purpose should mention probing or fingerprinting: {purpose}"
        )

    def test_registry_description_mentions_tech_detection(self):
        from prompts.tool_registry import TOOL_REGISTRY
        entry = TOOL_REGISTRY["execute_httpx"]
        desc = entry["description"].lower()
        self.assertTrue(
            "tech" in desc or "fingerprint" in desc,
            f"Description should mention tech detection: {desc}"
        )

    def test_registry_args_format(self):
        from prompts.tool_registry import TOOL_REGISTRY
        entry = TOOL_REGISTRY["execute_httpx"]
        self.assertIn("args", entry["args_format"])
        self.assertIn("httpx", entry["args_format"])

    def test_registry_ordering_after_curl(self):
        """execute_httpx should appear after execute_curl in registry."""
        from prompts.tool_registry import TOOL_REGISTRY
        keys = list(TOOL_REGISTRY.keys())
        curl_idx = keys.index("execute_curl")
        httpx_idx = keys.index("execute_httpx")
        self.assertGreater(httpx_idx, curl_idx)

    def test_registry_ordering_before_kali_shell(self):
        """execute_httpx should appear before kali_shell in registry."""
        from prompts.tool_registry import TOOL_REGISTRY
        keys = list(TOOL_REGISTRY.keys())
        httpx_idx = keys.index("execute_httpx")
        kali_idx = keys.index("kali_shell")
        self.assertLess(httpx_idx, kali_idx)

    def test_kali_shell_excludes_httpx(self):
        """kali_shell description should tell agent NOT to use it for httpx."""
        from prompts.tool_registry import TOOL_REGISTRY
        kali_desc = TOOL_REGISTRY["kali_shell"]["description"]
        self.assertIn("httpx", kali_desc)
        self.assertIn("Do NOT use for", kali_desc)

    def test_kali_shell_cli_list_no_httpx(self):
        """kali_shell CLI tools list should NOT mention httpx (it has its own tool)."""
        from prompts.tool_registry import TOOL_REGISTRY
        kali_desc = TOOL_REGISTRY["kali_shell"]["description"]
        # Extract just the CLI tools line
        for line in kali_desc.split('\n'):
            if '**CLI tools:**' in line:
                # httpx should NOT be listed as a CLI tool
                # (it should only appear in the "Do NOT use for" line)
                tools_after_prefix = line.split('**CLI tools:**')[1]
                self.assertNotIn('httpx', tools_after_prefix.split('Do NOT')[0])
                break


# ===========================================================================
# 3. Project Settings
# ===========================================================================

class TestHttpxProjectSettings(unittest.TestCase):
    """Test execute_httpx in project_settings.py."""

    def test_in_dangerous_tools(self):
        from project_settings import DANGEROUS_TOOLS
        self.assertIn('execute_httpx', DANGEROUS_TOOLS)

    def test_in_tool_phase_map(self):
        from project_settings import DEFAULT_AGENT_SETTINGS
        phase_map = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']
        self.assertIn('execute_httpx', phase_map)

    def test_phase_map_informational(self):
        from project_settings import DEFAULT_AGENT_SETTINGS
        phases = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']['execute_httpx']
        self.assertIn('informational', phases)

    def test_phase_map_exploitation(self):
        from project_settings import DEFAULT_AGENT_SETTINGS
        phases = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']['execute_httpx']
        self.assertIn('exploitation', phases)

    def test_phase_map_not_post_exploitation(self):
        from project_settings import DEFAULT_AGENT_SETTINGS
        phases = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']['execute_httpx']
        self.assertNotIn('post_exploitation', phases)

    def test_phase_map_matches_naabu_pattern(self):
        """httpx should have same phases as execute_naabu (active recon tools)."""
        from project_settings import DEFAULT_AGENT_SETTINGS
        phase_map = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']
        self.assertEqual(
            sorted(phase_map['execute_httpx']),
            sorted(phase_map['execute_naabu']),
        )


# ===========================================================================
# 4. Phase Enforcement
# ===========================================================================

class TestHttpxPhaseEnforcement(unittest.TestCase):
    """Test execute_httpx phase restriction logic."""

    def test_allowed_in_informational(self):
        from project_settings import is_tool_allowed_in_phase
        self.assertTrue(is_tool_allowed_in_phase('execute_httpx', 'informational'))

    def test_allowed_in_exploitation(self):
        from project_settings import is_tool_allowed_in_phase
        self.assertTrue(is_tool_allowed_in_phase('execute_httpx', 'exploitation'))

    def test_blocked_in_post_exploitation(self):
        from project_settings import is_tool_allowed_in_phase
        self.assertFalse(is_tool_allowed_in_phase('execute_httpx', 'post_exploitation'))


# ===========================================================================
# 5. Stealth Rules
# ===========================================================================

class TestHttpxStealthRules(unittest.TestCase):
    """Test execute_httpx stealth mode constraints."""

    def test_stealth_rules_contain_httpx_section(self):
        from prompts.stealth_rules import STEALTH_MODE_RULES
        self.assertIn("execute_httpx", STEALTH_MODE_RULES)

    def test_stealth_rules_httpx_restricted(self):
        from prompts.stealth_rules import STEALTH_MODE_RULES
        httpx_idx = STEALTH_MODE_RULES.index("execute_httpx")
        section = STEALTH_MODE_RULES[httpx_idx:httpx_idx + 400]
        self.assertIn("RESTRICTED", section)

    def test_stealth_rules_single_target_only(self):
        from prompts.stealth_rules import STEALTH_MODE_RULES
        httpx_idx = STEALTH_MODE_RULES.index("execute_httpx")
        section = STEALTH_MODE_RULES[httpx_idx:httpx_idx + 400]
        self.assertIn("-u", section)
        self.assertIn("FORBIDDEN", section)

    def test_stealth_rules_rate_limiting(self):
        from prompts.stealth_rules import STEALTH_MODE_RULES
        httpx_idx = STEALTH_MODE_RULES.index("execute_httpx")
        section = STEALTH_MODE_RULES[httpx_idx:httpx_idx + 400]
        self.assertIn("-rl", section)


# ===========================================================================
# 6. Prisma Schema Consistency
# ===========================================================================

class TestHttpxPrismaSchema(unittest.TestCase):
    """Test execute_httpx in Prisma schema default."""

    def _parse_prisma_default(self):
        """Parse the agentToolPhaseMap default JSON from schema.prisma."""
        import re
        schema_path = os.path.join(
            _agentic_dir, '..', 'webapp', 'prisma', 'schema.prisma'
        )
        with open(schema_path) as f:
            content = f.read()

        for line in content.split('\n'):
            if 'agentToolPhaseMap' in line and '@default' in line:
                m = re.search(r'@default\("(.+?)"\)\s+@map', line)
                if m:
                    raw = m.group(1).replace('\\"', '"')
                    return json.loads(raw)
        self.fail("Could not find agentToolPhaseMap default in schema.prisma")

    def test_httpx_in_prisma_default(self):
        prisma_map = self._parse_prisma_default()
        self.assertIn('execute_httpx', prisma_map)

    def test_prisma_phases_match_python(self):
        """Prisma default phases for httpx should match Python TOOL_PHASE_MAP."""
        from project_settings import DEFAULT_AGENT_SETTINGS
        prisma_map = self._parse_prisma_default()
        python_phases = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']['execute_httpx']
        self.assertEqual(
            sorted(prisma_map['execute_httpx']),
            sorted(python_phases),
        )

    def test_prisma_keys_subset_of_python(self):
        """All tools in Prisma default should exist in Python TOOL_PHASE_MAP."""
        from project_settings import DEFAULT_AGENT_SETTINGS
        prisma_map = self._parse_prisma_default()
        python_map = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']
        for key in prisma_map:
            self.assertIn(key, python_map, f"Prisma has '{key}' but Python TOOL_PHASE_MAP does not")


# ===========================================================================
# 7. Cross-Layer Consistency
# ===========================================================================

class TestHttpxCrossLayerConsistency(unittest.TestCase):
    """Verify execute_httpx is consistently registered across all layers."""

    def test_registry_and_phase_map_consistent(self):
        from prompts.tool_registry import TOOL_REGISTRY
        from project_settings import DEFAULT_AGENT_SETTINGS
        phase_map = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']
        self.assertIn('execute_httpx', TOOL_REGISTRY)
        self.assertIn('execute_httpx', phase_map)

    def test_dangerous_tool_is_in_phase_map(self):
        from project_settings import DANGEROUS_TOOLS, DEFAULT_AGENT_SETTINGS
        phase_map = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']
        self.assertIn('execute_httpx', DANGEROUS_TOOLS)
        self.assertIn('execute_httpx', phase_map)

    def test_tool_matrix_contains_httpx(self):
        """ToolMatrixSection.tsx should contain execute_httpx."""
        tsx_path = os.path.join(
            _agentic_dir, '..', 'webapp', 'src', 'components', 'projects',
            'ProjectForm', 'sections', 'ToolMatrixSection.tsx'
        )
        with open(tsx_path) as f:
            content = f.read()
        self.assertIn("'execute_httpx'", content)

    def test_all_dangerous_tools_have_phases(self):
        """Every DANGEROUS_TOOL should have an entry in TOOL_PHASE_MAP."""
        from project_settings import DANGEROUS_TOOLS, DEFAULT_AGENT_SETTINGS
        phase_map = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']
        for tool in DANGEROUS_TOOLS:
            self.assertIn(tool, phase_map, f"Dangerous tool '{tool}' missing from TOOL_PHASE_MAP")

    def test_all_phase_map_tools_in_registry_or_special(self):
        """Every TOOL_PHASE_MAP tool should be in TOOL_REGISTRY or a known special tool."""
        from prompts.tool_registry import TOOL_REGISTRY
        from project_settings import DEFAULT_AGENT_SETTINGS
        phase_map = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']
        # These tools are registered via non-registry mechanisms (API tools, MCP auto-discovery)
        special_tools = {'web_search', 'shodan', 'google_dork', 'msf_restart'}
        for tool in phase_map:
            self.assertTrue(
                tool in TOOL_REGISTRY or tool in special_tools,
                f"Tool '{tool}' in TOOL_PHASE_MAP but not in TOOL_REGISTRY or special tools"
            )


if __name__ == '__main__':
    unittest.main()
