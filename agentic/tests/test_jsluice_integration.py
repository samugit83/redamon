"""
Unit tests for jsluice agentic integration -- MCP tool function, tool registry,
project settings, stealth rules, phase enforcement, and cross-layer consistency.

Run with: python -m pytest tests/test_jsluice_integration.py -v
"""

import json
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

# Add parent dir to path so we can import from agentic modules
_agentic_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _agentic_dir)

# Add MCP servers dir to path for importing execute_jsluice
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
# 1. MCP Tool Function -- execute_jsluice
# ===========================================================================

class TestExecuteJsluiceMCPTool(unittest.TestCase):
    """Test the execute_jsluice MCP tool function in network_recon_server.py."""

    def _import_execute_jsluice(self):
        """Import execute_jsluice, stubbing FastMCP."""
        fake_mcp = MagicMock()
        fake_mcp.tool.return_value = lambda fn: fn  # decorator passthrough
        with patch.dict(sys.modules, {'fastmcp': MagicMock()}):
            import importlib
            if 'network_recon_server' in sys.modules:
                del sys.modules['network_recon_server']
            with patch('fastmcp.FastMCP', return_value=fake_mcp):
                import network_recon_server
                return network_recon_server.execute_jsluice

    @patch('subprocess.run')
    def test_urls_mode_returns_json_lines(self, mock_run):
        """Test urls subcommand returns JSON lines output."""
        execute_jsluice = self._import_execute_jsluice()

        mock_run.return_value = MagicMock(
            stdout='{"url":"http://target/api/v2/users"}\n{"url":"http://target/admin/config"}\n',
            stderr="",
            returncode=0,
        )

        result = execute_jsluice("urls /tmp/app.js")

        self.assertIn("/api/v2/users", result)
        self.assertIn("/admin/config", result)

        cmd = mock_run.call_args[0][0]
        self.assertEqual(cmd[0], "jsluice")
        self.assertEqual(cmd[1], "urls")
        self.assertEqual(cmd[2], "/tmp/app.js")

    @patch('subprocess.run')
    def test_secrets_mode(self, mock_run):
        """Test secrets subcommand returns secret findings."""
        execute_jsluice = self._import_execute_jsluice()

        mock_run.return_value = MagicMock(
            stdout='{"kind":"AWSAccessKey","severity":"high","data":{"key":"AKIA..."}}\n',
            stderr="",
            returncode=0,
        )

        result = execute_jsluice("secrets /tmp/app.js")

        self.assertIn("AWSAccessKey", result)
        self.assertIn("high", result)

    @patch('subprocess.run')
    def test_resolve_paths_flag(self, mock_run):
        """Test --resolve-paths flag is passed correctly."""
        execute_jsluice = self._import_execute_jsluice()

        mock_run.return_value = MagicMock(
            stdout='{"url":"http://10.0.0.5/api/users"}\n',
            stderr="",
            returncode=0,
        )

        execute_jsluice("urls --resolve-paths http://10.0.0.5 /tmp/app.js")

        cmd = mock_run.call_args[0][0]
        self.assertIn("--resolve-paths", cmd)
        self.assertIn("http://10.0.0.5", cmd)

    @patch('subprocess.run')
    def test_multiple_files(self, mock_run):
        """Test multiple file arguments are passed correctly."""
        execute_jsluice = self._import_execute_jsluice()

        mock_run.return_value = MagicMock(
            stdout='{"url":"/api/v1"}\n', stderr="", returncode=0,
        )

        execute_jsluice("urls /tmp/app.js /tmp/vendor.js /tmp/main.js")

        cmd = mock_run.call_args[0][0]
        self.assertIn("/tmp/app.js", cmd)
        self.assertIn("/tmp/vendor.js", cmd)
        self.assertIn("/tmp/main.js", cmd)

    @patch('subprocess.run')
    def test_concurrency_flag(self, mock_run):
        """Test --concurrency flag is passed correctly."""
        execute_jsluice = self._import_execute_jsluice()

        mock_run.return_value = MagicMock(
            stdout="", stderr="", returncode=0,
        )

        execute_jsluice("urls --concurrency 5 /tmp/app.js")

        cmd = mock_run.call_args[0][0]
        self.assertIn("--concurrency", cmd)
        self.assertIn("5", cmd)

    @patch('subprocess.run')
    def test_empty_output_returns_info(self, mock_run):
        """Test empty output returns info message."""
        execute_jsluice = self._import_execute_jsluice()

        mock_run.return_value = MagicMock(
            stdout="", stderr="", returncode=0,
        )

        result = execute_jsluice("urls /tmp/empty.js")

        self.assertIn("[INFO]", result)
        self.assertIn("No results found", result)

    @patch('subprocess.run')
    def test_timeout_returns_error(self, mock_run):
        """Test timeout returns descriptive error."""
        execute_jsluice = self._import_execute_jsluice()

        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="jsluice", timeout=120)

        result = execute_jsluice("urls /tmp/huge.js")

        self.assertIn("[ERROR]", result)
        self.assertIn("timed out", result)
        self.assertIn("120", result)

    @patch('subprocess.run')
    def test_file_not_found_returns_error(self, mock_run):
        """Test missing binary returns descriptive error."""
        execute_jsluice = self._import_execute_jsluice()

        mock_run.side_effect = FileNotFoundError()

        result = execute_jsluice("urls /tmp/app.js")

        self.assertIn("[ERROR]", result)
        self.assertIn("jsluice not found", result)

    @patch('subprocess.run')
    def test_generic_exception_returns_error(self, mock_run):
        """Test generic exception returns error message."""
        execute_jsluice = self._import_execute_jsluice()

        mock_run.side_effect = OSError("Permission denied")

        result = execute_jsluice("urls /tmp/app.js")

        self.assertIn("[ERROR]", result)
        self.assertIn("Permission denied", result)

    @patch('subprocess.run')
    def test_stderr_appended(self, mock_run):
        """Test stderr is appended to output with [STDERR] prefix."""
        execute_jsluice = self._import_execute_jsluice()

        mock_run.return_value = MagicMock(
            stdout='{"url":"/api"}\n',
            stderr="warning: file too large, skipping\n",
            returncode=0,
        )

        result = execute_jsluice("urls /tmp/app.js")

        self.assertIn("/api", result)
        self.assertIn("[STDERR]", result)
        self.assertIn("file too large", result)

    @patch('subprocess.run')
    def test_ansi_stripped_from_stderr(self, mock_run):
        """Test ANSI escape codes are stripped from stderr."""
        execute_jsluice = self._import_execute_jsluice()

        mock_run.return_value = MagicMock(
            stdout='{"url":"/api"}\n',
            stderr="\x1b[31merror: bad file\x1b[0m\n",
            returncode=0,
        )

        result = execute_jsluice("urls /tmp/app.js")

        self.assertNotIn("\x1b[", result)
        self.assertIn("error: bad file", result)

    @patch('subprocess.run')
    def test_stdout_json_preserved(self, mock_run):
        """Test JSON stdout is preserved as-is (no ANSI stripping on stdout)."""
        execute_jsluice = self._import_execute_jsluice()

        json_line = '{"url":"http://target/api","method":"GET","source":"fetch"}'
        mock_run.return_value = MagicMock(
            stdout=json_line + "\n",
            stderr="",
            returncode=0,
        )

        result = execute_jsluice("urls /tmp/app.js")

        # Verify the full JSON line is preserved
        self.assertIn(json_line, result)
        parsed = json.loads(result.strip())
        self.assertEqual(parsed["url"], "http://target/api")

    @patch('subprocess.run')
    def test_timeout_is_120_seconds(self, mock_run):
        """Verify the subprocess timeout is set to 120 seconds."""
        execute_jsluice = self._import_execute_jsluice()

        mock_run.return_value = MagicMock(
            stdout="", stderr="", returncode=0,
        )

        execute_jsluice("urls /tmp/app.js")

        self.assertEqual(mock_run.call_args[1]['timeout'], 120)
        self.assertTrue(mock_run.call_args[1]['capture_output'])
        self.assertTrue(mock_run.call_args[1]['text'])

    @patch('subprocess.run')
    def test_shlex_parsing_quoted_args(self, mock_run):
        """Test that quoted arguments are correctly parsed via shlex."""
        execute_jsluice = self._import_execute_jsluice()

        mock_run.return_value = MagicMock(
            stdout="", stderr="", returncode=0,
        )

        execute_jsluice("urls --resolve-paths 'http://target with space' /tmp/app.js")

        cmd = mock_run.call_args[0][0]
        self.assertIn("http://target with space", cmd)


# ===========================================================================
# 2. Tool Registry
# ===========================================================================

class TestJsluiceToolRegistry(unittest.TestCase):
    """Test execute_jsluice entry in TOOL_REGISTRY."""

    def test_in_registry(self):
        from prompts.tool_registry import TOOL_REGISTRY
        self.assertIn("execute_jsluice", TOOL_REGISTRY)

    def test_registry_has_required_keys(self):
        from prompts.tool_registry import TOOL_REGISTRY
        entry = TOOL_REGISTRY["execute_jsluice"]
        for key in ("purpose", "when_to_use", "args_format", "description"):
            self.assertIn(key, entry)

    def test_purpose_mentions_javascript(self):
        from prompts.tool_registry import TOOL_REGISTRY
        entry = TOOL_REGISTRY["execute_jsluice"]
        purpose_lower = entry["purpose"].lower()
        self.assertTrue(
            "javascript" in purpose_lower or "js" in purpose_lower,
            f"purpose should mention JavaScript: {entry['purpose']}"
        )

    def test_description_mentions_local_only(self):
        from prompts.tool_registry import TOOL_REGISTRY
        entry = TOOL_REGISTRY["execute_jsluice"]
        desc_lower = entry["description"].lower()
        self.assertIn("local", desc_lower)

    def test_description_mentions_both_subcommands(self):
        from prompts.tool_registry import TOOL_REGISTRY
        entry = TOOL_REGISTRY["execute_jsluice"]
        self.assertIn("urls", entry["description"])
        self.assertIn("secrets", entry["description"])

    def test_description_mentions_curl_workflow(self):
        from prompts.tool_registry import TOOL_REGISTRY
        entry = TOOL_REGISTRY["execute_jsluice"]
        self.assertIn("execute_curl", entry["description"])

    def test_args_format(self):
        from prompts.tool_registry import TOOL_REGISTRY
        entry = TOOL_REGISTRY["execute_jsluice"]
        self.assertIn("args", entry["args_format"])
        self.assertIn("jsluice", entry["args_format"])

    def test_kali_shell_excludes_jsluice(self):
        """kali_shell description should tell agent NOT to use it for jsluice."""
        from prompts.tool_registry import TOOL_REGISTRY
        kali_desc = TOOL_REGISTRY["kali_shell"]["description"]
        self.assertIn("jsluice", kali_desc)


# ===========================================================================
# 3. Project Settings
# ===========================================================================

class TestJsluiceProjectSettings(unittest.TestCase):
    """Test execute_jsluice in project_settings.py."""

    def test_not_in_dangerous_tools(self):
        """jsluice is passive local analysis -- should NOT be dangerous."""
        from project_settings import DANGEROUS_TOOLS
        self.assertNotIn('execute_jsluice', DANGEROUS_TOOLS)

    def test_in_tool_phase_map(self):
        from project_settings import DEFAULT_AGENT_SETTINGS
        phase_map = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']
        self.assertIn('execute_jsluice', phase_map)

    def test_phase_map_informational(self):
        from project_settings import DEFAULT_AGENT_SETTINGS
        phases = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']['execute_jsluice']
        self.assertIn('informational', phases)

    def test_phase_map_exploitation(self):
        from project_settings import DEFAULT_AGENT_SETTINGS
        phases = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']['execute_jsluice']
        self.assertIn('exploitation', phases)

    def test_phase_map_post_exploitation(self):
        """jsluice is useful in all 3 phases (passive local analysis)."""
        from project_settings import DEFAULT_AGENT_SETTINGS
        phases = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']['execute_jsluice']
        self.assertIn('post_exploitation', phases)

    def test_phase_map_matches_query_graph_pattern(self):
        """jsluice should have same phases as query_graph (passive tools in all phases)."""
        from project_settings import DEFAULT_AGENT_SETTINGS
        phase_map = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']
        self.assertEqual(
            sorted(phase_map['execute_jsluice']),
            sorted(phase_map['query_graph']),
        )


# ===========================================================================
# 4. Phase Enforcement
# ===========================================================================

class TestJsluicePhaseEnforcement(unittest.TestCase):
    """Test execute_jsluice phase restriction logic."""

    def test_allowed_in_informational(self):
        from project_settings import is_tool_allowed_in_phase
        self.assertTrue(is_tool_allowed_in_phase('execute_jsluice', 'informational'))

    def test_allowed_in_exploitation(self):
        from project_settings import is_tool_allowed_in_phase
        self.assertTrue(is_tool_allowed_in_phase('execute_jsluice', 'exploitation'))

    def test_allowed_in_post_exploitation(self):
        from project_settings import is_tool_allowed_in_phase
        self.assertTrue(is_tool_allowed_in_phase('execute_jsluice', 'post_exploitation'))


# ===========================================================================
# 5. Stealth Rules
# ===========================================================================

class TestJsluiceStealthRules(unittest.TestCase):
    """Test execute_jsluice stealth mode constraints."""

    def test_stealth_rules_contain_jsluice_section(self):
        from prompts.stealth_rules import STEALTH_MODE_RULES
        self.assertIn("execute_jsluice", STEALTH_MODE_RULES)

    def test_stealth_rules_no_restrictions(self):
        """jsluice is passive local analysis -- should have NO RESTRICTIONS."""
        from prompts.stealth_rules import STEALTH_MODE_RULES
        idx = STEALTH_MODE_RULES.index("execute_jsluice")
        section = STEALTH_MODE_RULES[idx:idx + 200]
        self.assertIn("NO RESTRICTIONS", section)

    def test_stealth_rules_not_forbidden(self):
        """jsluice should NOT be FORBIDDEN or RESTRICTED in stealth mode."""
        from prompts.stealth_rules import STEALTH_MODE_RULES
        idx = STEALTH_MODE_RULES.index("execute_jsluice")
        # Get just the jsluice section (up to next ### or end)
        section_end = STEALTH_MODE_RULES.find("###", idx + 1)
        if section_end == -1:
            section_end = idx + 200
        section = STEALTH_MODE_RULES[idx:section_end]
        self.assertNotIn("FORBIDDEN", section)
        self.assertNotIn("RESTRICTED", section.replace("NO RESTRICTIONS", ""))


# ===========================================================================
# 6. RoE Category Mapping
# ===========================================================================

class TestJsluiceRoECategory(unittest.TestCase):
    """Test execute_jsluice is NOT in any RoE category."""

    def test_jsluice_not_in_roe_categories(self):
        """jsluice is passive -- should not be in any CATEGORY_TOOL_MAP list."""
        plan_node_path = os.path.join(
            _agentic_dir, 'orchestrator_helpers', 'nodes', 'execute_plan_node.py'
        )
        with open(plan_node_path) as f:
            source = f.read()
        self.assertNotIn("'execute_jsluice'", source)
        self.assertNotIn('"execute_jsluice"', source)


# ===========================================================================
# 7. Prisma Schema Consistency
# ===========================================================================

class TestJsluicePrismaSchema(unittest.TestCase):
    """Test execute_jsluice in Prisma schema default."""

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

    def test_jsluice_in_prisma_default(self):
        prisma_map = self._parse_prisma_default()
        self.assertIn('execute_jsluice', prisma_map)

    def test_prisma_phases_match_python(self):
        """Prisma default phases should match Python TOOL_PHASE_MAP."""
        from project_settings import DEFAULT_AGENT_SETTINGS
        prisma_map = self._parse_prisma_default()
        python_phases = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']['execute_jsluice']
        self.assertEqual(
            sorted(prisma_map['execute_jsluice']),
            sorted(python_phases),
        )

    def test_prisma_has_all_three_phases(self):
        prisma_map = self._parse_prisma_default()
        phases = prisma_map['execute_jsluice']
        self.assertIn('informational', phases)
        self.assertIn('exploitation', phases)
        self.assertIn('post_exploitation', phases)


# ===========================================================================
# 8. Cross-Layer Consistency
# ===========================================================================

class TestJsluiceCrossLayerConsistency(unittest.TestCase):
    """Verify execute_jsluice is consistently registered across all layers."""

    def test_registry_and_phase_map_consistent(self):
        from prompts.tool_registry import TOOL_REGISTRY
        from project_settings import DEFAULT_AGENT_SETTINGS
        phase_map = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']
        self.assertIn('execute_jsluice', TOOL_REGISTRY)
        self.assertIn('execute_jsluice', phase_map)

    def test_not_dangerous_and_in_phase_map(self):
        """jsluice should be in TOOL_PHASE_MAP but NOT in DANGEROUS_TOOLS."""
        from project_settings import DANGEROUS_TOOLS, DEFAULT_AGENT_SETTINGS
        phase_map = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']
        self.assertNotIn('execute_jsluice', DANGEROUS_TOOLS)
        self.assertIn('execute_jsluice', phase_map)

    def test_tool_matrix_contains_jsluice(self):
        """ToolMatrixSection.tsx should contain execute_jsluice."""
        tsx_path = os.path.join(
            _agentic_dir, '..', 'webapp', 'src', 'components', 'projects',
            'ProjectForm', 'sections', 'ToolMatrixSection.tsx'
        )
        with open(tsx_path) as f:
            content = f.read()
        self.assertIn("'execute_jsluice'", content)

    def test_stealth_rules_contain_jsluice(self):
        from prompts.stealth_rules import STEALTH_MODE_RULES
        self.assertIn("execute_jsluice", STEALTH_MODE_RULES)

    def test_mcp_server_docstring_mentions_jsluice(self):
        """network_recon_server.py docstring should list jsluice."""
        server_path = os.path.join(
            _agentic_dir, '..', 'mcp', 'servers', 'network_recon_server.py'
        )
        with open(server_path) as f:
            # Read first 25 lines (module docstring)
            lines = [next(f) for _ in range(25)]
        docstring = ''.join(lines)
        self.assertIn("jsluice", docstring)


if __name__ == '__main__':
    unittest.main()
