"""
Unit tests for Katana agentic integration -- MCP tool function, tool registry,
project settings, stealth rules, and cross-layer consistency.

Run with: python -m pytest tests/test_katana_integration.py -v
"""

import json
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

# Add parent dir to path so we can import from agentic modules
_agentic_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _agentic_dir)

# Add MCP servers dir to path for importing execute_katana
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
# 1. MCP Tool Function -- execute_katana
# ===========================================================================

class TestExecuteKatanaMCPTool(unittest.TestCase):
    """Test the execute_katana MCP tool function in network_recon_server.py."""

    def _import_execute_katana(self):
        """Import execute_katana, stubbing FastMCP."""
        fake_mcp = MagicMock()
        fake_mcp.tool.return_value = lambda fn: fn  # decorator passthrough
        with patch.dict(sys.modules, {'fastmcp': MagicMock()}):
            import importlib
            if 'network_recon_server' in sys.modules:
                del sys.modules['network_recon_server']
            with patch('fastmcp.FastMCP', return_value=fake_mcp):
                import network_recon_server
                return network_recon_server.execute_katana

    @patch('subprocess.run')
    def test_basic_crawl(self, mock_run):
        """Test basic crawl returns discovered URLs."""
        execute_katana = self._import_execute_katana()

        mock_run.return_value = MagicMock(
            stdout="https://10.0.0.5/\nhttps://10.0.0.5/login\nhttps://10.0.0.5/api/v1\n",
            stderr="",
            returncode=0,
        )

        result = execute_katana("-u https://10.0.0.5 -d 3 -jc -silent")

        self.assertIn("https://10.0.0.5/login", result)
        self.assertIn("https://10.0.0.5/api/v1", result)

        cmd = mock_run.call_args[0][0]
        self.assertEqual(cmd[0], "katana")
        self.assertIn("-u", cmd)
        self.assertIn("-jc", cmd)

    @patch('subprocess.run')
    def test_silent_auto_injected(self, mock_run):
        """Test -silent is auto-injected if missing."""
        execute_katana = self._import_execute_katana()

        mock_run.return_value = MagicMock(
            stdout="https://target/page\n", stderr="", returncode=0,
        )

        execute_katana("-u https://target -d 2")

        cmd = mock_run.call_args[0][0]
        self.assertIn("-silent", cmd)

    @patch('subprocess.run')
    def test_silent_not_duplicated(self, mock_run):
        """Test -silent is not added twice if already present."""
        execute_katana = self._import_execute_katana()

        mock_run.return_value = MagicMock(
            stdout="output\n", stderr="", returncode=0,
        )

        execute_katana("-u https://target -d 2 -silent")

        cmd = mock_run.call_args[0][0]
        count = cmd.count("-silent")
        self.assertEqual(count, 1, "Should not duplicate -silent flag")

    @patch('subprocess.run')
    def test_info_stderr_filtered(self, mock_run):
        """Test that [INF] and [WRN] stderr lines are filtered."""
        execute_katana = self._import_execute_katana()

        mock_run.return_value = MagicMock(
            stdout="https://target/page\n",
            stderr=(
                "[INF] Started standard crawling for => https://target\n"
                "[INF] Found 15 results in 5 seconds\n"
                "[WRN] Could not fetch https://target/broken\n"
                "[ERR] Connection refused for https://target/api\n"
            ),
            returncode=0,
        )

        result = execute_katana("-u https://target -d 2")

        self.assertNotIn("[INF]", result)
        self.assertNotIn("[WRN]", result)
        self.assertIn("Connection refused", result)

    @patch('subprocess.run')
    def test_empty_output_returns_info(self, mock_run):
        """Test empty output returns info message."""
        execute_katana = self._import_execute_katana()

        mock_run.return_value = MagicMock(
            stdout="", stderr="", returncode=0,
        )

        result = execute_katana("-u https://unreachable.local -d 1")

        self.assertIn("[INFO]", result)
        self.assertIn("No URLs/endpoints discovered", result)

    @patch('subprocess.run')
    def test_timeout_returns_error(self, mock_run):
        """Test timeout returns descriptive error."""
        execute_katana = self._import_execute_katana()

        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="katana", timeout=600)

        result = execute_katana("-u https://target -d 5 -jc")

        self.assertIn("[ERROR]", result)
        self.assertIn("timed out", result)
        self.assertIn("600", result)

    @patch('subprocess.run')
    def test_file_not_found_returns_error(self, mock_run):
        """Test missing binary returns descriptive error."""
        execute_katana = self._import_execute_katana()

        mock_run.side_effect = FileNotFoundError()

        result = execute_katana("-u https://target -d 2")

        self.assertIn("[ERROR]", result)
        self.assertIn("katana not found", result)

    @patch('subprocess.run')
    def test_generic_exception_returns_error(self, mock_run):
        """Test generic exception returns error message."""
        execute_katana = self._import_execute_katana()

        mock_run.side_effect = OSError("Permission denied")

        result = execute_katana("-u https://target -d 2")

        self.assertIn("[ERROR]", result)
        self.assertIn("Permission denied", result)

    @patch('subprocess.run')
    def test_ansi_codes_stripped(self, mock_run):
        """Test ANSI escape codes are removed from output."""
        execute_katana = self._import_execute_katana()

        mock_run.return_value = MagicMock(
            stdout="\x1b[32mhttps://target/admin\x1b[0m\n",
            stderr="",
            returncode=0,
        )

        result = execute_katana("-u https://target -d 2")

        self.assertNotIn("\x1b[", result)
        self.assertIn("https://target/admin", result)

    @patch('subprocess.run')
    def test_timeout_is_600_seconds(self, mock_run):
        """Verify the subprocess timeout is set to 600 seconds."""
        execute_katana = self._import_execute_katana()

        mock_run.return_value = MagicMock(
            stdout="output\n", stderr="", returncode=0,
        )

        execute_katana("-u https://target -d 2")

        self.assertEqual(mock_run.call_args[1]['timeout'], 600)
        self.assertTrue(mock_run.call_args[1]['capture_output'])
        self.assertTrue(mock_run.call_args[1]['text'])

    @patch('subprocess.run')
    def test_shlex_parsing_quoted_args(self, mock_run):
        """Test that quoted arguments are correctly parsed via shlex."""
        execute_katana = self._import_execute_katana()

        mock_run.return_value = MagicMock(
            stdout="output\n", stderr="", returncode=0,
        )

        execute_katana("-u https://target -d 3 -ef 'png,jpg,gif,css'")

        cmd = mock_run.call_args[0][0]
        self.assertIn("png,jpg,gif,css", cmd)

    @patch('subprocess.run')
    def test_jsonl_output_passthrough(self, mock_run):
        """Test JSON lines output is returned as-is."""
        execute_katana = self._import_execute_katana()

        jsonl = (
            '{"url":"https://target/","path":"/","fqdn":"target"}\n'
            '{"url":"https://target/login","path":"/login","fqdn":"target"}\n'
        )
        mock_run.return_value = MagicMock(
            stdout=jsonl, stderr="", returncode=0,
        )

        result = execute_katana("-u https://target -d 2 -jsonl")

        self.assertIn('"url":', result)
        self.assertIn("/login", result)


# ===========================================================================
# 2. Tool Registry
# ===========================================================================

class TestKatanaToolRegistry(unittest.TestCase):
    """Test execute_katana entry in TOOL_REGISTRY."""

    def test_in_registry(self):
        from prompts.tool_registry import TOOL_REGISTRY
        self.assertIn("execute_katana", TOOL_REGISTRY)

    def test_registry_has_required_keys(self):
        from prompts.tool_registry import TOOL_REGISTRY
        entry = TOOL_REGISTRY["execute_katana"]
        self.assertIn("purpose", entry)
        self.assertIn("when_to_use", entry)
        self.assertIn("args_format", entry)
        self.assertIn("description", entry)

    def test_registry_purpose_mentions_crawling(self):
        from prompts.tool_registry import TOOL_REGISTRY
        entry = TOOL_REGISTRY["execute_katana"]
        self.assertIn("crawl", entry["purpose"].lower())

    def test_registry_description_mentions_js_crawl(self):
        from prompts.tool_registry import TOOL_REGISTRY
        entry = TOOL_REGISTRY["execute_katana"]
        self.assertIn("-jc", entry["description"])

    def test_registry_description_mentions_known_files(self):
        from prompts.tool_registry import TOOL_REGISTRY
        entry = TOOL_REGISTRY["execute_katana"]
        self.assertIn("-kf", entry["description"])

    def test_registry_description_mentions_active(self):
        from prompts.tool_registry import TOOL_REGISTRY
        entry = TOOL_REGISTRY["execute_katana"]
        self.assertIn("ACTIVE", entry["description"])

    def test_registry_args_format(self):
        from prompts.tool_registry import TOOL_REGISTRY
        entry = TOOL_REGISTRY["execute_katana"]
        self.assertIn("args", entry["args_format"])

    def test_registry_ordering_before_msf(self):
        """execute_katana should appear before msf_restart in registry."""
        from prompts.tool_registry import TOOL_REGISTRY
        keys = list(TOOL_REGISTRY.keys())
        katana_idx = keys.index("execute_katana")
        msf_idx = keys.index("msf_restart")
        self.assertLess(katana_idx, msf_idx)

    def test_kali_shell_excludes_katana(self):
        """kali_shell description should tell agent not to use it for katana."""
        from prompts.tool_registry import TOOL_REGISTRY
        kali_desc = TOOL_REGISTRY["kali_shell"]["description"]
        self.assertIn("katana", kali_desc)


# ===========================================================================
# 3. Project Settings
# ===========================================================================

class TestKatanaProjectSettings(unittest.TestCase):
    """Test execute_katana in project_settings.py."""

    def test_in_dangerous_tools(self):
        from project_settings import DANGEROUS_TOOLS
        self.assertIn('execute_katana', DANGEROUS_TOOLS)

    def test_in_tool_phase_map(self):
        from project_settings import DEFAULT_AGENT_SETTINGS
        phase_map = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']
        self.assertIn('execute_katana', phase_map)

    def test_phase_map_informational(self):
        from project_settings import DEFAULT_AGENT_SETTINGS
        phases = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']['execute_katana']
        self.assertIn('informational', phases)

    def test_phase_map_exploitation(self):
        from project_settings import DEFAULT_AGENT_SETTINGS
        phases = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']['execute_katana']
        self.assertIn('exploitation', phases)

    def test_phase_map_not_post_exploitation(self):
        from project_settings import DEFAULT_AGENT_SETTINGS
        phases = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']['execute_katana']
        self.assertNotIn('post_exploitation', phases)

    def test_phase_map_matches_naabu_pattern(self):
        """Katana should have same phases as execute_naabu (active scanning tools)."""
        from project_settings import DEFAULT_AGENT_SETTINGS
        phase_map = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']
        self.assertEqual(
            sorted(phase_map['execute_katana']),
            sorted(phase_map['execute_naabu']),
        )


# ===========================================================================
# 4. Phase Enforcement
# ===========================================================================

class TestKatanaPhaseEnforcement(unittest.TestCase):
    """Test execute_katana phase restriction logic."""

    def test_allowed_in_informational(self):
        from project_settings import is_tool_allowed_in_phase
        self.assertTrue(is_tool_allowed_in_phase('execute_katana', 'informational'))

    def test_allowed_in_exploitation(self):
        from project_settings import is_tool_allowed_in_phase
        self.assertTrue(is_tool_allowed_in_phase('execute_katana', 'exploitation'))

    def test_blocked_in_post_exploitation(self):
        from project_settings import is_tool_allowed_in_phase
        self.assertFalse(is_tool_allowed_in_phase('execute_katana', 'post_exploitation'))


# ===========================================================================
# 5. Stealth Rules
# ===========================================================================

class TestKatanaStealthRules(unittest.TestCase):
    """Test execute_katana stealth mode constraints."""

    def test_stealth_rules_contain_katana_section(self):
        from prompts.stealth_rules import STEALTH_MODE_RULES
        self.assertIn("execute_katana", STEALTH_MODE_RULES)

    def test_stealth_rules_heavily_restricted(self):
        from prompts.stealth_rules import STEALTH_MODE_RULES
        katana_idx = STEALTH_MODE_RULES.index("execute_katana")
        section = STEALTH_MODE_RULES[katana_idx:katana_idx + 300]
        self.assertIn("HEAVILY RESTRICTED", section)

    def test_stealth_rules_require_rate_limit(self):
        from prompts.stealth_rules import STEALTH_MODE_RULES
        katana_idx = STEALTH_MODE_RULES.index("execute_katana")
        section = STEALTH_MODE_RULES[katana_idx:katana_idx + 500]
        self.assertIn("-rl 2", section)

    def test_stealth_rules_require_depth_1(self):
        from prompts.stealth_rules import STEALTH_MODE_RULES
        katana_idx = STEALTH_MODE_RULES.index("execute_katana")
        section = STEALTH_MODE_RULES[katana_idx:katana_idx + 500]
        self.assertIn("-d 1", section)

    def test_stealth_rules_require_concurrency_1(self):
        from prompts.stealth_rules import STEALTH_MODE_RULES
        katana_idx = STEALTH_MODE_RULES.index("execute_katana")
        section = STEALTH_MODE_RULES[katana_idx:katana_idx + 500]
        self.assertIn("-c 1", section)

    def test_stealth_rules_forbid_headless(self):
        from prompts.stealth_rules import STEALTH_MODE_RULES
        katana_idx = STEALTH_MODE_RULES.index("execute_katana")
        section = STEALTH_MODE_RULES[katana_idx:katana_idx + 500]
        self.assertIn("-hl", section)
        self.assertIn("FORBIDDEN", section)

    def test_stealth_rules_forbid_list(self):
        from prompts.stealth_rules import STEALTH_MODE_RULES
        katana_idx = STEALTH_MODE_RULES.index("execute_katana")
        section = STEALTH_MODE_RULES[katana_idx:katana_idx + 500]
        self.assertIn("-list", section)
        self.assertIn("FORBIDDEN", section)


# ===========================================================================
# 6. RoE Category Mapping
# ===========================================================================

class TestKatanaRoECategory(unittest.TestCase):
    """Test execute_katana is NOT in any RoE CATEGORY_TOOL_MAP category."""

    def test_katana_not_in_roe_categories(self):
        """execute_katana should NOT be in any RoE category (it's a crawler, not exploit/brute)."""
        plan_node_path = os.path.join(
            _agentic_dir, 'orchestrator_helpers', 'nodes', 'execute_plan_node.py'
        )
        with open(plan_node_path) as f:
            source = f.read()
        # Find CATEGORY_TOOL_MAP block
        start = source.index('CATEGORY_TOOL_MAP')
        end = source.index('}', start) + 1
        category_block = source[start:end]
        self.assertNotIn('execute_katana', category_block)


# ===========================================================================
# 7. Prisma Schema Consistency
# ===========================================================================

class TestKatanaPrismaSchema(unittest.TestCase):
    """Test execute_katana in Prisma schema default."""

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

    def test_katana_in_prisma_default(self):
        prisma_map = self._parse_prisma_default()
        self.assertIn('execute_katana', prisma_map)

    def test_prisma_phases_match_python(self):
        """Prisma default phases for katana should match Python TOOL_PHASE_MAP."""
        from project_settings import DEFAULT_AGENT_SETTINGS
        prisma_map = self._parse_prisma_default()
        python_phases = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']['execute_katana']
        self.assertEqual(
            sorted(prisma_map['execute_katana']),
            sorted(python_phases),
        )


# ===========================================================================
# 8. Cross-Layer Consistency
# ===========================================================================

class TestKatanaCrossLayerConsistency(unittest.TestCase):
    """Verify execute_katana is consistently registered across all layers."""

    def test_registry_and_phase_map_consistent(self):
        from prompts.tool_registry import TOOL_REGISTRY
        from project_settings import DEFAULT_AGENT_SETTINGS
        phase_map = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']
        self.assertIn('execute_katana', TOOL_REGISTRY)
        self.assertIn('execute_katana', phase_map)

    def test_dangerous_tool_is_in_phase_map(self):
        from project_settings import DANGEROUS_TOOLS, DEFAULT_AGENT_SETTINGS
        phase_map = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']
        self.assertIn('execute_katana', DANGEROUS_TOOLS)
        self.assertIn('execute_katana', phase_map)

    def test_tool_matrix_contains_katana(self):
        """ToolMatrixSection.tsx should contain execute_katana."""
        tsx_path = os.path.join(
            _agentic_dir, '..', 'webapp', 'src', 'components', 'projects',
            'ProjectForm', 'sections', 'ToolMatrixSection.tsx'
        )
        with open(tsx_path) as f:
            content = f.read()
        self.assertIn("'execute_katana'", content)

    def test_dockerfile_contains_katana(self):
        """Kali sandbox Dockerfile should install katana."""
        dockerfile_path = os.path.join(
            _agentic_dir, '..', 'mcp', 'kali-sandbox', 'Dockerfile'
        )
        with open(dockerfile_path) as f:
            content = f.read()
        self.assertIn("katana", content)

    def test_mcp_server_docstring_mentions_katana(self):
        """network_recon_server.py docstring should list execute_katana."""
        server_path = os.path.join(
            _agentic_dir, '..', 'mcp', 'servers', 'network_recon_server.py'
        )
        with open(server_path) as f:
            # Read just the docstring (first 30 lines)
            lines = [next(f) for _ in range(30)]
        docstring = ''.join(lines)
        self.assertIn("execute_katana", docstring)


if __name__ == '__main__':
    unittest.main()
