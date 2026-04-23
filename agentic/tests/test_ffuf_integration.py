"""
Unit tests for FFuf agentic integration — MCP tool function, tool registry,
project settings, stealth rules, and RoE category mapping.

Run with: python -m pytest tests/test_ffuf_integration.py -v
"""

import json
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

# Add parent dir to path so we can import from agentic modules
_agentic_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _agentic_dir)

# Add MCP servers dir to path for importing execute_ffuf
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
# 1. MCP Tool Function — execute_ffuf
# ===========================================================================

class TestExecuteFfufMCPTool(unittest.TestCase):
    """Test the execute_ffuf MCP tool function in network_recon_server.py."""

    def _import_execute_ffuf(self):
        """Import execute_ffuf, stubbing FastMCP."""
        # Stub fastmcp before importing server module
        fake_mcp = MagicMock()
        fake_mcp.tool.return_value = lambda fn: fn  # decorator passthrough
        with patch.dict(sys.modules, {'fastmcp': MagicMock()}):
            # We need to import the function directly; reimport the module
            import importlib
            if 'network_recon_server' in sys.modules:
                del sys.modules['network_recon_server']
            # Patch FastMCP constructor
            with patch('fastmcp.FastMCP', return_value=fake_mcp):
                import network_recon_server
                return network_recon_server.execute_ffuf

    @patch('subprocess.run')
    def test_basic_directory_fuzzing(self, mock_run):
        """Test basic directory fuzzing returns stdout."""
        execute_ffuf = self._import_execute_ffuf()

        mock_run.return_value = MagicMock(
            stdout=":: Results ::\nhttp://target/admin  [Status: 200, Size: 1234]\nhttp://target/login  [Status: 301, Size: 0]",
            stderr="",
            returncode=0,
        )

        result = execute_ffuf(
            "-w /usr/share/seclists/Discovery/Web-Content/common.txt "
            "-u http://target/FUZZ -mc 200,301 -ac -noninteractive"
        )

        self.assertIn("http://target/admin", result)
        self.assertIn("http://target/login", result)
        self.assertIn("200", result)

        # Verify subprocess was called with correct args
        call_args = mock_run.call_args
        cmd = call_args[0][0]
        self.assertEqual(cmd[0], "ffuf")
        self.assertIn("-noninteractive", cmd)
        self.assertIn("-ac", cmd)
        self.assertEqual(call_args[1]['timeout'], 600)

    @patch('subprocess.run')
    def test_noninteractive_auto_injected(self, mock_run):
        """Test -noninteractive is auto-injected if missing."""
        execute_ffuf = self._import_execute_ffuf()

        mock_run.return_value = MagicMock(
            stdout="some output", stderr="", returncode=0,
        )

        execute_ffuf("-w wordlist.txt -u http://target/FUZZ -mc 200")

        cmd = mock_run.call_args[0][0]
        self.assertIn("-noninteractive", cmd)

    @patch('subprocess.run')
    def test_noninteractive_not_duplicated(self, mock_run):
        """Test -noninteractive is not added twice if already present."""
        execute_ffuf = self._import_execute_ffuf()

        mock_run.return_value = MagicMock(
            stdout="output", stderr="", returncode=0,
        )

        execute_ffuf("-w wordlist.txt -u http://target/FUZZ -noninteractive")

        cmd = mock_run.call_args[0][0]
        count = cmd.count("-noninteractive")
        self.assertEqual(count, 1, "Should not duplicate -noninteractive flag")

    @patch('subprocess.run')
    def test_stderr_progress_filtered(self, mock_run):
        """Test that FFuf progress/status lines are filtered from stderr."""
        execute_ffuf = self._import_execute_ffuf()

        mock_run.return_value = MagicMock(
            stdout="http://target/admin  [200]",
            stderr=(
                ":: Progress: [4750/4750] :: Job [1/1] :: 200 req/sec :: Duration: [0:00:24]\n"
                ":: Method: GET\n"
                ":: URL: http://target/FUZZ\n"
                "REAL ERROR: something broke\n"
            ),
            returncode=0,
        )

        result = execute_ffuf("-w w.txt -u http://target/FUZZ")

        # Progress/status lines should be filtered
        self.assertNotIn("Progress:", result)
        self.assertNotIn("Method:", result)
        self.assertNotIn("URL:", result)
        # Real errors should come through
        self.assertIn("REAL ERROR", result)

    @patch('subprocess.run')
    def test_stderr_banner_filtered(self, mock_run):
        """Test that FFuf ASCII banner is filtered from stderr."""
        execute_ffuf = self._import_execute_ffuf()

        banner = (
            "        /'___\\  /'___\\           /'___\\\n"
            "       /\\ \\__/ /\\ \\__/  __  __  /\\ \\__/\n"
            "       \\ \\ ,__\\\\ \\ ,__\\/\\ \\/\\ \\ \\ \\ ,__\\\n"
            "        \\ \\ \\_/ \\ \\ \\_/\\ \\ \\_\\ \\ \\ \\ \\_/\n"
            "         \\ \\_\\   \\ \\_\\  \\ \\____/  \\ \\_\\\n"
            "          \\/_/    \\/_/   \\/___/    \\/_/\n"
            "       v2.1.0-dev\n"
            "________________________________________________\n"
            "________________________________________________\n"
        )
        mock_run.return_value = MagicMock(
            stdout="http://target/admin  [200]",
            stderr=banner,
            returncode=0,
        )

        result = execute_ffuf("-w w.txt -u http://target/FUZZ")

        self.assertNotIn("/'___\\", result)
        self.assertNotIn("v2.1.0", result)
        self.assertNotIn("________________________________________________", result)
        self.assertNotIn("[STDERR]", result)

    @patch('subprocess.run')
    def test_empty_output_returns_info(self, mock_run):
        """Test empty output returns info message."""
        execute_ffuf = self._import_execute_ffuf()

        mock_run.return_value = MagicMock(
            stdout="", stderr="", returncode=0,
        )

        result = execute_ffuf("-w w.txt -u http://target/FUZZ")

        self.assertIn("[INFO]", result)
        self.assertIn("No results found", result)

    @patch('subprocess.run')
    def test_timeout_returns_error(self, mock_run):
        """Test timeout returns descriptive error."""
        execute_ffuf = self._import_execute_ffuf()

        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="ffuf", timeout=600)

        result = execute_ffuf("-w big.txt -u http://target/FUZZ")

        self.assertIn("[ERROR]", result)
        self.assertIn("timed out", result)
        self.assertIn("600", result)

    @patch('subprocess.run')
    def test_file_not_found_returns_error(self, mock_run):
        """Test missing binary returns descriptive error."""
        execute_ffuf = self._import_execute_ffuf()

        mock_run.side_effect = FileNotFoundError()

        result = execute_ffuf("-w w.txt -u http://target/FUZZ")

        self.assertIn("[ERROR]", result)
        self.assertIn("ffuf not found", result)

    @patch('subprocess.run')
    def test_ansi_codes_stripped(self, mock_run):
        """Test ANSI escape codes are removed from output."""
        execute_ffuf = self._import_execute_ffuf()

        mock_run.return_value = MagicMock(
            stdout="\x1b[32mhttp://target/admin\x1b[0m  [Status: 200]",
            stderr="",
            returncode=0,
        )

        result = execute_ffuf("-w w.txt -u http://target/FUZZ")

        self.assertNotIn("\x1b[", result)
        self.assertIn("http://target/admin", result)

    @patch('subprocess.run')
    def test_generic_exception_returns_error(self, mock_run):
        """Test generic exception returns error message."""
        execute_ffuf = self._import_execute_ffuf()

        mock_run.side_effect = OSError("Permission denied")

        result = execute_ffuf("-w w.txt -u http://target/FUZZ")

        self.assertIn("[ERROR]", result)
        self.assertIn("Permission denied", result)

    @patch('subprocess.run')
    def test_shlex_parsing(self, mock_run):
        """Test that quoted arguments are correctly parsed via shlex."""
        execute_ffuf = self._import_execute_ffuf()

        mock_run.return_value = MagicMock(
            stdout="output", stderr="", returncode=0,
        )

        execute_ffuf(
            "-w w.txt -u http://target/FUZZ -H 'Host: FUZZ.target.tld' -fs 0"
        )

        cmd = mock_run.call_args[0][0]
        self.assertIn("Host: FUZZ.target.tld", cmd)
        self.assertIn("-fs", cmd)

    @patch('subprocess.run')
    def test_timeout_is_600_seconds(self, mock_run):
        """Verify the subprocess timeout is set to 600 seconds."""
        execute_ffuf = self._import_execute_ffuf()

        mock_run.return_value = MagicMock(
            stdout="output", stderr="", returncode=0,
        )

        execute_ffuf("-w w.txt -u http://target/FUZZ")

        self.assertEqual(mock_run.call_args[1]['timeout'], 600)
        self.assertTrue(mock_run.call_args[1]['capture_output'])
        self.assertTrue(mock_run.call_args[1]['text'])


# ===========================================================================
# 2. Tool Registry
# ===========================================================================

class TestFfufToolRegistry(unittest.TestCase):
    """Test execute_ffuf entry in TOOL_REGISTRY."""

    def test_execute_ffuf_in_registry(self):
        from prompts.tool_registry import TOOL_REGISTRY
        self.assertIn("execute_ffuf", TOOL_REGISTRY)

    def test_registry_has_required_keys(self):
        from prompts.tool_registry import TOOL_REGISTRY
        entry = TOOL_REGISTRY["execute_ffuf"]
        self.assertIn("purpose", entry)
        self.assertIn("when_to_use", entry)
        self.assertIn("args_format", entry)
        self.assertIn("description", entry)

    def test_registry_purpose_mentions_fuzzing(self):
        from prompts.tool_registry import TOOL_REGISTRY
        entry = TOOL_REGISTRY["execute_ffuf"]
        self.assertIn("fuzz", entry["purpose"].lower())

    def test_registry_description_mentions_wordlists(self):
        from prompts.tool_registry import TOOL_REGISTRY
        entry = TOOL_REGISTRY["execute_ffuf"]
        self.assertIn("common.txt", entry["description"])
        self.assertIn("big.txt", entry["description"])

    def test_registry_description_mentions_noninteractive(self):
        from prompts.tool_registry import TOOL_REGISTRY
        entry = TOOL_REGISTRY["execute_ffuf"]
        self.assertIn("-noninteractive", entry["description"])

    def test_registry_description_mentions_fuzz_keyword(self):
        from prompts.tool_registry import TOOL_REGISTRY
        entry = TOOL_REGISTRY["execute_ffuf"]
        self.assertIn("FUZZ", entry["description"])

    def test_registry_args_format(self):
        from prompts.tool_registry import TOOL_REGISTRY
        entry = TOOL_REGISTRY["execute_ffuf"]
        self.assertIn("args", entry["args_format"])

    def test_registry_ordering_before_msf(self):
        """execute_ffuf should appear before msf_restart in registry."""
        from prompts.tool_registry import TOOL_REGISTRY
        keys = list(TOOL_REGISTRY.keys())
        ffuf_idx = keys.index("execute_ffuf")
        msf_idx = keys.index("msf_restart")
        self.assertLess(ffuf_idx, msf_idx)


# ===========================================================================
# 3. Project Settings
# ===========================================================================

class TestFfufProjectSettings(unittest.TestCase):
    """Test execute_ffuf in project_settings.py."""

    def test_in_dangerous_tools(self):
        from project_settings import DANGEROUS_TOOLS
        self.assertIn('execute_ffuf', DANGEROUS_TOOLS)

    def test_in_tool_phase_map(self):
        from project_settings import DEFAULT_AGENT_SETTINGS
        phase_map = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']
        self.assertIn('execute_ffuf', phase_map)

    def test_phase_map_informational(self):
        from project_settings import DEFAULT_AGENT_SETTINGS
        phases = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']['execute_ffuf']
        self.assertIn('informational', phases)

    def test_phase_map_exploitation(self):
        from project_settings import DEFAULT_AGENT_SETTINGS
        phases = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']['execute_ffuf']
        self.assertIn('exploitation', phases)

    def test_phase_map_not_post_exploitation(self):
        from project_settings import DEFAULT_AGENT_SETTINGS
        phases = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']['execute_ffuf']
        self.assertNotIn('post_exploitation', phases)

    def test_phase_map_matches_naabu_pattern(self):
        """FFuf should have same phases as execute_naabu (active scanning tools)."""
        from project_settings import DEFAULT_AGENT_SETTINGS
        phase_map = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']
        self.assertEqual(
            sorted(phase_map['execute_ffuf']),
            sorted(phase_map['execute_naabu']),
        )


# ===========================================================================
# 4. Phase Enforcement
# ===========================================================================

class TestFfufPhaseEnforcement(unittest.TestCase):
    """Test execute_ffuf phase restriction logic."""

    def test_allowed_in_informational(self):
        from project_settings import is_tool_allowed_in_phase
        self.assertTrue(is_tool_allowed_in_phase('execute_ffuf', 'informational'))

    def test_allowed_in_exploitation(self):
        from project_settings import is_tool_allowed_in_phase
        self.assertTrue(is_tool_allowed_in_phase('execute_ffuf', 'exploitation'))

    def test_blocked_in_post_exploitation(self):
        from project_settings import is_tool_allowed_in_phase
        self.assertFalse(is_tool_allowed_in_phase('execute_ffuf', 'post_exploitation'))


# ===========================================================================
# 5. Stealth Rules
# ===========================================================================

class TestFfufStealthRules(unittest.TestCase):
    """Test execute_ffuf stealth mode constraints."""

    def test_stealth_rules_contain_ffuf_section(self):
        from prompts.stealth_rules import STEALTH_MODE_RULES
        self.assertIn("execute_ffuf", STEALTH_MODE_RULES)

    def test_stealth_rules_ffuf_forbidden(self):
        from prompts.stealth_rules import STEALTH_MODE_RULES
        # Find the ffuf section and verify it says FORBIDDEN
        ffuf_idx = STEALTH_MODE_RULES.index("execute_ffuf")
        section = STEALTH_MODE_RULES[ffuf_idx:ffuf_idx + 200]
        self.assertIn("FORBIDDEN", section)

    def test_stealth_rules_suggest_curl_alternative(self):
        from prompts.stealth_rules import STEALTH_MODE_RULES
        ffuf_idx = STEALTH_MODE_RULES.index("execute_ffuf")
        section = STEALTH_MODE_RULES[ffuf_idx:ffuf_idx + 300]
        self.assertIn("execute_curl", section)


# ===========================================================================
# 6. RoE Category Mapping
# ===========================================================================

class TestFfufRoECategory(unittest.TestCase):
    """Test execute_ffuf in RoE CATEGORY_TOOL_MAP."""

    def test_ffuf_in_brute_force_category(self):
        """execute_ffuf should be in the brute_force RoE category."""
        # Read the source file directly since the function is deeply nested
        plan_node_path = os.path.join(
            _agentic_dir, 'orchestrator_helpers', 'nodes', 'execute_plan_node.py'
        )
        with open(plan_node_path) as f:
            source = f.read()
        self.assertIn("'execute_ffuf'", source)
        # Verify it's in the brute_force line
        for line in source.split('\n'):
            if 'brute_force' in line and 'CATEGORY_TOOL_MAP' not in line:
                self.assertIn('execute_ffuf', line)
                break
        else:
            self.fail("Could not find brute_force category line with execute_ffuf")


# ===========================================================================
# 7. Prisma Schema Consistency
# ===========================================================================

class TestFfufPrismaSchema(unittest.TestCase):
    """Test execute_ffuf in Prisma schema default."""

    def _parse_prisma_default(self):
        """Parse the agentToolPhaseMap default JSON from schema.prisma."""
        import re
        schema_path = os.path.join(
            _agentic_dir, '..', 'webapp', 'prisma', 'schema.prisma'
        )
        with open(schema_path) as f:
            content = f.read()

        # Find the agentToolPhaseMap line
        for line in content.split('\n'):
            if 'agentToolPhaseMap' in line and '@default' in line:
                m = re.search(r'@default\("(.+?)"\)\s+@map', line)
                if m:
                    raw = m.group(1).replace('\\"', '"')
                    return json.loads(raw)
        self.fail("Could not find agentToolPhaseMap default in schema.prisma")

    def test_ffuf_in_prisma_default(self):
        prisma_map = self._parse_prisma_default()
        self.assertIn('execute_ffuf', prisma_map)

    def test_prisma_phases_match_python(self):
        """Prisma default phases for ffuf should match Python TOOL_PHASE_MAP."""
        from project_settings import DEFAULT_AGENT_SETTINGS
        prisma_map = self._parse_prisma_default()
        python_phases = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']['execute_ffuf']
        self.assertEqual(
            sorted(prisma_map['execute_ffuf']),
            sorted(python_phases),
        )

    def test_prisma_keys_subset_of_python(self):
        """All tools in Prisma default should exist in Python TOOL_PHASE_MAP."""
        from project_settings import DEFAULT_AGENT_SETTINGS
        prisma_map = self._parse_prisma_default()
        python_map = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']
        # Every Prisma key should exist in Python (Prisma may lag behind Python)
        for key in prisma_map:
            self.assertIn(key, python_map, f"Prisma has '{key}' but Python TOOL_PHASE_MAP does not")


# ===========================================================================
# 8. Cross-Layer Consistency
# ===========================================================================

class TestFfufCrossLayerConsistency(unittest.TestCase):
    """Verify execute_ffuf is consistently registered across all layers."""

    def test_registry_and_phase_map_consistent(self):
        """Every tool in TOOL_REGISTRY that starts with execute_ should be in TOOL_PHASE_MAP."""
        from prompts.tool_registry import TOOL_REGISTRY
        from project_settings import DEFAULT_AGENT_SETTINGS
        phase_map = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']
        self.assertIn('execute_ffuf', TOOL_REGISTRY)
        self.assertIn('execute_ffuf', phase_map)

    def test_dangerous_tool_is_in_phase_map(self):
        """execute_ffuf is in both DANGEROUS_TOOLS and TOOL_PHASE_MAP."""
        from project_settings import DANGEROUS_TOOLS, DEFAULT_AGENT_SETTINGS
        phase_map = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']
        self.assertIn('execute_ffuf', DANGEROUS_TOOLS)
        self.assertIn('execute_ffuf', phase_map)

    def test_tool_matrix_contains_ffuf(self):
        """ToolMatrixSection.tsx should contain execute_ffuf."""
        tsx_path = os.path.join(
            _agentic_dir, '..', 'webapp', 'src', 'components', 'projects',
            'ProjectForm', 'sections', 'ToolMatrixSection.tsx'
        )
        with open(tsx_path) as f:
            content = f.read()
        self.assertIn("'execute_ffuf'", content)


if __name__ == '__main__':
    unittest.main()
