"""
Unit tests for subfinder integration into the agentic system.
Validates cross-file consistency, MCP tool function behavior, and data integrity.
"""
import json
import re
import sys
import os
import unittest
from unittest.mock import patch, MagicMock

# Add project roots to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'agentic'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'mcp', 'servers'))

BASE_DIR = os.path.join(os.path.dirname(__file__), '..')

# ---------------------------------------------------------------------------
# Stub heavy dependencies so we can import MCP server module without FastMCP
# ---------------------------------------------------------------------------
_stubs = {}
for mod_name in ['fastmcp']:
    if mod_name not in sys.modules:
        stub = MagicMock()
        # Make @mcp.tool() a no-op decorator that returns the function unchanged
        stub.FastMCP.return_value.tool.return_value = lambda fn: fn
        _stubs[mod_name] = stub
        sys.modules[mod_name] = stub


class TestToolRegistrySubfinder(unittest.TestCase):
    """Verify tool_registry.py has correct subfinder entry."""

    def setUp(self):
        from prompts.tool_registry import TOOL_REGISTRY
        self.registry = TOOL_REGISTRY

    def test_subfinder_in_registry(self):
        """execute_subfinder must be registered."""
        self.assertIn('execute_subfinder', self.registry)

    def test_subfinder_has_required_fields(self):
        """execute_subfinder entry must have all required fields."""
        entry = self.registry['execute_subfinder']
        for field in ('purpose', 'when_to_use', 'args_format', 'description'):
            self.assertIn(field, entry, f"Missing field: {field}")
            self.assertTrue(len(entry[field]) > 0, f"Empty field: {field}")

    def test_subfinder_description_mentions_passive(self):
        """Description should emphasize passive nature."""
        desc = self.registry['execute_subfinder']['description']
        self.assertIn('passive', desc.lower())
        self.assertIn('OSINT', desc)

    def test_subfinder_description_mentions_json(self):
        """Description should mention -json flag."""
        desc = self.registry['execute_subfinder']['description']
        self.assertIn('-json', desc)

    def test_subfinder_args_format(self):
        """args_format must match MCP tool parameter name."""
        fmt = self.registry['execute_subfinder']['args_format']
        self.assertIn('"args"', fmt)
        self.assertIn('subfinder', fmt)

    def test_subfinder_position_after_naabu(self):
        """execute_subfinder must come after execute_naabu in registry order."""
        keys = list(self.registry.keys())
        naabu_idx = keys.index('execute_naabu')
        subfinder_idx = keys.index('execute_subfinder')
        self.assertEqual(subfinder_idx, naabu_idx + 1,
                        "execute_subfinder must be immediately after execute_naabu")

    def test_subfinder_position_before_nmap(self):
        """execute_subfinder must come before execute_nmap in registry order."""
        keys = list(self.registry.keys())
        subfinder_idx = keys.index('execute_subfinder')
        nmap_idx = keys.index('execute_nmap')
        self.assertLess(subfinder_idx, nmap_idx)


class TestProjectSettings(unittest.TestCase):
    """Verify project_settings.py changes."""

    def setUp(self):
        from project_settings import DEFAULT_AGENT_SETTINGS, DANGEROUS_TOOLS
        self.phase_map = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']
        self.dangerous = DANGEROUS_TOOLS

    def test_subfinder_in_tool_phase_map(self):
        """execute_subfinder must be in TOOL_PHASE_MAP."""
        self.assertIn('execute_subfinder', self.phase_map)

    def test_subfinder_phases_correct(self):
        """execute_subfinder must be available in informational and exploitation only."""
        self.assertEqual(
            self.phase_map['execute_subfinder'],
            ['informational', 'exploitation']
        )

    def test_subfinder_not_in_dangerous_tools(self):
        """execute_subfinder must NOT be in DANGEROUS_TOOLS (passive tool)."""
        self.assertNotIn('execute_subfinder', self.dangerous)


class TestPrismaSchema(unittest.TestCase):
    """Verify schema.prisma JSON default includes subfinder."""

    def setUp(self):
        path = os.path.join(BASE_DIR, 'webapp', 'prisma', 'schema.prisma')
        with open(path) as f:
            self.content = f.read()
        match = re.search(r'agentToolPhaseMap\s+Json\s+@default\("(.+?)"\)\s+@map', self.content)
        self.assertIsNotNone(match, "Could not find agentToolPhaseMap default")
        self.raw_json = match.group(1)
        unescaped = self.raw_json.replace('\\"', '"')
        self.data = json.loads(unescaped)

    def test_subfinder_in_schema_default(self):
        """execute_subfinder must be in the schema default JSON."""
        self.assertIn('execute_subfinder', self.data)

    def test_subfinder_phases_in_schema(self):
        """execute_subfinder phases must match in schema."""
        self.assertEqual(
            self.data['execute_subfinder'],
            ['informational', 'exploitation']
        )

    def test_json_still_valid(self):
        """The full JSON default must still be parseable."""
        unescaped = self.raw_json.replace('\\"', '"')
        try:
            data = json.loads(unescaped)
        except json.JSONDecodeError as e:
            self.fail(f"JSON is not valid after subfinder addition: {e}")
        self.assertIsInstance(data, dict)


class TestStealthRules(unittest.TestCase):
    """Verify stealth_rules.py has subfinder section."""

    def setUp(self):
        path = os.path.join(BASE_DIR, 'agentic', 'prompts', 'stealth_rules.py')
        with open(path) as f:
            self.content = f.read()
            self.lines = self.content.split('\n')

    def test_subfinder_section_exists(self):
        """execute_subfinder stealth section must exist."""
        self.assertIn('### execute_subfinder', self.content)

    def test_subfinder_no_restrictions(self):
        """Subfinder should have NO RESTRICTIONS (passive OSINT)."""
        match = re.search(r'### execute_subfinder\s*[—\-]+\s*NO RESTRICTIONS', self.content)
        self.assertIsNotNone(match,
            "Heading must be '### execute_subfinder -- NO RESTRICTIONS'")

    def test_subfinder_mentions_passive(self):
        """Stealth rules must mention passive nature."""
        start = self.content.index('### execute_subfinder')
        # Find next section
        next_match = re.search(r'\n### ', self.content[start + 1:])
        if next_match:
            section = self.content[start:start + 1 + next_match.start()]
        else:
            section = self.content[start:]
        self.assertIn('passive', section.lower())
        self.assertIn('NO traffic', section)

    def test_subfinder_between_naabu_and_nmap(self):
        """Subfinder section must be between naabu and nmap sections."""
        naabu_pos = self.content.index('### execute_naabu')
        subfinder_pos = self.content.index('### execute_subfinder')
        nmap_pos = self.content.index('### execute_nmap')
        self.assertGreater(subfinder_pos, naabu_pos)
        self.assertLess(subfinder_pos, nmap_pos)

    def test_blank_line_before_subfinder(self):
        """There must be a blank line before the subfinder section heading."""
        for i, line in enumerate(self.lines):
            if '### execute_subfinder' in line:
                prev_line = self.lines[i - 1].strip()
                self.assertEqual(prev_line, '',
                    f"Expected blank line before subfinder heading, got: '{prev_line}'")
                break


class TestToolMatrixSection(unittest.TestCase):
    """Verify ToolMatrixSection.tsx includes subfinder."""

    def setUp(self):
        path = os.path.join(BASE_DIR, 'webapp', 'src', 'components', 'projects',
                           'ProjectForm', 'sections', 'ToolMatrixSection.tsx')
        with open(path) as f:
            self.content = f.read()

    def test_subfinder_in_tool_list(self):
        """execute_subfinder must appear in the tool list."""
        self.assertIn("id: 'execute_subfinder'", self.content)

    def test_no_duplicate_subfinder(self):
        """execute_subfinder must appear exactly once."""
        count = self.content.count("id: 'execute_subfinder'")
        self.assertEqual(count, 1, f"execute_subfinder appears {count} times, expected 1")

    def test_subfinder_after_naabu(self):
        """execute_subfinder must come after execute_naabu in the tool list."""
        naabu_pos = self.content.index("id: 'execute_naabu'")
        subfinder_pos = self.content.index("id: 'execute_subfinder'")
        self.assertGreater(subfinder_pos, naabu_pos)

    def test_subfinder_before_nmap(self):
        """execute_subfinder must come before execute_nmap."""
        subfinder_pos = self.content.index("id: 'execute_subfinder'")
        nmap_pos = self.content.index("id: 'execute_nmap'")
        self.assertLess(subfinder_pos, nmap_pos)


class TestRoECategoryMap(unittest.TestCase):
    """Verify execute_subfinder is NOT in any RoE category (passive tool)."""

    def setUp(self):
        path = os.path.join(BASE_DIR, 'agentic', 'orchestrator_helpers', 'nodes', 'execute_plan_node.py')
        with open(path) as f:
            self.content = f.read()

    def test_subfinder_not_in_any_roe_category(self):
        """execute_subfinder must NOT be in CATEGORY_TOOL_MAP (not an attack tool)."""
        match = re.search(r"CATEGORY_TOOL_MAP\s*=\s*\{([^}]+)\}", self.content)
        self.assertIsNotNone(match, "Could not find CATEGORY_TOOL_MAP")
        map_content = match.group(1)
        self.assertNotIn('execute_subfinder', map_content)


class TestDockerfileInstallation(unittest.TestCase):
    """Verify kali-sandbox Dockerfile installs subfinder."""

    def setUp(self):
        path = os.path.join(BASE_DIR, 'mcp', 'kali-sandbox', 'Dockerfile')
        with open(path) as f:
            self.content = f.read()

    def test_subfinder_go_install(self):
        """Dockerfile must have go install for subfinder."""
        self.assertIn('projectdiscovery/subfinder', self.content)

    def test_subfinder_v2_module(self):
        """Must use v2 module path."""
        self.assertIn('subfinder/v2/cmd/subfinder@latest', self.content)

    def test_subfinder_in_pd_tools_comment(self):
        """Comment should mention subfinder in the PD tools list."""
        self.assertIn('subfinder', self.content.split('go install')[0].rsplit('#', 1)[-1]
                      if 'subfinder' in self.content else '')
        # Simpler check: comment line mentioning subfinder before the go install block
        lines = self.content.split('\n')
        for i, line in enumerate(lines):
            if 'projectdiscovery/subfinder' in line:
                # Check preceding comment lines mention subfinder
                preceding = '\n'.join(lines[max(0, i-5):i])
                self.assertIn('subfinder', preceding.lower(),
                    "Comment above go install should mention subfinder")
                break


class TestCrossFileConsistency(unittest.TestCase):
    """Verify all files agree on subfinder presence and phases."""

    def setUp(self):
        from prompts.tool_registry import TOOL_REGISTRY
        from project_settings import DEFAULT_AGENT_SETTINGS, DANGEROUS_TOOLS
        self.registry = TOOL_REGISTRY
        self.phase_map = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']
        self.dangerous = DANGEROUS_TOOLS

        # Parse Prisma schema JSON
        schema_path = os.path.join(BASE_DIR, 'webapp', 'prisma', 'schema.prisma')
        with open(schema_path) as f:
            schema = f.read()
        match = re.search(r'agentToolPhaseMap\s+Json\s+@default\("(.+?)"\)\s+@map', schema)
        raw = match.group(1).replace('\\"', '"')
        self.prisma_phase_map = json.loads(raw)

        # Parse ToolMatrix tools
        tsx_path = os.path.join(BASE_DIR, 'webapp', 'src', 'components', 'projects',
                               'ProjectForm', 'sections', 'ToolMatrixSection.tsx')
        with open(tsx_path) as f:
            tsx = f.read()
        self.matrix_tools = set(re.findall(r"id: '(\w+)'", tsx))

        # Stealth rules
        stealth_path = os.path.join(BASE_DIR, 'agentic', 'prompts', 'stealth_rules.py')
        with open(stealth_path) as f:
            self.stealth_content = f.read()

    def test_subfinder_in_all_required_locations(self):
        """execute_subfinder must be present in all required locations."""
        self.assertIn('execute_subfinder', self.registry)
        self.assertIn('execute_subfinder', self.phase_map)
        self.assertIn('execute_subfinder', self.prisma_phase_map)
        self.assertIn('execute_subfinder', self.matrix_tools)
        self.assertIn('execute_subfinder', self.stealth_content)

    def test_subfinder_not_in_dangerous(self):
        """execute_subfinder must NOT be in DANGEROUS_TOOLS."""
        self.assertNotIn('execute_subfinder', self.dangerous)

    def test_subfinder_in_both_phase_maps(self):
        """execute_subfinder must be in both Python and Prisma phase maps."""
        self.assertIn('execute_subfinder', self.phase_map)
        self.assertIn('execute_subfinder', self.prisma_phase_map)

    def test_subfinder_phase_values_match(self):
        """Phase arrays must match between Python and Prisma for subfinder."""
        py_phases = self.phase_map['execute_subfinder']
        prisma_phases = self.prisma_phase_map['execute_subfinder']
        self.assertEqual(py_phases, prisma_phases,
                       f"Phase mismatch: Python={py_phases}, Prisma={prisma_phases}")

    def test_matrix_covers_phase_map(self):
        """Every tool in TOOL_PHASE_MAP should be in the Tool Matrix UI."""
        py_tools = set(self.phase_map.keys())
        missing = py_tools - self.matrix_tools
        self.assertEqual(missing, set(),
                        f"Tools in TOOL_PHASE_MAP but missing from ToolMatrix: {missing}")


class TestMCPToolFunction(unittest.TestCase):
    """Unit tests for the execute_subfinder MCP tool function."""

    def setUp(self):
        # Import the actual function (FastMCP is stubbed, so @mcp.tool() is a no-op)
        import importlib
        # Need to reload to get the unstubbed function
        if 'network_recon_server' in sys.modules:
            mod = importlib.reload(sys.modules['network_recon_server'])
        else:
            mod = importlib.import_module('network_recon_server')
        self.execute_subfinder = mod.execute_subfinder

    @patch('network_recon_server.subprocess.run')
    def test_basic_execution(self, mock_run):
        """Tool should run subfinder with correct args."""
        mock_run.return_value = MagicMock(
            stdout='sub1.example.com\nsub2.example.com\n',
            stderr='',
            returncode=0
        )
        result = self.execute_subfinder('-d example.com -silent')
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        self.assertEqual(cmd[0], 'subfinder')
        self.assertIn('-d', cmd)
        self.assertIn('example.com', cmd)
        self.assertIn('-silent', cmd)
        self.assertIn('sub1.example.com', result)
        self.assertIn('sub2.example.com', result)

    @patch('network_recon_server.subprocess.run')
    def test_json_output(self, mock_run):
        """Tool should pass through JSON output correctly."""
        json_output = '{"host":"sub1.example.com","source":"crtsh","input":"example.com"}\n'
        mock_run.return_value = MagicMock(
            stdout=json_output,
            stderr='',
            returncode=0
        )
        result = self.execute_subfinder('-d example.com -json -silent')
        self.assertIn('sub1.example.com', result)
        self.assertIn('crtsh', result)

    @patch('network_recon_server.subprocess.run')
    def test_empty_output(self, mock_run):
        """Tool should return info message when no subdomains found."""
        mock_run.return_value = MagicMock(
            stdout='', stderr='', returncode=0
        )
        result = self.execute_subfinder('-d nonexistent.invalid -silent')
        self.assertEqual(result, '[INFO] No subdomains found')

    @patch('network_recon_server.subprocess.run')
    def test_ansi_stripping(self, mock_run):
        """Tool should strip ANSI escape codes from output."""
        mock_run.return_value = MagicMock(
            stdout='\x1b[32msub1.example.com\x1b[0m\n',
            stderr='',
            returncode=0
        )
        result = self.execute_subfinder('-d example.com -silent')
        self.assertNotIn('\x1b', result)
        self.assertIn('sub1.example.com', result)

    @patch('network_recon_server.subprocess.run')
    def test_stderr_inf_filtering(self, mock_run):
        """Tool should filter out [INF] lines from stderr."""
        mock_run.return_value = MagicMock(
            stdout='sub1.example.com\n',
            stderr='[INF] Loading provider config\n[INF] Running enumeration\n',
            returncode=0
        )
        result = self.execute_subfinder('-d example.com -silent')
        self.assertNotIn('[INF]', result)
        self.assertNotIn('[STDERR]', result)
        self.assertIn('sub1.example.com', result)

    @patch('network_recon_server.subprocess.run')
    def test_stderr_errors_kept(self, mock_run):
        """Tool should keep non-INF stderr lines."""
        mock_run.return_value = MagicMock(
            stdout='',
            stderr='[INF] Loading config\n[ERR] Failed to connect to source\n',
            returncode=0
        )
        result = self.execute_subfinder('-d example.com -silent')
        self.assertIn('[STDERR]', result)
        self.assertIn('Failed to connect', result)

    @patch('network_recon_server.subprocess.run')
    def test_timeout_handling(self, mock_run):
        """Tool should handle subprocess timeout gracefully."""
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd='subfinder', timeout=120)
        result = self.execute_subfinder('-d example.com -all -silent')
        self.assertIn('[ERROR]', result)
        self.assertIn('timed out', result)
        self.assertIn('120', result)

    @patch('network_recon_server.subprocess.run')
    def test_file_not_found(self, mock_run):
        """Tool should handle missing binary gracefully."""
        mock_run.side_effect = FileNotFoundError()
        result = self.execute_subfinder('-d example.com -silent')
        self.assertIn('[ERROR]', result)
        self.assertIn('subfinder not found', result)

    @patch('network_recon_server.subprocess.run')
    def test_generic_exception(self, mock_run):
        """Tool should handle unexpected exceptions."""
        mock_run.side_effect = OSError('Permission denied')
        result = self.execute_subfinder('-d example.com')
        self.assertIn('[ERROR]', result)
        self.assertIn('Permission denied', result)

    @patch('network_recon_server.subprocess.run')
    def test_timeout_value(self, mock_run):
        """Tool must use 120s timeout."""
        mock_run.return_value = MagicMock(stdout='', stderr='', returncode=0)
        self.execute_subfinder('-d example.com')
        _, kwargs = mock_run.call_args
        self.assertEqual(kwargs.get('timeout'), 120)

    @patch('network_recon_server.subprocess.run')
    def test_capture_output_enabled(self, mock_run):
        """Tool must use capture_output=True."""
        mock_run.return_value = MagicMock(stdout='', stderr='', returncode=0)
        self.execute_subfinder('-d example.com')
        _, kwargs = mock_run.call_args
        self.assertTrue(kwargs.get('capture_output'))
        self.assertTrue(kwargs.get('text'))

    @patch('network_recon_server.subprocess.run')
    def test_shlex_split_args(self, mock_run):
        """Tool should correctly split complex args."""
        mock_run.return_value = MagicMock(stdout='result\n', stderr='', returncode=0)
        self.execute_subfinder('-d example.com -sources crtsh,hackertarget -json -silent')
        cmd = mock_run.call_args[0][0]
        self.assertEqual(cmd, [
            'subfinder', '-d', 'example.com',
            '-sources', 'crtsh,hackertarget',
            '-json', '-silent'
        ])


if __name__ == '__main__':
    unittest.main(verbosity=2)
