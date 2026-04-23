"""
Unit tests for amass integration into the agentic system.
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


class TestToolRegistryAmass(unittest.TestCase):
    """Verify tool_registry.py has correct amass entry."""

    def setUp(self):
        from prompts.tool_registry import TOOL_REGISTRY
        self.registry = TOOL_REGISTRY

    def test_amass_in_registry(self):
        """execute_amass must be registered."""
        self.assertIn('execute_amass', self.registry)

    def test_amass_has_required_fields(self):
        """execute_amass entry must have all required fields."""
        entry = self.registry['execute_amass']
        for field in ('purpose', 'when_to_use', 'args_format', 'description'):
            self.assertIn(field, entry, f"Missing field: {field}")
            self.assertTrue(len(entry[field]) > 0, f"Empty field: {field}")

    def test_amass_description_mentions_subdomain(self):
        """Description should mention subdomain discovery."""
        desc = self.registry['execute_amass']['description']
        self.assertIn('subdomain', desc.lower())

    def test_amass_description_mentions_passive(self):
        """Description should mention passive mode."""
        desc = self.registry['execute_amass']['description']
        self.assertIn('-passive', desc)

    def test_amass_description_mentions_timeout(self):
        """Description should mention -timeout flag."""
        desc = self.registry['execute_amass']['description']
        self.assertIn('-timeout', desc)

    def test_amass_args_format(self):
        """args_format must match MCP tool parameter name."""
        fmt = self.registry['execute_amass']['args_format']
        self.assertIn('"args"', fmt)
        self.assertIn('amass', fmt)

    def test_amass_position_after_nmap(self):
        """execute_amass must come after execute_nmap in registry order."""
        keys = list(self.registry.keys())
        nmap_idx = keys.index('execute_nmap')
        amass_idx = keys.index('execute_amass')
        self.assertGreater(amass_idx, nmap_idx)

    def test_amass_position_before_kali_shell(self):
        """execute_amass must come before kali_shell in registry order."""
        keys = list(self.registry.keys())
        amass_idx = keys.index('execute_amass')
        kali_idx = keys.index('kali_shell')
        self.assertLess(amass_idx, kali_idx)


class TestKaliShellExcludesAmass(unittest.TestCase):
    """Verify kali_shell description directs users to dedicated amass tool."""

    def setUp(self):
        from prompts.tool_registry import TOOL_REGISTRY
        self.kali_desc = TOOL_REGISTRY['kali_shell']['description']

    def test_amass_in_kali_cli_tools_list(self):
        """kali_shell CLI tools list should mention amass."""
        self.assertIn('amass', self.kali_desc)

    def test_amass_in_exclusion_list(self):
        """kali_shell exclusion list must include amass."""
        # Find the "Do NOT use for:" line
        self.assertIn('amass', self.kali_desc)
        do_not_use_match = re.search(r'Do NOT use for:.*', self.kali_desc)
        self.assertIsNotNone(do_not_use_match, "Missing 'Do NOT use for:' line")
        self.assertIn('amass', do_not_use_match.group(0))


class TestProjectSettings(unittest.TestCase):
    """Verify project_settings.py changes."""

    def setUp(self):
        from project_settings import DEFAULT_AGENT_SETTINGS, DANGEROUS_TOOLS
        self.phase_map = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']
        self.dangerous = DANGEROUS_TOOLS

    def test_amass_in_tool_phase_map(self):
        """execute_amass must be in TOOL_PHASE_MAP."""
        self.assertIn('execute_amass', self.phase_map)

    def test_amass_phases_correct(self):
        """execute_amass must be available in all three phases."""
        self.assertEqual(
            self.phase_map['execute_amass'],
            ['informational', 'exploitation', 'post_exploitation']
        )

    def test_amass_in_dangerous_tools(self):
        """execute_amass must be in DANGEROUS_TOOLS (active DNS queries)."""
        self.assertIn('execute_amass', self.dangerous)


class TestPrismaSchema(unittest.TestCase):
    """Verify schema.prisma JSON default includes amass."""

    def setUp(self):
        path = os.path.join(BASE_DIR, 'webapp', 'prisma', 'schema.prisma')
        with open(path) as f:
            self.content = f.read()
        match = re.search(r'agentToolPhaseMap\s+Json\s+@default\("(.+?)"\)\s+@map', self.content)
        self.assertIsNotNone(match, "Could not find agentToolPhaseMap default")
        self.raw_json = match.group(1)
        unescaped = self.raw_json.replace('\\"', '"')
        self.data = json.loads(unescaped)

    def test_amass_in_schema_default(self):
        """execute_amass must be in the schema default JSON."""
        self.assertIn('execute_amass', self.data)

    def test_amass_phases_in_schema(self):
        """execute_amass phases must match in schema."""
        self.assertEqual(
            self.data['execute_amass'],
            ['informational', 'exploitation', 'post_exploitation']
        )

    def test_json_still_valid(self):
        """The full JSON default must still be parseable."""
        unescaped = self.raw_json.replace('\\"', '"')
        try:
            data = json.loads(unescaped)
        except json.JSONDecodeError as e:
            self.fail(f"JSON is not valid after amass addition: {e}")
        self.assertIsInstance(data, dict)


class TestStealthRules(unittest.TestCase):
    """Verify stealth_rules.py has amass section."""

    def setUp(self):
        path = os.path.join(BASE_DIR, 'agentic', 'prompts', 'stealth_rules.py')
        with open(path) as f:
            self.content = f.read()
            self.lines = self.content.split('\n')

    def test_amass_section_exists(self):
        """execute_amass stealth section must exist."""
        self.assertIn('### execute_amass', self.content)

    def test_amass_heavily_restricted(self):
        """Amass should be HEAVILY RESTRICTED (active DNS in non-passive mode)."""
        match = re.search(r'### execute_amass\s*[—\-]+\s*HEAVILY RESTRICTED', self.content)
        self.assertIsNotNone(match,
            "Heading must be '### execute_amass -- HEAVILY RESTRICTED'")

    def test_amass_requires_passive_flag(self):
        """Stealth rules must require -passive flag."""
        start = self.content.index('### execute_amass')
        next_match = re.search(r'\n### ', self.content[start + 1:])
        if next_match:
            section = self.content[start:start + 1 + next_match.start()]
        else:
            section = self.content[start:]
        self.assertIn('-passive', section)

    def test_amass_forbids_active(self):
        """Stealth rules must forbid -active flag."""
        start = self.content.index('### execute_amass')
        next_match = re.search(r'\n### ', self.content[start + 1:])
        if next_match:
            section = self.content[start:start + 1 + next_match.start()]
        else:
            section = self.content[start:]
        self.assertIn('-active', section)
        self.assertIn('FORBIDDEN', section)

    def test_amass_forbids_brute(self):
        """Stealth rules must forbid -brute flag."""
        start = self.content.index('### execute_amass')
        next_match = re.search(r'\n### ', self.content[start + 1:])
        if next_match:
            section = self.content[start:start + 1 + next_match.start()]
        else:
            section = self.content[start:]
        self.assertIn('-brute', section)

    def test_blank_line_before_amass(self):
        """There must be a blank line before the amass section heading."""
        for i, line in enumerate(self.lines):
            if '### execute_amass' in line:
                prev_line = self.lines[i - 1].strip()
                self.assertEqual(prev_line, '',
                    f"Expected blank line before amass heading, got: '{prev_line}'")
                break


class TestToolMatrixSection(unittest.TestCase):
    """Verify ToolMatrixSection.tsx includes amass."""

    def setUp(self):
        path = os.path.join(BASE_DIR, 'webapp', 'src', 'components', 'projects',
                           'ProjectForm', 'sections', 'ToolMatrixSection.tsx')
        with open(path) as f:
            self.content = f.read()

    def test_amass_in_tool_list(self):
        """execute_amass must appear in the tool list."""
        self.assertIn("id: 'execute_amass'", self.content)

    def test_no_duplicate_amass(self):
        """execute_amass must appear exactly once."""
        count = self.content.count("id: 'execute_amass'")
        self.assertEqual(count, 1, f"execute_amass appears {count} times, expected 1")

    def test_amass_after_wpscan(self):
        """execute_amass must come after execute_wpscan in the tool list."""
        wpscan_pos = self.content.index("id: 'execute_wpscan'")
        amass_pos = self.content.index("id: 'execute_amass'")
        self.assertGreater(amass_pos, wpscan_pos)

    def test_amass_before_kali_shell(self):
        """execute_amass must come before kali_shell."""
        amass_pos = self.content.index("id: 'execute_amass'")
        kali_pos = self.content.index("id: 'kali_shell'")
        self.assertLess(amass_pos, kali_pos)

    def test_amass_not_in_tool_key_info(self):
        """execute_amass must NOT be in TOOL_KEY_INFO (no API key needed)."""
        # TOOL_KEY_INFO is at top of file, before the tool list
        key_info_match = re.search(
            r'TOOL_KEY_INFO.*?(?=\nexport|\nconst\s+\w+Section|\nfunction)',
            self.content, re.DOTALL
        )
        if key_info_match:
            self.assertNotIn('execute_amass', key_info_match.group(0))


class TestRoECategoryMap(unittest.TestCase):
    """Verify execute_amass is NOT in any RoE category (recon tool)."""

    def setUp(self):
        path = os.path.join(BASE_DIR, 'agentic', 'orchestrator_helpers', 'nodes', 'execute_plan_node.py')
        with open(path) as f:
            self.content = f.read()

    def test_amass_not_in_any_roe_category(self):
        """execute_amass must NOT be in CATEGORY_TOOL_MAP (not an attack tool)."""
        match = re.search(r"CATEGORY_TOOL_MAP\s*=\s*\{([^}]+)\}", self.content)
        self.assertIsNotNone(match, "Could not find CATEGORY_TOOL_MAP")
        map_content = match.group(1)
        self.assertNotIn('execute_amass', map_content)


class TestDockerfileInstallation(unittest.TestCase):
    """Verify kali-sandbox Dockerfile installs amass."""

    def setUp(self):
        path = os.path.join(BASE_DIR, 'mcp', 'kali-sandbox', 'Dockerfile')
        with open(path) as f:
            self.content = f.read()

    def test_amass_go_install(self):
        """Dockerfile must have go install for amass."""
        self.assertIn('owasp-amass/amass', self.content)

    def test_amass_v4_module(self):
        """Must use v4 module path."""
        self.assertIn('amass/v4/...@master', self.content)

    def test_amass_after_go_installation(self):
        """amass go install must come after Go is installed."""
        go_install_pos = self.content.index('tar -C /usr/local -xzf go')
        amass_pos = self.content.index('owasp-amass/amass')
        self.assertGreater(amass_pos, go_install_pos)

    def test_amass_has_comment(self):
        """There must be a comment explaining amass installation."""
        lines = self.content.split('\n')
        for i, line in enumerate(lines):
            if 'owasp-amass/amass' in line:
                preceding = '\n'.join(lines[max(0, i - 3):i])
                self.assertIn('Amass', preceding,
                    "Comment above go install should mention Amass")
                break


class TestCrossFileConsistency(unittest.TestCase):
    """Verify all files agree on amass presence and phases."""

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

    def test_amass_in_all_required_locations(self):
        """execute_amass must be present in all required locations."""
        self.assertIn('execute_amass', self.registry)
        self.assertIn('execute_amass', self.phase_map)
        self.assertIn('execute_amass', self.prisma_phase_map)
        self.assertIn('execute_amass', self.matrix_tools)
        self.assertIn('execute_amass', self.stealth_content)

    def test_amass_in_dangerous(self):
        """execute_amass must be in DANGEROUS_TOOLS."""
        self.assertIn('execute_amass', self.dangerous)

    def test_amass_in_both_phase_maps(self):
        """execute_amass must be in both Python and Prisma phase maps."""
        self.assertIn('execute_amass', self.phase_map)
        self.assertIn('execute_amass', self.prisma_phase_map)

    def test_amass_phase_values_match(self):
        """Phase arrays must match between Python and Prisma for amass."""
        py_phases = self.phase_map['execute_amass']
        prisma_phases = self.prisma_phase_map['execute_amass']
        self.assertEqual(py_phases, prisma_phases,
                       f"Phase mismatch: Python={py_phases}, Prisma={prisma_phases}")

    def test_matrix_covers_phase_map(self):
        """Every tool in TOOL_PHASE_MAP should be in the Tool Matrix UI."""
        py_tools = set(self.phase_map.keys())
        missing = py_tools - self.matrix_tools
        self.assertEqual(missing, set(),
                        f"Tools in TOOL_PHASE_MAP but missing from ToolMatrix: {missing}")

    def test_phase_map_covers_matrix(self):
        """Every tool in Tool Matrix should be in TOOL_PHASE_MAP."""
        # Exclude non-tool entries that might be in the TSX
        expected_non_phase = {'msf_restart'}  # msf_restart may or may not be in phase map
        missing = self.matrix_tools - set(self.phase_map.keys()) - expected_non_phase
        self.assertEqual(missing, set(),
                        f"Tools in ToolMatrix but missing from TOOL_PHASE_MAP: {missing}")


class TestMCPToolFunction(unittest.TestCase):
    """Unit tests for the execute_amass MCP tool function."""

    def setUp(self):
        import importlib
        if 'network_recon_server' in sys.modules:
            mod = importlib.reload(sys.modules['network_recon_server'])
        else:
            mod = importlib.import_module('network_recon_server')
        self.execute_amass = mod.execute_amass

    @patch('network_recon_server.subprocess.run')
    def test_basic_enum_execution(self, mock_run):
        """Tool should run amass enum with correct args."""
        mock_run.return_value = MagicMock(
            stdout='sub1.example.com\nsub2.example.com\n',
            stderr='',
            returncode=0
        )
        result = self.execute_amass('enum -d example.com -timeout 5')
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        self.assertEqual(cmd[0], 'amass')
        self.assertIn('enum', cmd)
        self.assertIn('-d', cmd)
        self.assertIn('example.com', cmd)
        self.assertIn('-timeout', cmd)
        self.assertIn('5', cmd)
        self.assertIn('sub1.example.com', result)
        self.assertIn('sub2.example.com', result)

    @patch('network_recon_server.subprocess.run')
    def test_passive_mode(self, mock_run):
        """Tool should pass -passive flag correctly."""
        mock_run.return_value = MagicMock(
            stdout='sub1.example.com\n',
            stderr='',
            returncode=0
        )
        self.execute_amass('enum -passive -d example.com -timeout 5')
        cmd = mock_run.call_args[0][0]
        self.assertIn('-passive', cmd)

    @patch('network_recon_server.subprocess.run')
    def test_active_brute_mode(self, mock_run):
        """Tool should pass -active and -brute flags correctly."""
        mock_run.return_value = MagicMock(
            stdout='sub1.example.com\n',
            stderr='',
            returncode=0
        )
        self.execute_amass('enum -d example.com -active -brute -timeout 10')
        cmd = mock_run.call_args[0][0]
        self.assertIn('-active', cmd)
        self.assertIn('-brute', cmd)

    @patch('network_recon_server.subprocess.run')
    def test_intel_subcommand(self, mock_run):
        """Tool should support intel subcommand."""
        mock_run.return_value = MagicMock(
            stdout='example.com\nexample.org\n',
            stderr='',
            returncode=0
        )
        result = self.execute_amass('intel -asn 12345')
        cmd = mock_run.call_args[0][0]
        self.assertEqual(cmd, ['amass', 'intel', '-asn', '12345'])
        self.assertIn('example.com', result)

    @patch('network_recon_server.subprocess.run')
    def test_empty_output(self, mock_run):
        """Tool should return info message when no subdomains found."""
        mock_run.return_value = MagicMock(
            stdout='', stderr='', returncode=0
        )
        result = self.execute_amass('enum -d nonexistent.invalid -timeout 2')
        self.assertIn('[INFO]', result)
        self.assertIn('No subdomains found', result)

    @patch('network_recon_server.subprocess.run')
    def test_ansi_stripping(self, mock_run):
        """Tool should strip ANSI escape codes from output."""
        mock_run.return_value = MagicMock(
            stdout='\x1b[32msub1.example.com\x1b[0m\n',
            stderr='',
            returncode=0
        )
        result = self.execute_amass('enum -d example.com -timeout 5')
        self.assertNotIn('\x1b', result)
        self.assertIn('sub1.example.com', result)

    @patch('network_recon_server.subprocess.run')
    def test_stderr_inf_filtering(self, mock_run):
        """Tool should filter out [INF] lines from stderr."""
        mock_run.return_value = MagicMock(
            stdout='sub1.example.com\n',
            stderr='[INF] Loading config\n[INF] Enumeration started\n',
            returncode=0
        )
        result = self.execute_amass('enum -d example.com -timeout 5')
        self.assertNotIn('[INF]', result)
        self.assertNotIn('[STDERR]', result)
        self.assertIn('sub1.example.com', result)

    @patch('network_recon_server.subprocess.run')
    def test_stderr_querying_filtering(self, mock_run):
        """Tool should filter out 'Querying ' progress lines from stderr."""
        mock_run.return_value = MagicMock(
            stdout='sub1.example.com\n',
            stderr='Querying crtsh for example.com\nQuerying hackertarget for example.com\n',
            returncode=0
        )
        result = self.execute_amass('enum -d example.com -timeout 5')
        self.assertNotIn('Querying', result)
        self.assertNotIn('[STDERR]', result)

    @patch('network_recon_server.subprocess.run')
    def test_stderr_errors_kept(self, mock_run):
        """Tool should keep non-noise stderr lines."""
        mock_run.return_value = MagicMock(
            stdout='',
            stderr='[INF] Loading config\n[ERR] Failed to resolve DNS\n',
            returncode=0
        )
        result = self.execute_amass('enum -d example.com -timeout 5')
        self.assertIn('[STDERR]', result)
        self.assertIn('Failed to resolve DNS', result)

    @patch('network_recon_server.subprocess.run')
    def test_timeout_handling(self, mock_run):
        """Tool should handle subprocess timeout gracefully."""
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd='amass', timeout=660)
        result = self.execute_amass('enum -d example.com -timeout 10')
        self.assertIn('[ERROR]', result)
        self.assertIn('timed out', result)
        self.assertIn('660', result)

    @patch('network_recon_server.subprocess.run')
    def test_file_not_found(self, mock_run):
        """Tool should handle missing binary gracefully."""
        mock_run.side_effect = FileNotFoundError()
        result = self.execute_amass('enum -d example.com')
        self.assertIn('[ERROR]', result)
        self.assertIn('amass not found', result)

    @patch('network_recon_server.subprocess.run')
    def test_generic_exception(self, mock_run):
        """Tool should handle unexpected exceptions."""
        mock_run.side_effect = OSError('Permission denied')
        result = self.execute_amass('enum -d example.com')
        self.assertIn('[ERROR]', result)
        self.assertIn('Permission denied', result)

    @patch('network_recon_server.subprocess.run')
    def test_timeout_value_is_660(self, mock_run):
        """Tool must use 660s timeout (11 min)."""
        mock_run.return_value = MagicMock(stdout='', stderr='', returncode=0)
        self.execute_amass('enum -d example.com')
        _, kwargs = mock_run.call_args
        self.assertEqual(kwargs.get('timeout'), 660)

    @patch('network_recon_server.subprocess.run')
    def test_capture_output_enabled(self, mock_run):
        """Tool must use capture_output=True and text=True."""
        mock_run.return_value = MagicMock(stdout='', stderr='', returncode=0)
        self.execute_amass('enum -d example.com')
        _, kwargs = mock_run.call_args
        self.assertTrue(kwargs.get('capture_output'))
        self.assertTrue(kwargs.get('text'))

    @patch('network_recon_server.subprocess.run')
    def test_shlex_split_args(self, mock_run):
        """Tool should correctly split complex args."""
        mock_run.return_value = MagicMock(stdout='result\n', stderr='', returncode=0)
        self.execute_amass('enum -d example.com -active -brute -timeout 10')
        cmd = mock_run.call_args[0][0]
        self.assertEqual(cmd, [
            'amass', 'enum', '-d', 'example.com',
            '-active', '-brute', '-timeout', '10'
        ])

    @patch('network_recon_server.subprocess.run')
    def test_json_output_flag(self, mock_run):
        """Tool should support -json output flag."""
        json_line = '{"name":"sub1.example.com","domain":"example.com","tag":"cert"}\n'
        mock_run.return_value = MagicMock(
            stdout=json_line,
            stderr='',
            returncode=0
        )
        result = self.execute_amass('enum -d example.com -json /tmp/out.json -timeout 5')
        cmd = mock_run.call_args[0][0]
        self.assertIn('-json', cmd)
        self.assertIn('sub1.example.com', result)

    @patch('network_recon_server.subprocess.run')
    def test_multiple_domains(self, mock_run):
        """Tool should handle multiple domains via comma separation."""
        mock_run.return_value = MagicMock(
            stdout='a.example.com\nb.example.org\n',
            stderr='',
            returncode=0
        )
        self.execute_amass('enum -d example.com,example.org -timeout 5')
        cmd = mock_run.call_args[0][0]
        self.assertIn('example.com,example.org', cmd)


class TestMCPServerDocstring(unittest.TestCase):
    """Verify network_recon_server.py module docstring mentions amass."""

    def setUp(self):
        path = os.path.join(BASE_DIR, 'mcp', 'servers', 'network_recon_server.py')
        with open(path) as f:
            self.content = f.read()

    def test_amass_in_module_docstring(self):
        """Module docstring must mention amass."""
        # Extract the module docstring (first triple-quoted string)
        match = re.search(r'^"""(.*?)"""', self.content, re.DOTALL)
        self.assertIsNotNone(match, "Could not find module docstring")
        docstring = match.group(1)
        self.assertIn('amass', docstring.lower())

    def test_execute_amass_in_tools_list(self):
        """Tools section in docstring must list execute_amass."""
        match = re.search(r'^"""(.*?)"""', self.content, re.DOTALL)
        docstring = match.group(1)
        self.assertIn('execute_amass', docstring)


if __name__ == '__main__':
    unittest.main(verbosity=2)
