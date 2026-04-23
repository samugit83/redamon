"""
Unit tests for PR #84 post-merge fixes: WPScan integration correctness.
Validates cross-file consistency, formatting, and data integrity.
"""
import json
import re
import ast
import sys
import os
import unittest

# Add project roots to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'agentic'))

BASE_DIR = os.path.join(os.path.dirname(__file__), '..')


class TestToolRegistryWPScan(unittest.TestCase):
    """Verify tool_registry.py changes."""

    def setUp(self):
        path = os.path.join(BASE_DIR, 'agentic', 'prompts', 'tool_registry.py')
        with open(path) as f:
            self.content = f.read()
        # Parse the module to extract TOOL_REGISTRY
        tree = ast.parse(self.content)
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == 'TOOL_REGISTRY':
                        self.registry_source = ast.get_source_segment(self.content, node.value)
        # Import the actual registry
        from prompts.tool_registry import TOOL_REGISTRY
        self.registry = TOOL_REGISTRY

    def test_wpscan_in_registry(self):
        """execute_wpscan must be registered."""
        self.assertIn('execute_wpscan', self.registry)

    def test_masscan_not_in_registry(self):
        """execute_masscan must NOT be in the registry (removed)."""
        self.assertNotIn('execute_masscan', self.registry)

    def test_wpscan_has_required_fields(self):
        """execute_wpscan entry must have all required fields."""
        entry = self.registry['execute_wpscan']
        for field in ('purpose', 'when_to_use', 'args_format', 'description'):
            self.assertIn(field, entry, f"Missing field: {field}")
            self.assertTrue(len(entry[field]) > 0, f"Empty field: {field}")

    def test_wpscan_description_mentions_key_flags(self):
        """Description should mention critical flags."""
        desc = self.registry['execute_wpscan']['description']
        self.assertIn('--url', desc)
        self.assertIn('--enumerate', desc)

    def test_no_masscan_string_in_registry_file(self):
        """No residual masscan references in the registry dict."""
        # Find the TOOL_REGISTRY dict content (between first { and last })
        start = self.content.find('TOOL_REGISTRY')
        registry_section = self.content[start:]
        self.assertNotIn('execute_masscan', registry_section)
        self.assertNotIn('masscan', registry_section.lower().split('execute_wpscan')[0][-200:] if 'execute_wpscan' in registry_section else registry_section)


class TestProjectSettings(unittest.TestCase):
    """Verify project_settings.py changes."""

    def setUp(self):
        path = os.path.join(BASE_DIR, 'agentic', 'project_settings.py')
        with open(path) as f:
            self.content = f.read()
            self.lines = self.content.split('\n')

    def test_wpscan_in_dangerous_tools(self):
        """execute_wpscan must be in DANGEROUS_TOOLS."""
        from project_settings import DANGEROUS_TOOLS
        self.assertIn('execute_wpscan', DANGEROUS_TOOLS)

    def test_masscan_not_in_dangerous_tools(self):
        """execute_masscan must NOT be in DANGEROUS_TOOLS."""
        from project_settings import DANGEROUS_TOOLS
        self.assertNotIn('execute_masscan', DANGEROUS_TOOLS)

    def test_wpscan_in_tool_phase_map(self):
        """execute_wpscan must be in TOOL_PHASE_MAP."""
        from project_settings import DEFAULT_AGENT_SETTINGS
        phase_map = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']
        self.assertIn('execute_wpscan', phase_map)
        self.assertEqual(phase_map['execute_wpscan'], ['informational', 'exploitation'])

    def test_masscan_not_in_tool_phase_map(self):
        """execute_masscan must NOT be in TOOL_PHASE_MAP."""
        from project_settings import DEFAULT_AGENT_SETTINGS
        phase_map = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']
        self.assertNotIn('execute_masscan', phase_map)

    def test_comment_separators_exist(self):
        """All section separator blocks must be present."""
        separator = '# ============================================================================='
        separator_count = self.content.count(separator)
        # 4 sections x 2 separators each = 8
        self.assertGreaterEqual(separator_count, 8,
                         f"Expected at least 8 separator lines, found {separator_count}")

    def test_dangerous_tools_separator(self):
        """DANGEROUS TOOLS section must have separators."""
        pattern = r'# =+\n# DANGEROUS TOOLS.*\n# =+'
        self.assertRegex(self.content, pattern)

    def test_default_settings_separator(self):
        """DEFAULT SETTINGS section must have separators."""
        pattern = r'# =+\n# DEFAULT SETTINGS.*\n# =+'
        self.assertRegex(self.content, pattern)

    def test_attack_skill_separator(self):
        """ATTACK SKILL HELPERS section must have separators."""
        pattern = r'# =+\n# ATTACK SKILL HELPERS\n# =+'
        self.assertRegex(self.content, pattern)

    def test_tool_phase_separator(self):
        """TOOL PHASE RESTRICTION HELPERS section must have separators."""
        pattern = r'# =+\n# TOOL PHASE RESTRICTION HELPERS.*\n# =+'
        self.assertRegex(self.content, pattern)

    def test_no_masscan_anywhere(self):
        """No residual execute_masscan references in file."""
        self.assertNotIn('execute_masscan', self.content)


class TestPrismaSchema(unittest.TestCase):
    """Verify schema.prisma JSON escaping and content."""

    def setUp(self):
        path = os.path.join(BASE_DIR, 'webapp', 'prisma', 'schema.prisma')
        with open(path) as f:
            self.content = f.read()
        # Extract the agentToolPhaseMap default JSON
        match = re.search(r'agentToolPhaseMap\s+Json\s+@default\("(.+?)"\)\s+@map', self.content)
        self.assertIsNotNone(match, "Could not find agentToolPhaseMap default")
        self.raw_json = match.group(1)

    def test_json_escaping_valid(self):
        """The JSON default must use proper \\\" escaping."""
        # The raw string from the file should have \" sequences
        self.assertIn('\\"', self.raw_json,
                      "JSON must use \\\" escaping, found raw quotes instead")

    def test_json_parseable(self):
        """The unescaped JSON must be valid and parseable."""
        unescaped = self.raw_json.replace('\\"', '"')
        try:
            data = json.loads(unescaped)
        except json.JSONDecodeError as e:
            self.fail(f"JSON is not valid: {e}")
        self.assertIsInstance(data, dict)

    def test_wpscan_in_schema_default(self):
        """execute_wpscan must be in the schema default JSON."""
        unescaped = self.raw_json.replace('\\"', '"')
        data = json.loads(unescaped)
        self.assertIn('execute_wpscan', data)
        self.assertEqual(data['execute_wpscan'], ['informational', 'exploitation'])

    def test_masscan_not_in_schema_default(self):
        """execute_masscan must NOT be in the schema default JSON."""
        unescaped = self.raw_json.replace('\\"', '"')
        data = json.loads(unescaped)
        self.assertNotIn('execute_masscan', data)

    def test_all_tools_present(self):
        """All expected tools must be in the schema default."""
        unescaped = self.raw_json.replace('\\"', '"')
        data = json.loads(unescaped)
        expected_tools = [
            'query_graph', 'web_search', 'shodan', 'google_dork',
            'execute_curl', 'execute_naabu', 'execute_wpscan',
            'execute_nmap', 'execute_nuclei', 'kali_shell',
            'execute_code', 'execute_playwright', 'execute_hydra',
            'metasploit_console', 'msf_restart',
        ]
        for tool in expected_tools:
            self.assertIn(tool, data, f"Missing tool in schema default: {tool}")

    def test_no_raw_unescaped_quotes(self):
        """Schema line must not contain unescaped quotes inside the JSON string."""
        # Find the full line
        for line in self.content.split('\n'):
            if 'agentToolPhaseMap' in line and '@default' in line:
                # Between @default(" and ") @map, all internal quotes must be \"
                inner_start = line.index('@default("') + len('@default("')
                inner_end = line.index('")')
                inner = line[inner_start:inner_end]
                # Replace valid \" with nothing, remaining " would be errors
                cleaned = inner.replace('\\"', '')
                self.assertNotIn('"', cleaned,
                                 "Found unescaped quotes in JSON default value")
                break


class TestStealthRules(unittest.TestCase):
    """Verify stealth_rules.py formatting."""

    def setUp(self):
        path = os.path.join(BASE_DIR, 'agentic', 'prompts', 'stealth_rules.py')
        with open(path) as f:
            self.content = f.read()
            self.lines = self.content.split('\n')

    def test_wpscan_section_exists(self):
        """execute_wpscan stealth section must exist."""
        self.assertIn('### execute_wpscan', self.content)

    def test_heading_format(self):
        """Heading must follow pattern: ### tool_name -- RESTRICTION_LEVEL."""
        # Should NOT have (WordPress Scanner) in the heading
        self.assertNotIn('(WordPress Scanner)', self.content)
        # Should have the standard format
        match = re.search(r'### execute_wpscan\s*[—\-]+\s*HEAVILY RESTRICTED', self.content)
        self.assertIsNotNone(match,
            "Heading must be '### execute_wpscan -- HEAVILY RESTRICTED'")

    def test_no_bold_restriction_line(self):
        """Should NOT have a separate **HEAVILY RESTRICTED** line after heading."""
        self.assertNotIn('**HEAVILY RESTRICTED**', self.content)

    def test_blank_line_before_wpscan(self):
        """There must be a blank line before the wpscan section heading."""
        for i, line in enumerate(self.lines):
            if '### execute_wpscan' in line:
                prev_line = self.lines[i - 1].strip()
                self.assertEqual(prev_line, '',
                    f"Expected blank line before wpscan heading, got: '{prev_line}'")
                break

    def test_blank_line_after_wpscan_section(self):
        """There must be a blank line after the wpscan section (before metasploit)."""
        in_wpscan = False
        for i, line in enumerate(self.lines):
            if '### execute_wpscan' in line:
                in_wpscan = True
            elif in_wpscan and line.startswith('### '):
                prev_line = self.lines[i - 1].strip()
                self.assertEqual(prev_line, '',
                    f"Expected blank line after wpscan section, got: '{prev_line}'")
                break

    def test_wpscan_has_forbidden_passwords(self):
        """Stealth rules must FORBID --passwords (brute force)."""
        wpscan_start = self.content.index('### execute_wpscan')
        next_section = self.content.index('### metasploit_console')
        wpscan_section = self.content[wpscan_start:next_section]
        self.assertIn('--passwords', wpscan_section)
        self.assertIn('FORBIDDEN', wpscan_section)


class TestRoECategoryMap(unittest.TestCase):
    """Verify execute_plan_node.py RoE mapping."""

    def setUp(self):
        path = os.path.join(BASE_DIR, 'agentic', 'orchestrator_helpers', 'nodes', 'execute_plan_node.py')
        with open(path) as f:
            self.content = f.read()

    def test_wpscan_in_brute_force_category(self):
        """execute_wpscan must be in brute_force RoE category."""
        # Extract CATEGORY_TOOL_MAP dict
        match = re.search(r"CATEGORY_TOOL_MAP\s*=\s*\{([^}]+)\}", self.content)
        self.assertIsNotNone(match, "Could not find CATEGORY_TOOL_MAP")
        map_content = match.group(1)

        # Find brute_force list
        bf_match = re.search(r"'brute_force'\s*:\s*\[([^\]]+)\]", map_content)
        self.assertIsNotNone(bf_match, "Could not find brute_force entry")
        bf_tools = bf_match.group(1)
        self.assertIn('execute_wpscan', bf_tools)
        self.assertIn('execute_hydra', bf_tools)


class TestToolMatrixSection(unittest.TestCase):
    """Verify ToolMatrixSection.tsx tool ordering."""

    def setUp(self):
        path = os.path.join(BASE_DIR, 'webapp', 'src', 'components', 'projects',
                           'ProjectForm', 'sections', 'ToolMatrixSection.tsx')
        with open(path) as f:
            self.content = f.read()

    def test_wpscan_in_tool_list(self):
        """execute_wpscan must appear in the tool list."""
        self.assertIn("id: 'execute_wpscan'", self.content)

    def test_no_duplicate_wpscan(self):
        """execute_wpscan must appear exactly once."""
        count = self.content.count("id: 'execute_wpscan'")
        self.assertEqual(count, 1, f"execute_wpscan appears {count} times, expected 1")

    def test_wpscan_after_nuclei(self):
        """execute_wpscan must come after execute_nuclei in the tool list."""
        nuclei_pos = self.content.index("id: 'execute_nuclei'")
        wpscan_pos = self.content.index("id: 'execute_wpscan'")
        self.assertGreater(wpscan_pos, nuclei_pos,
                          "execute_wpscan must be positioned after execute_nuclei")

    def test_wpscan_before_kali_shell(self):
        """execute_wpscan must come before kali_shell."""
        wpscan_pos = self.content.index("id: 'execute_wpscan'")
        kali_pos = self.content.index("id: 'kali_shell'")
        self.assertLess(wpscan_pos, kali_pos,
                       "execute_wpscan must be positioned before kali_shell")

    def test_wpscan_before_msf_restart(self):
        """execute_wpscan must NOT be at the end (after msf_restart)."""
        wpscan_pos = self.content.index("id: 'execute_wpscan'")
        msf_pos = self.content.index("id: 'msf_restart'")
        self.assertLess(wpscan_pos, msf_pos,
                       "execute_wpscan must be before msf_restart")

    def test_no_masscan_in_tool_list(self):
        """execute_masscan must NOT appear in the tool list."""
        self.assertNotIn("id: 'execute_masscan'", self.content)


class TestCrossFileConsistency(unittest.TestCase):
    """Verify all files agree on which tools exist and their phases."""

    def setUp(self):
        from project_settings import DEFAULT_AGENT_SETTINGS, DANGEROUS_TOOLS
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

    def test_phase_maps_match(self):
        """Python TOOL_PHASE_MAP and Prisma default must have the same tools."""
        py_tools = set(self.phase_map.keys())
        prisma_tools = set(self.prisma_phase_map.keys())
        self.assertEqual(py_tools, prisma_tools,
                        f"Mismatch: Python has {py_tools - prisma_tools}, "
                        f"Prisma has {prisma_tools - py_tools}")

    def test_phase_values_match(self):
        """Phase arrays must match between Python and Prisma for every tool."""
        for tool in self.phase_map:
            py_phases = self.phase_map[tool]
            prisma_phases = self.prisma_phase_map.get(tool, [])
            self.assertEqual(py_phases, prisma_phases,
                           f"Phase mismatch for {tool}: "
                           f"Python={py_phases}, Prisma={prisma_phases}")

    def test_matrix_covers_phase_map(self):
        """Every tool in TOOL_PHASE_MAP should be in the Tool Matrix UI."""
        py_tools = set(self.phase_map.keys())
        missing = py_tools - self.matrix_tools
        self.assertEqual(missing, set(),
                        f"Tools in TOOL_PHASE_MAP but missing from ToolMatrix: {missing}")

    def test_wpscan_consistent_everywhere(self):
        """execute_wpscan must be present in all required locations."""
        self.assertIn('execute_wpscan', self.phase_map)
        self.assertIn('execute_wpscan', self.prisma_phase_map)
        self.assertIn('execute_wpscan', self.matrix_tools)
        self.assertIn('execute_wpscan', self.dangerous)

    def test_masscan_absent_everywhere(self):
        """execute_masscan must be absent from all tool registrations."""
        self.assertNotIn('execute_masscan', self.phase_map)
        self.assertNotIn('execute_masscan', self.prisma_phase_map)
        self.assertNotIn('execute_masscan', self.matrix_tools)
        self.assertNotIn('execute_masscan', self.dangerous)


if __name__ == '__main__':
    unittest.main(verbosity=2)
