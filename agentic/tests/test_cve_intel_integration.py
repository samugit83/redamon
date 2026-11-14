"""
Tests for cve_intel integration -- MCP tool function, tool registry,
project settings, stealth rules, Prisma schema default, and cross-layer consistency.

Layers tested:
    1. UNIT          — cve_intel MCP function with mocked subprocess
    2. INTEGRATION   — tool_registry + TOOL_PHASE_MAP + stealth_rules wiring
    3. REGRESSION    — existing tools unaffected; Prisma JSON default valid
    4. SMOKE         — real vulnx binary if installed (auto-skipped otherwise)

Run with: python3 -m unittest tests.test_cve_intel_integration -v
"""

import json
import os
import re
import shutil
import subprocess
import sys
import unittest
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Path setup so we can import from both agentic/ and mcp/servers/
# ---------------------------------------------------------------------------
_agentic_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_repo_root = os.path.dirname(_agentic_dir)
_mcp_servers_dir = os.path.join(_repo_root, 'mcp', 'servers')

sys.path.insert(0, _agentic_dir)
sys.path.insert(0, _mcp_servers_dir)

# ---------------------------------------------------------------------------
# Stub heavy dependencies that aren't installed outside the agent container
# ---------------------------------------------------------------------------
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
        sys.modules[mod_name] = MagicMock()


class _FakeMessage:
    def __init__(self, content="", **kwargs):
        self.content = content


sys.modules['langchain_core.messages'].AIMessage = _FakeMessage
sys.modules['langchain_core.messages'].HumanMessage = _FakeMessage


def _fake_add_messages(left, right):
    return (left or []) + right


sys.modules['langgraph.graph.message'].add_messages = _fake_add_messages

# Stub fastmcp so the @mcp.tool() decorator becomes a no-op passthrough,
# letting us import the real cve_intel function for direct testing.
class _FakeMCP:
    def __init__(self, *a, **kw):
        pass

    def tool(self, *a, **kw):
        def _identity(fn):
            return fn
        return _identity

    def __getattr__(self, name):
        return MagicMock()


_fastmcp_mod = MagicMock()
_fastmcp_mod.FastMCP = _FakeMCP
sys.modules['fastmcp'] = _fastmcp_mod

# Force fresh import of network_recon_server now that fastmcp is stubbed.
sys.modules.pop('network_recon_server', None)
import network_recon_server  # noqa: E402
from network_recon_server import cve_intel  # noqa: E402

from project_settings import DANGEROUS_TOOLS, DEFAULT_AGENT_SETTINGS  # noqa: E402
from prompts.tool_registry import TOOL_REGISTRY  # noqa: E402
from prompts.stealth_rules import STEALTH_MODE_RULES  # noqa: E402


def _mock_completed(stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(
        args=["vulnx"], returncode=returncode, stdout=stdout, stderr=stderr
    )


# ===========================================================================
# 1. UNIT — cve_intel MCP function (mocked subprocess)
# ===========================================================================

class TestCveIntelMCPFunction(unittest.TestCase):
    """Direct tests of the cve_intel function with subprocess mocked."""

    @patch('network_recon_server.subprocess.run')
    def test_basic_invocation_uses_vulnx_binary(self, mock_run):
        mock_run.return_value = _mock_completed(stdout='[{"cve_id":"CVE-2024-1"}]')
        cve_intel("id CVE-2024-1 --json")
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        self.assertEqual(cmd[0], "vulnx")
        self.assertIn("id", cmd)
        self.assertIn("CVE-2024-1", cmd)
        self.assertIn("--json", cmd)

    @patch('network_recon_server.subprocess.run')
    def test_timeout_is_60s(self, mock_run):
        mock_run.return_value = _mock_completed()
        cve_intel("filters")
        self.assertEqual(mock_run.call_args[1]["timeout"], 60)

    @patch('network_recon_server.subprocess.run')
    def test_capture_output_and_text(self, mock_run):
        """subprocess.run must capture stdout/stderr as text."""
        mock_run.return_value = _mock_completed(stdout="ok")
        cve_intel("healthcheck")
        kwargs = mock_run.call_args[1]
        self.assertTrue(kwargs.get("capture_output"))
        self.assertTrue(kwargs.get("text"))

    @patch('network_recon_server.subprocess.run')
    def test_quoted_lucene_query_preserved_as_single_arg(self, mock_run):
        """A shell-quoted lucene query stays as one argv element after shlex."""
        mock_run.return_value = _mock_completed(stdout="[]")
        cve_intel("search 'product:confluence AND severity:critical' --json --limit 5")
        cmd = mock_run.call_args[0][0]
        self.assertIn("product:confluence AND severity:critical", cmd)
        # The lucene phrase must be ONE argv element, not split on AND
        idx = cmd.index("product:confluence AND severity:critical")
        self.assertEqual(cmd[idx - 1], "search")
        self.assertEqual(cmd[idx + 1], "--json")

    @patch('network_recon_server.subprocess.run')
    def test_stdout_returned(self, mock_run):
        json_blob = '[{"cve_id":"CVE-2024-21887","severity":"critical","is_kev":true}]'
        mock_run.return_value = _mock_completed(stdout=json_blob)
        result = cve_intel("id CVE-2024-21887 --json")
        self.assertIn("CVE-2024-21887", result)
        self.assertIn("critical", result)

    @patch('network_recon_server.subprocess.run')
    def test_empty_output_returns_info(self, mock_run):
        mock_run.return_value = _mock_completed(stdout="", stderr="")
        result = cve_intel("search 'product:nonexistent' --json")
        self.assertIn("[INFO]", result)
        self.assertIn("No CVEs", result)

    @patch('network_recon_server.subprocess.run')
    def test_ansi_codes_stripped_from_stdout(self, mock_run):
        mock_run.return_value = _mock_completed(
            stdout="\x1b[32m[+] CVE-2024-1\x1b[0m\n"
        )
        result = cve_intel("id CVE-2024-1")
        self.assertNotIn("\x1b[", result)
        self.assertIn("CVE-2024-1", result)

    @patch('network_recon_server.subprocess.run')
    def test_inf_lines_filtered_from_stderr(self, mock_run):
        mock_run.return_value = _mock_completed(
            stdout='[{"cve_id":"CVE-2024-1"}]',
            stderr="[INF] using cached results\n[INF] querying api\n"
        )
        result = cve_intel("id CVE-2024-1 --json")
        self.assertNotIn("[INF]", result)
        self.assertNotIn("[STDERR]", result)

    @patch('network_recon_server.subprocess.run')
    def test_version_banner_filtered_from_stderr(self, mock_run):
        mock_run.return_value = _mock_completed(
            stdout="ok",
            stderr="Current vulnx version 2.0.1\n"
        )
        result = cve_intel("version")
        self.assertNotIn("Current vulnx version", result)

    @patch('network_recon_server.subprocess.run')
    def test_real_stderr_errors_kept(self, mock_run):
        """Genuine error lines in stderr must surface to the agent."""
        mock_run.return_value = _mock_completed(
            stdout="",
            stderr="[ERR] invalid query syntax near 'AAA'\n"
        )
        result = cve_intel("search 'bad query' --json")
        self.assertIn("[STDERR]", result)
        self.assertIn("invalid query syntax", result)

    @patch('network_recon_server.subprocess.run')
    def test_timeout_error_message(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="vulnx", timeout=60)
        result = cve_intel("search 'huge' --limit 99999")
        self.assertIn("[ERROR]", result)
        self.assertIn("60 seconds", result)
        self.assertIn("--limit", result)

    @patch('network_recon_server.subprocess.run')
    def test_binary_not_found(self, mock_run):
        mock_run.side_effect = FileNotFoundError()
        result = cve_intel("healthcheck")
        self.assertIn("[ERROR]", result)
        self.assertIn("vulnx not found", result)

    @patch('network_recon_server.subprocess.run')
    def test_generic_exception_caught(self, mock_run):
        mock_run.side_effect = RuntimeError("boom")
        result = cve_intel("id CVE-1")
        self.assertIn("[ERROR]", result)
        self.assertIn("boom", result)

    def test_empty_args_returns_error(self):
        """Empty args -> shlex returns [] -> vulnx is called with no subcommand.
        Whatever vulnx does (print help / exit 1), the wrapper must not crash."""
        with patch('network_recon_server.subprocess.run') as mock_run:
            mock_run.return_value = _mock_completed(stdout="Usage: vulnx ...\n")
            result = cve_intel("")
            # Should not raise, should return SOMETHING (help text or info)
            self.assertIsInstance(result, str)
            self.assertGreater(len(result), 0)

    @patch('network_recon_server.subprocess.run')
    def test_no_target_traffic_principle(self, mock_run):
        """The wrapper must never inject a target URL/host -- only vulnx subcommands."""
        mock_run.return_value = _mock_completed(stdout="ok")
        cve_intel("search 'severity:critical' --json")
        cmd = mock_run.call_args[0][0]
        # No HTTP URLs should leak into the argv from the wrapper itself
        for arg in cmd:
            self.assertFalse(
                re.match(r'^https?://', arg),
                f"Wrapper unexpectedly included a URL: {arg}"
            )


# ===========================================================================
# 2. INTEGRATION — registry + phase map + stealth wiring
# ===========================================================================

class TestCveIntelToolRegistry(unittest.TestCase):

    def test_in_registry(self):
        self.assertIn('cve_intel', TOOL_REGISTRY)

    def test_required_fields_present(self):
        entry = TOOL_REGISTRY['cve_intel']
        for field in ('purpose', 'when_to_use', 'args_format', 'description'):
            self.assertIn(field, entry, f"missing {field}")
            self.assertTrue(entry[field], f"{field} is empty")

    def test_description_mentions_data_sources(self):
        desc = TOOL_REGISTRY['cve_intel']['description']
        for keyword in ('NVD', 'KEV', 'EPSS', 'PoC'):
            self.assertIn(keyword, desc, f"description missing {keyword}")

    def test_description_mentions_subcommands(self):
        desc = TOOL_REGISTRY['cve_intel']['description']
        # Critical subcommands the agent needs to know about
        for subcmd in ('search', 'id', 'filters'):
            self.assertIn(subcmd, desc, f"description missing subcommand {subcmd}")

    def test_args_format_mentions_vulnx(self):
        args_fmt = TOOL_REGISTRY['cve_intel']['args_format']
        self.assertIn('vulnx', args_fmt)

    def test_purpose_indicates_passive_intel(self):
        purpose = TOOL_REGISTRY['cve_intel']['purpose'].lower()
        self.assertTrue(
            'cve' in purpose or 'intelligence' in purpose,
            f"purpose='{purpose}' should indicate CVE intel"
        )

    def test_kali_shell_excludes_vulnx(self):
        """The kali_shell exclusion list must mention vulnx so the agent
        prefers the dedicated cve_intel wrapper."""
        kali_desc = TOOL_REGISTRY['kali_shell']['description']
        self.assertIn('vulnx', kali_desc)


class TestCveIntelPhaseMap(unittest.TestCase):

    def test_in_phase_map(self):
        phase_map = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']
        self.assertIn('cve_intel', phase_map)

    def test_all_three_phases(self):
        """cve_intel is passive lookup → all 3 phases."""
        phases = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']['cve_intel']
        self.assertEqual(
            sorted(phases),
            ['exploitation', 'informational', 'post_exploitation'],
        )


class TestCveIntelDangerousTools(unittest.TestCase):

    def test_NOT_in_dangerous_tools(self):
        """cve_intel is read-only API call → should NOT require confirmation."""
        self.assertNotIn('cve_intel', DANGEROUS_TOOLS)


class TestCveIntelStealthRules(unittest.TestCase):

    def test_section_present(self):
        self.assertIn('cve_intel', STEALTH_MODE_RULES)

    def test_no_restrictions_classification(self):
        """cve_intel sends no traffic to target → NO RESTRICTIONS."""
        # Look for the cve_intel header line specifically
        m = re.search(
            r'###\s*cve_intel\s*[—-]+\s*NO RESTRICTIONS',
            STEALTH_MODE_RULES,
        )
        self.assertIsNotNone(
            m,
            "cve_intel must have a 'NO RESTRICTIONS' stealth section header",
        )

    def test_section_explains_no_target_traffic(self):
        idx = STEALTH_MODE_RULES.find('### cve_intel')
        self.assertGreater(idx, 0)
        # Take the next ~400 chars (the section body)
        section = STEALTH_MODE_RULES[idx:idx + 400].lower()
        self.assertTrue(
            'no traffic' in section or 'passive' in section,
            "cve_intel stealth section should justify NO RESTRICTIONS",
        )


# ===========================================================================
# 3. REGRESSION — existing tools unaffected, Prisma JSON valid
# ===========================================================================

class TestRegressionExistingTools(unittest.TestCase):
    """Make sure adding cve_intel didn't break any existing wiring."""

    EXISTING_TOOLS = [
        'query_graph', 'web_search', 'shodan', 'google_dork',
        'execute_curl', 'execute_naabu', 'execute_httpx', 'execute_subfinder',
        'execute_gau', 'execute_nmap', 'execute_nuclei', 'execute_wpscan',
        'execute_jsluice', 'execute_amass', 'execute_arjun', 'execute_ffuf',
        'execute_katana', 'kali_shell', 'execute_code', 'execute_playwright',
        'execute_hydra', 'metasploit_console', 'msf_restart',
    ]

    def test_all_pre_existing_tools_still_in_registry(self):
        for t in self.EXISTING_TOOLS:
            self.assertIn(t, TOOL_REGISTRY, f"{t} disappeared from TOOL_REGISTRY")

    def test_all_pre_existing_tools_still_in_phase_map(self):
        phase_map = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']
        for t in self.EXISTING_TOOLS:
            self.assertIn(t, phase_map, f"{t} disappeared from TOOL_PHASE_MAP")

    def test_dangerous_tools_unchanged_set(self):
        """Spot-check core dangerous tools are still flagged."""
        for t in ('execute_nmap', 'execute_nuclei', 'kali_shell',
                  'metasploit_console', 'execute_hydra', 'execute_code'):
            self.assertIn(t, DANGEROUS_TOOLS, f"{t} dropped from DANGEROUS_TOOLS")

    def test_existing_phase_assignments_intact(self):
        """Spot-check key phase assignments weren't accidentally rewritten."""
        pm = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']
        self.assertEqual(
            sorted(pm['query_graph']),
            ['exploitation', 'informational', 'post_exploitation'],
        )
        self.assertEqual(sorted(pm['execute_hydra']),
                         ['exploitation', 'post_exploitation'])
        self.assertEqual(sorted(pm['google_dork']), ['informational'])


class TestPrismaSchemaDefault(unittest.TestCase):
    """The agentToolPhaseMap default in schema.prisma is JSON inside a string.
    Validate that it parses, contains cve_intel, and didn't drop any pre-existing
    tools."""

    SCHEMA_PATH = os.path.join(
        _repo_root, 'webapp', 'prisma', 'schema.prisma'
    )

    EXPECTED_TOOLS = [
        'query_graph', 'web_search', 'cve_intel', 'shodan', 'google_dork',
        'execute_curl', 'execute_naabu', 'execute_httpx', 'execute_subfinder',
        'execute_wpscan', 'execute_jsluice', 'execute_amass', 'execute_katana',
        'execute_arjun', 'execute_ffuf', 'execute_gau', 'execute_nmap',
        'execute_nuclei', 'kali_shell', 'execute_code', 'execute_playwright',
        'execute_hydra', 'metasploit_console', 'msf_restart',
        'tradecraft_lookup',
    ]

    def _extract_default_json(self):
        with open(self.SCHEMA_PATH, 'r') as f:
            content = f.read()
        # Find: agentToolPhaseMap ... @default("...JSON...") @map(...)
        m = re.search(
            r'agentToolPhaseMap\s+Json\s+@default\("(.+?)"\)\s+@map',
            content,
        )
        self.assertIsNotNone(m, "could not locate agentToolPhaseMap default")
        # Prisma escapes embedded quotes as \"; un-escape to get real JSON
        raw = m.group(1).replace('\\"', '"')
        return raw

    def test_default_is_valid_json(self):
        raw = self._extract_default_json()
        parsed = json.loads(raw)  # raises if malformed -> test fails
        self.assertIsInstance(parsed, dict)

    def test_default_contains_cve_intel(self):
        raw = self._extract_default_json()
        parsed = json.loads(raw)
        self.assertIn('cve_intel', parsed)
        self.assertEqual(
            sorted(parsed['cve_intel']),
            ['exploitation', 'informational', 'post_exploitation'],
        )

    def test_default_includes_all_known_tools(self):
        raw = self._extract_default_json()
        parsed = json.loads(raw)
        for t in self.EXPECTED_TOOLS:
            self.assertIn(t, parsed, f"{t} missing from Prisma default")


class TestRegistryPhaseMapConsistency(unittest.TestCase):
    """Cross-layer: every tool in TOOL_PHASE_MAP should be registered somewhere."""

    # tradecraft_lookup is injected dynamically at runtime by the orchestrator
    # (see swap_tradecraft_entry) and is not in the static TOOL_REGISTRY dict.
    KNOWN_DYNAMIC = {'tradecraft_lookup'}

    def test_phase_map_keys_are_in_registry(self):
        phase_map = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']
        for tool in phase_map:
            if tool in self.KNOWN_DYNAMIC:
                continue
            self.assertIn(
                tool, TOOL_REGISTRY,
                f"{tool} in TOOL_PHASE_MAP but missing from TOOL_REGISTRY",
            )


class TestFrontendToolMatrix(unittest.TestCase):
    """The Tool Matrix UI row is the agent's user-visible toggle for the tool.
    Without it, operators can't disable cve_intel per project."""

    TSX_PATH = os.path.join(
        _repo_root, 'webapp', 'src', 'components', 'projects',
        'ProjectForm', 'sections', 'ToolMatrixSection.tsx',
    )

    def test_row_present(self):
        with open(self.TSX_PATH, 'r') as f:
            content = f.read()
        self.assertIn("id: 'cve_intel'", content)
        self.assertIn("label: 'cve_intel'", content)


class TestShellInjectionSafety(unittest.TestCase):
    """Defense in depth: cve_intel must use argv form, never shell=True.
    A malicious agent prompt mustn't be able to escape into the host shell."""

    @patch('network_recon_server.subprocess.run')
    def test_subprocess_not_invoked_with_shell_true(self, mock_run):
        mock_run.return_value = _mock_completed(stdout="")
        # Pass an arg that WOULD be dangerous under shell=True
        cve_intel("search '; rm -rf / #' --json")
        # First positional arg must be a list (argv form), not a string
        first_pos = mock_run.call_args[0][0]
        self.assertIsInstance(first_pos, list)
        # And shell kwarg must not be True
        self.assertNotEqual(mock_run.call_args[1].get("shell"), True)

    @patch('network_recon_server.subprocess.run')
    def test_metacharacters_pass_through_as_literal_args(self, mock_run):
        """Backticks, $(), and ; in args must be literal argv elements,
        never interpreted by a shell."""
        mock_run.return_value = _mock_completed(stdout="")
        cve_intel("id 'CVE-2024-1; whoami' --json")
        cmd = mock_run.call_args[0][0]
        # The malicious payload remains a single, literal argv element
        self.assertIn("CVE-2024-1; whoami", cmd)


class TestPdcpApiKeyPlumbing(unittest.TestCase):
    """The PDCP API key is OPTIONAL, managed per-user from /settings, and silently
    injected by the executor at call time. No env vars, no Docker build args.
    This class locks the Pattern-2 contract end-to-end."""

    # ---- MCP function: accepts api_key kwarg and forwards as env var ----

    @patch('network_recon_server.subprocess.run')
    def test_no_key_no_pdcp_env_set(self, mock_run):
        """When api_key is not passed, PDCP_API_KEY must NOT be set in subprocess env."""
        mock_run.return_value = _mock_completed(stdout="ok")
        cve_intel("filters")
        env = mock_run.call_args[1].get("env", {})
        self.assertNotIn("PDCP_API_KEY", env)

    @patch('network_recon_server.subprocess.run')
    def test_key_passed_sets_pdcp_env(self, mock_run):
        """When api_key is passed, PDCP_API_KEY env var is set for that subprocess only."""
        mock_run.return_value = _mock_completed(stdout="ok")
        cve_intel("id CVE-2024-1 --json", api_key="test-pdcp-key-xyz")
        env = mock_run.call_args[1]["env"]
        self.assertEqual(env.get("PDCP_API_KEY"), "test-pdcp-key-xyz")

    @patch('network_recon_server.subprocess.run')
    def test_empty_key_does_not_set_pdcp_env(self, mock_run):
        """An empty-string api_key must be treated as 'no key' and NOT pollute env."""
        mock_run.return_value = _mock_completed(stdout="ok")
        cve_intel("filters", api_key="")
        env = mock_run.call_args[1].get("env", {})
        self.assertNotIn("PDCP_API_KEY", env)

    @patch('network_recon_server.subprocess.run')
    def test_key_does_not_appear_in_argv(self, mock_run):
        """The key must travel via env, NEVER in argv (would leak to process listing)."""
        mock_run.return_value = _mock_completed(stdout="ok")
        cve_intel("id CVE-1 --json", api_key="SECRET-12345")
        cmd = mock_run.call_args[0][0]
        for arg in cmd:
            self.assertNotIn("SECRET-12345", arg)

    @patch('network_recon_server.subprocess.run')
    def test_subprocess_env_inherits_path(self, mock_run):
        """Without inheriting parent env, vulnx wouldn't be findable on PATH."""
        mock_run.return_value = _mock_completed(stdout="ok")
        cve_intel("filters", api_key="any-key")
        env = mock_run.call_args[1]["env"]
        # PATH must be inherited so 'vulnx' resolves under /root/go/bin
        self.assertIn("PATH", env)

    # ---- Frontend: full Pattern-2 plumbing across all 5 layers ----

    def test_prisma_has_pdcp_field(self):
        schema = os.path.join(_repo_root, 'webapp', 'prisma', 'schema.prisma')
        with open(schema, 'r') as f:
            content = f.read()
        self.assertIn('pdcpApiKey', content)
        self.assertIn('@map("pdcp_api_key")', content)

    def test_settings_api_route_whitelists_pdcp_field(self):
        route = os.path.join(
            _repo_root, 'webapp', 'src', 'app', 'api', 'users',
            '[id]', 'settings', 'route.ts',
        )
        with open(route, 'r') as f:
            content = f.read()
        # PUT whitelist
        self.assertIn("'pdcpApiKey'", content)
        # GET masking: every column in SECRET_FIELDS goes through maskSecrets
        secret_fields = re.search(r"const SECRET_FIELDS = \[([\s\S]*?)\]", content)
        self.assertIsNotNone(secret_fields, "the route's SECRET_FIELDS list is gone")
        self.assertIn("'pdcpApiKey'", secret_fields.group(1))
        self.assertIn('maskSecrets(settings)', content)
        # Rotation allowlist (so the rotation modal actually persists): the PUT reads
        # the shared list since d03f53ed, which must name pdcp
        self.assertIn("from '@/lib/rotationTools'", content)
        self.assertIn('ROTATION_TOOL_NAMES', content)
        self.assertRegex(self._rotation_tools(), r"tool: 'pdcp', field: 'pdcpApiKey'")

    def _rotation_tools(self) -> str:
        with open(os.path.join(_repo_root, 'webapp', 'src', 'lib', 'rotationTools.ts')) as f:
            return f.read()

    def test_settings_page_has_pdcp_secretfield(self):
        page = os.path.join(
            _repo_root, 'webapp', 'src', 'app', 'settings', 'page.tsx'
        )
        with open(page, 'r') as f:
            content = f.read()
        # Interface + EMPTY + handler + JSX field
        self.assertIn('pdcpApiKey: string', content)
        self.assertIn("pdcpApiKey: ''", content)
        self.assertIn("pdcpApiKey: data.pdcpApiKey", content)
        self.assertIn('label="PDCP API Key"', content)
        # AI Agent badge (per user requirement)
        self.assertRegex(content, r'label="PDCP API Key"[\s\S]{0,400}badges=\{\[.*AI Agent.*\]\}')

    def test_tool_matrix_has_cve_intel_key_entry(self):
        tsx = os.path.join(
            _repo_root, 'webapp', 'src', 'components', 'projects',
            'ProjectForm', 'sections', 'ToolMatrixSection.tsx',
        )
        with open(tsx, 'r') as f:
            content = f.read()
        self.assertIn('cve_intel:', content)
        self.assertIn("field: 'pdcpApiKey'", content)
        self.assertIn("if (!settings.pdcpApiKey) missing.add('cve_intel')", content)

    def test_chat_drawer_has_cve_intel_key_modal(self):
        hook = os.path.join(
            _repo_root, 'webapp', 'src', 'app', 'graph', 'components',
            'AIAssistantDrawer', 'hooks', 'useApiKeyModal.ts',
        )
        with open(hook, 'r') as f:
            content = f.read()
        # The missing-key check is derived from API_KEY_INFO (missingKeyTools), so
        # cve_intel is covered only while API_KEY_INFO maps it to pdcpApiKey and the
        # settings fetch goes through missingKeyTools.
        info = re.search(r'^export const API_KEY_INFO\b[^=]*= \{\n(.*?)^\}', content, re.M | re.S)
        self.assertIsNotNone(info, 'API_KEY_INFO object not found')
        self.assertRegex(info.group(1), r"(?m)^\s*cve_intel:\s*\{\s*field:\s*'pdcpApiKey'")
        derive = re.search(r'^function missingKeyTools\(settings[^)]*\)[^{]*\{\n(.*?)^\}',
                           content, re.M | re.S)
        self.assertIsNotNone(derive, 'missingKeyTools not found')
        self.assertIn('Object.keys(API_KEY_INFO)', derive.group(1))
        self.assertRegex(derive.group(1), r'!\s*settings\[API_KEY_INFO\[\w+\]\.field\]')
        self.assertIn('setMissingApiKeys(missingKeyTools(settings))', content)

    def test_tool_execution_card_has_cve_intel_label(self):
        card = os.path.join(
            _repo_root, 'webapp', 'src', 'app', 'graph', 'components',
            'AIAssistantDrawer', 'ToolExecutionCard.tsx',
        )
        with open(card, 'r') as f:
            content = f.read()
        self.assertRegex(content, r"cve_intel:\s*'PDCP'")

    def test_api_keys_template_has_pdcp(self):
        tpl = os.path.join(
            _repo_root, 'webapp', 'src', 'lib', 'apiKeysTemplate.ts'
        )
        with open(tpl, 'r') as f:
            content = f.read()
        self.assertIn("'pdcpApiKey'", content)
        # Rotation entries come from the shared list, which must name pdcp
        self.assertIn("from './rotationTools'", content)
        self.assertRegex(self._rotation_tools(), r"tool: 'pdcp', field: 'pdcpApiKey'")

    # ---- Anti-regression: no env var leakage in the deployment surface ----

    def test_dockerfile_does_not_set_pdcp_env_var(self):
        """Dockerfile may MENTION the env var (for documentation), but must not
        ENV/ARG-declare it -- the key is per-user, never baked into the image."""
        dockerfile = os.path.join(_repo_root, 'mcp', 'kali-sandbox', 'Dockerfile')
        with open(dockerfile, 'r') as f:
            content = f.read()
        self.assertIsNone(
            re.search(r'^\s*ENV\s+PDCP_API_KEY', content, re.MULTILINE),
            "Dockerfile must not ENV-declare PDCP_API_KEY",
        )
        self.assertIsNone(
            re.search(r'^\s*ARG\s+PDCP_API_KEY', content, re.MULTILINE),
            "Dockerfile must not ARG-declare PDCP_API_KEY",
        )

    def test_docker_compose_does_not_set_pdcp_env_var(self):
        """docker-compose must not propagate PDCP_API_KEY -- per-user only."""
        for fname in ('docker-compose.yml', 'agentic/docker-compose.yml'):
            path = os.path.join(_repo_root, fname)
            if not os.path.exists(path):
                continue
            with open(path, 'r') as f:
                content = f.read()
            self.assertNotIn(
                'PDCP_API_KEY', content,
                f"{fname} must not declare PDCP_API_KEY env var (per-user only)",
            )


class TestDockerfileInstall(unittest.TestCase):
    """Verify the Dockerfile actually installs vulnx."""

    DOCKERFILE = os.path.join(
        _repo_root, 'mcp', 'kali-sandbox', 'Dockerfile'
    )

    def test_dockerfile_installs_vulnx(self):
        with open(self.DOCKERFILE, 'r') as f:
            content = f.read()
        self.assertIn('projectdiscovery/vulnx', content)
        self.assertIn('go install', content)
        # Verify the install line is actually executed (in a RUN block,
        # not just commented out)
        m = re.search(
            r'^RUN[^\n]*projectdiscovery/vulnx',
            content,
            re.MULTILINE,
        )
        self.assertIsNotNone(
            m,
            "vulnx install must be in a live RUN block, not a comment",
        )


# ===========================================================================
# 4. SMOKE — real vulnx binary if installed (auto-skipped otherwise)
# ===========================================================================

class TestCveIntelSmoke(unittest.TestCase):
    """Real-binary smoke tests. Skipped unless vulnx is on PATH."""

    @classmethod
    def setUpClass(cls):
        if shutil.which('vulnx') is None:
            raise unittest.SkipTest("vulnx not installed on PATH")

    def test_filters_subcommand_runs(self):
        """`vulnx filters` should always work, even unauthenticated."""
        result = cve_intel("filters")
        self.assertNotIn("[ERROR] vulnx not found", result)
        # Output should at least mention some known fields
        # (relaxed: tool may emit ascii table or json depending on flag)
        self.assertGreater(len(result), 50)

    def test_id_lookup_returns_text(self):
        """A well-known CVE lookup should return *something*."""
        result = cve_intel("id CVE-2021-44228 --json")
        self.assertIsInstance(result, str)
        # We accept either real data, rate-limit msg, or auth msg as success
        self.assertTrue(len(result) > 0)


if __name__ == '__main__':
    unittest.main()
