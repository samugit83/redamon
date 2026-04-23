"""
Unit tests for WPScan API token integration.
Validates the full key lifecycle: DB schema, API route, settings UI,
Tool Matrix, chat drawer, tool cards, executor injection, and orchestrator.
"""
import re
import os
import ast
import unittest

BASE_DIR = os.path.join(os.path.dirname(__file__), '..')


class TestPrismaSchemaWPScanToken(unittest.TestCase):
    """Verify wpscanApiToken field in UserSettings model."""

    def setUp(self):
        path = os.path.join(BASE_DIR, 'webapp', 'prisma', 'schema.prisma')
        with open(path) as f:
            self.content = f.read()

    def test_field_exists(self):
        """wpscanApiToken field must exist in UserSettings model."""
        self.assertIn('wpscanApiToken', self.content)

    def test_field_has_default_empty(self):
        """wpscanApiToken must default to empty string."""
        self.assertRegex(self.content, r'wpscanApiToken\s+String\s+@default\(""\)')

    def test_field_has_column_mapping(self):
        """wpscanApiToken must map to wpscan_api_token column."""
        self.assertIn('@map("wpscan_api_token")', self.content)

    def test_field_in_tool_keys_section(self):
        """wpscanApiToken must be in the Tool API Keys section (near other keys)."""
        # Should be near driftnetApiKey (the previous key in the list)
        driftnet_pos = self.content.index('driftnetApiKey')
        wpscan_pos = self.content.index('wpscanApiToken')
        ngrok_pos = self.content.index('ngrokAuthtoken')
        # wpscan should be between driftnet and ngrok (tunneling section)
        self.assertGreater(wpscan_pos, driftnet_pos)
        self.assertLess(wpscan_pos, ngrok_pos)


class TestSettingsAPIRoute(unittest.TestCase):
    """Verify settings API route includes wpscanApiToken."""

    def setUp(self):
        path = os.path.join(BASE_DIR, 'webapp', 'src', 'app', 'api',
                           'users', '[id]', 'settings', 'route.ts')
        with open(path) as f:
            self.content = f.read()

    def test_get_masking(self):
        """wpscanApiToken must be masked in GET response."""
        self.assertIn('wpscanApiToken: maskSecret(settings.wpscanApiToken)', self.content)

    def test_put_whitelist(self):
        """wpscanApiToken must be in PUT fields whitelist."""
        # Find the fields array
        match = re.search(r"const fields = \[([^\]]+)\]", self.content)
        self.assertIsNotNone(match)
        fields_str = match.group(1)
        self.assertIn("'wpscanApiToken'", fields_str)


class TestSettingsPageUI(unittest.TestCase):
    """Verify Global Settings page includes wpscanApiToken."""

    def setUp(self):
        path = os.path.join(BASE_DIR, 'webapp', 'src', 'app', 'settings', 'page.tsx')
        with open(path) as f:
            self.content = f.read()

    def test_interface_has_field(self):
        """UserSettings interface must include wpscanApiToken."""
        # Find the interface block
        match = re.search(r'interface UserSettings \{([^}]+)\}', self.content)
        self.assertIsNotNone(match)
        self.assertIn('wpscanApiToken: string', match.group(1))

    def test_empty_settings_has_field(self):
        """EMPTY_SETTINGS must include wpscanApiToken."""
        self.assertIn("wpscanApiToken: ''", self.content)

    def test_tool_name_map_has_entry(self):
        """TOOL_NAME_MAP must map wpscanApiToken to 'wpscan'."""
        self.assertIn("wpscanApiToken: 'wpscan'", self.content)

    def test_fetch_settings_has_field(self):
        """fetchSettings response handler must include wpscanApiToken."""
        count = self.content.count("wpscanApiToken: data.wpscanApiToken || ''")
        # Two handlers: initial fetch + save-and-refresh
        self.assertEqual(count, 2,
                        f"Expected 2 fetchSettings handlers with wpscanApiToken, found {count}")

    def test_secret_field_exists(self):
        """SecretField for WPScan API Token must exist."""
        self.assertIn('label="WPScan API Token"', self.content)

    def test_secret_field_has_signup_url(self):
        """SecretField must link to WPScan registration."""
        self.assertIn('signupUrl="https://wpscan.com/register"', self.content)

    def test_secret_field_has_agent_badge(self):
        """SecretField must have AI Agent badge."""
        # Find the WPScan SecretField block
        wpscan_start = self.content.index('label="WPScan API Token"')
        wpscan_end = self.content.index('/>', wpscan_start)
        wpscan_block = self.content[wpscan_start:wpscan_end]
        self.assertIn("badges={['AI Agent']}", wpscan_block)

    def test_secret_field_position(self):
        """WPScan SecretField should appear after SerpAPI and before NVD."""
        serp_pos = self.content.index('label="SerpAPI Key"')
        wpscan_pos = self.content.index('label="WPScan API Token"')
        nvd_pos = self.content.index('label="NVD API Key"')
        self.assertGreater(wpscan_pos, serp_pos)
        self.assertLess(wpscan_pos, nvd_pos)


class TestToolMatrixKeyInfo(unittest.TestCase):
    """Verify ToolMatrixSection includes WPScan key warning."""

    def setUp(self):
        path = os.path.join(BASE_DIR, 'webapp', 'src', 'components', 'projects',
                           'ProjectForm', 'sections', 'ToolMatrixSection.tsx')
        with open(path) as f:
            self.content = f.read()

    def test_tool_key_info_has_wpscan(self):
        """TOOL_KEY_INFO must have execute_wpscan entry."""
        self.assertIn("execute_wpscan:", self.content)

    def test_tool_key_info_field(self):
        """TOOL_KEY_INFO execute_wpscan must reference wpscanApiToken field."""
        self.assertIn("field: 'wpscanApiToken'", self.content)

    def test_tool_key_info_label(self):
        """TOOL_KEY_INFO execute_wpscan must have WPScan label."""
        self.assertIn("label: 'WPScan'", self.content)

    def test_fetch_key_status_checks_wpscan(self):
        """fetchKeyStatus must check for missing wpscanApiToken."""
        self.assertIn("!settings.wpscanApiToken", self.content)
        self.assertIn("missing.add('execute_wpscan')", self.content)


class TestUseApiKeyModal(unittest.TestCase):
    """Verify chat drawer API key modal includes WPScan."""

    def setUp(self):
        path = os.path.join(BASE_DIR, 'webapp', 'src', 'app', 'graph',
                           'components', 'AIAssistantDrawer', 'hooks', 'useApiKeyModal.ts')
        with open(path) as f:
            self.content = f.read()

    def test_api_key_info_has_wpscan(self):
        """API_KEY_INFO must have execute_wpscan entry."""
        self.assertIn('execute_wpscan:', self.content)

    def test_api_key_info_field(self):
        """API_KEY_INFO execute_wpscan must reference wpscanApiToken."""
        self.assertIn("field: 'wpscanApiToken'", self.content)

    def test_fetch_status_checks_wpscan(self):
        """fetchApiKeyStatus must check for missing wpscanApiToken."""
        self.assertIn("!settings.wpscanApiToken", self.content)
        self.assertIn("missing.add('execute_wpscan')", self.content)


class TestToolExecutionCard(unittest.TestCase):
    """Verify tool execution card has WPScan key label."""

    def setUp(self):
        path = os.path.join(BASE_DIR, 'webapp', 'src', 'app', 'graph',
                           'components', 'AIAssistantDrawer', 'ToolExecutionCard.tsx')
        with open(path) as f:
            self.content = f.read()

    def test_tool_key_label_has_wpscan(self):
        """TOOL_KEY_LABEL must have execute_wpscan entry."""
        self.assertIn("execute_wpscan: 'WPScan'", self.content)


class TestExecutorTokenInjection(unittest.TestCase):
    """Verify PhaseAwareToolExecutor injects WPScan API token."""

    def setUp(self):
        path = os.path.join(BASE_DIR, 'agentic', 'tools.py')
        with open(path) as f:
            self.content = f.read()

    def test_set_wpscan_api_token_method_exists(self):
        """set_wpscan_api_token method must exist on PhaseAwareToolExecutor."""
        self.assertIn('def set_wpscan_api_token(self, token: str)', self.content)

    def test_execute_wpscan_elif_branch(self):
        """execute() must have an elif branch for execute_wpscan."""
        self.assertIn('elif tool_name == "execute_wpscan":', self.content)

    def test_token_injection_checks_existing(self):
        """Token injection must not override user-provided --api-token."""
        self.assertIn("'--api-token' not in args", self.content)

    def test_token_injection_uses_getattr(self):
        """Token injection must safely access _wpscan_api_token with getattr."""
        self.assertIn("getattr(self, '_wpscan_api_token', '')", self.content)

    def test_token_prepended_to_args(self):
        """Token must be prepended to args string."""
        self.assertIn('f"--api-token {self._wpscan_api_token} {args}"', self.content)

    def test_original_tool_args_not_mutated(self):
        """Original tool_args dict must not be mutated (use spread)."""
        # Should create a new dict, not modify in place
        self.assertIn('{**tool_args, "args": args}', self.content)


class TestOrchestratorWPScanKey(unittest.TestCase):
    """Verify orchestrator reads and passes WPScan API token."""

    def setUp(self):
        path = os.path.join(BASE_DIR, 'agentic', 'orchestrator.py')
        with open(path) as f:
            self.content = f.read()

    def test_reads_wpscan_token_from_settings(self):
        """Orchestrator must read wpscanApiToken from user settings."""
        self.assertIn("user_settings.get('wpscanApiToken', '')", self.content)

    def test_calls_set_wpscan_api_token(self):
        """Orchestrator must call set_wpscan_api_token on executor."""
        self.assertIn('self.tool_executor.set_wpscan_api_token(wpscan_token)', self.content)

    def test_wpscan_block_position(self):
        """WPScan block must be in _apply_project_settings (near Shodan block)."""
        wpscan_pos = self.content.index("wpscanApiToken")
        shodan_pos = self.content.index("shodanApiKey")
        # WPScan should be near Shodan (within _apply_project_settings)
        self.assertLess(abs(wpscan_pos - shodan_pos), 1000,
                       "WPScan and Shodan key handling should be in the same method")

    def test_conditional_on_token_and_executor(self):
        """Token should only be set if both token exists and executor exists."""
        self.assertIn('if wpscan_token and self.tool_executor:', self.content)


class TestTokenInjectionLogic(unittest.TestCase):
    """Test the actual token injection logic in isolation."""

    def test_injection_when_token_set(self):
        """Token should be prepended when configured and not in args."""
        token = "abc123"
        args = "--url http://example.com --enumerate vp,vt"
        if token and '--api-token' not in args:
            args = f"--api-token {token} {args}"
        self.assertEqual(args, "--api-token abc123 --url http://example.com --enumerate vp,vt")

    def test_no_injection_when_already_present(self):
        """Token should NOT be injected if user already passed --api-token."""
        token = "abc123"
        args = "--url http://example.com --api-token USER_TOKEN --enumerate vp,vt"
        original_args = args
        if token and '--api-token' not in args:
            args = f"--api-token {token} {args}"
        self.assertEqual(args, original_args)

    def test_no_injection_when_no_token(self):
        """Token should NOT be injected if not configured."""
        token = ""
        args = "--url http://example.com"
        original_args = args
        if token and '--api-token' not in args:
            args = f"--api-token {token} {args}"
        self.assertEqual(args, original_args)

    def test_getattr_fallback(self):
        """getattr with default '' should work when attribute doesn't exist."""
        class MockExecutor:
            pass
        executor = MockExecutor()
        result = getattr(executor, '_wpscan_api_token', '')
        self.assertEqual(result, '')

    def test_getattr_with_token(self):
        """getattr should return token when attribute exists."""
        class MockExecutor:
            _wpscan_api_token = "test_key_123"
        executor = MockExecutor()
        result = getattr(executor, '_wpscan_api_token', '')
        self.assertEqual(result, 'test_key_123')


class TestCrossFileConsistencyAPIKey(unittest.TestCase):
    """Verify all files agree on field names and tool identifiers."""

    def setUp(self):
        self.files = {}
        paths = {
            'schema': ('webapp', 'prisma', 'schema.prisma'),
            'route': ('webapp', 'src', 'app', 'api', 'users', '[id]', 'settings', 'route.ts'),
            'settings': ('webapp', 'src', 'app', 'settings', 'page.tsx'),
            'matrix': ('webapp', 'src', 'components', 'projects', 'ProjectForm', 'sections', 'ToolMatrixSection.tsx'),
            'modal': ('webapp', 'src', 'app', 'graph', 'components', 'AIAssistantDrawer', 'hooks', 'useApiKeyModal.ts'),
            'card': ('webapp', 'src', 'app', 'graph', 'components', 'AIAssistantDrawer', 'ToolExecutionCard.tsx'),
            'tools': ('agentic', 'tools.py'),
            'orchestrator': ('agentic', 'orchestrator.py'),
        }
        for key, parts in paths.items():
            with open(os.path.join(BASE_DIR, *parts)) as f:
                self.files[key] = f.read()

    def test_field_name_consistent(self):
        """'wpscanApiToken' must appear in all frontend files."""
        for key in ['schema', 'route', 'settings', 'matrix', 'modal']:
            self.assertIn('wpscanApiToken', self.files[key],
                         f"wpscanApiToken missing from {key}")

    def test_tool_id_consistent(self):
        """'execute_wpscan' must be the tool identifier everywhere."""
        for key in ['matrix', 'modal', 'card', 'tools']:
            self.assertIn('execute_wpscan', self.files[key],
                         f"execute_wpscan missing from {key}")

    def test_db_column_name(self):
        """DB column must be wpscan_api_token (snake_case)."""
        self.assertIn('wpscan_api_token', self.files['schema'])

    def test_label_consistent(self):
        """Human label 'WPScan' must be consistent across UI files."""
        for key in ['matrix', 'modal', 'card']:
            self.assertIn("'WPScan'", self.files[key],
                         f"WPScan label missing from {key}")


if __name__ == '__main__':
    unittest.main(verbosity=2)
