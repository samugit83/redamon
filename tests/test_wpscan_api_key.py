"""
Unit tests for WPScan API token integration.
Validates the full key lifecycle: DB schema, API route, settings UI,
Tool Matrix, chat drawer, tool cards, executor injection, and orchestrator.
"""
import asyncio
import os
import re
import sys
import unittest
from subprocess import CompletedProcess
from unittest import mock

BASE_DIR = os.path.join(os.path.dirname(__file__), '..')
for _extra in (
    os.path.join(BASE_DIR, 'agentic'),
    os.path.join(BASE_DIR, 'agentic', 'tests'),
    os.path.join(BASE_DIR, 'mcp', 'servers'),
):
    if _extra not in sys.path:
        sys.path.insert(0, _extra)

import pytest


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
        # Scoped to UserSettings: model InstanceSettings, earlier in the file,
        # carries its own ngrokAuthtoken.
        match = re.search(r'^model UserSettings \{\n(.*?)^\}', self.content, re.M | re.S)
        self.assertIsNotNone(match, 'model UserSettings block not found')
        block = match.group(1)
        # Should be near driftnetApiKey (the previous key in the list)
        driftnet_pos = block.index('driftnetApiKey')
        wpscan_pos = block.index('wpscanApiToken')
        ngrok_pos = block.index('ngrokAuthtoken')
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
        """wpscanApiToken must be masked in GET response (the shared SECRET_FIELDS list)."""
        match = re.search(r"const SECRET_FIELDS = \[([^\]]+)\]", self.content)
        self.assertIsNotNone(match)
        self.assertIn("'wpscanApiToken'", match.group(1))
        self.assertIn('settings = maskSecrets(settings)', self.content)

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
        """The shared rotation list (rotationTools.ts) must map wpscanApiToken to 'wpscan'."""
        path = os.path.join(BASE_DIR, 'webapp', 'src', 'lib', 'rotationTools.ts')
        with open(path) as f:
            rotation = f.read()
        self.assertIn("{ tool: 'wpscan', field: 'wpscanApiToken'", rotation)
        self.assertIn("from '@/lib/rotationTools'", self.content)

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
        """The drawer's missing-key check covers wpscanApiToken.

        The check is derived from API_KEY_INFO (missingKeyTools), so WPScan is
        covered only while API_KEY_INFO maps execute_wpscan to wpscanApiToken
        AND both the own-settings fetch and the owner-catalog path use it.
        """
        info = re.search(r'^export const API_KEY_INFO\b[^=]*= \{\n(.*?)^\}',
                         self.content, re.M | re.S)
        self.assertIsNotNone(info, 'API_KEY_INFO object not found')
        self.assertRegex(info.group(1),
                         r"(?m)^\s*execute_wpscan:\s*\{\s*field:\s*'wpscanApiToken'")

        derive = re.search(r'^function missingKeyTools\(settings[^)]*\)[^{]*\{\n(.*?)^\}',
                           self.content, re.M | re.S)
        self.assertIsNotNone(derive, 'missingKeyTools not found')
        self.assertIn('Object.keys(API_KEY_INFO)', derive.group(1))
        self.assertRegex(derive.group(1), r'!\s*settings\[API_KEY_INFO\[\w+\]\.field\]')

        fetch = re.search(r'const fetchApiKeyStatus = useCallback\((.*?)\n  \}, \[',
                          self.content, re.S)
        self.assertIsNotNone(fetch, 'fetchApiKeyStatus not found')
        self.assertIn('setMissingApiKeys(missingKeyTools(settings))', fetch.group(1))
        self.assertIn('missingKeyTools(ownerKeys)', self.content)


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
    """Verify PhaseAwareToolExecutor injects WPScan API token safely via api_token kwarg."""

    def _executor(self, fallback_token=""):
        from one_sandbox import route_to
        from tools import PhaseAwareToolExecutor

        ex = PhaseAwareToolExecutor(mcp_manager=mock.MagicMock(), graph_tool=None)
        tool = mock.AsyncMock()
        tool.name = "execute_wpscan"
        tool.ainvoke.return_value = "ok"
        route_to(self, {"execute_wpscan": tool})
        if fallback_token:
            ex.set_wpscan_api_token(fallback_token)
        return ex, tool

    def _run(self, ex, tool_args, user_settings=None):
        import project_settings

        async def _invoke():
            ctx_token = None
            if user_settings is not None:
                ctx_token = project_settings._settings_ctx.set({"USER_SETTINGS": user_settings})
            try:
                with mock.patch("tools.is_tool_allowed_in_phase", return_value=True):
                    return await ex.execute("execute_wpscan", tool_args, phase="informational")
            finally:
                if ctx_token is not None:
                    project_settings._settings_ctx.reset(ctx_token)

        return asyncio.run(_invoke())

    def test_token_from_user_settings_travels_as_api_token_kwarg(self):
        """USER_SETTINGS token is passed via api_token kwarg, never in CLI args, without mutating input."""
        ex, tool = self._executor()
        original = {"args": "--url https://wp.example --format json"}
        self._run(ex, original, user_settings={"wpscanApiToken": "user-ctx-token"})

        sent = tool.ainvoke.call_args.args[0]
        self.assertEqual(sent["api_token"], "user-ctx-token")
        self.assertEqual(sent["args"], "--url https://wp.example --format json")
        self.assertNotIn("user-ctx-token", sent["args"])
        self.assertNotIn("--api-token", sent["args"])
        self.assertEqual(original, {"args": "--url https://wp.example --format json"})

    def test_explicit_cli_token_suppresses_injection(self):
        """An explicit --api-token in args is left intact without adding api_token."""
        ex, tool = self._executor(fallback_token="fallback-tok")
        self._run(
            ex,
            {"args": "--url https://wp.example --api-token MANUAL_TOK"},
            user_settings={"wpscanApiToken": "user-ctx-token"},
        )
        sent = tool.ainvoke.call_args.args[0]
        self.assertNotIn("api_token", sent)
        self.assertEqual(sent["args"], "--url https://wp.example --api-token MANUAL_TOK")

    def test_fallback_attribute_used_when_user_settings_empty(self):
        """set_wpscan_api_token acts as fallback when USER_SETTINGS has no wpscanApiToken."""
        ex, tool = self._executor(fallback_token="fallback-tok")
        self._run(ex, {"args": "--url https://wp.example"}, user_settings={})
        self.assertEqual(tool.ainvoke.call_args.args[0]["api_token"], "fallback-tok")

    def test_user_settings_overrides_fallback_and_empty_sends_none(self):
        """Task USER_SETTINGS overrides fallback; when both are empty, api_token is omitted."""
        ex, tool = self._executor(fallback_token="fallback-tok")
        self._run(ex, {"args": "--url https://wp.example"}, user_settings={"wpscanApiToken": "ctx-wins"})
        self.assertEqual(tool.ainvoke.call_args.args[0]["api_token"], "ctx-wins")

        ex_empty, tool_empty = self._executor(fallback_token="")
        self._run(ex_empty, {"args": "--url https://wp.example"}, user_settings={})
        self.assertNotIn("api_token", tool_empty.ainvoke.call_args.args[0])

    def test_concurrent_sessions_do_not_leak_tokens(self):
        """RBAC T17: concurrent tasks read isolated ContextVar USER_SETTINGS, never shared state."""
        import project_settings
        from one_sandbox import route_to
        from tools import PhaseAwareToolExecutor

        ex = PhaseAwareToolExecutor(mcp_manager=mock.MagicMock(), graph_tool=None)
        observed = []

        async def _fake_ainvoke(payload):
            await asyncio.sleep(0)
            observed.append(dict(payload))
            return "ok"

        tool = mock.MagicMock()
        tool.name = "execute_wpscan"
        tool.ainvoke = _fake_ainvoke
        route_to(self, {"execute_wpscan": tool})

        async def _session(user_settings):
            tok = project_settings._settings_ctx.set({"USER_SETTINGS": user_settings})
            try:
                with mock.patch("tools.is_tool_allowed_in_phase", return_value=True):
                    await ex.execute("execute_wpscan", {"args": "--url https://wp.example"}, phase="informational")
            finally:
                project_settings._settings_ctx.reset(tok)

        async def _run_both():
            await asyncio.gather(
                _session({"wpscanApiToken": "tenant-alpha-token"}),
                _session({}),
            )

        asyncio.run(_run_both())
        tokens = sorted(item.get("api_token", "") for item in observed)
        self.assertEqual(tokens, ["", "tenant-alpha-token"])


class TestMCPWPScanEnvPassing(unittest.TestCase):
    """Verify network_recon_server.execute_wpscan passes api_token via env, not CLI argv."""

    @staticmethod
    def _import_server():
        if "fastmcp" not in sys.modules:
            class _FakeMCP:
                def __init__(self, *a, **kw):
                    pass

                def tool(self, *a, **kw):
                    def _identity(fn):
                        return fn
                    return _identity

                def __getattr__(self, name):
                    return mock.MagicMock()

            fastmcp_mod = mock.MagicMock()
            fastmcp_mod.FastMCP = _FakeMCP
            sys.modules["fastmcp"] = fastmcp_mod
        import network_recon_server
        return network_recon_server

    def test_api_token_passed_in_env_not_command_argv(self):
        nrs = self._import_server()
        fn = getattr(nrs.execute_wpscan, "fn", None) or getattr(nrs.execute_wpscan, "__wrapped__", None) or nrs.execute_wpscan
        with mock.patch("capture_routing.agent_capture_routing", return_value=(None, None)), \
             mock.patch.object(nrs.subprocess, "run", return_value=CompletedProcess(args=[], returncode=0, stdout="{}", stderr="")) as mock_run:
            fn(args="--url https://wp.example --format json", api_token="secret-wpscan-tok")

        cmd = mock_run.call_args.args[0]
        env = mock_run.call_args.kwargs["env"]
        self.assertEqual(cmd[0], "wpscan")
        self.assertNotIn("secret-wpscan-tok", " ".join(cmd))
        self.assertNotIn("--api-token", cmd)
        self.assertEqual(env.get("WPSCAN_API_TOKEN"), "secret-wpscan-tok")

    def test_empty_api_token_omits_env_override(self):
        nrs = self._import_server()
        fn = getattr(nrs.execute_wpscan, "fn", None) or getattr(nrs.execute_wpscan, "__wrapped__", None) or nrs.execute_wpscan
        with mock.patch("capture_routing.agent_capture_routing", return_value=(None, None)), \
             mock.patch.object(nrs.subprocess, "run", return_value=CompletedProcess(args=[], returncode=0, stdout="{}", stderr="")) as mock_run, \
             mock.patch.dict(os.environ, {}, clear=True):
            fn(args="--url https://wp.example", api_token="")

        env = mock_run.call_args.kwargs["env"]
        self.assertNotIn("WPSCAN_API_TOKEN", env)


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
