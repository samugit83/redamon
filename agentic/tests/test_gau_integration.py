"""
Tests for execute_gau integration -- tool registry, phase map, dangerous tools,
stealth rules, and API key injection.

Run with: python -m pytest tests/test_gau_integration.py -v
"""

import os
import sys
import unittest
from unittest.mock import MagicMock, AsyncMock, patch

# Add parent dir to path so we can import from agentic modules
_agentic_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _agentic_dir)

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

# Stub httpx (used by tools.py, not available outside Docker)
if 'httpx' not in sys.modules:
    _stubs['httpx'] = MagicMock()
    sys.modules['httpx'] = _stubs['httpx']


class FakeAIMessage:
    def __init__(self, content="", **kwargs):
        self.content = content
        self.type = "ai"


class FakeHumanMessage:
    def __init__(self, content="", **kwargs):
        self.content = content
        self.type = "human"


sys.modules['langchain_core.messages'].AIMessage = FakeAIMessage
sys.modules['langchain_core.messages'].HumanMessage = FakeHumanMessage

def _fake_add_messages(left, right):
    if left is None:
        left = []
    return left + right

sys.modules['langgraph.graph.message'].add_messages = _fake_add_messages

from project_settings import DANGEROUS_TOOLS, DEFAULT_AGENT_SETTINGS
from prompts.tool_registry import TOOL_REGISTRY
from prompts.stealth_rules import STEALTH_MODE_RULES


# ===========================================================================
# 1. Tool Registry
# ===========================================================================

class TestGauToolRegistry(unittest.TestCase):
    """Verify execute_gau is registered in the tool registry."""

    def test_execute_gau_in_registry(self):
        self.assertIn('execute_gau', TOOL_REGISTRY)

    def test_registry_entry_has_required_fields(self):
        entry = TOOL_REGISTRY['execute_gau']
        for field in ('purpose', 'when_to_use', 'args_format', 'description'):
            self.assertIn(field, entry, f"Missing field: {field}")

    def test_registry_purpose_mentions_passive(self):
        entry = TOOL_REGISTRY['execute_gau']
        self.assertIn('Passive', entry['purpose'])

    def test_registry_description_mentions_archives(self):
        entry = TOOL_REGISTRY['execute_gau']
        desc = entry['description']
        self.assertIn('Wayback Machine', desc)
        self.assertIn('Common Crawl', desc)
        self.assertIn('AlienVault OTX', desc)

    def test_registry_args_format(self):
        entry = TOOL_REGISTRY['execute_gau']
        self.assertIn('"args"', entry['args_format'])
        self.assertIn('gau', entry['args_format'])

    def test_kali_shell_excludes_gau(self):
        """kali_shell description should tell agent not to use it for gau."""
        kali_desc = TOOL_REGISTRY['kali_shell']['description']
        self.assertIn('gau', kali_desc)


# ===========================================================================
# 2. Dangerous Tools
# ===========================================================================

class TestGauDangerousTools(unittest.TestCase):
    """Verify execute_gau is classified as dangerous."""

    def test_execute_gau_is_dangerous(self):
        self.assertIn('execute_gau', DANGEROUS_TOOLS)

    def test_dangerous_tools_is_frozenset(self):
        self.assertIsInstance(DANGEROUS_TOOLS, frozenset)


# ===========================================================================
# 3. Phase Map
# ===========================================================================

class TestGauPhaseMap(unittest.TestCase):
    """Verify execute_gau phase restrictions."""

    def test_execute_gau_in_phase_map(self):
        phase_map = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']
        self.assertIn('execute_gau', phase_map)

    def test_execute_gau_phases_correct(self):
        phases = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']['execute_gau']
        self.assertEqual(sorted(phases), ['exploitation', 'informational'])

    def test_execute_gau_not_in_post_exploitation(self):
        phases = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']['execute_gau']
        self.assertNotIn('post_exploitation', phases)


# ===========================================================================
# 4. Stealth Rules
# ===========================================================================

class TestGauStealthRules(unittest.TestCase):
    """Verify execute_gau has correct stealth constraints."""

    def test_stealth_rules_mention_execute_gau(self):
        self.assertIn('execute_gau', STEALTH_MODE_RULES)

    def test_stealth_rules_no_restrictions(self):
        self.assertIn('NO RESTRICTIONS', STEALTH_MODE_RULES)
        # Find the gau section and verify it's NO RESTRICTIONS
        lines = STEALTH_MODE_RULES.split('\n')
        gau_section_found = False
        for line in lines:
            if 'execute_gau' in line and 'NO RESTRICTIONS' in line:
                gau_section_found = True
                break
        self.assertTrue(gau_section_found,
                        "execute_gau should have NO RESTRICTIONS stealth level")

    def test_stealth_rules_mention_passive(self):
        # The gau section should mention it's passive
        idx = STEALTH_MODE_RULES.find('execute_gau')
        section = STEALTH_MODE_RULES[idx:idx + 300]
        self.assertIn('passive', section.lower())


# ===========================================================================
# 5. API Key Injection (PhaseAwareToolExecutor)
# ===========================================================================

class TestGauApiKeyInjection(unittest.TestCase):
    """Verify URLScan API key injection into execute_gau."""

    def _make_executor(self):
        from tools import PhaseAwareToolExecutor
        mock_mcp = MagicMock()
        executor = PhaseAwareToolExecutor(
            mcp_manager=mock_mcp,
            graph_tool=None,
        )
        # Register a mock execute_gau tool
        mock_gau_tool = AsyncMock()
        mock_gau_tool.name = 'execute_gau'
        executor._all_tools['execute_gau'] = mock_gau_tool
        # Set phase map so tool is allowed
        executor._phase_map = {'execute_gau': ['informational', 'exploitation']}
        executor._current_phase = 'informational'
        return executor, mock_gau_tool

    def test_set_gau_urlscan_api_key_method_exists(self):
        executor, _ = self._make_executor()
        self.assertTrue(hasattr(executor, 'set_gau_urlscan_api_key'))
        self.assertTrue(callable(executor.set_gau_urlscan_api_key))

    def test_set_gau_urlscan_api_key_stores_key(self):
        executor, _ = self._make_executor()
        executor.set_gau_urlscan_api_key('test-key-123')
        self.assertEqual(executor._gau_urlscan_api_key, 'test-key-123')

    def test_execute_gau_injects_api_key(self):
        """When API key is set, it should be injected into tool_args."""
        import asyncio
        executor, mock_tool = self._make_executor()
        executor.set_gau_urlscan_api_key('my-urlscan-key')

        mock_tool.ainvoke.return_value = "http://example.com/page1\nhttp://example.com/page2"

        result = asyncio.new_event_loop().run_until_complete(
            executor.execute('execute_gau', {'args': '--subs example.com'}, phase='informational')
        )

        # Verify ainvoke was called with the API key injected
        call_args = mock_tool.ainvoke.call_args[0][0]
        self.assertEqual(call_args['urlscan_api_key'], 'my-urlscan-key')
        self.assertEqual(call_args['args'], '--subs example.com')

    def test_execute_gau_no_key_no_injection(self):
        """When no API key is set, tool_args should not contain urlscan_api_key."""
        import asyncio
        executor, mock_tool = self._make_executor()

        mock_tool.ainvoke.return_value = "http://example.com/page1"

        result = asyncio.new_event_loop().run_until_complete(
            executor.execute('execute_gau', {'args': 'example.com'}, phase='informational')
        )

        call_args = mock_tool.ainvoke.call_args[0][0]
        self.assertNotIn('urlscan_api_key', call_args)

    def test_execute_gau_does_not_mutate_original_args(self):
        """API key injection should create a new dict, not mutate the original."""
        import asyncio
        executor, mock_tool = self._make_executor()
        executor.set_gau_urlscan_api_key('my-key')

        mock_tool.ainvoke.return_value = "http://example.com/page1"

        original_args = {'args': 'example.com'}
        result = asyncio.new_event_loop().run_until_complete(
            executor.execute('execute_gau', original_args, phase='informational')
        )

        # Original dict should NOT have urlscan_api_key
        self.assertNotIn('urlscan_api_key', original_args)


# ===========================================================================
# 6. Cross-Consistency
# ===========================================================================

class TestGauCrossConsistency(unittest.TestCase):
    """Verify execute_gau is consistent across all layers."""

    def test_registry_and_phase_map_in_sync(self):
        """Every tool in TOOL_PHASE_MAP should be in TOOL_REGISTRY or be a known exception."""
        known_non_registry = {'msf_restart'}  # msf_restart is in phase map but handled specially
        phase_map = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']
        for tool in phase_map:
            if tool not in known_non_registry:
                self.assertIn(tool, TOOL_REGISTRY,
                              f"{tool} is in TOOL_PHASE_MAP but not in TOOL_REGISTRY")

    def test_dangerous_tools_subset_of_phase_map(self):
        """Every dangerous tool should be in the phase map."""
        phase_map = DEFAULT_AGENT_SETTINGS['TOOL_PHASE_MAP']
        for tool in DANGEROUS_TOOLS:
            self.assertIn(tool, phase_map,
                          f"{tool} is DANGEROUS but not in TOOL_PHASE_MAP")


if __name__ == '__main__':
    unittest.main()
