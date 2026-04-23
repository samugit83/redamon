"""
Tests for the XSS (Cross-Site Scripting) built-in attack skill — classification,
prompt wiring, settings defaults, state validation, and template formatting.

Run with: python -m pytest tests/test_xss_skill.py -v
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

# Add parent dir to path so we can import from agentic modules
_agentic_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _agentic_dir)

# Stub out heavy dependencies not available outside Docker
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

sys.modules['langchain_core.messages'].AIMessage = FakeAIMessage
sys.modules['langchain_core.messages'].HumanMessage = FakeHumanMessage
sys.modules['langgraph.graph.message'].add_messages = _fake_add_messages

# Now safe to import agentic modules
from state import KNOWN_ATTACK_PATHS, is_unclassified_path, AttackPathClassification
from project_settings import DEFAULT_AGENT_SETTINGS
from prompts.xss_prompts import XSS_TOOLS, XSS_BLIND_WORKFLOW, XSS_PAYLOAD_REFERENCE
from prompts.classification import (
    _XSS_SECTION, _BUILTIN_SKILL_MAP, _CLASSIFICATION_INSTRUCTIONS,
    build_classification_prompt,
)


# ===========================================================================
# 1. State — KNOWN_ATTACK_PATHS includes xss
# ===========================================================================

class TestStateRegistration(unittest.TestCase):
    """Verify xss is registered as a known attack path."""

    def test_xss_in_known_paths(self):
        self.assertIn("xss", KNOWN_ATTACK_PATHS)

    def test_xss_is_not_unclassified(self):
        self.assertFalse(is_unclassified_path("xss"))

    def test_xss_unclassified_still_valid(self):
        """The legacy unclassified path should still pass regex validation."""
        self.assertTrue(is_unclassified_path("xss-unclassified"))

    def test_attack_path_classification_accepts_xss(self):
        """Pydantic model should accept xss as valid type."""
        apc = AttackPathClassification(
            attack_path_type="xss",
            required_phase="exploitation",
            confidence=0.95,
            reasoning="XSS test",
        )
        self.assertEqual(apc.attack_path_type, "xss")

    def test_all_known_paths_present(self):
        """All built-in skills should be in KNOWN_ATTACK_PATHS (now 6 entries)."""
        expected = {
            "cve_exploit", "brute_force_credential_guess",
            "phishing_social_engineering", "denial_of_service",
            "sql_injection", "xss",
        }
        self.assertEqual(KNOWN_ATTACK_PATHS, expected)


# ===========================================================================
# 2. Classification — skill map and instructions
# ===========================================================================

class TestClassificationRegistration(unittest.TestCase):
    """Verify xss is wired into the classification system."""

    def test_xss_section_defined(self):
        self.assertIn("xss", _XSS_SECTION)
        self.assertIn("Cross-Site Scripting", _XSS_SECTION)
        self.assertIn("DOM", _XSS_SECTION)
        self.assertIn("dalfox", _XSS_SECTION)

    def test_xss_in_builtin_skill_map(self):
        self.assertIn("xss", _BUILTIN_SKILL_MAP)
        section, letter, skill_id = _BUILTIN_SKILL_MAP["xss"]
        self.assertEqual(skill_id, "xss")
        self.assertEqual(section, _XSS_SECTION)

    def test_xss_in_classification_instructions(self):
        self.assertIn("xss", _CLASSIFICATION_INSTRUCTIONS)
        instruction = _CLASSIFICATION_INSTRUCTIONS["xss"]
        self.assertIn("XSS", instruction)
        self.assertIn("cross-site scripting", instruction.lower())

    def test_build_classification_prompt_includes_xss_when_enabled(self):
        """When xss is enabled, the classification prompt should include it."""
        with patch('prompts.classification.get_enabled_builtin_skills',
                   return_value={'xss', 'cve_exploit'}), \
             patch('prompts.classification.get_enabled_user_skills', return_value=[]), \
             patch('prompts.classification.get_setting', return_value=False):
            prompt = build_classification_prompt("Test for XSS on the login form")
            self.assertIn("xss", prompt)
            self.assertIn("Cross-Site Scripting", prompt)

    def test_build_classification_prompt_excludes_xss_when_disabled(self):
        """When xss is not enabled, the prompt should not include its section."""
        with patch('prompts.classification.get_enabled_builtin_skills',
                   return_value={'cve_exploit'}), \
             patch('prompts.classification.get_enabled_user_skills', return_value=[]), \
             patch('prompts.classification.get_setting', return_value=False):
            prompt = build_classification_prompt("Test for XSS on the login form")
            # The XSS section header should not be included
            self.assertNotIn("### xss — Cross-Site Scripting", prompt)
            # But unclassified should still be available as fallback
            self.assertIn("unclassified", prompt)

    def test_unclassified_section_no_longer_lists_xss_example(self):
        """The unclassified section should not list xss-unclassified as an example."""
        with patch('prompts.classification.get_enabled_builtin_skills',
                   return_value={'xss', 'cve_exploit'}), \
             patch('prompts.classification.get_enabled_user_skills', return_value=[]), \
             patch('prompts.classification.get_setting', return_value=False):
            prompt = build_classification_prompt("test")
            # Should NOT have xss-unclassified as an example value
            self.assertNotIn('"xss-unclassified"', prompt)


# ===========================================================================
# 3. Project settings — defaults
# ===========================================================================

class TestProjectSettings(unittest.TestCase):
    """Verify XSS settings are correctly configured in defaults."""

    def test_xss_in_attack_skill_config(self):
        config = DEFAULT_AGENT_SETTINGS['ATTACK_SKILL_CONFIG']
        self.assertIn('xss', config['builtIn'])

    def test_xss_enabled_by_default(self):
        config = DEFAULT_AGENT_SETTINGS['ATTACK_SKILL_CONFIG']
        self.assertTrue(config['builtIn']['xss'])

    def test_xss_dalfox_enabled_default(self):
        self.assertTrue(DEFAULT_AGENT_SETTINGS['XSS_DALFOX_ENABLED'])

    def test_xss_blind_callback_disabled_by_default(self):
        """Blind callbacks send data OOB to oast.fun; should be opt-in."""
        self.assertFalse(DEFAULT_AGENT_SETTINGS['XSS_BLIND_CALLBACK_ENABLED'])

    def test_xss_csp_bypass_enabled_default(self):
        self.assertTrue(DEFAULT_AGENT_SETTINGS['XSS_CSP_BYPASS_ENABLED'])


# ===========================================================================
# 4. Prompt templates — formatting and content
# ===========================================================================

class TestPromptTemplates(unittest.TestCase):
    """Verify prompt constants format correctly and contain expected content."""

    def _format_xss_tools(self, **overrides):
        defaults = dict(
            xss_dalfox_enabled=True,
            xss_blind_callback_enabled=False,
            xss_csp_bypass_enabled=True,
        )
        defaults.update(overrides)
        return XSS_TOOLS.format(**defaults)

    def test_xss_tools_format_with_defaults(self):
        """XSS_TOOLS should format cleanly with default settings."""
        result = self._format_xss_tools()
        self.assertIn("CROSS-SITE SCRIPTING", result)
        self.assertIn("dalfox automated WAF evasion: True", result)
        self.assertIn("Blind XSS callbacks (interactsh): False", result)
        # No unformatted placeholders (look for any {xss_...} pattern)
        import re
        self.assertEqual(re.findall(r'\{xss_[a-z_]+\}', result), [])

    def test_xss_tools_format_with_blind_enabled(self):
        result = self._format_xss_tools(xss_blind_callback_enabled=True)
        self.assertIn("Blind XSS callbacks (interactsh): True", result)

    def test_xss_tools_contains_all_steps(self):
        """Verify all 8 steps are present."""
        result = self._format_xss_tools()
        self.assertIn("Step 1: Reuse recon", result)
        self.assertIn("Step 2: Surface input vectors", result)
        self.assertIn("Step 3: Canary reflection sweep", result)
        self.assertIn("Step 3b: Per-char filter probe", result)
        self.assertIn("Step 4: Context-aware payload selection", result)
        self.assertIn("Step 5: DOM XSS via Playwright", result)
        self.assertIn("Step 6: Verify execution", result)
        self.assertIn("Step 7: WAF / filter bypass", result)
        self.assertIn("Step 8: Prove impact", result)

    def test_xss_tools_references_correct_tools(self):
        """Prompt should reference the verified-available tools."""
        result = self._format_xss_tools()
        self.assertIn("query_graph", result)
        self.assertIn("execute_curl", result)
        self.assertIn("execute_playwright", result)
        self.assertIn("kali_shell", result)
        self.assertIn("dalfox", result)
        self.assertIn("kxss", result)

    def test_xss_tools_includes_canary(self):
        """The canary string should be the documented constant value."""
        result = self._format_xss_tools()
        self.assertIn("rEdAm0n1337XsS", result)

    def test_xss_tools_includes_transition_phase(self):
        """Step 1 must instruct the agent to transition to exploitation."""
        result = self._format_xss_tools()
        self.assertIn("transition_phase", result)

    def test_xss_tools_dialog_handler_documented(self):
        """Step 6 should document Playwright dialog handler as canonical proof."""
        result = self._format_xss_tools()
        self.assertIn('page.on("dialog"', result)

    def test_xss_tools_dalfox_background_pattern(self):
        """Step 7 should describe dalfox in background mode (long-running)."""
        result = self._format_xss_tools()
        self.assertIn("--silence", result)
        self.assertIn("--waf-evasion", result)
        self.assertIn("/tmp/dalfox", result)

    def test_blind_workflow_no_format_needed(self):
        """XSS_BLIND_WORKFLOW should have no template placeholders."""
        import re
        self.assertEqual(re.findall(r'\{xss_[a-z_]+\}', XSS_BLIND_WORKFLOW), [])

    def test_blind_workflow_interactsh_steps(self):
        """Blind workflow should describe the interactsh-client lifecycle."""
        self.assertIn("interactsh-client", XSS_BLIND_WORKFLOW)
        self.assertIn("/tmp/interactsh.log", XSS_BLIND_WORKFLOW)
        self.assertIn("oast.fun", XSS_BLIND_WORKFLOW)
        self.assertIn("kill SAVED_PID", XSS_BLIND_WORKFLOW)

    def test_blind_workflow_warns_about_random_strings(self):
        """Blind workflow should warn that random domains don't work."""
        self.assertIn("cryptographically registered", XSS_BLIND_WORKFLOW)
        self.assertIn("Random strings will NOT work", XSS_BLIND_WORKFLOW)

    def test_blind_workflow_payload_variants(self):
        """Should include payloads for HTML body, JS string, and SVG contexts."""
        self.assertIn("onerror", XSS_BLIND_WORKFLOW)
        self.assertIn("document.cookie", XSS_BLIND_WORKFLOW)
        self.assertIn("dalfox", XSS_BLIND_WORKFLOW)

    def test_payload_reference_no_format_needed(self):
        """XSS_PAYLOAD_REFERENCE should have no template placeholders."""
        import re
        self.assertEqual(re.findall(r'\{xss_[a-z_]+\}', XSS_PAYLOAD_REFERENCE), [])

    def test_payload_reference_html_body(self):
        self.assertIn("<script>alert(1)</script>", XSS_PAYLOAD_REFERENCE)
        self.assertIn("<svg onload=alert(1)>", XSS_PAYLOAD_REFERENCE)
        self.assertIn("<img src=x onerror=alert(1)>", XSS_PAYLOAD_REFERENCE)

    def test_payload_reference_attribute_breakout(self):
        self.assertIn("onfocus=alert(1)", XSS_PAYLOAD_REFERENCE)
        self.assertIn("autofocus", XSS_PAYLOAD_REFERENCE)

    def test_payload_reference_url_context(self):
        self.assertIn("javascript:alert(1)", XSS_PAYLOAD_REFERENCE)
        self.assertIn("data:text/html", XSS_PAYLOAD_REFERENCE)

    def test_payload_reference_polyglot(self):
        """Brute Logic polyglot fragment should be present."""
        self.assertIn("jaVasCript:", XSS_PAYLOAD_REFERENCE)
        self.assertIn("oNcliCk", XSS_PAYLOAD_REFERENCE)

    def test_payload_reference_waf_bypass_table(self):
        self.assertIn("URL-encode", XSS_PAYLOAD_REFERENCE)
        self.assertIn("Double URL-encode", XSS_PAYLOAD_REFERENCE)
        self.assertIn("HTML entity", XSS_PAYLOAD_REFERENCE)

    def test_payload_reference_csp_bypass(self):
        self.assertIn("Content-Security-Policy", XSS_PAYLOAD_REFERENCE)
        self.assertIn("unsafe-inline", XSS_PAYLOAD_REFERENCE)
        self.assertIn("nonce", XSS_PAYLOAD_REFERENCE)


# ===========================================================================
# 5. get_phase_tools — activation logic
# ===========================================================================

class TestGetPhaseToolsActivation(unittest.TestCase):
    """Verify xss skill is injected into the exploitation prompt."""

    def _get_phase_tools(self, attack_path_type, enabled_skills, phase="exploitation",
                          allowed_tools=None, blind_callback=False):
        """Call get_phase_tools with mocked settings."""
        if allowed_tools is None:
            allowed_tools = ['kali_shell', 'execute_curl', 'execute_code',
                             'execute_playwright', 'query_graph']

        with patch('prompts.get_setting') as mock_setting, \
             patch('prompts.get_allowed_tools_for_phase', return_value=allowed_tools), \
             patch('project_settings.get_enabled_builtin_skills', return_value=enabled_skills), \
             patch('prompts.build_kali_install_prompt', return_value=""), \
             patch('prompts.build_tool_availability_table', return_value="## Tools\n"), \
             patch('prompts.get_hydra_flags_from_settings', return_value="-t 16 -f"), \
             patch('prompts.get_dos_settings_dict', return_value={}), \
             patch('prompts.get_session_config_prompt', return_value=""), \
             patch('prompts.build_informational_tool_descriptions', return_value="info tools"):

            def setting_side_effect(key, default=None):
                settings = {
                    'STEALTH_MODE': False,
                    'INFORMATIONAL_SYSTEM_PROMPT': '',
                    'EXPL_SYSTEM_PROMPT': '',
                    'POST_EXPL_SYSTEM_PROMPT': '',
                    'XSS_DALFOX_ENABLED': True,
                    'XSS_BLIND_CALLBACK_ENABLED': blind_callback,
                    'XSS_CSP_BYPASS_ENABLED': True,
                    'ROE_ENABLED': False,
                    'HYDRA_MAX_WORDLIST_ATTEMPTS': 3,
                    'DOS_ASSESSMENT_ONLY': False,
                    'PHISHING_SMTP_CONFIG': '',
                    'ACTIVATE_POST_EXPL_PHASE': True,
                }
                return settings.get(key, default)

            mock_setting.side_effect = setting_side_effect

            from prompts import get_phase_tools
            return get_phase_tools(
                phase=phase,
                activate_post_expl=True,
                post_expl_type="stateless",
                attack_path_type=attack_path_type,
                execution_trace=[],
            )

    def test_xss_skill_injects_workflow(self):
        """When xss is enabled and classified, inject XSS_TOOLS."""
        result = self._get_phase_tools("xss", {"xss", "cve_exploit"})
        self.assertIn("ATTACK SKILL: CROSS-SITE SCRIPTING", result)
        self.assertIn("rEdAm0n1337XsS", result)
        self.assertIn("kxss", result)

    def test_xss_skill_injects_payload_reference(self):
        """Payload reference should always be included when xss is active."""
        result = self._get_phase_tools("xss", {"xss"})
        self.assertIn("XSS Payload Reference", result)
        self.assertIn("<svg onload=alert(1)>", result)

    def test_xss_blind_workflow_only_when_enabled(self):
        """XSS_BLIND_WORKFLOW (the section, not just a reference) should be injected only when enabled.

        Note: XSS_TOOLS Step 8 references the section name 'OOB / Blind XSS Workflow' as a pointer,
        so we look for the actual H2 marker '## OOB / Blind XSS Workflow' that only appears in the
        full XSS_BLIND_WORKFLOW constant.
        """
        result_off = self._get_phase_tools("xss", {"xss"}, blind_callback=False)
        self.assertNotIn("## OOB / Blind XSS Workflow", result_off)
        # interactsh-client is only documented in the blind workflow constant
        self.assertNotIn("Step 1: Start interactsh-client", result_off)

        result_on = self._get_phase_tools("xss", {"xss"}, blind_callback=True)
        self.assertIn("## OOB / Blind XSS Workflow", result_on)
        self.assertIn("Step 1: Start interactsh-client", result_on)

    def test_xss_blind_workflow_requires_kali_shell(self):
        """Even with blind enabled, no kali_shell -> no blind workflow injected."""
        result = self._get_phase_tools(
            "xss", {"xss"},
            blind_callback=True,
            allowed_tools=['execute_curl', 'execute_playwright'],  # no kali_shell
        )
        self.assertNotIn("## OOB / Blind XSS Workflow", result)
        self.assertNotIn("Step 1: Start interactsh-client", result)

    def test_xss_disabled_falls_to_unclassified(self):
        """When xss is not enabled, xss-unclassified should get generic guidance."""
        result = self._get_phase_tools("xss-unclassified", {"cve_exploit"})
        self.assertIn("Unclassified Attack Skill", result)
        self.assertNotIn("ATTACK SKILL: CROSS-SITE SCRIPTING", result)

    def test_xss_enabled_but_wrong_path_doesnt_inject(self):
        """xss prompts should only inject for xss attack path."""
        result = self._get_phase_tools("cve_exploit", {"xss", "cve_exploit"})
        self.assertNotIn("ATTACK SKILL: CROSS-SITE SCRIPTING", result)

    def test_xss_without_execute_curl_falls_through(self):
        """If execute_curl is not available, xss should not activate."""
        result = self._get_phase_tools(
            "xss", {"xss"},
            allowed_tools=['kali_shell', 'execute_code'],  # no execute_curl
        )
        self.assertNotIn("ATTACK SKILL: CROSS-SITE SCRIPTING", result)


# ===========================================================================
# 6. Tool registry — kxss + dalfox + interactsh + playwright present
# ===========================================================================

class TestToolRegistry(unittest.TestCase):
    """Verify the XSS tooling is documented in the kali_shell + execute_playwright entries."""

    def test_dalfox_in_kali_shell_description(self):
        from prompts.tool_registry import TOOL_REGISTRY
        kali_desc = TOOL_REGISTRY["kali_shell"]["description"]
        self.assertIn("dalfox", kali_desc)

    def test_kxss_in_kali_shell_description(self):
        from prompts.tool_registry import TOOL_REGISTRY
        kali_desc = TOOL_REGISTRY["kali_shell"]["description"]
        self.assertIn("kxss", kali_desc)

    def test_interactsh_in_kali_shell_description(self):
        from prompts.tool_registry import TOOL_REGISTRY
        kali_desc = TOOL_REGISTRY["kali_shell"]["description"]
        self.assertIn("interactsh-client", kali_desc)

    def test_playwright_documented(self):
        from prompts.tool_registry import TOOL_REGISTRY
        self.assertIn("execute_playwright", TOOL_REGISTRY)
        pw = TOOL_REGISTRY["execute_playwright"]
        self.assertIn("XSS", pw["when_to_use"])


if __name__ == "__main__":
    unittest.main()
