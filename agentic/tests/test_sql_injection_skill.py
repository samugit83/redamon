"""
Tests for SQL Injection built-in attack skill — classification, prompt wiring,
settings defaults, state validation, and template formatting.

Run with: python -m pytest tests/test_sql_injection_skill.py -v
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
from prompts.sql_injection_prompts import SQLI_TOOLS, SQLI_OOB_WORKFLOW, SQLI_PAYLOAD_REFERENCE
from prompts.classification import (
    _SQLI_SECTION, _BUILTIN_SKILL_MAP, _CLASSIFICATION_INSTRUCTIONS,
    build_classification_prompt,
)


# ===========================================================================
# 1. State — KNOWN_ATTACK_PATHS includes sql_injection
# ===========================================================================

class TestStateRegistration(unittest.TestCase):
    """Verify sql_injection is registered as a known attack path."""

    def test_sql_injection_in_known_paths(self):
        self.assertIn("sql_injection", KNOWN_ATTACK_PATHS)

    def test_sql_injection_is_not_unclassified(self):
        self.assertFalse(is_unclassified_path("sql_injection"))

    def test_sql_injection_unclassified_still_valid(self):
        """The old unclassified path should still pass regex validation."""
        self.assertTrue(is_unclassified_path("sql_injection-unclassified"))

    def test_attack_path_classification_accepts_sql_injection(self):
        """Pydantic model should accept sql_injection as valid type."""
        apc = AttackPathClassification(
            attack_path_type="sql_injection",
            required_phase="exploitation",
            confidence=0.95,
            reasoning="SQL injection test",
        )
        self.assertEqual(apc.attack_path_type, "sql_injection")

    def test_all_known_paths_present(self):
        """All built-in skills should be in KNOWN_ATTACK_PATHS."""
        expected = {
            "cve_exploit", "brute_force_credential_guess",
            "phishing_social_engineering", "denial_of_service",
            "sql_injection", "xss",
        }
        self.assertEqual(KNOWN_ATTACK_PATHS, expected)


# ===========================================================================
# 2. Classification — skill map and priority instructions
# ===========================================================================

class TestClassificationRegistration(unittest.TestCase):
    """Verify sql_injection is wired into the classification system."""

    def test_sqli_section_defined(self):
        self.assertIn("sql_injection", _SQLI_SECTION)
        self.assertIn("SQLMap", _SQLI_SECTION)
        self.assertIn("OOB", _SQLI_SECTION)

    def test_sqli_in_builtin_skill_map(self):
        self.assertIn("sql_injection", _BUILTIN_SKILL_MAP)
        section, letter, skill_id = _BUILTIN_SKILL_MAP["sql_injection"]
        self.assertEqual(skill_id, "sql_injection")
        self.assertEqual(section, _SQLI_SECTION)

    def test_sqli_in_classification_instructions(self):
        self.assertIn("sql_injection", _CLASSIFICATION_INSTRUCTIONS)
        instruction = _CLASSIFICATION_INSTRUCTIONS["sql_injection"]
        self.assertIn("SQL injection", instruction)

    def test_build_classification_prompt_includes_sqli_when_enabled(self):
        """When sql_injection is enabled, the classification prompt should include it."""
        with patch('prompts.classification.get_enabled_builtin_skills',
                   return_value={'sql_injection', 'cve_exploit'}), \
             patch('prompts.classification.get_enabled_user_skills', return_value=[]), \
             patch('prompts.classification.get_setting', return_value=False):
            prompt = build_classification_prompt("Try SQL injection on the web app")
            self.assertIn("sql_injection", prompt)
            self.assertIn("SQL Injection", prompt)

    def test_build_classification_prompt_excludes_sqli_when_disabled(self):
        """When sql_injection is not enabled, the prompt should not include its section."""
        with patch('prompts.classification.get_enabled_builtin_skills',
                   return_value={'cve_exploit'}), \
             patch('prompts.classification.get_enabled_user_skills', return_value=[]), \
             patch('prompts.classification.get_setting', return_value=False):
            prompt = build_classification_prompt("Try SQL injection on the web app")
            # The SQLI section should not be included
            self.assertNotIn("### sql_injection — SQL Injection", prompt)
            # But unclassified should still mention it can be used
            self.assertIn("unclassified", prompt)

    def test_unclassified_section_no_longer_references_sqli(self):
        """The unclassified section should not list SQL injection as an example."""
        with patch('prompts.classification.get_enabled_builtin_skills',
                   return_value={'sql_injection', 'cve_exploit'}), \
             patch('prompts.classification.get_enabled_user_skills', return_value=[]), \
             patch('prompts.classification.get_setting', return_value=False):
            prompt = build_classification_prompt("test")
            # Should NOT have sql_injection-unclassified as an example
            self.assertNotIn('"sql_injection-unclassified"', prompt)


# ===========================================================================
# 3. Project settings — defaults
# ===========================================================================

class TestProjectSettings(unittest.TestCase):
    """Verify SQLi settings are correctly configured in defaults."""

    def test_sqli_in_attack_skill_config(self):
        config = DEFAULT_AGENT_SETTINGS['ATTACK_SKILL_CONFIG']
        self.assertIn('sql_injection', config['builtIn'])

    def test_sqli_enabled_by_default(self):
        config = DEFAULT_AGENT_SETTINGS['ATTACK_SKILL_CONFIG']
        self.assertTrue(config['builtIn']['sql_injection'])

    def test_sqli_level_default(self):
        self.assertEqual(DEFAULT_AGENT_SETTINGS['SQLI_LEVEL'], 1)

    def test_sqli_risk_default(self):
        self.assertEqual(DEFAULT_AGENT_SETTINGS['SQLI_RISK'], 1)

    def test_sqli_tamper_scripts_default_empty(self):
        self.assertEqual(DEFAULT_AGENT_SETTINGS['SQLI_TAMPER_SCRIPTS'], '')

    def test_sqli_level_valid_range(self):
        """Level should be 1-5."""
        level = DEFAULT_AGENT_SETTINGS['SQLI_LEVEL']
        self.assertGreaterEqual(level, 1)
        self.assertLessEqual(level, 5)

    def test_sqli_risk_valid_range(self):
        """Risk should be 1-3."""
        risk = DEFAULT_AGENT_SETTINGS['SQLI_RISK']
        self.assertGreaterEqual(risk, 1)
        self.assertLessEqual(risk, 3)


# ===========================================================================
# 4. Prompt templates — formatting and content
# ===========================================================================

class TestPromptTemplates(unittest.TestCase):
    """Verify prompt constants format correctly and contain expected content."""

    def test_sqli_tools_format_with_defaults(self):
        """SQLI_TOOLS should format cleanly with default settings."""
        result = SQLI_TOOLS.format(
            sqli_level=1,
            sqli_risk=1,
            sqli_tamper_scripts="none configured",
        )
        self.assertIn("SQLMap level: 1", result)
        self.assertIn("SQLMap risk:  1", result)
        self.assertIn("Tamper scripts: none configured", result)
        self.assertNotIn("{sqli_", result)  # No unformatted placeholders

    def test_sqli_tools_format_with_custom_settings(self):
        """SQLI_TOOLS should format with custom settings."""
        result = SQLI_TOOLS.format(
            sqli_level=3,
            sqli_risk=2,
            sqli_tamper_scripts="space2comment,randomcase",
        )
        self.assertIn("SQLMap level: 3", result)
        self.assertIn("SQLMap risk:  2", result)
        self.assertIn("--tamper=space2comment,randomcase", result)

    def test_sqli_tools_contains_all_steps(self):
        """Verify all 7 steps are present."""
        result = SQLI_TOOLS.format(sqli_level=1, sqli_risk=1, sqli_tamper_scripts="")
        self.assertIn("Step 1: Target Analysis", result)
        self.assertIn("Step 2: Quick SQLMap Detection", result)
        self.assertIn("Step 3: WAF Detection & Bypass", result)
        self.assertIn("Step 4: Exploitation", result)
        self.assertIn("Step 5: Long Scan Mode", result)
        self.assertIn("Step 6: Data Extraction Priority", result)
        self.assertIn("Step 7: Post-SQLi Escalation", result)

    def test_sqli_tools_references_correct_tools(self):
        """Prompt should reference existing tools, not new MCP server tools."""
        result = SQLI_TOOLS.format(sqli_level=1, sqli_risk=1, sqli_tamper_scripts="")
        self.assertIn("kali_shell", result)
        self.assertIn("execute_curl", result)
        # Should NOT reference MCP server tools from the rejected PR
        self.assertNotIn("execute_sqli", result)
        self.assertNotIn("generate_encoded_payload", result)
        self.assertNotIn("generate_oob_payload", result)

    def test_sqli_tools_batch_flag(self):
        """All sqlmap commands should include --batch."""
        result = SQLI_TOOLS.format(sqli_level=1, sqli_risk=1, sqli_tamper_scripts="")
        self.assertIn("--batch", result)

    def test_sqli_tools_long_scan_mode(self):
        """Long scan mode should describe background process pattern."""
        result = SQLI_TOOLS.format(sqli_level=1, sqli_risk=1, sqli_tamper_scripts="")
        self.assertIn("/tmp/sqlmap_out.txt", result)
        self.assertIn("& echo $!", result)
        self.assertIn("tail -50", result)
        self.assertIn("grep 'sqlmap'", result)

    def test_oob_workflow_no_format_needed(self):
        """SQLI_OOB_WORKFLOW should not need .format() — no template vars."""
        # Should not raise KeyError
        self.assertNotIn("{sqli_", SQLI_OOB_WORKFLOW)

    def test_oob_workflow_interactsh_steps(self):
        """OOB workflow should describe the correct interactsh-client pattern."""
        self.assertIn("interactsh-client", SQLI_OOB_WORKFLOW)
        self.assertIn("/tmp/interactsh.log", SQLI_OOB_WORKFLOW)
        self.assertIn("& echo $!", SQLI_OOB_WORKFLOW)
        self.assertIn("sleep 5", SQLI_OOB_WORKFLOW)
        self.assertIn("oast.fun", SQLI_OOB_WORKFLOW)
        self.assertIn("kill SAVED_PID", SQLI_OOB_WORKFLOW)

    def test_oob_workflow_warns_about_random_strings(self):
        """OOB workflow should warn that random domains don't work."""
        self.assertIn("cryptographically registered", SQLI_OOB_WORKFLOW)
        self.assertIn("Random strings will NOT work", SQLI_OOB_WORKFLOW)

    def test_oob_workflow_dbms_payloads(self):
        """OOB workflow should have payloads for all 4 major DBMS."""
        self.assertIn("MySQL", SQLI_OOB_WORKFLOW)
        self.assertIn("MSSQL", SQLI_OOB_WORKFLOW)
        self.assertIn("Oracle", SQLI_OOB_WORKFLOW)
        self.assertIn("PostgreSQL", SQLI_OOB_WORKFLOW)

    def test_oob_workflow_sqlmap_dns_domain(self):
        """OOB should recommend --dns-domain as preferred option."""
        self.assertIn("--dns-domain=", SQLI_OOB_WORKFLOW)
        self.assertIn("PREFERRED", SQLI_OOB_WORKFLOW)

    def test_payload_reference_no_format_needed(self):
        """SQLI_PAYLOAD_REFERENCE should not need .format() — no template vars."""
        self.assertNotIn("{sqli_", SQLI_PAYLOAD_REFERENCE)

    def test_payload_reference_auth_bypass(self):
        self.assertIn("OR '1'='1", SQLI_PAYLOAD_REFERENCE)
        self.assertIn("admin'--", SQLI_PAYLOAD_REFERENCE)

    def test_payload_reference_waf_bypass(self):
        self.assertIn("space2comment", SQLI_PAYLOAD_REFERENCE)
        self.assertIn("randomcase", SQLI_PAYLOAD_REFERENCE)
        self.assertIn("charencode", SQLI_PAYLOAD_REFERENCE)

    def test_payload_reference_error_based(self):
        self.assertIn("EXTRACTVALUE", SQLI_PAYLOAD_REFERENCE)
        self.assertIn("CONVERT", SQLI_PAYLOAD_REFERENCE)

    def test_payload_reference_time_based(self):
        self.assertIn("SLEEP(5)", SQLI_PAYLOAD_REFERENCE)
        self.assertIn("WAITFOR DELAY", SQLI_PAYLOAD_REFERENCE)
        self.assertIn("pg_sleep", SQLI_PAYLOAD_REFERENCE)


# ===========================================================================
# 5. get_phase_tools — activation logic
# ===========================================================================

class TestGetPhaseToolsActivation(unittest.TestCase):
    """Verify sql_injection skill is injected into the exploitation prompt."""

    def _get_phase_tools(self, attack_path_type, enabled_skills, phase="exploitation"):
        """Call get_phase_tools with mocked settings."""
        with patch('prompts.get_setting') as mock_setting, \
             patch('prompts.get_allowed_tools_for_phase', return_value=[
                 'kali_shell', 'execute_curl', 'execute_code',
                 'metasploit_console', 'execute_hydra',
             ]), \
             patch('project_settings.get_enabled_builtin_skills', return_value=enabled_skills), \
             patch('prompts.build_kali_install_prompt', return_value=""), \
             patch('prompts.build_tool_availability_table', return_value="## Tools\n"), \
             patch('prompts.get_hydra_flags_from_settings', return_value="-t 16 -f"), \
             patch('prompts.get_dos_settings_dict', return_value={}), \
             patch('prompts.get_session_config_prompt', return_value=""):

            def setting_side_effect(key, default=None):
                settings = {
                    'STEALTH_MODE': False,
                    'INFORMATIONAL_SYSTEM_PROMPT': '',
                    'EXPL_SYSTEM_PROMPT': '',
                    'POST_EXPL_SYSTEM_PROMPT': '',
                    'SQLI_LEVEL': 2,
                    'SQLI_RISK': 1,
                    'SQLI_TAMPER_SCRIPTS': 'space2comment',
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

    def test_sqli_skill_injects_workflow(self):
        """When sql_injection is enabled and classified, inject SQLI_TOOLS."""
        result = self._get_phase_tools("sql_injection", {"sql_injection", "cve_exploit"})
        self.assertIn("ATTACK SKILL: SQL INJECTION", result)
        self.assertIn("Step 1: Target Analysis", result)
        self.assertIn("SQLMap level: 2", result)
        self.assertIn("--tamper=space2comment", result)

    def test_sqli_skill_injects_oob_workflow(self):
        """OOB workflow should be included."""
        result = self._get_phase_tools("sql_injection", {"sql_injection"})
        self.assertIn("OOB SQL Injection Workflow", result)
        self.assertIn("interactsh-client", result)

    def test_sqli_skill_injects_payload_reference(self):
        """Payload reference should be included."""
        result = self._get_phase_tools("sql_injection", {"sql_injection"})
        self.assertIn("SQLi Payload Reference", result)
        self.assertIn("Auth Bypass", result)

    def test_sqli_disabled_falls_to_unclassified(self):
        """When sql_injection is not enabled, sql_injection-unclassified should get generic guidance."""
        result = self._get_phase_tools("sql_injection-unclassified", {"cve_exploit"})
        self.assertIn("Unclassified Attack Skill", result)
        self.assertNotIn("ATTACK SKILL: SQL INJECTION", result)

    def test_sqli_enabled_but_wrong_path_doesnt_inject(self):
        """sql_injection prompts should only inject for sql_injection attack path."""
        result = self._get_phase_tools("cve_exploit", {"sql_injection", "cve_exploit"})
        self.assertNotIn("ATTACK SKILL: SQL INJECTION", result)

    def test_sqli_without_kali_shell_falls_through(self):
        """If kali_shell is not available, sql_injection should not activate."""
        with patch('prompts.get_setting') as mock_setting, \
             patch('prompts.get_allowed_tools_for_phase', return_value=[
                 'execute_curl', 'execute_code',  # NO kali_shell
             ]), \
             patch('project_settings.get_enabled_builtin_skills', return_value={'sql_injection'}), \
             patch('prompts.build_kali_install_prompt', return_value=""), \
             patch('prompts.build_tool_availability_table', return_value=""), \
             patch('prompts.get_session_config_prompt', return_value=""), \
             patch('prompts.build_informational_tool_descriptions', return_value="info tools"):

            mock_setting.side_effect = lambda k, d=None: {
                'STEALTH_MODE': False,
                'INFORMATIONAL_SYSTEM_PROMPT': '',
                'EXPL_SYSTEM_PROMPT': '',
                'ACTIVATE_POST_EXPL_PHASE': True,
            }.get(k, d)

            from prompts import get_phase_tools
            result = get_phase_tools(
                phase="exploitation",
                attack_path_type="sql_injection",
            )
            # Should NOT have SQLi workflow since kali_shell is not available
            self.assertNotIn("ATTACK SKILL: SQL INJECTION", result)


# ===========================================================================
# 6. Tool registry — interactsh-client listed
# ===========================================================================

class TestToolRegistry(unittest.TestCase):
    """Verify interactsh-client is listed in kali_shell tool description."""

    def test_interactsh_in_kali_shell_description(self):
        from prompts.tool_registry import TOOL_REGISTRY
        kali_desc = TOOL_REGISTRY["kali_shell"]["description"]
        self.assertIn("interactsh-client", kali_desc)

    def test_sqlmap_still_listed(self):
        from prompts.tool_registry import TOOL_REGISTRY
        kali_desc = TOOL_REGISTRY["kali_shell"]["description"]
        self.assertIn("sqlmap", kali_desc)


if __name__ == "__main__":
    unittest.main()
