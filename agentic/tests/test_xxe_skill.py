"""
Tests for the XXE (XML External Entity injection) built-in attack skill.

Covers the full wiring of the new `xxe` class:
  - state schema / validator acceptance (KNOWN_ATTACK_PATHS, SkillSwitchDecision),
  - classification wiring (_BUILTIN_SKILL_MAP, _CLASSIFICATION_INSTRUCTIONS,
    build_skill_menu, build_classification_prompt render + valid_types, and the
    removal of the old `xxe-unclassified` advertisement),
  - phase injection (build_builtin_skill_workflow gate on execute_curl),
  - project-settings default,
  - the per-skill behavior blurb (build_attack_path_behavior),
  - technique coverage of XXE_TOOLS,
  - fairness + house style (no em dash, no format braces, no benchmark leak).

Run with: python -m pytest tests/test_xxe_skill.py -v
"""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

_agentic_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _agentic_dir)


# --- Stub heavy LangChain/LangGraph deps so `state` imports outside Docker too
#     (mirrors test_switch_skill.py / test_xss_skill.py). Harmless in-container.
class FakeAIMessage:
    def __init__(self, content="", **kwargs):
        self.content = content
        self.type = "ai"


class FakeHumanMessage:
    def __init__(self, content="", **kwargs):
        self.content = content
        self.type = "human"


def _fake_add_messages(left, right):
    return (left or []) + right


_stub_modules = [
    'langchain_core', 'langchain_core.tools', 'langchain_core.messages',
    'langchain_core.language_models', 'langchain_core.runnables',
    'langchain_mcp_adapters', 'langchain_mcp_adapters.client', 'langchain_neo4j',
    'langgraph', 'langgraph.graph', 'langgraph.graph.message',
    'langgraph.graph.state', 'langgraph.checkpoint', 'langgraph.checkpoint.memory',
    'langchain_openai', 'langchain_openai.chat_models',
    'langchain_openai.chat_models.azure', 'langchain_openai.chat_models.base',
    'langchain_anthropic', 'langchain_core.language_models.chat_models',
    'langchain_core.callbacks', 'langchain_core.outputs',
]
for _mod in _stub_modules:
    if _mod not in sys.modules:
        sys.modules[_mod] = MagicMock()
sys.modules['langchain_core.messages'].AIMessage = FakeAIMessage
sys.modules['langchain_core.messages'].HumanMessage = FakeHumanMessage
sys.modules['langgraph.graph.message'].add_messages = _fake_add_messages

import project_settings as ps  # noqa: E402
from prompts import build_builtin_skill_workflow, XXE_TOOLS  # noqa: E402
from prompts.base import build_attack_path_behavior  # noqa: E402
from prompts.classification import (  # noqa: E402
    build_skill_menu, build_classification_prompt,
    _BUILTIN_SKILL_MAP, _CLASSIFICATION_INSTRUCTIONS,
)
from state import KNOWN_ATTACK_PATHS, is_valid_attack_path_value, SkillSwitchDecision  # noqa: E402

CLS = "xxe"

# The benchmark that motivated the skill; the module must NOT leak its solution.
_XBEN032_LEAKS = (
    "soap_service", "flag.txt", "/app/flag", "account_id", "getaccountinfo",
    "getaccountholder", "password123", "john", "lxml", "resolve_entit",
    "xmlparser", "197ab91b", "nice soap", "myservice", "xben",
)


class TestXxeStateSchema(unittest.TestCase):
    def test_in_known_attack_paths(self):
        self.assertIn(CLS, KNOWN_ATTACK_PATHS)

    def test_is_valid_attack_path_value(self):
        self.assertTrue(is_valid_attack_path_value(CLS))

    def test_skill_switch_decision_accepts_xxe(self):
        self.assertEqual(SkillSwitchDecision(to_skill=CLS).to_skill, CLS)

    def test_xxe_unclassified_still_a_valid_fallback_format(self):
        # First-class xxe does not remove the generic -unclassified escape hatch.
        self.assertTrue(is_valid_attack_path_value("xxe-unclassified"))


class TestXxeClassificationWiring(unittest.TestCase):
    def test_in_builtin_skill_map(self):
        self.assertIn(CLS, _BUILTIN_SKILL_MAP)
        section, letter, sid = _BUILTIN_SKILL_MAP[CLS]
        self.assertEqual(sid, CLS)
        self.assertTrue(section.strip())

    def test_classification_instructions_present(self):
        self.assertIn(CLS, _CLASSIFICATION_INSTRUCTIONS)
        crit = _CLASSIFICATION_INSTRUCTIONS[CLS]
        for token in ("XXE", "DOCTYPE", "ENTITY", "DTD"):
            self.assertIn(token, crit, token)

    def test_skill_menu_lists_xxe(self):
        menu = build_skill_menu({CLS}, [])
        self.assertIn("### xxe", menu)
        self.assertIn("- **xxe**", menu)

    def test_menu_boundary_distinguishes_neighbors(self):
        section, _, _ = _BUILTIN_SKILL_MAP[CLS]
        # must disambiguate from the file-read / URL-fetch neighbors
        for token in ("ssrf", "path_traversal"):
            self.assertIn(token, section, token)

    def test_full_classification_prompt_renders_xxe(self):
        enabled = {"cve_exploit", "sql_injection", "xss", "ssrf", "rce",
                   "path_traversal", "access_control", "xxe"}
        with patch("prompts.classification.get_enabled_builtin_skills", return_value=set(enabled)), \
             patch("prompts.classification.get_enabled_user_skills", return_value=[]), \
             patch("prompts.classification.get_setting", return_value=False):
            prompt = build_classification_prompt("Test the XML endpoint")
        self.assertIn("### xxe", prompt)          # section rendered
        self.assertIn("- **xxe**", prompt)        # criteria rendered
        self.assertIn('"xxe"', prompt)            # in the valid_types JSON schema

    def test_unclassified_no_longer_advertises_xxe(self):
        # XXE is first-class now: the unclassified section must not route it away.
        enabled = {"xxe", "ssrf", "path_traversal"}
        with patch("prompts.classification.get_enabled_builtin_skills", return_value=set(enabled)), \
             patch("prompts.classification.get_enabled_user_skills", return_value=[]), \
             patch("prompts.classification.get_setting", return_value=False):
            prompt = build_classification_prompt("hack it")
        self.assertNotIn("xxe-unclassified", prompt)


class TestXxeInjection(unittest.TestCase):
    def test_workflow_builds_when_execute_curl_allowed(self):
        wf = build_builtin_skill_workflow(CLS, {"execute_curl", "kali_shell", "execute_code"})
        self.assertTrue(wf)
        self.assertIn(XXE_TOOLS, wf)

    def test_workflow_gated_on_execute_curl(self):
        # No execute_curl -> not injected (the agent could not send the payloads).
        self.assertEqual(build_builtin_skill_workflow(CLS, {"kali_shell"}), [])

    def test_workflow_empty_when_skill_disabled(self):
        # _build_builtin_skill_workflow reads enablement via a local
        # `from project_settings import get_enabled_builtin_skills`.
        with patch("project_settings.get_enabled_builtin_skills", return_value={"xss"}):
            self.assertEqual(
                build_builtin_skill_workflow(CLS, {"execute_curl"}), [])


class TestXxeProjectSettings(unittest.TestCase):
    def test_enabled_by_default(self):
        self.assertIs(
            ps.DEFAULT_AGENT_SETTINGS["ATTACK_SKILL_CONFIG"]["builtIn"][CLS], True)


class TestXxeBehaviorBlurb(unittest.TestCase):
    def test_behavior_blurb_present_and_specific(self):
        blurb = build_attack_path_behavior(CLS)
        self.assertTrue(blurb.strip())
        low = blurb.lower()
        for token in ("xml", "entity", "in-band"):
            self.assertIn(token, low, token)


class TestXxeContentCoverage(unittest.TestCase):
    """XXE_TOOLS must teach the full technique spectrum, generically."""

    def test_core_technique_tokens(self):
        for token in ("DOCTYPE", "ENTITY", "SYSTEM", "file://", "parameter entit",
                      "external DTD", "out-of-band", "XInclude", "php://filter"):
            self.assertIn(token, XXE_TOOLS, token)

    def test_delivery_and_upload_vectors(self):
        for token in ("SVG", "DOCX", "Content-Type", "SOAP", "CDATA"):
            self.assertIn(token, XXE_TOOLS, token)

    def test_has_structure_gate_and_reporting(self):
        for token in ("STOP checks", "Abandonment gate", "Reporting", "phase"):
            self.assertIn(token, XXE_TOOLS, token)

    def test_measurement_first_control_probe(self):
        # A control entity probe must precede escalation (measurement-first).
        self.assertIn("CONTROL", XXE_TOOLS)
        self.assertIn("&probe;", XXE_TOOLS)


class TestXxeFairnessAndStyle(unittest.TestCase):
    def test_no_em_dash(self):
        self.assertNotIn("—", XXE_TOOLS)
        self.assertNotIn("—", _BUILTIN_SKILL_MAP[CLS][0])
        self.assertNotIn("—", build_attack_path_behavior(CLS))

    def test_no_format_braces(self):
        # XXE_TOOLS is injected verbatim (no .format); stray braces would be a bug.
        self.assertEqual(XXE_TOOLS.count("{"), 0)
        self.assertEqual(XXE_TOOLS.count("}"), 0)

    def test_generic_example_files_not_target_file(self):
        # Uses universal proof files, never the motivating benchmark's flag path.
        self.assertIn("/etc/passwd", XXE_TOOLS)
        self.assertNotIn("/app/flag", XXE_TOOLS)

    def test_no_benchmark_leak(self):
        blob = (XXE_TOOLS + _BUILTIN_SKILL_MAP[CLS][0]
                + _CLASSIFICATION_INSTRUCTIONS[CLS]
                + build_attack_path_behavior(CLS)).lower()
        for leak in _XBEN032_LEAKS:
            self.assertNotIn(leak, blob, f"benchmark-specific leak: {leak}")


class TestXxeToolRegistryAlignment(unittest.TestCase):
    """Every tool the skill names must be a REAL registry tool, and the skill
    must actually steer to the useful ones (recon, discovery, OOB hosting)."""

    import re as _re

    def _referenced_tools(self):
        return set(self._re.findall(
            r"\b(query_graph|kali_shell|metasploit_console|execute_[a-z_]+|"
            r"proxy_[a-z_]+|fs_[a-z_]+|job_[a-z_]+)\b", XXE_TOOLS))

    def test_all_referenced_tools_are_real_registry_keys(self):
        from prompts.tool_registry import TOOL_REGISTRY
        bad = sorted(t for t in self._referenced_tools() if t not in TOOL_REGISTRY)
        self.assertEqual(bad, [], f"skill references non-registry tools: {bad}")

    def test_steers_to_key_tools(self):
        for tool in ("query_graph", "execute_curl", "execute_code", "kali_shell",
                     "execute_ffuf", "execute_httpx", "fs_write",
                     "redamon.", "execute_nuclei"):
            self.assertIn(tool, XXE_TOOLS, f"skill should reference {tool}")

    def test_oob_uses_house_oast_convention(self):
        # OOB listener via kali_shell + interactsh (matches ssrf/path_traversal)
        self.assertIn("interactsh", XXE_TOOLS)
        self.assertIn("kali_shell", XXE_TOOLS)


class TestXxeSystemPromptSmoke(unittest.TestCase):
    """End-to-end smoke: the real system-prompt assembler (get_phase_tools) must
    inject the XXE workflow when the class is xxe, and only then."""

    def test_exploitation_xxe_injects_workflow(self):
        from prompts import get_phase_tools
        sysprompt = get_phase_tools(phase="exploitation", attack_path_type="xxe")
        for marker in ("XML External Entity (XXE) Injection Workflow",
                       "STOP checks", "Abandonment gate", "external DTD"):
            self.assertIn(marker, sysprompt, marker)

    def test_other_class_does_not_inject_xxe(self):
        from prompts import get_phase_tools
        sysprompt = get_phase_tools(phase="exploitation", attack_path_type="xss")
        self.assertNotIn("XML External Entity (XXE) Injection Workflow", sysprompt)


class TestXxeFrontendArtifacts(unittest.TestCase):
    """Smoke checks against the webapp source (layers 6-9): the wiring that
    does not crash the agent but breaks the UI badge / toggle / tooltip /
    suggestions. Requires the repo checkout (webapp/ sibling of agentic/)."""

    REPO_ROOT = os.path.dirname(_agentic_dir)

    def _read(self, rel):
        with open(os.path.join(self.REPO_ROOT, rel), encoding="utf-8") as f:
            return f.read()

    def test_prisma_default_includes_xxe(self):
        body = self._read("webapp/prisma/schema.prisma")
        self.assertIn('\\"xxe\\":true', body)

    def test_attack_skills_section_lists_xxe(self):
        body = self._read(
            "webapp/src/components/projects/ProjectForm/sections/AttackSkillsSection.tsx")
        self.assertIn("id: 'xxe'", body)
        self.assertIn("xxe: true", body)  # DEFAULT_CONFIG default

    def test_drawer_tooltip_api_lists_xxe(self):
        body = self._read(
            "webapp/src/app/api/users/[id]/attack-skills/available/route.ts")
        self.assertIn("id: 'xxe'", body)

    def test_phase_config_has_badge(self):
        body = self._read(
            "webapp/src/app/graph/components/AIAssistantDrawer/phaseConfig.ts")
        self.assertIn("xxe: {", body)
        self.assertIn("'XXE'", body)

    def test_suggestion_data_has_block(self):
        body = self._read(
            "webapp/src/app/graph/components/AIAssistantDrawer/suggestionData.ts")
        self.assertIn("id: 'xxe'", body)
        self.assertIn("XML External Entity", body)


if __name__ == "__main__":
    unittest.main(verbosity=2)
