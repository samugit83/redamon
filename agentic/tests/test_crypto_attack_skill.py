"""
Tests for the Cryptographic Attacks built-in attack skill (`crypto_attack`).

Covers the full wiring of the new class:
  - state schema / validator acceptance (KNOWN_ATTACK_PATHS, SkillSwitchDecision),
  - classification wiring (_BUILTIN_SKILL_MAP, _CLASSIFICATION_INSTRUCTIONS,
    build_skill_menu, build_classification_prompt render + valid_types),
  - phase injection (build_builtin_skill_workflow gate on execute_code),
  - project-settings default,
  - the per-skill behavior blurb (build_attack_path_behavior),
  - technique coverage of CRYPTO_ATTACK_TOOLS,
  - disjointness from access_control (the JWT-crypto boundary),
  - fairness + house style (no em dash, no format braces, no benchmark leak),
  - tool-registry alignment (every named tool is real),
  - system-prompt smoke (get_phase_tools) and webapp artifacts (layers 6-9).

Includes NAMED regression tests for two wiring bugs found in review:
  - test_regression_skill_menu_includes_crypto_attack (build_skill_menu.order
    omitted crypto_attack -> the per-turn switch menu never showed it),
  - test_regression_behavior_blurb_is_specific_not_fallback
    (build_attack_path_behavior fell through to the generic fallback).

Run with: python -m pytest tests/test_crypto_attack_skill.py -v
"""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

_agentic_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _agentic_dir)


# --- Stub heavy LangChain/LangGraph deps so `state` imports outside Docker too
#     (mirrors test_xxe_skill.py / test_xss_skill.py). Harmless in-container.
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
from prompts import build_builtin_skill_workflow, CRYPTO_ATTACK_TOOLS  # noqa: E402
from prompts.base import build_attack_path_behavior  # noqa: E402
from prompts.classification import (  # noqa: E402
    build_skill_menu, build_classification_prompt,
    _BUILTIN_SKILL_MAP, _CLASSIFICATION_INSTRUCTIONS, _ACCESS_CONTROL_SECTION,
)
from state import KNOWN_ATTACK_PATHS, is_valid_attack_path_value, SkillSwitchDecision  # noqa: E402

CLS = "crypto_attack"

# The benchmark that motivated the skill (a crypto captcha). The skill must NOT
# leak ANY of its solution specifics. NOTE: the bare word "captcha" is a generic
# web concept and is deliberately NOT in this list; the library name, the key,
# the exact error strings, and the flag ARE.
_XBEN101_LEAKS = (
    "imagecaptcha", "captcha_text_redacted", "generate_captcha", "encrypt_captcha",
    "decrypt_captcha", "invalid captcha", "invalid padding bytes", "@flag@",
    "6473c2599d", "aes_key", "cccccccccccccccc", "36164c39", "newuserform",
    "lab-69ce4549", "xben", "redacted by design", "first 8", "[:8]",
    # solution-suggestive decoy terms this benchmark's trick turns on: the skill
    # must steer to crypto generically and NEVER name the wrong turn to avoid.
    "ocr", "rendered output", "transcrib", "captcha", "lossy", "read the image",
)


class TestCryptoAttackStateSchema(unittest.TestCase):
    def test_in_known_attack_paths(self):
        self.assertIn(CLS, KNOWN_ATTACK_PATHS)

    def test_is_valid_attack_path_value(self):
        self.assertTrue(is_valid_attack_path_value(CLS))

    def test_skill_switch_decision_accepts_crypto_attack(self):
        self.assertEqual(SkillSwitchDecision(to_skill=CLS).to_skill, CLS)

    def test_unclassified_still_a_valid_fallback_format(self):
        # First-class crypto_attack does not remove the -unclassified escape hatch.
        self.assertTrue(is_valid_attack_path_value("crypto-unclassified"))


class TestCryptoAttackClassificationWiring(unittest.TestCase):
    def test_in_builtin_skill_map(self):
        self.assertIn(CLS, _BUILTIN_SKILL_MAP)
        section, letter, sid = _BUILTIN_SKILL_MAP[CLS]
        self.assertEqual(sid, CLS)
        self.assertTrue(section.strip())

    def test_classification_instructions_present(self):
        self.assertIn(CLS, _CLASSIFICATION_INSTRUCTIONS)
        crit = _CLASSIFICATION_INSTRUCTIONS[CLS]
        for token in ("padding", "oracle", "JWT", "RSA"):
            self.assertIn(token, crit, token)

    def test_skill_menu_lists_crypto_attack(self):
        menu = build_skill_menu({CLS}, [])
        self.assertIn("### crypto_attack", menu)
        self.assertIn("- **crypto_attack**", menu)

    def test_regression_skill_menu_includes_crypto_attack(self):
        # REGRESSION: build_skill_menu had its own `order` list that omitted
        # crypto_attack, so the per-turn switch menu never showed its section or
        # criteria even though classification accepted it. Menu MUST render both
        # the section header and the selection criteria when enabled.
        menu = build_skill_menu({CLS, "xss", "ssrf"}, [])
        self.assertIn("### crypto_attack - Cryptographic Attacks", menu)
        self.assertIn("- **crypto_attack**", menu)
        # and it must NOT render when the skill is not in the enabled set
        menu_off = build_skill_menu({"xss"}, [])
        self.assertNotIn("### crypto_attack", menu_off)

    def test_menu_boundary_distinguishes_neighbors(self):
        section, _, _ = _BUILTIN_SKILL_MAP[CLS]
        # must disambiguate from access_control (claim/authz) and rce (code exec)
        for token in ("access_control", "rce", "brute_force_credential_guess"):
            self.assertIn(token, section, token)

    def test_full_classification_prompt_renders_crypto_attack(self):
        enabled = {"cve_exploit", "sql_injection", "xss", "ssrf", "rce",
                   "path_traversal", "access_control", "xxe", "crypto_attack"}
        with patch("prompts.classification.get_enabled_builtin_skills", return_value=set(enabled)), \
             patch("prompts.classification.get_enabled_user_skills", return_value=[]), \
             patch("prompts.classification.get_setting", return_value=False):
            prompt = build_classification_prompt("Break the encrypted session cookie")
        self.assertIn("### crypto_attack", prompt)          # section rendered
        self.assertIn("- **crypto_attack**", prompt)        # criteria rendered
        self.assertIn('"crypto_attack"', prompt)            # in the valid_types JSON schema

    def test_decisive_switch_trigger_is_generic(self):
        # The section must carry a POSITIVE, generic commitment trigger (recognise
        # a crypto surface -> switch + exploit) so the agent stops lingering in
        # recon. It must do so WITHOUT naming any target-specific decoy.
        section, _, _ = _BUILTIN_SKILL_MAP[CLS]
        low = section.lower()
        self.assertIn("decisive trigger", low)
        self.assertIn("switch_skill", section)
        self.assertIn("exploitation", low)
        for decoy in ("ocr", "captcha", "rendered output", "image", "lossy"):
            self.assertNotIn(decoy, low, f"section leaks solution-decoy term: {decoy}")

    def test_disabled_skill_not_rendered_in_classification(self):
        enabled = {"xss", "ssrf"}   # crypto_attack OFF
        with patch("prompts.classification.get_enabled_builtin_skills", return_value=set(enabled)), \
             patch("prompts.classification.get_enabled_user_skills", return_value=[]), \
             patch("prompts.classification.get_setting", return_value=False):
            prompt = build_classification_prompt("hack it")
        self.assertNotIn("### crypto_attack", prompt)


class TestCryptoAttackDisjointFromAccessControl(unittest.TestCase):
    """The JWT-crypto attacks were moved OUT of access_control INTO crypto_attack;
    the two must not both claim the cryptographic break (keyword-overlap rule)."""

    def test_access_control_no_longer_claims_jwt_crypto(self):
        # access_control keeps CLAIM tampering, not alg:none / weak-secret cracking.
        self.assertNotIn("alg:none, weak-secret cracking", _ACCESS_CONTROL_SECTION)
        self.assertIn("JWT CLAIM tampering", _ACCESS_CONTROL_SECTION)

    def test_crypto_owns_jwt_signature_break(self):
        section, _, _ = _BUILTIN_SKILL_MAP[CLS]
        self.assertIn("alg:none", section)
        self.assertIn("algorithm confusion", section)


class TestCryptoAttackInjection(unittest.TestCase):
    def test_workflow_builds_when_execute_code_allowed(self):
        wf = build_builtin_skill_workflow(CLS, {"execute_code", "kali_shell", "execute_curl"})
        self.assertTrue(wf)
        self.assertIn(CRYPTO_ATTACK_TOOLS, wf)

    def test_workflow_gated_on_execute_code(self):
        # No execute_code -> not injected (the agent could not script the attacks).
        self.assertEqual(build_builtin_skill_workflow(CLS, {"execute_curl", "kali_shell"}), [])

    def test_workflow_empty_when_skill_disabled(self):
        with patch("project_settings.get_enabled_builtin_skills", return_value={"xss"}):
            self.assertEqual(
                build_builtin_skill_workflow(CLS, {"execute_code"}), [])

    def test_other_class_does_not_inject_crypto(self):
        wf = build_builtin_skill_workflow("xss", {"execute_code", "execute_curl"})
        self.assertNotIn(CRYPTO_ATTACK_TOOLS, wf)


class TestCryptoAttackProjectSettings(unittest.TestCase):
    def test_enabled_by_default(self):
        self.assertIs(
            ps.DEFAULT_AGENT_SETTINGS["ATTACK_SKILL_CONFIG"]["builtIn"][CLS], True)


class TestCryptoAttackBehaviorBlurb(unittest.TestCase):
    def test_behavior_blurb_present_and_specific(self):
        blurb = build_attack_path_behavior(CLS)
        self.assertTrue(blurb.strip())
        low = blurb.lower()
        for token in ("crypto", "oracle", "execute_code"):
            self.assertIn(token, low, token)

    def test_regression_behavior_blurb_is_specific_not_fallback(self):
        # REGRESSION: crypto_attack fell through to the generic
        # "Follow the workflow guidance ..." fallback while every other
        # first-class skill had a dedicated blurb. It must NOT be the fallback.
        blurb = build_attack_path_behavior(CLS)
        fallback = build_attack_path_behavior("some_unknown_class")
        self.assertNotEqual(blurb.strip(), fallback.strip())
        self.assertGreater(len(blurb), 300, "crypto blurb should be a real per-skill blurb")
        self.assertIn("informational phase", blurb.lower())
        self.assertIn("exploitation", blurb.lower())


class TestCryptoAttackContentCoverage(unittest.TestCase):
    """CRYPTO_ATTACK_TOOLS must teach the full technique spectrum, generically.

    Matching is case- and whitespace-insensitive: the workflow line-wraps at ~80
    cols and uses mixed case (e.g. `ALGORITHM CONFUSION`, `Mersenne\\nTwister`),
    so a raw substring check would give false negatives on presentation, not
    coverage. We normalize once and assert the concepts are present.
    """

    # normalized haystack: collapse all whitespace runs to single spaces, lowercase
    _H = " ".join(CRYPTO_ATTACK_TOOLS.split()).lower()

    def _assert_all(self, tokens):
        for token in tokens:
            self.assertIn(token.lower(), self._H, token)

    def test_symmetric_block_techniques(self):
        self._assert_all(("padding oracle", "CBC", "ECB", "bit-flip",
                          "byte-at-a-time", "cut-and-paste", "IV"))

    def test_stream_and_oracle(self):
        self._assert_all(("keystream", "nonce reuse", "two-time pad",
                          "ERROR DIFFERENTIAL", "TIMING"))

    def test_jwt_techniques(self):
        self._assert_all(("alg:none", "algorithm confusion", "HS256", "jwt_tool",
                          "jku", "jwk", "kid"))

    def test_hash_and_asymmetric(self):
        self._assert_all(("hash length extension", "Merkle-Damgard", "HMAC",
                          "RSA", "Wiener", "Fermat", "Bleichenbacher", "factordb"))

    def test_randomness_and_encoding(self):
        self._assert_all(("Mersenne Twister", "LCG", "predictable",
                          "classical", "XOR"))

    def test_has_structure_gate_and_reporting(self):
        self._assert_all(("STOP checks", "Abandonment gate", "Reporting", "phase"))


class TestCryptoAttackFairnessAndStyle(unittest.TestCase):
    def test_no_em_dash(self):
        self.assertNotIn("—", CRYPTO_ATTACK_TOOLS)
        self.assertNotIn("—", _BUILTIN_SKILL_MAP[CLS][0])
        self.assertNotIn("—", build_attack_path_behavior(CLS))

    def test_no_format_braces(self):
        # CRYPTO_ATTACK_TOOLS is injected verbatim (no .format); stray braces
        # would only be a bug if someone later adds a .format() call, but the
        # skill legitimately contains {} in code examples, so we instead assert
        # it is NOT registered for formatting by checking the injection path is
        # a plain append (covered structurally by test_workflow_builds_*). Here
        # we assert the module docstring's verbatim contract is intact.
        import prompts.crypto_attack_prompts as m
        self.assertIn("injected VERBATIM", m.__doc__)

    def test_no_benchmark_leak(self):
        blob = (CRYPTO_ATTACK_TOOLS + _BUILTIN_SKILL_MAP[CLS][0]
                + _CLASSIFICATION_INSTRUCTIONS[CLS]
                + build_attack_path_behavior(CLS)).lower()
        for leak in _XBEN101_LEAKS:
            self.assertNotIn(leak, blob, f"benchmark-specific leak: {leak}")

    def test_generic_not_target_specific(self):
        # Names general primitives, never this benchmark's captcha library / key.
        self.assertIn("padding oracle", CRYPTO_ATTACK_TOOLS.lower())
        self.assertNotIn("imagecaptcha", CRYPTO_ATTACK_TOOLS.lower())


class TestCryptoAttackToolRegistryAlignment(unittest.TestCase):
    """Every RedAmon tool the skill names must be a REAL registry tool, and the
    skill must steer to the useful ones (scripting, recon, capture replay)."""

    import re as _re

    def _referenced_tools(self):
        return set(self._re.findall(
            r"\b(query_graph|kali_shell|metasploit_console|execute_[a-z_]+|"
            r"proxy_[a-z_]+|fs_[a-z_]+|job_[a-z_]+)\b", CRYPTO_ATTACK_TOOLS))

    def test_all_referenced_tools_are_real_registry_keys(self):
        from prompts.tool_registry import TOOL_REGISTRY
        bad = sorted(t for t in self._referenced_tools() if t not in TOOL_REGISTRY)
        self.assertEqual(bad, [], f"skill references non-registry tools: {bad}")

    def test_steers_to_key_tools(self):
        for tool in ("query_graph", "execute_code", "kali_shell", "execute_curl",
                     "fs_write", "job_spawn", "redamon."):
            self.assertIn(tool, CRYPTO_ATTACK_TOOLS, f"skill should reference {tool}")

    def test_names_only_installed_cli_crypto_tools(self):
        # These CLI tools were verified present in kali-sandbox; padbuster /
        # hashpump are NOT installed and the skill must not depend on them.
        for present in ("openssl", "jwt_tool", "hashcat", "john"):
            self.assertIn(present, CRYPTO_ATTACK_TOOLS, present)
        self.assertNotIn("padbuster is required", CRYPTO_ATTACK_TOOLS)


class TestCryptoAttackSystemPromptSmoke(unittest.TestCase):
    """End-to-end smoke: get_phase_tools must inject the crypto workflow when the
    class is crypto_attack and execute_code is allowed, and only then."""

    def test_exploitation_crypto_injects_workflow(self):
        from prompts import get_phase_tools
        sysprompt = get_phase_tools(phase="exploitation", attack_path_type="crypto_attack")
        for marker in ("Cryptographic Attack Workflow", "PADDING ORACLE",
                       "STOP checks", "Abandonment gate"):
            self.assertIn(marker, sysprompt, marker)

    def test_other_class_does_not_inject_crypto(self):
        from prompts import get_phase_tools
        sysprompt = get_phase_tools(phase="exploitation", attack_path_type="xss")
        self.assertNotIn("Cryptographic Attack Workflow", sysprompt)


class TestCryptoAttackFrontendArtifacts(unittest.TestCase):
    """Smoke checks against webapp source (layers 6-9): wiring that does not
    crash the agent but breaks the UI badge / toggle / tooltip / suggestions."""

    REPO_ROOT = os.path.dirname(_agentic_dir)

    def _read(self, rel):
        with open(os.path.join(self.REPO_ROOT, rel), encoding="utf-8") as f:
            return f.read()

    def test_prisma_default_includes_crypto_attack(self):
        body = self._read("webapp/prisma/schema.prisma")
        self.assertIn('\\"crypto_attack\\":true', body)

    def test_attack_skills_section_lists_crypto_attack(self):
        body = self._read(
            "webapp/src/components/projects/ProjectForm/sections/AttackSkillsSection.tsx")
        self.assertIn("id: 'crypto_attack'", body)
        self.assertIn("crypto_attack: true", body)  # DEFAULT_CONFIG default

    def test_drawer_tooltip_api_lists_crypto_attack(self):
        body = self._read(
            "webapp/src/app/api/users/[id]/attack-skills/available/route.ts")
        self.assertIn("id: 'crypto_attack'", body)

    def test_phase_config_has_badge(self):
        body = self._read(
            "webapp/src/app/graph/components/AIAssistantDrawer/phaseConfig.ts")
        self.assertIn("crypto_attack: {", body)
        self.assertIn("'CRYPT'", body)

    def test_suggestion_data_has_block(self):
        body = self._read(
            "webapp/src/app/graph/components/AIAssistantDrawer/suggestionData.ts")
        self.assertIn("id: 'crypto_attack'", body)
        self.assertIn("Cryptographic Attacks", body)


if __name__ == "__main__":
    unittest.main(verbosity=2)
