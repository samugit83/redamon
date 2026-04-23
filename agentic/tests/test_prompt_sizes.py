"""Pin prompt-size budgets so future edits that balloon tokens fail loudly.

These upper bounds reflect the post-Safe-tier compression (2026-04-19).
If a legitimate edit needs to push past a bound, raise the number AND
update the audit notes in FIRETEAM.md / prompt file headers.

Budgets are tracked in CHARS (not tokens) because they're what we actually
measure when grepping `FULL SYSTEM PROMPT (N chars)` in the agent log.

Run:
    docker run --rm -v "/home/samuele/Progetti didattici/redamon/agentic:/app" \
        -w /app redamon-agent python -m unittest tests.test_prompt_sizes -v
"""

from __future__ import annotations

import os
import sys
import unittest

_agentic_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _agentic_dir)


class IndividualPromptBlockBudgets(unittest.TestCase):
    """Per-block upper bounds. Breaking a budget usually means a recent edit
    duplicated content that already lives elsewhere."""

    def test_web_search_registry_entry(self):
        from prompts.tool_registry import TOOL_REGISTRY
        # Was ~2.8k pre-Safe; compressed to ~1.3k. Budget allows ~20% headroom.
        self.assertLess(
            len(TOOL_REGISTRY["web_search"]["description"]),
            1500,
            "web_search registry entry regressed — check for restored "
            "examples (Scoping patterns / Single-source shortcuts).",
        )

    def test_informational_guidance_info_phase(self):
        from prompts.base import build_informational_guidance
        info = build_informational_guidance("informational")
        # Was ~2k chars pre-Safe (Intent Detection + Graph-First split);
        # compressed to single bulleted block ~1.2k. Budget at 1400.
        self.assertLess(
            len(info), 1400,
            "build_informational_guidance regressed — check for restored "
            "multi-paragraph intent sections or duplicate Graph-First list.",
        )

    def test_informational_guidance_other_phases_empty(self):
        from prompts.base import build_informational_guidance
        # Phase-gated: exploitation/post_exploitation should pay zero chars.
        for phase in ("exploitation", "post_exploitation"):
            self.assertEqual(build_informational_guidance(phase), "")

    def test_fireteam_prompt_block_budget(self):
        from prompts.base import build_fireteam_prompt_fragments
        _, _, block = build_fireteam_prompt_fragments(
            True, "informational",
            ["informational", "exploitation", "post_exploitation"],
            max_members=5,
        )
        # Was ~6.6k pre-compression; now ~3.5k. Budget 4000 to catch bloat.
        self.assertLess(
            len(block), 4000,
            "_FIRETEAM_PROMPT_BLOCK regressed past 4000 chars — review recent "
            "edits to base._FIRETEAM_PROMPT_BLOCK.",
        )
        # When disabled, must be empty.
        enum, field, block = build_fireteam_prompt_fragments(
            False, "informational",
            ["informational", "exploitation", "post_exploitation"],
            max_members=5,
        )
        self.assertEqual((enum, field, block), ("", "", ""))

    def test_post_exploitation_tools_dedup(self):
        from prompts.post_exploitation import (
            POST_EXPLOITATION_TOOLS_STATEFULL,
            POST_EXPLOITATION_TOOLS_STATELESS,
        )
        # Complementary-tools duplicate table was removed; check it stays gone.
        self.assertNotIn("Complementary Tools", POST_EXPLOITATION_TOOLS_STATEFULL)
        # Both variants should share the Direction block shape.
        for v in (POST_EXPLOITATION_TOOLS_STATEFULL, POST_EXPLOITATION_TOOLS_STATELESS):
            self.assertIn("## Direction", v)
            self.assertIn('action="ask_user"', v)

    def test_dos_ascii_box_removed(self):
        from prompts.denial_of_service_prompts import DOS_TOOLS
        # The 26-line ASCII box was a duplicate of DOS_VECTOR_SELECTION.
        self.assertNotIn("┌─", DOS_TOOLS)
        self.assertNotIn("└─", DOS_TOOLS)
        self.assertIn("DoS VECTOR SELECTION GUIDE", DOS_TOOLS)

    def test_phishing_staged_column_collapsed(self):
        from prompts.phishing_social_engineering_prompts import (
            PHISHING_SOCIAL_ENGINEERING_TOOLS,
        )
        # Payload matrix now has a single "Payload (stageless)" column with a
        # 1-line staged note. Verify we no longer emit both columns side-by-side.
        self.assertNotIn("Payload (STAGED)", PHISHING_SOCIAL_ENGINEERING_TOOLS)
        self.assertIn("Payload (stageless)", PHISHING_SOCIAL_ENGINEERING_TOOLS)
        # The staged-variant note must still be present — it's a safety rule.
        self.assertIn("replace the underscore with a slash",
                      PHISHING_SOCIAL_ENGINEERING_TOOLS)

    def test_cve_exploit_fallback_shares_understand_cve_step(self):
        from prompts.cve_exploit_prompts import (
            NO_MODULE_FALLBACK_STATEFULL,
            NO_MODULE_FALLBACK_STATELESS,
            _UNDERSTAND_CVE_STEP,
            _COMMON_TROUBLESHOOTING_ROWS,
        )
        # Both variants must embed the shared Step 1 (no duplicate inline copy).
        self.assertIn(_UNDERSTAND_CVE_STEP.strip()[:80], NO_MODULE_FALLBACK_STATEFULL)
        self.assertIn(_UNDERSTAND_CVE_STEP.strip()[:80], NO_MODULE_FALLBACK_STATELESS)
        # Shared troubleshooting rows must appear in both variants.
        self.assertIn("Same approach fails 3+ times", NO_MODULE_FALLBACK_STATEFULL)
        self.assertIn("Same approach fails 3+ times", NO_MODULE_FALLBACK_STATELESS)
        self.assertIn("Same approach fails 3+ times", _COMMON_TROUBLESHOOTING_ROWS)


if __name__ == "__main__":
    unittest.main()
