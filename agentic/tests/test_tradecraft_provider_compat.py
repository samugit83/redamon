"""Provider-compat regression tests for tradecraft LLM call sites.

1.x's crawl decision, section picker and verify summary crashed on Bedrock with
`'list' object has no attribute 'strip'` until they were wrapped with normalize_content().
Those sites left with 1.x at the cut-over (T9.2); the 2.0 call sites are held to the same
pattern by test_provider_content_normalization.py's source scan (GUARDED_FILES), and the
tests below document the bug class itself.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class PreFixVsPostFixContractTests(unittest.TestCase):
    """These tests document the exact crash the fix prevents. They're not
    coverage of the runtime — they're documentation that future readers
    (and AI code-reviewers) can grep for to understand the bug class."""

    def test_old_pattern_crashes_on_bedrock_shape(self):
        bedrock = [{"type": "text", "text": '{"action":"stop"}'}]

        class R:
            content = bedrock

        # Old pattern (pre-fix) — this exact form was in 3 tradecraft sites:
        with self.assertRaises(AttributeError) as ctx:
            (getattr(R(), "content", "") or "").strip()
        self.assertIn("'list' object has no attribute 'strip'", str(ctx.exception))

    def test_new_pattern_works_on_bedrock_shape(self):
        from orchestrator_helpers.json_utils import normalize_content

        bedrock = [{"type": "text", "text": '{"action":"stop"}'}]

        class R:
            content = bedrock

        # New pattern (post-fix):
        text = normalize_content(getattr(R(), "content", "") or "").strip()
        self.assertEqual(text, '{"action":"stop"}')

    def test_new_pattern_works_on_openai_shape(self):
        from orchestrator_helpers.json_utils import normalize_content

        class R:
            content = '{"action":"stop"}'

        text = normalize_content(getattr(R(), "content", "") or "").strip()
        self.assertEqual(text, '{"action":"stop"}')


if __name__ == "__main__":
    unittest.main()
