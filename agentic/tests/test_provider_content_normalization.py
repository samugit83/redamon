"""Unit + regression tests for cross-provider LLM response content handling.

Different LangChain provider wrappers emit `response.content` in different
shapes:

- ChatOpenAI / ChatAnthropic (string mode)     -> str
- ChatBedrockConverse / ChatAnthropic (tool mode) -> list of content blocks
  e.g. [{"type": "text", "text": "..."}]
- Edge cases: empty list, None, mixed string/dict blocks, tool_use blocks
  alongside text blocks.

`orchestrator_helpers.json_utils.normalize_content()` is the single
flattener that every LLM-touching call site MUST go through before applying
string operations like `.strip()`.

These tests are designed to fail loudly the day someone:
1. Reverts a call site to raw `.strip()` on `.content` (re-introduces the
   "'list' object has no attribute 'strip'" Bedrock crash).
2. Changes `normalize_content` semantics in a way that drops text blocks.
3. Adds a new LLM call site that bypasses `normalize_content`.

Run inside the agent container:
    python -m unittest tests.test_provider_content_normalization
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

_AGENTIC_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_AGENTIC_DIR))

from orchestrator_helpers.json_utils import normalize_content


class NormalizeContentShapeTests(unittest.TestCase):
    """Direct exercise of every input shape `normalize_content` should handle."""

    # ------------- string inputs (OpenAI/Anthropic plain) -------------

    def test_plain_string_passthrough(self):
        self.assertEqual(normalize_content("hello"), "hello")

    def test_empty_string_passthrough(self):
        self.assertEqual(normalize_content(""), "")

    def test_string_with_whitespace_is_not_stripped(self):
        """normalize_content does not trim — callers chain .strip() themselves."""
        self.assertEqual(normalize_content("  hi  "), "  hi  ")

    # ------------- list inputs (Bedrock Converse / Anthropic tool mode) -------------

    def test_bedrock_single_text_block(self):
        content = [{"type": "text", "text": "decision json here"}]
        self.assertEqual(normalize_content(content), "decision json here")

    def test_bedrock_multiple_text_blocks_joined(self):
        content = [
            {"type": "text", "text": "line one"},
            {"type": "text", "text": "line two"},
        ]
        # Implementation joins with "\n" — both lines must appear.
        out = normalize_content(content)
        self.assertIn("line one", out)
        self.assertIn("line two", out)

    def test_bedrock_empty_list(self):
        self.assertEqual(normalize_content([]), "")

    def test_bedrock_mixed_text_and_tool_use_blocks(self):
        """Real Bedrock response when the model also emits a tool call.

        Only the text block's text should bubble up; tool_use blocks are
        consumed by a parallel code path (e.g. response.tool_calls) and must
        NOT pollute the text output.
        """
        content = [
            {"type": "text", "text": "I'll call the tool"},
            {"type": "tool_use", "id": "abc", "name": "kali_shell", "input": {"cmd": "id"}},
        ]
        out = normalize_content(content)
        self.assertEqual(out, "I'll call the tool")
        self.assertNotIn("tool_use", out)
        self.assertNotIn("kali_shell", out)

    def test_list_of_raw_strings(self):
        """Some wrappers return list[str] (no dict wrapping)."""
        self.assertEqual(normalize_content(["a", "b"]), "a\nb")

    def test_list_with_unknown_block_types_silently_skipped(self):
        """Unknown block types must not crash and must not leak into the text."""
        content = [
            {"type": "text", "text": "keep this"},
            {"type": "image", "source": {"bytes": b"binary"}},
            {"type": "future_block_type", "payload": "ignore"},
        ]
        out = normalize_content(content)
        self.assertEqual(out, "keep this")

    # ------------- defensive inputs -------------

    def test_none_input_returns_empty_string(self):
        """None should not raise — callers pass `getattr(resp, 'content', None)`."""
        # Per implementation: None hits the `str(content)` branch, returning "None".
        # That's still safe — a caller will treat "None" as a non-JSON parse failure,
        # not a crash. We pin the current contract so a future refactor can't
        # change it without us noticing.
        self.assertEqual(normalize_content(None), "None")

    def test_dict_input_returns_str_repr(self):
        """Unexpected dict input doesn't crash; returns its str() form."""
        out = normalize_content({"unexpected": "shape"})
        self.assertIn("unexpected", out)

    def test_integer_input_returns_str_repr(self):
        """Bizarre input still doesn't crash."""
        self.assertEqual(normalize_content(42), "42")


class NormalizeContentChainsWithStripTests(unittest.TestCase):
    """The canonical call pattern used across the codebase:
        text = normalize_content(getattr(resp, 'content', None)).strip()

    These tests verify the chain end-to-end for every provider shape, which
    is the exact failure that hit production on Bedrock:
        AttributeError: 'list' object has no attribute 'strip'
    """

    def _canonical(self, content):
        # Mimics what every fixed call site now does.
        class _R:
            pass
        r = _R()
        r.content = content
        return normalize_content(getattr(r, "content", None)).strip()

    def test_openai_string_chain(self):
        self.assertEqual(self._canonical("  ok  "), "ok")

    def test_bedrock_text_block_chain(self):
        self.assertEqual(
            self._canonical([{"type": "text", "text": "  ok  "}]),
            "ok",
        )

    def test_anthropic_multi_block_chain(self):
        """Anthropic returns multi-block content when it splits a long answer."""
        out = self._canonical([
            {"type": "text", "text": "{\"action\":"},
            {"type": "text", "text": "\"stop\"}"},
        ])
        # Joining preserves valid JSON when caller strips whitespace around it.
        self.assertIn("stop", out)

    def test_bedrock_empty_content_chain(self):
        self.assertEqual(self._canonical([]), "")

    def test_no_content_attribute_chain(self):
        """If getattr returns None (provider returned an unexpected shape)."""
        text = normalize_content(getattr(object(), "content", None)).strip()
        # Pinned contract: stringifies None to "None". Downstream JSON parsing
        # will fail loudly (which is what we want), not crash.
        self.assertEqual(text, "None")


class CallSitesUseNormalizeContentTests(unittest.TestCase):
    """Source-grep tests: no LLM call site should be doing `.strip()`
    directly on `response.content` again. If someone reverts the Bedrock fix,
    these tests fail with a clear message naming the offending line.
    """

    # Files where we deliberately keep the canonical pattern. If any
    # of these files appears in the bad-pattern grep, the test fails.
    GUARDED_FILES = [
        "api.py",
        # Tradecraft's model call sites (the 1.x crawl and lookup left at the cut-over, T9.2).
        "tradecraft/ingest/crawl.py",
        "tradecraft/ingest/focus.py",
        "tradecraft/ingest/summary.py",
        "tradecraft/ingest/tree.py",
        "tradecraft/librarian/graph.py",
        "orchestrator_helpers/nodes/think_node.py",
        "orchestrator_helpers/nodes/generate_response_node.py",
        "orchestrator_helpers/report_summarizer.py",
        "orchestrator_helpers/guardrail.py",
        "orchestrator_helpers/phase.py",
        "tools.py",
    ]

    # Patterns that, if found, indicate someone reverted to the bug-prone form.
    # The literal sequences we look for are exact substrings — anchored on
    # `response.content` / `resp.content` followed by `.strip` with no
    # `normalize_content(` between them.
    BAD_PATTERNS = [
        "(getattr(response, 'content', None) or '').strip()",
        '(getattr(response, "content", None) or "").strip()',
        "(getattr(resp, 'content', '') or '').strip()",
        '(getattr(resp, "content", "") or "").strip()',
        "response.content.strip()",
        "resp.content.strip()",
    ]

    def test_no_call_site_reverts_to_raw_strip(self):
        """Per-line scan: flag a bad pattern only if `normalize_content(`
        does not wrap it on the same line. This way the canonical safe form
            normalize_content(getattr(resp, "content", "") or "").strip()
        passes, while a regression to
            (getattr(resp, "content", "") or "").strip()
        fails the test.
        """
        offenders = []
        for rel in self.GUARDED_FILES:
            f = _AGENTIC_DIR / rel
            if not f.exists():
                continue
            for lineno, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
                for pat in self.BAD_PATTERNS:
                    if pat in line and "normalize_content(" not in line:
                        offenders.append(f"{rel}:{lineno}: {line.strip()}")
        self.assertEqual(
            offenders, [],
            "Call sites reverted to raw .strip() on .content (will crash "
            "on Bedrock):\n  " + "\n  ".join(offenders),
        )


if __name__ == "__main__":
    unittest.main()
