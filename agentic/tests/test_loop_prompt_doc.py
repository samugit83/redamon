"""The prompt document a driver reads: parts, dedup placeholders, paging."""
from __future__ import annotations

import unittest

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from agent_in_the_loop.prompt_doc import (
    MIN_DEDUP_CHARS, NON_TEXT, last_instruction, page, part_sha, placeholder, render, to_parts,
)

TIER0, TIER1, TIER2 = ("eternal " * 200, "session " * 200, "phase " * 200)


def think_messages(tail: str = "current state: iteration 4"):
    system = SystemMessage(content=[
        {"type": "text", "text": TIER0, "cache_control": {"type": "ephemeral"}},
        {"type": "text", "text": TIER1, "cache_control": {"type": "ephemeral"}},
        {"type": "text", "text": TIER2, "cache_control": {"type": "ephemeral"}},
        {"type": "text", "text": tail},
    ])
    return [system, HumanMessage(content="Output EXACTLY ONE valid JSON object.")]


class Parts(unittest.TestCase):
    def test_think_style_input_gives_one_part_per_tier(self):
        msgs = to_parts(think_messages())
        self.assertEqual([m.role for m in msgs], ["system", "user"])
        self.assertEqual(len(msgs[0].parts), 4)
        self.assertEqual(msgs[0].parts[0].sha, part_sha(TIER0))
        self.assertEqual(len(msgs[0].parts[0].sha), 16)
        # Stable: the same text always has the same sha.
        self.assertEqual(to_parts(think_messages())[0].parts[2].sha, msgs[0].parts[2].sha)

    def test_non_text_block(self):
        msgs = to_parts([HumanMessage(content=[{"type": "image_url", "image_url": {"url": "x"}}, "plain"])])
        self.assertEqual([p.text for p in msgs[0].parts], [NON_TEXT, "plain"])

    def test_string_and_converted_dict_input(self):
        # LangChain turns a bare string and {"role","content"} dicts into messages (E1).
        self.assertEqual(to_parts([HumanMessage(content="MATCH (n) RETURN n")])[0].parts[0].text,
                         "MATCH (n) RETURN n")
        msgs = to_parts([SystemMessage(content="s"), HumanMessage(content="u")])
        self.assertEqual([m.role for m in msgs], ["system", "user"])


class Render(unittest.TestCase):
    def test_first_render_is_full(self):
        text, spans = render(to_parts(think_messages()), delivered=set(), full=False)
        self.assertTrue(text.startswith("=== SYSTEM ===\n\n"))
        self.assertIn("=== USER ===", text)
        self.assertIn(TIER0, text)
        self.assertEqual(len(spans), 5)
        for span in spans:
            self.assertEqual(part_sha(text[span.start:span.end]), span.sha)

    def test_second_render_places_placeholders_for_delivered_tiers(self):
        first = to_parts(think_messages("iteration 4"))
        delivered = {p.sha for p in first[0].parts[:3]}
        second = to_parts(think_messages("iteration 5"))
        text, spans = render(second, delivered=delivered, full=False)
        for tier in (TIER0, TIER1, TIER2):
            self.assertNotIn(tier, text)
            self.assertIn(placeholder(part_sha(tier)), text)
        self.assertIn("iteration 5", text)
        self.assertEqual(len(spans), 2)

    def test_full_never_places_placeholders(self):
        msgs = to_parts(think_messages())
        text, _ = render(msgs, delivered={p.sha for p in msgs[0].parts}, full=True)
        self.assertNotIn("[[part", text)

    def test_no_dedup_without_a_delivered_set(self):
        msgs = to_parts(think_messages())
        text, _ = render(msgs, delivered=None, full=False)
        self.assertNotIn("[[part", text)

    def test_short_parts_are_never_deduped(self):
        short = "x" * (MIN_DEDUP_CHARS - 1)
        msgs = to_parts([HumanMessage(content=short)])
        text, _ = render(msgs, delivered={part_sha(short)}, full=False)
        self.assertIn(short, text)

    def test_retry_conversation_ends_with_the_correction(self):
        msgs = to_parts(think_messages() + [
            AIMessage(content="{not json"),
            HumanMessage(content="Your previous JSON response failed validation: x"),
        ])
        text, _ = render(msgs, delivered=None, full=False)
        self.assertIn("=== ASSISTANT (your earlier answer) ===\n\n{not json", text)
        self.assertTrue(text.endswith("Your previous JSON response failed validation: x"))
        self.assertEqual(last_instruction(msgs), "Your previous JSON response failed validation: x")


class Paging(unittest.TestCase):
    def test_pages_join_back(self):
        text = "".join(f"line {i:06d} " + "y" * 90 + "\n" for i in range(1000))
        self.assertGreater(len(text), 100_000)
        pages, cursor = [], 0
        while cursor is not None:
            chunk, cursor = page(text, cursor, 40_000)
            self.assertLessEqual(len(chunk), 40_000)
            pages.append(chunk)
        self.assertEqual("".join(pages), text)
        self.assertTrue(all(p.endswith("\n") for p in pages))

    def test_text_with_no_newline_is_cut_at_the_size(self):
        chunk, cursor = page("z" * 50, 0, 20)
        self.assertEqual((len(chunk), cursor), (20, 20))

    def test_cursor_past_the_end(self):
        self.assertEqual(page("abc", 10, 5), ("", None))
        self.assertEqual(page("abc", 0, 5), ("abc", None))

    def test_last_instruction_is_capped(self):
        msgs = to_parts([HumanMessage(content="q" * 5000)])
        self.assertEqual(len(last_instruction(msgs)), 2000)
        self.assertEqual(last_instruction(to_parts([SystemMessage(content="s")])), "")


if __name__ == "__main__":
    unittest.main()
