"""Every chat-run model call is labelled with its purpose, and the think prompt
reaches Agent in the Loop as tier blocks without cache markers."""
from __future__ import annotations

import inspect
import sys
import unittest
from unittest import mock

from langchain_core.messages import AIMessage

from agent_context import current_llm_purpose
from agent_in_the_loop.model import LoopChatModel
from prompts.base import CACHE_MARKERS, CACHE_TIER0_END, CACHE_TIER1_END, CACHE_TIER2_END

import orchestrator_helpers.nodes.think_node  # noqa: F401
import orchestrator_helpers.nodes.fireteam_member_think_node  # noqa: F401
import orchestrator_helpers.lats as lats_mod

think_mod = sys.modules["orchestrator_helpers.nodes.think_node"]
member_mod = sys.modules["orchestrator_helpers.nodes.fireteam_member_think_node"]


class Recording:
    def __init__(self, content):
        self.content, self.seen = content, []

    async def ainvoke(self, _messages):
        self.seen.append(dict(current_llm_purpose.get()))
        return AIMessage(content=self.content)


class Driven(unittest.IsolatedAsyncioTestCase):
    async def test_guardrail(self):
        from orchestrator_helpers.guardrail import _invoke_guardrail
        llm = Recording('{"allowed": true, "reason": "ok"}')
        await _invoke_guardrail(llm, "prompt")
        self.assertEqual(llm.seen, [{"purpose": "scope_guardrail", "attempt": 0}])

    async def test_classifier(self):
        from orchestrator_helpers.phase import classify_attack_path
        llm = Recording('{"attack_path_type": "cve_exploit", "required_phase": "informational", '
                        '"confidence": 0.9, "reasoning": "r"}')
        await classify_attack_path(llm, "scan it")
        self.assertEqual(llm.seen[0], {"purpose": "classify", "attempt": 0})

    async def test_the_label_is_gone_after_the_call(self):
        from orchestrator_helpers.guardrail import _invoke_guardrail
        await _invoke_guardrail(Recording('{"allowed": true, "reason": "ok"}'), "prompt")
        self.assertEqual(current_llm_purpose.get(), {"purpose": "other"})


class Wired(unittest.TestCase):
    """think, Deep Think, the Fireteam member and LATS are too heavy to drive here;
    pin that each call sits inside its label (as test_root_think_and_guardrail_retry)."""

    def assert_wrapped(self, src: str, label: str, call: str):
        at = src.index(f'with llm_purpose("{label}"')
        self.assertIn(call, src[at:at + 400], f"{label} does not wrap {call}")

    def test_think_and_deep_think(self):
        src = inspect.getsource(think_mod.think_node)
        self.assert_wrapped(src, "think", "await retry_llm_call(")
        self.assert_wrapped(src, "deep_think", "await retry_llm_call(")

    def test_fireteam_member(self):
        src = inspect.getsource(member_mod)
        self.assert_wrapped(src, "fireteam_member", "await retry_llm_call(")
        self.assertIn("member_id=member_id, member_name=member_name", src)

    def test_lats_expand(self):
        self.assert_wrapped(inspect.getsource(lats_mod.lats_expand), "lats_expand",
                            'await retry_llm_call(llm, messages, label="lats_expand")')


PROMPT = (f"persona {CACHE_TIER0_END} skills {CACHE_TIER1_END} "
          f"phase tools {CACHE_TIER2_END} current state")


class ChatAnthropic:  # the check is on the class name
    pass


class TierBlocks(unittest.TestCase):
    def build(self, llm, caching=True, prompt=PROMPT):
        return think_mod.build_system_message_content(prompt, llm, caching)

    def test_chat_anthropic_is_unchanged(self):
        self.assertEqual(self.build(ChatAnthropic()), [
            {"type": "text", "text": "persona", "cache_control": {"type": "ephemeral"}},
            {"type": "text", "text": "skills", "cache_control": {"type": "ephemeral"}},
            {"type": "text", "text": "phase tools", "cache_control": {"type": "ephemeral"}},
            {"type": "text", "text": "current state"},
        ])

    def test_loop_model_gets_four_blocks_without_cache_control(self):
        blocks = self.build(LoopChatModel())
        self.assertEqual(blocks, [{"type": "text", "text": t}
                                  for t in ("persona", "skills", "phase tools", "current state")])

    def test_loop_model_ignores_the_anthropic_switch(self):
        self.assertEqual(len(self.build(LoopChatModel(), caching=False)), 4)

    def test_other_models_and_switch_off_get_the_stripped_string(self):
        for llm, caching in ((mock.MagicMock(), True), (ChatAnthropic(), False)):
            with self.subTest(llm=type(llm).__name__, caching=caching):
                content = self.build(llm, caching)
                self.assertIsInstance(content, str)
                self.assertFalse(any(m in content for m in CACHE_MARKERS))
                self.assertIn("current state", content)

    def test_a_missing_marker_gives_the_string(self):
        content = self.build(LoopChatModel(), prompt=PROMPT.replace(CACHE_TIER1_END, ""))
        self.assertIsInstance(content, str)


if __name__ == "__main__":
    unittest.main()
