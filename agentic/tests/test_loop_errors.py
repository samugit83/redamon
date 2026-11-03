"""Agent in the Loop errors are never retried, and the purpose label scopes cleanly."""
from __future__ import annotations

import asyncio
import unittest

from agent_context import current_llm_purpose
from agent_in_the_loop.errors import (
    LoopCapReached, LoopDisabled, LoopError, LoopModelOutsideRun, LoopNoDriver,
    LoopStepDeclined, LoopStepNotAnswered, sanitize_reason,
)
from agent_in_the_loop.purpose import ANSWER_FORMAT, PURPOSES, answer_format, llm_purpose
from orchestrator_helpers.llm_retry import (
    _TRANSIENT_EXC_NAMES, _TRANSIENT_KEYWORDS, _TRANSIENT_STATUS_RE,
)

ALL = (LoopError, LoopStepNotAnswered, LoopNoDriver, LoopModelOutsideRun, LoopCapReached, LoopDisabled)


class Messages(unittest.TestCase):
    def test_no_message_looks_transient(self):
        errors = [cls() for cls in ALL] + [LoopStepDeclined("connection timeout 503 rate limit")]
        for exc in errors:
            with self.subTest(cls=type(exc).__name__):
                text = str(exc).lower()
                self.assertFalse([k for k in _TRANSIENT_KEYWORDS if k in text])
                self.assertIsNone(_TRANSIENT_STATUS_RE.search(text))
                self.assertFalse({b.__name__ for b in type(exc).__mro__} & _TRANSIENT_EXC_NAMES)

    def test_every_error_is_marked_no_retry_and_has_a_code(self):
        codes = set()
        for cls in ALL[1:] + (LoopStepDeclined,):
            exc = cls()
            self.assertTrue(exc.no_retry)
            self.assertTrue(exc.code.startswith("loop_"))
            codes.add(exc.code)
        self.assertEqual(len(codes), 6)

    def test_declined_reason_is_kept_out_of_the_message(self):
        exc = LoopStepDeclined("I will not\nscan this\x00 host")
        self.assertEqual(exc.reason, "I will not scan this host")
        self.assertNotIn("scan", str(exc))

    def test_reason_is_capped(self):
        self.assertEqual(len(sanitize_reason("x" * 1000)), 300)
        self.assertEqual(sanitize_reason(None), "")


class Purpose(unittest.TestCase):
    def test_default(self):
        self.assertEqual(current_llm_purpose.get(), {"purpose": "other"})

    def test_sets_and_restores_nested(self):
        with llm_purpose("think", iteration=3, attempt=0):
            self.assertEqual(current_llm_purpose.get(), {"purpose": "think", "iteration": 3, "attempt": 0})
            with llm_purpose("cypher"):
                self.assertEqual(current_llm_purpose.get()["purpose"], "cypher")
            self.assertEqual(current_llm_purpose.get()["purpose"], "think")
        self.assertEqual(current_llm_purpose.get(), {"purpose": "other"})

    def test_restores_after_an_exception(self):
        with self.assertRaises(ValueError):
            with llm_purpose("report"):
                raise ValueError("boom")
        self.assertEqual(current_llm_purpose.get()["purpose"], "other")

    def test_unknown_purpose_becomes_other(self):
        with llm_purpose("made_up"):
            self.assertEqual(current_llm_purpose.get()["purpose"], "other")

    def test_child_task_inherits_the_label(self):
        async def child():
            return current_llm_purpose.get()["purpose"]

        async def main():
            with llm_purpose("fireteam_member", member_id="m1"):
                return await asyncio.create_task(child())

        self.assertEqual(asyncio.run(main()), "fireteam_member")

    def test_answer_formats(self):
        self.assertEqual(set(ANSWER_FORMAT), set(PURPOSES))
        self.assertEqual(answer_format("think"), "json")
        self.assertEqual(answer_format("cypher"), "cypher")
        self.assertEqual(answer_format("report"), "markdown")
        self.assertEqual(answer_format("other"), "text")
        self.assertEqual(answer_format("nope"), "text")


if __name__ == "__main__":
    unittest.main()
