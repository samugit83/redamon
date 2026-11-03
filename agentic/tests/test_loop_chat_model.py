"""LoopChatModel opens a step inside a live loop run scope and nowhere else."""
from __future__ import annotations

import asyncio
import unittest
from unittest import mock

from langchain_core.messages import HumanMessage, SystemMessage

from agent_context import current_log_session_id, current_project_id, current_session_id, current_user_id
from agent_in_the_loop import LoopSettings, broker as broker_mod
from agent_in_the_loop.broker import StepBroker
from agent_in_the_loop.errors import LoopModelOutsideRun, LoopStepNotAnswered
from agent_in_the_loop.model import LoopChatModel, is_loop_llm
from agent_in_the_loop.purpose import llm_purpose
from orchestrator_helpers.llm_retry import retry_llm_call


def cfg(**over):
    base = dict(step_deadline_s=900, lease_s=90, wait_max_s=55, page_chars=40000,
                answer_max_chars=262144, max_open_steps_per_user=16, no_driver_grace_s=300,
                driver_seen_s=60, state_ttl_s=3600)
    base.update(over)
    return LoopSettings(**base)


class Clock:
    t = 1000.0

    def __call__(self):
        return self.t


class ModelCase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.clock = Clock()
        self.broker = StepBroker(now=self.clock, config=cfg(), poll_s=0.01)
        patcher = mock.patch.object(broker_mod, "_broker", self.broker)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.tokens = [current_log_session_id.set("s1"), current_user_id.set(""),
                       current_project_id.set(""), current_session_id.set("")]

    async def asyncTearDown(self):
        for var, tok in zip((current_log_session_id, current_user_id, current_project_id,
                             current_session_id), self.tokens):
            var.reset(tok)

    async def driver(self, answer, *, user="u1", projects=("p1",)):
        got = await self.broker.wait_next(user, list(projects), None, "t1", "cc-a", 2)
        step = got["step"]
        await self.broker.answer(user, list(projects), step["stepId"], text=answer,
                                 answered_by={"token_prefix": "rdm_x", "token_name": "n"})
        return step

    async def test_inside_a_scope_the_driver_answers(self):
        async with self.broker.run_scope("u1", "p1", "s1", None, uses_loop=True):
            driver = asyncio.create_task(self.driver('{"action": "complete"}'))
            with llm_purpose("think", iteration=3, attempt=0):
                msg = await LoopChatModel().ainvoke(
                    [SystemMessage(content="sys"), HumanMessage(content="decide")])
            step = await driver
        self.assertEqual(msg.content, '{"action": "complete"}')
        self.assertEqual(msg.usage_metadata, {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0})
        self.assertEqual(msg.response_metadata["answered_by"]["token_prefix"], "rdm_x")
        # Identity came from the scope while the tenant ContextVars were empty.
        self.assertEqual((step["projectId"], step["sessionId"]), ("p1", "s1"))
        self.assertEqual((step["purpose"], step["iteration"], step["answerFormat"]),
                         ("think", 3, "json"))
        self.assertEqual(step["lastInstruction"], "decide")

    async def test_outside_any_scope_fails_at_once(self):
        loop = asyncio.get_running_loop()
        start = loop.time()
        with self.assertRaises(LoopModelOutsideRun):
            await LoopChatModel().ainvoke("hi")
        self.assertLess(loop.time() - start, 0.1)
        self.assertEqual(self.broker._steps, {})

    async def test_a_provider_scope_for_the_session_fails_at_once(self):
        async with self.broker.run_scope("u1", "p1", "s1", None, uses_loop=False):
            with self.assertRaises(LoopModelOutsideRun):
                await LoopChatModel().ainvoke("hi")
        self.assertEqual(self.broker._steps, {})

    async def test_a_deadline_is_attempted_once(self):
        opened = []
        real_open = self.broker.open_step

        async def counting_open(step, scope=None):
            opened.append(step.id)
            await real_open(step, scope)
            self.clock.t += 901

        self.broker.open_step = counting_open
        async with self.broker.run_scope("u1", "p1", "s1", None, uses_loop=True):
            await self.broker.wait_next("u1", ["p1"], None, "t1", "cc-a", 0)
            with self.assertRaises(LoopStepNotAnswered):
                await retry_llm_call(LoopChatModel(), [HumanMessage(content="x")], label="t")
        self.assertEqual(len(opened), 1)

    async def test_string_and_dict_input(self):
        async with self.broker.run_scope("u1", "p1", "s1", None, uses_loop=True):
            driver = asyncio.create_task(self.driver("MATCH (n) RETURN n"))
            with llm_purpose("cypher"):
                msg = await LoopChatModel().ainvoke("Write a Cypher query")
            step = await driver
            self.assertEqual(msg.content, "MATCH (n) RETURN n")
            self.assertEqual(step["answerFormat"], "cypher")
            self.assertIn("=== USER ===\n\nWrite a Cypher query", step["prompt"])
            driver = asyncio.create_task(self.driver("[]"))
            with llm_purpose("lats_expand"):
                await LoopChatModel().ainvoke([{"role": "system", "content": "s"},
                                               {"role": "user", "content": "u"}])
            step = await driver
            self.assertTrue(step["prompt"].startswith("=== SYSTEM ===\n\ns"))

    def test_no_tokens_counted_and_sync_refused(self):
        model = LoopChatModel()
        self.assertEqual(model.get_num_tokens_from_messages([HumanMessage(content="x" * 100)]), 0)
        self.assertEqual(model.get_num_tokens("abc"), 0)
        with self.assertRaises(NotImplementedError):
            model.invoke("x")
        self.assertTrue(is_loop_llm(model))
        self.assertFalse(is_loop_llm(object()))
        self.assertFalse(is_loop_llm(mock.MagicMock()))  # a mock answers every attribute
        self.assertEqual(model._llm_type, "agent-in-the-loop")


if __name__ == "__main__":
    unittest.main()
