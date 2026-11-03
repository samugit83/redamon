"""An Agent in the Loop failure is never retried, never times out twice, and every
call site ends the way the plan says: safe default, fail closed, or a fixed report."""
from __future__ import annotations

import asyncio
import importlib
import sys
import unittest
from unittest import mock

from langchain_core.messages import AIMessage

from agent_context import current_llm, current_llm_purpose
from agent_in_the_loop.errors import LoopNoDriver, LoopStepDeclined, LoopStepNotAnswered
from agent_in_the_loop.model import LoopChatModel
from orchestrator_helpers.llm_retry import is_transient_llm_error, llm_error_reason

initialize_node = importlib.import_module("orchestrator_helpers.nodes.initialize_node")
importlib.import_module("orchestrator_helpers.nodes.generate_response_node")
report_mod = sys.modules["orchestrator_helpers.nodes.generate_response_node"]


class APIConnectionError(Exception):
    pass


class FailingLLM:
    def __init__(self, exc):
        self.exc, self.calls, self.purposes = exc, 0, []

    async def ainvoke(self, _messages):
        self.calls += 1
        self.purposes.append(current_llm_purpose.get()["purpose"])
        raise self.exc


class Classification(unittest.TestCase):
    def test_marker_wins_over_everything(self):
        self.assertFalse(is_transient_llm_error(LoopStepNotAnswered()))
        self.assertFalse(is_transient_llm_error(LoopNoDriver()))
        self.assertTrue(is_transient_llm_error(APIConnectionError("x")))
        self.assertTrue(is_transient_llm_error(RuntimeError("upstream 503")))

    def test_completion_reason_names_the_class(self):
        self.assertEqual(llm_error_reason(LoopStepNotAnswered()), "llm_error: LoopStepNotAnswered")
        self.assertEqual(llm_error_reason(LoopNoDriver()), "llm_error: LoopNoDriver")


class Classifier(unittest.IsolatedAsyncioTestCase):
    async def test_one_attempt_then_the_safe_default(self):
        from orchestrator_helpers.phase import classify_attack_path
        llm = FailingLLM(LoopStepNotAnswered())
        with mock.patch("orchestrator_helpers.phase.asyncio.sleep", new=mock.AsyncMock()):
            result = await classify_attack_path(llm, "find the sqli", max_retries=3)
        self.assertEqual(llm.calls, 1)
        self.assertEqual(llm.purposes, ["classify"])
        self.assertEqual(result, ("cve_exploit", "informational", None, None, []))

    async def test_other_errors_still_retry(self):
        from orchestrator_helpers.phase import classify_attack_path
        llm = FailingLLM(RuntimeError("bad"))
        with mock.patch("orchestrator_helpers.phase.asyncio.sleep", new=mock.AsyncMock()):
            await classify_attack_path(llm, "x", max_retries=3)
        self.assertEqual(llm.calls, 3)


def _settings(**values):
    return lambda key, default=None: values.get(key, default)


class Guardrail(unittest.IsolatedAsyncioTestCase):
    async def run_guardrail(self, exc):
        fake = _settings(IP_MODE=True, TARGET_IPS=["192.0.2.10"])
        with mock.patch.object(initialize_node, "get_setting", fake), \
                mock.patch("project_settings.soft_guardrail_names", return_value=[]), \
                mock.patch("orchestrator_helpers.guardrail.check_target_allowed",
                           new=mock.AsyncMock(side_effect=exc)):
            return await initialize_node._run_scope_guardrail(LoopChatModel(), "u1", "p1", "s1")

    async def test_a_loop_failure_blocks_with_its_own_reason(self):
        for exc in (LoopStepNotAnswered(), LoopNoDriver(), LoopStepDeclined("no")):
            with self.subTest(exc=type(exc).__name__):
                update = await self.run_guardrail(exc)
                self.assertTrue(update["_guardrail_blocked"])
                self.assertTrue(update["task_complete"])
                self.assertEqual(update["completion_reason"],
                                 "Scope Guardrail: your external agent did not answer")
                self.assertIn(exc.code, update["messages"][0].content)

    async def test_any_other_error_keeps_todays_reason(self):
        update = await self.run_guardrail(RuntimeError("boom"))
        self.assertTrue(update["_guardrail_blocked"])
        self.assertTrue(update["completion_reason"].startswith("Guardrail check failed:"))


class Report(unittest.IsolatedAsyncioTestCase):
    STATE = {
        "execution_trace": [{"success": True, "phase": "informational"},
                            {"success": False, "phase": "informational"}],
        "original_objective": "find the sqli",
        "completion_reason": "llm_error: LoopNoDriver",
    }
    CONFIG = {"configurable": {"user_id": "u1", "project_id": "p1", "thread_id": "s1"}}

    async def run_report(self, llm):
        with mock.patch.object(report_mod.chain_graph, "fire_update_chain_status") as chain:
            out = await report_mod.generate_response_node(
                dict(self.STATE), self.CONFIG, llm=llm, streaming_callbacks={},
                neo4j_creds=("bolt://x", "u", "p"))
        return out, chain

    async def test_a_loop_error_writes_the_fallback_report(self):
        llm = FailingLLM(LoopNoDriver())
        out, chain = await self.run_report(llm)
        self.assertEqual(llm.purposes, ["report"])
        text = out["messages"][0].content
        self.assertIn("The external agent did not write the final report", text)
        self.assertIn("loop_no_driver", text)
        self.assertIn("2 step(s) ran, 1 succeeded and 1 failed", text)
        self.assertTrue(out["task_complete"])
        chain.assert_called_once()

    async def test_any_other_error_still_raises(self):
        with self.assertRaises(RuntimeError):
            await self.run_report(FailingLLM(RuntimeError("provider down")))

    async def test_a_normal_answer_is_unchanged(self):
        llm = mock.MagicMock()
        llm.ainvoke = mock.AsyncMock(return_value=AIMessage(content="# Report"))
        out, _ = await self.run_report(llm)
        self.assertEqual(out["messages"][0].content, "# Report")


class TextToCypher(unittest.IsolatedAsyncioTestCase):
    async def test_a_loop_model_is_not_bound_by_the_generation_timeout(self):
        from tools import Neo4jToolManager

        class SlowLoop(LoopChatModel):
            async def ainvoke(self, _input, *a, **kw):
                self.__dict__.setdefault("purposes", []).append(current_llm_purpose.get()["purpose"])
                await asyncio.sleep(0.05)
                return AIMessage(content="MATCH (n:Domain) RETURN n LIMIT 5")

        llm = SlowLoop()
        manager = Neo4jToolManager("bolt://x", "u", "p", llm=None)
        token = current_llm.set(llm)
        try:
            with mock.patch.dict("os.environ", {"CYPHER_GENERATION_TIMEOUT": "0.01"}):
                cypher = await manager._generate_cypher("list domains")
        finally:
            current_llm.reset(token)
        self.assertIn("MATCH (n:Domain)", cypher)
        self.assertEqual(llm.__dict__["purposes"], ["cypher"])

    async def test_a_provider_model_still_is(self):
        from tools import CypherGenerationTimeout, Neo4jToolManager
        llm = mock.MagicMock()

        async def slow(_input):
            await asyncio.sleep(0.2)
        llm.ainvoke = slow
        manager = Neo4jToolManager("bolt://x", "u", "p", llm=llm)
        with mock.patch.dict("os.environ", {"CYPHER_GENERATION_TIMEOUT": "0.01"}):
            with self.assertRaises(CypherGenerationTimeout):
                await manager._generate_cypher("list domains")


if __name__ == "__main__":
    unittest.main()
