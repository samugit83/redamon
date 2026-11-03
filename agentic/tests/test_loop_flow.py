"""Agent in the Loop flows end to end through the broker, with a scripted driver.

Unit tier on purpose (no `_integration` in the name): every service is faked.
The root think node has no unit harness, so the decision loop is driven through
the Fireteam member node, which runs the same parse-retry loop on current_llm.
"""
from __future__ import annotations

import asyncio
import importlib
import json
import unittest
from unittest import mock

from langchain_core.messages import HumanMessage

import orchestrator as orchestrator_mod
from agent_context import current_llm, current_log_session_id, current_project_id, current_user_id
from agent_in_the_loop import LoopSettings, broker as broker_mod
from agent_in_the_loop.broker import StepBroker
from agent_in_the_loop.errors import LoopNoDriver
from agent_in_the_loop.model import LoopChatModel
from agent_in_the_loop.purpose import llm_purpose
import orchestrator_helpers.chain_graph_writer as cg

member_mod = importlib.import_module("orchestrator_helpers.nodes.fireteam_member_think_node")
initialize_mod = importlib.import_module("orchestrator_helpers.nodes.initialize_node")

COMPLETE = json.dumps({
    "thought": "t", "reasoning": "r", "action": "complete", "completion_reason": "done",
    "output_analysis": {
        "interpretation": "nothing more to do",
        "extracted_info": {"primary_target": "", "ports": [], "services": [], "technologies": [],
                           "vulnerabilities": [], "credentials": [], "sessions": []},
        "actionable_findings": [], "recommended_next_steps": [],
        "exploit_succeeded": False, "exploit_details": None, "chain_findings": [],
    },
})


class Clock:
    t = 1000.0

    def __call__(self):
        return self.t


def member_state():
    return {
        "messages": [], "current_iteration": 1, "max_iterations": 10,
        "task_complete": False, "completion_reason": None,
        "current_phase": "informational", "attack_path_type": "cve_exploit",
        "user_id": "u1", "project_id": "p1", "session_id": "s1",
        "parent_target_info": {}, "member_name": "Web Tester",
        "member_id": "member-0-abc", "fireteam_id": "fteam-1",
        "tools": ["query_graph"], "task": "summarise the target", "execution_trace": [],
        "target_info": {}, "chain_findings_memory": [], "chain_failures_memory": [],
        "_pending_confirmation": None, "tokens_used": 0, "_decision": None,
        "_current_step": None, "_last_chain_step_id": None, "_guardrail_blocked": False,
    }


class FlowCase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.clock = Clock()
        self.broker = StepBroker(now=self.clock, poll_s=0.01, config=LoopSettings(
            step_deadline_s=900, lease_s=90, wait_max_s=55, page_chars=40000,
            answer_max_chars=262144, max_open_steps_per_user=16, no_driver_grace_s=300,
            driver_seen_s=60, state_ttl_s=3600))
        for patcher in (mock.patch.object(broker_mod, "_broker", self.broker),
                        mock.patch.object(cg, "sync_record_step"),
                        mock.patch.object(cg, "fire_record_failure"),
                        mock.patch.object(cg, "fire_record_finding"),
                        mock.patch.object(cg, "fire_create_attack_chain"),
                        mock.patch.object(cg, "query_prior_chains", return_value=[])):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.llm = LoopChatModel()
        self.tokens = [(current_log_session_id, current_log_session_id.set("s1")),
                       (current_llm, current_llm.set(self.llm)),
                       (current_user_id, current_user_id.set("")),
                       (current_project_id, current_project_id.set(""))]
        self.seen = []

    async def asyncTearDown(self):
        for var, tok in reversed(self.tokens):
            var.reset(tok)

    async def driver(self, answers, *, user="u1"):
        """Answer the next len(answers) steps in order; record what was served."""
        for answer in answers:
            got = await self.broker.wait_next(user, ["p1"], None, "tok", "cc-test", 5)
            step = got["step"]
            self.assertIsNotNone(step, "no step reached the driver")
            self.seen.append(step)
            await self.broker.answer(user, ["p1"], step["stepId"], text=answer,
                                     answered_by={"token_prefix": "rdm_t", "token_name": "test"})

    async def member_turn(self):
        return await member_mod.fireteam_member_think_node(
            member_state(), None, llm=self.llm, neo4j_creds=("bolt://x", "u", "p"),
            streaming_callbacks=None)


class Flows(FlowCase):
    async def test_member_turn_is_answered_by_the_driver(self):
        async with self.broker.run_scope("u1", "p1", "s1", None, uses_loop=True):
            driver = asyncio.create_task(self.driver([COMPLETE]))
            update = await asyncio.wait_for(self.member_turn(), 5)
            await driver
        self.assertTrue(update.get("task_complete"))
        step = self.seen[0]
        self.assertEqual((step["purpose"], step["answerFormat"]), ("fireteam_member", "json"))
        self.assertEqual(step["member"], {"id": "member-0-abc", "name": "Web Tester"})
        self.assertEqual((step["projectId"], step["sessionId"]), ("p1", "s1"))

    async def test_invalid_json_gets_a_second_step_with_the_correction(self):
        async with self.broker.run_scope("u1", "p1", "s1", None, uses_loop=True):
            driver = asyncio.create_task(self.driver(["{not json", COMPLETE]))
            update = await asyncio.wait_for(self.member_turn(), 5)
            await driver
        self.assertTrue(update.get("task_complete"))
        first, second = self.seen
        self.assertEqual((first["attempt"], second["attempt"]), (0, 1))
        self.assertIn("=== ASSISTANT (your earlier answer) ===\n\n{not json", second["prompt"])
        self.assertIn("failed validation", second["lastInstruction"])

    async def test_three_parallel_members_answered_out_of_order(self):
        async def member(i):
            with llm_purpose("fireteam_member", member_id=f"m{i}"):
                return (await self.llm.ainvoke([HumanMessage(content=f"member {i}")])).content

        async with self.broker.run_scope("u1", "p1", "s1", None, uses_loop=True):
            tasks = [asyncio.create_task(member(i)) for i in range(3)]
            claimed = []
            for _ in range(3):
                claimed.append((await self.broker.wait_next("u1", ["p1"], None, "tok", "cc", 2))["step"])
            for view in reversed(claimed):
                await self.broker.answer("u1", ["p1"], view["stepId"], text=view["member"]["id"])
            results = await asyncio.gather(*tasks)
        self.assertEqual(results, ["m0", "m1", "m2"])

    async def test_no_driver_ends_the_turn_and_the_next_step_fails_at_once(self):
        async with self.broker.run_scope("u1", "p1", "s1", None, uses_loop=True):
            turn = asyncio.create_task(self.member_turn())
            await asyncio.sleep(0.05)
            self.clock.t += 301
            update = await asyncio.wait_for(turn, 5)
            self.assertEqual(update["completion_reason"], "llm_error: LoopNoDriver")
            loop = asyncio.get_running_loop()
            start = loop.time()
            with self.assertRaises(LoopNoDriver):
                await self.llm.ainvoke("report")
            self.assertLess(loop.time() - start, 0.1)
        self.assertEqual(self.broker.status_payload("u1:p1:s1")["state"], "error")
        self.assertEqual(self.broker.status_payload("u1:p1:s1")["detail"]["code"], "loop_no_driver")


class FakeGraph:
    """A one-node graph whose node asks the model, as think does."""

    def __init__(self, llm):
        self.llm = llm

    async def astream(self, _input, _config, stream_mode="values"):
        with llm_purpose("think", iteration=1, attempt=0):
            answer = await self.llm.ainvoke([HumanMessage(content="decide")])
        yield {"task_complete": True, "answer": answer.content}


class StopMidStep(FlowCase):
    async def test_a_stop_during_a_claimed_step(self):
        fake = mock.MagicMock()
        fake.graph, fake.llm = FakeGraph(self.llm), self.llm
        with mock.patch.object(orchestrator_mod, "emit_streaming_events", new=mock.AsyncMock()):
            run = asyncio.create_task(orchestrator_mod.AgentOrchestrator._stream_graph(
                fake, {}, {}, None, "u1", "p1", "s1"))
            got = await self.broker.wait_next("u1", ["p1"], None, "tok", "cc", 2)
            step_id = got["step"]["stepId"]
            run.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await run
        self.assertEqual(self.broker.status_payload("u1:p1:s1")["state"], "stopped")
        late = await self.broker.answer("u1", ["p1"], step_id, text="{}")
        self.assertEqual(late, {"ok": False, "code": "step_closed"})


def _settings(**values):
    return lambda key, default=None: values.get(key, default)


class FirstCallsOfARun(FlowCase):
    async def test_guardrail_and_classifier_open_with_the_scope_identity(self):
        # A domain, not an IP: reserved addresses are allowed without a model call.
        settings = _settings(IP_MODE=False, AGENT_GUARDRAIL_ENABLED=True)
        classification = json.dumps({"attack_path_type": "sql_injection-unclassified",
                                     "required_phase": "informational", "confidence": 0.9,
                                     "reasoning": "r"})
        state = {"messages": [HumanMessage(content="find the sql injection")]}
        config = {"configurable": {"user_id": "u1", "project_id": "p1", "thread_id": "s1"}}
        self.assertEqual((current_user_id.get(), current_project_id.get()), ("", ""))
        with mock.patch("project_settings.get_setting", settings), \
                mock.patch.object(initialize_mod, "get_setting", settings), \
                mock.patch("project_settings.soft_guardrail_names", return_value=["lab.example"]), \
                mock.patch("project_settings.guardrail_names", return_value=["lab.example"]):
            async with self.broker.run_scope("u1", "p1", "s1", None, uses_loop=True):
                driver = asyncio.create_task(self.driver(
                    ['{"allowed": true, "reason": "lab address"}', classification]))
                update = await asyncio.wait_for(initialize_mod.initialize_node(
                    state, config, llm=self.llm, neo4j_creds=("bolt://x", "u", "p")), 5)
                await driver
        self.assertFalse(update.get("_guardrail_blocked"))
        self.assertEqual([s["purpose"] for s in self.seen], ["scope_guardrail", "classify"])
        for step in self.seen:
            self.assertEqual((step["projectId"], step["sessionId"]), ("p1", "s1"))


if __name__ == "__main__":
    unittest.main()
