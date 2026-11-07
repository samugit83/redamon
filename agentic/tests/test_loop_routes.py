"""The /loop/* routes a driver reaches through the webapp: auth, validation,
codes, and no text where it does not belong."""
from __future__ import annotations

import asyncio
import os
import unittest
from unittest import mock

import httpx
from fastapi import FastAPI

from agent_in_the_loop import LoopSettings, broker as broker_mod
from agent_in_the_loop.broker import StepBroker
from agent_in_the_loop.prompt_doc import to_parts
from agent_in_the_loop.routes import hint, router
from langchain_core.messages import HumanMessage, SystemMessage

KEY = "k" * 64
HEADERS = {"x-internal-key": KEY}
TIER = "eternal tier " * 100


def cfg(**over):
    base = dict(step_deadline_s=900, lease_s=90, wait_max_s=55, page_chars=4000,
                answer_max_chars=2048, max_open_steps_per_user=16, no_driver_grace_s=300,
                driver_seen_s=60, state_ttl_s=3600)
    base.update(over)
    return LoopSettings(**base)


def _dep_names(route):
    return [getattr(d.dependency, "__name__", "") for d in route.dependencies or []]


class RouteCase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.broker = StepBroker(config=cfg(), poll_s=0.01)
        for patcher in (mock.patch.object(broker_mod, "_broker", self.broker),
                        mock.patch.dict(os.environ, {"INTERNAL_API_KEY": KEY,
                                                     "AGENT_IN_THE_LOOP_ENABLED": "true"})):
            patcher.start()
            self.addCleanup(patcher.stop)
        app = FastAPI()
        app.include_router(router)
        self.app = app
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://agent")
        self.addAsyncCleanup(self.client.aclose)
        cm = self.broker.run_scope("u1", "p1", "session_ab", None, uses_loop=True)
        self.scope = await cm.__aenter__()
        self.addAsyncCleanup(cm.__aexit__, None, None, None)

    async def open(self, text="decide", iteration=1):
        msgs = to_parts([SystemMessage(content=[{"type": "text", "text": TIER},
                                                {"type": "text", "text": text * 500}]),
                         HumanMessage(content="Output one JSON object.")])
        step = self.broker.new_step(self.scope, purpose="think", meta={"iteration": iteration},
                                    messages=msgs, answer_format="json",
                                    last_instruction="Output one JSON object.")
        await self.broker.open_step(step, self.scope)
        return step

    def body(self, **over):
        base = {"user_id": "u1", "driver_id": "tok1", "driver_name": "cc-amber-otter",
                "project_ids": ["p1"]}
        base.update(over)
        return {k: v for k, v in base.items() if v is not None}

    async def post(self, path, body, headers=HEADERS):
        return await self.client.post(path, json=body, headers=headers)


class Auth(RouteCase):
    def test_every_route_needs_the_configured_master_key(self):
        self.assertEqual({r.path for r in router.routes},
                         {"/loop/steps/wait", "/loop/steps/{step_id}/get",
                          "/loop/steps/{step_id}/answer", "/loop/stats"})
        self.assertIn("require_configured_master_auth", _dep_names(router))

    async def test_no_key_configured_is_503_and_wrong_key_401(self):
        with mock.patch.dict(os.environ, {"INTERNAL_API_KEY": ""}):
            resp = await self.post("/loop/steps/wait", self.body(wait_seconds=1))
            self.assertEqual(resp.status_code, 503)
        resp = await self.post("/loop/steps/wait", self.body(wait_seconds=1),
                               headers={"x-internal-key": "nope"})
        self.assertEqual(resp.status_code, 401)
        resp = await self.client.get("/loop/stats")
        self.assertEqual(resp.status_code, 401)

    async def test_switch_off_is_loop_disabled_everywhere(self):
        with mock.patch.dict(os.environ, {"AGENT_IN_THE_LOOP_ENABLED": "false"}):
            sid = "a" * 32
            for resp in (await self.post("/loop/steps/wait", self.body()),
                         await self.post(f"/loop/steps/{sid}/get", self.body()),
                         await self.post(f"/loop/steps/{sid}/answer", self.body(answer="x")),
                         await self.client.get("/loop/stats", headers=HEADERS)):
                self.assertEqual(resp.status_code, 404)
                self.assertEqual(resp.json()["code"], "loop_disabled")


class Validation(RouteCase):
    async def test_bad_bodies(self):
        bad = [
            self.body(extra="x"),
            self.body(user_id="u 1"),
            self.body(user_id=None),
            self.body(driver_name="has space"),
            self.body(driver_name="x" * 41),
            self.body(project_ids="p1"),
            self.body(project_ids=["p1\n"]),
            self.body(session_id="s\nx"),
            self.body(session_id="session_ab\n"),
            self.body(driver_id="tok1\n"),
            self.body(wait_seconds=0),
            self.body(wait_seconds=56),
            self.body(wait_seconds="5"),
            self.body(wait_seconds=True),
            self.body(delivery="all"),
        ]
        for body in bad:
            with self.subTest(body=body):
                resp = await self.post("/loop/steps/wait", body)
                self.assertEqual(resp.status_code, 422)
                self.assertEqual(resp.json(), {"error": "The request is not valid.", "code": "bad_args"})

    async def test_rejected_input_is_never_echoed(self):
        resp = await self.post("/loop/steps/wait", self.body(user_id="SECRET<script>"))
        self.assertNotIn("SECRET", resp.text)

    async def test_not_json(self):
        resp = await self.client.post("/loop/steps/wait", content=b"{nope", headers=HEADERS)
        self.assertEqual(resp.json()["code"], "bad_args")

    async def test_bad_step_ids(self):
        resp = await self.post("/loop/steps/XYZ/get", self.body())
        self.assertEqual((resp.status_code, resp.json()["code"]), (404, "not_found"))
        resp = await self.post("/loop/steps/XYZ/answer", self.body(answer="x"))
        self.assertEqual((resp.status_code, resp.json()["code"]), (409, "step_closed"))


class Flow(RouteCase):
    async def test_wait_get_answer(self):
        step = await self.open()
        resp = await self.post("/loop/steps/wait", self.body(wait_seconds=1))
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        view = data["step"]
        self.assertEqual(view["stepId"], step.id)
        self.assertEqual(view["contractVersion"], 2)
        self.assertEqual((view["purpose"], view["iteration"], view["answerFormat"]), ("think", 1, "json"))
        self.assertEqual(view["sessionId"], "session_ab")
        self.assertTrue(data["hint"].startswith("Answer this step with loop_submit_step"))
        self.assertIsNotNone(view["page"]["nextCursor"])

        text, cursor = view["prompt"], view["page"]["nextCursor"]
        while cursor is not None:
            resp = await self.post(f"/loop/steps/{step.id}/get", self.body(cursor=cursor))
            page = resp.json()["step"]
            text += page["prompt"]
            cursor = page["page"]["nextCursor"]
        self.assertEqual(len(text), view["page"]["totalChars"])

        task = asyncio.create_task(self.broker.await_answer(step))
        resp = await self.post(f"/loop/steps/{step.id}/answer", self.body(
            answer='{"action":"complete","SECRET":1}',
            answered_by={"token_prefix": "rdm_ab\n", "token_name": "laptop" * 20}))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"ok": True, "projectId": "p1", "sessionId": "session_ab",
                                       "purpose": "think", "iteration": 1})
        self.assertNotIn("SECRET", resp.text)
        self.assertEqual(await task, '{"action":"complete","SECRET":1}')
        self.assertEqual(step.answered_by, {"token_prefix": "rdm_ab", "token_name": ("laptop" * 20)[:64]})

        again = await self.post(f"/loop/steps/{step.id}/answer", self.body(answer="x"))
        self.assertEqual((again.status_code, again.json()["code"]), (409, "step_closed"))

    async def test_answer_codes(self):
        step = await self.open()
        both = await self.post(f"/loop/steps/{step.id}/answer", self.body(answer="x", declined=True))
        neither = await self.post(f"/loop/steps/{step.id}/answer", self.body())
        empty = await self.post(f"/loop/steps/{step.id}/answer", self.body(answer="  "))
        long_reason = await self.post(f"/loop/steps/{step.id}/answer",
                                      self.body(declined=True, reason="r" * 301))
        for resp in (both, neither, empty, long_reason):
            self.assertEqual(resp.json()["code"], "bad_args")
        big = await self.post(f"/loop/steps/{step.id}/answer", self.body(answer="x" * 2049))
        self.assertEqual((big.status_code, big.json()["code"]), (413, "answer_too_large"))
        foreign = await self.post(f"/loop/steps/{step.id}/answer", self.body(user_id="u2", answer="x"))
        self.assertEqual(foreign.json()["code"], "step_closed")
        other_project = await self.post(f"/loop/steps/{step.id}/answer",
                                        self.body(project_ids=["p9"], answer="x"))
        self.assertEqual(other_project.json()["code"], "step_closed")

    async def test_decline_with_reason(self):
        step = await self.open()
        task = asyncio.create_task(self.broker.await_answer(step))
        resp = await self.post(f"/loop/steps/{step.id}/answer",
                               self.body(declined=True, reason="out of scope\nhost"))
        self.assertTrue(resp.json()["ok"])
        from agent_in_the_loop.errors import LoopStepDeclined
        with self.assertRaises(LoopStepDeclined) as ctx:
            await task
        self.assertEqual(ctx.exception.reason, "out of scope host")

    async def test_get_of_another_users_step_is_not_found(self):
        step = await self.open()
        await self.post("/loop/steps/wait", self.body(wait_seconds=1))
        resp = await self.post(f"/loop/steps/{step.id}/get", self.body(user_id="u2"))
        self.assertEqual((resp.status_code, resp.json()["code"]), (404, "not_found"))

    async def test_dedup_and_full_delivery(self):
        first = await self.open("a")
        await self.post("/loop/steps/wait", self.body(wait_seconds=1))
        await self.post(f"/loop/steps/{first.id}/answer", self.body(answer="{}"))
        await self.open("b")
        dedup = (await self.post("/loop/steps/wait", self.body(wait_seconds=1))).json()["step"]
        self.assertIn("[[part", dedup["prompt"])
        self.broker._steps[dedup["stepId"]].state = "open"
        full = (await self.post("/loop/steps/wait",
                                self.body(wait_seconds=1, delivery="full"))).json()["step"]
        self.assertNotIn("[[part", full["prompt"])
        self.assertIn(TIER.strip()[:50], full["prompt"])

    async def test_no_step_answers_sessions_and_a_hint(self):
        resp = await self.post("/loop/steps/wait", self.body(wait_seconds=1))
        data = resp.json()
        self.assertIsNone(data["step"])
        self.assertEqual(data["sessions"][0]["sessionId"], "session_ab")
        self.assertIn("preparing the next step", data["hint"])

    async def test_stats_are_counts_only(self):
        step = await self.open()
        resp = await self.client.get("/loop/stats", headers=HEADERS)
        self.assertEqual(resp.json(), {"open_steps": 1, "claimed_steps": 0,
                                       "waiting_sessions": 1, "drivers_seen_5m": 0})
        self.assertNotIn(step.id, resp.text)


class Hints(unittest.TestCase):
    def test_hints(self):
        s = lambda state, **d: [{"state": state, "detail": d}]
        self.assertIn("No RedAmon chat", hint(None, []))
        self.assertIn("running execute_nmap", hint(None, s("running_tool", tool="execute_nmap")))
        self.assertIn("confirm a dangerous tool",
                      hint(None, s("awaiting_human", kind="tool_confirmation")))
        self.assertIn("keep waiting quietly", hint(None, s("awaiting_human", kind="approval")))
        self.assertIn("finished; stop", hint(None, s("finished")))
        self.assertIn("stopped", hint(None, s("stopped")))
        # A live session wins over an ended one.
        mixed = s("finished") + s("running_tool", tool="execute_curl")
        self.assertIn("execute_curl", hint(None, mixed))

    def test_a_run_ended_for_want_of_an_answer_says_how_to_resume(self):
        s = lambda state, **d: [{"state": state, "detail": d}]
        for code in ("loop_no_driver", "loop_step_not_answered"):
            with self.subTest(code=code):
                text = hint(None, s("error", code=code))
                self.assertIn("no agent answered a step in time", text)
                self.assertIn("type continue in the same RedAmon chat", text)
        other = hint(None, s("error", code="loop_step_declined"))
        self.assertIn("tell the person what the chat shows", other)

    def test_step_closed_says_the_run_may_have_given_up(self):
        from agent_in_the_loop.routes import ERRORS
        self.assertIn("RedAmon gave up on it", ERRORS["step_closed"][1])


if __name__ == "__main__":
    unittest.main()
