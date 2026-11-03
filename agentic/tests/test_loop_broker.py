"""The Agent in the Loop step broker: claims, leases, deadlines, filters, pruning.

The clock is injected; real waits are kept to a few hundredths of a second.
"""
from __future__ import annotations

import asyncio
import unittest

from langchain_core.messages import HumanMessage, SystemMessage

from agent_in_the_loop import LoopSettings
from agent_in_the_loop.broker import (
    DEDUP_REFRESH_STEPS, ENDED_STATUS_KEEP_S, MAX_DEDUP_SETS_PER_DRIVER, StepBroker, session_key,
)
from agent_in_the_loop.errors import (
    LoopCapReached, LoopNoDriver, LoopStepDeclined, LoopStepNotAnswered,
)
from agent_in_the_loop.prompt_doc import to_parts

TIER = "eternal tier " * 100


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def cfg(**over):
    base = dict(step_deadline_s=900, lease_s=90, wait_max_s=55, page_chars=40000,
                answer_max_chars=1000, max_open_steps_per_user=4, no_driver_grace_s=300,
                driver_seen_s=60, state_ttl_s=3600)
    base.update(over)
    return LoopSettings(**base)


class Recorder:
    def __init__(self):
        self.payloads = []

    async def on_loop_status(self, payload):
        self.payloads.append(payload)


class BrokerCase(unittest.IsolatedAsyncioTestCase):
    def make(self, **over):
        self.clock = Clock()
        self.broker = StepBroker(now=self.clock, config=cfg(**over), poll_s=0.01)
        return self.broker

    async def asyncSetUp(self):
        self.make()

    async def scope(self, user="u1", project="p1", session="s1", uses_loop=True, callback=None):
        cm = self.broker.run_scope(user, project, session, callback, uses_loop=uses_loop)
        scope = await cm.__aenter__()
        self.addAsyncCleanup(cm.__aexit__, None, None, None)
        return scope

    async def open(self, scope, purpose="think", text="decide", **meta):
        msgs = to_parts([SystemMessage(content=[{"type": "text", "text": TIER},
                                                {"type": "text", "text": text}]),
                         HumanMessage(content=f"{text}: output one JSON object")])
        step = self.broker.new_step(scope, purpose=purpose, meta=meta, messages=msgs,
                                    answer_format="json", last_instruction=text)
        await self.broker.open_step(step, scope)
        return step

    def awaiting(self, step):
        return asyncio.create_task(self.broker.await_answer(step))

    async def wait(self, user="u1", projects=("p1",), session=None, token="t1", driver="cc-a",
                   timeout=0.05):
        return await self.broker.wait_next(user, list(projects), session, token, driver, timeout)


class WaitAndAnswer(BrokerCase):
    async def test_open_then_wait_returns_it(self):
        scope = await self.scope()
        step = await self.open(scope)
        got = await self.wait()
        self.assertEqual(got["step"]["stepId"], step.id)
        self.assertEqual(got["step"]["contractVersion"], 1)
        self.assertEqual(got["step"]["answerFormat"], "json")
        self.assertEqual(step.state, "claimed")
        self.assertEqual(step.claimed_by, "t1:cc-a")

    async def test_wait_started_first_returns_when_a_step_opens(self):
        scope = await self.scope()
        waiter = asyncio.create_task(self.wait(timeout=2))
        await asyncio.sleep(0.01)
        step = await self.open(scope)
        got = await asyncio.wait_for(waiter, 1)
        self.assertEqual(got["step"]["stepId"], step.id)

    async def test_wait_without_a_step_lists_the_sessions(self):
        await self.scope()
        got = await self.wait()
        self.assertIsNone(got["step"])
        self.assertEqual([s["sessionId"] for s in got["sessions"]], ["s1"])
        self.assertEqual(got["sessions"][0]["state"], "thinking")

    async def test_answer_resolves_the_future_once(self):
        scope = await self.scope()
        step = await self.open(scope, iteration=4)
        task = self.awaiting(step)
        await self.wait()
        res = await self.broker.answer("u1", ["p1"], step.id, text='{"action":"complete"}',
                                       answered_by={"token_prefix": "rdm_ab", "token_name": "laptop"})
        self.assertEqual(res, {"ok": True, "projectId": "p1", "sessionId": "s1",
                               "purpose": "think", "iteration": 4})
        self.assertEqual(await task, '{"action":"complete"}')
        self.assertEqual(step.answered_by["token_name"], "laptop")
        again = await self.broker.answer("u1", ["p1"], step.id, text="x")
        self.assertEqual(again, {"ok": False, "code": "step_closed"})
        self.assertNotIn(step.id, self.broker._steps)

    async def test_an_unclaimed_step_may_still_be_answered(self):
        scope = await self.scope()
        step = await self.open(scope)
        task = self.awaiting(step)
        self.assertTrue((await self.broker.answer("u1", ["p1"], step.id, text="ok"))["ok"])
        self.assertEqual(await task, "ok")

    async def test_no_oracle_for_unknown_foreign_or_outside_project(self):
        scope = await self.scope()
        step = await self.open(scope)
        self.awaiting(step)
        for user, projects, sid in (("u2", ["p1"], step.id), ("u1", ["p9"], step.id),
                                    ("u1", ["p1"], "0" * 32)):
            res = await self.broker.answer(user, projects, sid, text="x")
            self.assertEqual(res, {"ok": False, "code": "step_closed"})

    async def test_oversized_answer(self):
        scope = await self.scope()
        step = await self.open(scope)
        self.awaiting(step)
        res = await self.broker.answer("u1", ["p1"], step.id, text="x" * 1001)
        self.assertEqual(res, {"ok": False, "code": "answer_too_large"})
        self.assertEqual(step.state, "open")

    async def test_decline_raises_with_the_sanitized_reason(self):
        rec = Recorder()
        scope = await self.scope(callback=rec)
        step = await self.open(scope)
        task = self.awaiting(step)
        await self.broker.answer("u1", ["p1"], step.id, declined=True, reason="no\nthanks")
        with self.assertRaises(LoopStepDeclined) as ctx:
            await task
        self.assertEqual(ctx.exception.reason, "no thanks")
        await asyncio.sleep(0)
        self.assertEqual(rec.payloads[-1]["state"], "error")
        self.assertEqual(rec.payloads[-1]["detail"]["code"], "loop_step_declined")

    async def test_fifo_across_sessions_and_user_isolation(self):
        a = await self.scope(session="s1")
        b = await self.scope(session="s2")
        first = await self.open(a)
        self.clock.t += 1
        second = await self.open(b)
        self.assertIsNone((await self.wait(user="u2"))["step"])
        self.assertEqual((await self.wait())["step"]["stepId"], first.id)
        self.assertEqual((await self.wait())["step"]["stepId"], second.id)
        self.assertEqual((await self.wait(user="u2"))["sessions"], [])

    async def test_session_filter(self):
        a = await self.scope(session="s1")
        b = await self.scope(session="s2")
        await self.open(a)
        self.clock.t += 1
        later = await self.open(b)
        got = await self.wait(session="s2")
        self.assertEqual(got["step"]["stepId"], later.id)
        self.assertEqual([s["sessionId"] for s in got["sessions"]], ["s2"])

    async def test_project_filter_hides_steps_and_sessions(self):
        scope = await self.scope(project="p1")
        step = await self.open(scope)
        got = await self.wait(projects=("p2",))
        self.assertIsNone(got["step"])
        self.assertEqual(got["sessions"], [])
        self.assertIsNone(self.broker.get("u1", ["p2"], step.id, "t1", "cc-a", 0, False))


class Leases(BrokerCase):
    async def test_lease_expiry_redelivers_to_another_driver(self):
        scope = await self.scope()
        step = await self.open(scope)
        await self.wait(driver="cc-a")
        self.assertIsNone((await self.wait(driver="cc-b"))["step"])
        self.clock.t += 91
        got = await self.wait(driver="cc-b")
        self.assertEqual(got["step"]["stepId"], step.id)
        self.assertEqual(step.claimed_by, "t1:cc-b")

    async def test_get_renews_the_lease_and_refuses_another_driver(self):
        scope = await self.scope()
        step = await self.open(scope)
        await self.wait(driver="cc-a")
        self.clock.t += 80
        view = self.broker.get("u1", ["p1"], step.id, "t1", "cc-a", 0, False)
        self.assertEqual(view["leaseExpiresInSeconds"], 90)
        self.assertIsNone(self.broker.get("u1", ["p1"], step.id, "t1", "cc-b", 0, False))
        self.assertIsNone(self.broker.get("u2", ["p1"], step.id, "t1", "cc-a", 0, False))


class Deadlines(BrokerCase):
    async def test_deadline(self):
        scope = await self.scope()
        step = await self.open(scope)
        await self.wait()   # claimed, so the no-driver rule does not apply
        task = self.awaiting(step)
        self.clock.t += 901
        with self.assertRaises(LoopStepNotAnswered):
            await asyncio.wait_for(task, 1)
        self.assertEqual(step.state, "expired")
        self.assertNotIn(step.id, self.broker._steps)
        late = await self.broker.answer("u1", ["p1"], step.id, text="late")
        self.assertEqual(late["code"], "step_closed")

    async def test_no_driver_ends_the_step_after_the_grace(self):
        scope = await self.scope()
        step = await self.open(scope)
        task = self.awaiting(step)
        self.clock.t += 299
        await asyncio.sleep(0.03)
        self.assertFalse(task.done())
        self.clock.t += 2
        with self.assertRaises(LoopNoDriver):
            await asyncio.wait_for(task, 1)

    async def test_a_driver_call_restarts_the_grace(self):
        scope = await self.scope()
        step = await self.open(scope)
        task = self.awaiting(step)
        self.clock.t += 250
        await self.wait()                           # claims it: lease until +340
        self.clock.t += 250                         # lease expired, nobody came back
        await asyncio.sleep(0.03)
        self.assertFalse(task.done())               # grace counts from the call
        self.clock.t += 60
        with self.assertRaises(LoopNoDriver):
            await asyncio.wait_for(task, 1)

    async def test_a_claim_whose_driver_vanished_hits_the_no_driver_rule(self):
        # The lease runs out and no driver call ever turns the step back to open.
        scope = await self.scope()
        step = await self.open(scope)
        await self.wait()
        task = self.awaiting(step)
        self.clock.t += 301
        with self.assertRaises(LoopNoDriver):
            await asyncio.wait_for(task, 1)

    async def test_a_live_lease_never_hits_the_no_driver_rule(self):
        scope = await self.scope()
        step = await self.open(scope)
        await self.wait()
        task = self.awaiting(step)
        self.clock.t += 80          # lease still live (90 s); grace counts from the call
        await asyncio.sleep(0.03)
        self.assertFalse(task.done())
        await self.broker.answer("u1", ["p1"], step.id, text="ok")
        self.assertEqual(await task, "ok")

    async def test_after_a_lost_driver_the_next_step_fails_at_once(self):
        scope = await self.scope()
        step = await self.open(scope)
        task = self.awaiting(step)
        self.clock.t += 301
        with self.assertRaises(LoopNoDriver):
            await asyncio.wait_for(task, 1)
        loop = asyncio.get_running_loop()
        start = loop.time()
        with self.assertRaises(LoopNoDriver):
            await self.open(scope, purpose="report")
        self.assertLess(loop.time() - start, 0.1)
        self.assertIsNone((await self.wait())["step"])
        # A new run scope starts clean.
        fresh = await self.scope(session="s2")
        await self.open(fresh)

    async def test_cancel_marks_cancelled_and_a_late_answer_is_closed(self):
        scope = await self.scope()
        step = await self.open(scope)
        task = self.awaiting(step)
        await self.wait()
        await asyncio.sleep(0)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(step.state, "cancelled")
        self.assertEqual((await self.broker.answer("u1", ["p1"], step.id, text="x"))["code"],
                         "step_closed")

    async def test_cap(self):
        scope = await self.scope()
        for _ in range(4):
            await self.open(scope)
        with self.assertRaises(LoopCapReached):
            await self.open(scope)

    async def test_three_concurrent_steps_answered_in_reverse(self):
        scope = await self.scope()
        steps = [await self.open(scope, purpose="fireteam_member", member_id=f"m{i}") for i in range(3)]
        tasks = [self.awaiting(s) for s in steps]
        for s in reversed(steps):
            await self.broker.answer("u1", ["p1"], s.id, text=s.meta["member_id"])
        self.assertEqual(await asyncio.gather(*tasks), ["m0", "m1", "m2"])


class Scopes(BrokerCase):
    async def run_and_exit(self, final_state=None, exc=None):
        rec = Recorder()
        cm = self.broker.run_scope("u1", "p1", "s1", rec, uses_loop=True)
        scope = await cm.__aenter__()
        left = await self.open(scope)
        scope.final_state = final_state
        if exc is None:
            await cm.__aexit__(None, None, None)
        else:
            with self.assertRaises(type(exc)):
                try:
                    raise exc
                except BaseException as e:
                    if not await cm.__aexit__(type(e), e, e.__traceback__):
                        raise
        await asyncio.sleep(0)
        return rec, left

    async def test_exit_states(self):
        cases = [
            ({"awaiting_tool_confirmation": True}, None, "awaiting_human", "tool_confirmation"),
            ({"awaiting_user_approval": True}, None, "awaiting_human", "approval"),
            ({"awaiting_user_question": True}, None, "awaiting_human", "question"),
            ({"task_complete": True}, None, "finished", None),
            (None, asyncio.CancelledError(), "stopped", None),
            (None, RuntimeError("x"), "error", None),
        ]
        for final, exc, state, kind in cases:
            with self.subTest(state=state, kind=kind):
                self.make()
                rec, left = await self.run_and_exit(final, exc)
                last = rec.payloads[-1]
                self.assertEqual(last["state"], state)
                self.assertEqual(last["detail"].get("kind"), kind)
                self.assertEqual(left.state, "cancelled")
                self.assertTrue(left.answer.cancelled())
                self.assertIsNone(self.broker.scope_for_session("s1"))

    async def test_status_payload_carries_no_text(self):
        rec = Recorder()
        scope = await self.scope(callback=rec)
        step = await self.open(scope, text="SECRET-PROMPT-TEXT", iteration=2)
        await self.wait()
        await self.broker.answer("u1", ["p1"], step.id, text="SECRET-ANSWER")
        await asyncio.sleep(0)
        self.assertTrue(rec.payloads)
        for payload in rec.payloads:
            self.assertNotIn("SECRET", repr(payload))
        claimed = [p for p in rec.payloads if p.get("step", {}).get("state") == "claimed"]
        self.assertEqual(claimed[0]["step"], {"stepId": step.id, "state": "claimed",
                                              "purpose": "think", "iteration": 2})
        self.assertEqual(set(rec.payloads[0]), {"state", "detail", "driver", "openSteps", "sinceSeconds"})

    async def test_scope_for_session(self):
        self.assertIsNone(self.broker.scope_for_session("s1"))
        scope = await self.scope()
        self.assertIs(self.broker.scope_for_session("s1"), scope)
        self.assertIsNone(self.broker.scope_for_session(""))

    async def test_scope_for_session_refuses_a_provider_scope_and_duplicates(self):
        await self.scope(session="prov", uses_loop=False)
        self.assertIsNone(self.broker.scope_for_session("prov"))
        await self.scope(user="u1", project="p1", session="dup")
        await self.scope(user="u2", project="p2", session="dup")
        self.assertIsNone(self.broker.scope_for_session("dup"))

    async def test_note_is_a_no_op_for_a_provider_run(self):
        rec = Recorder()
        await self.scope(session="prov", uses_loop=False, callback=rec)
        self.broker.note(session_key("u1", "p1", "prov"), "running_tool", tool="execute_nmap")
        await asyncio.sleep(0)
        self.assertEqual(rec.payloads, [])
        self.assertIsNone(self.broker.status_payload(session_key("u1", "p1", "prov")))

    async def test_note_emits_for_a_loop_run(self):
        rec = Recorder()
        await self.scope(callback=rec)
        self.broker.note(session_key("u1", "p1", "s1"), "running_tool", tool="execute_nmap")
        await asyncio.sleep(0)
        self.assertEqual(rec.payloads[-1]["state"], "running_tool")
        self.assertEqual(rec.payloads[-1]["detail"], {"tool": "execute_nmap"})
        self.assertEqual(self.broker.live_loop_state(session_key("u1", "p1", "s1")), "running_tool")

    async def test_a_decline_keeps_the_final_status_an_error(self):
        rec = Recorder()
        cm = self.broker.run_scope("u1", "p1", "s1", rec, uses_loop=True)
        scope = await cm.__aenter__()
        step = await self.open(scope)
        task = self.awaiting(step)
        await self.broker.answer("u1", ["p1"], step.id, declined=True, reason="no")
        with self.assertRaises(LoopStepDeclined):
            await task
        report = await self.open(scope, purpose="report")
        rtask = self.awaiting(report)
        await self.broker.answer("u1", ["p1"], report.id, text="# report")
        await rtask
        scope.final_state = {"task_complete": True}
        await cm.__aexit__(None, None, None)
        await asyncio.sleep(0)
        self.assertEqual(rec.payloads[-1]["state"], "error")
        self.assertEqual(rec.payloads[-1]["detail"]["code"], "loop_step_declined")

    async def test_driver_connected_flip_emits(self):
        rec = Recorder()
        scope = await self.scope(callback=rec)
        step = await self.open(scope)
        self.awaiting(step)
        await asyncio.sleep(0.02)
        self.assertFalse(rec.payloads[-1]["driver"]["connected"])
        await self.wait()
        await asyncio.sleep(0)
        self.assertTrue(rec.payloads[-1]["driver"]["connected"])
        self.clock.t += 91                          # past the lease and LOOP_DRIVER_SEEN_S
        await asyncio.sleep(0.03)
        self.assertFalse(rec.payloads[-1]["driver"]["connected"])
        self.assertEqual(rec.payloads[-1]["driver"]["lastSeenSeconds"], 91)


class Dedup(BrokerCase):
    async def test_second_step_gets_placeholders_for_the_same_driver_only(self):
        scope = await self.scope()
        first = await self.open(scope, text="iteration 1")
        await self.wait(driver="cc-a")
        await self.broker.answer("u1", ["p1"], first.id, text="{}", token_id="t1", driver_name="cc-a")
        second = await self.open(scope, text="iteration 2")
        got = await self.wait(driver="cc-a")
        self.assertEqual(got["step"]["stepId"], second.id)
        self.assertIn("[[part", got["step"]["prompt"])
        self.assertNotIn(TIER, got["step"]["prompt"])
        full = self.broker.get("u1", ["p1"], second.id, "t1", "cc-a", 0, True)
        self.assertIn(TIER, full["prompt"])
        # Another window on the same token has its own state.
        self.broker._steps[second.id].state = "open"
        other = await self.wait(driver="cc-b")
        self.assertIn(TIER, other["step"]["prompt"])

    async def test_no_driver_name_means_no_placeholders(self):
        scope = await self.scope()
        for i in range(2):
            step = await self.open(scope, text=f"iteration {i}")
            got = await self.wait(driver=None)
            self.assertIn(TIER, got["step"]["prompt"])
            await self.broker.answer("u1", ["p1"], step.id, text="{}")
        self.assertEqual(self.broker.delivered_shas("s1", "t1", None), set())

    async def test_paging_through_get(self):
        self.make(page_chars=4000)
        scope = await self.scope()
        step = await self.open(scope, text="x" * 9000)
        got = await self.wait()
        page = got["step"]["page"]
        self.assertEqual(page["cursor"], 0)
        self.assertIsNotNone(page["nextCursor"])
        text, cursor = got["step"]["prompt"], page["nextCursor"]
        while cursor is not None:
            view = self.broker.get("u1", ["p1"], step.id, "t1", "cc-a", cursor, False)
            text += view["prompt"]
            cursor = view["page"]["nextCursor"]
        self.assertEqual(len(text), page["totalChars"])



class StableRendering(BrokerCase):
    """A cursor is an offset into one rendering: pages must always line up."""

    async def big_step(self, scope, text):
        return await self.open(scope, text=text)

    def read(self, step_id, cursor, full=False, driver="cc-a"):
        return self.broker.get("u1", ["p1"], step_id, "t1", driver, cursor, full)

    async def seeded(self):
        # A first step delivers the tier; the second, read by pages, would dedup it.
        self.make(page_chars=1500)
        scope = await self.scope()
        first = await self.open(scope, text="iteration 1")
        got = await self.wait()
        cursor = got["step"]["page"]["nextCursor"]
        while cursor is not None:
            cursor = self.read(first.id, cursor)["page"]["nextCursor"]
        await self.broker.answer("u1", ["p1"], first.id, text="{}", token_id="t1", driver_name="cc-a")
        second = await self.open(scope, text="iteration 2 " + "y" * 3000)
        return second

    async def test_a_lease_lost_between_pages_keeps_the_same_document(self):
        # The tier (1300 chars) ends inside page 1: once delivered, a re-render
        # would turn it into a placeholder and shift every later cursor.
        self.make(page_chars=1500)
        scope = await self.scope()
        second = await self.open(scope, text="iteration 2 " + "y" * 3000)
        got = await self.wait()
        text, total = got["step"]["prompt"], got["step"]["page"]["totalChars"]
        self.clock.t += 91                      # e.g. the person approving a tool call
        cursor = got["step"]["page"]["nextCursor"]
        while cursor is not None:
            view = self.read(second.id, cursor)
            self.assertEqual(view["page"]["totalChars"], total)
            text += view["prompt"]
            cursor = view["page"]["nextCursor"]
        self.assertEqual(len(text), total)
        self.assertTrue(text.endswith("y" * 3000 + ": output one JSON object"))

    async def test_full_from_the_start_then_plain_pages_stay_in_the_full_document(self):
        second = await self.seeded()
        await self.wait()
        view = self.read(second.id, 0, full=True)
        text, total = view["prompt"], view["page"]["totalChars"]
        self.assertIn(TIER, text)
        cursor = view["page"]["nextCursor"]
        while cursor is not None:               # the client omits full on later pages
            view = self.read(second.id, cursor)
            self.assertEqual(view["page"]["totalChars"], total)
            text += view["prompt"]
            cursor = view["page"]["nextCursor"]
        self.assertEqual(len(text), total)
        self.assertNotIn("[[part", text)

    async def test_full_asked_mid_document_keeps_the_rendering_the_cursor_came_from(self):
        second = await self.seeded()
        got = await self.wait()
        text, total = got["step"]["prompt"], got["step"]["page"]["totalChars"]
        cursor = got["step"]["page"]["nextCursor"]
        while cursor is not None:
            view = self.read(second.id, cursor, full=True)
            self.assertEqual(view["page"]["totalChars"], total)
            text += view["prompt"]
            cursor = view["page"]["nextCursor"]
        self.assertEqual(len(text), total)


class DeliveryProof(BrokerCase):
    """A part counts as delivered only once the client proves it received it."""

    async def test_a_page_never_followed_by_a_request_or_answer_is_not_delivered(self):
        scope = await self.scope()
        first = await self.open(scope, text="iteration 1")
        await self.wait()                       # served; the response may have been lost
        self.assertEqual(self.broker.delivered_shas("s1", "t1", "cc-a"), set())
        self.broker._steps[first.id].lease_until = 0
        again = await self.wait()               # re-offered after the lease
        self.assertIn(TIER, again["step"]["prompt"])

    async def test_asking_for_the_next_page_proves_the_previous_one(self):
        self.make(page_chars=1500)
        scope = await self.scope()
        step = await self.open(scope, text="iteration 1 " + "z" * 2000)
        got = await self.wait()
        self.assertIsNotNone(got["step"]["page"]["nextCursor"])
        self.assertEqual(self.broker.delivered_shas("s1", "t1", "cc-a"), set())
        self.broker.get("u1", ["p1"], step.id, "t1", "cc-a", got["step"]["page"]["nextCursor"], False)
        self.assertTrue(self.broker.delivered_shas("s1", "t1", "cc-a"))

    async def test_parts_are_sent_in_full_again_after_the_refresh_window(self):
        scope = await self.scope()
        seen_full = []
        for i in range(DEDUP_REFRESH_STEPS + 1):
            step = await self.open(scope, text=f"iteration {i}")
            got = await self.wait()
            seen_full.append(TIER in got["step"]["prompt"])
            await self.broker.answer("u1", ["p1"], step.id, text="{}", token_id="t1", driver_name="cc-a")
        self.assertEqual(seen_full, [True] + [False] * (DEDUP_REFRESH_STEPS - 1) + [True])


class PresencePerSession(BrokerCase):
    """A driver scoped to one chat is no presence for the user's other chats."""

    async def test_a_scoped_driver_leaves_the_other_chat_unserved(self):
        rec_a, rec_b = Recorder(), Recorder()
        a = await self.scope(session="sA", callback=rec_a)
        b = await self.scope(session="sB", callback=rec_b)
        step_b = await self.open(b, text="chat B")
        task_b = self.awaiting(step_b)
        step_a = await self.open(a, text="chat A")
        got = await self.wait(session="sA")
        self.assertEqual(got["step"]["stepId"], step_a.id)
        await asyncio.sleep(0.02)
        self.assertTrue(rec_a.payloads[-1]["driver"]["connected"])
        self.assertFalse(rec_b.payloads[-1]["driver"]["connected"])
        for _ in range(6):                      # the driver keeps polling chat A only
            self.clock.t += 55
            await self.wait(session="sA")
        with self.assertRaises(LoopNoDriver):
            await asyncio.wait_for(task_b, 1)

    async def test_an_unscoped_driver_is_presence_for_every_chat_it_can_serve(self):
        rec_a, rec_b = Recorder(), Recorder()
        await self.scope(session="sA", callback=rec_a)
        b = await self.scope(session="sB", callback=rec_b)
        await self.open(b, text="chat B")
        await self.wait(projects=("p1",), timeout=0.01)
        await asyncio.sleep(0.02)
        self.assertTrue(rec_a.payloads[-1]["driver"]["connected"])
        self.assertTrue(rec_b.payloads[-1]["driver"]["connected"])

    async def test_a_chat_started_during_a_long_poll_counts_as_served(self):
        rec = Recorder()
        waiting = asyncio.create_task(self.wait(timeout=1.5))
        await asyncio.sleep(0.05)
        await self.scope(session="sNew", callback=rec)   # no step yet: nothing to claim
        await asyncio.sleep(1.2)                          # one wait slice later
        self.assertTrue(rec.payloads[-1]["driver"]["connected"])
        await waiting

    async def test_a_driver_of_other_projects_is_no_presence(self):
        rec = Recorder()
        scope = await self.scope(callback=rec)
        step = await self.open(scope)
        task = self.awaiting(step)
        self.clock.t += 250
        await self.wait(projects=("other",))
        self.clock.t += 51
        with self.assertRaises(LoopNoDriver):
            await asyncio.wait_for(task, 1)

class Pruning(BrokerCase):
    async def test_ended_status_and_dedup_sets_are_pruned(self):
        cm = self.broker.run_scope("u1", "p1", "s1", None, uses_loop=True)
        scope = await cm.__aenter__()
        step = await self.open(scope)
        await self.wait()
        await self.broker.answer("u1", ["p1"], step.id, text="{}")
        await cm.__aexit__(None, None, None)
        self.assertIn(session_key("u1", "p1", "s1"), self.broker._statuses)
        self.assertTrue(self.broker._delivered)
        self.clock.t += ENDED_STATUS_KEEP_S + 1
        self.broker._prune()
        self.assertEqual(self.broker._statuses, {})
        self.assertTrue(self.broker._delivered)
        self.clock.t += 3600
        self.broker._prune()
        self.assertEqual(self.broker._delivered, {})
        self.assertEqual(self.broker._last_driver_call, {})
        self.assertEqual(self.broker._driver_seen, {})

    async def test_dedup_sets_per_driver_are_lru_capped(self):
        for i in range(MAX_DEDUP_SETS_PER_DRIVER + 1):
            self.broker._delivered_set(f"s{i}", "t1", "cc-a", create=True)
        sets = self.broker._delivered[("t1", "cc-a")]
        self.assertEqual(len(sets), MAX_DEDUP_SETS_PER_DRIVER)
        self.assertNotIn("s0", sets)
        self.assertIn(f"s{MAX_DEDUP_SETS_PER_DRIVER}", sets)


class Stats(BrokerCase):
    async def test_counts_only(self):
        a = await self.scope(session="s1")
        b = await self.scope(session="s2")
        s1 = await self.open(a)
        await self.open(b)
        await self.wait()
        stats = self.broker.stats()
        self.assertEqual(stats, {"open_steps": 1, "claimed_steps": 1, "waiting_sessions": 2,
                                 "drivers_seen_5m": 1})
        self.assertNotIn(s1.id, repr(stats))


if __name__ == "__main__":
    unittest.main()
