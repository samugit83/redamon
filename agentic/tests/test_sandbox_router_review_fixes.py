"""
The per-user sandbox router after S09's reviews (group 1, S10: T5, I10, S5, T7, I11).

Each test pins one point the reviewers raised on the router S09 committed:

  (a) current_handle() answers only the handle of this work's person and view (and
      project), never the run scope's last handle whoever it belongs to;
  (b) an explicit view is only ever the work's own view (sandbox_view()), so a person's
      own work cannot pick the act_as view an admin acting as them works in;
  (c) a task detached from the run scope (a background job created inside a run) gets
      its own lease, never the run's handle released when the run ends;
  (d) status events name the view and the lease kind (the drawer listener forwards only
      the run's own events), and a refusal is logged under the view's own key;
  (e) for_person(None or "") binds "no person" and never falls back to the run actor;
  (f) the finalizer of a dropped handle cancels its renewal on the renewal's own loop,
      whichever thread collects the handle;
  (g) one mode rule: an answer outside the contract (a 5xx, a 401, a code-less 404, any
      4xx without a contract code) is an outage and keeps the last mode answered (the
      default before any), while a 403 refusing the person proves per-user mode;
  (h) the job map records the view: job_sandbox(job_id) -> (person, view).

Plus the gateway calls written as literal webapp URLs, which the drift test of the
middleware allowlist (webapp/src/middleware.internalCallers.test.ts) reads.

Run: ./agentic/run_tests.sh tests/test_sandbox_router_review_fixes.py
"""
import asyncio
import gc
import re
import sys
import threading
import unittest
from pathlib import Path
from unittest import mock

_TESTS_DIR = Path(__file__).resolve().parent
_AGENTIC_DIR = _TESTS_DIR.parent
for _p in (str(_AGENTIC_DIR), str(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import sandbox_contract as contract  # noqa: E402
import sandbox_router as router  # noqa: E402
from decision_check import current_run_actor  # noqa: E402
from sandbox_router import SandboxUnavailable  # noqa: E402
from test_sandbox_router import RouterTest, _connect_refused  # noqa: E402


class _Settle(RouterTest):
    async def _until(self, predicate, timeout=2.0):
        deadline = asyncio.get_running_loop().time() + timeout
        while not predicate():
            if asyncio.get_running_loop().time() > deadline:
                self.fail("condition not reached")
            await asyncio.sleep(0.005)


# =============================================================================
# (a) current_handle
# =============================================================================

class TestCurrentHandleIsTheWorksOwn(RouterTest):

    async def test_another_person_in_the_scope_never_gets_the_run_handle(self):
        self.actor("bob", "alice")
        async with router.run_scope("sess-a"):
            bob = await router.acquire("bob", project_id="p1", kind="run")
            self.assertIs(router.current_handle(), bob)
            with router.for_person("carol"):
                self.assertIsNone(router.current_handle(), "carol's work saw bob's handle")
            with router.for_person("bob", acting=True):
                self.assertIsNone(router.current_handle(), "act-as work saw the own view's handle")

    async def test_the_project_narrows_it(self):
        self.actor("bob", "alice")
        async with router.run_scope("sess-a"):
            bob = await router.acquire("bob", project_id="p1", kind="run")
            self.assertIs(router.current_handle("p1"), bob)
            self.assertIsNone(router.current_handle("p2"))

    async def test_no_person_has_no_handle(self):
        async with router.run_scope("sess-a"):
            await router.acquire("bob", project_id="p1", kind="run")
            self.assertIsNone(router.current_handle())


# =============================================================================
# (b) the explicit view
# =============================================================================

class TestExplicitViewIsTheWorksOwn(RouterTest):

    async def test_own_work_cannot_ask_for_the_act_as_view(self):
        self.actor("bob", "alice")
        with self.assertRaises(SandboxUnavailable) as ctx:
            await router.acquire("bob", project_id="p1", kind="run", view="act_as")
        self.assertEqual(ctx.exception.reason, "refused")
        with router.for_person("bob"):
            with self.assertRaises(SandboxUnavailable):
                await router.acquire("bob", project_id="p1", kind="exec", view="act_as")
        self.assertEqual(self.gateway.ensures(), [])

    async def test_the_works_own_view_may_be_named(self):
        with router.for_person("bob", acting=True):
            handle = await router.acquire("bob", project_id="p1", kind="hold", view="act_as")
        self.assertEqual(handle.view, contract.VIEW_ACT_AS)
        await router.release(handle)
        with router.for_person("bob"):
            handle = await router.acquire("bob", project_id="p1", kind="hold", view="own")
        self.assertEqual(handle.view, contract.VIEW_OWN)
        await router.release(handle)


# =============================================================================
# (c) a task detached from the run scope
# =============================================================================

class TestDetachedFromTheRun(RouterTest):

    async def test_a_detached_task_gets_its_own_lease(self):
        self.actor("bob", "alice")
        async with router.run_scope("sess-j"):
            run = await router.acquire("bob", project_id="p1", kind="run")

            async def job():
                with router.detach_run_scope():
                    self.assertIsNone(router.current_handle())
                    own = await router.acquire("bob", project_id="p1", kind="run")
                    self.assertIsNot(own, run)
                    await router.release(own)
                    return own

            own = await asyncio.create_task(job())
            self.assertTrue(own.released)
            self.assertFalse(run.released, "the job's end released the run's lease")
            self.assertEqual(len(self.gateway.leases()), 2)
            self.assertEqual(len(self.gateway.releases()), 1)
        self.assertTrue(run.released)


# =============================================================================
# (d) events carry the view and the kind
# =============================================================================

class TestEventsNameViewAndKind(_Settle):

    async def test_starting_and_ready_carry_view_and_kind(self):
        self.gateway.cold.add(("bob", "act_as"))
        with router.for_person("bob", acting=True):
            handle = await router.acquire("bob", project_id="p1", kind="job")
        self.assertEqual([(e["state"], e["view"], e["kind"]) for e in self.events],
                         [("starting", "act_as", "job"), ("ready", "act_as", "job")])
        for event in self.events:
            self.assertEqual(set(event), {"user_id", "project_id", "session_id", "state", "reason",
                                          "limit", "detail", "view", "kind"})
        await router.release(handle)

    async def test_a_refusal_carries_them_and_logs_the_views_key(self):
        self.gateway.script[contract.INTERNAL_ROUTE_ENSURE] = lambda b: (403, {"code": contract.ERR_USER_REFUSED})
        with router.for_person("bob", acting=True):
            with self.assertLogs("sandbox_router", "WARNING") as logs:
                with self.assertRaises(SandboxUnavailable):
                    await router.acquire("bob", project_id="p1", kind="triage")
        self.assertEqual([(e["state"], e["view"], e["kind"]) for e in self.events],
                         [("unavailable", "act_as", "triage")])
        text = "\n".join(logs.output)
        self.assertIn(contract.sandbox_key("bob", "act_as"), text)
        self.assertNotIn(contract.sandbox_key("bob", "own"), text)

    async def test_a_view_mismatch_refusal_names_the_works_view(self):
        with router.for_person("bob", acting=True):
            with self.assertRaises(SandboxUnavailable):
                await router.acquire("bob", project_id="p1", kind="exec", view="own")
        self.assertEqual([(e["reason"], e["view"], e["kind"]) for e in self.events],
                         [("refused", "act_as", "exec")])

    async def test_a_lost_renewal_carries_them(self):
        with mock.patch.object(router, "LEASE_RENEW_S", 0.01):
            with router.for_person("bob", acting=True):
                handle = await router.acquire("bob", project_id="p1", kind="tradecraft")
            self.gateway.lease_answer = (409, {"code": contract.ERR_NOT_RUNNING})
            await self._until(lambda: any(e["state"] == "unavailable" for e in self.events))
        event = [e for e in self.events if e["state"] == "unavailable"][-1]
        self.assertEqual((event["reason"], event["view"], event["kind"]), ("stopped", "act_as", "tradecraft"))
        await router.release(handle)

    async def test_no_user_stays_silent(self):
        with self.assertRaises(SandboxUnavailable):
            await router.acquire("", project_id="p1", kind="run")
        self.assertEqual(self.events, [])


# =============================================================================
# (e) for_person(None)
# =============================================================================

class TestForNobody(RouterTest):

    async def test_for_person_none_never_falls_back_to_the_run_actor(self):
        self.actor("bob", "alice")
        for nobody in (None, "", 42):
            with self.subTest(nobody=nobody):
                with router.for_person(nobody):
                    self.assertEqual(router.sandbox_user(), "")
                    with self.assertRaises(SandboxUnavailable) as ctx:
                        await router.acquire(router.sandbox_user(), project_id="p1", kind="exec")
                    self.assertEqual(ctx.exception.reason, "no_user")
                self.assertEqual(router.sandbox_user(), "bob")
        self.assertEqual(self.gateway.ensures(), [])

    async def test_unbound_falls_back_to_the_run_actor(self):
        self.assertEqual(router.sandbox_user(), "")
        self.actor("bob", "alice")
        self.assertEqual(router.sandbox_user(), "bob")


# =============================================================================
# (f) the finalizer
# =============================================================================

class TestFinalizerOnTheLoopThread(RouterTest):

    async def test_a_handle_collected_on_another_thread_cancels_on_the_loop(self):
        seen = []
        original = router._cancel_quietly

        def spy(task):
            seen.append(threading.get_ident())
            return original(task)

        loop_thread = threading.get_ident()
        with mock.patch.object(router, "_cancel_quietly", spy):
            handle = await router.acquire("bob", project_id="p1", kind="exec")
            task = handle._renew_task
            holder = [handle]
            del handle
            worker = threading.Thread(target=holder.clear)
            worker.start()
            worker.join()
            gc.collect()
            for _ in range(20):
                await asyncio.sleep(0)
                if task.done():
                    break
        self.assertTrue(seen, "the finalizer never ran")
        self.assertEqual(set(seen), {loop_thread}, "the renewal was cancelled off its loop's thread")
        self.assertTrue(task.cancelled() or task.done())


# =============================================================================
# (g) one mode rule (the driver's ruling on S10's reviews)
# =============================================================================

NOT_CONTRACT = {
    "code-less 404": (404, {}),
    "401": (401, {"error": "Unauthorized"}),
    "403 without a sandbox code": (403, {"error": "Forbidden"}),
    "400 without a code": (400, {"error": "bad"}),
    "503 orchestrator_unavailable": (503, {"code": "orchestrator_unavailable"}),
}


class TestOneModeRuleShared(RouterTest):
    mode = contract.MODE_SHARED

    async def test_an_answer_outside_the_contract_keeps_shared(self):
        for name, answer in NOT_CONTRACT.items():
            with self.subTest(answer=name):
                self.gateway.script[contract.INTERNAL_ROUTE_ENSURE] = lambda b, a=answer: a
                handle = await router.acquire("bob", project_id="p1", kind="run")
                self.assertEqual(handle.mode, contract.MODE_SHARED)
                self.assertEqual(router.current_mode(), contract.MODE_SHARED)


class TestOneModeRulePerUser(RouterTest):
    mode = contract.MODE_PER_USER

    async def test_an_answer_outside_the_contract_fails_closed(self):
        for name, answer in NOT_CONTRACT.items():
            with self.subTest(answer=name):
                self.gateway.script[contract.INTERNAL_ROUTE_ENSURE] = lambda b, a=answer: a
                with self.assertRaises(SandboxUnavailable) as ctx:
                    await router.acquire("bob", project_id="p1", kind="run")
                self.assertEqual(ctx.exception.reason, "error")


class TestOneModeRuleNoAnswerYet(RouterTest):
    mode = None

    async def test_a_refusal_proves_per_user_so_a_later_outage_fails_closed(self):
        self.gateway.script[contract.INTERNAL_ROUTE_ENSURE] = lambda b: (403, {"code": contract.ERR_USER_REFUSED})
        with self.assertRaises(SandboxUnavailable) as ctx:
            await router.acquire("bob", project_id="p1", kind="run")
        self.assertEqual(ctx.exception.reason, "refused")
        self.assertEqual(router.current_mode(), contract.MODE_PER_USER)
        self.gateway.script[contract.INTERNAL_ROUTE_ENSURE] = lambda b: (503, {})
        with self.assertRaises(SandboxUnavailable) as ctx:
            await router.acquire("bob", project_id="p1", kind="run")
        self.assertEqual(ctx.exception.reason, "error", "an outage after a per-user refusal went shared")

    # The default is per_user, so an outage before any answer fails closed: never a
    # handle on the shared container, which no answer named.

    async def test_an_answer_outside_the_contract_takes_the_default_before_any_answer(self):
        self.gateway.script[contract.INTERNAL_ROUTE_ENSURE] = lambda b: (404, {})
        with self.assertRaises(SandboxUnavailable) as ctx:
            await router.acquire("bob", project_id="p1", kind="run")
        self.assertEqual(ctx.exception.reason, "error")
        self.assertEqual(router.current_mode(), contract.MODE_PER_USER)

    async def test_a_real_outage_keeps_the_default(self):
        self.gateway.raises = _connect_refused
        with self.assertRaises(SandboxUnavailable) as ctx:
            await router.acquire("bob", project_id="p1", kind="run")
        self.assertEqual(ctx.exception.reason, "error")
        self.assertEqual(router.current_mode(), contract.MODE_PER_USER)


# =============================================================================
# (h) the job map's view
# =============================================================================

class TestJobMapView(RouterTest):

    async def test_job_sandbox_names_person_and_view(self):
        self.assertTrue(router.note_job("job-1", "bob", view="act_as"))
        self.assertEqual(router.job_sandbox("job-1"), ("bob", "act_as"))
        with router.for_person("carol", acting=True):
            self.assertTrue(router.note_job("job-2", "carol"))
        self.assertEqual(router.job_sandbox("job-2"), ("carol", "act_as"))
        self.assertTrue(router.note_job("job-3", "dave"))
        self.assertEqual(router.job_sandbox("job-3"), ("dave", "own"))
        self.assertFalse(router.note_job("job-4", "erin", view="admin"))
        self.assertEqual(router.job_sandbox("job-4"), ("", ""))
        self.assertEqual(router.job_sandbox("nope"), ("", ""))
        self.assertEqual(router.job_sandbox_user("job-1"), "bob")


# =============================================================================
# The gateway calls as literal webapp URLs
# =============================================================================

class GatewayUrlsAreLiteral(unittest.TestCase):
    """Each gateway call is an f-string `{WEBAPP_API_URL}/api/...` equal to its contract
    route, so the middleware drift test sees it and checks it is on the allowlist."""

    def test_every_route_is_written_out_and_equals_the_contract(self):
        source = (_AGENTIC_DIR / "sandbox_router.py").read_text()
        found = re.findall(r'f"\{WEBAPP_API_URL\}(/api/[^"{]*)"', source)
        expected = {contract.INTERNAL_ROUTE_ENSURE, contract.INTERNAL_ROUTE_LEASE,
                    contract.INTERNAL_ROUTE_RELEASE, contract.INTERNAL_ROUTE_LIST}
        self.assertEqual(set(found), expected)


if __name__ == "__main__":
    unittest.main()
