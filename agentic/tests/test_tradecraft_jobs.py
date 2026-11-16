"""The ingestion job runner (T1.5): per-owner FIFO, two at a time, one per owner, the lease
renewed for queued and running jobs, cancel, failures as codes, parsing off the event loop.

The store is ``MemoryStore``; time moves only when a test says (``SteppedClock``); the
pipeline is a scripted entry. The same rules on Postgres: ``test_tradecraft_jobs_integration.py``.
"""

from __future__ import annotations

import asyncio
import contextvars
import json
import logging
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent_in_the_loop.errors import LoopModelNotSupportedHere  # noqa: E402
from llm_budget import LlmBudgetExhausted  # noqa: E402
from tradecraft import clock as tc_clock  # noqa: E402
from tradecraft import jobs, models  # noqa: E402
from tradecraft.contract import JobOutcome, JobProgress, JobStartBatch  # noqa: E402
from tradecraft_doubles import FAKE_COOKIE, FakeClock, FixtureFetcher, ScriptedChatModel  # noqa: E402
from tradecraft_memory_store import MemoryStore  # noqa: E402

FIXTURE = json.loads((Path(__file__).resolve().parent / "fixtures" / "tradecraft_contract" /
                      "JobStartBatch.valid.json").read_text())["jobs"][0]
TOKEN = "ghp_fake_token_never_logged"


class SteppedClock(FakeClock):
    """A clock whose sleeps return only when ``advance`` moves time past them."""

    def __init__(self):
        super().__init__(start=datetime(2026, 11, 16, 12, 0, tzinfo=timezone.utc))
        self._waiters: list = []

    async def sleep(self, seconds):
        self.sleeps.append(seconds)
        fut = asyncio.get_running_loop().create_future()
        self._waiters.append((self._mono + max(0.0, seconds), fut))
        await fut

    def advance(self, seconds):
        super().advance(seconds)
        for target, fut in list(self._waiters):
            if target <= self._mono:
                self._waiters.remove((target, fut))
                if not fut.done():
                    fut.set_result(None)


async def settle(rounds=30):
    for _ in range(rounds):
        await asyncio.sleep(0)


def job(job_id, user="u1", resource=None, **resource_fields):
    j = json.loads(json.dumps(FIXTURE))
    j.update(job_id=job_id, user_id=user, actor_user_id=user, resource_id=resource or f"r-{job_id}")
    j["resource"].update(resource_fields)
    return j


class Gate:
    """A scripted pipeline: each job waits for its own release, then answers ``outcome``."""

    def __init__(self, outcome=None):
        self.started: list[str] = []
        self.finished: list[str] = []
        self.release: dict[str, asyncio.Event] = {}
        self.contexts: dict = {}
        self.outcome = outcome or (lambda ctx: JobOutcome(status="failed", error_code="fetch_failed"))

    def event(self, jid):
        return self.release.setdefault(jid, asyncio.Event())

    async def __call__(self, ctx):
        jid = ctx.request.job_id
        self.started.append(jid)
        self.contexts[jid] = ctx
        await self.event(jid).wait()
        self.finished.append(jid)
        return self.outcome(ctx)


def runner_with(store, entry, clock=None, **kw):
    return jobs.JobRunner(store, entry=entry, instance="inst-test", clock=clock or SteppedClock(),
                          fetcher_factory=FixtureFetcher, **kw)


def seed(store, *specs):
    for spec in specs:
        store.add_resource(spec["user_id"], spec["resource_id"], url=spec["resource"]["url"],
                           storage_mode=spec["resource"]["storage_mode"])
        store.add_job(spec["user_id"], spec["resource_id"], spec["job_id"])
    return JobStartBatch.model_validate({"jobs": list(specs)})


def run(coro):
    return asyncio.run(coro)


# --------------------------------------------------------------------------------------

def test_bulk_order_one_per_user():
    store, gate = MemoryStore(), Gate()
    batch = seed(store, job("a1"), job("a2"), job("a3"), job("b1", user="u2"))

    async def go():
        runner = runner_with(store, gate)
        answer = await runner.submit(batch)
        assert answer.accepted == ["a1", "a2", "a3", "b1"] and answer.refused == []
        await settle()
        # Two run: the first of each owner. The owner's next job waits for its first.
        assert sorted(gate.started) == ["a1", "b1"]
        assert runner.snapshot()["queued"] == {"u1": ["a2", "a3"]}
        gate.event("b1").set()
        await settle()
        assert sorted(gate.started) == ["a1", "b1"]  # b's slot frees, but a1 still holds owner u1
        gate.event("a1").set()
        await settle()
        assert gate.started[-1] == "a2"
        gate.event("a2").set()
        gate.event("a3").set()
        await settle(60)
        assert gate.started == ["a1", "b1", "a2", "a3"] or gate.started == ["b1", "a1", "a2", "a3"]
        assert gate.finished.index("a2") < gate.finished.index("a3")
        await runner.close()

    run(go())


def test_cap_two_running():
    store, gate = MemoryStore(), Gate()
    batch = seed(store, job("x", user="u1"), job("y", user="u2"), job("z", user="u3"))

    async def go():
        runner = runner_with(store, gate)
        await runner.submit(batch)
        await settle()
        assert len(gate.started) == 2 and len(runner.snapshot()["running"]) == 2
        first = gate.started[0]
        gate.event(first).set()
        await settle()
        assert len(gate.started) == 3
        for jid in ("x", "y", "z"):
            gate.event(jid).set()
        await settle(60)
        assert runner.snapshot() == {"queued": {}, "running": []}
        await runner.close()

    run(go())


def test_cancel_keeps_previous():
    store = MemoryStore()

    async def entry(ctx):
        # A crawl that checks between pages.
        for _ in range(100):
            if await ctx.is_cancelled():
                return JobOutcome(status="cancelled", error_code="cancelled")
            await asyncio.sleep(0)
        return JobOutcome(status="succeeded", swapped=True)

    batch = seed(store, job("run1", resource="r1"), job("run2", resource="r1b", user="u1"))
    store.resources["r1"].update(generation=4, summary="previous summary")

    async def go():
        runner = runner_with(store, entry)
        await runner.submit(batch)
        await settle(3)
        await runner.cancel_job("run1")   # running: stops at its next check
        await runner.cancel_job("run2")   # queued behind it: closed at once, never started
        await settle(80)
        await runner.close()

    run(go())
    assert store.jobs["run1"]["status"] == "cancelled" and store.jobs["run1"]["error_code"] == "cancelled"
    assert store.jobs["run2"]["status"] == "cancelled"
    assert ("discard_generation", ("u1", "r1", 5)) in store.calls
    r1 = store.resources["r1"]
    assert r1["generation"] == 4 and r1["summary"] == "previous summary" and r1["active_job_id"] is None
    assert not any(n == "claim_job_for_run" and a[1] == "run2" for n, a in store.calls)


def test_cancel_by_flag_from_another_copy():
    store = MemoryStore()
    seen = []

    async def entry(ctx):
        clock = tc_clock
        for _ in range(10):
            seen.append(await ctx.is_cancelled())
            await clock.sleep(1)
        return JobOutcome(status="succeeded", swapped=True)

    batch = seed(store, job("j1"))
    clock = SteppedClock()

    async def go():
        runner = runner_with(store, entry, clock=clock)
        await runner.submit(batch)
        await settle()
        store.jobs["j1"]["cancel_requested"] = True  # the webapp set the flag
        for _ in range(5):
            clock.advance(1)
            await settle()
        await runner.close()

    run(go())
    assert seen[0] is False and True in seen


def test_long_job_no_timeout():
    """AC-32: a ten-minute crawl finishes and is saved; its lease is renewed all along."""
    store, clock = MemoryStore(), SteppedClock()

    async def entry(ctx):
        for i in range(30):
            await tc_clock.sleep(20)
            await ctx.set_stage("build_map", JobProgress(done=i + 1, total=30, unit="pages"))
        await store.swap(ctx.request.user_id, ctx.request.resource_id, ctx.request.job_id, ctx.target_generation,
                         ctx.request.resource.url, ctx.request.resource.storage_mode, {"summary": "new"})
        return JobOutcome(status="succeeded", swapped=True)

    batch = seed(store, job("long"))

    async def go():
        runner = runner_with(store, entry, clock=clock)
        await runner.submit(batch)
        for _ in range(31):
            await settle()
            clock.advance(20)
        await settle(60)
        await runner.close()

    run(go())
    assert store.jobs["long"]["status"] == "succeeded"
    assert store.resources[store.jobs["long"]["resource_id"]]["summary"] == "new"
    renewals = [a for n, a in store.calls if n == "renew_leases"]
    assert len(renewals) >= 25
    assert ("purge_old_generations", ("u1", "r-long")) in store.calls


def test_queued_job_lease_renewed():
    store, clock, gate = MemoryStore(), SteppedClock(), Gate()
    batch = seed(store, job("first"), job("second"))

    async def go():
        runner = runner_with(store, gate, clock=clock)
        await runner.submit(batch)
        await settle()
        lease_before = store.jobs["second"]["lease_until"]
        clock.advance(20)
        await settle()
        assert store.jobs["second"]["status"] == "queued"
        assert store.jobs["second"]["lease_until"] > lease_before
        renewed = [a for n, a in store.calls if n == "renew_leases"][-1]
        assert set(renewed[1]) == {("u1", "first"), ("u1", "second")}
        gate.event("first").set()
        gate.event("second").set()
        await settle(60)
        await runner.close()

    run(go())


def test_a_job_taken_over_elsewhere_is_dropped():
    store, clock, gate = MemoryStore(), SteppedClock(), Gate()
    batch = seed(store, job("running"), job("queued2"))

    async def go():
        runner = runner_with(store, gate, clock=clock)
        await runner.submit(batch)
        await settle()
        # Another claim failed both (their leases had expired somewhere else).
        store.jobs["queued2"]["status"] = "failed"
        store.jobs["running"]["status"] = "failed"
        clock.advance(20)
        await settle()
        assert runner.snapshot()["queued"] == {}
        assert gate.contexts["running"] and await gate.contexts["running"].is_cancelled()
        gate.event("running").set()
        await settle(60)
        await runner.close()

    run(go())
    assert not any(n == "claim_job_for_run" and a[1] == "queued2" for n, a in store.calls)


def test_parse_does_not_block_loop():
    """AC-35: a blocking parse runs on the job pool while the event loop keeps answering."""
    store = MemoryStore()
    in_thread, release = threading.Event(), threading.Event()
    answered = []

    def blocking_parse():
        in_thread.set()
        assert release.wait(5), "the event loop never got to release the parse"
        return threading.current_thread().name

    async def entry(ctx):
        name = await runner.run_blocking(blocking_parse)
        assert name.startswith("tradecraft-ingest")
        return JobOutcome(status="succeeded", swapped=True)

    async def handler():
        # What a chat request does meanwhile: it runs to the end on the loop.
        while not in_thread.is_set():
            await asyncio.sleep(0)
        answered.append("chat answered")
        release.set()

    batch = seed(store, job("parse"))

    async def go():
        global runner
        runner = runner_with(store, entry)
        await runner.submit(batch)
        task = runner._running["parse"].task
        await asyncio.wait_for(handler(), timeout=5)
        await asyncio.wait_for(task, timeout=5)
        await runner.close()

    run(go())
    assert answered == ["chat answered"]
    # The job ran to its end: after its (scripted) swap the runner purged older generations.
    assert ("purge_old_generations", ("u1", "r-parse")) in store.calls


def test_blocking_pool_gets_values_only():
    store = MemoryStore()
    marker: contextvars.ContextVar = contextvars.ContextVar("tc_test_marker", default="unset")
    seen = {}

    def in_pool(value):
        seen["value"] = value
        seen["marker"] = marker.get()
        seen["thread"] = threading.current_thread().name
        return value * 2

    async def entry(ctx):
        seen["job_marker"] = marker.get()  # the job task starts in a fresh context
        marker.set("set-in-job")
        seen["doubled"] = await runner.run_blocking(in_pool, 21)
        return JobOutcome(status="succeeded", swapped=True)

    batch = seed(store, job("ctx"))

    async def go():
        global runner
        marker.set("set-by-the-request")
        runner = runner_with(store, entry)
        await runner.submit(batch)
        await asyncio.wait_for(runner._running["ctx"].task, timeout=5)
        await runner.close()

    run(go())
    assert seen["job_marker"] == "unset"
    assert seen["marker"] == "unset" and seen["value"] == 21 and seen["doubled"] == 42
    assert seen["thread"].startswith("tradecraft-ingest")


@pytest.mark.parametrize("outcome,expected", [
    (lambda ctx: JobOutcome(status="failed", error_code="fetch_failed"), "fetch_failed"),
    (lambda ctx: (_ for _ in ()).throw(RuntimeError("boom")), "internal_error"),
])
def test_failure_marks_failed_with_code(outcome, expected):
    store = MemoryStore()

    async def entry(ctx):
        return outcome(ctx)

    batch = seed(store, job("bad", resource="r-bad"))
    store.resources["r-bad"].update(generation=2, summary="kept")

    async def go():
        runner = runner_with(store, entry)
        await runner.submit(batch)
        await settle(60)
        await runner.close()

    run(go())
    j, r = store.jobs["bad"], store.resources["r-bad"]
    assert j["status"] == "failed" and j["error_code"] == expected
    assert r["last_error"] == expected and r["active_job_id"] is None
    assert r["generation"] == 2 and r["summary"] == "kept"
    assert ("discard_generation", ("u1", "r-bad", 3)) in store.calls


def test_deleted_resource_fails_the_job_quietly():
    store = MemoryStore()

    async def entry(ctx):
        store.delete_resource(ctx.request.resource_id)
        await store.write_tree(ctx.request.user_id, ctx.request.resource_id, ctx.target_generation,
                               [{"path": "/", "parent_path": "", "label": "x"}])
        raise AssertionError("unreachable")

    batch = seed(store, job("gone"))

    async def go():
        runner = runner_with(store, entry)
        await runner.submit(batch)
        await settle(60)
        await runner.close()

    run(go())
    assert "gone" not in store.jobs and store.writes == 0


def test_budget_refusal_not_retried():
    store = MemoryStore()
    model = ScriptedChatModel(LlmBudgetExhausted("u1", 10, "yours"))

    async def entry(ctx):
        llm = models.IngestModel(model, ctx.request.user_id, "openai/fake-small-model")
        await llm.ainvoke("summarize")
        return JobOutcome(status="succeeded", swapped=True)

    batch = seed(store, job("budget"))

    async def go():
        runner = runner_with(store, entry)
        await runner.submit(batch)
        await settle(60)
        await runner.close()

    run(go())
    assert model.calls == 1
    assert store.jobs["budget"]["status"] == "failed" and store.jobs["budget"]["error_code"] == "llm_budget_exhausted"


def test_loop_model_refused():
    store = MemoryStore()
    batch = seed(store, job("loopy", model="loop/claude-code"))

    async def go():
        runner = runner_with(store, Gate())
        answer = await runner.submit(batch)
        await runner.close()
        return answer

    answer = run(go())
    assert answer.accepted == [] and [(r.job_id, r.code) for r in answer.refused] == [
        ("loopy", "loop_model_not_supported_here")]
    assert store.jobs["loopy"]["status"] == "failed"
    assert store.resources["r-loopy"]["active_job_id"] is None
    assert store.resources["r-loopy"]["last_error"] == "loop_model_not_supported_here"

    async def explode(owner):
        raise AssertionError("no provider is read for a loop model")

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(models, "fetch_providers", explode)
        with pytest.raises(LoopModelNotSupportedHere):
            run(models.build_ingest_llm("u1", "loop/claude-code"))


def test_model_call_carries_purpose_and_budget_user():
    from agent_context import current_llm_purpose
    seen = {}

    class Recorder:
        def with_config(self, **cfg):
            seen["config"] = cfg
            return self

        async def ainvoke(self, messages, config=None, **kw):
            seen["purpose"] = current_llm_purpose.get().get("purpose")
            return "ok"

    run(models.IngestModel(Recorder(), "owner-1", "openai/x").ainvoke("hi"))
    assert seen == {"config": {"metadata": {"user_id": "owner-1"}}, "purpose": "tradecraft_ingest"}


def test_unreadable_providers_are_model_unavailable():
    async def fail(owner):
        raise OSError(f"connection refused while sending {TOKEN}")

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(models, "fetch_providers", fail)
        with pytest.raises(models.ModelUnavailable) as err:
            run(models.build_ingest_llm("u1", "openai/fake-small-model"))
    assert TOKEN not in str(err.value) and jobs.error_code_of(err.value) == "model_unavailable"


def test_logs_no_secrets(caplog):
    """D-11: a job with a GitHub token and a cookie whose pipeline fails logs codes only."""
    store = MemoryStore()

    async def entry(ctx):
        await ctx.set_stage("fetch_home", None)
        raise RuntimeError(f"fetch of https://wiki.tc-fixture.test/?token={TOKEN} failed with {FAKE_COOKIE}")

    spec = job("secret")
    spec["secrets"] = {"github_token": TOKEN, "credentials": {"cookie": FAKE_COOKIE, "headers": [], "basic_auth": None}}
    batch = seed(store, spec)

    async def go():
        runner = runner_with(store, entry)
        await runner.submit(batch)
        await settle(60)
        await runner.close()

    with caplog.at_level(logging.DEBUG):
        run(go())
    text = caplog.text + json.dumps(store.jobs) + json.dumps({k: v for k, v in store.resources.items()}, default=str)
    assert "[tradecraft] job secret" in caplog.text
    assert TOKEN not in text and FAKE_COOKIE not in text and "?token=" not in text
    assert store.jobs["secret"]["error_code"] == "internal_error"


def test_job_not_claimed_and_queue_full():
    store = MemoryStore()
    batch = seed(store, job("mine"), job("other"))
    store.resources["r-other"]["active_job_id"] = "someone-else"

    async def go():
        runner = runner_with(store, Gate(), )
        runner.max_queued = 0
        answer = await runner.submit(batch)
        await runner.close()
        return answer

    answer = run(go())
    assert {(r.job_id, r.code) for r in answer.refused} == {("mine", "queue_full"), ("other", "job_not_claimed")}
    assert store.jobs["mine"]["status"] == "failed" and store.jobs["other"]["status"] == "queued"


def test_the_same_start_twice_runs_once():
    store, gate = MemoryStore(), Gate()
    batch = seed(store, job("twice"))

    async def go():
        runner = runner_with(store, gate)
        first = await runner.submit(batch)
        second = await runner.submit(batch)
        await settle()
        gate.event("twice").set()
        await settle(60)
        await runner.close()
        return first, second

    first, second = run(go())
    assert first.accepted == second.accepted == ["twice"]
    assert gate.started == ["twice"]


def test_cancel_user_flags_every_job():
    store, gate = MemoryStore(), Gate()
    batch = seed(store, job("c1"), job("c2"), job("other", user="u2"))

    async def go():
        runner = runner_with(store, gate)
        await runner.submit(batch)
        await settle()
        n = await runner.cancel_user("u1")
        gate.event("c1").set()
        gate.event("other").set()
        await settle(60)
        await runner.close()
        return n

    assert run(go()) == 2
    assert store.jobs["c2"]["status"] == "cancelled"
    assert store.jobs["c1"]["cancel_requested"] is True
    assert store.jobs["other"]["cancel_requested"] is False


def test_recover_fails_expired_jobs_and_discards_their_generation():
    store = MemoryStore()
    clock = SteppedClock()
    store.add_resource("u1", "r1")
    store.add_resource("u1", "r2")
    store.add_resource("u1", "r3")
    store.add_job("u1", "r1", "dead-running", status="running", lease_until=clock.now())
    store.jobs["dead-running"]["target_generation"] = 7
    store.add_job("u1", "r2", "dead-queued", lease_until=None)
    store.add_job("u1", "r3", "alive", lease_until="far")
    runner = runner_with(store, Gate(), clock=clock)
    clock.advance(1)
    assert run(runner.recover()) == 2
    assert store.jobs["dead-running"]["error_code"] == "agent_restarted"
    assert store.jobs["alive"]["status"] == "queued"
    assert ("discard_generation", ("u1", "r1", 7)) in store.calls


def test_recover_on_boot_never_raises(monkeypatch):
    class Broken:
        async def fail_expired_leases(self, *a):
            raise OSError("database down")

    jobs.set_runner_for_tests(jobs.JobRunner(Broken(), entry=Gate(), instance="i"))
    try:
        run(jobs.recover_on_boot())
    finally:
        jobs.set_runner_for_tests(None)


def test_error_codes():
    from tradecraft.store import ResourceGone
    assert jobs.error_code_of(ResourceGone("r")) == "resource_deleted"
    assert jobs.error_code_of(LlmBudgetExhausted("u", 1, "yours")) == "llm_budget_exhausted"
    assert jobs.error_code_of(LoopModelNotSupportedHere()) == "loop_model_not_supported_here"
    assert jobs.error_code_of(ValueError("x")) == "internal_error"


def test_the_same_start_twice_at_once_runs_once():
    store, gate = MemoryStore(), Gate()
    batch = seed(store, job("both"))

    async def go():
        runner = runner_with(store, gate)
        first, second = await asyncio.gather(runner.submit(batch), runner.submit(batch))
        await settle()
        queued = runner.snapshot()
        gate.event("both").set()
        await settle(60)
        await runner.close()
        return first, second, queued

    first, second, queued = run(go())
    assert first.accepted == second.accepted == ["both"]
    assert gate.started == ["both"] and queued["queued"] == {}
    assert [a for n, a in store.calls if n == "accept_job"] == [("u1", "both")]



# --------------------------------------------------------------------------------------
# M1: a job that ends without a swap leaves the 1.x columns as 1.x would after a verify
# --------------------------------------------------------------------------------------

def test_a_failed_job_records_the_1x_error_state():
    """TD-18 / D-25: last_error and last_verified_at, so a 1.x tab (switch off) shows an error
    card instead of "verifying..." for ever; the previous map and summary stay."""
    store, clock = MemoryStore(), SteppedClock()

    async def entry(ctx):
        return JobOutcome(status="failed", error_code="fetch_failed")

    batch = seed(store, job("first-add", resource="r-new"))
    store.resources["r-new"].update(sitemap={"nav": []}, summary="")
    assert store.resources["r-new"]["last_verified_at"] is None

    async def go():
        runner = runner_with(store, entry, clock=clock)
        await runner.submit(batch)
        await asyncio.wait_for(runner._running["first-add"].task, timeout=5)
        await runner.close()

    run(go())
    r = store.resources["r-new"]
    assert r["last_error"] == "fetch_failed" and r["last_verified_at"] == clock.now()
    assert r["sitemap"] == {"nav": []} and r["active_job_id"] is None


@pytest.mark.parametrize("verified_before", [False, True])
def test_a_refused_start_records_the_1x_error_state(verified_before):
    """The agent never reached the site: the error, and a verify time only for a resource never
    verified (1.x keeps lastVerifiedAt when its agent call fails)."""
    store, clock = MemoryStore(), SteppedClock()
    earlier = datetime(2026, 11, 1, tzinfo=timezone.utc)
    batch = seed(store, job("loopy", model="loop/claude-code"))
    if verified_before:
        store.resources["r-loopy"]["last_verified_at"] = earlier

    async def go():
        runner = runner_with(store, Gate(), clock=clock)
        await runner.submit(batch)
        await runner.close()

    run(go())
    r = store.resources["r-loopy"]
    assert r["last_error"] == "loop_model_not_supported_here"
    assert r["last_verified_at"] == (earlier if verified_before else clock.now())


@pytest.mark.parametrize("verified_before", [False, True])
def test_a_cancelled_job_marks_only_a_resource_never_verified(verified_before):
    """A cancelled first add reads as an error card, not "verifying..."; a cancelled refresh of a
    good resource leaves its 1.x state as it was."""
    store, clock = MemoryStore(), SteppedClock()
    earlier = datetime(2026, 11, 1, tzinfo=timezone.utc)

    async def entry(ctx):
        return JobOutcome(status="cancelled", error_code="cancelled")

    batch = seed(store, job("running-c", resource="r-run"), job("queued-c", resource="r-queued"))
    for rid in ("r-run", "r-queued"):
        if verified_before:
            store.resources[rid].update(last_verified_at=earlier, last_error="")

    async def go():
        runner = runner_with(store, entry, clock=clock, max_running=1)
        await runner.submit(batch)
        await runner.cancel_job("queued-c")  # still queued behind the running one
        await asyncio.wait_for(runner._running["running-c"].task, timeout=5)
        await runner.close()

    run(go())
    for rid in ("r-run", "r-queued"):
        r = store.resources[rid]
        if verified_before:
            assert r["last_verified_at"] == earlier and r["last_error"] == "", rid
        else:
            assert r["last_verified_at"] == clock.now() and r["last_error"] == "cancelled", rid
        assert r["active_job_id"] is None


@pytest.mark.parametrize("verified_before", [False, True])
def test_a_job_recovered_at_boot_records_the_1x_error_state(verified_before):
    """The boot recovery (code agent_restarted) marks each resource whose claim it releases:
    nothing was verified, so a verified resource keeps the time of its last real verify."""
    store, clock = MemoryStore(), SteppedClock()
    earlier = datetime(2026, 11, 1, tzinfo=timezone.utc)
    store.add_resource("u1", "r-lost", last_verified_at=earlier if verified_before else None)
    store.add_job("u1", "r-lost", "lost-job", lease_until=None)
    runner = runner_with(store, Gate(), clock=clock)
    assert run(runner.recover()) == 1
    r = store.resources["r-lost"]
    assert r["last_error"] == "agent_restarted" and r["active_job_id"] is None
    assert r["last_verified_at"] == (earlier if verified_before else clock.now())
