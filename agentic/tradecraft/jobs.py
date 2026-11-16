"""The ingestion job runner (master plan TD-8): per-user queues, two jobs at a time, a lease.

The webapp creates the job row with a 60 s start lease and claims the resource; this runner
then takes the job (``accept_job`` renews its lease and names this copy), keeps it in the
owner's FIFO queue, runs at most ``constants.jobsPerAgent`` (2) jobs per copy and one per
owner at a time, and renews the lease of every job it holds, queued or running, every
``jobLeaseRenewSec`` (20 s). A job has no time limit (AC-32): only its lease, which this copy
keeps alive while it holds it, and the crawl's own limits.

Every way out releases the claim: the swap clears it, ``finish_job`` clears it, and a copy
that dies stops renewing, so the lease expires and the next claim (or this copy's boot,
``recover_on_boot``) fails the job. Cancel is a database flag, so any copy can cancel any
job; the copy that holds the job also wakes it at once.

Jobs run in a context of their own (no context variable of the HTTP request that started
them), with the clock and the fetcher the runner was given. Parsing runs on the
``tradecraft-ingest`` thread pool through ``run_blocking``, which passes plain values: a pool
thread carries no context variable, so nothing there can read a run's settings.
"""

from __future__ import annotations

import asyncio
import contextvars
import functools
import sys
import uuid
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Awaitable, Callable, Optional

from agent_in_the_loop import is_loop_model
from logging_config import get_logger
from tradecraft import clock as tc_clock
from tradecraft import net
from tradecraft import settings as tc_settings
from tradecraft.contract import (
    ERROR_CODES,
    JobContext,
    JobOutcome,
    JobProgress,
    JobStartAnswer,
    JobStartBatch,
    JobStartRequest,
    Refusal,
)
from tradecraft.store import ResourceGone, Store

logger = get_logger(__name__)

POOL_WORKERS = 2
POOL_PREFIX = "tradecraft-ingest"
# How often a running job's is_cancelled() asks the database (it answers from memory in between).
CANCEL_POLL_SEC = 1.0

Entry = Callable[[JobContext], Awaitable[JobOutcome]]


def error_code_of(exc: BaseException) -> str:
    """A failure as a job error code: the code an exception carries when it is one of the
    contract's (the budget, a loop model, an unavailable model), else ``internal_error``."""
    if isinstance(exc, ResourceGone):
        return "resource_deleted"
    code = getattr(exc, "code", "")
    return code if isinstance(code, str) and code in ERROR_CODES else "internal_error"


def _agent_mcp_manager() -> Any:
    # The orchestrator's MCP manager, for the browser tier. api.py imports this module's
    # router, so the running app is looked up at call time; outside the agent process (a
    # test, a script) there is none and pages are read without the browser.
    agent_api = sys.modules.get("api")
    return getattr(getattr(agent_api, "orchestrator", None), "_mcp_manager", None)


def _default_fetcher() -> net.Fetcher:
    return net.GuardedFetcher(_agent_mcp_manager())


@dataclass
class _Running:
    user_id: str
    job: JobStartRequest
    cancel: asyncio.Event = field(default_factory=asyncio.Event)
    task: Optional[asyncio.Task] = None


class JobRunner:
    def __init__(self, store: Optional[Store] = None, *, entry: Optional[Entry] = None,
                 instance: Optional[str] = None, clock: Optional[tc_clock.Clock] = None,
                 fetcher_factory: Optional[Callable[[], net.Fetcher]] = None,
                 max_running: Optional[int] = None) -> None:
        self.store = store or Store()
        self.instance = instance or f"agent-{uuid.uuid4().hex[:12]}"
        self._entry = entry
        self._clock = clock
        self._fetcher_factory = fetcher_factory or _default_fetcher
        self.max_running = max_running or tc_settings.constant("jobsPerAgent")
        self.lease_sec = tc_settings.constant("jobLeaseSec")
        self.renew_sec = tc_settings.constant("jobLeaseRenewSec")
        self.max_queued = tc_settings.constant("maxQueuedJobsPerUser")
        self._queues: dict[str, deque[JobStartRequest]] = {}
        self._order: deque[str] = deque()
        self._held: dict[str, str] = {}          # job id -> owner, queued or running
        self._taking: set[str] = set()           # job ids whose accept_job is in flight
        self._running: dict[str, _Running] = {}  # job id -> running job
        self._lease_task: Optional[asyncio.Task] = None
        self._background: set[asyncio.Task] = set()
        self._pool: Optional[ThreadPoolExecutor] = None

    # --- time, context and the thread pool ---------------------------------------------

    def _now(self):
        return (self._clock or tc_clock).now()

    def _lease_until(self):
        return self._now() + timedelta(seconds=self.lease_sec)

    def _spawn(self, coro_fn: Callable[[], Awaitable[Any]], name: str) -> asyncio.Task:
        """A task in a fresh context, with only the runner's clock and fetcher bound."""

        async def wrapped():
            with tc_clock.use_clock(self._clock or tc_clock._REAL), net.use_fetcher(self._fetcher_factory()):
                return await coro_fn()

        task = asyncio.get_running_loop().create_task(wrapped(), name=name, context=contextvars.Context())
        self._background.add(task)
        task.add_done_callback(self._background.discard)
        return task

    def _executor(self) -> ThreadPoolExecutor:
        if self._pool is None:
            self._pool = ThreadPoolExecutor(max_workers=POOL_WORKERS, thread_name_prefix=POOL_PREFIX)
        return self._pool

    async def run_blocking(self, fn: Callable[..., Any], *args: Any) -> Any:
        """``fn(*args)`` on the ingestion pool. ``run_in_executor`` copies no context, so pass
        values: a call that reads a context variable there sees its default."""
        return await asyncio.get_running_loop().run_in_executor(self._executor(), functools.partial(fn, *args))

    # --- taking jobs ------------------------------------------------------------------

    def _model_of(self, job: JobStartRequest) -> str:
        return job.resource.model or str(job.settings.get("summary.defaultModel") or "")

    async def submit(self, batch: JobStartBatch) -> JobStartAnswer:
        accepted: list[str] = []
        refused: list[Refusal] = []
        for job in batch.jobs:
            if job.job_id in self._held or job.job_id in self._taking:
                accepted.append(job.job_id)  # the same start twice, or twice at once: already ours
                continue
            self._taking.add(job.job_id)
            try:
                code = await self._take(job)
            except Exception as exc:
                logger.warning(f"[tradecraft] job {job.job_id} not taken: {type(exc).__name__}")
                code = "internal_error"
            finally:
                self._taking.discard(job.job_id)
            if code:
                refused.append(Refusal(job_id=job.job_id, code=code))
            else:
                accepted.append(job.job_id)
        self._dispatch()
        return JobStartAnswer(accepted=accepted, refused=refused)

    async def _take(self, job: JobStartRequest) -> str:
        user = job.user_id
        if not await self.store.accept_job(user, job.job_id, self.instance, self._lease_until()):
            return "job_not_claimed"
        code = ""
        if is_loop_model(self._model_of(job)):
            code = "loop_model_not_supported_here"
        elif len(self._queues.get(user, ())) >= self.max_queued:
            code = "queue_full"
        if code:
            # The job is ours now: close it and release the claim rather than leave it to its lease.
            await self.store.set_error_without_fetch(user, job.resource_id, job.job_id, code, self._now())
            await self.store.finish_job(user, job.job_id, "failed", code)
            logger.info(f"[tradecraft] job {job.job_id} failed code={code}")
            return code
        self._queues.setdefault(user, deque()).append(job)
        if user not in self._order:
            self._order.append(user)
        self._held[job.job_id] = user
        logger.info(f"[tradecraft] job {job.job_id} queued code=")
        self._ensure_lease_task()
        return ""

    def _dispatch(self) -> None:
        """Starts queued jobs while fewer than ``max_running`` run: owners in turn, one job of
        each owner at a time, each owner's jobs in the order they came."""
        busy = {r.user_id for r in self._running.values()}
        for _ in range(len(self._order)):
            if len(self._running) >= self.max_running or not self._order:
                return
            user = self._order[0]
            self._order.rotate(-1)
            queue = self._queues.get(user)
            if not queue:
                self._order.remove(user)
                self._queues.pop(user, None)
                continue
            if user in busy:
                continue
            job = queue.popleft()
            if not queue:
                self._order.remove(user)
                self._queues.pop(user, None)
            running = _Running(user, job)
            self._running[job.job_id] = running
            busy.add(user)
            running.task = self._spawn(lambda r=running: self._run(r), f"tradecraft-job-{job.job_id}")

    # --- running a job ----------------------------------------------------------------

    def _entry_fn(self) -> Entry:
        if self._entry is None:
            from tradecraft.ingest import pipeline
            self._entry = functools.partial(pipeline.run, store=self.store, run_blocking=self.run_blocking)
        return self._entry

    async def _run(self, running: _Running) -> None:
        job, user = running.job, running.user_id
        jid, rid = job.job_id, job.resource_id
        generation = 0
        try:
            if not await self.store.claim_job_for_run(user, jid, self.instance, self._lease_until()):
                # Finished meanwhile (a cancel, a takeover, the resource deleted): whoever
                # finished it closed it.
                logger.info(f"[tradecraft] job {jid} dropped code=job_not_claimed")
                return
            if running.cancel.is_set() or await self.store.cancel_requested(user, jid):
                await self.store.set_error_if_never_verified(user, rid, jid, "cancelled", self._now())
                await self.store.finish_job(user, jid, "cancelled", "cancelled")
                logger.info(f"[tradecraft] job {jid} cancelled code=cancelled")
                return
            begun = await self.store.begin_generation(user, rid, jid)
            if begun is None:
                code = "resource_deleted" if await self.store.resource(user, rid) is None else "agent_lost"
                await self.store.finish_job(user, jid, "failed", code)
                logger.info(f"[tradecraft] job {jid} failed code={code}")
                return
            generation = begun
            logger.info(f"[tradecraft] job {jid} running code=")
            ctx = JobContext(
                request=job,
                settings=tc_settings.EffectiveSettings(job.settings),
                target_generation=generation,
                is_cancelled=self._cancel_check(running),
                set_stage=self._stage_setter(user, jid),
            )
            try:
                outcome = await self._entry_fn()(ctx)
            except Exception as exc:
                code = error_code_of(exc)
                logger.warning(f"[tradecraft] job {jid} failed code={code} error={type(exc).__name__}")
                outcome = JobOutcome(status="failed", error_code=code)
            await self._close(user, rid, jid, generation, outcome)
        except Exception as exc:
            # The store itself failed (the database went away): the lease runs out and the
            # next claim, or the next boot, fails the job.
            logger.warning(f"[tradecraft] job {jid} not closed code=internal_error error={type(exc).__name__}")
        finally:
            self._running.pop(jid, None)
            self._held.pop(jid, None)
            self._dispatch()

    async def _close(self, user: str, rid: str, jid: str, generation: int, outcome: JobOutcome) -> None:
        if outcome.swapped:
            # The swap closed the job and released the claim; older generations go in batches.
            logger.info(f"[tradecraft] job {jid} {outcome.status} code={outcome.error_code}")
            try:
                await self.store.purge_old_generations(user, rid)
            except Exception as exc:
                logger.warning(f"[tradecraft] job {jid} purge deferred error={type(exc).__name__}")
            return
        await self.store.discard_generation(user, rid, generation)
        code = outcome.error_code or ("" if outcome.status == "succeeded" else "internal_error")
        if outcome.status == "failed":
            await self.store.set_last_error(user, rid, jid, code, self._now())
        elif outcome.status == "cancelled":
            await self.store.set_error_if_never_verified(user, rid, jid, code, self._now())
        await self.store.finish_job(user, jid, outcome.status, code)
        logger.info(f"[tradecraft] job {jid} {outcome.status} code={code}")

    def _cancel_check(self, running: _Running) -> Callable[[], Awaitable[bool]]:
        last = {"at": None, "answer": False}

        async def is_cancelled() -> bool:
            if running.cancel.is_set():
                return True
            now = tc_clock.monotonic()
            if last["at"] is None or now - last["at"] >= CANCEL_POLL_SEC:
                last["at"] = now
                last["answer"] = await self.store.cancel_requested(running.user_id, running.job.job_id)
                if last["answer"]:
                    running.cancel.set()
            return last["answer"]

        return is_cancelled

    def _stage_setter(self, user: str, jid: str) -> Callable[[str, Optional[JobProgress]], Awaitable[None]]:
        async def set_stage(stage: str, progress: Optional[JobProgress] = None) -> None:
            await self.store.set_job_stage(user, jid, stage, progress.model_dump() if progress else {})
            logger.info(f"[tradecraft] job {jid} {stage} code=")

        return set_stage

    # --- the lease --------------------------------------------------------------------

    def _ensure_lease_task(self) -> None:
        if self._lease_task is None or self._lease_task.done():
            self._lease_task = self._spawn(self._lease_loop, "tradecraft-leases")

    async def _lease_loop(self) -> None:
        while self._held:
            await tc_clock.sleep(self.renew_sec)
            held = list(self._held.items())
            if not held:
                return
            try:
                renewed = await self.store.renew_leases(self.instance, self._lease_until(),
                                                        [(user, jid) for jid, user in held])
            except Exception as exc:
                logger.warning(f"[tradecraft] lease renewal failed error={type(exc).__name__}")
                continue
            for jid, user in held:
                if jid in renewed or jid not in self._held:
                    continue
                # Finished or taken over elsewhere: stop it here.
                self._forget(jid, user)

    def _forget(self, jid: str, user: str) -> None:
        running = self._running.get(jid)
        if running is not None:
            running.cancel.set()
            return
        self._remove_queued(jid, user)
        logger.info(f"[tradecraft] job {jid} dropped code=agent_lost")

    def _remove_queued(self, jid: str, user: str) -> Optional[JobStartRequest]:
        """Takes a queued job out of its owner's queue; None when it was not queued here."""
        queue = self._queues.get(user)
        removed = next((j for j in queue or () if j.job_id == jid), None)
        if removed is None:
            return None
        remaining = deque(j for j in queue if j.job_id != jid)
        if remaining:
            self._queues[user] = remaining
        else:
            self._queues.pop(user, None)
            if user in self._order:
                self._order.remove(user)
        self._held.pop(jid, None)
        return removed

    # --- cancel -----------------------------------------------------------------------

    async def cancel_job(self, job_id: str) -> None:
        """Cancels a job this copy holds: a queued one is closed at once, a running one stops
        at its next check. A job another copy holds is cancelled by the flag the webapp set."""
        user = self._held.get(job_id)
        if user is None:
            return
        await self.store.request_cancel(user, job_id)
        await self._cancel_local(job_id, user)

    async def cancel_user(self, user_id: str) -> int:
        """Sets the cancel flag of every unfinished job of the user, on every copy, and stops
        the ones this copy holds; returns how many were unfinished."""
        flagged = await self.store.request_cancel_user(user_id)
        for jid, user in list(self._held.items()):
            if user == user_id:
                await self._cancel_local(jid, user)
        return len(flagged)

    async def _cancel_local(self, jid: str, user: str) -> None:
        running = self._running.get(jid)
        if running is not None:
            running.cancel.set()
            return
        job = self._remove_queued(jid, user)
        if job is None:
            return
        await self.store.set_error_if_never_verified(user, job.resource_id, jid, "cancelled", self._now())
        await self.store.finish_job(user, jid, "cancelled", "cancelled")
        logger.info(f"[tradecraft] job {jid} cancelled code=cancelled")

    # --- boot ------------------------------------------------------------------------

    async def recover(self) -> int:
        """Fails every job whose lease expired (no lease counts as expired), queued or running,
        with ``agent_restarted``, discards the generation it was writing and releases its claim.
        Jobs whose lease is still live belong to a copy that may still run them: they are left
        alone, and looked at again one lease period later."""
        failed = await self.store.fail_expired_leases(self._now(), "agent_restarted")
        for row in failed:
            if row.get("resource_id") and row.get("target_generation"):
                try:
                    await self.store.discard_generation(row["user_id"], row["resource_id"], int(row["target_generation"]))
                except Exception as exc:
                    logger.warning(f"[tradecraft] job {row['id']} discard deferred error={type(exc).__name__}")
            logger.info(f"[tradecraft] job {row['id']} failed code=agent_restarted")
        return len(failed)

    def schedule_second_recovery(self) -> None:
        """A job of the previous process whose lease was still live at boot is failed once it
        runs out, so its card does not read "running" until someone clicks Refresh."""

        async def later():
            await tc_clock.sleep(self.lease_sec + self.renew_sec)
            try:
                await self.recover()
            except Exception as exc:
                logger.warning(f"[tradecraft] second recovery failed error={type(exc).__name__}")

        self._spawn(later, "tradecraft-recover")

    async def close(self) -> None:
        for task in list(self._background):
            task.cancel()
        for task in list(self._background):
            try:
                await task
            except BaseException:
                pass
        if self._pool is not None:
            self._pool.shutdown(wait=False, cancel_futures=True)
            self._pool = None

    def snapshot(self) -> dict:
        """What this copy holds (tests and logs): queued ids per owner and running ids."""
        return {"queued": {u: [j.job_id for j in q] for u, q in self._queues.items()},
                "running": sorted(self._running)}


_runner: Optional[JobRunner] = None


def get_runner() -> JobRunner:
    global _runner
    if _runner is None:
        _runner = JobRunner()
    return _runner


def set_runner_for_tests(runner: Optional[JobRunner]) -> None:
    global _runner
    _runner = runner


async def recover_on_boot() -> None:
    """Called once from the agent's start-up. Never raises: a store that cannot be reached
    (no DATABASE_URL in a hand-run agent) leaves recovery to the next start."""
    runner = get_runner()
    try:
        count = await runner.recover()
        logger.info(f"[tradecraft] boot recovery failed {count} job(s) code=agent_restarted")
    except Exception as exc:
        logger.warning(f"[tradecraft] boot recovery skipped error={type(exc).__name__}")
        return
    runner.schedule_second_recovery()
