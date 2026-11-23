"""The job store under a sandbox that plants links, pipes and giants (FU-29).

Every Kali sandbox that mounts a project writes its `jobs/` folder as root, so
whatever sits at `<id>.log`, `<id>.meta.json` or `jobs` itself is attacker-chosen.
The agent must never read or write through a link there (STRIDE T3/I6: a link to
/proc/self/environ handed out every platform secret), never hang on a pipe and
never read a giant whole (D15: at boot that stopped the agent for every tenant).

`outside/` stands in for the agent container's own files; the canary in it stands
in for a secret. Nothing real is read.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import sys
import tempfile
import threading
import time
import tracemalloc
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import job_runner  # noqa: E402

JOB = "a" * 32
OTHER = "b" * 32
CANARY = "INTERNAL_API_KEY=planted-canary-0451"
GUARD_SEC = 5.0
# What a bounded read may cost; an unbounded one of the giants below costs >= 128 MiB.
PEAK_LIMIT = 8 << 20
GIANT = 128 << 20


def run_guarded(test, fn, fifos=()):
    """Run fn in a thread; a call still blocked after GUARD_SEC (the old open() of a
    FIFO) is unblocked by opening the FIFOs for writing, then FAILS the test, so a
    hang is reported, never a stuck run."""
    box = {}

    def target():
        try:
            box["value"] = fn()
        except BaseException as exc:  # noqa: BLE001 - re-raised in the test thread
            box["error"] = exc

    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join(GUARD_SEC)
    hung = t.is_alive()
    deadline = time.monotonic() + 10
    while t.is_alive() and time.monotonic() < deadline:
        for fifo in fifos:
            try:
                os.close(os.open(fifo, os.O_WRONLY | os.O_NONBLOCK))
            except OSError:
                pass
        t.join(0.05)
    if hung:
        test.fail(f"{getattr(fn, '__name__', fn)} blocked on a planted FIFO for {GUARD_SEC}s")
    if "error" in box:
        raise box["error"]
    return box.get("value")


def peak_bytes(fn):
    tracemalloc.start()
    try:
        result = fn()
        return result, tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


class _Base(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="redamon-jobstore-"))
        self.root = self.tmp / "workspace"
        self.outside = self.tmp / "outside"
        self.root.mkdir()
        self.outside.mkdir()
        self.secret = self.outside / "environ"
        self.secret.write_text(CANARY + "\n")
        self._orig_root = job_runner.WORKSPACE_ROOT
        job_runner.WORKSPACE_ROOT = self.root
        job_runner._registry = None
        getattr(job_runner, "_REFUSALS_LOGGED", set()).clear()
        self.reg = job_runner.get_registry()

    async def asyncTearDown(self):
        tasks = [h.task for h in self.reg._jobs.values() if h.task and not h.task.done()]
        for t in tasks:
            t.cancel()
        for t in tasks:
            try:
                await t
            except (asyncio.CancelledError, Exception):
                pass
        job_runner.WORKSPACE_ROOT = self._orig_root
        job_runner._registry = None
        shutil.rmtree(self.tmp, ignore_errors=True)

    def jobs(self, project="p1") -> Path:
        d = self.root / project / "jobs"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def meta(self, project="p1", job=JOB, status="done", **extra) -> Path:
        path = self.jobs(project) / f"{job}.meta.json"
        path.write_text(json.dumps({"job_id": job, "project_id": project, "tool_name": "kali_shell",
                                    "status": status, "started_at": "2026-01-01T00:00:00+00:00",
                                    **extra}))
        return path

    def outside_meta(self, name="victim.json", status="running") -> Path:
        path = self.outside / name
        path.write_text(json.dumps({"job_id": JOB, "status": status, "planted": CANARY}))
        return path

    def no_canary(self, value):
        self.assertNotIn("planted-canary", json.dumps(value, default=str))

    async def blocked_job(self, project="p1", first="first chunk"):
        """A live job that wrote `first` and waits for `release`."""
        release, wrote = asyncio.Event(), asyncio.Event()

        async def runner(_name, _args, append_log):
            await append_log(first)
            wrote.set()
            await release.wait()
            await append_log("second chunk")
            return {"success": True}

        job_id = (await self.reg.spawn(project, "kali_shell", {"command": "x"}, runner))["job_id"]
        await asyncio.wait_for(wrote.wait(), 5)
        return job_id, release


class ReadsNeverFollowALink(_Base):
    async def test_a_log_linked_outside_is_not_read_by_status(self):
        self.meta()
        (self.jobs() / f"{JOB}.log").symlink_to(self.secret)
        state = self.reg.status("p1", JOB)
        self.no_canary(state)
        self.assertEqual(state.get("size_bytes"), 0, "a link's target size is not the job's")

    async def test_a_live_jobs_log_swapped_for_a_link_is_not_read(self):
        job_id, release = await self.blocked_job()
        log = self.jobs() / f"{job_id}.log"
        log.unlink()
        log.symlink_to(self.secret)
        self.no_canary(self.reg.status("p1", job_id))
        self.no_canary(self.reg.list("p1"))
        release.set()

    async def test_a_linked_meta_is_not_a_job(self):
        (self.jobs() / f"{JOB}.meta.json").symlink_to(self.outside_meta(status="done"))
        state = self.reg.status("p1", JOB)
        self.assertNotIn("job_id", state)
        self.no_canary(state)
        self.no_canary(self.reg.list("p1"))

    async def test_a_jobs_folder_that_is_a_link_is_refused(self):
        elsewhere = self.outside / "jobs"
        elsewhere.mkdir()
        (elsewhere / f"{JOB}.meta.json").write_text(json.dumps({"job_id": JOB, "status": "done"}))
        (elsewhere / f"{JOB}.log").write_text(CANARY)
        (self.root / "p1").mkdir()
        (self.root / "p1" / "jobs").symlink_to(elsewhere)
        state = self.reg.status("p1", JOB)
        self.assertNotIn("job_id", state)
        self.no_canary(state)
        self.assertEqual(self.reg.list("p1"), [])

    async def test_a_traversing_project_id_neither_reads_nor_creates_outside(self):
        (self.outside / "jobs").mkdir()
        (self.outside / "jobs" / f"{JOB}.meta.json").write_text(
            json.dumps({"job_id": JOB, "status": "done", "planted": CANARY}))
        state = self.reg.status("../outside", JOB)
        self.assertNotIn("job_id", state)
        self.no_canary(state)
        self.no_canary(self.reg.list("../outside"))
        self.reg.status("../made", JOB)
        self.assertFalse((self.tmp / "made").exists(), "a status read created folders outside")
        refused = await self.reg.spawn("../outside", "kali_shell", {}, None)
        self.assertEqual(refused.get("code"), "invalid_project_id")
        self.assertEqual(sorted(p.name for p in (self.outside / "jobs").iterdir()),
                         [f"{JOB}.meta.json"])

    async def test_a_traversing_job_id_from_the_model_reads_nothing(self):
        # job_status passes the model's job_id through unchecked (tools.py).
        self.outside_meta(name="x.meta.json", status="done")
        (self.outside / "x.log").write_text(CANARY)
        self.jobs()
        for bad in ("../../../outside/x", "../../outside/x", "a/../../x"):
            state = self.reg.status("p1", bad)
            self.assertNotIn("job_id", state, bad)
            self.no_canary(state)


class NoHangNoGiantRead(_Base):
    async def test_a_fifo_meta_does_not_hang_status_or_list(self):
        fifo = self.jobs() / f"{JOB}.meta.json"
        os.mkfifo(fifo)
        state = run_guarded(self, lambda: self.reg.status("p1", JOB), [fifo])
        self.assertNotIn("job_id", state)
        self.assertEqual(run_guarded(self, lambda: self.reg.list("p1"), [fifo]), [])

    async def test_a_fifo_log_does_not_hang_status(self):
        self.meta()
        fifo = self.jobs() / f"{JOB}.log"
        os.mkfifo(fifo)
        state = run_guarded(self, lambda: self.reg.status("p1", JOB), [fifo])
        self.assertEqual(state["tail"], "")

    async def test_an_oversized_meta_is_refused(self):
        self.meta(pad="x" * (2 << 20), planted=CANARY)
        state = self.reg.status("p1", JOB)
        self.assertNotIn("job_id", state)
        self.no_canary(state)
        self.no_canary(self.reg.list("p1"))

    async def test_a_sparse_giant_meta_is_never_read_whole(self):
        giant = self.jobs() / f"{JOB}.meta.json"
        with open(giant, "wb") as fh:
            fh.truncate(GIANT)
        (state, rows), peak = peak_bytes(lambda: (self.reg.status("p1", JOB), self.reg.list("p1")))
        self.assertNotIn("job_id", state)
        self.assertEqual(rows, [])
        self.assertLess(peak, PEAK_LIMIT)

    async def test_the_status_tail_is_bounded(self):
        self.meta()
        line = "y" * (200 << 10) + "\n"
        (self.jobs() / f"{JOB}.log").write_text(line * 40)
        state = self.reg.status("p1", JOB)
        self.assertLessEqual(len(state["tail"]), 64 << 10)
        self.assertEqual(state["size_bytes"], len(line) * 40)

    async def test_a_sparse_giant_log_is_never_read_whole(self):
        self.meta()
        with open(self.jobs() / f"{JOB}.log", "wb") as fh:
            fh.truncate(GIANT)
        state, peak = peak_bytes(lambda: self.reg.status("p1", JOB))
        self.assertLessEqual(len(state["tail"]), 64 << 10)
        self.assertLess(peak, PEAK_LIMIT)


class BootRecoverySkipsWhatItCannotTrust(_Base):
    def legit(self):
        a = self.meta("p1", OTHER, status="running")
        b = self.meta("p2", JOB, status="running")
        return a, b

    def assert_flipped(self, *paths):
        for p in paths:
            self.assertEqual(json.loads(p.read_text())["status"], "interrupted", p)

    async def test_a_linked_meta_is_skipped_and_never_written_through(self):
        victim = self.outside_meta()
        before = victim.read_bytes()
        link = self.jobs() / f"{JOB}.meta.json"
        link.symlink_to(victim)
        legit = self.legit()
        records = []
        handler = logging.Handler(logging.WARNING)
        handler.emit = records.append
        job_runner.logger.addHandler(handler)
        try:
            run_guarded(self, self.reg.recover_on_boot)
        finally:
            job_runner.logger.removeHandler(handler)
        self.assertEqual(victim.read_bytes(), before, "boot wrote through the link")
        self.assertTrue(link.is_symlink())
        self.assert_flipped(*legit)
        lines = [r.getMessage() for r in records]
        self.assertTrue(any(f"{JOB}.meta.json" in line for line in lines), lines)

    async def test_a_fifo_meta_is_skipped_and_boot_completes(self):
        fifo = self.jobs() / f"{JOB}.meta.json"
        os.mkfifo(fifo)
        legit = self.legit()
        run_guarded(self, self.reg.recover_on_boot, [fifo])
        self.assert_flipped(*legit)
        self.assertTrue(fifo.is_fifo())

    async def test_a_jobs_folder_that_is_a_link_is_skipped(self):
        elsewhere = self.outside / "jobs"
        elsewhere.mkdir()
        victim = elsewhere / f"{JOB}.meta.json"
        victim.write_text(json.dumps({"job_id": JOB, "status": "running"}))
        before = victim.read_bytes()
        (self.root / "p3").mkdir()
        (self.root / "p3" / "jobs").symlink_to(elsewhere)
        legit = self.legit()
        run_guarded(self, self.reg.recover_on_boot)
        self.assertEqual(victim.read_bytes(), before)
        self.assertEqual(sorted(p.name for p in elsewhere.iterdir()), [victim.name])
        self.assert_flipped(*legit)

    async def test_oversized_metas_are_skipped_unread(self):
        big = self.meta("p1", JOB, status="running", pad="x" * (2 << 20))
        before = big.read_bytes()
        giant = self.jobs("p2") / f"{OTHER}.meta.json"
        with open(giant, "wb") as fh:
            fh.truncate(GIANT)
        legit = (self.meta("p1", "c" * 32, status="running"), self.meta("p2", "d" * 32, status="running"))
        _, peak = peak_bytes(lambda: run_guarded(self, self.reg.recover_on_boot))
        self.assertEqual(big.read_bytes(), before)
        self.assertEqual(giant.stat().st_size, GIANT)
        self.assertLess(peak, PEAK_LIMIT)
        self.assert_flipped(*legit)


class WritesNeverFollowALink(_Base):
    async def test_appends_never_follow_a_log_swapped_for_a_link(self):
        victim = self.outside / "agent_file.py"
        victim.write_text("original\n")
        job_id, release = await self.blocked_job()
        log = self.jobs() / f"{job_id}.log"
        log.unlink()
        log.symlink_to(victim)
        release.set()
        await self.reg.wait("p1", job_id, 5)
        self.assertEqual(victim.read_text(), "original\n", "the agent appended through the link")
        self.assertEqual(self.reg.status("p1", job_id)["status"], "done")

    async def test_the_meta_write_replaces_a_planted_link_instead_of_following_it(self):
        victim = self.outside / "agent_config.json"
        victim.write_text("{}")
        job_id, release = await self.blocked_job()
        meta = self.jobs() / f"{job_id}.meta.json"
        meta.unlink()
        meta.symlink_to(victim)
        release.set()
        await self.reg.wait("p1", job_id, 5)
        self.assertEqual(victim.read_text(), "{}", "the agent wrote its record through the link")
        self.assertFalse(meta.is_symlink())
        self.assertEqual(json.loads(meta.read_text())["status"], "done")

    async def test_a_jobs_folder_swapped_for_a_link_mid_job_is_not_written(self):
        elsewhere = self.outside / "jobs"
        elsewhere.mkdir()
        job_id, release = await self.blocked_job()
        jobs = self.root / "p1" / "jobs"
        jobs.rename(self.root / "p1" / "jobs.real")
        jobs.symlink_to(elsewhere)
        release.set()
        await self.reg.wait("p1", job_id, 5)
        self.assertEqual(list(elsewhere.iterdir()), [], "the agent wrote through the folder link")

    async def test_spawn_refuses_a_jobs_folder_that_is_a_link(self):
        elsewhere = self.outside / "jobs"
        elsewhere.mkdir()
        (self.root / "p1").mkdir()
        (self.root / "p1" / "jobs").symlink_to(elsewhere)

        async def runner(_name, _args, append_log):
            await append_log("output")
            return {"success": True}

        result = await self.reg.spawn("p1", "kali_shell", {}, runner)
        self.assertNotIn("job_id", result)
        self.assertEqual(result.get("code"), "job_store_refused")
        await asyncio.sleep(0.05)
        self.assertEqual(list(elsewhere.iterdir()), [])
        self.assertEqual(self.reg._jobs, {}, "a refused job holds no slot")


class LegitimateJobsStillWork(_Base):
    """Regression guards: these pass before and after the fix."""

    async def test_a_running_job_streams_then_completes(self):
        job_id, release = await self.blocked_job()
        mid = self.reg.status("p1", job_id)
        self.assertEqual(mid["status"], "running")
        self.assertEqual(mid["tail"], "first chunk\n")
        self.assertEqual(mid["size_bytes"], len("first chunk\n"))
        release.set()
        done = await self.reg.wait("p1", job_id, 5)
        self.assertEqual(done["status"], "done")
        self.assertEqual(done["tail"], "first chunk\nsecond chunk\n")
        log, meta = self.jobs() / f"{job_id}.log", self.jobs() / f"{job_id}.meta.json"
        self.assertTrue(log.is_file() and not log.is_symlink())
        self.assertEqual(json.loads(meta.read_text())["status"], "done")
        self.assertEqual([r["job_id"] for r in self.reg.list("p1")], [job_id])

    async def test_a_running_job_can_be_cancelled(self):
        job_id, _release = await self.blocked_job()
        self.assertEqual((await self.reg.cancel("p1", job_id))["status"], "cancelled")
        meta = json.loads((self.jobs() / f"{job_id}.meta.json").read_text())
        self.assertEqual(meta["status"], "cancelled")

    async def test_a_finished_job_reads_back_after_a_restart(self):
        job_id, release = await self.blocked_job()
        release.set()
        await self.reg.wait("p1", job_id, 5)
        job_runner._registry = None
        fresh = job_runner.get_registry()
        fresh.recover_on_boot()
        state = fresh.status("p1", job_id)
        self.assertEqual(state["status"], "done")
        self.assertEqual(state["tail"], "first chunk\nsecond chunk\n")
        self.assertEqual([r["job_id"] for r in fresh.list("p1")], [job_id])

    async def test_a_huge_argument_keeps_the_record_readable_after_a_restart(self):
        async def runner(_name, _args, _log):
            return {"success": True}

        job_id = (await self.reg.spawn("p1", "kali_shell", {"command": "x" * 200_000}, runner))["job_id"]
        await self.reg.wait("p1", job_id, 5)
        job_runner._registry = None
        self.assertEqual(job_runner.get_registry().status("p1", job_id)["status"], "done")


if __name__ == "__main__":
    unittest.main()
