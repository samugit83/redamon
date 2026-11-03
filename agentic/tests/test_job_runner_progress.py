"""job_runner.report_progress: in-job progress, throttled meta, progress events."""
from __future__ import annotations

import asyncio
import json
import shutil
import tempfile
import unittest
from pathlib import Path

import job_runner


class ProgressBase(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="jobs-progress-")
        self._orig_root = job_runner.WORKSPACE_ROOT
        job_runner.WORKSPACE_ROOT = Path(self.tmp)
        self.reg = job_runner.JobRegistry()
        self.events = []

        async def emit(evt):
            self.events.append(evt)

        self.reg.set_ws_emitter(emit)

    async def asyncTearDown(self):
        for h in list(self.reg._jobs.values()):
            if h.task and not h.task.done():
                h.task.cancel()
                try:
                    await h.task
                except (asyncio.CancelledError, Exception):
                    pass
        job_runner.WORKSPACE_ROOT = self._orig_root
        shutil.rmtree(self.tmp, ignore_errors=True)

    def meta(self, job_id):
        return json.loads((Path(self.tmp) / "p1" / "jobs" / f"{job_id}.meta.json").read_text())


class ReportProgress(ProgressBase):
    async def test_report_progress_inside_job_updates_status_and_meta(self):
        gate = asyncio.Event()

        async def runner(_name, _args, _log):
            await job_runner.report_progress({"phase": "extracting", "files": 3})
            await gate.wait()
            return {"success": True, "output": "ok"}

        jid = (await self.reg.spawn("p1", "workspace_upload", {}, runner))["job_id"]
        await asyncio.sleep(0.05)
        self.assertEqual(self.reg.status("p1", jid)["progress"], {"phase": "extracting", "files": 3})
        self.assertEqual(self.meta(jid)["progress"], {"phase": "extracting", "files": 3})
        gate.set()
        await self.reg.wait("p1", jid, 2)
        self.assertEqual(self.meta(jid)["status"], "done")

    async def test_report_progress_outside_job_is_noop(self):
        await job_runner.report_progress({"phase": "x"})  # no job in this task
        self.assertEqual(self.events, [])

    async def test_meta_writes_throttled_to_one_per_second(self):
        clock = iter([0.0, 0.2, 0.5, 0.99, 1.0, 1.5, 2.1])
        writes = []
        real_write = self.reg._write_meta

        def counting(handle):
            writes.append(dict(handle.progress or {}))
            real_write(handle)

        self.reg._write_meta = counting

        async def runner(_name, _args, _log):
            for i in range(7):
                await job_runner.report_progress({"n": i}, now=lambda: next(clock))
            return {"success": True}

        jid = (await self.reg.spawn("p1", "workspace_import", {}, runner))["job_id"]
        await self.reg.wait("p1", jid, 2)
        progress_writes = [w for w in writes if w]
        # t=0.0, t=1.0 and t=2.1 pass the throttle; the final write keeps the last value.
        self.assertEqual(progress_writes[:3], [{"n": 0}, {"n": 4}, {"n": 6}])
        self.assertEqual(self.meta(jid)["progress"], {"n": 6})

    async def test_job_update_event_carries_progress(self):
        async def runner(_name, _args, _log):
            await job_runner.report_progress({"phase": "downloading", "bytes": 10})
            return {"success": True}

        jid = (await self.reg.spawn("p1", "workspace_import", {}, runner))["job_id"]
        await self.reg.wait("p1", jid, 2)
        progress_events = [e for e in self.events if "progress" in e]
        self.assertEqual(progress_events, [{
            "type": "job_update", "project_id": "p1", "job_id": jid,
            "status": "running", "progress": {"phase": "downloading", "bytes": 10},
        }])

    async def test_cancel_before_the_task_starts_marks_cancelled(self):
        # A reset right after a commit cancels a job that never ran a step;
        # it must not stay "running" until the next restart.
        async def runner(_name, _args, _log):
            await asyncio.Event().wait()

        jid = (await self.reg.spawn("p1", "workspace_upload", {}, runner))["job_id"]
        result = await self.reg.cancel("p1", jid)  # no await in between: not started yet
        self.assertEqual(result["status"], "cancelled")
        self.assertEqual(self.meta(jid)["status"], "cancelled")
        self.assertIsNotNone(self.meta(jid)["ended_at"])
        self.assertIn({"type": "job_update", "project_id": "p1", "job_id": jid, "status": "cancelled"},
                      self.events)

    async def test_old_meta_without_progress_loads(self):
        jobs = Path(self.tmp) / "p1" / "jobs"
        jobs.mkdir(parents=True)
        old = {"job_id": "b" * 32, "project_id": "p1", "tool_name": "execute_nuclei", "args": {},
               "label": None, "status": "done", "started_at": "2026-01-01T00:00:00+00:00",
               "ended_at": "2026-01-01T00:01:00+00:00", "exit_code": 0, "output_path": "", "error": None}
        (jobs / f"{'b' * 32}.meta.json").write_text(json.dumps(old))
        self.assertEqual(self.reg.status("p1", "b" * 32)["status"], "done")
        rows = self.reg.list("p1")
        self.assertEqual([r["job_id"] for r in rows], ["b" * 32])
        self.reg.recover_on_boot()  # must not choke on the missing field either


if __name__ == "__main__":
    unittest.main()
