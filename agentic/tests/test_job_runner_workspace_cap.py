"""Upload and import jobs never take the governed background-job slots that the
agent's job_spawn and MCP kali exec rely on; they have their own cap."""
from __future__ import annotations

import asyncio
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import job_runner


class CapBase(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="jobs-cap-")
        self._orig_root = job_runner.WORKSPACE_ROOT
        job_runner.WORKSPACE_ROOT = Path(self.tmp)
        self.reg = job_runner.JobRegistry()
        self.release = asyncio.Event()

    async def asyncTearDown(self):
        self.release.set()
        for h in list(self.reg._jobs.values()):
            if h.task and not h.task.done():
                h.task.cancel()
                try:
                    await h.task
                except (asyncio.CancelledError, Exception):
                    pass
        job_runner.WORKSPACE_ROOT = self._orig_root
        shutil.rmtree(self.tmp, ignore_errors=True)

    async def runner(self, _name, _args, _log):
        await self.release.wait()
        return {"success": True}

    async def spawn(self, pid="p1", tool="execute_nuclei", **kw):
        return await self.reg.spawn(pid, tool, {}, self.runner, **kw)


class WorkspaceCap(CapBase):
    async def test_import_jobs_do_not_consume_governed_slots(self):
        with mock.patch.object(job_runner, "_governed_max_jobs", return_value=2), \
             mock.patch.dict(os.environ, {"WORKSPACE_IMPORT_MAX_JOBS": "4"}):
            for _ in range(4):
                r = await self.spawn(tool="workspace_import", counts_toward_cap=False)
                self.assertIn("job_id", r)
            # Both governed slots are still free for the agent / kali exec.
            self.assertIn("job_id", await self.spawn())
            self.assertIn("job_id", await self.spawn())
            refused = await self.spawn()
            self.assertEqual(refused.get("limitType"), "ram")

    async def test_workspace_job_global_cap(self):
        with mock.patch.object(job_runner, "_governed_max_jobs", return_value=None), \
             mock.patch.dict(os.environ, {"WORKSPACE_IMPORT_MAX_JOBS": "3"}):
            for pid in ("p1", "p2", "p3"):  # across projects
                self.assertIn("job_id", await self.spawn(pid, "workspace_upload", counts_toward_cap=False))
            refused = await self.spawn("p4", "workspace_import", counts_toward_cap=False)
            self.assertEqual(refused.get("limitType"), "workspace")
            self.assertNotIn("job_id", refused)
            # Governed jobs are not limited by the workspace cap.
            self.assertIn("job_id", await self.spawn("p4"))

    async def test_finished_workspace_jobs_free_their_slot(self):
        with mock.patch.dict(os.environ, {"WORKSPACE_IMPORT_MAX_JOBS": "1"}):
            first = await self.spawn(tool="workspace_import", counts_toward_cap=False)
            self.release.set()
            await self.reg.wait("p1", first["job_id"], 2)
            self.release.clear()
            self.assertIn("job_id", await self.spawn(tool="workspace_import", counts_toward_cap=False))

    async def test_default_spawn_unchanged(self):
        with mock.patch.object(job_runner, "_governed_max_jobs", return_value=1):
            self.assertIn("job_id", await self.spawn())
            refused = await self.spawn()
        self.assertEqual(refused["limitType"], "ram")
        h = next(iter(self.reg._jobs.values()))
        self.assertTrue(h.counts_toward_cap)
        self.assertTrue(self.reg.status("p1", h.job_id)["counts_toward_cap"])


if __name__ == "__main__":
    unittest.main()
