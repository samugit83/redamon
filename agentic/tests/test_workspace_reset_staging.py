"""Clean all cancels the project's uploads and imports and clears its staging,
and leaves other projects and other jobs alone."""
from __future__ import annotations

import asyncio
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import job_runner
import workspace_fs
from workspace_import import http_routes, staging


class ResetStaging(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ws-reset-"))
        self._patches = [
            mock.patch.object(workspace_fs, "WORKSPACE_ROOT", self.tmp),
            mock.patch.object(job_runner, "WORKSPACE_ROOT", self.tmp),
            mock.patch.object(job_runner, "_registry", job_runner.JobRegistry()),
        ]
        for p in self._patches:
            p.start()
        staging.reset_ledger()

    async def asyncTearDown(self):
        reg = job_runner.get_registry()
        for h in list(reg._jobs.values()):
            if h.task and not h.task.done():
                h.task.cancel()
                try:
                    await h.task
                except (asyncio.CancelledError, Exception):
                    pass
        for p in reversed(self._patches):
            p.stop()
        staging.reset_ledger()
        shutil.rmtree(self.tmp, ignore_errors=True)

    async def test_reset_sweeps_project_staging_and_cancels_import_jobs(self):
        reg = job_runner.get_registry()
        forever = asyncio.Event()

        async def runner(_n, _a, _log):
            await forever.wait()
            return {"success": True}

        up = (await reg.spawn("p1", "workspace_upload", {}, runner, counts_toward_cap=False))["job_id"]
        imp = (await reg.spawn("p1", "workspace_import", {}, runner, counts_toward_cap=False))["job_id"]
        other_tool = (await reg.spawn("p1", "execute_nuclei", {}, runner))["job_id"]
        other_project = (await reg.spawn("p2", "workspace_import", {}, runner, counts_toward_cap=False))["job_id"]
        op1 = staging.new_op_dir("p1", "up")
        op2 = staging.new_op_dir("p2", "imp")
        with mock.patch.object(staging, "disk_usage", lambda _p: type("U", (), {"free": 1 << 50})()):
            staging.reserve(op1.name, 100, project_id="p1")
            staging.reserve(op2.name, 100, project_id="p2")

        cancelled = await http_routes.reset_project_imports("p1")

        self.assertEqual(cancelled, 2)
        self.assertEqual(reg.status("p1", up)["status"], "cancelled")
        self.assertEqual(reg.status("p1", imp)["status"], "cancelled")
        self.assertEqual(reg.status("p1", other_tool)["status"], "running")
        self.assertEqual(reg.status("p2", other_project)["status"], "running")
        self.assertFalse(op1.exists())
        self.assertTrue(op2.exists())
        self.assertEqual(staging.reserved_total(), 100)


if __name__ == "__main__":
    unittest.main()
