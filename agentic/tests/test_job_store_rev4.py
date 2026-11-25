"""FU-29 rev 4, the job store side (round 2 of rev 2's review).

- A flood of planted records must neither hold a drawer poll or the boot, nor
  hide the agent's own jobs, nor silence the refusal log for good.
- A refused spawn answers with its code, so a caller can tell a refused jobs/
  folder from a full queue; the uploads and imports no longer report it as
  too_many_jobs (an endless retry).
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import job_runner  # noqa: E402
from workspace_import import errors  # noqa: E402


class _Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="jobs-rev4-"))
        self.root = self.tmp / "workspace"
        self.jobs = self.root / "p1" / "jobs"
        self.jobs.mkdir(parents=True)
        self._orig = job_runner.WORKSPACE_ROOT
        job_runner.WORKSPACE_ROOT = self.root
        job_runner._REFUSALS_LOGGED.clear()
        if hasattr(job_runner, "_refusal_window"):
            job_runner._refusal_window.update(start=0.0, lines=0, suppressed=0)

    def tearDown(self):
        job_runner.WORKSPACE_ROOT = self._orig
        shutil.rmtree(self.tmp, ignore_errors=True)

    def plant(self, n, status="running", started="2099"):
        rec = json.dumps({"job_id": "x", "status": status, "started_at": started}).encode()
        for i in range(n):
            fd = os.open(self.jobs / f"x{i}.meta.json", os.O_WRONLY | os.O_CREAT, 0o644)
            if i < 2000:
                os.write(fd, rec)
            os.close(fd)

    def real_job(self, status="done"):
        job_id = uuid.uuid4().hex
        (self.jobs / f"{job_id}.meta.json").write_text(json.dumps(
            {"job_id": job_id, "status": status, "started_at": "2026-01-01T00:00:00+00:00"}))
        os.utime(self.jobs / f"{job_id}.meta.json", (1, 1))  # older than every planted record
        return job_id


class AFloodOfPlantedRecords(_Base):
    def test_a_drawer_poll_stays_fast_and_still_shows_the_real_job(self):
        job_id = self.real_job()
        reg = job_runner.JobRegistry()
        reg.recover_on_boot()  # after a restart, the agent's records are the ones recovered
        self.plant(50_000)
        t = time.time()
        rows = reg.list("p1")
        took = time.time() - t
        self.assertLess(took, 0.5, f"one drawer poll took {took:.2f}s")
        self.assertIn(job_id, [r.get("job_id") for r in rows], "the flood hid the agent's own job")

    def test_boot_stays_bounded_and_logs_a_summary(self):
        job_id = self.real_job(status="running")
        self.plant(50_000)
        with self.assertLogs(job_runner.logger, "WARNING") as logs:
            job_runner.JobRegistry().recover_on_boot()
            job_runner.logger.warning("sentinel")
        self.assertLess(len(logs.output), 20, f"boot logged {len(logs.output)} lines")
        data = json.loads((self.jobs / f"{job_id}.meta.json").read_text())
        self.assertEqual(data["status"], "interrupted", "the agent's own running job was not recovered")

    def test_the_refusal_log_is_never_silenced_for_good(self):
        for i in range(1001):
            (self.jobs / f"y{i}.meta.json").symlink_to("/nonexistent")
        job_runner.JobRegistry().recover_on_boot()
        (self.jobs / "late.meta.json").symlink_to("/etc/hostname")
        with self.assertLogs(job_runner.logger, "WARNING") as logs:
            job_runner.JobRegistry().list("p1")
            job_runner.logger.warning("sentinel")
        self.assertTrue(any("late.meta.json" in line for line in logs.output), logs.output)

    def test_a_burst_of_refusals_is_summarized(self):
        for i in range(200):
            (self.jobs / f"z{i}.meta.json").symlink_to("/nonexistent")
        with self.assertLogs(job_runner.logger, "WARNING") as logs:
            job_runner.JobRegistry().list("p1")
            job_runner._refusal_window["start"] -= 61  # the next minute opens
            job_runner.note_refusal("p1", "after.meta.json", ValueError("planted"))
        self.assertLess(len(logs.output), 80)
        self.assertTrue(any("not logged one by one" in line for line in logs.output), logs.output)
        self.assertTrue(any("after.meta.json" in line for line in logs.output))


class ListAsync(unittest.IsolatedAsyncioTestCase):
    async def test_the_route_reads_the_disk_off_the_event_loop(self):
        reg = job_runner.JobRegistry()
        seen = []
        real = reg._with_disk_rows

        def spy(*a):
            import threading
            seen.append(threading.current_thread() is threading.main_thread())
            return real(*a)

        with mock.patch.object(reg, "_with_disk_rows", spy):
            await reg.list_async("p-none")
        self.assertEqual(seen, [False])


class SpawnRefusalsCarryTheirCode(unittest.IsolatedAsyncioTestCase):
    async def test_each_refusal_has_its_code(self):
        reg = job_runner.JobRegistry()
        with tempfile.TemporaryDirectory() as tmp:
            outside = Path(tmp) / "outside"
            outside.mkdir()
            with mock.patch.object(job_runner, "WORKSPACE_ROOT", Path(tmp) / "ws"):
                (Path(tmp) / "ws" / "p1").mkdir(parents=True)
                (Path(tmp) / "ws" / "p1" / "jobs").symlink_to(outside)
                refused = await reg.spawn("p1", "x", {}, None)
                bad = await reg.spawn("../p", "x", {}, None)
                with mock.patch.object(job_runner, "_create_file", side_effect=OSError(28, "full")):
                    (Path(tmp) / "ws" / "p2").mkdir()
                    failed = await reg.spawn("p2", "x", {}, None)
        self.assertEqual((refused.get("code"), bad.get("code"), failed.get("code")),
                         ("job_store_refused", "invalid_project_id", "job_store_error"))

    def test_imports_map_them_to_a_clear_refusal(self):
        self.assertEqual(errors.spawn_refusal({"error": "x", "code": "job_store_refused"}).code,
                         "jobs_folder_refused")
        self.assertEqual(errors.spawn_refusal({"error": "x", "code": "job_store_error"}).code,
                         "job_store_error")
        self.assertEqual(errors.spawn_refusal({"error": "Too many", "limitType": "workspace"}).code,
                         "too_many_jobs")


class KaliExecAnswersCarryTheCode(unittest.IsolatedAsyncioTestCase):
    """P4's kaliClient maps a refused spawn by `code` first."""

    async def test_each_status_comes_with_its_code(self):
        import api
        import sandbox_router
        from sandbox_route_fakes import WEBAPP, Fleet

        sandbox_router._reset()
        fleet = Fleet()
        fleet.add("alice")
        patches = [
            mock.patch.object(api, "orchestrator", mock.Mock(tool_executor=mock.Mock())),
            mock.patch.object(sandbox_router, "_transport", fleet.transport()),
            mock.patch.dict(sandbox_router.INTERNAL_HEADERS, {"X-Internal-Key": "test-internal-key"}),
            mock.patch.object(sandbox_router, "WEBAPP_API_URL", WEBAPP),
        ]
        for p in patches:
            p.start()
        try:
            for code, status in (("job_store_error", 503), ("job_store_refused", 409),
                                 ("invalid_project_id", 400)):
                reg = mock.Mock()

                async def spawn(*_a, code=code, **_kw):
                    return {"error": "refused", "code": code}

                reg.spawn = spawn
                with mock.patch.object(api.job_runner, "get_registry", return_value=reg):
                    resp = await api.kali_exec(api.KaliExecRequest(project_id="p1", command="id",
                                                                    user_id="alice"))
                body = json.loads(bytes(resp.body).decode())
                self.assertEqual((resp.status_code, body.get("code")), (status, code))
        finally:
            await sandbox_router._shutdown()
            for p in reversed(patches):
                p.stop()
            sandbox_router._reset()


if __name__ == "__main__":
    unittest.main()
