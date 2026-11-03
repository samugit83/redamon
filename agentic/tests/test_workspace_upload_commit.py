"""The upload commit job: extract, unwrap, place, and clean up on every path."""
from __future__ import annotations

import asyncio
import io
import json
import os
import shutil
import tarfile
import tempfile
import threading
import time
import unittest
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import job_runner
import workspace_fs
from workspace_import import busy, executor, place, project_check, staging, upload_job, upload_sessions
from workspace_import.errors import ImportFailure

GIB = 1024 ** 3


def tar_bytes(entries, mode="w"):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode, format=tarfile.PAX_FORMAT) as tf:
        for name, data in entries:
            ti = tarfile.TarInfo(name)
            if data is None:
                ti.type = tarfile.DIRTYPE
                tf.addfile(ti)
            else:
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def zip_bytes(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in entries:
            zf.writestr(name, data)
    return buf.getvalue()


class CommitBase(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ws-commit-"))
        self.exists = True
        self.free = 100 * GIB

        async def fake_exists(_pid):
            if isinstance(self.exists, Exception):
                raise self.exists
            return self.exists

        self._patches = [
            mock.patch.object(workspace_fs, "WORKSPACE_ROOT", self.tmp),
            mock.patch.object(job_runner, "WORKSPACE_ROOT", self.tmp),
            mock.patch.object(job_runner, "_registry", job_runner.JobRegistry()),
            mock.patch.object(job_runner, "_governed_max_jobs", return_value=None),
            mock.patch.object(project_check, "project_exists", fake_exists),
            mock.patch.object(staging, "disk_usage", lambda _p: SimpleNamespace(free=self.free)),
            mock.patch.dict(os.environ, {"JOB_QUEUE_MIN_FREE_DISK": "0", "WORKSPACE_IMPORT_MIN_FREE_BYTES": "1",
                                         "WORKSPACE_UPLOAD_CHUNK_BYTES": str(64 * 1024 * 1024)}),
        ]
        for p in self._patches:
            p.start()
        self._pool = executor.IMPORT_EXECUTOR
        executor.IMPORT_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="test-import")
        upload_sessions._sessions.clear()
        staging.reset_ledger()
        busy.clear()
        place._locks.clear()
        self.root = workspace_fs.resolve_for_project("p1", ".")

    async def asyncTearDown(self):
        reg = job_runner.get_registry()
        for h in list(reg._jobs.values()):
            if h.task and not h.task.done():
                h.task.cancel()
                try:
                    await h.task
                except (asyncio.CancelledError, Exception):
                    pass
        executor.IMPORT_EXECUTOR.shutdown(wait=True)
        executor.IMPORT_EXECUTOR = self._pool
        for p in reversed(self._patches):
            p.stop()
        upload_sessions._sessions.clear()
        staging.reset_ledger()
        busy.clear()
        shutil.rmtree(self.tmp, ignore_errors=True)

    async def upload(self, data: bytes, name: str, kind: str, policy="keep_both", dest="uploads"):
        uid = upload_sessions.create("p1", dest, name, len(data), kind, policy)["uploadId"]
        await upload_sessions.write_chunk("p1", uid, 0, data)
        return uid

    async def run_commit(self, data, name, kind, policy="keep_both", dest="uploads"):
        uid = await self.upload(data, name, kind, policy, dest)
        started = await upload_job.commit("p1", uid)
        status = await job_runner.get_registry().wait("p1", started["jobId"], 10)
        return started, status

    def staging_empty(self):
        base = self.tmp / ".staging" / "p1"
        return not base.exists() or not any(base.iterdir())


class Uploads(CommitBase):
    async def test_folder_tar_lands_with_tree_and_long_unicode_names(self):
        long_name = "rapport-" + "é" * 80 + ".txt"
        data = tar_bytes([("site/", None), ("site/a/b/c.txt", b"deep"), ("site/empty.txt", b""),
                          (f"site/{long_name}", b"u"), ("site/emptydir/", None)])
        _, status = await self.run_commit(data, "site", "folder")
        self.assertEqual(status["status"], "done", status)
        self.assertEqual((self.root / "uploads/site/a/b/c.txt").read_bytes(), b"deep")
        self.assertTrue((self.root / f"uploads/site/{long_name}").exists())
        self.assertTrue((self.root / "uploads/site/emptydir").is_dir())
        self.assertTrue(self.staging_empty())

    async def test_folder_keep_both_gives_name_2(self):
        (self.root / "uploads/site").mkdir()
        _, status = await self.run_commit(tar_bytes([("site/x", b"x")]), "site", "folder")
        self.assertEqual(status["progress"]["path"], "uploads/site-2")
        self.assertTrue((self.root / "uploads/site-2/x").exists())

    async def test_replace_policy_swaps(self):
        (self.root / "uploads/site").mkdir()
        (self.root / "uploads/site/old.txt").write_text("old")
        _, status = await self.run_commit(tar_bytes([("site/new.txt", b"n")]), "site", "folder", "replace")
        self.assertEqual(status["status"], "done", status)
        self.assertEqual(sorted(os.listdir(self.root / "uploads/site")), ["new.txt"])

    async def test_fail_policy_job_fails_with_exists(self):
        (self.root / "uploads/site").mkdir()
        _, status = await self.run_commit(tar_bytes([("site/x", b"x")]), "site", "folder", "fail")
        self.assertEqual((status["status"], status["error"]), ("failed", "exists"))
        self.assertTrue(self.staging_empty())

    async def test_archive_single_top_dir_is_unwrapped(self):
        data = tar_bytes([("project-1.2/", None), ("project-1.2/README", b"r")], "w:gz")
        _, status = await self.run_commit(data, "project-1.2", "archive")
        self.assertEqual(status["progress"]["path"], "uploads/project-1.2")
        self.assertEqual(os.listdir(self.root / "uploads/project-1.2"), ["README"])

    async def test_archive_multiple_top_entries_land_in_named_folder(self):
        data = zip_bytes([("a.txt", b"a"), ("b/c.txt", b"c")])
        _, status = await self.run_commit(data, "bundle", "archive")
        self.assertEqual(status["status"], "done", status)
        self.assertEqual(sorted(os.listdir(self.root / "uploads/bundle")), ["a.txt", "b"])

    async def test_large_file_kind_is_placed(self):
        data = os.urandom(200_000)
        _, status = await self.run_commit(data, "dump.bin", "file")
        self.assertEqual(status["progress"]["path"], "uploads/dump.bin")
        self.assertEqual((self.root / "uploads/dump.bin").read_bytes(), data)
        self.assertTrue(self.staging_empty())


class Refusals(CommitBase):
    async def test_traversal_archive_fails_unsafe_path_and_leaves_nothing(self):
        data = zip_bytes([("ok.txt", b"ok"), ("../evil.txt", b"x")])
        _, status = await self.run_commit(data, "trav", "archive")
        self.assertEqual(status["error"], "unsafe_path")
        self.assertFalse((self.root / "uploads/trav").exists())
        self.assertFalse((self.root / "uploads/evil.txt").exists())
        self.assertTrue(self.staging_empty())

    async def test_cancel_mid_extraction_is_cancelled_and_leaves_nothing(self):
        running = threading.Event()
        stopped = []

        def endless(_archive, out, cancel_event=None, **_kw):
            (Path(out) / "partial.bin").write_bytes(b"x" * 1000)
            running.set()
            while not cancel_event.is_set():
                time.sleep(0.01)
            stopped.append(True)
            raise ImportFailure("cancelled")

        with mock.patch.object(upload_job, "safe_extract", endless):
            uid = await self.upload(tar_bytes([("big/f", b"x")]), "big", "folder")
            started = await upload_job.commit("p1", uid)
            await asyncio.to_thread(running.wait, 5)
            status = await job_runner.get_registry().cancel("p1", started["jobId"])
        self.assertEqual(status["status"], "cancelled")
        self.assertEqual(stopped, [True])  # the worker was told to stop and was waited for
        self.assertFalse((self.root / "uploads/big").exists())
        self.assertTrue(self.staging_empty())
        self.assertEqual(staging.reserved_total(), 0)

    async def test_commit_before_complete_is_409(self):
        uid = upload_sessions.create("p1", "uploads", "x.bin", 10, "file", "keep_both")["uploadId"]
        with self.assertRaises(ImportFailure) as ctx:
            await upload_job.commit("p1", uid)
        self.assertEqual((ctx.exception.code, ctx.exception.status), ("session_incomplete", 409))

    async def test_enospc_during_extraction_is_insufficient_storage_and_leaves_nothing(self):
        with mock.patch("workspace_import.extract._copy", side_effect=OSError(28, "No space left on device")):
            _, status = await self.run_commit(tar_bytes([("d/x", b"x")]), "d", "folder")
        self.assertEqual(status["error"], "insufficient_storage")
        self.assertFalse((self.root / "uploads/d").exists())
        self.assertTrue(self.staging_empty())

    async def test_destination_deleted_mid_job_is_destination_missing(self):
        (self.root / "uploads/sub").mkdir()
        uid = await self.upload(tar_bytes([("d/x", b"x")]), "d", "folder", dest="uploads/sub")
        shutil.rmtree(self.root / "uploads/sub")
        started = await upload_job.commit("p1", uid)
        status = await job_runner.get_registry().wait("p1", started["jobId"], 10)
        self.assertEqual(status["error"], "destination_missing")
        self.assertTrue(self.staging_empty())


class Concurrency(CommitBase):
    async def test_extraction_runs_on_import_pool_and_reports_queued_when_full(self):
        threads = []
        real = upload_job.safe_extract

        def spy(*a, **kw):
            threads.append(threading.current_thread().name)
            return real(*a, **kw)

        release = threading.Event()
        held = [executor.submit(release.wait, 5) for _ in range(2)]  # both workers busy
        phases = []
        real_report = job_runner.report_progress

        async def record(progress, **kw):
            phases.append(progress.get("phase"))
            await real_report(progress, **kw)

        with mock.patch.object(upload_job, "safe_extract", spy), \
             mock.patch.object(job_runner, "report_progress", record):
            uid = await self.upload(tar_bytes([("q/x", b"x")]), "q", "folder")
            started = await upload_job.commit("p1", uid)
            await asyncio.sleep(0.6)
            self.assertIn("queued", phases)
            release.set()
            status = await job_runner.get_registry().wait("p1", started["jobId"], 10)
        for h in held:
            h.result(5)
        self.assertEqual(status["status"], "done", status)
        self.assertTrue(threads[0].startswith("test-import"))

    async def test_replace_commit_marks_target_busy_until_done(self):
        (self.root / "uploads/site").mkdir()
        (self.root / "uploads/site/old.txt").write_text("old")
        gate = asyncio.Event()
        real_exists = project_check.project_exists

        async def slow_exists(pid):
            await gate.wait()
            return await real_exists(pid)

        with mock.patch.object(project_check, "project_exists", slow_exists):
            uid = await self.upload(tar_bytes([("site/new.txt", b"n")]), "site", "folder", "replace")
            started = await upload_job.commit("p1", uid)
            await asyncio.sleep(0.3)
            with self.assertRaises(ImportFailure):
                workspace_fs.delete_for_project("p1", "uploads/site/old.txt")
            with self.assertRaises(ImportFailure):
                workspace_fs.check_not_busy("p1", "uploads/site/new-file.txt")  # what fs_write asks
            gate.set()
            await job_runner.get_registry().wait("p1", started["jobId"], 10)
        workspace_fs.check_not_busy("p1", "uploads/site/new-file.txt")
        workspace_fs.delete_for_project("p1", "uploads/site/new.txt")

    async def test_upload_job_does_not_consume_governed_slots(self):
        with mock.patch.object(job_runner, "_governed_max_jobs", return_value=1):
            gate = asyncio.Event()

            async def held(*_a):
                await gate.wait()
                return {"success": True}

            first = await job_runner.get_registry().spawn("p1", "execute_nuclei", {}, held)
            self.assertIn("job_id", first)
            _, status = await self.run_commit(tar_bytes([("g/x", b"x")]), "g", "folder")
            gate.set()
        self.assertEqual(status["status"], "done", status)


class WhatTheJobStores(CommitBase):
    async def test_job_error_is_a_code_and_log_has_no_exception_text(self):
        boom = RuntimeError("secret detail https://user:pw@example.test/x?token=SENTINEL")
        with mock.patch.object(place, "place", side_effect=boom), \
             self.assertLogs("workspace_import.upload_job", "INFO") as logs:
            started, status = await self.run_commit(tar_bytes([("e/x", b"x")]), "e", "folder")
        self.assertEqual(status["error"], "internal_error")
        meta = (self.root / "jobs" / f"{started['jobId']}.meta.json").read_text()
        log = (self.root / "jobs" / f"{started['jobId']}.log").read_text()
        for text in (meta, log, "\n".join(logs.output)):
            self.assertNotIn("secret detail", text)
            self.assertNotIn("SENTINEL", text)
            self.assertNotIn("pw@", text)

    test_unexpected_error_log_has_no_url_query = test_job_error_is_a_code_and_log_has_no_exception_text

    async def test_meta_args_hold_only_declared_fields(self):
        started, _ = await self.run_commit(tar_bytes([("m/x", b"x")]), "m", "folder")
        meta = json.loads((self.root / "jobs" / f"{started['jobId']}.meta.json").read_text())
        self.assertEqual(meta["tool_name"], "workspace_upload")
        self.assertEqual(sorted(meta["args"]), ["destDir", "kind", "name", "onConflict", "size"])
        self.assertFalse(meta["counts_toward_cap"])

    async def test_final_path_in_progress(self):
        started, status = await self.run_commit(tar_bytes([("p/x", b"x")]), "p", "folder")
        self.assertEqual(status["progress"]["phase"], "done")
        self.assertEqual(status["progress"]["path"], "uploads/p")
        log = (self.root / "jobs" / f"{started['jobId']}.log").read_text()
        self.assertIn("Saved as uploads/p: 1 files", log)

    async def test_reservation_released_when_job_ends_any_status(self):
        await self.run_commit(tar_bytes([("ok/x", b"x")]), "ok", "folder")
        self.assertEqual(staging.reserved_total(), 0)
        await self.run_commit(zip_bytes([("../x", b"x")]), "bad", "archive")
        self.assertEqual(staging.reserved_total(), 0)
        (self.root / "uploads/f").mkdir()
        await self.run_commit(tar_bytes([("f/x", b"x")]), "f", "folder", "fail")
        self.assertEqual(staging.reserved_total(), 0)

    async def test_commit_answer_carries_session_facts(self):
        started, _ = await self.run_commit(tar_bytes([("facts/x", b"x")]), "facts", "folder")
        self.assertEqual({k: started[k] for k in ("destDir", "name", "kind")},
                         {"destDir": "uploads", "name": "facts", "kind": "folder"})
        self.assertEqual(started["size"], len(tar_bytes([("facts/x", b"x")])))
        self.assertRegex(started["jobId"], r"^[0-9a-f]{32}$")

    async def test_deleted_project_job_fails_and_leaves_nothing(self):
        self.exists = False
        _, status = await self.run_commit(tar_bytes([("gone/x", b"x")]), "gone", "folder")
        self.assertEqual(status["error"], "project_deleted")
        self.assertFalse((self.root / "uploads/gone").exists())
        self.assertTrue(self.staging_empty())

    async def test_project_check_failure_fails_closed(self):
        self.exists = project_check.ProjectCheckFailed("status 500")
        _, status = await self.run_commit(tar_bytes([("x/x", b"x")]), "x", "folder")
        self.assertEqual(status["error"], "settings_unavailable")
        self.assertFalse((self.root / "uploads/x").exists())

    async def test_success_log_line(self):
        with self.assertLogs("workspace_import.upload_job", "INFO") as logs:
            started, _ = await self.run_commit(tar_bytes([("s/x", b"xy")]), "s", "folder")
        line = next(l for l in logs.output if "done project=" in l)
        self.assertIn(f"job={started['jobId']} kind=upload-folder path=uploads/s files=1 bytes=2", line)

    async def test_too_many_jobs_keeps_the_session_for_a_retry(self):
        with mock.patch.dict(os.environ, {"WORKSPACE_IMPORT_MAX_JOBS": "1"}):
            gate = asyncio.Event()

            async def held(*_a):
                await gate.wait()
                return {"success": True}

            await job_runner.get_registry().spawn("p1", "workspace_import", {}, held, counts_toward_cap=False)
            uid = await self.upload(tar_bytes([("r/x", b"x")]), "r", "folder")
            with self.assertRaises(ImportFailure) as ctx:
                await upload_job.commit("p1", uid)
            self.assertEqual(ctx.exception.code, "too_many_jobs")
            self.assertIn(uid, upload_sessions._sessions)
            gate.set()


if __name__ == "__main__":
    unittest.main()
