"""Workspace downloads and archive builds stream from disk, as attachments."""
from __future__ import annotations

import asyncio
import io
import os
import shutil
import tarfile
import tempfile
import unittest
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from fastapi.testclient import TestClient

import api
import workspace_fs
from llm_guard import require_configured_master_auth
from workspace_import import busy, executor, staging


class StreamingBase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ws-stream-"))
        self._patches = [mock.patch.object(workspace_fs, "WORKSPACE_ROOT", self.tmp)]
        for p in self._patches:
            p.start()
        self._pool = executor.IMPORT_EXECUTOR
        executor.IMPORT_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="test-import")
        staging.reset_ledger()
        api.app.dependency_overrides[require_configured_master_auth] = lambda: None
        self.client = TestClient(api.app)
        self.root = workspace_fs.resolve_for_project("p1", ".")
        site = self.root / "uploads" / "site"
        (site / "css").mkdir(parents=True)
        (site / "index.html").write_text("<script>alert(1)</script>")
        (site / "css" / "a.css").write_text("body{}")
        (self.root / "uploads" / "big.bin").write_bytes(os.urandom(3 * 1024 * 1024 + 17))

    def tearDown(self):
        api.app.dependency_overrides.pop(require_configured_master_auth, None)
        executor.IMPORT_EXECUTOR.shutdown(wait=True)
        executor.IMPORT_EXECUTOR = self._pool
        staging.reset_ledger()
        for p in reversed(self._patches):
            p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)


class Download(StreamingBase):
    def test_download_streams_the_checked_descriptor(self):
        real_open = os.open
        flags = []

        def recording(path, flag, *a, **kw):
            if str(path).endswith("big.bin"):
                flags.append(flag)
            return real_open(path, flag, *a, **kw)

        with mock.patch("workspace_fs.os.open", recording):
            r = self.client.get("/workspace/download", params={"projectId": "p1", "path": "uploads/big.bin"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.content, (self.root / "uploads/big.bin").read_bytes())
        self.assertEqual(len(flags), 1)
        self.assertTrue(flags[0] & os.O_NOFOLLOW)

    def test_symlink_target_is_refused(self):
        os.symlink("/etc/hostname", self.root / "uploads" / "link")
        r = self.client.get("/workspace/download", params={"projectId": "p1", "path": "uploads/link"})
        self.assertEqual(r.status_code, 400)
        # A component swapped for a symlink after the containment check is
        # refused at open (O_NOFOLLOW) instead of followed.
        with mock.patch.object(workspace_fs, "resolve_for_project",
                               return_value=self.root / "uploads" / "link"):
            with self.assertRaises(ValueError):
                workspace_fs.open_download_for_project("p1", "uploads/link")

    def test_opened_file_outside_the_project_is_refused(self):
        outside = self.tmp / "outside.txt"
        outside.write_text("secret")
        with mock.patch.object(workspace_fs, "resolve_for_project", return_value=outside):
            with self.assertRaises(ValueError):
                workspace_fs.open_download_for_project("p1", "uploads/x")

    def test_download_headers_attachment_and_nosniff(self):
        r = self.client.get("/workspace/download", params={"projectId": "p1", "path": "uploads/site/index.html"})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.headers["content-disposition"].startswith('attachment; filename="index.html"'))
        self.assertIn("filename*=UTF-8''index.html", r.headers["content-disposition"])
        self.assertEqual(r.headers["x-content-type-options"], "nosniff")
        self.assertEqual(r.headers["content-length"], str(len("<script>alert(1)</script>")))

    def test_directory_and_fifo_are_not_files(self):
        os.mkfifo(self.root / "uploads" / "pipe")
        for path in ("uploads/site", "uploads/pipe"):
            r = self.client.get("/workspace/download", params={"projectId": "p1", "path": path})
            self.assertEqual(r.status_code, 400, path)


class Archives(StreamingBase):
    def _no_op_dirs_left(self):
        base = self.tmp / ".staging" / "p1"
        return not base.exists() or not any(base.glob("dl-*"))

    def test_archive_temp_file_removed_after_response(self):
        r = self.client.get("/workspace/archive-download",
                            params={"projectId": "p1", "path": "uploads/site", "format": "tar.gz"})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(self._no_op_dirs_left())
        self.assertEqual(staging.reserved_total(), 0)
        self.assertTrue(r.headers["content-disposition"].startswith('attachment; filename="site.tar.gz"'))
        self.assertEqual(r.headers["x-content-type-options"], "nosniff")

    def test_archive_content_matches_in_memory_variant(self):
        r = self.client.get("/workspace/archive-download",
                            params={"projectId": "p1", "path": "uploads/site", "format": "zip"})
        streamed = zipfile.ZipFile(io.BytesIO(r.content))
        mem_bytes, _ = workspace_fs.archive_dir_for_project("p1", "uploads/site", format="zip")
        in_memory = zipfile.ZipFile(io.BytesIO(mem_bytes))
        self.assertEqual(sorted(streamed.namelist()), sorted(in_memory.namelist()))
        for n in streamed.namelist():
            self.assertEqual(streamed.read(n), in_memory.read(n))

        r = self.client.post("/workspace/bulk-archive",
                             json={"projectId": "p1", "paths": ["uploads/site", "uploads/big.bin"]})
        self.assertEqual(r.status_code, 200)
        with tarfile.open(fileobj=io.BytesIO(r.content), mode="r:gz") as tf:
            names = sorted(tf.getnames())
        self.assertIn("big.bin", names)
        self.assertIn("site/css/a.css", names)
        self.assertTrue(self._no_op_dirs_left())

    def test_archive_build_runs_on_import_pool_and_releases_reservation(self):
        import threading
        threads = []
        real = workspace_fs.write_dir_archive

        def spy(*a, **kw):
            threads.append(threading.current_thread().name)
            return real(*a, **kw)

        reserved = []
        real_reserve = staging.reserve

        def spy_reserve(op_id, nbytes, **kw):
            reserved.append(nbytes)
            return real_reserve(op_id, nbytes, **kw)

        with mock.patch.object(workspace_fs, "write_dir_archive", spy), \
             mock.patch.object(staging, "reserve", spy_reserve):
            r = self.client.get("/workspace/archive-download", params={"projectId": "p1", "path": "uploads/site"})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(threads and threads[0].startswith("test-import"))
        self.assertGreater(reserved[0], len("<script>alert(1)</script>") + len("body{}"))
        self.assertEqual(staging.reserved_total(), 0)

    def test_full_disk_answers_insufficient_storage(self):
        with mock.patch.object(staging, "disk_usage", lambda _p: SimpleNamespace(free=10)):
            r = self.client.get("/workspace/archive-download", params={"projectId": "p1", "path": "uploads/site"})
        self.assertEqual(r.status_code, 413)
        self.assertEqual(r.json()["code"], "insufficient_storage")
        self.assertTrue(self._no_op_dirs_left())

    def test_enospc_while_writing_is_insufficient_storage(self):
        def full(*_a, **_kw):
            raise OSError(28, "No space left on device")

        with mock.patch.object(workspace_fs, "write_bulk_archive", full):
            r = self.client.post("/workspace/bulk-archive", json={"projectId": "p1", "paths": ["uploads/site"]})
        self.assertEqual(r.status_code, 413)
        self.assertEqual(r.json()["code"], "insufficient_storage")
        self.assertNotIn("No space", r.text)
        self.assertTrue(self._no_op_dirs_left())
        self.assertEqual(staging.reserved_total(), 0)


class Listing(StreamingBase):
    def test_list_route_caps_and_reports_total(self):
        for i in range(5):
            (self.root / "notes" / f"n{i}.md").write_text("n")
        r = self.client.get("/workspace/list", params={"projectId": "p1", "path": "notes", "limit": 2})
        body = r.json()
        self.assertEqual(len(body["entries"]), 2)
        self.assertEqual(body["total"], 5)
        self.assertTrue(body["truncated"])
        r = self.client.get("/workspace/list", params={"projectId": "p1", "path": "notes"})
        self.assertFalse(r.json()["truncated"])
        r = self.client.get("/workspace/list", params={"projectId": "p1", "path": "notes", "limit": 10001})
        self.assertEqual(r.status_code, 422)


class BusyFolders(StreamingBase):
    """A Re-sync swaps its whole folder at the end, so an upload or a new
    folder inside it meanwhile would vanish; the routes refuse both and name
    the job holding the folder."""

    JOB = "ab" * 16

    def setUp(self):
        super().setUp()
        busy.register("p1", self.JOB, target="uploads/site", dest_dir="uploads")
        self.addCleanup(busy.clear)

    def test_upload_into_a_busy_folder_is_409_busy_with_the_holder(self):
        r = self.client.post("/workspace/upload", data={"projectId": "p1", "path": "uploads/site/css"},
                             files={"file": ("new.css", b"p{}")})
        self.assertEqual(r.status_code, 409)
        self.assertEqual(r.json()["code"], "busy")
        self.assertEqual(r.json()["jobId"], self.JOB)
        self.assertFalse((self.root / "uploads/site/css/new.css").exists())
        r = self.client.post("/workspace/upload", data={"projectId": "p1", "path": "uploads", "overwrite": "true"},
                             files={"file": ("site", b"x")})
        self.assertEqual((r.status_code, r.json()["code"]), (409, "busy"))
        self.assertTrue((self.root / "uploads/site").is_dir())

    def test_new_folder_inside_a_busy_folder_is_409_busy_with_the_holder(self):
        r = self.client.post("/workspace/mkdir", json={"projectId": "p1", "path": "uploads/site/new"})
        self.assertEqual(r.status_code, 409)
        self.assertEqual(r.json()["code"], "busy")
        self.assertEqual(r.json()["jobId"], self.JOB)
        self.assertFalse((self.root / "uploads/site/new").exists())

    def test_a_sibling_of_the_busy_folder_is_not_busy(self):
        r = self.client.post("/workspace/upload", data={"projectId": "p1", "path": "uploads"},
                             files={"file": ("other.txt", b"o")})
        self.assertEqual(r.status_code, 200, r.text)
        r = self.client.post("/workspace/mkdir", json={"projectId": "p1", "path": "uploads/other"})
        self.assertEqual(r.status_code, 200, r.text)


class DescriptorOwnership(unittest.TestCase):
    """The response owns the descriptor: closed exactly once, even when the
    stream never starts. uvicorn speaks ASGI 2.3, so Starlette races the stream
    against a disconnect listener."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ws-fd-"))
        self.file = self.tmp / "big.bin"
        self.file.write_bytes(b"x" * (3 * 1024 * 1024 + 7))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def serve(self, resp, receive):
        sent = []

        async def send(message):
            sent.append(message)
        scope = {"type": "http", "asgi": {"spec_version": "2.3"}, "method": "GET", "path": "/"}
        asyncio.run(resp(scope, receive, send))
        return sent

    def assertClosed(self, fd):
        with self.assertRaises(OSError):
            os.fstat(fd)

    def test_descriptor_closed_when_the_client_left_before_the_first_byte(self):
        from workspace_import import downloads
        fd = os.open(self.file, os.O_RDONLY)
        resp = downloads.stream_fd(fd, self.file.stat().st_size, "application/octet-stream", "big.bin")

        async def gone():
            return {"type": "http.disconnect"}
        sent = self.serve(resp, gone)
        self.assertFalse(any(m.get("body") for m in sent))
        self.assertClosed(fd)

    def test_full_stream_sends_everything_and_closes_once(self):
        from workspace_import import downloads
        fd = os.open(self.file, os.O_RDONLY)
        resp = downloads.stream_fd(fd, self.file.stat().st_size, "application/octet-stream", "big.bin")

        async def stays():
            await asyncio.Event().wait()
        sent = self.serve(resp, stays)
        body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
        self.assertEqual(body, self.file.read_bytes())
        self.assertClosed(fd)


if __name__ == "__main__":
    unittest.main()
