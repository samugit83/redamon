"""The workspace-import router, mounted on a bare FastAPI app."""
from __future__ import annotations

import asyncio
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from fastapi import FastAPI
from fastapi.testclient import TestClient

import job_runner
import workspace_fs
from llm_guard import require_configured_master_auth
from workspace_import import http_routes, staging, upload_sessions


class RoutesBase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ws-routes-"))
        self._patches = [
            mock.patch.object(workspace_fs, "WORKSPACE_ROOT", self.tmp),
            mock.patch.object(job_runner, "WORKSPACE_ROOT", self.tmp),
            mock.patch.object(job_runner, "_registry", job_runner.JobRegistry()),
        ]
        for p in self._patches:
            p.start()
        self.app = FastAPI()
        self.app.include_router(http_routes.router)
        self.app.dependency_overrides[require_configured_master_auth] = lambda: None
        self.client = TestClient(self.app)

    def tearDown(self):
        for p in reversed(self._patches):
            p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def spawn_done(self, pid):
        async def runner(_n, _a, _log):
            await job_runner.report_progress({"phase": "done", "path": "uploads/x"})
            return {"success": True, "output": "Saved"}

        async def go():
            reg = job_runner.get_registry()
            jid = (await reg.spawn(pid, "workspace_upload", {"name": "x"}, runner,
                                   counts_toward_cap=False))["job_id"]
            await reg.wait(pid, jid, 2)
            return jid
        return asyncio.run(go())


class JobStatusRoute(RoutesBase):
    def test_router_declares_master_auth(self):
        deps = [d.dependency for d in http_routes.router.dependencies]
        self.assertIn(require_configured_master_auth, deps)
        for route in http_routes.router.routes:
            self.assertIn(require_configured_master_auth, [d.dependency for d in route.dependencies],
                          route.path)

    def test_job_status_ok_and_other_project_is_404(self):
        jid = self.spawn_done("p1")
        r = self.client.get(f"/workspace/jobs/{jid}", params={"projectId": "p1"})
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["status"], "done")
        self.assertEqual(body["progress"], {"phase": "done", "path": "uploads/x"})
        self.assertNotIn("tail", body)
        r = self.client.get(f"/workspace/jobs/{jid}", params={"projectId": "p2"})
        self.assertEqual(r.status_code, 404)
        self.assertEqual(r.json()["code"], "not_found")

    def test_bad_job_id_is_404(self):
        for bad in ("x", "A" * 32, "a" * 31, "../" + "a" * 29):
            r = self.client.get(f"/workspace/jobs/{bad}", params={"projectId": "p1"})
            self.assertEqual(r.status_code, 404, bad)
        r = self.client.get(f"/workspace/jobs/{'a' * 32}", params={"projectId": "../etc"})
        self.assertEqual(r.status_code, 404)
        self.assertFalse((self.tmp.parent / "etc" / "jobs").exists())

    def test_unknown_job_is_404(self):
        r = self.client.get(f"/workspace/jobs/{'c' * 32}", params={"projectId": "p1"})
        self.assertEqual(r.status_code, 404)
        self.assertEqual(r.json(), {"error": "Not found.", "code": "not_found"})


class UploadSessionRoutes(RoutesBase):
    def setUp(self):
        super().setUp()
        self._env = mock.patch.dict("os.environ", {"JOB_QUEUE_MIN_FREE_DISK": "0",
                                                   "WORKSPACE_IMPORT_MIN_FREE_BYTES": "1"})
        self._env.start()
        upload_sessions._sessions.clear()
        staging.reset_ledger()
        workspace_fs.resolve_for_project("p1", ".")

    def tearDown(self):
        upload_sessions._sessions.clear()
        staging.reset_ledger()
        self._env.stop()
        super().tearDown()

    def create(self, **over):
        body = {"projectId": "p1", "destDir": "uploads", "name": "a.bin", "size": 6, "kind": "file",
                "onConflict": "keep_both", **over}
        return self.client.post("/workspace/upload-sessions", json=body)

    def test_upload_session_routes_round_trip(self):
        r = self.create()
        self.assertEqual(r.status_code, 201, r.text)
        uid = r.json()["uploadId"]
        put = lambda off, data: self.client.put(f"/workspace/upload-sessions/{uid}/chunk",
                                                params={"projectId": "p1", "offset": off}, content=data)
        self.assertEqual(put(0, b"abc").json(), {"received": 3})
        self.assertEqual(put(0, b"abc").json(), {"received": 3})  # a retried chunk
        bad = put(5, b"x")
        self.assertEqual(bad.status_code, 409)
        self.assertEqual(bad.json()["code"], "offset_mismatch")
        self.assertEqual(bad.json()["expectedOffset"], 3)
        self.assertEqual(put(3, b"def").json(), {"received": 6})
        with mock.patch("workspace_import.project_check.project_exists", mock.AsyncMock(return_value=True)):
            r = self.client.post(f"/workspace/upload-sessions/{uid}/commit", json={"projectId": "p1"})
            self.assertEqual(r.status_code, 202, r.text)
            job = r.json()
            self.assertEqual({k: job[k] for k in ("destDir", "name", "kind", "size")},
                             {"destDir": "uploads", "name": "a.bin", "kind": "file", "size": 6})
            for _ in range(50):
                st = self.client.get(f"/workspace/jobs/{job['jobId']}", params={"projectId": "p1"}).json()
                if st["status"] != "running":
                    break
                time.sleep(0.05)
        self.assertEqual(st["status"], "done", st)
        self.assertEqual((self.tmp / "p1" / "uploads" / "a.bin").read_bytes(), b"abcdef")

    def test_abort_route_is_idempotent(self):
        uid = self.create().json()["uploadId"]
        for _ in range(2):
            r = self.client.delete(f"/workspace/upload-sessions/{uid}", params={"projectId": "p1"})
            self.assertEqual(r.json(), {"aborted": True})
        r = self.client.delete("/workspace/upload-sessions/not-an-id", params={"projectId": "p1"})
        self.assertEqual(r.status_code, 200)

    def test_chunk_over_cap_refused_before_reading(self):
        uid = self.create(size=100).json()["uploadId"]
        with mock.patch.dict("os.environ", {"WORKSPACE_UPLOAD_CHUNK_BYTES": "4"}):
            r = self.client.put(f"/workspace/upload-sessions/{uid}/chunk",
                                params={"projectId": "p1", "offset": 0}, content=b"12345")
        self.assertEqual((r.status_code, r.json()["code"]), (413, "chunk_too_large"))
        r = self.client.put(f"/workspace/upload-sessions/{uid}/chunk",
                            params={"projectId": "p1", "offset": "-1"}, content=b"1")
        self.assertEqual((r.status_code, r.json()["code"]), (400, "invalid_request"))

    def test_errors_are_codes_not_exception_text(self):
        with mock.patch.object(upload_sessions, "create", side_effect=OSError(13, "Permission denied: /secret/path")):
            r = self.create()
        self.assertEqual(r.status_code, 500)
        self.assertEqual(r.json(), {"error": "Something went wrong on the server. Check the agent log.",
                                    "code": "internal_error"})
        self.assertNotIn("/secret/path", r.text)

    def test_invalid_body_answers_invalid_request_without_echo(self):
        sentinel = "TEST-SENTINEL-TOKEN-0000"
        for body in ({"projectId": "p1", "githubToken": sentinel},
                     {"projectId": "p1", "name": "a", "size": "big", "kind": "file", "githubToken": sentinel},
                     sentinel):
            r = self.client.post("/workspace/upload-sessions", json=body)
            self.assertEqual((r.status_code, r.json()["code"]), (400, "invalid_request"))
            self.assertNotIn(sentinel, r.text)
        r = self.client.post("/workspace/upload-sessions", content=b"{not json " + sentinel.encode())
        self.assertEqual(r.status_code, 400)
        self.assertNotIn(sentinel, r.text)
        r = self.client.post(f"/workspace/upload-sessions/{'a' * 32}/commit", json={"githubToken": sentinel})
        self.assertNotIn(sentinel, r.text)


if __name__ == "__main__":
    unittest.main()
