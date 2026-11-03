"""POST /workspace/project-purge acts only on a project the web app answers 404 for."""
from __future__ import annotations

import asyncio
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import httpx
from fastapi import FastAPI
from fastapi.testclient import TestClient

import job_runner
import workspace_fs
from llm_guard import require_configured_master_auth
from workspace_import import http_routes, project_check, staging, upload_sessions


class PurgeBase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ws-purge-"))
        self.webapp_status = 404
        self.webapp_calls = []

        def handler(request: httpx.Request) -> httpx.Response:
            self.webapp_calls.append((str(request.url), request.headers.get("x-internal-key")))
            if self.webapp_status == "timeout":
                raise httpx.ReadTimeout("slow", request=request)
            return httpx.Response(self.webapp_status, json={})

        self._patches = [
            mock.patch.object(workspace_fs, "WORKSPACE_ROOT", self.tmp),
            mock.patch.object(job_runner, "WORKSPACE_ROOT", self.tmp),
            mock.patch.object(job_runner, "_registry", job_runner.JobRegistry()),
            mock.patch.object(project_check, "TRANSPORT", httpx.MockTransport(handler)),
            mock.patch.dict(os.environ, {"WEBAPP_API_URL": "http://webapp.test", "INTERNAL_API_KEY": "k-test",
                                         "JOB_QUEUE_MIN_FREE_DISK": "0"}),
        ]
        for p in self._patches:
            p.start()
        upload_sessions._sessions.clear()
        staging.reset_ledger()
        self.app = FastAPI()
        self.app.include_router(http_routes.router)
        self.app.dependency_overrides[require_configured_master_auth] = lambda: None
        self.client = TestClient(self.app)
        self.root = workspace_fs.resolve_for_project("gone", ".")
        (self.root / "uploads" / "big").mkdir()
        (self.root / "uploads" / "big" / "f.txt").write_text("x")

    def tearDown(self):
        for p in reversed(self._patches):
            p.stop()
        upload_sessions._sessions.clear()
        staging.reset_ledger()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def purge(self, pid="gone"):
        return self.client.post("/workspace/project-purge", json={"projectId": pid})


class Purge(PurgeBase):
    def test_purge_refuses_a_live_project(self):
        self.webapp_status = 200
        r = self.purge()
        self.assertEqual((r.status_code, r.json()["code"]), (409, "project_exists"))
        self.assertTrue((self.root / "uploads/big/f.txt").exists())
        self.assertEqual(self.webapp_calls, [("http://webapp.test/api/projects/gone", "k-test")])

    def test_purge_fails_closed_when_the_webapp_fails(self):
        for status in ("timeout", 500, 401):
            self.webapp_status = status
            r = self.purge()
            self.assertEqual((r.status_code, r.json()["code"]), (503, "settings_unavailable"), status)
            self.assertTrue((self.root / "uploads/big/f.txt").exists())

    def test_purge_cancels_jobs_sessions_and_removes_root_and_staging(self):
        async def forever(*_a):
            await asyncio.Event().wait()

        async def setup():
            reg = job_runner.get_registry()
            await reg.spawn("gone", "execute_nuclei", {}, forever)
            await reg.spawn("gone", "workspace_import", {}, forever, counts_toward_cap=False)
            return reg

        # Run the jobs on the TestClient's event loop so cancel() can await them.
        with self.client as client:
            reg = client.portal.call(setup)
            uid = upload_sessions.create("gone", "uploads", "a.bin", 4, "file", "keep_both")["uploadId"]
            other = workspace_fs.resolve_for_project("alive", ".")
            r = client.post("/workspace/project-purge", json={"projectId": "gone"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["cancelledJobs"], 2)
        self.assertEqual(sorted(r.json()["removed"]), ["staging", "workspace"])
        self.assertFalse((self.tmp / "gone").exists())
        self.assertFalse((self.tmp / ".staging" / "gone").exists())
        self.assertNotIn(uid, upload_sessions._sessions)
        self.assertEqual(staging.reserved_total(), 0)
        self.assertTrue(other.exists())
        self.assertTrue(all(h.status != "running" for h in reg._jobs.values()))

    def test_purge_unlinks_a_symlinked_root_without_following_it(self):
        elsewhere = self.tmp.parent / f"{self.tmp.name}-elsewhere"
        elsewhere.mkdir()
        (elsewhere / "keep.txt").write_text("not ours")
        shutil.rmtree(self.root)
        os.symlink(elsewhere, self.tmp / "gone")
        try:
            r = self.purge()
            self.assertEqual(r.status_code, 200, r.text)
            self.assertFalse((self.tmp / "gone").is_symlink())
            self.assertTrue((elsewhere / "keep.txt").exists())
        finally:
            shutil.rmtree(elsewhere, ignore_errors=True)

    def test_purge_refuses_invalid_project_ids(self):
        for bad in ("../x", ".staging", "", "a/b"):
            r = self.purge(bad)
            self.assertEqual((r.status_code, r.json()["code"]), (400, "invalid_request"), bad)
        self.assertEqual(self.webapp_calls, [])

    def test_purge_requires_master_key(self):
        route = next(r for r in http_routes.router.routes if r.path == "/workspace/project-purge")
        self.assertIn(require_configured_master_auth, [d.dependency for d in route.dependencies])
        app = FastAPI()
        app.include_router(http_routes.router)
        with mock.patch.dict(os.environ, {"INTERNAL_API_KEY": "a-strong-master-key"}):
            r = TestClient(app).post("/workspace/project-purge", json={"projectId": "gone"})
        self.assertEqual(r.status_code, 401)
        self.assertTrue((self.root / "uploads/big/f.txt").exists())


if __name__ == "__main__":
    unittest.main()
