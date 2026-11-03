"""The workspace-import router, mounted on a bare FastAPI app."""
from __future__ import annotations

import asyncio
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fastapi import FastAPI
from fastapi.testclient import TestClient

import job_runner
import workspace_fs
from llm_guard import require_configured_master_auth
from workspace_import import http_routes


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


if __name__ == "__main__":
    unittest.main()
