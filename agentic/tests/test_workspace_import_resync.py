"""Re-sync, the imported flag and the import facts in Properties."""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import time
import unittest
from unittest import mock

import httpx
from fastapi import FastAPI
from fastapi.testclient import TestClient

import job_runner
import workspace_fs
from llm_guard import require_configured_master_auth
from workspace_import import http_routes, provenance

try:  # sibling-test helper; robust to namespace-package shadowing
    from tests.test_workspace_import_runner import REPO_TGZ, RunnerBase, tgz
except ModuleNotFoundError:
    from test_workspace_import_runner import REPO_TGZ, RunnerBase, tgz


class ResyncBase(RunnerBase):
    async def imported(self, url="https://github.com/o/r"):
        _, status = await self.do_import(url)
        self.assertEqual(status["status"], "done", status)
        return status["progress"]["path"]

    def client(self):
        app = FastAPI()
        app.include_router(http_routes.router)
        app.dependency_overrides[require_configured_master_auth] = lambda: None
        return TestClient(app)

    async def resync(self, path, wait=True):
        # The route spawns the job on this test's loop through the router directly.
        from starlette.requests import Request

        body = json.dumps({"projectId": "p1", "path": path}).encode()

        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}

        resp = await http_routes.resync_import(Request({"type": "http", "method": "POST", "headers": []}, receive))
        data = json.loads(resp.body)
        if wait and resp.status_code == 202:
            status = await job_runner.get_registry().wait("p1", data["jobId"], 10)
            return resp.status_code, data, status
        return resp.status_code, data, None


class Resync(ResyncBase):
    async def test_resync_replaces_contents_atomically_same_path(self):
        path = await self.imported()
        (self.root / path / "local-edit.txt").write_text("mine")
        self.world.routes[f"https://codeload.github.com/o/r/tar.gz/7fd1a60b01f91b314f59955a4e4d4e80d8edf11d"] = \
            lambda r: httpx.Response(200, content=tgz([("o-r-7fd1a60/NEW", b"fresh")]))
        code, data, status = await self.resync(path)
        self.assertEqual(code, 202, data)
        self.assertEqual(status["status"], "done", status)
        self.assertEqual(status["progress"]["path"], path)
        self.assertEqual(sorted(os.listdir(self.root / path)), [".import.json", "NEW"])
        self.assertTrue(self.staging_empty())

    async def test_not_imported_404(self):
        (self.root / "uploads/plain").mkdir()
        code, data, _ = await self.resync("uploads/plain")
        self.assertEqual((code, data["code"]), (404, "not_imported"))
        code, data, _ = await self.resync("uploads/missing")
        self.assertEqual(data["code"], "not_imported")

    async def test_invalid_body_never_echoed(self):
        from starlette.requests import Request

        body = b'{"projectId": "p1", "path": ["uploads"], "githubToken": "TEST-SENTINEL-TOKEN-0000"}'

        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}
        resp = await http_routes.resync_import(Request({"type": "http", "method": "POST", "headers": []}, receive))
        self.assertEqual((resp.status_code, json.loads(resp.body)["code"]), (400, "invalid_request"))
        self.assertNotIn(b"TEST-SENTINEL-TOKEN-0000", resp.body)

    async def test_protected_path_refused(self):
        code, data, _ = await self.resync("uploads")
        self.assertEqual((code, data["code"]), (403, "protected_path"))

    async def test_not_resyncable_422(self):
        self.world.routes["https://files.example.test/pack.zip?v=1"] = self.world.routes["https://files.example.test/pack.zip"]
        path = await self.imported("https://files.example.test/pack.zip?v=1")
        code, data, _ = await self.resync(path)
        self.assertEqual((code, data["code"]), (422, "not_resyncable"))

    async def test_edited_provenance_is_not_imported(self):
        path = await self.imported()
        f = self.root / path / ".import.json"
        data = json.loads(f.read_text())
        data["source"]["url"] = "https://evil.example.test/payload.zip"
        f.write_text(json.dumps(data))
        rows = {r["name"]: r for r in workspace_fs.list_dir_page("p1", "uploads", 100)[0]}
        self.assertFalse(rows["r"]["imported"])
        code, body, _ = await self.resync(path)
        self.assertEqual(body["code"], "not_imported")
        self.assertFalse(any("evil" in str(r.url) for r in self.world.seen))

    async def test_forged_provenance_is_ignored(self):
        d = self.root / "uploads/forged"
        d.mkdir()
        (d / ".import.json").write_text(json.dumps({"version": 1, "projectId": "p1", "resyncable": True,
                                                    "source": {"url": "https://evil.example.test/x"}}))
        self.assertEqual((await self.resync("uploads/forged"))[1]["code"], "not_imported")
        (d / ".import.json").write_text(json.dumps({"version": 1, "projectId": "p1", "resyncable": True,
                                                    "source": {"url": "https://evil.example.test/x"},
                                                    "sig": "ab" * 32}))
        self.assertEqual((await self.resync("uploads/forged"))[1]["code"], "not_imported")

    async def test_provenance_copied_from_another_project_is_ignored(self):
        path = await self.imported()
        other = workspace_fs.resolve_for_project("p2", ".")
        shutil.copytree(self.root / path, other / "uploads" / "copied")
        self.assertIsNone(provenance.read(other / "uploads" / "copied", project_id="p2"))
        rows = {r["name"]: r for r in workspace_fs.list_dir_page("p2", "uploads", 100)[0]}
        self.assertFalse(rows["copied"]["imported"])

    async def test_renamed_imported_folder_keeps_provenance(self):
        path = await self.imported()
        workspace_fs.rename_for_project("p1", path, "renamed")
        rows = {r["name"]: r for r in workspace_fs.list_dir_page("p1", "uploads", 100)[0]}
        self.assertTrue(rows["renamed"]["imported"])
        code, data, status = await self.resync("uploads/renamed")
        self.assertEqual((code, status["progress"]["path"]), (202, "uploads/renamed"))

    async def test_weak_master_key_reads_nothing(self):
        path = await self.imported()
        with mock.patch.dict(os.environ, {"INTERNAL_API_KEY": "changeme"}):
            rows = {r["name"]: r for r in workspace_fs.list_dir_page("p1", "uploads", 100)[0]}
            self.assertFalse(rows["r"]["imported"])
            self.assertNotIn("import", workspace_fs.properties_for_project("p1", path))

    async def test_list_marks_imported_dirs(self):
        await self.imported()
        (self.root / "uploads/plain").mkdir()
        rows = {r["name"]: r for r in workspace_fs.list_dir_page("p1", "uploads", 100)[0]}
        self.assertEqual((rows["r"]["imported"], rows["plain"]["imported"]), (True, False))
        self.assertEqual((rows["r"]["importKind"], rows["r"]["resyncable"]), ("github-repo", True))
        self.assertNotIn("importKind", rows["plain"])

    async def test_properties_show_sanitized_import_facts(self):
        path = await self.imported()
        facts = workspace_fs.properties_for_project("p1", path)["import"]
        self.assertEqual(facts, {"kind": "github-repo", "host": "github.com", "sourcePath": "/o/r", "ref": "main",
                                 "commit7": "7fd1a60", "fetchedAt": facts["fetchedAt"], "resyncable": True})
        self.assertEqual(workspace_fs.import_facts({"source": {"kind": "x\nIGNORE", "ref": "a\x1bb"}})["kind"], "x?IGNORE")

    async def test_resync_target_is_busy_for_drawer_and_fs_tools_until_job_ends(self):
        path = await self.imported()
        gate = asyncio.Event()

        async def slow_body():
            await gate.wait()
            yield REPO_TGZ

        self.world.routes["https://codeload.github.com/o/r/tar.gz/7fd1a60b01f91b314f59955a4e4d4e80d8edf11d"] = \
            lambda r: httpx.Response(200, content=slow_body())
        code, data, _ = await self.resync(path, wait=False)
        self.assertEqual(code, 202, data)
        await asyncio.sleep(0.2)
        from workspace_import.errors import ImportFailure
        with self.assertRaises(ImportFailure):
            workspace_fs.rename_for_project("p1", path, "other")
        with self.assertRaises(ImportFailure):
            workspace_fs.check_not_busy("p1", f"{path}/README")
        gate.set()
        await job_runner.get_registry().wait("p1", data["jobId"], 10)
        workspace_fs.check_not_busy("p1", f"{path}/README")

    async def test_resync_target_deleted_from_host_mid_job_is_destination_missing(self):
        path = await self.imported()
        gate = asyncio.Event()

        async def slow_body():
            await gate.wait()
            yield REPO_TGZ

        self.world.routes["https://codeload.github.com/o/r/tar.gz/7fd1a60b01f91b314f59955a4e4d4e80d8edf11d"] = \
            lambda r: httpx.Response(200, content=slow_body())
        code, data, _ = await self.resync(path, wait=False)
        await asyncio.sleep(0.2)
        shutil.rmtree(self.root / path)  # what kali or the host could do
        gate.set()
        status = await job_runner.get_registry().wait("p1", data["jobId"], 10)
        self.assertEqual(status["error"], "destination_missing")
        self.assertFalse((self.root / path).exists())
        self.assertTrue(self.staging_empty())


if __name__ == "__main__":
    unittest.main()
