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


class ResolveRoute(RoutesBase):
    TOKEN = "TEST-SENTINEL-TOKEN-0000"

    def setUp(self):
        super().setUp()
        import httpx
        from workspace_import.fetch import GuardedFetcher
        self.handler = lambda request: httpx.Response(404)
        self.seen_tokens = []

        def factory(github_token=""):
            self.seen_tokens.append(github_token)

            def handle(request):
                return self.handler(request)
            return GuardedFetcher(github_token=github_token, transport=httpx.MockTransport(handle),
                                  assert_safe=lambda _u: None)

        self._factory = mock.patch.object(http_routes, "fetcher_factory", factory)
        self._factory.start()

    def tearDown(self):
        self._factory.stop()
        super().tearDown()

    def resolve(self, url, **extra):
        return self.client.post("/workspace/import-url/resolve", json={"projectId": "p1", "url": url, **extra})

    def test_resolve_answers_kind_details_and_name(self):
        import httpx
        self.handler = lambda r: httpx.Response(200, content=b"PK\x03\x04data",
                                                 headers={"content-type": "application/octet-stream",
                                                          "content-length": "9"})
        r = self.resolve("https://files.example.test/dl/pack.zip?sig=SECRET#frag")
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertEqual((body["kind"], body["suggestedName"], body["host"], body["supported"]),
                         ("archive", "pack", "files.example.test", True))
        self.assertEqual(body["details"], {"contentType": "application/octet-stream", "bytes": 9})

    def test_resolve_redacts_url(self):
        import httpx
        self.handler = lambda r: httpx.Response(200, content=b"%PDF-1.4")
        r = self.resolve("https://files.example.test/paper.pdf?token=SECRET")
        self.assertEqual(r.json()["url"], "https://files.example.test/paper.pdf")
        self.assertNotIn("SECRET", r.text)

    def test_resolve_disabled_is_403(self):
        with mock.patch.dict("os.environ", {"WORKSPACE_URL_IMPORT_ENABLED": "false"}):
            r = self.resolve("https://github.com/o/r")
        self.assertEqual((r.status_code, r.json()["code"]), (403, "import_disabled"))
        self.assertEqual(self.seen_tokens, [])

    def test_resolve_timeout_code(self):
        import httpx

        def slow(request):
            raise httpx.ReadTimeout("slow", request=request)
        self.handler = slow
        r = self.resolve("https://files.example.test/a.zip")
        self.assertEqual(r.json()["code"], "timeout")
        with mock.patch.object(http_routes, "RESOLVE_TIMEOUT_SEC", 0.01), \
             mock.patch.object(http_routes.resolve, "inspect", new=slow_inspect):
            r = self.resolve("https://files.example.test/a.zip")
        self.assertEqual((r.status_code, r.json()["code"]), (422, "timeout"))

    def test_resolve_answers_codes_never_exception_text(self):
        import httpx
        self.handler = lambda r: httpx.Response(200, text="<!doctype html><html>Sign in</html>",
                                                 headers={"content-type": "text/html"})
        r = self.resolve("https://files.example.test/pack.tar.gz")
        self.assertEqual(r.json()["code"], "unexpected_html")
        for url, code in (("ftp://x.test/a", "unsupported_scheme"), ("https://u:p@x.test/a.zip", "credentials_in_url"),
                          ("https://github.com/o/r/issues/3", "kind_not_supported")):
            self.assertEqual(self.resolve(url).json()["code"], code)
        with mock.patch.object(http_routes.resolve, "inspect", side_effect=RuntimeError("boom /secret/x")):
            r = self.resolve("https://files.example.test/a.zip")
        self.assertEqual((r.status_code, r.json()["code"]), (500, "internal_error"))
        self.assertNotIn("/secret/x", r.text)

    def test_github_token_reaches_the_fetcher_only(self):
        import httpx
        sha = "7fd1a60b01f91b314f59955a4e4d4e80d8edf11d"
        api = "https://api.github.com/repos/o/r"
        answers = {api: httpx.Response(200, json={"default_branch": "main", "size": 1, "private": True}),
                   f"{api}/commits/main": httpx.Response(200, text=sha),
                   f"{api}/git/trees/{sha}?recursive=1": httpx.Response(200, json={"tree": [], "truncated": False})}
        auth = []

        def handler(request):
            auth.append(request.headers.get("authorization"))
            return answers.get(str(request.url), httpx.Response(404))
        self.handler = handler
        r = self.resolve("https://github.com/o/r", githubToken=self.TOKEN)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["details"]["private"], True)
        self.assertNotIn(self.TOKEN, r.text)
        self.assertEqual(set(auth), {f"token {self.TOKEN}"})

    def test_invalid_body_never_echoes_token(self):
        for path in ("/workspace/import-url/resolve",):
            for body in ({"projectId": "p1", "githubToken": self.TOKEN},
                         {"url": "https://github.com/o/r", "githubToken": self.TOKEN},
                         {"projectId": 7, "url": "x", "githubToken": self.TOKEN}):
                r = self.client.post(path, json=body)
                self.assertEqual((r.status_code, r.json()["code"]), (400, "invalid_request"))
                self.assertNotIn(self.TOKEN, r.text)


async def slow_inspect(*_a, **_kw):
    import asyncio
    await asyncio.sleep(1)


if __name__ == "__main__":
    unittest.main()
