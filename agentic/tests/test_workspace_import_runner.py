"""The URL import job, end to end on a canned GitHub/forge/file server."""
from __future__ import annotations

import asyncio
import io
import json
import os
import shutil
import tarfile
import tempfile
import time
import unittest
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import httpx
from fastapi import FastAPI
from fastapi.testclient import TestClient

import job_runner
import workspace_fs
from llm_guard import require_configured_master_auth
from workspace_import import (busy, executor, http_routes, mirror, mirror_rules, place, project_check, provenance,
                              resolve, runner, staging)
from workspace_import.errors import ImportFailure
from workspace_import.fetch import GuardedFetcher

GIB = 1024 ** 3
SHA = "7fd1a60b01f91b314f59955a4e4d4e80d8edf11d"
API = "https://api.github.com/repos/o/r"
TOKEN = "TEST-SENTINEL-TOKEN-0000"


def tgz(entries):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in entries:
            ti = tarfile.TarInfo(name)
            if data is None:
                ti.type = tarfile.DIRTYPE
                tf.addfile(ti)
            else:
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def zipb(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in entries:
            zf.writestr(name, data)
    return buf.getvalue()


REPO_TGZ = tgz([("o-r-7fd1a60/", None), ("o-r-7fd1a60/README", b"hello"),
                ("o-r-7fd1a60/docs/a.md", b"aaa"), ("o-r-7fd1a60/docs/sub/b.md", b"bb"),
                ("o-r-7fd1a60/.import.json", b'{"version":1,"source":{"url":"https://evil.example.test"}}')])
TREE = {"tree": [{"path": "README", "type": "blob", "size": 5, "mode": "100644"},
                 {"path": "docs", "type": "tree", "mode": "040000"},
                 {"path": "docs/a.md", "type": "blob", "size": 3, "mode": "100644"},
                 {"path": "docs/sub", "type": "tree", "mode": "040000"},
                 {"path": "docs/sub/b.md", "type": "blob", "size": 2, "mode": "100644"}],
        "truncated": False}


class World:
    """The fake internet: URL -> response factory, with a request log."""

    def __init__(self):
        self.seen: list[httpx.Request] = []
        self.routes = {
            API: lambda r: httpx.Response(200, json={"default_branch": "main", "size": 1, "private": False}),
            f"{API}/commits/main": lambda r: httpx.Response(200, text=SHA),
            f"{API}/git/trees/{SHA}?recursive=1": lambda r: httpx.Response(200, json=TREE),
            f"https://codeload.github.com/o/r/tar.gz/{SHA}": lambda r: httpx.Response(200, content=REPO_TGZ),
            f"{API}/tarball/{SHA}": lambda r: httpx.Response(302, headers={
                "location": f"https://codeload.github.com/o/r/legacy.tar.gz/{SHA}?token=TEMPTOKEN"}),
            f"https://codeload.github.com/o/r/legacy.tar.gz/{SHA}?token=TEMPTOKEN": lambda r: httpx.Response(200, content=REPO_TGZ),
            f"https://raw.githubusercontent.com/o/r/{SHA}/docs/a.md": lambda r: httpx.Response(200, content=b"aaa"),
            f"https://raw.githubusercontent.com/o/r/{SHA}/docs/sub/b.md": lambda r: httpx.Response(200, content=b"bb"),
            "https://raw.githubusercontent.com/o/r/main/README": lambda r: httpx.Response(
                200, content=b"hello", headers={"content-type": "text/plain"}),
            "https://api.github.com/gists/abcdef12": lambda r: httpx.Response(200, json={"files": {
                "a.py": {"raw_url": "https://gist.githubusercontent.com/u/abcdef12/raw/1/a.py", "size": 2}}}),
            "https://gist.githubusercontent.com/u/abcdef12/raw/1/a.py": lambda r: httpx.Response(200, content=b"pa"),
            "https://codeberg.org/api/v1/repos/o/r": lambda r: httpx.Response(200, json={"default_branch": "main"}),
            "https://codeberg.org/o/r/archive/main.tar.gz": lambda r: httpx.Response(
                200, content=tgz([("r/", None), ("r/x.txt", b"x")])),
            "https://files.example.test/pack.zip": lambda r: httpx.Response(
                200, content=zipb([("pack/one.txt", "1"), ("pack/two.txt", "2")]),
                headers={"content-type": "application/zip"}),
            "https://files.example.test/paper.pdf": lambda r: httpx.Response(
                200, content=b"%PDF-1.4 x", headers={"content-type": "application/pdf"}),
            "https://www.example.test/": lambda r: httpx.Response(
                200, content=b"<!doctype html><html>site</html>", headers={"content-type": "text/html"}),
        }

    def handler(self, request):
        self.seen.append(request)
        route = self.routes.get(str(request.url))
        return route(request) if route else httpx.Response(404)

    def factory(self, github_token=""):
        return GuardedFetcher(github_token=github_token, transport=httpx.MockTransport(self.handler),
                              assert_safe=lambda _u: None)


class RunnerBase(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ws-runner-"))
        self.world = World()
        self.exists = True
        self.free = 100 * GIB

        async def fake_exists(_pid):
            return self.exists

        self._patches = [
            mock.patch.object(workspace_fs, "WORKSPACE_ROOT", self.tmp),
            mock.patch.object(job_runner, "WORKSPACE_ROOT", self.tmp),
            mock.patch.object(job_runner, "_registry", job_runner.JobRegistry()),
            mock.patch.object(job_runner, "_governed_max_jobs", return_value=None),
            mock.patch.object(project_check, "project_exists", fake_exists),
            mock.patch.object(staging, "disk_usage", lambda _p: SimpleNamespace(free=self.free)),
            mock.patch.object(runner, "fetcher_factory", self.world.factory),
            mock.patch.object(http_routes, "fetcher_factory", self.world.factory),
            mock.patch.dict(os.environ, {"JOB_QUEUE_MIN_FREE_DISK": "0", "WORKSPACE_IMPORT_MIN_FREE_BYTES": "1",
                                         "INTERNAL_API_KEY": "a-strong-test-master-key"}),
        ]
        for p in self._patches:
            p.start()
        self._pool = executor.IMPORT_EXECUTOR
        executor.IMPORT_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="test-import")
        staging.reset_ledger()
        busy.clear()
        place._locks.clear()
        runner._running.clear()
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
        staging.reset_ledger()
        busy.clear()
        runner._running.clear()
        shutil.rmtree(self.tmp, ignore_errors=True)

    async def start(self, url, *, name=None, dest="uploads", policy="keep_both", options=None, token=""):
        async with self.world.factory(github_token=token) as f:
            insp = await resolve.inspect(url, f, subpath=(options or {}).get("subpath"))
        spec = runner.ImportSpec(url=url, dest_dir=dest, name=name or insp.name, on_conflict=policy,
                                 options=options or {})
        return await runner.start(spec, insp, project_id="p1", github_token=token)

    async def do_import(self, url, **kw):
        started = await self.start(url, **kw)
        status = await job_runner.get_registry().wait("p1", started["jobId"], 10)
        return started, status

    def staging_empty(self):
        base = self.tmp / ".staging" / "p1"
        return not base.exists() or not any(base.iterdir())

    def tree(self, rel):
        base = self.root / rel
        return sorted(str(p.relative_to(base)) for p in base.rglob("*"))


class Successful(RunnerBase):
    async def test_whole_repo_unwrapped_with_provenance(self):
        started, status = await self.do_import("https://github.com/o/r")
        self.assertEqual(status["status"], "done", status)
        self.assertEqual(status["progress"]["path"], "uploads/r")
        self.assertEqual(self.tree("uploads/r"), [".import.json", "README", "docs", "docs/a.md", "docs/sub", "docs/sub/b.md"])
        rec = provenance.read(self.root / "uploads/r", project_id="p1")
        self.assertEqual(rec["source"]["commit"], SHA)
        self.assertEqual((rec["source"]["ref"], rec["source"]["kind"]), ("main", "github-repo"))
        self.assertEqual(rec["stats"]["files"], 3)
        self.assertTrue(rec["resyncable"])
        self.assertTrue(self.staging_empty())

    async def test_archive_shipping_its_own_import_json_gets_only_ours(self):
        await self.do_import("https://github.com/o/r")
        rec = provenance.read(self.root / "uploads/r", project_id="p1")
        self.assertEqual(rec["source"]["url"], "https://github.com/o/r")
        self.assertNotIn("evil", (self.root / "uploads/r/.import.json").read_text())

    async def test_subfolder_raw_strategy_only_subtree(self):
        _, status = await self.do_import("https://github.com/o/r/tree/main/docs")
        self.assertEqual(status["status"], "done", status)
        self.assertEqual(self.tree("uploads/docs"), [".import.json", "a.md", "sub", "sub/b.md"])
        self.assertFalse(any("codeload" in str(r.url) for r in self.world.seen))
        rec = provenance.read(self.root / "uploads/docs", project_id="p1")
        self.assertEqual(rec["source"]["subpath"], "docs")

    async def test_github_preview_details_and_warnings(self):
        async with self.world.factory() as f:
            answer = (await resolve.inspect("https://github.com/o/r", f)).answer()
        self.assertEqual((answer["kind"], answer["suggestedName"], answer["host"]), ("github-repo", "r", "github.com"))
        self.assertEqual(answer["details"], {"ref": "main", "sha7": "7fd1a60", "files": 3, "bytes": 10,
                                             "subpath": "", "private": False})
        self.assertEqual(answer["warnings"], ["history_not_included"])
        self.world.routes[f"{API}/git/trees/{SHA}?recursive=1"] = lambda r: httpx.Response(
            200, json=dict(TREE, truncated=True))
        async with self.world.factory() as f:
            self.assertIn("tree_truncated", (await resolve.inspect("https://github.com/o/r", f)).warnings)

    async def test_failure_logs_a_code_never_exception_text_or_query(self):
        hits = {"n": 0}

        def flaky(_r):
            hits["n"] += 1  # the preview's probe passes, the job's download fails
            if hits["n"] == 1:
                return httpx.Response(200, content=zipb([("p/a.txt", "1")]), headers={"content-type": "application/zip"})
            return httpx.Response(503)
        url = "https://files.example.test/pack.zip?token=SECRET-QUERY-VALUE"
        self.world.routes[url] = flaky
        with self.assertLogs("workspace_import.runner", "INFO") as logs:
            _, status = await self.do_import(url)
        self.assertEqual(status["error"], "upstream_status")
        line = next(l for l in logs.output if "code=upstream_status" in l)
        self.assertIn("kind=archive", line)
        self.assertNotIn("SECRET-QUERY-VALUE", "\n".join(logs.output))

        # Built at run time: a logged frame shows its source line, never the values.
        message = "-".join(("SECRET", "IN", "MESSAGE")) + " https://x.example.test/?token=" + "SECRET-QUERY-VALUE"

        async def boom(*_a, **_k):
            raise RuntimeError(message)
        with mock.patch.object(runner, "_fetch_into", boom), self.assertLogs("workspace_import.runner", "INFO") as logs:
            _, status = await self.do_import("https://files.example.test/pack.zip")
        self.assertEqual(status["error"], "internal_error")
        text = "\n".join(logs.output)
        self.assertIn("code=internal_error", text)
        self.assertNotIn("SECRET-IN-MESSAGE", text)
        self.assertNotIn("SECRET-QUERY-VALUE", text)

    async def test_tree_link_with_cleared_subfolder_imports_whole_repo(self):
        # The dialog sends subpath "" when the user clears the field of a
        # /tree/<ref>/<dir> link; the route must not drop it.
        self.assertEqual(http_routes._clean_options({"subpath": ""}), {"subpath": ""})
        self.assertEqual(http_routes._clean_options({"subpath": "/docs/"}), {"subpath": "docs"})
        _, status = await self.do_import("https://github.com/o/r/tree/main/docs", options={"subpath": ""})
        self.assertEqual(status["status"], "done", status)
        self.assertEqual(status["progress"]["path"], "uploads/r")
        self.assertIn("README", self.tree("uploads/r"))

    async def test_subfolder_tarball_strategy_only_subtree(self):
        self.world.routes[f"{API}/git/trees/{SHA}?recursive=1"] = lambda r: httpx.Response(
            200, json=dict(TREE, truncated=True))
        _, status = await self.do_import("https://github.com/o/r/tree/main/docs")
        self.assertEqual(status["status"], "done", status)
        self.assertEqual(self.tree("uploads/docs"), [".import.json", "a.md", "sub", "sub/b.md"])
        self.assertTrue(any("codeload" in str(r.url) for r in self.world.seen))

    async def test_blob_link_places_single_file_without_provenance(self):
        _, status = await self.do_import("https://github.com/o/r/blob/main/README")
        self.assertEqual(status["progress"]["path"], "uploads/README")
        self.assertEqual((self.root / "uploads/README").read_bytes(), b"hello")
        self.assertTrue((self.root / "uploads/README").is_file())

    async def test_gist_folder(self):
        _, status = await self.do_import("https://gist.github.com/someone/abcdef12")
        self.assertEqual(status["progress"]["path"], "uploads/gist-abcdef12")
        self.assertEqual(self.tree("uploads/gist-abcdef12"), [".import.json", "a.py"])

    async def test_forge_archive_unwrapped(self):
        _, status = await self.do_import("https://codeberg.org/o/r")
        self.assertEqual(status["status"], "done", status)
        self.assertEqual(self.tree("uploads/r"), [".import.json", "x.txt"])

    async def test_archive_url_extracted(self):
        _, status = await self.do_import("https://files.example.test/pack.zip")
        self.assertEqual(self.tree("uploads/pack"), [".import.json", "one.txt", "two.txt"])
        _, status = await self.do_import("https://files.example.test/paper.pdf")
        self.assertEqual((self.root / "uploads/paper.pdf").read_bytes(), b"%PDF-1.4 x")

    async def test_second_import_keeps_both(self):
        await self.do_import("https://github.com/o/r")
        _, status = await self.do_import("https://github.com/o/r")
        self.assertEqual(status["progress"]["path"], "uploads/r-2")


class Refusals(RunnerBase):
    async def test_html_instead_of_archive_is_unexpected_html_and_nothing_saved(self):
        self.world.routes["https://files.example.test/login.zip"] = lambda r: httpx.Response(
            200, content=b"<html><form>Sign in</form></html>", headers={"content-type": "text/html"})
        with self.assertRaises(ImportFailure) as ctx:
            await self.start("https://files.example.test/login.zip")
        self.assertEqual(ctx.exception.code, "unexpected_html")
        # A server that answers the probe with a zip and the download with a page.
        calls = []

        def flip(_r):
            calls.append(1)
            if len(calls) == 1:
                return httpx.Response(200, content=b"PK\x03\x04", headers={"content-type": "application/zip"})
            return httpx.Response(200, content=b"<!doctype html><html>expired</html>", headers={"content-type": "text/html"})
        self.world.routes["https://files.example.test/flip.zip"] = flip
        _, status = await self.do_import("https://files.example.test/flip.zip")
        self.assertEqual(status["error"], "unexpected_html")
        self.assertEqual(os.listdir(self.root / "uploads"), [])
        self.assertTrue(self.staging_empty())

    async def test_too_large_by_header_and_mid_stream(self):
        self.world.routes["https://files.example.test/big.bin"] = lambda r: httpx.Response(
            200, content=b"y" * 5000, headers={"content-type": "application/octet-stream"})
        with mock.patch.dict(os.environ, {"WORKSPACE_IMPORT_MAX_BYTES": "1000"}):
            _, status = await self.do_import("https://files.example.test/big.bin")
        self.assertEqual(status["error"], "too_large")

        async def stream():
            for _ in range(5):
                yield b"z" * 600

        self.world.routes["https://files.example.test/stream.bin"] = lambda r: httpx.Response(200, content=stream())
        with mock.patch.dict(os.environ, {"WORKSPACE_IMPORT_MAX_BYTES": "1000"}):
            _, status = await self.do_import("https://files.example.test/stream.bin")
        self.assertEqual(status["error"], "too_large")
        self.assertEqual(os.listdir(self.root / "uploads"), [])
        self.assertTrue(self.staging_empty())

    async def test_cancel_mid_download_leaves_nothing(self):
        gate = asyncio.Event()

        async def slow():
            yield b"a" * 1000
            await gate.wait()
            yield b"b"

        calls = []

        def route(_r):
            calls.append(1)
            if len(calls) == 1:  # the preview probe answers at once
                return httpx.Response(200, content=b"a" * 10, headers={"content-type": "application/octet-stream"})
            return httpx.Response(200, content=slow())
        self.world.routes["https://files.example.test/slow.bin"] = route
        started = await self.start("https://files.example.test/slow.bin")
        await asyncio.sleep(0.2)
        status = await job_runner.get_registry().cancel("p1", started["jobId"])
        gate.set()
        self.assertEqual(status["status"], "cancelled")
        self.assertEqual(os.listdir(self.root / "uploads"), [])
        self.assertTrue(self.staging_empty())
        self.assertEqual(staging.reserved_total(), 0)

    async def test_website_import_runs_mirror_and_writes_provenance(self):
        # By design (R-URL-1): websites were refused before the mirror existed.
        with mock.patch.object(mirror_rules, "fetch_agent_settings", lambda *_a, **_k: {"ROE_ENABLED": False}):
            started, status = await self.do_import("https://www.example.test/")
        self.assertEqual(started["kind"], "website")
        self.assertEqual(status["status"], "done", status)
        path = status["progress"]["path"]
        self.assertEqual(path, "uploads/www.example.test")
        self.assertEqual(self.tree(path), [".import.json", "_manifest.jsonl", "index.html"])
        self.assertEqual((status["progress"]["pages"], status["progress"]["stoppedBecause"]), (1, "complete"))
        rec = provenance.read(self.root / path, project_id="p1")
        self.assertEqual(rec["source"]["kind"], "website")
        self.assertEqual(rec["options"], mirror.MirrorOptions.for_kind("website", None, total_cap=GIB).record())
        self.assertEqual((rec["stats"]["pages"], rec["stats"]["stoppedBecause"]), (1, "complete"))
        self.assertTrue(rec["resyncable"])
        self.assertTrue(self.staging_empty())
        self.assertEqual(staging.reserved_total(), 0)


class Mirrors(RunnerBase):
    def setUp(self):
        super().setUp()
        self.settings = {"p1": {"ROE_ENABLED": False}, "p2": {"ROE_ENABLED": False}}
        self.loaded: list[str] = []

        def fetch(project_id, _url, **kw):
            self.loaded.append(project_id)
            assert kw == {"include_skill_overrides": False}
            value = self.settings[project_id]
            if isinstance(value, Exception):
                raise value
            return value
        self._settings_patch = mock.patch.object(mirror_rules, "fetch_agent_settings", fetch)
        self._settings_patch.start()
        self.world.routes["https://www.example.test/"] = lambda r: httpx.Response(
            200, content=b'<html><body><a href="guide.html">Guide</a><p>Home text.</p></body></html>',
            headers={"content-type": "text/html"})
        self.world.routes["https://www.example.test/guide.html"] = lambda r: httpx.Response(
            200, content=b"<html><body><h1>Guide</h1><p>Guide text.</p></body></html>",
            headers={"content-type": "text/html"})

    async def asyncTearDown(self):
        self._settings_patch.stop()
        await super().asyncTearDown()

    async def test_resync_of_mirror_reuses_options(self):
        _, status = await self.do_import("https://www.example.test/", options={"outputMode": "readable", "maxPages": 5})
        self.assertEqual(status["status"], "done", status)
        path = status["progress"]["path"]
        self.assertEqual(self.tree(path), [".import.json", "_manifest.jsonl", "guide.md", "index.md"])
        (self.root / path / "index.md").write_text("edited")
        body = json.dumps({"projectId": "p1", "path": path}).encode()

        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}
        from starlette.requests import Request
        resp = await http_routes.resync_import(Request({"type": "http", "method": "POST", "headers": []}, receive))
        self.assertEqual(resp.status_code, 202, resp.body)
        status = await job_runner.get_registry().wait("p1", json.loads(resp.body)["jobId"], 10)
        self.assertEqual(status["status"], "done", status)
        self.assertEqual(self.tree(path), [".import.json", "_manifest.jsonl", "guide.md", "index.md"])
        self.assertIn("Home text.", (self.root / path / "index.md").read_text())
        rec = provenance.read(self.root / path, project_id="p1")
        self.assertEqual((rec["options"]["outputMode"], rec["options"]["maxPages"]), ("readable", 5))

    async def test_resolve_refuses_hard_blocked_site_root_without_request(self):
        blocked = lambda host: (host == "blocked.example.test", "")
        with mock.patch.object(resolve, "is_hard_blocked", blocked):
            async with self.world.factory() as f:
                with self.assertRaises(ImportFailure) as ctx:
                    await resolve.inspect("https://blocked.example.test/", f)
                self.assertEqual(ctx.exception.code, "hard_blocked")
                self.assertEqual(self.world.seen, [])
                # Not a site root: the one classification probe goes out, then the refusal.
                self.world.routes["https://blocked.example.test/docs/"] = self.world.routes["https://www.example.test/"]
                with self.assertRaises(ImportFailure) as ctx:
                    await resolve.inspect("https://blocked.example.test/docs/", f)
                self.assertEqual(ctx.exception.code, "hard_blocked")
                self.assertEqual(len(self.world.seen), 1)

    async def test_resolve_answers_scope_and_defaults(self):
        async with self.world.factory() as f:
            insp = await resolve.inspect("https://www.example.test/", f)
        answer = insp.answer()
        self.assertTrue(answer["supported"])
        self.assertEqual(answer["details"]["scopeHost"], "www.example.test")
        self.assertEqual(answer["details"]["scopePath"], "/")
        self.assertEqual(answer["details"]["defaults"]["outputMode"], "raw")

    async def test_repo_imports_never_load_settings(self):
        _, status = await self.do_import("https://github.com/o/r")
        self.assertEqual(status["status"], "done", status)
        self.assertEqual(self.loaded, [])

    async def test_settings_failure_fails_the_mirror_closed(self):
        self.settings["p1"] = ConnectionError("webapp down")
        _, status = await self.do_import("https://www.example.test/")
        self.assertEqual(status["error"], "settings_unavailable")
        self.assertFalse(any("www.example.test" in str(r.url) for r in self.world.seen[1:]))
        self.assertTrue(self.staging_empty())

    async def test_two_projects_mirror_concurrently_each_with_own_roe(self):
        self.settings["p1"] = {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": ["other.example.test"]}
        self.settings["p2"] = {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": ["www.example.test"]}
        workspace_fs.resolve_for_project("p2", ".")
        async with self.world.factory() as f:
            insp = await resolve.inspect("https://www.example.test/", f)
        jobs = []
        for pid in ("p1", "p2"):
            spec = runner.ImportSpec(url="https://www.example.test/", dest_dir="uploads", name="site")
            jobs.append((pid, (await runner.start(spec, insp, project_id=pid, github_token=""))["jobId"]))
        reg = job_runner.get_registry()
        done = {pid: await reg.wait(pid, job, 10) for pid, job in jobs}
        self.assertEqual(done["p1"]["status"], "done", done["p1"])
        self.assertEqual(done["p2"]["error"], "roe_excluded")
        self.assertEqual(sorted(self.loaded), ["p1", "p2"])

    async def test_invalid_mirror_option_refused_by_the_route(self):
        body = json.dumps({"projectId": "p1", "url": "https://www.example.test/", "destDir": "uploads",
                           "options": {"maxPages": "lots"}}).encode()

        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}
        from starlette.requests import Request
        resp = await http_routes.import_url(Request({"type": "http", "method": "POST", "headers": []}, receive))
        self.assertEqual((resp.status_code, json.loads(resp.body)["code"]), (400, "invalid_option"))


class Stored(RunnerBase):
    async def test_token_never_in_meta_log_progress_provenance_or_response(self):
        started, status = await self.do_import("https://github.com/o/r", token=TOKEN)
        self.assertEqual(status["status"], "done", status)
        # The token went to api.github.com only, never to codeload.
        for r in self.world.seen:
            auth = r.headers.get("authorization")
            if r.url.host == "api.github.com":
                self.assertEqual(auth, f"token {TOKEN}")
            else:
                self.assertIsNone(auth, str(r.url))
        for path in self.tmp.rglob("*"):
            if path.is_file():
                self.assertNotIn(TOKEN.encode(), path.read_bytes(), str(path))
        self.assertNotIn(TOKEN, json.dumps(started))
        self.assertNotIn(TOKEN, json.dumps(status))

    async def test_failed_job_stores_code(self):
        self.world.routes["https://files.example.test/gone.zip"] = lambda r: httpx.Response(
            200, content=b"PK\x03\x04", headers={"content-type": "application/zip"})
        _, status = await self.do_import("https://files.example.test/gone.zip")
        self.assertEqual((status["status"], status["error"]), ("failed", "corrupt_archive"))

    async def test_resyncable_false_when_query_present(self):
        self.world.routes["https://files.example.test/pack.zip?v=2"] = self.world.routes["https://files.example.test/pack.zip"]
        started, status = await self.do_import("https://files.example.test/pack.zip?v=2")
        rec = provenance.read(self.root / "uploads/pack", project_id="p1")
        self.assertFalse(rec["resyncable"])
        self.assertEqual(rec["source"]["url"], "https://files.example.test/pack.zip")
        meta = json.loads((self.root / "jobs" / f"{started['jobId']}.meta.json").read_text())
        self.assertEqual(meta["args"]["url"], "https://files.example.test/pack.zip")

    async def test_success_log_line_redacted(self):
        self.world.routes["https://files.example.test/pack.zip?sig=SECRET"] = self.world.routes["https://files.example.test/pack.zip"]
        with self.assertLogs("workspace_import.runner", "INFO") as logs:
            started, _ = await self.do_import("https://files.example.test/pack.zip?sig=SECRET")
        line = next(l for l in logs.output if "done project=" in l)
        self.assertIn(f"job={started['jobId']} kind=archive url=https://files.example.test/pack.zip path=uploads/pack", line)
        self.assertNotIn("SECRET", "\n".join(logs.output))


class DiskAndPool(RunnerBase):
    async def test_unknown_size_download_grows_reservation_and_stops_at_reserve(self):
        async def stream():
            for _ in range(3):
                yield b"q" * (40 * 1024 * 1024)

        self.world.routes["https://files.example.test/huge.bin"] = lambda r: httpx.Response(200, content=stream())
        self.free = 100 * 1024 * 1024  # room for one 64 MiB growth step, not two
        _, status = await self.do_import("https://files.example.test/huge.bin")
        self.assertEqual(status["error"], "insufficient_storage")
        self.assertEqual(staging.reserved_total(), 0)
        self.assertTrue(self.staging_empty())

    async def test_two_concurrent_imports_cannot_overrun_free_space(self):
        size = 30 * 1024 * 1024
        gate = asyncio.Event()

        async def held_body():
            await gate.wait()
            yield b"w" * 10

        def route(r, calls=[]):
            calls.append(1)
            headers = {"content-length": str(size), "content-type": "application/octet-stream"}
            if r.url.path == "/a.bin" and len([c for c in calls]) > 1:
                return httpx.Response(200, content=held_body(), headers={"content-type": "application/octet-stream"})
            return httpx.Response(200, content=b"w" * 10, headers=headers)
        self.world.routes["https://files.example.test/a.bin"] = route
        self.world.routes["https://files.example.test/b.bin"] = route
        self.free = int(1.5 * size)
        first = await self.start("https://files.example.test/a.bin")
        for _ in range(50):
            if staging.reserved_total():
                break
            await asyncio.sleep(0.02)
        self.assertEqual(staging.reserved_total(), size)  # the first job holds its reservation
        second = await self.start("https://files.example.test/b.bin")
        status = await job_runner.get_registry().wait("p1", second["jobId"], 10)
        self.assertEqual(status["error"], "insufficient_storage")
        gate.set()
        await job_runner.get_registry().wait("p1", first["jobId"], 10)

    async def test_enospc_mid_download_is_insufficient_storage_and_leaves_nothing(self):
        real_write = os.write

        def full(fd, data):
            raise OSError(28, "No space left on device")

        with mock.patch("workspace_import.fetch.os.write", full):
            _, status = await self.do_import("https://files.example.test/paper.pdf")
        self.assertEqual(status["error"], "insufficient_storage")
        self.assertEqual(os.listdir(self.root / "uploads"), [])
        self.assertTrue(self.staging_empty())
        del real_write

    async def test_destination_deleted_mid_import_is_destination_missing(self):
        (self.root / "uploads/sub").mkdir()
        gate = asyncio.Event()
        real = self.world.routes["https://files.example.test/pack.zip"]

        async def body():
            await gate.wait()
            yield real(None).content

        self.world.routes["https://files.example.test/late.zip"] = lambda r: httpx.Response(
            200, content=body(), headers={"content-type": "application/zip"})
        self.world.routes["https://files.example.test/late.zip"].__name__ = "late"
        probe_calls = []
        orig = self.world.routes["https://files.example.test/late.zip"]

        def route(r):
            probe_calls.append(1)
            if len(probe_calls) == 1:
                return httpx.Response(200, content=b"PK\x03\x04", headers={"content-type": "application/zip"})
            return orig(r)
        self.world.routes["https://files.example.test/late.zip"] = route
        started = await self.start("https://files.example.test/late.zip", dest="uploads/sub")
        await asyncio.sleep(0.1)
        shutil.rmtree(self.root / "uploads/sub")
        gate.set()
        status = await job_runner.get_registry().wait("p1", started["jobId"], 10)
        self.assertEqual(status["error"], "destination_missing")
        self.assertTrue(self.staging_empty())

    async def test_extraction_runs_on_import_pool(self):
        import threading
        names = []
        real = runner.safe_extract

        def spy(*a, **kw):
            names.append(threading.current_thread().name)
            return real(*a, **kw)

        with mock.patch.object(runner, "safe_extract", spy):
            await self.do_import("https://files.example.test/pack.zip")
        self.assertTrue(names and names[0].startswith("test-import"))


class CrossFeature(RunnerBase):
    async def test_import_job_does_not_consume_governed_slots(self):
        with mock.patch.object(job_runner, "_governed_max_jobs", return_value=1):
            gate = asyncio.Event()

            async def held(*_a):
                await gate.wait()
                return {"success": True}

            self.assertIn("job_id", await job_runner.get_registry().spawn("p1", "execute_nuclei", {}, held))
            _, status = await self.do_import("https://files.example.test/pack.zip")
            gate.set()
        self.assertEqual(status["status"], "done", status)

    async def test_deleted_project_import_fails_and_leaves_nothing(self):
        self.exists = False
        _, status = await self.do_import("https://github.com/o/r")
        self.assertEqual(status["error"], "project_deleted")
        self.assertEqual(os.listdir(self.root / "uploads"), [])
        self.assertTrue(self.staging_empty())


class RouteLimits(unittest.TestCase):
    """The import route through TestClient, so jobs run on its event loop."""

    def setUp(self):
        self.base = RunnerBase()
        RunnerBase.setUp(self.base)
        self.app = FastAPI()
        self.app.include_router(http_routes.router)
        self.app.dependency_overrides[require_configured_master_auth] = lambda: None

    def tearDown(self):
        asyncio.run(RunnerBase.asyncTearDown(self.base))

    def test_duplicate_is_409_busy_and_third_is_429(self):
        gate = {"open": False}

        async def slow():
            while not gate["open"]:
                await asyncio.sleep(0.02)
            yield b"%PDF-1.4"

        self.base.world.routes["https://files.example.test/a.pdf"] = lambda r: httpx.Response(
            200, content=slow() if r.method == "GET" and getattr(r, "_n", 0) else b"%PDF-1.4",
            headers={"content-type": "application/pdf"})
        for n in ("b", "c"):
            self.base.world.routes[f"https://files.example.test/{n}.pdf"] = self.base.world.routes["https://files.example.test/a.pdf"]
        hold = asyncio.Event()
        real_place = place.place

        async def held_place(*a, **kw):
            while not gate["open"]:
                await asyncio.sleep(0.02)
            return await real_place(*a, **kw)

        with mock.patch.object(place, "place", held_place), TestClient(self.app) as client:
            post = lambda url: client.post("/workspace/import-url", json={"projectId": "p1", "url": url,
                                                                          "destDir": "uploads"})
            first = post("https://files.example.test/a.pdf")
            self.assertEqual(first.status_code, 202, first.text)
            dup = post("https://files.example.test/a.pdf")
            self.assertEqual((dup.status_code, dup.json()["code"]), (409, "busy"))
            self.assertEqual(dup.json()["jobId"], first.json()["jobId"])
            self.assertEqual(post("https://files.example.test/b.pdf").status_code, 202)
            third = post("https://files.example.test/c.pdf")
            self.assertEqual((third.status_code, third.json()["code"]), (429, "too_many_imports"))
            gate["open"] = True
            for _ in range(100):
                jobs = client.get("/workspace/jobs/" + first.json()["jobId"], params={"projectId": "p1"}).json()
                if jobs["status"] != "running":
                    break
                time.sleep(0.05)
        del hold

    def test_kill_switch_blocks_import_but_not_upload_sessions(self):
        with mock.patch.dict(os.environ, {"WORKSPACE_URL_IMPORT_ENABLED": "no-thanks"}), TestClient(self.app) as client:
            r = client.post("/workspace/import-url", json={"projectId": "p1", "url": "https://github.com/o/r"})
            self.assertEqual((r.status_code, r.json()["code"]), (403, "import_disabled"))
            r = client.post("/workspace/import-url/resolve", json={"projectId": "p1", "url": "https://github.com/o/r"})
            self.assertEqual(r.status_code, 403)
            r = client.post("/workspace/upload-sessions", json={"projectId": "p1", "destDir": "uploads", "name": "a",
                                                                "size": 1, "kind": "file"})
            self.assertEqual(r.status_code, 201, r.text)
        self.assertEqual(self.base.world.seen, [])

    def test_invalid_body_never_echoes_token(self):
        with TestClient(self.app) as client:
            for body in ({"projectId": "p1", "githubToken": TOKEN}, {"url": "https://github.com/o/r", "githubToken": TOKEN},
                         {"projectId": "p1", "url": "https://github.com/o/r", "onConflict": "merge", "githubToken": TOKEN},
                         {"projectId": "p1", "url": "https://github.com/o/r", "options": {"subpath": 3}, "githubToken": TOKEN}):
                r = client.post("/workspace/import-url", json=body)
                self.assertEqual((r.status_code, r.json()["code"]), (400, "invalid_request"))
                self.assertNotIn(TOKEN, r.text)


if __name__ == "__main__":
    unittest.main()
