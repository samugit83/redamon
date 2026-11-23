"""MCP kali_output (`GET /kali/exec/{job_id}`) and the kill path against a planted
job store (FU-29, STRIDE I6/D15).

Shown live: a member planted `jobs/<id>.meta.json` and a `<id>.log` link to
/proc/self/cmdline in their own project, and kali_output returned the AGENT's
process line; /proc/self/environ would have given INTERNAL_API_KEY. Here
`outside/environ` stands in for the agent's file, with a canary in place of a
secret: nothing real is read.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import api  # noqa: E402
import job_runner  # noqa: E402
import sandbox_router as router  # noqa: E402
from sandbox_route_fakes import WEBAPP, Fleet  # noqa: E402
from test_job_store_links import CANARY, run_guarded  # noqa: E402

JOB = "a" * 32


def _body(resp):
    return json.loads(bytes(resp.body).decode())


class _Base(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="redamon-kalilog-"))
        self.root = self.tmp / "workspace"
        self.outside = self.tmp / "outside"
        self.root.mkdir()
        self.outside.mkdir()
        self.secret = self.outside / "environ"
        self.secret.write_text(CANARY + "\0HOSTNAME=agent\0")
        router._reset()
        getattr(job_runner, "_REFUSALS_LOGGED", set()).clear()
        self.registry = job_runner.JobRegistry()
        self.fleet = Fleet()
        self.executor = mock.Mock()
        self._patches = [
            mock.patch.dict(os.environ, {"WORKSPACE_ROOT": str(self.root)}),
            mock.patch.object(job_runner, "WORKSPACE_ROOT", self.root),
            mock.patch.object(api.job_runner, "get_registry", return_value=self.registry),
            mock.patch.object(api, "orchestrator", mock.Mock(tool_executor=self.executor)),
            mock.patch.object(router, "_transport", self.fleet.transport()),
            mock.patch.dict(router.INTERNAL_HEADERS, {"X-Internal-Key": "test-internal-key"}),
            mock.patch.object(router, "WEBAPP_API_URL", WEBAPP),
        ]
        for p in self._patches:
            p.start()

    async def asyncTearDown(self):
        tasks = [h.task for h in self.registry._jobs.values() if h.task and not h.task.done()]
        for t in tasks:
            t.cancel()
        for t in tasks:
            try:
                await t
            except (asyncio.CancelledError, Exception):
                pass
        await router._shutdown()
        for p in reversed(self._patches):
            p.stop()
        router._reset()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def jobs(self, project="p1") -> Path:
        d = self.root / project / "jobs"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def plant_meta(self, folder: Path, job=JOB):
        (folder / f"{job}.meta.json").write_text(json.dumps(
            {"job_id": JOB, "status": "done", "exit_code": 0, "started_at": "t0", "ended_at": "t1"}))

    async def poll(self, job=JOB, project="p1", cursor=0):
        return await api.kali_exec_status(job, project_id=project, cursor=cursor)

    def assert_no_canary(self, resp):
        self.assertNotIn("planted-canary", bytes(resp.body).decode())


class KaliOutputNeverFollowsALink(_Base):
    async def test_a_planted_log_link_is_never_returned(self):
        """The live finding: no real job, a planted meta and a log link."""
        self.plant_meta(self.jobs())
        (self.jobs() / f"{JOB}.log").symlink_to(self.secret)
        resp = await self.poll()
        self.assert_no_canary(resp)
        if resp.status_code == 200:
            self.assertEqual(_body(resp)["output"], "")

    async def test_a_live_jobs_log_swapped_for_a_link_is_not_read(self):
        release, wrote = asyncio.Event(), asyncio.Event()

        async def runner(_name, _args, append_log):
            await append_log("scan output")
            wrote.set()
            await release.wait()
            return {"success": True}

        job_id = (await self.registry.spawn("p1", "kali_shell", {"command": "x"}, runner))["job_id"]
        await asyncio.wait_for(wrote.wait(), 5)
        log = self.jobs() / f"{job_id}.log"
        log.unlink()
        log.symlink_to(self.secret)
        resp = await self.poll(job_id)
        self.assertEqual(resp.status_code, 200)
        self.assert_no_canary(resp)
        release.set()

    async def test_a_jobs_folder_that_is_a_link_is_refused(self):
        elsewhere = self.outside / "jobs"
        elsewhere.mkdir()
        self.plant_meta(elsewhere)
        (elsewhere / f"{JOB}.log").write_text(CANARY)
        (self.root / "p1").mkdir()
        (self.root / "p1" / "jobs").symlink_to(elsewhere)
        resp = await self.poll()
        self.assertEqual(resp.status_code, 404)
        self.assert_no_canary(resp)

    async def test_a_linked_meta_is_not_a_job(self):
        victim = self.outside / "meta.json"
        victim.write_text(json.dumps({"job_id": JOB, "status": "done", "note": CANARY}))
        (self.jobs() / f"{JOB}.meta.json").symlink_to(victim)
        resp = await self.poll()
        self.assertEqual(resp.status_code, 404)
        self.assert_no_canary(resp)

    async def test_a_traversing_project_id_reads_nothing(self):
        (self.outside / "jobs").mkdir()
        self.plant_meta(self.outside / "jobs")
        (self.outside / "jobs" / f"{JOB}.log").write_text(CANARY)
        for project in ("../outside", "p1/../../outside"):
            resp = await self.poll(project=project)
            self.assertEqual(resp.status_code, 404, project)
            self.assert_no_canary(resp)

    async def test_a_job_id_with_a_trailing_newline_is_rejected(self):
        self.plant_meta(self.jobs(), job=JOB + "\n")
        resp = await self.poll(JOB + "\n")
        self.assertEqual(resp.status_code, 404)


class KaliOutputNeverHangs(_Base):
    async def test_a_fifo_log_does_not_hang_the_poll(self):
        self.plant_meta(self.jobs())
        fifo = self.jobs() / f"{JOB}.log"
        os.mkfifo(fifo)
        resp = run_guarded(self, lambda: asyncio.run(self.poll()), [fifo])
        self.assertEqual(_body(resp)["output"], "")

    async def test_a_fifo_meta_does_not_hang_the_poll_or_the_kill(self):
        fifo = self.jobs() / f"{JOB}.meta.json"
        os.mkfifo(fifo)
        resp = run_guarded(self, lambda: asyncio.run(self.poll()), [fifo])
        self.assertEqual(resp.status_code, 404)
        resp = run_guarded(self, lambda: asyncio.run(api.kali_exec_cancel(JOB, project_id="p1")), [fifo])
        self.assertEqual(resp.status_code, 404)


class KaliExecRefusesALinkedJobsFolder(_Base):
    async def test_the_command_is_refused_and_nothing_is_written_outside(self):
        self.fleet.add("alice")
        elsewhere = self.outside / "jobs"
        elsewhere.mkdir()
        (self.root / "p1").mkdir()
        (self.root / "p1" / "jobs").symlink_to(elsewhere)
        resp = await api.kali_exec(api.KaliExecRequest(
            project_id="p1", command="id", user_id="alice", wait_seconds=1))
        self.assertEqual(resp.status_code, 409)
        self.assertEqual(list(elsewhere.iterdir()), [])
        self.assertEqual(self.registry._jobs, {})


class LegitimateCommandsStillStreamAndStop(_Base):
    """Regression guards: these pass before and after the fix."""

    async def test_a_running_command_streams_by_cursor_then_is_killed(self):
        more = asyncio.Event()

        async def runner(_name, _args, append_log):
            await append_log("line one")
            await more.wait()
            await append_log("line two")
            await asyncio.Event().wait()
            return {"success": True}

        job_id = (await self.registry.spawn("p1", "kali_shell", {"command": "x"}, runner))["job_id"]
        await asyncio.sleep(0.05)
        first = _body(await self.poll(job_id))
        self.assertEqual((first["status"], first["output"]), ("running", "line one\n"))
        more.set()
        await asyncio.sleep(0.05)
        second = _body(await self.poll(job_id, cursor=first["next_cursor"]))
        self.assertEqual(second["output"], "line two\n")
        killed = await api.kali_exec_cancel(job_id, project_id="p1")
        self.assertEqual(killed.status_code, 200)
        self.assertEqual(_body(killed)["status"], "cancelled")
        self.assertEqual(_body(await self.poll(job_id))["output"], "line one\nline two\n")

    async def test_a_finished_command_reads_back_after_a_restart(self):
        async def runner(_name, _args, append_log):
            await append_log("all done")
            return {"success": True}

        job_id = (await self.registry.spawn("p1", "kali_shell", {"command": "x"}, runner))["job_id"]
        await self.registry.wait("p1", job_id, 5)
        fresh = job_runner.JobRegistry()
        fresh.recover_on_boot()
        with mock.patch.object(api.job_runner, "get_registry", return_value=fresh):
            body = _body(await self.poll(job_id))
        self.assertEqual((body["status"], body["output"]), ("done", "all done\n"))


if __name__ == "__main__":
    unittest.main()
