"""The three agent endpoints behind the inbound MCP kali_exec tools.

kali_exec is at PARITY with the in-app agent: `bash -c`, no allowlist, no
per-command target check. So nothing here tests admission - there is none. What
is pinned is the wiring, where the failures are different in kind:

  - the command reaches the sandbox VERBATIM, because a caller is entitled to
    write a pipeline and quoting it would break every one;
  - the log path must be derived from the tenant, NEVER read from the job's own
    metadata (see LogPathTrustTests - that was an arbitrary file read);
  - a tool that failed must not be published as exit 0.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import api  # noqa: E402
JOB = "a" * 32          # a well-formed uuid4 hex
OTHER_JOB = "b" * 32


def _dep_names(route):
    names = []
    for d in list(getattr(route, "dependencies", []) or []):
        call = getattr(d, "dependency", None)
        names.append(getattr(call, "__name__", str(call)))
    return names


def _route(path, method):
    for r in api.app.routes:
        if getattr(r, "path", "") == path and method in (getattr(r, "methods", set()) or set()):
            return r
    return None


def _body(resp):
    import json

    return json.loads(bytes(resp.body).decode())


class _FakeExecutor:
    def __init__(self, output="OK", success=True):
        self.calls = []
        self._output = output
        self._success = success

    async def execute(self, name, args, phase, skip_phase_check=False):
        self.calls.append({"name": name, "args": args, "phase": phase})
        return {"success": self._success, "output": self._output, "error": None}


class _FakeRegistry:
    """A job registry that runs the job inline and writes where the real one
    would: <WORKSPACE_ROOT>/<project>/jobs/<job_id>.log."""

    def __init__(self, root, spawn_error=None, job_id=JOB):
        self.root = root
        self.spawn_error = spawn_error
        self.job_id = job_id
        self.spawned = []
        self.cancelled = []
        self._state = {}

    def _log(self, project_id, job_id):
        d = Path(self.root) / project_id / "jobs"
        d.mkdir(parents=True, exist_ok=True)
        return d / f"{job_id}.log"

    async def spawn(self, project_id, tool_name, args, runner, label=None):
        if self.spawn_error:
            return {"error": self.spawn_error}
        self.spawned.append({"project_id": project_id, "tool_name": tool_name, "args": args})
        log = self._log(project_id, self.job_id)
        log.touch()

        async def append_log(chunk):
            with log.open("a", encoding="utf-8") as fh:
                fh.write(chunk)

        result = await runner(tool_name, args, append_log)
        self._state[(project_id, self.job_id)] = {
            "job_id": self.job_id,
            "status": "done" if result.get("success") else "failed",
            "exit_code": 0 if result.get("success") else 1,
            "started_at": "t0", "ended_at": "t1",
            "output_path": str(log),
        }
        return {"job_id": self.job_id, "status": "running", "output_path": str(log)}

    async def wait(self, project_id, job_id, timeout_sec=30.0):
        return self.status(project_id, job_id)

    def status(self, project_id, job_id):
        return self._state.get((project_id, job_id), {"error": f"unknown job {job_id}"})

    async def cancel(self, project_id, job_id):
        self.cancelled.append(job_id)
        self._state[(project_id, job_id)]["status"] = "cancelled"
        return {"ok": True}


class _Base(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        import sandbox_contract
        import sandbox_router

        # These tests pin the shared sandbox's wiring. No gateway answers here and the
        # default mode is per_user, so the shared mode is named as the last answer.
        sandbox_router._reset(mode=sandbox_contract.MODE_SHARED)
        self.addCleanup(sandbox_router._reset)
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = self._tmp.name
        self.executor = _FakeExecutor()
        self.registry = _FakeRegistry(self.root)
        patches = [
            mock.patch.dict(os.environ, {"WORKSPACE_ROOT": self.root}),
            mock.patch.object(api, "orchestrator", mock.Mock(tool_executor=self.executor)),
            mock.patch.object(api.job_runner, "get_registry", return_value=self.registry),
        ]
        for p in patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in patches])

    async def _exec(self, command, **kw):
        return await api.kali_exec(api.KaliExecRequest(project_id="p1", command=command, **kw))

    def _seed(self, project_id, job_id, text):
        d = Path(self.root) / project_id / "jobs"
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{job_id}.log").write_text(text)
        self.registry._state[(project_id, job_id)] = {
            "job_id": job_id, "status": "done", "exit_code": 0,
            "started_at": "t0", "ended_at": "t1",
            "output_path": str(d / f"{job_id}.log"),
        }


class RouteRegistrationTests(unittest.TestCase):
    def test_all_three_routes_are_registered_and_master_key_gated(self):
        """require_internal_auth_only also accepts SCANNER_API_KEY, which the
        kali-sandbox and every spawned scan container hold. A leaked scanner
        token must not be able to run commands."""
        for path, method in (
            ("/kali/exec", "POST"),
            ("/kali/exec/{job_id}", "GET"),
            ("/kali/exec/{job_id}/cancel", "POST"),
        ):
            route = _route(path, method)
            self.assertIsNotNone(route, f"{method} {path} is not registered")
            deps = _dep_names(route)
            self.assertIn("require_master_internal_auth", deps, f"{method} {path}")
            self.assertNotIn("require_internal_auth_only", deps, f"{method} {path}")


class LogPathTrustTests(_Base):
    """REGRESSION: arbitrary file read on the AGENT container.

    JobRegistry.status() falls back to reading
    <workspace>/<project>/jobs/<job_id>.meta.json off disk and returns its
    parsed contents. kali_exec can write into that same workspace, so a caller
    who got one attacker-chosen body onto disk could set `output_path` to
    /proc/self/environ and page out INTERNAL_API_KEY and NEO4J_PASSWORD.
    """

    async def test_the_log_path_is_derived_not_taken_from_the_job_metadata(self):
        secret = Path(self.root) / "secret.env"
        secret.write_text("INTERNAL_API_KEY=super-secret")
        real = Path(self.root) / "p1" / "jobs"
        real.mkdir(parents=True, exist_ok=True)
        (real / f"{JOB}.log").write_text("the real output")
        # A poisoned meta pointing somewhere else entirely.
        self.registry._state[("p1", JOB)] = {
            "job_id": JOB, "status": "done", "exit_code": 0,
            "started_at": "t0", "ended_at": "t1",
            "output_path": str(secret),
        }
        body = _body(await api.kali_exec_status(JOB, project_id="p1", cursor=0))
        self.assertEqual(body["output"], "the real output")
        self.assertNotIn("super-secret", body["output"])

    async def test_a_job_id_that_is_not_a_uuid_hex_is_rejected(self):
        # The job id reaches a filesystem path, so traversal in it must not.
        for bad in ("../../../proc/self/environ", "a" * 31, "g" * 32, "", "../x"):
            resp = await api.kali_exec_status(bad, project_id="p1", cursor=0)
            self.assertEqual(resp.status_code, 404, bad)

    async def test_a_traversing_job_id_is_rejected_on_cancel_too(self):
        resp = await api.kali_exec_cancel("../../etc/passwd", project_id="p1")
        self.assertEqual(resp.status_code, 404)


class ExecTests(_Base):
    async def test_an_admitted_command_runs_and_returns_its_output(self):
        self.executor._output = "HTTP/1.1 200 OK"
        body = _body(await self._exec("curl -I https://acme.tld"))
        self.assertEqual(body["status"], "done")
        self.assertEqual(body["exit_code"], 0)
        self.assertIn("HTTP/1.1 200 OK", body["output"])

    async def test_the_sandbox_only_ever_receives_a_requoted_command(self):
        await self._exec("curl -A 'Mozilla 5.0' https://acme.tld")
        call = self.executor.calls[0]
        self.assertEqual(call["name"], "kali_shell")
        self.assertIn("'Mozilla 5.0'", call["args"]["command"])

    async def test_a_pipeline_reaches_the_sandbox_verbatim(self):
        """PARITY WITH THE DRAWER. kali_shell is `bash -c`, so a caller is
        entitled to write a pipeline - and quoting or rewriting it would break
        every one. Nothing between here and bash may touch the string."""
        cmd = "subfinder -d acme.tld -silent | httpx -silent -sc | head -20"
        await self._exec(cmd)
        self.assertEqual(self.executor.calls[0]["args"]["command"], cmd)

    async def test_metacharacters_are_not_stripped_or_refused(self):
        for cmd in (
            "nmap -p80 acme.tld && echo done",
            "curl -s https://acme.tld/ > /tmp/body.html",
            "echo $(whoami)",
            "for i in 1 2 3; do echo $i; done",
        ):
            self.executor.calls.clear()
            resp = await self._exec(cmd)
            self.assertNotEqual(getattr(resp, "status_code", 200), 400, cmd)
            self.assertEqual(self.executor.calls[0]["args"]["command"], cmd)

    async def test_the_command_is_echoed_back_exactly_as_given(self):
        cmd = "curl -A 'Mozilla 5.0' https://acme.tld"
        body = _body(await self._exec(cmd))
        self.assertEqual(body["command"], cmd)

    async def test_an_empty_command_is_still_refused(self):
        # The one check that survives: there is nothing to run.
        for cmd in ("", "   "):
            resp = await api.kali_exec(api.KaliExecRequest(project_id="p1", command=cmd))
            self.assertEqual(resp.status_code, 400)

    async def test_an_uninitialised_sandbox_is_unavailable_not_silent(self):
        with mock.patch.object(api, "orchestrator", None):
            resp = await self._exec("curl https://acme.tld")
        self.assertEqual(resp.status_code, 503)

    async def test_a_missing_project_id_is_refused(self):
        resp = await api.kali_exec(api.KaliExecRequest(project_id="", command="curl https://acme.tld"))
        self.assertEqual(resp.status_code, 400)

    async def test_the_job_cap_is_reported_as_a_retryable_limit(self):
        self.registry.spawn_error = "Too many background jobs running"
        resp = await self._exec("curl https://acme.tld")
        self.assertEqual(resp.status_code, 429)

    async def test_the_wait_is_clamped(self):
        captured = {}

        async def _wait(project_id, job_id, timeout_sec=30.0):
            captured["timeout"] = timeout_sec
            return self.registry.status(project_id, job_id)

        self.registry.wait = _wait
        await self._exec("curl https://acme.tld", wait_seconds=9999)
        self.assertEqual(captured["timeout"], api.KALI_EXEC_MAX_WAIT)


class FailureReportingTests(_Base):
    """REGRESSION: a failed tool was published as exit 0.

    PhaseAwareToolExecutor reports success for ANY MCP call that returned a
    string, and kali_shell encodes failure in its OUTPUT ("[ERROR] ...") rather
    than by raising. A caller told "exitCode 0" for a scan that never ran has a
    false negative, which is the bug class this surface exists to avoid.
    """

    async def test_a_tool_error_is_reported_as_a_failure(self):
        self.executor._output = "[ERROR] kali_shell failed: returncode=7, stderr=boom"
        body = _body(await self._exec("curl https://acme.tld"))
        self.assertEqual(body["status"], "failed")
        self.assertEqual(body["exit_code"], 1)

    async def test_a_timeout_is_reported_as_a_failure(self):
        self.executor._output = "[ERROR] Command timed out after 300 seconds."
        body = _body(await self._exec("curl https://acme.tld"))
        self.assertEqual(body["status"], "failed")

    async def test_ordinary_output_is_still_a_success(self):
        self.executor._output = "HTTP/2 200"
        body = _body(await self._exec("curl -I https://acme.tld"))
        self.assertEqual(body["status"], "done")


class PollAndCancelTests(_Base):
    async def test_an_unknown_job_is_not_found(self):
        resp = await api.kali_exec_status("c" * 32, project_id="p1", cursor=0)
        self.assertEqual(resp.status_code, 404)

    async def test_another_projects_job_id_reads_nothing(self):
        self._seed("p1", JOB, "secret output")
        resp = await api.kali_exec_status(JOB, project_id="p2", cursor=0)
        self.assertEqual(resp.status_code, 404)

    async def test_the_cursor_resumes_where_the_last_read_stopped(self):
        self._seed("p1", JOB, "line one\nline two\n")
        first = _body(await api.kali_exec_status(JOB, project_id="p1", cursor=0))
        self.assertEqual(first["output"], "line one\nline two\n")
        second = _body(await api.kali_exec_status(JOB, project_id="p1", cursor=first["next_cursor"]))
        self.assertEqual(second["output"], "")

    async def test_an_oversized_output_is_paged_never_silently_cut(self):
        self._seed("p1", JOB, "x" * (api.KALI_EXEC_MAX_OUTPUT_BYTES + 500))
        body = _body(await api.kali_exec_status(JOB, project_id="p1", cursor=0))
        self.assertTrue(body["truncated"])
        self.assertEqual(len(body["output"]), api.KALI_EXEC_MAX_OUTPUT_BYTES)
        rest = _body(await api.kali_exec_status(JOB, project_id="p1", cursor=body["next_cursor"]))
        self.assertEqual(len(rest["output"]), 500)
        self.assertFalse(rest["truncated"])

    async def test_undecodable_tool_output_does_not_lose_the_run(self):
        d = Path(self.root) / "p1" / "jobs"
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{JOB}.log").write_bytes(b"before \xff\xfe after")
        self.registry._state[("p1", JOB)] = {
            "job_id": JOB, "status": "done", "exit_code": 0,
            "started_at": "t0", "ended_at": "t1", "output_path": "",
        }
        body = _body(await api.kali_exec_status(JOB, project_id="p1", cursor=0))
        self.assertIn("before", body["output"])
        self.assertIn("after", body["output"])

    async def test_a_missing_log_reads_empty_rather_than_erroring(self):
        self.registry._state[("p1", OTHER_JOB)] = {
            "job_id": OTHER_JOB, "status": "done", "exit_code": 0,
            "started_at": "t0", "ended_at": "t1", "output_path": "",
        }
        body = _body(await api.kali_exec_status(OTHER_JOB, project_id="p1", cursor=0))
        self.assertEqual(body["output"], "")

    async def test_cancel_stops_the_job_and_says_what_that_means(self):
        """The note matters: cancelling the asyncio task does not stop the
        subprocess in the sandbox, so promising "stopped" would be a lie."""
        self._seed("p1", JOB, "partial")
        body = _body(await api.kali_exec_cancel(JOB, project_id="p1"))
        self.assertEqual(self.registry.cancelled, [JOB])
        self.assertEqual(body["status"], "cancelled")
        self.assertIn("may still be running", body["note"])

    async def test_cancelling_another_projects_job_is_not_found(self):
        self._seed("p1", JOB, "x")
        resp = await api.kali_exec_cancel(JOB, project_id="p2")
        self.assertEqual(resp.status_code, 404)
        self.assertEqual(self.registry.cancelled, [])


if __name__ == "__main__":
    unittest.main()


class FailedJobIsNotAMissingJobTests(_Base):
    """REGRESSION: a job that RAN AND FAILED was reported as "no such command".

    JobHandle carries its own `error` field, so `reg.status()` returns a dict
    with `error` set for a finished-but-failed run - a tool that exited
    non-zero, or the 300s kali_shell timeout. Both endpoints treated ANY
    `error` as a lookup miss and answered 404.

    Found live: a 5-minute nuclei scan hit kali_shell's 300s cap, the registry
    correctly recorded status=failed / exit_code=1 / error="[ERROR] Command
    timed out after 300 seconds.", and the caller polling it got "No such
    command." The output was on disk and unreachable, and the message said the
    job had never existed. That is the could-not-ask/found-nothing conflation
    this whole surface exists to prevent.
    """

    def _failed_job(self, error="[ERROR] Command timed out after 300 seconds."):
        self._seed("p1", JOB, "partial output before it died\n")
        self.registry._state[("p1", JOB)].update(
            {"status": "failed", "exit_code": 1, "error": error}
        )

    async def test_a_failed_job_is_readable_not_404(self):
        self._failed_job()
        resp = await api.kali_exec_status(JOB, project_id="p1", cursor=0)
        self.assertNotEqual(getattr(resp, "status_code", 200), 404)
        body = _body(resp)
        self.assertEqual(body["status"], "failed")
        self.assertEqual(body["exit_code"], 1)
        self.assertIn("partial output", body["output"])

    async def test_the_failure_reason_reaches_the_caller(self):
        # "it failed" without "why" sends an agent round the retry loop.
        self._failed_job()
        body = _body(await api.kali_exec_status(JOB, project_id="p1", cursor=0))
        self.assertIn("timed out after 300 seconds", body.get("error", ""))

    async def test_a_timed_out_scan_is_never_reported_as_a_clean_run(self):
        """The dangerous direction: a scan killed at 300s must not look like a
        scan that completed and found nothing."""
        self._failed_job()
        body = _body(await api.kali_exec_status(JOB, project_id="p1", cursor=0))
        self.assertNotEqual(body["status"], "done")
        self.assertNotEqual(body["exit_code"], 0)

    async def test_cancel_also_works_on_a_failed_job(self):
        self._failed_job()
        resp = await api.kali_exec_cancel(JOB, project_id="p1")
        self.assertNotEqual(getattr(resp, "status_code", 200), 404)

    async def test_a_genuine_lookup_miss_is_still_404(self):
        # The fix must not turn every unknown id into a 200.
        for bad in (OTHER_JOB, "c" * 32):
            resp = await api.kali_exec_status(bad, project_id="p1", cursor=0)
            self.assertEqual(resp.status_code, 404, bad)

    async def test_another_projects_failed_job_is_still_404(self):
        self._failed_job()
        resp = await api.kali_exec_status(JOB, project_id="p2", cursor=0)
        self.assertEqual(resp.status_code, 404)




# =============================================================================
# Per-user Kali sandboxes (group 1, S11): routed to the token's owner, `starting` on
# a cold sandbox, and the sandbox's failures as error codes.
# =============================================================================

import asyncio  # noqa: E402

import job_runner  # noqa: E402
import sandbox_contract as contract  # noqa: E402
import sandbox_router as router  # noqa: E402
import tools  # noqa: E402
from sandbox_route_fakes import (HARD_PAYLOAD, RAM_PAYLOAD, RAM_SENTENCE, WEBAPP,  # noqa: E402
                                 Fleet)


class _RoutedExecutor:
    """The executor's side of a /kali/exec job: which person's sandbox handle the call
    ran on (the one the runner bound), and what it answers."""

    def __init__(self):
        self.calls = []
        self.result = {"success": True, "output": "OK", "error": None}

    async def execute(self, name, args, phase, skip_phase_check=False):
        self.calls.append({"name": name, "args": args, "handle": tools.current_sandbox_handle(),
                           "person": router.sandbox_user()})
        return dict(self.result)


class _PerUserBase(unittest.IsolatedAsyncioTestCase):
    mode = contract.MODE_PER_USER

    async def asyncSetUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = self._tmp.name
        self.fleet = Fleet(self.mode)
        self.executor = _RoutedExecutor()
        router._reset(mode=None)
        self.registry = job_runner.JobRegistry()
        self._patches = [
            mock.patch.dict(os.environ, {"WORKSPACE_ROOT": self.root}),
            mock.patch.object(job_runner, "WORKSPACE_ROOT", Path(self.root)),
            mock.patch.object(api, "orchestrator", mock.Mock(tool_executor=self.executor)),
            mock.patch.object(api.job_runner, "get_registry", return_value=self.registry),
            mock.patch.object(router, "_transport", self.fleet.transport()),
            mock.patch.dict(router.INTERNAL_HEADERS, {"X-Internal-Key": "test-internal-key"}),
            mock.patch.object(router, "WEBAPP_API_URL", WEBAPP),
        ]
        for p in self._patches:
            p.start()

    async def asyncTearDown(self):
        await router._shutdown()
        for p in reversed(self._patches):
            p.stop()
        router._reset(mode=None)

    async def _exec(self, command="nmap -sV acme.tld", **kw):
        kw.setdefault("wait_seconds", 5)
        return await api.kali_exec(api.KaliExecRequest(project_id="p1", command=command, **kw))

    async def _finish(self, job_id):
        await self.registry.wait("p1", job_id, timeout_sec=10)

    async def _poll(self, job_id, **kw):
        return await api.kali_exec_status(job_id, project_id="p1", cursor=0, **kw)


class PerUserExecRoutingTests(_PerUserBase):
    async def test_a_cold_sandbox_answers_starting_at_once(self):
        """MCP kali_exec on a person whose sandbox is not running: the job exists at once
        and the answer says `starting`, without waiting for the cold start."""
        self.fleet.cold.add(("alice", "own"))
        self.fleet.ensure_delay = 0.3
        body = _body(await self._exec(user_id="alice"))
        self.assertEqual(body["status"], contract.KALI_EXEC_STATUS_STARTING)
        self.assertEqual(self.executor.calls, [], "the answer came before the command ran")
        await self._finish(body["job_id"])
        done = _body(await self._poll(body["job_id"]))
        self.assertEqual(done["status"], "done")
        self.assertIn("OK", done["output"])
        self.assertNotIn("error_code", done)

    async def test_a_running_sandbox_waits_as_today(self):
        self.fleet.add("alice")
        body = _body(await self._exec(user_id="alice"))
        self.assertEqual(body["status"], "done")
        self.assertIn("OK", body["output"])

    async def test_the_command_runs_in_the_token_owners_sandbox(self):
        bob = self.fleet.add("bob")
        alice = self.fleet.add("alice")
        body = _body(await self._exec(user_id="alice"))
        self.assertEqual(body["status"], "done")
        call = self.executor.calls[0]
        self.assertEqual(call["person"], "alice")
        self.assertEqual((call["handle"].user_id, call["handle"].view, call["handle"].instance),
                         ("alice", contract.VIEW_OWN, alice.instance))
        self.assertNotEqual(call["handle"].instance, bob.instance)
        self.assertEqual({b["userId"] for b in self.fleet.ensures()}, {"alice"})
        self.assertTrue(all(not b.get("actingAs") for b in self.fleet.ensures()))
        self.assertEqual([lease["kind"] for lease in self.fleet.leases()], ["exec"])
        self.assertEqual(len(self.fleet.releases()), 1, "the exec lease ends with the job")

    async def test_a_missing_person_is_refused_in_per_user_mode(self):
        self.fleet.add("alice")
        resp = await self._exec()
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(_body(resp)["code"], contract.ERR_INVALID_USER_ID)
        self.assertEqual(self.executor.calls, [])
        self.assertEqual(self.registry._jobs, {})

    async def test_a_malformed_person_is_refused(self):
        for bad in ("../alice", "a b", "x" * 65, "ensure"):
            resp = await self._exec(user_id=bad)
            self.assertEqual(resp.status_code, 400, bad)
        self.assertEqual(self.fleet.ensures(), [])


class PerUserExecFailureTests(_PerUserBase):
    async def _failed(self, **fleet):
        for key, value in fleet.items():
            setattr(self.fleet, key, value)
        body = _body(await self._exec(user_id="alice"))
        await self._finish(body["job_id"])
        return _body(await self._poll(body["job_id"]))

    async def test_not_enough_memory_is_the_ram_code_with_the_governors_sentence(self):
        view = await self._failed(ensure_answer=(409, {"code": contract.ERR_RAM, **RAM_PAYLOAD}))
        self.assertEqual(view["status"], "failed")
        self.assertEqual(view["error_code"], "ram")
        self.assertEqual(view["error"], RAM_SENTENCE)

    async def test_the_sandbox_limit_is_the_hard_code(self):
        view = await self._failed(ensure_answer=(409, {"code": contract.ERR_HARD, **HARD_PAYLOAD}))
        self.assertEqual(view["error_code"], "hard")
        self.assertEqual(view["error"], "3 of 3 Kali sandboxes allowed")

    async def test_a_refused_person_is_the_sandbox_refused_code(self):
        view = await self._failed(ensure_answer=(403, {"code": contract.ERR_USER_REFUSED}))
        self.assertEqual(view["error_code"], "sandbox_refused")
        self.assertEqual(view["error"], contract.SANDBOX_REFUSED)

    async def test_a_start_error_is_the_sandbox_error_code(self):
        view = await self._failed(ensure_answer=(503, {"code": contract.ERR_START_FAILED}))
        self.assertEqual(view["error_code"], "sandbox_error")
        self.assertEqual(view["error"], contract.SANDBOX_UNAVAILABLE_ERROR)

    async def test_a_sandbox_gone_during_the_call_is_the_sandbox_stopped_code(self):
        self.fleet.add("alice")
        self.executor.result = {"success": False, "output": None, "error": contract.SANDBOX_STOPPED}
        body = _body(await self._exec(user_id="alice"))
        await self._finish(body["job_id"])
        view = _body(await self._poll(body["job_id"]))
        self.assertEqual(view["status"], "failed")
        self.assertEqual(view["error_code"], "sandbox_stopped")
        self.assertEqual(view["error"], contract.SANDBOX_STOPPED)

    async def test_the_ram_text_is_only_ever_a_governor_sentence(self):
        """S18 review F3: the `error` of a ram/hard failure reaches the MCP caller
        verbatim, so it is the governor's fixed sentence or the contract's, never
        command output, an exception or whatever the ensure body carried."""
        hostile = dict(RAM_PAYLOAD, detail="uid=0(root) /proc/1/environ INTERNAL_API_KEY=xyz")
        view = await self._failed(ensure_answer=(409, {"code": contract.ERR_RAM, **hostile}))
        self.assertEqual(view["error_code"], "ram")
        self.assertEqual(view["error"], contract.SANDBOX_UNAVAILABLE_RAM)
        hostile = dict(HARD_PAYLOAD, detail="3 of 3 Kali sandboxes allowed; rm -rf /")
        router._reset(mode=None)
        view = await self._failed(ensure_answer=(409, {"code": contract.ERR_HARD, **hostile}))
        self.assertEqual(view["error"], contract.SANDBOX_UNAVAILABLE_HARD)

    async def test_an_error_code_never_comes_from_the_jobs_own_metadata(self):
        """The meta file sits in the project's workspace, which a sandbox writes: its
        fields never become an error code."""
        d = Path(self.root) / "p1" / "jobs"
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{JOB}.log").write_text("x")
        (d / f"{JOB}.meta.json").write_text(
            '{"job_id": "%s", "status": "failed", "error_code": "ram", "error": "forged"}' % JOB)
        view = _body(await self._poll(JOB))
        self.assertNotIn("error_code", view)


class PerUserPollAndCancelTests(_PerUserBase):
    """S18 review F2: a person polls or cancels only their own command when the webapp
    names them; another person's job is the same 404 as a job that does not exist."""

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.fleet.add("alice")
        self.fleet.add("bob")
        self.fleet.ensure_delay = 0.5
        self.fleet.cold.add(("carol", "own"))
        body = _body(await self._exec(user_id="carol", wait_seconds=0))
        self.job = body["job_id"]

    async def asyncTearDown(self):
        await self.registry.cancel("p1", self.job)
        await super().asyncTearDown()

    async def test_another_persons_job_is_not_found(self):
        resp = await self._poll(self.job, user_id="bob")
        self.assertEqual(resp.status_code, 404)
        resp = await api.kali_exec_cancel(self.job, project_id="p1", user_id="bob")
        self.assertEqual(resp.status_code, 404)
        self.assertEqual(self.registry.status("p1", self.job)["status"], "running")

    async def test_the_owner_polls_and_cancels(self):
        self.assertEqual((await self._poll(self.job, user_id="carol")).status_code, 200)
        resp = await api.kali_exec_cancel(self.job, project_id="p1", user_id="carol")
        self.assertEqual(_body(resp)["status"], "cancelled")

    async def test_without_a_person_the_route_answers_as_before(self):
        self.assertEqual((await self._poll(self.job)).status_code, 200)

    async def test_a_starting_job_reads_starting_when_polled(self):
        view = _body(await self._poll(self.job, user_id="carol"))
        self.assertEqual(view["status"], contract.KALI_EXEC_STATUS_STARTING)


class SharedModeExecTests(_PerUserBase):
    mode = contract.MODE_SHARED

    async def test_without_a_person_shared_mode_runs_as_today(self):
        body = _body(await self._exec())
        self.assertEqual(body["status"], "done")
        self.assertEqual(self.executor.calls[0]["handle"].mode, contract.MODE_SHARED)
        self.assertNotIn("error_code", body)

    async def test_with_a_person_shared_mode_runs_in_the_shared_sandbox(self):
        body = _body(await self._exec(user_id="alice"))
        self.assertEqual(body["status"], "done")
        self.assertEqual(self.executor.calls[0]["handle"].mode, contract.MODE_SHARED)
        self.assertEqual(self.fleet.leases(), [])
