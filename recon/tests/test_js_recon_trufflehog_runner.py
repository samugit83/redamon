"""Running the TruffleHog sidecar: budget, pause, stop, failures, cleanup.

`subprocess` is mocked; nothing starts a container. The budget counts running
time in ticks capped at 4 s, so a recon pause (this process frozen, then one
large clock jump) never spends it. The stage dir is a copy of target JS: it is
gone on every path and never sits in js_recon's work_dir.
"""

from __future__ import annotations

import io
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers import shutdown
from recon.helpers.js_recon import trufflehog_bridge as th


class FakeProc:
    """A Popen whose process ends after `polls_alive` polls, or when killed."""

    def __init__(self, stdout="", stderr="", returncode=0, polls_alive=0):
        self.stdout = io.StringIO(stdout)
        self.stderr = io.StringIO(stderr)
        self._rc = returncode
        self._alive = polls_alive
        self.returncode = None
        self.killed = False

    def poll(self):
        if self.killed or self._alive <= 0:
            self.returncode = 137 if self.killed else self._rc
            return self.returncode
        self._alive -= 1
        return None

    def wait(self, timeout=None):
        if self.returncode is None:
            self.returncode = 137 if self.killed else self._rc
        return self.returncode


class Clock:
    def __init__(self, steps):
        self.t = 0.0
        self.steps = list(steps)

    def __call__(self):
        return self.t

    def sleep(self, _s):
        self.t += self.steps.pop(0) if self.steps else 2.0


def _run(proc, budget=60.0, steps=(), docker=None, stop=False):
    clock = Clock(steps)
    calls = []

    def fake_docker(args, timeout=30):
        calls.append(args)
        if args[:1] == ["kill"]:
            proc.killed = True
        return mock.Mock(returncode=0, stdout="", stderr="")

    with mock.patch.object(th.subprocess, "Popen", return_value=proc) as popen, \
            mock.patch.object(th, "_docker", side_effect=docker or fake_docker), \
            mock.patch.object(th, "_stop_requested", return_value=stop):
        res = th.run_sidecar(["docker", "run"], name="redamon-jsth-x", budget_s=budget,
                             clock=clock, sleep=clock.sleep)
    return res, popen, calls


class Budget(unittest.TestCase):
    def test_spent_budget_kills_by_name(self):
        res, _, calls = _run(FakeProc(polls_alive=10_000), budget=10.0)
        self.assertEqual(res.status, "timed_out")
        self.assertIn(["kill", "redamon-jsth-x"], calls)

    def test_a_120s_clock_gap_counts_at_most_4s(self):
        # Ticks: 2 s, then a 120 s pause, then 2 s: 8 s counted against a 10 s
        # budget. Without the cap the pause alone would kill it.
        proc = FakeProc(polls_alive=3, stdout="")
        res, _, calls = _run(proc, budget=10.0, steps=[2.0, 120.0, 2.0, 2.0])
        self.assertEqual(res.status, "ran")
        self.assertNotIn(["kill", "redamon-jsth-x"], calls)

    def test_a_long_pause_never_times_out_alone(self):
        proc = FakeProc(polls_alive=3)
        res, _, _ = _run(proc, budget=15.0, steps=[3600.0, 3600.0, 3600.0])
        self.assertEqual(res.status, "ran")


class Outcomes(unittest.TestCase):
    def test_ran(self):
        res, popen, _ = _run(FakeProc(stdout='{"DetectorName":"Github","Raw":"x"}\n'))
        self.assertEqual(res.status, "ran")
        self.assertIn("Github", res.stdout)
        self.assertIsNone(popen.call_args.kwargs.get("env"))
        self.assertIn("env", popen.call_args.kwargs)

    def test_exit_1_is_failed_with_a_short_stderr_tail(self):
        stderr = "\n".join(f'{{"level":"error","msg":"line {i} {"x" * 400}"}}' for i in range(9))
        res, _, _ = _run(FakeProc(stderr=stderr, returncode=1))
        self.assertEqual((res.status, res.reason), ("failed", "exit 1"))
        self.assertEqual(len(res.stderr_tail), 5)
        self.assertTrue(all(len(line) <= 300 for line in res.stderr_tail))

    def test_broker_refusal_and_cap(self):
        refused = "docker: Error response from daemon: denied by docker-broker: image not on allowlist: 'x'"
        busy = "docker: Error response from daemon: denied by docker-broker: broker container count cap reached (48/48)"
        self.assertEqual(_run(FakeProc(stderr=refused, returncode=125))[0].reason, "broker_refused")
        self.assertEqual(_run(FakeProc(stderr=busy, returncode=125))[0].reason, "broker_busy")

    def test_stop_requested_is_stopped_and_kills_nothing(self):
        res, _, calls = _run(FakeProc(polls_alive=100), stop=True)
        self.assertEqual(res.status, "stopped")
        self.assertNotIn(["kill", "redamon-jsth-x"], calls)

    def test_a_refused_launch_is_stopped(self):
        with mock.patch.object(th.subprocess, "Popen",
                               side_effect=shutdown.ToolLaunchRefused("stopping")), \
                mock.patch.object(th, "_stop_requested", return_value=False):
            res = th.run_sidecar(["docker"], name="n", budget_s=10)
        self.assertEqual(res.status, "stopped")

    def test_stdout_over_the_cap_is_truncated(self):
        lines = "".join('{"DetectorName":"G","Raw":"r"}\n' for _ in range(th._STDOUT_MAX_LINES + 5))
        res, _, _ = _run(FakeProc(stdout=lines, polls_alive=3))
        self.assertEqual(res.status, "truncated")
        self.assertLessEqual(res.stdout.count("\n"), th._STDOUT_MAX_LINES)


class RunAndStage(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.files = [{"url": "https://a.example.com/main.js", "content": "var a=1;"},
                      {"url": "https://a.example.com/x.js.map#src/app.js", "content": "var b=2;"},
                      {"url": "upload://keys.js", "content": "var c=3;"},
                      {"url": "https://a.example.com/empty.js", "content": "  "}]

    def tearDown(self):
        import shutil
        shutil.rmtree(self.root, ignore_errors=True)

    def _run(self, side, image=True):
        seen = {}

        def fake_run_sidecar(argv, *, name, budget_s):
            stage = argv[argv.index("-v") + 1].split(":", 1)[0]
            seen["stage"] = stage
            seen["files"] = sorted(os.listdir(stage))
            seen["argv"] = argv
            return side

        with mock.patch.object(th, "image_available", return_value=image), \
                mock.patch.object(th, "run_sidecar", side_effect=fake_run_sidecar) as rs, \
                mock.patch.object(th, "ensure_verify_network", return_value=True), \
                mock.patch.dict(os.environ, {"RECON_RUN_ID": "run-42"}), \
                mock.patch.object(th.shutdown if hasattr(th, "shutdown") else shutdown,
                                  "register_drain") as drain, \
                mock.patch.object(th.atexit, "register") as at_exit:
            out = th.run(self.files, verify=False, concurrency=4, validation_timeout=5,
                         budget_s=30, root=self.root)
        return out, seen, rs, drain, at_exit

    def test_stage_dir_is_named_for_the_run_and_removed(self):
        out, seen, _, drain, at_exit = self._run(th.SidecarResult("ran"))
        self.assertEqual(out.status, "ran")
        self.assertTrue(os.path.basename(seen["stage"]).startswith("js_recon_th_run-42_"))
        self.assertEqual(seen["files"], ["f_00001.js", "f_00002.js", "f_00003.js"])
        self.assertFalse(os.path.exists(seen["stage"]))
        drain.assert_called_once()
        at_exit.assert_called_once()
        self.assertEqual([e["url"] for e in out.manifest.values()],
                         [f["url"] for f in self.files[:3]])

    def test_removed_on_failure_and_on_exception(self):
        out, seen, _, _, _ = self._run(th.SidecarResult("failed", "exit 1"))
        self.assertEqual(out.status, "failed")
        self.assertFalse(os.path.exists(seen["stage"]))
        with mock.patch.object(th, "image_available", return_value=True), \
                mock.patch.object(th, "run_sidecar", side_effect=RuntimeError("boom")), \
                mock.patch.object(th, "_stop_requested", return_value=False):
            out = th.run(self.files, verify=False, concurrency=4, validation_timeout=5,
                         budget_s=30, root=self.root)
        self.assertEqual((out.status, out.reason), ("failed", "RuntimeError"))
        self.assertEqual(os.listdir(self.root), [])

    def test_image_missing_runs_no_container(self):
        out, seen, rs, _, _ = self._run(th.SidecarResult("ran"), image=False)
        self.assertEqual((out.status, out.reason), ("skipped", "image_missing"))
        rs.assert_not_called()
        self.assertEqual(os.listdir(self.root), [])

    def test_never_under_the_work_dir(self):
        _, seen, _, _, _ = self._run(th.SidecarResult("ran"))
        self.assertNotRegex(os.path.basename(seen["stage"]), r"^js_recon_[0-9a-f]{12}$")
        self.assertTrue(os.path.basename(seen["stage"]).startswith(th.STAGE_PREFIX))


if __name__ == "__main__":
    unittest.main()
