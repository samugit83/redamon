"""GVM scan hardening - regression tests for issue #174.

Three independent defects put a GVM scan into a state where it ran for 18 hours
and produced nothing:

  1. The scan read its project settings with INTERNAL_API_KEY, but the
     orchestrator hands scan containers the SCOPED SCANNER_API_KEY, so the webapp
     answered 401 and every user-chosen setting was silently replaced by defaults.
  2. gvmd lists the OpenVAS scanner from its own database, so the scan connected
     happily even though ospd-openvas was never started, then sat at 0% until the
     4h task timeout - once per target, 1140 targets.
  3. (compose-side, covered by tests/redamon_gvm_compose_test.sh)

These tests pin 1 and 2.

Issue #177 then showed the #174 fix was itself the next defect: the stall
watchdog inferred "nothing is running this" from "the percentage has not moved",
and killed healthy full-IANA port sweeps at 30 minutes while ospd-openvas was up
and working. The detector is now VERIFY_SCANNER run on a cadence during the wait,
which answers the question directly instead of guessing from a clock.
"""
import contextlib
import io
import sys
import unittest
from pathlib import Path
from unittest import mock
from xml.etree import ElementTree as ET

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scanners"))

from gvm_scan import gvm_scanner as gvm_mod  # noqa: E402
from gvm_scan import project_settings as gvm_settings  # noqa: E402
from github_secret_hunt import project_settings as hunt_settings  # noqa: E402


def _json_response(payload):
    resp = mock.Mock()
    resp.json.return_value = payload
    resp.raise_for_status.return_value = None
    return resp


class ScannerTokenTest(unittest.TestCase):
    """The scan must present the token it was actually given."""

    def test_gvm_settings_fetch_sends_the_scanner_token(self):
        with mock.patch.dict("os.environ", {"SCANNER_API_KEY": "scoped-tok",
                                            "INTERNAL_API_KEY": "master-tok"}, clear=False), \
             mock.patch("requests.get", return_value=_json_response({})) as get:
            gvm_settings.fetch_gvm_settings("proj-1", "http://webapp:3000")

        sent = get.call_args.kwargs["headers"]["X-Internal-Key"]
        self.assertEqual(sent, "scoped-tok",
                         "the GVM scan must send SCANNER_API_KEY, not the master key")

    def test_gvm_settings_fetch_falls_back_to_the_master_key(self):
        """Pre-secret installs have no SCANNER_API_KEY; those must not break."""
        env = {"INTERNAL_API_KEY": "master-tok"}
        with mock.patch.dict("os.environ", env, clear=True), \
             mock.patch("requests.get", return_value=_json_response({})) as get:
            gvm_settings.fetch_gvm_settings("proj-1", "http://webapp:3000")

        self.assertEqual(get.call_args.kwargs["headers"]["X-Internal-Key"], "master-tok")

    def test_gvm_settings_are_applied_not_defaulted(self):
        """The 401 made every project value fall back to DEFAULT_GVM_SETTINGS."""
        project = {"gvmScanConfig": "Discovery", "gvmScanTargets": "ips_only",
                   "gvmTaskTimeout": 600, "gvmPollInterval": 5,
                   "gvmCleanupAfterScan": False}
        with mock.patch.dict("os.environ", {"SCANNER_API_KEY": "scoped-tok"}, clear=False), \
             mock.patch("requests.get", return_value=_json_response(project)):
            settings = gvm_settings.fetch_gvm_settings("proj-1", "http://webapp:3000")

        self.assertEqual(settings["SCAN_CONFIG"], "Discovery")
        self.assertEqual(settings["TASK_TIMEOUT"], 600)
        self.assertNotEqual(settings["TASK_TIMEOUT"],
                            gvm_settings.DEFAULT_GVM_SETTINGS["TASK_TIMEOUT"])

    def test_github_hunt_sends_the_scanner_token_on_both_calls(self):
        """The hunt reads the project AND the user's GitHub token; both were 401."""
        with mock.patch.dict("os.environ", {"SCANNER_API_KEY": "scoped-tok",
                                            "INTERNAL_API_KEY": "master-tok",
                                            "USER_ID": "user-1"}, clear=False), \
             mock.patch("requests.get", return_value=_json_response({})) as get:
            hunt_settings.fetch_github_settings("proj-1", "http://webapp:3000")

        self.assertGreaterEqual(get.call_count, 2, "expected a project and a user-settings call")
        for call in get.call_args_list:
            self.assertEqual(call.kwargs["headers"]["X-Internal-Key"], "scoped-tok")

    def test_no_scanner_reads_the_master_key_alone(self):
        """Structural: the next scanner added must not repeat the omission.

        The S3/E6 rollout updated recon and supply-chain but missed gvm_scan and
        github_secret_hunt, and nothing failed until a live scan 401'd.
        """
        offenders = []
        for settings_file in sorted((REPO_ROOT / "scanners").glob("*/project_settings.py")):
            # Comments are stripped first: the whole point is what the CODE sends,
            # and every one of these call sites carries a comment naming the key.
            lines = [ln.split("#", 1)[0] for ln in settings_file.read_text().splitlines()]
            for lineno, line in enumerate(lines, 1):
                if "X-Internal-Key" not in line:
                    continue
                # The credential may be built on a preceding line (supply-chain) or
                # wrapped onto the next one (gvm, hunt), so look either side.
                window = "\n".join(lines[max(0, lineno - 4):lineno + 2])
                if "SCANNER_API_KEY" not in window:
                    offenders.append(f"{settings_file.relative_to(REPO_ROOT)}:{lineno}")
        self.assertEqual(offenders, [],
                         "these scanners send only the master key and will 401: "
                         + ", ".join(offenders))


def _task(status, progress, report_id="report-1"):
    return ET.fromstring(
        f'<get_tasks_response><task id="task-1">'
        f'<status>{status}</status><progress>{progress}</progress>'
        f'<report id="{report_id}"/></task></get_tasks_response>'
    )


def _scanner(**overrides):
    """A GVMScanner built without python-gvm present (the agent test image)."""
    with mock.patch.object(gvm_mod, "GVM_AVAILABLE", True):
        s = gvm_mod.GVMScanner(socket_path="/tmp/none", username="u", password="p",
                               scan_config="Full and fast", task_timeout=0, poll_interval=0)
    for k, v in overrides.items():
        setattr(s, k, v)
    return s


class ScannerLivenessTest(unittest.TestCase):
    """A scanner row in gvmd's database is not a running scanner."""

    @staticmethod
    def _verify_response(status, status_text="detail"):
        return ET.fromstring(
            f'<verify_scanner_response status="{status}" status_text="{status_text}"/>'
        )

    def test_unreachable_scanner_is_rejected(self):
        s = _scanner()
        s.scanner_id = "scanner-1"
        s.gmp = mock.Mock()
        s.gmp.verify_scanner.return_value = self._verify_response(
            "500", "Service temporarily down")

        with self.assertRaises(RuntimeError) as ctx:
            s._verify_scanner_alive()
        self.assertIn("not reachable", str(ctx.exception))
        self.assertIn("ospd", str(ctx.exception))

    def test_reachable_scanner_passes(self):
        s = _scanner()
        s.scanner_id = "scanner-1"
        s.gmp = mock.Mock()
        s.gmp.verify_scanner.return_value = self._verify_response("200", "OK")
        s._verify_scanner_alive()   # must not raise

    def test_a_service_down_status_is_what_blocks(self):
        for status in gvm_mod.GVMScanner.SCANNER_DOWN_STATUSES:
            with self.subTest(status=status):
                s = _scanner()
                s.scanner_id = "scanner-1"
                s.gmp = mock.Mock()
                s.gmp.verify_scanner.return_value = self._verify_response(
                    status, "Service temporarily down")
                with self.assertRaises(RuntimeError):
                    s._verify_scanner_alive()

    def test_an_inconclusive_reply_never_vetoes_a_healthy_stack(self):
        """A probe that can block a working scan is worse than no probe."""
        for status in ("400", "404", "401", ""):
            with self.subTest(status=status):
                s = _scanner()
                s.scanner_id = "scanner-1"
                s.gmp = mock.Mock()
                s.gmp.verify_scanner.return_value = self._verify_response(
                    status, "Bad command")
                s._verify_scanner_alive()   # no verdict is not a failure

    def test_a_raising_verify_does_not_block_the_scan(self):
        s = _scanner()
        s.scanner_id = "scanner-1"
        s.gmp = mock.Mock()
        s.gmp.verify_scanner.side_effect = OSError("socket closed")
        s._verify_scanner_alive()   # must not raise

    def test_connect_verifies_liveness(self):
        """The probe has to be ON the connect path, not merely defined."""
        src = (REPO_ROOT / "scanners/gvm_scan/gvm_scanner.py").read_text()
        connect_body = src.split("def connect(", 1)[1].split("\n    def ", 1)[0]
        self.assertIn("self._verify_scanner_alive()", connect_body)


class StallWatchdogTest(unittest.TestCase):
    """The OPT-IN stall bound (0 = off by default, see ScannerLivenessDuringScanTest).

    It survives as an operator ceiling, but it is no longer how a dead stack is
    detected, because it cannot tell a dead scanner from a slow port list.
    """

    class _Clock:
        """time.time() advancing a fixed step per call."""

        def __init__(self, step=60.0):
            self.now = 0.0
            self.step = step

        def __call__(self):
            self.now += self.step
            return self.now

    def test_a_task_that_never_progresses_is_abandoned(self):
        # task_timeout stays at the shipped 4h so this test is BOUNDED: strip the
        # watchdog and it raises TimeoutError instead of looping forever, which is
        # a clean red rather than a hung suite.
        s = _scanner(no_progress_timeout=1800, task_timeout=14400)
        s.gmp = mock.Mock()
        s.gmp.get_task.return_value = _task("Running", "0")

        with mock.patch.object(gvm_mod.time, "sleep"), \
             mock.patch.object(gvm_mod.time, "time", self._Clock()):
            with self.assertRaises(RuntimeError) as ctx:
                s.wait_for_task("task-1")

        message = str(ctx.exception)
        self.assertIn("no progress", message)
        # It must NOT claim the scanner is dead: this bound fires while the
        # scanner is still answering, and blaming ospd sent issue #177 chasing
        # a broker that had nothing to do with the failure.
        self.assertNotIn("redamon-gvm-ospd", message)
        self.assertIn("GVM_NO_PROGRESS_TIMEOUT", message)

    def test_minus_one_progress_also_trips_it(self):
        """gvmd reports -1 for a task that has produced nothing at all."""
        s = _scanner(no_progress_timeout=600, task_timeout=14400)
        s.gmp = mock.Mock()
        s.gmp.get_task.return_value = _task("Running", "-1")

        with mock.patch.object(gvm_mod.time, "sleep"), \
             mock.patch.object(gvm_mod.time, "time", self._Clock()):
            with self.assertRaises(RuntimeError):
                s.wait_for_task("task-1")

    def test_a_slow_but_advancing_scan_is_never_cut_off(self):
        """The watchdog measures time since the last MOVE, not since the start."""
        s = _scanner(no_progress_timeout=120)
        s.gmp = mock.Mock()
        # Each poll advances by 1%, far slower than the 120s watchdog window,
        # then finishes. A start-relative timer would kill this scan.
        s.gmp.get_task.side_effect = (
            [_task("Running", str(p)) for p in range(1, 40)] + [_task("Done", "100")]
        )

        with mock.patch.object(gvm_mod.time, "sleep"), \
             mock.patch.object(gvm_mod.time, "time", self._Clock()):
            status, report_id = s.wait_for_task("task-1")

        self.assertEqual(status, "Done")
        self.assertEqual(report_id, "report-1")

    def test_a_finished_task_is_reported_even_with_no_progress_number(self):
        """Terminal status wins over the watchdog."""
        s = _scanner(no_progress_timeout=1)
        s.gmp = mock.Mock()
        s.gmp.get_task.return_value = _task("Done", "-1")

        with mock.patch.object(gvm_mod.time, "sleep"), \
             mock.patch.object(gvm_mod.time, "time", self._Clock()):
            status, _ = s.wait_for_task("task-1")
        self.assertEqual(status, "Done")

    def test_the_watchdog_can_be_disabled(self):
        s = _scanner(no_progress_timeout=0, task_timeout=100)
        s.gmp = mock.Mock()
        s.gmp.get_task.return_value = _task("Running", "0")

        with mock.patch.object(gvm_mod.time, "sleep"), \
             mock.patch.object(gvm_mod.time, "time", self._Clock()):
            # With the watchdog off, only the task timeout stops it.
            with self.assertRaises(TimeoutError):
                s.wait_for_task("task-1")

    def test_it_ships_disabled(self):
        """Issue #177: the 1800s default killed healthy scans. 0 means off."""
        self.assertEqual(gvm_settings.DEFAULT_GVM_SETTINGS["NO_PROGRESS_TIMEOUT"], 0)

    def test_the_liveness_probe_replaced_it_as_the_detector(self):
        defaults = gvm_settings.DEFAULT_GVM_SETTINGS
        self.assertGreater(defaults["LIVENESS_INTERVAL"], 0,
                           "with the stall bound off, something must catch a dead stack")
        self.assertLess(defaults["LIVENESS_INTERVAL"], defaults["TASK_TIMEOUT"],
                        "a probe that outlasts the task timeout never runs")


class FailureStreakTest(unittest.TestCase):
    """A broken stack fails every target, so the scan must stop asking."""

    def setUp(self):
        from gvm_scan import main as gvm_main
        self.main = gvm_main

    @staticmethod
    def _failed(error="Task made no progress for 1800s"):
        return {"status": "error", "error": error, "vulnerabilities": []}

    @staticmethod
    def _ok():
        return {"status": "Done", "vulnerability_count": 2, "vulnerabilities": []}

    def test_failures_below_the_limit_keep_scanning(self):
        streak = 0
        for i in range(self.main.MAX_CONSECUTIVE_TARGET_FAILURES - 1):
            streak = self.main.check_failure_streak(self._failed(), streak, f"10.0.0.{i}")
        self.assertEqual(streak, self.main.MAX_CONSECUTIVE_TARGET_FAILURES - 1)

    def test_the_limit_aborts_the_scan(self):
        streak = self.main.MAX_CONSECUTIVE_TARGET_FAILURES - 1
        with self.assertRaises(self.main.ScanAborted) as ctx:
            self.main.check_failure_streak(self._failed(), streak, "10.0.0.9")
        message = str(ctx.exception)
        self.assertIn("redamon-gvm-ospd", message)
        self.assertIn("10.0.0.9", message)

    def test_a_working_target_resets_the_streak(self):
        """Targets legitimately fail one at a time; only a RUN of them is systemic."""
        streak = self.main.MAX_CONSECUTIVE_TARGET_FAILURES - 1
        streak = self.main.check_failure_streak(self._ok(), streak, "10.0.0.1")
        self.assertEqual(streak, 0)
        # ...and the next failure therefore starts counting again from one.
        streak = self.main.check_failure_streak(self._failed(), streak, "10.0.0.2")
        self.assertEqual(streak, 1)

    def test_both_scan_phases_use_the_breaker(self):
        """IP and hostname phases are separate loops; neither may be left out."""
        src = (REPO_ROOT / "scanners/gvm_scan/main.py").read_text()
        self.assertEqual(src.count("check_failure_streak("), 3,
                         "expected the helper definition plus one call per scan phase")


class StallWatchdogKnobTest(unittest.TestCase):
    """The watchdog message tells operators to raise the bound, so it must exist.

    A genuinely slow target (a full IANA port sweep against a filtered host) can
    sit at 0% past the 30-minute default, and an operator hitting that needs a
    lever. It is deliberately an env pin, not a project setting: it is a
    diagnostic bound, and it must be adjustable without a webapp round-trip.
    """

    def test_the_pin_overrides_the_default(self):
        with mock.patch.dict("os.environ", {"GVM_NO_PROGRESS_TIMEOUT": "3600"}, clear=False):
            self.assertEqual(gvm_settings.get_setting("NO_PROGRESS_TIMEOUT"), 3600)

    def test_no_pin_keeps_the_shipped_default(self):
        env = {k: v for k, v in __import__("os").environ.items()
               if k != "GVM_NO_PROGRESS_TIMEOUT"}
        with mock.patch.dict("os.environ", env, clear=True):
            self.assertEqual(gvm_settings.get_setting("NO_PROGRESS_TIMEOUT"), 0)

    def test_an_unparseable_pin_never_changes_the_value(self):
        """A stray export must not silently reintroduce a ceiling."""
        for bad in ("", "   ", "abc", "30m"):
            with self.subTest(value=bad):
                with mock.patch.dict("os.environ",
                                     {"GVM_NO_PROGRESS_TIMEOUT": bad}, clear=False):
                    self.assertEqual(gvm_settings.get_setting("NO_PROGRESS_TIMEOUT"), 0)

    def test_the_liveness_interval_has_its_own_pin(self):
        with mock.patch.dict("os.environ", {"GVM_LIVENESS_INTERVAL": "45"}, clear=False):
            self.assertEqual(gvm_settings.get_setting("LIVENESS_INTERVAL"), 45)

    def test_the_pin_survives_project_settings_being_loaded(self):
        """API-sourced settings must not clobber the operator's pin."""
        project = {"gvmTaskTimeout": 600}
        with mock.patch.dict("os.environ", {"GVM_NO_PROGRESS_TIMEOUT": "60",
                                            "WEBAPP_API_URL": "http://webapp:3000"}, clear=False), \
             mock.patch("requests.get", return_value=_json_response(project)):
            gvm_settings.reload_settings("proj-knob")
            self.assertEqual(gvm_settings.get_setting("NO_PROGRESS_TIMEOUT"), 60)
            self.assertEqual(gvm_settings.get_setting("TASK_TIMEOUT"), 600)
        gvm_settings.reload_settings()   # do not leak cached state to other tests

    def test_the_message_names_the_real_variable(self):
        """The error must name the knob that actually controls it."""
        src = (REPO_ROOT / "scanners/gvm_scan/gvm_scanner.py").read_text()
        start = src.index("made no progress for")
        stall_msg = src[start:start + 900]      # the whole raise block, f-strings included
        self.assertIn("GVM_NO_PROGRESS_TIMEOUT", stall_msg)
        env_names = set(gvm_settings._ENV_OVERRIDES.values())
        self.assertIn("GVM_NO_PROGRESS_TIMEOUT", env_names)


class ScannerlessStackTest(unittest.TestCase):
    """End to end on the reported symptom, through the real code paths.

    Reproduces the state the issue was filed from: gvmd is up and accepts
    everything, but nothing is running the scans. Before the fix this walked
    1140 targets at 4h each; here it must give up after MAX_CONSECUTIVE_TARGET_
    FAILURES, having spent one stall window per target.
    """

    def test_the_scan_gives_up_instead_of_walking_1140_targets(self):
        """Through the SHIPPED defaults: no stall bound, liveness does the work."""
        from gvm_scan import main as gvm_main

        scanner = _scanner(no_progress_timeout=0, task_timeout=14400)
        scanner.config_id = "cfg-1"
        scanner.scanner_id = "scanner-1"
        scanner.port_list_id = "pl-1"
        # A gvmd with no scanner behind it: every call succeeds, the task is
        # accepted, and it then sits at 0% forever. VERIFY_SCANNER is the one
        # call that tells the truth about it.
        gmp = mock.Mock()
        gmp.verify_scanner.return_value = ET.fromstring(
            '<verify_scanner_response status="503" status_text="Service down"/>')
        gmp.get_report.side_effect = OSError("no report")
        gmp.create_target.return_value = ET.fromstring('<r status="201" id="tgt-1"/>')
        gmp.create_task.return_value = ET.fromstring('<r status="201" id="task-1"/>')
        gmp.start_task.return_value = ET.fromstring(
            '<r status="202"><report_id>rep-1</report_id></r>')
        gmp.get_task.return_value = _task("Running", "0")
        scanner.gmp = gmp

        targets = [f"10.0.0.{n}" for n in range(1, 1141)]
        attempted = 0
        streak = 0

        # python-gvm is absent from the test image, so AliveTest is None and
        # create_target would raise before the scan ever reached wait_for_task.
        # Without this the test passes on the wrong failure and proves nothing
        # about the detector it names.
        with mock.patch.object(gvm_mod.time, "sleep"), \
             mock.patch.object(gvm_mod, "AliveTest", mock.Mock()), \
             mock.patch.object(gvm_mod.time, "time", StallWatchdogTest._Clock()):
            with self.assertRaises(gvm_main.ScanAborted) as ctx:
                for ip in targets:
                    attempted += 1
                    result = scanner.scan_targets(targets=[ip], target_name=f"IP_{ip}",
                                                  cleanup=False)
                    streak = gvm_main.check_failure_streak(result, streak, ip)

        self.assertEqual(attempted, gvm_main.MAX_CONSECUTIVE_TARGET_FAILURES,
                         "the scan must stop after the streak limit, not grind on")
        self.assertLess(attempted, len(targets))
        self.assertIn("redamon-gvm-ospd", str(ctx.exception))
        # And each target died on the liveness verdict, not after a stall window.
        self.assertEqual(gmp.verify_scanner.call_count, attempted,
                         "one decisive probe per target, no waiting")


class ScannerLivenessDuringScanTest(unittest.TestCase):
    """The dead-stack detector is a question to gvmd, not a guess from a clock.

    Issue #177: the old detector inferred "nothing is running this" from "the
    percentage has not moved in 30 minutes". That is wrong in both directions. It
    killed healthy full-IANA port sweeps, and it could not see a scanner that died
    PART WAY through a scan, because progress had already advanced.
    """

    @staticmethod
    def _verify(status, status_text="detail"):
        return ET.fromstring(
            f'<verify_scanner_response status="{status}" status_text="{status_text}"/>'
        )

    def _scanner_with(self, verify_status, **overrides):
        s = _scanner(**overrides)
        s.scanner_id = "scanner-1"
        s.gmp = mock.Mock()
        s.gmp.get_task.return_value = _task("Running", "-1")
        s.gmp.get_report.side_effect = OSError("no report yet")
        s.gmp.verify_scanner.return_value = self._verify(verify_status)
        return s

    def test_a_dead_scanner_fails_the_task_on_the_first_poll(self):
        """No stall window: it stops as soon as gvmd says the service is down."""
        s = self._scanner_with("503", no_progress_timeout=0, task_timeout=14400)
        with mock.patch.object(gvm_mod.time, "sleep"), \
             mock.patch.object(gvm_mod.time, "time", StallWatchdogTest._Clock()):
            with self.assertRaises(RuntimeError) as ctx:
                s.wait_for_task("task-1")
        message = str(ctx.exception)
        self.assertIn("stopped answering", message)
        self.assertIn("ospd", message)
        self.assertEqual(s.gmp.verify_scanner.call_count, 1,
                         "the verdict is available on the very first poll")

    def test_a_scan_at_zero_percent_is_never_killed_while_the_scanner_answers(self):
        """The exact issue #177 shape: no percent for ages, healthy scanner."""
        s = self._scanner_with("200", no_progress_timeout=0, task_timeout=0)
        s.gmp.get_task.side_effect = ([_task("Running", "-1")] * 500
                                      + [_task("Done", "100")])
        with mock.patch.object(gvm_mod.time, "sleep"), \
             mock.patch.object(gvm_mod.time, "time", StallWatchdogTest._Clock()):
            status, report_id = s.wait_for_task("task-1")
        self.assertEqual(status, "Done")
        self.assertEqual(report_id, "report-1")

    def test_a_scanner_that_dies_mid_scan_is_caught(self):
        """The failure a progress-based watchdog structurally cannot detect."""
        s = self._scanner_with("200", no_progress_timeout=0, task_timeout=0)
        # Progress keeps ADVANCING, so no stall bound would ever fire...
        s.gmp.get_task.side_effect = [_task("Running", str(p)) for p in range(1, 400)]
        # ...but the scanner goes away partway through.
        s.gmp.verify_scanner.side_effect = ([self._verify("200")] * 3
                                            + [self._verify("503")] * 50)
        with mock.patch.object(gvm_mod.time, "sleep"), \
             mock.patch.object(gvm_mod.time, "time", StallWatchdogTest._Clock()):
            with self.assertRaises(RuntimeError) as ctx:
                s.wait_for_task("task-1")
        self.assertIn("stopped answering", str(ctx.exception))

    def test_the_probe_is_rate_limited_not_run_on_every_poll(self):
        """VERIFY_SCANNER is a round trip to ospd; it must not run once a poll."""
        s = self._scanner_with("200", no_progress_timeout=0, task_timeout=0)
        s.gmp.get_task.side_effect = ([_task("Running", "-1")] * 30
                                      + [_task("Done", "100")])
        with mock.patch.object(gvm_mod.time, "sleep"), \
             mock.patch.object(gvm_mod.time, "time", StallWatchdogTest._Clock()):
            s.wait_for_task("task-1")
        self.assertGreaterEqual(s.gmp.verify_scanner.call_count, 2)
        self.assertLess(s.gmp.verify_scanner.call_count, 30,
                        "the probe must be throttled, not once per poll")

    def test_the_probe_can_be_disabled(self):
        s = self._scanner_with("503", no_progress_timeout=0, task_timeout=100,
                               liveness_interval=0)
        with mock.patch.object(gvm_mod.time, "sleep"), \
             mock.patch.object(gvm_mod.time, "time", StallWatchdogTest._Clock()):
            with self.assertRaises(TimeoutError):
                s.wait_for_task("task-1")
        s.gmp.verify_scanner.assert_not_called()

    def test_an_inconclusive_verdict_does_not_kill_a_running_scan(self):
        """Mid-scan the probe must be exactly as forgiving as it is on connect."""
        s = self._scanner_with("400", no_progress_timeout=0, task_timeout=0)
        s.gmp.get_task.side_effect = ([_task("Running", "-1")] * 20
                                      + [_task("Done", "100")])
        with mock.patch.object(gvm_mod.time, "sleep"), \
             mock.patch.object(gvm_mod.time, "time", StallWatchdogTest._Clock()):
            status, _ = s.wait_for_task("task-1")
        self.assertEqual(status, "Done")

    def test_a_raising_probe_does_not_kill_a_running_scan(self):
        s = self._scanner_with("200", no_progress_timeout=0, task_timeout=0)
        s.gmp.verify_scanner.side_effect = OSError("socket closed")
        s.gmp.get_task.side_effect = ([_task("Running", "-1")] * 20
                                      + [_task("Done", "100")])
        with mock.patch.object(gvm_mod.time, "sleep"), \
             mock.patch.object(gvm_mod.time, "time", StallWatchdogTest._Clock()):
            status, _ = s.wait_for_task("task-1")
        self.assertEqual(status, "Done")

    def test_the_probe_is_on_the_wait_path_not_merely_defined(self):
        """Defining it and never calling it is what left #174 half-fixed."""
        src = (REPO_ROOT / "scanners/gvm_scan/gvm_scanner.py").read_text()
        body = src.split("def wait_for_task(", 1)[1].split("\n    def ", 1)[0]
        self.assertIn("self._verify_scanner_alive()", body)


class PortListTest(unittest.TestCase):
    """The port list decides how long a healthy scan LOOKS dead.

    Issue #177: "All IANA assigned TCP and UDP" was hardcoded as first choice with
    no way to change it. Its UDP half answers closed ports with silence, so every
    one must be timed out, and gvmd reports no percent until that finishes.
    """

    # The real names, verified against a live gvmd and the data-objects feed.
    # Inventing fixture names is what let a non-existent default ship.
    ALL_THREE = ("All IANA assigned TCP and UDP", "All IANA assigned TCP",
                 "All TCP and Nmap top 100 UDP")

    @classmethod
    def _port_lists(cls, *names):
        inner = "".join(f'<port_list id="pl-{i}"><name>{n}</name></port_list>'
                        for i, n in enumerate(names))
        return ET.fromstring(
            f'<get_port_lists_response>{inner}</get_port_lists_response>')

    def _resolve(self, configured, available=None):
        s = _scanner(port_list_name=configured)
        s.gmp = mock.Mock()
        s.gmp.get_port_lists.return_value = self._port_lists(
            *(available or self.ALL_THREE))
        s._cache_port_list_id()
        return s.port_list_id

    def test_the_shipped_default_is_not_the_full_udp_sweep(self):
        self.assertEqual(gvm_settings.DEFAULT_GVM_SETTINGS["PORT_LIST"],
                         "All TCP and Nmap top 100 UDP")

    def test_the_configured_list_is_the_one_used(self):
        self.assertEqual(self._resolve("All TCP and Nmap top 100 UDP"), "pl-2")

    def test_an_operator_can_still_choose_the_full_sweep(self):
        self.assertEqual(self._resolve("All IANA assigned TCP and UDP"), "pl-0")
        self.assertEqual(self._resolve("All IANA assigned TCP"), "pl-1")

    def test_a_missing_list_falls_back_to_the_cheapest_not_the_costliest(self):
        """The old order fell TOWARDS the full sweep; that was the bug."""
        self.assertEqual(self._resolve("Nonexistent List"), "pl-2")

    def test_the_setting_is_read_from_the_project(self):
        project = {"gvmPortList": "All IANA assigned TCP"}
        with mock.patch("requests.get", return_value=_json_response(project)):
            settings = gvm_settings.fetch_gvm_settings("proj-pl", "http://webapp:3000")
        self.assertEqual(settings["PORT_LIST"], "All IANA assigned TCP")

    def test_a_project_saved_before_the_field_existed_keeps_the_default(self):
        with mock.patch("requests.get", return_value=_json_response({})):
            settings = gvm_settings.fetch_gvm_settings("proj-pl", "http://webapp:3000")
        self.assertEqual(settings["PORT_LIST"],
                         gvm_settings.DEFAULT_GVM_SETTINGS["PORT_LIST"])

    def test_the_prisma_default_matches_the_python_default(self):
        """Drift here means the UI shows one list and the scan uses another."""
        schema = (REPO_ROOT / "webapp/prisma/schema.prisma").read_text()
        line = [ln for ln in schema.splitlines() if "gvmPortList" in ln]
        self.assertTrue(line, "gvmPortList is missing from the Prisma schema")
        self.assertIn(gvm_settings.DEFAULT_GVM_SETTINGS["PORT_LIST"], line[0])
        self.assertIn('@map("gvm_port_list")', line[0])

    def test_the_frontend_offers_the_setting_with_a_matching_fallback(self):
        section = (REPO_ROOT / "webapp/src/components/projects/ProjectForm"
                   / "sections/GvmScanSection.tsx").read_text()
        self.assertIn("gvmPortList", section)
        self.assertIn(gvm_settings.DEFAULT_GVM_SETTINGS["PORT_LIST"], section)


class ScanVisibilityTest(unittest.TestCase):
    """A healthy slow scan and a hung stack must not print the same thing.

    They did: 30 minutes of identical "Scanning..." lines carry no evidence
    either way, which is why issue #177 was filed against the scanner.
    """

    def test_minus_one_and_zero_are_described_differently(self):
        minus = gvm_mod.GVMScanner._describe_progress("-1")
        zero = gvm_mod.GVMScanner._describe_progress("0")
        self.assertNotEqual(minus, zero,
                            "conflating them threw away the one available signal")
        self.assertIn("discovery", minus)

    def test_a_real_percentage_is_shown_as_one(self):
        self.assertEqual(gvm_mod.GVMScanner._describe_progress("42"), "42%")

    def test_activity_reports_hosts_and_results(self):
        s = _scanner()
        s.gmp = mock.Mock()
        s.gmp.get_report.return_value = ET.fromstring(
            '<get_reports_response><report>'
            '<scan_run_status>Running</scan_run_status>'
            '<hosts><count>3</count></hosts>'
            '<result_count><full>17</full></result_count>'
            '</report></get_reports_response>')
        line = s._scan_activity("rep-1")
        self.assertIn("Hosts done: 3", line)
        self.assertIn("Results: 17", line)
        self.assertIn("Running", line)

    def test_activity_never_raises_and_never_fails_a_scan(self):
        """Observability must not be able to break the thing it observes."""
        s = _scanner()
        s.gmp = mock.Mock()
        s.gmp.get_report.side_effect = OSError("gvmd went away")
        self.assertIsNone(s._scan_activity("rep-1"))

    def test_activity_is_skipped_when_there_is_no_report_yet(self):
        s = _scanner()
        s.gmp = mock.Mock()
        self.assertIsNone(s._scan_activity(None))
        s.gmp.get_report.assert_not_called()

    def test_the_poll_line_carries_liveness_and_activity(self):
        s = _scanner(no_progress_timeout=0, task_timeout=0)
        s.scanner_id = "scanner-1"
        s.gmp = mock.Mock()
        s.gmp.get_task.side_effect = [_task("Running", "-1"), _task("Done", "100")]
        s.gmp.verify_scanner.return_value = ET.fromstring(
            '<verify_scanner_response status="200" status_text="OK"/>')
        s.gmp.get_report.return_value = ET.fromstring(
            '<get_reports_response><report><hosts><count>1</count></hosts>'
            '<result_count><full>5</full></result_count>'
            '</report></get_reports_response>')

        buf = io.StringIO()
        with mock.patch.object(gvm_mod.time, "sleep"), \
             mock.patch.object(gvm_mod.time, "time", StallWatchdogTest._Clock()), \
             contextlib.redirect_stdout(buf):
            s.wait_for_task("task-1")

        out = buf.getvalue()
        self.assertIn("Scanner: alive", out)
        self.assertIn("Hosts done: 1", out)
        self.assertIn("Results: 5", out)
        self.assertIn("discovery", out)



class DeepReviewRegressionTest(unittest.TestCase):
    """One test per defect found in the hardening review, named after the defect.

    These are not hypotheticals: each was reproduced against the real scan image
    before the fix landed.
    """

    # --- an empty <progress/> was rendered as "None%" ----------------------
    @staticmethod
    def _task_with_empty_progress(status="Running"):
        return ET.fromstring(
            f'<get_tasks_response><task id="task-1"><status>{status}</status>'
            f'<progress></progress><report id="report-1"/></task></get_tasks_response>'
        )

    def test_an_empty_progress_element_is_not_rendered_as_none_percent(self):
        """gvmd sends <progress/> with no text; .text is None, not "0"."""
        node = self._task_with_empty_progress().find('.//progress')
        self.assertIsNone(node.text, "precondition: the element really is textless")
        for raw in (None, "", "   "):
            with self.subTest(raw=raw):
                rendered = gvm_mod.GVMScanner._describe_progress(raw)
                self.assertNotIn("None", rendered)
                self.assertNotEqual(rendered.strip(), "%")
                self.assertIn("discovery", rendered)

    def test_a_non_numeric_progress_is_labelled_not_suffixed_with_percent(self):
        """"abc%" is a lie; say the value was not understood."""
        rendered = gvm_mod.GVMScanner._describe_progress("abc")
        self.assertNotEqual(rendered, "abc%")
        self.assertIn("unrecognised", rendered)

    def test_a_negative_or_large_progress_still_renders_as_a_percentage(self):
        self.assertEqual(gvm_mod.GVMScanner._describe_progress("100"), "100%")
        self.assertEqual(gvm_mod.GVMScanner._describe_progress("-2"), "-2%")

    def test_the_port_discovery_hint_fires_for_an_empty_progress_element(self):
        """The hint exists for "gvmd reports nothing"; it must fire there."""
        s = _scanner(no_progress_timeout=0, task_timeout=0, liveness_interval=0)
        s.gmp = mock.Mock()
        s.gmp.get_task.side_effect = ([self._task_with_empty_progress()] * 5
                                      + [_task("Done", "100")])
        buf = io.StringIO()
        with mock.patch.object(gvm_mod.time, "sleep"), \
             mock.patch.object(gvm_mod.time, "time", StallWatchdogTest._Clock()), \
             contextlib.redirect_stdout(buf):
            s.wait_for_task("task-1")
        out = buf.getvalue()
        self.assertIn("port-discovery phase", out)
        self.assertNotIn("None%", out)

    # --- terminal statuses printed no final line --------------------------
    def test_a_terminal_status_still_prints_a_final_line(self):
        """Returning straight out left the run ending on a stale poll line."""
        for status in ("Done", "Stopped", "Interrupted"):
            with self.subTest(status=status):
                s = _scanner(no_progress_timeout=0, task_timeout=0, liveness_interval=0)
                s.gmp = mock.Mock()
                s.gmp.get_task.return_value = _task(status, "100")
                buf = io.StringIO()
                with mock.patch.object(gvm_mod.time, "sleep"), \
                     mock.patch.object(gvm_mod.time, "time", StallWatchdogTest._Clock()), \
                     contextlib.redirect_stdout(buf):
                    try:
                        s.wait_for_task("task-1")
                    except RuntimeError:
                        pass    # Stopped/Interrupted raise by design
                self.assertIn(f"Status: {status}", buf.getvalue())

    # --- an empty <status/> crashed the whole poll loop ---------------------
    def test_an_empty_status_element_does_not_crash_the_poll_loop(self):
        """`"Error" in None` is a TypeError, and it failed an otherwise fine target."""
        empty_status = ET.fromstring(
            '<get_tasks_response><task id="task-1"><status></status>'
            '<progress>0</progress><report id="report-1"/></task></get_tasks_response>')
        s = _scanner(no_progress_timeout=0, task_timeout=0, liveness_interval=0)
        s.gmp = mock.Mock()
        s.gmp.get_task.side_effect = [empty_status] * 3 + [_task("Done", "100")]

        buf = io.StringIO()
        with mock.patch.object(gvm_mod.time, "sleep"), \
             mock.patch.object(gvm_mod.time, "time", StallWatchdogTest._Clock()), \
             contextlib.redirect_stdout(buf):
            status, report_id = s.wait_for_task("task-1")   # must not raise TypeError

        self.assertEqual(status, "Done")
        self.assertEqual(report_id, "report-1")
        self.assertIn("Unknown", buf.getvalue(),
                      "a textless status must be reported, not silently blank")

    def test_a_missing_status_element_is_also_survivable(self):
        no_status = ET.fromstring(
            '<get_tasks_response><task id="task-1"><progress>0</progress>'
            '<report id="report-1"/></task></get_tasks_response>')
        s = _scanner(no_progress_timeout=0, task_timeout=0, liveness_interval=0)
        s.gmp = mock.Mock()
        s.gmp.get_task.side_effect = [no_status, _task("Done", "100")]
        with mock.patch.object(gvm_mod.time, "sleep"), \
             mock.patch.object(gvm_mod.time, "time", StallWatchdogTest._Clock()), \
             contextlib.redirect_stdout(io.StringIO()):
            status, _ = s.wait_for_task("task-1")
        self.assertEqual(status, "Done")

    # --- an explicit null port list bypassed the default -------------------
    def test_an_explicit_null_port_list_falls_back_to_the_default(self):
        """dict.get(k, default) returns None when the key EXISTS and is null."""
        for stored in (None, ""):
            with self.subTest(stored=stored):
                with mock.patch("requests.get",
                                return_value=_json_response({"gvmPortList": stored})):
                    settings = gvm_settings.fetch_gvm_settings("p", "http://webapp:3000")
                self.assertEqual(settings["PORT_LIST"],
                                 gvm_settings.DEFAULT_GVM_SETTINGS["PORT_LIST"])

    def test_a_null_port_list_never_reaches_the_scanner_as_none(self):
        with mock.patch.object(gvm_mod, "get_setting",
                               side_effect=lambda k, d=None: None if k == "PORT_LIST" else d):
            s = _scanner()
        self.assertEqual(s.port_list_name, gvm_mod.DEFAULT_PORT_LIST_FALLBACKS[0])


class PortListBoundaryTest(unittest.TestCase):
    """Boundary and hostile values for the one new user-settable string."""

    def _resolve(self, configured):
        s = _scanner(port_list_name=configured)
        s.gmp = mock.Mock()
        s.gmp.get_port_lists.return_value = PortListTest._port_lists(*PortListTest.ALL_THREE)
        s._cache_port_list_id()
        return s.port_list_id

    def test_hostile_and_boundary_names_degrade_to_a_safe_fallback(self):
        """The name is compared, never interpolated, so nothing can be injected."""
        for value in ("", "   ", "x" * 5000, "üñïçø∂é", "'; DROP TABLE configs;--",
                      "<script>alert(1)</script>", "../../etc/passwd", "\x00null"):
            with self.subTest(value=value[:24]):
                self.assertEqual(self._resolve(value),
                                 "pl-2", "must land on the cheapest known list")

    def test_no_port_list_at_all_leaves_the_id_at_the_known_default_uuid(self):
        """An empty GVM (no lists yet) must not crash target creation."""
        s = _scanner(port_list_name="All TCP and Nmap top 100 UDP")
        s.gmp = mock.Mock()
        s.gmp.get_port_lists.return_value = ET.fromstring(
            '<get_port_lists_response></get_port_lists_response>')
        s._cache_port_list_id()
        self.assertEqual(s.port_list_id,
                         PortListFeedContractTest.GREENBONE_PORT_LISTS[
                             gvm_settings.DEFAULT_GVM_SETTINGS["PORT_LIST"]])

    def test_the_scan_never_sends_a_user_string_as_a_port_list_id(self):
        """port_list_id must always be an id GVM itself returned."""
        s = _scanner(port_list_name="'; DROP TABLE configs;--")
        s.gmp = mock.Mock()
        s.gmp.get_port_lists.return_value = PortListTest._port_lists(*PortListTest.ALL_THREE)
        s._cache_port_list_id()
        self.assertNotIn("DROP TABLE", str(s.port_list_id))
        self.assertTrue(str(s.port_list_id).startswith("pl-"))


class LivenessBoundaryTest(unittest.TestCase):
    """Boundary values and degraded dependencies for the new probe."""

    def test_a_negative_interval_is_treated_as_disabled(self):
        s = _scanner(no_progress_timeout=0, task_timeout=100, liveness_interval=-5)
        s.gmp = mock.Mock()
        s.gmp.get_task.return_value = _task("Running", "0")
        with mock.patch.object(gvm_mod.time, "sleep"), \
             mock.patch.object(gvm_mod.time, "time", StallWatchdogTest._Clock()):
            with self.assertRaises(TimeoutError):
                s.wait_for_task("task-1")
        s.gmp.verify_scanner.assert_not_called()

    def test_a_slow_report_call_cannot_stall_or_fail_the_wait(self):
        """A hanging/erroring gvmd report must not take the scan with it."""
        s = _scanner(no_progress_timeout=0, task_timeout=0)
        s.scanner_id = "scanner-1"
        s.gmp = mock.Mock()
        s.gmp.verify_scanner.return_value = ET.fromstring(
            '<verify_scanner_response status="200" status_text="OK"/>')
        s.gmp.get_report.side_effect = TimeoutError("gvmd is slow")
        s.gmp.get_task.side_effect = [_task("Running", "-1")] * 5 + [_task("Done", "100")]
        with mock.patch.object(gvm_mod.time, "sleep"), \
             mock.patch.object(gvm_mod.time, "time", StallWatchdogTest._Clock()):
            status, _ = s.wait_for_task("task-1")
        self.assertEqual(status, "Done")

    def test_a_malformed_report_response_yields_no_activity_not_a_crash(self):
        s = _scanner()
        s.gmp = mock.Mock()
        s.gmp.get_report.return_value = ET.fromstring('<nonsense/>')
        self.assertIsNone(s._scan_activity("rep-1"))

    def test_activity_is_skipped_when_there_is_no_gmp_connection(self):
        """wait_for_task can be reached with gmp cleared by a failed reconnect."""
        s = _scanner()
        s.gmp = None
        self.assertIsNone(s._scan_activity("rep-1"))

    def test_every_terminal_status_is_handled(self):
        """Stop Requested and Error were the two branches nothing exercised."""
        cases = {"Stop Requested": "was stopped", "Error - something": "Task failed"}
        for status, expected in cases.items():
            with self.subTest(status=status):
                s = _scanner(no_progress_timeout=0, task_timeout=0, liveness_interval=0)
                s.gmp = mock.Mock()
                s.gmp.get_task.return_value = _task(status, "0")
                buf = io.StringIO()
                with mock.patch.object(gvm_mod.time, "sleep"), \
                     mock.patch.object(gvm_mod.time, "time", StallWatchdogTest._Clock()), \
                     contextlib.redirect_stdout(buf):
                    with self.assertRaises(RuntimeError) as ctx:
                        s.wait_for_task("task-1")
                self.assertIn(expected, str(ctx.exception))
                self.assertIn(f"Status: {status}", buf.getvalue())

    def test_partial_report_data_still_reports_what_it_has(self):
        """Hosts present, results absent: show hosts rather than nothing."""
        s = _scanner()
        s.gmp = mock.Mock()
        s.gmp.get_report.return_value = ET.fromstring(
            '<r><report><hosts><count>4</count></hosts></report></r>')
        line = s._scan_activity("rep-1")
        self.assertIn("Hosts done: 4", line)
        self.assertNotIn("Results:", line)



class SettingsTenantScopeTest(unittest.TestCase):
    """The scan may only ever ask for the project it was spawned for.

    Route-level cross-tenant enforcement lives in requireProjectAccess and is
    covered by webapp/src/lib/access.test.ts; this feature adds no route, so what
    is pinned here is the client half: the scan must not be able to widen its own
    scope, and the port list it applies must come from its own project.
    """

    def test_the_fetch_url_names_only_the_projects_own_id(self):
        with mock.patch("requests.get", return_value=_json_response({})) as get:
            gvm_settings.fetch_gvm_settings("proj-A", "http://webapp:3000")
        url = get.call_args.args[0] if get.call_args.args else get.call_args.kwargs["url"]
        self.assertTrue(url.endswith("/api/projects/proj-A"), url)
        self.assertNotIn("proj-B", url)

    def test_another_projects_port_list_cannot_leak_in_through_the_response(self):
        """Only the documented key is read; stray fields are ignored."""
        payload = {"gvmPortList": "All IANA assigned TCP",
                   "otherProjectGvmPortList": "All IANA assigned TCP and UDP",
                   "id": "proj-B"}
        with mock.patch("requests.get", return_value=_json_response(payload)):
            settings = gvm_settings.fetch_gvm_settings("proj-A", "http://webapp:3000")
        self.assertEqual(settings["PORT_LIST"], "All IANA assigned TCP")

    def test_the_defaults_endpoint_key_matches_the_prisma_field(self):
        """/defaults derives camelCase from the Python key (recon_orchestrator/api.py).

        Drift here is silent: the endpoint serves a key the Project row does not
        have, and fetch_gvm_settings then reads None for every project.
        """
        def to_gvm_camel(snake_str):        # mirrors api.py exactly
            parts = f"gvm_{snake_str}".lower().split('_')
            return parts[0] + ''.join(x.title() for x in parts[1:])

        self.assertEqual(to_gvm_camel("PORT_LIST"), "gvmPortList")
        schema = (REPO_ROOT / "webapp/prisma/schema.prisma").read_text()
        self.assertIn("gvmPortList", schema)


class ProbeCostTest(unittest.TestCase):
    """The probe runs inside a loop that can poll for hours; it must stay cheap."""

    def test_the_report_is_fetched_per_liveness_tick_not_per_poll(self):
        """An N+1 here would be one full report round trip every 30s for hours."""
        s = _scanner(no_progress_timeout=0, task_timeout=0)
        s.scanner_id = "scanner-1"
        s.gmp = mock.Mock()
        s.gmp.verify_scanner.return_value = ET.fromstring(
            '<verify_scanner_response status="200" status_text="OK"/>')
        s.gmp.get_report.return_value = ET.fromstring(
            '<r><report><hosts><count>1</count></hosts></report></r>')
        polls = 30
        s.gmp.get_task.side_effect = ([_task("Running", "-1")] * polls
                                      + [_task("Done", "100")])

        with mock.patch.object(gvm_mod.time, "sleep"), \
             mock.patch.object(gvm_mod.time, "time", StallWatchdogTest._Clock()):
            s.wait_for_task("task-1")

        self.assertLess(s.gmp.get_report.call_count, polls // 2,
                        "get_report must follow the liveness cadence, not the poll rate")
        self.assertEqual(s.gmp.get_report.call_count, s.gmp.verify_scanner.call_count,
                         "both refresh on the same tick, so one round trip pair each")

    def test_get_task_is_still_the_only_per_poll_call(self):
        s = _scanner(no_progress_timeout=0, task_timeout=0, liveness_interval=0)
        s.gmp = mock.Mock()
        s.gmp.get_task.side_effect = [_task("Running", "-1")] * 10 + [_task("Done", "100")]
        with mock.patch.object(gvm_mod.time, "sleep"), \
             mock.patch.object(gvm_mod.time, "time", StallWatchdogTest._Clock()):
            s.wait_for_task("task-1")
        self.assertEqual(s.gmp.get_task.call_count, 11)
        s.gmp.get_report.assert_not_called()



class PortListFeedContractTest(unittest.TestCase):
    """Every port-list name RedAmon ships must be one GVM actually has.

    Caught by a live run, not by this suite: the default shipped as "All TCP and
    Nmap top 1000 UDP", which does not exist - the Greenbone feed ships top *100*.
    A name that cannot match never errors; it just falls through, so the scan
    quietly ran "All IANA assigned TCP" (no UDP at all) while the UI's recommended
    option was unselectable. The unit fixtures could not catch it because they
    invented their own names, so this class pins the real ones.
    """

    # The COMPLETE set shipped by the Greenbone community data-objects feed,
    # cross-checked against gvmd's predefined port_lists rows (uuid included so a
    # hardcoded fallback id cannot drift from the name it claims).
    GREENBONE_PORT_LISTS = {
        "All IANA assigned TCP":         "33d0cd82-57c6-11e1-8ed1-406186ea4fc5",
        "All IANA assigned TCP and UDP": "4a4717fe-57d2-11e1-9a26-406186ea4fc5",
        "All TCP and Nmap top 100 UDP":  "730ef368-57e2-11e1-a90f-406186ea4fc5",
    }

    SECTION = ("webapp/src/components/projects/ProjectForm/sections/"
               "GvmScanSection.tsx")

    def test_every_fallback_name_exists_in_gvm(self):
        for name in gvm_mod.DEFAULT_PORT_LIST_FALLBACKS:
            with self.subTest(name=name):
                self.assertIn(name, self.GREENBONE_PORT_LISTS)

    def test_the_shipped_python_default_exists_in_gvm(self):
        self.assertIn(gvm_settings.DEFAULT_GVM_SETTINGS["PORT_LIST"],
                      self.GREENBONE_PORT_LISTS)

    def test_the_prisma_default_exists_in_gvm(self):
        schema = (REPO_ROOT / "webapp/prisma/schema.prisma").read_text()
        line = next(ln for ln in schema.splitlines() if "gvmPortList" in ln)
        quoted = line.split('@default("')[1].split('")')[0]
        self.assertIn(quoted, self.GREENBONE_PORT_LISTS)
        self.assertEqual(quoted, gvm_settings.DEFAULT_GVM_SETTINGS["PORT_LIST"])

    def test_every_option_the_ui_offers_exists_in_gvm(self):
        """An unselectable option silently becomes something else."""
        import re
        tsx = (REPO_ROOT / self.SECTION).read_text()
        block = tsx.split("gvmPortList", 1)[1].split("</select>", 1)[0]
        options = re.findall(r'<option value="([^"]+)"', block)
        self.assertTrue(options, "no port-list options rendered")
        for value in options:
            with self.subTest(option=value):
                self.assertIn(value, self.GREENBONE_PORT_LISTS)

    def test_the_ui_offers_every_list_gvm_has(self):
        import re
        tsx = (REPO_ROOT / self.SECTION).read_text()
        block = tsx.split("gvmPortList", 1)[1].split("</select>", 1)[0]
        self.assertEqual(set(re.findall(r'<option value="([^"]+)"', block)),
                         set(self.GREENBONE_PORT_LISTS))

    def test_the_last_resort_uuid_is_the_default_lists_uuid(self):
        """A hardcoded id that names a different list is a silent scope change."""
        src = (REPO_ROOT / "scanners/gvm_scan/gvm_scanner.py").read_text()
        tail = src.split("def _cache_port_list_id", 1)[1]
        uuid = tail.split('self.port_list_id = "')[-1].split('"')[0]
        self.assertEqual(
            uuid,
            self.GREENBONE_PORT_LISTS[gvm_settings.DEFAULT_GVM_SETTINGS["PORT_LIST"]])



if __name__ == "__main__":
    unittest.main()
