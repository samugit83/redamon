"""
Scan Timeline — Scan Scheduler worker (plan Section 7.2 / 7.3, F3).

The worker is a TICKER, not the thing that starts scans: the webapp owns the
version freeze and the ScanJob history, so what must hold here is

  - it asks the webapp what is due,
  - it DEFERS (never spawns) when the project's graph is mid-activation (F3),
  - it DEFERS when the ledger has no headroom, using a NON-RESERVING read so a
    pre-check can never leak an envelope,
  - it otherwise asks the webapp to run the schedule,
  - and a single bad schedule/response never kills the loop.

Run: python3 -m unittest tests.test_scan_scheduler   (from /app in the
recon-orchestrator container).
"""
from __future__ import annotations

import asyncio
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import scan_scheduler as ss  # noqa: E402

MB = 1024 ** 2


class _Ledger:
    def __init__(self, remaining=8000 * MB, envelope=2000 * MB):
        self._remaining = remaining
        self._envelope = envelope
        self.admit_calls = []

    def remaining_for_new(self):
        return self._remaining

    def envelope_for(self, kind):
        return self._envelope

    async def try_admit(self, *a, **kw):  # must never be called by the worker
        self.admit_calls.append((a, kw))
        raise AssertionError("the worker must not reserve; start_recon owns admission")


class _Manager:
    def __init__(self, ledger=None):
        self.ledger = ledger or _Ledger()


def _run_tick(responses, manager=None):
    """Drive one tick with a scripted _request; returns (summary, calls)."""
    calls = []

    def fake_request(url, key, method="GET", payload=None, timeout=15.0):
        calls.append({"url": url, "method": method, "payload": payload})
        for pattern, value in responses:
            if pattern in url:
                return value() if callable(value) else value
        return None

    with mock.patch.dict(os.environ, {
        "INTERNAL_API_KEY": "test-key",
        "WEBAPP_API_URL": "http://webapp:3000",
    }), mock.patch.object(ss, "_request", side_effect=fake_request):
        summary = asyncio.run(ss.run_scheduler_tick(manager or _Manager()))
    return summary, calls


def _due(**over):
    sched = {
        "id": "sched1",
        "projectId": "p1",
        "userId": "u1",
        "mode": "interval",
        "scanMode": "new",
        "nextRunAt": "2026-07-30T12:00:00Z",
        "estimatedEnvelopeBytes": 2000 * MB,
        "activationInProgress": False,
    }
    sched.update(over)
    return {"now": "2026-07-30T12:00:01Z", "schedules": [sched]}


class TestConfig(unittest.TestCase):
    def test_enabled_by_default_and_switchable(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertTrue(ss.scheduler_enabled())
        for off in ("false", "0", "no", "off"):
            with mock.patch.dict(os.environ, {"SCAN_SCHEDULER_ENABLED": off}):
                self.assertFalse(ss.scheduler_enabled())

    def test_tick_interval_has_a_floor(self):
        with mock.patch.dict(os.environ, {"SCAN_SCHEDULER_TICK_SECONDS": "1"}):
            self.assertEqual(ss.tick_seconds(), ss.MIN_TICK_SECONDS)
        with mock.patch.dict(os.environ, {"SCAN_SCHEDULER_TICK_SECONDS": "not-a-number"}):
            self.assertEqual(ss.tick_seconds(), ss.DEFAULT_TICK_SECONDS)
        with mock.patch.dict(os.environ, {"SCAN_SCHEDULER_TICK_SECONDS": "300"}):
            self.assertEqual(ss.tick_seconds(), 300.0)


class TestTick(unittest.TestCase):
    def test_nothing_due_is_a_no_op(self):
        summary, calls = _run_tick([("/due", {"schedules": []})])
        self.assertEqual(summary, {"due": 0, "started": 0, "queued": 0, "failed": 0})
        schedule_calls = [c for c in calls if "/scan-schedules/" in c["url"]]
        self.assertEqual(len(schedule_calls), 1)

    def test_runs_a_due_schedule_via_the_webapp(self):
        summary, calls = _run_tick([
            ("/due", _due()),
            ("/run", {"ok": True, "scanJobId": "job1"}),
        ])
        self.assertEqual(summary["started"], 1)
        run_calls = [c for c in calls if c["url"].endswith("/run")]
        self.assertEqual(len(run_calls), 1)
        self.assertEqual(run_calls[0]["method"], "POST")
        self.assertIn("/api/internal/scan-schedules/sched1/run", run_calls[0]["url"])

    def test_a_temporary_refusal_is_ENQUEUED_not_deferred(self):
        # Phase 4: the worker no longer pre-checks or defers. It always calls /run;
        # a temporary refusal comes back as {ok:false, queued:true} because the run
        # route turned the occurrence into a durable queue row.
        ledger = _Ledger(remaining=100 * MB, envelope=2000 * MB)
        summary, calls = _run_tick(
            [("/due", _due()), ("/run", {"ok": False, "queued": True, "blockedCode": "ram"})],
            manager=_Manager(ledger),
        )
        self.assertEqual(summary["queued"], 1)
        self.assertEqual(summary["started"], 0)
        self.assertEqual(summary["failed"], 0)
        # It STILL calls /run (never a removed /defer route) ...
        self.assertTrue([c for c in calls if c["url"].endswith("/run")])
        self.assertFalse([c for c in calls if c["url"].endswith("/defer")])
        # ... and R1 holds: the worker never reserves.
        self.assertEqual(ledger.admit_calls, [])

    def test_always_runs_even_with_a_tight_ledger(self):
        # No pre-check remains, so a tight ledger does not stop the /run call.
        ledger = _Ledger(remaining=1 * MB, envelope=2000 * MB)
        summary, calls = _run_tick(
            [("/due", _due()), ("/run", {"ok": True})],
            manager=_Manager(ledger),
        )
        self.assertEqual(summary["started"], 1)
        self.assertTrue([c for c in calls if c["url"].endswith("/run")])
        self.assertEqual(ledger.admit_calls, [])

    def test_a_permanent_rejection_is_counted_but_does_not_raise(self):
        summary, _ = _run_tick([
            ("/due", _due()),
            ("/run", {"ok": False, "error": "Project has no target domain configured"}),
        ])
        self.assertEqual(summary["failed"], 1)
        self.assertEqual(summary["started"], 0)
        self.assertEqual(summary["queued"], 0)

    def test_a_transport_failure_on_run_is_counted_but_does_not_raise(self):
        summary, _ = _run_tick([("/due", _due()), ("/run", None)])
        self.assertEqual(summary["failed"], 1)

    def test_an_unreachable_webapp_skips_the_tick(self):
        summary, _ = _run_tick([("/due", None)])
        self.assertEqual(summary, {"due": 0, "started": 0, "queued": 0, "failed": 0})

    def test_without_an_internal_key_the_worker_does_nothing(self):
        calls = []

        def fake_request(*a, **kw):
            calls.append(a)
            return None

        with mock.patch.dict(os.environ, {"INTERNAL_API_KEY": ""}), \
                mock.patch.object(ss, "_request", side_effect=fake_request):
            summary = asyncio.run(ss.run_scheduler_tick(_Manager()))
        self.assertEqual(summary["due"], 0)
        self.assertEqual(calls, [], "no credentialed call may be attempted without a key")

    def test_a_schedule_without_an_id_is_skipped_not_fatal(self):
        payload = _due()
        payload["schedules"].append({"projectId": "p2"})  # malformed, no id
        summary, calls = _run_tick([("/due", payload), ("/run", {"ok": True})])
        self.assertEqual(summary["started"], 1)
        self.assertEqual(len([c for c in calls if c["url"].endswith("/run")]), 1)

    def test_a_manager_without_a_ledger_still_runs(self):
        class _NoLedger:
            ledger = None

        summary, _ = _run_tick([("/due", _due()), ("/run", {"ok": True})], manager=_NoLedger())
        self.assertEqual(summary["started"], 1)


class TestLoop(unittest.TestCase):
    def test_disabled_loop_returns_immediately(self):
        with mock.patch.dict(os.environ, {"SCAN_SCHEDULER_ENABLED": "false"}):
            asyncio.run(asyncio.wait_for(ss.scan_scheduler_loop(lambda: None), timeout=2))

    def test_a_failing_tick_does_not_kill_the_loop(self):
        async def drive():
            with mock.patch.dict(os.environ, {
                "SCAN_SCHEDULER_ENABLED": "true",
                "SCAN_SCHEDULER_TICK_SECONDS": "10",  # clamped to the floor
                "INTERNAL_API_KEY": "k",
            }), mock.patch.object(ss, "run_scheduler_tick",
                                  side_effect=RuntimeError("boom")):
                task = asyncio.create_task(ss.scan_scheduler_loop(lambda: _Manager()))
                await asyncio.sleep(0.05)
                self.assertFalse(task.done(), "the loop must survive a failing tick")
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

        asyncio.run(drive())


if __name__ == "__main__":
    unittest.main()
