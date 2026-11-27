"""
Tests for the scheduled scan delta alert outbox tick driven by scan_scheduler.py.

Run: python3 -m unittest tests.test_delta_alert_outbox_tick (from /app in the
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


class _Manager:
    ledger = None


class TestDeltaAlertOutboxTick(unittest.TestCase):
    def test_tick_calls_delta_alert_process_even_when_no_schedules_due(self):
        calls = []

        def fake_request(url, key, method="GET", payload=None, timeout=15.0):
            calls.append({"url": url, "method": method, "payload": payload})
            if url.endswith("/api/internal/scan-schedules/due"):
                return {"schedules": []}
            if url.endswith("/api/internal/delta-alerts/process"):
                return {"ok": True, "processed": 1, "sent": 1, "retried": 0, "failed": 0}
            return None

        with mock.patch.dict(os.environ, {
            "INTERNAL_API_KEY": "test-key",
            "WEBAPP_API_URL": "http://webapp:3000",
        }), mock.patch.object(ss, "_request", side_effect=fake_request):
            summary = asyncio.run(ss.run_scheduler_tick(_Manager()))

        self.assertEqual(summary, {"due": 0, "started": 0, "queued": 0, "failed": 0})
        process_calls = [c for c in calls if c["url"].endswith("/api/internal/delta-alerts/process")]
        self.assertEqual(len(process_calls), 1)
        self.assertEqual(process_calls[0]["method"], "POST")
        self.assertEqual(process_calls[0]["payload"], {})

    def test_delta_alert_process_exception_does_not_break_tick(self):
        def fake_request(url, key, method="GET", payload=None, timeout=15.0):
            if url.endswith("/api/internal/scan-schedules/due"):
                return {"schedules": []}
            if url.endswith("/api/internal/delta-alerts/process"):
                raise RuntimeError("transient error")
            return None

        with mock.patch.dict(os.environ, {
            "INTERNAL_API_KEY": "test-key",
            "WEBAPP_API_URL": "http://webapp:3000",
        }), mock.patch.object(ss, "_request", side_effect=fake_request):
            summary = asyncio.run(ss.run_scheduler_tick(_Manager()))

        self.assertEqual(summary, {"due": 0, "started": 0, "queued": 0, "failed": 0})


if __name__ == "__main__":
    unittest.main()
