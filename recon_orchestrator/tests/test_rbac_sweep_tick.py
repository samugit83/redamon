"""
The RBAC expiry sweep tick (step 4.15; SH-14, DV-09, T19): the webapp has no scheduler, so the
orchestrator's reaper asks it to sweep expired shares, overrides, break-glass rows and links every
RBAC_SWEEP_INTERVAL seconds (300), as it asks it to prune MCP tokens. The tick must:
  - POST /api/internal/rbac/sweep with the internal key at most once per interval,
  - make no call without the internal key,
  - survive an empty or bad RBAC_SWEEP_INTERVAL,
  - log `[rbac] sweep failed status=<code>` when the webapp refuses or is unreachable, never
    raise, and call again at the next interval,
  - run from the reaper loop, so a failing sweep never stops the loop, and never from the scan
    scheduler, so it runs with SCAN_SCHEDULER_ENABLED=false.

Run (in the recon-orchestrator image, from /repo/recon_orchestrator):
  python -m pytest tests/test_rbac_sweep_tick.py
"""
from __future__ import annotations

import asyncio
import inspect
import os
import re
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import api  # noqa: E402
import scan_scheduler  # noqa: E402

SWEEP_PATH = "/api/internal/rbac/sweep"


class _FakeWebapp:
    """Records every POST; answers `status`."""

    def __init__(self, status=200):
        self.requests = []
        self.status = status
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n) if n else b""
                fake.requests.append((self.path, dict(self.headers), body))
                payload = b'{"removed":{}}'
                self.send_response(fake.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()

    @property
    def base(self):
        host, port = self.server.server_address[:2]
        return f"http://{host}:{port}"

    def sweeps(self):
        return [r for r in self.requests if r[0] == SWEEP_PATH]

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class _TickCase(unittest.TestCase):
    def setUp(self):
        self.web = _FakeWebapp()
        self.env = mock.patch.dict(os.environ, {"INTERNAL_API_KEY": "k" * 64, "WEBAPP_API_URL": self.web.base})
        self.env.start()
        api._reset_rbac_sweep_state()
        self.interval = mock.patch.object(api, "RBAC_SWEEP_INTERVAL_S", 300)
        self.interval.start()

    def tearDown(self):
        self.interval.stop()
        self.env.stop()
        self.web.close()
        api._reset_rbac_sweep_state()


class TestRbacSweepTick(_TickCase):
    def test_posts_the_sweep_route_with_the_internal_key(self):
        asyncio.run(api._maybe_rbac_sweep())
        self.assertEqual(len(self.web.requests), 1)
        path, headers, _ = self.web.requests[0]
        self.assertEqual(path, SWEEP_PATH)
        lowered = {k.lower(): v for k, v in headers.items()}
        self.assertEqual(lowered.get("x-internal-key"), "k" * 64)

    def test_the_reaper_calls_the_sweep_at_most_once_per_interval(self):
        async def ticks():
            for _ in range(3):
                await api._maybe_rbac_sweep()
        asyncio.run(ticks())
        self.assertEqual(len(self.web.sweeps()), 1)
        with mock.patch.object(api.time, "monotonic", return_value=time.monotonic() + 299):
            asyncio.run(api._maybe_rbac_sweep())
        self.assertEqual(len(self.web.sweeps()), 1)
        with mock.patch.object(api.time, "monotonic", return_value=time.monotonic() + 301):
            asyncio.run(api._maybe_rbac_sweep())
        self.assertEqual(len(self.web.sweeps()), 2)

    def test_no_internal_key_no_call(self):
        for missing in ("", None):
            env = {k: v for k, v in os.environ.items() if k != "INTERNAL_API_KEY"}
            if missing is not None:
                env["INTERNAL_API_KEY"] = missing
            api._reset_rbac_sweep_state()
            with mock.patch.dict(os.environ, env, clear=True):
                asyncio.run(api._maybe_rbac_sweep())
        self.assertEqual(self.web.requests, [])

    def test_the_interval_is_300_and_survives_an_empty_or_bad_value(self):
        self.assertEqual(api._interval_from_env("RBAC_SWEEP_INTERVAL_UNSET_FOR_TEST", 300), 300)
        for raw, expected in (("", 300), ("   ", 300), ("abc", 300), ("-5", 300), ("0", 300), ("120", 120)):
            with mock.patch.dict(os.environ, {"RBAC_SWEEP_INTERVAL": raw}):
                self.assertEqual(api._interval_from_env("RBAC_SWEEP_INTERVAL", 300), expected, raw)
        src = inspect.getsource(api)
        self.assertIn('RBAC_SWEEP_INTERVAL_S = _interval_from_env("RBAC_SWEEP_INTERVAL", 300)', src)

    def test_a_refused_sweep_logs_its_status_and_is_retried_at_the_next_interval(self):
        self.web.status = 500
        with self.assertLogs(api.logger, level="WARNING") as logs:
            asyncio.run(api._maybe_rbac_sweep())
        self.assertIn("[rbac] sweep failed status=500", "\n".join(logs.output))
        with mock.patch.object(api.time, "monotonic", return_value=time.monotonic() + 301):
            asyncio.run(api._maybe_rbac_sweep())
        self.assertEqual(len(self.web.sweeps()), 2)

    def test_a_404_from_an_older_webapp_is_logged_and_retried(self):
        self.web.status = 404
        with self.assertLogs(api.logger, level="WARNING") as logs:
            asyncio.run(api._maybe_rbac_sweep())
        self.assertIn("[rbac] sweep failed status=404", "\n".join(logs.output))
        with mock.patch.object(api.time, "monotonic", return_value=time.monotonic() + 301):
            asyncio.run(api._maybe_rbac_sweep())
        self.assertEqual(len(self.web.sweeps()), 2)

    def test_the_webapp_down_never_raises_and_logs_unreachable(self):
        self.web.close()
        with self.assertLogs(api.logger, level="WARNING") as logs:
            asyncio.run(api._maybe_rbac_sweep())  # no exception
        self.assertIn("[rbac] sweep failed status=unreachable", "\n".join(logs.output))

    def test_a_successful_sweep_logs_no_failure(self):
        with mock.patch.object(api.logger, "warning") as warning:
            asyncio.run(api._maybe_rbac_sweep())
        warning.assert_not_called()


class _FakeContainerManager:
    """Just enough for one pass of the reaper body."""

    def __init__(self):
        self.reaps = 0

    async def reap_ai_attack(self):
        self.reaps += 1

    async def reap_codefix_sandboxes(self):
        pass

    async def refresh_all_scan_states(self):
        pass

    def reconcile_reservations(self):
        return 0

    def active_scan_projects(self):
        return []


class TestTheReaperRunsTheSweep(_TickCase):
    """The real `_ai_attack_reaper` loop, with a fake container manager and the neighbours quiet."""

    def setUp(self):
        super().setUp()
        self.cm = _FakeContainerManager()
        self.patches = [
            mock.patch.object(api, "container_manager", self.cm),
            mock.patch.object(api, "AI_ATTACK_REAP_INTERVAL_S", 0.01),
            mock.patch.object(api, "run_one_dispatch_tick", mock.AsyncMock()),
            mock.patch.object(api, "_post_job_queue_reconcile", mock.AsyncMock()),
            mock.patch.object(api, "_maybe_run_traffic_maintenance", mock.AsyncMock()),
            mock.patch.object(api, "_maybe_prune_mcp_tokens", mock.AsyncMock()),
            mock.patch.object(api, "_maybe_reconcile_plugins", mock.AsyncMock()),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        super().tearDown()

    def _run_reaper_until(self, done, timeout=3.0):
        async def scenario():
            task = asyncio.create_task(api._ai_attack_reaper())
            deadline = time.monotonic() + timeout
            while not done() and time.monotonic() < deadline:
                await asyncio.sleep(0.01)
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        asyncio.run(scenario())

    def test_the_sweep_runs_with_SCAN_SCHEDULER_ENABLED_false(self):
        with mock.patch.dict(os.environ, {"SCAN_SCHEDULER_ENABLED": "false"}):
            self._run_reaper_until(lambda: len(self.web.sweeps()) >= 1)
        self.assertEqual(len(self.web.sweeps()), 1)
        # Several reaper passes, still one sweep inside the interval.
        self.assertGreater(self.cm.reaps, 0)
        # The scheduler, which exits at start with that setting, has no part in it.
        self.assertNotIn("rbac", inspect.getsource(scan_scheduler).lower())

    def test_a_failing_sweep_does_not_stop_the_loop(self):
        calls = {"n": 0}

        async def boom():
            calls["n"] += 1
            raise RuntimeError("sweep exploded")

        with mock.patch.object(api, "_maybe_rbac_sweep", boom), \
                self.assertLogs(api.logger, level="WARNING") as logs:
            self._run_reaper_until(lambda: calls["n"] >= 3)
        self.assertGreaterEqual(calls["n"], 3)
        # The steps after the sweep still ran on every pass.
        self.assertGreaterEqual(api._maybe_reconcile_plugins.await_count, 3)
        self.assertTrue(any("[rbac] sweep tick failed" in line for line in logs.output))

    def test_a_refusing_webapp_does_not_stop_the_loop(self):
        self.web.status = 500
        with mock.patch.object(api, "RBAC_SWEEP_INTERVAL_S", 0.05), \
                self.assertLogs(api.logger, level="WARNING") as logs:
            self._run_reaper_until(lambda: len(self.web.sweeps()) >= 2)
        self.assertGreaterEqual(len(self.web.sweeps()), 2)
        self.assertTrue(any("[rbac] sweep failed status=500" in line for line in logs.output))

    def test_the_reaper_runs_the_tick_and_the_compose_file_passes_its_setting(self):
        self.assertIn("_maybe_rbac_sweep()", inspect.getsource(api._ai_attack_reaper))
        compose = (ROOT.parent / "docker-compose.yml").read_text()
        # The recon-orchestrator service has no env_file: only its own environment block reaches it.
        block = re.search(r"\n  recon-orchestrator:\n(.*?)(?=\n  [a-z][a-z0-9_-]*:\n)", compose, re.S).group(1)
        self.assertIn("RBAC_SWEEP_INTERVAL: ${RBAC_SWEEP_INTERVAL:-300}", block)


if __name__ == "__main__":
    unittest.main()
