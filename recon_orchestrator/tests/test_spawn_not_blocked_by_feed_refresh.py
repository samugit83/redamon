"""
The scan spawn must NOT wait on the OSV / incident-intel feed refresh.

Reported symptom: "Start Reconnaissance" sat on "Starting..." then reported
"operation aborted due to timeout", while the container had in fact spawned and
the scan was running. Cause: start_recon awaited ensure_osv_db_fresh_async(), and
a >24h-old feed's delta sync took ~30s, pushing the /recon/{id}/start response
past the webapp's 30s orchestrator timeout.

Fix: the refreshes now run in the background. These tests pin it - start_recon
returns RUNNING without waiting for a deliberately slow refresh, and a failing
refresh never breaks the spawn.

Scaffold mirrors tests.test_scan_mode_passthrough (the one place that already
spawns a real start_recon under stubbed docker).

    docker compose exec -T recon-orchestrator python -m unittest \
        tests.test_spawn_not_blocked_by_feed_refresh -v
"""
from __future__ import annotations

import asyncio
import sys
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import container_manager as cm  # noqa: E402
from models import ReconStatus, ReconState  # noqa: E402


def _make_manager(rec, osv=None, sca=None):
    mgr = cm.ContainerManager.__new__(cm.ContainerManager)

    class _Containers:
        def get(self, name):
            raise cm.NotFound(name)

        def run(self, image, **kw):
            rec["ran"] = True
            return mock.Mock(id="container123")

    mgr.client = mock.Mock()
    mgr.client.containers = _Containers()
    mgr.client.images = mock.Mock()
    mgr._docker_op_executor = ThreadPoolExecutor(max_workers=2)
    mgr.supply_chain_osv_db_volume = "redamon-osv-db"
    mgr.sca_intel_volume = "redamon-sca-intel"
    mgr.recon_image = "redamon-recon:latest"
    mgr.running_states = {}
    mgr.partial_recon_states = {}

    async def _idle(_pid):
        return ReconState(project_id=_pid, status=ReconStatus.IDLE)

    mgr.get_status = _idle
    mgr._count_active_partial_recons = lambda pid: 0

    async def _admit(*a, **kw):
        return "key"

    mgr._admit_scan = _admit

    rec["refresh_started"] = False
    rec["refresh_finished"] = False

    async def _default_osv(*a, **kw):
        rec["refresh_started"] = True
        await asyncio.sleep(2)          # stand-in for the ~30s real delta sync
        rec["refresh_finished"] = True
        return None

    async def _default_sca(*a, **kw):
        await asyncio.sleep(2)
        return None

    mgr.ensure_osv_db_fresh_async = osv or _default_osv
    mgr.ensure_sca_intel_fresh_async = sca or _default_sca

    mgr._get_container_name = lambda pid: f"redamon-recon-{pid}"
    mgr._scanner_env = lambda: {}
    mgr._scanner_hardening = lambda drop_caps=True: {}
    mgr._container_mem_limit = lambda kind: None
    mgr._container_pids_limit = lambda: None
    mgr._container_cpu_limit = lambda: None
    return mgr


class TestSpawnNotBlockedByFeedRefresh(unittest.TestCase):
    def test_start_returns_running_without_waiting_for_the_refresh(self):
        rec = {}
        mgr = _make_manager(rec)

        async def _go():
            start = time.monotonic()
            state = await mgr.start_recon(
                project_id="p1", user_id="u1",
                webapp_api_url="http://webapp:3000", recon_path="/app/recon",
            )
            elapsed = time.monotonic() - start
            await asyncio.sleep(2.3)     # let the background refresh finish
            return state, elapsed

        state, elapsed = asyncio.run(_go())

        self.assertEqual(state.status, ReconStatus.RUNNING)
        self.assertTrue(rec["ran"], "container was never spawned")
        self.assertLess(elapsed, 1.5, f"start blocked on the refresh ({elapsed:.2f}s)")
        # The refresh really did run - in the background, not skipped.
        self.assertTrue(rec["refresh_started"])
        self.assertTrue(rec["refresh_finished"])

    def test_a_failing_refresh_never_breaks_the_spawn(self):
        rec = {}

        async def _boom(*a, **kw):
            raise RuntimeError("feed server down")

        mgr = _make_manager(rec, osv=_boom)

        async def _go():
            state = await mgr.start_recon(
                project_id="p1", user_id="u1",
                webapp_api_url="http://webapp:3000", recon_path="/app/recon",
            )
            await asyncio.sleep(0.1)     # let the background task raise-and-swallow
            return state

        self.assertEqual(asyncio.run(_go()).status, ReconStatus.RUNNING)


if __name__ == "__main__":
    unittest.main()
