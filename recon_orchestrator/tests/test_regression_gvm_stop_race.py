"""GVM stop: the run being stopped owns its container, its state and its file.

stop_gvm_scan waits out the grace period and runs the backstop ingest off the
event loop, which can take minutes. Meanwhile:

* the status poll saw the exited container, flipped the run to ERROR and
  auto-removed the container from under the stop;
* start_gvm_scan refused only RUNNING/PAUSED, so a new start was accepted: it
  force-removed the container being stopped, and the stop's final
  `del self.gvm_states[project_id]` then deleted the NEW run's state.

Also covered: the project delete asks the GVM and GitHub-hunt stops to skip the
backstop ingest (it clears the graph next, and a write landing after the clear
leaves the deleted project's nodes), and the backstop recognises an IP-mode run
the scan already wrote (no Domain node carries the stamp there).
"""

import asyncio
import json
import os
import sys
import tempfile
import threading
import time
import types
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock
from unittest.mock import AsyncMock, MagicMock

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "recon_orchestrator"))
sys.path.insert(0, str(REPO))

import container_manager as cm_mod  # noqa: E402
from models import GithubHuntState, GithubHuntStatus, GvmState, GvmStatus  # noqa: E402

STAMP = "2026-09-30T10:00:00.000001"


class FakeNeo4j:
    """graph_db.Neo4jClient stand-in; records what the backstop asks of it."""

    def __init__(self, log, stamps=()):
        self.log = log
        self.driver = MagicMock()
        session = MagicMock()
        session.__enter__.return_value = session
        session.run.return_value.single.return_value = {"stamps": list(stamps)}
        self.driver.session.return_value = session

    def __call__(self, *a, **k):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def verify_connection(self):
        return True

    def update_graph_from_gvm_scan(self, gvm_data, user_id, project_id):
        self.log.append(("ingest", user_id, project_id))
        return {"vulnerabilities_created": 1}


class _Harness(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.log = []
        self.entered = threading.Event()
        self.release = threading.Event()
        self.addCleanup(self.release.set)   # never leave a worker thread parked

        m = cm_mod.ContainerManager.__new__(cm_mod.ContainerManager)
        m.client = MagicMock()
        m.gvm_states = {}
        m.github_hunt_states = {}
        m._docker_op_executor = ThreadPoolExecutor(max_workers=2)
        self.addCleanup(m._docker_op_executor.shutdown, wait=False)
        m.GVM_OUTPUT_DIR = Path(self._tmp.name)
        self.m = m

        self.state = GvmState(
            project_id="p1", status=GvmStatus.RUNNING, container_id="c1",
            started_at=datetime.now(timezone.utc) - timedelta(minutes=5))
        m.gvm_states["p1"] = self.state

        c = MagicMock()
        c.id = "c1"
        c.status = "running"
        c.attrs = {"Config": {"Env": ["PROJECT_ID=p1", "USER_ID=u1"]}, "State": {}}
        c.stop.side_effect = self._container_stop
        c.remove.side_effect = lambda **k: self.log.append(("remove", k))
        self.container = c
        m.client.containers.get.return_value = c

        self.graph = types.ModuleType("graph_db")
        self.graph.Neo4jClient = FakeNeo4j(self.log)
        patcher = mock.patch.dict(sys.modules, {"graph_db": self.graph})
        patcher.start()
        self.addCleanup(patcher.stop)

    def _container_stop(self, **kwargs):
        self.log.append(("stop", kwargs.get("timeout")))
        self.entered.set()
        if self.blocking:
            self.release.wait(10)
        # Exited on SIGTERM: what every status poll now sees.
        self.container.status = "exited"
        self.container.attrs["State"] = {"ExitCode": 137}

    blocking = False

    def write_results(self, **extra):
        (self.m.GVM_OUTPUT_DIR / "gvm_p1.json").write_text(json.dumps({
            "metadata": {"scan_timestamp": STAMP, "target_domain": ""},
            "scans": [{"status": "Done", "targets": ["10.0.0.1"], "vulnerabilities": []}],
            "interrupted": "Stopped before every target was scanned",
            **extra,
        }))

    def kinds(self):
        return [e[0] for e in self.log]

    def during_stop(self, action, **stop_kwargs):
        """Run `action` (a coroutine function) while the stop is parked inside
        container.stop, then let the stop finish. Returns both results."""
        self.blocking = True

        async def scenario():
            stop = asyncio.create_task(self.m.stop_gvm_scan("p1", **stop_kwargs))
            try:
                await asyncio.to_thread(self.entered.wait, 10)
                self.assertTrue(self.entered.is_set(), "the stop never reached the container")
                # The container has exited on SIGTERM; the stop is still running.
                self.container.status = "exited"
                self.container.attrs["State"] = {"ExitCode": 137}
                try:
                    during = await action()
                except Exception as e:  # noqa: BLE001 - handed to the test
                    during = e
            finally:
                self.release.set()
            return during, await stop

        return asyncio.run(scenario())

    def arm_start(self):
        m = self.m
        m._admit_scan = AsyncMock(return_value="gvm:p1")
        m.gvm_image = "redamon-vuln-scanner"
        m._container_mem_limit = MagicMock(return_value="1g")
        m._container_pids_limit = MagicMock(return_value=512)
        m._container_cpu_limit = MagicMock(return_value=1_000_000_000)
        m._scanner_hardening = MagicMock(return_value={})
        m._scanner_env = MagicMock(return_value={})
        m._recon_settings_mount = MagicMock(return_value={})
        m._graph_db_mount = MagicMock(return_value={})
        m.supply_chain_osv_db_volume = "osv"
        new = MagicMock()
        new.id = "c2"
        m.client.containers.run.return_value = new

        def start():
            return m.start_gvm_scan("p1", "u1", "http://webapp:3000",
                                    "/repo/recon", "/repo/scanners/gvm_scan")
        return start


class TestRegressionGvmStopStartRace(_Harness):
    def test_regression_gvm_start_during_stop_is_accepted(self):
        start = self.arm_start()
        during, stopped = self.during_stop(start)
        self.assertIsInstance(during, ValueError,
                              "a start was accepted while the previous run was stopping")
        self.assertIn("stopping", str(during))
        self.assertNotIn(("remove", {"force": True}), self.log,
                         "the start force-removed the container being stopped")
        self.m.client.containers.run.assert_not_called()
        self.assertEqual(stopped.status, GvmStatus.IDLE)

    def test_regression_gvm_status_poll_flips_stopping_run_to_error(self):
        removed_during = []

        async def poll():
            state = await self.m.get_gvm_status("p1")
            removed_during.extend(e for e in self.log if e[0] == "remove")
            return state.status

        during, stopped = self.during_stop(poll)
        self.assertEqual(during, GvmStatus.STOPPING,
                         "the poll read a run mid-stop as a finished one")
        self.assertEqual(removed_during, [],
                         "the poll auto-removed the container from under the stop")
        self.assertEqual(stopped.status, GvmStatus.IDLE)
        self.assertEqual(self.kinds().count("remove"), 1)

    def test_regression_gvm_stop_deletes_the_new_runs_state(self):
        newer = GvmState(project_id="p1", status=GvmStatus.RUNNING, container_id="c2",
                         started_at=datetime.now(timezone.utc))

        async def replace():
            self.m.gvm_states["p1"] = newer

        self.during_stop(replace)
        self.assertIs(self.m.gvm_states.get("p1"), newer,
                      "the stop deleted a state it does not own")

    def test_a_start_after_the_stop_has_finished_is_accepted(self):
        start = self.arm_start()
        asyncio.run(self.m.stop_gvm_scan("p1"))
        state = asyncio.run(start())
        self.assertEqual(state.status, GvmStatus.RUNNING)
        self.assertEqual(state.container_id, "c2")

    def test_the_stop_still_runs_off_the_event_loop(self):
        """The poll above could only run because the loop was free; here the
        loop also keeps ticking while the stop is parked in the grace period."""
        async def ticks():
            t0 = time.monotonic()
            n = 0
            while time.monotonic() - t0 < 0.2:
                await asyncio.sleep(0.01)
                n += 1
            return n

        during, _ = self.during_stop(ticks)
        self.assertGreater(during, 5)

    def test_a_clean_stop_is_unchanged(self):
        self.write_results()
        state = asyncio.run(self.m.stop_gvm_scan("p1"))
        self.assertEqual(state.status, GvmStatus.IDLE)
        self.assertNotIn("p1", self.m.gvm_states)
        self.assertEqual(self.kinds(), ["stop", "ingest", "remove"])


class TestRegressionGvmBackstopAfterProjectDelete(_Harness):
    def test_regression_gvm_backstop_writes_after_project_delete(self):
        self.write_results()
        state = asyncio.run(self.m.stop_gvm_scan("p1", ingest=False))
        self.assertNotIn("ingest", self.kinds(),
                         "the delete's stop wrote the run into a graph about to be cleared")
        self.assertIn("remove", self.kinds())
        self.assertEqual(state.status, GvmStatus.IDLE)

    def test_regression_gvm_backstop_writes_after_delete_during_a_stop(self):
        """A person stopped the scan, then deleted the project while that stop
        was still in its grace period: the delete's stop turns the pending
        backstop off rather than returning while it is still to come."""
        self.write_results()

        async def delete_stop():
            return (await self.m.stop_gvm_scan("p1", ingest=False)).status

        during, stopped = self.during_stop(delete_stop)
        self.assertNotIsInstance(during, Exception, during)
        self.assertEqual(during, GvmStatus.STOPPING)
        self.assertNotIn("ingest", self.kinds())
        self.assertEqual(self.kinds().count("stop"), 1)
        self.assertEqual(stopped.status, GvmStatus.IDLE)

    def test_regression_github_hunt_backstop_writes_after_project_delete(self):
        m = self.m
        hunt = GithubHuntState(project_id="p1", status=GithubHuntStatus.RUNNING,
                               container_id="h1", user_id="u1")
        m.github_hunt_states["p1"] = hunt
        hunt_container = MagicMock()
        hunt_container.status = "running"
        m.client.containers.get.return_value = hunt_container
        m._ingest_github_hunt = MagicMock()
        state = asyncio.run(m.stop_github_hunt("p1", ingest=False))
        m._ingest_github_hunt.assert_not_called()
        hunt_container.remove.assert_called_once_with(force=False, v=True)
        self.assertEqual(state.status, GithubHuntStatus.IDLE)

    def test_the_github_hunt_stop_still_ingests_by_default(self):
        m = self.m
        m.github_hunt_states["p1"] = GithubHuntState(
            project_id="p1", status=GithubHuntStatus.RUNNING, container_id="h1", user_id="u1")
        hunt_container = MagicMock()
        hunt_container.status = "running"
        m.client.containers.get.return_value = hunt_container
        m._ingest_github_hunt = MagicMock()
        asyncio.run(m.stop_github_hunt("p1"))
        m._ingest_github_hunt.assert_called_once()

    def test_regression_gvm_backstop_writes_after_project_delete_api_flag(self):
        try:
            import api
        except Exception as e:  # pragma: no cover - the orchestrator image has it
            self.skipTest(f"api is not importable here: {e}")
        cm = MagicMock()
        cm.stop_gvm_scan = AsyncMock(return_value="gvm-state")
        cm.stop_github_hunt = AsyncMock(return_value="hunt-state")
        with mock.patch.object(api, "container_manager", cm):
            asyncio.run(api.stop_gvm_scan("p1"))
            asyncio.run(api.stop_gvm_scan("p1", ingest=False))
            asyncio.run(api.stop_github_hunt("p1"))
            asyncio.run(api.stop_github_hunt("p1", ingest=False))
        self.assertEqual([c.kwargs.get("ingest") for c in cm.stop_gvm_scan.call_args_list],
                         [True, False])
        self.assertEqual([c.kwargs.get("ingest") for c in cm.stop_github_hunt.call_args_list],
                         [True, False])


class TestRegressionGvmIpModeBackstop(_Harness):
    def test_regression_gvm_ip_mode_stop_reingests_a_run_the_scan_wrote(self):
        """IP mode: no Domain node, so no stamp to find. The scan's own write
        of the stopped run landed and said so in the file."""
        self.write_results(graph_update={"vulnerabilities_created": 1})
        asyncio.run(self.m.stop_gvm_scan("p1"))
        self.assertNotIn("ingest", self.kinds(), "an IP-mode stop wrote the run twice")
        self.assertIn("remove", self.kinds())

    def test_a_run_killed_mid_write_is_still_ingested(self):
        """No marker: the scan's write may have been cut off half-way, and some
        of its Vulnerability nodes may already carry the run's stamp. The
        backstop must not take those for a finished write."""
        self.write_results()
        asyncio.run(self.m.stop_gvm_scan("p1"))
        self.assertIn("ingest", self.kinds())

    def test_a_domain_mode_run_the_scan_wrote_is_still_skipped(self):
        self.write_results()
        self.graph.Neo4jClient = FakeNeo4j(self.log, stamps=[STAMP])
        asyncio.run(self.m.stop_gvm_scan("p1"))
        self.assertNotIn("ingest", self.kinds())

    def test_an_earlier_runs_marker_is_ignored(self):
        """The mtime check runs first: a file from before this run is not this
        run's, marker or not."""
        self.write_results(graph_update={"vulnerabilities_created": 1})
        old = time.time() - 3600
        os.utime(self.m.GVM_OUTPUT_DIR / "gvm_p1.json", (old, old))
        asyncio.run(self.m.stop_gvm_scan("p1"))
        self.assertNotIn("ingest", self.kinds())


if __name__ == "__main__":
    unittest.main()
