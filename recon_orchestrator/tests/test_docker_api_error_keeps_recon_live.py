"""A transient Docker API error never fails a live recon run, and a start never
kills one (R-34).

One 5xx from the daemon while the status poll inspected a running scan set the
run to `error`: the webapp recorded the ScanJob as failed, Stop and Pause
refused it, the next poll never put it back to `running`, and a new start
passed the "already active" check and force-removed the still-running
container by name. Docker is the truth while the container lives: an API error
keeps the last status, a running container is `running`, and a start refuses
whenever a container of that name is still live, whatever the memory says.
"""
import asyncio
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "recon_orchestrator"))
sys.path.insert(0, str(REPO))

import container_manager as cm_mod  # noqa: E402
from models import (  # noqa: E402
    PartialReconState, PartialReconStatus, ReconState, ReconStatus,
)
from tests.fake_docker import FakeClient, FakeContainer, FakeContainers  # noqa: E402

PROJECT = "proj-a"
NAME = f"redamon-recon-{PROJECT}"
DAEMON_5XX = "500 Server Error for http+docker://localhost/v1.47/containers/json"


class FlakyContainers(FakeContainers):
    """`get` answers a 5xx for the refs in `fail`, the given number of times."""

    def __init__(self, containers=(), fail=None):
        super().__init__(containers)
        self.fail = dict(fail or {})
        self.runs = []

    def get(self, ref):
        if self.fail.get(ref, 0) > 0:
            self.fail[ref] -= 1
            raise cm_mod.APIError(DAEMON_5XX)
        return super().get(ref)

    def run(self, image, **kwargs):
        self.runs.append(kwargs)
        return self.add(FakeContainer("new-recon", image, kwargs.get("labels"),
                                      name=kwargs.get("name")))


def _recon(cid="recon-a", status="running"):
    return FakeContainer(cid, "redamon-recon:latest", {
        "redamon.run_id": "run-a", "redamon.project_id": PROJECT,
        "redamon.run_kind": "full_recon"}, status=status, name=NAME)


def _manager(containers=(), fail=None):
    m = cm_mod.ContainerManager.__new__(cm_mod.ContainerManager)
    m.client = FakeClient()
    m.client.containers = FlakyContainers(containers, fail)
    m.client.images = SimpleNamespace(get=lambda ref: None)
    m.running_states = {}
    m.partial_recon_states = {}
    m._docker_op_executor = ThreadPoolExecutor(max_workers=2)
    m.recon_image = "redamon-recon:latest"
    m.supply_chain_osv_db_volume = "osv"
    m.sca_intel_volume = "intel"
    m.admitted = []
    m.ledger = SimpleNamespace(release_nowait=lambda key: None)

    async def _admit(kind, project_id, run_id=None, user_id=None):
        m.admitted.append(kind)
        return kind

    m._admit_scan = _admit
    m._warm_feeds_in_background = lambda: None
    m._recon_settings_mount = lambda: {}
    m._graph_db_mount = lambda *a, **k: {}
    m._scanner_env = lambda: {}
    m._analyzer_env = lambda: {}
    m._container_mem_limit = lambda kind: None
    m._container_pids_limit = lambda: None
    m._container_cpu_limit = lambda: None
    m._scanner_hardening = lambda **k: {}
    return m


def _track(m, status=ReconStatus.RUNNING, cid="recon-a", error=None):
    m.running_states[PROJECT] = ReconState(project_id=PROJECT, status=status,
                                           container_id=cid, error=error)


def _start(m):
    return asyncio.run(m.start_recon(PROJECT, "u1", "http://webapp", "/host/recon"))


class TestTheStatusPoll:
    def test_an_api_error_keeps_the_run_running(self):
        m = _manager([_recon()], fail={"recon-a": 1})
        _track(m)
        first = asyncio.run(m.get_status(PROJECT))
        assert (first.status, first.error) == (ReconStatus.RUNNING, None)
        second = asyncio.run(m.get_status(PROJECT))
        assert second.status == ReconStatus.RUNNING

    def test_an_api_error_keeps_a_paused_run_paused(self):
        m = _manager([_recon(status="paused")], fail={"recon-a": 1})
        _track(m, status=ReconStatus.PAUSED)
        assert asyncio.run(m.get_status(PROJECT)).status == ReconStatus.PAUSED

    def test_a_running_container_puts_a_failed_state_back_to_running(self):
        m = _manager([_recon()])
        _track(m, status=ReconStatus.ERROR, error=f"Failed to pause: {DAEMON_5XX}")
        state = asyncio.run(m.get_status(PROJECT))
        assert (state.status, state.error, state.completed_at) == (ReconStatus.RUNNING, None, None)

    def test_a_container_confirmed_gone_still_fails_the_run(self):
        m = _manager([])
        _track(m)
        state = asyncio.run(m.get_status(PROJECT))
        assert (state.status, state.error) == (ReconStatus.ERROR, "Container not found")

    def test_a_finished_container_still_completes_the_run(self):
        m = _manager([_recon(status="exited")])
        _track(m)
        assert asyncio.run(m.get_status(PROJECT)).status == ReconStatus.COMPLETED

    def test_pause_still_works_after_the_error(self):
        m = _manager([_recon()], fail={"recon-a": 1})
        _track(m)
        state = asyncio.run(m.pause_recon(PROJECT))
        assert state.status == ReconStatus.PAUSED
        assert m.client.containers.get("recon-a").status == "paused"


class TestAStartNeverKillsALiveRun:
    def test_a_start_during_the_error_window_is_refused(self):
        live = _recon()
        m = _manager([live], fail={"recon-a": 1})
        _track(m)
        with pytest.raises(ValueError, match="already active"):
            _start(m)
        assert not live.removed
        assert (m.client.containers.runs, m.admitted) == ([], [])

    @pytest.mark.parametrize("status", ["running", "paused", "restarting"])
    def test_a_stale_failed_state_never_lets_a_start_remove_a_live_container(self, status):
        # The memory points at a container that is gone, while the run's
        # container (found by name) is still live.
        live = _recon(cid="recon-b", status=status)
        m = _manager([live])
        _track(m, status=ReconStatus.ERROR, cid="recon-gone", error="Container not found")
        with pytest.raises(ValueError, match="already active"):
            _start(m)
        assert not live.removed
        assert (m.client.containers.runs, m.admitted) == ([], [])

    def test_when_docker_cannot_say_whether_it_lives_nothing_is_removed(self):
        live = _recon(cid="recon-b")
        m = _manager([live], fail={NAME: 1})
        _track(m, status=ReconStatus.ERROR, cid="recon-gone", error="Container not found")
        with pytest.raises(cm_mod.APIError):
            _start(m)
        assert not live.removed
        assert (m.client.containers.runs, m.admitted) == ([], [])

    @pytest.mark.parametrize("status", ["exited", "created", "dead"])
    def test_a_finished_leftover_is_still_cleared_and_the_start_goes_on(self, status):
        leftover = _recon(cid="recon-old", status=status)
        m = _manager([leftover])
        state = _start(m)
        assert state.status == ReconStatus.RUNNING
        assert leftover.removed
        assert ("recon-old", "remove:force") in leftover.log
        assert len(m.client.containers.runs) == 1
        assert m.admitted == ["full_recon"]


def test_a_partial_run_still_only_logs_the_error():
    container = FakeContainer("part-1", "redamon-recon:latest", status="running")
    m = _manager([container], fail={"part-1": 1})
    state = PartialReconState(project_id=PROJECT, run_id="r1", tool_id="Naabu",
                              status=PartialReconStatus.RUNNING, container_id="part-1")
    m._refresh_partial_recon_state(state)
    assert (state.status, state.error) == (PartialReconStatus.RUNNING, None)
