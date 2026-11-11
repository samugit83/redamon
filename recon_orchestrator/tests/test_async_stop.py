"""Stop is asynchronous, and `stopping` is a live state (plan 12.3).

stop_recon used to `container.stop(10)` then remove, blocking the event loop,
and Python as PID 1 ignored the SIGTERM, so every stop was a SIGKILL ten
seconds later: no queued graph write landed and the mute rules never ran. Now
the stop answers `stopping` at once; a background task sends SIGTERM, removes
the run's tool containers every couple of seconds until the recon container
exits (it drains and sweeps first) or the grace ends, then SIGKILLs, logs the
exit code and removes it. Until then nothing maps the exit to `error`, and the
run keeps its reservation and its place in the mutual exclusion.
"""
import asyncio
import logging
import re
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "recon_orchestrator"))
sys.path.insert(0, str(REPO))

import container_manager as cm_mod  # noqa: E402
from models import PartialReconState, PartialReconStatus, ReconState, ReconStatus  # noqa: E402
from tests.fake_docker import FakeClient, FakeContainer, tool  # noqa: E402

RUN = "run-a-0001"


class ExitsOnTerm(FakeContainer):
    """A recon container that drains for `polls` status reads after SIGTERM, then exits 143."""

    def __init__(self, *a, polls=1, ignore_term=False, **k):
        super().__init__(*a, **k)
        self.polls = polls
        self.ignore_term = ignore_term
        self.termed = False
        self.threads = set()

    def _record(self, verb):
        self.threads.add(threading.current_thread().name)
        super()._record(verb)

    def kill(self, signal="SIGKILL"):
        super().kill(signal)
        if signal == "SIGTERM" and not self.ignore_term:
            self.termed = True

    def reload(self):
        self._record("reload")
        if self.termed and self.status == "running":
            self.polls -= 1
            if self.polls <= 0:
                self.status, self.exit_code = "exited", 143

    def wait(self, timeout=None):
        self._record("wait")
        return {"StatusCode": self.exit_code}


def _manager(containers):
    m = cm_mod.ContainerManager.__new__(cm_mod.ContainerManager)
    m.client = FakeClient(containers)
    m.running_states = {}
    m.partial_recon_states = {}
    m._docker_op_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="docker-op")
    return m


def _recon(**k):
    return ExitsOnTerm("recon-a", "redamon-recon:latest", {
        "redamon.run_id": RUN, "redamon.project_id": "proj-a",
        "redamon.run_kind": "full_recon"}, **k)


@pytest.fixture
def fast(monkeypatch):
    monkeypatch.setattr(cm_mod, "RECON_STOP_GRACE_S", 1.0)
    monkeypatch.setattr(cm_mod, "STOP_TOOL_SWEEP_INTERVAL_S", 0.05)


def _running(m, cid="recon-a"):
    m.running_states["proj-a"] = ReconState(project_id="proj-a", status=ReconStatus.RUNNING,
                                            container_id=cid)


class TestTheFullStop:
    def test_it_answers_stopping_at_once_and_finishes_in_the_background(self, fast, caplog):
        recon = _recon(polls=3)
        a_tool = tool("a-nuclei", RUN)
        m = _manager([recon, a_tool])
        _running(m)

        async def go():
            state = await m.stop_recon("proj-a")
            assert state.status == ReconStatus.STOPPING
            assert not recon.removed
            await m._stop_tasks[("full_recon", "proj-a")]
            return await m.get_status("proj-a")

        with caplog.at_level(logging.INFO, logger=cm_mod.logger.name):
            final = asyncio.run(go())
        verbs = [v for cid, v in recon.log if cid == "recon-a"]
        assert verbs[0] == "kill:SIGTERM"
        assert "kill:SIGKILL" not in verbs
        assert recon.removed and a_tool.removed
        assert final.status == ReconStatus.IDLE
        assert "proj-a" not in m.running_states
        assert any("exited with code 143" in r.getMessage() for r in caplog.records)

    def test_a_container_that_ignores_the_term_is_killed_at_the_grace(self, fast, caplog):
        recon = _recon(ignore_term=True)
        m = _manager([recon])
        _running(m)

        async def go():
            await m.stop_recon("proj-a")
            await m._stop_tasks[("full_recon", "proj-a")]

        with caplog.at_level(logging.INFO, logger=cm_mod.logger.name):
            asyncio.run(go())
        verbs = [v for _cid, v in recon.log]
        assert verbs.index("kill:SIGTERM") < verbs.index("kill:SIGKILL")
        assert recon.removed
        assert any("exited with code 137" in r.getMessage() for r in caplog.records)

    def test_tool_containers_are_removed_again_while_it_drains(self, fast):
        recon = _recon(polls=4)
        m = _manager([recon])
        _running(m)

        async def go():
            await m.stop_recon("proj-a")
            await asyncio.sleep(0.12)
            # A tool the draining run had already asked for, created late.
            m.client.containers.add(tool("late-httpx", RUN))
            await m._stop_tasks[("full_recon", "proj-a")]

        asyncio.run(go())
        assert m.client.containers.items["late-httpx"].removed

    def test_a_paused_run_is_unpaused_before_the_term(self, fast):
        recon = _recon(status="paused")
        m = _manager([recon])
        m.running_states["proj-a"] = ReconState(project_id="proj-a", status=ReconStatus.PAUSED,
                                                container_id="recon-a")

        async def go():
            await m.stop_recon("proj-a")
            await m._stop_tasks[("full_recon", "proj-a")]

        asyncio.run(go())
        verbs = [v for _cid, v in recon.log]
        assert verbs.index("unpause") < verbs.index("kill:SIGTERM")

    def test_every_docker_call_runs_off_the_event_loop(self, fast):
        recon = _recon(polls=2)
        m = _manager([recon])
        _running(m)

        async def go():
            await m.stop_recon("proj-a")
            await m._stop_tasks[("full_recon", "proj-a")]
            return threading.current_thread().name

        loop_thread = asyncio.run(go())
        assert recon.threads and loop_thread not in recon.threads
        assert all(name.startswith("docker-op") for name in recon.threads)

    def test_a_second_stop_while_it_drains_starts_nothing_new(self, fast):
        recon = _recon(polls=3)
        m = _manager([recon])
        _running(m)

        async def go():
            await m.stop_recon("proj-a")
            first = m._stop_tasks[("full_recon", "proj-a")]
            again = await m.stop_recon("proj-a")
            assert again.status == ReconStatus.STOPPING
            assert m._stop_tasks[("full_recon", "proj-a")] is first
            await first

        asyncio.run(go())
        assert [v for _c, v in recon.log].count("kill:SIGTERM") == 1


class TestStoppingIsALiveState:
    def test_the_exit_code_is_never_read_as_an_error_while_stopping(self):
        recon = _recon()
        recon.status, recon.exit_code = "exited", 143
        m = _manager([recon])
        m.running_states["proj-a"] = ReconState(project_id="proj-a", status=ReconStatus.STOPPING,
                                                container_id="recon-a")
        state = m._get_status_sync("proj-a")
        assert state.status == ReconStatus.STOPPING
        assert state.error is None
        assert not recon.removed

    def test_a_stopping_partial_is_not_refreshed_to_an_error(self):
        part = FakeContainer("p1", "redamon-recon:latest", status="exited")
        part.exit_code = 143
        m = _manager([part])
        state = PartialReconState(project_id="proj-a", run_id="r1",
                                  status=PartialReconStatus.STOPPING, container_id="p1")
        m._refresh_partial_recon_state(state)
        assert state.status == PartialReconStatus.STOPPING
        assert not part.removed

    def _stopping(self):
        m = _manager([])
        m.running_states["proj-a"] = ReconState(project_id="proj-a", status=ReconStatus.STOPPING)
        m.partial_recon_states["proj-b"] = {"r1": PartialReconState(
            project_id="proj-b", run_id="r1", tool_id="Naabu", status=PartialReconStatus.STOPPING)}
        for name in ("ai_attack_states", "gvm_states", "github_hunt_states", "trufflehog_states",
                     "supply_chain_states", "codefix_sandboxes"):
            setattr(m, name, {})
        m.guarddog_jobs = set()
        return m

    def test_it_keeps_its_reservation(self):
        keys = self._stopping()._active_scan_keys()
        assert "full_recon:proj-a" in keys
        assert "partial_recon:Naabu:proj-b:r1" in keys

    def test_it_counts_as_an_active_project(self):
        assert {"proj-a", "proj-b"} <= self._stopping().active_scan_projects()

    def test_a_start_is_refused_while_it_drains(self):
        m = self._stopping()
        with pytest.raises(ValueError, match="already active"):
            asyncio.run(m.start_recon("proj-a", "u1", "http://webapp", "/host/recon"))

    def test_a_partial_start_is_refused_while_the_full_run_drains(self):
        m = self._stopping()
        with pytest.raises(ValueError, match="Full recon"):
            asyncio.run(m.start_partial_recon("proj-a", "Naabu", {}, "/host/recon"))

    def test_a_draining_partial_blocks_a_full_start(self):
        m = self._stopping()
        assert m._count_active_partial_recons("proj-b") == 1


class TestTheHardStop:
    def test_graceful_false_kills_at_once_and_waits(self, fast):
        recon = _recon(polls=50)
        a_tool = tool("a-nuclei", RUN)
        m = _manager([recon, a_tool])
        _running(m)
        state = asyncio.run(m.stop_recon("proj-a", graceful=False))
        verbs = [v for cid, v in recon.log if cid == "recon-a"]
        assert "kill:SIGTERM" not in verbs
        assert verbs[0] == "kill:SIGKILL"
        assert recon.removed and a_tool.removed
        assert state.status == ReconStatus.IDLE

    def test_a_hard_stop_escalates_a_graceful_one_in_flight(self, fast, monkeypatch):
        monkeypatch.setattr(cm_mod, "RECON_STOP_GRACE_S", 30.0)
        recon = _recon(ignore_term=True)
        m = _manager([recon])
        _running(m)

        async def go():
            await m.stop_recon("proj-a")
            await asyncio.sleep(0.1)
            started = asyncio.get_running_loop().time()
            await m.stop_recon("proj-a", graceful=False)
            return asyncio.get_running_loop().time() - started

        took = asyncio.run(go())
        assert took < 5
        assert "kill:SIGKILL" in [v for _c, v in recon.log]
        assert recon.removed

    def test_the_project_delete_asks_for_the_hard_stop(self):
        # The DELETE route hands its stops to the shared teardown, which user
        # deletion runs too, so the hard stop is pinned where the teardown lives.
        route = (REPO / "webapp/src/app/api/projects/[id]/route.ts").read_text()
        assert "export async function DELETE" in route
        delete = route.split("export async function DELETE", 1)[1]
        assert "from '@/lib/projectTeardown'" in route
        assert "teardownProject(" in delete

        teardown = (REPO / "webapp/src/lib/projectTeardown.ts").read_text()
        assert "export async function teardownProject" in teardown
        body = teardown.split("export async function teardownProject", 1)[1]
        # The full recon: matched on the code, not the comment that explains it.
        assert re.search(r"\brecon:\s*'\?graceful=false'", body)
        assert "/stop${stopQuery[kind]" in body
        # Each running partial recon.
        assert "stopPartialRecons(id)" in body
        assert "/stop?graceful=false" in teardown


class TestThePartialStop:
    def test_it_answers_stopping_then_drops_the_run(self, fast):
        part = ExitsOnTerm("p1", "redamon-recon:latest", {"redamon.run_id": "r1"}, polls=2)
        m = _manager([part, tool("r1-katana", "r1", kind="partial_recon")])
        m.partial_recon_states["proj-a"] = {"r1": PartialReconState(
            project_id="proj-a", run_id="r1", status=PartialReconStatus.RUNNING, container_id="p1")}

        async def go():
            state = await m.stop_partial_recon("proj-a", "r1")
            assert state.status == PartialReconStatus.STOPPING
            assert "r1" in m.partial_recon_states["proj-a"]
            await m._stop_tasks[("partial_recon", "proj-a", "r1")]
            return state

        state = asyncio.run(go())
        assert state.status == PartialReconStatus.IDLE
        assert "proj-a" not in m.partial_recon_states
        assert part.removed
        assert m.client.containers.items["r1-katana"].removed
        assert [v for _c, v in part.log][0] == "kill:SIGTERM"


class TestTheGrace:
    @pytest.mark.parametrize("raw, expected", [("", 45.0), ("60", 60.0), ("x", 45.0), ("0", 45.0)])
    def test_blank_means_45(self, monkeypatch, raw, expected):
        monkeypatch.setenv("RECON_STOP_GRACE_S", raw)
        assert cm_mod._stop_grace_s() == expected

    def test_compose_passes_it_to_the_orchestrator(self):
        compose = (REPO / "docker-compose.yml").read_text()
        assert "RECON_STOP_GRACE_S: ${RECON_STOP_GRACE_S:-}" in compose

    def test_the_spawned_containers_get_it(self):
        src = (REPO / "recon_orchestrator" / "container_manager.py").read_text()
        assert src.count('"RECON_STOP_GRACE_S": str(RECON_STOP_GRACE_S)') == 2

    def test_shutdown_keeps_a_short_hard_bound(self, monkeypatch):
        calls = []

        async def stop_recon(pid, **kwargs):
            calls.append(("full", pid, kwargs))

        async def stop_partial(pid, rid, **kwargs):
            calls.append(("partial", pid, kwargs))

        m = _manager([])
        m.running_states["proj-a"] = ReconState(project_id="proj-a", status=ReconStatus.RUNNING)
        m.partial_recon_states["proj-b"] = {"r1": PartialReconState(project_id="proj-b", run_id="r1")}
        for name in ("gvm_states", "github_hunt_states", "trufflehog_states", "supply_chain_states",
                     "ai_attack_states", "codefix_sandboxes"):
            setattr(m, name, {})
        monkeypatch.setattr(m, "stop_recon", stop_recon)
        monkeypatch.setattr(m, "stop_partial_recon", stop_partial)
        asyncio.run(m.cleanup())
        assert calls == [("full", "proj-a", {"grace": 5, "wait": True}),
                         ("partial", "proj-b", {"grace": 5, "wait": True})]
