"""JS Recon's TruffleHog stage dirs never outlive their run, and its image is reported.

A run stages copies of a target's JavaScript in /tmp/redamon/js_recon_th_<run>_<8 hex>
and removes them itself; when its container is killed at the stop grace or
crashes, the orchestrator removes them where it reaps the run's tools, at run
completion, and in a startup sweep that spares every run whose container the
daemon still lists as live (a run outlives an orchestrator restart without
being adopted, so the startup state dicts are empty). Availability is an
uncached image lookup for the webapp's form.
"""
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from docker.errors import APIError, NotFound

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "recon_orchestrator"))
sys.path.insert(0, str(REPO))

import container_manager as cm_mod  # noqa: E402
from models import PartialReconState, PartialReconStatus, ReconState, ReconStatus  # noqa: E402
from tests.fake_docker import FakeClient, FakeContainer  # noqa: E402

LIVE = "1f0e2d3c-aaaa-4bbb-8ccc-000000000001"
DEAD = "1f0e2d3c-aaaa-4bbb-8ccc-000000000002"


def _recon(cid, run_id, status="running", name=None):
    return FakeContainer(cid, "redamon-recon:latest", {"redamon.run_id": run_id, "redamon.project_id": "p",
                                                       "redamon.run_kind": "full_recon"},
                         status=status, name=name or cid)


@pytest.fixture
def root(tmp_path, monkeypatch):
    monkeypatch.setattr(cm_mod, "JS_TRUFFLEHOG_STAGE_ROOT", str(tmp_path))
    for name in (f"js_recon_th_{LIVE}_0a1b2c3d", f"js_recon_th_{DEAD}_4e5f6a7b",
                 f"js_recon_th_{DEAD}_8c9d0e1f", "js_recon_abcdef012345", "trufflehog_p_git",
                 f"js_recon_th_{DEAD}_nothex12"):
        (tmp_path / name).mkdir()
        (tmp_path / name / "f_00001.js").write_text("var a = 1;")
    (tmp_path / f"js_recon_th_{DEAD}_aaaaaaaa").write_text("a file, not a stage dir")
    return tmp_path


def _manager(containers=()):
    m = cm_mod.ContainerManager.__new__(cm_mod.ContainerManager)
    m.client = FakeClient(containers)
    m.running_states, m.partial_recon_states = {}, {}
    m.trufflehog_image = "redamon-trufflehog:latest"
    return m


def _left(root):
    return sorted(os.listdir(root))


UNRELATED = ["js_recon_abcdef012345", f"js_recon_th_{DEAD}_aaaaaaaa", f"js_recon_th_{DEAD}_nothex12",
             "trufflehog_p_git"]


def test_reaping_a_runs_tools_removes_only_its_stage_dirs(root):
    _manager()._remove_run_tools_sync(DEAD)
    assert _left(root) == sorted([f"js_recon_th_{LIVE}_0a1b2c3d", *UNRELATED])


def test_completion_of_a_full_run_removes_its_stage_dirs(root):
    m = _manager([_recon("recon-dead", DEAD, status="exited")])
    m.running_states["p"] = ReconState(project_id="p", status=ReconStatus.RUNNING, container_id="recon-dead")
    assert m._get_status_sync("p").status == ReconStatus.COMPLETED
    assert f"js_recon_th_{DEAD}_4e5f6a7b" not in _left(root)
    assert f"js_recon_th_{LIVE}_0a1b2c3d" in _left(root)


def test_completion_of_a_partial_run_removes_its_stage_dirs(root):
    m = _manager([_recon("partial-dead", DEAD, status="exited")])
    state = PartialReconState(project_id="p", run_id=DEAD, status=PartialReconStatus.RUNNING,
                              container_id="partial-dead")
    m._refresh_partial_recon_state(state)
    assert state.status == PartialReconStatus.COMPLETED
    assert not {f"js_recon_th_{DEAD}_4e5f6a7b", f"js_recon_th_{DEAD}_8c9d0e1f"} & set(_left(root))
    assert f"js_recon_th_{LIVE}_0a1b2c3d" in _left(root)


def test_the_startup_sweep_spares_a_live_run(root):
    m = _manager([_recon("redamon-recon-p", LIVE), _recon("redamon-recon-q", DEAD, status="exited")])
    (root / "js_recon_th_test_x").mkdir()
    # Every stage dir of a run that is not alive goes, a hand-named one too;
    # a plain file and js_recon's own work dir are not stage dirs.
    assert m.sweep_trufflehog_stages() == 4
    assert _left(root) == sorted([f"js_recon_th_{LIVE}_0a1b2c3d", "js_recon_abcdef012345",
                                  f"js_recon_th_{DEAD}_aaaaaaaa", "trufflehog_p_git"])


def test_a_paused_run_is_alive_too(root):
    m = _manager([_recon("redamon-partial-recon-p-1", LIVE, status="paused")])
    m.sweep_trufflehog_stages()
    assert f"js_recon_th_{LIVE}_0a1b2c3d" in _left(root)


def test_no_listing_means_no_deletion(root):
    m = _manager()
    m.client.containers.list = MagicMock(side_effect=APIError("daemon down"))
    before = _left(root)
    assert m.sweep_trufflehog_stages() == 0
    assert _left(root) == before


@pytest.mark.parametrize("effect,want", [(None, True), (NotFound("x"), False), (APIError("x"), False)])
def test_availability(effect, want):
    m = _manager()
    m.client.images = MagicMock()
    m.client.images.get.side_effect = effect
    assert m.is_trufflehog_available() is want
    m.client.images.get.assert_called_once_with("redamon-trufflehog:latest")
