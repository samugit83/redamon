"""A container that could not be created is a refused start, not an accepted one (plan 12.9).

start_recon caught the spawn exception and returned `status: error`, and the
API answered that with 200, so the webapp ran retention (irreversible
deletions), kept the prepared version and recorded a running ScanJob for a
scan that never started. The memory reservation stayed until the 30 s reaper.
The API now answers 500 with code `spawn_failed`, and the reservation is
released at once.
"""
import asyncio
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "recon_orchestrator"))
sys.path.insert(0, str(REPO))

import api  # noqa: E402
import container_manager as cm_mod  # noqa: E402
from models import PartialReconStartRequest, ReconStartRequest  # noqa: E402
from tests.job_credentials import job_credential, use_keys  # noqa: E402


class _Ledger:
    def __init__(self):
        self.released = []

    def release_nowait(self, key):
        self.released.append(key)


def _manager():
    m = cm_mod.ContainerManager.__new__(cm_mod.ContainerManager)
    m.client = MagicMock()
    m.client.containers.get.side_effect = cm_mod.NotFound("none")
    m.client.containers.run.side_effect = cm_mod.APIError("No such image: redamon-recon:latest")
    m.running_states = {}
    m.partial_recon_states = {}
    m._docker_op_executor = ThreadPoolExecutor(max_workers=2)
    m.recon_image = "redamon-recon:latest"
    m.supply_chain_osv_db_volume = "osv"
    m.sca_intel_volume = "intel"
    m.ledger = _Ledger()

    async def admit(kind, project_id, run_id=None, user_id=None):
        return m._scan_key(kind, project_id, run_id)

    m._admit_scan = admit
    m._warm_feeds_in_background = lambda: None
    m._recon_settings_mount = lambda: {}
    m._graph_db_mount = lambda *a, **k: {}
    m._scanner_env = lambda: {}
    m._analyzer_env = lambda: {}
    m._container_mem_limit = lambda kind: "1g"
    m._container_pids_limit = lambda: 100
    m._container_cpu_limit = lambda: 1
    m._scanner_hardening = lambda **k: {}
    return m


@pytest.fixture
def manager(monkeypatch, tmp_path):
    m = _manager()
    monkeypatch.setattr(api, "container_manager", m)
    use_keys(monkeypatch)
    monkeypatch.setattr(api, "_fetch_project_for_preflight", lambda pid, **k: {"targetDomain": "example.com"})
    monkeypatch.setattr(cm_mod, "Path", lambda p: tmp_path / Path(p).name)
    return m


def test_a_full_start_that_cannot_spawn_answers_500_spawn_failed(manager):
    req = ReconStartRequest(project_id="p1", user_id="u1", webapp_api_url="",
                            job_credential=job_credential("p1", "u1"))
    with pytest.raises(HTTPException) as ei:
        asyncio.run(api.start_recon("p1", req))
    assert ei.value.status_code == 500
    assert ei.value.detail["code"] == "spawn_failed"
    assert "No such image" in ei.value.detail["detail"]


def test_its_reservation_is_released_at_once(manager):
    state = asyncio.run(manager.start_recon("p1", "u1", "http://webapp", "/host/recon"))
    assert state.status.value == "error"
    assert manager.ledger.released == ["full_recon:p1"]


def test_a_partial_start_that_cannot_spawn_answers_500_spawn_failed(manager):
    state = asyncio.run(manager.start_partial_recon(
        "p1", "Naabu", {"user_id": "u1", "webapp_api_url": "http://webapp"}, "/host/recon"))
    assert state.status.value == "error"
    assert manager.ledger.released == [f"partial_recon:Naabu:p1:{state.run_id}"]
    with pytest.raises(HTTPException) as ei:
        api._refuse_failed_spawn(state)
    assert ei.value.status_code == 500
    assert ei.value.detail["code"] == "spawn_failed"


def test_an_accepted_start_is_answered_as_before(manager):
    manager.client.containers.run.side_effect = None
    manager.client.containers.run.return_value = MagicMock(id="cid")
    req = ReconStartRequest(project_id="p1", user_id="u1", webapp_api_url="",
                            job_credential=job_credential("p1", "u1"))
    state = asyncio.run(api.start_recon("p1", req))
    assert state.status.value == "running"
    assert manager.ledger.released == []


def test_the_partial_endpoint_refuses_a_failed_spawn():
    body = (REPO / "recon_orchestrator" / "api.py").read_text()
    start = body.index("async def start_partial_recon(")
    block = body[start:body.index("\n@app.", start)]
    assert "_refuse_failed_spawn(state)" in block
