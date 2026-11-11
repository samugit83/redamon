"""
Integration tests for the parallel-scan freeze fix, exercising the real FastAPI
endpoint coroutines (api.py) wired to a ContainerManager with a mocked Docker
client. These lock the end-to-end behavior the freeze broke:

  * GET  /recon/{id}/partial/all  (list_partial_recons)  -- polled every ~5s
  * POST /recon/{id}/partial       (start_partial_recon)  -- the hanging POST

They assert both correctness (right response models) AND the concurrency
guarantee: a slow Docker daemon on one request cannot stall others.

The governor is disabled here so admission is deterministic (fail-open), and no
real Docker daemon is required.
"""
import asyncio
import os
import time
from unittest.mock import MagicMock, patch

import pytest

os.environ.setdefault("ORCHESTRATOR_API_KEY", "test-key")
os.environ["REDAMON_MEM_GOVERNOR"] = "0"  # deterministic admission (fail-open)

import api  # noqa: E402  (env must be set before import)
from container_manager import ContainerManager  # noqa: E402
from tests.job_credentials import job_credential, use_keys  # noqa: E402
from models import (  # noqa: E402
    PartialReconState,
    PartialReconStatus,
    PartialReconStartRequest,
)


@pytest.fixture
def mock_docker_client():
    client = MagicMock()
    client.containers = MagicMock()
    client.images = MagicMock()
    return client


@pytest.fixture
def wired_manager(mock_docker_client):
    """A ContainerManager with a mocked Docker client, installed as api.py's
    module-level singleton so the endpoint coroutines use it. Restored after."""
    with patch('container_manager.docker') as mock_docker_mod:
        mock_docker_mod.from_env.return_value = mock_docker_client
        mgr = ContainerManager()
        mgr.client = mock_docker_client
    prev = api.container_manager
    api.container_manager = mgr
    try:
        yield mgr
    finally:
        api.container_manager = prev


class TestListPartialReconsEndpoint:

    @pytest.mark.asyncio
    async def test_returns_list_response_model(self, wired_manager, mock_docker_client):
        wired_manager.partial_recon_states["p"] = {
            "r1": PartialReconState(project_id="p", run_id="r1", tool_id="Naabu",
                                    status=PartialReconStatus.RUNNING, container_id="c1"),
        }
        running = MagicMock()
        running.status = "running"
        mock_docker_client.containers.get.return_value = running

        resp = await api.list_partial_recons("p")
        assert resp.project_id == "p"
        assert len(resp.runs) == 1
        assert resp.runs[0].run_id == "r1"
        assert resp.runs[0].status == PartialReconStatus.RUNNING

    @pytest.mark.asyncio
    async def test_endpoint_stays_responsive_under_slow_docker(self, wired_manager, mock_docker_client):
        """The exact freeze scenario at the HTTP-handler level: several running
        partial recons, each with a SLOW Docker status call. While the poll runs,
        a heartbeat coroutine (standing in for /health and other requests) must
        keep advancing -- proving the endpoint no longer blocks the event loop."""
        wired_manager.partial_recon_states["p"] = {
            f"r{i}": PartialReconState(project_id="p", run_id=f"r{i}",
                                       status=PartialReconStatus.RUNNING, container_id=f"c{i}")
            for i in range(8)
        }

        def slow_get(_cid):
            time.sleep(0.2)
            c = MagicMock()
            c.status = "running"
            return c
        mock_docker_client.containers.get.side_effect = slow_get

        ticks = 0

        async def heartbeat():
            nonlocal ticks
            for _ in range(300):
                await asyncio.sleep(0.01)
                ticks += 1

        hb = asyncio.create_task(heartbeat())
        resp = await api.list_partial_recons("p")
        assert len(resp.runs) == 8
        assert ticks >= 5, f"endpoint blocked the event loop (ticks={ticks})"
        hb.cancel()

    @pytest.mark.asyncio
    async def test_concurrent_polls_do_not_serialize(self, wired_manager, mock_docker_client):
        """Two projects polled concurrently: with a dedicated pool the two slow
        Docker calls overlap, so wall time ~= one call, not two."""
        for proj in ("a", "b"):
            wired_manager.partial_recon_states[proj] = {
                "r1": PartialReconState(project_id=proj, run_id="r1",
                                        status=PartialReconStatus.RUNNING, container_id=f"{proj}-c1"),
            }

        def slow_get(_cid):
            time.sleep(0.3)
            c = MagicMock()
            c.status = "running"
            return c
        mock_docker_client.containers.get.side_effect = slow_get

        start = time.monotonic()
        ra, rb = await asyncio.gather(
            api.list_partial_recons("a"),
            api.list_partial_recons("b"),
        )
        elapsed = time.monotonic() - start
        assert len(ra.runs) == 1 and len(rb.runs) == 1
        assert elapsed < 0.5, f"concurrent polls serialized (elapsed={elapsed:.2f}s)"


class TestStartPartialReconEndpoint:

    @pytest.fixture(autouse=True)
    def _project(self, monkeypatch):
        # The scope pre-flight is unconditional (it reads the project's roots from the
        # webapp), so the start needs a webapp URL; the project it would fetch is this.
        monkeypatch.setattr(api, "_fetch_project_for_preflight",
                            lambda pid: {"targetDomain": "example.com", "subdomainList": []})
        use_keys(monkeypatch)

    @pytest.mark.asyncio
    async def test_spawns_container_and_returns_running(self, wired_manager, mock_docker_client):
        """End-to-end POST: image exists, containers.run (executor-wrapped via
        functools.partial) returns a container, endpoint returns a RUNNING state
        with the container id. Guards the spawn-path rewrite."""
        mock_docker_client.images.get.return_value = MagicMock()  # image present, no build
        spawned = MagicMock()
        spawned.id = "spawned-123"
        mock_docker_client.containers.run.return_value = spawned

        req = PartialReconStartRequest(
            project_id="p", user_id="u", webapp_api_url="http://localhost:3000",
            tool_id="SubdomainDiscovery", graph_inputs={"domain": "example.com"},
            job_credential=job_credential("p", "u"),
        )
        state = await api.start_partial_recon("p", req)

        assert state.status == PartialReconStatus.RUNNING
        assert state.container_id == "spawned-123"
        assert state.tool_id == "SubdomainDiscovery"
        assert mock_docker_client.containers.run.called

    @pytest.mark.asyncio
    async def test_start_does_not_block_event_loop_on_slow_spawn(self, wired_manager, mock_docker_client):
        """A slow containers.run (the POST the bug reported hanging) must not
        block the loop: a heartbeat keeps ticking during the spawn."""
        mock_docker_client.images.get.return_value = MagicMock()

        def slow_run(*_a, **_k):
            time.sleep(0.3)
            c = MagicMock()
            c.id = "slow-1"
            return c
        mock_docker_client.containers.run.side_effect = slow_run

        ticks = 0

        async def heartbeat():
            nonlocal ticks
            for _ in range(300):
                await asyncio.sleep(0.01)
                ticks += 1

        req = PartialReconStartRequest(
            project_id="p2", user_id="u", webapp_api_url="http://localhost:3000",
            tool_id="Naabu", graph_inputs={"domain": "example.com"},
            job_credential=job_credential("p2", "u"),
        )
        hb = asyncio.create_task(heartbeat())
        state = await api.start_partial_recon("p2", req)
        assert state.status == PartialReconStatus.RUNNING
        assert ticks >= 5, f"slow spawn blocked the event loop (ticks={ticks})"
        hb.cancel()
