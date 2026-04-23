"""
Tests for parallel partial recon support in ContainerManager.

These tests mock Docker to test the state management logic
without requiring a running Docker daemon.
"""
import asyncio
import sys
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch, AsyncMock

import pytest

from models import (
    PartialReconState,
    PartialReconStatus,
    PartialReconListResponse,
    ReconState,
    ReconStatus,
)
from container_manager import ContainerManager, MAX_PARALLEL_PARTIAL_RECONS


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_docker_client():
    """Create a mock Docker client."""
    client = MagicMock()
    client.containers = MagicMock()
    client.images = MagicMock()
    return client


@pytest.fixture
def manager(mock_docker_client):
    """Create a ContainerManager with mocked Docker client."""
    with patch('container_manager.docker') as mock_docker_mod:
        mock_docker_mod.from_env.return_value = mock_docker_client
        mgr = ContainerManager()
        mgr.client = mock_docker_client
        return mgr


# ---------------------------------------------------------------------------
# Model Tests
# ---------------------------------------------------------------------------

class TestPartialReconModels:
    def test_partial_recon_state_has_run_id(self):
        state = PartialReconState(project_id="proj-1", run_id="run-abc")
        assert state.run_id == "run-abc"
        assert state.status == PartialReconStatus.IDLE

    def test_partial_recon_state_default_run_id(self):
        state = PartialReconState(project_id="proj-1")
        assert state.run_id == ""

    def test_partial_recon_list_response(self):
        runs = [
            PartialReconState(project_id="proj-1", run_id="r1", tool_id="Naabu", status=PartialReconStatus.RUNNING),
            PartialReconState(project_id="proj-1", run_id="r2", tool_id="Httpx", status=PartialReconStatus.STARTING),
        ]
        resp = PartialReconListResponse(project_id="proj-1", runs=runs)
        assert resp.project_id == "proj-1"
        assert len(resp.runs) == 2
        assert resp.runs[0].run_id == "r1"
        assert resp.runs[1].tool_id == "Httpx"

    def test_partial_recon_list_response_empty(self):
        resp = PartialReconListResponse(project_id="proj-1", runs=[])
        assert len(resp.runs) == 0

    def test_partial_recon_state_serialization(self):
        state = PartialReconState(
            project_id="proj-1",
            run_id="run-abc",
            tool_id="Naabu",
            status=PartialReconStatus.RUNNING,
            container_id="abc123",
            started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        d = state.model_dump()
        assert d["run_id"] == "run-abc"
        assert d["status"] == "running"
        assert d["tool_id"] == "Naabu"


# ---------------------------------------------------------------------------
# Container Name Tests
# ---------------------------------------------------------------------------

class TestContainerNaming:
    def test_partial_container_name_includes_run_id(self, manager):
        name = manager._get_partial_container_name("proj-1", "abcdef12-3456-7890-abcd-ef1234567890")
        assert "abcdef12" in name
        assert "proj-1" in name

    def test_partial_container_name_sanitizes_project_id(self, manager):
        name = manager._get_partial_container_name("proj with spaces!", "run-123")
        assert " " not in name
        assert "!" not in name

    def test_different_run_ids_produce_different_names(self, manager):
        name1 = manager._get_partial_container_name("proj-1", "aaaaaaaa-1111-2222-3333-444444444444")
        name2 = manager._get_partial_container_name("proj-1", "bbbbbbbb-1111-2222-3333-444444444444")
        assert name1 != name2


# ---------------------------------------------------------------------------
# Count Active Tests
# ---------------------------------------------------------------------------

class TestCountActivePartialRecons:
    def test_count_zero_when_empty(self, manager):
        assert manager._count_active_partial_recons("proj-1") == 0

    def test_count_running(self, manager):
        manager.partial_recon_states["proj-1"] = {
            "r1": PartialReconState(project_id="proj-1", run_id="r1", status=PartialReconStatus.RUNNING),
        }
        assert manager._count_active_partial_recons("proj-1") == 1

    def test_count_starting(self, manager):
        manager.partial_recon_states["proj-1"] = {
            "r1": PartialReconState(project_id="proj-1", run_id="r1", status=PartialReconStatus.STARTING),
        }
        assert manager._count_active_partial_recons("proj-1") == 1

    def test_count_ignores_completed(self, manager):
        manager.partial_recon_states["proj-1"] = {
            "r1": PartialReconState(project_id="proj-1", run_id="r1", status=PartialReconStatus.RUNNING),
            "r2": PartialReconState(project_id="proj-1", run_id="r2", status=PartialReconStatus.COMPLETED),
            "r3": PartialReconState(project_id="proj-1", run_id="r3", status=PartialReconStatus.ERROR),
        }
        assert manager._count_active_partial_recons("proj-1") == 1

    def test_count_multiple_running(self, manager):
        manager.partial_recon_states["proj-1"] = {
            "r1": PartialReconState(project_id="proj-1", run_id="r1", status=PartialReconStatus.RUNNING),
            "r2": PartialReconState(project_id="proj-1", run_id="r2", status=PartialReconStatus.RUNNING),
            "r3": PartialReconState(project_id="proj-1", run_id="r3", status=PartialReconStatus.STARTING),
        }
        assert manager._count_active_partial_recons("proj-1") == 3

    def test_count_different_projects_isolated(self, manager):
        manager.partial_recon_states["proj-1"] = {
            "r1": PartialReconState(project_id="proj-1", run_id="r1", status=PartialReconStatus.RUNNING),
        }
        manager.partial_recon_states["proj-2"] = {
            "r2": PartialReconState(project_id="proj-2", run_id="r2", status=PartialReconStatus.RUNNING),
            "r3": PartialReconState(project_id="proj-2", run_id="r3", status=PartialReconStatus.RUNNING),
        }
        assert manager._count_active_partial_recons("proj-1") == 1
        assert manager._count_active_partial_recons("proj-2") == 2


# ---------------------------------------------------------------------------
# Refresh State Tests
# ---------------------------------------------------------------------------

class TestRefreshPartialReconState:
    def test_skip_if_no_container_id(self, manager):
        state = PartialReconState(project_id="p", run_id="r", status=PartialReconStatus.RUNNING)
        manager._refresh_partial_recon_state(state)
        assert state.status == PartialReconStatus.RUNNING

    def test_skip_if_already_completed(self, manager):
        state = PartialReconState(
            project_id="p", run_id="r", status=PartialReconStatus.COMPLETED,
            container_id="abc", completed_at=datetime.now(timezone.utc),
        )
        manager._refresh_partial_recon_state(state)
        assert state.status == PartialReconStatus.COMPLETED

    def test_detect_completion_exit_code_0(self, manager, mock_docker_client):
        mock_container = MagicMock()
        mock_container.status = "exited"
        mock_container.attrs = {"State": {"ExitCode": 0}}
        mock_docker_client.containers.get.return_value = mock_container

        state = PartialReconState(
            project_id="p", run_id="r", status=PartialReconStatus.RUNNING,
            container_id="abc",
        )
        manager._refresh_partial_recon_state(state)
        assert state.status == PartialReconStatus.COMPLETED
        assert state.completed_at is not None
        mock_container.remove.assert_called_once()

    def test_detect_error_nonzero_exit(self, manager, mock_docker_client):
        mock_container = MagicMock()
        mock_container.status = "exited"
        mock_container.attrs = {"State": {"ExitCode": 1}}
        mock_docker_client.containers.get.return_value = mock_container

        state = PartialReconState(
            project_id="p", run_id="r", status=PartialReconStatus.RUNNING,
            container_id="abc",
        )
        manager._refresh_partial_recon_state(state)
        assert state.status == PartialReconStatus.ERROR
        assert "exited with code 1" in state.error

    def test_container_not_found_sets_error(self, manager, mock_docker_client):
        from docker.errors import NotFound
        mock_docker_client.containers.get.side_effect = NotFound("gone")

        state = PartialReconState(
            project_id="p", run_id="r", status=PartialReconStatus.RUNNING,
            container_id="abc",
        )
        manager._refresh_partial_recon_state(state)
        assert state.status == PartialReconStatus.ERROR
        assert state.error == "Container not found"


# ---------------------------------------------------------------------------
# Get Status Tests
# ---------------------------------------------------------------------------

class TestGetPartialReconStatus:
    @pytest.mark.asyncio
    async def test_returns_idle_when_not_found(self, manager):
        state = await manager.get_partial_recon_status("proj-1", "nonexistent")
        assert state.status == PartialReconStatus.IDLE
        assert state.run_id == "nonexistent"
        assert state.project_id == "proj-1"

    @pytest.mark.asyncio
    async def test_returns_existing_state(self, manager, mock_docker_client):
        existing = PartialReconState(
            project_id="proj-1", run_id="r1", tool_id="Naabu",
            status=PartialReconStatus.RUNNING, container_id="abc",
        )
        manager.partial_recon_states["proj-1"] = {"r1": existing}

        mock_container = MagicMock()
        mock_container.status = "running"
        mock_docker_client.containers.get.return_value = mock_container

        state = await manager.get_partial_recon_status("proj-1", "r1")
        assert state.status == PartialReconStatus.RUNNING
        assert state.tool_id == "Naabu"


# ---------------------------------------------------------------------------
# Get All Statuses Tests
# ---------------------------------------------------------------------------

class TestGetAllPartialReconStatuses:
    @pytest.mark.asyncio
    async def test_returns_empty_for_unknown_project(self, manager):
        result = await manager.get_all_partial_recon_statuses("unknown")
        assert result == []

    @pytest.mark.asyncio
    async def test_returns_all_runs(self, manager, mock_docker_client):
        manager.partial_recon_states["proj-1"] = {
            "r1": PartialReconState(project_id="proj-1", run_id="r1", status=PartialReconStatus.RUNNING, container_id="c1"),
            "r2": PartialReconState(project_id="proj-1", run_id="r2", status=PartialReconStatus.STARTING),
        }
        mock_container = MagicMock()
        mock_container.status = "running"
        mock_docker_client.containers.get.return_value = mock_container

        result = await manager.get_all_partial_recon_statuses("proj-1")
        assert len(result) == 2
        run_ids = {r.run_id for r in result}
        assert "r1" in run_ids
        assert "r2" in run_ids

    @pytest.mark.asyncio
    async def test_auto_cleans_old_completed(self, manager):
        old_time = datetime.now(timezone.utc) - timedelta(seconds=120)
        manager.partial_recon_states["proj-1"] = {
            "r1": PartialReconState(
                project_id="proj-1", run_id="r1",
                status=PartialReconStatus.COMPLETED,
                completed_at=old_time,
            ),
            "r2": PartialReconState(
                project_id="proj-1", run_id="r2",
                status=PartialReconStatus.RUNNING,
                container_id="c2",
            ),
        }
        mock_container = MagicMock()
        mock_container.status = "running"
        manager.client.containers.get.return_value = mock_container

        result = await manager.get_all_partial_recon_statuses("proj-1")
        assert len(result) == 1
        assert result[0].run_id == "r2"

    @pytest.mark.asyncio
    async def test_keeps_recent_completed(self, manager):
        recent_time = datetime.now(timezone.utc) - timedelta(seconds=10)
        manager.partial_recon_states["proj-1"] = {
            "r1": PartialReconState(
                project_id="proj-1", run_id="r1",
                status=PartialReconStatus.COMPLETED,
                completed_at=recent_time,
            ),
        }
        result = await manager.get_all_partial_recon_statuses("proj-1")
        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_cleans_outer_dict_when_empty(self, manager):
        old_time = datetime.now(timezone.utc) - timedelta(seconds=120)
        manager.partial_recon_states["proj-1"] = {
            "r1": PartialReconState(
                project_id="proj-1", run_id="r1",
                status=PartialReconStatus.COMPLETED,
                completed_at=old_time,
            ),
        }
        await manager.get_all_partial_recon_statuses("proj-1")
        assert "proj-1" not in manager.partial_recon_states


# ---------------------------------------------------------------------------
# Start Partial Recon Tests
# ---------------------------------------------------------------------------

class TestStartPartialRecon:
    @pytest.mark.asyncio
    async def test_start_returns_state_with_run_id(self, manager, mock_docker_client):
        mock_docker_client.images.get.return_value = MagicMock()
        mock_container = MagicMock()
        mock_container.id = "container-123"
        mock_docker_client.containers.run.return_value = mock_container

        with patch('container_manager.Path') as mock_path:
            mock_path.return_value = MagicMock()
            state = await manager.start_partial_recon(
                project_id="proj-1",
                tool_id="Naabu",
                config={"tool_id": "Naabu", "domain": "example.com", "user_id": "u1", "webapp_api_url": "http://localhost"},
                recon_path="/app/recon",
            )

        assert state.run_id != ""
        assert len(state.run_id) == 36  # UUID format
        assert state.tool_id == "Naabu"
        assert state.status == PartialReconStatus.RUNNING
        assert state.container_id == "container-123"
        assert state.project_id == "proj-1"

    @pytest.mark.asyncio
    async def test_start_stores_in_nested_dict(self, manager, mock_docker_client):
        mock_docker_client.images.get.return_value = MagicMock()
        mock_container = MagicMock()
        mock_container.id = "c1"
        mock_docker_client.containers.run.return_value = mock_container

        with patch('container_manager.Path') as mock_path:
            mock_path.return_value = MagicMock()
            state = await manager.start_partial_recon(
                project_id="proj-1", tool_id="Naabu",
                config={"tool_id": "Naabu", "domain": "x.com", "user_id": "", "webapp_api_url": ""},
                recon_path="/app/recon",
            )

        assert "proj-1" in manager.partial_recon_states
        assert state.run_id in manager.partial_recon_states["proj-1"]

    @pytest.mark.asyncio
    async def test_concurrency_limit_enforced(self, manager):
        manager.partial_recon_states["proj-1"] = {}
        for i in range(MAX_PARALLEL_PARTIAL_RECONS):
            run_id = f"run-{i}"
            manager.partial_recon_states["proj-1"][run_id] = PartialReconState(
                project_id="proj-1", run_id=run_id, status=PartialReconStatus.RUNNING,
            )

        with pytest.raises(ValueError, match=f"Maximum {MAX_PARALLEL_PARTIAL_RECONS}"):
            await manager.start_partial_recon(
                project_id="proj-1", tool_id="Naabu",
                config={"tool_id": "Naabu", "domain": "x.com", "user_id": "", "webapp_api_url": ""},
                recon_path="/app/recon",
            )

    @pytest.mark.asyncio
    async def test_allows_start_when_under_limit(self, manager, mock_docker_client):
        manager.partial_recon_states["proj-1"] = {}
        for i in range(MAX_PARALLEL_PARTIAL_RECONS - 1):
            run_id = f"run-{i}"
            manager.partial_recon_states["proj-1"][run_id] = PartialReconState(
                project_id="proj-1", run_id=run_id, status=PartialReconStatus.RUNNING,
            )

        mock_docker_client.images.get.return_value = MagicMock()
        mock_container = MagicMock()
        mock_container.id = "c-new"
        mock_docker_client.containers.run.return_value = mock_container

        with patch('container_manager.Path') as mock_path:
            mock_path.return_value = MagicMock()
            state = await manager.start_partial_recon(
                project_id="proj-1", tool_id="Httpx",
                config={"tool_id": "Httpx", "domain": "x.com", "user_id": "", "webapp_api_url": ""},
                recon_path="/app/recon",
            )

        assert state.status == PartialReconStatus.RUNNING
        assert len(manager.partial_recon_states["proj-1"]) == MAX_PARALLEL_PARTIAL_RECONS

    @pytest.mark.asyncio
    async def test_blocks_when_full_recon_running(self, manager):
        manager.running_states["proj-1"] = ReconState(
            project_id="proj-1", status=ReconStatus.RUNNING,
        )

        with pytest.raises(ValueError, match="Full recon is running"):
            await manager.start_partial_recon(
                project_id="proj-1", tool_id="Naabu",
                config={"tool_id": "Naabu", "domain": "x.com", "user_id": "", "webapp_api_url": ""},
                recon_path="/app/recon",
            )

    @pytest.mark.asyncio
    async def test_completed_runs_dont_count_toward_limit(self, manager, mock_docker_client):
        manager.partial_recon_states["proj-1"] = {}
        for i in range(MAX_PARALLEL_PARTIAL_RECONS):
            run_id = f"run-{i}"
            manager.partial_recon_states["proj-1"][run_id] = PartialReconState(
                project_id="proj-1", run_id=run_id, status=PartialReconStatus.COMPLETED,
            )

        mock_docker_client.images.get.return_value = MagicMock()
        mock_container = MagicMock()
        mock_container.id = "c-new"
        mock_docker_client.containers.run.return_value = mock_container

        with patch('container_manager.Path') as mock_path:
            mock_path.return_value = MagicMock()
            state = await manager.start_partial_recon(
                project_id="proj-1", tool_id="Naabu",
                config={"tool_id": "Naabu", "domain": "x.com", "user_id": "", "webapp_api_url": ""},
                recon_path="/app/recon",
            )
        assert state.status == PartialReconStatus.RUNNING


# ---------------------------------------------------------------------------
# Stop Partial Recon Tests
# ---------------------------------------------------------------------------

class TestStopPartialRecon:
    @pytest.mark.asyncio
    async def test_stop_removes_from_dict(self, manager, mock_docker_client):
        state = PartialReconState(
            project_id="proj-1", run_id="r1", status=PartialReconStatus.RUNNING,
            container_id="c1",
        )
        manager.partial_recon_states["proj-1"] = {"r1": state}

        mock_container = MagicMock()
        mock_container.status = "running"
        mock_docker_client.containers.get.return_value = mock_container

        result = await manager.stop_partial_recon("proj-1", "r1")
        assert result.status == PartialReconStatus.IDLE
        assert "proj-1" not in manager.partial_recon_states

    @pytest.mark.asyncio
    async def test_stop_one_keeps_others(self, manager, mock_docker_client):
        s1 = PartialReconState(project_id="proj-1", run_id="r1", status=PartialReconStatus.RUNNING, container_id="c1")
        s2 = PartialReconState(project_id="proj-1", run_id="r2", status=PartialReconStatus.RUNNING, container_id="c2")
        manager.partial_recon_states["proj-1"] = {"r1": s1, "r2": s2}

        mock_container = MagicMock()
        mock_container.status = "running"
        mock_docker_client.containers.get.return_value = mock_container

        await manager.stop_partial_recon("proj-1", "r1")
        assert "r1" not in manager.partial_recon_states["proj-1"]
        assert "r2" in manager.partial_recon_states["proj-1"]

    @pytest.mark.asyncio
    async def test_stop_nonexistent_returns_idle(self, manager):
        result = await manager.stop_partial_recon("proj-1", "nonexistent")
        assert result.status == PartialReconStatus.IDLE

    @pytest.mark.asyncio
    async def test_stop_does_not_cleanup_sub_containers(self, manager, mock_docker_client):
        state = PartialReconState(
            project_id="proj-1", run_id="r1", status=PartialReconStatus.RUNNING,
            container_id="c1",
        )
        manager.partial_recon_states["proj-1"] = {"r1": state}

        mock_container = MagicMock()
        mock_container.status = "running"
        mock_docker_client.containers.get.return_value = mock_container

        await manager.stop_partial_recon("proj-1", "r1")
        # _cleanup_sub_containers should NOT be called
        mock_docker_client.containers.list.assert_not_called()


# ---------------------------------------------------------------------------
# Full Recon Mutual Exclusion Tests
# ---------------------------------------------------------------------------

class TestFullReconMutualExclusion:
    @pytest.mark.asyncio
    async def test_full_recon_blocked_by_partial(self, manager):
        manager.partial_recon_states["proj-1"] = {
            "r1": PartialReconState(
                project_id="proj-1", run_id="r1", status=PartialReconStatus.RUNNING,
            ),
        }

        with pytest.raises(ValueError, match="Partial recon.*running"):
            await manager.start_recon(
                project_id="proj-1",
                user_id="u1",
                webapp_api_url="http://localhost",
                recon_path="/app/recon",
            )

    @pytest.mark.asyncio
    async def test_full_recon_blocked_by_multiple_partials(self, manager):
        manager.partial_recon_states["proj-1"] = {
            "r1": PartialReconState(project_id="proj-1", run_id="r1", status=PartialReconStatus.RUNNING),
            "r2": PartialReconState(project_id="proj-1", run_id="r2", status=PartialReconStatus.STARTING),
        }

        with pytest.raises(ValueError, match="Partial recon.*running"):
            await manager.start_recon(
                project_id="proj-1",
                user_id="u1",
                webapp_api_url="http://localhost",
                recon_path="/app/recon",
            )


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

class TestConstants:
    def test_max_parallel_is_12(self):
        assert MAX_PARALLEL_PARTIAL_RECONS == 12
