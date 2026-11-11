"""S-5: scans that outlive an orchestrator restart are not adopted.

Scan containers are siblings on the host daemon (docker-py over the mounted
/var/run/docker.sock), not members of the compose project, so stopping or
restarting the orchestrator does not stop them. Its own shutdown hook
(`cleanup`) stops only the runs it has in memory, one after the other, and
uvicorn runs that hook only once every open response has finished (a scan log
stream stays open for the whole scan), inside compose's 10 s stop grace. A
crash or an OOM kill (restart: unless-stopped) skips it altogether. So after a
restart the containers keep running and the new process starts with empty
state dicts.

Here a fresh ContainerManager (its real __init__, on a fake daemon) meets the
containers a previous process left: a full recon, a partial recon, a GVM scan
and a TruffleHog source run, each with the name and labels its spawn gives it.

What works today (plain tests): the full recon, GVM and TruffleHog are found
by container NAME for a status read and a stop. What does not (strict xfail,
AssertionError only): nothing is put back into the state dicts, so the 30 s
reaper never counts them (governor reservations, the queue's live-project set),
an orphan that finishes is reported `idle` (the webapp records a completed scan
as canceled) and a finished TruffleHog run is never ingested (its container
holds no Neo4j credentials, so its findings are lost); the partial recon is not
found at all, so it cannot be listed or stopped and a full recon may start
beside it; the TruffleHog run is missing from the per-project listing the
webapp's version-save and activation guards read.

A fix that adopts at startup (an api.py lifespan hook) must call that hook in
`_restarted()`; a fix that adopts on the reaper's sweep needs no change here.
"""
import asyncio
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "recon_orchestrator"))
sys.path.insert(0, str(REPO))

import container_manager as cm_mod  # noqa: E402
from models import (  # noqa: E402
    GvmStatus, PartialReconStatus, ReconStatus, TrufflehogStatus,
)
from tests.fake_docker import FakeClient, FakeContainer, tool  # noqa: E402

RUN_FULL = "11111111-aaaa-4000-8000-000000000001"
RUN_PARTIAL = "22222222-bbbb-4000-8000-000000000002"

S5 = pytest.mark.xfail(
    strict=True, raises=AssertionError,
    reason="S-5: a scan that outlives an orchestrator restart is not adopted into the state dicts")


class _ReachedAdmission(Exception):
    """The start got past every mutual-exclusion check."""


def _restarted(client):
    """A new orchestrator process: the real constructor, on the given daemon."""
    with patch.object(cm_mod.docker, "from_env", return_value=client):
        return cm_mod.ContainerManager()


@pytest.fixture
def world():
    log = []
    full = FakeContainer("c-full", "redamon-recon:latest",
                         cm_mod.run_labels("proj-a", RUN_FULL, "full_recon"),
                         name="redamon-recon-proj-a", log=log)
    full_tool = tool("c-full-nuclei", RUN_FULL, project="proj-a", log=log)
    partial = FakeContainer("c-partial", "redamon-recon:latest",
                            cm_mod.run_labels("proj-b", RUN_PARTIAL, "partial_recon"),
                            name=f"redamon-partial-recon-proj-b-{RUN_PARTIAL[:8]}", log=log)
    gvm = FakeContainer("c-gvm", "redamon-vuln-scanner:latest",
                        name="redamon-gvm-proj-c", log=log)
    trufflehog = FakeContainer("c-th", "redamon-trufflehog:latest",
                               name="redamon-trufflehog-proj-d-github", log=log)
    client = FakeClient([full, full_tool, partial, gvm, trufflehog])
    m = _restarted(client)
    ingested = []
    m._ingest_trufflehog = lambda state: ingested.append((state.project_id, state.source))
    m._trufflehog_artifact_error = lambda project_id, source: None
    yield {"m": m, "log": log, "full": full, "full_tool": full_tool, "partial": partial,
           "gvm": gvm, "trufflehog": trufflehog, "ingested": ingested}
    m._docker_op_executor.shutdown(wait=False)
    m._log_stream_executor.shutdown(wait=False)


def _verbs(log, cid):
    return [verb for c, verb in log if c == cid]


def _reaper_tick(m):
    """What api.py's 30 s reaper does before it reconciles reservations and the queue."""
    asyncio.run(m.refresh_all_scan_states())
    return m.active_scan_projects(), m._active_scan_keys()


# --- what the name lookup already covers -------------------------------------

def test_the_full_recon_is_found_by_name_and_stopped_with_its_tools(world):
    m = world["m"]
    assert asyncio.run(m.get_status("proj-a")).status == ReconStatus.RUNNING
    asyncio.run(m.stop_recon("proj-a", graceful=False))
    assert world["full"].removed
    assert world["full_tool"].removed


def test_the_gvm_scan_is_found_by_name_and_stopped(world):
    m = world["m"]
    assert asyncio.run(m.get_gvm_status("proj-c")).status == GvmStatus.RUNNING
    assert asyncio.run(m.stop_gvm_scan("proj-c", timeout=1)).status == GvmStatus.IDLE
    assert "stop" in _verbs(world["log"], "c-gvm")
    assert world["gvm"].removed


def test_the_trufflehog_run_is_found_by_name_and_stopped(world):
    m = world["m"]
    assert asyncio.run(m.get_trufflehog_status("proj-d", "github")).status == TrufflehogStatus.RUNNING
    asyncio.run(m.stop_trufflehog("proj-d", "github", timeout=1))
    assert world["trufflehog"].removed


# --- what nothing adopts ---------------------------------------------------------

@S5
@pytest.mark.parametrize("project, kind", [
    ("proj-a", "full_recon"),
    ("proj-b", "partial_recon"),
    ("proj-c", "gvm"),
    ("proj-d", "trufflehog"),
])
def test_the_reaper_counts_a_scan_that_survived_the_restart(world, project, kind):
    # Not counted: the governor admits new scans on top of its RAM, and the queue
    # reconcile closes the project's running row while the scan still writes.
    projects, keys = _reaper_tick(world["m"])
    assert project in projects
    assert any(k.startswith(kind) and project in k.split(":") for k in keys)


@S5
def test_a_full_recon_that_finishes_after_the_restart_reads_completed(world):
    m = world["m"]
    assert asyncio.run(m.get_status("proj-a")).status == ReconStatus.RUNNING
    world["full"].status, world["full"].exit_code = "exited", 0
    assert asyncio.run(m.get_status("proj-a")).status == ReconStatus.COMPLETED


@S5
def test_the_partial_recon_is_listed_after_the_restart(world):
    runs = asyncio.run(world["m"].get_all_partial_recon_statuses("proj-b"))
    assert [(r.run_id, r.status) for r in runs] == [(RUN_PARTIAL, PartialReconStatus.RUNNING)]


@S5
def test_the_partial_recon_reads_running_after_the_restart(world):
    state = asyncio.run(world["m"].get_partial_recon_status("proj-b", RUN_PARTIAL))
    assert state.status == PartialReconStatus.RUNNING


@S5
def test_the_partial_recon_can_be_stopped_after_the_restart(world):
    asyncio.run(world["m"].stop_partial_recon("proj-b", RUN_PARTIAL, graceful=False))
    assert world["partial"].removed


@S5
def test_a_full_recon_is_refused_beside_a_surviving_partial_recon(world):
    m = world["m"]

    async def _reached(*a, **k):
        raise _ReachedAdmission

    m._admit_scan = _reached
    try:
        asyncio.run(m.start_recon("proj-b", "u1", "http://webapp", "/host/recon"))
        refused = False
    except ValueError:
        refused = True
    except _ReachedAdmission:
        refused = False
    assert refused


@S5
def test_the_trufflehog_run_is_listed_after_the_restart(world):
    runs = asyncio.run(world["m"].get_all_trufflehog_statuses("proj-d"))
    assert [(r.source, r.status) for r in runs] == [("github", TrufflehogStatus.RUNNING)]


@S5
def test_a_trufflehog_run_that_finishes_after_the_restart_is_ingested(world):
    m = world["m"]
    assert asyncio.run(m.get_trufflehog_status("proj-d", "github")).status == TrufflehogStatus.RUNNING
    world["trufflehog"].status, world["trufflehog"].exit_code = "exited", 0
    asyncio.run(m.get_trufflehog_status("proj-d", "github"))
    assert world["ingested"] == [("proj-d", "github")]
