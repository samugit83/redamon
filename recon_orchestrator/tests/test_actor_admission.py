"""
Scans carry their actor (step 5.5; SH-37, D-14, the actor part of NF-08).

A start names two people. The tenant (`user_id`, which must equal the `ten` of the job
credential) owns the project: the container runs under it and writes its graph. The actor
(`actor_user_id`) is the person who started the scan: admission's per-user ceiling counts the
actor, so a collaborator's scans on someone else's project count against the collaborator, never
the owner, and the global ceiling still applies to everyone. A start that names no actor (an
owner's start, or a webapp from before 5.5) is the tenant's: nothing changes for owners.
"""
import asyncio
import logging
import pathlib
import types
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

import api
import container_manager as cm
from admission_ledger import AdmissionError, ReservationLedger
from models import (
    AiAttackSurfaceStartRequest,
    GithubHuntStartRequest,
    GithubHuntState,
    GithubHuntStatus,
    GvmStartRequest,
    GvmState,
    GvmStatus,
    PartialReconStartRequest,
    PartialReconStatus,
    ReconStartRequest,
    ReconState,
    ReconStatus,
    SupplyChainStartRequest,
    SupplyChainState,
    SupplyChainStatus,
    TrufflehogStartRequest,
    TrufflehogState,
    TrufflehogStatus,
)
from tests.job_credentials import job_credential, use_keys

GB = 1024 ** 3


# ---------------------------------------------------------------------------
# The API: the actor travels beside the tenant
# ---------------------------------------------------------------------------

class _Spy:
    """container_manager with every start recorded and nothing spawned."""

    def __init__(self):
        self.calls = []

    def __getattr__(self, name):
        if not name.startswith("start_"):
            raise AttributeError(name)

        async def start(**kw):
            self.calls.append((name, kw))
            status = PartialReconStatus.RUNNING if name == "start_partial_recon" else ReconStatus.RUNNING
            return types.SimpleNamespace(status=status, run_id="run-1", error=None)

        return start


@pytest.fixture
def spy(monkeypatch):
    s = _Spy()
    monkeypatch.setattr(api, "container_manager", s)
    monkeypatch.setattr(api, "_fetch_project_for_preflight", lambda pid, **k: {"targetDomain": "example.com"})
    monkeypatch.setattr(api, "AI_ATTACK_SURFACE_PATH", "/host/ai_attack_surface_scan")
    monkeypatch.setattr(pathlib.Path, "exists", lambda self: True)
    use_keys(monkeypatch)
    return s


# (endpoint, request model, extra fields)
STARTS = [
    ("start_recon", ReconStartRequest, {}),
    ("start_partial_recon", PartialReconStartRequest, {"tool_id": "Tlsx", "graph_inputs": {}}),
    ("start_gvm_scan", GvmStartRequest, {}),
    ("start_github_hunt", GithubHuntStartRequest, {}),
    ("start_supply_chain", SupplyChainStartRequest, {}),
    ("start_ai_attack_surface", AiAttackSurfaceStartRequest, {"roe_confirmed": True}),
    ("start_trufflehog", TrufflehogStartRequest, {"source": "docker"}),
]
IDS = [s[0] for s in STARTS]


def _start(endpoint, model, extra, **fields):
    body = {"project_id": "p1", "user_id": "owner-1", "webapp_api_url": "http://localhost:3000",
            "job_credential": job_credential("p1", "owner-1"), **extra, **fields}
    return asyncio.run(getattr(api, endpoint)("p1", model(**body)))


def _tenant_of(name, kw):
    return kw["config"]["user_id"] if name == "start_partial_recon" else kw["user_id"]


@pytest.mark.parametrize("endpoint,model,extra", STARTS, ids=IDS)
def test_the_actor_reaches_the_start_and_the_tenant_stays_the_containers(spy, endpoint, model, extra):
    _start(endpoint, model, extra, actor_user_id="collab-1")
    (name, kw), = spy.calls
    assert kw["actor_user_id"] == "collab-1"
    assert _tenant_of(name, kw) == "owner-1"
    # The partial container's config file is the tenant's alone: the actor is not written into it.
    if name == "start_partial_recon":
        assert "actor_user_id" not in kw["config"]


@pytest.mark.parametrize("endpoint,model,extra", STARTS, ids=IDS)
def test_no_actor_means_the_tenant_is_the_actor(spy, endpoint, model, extra):
    for fields in ({}, {"actor_user_id": None}, {"actor_user_id": ""}):
        spy.calls.clear()
        _start(endpoint, model, extra, **fields)
        (name, kw), = spy.calls
        assert kw["actor_user_id"] == "owner-1", fields
        assert _tenant_of(name, kw) == "owner-1"


@pytest.mark.parametrize("endpoint,model,extra", STARTS, ids=IDS)
def test_an_actor_never_loosens_the_tenant_check(spy, endpoint, model, extra):
    # The body's user_id must still be the credential's tenant: naming the actor there is refused.
    with pytest.raises(HTTPException) as ei:
        _start(endpoint, model, extra, user_id="collab-1", actor_user_id="collab-1")
    assert ei.value.status_code == 403
    assert ei.value.detail["code"] == "job_credential_user_mismatch"
    assert spy.calls == []


def test_the_start_log_names_the_tenant_and_the_actor(spy, caplog):
    with caplog.at_level(logging.INFO):
        _start("start_gvm_scan", GvmStartRequest, {}, actor_user_id="collab-1")
    assert "[scan] start gvm project=p1 tenant=owner-1 actor=collab-1" in caplog.text


# ---------------------------------------------------------------------------
# The container manager: each start admits its actor and records it on the run
# ---------------------------------------------------------------------------

class _Reached(Exception):
    """The start got past admission and created its run's state: nothing is spawned."""


def _manager(ledger=None):
    m = cm.ContainerManager.__new__(cm.ContainerManager)
    m.client = MagicMock()
    m.ledger = ledger or MagicMock(envelope_for=MagicMock(return_value=64 * 1024 ** 2))
    m.running_states = {}
    m.partial_recon_states = {}
    m.ai_attack_states = {}
    m.gvm_states = {}
    m.github_hunt_states = {}
    m.trufflehog_states = {}
    m.supply_chain_states = {}
    m.codefix_sandboxes = {}
    m.guarddog_jobs = set()
    m.trufflehog_scan_roots = {}
    m.trufflehog_scope_checker = None

    async def _none(*a, **k):
        return None

    async def _idle_recon(pid):
        return ReconState(project_id=pid, status=ReconStatus.IDLE)

    async def _idle_gvm(pid):
        return GvmState(project_id=pid, status=GvmStatus.IDLE)

    async def _idle_hunt(pid):
        return GithubHuntState(project_id=pid, status=GithubHuntStatus.IDLE)

    async def _idle_supply(pid):
        return SupplyChainState(project_id=pid, status=SupplyChainStatus.IDLE)

    async def _idle_truffle(pid, source):
        return TrufflehogState(project_id=pid, status=TrufflehogStatus.IDLE)

    m.get_status = _idle_recon
    m.get_gvm_status = _idle_gvm
    m.get_github_hunt_status = _idle_hunt
    m.get_supply_chain_status = _idle_supply
    m.get_trufflehog_status = _idle_truffle
    m._run_blocking = _none
    m._warm_feeds_in_background = lambda: None
    m.ensure_osv_db_fresh_async = _none
    m.ensure_sca_intel_fresh_async = _none
    return m


def _start_kwargs(kind, project_id, tenant, actor):
    base = {"project_id": project_id}
    if actor is not None:
        base["actor_user_id"] = actor
    if kind == "start_partial_recon":
        return {**base, "tool_id": "Naabu", "config": {"user_id": tenant, "domains": ["example.com"]},
                "recon_path": "/app/recon"}
    if kind == "start_trufflehog":
        return {**base, "user_id": tenant, "trufflehog_path": "/app/trufflehog_scan", "source": "docker",
                "config": {"images": ["nginx:1.25"]}, "common": {}, "secrets": {}}
    extra = {
        "start_recon": {"recon_path": "/app/recon"},
        "start_gvm_scan": {"recon_path": "/app/recon", "gvm_scan_path": "/app/gvm_scan"},
        "start_github_hunt": {"github_hunt_path": "/app/github_secret_hunt"},
        "start_supply_chain": {"supply_chain_path": "/app/supply_chain_scan"},
        "start_ai_attack_surface": {"run_config": {"tool": "skeleton"}, "ai_attack_path": "/app/ai"},
    }[kind]
    return {**base, "user_id": tenant, "webapp_api_url": "http://webapp:3000", **extra}


# (start, the state class it creates). TruffleHog claims its run slot (the state) BEFORE
# admission, every other start creates its state right after.
MANAGER_STARTS = [
    ("start_recon", "ReconState"),
    ("start_partial_recon", "PartialReconState"),
    ("start_gvm_scan", "GvmState"),
    ("start_github_hunt", "GithubHuntState"),
    ("start_supply_chain", "SupplyChainState"),
    ("start_ai_attack_surface", "AiAttackSurfaceState"),
    ("start_trufflehog", "TrufflehogState"),
]
MANAGER_IDS = [s[0] for s in MANAGER_STARTS]


def _drive(m, kind, state_cls, project_id, tenant, actor, admit=None):
    """Run one start to the point where its run state exists; what admission and the state got."""
    admitted, states = [], []
    real_cls = getattr(cm, state_cls)

    async def recording_admit(k, pid, run_id=None, user_id=None):
        admitted.append(user_id)
        if admit is not None:
            await admit(k, pid, run_id, user_id=user_id)
        if kind == "start_trufflehog":
            raise _Reached()
        return f"{k}:{pid}"

    def recording_state(**kw):
        states.append(kw)
        if kind == "start_trufflehog":
            return real_cls(**kw)
        raise _Reached()

    m._admit_scan = recording_admit
    with patch.object(cm, state_cls, recording_state), \
            patch.object(cm, "classify_host", return_value=(True, "93.184.216.34", "ok")):
        with pytest.raises(_Reached):
            asyncio.run(getattr(m, kind)(**_start_kwargs(kind, project_id, tenant, actor)))
    return admitted, states


@pytest.mark.parametrize("kind,state_cls", MANAGER_STARTS, ids=MANAGER_IDS)
def test_each_start_admits_its_actor_and_records_it_on_the_run(kind, state_cls):
    admitted, states = _drive(_manager(), kind, state_cls, "p1", "owner-1", "collab-1")
    assert admitted == ["collab-1"]
    (state,) = states
    assert state["actor_user_id"] == "collab-1"
    # The tenant stays where the start already kept it (the hunt and TruffleHog ingest under it).
    if "user_id" in state:
        assert state["user_id"] == "owner-1"


@pytest.mark.parametrize("kind,state_cls", MANAGER_STARTS, ids=MANAGER_IDS)
def test_a_start_with_no_actor_admits_the_tenant(kind, state_cls):
    admitted, states = _drive(_manager(), kind, state_cls, "p1", "owner-1", None)
    assert admitted == ["owner-1"]
    assert states[0]["actor_user_id"] == "owner-1"


# ---------------------------------------------------------------------------
# The ledger: the per-user ceiling counts the actor, the global ceiling everyone
# ---------------------------------------------------------------------------

@pytest.fixture
def roomy(monkeypatch):
    """A governor with memory to spare, so only the count ceilings can refuse."""
    for name in ("RECON_MAX_CONCURRENT_GLOBAL", "RECON_MAX_CONCURRENT_PER_USER"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("REDAMON_MEM_GOVERNOR", "true")
    monkeypatch.setenv("RECON_JOB_ENVELOPE_MEM", "64m")
    monkeypatch.setenv("OS_HEADROOM_MEM", "1g")
    monkeypatch.setenv("SERVICE_BASELINE_MEM", "1g")
    return ReservationLedger(mem_reader=lambda: (64 * GB, 60 * GB), pressure_fn=lambda: "none")


def _start_through_the_manager(m, kind, state_cls, project_id, tenant, actor):
    """A start on the real ledger: admitted (its run state reached) or refused (AdmissionError)."""
    real_admit = cm.ContainerManager._admit_scan.__get__(m)
    try:
        _drive(m, kind, state_cls, project_id, tenant, actor, admit=real_admit)
    except AdmissionError as e:
        return e.result
    return None


def test_admission_counts_the_actor(roomy, monkeypatch):
    monkeypatch.setenv("RECON_MAX_CONCURRENT_PER_USER", "2")
    m = _manager(roomy)
    # The collaborator starts a scan on each of two owners' projects: both count against them.
    assert _start_through_the_manager(m, "start_gvm_scan", "GvmState", "p-alice", "alice", "collab") is None
    assert _start_through_the_manager(m, "start_github_hunt", "GithubHuntState", "p-bob", "bob", "collab") is None
    assert roomy.user_active_count("collab") == 2
    assert roomy.user_active_count("alice") == 0
    assert roomy.user_active_count("bob") == 0

    refused = _start_through_the_manager(m, "start_supply_chain", "SupplyChainState", "p-alice", "alice", "collab")
    assert refused is not None
    assert refused.setting_name == "RECON_MAX_CONCURRENT_PER_USER"
    assert (refused.current, refused.ceiling) == (2, 2)

    # The owner's own scans are theirs to count: the collaborator's two never used the owner's slots.
    assert _start_through_the_manager(m, "start_supply_chain", "SupplyChainState", "p-alice", "alice", None) is None
    assert roomy.user_active_count("alice") == 1


def test_the_global_ceiling_still_applies(roomy, monkeypatch):
    monkeypatch.setenv("RECON_MAX_CONCURRENT_GLOBAL", "2")
    m = _manager(roomy)
    assert _start_through_the_manager(m, "start_gvm_scan", "GvmState", "p-alice", "alice", "collab-1") is None
    assert _start_through_the_manager(m, "start_github_hunt", "GithubHuntState", "p-bob", "bob", "collab-2") is None
    refused = _start_through_the_manager(m, "start_supply_chain", "SupplyChainState", "p-carol", "carol", "carol")
    assert refused is not None
    assert refused.limit_type == "hard"
    assert refused.setting_name == "RECON_MAX_CONCURRENT_GLOBAL"


def test_the_admission_log_names_the_actor(roomy, caplog):
    m = _manager(roomy)
    with caplog.at_level(logging.INFO):
        asyncio.run(m._admit_scan("gvm", "p-alice", user_id="collab"))
    assert "admitted gvm:p-alice for collab" in caplog.text


# ---------------------------------------------------------------------------
# Status: the run carries its actor
# ---------------------------------------------------------------------------

def test_a_run_state_defaults_to_no_actor():
    # A run adopted after an orchestrator restart (or one started by an older webapp) has none.
    for state in (ReconState(project_id="p1", status=ReconStatus.IDLE),
                  GvmState(project_id="p1", status=GvmStatus.IDLE),
                  TrufflehogState(project_id="p1", status=TrufflehogStatus.IDLE)):
        assert state.actor_user_id is None


def test_active_scans_name_each_runs_actor(monkeypatch):
    fake = types.SimpleNamespace(
        running_states={"p1": ReconState(project_id="p1", status=ReconStatus.RUNNING, actor_user_id="collab-1")},
        gvm_states={"p2": GvmState(project_id="p2", status=GvmStatus.RUNNING)},
        github_hunt_states={}, supply_chain_states={}, trufflehog_states={},
        partial_recon_states={}, ai_attack_states={},
    )
    monkeypatch.setattr(api, "container_manager", fake)
    scans = {s["project_id"]: s for s in asyncio.run(api.system_active_scans())["scans"]}
    assert scans["p1"]["actor_user_id"] == "collab-1"
    assert scans["p2"]["actor_user_id"] is None
