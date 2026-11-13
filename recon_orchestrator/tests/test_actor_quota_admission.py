"""
The actor's scan quota (step 6.8, GV-10).

The webapp sends `actor_max_concurrent` beside step 5.5's `actor_user_id` when the person who
started the scan has a maxConcurrentScans quota. Admission keeps one per-user ceiling, the actor's,
and makes it the smaller of the quota and RECON_MAX_CONCURRENT_PER_USER: a quota only ever tightens
the operator's cap. A refusal by the quota names `maxConcurrentScans` (the webapp words it as a quota,
not a restart knob). The quota is an administrator's rule, so it applies with the memory governor off
as well. A start without the field (an unlimited actor, the governance switch off, an older webapp)
is admitted exactly as before.
"""
import asyncio
import types
from unittest.mock import MagicMock

import pytest

import api
import container_manager as cm
from admission_ledger import AdmissionError, ReservationLedger
from models import (
    AiAttackSurfaceStartRequest,
    GithubHuntStartRequest,
    GvmStartRequest,
    PartialReconStartRequest,
    PartialReconStatus,
    ReconStartRequest,
    ReconStatus,
    SupplyChainStartRequest,
    TrufflehogStartRequest,
)
from tests.job_credentials import job_credential, use_keys
from tests.test_actor_admission import MANAGER_STARTS, MANAGER_IDS, _manager, _start_kwargs, _Reached

GB = 1024 ** 3


# ---------------------------------------------------------------------------
# The API: the quota travels with the actor to every start
# ---------------------------------------------------------------------------

class _Spy:
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
    import pathlib
    s = _Spy()
    monkeypatch.setattr(api, "container_manager", s)
    monkeypatch.setattr(api, "_fetch_project_for_preflight", lambda pid, **k: {"targetDomain": "example.com"})
    monkeypatch.setattr(api, "AI_ATTACK_SURFACE_PATH", "/host/ai_attack_surface_scan")
    monkeypatch.setattr(pathlib.Path, "exists", lambda self: True)
    use_keys(monkeypatch)
    return s


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


@pytest.mark.parametrize("endpoint,model,extra", STARTS, ids=IDS)
def test_the_quota_reaches_each_start_beside_the_actor(spy, endpoint, model, extra):
    _start(endpoint, model, extra, actor_user_id="collab-1", actor_max_concurrent=2)
    (_name, kw), = spy.calls
    assert kw["actor_user_id"] == "collab-1"
    assert kw["actor_max_concurrent"] == 2


@pytest.mark.parametrize("endpoint,model,extra", STARTS, ids=IDS)
def test_no_quota_sent_means_none(spy, endpoint, model, extra):
    _start(endpoint, model, extra, actor_user_id="collab-1")
    (_name, kw), = spy.calls
    assert kw["actor_max_concurrent"] is None


@pytest.mark.parametrize("model", [s[1] for s in STARTS], ids=IDS)
def test_a_negative_quota_is_refused_by_the_model(model):
    with pytest.raises(Exception):
        model(project_id="p1", user_id="owner-1", webapp_api_url="http://x", actor_max_concurrent=-1,
              **({"tool_id": "Tlsx"} if model is PartialReconStartRequest else {}),
              **({"source": "docker"} if model is TrufflehogStartRequest else {}))


# ---------------------------------------------------------------------------
# The container manager: each start hands the quota to admission with the actor
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("kind,state_cls", MANAGER_STARTS, ids=MANAGER_IDS)
def test_each_start_admits_its_actor_with_the_quota(kind, state_cls):
    from unittest.mock import patch
    m = _manager()
    admitted = []

    async def recording_admit(k, pid, run_id=None, user_id=None, max_per_user=None):
        admitted.append((user_id, max_per_user))
        raise _Reached()

    m._admit_scan = recording_admit
    with patch.object(cm, "classify_host", return_value=(True, "93.184.216.34", "ok")):
        with pytest.raises(_Reached):
            asyncio.run(getattr(m, kind)(**_start_kwargs(kind, "p1", "owner-1", "collab-1"), actor_max_concurrent=1))
    assert admitted == [("collab-1", 1)]


# ---------------------------------------------------------------------------
# The ledger: one per-user ceiling, the smaller of the quota and the env cap
# ---------------------------------------------------------------------------

@pytest.fixture
def roomy(monkeypatch):
    for name in ("RECON_MAX_CONCURRENT_GLOBAL", "RECON_MAX_CONCURRENT_PER_USER"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("REDAMON_MEM_GOVERNOR", "true")
    monkeypatch.setenv("RECON_JOB_ENVELOPE_MEM", "64m")
    monkeypatch.setenv("OS_HEADROOM_MEM", "1g")
    monkeypatch.setenv("SERVICE_BASELINE_MEM", "1g")
    return ReservationLedger(mem_reader=lambda: (64 * GB, 60 * GB), pressure_fn=lambda: "none")


def _admit(ledger, key, user, quota=None):
    return asyncio.run(ledger.try_admit(key, 64 * 1024 ** 2, user_id=user, max_per_user=quota))


def test_scan_cap_passed_and_applied_the_quota_below_the_env_cap_refuses(roomy, monkeypatch):
    monkeypatch.setenv("RECON_MAX_CONCURRENT_PER_USER", "5")
    assert _admit(roomy, "gvm:p1", "collab", 2).admitted
    assert _admit(roomy, "github_hunt:p2", "collab", 2).admitted
    refused = _admit(roomy, "supply_chain:p3", "collab", 2)
    assert not refused.admitted
    assert refused.limit_type == "hard"
    assert refused.setting_name == "maxConcurrentScans"
    assert (refused.current, refused.ceiling) == (2, 2)
    assert "quota" in refused.detail
    # Another person is not counted against it.
    assert _admit(roomy, "supply_chain:p4", "other", 2).admitted


def test_the_env_cap_below_the_quota_still_decides(roomy, monkeypatch):
    monkeypatch.setenv("RECON_MAX_CONCURRENT_PER_USER", "1")
    assert _admit(roomy, "gvm:p1", "collab", 3).admitted
    refused = _admit(roomy, "github_hunt:p2", "collab", 3)
    assert not refused.admitted
    assert refused.setting_name == "RECON_MAX_CONCURRENT_PER_USER"


def test_a_quota_of_zero_refuses_the_first_scan(roomy):
    refused = _admit(roomy, "gvm:p1", "collab", 0)
    assert not refused.admitted
    assert refused.setting_name == "maxConcurrentScans"


def test_no_quota_is_the_env_cap_alone(roomy, monkeypatch):
    monkeypatch.setenv("RECON_MAX_CONCURRENT_PER_USER", "2")
    assert _admit(roomy, "gvm:p1", "collab").admitted
    assert _admit(roomy, "github_hunt:p2", "collab").admitted
    assert _admit(roomy, "supply_chain:p3", "collab").setting_name == "RECON_MAX_CONCURRENT_PER_USER"


def test_re_admitting_a_running_key_is_not_a_new_scan(roomy):
    assert _admit(roomy, "gvm:p1", "collab", 1).admitted
    assert _admit(roomy, "gvm:p1", "collab", 1).admitted
    assert roomy.user_active_count("collab") == 1


def test_a_released_scan_frees_its_slot(roomy):
    assert _admit(roomy, "gvm:p1", "collab", 1).admitted
    assert not _admit(roomy, "gvm:p2", "collab", 1).admitted
    asyncio.run(roomy.release("gvm:p1"))
    assert _admit(roomy, "gvm:p2", "collab", 1).admitted


def test_the_quota_applies_with_the_governor_off(monkeypatch):
    monkeypatch.setenv("REDAMON_MEM_GOVERNOR", "false")
    monkeypatch.setenv("RECON_MAX_CONCURRENT_PER_USER", "1")
    ledger = ReservationLedger(mem_reader=lambda: None, pressure_fn=lambda: "critical")
    assert _admit(ledger, "gvm:p1", "collab", 1).admitted
    assert _admit(ledger, "gvm:p1", "collab", 1).admitted  # idempotent
    refused = _admit(ledger, "gvm:p2", "collab", 1)
    assert not refused.admitted and refused.setting_name == "maxConcurrentScans"
    # Without a quota the governor-off ledger admits as before (the env cap is the governor's).
    assert _admit(ledger, "gvm:p3", "collab").admitted


def test_admit_scan_raises_the_quota_refusal_for_the_api(roomy):
    m = _manager(roomy)
    asyncio.run(m._admit_scan("gvm", "p1", user_id="collab", max_per_user=1))
    with pytest.raises(AdmissionError) as ei:
        asyncio.run(m._admit_scan("github_hunt", "p2", user_id="collab", max_per_user=1))
    assert ei.value.result.payload()["settingName"] == "maxConcurrentScans"
