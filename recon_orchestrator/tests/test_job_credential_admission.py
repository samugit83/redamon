"""
Job credentials at the orchestrator (step 1.16; NF-08, NF-16).

Every scan start carries the job credential the webapp minted for it. The
orchestrator verifies it, admits the scan under the credential's tenant (`ten`), not
the body's user_id, and hands it to the containers that call the webapp and the agent
back, as REDAMON_JOB_CREDENTIAL. Those containers get the scoped scanner key and never
the master key: with no scanner key configured the start is refused with 503
`scanner_key_missing`.
"""
import ast
import asyncio
import json
import logging
import os
import pathlib
import types
from pathlib import Path

import pytest
from fastapi import HTTPException

import api
import container_manager as cm
import job_credential as jc
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
from tests.job_credentials import KEYS, MASTER, job_credential, use_keys

ROOT = Path(__file__).resolve().parents[1]
VECTORS = json.loads((ROOT.parent / "tests" / "fixtures" / "machine_credential" / "vectors.json").read_text())


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
    # GVM and the GitHub hunt need recon output on disk; none here.
    monkeypatch.setattr(pathlib.Path, "exists", lambda self: True)
    use_keys(monkeypatch)
    return s


def _base(**kw):
    return {"project_id": "p1", "user_id": "u1", "webapp_api_url": "http://localhost:3000", **kw}


# (endpoint, request model, extra fields, does its container call back?)
STARTS = [
    ("start_recon", ReconStartRequest, {}, True),
    ("start_partial_recon", PartialReconStartRequest, {"tool_id": "Tlsx", "graph_inputs": {}}, True),
    ("start_gvm_scan", GvmStartRequest, {}, True),
    ("start_github_hunt", GithubHuntStartRequest, {}, True),
    ("start_supply_chain", SupplyChainStartRequest, {}, True),
    ("start_ai_attack_surface", AiAttackSurfaceStartRequest, {"roe_confirmed": True}, False),
    ("start_trufflehog", TrufflehogStartRequest, {"source": "docker"}, False),
]
IDS = [s[0] for s in STARTS]


def _start(endpoint, model, extra, **fields):
    req = model(**_base(**extra, **fields))
    return asyncio.run(getattr(api, endpoint)("p1", req))


def _refusal(endpoint, model, extra, **fields) -> HTTPException:
    with pytest.raises(HTTPException) as ei:
        _start(endpoint, model, extra, **fields)
    return ei.value


def _tenant_of(name, kw):
    return kw["config"]["user_id"] if name == "start_partial_recon" else kw["user_id"]


@pytest.mark.parametrize("endpoint,model,extra,calls_back", STARTS, ids=IDS)
def test_admission_counts_the_credentials_tenant(spy, endpoint, model, extra, calls_back):
    token = job_credential("p1", "u1")
    _start(endpoint, model, extra, job_credential=token)
    (name, kw), = spy.calls
    assert _tenant_of(name, kw) == "u1"
    # Only the containers that call the webapp and the agent back carry it.
    assert kw.get("job_credential") == (token if calls_back else None)


@pytest.mark.parametrize("endpoint,model,extra,calls_back", STARTS, ids=IDS)
def test_a_body_user_other_than_the_credentials_tenant_is_refused(spy, endpoint, model, extra, calls_back):
    err = _refusal(endpoint, model, extra, user_id="someone-else", job_credential=job_credential("p1", "u1"))
    assert err.status_code == 403
    assert err.detail["code"] == "job_credential_user_mismatch"
    assert spy.calls == []


@pytest.mark.parametrize("endpoint,model,extra,calls_back", STARTS, ids=IDS)
def test_invalid_credential_refused(spy, endpoint, model, extra, calls_back, caplog):
    cases = {
        "missing": None,
        "expired": job_credential("p1", "u1", exp_in=-1),
        "project_mismatch": job_credential("another-project", "u1"),
        "bad_signature": job_credential("p1", "u1", master="not-the-master-key"),
        "wrong_audience": job_credential("p1", "u1", aud="graph"),
        "malformed": "not-a-credential",
    }
    for code, token in cases.items():
        caplog.clear()
        with caplog.at_level(logging.WARNING):
            err = _refusal(endpoint, model, extra, job_credential=token)
        assert err.status_code == 403, code
        assert err.detail["code"] == f"job_credential_{code}"
        assert f"[rbac] job credential refused reason={code} project=p1" in caplog.text
    assert spy.calls == []


@pytest.mark.parametrize("endpoint,model,extra,calls_back", STARTS, ids=IDS)
def test_a_weak_master_key_cannot_verify_and_answers_503(spy, monkeypatch, endpoint, model, extra, calls_back):
    for weak in ("", "changeme"):
        monkeypatch.setenv("INTERNAL_API_KEY", weak)
        err = _refusal(endpoint, model, extra, job_credential=job_credential("p1", "u1"))
        assert err.status_code == 503
        assert err.detail["code"] == "job_credential_unverifiable"
    assert spy.calls == []


@pytest.mark.parametrize("endpoint,model,extra,calls_back", STARTS, ids=IDS)
def test_a_weak_master_key_answers_503_with_its_remedy_when_no_credential_came(spy, monkeypatch, endpoint, model,
                                                                               extra, calls_back):
    # The real case: the webapp of a stack whose INTERNAL_API_KEY was never generated
    # mints nothing, so its starts arrive with no credential at all.
    for weak in ("", "changeme"):
        monkeypatch.setenv("INTERNAL_API_KEY", weak)
        err = _refusal(endpoint, model, extra)
        assert err.status_code == 503
        assert err.detail["code"] == "job_credential_unverifiable"
        assert "./redamon.sh update" in err.detail["detail"]
    assert spy.calls == []


@pytest.mark.parametrize("endpoint,model,extra,calls_back", STARTS, ids=IDS)
def test_the_start_runs_under_the_tenant_job_tenant_returns_never_the_body_user(spy, monkeypatch, endpoint, model,
                                                                                extra, calls_back):
    # A body user other than `ten` is refused (above), so the two can only be told apart
    # at _job_tenant's answer: whatever it returns is what admission and the container
    # get, never request.user_id.
    real = api._job_tenant
    verified = []

    def tenant_differs(project_id, request, *, calls_back):
        verified.append(real(project_id, request, calls_back=calls_back))
        return "tenant-from-the-credential"

    monkeypatch.setattr(api, "_job_tenant", tenant_differs)
    _start(endpoint, model, extra, job_credential=job_credential("p1", "u1"))
    (name, kw), = spy.calls
    assert verified == ["u1"]
    assert _tenant_of(name, kw) == "tenant-from-the-credential"


@pytest.mark.parametrize("endpoint,model,extra,calls_back", STARTS, ids=IDS)
def test_no_scanner_key_means_a_503_for_the_scans_that_call_back(spy, monkeypatch, endpoint, model, extra,
                                                                 calls_back, caplog):
    for missing in ("", "changeme"):
        monkeypatch.setenv("SCANNER_API_KEY", missing)
        spy.calls.clear()
        caplog.clear()
        if not calls_back:
            _start(endpoint, model, extra, job_credential=job_credential("p1", "u1"))
            assert len(spy.calls) == 1
            continue
        with caplog.at_level(logging.ERROR):
            err = _refusal(endpoint, model, extra, job_credential=job_credential("p1", "u1"))
        assert err.status_code == 503
        assert err.detail["code"] == "scanner_key_missing"
        assert "[rbac] scanner key missing: run ./redamon.sh update to generate it" in caplog.text
        assert spy.calls == []


def test_the_shared_vectors_verify_here(monkeypatch):
    monkeypatch.setenv("INTERNAL_API_KEY", VECTORS["master"])
    for v in VECTORS["vectors"]:
        if v["label"] == "job":
            claims = jc.verify_job_credential(v["token"], v["claims"]["pid"], now=1_800_000_000)
            assert claims == v["claims"]


# ---------------------------------------------------------------------------
# The containers
# ---------------------------------------------------------------------------

def test_no_scanner_key_means_no_key_at_all_never_the_master_key(monkeypatch):
    m = cm.ContainerManager.__new__(cm.ContainerManager)
    monkeypatch.setenv("INTERNAL_API_KEY", MASTER)
    for missing in (None, "", "changeme"):
        if missing is None:
            monkeypatch.delenv("SCANNER_API_KEY", raising=False)
        else:
            monkeypatch.setenv("SCANNER_API_KEY", missing)
        assert m._scanner_env() == {}
    monkeypatch.setenv("SCANNER_API_KEY", KEYS["SCANNER_API_KEY"])
    assert m._scanner_env() == {"SCANNER_API_KEY": KEYS["SCANNER_API_KEY"]}


def test_the_job_env_carries_the_credential_only_when_there_is_one():
    assert cm.ContainerManager._job_env("tok.sig") == {"REDAMON_JOB_CREDENTIAL": "tok.sig"}
    assert cm.ContainerManager._job_env(None) == {}
    assert cm.ContainerManager._job_env("") == {}


def _spawn_recon(monkeypatch, job_credential_value):
    """start_recon with docker intercepted; the containers.run kwargs."""
    from concurrent.futures import ThreadPoolExecutor

    from models import ReconState

    use_keys(monkeypatch)
    mgr = cm.ContainerManager.__new__(cm.ContainerManager)
    calls = []

    class _Containers:
        def get(self, name):
            raise cm.NotFound(name)

        def run(self, image, **kw):
            calls.append(kw)
            return types.SimpleNamespace(id="container123")

    mgr.client = types.SimpleNamespace(containers=_Containers(), images=types.SimpleNamespace(get=lambda i: None))
    mgr._docker_op_executor = ThreadPoolExecutor(max_workers=2)
    mgr.supply_chain_osv_db_volume = "redamon-osv-db"
    mgr.sca_intel_volume = "redamon-sca-intel"
    mgr.recon_image = "redamon-recon:latest"
    mgr.running_states = {}
    mgr.partial_recon_states = {}

    async def _idle(pid):
        return ReconState(project_id=pid, status=ReconStatus.IDLE)

    async def _admit(*a, **kw):
        return "key"

    async def _noop(*a, **kw):
        return None

    mgr.get_status = _idle
    mgr._count_active_partial_recons = lambda pid: 0
    mgr._admit_scan = _admit
    mgr.ensure_osv_db_fresh_async = _noop
    mgr.ensure_sca_intel_fresh_async = _noop
    mgr._get_container_name = lambda pid: f"redamon-recon-{pid}"
    mgr._scanner_hardening = lambda drop_caps=True: {}
    mgr._container_mem_limit = lambda kind: None
    mgr._container_pids_limit = lambda: None
    mgr._container_cpu_limit = lambda: None
    state = asyncio.run(mgr.start_recon(project_id="p1", user_id="u1", webapp_api_url="http://webapp:3000",
                                        recon_path="/app/recon", job_credential=job_credential_value))
    assert state.status == ReconStatus.RUNNING, state.error
    return calls[0]["environment"]


def test_the_container_env_carries_the_credential(monkeypatch):
    env = _spawn_recon(monkeypatch, "tok.sig")
    assert env["REDAMON_JOB_CREDENTIAL"] == "tok.sig"
    assert env["SCANNER_API_KEY"] == KEYS["SCANNER_API_KEY"]
    assert "INTERNAL_API_KEY" not in env
    assert MASTER not in env.values()


def _run_env_sites():
    """Each container spawn in container_manager.py (any call given an `environment=`
    dict: containers.run, or functools.partial of it): (enclosing method, the
    expressions its environment dict splats in)."""
    tree = ast.parse((ROOT / "container_manager.py").read_text())
    sites = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for node in ast.walk(fn):
            if not isinstance(node, ast.Call):
                continue
            env = next((k.value for k in node.keywords if k.arg == "environment"), None)
            if not isinstance(env, ast.Dict):
                continue
            splats = {ast.unparse(v) for k, v in zip(env.keys, env.values) if k is None}
            sites.append((fn.name, splats))
    return sites


def test_only_the_containers_that_call_back_get_the_scanner_key_and_each_its_credential():
    sites = [(fn, s) for fn, s in _run_env_sites() if "self._scanner_env()" in s]
    by_fn = {fn: s for fn, s in sites}
    # The AI attack run calls nothing back, so it holds neither: the bare key would
    # still sign a `source=recon` capture tag for any tenant.
    assert set(by_fn) == {"start_recon", "start_partial_recon", "start_gvm_scan", "start_github_hunt",
                          "start_supply_chain"}
    for fn, splats in by_fn.items():
        assert "self._job_env(job_credential)" in splats, fn


def test_the_ai_attack_container_gets_no_scanner_key_and_no_credential(monkeypatch):
    from unittest.mock import MagicMock, patch

    use_keys(monkeypatch)
    with patch("container_manager.docker") as md:
        md.from_env.return_value = MagicMock()
        mgr = cm.ContainerManager()
    mgr.client = MagicMock()
    mgr.client.containers.run.return_value = types.SimpleNamespace(id="c0ffee")
    mgr.local_llm_manager = None
    state = asyncio.run(mgr.start_ai_attack_surface(
        project_id="p1", user_id="u1", webapp_api_url="http://webapp:3000",
        run_config={"tool": "skeleton", "targets": [], "bounds": {}, "roe_confirmed": True, "dry_run": True},
        ai_attack_path="/host/ai_attack_surface_scan"))
    assert state.error is None
    env = mgr.client.containers.run.call_args.kwargs["environment"]
    assert env["PROJECT_ID"] == "p1"
    for absent in ("SCANNER_API_KEY", "INTERNAL_API_KEY", "REDAMON_JOB_CREDENTIAL"):
        assert absent not in env
    assert not {KEYS["SCANNER_API_KEY"], MASTER} & set(env.values())


def test_no_spawn_hands_out_the_master_key_except_the_capture_proxy():
    text = (ROOT / "container_manager.py").read_text()
    tree = ast.parse(text)
    holders = set()
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            src = ast.get_source_segment(text, fn) or ""
            if '"INTERNAL_API_KEY":' in src:
                holders.add(fn.name)
    # The capture proxy is a long-lived service of the orchestrator, not a scan.
    assert holders == {"start_capture_proxy"}
