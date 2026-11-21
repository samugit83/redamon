"""
Per-user Kali sandboxes: the orchestrator's routes, its start-up wiring and the
capture proxy on sandbox networks (group 1: S7, E4, E3; B.9, TD-23..25).

The image has no httpx (so no TestClient): requests are driven straight through
the ASGI app (`asgi` below), so the key middleware and the route order are the
real ones. The manager behind the routes is either a stub that records its calls
or the real SandboxManager on the in-memory FakeDocker of
test_sandbox_manager_lifecycle.py. Every test sets KALI_SANDBOX_MODE explicitly.
"""
import asyncio
import json
import logging
import uuid
from types import SimpleNamespace
from unittest import mock
from unittest.mock import MagicMock, patch

import pytest

import api
import container_manager as cm
import sandbox_contract as sc
import sandbox_manager as sm
from admission_ledger import AdmissionResult
from tests import test_sandbox_manager_lifecycle as lc
from tests.test_sandbox_manager_lifecycle import (  # noqa: F401 - env and world are fixtures
    ALICE, BOB, GB, HOST_BASES, connects_to, env, fast_sleep, settle, world)

KEY = "orchestrator-test-key"
LEASE_ID = "0b6f7c1e-8a3d-4c2b-9e4f-1a2b3c4d5e6f"
POOL = sc.SUBNET_POOL


@pytest.fixture(autouse=True)
def engine_fidelity(monkeypatch):
    """An endpoint reports the GwPriority it was attached with, as the engine does,
    so a forced guest check does not re-attach a guest that is already right."""
    def attach(self, container, endpoint_config):
        self.endpoints[container.id] = dict(endpoint_config)
        self.attrs["Containers"][container.id] = {"Name": container.name}
        container.attrs["NetworkSettings"]["Networks"][self.name] = {
            "Aliases": endpoint_config.get("Aliases"),
            "GwPriority": endpoint_config.get("GwPriority", 0)}
    monkeypatch.setattr(lc.FakeNetwork, "_attach", attach)


@pytest.fixture
def served(monkeypatch):
    """The API as it serves once start-up is done: the key set, the manager adopted."""
    monkeypatch.setattr(api, "ORCHESTRATOR_API_KEY", KEY)
    monkeypatch.setattr(api, "sandbox_manager", None)
    monkeypatch.setattr(api, "_sandboxes_adopted", True)

    def use(manager):
        monkeypatch.setattr(api, "sandbox_manager", manager)
        return manager
    return use


async def asgi(method, path, body=None, key=KEY):
    """One request through the ASGI app; (status, decoded JSON or None)."""
    raw = b"" if body is None else json.dumps(body).encode()
    headers = [(b"content-type", b"application/json")]
    if key is not None:
        headers.append((b"x-orchestrator-key", key.encode()))
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
             "method": method, "scheme": "http", "path": path, "raw_path": path.encode(),
             "query_string": b"", "root_path": "", "headers": headers,
             "client": ("127.0.0.1", 40000), "server": ("orchestrator", 8010)}
    pending = [{"type": "http.request", "body": raw, "more_body": False}]

    async def receive():
        if pending:
            return pending.pop(0)
        await asyncio.Event().wait()

    sent = []

    async def send(message):
        sent.append(message)

    await api.app(scope, receive, send)
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    data = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return status, (json.loads(data) if data else None)


class StubManager:
    """Records every call; answers what a test sets."""

    def __init__(self, mode=sc.MODE_PER_USER):
        self._mode = mode
        self.calls = []
        self.raises = None
        self.answer = None

    def mode(self):
        return self._mode

    async def _do(self, name, *args, **kw):
        self.calls.append((name, args, kw))
        if self.raises is not None:
            raise self.raises
        return self.answer

    async def ensure(self, *a, **kw):
        if self._mode == sc.MODE_SHARED and self.raises is None:
            self.calls.append(("ensure", a, kw))
            return {"mode": sc.MODE_SHARED}
        return await self._do("ensure", *a, **kw)

    async def lease(self, *a, **kw):
        return await self._do("lease", *a, **kw)

    async def release_lease(self, *a, **kw):
        return await self._do("release_lease", *a, **kw)

    async def reconcile(self, *a, **kw):
        return await self._do("reconcile", *a, **kw)

    async def stop_user(self, *a, **kw):
        return await self._do("stop_user", *a, **kw)

    async def stop_project(self, *a, **kw):
        return await self._do("stop_project", *a, **kw)

    async def stop_all(self, *a, **kw):
        return await self._do("stop_all", *a, **kw)

    def status(self, user_id):
        self.calls.append(("status", (user_id,), {}))
        return {"mode": self._mode, "instances": []}

    def list_running(self):
        self.calls.append(("list_running", (), {}))
        return []


ENSURE_BODY = {"user_id": ALICE, "view": "own", "projects": ["projA"], "need_project": None,
               "wait": True, "touch": False}
# Every sandbox route of B.9, and a path under /sandboxes/ that no route matches.
ROUTES = [
    ("GET", "/sandboxes/mode", None),
    ("GET", "/sandboxes", None),
    ("POST", "/sandboxes/ensure", ENSURE_BODY),
    ("POST", "/sandboxes/stop-project", {"project_id": "projA", "reason": "project_deleted"}),
    ("POST", "/sandboxes/stop-all", {"reason": "emergency"}),
    ("GET", f"/sandboxes/{ALICE}", None),
    ("POST", f"/sandboxes/{ALICE}/leases", {"instance": "abc123", "lease_id": LEASE_ID, "kind": "run"}),
    ("DELETE", f"/sandboxes/{ALICE}/leases/{LEASE_ID}", None),
    ("POST", f"/sandboxes/{ALICE}/reconcile", {"projects": [], "act_as_projects": []}),
    ("POST", f"/sandboxes/{ALICE}/stop", {"reason": "operator"}),
    ("POST", "/sandboxes/a/b/stop", {"reason": "operator"}),
]


# --- The key and the routes -------------------------------------------------------

@pytest.mark.parametrize("method,path,body", ROUTES, ids=[f"{m} {p}" for m, p, _ in ROUTES])
@pytest.mark.parametrize("key", [None, "", "wrong-key"], ids=["no_key", "empty_key", "wrong_key"])
async def test_every_sandbox_route_refuses_without_the_orchestrator_key(served, method, path, body, key):
    stub = served(StubManager())
    status, answer = await asgi(method, path, body, key=key)
    assert status == 401
    assert "token" not in json.dumps(answer)
    assert stub.calls == []


def test_every_contract_route_is_declared_and_mode_before_status():
    declared = [(r.path, sorted(r.methods or ())) for r in api.app.routes if hasattr(r, "methods")]
    paths = [p for p, _ in declared]
    expected = {
        sc.ROUTE_ENSURE: ["POST"], sc.ROUTE_LEASES: ["POST"], sc.ROUTE_LEASE: ["DELETE"],
        sc.ROUTE_RECONCILE: ["POST"], sc.ROUTE_STOP_USER: ["POST"], sc.ROUTE_STOP_PROJECT: ["POST"],
        sc.ROUTE_STOP_ALL: ["POST"], sc.ROUTE_STATUS: ["GET"], sc.ROUTE_LIST: ["GET"],
        sc.ROUTE_MODE: ["GET"],
    }
    for route, methods in expected.items():
        assert any(p == route and set(methods) <= set(m) for p, m in declared), route
    # GET /sandboxes/mode would otherwise be GET /sandboxes/{user_id} with user_id "mode".
    assert paths.index(sc.ROUTE_MODE) < paths.index(sc.ROUTE_STATUS)


@pytest.mark.parametrize("mode", [sc.MODE_SHARED, sc.MODE_PER_USER])
async def test_mode_route_answers_only_the_mode(served, env, mode):
    env.setenv(sc.MODE_ENV, mode)
    stub = served(StubManager(mode))
    status, answer = await asgi("GET", "/sandboxes/mode")
    assert (status, answer) == (200, {"mode": mode})
    assert stub.calls == []


async def test_mode_route_answers_before_adoption_and_without_a_manager(served, env, monkeypatch):
    env.setenv(sc.MODE_ENV, sc.MODE_PER_USER)
    monkeypatch.setattr(api, "_sandboxes_adopted", False)
    assert await asgi("GET", "/sandboxes/mode") == (200, {"mode": sc.MODE_PER_USER})


# --- ensure -----------------------------------------------------------------------

async def test_ensure_passes_the_request_to_the_manager(served, env):
    stub = served(StubManager())
    stub.answer = {"mode": sc.MODE_PER_USER, "state": "starting", "instance": "abc123", "fresh": True}
    body = dict(ENSURE_BODY, view="act_as", need_project="projA", wait=False, touch=True)
    status, answer = await asgi("POST", "/sandboxes/ensure", body)
    assert status == 202 and answer == stub.answer
    name, args, kw = stub.calls[0]
    assert name == "ensure" and args == (ALICE, ["projA"])
    assert kw == {"view": "act_as", "need_project": "projA", "wait": False, "touch": True}


async def test_ensure_running_answers_200(served, env):
    stub = served(StubManager())
    stub.answer = {"mode": sc.MODE_PER_USER, "state": "running", "instance": "abc123", "fresh": False}
    status, answer = await asgi("POST", "/sandboxes/ensure", ENSURE_BODY)
    assert status == 200 and answer["state"] == "running"


async def test_ensure_in_shared_mode_answers_the_mode_even_before_adoption(served, env, monkeypatch):
    env.setenv(sc.MODE_ENV, sc.MODE_SHARED)
    monkeypatch.setattr(api, "_sandboxes_adopted", False)
    served(StubManager(sc.MODE_SHARED))
    assert await asgi("POST", "/sandboxes/ensure", ENSURE_BODY) == (200, {"mode": sc.MODE_SHARED})


@pytest.mark.parametrize("limit", ["ram", "hard"])
async def test_ensure_refusal_409_carries_the_payload_and_code(served, env, limit):
    stub = served(StubManager())
    result = AdmissionResult(False, limit_type=limit, resource=sc.RESOURCE, current=2, ceiling=2,
                             setting_name=sc.MAX_CONCURRENT_SETTING if limit == "hard" else None,
                             detail="not enough free memory to start a sandbox")
    stub.raises = sm.SandboxRefused(result)
    status, answer = await asgi("POST", "/sandboxes/ensure", ENSURE_BODY)
    assert status == 409
    detail = answer["detail"]
    assert detail["code"] == sc.REFUSAL_CODE_BY_LIMIT[limit]
    assert {k: detail[k] for k in sc.LIMIT_PAYLOAD_KEYS} == result.payload()


@pytest.mark.parametrize("code,status", [(sc.ERR_IMAGE_MISSING, 503), (sc.ERR_START_FAILED, 503),
                                         (sc.ERR_START_TIMEOUT, 504)])
async def test_ensure_start_errors_answer_503_or_504_with_the_code(served, env, code, status):
    stub = served(StubManager())
    stub.raises = sm.SandboxStartError(code, "the sandbox could not be created")
    got, answer = await asgi("POST", "/sandboxes/ensure", ENSURE_BODY)
    assert got == status and answer["detail"]["code"] == code


@pytest.mark.parametrize("change,code", [
    ({"user_id": "bad/user"}, sc.ERR_INVALID_USER_ID),
    ({"user_id": "mode"}, sc.ERR_INVALID_USER_ID),
    ({"view": "root"}, sc.ERR_INVALID_VIEW),
    ({"projects": ["../etc"]}, sc.ERR_INVALID_PROJECT_ID),
    ({"projects": [".staging"]}, sc.ERR_INVALID_PROJECT_ID),
    ({"need_project": "projB"}, sc.ERR_INVALID_PROJECT_ID),
], ids=["user", "reserved_user", "view", "dotdot", "staging", "need_not_listed"])
async def test_ensure_invalid_id_or_view_answers_400_with_the_code(served, world, change, code):
    served(world.mgr)
    status, answer = await asgi("POST", "/sandboxes/ensure", dict(ENSURE_BODY, **change))
    assert status == 400 and answer["detail"]["code"] == code
    assert world.d.mutations() == [] and world.ledger.sandbox_keys() == set()


# --- Status, list, leases, stops ------------------------------------------------------

async def test_list_carries_tokens_and_status_never_does(served, world):
    served(world.mgr)
    status, ens = await asgi("POST", "/sandboxes/ensure", ENSURE_BODY)
    assert status == 200 and ens["state"] == "running"
    status, listed = await asgi("GET", "/sandboxes")
    assert status == 200 and listed["mode"] == sc.MODE_PER_USER
    assert [s["token"] for s in listed["sandboxes"]] == [ens["token"]]
    assert listed["sandboxes"][0]["host"] == ens["host"]
    status, mine = await asgi("GET", f"/sandboxes/{ALICE}")
    assert status == 200 and [i["instance"] for i in mine["instances"]] == [ens["instance"]]
    text = json.dumps(mine)
    assert ens["token"] not in text and ens["tunnel_token"] not in text and "token" not in text


@pytest.mark.parametrize("user_id", ["mode", "ensure", "stop-all", "a.b", "x" * 65])
async def test_status_of_an_invalid_user_id_answers_400(served, world, user_id):
    served(world.mgr)
    status, answer = await asgi("GET", f"/sandboxes/{user_id}")
    if user_id == "mode":
        assert status == 200 and set(answer) == {"mode"}      # the mode route, matched first
    else:
        assert status == 400 and answer["detail"]["code"] == sc.ERR_INVALID_USER_ID


async def test_stop_project_reaches_the_manager(served, world):
    served(world.mgr)
    a = (await asgi("POST", "/sandboxes/ensure", dict(ENSURE_BODY, projects=["projA"])))[1]
    b = (await asgi("POST", "/sandboxes/ensure", dict(ENSURE_BODY, user_id=BOB, projects=["projB"])))[1]
    status, answer = await asgi("POST", "/sandboxes/stop-project",
                                {"project_id": "projA", "reason": "project_deleted"})
    assert (status, answer) == (200, {"stopped": 1})
    assert [c.name for c in world.created()] == [b["host"]]
    assert world.mgr.get_instance(ALICE, a["instance"]) is None
    status, answer = await asgi("POST", "/sandboxes/stop-project",
                                {"project_id": "../projB", "reason": "project_deleted"})
    assert status == 400 and answer["detail"]["code"] == sc.ERR_INVALID_PROJECT_ID
    assert len(world.created()) == 1


async def test_stop_user_reconcile_and_stop_all(served, world):
    served(world.mgr)
    await asgi("POST", "/sandboxes/ensure", ENSURE_BODY)
    await asgi("POST", "/sandboxes/ensure", dict(ENSURE_BODY, view="act_as", projects=[]))
    await asgi("POST", "/sandboxes/ensure", dict(ENSURE_BODY, user_id=BOB))
    status, answer = await asgi("POST", f"/sandboxes/{ALICE}/reconcile",
                                {"projects": ["projA"], "act_as_projects": ["projX"]})
    assert (status, answer) == (200, {"stopped": 0})
    status, answer = await asgi("POST", f"/sandboxes/{ALICE}/reconcile",
                                {"projects": [], "act_as_projects": []})
    assert (status, answer) == (200, {"stopped": 1})              # own lost projA; act_as had none
    assert await asgi("POST", f"/sandboxes/{ALICE}/stop", {"reason": "operator"}) == (200, {"stopped": 1})
    assert await asgi("POST", "/sandboxes/stop-all", {"reason": "emergency"}) == (200, {"stopped": 1})
    assert world.created() == []


@pytest.mark.parametrize("path,body", [
    (f"/sandboxes/{ALICE}/stop", {"reason": "because"}),
    ("/sandboxes/stop-all", {"reason": ""}),
    ("/sandboxes/stop-project", {"project_id": "projA", "reason": "deleted"}),
])
async def test_a_stop_with_an_unknown_reason_answers_400(served, world, path, body):
    served(world.mgr)
    await asgi("POST", "/sandboxes/ensure", ENSURE_BODY)
    status, answer = await asgi("POST", path, body)
    assert status == 400 and answer["detail"]["code"] == "invalid_stop_reason"
    assert len(world.created()) == 1


async def test_lease_and_release(served, world):
    served(world.mgr)
    ens = (await asgi("POST", "/sandboxes/ensure", ENSURE_BODY))[1]
    status, answer = await asgi("POST", f"/sandboxes/{ALICE}/leases",
                                {"instance": ens["instance"], "lease_id": LEASE_ID, "kind": "run"})
    assert status == 200 and set(answer) == {"expires_at", "state", "stop_at", "warn"}
    assert answer["state"] == "running"
    # Another person's instance is unknown to Bob, with the contract's code.
    status, answer = await asgi("POST", f"/sandboxes/{BOB}/leases",
                                {"instance": ens["instance"], "lease_id": str(uuid.uuid4()), "kind": "run"})
    assert status == 404 and answer["detail"]["code"] == sc.ERR_UNKNOWN_INSTANCE
    status, answer = await asgi("POST", f"/sandboxes/{ALICE}/leases",
                                {"instance": ens["instance"], "lease_id": "not-a-uuid", "kind": "run"})
    assert status == 400 and answer["detail"]["code"] == "invalid_sandbox_request"
    assert await asgi("DELETE", f"/sandboxes/{ALICE}/leases/{LEASE_ID}") == (204, None)
    assert world.mgr.get_instance(ALICE, ens["instance"]).leases == {}


@pytest.mark.parametrize("method,path,body", [
    ("POST", "/sandboxes/a/b/stop", {"reason": "operator"}),
    ("POST", f"/sandboxes/{ALICE}/bogus", {}),
    ("DELETE", f"/sandboxes/{ALICE}/leases/a/b", None),
    ("GET", f"/sandboxes/{ALICE}/leases", None),
    ("PUT", "/sandboxes/ensure", {}),
    ("GET", "/sandboxes/", None),
])
async def test_every_404_under_sandboxes_carries_a_contract_code(served, world, method, path, body):
    """The webapp reads a 404 without a code as an orchestrator without the sandbox
    routes, and a stop then as 'nothing to stop'."""
    served(world.mgr)
    status, answer = await asgi(method, path, body)
    assert status == 404
    assert answer["detail"]["code"] == sc.ERR_UNKNOWN_INSTANCE


async def test_routes_outside_sandboxes_keep_their_404(served, world):
    served(world.mgr)
    assert await asgi("GET", "/no-such-route") == (404, {"detail": "Not Found"})


@pytest.mark.parametrize("method,path,body", [r for r in ROUTES if r[1] not in ("/sandboxes/mode",
                                                                              "/sandboxes/a/b/stop")])
async def test_routes_answer_503_until_adoption_has_finished(served, env, monkeypatch, method, path, body):
    stub = served(StubManager())
    monkeypatch.setattr(api, "_sandboxes_adopted", False)
    status, answer = await asgi(method, path, body)
    assert status == 503 and answer["detail"]["code"] == sc.ERR_START_FAILED
    assert stub.calls == []


async def test_routes_answer_503_without_a_manager(served, env):
    status, answer = await asgi("POST", "/sandboxes/ensure", ENSURE_BODY)
    assert status == 503 and answer["detail"]["code"] == sc.ERR_START_FAILED


async def test_system_stats_passes_the_sandbox_fields_through(world, monkeypatch):
    monkeypatch.setattr(api, "container_manager", SimpleNamespace(ledger=world.ledger))
    await world.mgr.ensure(ALICE, ["projA"])
    out = await api.system_stats()
    mem = out["mem"]
    assert mem[sc.STATS_ACTIVE_SANDBOXES] == 1
    assert mem[sc.STATS_SANDBOX_COMMITTED] == world.ledger.sandbox_committed_bytes() > 0
    assert mem[sc.STATS_SANDBOX_ENVELOPE] == world.ledger.sandbox_envelope()
    assert mem["active_scans"] == 0


# --- Missing host folders ---------------------------------------------------------

@pytest.mark.parametrize("missing,line", [
    (sc.MOUNT_WORKSPACE, "./agentic/agent-workspace:/app/agent-workspace"),
    (sc.MOUNT_OUTPUT, "./mcp/output:/app/mcp-output"),
    (sc.MOUNT_SERVERS, "./mcp/servers:/app/mcp-servers:ro"),
])
async def test_missing_host_mounts_answer_503_and_name_the_compose_mount(served, world, caplog, missing, line):
    bases = {k: v for k, v in HOST_BASES.items() if k != missing}
    mgr = sm.SandboxManager(world.d, world.ledger, bases, "redamon-osv-db", "redamon",
                            clock=world.clock, cpu_count=lambda: 12, local_bases=world.local,
                            sleep=fast_sleep, start_timeout_s=3)
    served(mgr)
    caplog.set_level(logging.INFO, logger="sandbox_manager")
    status, answer = await asgi("POST", "/sandboxes/ensure", ENSURE_BODY)
    assert status == 503 and answer["detail"]["code"] == sc.ERR_START_FAILED
    assert line in caplog.text
    assert world.d.mutations() == [] and world.ledger.sandbox_keys() == set()
    assert mgr.reservation_keys() == set()
    # The answer names no host path.
    assert HOST_BASES[sc.MOUNT_OUTPUT] not in json.dumps(answer)


# --- Start-up: the manager, adoption, the idle loop ---------------------------------

def test_the_manager_is_built_from_the_orchestrator_mounts(monkeypatch):
    mounts = {"/app/agent-workspace": "/h/agentic/agent-workspace", "/app/mcp-output": "/h/mcp/output",
              "/app/mcp-servers": "/h/mcp/servers", "/app/recon": "/h/recon"}
    monkeypatch.setattr(api, "_host_mounts", mounts)
    monkeypatch.setattr(api, "GRAPH_DB_PATH", "/h/graph_db")
    monkeypatch.setattr(api, "CUSTOM_TEMPLATES_PATH", "/h/mcp/nuclei-templates")
    for name in ("AGENT_WORKSPACE_PATH", "HOST_WORKSPACE", "HOST_MCP_OUTPUT"):
        monkeypatch.setenv(name, "/elsewhere")
    fake_cm = SimpleNamespace(client=MagicMock(), ledger=MagicMock(), supply_chain_osv_db_volume="osv-vol")
    mgr = api._build_sandbox_manager(fake_cm, "myproj")
    assert isinstance(mgr, sm.SandboxManager)
    assert mgr.host_bases == {sc.MOUNT_WORKSPACE: "/h/agentic/agent-workspace", sc.MOUNT_OUTPUT: "/h/mcp/output",
                              sc.MOUNT_SERVERS: "/h/mcp/servers", sc.MOUNT_GRAPH_DB: "/h/graph_db",
                              sc.MOUNT_CUSTOM_TEMPLATES: "/h/mcp/nuclei-templates"}
    assert mgr.client is fake_cm.client and mgr.ledger is fake_cm.ledger
    assert mgr.osv_volume == "osv-vol" and mgr.own_compose_project == "myproj"
    # No environment fallback: without the compose mounts the kinds stay unknown.
    monkeypatch.setattr(api, "_host_mounts", {})
    bare = api._build_sandbox_manager(fake_cm, None)
    assert sc.MOUNT_WORKSPACE not in bare.host_bases and sc.MOUNT_OUTPUT not in bare.host_bases
    assert sc.MOUNT_SERVERS not in bare.host_bases


def test_own_compose_project_read_from_the_orchestrator_container():
    client = MagicMock()
    client.containers.get.return_value.labels = {sc.COMPOSE_PROJECT_LABEL: "redamon-b"}
    assert api._own_compose_project(client) == "redamon-b"
    client.containers.get.return_value.labels = {}
    assert api._own_compose_project(client) is None
    client.containers.get.side_effect = RuntimeError("no docker")
    assert api._own_compose_project(client) is None


class LifecycleManager:
    """A manager that records the order of start-up calls."""

    def __init__(self, fail_adoptions=0):
        self.events = []
        self.fail_adoptions = fail_adoptions
        self.adopted_flag_at_adopt = []
        self.idle_started = asyncio.Event()

    def mode(self):
        return sc.MODE_PER_USER

    def reservation_keys(self):
        return set()

    async def attach_capture_proxy_everywhere(self):
        return 0

    async def adopt(self):
        self.adopted_flag_at_adopt.append(api._sandboxes_adopted)
        self.events.append("adopt")
        if self.fail_adoptions:
            self.fail_adoptions -= 1
            raise RuntimeError("docker unreachable")
        return {"adopted": 0, "removed": 0, "networks_removed": 0}

    async def run_idle_loop(self, sleep=None):
        self.events.append("idle")
        self.idle_started.set()
        await asyncio.Event().wait()

    async def join_background(self):
        self.events.append("join")

    async def ensure(self, *a, **kw):
        self.events.append("ensure")
        return {"mode": sc.MODE_PER_USER, "state": "running"}


@pytest.fixture
def lifespan_env(monkeypatch):
    """The lifespan with every other service of the orchestrator stubbed."""
    fake_cm = SimpleNamespace(client=MagicMock(), ledger=MagicMock(), supply_chain_osv_db_volume="osv")

    async def _run_blocking(fn, *a, **kw):
        return None

    async def cleanup():
        return None

    fake_cm._run_blocking = _run_blocking
    fake_cm.sweep_trufflehog_stages = lambda: None
    fake_cm.cleanup = cleanup

    async def forever(*a, **kw):
        await asyncio.Event().wait()

    monkeypatch.setattr(api, "ContainerManager", lambda **kw: fake_cm)
    monkeypatch.setattr(api, "LocalLlmManager", lambda **kw: MagicMock())
    monkeypatch.setattr(api, "_ai_attack_reaper", forever)
    monkeypatch.setattr(api, "_capture_config_reconcile", forever)
    monkeypatch.setattr(api, "scan_scheduler_loop", forever)
    monkeypatch.setattr(api, "job_dispatcher_loop", forever)
    monkeypatch.setattr(api, "_own_compose_project", lambda client: "redamon")
    monkeypatch.setattr(api, "SANDBOX_ADOPT_RETRY_S", 0)
    monkeypatch.setattr(api, "ORCHESTRATOR_API_KEY", KEY)
    for name in ("container_manager", "local_llm_manager", "sandbox_manager", "_sandboxes_adopted"):
        monkeypatch.setattr(api, name, getattr(api, name))
    monkeypatch.setattr(api, "_sandboxes_adopted", False)

    def install(manager):
        monkeypatch.setattr(api, "_build_sandbox_manager", lambda cmgr, project: manager)
        return manager
    return SimpleNamespace(cm=fake_cm, install=install)


async def test_lifespan_adopts_once_before_serving_then_starts_the_idle_loop(lifespan_env, env):
    mgr = lifespan_env.install(LifecycleManager())
    async with api.lifespan(api.app):
        # Adoption finished before the app serves its first request.
        assert mgr.events[0] == "adopt" and api._sandboxes_adopted is True
        assert mgr.adopted_flag_at_adopt == [False]
        assert api.sandbox_manager is mgr
        assert lifespan_env.cm.extra_reservation_keys == mgr.reservation_keys
        assert lifespan_env.cm.on_capture_proxy_started == mgr.attach_capture_proxy_everywhere
        await asyncio.wait_for(mgr.idle_started.wait(), 2)
        status, _ = await asgi("POST", "/sandboxes/ensure", ENSURE_BODY)
        assert status == 200
    assert mgr.events.count("adopt") == 1 and mgr.events.count("idle") == 1
    assert mgr.events.index("adopt") < mgr.events.index("idle") < mgr.events.index("ensure")


async def test_failed_adoption_is_retried_and_routes_wait_for_it(lifespan_env, env, monkeypatch):
    mgr = lifespan_env.install(LifecycleManager(fail_adoptions=2))
    gate = asyncio.Event()
    real_sleep = asyncio.sleep

    async def held_sleep(seconds):
        await gate.wait()
        await real_sleep(0)
    monkeypatch.setattr(api, "_sandbox_retry_sleep", held_sleep)
    async with api.lifespan(api.app):
        assert api._sandboxes_adopted is False and mgr.events == ["adopt"]
        status, answer = await asgi("POST", "/sandboxes/ensure", ENSURE_BODY)
        assert status == 503 and answer["detail"]["code"] == sc.ERR_START_FAILED
        assert "ensure" not in mgr.events
        gate.set()
        await asyncio.wait_for(mgr.idle_started.wait(), 2)
        assert api._sandboxes_adopted is True
        assert await asgi("POST", "/sandboxes/ensure", ENSURE_BODY) == (200, {"mode": sc.MODE_PER_USER,
                                                                                "state": "running"})
    assert mgr.events.count("adopt") == 3 and mgr.events.count("idle") == 1
    assert mgr.events.index("idle") > 2


# --- The reaper hook (S02-F2) -----------------------------------------------------------

def _real_container_manager(ledger):
    with patch("container_manager.docker") as docker:
        docker.from_env.return_value = MagicMock()
        mgr = cm.ContainerManager()
    mgr.ledger = ledger
    return mgr


async def test_reaper_keeps_sandbox_keys_after_wiring(world):
    cmgr = _real_container_manager(world.ledger)
    api._wire_sandbox_manager(cmgr, world.mgr)
    assert cmgr.extra_reservation_keys == world.mgr.reservation_keys
    ans = await world.mgr.ensure(ALICE, ["projA"])
    live = sc.reservation_key(ALICE, ans["instance"])
    stale = sc.reservation_key(BOB, "dead00")
    world.ledger.account(stale, GB)
    world.ledger.account("gvm:finished", GB)
    assert cmgr.reconcile_reservations() == 2
    assert world.ledger.sandbox_keys() == {live}
    assert world.ledger.active_count() == 0


def _sbx(instance):
    return sc.reservation_key(ALICE, instance)


def test_reaper_hook_vouches_for_sandbox_keys_only(world):
    cmgr = _real_container_manager(world.ledger)
    cmgr.extra_reservation_keys = lambda: {_sbx("aaa111"), "gvm:finished", ("kali_sandbox:x",), 7}
    world.ledger.account(_sbx("aaa111"), GB)
    world.ledger.account("gvm:finished", GB)
    keys = cmgr._active_scan_keys()
    assert _sbx("aaa111") in keys and "gvm:finished" not in keys
    assert cmgr.reconcile_reservations() == 1
    assert world.ledger.sandbox_keys() == {_sbx("aaa111")} and world.ledger.active_count() == 0


def test_reaper_refuses_a_bare_string_and_keeps_every_sandbox_key(world, caplog):
    cmgr = _real_container_manager(world.ledger)
    cmgr.extra_reservation_keys = lambda: _sbx("aaa111")
    world.ledger.account(_sbx("aaa111"), GB)
    world.ledger.account(_sbx("bbb222"), GB)
    with caplog.at_level(logging.WARNING):
        cmgr.reconcile_reservations()
    assert world.ledger.sandbox_keys() == {_sbx("aaa111"), _sbx("bbb222")}
    assert "extra reservation keys" in caplog.text


def test_reaper_refuses_an_async_hook_without_leaking_a_coroutine(world, caplog, recwarn):
    cmgr = _real_container_manager(world.ledger)

    async def hook():
        return {_sbx("aaa111")}
    cmgr.extra_reservation_keys = hook
    world.ledger.account(_sbx("bbb222"), GB)
    with caplog.at_level(logging.WARNING):
        cmgr.reconcile_reservations()
    assert world.ledger.sandbox_keys() == {_sbx("bbb222")}
    assert "extra reservation keys" in caplog.text
    assert not [w for w in recwarn if "was never awaited" in str(w.message)]


# --- The capture proxy (TD-23, TD-24, TD-25) -----------------------------------------------

def _start_proxy(config, environ=None, hook=None):
    """start_capture_proxy, as most orchestrator tests build the manager (no
    __init__), with Docker intercepted: (proxy run kwargs, ingest run kwargs,
    the order of the runs and the hook)."""
    mgr = cm.ContainerManager.__new__(cm.ContainerManager)
    runs, events = [], []

    class _Containers:
        def run(self, image, **kw):
            runs.append(kw)
            events.append(("run", kw["name"]))
            return MagicMock()

    mgr.client = MagicMock()
    mgr.client.containers = _Containers()
    mgr._remove_container_if_exists = lambda name: None
    mgr._capture_image = lambda: "redamon-capture-proxy:latest"
    mgr._capture_port = lambda: 8888
    if hook is not None:
        mgr.on_capture_proxy_started = lambda: hook(events)

    async def _status():
        return {"running": True}
    mgr.capture_proxy_status = _status
    with mock.patch.dict("os.environ", {"CAPTURE_BLOCKED_IPS": ""} if environ is None else environ):
        asyncio.run(mgr.start_capture_proxy(config))
    by_name = {kw["name"]: kw for kw in runs}
    return (by_name[cm.ContainerManager.CAPTURE_PROXY_NAME],
            by_name[cm.ContainerManager.TRAFFIC_INGEST_NAME], events)


def _proxy_kwargs(config, environ=None):
    proxy, ingest, _ = _start_proxy(config, environ)
    return proxy, ingest


@pytest.mark.parametrize("config,environ,expected", [
    ({"blockedIps": "10.9.9.9,172.31.0.1"}, {"CAPTURE_BLOCKED_IPS": "192.0.2.7"}, f"10.9.9.9,172.31.0.1,{POOL}"),
    ({}, {"CAPTURE_BLOCKED_IPS": "192.0.2.7, 198.51.100.0/24"}, f"192.0.2.7,198.51.100.0/24,{POOL}"),
    ({}, {"CAPTURE_BLOCKED_IPS": ""}, POOL),
    ({"blockedIps": f"{POOL},10.9.9.9"}, {"CAPTURE_BLOCKED_IPS": ""}, f"{POOL},10.9.9.9"),
    ({}, {"CAPTURE_BLOCKED_IPS": f"10.214.0.0/16,,{POOL}"}, f"{POOL},{POOL}"),
], ids=["settings", "environment", "empty", "already_first", "already_twice"])
def test_capture_proxy_started_without_forwarding_and_blocks_sandbox_pool(config, environ, expected):
    proxy, ingest = _proxy_kwargs(config, environ)
    assert proxy["sysctls"] == {"net.ipv4.ip_forward": "0"}
    assert proxy["environment"]["CAPTURE_BLOCKED_IPS"] == expected
    # The egress guard runs on HTTP requests only: after a CONNECT, a stream that
    # is not HTTP would be relayed raw to any address, the sandbox pool included.
    cmd = proxy["command"]
    assert cmd[cmd.index("rawtcp=false") - 1] == "--set"
    assert not any("rawtcp=true" in part or part == "--rawtcp" for part in cmd)
    # The ingest joins no sandbox network and is left as it was.
    assert "sysctls" not in ingest and "CAPTURE_BLOCKED_IPS" not in ingest["environment"]
    # The manager's own check accepts what was started.
    started = SimpleNamespace(attrs={"Config": {"Env": [f"CAPTURE_BLOCKED_IPS={expected}"]},
                                     "HostConfig": {"Sysctls": proxy["sysctls"]}})
    assert sm.SandboxManager._missing_sysctls(started) == []
    assert sm.SandboxManager._proxy_refuses_pool(started) is True


def test_capture_proxy_hook_runs_right_after_the_proxy_starts():
    def hook(events):
        events.append(("hook",))

    *_, events = _start_proxy({}, hook=hook)
    assert events == [("run", cm.ContainerManager.CAPTURE_PROXY_NAME), ("hook",),
                      ("run", cm.ContainerManager.TRAFFIC_INGEST_NAME)]


def test_capture_proxy_async_hook_is_awaited_and_a_failure_never_fails_the_toggle(caplog):
    async def attach(events):
        await asyncio.sleep(0)
        events.append(("attached",))

    *_, events = _start_proxy({}, hook=attach)
    assert events == [("run", cm.ContainerManager.CAPTURE_PROXY_NAME), ("attached",),
                      ("run", cm.ContainerManager.TRAFFIC_INGEST_NAME)]

    def broken(events):
        raise RuntimeError("docker hiccup")

    with caplog.at_level(logging.WARNING):
        *_, events = _start_proxy({}, hook=broken)
    assert events[-1] == ("run", cm.ContainerManager.TRAFFIC_INGEST_NAME)
    assert "sandbox networks" in caplog.text


def test_container_manager_hooks_default_to_no_op():
    cmgr = _real_container_manager(MagicMock())
    assert cmgr.on_capture_proxy_started() is None
    assert set(cmgr.extra_reservation_keys()) == set()


def _recreate_proxy(world, **kw):
    world.proxy.remove(force=True)
    world.proxy = lc.add_proxy(world.d, **kw)
    return world.proxy


async def test_capture_proxy_and_agent_join_with_low_gateway_priority(served, world):
    """E4: both guests join every sandbox network at a gateway priority that keeps
    their default route where it was, the agent under the alias `agent` only; a
    proxy the orchestrator recreates is attached again at once."""
    served(world.mgr)
    cmgr = _real_container_manager(world.ledger)
    api._wire_sandbox_manager(cmgr, world.mgr)
    a = (await asgi("POST", "/sandboxes/ensure", ENSURE_BODY))[1]
    b = (await asgi("POST", "/sandboxes/ensure", dict(ENSURE_BODY, user_id=BOB)))[1]
    nets = [sc.network_name(ALICE, "own"), sc.network_name(BOB, "own")]
    for net in nets:
        eps = connects_to(world, net)
        assert eps[world.agent.id] == {"Aliases": [sc.AGENT_ALIAS], "GwPriority": sc.GUEST_GATEWAY_PRIORITY}
        assert eps[world.proxy.id] == {"GwPriority": sc.GUEST_GATEWAY_PRIORITY}
    new_proxy = _recreate_proxy(world)
    for net in nets:
        assert new_proxy.id not in world.d.networks.get(net).attrs["Containers"]
    await cmgr.on_capture_proxy_started()
    for net in nets:
        members = world.d.networks.get(net).attrs["Containers"]
        assert new_proxy.id in members and world.agent.id in members
        assert connects_to(world, net)[new_proxy.id] == {"GwPriority": sc.GUEST_GATEWAY_PRIORITY}
    assert {a["host"], b["host"]} == {c.name for c in world.created()}


@pytest.mark.parametrize("variant", ["no_sysctl", "no_pool"])
async def test_recreated_proxy_that_may_forward_or_reach_the_pool_is_left_off(world, variant, caplog):
    await world.mgr.ensure(ALICE, ["projA"])
    if variant == "no_sysctl":
        new_proxy = _recreate_proxy(world, sysctls=None)
    else:
        new_proxy = _recreate_proxy(world, blocked="172.18.0.5")
    caplog.set_level(logging.INFO, logger="sandbox_manager")
    await world.mgr.attach_capture_proxy_everywhere()
    net = world.d.networks.get(sc.network_name(ALICE, "own"))
    assert new_proxy.id not in net.attrs["Containers"]
    assert world.agent.id in net.attrs["Containers"]
    assert "capture proxy" in caplog.text


async def test_attach_everywhere_survives_a_failing_network(world):
    await world.mgr.ensure(ALICE, ["projA"])
    await world.mgr.ensure(BOB, ["projB"])
    new_proxy = _recreate_proxy(world)
    original = world.mgr._guests_sync

    def flaky(network, strict, force=False):
        if network == sc.network_name(ALICE, "own"):
            raise RuntimeError("daemon hiccup")
        return original(network, strict, force)
    world.mgr._guests_sync = flaky
    assert await world.mgr.attach_capture_proxy_everywhere() == 1
    assert new_proxy.id in world.d.networks.get(sc.network_name(BOB, "own")).attrs["Containers"]


# --- Manager wiring fixes ---------------------------------------------------------------

async def test_compose_one_off_agent_containers_are_never_attached(world):
    one_off = lc.add_agent(world.d, name="redamon-agent-run-3f2a", labels={"com.docker.compose.oneoff": "True"})
    await world.mgr.ensure(ALICE, ["projA"])
    members = world.d.networks.get(sc.network_name(ALICE, "own")).attrs["Containers"]
    assert world.agent.id in members and one_off.id not in members


async def test_a_one_off_alone_is_no_agent(world, caplog):
    world.agent.remove(force=True)
    one_off = lc.add_agent(world.d, name="redamon-agent", labels={"com.docker.compose.oneoff": "True"})
    caplog.set_level(logging.INFO, logger="sandbox_manager")
    await world.mgr.ensure(ALICE, ["projA"])
    members = world.d.networks.get(sc.network_name(ALICE, "own")).attrs["Containers"]
    assert one_off.id not in members
    assert "no agent container" in caplog.text


async def test_sandbox_networks_pin_ipv4_only_and_the_bridge_options(world):
    made = []
    original = world.d.networks.create

    def create(name, **kw):
        made.append(kw)
        return original(name, **kw)
    world.d.networks.create = create
    await world.mgr.ensure(ALICE, ["projA"])
    assert len(made) == 1
    kw = made[0]
    assert kw.get("enable_ipv6") is not True
    assert kw["options"] == {
        "com.docker.network.enable_ipv6": "false",
        "com.docker.network.bridge.enable_icc": "true",
        "com.docker.network.bridge.enable_ip_masquerade": "true",
        "com.docker.network.bridge.gateway_mode_ipv4": "nat",
        "com.docker.network.bridge.host_binding_ipv4": "127.0.0.1",
    }
    assert kw["driver"] == sc.NETWORK_DRIVER and kw["internal"] is False


IPV6_OPTION = "com.docker.network.enable_ipv6"


def _daemon_turns_ipv6_on(world, honours_option=True):
    """A daemon whose `default-network-opts` turn IPv6 on, as Engine 29.10 does
    for a create body without EnableIPv6 (docker-py 7.2 sends that key only when
    it is true): the network gets an IPv6 subnet unless the create's own option
    says "false". `honours_option=False`: a daemon that ignores the option."""
    original = world.d.networks.create

    def create(name, **kw):
        net = original(name, **kw)
        asked = (kw.get("options") or {}).get(IPV6_OPTION) if honours_option else None
        net.attrs["EnableIPv6"] = kw.get("enable_ipv6") is True or asked != "false"
        if net.attrs["EnableIPv6"]:
            net.attrs["IPAM"]["Config"].append({"Subnet": "fdc9:43f5:475f::/64", "Gateway": None})
        return net
    world.d.networks.create = create


def _create_body(kwargs):
    """The JSON body docker-py 7.2 sends for networks.create(name, **kwargs)."""
    import docker as docker_sdk
    api = docker_sdk.APIClient(base_url="tcp://127.0.0.1:9", version="1.48")
    sent = []

    def post(url, data=None, **kw):
        sent.append(json.loads(data))
        res = MagicMock()
        res.json.return_value = {"Id": "n" * 64}
        res.raise_for_status.return_value = None
        return res
    api._post = post
    name = kwargs.pop("name")
    api.create_network(name, **kwargs)
    return sent[0]


async def test_sandbox_network_create_body_turns_ipv6_off(world):
    made = []
    original = world.d.networks.create

    def create(name, **kw):
        made.append(dict(kw, name=name))
        return original(name, **kw)
    world.d.networks.create = create
    await world.mgr.ensure(ALICE, ["projA"])
    body = _create_body(made[0])
    assert body["Options"][IPV6_OPTION] == "false"
    assert body.get("EnableIPv6") in (None, False)
    assert [c["Subnet"] for c in body["IPAM"]["Config"]] == [world.d.sandbox_networks()[0].attrs["IPAM"]["Config"][0]["Subnet"]]


async def test_sandbox_network_is_ipv4_only_under_an_ipv6_daemon_default(world):
    _daemon_turns_ipv6_on(world)
    ans = await world.mgr.ensure(ALICE, ["projA"])
    assert ans["state"] == "running"
    net = world.d.networks.get(sc.network_name(ALICE, "own"))
    assert net.attrs["EnableIPv6"] is False
    assert all(":" not in c["Subnet"] for c in net.attrs["IPAM"]["Config"])


async def test_a_network_the_daemon_made_ipv6_is_removed_and_the_start_refused(world, caplog):
    _daemon_turns_ipv6_on(world, honours_option=False)
    caplog.set_level(logging.INFO, logger="sandbox_manager")
    with pytest.raises(sm.SandboxStartError) as e:
        await world.mgr.ensure(ALICE, ["projA"])
    assert e.value.code == sc.ERR_START_FAILED
    assert world.d.sandbox_networks() == [] and world.created() == []
    assert world.ledger.sandbox_keys() == set() and world.mgr.reservation_keys() == set()
    assert "IPv6" in caplog.text


async def test_an_existing_ipv6_network_is_never_reused(world):
    first = await world.mgr.ensure(ALICE, ["projA"])
    world.d.networks.get(sc.network_name(ALICE, "own")).attrs["EnableIPv6"] = True
    with pytest.raises(sm.SandboxStartError) as e:
        await world.mgr.ensure(ALICE, ["projA", "projB"], need_project="projB")
    assert e.value.code == sc.ERR_START_FAILED
    assert [c.name for c in world.created(ALICE)] == [first["host"]]
    assert world.mgr.get_instance(ALICE, first["instance"]).state == "running"


async def test_adoption_refuses_a_sandbox_on_an_ipv6_network(world):
    ans = await world.mgr.ensure(ALICE, ["projA"])
    await world.mgr.ensure(BOB, ["projB"])
    world.d.networks.get(sc.network_name(ALICE, "own")).attrs["EnableIPv6"] = True
    world.ledger.reconcile(set())
    world.mgr = world.manager()
    summary = await world.mgr.adopt()
    assert summary["adopted"] == 1 and summary["removed"] == 1
    assert world.mgr.get_instance(ALICE, ans["instance"]) is None
    assert [c.labels[sc.LABEL_KEY] for c in world.created()] == [sc.sandbox_key(BOB, "own")]


async def test_instance_ids_are_unique_across_people(world, monkeypatch):
    """The webapp pairs sessions and audit rows by `<instance>:<n>` and the agent
    routes `?sandbox=<instance>`: an instance id is unique server-wide."""
    draws = iter(["abc123", "abc123", "abc123", "def456"])
    monkeypatch.setattr(sm.sc, "new_instance", lambda: next(draws))
    a = await world.mgr.ensure(ALICE, ["projA"])
    b = await world.mgr.ensure(BOB, ["projB"])
    assert a["instance"] == "abc123" and b["instance"] == "def456"
    assert len(world.ledger.sandbox_keys()) == 2


async def test_instance_ids_skip_adopted_instances_of_other_people(world, monkeypatch):
    first = await world.mgr.ensure(ALICE, ["projA"])
    world.ledger.reconcile(set())
    world.mgr = world.manager()
    await world.mgr.adopt()
    draws = iter([first["instance"], "fed987"])
    monkeypatch.setattr(sm.sc, "new_instance", lambda: next(draws))
    b = await world.mgr.ensure(BOB, ["projB"])
    assert b["instance"] == "fed987"
