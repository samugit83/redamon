"""Recon dials the capture proxy on the port it really listens on (L-15).

The proxy listens on the port set in Global Settings > TrafficMind, which the
webapp hands to /capture-proxy/start. Recon reads CAPTURE_PROXY_PORT and
CAPTURE_PROXY_MAX_BODY_KB from its environment (helpers/proxy_routing.py,
helpers/traffic_capture.py), and neither recon spawn set them, so with any port
but 8888 recon found the proxy "unreachable", ran direct and nothing was
captured. Both spawns now carry the port Docker publishes the proxy on and the
operator's body cap.
"""
import asyncio
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "recon_orchestrator"))
sys.path.insert(0, str(REPO))

import container_manager as cm_mod  # noqa: E402
from models import ReconStatus  # noqa: E402
from tests.fake_docker import FakeClient, FakeContainer, FakeContainers  # noqa: E402

PROXY = cm_mod.ContainerManager.CAPTURE_PROXY_NAME


class Proxy(FakeContainer):
    def __init__(self, bindings):
        super().__init__("proxy-1", "redamon-capture-proxy:latest", {"redamon.capture": "proxy"},
                         name=PROXY)
        self.bindings = bindings

    @property
    def attrs(self):
        return {"State": {"Status": "running"}, "HostConfig": {"PortBindings": self.bindings}}


def _published(container_port, host_port):
    return {f"{container_port}/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(host_port)}]}


class Containers(FakeContainers):
    def __init__(self, containers=(), broken=False):
        super().__init__(containers)
        self.broken = broken
        self.runs = []

    def get(self, ref):
        if self.broken and ref == PROXY:
            raise cm_mod.APIError("500 Server Error")
        return super().get(ref)

    def run(self, image, **kwargs):
        self.runs.append(kwargs)
        return self.add(FakeContainer(f"spawned-{len(self.runs)}", image,
                                      kwargs.get("labels"), name=kwargs.get("name")))


def _manager(containers=(), broken=False):
    m = cm_mod.ContainerManager.__new__(cm_mod.ContainerManager)
    m.client = FakeClient()
    m.client.containers = Containers(containers, broken)
    m.client.images = SimpleNamespace(get=lambda ref: None)
    m.running_states = {}
    m.partial_recon_states = {}
    m._docker_op_executor = ThreadPoolExecutor(max_workers=2)
    m.recon_image = "redamon-recon:latest"
    m.supply_chain_osv_db_volume = "osv"
    m.sca_intel_volume = "intel"
    m.ledger = SimpleNamespace(release_nowait=lambda key: None)

    async def _admit(*a, **k):
        return "key"

    m._admit_scan = _admit
    m._warm_feeds_in_background = lambda: None
    m._recon_settings_mount = lambda: {}
    m._graph_db_mount = lambda *a, **k: {}
    m._scanner_env = lambda: {}
    m._analyzer_env = lambda: {}
    m._container_mem_limit = lambda kind: None
    m._container_pids_limit = lambda: None
    m._container_cpu_limit = lambda: None
    m._scanner_hardening = lambda **k: {}
    return m


def _spawn_envs(m, tmp_path):
    """The environment of a full and of a partial recon container."""
    state = asyncio.run(m.start_recon("proj-a", "u1", "http://webapp", "/host/recon"))
    assert state.status == ReconStatus.RUNNING, state.error
    with mock.patch.object(cm_mod, "Path", lambda p: tmp_path / Path(p).name):
        partial = asyncio.run(m.start_partial_recon(
            "proj-b", "Httpx", {"user_id": "u1", "webapp_api_url": "http://webapp"},
            "/host/recon"))
    assert not partial.error, partial.error
    full_env, partial_env = (run["environment"] for run in m.client.containers.runs)
    return full_env, partial_env


@pytest.fixture
def no_capture_env(tmp_path, monkeypatch):
    for name in ("CAPTURE_PROXY_PORT", "CAPTURE_PROXY_MAX_BODY_KB"):
        monkeypatch.delenv(name, raising=False)
    config = tmp_path / ".capture-config.json"
    monkeypatch.setenv("CAPTURE_CONFIG_FILE", str(config))
    return config


def _capture(env):
    return {k: env.get(k) for k in ("CAPTURE_PROXY_PORT", "CAPTURE_PROXY_MAX_BODY_KB")}


class TestThePort:
    def test_the_port_the_proxy_is_published_on_reaches_both_spawns(self, tmp_path, no_capture_env):
        m = _manager([Proxy(_published(9090, 9090))])
        for env in _spawn_envs(m, tmp_path):
            assert env["CAPTURE_PROXY_PORT"] == "9090"

    def test_a_compose_started_proxy_is_dialled_on_its_host_port(self, tmp_path, no_capture_env):
        # docker compose --profile capture publishes CAPTURE_PROXY_PORT in front
        # of mitmdump's fixed 8888; recon (host network) needs the host side.
        m = _manager([Proxy(_published(8888, 9191))])
        for env in _spawn_envs(m, tmp_path):
            assert env["CAPTURE_PROXY_PORT"] == "9191"

    def test_the_last_start_is_used_when_docker_cannot_say(self, tmp_path, no_capture_env):
        m = _manager(broken=True)
        m._remove_container_if_exists = lambda name: None
        m._ingest_volumes = lambda vols: vols

        async def _status():
            return {}

        m.capture_proxy_status = _status
        asyncio.run(m.start_capture_proxy({"port": 9090}))
        m.client.containers.runs.clear()
        for env in _spawn_envs(m, tmp_path):
            assert env["CAPTURE_PROXY_PORT"] == "9090"

    def test_with_no_proxy_the_compose_value_is_forwarded(self, tmp_path, no_capture_env, monkeypatch):
        monkeypatch.setenv("CAPTURE_PROXY_PORT", "8888")
        m = _manager()
        for env in _spawn_envs(m, tmp_path):
            assert env["CAPTURE_PROXY_PORT"] == "8888"

    def test_the_status_reports_the_port_in_use(self, no_capture_env, monkeypatch):
        monkeypatch.setenv("CAPTURE_PROXY_PORT", "8888")
        m = _manager([Proxy(_published(9090, 9090))])
        assert asyncio.run(m.capture_proxy_status())["port"] == 9090


class TestTheBodyCap:
    def test_the_operators_cap_from_the_capture_config_reaches_both_spawns(
            self, tmp_path, no_capture_env, monkeypatch):
        monkeypatch.setenv("CAPTURE_PROXY_MAX_BODY_KB", "64")
        no_capture_env.write_text(json.dumps({"body": {"max_body_kb": 256}, "enabled": True}))
        m = _manager([Proxy(_published(9090, 9090))])
        for env in _spawn_envs(m, tmp_path):
            assert _capture(env) == {"CAPTURE_PROXY_PORT": "9090",
                                     "CAPTURE_PROXY_MAX_BODY_KB": "256"}

    def test_without_a_config_file_the_compose_value_is_forwarded(
            self, tmp_path, no_capture_env, monkeypatch):
        monkeypatch.setenv("CAPTURE_PROXY_MAX_BODY_KB", "128")
        m = _manager()
        for env in _spawn_envs(m, tmp_path):
            assert env["CAPTURE_PROXY_MAX_BODY_KB"] == "128"

    @pytest.mark.parametrize("content", [
        "{not json", json.dumps({"body": {"max_body_kb": "lots"}}),
        json.dumps({"body": {"max_body_kb": 0}}), json.dumps([1, 2]),
    ])
    def test_a_bad_config_falls_back_and_never_breaks_a_spawn(
            self, tmp_path, no_capture_env, content):
        no_capture_env.write_text(content)
        m = _manager([Proxy({"8888/tcp": None})])
        for env in _spawn_envs(m, tmp_path):
            assert _capture(env) == {"CAPTURE_PROXY_PORT": "8888",
                                     "CAPTURE_PROXY_MAX_BODY_KB": "64"}


def test_recon_reads_the_names_the_orchestrator_sends():
    """The contract on the recon side, read from its source (recon is not
    importable in this image)."""
    routing = (REPO / "recon" / "helpers" / "proxy_routing.py").read_text(encoding="utf-8")
    capture = (REPO / "recon" / "helpers" / "traffic_capture.py").read_text(encoding="utf-8")
    assert 'os.environ.get("CAPTURE_PROXY_PORT"' in routing
    assert 'os.environ.get("CAPTURE_PROXY_MAX_BODY_KB"' in capture
