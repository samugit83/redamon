"""Per-user Kali sandboxes: start, stop, reconcile and adopt them, and keep them
only while they are used (group 1).

One container per person and view, started on demand. It mounts only the
person's allowed project folders and their own output folder, and sits on a
network of its own that only the agent and the capture proxy join. The names,
labels, mount plan, container and network specification and timings are the
contract (``sandbox_contract.py``); this module applies them with Docker.

Each unit of work holds a lease on the instance it uses, renewed every
``LEASE_RENEW_S`` and lapsing after ``LEASE_TTL_S``. The idle loop stops an
instance nobody leases once it has been unused for the idle minutes, one held
only by live sessions or a tunnel (a ``hold`` lease, which is not use) after
eight hours without use, and a replaced (draining) one once its leases end.

A stopped or replaced instance's pool port is held for its person and view
(``sc.PORT_HOLD_HOURS_ENV``): nobody else gets it, the same person gets it back,
and the holds outlive a restart in a file of the output folder.

Concurrency: one asyncio lock per person guards every decision for both of
that person's views, a lease and the idle loop's stop included, and one global
lock guards subnet and port allocation and the retry of network removals.
docker-py is synchronous, so every Docker call runs in a thread. The work done
under a person's lock runs as its own task, shielded from the caller, so a
client that hangs up mid-start never leaves a half-made sandbox behind.

Nothing here logs a token, an environment or a raw user id (a reservation key
holds one): a log line names the person by sandbox key.
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import ipaddress
import json
import logging
import os
import re
import shutil
import stat
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Dict, Mapping, Optional

import docker
from docker.errors import APIError, ImageNotFound, NotFound

import resource_governor as rg
import sandbox_contract as sc
import sandbox_templates
from container_manager import BROKER_OWNED_LABEL, join_host_path

logger = logging.getLogger(__name__)

# docker-py 7.2 cannot send an endpoint's GwPriority, so guests are connected
# with a raw call, and the engine API must be new enough to honour it. Without
# it a guest's default route could move onto a sandbox network: refuse to start.
GW_PRIORITY_MIN_API = (1, 48)

# Pinned on every sandbox network, so a daemon's `default-network-opts` cannot
# change them: IPv4 only (the pool, the proxy's denylist and the guests'
# forwarding switch are IPv4), containers reach each other (the agent and the
# proxy reach the sandbox), NAT egress for the tools, no direct routing into the
# network from outside the host, and a published pool port that names no address
# binds the loopback. IPv6 is turned off by the option: docker-py 7.2 sends
# EnableIPv6 only when it is true, and without it the engine takes the option.
# A network that is IPv6 anyway is refused (_network_problem).
IPV6_OPTION = "com.docker.network.enable_ipv6"
NETWORK_OPTIONS = {
    IPV6_OPTION: "false",
    "com.docker.network.bridge.enable_icc": "true",
    "com.docker.network.bridge.enable_ip_masquerade": "true",
    "com.docker.network.bridge.gateway_mode_ipv4": "nat",
    "com.docker.network.bridge.host_binding_ipv4": "127.0.0.1",
}

# `docker compose build` stamps the project and service labels on the agent
# IMAGE, so every plain `docker run redamon-agent ...` (a unit gate, run_tests.sh)
# carries them too. Only the two labels below prove that compose itself created
# the container as a service replica: compose writes them on containers, never
# on images. `docker compose run agent ...` writes the hash too (Compose v5: no
# number), always marked one-off; older versions may write a number as well.
COMPOSE_CONFIG_HASH_LABEL = "com.docker.compose.config-hash"
COMPOSE_NUMBER_LABEL = "com.docker.compose.container-number"
COMPOSE_ONEOFF_LABEL = "com.docker.compose.oneoff"

# The compose line that gives the orchestrator each host folder a sandbox binds a
# part of: without it the host path is unknown and no sandbox can start.
COMPOSE_MOUNTS = {
    sc.MOUNT_WORKSPACE: "./agentic/agent-workspace:/app/agent-workspace",
    sc.MOUNT_OUTPUT: "./mcp/output:/app/mcp-output",
    sc.MOUNT_SERVERS: "./mcp/servers:/app/mcp-servers:ro",
    sc.MOUNT_GRAPH_DB: "./graph_db:/app/graph_db:ro",
}

# Below the 1024 every service container runs with: under CPU contention the
# platform's services win over any number of sandboxes (a fork bomb in one is
# also capped by its own CPUs and process count). Docker maps it to cpu.weight.
SANDBOX_CPU_SHARES = 256

# `docker compose build` stamps these on the Kali image and every container
# started from it inherits them; blanked, so compose never counts a sandbox as
# a surplus kali-sandbox replica that `up` removes, or a container `down` owns.
COMPOSE_LABEL_OVERRIDES = {sc.COMPOSE_PROJECT_LABEL: "", sc.COMPOSE_SERVICE_LABEL: ""}

# Every container and network a stack makes carries its owner (the orchestrator's
# compose project), and adoption, removal and network reuse touch only their own:
# a test stack or a second checkout on the same daemon keeps its sandboxes.
LABEL_OWNER = "redamon.sandbox.owner"
# The image the orchestrator starts the capture proxy from (ContainerManager.
# _capture_image; a test pins the two). Only a proxy on its current id joins a
# sandbox network: an older one may predate the egress guard it relies on there.
CAPTURE_PROXY_IMAGE_ENV = "CAPTURE_PROXY_IMAGE"
CAPTURE_PROXY_IMAGE_DEFAULT = "redamon-capture-proxy:latest"


def capture_proxy_image() -> str:
    return os.environ.get(CAPTURE_PROXY_IMAGE_ENV, CAPTURE_PROXY_IMAGE_DEFAULT)


# An older image of the sandbox is one these labels of the current image match
# (compose stamps them at build); the broker label already rules out a scan's.
IMAGE_LINEAGE_LABELS = (sc.COMPOSE_SERVICE_LABEL, "description")
# Host-config fields the manager never sets: adoption requires each empty.
NEUTRAL_HOST_KEYS = (
    "Binds", "VolumesFrom", "Devices", "DeviceCgroupRules", "DeviceRequests", "Links",
    "GroupAdd", "DnsOptions", "DnsSearch", "Tmpfs", "Sysctls", "Ulimits",
    "CapDrop", "Privileged", "PublishAllPorts", "OomKillDisable", "PidMode", "UTSMode",
    "UsernsMode", "Cgroup", "CgroupParent", "VolumeDriver", "StorageOpt")

HEALTH_POLL_S = 1
# A pool port the host already uses fails the start; it is skipped this long.
BUSY_PORT_HOLD_S = 600
# The pool ports held for their person and view (sc.PORT_HOLD_HOURS_ENV), as
# {"holds": [{"port", "key", "since"}]}: the sandbox key, never a user id. In the
# output folder, which survives an orchestrator restart, which git ignores, and
# which only the orchestrator mounts whole (a sandbox mounts its `users/<key>`).
PORT_HOLDS_FILE = ".sandbox-port-holds.json"
# The same content, written after it: read when the file itself is damaged.
PORT_HOLDS_COPY = ".sandbox-port-holds.json.prev"
PORT_HOLDS_MAX_BYTES = 1 << 20
_SANDBOX_KEY = re.compile(r"[0-9a-f]{16}")
# The copy of one view's custom nuclei templates: the webapp caps one upload at 1 MiB.
CUSTOM_TEMPLATE_MAX_BYTES = 1 << 20
CUSTOM_TEMPLATES_MAX_FILES = 2000
CUSTOM_TEMPLATES_MAX_TOTAL_BYTES = 64 << 20
INSTANCE_DRAWS = 32
_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}")
_PORT_BUSY_MARKERS = ("port is already allocated", "address already in use")

IMAGE_MISSING_DETAIL = (
    f"the Kali sandbox image {sc.IMAGE} is missing: run ./redamon.sh up, which builds "
    "missing tool images, or build it by hand with "
    "docker compose --profile tools build kali-sandbox")

_LIVE_STATES = ("starting", "running", "draining", "stopping")

# The agent names its leases with a UUID (the webapp checks the same shape).
_LEASE_ID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
ERR_INVALID_LEASE = "invalid_sandbox_request"
DRAIN_REASON = "replaced"
# Why an adopted sandbox without a pool port drains: a pool is configured now and has
# a port for its person and view. With none to give, its replacement would get no port
# either, and would turn the person's tunnel off.
PORTLESS_DRAIN = "a pool port is free now"

# A restart loses every lease. An adopted instance therefore takes lease ids it
# does not know, and is never stopped for holding none, for one lease lifetime,
# while the agent's renewals (every 30 s) and the hold watcher (every 60 s) take
# them again; else a draining one would be stopped at the first tick with its
# sessions and jobs still running.
ADOPTION_GRACE_S = sc.LEASE_TTL_S

# A start whose readiness never settles (its health read kept failing, its
# check task died) is stopped by the idle loop this long after its timeout.
START_STUCK_GRACE_S = 60

# A running instance whose container is gone or exited (its main process killed by
# the memory limit or by a shell, `restart: no`) is stopped under this reason, by
# the next ensure or idle tick, so it is never handed out again. An unhealthy one
# is stopped only while no lease holds it: a probe that times out under a person's
# own heavy load is no crash, and stopping it would end their sessions.
CRASH_REASON = "crashed"
CRASHED_HEALTH = ("exited", "dead", "gone")

# A sandbox's container log, under a log driver that rotates: a root shell that
# writes to PID 1's stdout grows it, on the host's disk, for as long as it runs.
# A daemon whose default driver is another one (journald, syslog, a shipper) keeps it.
ROTATING_LOG_DRIVERS = ("json-file", "local")
LOG_MAX_SIZE = "10m"
LOG_MAX_FILES = "3"

# The workspace project folder is written by the agent (not root) and the sandbox,
# so it is 0777; a person's output folder only by their sandbox (root inside).
WORKSPACE_LEAF_MODE = 0o777
OUTPUT_LEAF_MODE = 0o755

# Turns off the tunnels of a replaced instance (tunnel_manager.py on its own
# loopback, an empty config). The token reaches it through the exec's
# environment, never its command line; proxies are bypassed. The person is root
# in there and decides what the exec prints and how long it runs, so it is
# started detached and never attached: its output is never read, its exit code
# is read at the next tick and proves little, and the config is sent again at
# every tick while the instance drains. Its Docker calls run on a pool of their
# own with a deadline, so a wedged daemon never holds the shared executor.
TUNNEL_TOKEN_VAR = "REDAMON_TUNNEL_TOKEN"
TUNNEL_OFF_TIMEOUT_S = 30
TUNNEL_WORKERS = 2
TUNNEL_THREAD_PREFIX = "sandbox-tunnel"
TUNNEL_CALL_DEADLINE_S = 20
TUNNEL_OFF_SCRIPT = (
    "import os, urllib.request as r\n"
    f"q = r.Request('http://127.0.0.1:{sc.PORTS['tunnel']}/tunnel/configure', data=b'{{}}', "
    "method='POST', headers={'Content-Type': 'application/json', "
    f"'Authorization': 'Bearer ' + os.environ.pop('{TUNNEL_TOKEN_VAR}')}})\n"
    f"r.build_opener(r.ProxyHandler({{}})).open(q, timeout={TUNNEL_OFF_TIMEOUT_S}).read()\n")


def steady_clock() -> Callable[[], float]:
    """Epoch seconds that never jump: the wall time when it is made, moved on by
    the monotonic clock. Lease expiry, the idle timer and the hold cap must not
    fire because an NTP step or an operator moved the host's clock; the epoch
    values the API reports (``stop_at``, ``expires_at``) are off by at most the
    corrections made to the host's clock since the orchestrator started."""
    wall0, mono0 = time.time(), time.monotonic()
    return lambda: wall0 + (time.monotonic() - mono0)


_DOCKER_TIME = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})")


def _docker_created_ns(value) -> int:
    """Docker's RFC 3339 ``Created`` in nanoseconds since the epoch, 0 when absent
    or unreadable. Parsed, never compared as text: the engine trims trailing
    zeros of the fraction, so ``.1234Z`` sorts after ``.12341Z`` as a string."""
    match = _DOCKER_TIME.fullmatch(value.strip()) if isinstance(value, str) else None
    if match is None:
        return 0
    zone = "+00:00" if match.group(3) == "Z" else match.group(3)
    try:
        seconds = int(datetime.strptime(match.group(1) + zone, "%Y-%m-%dT%H:%M:%S%z").timestamp())
    except ValueError:
        return 0
    return seconds * 10 ** 9 + int((match.group(2) or "").ljust(9, "0"))


# --- Errors -------------------------------------------------------------------------

class SandboxError(Exception):
    """A refusal with a contract error code and its HTTP status."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(code)
        self.code = code
        self.detail = detail
        self.status = sc.ERROR_STATUS.get(code, 503)

    def payload(self) -> dict:
        return {"code": self.code, "detail": self.detail}


class SandboxInvalid(SandboxError, ValueError):
    """An invalid user id, view, project id, lease id or lease kind (400)."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(code, detail)
        self.status = 400


class SandboxStartError(SandboxError):
    """``sandbox_image_missing``, ``sandbox_start_failed`` or ``sandbox_start_timeout``."""


class SandboxRefused(SandboxError):
    """The memory governor refused the start (409 with the governor's payload)."""

    def __init__(self, result):
        super().__init__(sc.REFUSAL_CODE_BY_LIMIT.get(result.limit_type, sc.ERR_RAM), result.detail)
        self.result = result

    def payload(self) -> dict:
        return {**self.result.payload(), "code": self.code}


class _UnsafeFolder(Exception):
    """A mount source that is a symlink or not a folder."""


# --- State --------------------------------------------------------------------------

@dataclass(eq=False)
class Instance:
    user_id: str
    view: str
    instance: str
    state: str
    projects: tuple
    host: str
    key: str
    network: str
    created: float
    last_used: float
    token: str = field(default="", repr=False)
    tunnel_token: str = field(default="", repr=False)
    reverse_port: int = sc.DEFAULT_REVERSE_PORT
    pool_port: Optional[int] = None
    # None (unknown) until its port is allocated.
    reverse_port_state: Optional[str] = None
    container_id: Optional[str] = None
    # {lease_id: (kind, expires_at)}
    leases: dict = field(default_factory=dict)
    stop_reason: Optional[str] = None
    warn: bool = False
    start_error: Optional[SandboxError] = None
    ready: asyncio.Event = field(default_factory=asyncio.Event)
    # What it was started from, for the drain onto new code (TD-28).
    image_id: Optional[str] = None
    servers: Optional[str] = None
    grace_until: float = 0.0
    # Order of creation in this manager (adoption assigns it oldest first).
    seq: int = 0
    tunnel_exec: Optional[str] = None
    tunnel_future: Optional[concurrent.futures.Future] = field(default=None, repr=False)
    tunnel_confirmed: bool = False

    @property
    def reservation_key(self) -> str:
        return sc.reservation_key(self.user_id, self.instance)

    @property
    def projects_hash(self) -> str:
        return sc.projects_hash(self.projects)


@dataclass(eq=False)
class _Pending:
    """An ensure on its way to a start. A stop that would make its project list
    stale (account end, access loss, project deletion) fences it, so it cannot
    start a sandbox, or re-create a folder, after that stop."""
    view: str
    projects: frozenset
    fenced: bool = False


def _env_dict(entries) -> dict:
    out = {}
    for entry in entries or []:
        k, _, v = str(entry).partition("=")
        out[k] = v
    return out


def _api_version(value) -> Optional[tuple]:
    try:
        major, minor = str(value).split(".")[:2]
        return int(major), int(minor)
    except (TypeError, ValueError):
        return None


def _norm_mount(m: Mapping) -> tuple:
    return (m.get("Type"), m.get("Source"), m.get("Target"), bool(m.get("ReadOnly")))


def _norm_caps(caps) -> set:
    return {str(c).upper().removeprefix("CAP_") for c in caps or []}


class SandboxManager:
    """Starts, stops, reconciles and adopts per-user Kali sandboxes.

    ``host_bases`` maps the contract's host-side mount kinds to the host paths
    Docker binds (resolved by the orchestrator from its own mounts);
    ``local_bases`` maps the same kinds to where the orchestrator itself sees
    those folders (``MOUNT_HOST_BASES``). Folders are made through the local
    path and mounted by the host path."""

    def __init__(self, client, ledger, host_bases: Mapping[str, str], osv_volume: str,
                 own_compose_project: Optional[str], clock: Optional[Callable[[], float]] = None,
                 cpu_count: Callable[[], Optional[int]] = os.cpu_count, *,
                 local_bases: Optional[Mapping[str, str]] = None,
                 sleep: Callable = asyncio.sleep,
                 start_timeout_s: int = sc.START_TIMEOUT_S):
        self.client = client
        self.ledger = ledger
        self.host_bases = {k: v for k, v in dict(host_bases).items() if v}
        self.osv_volume = osv_volume or sc.OSV_VOLUME_DEFAULT
        self.own_compose_project = own_compose_project or None
        self.owner = self.own_compose_project or "standalone"
        self.clock = clock or steady_clock()
        self.cpu_count = cpu_count
        self.local_bases = dict(sc.MOUNT_HOST_BASES if local_bases is None else local_bases)
        self._sleep = sleep
        self._start_timeout_s = start_timeout_s
        self._by_user: Dict[str, Dict[str, Instance]] = {}
        self._user_locks: Dict[str, asyncio.Lock] = {}
        self._alloc_lock = asyncio.Lock()
        self._pending: Dict[str, set] = {}
        self._tasks: set = set()
        self._guest_cache: Dict[str, tuple] = {}
        self._servers_cache: Optional[tuple] = None
        self._busy_ports: Dict[int, float] = {}
        self._network_retry: set = set()
        self._warned: set = set()
        self._seq = 0
        self._tunnel_pool: Optional[concurrent.futures.ThreadPoolExecutor] = None
        self._tunnel_pending: set = set()
        # {pool port: (sandbox key, when its instance stopped)}; written in a
        # thread, the newest snapshot last (_save_port_holds_sync).
        self._port_holds: Dict[int, tuple] = {}
        self._holds_version = 0
        self._holds_written = 0
        self._holds_lock = threading.Lock()
        self._load_port_holds_sync()

    # --- Small helpers --------------------------------------------------------

    def _user_lock(self, user_id: str) -> asyncio.Lock:
        lock = self._user_locks.get(user_id)
        if lock is None:
            lock = self._user_locks[user_id] = asyncio.Lock()
        return lock

    def instances(self, user_id: Optional[str] = None) -> list:
        users = [user_id] if user_id is not None else list(self._by_user)
        return [i for u in users for i in list(self._by_user.get(u, {}).values())]

    def get_instance(self, user_id: str, instance: str) -> Optional[Instance]:
        return self._by_user.get(user_id, {}).get(instance)

    def _view_instances(self, user_id: str, view: str) -> list:
        return [i for i in self.instances(user_id) if i.view == view]

    def _current(self, user_id: str, view: str) -> Optional[Instance]:
        for inst in self._view_instances(user_id, view):
            if inst.state in ("starting", "running"):
                return inst
        return None

    def _register(self, inst: Instance) -> None:
        if not inst.seq:
            self._seq += 1
            inst.seq = self._seq
        self._by_user.setdefault(inst.user_id, {})[inst.instance] = inst

    def _unregister(self, inst: Instance) -> None:
        insts = self._by_user.get(inst.user_id)
        if insts and insts.get(inst.instance) is inst:
            del insts[inst.instance]
            if not insts:
                del self._by_user[inst.user_id]

    def _envelope(self) -> int:
        return int(rg.envelope(sc.ENVELOPE_PROFILE_KEY))

    def _idle_s(self) -> int:
        return sc.idle_minutes(os.environ.get(sc.IDLE_MINUTES_ENV)) * 60

    @staticmethod
    def _live_kinds(inst: Instance, now: float) -> set:
        return {kind for kind, expires in inst.leases.values() if expires > now}

    @staticmethod
    def _prune(inst: Instance, now: float) -> None:
        for lease_id, (_, expires) in list(inst.leases.items()):
            if expires <= now:
                del inst.leases[lease_id]

    def _stop_at(self, inst: Instance, now: Optional[float] = None) -> float:
        """When the idle loop will stop it if nothing changes: eight hours after its
        last use while a hold is held, else the idle minutes after it; at once for
        one already stopping, or draining with nothing left to finish."""
        now = self.clock() if now is None else now
        kinds = self._live_kinds(inst, now)
        if inst.state == "stopping" or (inst.state == "draining" and not kinds
                                        and now >= inst.grace_until):
            return now
        if sc.HOLD_LEASE_KIND in kinds:
            return inst.last_used + sc.HOLD_MAX_NO_USE_S
        return inst.last_used + self._idle_s()

    def _warn(self, inst: Instance, now: float) -> bool:
        """The hold cap's warning, from one hour before it (any use resets it)."""
        return (inst.state in ("running", "draining")
                and sc.HOLD_LEASE_KIND in self._live_kinds(inst, now)
                and now >= inst.last_used + sc.HOLD_MAX_NO_USE_S - sc.HOLD_WARN_BEFORE_S)

    @staticmethod
    def _shown_stop_reason(inst: Instance) -> Optional[str]:
        """Why an instance is on its way out; None while it is the current one."""
        return inst.stop_reason if inst.state in ("draining", "stopping") else None

    def _warn_once(self, tag: str, message: str) -> None:
        if tag not in self._warned:
            self._warned.add(tag)
            logger.warning(message)

    def _scrub(self, text: str, inst: Optional[Instance] = None) -> str:
        text = str(text)[:300]
        if inst is not None:
            for secret in (inst.token, inst.tunnel_token):
                if secret:
                    text = text.replace(secret, "***")
        return text

    def _log(self, event: str, inst: Instance, reason: Optional[str] = None) -> None:
        line = (f"[sandbox] {event} key={inst.key} view={inst.view} instance={inst.instance} "
                f"projects={inst.projects_hash}")
        if reason:
            line += f" reason={reason}"
        logger.info(line)

    def _spawn(self, coro) -> asyncio.Task:
        task = asyncio.ensure_future(coro)
        self._tasks.add(task)
        task.add_done_callback(self._task_done)
        return task

    def _task_done(self, task: asyncio.Task) -> None:
        self._tasks.discard(task)
        if not task.cancelled() and task.exception() is not None:
            exc = task.exception()
            if not isinstance(exc, SandboxError):
                logger.warning(f"[sandbox] background task failed: {type(exc).__name__}")

    async def _shielded(self, coro):
        """Run ``coro`` to its end even when the caller is cancelled."""
        return await asyncio.shield(self._spawn(coro))

    async def join_background(self) -> None:
        """Wait for the background start checks (tests, shutdown)."""
        while self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)

    @staticmethod
    def _check_reason(reason: str) -> str:
        if reason not in sc.STOP_REASONS:
            raise ValueError("invalid_stop_reason")
        return reason

    # --- The reaper's view ----------------------------------------------------

    def reservation_keys(self) -> set:
        """Every live instance's ledger key (starting, running, draining, adopted and
        a stop still in progress). Synchronous and memory-only: the 30 s reaper
        frees any sandbox key this does not list."""
        return {inst.reservation_key for inst in self.instances()}

    def networks_to_retry(self) -> set:
        """Sandbox networks whose removal failed (the idle loop retries them)."""
        return set(self._network_retry)

    # --- Ensure ---------------------------------------------------------------

    async def ensure(self, user_id, projects, view: str = sc.VIEW_OWN,
                     need_project: Optional[str] = None, wait: bool = True,
                     touch: bool = False, custom_templates=None) -> dict:
        """B.7: the person's running sandbox for ``view``, started when needed.
        ``touch`` starts in the background and swallows errors and refusals.
        ``custom_templates`` lists the custom nuclei templates the person may use
        (theirs and the instance's, which only the webapp knows); a start copies
        exactly those. None (a webapp that sends no list) copies none."""
        try:
            sc.check_user_id(user_id)
            sc.check_view(view)
            projects = sc.normalize_projects(projects)
            if need_project is not None:
                sc.check_project_id(need_project)
                if need_project not in projects:
                    raise ValueError(sc.ERR_INVALID_PROJECT_ID)
        except ValueError as e:
            raise SandboxInvalid(str(e)) from None
        templates = None if custom_templates is None else tuple(sc.normalize_template_paths(custom_templates))
        if touch:
            wait = False
        # Registered before the first await, so a stop called in the same loop pass
        # already sees (and fences) this ensure.
        pending = _Pending(view, frozenset(projects))
        self._pending.setdefault(user_id, set()).add(pending)
        try:
            inst, fresh = await self._shielded(
                self._ensure_locked(user_id, view, tuple(projects), need_project, pending, templates))
            if inst.state == "starting":
                if not wait:
                    return {"state": "starting", "instance": inst.instance, "fresh": fresh}
                await self._wait_ready(inst)
            inst.last_used = self.clock()
            return self._running_answer(inst, fresh)
        except SandboxError as e:
            if not touch:
                raise
            logger.info(f"[sandbox] warm-up for key={sc.sandbox_key(user_id, view)} not started: {e.code}")
            return {"state": "unavailable", "instance": None, "fresh": False}

    def _running_answer(self, inst: Instance, fresh: bool) -> dict:
        """``state`` is ``running`` for a served draining instance too (it serves the
        call); its ``stop_reason`` says it is on its way out."""
        now = self.clock()
        return {"user_id": inst.user_id, "view": inst.view,
                "instance": inst.instance, "host": inst.host, "token": inst.token,
                "tunnel_token": inst.tunnel_token, "ports": dict(sc.PORTS),
                "reverse_port": inst.reverse_port, "reverse_port_state": inst.reverse_port_state,
                "projects": list(inst.projects),
                "state": "running", "fresh": fresh, "stop_at": self._stop_at(inst, now),
                "stop_reason": self._shown_stop_reason(inst), "warn": self._warn(inst, now)}

    async def _wait_ready(self, inst: Instance) -> None:
        try:
            await asyncio.wait_for(inst.ready.wait(), self._start_timeout_s + 30)
        except asyncio.TimeoutError:
            raise SandboxStartError(sc.ERR_START_TIMEOUT, "the sandbox did not become healthy in time") from None
        if inst.start_error is not None:
            raise inst.start_error
        if inst.state not in ("running", "draining"):
            raise SandboxStartError(sc.ERR_START_FAILED, "the sandbox stopped while starting")

    async def _ensure_locked(self, user_id: str, view: str, projects: tuple,
                             need_project: Optional[str], pending: _Pending,
                             templates: Optional[tuple] = None):
        try:
            async with self._user_lock(user_id):
                allowed = set(projects)
                for inst in self._view_instances(user_id, view):
                    if not set(inst.projects) <= allowed and inst.state != "stopping":
                        await self._stop_locked(inst, "access_lost")
                cur = self._current(user_id, view)
                if cur is not None and cur.state == "running" and await self._crashed(cur, self.clock()):
                    await self._stop_locked(cur, CRASH_REASON)
                    cur = self._current(user_id, view)
                replace = cur is not None and need_project is not None and need_project not in cur.projects
                if cur is not None and not replace:
                    if cur.state == "running":
                        await self._ensure_guests(cur.network, strict=True)
                        # Use is marked under the lock: an idle tick queued behind
                        # this ensure must not stop what it is handing out.
                        cur.last_used = self.clock()
                    return cur, False
                if pending.fenced:
                    raise SandboxStartError(sc.ERR_START_FAILED,
                                            "the sandbox was stopped while this start waited; ask again")
                # A replacement is admitted and made under its own key first: a
                # refusal or a failed start leaves the current instance current.
                try:
                    new = await self._start_locked(user_id, view, projects, templates)
                except SandboxRefused:
                    standby = self._standby(user_id, view, need_project) if cur is None else None
                    if standby is None:
                        raise
                    return standby, False
                if replace and cur.state in ("starting", "running"):
                    self._mark_draining(cur, "a project it lacks is needed")
                await self._stop_older_draining(user_id, view)
                self._turn_off_replaced_tunnels(user_id, view)
                return new, True
        finally:
            waiting = self._pending.get(user_id)
            if waiting is not None:
                waiting.discard(pending)
                if not waiting:
                    del self._pending[user_id]

    def _standby(self, user_id: str, view: str, need_project: Optional[str]) -> Optional[Instance]:
        """The view's draining instance, served when its replacement is refused for
        memory or the sandbox count (an update drains every sandbox onto new code
        while its sessions still hold it): the person keeps working in it instead
        of being refused while it runs. Never one that lacks the project the work
        needs (it mounts nothing new). It stays draining, never current; the next
        ensure tries the replacement again. A lease lifetime of grace lets the
        caller's new lease in. Under the person's lock."""
        candidates = [i for i in self._view_instances(user_id, view)
                      if i.state == "draining" and i.ready.is_set() and i.start_error is None
                      and (need_project is None or need_project in i.projects)]
        if not candidates:
            return None
        inst = max(candidates, key=lambda i: i.seq)
        now = self.clock()
        inst.grace_until = max(inst.grace_until, now + sc.LEASE_TTL_S)
        inst.last_used = now
        self._log("served while draining (its replacement was refused)", inst, DRAIN_REASON)
        return inst

    async def _crashed(self, inst: Instance, now: float) -> bool:
        """Whether a running or draining instance is no longer usable: its container is
        gone or exited, or unhealthy with no lease held on it (CRASH_REASON). A health
        that cannot be read is no crash: the next check reads it again."""
        try:
            health = await asyncio.to_thread(self._health_sync, inst.container_id or inst.host)
        except Exception as e:  # noqa: BLE001 - Docker failing is not the sandbox failing
            logger.warning(f"[sandbox] the health of key={inst.key} instance={inst.instance} "
                           f"could not be read: {type(e).__name__}")
            return False
        if health in CRASHED_HEALTH:
            return True
        return health == "unhealthy" and not self._live_kinds(inst, now)

    def _new_instance_id(self, user_id: str) -> str:
        """Instance ids are 24 random bits, unique server-wide: the webapp pairs
        sessions and audit rows by `<instance>:<n>` and the agent routes
        `?sandbox=<instance>`, so an id any live or adopted instance of anyone
        holds (either view) is drawn again."""
        taken = {i.instance for i in self.instances()}
        for _ in range(INSTANCE_DRAWS):
            candidate = sc.new_instance()
            if candidate not in taken:
                return candidate
        raise SandboxStartError(sc.ERR_START_FAILED, "no free instance id")

    def _missing_compose_mounts(self) -> list:
        return [line for kind, line in COMPOSE_MOUNTS.items() if not self.host_bases.get(kind)]

    async def _start_locked(self, user_id: str, view: str, projects: tuple,
                            templates: Optional[tuple] = None) -> Instance:
        missing = self._missing_compose_mounts()
        if missing:
            self._warn_once("missing-mounts:" + ",".join(missing),
                            f"[sandbox] cannot start a sandbox: the recon-orchestrator service lacks "
                            f"the compose mount(s) {', '.join(missing)}; recreate it with ./redamon.sh up")
            raise SandboxStartError(sc.ERR_START_FAILED, "the orchestrator lacks a folder a sandbox mounts")
        api = _api_version(getattr(self.client.api, "api_version", None))
        if api is None or api < GW_PRIORITY_MIN_API:
            engine = await asyncio.to_thread(self._engine_version_sync)
            logger.error(f"[sandbox] refusing to start: Docker engine {engine} negotiates API "
                         f"{getattr(self.client.api, 'api_version', '?')}, and a guest's gateway "
                         f"priority needs API {GW_PRIORITY_MIN_API[0]}.{GW_PRIORITY_MIN_API[1]} or later")
            raise SandboxStartError(sc.ERR_START_FAILED, "the Docker engine is too old for sandbox networks")
        now = self.clock()
        instance = self._new_instance_id(user_id)
        inst = Instance(user_id=user_id, view=view, instance=instance, state="starting",
                        projects=projects, host=sc.container_name(user_id, view, instance),
                        key=sc.sandbox_key(user_id, view), network=sc.network_name(user_id, view),
                        created=now, last_used=now)
        # Listed before admission, so the reaper can never free its key between the
        # ledger committing it and this coroutine resuming.
        self._register(inst)
        try:
            result = await self.ledger.try_admit(inst.reservation_key, self._envelope(),
                                                 resource=sc.RESOURCE)
        except BaseException:
            self._unregister(inst)
            raise
        if not result.admitted:
            self._unregister(inst)
            logger.info(f"[sandbox] start refused key={inst.key} view={view}: "
                        f"{result.limit_type} - {result.detail}")
            raise SandboxRefused(result)
        try:
            await self._create_locked(inst, templates)
        except SandboxError as e:
            await self._abort_start(inst, e)
            raise
        except Exception as e:  # noqa: BLE001 - any Docker or OS failure
            err = SandboxStartError(sc.ERR_START_FAILED, "the sandbox could not be created")
            logger.warning(f"[sandbox] start of key={inst.key} instance={inst.instance} failed: "
                           f"{type(e).__name__}: {self._scrub(e, inst)}")
            await self._abort_start(inst, err)
            raise err from None
        self._spawn(self._finish_start(inst))
        return inst

    async def _create_locked(self, inst: Instance, templates: Optional[tuple] = None) -> None:
        image = await asyncio.to_thread(self._image_sync)
        if image is None:
            logger.error(f"[sandbox] cannot start key={inst.key}: {IMAGE_MISSING_DETAIL}")
            raise SandboxStartError(sc.ERR_IMAGE_MISSING, IMAGE_MISSING_DETAIL)
        # Before the templates wait (minutes on a first start), so the status of a
        # starting instance says which port it will have.
        async with self._alloc_lock:
            await asyncio.to_thread(self._network_sync, inst.user_id, inst.view)
            inst.pool_port, inst.reverse_port_state = await self._allocate_port(inst)
            inst.reverse_port = inst.pool_port or sc.DEFAULT_REVERSE_PORT
        await asyncio.to_thread(sandbox_templates.ensure_templates_ready, self.client, self.owner)
        await self._ensure_guests(inst.network, strict=True)
        custom = await asyncio.to_thread(self._copy_custom_templates_sync, inst.user_id,
                                         inst.view, templates)
        identities = await asyncio.to_thread(self._prepare_folders_sync, inst.user_id,
                                             inst.view, inst.projects, custom)
        servers = await asyncio.to_thread(self._servers_hash_sync)
        inst.servers = servers
        log_config = self._log_config(await asyncio.to_thread(self._daemon_facts_sync))
        for attempt in range(2):
            inst.reverse_port = inst.pool_port or sc.DEFAULT_REVERSE_PORT
            env = sc.container_env(inst.user_id, inst.view, inst.instance,
                                   reverse_port=inst.pool_port)
            inst.token = env[sc.ENV_MCP_AUTH_TOKEN]
            inst.tunnel_token = env[sc.ENV_TUNNEL_AUTH_TOKEN]
            kwargs = self._container_kwargs(inst, env, servers, custom, log_config)
            try:
                inst.container_id, inst.image_id = await asyncio.to_thread(self._create_start_sync, kwargs)
                break
            except APIError as e:
                busy = inst.pool_port is not None and any(
                    m in str(e).lower() for m in _PORT_BUSY_MARKERS)
                if not busy or attempt:
                    raise
                self._busy_ports[inst.pool_port] = self.clock() + BUSY_PORT_HOLD_S
                logger.info(f"[sandbox] pool port {inst.pool_port} is in use on the host; trying another")
                async with self._alloc_lock:
                    inst.pool_port, inst.reverse_port_state = await self._allocate_port(inst)
        # Only now that its container publishes the port is the person's hold on it
        # spent: a start that failed before (a busy host port, a crash) keeps it.
        self._release_hold(inst)
        # Docker resolves a bind source when it starts the container, and follows a
        # link: a folder swapped for a link and back around the start passes any
        # check made from outside. So what was mounted is read from inside, before
        # the instance can become running or a token leave this manager.
        problem = await asyncio.to_thread(self._verify_mounts_sync, inst.container_id, identities)
        if problem:
            logger.error(f"[sandbox] refusing key={inst.key} instance={inst.instance}: {problem}; removing it")
            raise SandboxStartError(sc.ERR_START_FAILED, "a mount of the sandbox is not the folder that was checked")

    @staticmethod
    def _log_config(daemon: Mapping) -> Optional[dict]:
        """The rotation every sandbox's container log gets, under the daemon's own
        default driver when it is one that rotates; None leaves another driver as
        the operator set it."""
        driver = daemon.get("log_driver") or ""
        if driver not in ROTATING_LOG_DRIVERS:
            return None
        return {"type": driver, "config": {"max-size": LOG_MAX_SIZE, "max-file": LOG_MAX_FILES}}

    def _container_kwargs(self, inst: Instance, env: dict, servers: str, custom: bool,
                          log_config: Optional[dict] = None) -> dict:
        labels = dict(COMPOSE_LABEL_OVERRIDES)
        labels.update(sc.container_labels(inst.user_id, inst.view, inst.instance, inst.projects,
                                          created=inst.created, port=inst.pool_port, servers=servers))
        labels[LABEL_OWNER] = self.owner
        healthcheck = sc.healthcheck(sc.START_TIMEOUT_S)
        # docker-py 7.2 drops it anyway; the start polls at the 2 s interval.
        healthcheck.pop("start_interval", None)
        kwargs = dict(
            # The hostname is a DNS name on the sandbox network the agent and the proxy
            # join, so it is the sandbox's own unique name; sc.SELF_NAME resolves only
            # inside, to the sandbox itself.
            image=sc.IMAGE, name=inst.host, hostname=inst.host, extra_hosts=dict(sc.EXTRA_HOSTS),
            detach=True,
            environment=env, labels=labels, mounts=self._mounts(inst, custom),
            network=inst.network, cap_add=list(sc.CAP_ADD), security_opt=list(sc.SECURITY_OPT),
            dns=list(sc.DNS), restart_policy=dict(sc.RESTART_POLICY), healthcheck=healthcheck,
            cpu_shares=SANDBOX_CPU_SHARES,
            # Docker's init as PID 1 reaps what a shell leaves behind; the image's
            # PID 1 (run_servers.py) does not, so orphans would stay zombies and
            # count against the pids limit until the sandbox stops.
            init=True,
            **sc.limits(self._envelope(), self.cpu_count()))
        pool = self._pool()
        if inst.pool_port is not None and pool is not None:
            kwargs["ports"] = sc.published_ports(inst.pool_port, pool.bind_ip)
        if log_config is not None:
            kwargs["log_config"] = docker.types.LogConfig(**log_config)
        return kwargs

    def _mounts(self, inst: Instance, custom: bool) -> list:
        mounts = []
        for m in sc.mount_targets(inst.user_id, inst.view, inst.projects,
                                  osv_volume=self.osv_volume, custom_templates=custom):
            if m.kind.startswith("volume:"):
                mounts.append(docker.types.Mount(m.target, m.rel, type="volume", read_only=m.read_only))
                continue
            base = self.host_bases.get(m.kind)
            if not base:
                raise SandboxStartError(sc.ERR_START_FAILED, f"the host path of {m.kind} is unknown")
            mounts.append(docker.types.Mount(m.target, join_host_path(base, *m.rel_parts()),
                                             type="bind", read_only=m.read_only))
        return mounts

    def _shared_templates_mount(self) -> Optional[tuple]:
        """The mount of the shared folder of every member's custom templates, as an
        older release gave every sandbox (normalized like _norm_mount), or None."""
        host = self.host_bases.get(sc.MOUNT_CUSTOM_TEMPLATES)
        if not host:
            return None
        return "bind", join_host_path(host), sc.CUSTOM_TEMPLATES_TARGET, True

    async def _finish_start(self, inst: Instance) -> None:
        try:
            code = await self._wait_healthy(inst, self._start_timeout_s)
        except Exception as e:  # noqa: BLE001 - an unreadable health is a failed start
            logger.warning(f"[sandbox] the health of key={inst.key} instance={inst.instance} "
                           f"could not be read: {type(e).__name__}")
            code = sc.ERR_START_FAILED
        async with self._user_lock(inst.user_id):
            # A start replaced before it was ready is draining: it still becomes
            # ready (its callers wait for it) and drains from there.
            if self.get_instance(inst.user_id, inst.instance) is not inst or \
                    inst.state not in ("starting", "draining"):
                return
            if code is None:
                if inst.state == "starting":
                    inst.state = "running"
                inst.last_used = self.clock()
                self._log("started", inst)
                inst.ready.set()
                return
            detail = ("the sandbox did not become healthy in time" if code == sc.ERR_START_TIMEOUT
                      else "the sandbox stopped or turned unhealthy while starting")
            inst.start_error = SandboxStartError(code, detail)
            await self._stop_locked(inst, "start_failed")

    async def _wait_healthy(self, inst: Instance, timeout_s: int) -> Optional[str]:
        """None once healthy, else the error code. Polls once a second."""
        for _ in range(max(1, int(timeout_s / HEALTH_POLL_S))):
            if self.get_instance(inst.user_id, inst.instance) is not inst:
                return sc.ERR_START_FAILED
            status = await asyncio.to_thread(self._health_sync, inst.container_id or inst.host)
            if status == "healthy":
                return None
            if status in ("unhealthy", "exited", "dead", "gone"):
                return sc.ERR_START_FAILED
            await self._sleep(HEALTH_POLL_S)
        return sc.ERR_START_TIMEOUT

    async def _abort_start(self, inst: Instance, err: SandboxError) -> None:
        inst.start_error = err
        await self._stop_locked(inst, "start_failed")

    # --- Stop -----------------------------------------------------------------

    async def _stop_locked(self, inst: Instance, reason: str) -> bool:
        """Stop and remove one instance, release its reservation, and remove the
        view's network when no instance of the view remains. Under the person's lock."""
        inst.state = "stopping"
        inst.stop_reason = reason
        if inst.start_error is None and not inst.ready.is_set():
            inst.start_error = SandboxStartError(sc.ERR_START_FAILED, "the sandbox was stopped while starting")
        removed = await asyncio.to_thread(self._remove_container_sync, inst)
        if not removed:
            # Kept, still holding its reservation: its container may still run.
            inst.ready.set()
            return False
        await self.ledger.release(inst.reservation_key)
        self._unregister(inst)
        self._hold_port(inst)
        if not self._view_instances(inst.user_id, inst.view):
            await asyncio.to_thread(self._remove_network_sync, inst.network)
        self._log("stopped", inst, reason)
        inst.ready.set()
        return True

    async def stop(self, user_id: str, instance: str, reason: str) -> int:
        """Stop one instance (no fence: an idle stop must not refuse a new start)."""
        self._check_reason(reason)
        try:
            sc.check_user_id(user_id)
        except ValueError as e:
            raise SandboxInvalid(str(e)) from None
        if not sc.valid_instance(instance):
            return 0
        return await self._shielded(self._stop_one(user_id, instance, reason))

    async def _stop_one(self, user_id: str, instance: str, reason: str) -> int:
        async with self._user_lock(user_id):
            inst = self.get_instance(user_id, instance)
            if inst is None:
                return 0
            return int(await self._stop_locked(inst, reason))

    async def stop_user(self, user_id: str, reason: str) -> int:
        """Stop both views of a person. ``account_deleted`` also deletes both views'
        output folders, found by key, with or without a running instance."""
        self._check_reason(reason)
        try:
            sc.check_user_id(user_id)
        except ValueError as e:
            raise SandboxInvalid(str(e)) from None
        for pending in self._pending.get(user_id, ()):
            pending.fenced = True
        return await self._shielded(self._stop_user(user_id, reason))

    async def _stop_user(self, user_id: str, reason: str) -> int:
        async with self._user_lock(user_id):
            stopped = 0
            for inst in self.instances(user_id):
                stopped += int(await self._stop_locked(inst, reason))
            if reason == sc.STOP_REASON_DELETES_OUTPUT:
                await asyncio.to_thread(self._delete_outputs_sync, user_id)
            return stopped

    async def stop_all(self, reason: str) -> int:
        self._check_reason(reason)
        for waiting in self._pending.values():
            for pending in waiting:
                pending.fenced = True
        return await self._shielded(self._stop_all(reason))

    def _people(self) -> list:
        """Everyone with an instance or an ensure on its way: a person whose last
        instance is being removed is briefly in neither list but still pending."""
        return sorted(set(self._by_user) | set(self._pending))

    async def _stop_all(self, reason: str) -> int:
        stopped = 0
        for user_id in self._people():
            async with self._user_lock(user_id):
                for inst in self.instances(user_id):
                    stopped += int(await self._stop_locked(inst, reason))
        return stopped

    async def stop_project(self, project_id: str, reason: str) -> int:
        """Stop every instance, of every person and view, that mounts the project
        (before its folder is purged, TD-27)."""
        self._check_reason(reason)
        try:
            sc.check_project_id(project_id)
        except ValueError as e:
            raise SandboxInvalid(str(e)) from None
        for waiting in self._pending.values():
            for pending in waiting:
                if project_id in pending.projects:
                    pending.fenced = True
        return await self._shielded(self._stop_project(project_id, reason))

    async def _stop_project(self, project_id: str, reason: str) -> int:
        stopped = 0
        for user_id in self._people():
            async with self._user_lock(user_id):
                for inst in self.instances(user_id):
                    if project_id in inst.projects:
                        stopped += int(await self._stop_locked(inst, reason))
        return stopped

    async def reconcile(self, user_id: str, projects, act_as_projects) -> int:
        """Stop every instance whose projects are not a subset of its view's list;
        start nothing."""
        try:
            sc.check_user_id(user_id)
            lists = {sc.VIEW_OWN: frozenset(sc.normalize_projects(projects)),
                     sc.VIEW_ACT_AS: frozenset(sc.normalize_projects(act_as_projects))}
        except ValueError as e:
            raise SandboxInvalid(str(e)) from None
        for pending in self._pending.get(user_id, ()):
            if not pending.projects <= lists[pending.view]:
                pending.fenced = True
        return await self._shielded(self._reconcile(user_id, lists))

    async def _reconcile(self, user_id: str, lists: dict) -> int:
        async with self._user_lock(user_id):
            stopped = 0
            for inst in self.instances(user_id):
                if not set(inst.projects) <= lists[inst.view]:
                    stopped += int(await self._stop_locked(inst, "access_lost"))
            return stopped

    # --- Status ---------------------------------------------------------------

    def status(self, user_id: str) -> dict:
        """Both views of a person, without tokens. ``lease_kinds`` lists unexpired
        leases only; ``stop_reason`` is set for an instance on its way out."""
        now = self.clock()
        out = []
        for inst in sorted(self.instances(user_id), key=lambda i: (i.view, i.created)):
            out.append({"instance": inst.instance, "view": inst.view, "state": inst.state,
                        "projects_hash": inst.projects_hash, "created_at": inst.created,
                        "last_used": inst.last_used,
                        "lease_kinds": sorted(self._live_kinds(inst, now)),
                        "stop_at": self._stop_at(inst, now),
                        "stop_reason": self._shown_stop_reason(inst),
                        "warn": self._warn(inst, now), "reverse_port": inst.reverse_port,
                        "reverse_port_state": inst.reverse_port_state})
        return {"instances": out}

    def list_running(self) -> list:
        """Running and draining instances with their address and token, for the
        agent (its session fan-out reaches a draining instance's sessions too, and
        its prompt reads a person's reverse port here without starting anything)."""
        return [{"user_id": i.user_id, "view": i.view, "instance": i.instance, "host": i.host,
                 "token": i.token, "state": i.state, "reverse_port": i.reverse_port,
                 "reverse_port_state": i.reverse_port_state}
                for i in self.instances() if i.state in ("running", "draining")]

    # --- Leases (B.8) ---------------------------------------------------------

    def _owner_of(self, instance: str) -> Optional[str]:
        for inst in self.instances():
            if inst.instance == instance:
                return inst.user_id
        return None

    async def lease(self, user_id: str, instance: str, lease_id: str, kind: str) -> dict:
        """Take or renew (one upsert keyed by ``lease_id``) a lease on one of the
        person's own instances, until ``LEASE_TTL_S`` from now. Under the person's
        lock, so a lease and the idle loop's stop never cross: whichever takes the
        lock first wins, and a lease after a stop is ``sandbox_not_running``.

        Another person's instance is ``unknown_instance`` (404); a stopping or gone
        one ``sandbox_not_running``; a draining one renews the ids it holds and
        refuses others (``sandbox_draining``). A kind in ``USE_KINDS`` is use."""
        try:
            sc.check_user_id(user_id)
        except ValueError as e:
            raise SandboxInvalid(str(e)) from None
        if kind not in sc.LEASE_KINDS or not isinstance(lease_id, str) or not _LEASE_ID.fullmatch(lease_id):
            raise SandboxInvalid(ERR_INVALID_LEASE, "not a valid lease id or kind")
        if not sc.valid_instance(instance):
            raise SandboxError(sc.ERR_UNKNOWN_INSTANCE, "no such sandbox instance")
        if user_id not in self._by_user:
            return self._lease_refusal(user_id, instance)
        async with self._user_lock(user_id):
            now = self.clock()
            inst = self.get_instance(user_id, instance)
            if inst is None or inst.state == "stopping":
                return self._lease_refusal(user_id, instance)
            self._prune(inst, now)
            if inst.state == "draining" and lease_id not in inst.leases and now >= inst.grace_until:
                raise SandboxError(sc.ERR_DRAINING, "this sandbox is being replaced; ask for the new one")
            expires = now + sc.LEASE_TTL_S
            inst.leases[lease_id] = (kind, expires)
            if kind in sc.USE_KINDS:
                inst.last_used = now
            inst.warn = self._warn(inst, now)
            return {"expires_at": expires, "state": inst.state, "stop_at": self._stop_at(inst, now),
                    "warn": inst.warn}

    def _lease_refusal(self, user_id: str, instance: str):
        owner = self._owner_of(instance)
        if owner is not None and owner != user_id:
            raise SandboxError(sc.ERR_UNKNOWN_INSTANCE, "no such sandbox instance")
        raise SandboxError(sc.ERR_NOT_RUNNING, "this sandbox is not running; ask for it again")

    async def release_lease(self, user_id: str, lease_id: str) -> int:
        """Drop the person's lease ``lease_id`` from every instance of theirs that
        holds it (idempotent). Ending a use lease is use: the idle timer counts
        from now."""
        try:
            sc.check_user_id(user_id)
        except ValueError as e:
            raise SandboxInvalid(str(e)) from None
        if not isinstance(lease_id, str) or not _LEASE_ID.fullmatch(lease_id) or user_id not in self._by_user:
            return 0
        async with self._user_lock(user_id):
            now = self.clock()
            dropped = 0
            for inst in self.instances(user_id):
                held = inst.leases.pop(lease_id, None)
                if held is None:
                    continue
                dropped += 1
                kind, expires = held
                if kind in sc.USE_KINDS and expires > now and inst.state != "stopping":
                    inst.last_used = max(inst.last_used, now)
            return dropped

    # --- Draining (B.7, TD-28) ------------------------------------------------

    def _mark_draining(self, inst: Instance, why: str) -> None:
        """Not current any more: new work goes to a new instance, and this one
        stops once its leases end (reason ``replaced``)."""
        inst.state = "draining"
        inst.stop_reason = DRAIN_REASON
        self._log(f"draining ({why})", inst, DRAIN_REASON)

    async def _stop_older_draining(self, user_id: str, view: str) -> None:
        """At most one draining instance per person and view: when a replacement
        starts while an older one still drains, the older one stops (``replaced``),
        else a new project per run kept alive by renewed leases would let one
        person hold any number of instances. Under the person's lock."""
        draining = [i for i in self._view_instances(user_id, view) if i.state == "draining"]
        for inst in sorted(draining, key=lambda i: i.seq)[:-1]:
            await self._stop_locked(inst, DRAIN_REASON)

    def _turn_off_replaced_tunnels(self, user_id: str, view: str) -> None:
        """Once a view has a new instance, its draining ones lose their tunnels:
        the webapp turns the person's tunnel setting off on that fresh start (the
        I19 rule), so no old instance may keep a tunnel up. A drain with no
        replacement yet (new code) keeps it, so sessions that came in through it
        live until then. Sent at once and again at every tick while it drains,
        one call at a time per instance, never queued behind a wedged daemon."""
        if self._current(user_id, view) is None:
            return
        for inst in self._view_instances(user_id, view):
            if inst.state != "draining" or not inst.tunnel_token:
                continue
            if inst.tunnel_future is not None and not inst.tunnel_future.done():
                continue
            if len(self._tunnel_pending) >= TUNNEL_WORKERS:
                return
            if self._tunnel_pool is None:
                self._tunnel_pool = concurrent.futures.ThreadPoolExecutor(
                    max_workers=TUNNEL_WORKERS, thread_name_prefix=TUNNEL_THREAD_PREFIX)
            future = self._tunnel_pool.submit(self._turn_off_tunnel_sync, inst)
            inst.tunnel_future = future
            self._tunnel_pending.add(future)
            future.add_done_callback(self._tunnel_pending.discard)
            self._spawn(self._await_tunnel_call(inst, future))

    async def _await_tunnel_call(self, inst: Instance, future: concurrent.futures.Future) -> None:
        try:
            await asyncio.wait_for(asyncio.shield(asyncio.wrap_future(future)), TUNNEL_CALL_DEADLINE_S)
        except asyncio.TimeoutError:
            # The thread stays busy until Docker answers; nothing is queued behind it.
            logger.warning(f"[sandbox] the Docker daemon did not answer the tunnel switch-off of "
                           f"key={inst.key} instance={inst.instance} within {TUNNEL_CALL_DEADLINE_S} s")

    def _turn_off_tunnel_sync(self, inst: Instance) -> None:
        """One step, on the tunnel pool: read how the previous switch-off ended,
        then send another, detached. Never raises."""
        if self.get_instance(inst.user_id, inst.instance) is not inst or inst.state != "draining":
            return
        api = self.client.api
        try:
            if inst.tunnel_exec:
                info = api.exec_inspect(inst.tunnel_exec) or {}
                if info.get("Running"):
                    return
                code = info.get("ExitCode")
                inst.tunnel_exec = None
                if code == 0:
                    if not inst.tunnel_confirmed:
                        inst.tunnel_confirmed = True
                        logger.info(f"[sandbox] tunnel turned off key={inst.key} view={inst.view} "
                                    f"instance={inst.instance} (replaced)")
                else:
                    self._warn_once(f"tunnel-exit:{inst.instance}:{code}",
                                    f"[sandbox] turning off the tunnel of key={inst.key} "
                                    f"instance={inst.instance} exited {code}; it is sent again")
            created = api.exec_create(inst.container_id or inst.host, ["python3", "-c", TUNNEL_OFF_SCRIPT],
                                      stdout=False, stderr=False,
                                      environment={TUNNEL_TOKEN_VAR: inst.tunnel_token})
            api.exec_start(created["Id"], detach=True)
            inst.tunnel_exec = created["Id"]
        except Exception as e:  # noqa: BLE001 - sent again at the next idle tick
            self._warn_once(f"tunnel-call:{inst.instance}:{type(e).__name__}",
                            f"[sandbox] could not turn off the tunnel of key={inst.key} "
                            f"instance={inst.instance}: {type(e).__name__}; it is sent again")

    async def _current_code(self) -> Optional[tuple]:
        """(id of the image IMAGE names, hash of the server code) for TD-28, or
        None when either cannot be read: a missing image or server folder drains
        nothing (the running instances keep working)."""
        try:
            image = await asyncio.to_thread(self._image_sync)
            if image is None or not os.path.isdir(self.local_bases.get(sc.MOUNT_SERVERS) or ""):
                return None
            return image.id, await asyncio.to_thread(self._servers_hash_sync, True)
        except Exception as e:  # noqa: BLE001 - checked again at the next tick
            logger.warning(f"[sandbox] cannot read the current sandbox image or server code: {type(e).__name__}")
            return None

    # --- The idle loop (B.7) --------------------------------------------------

    async def run_idle_loop(self, sleep: Optional[Callable] = None) -> None:
        """Every ``IDLE_CHECK_S``, until cancelled."""
        sleep = sleep or asyncio.sleep
        while True:
            await sleep(sc.IDLE_CHECK_S)
            try:
                await self.idle_tick()
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001 - the next tick tries again
                logger.warning(f"[sandbox] idle check failed: {type(e).__name__}")

    async def idle_tick(self) -> dict:
        """One pass: drain instances on old code (TD-28), stop what is idle, held
        too long without use, drained and finished, or left stopping by a failed
        removal; check both guests on every live network (TD-25); retry failed
        network removals. One failing person or network is logged and never
        stops the pass for the others."""
        code = await self._current_code()
        people = self._people()
        results = await asyncio.gather(*(self._shielded(self._tick_user(u, code)) for u in people),
                                       return_exceptions=True)
        summary = {"stopped": 0, "drained": 0, "failed": 0, "networks_removed": 0}
        for user_id, result in zip(people, results):
            if isinstance(result, BaseException):
                summary["failed"] += 1
                logger.warning(f"[sandbox] idle check of key={sc.sandbox_key(user_id, sc.VIEW_OWN)} "
                               f"failed: {type(result).__name__}")
                continue
            summary["stopped"] += result[0]
            summary["drained"] += result[1]
        try:
            summary["networks_removed"] = await self._retry_network_removals()
        except Exception as e:  # noqa: BLE001
            logger.warning(f"[sandbox] network removal retry failed: {type(e).__name__}")
        return summary

    async def _tick_user(self, user_id: str, code: Optional[tuple]) -> tuple:
        async with self._user_lock(user_id):
            now = self.clock()
            drained = stopped = 0
            for inst in self.instances(user_id):
                self._prune(inst, now)
            if code is not None:
                image_id, servers = code
                for inst in self.instances(user_id):
                    if inst.state != "running":
                        continue
                    if inst.image_id and inst.image_id != image_id:
                        self._mark_draining(inst, "new image")
                    elif inst.servers and inst.servers != servers:
                        self._mark_draining(inst, "new server code")
                    else:
                        continue
                    drained += 1
            for inst in self.instances(user_id):
                if (inst.state in ("running", "draining") and inst.ready.is_set()
                        and await self._crashed(inst, now)):
                    stopped += int(await self._stop_locked(inst, CRASH_REASON))
                    continue
                reason = self._idle_reason(inst, now)
                if reason is not None:
                    stopped += int(await self._stop_locked(inst, reason))
                else:
                    inst.warn = self._warn(inst, now)
            for view in sc.VIEWS:
                self._turn_off_replaced_tunnels(user_id, view)
            networks = {i.network for i in self.instances(user_id) if i.state != "stopping"}
            for network in sorted(networks):
                try:
                    await asyncio.to_thread(self._guests_sync, network, False, True)
                except Exception as e:  # noqa: BLE001 - the next ensure or tick retries
                    logger.warning(f"[sandbox] guest check of {network} failed: {type(e).__name__}")
            return stopped, drained

    def _idle_reason(self, inst: Instance, now: float) -> Optional[str]:
        """B.7's decision for one instance: the stop reason, or None to keep it."""
        if inst.state == "stopping":
            # A removal that failed earlier (the container already killed and cut off).
            return inst.stop_reason if inst.stop_reason in sc.STOP_REASONS else "operator"
        if not inst.ready.is_set():
            # Its start check normally settles it; one that never did holds a
            # reservation and blocks every ensure of the view.
            if now - inst.created >= self._start_timeout_s + START_STUCK_GRACE_S:
                return "start_failed"
            return None
        if inst.state not in ("running", "draining"):
            return None
        kinds = self._live_kinds(inst, now)
        if kinds - {sc.HOLD_LEASE_KIND}:
            return None
        if sc.HOLD_LEASE_KIND in kinds:
            # Sessions or a tunnel hold it, a draining one too, for at most eight
            # hours without use (D24).
            return "hold_unused" if now - inst.last_used >= sc.HOLD_MAX_NO_USE_S else None
        if now < inst.grace_until:
            return None
        if inst.state == "draining":
            return inst.stop_reason if inst.stop_reason in sc.STOP_REASONS else DRAIN_REASON
        return "idle" if now - inst.last_used >= self._idle_s() else None

    async def _retry_network_removals(self) -> int:
        """Under the allocation lock: a start re-uses its view's network (found by
        name under this same lock), so a removal never pulls one from under it."""
        if not self._network_retry:
            return 0
        async with self._alloc_lock:
            live = {i.network for i in self.instances()}
            return await asyncio.to_thread(self.retry_network_removals, live)

    # --- Guests ---------------------------------------------------------------

    async def _ensure_guests(self, network: str, *, strict: bool) -> None:
        await asyncio.to_thread(self._guests_sync, network, strict)

    async def attach_capture_proxy_everywhere(self) -> int:
        """TD-25 for a capture proxy the orchestrator has just (re)started: a new
        container, on no sandbox network. Each live network gets the guest check,
        which attaches the proxy only when it forwards nothing and refuses the
        pool. Under each person's lock, as the idle loop's check; one failing
        network is logged and never stops the others. Returns the networks checked."""
        people = self._people()
        results = await asyncio.gather(*(self._shielded(self._attach_guests_of(u)) for u in people),
                                       return_exceptions=True)
        return sum(r for r in results if isinstance(r, int))

    async def _attach_guests_of(self, user_id: str) -> int:
        checked = 0
        async with self._user_lock(user_id):
            networks = {i.network for i in self.instances(user_id) if i.state != "stopping"}
            for network in sorted(networks):
                try:
                    await asyncio.to_thread(self._guests_sync, network, False, True)
                    checked += 1
                except Exception as e:  # noqa: BLE001 - the idle loop retries
                    logger.warning(f"[sandbox] guest check of {network} failed: {type(e).__name__}")
        return checked

    def _guests_sync(self, network: str, strict: bool, force: bool = False) -> None:
        """TD-23..25: the agent (alias ``agent``) and the capture proxy on the
        network, each only when it cannot forward between its networks, the proxy
        only when it refuses the sandbox pool, both at a gateway priority that
        keeps their default route where it is. A recreated guest is a new
        container: it is attached again; so is one attached at another priority
        (by hand, or by an engine that ignored it). ``force`` skips the cache (the
        idle loop's check)."""
        agents = self._find_agents_sync()
        proxy = self._find_proxy_sync()
        eligible = []
        for agent in agents:
            missing = self._missing_sysctls(agent)
            if missing:
                logger.error(f"[sandbox] the agent container {agent.name} lacks {missing} in its sysctls, "
                             f"so it could route between networks; it is not attached to a sandbox network")
                continue
            eligible.append((agent, [sc.AGENT_ALIAS]))
        # Replicas of the agent service are attached one by one; the start fails
        # only when none of them may join (the agent could never reach the sandbox).
        if strict and agents and not eligible:
            raise SandboxStartError(sc.ERR_START_FAILED, "the agent container may forward packets")
        if not agents:
            self._warn_once("no-agent", "[sandbox] no agent container found to attach to sandbox networks")
        if proxy is not None:
            missing = self._missing_sysctls(proxy)
            if missing:
                self._warn_once(f"proxy-sysctl:{proxy.id}",
                                f"[sandbox] the capture proxy lacks {missing} in its sysctls; "
                                f"it is left off sandbox networks")
            elif not self._proxy_refuses_pool(proxy):
                self._warn_once(f"proxy-pool:{proxy.id}",
                                f"[sandbox] the capture proxy's CAPTURE_BLOCKED_IPS does not hold "
                                f"{sc.SUBNET_POOL}; it is left off sandbox networks")
            else:
                problem = self._proxy_build_problem(proxy)
                if problem:
                    self._warn_once(f"proxy-build:{proxy.id}",
                                    f"[sandbox] the capture proxy {problem}; it is left off sandbox networks")
                else:
                    eligible.append((proxy, None))
        ids = frozenset(c.id for c, _ in eligible)
        cached = self._guest_cache.get(network)
        if not force and cached and self.clock() - cached[0] < sc.IDLE_CHECK_S and ids <= cached[1]:
            return
        net = self.client.networks.get(network)
        net.reload()
        attached = set((net.attrs.get("Containers") or {}).keys())
        for container, aliases in eligible:
            if container.id in attached:
                endpoint = ((((container.attrs or {}).get("NetworkSettings") or {}).get("Networks") or {})
                            .get(network) or {})
                priority = endpoint.get("GwPriority", 0)
                if priority == sc.GUEST_GATEWAY_PRIORITY:
                    continue
                logger.warning(f"[sandbox] a guest on {network} has gateway priority {priority}, not "
                               f"{sc.GUEST_GATEWAY_PRIORITY}; attaching it again")
                net.disconnect(container.id, force=True)
            self._connect_sync(net, container, aliases)
        self._guest_cache[network] = (self.clock(), ids)

    def _find_agents_sync(self) -> list:
        """Every running replica compose created for this stack's ``agent``
        service; else the container named ``redamon-agent``, when it is this
        stack's compose replica or carries no compose label at all (an agent
        started without compose). A copy of the agent image started any other
        way is never the agent, whatever its name or sysctls."""
        found = []
        if self.own_compose_project:
            # docker-py inspects each listed container: without ignore_removed, one
            # removed in between (a broker caller may churn any labels) raises.
            listed = self.client.containers.list(ignore_removed=True, filters={"label": [
                f"{sc.COMPOSE_SERVICE_LABEL}={sc.AGENT_COMPOSE_SERVICE}",
                f"{sc.COMPOSE_PROJECT_LABEL}={self.own_compose_project}"]})
            found = [c for c in listed if self._compose_replica(c)]
        if not found:
            try:
                c = self.client.containers.get(sc.AGENT_CONTAINER_NAME)
            except NotFound:
                return []
            labels = c.labels or {}
            if c.status != "running" or labels.get(BROKER_OWNED_LABEL) or self._one_off(c):
                return []
            if labels.get(sc.COMPOSE_PROJECT_LABEL) or labels.get(sc.COMPOSE_SERVICE_LABEL):
                if not (self.own_compose_project and self._compose_replica(c)
                        and labels.get(sc.COMPOSE_PROJECT_LABEL) == self.own_compose_project):
                    return []
            found = [c]
        return found

    @classmethod
    def _compose_replica(cls, container) -> bool:
        """Created by compose as a service replica: not a one-off, not through
        the broker (which lets a scan write any label but its own)."""
        labels = container.labels or {}
        return bool(labels.get(COMPOSE_CONFIG_HASH_LABEL)) \
            and str(labels.get(COMPOSE_NUMBER_LABEL) or "").isdigit() \
            and not cls._one_off(container) and not labels.get(BROKER_OWNED_LABEL)

    @staticmethod
    def _one_off(container) -> bool:
        return str((container.labels or {}).get(COMPOSE_ONEOFF_LABEL, "")).lower() == "true"

    def _find_proxy_sync(self):
        try:
            c = self.client.containers.get(sc.CAPTURE_PROXY_NAME)
        except NotFound:
            return None
        if c.status != "running" or (c.labels or {}).get(BROKER_OWNED_LABEL):
            return None
        return c

    @staticmethod
    def _missing_sysctls(container) -> list:
        have = ((container.attrs or {}).get("HostConfig") or {}).get("Sysctls") or {}
        return [f"{k}={v}" for k, v in sc.GUEST_SYSCTLS.items() if str(have.get(k)) != v]

    @staticmethod
    def _proxy_refuses_pool(container) -> bool:
        env = _env_dict(((container.attrs or {}).get("Config") or {}).get("Env"))
        pool = ipaddress.ip_network(sc.SUBNET_POOL)
        for entry in (env.get("CAPTURE_BLOCKED_IPS") or "").split(","):
            try:
                net = ipaddress.ip_network(entry.strip(), strict=False)
            except ValueError:
                continue
            if net.version == pool.version and pool.subnet_of(net):
                return True
        return False

    def _proxy_build_problem(self, container) -> Optional[str]:
        """Why the proxy is not the one the orchestrator starts, or None: it must
        run the current proxy image's id, and mitmdump with raw TCP relaying off
        (a stream after CONNECT that is not HTTP would pass the egress guard,
        which reads HTTP only, to any address another sandbox's included)."""
        try:
            current = self.client.images.get(capture_proxy_image())
        except (ImageNotFound, NotFound, APIError):
            return "image is missing, so its code cannot be checked"
        attrs = container.attrs or {}
        if attrs.get("Image") != current.id:
            return "does not run the current capture proxy image"
        config = attrs.get("Config") or {}
        cmd = [str(t) for t in config.get("Cmd") or []]
        if config.get("Entrypoint") or not cmd or cmd[0] != "mitmdump":
            return "does not run mitmdump as the orchestrator starts it"
        rawtcp = [i for i, token in enumerate(cmd) if "rawtcp" in token]
        if len(rawtcp) != 1 or cmd[rawtcp[0]] != "rawtcp=false" or cmd[rawtcp[0] - 1] != "--set":
            return "may relay raw TCP (its command does not set rawtcp=false once)"
        return None

    def _connect_sync(self, net, container, aliases) -> None:
        api = self.client.api
        version = _api_version(getattr(api, "api_version", None))
        if version is None or version < GW_PRIORITY_MIN_API:
            raise SandboxStartError(sc.ERR_START_FAILED, "the Docker engine is too old for sandbox networks")
        endpoint = {"GwPriority": sc.GUEST_GATEWAY_PRIORITY}
        if aliases:
            endpoint["Aliases"] = list(aliases)
        body = {"Container": container.id, "EndpointConfig": endpoint}
        res = api.post(api._url("/networks/{0}/connect", net.id), data=json.dumps(body),
                       headers={"Content-Type": "application/json"})
        try:
            api._raise_for_status(res)
        except APIError as e:
            if "already exists" not in str(e):
                raise

    # --- Docker, in threads ---------------------------------------------------

    def _engine_version_sync(self) -> str:
        try:
            return str(self.client.version().get("Version", "?"))
        except Exception:  # noqa: BLE001 - only for the log line
            return "?"

    def _image_sync(self):
        try:
            return self.client.images.get(sc.IMAGE)
        except (ImageNotFound, NotFound):
            return None

    def _network_sync(self, user_id: str, view: str):
        """The view's network, created in the lowest free /28 when missing. A
        network of that name the orchestrator did not make is never used."""
        name = sc.network_name(user_id, view)
        try:
            net = self.client.networks.get(name)
        except NotFound:
            net = None
        key = sc.sandbox_key(user_id, view)
        if net is not None:
            problem = self._network_problem(net, user_id, view)
            if problem:
                logger.error(f"[sandbox] the existing sandbox network of key={key} is not used: {problem}")
                raise SandboxStartError(sc.ERR_START_FAILED, "the sandbox network name is taken")
            return net
        used = []
        for other in self.client.networks.list():
            for cfg in (((other.attrs or {}).get("IPAM") or {}).get("Config") or []):
                used.append(cfg.get("Subnet"))
        try:
            subnet = sc.allocate_subnet(used)
        except sc.SubnetPoolExhausted:
            raise SandboxStartError(sc.ERR_START_FAILED, "no free sandbox subnet") from None
        ipam = docker.types.IPAMConfig(pool_configs=[
            docker.types.IPAMPool(subnet=subnet, gateway=sc.gateway_for(subnet))])
        self._guest_cache.pop(name, None)
        net = self.client.networks.create(name, driver=sc.NETWORK_DRIVER, internal=sc.NETWORK_INTERNAL,
                                          labels=self._network_labels(user_id, view), ipam=ipam,
                                          check_duplicate=True, options=dict(NETWORK_OPTIONS))
        # What the engine made, not what was asked: a daemon that ignores the
        # option still turns IPv6 on.
        problem = self._network_problem(net, user_id, view)
        if problem:
            logger.error(f"[sandbox] the new sandbox network of key={key} is removed: {problem}")
            self._remove_network_sync(name)
            raise SandboxStartError(sc.ERR_START_FAILED, "the sandbox network could not be made IPv4-only")
        return net

    def _network_problem(self, net, user_id: str, view: str) -> Optional[str]:
        """Why ``net`` is not the view's sandbox network as this orchestrator makes
        it, or None: its name and labels (owner included, no broker label), a plain
        bridge, IPv6 off, and IPv4 subnets of the sandbox pool only."""
        attrs = net.attrs or {}
        labels = attrs.get("Labels") or {}
        if attrs.get("Name") != sc.network_name(user_id, view) or labels.get(BROKER_OWNED_LABEL) or \
                any(labels.get(k) != v for k, v in self._network_labels(user_id, view).items()):
            return "it is not this orchestrator's network"
        if attrs.get("Driver") != sc.NETWORK_DRIVER or attrs.get("Internal"):
            return "it is not a plain bridge"
        if attrs.get("EnableIPv6"):
            return "it has IPv6 on"
        pool = ipaddress.ip_network(sc.SUBNET_POOL)
        subnets = [c.get("Subnet") for c in ((attrs.get("IPAM") or {}).get("Config") or [])]
        for subnet in subnets:
            try:
                cidr = ipaddress.ip_network(subnet, strict=False)
            except (TypeError, ValueError):
                return "its subnet is unreadable"
            if cidr.version != pool.version or not cidr.subnet_of(pool):
                return "a subnet is not an IPv4 subnet of the sandbox pool"
        return None if subnets else "it has no subnet"

    def _network_problem_by_name_sync(self, user_id: str, view: str) -> Optional[str]:
        try:
            net = self.client.networks.get(sc.network_name(user_id, view))
        except NotFound:
            return "its network is gone"
        return self._network_problem(net, user_id, view)

    def _network_labels(self, user_id: str, view: str) -> dict:
        return {**sc.network_labels(user_id, view), LABEL_OWNER: self.owner}

    def _remove_network_sync(self, name: str) -> bool:
        """Disconnect every endpoint (guests, a lab an operator connected), then
        remove. A failure is kept for the idle loop to retry; its /28 stays taken."""
        self._guest_cache.pop(name, None)
        try:
            net = self.client.networks.get(name)
            net.reload()
            labels = net.attrs.get("Labels") or {}
            if labels.get(sc.LABEL_SANDBOX) != sc.LABEL_TRUE or labels.get(BROKER_OWNED_LABEL) \
                    or labels.get(LABEL_OWNER) != self.owner:
                logger.warning(f"[sandbox] network {name} is not this orchestrator's; left in place")
                self._network_retry.discard(name)
                return True
            for cid in list((net.attrs.get("Containers") or {}).keys()):
                try:
                    net.disconnect(cid, force=True)
                except NotFound:
                    pass
            net.remove()
        except NotFound:
            pass
        except Exception as e:  # noqa: BLE001 - logged and retried
            logger.warning(f"[sandbox] could not remove network {name}: {type(e).__name__}; will retry")
            self._network_retry.add(name)
            return False
        self._network_retry.discard(name)
        return True

    def retry_network_removals(self, live: Optional[set] = None) -> int:
        """Blocking: retry the removals that failed, leaving a network a live
        instance uses. The idle loop calls it in a thread under the allocation
        lock, with ``live`` read in the event loop."""
        if live is None:
            live = {i.network for i in self.instances()}
        return sum(1 for name in list(self._network_retry)
                   if name not in live and self._remove_network_sync(name))

    def _create_start_sync(self, kwargs: dict) -> tuple:
        """(container id, the id of the image it was made from: the tag may move
        between the image check and the create)."""
        container = self.client.containers.create(**kwargs)
        try:
            container.start()
        except Exception:
            try:
                container.remove(force=True)
            except Exception:  # noqa: BLE001 - the start error is the one to report
                pass
            raise
        return container.id, (container.attrs or {}).get("Image")

    def _health_sync(self, ref: str) -> str:
        try:
            c = self.client.containers.get(ref)
            c.reload()
        except NotFound:
            return "gone"
        state = (c.attrs or {}).get("State") or {}
        if state.get("Status") in ("exited", "dead"):
            return state["Status"]
        return ((state.get("Health") or {}).get("Status")) or "starting"

    def _remove_container_sync(self, inst: Instance) -> bool:
        try:
            c = self.client.containers.get(inst.container_id or inst.host)
        except NotFound:
            return True
        try:
            try:
                c.stop(timeout=sc.STOP_GRACE_S)
            except APIError:
                pass
            c.remove(force=True)
            return True
        except NotFound:
            return True
        except Exception as e:  # noqa: BLE001 - kept registered, retried
            logger.warning(f"[sandbox] could not remove key={inst.key} instance={inst.instance}: "
                           f"{type(e).__name__}: {self._scrub(e, inst)}")
        self._contain_sync(c, inst)
        return False

    def _contain_sync(self, c, inst: Instance) -> None:
        """A container that could not be removed is killed and taken off its
        network, so what it mounts (a project access was just lost to) is out of
        reach before the idle loop retries the removal. Best effort."""
        try:
            c.kill()
        except Exception as e:  # noqa: BLE001 - already stopped, or Docker failing
            logger.warning(f"[sandbox] could not kill key={inst.key} instance={inst.instance}: {type(e).__name__}")
        try:
            self.client.networks.get(inst.network).disconnect(c.id, force=True)
        except Exception as e:  # noqa: BLE001
            logger.warning(f"[sandbox] could not disconnect key={inst.key} instance={inst.instance}: "
                           f"{type(e).__name__}")

    # --- Pool ports -----------------------------------------------------------

    def _pool(self):
        raw = os.environ.get(sc.PORT_POOL_ENV)
        pool = sc.port_pool(raw)
        if pool is None and raw and raw.strip():
            self._warn_once(f"pool:{raw}", f"[sandbox] {sc.PORT_POOL_ENV} is malformed; no pool port is published")
        return pool

    async def _allocate_port(self, inst: Instance) -> tuple:
        """(port, reverse_port_state) for ``inst``, under the allocation lock: the
        port held for its person and view when one is free (the one they used last),
        else the lowest pool port nobody uses and nobody else holds. A port held for
        another person is never given out: with only those left the instance starts
        without one (``pool_full``). A port the sandbox serves itself (4040's
        unauthenticated ngrok API above all) is never one."""
        pool = self._pool()
        if pool is None:
            return None, sc.REVERSE_PORT_NO_POOL
        now = self.clock()
        usable = self._usable_ports(pool, now, await asyncio.to_thread(self._labelled_ports_sync))
        holds = self._live_holds(now)
        own = [p for p in usable if holds.get(p) == inst.key]
        if own:
            port = max(own, key=lambda p: (self._port_holds[p][1], -p))
        else:
            free = [p for p in usable if p not in holds]
            if not free:
                held = sum(1 for p in usable if p in holds)
                logger.warning(f"[sandbox] the port pool is full for key={inst.key} view={inst.view} "
                               f"instance={inst.instance}: {len(pool.ports()) - len(usable)} in use, "
                               f"{held} held for other persons; it starts without a reverse-shell port")
                return None, sc.REVERSE_PORT_POOL_FULL
            port = free[0]
        return port, sc.REVERSE_PORT_ASSIGNED

    def _usable_ports(self, pool, now: float, labelled: set) -> list:
        """The pool ports no instance uses, no sandbox container is labelled with, the
        host does not hold busy and the sandbox does not serve itself; a hold decides
        who of them may get one."""
        taken = {i.pool_port for i in self.instances() if i.pool_port}
        taken |= {p for p, until in self._busy_ports.items() if until > now}
        taken |= set(sc.PORTS.values()) | set(sc.HEALTH_PROBE_PORTS)
        taken |= labelled
        return [p for p in pool.ports() if p not in taken]

    def _port_for(self, key: str, labelled: set, promised: set) -> Optional[int]:
        """A pool port a start of this person and view would get now, past those
        ``promised`` to others already, or None."""
        pool = self._pool()
        if pool is None:
            return None
        now = self.clock()
        holds = self._live_holds(now)
        ports = [p for p in self._usable_ports(pool, now, labelled)
                 if p not in promised and holds.get(p, key) == key]
        return ports[0] if ports else None

    # --- Pool port holds (D-A) ------------------------------------------------

    def _hold_s(self) -> int:
        return sc.port_hold_hours(os.environ.get(sc.PORT_HOLD_HOURS_ENV)) * 3600

    def _live_holds(self, now: float) -> dict:
        """{port: sandbox key} of the holds not yet over (the hold time is read now,
        so a changed KALI_SANDBOX_PORT_HOLD_HOURS applies to every hold)."""
        hold_s = self._hold_s()
        return {port: key for port, (key, since) in self._port_holds.items() if now < since + hold_s}

    def _release_hold(self, inst: Instance) -> None:
        held = self._port_holds.get(inst.pool_port) if inst.pool_port is not None else None
        if held is not None and held[0] == inst.key:
            del self._port_holds[inst.pool_port]
            self._holds_changed()

    def _hold_port(self, inst: Instance) -> None:
        """A stopped instance's pool port goes to nobody else for the hold time."""
        if inst.pool_port is None or self._hold_s() <= 0:
            return
        self._port_holds[inst.pool_port] = (inst.key, self.clock())
        logger.info(f"[sandbox] pool port {inst.pool_port} held for key={inst.key} view={inst.view} "
                    f"for {self._hold_s() // 3600} h")
        self._holds_changed()

    def _hold_removed_port(self, container) -> bool:
        """At adoption, a sandbox removed as not adoptable (an exited one after a host
        restart, above all) held its pool port as much as one stopped here. Its
        labels name the port and person; a container made through the broker can
        carry any label, so it holds nothing."""
        labels = container.labels or {}
        user_id, view, raw = labels.get(sc.LABEL_USER), labels.get(sc.LABEL_VIEW), labels.get(sc.LABEL_PORT) or ""
        if labels.get(BROKER_OWNED_LABEL) or not sc.valid_user_id(user_id) or view not in sc.VIEWS \
                or not re.fullmatch(r"[0-9]{1,5}", raw) or not 1 <= int(raw) <= 65535 or self._hold_s() <= 0:
            return False
        self._port_holds[int(raw)] = (sc.sandbox_key(user_id, view), self.clock())
        return True

    def _holds_changed(self) -> None:
        """Drop the holds that are over and save the rest, in a thread."""
        now, hold_s = self.clock(), self._hold_s()
        for port, (_, since) in list(self._port_holds.items()):
            if now >= since + hold_s:
                del self._port_holds[port]
        self._holds_version += 1
        self._spawn(asyncio.to_thread(self._save_port_holds_sync, self._holds_version,
                                      dict(self._port_holds)))

    def _holds_folder(self) -> Optional[str]:
        """The output folder as the orchestrator sees it, when compose mounts it (its
        host path is known): without the mount /app/mcp-output is a folder of the
        source tree, which git does not ignore, and the holds stay in memory."""
        if not self.host_bases.get(sc.MOUNT_OUTPUT):
            return None
        return self.local_bases.get(sc.MOUNT_OUTPUT) or None

    def _save_port_holds_sync(self, version: int, holds: dict) -> None:
        """Write one snapshot, unless a newer one was written already (the threads
        may run out of order): the file, then its copy, each synced and renamed into
        place, then the folder synced. Never follows a link; never raises."""
        folder = self._holds_folder()
        if folder is None:
            return
        with self._holds_lock:
            if version <= self._holds_written:
                return
            body = json.dumps({"holds": [{"port": port, "key": key, "since": since}
                                         for port, (key, since) in sorted(holds.items())]}).encode()
            try:
                dir_fd = self._open_folder(folder, (), create=False)
            except _UnsafeFolder:
                self._warn_once("holds-write", "[sandbox] the output folder cannot be opened; the pool port "
                                               "holds last until the orchestrator restarts")
                return
            try:
                for name in (PORT_HOLDS_FILE, PORT_HOLDS_COPY):
                    self._write_synced(dir_fd, name, body)
                os.fsync(dir_fd)
                self._holds_written = version
            except OSError as e:
                self._warn_once("holds-write", f"[sandbox] the pool port holds cannot be saved in the output "
                                               f"folder ({type(e).__name__}); they last until a restart")
            finally:
                os.close(dir_fd)

    @staticmethod
    def _write_synced(dir_fd: int, name: str, body: bytes) -> None:
        # Whatever sits at the temporary name (a planted FIFO or link) is removed,
        # and the new file is created exclusively, so nothing there is opened.
        tmp = name + ".tmp"
        try:
            os.unlink(tmp, dir_fd=dir_fd)
        except FileNotFoundError:
            pass
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600,
                     dir_fd=dir_fd)
        try:
            view = memoryview(body)
            while view:
                view = view[os.write(fd, view):]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)

    @staticmethod
    def _read_holds(dir_fd: int, name: str):
        """The entries of one holds file, None when it does not exist; ValueError
        when it is there but unreadable (a link, not a file, too large, not JSON)."""
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
        except FileNotFoundError:
            return None
        except OSError as e:
            raise ValueError(type(e).__name__) from None
        try:
            with os.fdopen(fd, "rb") as f:
                if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                    raise ValueError("not a file")
                raw = f.read(PORT_HOLDS_MAX_BYTES + 1)
        except OSError as e:
            raise ValueError(type(e).__name__) from None
        if len(raw) > PORT_HOLDS_MAX_BYTES:
            raise ValueError("too large")
        try:
            entries = json.loads(raw)["holds"]
        except (ValueError, KeyError, TypeError) as e:
            raise ValueError(type(e).__name__) from None
        if not isinstance(entries, list):
            raise ValueError("not a list")
        return entries

    def _load_port_holds_sync(self) -> None:
        """The holds saved before a restart: the file, else its copy. Only when both
        are unreadable does the orchestrator run with no hold, and it says so loudly;
        the start never fails on it. A hold dated in the future counts from now."""
        folder = self._holds_folder()
        if folder is None:
            self._warn_once("holds-memory", "[sandbox] the output folder is not mounted: the pool port holds "
                                            "last until the orchestrator restarts")
            return
        try:
            dir_fd = self._open_folder(folder, (), create=False)
        except _UnsafeFolder:
            return
        damaged = []
        entries = None
        try:
            for name in (PORT_HOLDS_FILE, PORT_HOLDS_COPY):
                try:
                    entries = self._read_holds(dir_fd, name)
                except ValueError as e:
                    damaged.append(f"{name} ({e})")
                    continue
                if entries is not None:
                    break
        finally:
            os.close(dir_fd)
        if entries is None:
            if damaged:
                logger.error(f"[sandbox] the pool port holds are unreadable ({', '.join(damaged)}): none is "
                             f"kept, so a port whose sandbox stopped in the last {self._hold_s() // 3600} h "
                             f"can go to another person")
            return
        if damaged:
            logger.warning(f"[sandbox] the pool port holds file is unreadable ({damaged[0]}); its last good "
                           f"copy is used")
        now = self.clock()
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            port, key, since = entry.get("port"), entry.get("key"), entry.get("since")
            if (isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535
                    and isinstance(key, str) and _SANDBOX_KEY.fullmatch(key)
                    and isinstance(since, (int, float)) and not isinstance(since, bool)
                    and since == since):
                self._port_holds[port] = (key, min(float(since), now))

    def _labelled_ports_sync(self) -> set:
        """The ports sandbox-labelled containers name, whoever made them. A label that
        is not a port (a broker-made container may carry any) is skipped: it must
        never fail every pool start."""
        ports = set()
        for c in self.client.containers.list(all=True, ignore_removed=True,
                                             filters={"label": f"{sc.LABEL_SANDBOX}={sc.LABEL_TRUE}"}):
            raw = (c.labels or {}).get(sc.LABEL_PORT) or ""
            if isinstance(raw, str) and re.fullmatch(r"[0-9]{1,5}", raw):
                ports.add(int(raw))
        return ports

    # --- Folders --------------------------------------------------------------

    def _bind_chains(self, user_id: str, view: str, projects, custom: bool) -> list:
        """(target inside the sandbox, local base, components, make it when
        missing, the mode of a folder it makes) of every bind. The custom
        templates copy is made by the copy."""
        output = self.local_bases[sc.MOUNT_OUTPUT]
        chains = [(f"{sc.WORKSPACE_ROOT}/{p}", self.local_bases[sc.MOUNT_WORKSPACE], (p,), True,
                   WORKSPACE_LEAF_MODE) for p in projects]
        chains.append((sc.OUTPUT_TARGET, output, tuple(sc.output_rel(user_id, view).split("/")), True,
                       OUTPUT_LEAF_MODE))
        chains += [(target, self.local_bases[kind], (), False, None) for target, kind in
                   ((sc.SERVERS_TARGET, sc.MOUNT_SERVERS), (sc.GRAPH_DB_TARGET, sc.MOUNT_GRAPH_DB))]
        if custom:
            chains.append((sc.CUSTOM_TEMPLATES_TARGET, output,
                           tuple(sc.custom_templates_rel(user_id, view).split("/")), False, None))
        return chains

    @staticmethod
    def _open_folder(base, parts, create: bool, leaf_mode: int = WORKSPACE_LEAF_MODE,
                     tighten: bool = False) -> int:
        """A descriptor of ``base/parts...`` (``base`` a path, or a folder
        descriptor), opened one component at a time, never following a link,
        making a missing component when ``create``: the last one ``leaf_mode``
        (0777 by default: the agent and the sandbox both write it), one above it
        0755 (only the orchestrator adds to ``users/``), set through the descriptor
        so the umask cannot narrow them. ``tighten`` also narrows an existing last
        folder of the orchestrator's own to ``leaf_mode`` (one an older release made
        0777). A link or a non-folder anywhere raises ``_UnsafeFolder``."""
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        try:
            fd = os.dup(base) if isinstance(base, int) else os.open(base, flags)
        except OSError as e:
            raise _UnsafeFolder(str(base)) from e
        try:
            for index, name in enumerate(parts):
                made = False
                if create:
                    try:
                        os.mkdir(name, 0o700, dir_fd=fd)
                        made = True
                    except FileExistsError:
                        pass
                try:
                    child = os.open(name, flags, dir_fd=fd)
                except OSError as e:
                    raise _UnsafeFolder(name) from e
                os.close(fd)
                fd = child
                if made:
                    os.fchmod(fd, leaf_mode if index == len(parts) - 1 else 0o755)
            st = os.fstat(fd)
            if not stat.S_ISDIR(st.st_mode):
                raise _UnsafeFolder(base)
            if (tighten and parts and st.st_uid == os.geteuid()
                    and stat.S_IMODE(st.st_mode) & ~leaf_mode):
                os.fchmod(fd, stat.S_IMODE(st.st_mode) & leaf_mode)
        except BaseException:
            os.close(fd)
            raise
        return fd

    @classmethod
    def _walk(cls, base: str, parts, create: bool, leaf_mode: Optional[int] = None) -> tuple:
        """``_open_folder``, returning the final folder's (dev, inode). A
        ``leaf_mode`` other than the workspace's also narrows an existing folder."""
        mode = WORKSPACE_LEAF_MODE if leaf_mode is None else leaf_mode
        fd = cls._open_folder(base, parts, create, leaf_mode=mode,
                              tighten=mode != WORKSPACE_LEAF_MODE)
        try:
            st = os.fstat(fd)
            return st.st_dev, st.st_ino
        finally:
            os.close(fd)

    def _prepare_folders_sync(self, user_id: str, view: str, projects, custom: bool) -> dict:
        """B.3: make the missing project and output folders, refusing any bind
        source that is (or passes through) a symlink, or is not a folder. A link
        planted where a folder belongs would have Docker mount its target."""
        out = {}
        for target, base, parts, create, mode in self._bind_chains(user_id, view, projects, custom):
            try:
                out[target] = self._walk(base, parts, create=create, leaf_mode=mode)
            except _UnsafeFolder:
                logger.error(f"[sandbox] refusing to start key={sc.sandbox_key(user_id, view)}: a mount "
                             f"source is missing, a symlink or not a folder")
                raise SandboxStartError(sc.ERR_START_FAILED,
                                        "a mount source is missing, a symlink or not a folder") from None
        return out

    def _verify_mounts_sync(self, ref: str, identities: Mapping[str, tuple]) -> Optional[str]:
        """None when every bind target inside the started container is the folder
        the walk opened (a bind keeps its source's device and inode), else why."""
        targets = sorted(identities)
        try:
            result = self.client.containers.get(ref).exec_run(["stat", "-c", "%d:%i", *targets])
            code, output = result[0], result[1]
        except Exception as e:  # noqa: BLE001 - an unreadable mount is refused
            return f"its mounts cannot be read ({type(e).__name__})"
        lines = (output or b"").decode(errors="replace").split()
        if code != 0 or len(lines) != len(targets):
            return "its mounts cannot be read"
        for target, line in zip(targets, lines):
            dev, _, ino = line.partition(":")
            if not (dev.isdigit() and ino.isdigit()) or (int(dev), int(ino)) != tuple(identities[target]):
                return f"{target} is not the folder that was checked"
        return None

    def _copy_custom_templates_sync(self, user_id: str, view: str, templates: Optional[tuple]) -> bool:
        """The view's copy of the custom nuclei templates holds exactly ``templates``
        (the files of the shared folder its person may use, as the webapp lists
        them), so no sandbox sees another member's template. A file is read without
        following a link anywhere on its path (the webapp writes the shared folder),
        and only a regular file within the size caps is copied. True when the copy
        holds one at least, so it is mounted."""
        try:
            dest = self._open_folder(self.local_bases[sc.MOUNT_OUTPUT],
                                     tuple(sc.custom_templates_rel(user_id, view).split("/")),
                                     create=True, leaf_mode=0o755)
        except _UnsafeFolder:
            # Something planted in the output folder must not stop every sandbox:
            # this one starts without custom templates.
            logger.error(f"[sandbox] key={sc.sandbox_key(user_id, view)} starts without custom templates: "
                         f"{sc.custom_templates_rel(user_id, view)} in the output folder passes through a "
                         f"symlink or is not a folder")
            return False
        try:
            self._empty_folder(dest)
            if templates is None:
                self._warn_once("no-template-list", "[sandbox] the webapp named no custom nuclei templates "
                                                    "in its ensure; a sandbox starts without any")
                return False
            source = self.local_bases.get(sc.MOUNT_CUSTOM_TEMPLATES)
            copied = total = 0
            for rel in templates[:CUSTOM_TEMPLATES_MAX_FILES]:
                data = self._read_template(source, rel) if source else None
                if data is None:
                    continue
                if total + len(data) > CUSTOM_TEMPLATES_MAX_TOTAL_BYTES:
                    self._warn_once("templates-cap", f"[sandbox] the custom templates of a sandbox pass "
                                                     f"{CUSTOM_TEMPLATES_MAX_TOTAL_BYTES >> 20} MiB; the rest "
                                                     f"are not copied")
                    break
                if self._write_template(dest, rel, data):
                    copied += 1
                    total += len(data)
            return copied > 0
        finally:
            os.close(dest)

    @staticmethod
    def _empty_folder(fd: int) -> None:
        for name in os.listdir(fd):
            if stat.S_ISDIR(os.lstat(name, dir_fd=fd).st_mode):
                shutil.rmtree(name, dir_fd=fd)
            else:
                os.unlink(name, dir_fd=fd)

    @classmethod
    def _read_template(cls, base: str, rel: str) -> Optional[bytes]:
        parts = rel.split("/")
        try:
            folder = cls._open_folder(base, tuple(parts[:-1]), create=False)
        except _UnsafeFolder:
            return None
        try:
            fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=folder)
        except OSError:
            return None
        finally:
            os.close(folder)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return None
            data = b""
            while len(data) <= CUSTOM_TEMPLATE_MAX_BYTES:
                chunk = os.read(fd, 65536)
                if not chunk:
                    return data
                data += chunk
            return None
        finally:
            os.close(fd)

    @classmethod
    def _write_template(cls, dest: int, rel: str, data: bytes) -> bool:
        parts = rel.split("/")
        try:
            folder = cls._open_folder(dest, tuple(parts[:-1]), create=True, leaf_mode=0o755)
        except _UnsafeFolder:
            return False
        try:
            fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644,
                         dir_fd=folder)
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            return True
        except OSError:
            # Two names a case-insensitive host folder sees as one, say.
            return False
        finally:
            os.close(folder)

    def _servers_hash_sync(self, fresh: bool = False) -> str:
        now = self.clock()
        if not fresh and self._servers_cache and now - self._servers_cache[0] < sc.IDLE_CHECK_S:
            return self._servers_cache[1]
        value = sc.servers_fingerprint(self.local_bases[sc.MOUNT_SERVERS])
        self._servers_cache = (now, value)
        return value

    def _delete_outputs_sync(self, user_id: str) -> None:
        """Both views' ``users/<key>`` folders and custom templates copies. A link
        planted there is unlinked, never followed; a ``users`` (or ``templates``)
        that is itself a link is left alone."""
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        try:
            base = os.open(self.local_bases[sc.MOUNT_OUTPUT], flags)
        except OSError:
            logger.warning("[sandbox] the output folder cannot be opened; no output deleted")
            return
        try:
            for folder, what in ((sc.OUTPUT_USERS_DIR, "output folder"),
                                 (sc.CUSTOM_TEMPLATES_COPY_DIR, "custom templates copy")):
                try:
                    parent = os.open(folder, flags, dir_fd=base)
                except FileNotFoundError:
                    continue
                except OSError:
                    logger.warning(f"[sandbox] {folder}/ in the output folder is a symlink or "
                                   f"not a folder; nothing in it deleted")
                    continue
                try:
                    for view in sc.VIEWS:
                        name = sc.sandbox_key(user_id, view)
                        try:
                            st = os.lstat(name, dir_fd=parent)
                        except FileNotFoundError:
                            continue
                        if stat.S_ISDIR(st.st_mode):
                            shutil.rmtree(name, dir_fd=parent)
                        else:
                            os.unlink(name, dir_fd=parent)
                        logger.info(f"[sandbox] deleted the {what} of key={name} (account deleted)")
                finally:
                    os.close(parent)
        finally:
            os.close(base)

    # --- Adoption -------------------------------------------------------------

    async def adopt(self) -> dict:
        """B.7 at orchestrator start, over this stack's sandboxes only (its owner
        label: another RedAmon stack on the same daemon keeps its own). A running,
        healthy sandbox exactly as this orchestrator starts it is kept; one that
        differs only by an older Kali image, a changed port pool, no init process,
        the hostname every sandbox once shared (``sc.SELF_NAME``, no ExtraHosts) or
        the shared custom templates folder every sandbox once mounted is kept
        draining (it stops when unused, reason ``replaced``); every other one is
        removed, its pool port held for its person and view, and so is every
        network of this stack no kept instance uses. The templates refresher is
        left to finish."""
        current = await asyncio.to_thread(self._image_sync)
        daemon = await asyncio.to_thread(self._daemon_facts_sync)
        mine = [f"{sc.LABEL_SANDBOX}={sc.LABEL_TRUE}", f"{LABEL_OWNER}={self.owner}"]
        containers = await asyncio.to_thread(
            lambda: self.client.containers.list(all=True, ignore_removed=True, filters={"label": mine}))
        candidates, removed, held = [], 0, False
        for c in containers:
            labels = c.labels or {}
            if labels.get(LABEL_OWNER) != self.owner:
                continue
            # A scan's broker can create a container with any labels, but always
            # with its own: a look-alike is no refresher of ours, and goes.
            if (labels.get(sc.LABEL_ROLE) == sc.ROLE_TEMPLATES and not labels.get(sc.LABEL_USER)
                    and not labels.get(BROKER_OWNED_LABEL)):
                continue
            own_image = await asyncio.to_thread(self._image_by_id_sync, (c.attrs or {}).get("Image"))
            inst, problem, drain = self._adoptable(c, current, own_image, daemon)
            if inst is not None and any(i.user_id == inst.user_id and i.instance == inst.instance
                                        for i, _, _ in candidates):
                inst, problem = None, "duplicate instance id"
            if inst is not None:
                network_problem = await asyncio.to_thread(
                    self._network_problem_by_name_sync, inst.user_id, inst.view)
                if network_problem:
                    inst, problem = None, f"its network is refused: {network_problem}"
            if inst is None:
                logger.warning(f"[sandbox] removing sandbox-labelled container {c.id[:12]}: {problem}")
                if await asyncio.to_thread(self._force_remove_sync, c):
                    removed += 1
                    held = self._hold_removed_port(c) or held
                continue
            candidates.append((inst, c, drain))
        if held:
            self._holds_changed()
        if any(drain == PORTLESS_DRAIN for _, _, drain in candidates):
            labelled, promised, decided = await asyncio.to_thread(self._labelled_ports_sync), set(), []
            for inst, c, drain in candidates:
                if drain == PORTLESS_DRAIN:
                    port = self._port_for(inst.key, labelled, promised)
                    if port is None:
                        drain = None
                    else:
                        promised.add(port)
                decided.append((inst, c, drain))
            candidates = decided
        # The created label holds whole seconds: a replacement started in the same
        # second as the instance it replaced is told apart by Docker's own time.
        candidates.sort(key=lambda t: (t[0].created, _docker_created_ns((t[1].attrs or {}).get("Created"))))
        for inst, _, _ in candidates:
            self._seq += 1
            inst.seq = self._seq
        adopted = []
        for inst, c, drain in reversed(candidates):
            memory = int(((c.attrs or {}).get("HostConfig") or {}).get("Memory") or 0)
            self.ledger.account(inst.reservation_key, max(memory, 1))
            inst.state = "draining" if drain or self._current(inst.user_id, inst.view) else "running"
            inst.stop_reason = DRAIN_REASON if inst.state == "draining" else None
            inst.grace_until = self.clock() + ADOPTION_GRACE_S
            inst.ready.set()
            self._register(inst)
            adopted.append(inst)
            if drain:
                self._log(f"adopted draining ({drain})", inst, DRAIN_REASON)
            else:
                self._log("adopted", inst)
        for user_id, view in sorted({(i.user_id, i.view) for i in adopted}):
            self._turn_off_replaced_tunnels(user_id, view)
        live = {i.network for i in adopted}
        networks = await asyncio.to_thread(
            lambda: self.client.networks.list(filters={"label": mine}))
        removed_networks = 0
        for net in networks:
            if net.name not in live and await asyncio.to_thread(self._remove_network_sync, net.name):
                removed_networks += 1
        for name in sorted(live):
            try:
                await self._ensure_guests(name, strict=False)
            except Exception as e:  # noqa: BLE001 - the next ensure or idle tick retries
                logger.warning(f"[sandbox] guest check of {name} failed: {type(e).__name__}")
        return {"adopted": len(adopted), "removed": removed, "networks_removed": removed_networks}

    def _force_remove_sync(self, container) -> bool:
        try:
            container.remove(force=True)
            return True
        except NotFound:
            return True
        except Exception as e:  # noqa: BLE001
            logger.warning(f"[sandbox] could not remove container {container.id[:12]}: {type(e).__name__}")
            return False

    def _image_by_id_sync(self, image_id):
        if not image_id:
            return None
        try:
            return self.client.images.get(image_id)
        except (ImageNotFound, NotFound, APIError):
            return None

    def _daemon_facts_sync(self) -> dict:
        """The engine defaults a container gets for the host-config fields whose
        default is not empty: the cgroup namespace (``host`` on cgroup v1), the
        runtime and the log driver."""
        try:
            info = self.client.info() or {}
        except Exception:  # noqa: BLE001 - the strict defaults apply
            info = {}
        return {"cgroup_v1": str(info.get("CgroupVersion") or "") == "1",
                "runtime": str(info.get("DefaultRuntime") or "runc"),
                "log_driver": str(info.get("LoggingDriver") or "")}

    @staticmethod
    def _same_lineage(old, current) -> bool:
        old_labels = ((old.attrs or {}).get("Config") or {}).get("Labels") or {}
        cur_labels = ((current.attrs or {}).get("Config") or {}).get("Labels") or {}
        return all(old_labels.get(k) == cur_labels[k] for k in IMAGE_LINEAGE_LABELS if k in cur_labels)

    def _adoptable(self, c, current, own_image, daemon: Mapping) -> tuple:
        """(Instance, None, drain) when ``c`` is a sandbox exactly as this
        orchestrator starts it, ``drain`` naming why it must drain (an older
        image, a changed port pool, no init process, the shared hostname, the
        shared custom templates) or None;
        else (None, why, None). Labels
        alone prove nothing: a scan container can ask the broker for any label,
        but never without the broker's own. The host config is compared with what
        ``_container_kwargs`` makes for the same instance, and every field the
        manager never sets must be empty."""
        refused = lambda why: (None, why, None)  # noqa: E731
        attrs = c.attrs or {}
        labels = c.labels or {}
        config = attrs.get("Config") or {}
        hc = attrs.get("HostConfig") or {}
        state = attrs.get("State") or {}
        drain = None
        if labels.get(BROKER_OWNED_LABEL):
            return refused("created through the Docker broker")
        if labels.get(sc.LABEL_CONTRACT) != str(sc.CONTRACT_VERSION):
            return refused("another contract version")
        if state.get("Status") != "running" or (state.get("Health") or {}).get("Status") != "healthy":
            return refused("not running and healthy")
        user_id, view, instance = (labels.get(sc.LABEL_USER), labels.get(sc.LABEL_VIEW),
                                   labels.get(sc.LABEL_INSTANCE))
        if not (sc.valid_user_id(user_id) and view in sc.VIEWS and sc.valid_instance(instance)):
            return refused("invalid labels")
        if c.name != sc.container_name(user_id, view, instance):
            return refused("its name is not the sandbox's")
        if own_image is None or attrs.get("Image") != own_image.id or config.get("Image") != sc.IMAGE:
            return refused("not a Kali sandbox image")
        if current is None or own_image.id != current.id:
            if current is not None and not self._same_lineage(own_image, current):
                return refused("not a Kali sandbox image")
            drain = "older image"
        image_config = (own_image.attrs or {}).get("Config") or {}
        for key in ("Entrypoint", "Cmd"):
            if (config.get(key) or None) != (image_config.get(key) or None):
                return refused(f"{key.lower()} changed")
        if (config.get("User") or "") != (image_config.get("User") or ""):
            return refused("user changed")
        try:
            mounts = hc.get("Mounts") or []
            projects = tuple(sc.projects_from_destinations(m.get("Target") for m in mounts))
        except ValueError:
            return refused("a workspace mount that is not one project folder")
        port_label = labels.get(sc.LABEL_PORT) or ""
        if port_label and not (port_label.isdigit() and 1 <= int(port_label) <= 65535):
            return refused("invalid port label")
        pool_port = int(port_label) if port_label else None
        env = _env_dict(config.get("Env"))
        problem, env_drift = self._env_problem(env, _env_dict(image_config.get("Env")), user_id, view,
                                               pool_port)
        if problem:
            return refused(problem)
        drain = drain or env_drift
        probe = Instance(user_id=user_id, view=view, instance=instance, state="running",
                         projects=projects, host=c.name, key=sc.sandbox_key(user_id, view),
                         network=sc.network_name(user_id, view), created=0.0, last_used=0.0,
                         token=env[sc.ENV_MCP_AUTH_TOKEN], tunnel_token=env[sc.ENV_TUNNEL_AUTH_TOKEN],
                         pool_port=pool_port, reverse_port=pool_port or sc.DEFAULT_REVERSE_PORT,
                         # Without a port while a pool is configured now it drains
                         # (below), so its next start gets one.
                         reverse_port_state=(sc.REVERSE_PORT_ASSIGNED if pool_port else
                                             sc.REVERSE_PORT_POOL_FULL if self._pool() else
                                             sc.REVERSE_PORT_NO_POOL),
                         container_id=c.id, image_id=attrs.get("Image"),
                         servers=labels.get(sc.LABEL_SERVERS) or None)
        try:
            probe.created = float(labels.get(sc.LABEL_CREATED) or 0)
        except ValueError:
            return refused("invalid created label")
        log_config = self._log_config(daemon)
        try:
            plans = [self._container_kwargs(probe, env, labels.get(sc.LABEL_SERVERS) or "", custom,
                                            log_config)
                     for custom in (True, False)]
        except (SandboxError, ValueError):
            return refused("its plan cannot be rebuilt")
        expected = plans[0]
        got_mounts = [_norm_mount(m) for m in mounts]
        planned = [{_norm_mount(m) for m in plan["mounts"]} for plan in plans]
        if len(got_mounts) != len(set(got_mounts)):
            return refused("mounts differ from the plan")
        if set(got_mounts) not in planned:
            # Started when every sandbox mounted the shared folder of every member's
            # templates: kept until unused, never current.
            shared = self._shared_templates_mount()
            if shared is None or set(got_mounts) != planned[1] | {shared}:
                return refused("mounts differ from the plan")
            drain = drain or "every member's custom templates"
        skip = {sc.LABEL_CREATED, sc.LABEL_SERVERS, sc.LABEL_PORT}
        if any(labels.get(k) != v for k, v in expected["labels"].items() if k not in skip):
            return refused("labels differ from the plan")
        extra_hosts = list(hc.get("ExtraHosts") or [])
        if config.get("Hostname") == expected["hostname"]:
            if extra_hosts != [f"{k}:{v}" for k, v in sorted(expected["extra_hosts"].items())]:
                return refused("extra hosts differ")
        elif config.get("Hostname") == sc.SELF_NAME and not extra_hosts:
            # Started when every sandbox had this hostname: a DNS name all of them
            # shared on networks the agent joins. Kept until unused, never current.
            drain = drain or "shared hostname"
        else:
            return refused("hostname changed")
        if _norm_caps(hc.get("CapAdd")) != _norm_caps(expected["cap_add"]) or \
                set(hc.get("SecurityOpt") or []) != set(expected["security_opt"]):
            return refused("privileges differ")
        if list(hc.get("Dns") or []) != expected["dns"] or \
                (hc.get("RestartPolicy") or {}).get("Name") != expected["restart_policy"]["Name"]:
            return refused("dns or restart policy differ")
        if hc.get("CpuShares") != expected["cpu_shares"] or hc.get("NanoCpus") != expected["nano_cpus"] \
                or hc.get("PidsLimit") != expected["pids_limit"]:
            return refused("limits differ")
        if hc.get("Init") is not expected["init"]:
            # Started before the spec had an init: its zombies stay until it stops.
            drain = drain or "no init process"
        if log_config is not None:
            got_log = hc.get("LogConfig") or {}
            if got_log.get("Type") != log_config["type"] or \
                    dict(got_log.get("Config") or {}) != log_config["config"]:
                # Started before its log was capped, or under another rotation: the
                # log keeps growing until it stops.
                drain = drain or "no log cap"
        memory = int(hc.get("Memory") or 0)
        if memory <= 0 or int(hc.get("MemorySwap") or 0) != memory:
            return refused("limits differ")
        for key in NEUTRAL_HOST_KEYS:
            if hc.get(key):
                return refused(f"{key} is set")
        if hc.get("IpcMode") not in (None, "", "private", "shareable"):
            return refused("shares an IPC namespace")
        if hc.get("CgroupnsMode") not in (None, "", "private") and not (
                daemon.get("cgroup_v1") and hc.get("CgroupnsMode") == "host"):
            return refused("shares the host cgroup namespace")
        if hc.get("Runtime") not in (None, "", "runc", daemon.get("runtime")):
            return refused("another runtime")
        if hc.get("NetworkMode") != expected["network"] or \
                set(((attrs.get("NetworkSettings") or {}).get("Networks") or {})) != {expected["network"]}:
            return refused("not on its own network only")
        bindings = hc.get("PortBindings") or {}
        if pool_port is None:
            if bindings:
                return refused("publishes a port")
            if self._pool() is not None:
                # adopt() keeps it current when the pool has no port for it now.
                drain = drain or PORTLESS_DRAIN
        else:
            entries = bindings.get(f"{pool_port}/tcp") or []
            if set(bindings) != {f"{pool_port}/tcp"} or len(entries) != 1 or \
                    str(entries[0].get("HostPort")) != str(pool_port) or \
                    pool_port in set(sc.PORTS.values()) | set(sc.HEALTH_PROBE_PORTS):
                return refused("publishes a port other than its pool port")
            pool = self._pool()
            if pool is None or pool_port not in pool.ports() or entries[0].get("HostIp") != pool.bind_ip:
                drain = drain or "port pool changed"
        probe.last_used = self.clock()
        return probe, None, drain

    @staticmethod
    def _env_problem(env: dict, image_env: dict, user_id: str, view: str,
                     pool_port: Optional[int]) -> tuple:
        """(why it is refused, why it drains) for a candidate's environment. A fixed
        variable it lacks is an older release's (a release that adds a server port
        adds one): kept draining, so an update does not cut its sessions. A fixed
        value that differs, or a variable no release sets, is refused."""
        allowed = (set(sc.CONTAINER_ENV_FIXED) | {sc.ENV_MCP_AUTH_TOKEN, sc.ENV_TUNNEL_AUTH_TOKEN,
                                                  sc.ENV_SANDBOX_KEY, sc.ENV_REVERSE_PORT,
                                                  sc.TERMINAL_MAX_SESSIONS_ENV} | set(image_env))
        if set(env) - allowed:
            return "unexpected environment variables", None
        drift = None
        for k, v in sc.CONTAINER_ENV_FIXED.items():
            if k not in env:
                drift = "an older release's environment"
            elif env[k] != v:
                return "a fixed environment value changed", None
        problem = SandboxManager._env_identity_problem(env, image_env, user_id, view, pool_port)
        return problem, (None if problem else drift)

    @staticmethod
    def _env_identity_problem(env: dict, image_env: dict, user_id: str, view: str,
                              pool_port: Optional[int]) -> Optional[str]:
        for k, v in image_env.items():
            if k not in sc.CONTAINER_ENV_FIXED and env.get(k) != v:
                return "an image environment value changed"
        if env.get(sc.ENV_SANDBOX_KEY) != sc.sandbox_key(user_id, view):
            return "its key variable is not the sandbox's"
        if env.get(sc.ENV_REVERSE_PORT) != str(pool_port or sc.DEFAULT_REVERSE_PORT):
            return "its reverse port is not the sandbox's"
        tokens = (env.get(sc.ENV_MCP_AUTH_TOKEN), env.get(sc.ENV_TUNNEL_AUTH_TOKEN))
        if not all(isinstance(t, str) and _TOKEN.fullmatch(t) for t in tokens) or tokens[0] == tokens[1]:
            return "its tokens are not the sandbox's"
        raw = env.get(sc.TERMINAL_MAX_SESSIONS_ENV)
        if raw is not None and not re.fullmatch(r"[0-9]{1,9}", raw):
            return "invalid terminal session cap"
        return None
