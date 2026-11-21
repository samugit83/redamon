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
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Dict, Mapping, Optional

import docker
from docker.errors import APIError, ImageNotFound, NotFound

import resource_governor as rg
import sandbox_contract as sc
from container_manager import BROKER_OWNED_LABEL, join_host_path

logger = logging.getLogger(__name__)

# docker-py 7.2 cannot send an endpoint's GwPriority, so guests are connected
# with a raw call, and the engine API must be new enough to honour it. Without
# it a guest's default route could move onto a sandbox network: refuse to start.
GW_PRIORITY_MIN_API = (1, 48)

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
# An older image of the sandbox is one these labels of the current image match
# (compose stamps them at build); the broker label already rules out a scan's.
IMAGE_LINEAGE_LABELS = (sc.COMPOSE_SERVICE_LABEL, "description")
# Host-config fields the manager never sets: adoption requires each empty.
NEUTRAL_HOST_KEYS = (
    "Binds", "VolumesFrom", "Devices", "DeviceCgroupRules", "DeviceRequests", "Links",
    "ExtraHosts", "GroupAdd", "DnsOptions", "DnsSearch", "Tmpfs", "Sysctls", "Ulimits",
    "CapDrop", "Privileged", "PublishAllPorts", "OomKillDisable", "PidMode", "UTSMode",
    "UsernsMode", "Cgroup", "CgroupParent", "VolumeDriver", "StorageOpt")

HEALTH_POLL_S = 1
# A pool port the host already uses fails the start; it is skipped this long.
BUSY_PORT_HOLD_S = 600
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

# A restart loses every lease. An adopted instance therefore takes lease ids it
# does not know, and is never stopped for holding none, for one lease lifetime,
# while the agent's renewals (every 30 s) and the hold watcher (every 60 s) take
# them again; else a draining one would be stopped at the first tick with its
# sessions and jobs still running.
ADOPTION_GRACE_S = sc.LEASE_TTL_S

# A start whose readiness never settles (its health read kept failing, its
# check task died) is stopped by the idle loop this long after its timeout.
START_STUCK_GRACE_S = 60

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

    # --- Small helpers --------------------------------------------------------

    def mode(self) -> str:
        return sc.mode_from_env(os.environ.get(sc.MODE_ENV))

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
                     touch: bool = False) -> dict:
        """B.7: the person's running sandbox for ``view``, started when needed.
        ``touch`` starts in the background and swallows errors and refusals."""
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
        mode = self.mode()
        if mode == sc.MODE_SHARED:
            return {"mode": sc.MODE_SHARED}
        if touch:
            wait = False
        # Registered before the first await, so a stop called in the same loop pass
        # already sees (and fences) this ensure.
        pending = _Pending(view, frozenset(projects))
        self._pending.setdefault(user_id, set()).add(pending)
        try:
            inst, fresh = await self._shielded(
                self._ensure_locked(user_id, view, tuple(projects), need_project, pending))
            if inst.state == "starting":
                if not wait:
                    return {"mode": mode, "state": "starting", "instance": inst.instance,
                            "fresh": fresh}
                await self._wait_ready(inst)
            inst.last_used = self.clock()
            return self._running_answer(inst, fresh, mode)
        except SandboxError as e:
            if not touch:
                raise
            logger.info(f"[sandbox] warm-up for key={sc.sandbox_key(user_id, view)} not started: {e.code}")
            return {"mode": mode, "state": "unavailable", "instance": None, "fresh": False}

    def _running_answer(self, inst: Instance, fresh: bool, mode: str) -> dict:
        now = self.clock()
        return {"mode": mode, "user_id": inst.user_id, "view": inst.view,
                "instance": inst.instance, "host": inst.host, "token": inst.token,
                "tunnel_token": inst.tunnel_token, "ports": dict(sc.PORTS),
                "reverse_port": inst.reverse_port, "projects": list(inst.projects),
                "state": "running", "fresh": fresh, "stop_at": self._stop_at(inst, now),
                "stop_reason": None, "warn": self._warn(inst, now)}

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
                             need_project: Optional[str], pending: _Pending):
        try:
            async with self._user_lock(user_id):
                allowed = set(projects)
                for inst in self._view_instances(user_id, view):
                    if not set(inst.projects) <= allowed and inst.state != "stopping":
                        await self._stop_locked(inst, "access_lost")
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
                new = await self._start_locked(user_id, view, projects)
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

    def _new_instance_id(self, user_id: str) -> str:
        """Instance ids are 24 random bits and the ledger key omits the view, so
        an id already held by the person (either view) is drawn again."""
        taken = {i.instance for i in self.instances(user_id)}
        for _ in range(INSTANCE_DRAWS):
            candidate = sc.new_instance()
            if candidate not in taken:
                return candidate
        raise SandboxStartError(sc.ERR_START_FAILED, "no free instance id")

    async def _start_locked(self, user_id: str, view: str, projects: tuple) -> Instance:
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
            await self._create_locked(inst)
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

    async def _create_locked(self, inst: Instance) -> None:
        image = await asyncio.to_thread(self._image_sync)
        if image is None:
            logger.error(f"[sandbox] cannot start key={inst.key}: {IMAGE_MISSING_DETAIL}")
            raise SandboxStartError(sc.ERR_IMAGE_MISSING, IMAGE_MISSING_DETAIL)
        async with self._alloc_lock:
            await asyncio.to_thread(self._network_sync, inst.user_id, inst.view)
            inst.pool_port = await self._allocate_port()
        await self._ensure_guests(inst.network, strict=True)
        custom = await asyncio.to_thread(self._custom_templates_sync)
        identities = await asyncio.to_thread(self._prepare_folders_sync, inst.user_id,
                                             inst.view, inst.projects, custom)
        servers = await asyncio.to_thread(self._servers_hash_sync)
        inst.servers = servers
        for attempt in range(2):
            inst.reverse_port = inst.pool_port or sc.DEFAULT_REVERSE_PORT
            env = sc.container_env(inst.user_id, inst.view, inst.instance,
                                   reverse_port=inst.pool_port)
            inst.token = env[sc.ENV_MCP_AUTH_TOKEN]
            inst.tunnel_token = env[sc.ENV_TUNNEL_AUTH_TOKEN]
            kwargs = self._container_kwargs(inst, env, servers, custom)
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
                    inst.pool_port = await self._allocate_port()
        # Docker resolves a bind source when it starts the container, and follows a
        # link: a folder swapped for a link and back around the start passes any
        # check made from outside. So what was mounted is read from inside, before
        # the instance can become running or a token leave this manager.
        problem = await asyncio.to_thread(self._verify_mounts_sync, inst.container_id, identities)
        if problem:
            logger.error(f"[sandbox] refusing key={inst.key} instance={inst.instance}: {problem}; removing it")
            raise SandboxStartError(sc.ERR_START_FAILED, "a mount of the sandbox is not the folder that was checked")

    def _container_kwargs(self, inst: Instance, env: dict, servers: str, custom: bool) -> dict:
        labels = dict(COMPOSE_LABEL_OVERRIDES)
        labels.update(sc.container_labels(inst.user_id, inst.view, inst.instance, inst.projects,
                                          created=inst.created, port=inst.pool_port, servers=servers))
        labels[LABEL_OWNER] = self.owner
        healthcheck = sc.healthcheck(sc.START_TIMEOUT_S)
        # docker-py 7.2 drops it anyway; the start polls at the 2 s interval.
        healthcheck.pop("start_interval", None)
        kwargs = dict(
            image=sc.IMAGE, name=inst.host, hostname=sc.CONTAINER_HOSTNAME, detach=True,
            environment=env, labels=labels, mounts=self._mounts(inst, custom),
            network=inst.network, cap_add=list(sc.CAP_ADD), security_opt=list(sc.SECURITY_OPT),
            dns=list(sc.DNS), restart_policy=dict(sc.RESTART_POLICY), healthcheck=healthcheck,
            cpu_shares=SANDBOX_CPU_SHARES,
            **sc.limits(self._envelope(), self.cpu_count()))
        pool = self._pool()
        if inst.pool_port is not None and pool is not None:
            kwargs["ports"] = sc.published_ports(inst.pool_port, pool.bind_ip)
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
                        "warn": self._warn(inst, now), "reverse_port": inst.reverse_port})
        return {"mode": self.mode(), "instances": out}

    def list_running(self) -> list:
        """Running and draining instances with their address and token, for the
        agent (its session fan-out reaches a draining instance's sessions too)."""
        return [{"user_id": i.user_id, "view": i.view, "instance": i.instance, "host": i.host,
                 "token": i.token, "state": i.state}
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
        """Every ``IDLE_CHECK_S``, in both modes, until cancelled: per-user
        instances left after a switch back to ``shared`` stop as they go idle."""
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
                logger.error(f"[sandbox] the agent container lacks {missing} in its sysctls, so it "
                             f"could route between networks; it is not attached to a sandbox network")
                if strict:
                    raise SandboxStartError(sc.ERR_START_FAILED, "the agent container may forward packets")
                continue
            eligible.append((agent, [sc.AGENT_ALIAS]))
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
        found = []
        if self.own_compose_project:
            found = self.client.containers.list(filters={"label": [
                f"{sc.COMPOSE_SERVICE_LABEL}={sc.AGENT_COMPOSE_SERVICE}",
                f"{sc.COMPOSE_PROJECT_LABEL}={self.own_compose_project}"]})
            found = [c for c in found if not (c.labels or {}).get(BROKER_OWNED_LABEL)]
        if not found:
            try:
                c = self.client.containers.get(sc.AGENT_CONTAINER_NAME)
                labels = c.labels or {}
                # By name only when it is not another compose project's agent.
                project = labels.get(sc.COMPOSE_PROJECT_LABEL)
                if c.status == "running" and not labels.get(BROKER_OWNED_LABEL) and \
                        (not project or project == self.own_compose_project):
                    found = [c]
            except NotFound:
                pass
        return found

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
        if net is not None:
            attrs = net.attrs or {}
            labels = attrs.get("Labels") or {}
            expected = self._network_labels(user_id, view)
            subnets = [c.get("Subnet") for c in ((attrs.get("IPAM") or {}).get("Config") or [])]
            pool = ipaddress.ip_network(sc.SUBNET_POOL)
            def in_pool(subnet) -> bool:
                try:
                    net_ = ipaddress.ip_network(subnet, strict=False)
                except (TypeError, ValueError):
                    return False
                return net_.version == pool.version and net_.subnet_of(pool)

            ok = (attrs.get("Name") == name and all(labels.get(k) == v for k, v in expected.items())
                  and not labels.get(BROKER_OWNED_LABEL) and attrs.get("Driver") == sc.NETWORK_DRIVER
                  and not attrs.get("Internal") and subnets and all(in_pool(s) for s in subnets))
            if not ok:
                logger.error(f"[sandbox] a network named like the sandbox network of key="
                             f"{expected[sc.LABEL_KEY]} exists and is not the orchestrator's; not used")
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
        return self.client.networks.create(name, driver=sc.NETWORK_DRIVER, internal=sc.NETWORK_INTERNAL,
                                           labels=self._network_labels(user_id, view), ipam=ipam,
                                           check_duplicate=True)

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

    async def _allocate_port(self) -> Optional[int]:
        """The lowest free pool port, under the allocation lock. A port the sandbox
        serves itself (4040's unauthenticated ngrok API above all) is never one."""
        pool = self._pool()
        if pool is None:
            return None
        now = self.clock()
        taken = {i.pool_port for i in self.instances() if i.pool_port}
        taken |= {p for p, until in self._busy_ports.items() if until > now}
        taken |= set(sc.PORTS.values()) | set(sc.HEALTH_PROBE_PORTS)
        taken |= await asyncio.to_thread(self._labelled_ports_sync)
        for port in pool.ports():
            if port not in taken:
                return port
        self._warn_once("pool-full", "[sandbox] the port pool has no free port; a sandbox starts without one")
        return None

    def _labelled_ports_sync(self) -> set:
        ports = set()
        for c in self.client.containers.list(all=True, filters={"label": f"{sc.LABEL_SANDBOX}={sc.LABEL_TRUE}"}):
            raw = (c.labels or {}).get(sc.LABEL_PORT) or ""
            if raw.isdigit():
                ports.add(int(raw))
        return ports

    # --- Folders --------------------------------------------------------------

    def _bind_chains(self, user_id: str, view: str, projects, custom: bool) -> list:
        """(target inside the sandbox, local base, components) of every bind."""
        chains = [(f"{sc.WORKSPACE_ROOT}/{p}", self.local_bases[sc.MOUNT_WORKSPACE], (p,)) for p in projects]
        chains.append((sc.OUTPUT_TARGET, self.local_bases[sc.MOUNT_OUTPUT],
                       tuple(sc.output_rel(user_id, view).split("/"))))
        kinds = [(sc.SERVERS_TARGET, sc.MOUNT_SERVERS), (sc.GRAPH_DB_TARGET, sc.MOUNT_GRAPH_DB)]
        if custom:
            kinds.append((sc.CUSTOM_TEMPLATES_TARGET, sc.MOUNT_CUSTOM_TEMPLATES))
        chains += [(target, self.local_bases[kind], ()) for target, kind in kinds]
        return chains

    @staticmethod
    def _walk(base: str, parts, create: bool) -> tuple:
        """Open ``base/parts...`` one component at a time, never following a link,
        making a missing component when ``create``: the last one 0777 (the agent
        and the sandbox both write it), one above it 0755 (only the orchestrator
        adds to ``users/``), set through the descriptor so the umask cannot narrow
        them. Returns the final folder's (dev, inode). A link or a non-folder
        anywhere raises ``_UnsafeFolder``."""
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        try:
            fd = os.open(base, flags)
        except OSError as e:
            raise _UnsafeFolder(base) from e
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
                    os.fchmod(fd, 0o777 if index == len(parts) - 1 else 0o755)
            st = os.fstat(fd)
            if not stat.S_ISDIR(st.st_mode):
                raise _UnsafeFolder(base)
            return st.st_dev, st.st_ino
        finally:
            os.close(fd)

    def _prepare_folders_sync(self, user_id: str, view: str, projects, custom: bool) -> dict:
        """B.3: make the missing project and output folders, refusing any bind
        source that is (or passes through) a symlink, or is not a folder. A link
        planted where a folder belongs would have Docker mount its target."""
        out = {}
        for target, base, parts in self._bind_chains(user_id, view, projects, custom):
            try:
                out[target] = self._walk(base, parts, create=bool(parts))
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

    def _custom_templates_sync(self) -> bool:
        local = self.local_bases.get(sc.MOUNT_CUSTOM_TEMPLATES)
        if not local or not self.host_bases.get(sc.MOUNT_CUSTOM_TEMPLATES):
            return False
        try:
            return any(True for _ in os.scandir(local))
        except OSError:
            return False

    def _servers_hash_sync(self, fresh: bool = False) -> str:
        now = self.clock()
        if not fresh and self._servers_cache and now - self._servers_cache[0] < sc.IDLE_CHECK_S:
            return self._servers_cache[1]
        value = sc.servers_fingerprint(self.local_bases[sc.MOUNT_SERVERS])
        self._servers_cache = (now, value)
        return value

    def _delete_outputs_sync(self, user_id: str) -> None:
        """Both views' ``users/<key>`` folders. A link planted there is unlinked,
        never followed; a ``users`` that is itself a link is left alone."""
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        try:
            base = os.open(self.local_bases[sc.MOUNT_OUTPUT], flags)
        except OSError:
            logger.warning("[sandbox] the output folder cannot be opened; no output deleted")
            return
        try:
            try:
                users = os.open(sc.OUTPUT_USERS_DIR, flags, dir_fd=base)
            except FileNotFoundError:
                return
            except OSError:
                logger.warning(f"[sandbox] {sc.OUTPUT_USERS_DIR}/ in the output folder is a symlink or "
                               f"not a folder; no output deleted")
                return
            try:
                for view in sc.VIEWS:
                    name = sc.sandbox_key(user_id, view)
                    try:
                        st = os.lstat(name, dir_fd=users)
                    except FileNotFoundError:
                        continue
                    if stat.S_ISDIR(st.st_mode):
                        shutil.rmtree(name, dir_fd=users)
                    else:
                        os.unlink(name, dir_fd=users)
                    logger.info(f"[sandbox] deleted the output folder of key={name} (account deleted)")
            finally:
                os.close(users)
        finally:
            os.close(base)

    # --- Adoption -------------------------------------------------------------

    async def adopt(self) -> dict:
        """B.7 at orchestrator start, over this stack's sandboxes only (its owner
        label: another RedAmon stack on the same daemon keeps its own). A running,
        healthy sandbox exactly as this orchestrator starts it is kept; one that
        differs only by an older Kali image or a changed port pool is kept
        draining (it stops when unused, reason ``replaced``); every other one is
        removed, and so is every network of this stack no kept instance uses. The
        templates refresher is left to finish."""
        current = await asyncio.to_thread(self._image_sync)
        daemon = await asyncio.to_thread(self._daemon_facts_sync)
        mine = [f"{sc.LABEL_SANDBOX}={sc.LABEL_TRUE}", f"{LABEL_OWNER}={self.owner}"]
        containers = await asyncio.to_thread(
            lambda: self.client.containers.list(all=True, filters={"label": mine}))
        candidates, removed = [], 0
        for c in containers:
            labels = c.labels or {}
            if labels.get(LABEL_OWNER) != self.owner:
                continue
            if labels.get(sc.LABEL_ROLE) == sc.ROLE_TEMPLATES and not labels.get(sc.LABEL_USER):
                continue
            own_image = await asyncio.to_thread(self._image_by_id_sync, (c.attrs or {}).get("Image"))
            inst, problem, drain = self._adoptable(c, current, own_image, daemon)
            if inst is not None and any(i.user_id == inst.user_id and i.instance == inst.instance
                                        for i, _, _ in candidates):
                inst, problem = None, "duplicate instance id"
            if inst is None:
                logger.warning(f"[sandbox] removing sandbox-labelled container {c.id[:12]}: {problem}")
                if await asyncio.to_thread(self._force_remove_sync, c):
                    removed += 1
                continue
            candidates.append((inst, c, drain))
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
        """The engine defaults a container gets for the two host-config fields whose
        default is not empty: the cgroup namespace (``host`` on cgroup v1) and the
        runtime."""
        try:
            info = self.client.info() or {}
        except Exception:  # noqa: BLE001 - the strict defaults apply
            info = {}
        return {"cgroup_v1": str(info.get("CgroupVersion") or "") == "1",
                "runtime": str(info.get("DefaultRuntime") or "runc")}

    @staticmethod
    def _same_lineage(old, current) -> bool:
        old_labels = ((old.attrs or {}).get("Config") or {}).get("Labels") or {}
        cur_labels = ((current.attrs or {}).get("Config") or {}).get("Labels") or {}
        return all(old_labels.get(k) == cur_labels[k] for k in IMAGE_LINEAGE_LABELS if k in cur_labels)

    def _adoptable(self, c, current, own_image, daemon: Mapping) -> tuple:
        """(Instance, None, drain) when ``c`` is a sandbox exactly as this
        orchestrator starts it, ``drain`` naming why it must drain (an older
        image, a changed port pool) or None; else (None, why, None). Labels
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
        problem = self._env_problem(env, _env_dict(image_config.get("Env")), user_id, view, pool_port)
        if problem:
            return refused(problem)
        probe = Instance(user_id=user_id, view=view, instance=instance, state="running",
                         projects=projects, host=c.name, key=sc.sandbox_key(user_id, view),
                         network=sc.network_name(user_id, view), created=0.0, last_used=0.0,
                         token=env[sc.ENV_MCP_AUTH_TOKEN], tunnel_token=env[sc.ENV_TUNNEL_AUTH_TOKEN],
                         pool_port=pool_port, reverse_port=pool_port or sc.DEFAULT_REVERSE_PORT,
                         container_id=c.id, image_id=attrs.get("Image"),
                         servers=labels.get(sc.LABEL_SERVERS) or None)
        try:
            probe.created = float(labels.get(sc.LABEL_CREATED) or 0)
        except ValueError:
            return refused("invalid created label")
        try:
            plans = [self._container_kwargs(probe, env, labels.get(sc.LABEL_SERVERS) or "", custom)
                     for custom in (True, False)]
        except (SandboxError, ValueError):
            return refused("its plan cannot be rebuilt")
        expected = plans[0]
        got_mounts = [_norm_mount(m) for m in mounts]
        if len(got_mounts) != len(set(got_mounts)) or \
                set(got_mounts) not in [{_norm_mount(m) for m in plan["mounts"]} for plan in plans]:
            return refused("mounts differ from the plan")
        skip = {sc.LABEL_CREATED, sc.LABEL_SERVERS, sc.LABEL_PORT}
        if any(labels.get(k) != v for k, v in expected["labels"].items() if k not in skip):
            return refused("labels differ from the plan")
        if config.get("Hostname") != expected["hostname"]:
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
                     pool_port: Optional[int]) -> Optional[str]:
        allowed = (set(sc.CONTAINER_ENV_FIXED) | {sc.ENV_MCP_AUTH_TOKEN, sc.ENV_TUNNEL_AUTH_TOKEN,
                                                  sc.ENV_SANDBOX_KEY, sc.ENV_REVERSE_PORT,
                                                  sc.TERMINAL_MAX_SESSIONS_ENV} | set(image_env))
        if set(env) - allowed:
            return "unexpected environment variables"
        for k, v in sc.CONTAINER_ENV_FIXED.items():
            if env.get(k) != v:
                return "a fixed environment value changed"
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
