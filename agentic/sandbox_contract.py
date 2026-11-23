"""The contract for per-user Kali sandboxes.

This module is the contract every per-user sandbox part is built against: the
names, labels and keys, the mount plan, the container and network
specification, the governor keys, lifecycle states, lease kinds, routes, error
codes, messages, environment variables and timings. It exists in three copies:

- ``recon_orchestrator/sandbox_contract.py`` and ``agentic/sandbox_contract.py``,
  byte-identical (the orchestrator and the agent each import their own);
- ``webapp/src/lib/sandbox/contract.ts``, the constants the webapp uses.

``tests/test_sandbox_contract.py`` fails when the two Python copies differ by one
byte or a TypeScript constant differs from this file, so change all three
together. The prose is ``docs/readmes/README.KALI_SANDBOX.md``.

Standard library only, with no Docker and no other RedAmon import, so both
services and the tests can load it by path. Every function is pure except
``new_instance`` and ``instance_env``/``container_env`` (random values) and
``servers_fingerprint`` (reads a folder).
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import secrets
from dataclasses import dataclass
from types import MappingProxyType
from typing import Iterable, Mapping, NamedTuple, Optional

CONTRACT_VERSION = 1

# --- Ids --------------------------------------------------------------------------

# The character classes are explicit ASCII ranges and the checks use fullmatch:
# no Unicode look-alike, no trailing newline (which `$` alone would accept), no
# re.IGNORECASE (under which the Kelvin sign matches `k`).
USER_ID_RE = r"^[A-Za-z0-9_-]{1,64}$"
# No dot at all, so `.`, `..`, `.staging` and every path separator are refused.
PROJECT_ID_RE = r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$"
INSTANCE_RE = r"^[0-9a-f]{6}$"
_USER_ID = re.compile(USER_ID_RE)
_PROJECT_ID = re.compile(PROJECT_ID_RE)
_INSTANCE = re.compile(INSTANCE_RE)

# The single-segment orchestrator routes under /sandboxes/: a user id equal to
# one of them would make GET /sandboxes/{user_id} unreachable for that person.
RESERVED_USER_IDS = ("ensure", "stop-all", "stop-project")
# A folder with a device name cannot be created on a Windows host.
_WINDOWS_DEVICE_NAMES = frozenset(
    ["CON", "PRN", "AUX", "NUL"]
    + [f"COM{i}" for i in range(10)] + [f"LPT{i}" for i in range(10)])

ERR_INVALID_PROJECT_ID = "invalid_project_id"
ERR_INVALID_USER_ID = "invalid_user_id"
ERR_INVALID_VIEW = "invalid_view"
# Raised by the helpers below; never an HTTP answer of their own.
ERR_INVALID_INSTANCE = "invalid_instance"
ERR_INVALID_PORT = "invalid_port"
ERR_INVALID_ENVELOPE = "invalid_envelope"
ERR_INVALID_VOLUME = "invalid_volume"


def valid_user_id(user_id) -> bool:
    return (isinstance(user_id, str) and _USER_ID.fullmatch(user_id) is not None
            and user_id not in RESERVED_USER_IDS)


def valid_project_id(project_id) -> bool:
    return (isinstance(project_id, str) and _PROJECT_ID.fullmatch(project_id) is not None
            and project_id.upper() not in _WINDOWS_DEVICE_NAMES)


def valid_instance(instance) -> bool:
    return isinstance(instance, str) and _INSTANCE.fullmatch(instance) is not None


def check_user_id(user_id) -> str:
    if not valid_user_id(user_id):
        raise ValueError(ERR_INVALID_USER_ID)
    return user_id


def check_project_id(project_id) -> str:
    if not valid_project_id(project_id):
        raise ValueError(ERR_INVALID_PROJECT_ID)
    return project_id


def check_instance(instance) -> str:
    if not valid_instance(instance):
        raise ValueError(ERR_INVALID_INSTANCE)
    return instance


def normalize_projects(project_ids) -> list:
    """The project ids sorted and de-duplicated; ``ValueError("invalid_project_id")``
    for a bad id, or for a bare string (which would iterate into characters)."""
    if isinstance(project_ids, (str, bytes)) or project_ids is None:
        raise ValueError(ERR_INVALID_PROJECT_ID)
    try:
        ids = list(project_ids)
    except TypeError:
        raise ValueError(ERR_INVALID_PROJECT_ID) from None
    for project_id in ids:
        check_project_id(project_id)
    return sorted(set(ids))


# --- Views, names, labels, keys ---------------------------------------------------

IMAGE = "redamon-kali-sandbox:latest"

VIEW_OWN = "own"
VIEW_ACT_AS = "act_as"
VIEWS = (VIEW_OWN, VIEW_ACT_AS)


def check_view(view) -> str:
    if view not in VIEWS or not isinstance(view, str):
        raise ValueError(ERR_INVALID_VIEW)
    return view


def _hex16(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def user_key(user_id: str) -> str:
    return _hex16(check_user_id(user_id))


def sandbox_key(user_id: str, view: str) -> str:
    """The key of one view of a person. USER_ID_RE has no `:`, so no user id can
    hash to the `act_as:` string of another: the two views never share a key."""
    check_view(view)
    check_user_id(user_id)
    if view == VIEW_OWN:
        return user_key(user_id)
    return _hex16("act_as:" + user_id)


def network_name(user_id: str, view: str) -> str:
    return f"redamon-sbx-{sandbox_key(user_id, view)}"


def new_instance() -> str:
    return secrets.token_hex(3)


def container_name(user_id: str, view: str, instance: str) -> str:
    return f"redamon-kali-{sandbox_key(user_id, view)}-{check_instance(instance)}"


RESERVATION_PREFIX = "kali_sandbox:"


def reservation_key(user_id: str, instance: str) -> str:
    """The governor key of one instance (instances are unique across views)."""
    return f"{RESERVATION_PREFIX}{check_user_id(user_id)}:{check_instance(instance)}"


ENVELOPE_PROFILE_KEY = "kali_sandbox_envelope_bytes"

LABEL_SANDBOX = "redamon.sandbox"
LABEL_USER = "redamon.sandbox.user"
LABEL_VIEW = "redamon.sandbox.view"
LABEL_KEY = "redamon.sandbox.key"
LABEL_INSTANCE = "redamon.sandbox.instance"
LABEL_PROJECTS = "redamon.sandbox.projects"
LABEL_CREATED = "redamon.sandbox.created"
LABEL_PORT = "redamon.sandbox.port"
LABEL_SERVERS = "redamon.sandbox.servers"
LABEL_CONTRACT = "redamon.sandbox.contract"
LABEL_ROLE = "redamon.sandbox.role"
LABEL_TRUE = "1"
ROLE_TEMPLATES = "templates"


def projects_hash(project_ids) -> str:
    return _hex16("\n".join(normalize_projects(project_ids)))


def container_labels(user_id: str, view: str, instance: str, project_ids, *,
                     created: float, port: Optional[int], servers: str) -> dict:
    """The labels of a sandbox container. They hold the user id (for the
    orchestrator's adoption), never a token; labels are not visible inside."""
    return {
        LABEL_SANDBOX: LABEL_TRUE,
        LABEL_USER: check_user_id(user_id),
        LABEL_VIEW: check_view(view),
        LABEL_KEY: sandbox_key(user_id, view),
        LABEL_INSTANCE: check_instance(instance),
        LABEL_PROJECTS: projects_hash(project_ids),
        LABEL_CREATED: str(int(created)),
        LABEL_PORT: str(port) if port else "",
        LABEL_SERVERS: servers,
        LABEL_CONTRACT: str(CONTRACT_VERSION),
    }


def templates_labels() -> dict:
    """The nuclei templates refresher: a sandbox-labelled container with no user."""
    return {LABEL_SANDBOX: LABEL_TRUE, LABEL_ROLE: ROLE_TEMPLATES}


def servers_hash(entries: Iterable) -> str:
    """First 16 hex of the SHA-256 over sorted ``(relative path, size, mtime)``."""
    text = "".join(f"{rel}\0{size}\0{mtime}\n" for rel, size, mtime in sorted(entries))
    return _hex16(text)


def servers_fingerprint(root: str) -> str:
    """``servers_hash`` of the files under ``root`` (the orchestrator's
    /app/mcp-servers). Bytecode and dot folders are skipped: a test run that
    imports the servers writes __pycache__ there, and must not drain every
    running sandbox as if the server code had changed."""
    entries = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != "__pycache__" and not d.startswith(".")]
        for name in filenames:
            if name.endswith((".pyc", ".pyo")):
                continue
            path = os.path.join(dirpath, name)
            try:
                st = os.stat(path)
            except OSError:
                continue
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            entries.append((rel, st.st_size, st.st_mtime_ns))
    return servers_hash(entries)


TEMPLATES_VOLUME = "redamon-kali-nuclei-templates"
TEMPLATES_REFRESH_CONTAINER = "redamon-kali-templates-refresh"
AGENT_ALIAS = "agent"
# The agent is found by its compose service label in the orchestrator's own
# compose project, falling back to its container name.
AGENT_COMPOSE_SERVICE = "agent"
AGENT_CONTAINER_NAME = "redamon-agent"
COMPOSE_SERVICE_LABEL = "com.docker.compose.service"
COMPOSE_PROJECT_LABEL = "com.docker.compose.project"
CAPTURE_PROXY_NAME = "redamon-capture-proxy"
SUBNET_POOL = "10.214.0.0/16"
SUBNET_PREFIX = 28
GUEST_GATEWAY_PRIORITY = -1000
# A guest (the agent, the capture proxy) joins a sandbox network only when its
# HostConfig.Sysctls holds these: it must never route between its networks.
GUEST_SYSCTLS = MappingProxyType({"net.ipv4.ip_forward": "0"})

# --- The mount plan ---------------------------------------------------------------


class MountTarget(NamedTuple):
    """One mount: ``kind`` names the host base (``MOUNT_HOST_BASES``) or a named
    volume; ``rel`` is joined under that base, `/`-separated (or is the volume
    name); ``target`` is the path inside the sandbox."""
    kind: str
    rel: str
    target: str
    read_only: bool

    def rel_parts(self) -> tuple:
        return tuple(p for p in self.rel.split("/") if p)


MOUNT_WORKSPACE = "workspace"
MOUNT_OUTPUT = "output"
MOUNT_SERVERS = "servers"
MOUNT_GRAPH_DB = "graph_db"
MOUNT_CUSTOM_TEMPLATES = "custom_templates"
MOUNT_TEMPLATES_VOLUME = "volume:templates"
MOUNT_OSV_VOLUME = "volume:osv"
MOUNT_KINDS = (MOUNT_WORKSPACE, MOUNT_OUTPUT, MOUNT_SERVERS, MOUNT_GRAPH_DB,
               MOUNT_CUSTOM_TEMPLATES, MOUNT_TEMPLATES_VOLUME, MOUNT_OSV_VOLUME)
# The orchestrator's own mounts that each host-side kind resolves against.
MOUNT_HOST_BASES = MappingProxyType({
    MOUNT_WORKSPACE: "/app/agent-workspace",
    MOUNT_OUTPUT: "/app/mcp-output",
    MOUNT_SERVERS: "/app/mcp-servers",
    MOUNT_GRAPH_DB: "/app/graph_db",
    MOUNT_CUSTOM_TEMPLATES: "/app/nuclei-templates",
})
WORKSPACE_ROOT = "/workspace"
OUTPUT_TARGET = "/opt/output"
OUTPUT_USERS_DIR = "users"
# Each view's copy of the custom nuclei templates its person may use, made by the
# orchestrator under the output base (never inside a `users/` folder, which the
# sandbox writes). The shared folder of every member's templates is never mounted.
CUSTOM_TEMPLATES_COPY_DIR = "templates"
SERVERS_TARGET = "/opt/mcp_servers"
GRAPH_DB_TARGET = "/opt/graph_db"
CUSTOM_TEMPLATES_TARGET = "/opt/nuclei-templates"
TEMPLATES_TARGET = "/root/nuclei-templates"
OSV_TARGET = "/osv-db"
# The orchestrator's SUPPLY_CHAIN_OSV_DB_VOLUME default.
OSV_VOLUME_DEFAULT = "redamon-osv-db"
_VOLUME_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,254}")


def output_rel(user_id: str, view: str) -> str:
    return f"{OUTPUT_USERS_DIR}/{sandbox_key(user_id, view)}"


def custom_templates_rel(user_id: str, view: str) -> str:
    return f"{CUSTOM_TEMPLATES_COPY_DIR}/{sandbox_key(user_id, view)}"


def person_output_rels(user_id: str) -> tuple:
    """Both views' output folders: what a stop for ``account_deleted`` removes."""
    return tuple(output_rel(user_id, view) for view in VIEWS)


# One custom template as the webapp names it: a path relative to the templates
# folder, plain segments (no dot-led one, so no `..` and no hidden file), ending
# in .yaml or .yml. The webapp's uploads always fit; a file an operator put on
# the host under another name is simply not copied.
_TEMPLATE_SEGMENT = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}")
_TEMPLATE_FILE = re.compile(r".*\.ya?ml", re.IGNORECASE)
CUSTOM_TEMPLATES_MAX_DEPTH = 8


def normalize_template_paths(paths) -> list:
    """The template paths of an ensure, sorted and de-duplicated. An entry that is
    not such a path is dropped (it can name no file the person may use); a value
    that is not a list of strings is an empty list."""
    if isinstance(paths, (str, bytes)) or paths is None:
        return []
    try:
        entries = list(paths)
    except TypeError:
        return []
    out = set()
    for entry in entries:
        if not isinstance(entry, str):
            continue
        parts = entry.split("/")
        if (len(parts) <= CUSTOM_TEMPLATES_MAX_DEPTH and _TEMPLATE_FILE.fullmatch(parts[-1])
                and all(_TEMPLATE_SEGMENT.fullmatch(p) for p in parts)):
            out.add(entry)
    return sorted(out)


def mount_targets(user_id: str, view: str, project_ids, *,
                  osv_volume: str = OSV_VOLUME_DEFAULT,
                  custom_templates: bool = True) -> list:
    """Everything a sandbox mounts, and nothing else: one read-write folder per
    allowed project, the view's own output folder, and read-only tools.

    The workspace root and `.staging` can never appear (PROJECT_ID_RE has no
    dot); an empty project list is valid. The custom nuclei templates are the
    view's own copy (``custom_templates_rel``) of its person's templates and the
    instance's; pass ``custom_templates=False`` when that copy is empty."""
    key = sandbox_key(user_id, view)
    projects = normalize_projects(project_ids)
    if not isinstance(osv_volume, str) or not _VOLUME_NAME.fullmatch(osv_volume):
        raise ValueError(ERR_INVALID_VOLUME)
    mounts = [MountTarget(MOUNT_WORKSPACE, pid, f"{WORKSPACE_ROOT}/{pid}", False)
              for pid in projects]
    mounts += [
        MountTarget(MOUNT_OUTPUT, f"{OUTPUT_USERS_DIR}/{key}", OUTPUT_TARGET, False),
        MountTarget(MOUNT_SERVERS, "", SERVERS_TARGET, True),
        MountTarget(MOUNT_GRAPH_DB, "", GRAPH_DB_TARGET, True),
    ]
    if custom_templates:
        mounts.append(MountTarget(MOUNT_OUTPUT, f"{CUSTOM_TEMPLATES_COPY_DIR}/{key}",
                                  CUSTOM_TEMPLATES_TARGET, True))
    mounts += [
        MountTarget(MOUNT_TEMPLATES_VOLUME, TEMPLATES_VOLUME, TEMPLATES_TARGET, True),
        MountTarget(MOUNT_OSV_VOLUME, osv_volume, OSV_TARGET, True),
    ]
    for m in mounts:
        if m.target == WORKSPACE_ROOT or m.target.startswith(WORKSPACE_ROOT + "/."):
            raise ValueError(ERR_INVALID_PROJECT_ID)
    return mounts


def projects_from_destinations(destinations: Iterable) -> list:
    """The project ids of a running sandbox, read back from its mount
    destinations (adoption). A workspace mount that is not one valid project
    folder raises ``ValueError``: such a container is not adopted."""
    projects = []
    for dest in destinations:
        if dest == WORKSPACE_ROOT or dest.startswith(WORKSPACE_ROOT + "/"):
            projects.append(check_project_id(dest[len(WORKSPACE_ROOT) + 1:]))
    return sorted(set(projects))


# --- The container ----------------------------------------------------------------

# The name tools and prompts inside a sandbox use for the sandbox itself. Docker makes
# a container's hostname a DNS name on the network it is created on, and the agent and
# the capture proxy join every sandbox network: a hostname all sandboxes shared would
# resolve, from them, to whichever sandbox came first. So a sandbox's hostname is its
# own container name, and this name resolves only inside the sandbox, to itself, from
# its own /etc/hosts (EXTRA_HOSTS).
SELF_NAME = "kali-sandbox"
EXTRA_HOSTS = MappingProxyType({SELF_NAME: "127.0.0.1"})
CONTAINER_ENV_FIXED = MappingProxyType({
    "PYTHONUNBUFFERED": "1",
    "PYTHONPATH": "/opt:/opt/mcp_servers",
    "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": "/osv-db",
    "PYTHONDONTWRITEBYTECODE": "1",
    "MCP_TRANSPORT": "sse",
    "MCP_HOST": "0.0.0.0",
    "NETWORK_RECON_PORT": "8000",
    "NUCLEI_PORT": "8002",
    "METASPLOIT_PORT": "8003",
    "NMAP_PORT": "8004",
    "PLAYWRIGHT_PORT": "8005",
    "MSF_PROGRESS_PORT": "8013",
    "HYDRA_PROGRESS_PORT": "8014",
    "TERMINAL_WS_PORT": "8016",
    "MSF_AUTO_UPDATE": "false",
    "NUCLEI_AUTO_UPDATE": "false",
    "REDAMON_AGENT_URL": "http://agent:8080",
    "WEBAPP_API_URL": "",
    # No server branches on it (a sandbox is always one person's); every sandbox
    # started so far carries it, and adoption requires the fixed environment as is.
    "REDAMON_SANDBOX_MODE": "per_user",
})
ENV_MCP_AUTH_TOKEN = "MCP_AUTH_TOKEN"
ENV_TUNNEL_AUTH_TOKEN = "TUNNEL_AUTH_TOKEN"
ENV_SANDBOX_KEY = "REDAMON_SANDBOX_KEY"
ENV_REVERSE_PORT = "MSF_REVERSE_PORT"
TERMINAL_MAX_SESSIONS_ENV = "TERMINAL_MAX_SESSIONS"
TOKEN_BYTES = 32
DEFAULT_REVERSE_PORT = 4444
# Platform secrets and credentials a sandbox never receives. Its own two tokens
# are the only secrets in its environment, and only the person's key, never
# their user id.
NEVER_IN_ENV = (
    "INTERNAL_API_KEY", "SCANNER_API_KEY", "AUTH_SECRET", "ORCHESTRATOR_API_KEY",
    "AGENT_WS_TICKET_SECRET", "PLUGIN_CALL_TOKEN_SECRET", "REDAMON_SECRET_HMAC_KEY",
    "DATABASE_URL", "POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_DB",
    "NEO4J_URI", "NEO4J_USER", "NEO4J_PASSWORD", "GVM_PASSWORD",
    "NVD_API_KEY", "KB_EMBEDDING_API_KEY", "MCP_SERVER_TOKEN",
    "NGROK_AUTHTOKEN", "CHISEL_AUTH",
)
_DIGITS = re.compile(r"[0-9]{1,9}")


def _check_port(port) -> int:
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ValueError(ERR_INVALID_PORT)
    return port


def instance_env(user_id: str, view: str, instance: str,
                 reverse_port: Optional[int] = None,
                 environ: Optional[Mapping] = None) -> dict:
    """The per-instance environment: two new independent random tokens on every
    call, the view's key, the reverse-shell port (the pool port, or 4444), and
    ``TERMINAL_MAX_SESSIONS`` copied from ``environ`` (the orchestrator's own
    environment by default) when it holds a number."""
    check_instance(instance)
    env = {
        ENV_MCP_AUTH_TOKEN: secrets.token_urlsafe(TOKEN_BYTES),
        ENV_TUNNEL_AUTH_TOKEN: secrets.token_urlsafe(TOKEN_BYTES),
        ENV_SANDBOX_KEY: sandbox_key(user_id, view),
        ENV_REVERSE_PORT: str(DEFAULT_REVERSE_PORT if reverse_port is None
                              else _check_port(reverse_port)),
    }
    raw = (os.environ if environ is None else environ).get(TERMINAL_MAX_SESSIONS_ENV)
    if isinstance(raw, str) and _DIGITS.fullmatch(raw.strip()):
        env[TERMINAL_MAX_SESSIONS_ENV] = raw.strip()
    return env


def container_env(user_id: str, view: str, instance: str,
                  reverse_port: Optional[int] = None,
                  environ: Optional[Mapping] = None) -> dict:
    """A fresh dict: ``CONTAINER_ENV_FIXED`` plus ``instance_env``."""
    env = dict(CONTAINER_ENV_FIXED)
    env.update(instance_env(user_id, view, instance, reverse_port, environ))
    if set(env) & set(NEVER_IN_ENV):
        raise ValueError("secret_in_env")
    return env


PIDS_LIMIT = 4096
MAX_CPUS = 4


def limits(envelope: int, cpu_count: Optional[int]) -> dict:
    """docker-py keyword arguments: memory and swap equal the envelope (no
    swap beyond it), a process cap, and half the host's CPUs between 1 and 4."""
    if not isinstance(envelope, int) or isinstance(envelope, bool) or envelope <= 0:
        raise ValueError(ERR_INVALID_ENVELOPE)
    cpus = max(1, min(MAX_CPUS, (cpu_count or 1) // 2))
    return {"mem_limit": envelope, "memswap_limit": envelope,
            "pids_limit": PIDS_LIMIT, "nano_cpus": cpus * 1_000_000_000}


# The tools need these unchanged; see the orchestrator-container-spawn skill for
# why no cap_drop and no no-new-privileges.
CAP_ADD = ("NET_ADMIN", "NET_RAW")
SECURITY_OPT = ("seccomp=unconfined",)
DNS = ("8.8.8.8", "8.8.4.4")
RESTART_POLICY = MappingProxyType({"Name": "no"})

HEALTH_PROBE_PORTS = (8000, 8002, 8003, 8004, 8005, 8013, 8015, 8016)
HEALTH_PROBE = (
    "import socket,sys\n"
    f"for p in {HEALTH_PROBE_PORTS!r}:\n"
    "    try:\n"
    "        socket.create_connection(('127.0.0.1', p), 1).close()\n"
    "    except OSError:\n"
    "        sys.exit(1)\n"
)
HEALTH_INTERVAL_S = 2
HEALTH_TIMEOUT_S = 2
HEALTH_RETRIES = 3
HEALTH_START_INTERVAL_S = 1
_NS = 1_000_000_000


def healthcheck(start_timeout_s: int) -> dict:
    """docker-py healthcheck keys, durations in nanoseconds. docker-py 7.2's
    Healthcheck type drops ``start_interval``; a caller that wants it sends it
    as the API's ``StartInterval``."""
    return {
        "test": ["CMD", "python3", "-c", HEALTH_PROBE],
        "interval": HEALTH_INTERVAL_S * _NS,
        "timeout": HEALTH_TIMEOUT_S * _NS,
        "retries": HEALTH_RETRIES,
        "start_period": int(start_timeout_s) * _NS,
        "start_interval": HEALTH_START_INTERVAL_S * _NS,
    }


DEFAULT_POOL_BIND_IP = "127.0.0.1"


def published_ports(pool_port: Optional[int], bind_ip: str = DEFAULT_POOL_BIND_IP) -> dict:
    """Nothing is published but the pool port, when the instance has one."""
    if pool_port is None:
        return {}
    port = _check_port(pool_port)
    return {f"{port}/tcp": (bind_ip, port)}


# The ports a sandbox serves on its own network (`ensure` answers them).
PORTS = MappingProxyType({
    "network_recon": 8000, "nuclei": 8002, "metasploit": 8003, "nmap": 8004,
    "playwright": 8005, "sessions": 8013, "hydra": 8014, "tunnel": 8015,
    "terminal": 8016, "ngrok_api": 4040,
})

# --- The network ------------------------------------------------------------------

NETWORK_DRIVER = "bridge"
# Not internal: the tools need NAT egress.
NETWORK_INTERNAL = False


def network_labels(user_id: str, view: str) -> dict:
    return {LABEL_SANDBOX: LABEL_TRUE, LABEL_USER: check_user_id(user_id),
            LABEL_VIEW: check_view(view), LABEL_KEY: sandbox_key(user_id, view)}


class SubnetPoolExhausted(RuntimeError):
    """No free /28 is left in SUBNET_POOL."""


def allocate_subnet(used_subnets: Iterable) -> str:
    """The lowest /28 of SUBNET_POOL that overlaps none of ``used_subnets`` (the
    subnets of every existing Docker network; empty entries and other address
    families are ignored, a malformed one raises ``ValueError``). The caller
    holds the global allocation lock."""
    pool = ipaddress.ip_network(SUBNET_POOL)
    base = int(pool.network_address)
    top = int(pool.broadcast_address)
    step = 1 << (pool.max_prefixlen - SUBNET_PREFIX)
    blocked = set()
    for entry in used_subnets:
        if entry is None or entry == "":
            continue
        net = ipaddress.ip_network(str(entry).strip(), strict=False)
        if net.version != pool.version:
            continue
        lo = max(int(net.network_address), base)
        hi = min(int(net.broadcast_address), top)
        if lo <= hi:
            blocked.update(range((lo - base) // step, (hi - base) // step + 1))
    for index in range(pool.num_addresses // step):
        if index not in blocked:
            return str(ipaddress.ip_network((base + index * step, SUBNET_PREFIX)))
    raise SubnetPoolExhausted(SUBNET_POOL)


def gateway_for(subnet: str) -> str:
    """The first host address of the subnet."""
    return str(next(ipaddress.ip_network(subnet).hosts()))


# --- The governor -----------------------------------------------------------------

ENVELOPE_DEFAULT_BYTES = 1_073_741_824
RESOURCE = "kali_sandbox"
MAX_CONCURRENT_SETTING = "KALI_SANDBOX_MAX_CONCURRENT"
LIMIT_TYPES = ("ram", "hard")
# The keys of AdmissionResult.payload(), which a 409 refusal carries.
LIMIT_PAYLOAD_KEYS = ("admitted", "limitType", "resource", "current", "ceiling",
                      "settingName", "detail")
STATS_ACTIVE_SANDBOXES = "active_sandboxes"
STATS_SANDBOX_COMMITTED = "sandbox_committed"
STATS_SANDBOX_ENVELOPE = "sandbox_envelope"

# --- The lifecycle and leases -----------------------------------------------------

STATES = ("starting", "running", "draining", "stopping")
STOP_REASONS = ("idle", "hold_unused", "access_lost", "account_disabled",
                "account_deleted", "project_deleted", "last_project_deleted",
                "emergency", "operator", "replaced", "start_failed", "crashed")
# The only stop that also deletes the person's output folders (both views).
STOP_REASON_DELETES_OUTPUT = "account_deleted"
LEASE_KINDS = ("run", "terminal", "exec", "job", "triage", "tradecraft", "interact", "hold")
HOLD_LEASE_KIND = "hold"
# Every kind but `hold` counts as use (renews last_used).
USE_KINDS = ("run", "terminal", "exec", "job", "triage", "tradecraft", "interact")

# --- The orchestrator API ---------------------------------------------------------

ROUTE_ENSURE = "/sandboxes/ensure"
ROUTE_LEASES = "/sandboxes/{user_id}/leases"
ROUTE_LEASE = "/sandboxes/{user_id}/leases/{lease_id}"
ROUTE_RECONCILE = "/sandboxes/{user_id}/reconcile"
ROUTE_STOP_USER = "/sandboxes/{user_id}/stop"
ROUTE_STOP_PROJECT = "/sandboxes/stop-project"
ROUTE_STOP_ALL = "/sandboxes/stop-all"
ROUTE_STATUS = "/sandboxes/{user_id}"
ROUTE_LIST = "/sandboxes"
ROUTE_SYSTEM_STATS = "/system/stats"

# The keys of an `ensure` answer: 200 with a running instance, 202 when the call
# did not wait. Both carry `fresh` (this call created the instance), because the
# webapp writes the start's audit row and turns the person's tunnels off on it,
# and a non-waiting call (the warm-up) is often the one that creates it.
ENSURE_RUNNING_KEYS = ("user_id", "view", "instance", "host", "token",
                       "tunnel_token", "ports", "reverse_port", "projects", "state",
                       "fresh", "stop_at", "stop_reason", "warn")
ENSURE_STARTING_KEYS = ("state", "instance", "fresh")

# Why an answer's `reverse_port` is what it is: a pool port was given to the
# instance, no pool is configured, or the pool had no port free for this person
# and view (every one in use or held for someone else, see PORT_HOLD_HOURS_ENV).
# Without a pool port the sandbox's reverse port is DEFAULT_REVERSE_PORT, which
# only a tunnel the person runs reaches.
REVERSE_PORT_ASSIGNED = "assigned"
REVERSE_PORT_NO_POOL = "no_pool"
REVERSE_PORT_POOL_FULL = "pool_full"
REVERSE_PORT_STATES = (REVERSE_PORT_ASSIGNED, REVERSE_PORT_NO_POOL, REVERSE_PORT_POOL_FULL)
# Keys this orchestrator always sends and an older one did not: a reader keeps
# them when present and never requires them (reverse_port_state() reads one). A
# starting instance's status carries null until its port is allocated.
ENSURE_RUNNING_OPTIONAL_KEYS = ("reverse_port_state",)
STATUS_OPTIONAL_KEYS = ("reverse_port_state",)
LIST_OPTIONAL_KEYS = ("reverse_port", "reverse_port_state")


def reverse_port_state(value) -> Optional[str]:
    """One of REVERSE_PORT_STATES, or None (unknown) for a missing or other value:
    an answer from an orchestrator older than the field is never an error."""
    return value if isinstance(value, str) and value in REVERSE_PORT_STATES else None

ERR_IMAGE_MISSING = "sandbox_image_missing"
ERR_START_FAILED = "sandbox_start_failed"
ERR_START_TIMEOUT = "sandbox_start_timeout"
ERR_UNKNOWN_INSTANCE = "unknown_instance"
ERR_NOT_RUNNING = "sandbox_not_running"
ERR_DRAINING = "sandbox_draining"
ERR_RAM = "sandbox_ram"
ERR_HARD = "sandbox_hard"
# Answered by the webapp gateway, not the orchestrator.
ERR_USER_REFUSED = "sandbox_user_refused"
ERR_PROJECT_REFUSED = "sandbox_project_refused"
ERROR_STATUS = MappingProxyType({
    ERR_INVALID_PROJECT_ID: 400, ERR_INVALID_USER_ID: 400, ERR_INVALID_VIEW: 400,
    ERR_USER_REFUSED: 403, ERR_PROJECT_REFUSED: 403,
    ERR_UNKNOWN_INSTANCE: 404,
    ERR_NOT_RUNNING: 409, ERR_DRAINING: 409, ERR_RAM: 409, ERR_HARD: 409,
    ERR_IMAGE_MISSING: 503, ERR_START_FAILED: 503,
    ERR_START_TIMEOUT: 504,
})
REFUSAL_CODE_BY_LIMIT = MappingProxyType({"ram": ERR_RAM, "hard": ERR_HARD})

# --- The webapp gateway and the agent's routes ------------------------------------

INTERNAL_ROUTE_ENSURE = "/api/internal/agent/sandbox/ensure"
INTERNAL_ROUTE_LEASE = "/api/internal/agent/sandbox/lease"
INTERNAL_ROUTE_RELEASE = "/api/internal/agent/sandbox/release"
INTERNAL_ROUTE_LIST = "/api/internal/agent/sandbox/list"
SESSION_ROUTE_STATUS = "/api/agent/sandbox/status"
AGENT_ROUTE_DROP = "/sandboxes/{user_id}/drop"
AGENT_ROUTE_TUNNEL = "/sandboxes/{user_id}/tunnel"

# --- Events and messages ----------------------------------------------------------

# The router's SandboxUnavailable reasons; `no_user` never reaches a browser.
UNAVAILABLE_REASONS = ("ram", "hard", "error", "no_user", "refused", "stopped")
SANDBOX_STATUS = "sandbox_status"
SANDBOX_STATUS_STATES = ("starting", "ready", "unavailable")
SANDBOX_STATUS_REASONS = ("ram", "hard", "error", "refused", "stopped")

SANDBOX_UNAVAILABLE_RAM = "sandbox unavailable: not enough memory"
SANDBOX_UNAVAILABLE_HARD = "sandbox unavailable: the instance's sandbox limit is reached"
SANDBOX_UNAVAILABLE_ERROR = "sandbox unavailable: the sandbox could not start"
SANDBOX_REFUSED = "sandbox unavailable: this person may not use the Kali sandbox on this project"
SANDBOX_STOPPED = "sandbox stopped during the call"

# Terminal socket close codes after a `sandbox_status` frame: 1013 "try again
# later" for ram/hard/error, 1008 "policy violation" for refused.
TERMINAL_CLOSE_UNAVAILABLE = 1013
TERMINAL_CLOSE_REFUSED = 1008

KALI_EXEC_STATUS_STARTING = "starting"
KALI_EXEC_ERROR_CODES = ("ram", "hard", "sandbox_error", "sandbox_refused", "sandbox_stopped")

SHARE_KEYS_LENT_TEXT = (
    "This person's agent runs on this project use your WPScan, URLScan and "
    "ProjectDiscovery keys inside a Kali sandbox, where this person can read them "
    "while their runs use them.")
MODAL_RAM_TITLE = "Not enough memory"
MODAL_RAM_BODY = ("Your Kali sandbox cannot start now: the instance's memory is in use "
                  "by scans and other sandboxes.")
MODAL_HARD_TITLE = "Sandbox limit reached"
MODAL_HARD_BODY = "Your Kali sandbox cannot start now: the instance's sandbox limit is reached."
MODAL_REFUSED_TITLE = "Kali sandbox not available"
MODAL_REFUSED_BODY = ("You cannot use the Kali sandbox on this project. Ask its owner for "
                      "Use AI agent or Exploitation & shells.")
MODAL_RETRY_LABEL = "Retry"
MODAL_CLOSE_LABEL = "Close"
PARTIAL_ANSWER_ONE = "1 sandbox did not answer; its sessions may be out of date or missing"
PARTIAL_ANSWER_MANY = "{n} sandboxes did not answer; their sessions may be out of date or missing"

# --- Environment variables --------------------------------------------------------

IDLE_MINUTES_ENV = "KALI_SANDBOX_IDLE_MINUTES"
MAX_CONCURRENT_ENV = "KALI_SANDBOX_MAX_CONCURRENT"
PORT_POOL_ENV = "KALI_SANDBOX_PORT_POOL"
# How long a pool port stays reserved for its person and view after their
# instance stops or is replaced: a callback still on its way (a phishing payload,
# an implant, a handler left waiting at the hold cap) must never land in another
# person's sandbox, and the person gets the same port back on their next start.
PORT_HOLD_HOURS_ENV = "KALI_SANDBOX_PORT_HOLD_HOURS"
# Every one is optional and read by the orchestrator only.
ENV_VARS = (IDLE_MINUTES_ENV, MAX_CONCURRENT_ENV, PORT_POOL_ENV, PORT_HOLD_HOURS_ENV)
IDLE_MINUTES_DEFAULT = 20
PORT_HOLD_HOURS_DEFAULT = 24


def idle_minutes(value: Optional[str]) -> int:
    """An integer of at least 1, else ``IDLE_MINUTES_DEFAULT``."""
    if isinstance(value, str) and _DIGITS.fullmatch(value.strip()):
        minutes = int(value.strip())
        if minutes >= 1:
            return minutes
    return IDLE_MINUTES_DEFAULT


def port_hold_hours(value: Optional[str]) -> int:
    """An integer of at least 0 (0: a stopped instance's port is free at once),
    else ``PORT_HOLD_HOURS_DEFAULT``."""
    if isinstance(value, str) and _DIGITS.fullmatch(value.strip()):
        return int(value.strip())
    return PORT_HOLD_HOURS_DEFAULT


def max_concurrent(value: Optional[str]) -> Optional[int]:
    """An integer of at least 0 (0 blocks every new sandbox), else None (no cap)."""
    if isinstance(value, str) and _DIGITS.fullmatch(value.strip()):
        return int(value.strip())
    return None


@dataclass(frozen=True)
class PortPool:
    bind_ip: str
    first: int
    last: int

    def ports(self) -> tuple:
        """The pool's ports, never ``DEFAULT_REVERSE_PORT``: a sandbox without a pool port
        listens there, so the agent reads that port as "nothing published"."""
        return tuple(p for p in range(self.first, self.last + 1) if p != DEFAULT_REVERSE_PORT)


_PORT_RANGE = re.compile(r"([0-9]{1,5})-([0-9]{1,5})")


def port_pool(value: Optional[str]) -> Optional[PortPool]:
    """``[bind-ip:]first-last`` (an IPv6 address may be bracketed); bound on
    127.0.0.1 when no address is given. Unset or malformed: None (no pool), which
    the caller logs when the value was not empty."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    bind_ip = DEFAULT_POOL_BIND_IP
    if ":" in text:
        address, _, text = text.rpartition(":")
        if address.startswith("[") and address.endswith("]"):
            address = address[1:-1]
        try:
            bind_ip = str(ipaddress.ip_address(address))
        except ValueError:
            return None
    match = _PORT_RANGE.fullmatch(text)
    if not match:
        return None
    first, last = int(match.group(1)), int(match.group(2))
    if not 1 <= first <= last <= 65535:
        return None
    return PortPool(bind_ip, first, last)


# --- Timings (seconds) ------------------------------------------------------------

LEASE_TTL_S = 90
LEASE_RENEW_S = 30
IDLE_CHECK_S = 60
HOLD_MAX_NO_USE_S = 28_800
HOLD_WARN_BEFORE_S = 3_600
HOLD_WATCH_S = 60
STOP_GRACE_S = 10
# 300 s floor: three times the measured cold start (3.4 s) is far below it.
START_TIMEOUT_S = 300
TEMPLATES_REFRESH_S = 86_400
# The agent's wait on the webapp outlasts the webapp's wait on the orchestrator,
# which outlasts the start itself, so each layer answers before its caller gives up.
GATEWAY_ENSURE_TIMEOUT_S = START_TIMEOUT_S + 30
GATEWAY_TIMEOUT_S = 10
ORCHESTRATOR_ENSURE_TIMEOUT_S = START_TIMEOUT_S + 15
FANOUT_TIMEOUT_S = 5
