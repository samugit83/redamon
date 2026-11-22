#!/usr/bin/env python3
"""
Docker socket broker (V4) — a filtering reverse proxy for the Docker Engine API.

WHY THIS EXISTS
---------------
The recon / partial-recon containers spawn their scan tools as sibling
containers via the Docker socket. Mounting the raw `/var/run/docker.sock` into a
container is equivalent to giving it root on the host: a compromised recon
container could `docker run -v /:/host --privileged <anything>` and own the
machine.

This broker sits BETWEEN the recon container and the real Docker socket. The
recon container mounts the broker's socket instead of the real one. The broker
blocks by default (decision D4): only the Docker API calls the scan tools' real
`docker` invocations make are forwarded (`_ROUTES`), each with its method, and
everything else is refused with a 403 and one log line before the daemon is
contacted. `POST /containers/create` bodies are validated against an allowlist —
rejecting any request that would let a container escape to the host
(bind-mounting host paths, --privileged, dangerous caps/namespaces, mounting the
docker socket, or a non-allowlisted image). Verbs on existing containers are
allowed only on containers the broker itself created, for the run the caller
names (RUN_HEADER), and reach the daemon by the full id the check read.

The orchestrator keeps the REAL socket (it is the trusted component). Only the
recon/partial-recon containers are put behind the broker.

DESIGN (deliberately simple to stay correct)
---------------------------------------------
One Docker API request per client connection. The daemon gets a head the broker
writes itself (the checked request line, a few allowlisted headers and
`Connection: close`, so the upstream closes after each response and the docker
client just reconnects for the next call), never the client's bytes. For each
connection:
  * parse the request line + headers, refusing any head the daemon could read
    differently (bare CR/LF, control bytes, folded or repeated headers,
    Transfer-Encoding), then the body via Content-Length,
  * match it against `_ROUTES`; no match -> 403,
  * if it is an attach (`/containers/<id>/attach`) -> forward the upgrade and,
    once the daemon answers 101, pipe BYTES bidirectionally until close
    (handles streamed stdin/stdout, e.g. hakrawler's piped stdin and live tool
    output); any other answer is relayed and the connection closed,
  * if it carries a body the broker checks (container, volume or network
    create) -> validate it; reject with 403 or forward the body as validated
    (re-serialized) + relay the response,
  * otherwise -> forward and relay the (possibly streamed/chunked) response.

Stdlib only (asyncio + json) so it runs in a tiny image with no dependencies.
"""
import asyncio
import collections
import ipaddress
import json
import os
import re
import sys
import time
import urllib.parse

# --------------------------------------------------------------------------
# Policy (allowlist). Seeded from env so it can be kept in sync with V3.
# --------------------------------------------------------------------------
UPSTREAM_SOCK = os.environ.get("DOCKER_BROKER_UPSTREAM", "/var/run/docker.sock")
LISTEN_SOCK = os.environ.get("DOCKER_BROKER_LISTEN", "/run/broker/docker.sock")

# Tool images the recon pipeline is allowed to run (the V3 set + cleanup helpers).
_DEFAULT_ALLOWED_IMAGES = [
    "projectdiscovery/naabu:latest",
    "projectdiscovery/httpx:latest",
    "projectdiscovery/katana:latest",
    "projectdiscovery/nuclei:latest",
    "projectdiscovery/uncover:latest",
    "projectdiscovery/subfinder:latest",
    "projectdiscovery/tlsx:latest",
    "caffix/amass:latest",
    "frost19k/puredns:latest",
    "sxcurity/gau:latest",
    "jauderho/hakrawler:latest",
    "ghcr.io/zaproxy/zaproxy:stable",
    "dolevf/graphql-cop:1.14",
    "redamon-baddns:latest",
    "redamon-wcvs:latest",
    # Supply-chain feature (plan Phase 0.5/2): the DIRTY analyzer, spawned by a
    # broker-socket caller (recon in L2), so it must be allowlisted or the spawn
    # fails closed. The CLEAN scanner is started by the orchestrator on the real
    # socket, so it is not on this list.
    "redamon-supply-chain-analyzer:latest",
    # JS Recon's TruffleHog sidecar, spawned by recon over the broker socket
    # (recon/helpers/js_recon/trufflehog_bridge.py). The orchestrator's own
    # TruffleHog scans use the real socket and need no entry.
    "redamon-trufflehog:latest",
    "alpine",          # temp-file cleanup helper
    "alpine:latest",
]


def _csv_env(name: str) -> list[str]:
    return [p.strip() for p in os.environ.get(name, "").split(",") if p.strip()]


ALLOWED_IMAGES = set(_DEFAULT_ALLOWED_IMAGES) | set(_csv_env("DOCKER_BROKER_ALLOWED_IMAGES"))


def _canonical_image(image: str) -> str:
    """Canonicalize a Docker image reference for allowlist matching.

    URL-decodes (docker sends `fromImage` percent-encoded, e.g. `%2F` for `/`),
    then strips the *implicit* Docker Hub registry (`docker.io/`,
    `index.docker.io/`) and the `library/` namespace of official images. This is
    what makes the daemon's fully-qualified auto-pull form compare equal to the
    short names operators put on the allowlist:

        docker.io/projectdiscovery/naabu:latest -> projectdiscovery/naabu:latest
        docker.io/library/alpine:latest         -> alpine:latest

    A `docker run <img>` for an image that isn't present locally triggers the
    daemon to pull `docker.io/<img>` (newer Docker/BuildKit fully-qualify it), so
    without this every runtime tool pull on a fresh host is denied. Non-default
    registries (e.g. `ghcr.io/...`) are left intact, so this only equates a
    reference with its own default-registry spelling -- it never widens the set
    of images that are allowed."""
    if not image:
        return image
    image = urllib.parse.unquote(image)
    for prefix in ("index.docker.io/", "docker.io/"):
        if image.startswith(prefix):
            image = image[len(prefix):]
            break
    if image.startswith("library/"):
        image = image[len("library/"):]
    return image


# Precompute the canonical allowlist once (entries are short-form, but run through
# the same canonicalizer so an operator-supplied `docker.io/...` extra also matches).
_CANONICAL_ALLOWED = {_canonical_image(i) for i in ALLOWED_IMAGES}

# Host bind-mount sources. /tmp/redamon is the scratch dir shared with the host
# at the same path: every tool's per-run folder lives there, many of them
# dot-prefixed on purpose (.naabu_temp_*, .tlsx_scan_*, .httpx_temp_*,
# .amass_temp_*, .gau_*, .jsluice_*, .paramspider_*), so dot components are
# allowed below these prefixes only.
_DEFAULT_BIND_PREFIXES = ["/tmp/redamon"]
SCRATCH_PREFIXES = list(_DEFAULT_BIND_PREFIXES)

# The repository subdirectories a tool mounts, never the repository itself: its
# root holds .env, the master keys that the scoped scan-container key exists to
# keep out of scan containers. Each entry names who mounts it;
# test_tool_invocations.py fails when one is unused or a tool needs another.
REPO_TOOL_SUBDIRS = (
    "recon/wordlists",               # Amass brute force (jhaddix-all.txt)
    "mcp/nuclei-templates",          # HOST_CUSTOM_TEMPLATES_PATH: the user's nuclei templates
    "scanners/supply_chain_common",  # the dirty analyzer's code (SUPPLY_CHAIN_COMMON_HOST_PATH)
)


def _sane_prefixes(prefixes) -> list:
    """Absolute prefixes only, and never one that is the host root: "/" (or a
    spelling of it) would make every host path pass the prefix match."""
    out = []
    for p in prefixes:
        if not p or not p.startswith("/"):
            continue
        norm = os.path.normpath(p)
        if norm != "/" and not norm.startswith("//"):
            out.append(norm)
    return out


def repo_bind_prefixes(repo_root: str) -> list:
    """The host paths of REPO_TOOL_SUBDIRS for a repository at `repo_root` (its
    path as the Docker daemon sees it; compose passes ${PWD}). None when unset:
    a missing root fails closed instead of guessing a checkout location."""
    if not repo_root or not repo_root.startswith("/") or os.path.normpath(repo_root) == "/":
        return []
    return [os.path.join(os.path.normpath(repo_root), sub) for sub in REPO_TOOL_SUBDIRS]


REPO_ROOT = os.environ.get("DOCKER_BROKER_REPO_ROOT", "").strip()
ALLOWED_BIND_PREFIXES = _sane_prefixes(
    _DEFAULT_BIND_PREFIXES + repo_bind_prefixes(REPO_ROOT)
    + _csv_env("DOCKER_BROKER_ALLOWED_BIND_PREFIXES"))

# Named volumes a tool may mount, read-only unless also in ALLOWED_RW_VOLUMES,
# in both the Binds and the Mounts form. nuclei-templates is the one writable
# volume: the template update (`nuclei -ut`) writes it. The shared offline OSV
# database and the incident intel stay read-only, so a spawned scanner cannot
# poison what every tenant's supply-chain verdicts are computed from.
ALLOWED_VOLUMES = set(_csv_env("DOCKER_BROKER_ALLOWED_VOLUMES")) | {
    "nuclei-templates", "redamon-osv-db", "redamon-sca-intel"}
ALLOWED_RW_VOLUMES = set(_csv_env("DOCKER_BROKER_ALLOWED_RW_VOLUMES")) | {"nuclei-templates"}

# The user-defined bridges tools inspect, create and attach to: the dirty
# supply-chain analyzer's (analyzer_dispatch.ANALYZER_NETWORK) and JS Recon's
# TruffleHog verifier's (trufflehog_bridge.VERIFY_NETWORK).
ALLOWED_NETWORKS = set(_csv_env("DOCKER_BROKER_ALLOWED_NETWORKS")) | {
    "redamon-supply-chain-net", "redamon-trufflehog-net"}

# The per-user Kali sandboxes' networks, as recon_orchestrator/sandbox_contract.py
# names, labels and addresses them (network_name, LABEL_SANDBOX, SUBNET_POOL;
# test_sandbox_networks.py pins the three). A tool container must never join
# one: from there it reaches the sandbox's listeners and can spoof the agent's
# link to it. And no network create may take the pool's addresses, or the
# sandboxes would find no subnet.
SANDBOX_NETWORK_PREFIX = "redamon-sbx-"
SANDBOX_LABEL = "redamon.sandbox"
SANDBOX_SUBNET_POOL = ipaddress.ip_network("10.214.0.0/16")
ALLOWED_NETWORKS = {n for n in ALLOWED_NETWORKS if not n.startswith(SANDBOX_NETWORK_PREFIX)}
# The network modes that name no network of their own.
_BUILTIN_NETWORKS = frozenset({"", "default", "bridge", "host", "none"})

# T1/T2: host paths a tool container may bind READ-WRITE. Every other allowed
# host path (the repository subdirectories) may be bound only :ro. Legit
# sub-tool spawns write exclusively under /tmp/redamon.
_DEFAULT_RW_PREFIXES = ["/tmp/redamon"]
ALLOWED_RW_PREFIXES = _sane_prefixes(_DEFAULT_RW_PREFIXES + _csv_env("DOCKER_BROKER_ALLOWED_RW_PREFIXES"))

# Capabilities a tool container may request (naabu SYN etc.). Everything else
# (SYS_ADMIN, SYS_PTRACE, ALL, ...) is denied.
ALLOWED_CAPS = {"NET_RAW", "NET_ADMIN", "CAP_NET_RAW", "CAP_NET_ADMIN"}

# The only security option a tool container may carry, in the spellings the
# daemon accepts for it.
_ALLOWED_SECURITY_OPTS = frozenset({"no-new-privileges", "no-new-privileges:true", "no-new-privileges=true"})

# E1: marker label injected into every broker-created container so operate-on-
# existing verbs can be gated to broker-owned targets only. Without this, the
# create-time allowlist is irrelevant to a hijack of a trusted infra container
# (exec/attach into the orchestrator/broker -> host root).
_OWNER_LABEL = "redamon.broker-owned"

# D4: every Docker API call a caller may make, as (methods, path, kind). The set
# is what the tools' real `docker` invocations send (recorded from the Docker
# CLI; test_tool_invocations.py replays each tool's command through it), so a
# call missing here fails a test rather than a scan. Not listed, so refused:
# exec, archive (docker cp), update (it would lift the memory cap), rename,
# restart, export, commit, build, image tag/push/delete/load, network and volume
# endpoints beyond the names tools use, events, system, swarm, plugins.
_V = r"^/(?:v[\d.]+/)?"
# Docker's own name grammar, narrower than "[^/]+" on purpose: no "%" and no
# leading "." means an encoded "/" or a ".." segment cannot make the daemon's
# router see a different path than the one checked here.
_NAME = r"([A-Za-z0-9][A-Za-z0-9_.-]*)"
_ROUTES = tuple((label, frozenset(methods), re.compile(_V + path + "$"), kind)
                for label, methods, path, kind in (
    ("ping", ("HEAD", "GET"), r"_ping", "plain"),
    ("version", ("GET",), r"version", "plain"),
    ("info", ("GET",), r"info", "plain"),
    ("container-create", ("POST",), r"containers/create", "create"),
    ("container-list", ("GET",), r"containers/json", "list"),
    ("container-attach", ("POST",), rf"containers/{_NAME}/attach", "attach"),
    ("container-verb", ("POST",), rf"containers/{_NAME}/(?:start|wait|kill|stop|pause|unpause)", "owned"),
    ("container-read", ("GET",), rf"containers/{_NAME}/(?:logs|json)", "owned"),
    ("container-remove", ("DELETE",), rf"containers/{_NAME}", "owned"),
    ("image-pull", ("POST",), r"images/create", "pull"),
    ("image-list", ("GET",), r"images/json", "plain"),
    ("image-inspect", ("GET",), r"images/(.+)/json", "image"),
    ("volume-inspect", ("GET",), rf"volumes/{_NAME}", "volume"),
    ("volume-create", ("POST",), r"volumes/create", "volume-create"),
    ("network-inspect", ("GET",), rf"networks/{_NAME}", "network"),
    ("network-create", ("POST",), r"networks/create", "network-create"),
))


def match_route(method: str, path_only: str):
    """(kind, match) of the allowlist entry for this call, or (None, None)."""
    for _label, methods, rx, kind in _ROUTES:
        if method in methods:
            m = rx.match(path_only)
            if m:
                return kind, m
    return None, None


def route_label(method: str, path_only: str):
    """The name of the allowlist entry this call matches, or None.
    test_tool_invocations.py uses it to show every entry has a user."""
    for label, methods, rx, _kind in _ROUTES:
        if method in methods and rx.match(path_only):
            return label
    return None


def _normalize_path(path: str) -> str:
    """Canonicalize the request path so create-detection cannot be evaded with
    trailing slashes or doubled slashes (e.g. '/v1.43/containers/create/' or
    '//containers/create'). Query string is stripped here."""
    p = path.split("?", 1)[0]
    p = re.sub(r"/{2,}", "/", p)       # collapse repeated slashes
    if len(p) > 1:
        p = p.rstrip("/")              # drop trailing slash(es)
    return p or "/"


def _log(msg: str) -> None:
    print(f"[docker-broker] {msg}", flush=True)


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------
def _image_allowed(image: str) -> bool:
    if not image:
        return False
    # Canonicalize (URL-decode + strip the implicit docker.io/library prefixes) so
    # the daemon's fully-qualified auto-pull form matches the short allowlist names.
    canon = _canonical_image(image)
    if canon in _CANONICAL_ALLOWED:
        return True
    # also accept the implicit ":latest" form (docker normalizes "alpine" ->
    # "alpine:latest"); accept if either spelling is allowlisted.
    if ":" not in canon.split("/")[-1] and f"{canon}:latest" in _CANONICAL_ALLOWED:
        return True
    return False


def _below(norm: str, prefix: str):
    """The part of `norm` below `prefix` ("" when equal), or None outside it."""
    base = os.path.normpath(prefix)
    if norm == base:
        return ""
    if norm.startswith(base + "/"):
        return norm[len(base) + 1:]
    return None


def _bind_source_allowed(source: str) -> bool:
    if not source:
        return False
    if source.startswith("/"):
        # absolute host path. NORMALIZE first so traversal tricks like
        # "/tmp/redamon/../../etc" (which textually starts with the allowed
        # prefix but resolves to /etc) are caught.
        norm = os.path.normpath(source)
        if norm == "/" or "docker.sock" in norm:
            return False
        scratch = any(_below(norm, p) is not None for p in SCRATCH_PREFIXES)
        for p in ALLOWED_BIND_PREFIXES:
            rest = _below(norm, p)
            if rest is None:
                continue
            # Below a repository prefix, never a dotfile or dot directory
            # (.env, .git, .env.local): the tools mount none.
            if scratch or not any(c.startswith(".") for c in rest.split("/")):
                return True
        return False
    # no leading slash -> named volume
    return source in ALLOWED_VOLUMES


def _rw_host_path_allowed(source: str) -> bool:
    """T1/T2: is this host path allowed to be bound READ-WRITE?"""
    norm = os.path.normpath(source)
    return any(_below(norm, p) is not None for p in ALLOWED_RW_PREFIXES)


def _bind_is_readonly(opts: str) -> bool:
    """A docker bind mode field is comma-separated (e.g. 'ro', 'ro,z', 'rw').
    Read-only iff the 'ro' token is present; default (no field) is read-write."""
    return "ro" in [o.strip() for o in opts.split(",") if o.strip()]


# --------------------------------------------------------------------------
# Reading a body the way the daemon does. The daemon decodes JSON with Go's
# encoding/json: a key matches a struct field whatever its ASCII case (and
# U+017F long s matches "s", the Kelvin sign U+212A "k"), and every key naming
# one field is applied in turn, objects merged and the last scalar or list
# winning; map keys (Labels, Tmpfs, ...) stay exact. The checks below read
# exact keys, so `"privileged": true`, a second "labels" or a repeated
# "DriverOpts" reached the daemon unchecked (each reproduced on Engine 29.10).
# So parse_body refuses a key repeated exactly in one object, and
# _canonical_keys, in every struct the broker checks, renames a lone ASCII case
# variant of a field to the API's spelling (docker-py writes
# "CPURealtimePeriod"; the forwarded body is re-serialized, so the checks and
# the daemon read the same key), and refuses two spellings of one field or any
# non-ASCII key.
# --------------------------------------------------------------------------
# A body larger than its cap is refused before it is read or parsed, which
# keeps the parse off the event loop's critical path and bounds what a
# connection still sending its body holds (MAX_PENDING_BODIES). A container
# create carries a tool's whole command line: nuclei passes each selected
# custom template as its own `-t` (1000 templates make a 71 KB body) and naabu
# an explicit port list, so creates get 256 KiB; the volume and network bodies
# the CLI sends are under 1 KiB.
CREATE_BODY_MAX = 256 * 1024
JSON_BODY_MAX = 64 * 1024


def body_max(kind: str) -> int:
    return CREATE_BODY_MAX if kind == "create" else JSON_BODY_MAX


def _refuse_repeated_keys(pairs):
    obj = dict(pairs)
    if len(obj) != len(pairs):
        seen = set()
        for key, _ in pairs:
            if key in seen:
                raise ValueError(f"repeated key {key!r}")
            seen.add(key)
    return obj


def parse_body(raw: bytes):
    """A request body as JSON; ValueError when it does not parse or an object
    repeats a key (the daemon applies each, Python keeps one)."""
    return json.loads(raw, object_pairs_hook=_refuse_repeated_keys)


def _struct(scalars: str = "", **nested) -> dict:
    return {**dict.fromkeys(scalars.split()), **nested}


# The JSON field names of every object the broker forwards, spelt as the Docker
# Engine API spells them (checked against the bodies Docker CLI 29.10 sends).
# A field maps to what its value holds: None (a scalar, a list of scalars or a
# map with free keys), another struct's name, or ("list"|"map", what each item
# holds). A field missing here is only forwarded unchecked, as any unknown key.
_LIST, _MAP = "list", "map"
_API_FIELDS = {
    "ContainerCreate": _struct(
        "Hostname Domainname User AttachStdin AttachStdout AttachStderr ExposedPorts Tty "
        "OpenStdin StdinOnce Env Cmd ArgsEscaped Image Volumes WorkingDir Entrypoint "
        "NetworkDisabled MacAddress OnBuild Labels StopSignal StopTimeout Shell",
        Healthcheck="HealthConfig", HostConfig="HostConfig", NetworkingConfig="NetworkingConfig"),
    "HealthConfig": _struct("Test Interval Timeout StartPeriod StartInterval Retries"),
    "HostConfig": _struct(
        "Binds ContainerIDFile NetworkMode AutoRemove VolumeDriver VolumesFrom ConsoleSize "
        "Annotations CapAdd CapDrop CgroupnsMode Dns DnsOptions DnsSearch ExtraHosts GroupAdd "
        "IpcMode Cgroup Links OomScoreAdj PidMode Privileged PublishAllPorts ReadonlyRootfs "
        "SecurityOpt StorageOpt Tmpfs UTSMode UsernsMode ShmSize Sysctls Runtime Isolation "
        "CpuShares Memory NanoCpus CgroupParent BlkioWeight CpuPeriod CpuQuota "
        "CpuRealtimePeriod CpuRealtimeRuntime CpusetCpus CpusetMems DeviceCgroupRules "
        "KernelMemory KernelMemoryTCP MemoryReservation MemorySwap MemorySwappiness "
        "OomKillDisable PidsLimit CpuCount CpuPercent IOMaximumIOps IOMaximumBandwidth "
        "MaskedPaths ReadonlyPaths Init",
        LogConfig="LogConfig", RestartPolicy="RestartPolicy",
        PortBindings=(_MAP, (_LIST, "PortBinding")),
        BlkioWeightDevice=(_LIST, "WeightDevice"),
        BlkioDeviceReadBps=(_LIST, "ThrottleDevice"), BlkioDeviceWriteBps=(_LIST, "ThrottleDevice"),
        BlkioDeviceReadIOps=(_LIST, "ThrottleDevice"), BlkioDeviceWriteIOps=(_LIST, "ThrottleDevice"),
        Devices=(_LIST, "DeviceMapping"), DeviceRequests=(_LIST, "DeviceRequest"),
        Ulimits=(_LIST, "Ulimit"), Mounts=(_LIST, "Mount")),
    "LogConfig": _struct("Type Config"),
    "RestartPolicy": _struct("Name MaximumRetryCount"),
    "PortBinding": _struct("HostIp HostPort"),
    "WeightDevice": _struct("Path Weight"),
    "ThrottleDevice": _struct("Path Rate"),
    "DeviceMapping": _struct("PathOnHost PathInContainer CgroupPermissions"),
    "DeviceRequest": _struct("Driver Count DeviceIDs Capabilities Options"),
    "Ulimit": _struct("Name Hard Soft"),
    "Mount": _struct("Type Source Target ReadOnly Consistency ClusterOptions",
                     BindOptions="BindOptions", VolumeOptions="VolumeOptions",
                     ImageOptions="ImageOptions", TmpfsOptions="TmpfsOptions"),
    "BindOptions": _struct("Propagation NonRecursive CreateMountpoint ReadOnlyNonRecursive "
                           "ReadOnlyForceRecursive"),
    "VolumeOptions": _struct("NoCopy Labels Subpath", DriverConfig="Driver"),
    "Driver": _struct("Name Options"),
    "ImageOptions": _struct("Subpath"),
    "TmpfsOptions": _struct("SizeBytes Mode Options"),
    "NetworkingConfig": _struct(EndpointsConfig=(_MAP, "EndpointSettings")),
    "EndpointSettings": _struct(
        "Links Aliases DriverOpts GwPriority NetworkID EndpointID Gateway IPAddress IPPrefixLen "
        "IPv6Gateway GlobalIPv6Address GlobalIPv6PrefixLen MacAddress DNSNames",
        IPAMConfig="EndpointIPAMConfig"),
    "EndpointIPAMConfig": _struct("IPv4Address IPv6Address LinkLocalIPs"),
    "VolumeCreate": _struct("Name Driver DriverOpts Labels ClusterVolumeSpec"),
    "NetworkCreate": _struct("Name CheckDuplicate Driver Scope EnableIPv4 EnableIPv6 Internal "
                             "Attachable Ingress ConfigOnly Options Labels",
                             IPAM="IPAM", ConfigFrom="ConfigReference"),
    "IPAM": _struct("Driver Options", Config=(_LIST, "IPAMConfig")),
    "IPAMConfig": _struct("Subnet IPRange Gateway AuxiliaryAddresses"),
    "ConfigReference": _struct("Network"),
}
_FOLDED_FIELDS = {kind: {f.upper(): f for f in fields} for kind, fields in _API_FIELDS.items()}
# Engines whose create wrapper still embeds HostConfig read its fields from the
# top level too, where no check here looks: they are refused there.
_TOP_LEVEL_HOST_FIELDS = {f.upper(): f for f in _API_FIELDS["HostConfig"]}


def _canonical_keys(value, kind, where: str = ""):
    """Give every struct below `value` the API's spelling of its fields, in
    place; the reason to refuse the body, or None. Docker's field names are
    ASCII, so a non-ASCII key in a struct can only be a look-alike of one."""
    if kind is None or value is None:
        return None
    if isinstance(kind, tuple):
        shape, item = kind
        if shape == _LIST and isinstance(value, list):
            entries = ((f"[{i}]", v) for i, v in enumerate(value))
        elif shape == _MAP and isinstance(value, dict):
            entries = ((f"[{k!r}]", v) for k, v in value.items())
        else:
            return f"{where} is not a JSON {'array' if shape == _LIST else 'object'}"
        for suffix, v in entries:
            found = _canonical_keys(v, item, where + suffix)
            if found:
                return found
        return None
    if not isinstance(value, dict):
        return f"{where or 'the body'} is not a JSON object"
    fields, folded = _API_FIELDS[kind], _FOLDED_FIELDS[kind]
    spelt = {}
    for key in value:
        path = f"{where}.{key}" if where else key
        if not key.isascii():
            return f"key {path!r} is not ASCII, as every Docker API field is"
        if kind == "ContainerCreate" and key.upper() in _TOP_LEVEL_HOST_FIELDS:
            return f"key {path!r} names the HostConfig field {_TOP_LEVEL_HOST_FIELDS[key.upper()]!r} at the top level"
        field = key if key in fields else folded.get(key.upper())
        if field is None:
            continue
        if field in spelt:
            return (f"keys {spelt[field]!r} and {key!r} in {(where or 'the body')!r} "
                    f"both name the Docker API field {field!r}")
        spelt[field] = key
    if any(field != key for field, key in spelt.items()):
        renamed = {key: field for field, key in spelt.items()}
        items = list(value.items())
        value.clear()
        value.update((renamed.get(k, k), v) for k, v in items)
    for field in spelt:
        found = _canonical_keys(value[field], fields[field], f"{where}.{field}" if where else field)
        if found:
            return found
    return None


def validate_create(body: dict) -> tuple[bool, str]:
    """Return (allowed, reason) for a POST /containers/create body."""
    if not isinstance(body, dict):
        return False, "create body is not a JSON object"
    refused = _canonical_keys(body, "ContainerCreate")
    if refused:
        return False, refused
    image = body.get("Image", "")
    if not isinstance(image, str) or not _image_allowed(image):
        return False, f"image not on allowlist: {image!r}"

    hc = body.get("HostConfig") or {}
    # The fields read below as lists or numbers, of the type the daemon reads.
    for name in ("Binds", "CapAdd", "SecurityOpt"):
        if not isinstance(hc.get(name), (list, type(None))):
            return False, f"HostConfig.{name} is not a JSON array"
    for name in ("Memory", "MemorySwap", "PidsLimit"):
        value = hc.get(name)
        if value is not None and (isinstance(value, bool) or not isinstance(value, int)):
            return False, f"HostConfig.{name} is not an integer"
    if not isinstance(hc.get("NetworkMode"), (str, type(None))):
        return False, "HostConfig.NetworkMode is not a string"
    stop_timeout = body.get("StopTimeout")
    if stop_timeout is not None and (isinstance(stop_timeout, bool) or not isinstance(stop_timeout, int)):
        return False, "StopTimeout is not an integer"

    if hc.get("Privileged"):
        return False, "Privileged=true denied"
    # Every client value a reason names is quoted (!r): the DENY log limiter
    # tells refusals apart by their text with the quoted values masked.
    for cap in hc.get("CapAdd") or []:
        if str(cap).upper() not in ALLOWED_CAPS:
            return False, f"capability not allowed: {str(cap)!r}"
    if hc.get("Devices"):
        return False, "device passthrough denied"
    # A device cgroup rule lets the container make and open device nodes (with
    # the default MKNOD, `b *:* rwm` reads the host's raw disks); a device
    # request hands it host devices such as GPUs. No tool asks for either.
    if hc.get("DeviceCgroupRules") or hc.get("DeviceRequests"):
        return False, "device cgroup rules and device requests denied"
    for ns in ("PidMode", "IpcMode", "UsernsMode", "CgroupnsMode"):
        v = str(hc.get(ns, ""))
        # host -> shares the host namespace; container:<x> -> joins another
        # container's namespace (e.g. the orchestrator's) -> escape/lateral path.
        if v.startswith("host") or v.startswith("container:"):
            return False, f"{ns}={v!r} denied"
    # NetworkMode host is needed (loopback/raw); but joining another container's
    # netns (e.g. the orchestrator's, to reach its loopback API) is denied.
    if str(hc.get("NetworkMode", "")).startswith("container:"):
        return False, f"NetworkMode={str(hc.get('NetworkMode'))!r} denied"
    # VolumesFrom would inherit ANOTHER container's mounts (e.g. the orchestrator's
    # /var/run/docker.sock) -> host root. Recon tools never use it.
    if hc.get("VolumesFrom"):
        return False, "VolumesFrom denied"
    # Overriding the daemon's default masked/readonly /proc paths weakens
    # isolation (exposes /proc/kcore etc.). Legit tool runs never set these.
    for sensitive in ("MaskedPaths", "ReadonlyPaths"):
        if hc.get(sensitive) is not None:
            return False, f"{sensitive} override denied"
    # Any other security option (an inline seccomp profile, an AppArmor profile
    # that is itself unconfined, an SELinux label, systempaths=unconfined) can
    # widen what the container may do, whatever its wording. No tool sends one.
    for so in hc.get("SecurityOpt") or []:
        if not isinstance(so, str) or so not in _ALLOWED_SECURITY_OPTS:
            return False, f"SecurityOpt {so!r} denied"

    # A volume plugin, or the local driver's options, can make a named volume
    # a bind of any host path; the tools use plain local volumes only.
    if str(hc.get("VolumeDriver") or "local") != "local":
        return False, f"VolumeDriver {hc.get('VolumeDriver')!r} denied"

    # Binds: ["src:dst", "src:dst:ro", "src:dst:rw,z", ...]
    for b in hc.get("Binds") or []:
        parts = str(b).split(":")
        src = parts[0]
        if not _bind_source_allowed(src):
            return False, f"bind mount not allowed: {b!r}"
        # T1/T2: enforce mount MODE, not just the source path. A host path may
        # be bound rw only if it is under an ALLOWED_RW_PREFIXES prefix; every
        # other allowed host path (the repository subdirectories) must be :ro.
        opts = parts[2] if len(parts) >= 3 else ""
        if _bind_is_readonly(opts):
            continue
        if src.startswith("/") and not _rw_host_path_allowed(src):
            return False, (
                f"read-write bind of {src!r} denied — source-tree binds must be "
                f":ro; only {ALLOWED_RW_PREFIXES} may be mounted rw"
            )
        if not src.startswith("/") and src not in ALLOWED_RW_VOLUMES:
            return False, f"read-write volume {src!r} denied — mount it :ro"

    # Mounts: [{Type, Source, Target, ReadOnly, ...}]
    for m in hc.get("Mounts") or []:
        mtype = m.get("Type")
        if mtype == "bind":
            src = m.get("Source", "")
            if not _bind_source_allowed(src):
                return False, f"bind mount not allowed: {src!r}"
            # T1/T2: Mounts carry mode via the ReadOnly flag (default False = rw).
            if src.startswith("/") and not m.get("ReadOnly") \
                    and not _rw_host_path_allowed(src):
                return False, (
                    f"read-write bind of {src!r} denied — source-tree binds must "
                    f"be ReadOnly; only {ALLOWED_RW_PREFIXES} may be mounted rw"
                )
        elif mtype == "volume":
            src = m.get("Source")
            if src and src not in ALLOWED_VOLUMES:
                return False, f"volume not allowed: {src!r}"
            if (m.get("VolumeOptions") or {}).get("DriverConfig"):
                return False, f"volume driver options denied for {src!r}"
            # A named volume may be mounted rw only if allowlisted for writes;
            # an empty list means none is.
            if src and not m.get("ReadOnly") and src not in ALLOWED_RW_VOLUMES:
                return False, f"read-write volume {src!r} denied"
        elif mtype:
            return False, f"mount type not allowed: {mtype!r}"

    return True, "ok"


# --------------------------------------------------------------------------
# Memory governor (Part 4d): inject a hard memory cap into every sibling tool
# container the recon pipeline spawns. These are separate top-level containers,
# so the recon container's own mem_limit can't reach them — the broker is the
# only choke point. Additive to the security filtering above; never relaxes it.
# --------------------------------------------------------------------------
def _parse_size(s: str, default: int) -> int:
    """Parse '2g'/'512m'/'1073741824' to bytes; default on empty/invalid."""
    s = (s or "").strip().lower()
    if not s:
        return default
    if s.endswith("b"):
        s = s[:-1].strip()
    mult = 1
    if s and s[-1] in ("k", "m", "g", "t"):
        mult = {"k": 1024, "m": 1024**2, "g": 1024**3, "t": 1024**4}[s[-1]]
        s = s[:-1].strip()
    try:
        val = int(float(s) * mult)
    except (TypeError, ValueError):
        return default
    return val if val >= 0 else default   # a typo'd negative must not silently disable the cap


def _parse_int(s: str, default: int) -> int:
    """Parse a plain integer env var; default on empty/invalid (never crash import)."""
    try:
        return int(str(s).strip())
    except (TypeError, ValueError):
        return default


def _default_tool_mem() -> int:
    """Sibling tool ceiling from the governor, not a flat 2 GiB.

    container_cap() exists precisely because THREE processes spawn capped
    containers; the broker was the one still using a literal, so a calibrated
    host's measured tool envelope was ignored here while being honoured on the
    other two paths. Falls back to 2 GiB if the governor is unavailable (the
    broker must never fail to start: recon could then spawn no tool at all).
    """
    try:
        import resource_governor as _rg
        cap = _rg.container_cap(_rg.tool_container_envelope("_default"))
        if cap and cap > 0:
            return int(cap)
    except Exception:
        pass
    return 2 * 1024**3


BROKER_TOOL_MEM = _parse_size(os.environ.get("BROKER_TOOL_MEM_BYTES", ""), _default_tool_mem())
# Defensive parse: a non-integer (e.g. "512m") must not crash the broker at import,
# which would leave recon unable to spawn ANY tool container.
BROKER_TOOL_PIDS = max(0, _parse_int(os.environ.get("BROKER_TOOL_PIDS", "0"), 0))  # 0 = don't set
# Phase 7: sibling tool containers had NO count cap, so a runaway scan (or many
# concurrent scans) could spawn unbounded containers the memory governor never
# sees. A generous backstop; 0 disables it. A create, or a start of an exited
# container, is denied once this many broker-owned containers are not exited
# (_LIVE_STATES) or still have an attach or long call open, counting the
# creates and starts already admitted that the daemon has not answered yet
# (_admit_container). A PAUSED container counts: a
# run the orchestrator pauses keeps every tool container it holds counted until
# it is resumed or stopped, so with many paused runs new tools can be refused.
BROKER_MAX_CONTAINERS = max(0, _parse_int(os.environ.get("BROKER_MAX_CONTAINERS", "0"), 0))


def inject_limits(cfg: dict) -> dict:
    """Add HostConfig.Memory (and optionally PidsLimit) if absent or larger than
    our cap — respect a lower explicit value. Zero or a negative value means
    unlimited to the daemon (PidsLimit -1, Memory -1), so it gets the cap too.
    Mutates and returns cfg."""
    hc = cfg.get("HostConfig")
    if not isinstance(hc, dict):
        hc = {}
        cfg["HostConfig"] = hc
    if BROKER_TOOL_MEM > 0:
        cur = hc.get("Memory") or 0
        if cur <= 0 or cur > BROKER_TOOL_MEM:
            hc["Memory"] = BROKER_TOOL_MEM
        # MemorySwap is memory + swap: -1 is unlimited swap, and 0 lets the
        # daemon give twice Memory, so nothing may ask for more than that.
        swap = hc.get("MemorySwap") or 0
        if swap < 0 or swap > 2 * hc["Memory"]:
            hc["MemorySwap"] = 2 * hc["Memory"]
    if BROKER_TOOL_PIDS > 0:
        cur = hc.get("PidsLimit") or 0
        if cur <= 0 or cur > BROKER_TOOL_PIDS:
            hc["PidsLimit"] = BROKER_TOOL_PIDS
    return cfg


# `stop` waits up to `t` seconds before it kills, and with no `t` up to the
# container's own StopTimeout, -1 meaning for good: the broker forwards a stop
# with `t` of at most this, and caps the StopTimeout a create asks for (the
# daemon reads it on its own stops, at shutdown among them).
STOP_TIMEOUT_MAX = 30
STOP_TIMEOUT_DEFAULT = 10   # the daemon's own default when neither gives one


def clamp_stop_timeout(cfg: dict) -> dict:
    """A create's StopTimeout within 0..STOP_TIMEOUT_MAX (a negative one, "for
    good", becomes the maximum); absent stays absent. Mutates and returns cfg."""
    seconds = cfg.get("StopTimeout")
    if isinstance(seconds, int) and not isinstance(seconds, bool) \
            and (seconds < 0 or seconds > STOP_TIMEOUT_MAX):
        cfg["StopTimeout"] = STOP_TIMEOUT_MAX
    return cfg


def mark_owned(cfg: dict) -> dict:
    """E1: stamp the broker-owned marker label onto a create body so operate
    verbs can later verify ownership. Mutates and returns cfg."""
    labels = cfg.get("Labels")
    if not isinstance(labels, dict):
        labels = {}
        cfg["Labels"] = labels
    labels[_OWNER_LABEL] = "1"
    return cfg


# The run a tool container belongs to, so the orchestrator can stop or pause one
# run's tools and nobody else's. The broker cannot tell its callers apart (every
# recon container shares one socket), so the recon container names its run in a
# header its Docker CLI sends on every call (recon/entrypoint.sh writes it into
# the CLI's config.json). Labels stay advisory: the orchestrator also requires
# _OWNER_LABEL, and it talks to the real daemon directly.
#
# The broker also scopes a caller to the run its header names: a listing shows,
# and a call on an existing container reaches, only containers carrying exactly
# those three labels; without a well-formed header, only containers carrying
# none of them (and a listing shows nothing, as the daemon's filters cannot
# select "no such label"). The header is a claim, not a proof: a compromised
# scan container that learns another run's project and run id (they appear in
# the shared /tmp/redamon and recon output paths) can name that run. So the
# scope stops one run reaching another by mistake or by a listing, and a
# forged or missing header still reaches at most one run's containers.
RUN_HEADER = "x-redamon-run"
RUN_LABELS = ("redamon.run_kind", "redamon.project_id", "redamon.run_id")
_RUN_KINDS = frozenset({"full_recon", "partial_recon"})
_RUN_PART_RE = re.compile(r"[A-Za-z0-9_-]{1,128}")


def parse_run_header(value) -> "tuple[str, str, str] | None":
    """(kind, project_id, run_id) from `<kind>:<project>:<run>`, or None."""
    if not isinstance(value, str):
        return None
    parts = value.split(":")
    if len(parts) != 3 or parts[0] not in _RUN_KINDS:
        return None
    if not all(_RUN_PART_RE.fullmatch(p) for p in parts[1:]):
        return None
    return parts[0], parts[1], parts[2]


def stamp_run_labels(cfg: dict, header_value) -> dict:
    """Label a create body with the run its header names. Run labels come only
    from the header: a client-supplied one is overwritten, or dropped when the
    header is absent or malformed. Mutates and returns cfg."""
    labels = cfg.get("Labels")
    if not isinstance(labels, dict):
        labels = {}
        cfg["Labels"] = labels
    for name in RUN_LABELS:
        labels.pop(name, None)
    run = parse_run_header(header_value)
    if run:
        labels.update(zip(RUN_LABELS, run))
    return cfg


_NO_RUN = (None,) * len(RUN_LABELS)


def caller_run(header_value) -> tuple:
    """The run-label values a request's header names, in RUN_LABELS order, or
    _NO_RUN when the header is absent or malformed (stamp_run_labels then
    stamps none either)."""
    return parse_run_header(header_value) or _NO_RUN


def container_run(info) -> tuple:
    """The run-label values of a container's inspect document, None where absent."""
    config = (info or {}).get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    labels = labels if isinstance(labels, dict) else {}
    return tuple(labels.get(name) for name in RUN_LABELS)


def _dechunk(body: bytes) -> bytes:
    """Decode HTTP/1.1 chunked transfer-encoding into the raw body."""
    out = b""
    i = 0
    while i < len(body):
        j = body.find(b"\r\n", i)
        if j < 0:
            break
        try:
            size = int(body[i:j].split(b";", 1)[0], 16)
        except ValueError:
            break
        if size == 0:
            break
        start = j + 2
        out += body[start:start + size]
        i = start + size + 2  # skip the trailing CRLF
    return out


# The broker's own reads of the daemon (the ownership inspect, the watchdog's,
# the container count) have a deadline: a daemon that never answers must not
# hold a call, or the admission lock, for good.
INSPECT_TIMEOUT = 30


async def _upstream_get_json(target: str, timeout: float):
    """(status, parsed JSON body) of one upstream GET, or (0, None) when the
    daemon could not be reached, or did not answer whole within `timeout`."""
    r = w = None
    try:
        r, w = await asyncio.open_unix_connection(UPSTREAM_SOCK)
        w.write(f"GET {target} HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n".encode("latin1"))
        await w.drain()
        raw = await asyncio.wait_for(r.read(), timeout)  # Connection: close -> read to EOF
    except Exception:
        return 0, None
    finally:
        if w is not None:
            try:
                w.close()
            except Exception:
                pass
    if b"\r\n\r\n" not in raw:
        return 0, None
    head_b, body = raw.split(b"\r\n\r\n", 1)
    head_text = head_b.decode("latin1")
    parts = head_text.split("\r\n", 1)[0].split(" ")   # e.g. "HTTP/1.1 200 OK"
    status = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
    if "transfer-encoding: chunked" in head_text.lower():
        body = _dechunk(body)
    try:
        return status, json.loads(body or b"null")
    except Exception:
        return status, None


async def _upstream_inspect(cid: str):
    """A container's inspect document, or None if it is absent, unparseable or
    the daemon did not answer."""
    status, info = await _upstream_get_json(f"/containers/{cid}/json", INSPECT_TIMEOUT)
    return info if status == 200 and isinstance(info, dict) else None


def _is_owned(info) -> bool:
    """Is this inspect document a container the broker created?"""
    config = (info or {}).get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    return isinstance(labels, dict) and labels.get(_OWNER_LABEL) == "1"


# Every state but exited and dead: a created container (never started) can be
# attached to, waited on and started like a running one, so it counts; so does a
# paused one (see BROKER_MAX_CONTAINERS).
_LIVE_STATES = ("created", "restarting", "running", "paused")
# The states of a container that will not run again unless started: a call that
# waits for it to run or exit would wait for a start that may never come.
_ENDED_STATES = ("exited", "dead", "removing")
# A daemon that does not answer the count must not hold the admission lock for good.
COUNT_TIMEOUT = 30


async def _count_broker_owned_live() -> int:
    """Count the broker-owned containers not yet exited via an upstream
    GET /containers/json filtered by the ownership label (Phase 7 count cap).
    Returns -1 if the count cannot be determined, so the caller can fail OPEN
    (never block a legitimate spawn on a transient upstream hiccup)."""
    filt = urllib.parse.quote(json.dumps({"label": [f"{_OWNER_LABEL}=1"], "status": list(_LIVE_STATES)}))
    status, arr = await _upstream_get_json(f"/containers/json?filters={filt}", COUNT_TIMEOUT)
    if status != 200 or not isinstance(arr, list):
        return -1
    # A container whose attach or long call is still open counts too, ended or
    # not (see _Watched): a caller that never reads keeps no more than the cap.
    live = {c.get("Id") if isinstance(c, dict) else None for c in arr}
    return len(live | {key[1] for key, w in list(_WATCHED.items()) if not w.task.done()})


# Creates and capped starts admitted under BROKER_MAX_CONTAINERS whose answer
# from the daemon is not in yet: until it is, the daemon's count does not show
# them. Admission is one count at a time (_cap_lock), so concurrent creates
# cannot all read the same count below the cap.
_admitted = 0
_cap_lock_of_loop: list = [None, None]   # [loop, its lock]: an asyncio.Lock serves one loop


def _cap_lock() -> asyncio.Lock:
    loop = asyncio.get_running_loop()
    if _cap_lock_of_loop[0] is not loop:
        _cap_lock_of_loop[:] = [loop, asyncio.Lock()]
    return _cap_lock_of_loop[1]


async def _admit_container():
    """Take a place under BROKER_MAX_CONTAINERS for one create, or one start of
    an exited container: the reason to refuse it, or None once admitted (the
    caller then calls _release_admission after the daemon has answered). An
    unknown count admits (a daemon hiccup must not block a legitimate spawn)."""
    global _admitted
    async with _cap_lock():
        live = await _count_broker_owned_live()
        if live >= 0 and live + _admitted >= BROKER_MAX_CONTAINERS:
            return (f"broker container count cap reached "
                    f"({live + _admitted}/{BROKER_MAX_CONTAINERS})")
        _admitted += 1
    return None


def _release_admission() -> None:
    global _admitted
    _admitted = max(0, _admitted - 1)


# An attach or a long call can outlive its container: the daemon never ends an
# attach to a container removed before it started, and a wait for the next exit
# (or an attach) forwarded just after its container exited waits for a start
# that never comes, while the container no longer counts against the cap. So
# every WATCH_INTERVAL the broker re-inspects, by full id, each container with
# an open attach or long call, and ends a call once its container has been
# gone or ended since an earlier pass and for its grace, never in the pass that
# first sees it so (the daemon answers a wait for removal just after the
# container leaves its store). The grace is ENDED_GRACE, but REMOVAL_GRACE for
# a wait for the removal of a container the daemon removes on exit while it is
# exited or removing (the daemon answers that wait when the removal is done,
# however long it takes). An attach or logs whose client has not yet taken
# everything (data still flowing since the last pass, or queued toward the
# client: a caller whose recon container is paused) is kept, for at most
# KEPT_MAX; and a client that never reads cannot hold more than that: every
# container with an open call counts against BROKER_MAX_CONTAINERS until the
# call ends (_count_broker_owned_live), and a new attach or long call that
# finds its budget full ends a kept one first, taken from the run holding the
# most (evict_kept).
WATCH_INTERVAL = 30.0
ENDED_GRACE = 5.0
REMOVAL_GRACE = 600.0
# Five minutes after its container ended a kept call ends whatever its client
# still has to read: long enough for a caller frozen a while (a recon container
# paused right after its tool exited still gets the tool's whole output, e.g.
# 4 MB unread for 75 s), short enough to free its slot, its cap place and the
# socket buffers it pins.
KEPT_MAX = 300.0
_watchdog_of_loop: list = [None, None]     # [loop, its watchdog task]


class _Watched:
    """What the watchdog knows of one open attach or long call."""

    def __init__(self, task, writer, removal_wait: bool = False, run=None):
        self.task, self.writer, self.removal_wait, self.run = task, writer, removal_wait, run
        self.relayed = self.seen = 0       # bytes relayed to the client; as of the last pass
        self.since = None                  # when a pass first saw its container gone or ended
        self.kept = False                  # past its grace, kept for a client still taking data
        self.opened = time.monotonic()

    def count(self, data: bytes) -> None:
        self.relayed += len(data)

    def busy(self) -> bool:
        """Does its client still have data coming, or queued toward it?"""
        flowing = self.relayed != self.seen
        self.seen = self.relayed
        transport = getattr(self.writer, "transport", None)
        queued = bool(transport) and not transport.is_closing() and transport.get_write_buffer_size() > 0
        return flowing or queued


_WATCHED: dict = {}                        # (call, full container id) -> _Watched


def _ensure_watchdog() -> None:
    loop = asyncio.get_running_loop()
    task = _watchdog_of_loop[1]
    if _watchdog_of_loop[0] is not loop or task is None or task.done():
        _watchdog_of_loop[:] = [loop, loop.create_task(_watchdog())]


def _end(key, why: str) -> None:
    watched = _WATCHED.pop(key, None)
    if watched is not None and not watched.task.done():
        watched.task.cancel()
        _log_limited(("end", why), f"END {key[0]} on container {key[1][:12]}: {why}")


def evict_kept(call: str) -> bool:
    """End one kept call of this kind (an attach, or a long call) to make room
    for a new one: the oldest of the run holding the most. False if none."""
    kinds = ("attach",) if call == "attach" else _LONG_CALLS_ON_A_CONTAINER
    kept = [(w.opened, key, w.run) for key, w in _WATCHED.items()
            if w.kept and key[0] in kinds and not w.task.done()]
    if not kept:
        return False
    per_run = collections.Counter(run for _, _, run in kept)
    _, key, _ = min(kept, key=lambda k: (-per_run[k[2]], k[0]))
    _end(key, "its slot was needed by a new call")
    return True


def calls_removed(container_id: str, spare=None) -> None:
    """The broker forwarded a removal of this container: end its open attach,
    logs and stop at once, unless their client is still taking data; a wait,
    which the daemon answers once the removal is done, and those are ended at
    the next pass if still open."""
    for key, watched in list(_WATCHED.items()):
        if key[1] != container_id or watched.task is spare or watched.task.done():
            continue
        if key[0] == "wait" or watched.busy():
            watched.since = watched.since or time.monotonic() - ENDED_GRACE
        else:
            _end(key, "the container was removed")


async def watch_once() -> None:
    """One pass of the watchdog."""
    for key in [k for k, w in _WATCHED.items() if w.task.done()]:
        del _WATCHED[key]
    by_container: dict = {}
    for key in list(_WATCHED):
        by_container.setdefault(key[1], []).append(key)
    for cid, keys in by_container.items():
        status, info = await _upstream_get_json(f"/containers/{cid}/json", INSPECT_TIMEOUT)
        if status == 404:
            state = "gone"
        elif status == 200 and isinstance(info, dict):
            state = (info.get("State") or {}).get("Status")
            state = state if state in _ENDED_STATES else None
        else:
            continue                       # the daemon is not sure: keep the calls as they are
        now = time.monotonic()
        for key in keys:
            watched = _WATCHED.get(key)
            if watched is None:
                continue
            busy = key[0] in ("attach", "logs") and watched.busy()   # (data since the last pass)
            if state is None:
                watched.since = None
                continue
            if watched.since is None:
                watched.since = now        # ended or gone: never ended in the pass that first sees it
                continue
            removal = watched.removal_wait and state in ("exited", "removing")
            if now - watched.since < (REMOVAL_GRACE if removal else ENDED_GRACE):
                continue
            if busy and now - watched.since < KEPT_MAX:
                watched.kept = True
                continue
            _end(key, "the container is gone" if state == "gone" else f"the container has ended ({state})")


async def _watchdog() -> None:
    while True:
        await asyncio.sleep(WATCH_INTERVAL)
        try:
            await watch_once()
        except Exception as e:  # noqa: BLE001 - the watchdog must outlive one bad pass
            _log_limited(("error", "watchdog"), _clip(f"error: watchdog: {e!r}"))


def _owned_list_target(target: str, run: tuple = _NO_RUN) -> str:
    """E1: force the broker-owned label filter onto GET /containers/json so the
    listing can only ever return broker-created containers (narrows, never
    widens, whatever the client asked for), and the caller's run labels so it
    shows only that run's; with no run it shows none (both owner values are
    required). Returns the rewritten target."""
    base, _, query = target.partition("?")
    params = urllib.parse.parse_qs(query, keep_blank_values=True)
    filters = {}
    if "filters" in params:
        try:
            filters = json.loads(params["filters"][0])
        except Exception:
            filters = {}
    if not isinstance(filters, dict):
        filters = {}
    labels = filters.get("label")
    if isinstance(labels, dict):
        labels = list(labels.keys())
    if not isinstance(labels, list):
        labels = []
    # Label filters all have to match, so each one added can only narrow.
    required = [f"{_OWNER_LABEL}=1"]
    if run == _NO_RUN:
        required.append(f"{_OWNER_LABEL}=0")
    else:
        required += [f"{name}={value}" for name, value in zip(RUN_LABELS, run)]
    labels += [label for label in required if label not in labels]
    filters["label"] = labels
    params["filters"] = [json.dumps(filters)]
    new_query = urllib.parse.urlencode(params, doseq=True)
    return base + ("?" + new_query if new_query else "")


# The query parameters `docker pull` sends. The daemon decodes parameter names
# as well as values and reads the FIRST of a repeated one; with an empty
# fromImage it imports the request body (or the URL in fromSrc) as repo:tag,
# which could replace a tool image every scan runs.
_PULL_PARAMS = frozenset({"fromImage", "tag", "platform"})


def validate_pull(path: str) -> tuple[bool, str]:
    """Validate docker pull (POST /images/create?fromImage=...&tag=...)."""
    q = path.split("?", 1)[1] if "?" in path else ""
    pairs = urllib.parse.parse_qsl(q, keep_blank_values=True)
    names = [name for name, _ in pairs]
    if len(set(names)) != len(names):
        return False, f"repeated pull parameter in {sorted(names)}"
    if set(names) - _PULL_PARAMS:
        return False, f"pull parameter(s) {sorted(set(names) - _PULL_PARAMS)} denied"
    params = dict(pairs)
    from_image = params.get("fromImage", "")
    if not from_image:
        return False, "pull without fromImage denied"
    tag = params.get("tag", "")
    image = f"{from_image}:{tag}" if tag else from_image
    if _image_allowed(image) or _image_allowed(from_image):
        return True, "ok"
    return False, f"pull of non-allowlisted image denied: {image!r}"


def validate_volume_create(body) -> tuple[bool, str]:
    """POST /volumes/create: only a writable tool volume, as a plain local volume.
    Driver options would let the volume be a bind of any host path under a
    name the tools may then mount read-write."""
    if not isinstance(body, dict):
        return False, "unparseable volume create body"
    refused = _canonical_keys(body, "VolumeCreate")
    if refused:
        return False, refused
    name = body.get("Name")
    if not isinstance(name, str) or name not in ALLOWED_RW_VOLUMES:
        return False, f"creating volume {name!r} denied"
    if str(body.get("Driver") or "local") != "local":
        return False, f"volume driver {body.get('Driver')!r} denied"
    if body.get("DriverOpts") or body.get("ClusterVolumeSpec"):
        return False, f"volume options denied for {name!r}"
    return True, "ok"


def validate_network_create(body) -> tuple[bool, str]:
    """POST /networks/create: only a tool network, as a plain local bridge."""
    if not isinstance(body, dict):
        return False, "unparseable network create body"
    refused = _canonical_keys(body, "NetworkCreate")
    if refused:
        return False, refused
    name = body.get("Name")
    if not isinstance(name, str) or name not in ALLOWED_NETWORKS:
        return False, f"creating network {name!r} denied"
    if str(body.get("Driver") or "bridge") != "bridge":
        return False, f"network driver {body.get('Driver')!r} denied"
    # Options can rebind an existing host bridge (com.docker.network.bridge.name);
    # ConfigFrom/ConfigOnly/Ingress/swarm scope are swarm features no tool uses.
    if body.get("Options") or body.get("ConfigFrom") or body.get("ConfigOnly") \
            or body.get("Ingress") or str(body.get("Scope") or "local") != "local":
        return False, f"network options denied for {name!r}"
    ipam = body.get("IPAM") or {}
    if str(ipam.get("Driver") or "default") != "default" or ipam.get("Options"):
        return False, f"network IPAM options denied for {name!r}"
    if name.startswith(SANDBOX_NETWORK_PREFIX):
        return False, f"network {name!r} is a sandbox network"
    # No tool labels a network (the CLI sends none); a `redamon.sandbox` label
    # would make a tool network one every tool container is refused on.
    if body.get("Labels"):
        return False, f"network labels denied for {name!r}"
    for config in ipam.get("Config") or []:
        aux = config.get("AuxiliaryAddresses") or {}
        if not isinstance(aux, dict):
            return False, "IPAM.Config.AuxiliaryAddresses is not a JSON object"
        for value in [config.get(f) for f in ("Subnet", "IPRange", "Gateway")] + list(aux.values()):
            if value not in (None, "") and _in_sandbox_pool(value):
                return False, f"network address {value!r} is not one outside the sandbox subnet pool"
    return True, "ok"


_IPV4_MAPPED = ipaddress.ip_network("::ffff:0:0/96")


def _in_sandbox_pool(value) -> bool:
    """Does an address or a subnet overlap the sandbox pool? One that does not
    parse counts as inside: the broker must not read it otherwise than the
    daemon. An IPv4-mapped IPv6 one is read as the IPv4 range it maps (the
    daemon stores `::ffff:10.214.255.224/124` as 10.214.255.224/28), one that
    covers the whole mapped space counts as inside; any other IPv6 one never
    is (the pool is IPv4 only)."""
    try:
        net = ipaddress.ip_network(str(value).strip(), strict=False)
    except ValueError:
        return True
    if net.version == 6:
        if not net.overlaps(_IPV4_MAPPED):
            return False
        if net.prefixlen <= _IPV4_MAPPED.prefixlen:
            return True
        net = ipaddress.ip_network((int(net.network_address) & 0xFFFFFFFF, net.prefixlen - 96))
    return net.overlaps(SANDBOX_SUBNET_POOL)


def _is_sandbox_network(doc: dict) -> bool:
    """A network inspect: by its name, its label or an address in the pool."""
    if str(doc.get("Name") or "").startswith(SANDBOX_NETWORK_PREFIX):
        return True
    if SANDBOX_LABEL in (doc.get("Labels") or {}):
        return True
    return any(isinstance(c, dict) and c.get("Subnet") and _in_sandbox_pool(c["Subnet"])
               for c in ((doc.get("IPAM") or {}).get("Config") or []))


_NETWORK_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")
# A tool names one network (`--network X` makes one EndpointsConfig entry);
# each entry costs the broker up to two inspects, so a create names few.
MAX_ENDPOINTS = 4


async def sandbox_network_refusal(cfg: dict):
    """Why a create may not reach the networks it names, or None: every network
    its NetworkMode, its EndpointsConfig names and their NetworkID name, other
    than the built-in ones, must be one the daemon resolves (a name, an id or an
    id prefix, as it would) to a network that is not a sandbox's. A name with the
    sandbox prefix is refused before that: the container could be made before
    its sandbox network exists, and join it at its start."""
    hc = cfg.get("HostConfig") or {}
    endpoints = ((cfg.get("NetworkingConfig") or {}).get("EndpointsConfig")) or {}
    if len(endpoints) > MAX_ENDPOINTS:
        return f"a create names {len(endpoints)} networks, more than {MAX_ENDPOINTS}"
    refs = [hc.get("NetworkMode") or ""]
    for name, settings in endpoints.items():
        refs += [name, (settings or {}).get("NetworkID") or ""]
    if not all(isinstance(ref, str) for ref in refs):
        return "a network reference is not a string"
    for ref in dict.fromkeys(refs):
        if ref in _BUILTIN_NETWORKS or ref.startswith("container:"):
            continue
        if not _NETWORK_REF.fullmatch(ref):
            return f"network reference {ref!r} is not a network name or id"
        if ref.startswith(SANDBOX_NETWORK_PREFIX):
            return f"network {ref!r} is a sandbox network"
        status, doc = await _upstream_get_json(f"/networks/{ref}", INSPECT_TIMEOUT)
        if status != 200 or not isinstance(doc, dict):
            return f"network {ref!r} is not one the daemon knows"
        if _is_sandbox_network(doc):
            return f"network {ref!r} is a sandbox network, or has an address in the sandbox subnet pool"
        # The daemon keeps the reference as given and resolves it again at the
        # start: an id prefix could then name another network, a sandbox's.
        if ref not in (doc.get("Name"), doc.get("Id")):
            return f"network reference {ref!r} is neither the network's name nor its full id"
    return None


def _name_allowed(kind: str, m) -> tuple[bool, str]:
    """Inspect calls name what they read; only the tools' own names pass."""
    name = m.group(1)
    if kind == "image":
        return _image_allowed(name), f"image {urllib.parse.unquote(name)!r} is not a tool image"
    if kind == "volume":
        return name in ALLOWED_VOLUMES, f"volume {name!r} is not a tool volume"
    return name in ALLOWED_NETWORKS, f"network {name!r} is not a tool network"


def _checked(validate, body) -> tuple[bool, str]:
    """A validator's verdict; a value of a shape it does not expect is a
    refusal (the daemon would refuse it too), never a dropped connection."""
    try:
        return validate(body)
    except Exception as e:  # noqa: BLE001 - refused, never forwarded
        return False, f"unexpected value in the body ({type(e).__name__})"


# --------------------------------------------------------------------------
# HTTP plumbing. The daemon's Go HTTP server ends a line at a bare LF, so a
# head the broker splits on CRLF can hold more requests for the daemon than for
# the broker (each one unchecked). A head is therefore refused unless every
# line ends in CRLF and reads the same to both, and what reaches the daemon is
# a head the broker writes itself: the request line it checked and the few
# headers the Docker CLI needs (recorded from CLI 29.10 for every allowed call).
# --------------------------------------------------------------------------
# The Docker CLI's heads are under 1 KiB; a registry credential in
# X-Registry-Auth the size of an ECR token makes one of 4 KiB, a deliberately
# oversized one (8 KiB password + 8 KiB identity token) 22 KiB. 32 KiB keeps
# MAX_PENDING_HEADS half-sent heads within 128 MiB of the broker's memory.
HEAD_MAX = 32 * 1024
# Generous: a recon container paused mid-request still finishes; floods are
# stopped by the budgets below, not by these.
HEAD_TIMEOUT = 60       # seconds for a whole request head
BODY_TIMEOUT = 60       # seconds for a whole request body
# The daemon answers an attach at once; a long bound only so that a daemon
# that never does cannot hold the connection for good (logged when it trips).
ATTACH_ANSWER_TIMEOUT = 600
# Budgets, sized from the open-file limit at startup (raise_nofile_limit).
# Connections still sending their head, or their body (up to CREATE_BODY_MAX
# buffered each, so 128 bodies hold at most 32 MiB): when full, the one waiting
# longest is closed, so a flood cannot keep a real request out (a real one is
# never the oldest). Attach streams and long calls (a wait, logs, a stop): one
# of each per container (the CLI opens exactly one attach and one wait per
# `docker run`), and a global budget beyond which they are refused.
MAX_PENDING_HEADS = 4096
MAX_PENDING_BODIES = 128
MAX_ATTACH_STREAMS = 1024
MAX_LONG_CALLS = 1024
# The calls on a container that last as long as it runs, or longer, and so the
# only ones the broker ends when their caller hangs up (_relay). Every other
# call is answered at once and relayed whole, even to a caller that has already
# half-closed its side (`nc -N`, a shutdown(SHUT_WR) after the request).
_LONG_CALLS_ON_A_CONTAINER = ("wait", "logs", "stop")
# The calls the watchdog ends when their container is gone or has ended.
_WATCHED_CALLS = ("attach",) + _LONG_CALLS_ON_A_CONTAINER
# A start never lasts, but two at once on one exited container would both
# read it exited, and a start of a running one (a no-op the CLI never sends)
# could be forwarded after it exited and restart it unadmitted: one at a time,
# and only of a container that is created or ended.
_STARTABLE_STATES = ("created", "exited", "dead")
_WAIT_CONDITIONS = ("not-running", "next-exit", "removed")
# The daemon's full container id: the broker forwards every call on the
# container it checked by this, never by the client's name or id prefix.
_FULL_ID = re.compile(r"[0-9a-f]{64}")
_PENDING_HEADS: "collections.OrderedDict[asyncio.StreamWriter, None]" = collections.OrderedDict()
_PENDING_BODIES: "collections.OrderedDict[asyncio.StreamWriter, None]" = collections.OrderedDict()
_ATTACH_STREAMS: set = set()
_LONG_CALLS: set = set()
_LIVE_CALLS: dict = {}  # (call, full container id) -> the handler task holding it
_REQUEST_LINE = re.compile(rb"([!#$%&'*+.^_`|~0-9A-Za-z-]+) ([\x21-\x7e]+) HTTP/1\.[01]")
_HEADER_NAME = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_HEADER_VALUE = re.compile(rb"[\t\x20-\x7e\x80-\xff]*")
_BARE_CR_OR_LF = re.compile(rb"\r(?!\n)|(?<!\r)\n")
_FORWARDED_HEADERS = ("Host", "User-Agent", "Content-Type", "X-Registry-Auth")
# The calls whose body the broker parses, checks and re-serializes; every other
# call is forwarded without a body (the CLI sends none).
_JSON_BODY_KINDS = ("create", "volume-create", "network-create")


class BadHead(ValueError):
    """A request head the daemon could read differently from the broker, or
    one that does not arrive whole, small and in time."""


async def _read_head(reader: asyncio.StreamReader):
    """The request head up to its blank line (excluded), or None when the
    client closed without sending anything. One readuntil (linear, bounded by
    the server's `limit`), not a byte at a time."""
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), HEAD_TIMEOUT)
    except asyncio.LimitOverrunError:
        raise BadHead(f"request head over {HEAD_MAX} bytes") from None
    except asyncio.IncompleteReadError as e:
        if not e.partial:
            return None
        raise BadHead("connection closed inside the request head") from None
    except asyncio.TimeoutError:
        raise BadHead(f"request head not complete within {HEAD_TIMEOUT} s") from None
    if len(head) > HEAD_MAX:
        raise BadHead(f"request head over {HEAD_MAX} bytes")
    return head[:-4]


def _admit(pending, limit: int, writer, what: str) -> None:
    while len(pending) >= limit:
        oldest, _ = pending.popitem(last=False)
        oldest.transport.abort()
        _log_limited(("evict", what), f"{limit} connections were sending their {what}: "
                                      f"closed the one waiting longest")
    pending[writer] = None


def _clip(text: str, limit: int = 300) -> str:
    """A refusal echoes client values (an image, a key path): never more than
    `limit` characters of them."""
    return text if len(text) <= limit else f"{text[:limit]}... ({len(text)} characters)"


_LOG_INTERVAL = 10.0
# key -> (interval start, lines shown, lines held back); a shared allowance is
# kept here too, under ("pool", name), so a test that resets this resets all.
_log_marks: dict = {}
# Keys are bounded by construction (refusal classes come from the broker's own
# reason texts); past this many in one interval, new keys share one "overflow".
MAX_LOG_KEYS = 1024


def _log_limited(key, msg: str, burst: int = 1, shared: int = 0, first_cap: int = 0) -> None:
    """At most `burst` lines per `key` every _LOG_INTERVAL seconds, the next
    one naming how many were held back: a flood must not become a flood of log
    lines (the broker's log has no rotation of its own). With `shared`, the
    lines after a key's first also draw on one allowance of `shared` lines per
    interval for every key of the same kind (key[0]). With `first_cap`, the
    first lines too are limited, to `first_cap` keys per interval for every key
    of the same kind and pool (key[:2]), then one line says the rest are only
    counted; without it a key's first line always shows."""
    now = time.monotonic()
    if key not in _log_marks and len(_log_marks) >= MAX_LOG_KEYS:
        for stale in [k for k, mark in _log_marks.items() if now - mark[0] >= _LOG_INTERVAL]:
            del _log_marks[stale]       # its held-back count is lost
        if len(_log_marks) >= MAX_LOG_KEYS:
            key = (key[0], "overflow")
    start, shown, held = _log_marks.get(key, (None, 0, 0))
    if start is None or now - start >= _LOG_INTERVAL:
        if first_cap:
            firsts = ("firsts",) + tuple(key[:2])
            f_start, f_used, f_held = _log_marks.get(firsts, (now, 0, 0))
            if now - f_start >= _LOG_INTERVAL:
                f_start, f_used, f_held = now, 0, 0
            if f_used >= first_cap:
                if not f_held:
                    _log(f"{key[0].upper()}: more than {first_cap} kinds of {key[1]} refusals within "
                         f"{_LOG_INTERVAL:.0f} s; the rest are only counted")
                _log_marks[firsts] = (f_start, f_used, f_held + 1)
                _log_marks[key] = (now, burst, held + 1)
                return
            _log_marks[firsts] = (f_start, f_used + 1, f_held)
        _log(msg + (f" (and {held} more like it)" if held else ""))
        _log_marks[key] = (now, 1, 0)
        return
    pool = ("pool", key[0])
    pool_start, pool_used, _ = _log_marks.get(pool, (now, 0, 0))
    if now - pool_start >= _LOG_INTERVAL:
        pool_start, pool_used = now, 0
    if shown < burst and (not shared or pool_used < shared):
        _log(msg)
        _log_marks[key] = (start, shown + 1, held)
        if shared:
            _log_marks[pool] = (pool_start, pool_used + 1, 0)
    else:
        _log_marks[key] = (start, shown, held + 1)


# A client value inside a refusal reason: a quoted repr, a bracketed one (a
# list or dict, or a count in parentheses), a number or a JSON literal. Reasons
# quote every value they echo, so what is left is the broker's own text.
_REASON_VALUE = re.compile(r"""'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|[\[{(].*[\]})]"""
                           r"""|-?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|\b(?:True|False|None)\b""")
# The Docker API's top-level resources, so that a refused call off the
# allowlist names what it reached for (a delete of a volume, an exec, a plugin
# install), by method and resource, apart from junk paths; anything else reads
# "…". The verb stays out of the class: it would multiply the classes a caller
# can cycle through, and the line names the whole path anyway.
_API_RESOURCES = frozenset("""containers images volumes networks exec plugins swarm nodes services tasks
    secrets configs system events build session grpc auth commit distribution info version _ping""".split())
_HTTP_METHODS = frozenset("GET HEAD POST PUT DELETE PATCH OPTIONS".split())


# Calls off the allowlist that reach for a way past the broker (a shell or a
# copy into a container, a change to it, an image the tools run, a build, a
# plugin, swarm, a volume or network removed or rewired, the daemon's own
# events): refused into the alarm pool, one class per resource and action from
# this fixed list, "*" for any call on the resource, "delete" for a DELETE.
_DANGEROUS_CALLS = {
    "containers": {"exec", "archive", "update", "export", "commit", "rename", "restart", "resize", "top",
                   "changes", "stats", "prune", "copy", "attach"},
    "images": {"load", "push", "tag", "get", "prune", "delete"},
    "volumes": {"delete", "prune"},
    "networks": {"delete", "prune", "connect", "disconnect"},
    **dict.fromkeys(("exec", "build", "commit", "plugins", "swarm", "session", "grpc", "auth", "secrets",
                     "configs", "services", "nodes", "tasks", "distribution", "system", "events"), "*"),
}


def _api_segments(path_only: str) -> list:
    """The path's segments as the daemon routes them: it decodes the path once
    (%2F included) before matching, so the classes read it decoded too."""
    segments = [s for s in _normalize_path(urllib.parse.unquote(path_only)).split("/") if s]
    if segments and re.fullmatch(r"v[0-9.]+", segments[0]):
        segments = segments[1:]
    return segments


def _dangerous_action(method: str, path_only: str):
    """(resource, action) of a call off the allowlist on the list above, or None.
    The action of a container, network or exec call is the segment after its
    id (`/containers/<id>/attach/ws` is an attach); of an image call, the last
    (image names hold slashes)."""
    segments = _api_segments(path_only)
    rule = _DANGEROUS_CALLS.get(segments[0]) if segments else None
    if rule == "*":
        return segments[0], "*"
    if method == "DELETE":
        action = "delete"
    elif segments[:1] in (["containers"], ["networks"], ["exec"]) and len(segments) > 2:
        action = segments[2]
    else:
        action = segments[-1] if len(segments) > 1 else ""
    return (segments[0], action) if rule and action in rule else None


def _refusal_class(reason: str, path_only: str = "", extra: str = "", method: str = "") -> str:
    """What the DENY limiter tells refusals apart by: the reason (and the
    log-only detail) with every client value masked, so junk cannot make a
    class per value, and for a call off the allowlist the dangerous resource
    and action it names, else its method and the Docker API resource."""
    cls = _REASON_VALUE.sub("…", reason + extra)[:200]
    if reason == _OFF_THE_ALLOWLIST:
        cls += " ({} {})".format(*(_dangerous_action(method, path_only) or _call_shape(method, path_only)))
    return cls


def _off_allowlist_pool(method: str, path_only: str) -> str:
    # A "%" left after the daemon's own decode is a second encoding (or a bad
    # one): no tool sends either, so it is an alarm whatever it spells.
    if _dangerous_action(method, path_only) or "%" in urllib.parse.unquote(path_only):
        return "alarm"
    return "noise" if _call_shape(method, path_only)[1] == "…" else "endpoint"


def _call_shape(method: str, path_only: str) -> tuple:
    """(method, resource) of a call, each from a fixed vocabulary or "…"."""
    segments = _api_segments(path_only)
    resource = segments[0] if segments and segments[0] in _API_RESOURCES else "…"
    return (method if method in _HTTP_METHODS else "…"), resource


# Validator refusals that are no attempt to reach past the broker: a body or a
# value of a shape the daemon would refuse too (they share DENY_FIRST_NOISE
# first lines). Matched whole against the reason with its client values masked:
# a refused bind whose destination reads "is not an integer" stays an alarm.
_SHAPE_REASONS = re.compile(r"(?:[A-Za-z.…]+|the body|create body) is not a JSON (?:object|array)"
                            r"|[A-Za-z.]+ is not an integer|unexpected value in the body …"
                            r"|unparseable (?:volume|network) create body")


def _validator_pool(reason: str) -> str:
    return "noise" if _SHAPE_REASONS.fullmatch(_REASON_VALUE.sub("…", reason)) else "alarm"


def _loop_exception(loop, context) -> None:
    """The event loop's own errors (accept() out of file descriptors among
    them) as one rate-limited line, not a traceback per occurrence."""
    message = context.get("message", "event loop error")
    exc = context.get("exception")
    _log_limited(("loop", message), f"loop: {message}" + (f": {exc!r}" if exc else ""))


def raise_nofile_limit() -> int:
    """Raise the soft open-file limit to the hard one (the broker container
    starts at 1024 of 524288, and at 1024 a flood of idle connections made
    accept() fail) and size the connection budgets from it. Returns it."""
    global MAX_PENDING_HEADS, MAX_PENDING_BODIES, MAX_ATTACH_STREAMS, MAX_LONG_CALLS
    soft = 1024
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target = hard if hard != resource.RLIM_INFINITY else max(soft, 1048576)
        if target > soft:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
            soft = target
    except (ImportError, ValueError, OSError):
        pass
    # An eighth each: attach streams and long calls hold two descriptors, and
    # every other request needs some.
    MAX_PENDING_HEADS = max(16, min(4096, soft // 8))
    MAX_PENDING_BODIES = max(16, min(128, soft // 16))
    MAX_ATTACH_STREAMS = MAX_LONG_CALLS = max(16, min(1024, soft // 8))
    return soft


def parse_head(head: bytes) -> tuple[str, str, dict]:
    """(method, target, headers by lower-case name) of a request head, or
    BadHead: a bare CR or LF, a NUL or other control byte, a folded or
    malformed header line, a header given twice, a Transfer-Encoding, or a
    Content-Length that is not plain digits."""
    if _BARE_CR_OR_LF.search(head):
        raise BadHead("a bare CR or LF in the request head")
    lines = head.split(b"\r\n")
    m = _REQUEST_LINE.fullmatch(lines[0])
    if not m:
        raise BadHead(f"malformed request line ({len(lines[0])} bytes)")
    headers = {}
    for line in lines[1:]:
        if line[:1] in (b" ", b"\t"):
            raise BadHead("a folded header line")
        name, colon, value = line.partition(b":")
        if not colon or not _HEADER_NAME.fullmatch(name):
            raise BadHead(f"malformed header line ({len(line)} bytes)")
        value = value.strip(b" \t")
        if not _HEADER_VALUE.fullmatch(value):
            raise BadHead(f"control character in header {name.decode()!r}")
        key = name.decode("ascii").lower()
        if key in headers:
            raise BadHead(f"header {name.decode()!r} given twice")
        headers[key] = value.decode("latin1")
    if "transfer-encoding" in headers:
        raise BadHead("Transfer-Encoding is not accepted; send a Content-Length")
    if not re.fullmatch(r"[0-9]{1,18}", headers.get("content-length", "0")):
        raise BadHead("Content-Length is not 1 to 18 digits")
    return m.group(1).decode("ascii"), m.group(2).decode("ascii"), headers


def _upstream_head(method: str, target: str, headers: dict, body_len: int, attach: bool = False) -> bytes:
    """The head the daemon gets: the checked request line and the allowlisted
    headers, never the client's bytes."""
    lines = [f"{method} {target} HTTP/1.1"]
    if "host" not in headers:
        lines.append("Host: docker")
    lines += [f"{name}: {headers[name.lower()]}" for name in _FORWARDED_HEADERS if name.lower() in headers]
    lines += ["Connection: Upgrade", "Upgrade: tcp"] if attach else ["Connection: close"]
    if body_len or method in ("POST", "PUT"):
        lines.append(f"Content-Length: {body_len}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin1")


def _deny(reason: str) -> bytes:
    body = json.dumps({"message": f"denied by docker-broker: {reason}"}).encode()
    return (
        b"HTTP/1.1 403 Forbidden\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"Connection: close\r\n\r\n" + body
    )


async def _pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter, on_first=None, on_data=None):
    """Copy src to dst until src ends; `on_first` sees the first bytes, `on_data` every chunk."""
    try:
        while True:
            data = await src.read(65536)
            if not data:
                break
            if on_first is not None:
                on_first(data)
                on_first = None
            if on_data is not None:
                on_data(data)
            dst.write(data)
            await dst.drain()
    except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
        pass
    finally:
        try:
            dst.write_eof()
        except Exception:
            pass


async def _attach(client_reader, client_writer, up_reader, up_writer, label: str, on_data=None):
    """Relay an attach. The client's bytes reach the daemon only once it has
    answered 101 and taken the connection over: before that (an API version too
    old, a bad query), the daemon would read them as the next request."""
    try:
        answer = await asyncio.wait_for(up_reader.readuntil(b"\r\n\r\n"), ATTACH_ANSWER_TIMEOUT)
    except asyncio.TimeoutError:
        _log(_clip(f"DROP {label}: the daemon did not answer the attach within {ATTACH_ANSWER_TIMEOUT} s"))
        return
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError) as e:
        _log(_clip(f"DROP {label}: the daemon closed or garbled its answer to the attach ({type(e).__name__})"))
        return
    client_writer.write(answer)
    await client_writer.drain()
    status = answer.split(b" ", 2)[1:2]
    if status == [b"101"]:
        # The daemon ends the stream once the container's output has ended (it
        # exited, or was removed after it ran): the attach ends then, whether
        # or not the client ever closes its side.
        to_daemon = asyncio.ensure_future(_pipe(client_reader, up_writer))
        try:
            await _pipe(up_reader, client_writer, on_data=on_data)
        finally:
            to_daemon.cancel()
            await asyncio.gather(to_daemon, return_exceptions=True)
        return
    length = re.search(rb"(?im)^content-length:[ \t]*([0-9]+)[ \t]*\r$", answer)
    try:
        if length:
            client_writer.write(await asyncio.wait_for(up_reader.readexactly(int(length.group(1))), 30))
        else:
            up_writer.write_eof()   # the daemon closes once its answer is out
            await asyncio.wait_for(_pipe(up_reader, client_writer), 30)
        await client_writer.drain()
    except (asyncio.IncompleteReadError, asyncio.TimeoutError):
        pass


async def _until_client_leaves(reader) -> None:
    try:
        while await reader.read(65536):
            pass
    except (ConnectionError, OSError):
        pass


async def _relay(up_reader, client_reader, client_writer, on_data=None) -> None:
    """Relay the daemon's answer until it ends or the client hangs up. A wait
    for a container that never exits gets no byte from the daemon, so a caller
    that left would otherwise hold both connections for good."""
    relay = asyncio.ensure_future(_pipe(up_reader, client_writer, on_data=on_data))
    gone = asyncio.ensure_future(_until_client_leaves(client_reader))
    try:
        await asyncio.wait({relay, gone}, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for task in (relay, gone):
            task.cancel()
        await asyncio.gather(relay, gone, return_exceptions=True)


# A network inspect lists every container on the network (full id, name,
# addresses), other runs' and other tenants' included: the TruffleHog
# verifier's network holds the orchestrator's TruffleHog scans, whose
# environment carries tenants' tokens, and a full id is what a name-race
# needs. The tools read only whether the network exists (the CLI's exit code:
# trufflehog_bridge.ensure_verify_network, analyzer_dispatch), so the broker
# answers without them.
NETWORK_ANSWER_MAX = 4 * 1024 * 1024
_NETWORK_MEMBER_FIELDS = ("Containers", "Services")


def _answer(status_line: bytes, payload: bytes) -> bytes:
    return (status_line + b"\r\nContent-Type: application/json\r\nContent-Length: "
            + str(len(payload)).encode() + b"\r\nConnection: close\r\n\r\n" + payload)


async def _relay_network(up_reader, client_writer) -> None:
    """Relay a network inspect, whole and without its member containers."""
    data = b""

    async def read_all():
        nonlocal data
        while len(data) <= NETWORK_ANSWER_MAX:
            chunk = await up_reader.read(65536)
            if not chunk:
                return
            data += chunk
    try:
        await asyncio.wait_for(read_all(), INSPECT_TIMEOUT)
    except asyncio.TimeoutError:
        data = b""
    head, sep, body = data.partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n", 1)[0]
    if not sep or len(data) > NETWORK_ANSWER_MAX or not re.fullmatch(rb"HTTP/1\.[01] [0-9]{3}[ -~]*", status_line):
        client_writer.write(_answer(b"HTTP/1.1 502 Bad Gateway",
                                    b'{"message": "docker-broker: no readable network answer from the daemon"}'))
        return
    if b"transfer-encoding: chunked" in head.lower():
        body = _dechunk(body)
    if status_line.split(b" ", 2)[1] == b"200":
        try:
            doc = json.loads(body)
        except ValueError:
            doc = None
        if not isinstance(doc, dict):
            client_writer.write(_answer(b"HTTP/1.1 502 Bad Gateway",
                                        b'{"message": "docker-broker: no readable network answer from the daemon"}'))
            return
        for field in _NETWORK_MEMBER_FIELDS:
            doc.pop(field, None)
        body = json.dumps(doc).encode()
    client_writer.write(_answer(status_line, body))


# Refusals are logged per refusal class (_refusal_class) in each _LOG_INTERVAL,
# in three pools. "alarm": an attempt to reach past the broker (a privileged or
# host-reaching create, a smuggled head, a repeated or look-alike key, another
# run's or an infrastructure container, an image or volume not a tool's): the
# first line of every class always shows, so a flood of junk cannot hide one;
# its classes are the broker's own reason texts, a few dozen. "endpoint": a call
# off the allowlist naming a real Docker API resource, one class per method
# and resource, DENY_FIRST_ENDPOINT classes' first lines (an operator sees the
# probing past them and a line saying so); "noise" (a body that does not parse, a value of the
# wrong shape, a budget, junk paths), DENY_FIRST_NOISE; past those, one line
# says the rest are only counted. After its first line, a class gets up to
# DENY_BURST more while DENY_SHARED lines remain for all of them together.
DENY_BURST = 20
DENY_SHARED = 50
DENY_FIRST_ENDPOINT = 64
DENY_FIRST_NOISE = 16
_OFF_THE_ALLOWLIST = "not on the broker allowlist"


def _query_values(target: str, name: str) -> list:
    """Every value of one query parameter, decoded as the daemon decodes it
    (Go's ParseQuery: `&` only, names decoded too; it reads the first)."""
    query = target.partition("?")[2]
    return [v for k, v in urllib.parse.parse_qsl(query, keep_blank_values=True) if k == name]


def _wait_refusal(target: str, info: dict):
    """Why a wait on this container is refused, or None. A wait must end: one
    for the next exit of a container that has ended waits for a start that may
    never come, and one for the removal of a container the daemon does not
    remove on exit (no AutoRemove, which `docker run --rm` sets) waits for good;
    either would hold a long call after its container no longer counts against
    the container cap."""
    conditions = _query_values(target, "condition")
    if len(conditions) > 1:
        return "the wait condition is given twice"
    condition = (conditions or [""])[0] or "not-running"
    if condition not in _WAIT_CONDITIONS:
        return f"wait condition {condition!r} is not one the daemon knows"
    status = (info.get("State") or {}).get("Status")
    if condition == "next-exit" and status in _ENDED_STATES:
        return f"a wait for the next exit of a container that has ended ({status!r})"
    if condition == "removed" and (status == "dead"
                                   or (info.get("HostConfig") or {}).get("AutoRemove") is not True):
        return "a wait for the removal of a container the daemon does not remove on exit (AutoRemove)"
    return None


def _stop_target(target: str, info: dict):
    """(the stop the daemon gets, None) with `t` always set to at most
    STOP_TIMEOUT_MAX, or (None, the reason to refuse)."""
    given = _query_values(target, "t")
    if given and not re.fullmatch(r"[+-]?[0-9]{1,18}", given[0]):
        return None, "the stop timeout t is not an integer"
    if given:
        seconds = int(given[0])
    else:
        own = (info.get("Config") or {}).get("StopTimeout")
        seconds = own if isinstance(own, int) and not isinstance(own, bool) else STOP_TIMEOUT_DEFAULT
    seconds = STOP_TIMEOUT_MAX if seconds < 0 else min(seconds, STOP_TIMEOUT_MAX)
    query = [("t", str(seconds))] + [("signal", s) for s in _query_values(target, "signal")[:1]]
    return target.partition("?")[0] + "?" + urllib.parse.urlencode(query), None


# Strong references to every running handler. The event loop holds tasks only
# weakly and a StreamReaderProtocol holds its reader only by weakref, so once a
# client half-closes an attach stream (`docker run` does it right after the 101,
# before the container starts) nothing anchors the handler: a cyclic GC pass then
# destroys it mid-stream ("Task was destroyed but it is pending!"), the attach
# socket closes, and the tool's stdout/stderr is lost while `docker run` exits 0.
# GC runs more often under load, so this hit concurrent scans: katana and
# hakrawler reported 0 URLs as a genuine empty crawl.
_IN_FLIGHT: set = set()


def _on_container(path_only: str, route, full_id: str, target: str) -> str:
    """The forwarded target: the checked container named by its full id, the
    client's query kept."""
    query = target.partition("?")[2]
    path = path_only[:route.start(1)] + full_id + path_only[route.end(1):]
    return path + ("?" + query if query else "")


async def handle_client(client_reader, client_writer):
    """Handle one Docker-API request. Forwards only after the request is
    allowed, so a denied request never reaches the real daemon (the ownership
    check's own label inspect aside)."""
    up_writer = None
    me = asyncio.current_task()
    _IN_FLIGHT.add(me)
    method = path_only = "-"
    kind = live_key = call = container_id = watched = None
    admitted = False

    def release(_first_bytes=b""):
        # The daemon has answered the create or start it was admitted for: its
        # count now shows the container (or there is none), so the place is free.
        nonlocal admitted
        if admitted:
            admitted = False
            _release_admission()

    def removed(first_bytes: bytes):
        if first_bytes.split(b" ", 2)[1:2] in ([b"200"], [b"204"]):
            calls_removed(container_id, spare=me)

    async def _refuse(reason: str, log_extra: str = "", burst: int = DENY_BURST, cls=None, pool="alarm"):
        # One log line per refusal, naming the call: what a refused tool
        # (or an attacker) asked for is what the operator needs to see. Echoed
        # values are clipped, and lines are limited per refusal class and pool.
        line = f"DENY {_clip(method, 20)} {_clip(path_only, 200)}: {_clip(reason)}{_clip(log_extra, 200)}"
        key = ("deny", pool, cls or _refusal_class(reason, path_only, log_extra, method))
        first_cap = {"endpoint": DENY_FIRST_ENDPOINT, "noise": DENY_FIRST_NOISE}.get(pool, 0)
        _log_limited(key, line, burst=burst, shared=DENY_SHARED, first_cap=first_cap)
        if not client_writer.is_closing():
            client_writer.write(_deny(_clip(reason)))
            await client_writer.drain()

    async def _refuse_body(kind_of_body: str, error: Exception):
        # A repeated key is a way past the checks (the daemon applies every
        # repeat); every other body that does not parse is one class per kind.
        repeat = isinstance(error, ValueError) and str(error).startswith("repeated key")
        await _refuse(f"{kind_of_body} body refused: {error}",
                      cls=f"{kind_of_body} body repeats a key" if repeat else f"{kind_of_body} body does not parse",
                      pool="alarm" if repeat else "noise")

    try:
        _admit(_PENDING_HEADS, MAX_PENDING_HEADS, client_writer, "request head")
        try:
            head = await _read_head(client_reader)
            if head is None:
                return
            method, target, headers = parse_head(head)
        except BadHead as e:
            # Heads no tool sends: one line per class and interval.
            await _refuse(f"malformed request head: {e}", burst=1)
            return
        finally:
            _PENDING_HEADS.pop(client_writer, None)
        path_only = _normalize_path(target)  # canonical form for route matching
        run = caller_run(headers.get(RUN_HEADER))

        kind, route = match_route(method, path_only)
        if kind is None:
            await _refuse(_OFF_THE_ALLOWLIST, pool=_off_allowlist_pool(method, path_only))
            return

        # ---- E1: verbs on an EXISTING container only on broker-owned targets
        # of the caller's run. A compromised recon container must not be able
        # to attach/kill/inspect a container the broker did not create (the
        # orchestrator's environment holds the master keys; the broker's own
        # Docker socket is host root), nor take another run's tools.
        if kind in ("owned", "attach"):
            cid = route.group(1)
            info = await _upstream_inspect(cid)
            if not _is_owned(info) or container_run(info) != run:
                # One answer whether it is absent, not the broker's or another
                # run's, so a caller learns nothing of other runs' containers.
                why = "no such container" if info is None else \
                    "not created by the broker" if not _is_owned(info) else "created for another run"
                await _refuse(f"container {cid!r} is not a tool container of this run", f"; {why}")
                return
            container_id = info.get("Id")
            if not isinstance(container_id, str) or not _FULL_ID.fullmatch(container_id):
                await _refuse(f"no full id for container {cid!r} in the daemon's answer", pool="noise")
                return
            # The call goes to the container just checked, by its full id. The
            # daemon resolves a name, then an id prefix, again on the forward:
            # a caller that removes its own container named with another
            # container's id prefix in between had the prefix name the other.
            target = _on_container(path_only, route, container_id, target)
            status = (info.get("State") or {}).get("Status")
            # attach, or the verb after the name (start, wait, logs...); a DELETE
            # path ends with the name itself.
            call = "attach" if kind == "attach" else "remove" if method == "DELETE" \
                else path_only.rsplit("/", 1)[-1]
            # A long call must end: an attach to an ended container, or a
            # wait it cannot see happen, would hold its place for good once
            # the container no longer counts against the container cap (one
            # that ends right after this check is the watchdog's).
            if call == "attach" and status in _ENDED_STATES:
                await _refuse(f"an attach to a container that has ended ({status!r}) "
                              f"waits for a start that may never come", pool="noise")
                return
            if call == "wait":
                refused = _wait_refusal(target, info)
                if refused:
                    await _refuse(refused, pool="noise")
                    return
            if call == "stop":
                target, refused = _stop_target(target, info)
                if refused:
                    await _refuse(refused, pool="noise")
                    return
            if call == "start":
                if status not in _STARTABLE_STATES:
                    await _refuse(f"a start of a container that is {status!r}: no tool sends one", pool="noise")
                    return
                # A start of an exited container raises the live count the
                # create cap reads, so it is capped too (a created one is
                # already counted).
                if BROKER_MAX_CONTAINERS > 0 and status in ("exited", "dead"):
                    refused = await _admit_container()
                    if refused:
                        await _refuse(refused, pool="noise")
                        return
                    admitted = True
            if call in _WATCHED_CALLS or call == "start":
                if (call, container_id) in _LIVE_CALLS:
                    await _refuse(f"container {cid!r} already has an open {call}", pool="noise")
                    return
                if call in _LONG_CALLS_ON_A_CONTAINER:
                    if len(_LONG_CALLS) >= MAX_LONG_CALLS and not evict_kept(call):
                        # (a stop counts here too)
                        await _refuse(f"{MAX_LONG_CALLS} long calls (wait, logs) are already open", pool="noise")
                        return
                    _LONG_CALLS.add(me)
                live_key = (call, container_id)
                _LIVE_CALLS[live_key] = me
                if call in _WATCHED_CALLS:
                    watched = _Watched(me, client_writer, removal_wait=call == "wait"
                                       and _query_values(target, "condition")[:1] == ["removed"], run=run)
                    _WATCHED[live_key] = watched
                    _ensure_watchdog()
        elif kind in ("image", "volume", "network"):
            ok, reason = _name_allowed(kind, route)
            if not ok:
                await _refuse(reason)
                return

        clen = int(headers.get("content-length", "0"))
        if clen and kind not in _JSON_BODY_KINDS:
            await _refuse("this call carries no request body")
            return
        if clen > body_max(kind):
            await _refuse(f"request body over {body_max(kind)} bytes", pool="noise")
            return

        # ---- attach: upgrade, then raw bidirectional pipe ----
        if kind == "attach":
            if headers.get("upgrade", "").lower() != "tcp":
                await _refuse("an attach must ask for Upgrade: tcp")
                return
            if len(_ATTACH_STREAMS) >= MAX_ATTACH_STREAMS and not evict_kept("attach"):
                await _refuse(f"{MAX_ATTACH_STREAMS} attach streams are already open", pool="noise")
                return
            _ATTACH_STREAMS.add(me)
            try:
                up_reader, up_writer = await asyncio.open_unix_connection(UPSTREAM_SOCK)
                up_writer.write(_upstream_head(method, target, headers, 0, attach=True))
                await up_writer.drain()
                await _attach(client_reader, client_writer, up_reader, up_writer, f"{method} {path_only}",
                              on_data=watched.count if watched else None)
            finally:
                _ATTACH_STREAMS.discard(me)
            return

        # ---- E1: scope container listing to broker-owned so the pivot cannot
        # even enumerate infra containers, and to the caller's run. Force label
        # filters onto the query. ----
        if kind == "list":
            target = _owned_list_target(target, run)

        body = b""
        if clen:
            _admit(_PENDING_BODIES, MAX_PENDING_BODIES, client_writer, "request body")
            try:
                body = await asyncio.wait_for(client_reader.readexactly(clen), BODY_TIMEOUT)
            except asyncio.IncompleteReadError:
                return  # the client went away (or was closed) before its body was whole
            except asyncio.TimeoutError:
                await _refuse(f"request body not complete within {BODY_TIMEOUT} s", burst=1, pool="noise")
                return
            finally:
                _PENDING_BODIES.pop(client_writer, None)

        # ---- validate POST /containers/create (deny = no upstream contact) ----
        if kind == "create":
            try:
                cfg = parse_body(body or b"{}")
            except Exception as e:  # noqa: BLE001 - refused, never forwarded
                await _refuse_body("create", e)
                return
            ok, reason = _checked(validate_create, cfg)
            if ok:
                reason = await sandbox_network_refusal(cfg)
                ok = reason is None
            if not ok:
                await _refuse(reason, f" (image={cfg.get('Image')!r})" if isinstance(cfg, dict) else "",
                              pool=_validator_pool(reason))
                return
            # Phase 7: sibling-container count cap, admitted one at a time and
            # held until the daemon has answered (_admit_container).
            if BROKER_MAX_CONTAINERS > 0:
                refused = await _admit_container()
                if refused:
                    await _refuse(refused, pool="noise")
                    return
                admitted = True
            # Memory governor (Part 4d): inject the hard mem cap; E1: stamp the
            # broker-owned marker label; then re-serialize the body.
            inject_limits(cfg)
            clamp_stop_timeout(cfg)
            mark_owned(cfg)
            stamp_run_labels(cfg, headers.get(RUN_HEADER))
            body = json.dumps(cfg).encode("utf-8")
            _log(f"ALLOW create image={cfg.get('Image')!r} mem={cfg.get('HostConfig', {}).get('Memory')} "
                 f"run={cfg['Labels'].get('redamon.run_id', '-')}")

        # ---- validate docker pull (deny = no upstream contact) ----
        if kind == "pull":
            ok, reason = validate_pull(target)
            if not ok:
                await _refuse(reason)
                return

        if kind in ("volume-create", "network-create"):
            try:
                spec = parse_body(body or b"null")
            except Exception as e:  # noqa: BLE001 - refused, never forwarded
                await _refuse_body(kind, e)
                return
            validate = validate_volume_create if kind == "volume-create" else validate_network_create
            ok, reason = _checked(validate, spec)
            if not ok:
                await _refuse(reason, pool=_validator_pool(reason))
                return
            # Forward what was checked, not the client's bytes.
            body = json.dumps(spec).encode("utf-8")

        # ---- allowed: NOW connect upstream and forward; Connection: close
        # makes the daemon answer this one request only. ----
        up_reader, up_writer = await asyncio.open_unix_connection(UPSTREAM_SOCK)
        up_writer.write(_upstream_head(method, target, headers, len(body)) + body)
        await up_writer.drain()

        # relay response (possibly chunked/streamed) until upstream closes, or
        # for a long call until the client hangs up
        if call in _LONG_CALLS_ON_A_CONTAINER:
            await _relay(up_reader, client_reader, client_writer, on_data=watched.count if watched else None)
        elif kind == "network":
            await _relay_network(up_reader, client_writer)
        else:
            await _pipe(up_reader, client_writer, on_first=removed if call == "remove" else release)
    except (ConnectionResetError, BrokenPipeError):
        pass
    except Exception as e:
        _log_limited(("error", type(e).__name__), _clip(f"error: {e!r}"))
    finally:
        release()
        _IN_FLIGHT.discard(me)
        _LONG_CALLS.discard(me)
        if live_key is not None and _LIVE_CALLS.get(live_key) is me:
            del _LIVE_CALLS[live_key]
        if watched is not None and _WATCHED.get(live_key) is watched:
            del _WATCHED[live_key]
        for w in (client_writer, up_writer):
            if w is not None:
                try:
                    w.close()
                except Exception:
                    pass


async def main():
    # fresh socket
    try:
        os.makedirs(os.path.dirname(LISTEN_SOCK), exist_ok=True)
    except Exception:
        pass
    if os.path.exists(LISTEN_SOCK):
        os.unlink(LISTEN_SOCK)

    nofile = raise_nofile_limit()
    asyncio.get_running_loop().set_exception_handler(_loop_exception)
    # `limit` bounds the request head readuntil buffers (_read_head).
    # backlog: a burst of connections must not make a tool's connect() fail
    # with EAGAIN before the loop accepts it (the kernel caps it at somaxconn).
    server = await asyncio.start_unix_server(handle_client, path=LISTEN_SOCK, limit=HEAD_MAX, backlog=1024)
    try:
        os.chmod(LISTEN_SOCK, 0o660)
    except Exception:
        pass
    _log(f"listening on {LISTEN_SOCK} -> upstream {UPSTREAM_SOCK}")
    _log(f"open files {nofile}; at most {MAX_PENDING_HEADS} connections sending a head ({HEAD_TIMEOUT} s), "
         f"{MAX_PENDING_BODIES} sending a body ({BODY_TIMEOUT} s), {MAX_ATTACH_STREAMS} attach streams, "
         f"{MAX_LONG_CALLS} long calls")
    _log(f"allowed images: {sorted(ALLOWED_IMAGES)}")
    _log(f"allowed bind prefixes: {ALLOWED_BIND_PREFIXES}; volumes: {sorted(ALLOWED_VOLUMES)} "
         f"(writable: {sorted(ALLOWED_RW_VOLUMES)}); networks: {sorted(ALLOWED_NETWORKS)}")
    if not REPO_ROOT:
        _log("DOCKER_BROKER_REPO_ROOT is unset: no repository directory can be mounted "
             "(custom nuclei templates, the Amass wordlist and the supply-chain analyzer will be refused)")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
