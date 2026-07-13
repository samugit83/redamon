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
forwards everything transparently EXCEPT `POST /containers/create`, whose body it
parses and validates against an allowlist — rejecting any request that would let
a container escape to the host (bind-mounting host paths, --privileged, dangerous
caps/namespaces, mounting the docker socket, or a non-allowlisted image).

The orchestrator keeps the REAL socket (it is the trusted component). Only the
recon/partial-recon containers are put behind the broker.

DESIGN (deliberately simple to stay correct)
---------------------------------------------
One Docker API request per client connection (we inject `Connection: close` on
the forwarded request so the upstream closes after each response and the docker
client just reconnects for the next call — eliminating keep-alive request
smuggling). For each connection:
  * parse the request line + headers (+ body via Content-Length),
  * if it is a hijack endpoint (`/attach`, `/exec/<id>/start`) -> forward the
    headers then blind-pipe BYTES bidirectionally until close (handles streamed
    stdin/stdout, e.g. hakrawler's piped stdin and live tool output),
  * if it is `POST .../containers/create` -> validate the JSON body; reject with
    403 or forward + relay the response,
  * otherwise -> forward and relay the (possibly streamed/chunked) response.

Stdlib only (asyncio + json) so it runs in a tiny image with no dependencies.
"""
import asyncio
import json
import os
import re
import sys
from urllib.parse import parse_qs, urlsplit

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
    "caffix/amass:latest",
    "frost19k/puredns:latest",
    "sxcurity/gau:latest",
    "sxcurity/gau:arm64",
    "jauderho/hakrawler:latest",
    "ghcr.io/zaproxy/zaproxy:stable",
    "dolevf/graphql-cop:1.14",
    "redamon-baddns:latest",
    "alpine",          # temp-file cleanup helper
    "alpine:latest",
]


def _csv_env(name: str) -> list[str]:
    return [p.strip() for p in os.environ.get(name, "").split(",") if p.strip()]


ALLOWED_IMAGES = set(_DEFAULT_ALLOWED_IMAGES) | set(_csv_env("DOCKER_BROKER_ALLOWED_IMAGES"))

# Host bind-mount sources the tools legitimately need. Anything else (especially
# "/" or the docker socket) is denied. Sources without a leading "/" are treated
# as named volumes and checked against ALLOWED_VOLUMES.
_DEFAULT_BIND_PREFIXES = ["/tmp/redamon"]
ALLOWED_BIND_PREFIXES = _DEFAULT_BIND_PREFIXES + _csv_env("DOCKER_BROKER_ALLOWED_BIND_PREFIXES")
ALLOWED_VOLUMES = set(_csv_env("DOCKER_BROKER_ALLOWED_VOLUMES")) | {"nuclei-templates"}

# T1/T2: host paths a tool container may bind READ-WRITE. Any other allowed
# host path (e.g. the source tree under ${PWD}, which is an allowed *read*
# prefix so tools can mount wordlists/output ro) may be bound only :ro.
# Legit sub-tool spawns write exclusively under /tmp/redamon; everything else
# they mount is already :ro (targets, wordlists, work dirs, nuclei-templates).
# This closes the "bind ${PWD} rw and overwrite recon/main.py or a Skill" path.
_DEFAULT_RW_PREFIXES = ["/tmp/redamon"]
ALLOWED_RW_PREFIXES = _DEFAULT_RW_PREFIXES + _csv_env("DOCKER_BROKER_ALLOWED_RW_PREFIXES")
ALLOWED_RW_VOLUMES = set(_csv_env("DOCKER_BROKER_ALLOWED_RW_VOLUMES"))

# Capabilities a tool container may request (naabu SYN etc.). Everything else
# (SYS_ADMIN, SYS_PTRACE, ALL, ...) is denied.
ALLOWED_CAPS = {"NET_RAW", "NET_ADMIN", "CAP_NET_RAW", "CAP_NET_ADMIN"}

_CREATE_RE = re.compile(r"^/(v[\d.]+/)?containers/create$")
_HIJACK_RE = re.compile(r"^/(v[\d.]+/)?(containers/[^/]+/attach|exec/[^/]+/start)$")
_IMAGES_CREATE_RE = re.compile(r"^/(v[\d.]+/)?images/create$")  # docker pull


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
    # Docker's pull API canonicalizes Docker Hub names to docker.io/<repo> and
    # official images to docker.io/library/<name>.  Compare those canonical
    # spellings with the short allowlist form, but do not strip other registries.
    candidates = {image}
    if image.startswith("docker.io/"):
        short = image[len("docker.io/"):]
        candidates.add(short)
        if short.startswith("library/"):
            candidates.add(short[len("library/"):])
    for candidate in candidates:
        if candidate in ALLOWED_IMAGES:
            return True
        # Also accept the implicit ":latest" spelling.
        if ":" not in candidate.split("/")[-1] \
                and f"{candidate}:latest" in ALLOWED_IMAGES:
            return True
    return False


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
        return any(norm == p.rstrip("/") or norm.startswith(p.rstrip("/") + "/")
                   for p in ALLOWED_BIND_PREFIXES)
    # no leading slash -> named volume
    return source in ALLOWED_VOLUMES


def _rw_host_path_allowed(source: str) -> bool:
    """T1/T2: is this host path allowed to be bound READ-WRITE?"""
    norm = os.path.normpath(source)
    return any(norm == p.rstrip("/") or norm.startswith(p.rstrip("/") + "/")
               for p in ALLOWED_RW_PREFIXES)


def _bind_is_readonly(opts: str) -> bool:
    """A docker bind mode field is comma-separated (e.g. 'ro', 'ro,z', 'rw').
    Read-only iff the 'ro' token is present; default (no field) is read-write."""
    return "ro" in [o.strip() for o in opts.split(",") if o.strip()]


def validate_create(body: dict) -> tuple[bool, str]:
    """Return (allowed, reason) for a POST /containers/create body."""
    image = body.get("Image", "")
    if not _image_allowed(image):
        return False, f"image not on allowlist: {image!r}"

    hc = body.get("HostConfig") or {}

    if hc.get("Privileged"):
        return False, "Privileged=true denied"
    for cap in hc.get("CapAdd") or []:
        if str(cap).upper() not in ALLOWED_CAPS:
            return False, f"capability not allowed: {cap}"
    if hc.get("Devices"):
        return False, "device passthrough denied"
    for ns in ("PidMode", "IpcMode", "UsernsMode", "CgroupnsMode"):
        v = str(hc.get(ns, ""))
        # host -> shares the host namespace; container:<x> -> joins another
        # container's namespace (e.g. the orchestrator's) -> escape/lateral path.
        if v.startswith("host") or v.startswith("container:"):
            return False, f"{ns}={v} denied"
    # NetworkMode host is needed (loopback/raw); but joining another container's
    # netns (e.g. the orchestrator's, to reach its loopback API) is denied.
    if str(hc.get("NetworkMode", "")).startswith("container:"):
        return False, f"NetworkMode={hc.get('NetworkMode')} denied"
    # VolumesFrom would inherit ANOTHER container's mounts (e.g. the orchestrator's
    # /var/run/docker.sock) -> host root. Recon tools never use it.
    if hc.get("VolumesFrom"):
        return False, "VolumesFrom denied"
    # Overriding the daemon's default masked/readonly /proc paths weakens
    # isolation (exposes /proc/kcore etc.). Legit tool runs never set these.
    for sensitive in ("MaskedPaths", "ReadonlyPaths"):
        if hc.get(sensitive) is not None:
            return False, f"{sensitive} override denied"
    # docker.sock or sensitive security_opt
    for so in hc.get("SecurityOpt") or []:
        # allow seccomp/apparmor profiles; deny explicit unconfined which widens escape surface
        if "unconfined" in str(so):
            return False, f"SecurityOpt {so} denied"

    # Binds: ["src:dst", "src:dst:ro", "src:dst:rw,z", ...]
    for b in hc.get("Binds") or []:
        parts = str(b).split(":")
        src = parts[0]
        if not _bind_source_allowed(src):
            return False, f"bind mount not allowed: {b!r}"
        # T1/T2: enforce mount MODE, not just the source path. A host path may
        # be bound rw only if it is under an ALLOWED_RW_PREFIXES prefix; every
        # other allowed host path (the source tree) must be :ro.
        opts = parts[2] if len(parts) >= 3 else ""
        if src.startswith("/") and not _bind_is_readonly(opts) \
                and not _rw_host_path_allowed(src):
            return False, (
                f"read-write bind of {src!r} denied — source-tree binds must be "
                f":ro; only {ALLOWED_RW_PREFIXES} may be mounted rw"
            )

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
            if m.get("Source") and m.get("Source") not in ALLOWED_VOLUMES:
                return False, f"volume not allowed: {m.get('Source')!r}"
            # A named volume may be mounted rw only if allowlisted for writes.
            if m.get("Source") and not m.get("ReadOnly") \
                    and ALLOWED_RW_VOLUMES and m.get("Source") not in ALLOWED_RW_VOLUMES:
                return False, f"read-write volume {m.get('Source')!r} denied"
        elif mtype:
            return False, f"mount type not allowed: {mtype}"

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


BROKER_TOOL_MEM = _parse_size(os.environ.get("BROKER_TOOL_MEM_BYTES", ""), 2 * 1024**3)
# Defensive parse: a non-integer (e.g. "512m") must not crash the broker at import,
# which would leave recon unable to spawn ANY tool container.
BROKER_TOOL_PIDS = max(0, _parse_int(os.environ.get("BROKER_TOOL_PIDS", "0"), 0))  # 0 = don't set


def inject_limits(cfg: dict) -> dict:
    """Add HostConfig.Memory (and optionally PidsLimit) if absent or larger than
    our cap — respect a lower explicit value. Mutates and returns cfg."""
    hc = cfg.get("HostConfig")
    if not isinstance(hc, dict):
        hc = {}
        cfg["HostConfig"] = hc
    if BROKER_TOOL_MEM > 0:
        cur = hc.get("Memory") or 0
        if cur == 0 or cur > BROKER_TOOL_MEM:
            hc["Memory"] = BROKER_TOOL_MEM
    if BROKER_TOOL_PIDS > 0:
        cur = hc.get("PidsLimit") or 0
        if cur == 0 or cur > BROKER_TOOL_PIDS:
            hc["PidsLimit"] = BROKER_TOOL_PIDS
    return cfg


def validate_pull(path: str) -> tuple[bool, str]:
    """Validate docker pull (POST /images/create?fromImage=...&tag=...)."""
    # Docker percent-encodes repository separators (for example
    # docker.io%2Fprojectdiscovery%2Fnuclei).  parse_qs performs the required
    # decoding before the value is compared with the allowlist.
    params = parse_qs(urlsplit(path).query, keep_blank_values=True)
    from_image = params.get("fromImage", [""])[0]
    tag = params.get("tag", [""])[0]
    image = f"{from_image}:{tag}" if tag else from_image
    if _image_allowed(image) or _image_allowed(from_image):
        return True, "ok"
    return False, f"pull of non-allowlisted image denied: {image!r}"


# --------------------------------------------------------------------------
# HTTP plumbing
# --------------------------------------------------------------------------
async def _read_headers(reader: asyncio.StreamReader) -> tuple[bytes, str, dict]:
    """Read request line + headers. Returns (raw_head_bytes, request_line, headers)."""
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = await reader.read(1)
        if not chunk:
            break
        head += chunk
        if len(head) > 1024 * 1024:
            raise ValueError("header too large")
    if not head:
        return b"", "", {}
    head_text = head.split(b"\r\n\r\n", 1)[0].decode("latin1")
    lines = head_text.split("\r\n")
    request_line = lines[0] if lines else ""
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return head, request_line, headers


def _deny(reason: str) -> bytes:
    body = json.dumps({"message": f"denied by docker-broker: {reason}"}).encode()
    return (
        b"HTTP/1.1 403 Forbidden\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"Connection: close\r\n\r\n" + body
    )


async def _pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter):
    try:
        while True:
            data = await src.read(65536)
            if not data:
                break
            dst.write(data)
            await dst.drain()
    except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
        pass
    finally:
        try:
            dst.write_eof()
        except Exception:
            pass


async def handle_client(client_reader, client_writer):
    """Handle one Docker-API request. Connects to upstream LAZILY — only after a
    request is allowed — so a denied request never touches the real daemon at all
    (not even a connection)."""
    up_writer = None
    try:
        head, request_line, headers = await _read_headers(client_reader)
        if not request_line:
            return
        parts = request_line.split(" ")
        method = parts[0] if parts else ""
        path = parts[1] if len(parts) > 1 else ""
        path_only = _normalize_path(path)  # canonical form for create/hijack/pull matching

        def _reject(reason: str):
            client_writer.write(_deny(reason))

        # ---- hijack endpoints: forward headers, then raw bidirectional pipe ----
        if _HIJACK_RE.match(path_only):
            up_reader, up_writer = await asyncio.open_unix_connection(UPSTREAM_SOCK)
            up_writer.write(head)
            await up_writer.drain()
            await asyncio.gather(_pipe(client_reader, up_writer), _pipe(up_reader, client_writer))
            return

        # ---- read body (Content-Length) for validation/forwarding ----
        body = b""
        body_modified = False   # set when we rewrite the create body (Part 4d)
        clen = int(headers.get("content-length", "0") or "0")
        if clen > 8 * 1024 * 1024:  # create configs are tiny; cap to avoid a memory DoS
            _reject("request body too large")
            await client_writer.drain()
            return
        while len(body) < clen:
            chunk = await client_reader.read(clen - len(body))
            if not chunk:
                break
            body += chunk

        # ---- validate POST /containers/create (deny = no upstream contact) ----
        if method == "POST" and _CREATE_RE.match(path_only):
            try:
                cfg = json.loads(body or b"{}")
            except Exception as e:
                _reject(f"unparseable create body: {e}")
                await client_writer.drain()
                return
            ok, reason = validate_create(cfg)
            if not ok:
                _log(f"DENY create: {reason} (image={cfg.get('Image')!r})")
                _reject(reason)
                await client_writer.drain()
                return
            # Memory governor (Part 4d): inject the hard mem cap, then re-serialize
            # the body (Content-Length is corrected in the head rebuild below).
            inject_limits(cfg)
            body = json.dumps(cfg).encode("utf-8")
            body_modified = True
            _log(f"ALLOW create image={cfg.get('Image')!r} mem={cfg.get('HostConfig', {}).get('Memory')}")

        # ---- validate docker pull (deny = no upstream contact) ----
        if method == "POST" and _IMAGES_CREATE_RE.match(path_only):
            ok, reason = validate_pull(path)
            if not ok:
                _log(f"DENY pull: {reason}")
                _reject(reason)
                await client_writer.drain()
                return

        # ---- allowed: NOW connect upstream and forward ----
        # rebuild head with Connection: close to avoid keep-alive request smuggling.
        # If we rewrote the body (Part 4d), also drop the stale Content-Length and
        # set the correct one — a mismatch would hang or corrupt the upstream call.
        head_text = head.split(b"\r\n\r\n", 1)[0].decode("latin1")
        head_lines = [ln for ln in head_text.split("\r\n")
                      if not ln.lower().startswith("connection:")
                      and not (body_modified and (ln.lower().startswith("content-length:")
                                                  or ln.lower().startswith("transfer-encoding:")))]
        head_lines.append("Connection: close")
        if body_modified:
            # We send a concrete Content-Length, so any prior Transfer-Encoding
            # (dropped above) must not coexist with it.
            head_lines.append(f"Content-Length: {len(body)}")
        new_head = ("\r\n".join(head_lines) + "\r\n\r\n").encode("latin1")
        up_reader, up_writer = await asyncio.open_unix_connection(UPSTREAM_SOCK)
        up_writer.write(new_head + body)
        await up_writer.drain()

        # relay response (possibly chunked/streamed) until upstream closes
        await _pipe(up_reader, client_writer)
    except (ConnectionResetError, BrokenPipeError):
        pass
    except Exception as e:
        _log(f"error: {e}")
    finally:
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

    server = await asyncio.start_unix_server(handle_client, path=LISTEN_SOCK)
    try:
        os.chmod(LISTEN_SOCK, 0o660)
    except Exception:
        pass
    _log(f"listening on {LISTEN_SOCK} -> upstream {UPSTREAM_SOCK}")
    _log(f"allowed images: {sorted(ALLOWED_IMAGES)}")
    _log(f"allowed bind prefixes: {ALLOWED_BIND_PREFIXES}; volumes: {sorted(ALLOWED_VOLUMES)}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
