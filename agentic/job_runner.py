"""
Background job runner for long-running tool calls.

JobRegistry holds asyncio Tasks keyed by job_id (uuid4 hex). Each job's stdout
is tee'd to /workspace/<projectId>/jobs/<job_id>.log and metadata sits beside
it as <job_id>.meta.json.

Lifecycle:
    - spawn(): creates meta + log, kicks off asyncio.create_task(_run).
    - _run(): calls a caller-supplied `runner(tool_name, args, append_log)`
      coroutine which executes the tool and appends to the log. On completion
      flips status, writes final meta, emits a job_update WS event.
    - On agent process restart: in-memory state is gone, so recover_on_boot()
      flips any "running" meta on disk to "interrupted".

The 5 fs_*-shaped tools (job_spawn / status / wait / cancel / list) live in
tools.py's in-process dispatch and route directly to this module.

The jobs/ folder is not the agent's own: every Kali sandbox that mounts the
project writes it as root. So no job file is ever opened by path. Each access
walks root -> project -> jobs/ by descriptor without following a link, touches
only regular files, reads a bounded amount, and writes by O_EXCL create or by a
rename within the folder (STRIDE T3, I6, D15).
"""
from __future__ import annotations

import asyncio
import collections
import contextlib
import contextvars
import errno
import io
import json
import logging
import os
import re
import stat
import time
import uuid
from dataclasses import dataclass, field, fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Iterator, Optional

logger = logging.getLogger(__name__)

WORKSPACE_ROOT = Path(os.environ.get("WORKSPACE_ROOT", "/workspace"))

_META_SUFFIX = ".meta.json"
_LOG_SUFFIX = ".log"
# Far above any record the agent writes (_meta_record keeps its own under it), far
# below what a sparse file planted at a meta name could make a read allocate.
META_MAX_BYTES = 64 * 1024
# The tail status() returns: its last lines, from at most this much of the log's end.
LOG_TAIL_MAX_BYTES = 64 * 1024
# The records list() reads from disk, newest first. The agent's own ids
# (uuid4().hex) are read before any other name, so a flood of planted names
# cannot push a real job out; at most _SCAN_MAX_NAMES names are looked at.
LIST_MAX_DISK_JOBS = 500
_SCAN_MAX_NAMES = 1_000_000
# Boot reads at most this many records per project (the agent's own ids first):
# a crash leaves its running jobs among the newest, and a flood cannot hold the boot.
_BOOT_MAX_PER_PROJECT = 20_000
_OWN_ID_RE = re.compile(r"[0-9a-f]{32}")
# sandbox_contract.USER_ID_RE, without the import: a person id as the contract allows it.
_OWNER_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
# spawn() names jobs uuid4().hex; a disk record or an id the model typed into
# job_status is held to the same single safe path component.
_JOB_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}")

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
# O_NONBLOCK: a FIFO swapped in after the lstat must not hang the open (and with
# it the event loop and the boot). O_NOCTTY: a device must never become our tty.
_FILE_FLAGS = os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC
# What these opens answer for a link (ELOOP; ENOTDIR with O_DIRECTORY, as for any
# non-folder) or for a pipe with no reader opened to write (ENXIO).
_LINK_ERRNOS = (errno.ELOOP, errno.ENOTDIR, errno.ENXIO)


class JobFileRefused(Exception):
    """A job-store entry that is not one the store wrote: a link (in the file or a
    folder above it), a pipe, a device, a folder, an oversized record, or a name
    outside the store's rules. It is skipped, never followed or read."""


def valid_project_id(project_id) -> bool:
    """One path component that is not a dot entry: workspace_fs._validate_project_id's
    rule, as a predicate."""
    return (isinstance(project_id, str) and 0 < len(project_id) <= 255
            and not project_id.startswith(".")
            and not any(c in project_id for c in "/\\\x00"))


def valid_job_id(job_id) -> bool:
    return isinstance(job_id, str) and _JOB_ID_RE.fullmatch(job_id) is not None


# Each refused entry is logged once (the drawer polls, so a planted entry would
# otherwise log on every poll); the entries remembered are a bounded LRU, and the
# lines are rate limited: past _REFUSAL_LINES_PER_MINUTE the rest are counted and
# summarized when the next minute opens. A flood never silences the log for good.
_REFUSALS_LOGGED: "collections.OrderedDict[tuple, None]" = collections.OrderedDict()
_REFUSALS_LOGGED_MAX = 10_000
_REFUSAL_LINES_PER_MINUTE = 50
_refusal_window = {"start": 0.0, "lines": 0, "suppressed": 0}


def note_refusal(project_id: str, name: str, exc: BaseException) -> None:
    key = (project_id, name)
    if key in _REFUSALS_LOGGED:
        _REFUSALS_LOGGED.move_to_end(key)
        return
    _REFUSALS_LOGGED[key] = None
    while len(_REFUSALS_LOGGED) > _REFUSALS_LOGGED_MAX:
        _REFUSALS_LOGGED.popitem(last=False)
    now, window = time.monotonic(), _refusal_window
    if now - window["start"] >= 60:
        if window["suppressed"]:
            logger.warning("[jobs] %d more refused job-store entries in the last minute were "
                           "not logged one by one", window["suppressed"])
        window.update(start=now, lines=0, suppressed=0)
    if window["lines"] >= _REFUSAL_LINES_PER_MINUTE:
        window["suppressed"] += 1
        return
    window["lines"] += 1
    logger.warning("[jobs] refused %r in project %r: %s", name, project_id, exc)


def _open_subdir(name: str, dir_fd: int, create: bool) -> int:
    try:
        return os.open(name, _DIR_FLAGS, dir_fd=dir_fd)
    except FileNotFoundError:
        if not create:
            raise
    except OSError as exc:
        if exc.errno in _LINK_ERRNOS:
            raise JobFileRefused(f"{name!r} is not a plain folder") from None
        raise
    with contextlib.suppress(FileExistsError):
        os.mkdir(name, 0o777, dir_fd=dir_fd)
    try:
        return os.open(name, _DIR_FLAGS, dir_fd=dir_fd)
    except OSError as exc:
        if exc.errno in _LINK_ERRNOS:
            raise JobFileRefused(f"{name!r} is not a plain folder") from None
        raise


def _open_jobs_dir(project_id: str, *, create: bool = False, root=None) -> int:
    """A descriptor on <root>/<project>/jobs. The root is the agent's own mount and
    is opened as configured; the project folder and jobs/ are entered only when they
    are real folders, so a jobs/ a sandbox swapped for a link is refused, never
    followed. FileNotFoundError when it does not exist and `create` is false."""
    if not valid_project_id(project_id):
        raise JobFileRefused(f"invalid project id {project_id!r}")
    base = Path(root) if root is not None else WORKSPACE_ROOT
    if create:
        base.mkdir(parents=True, exist_ok=True)
    root_fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        project_fd = _open_subdir(project_id, root_fd, create)
    finally:
        os.close(root_fd)
    try:
        return _open_subdir("jobs", project_fd, create)
    finally:
        os.close(project_fd)


@contextlib.contextmanager
def _jobs_dir(project_id: str, *, create: bool = False, root=None) -> Iterator[int]:
    fd = _open_jobs_dir(project_id, create=create, root=root)
    try:
        yield fd
    finally:
        os.close(fd)


def _open_regular(dir_fd: int, name: str, flags: int) -> tuple[int, os.stat_result]:
    """Open `name` in the jobs folder only if it is a regular file. The lstat keeps
    a pipe or a device from being opened at all; the fstat checks what was opened."""
    st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    if not stat.S_ISREG(st.st_mode):
        raise JobFileRefused(f"{name!r} is not a regular file")
    try:
        fd = os.open(name, flags | _FILE_FLAGS, dir_fd=dir_fd)
    except OSError as exc:
        if exc.errno in _LINK_ERRNOS:
            raise JobFileRefused(f"{name!r} is not a regular file") from None
        raise
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise JobFileRefused(f"{name!r} is not a regular file")
    except BaseException:
        os.close(fd)
        raise
    return fd, st


def _read_at_most(fd: int, offset: int, limit: int) -> bytes:
    parts, remaining = [], max(0, limit)
    while remaining > 0:
        chunk = os.pread(fd, min(remaining, 1 << 20), offset)
        if not chunk:
            break
        parts.append(chunk)
        offset += len(chunk)
        remaining -= len(chunk)
    return b"".join(parts)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view):]


def _read_meta_at(dir_fd: int, name: str) -> dict:
    """A job record, bounded. JobFileRefused for anything but a regular file under
    META_MAX_BYTES; ValueError for one that is not a JSON object."""
    fd, st = _open_regular(dir_fd, name, os.O_RDONLY)
    try:
        if st.st_size > META_MAX_BYTES:
            raise JobFileRefused(f"{name!r} is larger than {META_MAX_BYTES} bytes")
        raw = _read_at_most(fd, 0, META_MAX_BYTES + 1)
    finally:
        os.close(fd)
    if len(raw) > META_MAX_BYTES:
        raise JobFileRefused(f"{name!r} is larger than {META_MAX_BYTES} bytes")
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("job record is not a JSON object")
    return data


def _create_file(dir_fd: int, name: str, *, append: bool = False) -> int:
    """A new file, never an existing entry: O_EXCL fails on a link planted there."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | (os.O_APPEND if append else 0)
    return os.open(name, flags | _FILE_FLAGS, 0o666, dir_fd=dir_fd)


def _replace_file(dir_fd: int, name: str, data: bytes) -> None:
    """Write `name` whole through a fresh file renamed over it in the same folder.
    What sits at `name` is never opened, so a link planted there is replaced, not
    written through, and a reader never sees half a record."""
    tmp = f".{name}.{uuid.uuid4().hex[:12]}.tmp"
    fd = _create_file(dir_fd, tmp)
    try:
        try:
            _write_all(fd, data)
        finally:
            os.close(fd)
        os.replace(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp, dir_fd=dir_fd)
        raise


def _append_file(dir_fd: int, name: str, data: bytes) -> None:
    try:
        fd, _ = _open_regular(dir_fd, name, os.O_WRONLY | os.O_APPEND)
    except FileNotFoundError:
        # Deleted under a running job: start it again, as a new file only.
        fd = _create_file(dir_fd, name, append=True)
    try:
        _write_all(fd, data)
    finally:
        os.close(fd)


def read_log(project_id: str, job_id: str, offset: int, limit: int, *, root=None) -> bytes:
    """Up to `limit` bytes of a job's log from byte `offset`. FileNotFoundError
    when there is no log; JobFileRefused when the entry, or a folder above it, is
    not what the job store writes."""
    if not valid_job_id(job_id):
        raise JobFileRefused(f"invalid job id {job_id!r}")
    with _jobs_dir(project_id, root=root) as dir_fd:
        fd, _ = _open_regular(dir_fd, f"{job_id}{_LOG_SUFFIX}", os.O_RDONLY)
        try:
            return _read_at_most(fd, max(0, int(offset)), limit)
        finally:
            os.close(fd)


def _read_log_end(project_id: str, job_id: str, max_bytes: int) -> tuple[int, bytes]:
    """(start offset, bytes) of the last `max_bytes` of a job's log."""
    if not valid_job_id(job_id):
        raise JobFileRefused(f"invalid job id {job_id!r}")
    with _jobs_dir(project_id) as dir_fd:
        fd, st = _open_regular(dir_fd, f"{job_id}{_LOG_SUFFIX}", os.O_RDONLY)
        try:
            start = max(0, st.st_size - max_bytes)
            return start, _read_at_most(fd, start, max_bytes)
        finally:
            os.close(fd)


#: Every person's sandbox jobs together, whatever each person's own cap: each still holds
#: a task and a log in the agent, which every tenant shares.
SANDBOX_JOBS_MAX = 256


def owner_of(row) -> Optional[str]:
    """The person a job row names as its owner, or None: no owner, or a value that is not a
    person id (a record from before owners were kept, or one a sandbox rewrote)."""
    owner = row.get("owner_user") if isinstance(row, dict) else None
    return owner if isinstance(owner, str) and _OWNER_RE.fullmatch(owner) else None


def owned_by_another(row, person: Optional[str]) -> bool:
    """True when the row names an owner other than ``person``. A row with no owner stays
    the project's, as before owners were kept. A sandbox can rewrite a record on disk, but
    only to name someone or no one: that never shows a job to anyone the project did not."""
    owner = owner_of(row)
    return owner is not None and owner != person


def _governed_max_jobs() -> Optional[int]:
    """Concurrent-background-job ceiling byte-budgeted to available RAM, or None to
    not cap (governor disabled / unavailable). Each job is a real subprocess
    (~measured envelope), so this uses the byte-budget model (not ratio) — safe on
    small hosts. Generous base (MAX_BACKGROUND_JOBS, default 16). Fail-open."""
    try:
        from graph_db import resource_governor as rg
    except Exception:
        try:
            import resource_governor as rg
        except Exception:
            return None
    try:
        if not rg.governor_enabled():
            return None
        base = int(os.environ.get("MAX_BACKGROUND_JOBS", "16") or "16")
        env = rg.envelope("background_job_envelope_bytes")
        frac = rg._env_float("AGENT_MEM_BUDGET_FRACTION", 0.5)
        return rg.scaled_cap(base, env, frac, 1)
    except Exception:
        return None


@dataclass
class JobHandle:
    job_id: str
    project_id: str
    tool_name: str
    args: dict
    label: Optional[str]
    status: str  # running|done|failed|cancelled|interrupted
    started_at: str
    ended_at: Optional[str] = None
    exit_code: Optional[int] = None
    output_path: str = ""
    error: Optional[str] = None
    # Set by long in-process jobs through report_progress(); meta files written
    # before this field existed simply lack it.
    progress: Optional[dict] = None
    # False for workspace upload/import jobs: they run in-process and are capped
    # by WORKSPACE_IMPORT_MAX_JOBS instead of taking a governed subprocess slot.
    counts_toward_cap: bool = True
    # The person (and view) whose chat or MCP token started the job. Only the copy in this
    # process decides who may see or stop it: the record on disk sits in a folder every
    # sandbox that mounts the project writes.
    owner_user: Optional[str] = None
    owner_view: Optional[str] = None
    # True when the job's tool runs in the owner's Kali sandbox: its process uses that
    # sandbox's memory, so it is capped per person rather than against the agent's own.
    in_sandbox: bool = False
    task: Optional[asyncio.Task] = field(default=None, repr=False)

    def to_dict(self) -> dict:
        # Build dict explicitly: asdict() deep-copies every field, which
        # blows up on the live asyncio.Task before we can pop it.
        return {f.name: getattr(self, f.name) for f in fields(self) if f.name != "task"}


def _meta_record(handle: JobHandle) -> bytes:
    data = handle.to_dict()
    raw = json.dumps(data, indent=2, default=str).encode("utf-8")
    if len(raw) <= META_MAX_BYTES:
        return raw
    # A huge command or code argument. A reader refuses a record over the cap, so the
    # record drops the arguments (the log keeps the output) rather than become unreadable.
    data["args"] = {"omitted": f"the arguments are too large for the job record ({len(raw)} bytes)"}
    if isinstance(data.get("error"), str):
        data["error"] = data["error"][:4096]
    if isinstance(data.get("label"), str):
        data["label"] = data["label"][:200]
    return json.dumps(data, indent=2, default=str).encode("utf-8")


# Runner callable contract:
#   async def runner(tool_name: str, args: dict, append_log: Callable[[str], Awaitable[None]]) -> dict
# Must return {"success": bool, "output": str|None, "error": str|None}.
RunnerFn = Callable[[str, dict, Callable[[str], Awaitable[None]]], Awaitable[dict]]

# (registry, handle) of the job whose runner is executing in this task, so a
# runner can report progress without a change to the runner contract above.
_current_job: contextvars.ContextVar = contextvars.ContextVar("current_job", default=None)
_PROGRESS_META_INTERVAL_SEC = 1.0


def current_job_id() -> Optional[str]:
    """The id of the job whose runner is executing in this task, or None."""
    current = _current_job.get()
    return current[1].job_id if current else None


async def report_progress(progress: dict, *, now: Callable[[], float] = time.monotonic) -> None:
    """Record the running job's progress. Meta and the job_update event are
    throttled to one per second; the final meta write always carries the last
    value. Outside a job this does nothing."""
    current = _current_job.get()
    if current is None:
        return
    registry, handle = current
    handle.progress = dict(progress)
    t = now()
    last = registry._progress_written.get(handle.job_id)
    if last is not None and t - last < _PROGRESS_META_INTERVAL_SEC:
        return
    registry._progress_written[handle.job_id] = t
    registry._write_meta(handle)
    await registry._notify({
        "type": "job_update",
        "project_id": handle.project_id,
        "job_id": handle.job_id,
        "status": "running",
        "progress": handle.progress,
    })


def _record_names(dir_fd: int, skip: set, limit: int) -> list[str]:
    """The record names in a jobs/ folder to read, at most `limit`: the agent's own
    ids (uuid4().hex) first, newest first, then the other valid names, newest
    first. Only the names are listed (bounded by _SCAN_MAX_NAMES); an entry is
    stat'ed only while there is room for it."""
    own, other = [], []
    with os.scandir(dir_fd) as entries:
        for i, entry in enumerate(entries):
            if i >= _SCAN_MAX_NAMES:
                break
            name = entry.name
            if not name.endswith(_META_SUFFIX):
                continue
            jid = name[:-len(_META_SUFFIX)]
            if jid in skip or not valid_job_id(jid):
                continue
            (own if _OWN_ID_RE.fullmatch(jid) else other).append(name)

    def newest(names: list[str]) -> list[str]:
        dated = []
        for name in names:
            with contextlib.suppress(OSError):
                dated.append((os.stat(name, dir_fd=dir_fd, follow_symlinks=False).st_mtime, name))
        dated.sort(reverse=True)
        return [name for _mtime, name in dated]

    picked = newest(own)[:limit]
    if len(picked) < limit and other:
        # Other names are legacy or planted: only a bounded sample is dated.
        picked += newest(other[:limit * 4])[:limit - len(picked)]
    return picked


def _listing_names(dir_fd: int, skip: set, known: set, limit: int) -> list[str]:
    """The record names a listing reads, at most `limit`, and never a full scan of
    the folder: first the agent's own records (`known`, the ids this process
    recovered at boot), each stat'ed by name, newest first; then a sample of the
    first limit*4 other names in directory order, newest first. A 32-hex name is
    no proof of a real job (a sandbox can plant any number), the registry is."""
    first = []
    for jid in known:
        if jid in skip:
            continue
        with contextlib.suppress(OSError):
            st = os.stat(f"{jid}{_META_SUFFIX}", dir_fd=dir_fd, follow_symlinks=False)
            first.append((st.st_mtime, f"{jid}{_META_SUFFIX}"))
    first.sort(reverse=True)
    picked = [name for _mtime, name in first[:limit]]
    if len(picked) < limit:
        sample = []
        with os.scandir(dir_fd) as entries:
            for entry in entries:
                name = entry.name
                if not name.endswith(_META_SUFFIX):
                    continue
                jid = name[:-len(_META_SUFFIX)]
                if jid in skip or jid in known or not valid_job_id(jid):
                    continue
                with contextlib.suppress(OSError):
                    sample.append((entry.stat(follow_symlinks=False).st_mtime, name))
                if len(sample) >= limit * 4:
                    break
        sample.sort(reverse=True)
        picked += [name for _mtime, name in sample[:limit - len(picked)]]
    return picked


def _count_records(dir_fd: int) -> int:
    with os.scandir(dir_fd) as entries:
        return sum(1 for i, e in enumerate(entries)
                   if i < _SCAN_MAX_NAMES and e.name.endswith(_META_SUFFIX))


class JobRegistry:
    def __init__(self):
        self._jobs: dict[str, JobHandle] = {}
        self._lock = asyncio.Lock()
        self._ws_emit: Optional[Callable[[dict], Awaitable[None]]] = None
        self._progress_written: dict[str, float] = {}
        # project -> the job ids recover_on_boot read: the agent's own records,
        # which a listing reads before any other name in jobs/.
        self._recovered: dict[str, set] = {}

    def set_ws_emitter(self, fn: Optional[Callable[[dict], Awaitable[None]]]) -> None:
        """Register a coroutine to receive job_update events for the drawer."""
        self._ws_emit = fn

    # ---- job files ---------------------------------------------------------

    def _write_meta(self, handle: JobHandle) -> None:
        try:
            with _jobs_dir(handle.project_id, create=True) as dir_fd:
                _replace_file(dir_fd, f"{handle.job_id}{_META_SUFFIX}", _meta_record(handle))
        except Exception as e:
            logger.error(f"write_meta failed for {handle.job_id}: {e}")

    async def _notify(self, evt: dict) -> None:
        if not self._ws_emit:
            return
        try:
            await self._ws_emit(evt)
        except Exception as e:
            logger.warning(f"job_update emit failed: {e}")

    # ---- public API --------------------------------------------------------

    async def spawn(
        self,
        project_id: str,
        tool_name: str,
        args: dict,
        runner: RunnerFn,
        label: Optional[str] = None,
        counts_toward_cap: bool = True,
        owner_user: Optional[str] = None,
        owner_view: Optional[str] = None,
        in_sandbox: bool = False,
    ) -> dict:
        """Kick off a background tool execution. Returns synchronously.

        ``owner_user``/``owner_view``: who started it (a chat run's person, an MCP token's
        owner); only they see and stop it. ``in_sandbox``: its tool runs in that person's
        Kali sandbox, so it counts against their own cap, not every tenant's."""
        if not project_id:
            return {"error": "project_id required"}
        if not valid_project_id(project_id):
            return {"error": f"invalid project_id {project_id!r}", "code": "invalid_project_id"}
        # Memory governor (Part 3): cap concurrent background jobs to available RAM
        # (none existed before). Generous base, scaled down under pressure; the
        # agent container mem_limit is the hard backstop. Fail-open.
        cap = _governed_max_jobs() if counts_toward_cap else None
        workspace_cap = None
        if not counts_toward_cap:
            from workspace_import import limits as _ws_limits
            workspace_cap = _ws_limits.max_jobs()
        job_id = uuid.uuid4().hex
        started = datetime.now(timezone.utc).isoformat()
        log_name = f"{job_id}{_LOG_SUFFIX}"
        # Reported to the caller (and the sandbox sees it at the same path); the agent
        # itself never opens it by this path.
        log_path = WORKSPACE_ROOT / project_id / "jobs" / log_name

        handle = JobHandle(
            job_id=job_id,
            project_id=project_id,
            tool_name=tool_name,
            args=args or {},
            label=label,
            status="running",
            started_at=started,
            output_path=str(log_path),
            counts_toward_cap=counts_toward_cap,
            owner_user=owner_user if owner_of({"owner_user": owner_user}) else None,
            owner_view=owner_view if owner_view in ("own", "act_as") else None,
            in_sandbox=bool(in_sandbox and owner_of({"owner_user": owner_user})),
        )
        # Count-and-insert atomically under the lock so two concurrent spawns
        # can't both pass the cap and over-admit.
        async with self._lock:
            running = [h for h in self._jobs.values() if h.status == "running" and h.counts_toward_cap]
            if cap is not None and handle.in_sandbox:
                # Each person's sandbox carries its own jobs: one person's many scans must
                # not refuse everyone else's, as a count over every tenant would.
                mine = sum(1 for h in running if h.in_sandbox and h.owner_user == handle.owner_user)
                if mine >= cap:
                    return {"error": f"Too many background jobs running in your Kali sandbox "
                                     f"({mine}/{cap}); wait for one to end or cancel one.",
                            "limitType": "ram"}
                total = sum(1 for h in running if h.in_sandbox)
                if total >= SANDBOX_JOBS_MAX:
                    return {"error": f"Too many background jobs running ({total}/"
                                     f"{SANDBOX_JOBS_MAX}); retry shortly.", "limitType": "ram"}
            elif cap is not None:
                active = sum(1 for h in running if not h.in_sandbox)
                if active >= cap:
                    return {"error": f"Too many background jobs running ({active}/{cap}); "
                                     f"memory-limited, retry shortly.", "limitType": "ram"}
            if workspace_cap is not None:
                active = sum(1 for h in self._jobs.values()
                             if h.status == "running" and not h.counts_toward_cap)
                if active >= workspace_cap:
                    return {"error": f"Too many workspace uploads and imports running "
                                     f"({active}/{workspace_cap}); retry shortly.",
                            "limitType": "workspace"}
            self._jobs[job_id] = handle
        # Only after admission, so a rejected job leaves no file.
        try:
            with _jobs_dir(project_id, create=True) as dir_fd:
                os.close(_create_file(dir_fd, log_name))
        except Exception as exc:
            self._jobs.pop(job_id, None)
            if isinstance(exc, JobFileRefused):
                note_refusal(project_id, "jobs", exc)
                return {"error": "the project's jobs folder is not a plain folder of the "
                                 "workspace, so no job can be started in it",
                        "code": "job_store_refused"}
            logger.error(f"job {job_id} log create failed: {exc}")
            return {"error": "the job's log could not be created", "code": "job_store_error"}
        self._write_meta(handle)

        async def append_log(chunk: str) -> None:
            if chunk is None:
                return
            try:
                text = chunk if chunk.endswith("\n") else chunk + "\n"
                with _jobs_dir(project_id) as dir_fd:
                    _append_file(dir_fd, log_name, text.encode("utf-8", "replace"))
            except Exception as e:
                logger.error(f"job {job_id} log append failed: {e}")

        async def _run():
            _current_job.set((self, handle))
            try:
                result = await runner(tool_name, args or {}, append_log)
                if isinstance(result, dict) and result.get("success"):
                    handle.status = "done"
                    handle.exit_code = 0
                else:
                    handle.status = "failed"
                    handle.exit_code = 1
                    if isinstance(result, dict) and result.get("error"):
                        handle.error = str(result["error"])
                final = (result or {}).get("output") if isinstance(result, dict) else result
                if final:
                    txt = final if isinstance(final, str) else str(final)
                    await append_log("\n--- final ---\n")
                    await append_log(txt)
            except asyncio.CancelledError:
                handle.status = "cancelled"
                raise
            except Exception as e:
                handle.status = "failed"
                handle.error = str(e)
                logger.exception(f"job {job_id} crashed")
            finally:
                handle.ended_at = datetime.now(timezone.utc).isoformat()
                handle.task = None
                self._progress_written.pop(job_id, None)
                self._write_meta(handle)
                await self._notify({
                    "type": "job_update",
                    "project_id": project_id,
                    "job_id": job_id,
                    "status": handle.status,
                })

        handle.task = asyncio.create_task(_run())
        await self._notify({
            "type": "job_update",
            "project_id": project_id,
            "job_id": job_id,
            "status": "running",
        })
        return {"job_id": job_id, "output_path": str(log_path), "status": "running"}

    def status(self, project_id: str, job_id: str) -> dict:
        h = self._jobs.get(job_id)
        if not h or h.project_id != project_id:
            # The record on disk is the sandbox-writable copy: read only through the
            # store's checks. A bad id or project is a plain miss, never a path.
            if not valid_job_id(job_id) or not valid_project_id(project_id):
                return {"error": f"unknown job {job_id}"}
            name = f"{job_id}{_META_SUFFIX}"
            try:
                with _jobs_dir(project_id) as dir_fd:
                    data = _read_meta_at(dir_fd, name)
            except FileNotFoundError:
                return {"error": f"unknown job {job_id}"}
            except JobFileRefused as e:
                note_refusal(project_id, name, e)
                return {"error": f"meta unreadable: {e}"}
            except Exception as e:
                return {"error": f"meta unreadable: {e}"}
            data["size_bytes"] = self._log_size(project_id, job_id)
            data["tail"] = self._log_tail(project_id, job_id, 40)
            return data
        d = h.to_dict()
        d["size_bytes"] = self._log_size(project_id, job_id)
        d["tail"] = self._log_tail(project_id, job_id, 40)
        return d

    async def wait(self, project_id: str, job_id: str, timeout_sec: float = 30.0) -> dict:
        h = self._jobs.get(job_id)
        if not h or h.project_id != project_id or h.task is None:
            return self.status(project_id, job_id)
        try:
            await asyncio.wait_for(asyncio.shield(h.task), timeout=timeout_sec)
        except asyncio.TimeoutError:
            pass
        except Exception:
            pass
        return self.status(project_id, job_id)

    async def cancel(self, project_id: str, job_id: str) -> dict:
        h = self._jobs.get(job_id)
        if not h or h.project_id != project_id:
            return {"error": f"unknown job {job_id}"}
        if h.task and not h.task.done():
            h.task.cancel()
            try:
                await h.task
            except (asyncio.CancelledError, Exception):
                pass
            if h.status == "running":
                # Cancelled before its first step, so _run never ran to record it.
                h.status = "cancelled"
                h.ended_at = datetime.now(timezone.utc).isoformat()
                h.task = None
                self._write_meta(h)
                await self._notify({"type": "job_update", "project_id": project_id,
                                    "job_id": job_id, "status": "cancelled"})
        return self.status(project_id, job_id)

    async def cancel_sandbox_jobs(self, user_id: Optional[str] = None, *,
                                  timeout: float = 5.0) -> int:
        """Cancel the running jobs whose tool runs in a Kali sandbox: every person's, or
        ``user_id``'s alone. The emergency stop calls it before the sandboxes stop: a job
        whose sandbox is then gone must not be left to start its work again in a new one.
        Bounded: a job that does not end in ``timeout`` is left cancelling."""
        targets = [h for h in list(self._jobs.values())
                   if h.status == "running" and h.in_sandbox
                   and (user_id is None or h.owner_user == user_id)]
        if targets:
            await asyncio.wait([asyncio.ensure_future(self.cancel(h.project_id, h.job_id))
                                for h in targets], timeout=timeout)
        return len(targets)

    def list(self, project_id: str, active: Optional[bool] = None) -> list[dict]:
        rows = [h.to_dict() for h in self._jobs.values() if h.project_id == project_id]
        return self._with_disk_rows(project_id, rows, active)

    async def list_async(self, project_id: str, active: Optional[bool] = None) -> list[dict]:
        """list() with its disk part off the event loop (the drawer polls it). The
        live handles are read here, on the loop that changes them."""
        rows = [h.to_dict() for h in self._jobs.values() if h.project_id == project_id]
        return await asyncio.to_thread(self._with_disk_rows, project_id, rows, active)

    def _with_disk_rows(self, project_id: str, rows: list[dict], active: Optional[bool]) -> list[dict]:
        # Augment from disk so jobs survived across restarts are visible too.
        rows.extend(self._disk_rows(project_id, {r["job_id"] for r in rows}))
        if active is True:
            rows = [r for r in rows if r.get("status") == "running"]
        elif active is False:
            rows = [r for r in rows if r.get("status") != "running"]
        # str(): a record from disk may carry any JSON value here.
        rows.sort(key=lambda r: str(r.get("started_at") or ""), reverse=True)
        # Augment with on-disk size/tail snapshot
        for r in rows:
            jid = r.get("job_id")
            if jid:
                r["size_bytes"] = self._log_size(project_id, jid)
        return rows

    # ---- internals ---------------------------------------------------------

    def _disk_rows(self, project_id: str, skip: set) -> list[dict]:
        """The records in the project's jobs/ that are not live handles: regular
        files only, each bounded, at most LIST_MAX_DISK_JOBS of them, the agent's
        own ids first and then the newest."""
        if not valid_project_id(project_id):
            return []
        try:
            dir_fd = _open_jobs_dir(project_id)
        except JobFileRefused as e:
            note_refusal(project_id, "jobs", e)
            return []
        except Exception:
            return []
        rows = []
        try:
            known = self._recovered.get(project_id, set())
            for name in _listing_names(dir_fd, skip, known, LIST_MAX_DISK_JOBS):
                try:
                    rows.append(_read_meta_at(dir_fd, name))
                except JobFileRefused as e:
                    note_refusal(project_id, name, e)
                except Exception:
                    pass
        except Exception as e:
            logger.warning(f"job list of {project_id!r} failed: {e}")
        finally:
            os.close(dir_fd)
        return rows

    def _log_size(self, project_id: str, job_id: str) -> int:
        # lstat: the size of a link's target is not the job's to report.
        if not valid_job_id(job_id):
            return 0
        try:
            with _jobs_dir(project_id) as dir_fd:
                st = os.stat(f"{job_id}{_LOG_SUFFIX}", dir_fd=dir_fd, follow_symlinks=False)
            return st.st_size if stat.S_ISREG(st.st_mode) else 0
        except Exception:
            return 0

    def _log_tail(self, project_id: str, job_id: str, n_lines: int) -> str:
        try:
            start, raw = _read_log_end(project_id, job_id, LOG_TAIL_MAX_BYTES)
        except JobFileRefused as e:
            note_refusal(project_id, f"{job_id}{_LOG_SUFFIX}", e)
            return ""
        except Exception:
            return ""
        if start > 0:
            # The window may open mid-line: drop that partial line when a whole one follows.
            cut = raw.find(b"\n")
            if 0 <= cut < len(raw) - 1:
                raw = raw[cut + 1:]
        lines = io.StringIO(raw.decode("utf-8", "replace"), newline=None).readlines()
        return "".join(lines[-n_lines:])

    def recover_on_boot(self) -> None:
        """Flip any meta files still marked 'running' to 'interrupted'.

        Runs before the agent serves anything, over every project's jobs/, which
        any sandbox of that project writes. So an entry that is not a regular
        record of the store (a link, a pipe, a device, an oversized file, a jobs/
        that is a link) is skipped and logged, never opened through, read whole
        or written through; one bad entry never stops the boot."""
        try:
            root_fd = os.open(WORKSPACE_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        except FileNotFoundError:
            return
        except Exception as e:
            logger.warning(f"recover_on_boot scan failed: {e}")
            return
        refused = 0
        try:
            with os.scandir(root_fd) as projects:
                for entry in projects:
                    try:
                        if valid_project_id(entry.name) and entry.is_dir(follow_symlinks=False):
                            refused += self._recover_project(root_fd, entry.name)
                    except Exception as e:
                        logger.warning(f"recover_on_boot: project {entry.name!r} skipped: {e}")
        except Exception as e:
            logger.warning(f"recover_on_boot scan failed: {e}")
        finally:
            os.close(root_fd)
        if refused:
            logger.warning(f"recover_on_boot: skipped {refused} job entries that are not "
                           "regular records of the job store")

    def _recover_project(self, root_fd: int, project_id: str) -> int:
        """Recover one project's records; the number of entries refused."""
        refused = 0
        try:
            project_fd = os.open(project_id, _DIR_FLAGS, dir_fd=root_fd)
        except OSError:
            return 0
        try:
            try:
                dir_fd = _open_subdir("jobs", project_fd, create=False)
            except FileNotFoundError:
                return 0
            except JobFileRefused as e:
                note_refusal(project_id, "jobs", e)
                return 1
            try:
                # One summary line per project, not one per entry: a planted flood
                # must neither hold the boot nor fill the log.
                examples, bad, skipped = [], 0, 0
                try:
                    names = _record_names(dir_fd, set(), _BOOT_MAX_PER_PROJECT)
                    skipped = _count_records(dir_fd) - len(names)
                    recovered = self._recovered.setdefault(project_id, set())
                    for name in names:
                        try:
                            data = _read_meta_at(dir_fd, name)
                            recovered.add(name[:-len(_META_SUFFIX)])
                            if data.get("status") == "running":
                                data["status"] = "interrupted"
                                data["ended_at"] = datetime.now(timezone.utc).isoformat()
                                _replace_file(dir_fd, name,
                                              json.dumps(data, indent=2, default=str).encode("utf-8"))
                        except JobFileRefused as e:
                            refused += 1
                            if len(examples) < 5:
                                examples.append(f"{name!r} ({e})")
                        except FileNotFoundError:
                            pass
                        except Exception:
                            bad += 1
                except Exception as e:
                    logger.warning(f"recover_on_boot: jobs of {project_id!r} skipped: {e}")
                if refused or bad or skipped > 0:
                    logger.warning(
                        f"recover_on_boot: project {project_id!r}: {refused} entries refused (not "
                        f"regular records of the job store), {bad} unreadable records, "
                        f"{max(0, skipped)} not read past the {_BOOT_MAX_PER_PROJECT} per project"
                        + (f"; e.g. {', '.join(examples)}" if examples else ""))
            finally:
                os.close(dir_fd)
        finally:
            os.close(project_fd)
        return refused


# Module-level singleton
_registry: Optional[JobRegistry] = None


def get_registry() -> JobRegistry:
    global _registry
    if _registry is None:
        _registry = JobRegistry()
    return _registry


JOB_TOOL_NAMES = frozenset({
    "job_spawn", "job_status", "job_wait", "job_cancel", "job_list",
})
