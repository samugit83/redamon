"""Resumable chunked upload sessions for the workspace.

A request through the web app is capped at 60 MB (Next proxy, nginx), so a
folder, an archive or a big file arrives in 8 MiB chunks. Each session lives in
its own staging op dir (`up-<uploadId>/data.part` + `session.json`), holds a
disk reservation from creation to the end of its commit job, and is deleted
when it sits idle longer than WORKSPACE_UPLOAD_SESSION_IDLE_SEC.

The in-memory table is authoritative: the agent is one process, and no session
survives a restart (staging is swept at boot).
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import posixpath
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

import workspace_fs
from workspace_import import limits, staging
from workspace_import.errors import ImportFailure, map_os_error
from workspace_import.place import POLICIES

logger = logging.getLogger(__name__)

UPLOAD_ID_RE = re.compile(r"^[0-9a-f]{32}$")
SWEEP_INTERVAL_SEC = 300
KINDS = ("file", "folder", "archive")
MAX_SESSIONS_PER_PROJECT = 4
DATA_NAME = "data.part"
STATE_NAME = "session.json"


@dataclass
class Session:
    upload_id: str
    project_id: str
    dest_dir: str
    name: str
    size: int
    kind: str
    on_conflict: str
    op_dir: Path
    reservation: staging.Reservation
    received: int = 0
    created_at: float = 0.0
    updated_at: float = 0.0
    lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)

    @property
    def data_path(self) -> Path:
        return self.op_dir / DATA_NAME

    def public(self) -> dict:
        return {"uploadId": self.upload_id, "destDir": self.dest_dir, "name": self.name,
                "size": self.size, "kind": self.kind, "onConflict": self.on_conflict,
                "received": self.received}

    def save(self) -> None:
        state = dict(self.public(), projectId=self.project_id,
                     createdAt=self.created_at, updatedAt=self.updated_at)
        tmp = self.op_dir / (STATE_NAME + ".tmp")
        tmp.write_text(json.dumps(state), encoding="utf-8")
        os.replace(tmp, self.op_dir / STATE_NAME)


_sessions: dict[str, Session] = {}


def valid_name(name: str) -> bool:
    """The rules of workspace_fs.upload_for_project, plus 255 bytes."""
    return bool(name) and name.strip() == name and "/" not in name and "\\" not in name \
        and "\x00" not in name and name not in (".", "..") \
        and len(name.encode("utf-8", "surrogateescape")) <= 255


def _drop(session: Session) -> None:
    _sessions.pop(session.upload_id, None)
    session.reservation.release()
    staging.remove_tree(session.op_dir)


def sweep_idle(now: Optional[float] = None) -> int:
    t = time.time() if now is None else now
    idle = limits.session_idle_sec()
    swept = 0
    for s in list(_sessions.values()):
        if t - s.updated_at > idle:
            _drop(s)
            swept += 1
            logger.info(f"[workspace-import] swept idle upload session project={s.project_id} upload={s.upload_id}")
    return swept


async def sweep_idle_forever(interval: float = SWEEP_INTERVAL_SEC, sleep=asyncio.sleep) -> None:
    """Sweep idle sessions on a timer. A tab that died mid-upload sends no
    DELETE, and the next create(), which also sweeps, may not come for days;
    meanwhile the session holds its partial file and its disk reservation."""
    while True:
        await sleep(interval)
        try:
            sweep_idle()
        except Exception as e:
            logger.warning(f"[workspace-import] idle upload session sweep failed: {type(e).__name__}")


def forget_project(project_id: str) -> None:
    """Drop the project's sessions from the table (its staging is swept by the caller)."""
    for s in [s for s in _sessions.values() if s.project_id == project_id]:
        _sessions.pop(s.upload_id, None)
        s.reservation.release()


def create(project_id: str, dest_dir: str, name: str, size, kind: str, on_conflict: str,
           *, now: Callable[[], float] = time.time, entries: Optional[int] = None) -> dict:
    try:
        workspace_fs._validate_project_id(project_id)
    except ValueError:
        raise ImportFailure("invalid_request") from None
    t = now()
    sweep_idle(t)
    if kind not in KINDS or on_conflict not in POLICIES or not valid_name(name):
        raise ImportFailure("invalid_request")
    if not isinstance(size, int) or isinstance(size, bool) or size < 1:
        raise ImportFailure("invalid_request")
    if size > limits.max_bytes():
        raise ImportFailure("too_large")
    if entries is not None and (not isinstance(entries, int) or isinstance(entries, bool) or entries < 0):
        raise ImportFailure("invalid_request")
    # Refused before the upload, not after gigabytes of it; extraction still
    # counts the real entries.
    if kind == "folder" and entries is not None and entries > limits.max_entries():
        raise ImportFailure("too_many_entries")
    try:
        dest = workspace_fs.resolve_for_project(project_id, dest_dir)
    except ValueError:
        raise ImportFailure("invalid_request") from None
    if not dest.is_dir():
        raise ImportFailure("destination_missing")
    workspace_fs.check_not_busy(project_id, posixpath.join(dest_dir or ".", name))
    if sum(1 for s in _sessions.values() if s.project_id == project_id) >= MAX_SESSIONS_PER_PROJECT:
        raise ImportFailure("too_many_uploads")
    op = staging.new_op_dir(project_id, "up")
    upload_id = op.name[len("up-"):]
    try:
        # An archive needs room for itself and for what it extracts to.
        reservation = staging.reserve(op.name, size if kind == "file" else size * 2, project_id=project_id)
    except ImportFailure:
        staging.remove_tree(op)
        raise
    session = Session(upload_id=upload_id, project_id=project_id, dest_dir=dest_dir or ".", name=name,
                      size=size, kind=kind, on_conflict=on_conflict, op_dir=op, reservation=reservation,
                      created_at=t, updated_at=t)
    try:
        fd = os.open(session.data_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o666)
        os.close(fd)
        session.save()
    except OSError as e:
        reservation.release()
        staging.remove_tree(op)
        raise (map_os_error(e) or ImportFailure("internal_error")) from None
    _sessions[upload_id] = session
    return {"uploadId": upload_id, "chunkSize": limits.chunk_bytes(), "maxBytes": limits.max_bytes()}


def get(project_id: str, upload_id: str) -> Session:
    s = _sessions.get(upload_id) if UPLOAD_ID_RE.match(upload_id or "") else None
    if s is None or s.project_id != project_id:
        raise ImportFailure("session_not_found")
    return s


def _append(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
    finally:
        os.close(fd)


async def write_chunk(project_id: str, upload_id: str, offset: int, data: bytes,
                      *, now: Callable[[], float] = time.time) -> int:
    """Append `data` at `offset`. A retried chunk the session already has is
    acknowledged without writing; anything else out of order is refused with
    the offset the client should resume from."""
    session = get(project_id, upload_id)
    if len(data) > limits.chunk_bytes():
        raise ImportFailure("chunk_too_large")
    async with session.lock:
        if session.upload_id not in _sessions:  # swept or aborted while we waited
            raise ImportFailure("session_not_found")
        if offset < 0:
            raise ImportFailure("offset_mismatch", detail=str(session.received))
        if offset + len(data) <= session.received and offset < session.received:
            return session.received
        if offset != session.received:
            raise ImportFailure("offset_mismatch", detail=str(session.received))
        if session.received + len(data) > session.size:
            raise ImportFailure("chunk_overflow")
        if data:
            try:
                await asyncio.to_thread(_append, session.data_path, data)
            except OSError as e:
                raise (map_os_error(e) or ImportFailure("internal_error")) from None
        session.received += len(data)
        session.updated_at = now()
        try:
            session.save()
        except OSError:
            pass
        return session.received


def abort(project_id: str, upload_id: str) -> bool:
    """Delete a session. An unknown session is already gone, which is success."""
    s = _sessions.get(upload_id)
    if s is None or s.project_id != project_id:
        return False
    _drop(s)
    return True


def restore(session: Session) -> None:
    """Put back a session whose commit could not start, so the client can retry."""
    _sessions[session.upload_id] = session


def take_for_commit(project_id: str, upload_id: str) -> Session:
    """Hand a complete session to its commit job: it leaves the table, and the
    job owns its op dir and reservation from here on."""
    s = get(project_id, upload_id)
    if s.received != s.size:
        raise ImportFailure("session_incomplete")
    _sessions.pop(upload_id, None)
    return s
