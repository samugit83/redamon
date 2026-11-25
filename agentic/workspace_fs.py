"""
Workspace filesystem primitives.

24 fs_* tools that operate inside /workspace/<projectId>/. Every user-supplied
path goes through _resolve_safe() which rejects .. traversal and symlink
escapes. project_id is pulled from the current_project_id contextvar (set by
the agent runtime) - tools refuse to run without it.

All functions are async coroutines that return a single string for direct LLM
consumption. The DISPATCH map at the bottom is what tools.py wires into the
in-process executor.
"""
from __future__ import annotations

import asyncio
import base64
import codecs
import collections
import contextlib
import contextvars
import difflib
import errno
import fnmatch
import gzip
import hashlib
import io
import json
import logging
import mimetypes
import os
import posixpath
import re
import shutil
import stat as statlib
import subprocess
import sys
import tarfile
import threading
import time
import urllib.parse
import uuid
import weakref
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterator, Optional

from workspace_import import busy as _busy
from workspace_import.errors import ImportFailure
from workspace_import import provenance as _provenance

logger = logging.getLogger(__name__)


def _int_env(name: str, default: int) -> int:
    """Read a positive-int env var; fall back to default on unset/invalid so a
    typo can never disable a safety cap (D10)."""
    try:
        v = int(str(os.environ.get(name, "")).strip())
        return v if v > 0 else default
    except (TypeError, ValueError):
        return default


WORKSPACE_ROOT = Path(os.environ.get("WORKSPACE_ROOT", "/workspace"))

# In-memory undo stack: absolute path -> list of pre-edit byte snapshots.
# Cap depth at 20 (oldest evicted). Lost on agent restart - undo is a
# session-scoped affordance, not durable state. One process serves every tenant,
# so the whole stack is bounded too: least recently edited paths go first, and a
# file larger than _UNDO_MAX_SNAPSHOT is edited without an undo step.
_edit_stack: "collections.OrderedDict[str, list[bytes]]" = collections.OrderedDict()
_EDIT_STACK_DEPTH = 20
_UNDO_MAX_SNAPSHOT = 8 * 1024 * 1024
_UNDO_MAX_TOTAL = 64 * 1024 * 1024

# (project_id, rel_path) -> last fs_read content + sha256. Used by
# fs_diff(vs_last_read=True) to detect concurrent writes. Content is kept only
# for files up to _SNAPSHOT_MAX_FILE, in an LRU of _SNAPSHOT_MAX_TOTAL bytes; a
# larger file keeps only its hash, so fs_diff can still say whether it changed.
_last_read_contents: "collections.OrderedDict[tuple[str, str], bytes]" = collections.OrderedDict()
_last_read_hashes: "collections.OrderedDict[tuple[str, str], str]" = collections.OrderedDict()
_SNAPSHOT_MAX_FILE = 1024 * 1024
_SNAPSHOT_MAX_TOTAL = 32 * 1024 * 1024
_SNAPSHOT_MAX_HASHES = 10_000

# Hard cap on fs_read_many total payload (bytes).
_DEFAULT_READ_MANY_CAP = 200_000

# Subdirs auto-created on first project access. These are also "protected"
# by the HTTP layer: the drawer cannot rename or delete them via
# rename_for_project / delete_for_project. The LLM-facing fs_delete /
# fs_move tools are NOT gated so the agent can still recreate them after
# accidental damage (next call to _workspace_root_for auto-creates).
_DEFAULT_SUBDIRS = ("notes", "tool-outputs", "jobs", "uploads")
PROTECTED_SUBDIRS = frozenset(_DEFAULT_SUBDIRS)


def is_protected_path(rel_path: str) -> bool:
    """True if rel_path is the project root or a default subdir.

    Used by HTTP delete/rename to refuse destructive operations on the
    layout the workspace assumes exists.

    SECURITY (bug #17 regression): normalize the path before checking,
    otherwise variants like ./notes, notes/, notes//, ./ bypass the
    gate via the naive .split('/') check. os.path.normpath collapses
    these, and we treat the result of '.' as the project root.
    """
    if rel_path is None:
        return True
    # Normalize: collapse ./ and //, strip trailing /. normpath('') -> '.'
    norm = os.path.normpath(rel_path.strip()) if rel_path.strip() else "."
    # Treat normalized root or '.' as the protected project root
    if norm in (".", "/", ""):
        return True
    # If normalization produces a '..' component, it's escape - protect
    # conservatively (also rejected by resolve_for_project later)
    if norm.startswith(".."):
        return True
    norm = norm.lstrip("/")
    parts = norm.split("/")
    return len(parts) == 1 and parts[0] in PROTECTED_SUBDIRS

# Dirs skipped by fs_tree.
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv"}


# =============================================================================
# Internals
# =============================================================================

def _validate_project_id(pid: str) -> None:
    """Reject project_ids that could escape the workspace root.

    SECURITY: this is the only thing protecting the workspace boundary
    when project_id is HTTP-attacker-controlled (it's a query-string
    parameter on /workspace/* endpoints). Without it, projectId="../foo"
    causes (WORKSPACE_ROOT / "../foo").resolve() to land OUTSIDE the
    workspace, and every subsequent path check accepts that escaped
    location as "the workspace root" - leaking host filesystem access.
    """
    if not pid:
        raise ValueError("project_id required")
    if "/" in pid or "\\" in pid or "\x00" in pid:
        raise ValueError(f"invalid project_id (contains separator): {pid!r}")
    if pid in (".", "..") or pid.startswith("."):
        raise ValueError(f"invalid project_id (dot path): {pid!r}")
    # Reject absolute-looking values
    if pid.startswith("/"):
        raise ValueError(f"invalid project_id (absolute): {pid!r}")


def _project_id() -> str:
    from agent_context import current_project_id
    pid = current_project_id.get()
    if not pid:
        raise ValueError("fs_* tool called without project_id in context")
    _validate_project_id(pid)
    return pid


def _workspace_root_for(project_id: str) -> Path:
    root = WORKSPACE_ROOT / project_id
    root.mkdir(parents=True, exist_ok=True)
    for sub in _DEFAULT_SUBDIRS:
        (root / sub).mkdir(exist_ok=True)
    return root


def _workspace_root() -> Path:
    return _workspace_root_for(_project_id())


def _resolve_safe(user_path: Optional[str], follow_symlinks: bool = True) -> Path:
    """Resolve user_path against project workspace. Reject any escape.

    follow_symlinks=False is for tools that need to *inspect* a symlink itself
    (fs_symlink_read, fs_stat) rather than its target. Even with following off,
    the path is still normalised (`..` collapsed) and confined to the workspace.
    """
    root = _workspace_root().resolve()
    if user_path in (None, "", ".", "/"):
        return root
    p = Path(user_path)
    if p.is_absolute():
        if follow_symlinks:
            try:
                resolved = p.resolve()
            except Exception:
                raise ValueError(f"absolute path not allowed: {user_path}")
        else:
            resolved = Path(os.path.normpath(str(p)))
        if resolved == root or root in resolved.parents:
            return resolved
        raise ValueError(f"absolute path not allowed: {user_path}")
    if follow_symlinks:
        candidate = (root / user_path).resolve()
    else:
        candidate = Path(os.path.normpath(str(root / user_path)))
    if candidate != root and root not in candidate.parents:
        raise ValueError(f"path escapes workspace: {user_path}")
    return candidate


def _rel(path: Path) -> str:
    try:
        return str(path.relative_to(_workspace_root().resolve()))
    except ValueError:
        return str(path)


# -----------------------------------------------------------------------------
# Touching what a checked path names
# -----------------------------------------------------------------------------
# Every Kali sandbox that mounts a project writes it as root. So the path that
# _resolve_safe / resolve_for_project approved can be a link, a pipe or a giant
# by the time it is used, or become one in between. The helpers below open the
# path's folder by descriptor and prove it is still inside the project, then
# touch the last component only through that descriptor: never following a link,
# regular files only, never blocking on the open, bounded reads, and writes by a
# fresh O_EXCL file renamed into place (FU-29, STRIDE T4, I6, D15).

_FILE_FLAGS = os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC


def _read_max_bytes() -> int:
    """The largest file fs_read, fs_edit, fs_multi_edit, fs_diff and fs_symbols
    load whole. A call holds it several times over (bytes, text, lines) and
    fs_read keeps a copy for fs_diff, in a 3 GB agent shared by every tenant. The
    model reads 2000 lines at a time and offloaded tool outputs are far smaller;
    fs_grep (ripgrep, streaming) searches anything larger."""
    return _int_env("FS_READ_MAX_BYTES", 32 * 1024 * 1024)


def _hash_max_bytes() -> int:
    """The largest file hashed (fs_hash, fs_stat, Properties). Hashing runs off the
    event loop, but 2 GiB still took the reviewer's run 1.4-2.8 s per click, and a
    planted sparse giant costs the same as a real one."""
    return _int_env("FS_HASH_MAX_BYTES", 256 * 1024 * 1024)


def _scan_max_bytes() -> int:
    """The most fs_read streams through to page a file (it counts every line):
    above the 2 GiB an import can bring, below what a planted sparse giant with a
    text head would cost a worker thread."""
    return _int_env("FS_READ_SCAN_MAX_BYTES", 4 * 1024 ** 3)


def _archive_max_bytes() -> int:
    """The bytes one archive build reads, charged at each file's open with its
    size: a sparse giant (or a file grown after the drawer's disk reservation)
    must not hold a worker for minutes."""
    return _int_env("FS_ARCHIVE_MAX_BYTES", 2 * 1024 ** 3)


def _copy_max_bytes() -> int:
    """The data one fs_copy writes (holes are copied as holes and cost nothing):
    a copy runs off the event loop, but a planted giant must not fill the disk."""
    return _int_env("FS_COPY_MAX_BYTES", 2 * 1024 ** 3)


def _inside(real: str, root: str) -> bool:
    return real == root or real.startswith(root + os.sep)


def _real_root(root) -> str:
    return os.path.realpath(root)


@contextlib.contextmanager
def _pinned_parent(full: Path, root):
    """(descriptor of the folder holding `full`, `full`'s last component).

    The folder is resolved, must lie inside `root`, is opened without following
    its last component, and the opened folder's own real path is checked again:
    a link swapped into the path after the check cannot take the operation out of
    the project. FileNotFoundError when the folder is gone."""
    root_s = _real_root(root)
    parent = os.path.realpath(full.parent)
    if not _inside(parent, root_s):
        raise ValueError(f"path escapes workspace: {full.name}")
    try:
        fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        raise
    except OSError:
        raise ValueError(f"not a folder: {full.parent.name}") from None
    try:
        if not _inside(os.readlink(f"/proc/self/fd/{fd}"), root_s):
            raise ValueError(f"path escapes workspace: {full.name}")
        yield fd, full.name
    finally:
        os.close(fd)


def _open_regular_at(dir_fd: int, name: str, flags: int = os.O_RDONLY) -> tuple[int, os.stat_result]:
    """Open `name` only if it is a regular file: the lstat keeps a pipe or a device
    from being opened at all, the fstat checks what was opened."""
    st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    if not statlib.S_ISREG(st.st_mode):
        raise ValueError(f"not a regular file: {name}")
    try:
        fd = os.open(name, flags | _FILE_FLAGS, dir_fd=dir_fd)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENXIO):
            raise ValueError(f"not a regular file: {name}") from None
        raise
    try:
        st = os.fstat(fd)
        if not statlib.S_ISREG(st.st_mode):
            raise ValueError(f"not a regular file: {name}")
    except BaseException:
        os.close(fd)
        raise
    return fd, st


@contextlib.contextmanager
def _open_file(full: Path, root, flags: int = os.O_RDONLY):
    """(fd, stat) of the regular file `full`, opened as _pinned_parent describes."""
    with _pinned_parent(full, root) as (dir_fd, name):
        fd, st = _open_regular_at(dir_fd, name, flags)
    try:
        yield fd, st
    finally:
        os.close(fd)


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


def _too_large(label: str, size: int, cap: int) -> ValueError:
    return ValueError(f"{label} is {size} bytes, more than the {cap} bytes a workspace "
                      f"tool reads whole. Search it with fs_grep instead.")


def _read_file(full: Path, root, label: str) -> bytes:
    """A whole regular file, at most _read_max_bytes()."""
    cap = _read_max_bytes()
    with _open_file(full, root) as (fd, st):
        if st.st_size > cap:
            raise _too_large(label, st.st_size, cap)
        data = _read_at_most(fd, 0, cap + 1)
    if len(data) > cap:
        raise _too_large(label, len(data), cap)
    return data


def _open_binary(full: Path, root):
    """A binary file object on the regular file `full`, opened as _open_file does."""
    with _open_file(full, root) as (fd, _st):
        return os.fdopen(os.dup(fd), "rb")


def _read_head(full: Path, root, limit: int) -> tuple[bytes, os.stat_result]:
    """The first `limit` bytes of a regular file, and its stat."""
    with _open_file(full, root) as (fd, st):
        return _read_at_most(fd, 0, limit), st


_BREAKS = "\n\r\v\f\x1c\x1d\x1e\x85  "  # str.splitlines() boundaries
_LINE_BREAK = re.compile(r"\r\n|[\n\r\v\f\x1c\x1d\x1e\x85  ]")


def _text_lines(fd: int, keep: int = 4096, on_chunk: Optional[Callable[[bytes], None]] = None) -> Iterator[str]:
    """The file's lines as str.splitlines() splits them (UTF-8, strict: a
    UnicodeDecodeError as for a whole decode), each cut to `keep` characters.
    Read 1 MiB at a time, so neither a huge file nor one endless line is ever held
    whole. `on_chunk` sees every raw chunk (fs_read hashes the file with it)."""
    dec = codecs.getincrementaldecoder("utf-8")("strict")
    held, line, overflow, offset = "", "", False, 0
    while True:
        raw = os.pread(fd, 1 << 20, offset)
        offset += len(raw)
        if on_chunk is not None and raw:
            on_chunk(raw)
        text = held + dec.decode(raw, final=not raw)
        held = ""
        if raw and text.endswith("\r"):
            # A "\r\n" can straddle two reads: the "\r" waits for the next one.
            text, held = text[:-1], "\r"
        if overflow:
            m = _LINE_BREAK.search(text)
            if m is None:
                if not raw:
                    yield line
                    return
                continue
            yield line
            line, overflow = "", False
            text = text[m.end():]
        pieces = text.splitlines(keepends=True)
        tail = pieces.pop() if pieces and pieces[-1][-1] not in _BREAKS else ""
        for piece in pieces:
            body = piece[:-2] if piece.endswith("\r\n") else piece[:-1]
            yield (line + body)[:keep]
            line = ""
        if tail:
            line = (line + tail)
            if len(line) > keep:
                line, overflow = line[:keep], True
        if not raw:
            if line:
                yield line
            return


def _text(raw: bytes, errors: str = "strict") -> str:
    """Decode as Path.read_text did: UTF-8 with universal newlines."""
    return io.TextIOWrapper(io.BytesIO(raw), encoding="utf-8", errors=errors).read()


def _hash_file(full: Path, root, algo: str) -> Optional[str]:
    """The file's hex digest, or None when it is over _hash_max_bytes()."""
    cap = _hash_max_bytes()
    with _open_file(full, root) as (fd, st):
        if st.st_size > cap:
            return None
        h = hashlib.new(algo)
        offset = 0
        while offset <= cap:
            chunk = os.pread(fd, 1 << 16, offset)
            if not chunk:
                return h.hexdigest()
            h.update(chunk)
            offset += len(chunk)
    return None


def _stat_digest_of(full: Path, root) -> str:
    with _open_file(full, root) as (_fd, st):
        return _stat_digest(st)


def _hash_stream(full: Path, root) -> Optional[str]:
    """sha256 of a regular file, up to the bytes fs_read pages through (None past
    them), for fs_diff against a snapshot too large to keep."""
    cap = _scan_max_bytes()
    with _open_file(full, root) as (fd, _st):
        h, offset = hashlib.sha256(), 0
        while chunk := os.pread(fd, 1 << 20, offset):
            h.update(chunk)
            offset += len(chunk)
            if offset > cap:
                return None
    return h.hexdigest()


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view):]


def _replace_at(dir_fd: int, name: str, fill, *, create_only: bool = False) -> None:
    """_replace_with in an already pinned folder."""
    tmp = f".redamon-{uuid.uuid4().hex}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _FILE_FLAGS, 0o666, dir_fd=dir_fd)
    try:
        try:
            fill(fd)
        finally:
            os.close(fd)
        if create_only:
            os.link(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd, follow_symlinks=False)
        else:
            os.replace(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
    finally:
        with contextlib.suppress(OSError):
            os.unlink(tmp, dir_fd=dir_fd)


def _replace_with(full: Path, root, fill, *, create_only: bool = False) -> None:
    """Write `full` whole: `fill(fd)` writes a fresh O_EXCL file in the same folder,
    which is then renamed over `full` (or linked, when `create_only`:
    FileExistsError if anything is there). What sits at `full`, or at any name a
    sandbox could guess, is never opened."""
    with _pinned_parent(full, root) as (dir_fd, name):
        _replace_at(dir_fd, name, fill, create_only=create_only)


def _write_file(full: Path, root, data: bytes, *, create_only: bool = False,
                mode: Optional[int] = None) -> None:
    def fill(fd):
        _write_all(fd, data)
        if mode is not None:
            os.fchmod(fd, mode)

    _replace_with(full, root, fill, create_only=create_only)


class _CopyTooLarge(ValueError):
    pass


def _copy_data(src_fd: int, dst_fd: int, size: int, budget: list) -> None:
    """Copy the first `size` bytes of src into dst with holes left as holes
    (SEEK_DATA / SEEK_HOLE), charging the data to budget[0]: ValueError once it
    runs out. A planted sparse giant therefore costs neither disk nor time."""
    off = 0
    while off < size:
        try:
            data = os.lseek(src_fd, off, os.SEEK_DATA)
        except OSError as exc:
            if exc.errno == errno.ENXIO:  # only a hole is left
                break
            raise
        if data >= size:
            break
        hole = min(os.lseek(src_fd, data, os.SEEK_HOLE), size)
        pos = data
        while pos < hole:
            chunk = os.pread(src_fd, min(1 << 20, hole - pos), pos)
            if not chunk:
                break
            budget[0] -= len(chunk)
            if budget[0] < 0:
                raise _CopyTooLarge(f"the copy is larger than the {_copy_max_bytes()} bytes "
                                    "fs_copy writes")
            view = memoryview(chunk)
            while view:
                n = os.pwrite(dst_fd, view, pos)
                view = view[n:]
                pos += n
        off = hole
    os.ftruncate(dst_fd, size)


def _copy_regular_at(src_fd: int, st: os.stat_result, dir_fd: int, name: str, budget: list) -> None:
    """shutil.copy2 for one open regular file, written as _replace_at writes."""
    def fill(fd):
        _copy_data(src_fd, fd, st.st_size, budget)
        os.utime(fd, ns=(st.st_atime_ns, st.st_mtime_ns))
        os.fchmod(fd, 0o666)

    _replace_at(dir_fd, name, fill)


def _copy_file(src: Path, dst: Path, root) -> None:
    """shutil.copy2 for one regular file, read and written as above."""
    with _open_file(src, root) as (src_fd, st), _pinned_parent(dst, root) as (dir_fd, name):
        _copy_regular_at(src_fd, st, dir_fd, name, [_copy_max_bytes()])


def _append_file(full: Path, root, data: bytes) -> None:
    with _pinned_parent(full, root) as (dir_fd, name):
        try:
            fd, _ = _open_regular_at(dir_fd, name, os.O_WRONLY | os.O_APPEND)
        except FileNotFoundError:
            fd = os.open(name, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_EXCL | _FILE_FLAGS,
                         0o666, dir_fd=dir_fd)
    try:
        _write_all(fd, data)
    finally:
        os.close(fd)


def _remove_at(dir_fd: int, name: str) -> None:
    """Delete one entry of a pinned folder, a folder with _rmtree_at: neither
    follows a link."""
    st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    if statlib.S_ISDIR(st.st_mode):
        _rmtree_at(dir_fd, name)
    else:
        os.unlink(name, dir_fd=dir_fd)


_RMTREE_MAX_STEPS = 10_000_000


def _rmtree_at(parent_fd: int, name: str) -> None:
    """Remove the folder `name` of an opened folder, of any depth, with two
    descriptors and no recursion: each subfolder's entries are moved up into the
    folder being emptied, then the subfolder removed. A sandbox can nest folders
    far deeper than Python's recursion (shutil.rmtree raised RecursionError on a
    1500-level tree, so the reset failed); links are unlinked, never followed."""
    top = os.open(name, _DIR_OPEN, dir_fd=parent_fd)
    steps = 0
    try:
        while True:
            entries = os.listdir(top)
            if not entries:
                break
            for entry in entries:
                steps += 1
                if steps > _RMTREE_MAX_STEPS:
                    raise OSError(errno.EBUSY, f"{name} keeps growing while it is removed")
                try:
                    st = os.stat(entry, dir_fd=top, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                if not statlib.S_ISDIR(st.st_mode):
                    with contextlib.suppress(FileNotFoundError):
                        os.unlink(entry, dir_fd=top)
                    continue
                try:
                    sub = os.open(entry, _DIR_OPEN, dir_fd=top)
                except (FileNotFoundError, NotADirectoryError):
                    continue
                try:
                    for inner in os.listdir(sub):
                        os.rename(inner, f".rm-{uuid.uuid4().hex}", src_dir_fd=sub, dst_dir_fd=top)
                finally:
                    os.close(sub)
                with contextlib.suppress(FileNotFoundError, OSError):
                    os.rmdir(entry, dir_fd=top)
    finally:
        os.close(top)
    os.rmdir(name, dir_fd=parent_fd)


def _entry_facts(full: Path, root) -> tuple[os.stat_result, str, Optional[Path], Optional[str]]:
    """(stat, kind, file to hash or None, link text or None) of an entry named by a
    path whose last component is NOT followed. A link shows its target's facts
    only when the target is inside the project; otherwise only its own."""
    root_s = _real_root(root)
    if os.path.realpath(full) == root_s and not full.is_symlink():
        return os.stat(root_s), "dir", None, None
    with _pinned_parent(full, root) as (dir_fd, name):
        lst = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        link = os.readlink(name, dir_fd=dir_fd) if statlib.S_ISLNK(lst.st_mode) else None
    if link is None:
        kind = "dir" if statlib.S_ISDIR(lst.st_mode) else "file"
        return lst, kind, (full if statlib.S_ISREG(lst.st_mode) else None), None
    target = Path(os.path.realpath(full))
    if _inside(str(target), root_s):
        try:
            st = target.stat()
            return st, "symlink", (target if statlib.S_ISREG(st.st_mode) else None), link
        except OSError:
            pass
    return lst, "symlink", None, link


def _link_view(dir_fd: int, name: str, lst: os.stat_result, root) -> tuple[os.stat_result, bool]:
    """(stat, shown as a folder) of a link inside an opened folder: its target's
    facts only when the target is inside the project, else its own."""
    try:
        real_dir = os.readlink(f"/proc/self/fd/{dir_fd}")
        target = os.path.realpath(os.path.join(real_dir, name))
        if _inside(target, _real_root(root)):
            st = os.stat(target)
            return st, statlib.S_ISDIR(st.st_mode)
    except OSError:
        pass
    return lst, False


def _listing_at(dir_fd: int, root, names=None) -> list[tuple[str, Optional[os.stat_result], bool, bool]]:
    """(name, stat or None, shown as a folder, is a link) of each entry of an
    opened folder (or of `names` in it), every stat relative to the descriptor: a
    folder swapped for a link after the check lists nothing outside the project."""
    rows = []
    for name in (os.listdir(dir_fd) if names is None else names):
        try:
            lst = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        except OSError:
            rows.append((name, None, False, False))
            continue
        if statlib.S_ISLNK(lst.st_mode):
            st, is_dir = _link_view(dir_fd, name, lst, root)
            rows.append((name, st, is_dir, True))
        else:
            rows.append((name, lst, statlib.S_ISDIR(lst.st_mode), False))
    return rows


_DIR_OPEN = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
# How deep a descriptor walk goes (one descriptor is open per level). A folder
# past it is reported to the caller (`cut`), never left out silently.
_WALK_MAX_DEPTH = 256
# How deep an extracted member may nest, as workspace_import's too_deep: a deeper
# tree is refused before anything is written.
_EXTRACT_MAX_DEPTH = 64


class _WalkTimeout(Exception):
    pass


@contextlib.contextmanager
def _open_dir(full: Path, root):
    """A descriptor on the folder `full`, opened as _pinned_parent opens a parent:
    never through a link. ValueError when it is not a plain folder of the project."""
    root_s = _real_root(root)
    if os.path.normpath(str(full)) == root_s:
        fd = os.open(root_s, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    else:
        with _pinned_parent(full, root) as (dir_fd, name):
            try:
                fd = os.open(name, _DIR_OPEN, dir_fd=dir_fd)
            except FileNotFoundError:
                raise
            except OSError:
                raise ValueError(f"not a folder: {full.name}") from None
    try:
        yield fd
    finally:
        os.close(fd)


def _walk_at(top_fd: int, *, deadline: Optional[float] = None, max_depth: int = _WALK_MAX_DEPTH,
             skip=None, descend=None, cut: Optional[list] = None
             ) -> Iterator[tuple[str, int, str, os.stat_result]]:
    """(path relative to top_fd, its folder's descriptor, its name, its lstat) of
    every entry under top_fd, each folder before what it holds. Every subfolder is
    opened from its parent's descriptor with O_NOFOLLOW: the walk cannot leave the
    tree it started in, whatever a sandbox swaps meanwhile, and a link is reported,
    never entered. The descriptor is valid until the next step. `skip(name)` drops
    an entry, `descend(path)` False keeps a folder closed, a folder past max_depth
    is appended to `cut`; _WalkTimeout past `deadline`."""
    first = os.dup(top_fd)
    stack = [(first, "", iter(sorted(os.listdir(first))))]
    try:
        while stack:
            fd, rel, names = stack[-1]
            name = next(names, None)
            if name is None:
                os.close(fd)
                stack.pop()
                continue
            if deadline is not None and time.monotonic() > deadline:
                raise _WalkTimeout()
            if skip is not None and skip(name):
                continue
            try:
                st = os.stat(name, dir_fd=fd, follow_symlinks=False)
            except OSError:
                continue
            path = f"{rel}/{name}" if rel else name
            yield path, fd, name, st
            if statlib.S_ISDIR(st.st_mode):
                if descend is not None and not descend(path):
                    continue
                if len(stack) > max_depth:
                    if cut is not None:
                        cut.append(path)
                    continue
                try:
                    sub = os.open(name, _DIR_OPEN, dir_fd=fd)
                except OSError:
                    continue
                try:
                    stack.append((sub, path, iter(sorted(os.listdir(sub)))))
                except BaseException:
                    os.close(sub)
                    raise
    finally:
        for fd, _rel, _names in stack:
            os.close(fd)


def _makedirs(full: Path, root, *, parents: bool = True, exist_ok: bool = True,
              chmod_new: Optional[int] = None) -> None:
    """mkdir for `full` (resolved, inside the project) and, with `parents`, each
    missing folder above it: one level at a time from the project root's
    descriptor, never through a link (ValueError), a new folder's mode set on its
    own descriptor. FileNotFoundError for a missing parent without `parents`;
    FileExistsError when `full` exists and not `exist_ok`."""
    root_s = _real_root(root)
    rel = os.path.relpath(os.path.normpath(str(full)), root_s)
    if rel == "." or rel.startswith(".."):
        if rel == ".":
            if not exist_ok:
                raise FileExistsError(str(full))
            return
        raise ValueError(f"path escapes workspace: {full.name}")
    parts = rel.split(os.sep)
    fd = os.open(root_s, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for i, part in enumerate(parts):
            last = i == len(parts) - 1
            try:
                try:
                    nfd = os.open(part, _DIR_OPEN, dir_fd=fd)
                except FileNotFoundError:
                    if not last and not parents:
                        raise
                    with contextlib.suppress(FileExistsError):
                        os.mkdir(part, 0o777, dir_fd=fd)
                    nfd = os.open(part, _DIR_OPEN, dir_fd=fd)
                    if chmod_new is not None:
                        os.fchmod(nfd, chmod_new)
                else:
                    if last and not exist_ok:
                        os.close(nfd)
                        raise FileExistsError(str(full))
            except OSError as exc:
                if exc.errno in (errno.ENOTDIR, errno.ELOOP):
                    raise ValueError(f"not a folder: {part}") from None
                raise
            os.close(fd)
            fd = nfd
    finally:
        os.close(fd)


def _project_root_of(path: Path) -> Path:
    """The project folder that holds a path resolve_for_project returned."""
    base = Path(os.path.realpath(WORKSPACE_ROOT))
    rel = Path(os.path.normpath(str(path))).relative_to(base)
    return base / rel.parts[0]


_pool: Optional[ThreadPoolExecutor] = None
_pool_lock = threading.Lock()


def _fs_pool() -> ThreadPoolExecutor:
    # Its own pool: the event loop's default one serves fetch_guard's pinned DNS
    # and model loading (workspace_import/executor.py), which a long copy must not stall.
    global _pool
    with _pool_lock:
        if _pool is None:
            _pool = ThreadPoolExecutor(max_workers=_int_env("FS_TOOL_WORKERS", 4),
                                       thread_name_prefix="workspace-fs")
        return _pool


async def _off_loop(fn: Callable, *args):
    """Run blocking file work off the event loop, in the caller's context (the
    project id is a contextvar)."""
    loop = asyncio.get_running_loop()
    ctx = contextvars.copy_context()
    return await loop.run_in_executor(_fs_pool(), ctx.run, fn, *args)


class _FdReader(io.RawIOBase):
    """Exactly `size` bytes of an open file, from offset 0: an archive entry's
    header already says the size, so a file that shrank while it was read is
    padded with zeros and one that grew is cut."""

    def __init__(self, fd: int, size: int):
        self.fd, self.left, self.pos = fd, size, 0

    def readable(self) -> bool:
        return True

    def readinto(self, b) -> int:
        n = min(len(b), self.left)
        if n <= 0:
            return 0
        chunk = os.pread(self.fd, n, self.pos)
        chunk += b"\0" * (n - len(chunk))
        b[:n] = chunk
        self.pos += n
        self.left -= n
        return n


_ZIP_EPOCH = 315532800  # 1980-01-01: the earliest date a zip entry can carry


class _ArchiveTooLarge(ValueError):
    pass


def _archive_add_file(out, fmt: str, arcname: str, fd: int, st: os.stat_result, budget: list) -> None:
    budget[0] -= st.st_size
    if budget[0] < 0:
        raise _ArchiveTooLarge(f"the archive would hold more than the {_archive_max_bytes()} bytes "
                               "an archive is built from")
    if fmt == "tar.gz":
        info = tarfile.TarInfo(arcname)
        info.size, info.mtime = st.st_size, int(st.st_mtime)
        info.mode, info.uid, info.gid = statlib.S_IMODE(st.st_mode), st.st_uid, st.st_gid
        out.addfile(info, _FdReader(fd, st.st_size))
        return
    info = zipfile.ZipInfo(arcname, date_time=time.localtime(max(st.st_mtime, _ZIP_EPOCH))[:6])
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = (statlib.S_IFREG | statlib.S_IMODE(st.st_mode)) << 16
    reader = _FdReader(fd, st.st_size)
    with out.open(info, "w", force_zip64=st.st_size >= zipfile.ZIP64_LIMIT) as dst:
        while chunk := reader.read(1 << 20):
            dst.write(chunk)


def _archive_add_dir_entry(out, fmt: str, arcname: str, st: os.stat_result) -> None:
    if fmt == "tar.gz":
        info = tarfile.TarInfo(arcname)
        info.type, info.mtime = tarfile.DIRTYPE, int(st.st_mtime)
        info.mode, info.uid, info.gid = statlib.S_IMODE(st.st_mode), st.st_uid, st.st_gid
        out.addfile(info)


def _archive_add(out, fmt: str, full: Path, root, arcname: str, budget: list, cut: list) -> bool:
    """Add a file or a folder tree to an open tarfile / ZipFile, by descriptor: each
    folder walked with _walk_at, each file opened with _open_regular_at and its
    content read from that descriptor, never from a path. Links, pipes, devices
    and sockets are left out, as the archive helpers always left links out. Each
    file's size is charged to budget[0]; a folder past _WALK_MAX_DEPTH goes to
    `cut`. False when `full` itself is none of a file or a folder."""
    if os.path.normpath(str(full)) != _real_root(root):
        with _pinned_parent(full, root) as (dir_fd, name):
            st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
            if statlib.S_ISREG(st.st_mode):
                fd, st = _open_regular_at(dir_fd, name)
                try:
                    _archive_add_file(out, fmt, arcname, fd, st, budget)
                finally:
                    os.close(fd)
                return True
            if not statlib.S_ISDIR(st.st_mode):
                return False
    with _open_dir(full, root) as top:
        _archive_add_tree(out, fmt, top, arcname, budget, cut)
    return True


def _archive_add_tree(out, fmt: str, top: int, arcname: str, budget: list, cut: list) -> None:
    _archive_add_dir_entry(out, fmt, arcname, os.fstat(top))
    for rel, parent_fd, entry, est in _walk_at(top, cut=cut):
        if statlib.S_ISDIR(est.st_mode):
            _archive_add_dir_entry(out, fmt, f"{arcname}/{rel}", est)
        elif statlib.S_ISREG(est.st_mode):
            try:
                fd, est = _open_regular_at(parent_fd, entry)
            except (OSError, ValueError):
                continue  # swapped for something else since it was listed
            try:
                _archive_add_file(out, fmt, f"{arcname}/{rel}", fd, est, budget)
            finally:
                os.close(fd)


def _open_archive_writer(fileobj, fmt: str):
    if fmt == "tar.gz":
        return tarfile.open(fileobj=fileobj, mode="w:gz")
    return zipfile.ZipFile(fileobj, "w", zipfile.ZIP_DEFLATED)


def _fmt_size(n: int) -> str:
    f = float(n)
    for u in ("B", "K", "M", "G"):
        if f < 1024:
            return f"{f:.0f}{u}"
        f /= 1024
    return f"{f:.0f}T"


def _is_binary(data: bytes) -> bool:
    return b"\x00" in data[:8192]


def _push_undo(abs_path: str, snapshot: bytes) -> None:
    if len(snapshot) > _UNDO_MAX_SNAPSHOT:
        return
    stack = _edit_stack.setdefault(abs_path, [])
    _edit_stack.move_to_end(abs_path)
    stack.append(snapshot)
    if len(stack) > _EDIT_STACK_DEPTH:
        stack.pop(0)
    total = sum(len(s) for st in _edit_stack.values() for s in st)
    while total > _UNDO_MAX_TOTAL and _edit_stack:
        oldest = next(iter(_edit_stack))
        steps = _edit_stack[oldest]
        total -= len(steps.pop(0))
        if not steps:
            del _edit_stack[oldest]


def _remember_read(key: tuple, digest: str, raw: Optional[bytes]) -> None:
    """Keep fs_read's snapshot for fs_diff: always the hash, the content only when
    `raw` is given (small files), both bounded LRUs."""
    _last_read_hashes[key] = digest
    _last_read_hashes.move_to_end(key)
    while len(_last_read_hashes) > _SNAPSHOT_MAX_HASHES:
        _last_read_hashes.popitem(last=False)
    _last_read_contents.pop(key, None)
    if raw is not None and len(raw) <= _SNAPSHOT_MAX_FILE:
        _last_read_contents[key] = raw
        total = sum(map(len, _last_read_contents.values()))
        while total > _SNAPSHOT_MAX_TOTAL and _last_read_contents:
            total -= len(_last_read_contents.popitem(last=False)[1])


def _parse_duration(spec: str) -> Optional[float]:
    """Parse '24h', '7d', etc. -> seconds. Leading <,>,= is ignored here."""
    if not spec:
        return None
    s = spec.strip().lstrip("<>=")
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
    if not s or s[-1] not in units:
        return None
    try:
        return float(s[:-1]) * units[s[-1]]
    except ValueError:
        return None


def _parse_size(spec: str) -> Optional[int]:
    if not spec:
        return None
    s = spec.strip().lstrip("<>=")
    units = {"B": 1, "K": 1024, "M": 1024 ** 2, "G": 1024 ** 3}
    if not s:
        return None
    if s[-1].upper() in units:
        try:
            return int(float(s[:-1]) * units[s[-1].upper()])
        except ValueError:
            return None
    try:
        return int(s)
    except ValueError:
        return None


# =============================================================================
# READ (3)
# =============================================================================

async def fs_read(path: str, offset: Optional[int] = None, limit: Optional[int] = None) -> str:
    try:
        full = _resolve_safe(path)
    except ValueError as e:
        return f"Error: {e}"
    if not full.exists():
        return f"Error: file not found: {path}. Use fs_glob to find the correct path."
    if full.is_dir():
        return f"Error: {path} is a directory. Use fs_list or fs_tree."

    key = (_project_id(), _rel(full))
    try:
        out, digest, snapshot = await _off_loop(_read_window, full, _workspace_root(), path,
                                                offset, limit)
    except FileNotFoundError:
        return f"Error: file not found: {path}. Use fs_glob to find the correct path."
    except ValueError as e:
        return f"Error: {e}"
    if digest is not None:
        _remember_read(key, digest, snapshot)
    return out


# The most fs_read collects for one answer: the old whole-file read could return
# up to its 32 MiB cap, so a wide window keeps that bound without the whole file.
_READ_WINDOW_MAX_CHARS = 32 * 1024 * 1024


def _read_window(full: Path, root, path: str, offset: Optional[int], limit: Optional[int]):
    """fs_read's body, off the event loop: (answer, sha256 or None, the content to
    snapshot or None). Text is streamed from the descriptor, so a file of any size
    can be paged with offset/limit in bounded memory; only a binary file, returned
    whole as base64, keeps the whole-file cap."""
    with _open_file(full, root) as (fd, st):
        head = _read_at_most(fd, 0, 8192)
        if _is_binary(head):
            cap = _read_max_bytes()
            if st.st_size > cap:
                raise _too_large(path, st.st_size, cap)
            raw = _read_at_most(fd, 0, cap + 1)
            if len(raw) > cap:
                raise _too_large(path, len(raw), cap)
            mime = mimetypes.guess_type(str(full))[0] or "application/octet-stream"
            b64 = base64.b64encode(raw).decode("ascii")
            return (f"[binary file: {path} ({len(raw)} bytes, {mime})]\n"
                    f"--- base64 ---\n{b64}", hashlib.sha256(raw).hexdigest(), raw)
        start = (offset - 1) if offset and offset > 0 else 0
        end = start + (limit if limit else 2000)
        h = hashlib.sha256()
        selected, total, kept, complete = [], 0, 0, False
        try:
            # Decoded only as far as the window: past it the lines are counted, not
            # decoded (three lines of a planted 4 GiB sparse file decoded every line).
            for line in _text_lines(fd, on_chunk=h.update):
                if start <= total < end and kept < _READ_WINDOW_MAX_CHARS:
                    selected.append(line)
                    kept += len(line)
                total += 1
                if total >= end or kept >= _READ_WINDOW_MAX_CHARS:
                    break
            else:
                complete = True
        except UnicodeDecodeError:
            return f"Error: {path} could not be decoded as UTF-8.", None, None
        digest = h.hexdigest() if complete else None
        if not complete:
            total, digest = _count_rest(fd, st)
        snapshot = None
        if st.st_size <= _SNAPSHOT_MAX_FILE and digest and not digest.startswith("stat:"):
            snapshot = _read_at_most(fd, 0, _SNAPSHOT_MAX_FILE + 1)
            if hashlib.sha256(snapshot).hexdigest() != digest:
                snapshot = None  # changed while it was read: keep only the hash
    width = max(1, len(str(start + len(selected))))
    formatted = []
    for i, line in enumerate(selected, start=start + 1):
        if len(line) > 2000:
            line = line[:2000] + " [LINE TRUNCATED]"
        formatted.append(f"{i:>{width}}\t{line}")
    out = "\n".join(formatted)
    if isinstance(total, str) or total > len(selected):
        out = f"[{path}: lines {start + 1}-{start + len(selected)} of {total}]\n{out}"
    return out, digest, snapshot


def _stat_digest(st: os.stat_result) -> str:
    # The change marker of a file too large to hash: its size and mtime.
    return f"stat:{st.st_size}:{st.st_mtime_ns}"


def _count_rest(fd: int, st: os.stat_result):
    """(line count, fs_diff marker) of a file whose window fs_read already filled:
    one raw pass counting newlines (no decoding), hashed only up to
    _hash_max_bytes(); a larger file is marked by size and mtime instead. Past
    _scan_max_bytes() the count is a lower bound."""
    hashed = st.st_size <= _hash_max_bytes()
    h, newlines, offset, last = hashlib.sha256(), 0, 0, b""
    cap = _scan_max_bytes()
    while chunk := os.pread(fd, 1 << 20, offset):
        newlines += chunk.count(b"\n")
        if hashed:
            h.update(chunk)
        offset += len(chunk)
        last = chunk[-1:]
        if offset > cap:
            return (f"more than {newlines} (fs_read stops counting after {cap} bytes)",
                    _stat_digest(st))
    total = newlines + (1 if offset and last != b"\n" else 0)
    return total, (h.hexdigest() if hashed else _stat_digest(st))


async def fs_read_many(paths: list, max_total_bytes: int = _DEFAULT_READ_MANY_CAP) -> str:
    if not isinstance(paths, list) or not paths:
        return "Error: `paths` must be a non-empty list of file paths."
    # The caller sets the cap; the whole answer still stays within one fs_read.
    max_total_bytes = min(max_total_bytes, _read_max_bytes())
    root = _workspace_root()
    out_parts = []
    used = 0
    for p in paths:
        try:
            full = _resolve_safe(p)
        except ValueError as e:
            out_parts.append(f"=== {p} ===\nError: {e}")
            continue
        if not full.exists():
            out_parts.append(f"=== {p} ===\nError: not found")
            continue
        if full.is_dir():
            out_parts.append(f"=== {p} ===\nError: is a directory")
            continue
        remaining = max_total_bytes - used
        if remaining <= 0:
            out_parts.append(f"=== {p} ===\n[skipped - total cap {max_total_bytes} reached]")
            continue
        try:
            # Only what can still be shown, and enough to tell binary from text.
            data, st = _read_head(full, root, max(remaining + 1, 8192))
        except Exception as e:
            out_parts.append(f"=== {p} ===\nError: {e}")
            continue
        if _is_binary(data):
            out_parts.append(f"=== {p} ===\n[binary file: {st.st_size} bytes - use fs_read for base64]")
            used += 80
            continue
        text = data.decode("utf-8", errors="replace")
        if len(text) > remaining or st.st_size > len(data):
            text = text[:remaining] + f"\n[truncated at {remaining} bytes]"
        used += len(text)
        out_parts.append(f"=== {p} ===\n{text}")
    return "\n\n".join(out_parts)


async def fs_stat(path: str, include_hash: bool = False) -> str:
    try:
        # follow_symlinks=False so a symlink reports as type=symlink instead
        # of being resolved to its target.
        full = _resolve_safe(path, follow_symlinks=False)
    except ValueError as e:
        return f"Error: {e}"
    root = _workspace_root()
    try:
        st, kind, hashable, _link = _entry_facts(full, root)
    except FileNotFoundError:
        return f"Error: not found: {path}"
    except ValueError as e:
        return f"Error: {e}"
    mtime = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(timespec="seconds")
    lines = [
        f"path: {path}",
        f"type: {kind}",
        f"size: {st.st_size}",
        f"mode: {statlib.filemode(st.st_mode)} ({oct(st.st_mode & 0o7777)})",
        f"mtime: {mtime}",
    ]
    if include_hash and hashable is not None:
        try:
            digest = await _off_loop(_hash_file, hashable, root, "sha256")
        except (OSError, ValueError) as e:
            digest, why = None, str(e)
        else:
            why = f"larger than {_hash_max_bytes()} bytes"
        lines.append(f"sha256: {digest}" if digest else f"sha256: (not computed: {why})")
    return "\n".join(lines)


# =============================================================================
# WRITE & MUTATE (10)
# =============================================================================

async def fs_write(path: str, content: str, mode: str = "overwrite") -> str:
    if mode not in ("overwrite", "create_only", "append"):
        return f"Error: invalid mode '{mode}'. Use overwrite|create_only|append."
    try:
        full = _resolve_safe(path)
    except ValueError as e:
        return f"Error: {e}"
    try:
        _makedirs(full.parent, _workspace_root())
    except ValueError as e:
        return f"Error: {e}"
    if mode == "create_only" and full.exists():
        return f"Error: file already exists: {path}. Use mode='overwrite' or 'append'."
    root = _workspace_root()
    try:
        if mode == "append":
            _append_file(full, root, content.encode("utf-8"))
            return f"Appended {len(content)} chars to {path}."
        _write_file(full, root, content.encode("utf-8"), create_only=mode == "create_only")
    except FileExistsError:
        return f"Error: file already exists: {path}. Use mode='overwrite' or 'append'."
    except ValueError as e:
        return f"Error: {e}"
    line_count = content.count("\n") + (0 if content.endswith("\n") else 1) if content else 0
    return f"Wrote {path} ({len(content)} chars, {line_count} lines, mode={mode})."


async def fs_edit(path: str, old_string: str, new_string: str, replace_all: bool = False) -> str:
    try:
        full = _resolve_safe(path)
    except ValueError as e:
        return f"Error: {e}"
    if not full.exists():
        return f"Error: not found: {path}"
    root = _workspace_root()
    try:
        raw = _read_file(full, root, path)
    except ValueError as e:
        return f"Error: {e}"
    content = _text(raw)
    if old_string not in content:
        return f"Error: old_string not found in {path}."
    if old_string == new_string:
        return "Error: new_string is identical to old_string."
    occurrences = content.count(old_string)
    if occurrences > 1 and not replace_all:
        return (
            f"Error: old_string found {occurrences} times in {path}. "
            "Provide more surrounding context, or set replace_all=True."
        )
    new_content = content.replace(old_string, new_string, -1 if replace_all else 1)
    try:
        _write_file(full, root, new_content.encode("utf-8"))
    except ValueError as e:
        return f"Error: {e}"
    _push_undo(str(full), raw)
    n = occurrences if replace_all else 1
    return f"Replaced {n} occurrence(s) in {path}."


async def fs_multi_edit(path: str, edits: list) -> str:
    if not isinstance(edits, list) or not edits:
        return "Error: `edits` must be a non-empty list of {old_string,new_string,replace_all?}."
    try:
        full = _resolve_safe(path)
    except ValueError as e:
        return f"Error: {e}"
    if not full.exists():
        return f"Error: not found: {path}"
    root = _workspace_root()
    try:
        snapshot = _read_file(full, root, path)
    except ValueError as e:
        return f"Error: {e}"
    new_content = snapshot.decode("utf-8", errors="strict")
    applied = []
    for i, edit in enumerate(edits, start=1):
        old_s = edit.get("old_string")
        new_s = edit.get("new_string")
        replace_all = bool(edit.get("replace_all", False))
        if old_s is None or new_s is None:
            return f"Error: edit #{i} missing old_string or new_string. No changes applied."
        if old_s == new_s:
            return f"Error: edit #{i} identical old/new. No changes applied."
        if old_s not in new_content:
            return f"Error: edit #{i} old_string not found (after prior edits). No changes applied."
        occurrences = new_content.count(old_s)
        if occurrences > 1 and not replace_all:
            return (
                f"Error: edit #{i} matches {occurrences} times. "
                "Provide more context or set replace_all=True. No changes applied."
            )
        new_content = new_content.replace(old_s, new_s, -1 if replace_all else 1)
        applied.append(occurrences if replace_all else 1)
    try:
        _write_file(full, root, new_content.encode("utf-8"))
    except ValueError as e:
        return f"Error: {e}"
    _push_undo(str(full), snapshot)
    return f"Applied {len(edits)} edits to {path} ({sum(applied)} replacements total)."


async def fs_undo_edit(path: str) -> str:
    try:
        full = _resolve_safe(path)
    except ValueError as e:
        return f"Error: {e}"
    stack = _edit_stack.get(str(full)) or []
    if not stack:
        return f"No undo history for {path}."
    try:
        _write_file(full, _workspace_root(), stack[-1])
    except ValueError as e:
        return f"Error: {e}"
    stack.pop()
    return f"Reverted {path} ({len(stack)} undo step(s) remaining)."


async def fs_delete(path: str, recursive: bool = False) -> str:
    try:
        full = _resolve_safe(path)
    except ValueError as e:
        return f"Error: {e}"
    if not full.exists():
        return f"Error: not found: {path}"
    if full == _workspace_root().resolve():
        return "Error: the workspace root cannot be deleted."
    if full.is_dir() and not recursive:
        return f"Error: {path} is a directory. Pass recursive=True to delete it and its contents."
    try:
        with _pinned_parent(full, _workspace_root()) as (dir_fd, name):
            is_dir = statlib.S_ISDIR(os.stat(name, dir_fd=dir_fd, follow_symlinks=False).st_mode)
            if is_dir and not recursive:
                return f"Error: {path} is a directory. Pass recursive=True to delete it and its contents."
            _remove_at(dir_fd, name)
    except ValueError as e:
        return f"Error: {e}"
    return f"Removed directory {path} (recursive)." if is_dir else f"Deleted file {path}."


async def fs_move(src: str, dst: str) -> str:
    try:
        src_p = _resolve_safe(src)
        dst_p = _resolve_safe(dst)
    except ValueError as e:
        return f"Error: {e}"
    if not src_p.exists():
        return f"Error: source not found: {src}"
    if src_p == _workspace_root().resolve():
        return "Error: the workspace root cannot be moved."
    try:
        _makedirs(dst_p.parent, _workspace_root())
    except ValueError as e:
        return f"Error: {e}"
    if dst_p.is_dir():
        dst_p = dst_p / src_p.name  # as shutil.move: into an existing folder
    root = _workspace_root()
    try:
        with _pinned_parent(src_p, root) as (src_fd, src_name), \
                _pinned_parent(dst_p, root) as (dst_fd, dst_name):
            os.rename(src_name, dst_name, src_dir_fd=src_fd, dst_dir_fd=dst_fd)
    except ValueError as e:
        return f"Error: {e}"
    return f"Moved {src} -> {dst}."


async def fs_copy(src: str, dst: str, recursive: bool = False) -> str:
    try:
        src_p = _resolve_safe(src)
        dst_p = _resolve_safe(dst)
    except ValueError as e:
        return f"Error: {e}"
    if not src_p.exists():
        return f"Error: source not found: {src}"
    root = _workspace_root()
    try:
        _makedirs(dst_p.parent, root)
        if src_p.is_dir():
            if not recursive:
                return f"Error: {src} is a directory. Pass recursive=True."
            cut = await _off_loop(_copy_tree, src_p, dst_p, root)
            if cut:
                return (f"Copied {src} -> {dst}, without {len(cut)} folder(s) nested deeper than "
                        f"{_WALK_MAX_DEPTH} levels (first: {cut[0]}).")
        else:
            if dst_p.is_dir():
                dst_p = dst_p / src_p.name  # as shutil.copy2: into an existing folder
            await _off_loop(_copy_file, src_p, dst_p, root)
    except FileExistsError:
        return f"Error: {dst} already exists."
    except ValueError as e:
        return f"Error: {e}"
    return f"Copied {src} -> {dst}."


def _copy_tree(src: Path, dst: Path, root) -> list:
    """shutil.copytree(src, dst, symlinks=True), by descriptor. The source is walked
    with _walk_at (a folder swapped for a link is refused, a link in it is copied
    as a link); every folder and file is created under the new tree's own
    descriptors (mkdir, O_EXCL file renamed in), so a link planted in dst during
    the copy is replaced, never written through. Pipes, devices and sockets are
    left out (a planted /dev/zero would be read forever). Folders get 0o777 and
    files 0o666 for the host user, and the data is bounded by _copy_max_bytes().
    Returns the folders left out past _WALK_MAX_DEPTH."""
    budget, cut = [_copy_max_bytes()], []
    with _open_dir(src, root) as src_fd:
        with _pinned_parent(dst, root) as (parent_fd, name):
            os.mkdir(name, 0o777, dir_fd=parent_fd)
            top = os.open(name, _DIR_OPEN, dir_fd=parent_fd)
        stack = [("", top)]
        try:
            os.fchmod(top, 0o777)
            for rel, src_dir, entry, st in _walk_at(src_fd, cut=cut):
                parent_rel = rel.rpartition("/")[0]
                for i in range(len(stack) - 1, -1, -1):
                    if stack[i][0] == parent_rel:
                        break
                else:
                    continue  # its folder could not be created
                while len(stack) > i + 1:
                    os.close(stack.pop()[1])
                dst_dir = stack[-1][1]
                try:
                    if statlib.S_ISDIR(st.st_mode):
                        with contextlib.suppress(FileExistsError):
                            os.mkdir(entry, 0o777, dir_fd=dst_dir)
                        sub = os.open(entry, _DIR_OPEN, dir_fd=dst_dir)
                        os.fchmod(sub, 0o777)
                        stack.append((rel, sub))
                    elif statlib.S_ISREG(st.st_mode):
                        fd, est = _open_regular_at(src_dir, entry)
                        try:
                            _copy_regular_at(fd, est, dst_dir, entry, budget)
                        finally:
                            os.close(fd)
                    elif statlib.S_ISLNK(st.st_mode):
                        os.symlink(os.readlink(entry, dir_fd=src_dir), entry, dir_fd=dst_dir)
                except _CopyTooLarge:
                    raise
                except (OSError, ValueError):
                    continue  # changed since it was listed
        finally:
            for _rel, fd in stack:
                os.close(fd)
    return cut


async def fs_mkdir(path: str, parents: bool = True) -> str:
    try:
        full = _resolve_safe(path)
    except ValueError as e:
        return f"Error: {e}"
    if full.exists():
        if not full.is_dir():
            return f"Error: {path} exists and is not a directory."
        try:
            entry_count = sum(1 for _ in full.iterdir())
        except OSError:
            entry_count = -1
        if entry_count < 0:
            return f"Directory {path} already exists (no change)."
        return f"Directory {path} already exists (no change, {entry_count} entries inside)."
    try:
        _makedirs(full, _workspace_root(), parents=parents, exist_ok=False)
    except ValueError as e:
        return f"Error: {e}"
    except FileNotFoundError:
        return (
            f"Error: parent of {path} does not exist. "
            f"Pass parents=True to auto-create intermediate directories."
        )
    except OSError as e:
        return f"Error: failed to create {path}: {e}"
    return f"Created directory {path}."


async def fs_chmod(path: str, mode_str: str) -> str:
    try:
        full = _resolve_safe(path)
    except ValueError as e:
        return f"Error: {e}"
    if not full.exists():
        return f"Error: not found: {path}"
    s = (mode_str or "").strip()
    if not s:
        return "Error: mode_str required (e.g. '755', '+x')."
    try:
        # An O_PATH descriptor on the entry itself, never through a link: the mode
        # is set on what was checked, through /proc/self/fd.
        if full == _workspace_root().resolve():
            fd = os.open(full, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
        else:
            with _pinned_parent(full, _workspace_root()) as (dir_fd, name):
                fd = os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
    except FileNotFoundError:
        return f"Error: not found: {path}"
    except (OSError, ValueError) as e:
        return f"Error: {e}"
    try:
        if statlib.S_ISLNK(os.fstat(fd).st_mode):
            return f"Error: {path} is a symlink."
        return _chmod_fd(fd, s, mode_str, path)
    finally:
        os.close(fd)


def _chmod_fd(fd: int, s: str, mode_str: str, path: str) -> str:
    target = f"/proc/self/fd/{fd}"
    try:
        if s[0] in ("+", "-"):
            cur = os.fstat(fd).st_mode
            op = s[0]
            flags = 0
            for ch in s[1:]:
                if ch == "x":
                    flags |= 0o111
                elif ch == "w":
                    flags |= 0o222
                elif ch == "r":
                    flags |= 0o444
                else:
                    return f"Error: unsupported chmod symbol '{ch}'. Use '+x'/'-x'/'+w' or octal '755'."
            new = (cur | flags) if op == "+" else (cur & ~flags)
            os.chmod(target, statlib.S_IMODE(new))
        else:
            os.chmod(target, int(s, 8))
    except ValueError:
        return f"Error: bad mode '{mode_str}'. Use octal '755' or '+x'/'-x'/'+w'."
    return f"chmod {mode_str} {path}."


async def fs_symlink_create(target: str, linkname: str, type: str = "soft") -> str:
    if type not in ("soft", "hard"):
        return "Error: type must be 'soft' or 'hard'."
    try:
        link = _resolve_safe(linkname)
        target_p = _resolve_safe(target)
    except ValueError as e:
        return f"Error: {e}"
    if link.exists() or link.is_symlink():
        return f"Error: {linkname} already exists."
    root = _workspace_root()
    try:
        _makedirs(link.parent, root)
    except ValueError as e:
        return f"Error: {e}"
    try:
        with _pinned_parent(link, root) as (link_fd, link_name):
            if type == "hard":
                with _pinned_parent(target_p, root) as (target_fd, target_name):
                    os.link(target_name, link_name, src_dir_fd=target_fd, dst_dir_fd=link_fd,
                            follow_symlinks=False)
            else:
                os.symlink(target_p, link_name, dir_fd=link_fd)
    except FileExistsError:
        return f"Error: {linkname} already exists."
    except ValueError as e:
        return f"Error: {e}"
    return f"Created {type} link {linkname} -> {target}."


# =============================================================================
# SEARCH & NAVIGATE (7)
# =============================================================================

# File types fs_grep's `type` accepts (ripgrep's names, by extension).
_GREP_TYPES = {
    "py": (".py", ".pyi"), "js": (".js", ".mjs", ".cjs", ".jsx"), "ts": (".ts", ".tsx", ".mts", ".cts"),
    "go": (".go",), "rust": (".rs",), "java": (".java",), "c": (".c", ".h"),
    "cpp": (".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx", ".h"), "cs": (".cs",), "php": (".php",),
    "ruby": (".rb",), "sh": (".sh", ".bash", ".zsh"), "md": (".md", ".markdown"),
    "markdown": (".md", ".markdown"), "json": (".json",), "yaml": (".yml", ".yaml"), "toml": (".toml",),
    "html": (".html", ".htm"), "css": (".css", ".scss", ".sass"), "xml": (".xml",), "sql": (".sql",),
    "txt": (".txt",), "log": (".log",), "kotlin": (".kt", ".kts"), "swift": (".swift",),
    "lua": (".lua",), "perl": (".pl", ".pm"), "config": (".conf", ".cfg", ".ini"), "csv": (".csv",),
}
_GREP_SECONDS = 25          # the child's own deadline: it answers with what it found
_GREP_KILL_SECONDS = 30     # the backstop for a child that does not answer
_GREP_MATCH_SECONDS = 2     # one line's match: past it the pattern backtracks, the search stops
_GREP_FILE_MAX_BYTES = 256 * 1024 * 1024
_GREP_MULTILINE_MAX_BYTES = 16 * 1024 * 1024  # multiline reads a file whole
_GREP_CHILD_MAX_MEMORY = 512 * 1024 * 1024
_GREP_LINE_SHOWN = 4000
# Searches running at once, per event loop: each child can take a full core, and
# the agent serves every tenant.
_GREP_CONCURRENCY = 2

# The search runs in a child Python given only the descriptor of the folder (or
# file) to search: it walks by descriptor (O_NOFOLLOW at every level, links never
# followed, regular files only), so nothing a sandbox swaps in can show it
# anything outside the project, and it takes no option from any argument.
_GREP_CHILD = r"""
import collections, fnmatch, json, os, re, resource, signal, stat, sys, time
a = json.loads(sys.argv[1])
# The kernel's own bounds on this child: CPU seconds and address space.
resource.setrlimit(resource.RLIMIT_CPU, (a["cpu"], a["cpu"] + 1))
resource.setrlimit(resource.RLIMIT_AS, (a["memory"], a["memory"]))
deadline = time.monotonic() + a["seconds"]
DIRF = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILEF = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC
lines, state = [], {"timed_out": False, "line_t": time.monotonic()}

class Deadline(Exception):
    pass

class Slow(Exception):
    pass

def tick(*_):
    # A timer signal reaches a running regex match too (re checks for signals),
    # so a backtracking pattern is stopped mid-match, not only between lines.
    now = time.monotonic()
    if now > deadline:
        raise Deadline()
    if now - state["line_t"] > a["match_seconds"]:
        raise Slow()

signal.signal(signal.SIGALRM, tick)
signal.setitimer(signal.ITIMER_REAL, 0.25, 0.25)

def done():
    signal.setitimer(signal.ITIMER_REAL, 0)
    sys.stdout.write(json.dumps({"lines": lines[:a["limit"] + 1], "timed_out": state["timed_out"]}))
    sys.exit(0)

def braces(pat):
    # "*.{py,txt}" -> ["*.py", "*.txt"]; one level, as most globs use them.
    m = re.search(r"\{([^{}]*,[^{}]*)\}", pat)
    if not m:
        return [pat]
    return [pat[:m.start()] + alt + pat[m.end():] for alt in m.group(1).split(",")][:64]

try:
    rx = re.compile(a["pattern"], (re.IGNORECASE if a["ignore_case"] else 0)
                    | ((re.MULTILINE | re.DOTALL) if a["multiline"] else 0))
except re.error as e:
    sys.stdout.write(json.dumps({"error": "invalid pattern: %s" % e}))
    sys.exit(0)

def emit(line):
    lines.append(line)
    if len(lines) > a["limit"]:
        done()

def show(text):
    text = text.rstrip("\r\n")
    return text if len(text) <= a["shown"] else text[:a["shown"]] + " [LINE TRUNCATED]"

def wanted(rel, name):
    if a["exts"] is not None and os.path.splitext(name)[1].lower() not in a["exts"]:
        return False
    g = a["glob"]
    if g:
        neg = g.startswith("!")
        pats = braces(g[1:] if neg else g)
        hit = any(fnmatch.fnmatchcase(rel if "/" in pat else name, pat) for pat in pats)
        if hit == neg:
            return False
    return True

def search(fd, display, single):
    if b"\0" in os.pread(fd, 8192, 0):
        return  # binary, skipped as ripgrep does
    prefix = "" if single and a["mode"] == "content" else display
    sep = lambda kind: (prefix + kind) if prefix else ""
    hits, last_shown = 0, 0
    before = collections.deque(maxlen=a["context"])
    after_left = 0
    if a["multiline"]:
        raw = os.pread(fd, a["multiline_per_file"], 0)
        text = raw.decode("utf-8", "replace")
        state["line_t"] = time.monotonic() + a["seconds"]  # one whole-file match: the deadline bounds it
        starts = sorted({text.count("\n", 0, m.start()) + 1 for m in rx.finditer(text)})[:1000]
        if not starts:
            return
        if a["mode"] == "files":
            return emit(display)
        if a["mode"] == "count":
            return emit("%d" % len(starts) if single else "%s:%d" % (display, len(starts)))
        all_lines = text.split("\n")
        for n in starts:
            emit("%s%d:%s" % (sep(":"), n, show(all_lines[n - 1])))
        return
    f = os.fdopen(os.dup(fd), "rb")
    with f:
        n, read = 0, 0
        while True:
            raw = f.readline(1 << 20)
            if not raw:
                break
            n += 1
            read += len(raw)
            if read > a["per_file"] or (n % 4096 == 0 and time.monotonic() > deadline):
                if time.monotonic() > deadline:
                    state["timed_out"] = True
                break
            text = raw.decode("utf-8", "replace")
            state["line_t"] = time.monotonic()
            if rx.search(text):
                hits += 1
                if a["mode"] == "files":
                    return emit(display)
                if a["mode"] == "content":
                    if a["context"] and last_shown and n - len(before) > last_shown + 1:
                        emit("--")
                    for k, t in enumerate(before):
                        emit("%s%d-%s" % (sep("-"), n - len(before) + k, show(t)))
                    before.clear()
                    emit("%s%d:%s" % (sep(":"), n, show(text)))
                    last_shown, after_left = n, a["context"]
                if hits >= 1000:
                    break
            elif after_left:
                emit("%s%d-%s" % (sep("-"), n, show(text)))
                last_shown, after_left = n, after_left - 1
            elif a["context"]:
                before.append(text)
    if a["mode"] == "count" and hits:
        emit("%d" % hits if single else "%s:%d" % (display, hits))

def join(base, rel):
    return rel if base in ("", ".") else base + "/" + rel

def walk():
    top = a["fd"]
    if not a["is_dir"]:
        search(top, a["base"], True)
        return
    walk_tree(top)

def walk_tree(top):
    stack = [(os.dup(top), "", iter(sorted(os.listdir(top))))]
    while stack:
        if time.monotonic() > deadline:
            raise Deadline()
        fd, rel, names = stack[-1]
        name = next(names, None)
        if name is None:
            os.close(fd)
            stack.pop()
            continue
        if name.startswith("."):
            continue  # hidden, skipped as ripgrep does
        try:
            st = os.stat(name, dir_fd=fd, follow_symlinks=False)
        except OSError:
            continue
        path = rel + "/" + name if rel else name
        if stat.S_ISDIR(st.st_mode):
            if len(stack) <= 64:
                try:
                    sub = os.open(name, DIRF, dir_fd=fd)
                    stack.append((sub, path, iter(sorted(os.listdir(sub)))))
                except OSError:
                    pass
            continue
        if not stat.S_ISREG(st.st_mode) or not wanted(path, name):
            continue
        try:
            f = os.open(name, FILEF, dir_fd=fd)
        except OSError:
            continue
        try:
            if stat.S_ISREG(os.fstat(f).st_mode):
                search(f, join(a["base"], path), False)
        finally:
            os.close(f)

try:
    walk()
except Deadline:
    state["timed_out"] = True
except Slow:
    signal.setitimer(signal.ITIMER_REAL, 0)
    sys.stdout.write(json.dumps({"error": "the pattern took more than %ss on one line (it backtracks); "
                                          "simplify it" % a["match_seconds"]}))
    sys.exit(0)
done()
"""
_GREP_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}


_grep_loops: "weakref.WeakKeyDictionary" = None  # type: ignore[assignment]


def _grep_slots() -> asyncio.Semaphore:
    """The search slots of the running event loop (a semaphore binds to one loop)."""
    global _grep_loops
    if _grep_loops is None:
        _grep_loops = weakref.WeakKeyDictionary()
    loop = asyncio.get_running_loop()
    slots = _grep_loops.get(loop)
    if slots is None:
        slots = _grep_loops[loop] = asyncio.Semaphore(_GREP_CONCURRENCY)
    return slots


async def _run_grep_child(full: Path, root, is_dir: bool, spec: dict) -> bytes:
    """The child's answer. The child is killed and reaped however this ends: on its
    own timeout, and on a cancel too (the chat's Stop), so none outlives its search."""
    opener = _open_dir(full, root) if is_dir else _open_file(full, root)
    with opener as opened:
        fd = opened if is_dir else opened[0]
        proc = await asyncio.create_subprocess_exec(
            sys.executable, "-I", "-S", "-c", _GREP_CHILD, json.dumps({**spec, "fd": fd}),
            pass_fds=(fd,), env=_GREP_ENV, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), _GREP_KILL_SECONDS)
        return stdout
    finally:
        if proc.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            with contextlib.suppress(Exception):
                await asyncio.shield(proc.wait())


async def fs_grep(
    pattern: str,
    path: str = ".",
    glob: Optional[str] = None,
    type: Optional[str] = None,
    output_mode: str = "files_with_matches",
    context: int = 0,
    case_insensitive: bool = False,
    multiline: bool = False,
    head_limit: int = 50,
) -> str:
    try:
        full = _resolve_safe(path)
    except ValueError as e:
        return f"Error: {e}"
    if not full.exists():
        return f"Error: not found: {path}"
    if not isinstance(pattern, str) or not pattern:
        return "Error: a pattern is required."
    exts = None
    if type:
        if type not in _GREP_TYPES:
            return f"Error: unknown file type {type!r}. Known: {', '.join(sorted(_GREP_TYPES))}."
        exts = list(_GREP_TYPES[type])
    mode = {"files_with_matches": "files", "count": "count", "content": "content"}.get(output_mode, "files")
    head_limit = max(1, min(int(head_limit or 50), 5000))
    root = _workspace_root()
    base = _rel(full)
    try:
        context = max(0, min(int(context or 0), 20))
    except (TypeError, ValueError):
        return f"Error: context must be a number, not {context!r}."
    if full.is_dir():
        is_dir = True
    elif full.is_file():
        is_dir = False
    else:
        # A pipe would block the search; a device would never end.
        return f"Error: not a regular file or folder: {path}"
    async with _grep_slots():
        try:
            stdout = await _run_grep_child(full, root, is_dir, {
                "is_dir": is_dir, "base": base, "pattern": pattern,
                "ignore_case": bool(case_insensitive), "multiline": bool(multiline),
                "mode": mode, "context": context, "limit": head_limit,
                "per_file": _GREP_FILE_MAX_BYTES, "multiline_per_file": _GREP_MULTILINE_MAX_BYTES,
                "shown": _GREP_LINE_SHOWN, "glob": glob or "", "exts": exts,
                "seconds": _GREP_SECONDS, "match_seconds": _GREP_MATCH_SECONDS,
                "cpu": _GREP_KILL_SECONDS, "memory": _GREP_CHILD_MAX_MEMORY})
        except asyncio.TimeoutError:
            return f"Error: search timed out after {_GREP_KILL_SECONDS}s."
        except (OSError, ValueError) as e:
            return f"Error: {e}"
    try:
        answer = json.loads(stdout.decode("utf-8", "replace") or "{}")
    except ValueError:
        return "Error: the search failed."
    if answer.get("error"):
        return f"Error: {answer['error']}"
    found = answer.get("lines") or []
    truncated = len(found) > head_limit
    out = "\n".join(found[:head_limit])
    if truncated:
        out += f"\n[Results truncated - showing first {head_limit}]"
    if answer.get("timed_out"):
        out += f"\n[Search stopped after {_GREP_SECONDS}s: results may be incomplete]"
    return out or "No matches found."


_GLOB_SECONDS = 10
_GLOB_MAX_MATCHES = 100_000


_GLOB_MAX_PARTS = 64
_BRACE = re.compile(r"\{([^{}]*,[^{}]*)\}")


def _expand_braces(pattern: str, limit: int = 64) -> list[str]:
    """`*.{py,txt}` as ["*.py", "*.txt"] (several groups expand together, flat ones
    only), at most `limit` alternatives."""
    todo, out = [pattern], []
    while todo:
        p = todo.pop()
        m = _BRACE.search(p)
        if m is None:
            out.append(p)
            continue
        todo.extend(p[:m.start()] + alt + p[m.end():] for alt in m.group(1).split(","))
        if len(todo) + len(out) > limit:
            raise ValueError(f"the pattern expands to more than {limit} alternatives")
    return out


class _GlobPattern:
    """A pathlib-style pattern matched one path part at a time: `**` is any number
    of folders, every other part fnmatch syntax with {a,b} alternatives. The state
    is the set of pattern positions still possible, so a match costs pattern
    length times path depth whatever the `**`s (a backtracking matcher was
    exponential in them), and a folder no state can continue in is not walked."""

    def __init__(self, pattern: str):
        parts: list = []
        for part in (p for p in pattern.split("/") if p not in ("", ".")):
            if part == "**":
                if parts and parts[-1] is None:
                    continue  # consecutive ** are one
                parts.append(None)
            else:
                alts = _expand_braces(part)
                parts.append(re.compile("|".join(f"(?:{fnmatch.translate(alt)})" for alt in alts)))
        if len(parts) > _GLOB_MAX_PARTS:
            raise ValueError(f"the pattern has more than {_GLOB_MAX_PARTS} parts")
        self.parts = parts
        self.depth = None if None in parts else len(parts)

    def _closure(self, states: set) -> frozenset:
        out, todo = set(states), list(states)
        while todo:
            j = todo.pop()
            if j < len(self.parts) and self.parts[j] is None and j + 1 not in out:
                out.add(j + 1)
                todo.append(j + 1)
        return frozenset(out)

    def start(self) -> frozenset:
        return self._closure({0})

    def step(self, states: frozenset, name: str) -> frozenset:
        nxt = set()
        for j in states:
            if j < len(self.parts):
                part = self.parts[j]
                if part is None:
                    nxt.add(j)
                elif part.match(name):
                    nxt.add(j + 1)
        return self._closure(nxt)

    def accepts(self, states: frozenset) -> bool:
        return len(self.parts) in states


async def fs_glob(pattern: str, path: Optional[str] = None) -> str:
    try:
        base = _resolve_safe(path or ".")
    except ValueError as e:
        return f"Error: {e}"
    if not base.exists():
        return f"Error: directory not found: {path}"
    if not pattern or pattern.startswith("/") or ".." in pattern.split("/"):
        return f"Error: unsupported pattern: {pattern!r} (relative, without '..')."
    try:
        found, more, timed_out = await _off_loop(_glob_walk, base, _workspace_root(), pattern)
    except (OSError, ValueError) as e:
        return f"Error: {e}"
    if not found:
        return f"No files matching pattern: {pattern}" + (
            f" (stopped after {_GLOB_SECONDS}s)" if timed_out else "")
    found.sort(key=lambda row: row[1], reverse=True)
    prefix = _rel(base)
    rows = [rel if prefix in ("", ".") else f"{prefix}/{rel}" for rel, _mtime in found[:500]]
    out = "\n".join(rows)
    total = f"{len(found)}+" if more or timed_out else str(len(found))
    if len(found) > 500 or more or timed_out:
        out += f"\n\n[Showing first {min(len(found), 500)} of {total} matches]"
    return out


def _glob_walk(base: Path, root, pattern: str):
    """fs_glob's walk, by descriptor (_walk_at: a link is matched by its name but
    never entered, so a planted link to / or /usr lists nothing behind it), only
    into folders the pattern can still match, with a deadline and a match cap."""
    glob = _GlobPattern(pattern)
    found, timed_out = [], False
    deadline = time.monotonic() + _GLOB_SECONDS
    max_depth = _WALK_MAX_DEPTH if glob.depth is None else max(0, glob.depth - 1)
    states = {"": glob.start()}

    def descend(rel: str) -> bool:
        return bool(states.get(rel))

    with _open_dir(base, root) as fd:
        try:
            for rel, _dir_fd, name, st in _walk_at(fd, deadline=deadline, max_depth=max_depth,
                                                    descend=descend):
                here = glob.step(states[rel.rpartition("/")[0]], name)
                if statlib.S_ISDIR(st.st_mode):
                    states[rel] = here
                if glob.accepts(here):
                    found.append((rel, st.st_mtime))
                    if len(found) >= _GLOB_MAX_MATCHES:
                        return found, True, False
        except _WalkTimeout:
            timed_out = True
    return found, False, timed_out


async def fs_find(
    path: Optional[str] = None,
    name: Optional[str] = None,
    mtime: Optional[str] = None,
    size: Optional[str] = None,
    type: Optional[str] = None,
    max_results: int = 200,
) -> str:
    try:
        base = _resolve_safe(path or ".")
    except ValueError as e:
        return f"Error: {e}"
    if not base.exists():
        return f"Error: directory not found: {path}"
    max_results = min(max(1, max_results), 5000)

    mtime_sec = _parse_duration(mtime) if mtime else None
    mtime_op = (mtime[0] if (mtime and mtime[0] in ("<", ">")) else ">") if mtime else None
    size_bytes = _parse_size(size) if size else None
    size_op = (size[0] if (size and size[0] in ("<", ">")) else ">") if size else None

    now = time.time()
    results: list[str] = []

    def _match(entry: str, st: os.stat_result) -> bool:
        # The walk's lstat: a planted link never answers questions about its target.
        if name and not fnmatch.fnmatch(entry, name):
            return False
        if type:
            if type == "file" and not statlib.S_ISREG(st.st_mode):
                return False
            if type == "dir" and not statlib.S_ISDIR(st.st_mode):
                return False
            if type == "symlink" and not statlib.S_ISLNK(st.st_mode):
                return False
        if mtime_sec is not None:
            age = now - st.st_mtime
            if mtime_op == "<" and age >= mtime_sec:
                return False
            if mtime_op == ">" and age <= mtime_sec:
                return False
        if size_bytes is not None:
            if size_op == "<" and st.st_size >= size_bytes:
                return False
            if size_op == ">" and st.st_size <= size_bytes:
                return False
        return True

    root, prefix = _workspace_root(), _rel(base)

    def walk() -> list[str]:
        # By descriptor, off the event loop: a folder swapped for a link is never
        # entered, so nothing outside the project is listed.
        with _open_dir(base, root) as fd:
            try:
                for rel, _dir_fd, entry, st in _walk_at(fd, deadline=time.monotonic() + 30):
                    if _match(entry, st):
                        results.append(rel if prefix in ("", ".") else f"{prefix}/{rel}")
                        if len(results) >= max_results:
                            results.append(f"[truncated at {max_results}]")
                            break
            except _WalkTimeout:
                results.append("[walk timeout after 30s]")
        return results

    try:
        await _off_loop(walk)
    except Exception as e:
        return f"Error during walk: {e}"
    return "\n".join(results) if results else "No matches found."


async def fs_list(path: str = ".") -> str:
    try:
        target = _resolve_safe(path)
    except ValueError as e:
        return f"Error: {e}"
    if not target.is_dir():
        return f"Error: not a directory: {path}"
    root = _workspace_root()
    try:
        with _open_dir(target, root) as fd:
            listed = _listing_at(fd, root)
    except (OSError, ValueError) as e:
        return f"Error: {e}"
    listed.sort(key=lambda row: (not row[2], row[0].lower()))
    rows = []
    for name, st, is_dir, is_link in listed[:200]:
        if is_dir:
            kind = "dir"
        elif is_link:
            kind = "lnk"
        else:
            kind = "   "
        if st is None:
            sz, mt = "?", "?"
        else:
            sz = _fmt_size(st.st_size) if statlib.S_ISREG(st.st_mode) else "-"
            mt = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(timespec="seconds")
        rows.append(f"{kind}  {sz:>6}  {mt}  {name}")
    out = "\n".join(rows)
    total = len(listed)
    if total > 200:
        out += f"\n\n[Showing first 200 of {total} entries]"
    return out or "(empty directory)"


async def fs_tree(path: str = ".", max_depth: int = 3, max_entries: int = 500) -> str:
    try:
        base = _resolve_safe(path)
    except ValueError as e:
        return f"Error: {e}"
    if not base.is_dir():
        return f"Error: not a directory: {path}"
    return "\n".join(_tree_rows(base, _workspace_root(), (_rel(base) or ".") + "/",
                                max_depth, max_entries))


def _tree_rows(base: Path, root, first: str, max_depth: int, max_entries: int) -> list[str]:
    """The ASCII tree of fs_tree and the drawer, read by descriptor: each folder is
    opened from its parent with O_NOFOLLOW, so a folder swapped for a link lists
    nothing outside the project. A link to a folder inside the project is shown
    as one but not entered."""
    rows = [first]
    count = [1]

    def _walk(dir_fd: int, depth: int, prefix: str):
        if depth > max_depth or count[0] >= max_entries:
            return
        try:
            names = [n for n in os.listdir(dir_fd) if not n.startswith(".") and n not in _SKIP_DIRS]
            children = _listing_at(dir_fd, root, names)
            children.sort(key=lambda row: (not row[2], row[0].lower()))
        except Exception:
            return
        for i, (name, _st, is_dir, is_link) in enumerate(children):
            if count[0] >= max_entries:
                rows.append(f"{prefix}└── [truncated at {max_entries} entries]")
                return
            last = i == len(children) - 1
            branch = "└── " if last else "├── "
            suffix = "/" if is_dir else ""
            rows.append(f"{prefix}{branch}{name}{suffix}")
            count[0] += 1
            if is_dir and not is_link:
                try:
                    sub = os.open(name, _DIR_OPEN, dir_fd=dir_fd)
                except OSError:
                    continue
                try:
                    _walk(sub, depth + 1, prefix + ("    " if last else "│   "))
                finally:
                    os.close(sub)

    try:
        with _open_dir(base, root) as fd:
            _walk(fd, 1, "")
    except (OSError, ValueError):
        pass
    return rows


# Ext -> tree-sitter language name
_EXT_TO_LANG = {
    ".py": "python", ".js": "javascript", ".ts": "typescript", ".tsx": "typescript",
    ".jsx": "javascript", ".java": "java", ".go": "go", ".rs": "rust",
    ".rb": "ruby", ".php": "php", ".c": "c", ".cpp": "cpp", ".cs": "c_sharp",
    ".kt": "kotlin", ".swift": "swift", ".scala": "scala",
}
_DEFINITION_TYPES = {
    "python": ["function_definition", "class_definition", "decorated_definition"],
    "javascript": ["function_declaration", "class_declaration", "method_definition", "arrow_function", "variable_declarator"],
    "typescript": ["function_declaration", "class_declaration", "method_definition", "arrow_function", "variable_declarator", "interface_declaration", "type_alias_declaration"],
    "java": ["class_declaration", "method_declaration", "interface_declaration"],
    "go": ["function_declaration", "method_declaration", "type_declaration"],
    "rust": ["function_item", "impl_item", "struct_item", "enum_item", "trait_item"],
    "ruby": ["method", "class", "module", "singleton_method"],
    "php": ["function_definition", "class_declaration", "method_declaration"],
    "c": ["function_definition", "struct_specifier"],
    "cpp": ["function_definition", "class_specifier", "struct_specifier"],
    "c_sharp": ["class_declaration", "method_declaration", "interface_declaration"],
}


_MARKDOWN_EXTS = (".md", ".markdown", ".mdown", ".mkd")


def _markdown_symbols(full: Path, rel_path: str) -> str:
    try:
        text = _text(_read_file(full, _workspace_root(), rel_path), errors="replace")
    except Exception as e:
        return f"Error parsing {rel_path}: {e}"
    headers: list[tuple[int, str, int, int]] = []
    lines = text.splitlines()
    in_fence = False
    fence_marker: str | None = None
    atx_re = re.compile(r"^\s{0,3}(#{1,6})\s+(.+?)\s*#*\s*$")
    setext_re = re.compile(r"^(=+|-+)\s*$")
    for idx, line in enumerate(lines):
        stripped = line.lstrip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            marker = stripped[:3]
            if not in_fence:
                in_fence, fence_marker = True, marker
            elif fence_marker and stripped.startswith(fence_marker):
                in_fence, fence_marker = False, None
            continue
        if in_fence:
            continue
        m = atx_re.match(line)
        if m:
            headers.append((len(m.group(1)), m.group(2).strip(), idx + 1, idx + 1))
            continue
        if idx > 0 and setext_re.match(line):
            prev = lines[idx - 1].strip()
            if prev and not prev.startswith("#") and not atx_re.match(lines[idx - 1]):
                level = 1 if line.lstrip().startswith("=") else 2
                headers.append((level, prev, idx, idx + 1))
    if not headers:
        return f"No definitions found in {rel_path}."
    out = [f"Symbols in {rel_path} ({len(headers)} defs):"]
    for level, name, start, end in headers[:500]:
        indent = "  " * (level - 1)
        out.append(f"{indent}h{level} {name}  [{start}-{end}]")
    return "\n".join(out)


async def fs_symbols(file_path: str) -> str:
    try:
        full = _resolve_safe(file_path)
    except ValueError as e:
        return f"Error: {e}"
    if not full.exists():
        return f"Error: file not found: {file_path}"
    if full.suffix.lower() in _MARKDOWN_EXTS:
        return _markdown_symbols(full, file_path)
    lang = _EXT_TO_LANG.get(full.suffix)
    if not lang:
        supported = ", ".join(list(_EXT_TO_LANG) + list(_MARKDOWN_EXTS))
        return f"Error: unsupported language for {full.suffix}. Supported: {supported}"
    try:
        from tree_sitter_languages import get_parser
        parser = get_parser(lang)
    except Exception as e:
        return f"Error: tree-sitter parser unavailable for {lang}: {e}"

    def _extract_name(node):
        for child in node.children:
            if child.type in ("identifier", "name", "property_identifier", "type_identifier"):
                return child.text.decode("utf-8")
        return None

    def _walk(node, depth=0, parent_name=None):
        defs = []
        types = _DEFINITION_TYPES.get(lang, [])
        for c in node.children:
            if c.type in types:
                nm = _extract_name(c)
                if nm:
                    kind = c.type.replace("_definition", "").replace("_declaration", "").replace("_item", "")
                    scope = f"{parent_name} > " if parent_name else ""
                    defs.append({
                        "name": nm, "kind": kind, "scope": scope, "depth": depth,
                        "start_line": c.start_point[0] + 1, "end_line": c.end_point[0] + 1,
                    })
                    defs.extend(_walk(c, depth + 1, nm))
            else:
                defs.extend(_walk(c, depth, parent_name))
        return defs

    try:
        tree = parser.parse(_read_file(full, _workspace_root(), file_path))
        defs = _walk(tree.root_node)
    except Exception as e:
        return f"Error parsing {file_path}: {e}"
    if not defs:
        return f"No definitions found in {file_path}."
    lines = [f"Symbols in {file_path} ({len(defs)} defs):"]
    for d in defs[:500]:
        lines.append(
            f"{'  ' * d['depth']}{d['kind']} {d['scope']}{d['name']}  "
            f"[{d['start_line']}-{d['end_line']}]"
        )
    return "\n".join(lines)


async def fs_symlink_read(path: str) -> str:
    try:
        full = _resolve_safe(path, follow_symlinks=False)
    except ValueError as e:
        return f"Error: {e}"
    try:
        # Read through the pinned folder: a link in a folder above (say to
        # /proc/self) must not reveal the agent's own links.
        with _pinned_parent(full, _workspace_root()) as (dir_fd, name):
            return f"{path} -> {os.readlink(name, dir_fd=dir_fd)}"
    except (FileNotFoundError, OSError) as e:
        if isinstance(e, FileNotFoundError) or e.errno == errno.EINVAL:
            return f"Error: {path} is not a symlink."
        return f"Error: {e}"
    except ValueError as e:
        return f"Error: {e}"


# =============================================================================
# INTEGRITY & ARCHIVE (4)
# =============================================================================

async def fs_hash(path: str, algo: str = "sha256") -> str:
    if algo not in ("sha256", "md5"):
        return "Error: algo must be sha256 or md5."
    try:
        full = _resolve_safe(path)
    except ValueError as e:
        return f"Error: {e}"
    if not full.is_file():
        return f"Error: not a file: {path}"
    try:
        digest = await _off_loop(_hash_file, full, _workspace_root(), algo)
    except ValueError as e:
        return f"Error: {e}"
    if digest is None:
        return f"Error: {path} is larger than the {_hash_max_bytes()} bytes fs_hash reads."
    return f"{algo}({path}) = {digest}"


async def fs_diff(
    path_a: str,
    path_b: Optional[str] = None,
    vs_last_read: bool = False,
) -> str:
    if vs_last_read:
        try:
            full = _resolve_safe(path_a)
        except ValueError as e:
            return f"Error: {e}"
        key = (_project_id(), _rel(full))
        prior, digest = _last_read_contents.get(key), _last_read_hashes.get(key)
        if digest is None:
            return f"Error: no fs_read snapshot for {path_a}. Call fs_read first."
        if prior is None:
            # A file too large to keep a copy of: its hash (or, past the hash cap,
            # its size and mtime) still says whether it changed.
            try:
                if not full.exists():
                    now = None
                elif digest.startswith("stat:"):
                    now = await _off_loop(_stat_digest_of, full, _workspace_root())
                else:
                    now = await _off_loop(_hash_stream, full, _workspace_root())
            except ValueError as e:
                return f"Error: {e}"
            if now == digest:
                return "(no changes since last fs_read)"
            return (f"{path_a} changed since the last fs_read (it is too large to keep a copy "
                    "for a line diff: fs_read it again).")
        try:
            cur = _read_file(full, _workspace_root(), path_a) if full.exists() else b""
        except ValueError as e:
            return f"Error: {e}"
        if hashlib.sha256(cur).hexdigest() == digest:
            return "(no changes since last fs_read)"
        a_text = prior.decode("utf-8", errors="replace")
        b_text = cur.decode("utf-8", errors="replace")
        diff = difflib.unified_diff(
            a_text.splitlines(keepends=True), b_text.splitlines(keepends=True),
            fromfile=f"a/{path_a} (last fs_read)", tofile=f"b/{path_a} (current)",
        )
        out = "".join(diff)
        return out or "(no changes since last fs_read)"

    if not path_b:
        return "Error: provide path_b (or set vs_last_read=True)."
    try:
        fa = _resolve_safe(path_a)
        fb = _resolve_safe(path_b)
    except ValueError as e:
        return f"Error: {e}"
    if not fa.exists() or not fb.exists():
        return "Error: one or both files not found."
    try:
        a_text = _text(_read_file(fa, _workspace_root(), path_a), errors="replace")
        b_text = _text(_read_file(fb, _workspace_root(), path_b), errors="replace")
    except ValueError as e:
        return f"Error: {e}"
    diff = difflib.unified_diff(
        a_text.splitlines(keepends=True), b_text.splitlines(keepends=True),
        fromfile=f"a/{path_a}", tofile=f"b/{path_b}",
    )
    out = "".join(diff)
    return out or "(files identical)"


async def fs_extract(archive_path: str, dest: str, format: str = "auto") -> str:
    try:
        archive = _resolve_safe(archive_path)
        dest_p = _resolve_safe(dest)
    except ValueError as e:
        return f"Error: {e}"
    if not archive.exists():
        return f"Error: archive not found: {archive_path}"
    try:
        _makedirs(dest_p, _workspace_root())
    except ValueError as e:
        return f"Error: {e}"

    fmt = format
    if fmt == "auto":
        n = archive.name.lower()
        if n.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tbz", ".tar")):
            fmt = "tar"
        elif n.endswith(".zip"):
            fmt = "zip"
        elif n.endswith(".gz"):
            fmt = "gz"
        else:
            return f"Error: cannot auto-detect format for {archive_path}. Pass format='tar'|'zip'|'gz'."

    try:
        af = _open_binary(archive, _workspace_root())
    except (OSError, ValueError) as e:
        return f"Error: {e}"
    with af:
        try:
            return await _off_loop(_extract_from, af, fmt, archive, archive_path, dest, dest_p)
        except ValueError as e:
            return f"Error: {e}. Aborted."


class _ExtractTooBig(Exception):
    pass


def _member_parts(name: str) -> Optional[list[str]]:
    """A member's path as folder names under dest, or None when it leaves dest."""
    norm = posixpath.normpath(name.replace("\x00", ""))
    if norm.startswith("/") or norm == ".." or norm.startswith("../"):
        return None
    return [part for part in norm.split("/") if part not in ("", ".")]


def _mkdirs_at(dir_fd: int, parts: list[str]) -> int:
    """A new descriptor on dir_fd/parts, each missing folder created, every level
    opened O_NOFOLLOW: a link (one a sandbox planted, or one the archive made)
    is never gone through (ValueError)."""
    fd = os.dup(dir_fd)
    try:
        for part in parts:
            try:
                nfd = os.open(part, _DIR_OPEN, dir_fd=fd)
            except FileNotFoundError:
                with contextlib.suppress(FileExistsError):
                    os.mkdir(part, 0o777, dir_fd=fd)
                try:
                    nfd = os.open(part, _DIR_OPEN, dir_fd=fd)
                except OSError:
                    raise ValueError(f"'{part}' is not a folder in dest") from None
            except OSError:
                raise ValueError(f"'{part}' is a link or a file in dest, not a folder") from None
            os.close(fd)
            fd = nfd
        return fd
    except BaseException:
        os.close(fd)
        raise


def _extract_from(af, fmt: str, archive: Path, archive_path: str, dest: str, dest_p: Path) -> str:
    """fs_extract's body, reading the archive from `af`: the descriptor checked."""
    dest_resolved = dest_p.resolve()
    root = _workspace_root()

    def _safe(member_name: str) -> bool:
        candidate = (dest_p / member_name).resolve()
        return candidate == dest_resolved or dest_resolved in candidate.parents

    def _safe_link(member) -> bool:
        # A tar entry may be a symlink/hardlink whose *target* escapes dest even
        # when its name does not (e.g. a link named "ok" pointing at
        # "../../etc/passwd"). extractall(filter="data") guards this on 3.12+,
        # but we validate explicitly so the check holds on every runtime.
        link = getattr(member, "linkname", "") or ""
        if not link:
            return True
        if os.path.isabs(link):
            return False
        if member.issym():
            base = dest_p / os.path.dirname(member.name)
        else:  # hardlink target is relative to the archive root
            base = dest_p
        candidate = (base / link).resolve()
        return candidate == dest_resolved or dest_resolved in candidate.parents

    # D10: zip/tar-bomb defense. Cap entry count and total DECLARED uncompressed
    # size before extracting, and stream the gz path with a byte ceiling, so a
    # small crafted archive cannot inflate to tens of GB and OOM the agent. Env-
    # overridable with generous defaults.
    max_entries = _int_env("FS_EXTRACT_MAX_ENTRIES", 5000)
    max_total = _int_env("FS_EXTRACT_MAX_TOTAL_BYTES", 500 * 1024 * 1024)

    def _special(member_name: str) -> bool:
        # tar and zip open an existing entry to write a member over it: a pipe
        # planted at that name would block the extraction (and the event loop).
        try:
            mode = os.lstat(dest_p / member_name).st_mode
        except OSError:
            return False
        return not (statlib.S_ISREG(mode) or statlib.S_ISDIR(mode) or statlib.S_ISLNK(mode))

    # Every member is written under dest's own descriptors (_extract_member): a
    # link a sandbox plants in dest while the archive is extracted is replaced,
    # never written through, and the data is counted against max_total as it
    # streams (a declared size can lie).
    written = [0]

    def stream(src, fd, mode=None):
        while chunk := src.read(1 << 20):
            written[0] += len(chunk)
            if written[0] > max_total:
                raise _ExtractTooBig()
            _write_all(fd, chunk)
        if mode is not None:
            os.fchmod(fd, mode)

    if fmt == "tar":
        with tarfile.open(fileobj=af, mode="r:*") as tf:
            members = tf.getmembers()
            if len(members) > max_entries:
                return f"Error: archive has too many entries ({len(members)}; max {max_entries}). Aborted."
            total = sum(max(0, m.size) for m in members)
            if total > max_total:
                return f"Error: archive decompresses too large ({total} bytes; max {max_total}). Aborted."
            for m in members:
                if not _safe(m.name):
                    return f"Error: tar-slip attempt detected for entry '{m.name}'. Aborted."
                if (m.issym() or m.islnk()) and not _safe_link(m):
                    return f"Error: unsafe link target in entry '{m.name}' -> '{m.linkname}'. Aborted."
                if _special(m.name):
                    return f"Error: '{m.name}' already exists in dest and is not a regular file. Aborted."
                parts = _member_parts(m.name)
                if parts is None:
                    return f"Error: tar-slip attempt detected for entry '{m.name}'. Aborted."
                if len(parts) > _EXTRACT_MAX_DEPTH:
                    return (f"Error: entry '{m.name[:200]}' nests folders more than "
                            f"{_EXTRACT_MAX_DEPTH} levels deep. Aborted.")
            try:
                with _open_dir(dest_p, root) as dest_fd:
                    for m in members:
                        _extract_member(tf, m, dest_fd, stream)
            except _ExtractTooBig:
                return f"Error: archive data exceeds max size ({max_total} bytes). Aborted."
            return f"Extracted {len(members)} entries from {archive_path} -> {dest}."
    if fmt == "zip":
        with zipfile.ZipFile(af, "r") as zf:
            infos = zf.infolist()
            if len(infos) > max_entries:
                return f"Error: archive has too many entries ({len(infos)}; max {max_entries}). Aborted."
            total = sum(max(0, i.file_size) for i in infos)
            if total > max_total:
                return f"Error: archive decompresses too large ({total} bytes; max {max_total}). Aborted."
            for i in infos:
                if not _safe(i.filename):
                    return f"Error: zip-slip attempt detected for entry '{i.filename}'. Aborted."
                if _special(i.filename):
                    return f"Error: '{i.filename}' already exists in dest and is not a regular file. Aborted."
                parts = _member_parts(i.filename)
                if parts is None:
                    return f"Error: zip-slip attempt detected for entry '{i.filename}'. Aborted."
                if len(parts) > _EXTRACT_MAX_DEPTH:
                    return (f"Error: entry '{i.filename[:200]}' nests folders more than "
                            f"{_EXTRACT_MAX_DEPTH} levels deep. Aborted.")
            try:
                with _open_dir(dest_p, root) as dest_fd:
                    for i in infos:
                        _extract_zip_member(zf, i, dest_fd, stream)
            except _ExtractTooBig:
                return f"Error: archive data exceeds max size ({max_total} bytes). Aborted."
            return f"Extracted {len(infos)} entries from {archive_path} -> {dest}."
    if fmt == "gz":
        out_name = archive.stem  # strips trailing .gz
        out_path = (dest_p / out_name).resolve()
        if out_path != dest_resolved and dest_resolved not in out_path.parents:
            return "Error: extraction would escape dest."

        if out_name in ("", ".", ".."):
            return "Error: extraction would escape dest."

        # gz carries no reliable declared size; stream with a hard byte ceiling.
        def fill(fd):
            with gzip.GzipFile(fileobj=af, mode="rb") as gz:
                stream(gz, fd)

        try:
            with _open_dir(dest_p, root) as dest_fd:
                _replace_at(dest_fd, out_name, fill)
        except _ExtractTooBig:
            return f"Error: gz stream exceeds max size ({max_total} bytes). Aborted."
        except ValueError as e:
            return f"Error: {e}"
        return f"Extracted 1 file from {archive_path} -> {dest}/{out_name}."
    return f"Error: unsupported format '{fmt}'."


def _tar_data_mode(mode: int) -> int:
    # tarfile's "data" filter: no setuid/setgid/sticky, no group/other write,
    # and the owner can always read and write.
    return (mode & 0o777 & ~0o022) | 0o600


def _write_member_link(dir_fd: int, name: str, target: str) -> None:
    tmp = f".redamon-{uuid.uuid4().hex}.lnk"
    os.symlink(target, tmp, dir_fd=dir_fd)
    try:
        os.replace(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp, dir_fd=dir_fd)
        raise


def _extract_member(tf, m, dest_fd: int, stream) -> None:
    parts = _member_parts(m.name)
    if not parts:
        return
    if m.isdir():
        os.close(_mkdirs_at(dest_fd, parts))
        return
    parent = _mkdirs_at(dest_fd, parts[:-1])
    try:
        if m.isreg() or m.islnk():
            src = tf.extractfile(m)  # a hard link reads its target member's data
            if src is not None:
                with src:
                    _replace_at(parent, parts[-1], lambda fd: stream(src, fd, _tar_data_mode(m.mode)))
        elif m.issym():
            _write_member_link(parent, parts[-1], m.linkname)
        # Devices, pipes and anything else are not extracted.
    finally:
        os.close(parent)


def _extract_zip_member(zf, info, dest_fd: int, stream) -> None:
    parts = _member_parts(info.filename)
    if not parts:
        return
    if info.is_dir():
        os.close(_mkdirs_at(dest_fd, parts))
        return
    parent = _mkdirs_at(dest_fd, parts[:-1])
    try:
        with zf.open(info) as src:
            _replace_at(parent, parts[-1], lambda fd: stream(src, fd))
    finally:
        os.close(parent)


async def fs_archive(paths: list, dest: str, format: str = "tar.gz") -> str:
    if not isinstance(paths, list) or not paths:
        return "Error: paths must be a non-empty list."
    if format not in ("tar.gz", "zip"):
        return "Error: format must be tar.gz or zip."
    try:
        dest_p = _resolve_safe(dest)
        resolved_inputs = [_resolve_safe(p) for p in paths]
    except ValueError as e:
        return f"Error: {e}"
    for p in resolved_inputs:
        if not p.exists():
            return f"Error: not found: {_rel(p)}"
    try:
        _makedirs(dest_p.parent, _workspace_root())
    except ValueError as e:
        return f"Error: {e}"
    root = _workspace_root()
    n, budget, cut = 0, [_archive_max_bytes()], []

    # Written as a fresh file renamed onto dest: a pipe or a link planted at dest
    # is replaced, never opened. Each input is read by descriptor (_archive_add).
    def fill(fd):
        nonlocal n
        with os.fdopen(os.dup(fd), "wb") as out, _open_archive_writer(out, format) as archive:
            for p in resolved_inputs:
                if _archive_add(archive, format, p, root, p.name, budget, cut):
                    n += 1

    try:
        await _off_loop(_replace_with, dest_p, root, fill)
    except ValueError as e:
        return f"Error: {e}"
    if cut:
        return (f"Archived {n} entries -> {dest} ({format}), without {len(cut)} folder(s) nested "
                f"deeper than {_WALK_MAX_DEPTH} levels (first: {cut[0]}).")
    return f"Archived {n} entries -> {dest} ({format})."


# =============================================================================
# Dispatch (name -> coroutine). Wired into PhaseAwareToolExecutor._invoke().
# =============================================================================

# =============================================================================
# Public helpers for HTTP endpoints (project-explicit, no contextvar dependency)
# =============================================================================
# These are used by api.py /workspace/* routes. They take project_id as an
# argument instead of reading the contextvar so the HTTP layer doesn't have
# to fiddle with contextvar state per request.

#: Where the agent and kali-sandbox mount every project's workspace (compose). A
#: file the agent writes for the person is named `/workspace/<projectId>/...`,
#: the only absolute form the webapp's download route accepts. Fixed, unlike
#: WORKSPACE_ROOT (the agent's own mount, which tests move).
SANDBOX_WORKSPACE_ROOT = "/workspace"


def sandbox_workspace_relative(project_id: str, path: Optional[str]) -> Optional[str]:
    """`path` relative to project `project_id`'s workspace, or None when it points
    anywhere else.

    `path` is absolute under `/workspace/<projectId>/` (as the sandbox and a chat
    download card name it) or already workspace-relative. An empty, `.` or `..`
    segment, a backslash or a NUL is refused, so nothing climbs out before
    resolve_for_project's own confinement, which also refuses a symlink escape.
    """
    try:
        _validate_project_id(project_id)
    except ValueError:
        return None
    if not isinstance(path, str) or not path or "\\" in path or "\x00" in path:
        return None
    if path.startswith("/"):
        prefix = f"{SANDBOX_WORKSPACE_ROOT}/{project_id}/"
        if not path.startswith(prefix):
            return None
        path = path[len(prefix):]
    if any(part in ("", ".", "..") for part in path.split("/")):
        return None
    return path


def resolve_for_project(project_id: str, user_path: Optional[str], follow_symlinks: bool = True) -> Path:
    """Public variant of _resolve_safe that takes project_id explicitly."""
    _validate_project_id(project_id)
    root = (WORKSPACE_ROOT / project_id).resolve()
    root.mkdir(parents=True, exist_ok=True)
    for sub in _DEFAULT_SUBDIRS:
        (root / sub).mkdir(exist_ok=True)
    if user_path in (None, "", ".", "/"):
        return root
    p = Path(user_path)
    if p.is_absolute():
        if follow_symlinks:
            try:
                resolved = p.resolve()
            except Exception:
                raise ValueError(f"absolute path not allowed: {user_path}")
        else:
            resolved = Path(os.path.normpath(str(p)))
        if resolved == root or root in resolved.parents:
            return resolved
        raise ValueError(f"absolute path not allowed: {user_path}")
    if follow_symlinks:
        candidate = (root / user_path).resolve()
    else:
        candidate = Path(os.path.normpath(str(root / user_path)))
    if candidate != root and root not in candidate.parents:
        raise ValueError(f"path escapes workspace: {user_path}")
    return candidate


def list_dir_for_project(project_id: str, path: str = ".") -> list[dict]:
    """Directory entries as structured dicts for the frontend drawer, listed
    through the folder's own descriptor (_listing_at)."""
    target = resolve_for_project(project_id, path)
    if not target.is_dir():
        raise ValueError(f"not a directory: {path}")
    rows = []
    root = (WORKSPACE_ROOT / project_id).resolve()
    with _open_dir(target, root) as fd:
        listed = _listing_at(fd, root)
    for name, st, is_dir, is_link in sorted(listed, key=lambda row: (not row[2], row[0].lower())):
        if st is None:
            logger.warning(f"list_dir: skipped {target / name}")
            continue
        rows.append({
            "name": name,
            "path": str((target / name).relative_to(root)),
            "isDir": is_dir,
            "isSymlink": is_link,
            "size": st.st_size,
            "mtime": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(timespec="seconds"),
        })
    return rows


def list_dir_page(project_id: str, path: str = ".", limit: int = 2000) -> tuple[list[dict], int]:
    """The first `limit` entries of a directory, dirs first then by name, and
    the total count. Only the page is stat'ed: the drawer polls this every few
    seconds, and an imported tree can hold tens of thousands of entries. Listed
    and stat'ed through the folder's own descriptor (_listing_at)."""
    target = resolve_for_project(project_id, path)
    if not target.is_dir():
        raise ValueError(f"not a directory: {path}")
    root = (WORKSPACE_ROOT / project_id).resolve()

    def _is_dir(e: os.DirEntry) -> bool:
        # Not following a link: the order must not reveal what a link points at.
        try:
            return e.is_dir(follow_symlinks=False)
        except OSError:
            return False

    rows = []
    with _open_dir(target, root) as fd:
        with os.scandir(fd) as it:
            entries = [(e.name, _is_dir(e)) for e in it]
        entries.sort(key=lambda e: (not e[1], e[0].lower()))
        page = _listing_at(fd, root, [name for name, _d in entries[:max(0, limit)]])
    for name, st, is_dir, is_link in page:
        full = target / name
        try:
            if st is None:
                raise OSError("vanished")
            # A signed record of this project, not just a file of that name.
            record = _provenance.read(full, project_id=project_id) \
                if is_dir and not is_link and os.path.isfile(os.path.join(full, _provenance.FILENAME)) \
                else None
            row = {
                "name": name,
                "path": str(full.relative_to(root)),
                "isDir": is_dir,
                "isSymlink": is_link,
                "size": st.st_size,
                "mtime": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(timespec="seconds"),
                "imported": record is not None,
            }
            if record is not None:
                facts = import_facts(record)
                row["importKind"] = facts["kind"]
                row["resyncable"] = facts["resyncable"]
            rows.append(row)
        except Exception as e:
            logger.warning(f"list_dir: skipped {full}: {e}")
    return rows, len(entries)


def tree_for_project(project_id: str, path: str = ".", max_depth: int = 3, max_entries: int = 500) -> str:
    """ASCII tree as a single string (for the drawer's tree view)."""
    base = resolve_for_project(project_id, path)
    if not base.is_dir():
        raise ValueError(f"not a directory: {path}")
    root = (WORKSPACE_ROOT / project_id).resolve()
    first = (str(base.relative_to(root)) if base != root else ".") + "/"
    return "\n".join(_tree_rows(base, root, first, max_depth, max_entries))


def download_for_project(project_id: str, path: str) -> tuple[bytes, str]:
    """Returns (content_bytes, mime_type). Raises ValueError on bad path."""
    full = resolve_for_project(project_id, path)
    if not full.is_file():
        raise ValueError(f"not a file: {path}")
    mime = mimetypes.guess_type(str(full))[0] or "application/octet-stream"
    return _read_file(full, (WORKSPACE_ROOT / project_id).resolve(), path), mime


def project_relative(project_id: str, user_path: Optional[str], follow_symlinks: bool = False) -> str:
    """`user_path` (relative or absolute) as a normalized project-relative path,
    '.' for the root. Raises ValueError when it escapes the project."""
    full = resolve_for_project(project_id, user_path, follow_symlinks=follow_symlinks)
    root = (WORKSPACE_ROOT / project_id).resolve()
    return "." if full == root else str(full.relative_to(root))


def check_not_busy(project_id: str, user_path: Optional[str]) -> None:
    """Refuse a mutation a running import would undo (workspace_import.busy).
    Both the path as written and where its symlinks lead are checked; any error
    in the check refuses."""
    try:
        for follow in (False, True):
            try:
                rel = project_relative(project_id, user_path, follow_symlinks=follow)
            except ValueError:
                continue
            _busy.check_mutation(project_id, rel)
    except Exception as e:
        if getattr(e, "code", None) == "busy":
            raise
        raise _busy.ImportFailure("busy", detail="unknown") from None


def open_download_for_project(project_id: str, path: str) -> tuple[int, int, str, str]:
    """Open a workspace file for streaming: (fd, size, mime, filename).

    The descriptor checked is the descriptor streamed. The workspace is writable
    by the agent, kali-sandbox and the host, so a component swapped for a
    symlink between a check and a later open-by-path would escape: the last
    component is opened with O_NOFOLLOW, and the opened file's real path is
    checked against the project root. O_NONBLOCK keeps a FIFO from hanging the
    open; fstat then refuses anything that is not a regular file.
    """
    full = resolve_for_project(project_id, path)
    root = str((WORKSPACE_ROOT / project_id).resolve())
    try:
        fd = os.open(full, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise ValueError(f"not a file: {path}") from None
    try:
        st = os.fstat(fd)
        if not statlib.S_ISREG(st.st_mode):
            raise ValueError(f"not a file: {path}")
        real = os.readlink(f"/proc/self/fd/{fd}")
        if real != root and not real.startswith(root + os.sep):
            raise ValueError(f"path escapes workspace: {path}")
    except OSError:
        os.close(fd)
        raise ValueError(f"not a file: {path}") from None
    except BaseException:
        os.close(fd)
        raise
    mime = mimetypes.guess_type(str(full))[0] or "application/octet-stream"
    return fd, st.st_size, mime, os.path.basename(str(full)) or "download"


def rename_for_project(project_id: str, path: str, new_name: str) -> str:
    """Rename a single entry within its parent dir. Returns new relative path."""
    if is_protected_path(path):
        raise ValueError(f"cannot rename protected path: {path}")
    if (not new_name or not new_name.strip() or "/" in new_name
            or "\x00" in new_name or new_name in ("..", ".")):
        raise ValueError(f"invalid new_name: {new_name!r}")
    full = resolve_for_project(project_id, path)
    if not (full.exists() or full.is_symlink()):
        raise ValueError(f"not found: {path}")
    new_full = full.parent / new_name
    # Re-validate the new path to be sure it stays in-workspace
    new_rel = str(new_full.relative_to((WORKSPACE_ROOT / project_id).resolve()))
    resolve_for_project(project_id, new_rel)
    check_not_busy(project_id, path)
    check_not_busy(project_id, new_rel)
    if new_full.exists() or new_full.is_symlink():
        raise ValueError(f"destination already exists: {new_name}")
    root = (WORKSPACE_ROOT / project_id).resolve()
    with _pinned_parent(full, root) as (dir_fd, name):
        try:
            os.stat(new_name, dir_fd=dir_fd, follow_symlinks=False)
            raise ValueError(f"destination already exists: {new_name}")
        except FileNotFoundError:
            pass
        os.rename(name, new_name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
    return str(new_full.relative_to(root))


def delete_for_project(project_id: str, path: str, recursive: bool = False) -> None:
    if is_protected_path(path):
        raise ValueError(f"cannot delete protected path: {path}")
    full = resolve_for_project(project_id, path)
    if not (full.exists() or full.is_symlink()):
        raise ValueError(f"not found: {path}")
    check_not_busy(project_id, path)
    with _pinned_parent(full, (WORKSPACE_ROOT / project_id).resolve()) as (dir_fd, name):
        if statlib.S_ISDIR(os.stat(name, dir_fd=dir_fd, follow_symlinks=False).st_mode) and not recursive:
            raise ValueError(f"{path} is a directory (pass recursive=True)")
        _remove_at(dir_fd, name)


def reset_for_project(project_id: str) -> dict:
    """Wipe the entire workspace back to its initial state.

    Removes every entry under the project root, then re-creates the four
    PROTECTED_SUBDIRS empty. Returns a small summary so the caller can
    confirm what was removed.
    """
    root = _workspace_root_for(project_id).resolve()
    removed_entries = 0
    removed_protected_children = 0
    # By descriptor all the way down: a default folder a sandbox swaps for a link
    # after the check must not have the files it points at emptied.
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for name in os.listdir(root_fd):
            mode = os.stat(name, dir_fd=root_fd, follow_symlinks=False).st_mode
            if name in PROTECTED_SUBDIRS and statlib.S_ISDIR(mode):
                child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                   dir_fd=root_fd)
                try:
                    for sub in os.listdir(child_fd):
                        _remove_at(child_fd, sub)
                        removed_protected_children += 1
                finally:
                    os.close(child_fd)
                continue
            _remove_at(root_fd, name)
            removed_entries += 1
    finally:
        os.close(root_fd)
    for sub in _DEFAULT_SUBDIRS:
        (root / sub).mkdir(exist_ok=True)
    return {
        "removed_top_level": removed_entries,
        "removed_protected_children": removed_protected_children,
        "default_subdirs": list(_DEFAULT_SUBDIRS),
    }


# =============================================================================
# Stage A additions: upload, mkdir, archive-download, preview, properties
# =============================================================================


def upload_for_project(
    project_id: str,
    dest_dir: str,
    file_bytes: bytes,
    filename: str,
    overwrite: bool = False,
) -> str:
    """Save uploaded file bytes into dest_dir under the given filename.

    Returns the new file's relative path.
    Raises ValueError on bad path/filename, FileExistsError if collision
    and overwrite=False.
    """
    if (not filename or "/" in filename or "\\" in filename
            or "\x00" in filename or filename in (".", "..")):
        raise ValueError(f"invalid filename: {filename!r}")
    full_dir = resolve_for_project(project_id, dest_dir)
    if not full_dir.is_dir():
        raise ValueError(f"not a directory: {dest_dir}")
    target = full_dir / filename
    # Inside a folder a Re-sync is replacing, the swap would delete this file.
    check_not_busy(project_id, posixpath.join(dest_dir or ".", filename))
    if (target.exists() or target.is_symlink()) and not overwrite:
        raise FileExistsError(f"{filename} already exists in {dest_dir}")
    root = (WORKSPACE_ROOT / project_id).resolve()
    # Atomic write (consistent with fs_write), never through a planted temp name.
    try:
        _write_file(target, root, file_bytes, create_only=not overwrite, mode=0o666)
    except FileExistsError:
        raise FileExistsError(f"{filename} already exists in {dest_dir}") from None
    return str(target.relative_to(root))


def mkdir_for_project(project_id: str, path: str) -> str:
    """Create a new directory. Returns relative path.

    Raises ValueError if the path already exists.
    """
    if not path or path in (".", ".."):
        raise ValueError(f"invalid path: {path!r}")
    full = resolve_for_project(project_id, path)
    if full.exists() or full.is_symlink():
        raise ValueError(f"already exists: {path}")
    check_not_busy(project_id, path)
    root = (WORKSPACE_ROOT / project_id).resolve()
    # The new folder's mode is set on its own descriptor: a chmod by path after
    # the mkdir followed a link swapped in at the new name.
    _makedirs(full, root, exist_ok=False, chmod_new=0o777)
    return str(full.relative_to(root))


def bulk_archive_for_project(
    project_id: str,
    paths: list,
    format: str = "tar.gz",
    archive_name: str = "bundle",
) -> tuple:
    """Bundle multiple workspace entries (files or dirs) into ONE archive.

    Returns (bytes, suggested_filename). Used by the drawer's multi-select
    "Download N as zip" action. Skips symlinks for the same reason as
    archive_dir_for_project (bug #18 - tarball/zip exfiltration of target
    content). Tar entries map each path to its top-level arcname; dir
    contents are nested under that.
    """
    import io as _io
    resolved, filename = prepare_bulk_archive(project_id, paths, format, archive_name)
    buf = _io.BytesIO()
    write_bulk_archive(buf, resolved, format)
    return buf.getvalue(), filename


def prepare_bulk_archive(project_id: str, paths: list, format: str, archive_name: str) -> tuple[list, str]:
    """Validate a bulk download: (resolved paths, suggested filename)."""
    if format not in ("tar.gz", "zip"):
        raise ValueError(f"format must be tar.gz or zip, got {format!r}")
    if not isinstance(paths, list) or not paths:
        raise ValueError("paths must be a non-empty list")
    resolved = []
    for p in paths:
        full = resolve_for_project(project_id, p)
        if not (full.exists() or full.is_symlink()):
            raise ValueError(f"not found: {p}")
        resolved.append(full)
    return resolved, f"{archive_name}.{format}"


def write_bulk_archive(fileobj, resolved: list, format: str) -> None:
    """Each path's file or tree, read by descriptor (_archive_add): an entry
    swapped for a link while the archive is built is left out, never followed."""
    if not resolved:
        return
    root, budget, cut = _project_root_of(resolved[0]), [_archive_max_bytes()], []
    with _drawer_archive_errors(cut), _open_archive_writer(fileobj, format) as archive:
        for p in resolved:
            _archive_add(archive, format, p, root, p.name, budget, cut)


@contextlib.contextmanager
def _drawer_archive_errors(cut: list):
    """A drawer download that would leave something out fails with a code
    instead (the download route answers ImportFailure as its status)."""
    try:
        yield
    except _ArchiveTooLarge:
        raise ImportFailure("too_large") from None
    if cut:
        raise ImportFailure("too_deep")


def archive_dir_for_project(
    project_id: str,
    path: str,
    format: str = "tar.gz",
) -> tuple:
    """Build an in-memory archive of a directory tree.

    Returns (bytes, suggested_filename).

    SECURITY (bug #18 regression): skip symlinks entirely. Without this,
    zipfile.write() follows symlinks - reading the TARGET's content and
    storing it under the symlink's name. A symlink inside the workspace
    pointing at /etc/passwd would otherwise leak through the archive
    download endpoint to anyone with project access.

    Tar's add() stores symlinks as link entries by default (no content
    leak), but we apply the same skip filter to both formats for
    consistency and defense in depth.
    """
    import io as _io
    src, name, filename = prepare_dir_archive(project_id, path, format)
    buf = _io.BytesIO()
    write_dir_archive(buf, src, name, format)
    return buf.getvalue(), filename


def prepare_dir_archive(project_id: str, path: str, format: str) -> tuple[Path, str, str]:
    """Validate a folder download: (source dir, top-level name, suggested filename)."""
    if format not in ("tar.gz", "zip"):
        raise ValueError(f"format must be tar.gz or zip, got {format!r}")
    src = resolve_for_project(project_id, path)
    if not src.is_dir():
        raise ValueError(f"not a directory: {path}")
    name = src.name or project_id
    return src, name, f"{name}.{format}"


def write_dir_archive(fileobj, src: Path, name: str, format: str) -> None:
    """The tree under `src`, read by descriptor (_archive_add): an entry swapped
    for a link while the archive is built is left out, never followed. A zip
    holds the files under src's own name, a tar the folders too, under `name`."""
    root, budget, cut = _project_root_of(src), [_archive_max_bytes()], []
    with _drawer_archive_errors(cut), _open_archive_writer(fileobj, format) as archive:
        if format == "tar.gz":
            _archive_add(archive, format, src, root, name, budget, cut)
            return
        with _open_dir(src, root) as top:
            for rel, parent_fd, entry, st in _walk_at(top, cut=cut):
                if not statlib.S_ISREG(st.st_mode):
                    continue
                try:
                    fd, st = _open_regular_at(parent_fd, entry)
                except (OSError, ValueError):
                    continue
                try:
                    _archive_add_file(archive, format, f"{src.name}/{rel}", fd, st, budget)
                finally:
                    os.close(fd)


_ARCHIVE_ENTRY_OVERHEAD = 1024  # a tar header block plus padding, per entry


def tree_bytes(paths: list) -> int:
    """An upper bound for an archive of `paths` (symlinks not followed): the
    regular files' bytes plus a header's worth per entry. Sizes the disk
    reservation of an archive build."""
    total = 0
    for p in paths:
        p = Path(p)
        if p.is_symlink():
            continue
        if p.is_file():
            total += p.stat().st_size + _ARCHIVE_ENTRY_OVERHEAD
            continue
        for dirpath, dirs, files in os.walk(p):
            total += _ARCHIVE_ENTRY_OVERHEAD * (1 + len(dirs))
            for f in files:
                try:
                    st = os.lstat(os.path.join(dirpath, f))
                except OSError:
                    continue
                if statlib.S_ISREG(st.st_mode):
                    total += st.st_size + _ARCHIVE_ENTRY_OVERHEAD
    return total


PREVIEW_MAX_BYTES = 1024 * 1024  # 1 MiB - default preview cap


def preview_for_project(
    project_id: str,
    path: str,
    max_bytes: int = PREVIEW_MAX_BYTES,
) -> dict:
    """Return file content suitable for inline rendering.

    Shape: {content, isBinary, truncated, mime, size, lines?}
    - text: content is the UTF-8 decoded string, truncated at max_bytes
    - binary: content is base64 of the first max_bytes
    """
    full = resolve_for_project(project_id, path)
    if not full.is_file():
        raise ValueError(f"not a file: {path}")
    raw, st = _read_head(full, (WORKSPACE_ROOT / project_id).resolve(), max_bytes)
    size = st.st_size
    truncated = size > max_bytes
    mime = mimetypes.guess_type(str(full))[0] or "application/octet-stream"
    is_bin = _is_binary(raw)
    if is_bin:
        content = base64.b64encode(raw).decode("ascii")
    else:
        try:
            content = raw.decode("utf-8")
        except UnicodeDecodeError:
            content = raw.decode("utf-8", errors="replace")
    return {
        "path": path,
        "content": content,
        "isBinary": is_bin,
        "truncated": truncated,
        "mime": mime,
        "size": size,
    }


def properties_for_project(project_id: str, path: str) -> dict:
    """Return rich metadata for a path - used by the properties popover.

    Shape: {path, type, size, mtime, mode, sha256?, target?}
    """
    full = resolve_for_project(project_id, path, follow_symlinks=False)
    root = (WORKSPACE_ROOT / project_id).resolve()
    try:
        st, kind, hashable, link = _entry_facts(full, root)
    except FileNotFoundError:
        raise ValueError(f"not found: {path}") from None
    props = {
        "path": path,
        "type": kind,
        "size": st.st_size,
        "mtime": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(timespec="seconds"),
        "mode": oct(st.st_mode & 0o7777),
    }
    if hashable is not None:
        try:
            digest = _hash_file(hashable, root, "sha256")
        except (OSError, ValueError):
            digest = None
        if digest:
            props["sha256"] = digest
    if link is not None:
        props["target"] = link
    if kind == "dir":
        record = _provenance.read(full, project_id=project_id)
        if record is not None:
            props["import"] = import_facts(record)
    return props


def import_facts(record: dict) -> dict:
    """What the Properties popover shows about an import, every field sanitized."""
    source = record.get("source") if isinstance(record.get("source"), dict) else {}

    def text(value, limit=200):
        value = "" if value is None else str(value)
        return "".join(ch if ch.isprintable() else "?" for ch in value)[:limit]

    try:
        source_path = urllib.parse.urlsplit(str(source.get("url") or "")).path
    except ValueError:
        source_path = ""
    commit = text(source.get("commit"), 64)
    return {
        "kind": text(source.get("kind"), 40),
        "host": text(source.get("host"), 255),
        "sourcePath": text(source_path, 500),
        "ref": text(source.get("ref"), 255),
        "commit7": commit[:7],
        "fetchedAt": text(record.get("fetchedAt"), 40),
        "resyncable": bool(record.get("resyncable")),
    }


DISPATCH = {
    # Read
    "fs_read": fs_read,
    "fs_read_many": fs_read_many,
    "fs_stat": fs_stat,
    # Write & Mutate
    "fs_write": fs_write,
    "fs_edit": fs_edit,
    "fs_multi_edit": fs_multi_edit,
    "fs_undo_edit": fs_undo_edit,
    "fs_delete": fs_delete,
    "fs_move": fs_move,
    "fs_copy": fs_copy,
    "fs_mkdir": fs_mkdir,
    "fs_chmod": fs_chmod,
    "fs_symlink_create": fs_symlink_create,
    # Search & Navigate
    "fs_grep": fs_grep,
    "fs_glob": fs_glob,
    "fs_find": fs_find,
    "fs_list": fs_list,
    "fs_tree": fs_tree,
    "fs_symbols": fs_symbols,
    "fs_symlink_read": fs_symlink_read,
    # Integrity & Archive
    "fs_hash": fs_hash,
    "fs_diff": fs_diff,
    "fs_extract": fs_extract,
    "fs_archive": fs_archive,
}

FS_TOOL_NAMES = frozenset(DISPATCH.keys())

# For each mutating fs_* tool, the arguments that name a path it writes,
# deletes or moves. The executor's single fs chokepoint refuses those paths
# while a running import is replacing them (workspace_import.busy). Every
# DISPATCH key is in exactly one of these two tables; a test enforces it, so a
# new tool cannot skip the check silently.
FS_TOOL_WRITE_ARGS: dict[str, tuple[str, ...]] = {
    "fs_write": ("path",),
    "fs_edit": ("path",),
    "fs_multi_edit": ("path",),
    "fs_undo_edit": ("path",),
    "fs_chmod": ("path",),
    "fs_delete": ("path",),
    "fs_move": ("src", "dst"),
    "fs_copy": ("dst",),
    "fs_mkdir": ("path",),
    "fs_symlink_create": ("linkname",),
    "fs_extract": ("dest",),
    "fs_archive": ("dest",),
}
FS_TOOL_READ_ONLY = frozenset({
    "fs_read", "fs_read_many", "fs_stat", "fs_grep", "fs_glob", "fs_find", "fs_list",
    "fs_tree", "fs_symbols", "fs_symlink_read", "fs_hash", "fs_diff",
})
