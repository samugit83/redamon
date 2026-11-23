"""The staging area and the disk-reservation ledger.

Every upload and import is built in /workspace/.staging/<projectId>/<opId>/ and
moved into place with one rename. The staging root sits outside every project
root, so the drawer, the fs_* tools and the prompt never see a half-written
tree, and it can never be a project: project ids that start with a dot are
refused (workspace_fs._validate_project_id).

No operation survives a restart: at boot, recover_swaps() first puts back any
folder a `replace` was swapping, then sweep_all() deletes the rest.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import stat
import threading
import uuid
from pathlib import Path
from typing import Callable, Optional

import workspace_fs
from workspace_import import limits
from workspace_import.errors import ImportFailure

logger = logging.getLogger(__name__)

STAGING_DIRNAME = ".staging"
SWAP_RECORD = "swap.json"
SWAP_ENTRY = "entry"
# A real record is `{"target_rel": ...}`, a few hundred bytes at most. The boot read is
# bounded so a planted record can never make it unbounded (D16, TD-18); no sandbox
# mounts .staging.
SWAP_RECORD_MAX_BYTES = 65_536

# Injectable for tests; must return an object with a `.free` attribute.
disk_usage: Callable[[Path], object] = shutil.disk_usage


def staging_root() -> Path:
    # Read at call time: tests swap workspace_fs.WORKSPACE_ROOT.
    return workspace_fs.WORKSPACE_ROOT / STAGING_DIRNAME


def project_staging(project_id: str) -> Path:
    workspace_fs._validate_project_id(project_id)
    return staging_root() / project_id


def _mkdir_777(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o777)
    except OSError:
        pass


def new_op_dir(project_id: str, prefix: str) -> Path:
    """A fresh `<prefix>-<uuid4hex>` folder in the project's staging. Its name
    is also the operation's reservation id."""
    base = project_staging(project_id)
    _mkdir_777(staging_root())
    _mkdir_777(base)
    op = base / f"{prefix}-{uuid.uuid4().hex}"
    op.mkdir(mode=0o777)
    try:
        os.chmod(op, 0o777)
    except OSError:
        pass
    return op


def remove_tree(path: Path) -> None:
    """Delete a staging entry without following links; never raises."""
    try:
        if path.is_symlink() or path.is_file():
            path.unlink()
        elif path.is_dir():
            shutil.rmtree(path, ignore_errors=True)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Reservation ledger. The agent is one process (check_single_worker), so this
# in-memory ledger is authoritative. Called from the event loop and from the
# import pool, hence a threading lock.
# ---------------------------------------------------------------------------

_ledger_lock = threading.Lock()
_ledger: dict[str, tuple[str, int]] = {}  # op_id -> (project_id, bytes)


def reserved_total() -> int:
    with _ledger_lock:
        return sum(n for _pid, n in _ledger.values())


def reset_ledger() -> None:
    with _ledger_lock:
        _ledger.clear()


def free_bytes() -> int:
    return int(disk_usage(workspace_fs.WORKSPACE_ROOT).free)


def _check_locked(needed: int) -> None:
    try:
        free = free_bytes()
    except Exception:
        # A disk we cannot measure is a disk we cannot fill safely.
        raise ImportFailure("insufficient_storage") from None
    reserved = sum(n for _pid, n in _ledger.values())
    if free - reserved - max(0, needed) < limits.min_free_bytes():
        raise ImportFailure("insufficient_storage")


def check_space(needed: int) -> None:
    with _ledger_lock:
        _check_locked(needed)


class Reservation:
    def __init__(self, op_id: str, project_id: str):
        self.op_id = op_id
        self.project_id = project_id
        self._released = False

    @property
    def nbytes(self) -> int:
        with _ledger_lock:
            entry = _ledger.get(self.op_id)
            return entry[1] if entry else 0

    def grow(self, n: int) -> None:
        """Reserve `n` more bytes, or raise insufficient_storage."""
        if n <= 0:
            return
        with _ledger_lock:
            # A worker thread that outlived its job must not bring the entry back.
            if self._released:
                return
            _check_locked(n)
            pid, have = _ledger.get(self.op_id, (self.project_id, 0))
            _ledger[self.op_id] = (pid, have + n)

    def release(self) -> None:
        with _ledger_lock:
            self._released = True
            _ledger.pop(self.op_id, None)


def reserve(op_id: str, nbytes: int, *, project_id: str = "") -> Reservation:
    """Check the free disk and record `nbytes` against it in one step, so two
    concurrent operations can never both pass against the same free space."""
    with _ledger_lock:
        _check_locked(nbytes)
        _ledger[op_id] = (project_id, max(0, nbytes))
    return Reservation(op_id, project_id)


# ---------------------------------------------------------------------------
# Sweeps and swap recovery
# ---------------------------------------------------------------------------

def sweep_project(project_id: str) -> None:
    base = project_staging(project_id)
    if base.exists() or base.is_symlink():
        remove_tree(base)
    with _ledger_lock:
        for op_id in [k for k, (pid, _n) in _ledger.items() if pid == project_id]:
            _ledger.pop(op_id, None)


def sweep_all() -> None:
    root = staging_root()
    if root.is_symlink():
        root.unlink()
    elif root.is_dir():
        for child in list(root.iterdir()):
            remove_tree(child)
    reset_ledger()


def write_swap_record(trash: Path, target_rel: str) -> None:
    rec = trash / SWAP_RECORD
    tmp = trash / (SWAP_RECORD + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"target_rel": target_rel}, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, rec)


class _OversizedRecord(Exception):
    pass


def _read_swap_record(rec: Path) -> Optional[str]:
    """The record's text, or None when it is not a regular file (a link is never followed).
    Raises _OversizedRecord past SWAP_RECORD_MAX_BYTES before reading a byte. The checks are
    made again on the open descriptor, so a record swapped after the lstat changes nothing."""
    try:
        st = os.lstat(rec)
    except OSError:
        return None
    if not stat.S_ISREG(st.st_mode):
        return None
    if st.st_size > SWAP_RECORD_MAX_BYTES:
        raise _OversizedRecord()
    # O_NONBLOCK: a FIFO swapped in after the lstat must not block the boot.
    fd = os.open(rec, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None
        if st.st_size > SWAP_RECORD_MAX_BYTES:
            raise _OversizedRecord()
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, SWAP_RECORD_MAX_BYTES + 1 - total)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > SWAP_RECORD_MAX_BYTES:
                raise _OversizedRecord()
    finally:
        os.close(fd)
    return b"".join(chunks).decode("utf-8")


def recover_swaps() -> int:
    """Put back every folder a crash left in a replace's trash. Returns how many
    were restored. Runs at boot, before sweep_all()."""
    root = staging_root()
    if not root.is_dir() or root.is_symlink():
        return 0
    restored = 0
    for pdir in root.iterdir():
        if not pdir.is_dir() or pdir.is_symlink():
            continue
        for trash in pdir.glob("trash-*"):
            if trash.is_symlink():
                continue
            rec = trash / SWAP_RECORD
            try:
                text = _read_swap_record(rec)
            except _OversizedRecord:
                logger.warning(f"[workspace-import] swap record of {trash.name} is over "
                               f"{SWAP_RECORD_MAX_BYTES} bytes; removed without reading it")
                remove_tree(trash)
                continue
            except Exception as e:
                logger.warning(f"[workspace-import] swap recovery skipped {trash.name}: {type(e).__name__}")
                remove_tree(trash)
                continue
            if text is None:
                continue
            try:
                target_rel = json.loads(text)["target_rel"]
                target = workspace_fs.resolve_for_project(pdir.name, target_rel, follow_symlinks=False)
                entry = trash / SWAP_ENTRY
                if (entry.exists() or entry.is_symlink()) and not (target.exists() or target.is_symlink()):
                    if target.parent.is_dir():
                        os.rename(entry, target)
                        restored += 1
                        logger.warning(f"[workspace-import] restored {pdir.name}/{target_rel} after an interrupted replace")
            except Exception as e:
                logger.warning(f"[workspace-import] swap recovery skipped {trash.name}: {type(e).__name__}")
            remove_tree(trash)
    return restored
