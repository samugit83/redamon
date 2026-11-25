"""Atomic placement of a staged entry into a workspace folder.

Policies:
  keep_both  name-2, name-3 … name-999 (before a file's extension: report-2.pdf)
  replace    swap the old entry out through a trash folder, crash-safe
  fail       refuse with `exists`

A `replace` writes its swap record first and does both renames with no await
between them, inside asyncio.shield, so neither a cancel nor anything short of
a crash can leave the target missing. A crash between the renames is repaired
at boot by staging.recover_swaps().

The destination folder is written by every sandbox of the project, so it can be
swapped for a link after resolve_for_project checked it. The name choice, the
type checks, the swap record's path and every rename go through that folder
opened once by descriptor and checked inside the project (workspace_fs._open_dir),
and the modes set afterwards reach only the inode that was placed
(_make_host_editable).
"""
from __future__ import annotations

import asyncio
import errno
import os
import stat
from pathlib import Path

import workspace_fs
from workspace_import import busy, executor, staging
from workspace_import.busy import normalize
from workspace_import.errors import ImportFailure

POLICIES = ("keep_both", "replace", "fail")
MAX_SUFFIX = 999
_COMPOUND_EXTS = (".tar.gz", ".tar.bz2", ".tar.xz")

_locks: dict[tuple[str, str], asyncio.Lock] = {}


def _lock_for(project_id: str, dest_rel: str) -> asyncio.Lock:
    key = (project_id, normalize(dest_rel))
    lock = _locks.get(key)
    if lock is None:
        lock = _locks[key] = asyncio.Lock()
    return lock


def _kind_at(dir_fd: int, name: str):
    """None, "dir", "link" or "file" for `name` in an opened folder (not followed)."""
    try:
        mode = os.stat(name, dir_fd=dir_fd, follow_symlinks=False).st_mode
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(mode):
        return "link"
    return "dir" if stat.S_ISDIR(mode) else "file"


def _split_ext(name: str) -> tuple[str, str]:
    lower = name.lower()
    for ext in _COMPOUND_EXTS:
        if lower.endswith(ext) and len(name) > len(ext):
            return name[: -len(ext)], name[-len(ext):]
    stem, ext = os.path.splitext(name)
    return (stem, ext) if stem else (name, "")


def choose_name(dir_fd: int, name: str, policy: str, *, is_dir: bool) -> str:
    """The name to place under, probed in the opened destination folder: by path,
    a folder swapped for a link after the check made the answer (and its error
    code) a probe of paths outside the project."""
    if policy not in POLICIES:
        raise ImportFailure("invalid_request")
    if _kind_at(dir_fd, name) is None or policy == "replace":
        return name
    if policy == "fail":
        raise ImportFailure("exists")
    stem, ext = (name, "") if is_dir else _split_ext(name)
    for i in range(2, MAX_SUFFIX + 1):
        candidate = f"{stem}-{i}{ext}"
        if _kind_at(dir_fd, candidate) is None:
            return candidate
    raise ImportFailure("name_exhausted")


def _root(project_id: str) -> Path:
    return (workspace_fs.WORKSPACE_ROOT / project_id).resolve()


def _rel(project_id: str, full: Path) -> str:
    return str(full.relative_to(_root(project_id)))


def _move_new(dir_fd: int, staged: Path, name: str) -> None:
    """Rename into a name the caller checked is free, in the opened destination
    folder. A file goes through a hard link, which fails with EEXIST instead of
    replacing something that appeared since the check."""
    if staged.is_dir():
        os.rename(staged, name, dst_dir_fd=dir_fd)
        return
    try:
        os.link(staged, name, dst_dir_fd=dir_fd, follow_symlinks=False)
    except OSError as e:
        if e.errno == errno.EEXIST:
            raise ImportFailure("exists") from None
        os.rename(staged, name, dst_dir_fd=dir_fd)
        return
    os.unlink(staged)


async def _swap(dir_fd: int, name: str, trash_entry: Path, staged: Path) -> None:
    # No await in here: both renames run back to back, in the folder opened when
    # the name was chosen. The descriptor is this task's own and closed here, so
    # cancelling place() cannot close it under the swap.
    try:
        os.rename(name, trash_entry, src_dir_fd=dir_fd)
        try:
            os.rename(staged, name, dst_dir_fd=dir_fd)
        except BaseException:
            os.rename(trash_entry, name, dst_dir_fd=dir_fd)
            raise
    finally:
        os.close(dir_fd)


async def place(project_id: str, staged, dest_dir_rel: str, name: str, policy: str) -> str:
    """Move `staged` into `dest_dir_rel` as `name` under `policy`; returns the
    final project-relative path."""
    staged = Path(staged)
    is_dir = staged.is_dir() and not staged.is_symlink()
    st = os.lstat(staged)
    placed = (st.st_dev, st.st_ino)  # a rename or a hard link keeps the inode
    async with _lock_for(project_id, dest_dir_rel):
        try:
            dest_dir = workspace_fs.resolve_for_project(project_id, dest_dir_rel)
        except ValueError:
            raise ImportFailure("destination_missing") from None
        if not dest_dir.is_dir():
            raise ImportFailure("destination_missing")
        try:
            # The name, the type checks, `rel` and the move all go through this one
            # descriptor: a folder swapped for a link after resolve_for_project
            # cannot redirect any of them.
            with workspace_fs._open_dir(dest_dir, _root(project_id)) as dir_fd:
                final = choose_name(dir_fd, name, policy, is_dir=is_dir)
                target = Path(os.readlink(f"/proc/self/fd/{dir_fd}")) / final
                rel = _rel(project_id, target)
                # Another job replacing this folder (or a folder above it) would undo
                # the placement when it swaps; this job's own registration is fine.
                from job_runner import current_job_id
                holder = busy.busy_job(project_id, rel, exclude=current_job_id())
                if holder is not None:
                    raise ImportFailure("busy", detail=holder)
                kind = _kind_at(dir_fd, final)
                if policy == "replace" and kind is not None:
                    if workspace_fs.is_protected_path(rel):
                        raise ImportFailure("protected_path")
                    if kind == "link" or (kind == "dir") != is_dir:
                        raise ImportFailure("conflict_type")
                    trash = staging.new_op_dir(project_id, "trash")
                    staging.write_swap_record(trash, rel)
                    cleanup = []

                    def _after_swap(fut, trash=trash):
                        # Runs even when this task was cancelled while the shielded
                        # swap finished, so the old copy never lingers until boot. A
                        # failed swap that put the old copy back leaves only its record;
                        # one that could not keeps the trash for recover_swaps().
                        if fut.cancelled():
                            return
                        if fut.exception() is None or not (trash / staging.SWAP_ENTRY).exists():
                            cleanup.append(executor.submit(staging.remove_tree, trash))

                    swap = asyncio.ensure_future(
                        _swap(os.dup(dir_fd), final, trash / staging.SWAP_ENTRY, staged))
                    swap.add_done_callback(_after_swap)
                    await asyncio.shield(swap)
                    if cleanup:
                        # Shielded: cancelling the wrapper would cancel the removal
                        # itself while it still waits for a pool thread.
                        await asyncio.shield(asyncio.wrap_future(cleanup[0]))
                else:
                    _move_new(dir_fd, staged, final)
        except ValueError:  # the folder is not a plain folder of the project any more
            raise ImportFailure("destination_missing") from None
    if is_dir:
        await executor.run_blocking(_make_host_editable, project_id, target, placed)
    else:
        _make_host_editable(project_id, target, placed)
    return rel


def _chmod_path_fd(fd: int, mode: int) -> None:
    # An O_PATH descriptor's inode, never a link: chmod through /proc/self/fd.
    try:
        os.chmod(f"/proc/self/fd/{fd}", mode)
    except OSError:
        pass


def _make_host_editable(project_id: str, target: Path, placed: tuple) -> None:
    """Folders 0o777 and files 0o666, so the host user can edit what root placed.

    Only the inode that was placed is touched, and a folder is walked by
    descriptor (os.fwalk never follows a link; each entry is opened O_PATH |
    O_NOFOLLOW and changed through that descriptor): a sandbox that swaps the new
    name, or anything under it, for a link after the move cannot aim the chmod at
    a file outside the project."""
    try:
        with workspace_fs._pinned_parent(target, _root(project_id)) as (dir_fd, name):
            top = os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
    except (OSError, ValueError):
        return
    try:
        st = os.fstat(top)
        if (st.st_dev, st.st_ino) != placed:
            return
        if stat.S_ISREG(st.st_mode):
            _chmod_path_fd(top, 0o666)
            return
        if not stat.S_ISDIR(st.st_mode):
            return
        _chmod_path_fd(top, 0o777)
        for _root_name, dirs, files, root_fd in os.fwalk(".", dir_fd=top):
            for entry in dirs + files:
                try:
                    fd = os.open(entry, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root_fd)
                except OSError:
                    continue
                try:
                    mode = os.fstat(fd).st_mode
                    if stat.S_ISDIR(mode):
                        _chmod_path_fd(fd, 0o777)
                    elif stat.S_ISREG(mode):
                        _chmod_path_fd(fd, 0o666)
                finally:
                    os.close(fd)
    finally:
        os.close(top)

