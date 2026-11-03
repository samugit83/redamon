"""Atomic placement of a staged entry into a workspace folder.

Policies:
  keep_both  name-2, name-3 … name-999 (before a file's extension: report-2.pdf)
  replace    swap the old entry out through a trash folder, crash-safe
  fail       refuse with `exists`

A `replace` writes its swap record first and does both renames with no await
between them, inside asyncio.shield, so neither a cancel nor anything short of
a crash can leave the target missing. A crash between the renames is repaired
at boot by staging.recover_swaps().
"""
from __future__ import annotations

import asyncio
import errno
import os
from pathlib import Path

import workspace_fs
from workspace_import import executor, staging
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


def _present(p: Path) -> bool:
    return p.exists() or p.is_symlink()


def _split_ext(name: str) -> tuple[str, str]:
    lower = name.lower()
    for ext in _COMPOUND_EXTS:
        if lower.endswith(ext) and len(name) > len(ext):
            return name[: -len(ext)], name[-len(ext):]
    stem, ext = os.path.splitext(name)
    return (stem, ext) if stem else (name, "")


def choose_name(dest_dir: Path, name: str, policy: str, *, is_dir: bool) -> str:
    if policy not in POLICIES:
        raise ImportFailure("invalid_request")
    if not _present(dest_dir / name) or policy == "replace":
        return name
    if policy == "fail":
        raise ImportFailure("exists")
    stem, ext = (name, "") if is_dir else _split_ext(name)
    for i in range(2, MAX_SUFFIX + 1):
        candidate = f"{stem}-{i}{ext}"
        if not _present(dest_dir / candidate):
            return candidate
    raise ImportFailure("name_exhausted")


def _rel(project_id: str, full: Path) -> str:
    root = (workspace_fs.WORKSPACE_ROOT / project_id).resolve()
    return str(full.relative_to(root))


def _move_new(staged: Path, target: Path) -> None:
    """Rename into a name the caller checked is free. A file goes through a hard
    link, which fails with EEXIST instead of replacing something that appeared
    since the check."""
    if staged.is_dir():
        os.rename(staged, target)
        return
    try:
        os.link(staged, target, follow_symlinks=False)
    except OSError as e:
        if e.errno == errno.EEXIST:
            raise ImportFailure("exists") from None
        os.rename(staged, target)
        return
    os.unlink(staged)


async def _swap(target: Path, trash_entry: Path, staged: Path) -> None:
    # No await in here: the two renames run back to back.
    os.rename(target, trash_entry)
    try:
        os.rename(staged, target)
    except BaseException:
        os.rename(trash_entry, target)
        raise


async def place(project_id: str, staged, dest_dir_rel: str, name: str, policy: str) -> str:
    """Move `staged` into `dest_dir_rel` as `name` under `policy`; returns the
    final project-relative path."""
    staged = Path(staged)
    async with _lock_for(project_id, dest_dir_rel):
        try:
            dest_dir = workspace_fs.resolve_for_project(project_id, dest_dir_rel)
        except ValueError:
            raise ImportFailure("destination_missing") from None
        if not dest_dir.is_dir():
            raise ImportFailure("destination_missing")
        is_dir = staged.is_dir() and not staged.is_symlink()
        final = choose_name(dest_dir, name, policy, is_dir=is_dir)
        target = dest_dir / final
        rel = _rel(project_id, target)
        if policy == "replace" and _present(target):
            if workspace_fs.is_protected_path(rel):
                raise ImportFailure("protected_path")
            if target.is_symlink() or target.is_dir() != is_dir:
                raise ImportFailure("conflict_type")
            trash = staging.new_op_dir(project_id, "trash")
            staging.write_swap_record(trash, rel)
            cleanup = []

            def _after_swap(fut, trash=trash):
                # Runs even when this task was cancelled while the shielded
                # swap finished, so the old copy never lingers until boot.
                if not fut.cancelled() and fut.exception() is None:
                    cleanup.append(executor.submit(staging.remove_tree, trash))

            swap = asyncio.ensure_future(_swap(target, trash / staging.SWAP_ENTRY, staged))
            swap.add_done_callback(_after_swap)
            await asyncio.shield(swap)
            if cleanup:
                await asyncio.wrap_future(cleanup[0])
        else:
            _move_new(staged, target)
    if is_dir:
        await executor.run_blocking(workspace_fs._normalize_workspace_tree, target)
    else:
        try:
            os.chmod(target, 0o666)
        except OSError:
            pass
    return rel

