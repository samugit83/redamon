"""Busy targets: paths a running upload or import is about to replace or place into.

While a job runs, a mutation on its target, inside it, or on an ancestor of its
destination folder is refused. A Re-sync swaps the whole folder at the end, so
a write that landed inside it meanwhile would be lost in silence.

Stdlib only: workspace_fs imports this module.
"""
from __future__ import annotations

import os
import threading
from typing import Optional

from workspace_import.errors import ImportFailure

_lock = threading.Lock()
# job_id -> (project_id, target or None, dest_dir)
_entries: dict[str, tuple[str, Optional[str], str]] = {}


def normalize(rel_path: Optional[str]) -> str:
    """Project-relative form: '.' for the root, no './', no trailing '/'.
    Same normalization as workspace_fs.is_protected_path."""
    raw = (rel_path or "").strip()
    norm = os.path.normpath(raw) if raw else "."
    norm = norm.lstrip("/") or "."
    return norm


def _within(path: str, ancestor: str) -> bool:
    return ancestor == "." or path == ancestor or path.startswith(ancestor + "/")


def register(project_id: str, job_id: str, *, target: Optional[str] = None, dest_dir: str) -> None:
    with _lock:
        _entries[job_id] = (project_id, normalize(target) if target else None, normalize(dest_dir))


def unregister(job_id: str) -> None:
    with _lock:
        _entries.pop(job_id, None)


def clear() -> None:
    with _lock:
        _entries.clear()


def busy_job(project_id: str, rel_path: str) -> Optional[str]:
    """The id of the job that makes `rel_path` busy, or None."""
    path = normalize(rel_path)
    with _lock:
        for job_id, (pid, target, dest) in _entries.items():
            if pid != project_id:
                continue
            if target is not None and _within(path, target):
                return job_id
            if _within(dest, path):
                return job_id
    return None


def check_mutation(project_id: str, rel_path: str) -> None:
    job_id = busy_job(project_id, rel_path)
    if job_id is not None:
        raise ImportFailure("busy", detail=job_id)
