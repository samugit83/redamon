"""Caps and switches for workspace uploads and URL imports, read at call time.

Numbers go through workspace_fs._int_env, so a typo falls back to the default
instead of disabling a cap.
"""
from __future__ import annotations

import logging
import os

from workspace_fs import _int_env

logger = logging.getLogger(__name__)

GIB = 1024 ** 3
_SCAN_FLOOR_DEFAULT = 10 * GIB


def max_bytes() -> int:
    return _int_env("WORKSPACE_IMPORT_MAX_BYTES", 2 * GIB)


def max_entries() -> int:
    return _int_env("WORKSPACE_IMPORT_MAX_ENTRIES", 50_000)


def _scan_floor() -> int:
    """The recon dispatcher's own disk floor, parsed as it parses it
    (recon_orchestrator/job_dispatcher.py min_free_disk), so 0 means the
    operator turned that floor off and a typo means the default."""
    raw = os.environ.get("JOB_QUEUE_MIN_FREE_DISK")
    if raw is None or raw.strip() == "":
        return _SCAN_FLOOR_DEFAULT
    try:
        return max(0, int(float(raw)))
    except (TypeError, ValueError):
        return _SCAN_FLOOR_DEFAULT


def min_free_bytes() -> int:
    """Free disk that must remain after an operation. The workspace and
    recon/output share the host disk, and the scan dispatcher defers every
    scan below its floor, so an import must never eat into it."""
    return _scan_floor() + _int_env("WORKSPACE_IMPORT_MIN_FREE_BYTES", GIB)


def chunk_bytes() -> int:
    return _int_env("WORKSPACE_UPLOAD_CHUNK_BYTES", 8 * 1024 * 1024)


def session_idle_sec() -> int:
    return _int_env("WORKSPACE_UPLOAD_SESSION_IDLE_SEC", 3600)


def max_jobs() -> int:
    return _int_env("WORKSPACE_IMPORT_MAX_JOBS", 4)


def import_workers() -> int:
    return _int_env("WORKSPACE_IMPORT_WORKERS", 2)


_warned_switch = False


def url_import_enabled() -> bool:
    """Unset or true/1/yes: on. Anything else is off, so a mistyped value
    fails closed."""
    global _warned_switch
    raw = os.environ.get("WORKSPACE_URL_IMPORT_ENABLED")
    if raw is None:
        return True
    if raw.strip().lower() in ("true", "1", "yes"):
        return True
    if not _warned_switch:
        logger.warning("[workspace-import] WORKSPACE_URL_IMPORT_ENABLED is not true/1/yes; URL import is off")
        _warned_switch = True
    return False
