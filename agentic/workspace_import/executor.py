"""The bounded thread pool for import CPU and disk work.

Extraction, hashing, archive builds and tree walks run here, never on the
event loop's default pool: the pinned DNS resolve (fetch_guard) and LLM
provider loading use that pool, so a few minutes-long extractions on it would
stall every guarded fetch and every chat start.
"""
from __future__ import annotations

import asyncio
import inspect
import threading
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Any, Callable, Optional

from workspace_import import limits

# Created lazily so tests can install their own.
IMPORT_EXECUTOR: Optional[ThreadPoolExecutor] = None
_lock = threading.Lock()
_in_flight = 0


def _executor() -> ThreadPoolExecutor:
    global IMPORT_EXECUTOR
    with _lock:
        if IMPORT_EXECUTOR is None:
            IMPORT_EXECUTOR = ThreadPoolExecutor(
                max_workers=limits.import_workers(), thread_name_prefix="workspace-import",
            )
        return IMPORT_EXECUTOR


def _workers(pool: ThreadPoolExecutor) -> int:
    return getattr(pool, "_max_workers", 1)


def _submit(fn: Callable[..., Any], *args) -> tuple[Future, bool]:
    global _in_flight
    pool = _executor()
    with _lock:
        queued = _in_flight >= _workers(pool)
        _in_flight += 1
    try:
        future = pool.submit(fn, *args)
    except BaseException:
        _done(None)
        raise
    # Counted down when the WORK ends: a cancelled await leaves it running.
    future.add_done_callback(_done)
    return future, queued


def submit(fn: Callable[..., Any], *args) -> Future:
    """Fire-and-forget on the import pool (a clean-up that must outlive a cancel)."""
    return _submit(fn, *args)[0]


async def run_blocking(fn: Callable[..., Any], *args, on_queued: Optional[Callable[[], Any]] = None):
    """Run `fn(*args)` on the import pool. When every worker is already busy,
    call `on_queued()` once first, so the job can report that it waits."""
    future, queued = _submit(fn, *args)
    if queued and on_queued is not None:
        result = on_queued()
        if inspect.isawaitable(result):
            await result
    return await asyncio.wrap_future(future)


def _done(_future) -> None:
    global _in_flight
    with _lock:
        _in_flight -= 1
