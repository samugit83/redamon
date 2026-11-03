"""Pieces the upload commit job and the URL import job share."""
from __future__ import annotations

import asyncio
import logging
import threading
from typing import Callable

import job_runner
from workspace_import import executor, limits, project_check
from workspace_import.errors import ImportFailure

logger = logging.getLogger(__name__)

PROGRESS_TICK_SEC = 0.25
CANCEL_GRACE_SEC = 30.0
GROW_STEP = 64 * 1024 * 1024


class Progress:
    """Progress written from any thread, reported from the job's own task."""

    def __init__(self, base: dict):
        self.state = dict(base)
        self._lock = threading.Lock()
        self.version = 0

    def update(self, **kw) -> None:
        with self._lock:
            self.state.update(kw)
            self.version += 1

    def snapshot(self) -> tuple[int, dict]:
        with self._lock:
            return self.version, dict(self.state)


async def report_loop(progress: Progress) -> None:
    seen = -1
    while True:
        version, state = progress.snapshot()
        if version != seen:
            seen = version
            await job_runner.report_progress(state)
        await asyncio.sleep(PROGRESS_TICK_SEC)


async def report_done(progress: dict) -> None:
    # now=inf passes the one-per-second throttle: the final state is written at once.
    await job_runner.report_progress(progress, now=lambda: float("inf"))


async def extract_on_pool(extractor: Callable, archive, out, progress: Progress, cancel: threading.Event,
                          *, reservation=None, base_bytes: int = 0, **kwargs):
    """Run `extractor(archive, out, ...)` on the import pool. On cancel, tell the
    worker to stop and wait for it, so staging is never deleted under a writer.

    With `reservation`, the disk it holds grows to cover the archive still on
    disk (`base_bytes`) plus everything extracted so far, or the extraction
    stops with insufficient_storage: a compressed archive's size says nothing
    about what it extracts to."""
    def on_progress(files, nbytes):
        progress.update(phase="extracting", files=files, bytes=nbytes)

    if reservation is not None:
        grower = ReservationGrower(reservation)
        kwargs["on_bytes"] = lambda extracted: grower(base_bytes + extracted)

    future, queued = executor.start(
        lambda: extractor(archive, out, max_bytes=limits.max_bytes(), max_entries=limits.max_entries(),
                          progress=on_progress, cancel_event=cancel, **kwargs),
    )
    if queued:
        progress.update(phase="queued")
    try:
        return await asyncio.wrap_future(future)
    except asyncio.CancelledError:
        cancel.set()
        try:
            await asyncio.wait_for(asyncio.shield(asyncio.wrap_future(future)), CANCEL_GRACE_SEC)
        except BaseException:
            pass
        raise


async def ensure_project_exists(project_id: str) -> None:
    try:
        exists = await project_check.project_exists(project_id)
    except project_check.ProjectCheckFailed:
        raise ImportFailure("settings_unavailable") from None
    if not exists:
        raise ImportFailure("project_deleted")


class ReservationGrower:
    """Grows a disk reservation as a download of unknown size goes, in 64 MiB
    steps; `factor` 2 also covers what an archive extracts to."""

    def __init__(self, reservation, factor: int = 1):
        self.reservation = reservation
        self.factor = factor

    def __call__(self, total_bytes: int) -> None:
        while total_bytes * self.factor > self.reservation.nbytes:
            self.reservation.grow(GROW_STEP * self.factor)
