"""
Scan Timeline — the Scan Scheduler worker (plan Section 7.2).

The orchestrator owns admission and the container spawn, so it owns the TICK; the
webapp owns the version freeze and the ScanJob history, so it owns the RUN. On
each tick the worker:

  1. asks the webapp which schedules are due
     (``GET /api/internal/scan-schedules/due``),
  2. defers any whose project is mid-activation (F3: never spawn into an in-flight
     graph swap) — the deferral is recorded as a ``deferred_ram``-style ScanJob
     with a "graph busy" reason and retried on a later tick,
  3. defers any that clearly cannot be admitted right now, using a NON-RESERVING
     read of the ledger (``remaining_for_new()`` vs ``envelope_for()``). The real,
     authoritative reservation still happens inside ``start_recon``'s
     ``_admit_scan`` when the webapp calls us back — pre-reserving here would leak
     an envelope whenever the spawn is then rejected for another reason,
  4. otherwise asks the webapp to run it
     (``POST /api/internal/scan-schedules/{id}/run``), which goes through exactly
     the same start path as a manual scan: activation lock, freeze-before-start,
     RoE time window / hard guardrail, admission, ScanJob history.

Never raises into the event loop: every iteration is wrapped, because a scheduler
that dies silently is worse than one that skips a tick.
"""
from __future__ import annotations

import asyncio
import logging
import os
from typing import Optional

from webapp_client import request_json

logger = logging.getLogger(__name__)

# Kept as a module-level name so mock.patch.object(scan_scheduler, "_request", ...)
# in the existing tests still resolves (Scan Queue plan Phase 2). The body now
# lives in webapp_client.request_json, shared with the queue dispatcher.
_request = request_json

DEFAULT_TICK_SECONDS = 60.0
# Below this, a tick costs more than it can possibly gain (a scan runs for minutes).
MIN_TICK_SECONDS = 10.0


def scheduler_enabled() -> bool:
    raw = (os.environ.get("SCAN_SCHEDULER_ENABLED", "true") or "").strip().lower()
    return raw not in ("0", "false", "no", "off")


def tick_seconds() -> float:
    try:
        value = float(os.environ.get("SCAN_SCHEDULER_TICK_SECONDS", "") or DEFAULT_TICK_SECONDS)
    except (TypeError, ValueError):
        return DEFAULT_TICK_SECONDS
    return max(MIN_TICK_SECONDS, value)


def _webapp_base() -> str:
    return (os.environ.get("WEBAPP_API_URL", "http://webapp:3000") or "").rstrip("/")


def _internal_key() -> str:
    return os.environ.get("INTERNAL_API_KEY", "")


async def run_scheduler_tick(container_manager) -> dict:
    """One pass. Returns a small summary (used by the tests).

    Phase 4: the worker no longer pre-checks admission or defers. It always asks
    the webapp to /run; the run route freezes the version, and on a TEMPORARY
    refusal (RAM/hard/activation/busy) enqueues the occurrence as a durable
    JobQueue row instead of burning it. So this worker holds no ledger opinion and
    never calls /defer (that route is gone), and try_admit is still only reached
    inside the real start path (R1)."""
    base, key = _webapp_base(), _internal_key()
    summary = {"due": 0, "started": 0, "queued": 0, "failed": 0}
    if not key:
        # Without the internal key we cannot talk to the webapp at all.
        return summary

    due = await asyncio.to_thread(_request, f"{base}/api/internal/scan-schedules/due", key)
    if not due:
        return summary

    schedules = due.get("schedules") or []
    summary["due"] = len(schedules)

    for sched in schedules:
        sched_id = sched.get("id")
        if not sched_id:
            continue

        result = await asyncio.to_thread(
            _request, f"{base}/api/internal/scan-schedules/{sched_id}/run", key, "POST", {},
        )
        if result is None:
            summary["failed"] += 1
            logger.warning("[scanScheduler] run request failed for schedule %s", sched_id)
        elif result.get("ok"):
            summary["started"] += 1
        elif result.get("queued"):
            # A temporary refusal became a queue row; the dispatcher will run it.
            summary["queued"] += 1
            logger.info("[scanScheduler] schedule %s enqueued (%s)", sched_id, result.get("blockedCode"))
        else:
            # Permanent: the webapp recorded a failed ScanJob with the reason.
            summary["failed"] += 1
            logger.info("[scanScheduler] schedule %s did not start: %s", sched_id, result.get("error"))

    # Best-effort outbox tick: failed webhook deliveries are retried by subsequent ticks.
    try:
        await asyncio.to_thread(
            _request, f"{base}/api/internal/delta-alerts/process", key, "POST", {},
        )
    except Exception as e:  # noqa: BLE001 - outbox failure must never break scheduling
        logger.warning("[scanScheduler] delta alert outbox tick failed: %s", e)

    return summary


async def scan_scheduler_loop(get_container_manager) -> None:
    """Background task: tick forever. `get_container_manager` is a callable so the
    loop picks up the manager once lifespan startup has created it."""
    if not scheduler_enabled():
        logger.info("[scanScheduler] disabled (SCAN_SCHEDULER_ENABLED=false)")
        return
    interval = tick_seconds()
    logger.info("[scanScheduler] started (tick=%ss)", interval)
    try:
        while True:
            await asyncio.sleep(interval)
            try:
                cm = get_container_manager()
                if cm is None:
                    continue
                summary = await run_scheduler_tick(cm)
                if summary["due"]:
                    logger.info(
                        "[scanScheduler] tick: %s due, %s started, %s queued, %s failed",
                        summary["due"], summary["started"], summary["queued"], summary["failed"],
                    )
            except Exception as e:  # noqa: BLE001 - never let one tick kill the loop
                logger.warning("[scanScheduler] tick failed: %s", e)
    except asyncio.CancelledError:
        pass
