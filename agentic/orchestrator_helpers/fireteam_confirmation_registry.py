"""In-process registry of fireteam member confirmations awaiting operator input.

When a fireteam member hits a dangerous tool, it does NOT terminate any more
(see FIRETEAM.md §7.3 — the old redeploy design is obsolete). Instead the
member awaits an `asyncio.Event` registered here. The WebSocket handler
resolves the Event from the operator's decision, which wakes the member so
its ReAct loop can either execute the approved tool(s) or loop back to think
after a rejection.

Entries are keyed by ``(session_id, wave_id, member_id)`` — unique by
construction, since each member runs exactly one tool-decision at a time.
This registry is process-local (no cross-process sharing) and is cleared on
member resume or wave cancellation. Not durable across backend restarts; if
the backend dies mid-await, the whole wave is cancelled and the member is
marked ``cancelled`` by normal fireteam cancellation semantics.

The single-process invariant is enforced at startup by
``agentic/startup_guard.py:check_single_worker()`` (called from
``api.py``'s FastAPI lifespan). With multiple workers, registrations in
worker A would be invisible to worker B and confirmations would silently
hang. To scale horizontally, replace ``_PENDING`` with a shared backing
store (Redis pub/sub, Postgres LISTEN/NOTIFY, etc.) and remove the guard.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class PendingMemberConfirmation:
    event: asyncio.Event
    decision: Optional[str] = None  # "approve" | "reject" | None (still pending)
    # Operator-supplied patched tool_args, keyed by tool_name. v1: unused.
    modifications: Optional[dict] = None
    meta: dict = field(default_factory=dict)  # for logging/debug


_PENDING: dict[tuple[str, str, str], PendingMemberConfirmation] = {}


# Wave-clock credit accounting. Operator confirmation waits must not consume
# the wave wall-clock budget. The deploy node's deadline loop polls
# get_credit_s and extends its deadline by the accumulated paused time.
# Interval-union semantics: N members waiting in parallel for 60s credit the
# wave 60s of pause (not 60s * N).
_WAVE_ACTIVE_WAITS: dict[tuple[str, str], int] = {}    # currently-waiting member count
_WAVE_PAUSE_START: dict[tuple[str, str], float] = {}   # monotonic when count went 0->1
_WAVE_CREDIT_S: dict[tuple[str, str], float] = {}      # accumulated paused time


def _wkey(session_id: str, wave_id: str) -> tuple[str, str]:
    return (session_id, wave_id)


def begin_confirmation_wait(session_id: str, wave_id: str) -> None:
    """Mark the start of one member's confirmation wait. Starts the pause
    clock on the 0->1 transition. Safe under nested/parallel waits within
    the same wave (interval-union)."""
    k = _wkey(session_id, wave_id)
    count = _WAVE_ACTIVE_WAITS.get(k, 0)
    if count == 0:
        _WAVE_PAUSE_START[k] = time.monotonic()
    _WAVE_ACTIVE_WAITS[k] = count + 1


def end_confirmation_wait(session_id: str, wave_id: str) -> None:
    """Mark the end of one member's confirmation wait. On 1->0 transition,
    commits the elapsed interval into the wave's credit total. Caller MUST
    invoke this via try/finally; an unbalanced count leaves the wave clock
    stuck-paused for the rest of the wave."""
    k = _wkey(session_id, wave_id)
    count = _WAVE_ACTIVE_WAITS.get(k, 0) - 1
    if count <= 0:
        start = _WAVE_PAUSE_START.pop(k, None)
        if start is not None:
            _WAVE_CREDIT_S[k] = _WAVE_CREDIT_S.get(k, 0.0) + (time.monotonic() - start)
        _WAVE_ACTIVE_WAITS.pop(k, None)
    else:
        _WAVE_ACTIVE_WAITS[k] = count


def get_credit_s(session_id: str, wave_id: str) -> float:
    """Return the wave's accumulated confirmation-wait credit in seconds,
    including any in-progress pause. Monotonically non-decreasing until
    drop_wave_credit clears the entry."""
    k = _wkey(session_id, wave_id)
    base = _WAVE_CREDIT_S.get(k, 0.0)
    start = _WAVE_PAUSE_START.get(k)
    if start is not None:
        return base + (time.monotonic() - start)
    return base


def drop_wave_credit(session_id: str, wave_id: str) -> None:
    """Clear credit-tracking state for a wave. Called on wave teardown
    (timeout / cancel / normal completion) alongside drop_wave."""
    k = _wkey(session_id, wave_id)
    _WAVE_ACTIVE_WAITS.pop(k, None)
    _WAVE_PAUSE_START.pop(k, None)
    _WAVE_CREDIT_S.pop(k, None)


def _key(session_id: str, wave_id: str, member_id: str) -> tuple[str, str, str]:
    return (session_id, wave_id, member_id)


def register(session_id: str, wave_id: str, member_id: str, meta: Optional[dict] = None) -> PendingMemberConfirmation:
    """Create a pending entry and return it. Caller awaits ``entry.event``.

    If an entry already exists for the same key (should not happen under
    normal flow), we log a warning and return the existing entry so the
    caller's wait reuses the same Event.
    """
    k = _key(session_id, wave_id, member_id)
    existing = _PENDING.get(k)
    if existing is not None:
        logger.warning(
            "[confirmation_registry] DUPLICATE register for %s; reusing existing entry", k,
        )
        return existing
    entry = PendingMemberConfirmation(event=asyncio.Event(), meta=meta or {})
    _PENDING[k] = entry
    tool_names = [t.get("tool_name") for t in (meta or {}).get("pending", {}).get("tools", [])]
    logger.info(
        "[confirmation_registry] REGISTER session=%s wave=%s member=%s tools=%s pending_total=%d",
        session_id, wave_id, member_id, tool_names, len(_PENDING),
    )
    return entry


def applied_decision(decision: str) -> str:
    """The decision `resolve` gives the member: `approve`, or `reject` for any other word."""
    return "approve" if decision == "approve" else "reject"


def resolve(session_id: str, wave_id: str, member_id: str, decision: str, modifications: Optional[dict] = None) -> bool:
    """Record the operator's decision and wake the awaiting member.

    Returns True if an entry was found and resolved, False otherwise.
    """
    k = _key(session_id, wave_id, member_id)
    entry = _PENDING.get(k)
    if entry is None:
        logger.warning(
            "[confirmation_registry] RESOLVE for UNKNOWN key %s decision=%s "
            "(operator decision arrived after member already timed out or was cancelled)",
            k, decision,
        )
        return False
    if decision not in ("approve", "reject"):
        logger.warning(
            "[confirmation_registry] invalid decision=%s for %s; treating as reject", decision, k,
        )
    decision = applied_decision(decision)
    entry.decision = decision
    entry.modifications = modifications
    entry.event.set()
    logger.info(
        "[confirmation_registry] RESOLVE session=%s wave=%s member=%s decision=%s (operator input)",
        session_id, wave_id, member_id, decision,
    )
    return True


def drop(session_id: str, wave_id: str, member_id: str) -> None:
    """Remove a pending entry. Called by the member once it has read the decision."""
    k = _key(session_id, wave_id, member_id)
    if _PENDING.pop(k, None) is not None:
        logger.debug("[confirmation_registry] DROP session=%s wave=%s member=%s (member resumed)",
                     session_id, wave_id, member_id)


def drop_wave(session_id: str, wave_id: str, reason: str = "wave_closed") -> int:
    """Drop all pending entries for a wave. Used on wave cancellation.

    Wakes any awaiting members with decision='reject' so they exit cleanly
    instead of hanging on the Event forever.
    """
    dropped = 0
    for k in list(_PENDING.keys()):
        if k[0] == session_id and k[1] == wave_id:
            entry = _PENDING.pop(k)
            if not entry.event.is_set():
                entry.decision = "reject"
                entry.meta["cancel_reason"] = reason
                entry.event.set()
            dropped += 1
    if dropped > 0:
        logger.info(
            "[confirmation_registry] DROP_WAVE session=%s wave=%s reason=%s "
            "woke %d pending member(s) with decision=reject",
            session_id, wave_id, reason, dropped,
        )
    return dropped
