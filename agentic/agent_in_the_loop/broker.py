"""The step broker: model calls waiting for an external driver.

One instance per process (the agent is single-worker, startup_guard). Plain
asyncio, no threads, no persistence: an agent restart drops every step, as a
restart drops a provider call in flight today.

A chat run opens a *run scope* for its session. Inside it the loop adapter
opens a *step* per model call and awaits its answer; a driver claims steps
with ``wait_next`` (a long poll), reads pages with ``get`` and resolves them
with ``answer``. Identity is the user id the webapp took from the MCP token,
checked on every operation; a step of another user, or of a project the user
no longer owns, answers exactly like a step that does not exist.
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from collections import OrderedDict
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from . import CONTRACT_VERSION, LoopSettings, loop_enabled, settings as load_settings
from .errors import (
    LoopCapReached, LoopError, LoopNoDriver, LoopStepDeclined, LoopStepNotAnswered,
    sanitize_reason,
)
from .prompt_doc import RenderedMessage, Span, page, render

logger = logging.getLogger("agent_in_the_loop")

ENDED_STATUS_KEEP_S = 600
MAX_DEDUP_SETS_PER_DRIVER = 64
# A part is sent in full again this many steps after the driver received it: an
# interactive client compacts its context in long runs and may no longer hold it.
DEDUP_REFRESH_STEPS = 10
DRIVERS_SEEN_WINDOW_S = 300
# How often an awaiting step re-checks its deadline and the no-driver rule.
DEFAULT_POLL_S = 5.0
# How often a waiting driver re-checks for an expired lease nobody announced.
WAIT_SLICE_S = 1.0

OPEN, CLAIMED = "open", "claimed"
LIVE_STEP_STATES = (OPEN, CLAIMED)


@dataclass
class Step:
    id: str
    user_id: str
    project_id: str
    session_id: str
    purpose: str
    meta: dict
    messages: list[RenderedMessage]
    answer_format: str
    last_instruction: str
    opened_at: float = 0.0
    deadline_at: float = 0.0
    lease_until: float = 0.0
    claimed_by: str = ""
    state: str = OPEN
    answered_by: dict = field(default_factory=dict)
    answer: Optional[asyncio.Future] = None
    # Per claimant, the renderings it read, frozen for the step's life:
    # {claimant: {"full" | "dedup": (text, spans), "current": mode}}. A cursor is
    # an offset into ONE rendering, so it must never be re-rendered under it.
    renderings: dict = field(default_factory=dict)
    # Per claimant, pages served but not yet known to be received:
    # [(page_end, shas, step_no)]. Committed when the claimant asks for a later
    # page or answers; a page lost on the way never counts as delivered.
    pending: dict = field(default_factory=dict)


@dataclass
class SessionStatus:
    user_id: str
    project_id: str
    session_id: str
    state: str = "idle"
    detail: dict = field(default_factory=dict)
    since: float = 0.0
    live: bool = True
    ended_at: float = 0.0
    steps_answered: int = 0


@dataclass
class RunScope:
    key: str
    user_id: str
    project_id: str
    session_id: str
    uses_loop: bool
    callback: Any = None
    driver_lost: Optional[type] = None
    final_state: Optional[dict] = None
    live: bool = True
    # The last loop failure of this run (decline, no driver): kept so the
    # final status says why, even after later steps succeeded.
    loop_error: dict = field(default_factory=dict)


def session_key(user_id: str, project_id: str, session_id: str) -> str:
    return f"{user_id}:{project_id}:{session_id}"


def _driver_key(token_id: str, driver_name: Optional[str]) -> str:
    return f"{token_id}:{driver_name or ''}"


class StepBroker:
    def __init__(self, now: Callable[[], float] = time.monotonic,
                 config: Optional[LoopSettings] = None, poll_s: float = DEFAULT_POLL_S):
        self._now = now
        self.cfg = config or load_settings()
        self._poll_s = poll_s
        self._cond: Optional[asyncio.Condition] = None
        self._steps: dict[str, Step] = {}
        self._scopes: dict[str, list[RunScope]] = {}
        self._statuses: dict[str, SessionStatus] = {}
        self._session_ended: dict[str, float] = {}
        # (token_id, driver_name) -> OrderedDict[session_id -> set of shas], LRU.
        self._delivered: dict[tuple[str, str], OrderedDict] = {}
        self._last_driver_call: dict[str, float] = {}
        self._driver_seen: dict[str, float] = {}
        # session key -> the last driver call that could serve that session. A
        # driver scoped to one session is no presence for the user's others.
        self._seen: dict[str, float] = {}
        self._connected: dict[str, bool] = {}
        self._answered_by: dict[str, dict] = {}
        self._bg: set[asyncio.Task] = set()

    # ------------------------------------------------------------ helpers --
    @property
    def cond(self) -> asyncio.Condition:
        if self._cond is None:
            self._cond = asyncio.Condition()
        return self._cond

    async def _notify(self) -> None:
        async with self.cond:
            self.cond.notify_all()

    def _notify_soon(self) -> None:
        try:
            self._spawn(self._notify())
        except RuntimeError:
            pass

    def _spawn(self, coro) -> None:
        task = asyncio.get_running_loop().create_task(coro)
        self._bg.add(task)
        task.add_done_callback(self._bg.discard)

    def enabled(self) -> bool:
        return loop_enabled()

    def _live_scopes(self, key: str) -> list[RunScope]:
        return [s for s in self._scopes.get(key, []) if s.live]

    def _scope_of_step(self, step: Step) -> Optional[RunScope]:
        live = self._live_scopes(session_key(step.user_id, step.project_id, step.session_id))
        return live[-1] if live else None

    def scope_for_session(self, session_id: str) -> Optional[RunScope]:
        """The one live loop scope of this session, or None (fail closed)."""
        if not session_id:
            return None
        live = [s for scopes in self._scopes.values() for s in scopes
                if s.live and s.session_id == session_id]
        if len(live) != 1 or not live[0].uses_loop:
            return None
        return live[0]

    # ------------------------------------------------------- driver activity --
    def driver_connected(self, key: str) -> tuple[bool, Optional[float]]:
        """Whether a driver is serving this session: a call that could reach it in
        the last LOOP_DRIVER_SEEN_S, or a live lease on one of its steps."""
        now = self._now()
        last = self._seen.get(key)
        seen = None if last is None else max(0.0, now - last)
        if seen is not None and seen <= self.cfg.driver_seen_s:
            return True, seen
        leased = any(session_key(s.user_id, s.project_id, s.session_id) == key
                     and s.state == CLAIMED and s.lease_until > now
                     for s in self._steps.values())
        return leased, seen

    def _record_driver_call(self, user_id: str, token_id: str, driver_name: Optional[str],
                            project_ids: Optional[set[str]] = None,
                            session_id: Optional[str] = None,
                            step_key: Optional[str] = None) -> None:
        """Record a driver call as presence for every session it could serve: the
        user's live sessions in `project_ids` (only `session_id` when scoped), or
        the one session of the step it reads or answers (`step_key`)."""
        now = self._now()
        self._last_driver_call[user_id] = now
        self._driver_seen[_driver_key(token_id, driver_name)] = now
        if step_key:
            self._seen[step_key] = now
        if project_ids is not None:
            for key, status in self._statuses.items():
                if (status.user_id == user_id and status.live and status.project_id in project_ids
                        and (not session_id or status.session_id == session_id)):
                    self._seen[key] = now
        self._check_connected(user_id)

    def _check_connected(self, user_id: str) -> None:
        for key, status in self._statuses.items():
            if status.user_id != user_id or not status.live:
                continue
            connected, _ = self.driver_connected(key)
            if self._connected.get(key) != connected:
                self._connected[key] = connected
                self._emit(key)

    # ---------------------------------------------------------- status out --
    def status_payload(self, key: str) -> Optional[dict]:
        status = self._statuses.get(key)
        if status is None:
            return None
        now = self._now()
        steps = sorted((s for s in self._steps.values()
                        if session_key(s.user_id, s.project_id, s.session_id) == key
                        and s.state in LIVE_STEP_STATES), key=lambda s: s.opened_at)
        connected, seen = self.driver_connected(key)
        payload: dict = {
            "state": status.state,
            "detail": dict(status.detail),
            "driver": {"connected": connected,
                       "lastSeenSeconds": None if seen is None else int(seen)},
            "openSteps": len(steps),
            "sinceSeconds": int(max(0.0, now - status.since)),
        }
        if steps:
            shown = next((s for s in steps if s.state == CLAIMED), steps[0])
            payload["step"] = {"stepId": shown.id, "state": shown.state,
                               "purpose": shown.purpose,
                               "iteration": shown.meta.get("iteration")}
        return payload

    def _emit(self, key: str) -> None:
        scope = next(iter(reversed(self._live_scopes(key))), None)
        if scope is None or not scope.uses_loop or scope.callback is None:
            return
        payload = self.status_payload(key)
        on_status = getattr(scope.callback, "on_loop_status", None)
        if payload is None or on_status is None:
            return

        async def send():
            try:
                await on_status(payload)
            except Exception:  # the browser may be gone; the run goes on
                logger.debug("loop_status send failed for %s", key, exc_info=True)

        try:
            self._spawn(send())
        except RuntimeError:
            pass

    def _set_state(self, key: str, state: str, **detail) -> None:
        status = self._statuses.get(key)
        if status is None:
            return
        changed = status.state != state or status.detail != detail
        if status.state != state:
            status.since = self._now()
        status.state, status.detail = state, {k: v for k, v in detail.items() if v is not None}
        if changed:
            self._emit(key)
            self._notify_soon()

    def note(self, key: str, state: str, **detail) -> None:
        """A status change from the chat run (StreamingCallback)."""
        live = self._live_scopes(key)
        if not live or not live[-1].uses_loop:
            return
        self._set_state(key, state, **detail)

    # ----------------------------------------------------------- run scopes --
    @asynccontextmanager
    async def run_scope(self, user_id: str, project_id: str, session_id: str,
                        callback: Any, *, uses_loop: bool):
        key = session_key(user_id, project_id, session_id)
        scope = RunScope(key, user_id, project_id, session_id, uses_loop, callback)
        self._scopes.setdefault(key, []).append(scope)
        if uses_loop:
            self._statuses[key] = SessionStatus(user_id, project_id, session_id,
                                                state="thinking", since=self._now())
            self._emit(key)
        outcome, detail = "finished", {}
        try:
            yield scope
            outcome, detail = _final_outcome(scope.final_state)
        except asyncio.CancelledError:
            outcome = "stopped"
            raise
        except BaseException:
            outcome = "error"
            raise
        finally:
            self._close_scope(scope, outcome, detail)

    def _close_scope(self, scope: RunScope, outcome: str, detail: dict) -> None:
        now = self._now()
        if scope.uses_loop and scope.key in self._statuses:
            if outcome == "finished" and scope.loop_error:
                outcome, detail = "error", scope.loop_error
            self._set_state(scope.key, outcome, **detail)
        scope.live = False
        if not self._live_scopes(scope.key):
            for step in list(self._steps.values()):
                if (session_key(step.user_id, step.project_id, step.session_id) == scope.key
                        and step.state in LIVE_STEP_STATES):
                    self._close_step(step, "cancelled")
                    if step.answer is not None and not step.answer.done():
                        step.answer.cancel()
        remaining = [s for s in self._scopes.get(scope.key, []) if s.live]
        if remaining:
            self._scopes[scope.key] = remaining
        else:
            self._scopes.pop(scope.key, None)
            status = self._statuses.get(scope.key)
            if status is not None:
                status.live, status.ended_at = False, now
            self._session_ended[scope.session_id] = now
            self._answered_by.pop(scope.key, None)
        self._notify_soon()
        self._prune()

    # ---------------------------------------------------------------- steps --
    def new_step(self, scope: RunScope, *, purpose: str, meta: dict,
                 messages: list[RenderedMessage], answer_format: str,
                 last_instruction: str) -> Step:
        now = self._now()
        return Step(id=uuid.uuid4().hex, user_id=scope.user_id, project_id=scope.project_id,
                    session_id=scope.session_id, purpose=purpose, meta=dict(meta),
                    messages=messages, answer_format=answer_format,
                    last_instruction=last_instruction, opened_at=now,
                    deadline_at=now + self.cfg.step_deadline_s)

    async def open_step(self, step: Step, scope: Optional[RunScope] = None) -> None:
        scope = scope or self._scope_of_step(step)
        if scope is not None and scope.driver_lost is not None:
            raise scope.driver_lost()
        self._prune()
        open_count = sum(1 for s in self._steps.values()
                         if s.user_id == step.user_id and s.state in LIVE_STEP_STATES)
        if open_count >= self.cfg.max_open_steps_per_user:
            raise LoopCapReached()
        step.answer = asyncio.get_running_loop().create_future()
        step.state = OPEN
        self._steps[step.id] = step
        key = session_key(step.user_id, step.project_id, step.session_id)
        status = self._statuses.get(key)
        if status is not None and status.state != "thinking":
            self._set_state(key, "thinking")
        else:
            self._emit(key)
        await self._notify()

    async def await_answer(self, step: Step) -> str:
        key = session_key(step.user_id, step.project_id, step.session_id)
        try:
            while True:
                fut = step.answer
                if fut.done():
                    if fut.cancelled():
                        raise asyncio.CancelledError()
                    kind, value = fut.result()
                    if kind == "declined":
                        self._record_error(step, key, code=LoopStepDeclined.code, reason=value)
                        self._log_end(step, "declined")
                        raise LoopStepDeclined(value)
                    status = self._statuses.get(key)
                    if status is not None:
                        status.steps_answered += 1
                    return value
                now = self._now()
                if now >= step.deadline_at:
                    self._fail(step, key, LoopStepNotAnswered)
                # A claim whose lease ran out is unserved too: its driver may be gone,
                # and only another driver call would turn it back to open.
                if step.state == OPEN or (step.state == CLAIMED and step.lease_until <= now):
                    since = max(step.opened_at, self._seen.get(key, 0.0))
                    if now - since >= self.cfg.no_driver_grace_s:
                        self._fail(step, key, LoopNoDriver)
                self._check_connected(step.user_id)
                await asyncio.wait({fut}, timeout=self._poll_s)
        except asyncio.CancelledError:
            if step.state in LIVE_STEP_STATES:
                self._close_step(step, "cancelled")
            raise
        finally:
            self._steps.pop(step.id, None)
            self._notify_soon()

    def _fail(self, step: Step, key: str, error: type[LoopError]) -> None:
        self._close_step(step, "expired")
        scope = self._scope_of_step(step)
        if scope is not None:
            scope.driver_lost = error
        self._record_error(step, key, code=error.code)
        self._log_end(step, "expired" if error is LoopStepNotAnswered else "no_driver")
        raise error()

    def _record_error(self, step: Step, key: str, **detail) -> None:
        scope = self._scope_of_step(step)
        if scope is not None:
            scope.loop_error = dict(detail)
        self._set_state(key, "error", **detail)

    def _close_step(self, step: Step, state: str) -> None:
        step.state = state
        step.renderings.clear()
        step.pending.clear()

    def _log_end(self, step: Step, outcome: str) -> None:
        logger.warning(
            "loop step %s %s: purpose=%s session=%s waited_s=%d",
            step.id, outcome, step.purpose, step.session_id, int(self._now() - step.opened_at),
        )

    # --------------------------------------------------------------- drivers --
    def _purge_leases(self) -> None:
        now = self._now()
        for step in self._steps.values():
            if step.state == CLAIMED and step.lease_until <= now:
                # The renderings stay: the same driver may come back with a cursor.
                step.state, step.claimed_by = OPEN, ""
                self._emit(session_key(step.user_id, step.project_id, step.session_id))

    def _claimable(self, user_id: str, project_ids: set[str],
                   session_id: Optional[str]) -> Optional[Step]:
        candidates = [s for s in self._steps.values()
                      if s.state == OPEN and s.user_id == user_id and s.project_id in project_ids
                      and (not session_id or s.session_id == session_id)
                      and s.answer is not None and not s.answer.done()]
        return min(candidates, key=lambda s: s.opened_at, default=None)

    def _delivered_set(self, session_id: str, token_id: str,
                       driver_name: Optional[str], create: bool = False) -> Optional[dict]:
        """A driver's dedup state for one session: {"steps": n, "shas": {sha: step_no}}."""
        if not driver_name:
            return None
        sets = self._delivered.get((token_id, driver_name))
        if sets is None:
            if not create:
                return None
            sets = self._delivered[(token_id, driver_name)] = OrderedDict()
        if session_id not in sets:
            if not create:
                return None
            sets[session_id] = {"steps": 0, "shas": {}}
            while len(sets) > MAX_DEDUP_SETS_PER_DRIVER:
                sets.popitem(last=False)
        sets.move_to_end(session_id)
        return sets[session_id]

    def delivered_shas(self, session_id: str, token_id: str, driver_name: Optional[str]) -> set:
        """The parts this driver received in its last DEDUP_REFRESH_STEPS steps."""
        state = self._delivered_set(session_id, token_id, driver_name)
        if not state:
            return set()
        return {sha for sha, step_no in state["shas"].items()
                if state["steps"] - step_no < DEDUP_REFRESH_STEPS}

    def _rendering(self, step: Step, token_id: str, driver_name: Optional[str],
                   full: bool, cursor: int) -> tuple[str, list[Span]]:
        claimant = _driver_key(token_id, driver_name)
        mine = step.renderings.get(claimant)
        if mine is None:
            mine = step.renderings[claimant] = {}
            state = self._delivered_set(step.session_id, token_id, driver_name, create=True)
            if state is not None:
                state["steps"] += 1
                mine["step_no"] = state["steps"]
        mode = "full" if (full or not driver_name) else "dedup"
        # A cursor belongs to the rendering it came from: the mode changes only at 0.
        current = mine.get("current")
        if current is not None and current != mode and cursor > 0:
            mode = current
        if mode not in mine:
            delivered = (None if mode == "full"
                         else self.delivered_shas(step.session_id, token_id, driver_name))
            mine[mode] = render(step.messages, delivered=delivered, full=(mode == "full"))
        mine["current"] = mode
        return mine[mode]

    def _commit_pending(self, step: Step, token_id: str, driver_name: Optional[str],
                        upto: Optional[int] = None) -> None:
        """Count as delivered the pages the claimant proved it received: those ending
        at or before `upto` (it asked for a later page), or all of them (it answered)."""
        claimant = _driver_key(token_id, driver_name)
        pending = step.pending.get(claimant)
        if not pending:
            return
        state = self._delivered_set(step.session_id, token_id, driver_name, create=True)
        keep = []
        for page_end, shas, step_no in pending:
            if upto is None or page_end <= upto:
                if state is not None:
                    for sha in shas:
                        state["shas"][sha] = step_no
            else:
                keep.append((page_end, shas, step_no))
        step.pending[claimant] = keep

    def _view(self, step: Step, token_id: str, driver_name: Optional[str],
              cursor: int, full: bool) -> dict:
        text, spans = self._rendering(step, token_id, driver_name, full, cursor)
        chunk, next_cursor = page(text, cursor, self.cfg.page_chars)
        if driver_name and chunk:
            end = cursor + len(chunk)
            claimant = _driver_key(token_id, driver_name)
            step_no = step.renderings.get(claimant, {}).get("step_no", 0)
            step.pending.setdefault(claimant, []).append(
                (end, [s.sha for s in spans if cursor < s.end <= end], step_no))
        now = self._now()
        view = {
            "contractVersion": CONTRACT_VERSION,
            "stepId": step.id,
            "sessionId": step.session_id,
            "projectId": step.project_id,
            "purpose": step.purpose,
            "attempt": int(step.meta.get("attempt") or 0),
            "answerFormat": step.answer_format,
            "lastInstruction": step.last_instruction,
            "prompt": chunk,
            "page": {"cursor": cursor, "nextCursor": next_cursor, "totalChars": len(text)},
            "leaseExpiresInSeconds": int(max(0.0, step.lease_until - now)),
            "deadlineInSeconds": int(max(0.0, step.deadline_at - now)),
        }
        if step.meta.get("iteration") is not None:
            view["iteration"] = step.meta["iteration"]
        if step.meta.get("member_id"):
            view["member"] = {"id": step.meta["member_id"], "name": step.meta.get("member_name", "")}
        return view

    def _claim(self, step: Step, token_id: str, driver_name: Optional[str]) -> None:
        step.state = CLAIMED
        step.claimed_by = _driver_key(token_id, driver_name)
        step.lease_until = self._now() + self.cfg.lease_s

    def _sessions(self, user_id: str, project_ids: set[str], session_id: Optional[str]) -> list[dict]:
        now = self._now()
        out = []
        for key, status in self._statuses.items():
            if status.user_id != user_id or status.project_id not in project_ids:
                continue
            if session_id and status.session_id != session_id:
                continue
            if not status.live and now - status.ended_at > ENDED_STATUS_KEEP_S:
                continue
            open_steps = sum(1 for s in self._steps.values()
                             if session_key(s.user_id, s.project_id, s.session_id) == key
                             and s.state in LIVE_STEP_STATES)
            detail = {k: v for k, v in status.detail.items() if k in ("tool", "kind", "code")}
            out.append({"sessionId": status.session_id, "projectId": status.project_id,
                        "state": status.state, "detail": detail,
                        "sinceSeconds": int(max(0.0, now - status.since)),
                        "openSteps": open_steps})
        return sorted(out, key=lambda s: s["sinceSeconds"])

    async def wait_next(self, user_id: str, project_ids: list[str], session_id: Optional[str],
                        token_id: str, driver_name: Optional[str], timeout: float,
                        full: bool = False) -> dict:
        allowed = set(project_ids)
        self._prune()
        loop = asyncio.get_running_loop()
        give_up = loop.time() + max(0.0, timeout)
        while True:
            # A chat that starts while this call waits is served by it: count it
            # as present at once, not only from the driver's next call.
            self._record_driver_call(user_id, token_id, driver_name, project_ids=allowed,
                                     session_id=session_id)
            self._purge_leases()
            step = self._claimable(user_id, allowed, session_id)
            if step is not None:
                self._claim(step, token_id, driver_name)
                view = self._view(step, token_id, driver_name, 0, full)
                self._emit(session_key(step.user_id, step.project_id, step.session_id))
                return {"step": view, "sessions": self._sessions(user_id, allowed, session_id)}
            remaining = give_up - loop.time()
            if remaining <= 0:
                return {"step": None, "sessions": self._sessions(user_id, allowed, session_id)}
            try:
                async with self.cond:
                    await asyncio.wait_for(self.cond.wait(), min(remaining, WAIT_SLICE_S))
            except asyncio.TimeoutError:
                pass

    def get(self, user_id: str, project_ids: list[str], step_id: str, token_id: str,
            driver_name: Optional[str], cursor: int, full: bool) -> Optional[dict]:
        self._record_driver_call(user_id, token_id, driver_name)
        self._purge_leases()
        step = self._steps.get(step_id)
        if (step is None or step.user_id != user_id or step.project_id not in set(project_ids)
                or step.state not in LIVE_STEP_STATES):
            return None
        claimant = _driver_key(token_id, driver_name)
        if step.state == CLAIMED and step.claimed_by != claimant:
            return None
        key = session_key(step.user_id, step.project_id, step.session_id)
        self._record_driver_call(user_id, token_id, driver_name, step_key=key)
        cursor = max(0, int(cursor))
        # Asking for a page proves the pages before it arrived.
        self._commit_pending(step, token_id, driver_name, upto=cursor)
        if step.state == OPEN:
            self._emit(key)
        self._claim(step, token_id, driver_name)
        return self._view(step, token_id, driver_name, cursor, bool(full))

    async def answer(self, user_id: str, project_ids: list[str], step_id: str, *,
                     text: Optional[str] = None, declined: bool = False, reason: str = "",
                     answered_by: Optional[dict] = None, token_id: str = "",
                     driver_name: Optional[str] = None) -> dict:
        self._record_driver_call(user_id, token_id, driver_name)
        step = self._steps.get(step_id)
        if (step is None or step.user_id != user_id or step.project_id not in set(project_ids)
                or step.state not in LIVE_STEP_STATES or step.answer is None or step.answer.done()):
            return {"ok": False, "code": "step_closed"}
        if not declined and len(text or "") > self.cfg.answer_max_chars:
            return {"ok": False, "code": "answer_too_large"}
        key = session_key(step.user_id, step.project_id, step.session_id)
        self._record_driver_call(user_id, token_id, driver_name, step_key=key)
        # An answer (or a decline) proves every page this claimant read arrived.
        self._commit_pending(step, token_id, driver_name)
        step.answered_by = dict(answered_by or {})
        if step.answered_by and step.purpose == "think":
            self._answered_by[session_key(step.user_id, step.project_id, step.session_id)] = \
                dict(step.answered_by)
        if declined:
            self._close_step(step, "declined")
            step.answer.set_result(("declined", sanitize_reason(reason)))
        else:
            self._close_step(step, "answered")
            step.answer.set_result(("answer", text or ""))
        self._emit(session_key(step.user_id, step.project_id, step.session_id))
        await self._notify()
        return {"ok": True, "projectId": step.project_id, "sessionId": step.session_id,
                "purpose": step.purpose, "iteration": step.meta.get("iteration")}

    # ------------------------------------------------------- housekeeping --
    def _prune(self) -> None:
        now = self._now()
        ttl = self.cfg.state_ttl_s
        for key in [k for k, s in self._statuses.items()
                    if not s.live and now - s.ended_at > ENDED_STATUS_KEEP_S]:
            del self._statuses[key]
        live_sessions = {s.session_id for scopes in self._scopes.values() for s in scopes if s.live}
        stale = {sid for sid, ended in self._session_ended.items()
                 if sid not in live_sessions and now - ended > ttl}
        for sid in stale:
            del self._session_ended[sid]
        for driver, sets in list(self._delivered.items()):
            for sid in [sid for sid in sets if sid in stale]:
                del sets[sid]
            if not sets:
                del self._delivered[driver]
        for table in (self._last_driver_call, self._driver_seen, self._seen):
            for k in [k for k, t in table.items() if now - t > ttl]:
                del table[k]
        for key in [k for k in self._connected if k not in self._statuses]:
            del self._connected[key]

    def take_answered_by(self, key: str) -> Optional[dict]:
        """Who answered the last decision step of this session, once (T23)."""
        return self._answered_by.pop(key, None)

    def stats(self) -> dict:
        now = self._now()
        live = [s for s in self._steps.values() if s.state in LIVE_STEP_STATES]
        return {
            "open_steps": sum(1 for s in live if s.state == OPEN),
            "claimed_steps": sum(1 for s in live if s.state == CLAIMED),
            "waiting_sessions": len({(s.user_id, s.project_id, s.session_id) for s in live}),
            "drivers_seen_5m": sum(1 for t in self._driver_seen.values()
                                   if now - t <= DRIVERS_SEEN_WINDOW_S),
        }

    def live_loop_state(self, key: str) -> Optional[str]:
        """The state for /agent-sessions/live, or None when the run is not a loop run."""
        live = self._live_scopes(key)
        status = self._statuses.get(key)
        if not live or not live[-1].uses_loop or status is None:
            return None
        if any(session_key(s.user_id, s.project_id, s.session_id) == key
               and s.state in LIVE_STEP_STATES for s in self._steps.values()):
            return "waiting_for_agent"
        return status.state


    def loop_states_for_project(self, project_id: str) -> dict[str, str]:
        """{session_id: state} of the project's live loop runs."""
        out = {}
        for key, scopes in self._scopes.items():
            live = [s for s in scopes if s.live]
            if live and live[-1].uses_loop and live[-1].project_id == project_id:
                state = self.live_loop_state(key)
                if state:
                    out[live[-1].session_id] = state
        return out


def _final_outcome(final_state: Optional[dict]) -> tuple[str, dict]:
    state = final_state or {}
    for flag, kind in (("awaiting_tool_confirmation", "tool_confirmation"),
                       ("awaiting_user_approval", "approval"),
                       ("awaiting_user_question", "question")):
        if state.get(flag):
            return "awaiting_human", {"kind": kind}
    return "finished", {}


_broker: Optional[StepBroker] = None


def get_broker() -> StepBroker:
    global _broker
    if _broker is None:
        _broker = StepBroker()
    return _broker
