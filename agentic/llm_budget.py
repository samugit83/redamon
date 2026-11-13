"""Daily budget of model calls on instance LLM providers (step 6.11, GV-12).

An administrator may give a person a daily number of model calls on the
providers the instance shares (6.8's `llmDailyCalls` quota; none = unlimited).
Every model built from an instance row (llm_setup.setup_llm's instance branch)
carries an `InstanceBudgetCallback`: before each call it asks this module, which
refuses with `LlmBudgetExhausted` (`llm_budget_exhausted`) once either budget is
used up:

- the actor's: the person who runs the call (the graph run's `user_id`, which
  LangChain copies into the callback metadata; the row's owner when the call has
  no run, as for a feature model or a recon planner);
- the owner's: the account whose provider list the row came from, the project's
  owner on a project run (C1). On a shared project the stricter of the two
  refuses (the Phase 6 kickoff's assumption). A call is counted once, for the
  actor, so the owner's usage report names who spent it.

It applies on top of the agent's own caps, never instead of them
(`LLM_GUARD_DAILY_CALL_CAP` in llm_guard.py and the MCP budget): whichever is
reached first refuses.

Each person's limit and the day's stored count are read from the webapp
(`GET /api/internal/llm-usage`, master key) and kept for `BUDGET_TTL_S`; the
calls counted here are reported to `POST /api/internal/llm-usage` at most every
`REPORT_EVERY_S`, in a background thread, and kept for the next report when one
fails. A budget that cannot be read is not enforced for that call (logged
`[rbac] llm_budget_unreadable`): it is a spend cap, the provider itself was
already authorised by the owner's entitlement, and a webapp blip must not stop
runs. Days are UTC.
"""
from __future__ import annotations

import logging
import os
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

BUDGET_TTL_S = 60.0
REPORT_EVERY_S = 60.0
FETCH_TIMEOUT_S = 3
REPORT_TIMEOUT_S = 5


class LlmBudgetExhausted(RuntimeError):
    """A model call refused because a daily budget on instance providers is used up.

    Never retried (`no_retry`); the text holds no transient phrase.
    """
    code = "llm_budget_exhausted"
    no_retry = True

    def __init__(self, user_id: str, limit: int, whose: str):
        self.user_id = user_id
        self.limit = limit
        self.whose = whose
        super().__init__(
            f"The daily budget of {limit} model calls on instance LLM providers is used up "
            f"({whose}); it starts again at 00:00 UTC.")


def utc_day(now: float) -> str:
    return datetime.fromtimestamp(now, tz=timezone.utc).strftime("%Y-%m-%d")


WEBAPP_API_URL = os.environ.get("WEBAPP_API_URL", "http://webapp:3000").rstrip("/")


def _headers() -> dict:
    return {"X-Internal-Key": os.environ.get("INTERNAL_API_KEY", "")}


def _count(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def fetch_budget(user_id: str) -> tuple[Optional[int], int]:
    """(limit or None for unlimited, calls stored today) of one person. Raises on any failure."""
    import requests

    url = f"{WEBAPP_API_URL}/api/internal/llm-usage"
    resp = requests.get(url, params={"userId": user_id}, headers=_headers(), timeout=FETCH_TIMEOUT_S)
    resp.raise_for_status()
    body = resp.json()
    limit, used = body.get("limit"), body.get("used")
    if (limit is not None and not _count(limit)) or not _count(used):
        raise ValueError("the budget answer holds no counts")
    return limit, used


def report_usage(counts: list[dict]) -> None:
    """Adds `[{userId, day, count}]` to the stored counts. Raises on any failure."""
    import requests

    url = f"{WEBAPP_API_URL}/api/internal/llm-usage"
    resp = requests.post(url, json={"counts": counts}, headers=_headers(), timeout=REPORT_TIMEOUT_S)
    resp.raise_for_status()


class BudgetTracker:
    """Per-process counts and cached budgets; thread-safe."""

    def __init__(self, fetch: Callable[[str], tuple] = fetch_budget,
                 report: Callable[[list], None] = report_usage,
                 clock: Callable[[], float] = time.time,
                 background: bool = True):
        self._fetch = fetch
        self._report = report
        self._clock = clock
        self._background = background
        self._lock = threading.Lock()
        # (user, day) -> (limit, stored count, read at)
        self._budgets: dict[tuple[str, str], tuple[Optional[int], int, float]] = {}
        # (user, day) -> calls counted here that the cached stored count does not include
        self._local: dict[tuple[str, str], int] = {}
        # (user, day) -> calls counted here and not reported yet
        self._pending: dict[tuple[str, str], int] = {}
        self._last_report = clock()

    def _budget(self, user: str, day: str, now: float) -> tuple[Optional[int], int]:
        key = (user, day)
        with self._lock:
            cached = self._budgets.get(key)
        if cached is None or now - cached[2] >= BUDGET_TTL_S:
            try:
                limit, used = self._fetch(user)
            except Exception as exc:                              # noqa: BLE001
                logger.warning(f"[rbac] llm_budget_unreadable: user {user} ({type(exc).__name__})")
                if cached is None:
                    return None, 0
            else:
                with self._lock:
                    self._budgets[key] = (limit, used, now)
                    # The stored count holds every reported call; the unreported ones are added here.
                    self._local[key] = self._pending.get(key, 0)
                    cached = self._budgets[key]
        with self._lock:
            return cached[0], cached[1] + self._local.get(key, 0)

    def consume(self, owner_id: str, actor_id: str) -> None:
        """Counts one call for the actor, or raises LlmBudgetExhausted. A call with no person is not counted."""
        actor = actor_id or owner_id
        if not actor:
            return
        now = self._clock()
        day = utc_day(now)
        checks = [(actor, "yours")] + ([(owner_id, "the project owner's")] if owner_id and owner_id != actor else [])
        for user, whose in checks:
            limit, used = self._budget(user, day, now)
            if limit is not None and used >= limit:
                logger.info(f"[rbac] llm_budget_exhausted: user {user} limit {limit} used {used}")
                raise LlmBudgetExhausted(user, limit, whose)
        key = (actor, day)
        with self._lock:
            self._local[key] = self._local.get(key, 0) + 1
            self._pending[key] = self._pending.get(key, 0) + 1
        self.maybe_report(now)

    def maybe_report(self, now: Optional[float] = None, force: bool = False) -> None:
        now = self._clock() if now is None else now
        with self._lock:
            if not self._pending or (not force and now - self._last_report < REPORT_EVERY_S):
                return
            batch = dict(self._pending)
            self._pending.clear()
            self._last_report = now
        counts = [{"userId": u, "day": d, "count": c} for (u, d), c in sorted(batch.items())]
        if self._background:
            threading.Thread(target=self._send, args=(batch, counts), daemon=True).start()
        else:
            self._send(batch, counts)

    def _send(self, batch: dict, counts: list) -> None:
        try:
            self._report(counts)
        except Exception as exc:                                  # noqa: BLE001
            logger.warning(f"[rbac] llm_usage_report_failed: {len(counts)} count(s) kept ({type(exc).__name__})")
            with self._lock:
                for key, count in batch.items():
                    self._pending[key] = self._pending.get(key, 0) + count

    def pending(self) -> dict:
        with self._lock:
            return dict(self._pending)


_tracker: Optional[BudgetTracker] = None
_tracker_lock = threading.Lock()


def tracker() -> BudgetTracker:
    global _tracker
    with _tracker_lock:
        if _tracker is None:
            _tracker = BudgetTracker()
        return _tracker


def set_tracker_for_tests(value: Optional[BudgetTracker]) -> None:
    global _tracker
    with _tracker_lock:
        _tracker = value


from langchain_core.callbacks import BaseCallbackHandler  # noqa: E402


class InstanceBudgetCallback(BaseCallbackHandler):
    """Asks the budget before every call of a model built from an instance row; a refusal raises."""

    raise_error = True

    def __init__(self, owner_id: str, provider_id: str):
        self.owner_id = owner_id
        self.provider_id = provider_id

    def _check(self, metadata: Optional[dict]) -> None:
        actor = (metadata or {}).get("user_id")
        tracker().consume(self.owner_id, actor if isinstance(actor, str) else "")

    def on_chat_model_start(self, serialized: Any, messages: Any, *, metadata: Optional[dict] = None, **kwargs: Any) -> None:
        self._check(metadata)

    def on_llm_start(self, serialized: Any, prompts: Any, *, metadata: Optional[dict] = None, **kwargs: Any) -> None:
        self._check(metadata)


def attach_instance_budget(llm, owner_id: str, provider_id: str):
    """`llm`, with the budget asked before each of its calls (bound and structured variants included)."""
    llm.callbacks = [*(getattr(llm, "callbacks", None) or []), InstanceBudgetCallback(owner_id, provider_id)]
    return llm
