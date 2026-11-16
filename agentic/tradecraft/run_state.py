"""One collector per agent run for the Tradecraft counters and the pages already seen (Q6, TD-13).

A run is one message with its resumes. Its library pages read or suggested, its librarian
questions and its hints live in AgentState fields (and the same on FireteamMemberState)
with no reducer. Tools never return state, so they add to the run's collector instead, and
the node that ran the tools returns ``drain()``: the full merged values, written as they are.

The values carry the run they belong to (``tradecraft_run_key``). LangGraph merges each new
message into the session's checkpoint, so the counters of the last message are still in the
state when the next one starts: a new message adds a new objective (initialize_node), its
key differs from the stored one, and ``bind`` starts from empty values. A resume (an
approval, an answer, a tool confirmation) keeps the objective, so it keeps the counts. A
Fireteam member's state has no objective index and keeps the run's values it was seeded with.

The collector sits in a context variable. The first node that binds creates it from the
state; asyncio copies the context, and with it the reference to the same collector, into
every task started afterwards, so the tools of a plan wave and the Fireteam members started
after the bind add to one collector, and a member's own ``bind`` keeps it. A node runs in
its own task, so the next node binds afresh from the state the previous one returned.
"""

from __future__ import annotations

import contextlib
import contextvars
import threading
from typing import Any, Iterable, Iterator, Mapping, Optional

FIELDS = (
    "tradecraft_seen_pages", "tradecraft_ask_count", "tradecraft_hint_count", "tradecraft_hint_log", "tradecraft_run_key",
)
COUNTERS = {"ask": "tradecraft_ask_count", "hint": "tradecraft_hint_count"}


def fresh_values(key: Optional[str] = None) -> dict[str, Any]:
    """The fields at the start of a run (a new message)."""
    return {"tradecraft_seen_pages": [], "tradecraft_ask_count": 0, "tradecraft_hint_count": 0,
            "tradecraft_hint_log": [], "tradecraft_run_key": key}


def run_key(state: Mapping[str, Any]) -> Optional[str]:
    """The run this state is in: its current objective, which a new message moves and a resume
    keeps; None for a state that has none (a Fireteam member's)."""
    index = state.get("current_objective_index")
    if isinstance(index, int) and not isinstance(index, bool):
        return f"objective:{index}"
    return None


def _int(v: Any) -> int:
    return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else 0


class RunCollector:
    """The run's pages and counts. Several tasks of one event loop add to it; a lock keeps a
    tool that runs in a worker thread from losing an update."""

    def __init__(self, state: Mapping[str, Any], session_id: str):
        self.session_id = session_id
        key, stored = run_key(state), state.get("tradecraft_run_key")
        self.run_key = key if key is not None else stored
        if key is not None and stored != key:
            # The values in the state belong to an earlier message of this session.
            state = {}
        seen = state.get("tradecraft_seen_pages") or []
        self._seen: list[str] = []
        for page in seen:
            if isinstance(page, str) and page and page not in self._seen:
                self._seen.append(page)
        self._counts = {kind: _int(state.get(field)) for kind, field in COUNTERS.items()}
        log = state.get("tradecraft_hint_log") or []
        self._hint_log: list[dict] = [dict(e) for e in log if isinstance(e, Mapping)]
        self._lock = threading.Lock()

    def record_seen(self, page_ids: Iterable[str]) -> list[str]:
        """Adds the page IDs not seen yet in this run; returns the ones that were new."""
        added = []
        with self._lock:
            for page in page_ids:
                if isinstance(page, str) and page and page not in self._seen:
                    self._seen.append(page)
                    added.append(page)
        return added

    def has_seen(self, page_id: str) -> bool:
        with self._lock:
            return page_id in self._seen

    def incr(self, kind: str) -> int:
        """One more librarian question (``"ask"``) or hint (``"hint"``); returns the new count."""
        if kind not in COUNTERS:
            raise ValueError(f"unknown counter {kind!r}: one of {', '.join(COUNTERS)}")
        with self._lock:
            self._counts[kind] += 1
            return self._counts[kind]

    def log_hint(self, entry: Mapping[str, Any]) -> None:
        """A hint note given (its checkpoint, page IDs, whether one was read later)."""
        with self._lock:
            self._hint_log.append(dict(entry))

    def counts(self) -> dict[str, int]:
        with self._lock:
            return dict(self._counts)

    def drain(self) -> dict[str, Any]:
        """The full values of the four fields, for the node's return. Copies: the collector
        keeps counting, and a second drain returns the same values plus what came since."""
        with self._lock:
            return {
                "tradecraft_seen_pages": list(self._seen),
                "tradecraft_ask_count": self._counts["ask"],
                "tradecraft_hint_count": self._counts["hint"],
                "tradecraft_hint_log": [dict(e) for e in self._hint_log],
                "tradecraft_run_key": self.run_key,
            }


_current: contextvars.ContextVar[Optional[RunCollector]] = contextvars.ContextVar("tradecraft_run_state", default=None)


def bind(state: Mapping[str, Any]) -> RunCollector:
    """The run's collector: the one already bound in this context for the same session and
    run (a plan wave's task, a Fireteam member), or a new one built from ``state``."""
    session_id = str(state.get("session_id") or "")
    key = run_key(state)
    collector = _current.get()
    if (collector is None or collector.session_id != session_id
            or (key is not None and collector.run_key != key)):
        collector = RunCollector(state, session_id)
        _current.set(collector)
    return collector


@contextlib.contextmanager
def bound(state: Mapping[str, Any]) -> Iterator[RunCollector]:
    """``bind`` for the length of a block, then the context as it was."""
    token = _current.set(_current.get())
    try:
        yield bind(state)
    finally:
        _current.reset(token)


def current() -> Optional[RunCollector]:
    return _current.get()


def _require() -> RunCollector:
    collector = _current.get()
    if collector is None:
        raise LookupError("no Tradecraft run state is bound in this task: the executor node binds it first")
    return collector


def record_seen(page_ids: Iterable[str]) -> list[str]:
    return _require().record_seen(page_ids)


def incr(kind: str) -> int:
    return _require().incr(kind)


def log_hint(entry: Mapping[str, Any]) -> None:
    _require().log_hint(entry)


def counts() -> dict[str, int]:
    return _require().counts()


def drain() -> dict[str, Any]:
    return _require().drain()
