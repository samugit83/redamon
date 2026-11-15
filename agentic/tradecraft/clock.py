"""The one source of time for tradecraft code.

Leases, deadlines, pacing and timestamps all read this module, so a test swaps the
clock with ``use_clock(FakeClock())`` instead of patching ``datetime`` or sleeping.
The clock lives in a context variable: a task started inside ``use_clock`` keeps it,
and production code never passes a clock around.
"""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import time
from datetime import datetime, timezone
from typing import Iterator, Protocol


class Clock(Protocol):
    def now(self) -> datetime: ...

    def monotonic(self) -> float: ...

    async def sleep(self, seconds: float) -> None: ...


class RealClock:
    def now(self) -> datetime:
        return datetime.now(timezone.utc)

    def monotonic(self) -> float:
        return time.monotonic()

    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(max(0.0, seconds))


_REAL = RealClock()
_current: contextvars.ContextVar[Clock] = contextvars.ContextVar("tradecraft_clock", default=_REAL)


def now() -> datetime:
    """The current time, UTC and timezone-aware."""
    return _current.get().now()


def monotonic() -> float:
    return _current.get().monotonic()


async def sleep(seconds: float) -> None:
    await _current.get().sleep(seconds)


@contextlib.contextmanager
def use_clock(clock: Clock) -> Iterator[Clock]:
    token = _current.set(clock)
    try:
        yield clock
    finally:
        _current.reset(token)
