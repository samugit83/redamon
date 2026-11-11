"""One request clock for the whole recon process: the RoE ceiling (decision D3).

``ROE_GLOBAL_MAX_RPS`` is the request rate agreed with the client for the
engagement, across everything recon sends. The external tools get it through
their own rate flags (``apply_roe_rate_cap``); this pacer holds it for the
requests recon makes itself, in-process. Every such requester takes a slot
before each request::

    from recon.helpers import request_pacer
    request_pacer.acquire()          # or: with request_pacer.pacer(): ...
    response = session.get(url, ...)

The slots are shared by every thread and every module, so N workers together
never exceed the ceiling, and a Domain batch's groups (run one after another in
one process) never reset it. With RoE off or no ceiling the pacer is inert:
``acquire`` returns at once, without taking a lock or reading the clock.

The process configures it once from the run's settings (``configure``). A
module that holds the settings may pass them to ``pacer(settings)``, which
configures it only when nothing did yet. Import it as
``recon.helpers.request_pacer`` only: loaded a second time under another name
(``helpers.request_pacer``) it would be a second clock and the ceiling would
double.
"""
from __future__ import annotations

import math
import threading
import time
from typing import Any, Callable, Mapping, Optional


def ceiling_rps(settings: Optional[Mapping[str, Any]]) -> float:
    """The RoE ceiling in requests per second, or 0.0 when there is none.

    The capper's own rule (``apply_roe_rate_cap``): RoE on and a rate above 0.
    Anything else, a missing, non-numeric or non-finite value included, is no
    ceiling, as it is for the tool rates.
    """
    if not settings or not settings.get("ROE_ENABLED", False):
        return 0.0
    raw = settings.get("ROE_GLOBAL_MAX_RPS")
    if isinstance(raw, bool):
        return 0.0
    try:
        rps = float(raw or 0)
    except (TypeError, ValueError):
        return 0.0
    return rps if math.isfinite(rps) and rps > 0 else 0.0


class RequestPacer:
    """A locked request clock: one slot every ``1 / rps`` seconds.

    ``acquire`` reserves the next free slot under the lock and sleeps outside
    it, so the waits of concurrent callers queue up instead of colliding.
    It never raises and never gives up: the time spent waiting is the
    ceiling's, not the target's, so a caller with a deadline should extend it
    by the returned wait rather than fail on it.
    """

    def __init__(self, rps: float = 0, *, clock: Optional[Callable[[], float]] = None,
                 sleep: Optional[Callable[[float], None]] = None):
        # None: look time.monotonic / time.sleep up at each call, so a test
        # that patches the time module drives every pacer at once.
        self._clock = clock
        self._sleep = sleep
        self._lock = threading.Lock()
        self._interval = 0.0
        self._next = 0.0
        self.set_rate(rps)

    @property
    def rps(self) -> float:
        return 1.0 / self._interval if self._interval else 0.0

    @property
    def active(self) -> bool:
        return bool(self._interval)

    def set_rate(self, rps: float) -> None:
        """0 makes the pacer inert. Slots already handed out stay where they are."""
        rate = float(rps or 0)
        if not math.isfinite(rate) or rate < 0:
            raise ValueError("request rate must be a finite number >= 0")
        with self._lock:
            self._interval = 1.0 / rate if rate else 0.0

    def _now(self) -> float:
        return (self._clock or time.monotonic)()

    def acquire(self) -> float:
        """Wait for this request's slot; returns the seconds waited."""
        if not self._interval:
            return 0.0
        with self._lock:
            interval = self._interval
            if not interval:
                return 0.0
            now = self._now()
            slot = max(now, self._next)
            self._next = slot + interval
        delay = slot - now
        if delay > 0:
            (self._sleep or time.sleep)(delay)
            return delay
        return 0.0

    def back_off(self, seconds: float) -> None:
        """Push every caller's next slot back (a 429, a Retry-After). Inert pacers ignore it."""
        if not self._interval:
            return
        with self._lock:
            self._next = max(self._next, self._now() + max(0.0, float(seconds or 0)))

    def _reset(self) -> None:
        with self._lock:
            self._interval = 0.0
            self._next = 0.0

    def __enter__(self) -> "RequestPacer":
        self.acquire()
        return self

    def __exit__(self, *exc) -> bool:
        return False


_PACER = RequestPacer(0)
_CONFIGURED = False
_CONFIG_LOCK = threading.Lock()


def _configure_locked(settings: Optional[Mapping[str, Any]]) -> None:
    global _CONFIGURED
    _PACER.set_rate(ceiling_rps(settings))
    _CONFIGURED = True
    if _PACER.rps:
        print(f"[*][RoE] In-process requests paced to the {_PACER.rps:g} rps ceiling, across every module")


def configure(settings: Optional[Mapping[str, Any]]) -> RequestPacer:
    """Set the process-wide ceiling from the run's settings. Call once at process start."""
    with _CONFIG_LOCK:
        _configure_locked(settings)
    return _PACER


def pacer(settings: Optional[Mapping[str, Any]] = None) -> RequestPacer:
    """The process-wide pacer; ``settings`` configure it only when nothing has yet."""
    if settings is not None and not _CONFIGURED:
        with _CONFIG_LOCK:
            if not _CONFIGURED:
                _configure_locked(settings)
    return _PACER


def acquire() -> float:
    """Take one slot of the process-wide pacer before a request; returns the seconds waited."""
    return _PACER.acquire()


def ceiling() -> float:
    """The process-wide ceiling in force, 0.0 when requests are not paced."""
    return _PACER.rps


def reset() -> None:
    """Tests only (a new scan is a new process): an inert, unconfigured pacer.

    Reset in place, so a module holding the pacer object sees the change.
    """
    global _CONFIGURED
    with _CONFIG_LOCK:
        _PACER._reset()
        _CONFIGURED = False
