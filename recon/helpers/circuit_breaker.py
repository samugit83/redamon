"""Circuit breakers for the recon pipeline's outbound calls.

A client that returns the same ``None``/``[]`` for "the service failed" and for
"there is no data" leaves its loop unable to tell a dead dependency from a clean
item, so it keeps paying the full timeout for every IP, domain, URL or finding
still queued. This module gives every outbound call a typed outcome and a
per-dependency breaker that stops calling after N consecutive failures, while a
genuinely empty answer (``NO_DATA``) never trips it.

Four pieces:

* **Outcomes** - ``Outcome`` / ``CallResult`` and the classifiers.
* **Breaker** - one per dependency key (``"otx:passive_dns"``). A key may name a
  provider-level parent (``"otx"``): a rate limit or a rejected key is a property
  of the account, so it stops every endpoint, while timeouts and 5xx stay
  endpoint-local.
* **HostHealth** - per scan target (``host:port``); counts connection failures
  only, never an HTTP response.
* **Coverage accumulator** - what this run could not check, read by the prune
  guard, the Domain coverage record and run history.

Rules every caller relies on:

* Nothing here raises. A guarded call whose breaker is open returns a
  ``SKIPPED`` result and the caller hands back its existing empty value; an
  internal fault lets the call through, which is today's behaviour.
* A ``detail`` is an HTTP status, an exception class name or a fixed phrase -
  never a response body and never exception text (``requests`` puts the full
  URL, key parameter included, into its connection-error messages).
* Import it only as ``recon.helpers.circuit_breaker``. The runtime has both
  ``/app`` and ``/app/recon`` on ``sys.path``, so ``helpers.circuit_breaker``
  would load a second module with a second registry. Import it lazily inside
  functions: ``recon/helpers/__init__.py`` eagerly imports the docker, security
  and CVE helpers.
* State is process-wide. One scan (or one partial run) is one container
  process, and a Domain batch runs its groups sequentially in it, so a breaker
  opened in group 1 legitimately stays open for group 2.

``RECON_CIRCUIT_BREAKERS=off`` makes every breaker and HostHealth admit every
call. It never disables the coverage accumulator: Nuclei truncation, image-pull
failures and budget kills are still recorded and still hold back the prune.
"""
from __future__ import annotations

import enum
import errno
import json
import math
import os
import re
import socket
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Optional
from urllib.parse import urlsplit

THIRD_PARTY_THRESHOLD = 5
# The agent LLM, WHOIS and scan targets fail as a unit: three in a row is enough.
INTERNAL_THRESHOLD = 3
COOLDOWN_S = 120.0
MAX_COOLDOWN_S = 1800.0
HOST_COOLDOWN_S = 300.0
# How long a half-open probe may stay unanswered before another caller may
# probe. Longer than any request timeout the pipeline uses for these calls.
PROBE_GRACE_S = 90.0
RETRY_AFTER_DEFAULT_S = 2.0
RETRY_AFTER_MAX_S = 60.0
DETAIL_MAX = 80
LOG_TEXT_MAX = 100
# How many skipped hosts a DEGRADED line names before it only counts them.
LOG_HOSTS_MAX = 10
# How many skipped hosts the Domain coverage record stores. The prune guard uses
# the full in-process list, so the cap never changes what is kept.
STORED_HOSTS_MAX = 500

_SWITCH = "RECON_CIRCUIT_BREAKERS"

# Log templates. The orchestrator classifies a line by its bracket prefix and
# flips the drawer's phase on PHASE_PATTERNS matched case-insensitively across
# the whole line, so these avoid every phase word ("probe" included: a detail
# is often "HTTP 502", and "http" ... "prob" is the HTTP-probing phase).
# recon/tests/test_circuit_breaker.py pins them against a copy of the patterns.
MSG_OPEN_TRANSIENT = ("[!][{label}] {name}: {count} consecutive failures ({detail})"
                      " - pausing it, next try in {cooldown}s")
MSG_OPEN_RATE_LIMIT = ("[!][{label}] {name}: rate-limited twice in a row ({detail})"
                       " - pausing it, next try in {cooldown}s")
MSG_OPEN_FORCED = "[!][{label}] {name}: {detail} - pausing it, next try in {cooldown}s"
MSG_OPEN_FATAL = "[!][{label}] {name}: {detail} - stopped for the rest of this run"
MSG_RECOVERED = "[+][{label}] {name} responding again - resumed"
MSG_KEY_DROPPED = ("[!][{label}] API key #{position} rejected ({detail})"
                   " - removed from rotation ({left} left)")
MSG_DEGRADED = "[!][DEGRADED][{label}] {name} skipped for {count} {unit} ({detail})"
MSG_DEGRADED_HOSTS = "[!][DEGRADED][{label}] {count} unreachable host(s) skipped: {hosts}"
MSG_HOST_DOWN = ("[!][Host] {host} unreachable ({count} connection failures)"
                 " - skipping it, next try in {cooldown}s")
MSG_HOST_BACK = "[+][Host] {host} responding again - resumed"
MSG_SWITCH_OFF = ("[*][Breakers] circuit breakers are off ({switch}=off) - failing"
                  " dependencies are called for every item")

TEMPLATES = (
    MSG_OPEN_TRANSIENT, MSG_OPEN_RATE_LIMIT, MSG_OPEN_FORCED, MSG_OPEN_FATAL,
    MSG_RECOVERED, MSG_KEY_DROPPED, MSG_DEGRADED, MSG_DEGRADED_HOSTS,
    MSG_HOST_DOWN, MSG_HOST_BACK, MSG_SWITCH_OFF,
)


# ---------------------------------------------------------------------------
# Switch, clock, output
# ---------------------------------------------------------------------------

def enabled() -> bool:
    """False only for the exact value ``off``; anything else, or unset, is on.

    Whitespace is stripped so a CRLF ``.env`` still switches it off. Read on
    every call rather than cached, so a test can flip it with ``patch.dict``.
    """
    return os.environ.get(_SWITCH, "on").strip() != "off"


def mode() -> str:
    """``"on"`` or ``"off"``, as recorded in the recon JSON metadata."""
    return "on" if enabled() else "off"


def announce_mode() -> str:
    """Print the one ``[*]`` line a run shows when the switch is off."""
    if not enabled():
        _emit(MSG_SWITCH_OFF.format(switch=_SWITCH))
    return mode()


def _monotonic() -> float:
    # Looked up at call time so a test that patches ``time.monotonic`` or
    # ``time.sleep`` in the module under test reaches this module too.
    return time.monotonic()


def _default_sleep(seconds: float) -> None:
    time.sleep(seconds)


_now: Callable[[], float] = _monotonic
_sleep: Callable[[float], None] = _default_sleep


def set_clock(now: Optional[Callable[[], float]] = None,
              sleep: Optional[Callable[[float], None]] = None) -> None:
    """Tests only: inject a monotonic clock and a sleep. ``None`` restores."""
    global _now, _sleep
    _now = now or _monotonic
    _sleep = sleep or _default_sleep


def _emit(line: str) -> None:
    # Recon configures no logging handler: logger.info is dropped and
    # logger.warning reaches the drawer unprefixed. print() keeps the level.
    try:
        print(line)
    except Exception:  # noqa: BLE001 - a closed stdout must not break a scan
        pass


_UNSAFE_LOG_CHARS = re.compile(r"[^A-Za-z0-9.:\-]")
_UNSAFE_LABEL_CHARS = re.compile(r"[^A-Za-z0-9 ._:\-]")


def safe_text(value: Any, limit: int = LOG_TEXT_MAX) -> str:
    """A target-derived string (hostname, URL) made safe for one log line.

    Certificate SANs and names extracted from JavaScript can carry newlines or
    brackets, which would forge a ``[DEGRADED]`` line or another level prefix.
    """
    return _UNSAFE_LOG_CHARS.sub("", str(value or ""))[:limit]


def _safe_label(value: Any) -> str:
    return _UNSAFE_LABEL_CHARS.sub("", str(value or ""))[:40] or "recon"


def _detail(value: Any) -> str:
    """One line, capped. Callers only ever pass a status, a class name or a phrase."""
    text = " ".join(str(value or "").split())
    return text.replace("[", "(").replace("]", ")")[:DETAIL_MAX]


def _fmt_count(n: int) -> str:
    return f"{n:,}"


# ---------------------------------------------------------------------------
# Outcomes and classification
# ---------------------------------------------------------------------------

class Outcome(str, enum.Enum):
    """The typed answer of one outbound call. The str mixin JSON-serialises it as its value."""

    OK = "ok"                  # 2xx with usable data
    NO_DATA = "no_data"        # 404, empty result, NXDOMAIN, WHOIS-empty for an IP
    TRANSIENT = "transient"    # timeout, refused/reset, 5xx, non-JSON where JSON expected, unexpected 4xx
    RATE_LIMIT = "rate_limit"  # 429, or a provider's documented rate signal
    FATAL = "fatal"            # bad/revoked key, 402, quota exhausted, plan-gated 403
    SKIPPED = "skipped"        # handed to a caller whose breaker was already open


_SUCCESS = (Outcome.OK, Outcome.NO_DATA)


@dataclass(frozen=True)
class CallResult:
    data: Any
    outcome: Outcome
    detail: str = ""
    retry_after: Optional[float] = None
    # A FATAL that belongs to this endpoint alone (a plan-gated 403): it stops
    # the endpoint but neither the provider nor the key, which still works
    # elsewhere.
    local: bool = False

    def __post_init__(self):
        object.__setattr__(self, "detail", _detail(self.detail))

    @property
    def ok(self) -> bool:
        return self.outcome is Outcome.OK

    @property
    def answered(self) -> bool:
        """The dependency answered: OK or a genuine empty answer."""
        return self.outcome in _SUCCESS


def status_of(resp: Any) -> Optional[int]:
    try:
        code = resp.status_code
        if isinstance(code, bool):
            return None
        return int(code)
    except Exception:  # noqa: BLE001
        return None


def classify_http(resp: Any, *, keyed: bool, no_data: Iterable[int] = (404,),
                  fatal: Iterable[int] = (), rate: Iterable[int] = ()) -> Outcome:
    """Map an HTTP status to an outcome. The explicit sets win over the defaults.

    ``keyed`` means the request carried an API key, so 401/403 mean that key
    was refused (FATAL). Without a key they are an unexpected 4xx (TRANSIENT).
    """
    code = status_of(resp)
    if code is None:
        return Outcome.TRANSIENT
    if code == 429 or code in tuple(rate):
        return Outcome.RATE_LIMIT
    if code in tuple(no_data):
        return Outcome.NO_DATA
    if code in tuple(fatal):
        return Outcome.FATAL
    if 200 <= code < 300:
        return Outcome.OK
    if code == 402:
        return Outcome.FATAL
    if keyed and code in (401, 403):
        return Outcome.FATAL
    return Outcome.TRANSIENT


def http_detail(resp: Any, outcome: Outcome, *, keyed: bool = False) -> str:
    code = status_of(resp)
    if code is None:
        return "no HTTP status"
    if outcome is Outcome.FATAL and keyed and code in (401, 403):
        return f"{code} key rejected"
    if code == 402:
        return "402 payment required"
    return f"HTTP {code}"


def _clamp_retry_after(raw: Any, default: float = RETRY_AFTER_DEFAULT_S) -> float:
    if raw is None:
        return default
    try:
        value = float(raw.strip() if isinstance(raw, str) else raw)
    except Exception:  # noqa: BLE001 - an HTTP-date or garbage
        return default
    if not math.isfinite(value) or value < 0:
        return default
    return min(value, RETRY_AFTER_MAX_S)


def retry_after_seconds(resp: Any, default: float = RETRY_AFTER_DEFAULT_S) -> float:
    """``Retry-After`` in seconds, clamped to ``[0, 60]``.

    Only a numeric value is honoured; a missing, negative, non-finite or
    HTTP-date value gives ``default``. A bare MagicMock header reads as 1.0.
    """
    try:
        headers = getattr(resp, "headers", None)
        raw = headers.get("Retry-After") if headers is not None else None
    except Exception:  # noqa: BLE001
        return default
    return _clamp_retry_after(raw, default)


def classify_exception(exc: BaseException) -> CallResult:
    """Every exception is TRANSIENT, and only its class name is kept."""
    name = type(exc).__name__ or "Exception"
    if name == "JSONDecodeError":
        return CallResult(None, Outcome.TRANSIENT, "non-JSON response")
    return CallResult(None, Outcome.TRANSIENT, name)


def json_result(resp: Any, *, keyed: bool, no_data: Iterable[int] = (404,),
                fatal: Iterable[int] = (), rate: Iterable[int] = (),
                empty_is_no_data: bool = False) -> CallResult:
    """The classify step for a plain JSON API: the status decides, a 2xx body is parsed.

    The body is read to parse it and never kept in the detail.
    """
    outcome = classify_http(resp, keyed=keyed, no_data=no_data, fatal=fatal, rate=rate)
    if outcome is not Outcome.OK:
        retry_after = retry_after_seconds(resp) if outcome is Outcome.RATE_LIMIT else None
        return CallResult(None, outcome, http_detail(resp, outcome, keyed=keyed), retry_after)
    try:
        data = resp.json()
    except Exception:  # noqa: BLE001
        return CallResult(None, Outcome.TRANSIENT, "non-JSON response")
    if empty_is_no_data and not data:
        return CallResult(data, Outcome.NO_DATA, http_detail(resp, Outcome.NO_DATA))
    return CallResult(data, Outcome.OK, http_detail(resp, Outcome.OK))


# ---------------------------------------------------------------------------
# Breaker
# ---------------------------------------------------------------------------

class _State(enum.Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


_ADMIT = "admit"
_PROBE = "probe"
_SKIP = "skip"


class Breaker:
    """Consecutive-failure breaker for one dependency key.

    TRANSIENT failures open it at ``threshold``; the first RATE_LIMIT sets a
    pause every caller sleeps out in ``allow()``, a second one opens it; FATAL
    opens it for the rest of the run. After ``cooldown`` exactly one caller is
    let through as a probe: success closes it, failure re-opens it with the
    cooldown doubled up to ``max_cooldown``. A late success from a call that was
    already in flight also closes it, since it is evidence of life.
    """

    def __init__(self, key: str, *, label: str, threshold: int = THIRD_PARTY_THRESHOLD,
                 cooldown_s: float = COOLDOWN_S, max_cooldown_s: float = MAX_COOLDOWN_S,
                 parent: Optional["Breaker"] = None):
        self.key = key
        self.label = _safe_label(label)
        self.name = key.split(":", 1)[1] if ":" in key else key
        self.threshold = max(1, int(threshold))
        self.base_cooldown = max(0.0, float(cooldown_s))
        self.max_cooldown = max(self.base_cooldown, float(max_cooldown_s))
        self.parent = parent
        self._lock = threading.Lock()
        self._reset_state()

    def _reset_state(self) -> None:
        self._state = _State.CLOSED
        self._fatal = False
        self._streak = 0
        self._rl_streak = 0
        # Bumped each time a rate limit is counted, so a 429 from a call that
        # was already in flight when the pause was set is not a second strike.
        self._rl_epoch = 0
        self._pause_until = 0.0
        self._cooldown = self.base_cooldown
        self._next_try_at = 0.0
        self._probe_deadline = 0.0
        self.skipped = 0
        self.opens = 0
        self.recoveries = 0
        self.failures = 0
        self.open_outcome: Optional[Outcome] = None
        self.open_detail = ""
        self.open_reason = ""

    # -- read side ---------------------------------------------------------

    @property
    def is_open(self) -> bool:
        """Open, half-open, or its parent is. False whenever the switch is off."""
        if not enabled():
            return False
        if self._fatal or self._state is not _State.CLOSED:
            return True
        return bool(self.parent and self.parent.is_open)

    @property
    def is_fatal(self) -> bool:
        if not enabled():
            return False
        return self._fatal or bool(self.parent and self.parent.is_fatal)

    @property
    def detail(self) -> str:
        """Why calls are being skipped: this breaker's, else its parent's reason."""
        if self._fatal or self._state is not _State.CLOSED:
            return self.open_detail or "paused"
        if self.parent is not None and self.parent.is_open:
            return self.parent.detail
        return self.open_detail or "paused"

    def _rate_holder(self) -> "Breaker":
        return self.parent if self.parent is not None else self

    def epoch(self) -> int:
        return self._rate_holder()._rl_epoch

    def counters(self) -> tuple[int, int]:
        return self.skipped, self.opens

    # -- admission ---------------------------------------------------------

    def allow(self) -> bool:
        """False while open (or while the parent is). Sleeps out a shared 429 pause."""
        if not enabled():
            return True
        try:
            return self._allow()
        except Exception:  # noqa: BLE001 - a fault in here lets the call through
            return True

    def _allow(self) -> bool:
        verdict, pause = self._check()
        if verdict == _SKIP:
            return False
        parent = self.parent
        if parent is not None:
            parent_verdict, parent_pause = parent._check()
            if parent_verdict == _SKIP:
                if verdict == _PROBE:
                    self._release_probe()
                return False
            pause = max(pause, parent_pause)
        if pause > 0:
            _sleep(min(pause, RETRY_AFTER_MAX_S))
        return True

    def _check(self) -> tuple[str, float]:
        with self._lock:
            now = _now()
            verdict = self._admit_locked(now)
            if verdict == _SKIP:
                self.skipped += 1
                return verdict, 0.0
            if verdict == _ADMIT:
                return verdict, max(0.0, self._pause_until - now)
            return verdict, 0.0

    def _admit_locked(self, now: float) -> str:
        if self._fatal:
            return _SKIP
        if self._state is _State.CLOSED:
            return _ADMIT
        if self._state is _State.OPEN:
            if now < self._next_try_at:
                return _SKIP
            self._state = _State.HALF_OPEN
            self._probe_deadline = now + PROBE_GRACE_S
            return _PROBE
        if now >= self._probe_deadline:
            # The probe never reported back (its caller died or skipped it).
            self._probe_deadline = now + PROBE_GRACE_S
            return _PROBE
        return _SKIP

    def _release_probe(self) -> None:
        with self._lock:
            if self._state is _State.HALF_OPEN:
                self._state = _State.OPEN

    def wait_pause(self) -> None:
        """Sleep out a shared rate-limit pause (this key's or its parent's) without admission.

        For a call admitted by ``allow()`` before a rate-limiter wait: a pause
        set during that wait still applies to it.
        """
        if not enabled():
            return
        try:
            now = _now()
            pause = self._pause_until - now
            if self.parent is not None:
                pause = max(pause, self.parent._pause_until - now)
            if pause > 0:
                _sleep(min(pause, RETRY_AFTER_MAX_S))
        except Exception:  # noqa: BLE001
            pass

    # -- recording ---------------------------------------------------------

    def record(self, outcome: Any, detail: str = "", retry_after: Optional[float] = None,
               *, epoch: Optional[int] = None, local: bool = False) -> None:
        """Feed one call's outcome back. ``epoch`` is ``self.epoch()`` read when the call was admitted.

        ``local=True`` keeps a FATAL on this endpoint instead of the provider.
        """
        if not enabled():
            return
        try:
            outcome = Outcome(outcome)
        except Exception:  # noqa: BLE001
            return
        if outcome is Outcome.SKIPPED:
            return
        try:
            parent = self.parent
            escalate = outcome is Outcome.RATE_LIMIT or (outcome is Outcome.FATAL and not local)
            if parent is not None and escalate:
                parent._apply(outcome, detail, retry_after, epoch)
                return
            self._apply(outcome, detail, retry_after, epoch)
            if parent is not None:
                parent._echo(outcome, epoch)
        except Exception:  # noqa: BLE001
            pass

    def force_open(self, detail: str) -> None:
        """Open without a failure streak (non-fatal); used by the archive preflight.

        On a half-open breaker it is the probe that failed: re-open with the
        cooldown doubled. An open one is left as it is.
        """
        if not enabled():
            return
        line = None
        with self._lock:
            now = _now()
            if self._fatal or self._state is _State.OPEN:
                return
            if self._state is _State.HALF_OPEN:
                self._reopen_locked(now)
                return
            self._open_locked(now, Outcome.TRANSIENT, detail, _detail(detail))
            line = MSG_OPEN_FORCED.format(label=self.label, name=self.name,
                                          detail=self.open_detail,
                                          cooldown=int(self._cooldown))
        if line:
            _emit(line)

    def _apply(self, outcome: Outcome, detail: str, retry_after: Optional[float],
               epoch: Optional[int]) -> None:
        line = None
        with self._lock:
            now = _now()
            if outcome in _SUCCESS:
                line = self._succeed_locked(epoch)
            elif outcome is Outcome.FATAL:
                self.failures += 1
                if not self._fatal:
                    self._fatal = True
                    self._open_locked(now, Outcome.FATAL, detail, _detail(detail))
                    line = MSG_OPEN_FATAL.format(label=self.label, name=self.name,
                                                 detail=self.open_detail or "rejected")
            elif outcome is Outcome.RATE_LIMIT:
                self.failures += 1
                pause_until = now + _clamp_retry_after(retry_after)
                self._pause_until = max(self._pause_until, pause_until)
                if epoch is None or epoch >= self._rl_epoch:
                    self._rl_epoch += 1
                    self._rl_streak += 1
                    if self._state is _State.HALF_OPEN:
                        self._reopen_locked(now)
                    elif self._state is _State.CLOSED and self._rl_streak >= 2:
                        self._open_locked(now, Outcome.RATE_LIMIT, detail,
                                          f"rate-limited twice in a row ({_detail(detail)})")
                        line = MSG_OPEN_RATE_LIMIT.format(
                            label=self.label, name=self.name, detail=self.open_detail,
                            cooldown=int(self._cooldown))
            else:
                self.failures += 1
                self._streak += 1
                if self._state is _State.HALF_OPEN:
                    self._reopen_locked(now)
                elif self._state is _State.CLOSED and self._streak >= self.threshold:
                    self._open_locked(now, Outcome.TRANSIENT, detail,
                                      f"{self._streak} consecutive failures ({_detail(detail)})")
                    line = MSG_OPEN_TRANSIENT.format(
                        label=self.label, name=self.name, count=self._streak,
                        detail=self.open_detail, cooldown=int(self._cooldown))
        if line:
            _emit(line)

    def _echo(self, outcome: Outcome, epoch: Optional[int]) -> None:
        """A child's result as seen by its provider-level parent."""
        line = None
        with self._lock:
            if outcome in _SUCCESS:
                line = self._succeed_locked(epoch)
            elif self._state is _State.HALF_OPEN:
                # The parent's probe went out through this child and failed.
                self._reopen_locked(_now())
        if line:
            _emit(line)

    def _succeed_locked(self, epoch: Optional[int]) -> Optional[str]:
        self._streak = 0
        if epoch is None or epoch >= self._rl_epoch:
            self._rl_streak = 0
        if self._state is not _State.CLOSED and not self._fatal:
            self._state = _State.CLOSED
            self._cooldown = self.base_cooldown
            self.recoveries += 1
            return MSG_RECOVERED.format(label=self.label, name=self.name)
        return None

    def _open_locked(self, now: float, outcome: Outcome, detail: str, reason: str) -> None:
        self._state = _State.OPEN
        self.opens += 1
        self.open_outcome = outcome
        self.open_detail = _detail(detail) or outcome.value
        self.open_reason = _detail(reason) or self.open_detail
        self._next_try_at = now + self._cooldown

    def _reopen_locked(self, now: float) -> None:
        self._cooldown = min(self._cooldown * 2, self.max_cooldown)
        self._state = _State.OPEN
        self._next_try_at = now + self._cooldown


_registry: dict[str, Breaker] = {}
_registry_lock = threading.Lock()


def get_breaker(key: str, *, label: str, threshold: int = THIRD_PARTY_THRESHOLD,
                cooldown_s: float = COOLDOWN_S, parent: Optional[str] = None) -> Breaker:
    """The process-wide breaker for ``key``, created on first use.

    ``parent`` names a provider-level breaker (created with the same label) that
    takes this key's rate limits and rejected keys, so one of those stops every
    endpoint of the provider. The first creation fixes the parameters.
    """
    with _registry_lock:
        breaker = _registry.get(key)
        if breaker is not None:
            return breaker
        parent_breaker = None
        if parent and parent != key:
            parent_breaker = _registry.get(parent)
            if parent_breaker is None:
                parent_breaker = Breaker(parent, label=label, threshold=threshold,
                                         cooldown_s=cooldown_s)
                _registry[parent] = parent_breaker
        breaker = Breaker(key, label=label, threshold=threshold, cooldown_s=cooldown_s,
                          parent=parent_breaker)
        _registry[key] = breaker
        return breaker


def peek_breaker(key: str) -> Optional[Breaker]:
    """The breaker for ``key`` if some module already created it, else None."""
    with _registry_lock:
        return _registry.get(key)


def is_open(key: str) -> bool:
    breaker = peek_breaker(key)
    return bool(breaker and breaker.is_open)


def is_fatal(key: str) -> bool:
    breaker = peek_breaker(key)
    return bool(breaker and breaker.is_fatal)


# ---------------------------------------------------------------------------
# Key pools
# ---------------------------------------------------------------------------

class KeyPool:
    """The key a provider call should use now, over an optional ``KeyRotator``.

    A FATAL answer for one key drops that key and the call retries with the
    next, so the provider breaker opens only once the pool is empty. Once every
    pooled key is gone the pool never falls back to the main key, which was the
    pool's first member and has just been refused.
    """

    def __init__(self, rotator: Any, fallback_key: str = "", *, label: str):
        self._rotator = rotator
        self._fallback = fallback_key or ""
        self.label = _safe_label(label)

    def current(self) -> str:
        rotator = self._rotator
        if rotator is not None:
            try:
                if getattr(rotator, "exhausted", False) is True:
                    return ""
                if rotator.has_keys:
                    key = rotator.current_key
                    if key:
                        return key
            except Exception:  # noqa: BLE001
                pass
        return self._fallback

    @property
    def has_key(self) -> bool:
        return bool(self.current())

    def tick(self) -> None:
        if self._rotator is None:
            return
        try:
            self._rotator.tick()
        except Exception:  # noqa: BLE001
            pass

    def reject(self, key: str, detail: str) -> bool:
        """Drop a refused key. True when another key is left to try."""
        if not enabled() or not key:
            return False
        rotator = self._rotator
        drop = getattr(rotator, "mark_bad", None) if rotator is not None else None
        if drop is None:
            return False
        try:
            dropped = drop(key)
        except Exception:  # noqa: BLE001
            return False
        if not isinstance(dropped, tuple) or len(dropped) != 2:
            return False
        position, left = dropped
        if not isinstance(left, int) or isinstance(left, bool):
            return False
        if isinstance(position, int) and position > 0:
            _emit(MSG_KEY_DROPPED.format(label=self.label, position=position,
                                         detail=_detail(detail), left=left))
        return left > 0


# ---------------------------------------------------------------------------
# Guarded call
# ---------------------------------------------------------------------------

def _attempt(send: Callable[..., Any], classify: Callable[[Any], CallResult],
             key: Optional[str], keys: Optional[KeyPool]) -> CallResult:
    try:
        response = send(key) if keys is not None else send()
    except Exception as exc:  # noqa: BLE001
        return classify_exception(exc)
    if keys is not None:
        keys.tick()
    try:
        result = classify(response)
    except Exception as exc:  # noqa: BLE001
        return CallResult(None, Outcome.TRANSIENT, f"unreadable response ({type(exc).__name__})")
    if not isinstance(result, CallResult):
        return CallResult(None, Outcome.TRANSIENT, "unclassified response")
    return result


def guarded_call(breaker: Breaker, send: Callable[..., Any],
                 classify: Callable[[Any], CallResult], *,
                 retry_rate_limited: bool = True,
                 keys: Optional[KeyPool] = None,
                 admitted: bool = False) -> CallResult:
    """``allow() -> send() -> classify() -> record()``. Never raises.

    ``classify`` turns a response into a ``CallResult``; an exception from
    ``send`` becomes TRANSIENT with its class name only. On the first
    RATE_LIMIT the call is sent once more, after ``allow()`` has slept out the
    shared pause. With ``keys``, ``send`` receives the key to use and a FATAL
    answer moves on to the next key before anything is recorded.

    ``admitted=True`` is for a worker that already called ``allow()`` at its
    top, before its rate-limiter wait (a breaker checked only in here would
    still make every queued worker sleep through its reserved slot). The
    first attempt then skips ``allow()``, so a half-open probe is not taken
    twice.
    """
    rate_retries = 1 if retry_rate_limited else 0
    key_retries = 16
    result = CallResult(None, Outcome.SKIPPED, "not attempted")
    first = True
    while True:
        if first and admitted:
            breaker.wait_pause()
        elif not breaker.allow():
            return CallResult(None, Outcome.SKIPPED, breaker.detail)
        first = False
        epoch = breaker.epoch()
        key = keys.current() if keys is not None else None
        result = _attempt(send, classify, key, keys)
        if (result.outcome is Outcome.FATAL and not result.local and keys is not None
                and key_retries > 0 and keys.reject(key or "", result.detail)):
            key_retries -= 1
            # Nothing is recorded for a key that was replaced, so hand back a
            # probe slot this call held; the retry takes it again.
            breaker._release_probe()
            if breaker.parent is not None:
                breaker.parent._release_probe()
            continue
        breaker.record(result.outcome, result.detail, result.retry_after, epoch=epoch,
                       local=result.local)
        if result.outcome is Outcome.RATE_LIMIT and rate_retries > 0:
            rate_retries -= 1
            if not enabled():
                # No breaker holds the pause when the switch is off; stay polite.
                _sleep(_clamp_retry_after(result.retry_after))
            continue
        return result


# ---------------------------------------------------------------------------
# Per-run answer cache
# ---------------------------------------------------------------------------

class RunCache:
    """A per-run memo of answers (OK and NO_DATA). Failures are never cached.

    Lives here, not in the calling module, so ``reset_registry()`` clears it
    with the breakers and a cached answer never leaks from one test to the next.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._data: dict = {}

    def get(self, key: Any) -> tuple[bool, Any]:
        with self._lock:
            if key in self._data:
                return True, self._data[key]
            return False, None

    def put(self, key: Any, value: Any) -> None:
        with self._lock:
            self._data[key] = value

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)

    def keys(self) -> list:
        with self._lock:
            return list(self._data)


_caches: dict[str, RunCache] = {}


def run_cache(name: str) -> RunCache:
    with _registry_lock:
        cache = _caches.get(name)
        if cache is None:
            cache = RunCache()
            _caches[name] = cache
        return cache


# ---------------------------------------------------------------------------
# HostHealth (scan targets)
# ---------------------------------------------------------------------------

_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443, "ftp": 21}
_HOST_CHARS = re.compile(r"^[a-z0-9.\-]+$|^[0-9a-f:]+$")


def host_key(target: Any) -> str:
    """``"https://A.example.com/x"`` -> ``"a.example.com:443"``; ``""`` when unparseable.

    A bare ``host:port`` keeps its port; a bare host has none.
    """
    text = str(target or "").strip()
    if not text:
        return ""
    try:
        parts = urlsplit(text if "://" in text else f"//{text}")
        host = (parts.hostname or "").lower().rstrip(".")
        if not host:
            return ""
        try:
            port = parts.port
        except ValueError:
            port = None
        if port is None and "://" in text:
            port = _DEFAULT_PORTS.get(parts.scheme.lower())
    except Exception:  # noqa: BLE001
        return ""
    if ":" in host:
        host = f"[{host}]"
    return f"{host}:{port}" if port else host


def hostname_of(key: str) -> str:
    """The lower-case hostname of a ``host_key`` (port and IPv6 brackets stripped)."""
    text = str(key or "").strip().lower()
    if text.startswith("["):
        return text[1:text.index("]")] if "]" in text else text[1:]
    if text.count(":") == 1:
        return text.split(":", 1)[0]
    return text


def _requests_exceptions():
    try:
        import requests.exceptions as rex  # noqa: PLC0415 - optional, and heavy
        return rex
    except Exception:  # noqa: BLE001
        return None


# errno values that say the network path to the host failed. Anything else
# from a raw OSError (EMFILE, ENOSPC, ...) is a local fault and never counts.
_NETWORK_ERRNOS = {
    errno.ECONNREFUSED, errno.ECONNRESET, errno.ECONNABORTED, errno.ETIMEDOUT,
    errno.EHOSTUNREACH, errno.ENETUNREACH, errno.ENETDOWN,
    getattr(errno, "EHOSTDOWN", errno.EHOSTUNREACH),
}

_CONNECT = "connect"
_READ_TIMEOUT = "read_timeout"
_ALIVE = "alive"

# OpenSSL's reason for every refused certificate: self-signed, expired,
# unknown CA, hostname or IP mismatch.
_CERT_VERIFY_REASON = "CERTIFICATE_VERIFY_FAILED"
# requests nests the ssl error three deep, urllib one: a chain that needs more
# exceptions than this to reach it is not theirs.
_MAX_CHAIN_NODES = 16


def _cert_error_types() -> tuple:
    types: list = []
    try:
        import ssl  # noqa: PLC0415
        types.append(ssl.SSLCertVerificationError)
    except Exception:  # noqa: BLE001
        pass
    try:
        # urllib3's own hostname matcher (assert_hostname, or an IP address
        # the ssl module did not check) raises this instead.
        from urllib3.util.ssl_match_hostname import CertificateError  # noqa: PLC0415
        types.append(CertificateError)
    except Exception:  # noqa: BLE001
        pass
    return tuple(types)


def _is_cert_verification_failure(exc: BaseException) -> bool:
    """True when ``exc`` is, or wraps, a certificate this client refused.

    The host completed enough of the handshake to present a certificate, so
    it is up: a self-signed one on a live internal host must not take it away
    from every other module. A handshake reset or EOF is not this and still
    counts. Only the ssl error's own OpenSSL text is read, never a wrapper's
    message, which carries the target-controlled URL.
    """
    try:
        import ssl  # noqa: PLC0415
        ssl_error: Any = ssl.SSLError
    except Exception:  # noqa: BLE001
        ssl_error = ()
    cert_types = _cert_error_types()
    seen: set[int] = set()
    stack: list = [exc]
    while stack and len(seen) < _MAX_CHAIN_NODES:
        node = stack.pop()
        if not isinstance(node, BaseException) or id(node) in seen:
            continue
        seen.add(id(node))
        if cert_types and isinstance(node, cert_types):
            return True
        if ssl_error and isinstance(node, ssl_error) and (
                getattr(node, "reason", None) == _CERT_VERIFY_REASON
                or f"[SSL: {_CERT_VERIFY_REASON}]" in str(node)):
            return True
        stack.extend(a for a in getattr(node, "args", ()) if isinstance(a, BaseException))
        stack.extend((getattr(node, "reason", None), node.__cause__, node.__context__))
    return False


def is_certificate_refused(exc: BaseException) -> bool:
    """True when this client refused the host's certificate. Never raises.

    The host is up, but a module that verifies certificates checked nothing
    on it: it must keep its earlier findings there (see ``note_degraded``).
    """
    try:
        return _is_cert_verification_failure(exc)
    except Exception:  # noqa: BLE001
        return False


def _failure_kind(exc: BaseException) -> Optional[str]:
    rex = _requests_exceptions()
    if rex is not None and isinstance(exc, rex.RequestException):
        # ProxyError subclasses ConnectionError: a dead capture proxy must not
        # make every host look down.
        if isinstance(exc, rex.ProxyError):
            return None
        if isinstance(exc, rex.SSLError) and _is_cert_verification_failure(exc):
            return None
        if isinstance(exc, (rex.ConnectTimeout, rex.SSLError, rex.ConnectionError)):
            return _CONNECT
        if isinstance(exc, rex.ReadTimeout):
            return _READ_TIMEOUT
        return None
    try:
        import urllib.error  # noqa: PLC0415
        if isinstance(exc, urllib.error.HTTPError):
            return _ALIVE
        if isinstance(exc, urllib.error.URLError):
            reason = getattr(exc, "reason", None)
            if isinstance(reason, BaseException):
                inner = _failure_kind(reason)
                # A timeout wrapped in URLError happened while connecting.
                return _CONNECT if inner in (_CONNECT, _READ_TIMEOUT) else inner
            return None
    except Exception:  # noqa: BLE001
        pass
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return _READ_TIMEOUT
    if isinstance(exc, (ConnectionError, socket.gaierror)):
        return _CONNECT
    try:
        import ssl  # noqa: PLC0415
        if isinstance(exc, ssl.SSLError):
            return None if _is_cert_verification_failure(exc) else _CONNECT
    except Exception:  # noqa: BLE001
        pass
    if isinstance(exc, OSError) and getattr(exc, "errno", None) in _NETWORK_ERRNOS:
        return _CONNECT
    return None


def is_connection_failure(exc: BaseException) -> bool:
    """True for the failures that say the host itself is unreachable.

    A read timeout is excluded here; ``HostHealth`` counts it only for a host
    that has produced no response yet this run.
    """
    try:
        return _failure_kind(exc) == _CONNECT
    except Exception:  # noqa: BLE001
        return False


class _Host:
    __slots__ = ("failures", "responded", "down", "cooldown", "next_try_at",
                 "probe_deadline", "probing", "skipped", "went_down")

    def __init__(self, cooldown: float):
        self.failures = 0
        self.responded = False
        self.down = False
        self.cooldown = cooldown
        self.next_try_at = 0.0
        self.probe_deadline = 0.0
        self.probing = False
        self.skipped = 0
        self.went_down = False


class HostHealth:
    """Per-target liveness shared by every module of the run.

    Any HTTP response - 403, 404, 500 or a WAF page - is life. Only connection
    failures count, so a live host is never skipped for how it answers.
    """

    def __init__(self, threshold: int = INTERNAL_THRESHOLD,
                 cooldown_s: float = HOST_COOLDOWN_S,
                 max_cooldown_s: float = MAX_COOLDOWN_S):
        self.threshold = max(1, int(threshold))
        self.base_cooldown = float(cooldown_s)
        self.max_cooldown = max(self.base_cooldown, float(max_cooldown_s))
        self._lock = threading.Lock()
        self._hosts: dict[str, _Host] = {}

    def reset(self) -> None:
        with self._lock:
            self._hosts.clear()

    def _host(self, key: str) -> _Host:
        host = self._hosts.get(key)
        if host is None:
            host = _Host(self.base_cooldown)
            self._hosts[key] = host
        return host

    def allow(self, target: Any) -> bool:
        if not enabled():
            return True
        try:
            key = host_key(target)
            if not key:
                return True
            with self._lock:
                host = self._hosts.get(key)
                if host is None or not host.down:
                    return True
                now = _now()
                if host.probing and now < host.probe_deadline:
                    host.skipped += 1
                    return False
                if now >= host.next_try_at:
                    host.probing = True
                    host.probe_deadline = now + PROBE_GRACE_S
                    return True
                host.skipped += 1
                return False
        except Exception:  # noqa: BLE001
            return True

    def is_down(self, target: Any) -> bool:
        """Marked unreachable right now. Docker-tool loops use this: their empty
        output cannot prove a host dead or alive, so they never probe."""
        if not enabled():
            return False
        try:
            key = host_key(target)
            with self._lock:
                host = self._hosts.get(key)
                return bool(host and host.down)
        except Exception:  # noqa: BLE001
            return False

    def record_alive(self, target: Any) -> None:
        if not enabled():
            return
        line = None
        try:
            key = host_key(target)
            if not key:
                return
            with self._lock:
                host = self._host(key)
                host.responded = True
                host.failures = 0
                host.probing = False
                if host.down:
                    host.down = False
                    host.cooldown = self.base_cooldown
                    line = MSG_HOST_BACK.format(host=safe_text(key))
        except Exception:  # noqa: BLE001
            return
        if line:
            _emit(line)

    def record_failure(self, target: Any, exc: BaseException) -> bool:
        """Count ``exc`` against the host when it is a connection failure. True if counted."""
        return self._record_failure(target, exc)[0]

    def _record_failure(self, target: Any, exc: BaseException) -> tuple[bool, bool]:
        """(counted, went_down_now)."""
        if not enabled():
            return False, False
        line = None
        try:
            kind = _failure_kind(exc)
            if kind == _ALIVE:
                self.record_alive(target)
                return False, False
            key = host_key(target)
            if not key or kind is None:
                return False, False
            with self._lock:
                host = self._host(key)
                if kind == _READ_TIMEOUT and host.responded:
                    return False, False
                now = _now()
                host.failures += 1
                if host.probing:
                    host.probing = False
                    host.cooldown = min(host.cooldown * 2, self.max_cooldown)
                    host.next_try_at = now + host.cooldown
                    return True, False
                if not host.down and host.failures >= self.threshold:
                    host.down = True
                    host.went_down = True
                    host.next_try_at = now + host.cooldown
                    line = MSG_HOST_DOWN.format(host=safe_text(key), count=host.failures,
                                                cooldown=int(host.cooldown))
                    went_down = True
                else:
                    went_down = False
        except Exception:  # noqa: BLE001
            return False, False
        if line:
            _emit(line)
        return True, went_down

    def unreachable(self) -> list[str]:
        """Every host marked unreachable at some point this run, sorted."""
        with self._lock:
            return sorted(k for k, h in self._hosts.items() if h.went_down)


host_health = HostHealth()


# ---------------------------------------------------------------------------
# Per-module report scope
# ---------------------------------------------------------------------------

def _matches(key: str, prefixes: tuple[str, ...]) -> bool:
    return any(key == p or key.startswith(p + ":") for p in prefixes)


class ReportScope:
    """What one module invocation cut, as deltas over the process-wide state.

    Breaker state outlives a module (a batch runs several groups in one
    process), so the scope snapshots the counters of the breakers it covers
    at its start and reports only what changed since. Hosts are tracked by the
    scope's own gate calls, which attributes them to this module even while
    another module runs in parallel.
    """

    def __init__(self, prefixes: Iterable[str], *, label: str, unit: str = "item(s)"):
        self.prefixes = tuple(p for p in prefixes if p)
        self.label = _safe_label(label)
        self.unit = unit
        self._lock = threading.Lock()
        self._start: dict[str, tuple[int, int]] = {}
        self._hosts_skipped: set[str] = set()
        self._hosts_down: set[str] = set()
        with _registry_lock:
            for key, breaker in _registry.items():
                if _matches(key, self.prefixes):
                    self._start[key] = breaker.counters()

    # -- scan-target gates -------------------------------------------------

    def allow_host(self, target: Any) -> bool:
        if host_health.allow(target):
            return True
        key = host_key(target)
        if key:
            with self._lock:
                self._hosts_skipped.add(key)
        return False

    def skip_if_down(self, target: Any) -> bool:
        """For docker-tool loops: skip only a host another module already found down."""
        if not host_health.is_down(target):
            return False
        key = host_key(target)
        if key:
            with self._lock:
                self._hosts_skipped.add(key)
        return True

    def host_alive(self, target: Any) -> None:
        host_health.record_alive(target)

    def host_failed(self, target: Any, exc: BaseException) -> bool:
        counted, went_down = host_health._record_failure(target, exc)
        if went_down:
            key = host_key(target)
            if key:
                with self._lock:
                    self._hosts_down.add(key)
        return counted

    def note_host_skipped(self, key: str) -> None:
        """Record a host this module skipped by its own logic (e.g. a dead IP:port)."""
        if key:
            with self._lock:
                self._hosts_skipped.add(str(key).strip().lower())

    # -- reading -----------------------------------------------------------

    def hosts(self) -> list[str]:
        with self._lock:
            return sorted(self._hosts_skipped | self._hosts_down)

    def report(self) -> list[dict]:
        """One JSON-plain entry per breaker that skipped calls in this scope, or
        opened in it and is still open (it failed on the last items)."""
        entries = []
        with _registry_lock:
            breakers = [(k, b) for k, b in _registry.items() if _matches(k, self.prefixes)]
        for key, breaker in sorted(breakers):
            start_skipped, start_opens = self._start.get(key, (0, 0))
            skipped = max(0, breaker.skipped - start_skipped)
            opened = breaker.opens > start_opens
            still_open = breaker._fatal or breaker._state is not _State.CLOSED
            if not skipped and not (opened and still_open):
                continue
            outcome = breaker.open_outcome or Outcome.TRANSIENT
            entries.append({
                "source": key,
                "label": breaker.label,
                "outcome": outcome.value,
                "reason": breaker.open_reason or breaker.open_detail or outcome.value,
                "detail": breaker.open_detail or outcome.value,
                "skipped": skipped,
                "recovered": not still_open,
            })
        return entries

    def finish(self, module: str, *, sources: Iterable[str] = (), host_source: str = "",
               host_field: bool = True, payload: Optional[dict] = None,
               log: bool = True, source_only_hosts: bool = False) -> list[dict]:
        """Print the module's DEGRADED summary, note it for the run, tag the payload.

        ``sources`` are the finding sources a breaker skip cuts at the source
        level (the prune leaves them alone). Host skips cut ``host_source`` for
        those hosts only - unless ``host_field`` is False (the module's findings
        carry no host), in which case they cut it at the source level. With
        ``source_only_hosts`` the hosts are cut for ``host_source`` alone (see
        ``note_degraded``). The payload gains ``degraded`` /
        ``unreachable_hosts`` only when something was cut, so a clean run keeps
        today's shape. Never raises.
        """
        try:
            return self._finish(module, tuple(s for s in sources if s), host_source,
                                host_field, payload, log, source_only_hosts)
        except Exception:  # noqa: BLE001
            _mark_accumulator_broken()
            return []

    def _finish(self, module, sources, host_source, host_field, payload, log,
                source_only_hosts=False) -> list[dict]:
        entries = self.report()
        hosts = self.hosts()
        if log:
            for entry in entries:
                _emit(MSG_DEGRADED.format(
                    label=entry["label"], name=entry["source"].split(":", 1)[-1],
                    count=_fmt_count(entry["skipped"]), unit=self.unit,
                    detail=entry["detail"]))
            if hosts:
                shown = ", ".join(safe_text(h) for h in hosts[:LOG_HOSTS_MAX])
                more = len(hosts) - LOG_HOSTS_MAX
                if more > 0:
                    shown += f" (+{_fmt_count(more)} more)"
                _emit(MSG_DEGRADED_HOSTS.format(label=self.label, count=_fmt_count(len(hosts)),
                                                hosts=shown))
        public = [{k: v for k, v in e.items() if k not in ("label", "detail")} for e in entries]
        if entries:
            if sources:
                reason = "; ".join(sorted({e["reason"] for e in entries}))
                note_degraded(module, sources=sources, reason=reason)
            else:
                note_degraded(module, entries=public)
        if hosts:
            target_source = host_source or (sources[0] if sources else module)
            if host_field:
                note_degraded(module, hosts=hosts, host_source=target_source,
                              source_only_hosts=source_only_hosts)
            else:
                note_degraded(module, sources=(target_source,),
                              reason=f"{len(hosts)} unreachable host(s) skipped")
        if isinstance(payload, dict):
            if public:
                payload["degraded"] = public
            if hosts:
                payload["unreachable_hosts"] = hosts
        return public


def scope(prefix: Any = (), *, label: str = "recon", unit: str = "item(s)") -> ReportScope:
    """A report scope over the breakers keyed ``prefix`` or ``prefix:*``.

    Take it at a module's start; call ``.finish()`` at its end.
    """
    prefixes = (prefix,) if isinstance(prefix, str) else tuple(prefix or ())
    return ReportScope(prefixes, label=label, unit=unit)


# ---------------------------------------------------------------------------
# Run-level coverage accumulator
# ---------------------------------------------------------------------------

class CoverageUnknown(RuntimeError):
    """The accumulator faulted, so what this run covered cannot be established."""


def _prune_hostnames(keys: Iterable[str]) -> tuple:
    names = set()
    for key in keys:
        name = hostname_of(key)
        if name and _HOST_CHARS.match(name):
            names.add(name)
    return tuple(sorted(names))


@dataclass(frozen=True)
class CoverageReport:
    degraded_sources: frozenset
    # Every skipped host, whatever it was skipped for: the coverage record.
    skipped_hosts: tuple
    nuclei_truncated: bool
    gaps: tuple
    # ((source, (host, ...)), ...): hosts only that source gave up on. Each is
    # also in skipped_hosts; a host some note cut for every source is not here.
    source_hosts: tuple = ()
    # ((source, ((check, (host, ...)), ...)), ...): what note_checked recorded;
    # check "*" is every finding type of the source. Not a cut: no gap.
    checked: tuple = ()

    @property
    def degraded(self) -> bool:
        return bool(self.degraded_sources or self.skipped_hosts or self.nuclei_truncated
                    or self.gaps)

    @property
    def positive_sources(self) -> frozenset:
        """The sources that recorded what they re-checked (``note_checked``).
        The prune deletes their stale findings only on those hosts; every
        other source keeps the rule "not reported and not cut means gone".
        A degraded one is listed too: the prune leaves it out first."""
        return frozenset(source for source, _ in self.checked)

    def checked_types(self, source: str) -> tuple:
        """The checks ``source`` recorded: ``"*"`` (every finding type) first
        when some note covered the whole source, then each finding ``type``
        recorded on its own."""
        checks = [check for check, _ in dict(self.checked).get(source, ())]
        return tuple(sorted(checks, key=lambda c: (c != "*", c)))

    def checked_hostnames(self, source: str, check: str = "*") -> tuple:
        """The hostnames whose ``source`` findings (of type ``check``, or of
        every type for ``"*"``) the prune may delete: those the source
        re-checked, minus every host the run cut for it. Degraded always
        wins: a source cut as a whole has none."""
        if source in self.degraded_sources:
            return ()
        per_check = dict(dict(self.checked).get(source, ()))
        hosts = set(per_check.get("*", ()))
        if check != "*":
            hosts.update(per_check.get(check, ()))
        kept = set(self.keep_hostnames(source))
        return tuple(h for h in _prune_hostnames(hosts) if h not in kept)

    def skipped_hostnames(self) -> tuple:
        """Hostnames (port stripped, lower-cased) safe to build a prune regex from."""
        return _prune_hostnames(self.skipped_hosts)

    def keep_hostnames(self, source: str = "") -> tuple:
        """The hostnames whose ``source`` findings the prune must keep.

        Every host skipped for all sources, plus the hosts only ``source`` gave
        up on. Another tool's per-source host is left out: ``source`` re-checked
        it, so its stale findings there are pruned as on any other host.
        """
        scoped = dict(self.source_hosts)
        others = {h for s, hosts in scoped.items() if s != source for h in hosts}
        own = set(scoped.get(source, ()))
        return _prune_hostnames(h for h in self.skipped_hosts if h in own or h not in others)

    def stored_skipped_hosts(self) -> list:
        return sorted(self.skipped_hosts)[:STORED_HOSTS_MAX]

    def gaps_json(self) -> str:
        return json.dumps(list(self.gaps), sort_keys=True, separators=(",", ":"))


_notes: list[dict] = []
_notes_lock = threading.Lock()
_accumulator_broken = False


def _mark_accumulator_broken() -> None:
    global _accumulator_broken
    _accumulator_broken = True


_TOKEN_CHARS = re.compile(r"[^A-Za-z0-9_.:\-]")


def _token(value: Any) -> str:
    return _TOKEN_CHARS.sub("", str(value or ""))[:64]


def _norm_host(value: Any) -> str:
    text = str(value or "").strip().lower()
    if not text or len(text) > 300:
        return ""
    return text if re.fullmatch(r"[a-z0-9.:\-\[\]]+", text) else ""


def note_degraded(module: str, *, sources: Iterable[str] = (), hosts: Iterable[str] = (),
                  host_source: str = "", nuclei_truncated: bool = False, reason: str = "",
                  entries: Iterable[dict] = (), source_only_hosts: bool = False,
                  aliases: Iterable[str] = ()) -> None:
    """Record, for the run, what ``module`` could not check. Never raises.

    ``sources``: finding sources cut as a whole - the prune leaves every one of
    their findings alone. ``hosts`` (``host:port`` keys): cut for these hosts
    only, recorded under ``host_source``. By default an unreachable host is cut
    for every source, since no tool could re-check it; ``source_only_hosts``
    cuts them for ``host_source`` alone, for a host that answered the other
    tools while this one gave up on it (an nmap host timeout). ``aliases``:
    the other source values the same provider stamps (Shodan writes
    `shodan_api` or `internetdb`), cut exactly as ``sources`` or
    ``host_source`` are but listed under their one gap, so the coverage
    record names the provider once. ``entries``: breaker report entries of a
    module that writes no findings; recorded as gaps, no prune effect.
    A fault here marks the accumulator broken, which makes the prune fail closed.
    """
    try:
        note = {
            "module": _token(module) or "recon",
            "sources": sorted({_token(s) for s in sources if _token(s)}),
            "hosts": sorted({h for h in (_norm_host(x) for x in hosts) if h}),
            "host_source": _token(host_source) or _token(module) or "recon",
            "source_only_hosts": bool(source_only_hosts),
            "aliases": sorted({_token(a) for a in aliases if _token(a)}),
            "nuclei_truncated": bool(nuclei_truncated),
            "reason": _detail(reason),
            "entries": [
                {
                    "source": _token(e.get("source")),
                    "reason": _detail(e.get("reason")),
                    "skipped": int(e.get("skipped") or 0),
                }
                for e in entries if isinstance(e, dict) and _token(e.get("source"))
            ],
        }
        with _notes_lock:
            _notes.append(note)
    except Exception:  # noqa: BLE001
        _mark_accumulator_broken()


def note_checked(source: str, *, hosts: Iterable[str] = (), checks: Iterable[str] = (),
                 module: str = "") -> None:
    """Record, for the run, the hosts ``source`` positively re-checked. Never raises.

    The positive-coverage prune (design decision D1). Once a finding source
    calls this in a run, the end-of-run prune deletes its stale findings only
    on these hosts and keeps every other one, so a host the module never
    reached (a crash, a cap, a host discovery stopped finding) keeps its
    findings without the module having to say so. A source that never calls
    it keeps the older rule: whatever is not noted degraded is pruned. A
    source switched off by configuration must not call it, so its old
    findings are pruned (README "Degraded vs. switched off").

    ``hosts``: ``host`` or ``host:port`` keys, as ``note_degraded`` takes them
    (``host_key`` turns a URL into one). The prune matches findings by
    hostname through ``_KEEP_HOST_FIELDS``, so a host counts as checked when
    any of its ports was. Called with none, the source re-checked nothing and
    prunes nothing. Findings with no host field are never pruned under this
    rule, so a source whose findings carry none should not adopt it.
    ``checks``: finding ``type`` values this record covers alone, for a
    source made of independent checks (``security_check``); empty means every
    type of the source.
    Degraded always wins: a source noted degraded, or a host cut for it or for
    every source, is kept even when also recorded here. Recording a check is
    not a coverage gap: it changes no gap, keep set or degraded flag.
    A fault here marks the accumulator broken, which makes the prune fail closed.
    """
    try:
        token = _token(source)
        if not token:
            return
        note = {
            "kind": "checked",
            "module": _token(module) or token,
            "source": token,
            "hosts": sorted({h for h in (_norm_host(x) for x in hosts) if h}),
            "checks": sorted({_token(c) for c in checks if _token(c)}),
        }
        with _notes_lock:
            _notes.append(note)
    except Exception:  # noqa: BLE001
        _mark_accumulator_broken()


def _aggregate(notes: list[dict]) -> CoverageReport:
    degraded_sources: set[str] = set()
    skipped_hosts: set[str] = set()
    every_source_hosts: set[str] = set()
    per_source_hosts: dict[str, set[str]] = {}
    checked: dict[str, dict[str, set[str]]] = {}
    truncated = False
    merged: dict[tuple[str, str], dict] = {}

    def _gap(source: str, module: str, reason: str, skipped: int = 0, hosts: int = 0) -> None:
        slot = merged.get((source, module))
        if slot is None:
            merged[(source, module)] = {"source": source, "module": module,
                                        "reason": reason, "skipped": skipped, "hosts": hosts}
            return
        slot["skipped"] += skipped
        slot["hosts"] = max(slot["hosts"], hosts)
        if reason and reason not in slot["reason"] and len(slot["reason"]) < 200:
            slot["reason"] = f"{slot['reason']}; {reason}" if slot["reason"] else reason

    for note in notes:
        if note.get("kind") == "checked":
            per_check = checked.setdefault(note["source"], {})
            for check in note["checks"] or ("*",):
                per_check.setdefault(check, set()).update(note["hosts"])
            continue
        module = note["module"]
        aliases = note.get("aliases") or []
        truncated = truncated or note["nuclei_truncated"]
        for source in note["sources"]:
            degraded_sources.add(source)
            _gap(source, module, note["reason"] or "coverage cut")
        if note["sources"]:
            degraded_sources.update(aliases)
        if note["hosts"]:
            skipped_hosts.update(note["hosts"])
            if note.get("source_only_hosts"):
                for source in (note["host_source"], *aliases):
                    per_source_hosts.setdefault(source, set()).update(note["hosts"])
            else:
                every_source_hosts.update(note["hosts"])
            # A host can be cut for a reason other than being down (js_recon's
            # file cap): the note's own reason, when it gives one, says which.
            _gap(note["host_source"], module, note["reason"] or "unreachable host(s) skipped",
                 hosts=len(note["hosts"]))
        if not note["sources"]:
            for entry in note["entries"]:
                _gap(entry["source"], module, entry["reason"], skipped=entry["skipped"])

    gaps = tuple(sorted(merged.values(), key=lambda g: (g["source"], g["module"])))
    source_hosts = tuple(sorted(
        (source, tuple(sorted(hosts - every_source_hosts)))
        for source, hosts in per_source_hosts.items() if hosts - every_source_hosts))
    checked_record = tuple(sorted(
        (source, tuple(sorted((check, tuple(sorted(hosts))) for check, hosts in per_check.items())))
        for source, per_check in checked.items()))
    return CoverageReport(frozenset(degraded_sources), tuple(sorted(skipped_hosts)),
                          truncated, gaps, source_hosts, checked_record)


def coverage_report() -> CoverageReport:
    """Everything noted this run. Raises ``CoverageUnknown`` if the accumulator faulted."""
    if _accumulator_broken:
        raise CoverageUnknown("coverage accumulator faulted")
    with _notes_lock:
        notes = list(_notes)
    return _aggregate(notes)


class GroupScope:
    """What one Domain-batch group added to the accumulator (groups run sequentially)."""

    def __init__(self):
        with _notes_lock:
            self._start = len(_notes)

    def report(self) -> CoverageReport:
        if _accumulator_broken:
            raise CoverageUnknown("coverage accumulator faulted")
        with _notes_lock:
            notes = list(_notes[self._start:])
        return _aggregate(notes)


def group_scope() -> GroupScope:
    return GroupScope()


# ---------------------------------------------------------------------------
# Tests only
# ---------------------------------------------------------------------------

def reset_registry() -> None:
    """Tests only: forget every breaker, host and coverage note, and restore the clock."""
    global _accumulator_broken
    with _registry_lock:
        _registry.clear()
        _caches.clear()
    host_health.reset()
    with _notes_lock:
        _notes.clear()
    _accumulator_broken = False
    set_clock()
