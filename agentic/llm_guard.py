"""
D3 — inbound auth + rate limit + spend cap for the agent's billed LLM endpoints.

The 9 `/llm/*`, `/guardrail/check-target`, `/roe/parse`, `/models` and
`/llm-provider/test` endpoints take ``user_id`` from the request body, fetch
that user's provider keys, and invoke a billed LLM call. They had NO inbound
auth and NO rate governor, so an unauthenticated flood could exhaust the
operator's LLM budget and trip provider rate limits (the D3 threat).

This module provides one FastAPI dependency, :func:`require_internal_auth`,
that:

1. **Authenticates** the caller with a constant-time compare of the
   ``X-Internal-Key`` header against ``INTERNAL_API_KEY`` **or**
   ``SCANNER_API_KEY`` (the scoped scanner token introduced by S3/E6). Both
   the webapp proxies and the recon planners already hold one of these.
2. **Rate limits** with a stdlib token bucket keyed by ``(user_id, source-ip)``.
3. **Spend-caps** with a per-user rolling daily call counter.

**Fail-open when neither secret is set** (with a one-time warning), matching
the MCP / WS-ticket rollout convention, so a pre-secret install never hard
-breaks; it closes the moment ``redamon.sh`` generates the key. Rate/spend
limits are always active (they need no secret) and bound damage either way.
"""

import hmac
import logging
import os
import threading
import time

from fastapi import HTTPException, Request

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config knobs (env-overridable; generous so legitimate callers never trip).
# ---------------------------------------------------------------------------
def _int_env(name: str, default: int) -> int:
    try:
        return max(1, int(os.environ.get(name, default)))
    except (TypeError, ValueError):
        return default


def _float_env(name: str, default: float) -> float:
    try:
        return max(0.001, float(os.environ.get(name, default)))
    except (TypeError, ValueError):
        return default


# Token-bucket: burst capacity + sustained refill rate, per (user_id, ip).
RATE_CAPACITY = _int_env("LLM_GUARD_RATE_CAPACITY", 60)
RATE_REFILL_PER_SEC = _float_env("LLM_GUARD_RATE_REFILL_PER_SEC", 1.0)
# Per-user rolling 24h call ceiling.
DAILY_CALL_CAP = _int_env("LLM_GUARD_DAILY_CALL_CAP", 5000)

_CHANGEME = "changeme"


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------
_warned_failopen = False
_warned_failopen_master = False


def _valid_keys() -> list[str]:
    """Accepted credentials: INTERNAL_API_KEY and the scoped SCANNER_API_KEY.

    Placeholder/unset values are excluded so an install that never generated a
    key stays in the documented fail-open state rather than accepting
    ``changeme``.
    """
    keys = []
    for name in ("INTERNAL_API_KEY", "SCANNER_API_KEY"):
        v = os.environ.get(name, "")
        if v and v != _CHANGEME:
            keys.append(v)
    return keys


def _key_ok(provided: str) -> bool:
    global _warned_failopen
    keys = _valid_keys()
    if not keys:
        if not _warned_failopen:
            logger.warning(
                "llm_guard: neither INTERNAL_API_KEY nor SCANNER_API_KEY is set; "
                "billed LLM endpoints are FAIL-OPEN (dev only). Generate the "
                "secret via redamon.sh to enforce auth."
            )
            _warned_failopen = True
        return True  # fail-open until a secret exists
    provided_b = (provided or "").encode()
    # compare against every accepted key; compare_digest is constant-time and
    # safe on length mismatch.
    return any(hmac.compare_digest(provided_b, k.encode()) for k in keys)


# ---------------------------------------------------------------------------
# Rate limiter (token bucket) + daily spend cap. Trivial, lock-guarded.
# ---------------------------------------------------------------------------
class _TokenBucket:
    def __init__(self, capacity: int, refill_per_sec: float):
        self.capacity = capacity
        self.refill = refill_per_sec
        self._state: dict[str, tuple[float, float]] = {}  # key -> (tokens, ts)
        self._lock = threading.Lock()

    def allow(self, key: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        with self._lock:
            tokens, last = self._state.get(key, (float(self.capacity), now))
            tokens = min(self.capacity, tokens + (now - last) * self.refill)
            if tokens < 1.0:
                self._state[key] = (tokens, now)
                return False
            self._state[key] = (tokens - 1.0, now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._state.clear()


class _DailyCap:
    def __init__(self, cap: int, window_sec: float = 86400.0):
        self.cap = cap
        self.window = window_sec
        self._state: dict[str, tuple[int, float]] = {}  # user -> (count, start)
        self._lock = threading.Lock()

    def allow(self, user_id: str, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        with self._lock:
            count, start = self._state.get(user_id, (0, now))
            if now - start >= self.window:
                count, start = 0, now  # roll the window
            if count >= self.cap:
                self._state[user_id] = (count, start)
                return False
            self._state[user_id] = (count + 1, start)
            return True

    def reset(self) -> None:
        with self._lock:
            self._state.clear()


_rate_limiter = _TokenBucket(RATE_CAPACITY, RATE_REFILL_PER_SEC)
_daily_cap = _DailyCap(DAILY_CALL_CAP)


def reset_state() -> None:
    """Test hook — clear rate/spend state between cases."""
    _rate_limiter.reset()
    _daily_cap.reset()


# ---------------------------------------------------------------------------
# Request helpers
# ---------------------------------------------------------------------------
def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


async def _extract_user_id(request: Request) -> str:
    """Best-effort user_id from the JSON body (Starlette caches the body, so
    the downstream route still parses it). Falls back to 'anonymous'."""
    try:
        body = await request.json()
        if isinstance(body, dict):
            uid = body.get("user_id") or body.get("userId")
            if uid:
                return str(uid)
    except Exception:
        pass
    return "anonymous"


# ---------------------------------------------------------------------------
# The dependency
# ---------------------------------------------------------------------------
async def require_internal_auth(request: Request) -> None:
    """FastAPI dependency: auth → rate-limit → spend-cap. Raises 401 / 429.

    Use for BILLED LLM endpoints (the rate-limit + daily cap protect LLM spend)."""
    provided = request.headers.get("x-internal-key", "")
    if not _key_ok(provided):
        raise HTTPException(status_code=401, detail="Unauthorized")

    ip = _client_ip(request)
    user_id = await _extract_user_id(request)

    if not _rate_limiter.allow(f"{user_id}|{ip}"):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    if not _daily_cap.allow(user_id):
        raise HTTPException(status_code=429, detail="Daily LLM call cap exceeded")


async def require_master_internal_auth(request: Request) -> None:
    """FastAPI dependency: the MASTER key only. Rejects the scanner token.

    `require_internal_auth_only` accepts SCANNER_API_KEY as well, which is
    correct for the read-only, fixed-op `/graph/exec`: the kali-sandbox holds
    that token by design and needs graph reads.

    It is NOT correct for an endpoint that MUTATES triage state. The worker is
    the least-trusted, target-facing component and deliberately does not hold
    INTERNAL_API_KEY (see docker-compose.yml). Without this stricter dependency
    a compromised worker could suppress findings so neither the operator nor the
    agent ever sees them, or stamp `triage_source='human'` so a later AI pass
    would refuse to correct it -- an integrity attack on the product's own
    output, mounted with a token we hand the worker on purpose.

    Fail-open when no master key exists mirrors `_key_ok`, so a dev install with
    no secrets behaves as documented rather than bricking.
    """
    master = os.environ.get("INTERNAL_API_KEY", "")
    if not master or master == _CHANGEME:
        global _warned_failopen_master
        if not _warned_failopen_master:
            logger.warning(
                "llm_guard: INTERNAL_API_KEY is not set; master-only endpoints "
                "(/graph/triage) are FAIL-OPEN (dev only). Generate the secret "
                "via redamon.sh to enforce auth."
            )
            _warned_failopen_master = True
        return
    provided = request.headers.get("x-internal-key", "")
    if not hmac.compare_digest(provided.encode(), master.encode()):
        raise HTTPException(status_code=401, detail="Unauthorized")


async def require_internal_auth_only(request: Request) -> None:
    """FastAPI dependency: AUTH ONLY (no LLM rate-limit / daily spend cap).

    For NON-LLM internal endpoints that authenticate the same way but are cheap
    high-frequency calls (e.g. /graph/exec graph reads) or rare control actions
    (/emergency-stop-all). Applying the LLM token bucket / 5000-per-day cap to
    these would throttle a legitimate bulk graph walk and let graph reads exhaust
    the LLM budget, which they must not (STRIDE S8 non-breaking requirement)."""
    provided = request.headers.get("x-internal-key", "")
    if not _key_ok(provided):
        raise HTTPException(status_code=401, detail="Unauthorized")
