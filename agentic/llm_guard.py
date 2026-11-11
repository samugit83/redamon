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
from typing import Optional

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
    _enforce_llm_limits(request, await _extract_user_id(request))


def _enforce_llm_limits(request: Request, user_id: str) -> None:
    """The token bucket and the daily spend cap of one billed call by `user_id`."""
    if not _rate_limiter.allow(f"{user_id}|{_client_ip(request)}"):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    if not _daily_cap.allow(user_id):
        raise HTTPException(status_code=429, detail="Daily LLM call cap exceeded")


def master_key_is_weak() -> bool:
    """True when INTERNAL_API_KEY is absent or still the compose default.

    `require_master_internal_auth` fails OPEN in that case so a dev install with
    no secrets keeps working, which is right for the endpoints that existed when
    it was written. An endpoint that must not be reachable unauthenticated calls
    this and refuses for itself, without changing that global behaviour.
    """
    master = os.environ.get("INTERNAL_API_KEY", "")
    return not master or master == _CHANGEME


async def require_master_internal_auth(request: Request) -> None:
    """FastAPI dependency: the MASTER key only. Rejects the scanner token.

    `require_internal_auth_only` accepts SCANNER_API_KEY as well, which the scan
    containers hold on purpose. That is NOT correct for an endpoint that MUTATES
    triage state: they are target-facing and deliberately do not hold
    INTERNAL_API_KEY (see docker-compose.yml). Without this stricter dependency
    a compromised scan container could suppress findings so neither the operator
    nor the agent ever sees them, or stamp `triage_source='human'` so a later AI
    pass would refuse to correct it -- an integrity attack on the product's own
    output, mounted with a token we hand those containers on purpose.

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


async def require_configured_master_auth(request: Request) -> None:
    """FastAPI dependency: the MASTER key only, and FAIL-CLOSED without one.

    For routes whose open use is code execution or another tenant's data: the
    workspace file API (read/write/delete any project's files, and the drop the
    kali-sandbox shares through /workspace), the Metasploit session proxy (runs
    commands on every host the operator holds a session on), and agent-session
    stop. The agent port is published on 0.0.0.0, so the fail-open of
    `require_master_internal_auth` would hand these to anyone on the network.
    Every redamon.sh install generates the key, and without it the agent
    WebSocket and the MCP tools already refuse, so refusing here bricks nothing
    that worked.
    """
    if master_key_is_weak():
        raise HTTPException(
            status_code=503,
            detail="INTERNAL_API_KEY is not configured; this endpoint is disabled. "
                   "Generate the secret via redamon.sh.",
        )
    await require_master_internal_auth(request)


async def require_internal_auth_only(request: Request) -> None:
    """FastAPI dependency: AUTH ONLY (no LLM rate-limit / daily spend cap).

    For NON-LLM internal endpoints that authenticate the same way (the master key
    or the scoped SCANNER_API_KEY) but are cheap, frequent calls or rare control
    actions. Applying the LLM token bucket / 5000-per-day cap to these would
    throttle legitimate bulk calls and let them exhaust the LLM budget, which they
    must not (STRIDE S8 non-breaking requirement). The graph read proxy does not
    use it: `/graph/exec` takes `require_master_or_run_credential('graph')`."""
    provided = request.headers.get("x-internal-key", "")
    if not _key_ok(provided):
        raise HTTPException(status_code=401, detail="Unauthorized")


# ---------------------------------------------------------------------------
# Master key or run credential (RBAC T15): the in-sandbox routes
# ---------------------------------------------------------------------------
RUN_CREDENTIAL_HEADER = "x-redamon-run"
_RUN_GATES: dict = {}

#: Audiences whose credential is honoured only while the run it names is open. A
#: terminal's graph credential sits in its shell's environment, which every root
#: process of the shared sandbox can read, so it must die with the terminal rather
#: than live out its 12 hours.
LIVE_RUN_AUDIENCES = frozenset({"graph"})
#: aud -> check(claims) -> bool, set by the process that holds those runs (api.py:
#: the open Kali terminal sockets). Unset, such a credential is refused.
_RUN_LIVENESS: dict = {}


def set_run_liveness(aud: str, check) -> None:
    """Name the check that says whether a verified `aud` credential's run is still open."""
    if aud not in LIVE_RUN_AUDIENCES:
        raise ValueError(f"not a live-run audience: {aud!r}")
    _RUN_LIVENESS[aud] = check


def run_credential_refusal(code: str, aud: str, status: int = 401) -> HTTPException:
    """Log a refused run credential and build the answer the sandbox client reads."""
    logger.warning("[rbac] run credential refused reason=%s aud=%s", code, aud)
    return HTTPException(status_code=status, detail={
        "error": "run credential expired" if code == "expired" else "run credential refused",
        "code": f"run_credential_{code}",
    })


def require_master_or_run_credential(aud: str, *, billed: bool = False):
    """FastAPI dependency for a route the sandbox calls back: the MASTER key, or a
    valid run credential (X-Redamon-Run) of audience `aud`. Fails closed.

    It returns None for the master key (the webapp, whose callers resolved the
    tenant from the database, so the route keeps the body's ids) and the verified
    claims for a credential, whose `ten` and `pid` the route uses instead of the
    body's. The bare scanner key opens nothing here: the sandbox no longer holds
    it, and a scan container has no business on these routes. A weak master key
    answers 503, as `require_configured_master_auth` does, since no credential can
    be verified without it. A credential of a LIVE_RUN_AUDIENCES audience must
    also name a run that is still open (`set_run_liveness`), else `closed`; this
    runs before `billed` adds the LLM token bucket and daily cap, counted against
    the credential's tenant (the master key's: the body user).

    One callable per (aud, billed), so a route can declare it in `dependencies`
    and also take its value as a parameter: FastAPI solves it once per request.
    """
    from machine_credential import RUN_AUDIENCES

    if aud not in RUN_AUDIENCES:
        raise ValueError(f"not a run credential audience: {aud!r}")
    gate = _RUN_GATES.get((aud, billed))
    if gate is not None:
        return gate

    async def gate(request: Request) -> Optional[dict]:
        if master_key_is_weak():
            raise HTTPException(
                status_code=503,
                detail="INTERNAL_API_KEY is not configured; this endpoint is disabled. "
                       "Generate the secret via redamon.sh.",
            )
        provided = request.headers.get("x-internal-key", "")
        if provided and hmac.compare_digest(provided.encode(), os.environ["INTERNAL_API_KEY"].encode()):
            if billed:
                _enforce_llm_limits(request, await _extract_user_id(request))
            return None
        token = request.headers.get(RUN_CREDENTIAL_HEADER, "")
        if not token:
            raise run_credential_refusal("missing", aud)
        from machine_credential import CredentialRefused, verify_run_credential
        try:
            claims = verify_run_credential(token, aud)
        except CredentialRefused as e:
            raise run_credential_refusal(e.code, aud)
        if aud in LIVE_RUN_AUDIENCES:
            live = _RUN_LIVENESS.get(aud)
            if live is None or not live(claims):
                raise run_credential_refusal("closed", aud)
        if billed:
            _enforce_llm_limits(request, claims["ten"])
        return claims

    gate.__name__ = gate.__qualname__ = f"require_master_or_run_credential_{aud}{'_billed' if billed else ''}"
    gate.run_credential_audience = aud
    gate.run_credential_billed = billed
    _RUN_GATES[(aud, billed)] = gate
    return gate


def run_credential_claims(value) -> Optional[dict]:
    """A route parameter filled by the gate above: claims for a credential, None for
    the master key. A handler called directly (a unit test) gets the Depends marker,
    which counts as the master key: only FastAPI fills it in production."""
    return value if isinstance(value, dict) else None


# ---------------------------------------------------------------------------
# Master key, or scanner key + job credential (RBAC T15, step 1.16): the scan routes
# ---------------------------------------------------------------------------
JOB_CREDENTIAL_HEADER = "x-redamon-job"


def job_credential_refusal(code: str, status: int = 401) -> HTTPException:
    """Log a refused job credential and build the answer the scan container reads."""
    logger.warning("[rbac] job credential refused reason=%s", code)
    return HTTPException(status_code=status, detail={
        "error": "job credential expired" if code == "expired" else "job credential refused",
        "code": f"job_credential_{code}",
    })


async def require_master_or_job_credential(request: Request) -> Optional[dict]:
    """FastAPI dependency for the scan containers' routes (/llm/*, /jev/*): the MASTER
    key, or the scanner key TOGETHER WITH a valid job credential (X-Redamon-Job), the
    one the webapp minted for the scan's start. Fails closed; billed.

    It returns None for the master key (the webapp: the body's user_id stands and the
    LLM limits count against it) and the verified claims for a scan, which acts for the
    credential's tenant and project only: a body user_id or project_id naming anyone
    else is refused (403 `job_credential_user_mismatch` / `_project_mismatch`), one
    left out is filled from the claims (`scan_job_ids`), and the limits count against
    the tenant. The bare scanner key answers 401 `job_credential_missing`. A weak
    master key answers 503: no credential can be verified without it.
    """
    if master_key_is_weak():
        raise HTTPException(
            status_code=503,
            detail="INTERNAL_API_KEY is not configured; this endpoint is disabled. "
                   "Generate the secret via redamon.sh.",
        )
    provided = request.headers.get("x-internal-key", "")
    if provided and hmac.compare_digest(provided.encode(), os.environ["INTERNAL_API_KEY"].encode()):
        _enforce_llm_limits(request, await _extract_user_id(request))
        return None
    scanner = os.environ.get("SCANNER_API_KEY", "")
    if not (scanner and scanner != _CHANGEME and provided
            and hmac.compare_digest(provided.encode(), scanner.encode())):
        raise HTTPException(status_code=401, detail="Unauthorized")
    token = request.headers.get(JOB_CREDENTIAL_HEADER, "")
    if not token:
        raise job_credential_refusal("missing")
    from machine_credential import CredentialRefused, verify_job_credential
    try:
        claims = verify_job_credential(token)
    except CredentialRefused as e:
        raise job_credential_refusal(e.code)
    body = await _json_body(request)
    for field, claim, code in (("user_id", "ten", "user_mismatch"), ("project_id", "pid", "project_mismatch")):
        value = body.get(field)
        if value and str(value) != claims[claim]:
            raise job_credential_refusal(code, 403)
    _enforce_llm_limits(request, claims["ten"])
    return claims


async def _json_body(request: Request) -> dict:
    try:
        body = await request.json()
    except Exception:
        return {}
    return body if isinstance(body, dict) else {}


def scan_job_ids(value, user_id: Optional[str], project_id: Optional[str]) -> tuple:
    """The (user, project) a scan route acts for: the job credential's when one opened
    it (the gate refused other body ids), else the body's (the master key). A handler
    called directly (a unit test) gets the Depends marker, which counts as the master
    key: only FastAPI fills it in production."""
    if isinstance(value, dict):
        return value["ten"], value["pid"]
    return user_id, project_id

