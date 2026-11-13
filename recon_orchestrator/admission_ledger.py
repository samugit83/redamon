"""
Memory-aware admission control for scan containers (Part 1 of the memory governor).

The orchestrator spawns scan jobs (full/partial recon, ai-attack, gvm, github,
trufflehog), each of which also spawns sibling tool containers. This ledger
decides whether there is room to start another one WITHOUT risking host OOM.

It reserves each job's expected peak (its "envelope"), not its current usage,
because containers allocate lazily: reading instantaneous free RAM would let many
jobs each see "plenty free" and then grow into a joint OOM. A job is admitted only
when its envelope still fits the scan pool AND live MemAvailable has headroom AND
we are not already in a critical-pressure state.

Pure and dependency-light (only resource_governor + stdlib) so it is unit-testable
without Docker. The mem/pressure sources are injectable for tests.
"""

import asyncio
import os
from typing import Callable, Dict, Optional, Tuple

import resource_governor as rg

# Built-in fallbacks when neither env nor profile provides a figure.
#
# These are PERCENTAGES OF HOST RAM, not fixed sizes. They used to be a flat 6 GB
# baseline and 2 GB headroom, which meant the scan pool was computed from numbers
# that had no relationship to the machine OR to what redamon.sh actually handed
# the always-on services: on an 8 GB host the two constants alone claimed the
# entire machine, and on a 512 GB host they under-reserved by two orders of
# magnitude. redamon.sh now exports OS_HEADROOM_MEM and SERVICE_BASELINE_MEM from
# the same computation that sets the per-service mem_limits, so these apply only
# when it has never run (a bare `docker compose up` on a fresh clone).
#
# Absolute floors are kept so a tiny host still reserves something meaningful.
_FALLBACK_SERVICE_BASELINE_PCT = 60   # matches redamon.sh's services share of usable
_FALLBACK_OS_HEADROOM_PCT = 8         # matches redamon.sh's OS_RESERVE_PCT
_FALLBACK_SERVICE_BASELINE_MIN = 2 * 1024 ** 3
_FALLBACK_OS_HEADROOM_MIN = 512 * 1024 ** 2


def _pct_of_host(pct: int, floor: int) -> int:
    """`pct` percent of host RAM, never below `floor`. Falls back to the floor
    when /proc/meminfo is unreadable (same fail-open contract as the governor)."""
    mem = rg.read_mem()
    if not mem or mem[0] <= 0:
        return floor
    return max(floor, mem[0] * pct // 100)

# D3: generous per-user concurrent-scan default when RECON_MAX_CONCURRENT_PER_USER
# is unset. Fails SAFE to a real number, never to "no cap".
_FALLBACK_PER_USER_CAP = 30


class AdmissionError(ValueError):
    """Raised when a scan cannot be admitted. Subclasses ValueError so existing
    `except ValueError` handlers in the API return a clean 4xx today; carries the
    typed `.result` for the Part 5 limit-modal payload."""

    def __init__(self, result: "AdmissionResult"):
        self.result = result
        super().__init__(result.detail or "scan admission denied")


class AdmissionResult:
    """Outcome of a try_admit() call. Mirrors the Part 5 limit-modal payload."""

    def __init__(self, admitted: bool, *, limit_type: Optional[str] = None,
                 resource: str = "scan", current: int = 0, ceiling: int = 0,
                 setting_name: Optional[str] = None, detail: str = ""):
        self.admitted = admitted
        self.limit_type = limit_type          # None | "hard" | "ram"
        self.resource = resource
        self.current = current
        self.ceiling = ceiling
        self.setting_name = setting_name
        self.detail = detail

    def payload(self) -> dict:
        return {
            "admitted": self.admitted,
            "limitType": self.limit_type,
            "resource": self.resource,
            "current": self.current,
            "ceiling": self.ceiling,
            "settingName": self.setting_name,
            "detail": self.detail,
        }


class ReservationLedger:
    def __init__(self,
                 mem_reader: Callable[[], Optional[Tuple[int, int]]] = rg.read_mem,
                 pressure_fn: Callable[[], str] = rg.pressure):
        self._mem_reader = mem_reader
        self._pressure_fn = pressure_fn
        self._committed: Dict[str, int] = {}      # key -> reserved bytes
        self._key_user: Dict[str, str] = {}       # D3: key -> owning user_id
        self._lock = asyncio.Lock()

    # --- configuration (read fresh so env changes / test overrides apply) -----

    def os_headroom(self) -> int:
        return rg.env_bytes(
            "OS_HEADROOM_MEM",
            _pct_of_host(_FALLBACK_OS_HEADROOM_PCT, _FALLBACK_OS_HEADROOM_MIN),
        )

    def service_baseline(self) -> int:
        env = rg.env_bytes("SERVICE_BASELINE_MEM", None)
        if env is not None:
            return env
        prof = rg.envelope("service_baseline_bytes")
        if prof:
            return prof
        return _pct_of_host(_FALLBACK_SERVICE_BASELINE_PCT, _FALLBACK_SERVICE_BASELINE_MIN)

    def host_total(self) -> int:
        mem = self._mem_reader()
        return mem[0] if mem else 0

    def available(self) -> int:
        mem = self._mem_reader()
        return mem[1] if mem else 0

    def scan_pool(self) -> int:
        return max(0, self.host_total() - self.os_headroom() - self.service_baseline())

    def max_concurrent_global(self, envelope: int) -> Optional[int]:
        """Optional secondary hard count cap. None = bytes-ledger only.

        Unset -> None (no count cap). An explicit value >= 0 is honored, so
        RECON_MAX_CONCURRENT_GLOBAL=0 correctly blocks ALL new scans (a valid
        "pause" knob) rather than disabling the cap."""
        raw = os.environ.get("RECON_MAX_CONCURRENT_GLOBAL")
        if raw is None or raw.strip() == "":
            return None
        try:
            val = int(float(raw))
        except (TypeError, ValueError):
            return None
        return max(0, val)

    def max_concurrent_per_user(self) -> int:
        """D3: per-user concurrent-scan ceiling. Unset/invalid -> generous default
        (fails safe to a number, never "no cap"). 0 blocks all of a user's scans."""
        raw = os.environ.get("RECON_MAX_CONCURRENT_PER_USER")
        if raw is None or raw.strip() == "":
            return _FALLBACK_PER_USER_CAP
        try:
            return max(0, int(float(raw)))
        except (TypeError, ValueError):
            return _FALLBACK_PER_USER_CAP

    def user_active_count(self, user_id: str) -> int:
        return sum(1 for u in self._key_user.values() if u == user_id)

    # --- accounting -----------------------------------------------------------

    def committed_bytes(self) -> int:
        return sum(self._committed.values())

    def active_count(self) -> int:
        return len(self._committed)

    def remaining_for_new(self) -> int:
        """RAM actually available to admit a new job (for the /system/stats UI)."""
        by_pool = self.scan_pool() - self.committed_bytes()
        by_live = self.available() - self.os_headroom()
        return max(0, min(by_pool, by_live))

    # --- admission ------------------------------------------------------------

    async def try_admit(self, key: str, envelope: int, user_id: Optional[str] = None) -> AdmissionResult:
        """Reserve `envelope` bytes for `key` if it fits; otherwise reject with a
        typed reason. Idempotent: re-admitting an already-committed key is a no-op
        success (keeps retries safe). `user_id` (when supplied) is subject to the
        per-user concurrent-scan ceiling (D3) and tracked for release symmetry."""
        if not rg.governor_enabled():
            async with self._lock:
                self._committed[key] = envelope
                if user_id is not None:
                    self._key_user[key] = user_id
            return AdmissionResult(True)
        async with self._lock:
            if key in self._committed:
                # Idempotent re-admit; keep the LARGER reservation so an escalated
                # envelope never under-counts.
                self._committed[key] = max(self._committed[key], envelope)
                if user_id is not None:
                    self._key_user.setdefault(key, user_id)
                return AdmissionResult(True)

            # Secondary hard count cap (explicit operator ceiling; 0 blocks all).
            cap = self.max_concurrent_global(envelope)
            if cap is not None and len(self._committed) >= cap:
                return AdmissionResult(
                    False, limit_type="hard", current=len(self._committed),
                    ceiling=cap, setting_name="RECON_MAX_CONCURRENT_GLOBAL",
                    detail=f"{len(self._committed)} of {cap} concurrent scans allowed")

            # D3: per-user hard count cap. `user_id` is the start's actor (step 5.5,
            # D-14: api._job_actor, the person who started it, defaulting to the job
            # credential's tenant), so a collaborator's scans on another person's
            # project count against the collaborator; unset falls back to a generous
            # default.
            if user_id is not None:
                per_user = self.max_concurrent_per_user()
                cur = self.user_active_count(user_id)
                if cur >= per_user:
                    return AdmissionResult(
                        False, limit_type="hard", current=cur, ceiling=per_user,
                        setting_name="RECON_MAX_CONCURRENT_PER_USER",
                        detail=f"{cur} of {per_user} concurrent scans allowed per user")

            # Fail OPEN: if host memory is unreadable (no /proc, restricted
            # container), the governor can't make a safe decision — admit rather
            # than deny everything. Matches resource_governor.scaled_cap's
            # fail-open contract so the two halves never disagree.
            if self._mem_reader() is None:
                self._committed[key] = envelope
                if user_id is not None:
                    self._key_user[key] = user_id
                return AdmissionResult(True)

            # Critical memory pressure blocks new work outright.
            if self._pressure_fn() == "critical":
                return AdmissionResult(
                    False, limit_type="ram", current=self.available(),
                    ceiling=self.scan_pool(),
                    detail="host memory critically low")

            pool = self.scan_pool()
            committed = self.committed_bytes()
            # Pool (concurrency) budget bounds CONCURRENT scans; never deny the
            # SOLE scan on budget grounds (would brick small hosts). The physical
            # availability check below still guards the first scan.
            if committed > 0 and committed + envelope > pool:
                return AdmissionResult(
                    False, limit_type="ram", current=committed, ceiling=pool,
                    detail="not enough reserved memory budget for another scan")
            # Physical reality check: live available RAM must hold this envelope
            # plus OS headroom (applies to the first scan too).
            if self.available() < envelope + self.os_headroom():
                return AdmissionResult(
                    False, limit_type="ram", current=self.available(),
                    ceiling=self.scan_pool(),
                    detail="not enough free memory to start this scan now")

            self._committed[key] = envelope
            if user_id is not None:
                self._key_user[key] = user_id
            return AdmissionResult(True)

    async def release(self, key: str) -> None:
        async with self._lock:
            self._committed.pop(key, None)
            self._key_user.pop(key, None)  # D3: keep per-user count in lockstep

    def release_nowait(self, key: str) -> None:
        """Sync release for callers that aren't in an async context (dict pop is
        atomic under the GIL; safe against an awaiting try_admit which re-reads
        committed after acquiring the lock)."""
        self._committed.pop(key, None)
        self._key_user.pop(key, None)  # D3

    def account(self, key: str, envelope: int) -> None:
        """Reserve `envelope` for `key` UNCONDITIONALLY - no gate, no refusal.

        For always-run consumers whose RAM the ledger must still SEE so it stops
        over-admitting scans on top of them (Phase 7: the CodeFix build sandbox).
        Unlike try_admit this never denies: the consumer runs regardless, but its
        bytes push back on the NEXT scan's admission. Release via release_nowait or
        reconcile, exactly like a scan reservation (dict assignment is atomic under
        the GIL, so no async lock is needed)."""
        self._committed[key] = envelope

    def reconcile(self, active_keys) -> int:
        """Drop any reservation whose scan is no longer active. Leak-proof
        alternative to hooking every terminal path: the caller passes the set of
        keys that are genuinely still RUNNING/STARTING and we keep only those.
        Returns the number of stale reservations released. D3: the per-user map is
        released here too so a crashed/orphaned scan cannot leak the user's count
        and self-DoS them out of new scans."""
        active = set(active_keys)
        stale = [k for k in self._committed if k not in active]
        for k in stale:
            self._committed.pop(k, None)
            self._key_user.pop(k, None)
        return len(stale)

    def envelope_for(self, scan_type: str) -> int:
        """Per-scan-type envelope: env override wins (if > 0), else measured
        profile. A 0/invalid override is ignored so it can't defeat the gate."""
        env = rg.env_bytes("RECON_JOB_ENVELOPE_MEM", None)
        if env and env > 0:
            return env
        return rg.scan_job_envelope(scan_type)

    def snapshot(self) -> dict:
        """For GET /system/stats (Part 5)."""
        return {
            "host_total": self.host_total(),
            "available": self.available(),
            "os_headroom": self.os_headroom(),
            "service_baseline": self.service_baseline(),
            "scan_pool": self.scan_pool(),
            "committed": self.committed_bytes(),
            "active_scans": self.active_count(),
            "remaining_for_new": self.remaining_for_new(),
            "pressure": self._pressure_fn(),
        }
