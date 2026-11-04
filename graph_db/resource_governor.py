"""
RAM-aware runtime resource governor (dual-cap: hard env ceiling + dynamic cap).

Single source of truth for turning a configured limit (the hard ceiling) into an
*effective* limit that also respects how much memory is actually available right
now. It NEVER returns more than the configured value; it only throttles DOWN
under memory pressure.

Two models (pick by what one unit of the knob is):
  - RATIO       (scaled)      : in-process concurrency (threads, -c/-t, pool
                                widths). Proportional throttle on available/total.
  - BYTE-BUDGET (scaled_cap)  : anything that costs real megabytes (a process /
                                container / session, or an in-memory *_MAX_* list).
                                effective = min(env, available * fraction / bytes).

Dependency-free (stdlib only) and platform-uniform: it reads /proc, which exists
inside every Linux container regardless of whether the host is Linux, macOS, or
Windows (on Docker Desktop it reports the VM's figures, which is the correct
ceiling to govern against). Fails OPEN: if /proc is unreadable or the governor is
disabled, scale()==1.0 and scaled_cap() returns the env value, i.e. current
behavior.

This file is vendored identically into `recon_orchestrator/resource_governor.py`
(the orchestrator does not import graph_db). Keep the two byte-identical.
"""

import json
import os
import time
from typing import Optional, Tuple

# ---------------------------------------------------------------------------
# Config (env-overridable; DEFAULTS LIVE HERE). Empty/unset env -> default.
# ---------------------------------------------------------------------------

_MEMINFO_PATH = "/proc/meminfo"
_STAT_PATH = "/proc/stat"


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return float(raw)
    except (TypeError, ValueError):
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def parse_size(s) -> Optional[int]:
    """Parse a Docker-style size ('2g', '512m', '1024k', '123') into bytes.

    Returns None on empty/invalid input. Plain numbers are treated as bytes.
    """
    if s is None:
        return None
    s = str(s).strip().lower()
    if s == "":
        return None
    # tolerate a trailing 'b' (e.g. '512mb') BEFORE reading the unit letter.
    if s.endswith("b"):
        s = s[:-1].strip()
    mult = 1
    if s and s[-1] in ("k", "m", "g", "t"):
        mult = {"k": 1024, "m": 1024 ** 2, "g": 1024 ** 3, "t": 1024 ** 4}[s[-1]]
        s = s[:-1].strip()
    try:
        val = float(s)
    except (TypeError, ValueError):
        return None
    if val < 0:
        return None
    return int(val * mult)


def env_bytes(name: str, default_bytes: Optional[int]) -> Optional[int]:
    """Read an env var as a byte size (Docker-style suffixes), else the default."""
    parsed = parse_size(os.environ.get(name))
    return parsed if parsed is not None else default_bytes


def governor_enabled() -> bool:
    return _env_bool("REDAMON_MEM_GOVERNOR", True)


def _scale_high() -> float:
    return _env_float("MEM_SCALE_HIGH", 0.50)


def _scale_low() -> float:
    return _env_float("MEM_SCALE_LOW", 0.15)


def _scale_floor() -> float:
    return _env_float("MEM_SCALE_FLOOR", 0.15)


def _read_ttl() -> float:
    return _env_float("MEM_READ_TTL_S", 2.0)


def budget_fraction() -> float:
    return _env_float("MEM_BUDGET_FRACTION", 0.10)


# ---------------------------------------------------------------------------
# Test/override hook: let callers inject a synthetic (total, available) so unit
# tests never depend on the real host. Set to None to use /proc.
# ---------------------------------------------------------------------------

_mem_override: Optional[Tuple[int, int]] = None
_mem_cache: Optional[Tuple[int, int]] = None
_mem_cache_at: float = 0.0


def set_mem_override(total: Optional[int], available: Optional[int]) -> None:
    """Force read_mem() to return these values (bytes). Pass None,None to clear."""
    global _mem_override, _mem_cache
    if total is None or available is None:
        _mem_override = None
    else:
        _mem_override = (int(total), int(available))
    _mem_cache = None  # invalidate cache so the override takes effect immediately


def _parse_meminfo(text: str) -> Optional[Tuple[int, int]]:
    """Return (total_bytes, available_bytes) from /proc/meminfo text, or None."""
    total_kb = None
    avail_kb = None
    for line in text.splitlines():
        if line.startswith("MemTotal:"):
            total_kb = _first_int(line)
        elif line.startswith("MemAvailable:"):
            avail_kb = _first_int(line)
        if total_kb is not None and avail_kb is not None:
            break
    if total_kb is None or avail_kb is None or total_kb <= 0:
        return None
    return total_kb * 1024, avail_kb * 1024


def _first_int(line: str) -> Optional[int]:
    for tok in line.split():
        if tok.isdigit():
            return int(tok)
    return None


def read_mem() -> Optional[Tuple[int, int]]:
    """(total_bytes, available_bytes) from /proc/meminfo (host/VM), cached ~TTL.

    Returns None if unreadable (callers then fail open). An override wins.
    """
    global _mem_cache, _mem_cache_at
    if _mem_override is not None:
        return _mem_override
    now = time.monotonic()
    if _mem_cache is not None and (now - _mem_cache_at) < _read_ttl():
        return _mem_cache
    try:
        with open(_MEMINFO_PATH, "r") as fh:
            parsed = _parse_meminfo(fh.read())
    except (OSError, ValueError):
        parsed = None
    if parsed is not None:
        _mem_cache = parsed
        _mem_cache_at = now
    return parsed


def avail_ratio() -> Optional[float]:
    """available/total in (0,1], or None if unreadable."""
    mem = read_mem()
    if mem is None:
        return None
    total, available = mem
    if total <= 0:
        return None
    return max(0.0, min(1.0, available / total))


# ---------------------------------------------------------------------------
# CPU percent (for the /system/stats endpoint). Delta between two /proc/stat
# reads; first call returns 0.0. Stateful, so not cached by the mem TTL.
# ---------------------------------------------------------------------------

_cpu_last: Optional[Tuple[int, int]] = None  # (busy, total)


def cpu_percent() -> float:
    """Host/VM CPU utilization percent since the previous call (0..100)."""
    global _cpu_last
    try:
        with open(_STAT_PATH, "r") as fh:
            first = fh.readline()
    except OSError:
        return 0.0
    if not first.startswith("cpu "):
        return 0.0
    parts = [int(x) for x in first.split()[1:] if x.isdigit()]
    if len(parts) < 4:
        return 0.0
    idle = parts[3] + (parts[4] if len(parts) > 4 else 0)  # idle + iowait
    total = sum(parts)
    busy = total - idle
    last = _cpu_last
    _cpu_last = (busy, total)
    if last is None:
        return 0.0
    d_busy = busy - last[0]
    d_total = total - last[1]
    if d_total <= 0:
        return 0.0
    return max(0.0, min(100.0, 100.0 * d_busy / d_total))


def cpu_cores() -> int:
    try:
        return os.cpu_count() or 1
    except Exception:
        return 1


# ---------------------------------------------------------------------------
# The two models.
# ---------------------------------------------------------------------------

def scale() -> float:
    """Global memory-pressure scale factor in (0,1]. 1.0 = full env ceiling.

    Piecewise: >=HIGH -> 1.0; <=LOW -> FLOOR; linear ramp between. Fails open
    (1.0) when the governor is disabled or /proc is unreadable.
    """
    if not governor_enabled():
        return 1.0
    ratio = avail_ratio()
    if ratio is None:
        return 1.0
    high, low, floor = _scale_high(), _scale_low(), _scale_floor()
    if high <= low:  # misconfigured; be safe
        return 1.0
    if ratio >= high:
        return 1.0
    if ratio <= low:
        return floor
    frac = (ratio - low) / (high - low)
    return floor + frac * (1.0 - floor)


def scaled(value: int, floor: int = 1) -> int:
    """RATIO model. clamp(round(value*scale()), floor, value). Never exceeds value."""
    try:
        value = int(value)
    except (TypeError, ValueError):
        return value
    if value <= 0:
        return value
    floor = max(0, min(int(floor), value))
    if not governor_enabled():
        return value
    eff = int(round(value * scale()))
    return max(floor, min(value, eff))


def scaled_cap(env_cap: int, bytes_per_unit: int, fraction: Optional[float] = None,
               floor: int = 1) -> int:
    """BYTE-BUDGET model for anything costing real bytes (processes/lists).

    effective = clamp(available * fraction // bytes_per_unit, floor, env_cap).
    Fails open to env_cap when disabled / unreadable / bad inputs.
    """
    try:
        env_cap = int(env_cap)
    except (TypeError, ValueError):
        return env_cap
    if env_cap <= 0:
        return env_cap
    floor = max(0, min(int(floor), env_cap))
    if not governor_enabled() or not bytes_per_unit or bytes_per_unit <= 0:
        return env_cap
    mem = read_mem()
    if mem is None:
        return env_cap
    available = mem[1]
    frac = budget_fraction() if fraction is None else float(fraction)
    by_budget = int((available * frac) // bytes_per_unit)
    return max(floor, min(env_cap, by_budget))


def pressure() -> str:
    """'ok' | 'warn' | 'critical' from the available/total ratio."""
    ratio = avail_ratio()
    if ratio is None or not governor_enabled():
        return "ok"
    if ratio <= _scale_low():
        return "critical"
    if ratio < _scale_high():
        return "warn"
    return "ok"


# ---------------------------------------------------------------------------
# resource_profile.json (measured envelopes + bytes-per-unit; Part 0A). Loaded
# lazily with a built-in fallback so the governor works before calibration.
# ---------------------------------------------------------------------------

# Conservative built-in fallbacks (bytes). Calibration TIGHTENS these from real
# measurements; they are intentionally generous so pre-calibration behavior is
# safe, not aggressive.
#
# scan_job_envelope_bytes is PER SCAN TYPE, not one number for all of them: a
# partial recon runs a single step (observed peak ~150 MB) while a full pipeline
# runs a dozen tools, and charging both the worst case made small hosts unable to
# admit ANY scan (8 GB host: 4 GB envelope + 2 GB OS headroom > free RAM, forever).
# Keep these in sync with recon_orchestrator/resource_profile.default.json and with
# recon_orchestrator/resource_governor.py (this file is its copy for the agent /
# recon / mcp side) — tests/test_resource_governor.py asserts all three match.
_FALLBACK_PROFILE = {
    "bytes_per_unit": {
        "url": 600,
        "js_file": 65536,
        "osint_result": 1024,
        "vhost_candidate": 256,
        # Identity family for knobs that are ALREADY expressed in bytes (e.g.
        # SUPPLY_CHAIN_IMPORT_MAX_BYTES). Without it those keys would fall to
        # the 1024 default and be budgeted as if each byte cost a kilobyte.
        "byte": 1,
    },
    "tool_container_envelope_bytes": {
        # The DIRTY supply-chain analyzer is a real, heavy SIBLING container (it
        # unpacks registry tarballs and runs semgrep/YARA), not an in-process
        # step. It is spawned from THREE places (orchestrator SDK, recon via the
        # broker socket, L1 scan via the broker socket), so its size lives here
        # rather than being hardcoded per call site — that is how the two dispatch
        # paths silently drifted (one governed, one a fixed "1500m" literal).
        #
        # 1 GB is the EXPECTED PEAK, not the ceiling: container_cap() multiplies
        # it by CONTAINER_CAP_HEADROOM (1.5) to 1.5 GB, reproducing the literal
        # this replaced. Envelopes are peaks; caps are peaks x headroom.
        "supply_chain_analyzer": 1_073_741_824,
        # JS Recon's TruffleHog sidecar, spawned by recon over the broker: the
        # staged JS plus TruffleHog's chunk buffers. Its own key, not the
        # Secret Multiscanner's (that image is shared), so mem_calibrate does
        # not size it from the other tool's runs.
        "trufflehog_js": 805_306_368,
        # ZAP Ajax Spider is the only tool that runs a JVM and a headless
        # Firefox in the SAME cgroup. Measured on a real vinted.com crawl: the
        # JVM held 1.05 GiB and Firefox's children (firefox-esr plus several
        # Isolated Web Content processes) another 0.82-1.20 GiB, so a 2 GiB
        # ceiling left no headroom and the kernel SIGKILLed the JVM mid-seed
        # (exit 137) on every crawl. 2 GiB is the measured PEAK, so
        # container_cap()'s 1.5x headroom yields the 3 GiB the pair actually
        # needs. Its own key, not _default: without it ZAP was charged the
        # generic 1.5 GB envelope, which x1.5 = 2.25 GiB disagreed with the
        # broker's 2 GiB clamp and the JVM was sized from a ceiling that did
        # not exist.
        "zap_ajax": 2_147_483_648,
        "_default": 1_500_000_000,
    },
    "scan_job_envelope_bytes": {
        "full_recon": 2_147_483_648,      # 2 GB   container + a dozen sibling tools
        "partial_recon": 805_306_368,     # 768 MB one step, few or no siblings
        # A supply-chain PARTIAL is not a cheap single step: it re-runs the JS
        # fetch AND spawns the dirty analyzer (retire.js always, GuardDog when
        # deep analysis is on). Charging it the generic 768 MB under-reserved it
        # by ~3x. Keyed "<kind>:<tool_id>" so only this tool pays; every other
        # partial keeps the cheap envelope and small hosts stay admittable.
        "partial_recon:SupplyChainRecon": 1_879_048_192,  # 1.75 GB step + analyzer
        # A JS Recon partial holds every downloaded bundle in memory and may
        # spawn the TruffleHog sidecar beside it.
        "partial_recon:JsRecon": 1_610_612_736,  # 1.5 GB step + sidecar
        "ai_attack": 1_073_741_824,       # 1 GB   probe workers (the local LLM is separate)
        "gvm": 2_684_354_560,             # 2.5 GB openvas is the heaviest scanner
        "github_hunt": 805_306_368,       # 768 MB clone + regex sweep
        "trufflehog": 805_306_368,        # 768 MB clone + verifier sweep
        # Source-qualified: docker and huggingface pull and decompress remote
        # blobs, so they peak far above the git-based sources. scan_job_envelope
        # falls back to (and floors at) the plain "trufflehog" entry, so every
        # source without a line here keeps the 768 MB family envelope.
        "trufflehog:docker": 1_610_612_736,        # 1.5 GB layer decompression
        "trufflehog:huggingface": 1_610_612_736,   # 1.5 GB model/LFS blobs
        "trufflehog:s3": 1_207_959_552,            # 1.125 GB object streaming
        "trufflehog:gcs": 1_207_959_552,           # 1.125 GB object streaming
        # 1.75 GB = clean writer + the dirty analyzer sibling it dispatches for
        # GuardDog deep analysis. The former 900 MB predated L1 deep analysis and
        # was smaller than the analyzer alone, so a deep L1 scan under-reserved.
        "supply_chain": 1_879_048_192,
        # CodeFix build sandbox (agent-driven). 2 GB matches CODEFIX_SANDBOX_MEM.
        # Not a scan, but it holds real RAM the ledger must ACCOUNT for (Phase 7).
        "codefix": 2_147_483_648,
        "_default": 2_147_483_648,        # 2 GB   unknown type: assume full-pipeline size
    },
    "agent_session_envelope_bytes": 512_000_000,
    "fireteam_member_envelope_bytes": 512_000_000,
    "plan_tool_slot_envelope_bytes": 400_000_000,
    "background_job_envelope_bytes": 512_000_000,
    "mcp_terminal_session_envelope_bytes": 64_000_000,
    "service_baseline_bytes": None,
}

_profile_cache: Optional[dict] = None


def _profile_path() -> str:
    p = os.environ.get("RESOURCE_PROFILE_PATH")
    if p and p.strip():
        return p.strip()
    # default: alongside this module
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "resource_profile.json")


def _default_profile_path() -> str:
    """The SHIPPED profile (tracked in git), one layer under the host-specific one.
    Absent next to this copy of the module is fine: _FALLBACK_PROFILE already
    carries the same numbers."""
    p = os.environ.get("RESOURCE_PROFILE_DEFAULT_PATH")
    if p and p.strip():
        return p.strip()
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "resource_profile.default.json")


def _read_profile_file(path: str) -> Optional[dict]:
    """Parse one profile layer; None if absent or unreadable (fail soft)."""
    try:
        with open(path, "r") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _merge_profile(base: dict, layer: dict) -> None:
    """Apply `layer` over `base` in place. Nested dicts update key-by-key, so a
    layer that measured only `full_recon` does not wipe the other scan types."""
    for k, v in layer.items():
        if isinstance(base.get(k), dict):
            # A section that is a MAP stays a map: a hand-edited scalar must not
            # replace (and so erase) the whole known-good section.
            if isinstance(v, dict):
                base[k].update(v)
        else:
            base[k] = v


def load_profile() -> dict:
    """Effective profile, lowest precedence first (cached):

      1. _FALLBACK_PROFILE           built-in, safe on any host, no file needed
      2. resource_profile.default.json  shipped in git; sane defaults for a fresh clone
      3. resource_profile.json       host-specific (gitignored, written by
                                     mem_calibrate.py); wins because it is MEASURED
                                     on this host

    Layers 2 and 3 are optional and fail soft, so a missing or corrupt file
    degrades to the layer below instead of breaking the governor.
    """
    global _profile_cache
    if _profile_cache is not None:
        return _profile_cache
    merged = json.loads(json.dumps(_FALLBACK_PROFILE))  # deep copy
    for path in (_default_profile_path(), _profile_path()):
        layer = _read_profile_file(path)
        if layer is not None:
            _merge_profile(merged, layer)
    _profile_cache = merged
    return merged


def reset_profile_cache() -> None:
    global _profile_cache
    _profile_cache = None


def _profile_map(key: str) -> dict:
    """A map-valued profile section, always a dict. A layer that put a scalar here
    is ignored rather than crashing every caller with AttributeError."""
    d = load_profile().get(key)
    return d if isinstance(d, dict) else {}


def _profile_bytes(value) -> Optional[int]:
    """Coerce one profile figure to a POSITIVE byte count, else None.

    Accepts plain numbers and Docker-style strings ('768m'), so a hand-edited
    profile behaves like the env knobs it mirrors. None/garbage/zero/negative all
    return None so the caller falls through to the next candidate: a negative or
    zero envelope would sail through admission and admit every scan, which is the
    one failure mode this module exists to prevent.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        n = int(value)
        return n if n > 0 else None
    if isinstance(value, str):
        n = parse_size(value)
        return n if n and n > 0 else None
    return None


def _first_bytes(*candidates) -> int:
    """First candidate that coerces to a positive byte count, else 0."""
    for c in candidates:
        val = _profile_bytes(c)
        if val is not None:
            return val
    return 0


def bytes_per_unit(family: str) -> int:
    return _first_bytes(_profile_map("bytes_per_unit").get(family),
                        _FALLBACK_PROFILE["bytes_per_unit"].get(family),
                        1024)


def tool_container_envelope(tool: str) -> int:
    d = _profile_map("tool_container_envelope_bytes")
    return _first_bytes(d.get(tool), d.get("_default"),
                        _FALLBACK_PROFILE["tool_container_envelope_bytes"]["_default"])


def scan_job_envelope(scan_type: str) -> int:
    """Expected peak RAM of one scan job of this type.

    `scan_type` may be a plain kind ("full_recon") or a tool-qualified key
    ("partial_recon:SupplyChainRecon"). A qualified key falls back to its BASE
    kind before _default, so a tool with no entry of its own keeps its family's
    cheap envelope instead of jumping to the 2 GB unknown-type figure.

    A qualified envelope is also FLOORED at its base kind, because a qualified
    job is definitionally its base kind PLUS extra work: a supply-chain partial
    is a partial recon that additionally spawns the analyzer. Without the floor,
    a calibration run that measured `partial_recon` higher than the shipped
    `partial_recon:SupplyChainRecon` would make the heavier job reserve LESS than
    the lighter one - an under-reservation that only appears on calibrated hosts.
    """
    d = _profile_map("scan_job_envelope_bytes")
    fallback_default = _FALLBACK_PROFILE["scan_job_envelope_bytes"]["_default"]
    if ":" not in scan_type:
        return _first_bytes(d.get(scan_type), d.get("_default"), fallback_default)

    base_kind = scan_type.split(":", 1)[0]
    base = _first_bytes(d.get(base_kind), d.get("_default"), fallback_default)
    qualified = _profile_bytes(d.get(scan_type))
    return max(qualified, base) if qualified else base


def container_cap(envelope_bytes: int) -> Optional[int]:
    """Hard per-container memory ceiling (bytes) derived from an envelope.

    `envelope x CONTAINER_CAP_HEADROOM`, clamped to PER_CONTAINER_MAX (so one
    container can never take the whole host and starve the DB) and floored at
    the envelope itself (so a NORMAL peak is never OOM-killed; the cap exists to
    contain a runaway, not to enforce the estimate).

    Lives here, not in the orchestrator, because THREE processes spawn capped
    containers: the orchestrator (Docker SDK), the recon container and the L1
    scan container (both shell out through the broker socket). When the clamp
    lived only in container_manager the other two hardcoded a literal instead,
    and the "identical hardening either way" contract quietly broke.

    Returns None (no limit) when the governor is disabled or the envelope is
    unusable — same fail-open contract as the rest of the module.
    """
    if not governor_enabled():
        return None
    if not envelope_bytes or envelope_bytes <= 0:
        return None
    headroom = _env_float("CONTAINER_CAP_HEADROOM", 1.5)
    if headroom < 1.0:
        headroom = 1.0
    cap = int(envelope_bytes * headroom)
    per_max = env_bytes("PER_CONTAINER_MAX", None)
    if per_max is None:
        mem = read_mem()
        per_max = int(mem[0] * 0.55) if mem else cap
    cap = min(cap, per_max)
    return max(512 * 1024 ** 2, envelope_bytes, cap)


def envelope(key: str) -> int:
    """Top-level scalar envelope (e.g. 'agent_session_envelope_bytes').

    A profile value of 0 (or any falsy/unparseable) is treated as missing so a
    bad measurement can't silently reserve 0 bytes: fall back to the built-in.
    """
    return _first_bytes(load_profile().get(key), _FALLBACK_PROFILE.get(key))


# ---------------------------------------------------------------------------
# Cap logging: emit a machine-detectable marker ONLY when a value was reduced,
# so the recon drawer can render it red. Prints to stdout (recon uses unbuffered
# stdout), so it rides the existing log pipeline.
# ---------------------------------------------------------------------------

RESOURCE_CAP_MARKER = "[RESOURCE-CAP]"


def _fmt_gb(nbytes: Optional[int]) -> str:
    if not nbytes:
        return "?"
    return f"{nbytes / (1024 ** 3):.1f}"


def log_cap(tool: str, param: str, env_value: int, effective: int, reason: str) -> None:
    """Print the RESOURCE-CAP marker line. Caller must only call when reduced."""
    mem = read_mem()
    avail = _fmt_gb(mem[1]) if mem else "?"
    print(
        f"{RESOURCE_CAP_MARKER} {tool} {param} {env_value} -> {effective} "
        f"(avail {avail} GB, {reason})",
        flush=True,
    )


def scaled_logged(value: int, floor: int, tool: str, param: str) -> int:
    """RATIO model + auto cap-log when it actually reduces `value`."""
    eff = scaled(value, floor)
    if eff < value:
        log_cap(tool, param, value, eff, "ratio")
    return eff


def budget_logged(env_cap: int, per_unit_bytes: int, tool: str, param: str,
                  floor: int = 1, fraction: Optional[float] = None) -> int:
    """BYTE-BUDGET model + auto cap-log when it actually reduces `env_cap`."""
    eff = scaled_cap(env_cap, per_unit_bytes, fraction, floor)
    if eff < env_cap:
        log_cap(tool, param, env_cap, eff, "byte-budget")
    return eff
