"""
Capture-proxy egress guard (plan §15.3, §20.5).

A new proxy is a new egress path, so it must not become an SSRF pivot into
RedAmon's internal network or a hard-guardrail bypass. This module is the pure,
testable core of that guard; the mitmdump addon calls it for every request (the
`request` hook) and again for every upstream dial (`server_connect`, which also
covers CONNECT tunnels and the DNS layer), and blocks anything it refuses.

Two layers:
  1. Internal denylist on the RESOLVED IP (not just the hostname) — RFC1918,
     loopback, link-local, CGNAT, reserved, multicast, unspecified, plus any
     explicitly configured RedAmon service IPs. Checking the resolved IP defeats
     DNS-rebinding (an in-scope name pointing at 169.254.169.254 / 10.x). That
     classification lives in the dual-shipped ``ip_denylist`` module, shared
     verbatim with the orchestrator's TruffleHog start guard so the two can
     never drift into disagreeing about what "internal" means.
  2. Static hard-guardrail on the hostname (.gov/.mil/.edu/.int + exact list),
     via an injected checker so the addon can wire in the bundled hard_guardrail
     module without this module depending on it.

Each block condition is individually toggleable via `EgressPolicy` (surfaced in
Global Settings > TrafficMind). Every toggle defaults to BLOCK, so the out-of-the-
box posture is identical to the original always-on guard; an operator can relax a
specific check (e.g. allow RFC1918 to reach an internal / lab target on a private
Docker network) without weakening the others. The explicit `extra_blocked` IP
denylist (RedAmon's own service IPs) is NOT toggleable; it stays enforced even
when the private-IP category is allowed, so unblocking private targets can never
turn the proxy into an SSRF pivot into RedAmon itself.

Pure stdlib. The addon is responsible for pinning the resolved IP it gets back
here for the actual upstream connection so a TOCTOU re-resolve can't slip past.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable, List, Mapping, Optional, Tuple

# The IP classification is shared verbatim with the orchestrator. In the proxy
# image the Dockerfile copies recon_orchestrator/ip_denylist.py to /app; outside
# it (tests, tooling) the repo-root package path resolves the same file. One
# file, two entry points — never a second hand-written denylist.
try:
    from ip_denylist import CGNAT, is_internal_ip, resolve_host
except ImportError:
    from recon_orchestrator.ip_denylist import CGNAT, is_internal_ip, resolve_host

__all__ = [
    "CGNAT", "DEFAULT_POLICY", "EgressPolicy", "POLICY_ENV", "check_egress",
    "is_internal_ip", "policy_from_dict", "policy_from_env", "policy_to_dict",
    "resolve_host",
]


@dataclass(frozen=True)
class EgressPolicy:
    """Which egress block conditions are enforced. Every field defaults to True
    (block), so `EgressPolicy()` reproduces the original always-on guard and all
    existing callers/tests keep their behavior. Set a field False to ALLOW that
    class of destination through the capture proxy.

    Security note: relaxing `block_private` (or loopback/link-local/…) opens the
    proxy to that address class. Keep RedAmon's own service IPs in the always-on
    `extra_blocked` denylist (env `CAPTURE_BLOCKED_IPS`) so they stay refused
    regardless of these toggles.
    """
    block_empty_host: bool = True       # refuse requests with no Host
    block_hard_guardrail: bool = True    # refuse .gov/.mil/.edu/.int + exact denylist
    fail_closed_on_error: bool = True    # on a guard-internal error, refuse (vs fail-open)
    block_unresolvable: bool = True      # refuse hosts that don't resolve / bad IDNA
    block_private: bool = True           # RFC1918 (10/8, 172.16/12, 192.168/16) + IPv6 ULA
    block_loopback: bool = True          # 127.0.0.0/8, ::1
    block_link_local: bool = True        # 169.254.0.0/16 (incl. cloud metadata), fe80::/10
    block_cgnat: bool = True             # 100.64.0.0/10 (carrier-grade NAT)
    block_reserved: bool = True          # IANA-reserved ranges
    block_multicast: bool = True         # 224.0.0.0/4, ff00::/8
    block_unspecified: bool = True       # 0.0.0.0, ::


DEFAULT_POLICY = EgressPolicy()

# camelCase config key (from CaptureProxyConfig) -> EgressPolicy field, and the
# env var the addon reads inside the proxy container. Kept in one place so the
# orchestrator (spawn env) and the addon (policy_from_env) never drift.
POLICY_ENV = {
    "block_empty_host":     "CAPTURE_EGRESS_BLOCK_EMPTY_HOST",
    "block_hard_guardrail": "CAPTURE_EGRESS_BLOCK_HARD_GUARDRAIL",
    "fail_closed_on_error": "CAPTURE_EGRESS_FAIL_CLOSED",
    "block_unresolvable":   "CAPTURE_EGRESS_BLOCK_UNRESOLVABLE",
    "block_private":        "CAPTURE_EGRESS_BLOCK_PRIVATE",
    "block_loopback":       "CAPTURE_EGRESS_BLOCK_LOOPBACK",
    "block_link_local":     "CAPTURE_EGRESS_BLOCK_LINK_LOCAL",
    "block_cgnat":          "CAPTURE_EGRESS_BLOCK_CGNAT",
    "block_reserved":       "CAPTURE_EGRESS_BLOCK_RESERVED",
    "block_multicast":      "CAPTURE_EGRESS_BLOCK_MULTICAST",
    "block_unspecified":    "CAPTURE_EGRESS_BLOCK_UNSPECIFIED",
}


def _as_bool(v, default: bool = True) -> bool:
    """Parse a truthy env/string value. Missing/empty -> default (block). Only an
    explicit false-like value (false/0/no/off) turns a check OFF, so a typo can
    never accidentally disable a guard."""
    if v is None:
        return default
    s = str(v).strip().lower()
    if s == "":
        return default
    return s not in ("false", "0", "no", "off")


def policy_from_env(env: Optional[Mapping[str, str]] = None) -> EgressPolicy:
    """Build an EgressPolicy from CAPTURE_EGRESS_* env vars (defaults = block)."""
    env = os.environ if env is None else env
    return EgressPolicy(**{
        field: _as_bool(env.get(var), True) for field, var in POLICY_ENV.items()
    })


def policy_from_dict(d: Optional[Mapping[str, object]]) -> EgressPolicy:
    """Build an EgressPolicy from a plain dict keyed by EgressPolicy field names
    (snake_case, e.g. ``{"block_private": false}``). This is the DB-sourced path:
    the config the operator saves in TrafficMind is materialised to a JSON file by
    the trusted control plane and read here — the proxy never touches the DB.

    Same fail-safe posture as `policy_from_env`: any missing/None/garbage field
    defaults to True (BLOCK), so a truncated or partially-written file can never
    silently relax the guard. Only an explicit false-like value turns a check off."""
    d = d or {}
    return EgressPolicy(**{
        field: _as_bool(d.get(field), True) for field in POLICY_ENV
    })


def policy_to_dict(policy: EgressPolicy) -> dict:
    """Serialise an EgressPolicy to the snake_case dict `policy_from_dict` reads.
    Used by the control plane when rendering the DB settings to the config file."""
    return {field: bool(getattr(policy, field)) for field in POLICY_ENV}


def check_egress(
    host: str,
    hard_blocked: Optional[Callable[[str], bool]] = None,
    extra_blocked_ips: Optional[List[str]] = None,
    policy: EgressPolicy = DEFAULT_POLICY,
) -> Tuple[bool, Optional[str], str]:
    """
    Decide whether the proxy may forward to `host` under `policy`.

    Returns (allowed, pinned_ip, reason). When allowed, `pinned_ip` is the first
    resolved address and the caller MUST connect to exactly that IP (no
    re-resolution) to avoid a rebinding TOCTOU. When blocked, `pinned_ip` is None.

    Structural invariant: `allowed` is True ONLY with a concrete pinned IP, so an
    empty/unresolvable host can never be forwarded regardless of the toggles (the
    toggles only control whether that refusal is labeled as an explicit policy
    block).
    """
    host = (host or "").strip().strip(".").lower()
    if not host:
        # No target to forward to; always refused, the toggle only relabels it.
        return (False, None, "empty host" if policy.block_empty_host else "empty-host-no-target")

    # Static hard-guardrail on the name (.gov/.mil/... + exact list).
    if hard_blocked is not None and policy.block_hard_guardrail:
        try:
            if hard_blocked(host):
                return (False, None, "hard-guardrail")
        except Exception:
            if policy.fail_closed_on_error:
                return (False, None, "hard-guardrail-error")  # fail closed
            # fail-open: skip the guardrail check and continue

    resolved = resolve_host(host)
    if not resolved:
        # No IP to pin; always refused, the toggle only relabels it.
        return (False, None, "unresolvable" if policy.block_unresolvable else "unresolvable-no-target")

    # Every resolved address must clear the policy; if ANY is refused we refuse
    # (a rebinding name that returns one public + one internal is hostile).
    for ip in resolved:
        if is_internal_ip(ip, extra_blocked_ips, policy):
            return (False, None, f"internal-ip:{ip}")

    return (True, resolved[0], "ok")
