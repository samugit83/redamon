"""What a project's settings change about a website mirror (R-URL-7, SEC-10).

The mirror reads ONLY the settings dict that fetch_agent_settings returned for
its own project (CF-5). The project_settings module-level readers serve the
running chat session; outside one they read whichever project loaded last,
and the loader that wraps them falls back to defaults (RoE off) when the web
app fails. Two mirrors of two projects can run at once, and each must apply
its own exclusions.

- RoE on: every host the project excludes is refused, on every hop.
- A seed inside the project's targets, with RoE on: refused outside the
  engagement dates or time window; ROE_GLOBAL_MAX_RPS caps the rate to each
  target host. With stealth mode: one request at a time, at most one a second.
- Any other public host keeps the mirror's own rules (decision Q12).
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Optional

from auth_profile import is_roe_excluded
from project_settings import fetch_agent_settings
from workspace_import import mirror
from workspace_import.errors import ImportFailure

# The charset rule the recon and orchestrator parsers apply to a batch root:
# drop rather than repair, so a hand-edited row cannot smuggle a target.
_DOMAIN_CHARSET = re.compile(r"^[a-z0-9.-]+$")
STEALTH_GAP_SEC = 1.0


async def load_settings(project_id: str) -> dict:
    """This project's settings, or settings_unavailable: never defaults."""
    webapp_url = os.environ.get("WEBAPP_URL", "http://webapp:3000")
    try:
        settings = await asyncio.to_thread(fetch_agent_settings, project_id, webapp_url,
                                           include_skill_overrides=False)
    except Exception:
        raise ImportFailure("settings_unavailable") from None
    if not isinstance(settings, dict):
        raise ImportFailure("settings_unavailable")
    return settings


def scope_domains(settings: dict) -> list[str]:
    """The project's target domains: the webapp's scope-group roots, the
    domain-batch roots, or TARGET_DOMAIN plus SUBDOMAIN_LIST. None in IP mode."""
    if settings.get("IP_MODE"):
        return []
    groups = settings.get("SCOPE_GROUPS")
    if settings.get("SCOPE_GROUPS_SOURCE") == "webapp" and isinstance(groups, list):
        roots = [str(g.get("scan_root") or "").strip().lower() for g in groups if isinstance(g, dict)]
        return [r for r in roots if r]
    candidates: list[str] = []
    if settings.get("DOMAIN_BATCH_MODE"):
        batch = settings.get("DOMAIN_BATCH_GROUPS") or []
        candidates = [str(e.get("rootDomain") or "") for e in batch if isinstance(e, dict)] if isinstance(batch, list) else []
    else:
        candidates = [str(settings.get("TARGET_DOMAIN") or "")]
        subs = settings.get("SUBDOMAIN_LIST") or []
        candidates += [str(s) for s in subs] if isinstance(subs, list) else []
    out: list[str] = []
    for raw in candidates:
        d = raw.strip().lower().rstrip(".")
        if d and "." in d and _DOMAIN_CHARSET.match(d) and ".." not in d and d not in out:
            out.append(d)
    return out


def _target_networks(settings: dict) -> list:
    nets = []
    for raw in settings.get("TARGET_IPS") or []:
        try:
            nets.append(ipaddress.ip_network(str(raw).strip(), strict=False))
        except ValueError:
            continue
    return nets


def scope_check(settings: dict) -> Callable[[str], bool]:
    """host -> is it one of the project's targets (a scope domain or one of
    its subdomains; in IP mode, a literal address within TARGET_IPS)."""
    if settings.get("IP_MODE"):
        nets = _target_networks(settings)

        def in_ip_scope(host: str) -> bool:
            try:
                address = ipaddress.ip_address(host.strip("[]"))
            except ValueError:
                return False
            return any(address in n for n in nets)
        return in_ip_scope

    domains = scope_domains(settings)

    def in_domain_scope(host: str) -> bool:
        host = (host or "").lower().rstrip(".")
        return any(host == d or host.endswith("." + d) for d in domains)
    return in_domain_scope


@dataclass(frozen=True)
class MirrorRules:
    roe_excluded: Optional[Callable[[str], bool]]
    concurrency: int
    gap_for: Callable[[str], float]
    seed_in_scope: bool
    # host -> may a request go there now. A copy can outlast the engagement
    # window it started in, so the window is judged on every target request.
    request_allowed: Callable[[str], bool] = lambda _host: True


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def rules_for(seed_url: str, settings: dict, *, now_utc: datetime,
              clock: Callable[[], datetime] = _utc_now) -> MirrorRules:
    """The rules a mirror of `seed_url` runs under; raises roe_outside_window."""
    roe_on = bool(settings.get("ROE_ENABLED"))
    excluded = list(settings.get("ROE_EXCLUDED_HOSTS") or [])
    roe_excluded = (lambda host: is_roe_excluded(host, excluded)) if roe_on else None

    in_scope = scope_check(settings)
    seed_in_scope = in_scope((urllib.parse.urlsplit(seed_url).hostname or "").lower())
    concurrency = mirror.CONCURRENCY
    target_gap = mirror.SAME_HOST_GAP_SEC
    window_open: Optional[Callable[[], bool]] = None
    # The window, the rate cap and stealth's pace hold for every request to a
    # target, also an asset a copy of some other site links to; only refusing
    # the whole copy, and stealth's one-at-a-time, need the seed to be one.
    if roe_on:
        from orchestrator_helpers.nodes.initialize_node import _roe_timing_warnings
        if seed_in_scope and _roe_timing_warnings(now_utc, get=settings.get):
            raise ImportFailure("roe_outside_window")

        def window_open() -> bool:
            return not _roe_timing_warnings(clock(), get=settings.get)
        try:
            rps = float(settings.get("ROE_GLOBAL_MAX_RPS") or 0)
        except (TypeError, ValueError):
            rps = 0.0
        if rps > 0:
            target_gap = max(target_gap, 1.0 / rps)
    if settings.get("STEALTH_MODE"):
        target_gap = max(target_gap, STEALTH_GAP_SEC)
        if seed_in_scope:
            concurrency = 1

    def gap_for(host: str) -> float:
        return target_gap if in_scope(host) else mirror.SAME_HOST_GAP_SEC

    def request_allowed(host: str) -> bool:
        return window_open is None or not in_scope(host) or window_open()
    return MirrorRules(roe_excluded=roe_excluded, concurrency=concurrency, gap_for=gap_for,
                       seed_in_scope=seed_in_scope, request_allowed=request_allowed)
