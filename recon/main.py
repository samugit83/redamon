#!/usr/bin/env python3
"""
RedAmon - Main Reconnaissance Controller
=========================================
Orchestrates all OSINT reconnaissance modules:
1. WHOIS lookup (integrated into domain recon JSON)
2. Subdomain discovery & DNS resolution
3. Port scanning (fast, lightweight)
4. HTTP probing & technology detection
5. Resource enumeration (endpoint discovery & classification)
6. Vulnerability scanning + MITRE CWE/CAPEC enrichment

Pipeline: domain_discovery -> port_scan -> http_probe -> resource_enum -> vuln_scan

Note: vuln_scan automatically includes MITRE CWE/CAPEC enrichment for all CVEs.

Run this file to execute the full recon pipeline.
"""

import sys
import json
import copy
import re
from pathlib import Path
from datetime import datetime
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add project root to path for imports (needed for graph_db, utils modules)
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Before the settings load below: a stop that arrives while the webapp answers
# slowly must still run the end-of-run steps (recon/helpers/shutdown.py). Only
# as the container's command, never when a test or a module imports this file.
from recon.helpers import shutdown as _shutdown
if __name__ == "__main__":
    _shutdown.install()

from recon.project_settings import get_settings, log_scope

# Load settings from the webapp API (PROJECT_ID/WEBAPP_API_URL set) or the
# defaults (CLI mode). A scope recon refuses raises ScopeRefused here, before
# any tool starts.
# get_settings() now applies stealth + AI cascade overrides internally so every
# downstream consumer (full pipeline + every partial recon module) gets them.
_settings = get_settings()

# HTTP traffic capture (Phase 1): configure capture-proxy routing once, up front,
# so every recon HTTP tool that supports it routes through the proxy when the
# per-project gate is on and the proxy is reachable (else runs direct, §20.1).
try:
    from helpers.proxy_routing import configure as _configure_capture_routing
    _configure_capture_routing(_settings)
except Exception as _cap_cfg_err:  # noqa: BLE001 — never block a scan on this
    print(f"[!][capture] routing not configured: {_cap_cfg_err}")

# Extract commonly used settings as module-level variables for compatibility
TARGET_DOMAIN = _settings['TARGET_DOMAIN']
SUBDOMAIN_LIST = _settings['SUBDOMAIN_LIST']
USE_BRUTEFORCE_FOR_SUBDOMAINS = _settings['USE_BRUTEFORCE_FOR_SUBDOMAINS']
SCAN_MODULES = _settings['SCAN_MODULES']
UPDATE_GRAPH_DB = _settings['UPDATE_GRAPH_DB']
# Every graph write below is wrapped in try/except (a scan must not die because
# Neo4j blipped), which also means a BROKEN /app/graph_db bind mount degrades
# silently: the pipeline finishes "green" having written nothing. Probe once, up
# front, so that condition is visible in the log instead of inferred from an
# empty graph. Non-fatal by design - the recon results themselves are still
# produced and written to disk. See recon/graph_db_preflight.py (issue #169).
if UPDATE_GRAPH_DB:
    from recon.graph_db_preflight import warn_if_graph_db_unusable
    warn_if_graph_db_unusable("Pipeline")
USER_ID = _settings['USER_ID']
PROJECT_ID = _settings['PROJECT_ID']
VERIFY_DOMAIN_OWNERSHIP = _settings['VERIFY_DOMAIN_OWNERSHIP']
OWNERSHIP_TOKEN = _settings['OWNERSHIP_TOKEN']
OWNERSHIP_TXT_PREFIX = _settings['OWNERSHIP_TXT_PREFIX']
IP_MODE = _settings['IP_MODE']
TARGET_IPS = _settings['TARGET_IPS']

# Import recon modules
from recon.main_recon_modules.whois_recon import whois_lookup
from recon.main_recon_modules.domain_recon import discover_subdomains, verify_domain_ownership, reverse_dns_lookup
from recon.main_recon_modules.port_scan import run_port_scan, run_port_scan_isolated
from recon.main_recon_modules.masscan_scan import run_masscan_scan, run_masscan_scan_isolated
from recon.main_recon_modules.http_probe import run_http_probe
from recon.main_recon_modules.resource_enum import run_resource_enum
from recon.main_recon_modules.ai_surface_recon import run_ai_surface_recon
from recon.main_recon_modules.vuln_scan import run_vuln_scan
from recon.main_recon_modules.add_mitre import run_mitre_enrichment
from recon.helpers.isolated_result import TopLevelKeys

# Output directory
OUTPUT_DIR = Path(__file__).parent / "output"

# ---------------------------------------------------------------------------
# Domain batch helpers
# ---------------------------------------------------------------------------
from helpers.output_paths import (  # noqa: E402 - after the sys.path setup above
    recon_output_file,
    clear_batch_outputs,
    merge_batch_outputs,
    initialize_batch_canonical,
)

DOMAIN_BATCH_MODE = _settings.get('DOMAIN_BATCH_MODE', False)


def _batch_groups() -> list:
    """The batch's scope groups (SCOPE_GROUPS), in run order, or [] outside batch mode.

    Read through a function rather than a module constant so a test can point the
    settings dict at a different project without re-importing this module.
    """
    if not _settings.get('DOMAIN_BATCH_MODE', False):
        return []
    return settings_scope_groups(_settings)


# The batch roots the graph writers may attach a host to. Fixed once per batch
# run by run_domain_batch; empty outside batch mode.
_BATCH_ATTACH_ROOTS: list = []


def _ownership_names(group: dict) -> list:
    """Where the ownership TXT record may live (§4.8): the scan root, then the
    registrable domain when it differs."""
    names = [group['scanRoot']]
    org = group.get('orgDomain')
    if org and org != group['scanRoot']:
        names.append(org)
    return names


def _group_ownership(group: dict) -> dict:
    """Is this group's ownership proven? ``{verified, record_names, expected_value, error}``.

    Proven when either name holds the token. Each name's definite answer (the
    record, no record, a wrong value) is cached for the run, so a batch asks
    once per name however many groups share it. A resolver failure is never
    cached and never read as "no record": the group fails closed with the
    resolver's message, and the second name is not tried.
    """
    from recon.helpers import circuit_breaker
    cache = circuit_breaker.run_cache('ownership_txt')
    names = _ownership_names(group)
    record_names, errors, expected = [], [], ''
    for name in names:
        hit, res = cache.get(name)
        if not hit:
            res = verify_domain_ownership(name, OWNERSHIP_TOKEN, OWNERSHIP_TXT_PREFIX)
            if not res.get('resolver_failed'):
                cache.put(name, res)
        record_names.append(res.get('record_name') or name)
        expected = res.get('expected_value') or expected
        if res.get('verified'):
            if name != group['scanRoot']:
                from recon.helpers.org_work import note_ownership_proven
                note_ownership_proven(name)
            return {'verified': True, 'record_names': record_names,
                    'expected_value': expected, 'error': None}
        if res.get('resolver_failed'):
            return {'verified': False, 'record_names': record_names,
                    'expected_value': expected, 'error': res.get('error')}
        errors.append(res.get('error') or 'no matching record')
    return {'verified': False,
            'record_names': [f"{OWNERSHIP_TXT_PREFIX}.{n}" for n in names],
            'expected_value': expected, 'error': '; '.join(e for e in errors if e)}


def _roe_refuses_root(root: str) -> bool:
    excluded = _settings.get('ROE_EXCLUDED_HOSTS') if _settings.get('ROE_ENABLED') else None
    return bool(excluded) and _is_roe_excluded(root, excluded)


def _eligible_batch_roots(groups: list) -> list:
    """The batch's scan roots its groups will actually scan, in order.

    run_domain_group refuses a root that is RoE-excluded or fails ownership
    verification. A host found under such a root must stay an informational
    ExternalDomain, not become an in-scope Subdomain, so the root is left out.
    The checks are the group's own (RoE first, then the cached ownership
    answer), so each name is verified once per run.
    """
    roots = []
    for group in groups or []:
        root = group.get('scanRoot') if isinstance(group, dict) else ''
        if not root or root in roots or _roe_refuses_root(root):
            continue
        if VERIFY_DOMAIN_OWNERSHIP:
            try:
                verified = _group_ownership(group)['verified']
            except Exception:  # noqa: BLE001 - an unanswered check is a failed check
                verified = False
            if not verified:
                continue
        roots.append(root)
    return roots


def _root_refusal(group: dict) -> list:
    """Why run_domain_group would refuse this group's root, as the lines it
    prints; empty when the root may be scanned. The same checks in the same
    order as there and in _eligible_batch_roots: RoE first (an excluded root
    gets no TXT lookup), then the cached ownership answer. A check that raises
    refuses."""
    root = group.get('scanRoot') if isinstance(group, dict) else ''
    if not root:
        return ["[!][Pipeline] A scope group has no scan root"]
    if _roe_refuses_root(root):
        return [f"[RoE] BLOCKED: Root domain '{root}' is in ROE excluded hosts list."]
    if not VERIFY_DOMAIN_OWNERSHIP:
        return []
    try:
        ownership = _group_ownership(group)
    except Exception as e:  # noqa: BLE001 - an unanswered check is a failed check
        return [f"[!][Pipeline] Domain ownership verification failed for {root}: "
                f"the check raised {type(e).__name__}"]
    if ownership['verified']:
        return []
    lines = [f"[!][Pipeline] Domain ownership verification failed for {root}"]
    if ownership.get('error'):
        lines.append(f"[!][Pipeline] {ownership['error']}")
    lines.append(f"[!][Pipeline] Add TXT {' OR '.join(ownership['record_names'])} → "
                 f"\"{ownership['expected_value']}\"")
    return lines


def _refuse_before_clear(groups: list) -> bool:
    """True when no scan root of this run may be scanned. Asked BEFORE the
    one-time graph clear (R-5).

    run_domain_group refuses a root the RoE excludes or whose ownership does
    not verify, but it runs after the clear: a refused run deleted the
    project's assets and rebuilt none. The ownership answers given here are
    cached for the run, so the group's own check does not ask again. A batch
    with one eligible root clears and runs; its refused groups still refuse
    in the loop.
    """
    # A latch left open would refuse the TXT lookup as "resolver down" (12.10).
    from recon.main_recon_modules.domain_recon import resolver_breaker
    resolver_breaker.recheck()
    refusals = []
    for group in groups:
        lines = _root_refusal(group)
        if not lines:
            return False
        refusals.extend(lines)
    print("\n[!][Pipeline] SCAN ABORTED: no scan root passed the Rules of Engagement "
          "and ownership checks")
    for line in refusals:
        print(line)
    print("[!][Pipeline] Nothing was cleared: the project's graph is left as it was")
    return True


def _stamp_project_roots(recon_data: dict) -> dict:
    """Carry the project's scope groups and roots (§4.10 output contract).

    The pipeline scans one group at a time, so recon_data["domain"] is the group
    root and the scan stays inside the group. The writers, though, must attach a
    host a scan found under ANOTHER batch root to that root's Domain, not record
    it as an ExternalDomain -- the same fix the partial path already has. They
    read this through attach_roots(); a single-domain project carries its one
    root, which is what attach_roots() falls back to anyway. It is deliberately
    NOT "domains", which would widen the per-group scan scope.
    """
    if not isinstance(recon_data, dict):
        return recon_data
    groups = settings_scope_groups(_settings)
    recon_data["scope_groups"] = [
        {"scan_root": g["scanRoot"], "org_domain": g["orgDomain"], "mode": g["mode"],
         "include_root": bool(g["includeRoot"]), "exact_hosts": list(g["exactHosts"])}
        for g in groups]
    if _batch_groups():
        if _BATCH_ATTACH_ROOTS:
            recon_data["all_project_roots"] = list(_BATCH_ATTACH_ROOTS)
    elif groups:
        recon_data["all_project_roots"] = [g["scanRoot"] for g in groups]
    return recon_data


# ---------------------------------------------------------------------------
# Background Graph DB update helper
# ---------------------------------------------------------------------------
# Serialized via max_workers=1 so Neo4j never gets concurrent writes,
# but the main pipeline thread is not blocked.
# Re-created per pipeline run via _graph_reset() to be safe across calls.
_graph_executor = None
_graph_futures = []


def _graph_reset():
    """Create a fresh background executor for a new pipeline run.

    A writer still live from an earlier group (one that raised before its
    _graph_wait_all) is drained first: replacing it would run two writers at
    once, against the one-writer rule.
    """
    global _graph_executor, _graph_futures
    if _graph_executor is not None:
        _graph_wait_all()
    _graph_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="graph-db")
    _graph_futures = []


#: The background writers that write recon findings, each with the
#: `_PHASE_FINDING_SOURCES` phase whose sources it writes. The findings a failed
#: write did not MERGE keep last run's `updated_at`, so the prune would read
#: them as gone: a writer that raises, reports an item error, finds Neo4j
#: unreachable or is never queued notes those sources degraded instead, which
#: wins over whatever the modules recorded as checked (R-20, D1).
#: Left out on purpose: writers of assets only (domain discovery, IP recon,
#: ports, httpx, tlsx, IP attribution, Uncover, external domains, urlscan
#: discovery and enrichment, Censys, FOFA, OTX, VirusTotal, ZoomEye, wildcard
#: zones) and supply chain, whose findings the recon prune never touches.
_WRITER_SOURCES = {
    'update_graph_from_vuln_scan': 'vuln_scan',
    'update_graph_from_nmap': 'nmap',
    'update_graph_from_resource_enum': 'resource_enum',
    'update_graph_from_ai_surface_recon': 'ai_surface_recon',
    'update_graph_from_js_recon': 'js_recon',
    'update_graph_from_serialized_scan': 'serialized_scan',
    'update_graph_from_graphql_scan': 'graphql_scan',
    'update_graph_from_subdomain_takeover': 'subdomain_takeover',
    'update_graph_from_vhost_sni': 'vhost_sni',
    'update_graph_from_cache_scan': 'cache_scan',
    'update_graph_from_origin_discovery': 'origin_discovery',
    'update_graph_from_route_exposure': 'route_exposure',
    'update_graph_from_urlscan_findings': 'urlscan',
    'update_graph_from_urlscan_takeover': 'urlscan',
    'update_graph_from_shodan': 'shodan',
    'update_graph_from_netlas': 'netlas',
    'update_graph_from_criminalip': 'criminalip',
}

#: Writer errors that cost no finding: nothing to write ("No vuln_scan data
#: found"), and the housekeeping passes that run after the findings are
#: written (BaseURL re-links, Domain counters, the OpenAPI status, coverage
#: stamps). Any other item error degrades the writer's sources.
_HOUSEKEEPING_WRITE_ERROR = re.compile(
    r"No \w+ (?:data|results)\b|(?:Orphan|Apex) BaseURL cleanup failed"
    r"|Domain update failed|OpenAPI source status update failed|[\w ]+ coverage stamp failed")


class _WriteResult(tuple):
    """``(writer, stats, failure)`` of one background write; ``failure`` is
    empty for a clean one."""

    def __new__(cls, writer: str, stats, failure: str):
        return super().__new__(cls, (writer, stats, failure))


def _writer_sources(update_method_name: str) -> set:
    """The finding sources a background writer writes; empty for an asset writer."""
    return set(_PHASE_FINDING_SOURCES.get(_WRITER_SOURCES.get(update_method_name), ()))


def _finding_write_errors(stats) -> str:
    errors = stats.get("errors") if isinstance(stats, dict) else None
    lost = [e for e in errors or [] if not _HOUSEKEEPING_WRITE_ERROR.match(str(e))]
    return f"{len(lost)} item error(s)" if lost else ""


def _note_writer_failed(update_method_name: str, why: str) -> None:
    """Keep this run's findings of a writer whose write failed. Never raises."""
    phase = _WRITER_SOURCES.get(update_method_name)
    if not phase:
        return
    sources = ", ".join(sorted(_writer_sources(update_method_name)))
    print(f"[!][graph-db] {update_method_name}: {why} - the findings of {sources} "
          f"are kept this run")
    _note_phase_error(phase, reason=f"graph write failed ({update_method_name})")


def _graph_update_bg(update_method_name: str, combined_result: dict,
                     user_id: str, project_id: str):
    """Submit a graph DB update to the background thread.

    Takes a deep-copy snapshot of combined_result so the main thread can
    keep mutating it safely. Once a stop is requested nothing new is queued:
    the stopper is landing what is already queued within its deadline.
    A graph error never fails the scan; a write of findings that fails, or
    never lands, keeps their sources out of this run's prune (R-20).
    """
    if not UPDATE_GRAPH_DB:
        return
    if _graph_executor is None:
        # The group's writer is already drained: this write would be dropped.
        _note_writer_failed(update_method_name, "not queued, the graph writer was closed")
        return
    if _shutdown.stop_requested():
        print(f"[!][graph-db] Stop requested: {update_method_name} not queued")
        return
    snapshot = copy.deepcopy(combined_result)

    def _do_update():
        stats, failure = None, ""
        try:
            from graph_db import Neo4jClient
            with Neo4jClient() as client:
                if client.verify_connection():
                    method = getattr(client, update_method_name)
                    stats = method(snapshot, user_id, project_id)
                    failure = _finding_write_errors(stats)
                    print(f"[graph-db] {update_method_name} complete")
                else:
                    failure = "Neo4j not reachable"
                    print(f"[!][graph-db] Neo4j not reachable — skipped {update_method_name}")
        except Exception as e:
            failure = type(e).__name__
            print(f"[!][graph-db] Background graph update ({update_method_name}) failed: {e}")
        if failure:
            _note_writer_failed(update_method_name, failure)
        return _WriteResult(update_method_name, stats, failure)

    future = _graph_executor.submit(_do_update)
    _graph_futures.append(future)


def _stamp_wildcard_zones(combined_result: dict) -> None:
    """Stamp every zone the wildcard control checked this group. The domain
    writer already stamped discovery's zones; the SAN, tlsx, js_recon and
    uncover merges can check new ones later in the run."""
    if (combined_result or {}).get("wildcard_zones"):
        _graph_update_bg("update_graph_wildcard_zones", combined_result, USER_ID, PROJECT_ID)


def _graph_wait_all():
    """Wait for every queued graph DB update to finish, then tear down the executor.

    Returns ``[(writer, stats, failure), ...]``, ``failure`` empty for a clean
    write. A failed one has already noted its finding sources degraded.
    """
    global _graph_executor
    if _graph_executor is None:
        return []
    _graph_executor.shutdown(wait=True)
    results = []
    for f in _graph_futures:
        exc = f.exception()
        if exc:
            print(f"[!][graph-db] Graph update error: {exc}")
        elif isinstance(f.result(), _WriteResult):
            results.append(f.result())
    failed = [writer for writer, _stats, failure in results if failure]
    if failed:
        print(f"[!][graph-db] {len(failed)} graph write(s) failed: {', '.join(failed)}")
    _graph_executor = None
    return results


def _drain_graph_writes(deadline: float) -> None:
    """The stopper's drain: let the queued graph writes land, until `deadline`
    (time.monotonic). What is still running then is cut by the exit."""
    import time
    from concurrent.futures import wait
    pending = [f for f in list(_graph_futures) if not f.done()]
    if not pending:
        return
    print(f"[*][graph-db] Stop: landing {len(pending)} queued graph write(s)", flush=True)
    _done, not_done = wait(pending, timeout=max(0.0, deadline - time.monotonic()))
    if not_done:
        print(f"[!][graph-db] Stop: {len(not_done)} queued graph write(s) did not land "
              f"before the deadline", flush=True)


# RoE matching and the time window live in recon.helpers.roe_scope so the
# modules can enforce them without importing this file (which would re-run its
# top level as a second module). Re-exported so the old `main` names resolve,
# and _run_pipeline calls the module-global name, which tests monkeypatch.
from recon.helpers.roe_scope import _is_roe_excluded, _filter_roe_excluded, _check_roe_time_window




# The aggregation lives in a helper partial recon can import; re-exported here.
from recon.helpers.external_domains import (  # noqa: E402
    _aggregate_external_domains, _js_recon_external_domains, _merge_external_domain,
)


def should_skip_active_scans(recon_data: dict) -> tuple:
    """
    Check if active scanning modules (resource_enum, vuln_scan) should be skipped.
    
    These modules require live targets to work with. If http_probe found no live URLs,
    there's nothing to crawl or scan.
    
    Args:
        recon_data: Current reconnaissance data
        
    Returns:
        Tuple of (should_skip: bool, reason: str)
    """
    http_probe_data = recon_data.get('http_probe', {})
    http_summary = http_probe_data.get('summary', {})
    
    live_urls = http_summary.get('live_urls', 0)
    total_hosts = http_summary.get('total_hosts', 0)
    
    # Check if http_probe ran but found nothing
    if 'http_probe' in recon_data:
        if live_urls == 0 and total_hosts == 0:
            # Also check by_url to be sure
            by_url = http_probe_data.get('by_url', {})
            if len(by_url) == 0:
                return True, "No live URLs found by http_probe - nothing to scan"
    
    return False, ""


# The per-group scope rules live in a module with no import side effects, so
# partial recon can use them without loading this file's settings.
from recon.helpers.batch_groups import (  # noqa: E402
    _PREFIX_CHARSET,
    group_discovery_enabled,
    parse_target,
    settings_scope_groups,
    target_info_from_group,
)


def _gate_injected_hosts(extra_hosts, known: list, target_info: dict, root_domain: str,
                         settings: dict, wildcard_filter=None) -> dict:
    """F1's gates on names another source found (urlscan), before DNS: the
    gates merge_discovered_hostnames applies to late names. An EXACT group
    takes none; an ENUMERATE group takes strict subdomains of its scan root
    (the root itself is Include Root's decision). Then the RoE, the host-name
    syntax and the wildcard-DNS check. Returns {host: source}."""
    if (target_info.get("mode") or "enumerate") == "exact" or not extra_hosts:
        return {}
    from recon.helpers.target_helpers import _is_valid_injected_hostname
    root = (root_domain or "").strip().lower()
    have = {str(h).lower() for h in known}
    picked: dict = {}
    for item in extra_hosts:
        host, source = (item if isinstance(item, (tuple, list)) else (item, "urlscan"))[:2]
        h = str(host or "").strip().strip(".").lower()
        if (h and h not in have and h not in picked and root and h.endswith("." + root)
                and _is_valid_injected_hostname(h)):
            picked[h] = source
    kept = _filter_roe_excluded(sorted(picked), settings, label="urlscan host")
    if kept and wildcard_filter is None:
        from recon.helpers import wildcard_control

        def wildcard_filter(names):
            return wildcard_control.filter_late_names(names, [root], settings, label="urlscan").kept
    kept = wildcard_filter(kept) if kept else []
    return {h: picked[h] for h in kept}


def merge_group_hosts(recon_result, target_info: dict, root_domain: str,
                      settings: dict, dns_enabled: bool = True,
                      resolver=None, extra_hosts=None, wildcard_filter=None) -> dict:
    """Merge what discovery found with the hosts the operator named.

    Returns ``{subdomains, dns, status_map, include_root}``.

    Three things have to be true at once and each has bitten:

    - The apex is scanned only when "Include Root Domain" asked for it, and
      ``include_root`` must ALWAYS be stamped into metadata: an absent key reads
      as True downstream (target_helpers), which scans the apex the operator
      deliberately left out.
    - A wildcard group may also list explicit hosts. Enumeration is not
      guaranteed to surface them, so they are seeded - nothing the operator
      pasted may be silently dropped. (A single-domain run arrives with
      ``full_subdomains`` empty, so the seeding is a no-op there.)
    - Anything seeded was never part of discovery's own resolution pass, so it
      carries no DNS and every later phase skips it as unresolved. Resolving
      only when discovery returned NOTHING would cover the total-failure case
      while silently dropping exactly the host seeding exists to protect: the
      sibling enumeration happened to miss. Note the total-failure case still
      needs covering, because discover_subdomains() builds its result dict
      unconditionally - every-source-failed returns a TRUTHY dict with an empty
      subdomain list.

    ``extra_hosts`` (F1) are names another source saw, as (host, source)
    pairs: urlscan's recent ones. They pass the late-name gates, get resolved
    with the rest, and are kept only with an address the scanner may probe;
    the DNS entry keeps their `source`.

    Split out of run_domain_recon so it can be tested as the thing the pipeline
    calls; inlined, it was only reachable through the whole 750-line phase.
    """
    from recon.main_recon_modules.ip_filter import is_never_scannable_ip, is_non_routable_ip

    discovered_subs = []
    if recon_result:
        discovered_subs = list(recon_result.get("subdomains") or [])
        discovered_subs = _filter_roe_excluded(
            discovered_subs, settings, label="discovered subdomain")

    include_root = bool(target_info.get("include_root_domain", False))
    if include_root and root_domain not in discovered_subs:
        discovered_subs.insert(0, root_domain)
    elif not include_root and root_domain in discovered_subs:
        # Discovery can list the root itself (a SAN, a passive source); with
        # Root off it is not a target, so it never reaches a scan.
        discovered_subs.remove(root_domain)
    roe_excluded = settings.get('ROE_EXCLUDED_HOSTS') if settings.get('ROE_ENABLED') else None
    for host in target_info.get("full_subdomains") or []:
        if host not in discovered_subs and not (roe_excluded and _is_roe_excluded(host, roe_excluded)):
            discovered_subs.append(host)
    injected = _gate_injected_hosts(extra_hosts, discovered_subs, target_info, root_domain,
                                    settings, wildcard_filter) if dns_enabled else {}
    discovered_subs.extend(injected)

    discovered_dns = dict((recon_result or {}).get("dns") or {})
    resolved = dict(discovered_dns.get("subdomains") or {})
    missing = [h for h in discovered_subs if h != root_domain and h not in resolved]
    need_root = include_root and not (discovered_dns.get("domain") or {})
    if dns_enabled and (missing or need_root):
        print(f"[*][DNS] Resolving {len(missing)} host(s) discovery did not resolve"
              f"{' (plus the root domain)' if need_root else ''}")
        if resolver is None:
            from recon.main_recon_modules.domain_recon import resolve_all_dns as resolver
        dns_result = resolver(
            root_domain, missing,
            max_workers=settings.get('DNS_MAX_WORKERS', 50),
            record_parallelism=settings.get('DNS_RECORD_PARALLELISM', True),
            settings=settings) or {}
        resolved.update(dns_result.get("subdomains") or {})
        discovered_dns["subdomains"] = resolved
        if need_root:
            discovered_dns["domain"] = dns_result.get("domain") or {}
    discovered_dns.setdefault("subdomains", resolved)
    if not include_root:
        # Resolved for the resolver canary, never kept: every phase that reads
        # dns.domain (or the root's own subdomains entry, which discovery's
        # fan-in can add) would make the root's addresses targets.
        discovered_dns["domain"] = {}
        resolved.pop(root_domain, None)
        discovered_dns["subdomains"] = resolved
    discovered_dns.setdefault("domain", {})

    # SSRF / scope-escape guard on what ENUMERATION dragged in.
    #
    # A discovered name is the domain owner's DNS, not ours: `localhost.<domain>
    # -> 127.0.0.1` is a real and common record (vulnweb.com publishes one), and
    # `x.<domain> -> 169.254.169.254` is cloud metadata. Neither is a host this
    # scanner may probe, and no downstream phase re-checks - port_scan and
    # http_probe filter nothing, so whatever lands here is what gets scanned.
    #
    # target_helpers has this guard already, but only for SAN-derived names, and
    # it re-resolves via getaddrinfo. Here DNS has already run, so the answer is
    # in `resolved` and costs nothing.
    #
    # Operator-supplied hosts are NOT filtered: if someone typed it, scanning it
    # is their decision. This drops only what discovery volunteered.
    listed = set(target_info.get("full_subdomains") or [])
    kept, dropped = [], []
    for host in discovered_subs:
        if host == root_domain or host in listed:
            kept.append(host)
            continue
        addrs = ((resolved.get(host) or {}).get("ips") or {})
        flat = list(addrs.get("ipv4") or []) + list(addrs.get("ipv6") or [])
        if any(is_never_scannable_ip(a) for a in flat):
            dropped.append((host, flat))
        else:
            kept.append(host)
    if dropped:
        for host, flat in dropped:
            print(f"[!][Scope] Dropped discovered host {host} -> {flat}: "
                  f"loopback/link-local/multicast is never a scan target")
        discovered_subs = kept
        for host, _ in dropped:
            resolved.pop(host, None)
        discovered_dns["subdomains"] = resolved

    # An injected name stays only with an address, and never a private one:
    # history names a host, it does not vouch for where it points now.
    for host, source in injected.items():
        entry = resolved.get(host) or {}
        addrs = list((entry.get("ips") or {}).get("ipv4") or []) + list((entry.get("ips") or {}).get("ipv6") or [])
        if not addrs or any(is_non_routable_ip(a) for a in addrs):
            if host in discovered_subs:
                discovered_subs.remove(host)
            resolved.pop(host, None)
        else:
            entry["source"] = source
    if injected:
        kept_injected = [h for h in injected if h in discovered_subs]
        print(f"[+][URLScan] {len(kept_injected)} of {len(injected)} urlscan name(s) joined the scan")
        discovered_dns["subdomains"] = resolved

    status_map = dict((recon_result or {}).get("subdomain_status_map") or {})
    if roe_excluded:
        # The list was filtered above, but discovery's DNS map (and a later
        # resolve) still hold the excluded hosts with their IPs, and the port
        # scan, nuclei, takeover and the security checks read that map.
        merged = {"subdomains": discovered_subs, "dns": discovered_dns,
                  "subdomain_status_map": status_map}
        _drop_roe_excluded_subdomains(merged, roe_excluded)
        discovered_subs = merged["subdomains"]
    return {
        "subdomains": discovered_subs,
        "dns": discovered_dns,
        "status_map": {s: st for s, st in status_map.items()
                       if s in set(discovered_subs)},
        "include_root": include_root,
        "wildcard_zones": dict((recon_result or {}).get("wildcard_zones") or {}),
        "injected": [h for h in injected if h in discovered_subs],
    }


def _org_whois(org: str) -> dict:
    """WHOIS of the group's registrable domain, once per run (§4.9).

    python-whois reduces a name to its registrable domain anyway, so asking for
    the org changes no answer; the run cache stops a batch asking once per
    group, and the org's later groups get a copy for their own graph write.
    """
    from recon.helpers.org_work import once_per_org
    value, _ = once_per_org(
        "whois", org, lambda o: whois_lookup(o, save_output=False, settings=_settings),
        answered=lambda r: bool((r or {}).get("whois_data")), label="WHOIS")
    return value


def _whois_scope():
    """A report scope over the WHOIS breaker for one group's single lookup."""
    from recon.helpers import circuit_breaker
    return circuit_breaker.scope("whois", label="WHOIS", unit="lookup(s)")


def _breaker_mode() -> str:
    """"on" or "off" for metadata.circuit_breakers (RECON_CIRCUIT_BREAKERS)."""
    from recon.helpers import circuit_breaker
    return circuit_breaker.mode()


def build_scan_type() -> str:
    """Build dynamic scan type based on enabled modules."""
    modules = []
    if "domain_discovery" in SCAN_MODULES:
        modules.append("domain_discovery")
    if "port_scan" in SCAN_MODULES:
        modules.append("port_scan")
    if "http_probe" in SCAN_MODULES:
        modules.append("http_probe")
    if "resource_enum" in SCAN_MODULES:
        modules.append("resource_enum")
    if "vuln_scan" in SCAN_MODULES:
        modules.append("vuln_scan")
    return "_".join(modules) if modules else "custom"


_save_lock = threading.Lock()


def save_recon_file(data: dict, output_file: Path):
    """Save recon data to JSON file (thread-safe).

    Every phase ends here, so once a stop is requested the calling thread parks
    after the save instead of starting the next phase: a phase that runs in
    Python (OSINT calls, security checks) would otherwise send new traffic until
    the stopper ends the process.
    """
    with _save_lock:
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
    _shutdown.park()


def _dns_names(result: dict) -> set:
    return set(((result.get("dns") or {}).get("subdomains") or {}))


def _late_names(result: dict, before: set, settings: dict, output_file: Path, *,
                after_port_scan: bool, probe_http: bool, label: str) -> None:
    """F2: names a step merged into dns.subdomains after GROUP 1 get their DNS;
    after the port scan, their ports; after httpx, a probe of their own. The
    graph gets their Subdomain -> IP edges and what was scanned."""
    new = sorted(_dns_names(result) - set(before))
    if not new:
        return
    from recon.helpers import late_names
    if not after_port_scan:
        if late_names.give_dns(result, new, settings):
            save_recon_file(result, output_file)
        return
    sub = late_names.scan_late_names(result, new, settings, probe_http=probe_http, label=label)
    if not sub:
        return
    save_recon_file(result, output_file)
    _graph_update_bg("update_graph_from_domain_discovery", {**sub, "whois": {}}, USER_ID, PROJECT_ID)
    if sub.get("port_scan"):
        _graph_update_bg("update_graph_from_port_scan", sub, USER_ID, PROJECT_ID)
    if sub.get("http_probe"):
        _graph_update_bg("update_graph_from_http_probe", sub, USER_ID, PROJECT_ID)


_TLS_HYGIENE_CHECK_SETTINGS = {
    "tls_expired": "SECURITY_CHECK_TLS_EXPIRED",
    "tls_self_signed": "SECURITY_CHECK_TLS_SELF_SIGNED",
    "tls_hostname_mismatch": "SECURITY_CHECK_TLS_HOSTNAME_MISMATCH",
    "tls_weak_version": "SECURITY_CHECK_TLS_WEAK_VERSION",
    "tls_weak_cipher": "SECURITY_CHECK_TLS_WEAK_CIPHER",
    "tls_wildcard_overbroad": "SECURITY_CHECK_TLS_WILDCARD_OVERBROAD",
    # Item 5's certificate rule reads the same stored certificates.
    "test_certificate": "SECURITY_CHECK_TEST_CERTIFICATES",
}


def _maybe_run_cert_hygiene(result: dict, settings: dict, output_file: Path) -> dict:
    """Certificate hygiene when the active scans were skipped (H2).

    `should_skip_active_scans` suppresses the whole vuln_scan module when httpx
    found no live URL, and run_security_checks -- which owns the TLS-hygiene
    checks -- lives inside it. A host serving TLS only on 993/636 therefore had
    its certificates grabbed and stored and then produced zero findings. That is
    the precise target class tlsx was added for, so the most relevant case was
    the one silently dropped.

    Only the certificate-data subset runs here. It reads what is already in
    memory and sends no packets, so none of the active probing the skip exists
    to prevent comes back. Mirrors js_recon, which runs in the same branch
    because uploaded files likewise need no live target.
    """
    if "vuln_scan" not in SCAN_MODULES:
        return result
    if not settings.get('SECURITY_CHECK_ENABLED', True):
        return result
    if not (result.get("tlsx") or result.get("http_probe")):
        return result

    enabled = {name: bool(settings.get(key, True))
               for name, key in _TLS_HYGIENE_CHECK_SETTINGS.items()}
    if not any(enabled.values()):
        return result

    try:
        from recon.helpers import run_cert_hygiene_checks_only
        print("\n[*][Pipeline] Certificate hygiene from stored cert data "
              "(active scans skipped, no network cost)")
        checks = run_cert_hygiene_checks_only(result, enabled)["security_checks"]
        if not checks.get("findings"):
            return result
        result.setdefault("vuln_scan", {})["security_checks"] = checks
        save_recon_file(result, output_file)
        _graph_update_bg("update_graph_from_vuln_scan", result, USER_ID, PROJECT_ID)
    except Exception as e:
        print(f"[!][Pipeline] certificate hygiene checks failed: {e}")
        result.setdefault("metadata", {}).setdefault("phase_errors", {})["cert_hygiene"] = str(e)
        _note_phase_error("cert_hygiene")
    return result


def _maybe_run_ai_surface(result: dict, settings: dict, output_file: Path) -> dict:
    """GROUP 4.5 — AI Surface Recon. Runs after resource_enum at every call site.

    Gated purely on AI_SURFACE_RECON_ENABLED (the js_recon pattern), not
    SCAN_MODULES. Failure-soft: a probe error records a phase_error and the
    pipeline continues.
    """
    if not settings.get('AI_SURFACE_RECON_ENABLED', True):
        return result
    print(f"\n[*][Pipeline] GROUP 4.5: AI Surface Recon")
    try:
        result = run_ai_surface_recon(result, output_file=output_file, settings=settings)
        result.setdefault("metadata", {}).setdefault("modules_executed", [])
        if "ai_surface_recon" not in result["metadata"]["modules_executed"]:
            result["metadata"]["modules_executed"].append("ai_surface_recon")
        save_recon_file(result, output_file)
        _graph_update_bg("update_graph_from_ai_surface_recon", result, USER_ID, PROJECT_ID)
    except Exception as e:
        print(f"[!][AISurfaceRecon] failed: {e}")
        result.setdefault("metadata", {}).setdefault("phase_errors", {})["ai_surface_recon"] = str(e)
        _note_phase_error("ai_surface_recon")
        try:
            save_recon_file(result, output_file)
        except Exception:
            pass
    return result


def _maybe_run_supply_chain(result: dict, settings: dict, output_file: Path) -> dict:
    """GROUP 5.5 — Supply-Chain Recon, in both pipelines, after JS Recon.

    It reads js_recon's source maps and work dir, http_probe and the
    technologies, and judges packages offline (OSV), so it runs even when the
    active scans are skipped; only the opt-in GuardDog leg downloads packages
    from public registries. Its findings are not recon prune sources, so a
    crash records a phase error and nothing else.
    """
    if not settings.get('SUPPLY_CHAIN_RECON_ENABLED', False):
        return result
    print(f"\n[*][Pipeline] GROUP 5.5: Supply-Chain Recon")
    try:
        from recon.main_recon_modules.supply_chain_recon import run_supply_chain_recon
        result = run_supply_chain_recon(result, settings=settings)
        result.setdefault("metadata", {}).setdefault("modules_executed", []).append("supply_chain_recon")
        save_recon_file(result, output_file)
        _graph_update_bg("update_graph_from_supply_chain_recon", result, USER_ID, PROJECT_ID)
    except Exception as e:
        print(f"[!][SupplyChainRecon] Error: {e}")
        result.setdefault("metadata", {}).setdefault("phase_errors", {})["supply_chain_recon"] = str(e)
    return result


def merge_port_scan_results(combined_result: dict) -> None:
    """
    Merge masscan_scan results into port_scan for downstream consumers.

    http_probe, graph_db, and other modules only read recon_data["port_scan"].
    This function merges masscan-discovered ports into that key, deduplicating
    by host+port. If only masscan ran (no naabu), its data becomes port_scan.
    """
    masscan_data = combined_result.get("masscan_scan")
    if not masscan_data:
        return

    port_scan = combined_result.get("port_scan")

    if not port_scan:
        combined_result["port_scan"] = {
            "scan_metadata": masscan_data.get("scan_metadata", {}),
            "by_host": dict(masscan_data.get("by_host", {})),
            "by_ip": dict(masscan_data.get("by_ip", {})),
            "all_ports": list(masscan_data.get("all_ports", [])),
            "ip_to_hostnames": dict(masscan_data.get("ip_to_hostnames", {})),
            "summary": dict(masscan_data.get("summary", {})),
        }
        return

    # Both scanners ran — merge masscan into port_scan, deduplicating
    for host, mdata in masscan_data.get("by_host", {}).items():
        if host not in port_scan["by_host"]:
            port_scan["by_host"][host] = mdata
        else:
            existing = port_scan["by_host"][host]
            for port in mdata.get("ports", []):
                if port not in existing["ports"]:
                    existing["ports"].append(port)
            for pd in mdata.get("port_details", []):
                if pd["port"] not in [x["port"] for x in existing.get("port_details", [])]:
                    existing.setdefault("port_details", []).append(pd)
            existing["ports"].sort()
            if "port_details" in existing:
                existing["port_details"].sort(key=lambda x: x["port"])

    for ip, mdata in masscan_data.get("by_ip", {}).items():
        if ip not in port_scan["by_ip"]:
            port_scan["by_ip"][ip] = mdata
        else:
            existing = port_scan["by_ip"][ip]
            for port in mdata.get("ports", []):
                if port not in existing["ports"]:
                    existing["ports"].append(port)
            for hn in mdata.get("hostnames", []):
                if hn not in existing.get("hostnames", []):
                    existing.setdefault("hostnames", []).append(hn)
            existing["ports"].sort()

    merged_ports = sorted(set(port_scan.get("all_ports", []) + masscan_data.get("all_ports", [])))
    port_scan["all_ports"] = merged_ports

    for ip, hosts in masscan_data.get("ip_to_hostnames", {}).items():
        existing_hosts = port_scan.setdefault("ip_to_hostnames", {}).setdefault(ip, [])
        for h in (hosts if isinstance(hosts, list) else [hosts]):
            if h not in existing_hosts:
                existing_hosts.append(h)

    existing_meta = port_scan.get("scan_metadata", {})
    scanners = existing_meta.get("scanners", ["naabu"])
    if "masscan" not in scanners:
        scanners.append("masscan")
    existing_meta["scanners"] = scanners

    by_host = port_scan["by_host"]
    by_ip = port_scan["by_ip"]
    port_scan["summary"] = {
        "hosts_scanned": len(by_host),
        "ips_scanned": len(by_ip),
        "hosts_with_open_ports": len([h for h in by_host.values() if h.get("ports")]),
        "total_open_ports": sum(len(h.get("ports", [])) for h in by_host.values()),
        "unique_ports": merged_ports,
        "unique_port_count": len(merged_ports),
        "cdn_hosts": len([h for h in by_host.values() if h.get("is_cdn")]),
    }


def _drop_shodan_cdn_ips(combined_result: dict) -> None:
    """Drop Shodan results for the IPs the port scan flagged as CDN. Never raises.

    Shodan runs beside the port scan, so its IP filter could not see naabu's
    CDN flags; this is the first point where both results are known.
    """
    shodan_data = combined_result.get("shodan")
    if not shodan_data or not combined_result.get("port_scan"):
        return
    try:
        from recon.main_recon_modules.shodan_enrich import drop_cdn_ips
        dropped = drop_cdn_ips(shodan_data, combined_result)
    except Exception as e:  # noqa: BLE001 - keeping the results beats losing the run
        print(f"[!][Shodan] Could not drop CDN IPs from the results: {type(e).__name__}")
        return
    if dropped:
        print(f"[*][Shodan] Dropped results for {dropped} CDN IP(s) flagged by the port scan")


def _reachcheck_shodan_cves(combined_result: dict, settings: dict) -> None:
    """Mark each Shodan CVE with whether this run's port scan found its port open.

    Shodan runs beside the port scan, so this is the first point where both
    are known; nmap re-probes only what the port scan found, so nothing else
    looks at a port only Shodan reported. No traffic. Never raises: a CVE left
    unmarked keeps whatever it had.
    """
    shodan_data = combined_result.get("shodan")
    if not shodan_data or not shodan_data.get("cves"):
        return
    try:
        from recon.helpers.port_coverage import port_scan_coverage
        from recon.main_recon_modules.shodan_enrich import reachcheck_cves
        counts = reachcheck_cves(shodan_data, port_scan_coverage(combined_result, settings))
    except Exception as e:  # noqa: BLE001 - an unchecked CVE beats losing the run
        print(f"[!][Shodan] Could not check CVE ports against the port scan: {type(e).__name__}")
        return
    print(f"[*][Shodan] CVE ports against the port scan: {counts['open']} open, "
          f"{counts['closed']} closed, {counts['unknown']} not scanned")


def _without_shodan_cves(combined_result: dict) -> dict:
    """The run's data with Shodan's CVEs held back for _write_shodan_cves.

    Shodan's hosts, ports and names are written at GROUP 3 as before; its CVEs
    wait for IP attribution, which runs after http_probe and decides which IPs
    are a shared edge.
    """
    shodan = combined_result.get("shodan")
    if not isinstance(shodan, dict) or not shodan.get("cves"):
        return combined_result
    return {**combined_result, "shodan": {**shodan, "cves": []}}


def _write_shodan_cves(combined_result: dict) -> None:
    """Queue the graph write of the Shodan CVEs held back at GROUP 3, minus
    those on a shared edge. The prune then removes an earlier run's CVE on such
    an IP: the lookup did re-check it."""
    shodan = combined_result.get("shodan")
    if not isinstance(shodan, dict) or not shodan.get("cves"):
        return
    from recon.main_recon_modules.ip_attribution import shared_edge_ips
    from recon.main_recon_modules.shodan_enrich import drop_shared_edge_cves
    dropped = drop_shared_edge_cves(shodan, shared_edge_ips(combined_result))
    if dropped:
        print(f"[*][Shodan] Dropped {dropped} passive CVE(s) on shared edge IP(s)")
    if shodan["cves"]:
        _graph_update_bg("update_graph_from_shodan", {**combined_result, "shodan": {"cves": shodan["cves"]}},
                         USER_ID, PROJECT_ID)


def _write_netlas(combined_result: dict) -> None:
    """Queue the Netlas graph write held back at GROUP 3b, its shared edge rows
    marked so the writer gives them no CVE finding."""
    netlas = combined_result.get("netlas")
    if not isinstance(netlas, dict) or not netlas.get("results"):
        return
    from recon.main_recon_modules.ip_attribution import shared_edge_ips
    from recon.main_recon_modules.netlas_enrich import retag_shared_edge
    retagged = retag_shared_edge(netlas, shared_edge_ips(combined_result))
    if retagged:
        print(f"[*][Netlas] {retagged} row(s) on shared edge IP(s) get no CVE finding")
    _graph_update_bg("update_graph_from_netlas", combined_result, USER_ID, PROJECT_ID)


def _run_ip_attribution(combined_result: dict, settings: dict, output_file) -> None:
    """Tag every IP of the run shared_edge / dedicated / unknown. Never raises.

    After the port scan, tlsx and http_probe, whose CDN flags, ASN and headers
    it reads; before vhost/SNI, origin discovery and the Shodan CVE and Netlas
    writes, which read the tag.
    """
    if not settings.get('IP_ATTRIBUTION_ENABLED', True):
        print("\n[-][IpAttribution] Disabled via settings -- skipping")
        return
    try:
        from recon.main_recon_modules.ip_attribution import run_ip_attribution
        run_ip_attribution(combined_result, settings)
        combined_result["metadata"]["modules_executed"].append("ip_attribution")
        save_recon_file(combined_result, output_file)
        _graph_update_bg("update_graph_from_ip_attribution", combined_result, USER_ID, PROJECT_ID)
    except Exception as e:  # noqa: BLE001 - the tag is optional; the run is not
        print(f"[!][IpAttribution] failed: {type(e).__name__}")
        combined_result["metadata"].setdefault("phase_errors", {})["ip_attribution"] = str(e)


# The Nmap merge lives in recon.helpers.nmap_merge, so partial recon reaches it
# without importing this file.
from recon.helpers.nmap_merge import (  # noqa: E402
    _add_nmap_confirmed_ports,
    _apply_nmap_detail,
    merge_nmap_into_port_scan,
)


def _merge_isolated_result(combined: dict, key: str, result) -> None:
    """Store one `_isolated` wrapper's answer in combined_result.

    A TopLevelKeys answer carries several top-level keys and each is merged
    (vuln_scan also hands back the CVE lookup's technology_cves); any other
    answer is the payload of `key` itself, even a dict that names other keys.
    """
    if isinstance(result, TopLevelKeys):
        combined[key] = result.get(key, {})
        for name, value in result.items():
            if name == key:
                continue
            if name == "jev_shadow" and isinstance(value, dict):
                # Each hook owns its own slot; a tool's answer never replaces
                # another hook's records written earlier in the run.
                combined.setdefault("jev_shadow", {}).update(value)
            else:
                combined[name] = value
    else:
        combined[key] = result


def _run_phase_a_fan_out(tools: dict, combined_result: dict, settings: dict,
                         output_file) -> None:
    """GROUP 6 Phase A: run the active scanners concurrently on deep copies.

    Each answer is merged before its graph update is queued, because the
    update snapshots combined_result at queue time.
    """
    if not tools:
        return
    print(f"\n[*][Pipeline] GROUP 6 Phase A: Active Vulnerability Scanning (fan-out: {', '.join(tools.keys())})")
    print("-" * 40)
    with ThreadPoolExecutor(max_workers=len(tools)) as pool:
        futures = {pool.submit(fn, combined_result, settings): key
                   for key, fn in tools.items()}
        for fut in as_completed(futures):
            key = futures[fut]
            try:
                _merge_isolated_result(combined_result, key, fut.result())
                combined_result["metadata"]["modules_executed"].append(key)
                save_recon_file(combined_result, output_file)
                _graph_update_bg(f"update_graph_from_{key}", combined_result, USER_ID, PROJECT_ID)
            except Exception as e:
                print(f"[!][Pipeline] {key} failed: {e}")
                combined_result["metadata"].setdefault("phase_errors", {})[key] = str(e)
                _note_phase_error(key)
                save_recon_file(combined_result, output_file)


def run_ip_recon(target_ips: list, settings: dict) -> dict:
    """
    Run IP-based reconnaissance: expand CIDRs, reverse DNS, IP WHOIS.

    Produces a recon data structure compatible with the domain-based pipeline
    using mock Domain/Subdomain names derived from reverse DNS or IP addresses.

    Args:
        target_ips: List of IP addresses and/or CIDR ranges
        settings: Full settings dictionary

    Returns:
        Complete reconnaissance data dict (same shape as run_domain_recon output)
    """
    import ipaddress
    from recon.main_recon_modules.domain_recon import dns_lookup

    print("\n" + "=" * 70)
    print("               RedAmon - IP-Based Reconnaissance")
    print("=" * 70)
    print(f"  [*][Pipeline] Target IPs/CIDRs: {', '.join(target_ips)}")
    print("=" * 70 + "\n")

    _graph_reset()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output_file = recon_output_file(OUTPUT_DIR, PROJECT_ID)

    mock_domain = f"ip-targets.{PROJECT_ID}"

    # Step 1: Expand CIDRs into individual IPs
    expanded_ips = []
    original_cidrs = []
    for entry in target_ips:
        entry = entry.strip()
        if '/' in entry:
            try:
                network = ipaddress.ip_network(entry, strict=False)
                original_cidrs.append(entry)
                for host in network.hosts():
                    expanded_ips.append(str(host))
                # For /32 (IPv4) or /128 (IPv6) single-host networks, hosts() is empty
                if network.prefixlen in (32, 128):
                    expanded_ips.append(str(network.network_address))
            except ValueError as e:
                print(f"[!][Pipeline] Invalid CIDR {entry}: {e}")
        else:
            expanded_ips.append(entry)

    expanded_ips = list(dict.fromkeys(expanded_ips))  # deduplicate preserving order
    print(f"[*][Pipeline] Expanded {len(target_ips)} entries to {len(expanded_ips)} individual IPs")

    # RoE: filter out excluded hosts (supports exact match + CIDR)
    expanded_ips = _filter_roe_excluded(expanded_ips, settings, label="IP")

    # Step 2: Reverse DNS for each IP
    ip_to_hostname = {}
    all_hostnames = []
    subdomains_dns = {}

    dns_enabled = settings.get('DNS_ENABLED', True)

    # The orchestrator takes the progress label from these GROUP headers only
    # (PIPELINE_HEADER_PHASES in recon_orchestrator/container_manager.py).
    print(f"\n[*][Pipeline] GROUP 1: Reverse DNS + DNS + IP WHOIS (IP mode)")

    if dns_enabled:
        print(f"\n[*][DNS] IP STEP 1: Reverse DNS Lookup")
        print("-" * 40)

        # Parallel PTR lookups: one IP at a time serialised the whole /24 sweep.
        # A per-/24 reverse-zone breaker inside reverse_dns_lookup skips a zone
        # whose PTR authority stopped answering (and the resolver breaker skips
        # everything if the resolver itself is down), so a dead range no longer
        # costs one timeout per IP.
        _rdns_retries = settings.get('DNS_MAX_RETRIES', 3)
        _rdns_workers = max(1, min(int(settings.get('DNS_MAX_WORKERS', 80)), len(expanded_ips) or 1))
        _rdns_results = {}
        with ThreadPoolExecutor(max_workers=_rdns_workers, thread_name_prefix="rdns") as _rdns_pool:
            _rdns_futs = {
                _rdns_pool.submit(reverse_dns_lookup, ip, _rdns_retries): ip
                for ip in expanded_ips
            }
            for _fut in as_completed(_rdns_futs):
                _ip = _rdns_futs[_fut]
                try:
                    _rdns_results[_ip] = _fut.result()
                except Exception:  # noqa: BLE001 - a lookup crash is a miss
                    _rdns_results[_ip] = None
        # Apply results in the original order for deterministic output.
        for ip in expanded_ips:
            hostname = _rdns_results.get(ip)
            if hostname:
                ip_to_hostname[ip] = hostname
                all_hostnames.append(hostname)
                print(f"[+][DNS] {ip} -> {hostname}")
            else:
                # Use IP with dashes as mock subdomain name
                mock_name = ip.replace('.', '-').replace(':', '-')
                ip_to_hostname[ip] = mock_name
                print(f"[-][DNS] {ip} -> no PTR (using {mock_name})")
    else:
        print(f"\n[-][DNS] IP STEP 1: Reverse DNS Lookup — SKIPPED (disabled)")
        for ip in expanded_ips:
            mock_name = ip.replace('.', '-').replace(':', '-')
            ip_to_hostname[ip] = mock_name

    # Step 3: Build DNS data structure for each "subdomain"
    subdomain_names = []
    if dns_enabled:
        print(f"\n[*][DNS] IP STEP 2: DNS Resolution for Discovered Hosts")
        print("-" * 40)

        for ip, hostname in ip_to_hostname.items():
            # Determine if this is a real hostname or mock
            is_real_hostname = hostname in all_hostnames and not hostname.replace('-', '').replace('.', '').isdigit()

            if is_real_hostname:
                # Resolve DNS for real hostnames
                print(f"[*][DNS] Resolving: {hostname}")
                host_dns = dns_lookup(hostname)
                subdomains_dns[hostname] = host_dns
                subdomain_names.append(hostname)
            else:
                # Mock entry - create minimal DNS data with the IP
                is_v6 = ':' in ip
                subdomains_dns[hostname] = {
                    "has_records": True,
                    "ips": {
                        "ipv4": [] if is_v6 else [ip],
                        "ipv6": [ip] if is_v6 else [],
                    },
                    "records": {},
                    "is_mock": True,
                    "actual_ip": ip,
                }
                subdomain_names.append(hostname)
    else:
        print(f"\n[-][DNS] IP STEP 2: DNS Resolution — SKIPPED (disabled)")
        for ip, hostname in ip_to_hostname.items():
            is_v6 = ':' in ip
            subdomains_dns[hostname] = {
                "has_records": True,
                "ips": {
                    "ipv4": [] if is_v6 else [ip],
                    "ipv6": [ip] if is_v6 else [],
                },
                "records": {},
                "is_mock": True,
                "actual_ip": ip,
            }
            subdomain_names.append(hostname)

    # Step 4: IP WHOIS (best-effort)
    ip_whois = {}
    if settings.get('WHOIS_ENABLED', True):
        print(f"\n[*][WHOIS] IP STEP 3: IP WHOIS Lookup")
        print("-" * 40)
        try:
            from recon.helpers import circuit_breaker
            from recon.main_recon_modules.whois_recon import (
                WhoisUnavailable, print_whois_settings, whois_lookup as ip_whois_lookup,
            )
            whois_scope = circuit_breaker.scope("whois", label="WHOIS", unit="IP block(s)")
            print_whois_settings(settings)
            # WHOIS a sample of IPs (first one per /24 block to avoid flooding)
            seen_blocks = set()
            for ip in expanded_ips:
                block = '.'.join(ip.split('.')[:3]) if '.' in ip else ip[:16]
                if block in seen_blocks:
                    continue
                seen_blocks.add(block)
                try:
                    result = ip_whois_lookup(ip, save_output=False, settings=settings,
                                             print_settings=False)
                    ip_whois[ip] = result.get("whois_data", {})
                    org = ip_whois[ip].get("org", "unknown")
                    print(f"[+][WHOIS] {ip}: org={org}")
                except WhoisUnavailable:
                    continue  # counted by the scope, summarised once below
                except Exception as e:
                    print(f"[-][WHOIS] WHOIS for {ip} failed: {e}")
            whois_scope.finish("whois")
        except Exception as e:
            print(f"[!][WHOIS] IP WHOIS module error: {e}")
    else:
        print(f"\n[-][WHOIS] IP STEP 3: IP WHOIS Lookup — SKIPPED (disabled)")

    # Build the subdomain_filter (all IPs + any PTR-resolved hostnames)
    # This becomes allowed_hosts for http_probe scope checking
    subdomain_filter = list(set(expanded_ips + all_hostnames + subdomain_names))

    # Build result structure compatible with domain-based pipeline
    combined_result = {
        "metadata": {
            "scan_type": build_scan_type(),
            "scan_timestamp": datetime.now().isoformat(),
            "target": mock_domain,
            "root_domain": mock_domain,
            "user_id": USER_ID,
            "project_id": PROJECT_ID,
            "ip_mode": True,
            "target_ips": target_ips,
            "expanded_ips": expanded_ips,
            "original_cidrs": original_cidrs,
            "ip_to_hostname": ip_to_hostname,
            "filtered_mode": True,
            # The mock root is no host and no registrable name: its own org,
            # an exact scope over the listed addresses, never a target itself.
            "org_domain": mock_domain,
            "scope_mode": "exact",
            "include_root_domain": False,
            "subdomain_filter": subdomain_filter,
            "anonymous_mode": False,
            "bruteforce_mode": False,
            "modules_executed": ["ip_recon", "reverse_dns"],
            "circuit_breakers": _breaker_mode(),
        },
        "domain": mock_domain,
        "whois": {"ip_whois": ip_whois},
        "subdomains": subdomain_names,
        "subdomain_count": len(subdomain_names),
        "dns": {
            "domain": {},
            "subdomains": subdomains_dns,
        },
    }

    save_recon_file(combined_result, output_file)
    print(f"\n[✓][Pipeline] Saved: {output_file}")

    # Background graph update: IP recon
    _graph_update_bg("update_graph_from_ip_recon", combined_result, USER_ID, PROJECT_ID)

    # =====================================================================
    # GROUP 2b — Uncover Target Expansion (before port scan / OSINT)
    # =====================================================================
    if settings.get('OSINT_ENRICHMENT_ENABLED', False) and settings.get('UNCOVER_ENABLED', False):
        try:
            from recon.main_recon_modules.uncover_enrich import run_uncover_expansion, merge_uncover_into_pipeline
            uncover_data = run_uncover_expansion(combined_result, settings)
            if uncover_data:
                combined_result["uncover"] = uncover_data
                merge_uncover_into_pipeline(combined_result, uncover_data, combined_result.get('domain', ''),
                                            settings=settings)
                combined_result["metadata"]["modules_executed"].append("uncover_expansion")
                save_recon_file(combined_result, output_file)
                _graph_update_bg("update_graph_from_uncover", combined_result, USER_ID, PROJECT_ID)
        except Exception as e:
            print(f"[!][Uncover] Expansion failed: {e}")

    # =====================================================================
    # Shodan + Port Scan (parallel fan-out) — same pattern as domain recon
    # =====================================================================
    shodan_enabled = settings.get('SHODAN_ENABLED', True) and any([
        settings.get('SHODAN_HOST_LOOKUP'),
        settings.get('SHODAN_REVERSE_DNS'),
        settings.get('SHODAN_DOMAIN_DNS'),
        settings.get('SHODAN_PASSIVE_CVES'),
    ])

    naabu_enabled = settings.get('NAABU_ENABLED', True)
    masscan_enabled = settings.get('MASSCAN_ENABLED', True)

    if "port_scan" in SCAN_MODULES and not naabu_enabled and not masscan_enabled:
        print("\n[!][Pipeline] Both Naabu and Masscan are disabled — skipping port scan phase")
        print("[!][Pipeline] Downstream modules (HTTP probe, vuln scan) require open ports to work")

    if shodan_enabled or "port_scan" in SCAN_MODULES:
        print(f"\n[*][Pipeline] GROUP 3: Shodan + Port Scan (parallel fan-out)")
        print("-" * 40)

        port_scan_workers = (1 if naabu_enabled else 0) + (1 if masscan_enabled else 0)
        max_workers = (1 if shodan_enabled else 0) + (port_scan_workers if "port_scan" in SCAN_MODULES else 0)
        max_workers = max(max_workers, 1)
        with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="ip-g3") as g3_exec:
            g3_futures = {}
            if shodan_enabled:
                from recon.main_recon_modules.shodan_enrich import run_shodan_enrichment_isolated
                g3_futures["shodan"] = g3_exec.submit(
                    run_shodan_enrichment_isolated, combined_result, settings
                )
            if naabu_enabled and "port_scan" in SCAN_MODULES:
                g3_futures["port_scan"] = g3_exec.submit(
                    run_port_scan_isolated, combined_result, settings
                )
            if masscan_enabled and "port_scan" in SCAN_MODULES:
                g3_futures["masscan_scan"] = g3_exec.submit(
                    run_masscan_scan_isolated, combined_result, settings
                )

            for name, future in g3_futures.items():
                try:
                    data = future.result()
                    if name == "shodan" and data:
                        combined_result["shodan"] = data
                        combined_result["metadata"]["modules_executed"].append("shodan_enrich")
                    elif name == "port_scan" and data:
                        combined_result["port_scan"] = data
                        combined_result["metadata"]["modules_executed"].append("port_scan")
                    elif name == "masscan_scan" and data:
                        combined_result["masscan_scan"] = data
                        combined_result["metadata"]["modules_executed"].append("masscan_scan")
                except Exception as e:
                    print(f"[!][{name}] Failed: {e}")
                    _note_phase_error(name)

        # Merge masscan results into port_scan for downstream consumers
        if "masscan_scan" in combined_result:
            merge_port_scan_results(combined_result)

        _drop_shodan_cdn_ips(combined_result)
        _reachcheck_shodan_cves(combined_result, settings)

        save_recon_file(combined_result, output_file)

        if "shodan" in combined_result:
            _graph_update_bg("update_graph_from_shodan", _without_shodan_cves(combined_result),
                             USER_ID, PROJECT_ID)

        if "port_scan" in combined_result:
            _graph_update_bg("update_graph_from_port_scan", combined_result, USER_ID, PROJECT_ID)

    # =====================================================================
    # GROUP 3.5 — Nmap Service Version Detection + NSE Vulnerability Scripts
    # IP-mode equivalent of the domain-mode block at run_domain_recon().
    # Without this, Service.product / Service.version / Service.ai_runtime_version
    # never get populated in IP-mode scans (recon's port_scan only carries
    # IANA-derived service names, not real banner-read versions).
    # Depends on: port_scan output. Runs sequentially BEFORE HTTP probe so
    # http_probe sees the enriched port_details.
    # =====================================================================
    nmap_enabled = settings.get('NMAP_ENABLED', True)
    if nmap_enabled and "port_scan" in combined_result:
        print(f"\n[*][Pipeline] GROUP 3.5: Nmap Service Detection (IP mode)")
        print("-" * 40)

        try:
            from recon.main_recon_modules.nmap_scan import run_nmap_scan
            combined_result = run_nmap_scan(combined_result, output_file=output_file, settings=settings)
            combined_result["metadata"]["modules_executed"].append("nmap_scan")

            # Merge Nmap service versions (incl. ai_runtime_version) into port_scan.port_details
            if "nmap_scan" in combined_result:
                merge_nmap_into_port_scan(combined_result)

            save_recon_file(combined_result, output_file)

            if "nmap_scan" in combined_result:
                _graph_update_bg("update_graph_from_nmap", combined_result, USER_ID, PROJECT_ID)
        except Exception as e:
            print(f"[!][Pipeline] nmap failed: {e}")
            combined_result["metadata"].setdefault("phase_errors", {})["nmap"] = str(e)
            _note_phase_error("nmap")
            save_recon_file(combined_result, output_file)
    elif nmap_enabled:
        _note_nmap_without_port_data(combined_result, settings)

    # =====================================================================
    # GROUP 3.6 — TLS certificate grab (tlsx), IP mode.
    # No SAN hostname injection here: IP mode has no apex to scope-test against,
    # so merge_discovered_hostnames would fail closed anyway. Certs still land
    # on the graph (IP-anchored), and non-HTTP TLS ports get identified.
    # =====================================================================
    if settings.get('TLSX_ENABLED', True) and "port_scan" in combined_result:
        print(f"\n[*][Pipeline] GROUP 3.6: TLS Certificate Grab (IP mode)")
        print("-" * 40)
        try:
            from recon.main_recon_modules.tls_scan import run_tlsx_enrichment
            combined_result = run_tlsx_enrichment(combined_result, settings=settings)
            combined_result["metadata"]["modules_executed"].append("tlsx")
            save_recon_file(combined_result, output_file)
            _graph_update_bg("update_graph_from_tlsx", combined_result, USER_ID, PROJECT_ID)
        except Exception as e:
            print(f"[!][Pipeline] tlsx failed: {e}")
            combined_result["metadata"].setdefault("phase_errors", {})["tlsx"] = str(e)

    # OSINT Enrichment (parallel, same logic as domain recon Group 3b)
    _ip_osint_tools = {
        'censys': ('CENSYS_ENABLED', 'recon.main_recon_modules.censys_enrich', 'run_censys_enrichment_isolated', 'update_graph_from_censys'),
        'fofa': ('FOFA_ENABLED', 'recon.main_recon_modules.fofa_enrich', 'run_fofa_enrichment_isolated', 'update_graph_from_fofa'),
        'otx': ('OTX_ENABLED', 'recon.main_recon_modules.otx_enrich', 'run_otx_enrichment_isolated', 'update_graph_from_otx'),
        'netlas': ('NETLAS_ENABLED', 'recon.main_recon_modules.netlas_enrich', 'run_netlas_enrichment_isolated', 'update_graph_from_netlas'),
        'virustotal': ('VIRUSTOTAL_ENABLED', 'recon.main_recon_modules.virustotal_enrich', 'run_virustotal_enrichment_isolated', 'update_graph_from_virustotal'),
        'zoomeye': ('ZOOMEYE_ENABLED', 'recon.main_recon_modules.zoomeye_enrich', 'run_zoomeye_enrichment_isolated', 'update_graph_from_zoomeye'),
        'criminalip': ('CRIMINALIP_ENABLED', 'recon.main_recon_modules.criminalip_enrich', 'run_criminalip_enrichment_isolated', 'update_graph_from_criminalip'),
    }
    if not settings.get('OSINT_ENRICHMENT_ENABLED', False):
        enabled_ip_osint = {}
    else:
        enabled_ip_osint = {
            name: cfg for name, cfg in _ip_osint_tools.items()
            if settings.get(cfg[0], False)
            and (
                settings.get(f'{name.upper()}_API_KEY', '')
                or (name == 'censys' and settings.get('CENSYS_API_TOKEN', ''))
                or name == 'otx'  # OTX supports anonymous requests without an API key
            )
        }
    if enabled_ip_osint:
        print(f"\n[*][Pipeline] GROUP 3b: OSINT Enrichment ({', '.join(enabled_ip_osint.keys())}) — parallel")
        print("-" * 40)
        import importlib
        osint_workers = min(len(enabled_ip_osint), 5)
        with ThreadPoolExecutor(max_workers=osint_workers, thread_name_prefix="ip-osint") as osint_exec:
            osint_futures = {}
            for name, (_, module_path, func_name, _) in enabled_ip_osint.items():
                mod = importlib.import_module(module_path)
                fn = getattr(mod, func_name)
                osint_futures[name] = osint_exec.submit(fn, combined_result, settings)
            for name, future in osint_futures.items():
                try:
                    data = future.result()
                    if data:
                        combined_result[name] = data
                        combined_result["metadata"]["modules_executed"].append(f"{name}_enrich")
                        print(f"[+][{name.upper()}] Enrichment merged")
                except Exception as e:
                    print(f"[!][{name.upper()}] Enrichment failed: {e}")
                    _note_phase_error(name)
        save_recon_file(combined_result, output_file)
        for name, (_, _, _, graph_method) in enabled_ip_osint.items():
            if name == "netlas":
                continue  # written after IP attribution (_write_netlas)
            if name in combined_result:
                _graph_update_bg(graph_method, combined_result, USER_ID, PROJECT_ID)

    # HTTP Probe
    if "http_probe" in SCAN_MODULES:
        if not settings.get('HTTPX_ENABLED', True):
            print("\n[*][httpx] HTTP probing disabled -- skipping")
        else:
            print(f"\n[*][Pipeline] GROUP 4: HTTP Probing")
            try:
                combined_result = run_http_probe(combined_result, output_file=output_file, settings=settings)
                combined_result["metadata"]["modules_executed"].append("http_probe")
                save_recon_file(combined_result, output_file)

                _graph_update_bg("update_graph_from_http_probe", combined_result, USER_ID, PROJECT_ID)
            except Exception as e:
                print(f"[!][Pipeline] http_probe failed: {e}")
                combined_result["metadata"].setdefault("phase_errors", {})["http_probe"] = str(e)
                _note_phase_error("http_probe")
                save_recon_file(combined_result, output_file)

    _run_ip_attribution(combined_result, settings, output_file)
    _write_shodan_cves(combined_result)
    _write_netlas(combined_result)

    # Check if active scans should be skipped
    skip_active_scans, skip_reason = should_skip_active_scans(combined_result)

    if skip_active_scans:
        print(f"\n[!][Pipeline] SKIPPING ACTIVE SCANS: {skip_reason}")
        combined_result["metadata"]["active_scans_skipped"] = True
        combined_result["metadata"]["active_scans_skip_reason"] = skip_reason
        save_recon_file(combined_result, output_file)
        combined_result = _maybe_run_cert_hygiene(combined_result, settings, output_file)
    else:
        if "resource_enum" in SCAN_MODULES:
            print(f"\n[*][Pipeline] GROUP 5: Resource Enumeration")
            try:
                combined_result = run_resource_enum(combined_result, output_file=output_file, settings=settings)
                combined_result["metadata"]["modules_executed"].append("resource_enum")
                save_recon_file(combined_result, output_file)
                _graph_update_bg("update_graph_from_resource_enum", combined_result, USER_ID, PROJECT_ID)
            except Exception as e:
                print(f"[!][Pipeline] resource_enum failed: {e}")
                combined_result["metadata"].setdefault("phase_errors", {})["resource_enum"] = str(e)
                _note_phase_error("resource_enum")
                save_recon_file(combined_result, output_file)

    # GROUP 4.5 -- AI Surface Recon (runs after resource_enum)
    combined_result = _maybe_run_ai_surface(combined_result, settings, output_file)

    # GROUP 5b -- JS Recon (runs after resource_enum, before vuln_scan;
    # runs even when active scans are skipped -- uploaded files don't need live targets)
    if settings.get('JS_RECON_ENABLED', False):
        print(f"\n[*][Pipeline] GROUP 5b: JS Recon")
        try:
            from recon.main_recon_modules.js_recon import run_js_recon
            combined_result = run_js_recon(combined_result, settings=settings)
            combined_result["metadata"]["modules_executed"].append("js_recon")
            save_recon_file(combined_result, output_file)
            _graph_update_bg("update_graph_from_js_recon", combined_result, USER_ID, PROJECT_ID)
        except Exception as e:
            print(f"[!][JsRecon] Error: {e}")
            _note_phase_error("js_recon")

    # GROUP 5b — Serialized-object detection (IP-mode mirror; passive, in-memory).
    if settings.get('SERIALIZED_SCAN_ENABLED', False):
        try:
            from recon.serialized_scan import run_serialized_scan
            combined_result = run_serialized_scan(combined_result, settings=settings)
            combined_result["metadata"]["modules_executed"].append("serialized_scan")
            save_recon_file(combined_result, output_file)
            _graph_update_bg("update_graph_from_serialized_scan", combined_result, USER_ID, PROJECT_ID)
        except Exception as e:
            print(f"[!][SerializedScan] Error: {e}")
            _note_phase_error("serialized_scan")

    # GROUP 5.5 -- Supply-Chain Recon (L2): runs AFTER JS-recon (consumes its
    # source_maps + technologies). Black-box package harvest + offline OSV verdict.
    combined_result = _maybe_run_supply_chain(combined_result, settings, output_file)

    if not skip_active_scans:
        if "vuln_scan" in SCAN_MODULES:
            print(f"\n[*][Pipeline] GROUP 6: Vulnerability Scanning (Nuclei, then MITRE)")
            try:
                combined_result = run_vuln_scan(combined_result, output_file=output_file, settings=settings)
                combined_result["metadata"]["modules_executed"].append("vuln_scan")
                save_recon_file(combined_result, output_file)

                if settings.get('MITRE_ENABLED', True):
                    try:
                        combined_result = run_mitre_enrichment(combined_result, output_file=output_file, settings=settings)
                    except Exception as e:
                        print(f"[!][Pipeline] mitre_enrichment failed: {e}")
                        combined_result["metadata"].setdefault("phase_errors", {})["mitre_enrichment"] = str(e)
                save_recon_file(combined_result, output_file)
                _graph_update_bg("update_graph_from_vuln_scan", combined_result, USER_ID, PROJECT_ID)
            except Exception as e:
                print(f"[!][Pipeline] vuln_scan failed: {e}")
                combined_result["metadata"].setdefault("phase_errors", {})["vuln_scan"] = str(e)
                _note_phase_error("vuln_scan")
                save_recon_file(combined_result, output_file)

        # GROUP 6 Phase A (IP mode) — the remaining active vuln scanners. vuln_scan
        # already ran above; here we fan out the same scanners the DOMAIN pipeline runs
        # so an IP target also gets GraphQL / Subdomain-Takeover / VHost-SNI / Web Cache
        # Poisoning coverage (previously these only ran for domain targets, so an IP
        # scan silently skipped them).
        ip_phase_a: dict = {}
        if settings.get('GRAPHQL_SECURITY_ENABLED', False):
            from recon.graphql_scan import run_graphql_scan_isolated
            ip_phase_a['graphql_scan'] = run_graphql_scan_isolated
        if settings.get('SUBDOMAIN_TAKEOVER_ENABLED', False):
            from recon.main_recon_modules.subdomain_takeover import run_subdomain_takeover_isolated
            ip_phase_a['subdomain_takeover'] = run_subdomain_takeover_isolated
        if settings.get('VHOST_SNI_ENABLED', False):
            from recon.main_recon_modules.vhost_sni_enum import run_vhost_sni_enrichment_isolated
            ip_phase_a['vhost_sni'] = run_vhost_sni_enrichment_isolated
        if settings.get('WEB_CACHE_POISON_ENABLED', False):
            from recon.cache_scan import run_cache_scan_isolated
            ip_phase_a['cache_scan'] = run_cache_scan_isolated
        if settings.get('ORIGIN_DISCOVERY_ENABLED', False):
            from recon.main_recon_modules.origin_discovery import run_origin_discovery_enrichment_isolated
            ip_phase_a['origin_discovery'] = run_origin_discovery_enrichment_isolated
        if settings.get('ROUTE_EXPOSURE_ENABLED', False):
            from recon.route_exposure import run_route_exposure_isolated
            ip_phase_a['route_exposure'] = run_route_exposure_isolated

        _run_phase_a_fan_out(ip_phase_a, combined_result, settings, output_file)

    # External Domains -- aggregate from all sources and persist
    try:
        ext_domains = _aggregate_external_domains(combined_result)
        if ext_domains:
            combined_result["external_domains_aggregated"] = ext_domains
            save_recon_file(combined_result, output_file)
            _graph_update_bg("update_graph_from_external_domains", combined_result, USER_ID, PROJECT_ID)
    except Exception as e:
        print(f"[!][Pipeline] external_domains aggregation failed: {e}")

    # Wait for all background graph DB updates to finish
    _graph_wait_all()

    print(f"\n{'=' * 70}")
    print(f"[✓][Pipeline] IP RECON COMPLETE")
    print(f"[+][Pipeline] IPs scanned: {len(expanded_ips)}")
    print(f"[+][Pipeline] Hostnames resolved: {len(all_hostnames)}")
    print(f"[+][Pipeline] Output saved: {output_file}")
    print(f"{'=' * 70}")

    return combined_result


def _scope_metadata(target_info: dict, root_domain: str, filtered_mode: bool) -> dict:
    """The group's scope in its recon metadata (§4.10).

    include_root_domain is restamped once the hosts are merged; it must never
    be absent, because a missing flag reads as True downstream.
    """
    return {
        "org_domain": target_info.get("org_domain") or root_domain,
        "scope_mode": target_info.get("mode") or ("exact" if filtered_mode else "enumerate"),
        "include_root_domain": bool(target_info.get("include_root_domain")),
    }


def run_domain_recon(target: str, bruteforce: bool = False,
                     target_info: dict = None,
                     discovery_enabled: bool = None) -> dict:
    """
    Run combined WHOIS + subdomain discovery + DNS resolution.
    Produces a single unified JSON file with incremental saves.

    Scan modes based on SUBDOMAIN_LIST:
    - Empty list []: Full subdomain discovery (discover and scan all subdomains)
    - With entries ["testphp.", "www."]: Filtered mode (only scan specified subdomains)

    Args:
        target: Root domain (e.g., "vulnweb.com", "example.com")
        bruteforce: Enable Knockpy bruteforce mode (only for full discovery mode)
        target_info: Parsed target info from parse_target()

    Returns:
        Complete reconnaissance data including WHOIS and subdomains
    """
    # Parse target if not provided. The module-level SUBDOMAIN_LIST is only a
    # fallback for the single-domain path; a Domain-batch group always passes its
    # own target_info, because its prefixes differ per group.
    if target_info is None:
        target_info = parse_target(target, SUBDOMAIN_LIST)

    # The per-group answer to "may this target enumerate". Decided by the caller
    # (run_domain_group), because only it sees one batch group's prefixes; None
    # means "no caller opinion", which is the standalone/test path.
    if discovery_enabled is None:
        discovery_enabled = _settings.get('SUBDOMAIN_DISCOVERY_ENABLED', True)

    # Auto-promote to FILTERED MODE when discovery is disabled and the root
    # domain is in scope. Without this, the FULL DISCOVERY branch runs but the
    # discovery step is skipped, leaving subdomains/dns empty and the rest of
    # the pipeline with no targets to chew on (silent failure).
    #
    # A wildcard group reaches here with include_root_domain False whenever the
    # operator did not also tick "include root", so the condition below cannot
    # save it — it would fall through to FULL DISCOVERY with discovery off and
    # produce an empty group that still exits 0. Refuse instead: a wildcard means
    # "enumerate", and a wildcard that cannot enumerate has nothing to scan.
    if not discovery_enabled and target_info.get("wildcard_mode"):
        if not target_info["full_subdomains"]:
            raise RuntimeError(
                f"'{target_info['root_domain']}' was listed as a wildcard "
                f"(enumerate) but Subdomain Discovery is disabled and no hosts "
                f"were listed for it, so there is nothing to scan. Enable "
                f"Subdomain Discovery, or replace the wildcard with hostnames."
            )
        target_info["filtered_mode"] = True
        # The graph property means "this domain WAS enumerated", and this group
        # is about to not be. Leaving it set would label a filtered scan as a
        # full one on the Domain node, which is the exact ambiguity the property
        # was added to remove.
        target_info["wildcard_mode"] = False
        print("[*][Pipeline] Wildcard + discovery disabled → FILTERED MODE over "
              "the explicitly listed hosts only")

    if (
        not target_info["filtered_mode"]
        and target_info.get("include_root_domain")
        and not discovery_enabled
    ):
        target_info["filtered_mode"] = True
        if target_info["root_domain"] not in target_info["full_subdomains"]:
            target_info["full_subdomains"].append(target_info["root_domain"])
        print("[*][Pipeline] Discovery disabled + root-domain-only → forcing FILTERED MODE")

    filtered_mode = target_info["filtered_mode"]
    root_domain = target_info["root_domain"]
    full_subdomains = target_info["full_subdomains"]

    print(f"[*][Pipeline] Target: {root_domain}")
    if filtered_mode:
        print(f"[*][Pipeline] Mode: FILTERED SUBDOMAIN SCAN")
        print(f"[*][Pipeline] Subdomains: {', '.join(full_subdomains)}")
    else:
        if target_info.get("wildcard_mode"):
            print(f"[*][Pipeline] Mode: FULL DISCOVERY (wildcard)")
        else:
            print(f"[*][Pipeline] Mode: FULL DISCOVERY (all subdomains)")

    # Setup output file and background graph executor. In a Domain batch each
    # group writes its OWN file; sharing the canonical one would make every group
    # overwrite the last, leaving a "whole batch" file describing one domain.
    _graph_reset()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output_file = recon_output_file(
        OUTPUT_DIR, PROJECT_ID, target_info["root_domain"] if _batch_groups() else None)

    # Initialize result structure with dynamic scan_type and empty modules_executed
    combined_result = {
        "metadata": {
            "scan_type": build_scan_type(),
            "scan_timestamp": datetime.now().isoformat(),
            "target": root_domain,
            "root_domain": root_domain,
            "user_id": USER_ID,
            "project_id": PROJECT_ID,
            "filtered_mode": filtered_mode,
            "wildcard_mode": bool(target_info.get("wildcard_mode")),
            **_scope_metadata(target_info, root_domain, filtered_mode),
            # Keys a domain-level finding (SPF, DMARC...) on its root, so a
            # batch's roots do not share one Vulnerability node (vuln_mixin).
            "domain_batch": bool(_batch_groups()),
            "subdomain_filter": full_subdomains if filtered_mode else [],
            "anonymous_mode": False,
            "bruteforce_mode": bruteforce if not filtered_mode else False,
            "modules_executed": [],
            "circuit_breakers": _breaker_mode(),
        },
        "domain": root_domain,
        "whois": {},
        "subdomains": [],
        "subdomain_count": 0,
        "dns": {}
    }
    # The batch's roots for the graph writers (urlscan/uncover/domain-discovery
    # write from inside this function, before it returns), not the scan scope.
    _stamp_project_roots(combined_result)

    # =====================================================================
    # GROUP 1 — Fan-Out: WHOIS + Subdomain Discovery + URLScan (parallel)
    # All three only need root_domain — no dependencies between them.
    # =====================================================================
    dns_enabled = _settings.get('DNS_ENABLED', True)

    if filtered_mode:
        # FILTERED MODE: skip discovery, just resolve the specified subdomains
        # WHOIS + URLScan can still run in parallel
        combined_result["subdomains"] = full_subdomains
        combined_result["subdomain_count"] = len(full_subdomains)

        print(f"\n[*][Pipeline] GROUP 1: WHOIS + URLScan (parallel)")
        print("-" * 40)
        whois_scope = _whois_scope()
        with ThreadPoolExecutor(max_workers=2, thread_name_prefix="group1") as g1_exec:
            g1_futures = {}
            if _settings.get('WHOIS_ENABLED', True):
                g1_futures["whois"] = g1_exec.submit(
                    _org_whois, target_info.get("org_domain") or root_domain)
            if _settings.get('URLSCAN_ENABLED'):
                from recon.main_recon_modules.urlscan_enrich import run_urlscan_discovery_only
                g1_futures["urlscan"] = g1_exec.submit(
                    run_urlscan_discovery_only, root_domain, _settings,
                    target_info.get("org_domain") or root_domain
                )

            for name, future in g1_futures.items():
                try:
                    result = future.result()
                    if name == "whois":
                        combined_result["whois"] = result.get("whois_data", {})
                        combined_result["metadata"]["modules_executed"].append("whois")
                        if combined_result["whois"]:
                            print(f"[+][WHOIS] Data retrieved successfully")
                        else:
                            print(f"[-][WHOIS] No WHOIS record for {root_domain}")
                    elif name == "urlscan":
                        if result:
                            combined_result["urlscan"] = result
                            combined_result["metadata"]["modules_executed"].append("urlscan_enrich")
                            print(f"[+][URLScan] Discovery complete")
                except Exception as e:
                    print(f"[!][{name}] Failed: {e}")
                    if name == "urlscan":
                        _note_phase_error("urlscan")
        whois_scope.finish("whois")

        if not _settings.get('WHOIS_ENABLED', True):
            combined_result["whois"] = {"skipped": True}

        # DNS resolution for filtered subdomains
        if dns_enabled:
            print(f"\n[*][DNS] GROUP 2: Filtered Subdomain DNS Resolution")
            print("-" * 40)
            from recon.main_recon_modules.domain_recon import dns_lookup, resolve_all_dns
            include_root = target_info.get("include_root_domain", False)
            # Use parallel resolve_all_dns for filtered subdomains too
            dns_workers = _settings.get('DNS_MAX_WORKERS', 50)
            dns_record_parallel = _settings.get('DNS_RECORD_PARALLELISM', True)
            dns_result = resolve_all_dns(root_domain, full_subdomains, max_workers=dns_workers, record_parallelism=dns_record_parallel, settings=_settings)
            domain_dns = dns_result["domain"] if include_root else {}
            combined_result["dns"] = {
                "domain": domain_dns,
                "subdomains": dns_result["subdomains"]
            }
            combined_result["metadata"]["include_root_domain"] = include_root
            combined_result["metadata"]["modules_executed"].append("dns_resolution")
        else:
            print(f"\n[-][DNS] GROUP 2: DNS Resolution — SKIPPED (disabled)")
            combined_result["metadata"]["include_root_domain"] = target_info.get("include_root_domain", False)

    else:
        # FULL DISCOVERY MODE: WHOIS + Discovery + URLScan all in parallel
        print(f"\n[*][Pipeline] GROUP 1: WHOIS + Subdomain Discovery + URLScan (parallel fan-out)")
        print("-" * 40)
        whois_scope = _whois_scope()

        with ThreadPoolExecutor(max_workers=3, thread_name_prefix="group1") as g1_exec:
            g1_futures = {}

            if _settings.get('WHOIS_ENABLED', True):
                g1_futures["whois"] = g1_exec.submit(
                    _org_whois, target_info.get("org_domain") or root_domain)

            if discovery_enabled:
                g1_futures["discovery"] = g1_exec.submit(
                    discover_subdomains, root_domain,
                    bruteforce=bruteforce,
                    resolve=dns_enabled, save_output=False, settings=_settings
                )
            else:
                print(f"[-][Discovery] Subdomain discovery disabled -- using root domain only")

            if _settings.get('URLSCAN_ENABLED'):
                from recon.main_recon_modules.urlscan_enrich import run_urlscan_discovery_only
                g1_futures["urlscan"] = g1_exec.submit(
                    run_urlscan_discovery_only, root_domain, _settings,
                    target_info.get("org_domain") or root_domain
                )

            g1_results = {}
            for name, future in g1_futures.items():
                try:
                    g1_results[name] = future.result()
                except Exception as e:
                    print(f"[!][{name}] Failed: {e}")
                    g1_results[name] = None
                    if name == "urlscan":
                        _note_phase_error("urlscan")

        whois_scope.finish("whois")

        # Fan-in: merge Group 1 results
        print(f"\n[*][Pipeline] Fan-in — merging parallel results")

        # WHOIS
        whois_data = g1_results.get("whois")
        if whois_data:
            combined_result["whois"] = whois_data.get("whois_data", {})
            combined_result["metadata"]["modules_executed"].append("whois")
            if combined_result["whois"]:
                print(f"[+][WHOIS] Data merged")
            else:
                print(f"[-][WHOIS] No WHOIS record for {root_domain}")
        elif not _settings.get('WHOIS_ENABLED', True):
            combined_result["whois"] = {"skipped": True}

        # Subdomain discovery
        recon_result = g1_results.get("discovery")
        if recon_result:
            combined_result["metadata"]["modules_executed"].append("subdomain_discovery")
            if recon_result.get("external_domains"):
                combined_result["domain_discovery_external_domains"] = recon_result["external_domains"]

        # F1: the names urlscan saw recently join the scan, only where
        # discovery itself runs (never in filtered mode or with discovery off).
        _urlscan_names = []
        if discovery_enabled and g1_results.get("urlscan"):
            from recon.main_recon_modules.urlscan_enrich import injectable_hosts
            _urlscan_names = [(h, "urlscan") for h in injectable_hosts(g1_results["urlscan"], _settings)]
        merged = merge_group_hosts(
            recon_result, target_info, root_domain, _settings, dns_enabled,
            extra_hosts=_urlscan_names)
        discovered_subs = merged["subdomains"]
        if merged.get("injected"):
            combined_result["metadata"]["urlscan_injected_hosts"] = merged["injected"]

        combined_result["subdomains"] = discovered_subs
        combined_result["subdomain_count"] = len(discovered_subs)
        combined_result["dns"] = merged["dns"]
        combined_result["subdomain_status_map"] = merged["status_map"]
        combined_result["wildcard_zones"] = merged["wildcard_zones"]
        wildcard_filter = ((recon_result or {}).get("metadata") or {}).get("wildcard_filter")
        if wildcard_filter:
            combined_result["metadata"]["wildcard_filter"] = wildcard_filter
        # Always stamped: a missing key defaults to True in target_helpers, which
        # would scan the apex the operator deliberately left out.
        combined_result["metadata"]["include_root_domain"] = merged["include_root"]
        if discovered_subs:
            combined_result["metadata"]["modules_executed"].append("dns_resolution")
            print(f"[+][Discovery] Merged: {len(discovered_subs)} subdomains")
        else:
            print(f"[!][Discovery] Produced no results")

        # URLScan
        urlscan_data = g1_results.get("urlscan")
        if urlscan_data:
            combined_result["urlscan"] = urlscan_data
            combined_result["metadata"]["modules_executed"].append("urlscan_enrich")
            print(f"[+][URLScan] Data merged")

    save_recon_file(combined_result, output_file)
    print(f"[✓][Pipeline] Saved: {output_file}")

    # Background graph update: domain discovery + URLScan discovery
    _graph_update_bg("update_graph_from_domain_discovery", combined_result, USER_ID, PROJECT_ID)
    if "urlscan" in combined_result:
        _graph_update_bg("update_graph_from_urlscan_discovery", combined_result, USER_ID, PROJECT_ID)
        # Its own writer, right after discovery on the one graph worker: the
        # findings never depend on httpx running.
        _graph_update_bg("update_graph_from_urlscan_findings", combined_result, USER_ID, PROJECT_ID)

    # =====================================================================
    # GROUP 2b — Uncover Target Expansion (before port scan / OSINT)
    # =====================================================================
    if _settings.get('OSINT_ENRICHMENT_ENABLED', False) and _settings.get('UNCOVER_ENABLED', False):
        try:
            from recon.main_recon_modules.uncover_enrich import run_uncover_expansion, merge_uncover_into_pipeline
            uncover_data = run_uncover_expansion(combined_result, _settings)
            if uncover_data:
                combined_result["uncover"] = uncover_data
                # THIS group's root, not the module-level TARGET_DOMAIN: in a
                # Domain batch the global is empty, so every group's expansion
                # would be merged against the wrong (or no) domain.
                _before = _dns_names(combined_result)
                merge_uncover_into_pipeline(
                    combined_result, uncover_data, target_info["root_domain"],
                    settings=_settings)
                # Before the port scan: their addresses are all it needs (F2).
                _late_names(combined_result, _before, _settings, output_file,
                            after_port_scan=False, probe_http=False, label="Uncover")
                combined_result["metadata"]["modules_executed"].append("uncover_expansion")
                save_recon_file(combined_result, output_file)
                _graph_update_bg("update_graph_from_uncover", combined_result, USER_ID, PROJECT_ID)
        except Exception as e:
            print(f"[!][Uncover] Expansion failed: {e}")

    # =====================================================================
    # GROUP 3 — Fan-Out: Shodan + Port Scan (parallel)
    # Both need IPs/hostnames from DNS. Independent of each other.
    # =====================================================================
    shodan_enabled = _settings.get('SHODAN_ENABLED', True) and any([
        _settings.get('SHODAN_HOST_LOOKUP'),
        _settings.get('SHODAN_REVERSE_DNS'),
        _settings.get('SHODAN_DOMAIN_DNS'),
        _settings.get('SHODAN_PASSIVE_CVES'),
    ])

    naabu_enabled = _settings.get('NAABU_ENABLED', True)
    masscan_enabled = _settings.get('MASSCAN_ENABLED', True)

    if "port_scan" in SCAN_MODULES and not naabu_enabled and not masscan_enabled:
        print("\n[!][Pipeline] Both Naabu and Masscan are disabled — skipping port scan phase")
        print("[!][Pipeline] Downstream modules (HTTP probe, vuln scan) require open ports to work")

    if shodan_enabled or "port_scan" in SCAN_MODULES:
        print(f"\n[*][Pipeline] GROUP 3: Shodan + Port Scan (parallel fan-out)")
        print("-" * 40)

        port_scan_workers = (1 if naabu_enabled else 0) + (1 if masscan_enabled else 0)
        max_workers = (1 if shodan_enabled else 0) + (port_scan_workers if "port_scan" in SCAN_MODULES else 0)
        max_workers = max(max_workers, 1)
        with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="group3") as g3_exec:
            g3_futures = {}

            if shodan_enabled:
                from recon.main_recon_modules.shodan_enrich import run_shodan_enrichment_isolated
                g3_futures["shodan"] = g3_exec.submit(
                    run_shodan_enrichment_isolated, combined_result, _settings
                )

            if naabu_enabled and "port_scan" in SCAN_MODULES:
                g3_futures["port_scan"] = g3_exec.submit(
                    run_port_scan_isolated, combined_result, _settings
                )

            if masscan_enabled and "port_scan" in SCAN_MODULES:
                g3_futures["masscan_scan"] = g3_exec.submit(
                    run_masscan_scan_isolated, combined_result, _settings
                )

            # Fan-in: merge results sequentially (safe — each writes different key)
            for name, future in g3_futures.items():
                try:
                    data = future.result()
                    if name == "shodan" and data:
                        combined_result["shodan"] = data
                        combined_result["metadata"]["modules_executed"].append("shodan_enrich")
                        print(f"[+][Shodan] Enrichment merged")
                    elif name == "port_scan" and data:
                        combined_result["port_scan"] = data
                        combined_result["metadata"]["modules_executed"].append("port_scan")
                        print(f"[+][Naabu] Port scan merged")
                    elif name == "masscan_scan" and data:
                        combined_result["masscan_scan"] = data
                        combined_result["metadata"]["modules_executed"].append("masscan_scan")
                        print(f"[+][Masscan] Port scan merged")
                except Exception as e:
                    print(f"[!][{name}] Failed: {e}")
                    _note_phase_error(name)

        # Merge masscan results into port_scan for downstream consumers
        if "masscan_scan" in combined_result:
            merge_port_scan_results(combined_result)

        _drop_shodan_cdn_ips(combined_result)
        _reachcheck_shodan_cves(combined_result, _settings)

        save_recon_file(combined_result, output_file)

        # Background graph updates for Shodan + port scan
        if "shodan" in combined_result:
            _graph_update_bg("update_graph_from_shodan", _without_shodan_cves(combined_result),
                             USER_ID, PROJECT_ID)

        if "port_scan" in combined_result:
            _graph_update_bg("update_graph_from_port_scan", combined_result, USER_ID, PROJECT_ID)

    # =====================================================================
    # GROUP 3.5 — Nmap Service Version Detection + NSE Vulnerability Scripts
    # Depends on: merged port_scan data (needs discovered open ports)
    # Runs sequentially AFTER port scan merge, BEFORE HTTP probe
    # =====================================================================
    nmap_enabled = _settings.get('NMAP_ENABLED', True)
    if nmap_enabled and "port_scan" in combined_result:
        print(f"\n[*][Pipeline] GROUP 3.5: Nmap Service Detection + NSE Vuln Scripts")
        print("-" * 40)

        try:
            from recon.main_recon_modules.nmap_scan import run_nmap_scan
            combined_result = run_nmap_scan(combined_result, output_file=output_file, settings=_settings)
            combined_result["metadata"]["modules_executed"].append("nmap_scan")

            # Merge Nmap service versions into port_scan.port_details
            if "nmap_scan" in combined_result:
                merge_nmap_into_port_scan(combined_result)

            save_recon_file(combined_result, output_file)

            if "nmap_scan" in combined_result:
                _graph_update_bg("update_graph_from_nmap", combined_result, USER_ID, PROJECT_ID)
        except Exception as e:
            print(f"[!][Pipeline] nmap failed: {e}")
            combined_result["metadata"].setdefault("phase_errors", {})["nmap"] = str(e)
            _note_phase_error("nmap")
            save_recon_file(combined_result, output_file)
    elif nmap_enabled:
        _note_nmap_without_port_data(combined_result, _settings)

    # =====================================================================
    # GROUP 3.6 — TLS certificate grab (tlsx)
    # Depends on: merged port_scan data. Runs BEFORE http_probe so SAN-derived
    # hostnames become probe targets, and before GROUP 6 so vhost_sni can use them.
    # Sequential (not a fan-out peer) because the SAN injection mutates shared
    # state GROUP 4 reads.
    # =====================================================================
    if _settings.get('TLSX_ENABLED', True) and "port_scan" in combined_result:
        print(f"\n[*][Pipeline] GROUP 3.6: TLS Certificate Grab")
        print("-" * 40)
        try:
            from recon.main_recon_modules.tls_scan import run_tlsx_enrichment
            combined_result = run_tlsx_enrichment(combined_result, settings=_settings)
            combined_result["metadata"]["modules_executed"].append("tlsx")
            if _settings.get('TLSX_INJECT_HOSTNAMES', True):
                from recon.helpers.target_helpers import merge_discovered_hostnames
                _before = _dns_names(combined_result)
                # root_domain is THIS group's own root (batch mode empties
                # metadata['root_domain'] precisely so a joined string can't be a
                # target); merge applies the apex test against it and fails closed.
                merge_discovered_hostnames(
                    combined_result,
                    (combined_result.get("tlsx") or {}).get("discovered_hostnames", []),
                    source="tlsx",
                    root_domain=root_domain,
                    settings=_settings,
                    max_injected=_settings.get('TLSX_MAX_INJECTED_HOSTNAMES', 200),
                )
                # After the port scan, before httpx: ports, then GROUP 4 probes them.
                _late_names(combined_result, _before, _settings, output_file,
                            after_port_scan=True, probe_http=False, label="tlsx")
            save_recon_file(combined_result, output_file)
            _graph_update_bg("update_graph_from_tlsx", combined_result, USER_ID, PROJECT_ID)
        except Exception as e:
            print(f"[!][Pipeline] tlsx failed: {e}")
            combined_result["metadata"].setdefault("phase_errors", {})["tlsx"] = str(e)

    # =====================================================================
    # GROUP 3b — OSINT Enrichment (parallel, passive — no packets to target)
    # Runs independently from port scanning; data feeds into the graph only.
    # =====================================================================
    _osint_tools = {
        'censys': ('CENSYS_ENABLED', 'recon.main_recon_modules.censys_enrich', 'run_censys_enrichment_isolated', 'update_graph_from_censys'),
        'fofa': ('FOFA_ENABLED', 'recon.main_recon_modules.fofa_enrich', 'run_fofa_enrichment_isolated', 'update_graph_from_fofa'),
        'otx': ('OTX_ENABLED', 'recon.main_recon_modules.otx_enrich', 'run_otx_enrichment_isolated', 'update_graph_from_otx'),
        'netlas': ('NETLAS_ENABLED', 'recon.main_recon_modules.netlas_enrich', 'run_netlas_enrichment_isolated', 'update_graph_from_netlas'),
        'virustotal': ('VIRUSTOTAL_ENABLED', 'recon.main_recon_modules.virustotal_enrich', 'run_virustotal_enrichment_isolated', 'update_graph_from_virustotal'),
        'zoomeye': ('ZOOMEYE_ENABLED', 'recon.main_recon_modules.zoomeye_enrich', 'run_zoomeye_enrichment_isolated', 'update_graph_from_zoomeye'),
        'criminalip': ('CRIMINALIP_ENABLED', 'recon.main_recon_modules.criminalip_enrich', 'run_criminalip_enrichment_isolated', 'update_graph_from_criminalip'),
    }

    if not _settings.get('OSINT_ENRICHMENT_ENABLED', False):
        enabled_osint = {}
    else:
        enabled_osint = {
            name: cfg for name, cfg in _osint_tools.items()
            if _settings.get(cfg[0], False)
            and (
                _settings.get(f'{name.upper()}_API_KEY', '')
                or (name == 'censys' and _settings.get('CENSYS_API_TOKEN', ''))
                or name == 'otx'  # OTX supports anonymous requests without an API key
            )
        }

    if enabled_osint:
        print(f"\n[*][Pipeline] GROUP 3b: OSINT Enrichment ({', '.join(enabled_osint.keys())}) — parallel")
        print("-" * 40)

        import importlib
        osint_workers = min(len(enabled_osint), 5)
        with ThreadPoolExecutor(max_workers=osint_workers, thread_name_prefix="osint") as osint_exec:
            osint_futures = {}
            for name, (_, module_path, func_name, _) in enabled_osint.items():
                mod = importlib.import_module(module_path)
                fn = getattr(mod, func_name)
                osint_futures[name] = osint_exec.submit(fn, combined_result, _settings)

            for name, future in osint_futures.items():
                try:
                    data = future.result()
                    if data:
                        combined_result[name] = data
                        combined_result["metadata"]["modules_executed"].append(f"{name}_enrich")
                        print(f"[+][{name.upper()}] Enrichment merged")
                except Exception as e:
                    print(f"[!][{name.upper()}] Enrichment failed: {e}")
                    _note_phase_error(name)

        save_recon_file(combined_result, output_file)

        # Queue graph updates for completed OSINT tools
        for name, (_, _, _, graph_method) in enabled_osint.items():
            if name == "netlas":
                continue  # written after IP attribution (_write_netlas)
            if name in combined_result:
                _graph_update_bg(graph_method, combined_result, USER_ID, PROJECT_ID)

    # =====================================================================
    # GROUP 4 — HTTP Probe (sequential, internally parallel via httpx threads)
    # Depends on: port scan data (open ports) + hostnames
    # =====================================================================
    if "http_probe" in SCAN_MODULES:
        if not _settings.get('HTTPX_ENABLED', True):
            print("\n[*][httpx] HTTP probing disabled -- skipping")
        else:
            print(f"\n[*][Pipeline] GROUP 4: HTTP Probing")
            try:
                combined_result = run_http_probe(combined_result, output_file=output_file, settings=_settings)
                combined_result["metadata"]["modules_executed"].append("http_probe")
                save_recon_file(combined_result, output_file)

                # Background graph updates
                _graph_update_bg("update_graph_from_http_probe", combined_result, USER_ID, PROJECT_ID)
            except Exception as e:
                print(f"[!][Pipeline] http_probe failed: {e}")
                combined_result["metadata"].setdefault("phase_errors", {})["http_probe"] = str(e)
                _note_phase_error("http_probe")
                save_recon_file(combined_result, output_file)

    # =====================================================================
    # Certificate SAN feedback (Phase 0.6)
    # httpx captures the full SAN list on every HTTPS port it probes and the
    # pipeline never read it back, so hostnames the target itself advertised
    # were discarded. Runs here, after GROUP 4, so the names reach vhost
    # (GROUP 6) and the graph; tlsx's own SANs were already merged at GROUP 3.6
    # and the scope filter is idempotent, so re-offering them is harmless.
    # Deliberately NOT gated on tlsx: this is the Phase 1.0 rule, gate on the
    # data you have, not on which tool produced it.
    # =====================================================================
    if _settings.get('TLSX_INJECT_HOSTNAMES', True):
        try:
            from recon.helpers.target_helpers import (
                collect_certificate_sans, merge_discovered_hostnames,
            )
            _san_names = collect_certificate_sans(combined_result)
            if _san_names:
                _before = _dns_names(combined_result)
                merge_discovered_hostnames(
                    combined_result, _san_names, source="certificate_san",
                    root_domain=root_domain, settings=_settings,
                    max_injected=_settings.get('TLSX_MAX_INJECTED_HOSTNAMES', 200),
                )
                # After httpx: these names get their own probe (F2).
                _late_names(combined_result, _before, _settings, output_file,
                            after_port_scan=True, probe_http=True, label="certificate SAN")
                save_recon_file(combined_result, output_file)
        except Exception as e:
            print(f"[!][Pipeline] certificate SAN feedback failed: {e}")

    # After the SAN feedback: a name it resolved counts as a current DNS name.
    _run_ip_attribution(combined_result, _settings, output_file)
    _write_shodan_cves(combined_result)
    _write_netlas(combined_result)

    # Item 5: which deleted-service pages urlscan recorded still describe their
    # host, decided with this scan's DNS and live pages. Outside the httpx step
    # (with httpx off the NXDOMAIN row still decides) and before Phase A, whose
    # copies Subdomain Takeover reads urlscan.takeover_hosts from.
    if (combined_result.get("urlscan") or {}).get("takeover_pages"):
        from recon.main_recon_modules.urlscan_takeover import run_takeover_verdict
        combined_result = run_takeover_verdict(combined_result, _settings)
        if (combined_result.get("urlscan") or {}).get("takeover_findings"):
            save_recon_file(combined_result, output_file)
            _graph_update_bg("update_graph_from_urlscan_takeover", combined_result, USER_ID, PROJECT_ID)

    # Check if we should skip active scanning modules (resource_enum, vuln_scan)
    # These require live targets from http_probe to work
    skip_active_scans, skip_reason = should_skip_active_scans(combined_result)

    if skip_active_scans:
        print(f"\n{'=' * 70}")
        print(f"[!][Pipeline] SKIPPING ACTIVE SCANS: {skip_reason}")
        print(f"[!][Pipeline] Modules skipped: resource_enum, vuln_scan")
        print(f"{'=' * 70}")
        combined_result["metadata"]["active_scans_skipped"] = True
        combined_result["metadata"]["active_scans_skip_reason"] = skip_reason
        save_recon_file(combined_result, output_file)
        combined_result = _maybe_run_cert_hygiene(combined_result, _settings, output_file)
    else:
        # GROUP 5 — Resource Enum (already parallel internally: Katana || GAU || Kiterunner)
        if "resource_enum" in SCAN_MODULES:
            print(f"\n[*][Pipeline] GROUP 5: Resource Enumeration")
            try:
                combined_result = run_resource_enum(combined_result, output_file=output_file, settings=_settings)
                combined_result["metadata"]["modules_executed"].append("resource_enum")
                save_recon_file(combined_result, output_file)
                _graph_update_bg("update_graph_from_resource_enum", combined_result, USER_ID, PROJECT_ID)
            except Exception as e:
                print(f"[!][Pipeline] resource_enum failed: {e}")
                combined_result["metadata"].setdefault("phase_errors", {})["resource_enum"] = str(e)
                _note_phase_error("resource_enum")
                save_recon_file(combined_result, output_file)

    # urlscan's enrichment writer only MATCHes existing BaseURLs, which httpx,
    # uncover and resource enumeration make: queued after GROUP 5's write, and
    # outside the httpx step so it still runs when httpx is off or fails.
    if 'urlscan' in combined_result:
        _graph_update_bg("update_graph_from_urlscan_enrichment", combined_result, USER_ID, PROJECT_ID)

    # GROUP 4.5 — AI Surface Recon (runs after resource_enum)
    combined_result = _maybe_run_ai_surface(combined_result, _settings, output_file)

    # GROUP 5b — JS Recon (runs after resource_enum, before vuln_scan;
    # runs even when active scans are skipped -- uploaded files don't need live targets)
    if _settings.get('JS_RECON_ENABLED', False):
        print(f"\n[*][Pipeline] GROUP 5b: JS Recon")
        try:
            from recon.main_recon_modules.js_recon import run_js_recon
            _before = _dns_names(combined_result)
            combined_result = run_js_recon(combined_result, settings=_settings)
            combined_result["metadata"]["modules_executed"].append("js_recon")
            save_recon_file(combined_result, output_file)
            _graph_update_bg("update_graph_from_js_recon", combined_result, USER_ID, PROJECT_ID)
            # After httpx and resource enumeration: their own probe (F2), in
            # time for the vulnerability scan.
            _late_names(combined_result, _before, _settings, output_file,
                        after_port_scan=True, probe_http=True, label="JS Recon")
        except Exception as e:
            print(f"[!][JsRecon] Error: {e}")
            _note_phase_error("js_recon")

    # GROUP 5b — Serialized-object detection (passive, in-memory; runs even when
    # active scans are skipped). Flags :Vulnerability candidates for the agent's
    # deserialization skill to confirm. Never deserializes.
    if _settings.get('SERIALIZED_SCAN_ENABLED', False):
        try:
            from recon.serialized_scan import run_serialized_scan
            combined_result = run_serialized_scan(combined_result, settings=_settings)
            combined_result["metadata"]["modules_executed"].append("serialized_scan")
            save_recon_file(combined_result, output_file)
            _graph_update_bg("update_graph_from_serialized_scan", combined_result, USER_ID, PROJECT_ID)
        except Exception as e:
            print(f"[!][SerializedScan] Error: {e}")
            _note_phase_error("serialized_scan")

    # GROUP 5.5 -- Supply-Chain Recon, after JS Recon as in IP mode.
    combined_result = _maybe_run_supply_chain(combined_result, _settings, output_file)

    if not skip_active_scans:
        # ================================================================
        # GROUP 6 Phase A — Parallel active vuln scanners (Nuclei || GraphQL)
        # ================================================================
        # Both scanners read BaseURL/Endpoint/Technology, both write Vulnerability,
        # and they have zero data dependency on each other. Run concurrently via
        # ThreadPoolExecutor using _isolated wrappers (each deep-copies the
        # combined_result so there's no shared-dict race).
        # ----------------------------------------------------------------
        phase_a_tools: dict = {}
        if "vuln_scan" in SCAN_MODULES:
            from recon.main_recon_modules.vuln_scan import run_vuln_scan_isolated
            phase_a_tools['vuln_scan'] = run_vuln_scan_isolated
        if _settings.get('GRAPHQL_SECURITY_ENABLED', False):
            from recon.graphql_scan import run_graphql_scan_isolated
            phase_a_tools['graphql_scan'] = run_graphql_scan_isolated
        if _settings.get('SUBDOMAIN_TAKEOVER_ENABLED', False):
            from recon.main_recon_modules.subdomain_takeover import run_subdomain_takeover_isolated
            phase_a_tools['subdomain_takeover'] = run_subdomain_takeover_isolated
        if _settings.get('VHOST_SNI_ENABLED', False):
            from recon.main_recon_modules.vhost_sni_enum import run_vhost_sni_enrichment_isolated
            phase_a_tools['vhost_sni'] = run_vhost_sni_enrichment_isolated
        if _settings.get('WEB_CACHE_POISON_ENABLED', False):
            from recon.cache_scan import run_cache_scan_isolated
            phase_a_tools['cache_scan'] = run_cache_scan_isolated
        if _settings.get('ORIGIN_DISCOVERY_ENABLED', False):
            from recon.main_recon_modules.origin_discovery import run_origin_discovery_enrichment_isolated
            phase_a_tools['origin_discovery'] = run_origin_discovery_enrichment_isolated
        if _settings.get('ROUTE_EXPOSURE_ENABLED', False):
            from recon.route_exposure import run_route_exposure_isolated
            phase_a_tools['route_exposure'] = run_route_exposure_isolated

        _run_phase_a_fan_out(phase_a_tools, combined_result, _settings, output_file)

        # ================================================================
        # GROUP 6 Phase B — MITRE enrichment (depends on Nuclei CVEs)
        # ================================================================
        if "vuln_scan" in SCAN_MODULES and _settings.get('MITRE_ENABLED', True) and 'vuln_scan' in combined_result:
            print(f"\n[*][Pipeline] GROUP 6 Phase B: MITRE CVE Enrichment")
            print("-" * 40)
            try:
                combined_result = run_mitre_enrichment(combined_result, output_file=output_file, settings=_settings)
                save_recon_file(combined_result, output_file)
                _graph_update_bg("update_graph_from_vuln_scan", combined_result, USER_ID, PROJECT_ID)
            except Exception as e:
                print(f"[!][Pipeline] mitre_enrichment failed: {e}")
                combined_result["metadata"].setdefault("phase_errors", {})["mitre_enrichment"] = str(e)
                save_recon_file(combined_result, output_file)

    # External Domains — aggregate from all sources and persist
    try:
        ext_domains = _aggregate_external_domains(combined_result)
        if ext_domains:
            combined_result["external_domains_aggregated"] = ext_domains
            save_recon_file(combined_result, output_file)
            _graph_update_bg("update_graph_from_external_domains", combined_result, USER_ID, PROJECT_ID)
    except Exception as e:
        print(f"[!][Pipeline] external_domains aggregation failed: {e}")

    _stamp_wildcard_zones(combined_result)

    # Wait for all background graph DB updates to finish before returning
    _graph_wait_all()

    # Print summary
    print(f"\n{'=' * 70}")
    print(f"[✓][Pipeline] DOMAIN RECON COMPLETE")
    if filtered_mode:
        print(f"[+][Pipeline] Mode: Filtered ({len(full_subdomains)} subdomain(s))")
    else:
        print(f"[+][Pipeline] Subdomains found: {combined_result['subdomain_count']}")

    # Port scan stats
    if "port_scan" in SCAN_MODULES and "port_scan" in combined_result:
        port_summary = combined_result["port_scan"].get("summary", {})
        naabu_ports = port_summary.get('total_open_ports', 0)
        print(f"[+][Naabu] Open ports: {naabu_ports}")

    # HTTP probe stats
    if "http_probe" in SCAN_MODULES and "http_probe" in combined_result:
        http_summary = combined_result["http_probe"].get("summary", {})
        live_urls = http_summary.get('live_urls', 0)
        print(f"[+][Httpx] Live URLs: {live_urls}")
        print(f"[+][Httpx] Technologies: {http_summary.get('technology_count', 0)}")
        # Report httpx-discovered service ports when Naabu found none
        if live_urls > 0 and "port_scan" in combined_result:
            naabu_ports_count = combined_result["port_scan"].get("summary", {}).get("total_open_ports", 0)
            if naabu_ports_count == 0:
                from urllib.parse import urlparse
                httpx_ports = set()
                for url in combined_result["http_probe"].get("by_url", {}):
                    p = urlparse(url)
                    httpx_ports.add(p.port or (443 if p.scheme == "https" else 80))
                if httpx_ports:
                    print(f"[+][Httpx] Service ports (from httpx): {', '.join(str(p) for p in sorted(httpx_ports))}")

    # Check if active scans were skipped
    active_scans_skipped = combined_result.get("metadata", {}).get("active_scans_skipped", False)

    # Resource enumeration stats
    if active_scans_skipped:
        print(f"[!][Pipeline] Resource enum: SKIPPED (no live targets)")
    elif "resource_enum" in SCAN_MODULES and "resource_enum" in combined_result:
        resource_summary = combined_result["resource_enum"].get("summary", {})
        print(f"[+][ResourceEnum] Endpoints: {resource_summary.get('total_endpoints', 0)}")
        print(f"[+][ResourceEnum] Parameters: {resource_summary.get('total_parameters', 0)}")
        print(f"[+][ResourceEnum] Forms (POST): {resource_summary.get('total_forms', 0)}")

    # Vuln scan stats (includes MITRE enrichment)
    if active_scans_skipped:
        print(f"[!][Pipeline] Vuln scan: SKIPPED (no live targets)")
    elif "vuln_scan" in SCAN_MODULES and "vuln_scan" in combined_result:
        vuln_summary = combined_result["vuln_scan"].get("summary", {})
        vuln_total = combined_result["vuln_scan"].get("vulnerabilities", {}).get("total", 0)
        print(f"[+][Nuclei] Vuln findings: {vuln_summary.get('total_findings', 0)} ({vuln_total} vulnerabilities)")

        # MITRE enrichment stats (part of vuln_scan)
        mitre_meta = combined_result.get("metadata", {}).get("mitre_enrichment", {})
        if mitre_meta:
            print(f"[+][MITRE] Enriched: {mitre_meta.get('total_cves_enriched', 0)}/{mitre_meta.get('total_cves_processed', 0)} CVEs")

    # GraphQL security stats
    if _settings.get('GRAPHQL_SECURITY_ENABLED', False) and "graphql_scan" in combined_result:
        graphql_summary = combined_result["graphql_scan"].get("summary", {})
        endpoints_tested = graphql_summary.get('endpoints_tested', 0)
        if endpoints_tested > 0:
            print(f"[+][GraphQL] Endpoints tested: {endpoints_tested}")
            print(f"[+][GraphQL] Introspection enabled: {graphql_summary.get('introspection_enabled', 0)}")
            vulns = graphql_summary.get('vulnerabilities_found', 0)
            if vulns > 0:
                print(f"[+][GraphQL] Vulnerabilities: {vulns} " +
                      f"(Critical: {graphql_summary['by_severity']['critical']}, " +
                      f"High: {graphql_summary['by_severity']['high']}, " +
                      f"Medium: {graphql_summary['by_severity']['medium']})")

    # Web cache poisoning stats
    if _settings.get('WEB_CACHE_POISON_ENABLED', False) and "cache_scan" in combined_result:
        cache_summary = combined_result["cache_scan"].get("summary", {})
        total = cache_summary.get('total_findings', 0)
        if total > 0:
            print(f"[+][CachePoison] Findings: {total} "
                  f"(Confirmed: {cache_summary.get('confirmed', 0)}, "
                  f"Strong: {cache_summary.get('strong', 0)}) "
                  f"across {cache_summary.get('cacheable_urls', 0)} cacheable URL(s)")

    print(f"[+][Pipeline] Output saved: {output_file}")
    print(f"{'=' * 70}")

    return combined_result


from recon.helpers.finding_sources import PASSIVE_CVE_SOURCES, RECON_FINDING_SOURCES  # noqa: E402

#: When this run started. Everything it writes gets a later `updated_at`, so the
#: prune at the end can tell "still reported" from "gone".
_RUN_STARTED_AT = None


def _clear_recon_graph():
    """Clear this project's previous recon ASSETS. Runs ONCE per pipeline run.

    Findings are deliberately NOT cleared here any more (X7). Deleting them up
    front deleted the operator's work with them: the mute they applied, the
    verdict they recorded, the AI's cached review, and the link from a fix item
    back to the finding. They are pruned after a SUCCESSFUL run instead, by
    `_prune_recon_findings`.

    Domain batch depends on this running once: the groups accumulate into a
    single graph, so clearing per group would leave only the last domain.
    """
    global _RUN_STARTED_AT
    if not UPDATE_GRAPH_DB:
        return
    print("[*][graph-db] Clearing previous recon assets for this project...")
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                from graph_db.mixins.base_mixin import run_timestamp
                _RUN_STARTED_AT = run_timestamp()
                clear_stats = graph_client.clear_recon_data(USER_ID, PROJECT_ID)
                print(f"[+][graph-db] Previous recon assets cleared: {clear_stats['nodes_deleted']} nodes removed\n")
            else:
                print("[!][graph-db] Could not connect to Neo4j - skipping clear\n")
    except Exception as e:
        print(f"[!][graph-db] Failed to clear previous graph data: {e}\n")


#: Set when any `_write_coverage_record` of this run failed. The prune then
#: cannot know what the run covered, so it does nothing (fail closed).
_COVERAGE_WRITE_FAILED = False


def _org_for_root(root: str) -> str:
    """The registrable domain a scan root's hosts attach to; the root itself in
    IP mode or when no group names it."""
    for group in settings_scope_groups(_settings):
        if group.get('scanRoot') == root:
            return group.get('orgDomain') or root
    return root


def _write_coverage_record(domain: str, group=None) -> bool:
    """Stamp this run's coverage record for scan root `domain` on its org's
    Domain node. Synchronous.

    Written for every full-run group, clean or not (see update_graph_coverage).
    Deliberately NOT through `_graph_update_bg`: by now `_graph_wait_all()` has
    torn that executor down, and a late submit is silently dropped. Any failure
    - no graph, no Domain node, an exception - marks the run's coverage unknown,
    which blocks the finding prune. `group` is the batch group's GroupScope, so
    the record carries only what that group cut.
    """
    global _COVERAGE_WRITE_FAILED
    if not UPDATE_GRAPH_DB:
        return True
    try:
        from recon.helpers import circuit_breaker
        from graph_db import Neo4jClient
        from graph_db.mixins.base_mixin import run_timestamp
        report = group.report() if group is not None else circuit_breaker.coverage_report()
        # Each gap names the scan root it came from, so a reader can drop the
        # gaps of a root since removed from scope (§4.11.7).
        gaps = json.loads(report.gaps_json() or "[]")
        for gap in gaps:
            if isinstance(gap, dict):
                gap.setdefault("root", domain)
        with Neo4jClient() as graph_client:
            if not graph_client.verify_connection():
                raise RuntimeError("Neo4j not reachable")
            # On the org's Domain; the org's groups of this run merge into one
            # record, keyed on when the run started.
            matched = graph_client.update_graph_coverage(USER_ID, PROJECT_ID, domain, {
                "at": run_timestamp(),
                "gaps_json": json.dumps(gaps, sort_keys=True, separators=(",", ":")),
                "skipped_hosts": report.stored_skipped_hosts(),
                "nuclei_truncated": report.nuclei_truncated,
                "org_domain": _org_for_root(domain),
            }, run_started_at=_RUN_STARTED_AT)
        if not matched:
            raise RuntimeError("no Domain node to stamp")
        return True
    except Exception as e:  # noqa: BLE001 - a housekeeping failure must not fail the scan
        _COVERAGE_WRITE_FAILED = True
        print(f"[!][graph-db] Coverage record not written ({type(e).__name__}) - "
              f"the finding prune is skipped for this run")
        return False


#: The orgs of the groups that passed RoE and ownership this run, in order.
_RUN_ORGS: list = []


def _note_run_org(org: str) -> None:
    if org and org not in _RUN_ORGS:
        _RUN_ORGS.append(org)


def _enabled_dns_check_types() -> list:
    """The DNS check types this run's settings mean to run, as vuln_scan reads them."""
    from recon.helpers.security_checks import DNS_CHECK_TYPES
    if "vuln_scan" not in SCAN_MODULES or not _settings.get("SECURITY_CHECK_ENABLED", True):
        return []
    return [t for t in DNS_CHECK_TYPES if _settings.get(f"SECURITY_CHECK_{t.upper()}", True)]


def _note_unchecked_dns_orgs() -> None:
    """Keep the previous DNS findings (SPF, DMARC, DNSSEC, zone transfer) of
    each org whose DNS checks ran in no group this run (no live URL, an RoE
    refusal), and only those.

    The enabled DNS check types are recorded as re-checked on no host
    (positive coverage, D1), so the prune deletes their findings only on the
    orgs run_dns_checks did check, and every other security_check finding
    prunes as usual. DNS checks switched off by configuration record nothing:
    their findings are pruned (README "Degraded vs. switched off").
    """
    from recon.helpers import circuit_breaker
    from recon.helpers.org_work import claimed_orgs
    enabled = _enabled_dns_check_types()
    if not enabled:
        return
    checked = set(claimed_orgs("dns_checks"))
    unchecked = [org for org in _RUN_ORGS if org.lower() not in checked]
    if not unchecked:
        return
    print(f"[*][graph-db] DNS checks ran for no group of {', '.join(unchecked)}: "
          f"their DNS findings are kept")
    circuit_breaker.note_checked("security_check", checks=enabled, module="security_checks")


def _checked_prune_batches(report, sources) -> dict:
    """``(keep_hosts, only_hosts, types, exclude_types)`` -> the positive
    sources pruned with them.

    A source that recorded what it re-checked (``circuit_breaker.note_checked``)
    is pruned once per check it recorded, on the hosts it re-checked minus
    those cut for it. The cut hosts are also passed as kept, so a finding that
    names one in any host field stays (degraded wins). Sources with the same
    record share one call, as Shodan's source values do.

    A source that recorded only some of its checks (security_check's DNS and
    service probes) is also pruned once by the source-level rule for every
    other finding type (``only_hosts`` None, those checks excluded), so a
    check that records nothing, or is switched off, prunes as before.
    """
    batches: dict = {}
    for source in sources:
        keep = report.keep_hostnames(source)
        checks = report.checked_types(source)
        for check in checks:
            key = (keep, report.checked_hostnames(source, check),
                   None if check == "*" else (check,), None)
            batches.setdefault(key, []).append(source)
        if "*" not in checks:
            batches.setdefault((keep, None, None, checks), []).append(source)
    return batches


def _org_check_batch(key) -> bool:
    """A per-type batch of a check whose findings name only their org (DNS)."""
    from recon.helpers.security_checks import DNS_CHECK_TYPES
    types = key[2]
    return bool(types) and set(types) <= set(DNS_CHECK_TYPES)


def _prune_recon_findings():
    """Remove the findings this run stopped reporting. AFTER a successful run.

    Only called on the success path, and never when the clear did not run: a
    scan that failed halfway reported nothing, and pruning on that would delete
    the project's entire finding set.

    Findings an operator muted and human-judged ones are kept and stamped stale
    rather than deleted, so an operator can see that a scanner stopped
    reporting something they had already suppressed. A node-filter rule's mute
    is not an operator's decision, so those are pruned like any other.

    A degraded run never deletes what it did not re-check: a source whose
    coverage was cut is left out of the prune, and every finding on a host the
    run skipped as unreachable is kept. A host only one tool gave up on (an nmap
    host timeout) keeps that tool's findings alone, since the others re-checked
    it. If the run's coverage cannot be established at all, nothing is pruned
    (fail closed).

    A source that recorded the hosts it re-checked (positive coverage, D1) is
    pruned on those hosts only, so a host it never reached keeps its findings
    even when nothing noted it degraded. Every other source keeps the rule
    above, and so do the finding types a source recorded nothing for
    (security_check records only its DNS and service probes).
    """
    if not UPDATE_GRAPH_DB or not _RUN_STARTED_AT:
        return
    if _shutdown.stop_requested():
        # Its killed tools returned empty results, which would read as "gone".
        print("[!][graph-db] Finding prune skipped: the run was stopped")
        return
    if _COVERAGE_WRITE_FAILED:
        print("[!][graph-db] Finding prune skipped: this run's coverage record was not written")
        return
    _note_unchecked_dns_orgs()
    try:
        from recon.helpers import circuit_breaker
        report = circuit_breaker.coverage_report()
    except Exception:  # noqa: BLE001 - unknown coverage means no prune
        print("[!][graph-db] Finding prune skipped: this run's coverage is unknown")
        return
    sources = [s for s in RECON_FINDING_SOURCES if s not in report.degraded_sources]
    keep_hosts = report.skipped_hostnames()
    if report.degraded_sources or keep_hosts:
        cut = sorted(report.degraded_sources)
        print(f"[*][graph-db] Findings this run could not re-check are kept: "
              f"{len(cut)} source(s) cut ({', '.join(cut) or 'none'}), "
              f"findings on {len(keep_hosts)} unreachable host(s)")
        for source, hosts in report.source_hosts:
            print(f"[*][graph-db]   {len(hosts)} of those host(s) only for {source}")
    positive = [s for s in sources if s in report.positive_sources]
    if positive:
        print(f"[*][graph-db] {len(positive)} source(s) prune only the hosts they "
              f"re-checked ({', '.join(positive)})")
    # One prune per distinct keep set. With no per-source host every source
    # shares one set, which is the single call a run has always made.
    batches: dict = {}
    for source in sources:
        if source not in report.positive_sources:
            batches.setdefault(report.keep_hostnames(source), []).append(source)
    checked_batches = _checked_prune_batches(report, positive)
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                # A host kept above is matched on the finding's host fields;
                # passive CVEs written before they carried one get it first.
                try:
                    graph_client.backfill_passive_cve_hosts(USER_ID, PROJECT_ID)
                except Exception as e:  # noqa: BLE001 - fail closed for those sources only
                    print(f"[!][graph-db] Could not backfill passive CVE hosts ({e}) - "
                          f"passive CVEs are not pruned this run")
                    passive = {s for group in PASSIVE_CVE_SOURCES.values() for s in group}
                    batches = {keep: [s for s in batch if s not in passive]
                               for keep, batch in batches.items()}
                    checked_batches = {key: [s for s in batch if s not in passive]
                                       for key, batch in checked_batches.items()}
                # DNS findings are matched on their org, which ones written
                # before they stored it get first.
                if any("security_check" in batch and _org_check_batch(key)
                       for key, batch in checked_batches.items()):
                    try:
                        graph_client.backfill_security_check_domains(USER_ID, PROJECT_ID)
                    except Exception as e:  # noqa: BLE001 - fail closed for those checks only
                        print(f"[!][graph-db] Could not backfill DNS finding orgs ({e}) - "
                              f"DNS security findings are not pruned this run")
                        checked_batches = {
                            key: [s for s in batch
                                  if not (s == "security_check" and _org_check_batch(key))]
                            for key, batch in checked_batches.items()}
                for keep, batch in batches.items():
                    graph_client.prune_unseen_findings(
                        USER_ID, PROJECT_ID, batch, _RUN_STARTED_AT,
                        keep_hosts=keep)
                for (keep, hosts, types, others), batch in checked_batches.items():
                    if not batch:
                        continue
                    if hosts is None:
                        graph_client.prune_unseen_findings(
                            USER_ID, PROJECT_ID, batch, _RUN_STARTED_AT,
                            keep_hosts=keep, exclude_types=others)
                    else:
                        graph_client.prune_unseen_findings(
                            USER_ID, PROJECT_ID, batch, _RUN_STARTED_AT,
                            keep_hosts=keep, only_hosts=hosts, types=types)
    except Exception as e:
        # Never fail a completed scan over housekeeping: a finding that should
        # have been pruned is visible and wrong, which beats losing the run.
        print(f"[!][graph-db] Could not prune stale findings: {e}\n")


# The finding sources each pipeline phase writes. A phase that raised
# re-checked none of them, so its sources are left out of the prune.
_PHASE_FINDING_SOURCES = {
    "http_probe": ("http_probe",),
    "nmap": ("nmap_nse",),
    "resource_enum": ("resource_enum", "jsluice", "url_archive"),
    "ai_surface_recon": ("ai_surface_recon",),
    "js_recon": ("js_recon",),
    "vuln_scan": ("nuclei", "security_check", "vuln_scan"),
    "cert_hygiene": ("security_check",),
    "graphql_scan": ("graphql_scan", "graphql_cop"),
    "subdomain_takeover": ("takeover_scan",),
    "vhost_sni": ("vhost_sni_enum",),
    "cache_scan": ("cache_poisoning", "wcvs"),
    "origin_discovery": ("origin_discovery",),
    "serialized_scan": ("serialized_scan",),
    "route_exposure": ("route_exposure",),
    "urlscan": ("urlscan_leak", "urlscan"),
    **PASSIVE_CVE_SOURCES,
}


def _note_phase_error(phase: str, reason: str = "the phase failed") -> None:
    """Record a crashed phase's finding sources as not re-checked. Never raises."""
    sources = _PHASE_FINDING_SOURCES.get(phase)
    if not sources:
        return
    try:
        if phase in PASSIVE_CVE_SOURCES:
            from recon.helpers.passive_cve_coverage import note_cve_coverage
            note_cve_coverage(phase, phase, failed=True, reason=reason)
            return
        from recon.helpers import circuit_breaker
        circuit_breaker.note_degraded(phase, sources=sources, reason=reason)
    except Exception:  # noqa: BLE001
        pass


def _note_nmap_without_port_data(combined_result: dict, settings: dict) -> None:
    """nmap is on and a port scan was meant to feed it, but none came back.

    The port scan's isolated wrapper returns {} for a failure, a timeout and a
    crash alike, so nmap is skipped without a word and the prune would read
    "no nmap_nse finding this run" as "every one is gone". The port scan
    itself writes no finding source (Port nodes are assets), so nmap_nse is
    the only finding source its failure leaves unchecked. A port scan turned
    off by configuration, or one with no target at all, is not a gap: nmap was
    not meant to run, or had nothing to re-check.
    """
    if not settings.get('NMAP_ENABLED', True) or "port_scan" in combined_result:
        return
    if "port_scan" not in SCAN_MODULES or not (
            settings.get('NAABU_ENABLED', True) or settings.get('MASSCAN_ENABLED', True)):
        return
    try:
        from recon.helpers import extract_targets_from_recon
        ips, hostnames, _ = extract_targets_from_recon(combined_result)
        if not ips and not hostnames:
            return
    except Exception:  # noqa: BLE001 - unknown targets: keep the findings
        pass
    print("[!][Pipeline] The port scan returned no data - nmap skipped, "
          "previous nmap NSE findings are kept")
    _note_phase_error("nmap", reason="no port scan data")


def _apply_node_filters():
    """Apply the project's node filters to what this run wrote. ONCE per run.

    Called from main()'s `finally`, never per group: a Domain batch would
    otherwise sweep N times, and a group that returned early would skip it.
    The rules are re-read here, at sweep time, not taken from scan start, so
    the sweep applies the operator's latest save.

    Housekeeping: `run_node_filter_sweep` never raises, so the job's exit code
    is whatever the pipeline returned. With no run timestamp (the clear never
    ran) there is no scope, and no sweep.
    """
    if not UPDATE_GRAPH_DB:
        return
    try:
        from recon.helpers.node_filter_sweep import run_node_filter_sweep
        stats = run_node_filter_sweep(USER_ID, PROJECT_ID, _RUN_STARTED_AT, RECON_FINDING_SOURCES)
    except Exception as e:  # noqa: BLE001 - a sweep must never change the job's outcome
        print(f"[!][NODE-FILTER] sweep failed: {e}")
        stats = {"error": str(e)[:500]}
    _record_node_filter_metadata(stats)


def _record_node_filter_metadata(stats):
    """Best-effort: the sweep's counts, or its error, into the run's output metadata."""
    if not stats or stats.get("skipped"):
        return
    try:
        from helpers.output_paths import canonical_output_file
        path = canonical_output_file(OUTPUT_DIR, PROJECT_ID)
        if not path.exists():
            return
        data = json.loads(path.read_text())
        data.setdefault("metadata", {})["node_filter"] = stats
        path.write_text(json.dumps(data, indent=2, default=str))
    except Exception as e:  # noqa: BLE001 - metadata is a nicety, never a failure
        print(f"[!][NODE-FILTER] could not record the sweep in the output file: {e}")


def _seed_batch_root_domains(roots: list) -> None:
    """Restore the attachable batch roots' org Domain nodes after the one-time clear.

    Groups run in order, so without this a later group's org has no Domain node
    while an earlier group's writers attach a host found under it
    (all_project_roots), and that Subdomain would be left unlinked. Never raises:
    a missing link is recoverable, a failed scan is not.
    """
    if not UPDATE_GRAPH_DB or not roots:
        return
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                seeded = graph_client.ensure_root_domains(roots, USER_ID, PROJECT_ID)
                print(f"[*][Batch] Domain nodes ready for {seeded} root(s)")
    except Exception as e:  # noqa: BLE001 - housekeeping must not fail the scan
        print(f"[!][Batch] Could not seed the batch's Domain nodes: {e}")


def run_domain_batch(groups: list, start_time) -> int:
    """Walk the operator-approved domain groups, one after another.

    The whole batch is ONE scan: one queue entry, one container, one version, one
    graph clear (already done by the caller). Each group runs the identical
    pipeline a single-domain project runs and writes its results to the graph
    before the next group starts, so the graph fills in progressively.

    A failing group does NOT abort the batch. One unresolvable domain must not
    cost the operator the other nineteen, so failures are collected and reported
    at the end; the run only fails outright if EVERY group failed.
    """
    total = len(groups)
    print("═" * 63)
    print(f"[*][Batch] DOMAIN BATCH: {total} domain group(s), sequential")
    for idx, group in enumerate(groups, 1):
        hosts = len(group['exactHosts']) + (1 if group['includeRoot'] else 0)
        _shape = 'enumerate' if group['mode'] == 'enumerate' else f"{hosts} host(s)"
        print(f"  [*][Batch] {idx}. {group['scanRoot']} ({_shape})")
    print("═" * 63)
    print()

    # Stale per-group files from a PREVIOUS run would be merged back into the
    # canonical output, resurrecting a domain the operator has since removed.
    # A run that skips discovery reads each group's previous file as its input,
    # so only the files of roots no longer in the batch are dropped.
    removed = clear_batch_outputs(
        OUTPUT_DIR, PROJECT_ID,
        keep_roots=[] if "domain_discovery" in SCAN_MODULES else [g['scanRoot'] for g in groups])
    if removed:
        print(f"[*][Batch] Removed {removed} stale group output file(s) from a previous run")
    # Replace the canonical file NOW. Until the first group finishes and the merge
    # runs, it would otherwise still describe the PREVIOUS run while the graph has
    # already been cleared, so anything reading it in that window (a GVM start only
    # checks the file exists) would scan the last run's targets.
    initialize_batch_canonical(OUTPUT_DIR, PROJECT_ID, [g['scanRoot'] for g in groups])
    global _BATCH_ATTACH_ROOTS
    _BATCH_ATTACH_ROOTS = _eligible_batch_roots(groups)
    # A Domain node is an org: the scan roots' orgs, each once.
    _seed_batch_root_domains(list(dict.fromkeys(_org_for_root(r) for r in _BATCH_ATTACH_ROOTS)))
    print()

    failed = []
    for idx, group in enumerate(groups, 1):
        root = group['scanRoot']
        if _shutdown.stop_requested():
            print(f"[!][Batch] Stop requested: group(s) {idx}..{total} not started")
            failed.extend(g['scanRoot'] for g in groups[idx - 1:])
            break
        # The marker the orchestrator parses into live "Group 2/3" progress;
        # the root stays one token (container_manager BATCH_GROUP_PATTERN).
        print(f"\n[Batch] Group {idx}/{total}: {root}")
        try:
            rc = run_domain_group(group, start_time=datetime.now())
        except Exception as e:  # noqa: BLE001 - one bad domain must not end the batch
            print(f"[!][Batch] Group {idx}/{total} ({root}) failed: {e}")
            rc = 1
        if rc != 0:
            failed.append(root)

        # Refresh the canonical file after EVERY group, so a batch stopped part
        # way still leaves GVM, the export and the report a file that describes
        # the groups that did finish.
        try:
            merge_batch_outputs(OUTPUT_DIR, PROJECT_ID)
        except Exception as e:  # noqa: BLE001 - results are already safe per group
            print(f"[!][Batch] Could not refresh the merged recon file: {e}")

    duration = datetime.now() - start_time
    print("\n" + "═" * 63)
    if failed:
        print(f"[!][Batch] DOMAIN BATCH COMPLETE with {len(failed)}/{total} failed group(s): "
              f"{', '.join(failed)}")
    else:
        print(f"[✓][Batch] DOMAIN BATCH COMPLETE: {total}/{total} group(s) succeeded")
    print(f"[*][Batch] Total time: {duration}")
    print("═" * 63)

    # ONCE per run, and never after a failed group: that group's previous
    # findings were not re-checked, and a prune would delete them outright.
    if failed:
        print(f"[!][Batch] Finding prune skipped: {', '.join(failed)} did not complete, "
              f"so no previous finding of this run is removed")
    else:
        _prune_recon_findings()

    # Only a batch where nothing succeeded is a failed run.
    return 1 if len(failed) == total else 0


def main():
    """Run the pipeline, then sweep node filters over what it wrote, whatever happened.

    The sweep sits in a `finally` so an early return or an exception still
    applies the rules to the findings the run managed to write. The graph
    writer is drained first, so the writes still queued land before the sweep
    reads them. A stopped run leaves both to the stopper, which bounds them by
    the stop deadline (recon/helpers/shutdown.py).
    """
    _shutdown.register_drain(_drain_graph_writes)
    _shutdown.set_sweep(_apply_node_filters)
    try:
        return _run_pipeline()
    finally:
        if not _shutdown.stop_requested():
            _graph_wait_all()
            _shutdown.sweep_once()
        _shutdown.park()


def _run_pipeline():
    """
    Main entry point - runs the complete recon pipeline.

    Pipeline: domain_discovery -> port_scan -> http_probe -> resource_enum -> vuln_scan

    Three targeting modes, all running the SAME pipeline:
    - IP mode:       run_ip_recon over the configured IPs/CIDRs.
    - Single domain: one run_domain_group call.
    - Domain batch:  one run_domain_group call per derived group, in order.

    Scan modes based on SUBDOMAIN_LIST:
    - Empty list []: Full subdomain discovery (discover and scan all subdomains)
    - With entries ["testphp.", "www."]: Filtered mode (only scan specified subdomains)
    """
    start_time = datetime.now()

    from recon.helpers import circuit_breaker
    circuit_breaker.announce_mode()

    # RoE: check the time window ONCE, before any target is touched and before
    # the clear, in both modes. The orchestrator checks it too, but this
    # container may start late (image pulls) after the window closed. A batch
    # that starts inside the window runs to completion; re-checking per group
    # would abandon a run half way through and leave the graph partially
    # rebuilt.
    allowed, reason = _check_roe_time_window(_settings)
    if not allowed:
        print(f"\n[RoE] BLOCKED: {reason}")
        print(f"[RoE] Reconnaissance aborted: outside Rules of Engagement time window.")
        return 1

    # IP Mode: skip domain verification and run IP-based recon instead
    if IP_MODE and TARGET_IPS:
        print(f"  [*][Pipeline] MODE:              IP-BASED TARGETING")
        print(f"  [*][Pipeline] TARGET_IPS:        {', '.join(TARGET_IPS)}")
        print(f"  [*][Pipeline] SCAN_MODULES:      {','.join(SCAN_MODULES) if isinstance(SCAN_MODULES, list) else SCAN_MODULES}")
        print(f"  [*][Pipeline] UPDATE_GRAPH_DB:   {UPDATE_GRAPH_DB}")
        print(f"  [*][Pipeline] USER_ID:           {USER_ID}")
        print(f"  [*][Pipeline] PROJECT_ID:        {PROJECT_ID}")
        print("═" * 63)

        _clear_recon_graph()

        ip_result = run_ip_recon(TARGET_IPS, _settings)

        _write_coverage_record((ip_result or {}).get("domain") or f"ip-targets.{PROJECT_ID}")
        _prune_recon_findings()

        end_time = datetime.now()
        duration = end_time - start_time
        print(f"\n[✓][Pipeline] Total time: {duration}")
        return 0

    log_scope(_settings)
    groups = _batch_groups()
    if DOMAIN_BATCH_MODE and not groups:
        # The settings load refuses this already; a batch must never fall
        # through to a single-domain run with an empty target.
        print("[!][Batch] Domain batch with no group to run: refusing.")
        return 1
    single = [] if groups else settings_scope_groups(_settings)
    if not groups and not single:
        print("[!][Pipeline] No target domain is configured: refusing.")
        return 1
    if _refuse_before_clear(groups or single[:1]):
        return 1

    # ONCE per run, before any group: this is what lets a batch's groups
    # accumulate into a single graph instead of each wiping the last.
    _clear_recon_graph()
    _start_urlscan_budget(groups or single)

    if groups:
        return run_domain_batch(groups, start_time)

    rc = run_domain_group(single[0], start_time=start_time)
    if rc == 0:
        _prune_recon_findings()
    return rc


def _start_urlscan_budget(groups) -> None:
    """One urlscan search budget for the whole run, shared by every scope group
    and every caller, with each root's first searches reserved up front."""
    if not _settings.get('URLSCAN_ENABLED'):
        return
    try:
        from recon.main_recon_modules.urlscan_enrich import start_search_budget
        roots = [g.get("scanRoot") for g in groups or [] if isinstance(g, dict)]
        budget = start_search_budget(_settings, [r for r in roots if r])
        print(f"[*][URLScan] Search budget for this run: {budget.limit} search(es)")
    except Exception as e:  # noqa: BLE001 - each search then gets a budget of its own
        print(f"[!][URLScan] Could not start the run's search budget: {type(e).__name__}")


# What run_domain_group's legacy branch (domain_discovery off) can re-check:
# http_probe, resource_enum (with jsluice), AI Surface, JS Recon and vuln_scan
# with its security checks. Every other recon source is never run there.
_LEGACY_PATH_SOURCES = frozenset({
    "http_probe", "resource_enum", "jsluice", "url_archive", "ai_surface_recon", "js_recon",
    "nuclei", "security_check", "vuln_scan",
})


def _note_legacy_unrun_sources() -> None:
    """Keep the findings of every recon source the legacy path does not run:
    they were not re-checked, so the prune must not read them as gone."""
    unrun = [s for s in RECON_FINDING_SOURCES if s not in _LEGACY_PATH_SOURCES]
    if not unrun:
        return
    print(f"[*][Pipeline] Domain discovery is off: {len(unrun)} finding source(s) this "
          f"path does not run keep their earlier findings")
    try:
        from recon.helpers import circuit_breaker
        circuit_breaker.note_degraded("legacy_pipeline", sources=unrun,
                                      reason="not run: domain discovery is off")
    except Exception:  # noqa: BLE001
        pass


def _drop_roe_excluded_subdomains(domain_result: dict, excluded: list) -> None:
    """Remove RoE-excluded hosts from a loaded recon file or a live merge, wherever it lists them."""
    subs = (domain_result.get('dns') or {}).get('subdomains') or {}
    status_map = domain_result.get('subdomain_status_map') or {}
    listed = domain_result.get('subdomains') or []
    dropped = {h for h in [*subs, *listed, *status_map] if _is_roe_excluded(h, excluded)}
    if not dropped:
        return
    for host in dropped:
        subs.pop(host, None)
        status_map.pop(host, None)
    domain_result['subdomains'] = [h for h in listed if h not in dropped]
    if 'subdomain_count' in domain_result:
        domain_result['subdomain_count'] = len(domain_result['subdomains'])
    print(f"[RoE] Removed {len(dropped)} excluded subdomain(s) from the DNS data")


def _write_legacy_domain_nodes(domain_result: dict) -> None:
    """Rebuild the Domain and Subdomain nodes from the loaded file. Synchronous,
    like the legacy path's other writes; never raises."""
    if not UPDATE_GRAPH_DB:
        return
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if not graph_client.verify_connection():
                print("[!][graph-db] Could not connect to Neo4j - Domain and subdomains not rebuilt")
                return
            graph_client.update_graph_from_domain_discovery(domain_result, USER_ID, PROJECT_ID)
            print("[+][graph-db] Domain and subdomains rebuilt from the loaded recon file")
    except Exception as e:  # noqa: BLE001
        print(f"[!][graph-db] Could not rebuild the Domain and subdomains: {e}")


def run_domain_group(group: dict, start_time=None) -> int:
    """Run the whole domain pipeline for ONE scope group: a single-domain
    project's one group, or one group of a Domain batch.

    Everything that is per-TARGET lives here (RoE host exclusion, ownership
    verification, target parsing, the pipeline itself, the summary). Everything
    that is per-RUN stays in main(): the RoE time window, and above all the
    graph clear, which must happen ONCE so a batch's groups accumulate into one
    graph instead of each wiping the last.

    The target arrives as an ARGUMENT, never through the module globals: a batch
    group's domain is not TARGET_DOMAIN (which is empty in batch mode), and
    downstream modules re-read settings from the API, so a mutated global would
    not reach them anyway.

    Returns 0 on success, 1 if this target was aborted.
    """
    if start_time is None:
        start_time = datetime.now()
    from recon.helpers import circuit_breaker
    coverage_group = circuit_breaker.group_scope()
    target_domain = group['scanRoot']

    # One bad moment in an earlier group must not leave this one unresolved;
    # before ownership, whose TXT lookup the latch would otherwise refuse.
    from recon.main_recon_modules.domain_recon import resolver_breaker
    resolver_breaker.recheck()

    # RoE before ownership: an excluded root gets no TXT lookup either.
    if _roe_refuses_root(target_domain):
        print(f"\n[RoE] BLOCKED: Root domain '{target_domain}' is in ROE excluded hosts list.")
        print(f"[RoE] Reconnaissance aborted — target domain excluded by Rules of Engagement.")
        return 1

    # Ownership (when on) before anything touches the target. A batch already
    # asked in _eligible_batch_roots; the answer is cached for the run.
    if VERIFY_DOMAIN_OWNERSHIP:
        ownership = _group_ownership(group)
        if not ownership["verified"]:
            print(f"\n[!][Pipeline] SCAN ABORTED: Domain ownership verification failed for {target_domain}")
            if ownership.get("error"):
                print(f"[!][Pipeline] {ownership['error']}")
            print(f"[!][Pipeline] Add TXT {' OR '.join(ownership['record_names'])} → "
                  f"\"{ownership['expected_value']}\"")
            return 1
    # A refused group never triggers org-level work (§4.9).
    _note_run_org(group.get('orgDomain') or target_domain)

    # A batch group runs on its scope group, whose mode is explicit. A single
    # domain keeps parse_target's legacy keys (its graph flags must not move)
    # and carries the group's scope beside them.
    if _batch_groups():
        target_info = target_info_from_group(group)
        subdomain_list = target_info["subdomain_list"]
    else:
        subdomain_list = SUBDOMAIN_LIST
        target_info = parse_target(target_domain, subdomain_list)
        scope = target_info_from_group(group)
        for key in ("scan_root", "org_domain", "mode", "include_root", "exact_hosts"):
            target_info[key] = scope[key]
    filtered_mode = target_info["filtered_mode"]
    root_domain = target_info["root_domain"]
    full_subdomains = target_info["full_subdomains"]

    # May THIS target enumerate? The settings toggle is a run-wide scalar, so it
    # can only say whether enumeration is allowed at all; in a Domain batch the
    # answer is per group, and only here do we hold one group's prefixes. A batch
    # group enumerates ONLY when the operator wrote a wildcard for it — every
    # other group scans exactly the hostnames it was given, which is the contract
    # the run-wide force-off in project_settings used to enforce on its own.
    discovery_enabled = group_discovery_enabled(
        _settings, _batch_groups(), target_info)

    # RoE: filter out excluded hosts from subdomains
    full_subdomains = _filter_roe_excluded(full_subdomains, _settings, label="subdomain")
    target_info["full_subdomains"] = full_subdomains

    # Display full configuration (values loaded from DB/API)
    print("═" * 63)
    print("[*][Pipeline] Configuration:")
    print(f"  [*][Pipeline] TARGET_DOMAIN:     {target_domain}")
    print(f"  [*][Pipeline] SUBDOMAIN_LIST:    {subdomain_list if subdomain_list else '[] (full discovery)'}")
    print(f"  [*][Pipeline] SCAN_MODULES:      {','.join(SCAN_MODULES) if isinstance(SCAN_MODULES, list) else SCAN_MODULES}")
    print(f"  [*][Pipeline] STEALTH_MODE:      {_settings.get('STEALTH_MODE', False)}")
    print(f"  [*][Pipeline] UPDATE_GRAPH_DB:   {UPDATE_GRAPH_DB}")
    print(f"  [*][Pipeline] USER_ID:           {USER_ID}")
    print(f"  [*][Pipeline] PROJECT_ID:        {PROJECT_ID}")
    if filtered_mode:
        print(f"  [*][Pipeline] MODE:              FILTERED SUBDOMAIN SCAN")
        print(f"  [*][Pipeline] SUBDOMAINS:        {', '.join(full_subdomains)}")
    else:
        print(f"  [*][Pipeline] MODE:              FULL DISCOVERY (all subdomains)")
    print("═" * 63)

    if _settings.get('STEALTH_MODE', False):
        print()
        print("  ╔══════════════════════════════════════════════════════════╗")
        print("  ║  STEALTH MODE ACTIVE — passive/low-noise only           ║")
        print("  ║  Kiterunner: OFF | Banner Grab: OFF | Brute Force: OFF  ║")
        print("  ║  Naabu: passive | httpx: 2 req/s | Nuclei: no DAST     ║")
        print("  ╚══════════════════════════════════════════════════════════╝")

    print()

    # Phase 1 & 2: Domain recon (WHOIS + Subdomains + DNS) - Combined JSON.
    # In a batch this is the GROUP's own file; merge_batch_outputs() rebuilds the
    # canonical recon_<project>.json that everything downstream reads.
    output_file = recon_output_file(
        OUTPUT_DIR, PROJECT_ID, root_domain if _batch_groups() else None)

    if "domain_discovery" in SCAN_MODULES:
        domain_result = run_domain_recon(
            target_domain,
            bruteforce=USE_BRUTEFORCE_FOR_SUBDOMAINS,
            target_info=target_info,
            discovery_enabled=discovery_enabled
        )
        _stamp_project_roots(domain_result)
    else:
        # The legacy path: domain_discovery is off, so the previous run's file
        # is reloaded and a few phases run on it, after _run_pipeline cleared the
        # graph. Its graph writes go through the background writer like the
        # main pipeline's, and before anything can let the prune run, the recon
        # sources this path never runs keep their findings.
        _graph_reset()
        _note_legacy_unrun_sources()
        if output_file.exists():
            with open(output_file, 'r') as f:
                domain_result = json.load(f)
            _stamp_project_roots(domain_result)
            print(f"[*][Pipeline] Loaded existing recon file: {output_file}")

            # RoE: filter excluded hosts from every place the loaded file lists
            # them; the domain writer reads the top-level list.
            if _settings.get('ROE_ENABLED') and _settings.get('ROE_EXCLUDED_HOSTS'):
                _drop_roe_excluded_subdomains(domain_result, _settings['ROE_EXCLUDED_HOSTS'])

            # The clear removed the Domain and Subdomain nodes, and no other
            # writer on this path MERGEs them (they only MATCH).
            _write_legacy_domain_nodes(domain_result)
        else:
            print(f"[!][Pipeline] No existing recon file found: {output_file}")
            print(f"[!][Pipeline] Add 'domain_discovery' to SCAN_MODULES to create it first")
            return 1
        
        # Run port_scan if in SCAN_MODULES (when domain_discovery is skipped)
        if "port_scan" in SCAN_MODULES:
            _naabu_on = _settings.get('NAABU_ENABLED', True)
            _masscan_on = _settings.get('MASSCAN_ENABLED', True)

            if not _naabu_on and not _masscan_on:
                print("\n[!][Pipeline] Both Naabu and Masscan are disabled — skipping port scan phase")
                print("[!][Pipeline] Downstream modules (HTTP probe, vuln scan) require open ports to work")
            else:
                print(f"\n[*][Pipeline] GROUP 3: Port Scan")
                if _naabu_on:
                    domain_result = run_port_scan(domain_result, output_file=output_file, settings=_settings)
                    if "metadata" in domain_result and "modules_executed" in domain_result["metadata"]:
                        if "port_scan" not in domain_result["metadata"]["modules_executed"]:
                            domain_result["metadata"]["modules_executed"].append("port_scan")

                if _masscan_on:
                    domain_result = run_masscan_scan(domain_result, output_file=None, settings=_settings)
                    merge_port_scan_results(domain_result)
                    if "metadata" in domain_result and "modules_executed" in domain_result["metadata"]:
                        if "masscan_scan" not in domain_result["metadata"]["modules_executed"]:
                            domain_result["metadata"]["modules_executed"].append("masscan_scan")

            with open(output_file, 'w') as f:
                json.dump(domain_result, f, indent=2)

            # Update Graph DB with port scan data
            if UPDATE_GRAPH_DB:
                print(f"\n[*][graph-db] GRAPH UPDATE: Port Scan Data")
                print("-" * 40)
                try:
                    from graph_db import Neo4jClient
                    with Neo4jClient() as graph_client:
                        if graph_client.verify_connection():
                            port_stats = graph_client.update_graph_from_port_scan(domain_result, USER_ID, PROJECT_ID)
                            domain_result["metadata"]["graph_db_port_scan_updated"] = True
                            domain_result["metadata"]["graph_db_port_scan_stats"] = port_stats
                            print(f"[+][graph-db] Graph database updated with port scan data")
                        else:
                            print(f"[!][graph-db] Could not connect to Neo4j - skipping port scan graph update")
                            domain_result["metadata"]["graph_db_port_scan_updated"] = False
                except ImportError:
                    print(f"[!][graph-db] Neo4j client not available - skipping port scan graph update")
                    domain_result["metadata"]["graph_db_port_scan_updated"] = False
                except Exception as e:
                    print(f"[!][graph-db] Port scan graph update failed: {e}")
                    domain_result["metadata"]["graph_db_port_scan_updated"] = False
                    domain_result["metadata"]["graph_db_port_scan_error"] = str(e)

                with open(output_file, 'w') as f:
                    json.dump(domain_result, f, indent=2)
        
        # Run http_probe if in SCAN_MODULES (when domain_discovery is skipped)
        if "http_probe" in SCAN_MODULES:
            if not _settings.get('HTTPX_ENABLED', True):
                print("\n[*][httpx] HTTP probing disabled -- skipping")
            else:
                print(f"\n[*][Pipeline] GROUP 4: HTTP Probing")
                domain_result = run_http_probe(domain_result, output_file=output_file, settings=_settings)
                if "metadata" in domain_result and "modules_executed" in domain_result["metadata"]:
                    if "http_probe" not in domain_result["metadata"]["modules_executed"]:
                        domain_result["metadata"]["modules_executed"].append("http_probe")
                with open(output_file, 'w') as f:
                    json.dump(domain_result, f, indent=2)

                # Update Graph DB with http probe data
                if UPDATE_GRAPH_DB:
                    print(f"\n[*][graph-db] GRAPH UPDATE: HTTP Probe Data")
                    print("-" * 40)
                    try:
                        from graph_db import Neo4jClient
                        with Neo4jClient() as graph_client:
                            if graph_client.verify_connection():
                                http_stats = graph_client.update_graph_from_http_probe(domain_result, USER_ID, PROJECT_ID)
                                domain_result["metadata"]["graph_db_http_probe_updated"] = True
                                domain_result["metadata"]["graph_db_http_probe_stats"] = http_stats
                                print(f"[+][graph-db] Graph database updated with http probe data")
                            else:
                                print(f"[!][graph-db] Could not connect to Neo4j - skipping http probe graph update")
                                domain_result["metadata"]["graph_db_http_probe_updated"] = False
                    except ImportError:
                        print(f"[!][graph-db] Neo4j client not available - skipping http probe graph update")
                        domain_result["metadata"]["graph_db_http_probe_updated"] = False
                    except Exception as e:
                        print(f"[!][graph-db] HTTP probe graph update failed: {e}")
                        domain_result["metadata"]["graph_db_http_probe_updated"] = False
                        domain_result["metadata"]["graph_db_http_probe_error"] = str(e)

                    with open(output_file, 'w') as f:
                        json.dump(domain_result, f, indent=2)

        # Check if we should skip active scanning modules (resource_enum, vuln_scan)
        # These require live targets from http_probe to work
        skip_active_scans, skip_reason = should_skip_active_scans(domain_result)
        
        if skip_active_scans:
            print(f"\n{'=' * 70}")
            print(f"[!][Pipeline] SKIPPING ACTIVE SCANS: {skip_reason}")
            print(f"[!][Pipeline] Modules skipped: resource_enum, vuln_scan")
            print(f"{'=' * 70}")
            if "metadata" in domain_result:
                domain_result["metadata"]["active_scans_skipped"] = True
                domain_result["metadata"]["active_scans_skip_reason"] = skip_reason
            with open(output_file, 'w') as f:
                json.dump(domain_result, f, indent=2)
            domain_result = _maybe_run_cert_hygiene(domain_result, _settings, output_file)
        else:
            # Run resource_enum if in SCAN_MODULES (when domain_discovery is skipped)
            if "resource_enum" in SCAN_MODULES:
                print(f"\n[*][Pipeline] GROUP 5: Resource Enumeration")
                domain_result = run_resource_enum(domain_result, output_file=output_file, settings=_settings)
                if "metadata" in domain_result and "modules_executed" in domain_result["metadata"]:
                    if "resource_enum" not in domain_result["metadata"]["modules_executed"]:
                        domain_result["metadata"]["modules_executed"].append("resource_enum")
                with open(output_file, 'w') as f:
                    json.dump(domain_result, f, indent=2)

                # Update Graph DB with resource enumeration data
                if UPDATE_GRAPH_DB:
                    print(f"\n[*][graph-db] GRAPH UPDATE: Resource Enumeration Data")
                    print("-" * 40)
                    try:
                        from graph_db import Neo4jClient
                        with Neo4jClient() as graph_client:
                            if graph_client.verify_connection():
                                resource_stats = graph_client.update_graph_from_resource_enum(domain_result, USER_ID, PROJECT_ID)
                                domain_result["metadata"]["graph_db_resource_enum_updated"] = True
                                domain_result["metadata"]["graph_db_resource_enum_stats"] = resource_stats
                                print(f"[+][graph-db] Graph database updated with resource enumeration data")
                            else:
                                print(f"[!][graph-db] Could not connect to Neo4j - skipping resource enum graph update")
                                domain_result["metadata"]["graph_db_resource_enum_updated"] = False
                    except ImportError:
                        print(f"[!][graph-db] Neo4j client not available - skipping resource enum graph update")
                        domain_result["metadata"]["graph_db_resource_enum_updated"] = False
                    except Exception as e:
                        print(f"[!][graph-db] Resource enum graph update failed: {e}")
                        domain_result["metadata"]["graph_db_resource_enum_updated"] = False
                        domain_result["metadata"]["graph_db_resource_enum_error"] = str(e)

                    with open(output_file, 'w') as f:
                        json.dump(domain_result, f, indent=2)

        # GROUP 4.5 — AI Surface Recon (runs after resource_enum)
        domain_result = _maybe_run_ai_surface(domain_result, _settings, output_file)

        # GROUP 5b — JS Recon (runs after resource_enum, before vuln_scan;
        # runs even when active scans are skipped -- uploaded files don't need live targets)
        if _settings.get('JS_RECON_ENABLED', False):
            print(f"\n[*][Pipeline] GROUP 5b: JS Recon")
            try:
                from recon.main_recon_modules.js_recon import run_js_recon
                domain_result = run_js_recon(domain_result, settings=_settings)
                if "metadata" in domain_result and "modules_executed" in domain_result["metadata"]:
                    if "js_recon" not in domain_result["metadata"]["modules_executed"]:
                        domain_result["metadata"]["modules_executed"].append("js_recon")
                with open(output_file, 'w') as f:
                    json.dump(domain_result, f, indent=2)

                if UPDATE_GRAPH_DB:
                    try:
                        from graph_db import Neo4jClient
                        with Neo4jClient() as graph_client:
                            if graph_client.verify_connection():
                                graph_client.update_graph_from_js_recon(domain_result, USER_ID, PROJECT_ID)
                                domain_result["metadata"]["graph_db_js_recon_updated"] = True
                                print(f"[+][graph-db] Graph database updated with JS Recon data")
                    except Exception as e:
                        print(f"[!][graph-db] JS Recon graph update failed: {e}")
                        domain_result["metadata"]["graph_db_js_recon_updated"] = False

                    with open(output_file, 'w') as f:
                        json.dump(domain_result, f, indent=2)
            except Exception as e:
                print(f"[!][JsRecon] Error: {e}")
                _note_phase_error("js_recon")

        if not skip_active_scans:
            # Run vuln_scan if in SCAN_MODULES (when domain_discovery is skipped)
            # vuln_scan automatically includes MITRE CWE/CAPEC enrichment
            if "vuln_scan" in SCAN_MODULES:
                print(f"\n[*][Pipeline] GROUP 6: Vulnerability Scanning (Nuclei, then MITRE)")
                domain_result = run_vuln_scan(domain_result, output_file=output_file, settings=_settings)
                if "metadata" in domain_result and "modules_executed" in domain_result["metadata"]:
                    if "vuln_scan" not in domain_result["metadata"]["modules_executed"]:
                        domain_result["metadata"]["modules_executed"].append("vuln_scan")
                with open(output_file, 'w') as f:
                    json.dump(domain_result, f, indent=2)

                # Automatically run MITRE CWE/CAPEC enrichment after vuln_scan
                if _settings.get('MITRE_ENABLED', True):
                    domain_result = run_mitre_enrichment(domain_result, output_file=output_file, settings=_settings)
                with open(output_file, 'w') as f:
                    json.dump(domain_result, f, indent=2)

                # Update Graph DB with vuln scan data
                if UPDATE_GRAPH_DB:
                    print(f"\n[*][graph-db] GRAPH UPDATE: Vuln Scan Data")
                    print("-" * 40)
                    try:
                        from graph_db import Neo4jClient
                        with Neo4jClient() as graph_client:
                            if graph_client.verify_connection():
                                vuln_stats = graph_client.update_graph_from_vuln_scan(domain_result, USER_ID, PROJECT_ID)
                                domain_result["metadata"]["graph_db_vuln_scan_updated"] = True
                                domain_result["metadata"]["graph_db_vuln_scan_stats"] = vuln_stats
                                print(f"[+][graph-db] Graph database updated with vuln scan data")
                            else:
                                print(f"[!][graph-db] Could not connect to Neo4j - skipping vuln scan graph update")
                                domain_result["metadata"]["graph_db_vuln_scan_updated"] = False
                    except ImportError:
                        print(f"[!][graph-db] Neo4j client not available - skipping vuln scan graph update")
                        domain_result["metadata"]["graph_db_vuln_scan_updated"] = False
                    except Exception as e:
                        print(f"[!][graph-db] Vuln scan graph update failed: {e}")
                        domain_result["metadata"]["graph_db_vuln_scan_updated"] = False
                        domain_result["metadata"]["graph_db_vuln_scan_error"] = str(e)

                    with open(output_file, 'w') as f:
                        json.dump(domain_result, f, indent=2)

    # Final summary
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    print("\n")
    print("─" * 50)
    print("  [✓][Pipeline] RECON PIPELINE COMPLETE")
    print("─" * 50)
    print(f"  [*][Pipeline] Duration: {duration:.2f} seconds")
    print(f"  [*][Pipeline] Target: {root_domain}")
    if filtered_mode:
        print(f"  [*][Pipeline] Mode: Filtered ({len(full_subdomains)} subdomain(s))")
    else:
        print(f"  [*][Pipeline] Mode: Full discovery")
        print(f"  [+][Pipeline] Subdomains found: {domain_result.get('subdomain_count', 0)}")

    # Port scan stats
    if "port_scan" in SCAN_MODULES and "port_scan" in domain_result:
        port_summary = domain_result["port_scan"].get("summary", {})
        naabu_ports = port_summary.get('total_open_ports', 0)
        hosts = port_summary.get('hosts_with_open_ports', 0)
        print(f"  [+][Naabu] Port Scan: {hosts} hosts, {naabu_ports} ports")
    elif "port_scan" not in SCAN_MODULES:
        print("  [-][Naabu] Port Scan: SKIPPED")

    # HTTP probe stats
    if "http_probe" in SCAN_MODULES and "http_probe" in domain_result:
        http_summary = domain_result["http_probe"].get("summary", {})
        live = http_summary.get('live_urls', 0)
        techs = http_summary.get('technology_count', 0)
        print(f"  [+][Httpx] HTTP Probe: {live} live URLs, {techs} technologies")
        if live > 0 and "port_scan" in domain_result:
            if domain_result["port_scan"].get("summary", {}).get("total_open_ports", 0) == 0:
                from urllib.parse import urlparse
                httpx_ports = set()
                for url in domain_result.get("http_probe", {}).get("by_url", {}):
                    p = urlparse(url)
                    httpx_ports.add(p.port or (443 if p.scheme == "https" else 80))
                if httpx_ports:
                    print(f"  [+][Httpx] Service ports (httpx): {', '.join(str(p) for p in sorted(httpx_ports))}")
    elif "http_probe" not in SCAN_MODULES:
        print("  [-][Httpx] HTTP Probe: SKIPPED")

    # Check if active scans were skipped due to no live targets
    active_scans_skipped = domain_result.get("metadata", {}).get("active_scans_skipped", False)
    skip_reason = domain_result.get("metadata", {}).get("active_scans_skip_reason", "")

    # Resource enumeration stats
    if active_scans_skipped:
        print(f"  [!][ResourceEnum] Resources: SKIPPED (no live targets)")
    elif "resource_enum" in SCAN_MODULES and "resource_enum" in domain_result:
        res_summary = domain_result["resource_enum"].get("summary", {})
        endpoints = res_summary.get('total_endpoints', 0)
        params = res_summary.get('total_parameters', 0)
        forms = res_summary.get('total_forms', 0)
        print(f"  [+][ResourceEnum] Resources: {endpoints} endpoints, {params} params, {forms} forms")
    elif "resource_enum" not in SCAN_MODULES:
        print("  [-][ResourceEnum] Resources: SKIPPED")

    # Vuln scan stats (includes MITRE enrichment)
    if active_scans_skipped:
        print(f"  [!][Nuclei] Vuln Scan: SKIPPED (no live targets)")
    elif "vuln_scan" in SCAN_MODULES and "vuln_scan" in domain_result:
        vuln_summary = domain_result["vuln_scan"].get("summary", {})
        total_findings = vuln_summary.get("total_findings", 0)
        crit = vuln_summary.get("critical", 0)
        high = vuln_summary.get("high", 0)
        vuln_info = f"{total_findings} findings"
        if crit > 0 or high > 0:
            vuln_info += f" ({crit} critical, {high} high)"
        print(f"  [+][Nuclei] Vuln Scan: {vuln_info}")

        # MITRE enrichment stats (part of vuln_scan)
        mitre_meta = domain_result.get("metadata", {}).get("mitre_enrichment", {})
        if mitre_meta:
            enriched = mitre_meta.get('total_cves_enriched', 0)
            total = mitre_meta.get('total_cves_processed', 0)
            print(f"  [+][MITRE] CWE/CAPEC: {enriched}/{total} CVEs enriched")
    elif "vuln_scan" not in SCAN_MODULES:
        print("  [-][Nuclei] Vuln Scan: SKIPPED")

    print("─" * 50)
    print("  [+][Pipeline] Output: recon_{}.json".format(PROJECT_ID))
    print("─" * 50)
    print()

    # The prune is run-level (see _run_pipeline / run_domain_batch): a batch
    # group that pruned here would delete the later groups' findings before
    # they were rescanned. The group's queued writes land first, so the record
    # is stamped on what they wrote (the legacy path's Domain included).
    _graph_wait_all()
    _write_coverage_record(root_domain, coverage_group)

    return 0


if __name__ == "__main__":
    sys.exit(main())
