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

# Import settings from project_settings (fetches from API or falls back to params.py)
from recon.project_settings import get_settings

# Load settings from API (if PROJECT_ID/WEBAPP_API_URL set) or params.py (CLI mode).
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
    """The operator-approved groups, in run order, or [] outside batch mode.

    Read through a function rather than a module constant so a test can point the
    settings dict at a different project without re-importing this module.
    """
    if not _settings.get('DOMAIN_BATCH_MODE', False):
        return []
    groups = _settings.get('DOMAIN_BATCH_GROUPS') or []
    return groups if isinstance(groups, list) else []


# The batch roots the graph writers may attach a host to. Fixed once per batch
# run by run_domain_batch; empty outside batch mode.
_BATCH_ATTACH_ROOTS: list = []


def _eligible_batch_roots(groups: list) -> list:
    """The batch's roots its groups will actually scan, in order.

    run_domain_group refuses a root that is RoE-excluded or fails ownership
    verification. A host found under such a root must stay an informational
    ExternalDomain, not become an in-scope Subdomain, so the root is left out.
    Ownership is checked the way the group checks it, failing closed.
    """
    excluded = _settings.get('ROE_EXCLUDED_HOSTS') if _settings.get('ROE_ENABLED') else None
    roots = []
    for group in groups or []:
        root = str(group.get('rootDomain') or '').strip() if isinstance(group, dict) else ''
        if not root or root in roots:
            continue
        if excluded and _is_roe_excluded(root, excluded):
            continue
        if VERIFY_DOMAIN_OWNERSHIP:
            try:
                verified = verify_domain_ownership(
                    root, OWNERSHIP_TOKEN, OWNERSHIP_TXT_PREFIX).get("verified")
            except Exception:  # noqa: BLE001 - an unanswered check is a failed check
                verified = False
            if not verified:
                continue
        roots.append(root)
    return roots


def _stamp_project_roots(recon_data: dict) -> dict:
    """Carry the whole batch's roots for the graph writers.

    The pipeline scans one group at a time, so recon_data["domain"] is the group
    root and the scan stays inside the group. The writers, though, must attach a
    host a scan found under ANOTHER batch root to that root's Domain, not record
    it as an ExternalDomain -- the same fix the partial path already has. They
    read this through attach_roots(); it is absent for a single-domain project,
    which needs no cross-root attachment. It is deliberately NOT "domains", which
    would widen the per-group scan scope.
    """
    if isinstance(recon_data, dict) and _batch_groups() and _BATCH_ATTACH_ROOTS:
        recon_data["all_project_roots"] = list(_BATCH_ATTACH_ROOTS)
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
    """Create a fresh background executor for a new pipeline run."""
    global _graph_executor, _graph_futures
    _graph_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="graph-db")
    _graph_futures = []


def _graph_update_bg(update_method_name: str, combined_result: dict,
                     user_id: str, project_id: str):
    """Submit a graph DB update to the background thread.

    Takes a deep-copy snapshot of combined_result so the main thread can
    keep mutating it safely.
    """
    if not UPDATE_GRAPH_DB or _graph_executor is None:
        return
    snapshot = copy.deepcopy(combined_result)

    def _do_update():
        try:
            from graph_db import Neo4jClient
            with Neo4jClient() as client:
                if client.verify_connection():
                    method = getattr(client, update_method_name)
                    method(snapshot, user_id, project_id)
                    print(f"[graph-db] {update_method_name} complete")
                else:
                    print(f"[!][graph-db] Neo4j not reachable — skipped {update_method_name}")
        except Exception as e:
            print(f"[!][graph-db] Background graph update ({update_method_name}) failed: {e}")

    future = _graph_executor.submit(_do_update)
    _graph_futures.append(future)


def _graph_wait_all():
    """Wait for every queued graph DB update to finish, then tear down the executor."""
    global _graph_executor
    if _graph_executor is None:
        return
    _graph_executor.shutdown(wait=True)
    for f in _graph_futures:
        exc = f.exception()
        if exc:
            print(f"[!][graph-db] Graph update error: {exc}")
    _graph_executor = None


# RoE excluded-host matching lives in recon.helpers.roe_scope so active scanners
# (origin_discovery) can enforce it without importing this module. Re-exported
# here so `from main import _is_roe_excluded/_filter_roe_excluded` still resolves.
from recon.helpers.roe_scope import _is_roe_excluded, _filter_roe_excluded


def _check_roe_time_window(settings: dict, _now=None) -> tuple[bool, str]:
    """Check if current time is within the RoE-allowed window.

    Returns (allowed, reason_message). Always returns (True, "") if
    RoE or its time window is disabled. Pass _now for testing.
    """
    if not settings.get('ROE_ENABLED') or not settings.get('ROE_TIME_WINDOW_ENABLED'):
        return True, ""

    from datetime import datetime as _dt
    import zoneinfo as _zi

    tz_name = settings.get('ROE_TIME_WINDOW_TIMEZONE', 'UTC')
    try:
        tz = _zi.ZoneInfo(tz_name)
    except Exception:
        print(f"[RoE] Unknown timezone '{tz_name}', falling back to UTC")
        tz = _zi.ZoneInfo('UTC')

    now = _now or _dt.now(tz)

    # Check day of week
    allowed_days = [d.lower() for d in settings.get('ROE_TIME_WINDOW_DAYS', [])]
    current_day = now.strftime('%A').lower()
    if current_day not in allowed_days:
        return False, f"Current day ({current_day}) is not in allowed days: {', '.join(allowed_days)} ({tz_name})"

    # Check time range
    start = settings.get('ROE_TIME_WINDOW_START_TIME', '09:00')
    end = settings.get('ROE_TIME_WINDOW_END_TIME', '18:00')
    current_time = now.strftime('%H:%M')
    if current_time < start or current_time >= end:
        return False, f"Current time ({current_time} {tz_name}) is outside allowed window ({start}\u2013{end})"

    return True, ""


def _merge_external_domain(aggregated: dict, entry: dict):
    """Merge a single external domain entry into the aggregated dict."""
    domain = entry.get("domain", "").strip().lower()
    if not domain:
        return
    if domain not in aggregated:
        aggregated[domain] = {
            "domain": domain, "sources": [], "redirect_from_urls": [],
            "redirect_to_urls": [], "status_codes_seen": [], "titles_seen": [],
            "servers_seen": [], "ips_seen": [], "countries_seen": [], "times_seen": 0,
        }
    rec = aggregated[domain]
    rec["times_seen"] += 1
    for val, key in [
        (entry.get("source"), "sources"),
        (entry.get("url"), "redirect_to_urls"),
        (entry.get("redirect_from_url"), "redirect_from_urls"),
        (entry.get("title"), "titles_seen"),
        (entry.get("server"), "servers_seen"),
        (entry.get("ip"), "ips_seen"),
        (entry.get("country"), "countries_seen"),
    ]:
        if val and val not in rec[key]:
            rec[key].append(val)
    sc = entry.get("status_code")
    if sc is not None:
        sc_str = str(sc)
        if sc_str not in rec["status_codes_seen"]:
            rec["status_codes_seen"].append(sc_str)


def _aggregate_external_domains(combined_result: dict) -> list:
    """Aggregate external domains from all pipeline sources."""
    aggregated = {}
    for e in combined_result.get("http_probe", {}).get("external_domains", []):
        _merge_external_domain(aggregated, e)
    for e in combined_result.get("urlscan", {}).get("external_domains", []):
        _merge_external_domain(aggregated, e)
    for e in combined_result.get("resource_enum", {}).get("external_domains", []):
        _merge_external_domain(aggregated, e)
    for e in combined_result.get("domain_discovery_external_domains", []):
        _merge_external_domain(aggregated, e)
    # Out-of-scope names diverted by merge_discovered_hostnames (certificate
    # SANs, js_recon subdomains): recorded, never scanned.
    for e in combined_result.get("discovered_external_domains", []):
        _merge_external_domain(aggregated, e)
    for e in _js_recon_external_domains(combined_result):
        _merge_external_domain(aggregated, e)
    return list(aggregated.values())


def _js_recon_external_domains(combined_result: dict) -> list:
    """Third-party hosts the target's JavaScript names, as external-domain entries.

    The graph keeps no Endpoint for them, so this is their only record. JS recon
    tests hosts against the root domain, which in IP mode is the synthetic
    ip-targets name, so the target IPs come back as "external" and are dropped.
    Only domain and source are passed: a URL a bundle names is not a redirect.
    """
    metadata = combined_result.get("metadata") or {}
    targets = {
        str(h).strip().lower()
        for h in [*(combined_result.get("subdomains") or []),
                  *(metadata.get("subdomain_filter") or []),
                  *(metadata.get("expanded_ips") or [])]
    }
    entries = (combined_result.get("js_recon") or {}).get("external_domains") or []
    return [
        {"domain": e["domain"], "source": "js_recon"}
        for e in entries
        if isinstance(e, dict) and isinstance(e.get("domain"), str)
        and e["domain"].strip().lower() not in targets
    ]


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
)


def merge_group_hosts(recon_result, target_info: dict, root_domain: str,
                      settings: dict, dns_enabled: bool = True,
                      resolver=None) -> dict:
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

    Split out of run_domain_recon so it can be tested as the thing the pipeline
    calls; inlined, it was only reachable through the whole 750-line phase.
    """
    from recon.main_recon_modules.ip_filter import is_never_scannable_ip

    discovered_subs = []
    if recon_result:
        discovered_subs = list(recon_result.get("subdomains") or [])
        discovered_subs = _filter_roe_excluded(
            discovered_subs, settings, label="discovered subdomain")

    include_root = bool(target_info.get("include_root_domain", False))
    if include_root and root_domain not in discovered_subs:
        discovered_subs.insert(0, root_domain)
    for host in target_info.get("full_subdomains") or []:
        if host not in discovered_subs:
            discovered_subs.append(host)

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
    discovered_dns.setdefault("domain", {})
    discovered_dns.setdefault("subdomains", resolved)

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

    status_map = (recon_result or {}).get("subdomain_status_map") or {}
    return {
        "subdomains": discovered_subs,
        "dns": discovered_dns,
        "status_map": {s: st for s, st in status_map.items()
                       if s in set(discovered_subs)},
        "include_root": include_root,
    }


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
    """Save recon data to JSON file (thread-safe)."""
    with _save_lock:
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)


_TLS_HYGIENE_CHECK_SETTINGS = {
    "tls_expired": "SECURITY_CHECK_TLS_EXPIRED",
    "tls_self_signed": "SECURITY_CHECK_TLS_SELF_SIGNED",
    "tls_hostname_mismatch": "SECURITY_CHECK_TLS_HOSTNAME_MISMATCH",
    "tls_weak_version": "SECURITY_CHECK_TLS_WEAK_VERSION",
    "tls_weak_cipher": "SECURITY_CHECK_TLS_WEAK_CIPHER",
    "tls_wildcard_overbroad": "SECURITY_CHECK_TLS_WILDCARD_OVERBROAD",
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
    return result


def _maybe_run_openapi(result: dict, settings: dict, output_file: Path, *, pacer=None) -> dict:
    """Configured descriptions remain usable even when live HTTP probing fails."""
    if not settings.get('OPENAPI_ENABLED', True):
        return result
    try:
        from recon.main_recon_modules.openapi_recon import run_openapi_recon
        if settings.get('DOMAIN_BATCH_MODE'):
            group = next((group for group in settings.get('DOMAIN_BATCH_GROUPS', [])
                          if group.get('rootDomain') == result.get('domain')), None)
            if group is None:
                raise ValueError('OpenAPI batch target is not in the approved groups')
            settings = {**settings, 'TARGET_DOMAIN': group['rootDomain'],
                        'SUBDOMAIN_LIST': list(group.get('prefixes') or [])}
        result = run_openapi_recon(result, settings, pacer=pacer)
        modules = result.setdefault('metadata', {}).setdefault('modules_executed', [])
        if 'openapi' not in modules:
            modules.append('openapi')
        if settings.get('UPDATE_GRAPH_DB', True):
            # This stage also runs when no background graph executor exists
            # (the saved-recon entry path); record actual persistence results.
            result['metadata']['openapi_graph_updated'] = False
            try:
                from graph_db import Neo4jClient
                with Neo4jClient() as client:
                    if not client.verify_connection():
                        raise RuntimeError('Graph unavailable')
                    stats = client.update_graph_from_openapi(result, USER_ID, PROJECT_ID)
                    error_count = len(stats.get('errors', []))
                    result['metadata']['openapi_graph_stats'] = {
                        **{key: value for key, value in stats.items() if key != 'errors'},
                        'error_count': error_count,
                    }
                    result['metadata']['openapi_graph_updated'] = not error_count
                    if error_count:
                        print(f'[!][OpenAPI] Graph ingestion incomplete: {error_count} write errors')
                    else:
                        print(f"[+][OpenAPI] Graph stored {stats.get('operations_imported', 0)} declarations")
            except Exception:
                result['metadata'].setdefault('phase_errors', {})['openapi_graph'] = 'OpenAPI graph ingestion failed'
                print('[!][OpenAPI] Graph ingestion failed; parsed inventory retained')
    except Exception:
        # Request exceptions can embed credentials in URLs; persist a fixed error.
        print('[!][OpenAPI] Ingestion failed; inspect document diagnostics')
        result.setdefault('metadata', {}).setdefault('phase_errors', {})['openapi'] = 'OpenAPI ingestion failed'
    save_recon_file(result, output_file)
    return result


def _maybe_run_ai_surface(result: dict, settings: dict, output_file: Path) -> dict:
    """GROUP 4.5 — AI Surface Recon. Runs after resource_enum at every call site.

    Gated purely on AI_SURFACE_RECON_ENABLED (the js_recon pattern), not
    SCAN_MODULES. Failure-soft: a probe error records a phase_error and the
    pipeline continues.
    """
    if not settings.get('AI_SURFACE_RECON_ENABLED', True):
        return result
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
        try:
            save_recon_file(result, output_file)
        except Exception:
            pass
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


def merge_nmap_into_port_scan(combined_result: dict) -> None:
    """
    Merge Nmap service version data into port_scan.port_details.

    Enriches existing port_details entries (from Naabu/Masscan) with Nmap's
    product, version, CPE, and NSE script results. Does NOT add new ports.
    """
    nmap_data = combined_result.get("nmap_scan", {})
    port_scan = combined_result.get("port_scan", {})
    if not nmap_data or not port_scan:
        return

    enriched_count = 0

    for host, nmap_host in nmap_data.get("by_host", {}).items():
        ps_host = port_scan.get("by_host", {}).get(host)
        if not ps_host:
            continue
        for nmap_pd in nmap_host.get("port_details", []):
            for ps_pd in ps_host.get("port_details", []):
                if ps_pd.get("port") == nmap_pd.get("port"):
                    if nmap_pd.get("product"):
                        ps_pd["product"] = nmap_pd["product"]
                    if nmap_pd.get("version"):
                        ps_pd["version"] = nmap_pd["version"]
                    if nmap_pd.get("cpe"):
                        ps_pd["cpe"] = nmap_pd["cpe"]
                    if nmap_pd.get("scripts"):
                        ps_pd["scripts"] = nmap_pd["scripts"]
                    enriched_count += 1
                    break

    # Update scan_metadata to include nmap
    scanners = port_scan.get("scan_metadata", {}).get("scanners", [])
    if "nmap" not in scanners:
        scanners.append("nmap")
        port_scan.get("scan_metadata", {})["scanners"] = scanners

    if enriched_count:
        print(f"[+][Nmap] Enriched {enriched_count} port(s) with service version data")


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

    if dns_enabled:
        print(f"\n[*][DNS] PHASE 1: Reverse DNS Lookup")
        print("-" * 40)

        for ip in expanded_ips:
            hostname = reverse_dns_lookup(ip, max_retries=settings.get('DNS_MAX_RETRIES', 3))
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
        print(f"\n[-][DNS] PHASE 1: Reverse DNS Lookup — SKIPPED (disabled)")
        for ip in expanded_ips:
            mock_name = ip.replace('.', '-').replace(':', '-')
            ip_to_hostname[ip] = mock_name

    # Step 3: Build DNS data structure for each "subdomain"
    subdomain_names = []
    if dns_enabled:
        print(f"\n[*][DNS] PHASE 2: DNS Resolution for Discovered Hosts")
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
        print(f"\n[-][DNS] PHASE 2: DNS Resolution — SKIPPED (disabled)")
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
        print(f"\n[*][WHOIS] PHASE 3: IP WHOIS Lookup")
        print("-" * 40)
        try:
            from recon.main_recon_modules.whois_recon import whois_lookup as ip_whois_lookup
            # WHOIS a sample of IPs (first one per /24 block to avoid flooding)
            seen_blocks = set()
            for ip in expanded_ips:
                block = '.'.join(ip.split('.')[:3]) if '.' in ip else ip[:16]
                if block in seen_blocks:
                    continue
                seen_blocks.add(block)
                try:
                    result = ip_whois_lookup(ip, save_output=False, settings=settings)
                    ip_whois[ip] = result.get("whois_data", {})
                    org = ip_whois[ip].get("org", "unknown")
                    print(f"[+][WHOIS] {ip}: org={org}")
                except Exception as e:
                    print(f"[-][WHOIS] WHOIS for {ip} failed: {e}")
        except Exception as e:
            print(f"[!][WHOIS] IP WHOIS module error: {e}")
    else:
        print(f"\n[-][WHOIS] PHASE 3: IP WHOIS Lookup — SKIPPED (disabled)")

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
            "subdomain_filter": subdomain_filter,
            "anonymous_mode": False,
            "bruteforce_mode": False,
            "modules_executed": ["ip_recon", "reverse_dns"],
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
                merge_uncover_into_pipeline(combined_result, uncover_data, combined_result.get('domain', ''))
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
        print(f"\n[*][Pipeline] GROUP: Shodan + Port Scan (parallel fan-out)")
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

        # Merge masscan results into port_scan for downstream consumers
        if "masscan_scan" in combined_result:
            merge_port_scan_results(combined_result)

        save_recon_file(combined_result, output_file)

        if "shodan" in combined_result:
            _graph_update_bg("update_graph_from_shodan", combined_result, USER_ID, PROJECT_ID)

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

        from recon.main_recon_modules.nmap_scan import run_nmap_scan
        combined_result = run_nmap_scan(combined_result, output_file=output_file, settings=settings)
        combined_result["metadata"]["modules_executed"].append("nmap_scan")

        # Merge Nmap service versions (incl. ai_runtime_version) into port_scan.port_details
        if "nmap_scan" in combined_result:
            merge_nmap_into_port_scan(combined_result)

        save_recon_file(combined_result, output_file)

        if "nmap_scan" in combined_result:
            _graph_update_bg("update_graph_from_nmap", combined_result, USER_ID, PROJECT_ID)

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
        print(f"\n[*][Pipeline] OSINT Enrichment ({', '.join(enabled_ip_osint.keys())}) — parallel")
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
        save_recon_file(combined_result, output_file)
        for name, (_, _, _, graph_method) in enabled_ip_osint.items():
            if name in combined_result:
                _graph_update_bg(graph_method, combined_result, USER_ID, PROJECT_ID)

    # HTTP Probe
    if "http_probe" in SCAN_MODULES:
        if not settings.get('HTTPX_ENABLED', True):
            print("\n[*][httpx] HTTP probing disabled -- skipping")
        else:
            try:
                combined_result = run_http_probe(combined_result, output_file=output_file, settings=settings)
                combined_result["metadata"]["modules_executed"].append("http_probe")
                save_recon_file(combined_result, output_file)

                _graph_update_bg("update_graph_from_http_probe", combined_result, USER_ID, PROJECT_ID)
                if 'urlscan' in combined_result:
                    _graph_update_bg("update_graph_from_urlscan_enrichment", combined_result, USER_ID, PROJECT_ID)
            except Exception as e:
                print(f"[!][Pipeline] http_probe failed: {e}")
                combined_result["metadata"].setdefault("phase_errors", {})["http_probe"] = str(e)
                save_recon_file(combined_result, output_file)

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
            try:
                combined_result = run_resource_enum(combined_result, output_file=output_file, settings=settings)
                combined_result["metadata"]["modules_executed"].append("resource_enum")
                save_recon_file(combined_result, output_file)
                _graph_update_bg("update_graph_from_resource_enum", combined_result, USER_ID, PROJECT_ID)
            except Exception as e:
                print(f"[!][Pipeline] resource_enum failed: {e}")
                combined_result["metadata"].setdefault("phase_errors", {})["resource_enum"] = str(e)
                save_recon_file(combined_result, output_file)

    # GROUP 4.5 -- AI Surface Recon (runs after resource_enum)
    combined_result = _maybe_run_openapi(combined_result, settings, output_file)
    combined_result = _maybe_run_ai_surface(combined_result, settings, output_file)

    # GROUP 5b -- JS Recon (runs after resource_enum, before vuln_scan;
    # runs even when active scans are skipped -- uploaded files don't need live targets)
    if settings.get('JS_RECON_ENABLED', False):
        try:
            from recon.main_recon_modules.js_recon import run_js_recon
            combined_result = run_js_recon(combined_result, settings=settings)
            combined_result["metadata"]["modules_executed"].append("js_recon")
            save_recon_file(combined_result, output_file)
            _graph_update_bg("update_graph_from_js_recon", combined_result, USER_ID, PROJECT_ID)
        except Exception as e:
            print(f"[!][JsRecon] Error: {e}")

    # GROUP 5.5 -- Supply-Chain Recon (L2): runs AFTER JS-recon (consumes its
    # source_maps + technologies). Black-box package harvest + offline OSV verdict.
    if settings.get('SUPPLY_CHAIN_RECON_ENABLED', False):
        try:
            from recon.main_recon_modules.supply_chain_recon import run_supply_chain_recon
            combined_result = run_supply_chain_recon(combined_result, settings=settings)
            combined_result["metadata"]["modules_executed"].append("supply_chain_recon")
            save_recon_file(combined_result, output_file)
            _graph_update_bg("update_graph_from_supply_chain_recon", combined_result, USER_ID, PROJECT_ID)
        except Exception as e:
            print(f"[!][SupplyChainRecon] Error: {e}")

    if not skip_active_scans:
        if "vuln_scan" in SCAN_MODULES:
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

        if ip_phase_a:
            print(f"\n[*][Pipeline] GROUP 6 Phase A: Active Vulnerability Scanning (fan-out: {', '.join(ip_phase_a.keys())})")
            print("-" * 40)
            with ThreadPoolExecutor(max_workers=len(ip_phase_a)) as pool:
                futures = {pool.submit(fn, combined_result, settings): key
                           for key, fn in ip_phase_a.items()}
                for fut in as_completed(futures):
                    key = futures[fut]
                    try:
                        combined_result[key] = fut.result()
                        combined_result["metadata"]["modules_executed"].append(key)
                        save_recon_file(combined_result, output_file)
                        _graph_update_bg(f"update_graph_from_{key}", combined_result, USER_ID, PROJECT_ID)
                    except Exception as e:
                        print(f"[!][Pipeline] {key} failed: {e}")
                        combined_result["metadata"].setdefault("phase_errors", {})[key] = str(e)
                        save_recon_file(combined_result, output_file)

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


def run_domain_recon(target: str, bruteforce: bool = False,
                     target_info: dict = None,
                     discovery_enabled: bool = None, *, openapi_pacer=None) -> dict:
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
            # Keys a domain-level finding (SPF, DMARC...) on its root, so a
            # batch's roots do not share one Vulnerability node (vuln_mixin).
            "domain_batch": bool(_batch_groups()),
            "subdomain_filter": full_subdomains if filtered_mode else [],
            "anonymous_mode": False,
            "bruteforce_mode": bruteforce if not filtered_mode else False,
            "modules_executed": []
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
        with ThreadPoolExecutor(max_workers=2, thread_name_prefix="group1") as g1_exec:
            g1_futures = {}
            if _settings.get('WHOIS_ENABLED', True):
                g1_futures["whois"] = g1_exec.submit(
                    whois_lookup, root_domain, save_output=False, settings=_settings
                )
            if _settings.get('URLSCAN_ENABLED'):
                from recon.main_recon_modules.urlscan_enrich import run_urlscan_discovery_only
                g1_futures["urlscan"] = g1_exec.submit(
                    run_urlscan_discovery_only, root_domain, _settings
                )

            for name, future in g1_futures.items():
                try:
                    result = future.result()
                    if name == "whois":
                        combined_result["whois"] = result.get("whois_data", {})
                        combined_result["metadata"]["modules_executed"].append("whois")
                        print(f"[+][WHOIS] Data retrieved successfully")
                    elif name == "urlscan":
                        if result:
                            combined_result["urlscan"] = result
                            combined_result["metadata"]["modules_executed"].append("urlscan_enrich")
                            print(f"[+][URLScan] Discovery complete")
                except Exception as e:
                    print(f"[!][{name}] Failed: {e}")

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

        with ThreadPoolExecutor(max_workers=3, thread_name_prefix="group1") as g1_exec:
            g1_futures = {}

            if _settings.get('WHOIS_ENABLED', True):
                g1_futures["whois"] = g1_exec.submit(
                    whois_lookup, root_domain, save_output=False, settings=_settings
                )

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
                    run_urlscan_discovery_only, root_domain, _settings
                )

            g1_results = {}
            for name, future in g1_futures.items():
                try:
                    g1_results[name] = future.result()
                except Exception as e:
                    print(f"[!][{name}] Failed: {e}")
                    g1_results[name] = None

        # Fan-in: merge Group 1 results
        print(f"\n[*][Pipeline] Fan-in — merging parallel results")

        # WHOIS
        whois_data = g1_results.get("whois")
        if whois_data:
            combined_result["whois"] = whois_data.get("whois_data", {})
            combined_result["metadata"]["modules_executed"].append("whois")
            print(f"[+][WHOIS] Data merged")
        elif not _settings.get('WHOIS_ENABLED', True):
            combined_result["whois"] = {"skipped": True}

        # Subdomain discovery
        recon_result = g1_results.get("discovery")
        if recon_result:
            combined_result["metadata"]["modules_executed"].append("subdomain_discovery")
            if recon_result.get("external_domains"):
                combined_result["domain_discovery_external_domains"] = recon_result["external_domains"]

        merged = merge_group_hosts(
            recon_result, target_info, root_domain, _settings, dns_enabled)
        discovered_subs = merged["subdomains"]

        combined_result["subdomains"] = discovered_subs
        combined_result["subdomain_count"] = len(discovered_subs)
        combined_result["dns"] = merged["dns"]
        combined_result["subdomain_status_map"] = merged["status_map"]
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
                merge_uncover_into_pipeline(
                    combined_result, uncover_data, target_info["root_domain"])
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

        # Merge masscan results into port_scan for downstream consumers
        if "masscan_scan" in combined_result:
            merge_port_scan_results(combined_result)

        save_recon_file(combined_result, output_file)

        # Background graph updates for Shodan + port scan
        if "shodan" in combined_result:
            _graph_update_bg("update_graph_from_shodan", combined_result, USER_ID, PROJECT_ID)

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

        from recon.main_recon_modules.nmap_scan import run_nmap_scan
        combined_result = run_nmap_scan(combined_result, output_file=output_file, settings=_settings)
        combined_result["metadata"]["modules_executed"].append("nmap_scan")

        # Merge Nmap service versions into port_scan.port_details
        if "nmap_scan" in combined_result:
            merge_nmap_into_port_scan(combined_result)

        save_recon_file(combined_result, output_file)

        if "nmap_scan" in combined_result:
            _graph_update_bg("update_graph_from_nmap", combined_result, USER_ID, PROJECT_ID)

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

        save_recon_file(combined_result, output_file)

        # Queue graph updates for completed OSINT tools
        for name, (_, _, _, graph_method) in enabled_osint.items():
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
            try:
                combined_result = run_http_probe(combined_result, output_file=output_file, settings=_settings)
                combined_result["metadata"]["modules_executed"].append("http_probe")
                save_recon_file(combined_result, output_file)

                # Background graph updates
                _graph_update_bg("update_graph_from_http_probe", combined_result, USER_ID, PROJECT_ID)
                if 'urlscan' in combined_result:
                    _graph_update_bg("update_graph_from_urlscan_enrichment", combined_result, USER_ID, PROJECT_ID)
            except Exception as e:
                print(f"[!][Pipeline] http_probe failed: {e}")
                combined_result["metadata"].setdefault("phase_errors", {})["http_probe"] = str(e)
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
                merge_discovered_hostnames(
                    combined_result, _san_names, source="certificate_san",
                    root_domain=root_domain, settings=_settings,
                    max_injected=_settings.get('TLSX_MAX_INJECTED_HOSTNAMES', 200),
                )
                save_recon_file(combined_result, output_file)
        except Exception as e:
            print(f"[!][Pipeline] certificate SAN feedback failed: {e}")

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
            try:
                combined_result = run_resource_enum(combined_result, output_file=output_file, settings=_settings)
                combined_result["metadata"]["modules_executed"].append("resource_enum")
                save_recon_file(combined_result, output_file)
                _graph_update_bg("update_graph_from_resource_enum", combined_result, USER_ID, PROJECT_ID)
            except Exception as e:
                print(f"[!][Pipeline] resource_enum failed: {e}")
                combined_result["metadata"].setdefault("phase_errors", {})["resource_enum"] = str(e)
                save_recon_file(combined_result, output_file)

    # GROUP 4.5 — AI Surface Recon (runs after resource_enum)
    combined_result = _maybe_run_openapi(combined_result, _settings, output_file, pacer=openapi_pacer)
    combined_result = _maybe_run_ai_surface(combined_result, _settings, output_file)

    # GROUP 5b — JS Recon (runs after resource_enum, before vuln_scan;
    # runs even when active scans are skipped -- uploaded files don't need live targets)
    if _settings.get('JS_RECON_ENABLED', False):
        try:
            from recon.main_recon_modules.js_recon import run_js_recon
            combined_result = run_js_recon(combined_result, settings=_settings)
            combined_result["metadata"]["modules_executed"].append("js_recon")
            save_recon_file(combined_result, output_file)
            _graph_update_bg("update_graph_from_js_recon", combined_result, USER_ID, PROJECT_ID)
        except Exception as e:
            print(f"[!][JsRecon] Error: {e}")

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

        if phase_a_tools:
            print(f"\n[*][Pipeline] GROUP 6 Phase A: Active Vulnerability Scanning (fan-out: {', '.join(phase_a_tools.keys())})")
            print("-" * 40)
            with ThreadPoolExecutor(max_workers=len(phase_a_tools)) as pool:
                futures = {pool.submit(fn, combined_result, _settings): key
                           for key, fn in phase_a_tools.items()}
                for fut in as_completed(futures):
                    key = futures[fut]
                    try:
                        combined_result[key] = fut.result()
                        combined_result["metadata"]["modules_executed"].append(key)
                        save_recon_file(combined_result, output_file)
                        _graph_update_bg(f"update_graph_from_{key}", combined_result, USER_ID, PROJECT_ID)
                    except Exception as e:
                        print(f"[!][Pipeline] {key} failed: {e}")
                        combined_result["metadata"].setdefault("phase_errors", {})[key] = str(e)
                        save_recon_file(combined_result, output_file)

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


from recon.helpers.finding_sources import RECON_FINDING_SOURCES  # noqa: E402

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


def _prune_recon_findings():
    """Remove the findings this run stopped reporting. AFTER a successful run.

    Only called on the success path, and never when the clear did not run: a
    scan that failed halfway reported nothing, and pruning on that would delete
    the project's entire finding set.

    Findings an operator muted and human-judged ones are kept and stamped stale
    rather than deleted, so an operator can see that a scanner stopped
    reporting something they had already suppressed. A node-filter rule's mute
    is not an operator's decision, so those are pruned like any other.
    """
    if not UPDATE_GRAPH_DB or not _RUN_STARTED_AT:
        return
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                graph_client.prune_unseen_findings(
                    USER_ID, PROJECT_ID, list(RECON_FINDING_SOURCES),
                    _RUN_STARTED_AT)
    except Exception as e:
        # Never fail a completed scan over housekeeping: a finding that should
        # have been pruned is visible and wrong, which beats losing the run.
        print(f"[!][graph-db] Could not prune stale findings: {e}\n")


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
    """Restore the attachable batch roots' Domain nodes after the one-time clear.

    Groups run in order, so without this a later group's root has no Domain node
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
    from recon.helpers.openapi.fetch import RequestPacer

    openapi_pacer = RequestPacer(_settings.get('ROE_GLOBAL_MAX_RPS', 0))
    total = len(groups)
    print("═" * 63)
    print(f"[*][Batch] DOMAIN BATCH: {total} domain group(s), sequential")
    for idx, group in enumerate(groups, 1):
        _pfx = group.get('prefixes') or []
        # '*' is a sentinel, not a host — counting it as one would advertise a
        # group that enumerates thousands of names as "1 host".
        _shape = ('enumerate' if '*' in _pfx
                  else f"{len([p for p in _pfx if p != '*'])} host(s)")
        print(f"  [*][Batch] {idx}. {group.get('rootDomain')} ({_shape})")
    print("═" * 63)
    print()

    # Stale per-group files from a PREVIOUS run would be merged back into the
    # canonical output, resurrecting a domain the operator has since removed.
    removed = clear_batch_outputs(OUTPUT_DIR, PROJECT_ID)
    if removed:
        print(f"[*][Batch] Removed {removed} stale group output file(s) from a previous run")
    # Replace the canonical file NOW. Until the first group finishes and the merge
    # runs, it would otherwise still describe the PREVIOUS run while the graph has
    # already been cleared, so anything reading it in that window (a GVM start only
    # checks the file exists) would scan the last run's targets.
    initialize_batch_canonical(
        OUTPUT_DIR, PROJECT_ID, [str(g.get('rootDomain') or '') for g in groups])
    global _BATCH_ATTACH_ROOTS
    _BATCH_ATTACH_ROOTS = _eligible_batch_roots(groups)
    _seed_batch_root_domains(_BATCH_ATTACH_ROOTS)
    print()

    failed = []
    for idx, group in enumerate(groups, 1):
        root = str(group.get('rootDomain') or '').strip()
        prefixes = [p for p in (group.get('prefixes') or []) if isinstance(p, str)]
        if not root or not prefixes:
            print(f"[!][Batch] Group {idx}/{total} skipped: no usable target")
            failed.append(root or f"group {idx}")
            continue

        # The marker the orchestrator parses into live "Group 2/3" progress.
        print(f"\n[Batch] Group {idx}/{total}: {root}")
        try:
            rc = run_domain_group(root, prefixes, start_time=datetime.now(),
                                  openapi_pacer=openapi_pacer)
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

    # Only a batch where nothing succeeded is a failed run.
    return 1 if len(failed) == total else 0


def main():
    """Run the pipeline, then sweep node filters over what it wrote, whatever happened.

    The sweep sits in a `finally` so an early return or an exception still
    applies the rules to the findings the run managed to write.
    """
    try:
        return _run_pipeline()
    finally:
        _apply_node_filters()


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

        run_ip_recon(TARGET_IPS, _settings)

        _prune_recon_findings()

        end_time = datetime.now()
        duration = end_time - start_time
        print(f"\n[✓][Pipeline] Total time: {duration}")
        return 0

    # RoE: check the time window ONCE, before any target is touched. A batch that
    # starts inside the window runs to completion; re-checking per group would
    # abandon a run half way through and leave the graph partially rebuilt.
    allowed, reason = _check_roe_time_window(_settings)
    if not allowed:
        print(f"\n[RoE] BLOCKED: {reason}")
        print(f"[RoE] Reconnaissance aborted: outside Rules of Engagement time window.")
        return 1

    # ONCE per run, before any group: this is what lets a batch's groups
    # accumulate into a single graph instead of each wiping the last.
    _clear_recon_graph()

    groups = _batch_groups()
    if groups:
        return run_domain_batch(groups, start_time)

    return run_domain_group(TARGET_DOMAIN, SUBDOMAIN_LIST, start_time=start_time)


def run_domain_group(target_domain: str, subdomain_list: list, start_time=None, *, openapi_pacer=None) -> int:
    """Run the whole domain pipeline for ONE target: a single-domain project, or
    one group of a Domain batch.

    Everything that is per-TARGET lives here (ownership verification, target
    parsing, RoE host exclusion, the pipeline itself, the summary). Everything
    that is per-RUN stays in main(): the RoE time window, and above all the
    graph clear, which must happen ONCE so a batch's groups accumulate into one
    graph instead of each wiping the last.

    The target arrives as ARGUMENTS, never through the module globals: a batch
    group's domain is not TARGET_DOMAIN (which is empty in batch mode), and
    downstream modules re-read settings from the API, so a mutated global would
    not reach them anyway.

    Returns 0 on success, 1 if this target was aborted.
    """
    if start_time is None:
        start_time = datetime.now()

    # Domain Ownership Verification (if enabled)
    # This MUST be the first check before any scanning to ensure we only
    # scan domains the user controls.
    if VERIFY_DOMAIN_OWNERSHIP:
        ownership_result = verify_domain_ownership(
            target_domain,
            OWNERSHIP_TOKEN,
            OWNERSHIP_TXT_PREFIX
        )

        if not ownership_result["verified"]:
            print(f"\n[!][Pipeline] SCAN ABORTED: Domain ownership verification failed!")
            print(f"[!][Pipeline] Add TXT record: {ownership_result['record_name']} → \"{ownership_result['expected_value']}\"")
            print(f"[!][Pipeline] Set VERIFY_DOMAIN_OWNERSHIP = False in params.py to disable\n")
            return 1

    # Parse target with this target's subdomain prefixes
    target_info = parse_target(target_domain, subdomain_list)
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

    # RoE: check if root domain itself is excluded
    if _settings.get('ROE_ENABLED') and _settings.get('ROE_EXCLUDED_HOSTS'):
        if _is_roe_excluded(target_domain, _settings['ROE_EXCLUDED_HOSTS']):
            print(f"\n[RoE] BLOCKED: Root domain '{target_domain}' is in ROE excluded hosts list.")
            print(f"[RoE] Reconnaissance aborted — target domain excluded by Rules of Engagement.")
            return 1

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
            discovery_enabled=discovery_enabled,
            openapi_pacer=openapi_pacer,
        )
        _stamp_project_roots(domain_result)
    else:
        # Load existing recon file if domain_discovery not in modules
        if output_file.exists():
            with open(output_file, 'r') as f:
                domain_result = json.load(f)
            _stamp_project_roots(domain_result)
            print(f"[*][Pipeline] Loaded existing recon file: {output_file}")

            # RoE: filter excluded hosts from loaded recon data
            if _settings.get('ROE_ENABLED') and _settings.get('ROE_EXCLUDED_HOSTS'):
                roe_excluded = _settings['ROE_EXCLUDED_HOSTS']
                dns_data = domain_result.get('dns', {})
                subs = dns_data.get('subdomains', {})
                excluded_subs = [s for s in subs if _is_roe_excluded(s, roe_excluded)]
                for s in excluded_subs:
                    del subs[s]
                if excluded_subs:
                    print(f"[RoE] Removed {len(excluded_subs)} excluded subdomain(s) from loaded recon file")
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
        domain_result = _maybe_run_openapi(domain_result, _settings, output_file, pacer=openapi_pacer)
        domain_result = _maybe_run_ai_surface(domain_result, _settings, output_file)

        # GROUP 5b — JS Recon (runs after resource_enum, before vuln_scan;
        # runs even when active scans are skipped -- uploaded files don't need live targets)
        if _settings.get('JS_RECON_ENABLED', False):
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

        if not skip_active_scans:
            # Run vuln_scan if in SCAN_MODULES (when domain_discovery is skipped)
            # vuln_scan automatically includes MITRE CWE/CAPEC enrichment
            if "vuln_scan" in SCAN_MODULES:
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

    _prune_recon_findings()

    return 0


if __name__ == "__main__":
    sys.exit(main())
