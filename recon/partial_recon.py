"""
Partial Recon - Entry point for per-tool partial reconnaissance runs.

This script is invoked by the orchestrator as a container command
(instead of main.py) for running individual recon phases on demand.

Configuration is passed via a JSON file whose path is in the
PARTIAL_RECON_CONFIG environment variable.

Currently supported tool_ids:
  - SubdomainDiscovery: runs discover_subdomains() from domain_recon.py
  - Naabu: runs run_port_scan() from port_scan.py
  - Masscan: runs run_masscan_scan() from masscan_scan.py
  - Nmap: runs run_nmap_scan() from nmap_scan.py
  - Masscan: runs run_masscan_scan() from masscan_scan.py
  - Httpx: runs run_http_probe() from http_probe.py
  - Katana: runs run_katana_crawler() from helpers/resource_enum
  - Hakrawler: runs run_hakrawler_crawler() from helpers
  - Ffuf: runs run_ffuf_discovery() from helpers/resource_enum
  - JsRecon: runs run_js_recon() from js_recon.py
  - Shodan: runs run_shodan_enrichment() from shodan_enrich.py
  - Urlscan: runs run_urlscan_discovery_only() from urlscan_enrich.py
  - OsintEnrichment: runs OSINT sub-tools (Censys, FOFA, OTX, etc.) in parallel
"""

import os
import sys
import json
import traceback
from pathlib import Path
from datetime import datetime

# Add project root to path (same pattern as main.py)
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# First, as in main.py: a stop during the imports or the settings load must
# still sweep and exit (recon/helpers/shutdown.py).
from recon.helpers import shutdown
if __name__ == "__main__":
    shutdown.install()

from recon.project_settings import get_settings
from recon.helpers import request_pacer
from recon.helpers.roe_scope import _is_roe_excluded
from recon.partial_recon_modules.helpers import (
    _classify_ip,
    _resolve_hostname,
    _is_ip_or_cidr,
    _is_valid_hostname,
    _is_valid_url,
    STATUS_OK,
    filter_partial_user_input,
    ip_mode_refusal,
    partial_domain_groups,
    print_run_report,
    run_exit_code,
    scope_roots,
    set_project_scope,
    set_run_ip_targets,
    set_run_roe,
    settings_project_roots,
    settings_scope_groups,
)
from recon.partial_recon_modules.graph_builders import (
    _build_recon_data_from_graph,
    _build_port_scan_data_from_graph,
    _build_http_probe_data_from_graph,
    _build_vuln_scan_data_from_graph,
)
from recon.partial_recon_modules.user_inputs import (
    _cleanup_orphan_user_inputs,
    _create_user_subdomains_in_graph,
)
from recon.partial_recon_modules.subdomain_discovery import run_subdomain_discovery
from recon.partial_recon_modules.port_scanning import (
    run_naabu,
    run_masscan,
    run_nmap,
)
from recon.partial_recon_modules.tlsx_scanning import run_tlsx
from recon.partial_recon_modules.http_probing import run_httpx
from recon.partial_recon_modules.web_crawling import (
    run_katana,
    run_hakrawler,
    run_zap_ajax_spider_partial,
    run_ffuf,
    run_gau,
    run_jsluice,
)
from recon.partial_recon_modules.parameter_discovery import (
    run_paramspider,
    run_arjun,
    run_kiterunner,
)
from recon.partial_recon_modules.endpoint_ai_classification import run_endpoint_ai_classifier
from recon.partial_recon_modules.ai_surface_recon import run_ai_surface_recon as run_ai_surface_partial
from recon.partial_recon_modules.js_analysis import run_jsrecon
from recon.partial_recon_modules.supply_chain import run_supply_chain
from recon.partial_recon_modules.graphql_scanning import run_graphqlscan
from recon.partial_recon_modules.cache_scanning import run_webcachepoison
from recon.partial_recon_modules.serialized_scanning import run_serialized_scan_partial
from recon.partial_recon_modules.origin_enrichment import run_origin_discovery
from recon.partial_recon_modules.vulnerability_scanning import (
    run_nuclei,
    run_security_checks_partial,
    run_subdomain_takeover_partial,
    run_vhost_sni_partial,
)
from recon.partial_recon_modules.osint_enrichment import (
    run_shodan,
    run_urlscan,
    run_uncover,
    run_osint_enrichment,
)


# The only settings a partial run may override, and the only keys the modal
# sends (the Nuclei checkboxes in PartialReconModal). The modules apply every
# override they receive, so without this a crafted request could switch off
# ROE_ENABLED or empty ROE_EXCLUDED_HOSTS for one run. Mirrors
# PARTIAL_OVERRIDE_KEYS in recon_orchestrator/batch_scope.py, which answers 400.
ALLOWED_SETTINGS_OVERRIDES = frozenset({
    "CVE_LOOKUP_ENABLED",
    "MITRE_ENABLED",
    "SECURITY_CHECK_ENABLED",
})

# The on/off switch(es) each partial tool runs under: its module forces them on,
# because the operator asked for that tool. Only the tool -> switch link lives
# here; whether stealth turns a switch off is read from the registry's stealth
# profile (_stealth_refusal). test_partial_stealth_refusal.py fails a dispatched
# tool with no row and a forced switch missing from every row.
PARTIAL_TOOL_SWITCHES = {
    "SubdomainDiscovery": ("SUBDOMAIN_DISCOVERY_ENABLED",),
    "Naabu": ("NAABU_ENABLED",),
    "Masscan": ("MASSCAN_ENABLED",),
    "Nmap": ("NMAP_ENABLED",),
    "Tlsx": ("TLSX_ENABLED",),
    "Httpx": ("HTTPX_ENABLED",),
    "IpAttribution": ("IP_ATTRIBUTION_ENABLED",),
    "Katana": ("KATANA_ENABLED",),
    "Hakrawler": ("HAKRAWLER_ENABLED",),
    "ZapAjaxSpider": ("ZAP_AJAX_SPIDER_ENABLED",),
    "Gau": ("GAU_ENABLED",),
    "Jsluice": ("JSLUICE_ENABLED",),
    "Kiterunner": ("KITERUNNER_ENABLED",),
    "ParamSpider": ("PARAMSPIDER_ENABLED",),
    "Ffuf": ("FFUF_ENABLED",),
    "Arjun": ("ARJUN_ENABLED",),
    "EndpointAiClassifier": ("RESOURCE_ENUM_AI_CLASSIFIER_ENABLED",),
    "OpenAPI": ("OPENAPI_ENABLED",),
    "AiSurfaceRecon": ("AI_SURFACE_RECON_ENABLED",),
    "JsRecon": ("JS_RECON_ENABLED",),
    "SerializedScan": ("SERIALIZED_SCAN_ENABLED",),
    "RouteExposure": ("ROUTE_EXPOSURE_ENABLED",),
    "SupplyChainRecon": ("SUPPLY_CHAIN_RECON_ENABLED", "JS_RECON_ENABLED"),
    "GraphqlScan": ("GRAPHQL_SECURITY_ENABLED",),
    "Nuclei": ("NUCLEI_ENABLED",),
    "SubdomainTakeover": ("SUBDOMAIN_TAKEOVER_ENABLED",),
    "VhostSni": ("VHOST_SNI_ENABLED",),
    "WebCachePoison": ("WEB_CACHE_POISON_ENABLED",),
    "SecurityChecks": ("SECURITY_CHECK_ENABLED",),
    "Shodan": ("SHODAN_ENABLED",),
    "Urlscan": ("URLSCAN_ENABLED",),
    "Uncover": ("UNCOVER_ENABLED", "OSINT_ENRICHMENT_ENABLED"),
    "OsintEnrichment": ("OSINT_ENRICHMENT_ENABLED",),
    "OriginDiscovery": ("ORIGIN_DISCOVERY_ENABLED",),
}


def _stealth_refusal(tool_id: str, settings: dict):
    """Why stealth mode refuses this partial tool, or None.

    The module would force its switch back on after get_settings() applied the
    stealth profile, so a partial FFuf in a stealth project ran unthrottled. A
    tool is refused when the profile sets one of its switches to false; a tool
    stealth only throttles runs, on the stealth values already applied. A tool
    with no row is refused too: stealth never assumes an unknown tool is quiet.
    """
    if not settings.get("STEALTH_MODE"):
        return None
    switches = PARTIAL_TOOL_SWITCHES.get(tool_id)
    if switches is None:
        return f"{tool_id} has no recorded on/off switch, so it does not run in stealth mode"
    from recon.settings_registry import stealth_profile
    profile = stealth_profile()
    off = [key for key in switches if (profile.get(key) or {}).get("set", True) is False]
    if off:
        return f"{tool_id} is off in stealth mode ({', '.join(off)})"
    return None



def load_config() -> dict:
    """Load partial recon configuration from JSON file."""
    config_path = os.environ.get("PARTIAL_RECON_CONFIG")
    if not config_path:
        print("[!][Partial] PARTIAL_RECON_CONFIG not set")
        sys.exit(1)

    try:
        with open(config_path, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"[!][Partial] Failed to load config from {config_path}: {e}")
        sys.exit(1)


def _allowlist_overrides(overrides) -> dict:
    """Keep only ALLOWED_SETTINGS_OVERRIDES; log the name of anything dropped."""
    if not isinstance(overrides, dict):
        return {}
    kept = {}
    for key, value in overrides.items():
        if key in ALLOWED_SETTINGS_OVERRIDES:
            kept[key] = value
        else:
            print(f"[!][Partial Recon] Ignoring settings override that is not allowed: {key!r}")
    return kept


def _ownership_verified(root: str, settings: dict) -> bool:
    """The full pipeline's ownership rule (§4.8), failing closed on any error.

    The token may sit at <prefix>.<scan root> or <prefix>.<registrable domain>;
    either passes. A resolver failure on the first name ends the check: it is
    not "no record", so the second name is not tried.
    """
    org = next((g.get("orgDomain") for g in settings_scope_groups(settings)
                if str(g.get("scanRoot") or "").lower() == root.lower()), None)
    names = [root] + ([org] if org and org.lower() != root.lower() else [])
    try:
        from recon.main_recon_modules.domain_recon import verify_domain_ownership
        for name in names:
            result = verify_domain_ownership(
                name,
                settings.get("OWNERSHIP_TOKEN", ""),
                settings.get("OWNERSHIP_TXT_PREFIX") or "_redamon-verify",
            )
            if result.get("verified"):
                return True
            if result.get("resolver_failed"):
                print(f"[!][Partial Recon] Ownership check for {root}: {result.get('error')}")
                return False
    except Exception as e:  # noqa: BLE001 - an unanswered check is a failed check
        print(f"[!][Partial Recon] Ownership check for {root} failed ({type(e).__name__})")
        return False
    return False


def _refusal_reason(root: str, settings: dict, project_roots: list):
    """Why the full pipeline would refuse this root, or None.

    The same two per-target checks run_domain_group applies (RoE excluded host,
    domain ownership), plus one the full pipeline never needs: the root must
    still be a project target when the container reads the settings.
    """
    if root.lower() not in {r.lower() for r in project_roots}:
        return "refused: no longer a project target"
    excluded = settings.get("ROE_EXCLUDED_HOSTS") or []
    if settings.get("ROE_ENABLED") and excluded and _is_roe_excluded(root, excluded):
        return "refused-roe"
    if (not settings.get("IP_MODE") and settings.get("VERIFY_DOMAIN_OWNERSHIP")
            and not _ownership_verified(root, settings)):
        return "refused-ownership"
    return None


def _prepare_scope(config: dict, settings: dict, project_id: str):
    """Refuse roots and write the scope the modules read.

    Returns {root: reason} for each refused root, for the report.
    """
    project_roots = settings_project_roots(settings, project_id)
    refused, kept = {}, []
    for root in scope_roots(config):
        reason = _refusal_reason(root, settings, project_roots)
        if reason:
            print(f"[!][Partial Recon] Not scanning {root}: {reason}")
            refused[root] = reason
        else:
            kept.append(root)

    config["domains"] = kept
    config["domain"] = kept[0] if kept else ""
    config["domain_groups"] = partial_domain_groups(settings, kept)
    # Every scan root of the project and its org, for the builders' longest-
    # root rule and the writers' org attach (the graph names a Domain after the org).
    set_project_scope(settings_scope_groups(settings))
    set_run_roe(settings)
    # Before the typed-input filter and every builder: both keep to this list.
    set_run_ip_targets(settings)
    config["ip_mode"] = bool(settings.get("IP_MODE"))
    config["batch_mode"] = bool(settings.get("DOMAIN_BATCH_MODE"))
    config["settings_overrides"] = _allowlist_overrides(config.get("settings_overrides"))
    config["_settings"] = settings

    typed = _typed_anything(config)
    dropped = filter_partial_user_input(config, settings)
    for item in dropped:
        print(f"[!][Partial Recon] Not using typed input outside the scope: {item}")
    if typed and not _typed_anything(config) and not config.get("include_graph_targets", True):
        print("[!][Partial Recon] No typed target is in this project's scope.")
        for root in kept:
            refused[root] = "refused: no typed target in scope"
        config["domains"], config["domain"] = [], ""
    return refused


def _typed_anything(config: dict) -> bool:
    targets = config.get("user_targets") or {}
    return bool(config.get("user_inputs")) or any(
        targets.get(k) for k in ("subdomains", "urls", "ips"))


# Which name the graph's Domain node carries: the org (registrable domain);
# mirrors GRAPH_DOMAIN_IS_ORG in webapp/src/lib/scopeGroups.ts.
GRAPH_DOMAIN_IS_ORG = True


def _legacy_graph_refusal(settings: dict, user_id: str, project_id: str):
    """Why this project's graph is refused as built under an older scope model, or None.

    The webapp refuses the same thing before it starts a job (§4.11.6); this is
    the backstop for a job that reached the container another way. It fails
    closed: a graph it cannot read is a graph it cannot vouch for.
    """
    if settings.get("IP_MODE"):
        return None
    groups = settings_scope_groups(settings)
    expected = sorted({(g["orgDomain"] if GRAPH_DOMAIN_IS_ORG else g["scanRoot"]).lower() for g in groups})
    related = sorted({n.lower() for g in groups for n in (g["orgDomain"], g["scanRoot"])})
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as client:
            if not client.verify_connection():
                return "the graph database is unreachable, so the scope model cannot be checked"
            legacy = client.legacy_domain_nodes(user_id, project_id, expected, related)
    except Exception as e:  # noqa: BLE001 - an unanswered check is a failed check
        return f"the scope model check failed ({type(e).__name__})"
    if legacy:
        return ("this project's graph was built before the current scope model "
                f"({', '.join(sorted(legacy)[:5])}); run a full recon first")
    return None


def _run_tool(tool_id: str, config: dict):
    """Run the tool; return ({root: status}, completed).

    A tool's own sys.exit() or exception fails the run rather than escaping, so
    the report is still printed. `completed` is False in that case.
    """
    roots = scope_roots(config)
    try:
        outcome = _dispatch(tool_id, config)
    except SystemExit as e:
        if e.code in (0, None):
            return {root: STATUS_OK for root in roots}, True
        return {root: "failed: SystemExit" for root in roots}, False
    except Exception as e:  # noqa: BLE001 - reported below, and the exit code says it failed
        traceback.print_exc()
        return {root: f"failed: {type(e).__name__}" for root in roots}, False
    if isinstance(outcome, dict):
        return outcome, True
    return {root: STATUS_OK for root in roots}, True


# The job's start stamp, kept where the stopper's sweep can read it. None until
# the dispatch starts: a job stopped before then wrote nothing, so the sweep
# skips itself.
_STARTED_AT = None


def main():
    global _STARTED_AT
    shutdown.set_sweep(lambda: _apply_node_filters(_STARTED_AT))
    config = load_config()
    tool_id = config.get("tool_id", "")

    # Every partial-recon tool reads its inputs from the graph and writes results
    # back, so a broken /app/graph_db bind mount is fatal. Fail here with one
    # actionable line instead of deep inside a tool with a bare
    # "cannot import name 'Neo4jClient' from 'graph_db' (unknown location)".
    from recon.graph_db_preflight import require_graph_db
    require_graph_db("Partial Recon")

    # HTTP traffic capture (Phase 1): configure capture-proxy routing for partial
    # recon too (each partial job is a fresh process, so it must configure itself).
    try:
        from helpers.proxy_routing import configure as _configure_capture_routing
        _configure_capture_routing(config)
    except Exception as _cap_err:
        print(f"[!][capture] partial-recon routing not configured: {_cap_err}")

    print(f"[*][Partial Recon] Starting partial recon for tool: {tool_id}")
    print(f"[*][Partial Recon] Timestamp: {datetime.now().isoformat()}")
    from recon.helpers import circuit_breaker
    circuit_breaker.announce_mode()

    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")

    # Loaded ONCE, and handed to the module: the refusal below and the tool must
    # judge the same settings. get_settings() raises when the webapp is
    # unreachable, so an unverifiable scope ends the run here.
    try:
        settings = get_settings()
    except Exception as e:  # noqa: BLE001 - fail closed, whatever the cause
        print(f"[!][Partial Recon] Cannot load the project settings ({type(e).__name__}). "
              f"Refusing to scan.")
        sys.exit(1)
    # The RoE ceiling for the requests the tool sends in-process (security
    # checks, OpenAPI...), before any of them runs.
    request_pacer.configure(settings)

    # Before the scope pass: a refused tool should not even make its ownership
    # TXT lookups or graph reads.
    stealth = _stealth_refusal(tool_id, settings)
    if stealth:
        print(f"[!][Partial Recon] Refusing to run: {stealth}")
        print_run_report(tool_id, {}, {root: f"refused: {stealth}" for root in scope_roots(config)})
        sys.exit(1)
    ip_refusal = ip_mode_refusal(tool_id, settings)
    if ip_refusal:
        print(f"[!][Partial Recon] Refusing to run {tool_id}: {ip_refusal}")
        print_run_report(tool_id, {}, {root: ip_refusal for root in scope_roots(config)})
        sys.exit(1)

    refused = _prepare_scope(config, settings, project_id)
    if not scope_roots(config):
        print_run_report(tool_id, {}, refused)
        sys.exit(1)
    legacy = _legacy_graph_refusal(settings, user_id, project_id)
    if legacy:
        print(f"[!][Partial Recon] Refusing to scan: {legacy}")
        print_run_report(tool_id, {}, {root: f"refused: {legacy}" for root in scope_roots(config)})
        sys.exit(1)
    print(f"[*][Partial Recon] Roots: {', '.join(scope_roots(config))}")

    # Taken BEFORE the dispatch: everything this job writes is stamped later, so
    # the end-of-job node-filter sweep reaches exactly what it wrote.
    from graph_db.mixins.base_mixin import run_timestamp
    _STARTED_AT = run_timestamp()
    try:
        statuses, completed = _run_tool(tool_id, config)
    finally:
        shutdown.sweep_once()
        # A stopped job ends in the stopper (exit 143), not in the report below.
        shutdown.park()

    # A partial run never prunes, so its coverage gaps protect nothing here; the
    # drain still says which empty results looked like a failure, and asks Jev
    # about the unexplained ones when the hook is on.
    from recon.helpers.ai_planner.tool_health import finish_tool_health
    finish_tool_health(
        settings,
        jev=bool(settings.get('AI_IN_PIPELINE') and settings.get('RESOURCE_ENUM_JEV_TOOL_HEALTH')))

    # Clean up orphan UserInput nodes (created but no PRODUCED children)
    if completed and user_id and project_id:
        _cleanup_orphan_user_inputs(user_id, project_id)

    print_run_report(tool_id, statuses, refused)
    exit_code = run_exit_code(statuses)
    if exit_code:
        sys.exit(exit_code)


def _apply_node_filters(started_at):
    """Sweep node filters over what this job wrote. Never raises.

    The rules are re-read now, not at job start: up to twelve partial recons
    can run at once, and one that started before an operator's save must not
    apply the rules that save replaced.
    """
    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")
    if not user_id or not project_id:
        return
    try:
        from recon.helpers.finding_sources import RECON_FINDING_SOURCES
        from recon.helpers.node_filter_sweep import run_node_filter_sweep
        run_node_filter_sweep(user_id, project_id, started_at, RECON_FINDING_SOURCES)
    except Exception as e:  # noqa: BLE001 - a sweep must never change the job's outcome
        print(f"[!][NODE-FILTER] sweep failed: {e}")


def _dispatch(tool_id: str, config: dict):
    """Run one tool. Loop tools return {root: status}; the rest return None."""
    # main() refuses these before the scope pass; this holds for any other
    # caller that dispatches an IP-mode config.
    ip_refusal = ip_mode_refusal(tool_id, {"IP_MODE": config.get("ip_mode")})
    if ip_refusal:
        print(f"[!][Partial Recon] Refusing to run {tool_id}: {ip_refusal}")
        return {root: ip_refusal for root in scope_roots(config)}
    if tool_id == "SubdomainDiscovery":
        return run_subdomain_discovery(config)
    elif tool_id == "Naabu":
        return run_naabu(config)
    elif tool_id == "Masscan":
        return run_masscan(config)
    elif tool_id == "Nmap":
        return run_nmap(config)
    elif tool_id == "Tlsx":
        return run_tlsx(config)
    elif tool_id == "Httpx":
        return run_httpx(config)
    elif tool_id == "IpAttribution":
        from recon.partial_recon_modules.ip_attribution import run_ip_attribution_partial
        return run_ip_attribution_partial(config)
    elif tool_id == "Katana":
        return run_katana(config)
    elif tool_id == "Hakrawler":
        return run_hakrawler(config)
    elif tool_id == "ZapAjaxSpider":
        return run_zap_ajax_spider_partial(config)
    elif tool_id == "Gau":
        return run_gau(config)
    elif tool_id == "Jsluice":
        return run_jsluice(config)
    elif tool_id == "Kiterunner":
        return run_kiterunner(config)
    elif tool_id == "ParamSpider":
        return run_paramspider(config)
    elif tool_id == "Ffuf":
        return run_ffuf(config)
    elif tool_id == "Arjun":
        return run_arjun(config)
    elif tool_id == "EndpointAiClassifier":
        return run_endpoint_ai_classifier(config)
    elif tool_id == "OpenAPI":
        from recon.partial_recon_modules.openapi_recon import run_openapi_partial
        return run_openapi_partial(config)
    elif tool_id == "AiSurfaceRecon":
        return run_ai_surface_partial(config)
    elif tool_id == "JsRecon":
        return run_jsrecon(config)
    elif tool_id == "SerializedScan":
        return run_serialized_scan_partial(config)
    elif tool_id == "RouteExposure":
        from recon.partial_recon_modules.route_exposure_scanning import run_route_exposure_partial
        return run_route_exposure_partial(config)
    elif tool_id == "SupplyChainRecon":
        return run_supply_chain(config)
    elif tool_id == "GraphqlScan":
        return run_graphqlscan(config)
    elif tool_id == "Nuclei":
        return run_nuclei(config)
    elif tool_id == "SubdomainTakeover":
        return run_subdomain_takeover_partial(config)
    elif tool_id == "VhostSni":
        return run_vhost_sni_partial(config)
    elif tool_id == "WebCachePoison":
        return run_webcachepoison(config)
    elif tool_id == "SecurityChecks":
        return run_security_checks_partial(config)
    elif tool_id == "Shodan":
        return run_shodan(config)
    elif tool_id == "Urlscan":
        return run_urlscan(config)
    elif tool_id == "Uncover":
        return run_uncover(config)
    elif tool_id == "OsintEnrichment":
        return run_osint_enrichment(config)
    elif tool_id == "OriginDiscovery":
        return run_origin_discovery(config)
    else:
        print(f"[!][Partial Recon] Unknown tool_id: {tool_id}")
        sys.exit(1)


if __name__ == "__main__":
    main()
