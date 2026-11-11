"""Partial recon entry point for web cache poisoning scanning.

Runs recon.cache_scan.run_cache_scan() against live URLs derived from the
existing Neo4j graph (BaseURLs + Endpoints) plus any user-supplied URLs from the
modal. Mirrors graphql_scanning.run_graphqlscan — inputs are graph-derived URLs
(per nodeMapping.ts: SECTION_INPUT_MAP[WebCachePoison] = [BaseURL, Endpoint]).
"""
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.partial_recon_modules.graph_builders import _build_graphql_data_from_graph
from recon.partial_recon_modules.helpers import (
    root_orgs,
    _should_include_root_domain,
    include_root_for,
    ip_mode_recon,
    partial_settings,
    scope_roots,
)


def run_webcachepoison(config: dict) -> None:
    """Run a partial web cache poisoning scan and merge results into the graph.

    User target inputs (per PROMPT.ADD_PARTIAL_RECON.md):
      - config["user_targets"]["urls"]: custom URLs to test directly
      - config["user_targets"]["url_attach_to"]: optional BaseURL to attach UserInputs to
      - config["include_graph_targets"]: whether to merge graph-derived targets
    """
    from recon.cache_scan import run_cache_scan
    from graph_db import Neo4jClient

    roots = scope_roots(config)
    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")

    print("[*][Partial Recon] Loading project settings...")
    settings = partial_settings(config)

    # Force-enable so the DB toggle doesn't override an explicit partial-recon run.
    settings["WEB_CACHE_POISON_ENABLED"] = True

    # Apply settings_overrides from modal checkboxes (bypass DB settings).
    for key, value in (config.get("settings_overrides") or {}).items():
        settings[key] = value

    include_root_domain = _should_include_root_domain(settings)

    user_targets = config.get("user_targets") or {}
    raw_user_urls = user_targets.get("urls") or []
    url_attach_to = user_targets.get("url_attach_to")
    user_urls = [u.strip() for u in raw_user_urls if u and u.strip()]

    print(f"\n{'=' * 50}")
    print("[*][Partial Recon] Web Cache Poisoning Scanning")
    print(f"[*][Partial Recon] Roots: {', '.join(roots)}")
    if user_urls:
        print(f"[+][Partial Recon] {len(user_urls)} custom URL(s) provided"
              + (f" (attach to: {url_attach_to})" if url_attach_to else " (generic UserInput)"))
    print(f"{'=' * 50}\n")

    include_graph = config.get("include_graph_targets", True)
    if include_graph:
        print("[*][Partial Recon] Querying graph for targets (BaseURLs, Endpoints)...")
        recon_data = _build_graphql_data_from_graph(roots, user_id, project_id, settings=settings,
                                                    domain_groups=config.get("domain_groups"))
    else:
        print("[*][Partial Recon] Skipping graph targets (user opted out)")
        recon_data = ip_mode_recon({
            "domain": roots[0] if roots else "",
            "domains": roots,
            "http_probe": {"by_url": {}},
            "resource_enum": {"endpoints": {}, "parameters": {}, "discovered_urls": []},
            "metadata": {
                "roe": {
                    "ROE_ENABLED": settings.get("ROE_ENABLED", False),
                    "ROE_EXCLUDED_HOSTS": settings.get("ROE_EXCLUDED_HOSTS", []) or [],
                }
            },
        }, settings)

    # Honor the Include Root Domain scope toggle: drop the BaseURLs of every
    # apex whose scope excludes it (per root when the groups are known).
    groups = config.get("domain_groups")
    if groups is None:
        excluded_apexes = set() if include_root_domain else {r.lower() for r in roots}
    else:
        excluded_apexes = {r.lower() for r in roots if not include_root_for(r, groups)}
    recon_data.setdefault("metadata", {})["include_root_domain"] = (
        bool(roots) and roots[0].lower() not in excluded_apexes)
    if excluded_apexes:
        kept = {
            url: data for url, data in recon_data["http_probe"]["by_url"].items()
            if (urlparse(url).hostname or "").lower() not in excluded_apexes
        }
        recon_data["http_probe"]["by_url"] = kept

    # Reshape Endpoints into the structure build_target_urls expects.
    # The graph builder emits resource_enum["endpoints"] = {base: [{path, method}]},
    # but build_target_urls_from_resource_enum (the Nuclei-style consumer cache_scan
    # uses) reads resource_enum["by_base_url"][base]["endpoints"][path]. Without this
    # reshape every graph Endpoint is silently dropped and only BaseURLs are scanned.
    # Apex endpoints are filtered too when root-domain scope is off.
    by_base_url: dict = {}
    for base, eps in (recon_data.get("resource_enum", {}).get("endpoints", {}) or {}).items():
        if (urlparse(base).hostname or "").lower() in excluded_apexes:
            continue
        ep_map = {}
        for ep in (eps or []):
            path = ep.get("path")
            if path:
                ep_map[path] = {"method": ep.get("method", "GET"), "parameters": {"query": []}}
        if ep_map:
            by_base_url[base] = {"endpoints": ep_map}
    recon_data.setdefault("resource_enum", {})["by_base_url"] = by_base_url

    # Inject user-provided URLs as live targets (http_probe.by_url entries).
    for u in user_urls:
        recon_data["http_probe"]["by_url"].setdefault(u, {
            "url": u, "host": urlparse(u).hostname or "", "status_code": 200,
            "content_type": "", "headers": {},
        })

    # Guard: no targets at all -> nothing to do.
    baseurl_count = len(recon_data["http_probe"]["by_url"])
    endpoint_count = sum(len(v.get("endpoints", {})) for v in by_base_url.values())
    if baseurl_count == 0 and endpoint_count == 0:
        print("[!][CachePoison] No targets available (graph empty, no custom URLs).")
        print("[!][CachePoison] Enable 'Include graph targets' OR paste custom URLs in the modal.")
        return

    # Run the scanner -- mutates recon_data in place, adds recon_data['cache_scan'].
    run_cache_scan(recon_data, settings)

    # Push results to Neo4j via the mixin.
    with Neo4jClient() as graph_client:
        graph_client.update_graph_from_cache_scan(recon_data, user_id, project_id)
        if user_urls:
            _link_user_urls(graph_client, user_urls, url_attach_to, roots, user_id, project_id)

    summary = recon_data.get("cache_scan", {}).get("summary", {}) or {}
    print(f"\n[+][Partial Recon][CachePoison] {summary.get('total_findings', 0)} finding(s) "
          f"(confirmed={summary.get('confirmed', 0)}, strong={summary.get('strong', 0)}) "
          f"across {summary.get('cacheable_urls', 0)} cacheable URL(s).")


def _link_user_urls(graph_client, user_urls, url_attach_to, roots, user_id, project_id):
    """Attach user-provided URLs to an existing BaseURL or a fresh UserInput node."""
    import uuid

    if url_attach_to:
        print(f"[*][Partial Recon][CachePoison] Linking {len(user_urls)} URL(s) to BaseURL {url_attach_to}")
        return

    user_input_id = f"userinput-cache-{uuid.uuid4().hex[:12]}"
    try:
        graph_client.create_user_input_node(
            domain=roots,
            user_input_data={
                "id": user_input_id,
                "input_type": "url",
                "values": user_urls,
                "tool_id": "WebCachePoison",
            },
            user_id=user_id,
            project_id=project_id,
            root_orgs=root_orgs(roots),
        )
        print(f"[*][Partial Recon][CachePoison] Created UserInput node {user_input_id} for {len(user_urls)} URL(s)")
    except Exception as e:
        print(f"[!][Partial Recon][CachePoison] Failed to create UserInput node: {e}")
