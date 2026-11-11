"""Partial recon entry point for the route exposure scan.

Runs recon.route_exposure.run_route_exposure(), the entry the full pipeline
uses (so the Jev hooks are inherited), against the BaseURLs and Endpoints of the
existing graph (SECTION_INPUT_MAP[RouteExposure] = [BaseURL, Endpoint]) plus the
URLs typed in the modal, and merges the results back. Mirrors
serialized_scanning.run_serialized_scan_partial; a partial run never prunes.
"""
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.partial_recon_modules.graph_builders import (
    _build_route_exposure_data_from_graph,
    graph_scope_subdomains,
)
from recon.partial_recon_modules.helpers import (
    _scope_partial_urls,
    partial_settings,
    root_orgs,
    scope_roots,
)


def _empty_recon_data(roots: list, settings: dict) -> dict:
    return {
        "domain": roots[0] if roots else "",
        "domains": roots,
        "subdomains": [],
        "http_probe": {"by_url": {}},
        "resource_enum": {"by_base_url": {}},
        "metadata": {
            "include_root_domain": bool(settings.get("INCLUDE_ROOT_DOMAIN", False)),
            "expanded_ips": list(settings.get("TARGET_IPS") or []) if settings.get("IP_MODE") else [],
            "roe": {
                "ROE_ENABLED": settings.get("ROE_ENABLED", False),
                "ROE_EXCLUDED_HOSTS": settings.get("ROE_EXCLUDED_HOSTS", []) or [],
            },
        },
    }


def _graph_subdomains(roots, user_id, project_id, domain_groups) -> list:
    from graph_db import Neo4jClient
    try:
        with Neo4jClient() as graph_client:
            if not graph_client.verify_connection():
                return []
            with graph_client.driver.session() as session:
                return graph_scope_subdomains(session, user_id, project_id, roots, domain_groups)
    except Exception as e:  # noqa: BLE001 - the scope then holds the typed and graph URL hosts only
        print(f"[!][Partial Recon][RouteExposure] Could not read the graph's subdomains ({type(e).__name__})")
        return []


def run_route_exposure_partial(config: dict) -> None:
    """Run a partial route exposure scan and merge its results into the graph."""
    from recon.route_exposure import run_route_exposure
    from graph_db import Neo4jClient

    roots = scope_roots(config)
    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")
    domain_groups = config.get("domain_groups")

    print("[*][Partial Recon] Loading project settings...")
    settings = partial_settings(config)
    # Force-enable so the DB toggle doesn't override an explicit partial-recon run.
    settings["ROUTE_EXPOSURE_ENABLED"] = True
    for key, value in (config.get("settings_overrides") or {}).items():
        settings[key] = value

    user_targets = config.get("user_targets") or {}
    url_attach_to = user_targets.get("url_attach_to")
    # Already scope-filtered when the run started (filter_partial_user_input).
    user_urls = [u.strip() for u in user_targets.get("urls") or [] if u and u.strip()]

    print(f"\n{'=' * 50}")
    print("[*][Partial Recon] Route Exposure")
    print(f"[*][Partial Recon] Roots: {', '.join(roots)}")
    if user_urls:
        print(f"[+][Partial Recon] {len(user_urls)} custom URL(s) provided"
              + (f" (attach to: {url_attach_to})" if url_attach_to else " (generic UserInput)"))
    print(f"{'=' * 50}\n")

    if config.get("include_graph_targets", True):
        print("[*][Partial Recon] Querying graph for targets (BaseURLs, Endpoints)...")
        recon_data = _build_route_exposure_data_from_graph(roots, user_id, project_id,
                                                           settings=settings, domain_groups=domain_groups)
        graph_subdomains = _graph_subdomains(roots, user_id, project_id, domain_groups)
    else:
        print("[*][Partial Recon] Skipping graph targets (user opted out)")
        recon_data = _empty_recon_data(roots, settings)
        graph_subdomains = []

    by_url = recon_data["http_probe"]["by_url"]
    by_base = recon_data["resource_enum"]["by_base_url"]
    graph_urls = list(by_url) + [b for b in by_base if b not in by_url]
    kept, scope_hosts = _scope_partial_urls(graph_urls, user_urls, graph_subdomains, settings,
                                            roots, domain_groups=domain_groups)
    # The probe scope and the writer's scope both read `subdomains`: without the
    # typed URLs' hosts there, a typed URL would be refused as out of scope.
    recon_data["subdomains"] = scope_hosts
    for url in list(by_url):
        if url not in kept:
            by_url.pop(url)
    for base in list(by_base):
        if base not in kept:
            by_base.pop(base)
    for url in user_urls:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            continue
        base = f"{parsed.scheme}://{parsed.netloc}"
        by_url.setdefault(base, {"url": base, "host": parsed.hostname or "", "status_code": 200,
                                 "technologies": []})
        path = parsed.path or "/"
        endpoints = by_base.setdefault(base, {"endpoints": {}})["endpoints"]
        # The typed route and the root of its host, so the generators have a base.
        for p in dict.fromkeys([path, "/"]):
            endpoints.setdefault(p, {"methods": ["GET"], "category": "other", "sources": ["user_input"]})

    if not by_url and not by_base:
        print("[!][RouteExposure] No targets available (graph empty, no custom URLs).")
        print("[!][RouteExposure] Enable 'Include graph targets' OR paste custom URLs in the modal.")
        return

    run_route_exposure(recon_data, settings)

    with Neo4jClient() as graph_client:
        graph_client.update_graph_from_route_exposure(recon_data, user_id, project_id)
        if user_urls:
            findings = (recon_data.get("route_exposure") or {}).get("findings") or []
            _link_user_urls(graph_client, user_urls, url_attach_to, roots, user_id, project_id, findings)

    summary = (recon_data.get("route_exposure") or {}).get("summary") or {}
    print(f"\n[+][Partial Recon][RouteExposure] {summary.get('candidates', 0)} lead(s), "
          f"{summary.get('findings', 0)} signature finding(s).")


def _link_user_urls(graph_client, user_urls, url_attach_to, roots, user_id, project_id, findings=()):
    """Attach typed URLs to an existing BaseURL, or record them on a UserInput node
    that PRODUCED the findings on their base URLs."""
    import uuid

    if url_attach_to:
        print(f"[*][Partial Recon][RouteExposure] Linking {len(user_urls)} URL(s) to an existing BaseURL")
        return

    typed_bases = {f"{p.scheme}://{p.netloc}" for p in map(urlparse, user_urls)}
    produced = [f for f in findings if f.get("baseurl") in typed_bases]
    user_input_id = f"userinput-route-exposure-{uuid.uuid4().hex[:12]}"
    try:
        graph_client.create_user_input_node(
            domain=roots,
            user_input_data={
                "id": user_input_id,
                "input_type": "url",
                "values": user_urls,
                "tool_id": "RouteExposure",
            },
            user_id=user_id,
            project_id=project_id,
            root_orgs=root_orgs(roots),
        )
        linked = graph_client.link_route_exposure_user_input(user_input_id, produced, user_id, project_id)
        graph_client.update_user_input_status(user_input_id, "completed", {"findings": linked}, user_id=user_id, project_id=project_id)
        print(f"[*][Partial Recon][RouteExposure] Created UserInput node for {len(user_urls)} URL(s), "
              f"PRODUCED {linked} finding(s)")
    except Exception as e:  # noqa: BLE001
        print(f"[!][Partial Recon][RouteExposure] Failed to record the UserInput node ({type(e).__name__})")
