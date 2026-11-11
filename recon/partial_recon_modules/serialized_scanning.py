"""Partial recon entry point for the serialized-object scan.

Runs recon.serialized_scan.run_serialized_scan() against targets derived from
the existing Neo4j graph (BaseURLs + Endpoints, per
SECTION_INPUT_MAP[SerializedScan] = [BaseURL, Endpoint]) plus any user-supplied
URLs from the modal, and merges the candidates back. Mirrors
cache_scanning.run_webcachepoison; the scan itself is passive and in-memory.
"""
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.partial_recon_modules.graph_builders import _build_serialized_data_from_graph
from recon.partial_recon_modules.helpers import (
    root_orgs,
    ip_mode_recon,
    partial_settings,
    scope_roots,
)


def run_serialized_scan_partial(config: dict) -> None:
    """Run a partial serialized-object scan and merge candidates into the graph."""
    from recon.serialized_scan import run_serialized_scan
    from graph_db import Neo4jClient

    roots = scope_roots(config)
    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")

    print("[*][Partial Recon] Loading project settings...")
    settings = partial_settings(config)
    # Force-enable so the DB toggle doesn't override an explicit partial-recon run.
    settings["SERIALIZED_SCAN_ENABLED"] = True
    for key, value in (config.get("settings_overrides") or {}).items():
        settings[key] = value

    user_targets = config.get("user_targets") or {}
    raw_user_urls = user_targets.get("urls") or []
    url_attach_to = user_targets.get("url_attach_to")
    user_urls = [u.strip() for u in raw_user_urls if u and u.strip()]

    print(f"\n{'=' * 50}")
    print("[*][Partial Recon] Serialized Object Scanning")
    print(f"[*][Partial Recon] Roots: {', '.join(roots)}")
    if user_urls:
        print(f"[+][Partial Recon] {len(user_urls)} custom URL(s) provided"
              + (f" (attach to: {url_attach_to})" if url_attach_to else " (generic UserInput)"))
    print(f"{'=' * 50}\n")

    include_graph = config.get("include_graph_targets", True)
    if include_graph:
        print("[*][Partial Recon] Querying graph for targets "
              "(BaseURLs, Endpoints, response headers, parameters, forms)...")
        # The builder rebuilds the full serialized corpus the scanner reads -
        # response headers + Set-Cookie, endpoints with parameter sample values,
        # and form field names - and applies Include-Root-Domain scope itself.
        recon_data = _build_serialized_data_from_graph(roots, user_id, project_id, settings=settings,
                                                       domain_groups=config.get("domain_groups"))
    else:
        print("[*][Partial Recon] Skipping graph targets (user opted out)")
        recon_data = ip_mode_recon({
            "domain": roots[0] if roots else "",
            "domains": roots,
            "http_probe": {"by_url": {}},
            "resource_enum": {"endpoints": {}, "parameters": {}, "by_base_url": {},
                              "forms": [], "discovered_urls": []},
            "metadata": {
                "roe": {
                    "ROE_ENABLED": settings.get("ROE_ENABLED", False),
                    "ROE_EXCLUDED_HOSTS": settings.get("ROE_EXCLUDED_HOSTS", []) or [],
                }
            },
        }, settings)

    by_base_url = recon_data.get("resource_enum", {}).get("by_base_url", {})

    # Inject user-provided URLs as live targets (http_probe.by_url entries). The
    # modal gives a URL only, so there is no response data to attach; the scanner
    # still checks the URL's own path/params.
    for u in user_urls:
        recon_data["http_probe"]["by_url"].setdefault(u, {
            "url": u, "host": urlparse(u).hostname or "", "status_code": 200,
            "content_type": "", "headers": {},
        })

    if len(recon_data["http_probe"]["by_url"]) == 0 and not by_base_url:
        print("[!][SerializedScan] No targets available (graph empty, no custom URLs).")
        print("[!][SerializedScan] Enable 'Include graph targets' OR paste custom URLs in the modal.")
        return

    run_serialized_scan(recon_data, settings)

    with Neo4jClient() as graph_client:
        graph_client.update_graph_from_serialized_scan(recon_data, user_id, project_id)
        if user_urls:
            _link_user_urls(graph_client, user_urls, url_attach_to, roots, user_id, project_id)

    summary = recon_data.get("serialized_scan", {}).get("summary", {}) or {}
    print(f"\n[+][Partial Recon][SerializedScan] {summary.get('total_findings', 0)} candidate(s) flagged.")


def _link_user_urls(graph_client, user_urls, url_attach_to, roots, user_id, project_id):
    """Attach user-provided URLs to an existing BaseURL or a fresh UserInput node."""
    import uuid

    if url_attach_to:
        print(f"[*][Partial Recon][SerializedScan] Linking {len(user_urls)} URL(s) to BaseURL {url_attach_to}")
        return

    user_input_id = f"userinput-serialized-{uuid.uuid4().hex[:12]}"
    try:
        graph_client.create_user_input_node(
            domain=roots,
            user_input_data={
                "id": user_input_id,
                "input_type": "url",
                "values": user_urls,
                "tool_id": "SerializedScan",
            },
            user_id=user_id,
            project_id=project_id,
            root_orgs=root_orgs(roots),
        )
        print(f"[*][Partial Recon][SerializedScan] Created UserInput node {user_input_id} for {len(user_urls)} URL(s)")
    except Exception as e:
        print(f"[!][Partial Recon][SerializedScan] Failed to create UserInput node: {e}")
