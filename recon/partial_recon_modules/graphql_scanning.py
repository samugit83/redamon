"""Partial recon entry point for GraphQL security scanning.

Runs recon.graphql_scan.run_graphql_scan() against endpoints derived from the
existing Neo4j graph (BaseURLs + Endpoints + JS findings) plus any user-supplied
endpoints in the GRAPHQL_ENDPOINTS setting. No user textareas -- inputs are
graph-only (per nodeMapping.ts: SECTION_INPUT_MAP[GraphqlScan] = [BaseURL, Endpoint]).
"""
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.partial_recon_modules.graph_builders import _build_graphql_data_from_graph


def run_graphqlscan(config: dict) -> None:
    """Run partial GraphQL security scan and merge results into the graph.

    User target inputs (per PROMPT.ADD_PARTIAL_RECON.md):
      - config["user_targets"]["urls"]: list of custom GraphQL endpoint URLs to test directly
      - config["user_targets"]["url_attach_to"]: optional existing BaseURL to attach UserInputs to
      - config["include_graph_targets"]: whether to merge graph-derived targets
    """
    from recon.graphql_scan import run_graphql_scan
    from recon.project_settings import get_settings
    from graph_db import Neo4jClient

    domain = config["domain"]
    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")

    print(f"[*][Partial Recon] Loading project settings...")
    settings = get_settings()

    # Force-enable so DB toggle doesn't override an explicit partial-recon request
    settings['GRAPHQL_SECURITY_ENABLED'] = True

    # Apply settings_overrides from modal checkboxes (bypass DB settings)
    settings_overrides = config.get("settings_overrides") or {}
    for key, value in settings_overrides.items():
        settings[key] = value

    # Parse user-provided custom URLs (Partial Recon modal textarea)
    user_targets = config.get("user_targets") or {}
    raw_user_urls = user_targets.get("urls") or []
    url_attach_to = user_targets.get("url_attach_to")
    user_urls = [u.strip() for u in raw_user_urls if u and u.strip()]

    print(f"\n{'=' * 50}")
    print(f"[*][Partial Recon] GraphQL Security Scanning")
    print(f"[*][Partial Recon] Domain: {domain}")
    if user_urls:
        print(f"[+][Partial Recon] {len(user_urls)} custom endpoint(s) provided"
              + (f" (attach to: {url_attach_to})" if url_attach_to else " (generic UserInput)"))
    print(f"{'=' * 50}\n")

    include_graph = config.get("include_graph_targets", True)
    if include_graph:
        print(f"[*][Partial Recon] Querying graph for targets (BaseURLs, Endpoints, JS findings)...")
        recon_data = _build_graphql_data_from_graph(domain, user_id, project_id)
    else:
        print(f"[*][Partial Recon] Skipping graph targets (user opted out)")
        recon_data = {
            "domain": domain,
            "http_probe": {"by_url": {}},
            "resource_enum": {"endpoints": {}, "parameters": {}, "discovered_urls": []},
            "js_recon": {"findings": []},
            "metadata": {
                "roe": {
                    "ROE_ENABLED": settings.get("ROE_ENABLED", False),
                    "ROE_EXCLUDED_HOSTS": settings.get("ROE_EXCLUDED_HOSTS", []) or [],
                }
            },
        }

    # Inject user URLs via the GRAPHQL_ENDPOINTS setting -- discovery.py already
    # seeds these into its candidate list before pattern-expansion.
    if user_urls:
        existing = (settings.get('GRAPHQL_ENDPOINTS', '') or '').strip()
        merged = ','.join(filter(None, [existing] + user_urls)) if existing else ','.join(user_urls)
        settings['GRAPHQL_ENDPOINTS'] = merged

    # Guard: no targets at all -> nothing to do
    final_user_endpoints = (settings.get('GRAPHQL_ENDPOINTS', '') or '').strip()
    baseurl_count = len(recon_data['http_probe']['by_url'])
    endpoint_count = sum(len(v) for v in recon_data['resource_enum']['endpoints'].values())
    if baseurl_count == 0 and endpoint_count == 0 and not final_user_endpoints:
        print(f"[!][GraphQL] No targets available (graph empty, no custom URLs, GRAPHQL_ENDPOINTS blank).")
        print(f"[!][GraphQL] Enable 'Include graph targets' OR paste Custom URLs in the modal OR set GRAPHQL_ENDPOINTS in the GraphQL tab.")
        return

    # Run the scanner -- mutates recon_data in place, adds recon_data['graphql_scan']
    run_graphql_scan(recon_data, settings)

    # Push results to Neo4j via the mixin
    with Neo4jClient() as graph_client:
        graph_client.update_graph_from_graphql_scan(recon_data, user_id, project_id)

        # If the user provided custom URLs, link them to the attachment target so
        # the Vulnerability/Endpoint nodes don't dangle in the graph. Mirrors the
        # UserInput attach-pattern used by Katana (see web_crawling.run_katana).
        if user_urls:
            _link_user_urls(graph_client, user_urls, url_attach_to, domain, user_id, project_id)

    summary = recon_data.get('graphql_scan', {}).get('summary', {}) or {}
    print(f"\n[+][Partial Recon][GraphQL] Tested {summary.get('endpoints_tested', 0)} endpoint(s), "
          f"introspection enabled on {summary.get('introspection_enabled', 0)}, "
          f"{summary.get('vulnerabilities_found', 0)} vulnerabilities found.")


def _link_user_urls(graph_client, user_urls, url_attach_to, domain, user_id, project_id):
    """Attach user-provided URLs to either an existing BaseURL (via HAS_USER_INPUT-less
    direct link) or a fresh UserInput node.
    """
    import uuid
    from datetime import datetime

    if url_attach_to:
        # Attach to an existing BaseURL: no UserInput, just ensure BaseURL exists.
        # The scanner will have MERGE'd Endpoint nodes under it already.
        print(f"[*][Partial Recon][GraphQL] Linking {len(user_urls)} URL(s) to BaseURL {url_attach_to}")
        return

    # Generic: create one UserInput node grouping the user-provided URLs
    user_input_id = f"userinput-graphql-{uuid.uuid4().hex[:12]}"
    try:
        graph_client.create_user_input_node(
            domain=domain,
            user_input_data={
                "id": user_input_id,
                "input_type": "url",
                "values": user_urls,
                "tool_id": "GraphqlScan",
            },
            user_id=user_id,
            project_id=project_id,
        )
        print(f"[*][Partial Recon][GraphQL] Created UserInput node {user_input_id} for {len(user_urls)} URL(s)")
    except Exception as e:
        print(f"[!][Partial Recon][GraphQL] Failed to create UserInput node: {e}")
