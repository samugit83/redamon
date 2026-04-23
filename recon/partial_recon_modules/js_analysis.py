import os
import sys
import json
import uuid
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.partial_recon_modules.helpers import _is_valid_url


def run_jsrecon(config: dict) -> None:
    """
    Run partial JS Recon analysis. Downloads and analyzes JavaScript files
    from graph-discovered URLs and/or user-provided URLs to find secrets,
    endpoints, source maps, dependencies, DOM sinks, and frameworks.

    Input nodes: BaseURL, Endpoint (from graph)
    Output nodes: Secret, Endpoint (merged into graph)

    Same URL-input pattern as run_jsluice() -- reads BaseURLs + Endpoints
    from graph and/or user-provided URLs, runs JS Recon analysis, merges
    results into the graph via update_graph_from_js_recon.
    """
    from recon.main_recon_modules.js_recon import run_js_recon
    from recon.project_settings import get_settings

    domain = config["domain"]

    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")

    print(f"[*][Partial Recon] Loading project settings...")
    settings = get_settings()

    # Force-enable JS Recon since the user explicitly chose to run it
    settings['JS_RECON_ENABLED'] = True

    print(f"\n{'=' * 50}")
    print(f"[*][Partial Recon] JS Recon Scanner")
    print(f"[*][Partial Recon] Domain: {domain}")
    print(f"{'=' * 50}\n")

    # Parse user targets -- JS Recon accepts URLs (same as Jsluice/Katana)
    user_targets = config.get("user_targets") or {}
    user_urls = []
    url_attach_to = None
    user_input_id = None

    if user_targets:
        for entry in user_targets.get("urls", []):
            entry = entry.strip()
            if entry and _is_valid_url(entry):
                user_urls.append(entry)
            elif entry:
                print(f"[!][Partial Recon] Skipping invalid URL: {entry}")

        url_attach_to = user_targets.get("url_attach_to")  # BaseURL or None

    if user_urls:
        print(f"[+][Partial Recon] Validated {len(user_urls)} custom URLs")
        if url_attach_to:
            print(f"[+][Partial Recon] URLs will be attached to BaseURL: {url_attach_to}")
        else:
            print(f"[+][Partial Recon] URLs will be tracked via UserInput (generic)")

    # Track whether we need a UserInput node
    needs_user_input = bool(user_urls and not url_attach_to)

    # Build target URLs from Neo4j graph (or start empty if user unchecked graph targets)
    include_graph = config.get("include_graph_targets", True)
    target_urls = []

    if include_graph:
        print(f"[*][Partial Recon] Querying graph for targets (BaseURLs + Endpoints)...")
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                driver = graph_client.driver
                with driver.session() as session:
                    # Get all endpoint full URLs (baseurl + path) from the graph
                    result = session.run(
                        """
                        MATCH (e:Endpoint {user_id: $uid, project_id: $pid})
                        RETURN DISTINCT e.baseurl + e.path AS url
                        """,
                        uid=user_id, pid=project_id,
                    )
                    for record in result:
                        url = record["url"]
                        if url:
                            target_urls.append(url)

                    # Also add BaseURLs themselves
                    result = session.run(
                        """
                        MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
                        RETURN DISTINCT b.url AS url
                        """,
                        uid=user_id, pid=project_id,
                    )
                    for record in result:
                        url = record["url"]
                        if url and url not in target_urls:
                            target_urls.append(url)

                print(f"[+][Partial Recon] Found {len(target_urls)} URLs from graph")
            else:
                print("[!][Partial Recon] Neo4j not reachable, cannot fetch graph inputs")
    else:
        print(f"[*][Partial Recon] Skipping graph targets (user opted out)")

    # Add user-provided URLs to target list
    if user_urls:
        print(f"[*][Partial Recon] Adding {len(user_urls)} user-provided URLs")
        for url in user_urls:
            if url not in target_urls:
                target_urls.append(url)

    # Check for uploaded JS files (they're loaded by run_js_recon internally)
    has_uploaded_files = False
    upload_dir = Path(f'/data/js-recon-uploads/{project_id}')
    if upload_dir.exists():
        uploaded = [f for f in upload_dir.iterdir() if f.is_file()]
        if uploaded:
            has_uploaded_files = True
            print(f"[+][Partial Recon] Found {len(uploaded)} uploaded JS file(s) in {upload_dir}")

    if not target_urls and not has_uploaded_files:
        print("[!][Partial Recon] No URLs to analyze and no uploaded JS files found.")
        print("[!][Partial Recon] Run HTTP Probing (Httpx) and Resource Enumeration (Katana/Hakrawler) first, provide URLs manually, or upload JS files.")
        sys.exit(1)

    print(f"[+][Partial Recon] Total {len(target_urls)} URLs for JS Recon analysis{f' + {len(uploaded)} uploaded files' if has_uploaded_files else ''}")

    # Build a combined_result structure that run_js_recon expects
    # It reads from resource_enum.discovered_urls and http_probe.by_url
    # We populate discovered_urls with all our target URLs
    # and http_probe.by_url as an empty dict (no live probe data in partial mode)
    subdomains = []
    if include_graph:
        try:
            from graph_db import Neo4jClient
            with Neo4jClient() as graph_client:
                if graph_client.verify_connection():
                    driver = graph_client.driver
                    with driver.session() as session:
                        result = session.run(
                            """
                            MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                                  -[:HAS_SUBDOMAIN]->(s:Subdomain)
                            RETURN collect(DISTINCT s.name) AS subdomains
                            """,
                            domain=domain, uid=user_id, pid=project_id,
                        )
                        record = result.single()
                        if record:
                            subdomains = record["subdomains"] or []
        except Exception:
            pass

    combined_result = {
        "domain": domain,
        "dns": {
            "subdomains": [{"subdomain": s, "source": "graph"} for s in subdomains],
        },
        "resource_enum": {
            "discovered_urls": target_urls,
        },
        "http_probe": {
            "by_url": {},
        },
        "metadata": {
            "project_id": project_id,
        },
    }

    # Run JS Recon analysis (same function as the full pipeline)
    print(f"[*][Partial Recon] Running JS Recon analysis...")
    combined_result = run_js_recon(combined_result, settings=settings)

    js_recon_data = combined_result.get("js_recon", {})
    secrets_count = len(js_recon_data.get("secrets", []))
    endpoints_count = len(js_recon_data.get("endpoints", []))
    print(f"[+][Partial Recon] JS Recon found {secrets_count} secrets, {endpoints_count} endpoints")

    if not js_recon_data or (not secrets_count and not endpoints_count):
        print("[*][Partial Recon] No JS Recon findings to update in graph")
        if not js_recon_data.get("scan_metadata", {}).get("js_files_analyzed", 0):
            print("[*][Partial Recon] No JS files were found/analyzed. Ensure target URLs contain .js files.")
        return

    # Update the graph database
    print(f"[*][Partial Recon] Updating graph database...")
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                stats = graph_client.update_graph_from_js_recon(
                    recon_data=combined_result,
                    user_id=user_id,
                    project_id=project_id,
                )

                # Link user-provided URLs to graph
                if user_urls:
                    from urllib.parse import urlparse as _urlparse
                    driver = graph_client.driver
                    with driver.session() as session:
                        if url_attach_to:
                            for url in user_urls:
                                parsed = _urlparse(url)
                                base_url = f"{parsed.scheme}://{parsed.netloc}"
                                session.run(
                                    """
                                    MATCH (parent:BaseURL {url: $parent_url, user_id: $uid, project_id: $pid})
                                    MERGE (b:BaseURL {url: $url, user_id: $uid, project_id: $pid})
                                    ON CREATE SET b.source = 'partial_recon_user_input',
                                                  b.host = $host,
                                                  b.updated_at = datetime()
                                    MERGE (b)-[:DISCOVERED_FROM]->(parent)
                                    """,
                                    parent_url=url_attach_to, url=base_url,
                                    uid=user_id, pid=project_id,
                                    host=parsed.netloc.split(":")[0],
                                )
                            print(f"[+][Partial Recon] Linked user URLs to {url_attach_to} via DISCOVERED_FROM")
                        elif needs_user_input:
                            user_input_id = str(uuid.uuid4())
                            graph_client.create_user_input_node(
                                domain=domain,
                                user_input_data={
                                    "id": user_input_id,
                                    "input_type": "urls",
                                    "values": user_urls,
                                    "tool_id": "JsRecon",
                                },
                                user_id=user_id,
                                project_id=project_id,
                            )
                            for url in user_urls:
                                parsed = _urlparse(url)
                                base_url = f"{parsed.scheme}://{parsed.netloc}"
                                session.run(
                                    """
                                    MERGE (b:BaseURL {url: $url, user_id: $uid, project_id: $pid})
                                    ON CREATE SET b.source = 'partial_recon_user_input',
                                                  b.host = $host,
                                                  b.updated_at = datetime()
                                    WITH b
                                    MATCH (ui:UserInput {id: $ui_id})
                                    MERGE (ui)-[:PRODUCED]->(b)
                                    """,
                                    ui_id=user_input_id, url=base_url,
                                    uid=user_id, pid=project_id,
                                    host=parsed.netloc.split(":")[0],
                                )
                            graph_client.update_user_input_status(
                                user_input_id, "completed", stats
                            )
                            print(f"[+][Partial Recon] Created UserInput + linked user URLs via PRODUCED")

                print(f"[+][Partial Recon] Graph updated successfully")
                print(f"[+][Partial Recon] Stats: {json.dumps(stats, default=str)}")
            else:
                print("[!][Partial Recon] Neo4j not reachable, graph not updated")
    except Exception as e:
        print(f"[!][Partial Recon] Graph update failed: {e}")
        raise

    print(f"\n[+][Partial Recon] JS Recon analysis completed successfully")
