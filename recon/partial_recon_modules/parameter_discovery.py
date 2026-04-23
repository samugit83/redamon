import os
import sys
import json
import uuid
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.partial_recon_modules.helpers import _is_valid_url, _is_valid_hostname
from recon.partial_recon_modules.graph_builders import _build_http_probe_data_from_graph
from recon.partial_recon_modules.user_inputs import _create_user_subdomains_in_graph


def run_paramspider(config: dict) -> None:
    """
    Run partial ParamSpider passive parameter discovery.

    ParamSpider queries the Wayback Machine for historical URLs containing
    query parameters for target domains/subdomains.
    Results are organized into Endpoint/Parameter/BaseURL nodes and merged
    into the graph via update_graph_from_resource_enum().
    """
    from recon.helpers.resource_enum.paramspider_helpers import (
        run_paramspider_discovery,
        merge_paramspider_into_by_base_url,
    )
    from recon.project_settings import get_settings

    domain = config["domain"]

    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")

    print(f"[*][Partial Recon] Loading project settings...")
    settings = get_settings()

    # Force-enable ParamSpider since the user explicitly chose to run it
    settings['PARAMSPIDER_ENABLED'] = True

    print(f"\n{'=' * 50}")
    print(f"[*][Partial Recon] ParamSpider Passive Parameter Discovery")
    print(f"[*][Partial Recon] Domain: {domain}")
    print(f"{'=' * 50}\n")

    # Parse user targets -- ParamSpider accepts subdomains
    user_targets = config.get("user_targets") or {}
    user_subdomains = []

    if user_targets:
        for entry in user_targets.get("subdomains", []):
            entry = entry.strip().lower()
            if entry and _is_valid_hostname(entry):
                if entry == domain or entry.endswith("." + domain):
                    user_subdomains.append(entry)
                else:
                    print(f"[!][Partial Recon] Skipping subdomain outside scope: {entry}")
            elif entry:
                print(f"[!][Partial Recon] Skipping invalid hostname: {entry}")

    if user_subdomains:
        print(f"[+][Partial Recon] Validated {len(user_subdomains)} custom subdomains")

    # Build target_domains from graph subdomains + user subdomains
    include_graph = config.get("include_graph_targets", True)
    target_domains = set()

    if include_graph:
        print(f"[*][Partial Recon] Querying graph for target subdomains...")
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
                    if record and record["subdomains"]:
                        target_domains.update(record["subdomains"])
            else:
                print("[!][Partial Recon] Neo4j not reachable, cannot fetch graph subdomains")
    else:
        print(f"[*][Partial Recon] Skipping graph targets (user opted out)")

    # Always include the root domain
    target_domains.add(domain)

    # Add user-provided subdomains
    for sub in user_subdomains:
        target_domains.add(sub)

    print(f"[+][Partial Recon] Total target domains for ParamSpider: {len(target_domains)}")

    # ParamSpider settings
    PARAMSPIDER_PLACEHOLDER = settings.get('PARAMSPIDER_PLACEHOLDER', 'FUZZ')
    PARAMSPIDER_TIMEOUT = settings.get('PARAMSPIDER_TIMEOUT', 120)

    use_proxy = False
    try:
        from recon.helpers import is_tor_running
        TOR_ENABLED = settings.get('TOR_ENABLED', False)
        if TOR_ENABLED and is_tor_running():
            use_proxy = True
    except Exception:
        pass

    # Run ParamSpider discovery
    print(f"[*][Partial Recon] Running ParamSpider on {len(target_domains)} domains...")
    paramspider_urls, paramspider_urls_by_domain = run_paramspider_discovery(
        target_domains,
        PARAMSPIDER_PLACEHOLDER,
        PARAMSPIDER_TIMEOUT,
        use_proxy,
    )
    print(f"[+][Partial Recon] ParamSpider discovered {len(paramspider_urls)} parameterized URLs")

    if not paramspider_urls:
        print("[!][Partial Recon] ParamSpider found no URLs. No archived parameters for these domains.")
        if user_subdomains:
            _create_user_subdomains_in_graph(domain, user_subdomains, user_id, project_id)
        print(f"\n[+][Partial Recon] ParamSpider completed (no results)")
        return

    # Merge ParamSpider URLs into by_base_url structure
    print(f"[*][Partial Recon] Merging ParamSpider endpoints...")
    by_base_url = {}
    by_base_url, paramspider_stats = merge_paramspider_into_by_base_url(
        paramspider_urls,
        by_base_url,
        target_domains,
    )

    print(f"[+][Partial Recon] ParamSpider stats:")
    print(f"[+][Partial Recon]   Total: {paramspider_stats.get('paramspider_total', 0)}")
    print(f"[+][Partial Recon]   Parsed: {paramspider_stats.get('paramspider_parsed', 0)}")
    print(f"[+][Partial Recon]   New endpoints: {paramspider_stats.get('paramspider_new', 0)}")
    print(f"[+][Partial Recon]   Overlap: {paramspider_stats.get('paramspider_overlap', 0)}")
    print(f"[+][Partial Recon]   Out of scope: {paramspider_stats.get('paramspider_out_of_scope', 0)}")

    # Build resource_enum result structure (same shape as full pipeline)
    recon_data = {
        "domain": domain,
        "subdomains": list(target_domains),
        "resource_enum": {
            "by_base_url": by_base_url,
            "forms": [],
            "jsluice_secrets": [],
            "scan_metadata": {
                "paramspider_stats": paramspider_stats,
            },
            "summary": {
                "total_endpoints": sum(
                    len(bd['endpoints']) for bd in by_base_url.values()
                ),
                "total_base_urls": len(by_base_url),
            },
            "external_domains": [],
        },
    }

    # Update the graph database
    print(f"[*][Partial Recon] Updating graph database...")
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                stats = graph_client.update_graph_from_resource_enum(
                    recon_data=recon_data,
                    user_id=user_id,
                    project_id=project_id,
                )

                # Create Subdomain nodes for user-provided subdomains
                if user_subdomains:
                    _create_user_subdomains_in_graph(domain, user_subdomains, user_id, project_id)

                print(f"[+][Partial Recon] Graph updated successfully")
                print(f"[+][Partial Recon] Stats: {json.dumps(stats, default=str)}")
            else:
                print("[!][Partial Recon] Neo4j not reachable, graph not updated")
    except Exception as e:
        print(f"[!][Partial Recon] Graph update failed: {e}")
        raise

    print(f"\n[+][Partial Recon] ParamSpider passive parameter discovery completed successfully")


def run_kiterunner(config: dict) -> None:
    """
    Run partial resource enumeration using only Kiterunner (not the full
    resource_enum pipeline). Kiterunner bruteforces API endpoints using
    Assetnote wordlists derived from real-world Swagger/OpenAPI specs.

    Same URL-input pattern as run_katana()/run_hakrawler() -- reads BaseURLs
    from graph and/or user-provided URLs, runs Kiterunner discovery, merges
    results into the graph via update_graph_from_resource_enum.
    """
    from recon.helpers.resource_enum import (
        ensure_kiterunner_binary,
        run_kiterunner_discovery,
        merge_kiterunner_into_by_base_url,
        detect_kiterunner_methods,
    )
    from recon.project_settings import get_settings

    domain = config["domain"]

    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")

    print(f"[*][Partial Recon] Loading project settings...")
    settings = get_settings()

    # Force-enable Kiterunner since the user explicitly chose to run it
    settings['KITERUNNER_ENABLED'] = True

    print(f"\n{'=' * 50}")
    print(f"[*][Partial Recon] Kiterunner API Discovery (only)")
    print(f"[*][Partial Recon] Domain: {domain}")
    print(f"{'=' * 50}\n")

    # Parse user targets -- Kiterunner accepts URLs
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

        url_attach_to = user_targets.get("url_attach_to")

    if user_urls:
        print(f"[+][Partial Recon] Validated {len(user_urls)} custom URLs")
        if url_attach_to:
            print(f"[+][Partial Recon] URLs will be attached to BaseURL: {url_attach_to}")
        else:
            print(f"[+][Partial Recon] URLs will be tracked via UserInput (generic)")

    # Track whether we need a UserInput node (created after scan succeeds, not before)
    needs_user_input = bool(user_urls and not url_attach_to)

    # Build target URLs from Neo4j graph (or start empty if user unchecked graph targets)
    include_graph = config.get("include_graph_targets", True)
    if include_graph:
        print(f"[*][Partial Recon] Querying graph for targets (BaseURLs)...")
        recon_data = _build_http_probe_data_from_graph(domain, user_id, project_id)
    else:
        print(f"[*][Partial Recon] Skipping graph targets (user opted out)")
        recon_data = {
            "domain": domain,
            "subdomains": [],
            "http_probe": {
                "by_url": {},
            },
        }

    # Inject user-provided URLs into the target list
    if user_urls:
        print(f"[*][Partial Recon] Adding {len(user_urls)} user-provided URLs to scan targets")
        for url in user_urls:
            if url not in recon_data["http_probe"]["by_url"]:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                recon_data["http_probe"]["by_url"][url] = {
                    "url": url,
                    "host": parsed.netloc.split(":")[0],
                    "status_code": 200,
                    "content_type": "text/html",
                }

    # Build target_urls list from http_probe.by_url (same logic as resource_enum.py)
    target_urls = []
    target_domains = set()
    for url, url_data in recon_data["http_probe"]["by_url"].items():
        status_code = url_data.get("status_code")
        if status_code and int(status_code) < 500:
            target_urls.append(url)
            host = url_data.get("host", "")
            if host:
                target_domains.add(host)

    # Ensure all target hostnames are in subdomains list for graph scope filtering
    existing_subs = set(recon_data.get("subdomains", []))
    for host in target_domains:
        if host not in existing_subs:
            existing_subs.add(host)
    recon_data["subdomains"] = list(existing_subs)

    if not target_urls:
        print("[!][Partial Recon] No URLs to scan (graph has no BaseURLs and no valid user URLs provided).")
        print("[!][Partial Recon] Run HTTP Probing (Httpx) first, or provide URLs manually.")
        sys.exit(1)

    print(f"[+][Partial Recon] Found {len(target_urls)} URLs to scan")

    # Extract Kiterunner settings
    KITERUNNER_WORDLISTS = settings.get('KITERUNNER_WORDLISTS', ['apiroutes-210228'])
    KITERUNNER_RATE_LIMIT = settings.get('KITERUNNER_RATE_LIMIT', 100)
    KITERUNNER_CONNECTIONS = settings.get('KITERUNNER_CONNECTIONS', 50)
    KITERUNNER_TIMEOUT = settings.get('KITERUNNER_TIMEOUT', 3)
    KITERUNNER_SCAN_TIMEOUT = settings.get('KITERUNNER_SCAN_TIMEOUT', 300)
    KITERUNNER_THREADS = settings.get('KITERUNNER_THREADS', 10)
    KITERUNNER_IGNORE_STATUS = settings.get('KITERUNNER_IGNORE_STATUS', ['404', '429', '503'])
    KITERUNNER_MATCH_STATUS = settings.get('KITERUNNER_MATCH_STATUS', [])
    KITERUNNER_MIN_CONTENT_LENGTH = settings.get('KITERUNNER_MIN_CONTENT_LENGTH', 0)
    KITERUNNER_HEADERS = settings.get('KITERUNNER_HEADERS', [])
    KITERUNNER_DETECT_METHODS = settings.get('KITERUNNER_DETECT_METHODS', True)
    KITERUNNER_METHOD_DETECTION_MODE = settings.get('KITERUNNER_METHOD_DETECTION_MODE', 'options')
    KITERUNNER_BRUTEFORCE_METHODS = settings.get('KITERUNNER_BRUTEFORCE_METHODS', ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
    KITERUNNER_METHOD_DETECT_TIMEOUT = settings.get('KITERUNNER_METHOD_DETECT_TIMEOUT', 3)
    KITERUNNER_METHOD_DETECT_RATE_LIMIT = settings.get('KITERUNNER_METHOD_DETECT_RATE_LIMIT', 50)
    KITERUNNER_METHOD_DETECT_THREADS = settings.get('KITERUNNER_METHOD_DETECT_THREADS', 20)
    GAU_VERIFY_DOCKER_IMAGE = settings.get('GAU_VERIFY_DOCKER_IMAGE', 'projectdiscovery/httpx:latest')

    use_proxy = False
    try:
        from recon.helpers import is_tor_running
        TOR_ENABLED = settings.get('TOR_ENABLED', False)
        if TOR_ENABLED and is_tor_running():
            use_proxy = True
    except Exception:
        pass

    # Ensure Kiterunner binary and run discovery for each wordlist
    kr_results = []
    for wordlist_name in KITERUNNER_WORDLISTS:
        print(f"\n[*][Partial Recon] Processing wordlist: {wordlist_name}")
        try:
            kr_binary_path, wordlist_path = ensure_kiterunner_binary(wordlist_name)
            if not kr_binary_path or not wordlist_path:
                print(f"[!][Partial Recon] Could not get binary/wordlist: {wordlist_name}")
                continue
            wordlist_results = run_kiterunner_discovery(
                target_urls,
                kr_binary_path,
                wordlist_path,
                wordlist_name,
                KITERUNNER_RATE_LIMIT,
                KITERUNNER_CONNECTIONS,
                KITERUNNER_TIMEOUT,
                KITERUNNER_SCAN_TIMEOUT,
                KITERUNNER_THREADS,
                KITERUNNER_IGNORE_STATUS,
                KITERUNNER_MATCH_STATUS,
                KITERUNNER_MIN_CONTENT_LENGTH,
                KITERUNNER_HEADERS,
                use_proxy,
            )
            # Merge results, avoiding duplicates
            existing_urls = {(r['url'], r['method']) for r in kr_results}
            for result in wordlist_results:
                if (result['url'], result['method']) not in existing_urls:
                    kr_results.append(result)
                    existing_urls.add((result['url'], result['method']))
            print(f"[+][Partial Recon] {wordlist_name}: {len(wordlist_results)} endpoints found, {len(kr_results)} total unique")
        except Exception as e:
            print(f"[!][Partial Recon] Failed for {wordlist_name}: {e}")

    print(f"[+][Partial Recon] Kiterunner found {len(kr_results)} total API endpoints")

    # Detect additional HTTP methods if enabled
    kr_url_methods = None
    if kr_results and KITERUNNER_DETECT_METHODS:
        kr_url_methods = detect_kiterunner_methods(
            kr_results,
            GAU_VERIFY_DOCKER_IMAGE,
            KITERUNNER_DETECT_METHODS,
            KITERUNNER_METHOD_DETECTION_MODE,
            KITERUNNER_BRUTEFORCE_METHODS,
            KITERUNNER_METHOD_DETECT_TIMEOUT,
            KITERUNNER_METHOD_DETECT_RATE_LIMIT,
            KITERUNNER_METHOD_DETECT_THREADS,
            use_proxy,
        )

    # Merge Kiterunner results into by_base_url structure
    by_base_url = {}
    kr_stats = {
        "kr_total": 0,
        "kr_parsed": 0,
        "kr_new": 0,
        "kr_overlap": 0,
        "kr_methods": {},
        "kr_with_multiple_methods": 0,
    }

    if kr_results:
        by_base_url, kr_stats = merge_kiterunner_into_by_base_url(
            kr_results,
            {},  # Start with empty -- Kiterunner is the only source
            kr_url_methods,
        )
        print(f"[+][Partial Recon] Organized {kr_stats['kr_new']} new endpoints across {len(by_base_url)} base URLs")
        if kr_stats.get('kr_methods'):
            print(f"[+][Partial Recon] Methods found: {kr_stats['kr_methods']}")
        if kr_stats.get('kr_with_multiple_methods', 0) > 0:
            print(f"[+][Partial Recon] Endpoints with multiple methods: {kr_stats['kr_with_multiple_methods']}")

    # Build resource_enum result structure (same shape as full pipeline output)
    result = dict(recon_data)
    result["resource_enum"] = {
        "by_base_url": by_base_url,
        "forms": [],
        "jsluice_secrets": [],
        "scan_metadata": {
            "kiterunner_total": kr_stats.get("kr_total", 0),
            "kiterunner_new": kr_stats.get("kr_new", 0),
        },
        "summary": {
            "total_endpoints": sum(
                len(bd['endpoints']) for bd in by_base_url.values()
            ),
            "total_base_urls": len(by_base_url),
        },
        "external_domains": [],
    }

    # Update the graph database
    print(f"[*][Partial Recon] Updating graph database...")
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                stats = graph_client.update_graph_from_resource_enum(
                    recon_data=result,
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
                                    "tool_id": "Kiterunner",
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

    print(f"\n[+][Partial Recon] Kiterunner API discovery completed successfully")


def run_arjun(config: dict) -> None:
    """
    Run partial parameter discovery using Arjun. Tests common parameter names
    against discovered endpoints to find hidden query/body parameters.

    Targets come from graph (BaseURLs + Endpoints from prior crawling) and/or
    user-provided URLs. Results are merged into the graph via
    update_graph_from_resource_enum() (same as full pipeline).
    """
    from recon.helpers.resource_enum.arjun_helpers import (
        arjun_binary_check,
        run_arjun_discovery,
        merge_arjun_into_by_base_url,
    )
    from recon.project_settings import get_settings

    domain = config["domain"]

    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")

    print(f"[*][Partial Recon] Loading project settings...")
    settings = get_settings()

    # Force-enable Arjun since the user explicitly chose to run it
    settings['ARJUN_ENABLED'] = True

    print(f"\n{'=' * 50}")
    print(f"[*][Partial Recon] Arjun Parameter Discovery (only)")
    print(f"[*][Partial Recon] Domain: {domain}")
    print(f"{'=' * 50}\n")

    # Check binary availability
    if not arjun_binary_check():
        print("[!][Partial Recon] arjun binary not found in PATH, cannot proceed")
        sys.exit(1)

    # Parse user targets -- Arjun accepts URLs
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

        url_attach_to = user_targets.get("url_attach_to")

    if user_urls:
        print(f"[+][Partial Recon] Validated {len(user_urls)} custom URLs")
        if url_attach_to:
            print(f"[+][Partial Recon] URLs will be attached to BaseURL: {url_attach_to}")
        else:
            print(f"[+][Partial Recon] URLs will be tracked via UserInput (generic)")

    # Track whether we need a UserInput node (created after scan succeeds, not before)
    needs_user_input = bool(user_urls and not url_attach_to)

    # Build target URLs from Neo4j graph (or start empty if user unchecked graph targets)
    include_graph = config.get("include_graph_targets", True)
    arjun_target_urls = []
    target_domains = set()

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
                            arjun_target_urls.append(url)

                    # Also add BaseURLs themselves (fallback if no endpoints)
                    result = session.run(
                        """
                        MATCH (b:BaseURL {user_id: $uid, project_id: $pid})
                        RETURN DISTINCT b.url AS url, b.host AS host
                        """,
                        uid=user_id, pid=project_id,
                    )
                    for record in result:
                        url = record["url"]
                        host = record["host"] or ""
                        if url and url not in arjun_target_urls:
                            arjun_target_urls.append(url)
                        if host:
                            target_domains.add(host)

                print(f"[+][Partial Recon] Found {len(arjun_target_urls)} URLs from graph")
            else:
                print("[!][Partial Recon] Neo4j not reachable, cannot fetch graph inputs")
    else:
        print(f"[*][Partial Recon] Skipping graph targets (user opted out)")

    # Add user-provided URLs to target list
    if user_urls:
        print(f"[*][Partial Recon] Adding {len(user_urls)} user-provided URLs")
        for url in user_urls:
            if url not in arjun_target_urls:
                arjun_target_urls.append(url)
            from urllib.parse import urlparse
            parsed = urlparse(url)
            host = parsed.netloc.split(":")[0]
            if host:
                target_domains.add(host)

    # Also add domain itself to target_domains for scope filtering
    if domain:
        target_domains.add(domain)

    if not arjun_target_urls:
        print("[!][Partial Recon] No URLs to test (graph has no BaseURLs/Endpoints and no valid user URLs provided).")
        print("[!][Partial Recon] Run Katana or Hakrawler first to discover endpoints, or provide URLs manually.")
        sys.exit(1)

    # Cap to max endpoints (most interesting first -- API/dynamic endpoints)
    ARJUN_MAX_ENDPOINTS = settings.get('ARJUN_MAX_ENDPOINTS', 50)
    if len(arjun_target_urls) > ARJUN_MAX_ENDPOINTS:
        api_urls = [u for u in arjun_target_urls if any(p in u.lower() for p in ['/api/', '/v1/', '/v2/', '/graphql', '/rest/'])]
        dynamic_urls = [u for u in arjun_target_urls if u not in api_urls and any(u.lower().endswith(e) for e in ['.php', '.asp', '.aspx', '.jsp'])]
        other_urls = [u for u in arjun_target_urls if u not in api_urls and u not in dynamic_urls]
        arjun_target_urls = (api_urls + dynamic_urls + other_urls)[:ARJUN_MAX_ENDPOINTS]
        print(f"[*][Partial Recon] Capped to {ARJUN_MAX_ENDPOINTS} endpoints (API: {len(api_urls)}, dynamic: {len(dynamic_urls)}, other: {len(other_urls)})")

    print(f"[+][Partial Recon] Total {len(arjun_target_urls)} URLs to test with Arjun")

    # Extract Arjun settings
    ARJUN_METHODS = settings.get('ARJUN_METHODS', ['GET', 'POST'])
    ARJUN_THREADS = settings.get('ARJUN_THREADS', 2)
    ARJUN_TIMEOUT = settings.get('ARJUN_TIMEOUT', 15)
    ARJUN_SCAN_TIMEOUT = settings.get('ARJUN_SCAN_TIMEOUT', 600)
    ARJUN_CHUNK_SIZE = settings.get('ARJUN_CHUNK_SIZE', 500)
    ARJUN_RATE_LIMIT = settings.get('ARJUN_RATE_LIMIT', 0)
    ARJUN_STABLE = settings.get('ARJUN_STABLE', False)
    ARJUN_PASSIVE = settings.get('ARJUN_PASSIVE', False)
    ARJUN_DISABLE_REDIRECTS = settings.get('ARJUN_DISABLE_REDIRECTS', False)
    ARJUN_CUSTOM_HEADERS = settings.get('ARJUN_CUSTOM_HEADERS', [])

    use_proxy = False
    try:
        from recon.helpers import is_tor_running
        TOR_ENABLED = settings.get('TOR_ENABLED', False)
        if TOR_ENABLED and is_tor_running():
            use_proxy = True
    except Exception:
        pass

    # Run Arjun parameter discovery
    print(f"[*][Partial Recon] Running Arjun parameter discovery on {len(arjun_target_urls)} URLs...")
    arjun_results, arjun_meta = run_arjun_discovery(
        arjun_target_urls,
        ARJUN_METHODS,
        ARJUN_THREADS,
        ARJUN_TIMEOUT,
        ARJUN_SCAN_TIMEOUT,
        ARJUN_CHUNK_SIZE,
        ARJUN_RATE_LIMIT,
        ARJUN_STABLE,
        ARJUN_PASSIVE,
        ARJUN_DISABLE_REDIRECTS,
        ARJUN_CUSTOM_HEADERS,
        target_domains,
        use_proxy,
    )

    # Merge Arjun results into by_base_url structure
    by_base_url = {}
    arjun_stats = {
        "arjun_total": 0,
        "arjun_new_endpoints": 0,
        "arjun_existing_enriched": 0,
        "arjun_params_discovered": 0,
    }

    if arjun_results:
        print(f"[*][Partial Recon] Merging discovered parameters into results...")
        by_base_url, arjun_stats = merge_arjun_into_by_base_url(
            arjun_results,
            {},  # Start with empty -- Arjun is the only source for this partial run
        )
        print(f"[+][Partial Recon] URLs with params: {arjun_stats['arjun_total']}")
        print(f"[+][Partial Recon] New endpoints: {arjun_stats['arjun_new_endpoints']}")
        print(f"[+][Partial Recon] Existing enriched: {arjun_stats['arjun_existing_enriched']}")
        print(f"[+][Partial Recon] Parameters discovered: {arjun_stats['arjun_params_discovered']}")
    else:
        print("[!][Partial Recon] Arjun found no parameters on any tested endpoint.")

    # Build recon_data for graph update (needs domain + subdomains for scope)
    recon_data = {
        "domain": domain,
        "subdomains": [],
    }

    # Get subdomains for scope filtering
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
                            recon_data["subdomains"] = record["subdomains"] or []
        except Exception:
            pass

    # Ensure all target hostnames are in subdomains list for graph scope filtering
    existing_subs = set(recon_data.get("subdomains", []))
    for host in target_domains:
        if host not in existing_subs:
            existing_subs.add(host)
    recon_data["subdomains"] = list(existing_subs)

    # Build resource_enum result structure (same shape as full pipeline output)
    result = dict(recon_data)
    result["resource_enum"] = {
        "by_base_url": by_base_url,
        "forms": [],
        "jsluice_secrets": [],
        "scan_metadata": {
            "arjun_stats": arjun_stats,
            "external_domains": arjun_meta.get("external_domains", []),
        },
        "summary": {
            "total_endpoints": sum(
                len(bd['endpoints']) for bd in by_base_url.values()
            ),
            "total_base_urls": len(by_base_url),
        },
        "external_domains": arjun_meta.get("external_domains", []),
    }

    # Update the graph database
    print(f"[*][Partial Recon] Updating graph database...")
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                stats = graph_client.update_graph_from_resource_enum(
                    recon_data=result,
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
                                    "tool_id": "Arjun",
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

    print(f"\n[+][Partial Recon] Arjun parameter discovery completed successfully")
