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


def run_katana(config: dict) -> None:
    """
    Run partial resource enumeration using only Katana (not the full
    resource_enum pipeline). Katana crawls BaseURLs to discover endpoints.

    Unlike run_resource_enum() which runs ALL sub-tools (Katana + Hakrawler +
    GAU + jsluice + FFuf + etc.), this runs only the Katana crawler +
    organize_endpoints, then updates the graph via update_graph_from_resource_enum.
    """
    from recon.helpers.resource_enum import (
        run_katana_crawler,
        pull_katana_docker_image,
        organize_endpoints,
    )
    from recon.project_settings import get_settings

    domain = config["domain"]

    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")

    print(f"[*][Partial Recon] Loading project settings...")
    settings = get_settings()

    # Force-enable Katana since the user explicitly chose to run it
    settings['KATANA_ENABLED'] = True

    print(f"\n{'=' * 50}")
    print(f"[*][Partial Recon] Katana Crawling (only)")
    print(f"[*][Partial Recon] Domain: {domain}")
    print(f"{'=' * 50}\n")

    # Parse user targets -- Katana accepts URLs
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

    # Track whether we need a UserInput node (created after scan succeeds, not before)
    needs_user_input = bool(user_urls and not url_attach_to)

    # Build recon_data from Neo4j graph (or start empty if user unchecked graph targets)
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
        print(f"[*][Partial Recon] Adding {len(user_urls)} user-provided URLs to crawl targets")
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
        print("[!][Partial Recon] No URLs to crawl (graph has no BaseURLs and no valid user URLs provided).")
        print("[!][Partial Recon] Run HTTP Probing (Httpx) first, or provide URLs manually.")
        sys.exit(1)

    print(f"[+][Partial Recon] Found {len(target_urls)} URLs to crawl")

    # Extract Katana settings
    KATANA_DOCKER_IMAGE = settings.get('KATANA_DOCKER_IMAGE', 'projectdiscovery/katana:latest')
    KATANA_DEPTH = settings.get('KATANA_DEPTH', 2)
    KATANA_MAX_URLS = settings.get('KATANA_MAX_URLS', 300)
    KATANA_RATE_LIMIT = settings.get('KATANA_RATE_LIMIT', 50)
    KATANA_TIMEOUT = settings.get('KATANA_TIMEOUT', 3600)
    KATANA_JS_CRAWL = settings.get('KATANA_JS_CRAWL', True)
    KATANA_PARAMS_ONLY = settings.get('KATANA_PARAMS_ONLY', False)
    KATANA_CUSTOM_HEADERS = settings.get('KATANA_CUSTOM_HEADERS', [])
    KATANA_EXCLUDE_PATTERNS = settings.get('KATANA_EXCLUDE_PATTERNS', [])

    use_proxy = False
    try:
        from recon.helpers import is_tor_running
        TOR_ENABLED = settings.get('TOR_ENABLED', False)
        if TOR_ENABLED and is_tor_running():
            use_proxy = True
    except Exception:
        pass

    # Pull Docker image
    print(f"[*][Partial Recon] Pulling Katana Docker image: {KATANA_DOCKER_IMAGE}")
    pull_katana_docker_image(KATANA_DOCKER_IMAGE)

    # Run Katana crawler (ONLY Katana -- not the full resource_enum pipeline)
    print(f"[*][Partial Recon] Running Katana crawler on {len(target_urls)} URLs...")
    katana_urls, katana_meta = run_katana_crawler(
        target_urls,
        KATANA_DOCKER_IMAGE,
        KATANA_DEPTH,
        KATANA_MAX_URLS,
        KATANA_RATE_LIMIT,
        KATANA_TIMEOUT,
        KATANA_JS_CRAWL,
        KATANA_PARAMS_ONLY,
        target_domains,
        KATANA_CUSTOM_HEADERS,
        KATANA_EXCLUDE_PATTERNS,
        use_proxy,
    )
    print(f"[+][Partial Recon] Katana found {len(katana_urls)} URLs")

    # Organize discovered URLs into by_base_url structure
    organized_data = organize_endpoints(katana_urls, use_proxy=use_proxy)

    # Mark all endpoints with sources=['katana']
    for base_url, base_data in organized_data['by_base_url'].items():
        for path, endpoint in base_data['endpoints'].items():
            endpoint['sources'] = ['katana']

    # Build resource_enum result structure (same shape as full pipeline output)
    result = dict(recon_data)
    result["resource_enum"] = {
        "by_base_url": organized_data['by_base_url'],
        "forms": organized_data.get('forms', []),
        "jsluice_secrets": [],
        "scan_metadata": {
            "katana_total": len(katana_urls),
            "external_domains": katana_meta.get("external_domains", []),
        },
        "summary": {
            "total_endpoints": sum(
                len(bd['endpoints']) for bd in organized_data['by_base_url'].values()
            ),
            "total_base_urls": len(organized_data['by_base_url']),
        },
        "external_domains": katana_meta.get("external_domains", []),
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
                            # Attached: link crawled BaseURLs to selected BaseURL via DISCOVERED_FROM
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
                            # Generic: create UserInput -> PRODUCED -> BaseURL
                            user_input_id = str(uuid.uuid4())
                            graph_client.create_user_input_node(
                                domain=domain,
                                user_input_data={
                                    "id": user_input_id,
                                    "input_type": "urls",
                                    "values": user_urls,
                                    "tool_id": "Katana",
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

    print(f"\n[+][Partial Recon] Katana crawling completed successfully")


def run_hakrawler(config: dict) -> None:
    """
    Run partial resource enumeration using only Hakrawler (not the full
    resource_enum pipeline). Hakrawler crawls BaseURLs to discover endpoints.

    Same pattern as run_katana() -- runs just the hakrawler crawler +
    organize_endpoints, then updates the graph via update_graph_from_resource_enum.
    """
    from recon.helpers.resource_enum import (
        run_hakrawler_crawler,
        pull_hakrawler_docker_image,
        organize_endpoints,
    )
    from recon.project_settings import get_settings

    domain = config["domain"]

    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")

    print(f"[*][Partial Recon] Loading project settings...")
    settings = get_settings()

    # Force-enable Hakrawler since the user explicitly chose to run it
    settings['HAKRAWLER_ENABLED'] = True

    print(f"\n{'=' * 50}")
    print(f"[*][Partial Recon] Resource Enumeration (Hakrawler)")
    print(f"[*][Partial Recon] Domain: {domain}")
    print(f"{'=' * 50}\n")

    # Parse user targets -- Hakrawler accepts URLs
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
        print(f"[*][Partial Recon] Adding {len(user_urls)} user-provided URLs to crawl targets")
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
        print("[!][Partial Recon] No URLs to crawl (graph has no BaseURLs and no valid user URLs provided).")
        print("[!][Partial Recon] Run HTTP Probing (Httpx) first, or provide URLs manually.")
        sys.exit(1)

    print(f"[+][Partial Recon] Found {len(target_urls)} URLs to crawl")

    # Extract Hakrawler settings
    HAKRAWLER_DOCKER_IMAGE = settings.get('HAKRAWLER_DOCKER_IMAGE', 'jauderho/hakrawler:latest')
    HAKRAWLER_DEPTH = settings.get('HAKRAWLER_DEPTH', 2)
    HAKRAWLER_THREADS = settings.get('HAKRAWLER_THREADS', 5)
    HAKRAWLER_TIMEOUT = settings.get('HAKRAWLER_TIMEOUT', 30)
    HAKRAWLER_MAX_URLS = settings.get('HAKRAWLER_MAX_URLS', 500)
    HAKRAWLER_INCLUDE_SUBS = settings.get('HAKRAWLER_INCLUDE_SUBS', False)
    HAKRAWLER_INSECURE = settings.get('HAKRAWLER_INSECURE', True)
    HAKRAWLER_CUSTOM_HEADERS = settings.get('HAKRAWLER_CUSTOM_HEADERS', [])

    use_proxy = False
    try:
        from recon.helpers import is_tor_running
        TOR_ENABLED = settings.get('TOR_ENABLED', False)
        if TOR_ENABLED and is_tor_running():
            use_proxy = True
    except Exception:
        pass

    # Pull Docker image
    print(f"[*][Partial Recon] Pulling Hakrawler Docker image: {HAKRAWLER_DOCKER_IMAGE}")
    pull_hakrawler_docker_image(HAKRAWLER_DOCKER_IMAGE)

    # Run Hakrawler crawler
    print(f"[*][Partial Recon] Running Hakrawler crawler on {len(target_urls)} URLs...")
    hakrawler_urls, hakrawler_meta = run_hakrawler_crawler(
        target_urls,
        HAKRAWLER_DOCKER_IMAGE,
        HAKRAWLER_DEPTH,
        HAKRAWLER_THREADS,
        HAKRAWLER_TIMEOUT,
        HAKRAWLER_MAX_URLS,
        HAKRAWLER_INCLUDE_SUBS,
        HAKRAWLER_INSECURE,
        target_domains,
        HAKRAWLER_CUSTOM_HEADERS,
        [],  # no exclude patterns for Hakrawler
        use_proxy,
    )
    print(f"[+][Partial Recon] Hakrawler found {len(hakrawler_urls)} URLs")

    # Organize discovered URLs into by_base_url structure
    organized_data = organize_endpoints(hakrawler_urls, use_proxy=use_proxy)

    # Mark all endpoints with sources=['hakrawler']
    for base_url, base_data in organized_data['by_base_url'].items():
        for path, endpoint in base_data['endpoints'].items():
            endpoint['sources'] = ['hakrawler']

    # Build resource_enum result structure (same as full pipeline output)
    result = dict(recon_data)
    result["resource_enum"] = {
        "by_base_url": organized_data['by_base_url'],
        "forms": organized_data.get('forms', []),
        "jsluice_secrets": [],
        "scan_metadata": {
            "hakrawler_total": len(hakrawler_urls),
            "external_domains": hakrawler_meta.get("external_domains", []),
        },
        "summary": {
            "total_endpoints": sum(
                len(bd['endpoints']) for bd in organized_data['by_base_url'].values()
            ),
            "total_base_urls": len(organized_data['by_base_url']),
        },
        "external_domains": hakrawler_meta.get("external_domains", []),
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
                            # Attached: link crawled BaseURLs to selected BaseURL via DISCOVERED_FROM
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
                            # Generic: create UserInput -> PRODUCED -> BaseURL
                            user_input_id = str(uuid.uuid4())
                            graph_client.create_user_input_node(
                                domain=domain,
                                user_input_data={
                                    "id": user_input_id,
                                    "input_type": "urls",
                                    "values": user_urls,
                                    "tool_id": "Hakrawler",
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

    print(f"\n[+][Partial Recon] Resource enumeration (Hakrawler) completed successfully")


def run_ffuf(config: dict) -> None:
    """
    Run partial resource enumeration using only FFuf directory fuzzer.
    FFuf fuzzes BaseURLs to discover hidden endpoints, directories, and files.

    Same pattern as run_hakrawler() -- takes BaseURL inputs, runs the fuzzer,
    then updates the graph via update_graph_from_resource_enum.
    """
    from recon.helpers.resource_enum import (
        run_ffuf_discovery,
        pull_ffuf_binary_check,
        merge_ffuf_into_by_base_url,
    )
    from recon.project_settings import get_settings

    domain = config["domain"]

    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")

    print(f"[*][Partial Recon] Loading project settings...")
    settings = get_settings()

    # Force-enable FFuf since the user explicitly chose to run it
    settings['FFUF_ENABLED'] = True

    print(f"\n{'=' * 50}")
    print(f"[*][Partial Recon] Directory Fuzzing (FFuf)")
    print(f"[*][Partial Recon] Domain: {domain}")
    print(f"{'=' * 50}\n")

    # Parse user targets -- FFuf accepts URLs
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
        print(f"[*][Partial Recon] Adding {len(user_urls)} user-provided URLs to fuzz targets")
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
    # (update_graph_from_resource_enum skips BaseURLs whose host is not in subdomains)
    existing_subs = set(recon_data.get("subdomains", []))
    for host in target_domains:
        if host not in existing_subs:
            existing_subs.add(host)
    recon_data["subdomains"] = list(existing_subs)

    if not target_urls:
        print("[!][Partial Recon] No URLs to fuzz (graph has no BaseURLs and no valid user URLs provided).")
        print("[!][Partial Recon] Run HTTP Probing (Httpx) first, or provide URLs manually.")
        sys.exit(1)

    print(f"[+][Partial Recon] Found {len(target_urls)} URLs to fuzz")

    # Extract FFuf settings
    FFUF_WORDLIST = settings.get('FFUF_WORDLIST', '/usr/share/seclists/Discovery/Web-Content/common.txt')
    FFUF_THREADS = settings.get('FFUF_THREADS', 40)
    FFUF_RATE = settings.get('FFUF_RATE', 0)
    FFUF_TIMEOUT = settings.get('FFUF_TIMEOUT', 10)
    FFUF_MAX_TIME = settings.get('FFUF_MAX_TIME', 600)
    FFUF_MATCH_CODES = settings.get('FFUF_MATCH_CODES', [200, 201, 204, 301, 302, 307, 308, 401, 403, 405])
    FFUF_FILTER_CODES = settings.get('FFUF_FILTER_CODES', [])
    FFUF_FILTER_SIZE = settings.get('FFUF_FILTER_SIZE', '')
    FFUF_EXTENSIONS = settings.get('FFUF_EXTENSIONS', [])
    FFUF_RECURSION = settings.get('FFUF_RECURSION', False)
    FFUF_RECURSION_DEPTH = settings.get('FFUF_RECURSION_DEPTH', 2)
    FFUF_AUTO_CALIBRATE = settings.get('FFUF_AUTO_CALIBRATE', True)
    FFUF_FOLLOW_REDIRECTS = settings.get('FFUF_FOLLOW_REDIRECTS', False)
    FFUF_CUSTOM_HEADERS = settings.get('FFUF_CUSTOM_HEADERS', [])
    FFUF_SMART_FUZZ = settings.get('FFUF_SMART_FUZZ', True)

    print(f"[*][Partial Recon] FFuf wordlist: {FFUF_WORDLIST}")
    print(f"[*][Partial Recon] FFuf threads: {FFUF_THREADS}")
    print(f"[*][Partial Recon] FFuf rate limit: {FFUF_RATE} req/s" if FFUF_RATE > 0 else "[*][Partial Recon] FFuf rate limit: unlimited")
    print(f"[*][Partial Recon] FFuf timeout: {FFUF_TIMEOUT}s per request, {FFUF_MAX_TIME}s max")

    # Check Tor proxy
    use_proxy = False
    try:
        from recon.helpers import is_tor_running
        TOR_ENABLED = settings.get('TOR_ENABLED', False)
        if TOR_ENABLED and is_tor_running():
            use_proxy = True
    except Exception:
        pass

    # Check ffuf binary
    if not pull_ffuf_binary_check():
        print("[!][Partial Recon] ffuf binary not found in PATH")
        sys.exit(1)

    # Smart fuzz: query existing endpoints from graph for discovered base paths
    discovered_base_paths = None
    if FFUF_SMART_FUZZ and include_graph:
        try:
            from graph_db import Neo4jClient
            with Neo4jClient() as gc:
                if gc.verify_connection():
                    with gc.driver.session() as session:
                        result = session.run(
                            """
                            MATCH (e:Endpoint {user_id: $uid, project_id: $pid})
                            RETURN collect(DISTINCT e.path) AS paths
                            """,
                            uid=user_id, pid=project_id,
                        )
                        record = result.single()
                        if record:
                            paths = record["paths"] or []
                            base_paths = set()
                            for path in paths:
                                if not path:
                                    continue
                                parts = path.strip('/').split('/')
                                if len(parts) >= 2:
                                    base_paths.add('/'.join(parts[:2]))
                                if len(parts) >= 1 and parts[0]:
                                    base_paths.add(parts[0])
                            if base_paths:
                                discovered_base_paths = sorted(base_paths)[:20]
                                print(f"[*][Partial Recon] Smart fuzz: targeting {len(discovered_base_paths)} discovered base paths")
        except Exception as e:
            print(f"[!][Partial Recon] Smart fuzz query failed: {e}")

    # Run FFuf discovery
    print(f"[*][Partial Recon] Running FFuf directory fuzzing on {len(target_urls)} URLs...")
    ffuf_results, ffuf_meta = run_ffuf_discovery(
        target_urls,
        FFUF_WORDLIST,
        FFUF_THREADS,
        FFUF_RATE,
        FFUF_TIMEOUT,
        FFUF_MAX_TIME,
        FFUF_MATCH_CODES,
        FFUF_FILTER_CODES,
        FFUF_FILTER_SIZE,
        FFUF_EXTENSIONS,
        FFUF_RECURSION,
        FFUF_RECURSION_DEPTH,
        FFUF_AUTO_CALIBRATE,
        FFUF_CUSTOM_HEADERS,
        FFUF_FOLLOW_REDIRECTS,
        target_domains,
        discovered_base_paths,
        use_proxy,
    )
    print(f"[+][Partial Recon] FFuf discovered {len(ffuf_results)} endpoints")

    # Merge FFuf results into by_base_url structure
    by_base_url = {}
    ffuf_stats = {"ffuf_total": 0, "ffuf_new": 0, "ffuf_overlap": 0}
    if ffuf_results:
        by_base_url, ffuf_stats = merge_ffuf_into_by_base_url(ffuf_results, by_base_url)
        print(f"[+][Partial Recon] FFuf total: {ffuf_stats['ffuf_total']} endpoints")
        print(f"[+][Partial Recon] FFuf new: {ffuf_stats['ffuf_new']}")

    # Build resource_enum result structure (same as full pipeline output)
    result = dict(recon_data)
    result["resource_enum"] = {
        "by_base_url": by_base_url,
        "forms": [],
        "jsluice_secrets": [],
        "scan_metadata": {
            "ffuf_total": len(ffuf_results),
            "external_domains": ffuf_meta.get("external_domains", []),
        },
        "summary": {
            "total_endpoints": sum(
                len(bd['endpoints']) for bd in by_base_url.values()
            ),
            "total_base_urls": len(by_base_url),
        },
        "external_domains": ffuf_meta.get("external_domains", []),
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
                                    "tool_id": "Ffuf",
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

    print(f"\n[+][Partial Recon] FFuf directory fuzzing completed successfully")


def run_gau(config: dict) -> None:
    """
    Run partial GAU (GetAllUrls) passive URL discovery.

    GAU queries web archives (Wayback Machine, Common Crawl, OTX, URLScan)
    for historical URLs associated with target domains/subdomains.
    Results are organized into Endpoint/Parameter/BaseURL nodes and merged
    into the graph via update_graph_from_resource_enum().
    """
    from recon.helpers.resource_enum import (
        pull_gau_docker_image,
        run_gau_discovery,
        verify_gau_urls,
        detect_gau_methods,
        merge_gau_into_by_base_url,
    )
    from recon.project_settings import get_settings

    domain = config["domain"]

    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")

    print(f"[*][Partial Recon] Loading project settings...")
    settings = get_settings()

    # Force-enable GAU since the user explicitly chose to run it
    settings['GAU_ENABLED'] = True

    print(f"\n{'=' * 50}")
    print(f"[*][Partial Recon] GAU Passive URL Discovery")
    print(f"[*][Partial Recon] Domain: {domain}")
    print(f"{'=' * 50}\n")

    # Parse user targets -- GAU accepts subdomains
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
                    # Get all subdomains from graph
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

    print(f"[+][Partial Recon] Total target domains for GAU: {len(target_domains)}")

    # Also get subdomains list for scope filtering later
    all_subdomains = list(target_domains)

    # GAU settings
    GAU_DOCKER_IMAGE = settings.get('GAU_DOCKER_IMAGE', 'sxcurity/gau:latest')
    GAU_PROVIDERS = list(settings.get('GAU_PROVIDERS', ['wayback', 'commoncrawl', 'otx', 'urlscan']))
    GAU_THREADS = settings.get('GAU_THREADS', 2)
    GAU_TIMEOUT = settings.get('GAU_TIMEOUT', 60)
    GAU_BLACKLIST_EXTENSIONS = settings.get('GAU_BLACKLIST_EXTENSIONS', ['png', 'jpg', 'jpeg', 'gif', 'css', 'woff', 'woff2', 'ttf', 'svg', 'ico', 'eot'])
    GAU_MAX_URLS = settings.get('GAU_MAX_URLS', 10000)
    GAU_YEAR_RANGE = settings.get('GAU_YEAR_RANGE', None)
    GAU_VERBOSE = settings.get('GAU_VERBOSE', False)
    GAU_VERIFY_URLS = settings.get('GAU_VERIFY_URLS', True)
    GAU_VERIFY_DOCKER_IMAGE = settings.get('GAU_VERIFY_DOCKER_IMAGE', 'projectdiscovery/httpx:latest')
    GAU_VERIFY_TIMEOUT = settings.get('GAU_VERIFY_TIMEOUT', 5)
    GAU_VERIFY_RATE_LIMIT = settings.get('GAU_VERIFY_RATE_LIMIT', 50)
    GAU_VERIFY_THREADS = settings.get('GAU_VERIFY_THREADS', 50)
    GAU_VERIFY_ACCEPT_STATUS = settings.get('GAU_VERIFY_ACCEPT_STATUS', ['200', '201', '301', '302', '307', '308', '401', '403'])
    GAU_DETECT_METHODS = settings.get('GAU_DETECT_METHODS', True)
    GAU_METHOD_DETECT_THREADS = settings.get('GAU_METHOD_DETECT_THREADS', 20)
    GAU_METHOD_DETECT_TIMEOUT = settings.get('GAU_METHOD_DETECT_TIMEOUT', 5)
    GAU_METHOD_DETECT_RATE_LIMIT = settings.get('GAU_METHOD_DETECT_RATE_LIMIT', 30)
    GAU_FILTER_DEAD_ENDPOINTS = settings.get('GAU_FILTER_DEAD_ENDPOINTS', True)

    URLSCAN_API_KEY = settings.get('URLSCAN_API_KEY', '')

    use_proxy = False
    try:
        from recon.helpers import is_tor_running
        TOR_ENABLED = settings.get('TOR_ENABLED', False)
        if TOR_ENABLED and is_tor_running():
            use_proxy = True
    except Exception:
        pass

    # Pull Docker image
    print(f"[*][Partial Recon] Pulling GAU Docker image: {GAU_DOCKER_IMAGE}")
    pull_gau_docker_image(GAU_DOCKER_IMAGE)

    # Run GAU discovery
    print(f"[*][Partial Recon] Running GAU on {len(target_domains)} domains...")
    gau_urls, gau_urls_by_domain = run_gau_discovery(
        target_domains,
        GAU_DOCKER_IMAGE,
        GAU_PROVIDERS,
        GAU_THREADS,
        GAU_TIMEOUT,
        GAU_BLACKLIST_EXTENSIONS,
        GAU_MAX_URLS,
        GAU_YEAR_RANGE,
        GAU_VERBOSE,
        use_proxy,
        URLSCAN_API_KEY,
    )
    print(f"[+][Partial Recon] GAU discovered {len(gau_urls)} total URLs")

    if not gau_urls:
        print("[!][Partial Recon] GAU found no URLs. No archives available for these domains.")
        # Still update graph with user subdomains if provided
        if user_subdomains:
            _create_user_subdomains_in_graph(domain, user_subdomains, user_id, project_id)
        print(f"\n[+][Partial Recon] GAU completed (no results)")
        return

    # Filter to in-scope URLs only
    from urllib.parse import urlparse as _urlparse
    in_scope_gau_urls = []
    gau_external_domains = []
    out_of_scope_count = 0
    for url in gau_urls:
        parsed = _urlparse(url)
        host = parsed.netloc.split(':')[0] if ':' in parsed.netloc else parsed.netloc
        if host in target_domains:
            in_scope_gau_urls.append(url)
        else:
            out_of_scope_count += 1
            if host:
                gau_external_domains.append({"domain": host, "source": "gau", "url": url})

    if out_of_scope_count > 0:
        print(f"[*][Partial Recon] Filtered {out_of_scope_count} out-of-scope URLs")
    print(f"[+][Partial Recon] In-scope URLs: {len(in_scope_gau_urls)}")

    gau_urls_to_process = in_scope_gau_urls

    # Verify GAU URLs if enabled
    verified_urls = None
    if GAU_VERIFY_URLS and gau_urls_to_process:
        verified_urls = verify_gau_urls(
            gau_urls_to_process,
            GAU_VERIFY_DOCKER_IMAGE,
            GAU_VERIFY_TIMEOUT,
            GAU_VERIFY_RATE_LIMIT,
            GAU_VERIFY_THREADS,
            GAU_VERIFY_ACCEPT_STATUS,
            use_proxy,
        )

    # Detect HTTP methods
    url_methods = None
    urls_to_probe = list(verified_urls) if verified_urls else gau_urls_to_process
    if GAU_DETECT_METHODS and urls_to_probe:
        url_methods = detect_gau_methods(
            urls_to_probe,
            GAU_VERIFY_DOCKER_IMAGE,
            GAU_METHOD_DETECT_THREADS,
            GAU_METHOD_DETECT_TIMEOUT,
            GAU_METHOD_DETECT_RATE_LIMIT,
            GAU_FILTER_DEAD_ENDPOINTS,
            use_proxy,
        )

    # Merge GAU URLs into by_base_url structure
    print(f"[*][Partial Recon] Merging GAU endpoints...")
    by_base_url = {}
    by_base_url, gau_stats = merge_gau_into_by_base_url(
        gau_urls_to_process,
        by_base_url,
        verified_urls,
        url_methods,
    )

    print(f"[+][Partial Recon] GAU stats:")
    print(f"[+][Partial Recon]   Parsed: {gau_stats['gau_parsed']}")
    print(f"[+][Partial Recon]   New endpoints: {gau_stats['gau_new']}")
    if GAU_VERIFY_URLS:
        print(f"[+][Partial Recon]   Skipped (unverified): {gau_stats.get('gau_skipped_unverified', 0)}")
    if GAU_DETECT_METHODS:
        print(f"[+][Partial Recon]   With POST: {gau_stats.get('gau_with_post', 0)}")
    if GAU_FILTER_DEAD_ENDPOINTS:
        print(f"[+][Partial Recon]   Dead filtered: {gau_stats.get('gau_skipped_dead', 0)}")

    # Build resource_enum result structure (same shape as full pipeline)
    recon_data = {
        "domain": domain,
        "subdomains": all_subdomains,
        "resource_enum": {
            "by_base_url": by_base_url,
            "forms": [],
            "jsluice_secrets": [],
            "scan_metadata": {
                "gau_urls_found_total": len(gau_urls),
                "gau_urls_in_scope": len(in_scope_gau_urls),
                "gau_stats": gau_stats,
                "external_domains": gau_external_domains,
            },
            "summary": {
                "total_endpoints": sum(
                    len(bd['endpoints']) for bd in by_base_url.values()
                ),
                "total_base_urls": len(by_base_url),
            },
            "external_domains": gau_external_domains,
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

    print(f"\n[+][Partial Recon] GAU passive URL discovery completed successfully")


def run_jsluice(config: dict) -> None:
    """
    Run partial resource enumeration using only jsluice (not the full
    resource_enum pipeline). jsluice analyzes JavaScript files to extract
    hidden API endpoints, parameters, and secrets.

    Unlike the full pipeline where jsluice runs after Katana/Hakrawler,
    this queries the graph for existing Endpoint URLs (from prior crawling)
    and/or accepts user-provided URLs, then runs jsluice analysis on them.
    """
    from recon.helpers.resource_enum import (
        run_jsluice_analysis,
        merge_jsluice_into_by_base_url,
    )
    from recon.project_settings import get_settings

    domain = config["domain"]

    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")

    print(f"[*][Partial Recon] Loading project settings...")
    settings = get_settings()

    # Force-enable jsluice since the user explicitly chose to run it
    settings['JSLUICE_ENABLED'] = True

    print(f"\n{'=' * 50}")
    print(f"[*][Partial Recon] jsluice JS Analysis (only)")
    print(f"[*][Partial Recon] Domain: {domain}")
    print(f"{'=' * 50}\n")

    # Parse user targets -- jsluice accepts URLs (same as Katana/Hakrawler)
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

    # Track whether we need a UserInput node (created after scan succeeds, not before)
    needs_user_input = bool(user_urls and not url_attach_to)

    # Build target URLs from Neo4j graph (or start empty if user unchecked graph targets)
    include_graph = config.get("include_graph_targets", True)
    target_urls = []
    target_domains = set()

    if include_graph:
        print(f"[*][Partial Recon] Querying graph for targets (Endpoints from prior crawling)...")
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

                    # Also add BaseURLs themselves (some may host JS directly)
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
                        if url and url not in target_urls:
                            target_urls.append(url)
                        if host:
                            target_domains.add(host)

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
            from urllib.parse import urlparse
            parsed = urlparse(url)
            host = parsed.netloc.split(":")[0]
            if host:
                target_domains.add(host)

    # Also add domain itself to target_domains for scope filtering
    if domain:
        target_domains.add(domain)

    if not target_urls:
        print("[!][Partial Recon] No URLs to analyze (graph has no Endpoints/BaseURLs and no valid user URLs provided).")
        print("[!][Partial Recon] Run Katana or Hakrawler first to discover URLs, or provide URLs manually.")
        sys.exit(1)

    print(f"[+][Partial Recon] Total {len(target_urls)} URLs to analyze with jsluice")

    # Extract jsluice settings
    JSLUICE_MAX_FILES = settings.get('JSLUICE_MAX_FILES', 100)
    JSLUICE_TIMEOUT = settings.get('JSLUICE_TIMEOUT', 300)
    JSLUICE_EXTRACT_URLS = settings.get('JSLUICE_EXTRACT_URLS', True)
    JSLUICE_EXTRACT_SECRETS = settings.get('JSLUICE_EXTRACT_SECRETS', True)
    JSLUICE_CONCURRENCY = settings.get('JSLUICE_CONCURRENCY', 5)

    use_proxy = False
    try:
        from recon.helpers import is_tor_running
        TOR_ENABLED = settings.get('TOR_ENABLED', False)
        if TOR_ENABLED and is_tor_running():
            use_proxy = True
    except Exception:
        pass

    # Run jsluice analysis (filters to .js files internally, downloads and analyzes)
    print(f"[*][Partial Recon] Running jsluice analysis...")
    JSLUICE_PARALLELISM = settings.get('JSLUICE_PARALLELISM', 3)
    jsluice_result = run_jsluice_analysis(
        target_urls,
        JSLUICE_MAX_FILES,
        JSLUICE_TIMEOUT,
        JSLUICE_EXTRACT_URLS,
        JSLUICE_EXTRACT_SECRETS,
        JSLUICE_CONCURRENCY,
        JSLUICE_PARALLELISM,
        target_domains,
        use_proxy,
    )

    jsluice_urls = jsluice_result.get("urls", [])
    jsluice_secrets = jsluice_result.get("secrets", [])
    external_domains = jsluice_result.get("external_domains", [])

    print(f"[+][Partial Recon] jsluice found {len(jsluice_urls)} URLs, {len(jsluice_secrets)} secrets, {len(external_domains)} external domains")

    # Organize extracted URLs into by_base_url structure
    by_base_url = {}
    jsluice_stats = {
        "jsluice_total": 0,
        "jsluice_parsed": 0,
        "jsluice_new": 0,
        "jsluice_overlap": 0,
    }

    if jsluice_urls:
        by_base_url, jsluice_stats = merge_jsluice_into_by_base_url(
            jsluice_urls,
            {},  # Start with empty -- jsluice is the only source
        )
        print(f"[+][Partial Recon] Organized {jsluice_stats['jsluice_new']} new endpoints across {len(by_base_url)} base URLs")

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
        "jsluice_secrets": jsluice_secrets,
        "scan_metadata": {
            "jsluice_total": jsluice_stats.get("jsluice_total", 0),
            "jsluice_new": jsluice_stats.get("jsluice_new", 0),
            "external_domains": external_domains,
        },
        "summary": {
            "total_endpoints": sum(
                len(bd['endpoints']) for bd in by_base_url.values()
            ),
            "total_base_urls": len(by_base_url),
        },
        "external_domains": external_domains,
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
                                    "tool_id": "Jsluice",
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

    print(f"\n[+][Partial Recon] jsluice analysis completed successfully")
