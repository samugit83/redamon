import os
import sys
import json
import uuid
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.partial_recon_modules.helpers import _classify_ip, _is_ip_or_cidr
from recon.partial_recon_modules.graph_builders import _build_recon_data_from_graph


def run_shodan(config: dict) -> None:
    """
    Run partial Shodan OSINT enrichment.

    Queries existing IPs from the graph and enriches them with Shodan data
    (host lookup, reverse DNS, domain DNS, passive CVEs).
    Users can also provide custom IPs to enrich.
    """
    from recon.main_recon_modules.shodan_enrich import run_shodan_enrichment
    from recon.project_settings import get_settings

    domain = config["domain"]
    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")
    include_graph = config.get("include_graph_targets", True)

    print(f"[*][Partial Recon] Loading project settings...")
    settings = get_settings()

    print(f"\n{'=' * 50}")
    print(f"[*][Partial Recon] Shodan OSINT Enrichment")
    print(f"[*][Partial Recon] Domain: {domain}")
    print(f"{'=' * 50}\n")

    # Force-enable Shodan for partial recon (user explicitly triggered it)
    settings["SHODAN_ENABLED"] = True

    # Parse user-provided IPs from structured targets
    user_targets = config.get("user_targets") or {}
    user_ips = []
    ip_attach_to = None

    if user_targets:
        for entry in user_targets.get("ips", []):
            entry = entry.strip()
            if entry and _is_ip_or_cidr(entry):
                user_ips.append(entry)
            elif entry:
                print(f"[!][Partial Recon] Skipping invalid IP: {entry}")
        ip_attach_to = user_targets.get("ip_attach_to")

    if user_ips:
        print(f"[+][Partial Recon] Validated {len(user_ips)} custom IPs/CIDRs")
        if ip_attach_to:
            print(f"[+][Partial Recon] IPs will be attached to subdomain: {ip_attach_to}")
        else:
            print(f"[+][Partial Recon] IPs will be tracked via UserInput (generic)")

    needs_user_input = bool(user_ips and not ip_attach_to)
    user_input_id = str(uuid.uuid4()) if needs_user_input else None

    # Build combined_result from graph (IPs + subdomains)
    if include_graph:
        print(f"[*][Partial Recon] Querying graph for targets (IPs and subdomains)...")
        combined_result = _build_recon_data_from_graph(domain, user_id, project_id)
    else:
        print(f"[*][Partial Recon] Skipping graph targets (user opted out)")
        combined_result = {
            "domain": domain,
            "dns": {
                "domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
                "subdomains": {},
            },
        }

    # Inject user-provided IPs into combined_result DNS structure
    if user_ips:
        print(f"[*][Partial Recon] Adding {len(user_ips)} user-provided IPs to DNS data")
        for ip_str in user_ips:
            bucket = _classify_ip(ip_str)
            if ip_attach_to:
                if ip_attach_to not in combined_result["dns"]["subdomains"]:
                    combined_result["dns"]["subdomains"][ip_attach_to] = {
                        "ips": {"ipv4": [], "ipv6": []},
                        "has_records": True,
                    }
                if ip_str not in combined_result["dns"]["subdomains"][ip_attach_to]["ips"][bucket]:
                    combined_result["dns"]["subdomains"][ip_attach_to]["ips"][bucket].append(ip_str)
            else:
                if ip_str not in combined_result["dns"]["domain"]["ips"][bucket]:
                    combined_result["dns"]["domain"]["ips"][bucket].append(ip_str)
                    combined_result["dns"]["domain"]["has_records"] = True

    # Count IPs for logging
    ip_count = len(combined_result.get("dns", {}).get("domain", {}).get("ips", {}).get("ipv4", []))
    for _sub, info in combined_result.get("dns", {}).get("subdomains", {}).items():
        ip_count += len(info.get("ips", {}).get("ipv4", []))
    print(f"[+][Partial Recon] Total IPs for enrichment: {ip_count}")

    if ip_count == 0:
        print(f"[-][Partial Recon] No IPs to enrich. Run Subdomain Discovery first or provide custom IPs.")
        return

    # Run Shodan enrichment (same function as full pipeline)
    combined_result = run_shodan_enrichment(combined_result, settings)

    shodan_data = combined_result.get("shodan", {})
    if not shodan_data:
        print(f"[-][Partial Recon] Shodan returned no data")
        return

    print(f"[+][Partial Recon] Shodan hosts enriched: {len(shodan_data.get('hosts', []))}")
    print(f"[+][Partial Recon] Reverse DNS entries: {len(shodan_data.get('reverse_dns', {}))}")
    print(f"[+][Partial Recon] Domain DNS subdomains: {len(shodan_data.get('domain_dns', {}).get('subdomains', []))}")
    print(f"[+][Partial Recon] Passive CVEs: {len(shodan_data.get('cves', []))}")

    # Update the graph database
    print(f"[*][Partial Recon] Updating graph database...")
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                stats = graph_client.update_graph_from_shodan(
                    recon_data=combined_result,
                    user_id=user_id,
                    project_id=project_id,
                )
                print(f"[+][Partial Recon] Graph updated successfully")
                print(f"[+][Partial Recon] Stats: {json.dumps(stats, default=str)}")

                # Link user-provided IPs to graph
                if user_ips:
                    needs_ip_user_input = needs_user_input
                    driver = graph_client.driver
                    with driver.session() as session:
                        if ip_attach_to:
                            check = session.run(
                                """
                                MATCH (s:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                                RETURN s.name AS name
                                """,
                                sub=ip_attach_to, uid=user_id, pid=project_id,
                            )
                            if check.single():
                                for ip_str in user_ips:
                                    version = _classify_ip(ip_str)
                                    session.run(
                                        """
                                        MERGE (i:IP {address: $addr, user_id: $uid, project_id: $pid})
                                        ON CREATE SET i.version = $version,
                                                      i.source = 'partial_recon_user_input',
                                                      i.created_at = datetime()
                                        WITH i
                                        MATCH (s:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                                        MERGE (s)-[:RESOLVES_TO]->(i)
                                        """,
                                        addr=ip_str, uid=user_id, pid=project_id,
                                        version=version, sub=ip_attach_to,
                                    )
                                print(f"[+][Partial Recon] Linked {len(user_ips)} IPs to {ip_attach_to}")
                            else:
                                print(f"[!][Partial Recon] Subdomain {ip_attach_to} not found, falling back to UserInput")
                                needs_ip_user_input = True

                        if needs_ip_user_input:
                            session.run(
                                """
                                MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                                MERGE (ui:UserInput {id: $ui_id, user_id: $uid, project_id: $pid})
                                ON CREATE SET ui.type = 'ip',
                                              ui.values = $ips,
                                              ui.created_at = datetime(),
                                              ui.tool = 'Shodan'
                                MERGE (d)-[:HAS_USER_INPUT]->(ui)
                                """,
                                domain=domain, uid=user_id, pid=project_id,
                                ui_id=user_input_id, ips=user_ips,
                            )
                            for ip_str in user_ips:
                                version = _classify_ip(ip_str)
                                session.run(
                                    """
                                    MERGE (i:IP {address: $addr, user_id: $uid, project_id: $pid})
                                    ON CREATE SET i.version = $version,
                                                  i.source = 'partial_recon_user_input',
                                                  i.created_at = datetime()
                                    WITH i
                                    MATCH (ui:UserInput {id: $ui_id, user_id: $uid, project_id: $pid})
                                    MERGE (ui)-[:PRODUCED]->(i)
                                    """,
                                    addr=ip_str, uid=user_id, pid=project_id,
                                    version=version, ui_id=user_input_id,
                                )
                            print(f"[+][Partial Recon] Created UserInput node for {len(user_ips)} IPs")
            else:
                print("[!][Partial Recon] Neo4j not reachable, graph not updated")
    except Exception as e:
        print(f"[!][Partial Recon] Graph update failed: {e}")
        raise

    print(f"\n[+][Partial Recon] Shodan enrichment completed successfully")


def run_urlscan(config: dict) -> None:
    """
    Run partial URLScan.io passive enrichment.

    Phase A (discovery): discovers subdomains, IPs, external domains, domain age.
    Phase B (enrichment): enriches existing BaseURLs with screenshots/endpoints/parameters.
    """
    from recon.main_recon_modules.urlscan_enrich import run_urlscan_discovery_only
    from recon.project_settings import get_settings

    domain = config["domain"]
    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")

    print(f"[*][Partial Recon] Loading project settings...")
    settings = get_settings()

    print(f"\n{'=' * 50}")
    print(f"[*][Partial Recon] URLScan.io Passive Enrichment")
    print(f"[*][Partial Recon] Domain: {domain}")
    print(f"{'=' * 50}\n")

    # Force-enable URLScan for partial recon (user explicitly triggered it)
    settings["URLSCAN_ENABLED"] = True

    # Run URLScan discovery (same function as full pipeline Phase A)
    urlscan_data = run_urlscan_discovery_only(domain, settings)

    if not urlscan_data or urlscan_data.get("results_count", 0) == 0:
        print(f"[-][Partial Recon] URLScan returned no results for {domain}")
        return

    print(f"[+][Partial Recon] URLScan returned {urlscan_data.get('results_count', 0)} results")
    print(f"[+][Partial Recon] Subdomains: {len(urlscan_data.get('subdomains_discovered', []))}")
    print(f"[+][Partial Recon] IPs: {len(urlscan_data.get('ips_discovered', []))}")
    print(f"[+][Partial Recon] URLs with paths: {len(urlscan_data.get('urls_with_paths', []))}")
    print(f"[+][Partial Recon] External domains: {len(urlscan_data.get('external_domains', []))}")

    # Build combined_result structure expected by graph update methods
    combined_result = {
        "domain": domain,
        "urlscan": urlscan_data,
    }

    # Update the graph database
    print(f"[*][Partial Recon] Updating graph database...")
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                # Phase A: discovery (subdomains, IPs, external domains, domain age)
                discovery_stats = graph_client.update_graph_from_urlscan_discovery(
                    recon_data=combined_result,
                    user_id=user_id,
                    project_id=project_id,
                )
                print(f"[+][Partial Recon] Discovery graph update: {json.dumps(discovery_stats, default=str)}")

                # Phase B: enrichment (BaseURL screenshots, endpoints, parameters)
                enrichment_stats = graph_client.update_graph_from_urlscan_enrichment(
                    recon_data=combined_result,
                    user_id=user_id,
                    project_id=project_id,
                )
                print(f"[+][Partial Recon] Enrichment graph update: {json.dumps(enrichment_stats, default=str)}")
            else:
                print("[!][Partial Recon] Neo4j not reachable, graph not updated")
    except Exception as e:
        print(f"[!][Partial Recon] Graph update failed: {e}")
        raise

    print(f"\n[+][Partial Recon] URLScan enrichment completed successfully")


def run_uncover(config: dict) -> None:
    """
    Run partial Uncover multi-engine target expansion.

    Queries Shodan, Censys, FOFA, ZoomEye, Netlas, CriminalIP, and other
    search engines to discover additional IPs, subdomains, ports, and URLs
    associated with the target domain.
    """
    from recon.main_recon_modules.uncover_enrich import run_uncover_expansion
    from recon.project_settings import get_settings

    domain = config["domain"]
    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")

    print(f"[*][Partial Recon] Loading project settings...")
    settings = get_settings()

    print(f"\n{'=' * 50}")
    print(f"[*][Partial Recon] Uncover Multi-Engine Expansion")
    print(f"[*][Partial Recon] Domain: {domain}")
    print(f"{'=' * 50}\n")

    # Force-enable Uncover for partial recon (user explicitly triggered it)
    settings["UNCOVER_ENABLED"] = True
    settings["OSINT_ENRICHMENT_ENABLED"] = True

    # API keys for Uncover engines are only loaded by get_settings() when
    # UNCOVER_ENABLED is True in the project config.  Since we force-enable it
    # after the fact, we must manually load the keys from user global settings.
    webapp_url = os.environ.get("WEBAPP_API_URL", "")
    if webapp_url and user_id:
        try:
            from recon.project_settings import _fetch_user_settings_full
            user_global = _fetch_user_settings_full(user_id, webapp_url)
            if user_global:
                # Shared OSINT keys (may already be set if the per-tool toggle was on)
                if not settings.get('SHODAN_API_KEY'):
                    settings['SHODAN_API_KEY'] = user_global.get('shodanApiKey', '')
                if not settings.get('FOFA_API_KEY'):
                    settings['FOFA_API_KEY'] = user_global.get('fofaApiKey', '')
                if not settings.get('ZOOMEYE_API_KEY'):
                    settings['ZOOMEYE_API_KEY'] = user_global.get('zoomEyeApiKey', '')
                if not settings.get('NETLAS_API_KEY'):
                    settings['NETLAS_API_KEY'] = user_global.get('netlasApiKey', '')
                if not settings.get('CRIMINALIP_API_KEY'):
                    settings['CRIMINALIP_API_KEY'] = user_global.get('criminalIpApiKey', '')
                if not settings.get('CENSYS_API_TOKEN'):
                    settings['CENSYS_API_TOKEN'] = user_global.get('censysApiToken', '')
                if not settings.get('CENSYS_ORG_ID'):
                    settings['CENSYS_ORG_ID'] = user_global.get('censysOrgId', '')
                # Uncover-specific keys
                settings['UNCOVER_QUAKE_API_KEY'] = user_global.get('quakeApiKey', '')
                settings['UNCOVER_HUNTER_API_KEY'] = user_global.get('hunterApiKey', '')
                settings['UNCOVER_PUBLICWWW_API_KEY'] = user_global.get('publicWwwApiKey', '')
                settings['UNCOVER_HUNTERHOW_API_KEY'] = user_global.get('hunterHowApiKey', '')
                settings['UNCOVER_GOOGLE_API_KEY'] = user_global.get('googleApiKey', '')
                settings['UNCOVER_GOOGLE_API_CX'] = user_global.get('googleApiCx', '')
                settings['UNCOVER_ONYPHE_API_KEY'] = user_global.get('onypheApiKey', '')
                settings['UNCOVER_DRIFTNET_API_KEY'] = user_global.get('driftnetApiKey', '')
                print(f"[+][Partial Recon] Loaded API keys from user settings")
        except Exception as e:
            print(f"[!][Partial Recon] Could not load user API keys: {e}")

    # Build minimal combined_result structure expected by run_uncover_expansion
    combined_result = {
        "domain": domain,
    }

    # Run Uncover expansion (same function as full pipeline)
    uncover_data = run_uncover_expansion(combined_result, settings)

    if not uncover_data:
        print(f"[-][Partial Recon] Uncover returned no results for {domain}")
        return

    print(f"[+][Partial Recon] Uncover returned {uncover_data.get('total_deduped', 0)} deduplicated results")
    print(f"[+][Partial Recon] Hosts: {len(uncover_data.get('hosts', []))}")
    print(f"[+][Partial Recon] IPs: {len(uncover_data.get('ips', []))}")
    print(f"[+][Partial Recon] URLs: {len(uncover_data.get('urls', []))}")

    # Build combined_result structure expected by graph update method
    combined_result["uncover"] = uncover_data

    # Update the graph database
    print(f"[*][Partial Recon] Updating graph database...")
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                stats = graph_client.update_graph_from_uncover(
                    recon_data=combined_result,
                    user_id=user_id,
                    project_id=project_id,
                )
                print(f"[+][Partial Recon] Graph updated successfully")
                print(f"[+][Partial Recon] Stats: {json.dumps(stats, default=str)}")
            else:
                print("[!][Partial Recon] Neo4j not reachable, graph not updated")
    except Exception as e:
        print(f"[!][Partial Recon] Graph update failed: {e}")
        raise

    print(f"\n[+][Partial Recon] Uncover expansion completed successfully")


def run_osint_enrichment(config: dict) -> None:
    """
    Run partial OSINT Enrichment (Censys, FOFA, OTX, Netlas, VirusTotal, ZoomEye, CriminalIP).

    Queries existing IPs from the graph and enriches them with passive OSINT data.
    Enabled sub-tools run in parallel (same as the full pipeline GROUP 3b).
    Users can also provide custom IPs to enrich.
    """
    import importlib
    from concurrent.futures import ThreadPoolExecutor
    from recon.project_settings import get_settings

    domain = config["domain"]
    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")
    include_graph = config.get("include_graph_targets", True)

    print(f"[*][Partial Recon] Loading project settings...")
    settings = get_settings()

    print(f"\n{'=' * 50}")
    print(f"[*][Partial Recon] OSINT Enrichment (multi-tool)")
    print(f"[*][Partial Recon] Domain: {domain}")
    print(f"{'=' * 50}\n")

    # Force-enable OSINT enrichment for partial recon (user explicitly triggered it)
    settings["OSINT_ENRICHMENT_ENABLED"] = True

    # Build combined_result from graph (IPs + subdomains)
    if include_graph:
        combined_result = _build_recon_data_from_graph(domain, user_id, project_id)
    else:
        combined_result = {
            "domain": domain,
            "dns": {
                "domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
                "subdomains": {},
            },
        }

    # Parse user-provided IPs
    user_targets = config.get("user_targets") or {}
    user_ips = []
    ip_attach_to = None
    needs_user_input = False

    if user_targets:
        for entry in user_targets.get("ips", []):
            entry = entry.strip()
            if entry and _is_ip_or_cidr(entry):
                user_ips.append(entry)
            elif entry:
                print(f"[!][Partial Recon] Skipping invalid IP: {entry}")
        ip_attach_to = user_targets.get("ip_attach_to")

    if user_ips:
        print(f"[+][Partial Recon] Validated {len(user_ips)} custom IPs/CIDRs")
        if ip_attach_to:
            print(f"[+][Partial Recon] IPs will be attached to subdomain: {ip_attach_to}")
        else:
            print(f"[+][Partial Recon] IPs will be tracked via UserInput (generic)")
        needs_user_input = bool(user_ips and not ip_attach_to)

        # Inject user IPs into combined_result so enrichment tools can see them
        import ipaddress as _ipaddress
        for raw_ip in user_ips:
            raw_ip = raw_ip.strip()
            # Expand CIDRs
            expanded = []
            if "/" in raw_ip:
                try:
                    net = _ipaddress.ip_network(raw_ip, strict=False)
                    expanded = [str(h) for h in net.hosts()]
                    if not expanded:
                        expanded = [str(net.network_address)]
                except ValueError:
                    expanded = [raw_ip]
            else:
                expanded = [raw_ip]

            for ip_addr in expanded:
                ip_type = _classify_ip(ip_addr)
                if ip_attach_to:
                    # Inject into subdomain bucket
                    sub_key = ip_attach_to
                    if sub_key not in combined_result["dns"]["subdomains"]:
                        combined_result["dns"]["subdomains"][sub_key] = {
                            "ips": {"ipv4": [], "ipv6": []}, "has_records": True,
                        }
                    sub_ips = combined_result["dns"]["subdomains"][sub_key]["ips"]
                    if ip_addr not in sub_ips.get(ip_type, []):
                        sub_ips.setdefault(ip_type, []).append(ip_addr)
                else:
                    # Inject into domain-level IPs
                    domain_ips = combined_result["dns"]["domain"]["ips"]
                    if ip_addr not in domain_ips.get(ip_type, []):
                        domain_ips.setdefault(ip_type, []).append(ip_addr)

    # Count IPs for logging
    ip_count = len(combined_result.get("dns", {}).get("domain", {}).get("ips", {}).get("ipv4", []))
    for _sub, info in combined_result.get("dns", {}).get("subdomains", {}).items():
        ip_count += len(info.get("ips", {}).get("ipv4", []))
    print(f"[+][Partial Recon] Total IPs for enrichment: {ip_count}")

    if ip_count == 0:
        print(f"[-][Partial Recon] No IPs to enrich. Provide custom IPs or run Subdomain Discovery first.")
        return

    # OSINT sub-tool registry (same as main.py GROUP 3b)
    _osint_tools = {
        'censys': ('CENSYS_ENABLED', 'recon.main_recon_modules.censys_enrich', 'run_censys_enrichment_isolated', 'update_graph_from_censys'),
        'fofa': ('FOFA_ENABLED', 'recon.main_recon_modules.fofa_enrich', 'run_fofa_enrichment_isolated', 'update_graph_from_fofa'),
        'otx': ('OTX_ENABLED', 'recon.main_recon_modules.otx_enrich', 'run_otx_enrichment_isolated', 'update_graph_from_otx'),
        'netlas': ('NETLAS_ENABLED', 'recon.main_recon_modules.netlas_enrich', 'run_netlas_enrichment_isolated', 'update_graph_from_netlas'),
        'virustotal': ('VIRUSTOTAL_ENABLED', 'recon.main_recon_modules.virustotal_enrich', 'run_virustotal_enrichment_isolated', 'update_graph_from_virustotal'),
        'zoomeye': ('ZOOMEYE_ENABLED', 'recon.main_recon_modules.zoomeye_enrich', 'run_zoomeye_enrichment_isolated', 'update_graph_from_zoomeye'),
        'criminalip': ('CRIMINALIP_ENABLED', 'recon.main_recon_modules.criminalip_enrich', 'run_criminalip_enrichment_isolated', 'update_graph_from_criminalip'),
    }

    # Filter to enabled sub-tools with valid API keys
    enabled_osint = {
        name: cfg for name, cfg in _osint_tools.items()
        if settings.get(cfg[0], False)
        and (
            settings.get(f'{name.upper()}_API_KEY', '')
            or (name == 'censys' and settings.get('CENSYS_API_TOKEN', ''))
            or name == 'otx'  # OTX supports anonymous requests without an API key
        )
    }

    if not enabled_osint:
        print(f"[-][Partial Recon] No OSINT sub-tools are enabled or have valid API keys.")
        print(f"[-][Partial Recon] Enable at least one OSINT tool in project settings and configure its API key.")
        return

    print(f"[+][Partial Recon] Enabled OSINT tools: {', '.join(enabled_osint.keys())}")

    # Run enabled sub-tools in parallel (same pattern as main.py)
    osint_workers = min(len(enabled_osint), 5)
    with ThreadPoolExecutor(max_workers=osint_workers, thread_name_prefix="osint") as osint_exec:
        osint_futures = {}
        for name, (_, module_path, func_name, _) in enabled_osint.items():
            mod = importlib.import_module(module_path)
            fn = getattr(mod, func_name)
            osint_futures[name] = osint_exec.submit(fn, combined_result, settings)

        for name, future in osint_futures.items():
            try:
                data = future.result()
                if data:
                    combined_result[name] = data
                    print(f"[+][{name.upper()}] Enrichment completed")
                else:
                    print(f"[-][{name.upper()}] No data returned")
            except Exception as e:
                print(f"[!][{name.upper()}] Enrichment failed: {e}")

    # Update the graph database for each completed tool
    print(f"[*][Partial Recon] Updating graph database...")
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                for name, (_, _, _, graph_method) in enabled_osint.items():
                    if name in combined_result:
                        try:
                            update_fn = getattr(graph_client, graph_method)
                            stats = update_fn(
                                recon_data=combined_result,
                                user_id=user_id,
                                project_id=project_id,
                            )
                            print(f"[+][{name.upper()}] Graph updated: {json.dumps(stats, default=str)}")
                        except Exception as e:
                            print(f"[!][{name.upper()}] Graph update failed: {e}")
            else:
                print("[!][Partial Recon] Neo4j not reachable, graph not updated")
    except Exception as e:
        print(f"[!][Partial Recon] Graph update failed: {e}")
        raise

    # Link user-provided IPs to graph (RESOLVES_TO or UserInput PRODUCED)
    if user_ips:
        print(f"[*][Partial Recon] Linking {len(user_ips)} user-provided IPs to graph...")
        try:
            from graph_db import Neo4jClient as _Neo4jClient2
            with _Neo4jClient2() as gc:
                if gc.verify_connection():
                    with gc.driver.session() as sess:
                        if needs_user_input:
                            # Create UserInput node for generic IPs
                            user_input_id = str(uuid.uuid4())
                            sess.run(
                                """
                                MATCH (d:Domain {user_id: $uid, project_id: $pid})
                                MERGE (ui:UserInput {id: $ui_id, user_id: $uid, project_id: $pid})
                                ON CREATE SET ui.source = 'OsintEnrichment',
                                              ui.created_at = datetime(),
                                              ui.label = 'Custom IPs for OSINT enrichment'
                                MERGE (d)-[:HAS_USER_INPUT]->(ui)
                                """,
                                uid=user_id, pid=project_id, ui_id=user_input_id,
                            )
                            # Link each IP to UserInput
                            for raw_ip in user_ips:
                                expanded = [raw_ip]
                                if "/" in raw_ip:
                                    import ipaddress as _ipa
                                    try:
                                        net = _ipa.ip_network(raw_ip, strict=False)
                                        expanded = [str(h) for h in net.hosts()] or [str(net.network_address)]
                                    except ValueError:
                                        pass
                                for ip_addr in expanded:
                                    sess.run(
                                        """
                                        MATCH (ui:UserInput {id: $ui_id, user_id: $uid, project_id: $pid})
                                        MERGE (ip:IP {address: $addr, user_id: $uid, project_id: $pid})
                                        MERGE (ui)-[:PRODUCED]->(ip)
                                        """,
                                        uid=user_id, pid=project_id, ui_id=user_input_id, addr=ip_addr,
                                    )
                            print(f"[+][Partial Recon] Created UserInput -> PRODUCED -> IP links")
                        elif ip_attach_to:
                            # Attach IPs to existing subdomain via RESOLVES_TO
                            for raw_ip in user_ips:
                                expanded = [raw_ip]
                                if "/" in raw_ip:
                                    import ipaddress as _ipa
                                    try:
                                        net = _ipa.ip_network(raw_ip, strict=False)
                                        expanded = [str(h) for h in net.hosts()] or [str(net.network_address)]
                                    except ValueError:
                                        pass
                                for ip_addr in expanded:
                                    sess.run(
                                        """
                                        MERGE (s:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                                        MERGE (ip:IP {address: $addr, user_id: $uid, project_id: $pid})
                                        MERGE (s)-[:RESOLVES_TO]->(ip)
                                        """,
                                        uid=user_id, pid=project_id, sub=ip_attach_to, addr=ip_addr,
                                    )
                            print(f"[+][Partial Recon] Created Subdomain -> RESOLVES_TO -> IP links")
        except Exception as e:
            print(f"[!][Partial Recon] User IP linking failed: {e}")

    print(f"\n[+][Partial Recon] OSINT enrichment completed successfully")
