"""
Partial-recon entry for Origin-IP Discovery.

Runs the SAME shared entry (`run_origin_discovery_enrichment`) the full pipeline
uses, so both paths behave identically. Reads CDN-fronted hosts from the existing
graph; a manually-entered Subdomain is injected as a fronted host to unmask. IPs
are graph-sourced only (a discovered origin IP is an OUTPUT, never a manual input).
Results merge into the graph via `update_graph_from_origin_discovery`.
"""

import os

from recon.partial_recon_modules.helpers import (
    _is_valid_hostname,
    _resolve_hostname,
    _should_include_root_domain,
)
from recon.partial_recon_modules.graph_builders import _build_vuln_scan_data_from_graph


def _inject_graph_fronted_hosts(by_url: dict, domain: str, user_id: str, project_id: str) -> None:
    """Mark CDN-fronted Subdomains from the graph as fronted http_probe entries.

    Fronted = the host resolves to a CDN IP (i.is_cdn) or one of its Endpoints
    carries is_cdn / a favicon hash (where httpx records the CDN classification).
    """
    from graph_db import Neo4jClient

    with Neo4jClient() as client:
        if not client.verify_connection():
            return
        with client.driver.session() as session:
            result = session.run(
                """
                MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                      -[:HAS_SUBDOMAIN]->(s:Subdomain)
                WHERE EXISTS { (s)-[:RESOLVES_TO]->(ci:IP) WHERE ci.is_cdn = true }
                   OR EXISTS { (s)-[:HAS_BASE_URL|HAS_BASEURL]->(:BaseURL)-[:HAS_ENDPOINT]->(ep:Endpoint)
                               WHERE ep.is_cdn = true OR ep.favicon_hash IS NOT NULL }
                OPTIONAL MATCH (s)-[:HAS_BASE_URL|HAS_BASEURL]->(:BaseURL)-[:HAS_ENDPOINT]->(e:Endpoint)
                OPTIONAL MATCH (s)-[:RESOLVES_TO]->(i:IP)
                RETURN s.name AS host,
                       head([x IN collect(DISTINCT e.favicon_hash) WHERE x IS NOT NULL]) AS favicon,
                       head([x IN collect(DISTINCT e.cdn) WHERE x IS NOT NULL]) AS cdn,
                       head(collect(DISTINCT i.address)) AS ip
                """,
                domain=domain, uid=user_id, pid=project_id,
            )
            count = 0
            for record in result:
                host = record["host"]
                if not host:
                    continue
                url = f"https://{host}"
                entry = by_url.setdefault(url, {"url": url, "host": host})
                entry["host"] = host
                entry["is_cdn"] = True
                if record["favicon"] is not None and entry.get("favicon_hash") in (None, ""):
                    entry["favicon_hash"] = record["favicon"]
                if record["cdn"] and not entry.get("cdn"):
                    entry["cdn"] = record["cdn"]
                if record["ip"] and not entry.get("ip"):
                    entry["ip"] = record["ip"]
                count += 1
            if count:
                print(f"[+][Partial Recon] Loaded {count} CDN-fronted host(s) from the graph")


def run_origin_discovery(config: dict) -> None:
    from recon.main_recon_modules.origin_discovery import run_origin_discovery_enrichment
    from recon.project_settings import get_settings

    domain = config["domain"]
    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")

    print(f"[*][Partial Recon] Loading project settings...")
    settings = get_settings()
    # The user explicitly chose to run this tool.
    settings["ORIGIN_DISCOVERY_ENABLED"] = True

    print(f"\n{'=' * 50}")
    print(f"[*][Partial Recon] Origin Discovery")
    print(f"[*][Partial Recon] Domain: {domain}")
    print(f"{'=' * 50}\n")

    # --- validate the one manual input type: Subdomain (IP is graph-only) ---
    user_targets = config.get("user_targets") or {}
    user_subdomains = []
    for entry in user_targets.get("subdomains", []):
        entry = (entry or "").strip().lower()
        if not entry:
            continue
        if not _is_valid_hostname(entry):
            print(f"[!][Partial Recon] Skipping invalid hostname: {entry}")
            continue
        if entry.endswith("." + domain) or entry == domain:
            user_subdomains.append(entry)
        else:
            print(f"[!][Partial Recon] Skipping out-of-scope subdomain: {entry}")
    if user_targets.get("ips"):
        # IP is a discovery OUTPUT, never a manual input (mirrors SECTION_INPUT_MAP).
        print(f"[!][Partial Recon] Ignoring manually-entered IPs — origin IPs are discovered, not entered")

    # --- fronted hosts from the graph (prior HTTP-probe classification) ---
    include_graph = config.get("include_graph_targets", True)
    if include_graph:
        print(f"[*][Partial Recon] Querying graph for CDN-fronted hosts...")
        recon_data = _build_vuln_scan_data_from_graph(
            domain, user_id, project_id,
            include_root_domain=_should_include_root_domain(settings),
        )
    else:
        print(f"[*][Partial Recon] Skipping graph targets (user opted out)")
        # Stamp the apex-scope flag identically to the full pipeline even on the
        # graph-off branch, so a manually-entered apex is scoped correctly.
        recon_data = {
            "domain": domain,
            "subdomains": [],
            "dns": {"domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False}, "subdomains": {}},
            "metadata": {"include_root_domain": _should_include_root_domain(settings)},
            "http_probe": {"by_url": {}},
            "port_scan": {"by_ip": {}},
        }

    recon_data.setdefault("http_probe", {}).setdefault("by_url", {})

    # The reused graph builder reconstructs http_probe.by_url from BaseURL nodes,
    # but is_cdn/favicon_hash live on the Endpoint node — so it never flags a host
    # as fronted. Query the graph directly (Endpoint is_cdn/favicon, or a CDN IP)
    # and inject the fronted hosts, so graph-sourced discovery actually runs and
    # the modal's fronted_count guard matches the tool's behavior. Never-raise.
    if include_graph:
        try:
            _inject_graph_fronted_hosts(recon_data["http_probe"]["by_url"], domain, user_id, project_id)
        except Exception as e:
            print(f"[!][Partial Recon] Could not load fronted hosts from graph: {e}")

    # --- inject each validated user subdomain as a fronted host to unmask ---
    # The user entered it because it is CDN-fronted; mark it is_cdn so
    # _select_fronted_hosts picks it up. The favicon is self-fetched (SSRF-guarded)
    # by origin_discovery when absent.
    for sub in user_subdomains:
        ips = _resolve_hostname(sub)
        edge_ip = (ips.get("ipv4") or [None])[0] or (ips.get("ipv6") or [None])[0]
        url = f"https://{sub}"
        entry = recon_data["http_probe"]["by_url"].setdefault(url, {"url": url, "host": sub})
        entry["host"] = sub
        entry["is_cdn"] = True
        if edge_ip and not entry.get("ip"):
            entry["ip"] = edge_ip
        print(f"[+][Partial Recon] Marked user subdomain as fronted: {sub}"
              + (f" (edge {edge_ip})" if edge_ip else ""))

    fronted_count = sum(
        1 for v in recon_data["http_probe"]["by_url"].values()
        if isinstance(v, dict) and v.get("is_cdn")
    )
    if not fronted_count:
        print(f"[!][Partial Recon] No CDN-fronted hosts found in the graph and no subdomain entered — "
              f"run an HTTP-probe scan first, or enter a fronted subdomain. Nothing to unmask.")

    # --- run the shared entry + persist ---
    run_origin_discovery_enrichment(recon_data, settings)

    payload = recon_data.get("origin_discovery") or {}
    confirmed = payload.get("confirmed") or []
    print(f"[*][Partial Recon] Origin Discovery found {len(confirmed)} confirmed origin(s)")

    print(f"[*][Partial Recon] Updating graph database...")
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                graph_client.update_graph_from_origin_discovery(
                    recon_data=recon_data,
                    user_id=user_id,
                    project_id=project_id,
                )
                print(f"[+][Partial Recon] Graph updated")
            else:
                print(f"[!][Partial Recon] Neo4j not reachable — skipped graph update")
    except Exception as e:
        print(f"[!][Partial Recon] Graph update failed: {e}")
