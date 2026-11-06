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
    typed_host_ok,
    _is_valid_hostname,
    _resolve_hostname,
    _should_include_root_domain,
    host_in_roots,
    partial_settings,
    root_for_host,
    scope_roots,
)
from recon.partial_recon_modules.graph_builders import (
    FORWARD_DNS,
    _GraphScope,
    _build_vuln_scan_data_from_graph,
    attach_graph_ownership,
)
from recon.main_recon_modules.origin_discovery import _is_edge_cdn_label


def _inject_graph_fronted_hosts(by_url: dict, roots: list, user_id: str, project_id: str,
                                domain_groups: list = None) -> None:
    """Mark CDN-fronted Subdomains from the graph as fronted http_probe entries.

    Fronted = the host resolves to a CDN IP (i.is_cdn) or one of its Endpoints
    carries is_cdn / a favicon hash (where httpx records the CDN classification).
    A literal batch group contributes only the hosts it listed, as in the
    builders: a Subdomain another writer hung under it is not probed.

    Forward DNS only: the IP read here is the host's edge, which a candidate is
    dropped against, and a Shodan PTR edge names a former origin as often as not.
    """
    from graph_db import Neo4jClient

    scope = _GraphScope(roots, domain_groups, include_root_domain=False)

    with Neo4jClient() as client:
        if not client.verify_connection():
            return
        with client.driver.session() as session:
            result = session.run(
                """
                MATCH (d:Domain {user_id: $uid, project_id: $pid})
                      -[:HAS_SUBDOMAIN]->(s:Subdomain)
                WHERE toLower(d.name) IN $domains
                  AND (EXISTS { (s)-[r:RESOLVES_TO]->(ci:IP) WHERE ci.is_cdn = true AND """ + FORWARD_DNS + """ }
                   OR EXISTS { (s)-[:HAS_BASE_URL|HAS_BASEURL]->(:BaseURL)-[:HAS_ENDPOINT]->(ep:Endpoint)
                               WHERE ep.is_cdn = true OR ep.favicon_hash IS NOT NULL })
                OPTIONAL MATCH (s)-[:HAS_BASE_URL|HAS_BASEURL]->(:BaseURL)-[:HAS_ENDPOINT]->(e:Endpoint)
                OPTIONAL MATCH (s)-[r:RESOLVES_TO]->(i:IP) WHERE """ + FORWARD_DNS + """
                RETURN d.name AS root, s.name AS host,
                       head([x IN collect(DISTINCT e.favicon_hash) WHERE x IS NOT NULL]) AS favicon,
                       [x IN collect(DISTINCT e.cdn) WHERE x IS NOT NULL]
                         + [x IN collect(DISTINCT i.cdn_name) WHERE x IS NOT NULL] AS cdns,
                       head(collect(DISTINCT i.address)) AS ip
                """,
                domains=scope.orgs, uid=user_id, pid=project_id,
            )
            count = 0
            for record in result:
                host = record["host"]
                if not host or not scope.keeps(host, record["root"]):
                    continue
                url = f"https://{host}"
                entry = by_url.setdefault(url, {"url": url, "host": host})
                entry["host"] = host
                entry["is_cdn"] = True
                if record["favicon"] is not None and entry.get("favicon_hash") in (None, ""):
                    entry["favicon_hash"] = record["favicon"]
                if record["cdns"] and not entry.get("cdn"):
                    # Labels across scans and nodes come unordered: prefer an
                    # edge CDN over a cloud-hosting label for the same host.
                    edge = [c for c in record["cdns"] if _is_edge_cdn_label(c)]
                    entry["cdn"] = (edge or record["cdns"])[0]
                if record["ip"] and not entry.get("ip"):
                    entry["ip"] = record["ip"]
                count += 1
            if count:
                print(f"[+][Partial Recon] Loaded {count} CDN-fronted host(s) from the graph")


def _load_urlscan_inputs(recon_data: dict, hosts: list, roots: list, user_id: str,
                         project_id: str, domain_groups: list = None) -> None:
    """Item 7 in partial recon: the urlscan source's two inputs, from the graph.

    Old addresses come from an earlier URLScan run's
    `(Subdomain)-[:HISTORICALLY_RESOLVED_TO {source:'urlscan'}]->(IP)`, never
    from a current RESOLVES_TO, loaded into the `urlscan.entries` shape. The
    site's files come from JS Recon's `js_file` nodes, inside the run's scope,
    into `resource_enum.js_urls`. Typed subdomains get the history read too."""
    from graph_db import Neo4jClient
    from urllib.parse import urlparse

    hosts = sorted({str(h).lower() for h in hosts or [] if h})
    scope = _GraphScope(roots, domain_groups, include_root_domain=True)
    with Neo4jClient() as client:
        if not client.verify_connection():
            return
        with client.driver.session() as session:
            entries = recon_data.setdefault("urlscan", {}).setdefault("entries", [])
            if hosts:
                rows = session.run(
                    """
                    MATCH (s:Subdomain {user_id: $uid, project_id: $pid})
                          -[r:HISTORICALLY_RESOLVED_TO {source: 'urlscan'}]->(i:IP)
                    WHERE toLower(s.name) IN $hosts
                    RETURN toLower(s.name) AS host, i.address AS ip, r.last_seen AS last_seen
                    """, uid=user_id, pid=project_id, hosts=hosts)
                for r in rows:
                    if r["ip"]:
                        entries.append({"domain": r["host"], "ip": r["ip"],
                                        "scan_time": r["last_seen"] or "", "in_scope": True})
            rows = session.run(
                """
                MATCH (f:JsReconFinding {user_id: $uid, project_id: $pid, finding_type: 'js_file'})
                WHERE f.source_url STARTS WITH 'http' AND NOT f.source_url CONTAINS '#'
                RETURN DISTINCT f.source_url AS url
                """, uid=user_id, pid=project_id)
            js_urls = recon_data.setdefault("resource_enum", {}).setdefault("js_urls", [])
            for r in rows:
                url = r["url"]
                host = (urlparse(url).hostname or "").lower() if isinstance(url, str) else ""
                if host and scope.keeps(host) and url not in js_urls:
                    js_urls.append(url)
    if entries or js_urls:
        print(f"[+][Partial Recon] urlscan source: {len(entries)} old address(es), "
              f"{len(js_urls)} JS file(s) from the graph")


def run_origin_discovery(config: dict) -> None:
    from recon.main_recon_modules.origin_discovery import run_origin_discovery_enrichment

    roots = scope_roots(config)
    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")

    print(f"[*][Partial Recon] Loading project settings...")
    settings = partial_settings(config)
    # The user explicitly chose to run this tool.
    settings["ORIGIN_DISCOVERY_ENABLED"] = True

    print(f"\n{'=' * 50}")
    print(f"[*][Partial Recon] Origin Discovery")
    print(f"[*][Partial Recon] Roots: {', '.join(roots)}")
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
        if typed_host_ok(entry, roots, config.get("domain_groups")):
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
            roots, user_id, project_id,
            include_root_domain=_should_include_root_domain(settings),
            domain_groups=config.get("domain_groups"),
        )
    else:
        print(f"[*][Partial Recon] Skipping graph targets (user opted out)")
        # Stamp the apex-scope flag identically to the full pipeline even on the
        # graph-off branch, so a manually-entered apex is scoped correctly.
        recon_data = {
            "domain": roots[0] if roots else "",
            "domains": roots,
            "subdomains": [],
            "dns": {"domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False}, "subdomains": {}},
            "metadata": {"include_root_domain": _should_include_root_domain(settings)},
            "http_probe": {"by_url": {}},
            "port_scan": {"by_ip": {}},
        }

    recon_data.setdefault("http_probe", {}).setdefault("by_url", {})
    # A candidate the graph's IP attribution tagged shared_edge is never an origin.
    attach_graph_ownership(recon_data, user_id, project_id)

    # The reused graph builder reconstructs http_probe.by_url from BaseURL nodes,
    # but is_cdn/favicon_hash live on the Endpoint node — so it never flags a host
    # as fronted. Query the graph directly (Endpoint is_cdn/favicon, or a CDN IP)
    # and inject the fronted hosts, so graph-sourced discovery actually runs and
    # the modal's fronted_count guard matches the tool's behavior. Never-raise.
    if include_graph:
        try:
            _inject_graph_fronted_hosts(recon_data["http_probe"]["by_url"], roots, user_id, project_id,
                                        domain_groups=config.get("domain_groups"))
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
        entry["user_fronted"] = True
        if edge_ip and not entry.get("ip"):
            entry["ip"] = edge_ip
        print(f"[+][Partial Recon] Marked user subdomain as fronted: {sub}"
              + (f" (edge {edge_ip})" if edge_ip else ""))

    fronted_count = sum(
        1 for v in recon_data["http_probe"]["by_url"].values()
        if isinstance(v, dict) and v.get("is_cdn")
    )

    from recon.main_recon_modules.origin_discovery import _urlscan_source_on
    if _urlscan_source_on(settings):
        fronted_hosts = [v.get("host") for v in recon_data["http_probe"]["by_url"].values()
                         if isinstance(v, dict) and v.get("is_cdn")]
        try:
            _load_urlscan_inputs(recon_data, fronted_hosts, roots, user_id, project_id,
                                 domain_groups=config.get("domain_groups"))
        except Exception as e:
            print(f"[!][Partial Recon] Could not load urlscan history from the graph: {e}")
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
