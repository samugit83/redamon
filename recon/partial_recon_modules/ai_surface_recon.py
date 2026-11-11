"""Partial recon for the AI Surface Recon central module.

Re-runs the active AI/LLM/MCP probes against the AI surfaces already in the
graph, without re-crawling. Reconstructs the minimal combined_result the full
pipeline's run_ai_surface_recon() expects (resource_enum endpoints + http_probe
AI flags + port_scan hosts), then reuses the SAME runner and graph mixin.

Use cases: catalogue/probe-pack updated; the module was off during the original
scan; re-confirm MCP servers / chat endpoints / vector DBs on demand.

Reads:  BaseURL + Endpoint (AI-tagged) + IP/Port/Service(ai-vector-db).
Writes: via update_graph_from_ai_surface_recon (Endpoint/Parameter/Technology
        annotations + MCP tool-poisoning Vulnerability nodes).
"""
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.partial_recon_modules.graph_builders import declared_only, graph_url_scope, quarantined, url_host
from recon.partial_recon_modules.helpers import ip_mode_recon, partial_settings, scope_roots


def run_ai_surface_recon(config: dict) -> None:
    from recon.main_recon_modules.ai_surface_recon import (
        run_ai_surface_recon as run_full,
    )
    from graph_db.neo4j_client import Neo4jClient

    user_id = os.environ.get("USER_ID", "") or config.get("user_id", "")
    project_id = os.environ.get("PROJECT_ID", "") or config.get("project_id", "")
    if not (user_id and project_id):
        print("[!][AISurfaceRecon] Missing USER_ID or PROJECT_ID — refusing to run")
        return

    print(f"\n{'=' * 50}")
    print(f"[*][AISurfaceRecon] Partial recon: AI Surface Recon")
    print(f"[*][AISurfaceRecon] Project: {project_id}")
    print(f"{'=' * 50}\n")

    settings = partial_settings(config)
    settings["AI_SURFACE_RECON_ENABLED"] = True  # operator explicitly asked

    roots = scope_roots(config)
    client = Neo4jClient()
    recon_data: dict = ip_mode_recon({
        "domain": roots[0] if roots else "",
        "domains": roots,
        "metadata": {"project_id": project_id},
        "resource_enum": {"by_base_url": {}},
        "http_probe": {"by_url": {}},
        "port_scan": {"by_host": {}},
    }, settings)
    by_base = recon_data["resource_enum"]["by_base_url"]

    with client.driver.session() as session:
        # AI surfaces are read project-wide; skip those on a host this run does
        # not cover (a root dropped from the batch, or left unticked).
        keep = graph_url_scope(session, user_id, project_id, roots,
                               config.get("domain_groups"), apex_filter=False)

        # AI-tagged endpoints (the §3a candidate set)
        ep_rows = session.run(
            """
            MATCH (b:BaseURL {user_id:$u, project_id:$p})-[:HAS_ENDPOINT]->(e:Endpoint)
            WHERE ((e.ai_interface_type IS NOT NULL AND e.ai_interface_type <> 'non-llm')
               OR e.is_ai_framework_detected = true)
              AND NOT """ + quarantined("e") + """
            RETURN b.url AS base_url, e.path AS path,
                   coalesce(e.method,'GET') AS method,
                   e.ai_interface_type AS iface,
                   coalesce(e.is_ai_framework_detected,false) AS ai_fw,
                   """ + declared_only("e") + """ AS declared_only
            """,
            u=user_id, p=project_id,
        )
        ep_total = 0
        for row in ep_rows:
            if row["base_url"] and not keep(url_host(row["base_url"])):
                continue
            ep_total += 1
            base = row["base_url"] or "unknown"
            path = row["path"] or "/"
            bd = by_base.setdefault(base, {"endpoints": {}})
            ep = bd["endpoints"].setdefault(path, {"methods": [], "parameters": {}})
            if row["method"] not in ep["methods"]:
                ep["methods"].append(row["method"])
            # A path is declared-only while every node read for it is: the
            # chat-shape POST probe skips it (D15).
            ep["declared_only"] = ep.get("declared_only", True) and bool(row["declared_only"])
            if row["iface"]:
                ep["ai_interface_type"] = row["iface"]
            # populate http_probe AI flag so the host gate + static fallback fire
            if row["ai_fw"]:
                recon_data["http_probe"]["by_url"][base + "/"] = {
                    "is_ai_framework_detected": True}

        # Host-level AI flags for any base flagged by http_probe
        host_rows = session.run(
            """
            MATCH (b:BaseURL {user_id:$u, project_id:$p})-[:HAS_ENDPOINT]->(e:Endpoint)
            WHERE e.is_ai_framework_detected = true
            RETURN DISTINCT b.url AS base_url
            """,
            u=user_id, p=project_id,
        )
        for row in host_rows:
            base = row["base_url"]
            if base and keep(url_host(base)):
                recon_data["http_probe"]["by_url"][base + "/"] = {
                    "is_ai_framework_detected": True}

        # Addresses with ports, minus the ones the run's RoE excludes.
        ip_rows = session.run(
            """
            MATCH (ip:IP {user_id:$u, project_id:$p})-[:HAS_PORT]->(:Port)
            RETURN DISTINCT ip.address AS ip
            """,
            u=user_id, p=project_id,
        )
        port_ips = sorted({row["ip"] for row in ip_rows if row["ip"] and keep(row["ip"])})
    # IP mode: the vector-DB reads go to target addresses only. The graph can
    # hold a port on an address no target list names (B-01's forward answer).
    from recon.helpers.target_admission import clamp_to_targets
    port_ips = clamp_to_targets(recon_data, port_ips)

    print(f"[*][AISurfaceRecon] Loaded {ep_total} AI-tagged endpoint(s) from graph")
    if ep_total == 0 and not recon_data["http_probe"]["by_url"]:
        print("[-][AISurfaceRecon] No AI surfaces in graph — nothing to probe")
        client.close()
        return

    # run_full's _confirm_vector_dbs sends a read to every vector-DB port in
    # port_scan.by_host, which in the full pipeline holds what its own active
    # scan found. A port only a passive source reported (Shodan, Uncover...)
    # is a third party's crawl, often of an address outside the engagement.
    active_ports = client.active_open_ports(user_id, project_id, port_ips) if port_ips else {}
    for ip, ports in active_ports.items():
        recon_data["port_scan"]["by_host"][ip] = {"ip": ip, "ports": sorted(ports)}

    # Reuse the exact same runner as the full pipeline.
    recon_data = run_full(recon_data, output_file=None, settings=settings)

    # Persist via the shared mixin.
    client.update_graph_from_ai_surface_recon(recon_data, user_id, project_id)
    client.close()
    print(f"[+][AISurfaceRecon] Partial AI surface recon complete")
