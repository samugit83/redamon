"""Partial recon: SupplyChainRecon (L2 standalone).

Input nodes: BaseURL, Endpoint, Technology (from graph) + JS/source-maps.
Output nodes: Package, MalPackageFinding (MERGEd, anchored to BaseURLs).

Standalone runs need the served JS to harvest packages, so this reuses the full
JS-recon flow (force-enabled) to fetch JS + parse source maps, then runs the
supply-chain harvest+verdict over the SAME combined_result. Everything stays
offline for the verdict (osv-scanner against the mounted redamon-osv-db); no
tarballs, no package manager (S1).
"""

import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.partial_recon_modules.graph_builders import declared_only_unsafe, quarantined
from recon.partial_recon_modules.helpers import (
    _is_valid_url, _scope_partial_urls, ip_mode_recon, partial_settings, scope_roots,
)


def run_supply_chain(config: dict) -> None:
    from recon.main_recon_modules.js_recon import run_js_recon
    from recon.main_recon_modules.supply_chain_recon import run_supply_chain_recon

    roots = scope_roots(config)
    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")

    settings = partial_settings(config)
    # The user explicitly chose this tool, so force-enable both stages.
    settings["JS_RECON_ENABLED"] = True
    settings["SUPPLY_CHAIN_RECON_ENABLED"] = True

    print(f"\n{'=' * 50}")
    print(f"[*][Partial Recon] Supply-Chain Recon")
    print(f"[*][Partial Recon] Roots: {', '.join(roots)}")
    print(f"{'=' * 50}\n")

    # User-provided URLs (same input pattern as JsRecon/Katana).
    user_targets = config.get("user_targets") or {}
    user_urls = []
    for entry in (user_targets.get("urls", []) if user_targets else []):
        entry = (entry or "").strip()
        if entry and _is_valid_url(entry):
            user_urls.append(entry)
        elif entry:
            print(f"[!][Partial Recon] Skipping invalid URL: {entry}")

    include_graph = config.get("include_graph_targets", True)
    target_urls = []
    if include_graph:
        print("[*][Partial Recon] Querying graph for targets (BaseURLs + Endpoints)...")
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                with graph_client.driver.session() as session:
                    for rec in session.run(
                        "MATCH (e:Endpoint {user_id:$uid, project_id:$pid}) "
                        "WHERE NOT " + declared_only_unsafe("e") + " AND NOT " + quarantined("e") + " "
                        "RETURN DISTINCT e.baseurl + e.path AS url",
                        uid=user_id, pid=project_id):
                        if rec["url"]:
                            target_urls.append(rec["url"])
                    for rec in session.run(
                        "MATCH (b:BaseURL {user_id:$uid, project_id:$pid}) "
                        "RETURN DISTINCT b.url AS url", uid=user_id, pid=project_id):
                        if rec["url"] and rec["url"] not in target_urls:
                            target_urls.append(rec["url"])
                print(f"[+][Partial Recon] Found {len(target_urls)} URLs from graph")
            else:
                print("[!][Partial Recon] Neo4j not reachable, cannot fetch graph inputs")

    target_urls, scope_hosts = _scope_partial_urls(
        target_urls, user_urls, [], settings, roots,
        domain_groups=config.get("domain_groups"),
    )

    has_uploaded = False
    upload_dir = Path(f"/data/js-recon-uploads/{project_id}")
    if upload_dir.exists() and any(f.is_file() for f in upload_dir.iterdir()):
        has_uploaded = True

    if not target_urls and not has_uploaded:
        print("[!][Partial Recon] No URLs to analyze and no uploaded JS files found.")
        print("[!][Partial Recon] Run HTTP Probing + Resource Enumeration first, "
              "provide URLs, or upload JS files.")
        sys.exit(1)

    combined_result = ip_mode_recon({
        "domain": roots[0] if roots else "",
        "domains": roots,
        "subdomains": scope_hosts,
        "resource_enum": {"discovered_urls": target_urls},
        "http_probe": {"by_url": {}},
        "metadata": {"project_id": project_id, "modules_executed": []},
    }, settings)

    # 1) JS Recon: fetch JS + parse source maps into combined_result.
    combined_result = run_js_recon(combined_result, settings=settings)
    # 2) Supply-Chain harvest + offline verdict over the JS-recon output.
    combined_result = run_supply_chain_recon(combined_result, settings=settings)

    # Graph write (this container holds Neo4j creds).
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as client:
            if client.verify_connection():
                # JS-recon nodes first (endpoints/secrets/source-maps), then packages.
                try:
                    client.update_graph_from_js_recon(combined_result, user_id, project_id)
                except Exception as e:
                    print(f"[!][Partial Recon] js_recon graph update failed: {e}")
                stats = client.update_graph_from_supply_chain_recon(
                    combined_result, user_id, project_id)
                print(f"[+][Partial Recon] Supply-Chain graph update: {stats}")
            else:
                print("[!][Partial Recon] Neo4j not reachable, skipping graph update")
    except Exception as e:
        print(f"[!][Partial Recon] Graph update failed (non-fatal): {e}")
