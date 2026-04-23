import os
import sys
import json
import uuid
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def run_subdomain_discovery(config: dict) -> None:
    """
    Run partial subdomain discovery using the exact same functions
    as the full pipeline in domain_recon.py.
    """
    from recon.main_recon_modules.domain_recon import discover_subdomains, resolve_all_dns, run_puredns_resolve
    from recon.project_settings import get_settings

    domain = config["domain"]
    user_inputs = config.get("user_inputs", [])

    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")

    # Fetch settings via the same API conversion as main.py (camelCase -> UPPER_SNAKE_CASE)
    # This ensures tool toggles and parameters are in the correct format
    print(f"[*][Partial Recon] Loading project settings...")
    settings = get_settings()

    print(f"\n{'=' * 50}")
    print(f"[*][Partial Recon] Subdomain Discovery")
    print(f"[*][Partial Recon] Domain: {domain}")
    if user_inputs:
        print(f"[*][Partial Recon] User inputs: {len(user_inputs)} custom subdomains")
    print(f"{'=' * 50}\n")

    # Track whether we need a UserInput node (created after scan succeeds, not before)
    user_input_id = None
    needs_user_input = bool(user_inputs)

    # Run the standard subdomain discovery (same function as full pipeline)
    print(f"[*][Partial Recon] Running subdomain discovery tools...")
    result = discover_subdomains(
        domain=domain,
        anonymous=settings.get("USE_TOR_FOR_RECON", False),
        bruteforce=settings.get("USE_BRUTEFORCE_FOR_SUBDOMAINS", False),
        resolve=True,
        save_output=False,  # Don't save intermediate JSON
        project_id=project_id,
        settings=settings,
    )

    discovered_subs = result.get("subdomains", [])
    print(f"[+][Partial Recon] Discovery found {len(discovered_subs)} subdomains")

    # Merge user-added subdomains into the result
    if user_inputs:
        # Filter user inputs: must be valid subdomains of the target domain
        valid_user_subs = []
        for sub in user_inputs:
            sub = sub.strip().lower()
            if sub and (sub == domain or sub.endswith("." + domain)):
                valid_user_subs.append(sub)
            elif sub:
                print(f"[!][Partial Recon] Skipping invalid user input: {sub} (not a subdomain of {domain})")

        # Add user subdomains not already in the discovered list
        new_user_subs = [s for s in valid_user_subs if s not in discovered_subs]
        if new_user_subs:
            print(f"[*][Partial Recon] Adding {len(new_user_subs)} user-provided subdomains")
            all_subs = sorted(set(discovered_subs + new_user_subs))

            # Run puredns wildcard filtering on the new combined list
            all_subs = run_puredns_resolve(all_subs, domain, settings)

            # Re-resolve DNS for the full combined list
            print(f"[*][Partial Recon] Resolving DNS for {len(all_subs)} subdomains...")
            result["subdomains"] = all_subs
            result["subdomain_count"] = len(all_subs)
            dns_workers = settings.get('DNS_MAX_WORKERS', 50)
            dns_record_parallel = settings.get('DNS_RECORD_PARALLELISM', True)
            result["dns"] = resolve_all_dns(domain, all_subs, max_workers=dns_workers, record_parallelism=dns_record_parallel)

            # Rebuild subdomain status map
            subdomain_status_map = {}
            if result["dns"]:
                dns_subs = result["dns"].get("subdomains", {})
                for s in all_subs:
                    info = result["dns"].get("domain", {}) if s == domain else dns_subs.get(s, {})
                    if info.get("has_records", False):
                        subdomain_status_map[s] = "resolved"
            result["subdomain_status_map"] = subdomain_status_map

    final_count = len(result.get("subdomains", []))
    print(f"[+][Partial Recon] Final subdomain count: {final_count}")

    # Update the graph database
    print(f"[*][Partial Recon] Updating graph database...")
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                # Create UserInput node NOW (after scan succeeded) if needed
                if needs_user_input:
                    user_input_id = str(uuid.uuid4())
                    graph_client.create_user_input_node(
                        domain=domain,
                        user_input_data={
                            "id": user_input_id,
                            "input_type": "subdomains",
                            "values": user_inputs,
                            "tool_id": "SubdomainDiscovery",
                        },
                        user_id=user_id,
                        project_id=project_id,
                    )

                stats = graph_client.update_graph_from_partial_discovery(
                    recon_data=result,
                    user_id=user_id,
                    project_id=project_id,
                    user_input_id=user_input_id,
                )

                if user_input_id:
                    graph_client.update_user_input_status(
                        user_input_id, "completed", stats
                    )
                    print(f"[+][Partial Recon] Created UserInput + linked to discovery results")

                print(f"[+][Partial Recon] Graph updated successfully")
                print(f"[+][Partial Recon] Stats: {json.dumps(stats, default=str)}")
            else:
                print("[!][Partial Recon] Neo4j not reachable, graph not updated")
    except Exception as e:
        print(f"[!][Partial Recon] Graph update failed: {e}")
        raise

    print(f"\n[+][Partial Recon] Subdomain discovery completed successfully")
