#!/usr/bin/env python3
"""
RedAmon - Graph Database Update Script
=======================================
Standalone script to update Neo4j graph database from recon JSON files.

This script allows you to run graph updates independently from the main pipeline,
useful for:
- Re-importing data after schema changes
- Updating graph from existing JSON files
- Running specific update functions without re-running scans
- Debugging/testing graph updates

Usage:
    python -m graph_db.update_graph_from_json
    python graph_db/update_graph_from_json.py

Configuration:
    Edit the UPDATE_MODULES list below to select which updates to run.
    By default, all update functions are enabled.
"""

import sys
import json
from pathlib import Path
from datetime import datetime

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from params import USER_ID, PROJECT_ID, TARGET_DOMAIN
from graph_db import Neo4jClient

# =============================================================================
# CONFIGURATION - Select which graph updates to run
# =============================================================================

# Available update modules:
#   - "domain_discovery" : Updates Domain, Subdomain, IP, DNSRecord nodes
#   - "port_scan"        : Updates Port, Service nodes
#   - "http_probe"       : Updates BaseURL, Technology, Header nodes
#   - "vuln_scan"        : Updates Endpoint, Parameter, Vulnerability nodes
#
# Set to list of modules to run, or empty list [] to run ALL modules
UPDATE_MODULES = []  # Empty = run all, or specify: ["domain_discovery", "port_scan", "http_probe", "vuln_scan"]

# Path to recon JSON file (None = auto-detect from TARGET_DOMAIN)
RECON_JSON_PATH = None  # Example: "/path/to/recon_vulnweb.com.json"

# Override user/project IDs (None = use from params.py)
OVERRIDE_USER_ID = None
OVERRIDE_PROJECT_ID = None


# =============================================================================
# UPDATE FUNCTIONS MAPPING
# =============================================================================

UPDATE_FUNCTION_MAP = {
    "domain_discovery": "update_graph_from_domain_discovery",
    "port_scan": "update_graph_from_port_scan",
    "http_probe": "update_graph_from_http_probe",
    "vuln_scan": "update_graph_from_vuln_scan",
}

# Ordered execution (dependencies: domain_discovery should run first)
UPDATE_ORDER = ["domain_discovery", "port_scan", "http_probe", "vuln_scan"]


def load_recon_json(json_path: Path) -> dict:
    """Load recon JSON file."""
    if not json_path.exists():
        raise FileNotFoundError(f"Recon JSON file not found: {json_path}")

    with open(json_path, 'r') as f:
        return json.load(f)


def get_recon_file_path(target_domain: str) -> Path:
    """Get the path to the recon JSON file for a target domain."""
    import tldextract
    extracted = tldextract.extract(target_domain)
    root_domain = f"{extracted.domain}.{extracted.suffix}"
    return PROJECT_ROOT / "recon" / "output" / f"recon_{root_domain}.json"


def run_graph_updates(
    recon_data: dict,
    user_id: str,
    project_id: str,
    modules: list = None
) -> dict:
    """
    Run graph database updates for specified modules.

    Args:
        recon_data: The recon JSON data
        user_id: User identifier for multi-tenant isolation
        project_id: Project identifier for multi-tenant isolation
        modules: List of modules to update, or None/[] for all modules

    Returns:
        Dictionary with stats for each module
    """
    results = {
        "timestamp": datetime.now().isoformat(),
        "user_id": user_id,
        "project_id": project_id,
        "modules": {},
        "errors": []
    }

    # Determine which modules to run
    if not modules:
        modules_to_run = UPDATE_ORDER
    else:
        # Maintain order while filtering
        modules_to_run = [m for m in UPDATE_ORDER if m in modules]

    print("\n" + "=" * 70)
    print("           RedAmon - Graph Database Update Script")
    print("=" * 70)
    print(f"  User ID: {user_id}")
    print(f"  Project ID: {project_id}")
    print(f"  Modules to run: {', '.join(modules_to_run)}")
    print("=" * 70 + "\n")

    # Check what data is available in the JSON
    available_data = []
    if recon_data.get("dns") or recon_data.get("subdomains"):
        available_data.append("domain_discovery")
    if recon_data.get("port_scan"):
        available_data.append("port_scan")
    if recon_data.get("http_probe"):
        available_data.append("http_probe")
    if recon_data.get("vuln_scan"):
        available_data.append("vuln_scan")

    print(f"[*] Data available in JSON: {', '.join(available_data) if available_data else 'None'}")
    print()

    # Connect to Neo4j and run updates
    try:
        with Neo4jClient() as graph_client:
            if not graph_client.verify_connection():
                raise ConnectionError("Could not connect to Neo4j database")

            print("[+] Connected to Neo4j database")
            print()

            for module in modules_to_run:
                if module not in available_data:
                    print(f"[!] Skipping {module}: No data available in JSON")
                    results["modules"][module] = {"skipped": True, "reason": "No data in JSON"}
                    continue

                function_name = UPDATE_FUNCTION_MAP.get(module)
                if not function_name:
                    print(f"[!] Unknown module: {module}")
                    results["errors"].append(f"Unknown module: {module}")
                    continue

                update_func = getattr(graph_client, function_name, None)
                if not update_func:
                    print(f"[!] Function not found: {function_name}")
                    results["errors"].append(f"Function not found: {function_name}")
                    continue

                print(f"[RUNNING] {module}")
                print("-" * 40)

                try:
                    stats = update_func(recon_data, user_id, project_id)
                    results["modules"][module] = {
                        "success": True,
                        "stats": stats
                    }
                    print(f"[+] {module} completed successfully")
                    print()
                except Exception as e:
                    error_msg = f"{module} failed: {str(e)}"
                    print(f"[!] {error_msg}")
                    results["modules"][module] = {
                        "success": False,
                        "error": str(e)
                    }
                    results["errors"].append(error_msg)
                    print()

    except Exception as e:
        results["errors"].append(f"Neo4j connection failed: {str(e)}")
        print(f"[!] Neo4j connection failed: {e}")

    return results


def print_summary(results: dict):
    """Print a summary of the update results."""
    print("\n" + "=" * 70)
    print("                      UPDATE SUMMARY")
    print("=" * 70)

    for module, data in results["modules"].items():
        if data.get("skipped"):
            status = f"SKIPPED ({data.get('reason', 'unknown')})"
        elif data.get("success"):
            status = "SUCCESS"
        else:
            status = f"FAILED ({data.get('error', 'unknown')})"

        print(f"  {module:20s} : {status}")

        # Print stats if available
        if data.get("stats"):
            stats = data["stats"]
            stat_items = []
            for key, value in stats.items():
                if key != "errors" and isinstance(value, int) and value > 0:
                    # Clean up key name for display
                    display_key = key.replace("_created", "").replace("_", " ")
                    stat_items.append(f"{value} {display_key}")
            if stat_items:
                print(f"                         ({', '.join(stat_items)})")

    if results["errors"]:
        print()
        print("  Errors:")
        for error in results["errors"]:
            print(f"    - {error}")

    print("=" * 70)
    print()


def main():
    """Main entry point."""
    start_time = datetime.now()

    # Determine user/project IDs
    user_id = OVERRIDE_USER_ID or USER_ID
    project_id = OVERRIDE_PROJECT_ID or PROJECT_ID

    # Determine JSON file path
    if RECON_JSON_PATH:
        json_path = Path(RECON_JSON_PATH)
    else:
        json_path = get_recon_file_path(TARGET_DOMAIN)

    print(f"[*] Loading recon data from: {json_path}")

    try:
        recon_data = load_recon_json(json_path)
        print(f"[+] Loaded JSON successfully")

        # Show metadata
        metadata = recon_data.get("metadata", {})
        print(f"[*] Target: {metadata.get('root_domain', 'unknown')}")
        print(f"[*] Scan timestamp: {metadata.get('scan_timestamp', 'unknown')}")
        print(f"[*] Modules executed: {', '.join(metadata.get('modules_executed', []))}")

    except FileNotFoundError as e:
        print(f"[!] Error: {e}")
        print(f"[!] Run the recon pipeline first, or set RECON_JSON_PATH manually")
        return 1
    except json.JSONDecodeError as e:
        print(f"[!] Error parsing JSON: {e}")
        return 1

    # Run updates
    results = run_graph_updates(
        recon_data=recon_data,
        user_id=user_id,
        project_id=project_id,
        modules=UPDATE_MODULES if UPDATE_MODULES else None
    )

    # Print summary
    print_summary(results)

    # Print duration
    duration = (datetime.now() - start_time).total_seconds()
    print(f"[*] Total duration: {duration:.2f} seconds")

    # Return exit code based on errors
    return 1 if results["errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
