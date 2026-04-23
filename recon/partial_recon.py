"""
Partial Recon - Entry point for per-tool partial reconnaissance runs.

This script is invoked by the orchestrator as a container command
(instead of main.py) for running individual recon phases on demand.

Configuration is passed via a JSON file whose path is in the
PARTIAL_RECON_CONFIG environment variable.

Currently supported tool_ids:
  - SubdomainDiscovery: runs discover_subdomains() from domain_recon.py
  - Naabu: runs run_port_scan() from port_scan.py
  - Masscan: runs run_masscan_scan() from masscan_scan.py
  - Nmap: runs run_nmap_scan() from nmap_scan.py
  - Masscan: runs run_masscan_scan() from masscan_scan.py
  - Httpx: runs run_http_probe() from http_probe.py
  - Katana: runs run_katana_crawler() from helpers/resource_enum
  - Hakrawler: runs run_hakrawler_crawler() from helpers
  - Ffuf: runs run_ffuf_discovery() from helpers/resource_enum
  - JsRecon: runs run_js_recon() from js_recon.py
  - Shodan: runs run_shodan_enrichment() from shodan_enrich.py
  - Urlscan: runs run_urlscan_discovery_only() from urlscan_enrich.py
  - OsintEnrichment: runs OSINT sub-tools (Censys, FOFA, OTX, etc.) in parallel
"""

import os
import sys
import json
from pathlib import Path
from datetime import datetime

# Add project root to path (same pattern as main.py)
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


from recon.partial_recon_modules.user_inputs import (
    _cleanup_orphan_user_inputs,
)
from recon.partial_recon_modules.subdomain_discovery import run_subdomain_discovery
from recon.partial_recon_modules.port_scanning import (
    run_naabu,
    run_masscan,
    run_nmap,
)
from recon.partial_recon_modules.http_probing import run_httpx
from recon.partial_recon_modules.web_crawling import (
    run_katana,
    run_hakrawler,
    run_ffuf,
    run_gau,
    run_jsluice,
)
from recon.partial_recon_modules.parameter_discovery import (
    run_paramspider,
    run_arjun,
    run_kiterunner,
)
from recon.partial_recon_modules.js_analysis import run_jsrecon
from recon.partial_recon_modules.graphql_scanning import run_graphqlscan
from recon.partial_recon_modules.vulnerability_scanning import (
    run_nuclei,
    run_security_checks_partial,
    run_subdomain_takeover_partial,
)
from recon.partial_recon_modules.osint_enrichment import (
    run_shodan,
    run_urlscan,
    run_uncover,
    run_osint_enrichment,
)


def load_config() -> dict:
    """Load partial recon configuration from JSON file."""
    config_path = os.environ.get("PARTIAL_RECON_CONFIG")
    if not config_path:
        print("[!][Partial] PARTIAL_RECON_CONFIG not set")
        sys.exit(1)

    try:
        with open(config_path, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"[!][Partial] Failed to load config from {config_path}: {e}")
        sys.exit(1)


def main():
    config = load_config()
    tool_id = config.get("tool_id", "")

    print(f"[*][Partial Recon] Starting partial recon for tool: {tool_id}")
    print(f"[*][Partial Recon] Timestamp: {datetime.now().isoformat()}")

    if tool_id == "SubdomainDiscovery":
        run_subdomain_discovery(config)
    elif tool_id == "Naabu":
        run_naabu(config)
    elif tool_id == "Masscan":
        run_masscan(config)
    elif tool_id == "Nmap":
        run_nmap(config)
    elif tool_id == "Httpx":
        run_httpx(config)
    elif tool_id == "Katana":
        run_katana(config)
    elif tool_id == "Hakrawler":
        run_hakrawler(config)
    elif tool_id == "Gau":
        run_gau(config)
    elif tool_id == "Jsluice":
        run_jsluice(config)
    elif tool_id == "Kiterunner":
        run_kiterunner(config)
    elif tool_id == "ParamSpider":
        run_paramspider(config)
    elif tool_id == "Ffuf":
        run_ffuf(config)
    elif tool_id == "Arjun":
        run_arjun(config)
    elif tool_id == "JsRecon":
        run_jsrecon(config)
    elif tool_id == "GraphqlScan":
        run_graphqlscan(config)
    elif tool_id == "Nuclei":
        run_nuclei(config)
    elif tool_id == "SubdomainTakeover":
        run_subdomain_takeover_partial(config)
    elif tool_id == "SecurityChecks":
        run_security_checks_partial(config)
    elif tool_id == "Shodan":
        run_shodan(config)
    elif tool_id == "Urlscan":
        run_urlscan(config)
    elif tool_id == "Uncover":
        run_uncover(config)
    elif tool_id == "OsintEnrichment":
        run_osint_enrichment(config)
    else:
        print(f"[!][Partial Recon] Unknown tool_id: {tool_id}")
        sys.exit(1)

    # Clean up orphan UserInput nodes (created but no PRODUCED children)
    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")
    if user_id and project_id:
        _cleanup_orphan_user_inputs(user_id, project_id)


if __name__ == "__main__":
    main()
