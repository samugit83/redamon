"""Partial-recon entry for IP attribution (plan 11.5).

Re-tags the graph's IPs shared_edge / dedicated / unknown with the SAME
run_ip_attribution the full pipeline runs, and writes the tags back through
update_graph_from_ip_attribution. Graph targets only: the writer tags existing
IP nodes and never creates one, so a typed address would have nothing to tag.

The signals come from the graph: each IP's open ports and CDN tag (naabu, tlsx,
httpx), its ASN, and the forward-DNS RESOLVES_TO edges, read as this run's DNS
block. The one active check is the same capped, RoE-filtered handshake without
SNI the full run makes, and stealth mode turns it off the same way.
"""

import json
import os
import sys

from recon.helpers.ip_placeholders import is_placeholder
from recon.partial_recon_modules.helpers import (
    _should_include_root_domain,
    partial_settings,
    scope_roots,
)
from recon.partial_recon_modules.graph_builders import _build_port_scan_data_from_graph

# An IP-mode target's Subdomain is its address with dashes ("192-0-2-1"): a
# label, not a DNS name. Kept under its old name for the callers.
_is_placeholder = is_placeholder


def _mark_placeholders(recon_data: dict) -> None:
    for name, entry in ((recon_data.get("dns") or {}).get("subdomains") or {}).items():
        if isinstance(entry, dict) and _is_placeholder(str(name)):
            entry["is_mock"] = True


def run_ip_attribution_partial(config: dict) -> None:
    from recon.main_recon_modules.ip_attribution import run_ip_attribution

    roots = scope_roots(config)
    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")

    print("[*][Partial Recon] Loading project settings...")
    settings = partial_settings(config)
    settings['IP_ATTRIBUTION_ENABLED'] = True  # the user explicitly chose to run it

    print(f"\n{'=' * 50}")
    print("[*][Partial Recon] IP Attribution")
    print(f"[*][Partial Recon] Roots: {', '.join(roots)}")
    print(f"{'=' * 50}\n")

    print("[*][Partial Recon] Querying graph for IPs, their ports and the names resolving to them...")
    recon_data = _build_port_scan_data_from_graph(
        roots, user_id, project_id,
        include_root_domain=_should_include_root_domain(settings),
        domain_groups=config.get("domain_groups"),
    )
    by_ip = (recon_data.get("port_scan") or {}).get("by_ip") or {}
    dns = recon_data.get("dns") or {}
    has_dns_ip = any(
        (entry or {}).get("ips", {}).get("ipv4") or (entry or {}).get("ips", {}).get("ipv6")
        for entry in [dns.get("domain") or {}, *(dns.get("subdomains") or {}).values()]
    )
    if not by_ip and not has_dns_ip:
        print("[!][Partial Recon] No IPs in the graph to attribute. Run a scan first.")
        sys.exit(1)

    _mark_placeholders(recon_data)
    result = run_ip_attribution(recon_data, settings)

    print("[*][Partial Recon] Updating graph database...")
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if not graph_client.verify_connection():
                print("[!][Partial Recon] Neo4j not reachable -- graph not updated")
                return
            stats = graph_client.update_graph_from_ip_attribution(result, user_id, project_id)
            print(f"[+][Partial Recon] IP attribution graph update: {json.dumps(stats, default=str)}")
    except Exception as e:
        print(f"[!][Partial Recon] Graph update failed: {e}")
