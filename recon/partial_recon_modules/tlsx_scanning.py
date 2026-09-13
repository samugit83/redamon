"""Partial-recon entry for tlsx (TLS certificate grab).

Mirrors the Nmap partial path (same IP + Port input shape): builds recon_data
from the existing graph (IPs + Ports + Subdomains), optionally injects
user-provided IPs/ports, runs the SAME run_tlsx_enrichment used by the full
pipeline, and merges the result back via update_graph_from_tlsx. Partial and
full share one graph, so every write is a MERGE on the tenant triple.
"""

import json
import os
import sys
import uuid

from recon.partial_recon_modules.helpers import _classify_ip, _is_ip_or_cidr, _should_include_root_domain
from recon.partial_recon_modules.graph_builders import _build_port_scan_data_from_graph


def run_tlsx(config: dict) -> None:
    from recon.main_recon_modules.tls_scan import run_tlsx_enrichment
    from recon.project_settings import get_settings

    domain = config["domain"]
    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")

    print("[*][Partial Recon] Loading project settings...")
    settings = get_settings()
    settings['TLSX_ENABLED'] = True  # the user explicitly chose to run tlsx

    print(f"\n{'=' * 50}")
    print("[*][Partial Recon] tlsx TLS Certificate Grab")
    print(f"[*][Partial Recon] Domain: {domain}")
    print(f"{'=' * 50}\n")

    # Parse user targets (IPs + ports), same shape Nmap accepts.
    user_targets = config.get("user_targets") or {}
    user_ips, user_ports = [], []
    ip_attach_to = None
    if user_targets:
        for entry in user_targets.get("ips", []):
            entry = (entry or "").strip()
            if entry and _is_ip_or_cidr(entry):
                user_ips.append(entry)
            elif entry:
                print(f"[!][Partial Recon] Skipping invalid IP: {entry}")
        for entry in user_targets.get("ports", []):
            try:
                port = int(entry)
                if 1 <= port <= 65535:
                    user_ports.append(port)
            except (ValueError, TypeError):
                print(f"[!][Partial Recon] Skipping invalid port: {entry}")
        ip_attach_to = user_targets.get("ip_attach_to")
    elif config.get("user_inputs"):
        for entry in config["user_inputs"]:
            entry = (entry or "").strip()
            if entry and _is_ip_or_cidr(entry):
                user_ips.append(entry)

    include_graph = config.get("include_graph_targets", True)
    if include_graph:
        print("[*][Partial Recon] Querying graph for targets (IPs, ports, subdomains)...")
        recon_data = _build_port_scan_data_from_graph(
            domain, user_id, project_id,
            include_root_domain=_should_include_root_domain(settings),
        )
    else:
        recon_data = {
            "domain": domain,
            "port_scan": {"by_ip": {}, "by_host": {}, "ip_to_hostnames": {},
                          "all_ports": [], "scan_metadata": {}, "summary": {}},
            "dns": {"domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
                    "subdomains": {}},
        }

    # Inject user IPs.
    user_ip_addrs = []
    for ip_str in user_ips:
        if "/" in ip_str:
            import ipaddress as _ip
            try:
                network = _ip.ip_network(ip_str, strict=False)
                if network.num_addresses > 256:
                    print(f"[!][Partial Recon] CIDR {ip_str} too large; max /24. Skipping.")
                    continue
                addrs = [str(h) for h in network.hosts()]
            except ValueError:
                print(f"[!][Partial Recon] Invalid CIDR: {ip_str}")
                continue
        else:
            addrs = [ip_str]
        for addr in addrs:
            user_ip_addrs.append(addr)
            recon_data["port_scan"]["by_ip"].setdefault(addr, {
                "ip": addr, "hostnames": [ip_attach_to] if ip_attach_to else [],
                "ports": [], "port_details": [],
            })

    # Inject user ports across every IP (tlsx builds targets from by_ip.ports).
    if user_ports:
        for port in user_ports:
            if port not in recon_data["port_scan"]["all_ports"]:
                recon_data["port_scan"]["all_ports"].append(port)
            for ip_data in recon_data["port_scan"]["by_ip"].values():
                if port not in ip_data["ports"]:
                    ip_data["ports"].append(port)
                    ip_data.setdefault("port_details", []).append(
                        {"port": port, "protocol": "tcp", "service": ""})

    if not recon_data["port_scan"]["by_ip"]:
        print("[!][Partial Recon] No scannable IPs (graph empty and no valid user IPs).")
        print("[!][Partial Recon] Run Naabu/Nmap first, or provide IPs + ports manually.")
        sys.exit(1)

    result = run_tlsx_enrichment(recon_data, settings=settings)

    print("[*][Partial Recon] Updating graph database...")
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if not graph_client.verify_connection():
                print("[!][Partial Recon] Neo4j not reachable -- graph not updated")
                return
            # Custom ports: create Port/Service/IP nodes first so the tlsx MATCH
            # on Service lands (update_graph_from_tlsx uses MATCH, not MERGE, for
            # Service enrichment).
            if user_ports:
                graph_client.update_graph_from_port_scan(
                    recon_data=result, user_id=user_id, project_id=project_id)
            stats = graph_client.update_graph_from_tlsx(
                recon_data=result, user_id=user_id, project_id=project_id)
            print(f"[+][Partial Recon] tlsx graph update: {json.dumps(stats, default=str)}")

            # Track generic user IPs via a UserInput node (parity with Nmap).
            if user_ip_addrs and not ip_attach_to:
                try:
                    # create_user_input_node reads input_type / values / tool_id.
                    # Passing anything else does not raise -- it .get()s past them
                    # and writes a UserInput with values=[] and tool_id='',
                    # silently losing the operator's manually-entered IPs.
                    graph_client.create_user_input_node(
                        domain=domain,
                        user_input_data={
                            "id": str(uuid.uuid4()),
                            "input_type": "ips",
                            "values": user_ip_addrs,
                            "tool_id": "Tlsx",
                        },
                        user_id=user_id, project_id=project_id,
                    )
                except Exception as e:
                    print(f"[!][Partial Recon] UserInput node creation failed (non-fatal): {e}")
    except Exception as e:
        print(f"[!][Partial Recon] Graph update failed: {e}")
