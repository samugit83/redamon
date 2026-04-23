import os
import sys
import json
import uuid
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.partial_recon_modules.helpers import (
    _classify_ip,
    _is_ip_or_cidr,
    _is_valid_hostname,
    _is_valid_url,
    _resolve_hostname,
)
from recon.partial_recon_modules.graph_builders import _build_port_scan_data_from_graph


def run_httpx(config: dict) -> None:
    """
    Run partial HTTP probing using httpx (run_http_probe from http_probe.py).

    Httpx probes URLs built from port_scan data (IPs + ports) and DNS data
    (subdomains). User can provide custom subdomains, IPs, and ports.
    IPs+ports are injected into the port_scan structure (same as Nmap).
    Subdomains are resolved and added to the DNS section.
    """
    import ipaddress as _ipaddress
    from recon.main_recon_modules.http_probe import run_http_probe as _run_http_probe
    from recon.project_settings import get_settings

    domain = config["domain"]

    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")

    print(f"[*][Partial Recon] Loading project settings...")
    settings = get_settings()

    # Force-enable httpx since the user explicitly chose to run it
    settings['HTTPX_ENABLED'] = True

    print(f"\n{'=' * 50}")
    print(f"[*][Partial Recon] HTTP Probing (Httpx)")
    print(f"[*][Partial Recon] Domain: {domain}")
    print(f"{'=' * 50}\n")

    # Parse user targets -- Httpx accepts subdomains, IPs, and ports
    user_targets = config.get("user_targets") or {}
    user_hostnames = []
    user_ips = []
    user_ports = []
    ip_attach_to = None
    user_input_id = None

    if user_targets:
        for entry in user_targets.get("subdomains", []):
            entry = entry.strip().lower()
            if entry and _is_valid_hostname(entry):
                user_hostnames.append(entry)
            elif entry:
                print(f"[!][Partial Recon] Skipping invalid subdomain: {entry}")

        for entry in user_targets.get("ips", []):
            entry = entry.strip()
            if entry and _is_ip_or_cidr(entry):
                user_ips.append(entry)
            elif entry:
                print(f"[!][Partial Recon] Skipping invalid IP: {entry}")

        for entry in user_targets.get("ports", []):
            try:
                port = int(entry)
                if 1 <= port <= 65535:
                    user_ports.append(port)
                else:
                    print(f"[!][Partial Recon] Skipping out-of-range port: {entry}")
            except (ValueError, TypeError):
                print(f"[!][Partial Recon] Skipping invalid port: {entry}")

        ip_attach_to = user_targets.get("ip_attach_to")

    if user_hostnames:
        print(f"[+][Partial Recon] Validated {len(user_hostnames)} custom hostnames")
    if user_ips:
        print(f"[+][Partial Recon] Validated {len(user_ips)} custom IPs/CIDRs")
        if ip_attach_to:
            print(f"[+][Partial Recon] IPs will be attached to subdomain: {ip_attach_to}")
        else:
            print(f"[+][Partial Recon] IPs will be tracked via UserInput (generic)")
    if user_ports:
        print(f"[+][Partial Recon] Validated {len(user_ports)} custom ports: {user_ports}")

    # Create UserInput node only when IPs are generic (no subdomain attachment)
    if user_ips and not ip_attach_to:
        user_input_id = str(uuid.uuid4())
        try:
            from graph_db import Neo4jClient
            with Neo4jClient() as graph_client:
                if graph_client.verify_connection():
                    graph_client.create_user_input_node(
                        domain=domain,
                        user_input_data={
                            "id": user_input_id,
                            "input_type": "ips",
                            "values": user_ips,
                            "tool_id": "Httpx",
                        },
                        user_id=user_id,
                        project_id=project_id,
                    )
                    print(f"[+][Partial Recon] Created UserInput node for IPs: {user_input_id}")
                else:
                    print("[!][Partial Recon] Neo4j not reachable, skipping UserInput node")
                    user_input_id = None
        except Exception as e:
            print(f"[!][Partial Recon] Failed to create UserInput node: {e}")
            user_input_id = None

    # Build recon_data from Neo4j graph (port_scan + DNS, same structure as Nmap)
    # httpx uses port_scan data if available, falls back to DNS for default ports
    include_graph = config.get("include_graph_targets", True)
    if include_graph:
        print(f"[*][Partial Recon] Querying graph for targets (IPs, ports, subdomains)...")
        recon_data = _build_port_scan_data_from_graph(domain, user_id, project_id)
    else:
        print(f"[*][Partial Recon] Skipping graph targets (user opted out)")
        recon_data = {
            "domain": domain,
            "port_scan": {
                "by_ip": {}, "by_host": {}, "ip_to_hostnames": {},
                "all_ports": [], "scan_metadata": {"scanners": ["naabu"]}, "summary": {},
            },
            "dns": {
                "domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
                "subdomains": {},
            },
        }

    # STEP 1: Resolve user-provided hostnames and add to recon_data DNS section
    resolved_hostnames = {}
    if user_hostnames:
        print(f"[*][Partial Recon] Resolving {len(user_hostnames)} user-provided hostnames...")
        for hostname in user_hostnames:
            if hostname in recon_data["dns"]["subdomains"]:
                print(f"[*][Partial Recon] {hostname} already in graph, skipping")
                continue
            ips = _resolve_hostname(hostname)
            if ips["ipv4"] or ips["ipv6"]:
                recon_data["dns"]["subdomains"][hostname] = {
                    "ips": ips,
                    "has_records": True,
                }
                resolved_hostnames[hostname] = ips
                print(f"[+][Partial Recon] Resolved {hostname} -> {ips['ipv4'] + ips['ipv6']}")
            else:
                print(f"[!][Partial Recon] Could not resolve {hostname}, skipping")

        # Create Subdomain + IP + relationships in Neo4j for newly resolved hostnames
        if resolved_hostnames:
            print(f"[*][Partial Recon] Creating graph nodes for {len(resolved_hostnames)} user hostnames...")
            try:
                from graph_db import Neo4jClient
                with Neo4jClient() as graph_client:
                    if graph_client.verify_connection():
                        driver = graph_client.driver
                        with driver.session() as session:
                            for hostname, ips in resolved_hostnames.items():
                                session.run(
                                    """
                                    MERGE (s:Subdomain {name: $name, user_id: $uid, project_id: $pid})
                                    SET s.has_dns_records = true,
                                        s.status = coalesce(s.status, 'resolved'),
                                        s.discovered_at = coalesce(s.discovered_at, datetime()),
                                        s.updated_at = datetime(),
                                        s.source = 'partial_recon_user_input'
                                    """,
                                    name=hostname, uid=user_id, pid=project_id,
                                )
                                session.run(
                                    """
                                    MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                                    MATCH (s:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                                    MERGE (s)-[:BELONGS_TO]->(d)
                                    MERGE (d)-[:HAS_SUBDOMAIN]->(s)
                                    """,
                                    domain=domain, sub=hostname, uid=user_id, pid=project_id,
                                )
                                for ip_version in ("ipv4", "ipv6"):
                                    for ip_addr in ips.get(ip_version, []):
                                        session.run(
                                            """
                                            MERGE (i:IP {address: $addr, user_id: $uid, project_id: $pid})
                                            SET i.version = $version, i.updated_at = datetime()
                                            """,
                                            addr=ip_addr, uid=user_id, pid=project_id, version=ip_version,
                                        )
                                        record_type = "A" if ip_version == "ipv4" else "AAAA"
                                        session.run(
                                            """
                                            MATCH (s:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                                            MATCH (i:IP {address: $addr, user_id: $uid, project_id: $pid})
                                            MERGE (s)-[:RESOLVES_TO {record_type: $rtype}]->(i)
                                            """,
                                            sub=hostname, addr=ip_addr, uid=user_id, pid=project_id, rtype=record_type,
                                        )
                                print(f"[+][Partial Recon] Created graph nodes for {hostname}")
                    else:
                        print("[!][Partial Recon] Neo4j not reachable, skipping subdomain node creation")
            except Exception as e:
                print(f"[!][Partial Recon] Failed to create subdomain nodes: {e}")

    # STEP 2: Inject user-provided IPs into port_scan structure
    # Safety: if ip_attach_to points to a subdomain not in graph, fall back to generic
    if ip_attach_to and ip_attach_to not in recon_data["dns"]["subdomains"]:
        _sub_exists = False
        try:
            from graph_db import Neo4jClient
            with Neo4jClient() as _gc:
                if _gc.verify_connection():
                    with _gc.driver.session() as _s:
                        _res = _s.run(
                            "MATCH (s:Subdomain {name: $name, user_id: $uid, project_id: $pid}) RETURN s LIMIT 1",
                            name=ip_attach_to, uid=user_id, pid=project_id,
                        )
                        _sub_exists = _res.single() is not None
        except Exception:
            pass
        if not _sub_exists:
            print(f"[!][Partial Recon] Subdomain {ip_attach_to} not found in graph, falling back to generic UserInput for IPs")
            ip_attach_to = None
            if user_ips and not user_input_id:
                user_input_id = str(uuid.uuid4())
                try:
                    from graph_db import Neo4jClient
                    with Neo4jClient() as graph_client:
                        if graph_client.verify_connection():
                            graph_client.create_user_input_node(
                                domain=domain,
                                user_input_data={
                                    "id": user_input_id,
                                    "input_type": "ips",
                                    "values": user_ips,
                                    "tool_id": "Httpx",
                                },
                                user_id=user_id,
                                project_id=project_id,
                            )
                            print(f"[+][Partial Recon] Created fallback UserInput node: {user_input_id}")
                except Exception:
                    user_input_id = None

    user_ip_addrs = []
    if user_ips:
        print(f"[*][Partial Recon] Adding {len(user_ips)} user-provided IPs/CIDRs to scan targets")
        for ip_str in user_ips:
            if "/" in ip_str:
                try:
                    network = _ipaddress.ip_network(ip_str, strict=False)
                    if network.num_addresses > 256:
                        print(f"[!][Partial Recon] CIDR {ip_str} too large ({network.num_addresses} hosts), max /24 (256). Skipping.")
                        continue
                    for host_ip in network.hosts():
                        addr = str(host_ip)
                        user_ip_addrs.append(addr)
                        if addr not in recon_data["port_scan"]["by_ip"]:
                            recon_data["port_scan"]["by_ip"][addr] = {
                                "ip": addr,
                                "hostnames": [ip_attach_to] if ip_attach_to else [],
                                "ports": [],
                                "port_details": [],
                            }
                except ValueError:
                    print(f"[!][Partial Recon] Invalid CIDR: {ip_str}")
            else:
                user_ip_addrs.append(ip_str)
                if ip_str not in recon_data["port_scan"]["by_ip"]:
                    recon_data["port_scan"]["by_ip"][ip_str] = {
                        "ip": ip_str,
                        "hostnames": [ip_attach_to] if ip_attach_to else [],
                        "ports": [],
                        "port_details": [],
                    }

        # Also populate dns section for user IPs
        if ip_attach_to:
            if ip_attach_to not in recon_data["dns"]["subdomains"]:
                recon_data["dns"]["subdomains"][ip_attach_to] = {
                    "ips": {"ipv4": [], "ipv6": []},
                    "has_records": True,
                }
            target_dns_ips = recon_data["dns"]["subdomains"][ip_attach_to]["ips"]
        else:
            target_dns_ips = recon_data["dns"]["domain"]["ips"]

        for addr in user_ip_addrs:
            bucket = _classify_ip(addr)
            if addr not in target_dns_ips[bucket]:
                target_dns_ips[bucket].append(addr)
                if not ip_attach_to:
                    recon_data["dns"]["domain"]["has_records"] = True

    # STEP 3: Inject user-provided ports into port_scan (global -- applies to all IPs)
    if user_ports:
        for port in user_ports:
            if port not in recon_data["port_scan"]["all_ports"]:
                recon_data["port_scan"]["all_ports"].append(port)
            for ip_data in recon_data["port_scan"]["by_ip"].values():
                if port not in ip_data["ports"]:
                    ip_data["ports"].append(port)
                    ip_data["port_details"].append({
                        "port": port, "protocol": "tcp", "service": "",
                    })
            for host_data in recon_data["port_scan"]["by_host"].values():
                if port not in host_data["ports"]:
                    host_data["ports"].append(port)
                    host_data["port_details"].append({
                        "port": port, "protocol": "tcp", "service": "",
                    })
        recon_data["port_scan"]["all_ports"].sort()
        print(f"[+][Partial Recon] Injected {len(user_ports)} custom ports into scan targets")

    # STEP 4: Ensure all user targets are in port_scan.by_host so httpx builds URLs.
    # build_targets_from_naabu() only reads by_host -- anything not there is invisible.
    # Use custom ports if provided, otherwise default to 80+443.
    probe_ports = user_ports if user_ports else [80, 443]
    probe_port_details = [{"port": p, "protocol": "tcp", "service": ""} for p in probe_ports]
    injected_hosts = 0

    # Inject resolved user subdomains
    for hostname, ips in resolved_hostnames.items():
        if hostname not in recon_data["port_scan"]["by_host"]:
            all_ips = ips.get("ipv4", []) + ips.get("ipv6", [])
            recon_data["port_scan"]["by_host"][hostname] = {
                "host": hostname,
                "ip": all_ips[0] if all_ips else "",
                "ports": list(probe_ports),
                "port_details": list(probe_port_details),
            }
            injected_hosts += 1
            # Also register in ip_to_hostnames
            for ip_addr in all_ips:
                recon_data["port_scan"]["ip_to_hostnames"].setdefault(ip_addr, [])
                if hostname not in recon_data["port_scan"]["ip_to_hostnames"][ip_addr]:
                    recon_data["port_scan"]["ip_to_hostnames"][ip_addr].append(hostname)
                # Ensure IP is in by_ip with ports
                if ip_addr not in recon_data["port_scan"]["by_ip"]:
                    recon_data["port_scan"]["by_ip"][ip_addr] = {
                        "ip": ip_addr, "hostnames": [hostname],
                        "ports": list(probe_ports), "port_details": list(probe_port_details),
                    }
                else:
                    existing = recon_data["port_scan"]["by_ip"][ip_addr]
                    if hostname not in existing.get("hostnames", []):
                        existing.setdefault("hostnames", []).append(hostname)

    # Inject user IPs as direct hosts (httpx can probe http://1.2.3.4:port)
    for ip_addr in user_ip_addrs:
        if ip_addr not in recon_data["port_scan"]["by_host"]:
            recon_data["port_scan"]["by_host"][ip_addr] = {
                "host": ip_addr,
                "ip": ip_addr,
                "ports": list(probe_ports),
                "port_details": list(probe_port_details),
            }
            injected_hosts += 1

    # Ensure probe ports are in all_ports
    for p in probe_ports:
        if p not in recon_data["port_scan"]["all_ports"]:
            recon_data["port_scan"]["all_ports"].append(p)
    recon_data["port_scan"]["all_ports"].sort()

    if injected_hosts:
        if user_ports:
            print(f"[+][Partial Recon] Injected {injected_hosts} user targets into httpx probe list with custom ports {user_ports}")
        else:
            print(f"[+][Partial Recon] Injected {injected_hosts} user targets into httpx probe list with default ports [80, 443]")

    # Check we have targets
    has_port_scan = bool(recon_data.get("port_scan", {}).get("by_host"))
    sub_count = len(recon_data["dns"]["subdomains"])
    domain_has_ips = recon_data["dns"]["domain"]["has_records"]

    if not has_port_scan and sub_count == 0 and not domain_has_ips:
        print("[!][Partial Recon] No scannable targets found (graph is empty and no valid user targets resolved).")
        print("[!][Partial Recon] Run Subdomain Discovery + Port Scanning first, or provide targets manually.")
        sys.exit(1)

    if has_port_scan:
        ip_count = len(recon_data["port_scan"]["by_ip"])
        port_count = len(recon_data["port_scan"]["all_ports"])
        print(f"[+][Partial Recon] Found {ip_count} IPs with {port_count} ports + {sub_count} subdomains")
    else:
        print(f"[+][Partial Recon] Found {sub_count} subdomains (no port scan data, httpx will use default ports)")

    # Run httpx probe (same function as full pipeline)
    print(f"[*][Partial Recon] Running httpx HTTP probing...")
    result = _run_http_probe(recon_data, output_file=None, settings=settings)

    # Update the graph database
    print(f"[*][Partial Recon] Updating graph database...")
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                # Create Port nodes for user-injected targets (subdomains + IPs)
                # so the full chain IP -> Port -> Service -> BaseURL connects
                if (resolved_hostnames or user_ip_addrs) and "port_scan" in result:
                    ps_stats = graph_client.update_graph_from_port_scan(
                        recon_data=result,
                        user_id=user_id,
                        project_id=project_id,
                    )
                    print(f"[+][Partial Recon] Created Port nodes for user targets: {json.dumps(ps_stats, default=str)}")

                stats = graph_client.update_graph_from_http_probe(
                    recon_data=result,
                    user_id=user_id,
                    project_id=project_id,
                )

                # Link user-provided IPs to graph
                if user_ip_addrs:
                    driver = graph_client.driver
                    with driver.session() as session:
                        if ip_attach_to and not user_input_id:
                            for ip_addr in user_ip_addrs:
                                ip_version = _classify_ip(ip_addr)
                                record_type = "A" if ip_version == "ipv4" else "AAAA"
                                session.run(
                                    """
                                    MERGE (i:IP {address: $addr, user_id: $uid, project_id: $pid})
                                    SET i.version = $version, i.updated_at = datetime()
                                    WITH i
                                    MATCH (s:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                                    MERGE (s)-[:RESOLVES_TO {record_type: $rtype}]->(i)
                                    """,
                                    addr=ip_addr, uid=user_id, pid=project_id,
                                    version=ip_version, sub=ip_attach_to, rtype=record_type,
                                )
                            print(f"[+][Partial Recon] Linked {len(user_ip_addrs)} IPs to {ip_attach_to} via RESOLVES_TO")
                        elif user_input_id:
                            for ip_addr in user_ip_addrs:
                                ip_version = _classify_ip(ip_addr)
                                session.run(
                                    """
                                    MERGE (i:IP {address: $addr, user_id: $uid, project_id: $pid})
                                    SET i.version = $version, i.updated_at = datetime()
                                    WITH i
                                    MATCH (ui:UserInput {id: $ui_id})
                                    MERGE (ui)-[:PRODUCED]->(i)
                                    """,
                                    addr=ip_addr, uid=user_id, pid=project_id,
                                    version=ip_version, ui_id=user_input_id,
                                )
                            graph_client.update_user_input_status(
                                user_input_id, "completed", stats
                            )
                            print(f"[+][Partial Recon] Linked {len(user_ip_addrs)} IPs via UserInput PRODUCED")

                print(f"[+][Partial Recon] Graph updated successfully")
                print(f"[+][Partial Recon] Stats: {json.dumps(stats, default=str)}")
            else:
                print("[!][Partial Recon] Neo4j not reachable, graph not updated")
    except Exception as e:
        print(f"[!][Partial Recon] Graph update failed: {e}")
        if user_input_id:
            try:
                from graph_db import Neo4jClient
                with Neo4jClient() as gc:
                    if gc.verify_connection():
                        gc.update_user_input_status(user_input_id, "error", {"error": str(e)})
            except Exception:
                pass
        raise

    print(f"\n[+][Partial Recon] HTTP probing completed successfully")
