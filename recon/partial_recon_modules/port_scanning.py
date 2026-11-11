import os
import sys
import json
import uuid
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.partial_recon_modules.helpers import (
    typed_host_ok,
    root_orgs,
    attach_org,
    _classify_ip,
    _is_ip_or_cidr,
    _is_valid_hostname,
    _resolve_hostname,
    _should_include_root_domain,
    host_in_roots,
    partial_settings,
    root_for_host,
    scope_roots,
)
from recon.partial_recon_modules.graph_builders import (
    _build_recon_data_from_graph,
    _build_port_scan_data_from_graph,
)


def _run_port_scanner(config: dict, tool_id: str, scan_fn, label: str,
                      pre_settings: dict = None, normalize_fn=None) -> None:
    """
    Shared logic for port-scanner partial recon (Naabu, Masscan, etc.).

    Args:
        config: Partial recon config dict from orchestrator.
        tool_id: Tool identifier for UserInput nodes (e.g. "Naabu", "Masscan").
        scan_fn: The scan function to call (e.g. run_port_scan, run_masscan_scan).
        label: Display label for log messages.
        pre_settings: Settings to force before calling scan_fn (e.g. MASSCAN_ENABLED).
        normalize_fn: Optional post-scan normalizer -- receives recon_data, mutates in place.
    """
    import ipaddress as _ipaddress

    roots = scope_roots(config)
    user_inputs = config.get("user_inputs", [])

    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")

    print(f"[*][Partial Recon] Loading project settings...")
    settings = partial_settings(config)

    if pre_settings:
        settings.update(pre_settings)

    print(f"\n{'=' * 50}")
    print(f"[*][Partial Recon] Port Scanning ({label})")
    print(f"[*][Partial Recon] Roots: {', '.join(roots)}")
    print(f"{'=' * 50}\n")

    # Parse user targets (structured format from new modal, or legacy flat list)
    user_targets = config.get("user_targets") or {}
    user_ips = []
    user_hostnames = []
    ip_attach_to = None
    user_input_id = None

    if user_targets:
        # New structured format: {subdomains: [...], ips: [...], ip_attach_to: "..." | null}
        for entry in user_targets.get("subdomains", []):
            entry = entry.strip().lower()
            if entry and _is_valid_hostname(entry) and typed_host_ok(entry, roots, config.get("domain_groups")):
                user_hostnames.append(entry)
            elif entry and _is_valid_hostname(entry):
                print(f"[!][Partial Recon] Skipping subdomain outside the project's domains: {entry}")
            elif entry:
                print(f"[!][Partial Recon] Skipping invalid subdomain: {entry}")

        for entry in user_targets.get("ips", []):
            entry = entry.strip()
            if entry and _is_ip_or_cidr(entry):
                user_ips.append(entry)
            elif entry:
                print(f"[!][Partial Recon] Skipping invalid IP: {entry}")

        ip_attach_to = user_targets.get("ip_attach_to")  # subdomain name or None

    elif user_inputs:
        # Legacy flat list fallback: classify each entry
        for entry in user_inputs:
            entry = entry.strip().lower()
            if not entry:
                continue
            if _is_ip_or_cidr(entry):
                user_ips.append(entry)
            elif _is_valid_hostname(entry) and typed_host_ok(entry, roots, config.get("domain_groups")):
                user_hostnames.append(entry)
            else:
                print(f"[!][Partial Recon] Skipping invalid or out-of-scope target: {entry}")

    if user_ips:
        print(f"[+][Partial Recon] Validated {len(user_ips)} custom IPs/CIDRs")
        if ip_attach_to:
            print(f"[+][Partial Recon] IPs will be attached to subdomain: {ip_attach_to}")
        else:
            print(f"[+][Partial Recon] IPs will be tracked via UserInput (generic)")
    if user_hostnames:
        print(f"[+][Partial Recon] Validated {len(user_hostnames)} custom hostnames")

    # Track whether we need a UserInput node (created after scan succeeds, not before)
    needs_user_input = bool(user_ips and not ip_attach_to)

    # Build recon_data from Neo4j graph (or start empty if user unchecked graph targets)
    include_graph = config.get("include_graph_targets", True)
    if include_graph:
        print(f"[*][Partial Recon] Querying graph for targets (IPs and subdomains)...")
        recon_data = _build_recon_data_from_graph(
            roots, user_id, project_id,
            include_root_domain=_should_include_root_domain(settings),
            domain_groups=config.get("domain_groups"),
        )
    else:
        print(f"[*][Partial Recon] Skipping graph targets (user opted out)")
        recon_data = {
            "domain": roots[0] if roots else "",
            "domains": roots,
            "dns": {
                "domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
                "subdomains": {},
            },
        }

    # STEP 1: Resolve user-provided hostnames FIRST (before IP injection)
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
                                # MERGE Subdomain node
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
                                # MERGE Domain <-> Subdomain relationships, on the
                                # hostname's own root.
                                session.run(
                                    """
                                    MATCH (d:Domain {user_id: $uid, project_id: $pid}) WHERE toLower(d.name) = toLower($domain)
                                    MATCH (s:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                                    MERGE (s)-[:BELONGS_TO]->(d)
                                    MERGE (d)-[:HAS_SUBDOMAIN]->(s)
                                    """,
                                    domain=attach_org(root_for_host(hostname, roots)), sub=hostname,
                                    uid=user_id, pid=project_id,
                                )
                                # MERGE IP nodes + RESOLVES_TO relationships
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
                                            MERGE (s)-[r:RESOLVES_TO]->(i)
                                            SET r.record_type = coalesce(r.record_type, $rtype)
                                            """,
                                            sub=hostname, addr=ip_addr, uid=user_id, pid=project_id, rtype=record_type,
                                        )
                                print(f"[+][Partial Recon] Created graph nodes for {hostname}")
                    else:
                        print("[!][Partial Recon] Neo4j not reachable, skipping subdomain node creation")
            except Exception as e:
                print(f"[!][Partial Recon] Failed to create subdomain nodes: {e}")

    # STEP 2: Inject user-provided IPs/CIDRs into recon_data (AFTER hostname resolution)
    # If ip_attach_to is set, inject into that subdomain's entry; otherwise into domain IPs
    # Safety: if ip_attach_to points to a subdomain that failed resolution, fall back to generic
    if ip_attach_to and ip_attach_to not in recon_data["dns"]["subdomains"]:
        # Check if the subdomain exists in Neo4j graph already
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
            needs_user_input = bool(user_ips)

    user_ip_addrs = []
    if user_ips:
        if ip_attach_to:
            # Ensure the target subdomain entry exists (may have been created by hostname resolution above)
            if ip_attach_to not in recon_data["dns"]["subdomains"]:
                recon_data["dns"]["subdomains"][ip_attach_to] = {
                    "ips": {"ipv4": [], "ipv6": []},
                    "has_records": True,
                }
            target_ips = recon_data["dns"]["subdomains"][ip_attach_to]["ips"]
            print(f"[*][Partial Recon] Adding {len(user_ips)} user-provided IPs/CIDRs -> {ip_attach_to}")
        else:
            target_ips = recon_data["dns"]["domain"]["ips"]
            print(f"[*][Partial Recon] Adding {len(user_ips)} user-provided IPs/CIDRs -> domain (generic)")

        for ip_str in user_ips:
            if "/" in ip_str:
                try:
                    network = _ipaddress.ip_network(ip_str, strict=False)
                    if network.num_addresses > 256:
                        print(f"[!][Partial Recon] CIDR {ip_str} too large ({network.num_addresses} hosts), max /24 (256). Skipping.")
                        continue
                    for host_ip in network.hosts():
                        addr = str(host_ip)
                        bucket = _classify_ip(addr)
                        if addr not in target_ips[bucket]:
                            target_ips[bucket].append(addr)
                        user_ip_addrs.append(addr)
                    if not ip_attach_to:
                        recon_data["dns"]["domain"]["has_records"] = True
                except ValueError:
                    print(f"[!][Partial Recon] Invalid CIDR: {ip_str}")
            else:
                bucket = _classify_ip(ip_str)
                if ip_str not in target_ips[bucket]:
                    target_ips[bucket].append(ip_str)
                    if not ip_attach_to:
                        recon_data["dns"]["domain"]["has_records"] = True
                user_ip_addrs.append(ip_str)

    # Check we have targets
    domain_ips = recon_data["dns"]["domain"]["ips"]
    sub_count = len(recon_data["dns"]["subdomains"])
    ip_count = len(domain_ips["ipv4"]) + len(domain_ips["ipv6"])
    for sub_data in recon_data["dns"]["subdomains"].values():
        ip_count += len(sub_data["ips"]["ipv4"]) + len(sub_data["ips"]["ipv6"])

    if ip_count == 0:
        print("[!][Partial Recon] No scannable targets found (graph is empty and no valid user targets resolved).")
        print("[!][Partial Recon] Run Subdomain Discovery first, or provide IPs/subdomains manually.")
        sys.exit(1)

    print(f"[+][Partial Recon] Found {ip_count} IPs across {sub_count} subdomains + domain")

    # Run scan (same function as full pipeline)
    print(f"[*][Partial Recon] Running {label} port scan...")
    result = scan_fn(recon_data, output_file=None, settings=settings)

    # Normalize scan results if needed (e.g. masscan_scan -> port_scan)
    if normalize_fn:
        normalize_fn(result)

    # Update the graph database
    print(f"[*][Partial Recon] Updating graph database...")
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                stats = graph_client.update_graph_from_port_scan(
                    recon_data=result,
                    user_id=user_id,
                    project_id=project_id,
                )

                # Link user-provided IPs to graph
                if user_ip_addrs:
                    driver = graph_client.driver
                    with driver.session() as session:
                        if ip_attach_to and not user_input_id:
                            # IPs attached to a subdomain: create RESOLVES_TO relationships
                            for ip_addr in user_ip_addrs:
                                ip_version = _classify_ip(ip_addr)
                                record_type = "A" if ip_version == "ipv4" else "AAAA"
                                session.run(
                                    """
                                    MERGE (i:IP {address: $addr, user_id: $uid, project_id: $pid})
                                    SET i.version = $version, i.updated_at = datetime()
                                    WITH i
                                    MATCH (s:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                                    MERGE (s)-[r:RESOLVES_TO]->(i)
                                    SET r.record_type = coalesce(r.record_type, $rtype)
                                    """,
                                    addr=ip_addr, uid=user_id, pid=project_id,
                                    version=ip_version, sub=ip_attach_to, rtype=record_type,
                                )
                            print(f"[+][Partial Recon] Linked {len(user_ip_addrs)} IPs to {ip_attach_to} via RESOLVES_TO")
                        elif needs_user_input:
                            # Generic IPs: create UserInput node NOW (after scan succeeded) and link
                            user_input_id = str(uuid.uuid4())
                            graph_client.create_user_input_node(
                                domain=roots,
                                user_input_data={
                                    "id": user_input_id,
                                    "input_type": "ips",
                                    "values": user_ips,
                                    "tool_id": tool_id,
                                },
                                user_id=user_id,
                                project_id=project_id,
                                root_orgs=root_orgs(roots),
                            )
                            for ip_addr in user_ip_addrs:
                                session.run(
                                    """
                                    MATCH (ui:UserInput {id: $ui_id, user_id: $uid, project_id: $pid})
                                    MATCH (i:IP {address: $addr, user_id: $uid, project_id: $pid})
                                    MERGE (ui)-[:PRODUCED]->(i)
                                    """,
                                    ui_id=user_input_id, addr=ip_addr, uid=user_id, pid=project_id,
                                )
                            graph_client.update_user_input_status(
                                user_input_id, "completed", stats
                            )
                            print(f"[+][Partial Recon] Created UserInput + linked {len(user_ip_addrs)} IPs via PRODUCED")

                print(f"[+][Partial Recon] Graph updated successfully")
                print(f"[+][Partial Recon] Stats: {json.dumps(stats, default=str)}")
            else:
                print("[!][Partial Recon] Neo4j not reachable, graph not updated")
    except Exception as e:
        print(f"[!][Partial Recon] Graph update failed: {e}")
        raise

    print(f"\n[+][Partial Recon] {label} port scanning completed successfully")


def _normalize_masscan_result(result: dict) -> None:
    """Copy masscan_scan data into port_scan key for update_graph_from_port_scan()."""
    masscan_data = result.get("masscan_scan", {})
    if masscan_data:
        result["port_scan"] = {
            "scan_metadata": masscan_data.get("scan_metadata", {}),
            "by_host": dict(masscan_data.get("by_host", {})),
            "by_ip": dict(masscan_data.get("by_ip", {})),
            "all_ports": list(masscan_data.get("all_ports", [])),
            "ip_to_hostnames": dict(masscan_data.get("ip_to_hostnames", {})),
            "summary": dict(masscan_data.get("summary", {})),
        }


def run_naabu(config: dict) -> None:
    """Run partial port scanning using Naabu (run_port_scan from port_scan.py)."""
    from recon.main_recon_modules.port_scan import run_port_scan
    _run_port_scanner(config, tool_id="Naabu", scan_fn=run_port_scan, label="Naabu")


def run_masscan(config: dict) -> None:
    """Run partial port scanning using Masscan (run_masscan_scan from masscan_scan.py)."""
    from recon.main_recon_modules.masscan_scan import run_masscan_scan
    _run_port_scanner(
        config, tool_id="Masscan", scan_fn=run_masscan_scan, label="Masscan",
        pre_settings={"MASSCAN_ENABLED": True},
        normalize_fn=_normalize_masscan_result,
    )


def _norm_ip(ip) -> str:
    import ipaddress as _ipaddress
    text = str(ip or "").strip()
    try:
        return str(_ipaddress.ip_address(text))
    except ValueError:
        return text.lower()


def _drop_ports_nmap_found_closed(recon_data: dict, injected: dict) -> int:
    """Remove the custom ports nmap scanned on an IP and did not find open.

    `injected` maps a by_host key to the custom ports this run added to it;
    ports the graph already had are never touched. When nmap did not run, or
    gave up on that IP (its `unreachable_hosts`), the operator's explicit input
    is all there is, so those ports stay. by_ip is left as it is: the port_scan
    writer reads it only to decide whether to write the IP node.

    Returns how many (IP, port) pairs were removed.
    """
    nmap_data = recon_data.get("nmap_scan")
    if not isinstance(nmap_data, dict):
        return 0
    gave_up = {_norm_ip(ip) for ip in nmap_data.get("unreachable_hosts", [])}
    open_on: dict = {}
    for entry in (nmap_data.get("by_host") or {}).values():
        ip = _norm_ip(entry.get("ip"))
        for pd in entry.get("port_details", []):
            if pd.get("state", "open") == "open":
                open_on.setdefault(ip, set()).add(pd.get("port"))

    dropped = set()
    by_host = recon_data.get("port_scan", {}).get("by_host", {})
    for host, ports in injected.items():
        entry = by_host.get(host)
        ip = _norm_ip((entry or {}).get("ip"))
        if not entry or not ip or ip in gave_up:
            continue
        closed = {p for p in ports if p not in open_on.get(ip, set())}
        if not closed:
            continue
        entry["ports"] = [p for p in entry.get("ports", []) if p not in closed]
        entry["port_details"] = [pd for pd in entry.get("port_details", [])
                                 if pd.get("port") not in closed]
        dropped.update((ip, p) for p in closed)
    return len(dropped)


def measured_port_data(recon_data: dict, measured: dict) -> dict:
    """recon_data for update_graph_from_port_scan, its by_host cut to what was measured.

    D5: a partial run writes only what its tool measured. by_host was rebuilt
    from the graph, and writing it back would mark every port open and
    actively found again, Shodan-only ones included. `measured` maps a by_host
    key to the ports this run's tool saw there; every other port is left out.
    by_ip stays whole: the writer reads it for the IP node alone (typed
    addresses need theirs) and never lowers is_cdn.
    """
    port_scan = recon_data.get("port_scan") or {}
    by_host = {}
    for host, entry in (port_scan.get("by_host") or {}).items():
        ports = measured.get(host)
        if not ports or not isinstance(entry, dict):
            continue
        details = [pd for pd in entry.get("port_details") or [] if pd.get("port") in ports]
        if details:
            by_host[host] = {**entry, "ports": sorted({pd["port"] for pd in details}),
                             "port_details": details}
    return {**recon_data, "port_scan": {**port_scan, "by_host": by_host}}


def run_nmap(config: dict) -> None:
    """
    Run partial Nmap service detection + NSE vulnerability scanning
    using the exact same function as the full pipeline in nmap_scan.py.

    Nmap runs on IPs+Ports already in the graph (from prior port scanning).
    It enriches existing Port nodes with product/version/CPE and creates
    Technology, Vulnerability, and CVE nodes from NSE script findings.
    """
    import ipaddress as _ipaddress
    from recon.main_recon_modules.nmap_scan import run_nmap_scan
    from recon.helpers.nmap_merge import merge_nmap_into_port_scan

    roots = scope_roots(config)
    user_inputs = config.get("user_inputs", [])

    user_id = os.environ.get("USER_ID", "")
    project_id = os.environ.get("PROJECT_ID", "")

    print(f"[*][Partial Recon] Loading project settings...")
    settings = partial_settings(config)

    # Force-enable Nmap since the user explicitly chose to run it
    settings['NMAP_ENABLED'] = True

    print(f"\n{'=' * 50}")
    print(f"[*][Partial Recon] Nmap Service Detection + NSE Vuln Scripts")
    print(f"[*][Partial Recon] Roots: {', '.join(roots)}")
    print(f"{'=' * 50}\n")

    # Parse user targets -- Nmap accepts IPs and Ports
    user_targets = config.get("user_targets") or {}
    user_ips = []           # validated IPs and CIDRs
    user_ports = []         # validated port numbers
    ip_attach_to = None     # subdomain to attach IPs to (None = UserInput)
    user_input_id = None    # only created when IPs are generic (no subdomain attachment)

    if user_targets:
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

        ip_attach_to = user_targets.get("ip_attach_to")  # subdomain name or None

    elif user_inputs:
        # Legacy flat list fallback: only accept IPs
        for entry in user_inputs:
            entry = entry.strip()
            if not entry:
                continue
            if _is_ip_or_cidr(entry):
                user_ips.append(entry)
            else:
                print(f"[!][Partial Recon] Skipping non-IP target (Nmap only accepts IPs): {entry}")

    if user_ips:
        print(f"[+][Partial Recon] Validated {len(user_ips)} custom IPs/CIDRs")
        if ip_attach_to:
            print(f"[+][Partial Recon] IPs will be attached to subdomain: {ip_attach_to}")
        else:
            print(f"[+][Partial Recon] IPs will be tracked via UserInput (generic)")
    if user_ports:
        print(f"[+][Partial Recon] Validated {len(user_ports)} custom ports: {user_ports}")

    # Track whether we need a UserInput node (created after scan succeeds, not before)
    needs_user_input = bool(user_ips and not ip_attach_to)

    # Build recon_data from Neo4j graph (or start empty if user unchecked graph targets)
    include_graph = config.get("include_graph_targets", True)
    if include_graph:
        print(f"[*][Partial Recon] Querying graph for targets (IPs, ports, subdomains)...")
        recon_data = _build_port_scan_data_from_graph(
            roots, user_id, project_id,
            include_root_domain=_should_include_root_domain(settings),
            domain_groups=config.get("domain_groups"),
        )
    else:
        print(f"[*][Partial Recon] Skipping graph targets (user opted out)")
        recon_data = {
            "domain": roots[0] if roots else "",
            "domains": roots,
            "port_scan": {
                "by_ip": {}, "by_host": {}, "ip_to_hostnames": {},
                "all_ports": [], "scan_metadata": {"scanners": ["naabu"]}, "summary": {},
            },
            "dns": {
                "domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
                "subdomains": {},
            },
        }

    # Inject user-provided IPs/CIDRs into port_scan structure
    # Safety: if ip_attach_to points to a subdomain that failed resolution, fall back to generic
    if ip_attach_to and ip_attach_to not in recon_data["dns"]["subdomains"]:
        # Check if the subdomain exists in Neo4j graph already
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
            needs_user_input = bool(user_ips)

    user_ip_addrs = []  # flat list of individual IPs from user (after CIDR expansion)
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

        # Also populate dns section for user IPs (needed for post-scan IP linking)
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

    # Inject user-provided ports into port_scan (global -- applies to all IPs)
    injected_ports = {}  # by_host key -> the custom ports added to it, not already in the graph
    if user_ports:
        for port in user_ports:
            if port not in recon_data["port_scan"]["all_ports"]:
                recon_data["port_scan"]["all_ports"].append(port)
            # Add to each IP's port list so build_nmap_targets picks them up
            for ip_data in recon_data["port_scan"]["by_ip"].values():
                if port not in ip_data["ports"]:
                    ip_data["ports"].append(port)
                    ip_data["port_details"].append({
                        "port": port, "protocol": "tcp", "service": "",
                    })
            for host, host_data in recon_data["port_scan"]["by_host"].items():
                if port not in host_data["ports"]:
                    host_data["ports"].append(port)
                    host_data["port_details"].append({
                        "port": port, "protocol": "tcp", "service": "",
                    })
                    injected_ports.setdefault(host, set()).add(port)
        recon_data["port_scan"]["all_ports"].sort()
        print(f"[+][Partial Recon] Injected {len(user_ports)} custom ports into scan targets")

    # Check we have scannable targets
    port_count = len(recon_data["port_scan"]["all_ports"])
    ip_count = len(recon_data["port_scan"]["by_ip"])

    if ip_count == 0:
        print("[!][Partial Recon] No scannable targets found (graph is empty and no valid user targets provided).")
        print("[!][Partial Recon] Run Subdomain Discovery + Naabu first, or provide IPs manually.")
        sys.exit(1)

    if port_count == 0:
        print("[!][Partial Recon] No ports to scan. Provide custom ports or run Naabu first to discover open ports.")
        sys.exit(1)

    print(f"[+][Partial Recon] Found {ip_count} IPs with {port_count} unique ports to scan")

    # Run Nmap scan (same function as full pipeline)
    print(f"[*][Partial Recon] Running Nmap service detection + NSE vuln scripts...")
    result = run_nmap_scan(recon_data, output_file=None, settings=settings)

    dropped = _drop_ports_nmap_found_closed(result, injected_ports)
    if dropped:
        print(f"[*][Partial Recon] {dropped} custom IP:port pair(s) nmap found closed or "
              f"filtered are not written as open ports")

    # Merge Nmap service versions into port_scan.port_details
    if "nmap_scan" in result:
        merge_nmap_into_port_scan(result)
        print(f"[+][Partial Recon] Merged Nmap results into port_scan data")
    else:
        print("[!][Partial Recon] Nmap scan produced no results (nmap_scan key missing)")

    # Update the graph database
    print(f"[*][Partial Recon] Updating graph database...")
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if graph_client.verify_connection():
                stats = {}

                # If user provided custom ports, create Port nodes first
                # (update_graph_from_nmap only enriches Port nodes that exist, and
                # a custom port is not one of the new ports it creates itself).
                # Only the custom ports still there after the closed ones were
                # dropped: the graph's own ports are not this run's measurement.
                if user_ports and "port_scan" in result:
                    ps_stats = graph_client.update_graph_from_port_scan(
                        recon_data=measured_port_data(result, injected_ports),
                        user_id=user_id,
                        project_id=project_id,
                    )
                    print(f"[+][Partial Recon] Created Port nodes for custom ports: {json.dumps(ps_stats, default=str)}")

                if "nmap_scan" in result:
                    stats = graph_client.update_graph_from_nmap(
                        recon_data=result,
                        user_id=user_id,
                        project_id=project_id,
                    )

                # Link user-provided IPs to graph
                if user_ip_addrs:
                    driver = graph_client.driver
                    with driver.session() as session:
                        if ip_attach_to and not user_input_id:
                            # IPs attached to a subdomain: create RESOLVES_TO relationships
                            for ip_addr in user_ip_addrs:
                                ip_version = _classify_ip(ip_addr)
                                record_type = "A" if ip_version == "ipv4" else "AAAA"
                                session.run(
                                    """
                                    MERGE (i:IP {address: $addr, user_id: $uid, project_id: $pid})
                                    SET i.version = $version, i.updated_at = datetime()
                                    WITH i
                                    MATCH (s:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                                    MERGE (s)-[r:RESOLVES_TO]->(i)
                                    SET r.record_type = coalesce(r.record_type, $rtype)
                                    """,
                                    addr=ip_addr, uid=user_id, pid=project_id,
                                    version=ip_version, sub=ip_attach_to, rtype=record_type,
                                )
                            print(f"[+][Partial Recon] Linked {len(user_ip_addrs)} IPs to {ip_attach_to} via RESOLVES_TO")
                        elif needs_user_input:
                            # Generic IPs: create UserInput NOW (after scan succeeded) and link
                            user_input_id = str(uuid.uuid4())
                            graph_client.create_user_input_node(
                                domain=roots,
                                user_input_data={
                                    "id": user_input_id,
                                    "input_type": "ips",
                                    "values": user_ips,
                                    "tool_id": "Nmap",
                                },
                                user_id=user_id,
                                project_id=project_id,
                                root_orgs=root_orgs(roots),
                            )
                            for ip_addr in user_ip_addrs:
                                session.run(
                                    """
                                    MATCH (ui:UserInput {id: $ui_id, user_id: $uid, project_id: $pid})
                                    MATCH (i:IP {address: $addr, user_id: $uid, project_id: $pid})
                                    MERGE (ui)-[:PRODUCED]->(i)
                                    """,
                                    ui_id=user_input_id, addr=ip_addr, uid=user_id, pid=project_id,
                                )
                            graph_client.update_user_input_status(
                                user_input_id, "completed", stats
                            )
                            print(f"[+][Partial Recon] Created UserInput + linked {len(user_ip_addrs)} IPs via PRODUCED")

                print(f"[+][Partial Recon] Graph updated successfully")
                print(f"[+][Partial Recon] Stats: {json.dumps(stats, default=str)}")
            else:
                print("[!][Partial Recon] Neo4j not reachable, graph not updated")
    except Exception as e:
        print(f"[!][Partial Recon] Graph update failed: {e}")
        raise

    print(f"\n[+][Partial Recon] Nmap service detection completed successfully")
