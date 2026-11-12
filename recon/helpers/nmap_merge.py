"""
Merge Nmap's service detection into the port scan's result.

Extracted from recon.main so partial recon (partial_recon_modules/
port_scanning.py) can use it without importing recon.main, which would
re-run the pipeline's top level as a second module. recon.main re-exports
these names.
"""


def _apply_nmap_detail(ps_pd: dict, nmap_pd: dict) -> None:
    if nmap_pd.get("product"):
        ps_pd["product"] = nmap_pd["product"]
    if nmap_pd.get("version"):
        ps_pd["version"] = nmap_pd["version"]
    if nmap_pd.get("cpe"):
        ps_pd["cpe"] = nmap_pd["cpe"]
    if nmap_pd.get("scripts"):
        ps_pd["scripts"] = nmap_pd["scripts"]


def _names_its_ips(entry: dict) -> bool:
    """True when the entry's port details name the address each is on."""
    return any(isinstance(d, dict) and d.get("ip") for d in entry.get("port_details") or [])


def _ports_by_address(entry: dict, normalize_ip) -> dict:
    """{address: ports} of one by_host entry.

    A domain run's name on several addresses holds every address's ports, each
    detail naming its own; an entry whose details name none (IP mode, keyed by
    address) has all its ports on its `ip`.
    """
    own = normalize_ip(entry["ip"])
    if not _names_its_ips(entry):
        return {own: set(entry.get("ports") or [])}
    out: dict = {own: set()}
    for detail in entry.get("port_details") or []:
        if isinstance(detail, dict):
            out.setdefault(normalize_ip(detail.get("ip")) or own, set()).add(detail.get("port"))
    return out


def _add_nmap_confirmed_ports(nmap_data: dict, port_scan: dict) -> list:
    """Add the open ports nmap confirmed that the port scan did not report.

    nmap probes every IP with the union of all IPs' ports, so it can confirm a
    port naabu/masscan missed on one of them. Each one joins by_ip, every
    by_host entry on that IP, all_ports and the summary counts in naabu's
    shape, and is returned for the graph writer, which creates its Port node.
    A port is known per address: one a name lists for its other address is
    still new here. A CDN edge is skipped: NAABU_EXCLUDE_CDN limits those to
    80/443 on purpose, and an edge's other ports belong to the CDN, not to the
    target.
    """
    from recon.main_recon_modules.nmap_scan import normalize_ip

    by_ip = port_scan.get("by_ip") or {}
    by_host = port_scan.get("by_host") or {}
    ip_keys = {normalize_ip(ip): ip for ip in by_ip}
    hosts_on: dict = {}
    known_on: dict = {}
    for entry in by_host.values():
        if isinstance(entry, dict) and entry.get("ip"):
            for address, ports in _ports_by_address(entry, normalize_ip).items():
                hosts_on.setdefault(address, []).append(entry)
                known_on.setdefault(address, set()).update(ports)

    added = []
    for nmap_host in (nmap_data.get("by_host") or {}).values():
        ip = normalize_ip(nmap_host.get("ip"))
        if not ip:
            continue
        ip_entry = by_ip.get(ip_keys.get(ip))
        if not isinstance(ip_entry, dict):
            ip_entry = None
        if ip_entry is not None and ip_entry.get("is_cdn"):
            continue
        entries = hosts_on.get(ip, [])
        known = set((ip_entry or {}).get("ports") or []) | known_on.get(ip, set())
        address = ip_keys.get(ip) or nmap_host.get("ip")

        for nmap_pd in nmap_host.get("port_details", []):
            port = nmap_pd.get("port")
            if not port or port in known or nmap_pd.get("state", "open") != "open":
                continue
            known.add(port)
            protocol = nmap_pd.get("protocol") or "tcp"
            service = nmap_pd.get("service") or ""
            if ip_entry is not None:
                ip_entry.setdefault("ports", []).append(port)
                ip_entry["ports"].sort()
                if isinstance(ip_entry.get("port_details"), list):
                    ip_entry["port_details"].append(
                        {"port": port, "protocol": protocol, "service": service})
            for entry in entries:
                ports = entry.setdefault("ports", [])
                if port not in ports:
                    ports.append(port)
                    ports.sort()
                detail = {"port": port, "protocol": protocol, "service": service}
                _apply_nmap_detail(detail, nmap_pd)
                if _names_its_ips(entry):
                    detail["ip"] = address
                entry.setdefault("port_details", []).append(detail)
                entry["port_details"].sort(key=lambda x: x["port"])
            added.append({"ip": address, "port": port,
                          "protocol": protocol, "service": service})

    if added:
        all_ports = sorted(set(port_scan.get("all_ports") or []) | {a["port"] for a in added})
        port_scan["all_ports"] = all_ports
        summary = port_scan.get("summary")
        if isinstance(summary, dict):
            if "total_open_ports" in summary:
                summary["total_open_ports"] = sum(len(h.get("ports", [])) for h in by_host.values())
            if "hosts_with_open_ports" in summary:
                summary["hosts_with_open_ports"] = len([h for h in by_host.values() if h.get("ports")])
            if "unique_ports" in summary:
                summary["unique_ports"] = all_ports
            if "unique_port_count" in summary:
                summary["unique_port_count"] = len(all_ports)
    return added


def merge_nmap_into_port_scan(combined_result: dict) -> None:
    """
    Merge Nmap service version data into port_scan.port_details.

    Enriches existing port_details entries (from Naabu/Masscan) with Nmap's
    product, version, CPE, and NSE script results, and adds the open ports nmap
    confirmed that the port scan missed (listed in nmap_scan.new_open_ports).
    """
    from recon.main_recon_modules.nmap_scan import normalize_ip

    nmap_data = combined_result.get("nmap_scan", {})
    port_scan = combined_result.get("port_scan", {})
    if not nmap_data or not port_scan:
        return

    enriched_count = 0

    for host, nmap_host in nmap_data.get("by_host", {}).items():
        ps_host = port_scan.get("by_host", {}).get(host)
        if not ps_host:
            continue
        # A hostname can front several IPs; never copy one IP's versions onto another's ports.
        if (ps_host.get("ip") and nmap_host.get("ip")
                and normalize_ip(ps_host["ip"]) != normalize_ip(nmap_host["ip"])):
            continue
        nmap_ip = normalize_ip(nmap_host.get("ip"))
        for nmap_pd in nmap_host.get("port_details", []):
            for ps_pd in ps_host.get("port_details", []):
                if ps_pd.get("port") != nmap_pd.get("port"):
                    continue
                # The same port on the name's other address is that address's.
                if ps_pd.get("ip") and nmap_ip and normalize_ip(ps_pd["ip"]) != nmap_ip:
                    continue
                _apply_nmap_detail(ps_pd, nmap_pd)
                enriched_count += 1
                break

    added = _add_nmap_confirmed_ports(nmap_data, port_scan)
    if added:
        nmap_data["new_open_ports"] = added
        print(f"[+][Nmap] Added {len(added)} open port(s) the port scan did not report")

    # Update scan_metadata to include nmap
    scanners = port_scan.get("scan_metadata", {}).get("scanners", [])
    if "nmap" not in scanners:
        scanners.append("nmap")
        port_scan.get("scan_metadata", {})["scanners"] = scanners

    if enriched_count:
        print(f"[+][Nmap] Enriched {enriched_count} port(s) with service version data")
