"""
RedAmon - Nmap Scanner Module

Service version detection and NSE vulnerability scanning for discovered ports.
Runs AFTER the port_scan merge step, targeting only ports already found open
by Naabu/Masscan.

Features:
- Service version detection (-sV)
- NSE vulnerability script scanning (--script vuln)
- XML output for reliable structured parsing
- Extracts CVEs from NSE script output
- Normalized output with by_host, services_detected, nse_vulns
"""

import json
import re
import subprocess
import shutil
import uuid
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set, Tuple
import sys

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# =============================================================================
# Prerequisites
# =============================================================================

def is_nmap_installed() -> bool:
    """Check if nmap binary is available."""
    return shutil.which("nmap") is not None


# =============================================================================
# Target Preparation
# =============================================================================

def build_nmap_targets(recon_data: dict, settings: dict) -> Tuple[List[str], str, Dict[str, List[str]]]:
    """
    Extract IPs and discovered ports from recon_data['port_scan'].

    Nmap runs after port_scan merge, so it reads the merged port_scan results
    to determine which IPs and ports to probe for version/vuln info.

    Args:
        recon_data: Pipeline data containing port_scan results
        settings: Settings dictionary

    Returns:
        Tuple of (ip_list, port_string, ip_to_hostnames)
        where port_string is '21,22,80,3306,...'
    """
    port_scan = recon_data.get("port_scan", {})
    by_ip = port_scan.get("by_ip", {})
    by_host = port_scan.get("by_host", {})

    unique_ips: Set[str] = set()
    all_ports: Set[int] = set()
    ip_to_hostnames: Dict[str, List[str]] = {}

    # Collect from by_ip
    for ip, ip_data in by_ip.items():
        unique_ips.add(ip)
        for port in ip_data.get("ports", []):
            all_ports.add(int(port))
        hostnames = ip_data.get("hostnames", [])
        if hostnames:
            ip_to_hostnames.setdefault(ip, [])
            for h in hostnames:
                if h not in ip_to_hostnames[ip]:
                    ip_to_hostnames[ip].append(h)

    # Also collect from by_host to catch any hostname->IP mappings
    for hostname, host_data in by_host.items():
        ip = host_data.get("ip", "")
        if ip:
            unique_ips.add(ip)
            for port in host_data.get("ports", []):
                all_ports.add(int(port))
            ip_to_hostnames.setdefault(ip, [])
            if hostname not in ip_to_hostnames[ip]:
                ip_to_hostnames[ip].append(hostname)

    # Also pull from ip_to_hostnames stored in port_scan itself
    stored_map = port_scan.get("ip_to_hostnames", {})
    for ip, hostnames in stored_map.items():
        if ip in unique_ips:
            ip_to_hostnames.setdefault(ip, [])
            if isinstance(hostnames, list):
                for h in hostnames:
                    if h not in ip_to_hostnames[ip]:
                        ip_to_hostnames[ip].append(h)
            elif isinstance(hostnames, str) and hostnames not in ip_to_hostnames[ip]:
                ip_to_hostnames[ip].append(hostnames)

    ip_list = sorted(unique_ips)
    port_string = ",".join(str(p) for p in sorted(all_ports))

    return ip_list, port_string, ip_to_hostnames


# =============================================================================
# Command Builder
# =============================================================================

def build_nmap_command(target_ip: str, ports: str, output_file: str, settings: dict) -> List[str]:
    """
    Build nmap CLI command for a single target IP.

    Args:
        target_ip: IP address to scan
        ports: Comma-separated port list (e.g. '21,22,80,3306')
        output_file: Path for XML output (-oX)
        settings: Settings dictionary

    Returns:
        List of command arguments
    """
    VERSION_DETECTION = settings.get('NMAP_VERSION_DETECTION', True)
    SCRIPT_SCAN = settings.get('NMAP_SCRIPT_SCAN', True)
    TIMING = settings.get('NMAP_TIMING_TEMPLATE', 'T3')
    HOST_TIMEOUT = settings.get('NMAP_HOST_TIMEOUT', 300)

    cmd = ["nmap"]

    # Service version detection
    if VERSION_DETECTION:
        cmd.append("-sV")

    # NSE vulnerability scripts
    if SCRIPT_SCAN:
        cmd.extend(["--script", "vuln"])

    # XML output
    cmd.extend(["-oX", output_file])

    # Ports
    if ports:
        cmd.extend(["-p", ports])

    # Timing template
    timing = str(TIMING).strip()
    if not timing.startswith("-"):
        if not timing.startswith("T"):
            timing = f"-T{timing}"
        else:
            timing = f"-{timing}"
    cmd.append(timing)

    # Per-host timeout (ensure 's' suffix for seconds if value is numeric)
    if HOST_TIMEOUT:
        timeout_str = str(HOST_TIMEOUT)
        if timeout_str.isdigit():
            timeout_str = f"{timeout_str}s"
        cmd.extend(["--host-timeout", timeout_str])

    # Target IP
    cmd.append(target_ip)

    return cmd


# =============================================================================
# XML Parsing
# =============================================================================

def parse_nmap_xml(xml_path: str, ip_to_hostnames: Dict[str, List[str]]) -> Dict:
    """
    Parse Nmap XML output using xml.etree.ElementTree.

    Extracts host IP, port number, protocol, state, service product/version/cpe,
    and NSE script results including CVE extraction.

    Args:
        xml_path: Path to Nmap XML output file
        ip_to_hostnames: Mapping of IP -> list of hostnames

    Returns:
        Dict with by_host, services_detected, nse_vulns, nmap_version
    """
    by_host: Dict = {}
    services_detected: List[Dict] = []
    nse_vulns: List[Dict] = []
    nmap_version = ""

    if not Path(xml_path).exists():
        return {
            "by_host": {},
            "services_detected": [],
            "nse_vulns": [],
            "nmap_version": "",
        }

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"[!][Nmap] Failed to parse XML: {e}")
        return {
            "by_host": {},
            "services_detected": [],
            "nse_vulns": [],
            "nmap_version": "",
        }

    # Extract nmap version from root attributes
    nmap_version = root.attrib.get("scanner", "nmap")
    nmap_version = root.attrib.get("version", nmap_version)

    # Process each host
    for host_elem in root.findall("host"):
        # Get IP address
        ip = ""
        for addr in host_elem.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr", "")
                break
        if not ip:
            # Try ipv6 as fallback
            for addr in host_elem.findall("address"):
                if addr.get("addrtype") == "ipv6":
                    ip = addr.get("addr", "")
                    break
        if not ip:
            continue

        # Determine hostname(s) for this IP
        hostnames = ip_to_hostnames.get(ip, [ip])
        primary_hostname = hostnames[0] if hostnames else ip

        ports_list: List[int] = []
        port_details: List[Dict] = []

        # Process ports
        ports_elem = host_elem.find("ports")
        if ports_elem is None:
            continue

        for port_elem in ports_elem.findall("port"):
            protocol = port_elem.get("protocol", "tcp")
            port_num = int(port_elem.get("portid", "0"))

            # Check state -- skip non-open ports
            state_elem = port_elem.find("state")
            state = state_elem.get("state", "") if state_elem is not None else ""
            if state != "open":
                continue

            # Service info
            service_elem = port_elem.find("service")
            service_name = ""
            product = ""
            version = ""
            extrainfo = ""
            cpe = ""

            if service_elem is not None:
                service_name = service_elem.get("name", "")
                product = service_elem.get("product", "")
                version = service_elem.get("version", "")
                extrainfo = service_elem.get("extrainfo", "")
                cpe_elem = service_elem.find("cpe")
                if cpe_elem is not None and cpe_elem.text:
                    cpe = cpe_elem.text

            ports_list.append(port_num)

            port_detail = {
                "port": port_num,
                "protocol": protocol,
                "state": state,
                "service": service_name,
                "product": product,
                "version": version,
                "extrainfo": extrainfo,
                "cpe": cpe,
                "scripts": {},
            }

            # Track service detection
            if product:
                services_detected.append({
                    "product": product,
                    "version": version,
                    "port": port_num,
                    "host": primary_hostname,
                    "cpe": cpe,
                })

            # Process NSE scripts
            for script_elem in port_elem.findall("script"):
                script_id = script_elem.get("id", "")
                script_output = script_elem.get("output", "")

                if script_id:
                    port_detail["scripts"][script_id] = script_output

                    # Extract vulnerability info from NSE output
                    vuln_state = ""
                    output_upper = script_output.upper()
                    if "NOT VULNERABLE" in output_upper:
                        continue  # skip non-vulnerable findings
                    elif "LIKELY VULNERABLE" in output_upper:
                        vuln_state = "LIKELY VULNERABLE"
                    elif "VULNERABLE" in output_upper:
                        vuln_state = "VULNERABLE"

                    if vuln_state:
                        # Extract CVE IDs
                        cves = re.findall(r'CVE-\d{4}-\d+', script_output)
                        cve_str = cves[0] if cves else ""

                        nse_vulns.append({
                            "host": ip,
                            "port": port_num,
                            "script_id": script_id,
                            "state": vuln_state,
                            "output": script_output.strip(),
                            "cve": cve_str,
                        })

            port_details.append(port_detail)

        # Sort ports
        ports_list.sort()
        port_details.sort(key=lambda x: x["port"])

        # Store under primary hostname
        by_host[primary_hostname] = {
            "host": primary_hostname,
            "ip": ip,
            "ports": ports_list,
            "port_details": port_details,
        }

    return {
        "by_host": by_host,
        "services_detected": services_detected,
        "nse_vulns": nse_vulns,
        "nmap_version": nmap_version,
    }


# =============================================================================
# Main Scan Function
# =============================================================================

def run_nmap_scan(recon_data: dict, output_file: Path = None, settings: dict = None) -> dict:
    """
    Run Nmap scan on targets from port_scan merge results.

    Nmap runs after port discovery, targeting only IPs and ports already found
    open by Naabu/Masscan. This provides service version detection and NSE
    vulnerability scanning on known-open ports.

    Args:
        recon_data: Dictionary containing port_scan results
        output_file: Path to save enriched results (optional)
        settings: Settings dictionary from main.py

    Returns:
        Enriched recon_data with "nmap_scan" section added
    """
    print("\n" + "=" * 60)
    print("[*][Nmap] SERVICE & VULNERABILITY SCANNER")
    print("=" * 60)

    if settings is None:
        settings = {}

    if not settings.get('NMAP_ENABLED', True):
        print("[-][Nmap] Disabled -- skipping")
        return recon_data

    NMAP_VERSION_DETECTION = settings.get('NMAP_VERSION_DETECTION', True)
    NMAP_SCRIPT_SCAN = settings.get('NMAP_SCRIPT_SCAN', True)
    NMAP_TIMING = settings.get('NMAP_TIMING_TEMPLATE', 'T3')
    NMAP_TIMEOUT = settings.get('NMAP_TIMEOUT', 600)
    NMAP_HOST_TIMEOUT = settings.get('NMAP_HOST_TIMEOUT', 300)

    if not is_nmap_installed():
        print("[!][Nmap] Binary not found. Ensure nmap is installed.")
        return recon_data

    # Check that port_scan data exists
    port_scan = recon_data.get("port_scan", {})
    if not port_scan or not port_scan.get("by_ip"):
        print("[!][Nmap] No port_scan data found -- run port scanners first")
        return recon_data

    # Extract targets from port_scan
    print("[*][Nmap] Extracting targets from port_scan results...")
    ip_list, port_string, ip_to_hostnames = build_nmap_targets(recon_data, settings)

    if not ip_list:
        print("[!][Nmap] No IP targets found in port_scan data")
        return recon_data

    if not port_string:
        print("[!][Nmap] No open ports found in port_scan data")
        return recon_data

    print(f"[*][Nmap] Total IP targets: {len(ip_list)}")
    print(f"[*][Nmap] Ports to probe: {port_string}")
    print(f"[*][Nmap] Version detection: {NMAP_VERSION_DETECTION}")
    print(f"[*][Nmap] Script scan (vuln): {NMAP_SCRIPT_SCAN}")
    print(f"[*][Nmap] Timing: {NMAP_TIMING}")
    print(f"[*][Nmap] Host timeout: {NMAP_HOST_TIMEOUT}")

    nmap_parallelism = (settings or {}).get('NMAP_PARALLELISM', 2)
    print(f"[*][Nmap] Parallelism: {nmap_parallelism} concurrent IPs")

    scan_id = uuid.uuid4().hex[:12]
    scan_temp_dir = Path(f"/tmp/redamon/.nmap_scan_{scan_id}")
    scan_temp_dir.mkdir(parents=True, exist_ok=True)

    def _scan_single_ip(target_ip, idx, total, port_string, nmap_timeout, output_dir):
        """Scan a single IP with nmap and return parsed results."""
        xml_output = str(output_dir / f"nmap_{idx}_{target_ip.replace(':', '_')}.xml")

        cmd = build_nmap_command(target_ip, port_string, xml_output, settings)

        print(f"[*][Nmap] Scanning {target_ip} ({idx}/{total})...")

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            _, stderr = process.communicate(timeout=nmap_timeout)

            if process.returncode != 0 and not Path(xml_output).exists():
                print(f"[!][Nmap] Scan failed for {target_ip}: {(stderr or '')[:200]}")
                return [], [], ""

        except subprocess.TimeoutExpired:
            print(f"[!][Nmap] Scan timed out for {target_ip} after {nmap_timeout}s -- killing")
            try:
                process.kill()
                process.wait(timeout=10)
            except Exception:
                pass
            return [], [], ""
        except Exception as e:
            print(f"[!][Nmap] Error scanning {target_ip}: {e}")
            return [], [], ""

        # Parse XML results for this target
        parsed = parse_nmap_xml(xml_output, ip_to_hostnames)

        hosts = list(parsed.get("by_host", {}).items())
        services = parsed.get("services_detected", [])
        vulns = parsed.get("nse_vulns", [])
        version = parsed.get("nmap_version", "")

        return hosts, services, vulns, version, " ".join(cmd)

    try:
        # Aggregate results across all target IPs
        merged_by_host: Dict = {}
        merged_services: List[Dict] = []
        merged_vulns: List[Dict] = []
        nmap_version = ""
        full_command = ""

        start_time = datetime.now()

        max_workers = min(nmap_parallelism, len(ip_list))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(
                    _scan_single_ip, ip, idx, len(ip_list),
                    port_string, NMAP_TIMEOUT, scan_temp_dir
                ): ip
                for idx, ip in enumerate(ip_list, 1)
            }
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    result = future.result()
                    if len(result) == 3:
                        # Error path returns 3-tuple
                        continue
                    hosts, services, vulns, version, cmd_str = result

                    if not full_command and cmd_str:
                        full_command = cmd_str
                    if not nmap_version and version:
                        nmap_version = version

                    # Merge host results
                    for host_key, host_data in hosts:
                        if host_key in merged_by_host:
                            existing_ports = set(merged_by_host[host_key]["ports"])
                            for pd in host_data.get("port_details", []):
                                if pd["port"] not in existing_ports:
                                    merged_by_host[host_key]["ports"].append(pd["port"])
                                    merged_by_host[host_key]["port_details"].append(pd)
                                    existing_ports.add(pd["port"])
                            merged_by_host[host_key]["ports"].sort()
                            merged_by_host[host_key]["port_details"].sort(key=lambda x: x["port"])
                        else:
                            merged_by_host[host_key] = host_data

                    merged_services.extend(services)
                    merged_vulns.extend(vulns)
                except Exception as e:
                    print(f"[!][Nmap] Error scanning {ip}: {e}")

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        nmap_results = {
            "scan_metadata": {
                "scanner": "nmap",
                "scan_timestamp": start_time.isoformat(),
                "scan_duration_seconds": round(duration, 2),
                "nmap_version": nmap_version,
                "command": full_command,
                "total_targets": len(ip_list),
                "ports_scanned": port_string,
            },
            "by_host": merged_by_host,
            "services_detected": merged_services,
            "nse_vulns": merged_vulns,
            "summary": {
                "hosts_scanned": len(merged_by_host),
                "services_detected": len(merged_services),
                "nse_vulns_found": len(merged_vulns),
            },
        }

        print(f"[+][Nmap] Scan completed in {duration:.1f} seconds")
        print(f"[+][Nmap] Hosts scanned: {len(merged_by_host)}")
        print(f"[+][Nmap] Services detected: {len(merged_services)}")
        print(f"[+][Nmap] NSE vulnerabilities found: {len(merged_vulns)}")

        if merged_services:
            unique_products = set()
            for svc in merged_services:
                label = svc.get("product", "")
                ver = svc.get("version", "")
                if ver:
                    label = f"{label}/{ver}"
                if label:
                    unique_products.add(label)
            if unique_products:
                preview = ", ".join(sorted(unique_products)[:10])
                extra = f" (+{len(unique_products)-10} more)" if len(unique_products) > 10 else ""
                print(f"[+][Nmap] Services: {preview}{extra}")

        if merged_vulns:
            for vuln in merged_vulns:
                cve_tag = f" ({vuln['cve']})" if vuln.get("cve") else ""
                print(f"[+][Nmap] VULN: {vuln['script_id']} on {vuln['host']}:{vuln['port']}{cve_tag}")

        recon_data["nmap_scan"] = nmap_results

        if output_file:
            with open(output_file, 'w') as f:
                json.dump(recon_data, f, indent=2, default=str)
            print(f"[+][Nmap] Results saved to {output_file}")

        return recon_data

    except Exception as e:
        print(f"[!][Nmap] Error during scan: {e}")
        return recon_data
    finally:
        try:
            if scan_temp_dir.exists():
                for f in scan_temp_dir.iterdir():
                    f.unlink()
                scan_temp_dir.rmdir()
        except Exception:
            pass


def run_nmap_scan_isolated(recon_data: dict, settings: dict = None) -> dict:
    """
    Run Nmap scan and return only the 'nmap_scan' data dict.

    Thread-safe: does not mutate recon_data.

    Args:
        recon_data: The pipeline's combined result dictionary (read-only)
        settings: Settings dictionary from main.py

    Returns:
        The 'nmap_scan' data dict, or empty dict if scan produced no results.
    """
    import copy
    snapshot = copy.copy(recon_data)
    run_nmap_scan(snapshot, output_file=None, settings=settings)
    return snapshot.get("nmap_scan", {})
