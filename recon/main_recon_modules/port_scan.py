"""
RedAmon - Port Scanner Module

Fast, lightweight port scanning.
Runs via Docker for consistent environment and no installation required.

Features:
- SYN and CONNECT scan modes
- Service detection
- CDN/WAF detection
- Passive mode via Shodan InternetDB
- JSON output with structured results
"""

import json
import subprocess
import shutil
import os
import uuid
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
import sys

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Import IANA service lookup (15,000+ services from official registry)
from helpers.iana_services import get_service_name_friendly as get_service_name

# AI surface recon — port catalogue lookup for AI runtimes / vector DBs / frontends
from helpers.ai_signal_catalog import lookup_ai_port

# Settings are passed from main.py to avoid multiple database queries


def _annotate_ai_port_catalog(by_host: dict, settings: dict | None, detected_by: str) -> int:
    """Walk ``by_host`` and annotate each port entry whose port number matches
    the AI port catalogue. Returns the count of annotations written.

    Mutates ``by_host`` in place by adding ``ai_service`` to each matching
    entry in ``port_details``. Each annotation has the shape:

        {"name": "ollama", "category": "ai-runtime", "detected_by": "naabu-ai-port"}

    Ports flagged ``disambiguate=True`` in the catalogue (e.g. 8000, 8080)
    are *not* annotated here — they share their port with many non-AI
    services. The central ``ai_surface_recon`` module (Phase 15) will
    confirm them via chat-shape probes; until then, http_probe's header
    or favicon signal is the only way they get promoted.

    No-op when ``settings`` is None or when the relevant toggle is off.
    """
    if settings is None:
        return 0
    # Toggle key derived from detected_by to keep the helper reusable:
    #   "naabu-ai-port"   -> PORT_SCAN_AI_PORT_CATALOG_ENABLED
    #   "masscan-ai-port" -> MASSCAN_AI_PORT_CATALOG_ENABLED
    toggle_key = {
        "naabu-ai-port":   "PORT_SCAN_AI_PORT_CATALOG_ENABLED",
        "masscan-ai-port": "MASSCAN_AI_PORT_CATALOG_ENABLED",
    }.get(detected_by)
    if toggle_key is None or not settings.get(toggle_key, True):
        return 0

    annotated = 0
    for host_info in (by_host or {}).values():
        for entry in host_info.get("port_details") or []:
            port = entry.get("port")
            descriptor = lookup_ai_port(port) if port is not None else None
            if descriptor and not descriptor.get("disambiguate"):
                entry["ai_service"] = {
                    "name": descriptor["name"],
                    "category": descriptor["category"],
                    "detected_by": detected_by,
                }
                annotated += 1
    return annotated


# =============================================================================
# Docker Helper Functions
# =============================================================================

def is_docker_installed() -> bool:
    """Check if Docker is installed."""
    return shutil.which("docker") is not None


def is_docker_running() -> bool:
    """Check if Docker daemon is running."""
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except Exception:
        return False


def pull_naabu_docker_image(docker_image: str) -> bool:
    """Pull the Naabu Docker image if not present."""
    print(f"[*][Naabu] Checking Docker image: {docker_image}")

    # Check if image exists
    result = subprocess.run(
        ["docker", "images", "-q", docker_image],
        capture_output=True,
        text=True
    )

    if result.stdout.strip():
        print(f"[✓][Naabu] Image already available")
        return True

    print(f"[*][Naabu] Pulling image (this may take a moment)...")
    result = subprocess.run(
        ["docker", "pull", docker_image],
        capture_output=True,
        text=True,
        timeout=300
    )

    if result.returncode == 0:
        print(f"[✓][Naabu] Image pulled successfully")
        return True
    else:
        print(f"[!][Naabu] Failed to pull image: {result.stderr[:200]}")
        return False


# =============================================================================
# Target Extraction
# =============================================================================

def extract_targets_from_recon(recon_data: dict, settings: dict = None) -> Tuple[Set[str], Set[str], Dict[str, List[str]]]:
    """
    Extract IPs and hostnames from recon data, through the RoE admission gate.

    Under an RoE IP or CIDR exclusion naabu is handed addresses only: it
    resolves a name itself, and its answer could be an address the gate never
    saw. Each name still gets its ports, through ip_to_hostnames
    (parse_naabu_output). IP mode does the same: the targets are the listed
    addresses, each once (the gate keeps them to the target list and turns an
    IP-mode label into its address, so no label reaches naabu or by_host).

    Returns:
        Tuple of (unique_ips, unique_hostnames, ip_to_hostnames_mapping)
    """
    unique_ips = set()
    unique_hostnames = set()
    ip_to_hostnames = {}

    dns_data = recon_data.get("dns", {})

    # The scan root (and its addresses) only when it is a target: a `*`-only
    # group must never port-scan its apex. A legacy file keeps the apex.
    from recon.helpers.recon_scope import recon_scope
    domain_dns = dns_data.get("domain", {})
    domain_name = recon_data.get("domain", "")

    if domain_name and recon_scope(recon_data).include_root:
        domain_ips = domain_dns.get("ips", {})
        ipv4_list = domain_ips.get("ipv4", [])
        ipv6_list = domain_ips.get("ipv6", [])

        if ipv4_list or ipv6_list:
            unique_hostnames.add(domain_name)
            for ip in ipv4_list + ipv6_list:
                unique_ips.add(ip)
                if ip not in ip_to_hostnames:
                    ip_to_hostnames[ip] = []
                if domain_name not in ip_to_hostnames[ip]:
                    ip_to_hostnames[ip].append(domain_name)

    # Extract from subdomains
    subdomains_dns = dns_data.get("subdomains", {})
    for subdomain, sub_data in subdomains_dns.items():
        if not sub_data.get("has_records", False):
            continue

        sub_ips = sub_data.get("ips", {})
        ipv4_list = sub_ips.get("ipv4", [])
        ipv6_list = sub_ips.get("ipv6", [])

        if ipv4_list or ipv6_list:
            unique_hostnames.add(subdomain)
            for ip in ipv4_list + ipv6_list:
                unique_ips.add(ip)
                if ip not in ip_to_hostnames:
                    ip_to_hostnames[ip] = []
                if subdomain not in ip_to_hostnames[ip]:
                    ip_to_hostnames[ip].append(subdomain)

    from recon.helpers.target_admission import admission_context, admit_host_targets
    unique_ips, unique_hostnames, ip_to_hostnames = admit_host_targets(
        settings, recon_data, unique_ips, unique_hostnames, ip_to_hostnames,
        module="naabu", resolves_names=False)
    context = admission_context(settings, recon_data)
    if context.ip_rules or context.targets is not None:
        unique_hostnames = set()
    return unique_ips, unique_hostnames, ip_to_hostnames


# =============================================================================
# Naabu Command Builder
# =============================================================================

def get_host_path(container_path: str) -> str:
    """
    Convert container path to host path for Docker-in-Docker volume mounts.

    When running inside a container with mounted volumes, sibling containers
    need host paths, not container paths. This function translates paths
    using the HOST_RECON_OUTPUT_PATH environment variable.

    The recon container mounts: ./output:/app/recon/output
    So /app/recon/output/* inside the container maps to <host>/recon/output/* on host.

    /tmp/redamon is mounted to the same path inside and outside, so no translation needed.
    """
    # /tmp/redamon paths are the same inside and outside the container
    if container_path.startswith("/tmp/redamon"):
        return container_path

    host_output_path = os.environ.get("HOST_RECON_OUTPUT_PATH", "")
    container_output_path = "/app/recon/output"

    if host_output_path and container_path.startswith(container_output_path):
        # Replace container path with host path
        return container_path.replace(container_output_path, host_output_path, 1)

    # If not in container or path doesn't match, return as-is
    return container_path


def build_naabu_command(targets_file: str, output_file: str, settings: dict,
                        container_name: str = None) -> List[str]:
    """
    Build the Docker command for running Naabu.

    Args:
        targets_file: Path to file containing targets (one per line)
        output_file: Path for JSON output
        settings: Settings dictionary from main.py
        container_name: the name the run timeout kills the container by

    Returns:
        List of command arguments
    """
    # Extract settings from passed dict
    NAABU_DOCKER_IMAGE = settings.get('NAABU_DOCKER_IMAGE', 'projectdiscovery/naabu:latest')
    NAABU_TOP_PORTS = settings.get('NAABU_TOP_PORTS', '1000')
    NAABU_CUSTOM_PORTS = settings.get('NAABU_CUSTOM_PORTS', '')
    NAABU_RATE_LIMIT = settings.get('NAABU_RATE_LIMIT', 1000)
    NAABU_THREADS = settings.get('NAABU_THREADS', 25)
    NAABU_TIMEOUT = settings.get('NAABU_TIMEOUT', 10000)
    NAABU_RETRIES = settings.get('NAABU_RETRIES', 1)
    NAABU_SCAN_TYPE = settings.get('NAABU_SCAN_TYPE', 's')
    NAABU_EXCLUDE_CDN = settings.get('NAABU_EXCLUDE_CDN', False)
    NAABU_DISPLAY_CDN = settings.get('NAABU_DISPLAY_CDN', True)
    NAABU_SKIP_HOST_DISCOVERY = settings.get('NAABU_SKIP_HOST_DISCOVERY', True)
    NAABU_VERIFY_PORTS = settings.get('NAABU_VERIFY_PORTS', True)
    NAABU_PASSIVE_MODE = settings.get('NAABU_PASSIVE_MODE', False)

    # Convert container paths to host paths for sibling container volume mounts
    targets_host_path = get_host_path(str(Path(targets_file).parent))
    output_host_path = get_host_path(str(Path(output_file).parent))

    targets_filename = Path(targets_file).name
    output_filename = Path(output_file).name

    # Build Docker command
    # Note: Naabu requires --net=host for proper packet handling
    cmd = [
        "docker", "run", "--rm",
        "--net=host",  # Required for SYN scans
    ]
    if container_name:
        cmd.extend(["--name", container_name])
    cmd.extend([
        "-v", f"{targets_host_path}:/targets:ro",
        "-v", f"{output_host_path}:/output",
    ])

    # Add image
    cmd.append(NAABU_DOCKER_IMAGE)

    # Input/Output
    cmd.extend(["-list", f"/targets/{targets_filename}"])
    # Resolve the hostnames as the DNS step did (recon/helpers/system_resolvers.py).
    from recon.helpers.system_resolvers import resolver_args
    cmd.extend(resolver_args())
    cmd.extend(["-o", f"/output/{output_filename}"])
    cmd.append("-json")
    cmd.append("-silent")

    # Port configuration
    if NAABU_CUSTOM_PORTS:
        cmd.extend(["-p", NAABU_CUSTOM_PORTS])
    elif NAABU_TOP_PORTS:
        cmd.extend(["-top-ports", str(NAABU_TOP_PORTS)])

    # Scan type
    cmd.extend(["-scan-type", NAABU_SCAN_TYPE])

    # Performance settings
    cmd.extend(["-rate", str(NAABU_RATE_LIMIT)])
    cmd.extend(["-c", str(NAABU_THREADS)])
    cmd.extend(["-timeout", str(NAABU_TIMEOUT)])
    cmd.extend(["-retries", str(NAABU_RETRIES)])

    # Feature flags
    if NAABU_EXCLUDE_CDN:
        cmd.append("-exclude-cdn")

    if NAABU_DISPLAY_CDN:
        cmd.append("-cdn")

    if NAABU_SKIP_HOST_DISCOVERY:
        cmd.append("-Pn")

    if NAABU_VERIFY_PORTS:
        cmd.append("-verify")

    if NAABU_PASSIVE_MODE:
        cmd.append("-passive")

    return cmd


# =============================================================================
# Result Parsing
# =============================================================================

def parse_naabu_output(output_file: str, settings: dict = None,
                       ip_to_hostnames: Optional[Dict[str, list]] = None) -> Dict:
    """
    Parse Naabu JSON Lines output into structured format.

    Naabu outputs one JSON object per line:
    {"host":"example.com","ip":"93.184.216.34","port":80}
    {"host":"example.com","ip":"93.184.216.34","port":443}

    Args:
        output_file: Path to naabu's JSONL output file.
        settings: Optional settings dict; when provided, AI surface recon
            port-catalogue annotation runs against each port_details entry
            (gated by PORT_SCAN_AI_PORT_CATALOG_ENABLED).

        ip_to_hostnames: the run's own names per address (extract_targets_from_recon).
            naabu 2.6 writes no "host" for any target, a hostname included, so
            every name that resolves to a scanned address takes that address's
            open ports: by_host is what httpx probes, and keyed by address alone
            no virtual host is ever probed.

    Returns:
        Structured dictionary with by_host, by_ip, and summary sections
    """
    by_host = {}
    by_ip = {}
    all_ports = set()

    if not Path(output_file).exists():
        return {
            "by_host": {},
            "by_ip": {},
            "all_ports": [],
            "summary": {
                "hosts_scanned": 0,
                "ips_scanned": 0,
                "hosts_with_open_ports": 0,
                "total_open_ports": 0,
                "unique_ports": [],
                "unique_port_count": 0,
                "cdn_hosts": 0
            }
        }

    with open(output_file, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            host = entry.get("host", "")
            ip = entry.get("ip", "")
            port = entry.get("port")
            cdn = entry.get("cdn", "")
            cdn_name = entry.get("cdn-name", "")

            if port:
                all_ports.add(port)

            # naabu omits "host" entirely when the target was a bare IP with no
            # reverse DNS, and by_host is the ONLY source of Port/Service nodes
            # (port_mixin reads by_ip for CDN fields alone). So an IP-mode scan of
            # a PTR-less target used to produce an IP node with no ports at all,
            # and every port-keyed consumer downstream -- Service enrichment,
            # tlsx's tls_service_hint, the partial-recon input list -- had
            # nothing to attach to. Key it by the IP, which is what the
            # partial-recon path already does for user-supplied IPs.
            #
            # Deliberately a separate name: `host` stays empty so the IP is not
            # appended to by_ip[...]["hostnames"], which callers read as real
            # hostnames (SNI, cert subject matching, httpx vhosts).
            host_key = host or ip

            # Organize by host
            if host_key:
                if host_key not in by_host:
                    by_host[host_key] = {
                        "host": host_key,
                        "ip": ip,
                        "ports": [],
                        "port_details": [],
                        "cdn": cdn_name if cdn_name else None,
                        "is_cdn": bool(cdn or cdn_name)
                    }

                if port and port not in by_host[host_key]["ports"]:
                    by_host[host_key]["ports"].append(port)

                    # Determine service based on common port mappings
                    service = get_service_name(port)
                    by_host[host_key]["port_details"].append({
                        "port": port,
                        "protocol": "tcp",
                        "service": service
                    })

            # Organize by IP
            if ip:
                if ip not in by_ip:
                    by_ip[ip] = {
                        "ip": ip,
                        "hostnames": [],
                        "ports": [],
                        "cdn": cdn_name if cdn_name else None,
                        "is_cdn": bool(cdn or cdn_name)
                    }

                if host and host not in by_ip[ip]["hostnames"]:
                    by_ip[ip]["hostnames"].append(host)

                if port and port not in by_ip[ip]["ports"]:
                    by_ip[ip]["ports"].append(port)

    for ip, ip_entry in by_ip.items():
        for name in (ip_to_hostnames or {}).get(ip) or []:
            if not isinstance(name, str) or not name or name in by_host:
                continue
            by_host[name] = {
                "host": name, "ip": ip, "ports": list(ip_entry["ports"]),
                "port_details": [{"port": p, "protocol": "tcp", "service": get_service_name(p)}
                                 for p in ip_entry["ports"]],
                "cdn": ip_entry.get("cdn"), "is_cdn": ip_entry.get("is_cdn", False),
            }
            if name not in ip_entry["hostnames"]:
                ip_entry["hostnames"].append(name)

    # Sort ports
    for host in by_host:
        by_host[host]["ports"].sort()
        by_host[host]["port_details"].sort(key=lambda x: x["port"])

    for ip in by_ip:
        by_ip[ip]["ports"].sort()

    all_ports_sorted = sorted(list(all_ports))

    # AI surface recon — annotate AI-bearing ports on each port_details entry
    ai_annotations = _annotate_ai_port_catalog(by_host, settings, detected_by="naabu-ai-port")

    # Build summary
    summary = {
        "hosts_scanned": len(by_host),
        "ips_scanned": len(by_ip),
        "hosts_with_open_ports": len([h for h in by_host.values() if h["ports"]]),
        "total_open_ports": sum(len(h["ports"]) for h in by_host.values()),
        "unique_ports": all_ports_sorted,
        "unique_port_count": len(all_ports_sorted),
        "cdn_hosts": len([h for h in by_host.values() if h.get("is_cdn")]),
        "ai_ports_annotated": ai_annotations,
    }

    return {
        "by_host": by_host,
        "by_ip": by_ip,
        "all_ports": all_ports_sorted,
        "summary": summary
    }


# =============================================================================
# File Ownership Handling
# =============================================================================

def get_real_user_ids() -> tuple:
    """Get the real user/group IDs (handles sudo)."""
    sudo_uid = os.environ.get('SUDO_UID')
    sudo_gid = os.environ.get('SUDO_GID')

    if sudo_uid and sudo_gid:
        return (int(sudo_uid), int(sudo_gid))
    return (os.getuid(), os.getgid())


def fix_file_ownership(file_path: Path) -> None:
    """Fix file ownership for files created by Docker (as root)."""
    try:
        uid, gid = get_real_user_ids()
        os.chown(str(file_path), uid, gid)
    except Exception:
        pass  # Silently ignore if we can't change ownership


def _targets_without_ports(targets: List[str], results: Dict) -> List[str]:
    """The targets a cut naabu wrote no open port for: it did not finish them,
    so they are not known to have none."""
    found = set(results.get("by_host") or {}) | set(results.get("by_ip") or {})
    return [t for t in targets if t not in found]


def _note_naabu_cut(targets: List[str], unscanned: List[str], kept_ports: bool, reason: str) -> None:
    """Record what a naabu run cut by its timeout did not port-scan. Never raises.

    With the ports it did write kept, the downstream tools probe only those,
    so no tool re-checked the hosts it left without one: they are cut for
    every source. With nothing written there is no port data at all, as for a
    failed scan: httpx falls back to the DNS names and the pipeline keeps
    nmap's findings, so this is a coverage gap only.
    """
    try:
        from recon.helpers import circuit_breaker
        if kept_ports:
            if unscanned:
                circuit_breaker.note_degraded("port_scan", hosts=unscanned, host_source="naabu",
                                              reason=reason)
        else:
            circuit_breaker.note_degraded("port_scan", entries=[
                {"source": "naabu", "reason": reason, "skipped": len(targets)}])
    except Exception:  # noqa: BLE001
        pass


# =============================================================================
# Main Scan Function
# =============================================================================

def run_port_scan(recon_data: dict, output_file: Path = None, settings: dict = None) -> dict:
    """
    Run Naabu port scan on targets from recon data.

    Args:
        recon_data: Dictionary containing DNS/subdomain data
        output_file: Path to save enriched results (optional)
        settings: Settings dictionary from main.py

    Returns:
        Enriched recon_data with "port_scan" section added
    """
    print("\n" + "="*60)
    print("[*][Naabu] PORT SCANNER")
    print("="*60)

    # Use passed settings or empty dict as fallback
    if settings is None:
        settings = {}

    if not settings.get('NAABU_ENABLED', True):
        print("[-][Naabu] Disabled — skipping")
        return recon_data

    from recon.helpers import print_effective_settings
    print_effective_settings(
        "Naabu",
        settings,
        keys=[
            ("NAABU_ENABLED", "Toggle"),
            ("NAABU_DOCKER_IMAGE", "Image"),
            ("NAABU_TOP_PORTS", "Ports"),
            ("NAABU_CUSTOM_PORTS", "Ports"),
            ("NAABU_RATE_LIMIT", "Performance"),
            ("NAABU_THREADS", "Performance"),
            ("NAABU_TIMEOUT", "Performance"),
            ("NAABU_RETRIES", "Performance"),
            ("NAABU_SCAN_TYPE", "Behavior"),
            ("NAABU_EXCLUDE_CDN", "Behavior"),
            ("NAABU_DISPLAY_CDN", "Behavior"),
            ("NAABU_SKIP_HOST_DISCOVERY", "Behavior"),
            ("NAABU_VERIFY_PORTS", "Behavior"),
            ("NAABU_PASSIVE_MODE", "Behavior"),
        ],
    )

    # Extract settings from passed dict
    NAABU_DOCKER_IMAGE = settings.get('NAABU_DOCKER_IMAGE', 'projectdiscovery/naabu:latest')
    NAABU_TOP_PORTS = settings.get('NAABU_TOP_PORTS', '1000')
    NAABU_CUSTOM_PORTS = settings.get('NAABU_CUSTOM_PORTS', '')
    NAABU_RATE_LIMIT = settings.get('NAABU_RATE_LIMIT', 1000)
    NAABU_SCAN_TYPE = settings.get('NAABU_SCAN_TYPE', 's')
    NAABU_EXCLUDE_CDN = settings.get('NAABU_EXCLUDE_CDN', False)
    NAABU_PASSIVE_MODE = settings.get('NAABU_PASSIVE_MODE', False)

    # Check Docker
    if not is_docker_installed():
        print("[!][Naabu] Docker is not installed. Please install Docker first.")
        return recon_data

    if not is_docker_running():
        print("[!][Naabu] Docker daemon is not running. Please start Docker.")
        return recon_data

    # Pull image if needed
    if not pull_naabu_docker_image(NAABU_DOCKER_IMAGE):
        print("[!][Naabu] Failed to get Docker image")
        return recon_data

    # Extract targets
    print("[*][Naabu] Extracting targets from recon data...")
    unique_ips, unique_hostnames, ip_to_hostnames = extract_targets_from_recon(recon_data, settings)

    # Every name and every address. The filter removes nothing, because
    # ip_to_hostnames is keyed by address, so an address is scanned even when
    # a name of its is too. In IP mode (and under an RoE IP rule) there are no
    # names here at all: the addresses only, each once.
    all_targets = list(unique_hostnames) + [ip for ip in unique_ips if ip not in [
        h_ip for h in unique_hostnames for h_ip in ip_to_hostnames.get(h, [])
    ]]

    if not all_targets:
        print("[!][Naabu] No targets found in recon data")
        return recon_data

    print(f"[*][Naabu] Found {len(unique_hostnames)} hostnames and {len(unique_ips)} IPs")
    print(f"[*][Naabu] Total targets to scan: {len(all_targets)}")

    # Create temp directory for scan files
    # Use /tmp/redamon to avoid spaces in paths (snap Docker issue). One dir per
    # run: concurrent scans share /tmp/redamon, and the cleanup below empties it.
    scan_temp_dir = Path(f"/tmp/redamon/.naabu_temp_{uuid.uuid4().hex[:12]}")
    scan_temp_dir.mkdir(parents=True, exist_ok=True)

    try:
        # Write targets file
        targets_file = scan_temp_dir / "targets.txt"
        with open(targets_file, 'w') as f:
            for target in all_targets:
                f.write(f"{target}\n")

        # Set output file
        naabu_output = scan_temp_dir / "naabu_output.json"

        print(f"[*][Naabu] Starting scan...")
        print(f"[*][Naabu] Scan type: {'SYN' if NAABU_SCAN_TYPE == 's' else 'CONNECT'}")
        print(f"[*][Naabu] Ports: {NAABU_CUSTOM_PORTS if NAABU_CUSTOM_PORTS else f'top {NAABU_TOP_PORTS}'}")
        print(f"[*][Naabu] Rate limit: {NAABU_RATE_LIMIT} pps")
        print(f"[*][Naabu] Threads: {settings.get('NAABU_THREADS', 25)}")
        print(f"[*][Naabu] Timeout: {settings.get('NAABU_TIMEOUT', 10000)}ms")
        print(f"[*][Naabu] Retries: {settings.get('NAABU_RETRIES', 1)}")
        print(f"[*][Naabu] Exclude CDN: {NAABU_EXCLUDE_CDN}")
        print(f"[*][Naabu] Skip host discovery: {settings.get('NAABU_SKIP_HOST_DISCOVERY', True)}")
        print(f"[*][Naabu] Verify ports: {settings.get('NAABU_VERIFY_PORTS', True)}")

        if NAABU_PASSIVE_MODE:
            print(f"[*][Naabu] Mode: PASSIVE (Shodan InternetDB)")

        start_time = datetime.now()

        # Execute scan with fallback mechanism
        from recon.helpers.docker_helpers import kill_container, tool_container_name
        scan_succeeded = False
        timed_out = False
        run_timeout = 1800  # 30 min
        actual_scan_type = NAABU_SCAN_TYPE

        for attempt, scan_type in enumerate([NAABU_SCAN_TYPE, 'c'] if NAABU_SCAN_TYPE == 's' else [NAABU_SCAN_TYPE]):
            # One name per attempt: a timeout kills the container by it.
            container_name = tool_container_name("naabu")
            if attempt > 0:
                # Retry with CONNECT scan after SYN scan failed
                print(f"[*][Naabu] Retrying with CONNECT scan...")
                settings_copy = settings.copy()
                settings_copy['NAABU_SCAN_TYPE'] = 'c'
                cmd = build_naabu_command(str(targets_file), str(naabu_output), settings_copy,
                                          container_name=container_name)
                actual_scan_type = 'c'
            else:
                cmd = build_naabu_command(str(targets_file), str(naabu_output), settings,
                                          container_name=container_name)

            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            try:
                _, stderr = process.communicate(timeout=run_timeout)
            except subprocess.TimeoutExpired:
                # Killing the docker CLI alone leaves the container scanning.
                # No CONNECT retry: the budget is spent.
                print(f"[!][Naabu] Scan timed out after {run_timeout}s -- stopping it, "
                      f"keeping the ports it wrote")
                kill_container(container_name)
                try:
                    process.kill()
                    process.communicate(timeout=10)
                except Exception:  # noqa: BLE001
                    pass
                timed_out = True
                break

            # Check for SIGSEGV crash (common in SYN mode)
            if 'SIGSEGV' in stderr or 'segmentation' in stderr.lower():
                print(f"[!][Naabu] Scan crashed (SIGSEGV) — binary error")
                if scan_type == 's' and attempt == 0:
                    print(f"[*][Naabu] SYN scan requires raw sockets — will try CONNECT scan")
                    continue  # Try CONNECT scan
                else:
                    break  # No more fallbacks

            if process.returncode == 0 or naabu_output.exists():
                # SYN scan succeeded but found 0 ports — firewall may be
                # silently dropping SYN probes.  Retry with CONNECT scan
                # which uses full TCP handshake and works through most firewalls.
                if (scan_type == 's' and attempt == 0
                        and (not naabu_output.exists()
                             or naabu_output.stat().st_size == 0)):
                    print(f"[!][Naabu] SYN scan completed but found no open ports")
                    print(f"[*][Naabu] Firewall may be dropping SYN probes — retrying with CONNECT scan...")
                    continue
                scan_succeeded = True
                break

            if stderr and attempt == 0 and scan_type == 's':
                print(f"[!][Naabu] SYN scan failed: {stderr[:150] if stderr else 'Unknown error'}")
                continue  # Try CONNECT scan

            print(f"[!][Naabu] Scan failed: {stderr[:200] if stderr else 'Unknown error'}")
            break

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        if not timed_out and not scan_succeeded and not naabu_output.exists():
            print(f"[!][Naabu] All scan attempts failed")
            return recon_data

        # Parse results
        print(f"[*][Naabu] Parsing results...")
        results = parse_naabu_output(str(naabu_output), settings=settings,
                                     ip_to_hostnames=ip_to_hostnames)
        if results.get("summary", {}).get("ai_ports_annotated"):
            print(f"[+][Naabu] AI port catalog matched {results['summary']['ai_ports_annotated']} port(s)")

        unscanned = []
        if timed_out:
            unscanned = _targets_without_ports(all_targets, results)
            _note_naabu_cut(all_targets, unscanned, bool(results["by_host"]),
                            f"naabu timed out after {run_timeout}s")
            if not results["by_host"]:
                # An empty port list would read as "no open port anywhere".
                print(f"[!][Naabu] Nothing was written before the timeout - no port data")
                return recon_data
            print(f"[!][Naabu] {len(unscanned)} of {len(all_targets)} target(s) got no port "
                  f"before the timeout; their earlier findings are kept")

        # Build final structure
        naabu_results = {
            "scan_metadata": {
                "scan_timestamp": start_time.isoformat(),
                "scan_duration_seconds": round(duration, 2),
                "docker_image": NAABU_DOCKER_IMAGE,
                "scan_type": "syn" if actual_scan_type == "s" else "connect",
                "scan_type_fallback": actual_scan_type != NAABU_SCAN_TYPE,
                "ports_config": NAABU_CUSTOM_PORTS if NAABU_CUSTOM_PORTS else f"top-{NAABU_TOP_PORTS}",
                "rate_limit": NAABU_RATE_LIMIT,
                "passive_mode": NAABU_PASSIVE_MODE,
                "proxy_used": False,
                "total_targets": len(all_targets),
                "cdn_exclusion": NAABU_EXCLUDE_CDN
            },
            "by_host": results["by_host"],
            "by_ip": results["by_ip"],
            "all_ports": results["all_ports"],
            "ip_to_hostnames": ip_to_hostnames,
            "summary": results["summary"]
        }
        if timed_out:
            # What a cut scan looked at is unknown, so it records no port list:
            # port_coverage then counts the ports it found as open and calls
            # none closed.
            naabu_results["scan_metadata"].update(
                ports_config=None, timed_out=True, unchecked_targets=len(unscanned))

        # Print summary
        summary = results["summary"]
        if timed_out:
            print(f"[!][Naabu] Scan cut at its {run_timeout}s timeout")
        else:
            print(f"[✓][Naabu] Scan completed in {duration:.1f} seconds")
        if actual_scan_type != NAABU_SCAN_TYPE:
            print(f"[*][Naabu] Note: Used CONNECT scan (SYN scan crashed)")
        print(f"[+][Naabu] Hosts with open ports: {summary['hosts_with_open_ports']}")
        print(f"[+][Naabu] Total open ports found: {summary['total_open_ports']}")
        print(f"[+][Naabu] Unique ports: {summary['unique_port_count']}")

        if summary.get('cdn_hosts', 0) > 0:
            print(f"[*][Naabu] CDN-protected hosts: {summary['cdn_hosts']}")

        if results["all_ports"]:
            print(f"[+][Naabu] Ports discovered: {', '.join(map(str, results['all_ports'][:20]))}" +
                  (f"... (+{len(results['all_ports'])-20} more)" if len(results['all_ports']) > 20 else ""))

        # Add to recon_data
        recon_data["port_scan"] = naabu_results

        # Save incrementally
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(recon_data, f, indent=2, default=str)
            fix_file_ownership(output_file)
            print(f"[✓][Naabu] Results saved to {output_file}")

        return recon_data

    except Exception as e:
        print(f"[!][Naabu] Error during scan: {e}")
        return recon_data
    finally:
        # Cleanup temp files
        try:
            if scan_temp_dir.exists():
                for f in scan_temp_dir.iterdir():
                    f.unlink()
                scan_temp_dir.rmdir()
        except Exception:
            pass


# =============================================================================
# Standalone Entry Point
# =============================================================================

def enrich_recon_file(recon_file: Path) -> dict:
    """
    Enrich an existing recon JSON file with Naabu scan results.

    Args:
        recon_file: Path to existing recon JSON file

    Returns:
        Enriched recon data
    """
    # Load settings for standalone usage
    from recon.project_settings import get_settings
    settings = get_settings()

    print(f"[*][Naabu] Loading recon file: {recon_file}")

    with open(recon_file, 'r') as f:
        recon_data = json.load(f)

    enriched = run_port_scan(recon_data, output_file=recon_file, settings=settings)

    return enriched


def run_port_scan_isolated(recon_data: dict, settings: dict = None) -> dict:
    """
    Run port scan and return only the 'port_scan' data dict.

    Thread-safe: does not mutate recon_data. Reads DNS/subdomain data from
    it but writes nothing back. Designed for parallel execution alongside
    other modules (e.g., Shodan enrichment).

    Args:
        recon_data: The pipeline's combined result dictionary (read-only)
        settings: Settings dictionary from main.py

    Returns:
        The 'port_scan' data dictionary (just the scan payload),
        or empty dict if scan produced no results.
    """
    import copy
    # Deep, not shallow: the fan-out hands every worker one shared copy, which
    # a nested write would change under the others' copies.
    snapshot = copy.deepcopy(recon_data)
    run_port_scan(snapshot, output_file=None, settings=settings)
    return snapshot.get("port_scan", {})

