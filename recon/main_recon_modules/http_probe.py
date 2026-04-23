"""
RedAmon - HTTP Probing Module + Banner Grabbing

Multi-purpose HTTP toolkit for probing and technology detection.
Uses Docker for consistent environment and no installation required.

Also includes banner grabbing for non-HTTP services (SSH, FTP, SMTP, etc.)
to detect service versions on ports that HTTP probing cannot handle.

Features:
- HTTP status code, headers, and body extraction
- Technology detection (Wappalyzer-based)
- SSL/TLS certificate information
- Favicon and JARM fingerprinting
- CDN and ASN detection
- Response body hashing
- Banner grabbing for non-HTTP ports (SSH, FTP, SMTP, MySQL, etc.)
"""

import json
import subprocess
import shutil
import os
import socket
import ssl
import re
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Settings are passed from main.py to avoid multiple database queries


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


def pull_httpx_docker_image(docker_image: str) -> bool:
    """Pull the httpx Docker image if not present."""
    print(f"[*][httpx] Checking Docker image: {docker_image}")

    # Check if image exists
    result = subprocess.run(
        ["docker", "images", "-q", docker_image],
        capture_output=True,
        text=True
    )

    if result.stdout.strip():
        print(f"[✓][httpx] Image already available")
        return True

    print(f"[*][httpx] Pulling image (this may take a moment)...")
    result = subprocess.run(
        ["docker", "pull", docker_image],
        capture_output=True,
        text=True,
        timeout=300
    )

    if result.returncode == 0:
        print(f"[✓][httpx] Image pulled successfully")
        return True
    else:
        print(f"[!][httpx] Failed to pull image: {result.stderr[:200]}")
        return False


def is_tor_running() -> bool:
    """Check if Tor SOCKS proxy is available."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex(('127.0.0.1', 9050))
        sock.close()
        return result == 0
    except Exception:
        return False


# =============================================================================
# Banner Grabbing for Non-HTTP Services
# =============================================================================

# HTTP ports that httpx handles (skip these for banner grabbing)
HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8888, 8008, 3000, 5000, 9000, 9090, 8800}

# Service probes - sent to trigger banner responses
SERVICE_PROBES = {
    21: b"",              # FTP - sends banner immediately
    22: b"",              # SSH - sends banner immediately
    23: b"",              # Telnet - sends banner
    25: b"EHLO probe\r\n", # SMTP
    110: b"",             # POP3
    143: b"",             # IMAP
    465: b"EHLO probe\r\n", # SMTPS
    587: b"EHLO probe\r\n", # Submission
    993: b"",             # IMAPS
    995: b"",             # POP3S
    3306: b"",            # MySQL
    5432: b"\x00\x00\x00\x08\x04\xd2\x16\x2f",  # PostgreSQL cancel request
    5900: b"",            # VNC
    6379: b"INFO\r\n",    # Redis
    11211: b"version\r\n", # Memcached
    27017: b"",           # MongoDB
    "default": b"",
}

# Service identification patterns
SERVICE_PATTERNS = [
    # SSH
    (r"SSH-[\d.]+-(\S+)", "ssh", lambda m: m.group(1)),
    (r"OpenSSH[_\s]*([\d.p]+)", "ssh", lambda m: f"OpenSSH {m.group(1)}"),
    (r"dropbear[_\s]*([\d.]+)?", "ssh", lambda m: f"Dropbear {m.group(1) or ''}".strip()),
    
    # FTP
    (r"220[- ].*vsftpd\s*([\d.]+)?", "ftp", lambda m: f"vsFTPd {m.group(1) or ''}".strip()),
    (r"220[- ].*ProFTPD\s*([\d.]+)?", "ftp", lambda m: f"ProFTPD {m.group(1) or ''}".strip()),
    (r"220[- ].*Pure-FTPd", "ftp", lambda m: "Pure-FTPd"),
    (r"220[- ].*FileZilla", "ftp", lambda m: "FileZilla FTP"),
    (r"220[- ].*Microsoft FTP", "ftp", lambda m: "Microsoft FTP"),
    (r"220[- ]", "ftp", lambda m: "FTP"),
    
    # SMTP
    (r"220[- ].*Postfix", "smtp", lambda m: "Postfix"),
    (r"220[- ].*Sendmail", "smtp", lambda m: "Sendmail"),
    (r"220[- ].*Exim\s*([\d.]+)?", "smtp", lambda m: f"Exim {m.group(1) or ''}".strip()),
    (r"220[- ].*Microsoft ESMTP", "smtp", lambda m: "Microsoft Exchange"),
    (r"220[- ].*ESMTP", "smtp", lambda m: "SMTP"),
    
    # POP3/IMAP
    (r"\+OK.*Dovecot", "pop3", lambda m: "Dovecot POP3"),
    (r"\+OK", "pop3", lambda m: "POP3"),
    (r"\* OK.*Dovecot", "imap", lambda m: "Dovecot IMAP"),
    (r"\* OK", "imap", lambda m: "IMAP"),
    
    # Databases
    (r"(\d+\.\d+\.\d+).*?mysql", "mysql", lambda m: f"MySQL/{m.group(1)}"),
    (r"(\d+\.\d+\.\d+)-MariaDB", "mysql", lambda m: f"MariaDB/{m.group(1)}"),
    (r"mysql|MariaDB", "mysql", lambda m: "MySQL/MariaDB"),
    (r"PostgreSQL", "postgresql", lambda m: "PostgreSQL"),
    (r"redis_version:([\d.]+)", "redis", lambda m: f"Redis {m.group(1)}"),
    (r"-ERR.*Redis", "redis", lambda m: "Redis"),
    (r"MongoDB|mongod|It looks like you are trying to access MongoDB", "mongodb", lambda m: "MongoDB"),

    # VNC
    (r"RFB\s*([\d.]+)", "vnc", lambda m: f"VNC (RFB {m.group(1)})"),
    
    # Memcached
    (r"VERSION\s*([\d.]+)", "memcached", lambda m: f"Memcached {m.group(1)}"),
    
    # Telnet
    (r"login:", "telnet", lambda m: "Telnet"),
]


def grab_banner(host: str, port: int, timeout: float = 5.0, use_ssl: bool = False, max_length: int = 500) -> Optional[str]:
    """
    Connect to a host:port and grab the service banner.

    Args:
        host: Target hostname or IP
        port: Target port
        timeout: Connection timeout in seconds
        use_ssl: Whether to use SSL/TLS
        max_length: Maximum banner length to return

    Returns:
        Banner string or None if failed
    """

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # Wrap with SSL if needed
        if use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=host)

        # Get probe for this port
        probe = SERVICE_PROBES.get(port, SERVICE_PROBES["default"])

        banner = b""

        # First try to receive (many services send banner immediately)
        try:
            sock.settimeout(3.0)
            banner = sock.recv(1024)
        except socket.timeout:
            pass

        # If no banner and we have a probe, send it
        if not banner and probe:
            try:
                sock.send(probe)
                sock.settimeout(timeout)
                banner = sock.recv(1024)
            except:
                pass

        sock.close()

        if banner:
            return banner.decode('utf-8', errors='replace').strip()[:max_length]

        return None

    except Exception:
        return None


def identify_service(banner: str, port: int) -> Dict:
    """
    Identify service from banner using pattern matching.
    """
    if not banner:
        return {"service": "unknown", "version": None, "confidence": "none"}
    
    for pattern, service, extractor in SERVICE_PATTERNS:
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            try:
                version_info = extractor(match)
                return {
                    "service": service,
                    "version": version_info,
                    "confidence": "high"
                }
            except:
                return {"service": service, "version": None, "confidence": "medium"}
    
    return {"service": "unknown", "version": None, "banner_hint": banner[:100], "confidence": "low"}


def grab_banner_for_target(target: tuple, timeout: float = 5, max_length: int = 500) -> Dict:
    """Grab banner for a single target (used for parallel execution)."""
    host, port, original_host = target

    # Try regular connection first
    banner = grab_banner(host, port, timeout, use_ssl=False, max_length=max_length)

    # If port looks like SSL and no banner, try SSL
    ssl_ports = {993, 995, 465, 636, 990}
    if not banner and port in ssl_ports:
        banner = grab_banner(host, port, timeout, use_ssl=True, max_length=max_length)

    service_info = identify_service(banner, port)

    return {
        "host": original_host,
        "ip": host if host != original_host else None,
        "port": port,
        "banner": banner,
        "service": service_info["service"],
        "version": service_info.get("version"),
        "confidence": service_info.get("confidence", "none")
    }


def run_banner_grab(recon_data: dict, settings: dict = None) -> Dict:
    """
    Run banner grabbing on non-HTTP ports from naabu results.

    Args:
        recon_data: Dictionary containing naabu/DNS data
        settings: Settings dictionary from main.py

    Returns:
        Dictionary with banner grabbing results
    """
    if settings is None:
        settings = {}

    # Extract settings from passed dict
    BANNER_GRAB_ENABLED = settings.get('BANNER_GRAB_ENABLED', True)
    BANNER_GRAB_TIMEOUT = settings.get('BANNER_GRAB_TIMEOUT', 5)
    BANNER_GRAB_THREADS = settings.get('BANNER_GRAB_THREADS', 20)
    BANNER_GRAB_MAX_LENGTH = settings.get('BANNER_GRAB_MAX_LENGTH', 500)

    if not BANNER_GRAB_ENABLED:
        return {}

    naabu_data = recon_data.get("port_scan", {})
    if not naabu_data:
        return {}

    by_host = naabu_data.get("by_host", {})
    if not by_host:
        return {}

    # Build target list for non-HTTP ports
    targets = []
    for hostname, host_data in by_host.items():
        ip = host_data.get("ip", hostname)
        ports = host_data.get("ports", [])

        for port in ports:
            # Skip HTTP ports - httpx handles these
            if port in HTTP_PORTS:
                continue
            targets.append((ip, port, hostname))

    if not targets:
        return {}

    print(f"\n[*][httpx] Banner grabbing for non-HTTP ports...")
    print(f"[*][httpx] Ports to probe: {len(targets)}")
    print(f"[*][httpx] Threads: {BANNER_GRAB_THREADS}")
    
    start_time = datetime.now()
    results = []
    
    with ThreadPoolExecutor(max_workers=BANNER_GRAB_THREADS) as executor:
        futures = {executor.submit(grab_banner_for_target, t, BANNER_GRAB_TIMEOUT, BANNER_GRAB_MAX_LENGTH): t for t in targets}
        
        for future in as_completed(futures):
            try:
                result = future.result()
                results.append(result)
                
                if result.get("banner"):
                    service = result.get("version") or result.get("service") or "unknown"
                    print(f"[+][httpx] {result['host']}:{result['port']} - {service}")
            except Exception:
                pass
    
    duration = (datetime.now() - start_time).total_seconds()
    
    # Build results structure
    banner_results = {
        "scan_metadata": {
            "scan_timestamp": start_time.isoformat(),
            "scan_duration_seconds": round(duration, 2),
            "total_ports_scanned": len(targets),
            "banners_retrieved": len([r for r in results if r.get("banner")])
        },
        "by_host": {},
        "services_found": {}
    }
    
    # Organize by host
    for result in results:
        host = result["host"]
        port = result["port"]
        
        if host not in banner_results["by_host"]:
            banner_results["by_host"][host] = {"host": host, "ports": {}}
        
        banner_results["by_host"][host]["ports"][port] = {
            "port": port,
            "banner": result.get("banner"),
            "service": result.get("service"),
            "version": result.get("version"),
            "confidence": result.get("confidence")
        }
        
        # Track services
        service = result.get("service", "unknown")
        if service != "unknown":
            if service not in banner_results["services_found"]:
                banner_results["services_found"][service] = []
            banner_results["services_found"][service].append({
                "host": host,
                "port": port,
                "version": result.get("version")
            })
    
    # Also enrich naabu port_details with banner info
    for host, host_data in naabu_data.get("by_host", {}).items():
        if "port_details" in host_data:
            for port_detail in host_data["port_details"]:
                port = port_detail.get("port")
                for result in results:
                    if result["host"] == host and result["port"] == port:
                        if result.get("banner"):
                            port_detail["banner"] = result["banner"]
                        if result.get("version"):
                            port_detail["version"] = result["version"]
                        break
    
    banners_found = banner_results["scan_metadata"]["banners_retrieved"]
    print(f"[✓][httpx] Banner grab complete: {banners_found}/{len(targets)} banners retrieved")
    
    return banner_results


# =============================================================================
# Target Building from Naabu Results
# =============================================================================

def build_targets_from_naabu(recon_data: dict) -> List[str]:
    """
    Build HTTP/HTTPS URLs from Naabu port scan results.

    Args:
        recon_data: Dictionary containing naabu scan results

    Returns:
        List of URLs to probe (e.g., ["http://example.com", "https://example.com:8443"])
    """
    urls = []
    naabu_data = recon_data.get("port_scan", {})

    # Common HTTPS ports
    https_ports = {443, 8443, 4443, 9443, 8843}
    # Common HTTP ports
    http_ports = {80, 8080, 8000, 8888, 8008, 3000, 5000, 9000}

    if naabu_data:
        for host, data in naabu_data.get("by_host", {}).items():
            for port_info in data.get("port_details", []):
                port = port_info.get("port")
                service = port_info.get("service", "").lower()

                if not port:
                    continue

                # Determine protocol based on port and service
                if port == 443 or "https" in service or "ssl" in service or "tls" in service:
                    url = f"https://{host}" if port == 443 else f"https://{host}:{port}"
                    urls.append(url)
                elif port == 80 or "http" in service:
                    url = f"http://{host}" if port == 80 else f"http://{host}:{port}"
                    urls.append(url)
                elif port in https_ports:
                    # Known HTTPS ports
                    urls.append(f"https://{host}:{port}")
                elif port in http_ports:
                    # Known HTTP ports
                    urls.append(f"http://{host}:{port}")
                else:
                    # Unknown port - try both protocols
                    urls.append(f"http://{host}:{port}")
                    urls.append(f"https://{host}:{port}")

    # Fallback: build from DNS data if no naabu results
    if not urls:
        urls = build_targets_from_dns(recon_data)

    return list(set(urls))


def build_targets_from_dns(recon_data: dict) -> List[str]:
    """
    Fallback: Build URLs from DNS data when naabu results are not available.

    Probes default ports (80, 443) plus common non-standard HTTP ports
    that firewalls/rate-limiting may cause naabu to miss.

    Returns:
        List of URLs to probe
    """
    urls = []
    dns_data = recon_data.get("dns", {})

    # Common non-standard HTTP ports to try when port scan has no results
    extra_http_ports = [8080, 8000, 8888, 3000, 5000, 9000]
    extra_https_ports = [8443, 4443, 9443]

    def _add_host(host: str) -> None:
        urls.append(f"http://{host}")
        urls.append(f"https://{host}")
        for port in extra_http_ports:
            urls.append(f"http://{host}:{port}")
        for port in extra_https_ports:
            urls.append(f"https://{host}:{port}")

    # Add root domain
    domain = recon_data.get("domain", "")
    if domain:
        domain_dns = dns_data.get("domain", {})
        if domain_dns.get("ips", {}).get("ipv4") or domain_dns.get("ips", {}).get("ipv6"):
            _add_host(domain)

    # Add subdomains
    metadata = recon_data.get("metadata", {})
    ip_mode = metadata.get("ip_mode", False)
    subdomains_dns = dns_data.get("subdomains", {})
    for subdomain, sub_data in subdomains_dns.items():
        if sub_data.get("has_records", False):
            if ip_mode and sub_data.get("is_mock", False):
                # In IP mode, mock subdomain names aren't valid hostnames.
                # Use the actual IP address instead.
                actual_ip = sub_data.get("actual_ip", "")
                if actual_ip:
                    _add_host(actual_ip)
                    continue
                # Fallback: extract IPs from dns data
                ips = sub_data.get("ips", {})
                for ip in (ips.get("ipv4", []) or []) + (ips.get("ipv6", []) or []):
                    _add_host(ip)
            else:
                _add_host(subdomain)

    return urls


# =============================================================================
# httpx Command Builder
# =============================================================================

def get_host_path(container_path: str) -> str:
    """
    Convert container path to host path for Docker-in-Docker volume mounts.

    When running inside a container with mounted volumes, sibling containers
    need host paths, not container paths.

    /tmp/redamon is mounted to the same path inside and outside, so no translation needed.
    """
    # /tmp/redamon paths are the same inside and outside the container
    if container_path.startswith("/tmp/redamon"):
        return container_path

    host_output_path = os.environ.get("HOST_RECON_OUTPUT_PATH", "")
    container_output_path = "/app/recon/output"

    if host_output_path and container_path.startswith(container_output_path):
        return container_path.replace(container_output_path, host_output_path, 1)
    return container_path


def build_httpx_command(targets_file: str, output_file: str, settings: dict, use_proxy: bool = False) -> List[str]:
    """
    Build the Docker command for running httpx.

    Args:
        targets_file: Path to file containing URLs (one per line)
        output_file: Path for JSON output
        settings: Settings dictionary from main.py
        use_proxy: Whether to use Tor proxy

    Returns:
        List of command arguments
    """
    # Extract settings from passed dict
    HTTPX_DOCKER_IMAGE = settings.get('HTTPX_DOCKER_IMAGE', 'projectdiscovery/httpx:latest')
    HTTPX_THREADS = settings.get('HTTPX_THREADS', 50)
    HTTPX_TIMEOUT = settings.get('HTTPX_TIMEOUT', 10)
    HTTPX_RETRIES = settings.get('HTTPX_RETRIES', 2)
    HTTPX_RATE_LIMIT = settings.get('HTTPX_RATE_LIMIT', 50)
    HTTPX_FOLLOW_REDIRECTS = settings.get('HTTPX_FOLLOW_REDIRECTS', True)
    HTTPX_MAX_REDIRECTS = settings.get('HTTPX_MAX_REDIRECTS', 10)
    HTTPX_PROBE_STATUS_CODE = settings.get('HTTPX_PROBE_STATUS_CODE', True)
    HTTPX_PROBE_CONTENT_LENGTH = settings.get('HTTPX_PROBE_CONTENT_LENGTH', True)
    HTTPX_PROBE_CONTENT_TYPE = settings.get('HTTPX_PROBE_CONTENT_TYPE', True)
    HTTPX_PROBE_TITLE = settings.get('HTTPX_PROBE_TITLE', True)
    HTTPX_PROBE_SERVER = settings.get('HTTPX_PROBE_SERVER', True)
    HTTPX_PROBE_RESPONSE_TIME = settings.get('HTTPX_PROBE_RESPONSE_TIME', True)
    HTTPX_PROBE_WORD_COUNT = settings.get('HTTPX_PROBE_WORD_COUNT', True)
    HTTPX_PROBE_LINE_COUNT = settings.get('HTTPX_PROBE_LINE_COUNT', True)
    HTTPX_PROBE_TECH_DETECT = settings.get('HTTPX_PROBE_TECH_DETECT', True)
    HTTPX_PROBE_IP = settings.get('HTTPX_PROBE_IP', True)
    HTTPX_PROBE_CNAME = settings.get('HTTPX_PROBE_CNAME', True)
    HTTPX_PROBE_TLS_INFO = settings.get('HTTPX_PROBE_TLS_INFO', True)
    HTTPX_PROBE_TLS_GRAB = settings.get('HTTPX_PROBE_TLS_GRAB', True)
    HTTPX_PROBE_FAVICON = settings.get('HTTPX_PROBE_FAVICON', True)
    HTTPX_PROBE_JARM = settings.get('HTTPX_PROBE_JARM', True)
    HTTPX_PROBE_HASH = settings.get('HTTPX_PROBE_HASH', 'sha256')
    HTTPX_INCLUDE_RESPONSE = settings.get('HTTPX_INCLUDE_RESPONSE', True)
    HTTPX_INCLUDE_RESPONSE_HEADERS = settings.get('HTTPX_INCLUDE_RESPONSE_HEADERS', True)
    HTTPX_PROBE_ASN = settings.get('HTTPX_PROBE_ASN', True)
    HTTPX_PROBE_CDN = settings.get('HTTPX_PROBE_CDN', True)
    HTTPX_PATHS = settings.get('HTTPX_PATHS', [])
    HTTPX_CUSTOM_HEADERS = settings.get('HTTPX_CUSTOM_HEADERS', [])
    HTTPX_MATCH_CODES = settings.get('HTTPX_MATCH_CODES', [])
    HTTPX_FILTER_CODES = settings.get('HTTPX_FILTER_CODES', [])

    # Convert container paths to host paths for sibling container volume mounts
    targets_host_path = get_host_path(str(Path(targets_file).parent))
    output_host_path = get_host_path(str(Path(output_file).parent))

    targets_filename = Path(targets_file).name
    output_filename = Path(output_file).name

    # Build Docker command
    cmd = [
        "docker", "run", "--rm",
        # Note: Don't use -i (interactive) when reading from file, causes deadlock
        "-v", f"{targets_host_path}:/targets:ro",
        "-v", f"{output_host_path}:/output",
    ]

    # Add image
    cmd.append(HTTPX_DOCKER_IMAGE)

    # Input/Output
    cmd.extend(["-l", f"/targets/{targets_filename}"])
    cmd.extend(["-o", f"/output/{output_filename}"])
    cmd.append("-json")
    cmd.append("-silent")
    cmd.append("-nc")  # No color

    # Performance settings
    cmd.extend(["-t", str(HTTPX_THREADS)])
    cmd.extend(["-timeout", str(HTTPX_TIMEOUT)])
    cmd.extend(["-retries", str(HTTPX_RETRIES)])

    if HTTPX_RATE_LIMIT > 0:
        cmd.extend(["-rl", str(HTTPX_RATE_LIMIT)])

    # Redirect handling
    if HTTPX_FOLLOW_REDIRECTS:
        cmd.append("-fr")
        cmd.extend(["-maxr", str(HTTPX_MAX_REDIRECTS)])

    # Probing options
    if HTTPX_PROBE_STATUS_CODE:
        cmd.append("-sc")
    if HTTPX_PROBE_CONTENT_LENGTH:
        cmd.append("-cl")
    if HTTPX_PROBE_CONTENT_TYPE:
        cmd.append("-ct")
    if HTTPX_PROBE_TITLE:
        cmd.append("-title")
    if HTTPX_PROBE_SERVER:
        cmd.append("-server")
    if HTTPX_PROBE_RESPONSE_TIME:
        cmd.append("-rt")
    if HTTPX_PROBE_WORD_COUNT:
        cmd.append("-wc")
    if HTTPX_PROBE_LINE_COUNT:
        cmd.append("-lc")

    # Technology detection
    if HTTPX_PROBE_TECH_DETECT:
        cmd.append("-td")

    # Network info
    if HTTPX_PROBE_IP:
        cmd.append("-ip")
    if HTTPX_PROBE_CNAME:
        cmd.append("-cname")

    # TLS info
    if HTTPX_PROBE_TLS_INFO:
        cmd.append("-tls-probe")
    if HTTPX_PROBE_TLS_GRAB:
        cmd.append("-tls-grab")

    # Fingerprinting
    if HTTPX_PROBE_FAVICON:
        cmd.append("-favicon")
    if HTTPX_PROBE_JARM:
        cmd.append("-jarm")
    if HTTPX_PROBE_HASH:
        cmd.extend(["-hash", HTTPX_PROBE_HASH])

    # Response inclusion
    if HTTPX_INCLUDE_RESPONSE:
        cmd.append("-irr")  # include-response (headers + body)
    if HTTPX_INCLUDE_RESPONSE_HEADERS:
        cmd.append("-irh")  # include-response-header

    # ASN and CDN
    if HTTPX_PROBE_ASN:
        cmd.append("-asn")
    if HTTPX_PROBE_CDN:
        cmd.append("-cdn")

    # Additional paths
    if HTTPX_PATHS:
        for path in HTTPX_PATHS:
            cmd.extend(["-path", path])

    # Custom headers
    if HTTPX_CUSTOM_HEADERS:
        for header in HTTPX_CUSTOM_HEADERS:
            cmd.extend(["-H", header])

    # Status code filters
    if HTTPX_MATCH_CODES:
        cmd.extend(["-mc", ",".join(HTTPX_MATCH_CODES)])
    if HTTPX_FILTER_CODES:
        cmd.extend(["-fc", ",".join(HTTPX_FILTER_CODES)])

    # Proxy support
    if use_proxy:
        cmd.extend(["-proxy", "socks5://127.0.0.1:9050"])

    return cmd


# =============================================================================
# Result Parsing
# =============================================================================

def parse_httpx_output(output_file: str, root_domain: str = None, allowed_hosts: list = None) -> Dict:
    """
    Parse httpx JSON Lines output into structured format.
    
    Args:
        output_file: Path to httpx JSON Lines output file
        root_domain: Target root domain for filtering redirects (e.g., "vulnweb.com")
                    If provided, URLs that redirect outside this domain are excluded.
        allowed_hosts: List of specific allowed hostnames (from filtered mode).
                      If provided, only URLs matching these exact hosts are included.
                      If None (full discovery mode), any host within root_domain is allowed.

    Returns:
        Structured dictionary with by_url, by_host, technologies_found, and summary
    """
    by_url = {}
    by_host = {}
    technologies_found = {}
    servers_found = {}
    filtered_count = 0  # Track URLs filtered out due to domain/host mismatch
    external_domain_entries = []  # Collect out-of-scope domains for situational awareness

    if not Path(output_file).exists():
        return {
            "by_url": {},
            "by_host": {},
            "technologies_found": {},
            "summary": {}
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

            url = entry.get("url", "")
            if not url:
                continue

            # Extract host from URL
            host = extract_host_from_url(url)

            # Filter URLs outside target scope
            # In filtered mode: only allow specific hosts from SUBDOMAIN_LIST
            # In full discovery mode: allow any host within root_domain scope
            # Also check the original input URL host (httpx may follow redirects to a different host)
            if root_domain and not is_host_in_scope(host, root_domain, allowed_hosts):
                input_url = entry.get("input", "")
                input_host = extract_host_from_url(input_url) if input_url else ""
                if not input_host or not is_host_in_scope(input_host, root_domain, allowed_hosts):
                    filtered_count += 1
                    # Collect external domain data for situational awareness
                    if host:
                        external_domain_entries.append({
                            "domain": host,
                            "source": "http_probe_redirect",
                            "url": url,
                            "redirect_from_url": input_url,
                            "status_code": entry.get("status_code") or entry.get("status-code"),
                            "title": entry.get("title"),
                            "server": entry.get("webserver") or entry.get("server"),
                        })
                    continue

            # Extract status code (tracking deferred until after by_url dedup)
            status_code = entry.get("status_code") or entry.get("status-code")

            # Build URL entry
            url_entry = {
                "url": url,
                "host": host,
                "status_code": status_code,
                "content_length": entry.get("content_length") or entry.get("content-length"),
                "content_type": entry.get("content_type") or entry.get("content-type"),
                "title": entry.get("title"),
                "server": entry.get("webserver") or entry.get("server"),
                "response_time_ms": entry.get("response_time") or entry.get("response-time"),
                "word_count": entry.get("words") or entry.get("word-count"),
                "line_count": entry.get("lines") or entry.get("line-count"),
                "technologies": entry.get("tech") or entry.get("technologies") or [],
                "ip": entry.get("host") if entry.get("host") and is_ip(entry.get("host")) else entry.get("a", [None])[0] if entry.get("a") else None,
                "cname": entry.get("cname"),
                "cdn": entry.get("cdn_name") or entry.get("cdn-name"),
                "is_cdn": bool(entry.get("cdn") or entry.get("cdn_name")),
                "asn": entry.get("asn"),
            }

            # TLS information
            tls_data = entry.get("tls") or entry.get("tls-grab") or {}
            if tls_data or entry.get("tls_version"):
                url_entry["tls"] = {
                    "version": tls_data.get("version") or entry.get("tls_version"),
                    "cipher": tls_data.get("cipher"),
                    "certificate": {
                        "subject_cn": tls_data.get("subject_cn") or entry.get("subject_cn"),
                        "issuer": tls_data.get("issuer_org") or entry.get("issuer_org"),
                        "not_before": tls_data.get("not_before"),
                        "not_after": tls_data.get("not_after"),
                        "san": tls_data.get("subject_an") or entry.get("subject_an") or [],
                    }
                }

            # Fingerprinting
            if entry.get("favicon"):
                url_entry["favicon_hash"] = entry.get("favicon")
            if entry.get("jarm"):
                url_entry["jarm"] = entry.get("jarm")
            if entry.get("hash"):
                url_entry["body_hash"] = entry.get("hash")

            # Response headers
            if entry.get("header"):
                url_entry["headers"] = entry.get("header")

            # Response body (if included)
            if entry.get("body"):
                url_entry["body"] = entry.get("body")

            # Add to by_url
            by_url[url] = url_entry

            # Track technologies
            techs = url_entry.get("technologies", [])
            if isinstance(techs, list):
                for tech in techs:
                    if tech:
                        if tech not in technologies_found:
                            technologies_found[tech] = []
                        if url not in technologies_found[tech]:
                            technologies_found[tech].append(url)

            # Track servers
            server = url_entry.get("server")
            if server:
                if server not in servers_found:
                    servers_found[server] = []
                if url not in servers_found[server]:
                    servers_found[server].append(url)

            # Build by_host entry
            if host:
                if host not in by_host:
                    by_host[host] = {
                        "hostname": host,
                        "urls": [],
                        "live_urls": [],
                        "technologies": set(),
                        "servers": set(),
                        "status_codes": set()
                    }

                by_host[host]["urls"].append(url)

                # Only track as live if status code exists and not an error
                if status_code and status_code < 500:
                    by_host[host]["live_urls"].append(url)

                for tech in techs:
                    if tech:
                        by_host[host]["technologies"].add(tech)

                if server:
                    by_host[host]["servers"].add(server)

                if status_code:
                    by_host[host]["status_codes"].add(status_code)

    # Convert sets to lists for JSON serialization
    for host in by_host:
        by_host[host]["technologies"] = sorted(list(by_host[host]["technologies"]))
        by_host[host]["servers"] = sorted(list(by_host[host]["servers"]))
        by_host[host]["status_codes"] = sorted(list(by_host[host]["status_codes"]))

    # Build status code counts from deduplicated by_url (not raw httpx lines)
    status_codes = {}
    for url_info in by_url.values():
        sc = url_info.get("status_code")
        if sc:
            sc_str = str(sc)
            status_codes[sc_str] = status_codes.get(sc_str, 0) + 1

    # Build summary
    summary = {
        "total_urls_probed": len(by_url),
        "live_urls": len([u for u in by_url.values() if u.get("status_code") and u["status_code"] < 500]),
        "total_hosts": len(by_host),
        "by_status_code": status_codes,
        "unique_technologies": sorted(list(technologies_found.keys())),
        "technology_count": len(technologies_found),
        "unique_servers": sorted(list(servers_found.keys())),
        "server_count": len(servers_found),
        "cdn_hosts": len([h for h in by_host.values() if any(
            by_url.get(u, {}).get("is_cdn") for u in h.get("urls", [])
        )]),
        "filtered_out_of_scope": filtered_count  # URLs filtered due to redirect outside target domain
    }

    return {
        "by_url": by_url,
        "by_host": by_host,
        "technologies_found": technologies_found,
        "servers_found": servers_found,
        "summary": summary,
        "external_domains": external_domain_entries,
    }


def extract_host_from_url(url: str) -> str:
    """Extract hostname from URL."""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.netloc
        # Remove port if present
        if ':' in host:
            host = host.split(':')[0]
        return host
    except Exception:
        return ""


def is_host_in_scope(host: str, root_domain: str, allowed_hosts: list = None) -> bool:
    """
    Check if a hostname is within the target scope.
    
    If allowed_hosts is provided (filtered mode), only those specific hosts are allowed.
    If allowed_hosts is None/empty (full discovery mode), any subdomain of root_domain is allowed.
    
    Args:
        host: The hostname to check
        root_domain: The target root domain
        allowed_hosts: List of specific allowed hostnames (from SUBDOMAIN_LIST filter).
                      If None or empty, allows any host within root_domain scope.
        
    Returns:
        True if host is in scope, False otherwise
    """
    if not host or not root_domain:
        return False

    host = host.lower().strip()
    root_domain = root_domain.lower().strip()

    # If allowed_hosts is specified (filtered mode), check against that list first.
    # This must come before the root_domain scope check because in IP-mode the
    # root_domain is a fake placeholder that real hostnames will never match.
    if allowed_hosts:
        allowed_set = {h.lower().strip() for h in allowed_hosts}
        return host in allowed_set

    # IP addresses bypass domain scope check
    if is_ip(host):
        return True

    # Check if host is within the root domain scope
    in_root_scope = (host == root_domain or host.endswith(f".{root_domain}"))
    return in_root_scope


def is_ip(value: str) -> bool:
    """Check if a string is an IP address."""
    if not value:
        return False
    import re
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
    return bool(re.match(ipv4_pattern, value) or re.match(ipv6_pattern, value))


# =============================================================================
# Wappalyzer Technology Enhancement
# =============================================================================

def download_wappalyzer_database(settings: dict = None) -> Optional[str]:
    """
    Download the latest Wappalyzer technologies database from npm/unpkg CDN.

    The python-Wappalyzer library is archived (Sept 2020) with an outdated database.
    This function downloads the latest fingerprints from the Wappalyzer npm package,
    which contains ~4000 technology fingerprints split into alphabetical files.

    Args:
        settings: Settings dictionary from main.py

    Returns:
        Path to downloaded technologies.json file, or None if download fails
    """
    import requests
    import time

    if settings is None:
        settings = {}

    # Extract settings from passed dict
    WAPPALYZER_AUTO_UPDATE = settings.get('WAPPALYZER_AUTO_UPDATE', True)
    WAPPALYZER_CACHE_TTL_HOURS = settings.get('WAPPALYZER_CACHE_TTL_HOURS', 24)
    WAPPALYZER_NPM_VERSION = settings.get('WAPPALYZER_NPM_VERSION', '6.10.56')
    # Wappalyzer URLs and paths (files are at root, not in /src/)
    WAPPALYZER_BASE_URL = f"https://unpkg.com/wappalyzer@{WAPPALYZER_NPM_VERSION}"
    WAPPALYZER_CATEGORIES_URL = f"{WAPPALYZER_BASE_URL}/categories.json"
    WAPPALYZER_CACHE_DIR = Path(__file__).parent / "data" / "wappalyzer_cache"
    WAPPALYZER_CACHE_FILE = WAPPALYZER_CACHE_DIR / "technologies.json"

    if not WAPPALYZER_AUTO_UPDATE:
        return None

    # Ensure cache directory exists
    os.makedirs(WAPPALYZER_CACHE_DIR, exist_ok=True)

    # Check if cache exists and is fresh
    if os.path.exists(WAPPALYZER_CACHE_FILE) and WAPPALYZER_CACHE_TTL_HOURS > 0:
        file_age_hours = (time.time() - os.path.getmtime(WAPPALYZER_CACHE_FILE)) / 3600
        if file_age_hours < WAPPALYZER_CACHE_TTL_HOURS:
            # Load cached file to get tech count
            try:
                with open(WAPPALYZER_CACHE_FILE, 'r') as f:
                    cached_data = json.load(f)
                tech_count = len(cached_data.get('technologies', {}))
                print(f"[*][httpx] Using cached Wappalyzer DB ({tech_count} technologies, {file_age_hours:.1f}h old)")
            except:
                print(f"[*][httpx] Using cached Wappalyzer DB ({file_age_hours:.1f}h old)")
            return str(WAPPALYZER_CACHE_FILE)

    print("[*][httpx] Downloading latest Wappalyzer technologies database...")

    try:
        # Download categories
        print("[*][httpx] Downloading categories...", end=" ", flush=True)
        categories_resp = requests.get(WAPPALYZER_CATEGORIES_URL, timeout=10)
        categories_resp.raise_for_status()
        categories_data = categories_resp.json()
        print("OK")

        # Download and merge all technology files (_.json, a.json through z.json)
        technologies_data = {}
        tech_files = ['_'] + list('abcdefghijklmnopqrstuvwxyz')

        print("[*][httpx] Downloading technologies: ", end="", flush=True)
        for letter in tech_files:
            url = f"{WAPPALYZER_BASE_URL}/technologies/{letter}.json"
            try:
                resp = requests.get(url, timeout=5)
                if resp.status_code == 200:
                    tech_data = resp.json()
                    technologies_data.update(tech_data)
                    print(letter, end="", flush=True)
            except Exception:
                print(".", end="", flush=True)
        print(" Done")

        if not technologies_data:
            raise Exception("No technology data downloaded")

        # Normalize technologies for compatibility with python-Wappalyzer
        # The library expects strings, but newer DB has lists in some fields
        def normalize_tech(tech_data):
            """Convert list patterns to strings for python-Wappalyzer compatibility."""
            normalized = {}
            for key, value in tech_data.items():
                if isinstance(value, list):
                    # Convert list to first item if it's a pattern list
                    if key in ['headers', 'meta', 'cookies']:
                        # These should be dicts
                        if all(isinstance(v, dict) for v in value):
                            merged = {}
                            for item in value:
                                merged.update(item)
                            normalized[key] = merged
                        else:
                            normalized[key] = value[0] if value else ""
                    else:
                        normalized[key] = value
                elif isinstance(value, dict):
                    # Recursively normalize nested dicts (headers, meta, etc.)
                    norm_dict = {}
                    for k, v in value.items():
                        if isinstance(v, list):
                            norm_dict[k] = v[0] if v else ""
                        else:
                            norm_dict[k] = v
                    normalized[key] = norm_dict
                else:
                    normalized[key] = value
            return normalized

        normalized_technologies = {}
        for name, data in technologies_data.items():
            normalized_technologies[name] = normalize_tech(data)

        # Combine into the format expected by python-Wappalyzer
        combined_data = {
            "categories": categories_data,
            "technologies": normalized_technologies
        }

        # Save to cache
        with open(WAPPALYZER_CACHE_FILE, 'w') as f:
            json.dump(combined_data, f)

        tech_count = len(technologies_data)
        print(f"[✓][httpx] Downloaded {tech_count} technology fingerprints")
        return str(WAPPALYZER_CACHE_FILE)

    except requests.exceptions.RequestException as e:
        print(f"[!][httpx] Failed to download Wappalyzer DB: {e}")
        # Fall back to cached version if available
        if os.path.exists(WAPPALYZER_CACHE_FILE):
            print("[*][httpx] Using previously cached database")
            return str(WAPPALYZER_CACHE_FILE)
        print("[*][httpx] Will use bundled (outdated) database")
        return None
    except Exception as e:
        print(f"[!][httpx] Error processing Wappalyzer DB: {e}")
        if os.path.exists(WAPPALYZER_CACHE_FILE):
            print("[*][httpx] Using previously cached database")
            return str(WAPPALYZER_CACHE_FILE)
        return None


def enhance_with_wappalyzer(httpx_results: Dict, settings: dict = None) -> Dict:
    """
    Enhance httpx technology detection with Wappalyzer's full pattern database.
    Uses existing HTML from httpx (no additional HTTP requests needed).

    Args:
        httpx_results: Dictionary containing httpx scan results with HTML bodies
        settings: Settings dictionary from main.py

    Returns:
        Enhanced httpx_results with additional technologies and wappalyzer section
    """
    if settings is None:
        settings = {}

    # Extract settings from passed dict
    WAPPALYZER_ENABLED = settings.get('WAPPALYZER_ENABLED', True)
    WAPPALYZER_MIN_CONFIDENCE = settings.get('WAPPALYZER_MIN_CONFIDENCE', 50)
    WAPPALYZER_REQUIRE_HTML = settings.get('WAPPALYZER_REQUIRE_HTML', True)

    if not WAPPALYZER_ENABLED:
        return httpx_results

    try:
        from Wappalyzer import Wappalyzer, WebPage
    except ImportError:
        print("[!][httpx] Wappalyzer not installed - skipping enhancement")
        print("[*][httpx] Install with: pip install python-Wappalyzer")
        return httpx_results

    print("\n[*][httpx] Enhancing technology detection with Wappalyzer...")

    # Try to get latest database, fall back to bundled if unavailable
    technologies_file = download_wappalyzer_database(settings)
    if technologies_file:
        wappalyzer = Wappalyzer.latest(technologies_file=technologies_file)
    else:
        wappalyzer = Wappalyzer.latest()

    wappalyzer_data = {
        "scan_metadata": {
            "scan_timestamp": datetime.now().isoformat(),
            "min_confidence": WAPPALYZER_MIN_CONFIDENCE,
            "urls_analyzed": 0,
            "new_technologies_found": 0,
        },
        "by_url": {},
        "new_technologies": {},  # Techs found by Wappalyzer but NOT httpx
        "all_technologies": {},  # Full Wappalyzer data with versions/categories
        "summary": {}
    }

    urls_analyzed = 0
    new_tech_count = 0

    for url, url_data in httpx_results.get("by_url", {}).items():
        html = url_data.get("body", "")
        headers = url_data.get("headers", {})

        # Check if HTML is required
        if WAPPALYZER_REQUIRE_HTML and not html:
            continue
        
        # Skip if no HTML and require_html is True
        if not html:
            continue
        
        try:
            # Convert headers dict to format expected by WebPage
            # IMPORTANT: httpx stores headers with underscores (x_powered_by)
            # but Wappalyzer expects dashes (x-powered-by)
            headers_dict = {}
            if isinstance(headers, dict):
                for key, value in headers.items():
                    # Convert underscores to dashes for Wappalyzer compatibility
                    corrected_key = key.replace('_', '-')
                    headers_dict[corrected_key] = value
            elif isinstance(headers, str):
                # Parse header string if needed
                for line in headers.split('\n'):
                    if ':' in line:
                        key, value = line.split(':', 1)
                        headers_dict[key.strip()] = value.strip()
            
            # Analyze with Wappalyzer (using existing HTML - no HTTP request)
            # Use direct constructor instead of new_from_url() to avoid making HTTP requests
            webpage = WebPage(url, html=html, headers=headers_dict)
            # Returns dict: {'TechName': {'versions': [...], 'categories': [...]}, ...}
            wap_results = wappalyzer.analyze_with_versions_and_categories(webpage)
            
            urls_analyzed += 1
            httpx_techs = set(url_data.get("technologies", []))
            # Also check for versioned httpx techs (e.g., "Nginx:1.19.0" -> "Nginx")
            httpx_tech_names = set(t.split(':')[0] for t in httpx_techs)
            
            # Process each detected technology (dict format)
            url_techs = []
            for tech_name, tech_data in wap_results.items():
                # Get confidence level for this technology
                confidence = wappalyzer.get_confidence(tech_name)
                # Handle case where confidence is a list or not available
                if isinstance(confidence, list):
                    confidence = confidence[0] if confidence else 100
                elif not confidence:
                    confidence = 100  # Default to 100 if not available
                
                # Filter by minimum confidence threshold
                if confidence < WAPPALYZER_MIN_CONFIDENCE:
                    continue
                
                versions = tech_data.get('versions', [])
                categories = tech_data.get('categories', [])
                # Get the first version if available
                version = versions[0] if versions else None
                
                tech_entry = {
                    "name": tech_name,
                    "version": version,
                    "categories": categories,
                    "versions_all": versions,
                    "confidence": confidence
                }
                url_techs.append(tech_entry)
                
                # Track by technology name
                if tech_name not in wappalyzer_data["all_technologies"]:
                    wappalyzer_data["all_technologies"][tech_name] = {
                        "name": tech_name,
                        "versions_found": set(),
                        "categories": set(),
                        "urls": [],
                        "confidence": confidence
                    }
                
                for v in versions:
                    wappalyzer_data["all_technologies"][tech_name]["versions_found"].add(v)
                wappalyzer_data["all_technologies"][tech_name]["categories"].update(categories)
                wappalyzer_data["all_technologies"][tech_name]["urls"].append(url)
                # Update confidence if higher
                if confidence > wappalyzer_data["all_technologies"][tech_name]["confidence"]:
                    wappalyzer_data["all_technologies"][tech_name]["confidence"] = confidence
                
                # Check if this is NEW (not found by httpx)
                if tech_name not in httpx_tech_names:
                    new_tech_count += 1
                    if tech_name not in wappalyzer_data["new_technologies"]:
                        wappalyzer_data["new_technologies"][tech_name] = []
                    wappalyzer_data["new_technologies"][tech_name].append(url)
                    
                    # MERGE: Add new technology to httpx results
                    if "technologies" not in url_data:
                        url_data["technologies"] = []
                    # Add with version if available
                    tech_str = f"{tech_name}:{version}" if version else tech_name
                    if tech_str not in url_data["technologies"] and tech_name not in url_data["technologies"]:
                        url_data["technologies"].append(tech_str)
                
            
            wappalyzer_data["by_url"][url] = url_techs
            
            # Update by_host technologies
            host = url_data.get("host", "")
            if host and host in httpx_results.get("by_host", {}):
                host_data = httpx_results["by_host"][host]
                wap_tech_names = set(wap_results.keys())
                if isinstance(host_data.get("technologies"), list):
                    host_data["technologies"] = list(set(host_data["technologies"]) | wap_tech_names)
                else:
                    host_data["technologies"] = list(wap_tech_names)
            
        except Exception as e:
            # Silently continue on errors (Wappalyzer can fail on malformed HTML)
            continue
    
    # Convert sets to lists for JSON serialization
    for tech_name, tech_data in wappalyzer_data["all_technologies"].items():
        tech_data["versions_found"] = list(tech_data["versions_found"])
        tech_data["categories"] = list(tech_data["categories"])
    
    # Build summary
    wappalyzer_data["scan_metadata"]["urls_analyzed"] = urls_analyzed
    wappalyzer_data["scan_metadata"]["new_technologies_found"] = len(wappalyzer_data["new_technologies"])

    wappalyzer_data["summary"] = {
        "urls_analyzed": urls_analyzed,
        "total_technologies": len(wappalyzer_data["all_technologies"]),
        "new_technologies": len(wappalyzer_data["new_technologies"]),
        "httpx_missed": list(wappalyzer_data["new_technologies"].keys()),
    }
    
    # Add wappalyzer section to httpx_results
    httpx_results["wappalyzer"] = wappalyzer_data
    
    # Update summary technologies count
    if "summary" in httpx_results:
        all_techs = set()
        for url_data in httpx_results.get("by_url", {}).values():
            all_techs.update(url_data.get("technologies", []))
        httpx_results["summary"]["unique_technologies"] = sorted(list(all_techs))
        httpx_results["summary"]["technology_count"] = len(all_techs)
        httpx_results["summary"]["wappalyzer_additions"] = len(wappalyzer_data["new_technologies"])
    
    # Print summary
    if urls_analyzed > 0:
        print(f"[✓][httpx] Wappalyzer enhancement complete")
        print(f"[*][httpx] URLs analyzed: {urls_analyzed}")
        print(f"[*][httpx] New technologies found: {len(wappalyzer_data['new_technologies'])}")
        if wappalyzer_data["new_technologies"]:
            new_techs_list = list(wappalyzer_data["new_technologies"].keys())[:10]
            print(f"[*][httpx] New techs: {', '.join(new_techs_list)}" +
                  ("..." if len(wappalyzer_data["new_technologies"]) > 10 else ""))
    
    return httpx_results


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
        pass


# =============================================================================
# Main Scan Function
# =============================================================================

def run_http_probe(recon_data: dict, output_file: Path = None, settings: dict = None) -> dict:
    """
    Run httpx HTTP probing on targets.

    Args:
        recon_data: Dictionary containing naabu/DNS data
        output_file: Path to save enriched results (optional)
        settings: Settings dictionary from main.py

    Returns:
        Enriched recon_data with "http_probe" section added
    """
    print("\n" + "="*60)
    print("[*][httpx] HTTPX HTTP PROBER")
    print("="*60)

    # Use passed settings or empty dict as fallback
    if settings is None:
        settings = {}

    # Extract settings from passed dict
    HTTPX_DOCKER_IMAGE = settings.get('HTTPX_DOCKER_IMAGE', 'projectdiscovery/httpx:latest')
    HTTPX_THREADS = settings.get('HTTPX_THREADS', 50)
    HTTPX_TIMEOUT = settings.get('HTTPX_TIMEOUT', 10)
    HTTPX_RATE_LIMIT = settings.get('HTTPX_RATE_LIMIT', 50)
    HTTPX_FOLLOW_REDIRECTS = settings.get('HTTPX_FOLLOW_REDIRECTS', True)
    HTTPX_PROBE_TECH_DETECT = settings.get('HTTPX_PROBE_TECH_DETECT', True)
    HTTPX_PROBE_TLS_INFO = settings.get('HTTPX_PROBE_TLS_INFO', True)
    HTTPX_INCLUDE_RESPONSE = settings.get('HTTPX_INCLUDE_RESPONSE', True)
    USE_TOR_FOR_RECON = settings.get('USE_TOR_FOR_RECON', False)
    BANNER_GRAB_ENABLED = settings.get('BANNER_GRAB_ENABLED', True)

    # Check Docker
    if not is_docker_installed():
        print("[!][httpx] Docker is not installed. Please install Docker first.")
        return recon_data

    if not is_docker_running():
        print("[!][httpx] Docker daemon is not running. Please start Docker.")
        return recon_data

    # Pull image if needed
    if not pull_httpx_docker_image(HTTPX_DOCKER_IMAGE):
        print("[!][httpx] Failed to get httpx Docker image")
        return recon_data

    # Check Tor if enabled
    use_proxy = False
    if USE_TOR_FOR_RECON:
        if is_tor_running():
            print("[✓][httpx] Tor proxy detected - enabling anonymous probing")
            use_proxy = True
        else:
            print("[!][httpx] Tor not running - probing without proxy")

    # Build target URLs
    print("\n[*][httpx] Building target URLs...")

    # Prefer naabu results, fallback to DNS
    if recon_data.get("port_scan"):
        urls = build_targets_from_naabu(recon_data)
        # build_targets_from_naabu falls back to DNS internally if no ports found
        has_ports = bool(recon_data["port_scan"].get("by_host"))
        if has_ports:
            print(f"[*][httpx] Built {len(urls)} URLs from Naabu port scan results")
        else:
            print(f"[*][httpx] Built {len(urls)} URLs from DNS fallback (Naabu found no open ports)")
    else:
        urls = build_targets_from_dns(recon_data)
        print(f"[*][httpx] Built {len(urls)} URLs from DNS data (no Naabu results)")

    if not urls:
        print("[!][httpx] No URLs to probe")
        return recon_data

    # Create temp directory for scan files
    # Use /tmp/redamon to avoid spaces in paths (snap Docker issue)
    scan_temp_dir = Path("/tmp/redamon/.httpx_temp")
    scan_temp_dir.mkdir(parents=True, exist_ok=True)

    try:
        # Write targets file
        targets_file = scan_temp_dir / "targets.txt"
        with open(targets_file, 'w') as f:
            for url in urls:
                f.write(f"{url}\n")

        # Set output file
        httpx_output = scan_temp_dir / "httpx_output.json"

        # Build and run command
        cmd = build_httpx_command(str(targets_file), str(httpx_output), settings, use_proxy)

        print(f"\n[*][httpx] Starting httpx probe...")
        print(f"[*][httpx] URLs to probe: {len(urls)}")
        print(f"[*][httpx] Threads: {HTTPX_THREADS}")
        print(f"[*][httpx] Timeout: {HTTPX_TIMEOUT}s")
        print(f"[*][httpx] Rate limit: {HTTPX_RATE_LIMIT} req/s")
        print(f"[*][httpx] Follow redirects: {HTTPX_FOLLOW_REDIRECTS}")

        if HTTPX_PROBE_TECH_DETECT:
            print(f"[*][httpx] Technology detection: enabled")
        if HTTPX_PROBE_TLS_INFO:
            print(f"[*][httpx] TLS probing: enabled")
        if HTTPX_INCLUDE_RESPONSE:
            print(f"[*][httpx] Response body: included")
        print(f"[*][httpx] Banner grabbing: {BANNER_GRAB_ENABLED}")

        start_time = datetime.now()

        # Execute probe
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # Safety-net timeout: num_urls * per-url timeout (worst case if all sequential)
        # Under normal parallel operation this will never trigger
        safety_timeout = len(urls) * HTTPX_TIMEOUT
        _, stderr = process.communicate(timeout=safety_timeout)

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        if process.returncode != 0 and not httpx_output.exists():
            print(f"[!][httpx] Probe failed: {stderr[:200] if stderr else 'Unknown error'}")
            return recon_data

        # Parse results (filter URLs outside target scope)
        print(f"\n[*][httpx] Parsing results...")
        root_domain = recon_data.get("domain", "") or recon_data.get("metadata", {}).get("root_domain", "")
        
        # Get allowed hosts for filtering (from SUBDOMAIN_LIST filter)
        # In filtered mode: subdomain_filter contains the explicit list of allowed hosts
        # In full discovery mode (subdomain_filter empty): allow any host in root_domain scope
        metadata = recon_data.get("metadata", {})
        filtered_mode = metadata.get("filtered_mode", False)
        allowed_hosts = None
        if filtered_mode:
            # Use the subdomain_filter which contains the full subdomain names
            allowed_hosts = metadata.get("subdomain_filter", [])
            if allowed_hosts:
                print(f"[*][httpx] Filtering to allowed hosts: {', '.join(allowed_hosts)}")
        
        results = parse_httpx_output(str(httpx_output), root_domain=root_domain, allowed_hosts=allowed_hosts)
        
        # Log if any URLs were filtered out
        filtered_count = results.get("summary", {}).get("filtered_out_of_scope", 0)
        if filtered_count > 0:
            print(f"[*][httpx] Filtered {filtered_count} URL(s) outside target scope")

        # Build final structure
        httpx_results = {
            "scan_metadata": {
                "scan_timestamp": start_time.isoformat(),
                "scan_duration_seconds": round(duration, 2),
                "docker_image": HTTPX_DOCKER_IMAGE,
                "threads": HTTPX_THREADS,
                "timeout": HTTPX_TIMEOUT,
                "rate_limit": HTTPX_RATE_LIMIT,
                "follow_redirects": HTTPX_FOLLOW_REDIRECTS,
                "tech_detection": HTTPX_PROBE_TECH_DETECT,
                "tls_probing": HTTPX_PROBE_TLS_INFO,
                "response_included": HTTPX_INCLUDE_RESPONSE,
                "proxy_used": use_proxy,
                "total_urls_probed": len(urls),
                "root_domain_filter": root_domain,
                "filtered_mode": filtered_mode,
                "allowed_hosts_filter": allowed_hosts  # Specific hosts allowed (None = all in scope)
            },
            "by_url": results["by_url"],
            "by_host": results["by_host"],
            "technologies_found": results["technologies_found"],
            "servers_found": results.get("servers_found", {}),
            "summary": results["summary"]
        }

        # Print summary
        summary = results["summary"]
        print(f"\n[✓][httpx] Probe completed in {duration:.1f} seconds")
        print(f"[*][httpx] URLs probed: {summary['total_urls_probed']}")
        print(f"[*][httpx] Live URLs: {summary['live_urls']}")
        print(f"[*][httpx] Unique hosts: {summary['total_hosts']}")

        if summary.get('technology_count', 0) > 0:
            print(f"[*][httpx] Technologies detected: {summary['technology_count']}")
            techs = summary.get('unique_technologies', [])[:10]
            if techs:
                print(f"[*][httpx] {', '.join(techs)}" + ("..." if len(summary.get('unique_technologies', [])) > 10 else ""))

        if summary.get('by_status_code'):
            codes = summary['by_status_code']
            code_str = ", ".join([f"{k}:{v}" for k, v in sorted(codes.items())[:5]])
            print(f"[*][httpx] Status codes: {code_str}")

        # Enhance with Wappalyzer (uses existing HTML from httpx)
        httpx_results = enhance_with_wappalyzer(httpx_results, settings)

        # Remove body from results to keep JSON small (already used for analysis)
        for url_data in httpx_results.get("by_url", {}).values():
            url_data.pop("body", None)

        # Add to recon_data
        recon_data["http_probe"] = httpx_results

        # Run banner grabbing for non-HTTP ports
        if BANNER_GRAB_ENABLED and recon_data.get("port_scan"):
            banner_results = run_banner_grab(recon_data, settings)
            if banner_results:
                recon_data["banner_grab"] = banner_results

        # Save incrementally
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(recon_data, f, indent=2, default=str)
            fix_file_ownership(output_file)
            print(f"\n[✓][httpx] Results saved to {output_file}")

        return recon_data

    except subprocess.TimeoutExpired:
        process.kill()
        print(f"[!][httpx] Probe hit safety timeout ({len(urls)} urls * {HTTPX_TIMEOUT}s = {safety_timeout}s)")
        return recon_data
    except Exception as e:
        print(f"[!][httpx] Error during probe: {e}")
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
    Enrich an existing recon JSON file with httpx probe results.

    Args:
        recon_file: Path to existing recon JSON file

    Returns:
        Enriched recon data
    """
    # Load settings for standalone usage
    from recon.project_settings import get_settings
    settings = get_settings()

    print(f"\n[*][httpx] Loading recon file: {recon_file}")

    with open(recon_file, 'r') as f:
        recon_data = json.load(f)

    enriched = run_http_probe(recon_data, output_file=recon_file, settings=settings)

    return enriched
