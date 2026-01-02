"""
RedAmon - Vulnerability Scanner Module
======================================
Template-based vulnerability scanning.
Enriches reconnaissance data with comprehensive web application vulnerability detection:
- CVE detection (8000+ templates)
- Web application vulnerabilities (SQLi, XSS, RCE, etc.)
- Exposed panels and sensitive files
- Misconfigurations
- Default credentials
- Cloud security issues
- Technology fingerprinting

Scans both IPs and hostnames (subdomains) for complete coverage.
Organizes results by target in the JSON output.
Supports proxy/Tor for anonymous scanning.
"""

import json
import subprocess
import shutil
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set, Tuple, Optional
import sys

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import re
import time
import requests

from params import (
    NUCLEI_SEVERITY,
    NUCLEI_TEMPLATES,
    NUCLEI_EXCLUDE_TEMPLATES,
    NUCLEI_RATE_LIMIT,
    NUCLEI_BULK_SIZE,
    NUCLEI_CONCURRENCY,
    NUCLEI_TIMEOUT,
    NUCLEI_RETRIES,
    NUCLEI_TAGS,
    NUCLEI_EXCLUDE_TAGS,
    NUCLEI_DAST_MODE,
    NUCLEI_NEW_TEMPLATES_ONLY,
    NUCLEI_CUSTOM_TEMPLATES,
    NUCLEI_HEADLESS,
    NUCLEI_SYSTEM_RESOLVERS,
    NUCLEI_FOLLOW_REDIRECTS,
    NUCLEI_MAX_REDIRECTS,
    NUCLEI_SCAN_ALL_IPS,
    NUCLEI_INTERACTSH,
    NUCLEI_DOCKER_IMAGE,
    USE_TOR_FOR_RECON,
    # Katana crawler settings (for DAST mode)
    KATANA_DOCKER_IMAGE,
    KATANA_DEPTH,
    KATANA_MAX_URLS,
    KATANA_RATE_LIMIT,
    KATANA_TIMEOUT,
    KATANA_JS_CRAWL,
    KATANA_PARAMS_ONLY,
    KATANA_SCOPE,
    KATANA_CUSTOM_HEADERS,
    # Template auto-update
    NUCLEI_AUTO_UPDATE_TEMPLATES,
    # CVE Lookup settings
    CVE_LOOKUP_ENABLED,
    CVE_LOOKUP_SOURCE,
    CVE_LOOKUP_MAX_CVES,
    CVE_LOOKUP_MIN_CVSS,
    VULNERS_API_KEY,
)


# =============================================================================
# Severity Definitions
# =============================================================================

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]

SEVERITY_COLORS = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
    "unknown": "⚫"
}


def is_docker_installed() -> bool:
    """Check if Docker is installed and accessible."""
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


def pull_nuclei_docker_image() -> bool:
    """Pull the nuclei Docker image if not present."""
    try:
        print(f"    [*] Pulling Docker image: {NUCLEI_DOCKER_IMAGE}...")
        result = subprocess.run(
            ["docker", "pull", NUCLEI_DOCKER_IMAGE],
            capture_output=True,
            text=True,
            timeout=300
        )
        return result.returncode == 0
    except Exception:
        return False


# Volume name for persistent nuclei templates
NUCLEI_TEMPLATES_VOLUME = "nuclei-templates"


def ensure_templates_volume() -> bool:
    """
    Ensure the nuclei-templates Docker volume exists and has templates.
    Creates the volume and downloads templates if needed.
    
    Returns:
        True if templates are ready, False otherwise
    """
    try:
        # Check if volume exists
        result = subprocess.run(
            ["docker", "volume", "inspect", NUCLEI_TEMPLATES_VOLUME],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        volume_exists = result.returncode == 0
        needs_download = False
        
        if not volume_exists:
            print(f"    [*] Creating templates volume: {NUCLEI_TEMPLATES_VOLUME}...")
            subprocess.run(
                ["docker", "volume", "create", NUCLEI_TEMPLATES_VOLUME],
                capture_output=True,
                text=True,
                timeout=30
            )
            needs_download = True  # New volume, definitely needs templates
        else:
            # Volume exists - check if it has templates by counting .yaml files
            check_result = subprocess.run(
                ["docker", "run", "--rm", 
                 "-v", f"{NUCLEI_TEMPLATES_VOLUME}:/root/nuclei-templates",
                 "alpine", 
                 "sh", "-c", "find /root/nuclei-templates -name '*.yaml' 2>/dev/null | head -5 | wc -l"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            template_count = int(check_result.stdout.strip()) if check_result.stdout.strip().isdigit() else 0
            needs_download = template_count == 0
        
        # Download templates if needed OR auto-update is enabled
        if needs_download:
            print(f"    [*] Downloading nuclei templates (first run, this may take a minute)...")
        elif NUCLEI_AUTO_UPDATE_TEMPLATES:
            print(f"    [*] Checking for template updates...")
        
        if needs_download or NUCLEI_AUTO_UPDATE_TEMPLATES:
            update_result = subprocess.run(
                ["docker", "run", "--rm",
                 "-v", f"{NUCLEI_TEMPLATES_VOLUME}:/root/nuclei-templates",
                 NUCLEI_DOCKER_IMAGE,
                 "-ut"],  # Update templates
                capture_output=True,
                text=True,
                timeout=600  # 10 minutes for initial download
            )
            
            if update_result.returncode != 0:
                print(f"    [!] Warning: Template update may have issues")
                if update_result.stderr:
                    # Filter out info messages
                    errors = [l for l in update_result.stderr.split('\n') if 'FTL' in l or 'ERR' in l]
                    if errors:
                        print(f"    [!] {errors[0][:200]}")
            else:
                # Parse update info from output
                if update_result.stdout:
                    for line in update_result.stdout.split('\n'):
                        if 'Successfully updated' in line or 'already up to date' in line.lower():
                            print(f"    [✓] {line.strip()[:80]}")
                            break
                    else:
                        print(f"    [✓] Templates updated successfully")
                else:
                    print(f"    [✓] Templates ready")
        else:
            print(f"    [✓] Templates volume ready (auto-update disabled)")
        
        return True
        
    except subprocess.TimeoutExpired:
        print(f"    [!] Timeout while setting up templates")
        return False
    except Exception as e:
        print(f"    [!] Error setting up templates: {e}")
        return False


# =============================================================================
# Katana Web Crawler Functions (for DAST mode)
# =============================================================================

def pull_katana_docker_image() -> bool:
    """Pull the Katana Docker image if not present."""
    try:
        print(f"    [*] Pulling Katana image: {KATANA_DOCKER_IMAGE}...")
        result = subprocess.run(
            ["docker", "pull", KATANA_DOCKER_IMAGE],
            capture_output=True,
            text=True,
            timeout=300
        )
        return result.returncode == 0
    except Exception:
        return False


def run_katana_crawler(target_urls: List[str], use_proxy: bool = False) -> List[str]:
    """
    Run Katana crawler to discover URLs with parameters for DAST fuzzing.
    
    Args:
        target_urls: Base URLs to crawl (e.g., ["http://example.com"])
        use_proxy: Whether to use Tor proxy
        
    Returns:
        List of discovered URLs with parameters
    """
    print(f"\n[*] Running Katana crawler to discover URLs with parameters...")
    print(f"    Crawl depth: {KATANA_DEPTH}")
    print(f"    Max URLs: {KATANA_MAX_URLS}")
    print(f"    Rate limit: {KATANA_RATE_LIMIT} req/s")
    
    discovered_urls = set()
    
    for base_url in target_urls:
        # Only crawl http/https URLs (skip non-standard ports for base crawl)
        if not base_url.startswith(('http://', 'https://')):
            continue
            
        # Build Katana command
        cmd = [
            "docker", "run", "--rm",
        ]

        # Add network host mode for Tor proxy access
        if use_proxy:
            cmd.extend(["--network", "host"])

        # Mount tmp directory for Chrome/headless browser (needed for JS crawling)
        cmd.extend(["-v", "/tmp:/tmp"])

        cmd.extend([
            KATANA_DOCKER_IMAGE,
            "-u", base_url,
            "-d", str(KATANA_DEPTH),
            "-silent",
            "-nc",  # No color
            "-rl", str(KATANA_RATE_LIMIT),
            "-timeout", str(KATANA_TIMEOUT),
            "-fs", KATANA_SCOPE,  # Field scope
        ])
        
        # JavaScript crawling
        if KATANA_JS_CRAWL:
            cmd.append("-jc")  # JavaScript crawl
        
        # Custom headers for authentication (cookies, tokens, etc.)
        if KATANA_CUSTOM_HEADERS:
            for header in KATANA_CUSTOM_HEADERS:
                cmd.extend(["-H", header])
        
        # Proxy for Tor
        if use_proxy:
            cmd.extend(["-proxy", "socks5://127.0.0.1:9050"])
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=KATANA_TIMEOUT + 60  # Extra buffer
            )
            
            if result.stdout:
                for line in result.stdout.strip().split('\n'):
                    url = line.strip()
                    if url:
                        # Filter for URLs with parameters if enabled
                        if KATANA_PARAMS_ONLY:
                            if '?' in url and '=' in url:
                                discovered_urls.add(url)
                        else:
                            discovered_urls.add(url)
                        
                        # Stop if we've reached max URLs
                        if len(discovered_urls) >= KATANA_MAX_URLS:
                            break
                            
        except subprocess.TimeoutExpired:
            print(f"    [!] Katana timeout for {base_url}")
        except Exception as e:
            print(f"    [!] Katana error for {base_url}: {e}")
        
        if len(discovered_urls) >= KATANA_MAX_URLS:
            break
    
    urls_list = sorted(list(discovered_urls))
    
    print(f"    [✓] Katana found {len(urls_list)} URLs with parameters")
    if urls_list:
        print(f"    Sample URLs:")
        for url in urls_list[:5]:
            print(f"      - {url[:80]}{'...' if len(url) > 80 else ''}")
        if len(urls_list) > 5:
            print(f"      ... and {len(urls_list) - 5} more")
    
    return urls_list


def is_tor_running() -> bool:
    """Check if Tor is running by testing SOCKS proxy."""
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex(('127.0.0.1', 9050))
        sock.close()
        return result == 0
    except Exception:
        return False


def extract_targets_from_recon(recon_data: dict) -> Tuple[Set[str], Set[str], Dict[str, List[str]]]:
    """
    Extract all unique IPs, hostnames, and build IP-to-hostname mapping.
    
    Args:
        recon_data: The domain reconnaissance JSON data
        
    Returns:
        Tuple of (unique_ips, unique_hostnames, ip_to_hostnames_mapping)
    """
    ips = set()
    hostnames = set()
    ip_to_hostnames = {}
    
    dns_data = recon_data.get("dns", {})
    if not dns_data:
        return ips, hostnames, ip_to_hostnames
    
    # Extract from root domain
    domain = recon_data.get("domain", "") or recon_data.get("metadata", {}).get("target", "")
    domain_dns = dns_data.get("domain", {})
    if domain_dns:
        domain_ips = domain_dns.get("ips", {})
        ipv4_list = domain_ips.get("ipv4", [])
        ipv6_list = domain_ips.get("ipv6", [])
        
        ips.update(ipv4_list)
        ips.update(ipv6_list)
        
        if domain:
            hostnames.add(domain)
            for ip in ipv4_list + ipv6_list:
                if ip:
                    if ip not in ip_to_hostnames:
                        ip_to_hostnames[ip] = []
                    if domain not in ip_to_hostnames[ip]:
                        ip_to_hostnames[ip].append(domain)
    
    # Extract from all subdomains
    subdomains_dns = dns_data.get("subdomains", {})
    for subdomain, subdomain_data in subdomains_dns.items():
        if subdomain_data:
            if subdomain_data.get("has_records"):
                hostnames.add(subdomain)
            
            if subdomain_data.get("ips"):
                ipv4_list = subdomain_data["ips"].get("ipv4", [])
                ipv6_list = subdomain_data["ips"].get("ipv6", [])
                
                ips.update(ipv4_list)
                ips.update(ipv6_list)
                
                for ip in ipv4_list + ipv6_list:
                    if ip:
                        if ip not in ip_to_hostnames:
                            ip_to_hostnames[ip] = []
                        if subdomain not in ip_to_hostnames[ip]:
                            ip_to_hostnames[ip].append(subdomain)
    
    # Filter out empty strings
    ips = {ip for ip in ips if ip}
    hostnames = {h for h in hostnames if h}
    
    return ips, hostnames, ip_to_hostnames


def build_target_urls_from_httpx(httpx_data: Optional[dict]) -> List[str]:
    """
    Build list of target URLs from httpx scan results.
    Uses live URLs discovered by httpx for more accurate targeting.
    
    Args:
        httpx_data: httpx scan results containing live URLs
        
    Returns:
        List of live URLs to scan
    """
    urls = []
    
    if httpx_data:
        # Use live URLs from httpx (already verified to be responding)
        by_url = httpx_data.get("by_url", {})
        for url, url_data in by_url.items():
            status_code = url_data.get("status_code")
            # Include URLs with successful responses (not server errors)
            if status_code and status_code < 500:
                urls.append(url)
    
    return sorted(list(set(urls)))


def build_target_urls_from_naabu(naabu_data: Optional[dict], hostnames: Set[str]) -> List[str]:
    """
    Build list of target URLs from naabu port scan results.
    Falls back to default ports if naabu data is not available.
    
    Args:
        naabu_data: naabu scan results containing open ports
        hostnames: Set of hostnames to scan
        
    Returns:
        List of URLs to scan
    """
    urls = []
    
    # Common HTTPS ports
    https_ports = {443, 8443, 4443, 9443}
    # Common HTTP ports
    http_ports = {80, 8080, 8000, 8888, 3000, 5000, 9000}
    
    if naabu_data:
        # Build URLs from naabu port discovery
        by_host = naabu_data.get("by_host", {})
        for host, data in by_host.items():
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
                    urls.append(f"https://{host}:{port}")
                elif port in http_ports:
                    urls.append(f"http://{host}:{port}")
                else:
                    # Unknown port - try both protocols
                    urls.append(f"http://{host}:{port}")
                    urls.append(f"https://{host}:{port}")
    else:
        # Fallback: generate default URLs for all hostnames
        for hostname in sorted(hostnames):
            urls.append(f"http://{hostname}")
            urls.append(f"https://{hostname}")
    
    return sorted(list(set(urls)))


def build_target_urls(hostnames: Set[str], ips: Set[str], recon_data: Optional[dict] = None) -> List[str]:
    """
    Build list of target URLs for nuclei scanning.
    Prefers httpx data (live URLs), falls back to naabu (ports), then DNS data.
    
    Args:
        hostnames: Set of hostnames to scan
        ips: Set of IPs to scan (if NUCLEI_SCAN_ALL_IPS is True)
        recon_data: Full recon data containing httpx/naabu results
        
    Returns:
        List of URLs to scan
    """
    urls = []
    
    # Priority 1: Use live URLs from httpx (most accurate)
    httpx_data = recon_data.get("http_probe") if recon_data else None
    if httpx_data:
        urls = build_target_urls_from_httpx(httpx_data)
        if urls:
            print(f"    [*] Using {len(urls)} live URLs from httpx probe")
            return urls
    
    # Priority 2: Use naabu port data
    naabu_data = recon_data.get("port_scan") if recon_data else None
    if naabu_data:
        urls = build_target_urls_from_naabu(naabu_data, hostnames)
        if urls:
            print(f"    [*] Using {len(urls)} URLs from naabu port scan")
            return urls
    
    # Priority 3: Fallback to default ports for all hostnames
    for hostname in sorted(hostnames):
        urls.append(f"http://{hostname}")
        urls.append(f"https://{hostname}")
    
    # Optionally add IPs
    if NUCLEI_SCAN_ALL_IPS:
        for ip in sorted(ips):
            urls.append(f"http://{ip}")
            urls.append(f"https://{ip}")
    
    print(f"    [*] Using {len(urls)} default URLs (no httpx/naabu data)")
    return sorted(list(set(urls)))


def get_real_user_ids() -> tuple:
    """
    Get the real user's UID and GID, even when running under sudo.
    This ensures Docker creates files owned by the actual user, not root.
    """
    import os
    
    # Check if running under sudo - use original user's IDs
    sudo_uid = os.environ.get('SUDO_UID')
    sudo_gid = os.environ.get('SUDO_GID')
    
    if sudo_uid and sudo_gid:
        return int(sudo_uid), int(sudo_gid)
    
    # Not running under sudo, use current user
    return os.getuid(), os.getgid()


def fix_file_ownership(file_path: Path) -> None:
    """
    Fix file ownership to the real user when running under sudo.
    This prevents permission issues when files are created by root.
    """
    import os
    
    uid, gid = get_real_user_ids()
    current_uid = os.getuid()
    
    # Only chown if running as root (sudo) and real user is different
    if current_uid == 0 and uid != 0:
        try:
            os.chown(str(file_path), uid, gid)
        except Exception:
            pass  # Silently fail if chown not possible


def build_nuclei_command(targets_file: str, output_file: str, use_proxy: bool = False) -> List[str]:
    """
    Build nuclei Docker command with all configured parameters.
    
    Args:
        targets_file: Path to file containing target URLs
        output_file: Path for JSON output
        use_proxy: Whether to use Tor proxy
        
    Returns:
        Command as list of arguments
    """
    # Docker command with volume mounts
    # Mount the targets file and output directory
    targets_dir = str(Path(targets_file).parent)
    output_dir = str(Path(output_file).parent)
    targets_filename = Path(targets_file).name
    output_filename = Path(output_file).name
    
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{targets_dir}:/targets:ro",
        "-v", f"{output_dir}:/output",
        "-v", f"{NUCLEI_TEMPLATES_VOLUME}:/root/nuclei-templates",  # Mount templates volume
    ]
    
    # Add network host mode for Tor proxy access
    if use_proxy:
        cmd.extend(["--network", "host"])
    
    cmd.extend([
        NUCLEI_DOCKER_IMAGE,
        "-l", f"/targets/{targets_filename}",
        "-jsonl",
        "-o", f"/output/{output_filename}",
        "-silent",
        "-nc",
        "-duc",  # Disable automatic update check (correct flag)
    ])
    
    # Severity filter
    if NUCLEI_SEVERITY:
        cmd.extend(["-severity", ",".join(NUCLEI_SEVERITY)])
    
    # Template selection
    if NUCLEI_TEMPLATES:
        for template in NUCLEI_TEMPLATES:
            cmd.extend(["-t", template])
    
    if NUCLEI_EXCLUDE_TEMPLATES:
        for template in NUCLEI_EXCLUDE_TEMPLATES:
            cmd.extend(["-exclude-templates", template])
    
    if NUCLEI_CUSTOM_TEMPLATES:
        for template in NUCLEI_CUSTOM_TEMPLATES:
            cmd.extend(["-t", template])
    
    # Tags
    if NUCLEI_TAGS:
        cmd.extend(["-tags", ",".join(NUCLEI_TAGS)])
    
    if NUCLEI_EXCLUDE_TAGS:
        cmd.extend(["-exclude-tags", ",".join(NUCLEI_EXCLUDE_TAGS)])
    
    # Rate limiting
    if NUCLEI_RATE_LIMIT > 0:
        cmd.extend(["-rate-limit", str(NUCLEI_RATE_LIMIT)])
    
    if NUCLEI_BULK_SIZE > 0:
        cmd.extend(["-bulk-size", str(NUCLEI_BULK_SIZE)])
    
    if NUCLEI_CONCURRENCY > 0:
        cmd.extend(["-concurrency", str(NUCLEI_CONCURRENCY)])
    
    # Timeouts
    if NUCLEI_TIMEOUT > 0:
        cmd.extend(["-timeout", str(NUCLEI_TIMEOUT)])
    
    if NUCLEI_RETRIES > 0:
        cmd.extend(["-retries", str(NUCLEI_RETRIES)])
    
    # DAST mode for active vulnerability fuzzing (XSS, SQLi, etc.)
    if NUCLEI_DAST_MODE:
        cmd.append("-dast")  # Dynamic Application Security Testing
    
    # New templates only
    if NUCLEI_NEW_TEMPLATES_ONLY:
        cmd.append("-nt")  # New templates
    
    # Headless browser
    if NUCLEI_HEADLESS:
        cmd.append("-headless")
    
    # System resolvers
    if NUCLEI_SYSTEM_RESOLVERS:
        cmd.append("-system-resolvers")
    
    # Follow redirects
    if NUCLEI_FOLLOW_REDIRECTS:
        cmd.extend(["-follow-redirects"])
        if NUCLEI_MAX_REDIRECTS > 0:
            cmd.extend(["-max-redirects", str(NUCLEI_MAX_REDIRECTS)])
    
    # Interactsh (OOB testing)
    if not NUCLEI_INTERACTSH:
        cmd.append("-no-interactsh")
    
    # Proxy for Tor
    if use_proxy:
        cmd.extend(["-proxy", "socks5://127.0.0.1:9050"])
    
    return cmd


def parse_nuclei_finding(finding: dict) -> dict:
    """
    Parse a single nuclei finding into standardized format.
    
    Args:
        finding: Raw nuclei JSON output line
        
    Returns:
        Standardized finding dictionary
    """
    info = finding.get("info", {})
    
    # Extract CVE IDs from various locations
    cves = []
    
    # From classification
    classification = info.get("classification", {})
    if classification.get("cve-id"):
        cve_ids = classification["cve-id"]
        if isinstance(cve_ids, str):
            cve_ids = [cve_ids]
        for cve_id in cve_ids:
            if cve_id and cve_id.startswith("CVE-"):
                cves.append({
                    "id": cve_id,
                    "cvss": classification.get("cvss-score"),
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                })
    
    # From CVE details
    if classification.get("cve"):
        cve_detail = classification["cve"]
        if isinstance(cve_detail, list):
            for cve_id in cve_detail:
                if cve_id and not any(c["id"] == cve_id for c in cves):
                    cves.append({
                        "id": cve_id,
                        "cvss": None,
                        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                    })
    
    # Extract tags
    tags = info.get("tags", [])
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",")]
    
    # Determine category from tags
    category = "general"
    category_map = {
        "xss": "xss",
        "sqli": "sqli",
        "rce": "rce",
        "lfi": "lfi",
        "rfi": "rfi",
        "ssrf": "ssrf",
        "xxe": "xxe",
        "ssti": "ssti",
        "cve": "cve",
        "exposure": "exposure",
        "misconfig": "misconfiguration",
        "default-login": "authentication",
        "auth-bypass": "authentication",
        "panel": "exposed_panel",
        "tech": "technology",
        "takeover": "takeover",
        "dos": "dos",
        "idor": "idor",
        "csrf": "csrf",
        "redirect": "open_redirect",
        "crlf": "crlf",
        "injection": "injection",
        "file-upload": "file_upload",
        "traversal": "path_traversal",
        "disclosure": "information_disclosure",
        "ssl": "ssl_tls",
        "tls": "ssl_tls",
        "cloud": "cloud",
        "aws": "cloud",
        "azure": "cloud",
        "gcp": "cloud",
        "kubernetes": "cloud",
        "docker": "cloud",
    }
    
    for tag in tags:
        tag_lower = tag.lower()
        for key, cat in category_map.items():
            if key in tag_lower:
                category = cat
                break
        if category != "general":
            break
    
    # Build result
    result = {
        "template_id": finding.get("template-id", "unknown"),
        "template_path": finding.get("template", ""),
        "name": info.get("name", "Unknown"),
        "description": info.get("description", ""),
        "severity": info.get("severity", "unknown").lower(),
        "category": category,
        "tags": tags,
        "reference": info.get("reference", []),
        "cves": cves,
        "cvss_score": classification.get("cvss-score"),
        "cvss_metrics": classification.get("cvss-metrics", ""),
        "cwe_id": classification.get("cwe-id", []),
        "target": finding.get("host", ""),
        "matched_at": finding.get("matched-at", ""),
        "matcher_name": finding.get("matcher-name", ""),
        "extracted_results": finding.get("extracted-results", []),
        "curl_command": finding.get("curl-command", ""),
        "request": finding.get("request", ""),
        "response": finding.get("response", "")[:500] if finding.get("response") else "",
        "timestamp": finding.get("timestamp", datetime.now().isoformat()),
        "raw": finding  # Keep raw data for reference
    }
    
    return result


# =============================================================================
# CVE Lookup - Technology-Based (like Nmap's vulners script)
# =============================================================================

# CPE mappings for common technologies (vendor, product)
CPE_MAPPINGS = {
    # Web Servers
    "nginx": ("f5", "nginx"),  # F5 acquired nginx
    "apache": ("apache", "http_server"),
    "iis": ("microsoft", "internet_information_services"),
    "tomcat": ("apache", "tomcat"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "caddy": ("caddyserver", "caddy"),
    # Languages/Runtimes
    "php": ("php", "php"),
    "python": ("python", "python"),
    "node.js": ("nodejs", "node.js"),
    "ruby": ("ruby-lang", "ruby"),
    # Databases
    "mysql": ("oracle", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "postgresql": ("postgresql", "postgresql"),
    "mongodb": ("mongodb", "mongodb"),
    "redis": ("redis", "redis"),
    "elasticsearch": ("elastic", "elasticsearch"),
    # CMS/Frameworks
    "wordpress": ("wordpress", "wordpress"),
    "drupal": ("drupal", "drupal"),
    "joomla": ("joomla", "joomla"),
    "django": ("djangoproject", "django"),
    "laravel": ("laravel", "laravel"),
    "spring": ("vmware", "spring_framework"),
    # JavaScript
    "jquery": ("jquery", "jquery"),
    "angular": ("angular", "angular"),
    "react": ("facebook", "react"),
    "vue": ("vuejs", "vue.js"),
    "bootstrap": ("getbootstrap", "bootstrap"),
    # Security
    "openssh": ("openbsd", "openssh"),
    "openssl": ("openssl", "openssl"),
    # Other
    "varnish": ("varnish-software", "varnish_cache"),
    "grafana": ("grafana", "grafana"),
    "jenkins": ("jenkins", "jenkins"),
    "gitlab": ("gitlab", "gitlab"),
    "haproxy": ("haproxy", "haproxy"),
}

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
VULNERS_API_URL = "https://vulners.com/api/v3/burp/software/"


def parse_technology_string(tech: str) -> Tuple[str, Optional[str]]:
    """Parse technology string like 'Nginx:1.19.0' into (name, version)."""
    tech = tech.strip()
    for delimiter in [':', '/', ' ']:
        if delimiter in tech:
            parts = tech.split(delimiter, 1)
            name = parts[0].strip().lower()
            version = parts[1].strip() if len(parts) > 1 else None
            if version:
                version = re.sub(r'^v', '', version)
            return name, version
    return tech.lower(), None


def normalize_product_name(name: str) -> str:
    """Normalize product name for lookup."""
    name = name.lower().strip()
    aliases = {
        "nginx": "nginx", "apache httpd": "apache", "microsoft-iis": "iis",
        "node": "node.js", "nodejs": "node.js", "postgres": "postgresql",
        "mongo": "mongodb", "wp": "wordpress", "ssh": "openssh",
    }
    return aliases.get(name, name)


def classify_cvss_score(score: float) -> str:
    """Classify CVSS score into severity level."""
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score >= 0.1:
        return "LOW"
    return "NONE"


def lookup_cves_nvd(product: str, version: str = None, max_results: int = 20) -> List[Dict]:
    """Query NVD API for CVEs affecting a product/version."""
    cves = []
    product_normalized = normalize_product_name(product)
    cpe_info = CPE_MAPPINGS.get(product_normalized)
    
    params = {"resultsPerPage": max_results}
    
    if cpe_info and version:
        vendor, prod = cpe_info
        # Use virtualMatchString for better version matching
        params["virtualMatchString"] = f"cpe:2.3:a:{vendor}:{prod}:{version}:*:*:*:*:*:*:*"
    elif cpe_info:
        vendor, prod = cpe_info
        params["virtualMatchString"] = f"cpe:2.3:a:{vendor}:{prod}:*:*:*:*:*:*:*:*"
    else:
        # Fallback to keyword search for unknown products
        keyword = product
        if version:
            keyword += f" {version}"
        params["keywordSearch"] = keyword
    
    try:
        response = requests.get(NVD_API_URL, params=params, timeout=30)
        response.raise_for_status()
        data = response.json()
        
        for vuln in data.get("vulnerabilities", []):
            cve_data = vuln.get("cve", {})
            cve_id = cve_data.get("id", "")
            
            metrics = cve_data.get("metrics", {})
            cvss_v3 = metrics.get("cvssMetricV31", [{}])[0] if metrics.get("cvssMetricV31") else None
            cvss_v2 = metrics.get("cvssMetricV2", [{}])[0] if metrics.get("cvssMetricV2") else None
            
            cvss_score = None
            severity = None
            
            if cvss_v3:
                cvss_score = cvss_v3.get("cvssData", {}).get("baseScore")
                severity = cvss_v3.get("cvssData", {}).get("baseSeverity")
            elif cvss_v2:
                cvss_score = cvss_v2.get("cvssData", {}).get("baseScore")
                severity = cvss_v2.get("baseSeverity")
            
            descriptions = cve_data.get("descriptions", [])
            description = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
            
            refs = cve_data.get("references", [])
            reference_urls = [ref.get("url") for ref in refs[:3] if ref.get("url")]
            
            cves.append({
                "id": cve_id,
                "cvss": cvss_score,
                "severity": severity,
                "description": description[:300] if description else "",
                "published": cve_data.get("published"),
                "references": reference_urls,
                "source": "nvd",
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            })
            
    except Exception as e:
        print(f"        [!] NVD API error: {str(e)[:80]}")
    
    return cves


def lookup_cves_vulners(product: str, version: str, api_key: str = None) -> List[Dict]:
    """Query Vulners API for CVEs (like Nmap's vulners script)."""
    cves = []
    if not version:
        return cves
    
    params = {"software": f"{product} {version}", "version": version, "type": "software"}
    if api_key:
        params["apiKey"] = api_key
    
    try:
        response = requests.get(VULNERS_API_URL, params=params, timeout=30)
        response.raise_for_status()
        data = response.json()
        
        if data.get("result") == "OK":
            for vuln in data.get("data", {}).get("search", []):
                vuln_id = vuln.get("id", "")
                cvss_data = vuln.get("cvss", {})
                
                cves.append({
                    "id": vuln_id,
                    "cvss": cvss_data.get("score"),
                    "severity": classify_cvss_score(cvss_data.get("score")),
                    "description": vuln.get("description", "")[:300],
                    "published": vuln.get("published"),
                    "references": [vuln.get("href")] if vuln.get("href") else [],
                    "source": "vulners",
                    "url": f"https://vulners.com/{vuln.get('type', 'cve')}/{vuln_id}",
                })
    except Exception as e:
        print(f"        [!] Vulners API error: {str(e)[:80]}")
    
    return cves


def run_cve_lookup(recon_data: dict) -> Dict:
    """
    Lookup CVEs for all technologies detected by httpx.
    Returns a dictionary to add to recon_data.
    """
    if not CVE_LOOKUP_ENABLED:
        return {}
    
    print(f"\n{'='*60}")
    print("CVE LOOKUP - Technology-Based Vulnerability Discovery")
    print(f"{'='*60}")
    print(f"    Source: {CVE_LOOKUP_SOURCE.upper()}")
    print(f"    Min CVSS: {CVE_LOOKUP_MIN_CVSS}")
    
    # Extract technologies from httpx
    technologies = set()
    httpx_data = recon_data.get("http_probe", {})
    
    for url_data in httpx_data.get("by_url", {}).values():
        techs = url_data.get("technologies", [])
        technologies.update(techs)
        server = url_data.get("server")
        if server:
            technologies.add(server)
    
    # Filter technologies to lookup
    tech_to_lookup = []
    skip_list = ["ubuntu", "debian", "centos", "linux", "windows", 
                 "dreamweaver", "frontpage", "html", "css", "aws"]
    
    for tech in technologies:
        name, version = parse_technology_string(tech)
        name = normalize_product_name(name)
        if not version or name in skip_list:
            continue
        tech_to_lookup.append(tech)
    
    print(f"\n[*] Technologies with versions: {len(tech_to_lookup)}")
    
    if not tech_to_lookup:
        print("[!] No technologies with versions found")
        return {"technology_cves": {"summary": {"total_cves": 0}}}
    
    # Lookup CVEs
    cve_results = {}
    all_cves = []
    
    for i, tech in enumerate(tech_to_lookup, 1):
        name, version = parse_technology_string(tech)
        name = normalize_product_name(name)
        
        print(f"    [{i}/{len(tech_to_lookup)}] {tech}...", end=" ", flush=True)
        
        if CVE_LOOKUP_SOURCE == "vulners" and VULNERS_API_KEY:
            cves = lookup_cves_vulners(name, version, VULNERS_API_KEY)
        else:
            cves = lookup_cves_nvd(name, version, CVE_LOOKUP_MAX_CVES)
        
        # Filter by min CVSS
        if CVE_LOOKUP_MIN_CVSS > 0:
            cves = [c for c in cves if (c.get("cvss") or 0) >= CVE_LOOKUP_MIN_CVSS]
        
        cves.sort(key=lambda x: x.get("cvss") or 0, reverse=True)
        cves = cves[:CVE_LOOKUP_MAX_CVES]
        
        if cves:
            cve_results[tech] = {
                "technology": tech,
                "product": name,
                "version": version,
                "cve_count": len(cves),
                "critical": len([c for c in cves if c.get("severity") == "CRITICAL"]),
                "high": len([c for c in cves if c.get("severity") == "HIGH"]),
                "cves": cves,
            }
            all_cves.extend(cves)
            print(f"✓ {len(cves)} CVEs found")
        else:
            print("no CVEs")
        
        # Rate limiting for NVD API
        if CVE_LOOKUP_SOURCE == "nvd" and i < len(tech_to_lookup):
            time.sleep(6)
    
    # Count unique CVEs across all technologies (for summary stats only)
    unique_cve_ids = set()
    for tech_data in cve_results.values():
        for cve in tech_data.get("cves", []):
            unique_cve_ids.add(cve["id"])

    # Count severity distribution
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for tech_data in cve_results.values():
        for cve in tech_data.get("cves", []):
            sev = cve.get("severity", "").upper()
            if sev in severity_counts:
                severity_counts[sev] += 1

    # Build result (no all_cves - CVEs are stored inside by_technology)
    result = {
        "technology_cves": {
            "lookup_timestamp": datetime.now().isoformat(),
            "source": CVE_LOOKUP_SOURCE,
            "technologies_checked": len(tech_to_lookup),
            "technologies_with_cves": len(cve_results),
            "by_technology": cve_results,
            "summary": {
                "total_unique_cves": len(unique_cve_ids),
                "critical": severity_counts["CRITICAL"],
                "high": severity_counts["HIGH"],
                "medium": severity_counts["MEDIUM"],
                "low": severity_counts["LOW"],
            }
        }
    }
    
    # Print summary
    summary = result["technology_cves"]["summary"]
    print(f"\n[+] CVE LOOKUP SUMMARY:")
    print(f"    Total unique CVEs: {summary['total_unique_cves']}")
    if summary['critical'] > 0:
        print(f"    🔴 CRITICAL: {summary['critical']}")
    if summary['high'] > 0:
        print(f"    🟠 HIGH: {summary['high']}")
    if summary['medium'] > 0:
        print(f"    🟡 MEDIUM: {summary['medium']}")
    print(f"{'='*60}")
    
    return result


def run_vuln_scan(recon_data: dict, output_file: Path = None) -> dict:
    """
    Run nuclei scan on all URLs derived from recon data.
    
    Args:
        recon_data: Domain reconnaissance data dictionary
        output_file: Optional path to save incremental results
        
    Returns:
        Updated recon_data with nuclei results added
    """
    print("\n" + "=" * 70)
    print("         RedAmon - Nuclei Vulnerability Scanner")
    print("=" * 70)
    
    # Docker mode is required
    if not is_docker_installed():
        print("[!] Docker not found. Please install Docker to use Nuclei scanner.")
        print("[!] Skipping nuclei scan.")
        return recon_data
    
    if not is_docker_running():
        print("[!] Docker daemon is not running. Start it with: sudo systemctl start docker")
        print("[!] Skipping nuclei scan.")
        return recon_data
    
    # Pull image if needed (will skip if already present)
    pull_nuclei_docker_image()
    
    # Ensure templates volume exists and has templates
    if not ensure_templates_volume():
        print("[!] Could not setup nuclei templates. Skipping scan.")
        return recon_data
    
    print(f"  Execution Mode: DOCKER ({NUCLEI_DOCKER_IMAGE})")
    nuclei_version = f"Docker: {NUCLEI_DOCKER_IMAGE}"
    template_count = 8000  # Approximate, Docker image includes templates
    
    print(f"  Nuclei Version: {nuclei_version}")
    print(f"  Templates Available: ~{template_count}")
    
    # Check Tor status
    use_proxy = False
    if USE_TOR_FOR_RECON:
        if is_tor_running():
            use_proxy = True
            print(f"  [🧅] ANONYMOUS MODE: Using Tor SOCKS proxy")
        else:
            print("  [!] USE_TOR_FOR_RECON enabled but Tor not running")
            print("  [!] Falling back to direct scanning")
    
    # Extract targets
    ips, hostnames, ip_to_hostnames = extract_targets_from_recon(recon_data)
    
    if not hostnames and not ips:
        print("[!] No targets found in recon data")
        return recon_data
    
    # Build target URLs using httpx/naabu data if available
    target_urls = build_target_urls(hostnames, ips, recon_data)
    
    # For DAST mode, we need URLs with parameters
    # Run Katana crawler to discover them
    dast_urls = []
    if NUCLEI_DAST_MODE:
        print(f"  DAST Mode: ENABLED (active fuzzing for XSS, SQLi, etc.)")
        print(f"  [*] DAST requires URLs with parameters - running Katana crawler...")
        
        # Pull Katana image
        pull_katana_docker_image()
        
        # Use live URLs from httpx (already verified to be responding)
        # instead of constructing new URLs from hostnames
        # This avoids timeouts on non-responding protocols (e.g., http when only https works)
        dast_urls = run_katana_crawler(target_urls, use_proxy)
        
        if not dast_urls:
            print(f"  [!] No URLs with parameters found - DAST scan may not find vulnerabilities")
            print(f"  [!] Will run standard scan instead")
    
    print(f"  Unique Hostnames: {len(hostnames)}")
    print(f"  Unique IPs: {len(ips)}")
    print(f"  Base URLs: {len(target_urls)}")
    if NUCLEI_DAST_MODE and dast_urls:
        print(f"  DAST URLs (with params): {len(dast_urls)}")
    print(f"  Scan IPs: {'YES' if NUCLEI_SCAN_ALL_IPS else 'NO (hostnames only)'}")
    print(f"  Severity Filter: {', '.join(NUCLEI_SEVERITY) if NUCLEI_SEVERITY else 'ALL'}")
    print(f"  Rate Limit: {NUCLEI_RATE_LIMIT} req/s")
    if NUCLEI_TAGS:
        print(f"  Tags: {', '.join(NUCLEI_TAGS)}")
    print("=" * 70 + "\n")
    
    # Create a temporary directory for nuclei files in a location Docker can access
    # Using the project's output directory to avoid permission/access issues
    output_dir = Path(__file__).parent / "output"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    nuclei_temp_dir = output_dir / ".nuclei_temp"
    nuclei_temp_dir.mkdir(parents=True, exist_ok=True)
    
    # Create targets file
    # For DAST mode with discovered URLs, use those; otherwise use base URLs
    scan_urls = target_urls
    if NUCLEI_DAST_MODE and dast_urls:
        # Combine DAST URLs with base URLs for comprehensive coverage
        scan_urls = list(set(target_urls + dast_urls))
        print(f"[*] DAST scan will test {len(dast_urls)} URLs with parameters + {len(target_urls)} base URLs")
    
    targets_file = str(nuclei_temp_dir / "targets.txt")
    with open(targets_file, 'w') as f:
        for url in scan_urls:
            f.write(url + "\n")
    
    # Output file path
    nuclei_output_file = str(nuclei_temp_dir / "nuclei_output.jsonl")
    
    try:
        # Build and run nuclei command
        cmd = build_nuclei_command(targets_file, nuclei_output_file, use_proxy)
        
        print(f"[*] Running nuclei scan [DOCKER]...")
        print(f"[*] Command: {' '.join(cmd[:12])}...")
        
        # Run nuclei
        start_time = datetime.now()
        
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Monitor progress
        stdout, stderr = process.communicate()
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        if process.returncode != 0 and stderr:
            # Filter out common non-error messages
            error_lines = [l for l in stderr.split('\n') if l and 'WRN' not in l and 'INF' not in l]
            if error_lines:
                print(f"[!] Nuclei warnings: {error_lines[0][:100]}")
        
        # Parse results
        findings = []
        if Path(nuclei_output_file).exists():
            with open(nuclei_output_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            raw_finding = json.loads(line)
                            parsed = parse_nuclei_finding(raw_finding)
                            findings.append(parsed)
                        except json.JSONDecodeError:
                            continue
        
        # Organize results
        nuclei_results = {
            "scan_metadata": {
                "scan_timestamp": start_time.isoformat(),
                "scan_duration_seconds": duration,
                "nuclei_version": nuclei_version,
                "templates_available": template_count,
                "execution_mode": "docker",
                "docker_image": NUCLEI_DOCKER_IMAGE,
                "anonymous_mode": use_proxy,
                "severity_filter": NUCLEI_SEVERITY,
                "tags_filter": NUCLEI_TAGS,
                "exclude_tags": NUCLEI_EXCLUDE_TAGS,
                "rate_limit": NUCLEI_RATE_LIMIT,
                "dast_mode": NUCLEI_DAST_MODE,
                "dast_urls_discovered": len(dast_urls) if NUCLEI_DAST_MODE else 0,
                "katana_crawl_depth": KATANA_DEPTH if NUCLEI_DAST_MODE else None,
                "total_urls_scanned": len(scan_urls),
                "total_hostnames": len(hostnames),
                "total_ips": len(ips),
            },
            "discovered_urls": {
                "base_urls": sorted(target_urls),
                "dast_urls_with_params": sorted(dast_urls) if dast_urls else [],
                "all_scanned_urls": sorted(scan_urls),
            },
            "by_target": {},
            "summary": {
                "total_findings": len(findings),
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
                "unknown": 0,
            },
            "vulnerabilities": {
                "total": 0,
                "critical": [],
                "high": [],
                "medium": [],
                "low": [],
                "info": [],
                "unknown": [],
            },
            "all_cves": [],
            "by_category": {},
            "by_template": {},
        }
        
        # Process findings
        all_cves = []
        
        for finding in findings:
            severity = finding["severity"]
            target = finding["target"]
            template_id = finding["template_id"]
            category = finding["category"]
            
            # Count by severity
            if severity in nuclei_results["summary"]:
                nuclei_results["summary"][severity] += 1
            else:
                nuclei_results["summary"]["unknown"] += 1
            
            # Group by target
            if target not in nuclei_results["by_target"]:
                nuclei_results["by_target"][target] = {
                    "findings": [],
                    "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
                }
            nuclei_results["by_target"][target]["findings"].append(finding)
            if severity in nuclei_results["by_target"][target]["severity_counts"]:
                nuclei_results["by_target"][target]["severity_counts"][severity] += 1
            
            # Add to severity-based vulnerability list
            finding_summary = {
                "template_id": template_id,
                "name": finding["name"],
                "target": target,
                "matched_at": finding["matched_at"],
                "category": category,
                "cves": [c["id"] for c in finding["cves"]],
                "cvss": finding["cvss_score"],
            }
            
            if severity in nuclei_results["vulnerabilities"]:
                nuclei_results["vulnerabilities"][severity].append(finding_summary)
            else:
                nuclei_results["vulnerabilities"]["unknown"].append(finding_summary)
            
            # Collect CVEs
            all_cves.extend(finding["cves"])
            
            # Group by category
            if category not in nuclei_results["by_category"]:
                nuclei_results["by_category"][category] = []
            nuclei_results["by_category"][category].append(finding_summary)
            
            # Group by template
            if template_id not in nuclei_results["by_template"]:
                nuclei_results["by_template"][template_id] = {
                    "name": finding["name"],
                    "severity": severity,
                    "findings_count": 0,
                    "targets": []
                }
            nuclei_results["by_template"][template_id]["findings_count"] += 1
            if target not in nuclei_results["by_template"][template_id]["targets"]:
                nuclei_results["by_template"][template_id]["targets"].append(target)
        
        # Deduplicate and sort CVEs
        seen_cves = set()
        unique_cves = []
        for cve in all_cves:
            if cve["id"] not in seen_cves:
                seen_cves.add(cve["id"])
                unique_cves.append(cve)
        unique_cves.sort(key=lambda x: x.get("cvss") or 0, reverse=True)
        nuclei_results["all_cves"] = unique_cves
        
        # Calculate total vulnerabilities (excluding info)
        nuclei_results["vulnerabilities"]["total"] = (
            nuclei_results["summary"]["critical"] +
            nuclei_results["summary"]["high"] +
            nuclei_results["summary"]["medium"] +
            nuclei_results["summary"]["low"]
        )
        
        # Add to recon data
        recon_data["vuln_scan"] = nuclei_results
        
        # Save incrementally if output file provided
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(recon_data, f, indent=2)
            fix_file_ownership(output_file)  # Ensure correct ownership when running under sudo
        
        # Print summary
        print(f"\n{'=' * 70}")
        print(f"[+] NUCLEI SCAN COMPLETE")
        print(f"[+] Duration: {duration:.2f} seconds")
        print(f"[+] Execution mode: DOCKER")
        if use_proxy:
            print(f"[+] Anonymous mode: YES (via Tor)")
        print(f"[+] URLs scanned: {len(target_urls)}")
        print(f"[+] Total findings: {len(findings)}")
        
        # Vulnerability summary
        summary = nuclei_results["summary"]
        vuln_total = nuclei_results["vulnerabilities"]["total"]
        
        if vuln_total > 0:
            print(f"\n[+] VULNERABILITY SUMMARY:")
            if summary['critical'] > 0:
                print(f"    🔴 CRITICAL: {summary['critical']}")
            if summary['high'] > 0:
                print(f"    🟠 HIGH: {summary['high']}")
            if summary['medium'] > 0:
                print(f"    🟡 MEDIUM: {summary['medium']}")
            if summary['low'] > 0:
                print(f"    🔵 LOW: {summary['low']}")
        
        if summary['info'] > 0:
            print(f"    ⚪ INFO: {summary['info']}")
        
        # CVE summary
        cve_count = len(unique_cves)
        if cve_count > 0:
            print(f"\n[+] CVEs FOUND: {cve_count}")
            for cve in unique_cves[:5]:
                cvss_str = f"CVSS {cve['cvss']}" if cve.get('cvss') else "CVSS N/A"
                print(f"    - {cve['id']} ({cvss_str})")
            if cve_count > 5:
                print(f"    ... and {cve_count - 5} more")
        
        # Top affected targets
        if nuclei_results["by_target"]:
            print(f"\n[+] FINDINGS BY TARGET:")
            sorted_targets = sorted(
                nuclei_results["by_target"].items(),
                key=lambda x: len(x[1]["findings"]),
                reverse=True
            )[:5]
            for target, data in sorted_targets:
                counts = data["severity_counts"]
                count_str = ", ".join([
                    f"{SEVERITY_COLORS.get(s, '')}{counts[s]}" 
                    for s in ["critical", "high", "medium", "low", "info"] 
                    if counts.get(s, 0) > 0
                ])
                print(f"    - {target[:50]}: {len(data['findings'])} findings ({count_str})")
        
        # Top categories
        if nuclei_results["by_category"]:
            print(f"\n[+] TOP VULNERABILITY CATEGORIES:")
            sorted_cats = sorted(
                nuclei_results["by_category"].items(),
                key=lambda x: len(x[1]),
                reverse=True
            )[:5]
            for cat, findings_list in sorted_cats:
                print(f"    - {cat}: {len(findings_list)} findings")
        
        print(f"{'=' * 70}")
        
        # Run CVE lookup for detected technologies (like Nmap's vulners)
        if CVE_LOOKUP_ENABLED and recon_data.get("http_probe"):
            cve_results = run_cve_lookup(recon_data)
            recon_data.update(cve_results)
            
            # Save with CVE data
            if output_file:
                with open(output_file, 'w') as f:
                    json.dump(recon_data, f, indent=2)
                fix_file_ownership(output_file)
        
    finally:
        # Cleanup temporary files and directory
        # Docker may create files as root, so we use Docker to clean up if needed
        try:
            Path(targets_file).unlink(missing_ok=True)
        except PermissionError:
            # File owned by root (from Docker), use docker to remove it
            subprocess.run(["docker", "run", "--rm", "-v", f"{nuclei_temp_dir}:/cleanup", 
                          "alpine", "rm", "-f", f"/cleanup/{Path(targets_file).name}"],
                         capture_output=True)
        
        try:
            Path(nuclei_output_file).unlink(missing_ok=True)
        except PermissionError:
            subprocess.run(["docker", "run", "--rm", "-v", f"{nuclei_temp_dir}:/cleanup",
                          "alpine", "rm", "-f", f"/cleanup/{Path(nuclei_output_file).name}"],
                         capture_output=True)
        
        try:
            nuclei_temp_dir.rmdir()  # Only removes if empty
        except Exception:
            pass
    
    return recon_data


def enrich_recon_file(recon_file: Path) -> dict:
    """
    Load a recon JSON file, enrich it with nuclei data, and save it back.
    
    Args:
        recon_file: Path to the recon JSON file
        
    Returns:
        Enriched recon data
    """
    # Load existing data
    with open(recon_file, 'r') as f:
        recon_data = json.load(f)
    
    # Run nuclei scan
    enriched_data = run_vuln_scan(recon_data, output_file=recon_file)
    
    # Save enriched data
    with open(recon_file, 'w') as f:
        json.dump(enriched_data, f, indent=2)
    
    print(f"[+] Enriched data saved to: {recon_file}")
    
    return enriched_data

