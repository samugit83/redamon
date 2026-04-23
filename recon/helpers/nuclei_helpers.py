"""
RedAmon - Nuclei Helper Functions
==================================
Functions for building Nuclei commands, parsing output, and detecting false positives.
"""

import os
from datetime import datetime
from pathlib import Path
from typing import List

# Import volume constant from docker helpers
from .docker_helpers import NUCLEI_TEMPLATES_VOLUME


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


# =============================================================================
# Nuclei Command Building
# =============================================================================

def build_nuclei_command(
    targets_file: str,
    output_file: str,
    docker_image: str,
    use_proxy: bool = False,
    # Nuclei configuration
    severity: List[str] = None,
    templates: List[str] = None,
    exclude_templates: List[str] = None,
    custom_templates: List[str] = None,
    selected_custom_templates: List[str] = None,
    tags: List[str] = None,
    exclude_tags: List[str] = None,
    rate_limit: int = 0,
    bulk_size: int = 0,
    concurrency: int = 0,
    timeout: int = 0,
    retries: int = 0,
    dast_mode: bool = False,
    new_templates_only: bool = False,
    headless: bool = False,
    system_resolvers: bool = False,
    follow_redirects: bool = False,
    max_redirects: int = 0,
    interactsh: bool = True,
) -> List[str]:
    """
    Build nuclei Docker command with all configured parameters.
    
    Args:
        targets_file: Path to file containing target URLs
        output_file: Path for JSON output
        docker_image: Nuclei Docker image to use
        use_proxy: Whether to use Tor proxy
        ... (configuration parameters)
        
    Returns:
        Command as list of arguments
    """
    # Docker command with volume mounts
    # Convert container paths to host paths for sibling container volume mounts
    targets_host_path = get_host_path(str(Path(targets_file).parent))
    output_host_path = get_host_path(str(Path(output_file).parent))
    targets_filename = Path(targets_file).name
    output_filename = Path(output_file).name

    cmd = [
        "docker", "run", "--rm",
        "-v", f"{targets_host_path}:/targets:ro",
        "-v", f"{output_host_path}:/output",
        "-v", f"{NUCLEI_TEMPLATES_VOLUME}:/root/nuclei-templates",
    ]

    # Mount custom templates if any are selected
    host_custom_templates = os.environ.get("HOST_CUSTOM_TEMPLATES_PATH", "")
    if selected_custom_templates and host_custom_templates:
        cmd.extend(["-v", f"{host_custom_templates}:/custom-templates:ro"])

    # Add network host mode for Tor proxy access
    if use_proxy:
        cmd.extend(["--network", "host"])
    
    cmd.extend([
        docker_image,
        "-l", f"/targets/{targets_filename}",
        "-jsonl",
        "-o", f"/output/{output_filename}",
        "-silent",
        "-nc",
        "-duc",  # Disable automatic update check
    ])
    
    # Severity filter
    if severity:
        cmd.extend(["-severity", ",".join(severity)])
    
    # Template selection
    if templates:
        for template in templates:
            cmd.extend(["-t", template])
    
    if exclude_templates:
        for template in exclude_templates:
            cmd.extend(["-exclude-templates", template])
    
    if custom_templates:
        for template in custom_templates:
            cmd.extend(["-t", template])

    # Include individually selected custom templates (alongside built-in)
    if selected_custom_templates and os.environ.get("HOST_CUSTOM_TEMPLATES_PATH"):
        # If no specific templates were requested, we must explicitly include
        # the built-in templates too — otherwise nuclei only scans the custom ones
        if not templates:
            cmd.extend(["-t", "/root/nuclei-templates/"])
        for tpl_path in selected_custom_templates:
            cmd.extend(["-t", f"/custom-templates/{tpl_path}"])

    # Tags
    if tags:
        cmd.extend(["-tags", ",".join(tags)])
    
    if exclude_tags:
        cmd.extend(["-exclude-tags", ",".join(exclude_tags)])
    
    # Rate limiting
    if rate_limit > 0:
        cmd.extend(["-rate-limit", str(rate_limit)])
    
    if bulk_size > 0:
        cmd.extend(["-bulk-size", str(bulk_size)])
    
    if concurrency > 0:
        cmd.extend(["-concurrency", str(concurrency)])
    
    # Timeouts
    if timeout > 0:
        cmd.extend(["-timeout", str(timeout)])
    
    if retries > 0:
        cmd.extend(["-retries", str(retries)])
    
    # DAST mode for active vulnerability fuzzing
    if dast_mode:
        cmd.append("-dast")
    
    # New templates only
    if new_templates_only:
        cmd.append("-nt")
    
    # Headless browser
    if headless:
        cmd.append("-headless")
    
    # System resolvers
    if system_resolvers:
        cmd.append("-system-resolvers")
    
    # Follow redirects
    if follow_redirects:
        cmd.extend(["-follow-redirects"])
        if max_redirects > 0:
            cmd.extend(["-max-redirects", str(max_redirects)])
    
    # Interactsh (OOB testing)
    if not interactsh:
        cmd.append("-no-interactsh")
    
    # Proxy for Tor
    if use_proxy:
        cmd.extend(["-proxy", "socks5://127.0.0.1:9050"])
    
    return cmd


# =============================================================================
# False Positive Detection
# =============================================================================

def is_false_positive(finding: dict) -> tuple:
    """
    Detect common false positive patterns in nuclei findings.
    
    False positive indicators:
    1. Rate limiting (429 status) - timing-based attacks become unreliable
    2. WAF/firewall blocks - response doesn't reflect actual vulnerability
    3. Generic error pages - timing variations due to error handling
    
    Args:
        finding: Raw nuclei JSON output line
        
    Returns:
        Tuple of (is_false_positive: bool, reason: str or None)
    """
    response = finding.get("response", "")
    template_id = finding.get("template-id", "")
    info = finding.get("info", {})
    tags = info.get("tags", [])
    
    # Patterns that indicate false positives
    rate_limit_indicators = [
        "429 Too Many Requests",
        "HTTP/1.1 429",
        "HTTP/2 429",
        "Too Many Requests",
        "rate limit",
        "Rate Limit",
        "too many attempts",
        "Too many attempts",
        "please wait",
        "try again later",
        "temporarily blocked",
        "Request blocked",
    ]
    
    waf_block_indicators = [
        "403 Forbidden",
        "Access Denied",
        "Request Blocked",
        "Blocked by",
        "Web Application Firewall",
        "WAF",
        "ModSecurity",
        "Cloudflare",
        "AWS WAF",
    ]
    
    # Check for rate limiting - especially bad for time-based attacks
    is_time_based = any(t in ["time-based", "blind", "time-based-sqli"] for t in tags) or \
                    "time" in template_id.lower() or "blind" in template_id.lower()
    
    for indicator in rate_limit_indicators:
        if indicator.lower() in response.lower():
            if is_time_based:
                return True, f"Rate limiting detected ('{indicator}') - invalidates time-based attack detection"
            else:
                # For non-time-based, rate limiting is less critical but still suspicious
                return True, f"Rate limiting detected ('{indicator}') - response may not reflect actual vulnerability"
    
    # Check for WAF blocks on injection attacks
    is_injection = any(t in ["sqli", "xss", "rce", "lfi", "ssti", "injection"] for t in tags)
    
    if is_injection:
        for indicator in waf_block_indicators:
            if indicator.lower() in response.lower():
                # 403 with WAF indicators likely means WAF blocked the payload, not a real vuln
                if "403" in response[:50]:
                    return True, f"WAF/Firewall block detected ('{indicator}') - payload was blocked, not executed"
    
    return False, None


# =============================================================================
# Nuclei Output Parsing
# =============================================================================

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

