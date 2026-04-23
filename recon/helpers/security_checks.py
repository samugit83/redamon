"""
RedAmon - Vulnerability Scan Helper Functions
=============================================
Security check functions for detecting misconfigurations and vulnerabilities.
These are custom checks that complement Nuclei template scanning.

Security Check Categories:
1. Direct IP Access Checks - Detect WAF bypass, direct IP exposure
2. TLS/SSL Security Checks - Certificate validation, cipher strength, HSTS
"""

import socket
import ssl
import requests
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
import concurrent.futures

# Suppress SSL warnings for security testing
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# =============================================================================
# Direct IP Access Security Checks
# =============================================================================

def _is_ip_address(host: str) -> bool:
    """Check if a string is an IP address (v4 or v6)."""
    import re
    # IPv4 pattern
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    # IPv6 pattern (simplified)
    ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
    return bool(re.match(ipv4_pattern, host) or re.match(ipv6_pattern, host))


def _analyze_redirect_chain(ip: str, scheme: str, timeout: int = 10) -> Dict:
    """
    Analyze redirect behavior when accessing IP directly.
    
    Returns:
        Dict with redirect analysis:
        - redirects: bool - whether it redirects
        - final_url: str - final destination URL
        - final_host: str - final destination host
        - redirects_to_hostname: bool - whether final destination is a hostname (not IP)
        - redirect_count: int - number of redirects
    """
    url = f"{scheme}://{ip}"
    result = {
        "redirects": False,
        "final_url": url,
        "final_host": ip,
        "redirects_to_hostname": False,
        "redirect_count": 0,
        "initial_status_code": None,
    }
    
    try:
        # First, check initial response without following redirects
        initial_response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=False,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"}
        )
        result["initial_status_code"] = initial_response.status_code
        
        # Check if it's a redirect
        if initial_response.status_code in [301, 302, 303, 307, 308]:
            result["redirects"] = True
            
            # Now follow redirects to see where it goes
            try:
                final_response = requests.get(
                    url,
                    timeout=timeout,
                    allow_redirects=True,
                    verify=False,
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"}
                )
                result["final_url"] = final_response.url
                result["redirect_count"] = len(final_response.history)
                
                # Extract host from final URL
                from urllib.parse import urlparse
                parsed = urlparse(final_response.url)
                final_host = parsed.netloc.split(':')[0]  # Remove port if present
                result["final_host"] = final_host
                
                # Check if final destination is a hostname (not an IP)
                result["redirects_to_hostname"] = not _is_ip_address(final_host)
                
            except requests.exceptions.RequestException:
                # If following redirects fails, we still know it redirects
                pass
    
    except requests.exceptions.RequestException:
        pass
    
    return result


def check_direct_ip_http(ip: str, timeout: int = 10) -> Optional[Dict]:
    """
    Check if HTTP is accessible directly via IP without TLS.
    This can indicate WAF bypass opportunities or exposed services.
    
    Intelligently handles redirects:
    - If IP redirects to a hostname: Low/Info severity (mitigated)
    - If IP serves content or redirects to same IP: Medium severity

    Args:
        ip: IP address to check
        timeout: Request timeout in seconds

    Returns:
        Vulnerability dict if HTTP is accessible, None otherwise
    """
    try:
        url = f"http://{ip}"
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=False,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"}
        )

        if response.status_code < 500:
            # Analyze redirect behavior
            redirect_info = _analyze_redirect_chain(ip, "http", timeout)
            
            # Determine severity based on redirect behavior
            if redirect_info["redirects"] and redirect_info["redirects_to_hostname"]:
                # Redirects to a hostname - mitigated, lower severity
                severity = "info"
                description = (
                    f"HTTP service on IP {ip} redirects to hostname {redirect_info['final_host']}. "
                    f"This is a mitigated configuration - the server enforces hostname-based access. "
                    f"However, the IP still responds which reveals server existence."
                )
                evidence = (
                    f"HTTP {response.status_code} redirect → {redirect_info['final_url']} "
                    f"({redirect_info['redirect_count']} redirect(s))"
                )
            elif redirect_info["redirects"]:
                # Redirects but stays on IP - still concerning
                severity = "medium"
                description = (
                    f"HTTP service is accessible directly via IP {ip} without TLS encryption. "
                    f"Server redirects but final destination is still IP-based. "
                    "This may allow attackers to bypass WAF/CDN protections or intercept traffic."
                )
                evidence = f"HTTP {response.status_code} redirect to {redirect_info['final_url']}"
            else:
                # Serves content directly - most concerning
                severity = "medium"
                description = (
                    f"HTTP service is accessible directly via IP {ip} without TLS encryption. "
                    "Server serves content directly on IP without redirecting to hostname. "
                    "This may allow attackers to bypass WAF/CDN protections or intercept traffic."
                )
                evidence = f"HTTP {response.status_code} response - content served directly"
            
            return {
                "type": "direct_ip_http",
                "severity": severity,
                "name": "Direct IP HTTP Access",
                "description": description,
                "url": url,
                "matched_ip": ip,
                "status_code": response.status_code,
                "server": response.headers.get("Server", ""),
                "evidence": evidence,
                "redirects": redirect_info["redirects"],
                "redirects_to_hostname": redirect_info["redirects_to_hostname"],
                "final_url": redirect_info["final_url"] if redirect_info["redirects"] else None,
            }
    except requests.exceptions.RequestException:
        pass

    return None


def check_direct_ip_https(ip: str, timeout: int = 10) -> Optional[Dict]:
    """
    Check if HTTPS is accessible directly via IP.
    Less severe than HTTP but still indicates direct IP exposure.
    
    Intelligently handles redirects:
    - If IP redirects to a hostname: Info severity (mitigated)
    - If IP serves content or redirects to same IP: Low severity

    Args:
        ip: IP address to check
        timeout: Request timeout in seconds

    Returns:
        Vulnerability dict if HTTPS is accessible, None otherwise
    """
    try:
        url = f"https://{ip}"
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=False,
            verify=False,  # Ignore cert errors for IP-based access
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"}
        )

        if response.status_code < 500:
            # Analyze redirect behavior
            redirect_info = _analyze_redirect_chain(ip, "https", timeout)
            
            # Determine severity based on redirect behavior
            if redirect_info["redirects"] and redirect_info["redirects_to_hostname"]:
                # Redirects to a hostname - mitigated, info only
                severity = "info"
                description = (
                    f"HTTPS service on IP {ip} redirects to hostname {redirect_info['final_host']}. "
                    f"This is a properly mitigated configuration. "
                    f"The IP responds but enforces hostname-based access with TLS."
                )
                evidence = (
                    f"HTTPS {response.status_code} redirect → {redirect_info['final_url']} "
                    f"({redirect_info['redirect_count']} redirect(s))"
                )
            elif redirect_info["redirects"]:
                # Redirects but stays on IP - low concern
                severity = "low"
                description = (
                    f"HTTPS service is accessible directly via IP {ip}. "
                    f"Server redirects but final destination is still IP-based. "
                    "While encrypted, this may allow bypassing CDN/WAF protections."
                )
                evidence = f"HTTPS {response.status_code} redirect to {redirect_info['final_url']}"
            else:
                # Serves content directly - concerning
                severity = "low"
                description = (
                    f"HTTPS service is accessible directly via IP {ip}. "
                    "Server serves content directly on IP without redirecting to hostname. "
                    "While encrypted, this may allow bypassing CDN/WAF protections."
                )
                evidence = f"HTTPS {response.status_code} response - content served directly"
            
            return {
                "type": "direct_ip_https",
                "severity": severity,
                "name": "Direct IP HTTPS Access",
                "description": description,
                "url": url,
                "matched_ip": ip,
                "status_code": response.status_code,
                "server": response.headers.get("Server", ""),
                "evidence": evidence,
                "redirects": redirect_info["redirects"],
                "redirects_to_hostname": redirect_info["redirects_to_hostname"],
                "final_url": redirect_info["final_url"] if redirect_info["redirects"] else None,
            }
    except requests.exceptions.RequestException:
        pass

    return None


def check_ip_api_exposed(ip: str, timeout: int = 10) -> Optional[Dict]:
    """
    Check if API endpoints are exposed directly on IP without TLS.
    Common API paths that shouldn't be accessible via direct IP.

    Args:
        ip: IP address to check
        timeout: Request timeout in seconds

    Returns:
        Vulnerability dict if API is exposed, None otherwise
    """
    api_paths = [
        "/api",
        "/api/v1",
        "/api/v2",
        "/graphql",
        "/rest",
        "/v1",
        "/v2",
    ]

    for path in api_paths:
        try:
            url = f"http://{ip}{path}"
            response = requests.get(
                url,
                timeout=timeout,
                allow_redirects=False,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
                    "Accept": "application/json",
                }
            )

            # Look for API-like responses (JSON or specific status codes)
            content_type = response.headers.get("Content-Type", "")
            is_json = "application/json" in content_type or "text/json" in content_type

            # 200 OK with JSON or 401/403 (auth required) indicates API presence
            if response.status_code in [200, 401, 403] and (is_json or response.status_code in [401, 403]):
                return {
                    "type": "ip_api_exposed",
                    "severity": "high",
                    "name": "API Endpoint Exposed on IP",
                    "description": f"API endpoint {path} is accessible via direct IP {ip} without TLS. "
                                  "This exposes the API to interception and WAF bypass attacks.",
                    "url": url,
                    "matched_ip": ip,
                    "path": path,
                    "status_code": response.status_code,
                    "content_type": content_type,
                    "evidence": f"API endpoint returned {response.status_code} with {content_type}",
                }
        except requests.exceptions.RequestException:
            continue

    return None


def check_waf_bypass(
    subdomain: str,
    ip: str,
    timeout: int = 10
) -> Optional[Dict]:
    """
    Check if WAF can be bypassed by accessing the origin server directly via IP.
    Compares responses from subdomain vs direct IP access.

    Args:
        subdomain: The hostname/subdomain
        ip: The resolved IP address
        timeout: Request timeout in seconds

    Returns:
        Vulnerability dict if WAF bypass is possible, None otherwise
    """
    try:
        # Try accessing via subdomain (through WAF/CDN)
        subdomain_url = f"https://{subdomain}"
        subdomain_response = requests.get(
            subdomain_url,
            timeout=timeout,
            allow_redirects=False,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"}
        )

        # Try accessing via direct IP with Host header
        ip_url = f"https://{ip}"
        ip_response = requests.get(
            ip_url,
            timeout=timeout,
            allow_redirects=False,
            verify=False,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
                "Host": subdomain,  # Set Host header to bypass virtual hosting
            }
        )

        # Check if both return similar content (WAF bypass)
        subdomain_server = subdomain_response.headers.get("Server", "").lower()
        ip_server = ip_response.headers.get("Server", "").lower()

        # Detect if subdomain is behind WAF/CDN
        waf_indicators = ["cloudflare", "akamai", "cloudfront", "fastly", "imperva", "sucuri"]
        subdomain_has_waf = any(waf in subdomain_server for waf in waf_indicators)
        ip_has_waf = any(waf in ip_server for waf in waf_indicators)

        # WAF bypass: subdomain has WAF but IP doesn't, and IP returns valid response
        if subdomain_has_waf and not ip_has_waf and ip_response.status_code < 500:
            return {
                "type": "waf_bypass",
                "severity": "high",
                "name": "WAF Bypass via Direct IP Access",
                "description": f"The subdomain {subdomain} is protected by WAF ({subdomain_server}), "
                              f"but the origin server at {ip} is directly accessible. "
                              "This allows bypassing WAF protections.",
                "url": ip_url,
                "matched_ip": ip,
                "subdomain": subdomain,
                "subdomain_server": subdomain_server,
                "ip_server": ip_server,
                "evidence": f"WAF detected on subdomain ({subdomain_server}) but not on IP",
            }

        # Also check if IP returns content without Host header (direct origin exposure)
        if not subdomain_has_waf and ip_response.status_code == 200:
            # Check if responses are similar (same origin)
            if abs(len(subdomain_response.text) - len(ip_response.text)) < 1000:
                return {
                    "type": "waf_bypass",
                    "severity": "medium",
                    "name": "Origin Server Directly Accessible",
                    "description": f"The origin server for {subdomain} is directly accessible at {ip}. "
                                  "Consider restricting access to only allow traffic from CDN/WAF.",
                    "url": ip_url,
                    "matched_ip": ip,
                    "subdomain": subdomain,
                    "evidence": "Similar content served via direct IP access with Host header",
                }
    except requests.exceptions.RequestException:
        pass

    return None


def run_direct_ip_checks(
    ips: List[str],
    subdomains_to_ips: Dict[str, List[str]],
    enabled_checks: Dict[str, bool],
    timeout: int = 10,
    max_workers: int = 10
) -> List[Dict]:
    """
    Run all enabled direct IP access security checks.

    Args:
        ips: List of IP addresses to check
        subdomains_to_ips: Mapping of subdomains to their IPs
        enabled_checks: Dict of check_name -> enabled (bool)
        timeout: Request timeout in seconds
        max_workers: Maximum concurrent workers

    Returns:
        List of vulnerability findings
    """
    findings = []

    def check_single_ip(ip: str) -> List[Dict]:
        ip_findings = []

        if enabled_checks.get("direct_ip_http", True):
            result = check_direct_ip_http(ip, timeout)
            if result:
                ip_findings.append(result)

        if enabled_checks.get("direct_ip_https", True):
            result = check_direct_ip_https(ip, timeout)
            if result:
                ip_findings.append(result)

        if enabled_checks.get("ip_api_exposed", True):
            result = check_ip_api_exposed(ip, timeout)
            if result:
                ip_findings.append(result)

        return ip_findings

    # Run IP checks in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(check_single_ip, ip): ip for ip in ips}
        for future in concurrent.futures.as_completed(future_to_ip):
            try:
                ip_findings = future.result()
                findings.extend(ip_findings)
            except Exception:
                pass

    # Run WAF bypass checks (requires subdomain-to-IP mapping)
    if enabled_checks.get("waf_bypass", True):
        for subdomain, subdomain_ips in subdomains_to_ips.items():
            for ip in subdomain_ips:
                result = check_waf_bypass(subdomain, ip, timeout)
                if result:
                    findings.append(result)

    return findings


# =============================================================================
# TLS/SSL Security Checks
# =============================================================================

def get_ssl_certificate(hostname: str, port: int = 443, timeout: int = 10) -> Optional[Dict]:
    """
    Retrieve SSL certificate information for a host.

    Args:
        hostname: Hostname to check
        port: Port number (default 443)
        timeout: Connection timeout

    Returns:
        Certificate info dict or None if failed
    """
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # Allow self-signed for testing

        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                cert_binary = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                version = ssock.version()

                return {
                    "cert": cert,
                    "cert_binary": cert_binary,
                    "cipher": cipher,
                    "version": version,
                }
    except Exception:
        return None


def parse_cert_date(date_str: str) -> Optional[datetime]:
    """Parse certificate date string to datetime."""
    try:
        # Format: 'Jan  1 00:00:00 2024 GMT'
        return datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
    except ValueError:
        try:
            # Alternative format
            return datetime.strptime(date_str, "%b  %d %H:%M:%S %Y %Z")
        except ValueError:
            return None


def check_tls_expiring_soon(
    hostname: str,
    port: int = 443,
    days_threshold: int = 30,
    timeout: int = 10
) -> Optional[Dict]:
    """
    Check if TLS certificate is expiring soon.

    Args:
        hostname: Hostname to check
        port: Port number
        days_threshold: Days before expiry to warn
        timeout: Connection timeout

    Returns:
        Vulnerability dict if expiring soon, None otherwise
    """
    cert_info = get_ssl_certificate(hostname, port, timeout)
    if not cert_info or not cert_info.get("cert"):
        return None

    cert = cert_info["cert"]
    not_after = cert.get("notAfter")

    if not_after:
        expiry_date = parse_cert_date(not_after)
        now = datetime.now(timezone.utc).replace(tzinfo=None)

        if expiry_date and expiry_date > now:
            days_until_expiry = (expiry_date - now).days
            if days_until_expiry <= days_threshold:
                return {
                    "type": "tls_expiring_soon",
                    "severity": "low",
                    "name": "TLS Certificate Expiring Soon",
                    "description": f"The TLS certificate for {hostname} will expire in {days_until_expiry} days ({not_after}). "
                                  "Consider renewing the certificate to avoid service disruption.",
                    "url": f"https://{hostname}:{port}",
                    "hostname": hostname,
                    "port": port,
                    "expiry_date": not_after,
                    "days_until_expiry": days_until_expiry,
                    "evidence": f"Certificate expires in {days_until_expiry} days",
                }

    return None


def run_tls_checks(
    hostnames: List[str],
    enabled_checks: Dict[str, bool],
    timeout: int = 10,
    expiry_days_threshold: int = 30,
    max_workers: int = 10
) -> List[Dict]:
    """
    Run TLS expiring soon check (other TLS checks are covered by Nuclei).

    Args:
        hostnames: List of hostnames to check
        enabled_checks: Dict of check_name -> enabled (bool)
        timeout: Connection timeout in seconds
        expiry_days_threshold: Days before expiry to warn
        max_workers: Maximum concurrent workers

    Returns:
        List of vulnerability findings
    """
    findings = []

    def check_single_host(hostname: str) -> List[Dict]:
        host_findings = []

        if enabled_checks.get("tls_expiring_soon", True):
            result = check_tls_expiring_soon(hostname, days_threshold=expiry_days_threshold, timeout=timeout)
            if result:
                host_findings.append(result)

        return host_findings

    # Run checks in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_host = {executor.submit(check_single_host, h): h for h in hostnames}
        for future in concurrent.futures.as_completed(future_to_host):
            try:
                host_findings = future.result()
                findings.extend(host_findings)
            except Exception:
                pass

    return findings


# =============================================================================
# Security Headers Checks
# =============================================================================

# Security headers to check (only headers NOT covered by Nuclei templates)
# Note: CSP, X-Frame-Options, X-Content-Type-Options, CORS are covered by Nuclei
SECURITY_HEADERS = {
    "Referrer-Policy": {
        "check_name": "missing_referrer_policy",
        "severity": "low",
        "name": "Referrer-Policy Header Missing",
        "description": "The Referrer-Policy header is not set. "
                      "This may leak sensitive URL information to third-party sites.",
        "recommendation": "Set Referrer-Policy to 'strict-origin-when-cross-origin' or 'no-referrer'.",
    },
    "Permissions-Policy": {
        "check_name": "missing_permissions_policy",
        "severity": "low",
        "name": "Permissions-Policy Header Missing",
        "description": "The Permissions-Policy (formerly Feature-Policy) header is not set. "
                      "This header controls which browser features can be used.",
        "recommendation": "Implement Permissions-Policy to restrict access to sensitive browser APIs.",
    },
    "Cross-Origin-Opener-Policy": {
        "check_name": "missing_coop",
        "severity": "info",
        "name": "Cross-Origin-Opener-Policy Header Missing",
        "description": "The Cross-Origin-Opener-Policy header is not set. "
                      "This header helps prevent cross-origin attacks like Spectre.",
        "recommendation": "Set Cross-Origin-Opener-Policy to 'same-origin' for enhanced isolation.",
    },
    "Cross-Origin-Resource-Policy": {
        "check_name": "missing_corp",
        "severity": "info",
        "name": "Cross-Origin-Resource-Policy Header Missing",
        "description": "The Cross-Origin-Resource-Policy header is not set. "
                      "This header prevents other origins from loading your resources.",
        "recommendation": "Set Cross-Origin-Resource-Policy to 'same-origin' or 'same-site'.",
    },
    "Cross-Origin-Embedder-Policy": {
        "check_name": "missing_coep",
        "severity": "info",
        "name": "Cross-Origin-Embedder-Policy Header Missing",
        "description": "The Cross-Origin-Embedder-Policy header is not set. "
                      "Required for SharedArrayBuffer and high-resolution timers.",
        "recommendation": "Set Cross-Origin-Embedder-Policy to 'require-corp' if using advanced features.",
    },
}


def check_security_headers(
    hostname: str,
    port: int = 443,
    timeout: int = 10,
    enabled_headers: Dict[str, bool] = None
) -> List[Dict]:
    """
    Check for missing security headers on a web application.

    Args:
        hostname: Hostname to check
        port: Port number (443 for HTTPS, 80 for HTTP)
        timeout: Request timeout
        enabled_headers: Dict of header_check_name -> enabled (bool)

    Returns:
        List of vulnerability dicts for missing headers
    """
    findings = []

    # Determine protocol based on port
    protocol = "https" if port == 443 else "http"
    url = f"{protocol}://{hostname}" if port in [80, 443] else f"{protocol}://{hostname}:{port}"

    try:
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            verify=False,  # Allow self-signed for testing
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"}
        )

        # Only check successful responses
        if response.status_code != 200:
            return findings

        response_headers = {k.lower(): v for k, v in response.headers.items()}

        for header_name, header_info in SECURITY_HEADERS.items():
            check_name = header_info["check_name"]

            # Skip if this specific check is disabled
            if enabled_headers and not enabled_headers.get(check_name, True):
                continue

            header_lower = header_name.lower()

            if header_lower not in response_headers:
                findings.append({
                    "type": check_name,
                    "severity": header_info["severity"],
                    "name": header_info["name"],
                    "description": header_info["description"],
                    "url": url,
                    "hostname": hostname,
                    "port": port,
                    "missing_header": header_name,
                    "recommendation": header_info["recommendation"],
                    "evidence": f"Header '{header_name}' not present in response",
                })

    except requests.exceptions.RequestException:
        pass

    return findings


def check_cache_control_missing(hostname: str, port: int = 443, timeout: int = 10) -> Optional[Dict]:
    """
    Check for missing or weak Cache-Control headers on sensitive pages.

    Args:
        hostname: Hostname to check
        port: Port number
        timeout: Request timeout

    Returns:
        Vulnerability dict if cache control is missing/weak, None otherwise
    """
    protocol = "https" if port == 443 else "http"
    url = f"{protocol}://{hostname}" if port in [80, 443] else f"{protocol}://{hostname}:{port}"

    try:
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"}
        )

        if response.status_code != 200:
            return None

        cache_control = response.headers.get("Cache-Control", "").lower()
        pragma = response.headers.get("Pragma", "").lower()

        # Check if caching is properly disabled for the main page
        has_no_store = "no-store" in cache_control
        has_no_cache = "no-cache" in cache_control or "no-cache" in pragma
        has_private = "private" in cache_control

        # If none of these protective measures are present
        if not has_no_store and not has_no_cache and not has_private:
            return {
                "type": "cache_control_missing",
                "severity": "info",
                "name": "Cache-Control Header Missing or Weak",
                "description": f"The server at {hostname} does not set proper Cache-Control headers. "
                              "Sensitive pages may be cached by proxies or browsers.",
                "url": url,
                "hostname": hostname,
                "port": port,
                "cache_control": cache_control if cache_control else None,
                "pragma": pragma if pragma else None,
                "evidence": "No 'no-store', 'no-cache', or 'private' directive found",
                "recommendation": "Set 'Cache-Control: no-store, no-cache, must-revalidate' for sensitive pages.",
            }

    except requests.exceptions.RequestException:
        pass

    return None


# =============================================================================
# Authentication Security Checks
# =============================================================================

def check_login_no_https(hostname: str, timeout: int = 10) -> List[Dict]:
    """
    Check if login forms are served over HTTP (insecure).

    Args:
        hostname: Hostname to check
        timeout: Request timeout

    Returns:
        List of vulnerability findings
    """
    findings = []

    # Common login paths to check
    login_paths = [
        "/login", "/signin", "/sign-in", "/auth", "/authenticate",
        "/admin", "/admin/login", "/wp-login.php", "/user/login",
        "/account/login", "/members/login", "/portal/login",
    ]

    # Check HTTP (insecure)
    for path in login_paths:
        url = f"http://{hostname}{path}"
        try:
            response = requests.get(
                url,
                timeout=timeout,
                allow_redirects=False,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"}
            )

            # Check if response contains login form indicators
            if response.status_code == 200:
                content = response.text.lower()
                has_login_form = any([
                    'type="password"' in content,
                    "type='password'" in content,
                    'name="password"' in content,
                    'id="password"' in content,
                    '<form' in content and 'login' in content,
                ])

                if has_login_form:
                    findings.append({
                        "type": "login_no_https",
                        "severity": "high",
                        "name": "Login Form Served Over HTTP",
                        "description": f"A login form at {url} is served over unencrypted HTTP. "
                                      "User credentials can be intercepted by attackers.",
                        "url": url,
                        "hostname": hostname,
                        "path": path,
                        "evidence": "Login form with password field found on HTTP",
                        "recommendation": "Serve all login pages exclusively over HTTPS and redirect HTTP to HTTPS.",
                    })
                    break  # Found one, no need to check more paths

        except requests.exceptions.RequestException:
            pass

    return findings


def check_session_cookies(hostname: str, timeout: int = 10) -> List[Dict]:
    """
    Check session cookies for missing Secure and HttpOnly flags.

    Args:
        hostname: Hostname to check
        timeout: Request timeout

    Returns:
        List of vulnerability findings
    """
    findings = []
    url = f"https://{hostname}/"

    try:
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"}
        )

        # Check Set-Cookie headers
        set_cookies = response.headers.get_all('Set-Cookie') if hasattr(response.headers, 'get_all') else []
        if not set_cookies:
            # Try alternative method
            set_cookies = [v for k, v in response.headers.items() if k.lower() == 'set-cookie']

        # Also check response.cookies
        for cookie in response.cookies:
            cookie_str = f"{cookie.name}={cookie.value}"

            # Session-like cookie names
            session_indicators = ['session', 'sess', 'sid', 'token', 'auth', 'jwt', 'phpsessid', 'jsessionid', 'asp.net_sessionid']
            is_session_cookie = any(ind in cookie.name.lower() for ind in session_indicators)

            if is_session_cookie:
                # Check Secure flag
                if not cookie.secure:
                    findings.append({
                        "type": "session_no_secure",
                        "severity": "medium",
                        "name": "Session Cookie Missing Secure Flag",
                        "description": f"The session cookie '{cookie.name}' does not have the Secure flag. "
                                      "It can be transmitted over unencrypted HTTP connections.",
                        "url": url,
                        "hostname": hostname,
                        "cookie_name": cookie.name,
                        "evidence": f"Cookie '{cookie.name}' missing Secure attribute",
                        "recommendation": "Add the Secure flag to all session cookies.",
                    })

                # Check HttpOnly flag
                # Note: requests library doesn't expose HttpOnly directly, check raw header
                raw_cookie = response.headers.get('Set-Cookie', '')
                if cookie.name in raw_cookie and 'httponly' not in raw_cookie.lower():
                    findings.append({
                        "type": "session_no_httponly",
                        "severity": "medium",
                        "name": "Session Cookie Missing HttpOnly Flag",
                        "description": f"The session cookie '{cookie.name}' does not have the HttpOnly flag. "
                                      "It can be accessed by JavaScript, enabling XSS-based session theft.",
                        "url": url,
                        "hostname": hostname,
                        "cookie_name": cookie.name,
                        "evidence": f"Cookie '{cookie.name}' missing HttpOnly attribute",
                        "recommendation": "Add the HttpOnly flag to all session cookies.",
                    })

    except requests.exceptions.RequestException:
        pass

    return findings


def check_basic_auth_no_tls(hostname: str, timeout: int = 10) -> Optional[Dict]:
    """
    Check if Basic Authentication is used over HTTP (insecure).

    Args:
        hostname: Hostname to check
        timeout: Request timeout

    Returns:
        Vulnerability dict if found, None otherwise
    """
    url = f"http://{hostname}/"

    try:
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=False,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"}
        )

        # Check for WWW-Authenticate header with Basic auth
        www_auth = response.headers.get('WWW-Authenticate', '')
        if 'basic' in www_auth.lower():
            return {
                "type": "basic_auth_no_tls",
                "severity": "high",
                "name": "Basic Authentication Over HTTP",
                "description": f"The server at {hostname} uses Basic Authentication over unencrypted HTTP. "
                              "Credentials are sent in base64 encoding which can be easily decoded.",
                "url": url,
                "hostname": hostname,
                "www_authenticate": www_auth,
                "evidence": f"WWW-Authenticate: {www_auth}",
                "recommendation": "Use Basic Authentication only over HTTPS, or switch to a more secure authentication method.",
            }

    except requests.exceptions.RequestException:
        pass

    return None


def run_auth_checks(
    hostnames: List[str],
    enabled_checks: Dict[str, bool],
    timeout: int = 10,
    max_workers: int = 10
) -> List[Dict]:
    """
    Run all enabled authentication security checks.

    Args:
        hostnames: List of hostnames to check
        enabled_checks: Dict of check_name -> enabled (bool)
        timeout: Request timeout
        max_workers: Maximum concurrent workers

    Returns:
        List of vulnerability findings
    """
    findings = []

    def check_single_host(hostname: str) -> List[Dict]:
        host_findings = []

        if enabled_checks.get("login_no_https", True):
            results = check_login_no_https(hostname, timeout=timeout)
            host_findings.extend(results)

        if enabled_checks.get("session_no_secure", True) or enabled_checks.get("session_no_httponly", True):
            results = check_session_cookies(hostname, timeout=timeout)
            # Filter based on which checks are enabled
            for finding in results:
                if finding["type"] == "session_no_secure" and enabled_checks.get("session_no_secure", True):
                    host_findings.append(finding)
                elif finding["type"] == "session_no_httponly" and enabled_checks.get("session_no_httponly", True):
                    host_findings.append(finding)

        if enabled_checks.get("basic_auth_no_tls", True):
            result = check_basic_auth_no_tls(hostname, timeout=timeout)
            if result:
                host_findings.append(result)

        return host_findings

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_host = {executor.submit(check_single_host, h): h for h in hostnames}
        for future in concurrent.futures.as_completed(future_to_host):
            try:
                host_findings = future.result()
                findings.extend(host_findings)
            except Exception:
                pass

    return findings


# =============================================================================
# DNS Security Checks
# =============================================================================

import dns.resolver
import dns.zone
import dns.query


def check_spf_missing(domain: str) -> Optional[Dict]:
    """
    Check if SPF record is missing for email security.

    Args:
        domain: Domain to check

    Returns:
        Vulnerability dict if SPF is missing, None otherwise
    """
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt_record = str(rdata).strip('"')
            if txt_record.startswith('v=spf1'):
                return None  # SPF exists

        # No SPF record found
        return {
            "type": "spf_missing",
            "severity": "medium",
            "name": "SPF Record Missing",
            "description": f"The domain {domain} does not have an SPF record. "
                          "This allows attackers to send spoofed emails appearing to come from this domain.",
            "domain": domain,
            "evidence": "No TXT record starting with 'v=spf1' found",
            "recommendation": "Add an SPF record to specify which mail servers can send email for your domain.",
        }

    except dns.resolver.NXDOMAIN:
        return None  # Domain doesn't exist
    except dns.resolver.NoAnswer:
        return {
            "type": "spf_missing",
            "severity": "medium",
            "name": "SPF Record Missing",
            "description": f"The domain {domain} does not have an SPF record.",
            "domain": domain,
            "evidence": "No TXT records found",
            "recommendation": "Add an SPF record to specify which mail servers can send email for your domain.",
        }
    except Exception:
        return None


def check_dmarc_missing(domain: str) -> Optional[Dict]:
    """
    Check if DMARC record is missing for email security.

    Args:
        domain: Domain to check

    Returns:
        Vulnerability dict if DMARC is missing, None otherwise
    """
    dmarc_domain = f"_dmarc.{domain}"

    try:
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        for rdata in answers:
            txt_record = str(rdata).strip('"')
            if txt_record.startswith('v=DMARC1'):
                return None  # DMARC exists

        return {
            "type": "dmarc_missing",
            "severity": "medium",
            "name": "DMARC Record Missing",
            "description": f"The domain {domain} does not have a DMARC record. "
                          "Without DMARC, receiving mail servers cannot verify email authenticity.",
            "domain": domain,
            "evidence": f"No TXT record at _dmarc.{domain} starting with 'v=DMARC1'",
            "recommendation": "Add a DMARC record to define your email authentication policy.",
        }

    except dns.resolver.NXDOMAIN:
        return {
            "type": "dmarc_missing",
            "severity": "medium",
            "name": "DMARC Record Missing",
            "description": f"The domain {domain} does not have a DMARC record.",
            "domain": domain,
            "evidence": f"_dmarc.{domain} does not exist",
            "recommendation": "Add a DMARC record to define your email authentication policy.",
        }
    except dns.resolver.NoAnswer:
        return {
            "type": "dmarc_missing",
            "severity": "medium",
            "name": "DMARC Record Missing",
            "description": f"The domain {domain} does not have a DMARC record.",
            "domain": domain,
            "evidence": f"No TXT records at _dmarc.{domain}",
            "recommendation": "Add a DMARC record to define your email authentication policy.",
        }
    except Exception:
        return None


def check_dnssec_missing(domain: str) -> Optional[Dict]:
    """
    Check if DNSSEC is not enabled for the domain.

    Args:
        domain: Domain to check

    Returns:
        Vulnerability dict if DNSSEC is missing, None otherwise
    """
    try:
        # Try to get DNSKEY records - their presence indicates DNSSEC
        answers = dns.resolver.resolve(domain, 'DNSKEY')
        if answers:
            return None  # DNSSEC is enabled

    except dns.resolver.NoAnswer:
        return {
            "type": "dnssec_missing",
            "severity": "low",
            "name": "DNSSEC Not Enabled",
            "description": f"The domain {domain} does not have DNSSEC enabled. "
                          "DNS responses are not cryptographically signed, allowing DNS spoofing attacks.",
            "domain": domain,
            "evidence": "No DNSKEY records found",
            "recommendation": "Enable DNSSEC to cryptographically sign DNS records.",
        }
    except dns.resolver.NXDOMAIN:
        return None
    except Exception:
        pass

    return None


def check_zone_transfer(domain: str, timeout: int = 10) -> Optional[Dict]:
    """
    Check if DNS zone transfer (AXFR) is enabled.

    Args:
        domain: Domain to check
        timeout: Query timeout

    Returns:
        Vulnerability dict if zone transfer is allowed, None otherwise
    """
    try:
        # Get nameservers for the domain
        ns_answers = dns.resolver.resolve(domain, 'NS')

        for ns in ns_answers:
            ns_host = str(ns.target).rstrip('.')
            try:
                # Try zone transfer
                zone = dns.zone.from_xfr(
                    dns.query.xfr(ns_host, domain, timeout=timeout, lifetime=timeout)
                )

                if zone:
                    # Zone transfer succeeded - this is a vulnerability
                    record_count = len(list(zone.nodes.keys()))
                    return {
                        "type": "zone_transfer",
                        "severity": "high",
                        "name": "DNS Zone Transfer Enabled",
                        "description": f"The nameserver {ns_host} allows zone transfers for {domain}. "
                                      f"An attacker can download all DNS records ({record_count} records found).",
                        "domain": domain,
                        "nameserver": ns_host,
                        "record_count": record_count,
                        "evidence": f"AXFR query to {ns_host} succeeded",
                        "recommendation": "Restrict zone transfers to authorized secondary nameservers only.",
                    }

            except Exception:
                continue  # This NS doesn't allow transfers, try next

    except Exception:
        pass

    return None


def run_dns_checks(
    domain: str,
    enabled_checks: Dict[str, bool],
    timeout: int = 10
) -> List[Dict]:
    """
    Run all enabled DNS security checks.

    Args:
        domain: Domain to check
        enabled_checks: Dict of check_name -> enabled (bool)
        timeout: Query timeout

    Returns:
        List of vulnerability findings
    """
    findings = []

    if enabled_checks.get("spf_missing", True):
        result = check_spf_missing(domain)
        if result:
            findings.append(result)

    if enabled_checks.get("dmarc_missing", True):
        result = check_dmarc_missing(domain)
        if result:
            findings.append(result)

    if enabled_checks.get("dnssec_missing", True):
        result = check_dnssec_missing(domain)
        if result:
            findings.append(result)

    if enabled_checks.get("zone_transfer", True):
        result = check_zone_transfer(domain, timeout=timeout)
        if result:
            findings.append(result)

    return findings


# =============================================================================
# Port/Service Security Checks
# =============================================================================

# Sensitive ports to check
ADMIN_PORTS = {
    22: ("SSH", "Remote shell access"),
    23: ("Telnet", "Unencrypted remote access"),
    3389: ("RDP", "Remote Desktop"),
    5900: ("VNC", "Virtual Network Computing"),
    5901: ("VNC", "Virtual Network Computing"),
}

DATABASE_PORTS = {
    3306: ("MySQL", "MySQL Database"),
    5432: ("PostgreSQL", "PostgreSQL Database"),
    27017: ("MongoDB", "MongoDB Database"),
    27018: ("MongoDB", "MongoDB Database"),
    1433: ("MSSQL", "Microsoft SQL Server"),
    1521: ("Oracle", "Oracle Database"),
    6379: ("Redis", "Redis Cache/Database"),
    9200: ("Elasticsearch", "Elasticsearch"),
    9300: ("Elasticsearch", "Elasticsearch Transport"),
}


def check_admin_ports_exposed(ip: str, open_ports: List[int], timeout: int = 5) -> List[Dict]:
    """
    Check if administrative ports are exposed publicly.

    Args:
        ip: IP address to check
        open_ports: List of open ports from port scan
        timeout: Connection timeout

    Returns:
        List of vulnerability findings
    """
    findings = []

    for port in open_ports:
        if port in ADMIN_PORTS:
            service_name, description = ADMIN_PORTS[port]
            findings.append({
                "type": "admin_port_exposed",
                "severity": "medium",
                "name": f"{service_name} Port Exposed",
                "description": f"{description} port {port} is publicly accessible on {ip}. "
                              "Administrative services should not be directly exposed to the internet.",
                "ip": ip,
                "port": port,
                "service": service_name,
                "evidence": f"Port {port} ({service_name}) is open",
                "recommendation": f"Restrict access to {service_name} using firewall rules or VPN.",
            })

    return findings


def check_database_ports_exposed(ip: str, open_ports: List[int], timeout: int = 5) -> List[Dict]:
    """
    Check if database ports are exposed publicly.

    Args:
        ip: IP address to check
        open_ports: List of open ports from port scan
        timeout: Connection timeout

    Returns:
        List of vulnerability findings
    """
    findings = []

    for port in open_ports:
        if port in DATABASE_PORTS:
            service_name, description = DATABASE_PORTS[port]
            severity = "high" if port != 6379 else "medium"  # Redis handled separately
            findings.append({
                "type": "database_exposed",
                "severity": severity,
                "name": f"{service_name} Port Exposed",
                "description": f"{description} port {port} is publicly accessible on {ip}. "
                              "Database services should never be directly exposed to the internet.",
                "ip": ip,
                "port": port,
                "service": service_name,
                "evidence": f"Port {port} ({service_name}) is open",
                "recommendation": f"Move {service_name} behind a firewall. Only allow access from application servers.",
            })

    return findings


def check_redis_no_auth(ip: str, port: int = 6379, timeout: int = 5) -> Optional[Dict]:
    """
    Check if Redis is accessible without authentication.

    Args:
        ip: IP address to check
        port: Redis port
        timeout: Connection timeout

    Returns:
        Vulnerability dict if Redis has no auth, None otherwise
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        # Send PING command
        sock.send(b"PING\r\n")
        response = sock.recv(1024).decode('utf-8', errors='ignore')
        sock.close()

        if "+PONG" in response:
            return {
                "type": "redis_no_auth",
                "severity": "critical",
                "name": "Redis Without Authentication",
                "description": f"Redis at {ip}:{port} responds to commands without authentication. "
                              "An attacker can read/write data, execute Lua scripts, or potentially get shell access.",
                "ip": ip,
                "port": port,
                "evidence": "PING command returned PONG without authentication",
                "recommendation": "Enable Redis AUTH and use strong passwords. Never expose Redis to the internet.",
            }

    except Exception:
        pass

    return None


def check_kubernetes_api_exposed(ip: str, timeout: int = 10) -> Optional[Dict]:
    """
    Check if Kubernetes API is publicly exposed.

    Args:
        ip: IP address to check
        timeout: Request timeout

    Returns:
        Vulnerability dict if K8s API is exposed, None otherwise
    """
    k8s_ports = [6443, 8443, 443]

    for port in k8s_ports:
        url = f"https://{ip}:{port}/api"
        try:
            response = requests.get(
                url,
                timeout=timeout,
                verify=False,
                headers={"User-Agent": "Mozilla/5.0"}
            )

            # Check for Kubernetes API response
            if response.status_code in [200, 401, 403]:
                content = response.text.lower()
                if 'kind' in content or 'kubernetes' in content or 'apiversion' in content:
                    severity = "critical" if response.status_code == 200 else "high"
                    return {
                        "type": "kubernetes_api_exposed",
                        "severity": severity,
                        "name": "Kubernetes API Exposed",
                        "description": f"Kubernetes API is accessible at {ip}:{port}. "
                                      "This could allow attackers to control the entire cluster.",
                        "ip": ip,
                        "port": port,
                        "url": url,
                        "status_code": response.status_code,
                        "evidence": f"Kubernetes API responded with status {response.status_code}",
                        "recommendation": "Restrict Kubernetes API access using network policies and authentication.",
                    }

        except requests.exceptions.RequestException:
            pass

    return None


def check_smtp_open_relay(ip: str, port: int = 25, timeout: int = 10) -> Optional[Dict]:
    """
    Check if SMTP server is an open relay.

    Args:
        ip: IP address to check
        port: SMTP port
        timeout: Connection timeout

    Returns:
        Vulnerability dict if open relay, None otherwise
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        # Read banner
        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        if '220' not in banner:
            sock.close()
            return None

        # Send HELO
        sock.send(b"HELO test.example.com\r\n")
        response = sock.recv(1024).decode('utf-8', errors='ignore')

        # Try to send from external domain
        sock.send(b"MAIL FROM:<test@external-domain.com>\r\n")
        response = sock.recv(1024).decode('utf-8', errors='ignore')

        if '250' in response:
            # Try recipient at another external domain
            sock.send(b"RCPT TO:<test@another-external-domain.com>\r\n")
            response = sock.recv(1024).decode('utf-8', errors='ignore')

            if '250' in response or '251' in response:
                sock.send(b"QUIT\r\n")
                sock.close()
                return {
                    "type": "smtp_open_relay",
                    "severity": "high",
                    "name": "SMTP Open Relay",
                    "description": f"SMTP server at {ip}:{port} accepts mail relay from external sources. "
                                  "This can be abused for spam campaigns and email spoofing.",
                    "ip": ip,
                    "port": port,
                    "evidence": "Server accepted RCPT TO for external domain",
                    "recommendation": "Configure SMTP to only relay mail for authenticated users or authorized domains.",
                }

        sock.send(b"QUIT\r\n")
        sock.close()

    except Exception:
        pass

    return None


def run_port_service_checks(
    recon_data: Dict[str, Any],
    enabled_checks: Dict[str, bool],
    timeout: int = 10,
    max_workers: int = 10
) -> List[Dict]:
    """
    Run all enabled port/service security checks.

    Args:
        recon_data: Reconnaissance data with port scan results
        enabled_checks: Dict of check_name -> enabled (bool)
        timeout: Connection timeout
        max_workers: Maximum concurrent workers

    Returns:
        List of vulnerability findings
    """
    findings = []

    # Get port scan data
    port_scan = recon_data.get("port_scan", {})

    def check_single_ip(ip: str, ports_data: Dict) -> List[Dict]:
        ip_findings = []

        # Extract open ports
        open_ports = []
        for port_str, port_info in ports_data.items():
            if isinstance(port_info, dict) and port_info.get("state") == "open":
                try:
                    open_ports.append(int(port_str))
                except ValueError:
                    pass

        if enabled_checks.get("admin_port_exposed", True):
            results = check_admin_ports_exposed(ip, open_ports, timeout)
            ip_findings.extend(results)

        if enabled_checks.get("database_exposed", True):
            results = check_database_ports_exposed(ip, open_ports, timeout)
            ip_findings.extend(results)

        if enabled_checks.get("redis_no_auth", True) and 6379 in open_ports:
            result = check_redis_no_auth(ip, timeout=timeout)
            if result:
                ip_findings.append(result)

        if enabled_checks.get("kubernetes_api_exposed", True):
            result = check_kubernetes_api_exposed(ip, timeout=timeout)
            if result:
                ip_findings.append(result)

        if enabled_checks.get("smtp_open_relay", True) and 25 in open_ports:
            result = check_smtp_open_relay(ip, timeout=timeout)
            if result:
                ip_findings.append(result)

        return ip_findings

    # Process each IP with port scan data
    ips_to_check = []
    for ip, ports_data in port_scan.items():
        if isinstance(ports_data, dict):
            ips_to_check.append((ip, ports_data))

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(check_single_ip, ip, ports): ip for ip, ports in ips_to_check}
        for future in concurrent.futures.as_completed(future_to_ip):
            try:
                ip_findings = future.result()
                findings.extend(ip_findings)
            except Exception:
                pass

    return findings


# =============================================================================
# Application Security Checks
# =============================================================================

def check_csp_unsafe_inline(hostname: str, timeout: int = 10) -> Optional[Dict]:
    """
    Check if CSP header allows unsafe-inline (weakens XSS protection).

    Args:
        hostname: Hostname to check
        timeout: Request timeout

    Returns:
        Vulnerability dict if unsafe-inline found, None otherwise
    """
    url = f"https://{hostname}/"

    try:
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"}
        )

        csp = response.headers.get('Content-Security-Policy', '')

        if csp and "'unsafe-inline'" in csp.lower():
            # Check which directives have unsafe-inline
            unsafe_directives = []
            for directive in csp.split(';'):
                directive = directive.strip()
                if "'unsafe-inline'" in directive.lower():
                    unsafe_directives.append(directive.split()[0] if directive.split() else directive)

            return {
                "type": "csp_unsafe_inline",
                "severity": "medium",
                "name": "CSP Allows Unsafe Inline",
                "description": f"The Content-Security-Policy for {hostname} allows 'unsafe-inline'. "
                              "This weakens XSS protection by allowing inline scripts/styles.",
                "url": url,
                "hostname": hostname,
                "csp_header": csp[:500],  # Truncate if very long
                "unsafe_directives": unsafe_directives,
                "evidence": f"'unsafe-inline' found in: {', '.join(unsafe_directives)}",
                "recommendation": "Remove 'unsafe-inline' and use nonces or hashes for inline scripts.",
            }

    except requests.exceptions.RequestException:
        pass

    return None


def check_insecure_form_action(hostname: str, timeout: int = 10) -> List[Dict]:
    """
    Check if HTTPS pages have forms that post to HTTP endpoints.

    Args:
        hostname: Hostname to check
        timeout: Request timeout

    Returns:
        List of vulnerability findings
    """
    import re
    findings = []
    url = f"https://{hostname}/"

    try:
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"}
        )

        if response.status_code == 200:
            content = response.text

            # Find form actions pointing to HTTP
            form_pattern = r'<form[^>]*action\s*=\s*["\']?(http://[^"\'>\s]+)["\']?'
            matches = re.findall(form_pattern, content, re.IGNORECASE)

            for http_action in matches:
                findings.append({
                    "type": "insecure_form_action",
                    "severity": "high",
                    "name": "HTTPS Form Posts to HTTP",
                    "description": f"A form on {url} posts data to an unencrypted HTTP endpoint: {http_action}. "
                                  "Form data including credentials may be intercepted.",
                    "url": url,
                    "hostname": hostname,
                    "insecure_action": http_action,
                    "evidence": f"Form action points to {http_action}",
                    "recommendation": "Ensure all form actions use HTTPS endpoints.",
                })

    except requests.exceptions.RequestException:
        pass

    return findings


def run_app_security_checks(
    hostnames: List[str],
    enabled_checks: Dict[str, bool],
    timeout: int = 10,
    max_workers: int = 10
) -> List[Dict]:
    """
    Run all enabled application security checks.

    Args:
        hostnames: List of hostnames to check
        enabled_checks: Dict of check_name -> enabled (bool)
        timeout: Request timeout
        max_workers: Maximum concurrent workers

    Returns:
        List of vulnerability findings
    """
    findings = []

    def check_single_host(hostname: str) -> List[Dict]:
        host_findings = []

        if enabled_checks.get("csp_unsafe_inline", True):
            result = check_csp_unsafe_inline(hostname, timeout=timeout)
            if result:
                host_findings.append(result)

        if enabled_checks.get("insecure_form_action", True):
            results = check_insecure_form_action(hostname, timeout=timeout)
            host_findings.extend(results)

        return host_findings

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_host = {executor.submit(check_single_host, h): h for h in hostnames}
        for future in concurrent.futures.as_completed(future_to_host):
            try:
                host_findings = future.result()
                findings.extend(host_findings)
            except Exception:
                pass

    return findings


# =============================================================================
# Rate Limiting Checks
# =============================================================================

def check_no_rate_limiting(urls: List[str], hostname: str, timeout: int = 5) -> List[Dict]:
    """
    Check if rate limiting is missing on login/auth endpoints.

    Args:
        urls: List of URLs discovered from recon (e.g., from resource_enum)
        hostname: Hostname being checked
        timeout: Request timeout per request

    Returns:
        List of vulnerability findings for endpoints without rate limiting
    """
    findings = []

    # Keywords that indicate authentication endpoints
    auth_keywords = [
        'login', 'signin', 'sign-in', 'auth', 'authenticate', 'session',
        'token', 'oauth', 'sso', 'password', 'credential', 'account/login',
        'user/login', 'admin/login', 'api/login', 'api/auth', 'wp-login',
        'register', 'signup', 'sign-up', 'forgot', 'reset-password'
    ]

    # Filter URLs that belong to this hostname and contain auth keywords
    auth_urls = set()
    for url in urls:
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            # Check if URL belongs to this hostname
            if parsed.netloc == hostname or parsed.netloc.endswith(f'.{hostname}'):
                url_lower = url.lower()
                if any(keyword in url_lower for keyword in auth_keywords):
                    # Normalize to base URL without query params for rate limit test
                    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    auth_urls.add(base_url)
        except Exception:
            pass

    # Fallback: also check common endpoints if no auth URLs found from recon
    if not auth_urls:
        fallback_endpoints = [
            "/login", "/signin", "/sign-in", "/auth", "/authenticate",
            "/admin/login", "/wp-login.php", "/user/login", "/api/login",
            "/api/auth", "/api/v1/login", "/oauth/token"
        ]
        for endpoint in fallback_endpoints:
            auth_urls.add(f"https://{hostname}{endpoint}")

    # Test each auth URL for rate limiting
    tested_urls = set()  # Avoid testing same URL twice

    for url in auth_urls:
        if url in tested_urls:
            continue
        tested_urls.add(url)

        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            endpoint = parsed.path

            # First check if endpoint exists
            response = requests.get(
                url,
                timeout=timeout,
                verify=False,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"}
            )

            # Skip if endpoint doesn't exist
            if response.status_code == 404:
                continue

            # Send multiple rapid requests (10 requests)
            success_count = 0
            rate_limit_detected = False

            for i in range(10):
                try:
                    resp = requests.post(
                        url,
                        timeout=timeout,
                        verify=False,
                        data={"username": f"test{i}", "password": "test"},
                        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"}
                    )

                    # Check for rate limiting indicators
                    if resp.status_code == 429:  # Too Many Requests
                        rate_limit_detected = True
                        break
                    if 'rate' in resp.text.lower() and 'limit' in resp.text.lower():
                        rate_limit_detected = True
                        break
                    if resp.headers.get('Retry-After'):
                        rate_limit_detected = True
                        break
                    if resp.headers.get('X-RateLimit-Remaining', '999') == '0':
                        rate_limit_detected = True
                        break

                    success_count += 1

                except requests.exceptions.RequestException:
                    break

            if success_count >= 10 and not rate_limit_detected:
                findings.append({
                    "type": "no_rate_limiting",
                    "severity": "medium",
                    "name": "No Rate Limiting on Login",
                    "description": f"The login endpoint {url} does not appear to have rate limiting. "
                                  "This allows brute force attacks against user accounts.",
                    "url": url,
                    "hostname": hostname,
                    "endpoint": endpoint,
                    "requests_sent": success_count,
                    "evidence": f"Sent {success_count} requests without triggering rate limit",
                    "recommendation": "Implement rate limiting on authentication endpoints (e.g., 5 attempts per minute).",
                })

        except requests.exceptions.RequestException:
            continue

    return findings


def run_rate_limit_checks(
    hostnames: List[str],
    recon_data: Dict[str, Any],
    enabled_checks: Dict[str, bool],
    timeout: int = 5,
    max_workers: int = 5  # Lower concurrency to avoid false positives
) -> List[Dict]:
    """
    Run all enabled rate limiting checks.

    Args:
        hostnames: List of hostnames to check
        recon_data: Reconnaissance data containing discovered URLs
        enabled_checks: Dict of check_name -> enabled (bool)
        timeout: Request timeout
        max_workers: Maximum concurrent workers

    Returns:
        List of vulnerability findings
    """
    findings = []

    if not enabled_checks.get("no_rate_limiting", True):
        return findings

    # Extract all discovered URLs from recon data
    discovered_urls = []

    # From resource_enum
    resource_enum = recon_data.get("resource_enum", {})
    if resource_enum:
        discovered_urls.extend(resource_enum.get("discovered_urls", []))

    # From nuclei scan discovered_urls
    nuclei_data = recon_data.get("nuclei_scan", {})
    if nuclei_data:
        nuclei_urls = nuclei_data.get("discovered_urls", {})
        if nuclei_urls:
            discovered_urls.extend(nuclei_urls.get("all_scanned_urls", []))
            discovered_urls.extend(nuclei_urls.get("dast_urls_with_params", []))

    # From httpx data (live URLs)
    httpx_data = recon_data.get("httpx", {})
    if httpx_data:
        for entry in httpx_data.values():
            if isinstance(entry, dict) and entry.get("url"):
                discovered_urls.append(entry["url"])

    # Deduplicate
    discovered_urls = list(set(discovered_urls))

    def check_single_host(hostname: str) -> List[Dict]:
        host_findings = check_no_rate_limiting(
            urls=discovered_urls,
            hostname=hostname,
            timeout=timeout
        )
        return host_findings

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_host = {executor.submit(check_single_host, h): h for h in hostnames}
        for future in concurrent.futures.as_completed(future_to_host):
            try:
                host_findings = future.result()
                findings.extend(host_findings)
            except Exception:
                pass

    return findings


def run_security_headers_checks(
    hostnames: List[str],
    enabled_checks: Dict[str, bool],
    timeout: int = 10,
    max_workers: int = 10
) -> List[Dict]:
    """
    Run all enabled security headers checks.

    Args:
        hostnames: List of hostnames to check
        enabled_checks: Dict of check_name -> enabled (bool)
        timeout: Request timeout in seconds
        max_workers: Maximum concurrent workers

    Returns:
        List of vulnerability findings
    """
    findings = []

    def check_single_host(hostname: str) -> List[Dict]:
        host_findings = []

        # Check missing security headers (HTTPS)
        any_header_check_enabled = any(
            enabled_checks.get(info["check_name"], True)
            for info in SECURITY_HEADERS.values()
        )

        if any_header_check_enabled:
            header_findings = check_security_headers(
                hostname=hostname,
                port=443,
                timeout=timeout,
                enabled_headers=enabled_checks
            )
            host_findings.extend(header_findings)

        # Check cache control
        if enabled_checks.get("cache_control_missing", True):
            result = check_cache_control_missing(hostname, port=443, timeout=timeout)
            if result:
                host_findings.append(result)

        return host_findings

    # Run checks in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_host = {executor.submit(check_single_host, h): h for h in hostnames}
        for future in concurrent.futures.as_completed(future_to_host):
            try:
                host_findings = future.result()
                findings.extend(host_findings)
            except Exception:
                pass

    return findings


# =============================================================================
# Main Entry Point
# =============================================================================

def run_security_checks(
    recon_data: Dict[str, Any],
    enabled_checks: Dict[str, bool],
    timeout: int = 10,
    tls_expiry_days: int = 30,
    max_workers: int = 10
) -> Dict[str, Any]:
    """
    Run all enabled security checks on recon data.

    Args:
        recon_data: The reconnaissance data dictionary
        enabled_checks: Dict of check_name -> enabled (bool)
        timeout: Request/connection timeout
        tls_expiry_days: Days before TLS expiry to warn
        max_workers: Maximum concurrent workers

    Returns:
        Dictionary with security check findings
    """
    print("\n" + "=" * 70)
    print("[*][SecurityCheck] Custom Security Checks")
    print("=" * 70)

    # Extract IPs and hostnames from recon data
    ips = set()
    hostnames = set()
    subdomains_to_ips = {}

    dns_data = recon_data.get("dns", {})

    # From root domain
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
            subdomains_to_ips[domain] = list(set(ipv4_list + ipv6_list))

    # From subdomains
    subdomains_dns = dns_data.get("subdomains", {})
    for subdomain, subdomain_data in subdomains_dns.items():
        if subdomain_data and subdomain_data.get("has_records"):
            hostnames.add(subdomain)
            if subdomain_data.get("ips"):
                ipv4_list = subdomain_data["ips"].get("ipv4", [])
                ipv6_list = subdomain_data["ips"].get("ipv6", [])
                ips.update(ipv4_list)
                ips.update(ipv6_list)
                subdomains_to_ips[subdomain] = list(set(ipv4_list + ipv6_list))

    # Filter empty values
    ips = [ip for ip in ips if ip]
    hostnames = [h for h in hostnames if h]

    print(f"[*][SecurityCheck] Targets: {len(hostnames)} hostnames, {len(ips)} IPs")
    print(f"[*][SecurityCheck] Timeout: {timeout}s")
    print(f"[*][SecurityCheck] Workers: {max_workers}")

    # Count enabled checks by category
    ip_checks = ["direct_ip_http", "direct_ip_https", "ip_api_exposed", "waf_bypass"]
    tls_checks = ["tls_expiring_soon"]
    header_checks = [
        "missing_referrer_policy", "missing_permissions_policy",
        "missing_coop", "missing_corp", "missing_coep",
        "cache_control_missing"
    ]
    auth_checks = ["login_no_https", "session_no_secure", "session_no_httponly", "basic_auth_no_tls"]
    dns_checks = ["spf_missing", "dmarc_missing", "dnssec_missing", "zone_transfer"]
    port_checks = ["admin_port_exposed", "database_exposed", "redis_no_auth", "kubernetes_api_exposed", "smtp_open_relay"]
    app_checks = ["csp_unsafe_inline", "insecure_form_action"]
    rate_checks = ["no_rate_limiting"]

    enabled_ip = sum(1 for c in ip_checks if enabled_checks.get(c, False))
    enabled_tls = sum(1 for c in tls_checks if enabled_checks.get(c, False))
    enabled_headers = sum(1 for c in header_checks if enabled_checks.get(c, False))
    enabled_auth = sum(1 for c in auth_checks if enabled_checks.get(c, False))
    enabled_dns = sum(1 for c in dns_checks if enabled_checks.get(c, False))
    enabled_port = sum(1 for c in port_checks if enabled_checks.get(c, False))
    enabled_app = sum(1 for c in app_checks if enabled_checks.get(c, False))
    enabled_rate = sum(1 for c in rate_checks if enabled_checks.get(c, False))

    print(f"[*][SecurityCheck] Enabled checks:")
    print(f"[*][SecurityCheck]   - Direct IP: {enabled_ip}, TLS: {enabled_tls}, Headers: {enabled_headers}")
    print(f"[*][SecurityCheck]   - Auth: {enabled_auth}, DNS: {enabled_dns}, Port/Service: {enabled_port}")
    print(f"[*][SecurityCheck]   - App Security: {enabled_app}, Rate Limit: {enabled_rate}")
    print("=" * 70 + "\n")

    all_findings = []

    # Run direct IP access checks
    if enabled_ip > 0 and ips:
        print(f"[*][SecurityCheck] Running Direct IP Access checks on {len(ips)} IPs...")
        ip_findings = run_direct_ip_checks(
            ips=list(ips),
            subdomains_to_ips=subdomains_to_ips,
            enabled_checks=enabled_checks,
            timeout=timeout,
            max_workers=max_workers
        )
        all_findings.extend(ip_findings)
        print(f"[+][SecurityCheck] Found {len(ip_findings)} issues")

    # Run TLS/SSL checks
    if enabled_tls > 0 and hostnames:
        print(f"[*][SecurityCheck] Running TLS/SSL checks on {len(hostnames)} hostnames...")
        tls_findings = run_tls_checks(
            hostnames=list(hostnames),
            enabled_checks=enabled_checks,
            timeout=timeout,
            expiry_days_threshold=tls_expiry_days,
            max_workers=max_workers
        )
        all_findings.extend(tls_findings)
        print(f"[+][SecurityCheck] Found {len(tls_findings)} issues")

    # Run Security Headers checks
    if enabled_headers > 0 and hostnames:
        print(f"[*][SecurityCheck] Running Security Headers checks on {len(hostnames)} hostnames...")
        headers_findings = run_security_headers_checks(
            hostnames=list(hostnames),
            enabled_checks=enabled_checks,
            timeout=timeout,
            max_workers=max_workers
        )
        all_findings.extend(headers_findings)
        print(f"[+][SecurityCheck] Found {len(headers_findings)} issues")

    # Run Authentication checks
    if enabled_auth > 0 and hostnames:
        print(f"[*][SecurityCheck] Running Authentication checks on {len(hostnames)} hostnames...")
        auth_findings = run_auth_checks(
            hostnames=list(hostnames),
            enabled_checks=enabled_checks,
            timeout=timeout,
            max_workers=max_workers
        )
        all_findings.extend(auth_findings)
        print(f"[+][SecurityCheck] Found {len(auth_findings)} issues")

    # Run DNS Security checks
    if enabled_dns > 0:
        # Extract domain from recon_data
        domain = recon_data.get("domain", "")
        if domain:
            print(f"[*][SecurityCheck] Running DNS Security checks on {domain}...")
            dns_findings = run_dns_checks(
                domain=domain,
                enabled_checks=enabled_checks,
                timeout=timeout
            )
            all_findings.extend(dns_findings)
            print(f"[+][SecurityCheck] Found {len(dns_findings)} issues")

    # Run Port/Service Security checks
    if enabled_port > 0:
        print(f"[*][SecurityCheck] Running Port/Service Security checks...")
        port_findings = run_port_service_checks(
            recon_data=recon_data,
            enabled_checks=enabled_checks,
            timeout=timeout,
            max_workers=max_workers
        )
        all_findings.extend(port_findings)
        print(f"[+][SecurityCheck] Found {len(port_findings)} issues")

    # Run Application Security checks
    if enabled_app > 0 and hostnames:
        print(f"[*][SecurityCheck] Running Application Security checks on {len(hostnames)} hostnames...")
        app_findings = run_app_security_checks(
            hostnames=list(hostnames),
            enabled_checks=enabled_checks,
            timeout=timeout,
            max_workers=max_workers
        )
        all_findings.extend(app_findings)
        print(f"[+][SecurityCheck] Found {len(app_findings)} issues")

    # Run Rate Limiting checks
    if enabled_rate > 0 and hostnames:
        print(f"[*][SecurityCheck] Running Rate Limiting checks on {len(hostnames)} hostnames...")
        rate_findings = run_rate_limit_checks(
            hostnames=list(hostnames),
            recon_data=recon_data,
            enabled_checks=enabled_checks,
            timeout=timeout,
            max_workers=min(max_workers, 5)  # Lower concurrency for rate limit checks
        )
        all_findings.extend(rate_findings)
        print(f"[+][SecurityCheck] Found {len(rate_findings)} issues")

    # Organize findings by type and severity
    by_type = {}
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    for finding in all_findings:
        finding_type = finding.get("type", "unknown")
        severity = finding.get("severity", "info")

        if finding_type not in by_type:
            by_type[finding_type] = []
        by_type[finding_type].append(finding)

        if severity in severity_counts:
            severity_counts[severity] += 1

    # Build result structure (compatible with neo4j_client)
    result = {
        "security_checks": {
            "scan_timestamp": datetime.now().isoformat(),
            "checks_enabled": enabled_checks,
            "targets_checked": {
                "hostnames": len(hostnames),
                "ips": len(ips),
            },
            "findings": all_findings,
            "by_type": by_type,
            "summary": {
                "total_findings": len(all_findings),
                **severity_counts,
            }
        }
    }

    # Print summary
    print(f"\n{'=' * 70}")
    print(f"[+][SecurityCheck] SECURITY CHECKS COMPLETE")
    print(f"[+][SecurityCheck] Total findings: {len(all_findings)}")

    if any(severity_counts[s] > 0 for s in ["critical", "high", "medium", "low"]):
        print(f"\n[+][SecurityCheck] SEVERITY SUMMARY:")
        if severity_counts['critical'] > 0:
            print(f"[!][SecurityCheck] CRITICAL: {severity_counts['critical']}")
        if severity_counts['high'] > 0:
            print(f"[!][SecurityCheck] HIGH: {severity_counts['high']}")
        if severity_counts['medium'] > 0:
            print(f"[*][SecurityCheck] MEDIUM: {severity_counts['medium']}")
        if severity_counts['low'] > 0:
            print(f"[*][SecurityCheck] LOW: {severity_counts['low']}")

    if by_type:
        print(f"\n[+][SecurityCheck] FINDINGS BY TYPE:")
        for finding_type, findings_list in sorted(by_type.items(), key=lambda x: len(x[1]), reverse=True):
            print(f"[*][SecurityCheck]   {finding_type}: {len(findings_list)}")

    print(f"{'=' * 70}")

    return result
