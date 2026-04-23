"""
RedAmon - Target Extraction Helpers
====================================
Functions for extracting and building target URLs from reconnaissance data.
"""

from typing import Dict, List, Optional, Set, Tuple


# =============================================================================
# Target Extraction from Recon Data
# =============================================================================

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


# =============================================================================
# URL Building from httpx Data
# =============================================================================

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


# =============================================================================
# URL Building from Resource Enumeration Data
# =============================================================================

def build_target_urls_from_resource_enum(resource_enum_data: Optional[dict]) -> Tuple[List[str], List[str]]:
    """
    Build list of target URLs from resource_enum data.

    Args:
        resource_enum_data: Resource enumeration data with endpoints

    Returns:
        Tuple of (base_urls, endpoint_urls_with_params)
    """
    base_urls = []
    endpoint_urls = []

    if not resource_enum_data:
        return base_urls, endpoint_urls

    by_base_url = resource_enum_data.get("by_base_url", {})

    for base_url, base_data in by_base_url.items():
        base_urls.append(base_url)

        endpoints = base_data.get("endpoints", {})
        for path, endpoint_info in endpoints.items():
            # Build URLs with sample parameter values for GET endpoints
            parameters = endpoint_info.get("parameters", {})
            query_params = parameters.get("query", [])

            if query_params:
                # Build URL with parameters
                param_parts = []
                for param in query_params:
                    name = param.get("name")
                    sample_values = param.get("sample_values", [])
                    value = sample_values[0] if sample_values else "1"
                    param_parts.append(f"{name}={value}")

                if param_parts:
                    full_url = f"{base_url}{path}?{'&'.join(param_parts)}"
                    endpoint_urls.append(full_url)
            else:
                # Add path without params
                endpoint_urls.append(f"{base_url}{path}")

    return base_urls, endpoint_urls


# =============================================================================
# Combined URL Building
# =============================================================================

def build_target_urls(
    hostnames: Set[str], 
    ips: Set[str], 
    recon_data: Optional[dict] = None,
    scan_all_ips: bool = False
) -> List[str]:
    """
    Build list of target URLs for nuclei scanning.
    Prefers resource_enum endpoints, then httpx data (live URLs), falls back to default URLs.

    Args:
        hostnames: Set of hostnames to scan
        ips: Set of IPs to scan (if scan_all_ips is True)
        recon_data: Full recon data containing httpx/resource_enum results
        scan_all_ips: Whether to include IP addresses in URL list

    Returns:
        List of URLs to scan
    """
    urls = []

    # Priority 1: Use resource_enum endpoints if available (most comprehensive)
    resource_enum_data = recon_data.get("resource_enum") if recon_data else None
    if resource_enum_data:
        base_urls, endpoint_urls = build_target_urls_from_resource_enum(resource_enum_data)
        if base_urls:
            # Combine base URLs with endpoint URLs for comprehensive coverage
            urls = list(set(base_urls + endpoint_urls))
            print(f"[*][Targets] Using {len(base_urls)} base URLs + {len(endpoint_urls)} endpoint URLs from resource_enum")
            return sorted(urls)

    # Priority 2: Use live URLs from httpx (fallback if resource_enum not run)
    httpx_data = recon_data.get("http_probe") if recon_data else None
    if httpx_data:
        urls = build_target_urls_from_httpx(httpx_data)
        if urls:
            print(f"[*][Targets] Using {len(urls)} live URLs from httpx probe")
            return urls

    # Priority 3: Fallback to default ports for all hostnames
    for hostname in sorted(hostnames):
        urls.append(f"http://{hostname}")
        urls.append(f"https://{hostname}")

    # Optionally add IPs
    if scan_all_ips:
        for ip in sorted(ips):
            urls.append(f"http://{ip}")
            urls.append(f"https://{ip}")

    print(f"[*][Targets] Using {len(urls)} default URLs (no httpx data)")
    return sorted(list(set(urls)))

