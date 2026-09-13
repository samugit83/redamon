"""
RedAmon - Target Extraction Helpers
====================================
Functions for extracting and building target URLs from reconnaissance data.
"""

import ipaddress
import re
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse


# =============================================================================
# Target Extraction from Recon Data
# =============================================================================

def extract_targets_from_recon(recon_data: dict) -> Tuple[Set[str], Set[str], Dict[str, List[str]]]:
    """
    Extract all unique IPs, hostnames, and build IP-to-hostname mapping.

    Honors recon_data["metadata"]["include_root_domain"]: when explicitly
    False, the apex/root domain is NOT added to the hostname set, even when
    dns.domain is populated. The full pipeline sets this flag in main.py
    (parse_target + GROUP-2/3 branches); partial-recon graph builders set
    it from project settings. Default (flag missing) is True, preserving
    legacy behavior where the apex is always included.

    Returns:
        Tuple of (unique_ips, unique_hostnames, ip_to_hostnames_mapping)
    """
    ips = set()
    hostnames = set()
    ip_to_hostnames = {}

    dns_data = recon_data.get("dns", {})
    if not dns_data:
        return ips, hostnames, ip_to_hostnames

    metadata = recon_data.get("metadata") or {}
    include_root_domain = metadata.get("include_root_domain", True)

    # Extract from root domain
    domain = recon_data.get("domain", "") or metadata.get("target", "")
    domain_dns = dns_data.get("domain", {})
    if domain_dns:
        domain_ips = domain_dns.get("ips", {})
        ipv4_list = domain_ips.get("ipv4", [])
        ipv6_list = domain_ips.get("ipv6", [])

        ips.update(ipv4_list)
        ips.update(ipv6_list)

        if domain and include_root_domain:
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

def _hosts_in_urls(urls: Set[str]) -> Set[str]:
    """Extract the set of lowercased hostnames present in a URL set."""
    hosts: Set[str] = set()
    for u in urls:
        try:
            host = urlparse(u).hostname
        except (ValueError, TypeError):
            continue
        if host:
            hosts.add(host.lower())
    return hosts


# Mock hostnames minted for IPs with no PTR record: recon/main.py replaces the
# separators with dashes ("192.88.99.10" -> "192-88-99-10", "fe80::1" ->
# "fe80--1"). They exist so the graph can label the host; they are NOT
# resolvable and must never reach a crawler. See build_target_urls source 3.
_MOCK_IPV4_RE = re.compile(r"^\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}$")


def _is_mock_ip_hostname(hostname: str) -> bool:
    """True when `hostname` is a dashed-IP placeholder rather than a real host.

    Deliberately narrow: only a label that is ENTIRELY digits and dashes (or
    hex and dashes, for IPv6) and that maps back to a valid IP literal. A real
    domain like "mail-01.example.com" contains dots and is never matched.
    """
    if not hostname or "." in hostname:
        return False
    candidate = hostname.strip().lower()
    if _MOCK_IPV4_RE.match(candidate):
        try:
            ipaddress.ip_address(candidate.replace("-", "."))
            return True
        except ValueError:
            return False
    # IPv6 placeholders: only hex digits and dashes, and round-trips to an IP.
    if candidate and all(c in "0123456789abcdef-" for c in candidate) and "-" in candidate:
        try:
            ipaddress.ip_address(candidate.replace("-", ":"))
            return True
        except ValueError:
            return False
    return False


def build_target_urls(
    hostnames: Set[str],
    ips: Set[str],
    recon_data: Optional[dict] = None,
    scan_all_ips: bool = False,
) -> List[str]:
    """
    Build the list of target URLs for nuclei scanning as the UNION of every
    available source, deduplicated.

    Sources (all merged, none shadowed):
      1. Endpoint URLs from resource_enum (parameterized URLs, e.g. /api?q=1).
      2. BaseURL nodes from httpx (live URLs, e.g. https://A.com).
      3. http(s)://{hostname} for every hostname/subdomain whose host is NOT
         already represented by sources 1 or 2 (so newly-discovered subdomains
         that haven't been probed yet still get scanned).
      4. http(s)://{ip} for IPs not already covered, only if scan_all_ips=True.

    A hostname is "already covered" iff some URL in sources 1+2 has that exact
    hostname (httpx already picked the working scheme; re-scanning the other
    scheme would just waste rate-limit budget).

    Args:
        hostnames: Set of hostnames/subdomains discovered via DNS.
        ips: Set of IPs discovered via DNS.
        recon_data: Full recon data dict with optional 'resource_enum' and
                    'http_probe' keys.
        scan_all_ips: Whether to include IP addresses (default False).

    Returns:
        Sorted, deduplicated list of URLs to scan.
    """
    url_set: Set[str] = set()
    counts = {
        "resource_enum_base": 0,
        "resource_enum_endpoint": 0,
        "httpx": 0,
        "fallback_subdomain": 0,
        "fallback_ip": 0,
        "skipped_mock_hostname": 0,
    }

    # Source 1: resource_enum (BaseURLs + parameterized endpoint URLs)
    resource_enum_data = recon_data.get("resource_enum") if recon_data else None
    if resource_enum_data:
        base_urls, endpoint_urls = build_target_urls_from_resource_enum(resource_enum_data)
        for u in base_urls:
            if u not in url_set:
                url_set.add(u)
                counts["resource_enum_base"] += 1
        for u in endpoint_urls:
            if u not in url_set:
                url_set.add(u)
                counts["resource_enum_endpoint"] += 1

    # Source 2: httpx live URLs (BaseURLs verified by httpx)
    httpx_data = recon_data.get("http_probe") if recon_data else None
    if httpx_data:
        for u in build_target_urls_from_httpx(httpx_data):
            if u not in url_set:
                url_set.add(u)
                counts["httpx"] += 1

    # Compute which hostnames sources 1+2 already cover (host-only match,
    # ignoring scheme/port/path) so we don't re-add them as fallback URLs.
    covered_hosts = _hosts_in_urls(url_set)

    # Source 3: hostnames not covered by httpx/resource_enum → both schemes.
    # This catches newly discovered subdomains that haven't been probed yet.
    for hostname in sorted(hostnames):
        if not hostname or hostname.lower() in covered_hosts:
            continue
        # Skip MOCK hostnames. When an IP has no PTR record, recon/main.py
        # labels it with the IP's dots turned into dashes ("192.88.99.10" ->
        # "192-88-99-10") so the graph has something to show. That label is a
        # DISPLAY ARTIFACT - it has no DNS record and never will.
        #
        # Handing it to the crawlers is not merely wasteful, it is destructive:
        # a non-resolving seed makes hakrawler return ZERO urls overall (not
        # merely zero for that seed) and collapses katana's stdout to zero
        # lines, while both still exit 0 with no stderr. Every real URL they
        # crawled is discarded. Bisected against the guinea pig on 2026-08-07:
        #
        #   real seeds only ............. katana 25, hakrawler 48
        #   + the two mock seeds ........ katana  0, hakrawler  0
        #
        # depth and crawl-duration were ruled out; the mock seeds alone flip it.
        # This hit EVERY IP-only target, silently, and downstream it looked
        # like "the target serves no JavaScript" - which in the supply-chain
        # pipeline reads as a clean bill of health.
        #
        # Nothing is lost by skipping them: the real IP URLs are already in the
        # set from httpx (source 2), and source 4 covers un-probed IPs.
        if _is_mock_ip_hostname(hostname):
            counts["skipped_mock_hostname"] += 1
            continue
        before = len(url_set)
        url_set.add(f"http://{hostname}")
        url_set.add(f"https://{hostname}")
        if len(url_set) > before:
            counts["fallback_subdomain"] += 1

    # Source 4: IPs not covered (opt-in)
    if scan_all_ips:
        for ip in sorted(ips):
            if not ip or ip in covered_hosts:
                continue
            # IPv6 literals need brackets in URLs: http://[::1]/ not http://::1/.
            # An IPv6 contains ':' (IPv4 does not).
            ip_for_url = f"[{ip}]" if ":" in ip else ip
            before = len(url_set)
            url_set.add(f"http://{ip_for_url}")
            url_set.add(f"https://{ip_for_url}")
            if len(url_set) > before:
                counts["fallback_ip"] += 1

    parts = []
    if counts["resource_enum_base"]:
        parts.append(f"{counts['resource_enum_base']} resource_enum base URLs")
    if counts["resource_enum_endpoint"]:
        parts.append(f"{counts['resource_enum_endpoint']} parameterized endpoints")
    if counts["httpx"]:
        parts.append(f"{counts['httpx']} additional httpx URLs")
    if counts["fallback_subdomain"]:
        parts.append(f"{counts['fallback_subdomain']} unprobed subdomains")
    if counts["fallback_ip"]:
        parts.append(f"{counts['fallback_ip']} unprobed IPs")

    if parts:
        print(f"[*][Targets] Merged {len(url_set)} URLs: " + " + ".join(parts))
    else:
        print(f"[*][Targets] No targets available")

    return sorted(url_set)



# =============================================================================
# Discovered-hostname feedback (certificate SANs, JS-recon subdomains, ...)
# =============================================================================

def _is_valid_injected_hostname(hostname: str) -> bool:
    """Mirror of ``vhost_sni_enum._is_valid_hostname``.

    The ``\\Z`` anchor is load-bearing: Python's ``$`` also matches *before* a
    trailing newline, and the nuclei / subjack target files are newline
    delimited, so a newline embedded in a SAN would split one entry into two.
    """
    if not hostname or len(hostname) > 253:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1]
    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)\Z", re.IGNORECASE)
    return all(allowed.match(label) for label in hostname.split("."))


def _resolves_to_routable(hostname: str) -> bool:
    """Resolve-and-check for a SAN-derived name.

    Returns False ONLY when the name resolves to at least one non-routable
    address (the SSRF / scope-escape case we must drop). An unresolvable name
    returns True: it is in scope and cannot be an internal pivot; it simply will
    not be probed if nothing answers.
    """
    import socket
    from recon.main_recon_modules.ip_filter import is_non_routable_ip
    try:
        infos = socket.getaddrinfo(hostname, None)
    except Exception:
        return True
    for info in infos:
        try:
            addr = info[4][0]
        except (IndexError, TypeError):
            continue
        if is_non_routable_ip(addr):
            return False
    return True


def merge_discovered_hostnames(
    combined_result: dict,
    hostnames: list,
    source: str,
    root_domain: Optional[str] = None,
    settings: Optional[dict] = None,
    max_injected: Optional[int] = None,
) -> dict:
    """Merge discovered hostnames into ``dns.subdomains`` (the DICT shape read by
    ``extract_targets_from_recon``) + ``discovered_external_domains``, mirroring
    ``domain_recon``'s in-scope / out-of-scope split.

    SECURITY — a certificate SAN list is chosen by the scanned target, so every
    name here is attacker-influenced. Containment, in order:

      1. Apex-suffix allow-list: keep a name only if it equals ``root_domain`` or
         ends with ``"." + root_domain``. Every other name is recorded in
         ``discovered_external_domains`` and never becomes an active-scan target.
      2. RoE narrowing (``_filter_roe_excluded``) — additive, never sufficient
         on its own (it is off by default).
      3. Hostname syntax validation (``\\Z``-anchored; blocks newline injection
         into the newline-delimited target files).
      4. Resolve-and-check: drop any name resolving to a non-routable IP.
      5. Cap the injected count (``max_injected``).

    Fails closed: without ``root_domain`` nothing is injected (names are still
    recorded as external), because there is no apex to test against — e.g. batch
    mode, where ``metadata['root_domain']`` is deliberately empty (a joined
    string once became a literal scan target).
    """
    settings = settings or {}
    result = combined_result

    candidates = []
    seen = set()
    for h in hostnames or []:
        if not isinstance(h, str):
            continue
        name = h.strip().lower().lstrip("*.")
        if name and name not in seen:
            seen.add(name)
            candidates.append(name)

    external = result.setdefault("discovered_external_domains", [])
    existing_external = {e.get("domain") for e in external if isinstance(e, dict)}

    def _record_external(name):
        if name not in existing_external:
            external.append({"domain": name, "source": source})
            existing_external.add(name)

    # Fail closed without an apex to test against.
    if not root_domain:
        for name in candidates:
            _record_external(name)
        return result

    root_domain = root_domain.strip().lower()

    # 1. Apex-suffix split.
    in_scope = []
    for name in candidates:
        if name == root_domain or name.endswith("." + root_domain):
            in_scope.append(name)
        else:
            _record_external(name)

    # 2. RoE narrowing pass.
    from recon.helpers.roe_scope import _filter_roe_excluded
    in_scope = _filter_roe_excluded(in_scope, settings, label="SAN hostname")

    # 3. Syntax validation.
    in_scope = [n for n in in_scope if _is_valid_injected_hostname(n)]

    # Deterministic order so the cap truncates reproducibly.
    in_scope = sorted(set(in_scope))

    # 4. Cap BEFORE resolving. Each resolve is a blocking getaddrinfo, and this
    # runs in GROUP 3.6, ahead of the HTTP probe: resolving every SAN a scan
    # collected (one multi-SAN cert per host, unbounded) would put an unbounded
    # number of sequential DNS timeouts on the pipeline's critical path. Capping
    # first bounds that work to max_injected lookups. The cost is that a name
    # dropped in step 5 does not free a slot for the next candidate; bounding
    # the stall is worth more than filling the quota exactly.
    if max_injected is not None and max_injected >= 0 and len(in_scope) > max_injected:
        dropped = len(in_scope) - max_injected
        print(f"[*][{source}] injected-hostname cap: kept {max_injected}, dropped {dropped}")
        in_scope = in_scope[:max_injected]

    # 5. Resolve-and-check (SAN-derived names only, never the port-scan list).
    in_scope = [n for n in in_scope if _resolves_to_routable(n)]

    # Merge in-scope names into dns.subdomains (the DICT shape). Only in-scope
    # names reach here, so the eventual HAS_SUBDOMAIN edge cannot promote a
    # foreign host to a permanent target (Phase 0.5 rule 5).
    dns = result.setdefault("dns", {})
    subs = dns.get("subdomains")
    if not isinstance(subs, dict):
        subs = {}
        dns["subdomains"] = subs
    injected = 0
    for name in in_scope:
        entry = subs.get(name)
        if not isinstance(entry, dict):
            entry = {}
            subs[name] = entry
        entry["has_records"] = True
        entry.setdefault("source", source)
        injected += 1
    if injected:
        print(f"[*][{source}] merged {injected} in-scope hostname(s) into dns.subdomains")
    return result


def collect_certificate_sans(combined_result: dict) -> list:
    """Every hostname named by a certificate already captured in memory.

    Phase 0.6: httpx grabs the full SAN list on every HTTPS port it probes and
    the pipeline never looked at it again, so names the target itself advertised
    were thrown away. Reads BOTH sources so the feedback path does not depend on
    tlsx being enabled (the Phase 1.0 rule):

      - http_probe.by_url[*].tls.certificate.san
      - tlsx.by_target[*].san

    Returns raw names (wildcards included); scoping, validation and the cap are
    ``merge_discovered_hostnames``'s job, not this one's.
    """
    names: set = set()

    by_url = ((combined_result.get("http_probe") or {}).get("by_url")) or {}
    for info in by_url.values():
        if not isinstance(info, dict):
            continue
        cert = ((info.get("tls") or {}).get("certificate")) or {}
        for san in cert.get("san") or []:
            if isinstance(san, str) and san.strip():
                names.add(san.strip().lower())
        cn = cert.get("subject_cn")
        if isinstance(cn, str) and cn.strip():
            names.add(cn.strip().lower())

    by_target = ((combined_result.get("tlsx") or {}).get("by_target")) or {}
    for entry in by_target.values():
        if not isinstance(entry, dict):
            continue
        for san in entry.get("san") or []:
            if isinstance(san, str) and san.strip():
                names.add(san.strip().lower())

    return sorted(names)
