"""
URLScan.io Passive Enrichment Module

Passive OSINT enrichment using the URLScan.io Search API.
Queries historical scan data to discover subdomains, IPs, TLS info,
server technologies, domain age, and screenshots — all without
touching the target directly.

Works without an API key (public results only).
With an API key, gets higher rate limits and access to private scans.

Features:
  - Subdomain discovery from historical scans
  - IP + ASN + country enrichment
  - Domain age detection
  - TLS certificate metadata
  - Server/technology identification
  - Screenshot URLs
  - URL path discovery (for Phase B endpoint creation)
"""
import logging
from typing import Any
from urllib.parse import urlparse, parse_qs

import requests

logger = logging.getLogger(__name__)

URLSCAN_API_BASE = "https://urlscan.io/api/v1"


def _urlscan_search(domain: str, api_key: str, max_results: int = 500, key_rotator=None) -> list[dict]:
    """Query URLScan.io Search API for domain results.

    Uses page.domain field for accurate matching:
    - Without API key: exact match on page.domain (root domain only)
    - With API key: also searches page.domain:*.domain for subdomain discovery
    """
    effective_key = key_rotator.current_key if key_rotator and key_rotator.has_keys else api_key
    url = f"{URLSCAN_API_BASE}/search/"

    # page.domain: matches the actual page domain (not a full-text index)
    # Wildcard *.domain requires authentication (403 for anonymous users)
    if effective_key:
        query = f"page.domain:{domain} OR page.domain:*.{domain}"
    else:
        query = f"page.domain:{domain}"

    params = {
        "q": query,
        "size": min(max_results, 10000),
    }
    headers = {}
    if effective_key:
        headers["API-Key"] = effective_key

    all_results = []

    try:
        resp = requests.get(url, params=params, headers=headers, timeout=60)
        if key_rotator:
            key_rotator.tick()
        if resp.status_code == 200:
            data = resp.json()
            results = data.get("results", [])
            logger.info(f"URLScan search returned {len(results)} results for {domain}")
            all_results.extend(results)
        elif resp.status_code == 429:
            logger.warning("URLScan rate limit hit")
            print("[!][URLScan] Rate limit hit -- try adding an API key in Global Settings")
            return []
        else:
            logger.warning(f"URLScan {resp.status_code}: {resp.text[:200]}")
            print(f"[!][URLScan] API returned {resp.status_code}")
            return []
    except requests.RequestException as e:
        logger.warning(f"URLScan request failed: {e}")
        print(f"[!][URLScan] Request failed: {e}")
        return []

    return all_results


def _parse_url_path(full_url: str) -> dict | None:
    """Parse a URL into base_url, path, and query params.

    Returns None for root paths (/) or URLs without meaningful paths.
    """
    try:
        parsed = urlparse(full_url)
        path = parsed.path or "/"
        if path == "/" and not parsed.query:
            return None

        base_url = f"{parsed.scheme}://{parsed.netloc}"
        params = {}
        if parsed.query:
            raw_params = parse_qs(parsed.query, keep_blank_values=True)
            params = {k: v[0] if len(v) == 1 else v for k, v in raw_params.items()}

        return {
            "full_url": full_url,
            "base_url": base_url,
            "path": path,
            "params": params,
        }
    except Exception:
        return None


def _extract_domain_from_url(url: str, root_domain: str) -> str | None:
    """Extract subdomain from a URL, only if it belongs to the root domain."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if hostname and (hostname == root_domain or hostname.endswith("." + root_domain)):
            return hostname
    except Exception:
        pass
    return None


def run_urlscan_enrichment(combined_result: dict, settings: dict[str, Any]) -> dict:
    """
    Run URLScan.io passive enrichment on the target domain.

    Runs after domain discovery, before port scanning.
    Discovers additional subdomains, IPs, and metadata from historical scans.

    Args:
        combined_result: The pipeline's combined result dictionary
        settings: Project settings dict (SCREAMING_SNAKE_CASE keys)

    Returns:
        The enriched combined_result with 'urlscan' key added
    """
    if not settings.get("URLSCAN_ENABLED", False):
        return combined_result

    domain = combined_result.get("domain", "")
    is_ip_mode = combined_result.get("metadata", {}).get("ip_mode", False)

    # URLScan indexes by domain, not IP — skip in IP mode
    if is_ip_mode or not domain:
        return combined_result

    api_key = settings.get("URLSCAN_API_KEY", "")
    key_rotator = settings.get("URLSCAN_KEY_ROTATOR")
    max_results = settings.get("URLSCAN_MAX_RESULTS", 500)

    print(f"\n[PHASE] URLScan.io Passive Enrichment")
    print("-" * 40)
    if api_key:
        print(f"[+][URLScan] Using API key for higher rate limits")
    else:
        print(f"[*][URLScan] No API key — using public results only")
    print(f"[*][URLScan] Querying for domain: {domain} (max {max_results} results)")

    results = _urlscan_search(domain, api_key, max_results, key_rotator=key_rotator)

    if not results:
        print(f"[-][URLScan] No results found for {domain}")
        combined_result["urlscan"] = {
            "results_count": 0,
            "subdomains_discovered": [],
            "ips_discovered": [],
            "urls_with_paths": [],
            "entries": [],
        }
        return combined_result

    # Parse results
    entries = []
    subdomains: set[str] = set()
    ips: set[str] = set()
    urls_with_paths: list[dict] = []
    seen_urls: set[str] = set()

    # Track domain age (take max from all results)
    domain_age_days = None
    apex_domain_age_days = None
    external_domain_entries = []  # Collect out-of-scope domains for situational awareness

    for result in results:
        page = result.get("page", {})
        task = result.get("task", {})

        page_url = page.get("url", "")
        page_domain = page.get("domain", "")
        page_ip = page.get("ip", "")
        page_asn = page.get("asn", "")
        page_asnname = page.get("asnname", "")
        page_country = page.get("country", "")
        page_server = page.get("server", "")
        page_status = str(page.get("status") or "")
        page_title = page.get("title", "")
        page_tls_issuer = page.get("tlsIssuer", "")
        page_tls_valid_days = page.get("tlsValidDays")
        page_tls_valid_from = page.get("tlsValidFrom", "")
        page_tls_age_days = page.get("tlsAgeDays")
        page_domain_age = page.get("domainAgeDays")
        page_apex_age = page.get("apexDomainAgeDays")
        screenshot = result.get("screenshot", "")
        scan_time = task.get("time", "")

        # Check if this result belongs to the target domain
        # URLScan can return unrelated domains in search results
        is_in_scope = (
            page_domain and
            (page_domain == domain or page_domain.endswith("." + domain))
        )

        # Track subdomain discovery (in-scope only)
        if is_in_scope:
            subdomains.add(page_domain)

        # Also discover subdomains from the URL itself
        url_domain = _extract_domain_from_url(page_url, domain)
        if url_domain:
            subdomains.add(url_domain)
            is_in_scope = True  # URL hostname confirms scope

        # Collect out-of-scope domains for situational awareness
        if not is_in_scope and page_domain:
            external_domain_entries.append({
                "domain": page_domain,
                "source": "urlscan",
                "url": page_url,
                "status_code": int(page_status) if page_status.isdigit() else None,
                "title": page_title,
                "server": page_server,
                "ip": page_ip,
                "country": page_country,
            })

        # Track IPs (in-scope only — foreign IPs would pollute the graph)
        if page_ip and is_in_scope:
            ips.add(page_ip)

        # Track domain age (in-scope only — foreign domain ages are irrelevant)
        if is_in_scope:
            if page_domain_age is not None:
                if domain_age_days is None or page_domain_age > domain_age_days:
                    domain_age_days = page_domain_age
            if page_apex_age is not None:
                if apex_domain_age_days is None or page_apex_age > apex_domain_age_days:
                    apex_domain_age_days = page_apex_age

        # Parse URL paths for Phase B endpoint creation (in-scope only)
        if page_url and page_url not in seen_urls and is_in_scope:
            seen_urls.add(page_url)
            parsed = _parse_url_path(page_url)
            if parsed:
                urls_with_paths.append(parsed)

        # Build entry
        entry = {
            "url": page_url,
            "domain": page_domain,
            "ip": page_ip,
            "asn": page_asn,
            "asn_name": page_asnname,
            "country": page_country,
            "server": page_server,
            "status": page_status,
            "title": page_title,
            "tls_issuer": page_tls_issuer,
            "tls_valid_days": page_tls_valid_days,
            "tls_valid_from": page_tls_valid_from,
            "tls_age_days": page_tls_age_days,
            "domain_age_days": page_domain_age,
            "screenshot_url": screenshot,
            "scan_time": scan_time,
        }
        entries.append(entry)

    # Remove root domain from subdomain list (it's not a "discovery")
    subdomains.discard(domain)

    urlscan_data = {
        "results_count": len(results),
        "subdomains_discovered": sorted(subdomains),
        "ips_discovered": sorted(ips),
        "domain_age_days": domain_age_days,
        "apex_domain_age_days": apex_domain_age_days,
        "urls_with_paths": urls_with_paths,
        "entries": entries,
        "external_domains": external_domain_entries,
    }

    print(f"[+][URLScan] {len(results)} scans found")
    print(f"[+][URLScan] Subdomains discovered: {len(subdomains)}")
    print(f"[+][URLScan] Unique IPs found: {len(ips)}")
    print(f"[+][URLScan] URLs with paths: {len(urls_with_paths)}")
    if domain_age_days is not None:
        print(f"[+][URLScan] Domain age: {domain_age_days} days")

    combined_result["urlscan"] = urlscan_data
    return combined_result


def run_urlscan_discovery_only(domain: str, settings: dict[str, Any]) -> dict:
    """
    Run URLScan.io discovery and return only the 'urlscan' data dict.

    Thread-safe: does not need or mutate combined_result. Designed for
    parallel execution alongside other discovery tools (WHOIS, subdomain enum).

    Args:
        domain: Root domain to query
        settings: Project settings dict

    Returns:
        The 'urlscan' data dictionary, or empty dict if disabled/no results.
    """
    if not settings.get("URLSCAN_ENABLED", False):
        return {}

    if not domain:
        return {}

    # Build a minimal combined_result just for the enrichment function
    fake_combined = {
        "domain": domain,
        "metadata": {"ip_mode": False},
    }
    run_urlscan_enrichment(fake_combined, settings)
    return fake_combined.get("urlscan", {})
