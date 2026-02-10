"""
RedAmon - Resource Enumeration Module
=====================================
Comprehensive endpoint discovery and classification.
Discovers all endpoints (GET, POST, APIs) and organizes them by base URL.

Features:
- Katana crawling for endpoint discovery (active)
- GAU passive URL discovery from archives (passive)
  - Wayback Machine, Common Crawl, OTX, URLScan
- HTML form parsing for POST endpoints
- Parameter extraction and classification
- Endpoint categorization (auth, file_access, api, dynamic, static, admin)
- Parameter type detection (id, file, search, auth params)
- Parallel execution of Katana + GAU with merged results

Pipeline: http_probe -> resource_enum (Katana + GAU parallel) -> vuln_scan
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
import sys

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Settings are passed from main.py to avoid multiple database queries

# Import from helpers (shared with vuln_scan)
from recon.helpers import (
    is_docker_installed,
    is_docker_running,
    is_tor_running,
)

# Import from resource_enum helpers
from recon.helpers.resource_enum import (
    # GAU helpers
    pull_gau_docker_image,
    run_gau_discovery,
    verify_gau_urls,
    detect_gau_methods,
    merge_gau_into_by_base_url,
    # Kiterunner helpers
    ensure_kiterunner_binary,
    run_kiterunner_discovery,
    merge_kiterunner_into_by_base_url,
    detect_kiterunner_methods,
    # Katana helpers
    run_katana_crawler,
    pull_katana_docker_image,
    # Endpoint organization
    organize_endpoints,
)


# =============================================================================
# Main Function
# =============================================================================

def run_resource_enum(recon_data: dict, output_file: Optional[Path] = None, settings: dict = None) -> dict:
    """
    Run resource enumeration to discover and classify all endpoints.

    Combines:
    - Katana active crawling for current site structure
    - GAU passive URL discovery from archives (Wayback, CommonCrawl, OTX, URLScan)

    Both tools run in parallel for efficiency, then results are merged and deduplicated.

    Args:
        recon_data: Reconnaissance data from previous modules
        output_file: Optional path to save incremental results
        settings: Settings dictionary from main.py

    Returns:
        Updated recon_data with resource_enum results
    """
    print("\n" + "=" * 70)
    print("         RedAmon - Resource Enumeration")
    print("         (Katana + GAU + Kiterunner Parallel Discovery)")
    print("=" * 70)

    # Use passed settings or empty dict as fallback
    if settings is None:
        settings = {}

    # Extract settings from passed dict
    # Katana settings
    KATANA_ENABLED = settings.get('KATANA_ENABLED', True)
    KATANA_DOCKER_IMAGE = settings.get('KATANA_DOCKER_IMAGE', 'projectdiscovery/katana:latest')
    KATANA_DEPTH = settings.get('KATANA_DEPTH', 2)
    KATANA_MAX_URLS = settings.get('KATANA_MAX_URLS', 300)
    KATANA_RATE_LIMIT = settings.get('KATANA_RATE_LIMIT', 50)
    KATANA_TIMEOUT = settings.get('KATANA_TIMEOUT', 3600)
    KATANA_JS_CRAWL = settings.get('KATANA_JS_CRAWL', True)
    KATANA_PARAMS_ONLY = settings.get('KATANA_PARAMS_ONLY', False)
    KATANA_CUSTOM_HEADERS = settings.get('KATANA_CUSTOM_HEADERS', [])
    KATANA_EXCLUDE_PATTERNS = settings.get('KATANA_EXCLUDE_PATTERNS', [])

    # GAU settings
    GAU_ENABLED = settings.get('GAU_ENABLED', False)
    GAU_DOCKER_IMAGE = settings.get('GAU_DOCKER_IMAGE', 'sxcurity/gau:latest')
    GAU_PROVIDERS = settings.get('GAU_PROVIDERS', ['wayback', 'commoncrawl', 'otx', 'urlscan'])
    GAU_THREADS = settings.get('GAU_THREADS', 2)
    GAU_TIMEOUT = settings.get('GAU_TIMEOUT', 60)
    GAU_BLACKLIST_EXTENSIONS = settings.get('GAU_BLACKLIST_EXTENSIONS', ['png', 'jpg', 'jpeg', 'gif', 'css', 'woff', 'woff2', 'ttf', 'svg', 'ico', 'eot'])
    GAU_MAX_URLS = settings.get('GAU_MAX_URLS', 10000)
    GAU_YEAR_RANGE = settings.get('GAU_YEAR_RANGE', None)
    GAU_VERBOSE = settings.get('GAU_VERBOSE', False)
    GAU_VERIFY_URLS = settings.get('GAU_VERIFY_URLS', True)
    GAU_VERIFY_DOCKER_IMAGE = settings.get('GAU_VERIFY_DOCKER_IMAGE', 'projectdiscovery/httpx:latest')
    GAU_VERIFY_TIMEOUT = settings.get('GAU_VERIFY_TIMEOUT', 5)
    GAU_VERIFY_RATE_LIMIT = settings.get('GAU_VERIFY_RATE_LIMIT', 50)
    GAU_VERIFY_THREADS = settings.get('GAU_VERIFY_THREADS', 50)
    GAU_VERIFY_ACCEPT_STATUS = settings.get('GAU_VERIFY_ACCEPT_STATUS', ['200', '201', '301', '302', '307', '308', '401', '403'])
    GAU_DETECT_METHODS = settings.get('GAU_DETECT_METHODS', True)
    GAU_METHOD_DETECT_THREADS = settings.get('GAU_METHOD_DETECT_THREADS', 20)
    GAU_METHOD_DETECT_TIMEOUT = settings.get('GAU_METHOD_DETECT_TIMEOUT', 5)
    GAU_METHOD_DETECT_RATE_LIMIT = settings.get('GAU_METHOD_DETECT_RATE_LIMIT', 30)
    GAU_FILTER_DEAD_ENDPOINTS = settings.get('GAU_FILTER_DEAD_ENDPOINTS', True)

    # Kiterunner settings
    KITERUNNER_ENABLED = settings.get('KITERUNNER_ENABLED', False)
    KITERUNNER_WORDLISTS = settings.get('KITERUNNER_WORDLISTS', ['apiroutes-210228'])
    KITERUNNER_RATE_LIMIT = settings.get('KITERUNNER_RATE_LIMIT', 100)
    KITERUNNER_CONNECTIONS = settings.get('KITERUNNER_CONNECTIONS', 50)
    KITERUNNER_TIMEOUT = settings.get('KITERUNNER_TIMEOUT', 3)
    KITERUNNER_SCAN_TIMEOUT = settings.get('KITERUNNER_SCAN_TIMEOUT', 300)
    KITERUNNER_THREADS = settings.get('KITERUNNER_THREADS', 10)
    KITERUNNER_IGNORE_STATUS = settings.get('KITERUNNER_IGNORE_STATUS', ['404', '429', '503'])
    KITERUNNER_MATCH_STATUS = settings.get('KITERUNNER_MATCH_STATUS', [])
    KITERUNNER_MIN_CONTENT_LENGTH = settings.get('KITERUNNER_MIN_CONTENT_LENGTH', 0)
    KITERUNNER_HEADERS = settings.get('KITERUNNER_HEADERS', [])
    KITERUNNER_DETECT_METHODS = settings.get('KITERUNNER_DETECT_METHODS', True)
    KITERUNNER_METHOD_DETECTION_MODE = settings.get('KITERUNNER_METHOD_DETECTION_MODE', 'options')
    KITERUNNER_BRUTEFORCE_METHODS = settings.get('KITERUNNER_BRUTEFORCE_METHODS', ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
    KITERUNNER_METHOD_DETECT_TIMEOUT = settings.get('KITERUNNER_METHOD_DETECT_TIMEOUT', 3)
    KITERUNNER_METHOD_DETECT_RATE_LIMIT = settings.get('KITERUNNER_METHOD_DETECT_RATE_LIMIT', 50)
    KITERUNNER_METHOD_DETECT_THREADS = settings.get('KITERUNNER_METHOD_DETECT_THREADS', 20)

    # General settings
    USE_TOR_FOR_RECON = settings.get('USE_TOR_FOR_RECON', False)

    # Check Docker
    if not is_docker_installed():
        print("[!] Docker not found. Please install Docker.")
        return recon_data

    if not is_docker_running():
        print("[!] Docker daemon is not running.")
        return recon_data

    # Pull Docker images and ensure Kiterunner binary in parallel
    print("\n[*] Setting up tools...")
    kr_binary_path = None

    with ThreadPoolExecutor(max_workers=3) as executor:
        if KATANA_ENABLED:
            katana_future = executor.submit(pull_katana_docker_image, KATANA_DOCKER_IMAGE)
        if GAU_ENABLED:
            gau_future = executor.submit(pull_gau_docker_image, GAU_DOCKER_IMAGE)
        if KITERUNNER_ENABLED and KITERUNNER_WORDLISTS:
            # Ensure binary is available
            kr_future = executor.submit(ensure_kiterunner_binary, KITERUNNER_WORDLISTS[0])
        if KATANA_ENABLED:
            katana_future.result()
        if GAU_ENABLED:
            gau_future.result()
        if KITERUNNER_ENABLED and KITERUNNER_WORDLISTS:
            kr_binary_path, _ = kr_future.result()

    # Check Tor status
    use_proxy = False
    if USE_TOR_FOR_RECON:
        if is_tor_running():
            use_proxy = True
            print(f"  [*] Anonymous mode: Using Tor SOCKS proxy")
        else:
            print("  [!] Tor not running, falling back to direct connection")

    # Get target URLs from http_probe
    http_probe_data = recon_data.get('http_probe', {})
    target_urls = []
    target_domains = set()

    by_url = http_probe_data.get('by_url', {})
    for url, url_data in by_url.items():
        status_code = url_data.get('status_code')
        if status_code and status_code < 500:
            target_urls.append(url)
            # Extract domain for GAU
            host = url_data.get('host', '')
            if host:
                target_domains.add(host)

    if not target_urls:
        # Fallback to DNS data
        dns_data = recon_data.get('dns', {})
        domain = recon_data.get('domain', '')
        
        # Include root domain if it has DNS records
        domain_dns = dns_data.get('domain', {})
        if domain and domain_dns.get('has_records'):
            target_urls.append(f"http://{domain}")
            target_urls.append(f"https://{domain}")
            target_domains.add(domain)
        
        # Include subdomains
        subdomains = dns_data.get('subdomains', {})
        for subdomain, sub_data in subdomains.items():
            if sub_data.get('has_records'):
                target_urls.append(f"http://{subdomain}")
                target_urls.append(f"https://{subdomain}")
                target_domains.add(subdomain)

    if not target_urls:
        print("[!] No target URLs found")
        return recon_data

    print(f"\n  Target URLs: {len(target_urls)}")
    print(f"  Target domains (for GAU): {len(target_domains)}")
    print(f"  Katana enabled: {KATANA_ENABLED}")
    if KATANA_ENABLED:
        print(f"  Katana crawl depth: {KATANA_DEPTH}")
        print(f"  Katana max URLs: {KATANA_MAX_URLS}")
    print(f"  GAU enabled: {GAU_ENABLED}")
    if GAU_ENABLED:
        print(f"  GAU providers: {', '.join(GAU_PROVIDERS)}")
        print(f"  GAU URL verification: {GAU_VERIFY_URLS}")
    print(f"  Kiterunner enabled: {KITERUNNER_ENABLED}")
    if KITERUNNER_ENABLED:
        print(f"  Kiterunner wordlists: {', '.join(KITERUNNER_WORDLISTS)}")
    print("=" * 70)

    start_time = datetime.now()

    # Initialize results
    katana_urls = []
    gau_urls = []
    gau_urls_by_domain = {}
    kr_results = []

    # Run Katana and GAU in parallel first (if enabled)
    if KATANA_ENABLED or GAU_ENABLED:
        tools_running = []
        if KATANA_ENABLED:
            tools_running.append("Katana")
        if GAU_ENABLED:
            tools_running.append("GAU")
        print(f"\n[*] Running URL discovery ({' + '.join(tools_running)})...")
    elif not KITERUNNER_ENABLED:
        print("\n[*] All URL discovery tools disabled (Katana, GAU, Kiterunner)")

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = {}

        # Submit Katana crawler if enabled
        if KATANA_ENABLED:
            futures['katana'] = executor.submit(
                run_katana_crawler,
                target_urls,
                KATANA_DOCKER_IMAGE,
                KATANA_DEPTH,
                KATANA_MAX_URLS,
                KATANA_RATE_LIMIT,
                KATANA_TIMEOUT,
                KATANA_JS_CRAWL,
                KATANA_PARAMS_ONLY,
                target_domains,
                KATANA_CUSTOM_HEADERS,
                KATANA_EXCLUDE_PATTERNS,
                use_proxy
            )

        # Submit GAU discovery if enabled
        if GAU_ENABLED and target_domains:
            futures['gau'] = executor.submit(
                run_gau_discovery,
                target_domains,
                GAU_DOCKER_IMAGE,
                GAU_PROVIDERS,
                GAU_THREADS,
                GAU_TIMEOUT,
                GAU_BLACKLIST_EXTENSIONS,
                GAU_MAX_URLS,
                GAU_YEAR_RANGE,
                GAU_VERBOSE,
                use_proxy
            )

        # Collect Katana and GAU results
        for name, future in futures.items():
            try:
                if name == 'katana':
                    katana_urls, _ = future.result(timeout=KATANA_TIMEOUT + 120)
                    print(f"\n[+] Katana completed: {len(katana_urls)} URLs")
                elif name == 'gau':
                    gau_urls, gau_urls_by_domain = future.result(timeout=GAU_TIMEOUT * len(GAU_PROVIDERS) + 180)
                    print(f"[+] GAU completed: {len(gau_urls)} URLs")
            except Exception as e:
                print(f"[!] {name} failed: {e}")

    # Run Kiterunner sequentially for each wordlist
    if KITERUNNER_ENABLED and target_urls and kr_binary_path and KITERUNNER_WORDLISTS:
        print(f"\n[*] Running Kiterunner API discovery ({len(KITERUNNER_WORDLISTS)} wordlists sequentially)...")
        for wordlist_name in KITERUNNER_WORDLISTS:
            print(f"\n    [*] Processing wordlist: {wordlist_name}")
            try:
                # Get the proper wordlist path (downloads if needed, or returns ASSETNOTE: prefix)
                _, wordlist_path = ensure_kiterunner_binary(wordlist_name)
                if not wordlist_path:
                    print(f"    [!] Could not get wordlist: {wordlist_name}")
                    continue
                wordlist_results = run_kiterunner_discovery(
                    target_urls,
                    kr_binary_path,
                    wordlist_path,
                    wordlist_name,
                    KITERUNNER_RATE_LIMIT,
                    KITERUNNER_CONNECTIONS,
                    KITERUNNER_TIMEOUT,
                    KITERUNNER_SCAN_TIMEOUT,
                    KITERUNNER_THREADS,
                    KITERUNNER_IGNORE_STATUS,
                    KITERUNNER_MATCH_STATUS,
                    KITERUNNER_MIN_CONTENT_LENGTH,
                    KITERUNNER_HEADERS,
                    use_proxy
                )
                # Merge results, avoiding duplicates
                existing_urls = {(r['url'], r['method']) for r in kr_results}
                for result in wordlist_results:
                    if (result['url'], result['method']) not in existing_urls:
                        kr_results.append(result)
                        existing_urls.add((result['url'], result['method']))
                print(f"    [+] {wordlist_name}: {len(wordlist_results)} endpoints found, {len(kr_results)} total unique")
            except Exception as e:
                print(f"    [!] Kiterunner failed for {wordlist_name}: {e}")

    # Organize discovered endpoints
    if katana_urls:
        print("\n[*] Organizing Katana endpoints...")
    organized_data = organize_endpoints(katana_urls, use_proxy=use_proxy)

    # Mark all Katana endpoints with sources=['katana'] (array format)
    for base_url, base_data in organized_data['by_base_url'].items():
        for path, endpoint in base_data['endpoints'].items():
            endpoint['sources'] = ['katana']

    # Merge GAU results if available
    gau_stats = {
        "gau_total": 0,
        "gau_parsed": 0,
        "gau_new": 0,
        "gau_overlap": 0,
        "gau_skipped_unverified": 0,
        "gau_out_of_scope": 0
    }
    gau_urls_to_process = []  # Initialize empty, will be populated if GAU enabled

    if GAU_ENABLED and gau_urls:
        # Filter GAU URLs to only include target domains (in-scope)
        in_scope_gau_urls = []
        out_of_scope_count = 0
        for url in gau_urls:
            parsed = urlparse(url)
            host = parsed.netloc.split(':')[0] if ':' in parsed.netloc else parsed.netloc
            if host in target_domains:
                in_scope_gau_urls.append(url)
            else:
                out_of_scope_count += 1

        if out_of_scope_count > 0:
            print(f"\n[*] Filtered {out_of_scope_count} GAU URLs (out of scan scope)")
            print(f"    [+] In-scope GAU URLs: {len(in_scope_gau_urls)}")

        # Use filtered URLs for the rest of processing
        gau_urls_to_process = in_scope_gau_urls

        # Verify GAU URLs if enabled
        verified_urls = None
        if GAU_VERIFY_URLS and gau_urls_to_process:
            verified_urls = verify_gau_urls(
                gau_urls_to_process,
                GAU_VERIFY_DOCKER_IMAGE,
                GAU_VERIFY_TIMEOUT,
                GAU_VERIFY_RATE_LIMIT,
                GAU_VERIFY_THREADS,
                GAU_VERIFY_ACCEPT_STATUS,
                use_proxy
            )

        # Detect HTTP methods for GAU URLs using OPTIONS probe
        url_methods = None
        urls_to_probe = list(verified_urls) if verified_urls else gau_urls_to_process
        if GAU_DETECT_METHODS and urls_to_probe:
            url_methods = detect_gau_methods(
                urls_to_probe,
                GAU_VERIFY_DOCKER_IMAGE,
                GAU_METHOD_DETECT_THREADS,
                GAU_METHOD_DETECT_TIMEOUT,
                GAU_METHOD_DETECT_RATE_LIMIT,
                GAU_FILTER_DEAD_ENDPOINTS,
                use_proxy
            )

        # Merge GAU into by_base_url (use in-scope URLs only)
        print("\n[*] Merging GAU endpoints into results...")
        organized_data['by_base_url'], gau_stats = merge_gau_into_by_base_url(
            gau_urls_to_process,
            organized_data['by_base_url'],
            verified_urls,
            url_methods
        )

        # Add out-of-scope count to stats
        gau_stats['gau_out_of_scope'] = out_of_scope_count

        print(f"    [+] GAU in-scope URLs: {gau_stats['gau_total']}")
        if out_of_scope_count > 0:
            print(f"    [+] GAU out-of-scope (filtered): {out_of_scope_count}")
        print(f"    [+] GAU parsed: {gau_stats['gau_parsed']}")
        print(f"    [+] GAU new endpoints: {gau_stats['gau_new']}")
        print(f"    [+] GAU overlap with Katana: {gau_stats['gau_overlap']}")
        if GAU_VERIFY_URLS:
            print(f"    [+] GAU skipped (unverified): {gau_stats['gau_skipped_unverified']}")
        if GAU_DETECT_METHODS:
            print(f"    [+] GAU with POST method: {gau_stats.get('gau_with_post', 0)}")
            print(f"    [+] GAU with multiple methods: {gau_stats.get('gau_with_multiple_methods', 0)}")
        if GAU_FILTER_DEAD_ENDPOINTS:
            print(f"    [+] GAU dead endpoints filtered: {gau_stats.get('gau_skipped_dead', 0)}")

    # Merge Kiterunner results if available
    kr_stats = {
        "kr_total": 0,
        "kr_parsed": 0,
        "kr_new": 0,
        "kr_overlap": 0,
        "kr_methods": {},
        "kr_with_multiple_methods": 0
    }
    kr_url_methods = None

    if KITERUNNER_ENABLED and kr_results:
        # Detect additional HTTP methods for Kiterunner endpoints
        if KITERUNNER_DETECT_METHODS:
            kr_url_methods = detect_kiterunner_methods(
                kr_results,
                GAU_VERIFY_DOCKER_IMAGE,
                KITERUNNER_DETECT_METHODS,
                KITERUNNER_METHOD_DETECTION_MODE,
                KITERUNNER_BRUTEFORCE_METHODS,
                KITERUNNER_METHOD_DETECT_TIMEOUT,
                KITERUNNER_METHOD_DETECT_RATE_LIMIT,
                KITERUNNER_METHOD_DETECT_THREADS,
                use_proxy
            )

        print("\n[*] Merging Kiterunner API endpoints into results...")
        organized_data['by_base_url'], kr_stats = merge_kiterunner_into_by_base_url(
            kr_results,
            organized_data['by_base_url'],
            kr_url_methods
        )

        print(f"    [+] Kiterunner total: {kr_stats['kr_total']} endpoints")
        print(f"    [+] Kiterunner parsed: {kr_stats['kr_parsed']}")
        print(f"    [+] Kiterunner new endpoints: {kr_stats['kr_new']}")
        print(f"    [+] Overlap with Katana/GAU: {kr_stats['kr_overlap']}")
        if kr_stats['kr_methods']:
            print(f"    [+] Methods found: {kr_stats['kr_methods']}")
        if KITERUNNER_DETECT_METHODS and kr_stats.get('kr_with_multiple_methods', 0) > 0:
            print(f"    [+] Endpoints with multiple methods: {kr_stats['kr_with_multiple_methods']}")

    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    # Get in-scope GAU URLs (already filtered if GAU was enabled)
    in_scope_gau = gau_urls_to_process if GAU_ENABLED and gau_urls else []

    # Combine all discovered URLs (deduplicated, in-scope only)
    all_discovered_urls = sorted(set(katana_urls + in_scope_gau))

    # Build result structure
    resource_enum_result = {
        'scan_metadata': {
            'scan_timestamp': start_time.isoformat(),
            'scan_duration_seconds': duration,
            # Katana metadata
            'katana_enabled': KATANA_ENABLED,
            'katana_docker_image': KATANA_DOCKER_IMAGE if KATANA_ENABLED else None,
            'katana_crawl_depth': KATANA_DEPTH if KATANA_ENABLED else None,
            'katana_max_urls': KATANA_MAX_URLS if KATANA_ENABLED else None,
            'katana_rate_limit': KATANA_RATE_LIMIT if KATANA_ENABLED else None,
            'katana_js_crawl': KATANA_JS_CRAWL if KATANA_ENABLED else None,
            'katana_params_only': KATANA_PARAMS_ONLY if KATANA_ENABLED else None,
            'katana_urls_found': len(katana_urls) if KATANA_ENABLED else 0,
            # GAU metadata
            'gau_enabled': GAU_ENABLED,
            'gau_docker_image': GAU_DOCKER_IMAGE if GAU_ENABLED else None,
            'gau_providers': GAU_PROVIDERS if GAU_ENABLED else [],
            'gau_urls_found_total': len(gau_urls),  # All URLs found by GAU
            'gau_urls_in_scope': len(in_scope_gau),  # Only in-scope URLs
            'gau_verify_enabled': GAU_VERIFY_URLS if GAU_ENABLED else False,
            'gau_method_detection_enabled': GAU_DETECT_METHODS if GAU_ENABLED else False,
            'gau_filter_dead_endpoints': GAU_FILTER_DEAD_ENDPOINTS if GAU_ENABLED else False,
            'gau_stats': gau_stats,
            # Kiterunner metadata
            'kiterunner_enabled': KITERUNNER_ENABLED,
            'kiterunner_binary_path': kr_binary_path if KITERUNNER_ENABLED else None,
            'kiterunner_wordlists': KITERUNNER_WORDLISTS if KITERUNNER_ENABLED else [],
            'kiterunner_wordlists_count': len(KITERUNNER_WORDLISTS) if KITERUNNER_ENABLED else 0,
            'kiterunner_endpoints_found': len(kr_results) if KITERUNNER_ENABLED else 0,
            'kiterunner_method_detection_enabled': KITERUNNER_DETECT_METHODS if KITERUNNER_ENABLED else False,
            'kiterunner_method_detection_mode': KITERUNNER_METHOD_DETECTION_MODE if KITERUNNER_ENABLED else None,
            'kiterunner_stats': kr_stats,
            # General
            'proxy_used': use_proxy,
            'target_urls_count': len(target_urls),
            'target_domains_count': len(target_domains),
            'total_discovered_urls': len(all_discovered_urls)
        },
        'discovered_urls': all_discovered_urls,
        'by_base_url': organized_data['by_base_url'],
        'forms': organized_data['forms'],
        'summary': {
            'total_base_urls': len(organized_data['by_base_url']),
            'total_endpoints': sum(
                data['summary']['total_endpoints']
                for data in organized_data['by_base_url'].values()
            ),
            'total_parameters': sum(
                data['summary']['total_parameters']
                for data in organized_data['by_base_url'].values()
            ),
            'total_forms': len(organized_data['forms']),
            # Source breakdown
            'from_katana': len(katana_urls),
            'from_gau_total': len(gau_urls),  # All URLs found by GAU
            'from_gau_in_scope': len(in_scope_gau),  # Only in-scope URLs
            'gau_new_endpoints': gau_stats['gau_new'],
            'gau_overlap': gau_stats['gau_overlap'],
            # Kiterunner breakdown
            'from_kiterunner': len(kr_results) if KITERUNNER_ENABLED else 0,
            'kiterunner_new_endpoints': kr_stats['kr_new'],
            'kiterunner_overlap': kr_stats['kr_overlap'],
            'kiterunner_with_multiple_methods': kr_stats.get('kr_with_multiple_methods', 0),
            'methods': {},
            'categories': {}
        }
    }

    # Aggregate methods and categories across all base URLs
    for base_data in organized_data['by_base_url'].values():
        for method, count in base_data['summary']['methods'].items():
            resource_enum_result['summary']['methods'][method] = \
                resource_enum_result['summary']['methods'].get(method, 0) + count
        for category, count in base_data['summary']['categories'].items():
            resource_enum_result['summary']['categories'][category] = \
                resource_enum_result['summary']['categories'].get(category, 0) + count

    # Add to recon_data
    recon_data['resource_enum'] = resource_enum_result

    # Save incrementally
    if output_file:
        with open(output_file, 'w') as f:
            json.dump(recon_data, f, indent=2)

    # Print summary
    print(f"\n{'=' * 70}")
    print(f"[+] RESOURCE ENUMERATION COMPLETE")
    print(f"[+] Duration: {duration:.2f} seconds")
    print(f"[+] Total URLs discovered: {len(all_discovered_urls)}")
    print(f"    - Katana (active crawl): {len(katana_urls) if KATANA_ENABLED else 'disabled'}")
    print(f"    - GAU (passive archive): {len(gau_urls) if GAU_ENABLED else 'disabled'}")
    if GAU_ENABLED and gau_urls:
        print(f"      - GAU new endpoints: {gau_stats['gau_new']}")
        print(f"      - GAU overlap: {gau_stats['gau_overlap']}")
    print(f"    - Kiterunner (API bruteforce): {len(kr_results) if KITERUNNER_ENABLED else 'disabled'}")
    if KITERUNNER_ENABLED and kr_results:
        print(f"      - Kiterunner new endpoints: {kr_stats['kr_new']}")
        print(f"      - Kiterunner overlap: {kr_stats['kr_overlap']}")
    print(f"[+] Base URLs: {resource_enum_result['summary']['total_base_urls']}")
    print(f"[+] Endpoints: {resource_enum_result['summary']['total_endpoints']}")
    print(f"[+] Parameters: {resource_enum_result['summary']['total_parameters']}")
    print(f"[+] Forms (POST): {resource_enum_result['summary']['total_forms']}")

    # Methods breakdown
    methods = resource_enum_result['summary']['methods']
    if methods:
        print(f"\n[+] HTTP Methods:")
        for method, count in sorted(methods.items()):
            print(f"    {method}: {count}")

    # Categories breakdown
    categories = resource_enum_result['summary']['categories']
    if categories:
        print(f"\n[+] Endpoint Categories:")
        for category, count in sorted(categories.items(), key=lambda x: -x[1]):
            print(f"    {category}: {count}")

    print(f"{'=' * 70}")

    return recon_data


if __name__ == "__main__":
    # Test with a sample recon file
    import sys

    if len(sys.argv) > 1:
        recon_file = Path(sys.argv[1])
        if recon_file.exists():
            # Load settings for standalone usage
            from recon.project_settings import get_settings
            settings = get_settings()

            with open(recon_file, 'r') as f:
                recon_data = json.load(f)

            result = run_resource_enum(recon_data, output_file=recon_file, settings=settings)
            print(f"\n[+] Results saved to: {recon_file}")
        else:
            print(f"[!] File not found: {recon_file}")
    else:
        print("Usage: python resource_enum.py <recon_file.json>")
