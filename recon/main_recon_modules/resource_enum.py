"""
RedAmon - Resource Enumeration Module
=====================================
Comprehensive endpoint discovery and classification.
Discovers all endpoints (GET, POST, APIs) and organizes them by base URL.

Features:
- Katana crawling for endpoint discovery (active)
- Hakrawler crawling for complementary endpoint discovery (active)
- GAU passive URL discovery from archives (passive)
  - Wayback Machine, Common Crawl, OTX, URLScan
- jsluice JavaScript analysis for hidden URLs and secrets (active - downloads JS files)
- FFuf directory fuzzing for hidden content discovery (active)
- HTML form parsing for POST endpoints
- Parameter extraction and classification
- Endpoint categorization (auth, file_access, api, dynamic, static, admin)
- Parameter type detection (id, file, search, auth params)
- ParamSpider passive parameter URL discovery from Wayback Machine (passive)
- Parallel execution of Katana + Hakrawler + GAU + ParamSpider with merged results
- jsluice post-crawl analysis on discovered JS files
- FFuf post-crawl directory fuzzing with smart base path targeting

Pipeline: http_probe -> resource_enum (Katana + Hakrawler + GAU + ParamSpider parallel, then jsluice, then FFuf) -> vuln_scan
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
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
    # Hakrawler helpers
    run_hakrawler_crawler,
    pull_hakrawler_docker_image,
    merge_hakrawler_into_by_base_url,
    # jsluice helpers
    run_jsluice_analysis,
    merge_jsluice_into_by_base_url,
    # FFuf helpers
    run_ffuf_discovery,
    pull_ffuf_binary_check,
    merge_ffuf_into_by_base_url,
    # Arjun helpers
    arjun_binary_check,
    run_arjun_discovery,
    merge_arjun_into_by_base_url,
    # ParamSpider helpers
    run_paramspider_discovery,
    merge_paramspider_into_by_base_url,
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
    print("[*][ResourceEnum] RedAmon - Resource Enumeration")
    print("[*][ResourceEnum] (Katana + Hakrawler + GAU + jsluice + FFuf + Kiterunner + Arjun)")
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
    KATANA_PARALLELISM = settings.get('KATANA_PARALLELISM', 5)
    KATANA_CONCURRENCY = settings.get('KATANA_CONCURRENCY', 10)

    # Hakrawler settings
    HAKRAWLER_ENABLED = settings.get('HAKRAWLER_ENABLED', False)
    HAKRAWLER_DOCKER_IMAGE = settings.get('HAKRAWLER_DOCKER_IMAGE', 'jauderho/hakrawler:latest')
    HAKRAWLER_DEPTH = settings.get('HAKRAWLER_DEPTH', 2)
    HAKRAWLER_THREADS = settings.get('HAKRAWLER_THREADS', 5)
    HAKRAWLER_TIMEOUT = settings.get('HAKRAWLER_TIMEOUT', 30)
    HAKRAWLER_MAX_URLS = settings.get('HAKRAWLER_MAX_URLS', 500)
    HAKRAWLER_INCLUDE_SUBS = settings.get('HAKRAWLER_INCLUDE_SUBS', False)
    HAKRAWLER_INSECURE = settings.get('HAKRAWLER_INSECURE', True)
    HAKRAWLER_CUSTOM_HEADERS = settings.get('HAKRAWLER_CUSTOM_HEADERS', [])
    HAKRAWLER_PARALLELISM = settings.get('HAKRAWLER_PARALLELISM', 4)

    # jsluice settings
    JSLUICE_ENABLED = settings.get('JSLUICE_ENABLED', True)
    JSLUICE_MAX_FILES = settings.get('JSLUICE_MAX_FILES', 100)
    JSLUICE_TIMEOUT = settings.get('JSLUICE_TIMEOUT', 300)
    JSLUICE_EXTRACT_URLS = settings.get('JSLUICE_EXTRACT_URLS', True)
    JSLUICE_EXTRACT_SECRETS = settings.get('JSLUICE_EXTRACT_SECRETS', True)
    JSLUICE_CONCURRENCY = settings.get('JSLUICE_CONCURRENCY', 5)
    JSLUICE_PARALLELISM = settings.get('JSLUICE_PARALLELISM', 3)

    # FFuf settings
    FFUF_ENABLED = settings.get('FFUF_ENABLED', False)
    FFUF_WORDLIST = settings.get('FFUF_WORDLIST', '/usr/share/seclists/Discovery/Web-Content/common.txt')
    FFUF_THREADS = settings.get('FFUF_THREADS', 40)
    FFUF_RATE = settings.get('FFUF_RATE', 0)
    FFUF_TIMEOUT = settings.get('FFUF_TIMEOUT', 10)
    FFUF_MAX_TIME = settings.get('FFUF_MAX_TIME', 600)
    FFUF_MATCH_CODES = settings.get('FFUF_MATCH_CODES', [200, 201, 204, 301, 302, 307, 308, 401, 403, 405])
    FFUF_FILTER_CODES = settings.get('FFUF_FILTER_CODES', [])
    FFUF_FILTER_SIZE = settings.get('FFUF_FILTER_SIZE', '')
    FFUF_EXTENSIONS = settings.get('FFUF_EXTENSIONS', [])
    FFUF_RECURSION = settings.get('FFUF_RECURSION', False)
    FFUF_RECURSION_DEPTH = settings.get('FFUF_RECURSION_DEPTH', 2)
    FFUF_AUTO_CALIBRATE = settings.get('FFUF_AUTO_CALIBRATE', True)
    FFUF_FOLLOW_REDIRECTS = settings.get('FFUF_FOLLOW_REDIRECTS', False)
    FFUF_CUSTOM_HEADERS = settings.get('FFUF_CUSTOM_HEADERS', [])
    FFUF_SMART_FUZZ = settings.get('FFUF_SMART_FUZZ', True)
    FFUF_PARALLELISM = settings.get('FFUF_PARALLELISM', 3)

    # Arjun settings
    ARJUN_ENABLED = settings.get('ARJUN_ENABLED', False)
    ARJUN_THREADS = settings.get('ARJUN_THREADS', 2)
    ARJUN_TIMEOUT = settings.get('ARJUN_TIMEOUT', 15)
    ARJUN_SCAN_TIMEOUT = settings.get('ARJUN_SCAN_TIMEOUT', 600)
    ARJUN_METHODS = settings.get('ARJUN_METHODS', ['GET'])
    ARJUN_MAX_ENDPOINTS = settings.get('ARJUN_MAX_ENDPOINTS', 50)
    ARJUN_CHUNK_SIZE = settings.get('ARJUN_CHUNK_SIZE', 500)
    ARJUN_RATE_LIMIT = settings.get('ARJUN_RATE_LIMIT', 0)
    ARJUN_STABLE = settings.get('ARJUN_STABLE', False)
    ARJUN_PASSIVE = settings.get('ARJUN_PASSIVE', False)
    ARJUN_DISABLE_REDIRECTS = settings.get('ARJUN_DISABLE_REDIRECTS', False)
    ARJUN_CUSTOM_HEADERS = settings.get('ARJUN_CUSTOM_HEADERS', [])

    # GAU settings - disable in IP mode (archives index by domain, not IP)
    ip_mode = recon_data.get("metadata", {}).get("ip_mode", False)
    GAU_ENABLED = False if ip_mode else settings.get('GAU_ENABLED', False)
    GAU_DOCKER_IMAGE = settings.get('GAU_DOCKER_IMAGE', 'sxcurity/gau:latest')
    GAU_PROVIDERS = list(settings.get('GAU_PROVIDERS', ['wayback', 'commoncrawl', 'otx', 'urlscan']))

    # If URLScan enrichment already ran and returned data, remove urlscan from GAU
    # providers to avoid duplicate API calls and wasted rate limits (same data source)
    if recon_data.get('urlscan', {}).get('results_count', 0) > 0 and 'urlscan' in GAU_PROVIDERS:
        GAU_PROVIDERS = [p for p in GAU_PROVIDERS if p != 'urlscan']
        print(f"[*][GAU] Removed 'urlscan' from GAU providers (already fetched by URLScan enrichment)")
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
    GAU_WORKERS = settings.get('GAU_WORKERS', 10)
    URLSCAN_API_KEY = settings.get('URLSCAN_API_KEY', '')

    # ParamSpider settings - disable in IP mode (archives index by domain, not IP)
    PARAMSPIDER_ENABLED = False if ip_mode else settings.get('PARAMSPIDER_ENABLED', False)
    PARAMSPIDER_PLACEHOLDER = settings.get('PARAMSPIDER_PLACEHOLDER', 'FUZZ')
    PARAMSPIDER_TIMEOUT = settings.get('PARAMSPIDER_TIMEOUT', 120)
    PARAMSPIDER_WORKERS = settings.get('PARAMSPIDER_WORKERS', 5)

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
    KITERUNNER_PARALLELISM = settings.get('KITERUNNER_PARALLELISM', 2)

    # General settings
    USE_TOR_FOR_RECON = settings.get('USE_TOR_FOR_RECON', False)

    # Check Docker
    if not is_docker_installed():
        print("[!][ResourceEnum] Docker not found. Please install Docker.")
        return recon_data

    if not is_docker_running():
        print("[!][ResourceEnum] Docker daemon is not running.")
        return recon_data

    # Pull Docker images and ensure Kiterunner binary in parallel
    print("\n[*][ResourceEnum] Setting up tools...")
    kr_binary_path = None

    with ThreadPoolExecutor(max_workers=4) as executor:
        if KATANA_ENABLED:
            katana_future = executor.submit(pull_katana_docker_image, KATANA_DOCKER_IMAGE)
        if HAKRAWLER_ENABLED:
            hakrawler_future = executor.submit(pull_hakrawler_docker_image, HAKRAWLER_DOCKER_IMAGE)
        if GAU_ENABLED:
            gau_future = executor.submit(pull_gau_docker_image, GAU_DOCKER_IMAGE)
        if KITERUNNER_ENABLED and KITERUNNER_WORDLISTS:
            kr_future = executor.submit(ensure_kiterunner_binary, KITERUNNER_WORDLISTS[0])
        if KATANA_ENABLED:
            katana_future.result()
        if HAKRAWLER_ENABLED:
            hakrawler_future.result()
        if GAU_ENABLED:
            gau_future.result()
        if KITERUNNER_ENABLED and KITERUNNER_WORDLISTS:
            kr_binary_path, _ = kr_future.result()

    # Check Tor status
    use_proxy = False
    if USE_TOR_FOR_RECON:
        if is_tor_running():
            use_proxy = True
            print(f"[*][ResourceEnum] Anonymous mode: Using Tor SOCKS proxy")
        else:
            print("[!][ResourceEnum] Tor not running, falling back to direct connection")

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
        dns_data = recon_data.get('dns') or {}
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
        print("[!][ResourceEnum] No target URLs found")
        return recon_data

    print(f"\n[*][ResourceEnum] Target URLs: {len(target_urls)}")
    print(f"[*][ResourceEnum] Target domains (for GAU): {len(target_domains)}")
    print(f"[*][ResourceEnum] Tor proxy: {use_proxy}")
    # Katana settings
    print(f"[*][Katana] Enabled: {KATANA_ENABLED}")
    if KATANA_ENABLED:
        print(f"[*][Katana] Crawl depth: {KATANA_DEPTH}")
        print(f"[*][Katana] Max URLs: {KATANA_MAX_URLS}")
        print(f"[*][Katana] Rate limit: {KATANA_RATE_LIMIT} req/s")
        print(f"[*][Katana] Timeout: {KATANA_TIMEOUT}s")
        print(f"[*][Katana] JS crawl: {KATANA_JS_CRAWL}")
        print(f"[*][Katana] Params only: {KATANA_PARAMS_ONLY}")
        if KATANA_CUSTOM_HEADERS:
            print(f"[*][Katana] Custom headers: {len(KATANA_CUSTOM_HEADERS)}")
        if KATANA_EXCLUDE_PATTERNS:
            print(f"[*][Katana] Exclude patterns: {len(KATANA_EXCLUDE_PATTERNS)}")
        print(f"[*][Katana] Parallelism: {KATANA_PARALLELISM} (concurrent targets)")
        print(f"[*][Katana] Concurrency: {KATANA_CONCURRENCY} (fetchers per target)")
    # Hakrawler settings
    print(f"[*][Hakrawler] Enabled: {HAKRAWLER_ENABLED}")
    if HAKRAWLER_ENABLED:
        print(f"[*][Hakrawler] Crawl depth: {HAKRAWLER_DEPTH}")
        print(f"[*][Hakrawler] Threads: {HAKRAWLER_THREADS}")
        print(f"[*][Hakrawler] Per-URL timeout: {HAKRAWLER_TIMEOUT}s")
        print(f"[*][Hakrawler] Max URLs: {HAKRAWLER_MAX_URLS}")
        print(f"[*][Hakrawler] Include subdomains: {HAKRAWLER_INCLUDE_SUBS}")
        if HAKRAWLER_CUSTOM_HEADERS:
            print(f"[*][Hakrawler] Custom headers: {len(HAKRAWLER_CUSTOM_HEADERS)}")
        print(f"[*][Hakrawler] Parallelism: {HAKRAWLER_PARALLELISM} concurrent crawlers")
    # jsluice settings
    print(f"[*][jsluice] Enabled: {JSLUICE_ENABLED}")
    if JSLUICE_ENABLED:
        print(f"[*][jsluice] Max files: {JSLUICE_MAX_FILES}")
        print(f"[*][jsluice] Timeout: {JSLUICE_TIMEOUT}s")
        print(f"[*][jsluice] Extract URLs: {JSLUICE_EXTRACT_URLS}")
        print(f"[*][jsluice] Extract secrets: {JSLUICE_EXTRACT_SECRETS}")
        print(f"[*][jsluice] Parallelism: {JSLUICE_PARALLELISM} concurrent base URLs")
    # FFuf settings
    print(f"[*][FFuf] Enabled: {FFUF_ENABLED}")
    if FFUF_ENABLED:
        print(f"[*][FFuf] Wordlist: {FFUF_WORDLIST}")
        print(f"[*][FFuf] Threads: {FFUF_THREADS}")
        print(f"[*][FFuf] Rate limit: {FFUF_RATE} req/s" if FFUF_RATE > 0 else "[*][FFuf] Rate limit: unlimited")
        print(f"[*][FFuf] Timeout: {FFUF_TIMEOUT}s per request, {FFUF_MAX_TIME}s max")
        print(f"[*][FFuf] Auto-calibrate: {FFUF_AUTO_CALIBRATE}")
        print(f"[*][FFuf] Smart fuzz: {FFUF_SMART_FUZZ}")
        print(f"[*][FFuf] Parallelism: {FFUF_PARALLELISM} concurrent targets")
        if FFUF_EXTENSIONS:
            print(f"[*][FFuf] Extensions: {', '.join(FFUF_EXTENSIONS)}")
        if FFUF_RECURSION:
            print(f"[*][FFuf] Recursion: depth {FFUF_RECURSION_DEPTH}")
    # GAU settings
    print(f"[*][GAU] Enabled: {GAU_ENABLED}")
    if GAU_ENABLED:
        print(f"[*][GAU] Providers: {', '.join(GAU_PROVIDERS)}")
        print(f"[*][GAU] Threads: {GAU_THREADS}")
        print(f"[*][GAU] Timeout: {GAU_TIMEOUT}s")
        print(f"[*][GAU] Max URLs: {GAU_MAX_URLS}")
        print(f"[*][GAU] URL verification: {GAU_VERIFY_URLS}")
        if GAU_VERIFY_URLS:
            print(f"[*][GAU] Verify rate limit: {GAU_VERIFY_RATE_LIMIT} req/s")
            print(f"[*][GAU] Verify threads: {GAU_VERIFY_THREADS}")
            print(f"[*][GAU] Verify timeout: {GAU_VERIFY_TIMEOUT}s")
        print(f"[*][GAU] Detect methods: {GAU_DETECT_METHODS}")
        print(f"[*][GAU] Filter dead endpoints: {GAU_FILTER_DEAD_ENDPOINTS}")
        print(f"[*][GAU] Workers: {GAU_WORKERS} parallel domain queries")
    # ParamSpider settings
    print(f"[*][ParamSpider] Enabled: {PARAMSPIDER_ENABLED}")
    if PARAMSPIDER_ENABLED:
        print(f"[*][ParamSpider] Placeholder: {PARAMSPIDER_PLACEHOLDER}")
        print(f"[*][ParamSpider] Timeout: {PARAMSPIDER_TIMEOUT}s")
        print(f"[*][ParamSpider] Workers: {PARAMSPIDER_WORKERS} parallel domains")
    # Kiterunner settings
    print(f"[*][Kiterunner] Enabled: {KITERUNNER_ENABLED}")
    if KITERUNNER_ENABLED:
        print(f"[*][Kiterunner] Wordlists: {', '.join(KITERUNNER_WORDLISTS)}")
        print(f"[*][Kiterunner] Rate limit: {KITERUNNER_RATE_LIMIT} req/s")
        print(f"[*][Kiterunner] Connections: {KITERUNNER_CONNECTIONS}")
        print(f"[*][Kiterunner] Timeout: {KITERUNNER_TIMEOUT}s")
        print(f"[*][Kiterunner] Scan timeout: {KITERUNNER_SCAN_TIMEOUT}s")
        print(f"[*][Kiterunner] Threads: {KITERUNNER_THREADS}")
        print(f"[*][Kiterunner] Detect methods: {KITERUNNER_DETECT_METHODS}")
        if KITERUNNER_DETECT_METHODS:
            print(f"[*][Kiterunner] Method detection mode: {KITERUNNER_METHOD_DETECTION_MODE}")
    # Arjun settings
    print(f"[*][Arjun] Enabled: {ARJUN_ENABLED}")
    if ARJUN_ENABLED:
        print(f"[*][Arjun] Methods: {', '.join(ARJUN_METHODS)} ({'parallel' if len(ARJUN_METHODS) > 1 else 'single'})")
        print(f"[*][Arjun] Max endpoints: {ARJUN_MAX_ENDPOINTS}")
        print(f"[*][Arjun] Threads: {ARJUN_THREADS}")
        print(f"[*][Arjun] Timeout: {ARJUN_TIMEOUT}s per request, {ARJUN_SCAN_TIMEOUT}s scan")
        print(f"[*][Arjun] Chunk size: {ARJUN_CHUNK_SIZE}")
        print(f"[*][Arjun] Rate limit: {ARJUN_RATE_LIMIT} req/s" if ARJUN_RATE_LIMIT > 0 else "[*][Arjun] Rate limit: unlimited")
        print(f"[*][Arjun] Passive only: {ARJUN_PASSIVE}")
        print(f"[*][Arjun] Stable mode: {ARJUN_STABLE}")
        if ARJUN_CUSTOM_HEADERS:
            print(f"[*][Arjun] Custom headers: {len(ARJUN_CUSTOM_HEADERS)}")
    print("=" * 70)

    start_time = datetime.now()

    # Initialize results
    katana_urls = []
    katana_meta = {}
    hakrawler_urls = []
    hakrawler_meta = {}
    gau_urls = []
    gau_urls_by_domain = {}
    paramspider_urls = []
    paramspider_urls_by_domain = {}
    kr_results = []
    ffuf_results = []
    ffuf_meta = {}
    arjun_results = []
    arjun_meta = {}
    jsluice_result = {"urls": [], "secrets": [], "external_domains": []}

    # Run Katana, Hakrawler, GAU, and ParamSpider in parallel first (if enabled)
    if KATANA_ENABLED or HAKRAWLER_ENABLED or GAU_ENABLED or PARAMSPIDER_ENABLED:
        tools_running = []
        if KATANA_ENABLED:
            tools_running.append("Katana")
        if HAKRAWLER_ENABLED:
            tools_running.append("Hakrawler")
        if GAU_ENABLED:
            tools_running.append("GAU")
        if PARAMSPIDER_ENABLED:
            tools_running.append("ParamSpider")
        print(f"\n[*][ResourceEnum] Running URL discovery ({' + '.join(tools_running)})...")
    elif not KITERUNNER_ENABLED:
        print("\n[-][ResourceEnum] All URL discovery tools disabled (Katana, Hakrawler, GAU, ParamSpider, Kiterunner)")

    with ThreadPoolExecutor(max_workers=4) as executor:
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
                use_proxy,
                KATANA_PARALLELISM,
                KATANA_CONCURRENCY,
            )

        # Submit Hakrawler crawler if enabled
        if HAKRAWLER_ENABLED:
            futures['hakrawler'] = executor.submit(
                run_hakrawler_crawler,
                target_urls,
                HAKRAWLER_DOCKER_IMAGE,
                HAKRAWLER_DEPTH,
                HAKRAWLER_THREADS,
                HAKRAWLER_TIMEOUT,
                HAKRAWLER_MAX_URLS,
                HAKRAWLER_INCLUDE_SUBS,
                HAKRAWLER_INSECURE,
                target_domains,
                HAKRAWLER_CUSTOM_HEADERS,
                KATANA_EXCLUDE_PATTERNS,
                use_proxy,
                HAKRAWLER_PARALLELISM,
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
                use_proxy,
                URLSCAN_API_KEY,
                GAU_WORKERS,
            )

        # Submit ParamSpider discovery if enabled
        if PARAMSPIDER_ENABLED and target_domains:
            futures['paramspider'] = executor.submit(
                run_paramspider_discovery,
                target_domains,
                PARAMSPIDER_PLACEHOLDER,
                PARAMSPIDER_TIMEOUT,
                use_proxy,
                PARAMSPIDER_WORKERS,
            )

        # Collect results from all parallel tools
        for name, future in futures.items():
            try:
                if name == 'katana':
                    katana_urls, katana_meta = future.result(timeout=KATANA_TIMEOUT + 120)
                    print(f"\n[+][Katana] Completed: {len(katana_urls)} URLs")
                elif name == 'hakrawler':
                    hakrawler_urls, hakrawler_meta = future.result(timeout=HAKRAWLER_TIMEOUT * 2 + 120)
                    print(f"[+][Hakrawler] Completed: {len(hakrawler_urls)} URLs")
                elif name == 'gau':
                    gau_workers = min(5, len(target_domains))
                    gau_per_domain_timeout = GAU_TIMEOUT * len(GAU_PROVIDERS) + 120
                    gau_overall_timeout = gau_per_domain_timeout * (len(target_domains) // gau_workers + 1) + 180
                    gau_urls, gau_urls_by_domain = future.result(timeout=gau_overall_timeout)
                    print(f"[+][GAU] Completed: {len(gau_urls)} URLs")
                elif name == 'paramspider':
                    paramspider_urls, paramspider_urls_by_domain = future.result(timeout=PARAMSPIDER_TIMEOUT * len(target_domains) + 120)
                    print(f"[+][ParamSpider] Completed: {len(paramspider_urls)} parameterized URLs")
            except Exception as e:
                print(f"[!][ResourceEnum] {name} failed: {e}")

    # Run Kiterunner in parallel for each wordlist
    if KITERUNNER_ENABLED and target_urls and kr_binary_path and KITERUNNER_WORDLISTS:
        # KITERUNNER_PARALLELISM already extracted from settings above
        max_workers = min(KITERUNNER_PARALLELISM, len(KITERUNNER_WORDLISTS))
        print(f"\n[*][Kiterunner] Running API discovery ({len(KITERUNNER_WORDLISTS)} wordlists, {max_workers} parallel)...")

        def _run_kr_wordlist(wordlist_name):
            print(f"\n[*][Kiterunner] Processing wordlist: {wordlist_name}")
            _, wordlist_path = ensure_kiterunner_binary(wordlist_name)
            if not wordlist_path:
                print(f"[!][Kiterunner] Could not get wordlist: {wordlist_name}")
                return wordlist_name, []
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
            return wordlist_name, wordlist_results

        all_wordlist_results = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(_run_kr_wordlist, wl): wl
                for wl in KITERUNNER_WORDLISTS
            }
            for future in as_completed(futures):
                try:
                    wordlist_name, wordlist_results = future.result()
                    all_wordlist_results.append((wordlist_name, wordlist_results))
                    print(f"[+][Kiterunner] {wordlist_name}: {len(wordlist_results)} endpoints found")
                except Exception as e:
                    wl = futures[future]
                    print(f"[!][Kiterunner] Failed for {wl}: {e}")

        # Merge all results, deduplicating
        existing_urls = set()
        for wordlist_name, wordlist_results in all_wordlist_results:
            for result in wordlist_results:
                key = (result['url'], result['method'])
                if key not in existing_urls:
                    kr_results.append(result)
                    existing_urls.add(key)
        print(f"[+][Kiterunner] Total unique endpoints: {len(kr_results)}")

    # Organize discovered endpoints
    if katana_urls:
        print("\n[*][Katana] Organizing endpoints...")
    organized_data = organize_endpoints(katana_urls, use_proxy=use_proxy)

    # Mark all Katana endpoints with sources=['katana'] (array format)
    for base_url, base_data in organized_data['by_base_url'].items():
        for path, endpoint in base_data['endpoints'].items():
            endpoint['sources'] = ['katana']

    # Merge Hakrawler results if available
    hakrawler_stats = {
        "hakrawler_total": 0,
        "hakrawler_new": 0,
        "hakrawler_overlap": 0,
    }

    if HAKRAWLER_ENABLED and hakrawler_urls:
        print("\n[*][Hakrawler] Organizing and merging endpoints...")
        hakrawler_organized = organize_endpoints(hakrawler_urls, use_proxy=use_proxy)
        organized_data['by_base_url'], hakrawler_stats = merge_hakrawler_into_by_base_url(
            hakrawler_organized['by_base_url'],
            organized_data['by_base_url'],
        )
        organized_data['forms'].extend(hakrawler_organized.get('forms', []))

        print(f"[+][Hakrawler] Total endpoints: {hakrawler_stats['hakrawler_total']}")
        print(f"[+][Hakrawler] New endpoints: {hakrawler_stats['hakrawler_new']}")
        print(f"[+][Hakrawler] Overlap with Katana: {hakrawler_stats['hakrawler_overlap']}")

    # jsluice post-crawl JS analysis (runs after crawlers complete)
    jsluice_stats = {
        "jsluice_total": 0,
        "jsluice_parsed": 0,
        "jsluice_new": 0,
        "jsluice_overlap": 0,
    }

    if JSLUICE_ENABLED and (JSLUICE_EXTRACT_URLS or JSLUICE_EXTRACT_SECRETS):
        all_crawl_urls = list(set(katana_urls + hakrawler_urls))
        if all_crawl_urls:
            jsluice_result = run_jsluice_analysis(
                all_crawl_urls,
                JSLUICE_MAX_FILES,
                JSLUICE_TIMEOUT,
                JSLUICE_EXTRACT_URLS,
                JSLUICE_EXTRACT_SECRETS,
                JSLUICE_CONCURRENCY,
                JSLUICE_PARALLELISM,
                target_domains,
                use_proxy
            )

            if jsluice_result.get("urls"):
                print("\n[*][jsluice] Merging extracted URLs into results...")
                organized_data['by_base_url'], jsluice_stats = merge_jsluice_into_by_base_url(
                    jsluice_result["urls"],
                    organized_data['by_base_url'],
                )
                print(f"[+][jsluice] Total URLs: {jsluice_stats['jsluice_total']}")
                print(f"[+][jsluice] New endpoints: {jsluice_stats['jsluice_new']}")
                print(f"[+][jsluice] Overlap: {jsluice_stats['jsluice_overlap']}")

    # FFuf directory fuzzing (runs after crawlers and jsluice, before GAU merge)
    ffuf_stats = {
        "ffuf_total": 0,
        "ffuf_new": 0,
        "ffuf_overlap": 0,
    }

    if FFUF_ENABLED:
        if pull_ffuf_binary_check():
            discovered_base_paths = None
            if FFUF_SMART_FUZZ:
                base_paths = set()
                for base_url, base_data in organized_data['by_base_url'].items():
                    for path in base_data.get('endpoints', {}).keys():
                        parts = path.strip('/').split('/')
                        if len(parts) >= 2:
                            base_paths.add('/'.join(parts[:2]))
                        if len(parts) >= 1 and parts[0]:
                            base_paths.add(parts[0])
                if base_paths:
                    discovered_base_paths = sorted(base_paths)[:20]
                    print(f"[*][FFuf] Smart fuzz: targeting {len(discovered_base_paths)} discovered base paths")

            ffuf_results, ffuf_meta = run_ffuf_discovery(
                target_urls,
                FFUF_WORDLIST,
                FFUF_THREADS,
                FFUF_RATE,
                FFUF_TIMEOUT,
                FFUF_MAX_TIME,
                FFUF_MATCH_CODES,
                FFUF_FILTER_CODES,
                FFUF_FILTER_SIZE,
                FFUF_EXTENSIONS,
                FFUF_RECURSION,
                FFUF_RECURSION_DEPTH,
                FFUF_AUTO_CALIBRATE,
                FFUF_CUSTOM_HEADERS,
                FFUF_FOLLOW_REDIRECTS,
                target_domains,
                discovered_base_paths,
                use_proxy,
                FFUF_PARALLELISM,
            )

            if ffuf_results:
                print("\n[*][FFuf] Merging discovered endpoints into results...")
                organized_data['by_base_url'], ffuf_stats = merge_ffuf_into_by_base_url(
                    ffuf_results,
                    organized_data['by_base_url'],
                )
                print(f"[+][FFuf] Total: {ffuf_stats['ffuf_total']} endpoints")
                print(f"[+][FFuf] New endpoints: {ffuf_stats['ffuf_new']}")
                print(f"[+][FFuf] Overlap with crawlers: {ffuf_stats['ffuf_overlap']}")
        else:
            print("[!][FFuf] ffuf binary not found in PATH, skipping")

    # Arjun parameter discovery (runs after crawlers/FFuf, enriches endpoints with hidden params)
    # Feeds DISCOVERED endpoint URLs (not just base URLs) for maximum coverage.
    arjun_stats = {
        "arjun_total": 0,
        "arjun_new_endpoints": 0,
        "arjun_existing_enriched": 0,
        "arjun_params_discovered": 0,
    }

    if ARJUN_ENABLED:
        if arjun_binary_check():
            # Collect full endpoint URLs from discovered data (Katana + Hakrawler + jsluice + FFuf)
            arjun_target_urls = []
            for base_url, base_data in organized_data['by_base_url'].items():
                for path in base_data.get('endpoints', {}).keys():
                    full_url = base_url.rstrip('/') + path
                    arjun_target_urls.append(full_url)

            # Fall back to base target_urls if no endpoints discovered yet
            if not arjun_target_urls:
                arjun_target_urls = list(target_urls)

            # Cap to max endpoints (most interesting first — API/dynamic endpoints)
            if len(arjun_target_urls) > ARJUN_MAX_ENDPOINTS:
                # Prioritize API and dynamic endpoints over static ones
                api_urls = [u for u in arjun_target_urls if any(p in u.lower() for p in ['/api/', '/v1/', '/v2/', '/graphql', '/rest/'])]
                dynamic_urls = [u for u in arjun_target_urls if u not in api_urls and any(u.lower().endswith(e) for e in ['.php', '.asp', '.aspx', '.jsp'])]
                other_urls = [u for u in arjun_target_urls if u not in api_urls and u not in dynamic_urls]
                arjun_target_urls = (api_urls + dynamic_urls + other_urls)[:ARJUN_MAX_ENDPOINTS]
                print(f"[*][Arjun] Capped to {ARJUN_MAX_ENDPOINTS} endpoints (API: {len(api_urls)}, dynamic: {len(dynamic_urls)}, other: {len(other_urls)})")

            arjun_results, arjun_meta = run_arjun_discovery(
                arjun_target_urls,
                ARJUN_METHODS,
                ARJUN_THREADS,
                ARJUN_TIMEOUT,
                ARJUN_SCAN_TIMEOUT,
                ARJUN_CHUNK_SIZE,
                ARJUN_RATE_LIMIT,
                ARJUN_STABLE,
                ARJUN_PASSIVE,
                ARJUN_DISABLE_REDIRECTS,
                ARJUN_CUSTOM_HEADERS,
                target_domains,
                use_proxy,
            )

            if arjun_results:
                print("\n[*][Arjun] Merging discovered parameters into results...")
                organized_data['by_base_url'], arjun_stats = merge_arjun_into_by_base_url(
                    arjun_results,
                    organized_data['by_base_url'],
                )
                print(f"[+][Arjun] Total URLs with params: {arjun_stats['arjun_total']}")
                print(f"[+][Arjun] New endpoints: {arjun_stats['arjun_new_endpoints']}")
                print(f"[+][Arjun] Existing endpoints enriched: {arjun_stats['arjun_existing_enriched']}")
                print(f"[+][Arjun] Parameters discovered: {arjun_stats['arjun_params_discovered']}")
        else:
            print("[!][Arjun] arjun binary not found in PATH, skipping")

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

    gau_external_domains = []  # Collect out-of-scope domains for situational awareness

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
                if host:
                    gau_external_domains.append({"domain": host, "source": "gau", "url": url})

        if out_of_scope_count > 0:
            print(f"\n[*][GAU] Filtered {out_of_scope_count} URLs (out of scan scope)")
            print(f"[+][GAU] In-scope URLs: {len(in_scope_gau_urls)}")

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
        print("\n[*][GAU] Merging endpoints into results...")
        organized_data['by_base_url'], gau_stats = merge_gau_into_by_base_url(
            gau_urls_to_process,
            organized_data['by_base_url'],
            verified_urls,
            url_methods
        )

        # Add out-of-scope count to stats
        gau_stats['gau_out_of_scope'] = out_of_scope_count

        print(f"[+][GAU] In-scope URLs: {gau_stats['gau_total']}")
        if out_of_scope_count > 0:
            print(f"[+][GAU] Out-of-scope (filtered): {out_of_scope_count}")
        print(f"[+][GAU] Parsed: {gau_stats['gau_parsed']}")
        print(f"[+][GAU] New endpoints: {gau_stats['gau_new']}")
        print(f"[+][GAU] Overlap with Katana: {gau_stats['gau_overlap']}")
        if GAU_VERIFY_URLS:
            print(f"[+][GAU] Skipped (unverified): {gau_stats['gau_skipped_unverified']}")
        if GAU_DETECT_METHODS:
            print(f"[+][GAU] With POST method: {gau_stats.get('gau_with_post', 0)}")
            print(f"[+][GAU] With multiple methods: {gau_stats.get('gau_with_multiple_methods', 0)}")
        if GAU_FILTER_DEAD_ENDPOINTS:
            print(f"[+][GAU] Dead endpoints filtered: {gau_stats.get('gau_skipped_dead', 0)}")

    # Merge ParamSpider results if available
    paramspider_stats = {
        "paramspider_total": 0,
        "paramspider_parsed": 0,
        "paramspider_new": 0,
        "paramspider_overlap": 0,
        "paramspider_out_of_scope": 0,
    }

    if PARAMSPIDER_ENABLED and paramspider_urls:
        print("\n[*][ParamSpider] Merging parameterized endpoints into results...")
        organized_data['by_base_url'], paramspider_stats = merge_paramspider_into_by_base_url(
            paramspider_urls,
            organized_data['by_base_url'],
            target_domains,
        )

        print(f"[+][ParamSpider] Total URLs: {paramspider_stats['paramspider_total']}")
        if paramspider_stats['paramspider_out_of_scope'] > 0:
            print(f"[+][ParamSpider] Out-of-scope (filtered): {paramspider_stats['paramspider_out_of_scope']}")
        print(f"[+][ParamSpider] Parsed: {paramspider_stats['paramspider_parsed']}")
        print(f"[+][ParamSpider] New endpoints: {paramspider_stats['paramspider_new']}")
        print(f"[+][ParamSpider] Overlap with other tools: {paramspider_stats['paramspider_overlap']}")

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

        print("\n[*][Kiterunner] Merging API endpoints into results...")
        organized_data['by_base_url'], kr_stats = merge_kiterunner_into_by_base_url(
            kr_results,
            organized_data['by_base_url'],
            kr_url_methods
        )

        print(f"[+][Kiterunner] Total: {kr_stats['kr_total']} endpoints")
        print(f"[+][Kiterunner] Parsed: {kr_stats['kr_parsed']}")
        print(f"[+][Kiterunner] New endpoints: {kr_stats['kr_new']}")
        print(f"[+][Kiterunner] Overlap with Katana/GAU: {kr_stats['kr_overlap']}")
        if kr_stats['kr_methods']:
            print(f"[+][Kiterunner] Methods found: {kr_stats['kr_methods']}")
        if KITERUNNER_DETECT_METHODS and kr_stats.get('kr_with_multiple_methods', 0) > 0:
            print(f"[+][Kiterunner] Endpoints with multiple methods: {kr_stats['kr_with_multiple_methods']}")

    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    # Get in-scope GAU URLs (already filtered if GAU was enabled)
    in_scope_gau = gau_urls_to_process if GAU_ENABLED and gau_urls else []

    # Merge URLScan discovered URLs into the pipeline (passive URL source, like GAU)
    # Scope-filter against target_domains to prevent out-of-scope URL leakage
    urlscan_urls = []
    urlscan_data = recon_data.get("urlscan", {})
    if urlscan_data:
        urlscan_skipped = 0
        for entry in urlscan_data.get("urls_with_paths", []):
            full_url = entry.get("full_url", "")
            if full_url:
                parsed = urlparse(full_url)
                host = parsed.netloc.split(':')[0] if ':' in parsed.netloc else parsed.netloc
                if host in target_domains:
                    urlscan_urls.append(full_url)
                else:
                    urlscan_skipped += 1
        if urlscan_urls:
            print(f"[+][ResourceEnum] URLScan contributed {len(urlscan_urls)} in-scope URLs with paths")
        if urlscan_skipped:
            print(f"[-][ResourceEnum] URLScan skipped {urlscan_skipped} out-of-scope URLs")

    # Combine all discovered URLs (deduplicated, in-scope only)
    jsluice_in_scope_urls = jsluice_result.get("urls", []) if JSLUICE_ENABLED else []
    ffuf_discovered_urls = [r["url"] for r in ffuf_results] if FFUF_ENABLED else []
    all_discovered_urls = sorted(set(
        katana_urls + hakrawler_urls + in_scope_gau + paramspider_urls + urlscan_urls + jsluice_in_scope_urls + ffuf_discovered_urls
    ))

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
            'katana_parallelism': KATANA_PARALLELISM if KATANA_ENABLED else None,
            'katana_concurrency': KATANA_CONCURRENCY if KATANA_ENABLED else None,
            'katana_urls_found': len(katana_urls) if KATANA_ENABLED else 0,
            # Hakrawler metadata
            'hakrawler_enabled': HAKRAWLER_ENABLED,
            'hakrawler_docker_image': HAKRAWLER_DOCKER_IMAGE if HAKRAWLER_ENABLED else None,
            'hakrawler_depth': HAKRAWLER_DEPTH if HAKRAWLER_ENABLED else None,
            'hakrawler_threads': HAKRAWLER_THREADS if HAKRAWLER_ENABLED else None,
            'hakrawler_parallelism': HAKRAWLER_PARALLELISM if HAKRAWLER_ENABLED else None,
            'hakrawler_urls_found': len(hakrawler_urls) if HAKRAWLER_ENABLED else 0,
            'hakrawler_stats': hakrawler_stats,
            # jsluice metadata
            'jsluice_enabled': JSLUICE_ENABLED,
            'jsluice_max_files': JSLUICE_MAX_FILES if JSLUICE_ENABLED else None,
            'jsluice_urls_found': len(jsluice_in_scope_urls),
            'jsluice_secrets_found': len(jsluice_result.get("secrets", [])),
            'jsluice_stats': jsluice_stats,
            # FFuf metadata
            'ffuf_enabled': FFUF_ENABLED,
            'ffuf_wordlist': FFUF_WORDLIST if FFUF_ENABLED else None,
            'ffuf_threads': FFUF_THREADS if FFUF_ENABLED else None,
            'ffuf_rate': FFUF_RATE if FFUF_ENABLED else None,
            'ffuf_endpoints_found': len(ffuf_results) if FFUF_ENABLED else 0,
            'ffuf_smart_fuzz': FFUF_SMART_FUZZ if FFUF_ENABLED else None,
            'ffuf_stats': ffuf_stats,
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
            # ParamSpider metadata
            'paramspider_enabled': PARAMSPIDER_ENABLED,
            'paramspider_urls_found_total': len(paramspider_urls),
            'paramspider_stats': paramspider_stats,
            # Kiterunner metadata
            'kiterunner_enabled': KITERUNNER_ENABLED,
            'kiterunner_binary_path': kr_binary_path if KITERUNNER_ENABLED else None,
            'kiterunner_wordlists': KITERUNNER_WORDLISTS if KITERUNNER_ENABLED else [],
            'kiterunner_wordlists_count': len(KITERUNNER_WORDLISTS) if KITERUNNER_ENABLED else 0,
            'kiterunner_endpoints_found': len(kr_results) if KITERUNNER_ENABLED else 0,
            'kiterunner_method_detection_enabled': KITERUNNER_DETECT_METHODS if KITERUNNER_ENABLED else False,
            'kiterunner_method_detection_mode': KITERUNNER_METHOD_DETECTION_MODE if KITERUNNER_ENABLED else None,
            'kiterunner_stats': kr_stats,
            # Arjun metadata
            'arjun_enabled': ARJUN_ENABLED,
            'arjun_methods': ARJUN_METHODS if ARJUN_ENABLED else [],
            'arjun_max_endpoints': ARJUN_MAX_ENDPOINTS if ARJUN_ENABLED else None,
            'arjun_passive': ARJUN_PASSIVE if ARJUN_ENABLED else None,
            'arjun_params_discovered': arjun_stats['arjun_params_discovered'],
            'arjun_stats': arjun_stats,
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
            'from_hakrawler': len(hakrawler_urls) if HAKRAWLER_ENABLED else 0,
            'hakrawler_new_endpoints': hakrawler_stats['hakrawler_new'],
            'hakrawler_overlap': hakrawler_stats['hakrawler_overlap'],
            'from_jsluice_urls': len(jsluice_in_scope_urls),
            'jsluice_new_endpoints': jsluice_stats['jsluice_new'],
            'jsluice_overlap': jsluice_stats['jsluice_overlap'],
            'jsluice_secrets_count': len(jsluice_result.get("secrets", [])),
            'from_ffuf': len(ffuf_results) if FFUF_ENABLED else 0,
            'ffuf_new_endpoints': ffuf_stats['ffuf_new'],
            'ffuf_overlap': ffuf_stats['ffuf_overlap'],
            'from_gau_total': len(gau_urls),  # All URLs found by GAU
            'from_gau_in_scope': len(in_scope_gau),  # Only in-scope URLs
            'gau_new_endpoints': gau_stats['gau_new'],
            'gau_overlap': gau_stats['gau_overlap'],
            # ParamSpider breakdown
            'from_paramspider_total': len(paramspider_urls),
            'paramspider_new_endpoints': paramspider_stats['paramspider_new'],
            'paramspider_overlap': paramspider_stats['paramspider_overlap'],
            # Kiterunner breakdown
            'from_kiterunner': len(kr_results) if KITERUNNER_ENABLED else 0,
            'kiterunner_new_endpoints': kr_stats['kr_new'],
            'kiterunner_overlap': kr_stats['kr_overlap'],
            'kiterunner_with_multiple_methods': kr_stats.get('kr_with_multiple_methods', 0),
            # Arjun breakdown
            'from_arjun': arjun_stats['arjun_total'] if ARJUN_ENABLED else 0,
            'arjun_new_endpoints': arjun_stats['arjun_new_endpoints'],
            'arjun_existing_enriched': arjun_stats['arjun_existing_enriched'],
            'arjun_params_discovered': arjun_stats['arjun_params_discovered'],
            'methods': {},
            'categories': {}
        },
        'jsluice_secrets': jsluice_result.get("secrets", []),
        'external_domains': (
            gau_external_domains
            + katana_meta.get("external_domains", [])
            + hakrawler_meta.get("external_domains", [])
            + jsluice_result.get("external_domains", [])
            + ffuf_meta.get("external_domains", [])
            + arjun_meta.get("external_domains", [])
        ),
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
    print(f"[✓][ResourceEnum] RESOURCE ENUMERATION COMPLETE")
    print(f"[+][ResourceEnum] Duration: {duration:.2f} seconds")
    print(f"[+][ResourceEnum] Total URLs discovered: {len(all_discovered_urls)}")
    print(f"[+][Katana] Active crawl: {len(katana_urls) if KATANA_ENABLED else 'disabled'}")
    print(f"[+][Hakrawler] Active crawl: {len(hakrawler_urls) if HAKRAWLER_ENABLED else 'disabled'}")
    if HAKRAWLER_ENABLED and hakrawler_urls:
        print(f"[+][Hakrawler] New endpoints: {hakrawler_stats['hakrawler_new']}")
        print(f"[+][Hakrawler] Overlap: {hakrawler_stats['hakrawler_overlap']}")
    print(f"[+][jsluice] JS analysis: {len(jsluice_in_scope_urls)} URLs, {len(jsluice_result.get('secrets', []))} secrets" if JSLUICE_ENABLED else "[+][jsluice] JS analysis: disabled")
    if JSLUICE_ENABLED and jsluice_in_scope_urls:
        print(f"[+][jsluice] New endpoints: {jsluice_stats['jsluice_new']}")
    print(f"[+][FFuf] Directory fuzzing: {len(ffuf_results) if FFUF_ENABLED else 'disabled'}")
    if FFUF_ENABLED and ffuf_results:
        print(f"[+][FFuf] New endpoints: {ffuf_stats['ffuf_new']}")
        print(f"[+][FFuf] Overlap: {ffuf_stats['ffuf_overlap']}")
    print(f"[+][GAU] Passive archive: {len(gau_urls) if GAU_ENABLED else 'disabled'}")
    if GAU_ENABLED and gau_urls:
        print(f"[+][GAU] New endpoints: {gau_stats['gau_new']}")
        print(f"[+][GAU] Overlap: {gau_stats['gau_overlap']}")
    print(f"[+][ParamSpider] Passive params: {len(paramspider_urls) if PARAMSPIDER_ENABLED else 'disabled'}")
    if PARAMSPIDER_ENABLED and paramspider_urls:
        print(f"[+][ParamSpider] New endpoints: {paramspider_stats['paramspider_new']}")
        print(f"[+][ParamSpider] Overlap: {paramspider_stats['paramspider_overlap']}")
    print(f"[+][Kiterunner] API bruteforce: {len(kr_results) if KITERUNNER_ENABLED else 'disabled'}")
    if KITERUNNER_ENABLED and kr_results:
        print(f"[+][Kiterunner] New endpoints: {kr_stats['kr_new']}")
        print(f"[+][Kiterunner] Overlap: {kr_stats['kr_overlap']}")
    print(f"[+][Arjun] Parameter discovery: {arjun_stats['arjun_params_discovered']} params" if ARJUN_ENABLED else "[+][Arjun] Parameter discovery: disabled")
    if ARJUN_ENABLED and arjun_stats['arjun_params_discovered'] > 0:
        print(f"[+][Arjun] Enriched endpoints: {arjun_stats['arjun_existing_enriched']}")
        print(f"[+][Arjun] New endpoints: {arjun_stats['arjun_new_endpoints']}")
    print(f"[+][ResourceEnum] Base URLs: {resource_enum_result['summary']['total_base_urls']}")
    print(f"[+][ResourceEnum] Endpoints: {resource_enum_result['summary']['total_endpoints']}")
    print(f"[+][ResourceEnum] Parameters: {resource_enum_result['summary']['total_parameters']}")
    print(f"[+][ResourceEnum] Forms (POST): {resource_enum_result['summary']['total_forms']}")

    # Methods breakdown
    methods = resource_enum_result['summary']['methods']
    if methods:
        print(f"\n[+][ResourceEnum] HTTP Methods:")
        for method, count in sorted(methods.items()):
            print(f"[*][ResourceEnum] {method}: {count}")

    # Categories breakdown
    categories = resource_enum_result['summary']['categories']
    if categories:
        print(f"\n[+][ResourceEnum] Endpoint Categories:")
        for category, count in sorted(categories.items(), key=lambda x: -x[1]):
            print(f"[*][ResourceEnum] {category}: {count}")

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
            print(f"\n[+][ResourceEnum] Results saved to: {recon_file}")
        else:
            print(f"[!][ResourceEnum] File not found: {recon_file}")
    else:
        print("[*][ResourceEnum] Usage: python resource_enum.py <recon_file.json>")
