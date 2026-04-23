"""
Project Settings - Fetch project configuration from webapp API

When PROJECT_ID and WEBAPP_API_URL are set as environment variables,
settings are fetched from the PostgreSQL database via webapp API.
Otherwise, falls back to DEFAULT_SETTINGS for CLI usage.
"""
import os
import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)

# =============================================================================
# DEFAULT SETTINGS - Used as fallback for CLI usage and missing API fields
# =============================================================================
# These defaults are used when:
# 1. Running from CLI without PROJECT_ID/WEBAPP_API_URL env vars
# 2. As default values for any fields missing from the API response

DEFAULT_SETTINGS: dict[str, Any] = {
    # Core identifiers (empty for CLI usage)
    'PROJECT_ID': '',
    'USER_ID': '',

    # Target Configuration
    'TARGET_DOMAIN': '',
    'SUBDOMAIN_LIST': [],
    'IP_MODE': False,
    'TARGET_IPS': [],
    'VERIFY_DOMAIN_OWNERSHIP': False,
    'OWNERSHIP_TOKEN': 'your-secret-token-here',
    'OWNERSHIP_TXT_PREFIX': '_redamon-verify',

    # Scan Modules
    'SCAN_MODULES': ['domain_discovery', 'port_scan', 'http_probe', 'resource_enum', 'vuln_scan'],
    'UPDATE_GRAPH_DB': True,
    'USE_TOR_FOR_RECON': False,
    'USE_BRUTEFORCE_FOR_SUBDOMAINS': False,
    'STEALTH_MODE': False,

    # WHOIS/DNS
    'WHOIS_ENABLED': True,
    'WHOIS_MAX_RETRIES': 6,
    'DNS_ENABLED': True,
    'DNS_MAX_RETRIES': 3,
    'DNS_MAX_WORKERS': 80,
    'DNS_RECORD_PARALLELISM': True,

    # Naabu Port Scanner
    'NAABU_ENABLED': True,
    'NAABU_DOCKER_IMAGE': 'projectdiscovery/naabu:latest',
    'NAABU_TOP_PORTS': '1000',
    'NAABU_CUSTOM_PORTS': '',
    'NAABU_RATE_LIMIT': 1000,
    'NAABU_THREADS': 25,
    'NAABU_TIMEOUT': 10000,
    'NAABU_RETRIES': 1,
    'NAABU_SCAN_TYPE': 's',
    'NAABU_EXCLUDE_CDN': False,
    'NAABU_DISPLAY_CDN': True,
    'NAABU_SKIP_HOST_DISCOVERY': True,
    'NAABU_VERIFY_PORTS': True,
    'NAABU_PASSIVE_MODE': False,

    # Nmap Service Detection & NSE Vuln Scripts
    'NMAP_ENABLED': True,
    'NMAP_VERSION_DETECTION': True,
    'NMAP_SCRIPT_SCAN': True,
    'NMAP_TIMING_TEMPLATE': 'T3',
    'NMAP_TIMEOUT': 600,
    'NMAP_HOST_TIMEOUT': 300,
    'NMAP_PARALLELISM': 5,

    # Masscan Port Scanner (disabled by default -- only useful for large IP ranges/CIDRs)
    'MASSCAN_ENABLED': False,
    'MASSCAN_TOP_PORTS': '1000',
    'MASSCAN_CUSTOM_PORTS': '',
    'MASSCAN_RATE': 1000,
    'MASSCAN_BANNERS': False,
    'MASSCAN_WAIT': 10,
    'MASSCAN_RETRIES': 1,
    'MASSCAN_EXCLUDE_TARGETS': '',

    # httpx HTTP Probing
    'HTTPX_ENABLED': True,
    'HTTPX_DOCKER_IMAGE': 'projectdiscovery/httpx:latest',
    'HTTPX_THREADS': 50,
    'HTTPX_TIMEOUT': 10,
    'HTTPX_RETRIES': 2,
    'HTTPX_RATE_LIMIT': 50,
    'HTTPX_FOLLOW_REDIRECTS': True,
    'HTTPX_MAX_REDIRECTS': 10,
    'HTTPX_PROBE_STATUS_CODE': True,
    'HTTPX_PROBE_CONTENT_LENGTH': True,
    'HTTPX_PROBE_CONTENT_TYPE': True,
    'HTTPX_PROBE_TITLE': True,
    'HTTPX_PROBE_SERVER': True,
    'HTTPX_PROBE_RESPONSE_TIME': True,
    'HTTPX_PROBE_WORD_COUNT': True,
    'HTTPX_PROBE_LINE_COUNT': True,
    'HTTPX_PROBE_TECH_DETECT': True,
    'HTTPX_PROBE_IP': True,
    'HTTPX_PROBE_CNAME': True,
    'HTTPX_PROBE_TLS_INFO': True,
    'HTTPX_PROBE_TLS_GRAB': True,
    'HTTPX_PROBE_FAVICON': True,
    'HTTPX_PROBE_JARM': True,
    'HTTPX_PROBE_HASH': 'sha256',
    'HTTPX_INCLUDE_RESPONSE': True,
    'HTTPX_INCLUDE_RESPONSE_HEADERS': True,
    'HTTPX_PROBE_ASN': True,
    'HTTPX_PROBE_CDN': True,
    'HTTPX_PATHS': [],
    'HTTPX_CUSTOM_HEADERS': [
        'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language: en-US,en;q=0.9',
        'Accept-Encoding: gzip, deflate',
        'Connection: keep-alive',
        'Upgrade-Insecure-Requests: 1',
        'Sec-Fetch-Dest: document',
        'Sec-Fetch-Mode: navigate',
        'Sec-Fetch-Site: none',
        'Sec-Fetch-User: ?1',
        'Cache-Control: max-age=0',
    ],
    'HTTPX_MATCH_CODES': [],
    'HTTPX_FILTER_CODES': [],

    # Wappalyzer
    'WAPPALYZER_ENABLED': True,
    'WAPPALYZER_MIN_CONFIDENCE': 50,
    'WAPPALYZER_REQUIRE_HTML': True,
    'WAPPALYZER_AUTO_UPDATE': True,
    'WAPPALYZER_NPM_VERSION': '6.10.56',
    'WAPPALYZER_CACHE_TTL_HOURS': 24,

    # Banner Grabbing
    'BANNER_GRAB_ENABLED': True,
    'BANNER_GRAB_TIMEOUT': 5,
    'BANNER_GRAB_THREADS': 20,
    'BANNER_GRAB_MAX_LENGTH': 500,

    # Nuclei Vulnerability Scanner
    'NUCLEI_ENABLED': True,
    'NUCLEI_SEVERITY': ['critical', 'high', 'medium', 'low'],
    'NUCLEI_TEMPLATES': [],
    'NUCLEI_EXCLUDE_TEMPLATES': [],
    'NUCLEI_CUSTOM_TEMPLATES': [],
    'NUCLEI_SELECTED_CUSTOM_TEMPLATES': [],
    'NUCLEI_RATE_LIMIT': 100,
    'NUCLEI_BULK_SIZE': 25,
    'NUCLEI_CONCURRENCY': 25,
    'NUCLEI_TIMEOUT': 10,
    'NUCLEI_RETRIES': 1,
    'NUCLEI_TAGS': [],
    'NUCLEI_EXCLUDE_TAGS': [],
    'NUCLEI_DAST_MODE': True,
    'NUCLEI_AUTO_UPDATE_TEMPLATES': True,
    'NUCLEI_NEW_TEMPLATES_ONLY': False,
    'NUCLEI_HEADLESS': False,
    'NUCLEI_SYSTEM_RESOLVERS': True,
    'NUCLEI_FOLLOW_REDIRECTS': True,
    'NUCLEI_MAX_REDIRECTS': 10,
    'NUCLEI_SCAN_ALL_IPS': False,
    'NUCLEI_INTERACTSH': True,
    'NUCLEI_DOCKER_IMAGE': 'projectdiscovery/nuclei:latest',

    # Subdomain Takeover Scanner (Subjack + Nuclei takeover templates)
    # Runs in GROUP 6 Phase A alongside Nuclei; writes Vulnerability nodes
    # with source="takeover_scan". See recon/main_recon_modules/subdomain_takeover.py.
    'SUBDOMAIN_TAKEOVER_ENABLED': False,
    'SUBJACK_ENABLED': True,
    'SUBJACK_THREADS': 10,
    'SUBJACK_TIMEOUT': 30,
    'SUBJACK_SSL': True,
    'SUBJACK_ALL': False,
    'SUBJACK_CHECK_NS': False,
    'SUBJACK_CHECK_AR': False,
    'SUBJACK_CHECK_MAIL': False,
    'SUBJACK_RUN_TIMEOUT': 900,
    'NUCLEI_TAKEOVERS_ENABLED': True,
    'NUCLEI_TAKEOVER_RUN_TIMEOUT': 1800,
    'TAKEOVER_SEVERITY': ['critical', 'high', 'medium'],
    'TAKEOVER_CONFIDENCE_THRESHOLD': 60,
    'TAKEOVER_RATE_LIMIT': 50,
    'TAKEOVER_MANUAL_REVIEW_AUTO_PUBLISH': False,
    # BadDNS (AGPL-3.0, isolated sidecar — disabled by default, opt-in)
    'BADDNS_ENABLED': False,
    'BADDNS_DOCKER_IMAGE': 'redamon-baddns:latest',
    'BADDNS_MODULES': ['cname', 'ns', 'mx', 'txt', 'spf'],
    'BADDNS_NAMESERVERS': [],
    'BADDNS_RUN_TIMEOUT': 1800,

    # Katana Web Crawler
    'KATANA_ENABLED': True,
    'KATANA_DOCKER_IMAGE': 'projectdiscovery/katana:latest',
    'KATANA_DEPTH': 2,
    'KATANA_MAX_URLS': 300,
    'KATANA_RATE_LIMIT': 50,
    'KATANA_TIMEOUT': 3600,
    'KATANA_JS_CRAWL': True,
    'KATANA_PARAMS_ONLY': False,
    'KATANA_EXCLUDE_PATTERNS': [
        '/_next/image', '/_next/static', '/_next/data', '/__nextjs',
        '/_nuxt/', '/__nuxt',
        '/runtime.', '/polyfills.', '/vendor.',
        '/webpack', '/chunk.', '.chunk.js', '.bundle.js', 'hot-update',
        '/static/', '/public/', '/dist/', '/build/', '/lib/', '/vendor/', '/node_modules/',
        '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp', '.avif',
        '.bmp', '.tiff', '.tif', '.heic', '.heif', '.raw',
        '/images/', '/img/', '/image/', '/pics/', '/pictures/',
        '/thumbnails/', '/thumb/', '/thumbs/',
        '.css', '.scss', '.sass', '.less', '.styl', '.css.map',
        '/css/', '/styles/', '/style/', '/stylesheet/',
        '.js.map', '.min.js', '/js/lib/', '/js/vendor/', '/js/plugins/',
        'jquery', 'bootstrap.js', 'popper.js',
        '.woff', '.woff2', '.ttf', '.eot', '.otf', '/fonts/', '/font/', '/webfonts/',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.txt', '.rtf', '.odt', '.ods', '.odp',
        '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2',
        '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.webm', '.mkv',
        '.wav', '.ogg', '.aac', '.m4a', '.flac',
        '/video/', '/videos/', '/audio/', '/music/', '/sounds/',
        '/wp-content/uploads/', '/wp-content/themes/', '/wp-includes/',
        '/sites/default/files/', '/core/assets/',
        '/pub/static/', '/pub/media/',
        '/storage/', '/staticfiles/', '/packs/',
        'cdn.', 'cdnjs.', 'cloudflare.', 'akamai.', 'fastly.',
        'googleapis.com', 'gstatic.com', 'cloudfront.net',
        'unpkg.com', 'jsdelivr.net', 'bootstrapcdn.com',
        'google-analytics', 'googletagmanager', 'gtag/',
        'facebook.com/tr', 'facebook.net',
        'analytics.', 'tracking.', 'pixel.',
        'hotjar.', 'mouseflow.', 'clarity.',
        'googlesyndication', 'doubleclick', 'adservice',
        'platform.twitter', 'connect.facebook', 'platform.linkedin',
        'maps.google', 'maps.googleapis', 'openstreetmap', 'mapbox',
        'recaptcha', 'hcaptcha', 'captcha',
        'manifest.json', 'sw.js', 'service-worker',
        'browserconfig.xml', 'robots.txt', 'sitemap.xml', '.well-known/',
        'favicon', 'apple-touch-icon', 'android-chrome', '/icons/', '/icon/',
    ],
    'KATANA_CUSTOM_HEADERS': [
        'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language: en-US,en;q=0.9',
    ],
    'KATANA_PARALLELISM': 8,
    'KATANA_CONCURRENCY': 15,

    # GAU Passive URL Discovery
    'GAU_ENABLED': False,
    'GAU_DOCKER_IMAGE': 'sxcurity/gau:latest',
    'GAU_PROVIDERS': ['wayback', 'commoncrawl', 'otx', 'urlscan'],
    'GAU_MAX_URLS': 1000,
    'GAU_TIMEOUT': 60,
    'GAU_THREADS': 5,
    'GAU_BLACKLIST_EXTENSIONS': [
        'png', 'jpg', 'jpeg', 'gif', 'svg', 'ico', 'webp', 'avif',
        'css', 'woff', 'woff2', 'ttf', 'eot', 'otf',
        'mp3', 'mp4', 'avi', 'mov', 'wmv', 'flv', 'webm',
        'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
        'zip', 'rar', '7z', 'tar', 'gz',
    ],
    'GAU_YEAR_RANGE': [],
    'GAU_VERBOSE': False,
    'GAU_VERIFY_URLS': True,
    'GAU_VERIFY_DOCKER_IMAGE': 'projectdiscovery/httpx:latest',
    'GAU_VERIFY_TIMEOUT': 5,
    'GAU_VERIFY_RATE_LIMIT': 100,
    'GAU_VERIFY_THREADS': 50,
    'GAU_VERIFY_ACCEPT_STATUS': [200, 201, 301, 302, 307, 308, 401, 403],
    'GAU_DETECT_METHODS': True,
    'GAU_METHOD_DETECT_TIMEOUT': 5,
    'GAU_METHOD_DETECT_RATE_LIMIT': 50,
    'GAU_METHOD_DETECT_THREADS': 25,
    'GAU_FILTER_DEAD_ENDPOINTS': True,
    'GAU_WORKERS': 10,

    # ParamSpider Passive Parameter Discovery
    'PARAMSPIDER_ENABLED': False,
    'PARAMSPIDER_PLACEHOLDER': 'FUZZ',
    'PARAMSPIDER_TIMEOUT': 120,
    'PARAMSPIDER_WORKERS': 8,

    # Hakrawler Web Crawler
    'HAKRAWLER_ENABLED': True,
    'HAKRAWLER_DOCKER_IMAGE': 'jauderho/hakrawler:latest',
    'HAKRAWLER_DEPTH': 2,
    'HAKRAWLER_THREADS': 5,
    'HAKRAWLER_TIMEOUT': 30,
    'HAKRAWLER_MAX_URLS': 500,
    'HAKRAWLER_INCLUDE_SUBS': True,
    'HAKRAWLER_INSECURE': True,
    'HAKRAWLER_CUSTOM_HEADERS': [],
    'HAKRAWLER_PARALLELISM': 5,

    # jsluice JavaScript Analyzer
    'JSLUICE_ENABLED': True,
    'JSLUICE_MAX_FILES': 100,
    'JSLUICE_TIMEOUT': 300,
    'JSLUICE_EXTRACT_URLS': True,
    'JSLUICE_EXTRACT_SECRETS': True,
    'JSLUICE_CONCURRENCY': 5,
    'JSLUICE_PARALLELISM': 5,

    # ========== JS RECON SCANNER ==========
    'JS_RECON_ENABLED': False,
    'JS_RECON_MAX_FILES': 500,
    'JS_RECON_TIMEOUT': 900,
    'JS_RECON_CONCURRENCY': 10,
    'JS_RECON_VALIDATE_KEYS': True,
    'JS_RECON_VALIDATION_TIMEOUT': 5,
    'JS_RECON_EXTRACT_ENDPOINTS': True,
    'JS_RECON_REGEX_PATTERNS': True,
    'JS_RECON_SOURCE_MAPS': True,
    'JS_RECON_DEPENDENCY_CHECK': True,
    'JS_RECON_DOM_SINKS': True,
    'JS_RECON_FRAMEWORK_DETECT': True,
    'JS_RECON_DEV_COMMENTS': True,
    'JS_RECON_INCLUDE_CHUNKS': True,
    'JS_RECON_INCLUDE_FRAMEWORK_JS': True,
    'JS_RECON_INCLUDE_ARCHIVED_JS': True,
    'JS_RECON_MIN_CONFIDENCE': 'low',
    'JS_RECON_STANDALONE_CRAWL_DEPTH': 3,
    'JS_RECON_STANDALONE_CRAWL_SCOPE': 'subdomain',
    'JS_RECON_UPLOADED_FILES': [],
    'JS_RECON_CUSTOM_PATTERNS': '',
    'JS_RECON_CUSTOM_SOURCEMAP_PATHS': '',
    'JS_RECON_CUSTOM_PACKAGES': '',
    'JS_RECON_CUSTOM_ENDPOINT_KEYWORDS': '',
    'JS_RECON_CUSTOM_FRAMEWORKS': '',

    # FFuf Directory Fuzzer
    'FFUF_ENABLED': False,
    'FFUF_WORDLIST': '/usr/share/seclists/Discovery/Web-Content/common.txt',
    'FFUF_THREADS': 40,
    'FFUF_RATE': 0,
    'FFUF_TIMEOUT': 10,
    'FFUF_MAX_TIME': 600,
    'FFUF_MATCH_CODES': [200, 201, 204, 301, 302, 307, 308, 401, 403, 405],
    'FFUF_FILTER_CODES': [],
    'FFUF_FILTER_SIZE': '',
    'FFUF_EXTENSIONS': [],
    'FFUF_RECURSION': False,
    'FFUF_RECURSION_DEPTH': 2,
    'FFUF_AUTO_CALIBRATE': True,
    'FFUF_FOLLOW_REDIRECTS': False,
    'FFUF_CUSTOM_HEADERS': [],
    'FFUF_SMART_FUZZ': True,
    'FFUF_PARALLELISM': 4,

    # Arjun Parameter Discovery
    'ARJUN_ENABLED': True,
    'ARJUN_THREADS': 2,
    'ARJUN_TIMEOUT': 15,
    'ARJUN_SCAN_TIMEOUT': 600,
    'ARJUN_METHODS': ['GET', 'POST'],
    'ARJUN_MAX_ENDPOINTS': 50,
    'ARJUN_CHUNK_SIZE': 500,
    'ARJUN_RATE_LIMIT': 0,
    'ARJUN_STABLE': False,
    'ARJUN_PASSIVE': False,
    'ARJUN_DISABLE_REDIRECTS': False,
    'ARJUN_CUSTOM_HEADERS': [],

    # Kiterunner API Discovery
    'KITERUNNER_ENABLED': False,
    'KITERUNNER_WORDLISTS': ['routes-large'],
    'KITERUNNER_RATE_LIMIT': 100,
    'KITERUNNER_CONNECTIONS': 100,
    'KITERUNNER_TIMEOUT': 10,
    'KITERUNNER_SCAN_TIMEOUT': 1000,
    'KITERUNNER_THREADS': 50,
    'KITERUNNER_IGNORE_STATUS': [],
    'KITERUNNER_MIN_CONTENT_LENGTH': 0,
    'KITERUNNER_MATCH_STATUS': [200, 201, 204, 301, 302, 401, 403, 405],
    'KITERUNNER_HEADERS': [],
    'KITERUNNER_DETECT_METHODS': True,
    'KITERUNNER_METHOD_DETECTION_MODE': 'bruteforce',
    'KITERUNNER_BRUTEFORCE_METHODS': ['POST', 'PUT', 'DELETE', 'PATCH'],
    'KITERUNNER_METHOD_DETECT_TIMEOUT': 5,
    'KITERUNNER_METHOD_DETECT_RATE_LIMIT': 50,
    'KITERUNNER_METHOD_DETECT_THREADS': 25,
    'KITERUNNER_PARALLELISM': 3,

    # CVE Lookup
    'CVE_LOOKUP_ENABLED': True,
    'CVE_LOOKUP_SOURCE': 'nvd',
    'CVE_LOOKUP_MAX_CVES': 20,
    'CVE_LOOKUP_MIN_CVSS': 0.0,
    'VULNERS_API_KEY': '',
    'NVD_API_KEY': '',  # Configured in Global Settings → Tool API Keys

    # MITRE CWE/CAPEC Enrichment
    'MITRE_ENABLED': True,
    'MITRE_AUTO_UPDATE_DB': True,
    'MITRE_INCLUDE_CWE': True,
    'MITRE_INCLUDE_CAPEC': True,
    'MITRE_ENRICH_RECON': True,
    'MITRE_ENRICH_GVM': True,
    'MITRE_CACHE_TTL_HOURS': 24,

    # Security Checks
    'SECURITY_CHECK_ENABLED': True,
    'SECURITY_CHECK_DIRECT_IP_HTTP': True,
    'SECURITY_CHECK_DIRECT_IP_HTTPS': True,
    'SECURITY_CHECK_IP_API_EXPOSED': True,
    'SECURITY_CHECK_WAF_BYPASS': True,
    'SECURITY_CHECK_TLS_EXPIRING_SOON': True,
    'SECURITY_CHECK_TLS_EXPIRY_DAYS': 30,
    'SECURITY_CHECK_MISSING_REFERRER_POLICY': True,
    'SECURITY_CHECK_MISSING_PERMISSIONS_POLICY': True,
    'SECURITY_CHECK_MISSING_COOP': True,
    'SECURITY_CHECK_MISSING_CORP': True,
    'SECURITY_CHECK_MISSING_COEP': True,
    'SECURITY_CHECK_CACHE_CONTROL_MISSING': True,
    'SECURITY_CHECK_LOGIN_NO_HTTPS': True,
    'SECURITY_CHECK_SESSION_NO_SECURE': True,
    'SECURITY_CHECK_SESSION_NO_HTTPONLY': True,
    'SECURITY_CHECK_BASIC_AUTH_NO_TLS': True,
    'SECURITY_CHECK_SPF_MISSING': True,
    'SECURITY_CHECK_DMARC_MISSING': True,
    'SECURITY_CHECK_DNSSEC_MISSING': True,
    'SECURITY_CHECK_ZONE_TRANSFER': True,
    'SECURITY_CHECK_ADMIN_PORT_EXPOSED': True,
    'SECURITY_CHECK_DATABASE_EXPOSED': True,
    'SECURITY_CHECK_REDIS_NO_AUTH': True,
    'SECURITY_CHECK_KUBERNETES_API_EXPOSED': True,
    'SECURITY_CHECK_SMTP_OPEN_RELAY': True,
    'SECURITY_CHECK_CSP_UNSAFE_INLINE': True,
    'SECURITY_CHECK_INSECURE_FORM_ACTION': True,
    'SECURITY_CHECK_NO_RATE_LIMITING': True,
    'SECURITY_CHECK_TIMEOUT': 10,
    'SECURITY_CHECK_MAX_WORKERS': 10,

    # Shodan Pipeline Enrichment
    'SHODAN_ENABLED': True,
    'SHODAN_HOST_LOOKUP': True,
    'SHODAN_REVERSE_DNS': True,
    'SHODAN_DOMAIN_DNS': False,
    'SHODAN_PASSIVE_CVES': True,
    'SHODAN_WORKERS': 5,
    'SHODAN_API_KEY': '',
    'URLSCAN_API_KEY': '',

    # URLScan.io Passive Enrichment
    'URLSCAN_ENABLED': True,
    'URLSCAN_MAX_RESULTS': 5000,

    # OSINT & Threat Intelligence Enrichment
    'OSINT_ENRICHMENT_ENABLED': False,
    'CENSYS_ENABLED': False,
    'CENSYS_API_TOKEN': '',
    'CENSYS_ORG_ID': '',
    'FOFA_ENABLED': False,
    'FOFA_MAX_RESULTS': 1000,
    'FOFA_API_KEY': '',
    'OTX_ENABLED': True,
    'OTX_API_KEY': '',
    'NETLAS_ENABLED': False,
    'NETLAS_MAX_RESULTS': 1000,
    'NETLAS_API_KEY': '',
    'VIRUSTOTAL_ENABLED': False,
    'VIRUSTOTAL_API_KEY': '',
    'VIRUSTOTAL_RATE_LIMIT': 4,
    'VIRUSTOTAL_MAX_TARGETS': 20,
    'ZOOMEYE_ENABLED': False,
    'ZOOMEYE_MAX_RESULTS': 1000,
    'ZOOMEYE_API_KEY': '',
    'CRIMINALIP_ENABLED': False,
    'CRIMINALIP_API_KEY': '',
    # OSINT Enrichment Parallelism
    'OTX_WORKERS': 5,
    'VIRUSTOTAL_WORKERS': 3,
    'CENSYS_WORKERS': 5,
    'CRIMINALIP_WORKERS': 5,
    'FOFA_WORKERS': 5,
    'NETLAS_WORKERS': 5,
    'ZOOMEYE_WORKERS': 5,

    # Uncover (ProjectDiscovery multi-engine search)
    'UNCOVER_ENABLED': False,
    'UNCOVER_MAX_RESULTS': 500,
    'UNCOVER_DOCKER_IMAGE': 'projectdiscovery/uncover:latest',
    'UNCOVER_QUAKE_API_KEY': '',
    'UNCOVER_HUNTER_API_KEY': '',
    'UNCOVER_PUBLICWWW_API_KEY': '',
    'UNCOVER_HUNTERHOW_API_KEY': '',
    'UNCOVER_GOOGLE_API_KEY': '',
    'UNCOVER_GOOGLE_API_CX': '',
    'UNCOVER_ONYPHE_API_KEY': '',
    'UNCOVER_DRIFTNET_API_KEY': '',

    # Subdomain Discovery
    'SUBDOMAIN_DISCOVERY_ENABLED': True,

    # Subdomain Discovery Tool Toggles
    'CRTSH_ENABLED': True,
    'CRTSH_MAX_RESULTS': 5000,
    'HACKERTARGET_ENABLED': True,
    'HACKERTARGET_MAX_RESULTS': 5000,
    'KNOCKPY_RECON_ENABLED': True,
    'KNOCKPY_RECON_MAX_RESULTS': 5000,
    'SUBFINDER_ENABLED': True,
    'SUBFINDER_MAX_RESULTS': 5000,
    'SUBFINDER_DOCKER_IMAGE': 'projectdiscovery/subfinder:latest',

    # Amass (OWASP subdomain enumeration)
    'AMASS_ENABLED': True,
    'AMASS_MAX_RESULTS': 5000,
    'AMASS_TIMEOUT': 10,
    'AMASS_ACTIVE': True,
    'AMASS_BRUTE': False,
    'AMASS_BRUTE_WORDLISTS': ['default'],
    'AMASS_DOCKER_IMAGE': 'caffix/amass:latest',

    # Puredns (wildcard filtering — runs after discovery, before DNS resolution)
    'PUREDNS_ENABLED': True,
    'PUREDNS_DOCKER_IMAGE': 'frost19k/puredns:latest',
    'PUREDNS_THREADS': 0,          # 0 = auto-detect
    'PUREDNS_RATE_LIMIT': 0,       # 0 = unlimited
    'PUREDNS_WILDCARD_BATCH': 0,   # 0 = default batch size
    'PUREDNS_SKIP_VALIDATION': False,

    # Rules of Engagement (recon-relevant fields only)
    'ROE_ENABLED': False,
    'ROE_EXCLUDED_HOSTS': [],
    'ROE_TIME_WINDOW_ENABLED': False,
    'ROE_TIME_WINDOW_TIMEZONE': 'UTC',
    'ROE_TIME_WINDOW_DAYS': ['monday', 'tuesday', 'wednesday', 'thursday', 'friday'],
    'ROE_TIME_WINDOW_START_TIME': '09:00',
    'ROE_TIME_WINDOW_END_TIME': '18:00',
    'ROE_GLOBAL_MAX_RPS': 0,

    # GraphQL Security Testing
    'GRAPHQL_SECURITY_ENABLED': False,
    'GRAPHQL_INTROSPECTION_TEST': True,
    'GRAPHQL_TIMEOUT': 30,
    'GRAPHQL_RATE_LIMIT': 10,
    'GRAPHQL_CONCURRENCY': 5,
    'GRAPHQL_AUTH_TYPE': '',
    'GRAPHQL_AUTH_VALUE': '',
    'GRAPHQL_AUTH_HEADER': '',
    'GRAPHQL_ENDPOINTS': '',
    'GRAPHQL_DEPTH_LIMIT': 10,
    'GRAPHQL_RETRY_COUNT': 3,
    'GRAPHQL_RETRY_BACKOFF': 2.0,
    'GRAPHQL_VERIFY_SSL': True,  # Enable SSL verification by default

    # GraphQL Cop (external Docker-based misconfig scanner -- Phase 2 §17)
    'GRAPHQL_COP_ENABLED': False,                   # Master toggle (opt-in)
    'GRAPHQL_COP_DOCKER_IMAGE': 'dolevf/graphql-cop:1.14',
    'GRAPHQL_COP_TIMEOUT': 120,                     # Seconds per endpoint
    'GRAPHQL_COP_FORCE_SCAN': False,                # -f flag: scan even if endpoint isn't GraphQL-like
    'GRAPHQL_COP_DEBUG': False,                     # -d flag: X-GraphQL-Cop-Test header per request
    # Per-test toggles (True = run, False = exclude via -e)
    'GRAPHQL_COP_TEST_FIELD_SUGGESTIONS': True,
    'GRAPHQL_COP_TEST_INTROSPECTION': False,        # Off by default -- PR's native check covers this
    'GRAPHQL_COP_TEST_GRAPHIQL': True,
    'GRAPHQL_COP_TEST_GET_METHOD': True,
    'GRAPHQL_COP_TEST_ALIAS_OVERLOADING': True,     # DoS (disabled in stealth mode)
    'GRAPHQL_COP_TEST_BATCH_QUERY': True,           # DoS
    'GRAPHQL_COP_TEST_TRACE_MODE': True,
    'GRAPHQL_COP_TEST_DIRECTIVE_OVERLOADING': True, # DoS
    'GRAPHQL_COP_TEST_CIRCULAR_INTROSPECTION': True,# DoS
    'GRAPHQL_COP_TEST_GET_MUTATION': True,
    'GRAPHQL_COP_TEST_POST_CSRF': True,
    'GRAPHQL_COP_TEST_UNHANDLED_ERROR': True,
}


def _fetch_user_api_key(user_id: str, webapp_url: str, key_name: str) -> str:
    """Fetch an unmasked API key from user's global settings."""
    import requests as _req
    try:
        url = f"{webapp_url.rstrip('/')}/api/users/{user_id}/settings?internal=true"
        _headers = {"X-Internal-Key": os.environ.get("INTERNAL_API_KEY", "")}
        resp = _req.get(url, timeout=10, headers=_headers)
        resp.raise_for_status()
        return resp.json().get(key_name, '')
    except Exception as e:
        logger.warning(f"Could not fetch {key_name}: {e}")
        return ''


def _fetch_user_settings_full(user_id: str, webapp_url: str) -> dict:
    """Fetch all unmasked user settings including rotation configs."""
    import requests as _req
    try:
        url = f"{webapp_url.rstrip('/')}/api/users/{user_id}/settings?internal=true"
        _headers = {"X-Internal-Key": os.environ.get("INTERNAL_API_KEY", "")}
        resp = _req.get(url, timeout=10, headers=_headers)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        logger.warning(f"Could not fetch user settings: {e}")
        return {}


def _fetch_shodan_api_key(user_id: str, webapp_url: str) -> str:
    """Fetch the unmasked Shodan API key from user's global settings."""
    return _fetch_user_api_key(user_id, webapp_url, 'shodanApiKey')


def _fetch_urlscan_api_key(user_id: str, webapp_url: str) -> str:
    """Fetch the unmasked URLScan API key from user's global settings."""
    return _fetch_user_api_key(user_id, webapp_url, 'urlscanApiKey')


def fetch_project_settings(project_id: str, webapp_url: str) -> dict[str, Any]:
    """
    Fetch project settings from webapp API.

    Args:
        project_id: The project ID to fetch settings for
        webapp_url: Base URL of the webapp API (e.g., http://localhost:3000)

    Returns:
        Dictionary of settings in SCREAMING_SNAKE_CASE format
    """
    import requests

    url = f"{webapp_url.rstrip('/')}/api/projects/{project_id}"
    logger.info(f"Fetching project settings from {url}")

    _internal_headers = {"X-Internal-Key": os.environ.get("INTERNAL_API_KEY", "")}
    response = requests.get(url, timeout=30, headers=_internal_headers)
    response.raise_for_status()
    project = response.json()

    # Start with defaults, then override with API values
    settings = DEFAULT_SETTINGS.copy()

    # Core identifiers
    settings['PROJECT_ID'] = project_id
    settings['USER_ID'] = project.get('userId', DEFAULT_SETTINGS['USER_ID'])

    # Target Configuration
    settings['TARGET_DOMAIN'] = project.get('targetDomain', DEFAULT_SETTINGS['TARGET_DOMAIN']).strip()
    raw_subs = project.get('subdomainList', DEFAULT_SETTINGS['SUBDOMAIN_LIST'])
    settings['SUBDOMAIN_LIST'] = [s.strip() for s in raw_subs if s.strip()]
    settings['IP_MODE'] = project.get('ipMode', DEFAULT_SETTINGS['IP_MODE'])
    raw_ips = project.get('targetIps', DEFAULT_SETTINGS['TARGET_IPS'])
    settings['TARGET_IPS'] = [ip.strip() for ip in raw_ips if ip.strip()]
    settings['VERIFY_DOMAIN_OWNERSHIP'] = project.get('verifyDomainOwnership', DEFAULT_SETTINGS['VERIFY_DOMAIN_OWNERSHIP'])
    settings['OWNERSHIP_TOKEN'] = project.get('ownershipToken', DEFAULT_SETTINGS['OWNERSHIP_TOKEN'])
    settings['OWNERSHIP_TXT_PREFIX'] = project.get('ownershipTxtPrefix', DEFAULT_SETTINGS['OWNERSHIP_TXT_PREFIX'])

    # Scan Modules
    settings['SCAN_MODULES'] = project.get('scanModules', DEFAULT_SETTINGS['SCAN_MODULES'])
    settings['UPDATE_GRAPH_DB'] = project.get('updateGraphDb', DEFAULT_SETTINGS['UPDATE_GRAPH_DB'])
    settings['USE_TOR_FOR_RECON'] = project.get('useTorForRecon', DEFAULT_SETTINGS['USE_TOR_FOR_RECON'])
    settings['USE_BRUTEFORCE_FOR_SUBDOMAINS'] = project.get('useBruteforceForSubdomains', DEFAULT_SETTINGS['USE_BRUTEFORCE_FOR_SUBDOMAINS'])
    settings['STEALTH_MODE'] = project.get('stealthMode', DEFAULT_SETTINGS['STEALTH_MODE'])

    # WHOIS/DNS
    settings['WHOIS_ENABLED'] = project.get('whoisEnabled', DEFAULT_SETTINGS['WHOIS_ENABLED'])
    settings['WHOIS_MAX_RETRIES'] = project.get('whoisMaxRetries', DEFAULT_SETTINGS['WHOIS_MAX_RETRIES'])
    settings['DNS_ENABLED'] = project.get('dnsEnabled', DEFAULT_SETTINGS['DNS_ENABLED'])
    settings['DNS_MAX_RETRIES'] = project.get('dnsMaxRetries', DEFAULT_SETTINGS['DNS_MAX_RETRIES'])
    settings['DNS_MAX_WORKERS'] = project.get('dnsMaxWorkers', DEFAULT_SETTINGS['DNS_MAX_WORKERS'])
    settings['DNS_RECORD_PARALLELISM'] = project.get('dnsRecordParallelism', DEFAULT_SETTINGS['DNS_RECORD_PARALLELISM'])

    # Naabu Port Scanner
    settings['NAABU_ENABLED'] = project.get('naabuEnabled', DEFAULT_SETTINGS['NAABU_ENABLED'])
    settings['NAABU_DOCKER_IMAGE'] = project.get('naabuDockerImage', DEFAULT_SETTINGS['NAABU_DOCKER_IMAGE'])
    settings['NAABU_TOP_PORTS'] = project.get('naabuTopPorts', DEFAULT_SETTINGS['NAABU_TOP_PORTS'])
    settings['NAABU_CUSTOM_PORTS'] = project.get('naabuCustomPorts', DEFAULT_SETTINGS['NAABU_CUSTOM_PORTS'])
    settings['NAABU_RATE_LIMIT'] = project.get('naabuRateLimit', DEFAULT_SETTINGS['NAABU_RATE_LIMIT'])
    settings['NAABU_THREADS'] = project.get('naabuThreads', DEFAULT_SETTINGS['NAABU_THREADS'])
    settings['NAABU_TIMEOUT'] = project.get('naabuTimeout', DEFAULT_SETTINGS['NAABU_TIMEOUT'])
    settings['NAABU_RETRIES'] = project.get('naabuRetries', DEFAULT_SETTINGS['NAABU_RETRIES'])
    settings['NAABU_SCAN_TYPE'] = project.get('naabuScanType', DEFAULT_SETTINGS['NAABU_SCAN_TYPE'])
    settings['NAABU_EXCLUDE_CDN'] = project.get('naabuExcludeCdn', DEFAULT_SETTINGS['NAABU_EXCLUDE_CDN'])
    settings['NAABU_DISPLAY_CDN'] = project.get('naabuDisplayCdn', DEFAULT_SETTINGS['NAABU_DISPLAY_CDN'])
    settings['NAABU_SKIP_HOST_DISCOVERY'] = project.get('naabuSkipHostDiscovery', DEFAULT_SETTINGS['NAABU_SKIP_HOST_DISCOVERY'])
    settings['NAABU_VERIFY_PORTS'] = project.get('naabuVerifyPorts', DEFAULT_SETTINGS['NAABU_VERIFY_PORTS'])
    settings['NAABU_PASSIVE_MODE'] = project.get('naabuPassiveMode', DEFAULT_SETTINGS['NAABU_PASSIVE_MODE'])

    # Masscan Port Scanner
    settings['MASSCAN_ENABLED'] = project.get('masscanEnabled', DEFAULT_SETTINGS['MASSCAN_ENABLED'])
    settings['MASSCAN_TOP_PORTS'] = project.get('masscanTopPorts', DEFAULT_SETTINGS['MASSCAN_TOP_PORTS'])
    settings['MASSCAN_CUSTOM_PORTS'] = project.get('masscanCustomPorts', DEFAULT_SETTINGS['MASSCAN_CUSTOM_PORTS'])
    settings['MASSCAN_RATE'] = project.get('masscanRate', DEFAULT_SETTINGS['MASSCAN_RATE'])
    settings['MASSCAN_BANNERS'] = project.get('masscanBanners', DEFAULT_SETTINGS['MASSCAN_BANNERS'])
    settings['MASSCAN_WAIT'] = project.get('masscanWait', DEFAULT_SETTINGS['MASSCAN_WAIT'])
    settings['MASSCAN_RETRIES'] = project.get('masscanRetries', DEFAULT_SETTINGS['MASSCAN_RETRIES'])
    settings['MASSCAN_EXCLUDE_TARGETS'] = project.get('masscanExcludeTargets', DEFAULT_SETTINGS['MASSCAN_EXCLUDE_TARGETS'])

    # Nmap Service Detection & NSE Vuln Scripts
    settings['NMAP_ENABLED'] = project.get('nmapEnabled', DEFAULT_SETTINGS['NMAP_ENABLED'])
    settings['NMAP_VERSION_DETECTION'] = project.get('nmapVersionDetection', DEFAULT_SETTINGS['NMAP_VERSION_DETECTION'])
    settings['NMAP_SCRIPT_SCAN'] = project.get('nmapScriptScan', DEFAULT_SETTINGS['NMAP_SCRIPT_SCAN'])
    settings['NMAP_TIMING_TEMPLATE'] = project.get('nmapTimingTemplate', DEFAULT_SETTINGS['NMAP_TIMING_TEMPLATE'])
    settings['NMAP_TIMEOUT'] = project.get('nmapTimeout', DEFAULT_SETTINGS['NMAP_TIMEOUT'])
    settings['NMAP_HOST_TIMEOUT'] = project.get('nmapHostTimeout', DEFAULT_SETTINGS['NMAP_HOST_TIMEOUT'])
    settings['NMAP_PARALLELISM'] = project.get('nmapParallelism', DEFAULT_SETTINGS['NMAP_PARALLELISM'])

    # httpx HTTP Probing
    settings['HTTPX_ENABLED'] = project.get('httpxEnabled', DEFAULT_SETTINGS['HTTPX_ENABLED'])
    settings['HTTPX_DOCKER_IMAGE'] = project.get('httpxDockerImage', DEFAULT_SETTINGS['HTTPX_DOCKER_IMAGE'])
    settings['HTTPX_THREADS'] = project.get('httpxThreads', DEFAULT_SETTINGS['HTTPX_THREADS'])
    settings['HTTPX_TIMEOUT'] = project.get('httpxTimeout', DEFAULT_SETTINGS['HTTPX_TIMEOUT'])
    settings['HTTPX_RETRIES'] = project.get('httpxRetries', DEFAULT_SETTINGS['HTTPX_RETRIES'])
    settings['HTTPX_RATE_LIMIT'] = project.get('httpxRateLimit', DEFAULT_SETTINGS['HTTPX_RATE_LIMIT'])
    settings['HTTPX_FOLLOW_REDIRECTS'] = project.get('httpxFollowRedirects', DEFAULT_SETTINGS['HTTPX_FOLLOW_REDIRECTS'])
    settings['HTTPX_MAX_REDIRECTS'] = project.get('httpxMaxRedirects', DEFAULT_SETTINGS['HTTPX_MAX_REDIRECTS'])
    settings['HTTPX_PROBE_STATUS_CODE'] = project.get('httpxProbeStatusCode', DEFAULT_SETTINGS['HTTPX_PROBE_STATUS_CODE'])
    settings['HTTPX_PROBE_CONTENT_LENGTH'] = project.get('httpxProbeContentLength', DEFAULT_SETTINGS['HTTPX_PROBE_CONTENT_LENGTH'])
    settings['HTTPX_PROBE_CONTENT_TYPE'] = project.get('httpxProbeContentType', DEFAULT_SETTINGS['HTTPX_PROBE_CONTENT_TYPE'])
    settings['HTTPX_PROBE_TITLE'] = project.get('httpxProbeTitle', DEFAULT_SETTINGS['HTTPX_PROBE_TITLE'])
    settings['HTTPX_PROBE_SERVER'] = project.get('httpxProbeServer', DEFAULT_SETTINGS['HTTPX_PROBE_SERVER'])
    settings['HTTPX_PROBE_RESPONSE_TIME'] = project.get('httpxProbeResponseTime', DEFAULT_SETTINGS['HTTPX_PROBE_RESPONSE_TIME'])
    settings['HTTPX_PROBE_WORD_COUNT'] = project.get('httpxProbeWordCount', DEFAULT_SETTINGS['HTTPX_PROBE_WORD_COUNT'])
    settings['HTTPX_PROBE_LINE_COUNT'] = project.get('httpxProbeLineCount', DEFAULT_SETTINGS['HTTPX_PROBE_LINE_COUNT'])
    settings['HTTPX_PROBE_TECH_DETECT'] = project.get('httpxProbeTechDetect', DEFAULT_SETTINGS['HTTPX_PROBE_TECH_DETECT'])
    settings['HTTPX_PROBE_IP'] = project.get('httpxProbeIp', DEFAULT_SETTINGS['HTTPX_PROBE_IP'])
    settings['HTTPX_PROBE_CNAME'] = project.get('httpxProbeCname', DEFAULT_SETTINGS['HTTPX_PROBE_CNAME'])
    settings['HTTPX_PROBE_TLS_INFO'] = project.get('httpxProbeTlsInfo', DEFAULT_SETTINGS['HTTPX_PROBE_TLS_INFO'])
    settings['HTTPX_PROBE_TLS_GRAB'] = project.get('httpxProbeTlsGrab', DEFAULT_SETTINGS['HTTPX_PROBE_TLS_GRAB'])
    settings['HTTPX_PROBE_FAVICON'] = project.get('httpxProbeFavicon', DEFAULT_SETTINGS['HTTPX_PROBE_FAVICON'])
    settings['HTTPX_PROBE_JARM'] = project.get('httpxProbeJarm', DEFAULT_SETTINGS['HTTPX_PROBE_JARM'])
    settings['HTTPX_PROBE_HASH'] = project.get('httpxProbeHash', DEFAULT_SETTINGS['HTTPX_PROBE_HASH'])
    settings['HTTPX_INCLUDE_RESPONSE'] = project.get('httpxIncludeResponse', DEFAULT_SETTINGS['HTTPX_INCLUDE_RESPONSE'])
    settings['HTTPX_INCLUDE_RESPONSE_HEADERS'] = project.get('httpxIncludeResponseHeaders', DEFAULT_SETTINGS['HTTPX_INCLUDE_RESPONSE_HEADERS'])
    settings['HTTPX_PROBE_ASN'] = project.get('httpxProbeAsn', DEFAULT_SETTINGS['HTTPX_PROBE_ASN'])
    settings['HTTPX_PROBE_CDN'] = project.get('httpxProbeCdn', DEFAULT_SETTINGS['HTTPX_PROBE_CDN'])
    settings['HTTPX_PATHS'] = project.get('httpxPaths', DEFAULT_SETTINGS['HTTPX_PATHS'])
    settings['HTTPX_CUSTOM_HEADERS'] = project.get('httpxCustomHeaders', DEFAULT_SETTINGS['HTTPX_CUSTOM_HEADERS'])
    settings['HTTPX_MATCH_CODES'] = project.get('httpxMatchCodes', DEFAULT_SETTINGS['HTTPX_MATCH_CODES'])
    settings['HTTPX_FILTER_CODES'] = project.get('httpxFilterCodes', DEFAULT_SETTINGS['HTTPX_FILTER_CODES'])

    # Wappalyzer
    settings['WAPPALYZER_ENABLED'] = project.get('wappalyzerEnabled', DEFAULT_SETTINGS['WAPPALYZER_ENABLED'])
    settings['WAPPALYZER_MIN_CONFIDENCE'] = project.get('wappalyzerMinConfidence', DEFAULT_SETTINGS['WAPPALYZER_MIN_CONFIDENCE'])
    settings['WAPPALYZER_REQUIRE_HTML'] = project.get('wappalyzerRequireHtml', DEFAULT_SETTINGS['WAPPALYZER_REQUIRE_HTML'])
    settings['WAPPALYZER_AUTO_UPDATE'] = project.get('wappalyzerAutoUpdate', DEFAULT_SETTINGS['WAPPALYZER_AUTO_UPDATE'])
    settings['WAPPALYZER_NPM_VERSION'] = project.get('wappalyzerNpmVersion', DEFAULT_SETTINGS['WAPPALYZER_NPM_VERSION'])
    settings['WAPPALYZER_CACHE_TTL_HOURS'] = project.get('wappalyzerCacheTtlHours', DEFAULT_SETTINGS['WAPPALYZER_CACHE_TTL_HOURS'])

    # Banner Grabbing
    settings['BANNER_GRAB_ENABLED'] = project.get('bannerGrabEnabled', DEFAULT_SETTINGS['BANNER_GRAB_ENABLED'])
    settings['BANNER_GRAB_TIMEOUT'] = project.get('bannerGrabTimeout', DEFAULT_SETTINGS['BANNER_GRAB_TIMEOUT'])
    settings['BANNER_GRAB_THREADS'] = project.get('bannerGrabThreads', DEFAULT_SETTINGS['BANNER_GRAB_THREADS'])
    settings['BANNER_GRAB_MAX_LENGTH'] = project.get('bannerGrabMaxLength', DEFAULT_SETTINGS['BANNER_GRAB_MAX_LENGTH'])

    # Nuclei Vulnerability Scanner
    settings['NUCLEI_ENABLED'] = project.get('nucleiEnabled', DEFAULT_SETTINGS['NUCLEI_ENABLED'])
    settings['NUCLEI_SEVERITY'] = project.get('nucleiSeverity', DEFAULT_SETTINGS['NUCLEI_SEVERITY'])
    settings['NUCLEI_TEMPLATES'] = project.get('nucleiTemplates', DEFAULT_SETTINGS['NUCLEI_TEMPLATES'])
    settings['NUCLEI_EXCLUDE_TEMPLATES'] = project.get('nucleiExcludeTemplates', DEFAULT_SETTINGS['NUCLEI_EXCLUDE_TEMPLATES'])
    settings['NUCLEI_CUSTOM_TEMPLATES'] = project.get('nucleiCustomTemplates', DEFAULT_SETTINGS['NUCLEI_CUSTOM_TEMPLATES'])
    settings['NUCLEI_SELECTED_CUSTOM_TEMPLATES'] = project.get('nucleiSelectedCustomTemplates', DEFAULT_SETTINGS['NUCLEI_SELECTED_CUSTOM_TEMPLATES'])
    settings['NUCLEI_RATE_LIMIT'] = project.get('nucleiRateLimit', DEFAULT_SETTINGS['NUCLEI_RATE_LIMIT'])
    settings['NUCLEI_BULK_SIZE'] = project.get('nucleiBulkSize', DEFAULT_SETTINGS['NUCLEI_BULK_SIZE'])
    settings['NUCLEI_CONCURRENCY'] = project.get('nucleiConcurrency', DEFAULT_SETTINGS['NUCLEI_CONCURRENCY'])
    settings['NUCLEI_TIMEOUT'] = project.get('nucleiTimeout', DEFAULT_SETTINGS['NUCLEI_TIMEOUT'])
    settings['NUCLEI_RETRIES'] = project.get('nucleiRetries', DEFAULT_SETTINGS['NUCLEI_RETRIES'])
    settings['NUCLEI_TAGS'] = project.get('nucleiTags', DEFAULT_SETTINGS['NUCLEI_TAGS'])
    settings['NUCLEI_EXCLUDE_TAGS'] = project.get('nucleiExcludeTags', DEFAULT_SETTINGS['NUCLEI_EXCLUDE_TAGS'])
    settings['NUCLEI_DAST_MODE'] = project.get('nucleiDastMode', DEFAULT_SETTINGS['NUCLEI_DAST_MODE'])
    settings['NUCLEI_AUTO_UPDATE_TEMPLATES'] = project.get('nucleiAutoUpdateTemplates', DEFAULT_SETTINGS['NUCLEI_AUTO_UPDATE_TEMPLATES'])
    settings['NUCLEI_NEW_TEMPLATES_ONLY'] = project.get('nucleiNewTemplatesOnly', DEFAULT_SETTINGS['NUCLEI_NEW_TEMPLATES_ONLY'])
    settings['NUCLEI_HEADLESS'] = project.get('nucleiHeadless', DEFAULT_SETTINGS['NUCLEI_HEADLESS'])
    settings['NUCLEI_SYSTEM_RESOLVERS'] = project.get('nucleiSystemResolvers', DEFAULT_SETTINGS['NUCLEI_SYSTEM_RESOLVERS'])
    settings['NUCLEI_FOLLOW_REDIRECTS'] = project.get('nucleiFollowRedirects', DEFAULT_SETTINGS['NUCLEI_FOLLOW_REDIRECTS'])
    settings['NUCLEI_MAX_REDIRECTS'] = project.get('nucleiMaxRedirects', DEFAULT_SETTINGS['NUCLEI_MAX_REDIRECTS'])
    settings['NUCLEI_SCAN_ALL_IPS'] = project.get('nucleiScanAllIps', DEFAULT_SETTINGS['NUCLEI_SCAN_ALL_IPS'])
    settings['NUCLEI_INTERACTSH'] = project.get('nucleiInteractsh', DEFAULT_SETTINGS['NUCLEI_INTERACTSH'])
    settings['NUCLEI_DOCKER_IMAGE'] = project.get('nucleiDockerImage', DEFAULT_SETTINGS['NUCLEI_DOCKER_IMAGE'])

    # Subdomain Takeover Scanner
    settings['SUBDOMAIN_TAKEOVER_ENABLED'] = project.get('subdomainTakeoverEnabled', DEFAULT_SETTINGS['SUBDOMAIN_TAKEOVER_ENABLED'])
    settings['SUBJACK_ENABLED'] = project.get('subjackEnabled', DEFAULT_SETTINGS['SUBJACK_ENABLED'])
    settings['SUBJACK_THREADS'] = project.get('subjackThreads', DEFAULT_SETTINGS['SUBJACK_THREADS'])
    settings['SUBJACK_TIMEOUT'] = project.get('subjackTimeout', DEFAULT_SETTINGS['SUBJACK_TIMEOUT'])
    settings['SUBJACK_SSL'] = project.get('subjackSsl', DEFAULT_SETTINGS['SUBJACK_SSL'])
    settings['SUBJACK_ALL'] = project.get('subjackAll', DEFAULT_SETTINGS['SUBJACK_ALL'])
    settings['SUBJACK_CHECK_NS'] = project.get('subjackCheckNs', DEFAULT_SETTINGS['SUBJACK_CHECK_NS'])
    settings['SUBJACK_CHECK_AR'] = project.get('subjackCheckAr', DEFAULT_SETTINGS['SUBJACK_CHECK_AR'])
    settings['SUBJACK_CHECK_MAIL'] = project.get('subjackCheckMail', DEFAULT_SETTINGS['SUBJACK_CHECK_MAIL'])
    settings['SUBJACK_RUN_TIMEOUT'] = project.get('subjackRunTimeout', DEFAULT_SETTINGS['SUBJACK_RUN_TIMEOUT'])
    settings['NUCLEI_TAKEOVERS_ENABLED'] = project.get('nucleiTakeoversEnabled', DEFAULT_SETTINGS['NUCLEI_TAKEOVERS_ENABLED'])
    settings['NUCLEI_TAKEOVER_RUN_TIMEOUT'] = project.get('nucleiTakeoverRunTimeout', DEFAULT_SETTINGS['NUCLEI_TAKEOVER_RUN_TIMEOUT'])
    settings['TAKEOVER_SEVERITY'] = project.get('takeoverSeverity', DEFAULT_SETTINGS['TAKEOVER_SEVERITY'])
    settings['TAKEOVER_CONFIDENCE_THRESHOLD'] = project.get('takeoverConfidenceThreshold', DEFAULT_SETTINGS['TAKEOVER_CONFIDENCE_THRESHOLD'])
    settings['TAKEOVER_RATE_LIMIT'] = project.get('takeoverRateLimit', DEFAULT_SETTINGS['TAKEOVER_RATE_LIMIT'])
    settings['TAKEOVER_MANUAL_REVIEW_AUTO_PUBLISH'] = project.get('takeoverManualReviewAutoPublish', DEFAULT_SETTINGS['TAKEOVER_MANUAL_REVIEW_AUTO_PUBLISH'])
    settings['BADDNS_ENABLED'] = project.get('baddnsEnabled', DEFAULT_SETTINGS['BADDNS_ENABLED'])
    settings['BADDNS_DOCKER_IMAGE'] = project.get('baddnsDockerImage', DEFAULT_SETTINGS['BADDNS_DOCKER_IMAGE'])
    settings['BADDNS_MODULES'] = project.get('baddnsModules', DEFAULT_SETTINGS['BADDNS_MODULES'])
    settings['BADDNS_NAMESERVERS'] = project.get('baddnsNameservers', DEFAULT_SETTINGS['BADDNS_NAMESERVERS'])
    settings['BADDNS_RUN_TIMEOUT'] = project.get('baddnsRunTimeout', DEFAULT_SETTINGS['BADDNS_RUN_TIMEOUT'])

    # Katana Web Crawler
    settings['KATANA_ENABLED'] = project.get('katanaEnabled', DEFAULT_SETTINGS['KATANA_ENABLED'])
    settings['KATANA_DOCKER_IMAGE'] = project.get('katanaDockerImage', DEFAULT_SETTINGS['KATANA_DOCKER_IMAGE'])
    settings['KATANA_DEPTH'] = project.get('katanaDepth', DEFAULT_SETTINGS['KATANA_DEPTH'])
    settings['KATANA_MAX_URLS'] = project.get('katanaMaxUrls', DEFAULT_SETTINGS['KATANA_MAX_URLS'])
    settings['KATANA_RATE_LIMIT'] = project.get('katanaRateLimit', DEFAULT_SETTINGS['KATANA_RATE_LIMIT'])
    settings['KATANA_TIMEOUT'] = project.get('katanaTimeout', DEFAULT_SETTINGS['KATANA_TIMEOUT'])
    settings['KATANA_JS_CRAWL'] = project.get('katanaJsCrawl', DEFAULT_SETTINGS['KATANA_JS_CRAWL'])
    settings['KATANA_PARAMS_ONLY'] = project.get('katanaParamsOnly', DEFAULT_SETTINGS['KATANA_PARAMS_ONLY'])
    settings['KATANA_EXCLUDE_PATTERNS'] = project.get('katanaExcludePatterns', DEFAULT_SETTINGS['KATANA_EXCLUDE_PATTERNS'])
    settings['KATANA_CUSTOM_HEADERS'] = project.get('katanaCustomHeaders', DEFAULT_SETTINGS['KATANA_CUSTOM_HEADERS'])
    settings['KATANA_PARALLELISM'] = project.get('katanaParallelism', DEFAULT_SETTINGS['KATANA_PARALLELISM'])
    settings['KATANA_CONCURRENCY'] = project.get('katanaConcurrency', DEFAULT_SETTINGS['KATANA_CONCURRENCY'])

    # Hakrawler Web Crawler
    settings['HAKRAWLER_ENABLED'] = project.get('hakrawlerEnabled', DEFAULT_SETTINGS['HAKRAWLER_ENABLED'])
    settings['HAKRAWLER_DOCKER_IMAGE'] = project.get('hakrawlerDockerImage', DEFAULT_SETTINGS['HAKRAWLER_DOCKER_IMAGE'])
    settings['HAKRAWLER_DEPTH'] = project.get('hakrawlerDepth', DEFAULT_SETTINGS['HAKRAWLER_DEPTH'])
    settings['HAKRAWLER_THREADS'] = project.get('hakrawlerThreads', DEFAULT_SETTINGS['HAKRAWLER_THREADS'])
    settings['HAKRAWLER_TIMEOUT'] = project.get('hakrawlerTimeout', DEFAULT_SETTINGS['HAKRAWLER_TIMEOUT'])
    settings['HAKRAWLER_MAX_URLS'] = project.get('hakrawlerMaxUrls', DEFAULT_SETTINGS['HAKRAWLER_MAX_URLS'])
    settings['HAKRAWLER_INCLUDE_SUBS'] = project.get('hakrawlerIncludeSubs', DEFAULT_SETTINGS['HAKRAWLER_INCLUDE_SUBS'])
    settings['HAKRAWLER_INSECURE'] = project.get('hakrawlerInsecure', DEFAULT_SETTINGS['HAKRAWLER_INSECURE'])
    settings['HAKRAWLER_CUSTOM_HEADERS'] = project.get('hakrawlerCustomHeaders', DEFAULT_SETTINGS['HAKRAWLER_CUSTOM_HEADERS'])
    settings['HAKRAWLER_PARALLELISM'] = project.get('hakrawlerParallelism', DEFAULT_SETTINGS['HAKRAWLER_PARALLELISM'])

    # jsluice JavaScript Analyzer
    settings['JSLUICE_ENABLED'] = project.get('jsluiceEnabled', DEFAULT_SETTINGS['JSLUICE_ENABLED'])
    settings['JSLUICE_MAX_FILES'] = project.get('jsluiceMaxFiles', DEFAULT_SETTINGS['JSLUICE_MAX_FILES'])
    settings['JSLUICE_TIMEOUT'] = project.get('jsluiceTimeout', DEFAULT_SETTINGS['JSLUICE_TIMEOUT'])
    settings['JSLUICE_EXTRACT_URLS'] = project.get('jsluiceExtractUrls', DEFAULT_SETTINGS['JSLUICE_EXTRACT_URLS'])
    settings['JSLUICE_EXTRACT_SECRETS'] = project.get('jsluiceExtractSecrets', DEFAULT_SETTINGS['JSLUICE_EXTRACT_SECRETS'])
    settings['JSLUICE_CONCURRENCY'] = project.get('jsluiceConcurrency', DEFAULT_SETTINGS['JSLUICE_CONCURRENCY'])
    settings['JSLUICE_PARALLELISM'] = project.get('jsluiceParallelism', DEFAULT_SETTINGS['JSLUICE_PARALLELISM'])

    # JS Recon Scanner
    settings['JS_RECON_ENABLED'] = project.get('jsReconEnabled', DEFAULT_SETTINGS['JS_RECON_ENABLED'])
    settings['JS_RECON_MAX_FILES'] = project.get('jsReconMaxFiles', DEFAULT_SETTINGS['JS_RECON_MAX_FILES'])
    settings['JS_RECON_TIMEOUT'] = project.get('jsReconTimeout', DEFAULT_SETTINGS['JS_RECON_TIMEOUT'])
    settings['JS_RECON_CONCURRENCY'] = project.get('jsReconConcurrency', DEFAULT_SETTINGS['JS_RECON_CONCURRENCY'])
    settings['JS_RECON_VALIDATE_KEYS'] = project.get('jsReconValidateKeys', DEFAULT_SETTINGS['JS_RECON_VALIDATE_KEYS'])
    settings['JS_RECON_VALIDATION_TIMEOUT'] = project.get('jsReconValidationTimeout', DEFAULT_SETTINGS['JS_RECON_VALIDATION_TIMEOUT'])
    settings['JS_RECON_EXTRACT_ENDPOINTS'] = project.get('jsReconExtractEndpoints', DEFAULT_SETTINGS['JS_RECON_EXTRACT_ENDPOINTS'])
    settings['JS_RECON_REGEX_PATTERNS'] = project.get('jsReconRegexPatterns', DEFAULT_SETTINGS['JS_RECON_REGEX_PATTERNS'])
    settings['JS_RECON_SOURCE_MAPS'] = project.get('jsReconSourceMaps', DEFAULT_SETTINGS['JS_RECON_SOURCE_MAPS'])
    settings['JS_RECON_DEPENDENCY_CHECK'] = project.get('jsReconDependencyCheck', DEFAULT_SETTINGS['JS_RECON_DEPENDENCY_CHECK'])
    settings['JS_RECON_DOM_SINKS'] = project.get('jsReconDomSinks', DEFAULT_SETTINGS['JS_RECON_DOM_SINKS'])
    settings['JS_RECON_FRAMEWORK_DETECT'] = project.get('jsReconFrameworkDetect', DEFAULT_SETTINGS['JS_RECON_FRAMEWORK_DETECT'])
    settings['JS_RECON_DEV_COMMENTS'] = project.get('jsReconDevComments', DEFAULT_SETTINGS['JS_RECON_DEV_COMMENTS'])
    settings['JS_RECON_INCLUDE_CHUNKS'] = project.get('jsReconIncludeChunks', DEFAULT_SETTINGS['JS_RECON_INCLUDE_CHUNKS'])
    settings['JS_RECON_INCLUDE_FRAMEWORK_JS'] = project.get('jsReconIncludeFrameworkJs', DEFAULT_SETTINGS['JS_RECON_INCLUDE_FRAMEWORK_JS'])
    settings['JS_RECON_INCLUDE_ARCHIVED_JS'] = project.get('jsReconIncludeArchivedJs', DEFAULT_SETTINGS['JS_RECON_INCLUDE_ARCHIVED_JS'])
    settings['JS_RECON_MIN_CONFIDENCE'] = project.get('jsReconMinConfidence', DEFAULT_SETTINGS['JS_RECON_MIN_CONFIDENCE'])
    settings['JS_RECON_STANDALONE_CRAWL_DEPTH'] = project.get('jsReconStandaloneCrawlDepth', DEFAULT_SETTINGS['JS_RECON_STANDALONE_CRAWL_DEPTH'])
    settings['JS_RECON_STANDALONE_CRAWL_SCOPE'] = project.get('jsReconStandaloneCrawlScope', DEFAULT_SETTINGS['JS_RECON_STANDALONE_CRAWL_SCOPE'])
    settings['JS_RECON_UPLOADED_FILES'] = project.get('jsReconUploadedFiles', DEFAULT_SETTINGS['JS_RECON_UPLOADED_FILES'])
    settings['JS_RECON_CUSTOM_PATTERNS'] = project.get('jsReconCustomPatterns', DEFAULT_SETTINGS['JS_RECON_CUSTOM_PATTERNS'])
    settings['JS_RECON_CUSTOM_SOURCEMAP_PATHS'] = project.get('jsReconCustomSourcemapPaths', DEFAULT_SETTINGS['JS_RECON_CUSTOM_SOURCEMAP_PATHS'])
    settings['JS_RECON_CUSTOM_PACKAGES'] = project.get('jsReconCustomPackages', DEFAULT_SETTINGS['JS_RECON_CUSTOM_PACKAGES'])
    settings['JS_RECON_CUSTOM_ENDPOINT_KEYWORDS'] = project.get('jsReconCustomEndpointKeywords', DEFAULT_SETTINGS['JS_RECON_CUSTOM_ENDPOINT_KEYWORDS'])
    settings['JS_RECON_CUSTOM_FRAMEWORKS'] = project.get('jsReconCustomFrameworks', DEFAULT_SETTINGS['JS_RECON_CUSTOM_FRAMEWORKS'])

    # FFuf Directory Fuzzer
    settings['FFUF_ENABLED'] = project.get('ffufEnabled', DEFAULT_SETTINGS['FFUF_ENABLED'])
    settings['FFUF_WORDLIST'] = project.get('ffufWordlist', DEFAULT_SETTINGS['FFUF_WORDLIST'])
    settings['FFUF_THREADS'] = project.get('ffufThreads', DEFAULT_SETTINGS['FFUF_THREADS'])
    settings['FFUF_RATE'] = project.get('ffufRate', DEFAULT_SETTINGS['FFUF_RATE'])
    settings['FFUF_TIMEOUT'] = project.get('ffufTimeout', DEFAULT_SETTINGS['FFUF_TIMEOUT'])
    settings['FFUF_MAX_TIME'] = project.get('ffufMaxTime', DEFAULT_SETTINGS['FFUF_MAX_TIME'])
    settings['FFUF_MATCH_CODES'] = project.get('ffufMatchCodes', DEFAULT_SETTINGS['FFUF_MATCH_CODES'])
    settings['FFUF_FILTER_CODES'] = project.get('ffufFilterCodes', DEFAULT_SETTINGS['FFUF_FILTER_CODES'])
    settings['FFUF_FILTER_SIZE'] = project.get('ffufFilterSize', DEFAULT_SETTINGS['FFUF_FILTER_SIZE'])
    settings['FFUF_EXTENSIONS'] = project.get('ffufExtensions', DEFAULT_SETTINGS['FFUF_EXTENSIONS'])
    settings['FFUF_RECURSION'] = project.get('ffufRecursion', DEFAULT_SETTINGS['FFUF_RECURSION'])
    settings['FFUF_RECURSION_DEPTH'] = project.get('ffufRecursionDepth', DEFAULT_SETTINGS['FFUF_RECURSION_DEPTH'])
    settings['FFUF_AUTO_CALIBRATE'] = project.get('ffufAutoCalibrate', DEFAULT_SETTINGS['FFUF_AUTO_CALIBRATE'])
    settings['FFUF_FOLLOW_REDIRECTS'] = project.get('ffufFollowRedirects', DEFAULT_SETTINGS['FFUF_FOLLOW_REDIRECTS'])
    settings['FFUF_CUSTOM_HEADERS'] = project.get('ffufCustomHeaders', DEFAULT_SETTINGS['FFUF_CUSTOM_HEADERS'])
    settings['FFUF_SMART_FUZZ'] = project.get('ffufSmartFuzz', DEFAULT_SETTINGS['FFUF_SMART_FUZZ'])
    settings['FFUF_PARALLELISM'] = project.get('ffufParallelism', DEFAULT_SETTINGS['FFUF_PARALLELISM'])

    # Arjun Parameter Discovery
    settings['ARJUN_ENABLED'] = project.get('arjunEnabled', DEFAULT_SETTINGS['ARJUN_ENABLED'])
    settings['ARJUN_THREADS'] = project.get('arjunThreads', DEFAULT_SETTINGS['ARJUN_THREADS'])
    settings['ARJUN_TIMEOUT'] = project.get('arjunTimeout', DEFAULT_SETTINGS['ARJUN_TIMEOUT'])
    settings['ARJUN_SCAN_TIMEOUT'] = project.get('arjunScanTimeout', DEFAULT_SETTINGS['ARJUN_SCAN_TIMEOUT'])
    settings['ARJUN_METHODS'] = project.get('arjunMethods', DEFAULT_SETTINGS['ARJUN_METHODS'])
    settings['ARJUN_MAX_ENDPOINTS'] = project.get('arjunMaxEndpoints', DEFAULT_SETTINGS['ARJUN_MAX_ENDPOINTS'])
    settings['ARJUN_CHUNK_SIZE'] = project.get('arjunChunkSize', DEFAULT_SETTINGS['ARJUN_CHUNK_SIZE'])
    settings['ARJUN_RATE_LIMIT'] = project.get('arjunRateLimit', DEFAULT_SETTINGS['ARJUN_RATE_LIMIT'])
    settings['ARJUN_STABLE'] = project.get('arjunStable', DEFAULT_SETTINGS['ARJUN_STABLE'])
    settings['ARJUN_PASSIVE'] = project.get('arjunPassive', DEFAULT_SETTINGS['ARJUN_PASSIVE'])
    settings['ARJUN_DISABLE_REDIRECTS'] = project.get('arjunDisableRedirects', DEFAULT_SETTINGS['ARJUN_DISABLE_REDIRECTS'])
    settings['ARJUN_CUSTOM_HEADERS'] = project.get('arjunCustomHeaders', DEFAULT_SETTINGS['ARJUN_CUSTOM_HEADERS'])

    # GAU Passive URL Discovery
    settings['GAU_ENABLED'] = project.get('gauEnabled', DEFAULT_SETTINGS['GAU_ENABLED'])
    settings['GAU_DOCKER_IMAGE'] = project.get('gauDockerImage', DEFAULT_SETTINGS['GAU_DOCKER_IMAGE'])
    settings['GAU_PROVIDERS'] = project.get('gauProviders', DEFAULT_SETTINGS['GAU_PROVIDERS'])
    settings['GAU_MAX_URLS'] = project.get('gauMaxUrls', DEFAULT_SETTINGS['GAU_MAX_URLS'])
    settings['GAU_TIMEOUT'] = project.get('gauTimeout', DEFAULT_SETTINGS['GAU_TIMEOUT'])
    settings['GAU_THREADS'] = project.get('gauThreads', DEFAULT_SETTINGS['GAU_THREADS'])
    settings['GAU_BLACKLIST_EXTENSIONS'] = project.get('gauBlacklistExtensions', DEFAULT_SETTINGS['GAU_BLACKLIST_EXTENSIONS'])
    settings['GAU_YEAR_RANGE'] = project.get('gauYearRange', DEFAULT_SETTINGS['GAU_YEAR_RANGE'])
    settings['GAU_VERBOSE'] = project.get('gauVerbose', DEFAULT_SETTINGS['GAU_VERBOSE'])
    settings['GAU_VERIFY_URLS'] = project.get('gauVerifyUrls', DEFAULT_SETTINGS['GAU_VERIFY_URLS'])
    settings['GAU_VERIFY_DOCKER_IMAGE'] = project.get('gauVerifyDockerImage', DEFAULT_SETTINGS['GAU_VERIFY_DOCKER_IMAGE'])
    settings['GAU_VERIFY_TIMEOUT'] = project.get('gauVerifyTimeout', DEFAULT_SETTINGS['GAU_VERIFY_TIMEOUT'])
    settings['GAU_VERIFY_RATE_LIMIT'] = project.get('gauVerifyRateLimit', DEFAULT_SETTINGS['GAU_VERIFY_RATE_LIMIT'])
    settings['GAU_VERIFY_THREADS'] = project.get('gauVerifyThreads', DEFAULT_SETTINGS['GAU_VERIFY_THREADS'])
    settings['GAU_VERIFY_ACCEPT_STATUS'] = project.get('gauVerifyAcceptStatus', DEFAULT_SETTINGS['GAU_VERIFY_ACCEPT_STATUS'])
    settings['GAU_DETECT_METHODS'] = project.get('gauDetectMethods', DEFAULT_SETTINGS['GAU_DETECT_METHODS'])
    settings['GAU_METHOD_DETECT_TIMEOUT'] = project.get('gauMethodDetectTimeout', DEFAULT_SETTINGS['GAU_METHOD_DETECT_TIMEOUT'])
    settings['GAU_METHOD_DETECT_RATE_LIMIT'] = project.get('gauMethodDetectRateLimit', DEFAULT_SETTINGS['GAU_METHOD_DETECT_RATE_LIMIT'])
    settings['GAU_METHOD_DETECT_THREADS'] = project.get('gauMethodDetectThreads', DEFAULT_SETTINGS['GAU_METHOD_DETECT_THREADS'])
    settings['GAU_FILTER_DEAD_ENDPOINTS'] = project.get('gauFilterDeadEndpoints', DEFAULT_SETTINGS['GAU_FILTER_DEAD_ENDPOINTS'])
    settings['GAU_WORKERS'] = project.get('gauWorkers', DEFAULT_SETTINGS['GAU_WORKERS'])

    # ParamSpider Passive Parameter Discovery
    settings['PARAMSPIDER_ENABLED'] = project.get('paramspiderEnabled', DEFAULT_SETTINGS['PARAMSPIDER_ENABLED'])
    settings['PARAMSPIDER_PLACEHOLDER'] = project.get('paramspiderPlaceholder', DEFAULT_SETTINGS['PARAMSPIDER_PLACEHOLDER'])
    settings['PARAMSPIDER_TIMEOUT'] = project.get('paramspiderTimeout', DEFAULT_SETTINGS['PARAMSPIDER_TIMEOUT'])
    settings['PARAMSPIDER_WORKERS'] = project.get('paramspiderWorkers', DEFAULT_SETTINGS['PARAMSPIDER_WORKERS'])

    # Kiterunner API Discovery
    settings['KITERUNNER_ENABLED'] = project.get('kiterunnerEnabled', DEFAULT_SETTINGS['KITERUNNER_ENABLED'])
    settings['KITERUNNER_WORDLISTS'] = project.get('kiterunnerWordlists', DEFAULT_SETTINGS['KITERUNNER_WORDLISTS'])
    settings['KITERUNNER_RATE_LIMIT'] = project.get('kiterunnerRateLimit', DEFAULT_SETTINGS['KITERUNNER_RATE_LIMIT'])
    settings['KITERUNNER_CONNECTIONS'] = project.get('kiterunnerConnections', DEFAULT_SETTINGS['KITERUNNER_CONNECTIONS'])
    settings['KITERUNNER_TIMEOUT'] = project.get('kiterunnerTimeout', DEFAULT_SETTINGS['KITERUNNER_TIMEOUT'])
    settings['KITERUNNER_SCAN_TIMEOUT'] = project.get('kiterunnerScanTimeout', DEFAULT_SETTINGS['KITERUNNER_SCAN_TIMEOUT'])
    settings['KITERUNNER_THREADS'] = project.get('kiterunnerThreads', DEFAULT_SETTINGS['KITERUNNER_THREADS'])
    settings['KITERUNNER_IGNORE_STATUS'] = project.get('kiterunnerIgnoreStatus', DEFAULT_SETTINGS['KITERUNNER_IGNORE_STATUS'])
    settings['KITERUNNER_MIN_CONTENT_LENGTH'] = project.get('kiterunnerMinContentLength', DEFAULT_SETTINGS['KITERUNNER_MIN_CONTENT_LENGTH'])
    settings['KITERUNNER_MATCH_STATUS'] = project.get('kiterunnerMatchStatus', DEFAULT_SETTINGS['KITERUNNER_MATCH_STATUS'])
    settings['KITERUNNER_HEADERS'] = project.get('kiterunnerHeaders', DEFAULT_SETTINGS['KITERUNNER_HEADERS'])
    settings['KITERUNNER_DETECT_METHODS'] = project.get('kiterunnerDetectMethods', DEFAULT_SETTINGS['KITERUNNER_DETECT_METHODS'])
    settings['KITERUNNER_METHOD_DETECTION_MODE'] = project.get('kiterunnerMethodDetectionMode', DEFAULT_SETTINGS['KITERUNNER_METHOD_DETECTION_MODE'])
    settings['KITERUNNER_BRUTEFORCE_METHODS'] = project.get('kiterunnerBruteforceMethods', DEFAULT_SETTINGS['KITERUNNER_BRUTEFORCE_METHODS'])
    settings['KITERUNNER_METHOD_DETECT_TIMEOUT'] = project.get('kiterunnerMethodDetectTimeout', DEFAULT_SETTINGS['KITERUNNER_METHOD_DETECT_TIMEOUT'])
    settings['KITERUNNER_METHOD_DETECT_RATE_LIMIT'] = project.get('kiterunnerMethodDetectRateLimit', DEFAULT_SETTINGS['KITERUNNER_METHOD_DETECT_RATE_LIMIT'])
    settings['KITERUNNER_METHOD_DETECT_THREADS'] = project.get('kiterunnerMethodDetectThreads', DEFAULT_SETTINGS['KITERUNNER_METHOD_DETECT_THREADS'])
    settings['KITERUNNER_PARALLELISM'] = project.get('kiterunnerParallelism', DEFAULT_SETTINGS['KITERUNNER_PARALLELISM'])

    # CVE Lookup
    settings['CVE_LOOKUP_ENABLED'] = project.get('cveLookupEnabled', DEFAULT_SETTINGS['CVE_LOOKUP_ENABLED'])
    settings['CVE_LOOKUP_SOURCE'] = project.get('cveLookupSource', DEFAULT_SETTINGS['CVE_LOOKUP_SOURCE'])
    settings['CVE_LOOKUP_MAX_CVES'] = project.get('cveLookupMaxCves', DEFAULT_SETTINGS['CVE_LOOKUP_MAX_CVES'])
    settings['CVE_LOOKUP_MIN_CVSS'] = project.get('cveLookupMinCvss', DEFAULT_SETTINGS['CVE_LOOKUP_MIN_CVSS'])

    # MITRE CWE/CAPEC Enrichment
    settings['MITRE_ENABLED'] = project.get('mitreEnabled', DEFAULT_SETTINGS['MITRE_ENABLED'])
    settings['MITRE_AUTO_UPDATE_DB'] = project.get('mitreAutoUpdateDb', DEFAULT_SETTINGS['MITRE_AUTO_UPDATE_DB'])
    settings['MITRE_INCLUDE_CWE'] = project.get('mitreIncludeCwe', DEFAULT_SETTINGS['MITRE_INCLUDE_CWE'])
    settings['MITRE_INCLUDE_CAPEC'] = project.get('mitreIncludeCapec', DEFAULT_SETTINGS['MITRE_INCLUDE_CAPEC'])
    settings['MITRE_ENRICH_RECON'] = project.get('mitreEnrichRecon', DEFAULT_SETTINGS['MITRE_ENRICH_RECON'])
    settings['MITRE_ENRICH_GVM'] = project.get('mitreEnrichGvm', DEFAULT_SETTINGS['MITRE_ENRICH_GVM'])
    settings['MITRE_CACHE_TTL_HOURS'] = project.get('mitreCacheTtlHours', DEFAULT_SETTINGS['MITRE_CACHE_TTL_HOURS'])

    # Security Checks
    settings['SECURITY_CHECK_ENABLED'] = project.get('securityCheckEnabled', DEFAULT_SETTINGS['SECURITY_CHECK_ENABLED'])
    settings['SECURITY_CHECK_DIRECT_IP_HTTP'] = project.get('securityCheckDirectIpHttp', DEFAULT_SETTINGS['SECURITY_CHECK_DIRECT_IP_HTTP'])
    settings['SECURITY_CHECK_DIRECT_IP_HTTPS'] = project.get('securityCheckDirectIpHttps', DEFAULT_SETTINGS['SECURITY_CHECK_DIRECT_IP_HTTPS'])
    settings['SECURITY_CHECK_IP_API_EXPOSED'] = project.get('securityCheckIpApiExposed', DEFAULT_SETTINGS['SECURITY_CHECK_IP_API_EXPOSED'])
    settings['SECURITY_CHECK_WAF_BYPASS'] = project.get('securityCheckWafBypass', DEFAULT_SETTINGS['SECURITY_CHECK_WAF_BYPASS'])
    settings['SECURITY_CHECK_TLS_EXPIRING_SOON'] = project.get('securityCheckTlsExpiringSoon', DEFAULT_SETTINGS['SECURITY_CHECK_TLS_EXPIRING_SOON'])
    settings['SECURITY_CHECK_TLS_EXPIRY_DAYS'] = project.get('securityCheckTlsExpiryDays', DEFAULT_SETTINGS['SECURITY_CHECK_TLS_EXPIRY_DAYS'])
    settings['SECURITY_CHECK_MISSING_REFERRER_POLICY'] = project.get('securityCheckMissingReferrerPolicy', DEFAULT_SETTINGS['SECURITY_CHECK_MISSING_REFERRER_POLICY'])
    settings['SECURITY_CHECK_MISSING_PERMISSIONS_POLICY'] = project.get('securityCheckMissingPermissionsPolicy', DEFAULT_SETTINGS['SECURITY_CHECK_MISSING_PERMISSIONS_POLICY'])
    settings['SECURITY_CHECK_MISSING_COOP'] = project.get('securityCheckMissingCoop', DEFAULT_SETTINGS['SECURITY_CHECK_MISSING_COOP'])
    settings['SECURITY_CHECK_MISSING_CORP'] = project.get('securityCheckMissingCorp', DEFAULT_SETTINGS['SECURITY_CHECK_MISSING_CORP'])
    settings['SECURITY_CHECK_MISSING_COEP'] = project.get('securityCheckMissingCoep', DEFAULT_SETTINGS['SECURITY_CHECK_MISSING_COEP'])
    settings['SECURITY_CHECK_CACHE_CONTROL_MISSING'] = project.get('securityCheckCacheControlMissing', DEFAULT_SETTINGS['SECURITY_CHECK_CACHE_CONTROL_MISSING'])
    settings['SECURITY_CHECK_LOGIN_NO_HTTPS'] = project.get('securityCheckLoginNoHttps', DEFAULT_SETTINGS['SECURITY_CHECK_LOGIN_NO_HTTPS'])
    settings['SECURITY_CHECK_SESSION_NO_SECURE'] = project.get('securityCheckSessionNoSecure', DEFAULT_SETTINGS['SECURITY_CHECK_SESSION_NO_SECURE'])
    settings['SECURITY_CHECK_SESSION_NO_HTTPONLY'] = project.get('securityCheckSessionNoHttponly', DEFAULT_SETTINGS['SECURITY_CHECK_SESSION_NO_HTTPONLY'])
    settings['SECURITY_CHECK_BASIC_AUTH_NO_TLS'] = project.get('securityCheckBasicAuthNoTls', DEFAULT_SETTINGS['SECURITY_CHECK_BASIC_AUTH_NO_TLS'])
    settings['SECURITY_CHECK_SPF_MISSING'] = project.get('securityCheckSpfMissing', DEFAULT_SETTINGS['SECURITY_CHECK_SPF_MISSING'])
    settings['SECURITY_CHECK_DMARC_MISSING'] = project.get('securityCheckDmarcMissing', DEFAULT_SETTINGS['SECURITY_CHECK_DMARC_MISSING'])
    settings['SECURITY_CHECK_DNSSEC_MISSING'] = project.get('securityCheckDnssecMissing', DEFAULT_SETTINGS['SECURITY_CHECK_DNSSEC_MISSING'])
    settings['SECURITY_CHECK_ZONE_TRANSFER'] = project.get('securityCheckZoneTransfer', DEFAULT_SETTINGS['SECURITY_CHECK_ZONE_TRANSFER'])
    settings['SECURITY_CHECK_ADMIN_PORT_EXPOSED'] = project.get('securityCheckAdminPortExposed', DEFAULT_SETTINGS['SECURITY_CHECK_ADMIN_PORT_EXPOSED'])
    settings['SECURITY_CHECK_DATABASE_EXPOSED'] = project.get('securityCheckDatabaseExposed', DEFAULT_SETTINGS['SECURITY_CHECK_DATABASE_EXPOSED'])
    settings['SECURITY_CHECK_REDIS_NO_AUTH'] = project.get('securityCheckRedisNoAuth', DEFAULT_SETTINGS['SECURITY_CHECK_REDIS_NO_AUTH'])
    settings['SECURITY_CHECK_KUBERNETES_API_EXPOSED'] = project.get('securityCheckKubernetesApiExposed', DEFAULT_SETTINGS['SECURITY_CHECK_KUBERNETES_API_EXPOSED'])
    settings['SECURITY_CHECK_SMTP_OPEN_RELAY'] = project.get('securityCheckSmtpOpenRelay', DEFAULT_SETTINGS['SECURITY_CHECK_SMTP_OPEN_RELAY'])
    settings['SECURITY_CHECK_CSP_UNSAFE_INLINE'] = project.get('securityCheckCspUnsafeInline', DEFAULT_SETTINGS['SECURITY_CHECK_CSP_UNSAFE_INLINE'])
    settings['SECURITY_CHECK_INSECURE_FORM_ACTION'] = project.get('securityCheckInsecureFormAction', DEFAULT_SETTINGS['SECURITY_CHECK_INSECURE_FORM_ACTION'])
    settings['SECURITY_CHECK_NO_RATE_LIMITING'] = project.get('securityCheckNoRateLimiting', DEFAULT_SETTINGS['SECURITY_CHECK_NO_RATE_LIMITING'])
    settings['SECURITY_CHECK_TIMEOUT'] = project.get('securityCheckTimeout', DEFAULT_SETTINGS['SECURITY_CHECK_TIMEOUT'])
    settings['SECURITY_CHECK_MAX_WORKERS'] = project.get('securityCheckMaxWorkers', DEFAULT_SETTINGS['SECURITY_CHECK_MAX_WORKERS'])

    # Shodan Pipeline Enrichment
    settings['SHODAN_ENABLED'] = project.get('shodanEnabled', DEFAULT_SETTINGS['SHODAN_ENABLED'])
    settings['SHODAN_HOST_LOOKUP'] = project.get('shodanHostLookup', DEFAULT_SETTINGS['SHODAN_HOST_LOOKUP'])
    settings['SHODAN_REVERSE_DNS'] = project.get('shodanReverseDns', DEFAULT_SETTINGS['SHODAN_REVERSE_DNS'])
    settings['SHODAN_DOMAIN_DNS'] = project.get('shodanDomainDns', DEFAULT_SETTINGS['SHODAN_DOMAIN_DNS'])
    settings['SHODAN_PASSIVE_CVES'] = project.get('shodanPassiveCves', DEFAULT_SETTINGS['SHODAN_PASSIVE_CVES'])
    settings['SHODAN_WORKERS'] = project.get('shodanWorkers', DEFAULT_SETTINGS['SHODAN_WORKERS'])

    # URLScan.io Passive Enrichment
    settings['URLSCAN_ENABLED'] = project.get('urlscanEnabled', DEFAULT_SETTINGS['URLSCAN_ENABLED'])
    settings['URLSCAN_MAX_RESULTS'] = project.get('urlscanMaxResults', DEFAULT_SETTINGS['URLSCAN_MAX_RESULTS'])

    # OSINT & Threat Intelligence Enrichment
    settings['OSINT_ENRICHMENT_ENABLED'] = project.get('osintEnrichmentEnabled', DEFAULT_SETTINGS['OSINT_ENRICHMENT_ENABLED'])
    settings['CENSYS_ENABLED'] = project.get('censysEnabled', DEFAULT_SETTINGS['CENSYS_ENABLED'])
    settings['FOFA_ENABLED'] = project.get('fofaEnabled', DEFAULT_SETTINGS['FOFA_ENABLED'])
    settings['FOFA_MAX_RESULTS'] = int(project.get('fofaMaxResults', DEFAULT_SETTINGS['FOFA_MAX_RESULTS']) or DEFAULT_SETTINGS['FOFA_MAX_RESULTS'])
    settings['OTX_ENABLED'] = project.get('otxEnabled', DEFAULT_SETTINGS['OTX_ENABLED'])
    settings['NETLAS_ENABLED'] = project.get('netlasEnabled', DEFAULT_SETTINGS['NETLAS_ENABLED'])
    settings['VIRUSTOTAL_ENABLED'] = project.get('virusTotalEnabled', DEFAULT_SETTINGS['VIRUSTOTAL_ENABLED'])
    settings['ZOOMEYE_ENABLED'] = project.get('zoomEyeEnabled', DEFAULT_SETTINGS['ZOOMEYE_ENABLED'])
    settings['ZOOMEYE_MAX_RESULTS'] = project.get('zoomEyeMaxResults', DEFAULT_SETTINGS['ZOOMEYE_MAX_RESULTS'])
    settings['CRIMINALIP_ENABLED'] = project.get('criminalIpEnabled', DEFAULT_SETTINGS['CRIMINALIP_ENABLED'])
    settings['OTX_WORKERS'] = project.get('otxWorkers', DEFAULT_SETTINGS['OTX_WORKERS'])
    settings['VIRUSTOTAL_WORKERS'] = project.get('virusTotalWorkers', DEFAULT_SETTINGS['VIRUSTOTAL_WORKERS'])
    settings['CENSYS_WORKERS'] = project.get('censysWorkers', DEFAULT_SETTINGS['CENSYS_WORKERS'])
    settings['CRIMINALIP_WORKERS'] = project.get('criminalIpWorkers', DEFAULT_SETTINGS['CRIMINALIP_WORKERS'])
    settings['FOFA_WORKERS'] = project.get('fofaWorkers', DEFAULT_SETTINGS['FOFA_WORKERS'])
    settings['NETLAS_WORKERS'] = project.get('netlasWorkers', DEFAULT_SETTINGS['NETLAS_WORKERS'])
    settings['ZOOMEYE_WORKERS'] = project.get('zoomEyeWorkers', DEFAULT_SETTINGS['ZOOMEYE_WORKERS'])
    settings['UNCOVER_ENABLED'] = project.get('uncoverEnabled', DEFAULT_SETTINGS['UNCOVER_ENABLED'])
    settings['UNCOVER_MAX_RESULTS'] = int(project.get('uncoverMaxResults', DEFAULT_SETTINGS['UNCOVER_MAX_RESULTS']) or DEFAULT_SETTINGS['UNCOVER_MAX_RESULTS'])
    settings['UNCOVER_DOCKER_IMAGE'] = project.get('uncoverDockerImage', DEFAULT_SETTINGS['UNCOVER_DOCKER_IMAGE'])

    # Subdomain Discovery Tool Toggles
    settings['SUBDOMAIN_DISCOVERY_ENABLED'] = project.get('subdomainDiscoveryEnabled', DEFAULT_SETTINGS['SUBDOMAIN_DISCOVERY_ENABLED'])
    settings['CRTSH_ENABLED'] = project.get('crtshEnabled', DEFAULT_SETTINGS['CRTSH_ENABLED'])
    settings['CRTSH_MAX_RESULTS'] = project.get('crtshMaxResults', DEFAULT_SETTINGS['CRTSH_MAX_RESULTS'])
    settings['HACKERTARGET_ENABLED'] = project.get('hackerTargetEnabled', DEFAULT_SETTINGS['HACKERTARGET_ENABLED'])
    settings['HACKERTARGET_MAX_RESULTS'] = project.get('hackerTargetMaxResults', DEFAULT_SETTINGS['HACKERTARGET_MAX_RESULTS'])
    settings['KNOCKPY_RECON_ENABLED'] = project.get('knockpyReconEnabled', DEFAULT_SETTINGS['KNOCKPY_RECON_ENABLED'])
    settings['KNOCKPY_RECON_MAX_RESULTS'] = project.get('knockpyReconMaxResults', DEFAULT_SETTINGS['KNOCKPY_RECON_MAX_RESULTS'])
    settings['SUBFINDER_ENABLED'] = project.get('subfinderEnabled', DEFAULT_SETTINGS['SUBFINDER_ENABLED'])
    settings['SUBFINDER_MAX_RESULTS'] = project.get('subfinderMaxResults', DEFAULT_SETTINGS['SUBFINDER_MAX_RESULTS'])
    settings['SUBFINDER_DOCKER_IMAGE'] = project.get('subfinderDockerImage', DEFAULT_SETTINGS['SUBFINDER_DOCKER_IMAGE'])
    settings['AMASS_ENABLED'] = project.get('amassEnabled', DEFAULT_SETTINGS['AMASS_ENABLED'])
    settings['AMASS_MAX_RESULTS'] = project.get('amassMaxResults', DEFAULT_SETTINGS['AMASS_MAX_RESULTS'])
    settings['AMASS_TIMEOUT'] = project.get('amassTimeout', DEFAULT_SETTINGS['AMASS_TIMEOUT'])
    settings['AMASS_ACTIVE'] = project.get('amassActive', DEFAULT_SETTINGS['AMASS_ACTIVE'])
    settings['AMASS_BRUTE'] = project.get('amassBrute', DEFAULT_SETTINGS['AMASS_BRUTE'])
    settings['AMASS_BRUTE_WORDLISTS'] = project.get('amassBruteWordlists', DEFAULT_SETTINGS['AMASS_BRUTE_WORDLISTS'])
    settings['AMASS_DOCKER_IMAGE'] = project.get('amassDockerImage', DEFAULT_SETTINGS['AMASS_DOCKER_IMAGE'])

    # Puredns (wildcard filtering)
    settings['PUREDNS_ENABLED'] = project.get('purednsEnabled', DEFAULT_SETTINGS['PUREDNS_ENABLED'])
    settings['PUREDNS_DOCKER_IMAGE'] = project.get('purednsDockerImage', DEFAULT_SETTINGS['PUREDNS_DOCKER_IMAGE'])
    settings['PUREDNS_THREADS'] = project.get('purednsThreads', DEFAULT_SETTINGS['PUREDNS_THREADS'])
    settings['PUREDNS_RATE_LIMIT'] = project.get('purednsRateLimit', DEFAULT_SETTINGS['PUREDNS_RATE_LIMIT'])
    settings['PUREDNS_WILDCARD_BATCH'] = project.get('purednsWildcardBatch', DEFAULT_SETTINGS['PUREDNS_WILDCARD_BATCH'])
    settings['PUREDNS_SKIP_VALIDATION'] = project.get('purednsSkipValidation', DEFAULT_SETTINGS['PUREDNS_SKIP_VALIDATION'])

    # Fetch all API keys and rotation configs from user's global settings (single call)
    from helpers.key_rotation import KeyRotator

    user_global = {}
    if settings.get('USER_ID'):
        user_global = _fetch_user_settings_full(settings['USER_ID'], webapp_url)

    rotation_cfgs = user_global.get('rotationConfigs', {})

    def _build_rotator(main_key: str, tool_name: str) -> 'KeyRotator':
        cfg = rotation_cfgs.get(tool_name, {})
        extra = cfg.get('extraKeys', [])
        rotate_n = cfg.get('rotateEveryN', 10)
        return KeyRotator([main_key] + extra, rotate_n)

    # Shodan
    shodan_any = any([
        settings['SHODAN_HOST_LOOKUP'], settings['SHODAN_REVERSE_DNS'],
        settings['SHODAN_DOMAIN_DNS'], settings['SHODAN_PASSIVE_CVES'],
    ])
    if shodan_any:
        shodan_key = user_global.get('shodanApiKey', '')
        settings['SHODAN_API_KEY'] = shodan_key
        settings['SHODAN_KEY_ROTATOR'] = _build_rotator(shodan_key, 'shodan')

    # URLScan
    urlscan_enrichment = settings.get('URLSCAN_ENABLED', False)
    gau_uses_urlscan = (
        settings.get('GAU_ENABLED', False)
        and 'urlscan' in settings.get('GAU_PROVIDERS', [])
    )
    if urlscan_enrichment or gau_uses_urlscan:
        urlscan_key = user_global.get('urlscanApiKey', '')
        settings['URLSCAN_API_KEY'] = urlscan_key
        settings['URLSCAN_KEY_ROTATOR'] = _build_rotator(urlscan_key, 'urlscan')

    # NVD / Vulners
    if settings.get('CVE_LOOKUP_ENABLED'):
        nvd_key = user_global.get('nvdApiKey', '')
        vulners_key = user_global.get('vulnersApiKey', '')
        settings['NVD_API_KEY'] = nvd_key
        settings['VULNERS_API_KEY'] = vulners_key
        settings['NVD_KEY_ROTATOR'] = _build_rotator(nvd_key, 'nvd')
        settings['VULNERS_KEY_ROTATOR'] = _build_rotator(vulners_key, 'vulners')

    # OSINT & Threat Intelligence keys
    if settings.get('CENSYS_ENABLED'):
        settings['CENSYS_API_TOKEN'] = user_global.get('censysApiToken', '')
        settings['CENSYS_ORG_ID'] = user_global.get('censysOrgId', '')

    if settings.get('FOFA_ENABLED'):
        fofa_key = user_global.get('fofaApiKey', '')
        settings['FOFA_API_KEY'] = fofa_key
        settings['FOFA_KEY_ROTATOR'] = _build_rotator(fofa_key, 'fofa')

    if settings.get('OTX_ENABLED'):
        otx_key = user_global.get('otxApiKey', '')
        settings['OTX_API_KEY'] = otx_key
        settings['OTX_KEY_ROTATOR'] = _build_rotator(otx_key, 'otx')

    if settings.get('NETLAS_ENABLED'):
        netlas_key = user_global.get('netlasApiKey', '')
        settings['NETLAS_API_KEY'] = netlas_key
        settings['NETLAS_KEY_ROTATOR'] = _build_rotator(netlas_key, 'netlas')

    if settings.get('VIRUSTOTAL_ENABLED'):
        vt_key = user_global.get('virusTotalApiKey', '')
        settings['VIRUSTOTAL_API_KEY'] = vt_key
        settings['VIRUSTOTAL_KEY_ROTATOR'] = _build_rotator(vt_key, 'virustotal')

    if settings.get('ZOOMEYE_ENABLED'):
        ze_key = user_global.get('zoomEyeApiKey', '')
        settings['ZOOMEYE_API_KEY'] = ze_key
        settings['ZOOMEYE_KEY_ROTATOR'] = _build_rotator(ze_key, 'zoomeye')

    if settings.get('CRIMINALIP_ENABLED'):
        cip_key = user_global.get('criminalIpApiKey', '')
        settings['CRIMINALIP_API_KEY'] = cip_key
        settings['CRIMINALIP_KEY_ROTATOR'] = _build_rotator(cip_key, 'criminalip')

    # Uncover keys — always load shared OSINT keys so uncover can use
    # engines even when the per-tool enrichment toggles are off.
    if settings.get('UNCOVER_ENABLED'):
        if not settings.get('SHODAN_API_KEY'):
            settings['SHODAN_API_KEY'] = user_global.get('shodanApiKey', '')
        if not settings.get('FOFA_API_KEY'):
            settings['FOFA_API_KEY'] = user_global.get('fofaApiKey', '')
        if not settings.get('ZOOMEYE_API_KEY'):
            settings['ZOOMEYE_API_KEY'] = user_global.get('zoomEyeApiKey', '')
        if not settings.get('NETLAS_API_KEY'):
            settings['NETLAS_API_KEY'] = user_global.get('netlasApiKey', '')
        if not settings.get('CRIMINALIP_API_KEY'):
            settings['CRIMINALIP_API_KEY'] = user_global.get('criminalIpApiKey', '')
        if not settings.get('CENSYS_API_TOKEN'):
            settings['CENSYS_API_TOKEN'] = user_global.get('censysApiToken', '')
        if not settings.get('CENSYS_ORG_ID'):
            settings['CENSYS_ORG_ID'] = user_global.get('censysOrgId', '')
        settings['UNCOVER_QUAKE_API_KEY'] = user_global.get('quakeApiKey', '')
        settings['UNCOVER_HUNTER_API_KEY'] = user_global.get('hunterApiKey', '')
        settings['UNCOVER_PUBLICWWW_API_KEY'] = user_global.get('publicWwwApiKey', '')
        settings['UNCOVER_HUNTERHOW_API_KEY'] = user_global.get('hunterHowApiKey', '')
        settings['UNCOVER_GOOGLE_API_KEY'] = user_global.get('googleApiKey', '')
        settings['UNCOVER_GOOGLE_API_CX'] = user_global.get('googleApiCx', '')
        settings['UNCOVER_ONYPHE_API_KEY'] = user_global.get('onypheApiKey', '')
        settings['UNCOVER_DRIFTNET_API_KEY'] = user_global.get('driftnetApiKey', '')

    # Rules of Engagement
    settings['ROE_ENABLED'] = project.get('roeEnabled', DEFAULT_SETTINGS['ROE_ENABLED'])
    settings['ROE_EXCLUDED_HOSTS'] = project.get('roeExcludedHosts', DEFAULT_SETTINGS['ROE_EXCLUDED_HOSTS'])
    settings['ROE_TIME_WINDOW_ENABLED'] = project.get('roeTimeWindowEnabled', DEFAULT_SETTINGS['ROE_TIME_WINDOW_ENABLED'])
    settings['ROE_TIME_WINDOW_TIMEZONE'] = project.get('roeTimeWindowTimezone', DEFAULT_SETTINGS['ROE_TIME_WINDOW_TIMEZONE'])
    settings['ROE_TIME_WINDOW_DAYS'] = project.get('roeTimeWindowDays', DEFAULT_SETTINGS['ROE_TIME_WINDOW_DAYS'])
    settings['ROE_TIME_WINDOW_START_TIME'] = project.get('roeTimeWindowStartTime', DEFAULT_SETTINGS['ROE_TIME_WINDOW_START_TIME'])
    settings['ROE_TIME_WINDOW_END_TIME'] = project.get('roeTimeWindowEndTime', DEFAULT_SETTINGS['ROE_TIME_WINDOW_END_TIME'])
    settings['ROE_GLOBAL_MAX_RPS'] = project.get('roeGlobalMaxRps', DEFAULT_SETTINGS['ROE_GLOBAL_MAX_RPS'])

    # GraphQL Security Testing
    settings['GRAPHQL_SECURITY_ENABLED'] = project.get('graphqlSecurityEnabled', DEFAULT_SETTINGS['GRAPHQL_SECURITY_ENABLED'])
    settings['GRAPHQL_INTROSPECTION_TEST'] = project.get('graphqlIntrospectionTest', DEFAULT_SETTINGS['GRAPHQL_INTROSPECTION_TEST'])
    settings['GRAPHQL_TIMEOUT'] = project.get('graphqlTimeout', DEFAULT_SETTINGS['GRAPHQL_TIMEOUT'])
    settings['GRAPHQL_RATE_LIMIT'] = project.get('graphqlRateLimit', DEFAULT_SETTINGS['GRAPHQL_RATE_LIMIT'])
    settings['GRAPHQL_CONCURRENCY'] = project.get('graphqlConcurrency', DEFAULT_SETTINGS['GRAPHQL_CONCURRENCY'])
    settings['GRAPHQL_AUTH_TYPE'] = project.get('graphqlAuthType', DEFAULT_SETTINGS['GRAPHQL_AUTH_TYPE'])
    settings['GRAPHQL_AUTH_VALUE'] = project.get('graphqlAuthValue', DEFAULT_SETTINGS['GRAPHQL_AUTH_VALUE'])
    settings['GRAPHQL_AUTH_HEADER'] = project.get('graphqlAuthHeader', DEFAULT_SETTINGS['GRAPHQL_AUTH_HEADER'])
    settings['GRAPHQL_ENDPOINTS'] = project.get('graphqlEndpoints', DEFAULT_SETTINGS['GRAPHQL_ENDPOINTS'])
    settings['GRAPHQL_DEPTH_LIMIT'] = project.get('graphqlDepthLimit', DEFAULT_SETTINGS['GRAPHQL_DEPTH_LIMIT'])
    settings['GRAPHQL_RETRY_COUNT'] = project.get('graphqlRetryCount', DEFAULT_SETTINGS['GRAPHQL_RETRY_COUNT'])
    settings['GRAPHQL_RETRY_BACKOFF'] = project.get('graphqlRetryBackoff', DEFAULT_SETTINGS['GRAPHQL_RETRY_BACKOFF'])
    settings['GRAPHQL_VERIFY_SSL'] = project.get('graphqlVerifySsl', DEFAULT_SETTINGS['GRAPHQL_VERIFY_SSL'])

    # GraphQL Cop (external scanner) - Phase 2 §17
    settings['GRAPHQL_COP_ENABLED'] = project.get('graphqlCopEnabled', DEFAULT_SETTINGS['GRAPHQL_COP_ENABLED'])
    settings['GRAPHQL_COP_DOCKER_IMAGE'] = project.get('graphqlCopDockerImage', DEFAULT_SETTINGS['GRAPHQL_COP_DOCKER_IMAGE'])
    settings['GRAPHQL_COP_TIMEOUT'] = project.get('graphqlCopTimeout', DEFAULT_SETTINGS['GRAPHQL_COP_TIMEOUT'])
    settings['GRAPHQL_COP_FORCE_SCAN'] = project.get('graphqlCopForceScan', DEFAULT_SETTINGS['GRAPHQL_COP_FORCE_SCAN'])
    settings['GRAPHQL_COP_DEBUG'] = project.get('graphqlCopDebug', DEFAULT_SETTINGS['GRAPHQL_COP_DEBUG'])
    settings['GRAPHQL_COP_TEST_FIELD_SUGGESTIONS'] = project.get('graphqlCopTestFieldSuggestions', DEFAULT_SETTINGS['GRAPHQL_COP_TEST_FIELD_SUGGESTIONS'])
    settings['GRAPHQL_COP_TEST_INTROSPECTION'] = project.get('graphqlCopTestIntrospection', DEFAULT_SETTINGS['GRAPHQL_COP_TEST_INTROSPECTION'])
    settings['GRAPHQL_COP_TEST_GRAPHIQL'] = project.get('graphqlCopTestGraphiql', DEFAULT_SETTINGS['GRAPHQL_COP_TEST_GRAPHIQL'])
    settings['GRAPHQL_COP_TEST_GET_METHOD'] = project.get('graphqlCopTestGetMethod', DEFAULT_SETTINGS['GRAPHQL_COP_TEST_GET_METHOD'])
    settings['GRAPHQL_COP_TEST_ALIAS_OVERLOADING'] = project.get('graphqlCopTestAliasOverloading', DEFAULT_SETTINGS['GRAPHQL_COP_TEST_ALIAS_OVERLOADING'])
    settings['GRAPHQL_COP_TEST_BATCH_QUERY'] = project.get('graphqlCopTestBatchQuery', DEFAULT_SETTINGS['GRAPHQL_COP_TEST_BATCH_QUERY'])
    settings['GRAPHQL_COP_TEST_TRACE_MODE'] = project.get('graphqlCopTestTraceMode', DEFAULT_SETTINGS['GRAPHQL_COP_TEST_TRACE_MODE'])
    settings['GRAPHQL_COP_TEST_DIRECTIVE_OVERLOADING'] = project.get('graphqlCopTestDirectiveOverloading', DEFAULT_SETTINGS['GRAPHQL_COP_TEST_DIRECTIVE_OVERLOADING'])
    settings['GRAPHQL_COP_TEST_CIRCULAR_INTROSPECTION'] = project.get('graphqlCopTestCircularIntrospection', DEFAULT_SETTINGS['GRAPHQL_COP_TEST_CIRCULAR_INTROSPECTION'])
    settings['GRAPHQL_COP_TEST_GET_MUTATION'] = project.get('graphqlCopTestGetMutation', DEFAULT_SETTINGS['GRAPHQL_COP_TEST_GET_MUTATION'])
    settings['GRAPHQL_COP_TEST_POST_CSRF'] = project.get('graphqlCopTestPostCsrf', DEFAULT_SETTINGS['GRAPHQL_COP_TEST_POST_CSRF'])
    settings['GRAPHQL_COP_TEST_UNHANDLED_ERROR'] = project.get('graphqlCopTestUnhandledError', DEFAULT_SETTINGS['GRAPHQL_COP_TEST_UNHANDLED_ERROR'])

    # RoE: cap all rate limits to the global max if set
    roe_max_rps = settings['ROE_GLOBAL_MAX_RPS']
    if settings.get('ROE_ENABLED', False) and roe_max_rps > 0:
        RATE_LIMIT_KEYS = [
            'NAABU_RATE_LIMIT', 'MASSCAN_RATE', 'HTTPX_RATE_LIMIT', 'NUCLEI_RATE_LIMIT',
            'KATANA_RATE_LIMIT', 'GAU_VERIFY_RATE_LIMIT', 'GAU_METHOD_DETECT_RATE_LIMIT',
            'KITERUNNER_RATE_LIMIT', 'KITERUNNER_METHOD_DETECT_RATE_LIMIT',
            'FFUF_RATE', 'ARJUN_RATE_LIMIT',
            'PUREDNS_RATE_LIMIT',
            'HAKRAWLER_THREADS',
            'GRAPHQL_RATE_LIMIT',
        ]
        for key in RATE_LIMIT_KEYS:
            if key not in settings:
                continue
            # FFUF_RATE and ARJUN_RATE_LIMIT use 0 to mean "unlimited" — must be capped under RoE
            if settings[key] == 0 and key in ('FFUF_RATE', 'ARJUN_RATE_LIMIT'):
                logger.info(f"RoE: capping {key} from unlimited (0) to {roe_max_rps} rps")
                settings[key] = roe_max_rps
            elif settings[key] > roe_max_rps:
                logger.info(f"RoE: capping {key} from {settings[key]} to {roe_max_rps} rps")
                settings[key] = roe_max_rps

    logger.info(f"Loaded {len(settings)} settings for project {project_id}")
    return settings


def get_settings() -> dict[str, Any]:
    """
    Get project settings from webapp API.

    REQUIRES PROJECT_ID and WEBAPP_API_URL environment variables to be set.
    When running in Docker container, these are always provided by the orchestrator.
    Falls back to DEFAULT_SETTINGS only for CLI usage without env vars.

    Returns:
        Dictionary of settings in SCREAMING_SNAKE_CASE format
    """
    project_id = os.environ.get('PROJECT_ID')
    webapp_url = os.environ.get('WEBAPP_API_URL')

    if project_id and webapp_url:
        try:
            settings = fetch_project_settings(project_id, webapp_url)
            logger.info(f"Loaded {len(settings)} settings from API for project {project_id}")
            return settings

        except Exception as e:
            logger.error(f"Failed to fetch project settings: {e}")
            raise  # Don't silently fall back - fail loudly if API is expected but unavailable

    # Fallback to DEFAULT_SETTINGS for CLI usage only
    logger.info("Using DEFAULT_SETTINGS (no PROJECT_ID/WEBAPP_API_URL set - CLI mode)")
    return DEFAULT_SETTINGS.copy()


# Singleton settings instance
_settings: Optional[dict[str, Any]] = None


def get_setting(key: str, default: Any = None) -> Any:
    """
    Get a single setting value.

    Args:
        key: Setting name in SCREAMING_SNAKE_CASE
        default: Default value if setting not found

    Returns:
        Setting value or default
    """
    global _settings
    if _settings is None:
        _settings = get_settings()
    return _settings.get(key, default)


def reload_settings() -> dict[str, Any]:
    """Force reload of settings (useful for testing)"""
    global _settings
    _settings = get_settings()
    return _settings


# =============================================================================
# STEALTH MODE OVERRIDES
# =============================================================================

def apply_stealth_overrides(settings: dict[str, Any]) -> dict[str, Any]:
    """
    Apply stealth mode overrides to all recon tool settings.

    When STEALTH_MODE is True, forces all tools to use passive/low-noise
    techniques. Noisy tools (Kiterunner, banner grabbing) are disabled entirely.

    Args:
        settings: The full settings dictionary

    Returns:
        Modified settings dictionary with stealth overrides applied
    """
    if not settings.get('STEALTH_MODE', False):
        return settings

    logger.info("STEALTH MODE ENABLED — applying passive/low-noise overrides to all recon tools")

    # --- Naabu Port Scanner: passive mode only ---
    settings['NAABU_PASSIVE_MODE'] = True
    settings['NAABU_RATE_LIMIT'] = 10
    settings['NAABU_THREADS'] = 1
    settings['NAABU_SCAN_TYPE'] = 'c'  # CONNECT scan (no raw SYN)
    settings['NAABU_SKIP_HOST_DISCOVERY'] = True

    # --- httpx HTTP Probing: low-rate, disable fingerprinting ---
    settings['HTTPX_THREADS'] = 1
    settings['HTTPX_RATE_LIMIT'] = 2
    settings['HTTPX_PROBE_JARM'] = False      # JARM = 10 TLS connections per target
    settings['HTTPX_PROBE_FAVICON'] = False    # Extra HTTP requests for hashing

    # --- Katana Web Crawler: minimal crawl ---
    settings['KATANA_DEPTH'] = 1
    settings['KATANA_RATE_LIMIT'] = 2
    settings['KATANA_MAX_URLS'] = 50
    settings['KATANA_JS_CRAWL'] = False  # JS rendering = headless browser = noisy
    settings['KATANA_PARALLELISM'] = 1
    settings['KATANA_CONCURRENCY'] = 1

    # --- GAU: enable it (passive source) but throttle verification ---
    settings['GAU_ENABLED'] = True
    settings['GAU_VERIFY_RATE_LIMIT'] = 2
    settings['GAU_VERIFY_THREADS'] = 1
    settings['GAU_METHOD_DETECT_RATE_LIMIT'] = 2
    settings['GAU_METHOD_DETECT_THREADS'] = 1
    settings['GAU_WORKERS'] = 1

    # --- ParamSpider: enable it (passive source) ---
    settings['PARAMSPIDER_ENABLED'] = True
    settings['PARAMSPIDER_WORKERS'] = 1

    # --- Nuclei: passive-only scanning ---
    settings['NUCLEI_DAST_MODE'] = False       # No active fuzzing
    settings['NUCLEI_INTERACTSH'] = False      # No OOB callbacks
    settings['NUCLEI_RATE_LIMIT'] = 5
    settings['NUCLEI_CONCURRENCY'] = 2
    settings['NUCLEI_BULK_SIZE'] = 5
    settings['NUCLEI_HEADLESS'] = False
    # Exclude intrusive template tags
    existing_exclude = settings.get('NUCLEI_EXCLUDE_TAGS', [])
    stealth_exclude = ['dos', 'fuzz', 'intrusive', 'sqli', 'rce']
    settings['NUCLEI_EXCLUDE_TAGS'] = list(set(existing_exclude + stealth_exclude))

    # --- Subdomain Takeover: passive-only (subjack DNS, no nuclei HTTP fuzzing) ---
    settings['NUCLEI_TAKEOVERS_ENABLED'] = False
    settings['SUBJACK_ALL'] = False             # Don't probe non-CNAME hosts
    settings['SUBJACK_CHECK_NS'] = True         # NS checks are safe DNS-only
    settings['SUBJACK_CHECK_MAIL'] = True       # Mail checks are safe DNS-only
    settings['SUBJACK_THREADS'] = 3
    settings['TAKEOVER_RATE_LIMIT'] = 10
    settings['BADDNS_ENABLED'] = False          # Keep isolated sidecar off in stealth

    # --- Hakrawler: DISABLED (active crawler, no rate-limit control) ---
    settings['HAKRAWLER_ENABLED'] = False

    # --- jsluice: keep enabled but reduce file count ---
    settings['JSLUICE_MAX_FILES'] = 20
    settings['JSLUICE_PARALLELISM'] = 1

    # --- FFuf: DISABLED (active directory brute-force) ---
    settings['FFUF_ENABLED'] = False

    # --- Kiterunner: DISABLED (active brute-force API discovery) ---
    settings['KITERUNNER_ENABLED'] = False

    # --- Arjun: force PASSIVE ONLY (no active probing in stealth) ---
    settings['ARJUN_PASSIVE'] = True

    # --- Banner Grabbing: DISABLED (direct socket connections) ---
    settings['BANNER_GRAB_ENABLED'] = False

    # --- Nmap: minimal parallelism ---
    settings['NMAP_PARALLELISM'] = 1

    # --- Shodan: reduce parallel workers ---
    settings['SHODAN_WORKERS'] = 1

    # --- OSINT enrichment: reduce parallel workers ---
    settings['OTX_WORKERS'] = 1
    settings['VIRUSTOTAL_WORKERS'] = 1
    settings['CENSYS_WORKERS'] = 1
    settings['CRIMINALIP_WORKERS'] = 1
    settings['FOFA_WORKERS'] = 1
    settings['NETLAS_WORKERS'] = 1
    settings['ZOOMEYE_WORKERS'] = 1

    # --- DNS: reduce parallel workers ---
    settings['DNS_MAX_WORKERS'] = 5
    settings['DNS_RECORD_PARALLELISM'] = False

    # --- Subdomain Brute Force: DISABLED ---
    settings['USE_BRUTEFORCE_FOR_SUBDOMAINS'] = False

    # --- Passive sources: keep enabled but reduce results ---
    settings['URLSCAN_MAX_RESULTS'] = min(settings.get('URLSCAN_MAX_RESULTS', 5000), 100)
    settings['CRTSH_MAX_RESULTS'] = min(settings.get('CRTSH_MAX_RESULTS', 5000), 100)
    settings['HACKERTARGET_MAX_RESULTS'] = min(settings.get('HACKERTARGET_MAX_RESULTS', 5000), 100)
    settings['KNOCKPY_RECON_MAX_RESULTS'] = min(settings.get('KNOCKPY_RECON_MAX_RESULTS', 5000), 100)
    settings['SUBFINDER_MAX_RESULTS'] = min(settings.get('SUBFINDER_MAX_RESULTS', 5000), 100)
    settings['AMASS_ACTIVE'] = False
    settings['AMASS_BRUTE'] = False
    settings['AMASS_MAX_RESULTS'] = min(settings.get('AMASS_MAX_RESULTS', 5000), 100)

    # --- Puredns: DISABLED (active DNS queries) ---
    settings['PUREDNS_ENABLED'] = False

    # --- Security Checks: disable active checks, keep passive ones ---
    # Active checks (make network connections to target)
    settings['SECURITY_CHECK_DIRECT_IP_HTTP'] = False
    settings['SECURITY_CHECK_DIRECT_IP_HTTPS'] = False
    settings['SECURITY_CHECK_WAF_BYPASS'] = False
    settings['SECURITY_CHECK_ZONE_TRANSFER'] = False
    settings['SECURITY_CHECK_ADMIN_PORT_EXPOSED'] = False
    settings['SECURITY_CHECK_DATABASE_EXPOSED'] = False
    settings['SECURITY_CHECK_REDIS_NO_AUTH'] = False
    settings['SECURITY_CHECK_KUBERNETES_API_EXPOSED'] = False
    settings['SECURITY_CHECK_SMTP_OPEN_RELAY'] = False
    settings['SECURITY_CHECK_NO_RATE_LIMITING'] = False
    # Passive checks remain enabled (SPF, DMARC, DNSSEC, TLS expiry, headers)

    # --- Nmap: reduce aggressiveness ---
    settings['NMAP_TIMING_TEMPLATE'] = 'T2'
    settings['NMAP_SCRIPT_SCAN'] = False

    # --- Masscan: DISABLED (active SYN scanning) ---
    settings['MASSCAN_ENABLED'] = False

    # --- JS Recon: disable validation (makes outbound API calls), reduce scope ---
    settings['JS_RECON_MAX_FILES'] = 50
    settings['JS_RECON_VALIDATE_KEYS'] = False
    settings['JS_RECON_INCLUDE_CHUNKS'] = False
    settings['JS_RECON_INCLUDE_FRAMEWORK_JS'] = False

    # --- GraphQL Security: minimal introspection only ---
    settings['GRAPHQL_SECURITY_ENABLED'] = True  # Can still do passive introspection
    settings['GRAPHQL_INTROSPECTION_TEST'] = True
    settings['GRAPHQL_RATE_LIMIT'] = 2            # Very low rate
    settings['GRAPHQL_CONCURRENCY'] = 1           # Sequential only
    settings['GRAPHQL_TIMEOUT'] = 60              # Longer timeout for slow responses

    # --- GraphQL Cop: disable DoS probes in stealth mode ---
    # (Info-leak + CSRF checks still run -- they're low-traffic.)
    settings['GRAPHQL_COP_TEST_ALIAS_OVERLOADING'] = False
    settings['GRAPHQL_COP_TEST_BATCH_QUERY'] = False
    settings['GRAPHQL_COP_TEST_DIRECTIVE_OVERLOADING'] = False
    settings['GRAPHQL_COP_TEST_CIRCULAR_INTROSPECTION'] = False

    logger.info("Stealth overrides applied: Naabu=passive, Masscan=OFF, httpx=low-rate, Katana=minimal, "
                "Nuclei=no-DAST, Kiterunner=OFF, BannerGrab=OFF, BruteForce=OFF, "
                "ActiveSecurityChecks=OFF, JsRecon=reduced, GraphQL=introspection-only, "
                "GraphQLCop=no-DoS")

    return settings
