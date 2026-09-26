"""
Project Settings - Fetch project configuration from webapp API

When PROJECT_ID and WEBAPP_API_URL are set as environment variables,
settings are fetched from the PostgreSQL database via webapp API.
Otherwise, falls back to DEFAULT_SETTINGS for CLI usage.
"""
import os
import logging
import re
from typing import Any, Optional

# The settings registry: every parameter's bound, unit, and engagement cap.
# Imported two ways because this module is loaded both as `recon.project_settings`
# (tests, the agent) and as `project_settings` with /app/recon on the path (a
# spawned scan container). It is deliberately NOT wrapped in a try/except that
# falls back: a scan with no registry has no engagement ceiling, so the import
# failing must stop the scan rather than quietly widen it.
try:
    from recon import settings_registry as _registry
except ImportError:  # pragma: no cover - the container's own layout
    import settings_registry as _registry

from recon_settings.engagement import derive_roe_enabled

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
    # Domain batch: the third targeting mode. DOMAIN_BATCH_GROUPS is the derived,
    # operator-approved run order: [{'rootDomain': str, 'prefixes': [str], 'hosts': [str]}].
    # The webapp derives it; the pipeline never re-derives, so both agree on scope.
    'DOMAIN_BATCH_MODE': False,
    'DOMAIN_BATCH_GROUPS': [],
    'VERIFY_DOMAIN_OWNERSHIP': False,
    'OWNERSHIP_TOKEN': 'your-secret-token-here',
    'OWNERSHIP_TXT_PREFIX': '_redamon-verify',

    # Scan Modules
    'SCAN_MODULES': ['domain_discovery', 'port_scan', 'http_probe', 'resource_enum', 'vuln_scan'],
    'UPDATE_GRAPH_DB': True,
    'USE_BRUTEFORCE_FOR_SUBDOMAINS': False,
    'STEALTH_MODE': False,

    # AI in Pipeline (master switch + model picker for all AI hooks across recon)
    'AI_IN_PIPELINE': False,
    'AI_PIPELINE_MODEL': 'claude-opus-4-6',

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
    # AI surface recon — annotate AI-bearing ports (Ollama 11434, Qdrant 6333, Open WebUI 8080, …) on naabu output
    'PORT_SCAN_AI_PORT_CATALOG_ENABLED': True,

    # Nmap Service Detection & NSE Vuln Scripts
    'NMAP_ENABLED': True,
    'NMAP_VERSION_DETECTION': True,
    'NMAP_SCRIPT_SCAN': True,
    'NMAP_TIMING_TEMPLATE': 'T3',
    'NMAP_TIMEOUT': 600,
    'NMAP_HOST_TIMEOUT': 300,
    'NMAP_PARALLELISM': 5,
    # AI surface recon — regex nmap product/version strings against AI runtimes (Ollama, vLLM, LiteLLM, TGI, …)
    'NMAP_AI_VERSION_REGEX_ENABLED': True,

    # Masscan Port Scanner (disabled by default -- only useful for large IP ranges/CIDRs)
    'MASSCAN_ENABLED': False,
    'MASSCAN_TOP_PORTS': '1000',
    'MASSCAN_CUSTOM_PORTS': '',
    'MASSCAN_RATE': 1000,
    'MASSCAN_BANNERS': False,
    'MASSCAN_WAIT': 10,
    'MASSCAN_RETRIES': 1,
    'MASSCAN_EXCLUDE_TARGETS': '',
    # AI surface recon — same AI port catalogue applied to masscan output
    'MASSCAN_AI_PORT_CATALOG_ENABLED': True,

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
    # AI surface recon — annotate captured response headers / favicon / title against AI vendor catalogues
    'HTTP_PROBE_AI_HEADER_SCAN_ENABLED': True,
    'HTTP_PROBE_AI_FAVICON_HASH_ENABLED': True,
    'HTTP_PROBE_AI_TITLE_DETECTION_ENABLED': True,
    'HTTP_PROBE_AI_WAPPALYZER_ENABLED': True,

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
    'BANNER_GRAB_MAX_LENGTH': 1000,

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
    'NUCLEI_TAGS': ['cve', 'xss', 'sqli', 'rce', 'lfi', 'ssrf', 'xxe', 'ssti'],
    'NUCLEI_EXCLUDE_TAGS': ['dos', 'fuzz'],
    'NUCLEI_DAST_MODE': False,
    'NUCLEI_AUTO_UPDATE_TEMPLATES': True,
    'NUCLEI_NEW_TEMPLATES_ONLY': False,
    'NUCLEI_HEADLESS': False,
    'NUCLEI_SYSTEM_RESOLVERS': True,
    'NUCLEI_FOLLOW_REDIRECTS': True,
    'NUCLEI_MAX_REDIRECTS': 10,
    'NUCLEI_SCAN_ALL_IPS': False,
    'NUCLEI_INTERACTSH': True,
    'NUCLEI_DOCKER_IMAGE': 'projectdiscovery/nuclei:latest',
    'NUCLEI_AI_TAGS': False,
    # Cascade-gated by AI_IN_PIPELINE. When on, is_false_positive() falls
    # back to the agent's /llm/nuclei-fp-filter endpoint when the keyword
    # WAF block list misses but the response still looks like a block.
    'NUCLEI_AI_RESPONSE_FILTER': False,

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
    'TAKEOVER_CNAME_VALIDATION_ENABLED': True,
    # Certificate-derived takeover signals (Phase 3). Mirrors the CNAME toggle
    # above; gates the cert enrichment + the new cert scoring rules. Reads
    # whatever cert data is available (httpx 443 with tlsx off, more with on).
    'TAKEOVER_CERT_VALIDATION_ENABLED': True,
    # Cascade-gated by AI_IN_PIPELINE. When on, takeover findings whose
    # response carries no third-party vendor token get an LLM second pass
    # to disambiguate genuine "service unclaimed" pages from WAF block
    # pages that match the same static fingerprint.
    'TAKEOVER_AI_CLASSIFIER': False,
    # BadDNS (AGPL-3.0, isolated sidecar — disabled by default, opt-in)
    'BADDNS_ENABLED': False,
    'BADDNS_DOCKER_IMAGE': 'redamon-baddns:latest',
    'BADDNS_MODULES': ['cname', 'ns', 'mx', 'txt', 'spf'],
    'BADDNS_NAMESERVERS': [],
    'BADDNS_RUN_TIMEOUT': 1800,

    # VHost & SNI Enumeration
    # Runs in GROUP 6 Phase A alongside Nuclei/GraphQL/Subdomain Takeover.
    # Tests every (subdomain, IP, port) for hidden virtual hosts via L7
    # (Host header) and L4 (TLS SNI) probes. Writes Vulnerability nodes with
    # source="vhost_sni_enum". See recon/main_recon_modules/vhost_sni_enum.py.
    'VHOST_SNI_ENABLED': False,
    'VHOST_SNI_TIMEOUT': 3,
    'VHOST_SNI_CONCURRENCY': 20,
    'VHOST_SNI_BASELINE_SIZE_TOLERANCE': 50,
    'VHOST_SNI_TEST_L7': True,
    'VHOST_SNI_TEST_L4': True,
    'VHOST_SNI_INJECT_DISCOVERED': True,
    'VHOST_SNI_USE_DEFAULT_WORDLIST': True,
    'VHOST_SNI_USE_GRAPH_CANDIDATES': True,
    'VHOST_SNI_CUSTOM_WORDLIST': '',
    'VHOST_SNI_MAX_CANDIDATES_PER_IP': 2000,

    # tlsx TLS certificate grab (GROUP 3.6). Default ON: one handshake per open
    # non-HTTP TLS port, quieter than -jarm (already default-on in httpx) and
    # net-zero on the 5 SSL ports http_probe already dials and discards.
    'TLSX_ENABLED': True,
    'TLSX_DOCKER_IMAGE': 'projectdiscovery/tlsx:latest',
    'TLSX_SCAN_MODE': 'auto',                # ctls|ztls|openssl|auto
    'TLSX_CONCURRENCY': 50,                  # tlsx default is 300; 50 is quieter
    'TLSX_TIMEOUT': 5,                       # per-handshake -timeout (seconds)
    'TLSX_RUN_TIMEOUT': 900,                 # whole-container ceiling (Popen)
    'TLSX_RETRIES': 1,                       # tlsx default is 3
    'TLSX_MAX_INJECTED_HOSTNAMES': 200,      # SAN names merged into dns.subdomains
    'TLSX_DELAY': '',                        # -delay (stealth only)
    'TLSX_INCLUDE_HTTP_PORTS': False,        # anti-duplication with httpx
    'TLSX_INJECT_HOSTNAMES': True,           # SAN -> dns.subdomains
    'TLSX_REV_PTR_SNI': False,               # -rps, extra DNS per bare IP
    'TLSX_MAX_HOSTNAMES_PER_IP': 1,          # SNI correctness cap
    'TLSX_PROBE_JARM': False,                # -jarm/-ja3: ~10 handshakes/target
    'TLSX_VERSION_ENUM': False,              # -ve: extra connections per target
    'TLSX_CIPHER_ENUM': False,               # -ce: extra connections per target
    'TLSX_CIPHER_CONCURRENCY': 10,           # -cec, only when cipher enum on
    'TLSX_MAX_TARGETS': 2000,

    # Resource Enum AI Classifier — cross-cutting endpoint + parameter
    # classifier that runs after Katana/Hakrawler/GAU/FFuf/jsluice/ParamSpider/
    # Kiterunner/Arjun have produced endpoints. Pure regex, no extra traffic.
    'RESOURCE_ENUM_AI_CLASSIFIER_ENABLED': True,
    'RESOURCE_ENUM_AI_PATH_CLASSIFIER_ENABLED': True,
    'RESOURCE_ENUM_AI_RAG_PATH_FLAG_ENABLED': True,
    'RESOURCE_ENUM_AI_PARAM_INJECTABLE_FLAG_ENABLED': True,
    'RESOURCE_ENUM_AI_TOOL_ARG_PATH_ENABLED': True,

    # AI Surface Recon (central module) — active, protocol-aware AI/LLM/MCP
    # fingerprinting. Runs after resource_enum (display Phase 4.5). Benign
    # shape-probes only; gated per-workload, stealth flips actives off.
    'AI_SURFACE_RECON_ENABLED': True,
    'AI_SURFACE_RECON_TIMEOUT': 10,
    'AI_SURFACE_RECON_MAX_WORKERS': 5,
    'AI_SURFACE_RECON_USER_AGENT': 'RedAmon-AISurfaceRecon/1.0',
    'AI_SURFACE_RECON_CHAT_SHAPE_PROBE_ENABLED': True,
    'AI_SURFACE_RECON_MCP_HANDSHAKE_ENABLED': True,
    'AI_SURFACE_RECON_MCP_LIST_TOOLS_ENABLED': True,
    'AI_SURFACE_RECON_MCP_YARA_ENABLED': True,
    'AI_SURFACE_RECON_OPENAPI_DISCOVERY_ENABLED': True,
    'AI_SURFACE_RECON_MODEL_LIST_ENABLED': True,
    'AI_SURFACE_RECON_VECTOR_DB_READ_ENABLED': True,
    'AI_SURFACE_RECON_JULIUS_PROBE_PACK_ENABLED': True,
    'AI_SURFACE_RECON_LATENCY_BASELINE_ENABLED': True,
    'AI_SURFACE_RECON_CACHE_ENABLED': True,
    'AI_SURFACE_RECON_PROBE_PACK_VERSION': 'latest',

    # Katana Web Crawler
    'KATANA_ENABLED': True,
    'KATANA_DOCKER_IMAGE': 'projectdiscovery/katana:latest',
    'KATANA_DEPTH': 2,
    'KATANA_MAX_URLS': 300000,
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

    'OPENAPI_ENABLED': True,
    'OPENAPI_AUTO_DISCOVER': False,
    'OPENAPI_DISCOVERY_PATHS': ["/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml", "/v3/api-docs", "/v2/api-docs", "/swagger/v1/swagger.json", "/swagger-ui/index.html", "/swagger-ui.html", "/docs", "/api-docs", "/api-docs/"],
    'OPENAPI_SOURCES': [],
    'OPENAPI_TIMEOUT': 10,
    'OPENAPI_MAX_DOCUMENTS': 50,

    # HTTP Traffic Capture (mitmproxy integration, Phase 0+)
    # Off by default: when off, recon does not retain httpx bodies and posts
    # nothing to the /traffic store. Turning it on makes recon persist probed
    # transactions (metadata + capped bodies) to Postgres via the webapp.
    'CAPTURE_PROXY_ENABLED': False,

    # ZAP Ajax Spider Browser Crawler
    'ZAP_AJAX_SPIDER_ENABLED': False,
    'ZAP_AJAX_SPIDER_DOCKER_IMAGE': 'ghcr.io/zaproxy/zaproxy:stable',
    'ZAP_AJAX_SPIDER_SEED_MODE': 'base_urls',
    'ZAP_AJAX_SPIDER_MAX_DURATION': 10,
    'ZAP_AJAX_SPIDER_MAX_CRAWL_DEPTH': 5,
    'ZAP_AJAX_SPIDER_MAX_CRAWL_STATES': 0,
    'ZAP_AJAX_SPIDER_NUMBER_OF_BROWSERS': 1,
    'ZAP_AJAX_SPIDER_BROWSER_ID': 'firefox-headless',
    'ZAP_AJAX_SPIDER_EVENT_WAIT': 1000,
    'ZAP_AJAX_SPIDER_RELOAD_WAIT': 1000,
    'ZAP_AJAX_SPIDER_CLICK_DEFAULT_ELEMS': True,
    'ZAP_AJAX_SPIDER_CLICK_ELEMS_ONCE': True,
    'ZAP_AJAX_SPIDER_RANDOM_INPUTS': False,
    'ZAP_AJAX_SPIDER_LOGOUT_AVOIDANCE': True,
    'ZAP_AJAX_SPIDER_SCOPE_CHECK': 'Strict',
    'ZAP_AJAX_SPIDER_CUSTOM_HEADERS': [],
    'ZAP_AJAX_SPIDER_EXCLUDE_PATTERNS': [],
    'ZAP_AJAX_SPIDER_MAX_URLS': 1000,
    'ZAP_AJAX_SPIDER_PARALLELISM': 3,

    # GAU Passive URL Discovery
    'GAU_ENABLED': False,
    'GAU_DOCKER_IMAGE': 'sxcurity/gau:latest',
    'GAU_PROVIDERS': ['wayback', 'commoncrawl', 'otx', 'urlscan'],
    'GAU_MAX_URLS': 50000,
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
    'HAKRAWLER_MAX_URLS': 50000,
    'HAKRAWLER_INCLUDE_SUBS': True,
    'HAKRAWLER_INSECURE': True,
    'HAKRAWLER_CUSTOM_HEADERS': [],
    'HAKRAWLER_PARALLELISM': 5,

    # jsluice JavaScript Analyzer
    'JSLUICE_ENABLED': True,
    'JSLUICE_MAX_FILES': 10000,
    'JSLUICE_TIMEOUT': 300,
    'JSLUICE_EXTRACT_URLS': True,
    'JSLUICE_EXTRACT_SECRETS': True,
    'JSLUICE_CONCURRENCY': 5,
    'JSLUICE_PARALLELISM': 5,
    'JSLUICE_VERIFY_URLS': True,
    'JSLUICE_VERIFY_DOCKER_IMAGE': 'projectdiscovery/httpx:latest',
    'JSLUICE_VERIFY_TIMEOUT': 5,
    'JSLUICE_VERIFY_RATE_LIMIT': 50,
    'JSLUICE_VERIFY_THREADS': 50,
    'JSLUICE_VERIFY_ACCEPT_STATUS': [200, 201, 301, 302, 307, 308, 401, 403],
    'JSLUICE_EXCLUDE_PATTERNS': [
        '/_next/image', '/_next/static', '/_next/data', '/__nextjs',
        '/_nuxt/', '/__nuxt',
        '/runtime.', '/polyfills.', '/vendor.',
        '/webpack', '/chunk.', '.chunk.js', '.bundle.js', 'hot-update',
        '/static/', '/public/', '/dist/', '/build/', '/lib/', '/vendor/', '/node_modules/',
        '.js', '.mjs', '.map', '.css', '.scss', '.sass', '.less',
        '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp', '.avif',
        '.woff', '.woff2', '.ttf', '.eot', '.otf',
        '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.webm',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.zip', '.rar', '.7z', '.tar', '.gz',
        '/rxjs/', '/react/', '/angular/', '/lodash/', '/zone.js/',
    ],

    # ========== JS RECON SCANNER ==========
    'JS_RECON_ENABLED': False,
    'JS_RECON_MAX_FILES': 10000,
    'JS_RECON_TIMEOUT': 900,
    'JS_RECON_CONCURRENCY': 10,
    'JS_RECON_VALIDATE_KEYS': True,
    'JS_RECON_VALIDATION_TIMEOUT': 5,
    'JS_RECON_EXTRACT_ENDPOINTS': True,
    'JS_RECON_VALIDATE_ENDPOINTS': False,
    'JS_RECON_ENDPOINT_ACCEPT_STATUS': [200, 201, 204, 301, 302, 307, 308, 401, 403, 405],
    'JS_RECON_ENDPOINT_CUSTOM_HEADERS': [],
    'JS_RECON_ENDPOINT_CONCURRENCY': 10,
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
    # AI SDK detection — Phase 6 of the Adversarial AI surface recon rollout.
    # Scans every analysed JS file for AI/LLM SDK imports, hard-coded provider
    # keys, ``dangerouslyAllowBrowser`` flags, and AI-frontend product markers
    # that http_probe's Wappalyzer pass cannot see (those live in async-loaded
    # chunks, not the initial HTML body). Default on — pure regex over data
    # js_recon already harvested, sends no additional traffic.
    'JS_RECON_AI_SDK_DETECTION_ENABLED': True,

    # ========== SUPPLY-CHAIN RECON (L2) ==========
    # Black-box package harvest from JS-recon output + offline OSV verdict.
    # Runs in GROUP 5.5 after JS-recon; off by default.
    'SUPPLY_CHAIN_RECON_ENABLED': False,
    # Comma-separated OSV ecosystem allow-filter for the graph write.
    'SUPPLY_CHAIN_RECON_ECOSYSTEMS': 'npm',
    # GuardDog deep analysis (downloads untrusted tarballs). OFF by default
    # (S5.5); dispatch to the DIRTY analyzer is v2.
    'SUPPLY_CHAIN_RECON_DEEP_ANALYSIS_ENABLED': False,
    # A2: correlate discovered hosts against the supply-chain incident catalog.
    # ON by default because it is a local set lookup: no network, no new
    # container, no measurable cost. Inert unless SUPPLY_CHAIN_RECON_ENABLED.
    'SCA_INTEL_CORRELATION_ENABLED': True,
    # D: the fuzzy (edit-distance) typosquat check only. The exact-match lookup
    # always runs - it cannot produce a false positive, since it only reports
    # names the catalog already names.
    'SUPPLY_CHAIN_TYPOSQUAT_ENABLED': False,
    # Import-mining budget. These are genuine in-memory accumulators (every JS
    # file read is held while its specifiers are extracted), so they belong to
    # the memory governor's BYTE-BUDGET model - see _GOV_BUDGET_KEYS. They were
    # module-level os.environ reads in supply_chain_recon.py, which put them out
    # of the governor's reach entirely: apply_memory_governor only walks this
    # dict. Env vars still override, so existing deployments are unaffected.
    'SUPPLY_CHAIN_IMPORT_MAX_FILES': 200,
    'SUPPLY_CHAIN_IMPORT_MAX_BYTES': 64 * 1024 * 1024,

    # FFuf Directory Fuzzer
    'FFUF_ENABLED': False,
    'FFUF_WORDLIST': '/usr/share/seclists/Discovery/Web-Content/common.txt',
    'FFUF_THREADS': 40,
    'FFUF_RATE': 0,
    'FFUF_TIMEOUT': 10,
    'FFUF_MAX_TIME': 1800,
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
    'FFUF_PARALLELISM': 20,
    'FFUF_AI_EXTENSIONS': False,

    # Arjun Parameter Discovery
    'ARJUN_ENABLED': True,
    'ARJUN_THREADS': 2,
    'ARJUN_TIMEOUT': 15,
    'ARJUN_SCAN_TIMEOUT': 600,
    'ARJUN_METHODS': ['GET', 'POST'],
    'ARJUN_MAX_ENDPOINTS': 50000,
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
    # Cascade-gated by AI_IN_PIPELINE. When on, _has_cdn_markers() and
    # check_waf_bypass() fall back to the agent's /llm/waf-classify endpoint
    # if the static Server/header token check returns no match.
    'WAF_AI_CLASSIFIER': False,
    'SECURITY_CHECK_TLS_EXPIRING_SOON': True,
    'SECURITY_CHECK_TLS_EXPIRY_DAYS': 30,
    # TLS-hygiene checks derived from certificate data (tlsx/httpx), per-check so
    # an operator can silence one class of TLS finding without losing the rest.
    'SECURITY_CHECK_TLS_EXPIRED': True,
    'SECURITY_CHECK_TLS_SELF_SIGNED': True,
    'SECURITY_CHECK_TLS_HOSTNAME_MISMATCH': True,
    'SECURITY_CHECK_TLS_WEAK_VERSION': True,
    'SECURITY_CHECK_TLS_WEAK_CIPHER': True,
    'SECURITY_CHECK_TLS_WILDCARD_OVERBROAD': True,
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

    # Origin-IP Discovery (unmask the real server behind a CDN/WAF). Passive
    # source queries + active weighted-similarity validation probes (badge: both).
    'ORIGIN_DISCOVERY_ENABLED': False,
    'ORIGIN_DISCOVERY_KEYLESS': True,        # subdomain probe + SPF/MX + crt.sh + favicon (no key needed)
    'ORIGIN_DISCOVERY_SCANNERS': True,       # Shodan/Censys/FOFA/ZoomEye/OTX/VT (each still needs its own key)
    'ORIGIN_DISCOVERY_PASSIVE_DNS': True,    # SecurityTrails + ViewDNS history
    'ORIGIN_DISCOVERY_MAX_CANDIDATES': 25,   # cap probed candidate IPs per host
    'ORIGIN_DISCOVERY_MAX_SEARCH_CALLS': 50, # per-scan budget of genuine keyed search calls
    'ORIGIN_DISCOVERY_THRESHOLD': 60,        # weighted-similarity confirm threshold (0-100)
    'ORIGIN_DISCOVERY_TIMEOUT': 10,          # per-probe HTTP timeout (seconds)
    'ORIGIN_DISCOVERY_WORKERS': 10,          # bounded fan-out per host
    'ORIGIN_DISCOVERY_RATE': 0,              # active-probe rps ceiling (0 = unlimited); capped by ROE_GLOBAL_MAX_RPS
    'SECURITYTRAILS_API_KEY': '',
    'VIEWDNS_API_KEY': '',

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
    'URLSCAN_MAX_RESULTS': 50000,

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
    'UNCOVER_MAX_RESULTS': 50000,
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

    # AI surface recon hooks inside domain_recon (TXT/NS hint annotation during DNS pass)
    'DOMAIN_RECON_AI_TXT_HINT_ENABLED': True,
    'DOMAIN_RECON_AI_NS_HINT_ENABLED': True,

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
    'AMASS_ENABLED': False,
    'AMASS_MAX_RESULTS': 50000,
    'AMASS_TIMEOUT': 10,
    'AMASS_ACTIVE': False,
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

    # Unified authenticated-session profile (the whole ProjectAuthProfile row,
    # or None). Served only to internal/scanner callers, so it carries the
    # plaintext authValue/extraHeaders here. Consumed via helpers.auth_profile.
    'AUTH_PROFILE': None,
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

    # Web Cache Poisoning (WCVS breadth + native 5-phase confirmation)
    'WEB_CACHE_POISON_ENABLED': False,                          # Master toggle (active, opt-in)
    'WEB_CACHE_POISON_DOCKER_IMAGE': 'redamon-wcvs:latest',     # WCVS image (locally built)
    'WEB_CACHE_POISON_SCAN_PROFILE': 'safe-confirm',           # safe-confirm | extended | research
    'WEB_CACHE_POISON_TIMEOUT': 1800,                          # WCVS subprocess timeout (seconds)
    'WEB_CACHE_POISON_TIMEOUT_PER_REQ': 10,                    # Native confirmation per-request timeout
    'WEB_CACHE_POISON_CONCURRENCY': 10,                        # WCVS threads
    'WEB_CACHE_POISON_CONFIRM_WORKERS': 6,                     # native confirmation parallel workers (URLs in flight)
    'WEB_CACHE_POISON_MAX_RPS_PER_HOST': 0,                    # 0 = unlimited (WCVS -rr)
    'WEB_CACHE_POISON_MIN_CONFIDENCE': 0.8,                    # Only >= this becomes a finding
    'WEB_CACHE_POISON_ALLOW_FRAMEWORK_PACKS': True,           # Next.js/Nuxt/Remix hypothesis packs
    'WEB_CACHE_POISON_ALLOW_DECEPTION': True,                 # Web-cache-deception (.css path tricks)
    'WEB_CACHE_POISON_ALLOW_CPDOS': False,                    # Cache-poisoned DoS (research profile only)
    'WEB_CACHE_POISON_CROSS_VANTAGE': False,                  # Second-vantage revalidation (infra-gated)
    'WEB_CACHE_POISON_CACHE_HEADER': '',                      # Custom cache header (WCVS -ch)
    'WEB_CACHE_POISON_CACHE_BUSTER_PARAM': 'rdmncb',          # Isolation cache-buster param name
    'WEB_CACHE_POISON_VERIFY_SSL': True,
    'WEB_CACHE_POISON_BEHAVIORAL_ORACLE': True,              # Detect silent caches (no cache headers) via frozen-Date probe
    'WEB_CACHE_POISON_BEHAVIORAL_DELAY': 1.1,                # Seconds between the two frozen-Date probes
    'WEB_CACHE_POISON_DIFFERENTIAL': True,                   # Non-reflective detection (status/location/body diff); adds one baseline probe/vector
}


# ---------------------------------------------------------------------------
# V3 — tool Docker image allowlist (anti image-injection)
# ---------------------------------------------------------------------------
# Recon modules read `*_DOCKER_IMAGE` from project settings and pass them
# verbatim to `docker run` on the host Docker daemon (often with `--net=host`).
# These settings are user-editable (Prisma columns + project-settings UI) and
# flow from the webapp API, so an unvalidated value is arbitrary-container
# execution on the host. We pin every tool image to a known-good allowlist at the
# settings chokepoint (`fetch_project_settings`).
#
# The allowlist is the set of images we ship (derived from DEFAULT_SETTINGS so it
# stays in sync as tools are added/bumped) PLUS any images the *operator* approves
# server-side via the `RECON_EXTRA_ALLOWED_IMAGES` env var (comma-separated). The
# env is server-controlled (set on the orchestrator / spawned recon container),
# NOT attacker-influenceable like project settings — so air-gapped / private-
# registry deployments can keep their custom mirror images (e.g.
# `myregistry.local/naabu:latest`) without re-opening the injection hole.
ALLOWED_TOOL_IMAGES = frozenset(
    v for k, v in DEFAULT_SETTINGS.items()
    if k.endswith('_DOCKER_IMAGE') and isinstance(v, str) and v
)


def _env_int(name: str, default: int) -> int:
    """A positive int from env, else the default. Never raises: a typo'd env var
    must not abort a scan's settings load, it just keeps the shipped value."""
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        val = int(raw.strip())
    except (TypeError, ValueError):
        return default
    return val if val > 0 else default


def _operator_allowed_images() -> frozenset:
    """Operator-approved extra images from `RECON_EXTRA_ALLOWED_IMAGES` (env)."""
    raw = os.environ.get('RECON_EXTRA_ALLOWED_IMAGES', '')
    return frozenset(part.strip() for part in raw.split(',') if part.strip())


def sanitize_image_settings(settings: dict[str, Any]) -> dict[str, Any]:
    """Force every `*_DOCKER_IMAGE` setting to a known-good image (V3).

    Allowed = shipped images (``ALLOWED_TOOL_IMAGES``) plus operator-approved
    images from ``RECON_EXTRA_ALLOWED_IMAGES``. A value outside that set is
    replaced with the shipped default for that key (or dropped if the key is
    unknown, so the consumer falls back to its own hardcoded default). Mutates and
    returns ``settings``.
    """
    allowed = ALLOWED_TOOL_IMAGES | _operator_allowed_images()
    for key in list(settings.keys()):
        if not key.endswith('_DOCKER_IMAGE'):
            continue
        value = settings.get(key)
        if isinstance(value, str) and value in allowed:
            continue  # allowlisted — keep
        safe = DEFAULT_SETTINGS.get(key)
        if safe is not None:
            logger.warning(
                f"[guardrail] Rejected non-allowlisted Docker image for {key}: "
                f"{value!r} -> pinned to {safe!r}"
            )
            settings[key] = safe
        else:
            logger.warning(
                f"[guardrail] Dropped unknown Docker image setting {key}={value!r} "
                f"(no shipped default; consumer will use its own)"
            )
            del settings[key]
    return settings


def apply_roe_rate_cap(settings: dict[str, Any]) -> dict[str, Any]:
    """Cap every rate the engagement ceiling applies to. Mutates and returns.

    The key list and the zero-handling set are both REGISTRY QUERIES. They used
    to be two hardcoded lists in this function, and the gap between them was a
    live control failure in three directions at once:

      * `TAKEOVER_RATE_LIMIT` and `JSLUICE_VERIFY_RATE_LIMIT` were settable over
        MCP and in neither list, so a token holding only `recon:settings` could
        run 500 and 1000 rps against a project whose operator had set 3.
      * `PUREDNS_RATE_LIMIT` WAS in the cap list, which made it look covered.
        Its default is 0, 0 means unlimited, and `0 > 3` is False, so it ran
        unlimited. Being in the list is not the same as being capped.
      * `WEB_CACHE_POISON_MAX_RPS_PER_HOST` has the same 0-means-unlimited
        default and was in neither list.

    Deriving both from `roe_capped` and `zero_means` closes all three, and the
    registry's own tests make it impossible to add a fourth: an active `rps`
    field that is not `roe_capped` fails the build.
    """
    roe_max_rps = settings.get('ROE_GLOBAL_MAX_RPS', 0)
    if not settings.get('ROE_ENABLED', False) or not roe_max_rps or roe_max_rps <= 0:
        return settings

    unlimited_at_zero = _registry.unlimited_zero_runtime_keys()
    for key in _registry.roe_capped_runtime_keys():
        value = settings.get(key)
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            continue
        if value == 0 and key in unlimited_at_zero:
            logger.info(f"RoE: capping {key} from unlimited (0) to {roe_max_rps} rps")
            settings[key] = roe_max_rps
        elif value > roe_max_rps:
            logger.info(f"RoE: capping {key} from {value} to {roe_max_rps} rps")
            settings[key] = roe_max_rps
    return settings


# Roots a path-valued setting may resolve inside. Everything else is dropped to
# the shipped default at scan start.
#
# Why this matters more than a file read: ffuf sends each wordlist LINE as a URL
# path and records which ones responded, so a wordlist pointed at a file inside
# the scan container gets its contents reflected into the graph and the scan
# output. That is exfiltration, not just disclosure. The same shape applies to
# any tool that reads a list and reports what matched.
#
# Until the registry work these columns were simply refused by name on the MCP
# surface, and there was no check at all on the recon side. The deny list WAS the
# control; this is what replaces it.
# The one shared root that also holds per-project uploads, at
# `<root>/<project_id>/<name>`. Every OTHER root holds only shipped or
# operator-mounted files, which every project may read.
_PROJECT_UPLOAD_ROOT = "/app/recon/wordlists"

_PROJECT_FILE_ROOTS = (
    "/app/recon/wordlists",      # shipped lists + the per-project upload dir
    "/app/custom_templates",     # operator-supplied nuclei templates
    "/custom-templates",         # the same directory as the scan container sees it
    "/usr/share/seclists",       # shipped system wordlists (the ffuf default)
    "/usr/share/wordlists",
    "/usr/share/dirb",
    "/usr/share/dirbuster",
)


def _inside_allowed_root(raw: Any, project_id: str = "") -> bool:
    """True when `raw` is an absolute path this project may read.

    Fail closed: a value that is not a string, is empty, or cannot be resolved
    counts as escaping. `os.path.realpath` is used rather than `abspath` so a
    symlink planted inside an allowed root cannot point out of it.

    The upload root is SHARED between projects, so "inside an allowed root" is
    not the same question as "this project may read it". Uploads land at
    `<upload root>/<project id>/<name>`, and the tools that read these files
    report what matched, so pointing one at a neighbouring project's directory
    reflects that project's uploaded file into this scan's graph. Inside the
    upload root a path is therefore allowed only when it is a shipped list
    sitting directly in it, or when it is under THIS project's directory.
    """
    if not isinstance(raw, str) or not raw.strip():
        return False
    try:
        resolved = os.path.realpath(raw.strip())
    except (OSError, ValueError):
        return False
    upload_root = os.path.realpath(_PROJECT_UPLOAD_ROOT)
    for root in _PROJECT_FILE_ROOTS:
        real_root = os.path.realpath(root)
        if resolved == real_root:
            return True
        if not resolved.startswith(real_root + os.sep):
            continue
        if real_root != upload_root:
            return True
        relative = resolved[len(real_root) + 1:]
        if os.sep not in relative:
            return True  # a shipped list, not an upload
        return bool(project_id) and relative.split(os.sep, 1)[0] == project_id
    return False


def _is_safe_basename(raw: Any) -> bool:
    """True when `raw` is a plain filename the scan can join onto a directory."""
    if not isinstance(raw, str) or not raw.strip():
        return False
    name = raw.strip()
    if "\0" in name or "/" in name or "\\" in name:
        return False
    if name in (".", "..") or name.startswith("."):
        return False
    return os.path.basename(name) == name


def sanitize_project_file_settings(settings: dict[str, Any]) -> dict[str, Any]:
    """Drop every path-valued setting that escapes its allowed directory.

    Mirrors `sanitize_image_settings`: the column is OPEN and the runtime is the
    control, so an escaping value is replaced with the shipped default and a
    `[guardrail]` line records it rather than the scan failing. The MCP write
    path rejects the same values outright; this is the authoritative half,
    because a row can also be written through the webapp, an import, or a
    restore.

    Both validators come from the registry, so a new path-valued column is
    covered the moment it declares one.
    """
    # The upload directory is shared, so "allowed" is a per-project question.
    # An empty id means we could not establish whose scan this is, and then no
    # upload directory is readable at all.
    project_id = str(settings.get('PROJECT_ID') or '').strip()
    for key in _registry.project_file_runtime_keys():
        if key not in settings:
            continue
        value = settings[key]
        shipped = DEFAULT_SETTINGS.get(key)
        if isinstance(value, list):
            kept = [v for v in value if _inside_allowed_root(v, project_id)]
            if len(kept) != len(value):
                dropped = [v for v in value if v not in kept]
                logger.warning(
                    f"[guardrail] Rejected path(s) outside the allowed directories for "
                    f"{key}: {dropped} -> dropped"
                )
                print(
                    f"[guardrail] Rejected path(s) outside the allowed directories for "
                    f"{key}: {dropped} -> dropped",
                    flush=True,
                )
                settings[key] = kept
            continue
        # An empty string is "not set", which every consumer already handles.
        if value in (None, "") or _inside_allowed_root(value, project_id):
            continue
        logger.warning(
            f"[guardrail] Rejected path outside the allowed directories for {key}: "
            f"{value!r} -> pinned to {shipped!r}"
        )
        print(
            f"[guardrail] Rejected path outside the allowed directories for {key}: "
            f"{value!r} -> pinned to {shipped!r}",
            flush=True,
        )
        settings[key] = shipped

    for key in _registry.project_file_name_runtime_keys():
        if key not in settings:
            continue
        value = settings[key]
        if not isinstance(value, list):
            continue
        kept = [v for v in value if _is_safe_basename(v)]
        if len(kept) != len(value):
            dropped = [v for v in value if v not in kept]
            logger.warning(
                f"[guardrail] Rejected non-filename entr(ies) for {key}: {dropped} -> dropped"
            )
            print(
                f"[guardrail] Rejected non-filename entr(ies) for {key}: {dropped} -> dropped",
                flush=True,
            )
            settings[key] = kept
    return settings


def _fetch_user_api_key(user_id: str, webapp_url: str, key_name: str) -> str:
    """Fetch an unmasked API key from user's global settings."""
    import requests as _req
    try:
        url = f"{webapp_url.rstrip('/')}/api/users/{user_id}/settings?internal=true"
        _headers = {"X-Internal-Key": (os.environ.get("SCANNER_API_KEY") or os.environ.get("INTERNAL_API_KEY", ""))}
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
        _headers = {"X-Internal-Key": (os.environ.get("SCANNER_API_KEY") or os.environ.get("INTERNAL_API_KEY", ""))}
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


_BATCH_HOST_CHARSET = re.compile(r'^[a-z0-9.-]+$')


def _is_public_suffix(root: str) -> bool:
    """Is this 'registrable domain' actually a public suffix, e.g. ``co.uk``?

    The batch grouping rule is last-two-labels, so ``acme.co.uk`` reduces to
    ``co.uk``. Harmless for a literal group (it still scans only the host that
    was listed) and NOT harmless for a wildcard one.

    Imported lazily from origin_discovery, which owns the curated list for the
    same reason: a module-level import would pull a scan module into the settings
    layer, and this is the only place that needs it.
    """
    try:
        from recon.main_recon_modules.origin_discovery import _MULTI_LABEL_SUFFIXES
    except Exception as e:  # noqa: BLE001 - a missing list must not admit the wildcard
        # Fail closed, but never silently: this answer demotes EVERY wildcard in
        # the run to a literal scan, which looks like a working scan that simply
        # found less.
        print(f"[!][settings] public-suffix list unavailable ({e}); treating every "
              f"wildcard root as a public suffix, so no group will enumerate.")
        return True
    return root in _MULTI_LABEL_SUFFIXES


def _parse_domain_batch_groups(raw: Any) -> list[dict[str, Any]]:
    """Parse and RE-VALIDATE the webapp's derived domain-batch groups.

    The webapp already validates the operator's hostname list, but these strings
    end up as scan targets and as a component of an output filename, so they cross
    a trust boundary a second time here. Re-checking the charset is what stops a
    row edited directly in the database (the PUT route does not lock target fields)
    from reaching a path or a tool argument.

    Malformed entries are DROPPED rather than repaired: a repaired hostname would
    scan something the operator never approved in the preview. A group that loses
    every prefix is dropped whole.
    """
    if not isinstance(raw, list):
        return []

    groups: list[dict[str, Any]] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        root = str(entry.get('rootDomain') or '').strip().lower()
        if not root or not _BATCH_HOST_CHARSET.match(root) or '..' in root:
            continue
        prefixes = [
            p.strip().lower() for p in (entry.get('prefixes') or [])
            if isinstance(p, str) and p.strip()
        ]
        # Two sentinels, neither of which is a hostname: '.' is "the root domain
        # itself" and '*' is "enumerate this domain" (see parse_target). Both are
        # matched EXACTLY, so the charset below stays free of metacharacters and
        # a '*' anywhere other than a whole prefix is still dropped.
        prefixes = [
            p for p in prefixes
            if p in ('.', '*') or (_BATCH_HOST_CHARSET.match(p) and '..' not in p)
        ]
        if not prefixes:
            continue
        # A wildcard on a public suffix would enumerate every subdomain of, say,
        # co.uk. The webapp already refuses it, but scope is re-derived here for
        # rows that never went through the form, so it is refused here too — by
        # demoting the group to literal rather than dropping it, because dropping
        # it would silently shrink a scope the operator can see in the preview.
        if '*' in prefixes and _is_public_suffix(root):
            prefixes = [p for p in prefixes if p != '*']
            print(f"[!][settings] '{root}' is a public suffix; wildcard ignored "
                  f"for that group (it would enumerate the whole suffix).")
            if not prefixes:
                continue
        groups.append({'rootDomain': root, 'prefixes': prefixes})

    return groups


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

    _internal_headers = {"X-Internal-Key": (os.environ.get("SCANNER_API_KEY") or os.environ.get("INTERNAL_API_KEY", ""))}
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
    settings['DOMAIN_BATCH_MODE'] = project.get(
        'domainBatchMode', DEFAULT_SETTINGS['DOMAIN_BATCH_MODE'])
    settings['DOMAIN_BATCH_GROUPS'] = _parse_domain_batch_groups(
        project.get('domainBatchGroups'))
    settings['VERIFY_DOMAIN_OWNERSHIP'] = project.get('verifyDomainOwnership', DEFAULT_SETTINGS['VERIFY_DOMAIN_OWNERSHIP'])
    settings['OWNERSHIP_TOKEN'] = project.get('ownershipToken', DEFAULT_SETTINGS['OWNERSHIP_TOKEN'])
    settings['OWNERSHIP_TXT_PREFIX'] = project.get('ownershipTxtPrefix', DEFAULT_SETTINGS['OWNERSHIP_TXT_PREFIX'])

    # Scan Modules
    settings['SCAN_MODULES'] = project.get('scanModules', DEFAULT_SETTINGS['SCAN_MODULES'])
    settings['UPDATE_GRAPH_DB'] = project.get('updateGraphDb', DEFAULT_SETTINGS['UPDATE_GRAPH_DB'])
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
    settings['PORT_SCAN_AI_PORT_CATALOG_ENABLED'] = project.get('portScanAiPortCatalogEnabled', DEFAULT_SETTINGS['PORT_SCAN_AI_PORT_CATALOG_ENABLED'])

    # Masscan Port Scanner
    settings['MASSCAN_ENABLED'] = project.get('masscanEnabled', DEFAULT_SETTINGS['MASSCAN_ENABLED'])
    settings['MASSCAN_TOP_PORTS'] = project.get('masscanTopPorts', DEFAULT_SETTINGS['MASSCAN_TOP_PORTS'])
    settings['MASSCAN_CUSTOM_PORTS'] = project.get('masscanCustomPorts', DEFAULT_SETTINGS['MASSCAN_CUSTOM_PORTS'])
    settings['MASSCAN_RATE'] = project.get('masscanRate', DEFAULT_SETTINGS['MASSCAN_RATE'])
    settings['MASSCAN_BANNERS'] = project.get('masscanBanners', DEFAULT_SETTINGS['MASSCAN_BANNERS'])
    settings['MASSCAN_WAIT'] = project.get('masscanWait', DEFAULT_SETTINGS['MASSCAN_WAIT'])
    settings['MASSCAN_RETRIES'] = project.get('masscanRetries', DEFAULT_SETTINGS['MASSCAN_RETRIES'])
    settings['MASSCAN_EXCLUDE_TARGETS'] = project.get('masscanExcludeTargets', DEFAULT_SETTINGS['MASSCAN_EXCLUDE_TARGETS'])
    settings['MASSCAN_AI_PORT_CATALOG_ENABLED'] = project.get('masscanAiPortCatalogEnabled', DEFAULT_SETTINGS['MASSCAN_AI_PORT_CATALOG_ENABLED'])

    # Nmap Service Detection & NSE Vuln Scripts
    settings['NMAP_ENABLED'] = project.get('nmapEnabled', DEFAULT_SETTINGS['NMAP_ENABLED'])
    settings['NMAP_VERSION_DETECTION'] = project.get('nmapVersionDetection', DEFAULT_SETTINGS['NMAP_VERSION_DETECTION'])
    settings['NMAP_SCRIPT_SCAN'] = project.get('nmapScriptScan', DEFAULT_SETTINGS['NMAP_SCRIPT_SCAN'])
    settings['NMAP_TIMING_TEMPLATE'] = project.get('nmapTimingTemplate', DEFAULT_SETTINGS['NMAP_TIMING_TEMPLATE'])
    settings['NMAP_TIMEOUT'] = project.get('nmapTimeout', DEFAULT_SETTINGS['NMAP_TIMEOUT'])
    settings['NMAP_HOST_TIMEOUT'] = project.get('nmapHostTimeout', DEFAULT_SETTINGS['NMAP_HOST_TIMEOUT'])
    settings['NMAP_PARALLELISM'] = project.get('nmapParallelism', DEFAULT_SETTINGS['NMAP_PARALLELISM'])
    settings['NMAP_AI_VERSION_REGEX_ENABLED'] = project.get('nmapAiVersionRegexEnabled', DEFAULT_SETTINGS['NMAP_AI_VERSION_REGEX_ENABLED'])

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
    settings['HTTP_PROBE_AI_HEADER_SCAN_ENABLED'] = project.get('httpProbeAiHeaderScanEnabled', DEFAULT_SETTINGS['HTTP_PROBE_AI_HEADER_SCAN_ENABLED'])
    settings['HTTP_PROBE_AI_FAVICON_HASH_ENABLED'] = project.get('httpProbeAiFaviconHashEnabled', DEFAULT_SETTINGS['HTTP_PROBE_AI_FAVICON_HASH_ENABLED'])
    settings['HTTP_PROBE_AI_TITLE_DETECTION_ENABLED'] = project.get('httpProbeAiTitleDetectionEnabled', DEFAULT_SETTINGS['HTTP_PROBE_AI_TITLE_DETECTION_ENABLED'])
    settings['HTTP_PROBE_AI_WAPPALYZER_ENABLED'] = project.get('httpProbeAiWappalyzerEnabled', DEFAULT_SETTINGS['HTTP_PROBE_AI_WAPPALYZER_ENABLED'])

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
    settings['NUCLEI_AI_TAGS'] = project.get('nucleiAiTags', DEFAULT_SETTINGS['NUCLEI_AI_TAGS'])
    settings['NUCLEI_AI_RESPONSE_FILTER'] = project.get('nucleiAiResponseFilter', DEFAULT_SETTINGS['NUCLEI_AI_RESPONSE_FILTER'])

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
    settings['TAKEOVER_AI_CLASSIFIER'] = project.get('takeoverAiClassifier', DEFAULT_SETTINGS['TAKEOVER_AI_CLASSIFIER'])
    settings['BADDNS_ENABLED'] = project.get('baddnsEnabled', DEFAULT_SETTINGS['BADDNS_ENABLED'])
    settings['BADDNS_DOCKER_IMAGE'] = project.get('baddnsDockerImage', DEFAULT_SETTINGS['BADDNS_DOCKER_IMAGE'])
    settings['BADDNS_MODULES'] = project.get('baddnsModules', DEFAULT_SETTINGS['BADDNS_MODULES'])
    settings['BADDNS_NAMESERVERS'] = project.get('baddnsNameservers', DEFAULT_SETTINGS['BADDNS_NAMESERVERS'])
    settings['BADDNS_RUN_TIMEOUT'] = project.get('baddnsRunTimeout', DEFAULT_SETTINGS['BADDNS_RUN_TIMEOUT'])

    # VHost & SNI Enumeration
    settings['VHOST_SNI_ENABLED'] = project.get('vhostSniEnabled', DEFAULT_SETTINGS['VHOST_SNI_ENABLED'])
    settings['VHOST_SNI_TIMEOUT'] = project.get('vhostSniTimeout', DEFAULT_SETTINGS['VHOST_SNI_TIMEOUT'])
    settings['VHOST_SNI_CONCURRENCY'] = project.get('vhostSniConcurrency', DEFAULT_SETTINGS['VHOST_SNI_CONCURRENCY'])
    settings['VHOST_SNI_BASELINE_SIZE_TOLERANCE'] = project.get('vhostSniBaselineSizeTolerance', DEFAULT_SETTINGS['VHOST_SNI_BASELINE_SIZE_TOLERANCE'])
    settings['VHOST_SNI_TEST_L7'] = project.get('vhostSniTestL7', DEFAULT_SETTINGS['VHOST_SNI_TEST_L7'])
    settings['VHOST_SNI_TEST_L4'] = project.get('vhostSniTestL4', DEFAULT_SETTINGS['VHOST_SNI_TEST_L4'])
    settings['VHOST_SNI_INJECT_DISCOVERED'] = project.get('vhostSniInjectDiscovered', DEFAULT_SETTINGS['VHOST_SNI_INJECT_DISCOVERED'])
    settings['VHOST_SNI_USE_DEFAULT_WORDLIST'] = project.get('vhostSniUseDefaultWordlist', DEFAULT_SETTINGS['VHOST_SNI_USE_DEFAULT_WORDLIST'])
    settings['VHOST_SNI_USE_GRAPH_CANDIDATES'] = project.get('vhostSniUseGraphCandidates', DEFAULT_SETTINGS['VHOST_SNI_USE_GRAPH_CANDIDATES'])
    settings['VHOST_SNI_CUSTOM_WORDLIST'] = project.get('vhostSniCustomWordlist', DEFAULT_SETTINGS['VHOST_SNI_CUSTOM_WORDLIST'])
    settings['VHOST_SNI_MAX_CANDIDATES_PER_IP'] = project.get('vhostSniMaxCandidatesPerIp', DEFAULT_SETTINGS['VHOST_SNI_MAX_CANDIDATES_PER_IP'])

    # tlsx TLS certificate grab
    settings['TLSX_ENABLED'] = project.get('tlsxEnabled', DEFAULT_SETTINGS['TLSX_ENABLED'])
    settings['TLSX_DOCKER_IMAGE'] = project.get('tlsxDockerImage', DEFAULT_SETTINGS['TLSX_DOCKER_IMAGE'])
    settings['TLSX_SCAN_MODE'] = project.get('tlsxScanMode', DEFAULT_SETTINGS['TLSX_SCAN_MODE'])
    settings['TLSX_CONCURRENCY'] = project.get('tlsxConcurrency', DEFAULT_SETTINGS['TLSX_CONCURRENCY'])
    settings['TLSX_TIMEOUT'] = project.get('tlsxTimeout', DEFAULT_SETTINGS['TLSX_TIMEOUT'])
    settings['TLSX_RUN_TIMEOUT'] = project.get('tlsxRunTimeout', DEFAULT_SETTINGS['TLSX_RUN_TIMEOUT'])
    settings['TLSX_RETRIES'] = project.get('tlsxRetries', DEFAULT_SETTINGS['TLSX_RETRIES'])
    settings['TLSX_MAX_INJECTED_HOSTNAMES'] = project.get('tlsxMaxInjectedHostnames', DEFAULT_SETTINGS['TLSX_MAX_INJECTED_HOSTNAMES'])
    settings['TLSX_DELAY'] = project.get('tlsxDelay', DEFAULT_SETTINGS['TLSX_DELAY'])
    settings['TLSX_INCLUDE_HTTP_PORTS'] = project.get('tlsxIncludeHttpPorts', DEFAULT_SETTINGS['TLSX_INCLUDE_HTTP_PORTS'])
    settings['TLSX_INJECT_HOSTNAMES'] = project.get('tlsxInjectHostnames', DEFAULT_SETTINGS['TLSX_INJECT_HOSTNAMES'])
    settings['TLSX_REV_PTR_SNI'] = project.get('tlsxRevPtrSni', DEFAULT_SETTINGS['TLSX_REV_PTR_SNI'])
    settings['TLSX_MAX_HOSTNAMES_PER_IP'] = project.get('tlsxMaxHostnamesPerIp', DEFAULT_SETTINGS['TLSX_MAX_HOSTNAMES_PER_IP'])
    settings['TLSX_PROBE_JARM'] = project.get('tlsxProbeJarm', DEFAULT_SETTINGS['TLSX_PROBE_JARM'])
    settings['TLSX_VERSION_ENUM'] = project.get('tlsxVersionEnum', DEFAULT_SETTINGS['TLSX_VERSION_ENUM'])
    settings['TLSX_CIPHER_ENUM'] = project.get('tlsxCipherEnum', DEFAULT_SETTINGS['TLSX_CIPHER_ENUM'])
    settings['TLSX_CIPHER_CONCURRENCY'] = project.get('tlsxCipherConcurrency', DEFAULT_SETTINGS['TLSX_CIPHER_CONCURRENCY'])
    settings['TLSX_MAX_TARGETS'] = project.get('tlsxMaxTargets', DEFAULT_SETTINGS['TLSX_MAX_TARGETS'])
    settings['TAKEOVER_CERT_VALIDATION_ENABLED'] = project.get('takeoverCertValidationEnabled', DEFAULT_SETTINGS['TAKEOVER_CERT_VALIDATION_ENABLED'])

    # Resource Enum AI Classifier
    settings['RESOURCE_ENUM_AI_CLASSIFIER_ENABLED'] = project.get('resourceEnumAiClassifierEnabled', DEFAULT_SETTINGS['RESOURCE_ENUM_AI_CLASSIFIER_ENABLED'])
    settings['RESOURCE_ENUM_AI_PATH_CLASSIFIER_ENABLED'] = project.get('resourceEnumAiPathClassifierEnabled', DEFAULT_SETTINGS['RESOURCE_ENUM_AI_PATH_CLASSIFIER_ENABLED'])
    settings['RESOURCE_ENUM_AI_RAG_PATH_FLAG_ENABLED'] = project.get('resourceEnumAiRagPathFlagEnabled', DEFAULT_SETTINGS['RESOURCE_ENUM_AI_RAG_PATH_FLAG_ENABLED'])
    settings['RESOURCE_ENUM_AI_PARAM_INJECTABLE_FLAG_ENABLED'] = project.get('resourceEnumAiParamInjectableFlagEnabled', DEFAULT_SETTINGS['RESOURCE_ENUM_AI_PARAM_INJECTABLE_FLAG_ENABLED'])
    settings['RESOURCE_ENUM_AI_TOOL_ARG_PATH_ENABLED'] = project.get('resourceEnumAiToolArgPathEnabled', DEFAULT_SETTINGS['RESOURCE_ENUM_AI_TOOL_ARG_PATH_ENABLED'])

    # AI Surface Recon (central module)
    settings['AI_SURFACE_RECON_ENABLED'] = project.get('aiSurfaceReconEnabled', DEFAULT_SETTINGS['AI_SURFACE_RECON_ENABLED'])
    settings['AI_SURFACE_RECON_TIMEOUT'] = project.get('aiSurfaceReconTimeout', DEFAULT_SETTINGS['AI_SURFACE_RECON_TIMEOUT'])
    settings['AI_SURFACE_RECON_MAX_WORKERS'] = project.get('aiSurfaceReconMaxWorkers', DEFAULT_SETTINGS['AI_SURFACE_RECON_MAX_WORKERS'])
    settings['AI_SURFACE_RECON_USER_AGENT'] = project.get('aiSurfaceReconUserAgent', DEFAULT_SETTINGS['AI_SURFACE_RECON_USER_AGENT'])
    settings['AI_SURFACE_RECON_CHAT_SHAPE_PROBE_ENABLED'] = project.get('aiSurfaceReconChatShapeProbeEnabled', DEFAULT_SETTINGS['AI_SURFACE_RECON_CHAT_SHAPE_PROBE_ENABLED'])
    settings['AI_SURFACE_RECON_MCP_HANDSHAKE_ENABLED'] = project.get('aiSurfaceReconMcpHandshakeEnabled', DEFAULT_SETTINGS['AI_SURFACE_RECON_MCP_HANDSHAKE_ENABLED'])
    settings['AI_SURFACE_RECON_MCP_LIST_TOOLS_ENABLED'] = project.get('aiSurfaceReconMcpListToolsEnabled', DEFAULT_SETTINGS['AI_SURFACE_RECON_MCP_LIST_TOOLS_ENABLED'])
    settings['AI_SURFACE_RECON_MCP_YARA_ENABLED'] = project.get('aiSurfaceReconMcpYaraEnabled', DEFAULT_SETTINGS['AI_SURFACE_RECON_MCP_YARA_ENABLED'])
    settings['AI_SURFACE_RECON_OPENAPI_DISCOVERY_ENABLED'] = project.get('aiSurfaceReconOpenapiDiscoveryEnabled', DEFAULT_SETTINGS['AI_SURFACE_RECON_OPENAPI_DISCOVERY_ENABLED'])
    settings['AI_SURFACE_RECON_MODEL_LIST_ENABLED'] = project.get('aiSurfaceReconModelListEnabled', DEFAULT_SETTINGS['AI_SURFACE_RECON_MODEL_LIST_ENABLED'])
    settings['AI_SURFACE_RECON_VECTOR_DB_READ_ENABLED'] = project.get('aiSurfaceReconVectorDbReadEnabled', DEFAULT_SETTINGS['AI_SURFACE_RECON_VECTOR_DB_READ_ENABLED'])
    settings['AI_SURFACE_RECON_JULIUS_PROBE_PACK_ENABLED'] = project.get('aiSurfaceReconJuliusProbePackEnabled', DEFAULT_SETTINGS['AI_SURFACE_RECON_JULIUS_PROBE_PACK_ENABLED'])
    settings['AI_SURFACE_RECON_LATENCY_BASELINE_ENABLED'] = project.get('aiSurfaceReconLatencyBaselineEnabled', DEFAULT_SETTINGS['AI_SURFACE_RECON_LATENCY_BASELINE_ENABLED'])
    settings['AI_SURFACE_RECON_CACHE_ENABLED'] = project.get('aiSurfaceReconCacheEnabled', DEFAULT_SETTINGS['AI_SURFACE_RECON_CACHE_ENABLED'])
    settings['AI_SURFACE_RECON_PROBE_PACK_VERSION'] = project.get('aiSurfaceReconProbePackVersion', DEFAULT_SETTINGS['AI_SURFACE_RECON_PROBE_PACK_VERSION'])

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

    settings['OPENAPI_ENABLED'] = project.get('openapiEnabled', DEFAULT_SETTINGS['OPENAPI_ENABLED'])
    settings['OPENAPI_DISCOVERY_PATHS'] = project.get('openapiDiscoveryPaths', DEFAULT_SETTINGS['OPENAPI_DISCOVERY_PATHS'])
    settings['OPENAPI_AUTO_DISCOVER'] = project.get('openapiAutoDiscover', DEFAULT_SETTINGS['OPENAPI_AUTO_DISCOVER'])
    settings['OPENAPI_SOURCES'] = project.get('openapiSources', DEFAULT_SETTINGS['OPENAPI_SOURCES'])
    settings['OPENAPI_TIMEOUT'] = project.get('openapiTimeout', DEFAULT_SETTINGS['OPENAPI_TIMEOUT'])
    settings['OPENAPI_MAX_DOCUMENTS'] = project.get('openapiMaxDocuments', DEFAULT_SETTINGS['OPENAPI_MAX_DOCUMENTS'])

    # HTTP Traffic Capture (mitmproxy integration, Phase 0+)
    settings['CAPTURE_PROXY_ENABLED'] = project.get('captureProxyEnabled', DEFAULT_SETTINGS['CAPTURE_PROXY_ENABLED'])

    # ZAP Ajax Spider Browser Crawler
    settings['ZAP_AJAX_SPIDER_ENABLED'] = project.get('zapAjaxSpiderEnabled', DEFAULT_SETTINGS['ZAP_AJAX_SPIDER_ENABLED'])
    settings['ZAP_AJAX_SPIDER_DOCKER_IMAGE'] = project.get('zapAjaxSpiderDockerImage', DEFAULT_SETTINGS['ZAP_AJAX_SPIDER_DOCKER_IMAGE'])
    settings['ZAP_AJAX_SPIDER_SEED_MODE'] = project.get('zapAjaxSpiderSeedMode', DEFAULT_SETTINGS['ZAP_AJAX_SPIDER_SEED_MODE'])
    settings['ZAP_AJAX_SPIDER_MAX_DURATION'] = project.get('zapAjaxSpiderMaxDuration', DEFAULT_SETTINGS['ZAP_AJAX_SPIDER_MAX_DURATION'])
    settings['ZAP_AJAX_SPIDER_MAX_CRAWL_DEPTH'] = project.get('zapAjaxSpiderMaxCrawlDepth', DEFAULT_SETTINGS['ZAP_AJAX_SPIDER_MAX_CRAWL_DEPTH'])
    settings['ZAP_AJAX_SPIDER_MAX_CRAWL_STATES'] = project.get('zapAjaxSpiderMaxCrawlStates', DEFAULT_SETTINGS['ZAP_AJAX_SPIDER_MAX_CRAWL_STATES'])
    settings['ZAP_AJAX_SPIDER_NUMBER_OF_BROWSERS'] = project.get('zapAjaxSpiderNumberOfBrowsers', DEFAULT_SETTINGS['ZAP_AJAX_SPIDER_NUMBER_OF_BROWSERS'])
    settings['ZAP_AJAX_SPIDER_BROWSER_ID'] = project.get('zapAjaxSpiderBrowserId', DEFAULT_SETTINGS['ZAP_AJAX_SPIDER_BROWSER_ID'])
    settings['ZAP_AJAX_SPIDER_EVENT_WAIT'] = project.get('zapAjaxSpiderEventWait', DEFAULT_SETTINGS['ZAP_AJAX_SPIDER_EVENT_WAIT'])
    settings['ZAP_AJAX_SPIDER_RELOAD_WAIT'] = project.get('zapAjaxSpiderReloadWait', DEFAULT_SETTINGS['ZAP_AJAX_SPIDER_RELOAD_WAIT'])
    settings['ZAP_AJAX_SPIDER_CLICK_DEFAULT_ELEMS'] = project.get('zapAjaxSpiderClickDefaultElems', DEFAULT_SETTINGS['ZAP_AJAX_SPIDER_CLICK_DEFAULT_ELEMS'])
    settings['ZAP_AJAX_SPIDER_CLICK_ELEMS_ONCE'] = project.get('zapAjaxSpiderClickElemsOnce', DEFAULT_SETTINGS['ZAP_AJAX_SPIDER_CLICK_ELEMS_ONCE'])
    settings['ZAP_AJAX_SPIDER_RANDOM_INPUTS'] = project.get('zapAjaxSpiderRandomInputs', DEFAULT_SETTINGS['ZAP_AJAX_SPIDER_RANDOM_INPUTS'])
    settings['ZAP_AJAX_SPIDER_LOGOUT_AVOIDANCE'] = project.get('zapAjaxSpiderLogoutAvoidance', DEFAULT_SETTINGS['ZAP_AJAX_SPIDER_LOGOUT_AVOIDANCE'])
    settings['ZAP_AJAX_SPIDER_SCOPE_CHECK'] = project.get('zapAjaxSpiderScopeCheck', DEFAULT_SETTINGS['ZAP_AJAX_SPIDER_SCOPE_CHECK'])
    settings['ZAP_AJAX_SPIDER_CUSTOM_HEADERS'] = project.get('zapAjaxSpiderCustomHeaders', DEFAULT_SETTINGS['ZAP_AJAX_SPIDER_CUSTOM_HEADERS'])
    settings['ZAP_AJAX_SPIDER_EXCLUDE_PATTERNS'] = project.get('zapAjaxSpiderExcludePatterns', DEFAULT_SETTINGS['ZAP_AJAX_SPIDER_EXCLUDE_PATTERNS'])
    settings['ZAP_AJAX_SPIDER_MAX_URLS'] = project.get('zapAjaxSpiderMaxUrls', DEFAULT_SETTINGS['ZAP_AJAX_SPIDER_MAX_URLS'])
    settings['ZAP_AJAX_SPIDER_PARALLELISM'] = project.get('zapAjaxSpiderParallelism', DEFAULT_SETTINGS['ZAP_AJAX_SPIDER_PARALLELISM'])

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
    settings['JSLUICE_VERIFY_URLS'] = project.get('jsluiceVerifyUrls', DEFAULT_SETTINGS['JSLUICE_VERIFY_URLS'])
    settings['JSLUICE_VERIFY_DOCKER_IMAGE'] = project.get('jsluiceVerifyDockerImage', DEFAULT_SETTINGS['JSLUICE_VERIFY_DOCKER_IMAGE'])
    settings['JSLUICE_VERIFY_TIMEOUT'] = project.get('jsluiceVerifyTimeout', DEFAULT_SETTINGS['JSLUICE_VERIFY_TIMEOUT'])
    settings['JSLUICE_VERIFY_RATE_LIMIT'] = project.get('jsluiceVerifyRateLimit', DEFAULT_SETTINGS['JSLUICE_VERIFY_RATE_LIMIT'])
    settings['JSLUICE_VERIFY_THREADS'] = project.get('jsluiceVerifyThreads', DEFAULT_SETTINGS['JSLUICE_VERIFY_THREADS'])
    # Treat empty arrays as "use defaults" so DB rows defaulted to [] don't silently disable filtering/status acceptance.
    accept_status = project.get('jsluiceVerifyAcceptStatus') or DEFAULT_SETTINGS['JSLUICE_VERIFY_ACCEPT_STATUS']
    settings['JSLUICE_VERIFY_ACCEPT_STATUS'] = accept_status
    exclude_patterns = project.get('jsluiceExcludePatterns') or DEFAULT_SETTINGS['JSLUICE_EXCLUDE_PATTERNS']
    settings['JSLUICE_EXCLUDE_PATTERNS'] = exclude_patterns

    # JS Recon Scanner
    settings['SUPPLY_CHAIN_RECON_ENABLED'] = project.get('supplyChainReconEnabled', DEFAULT_SETTINGS['SUPPLY_CHAIN_RECON_ENABLED'])
    settings['SUPPLY_CHAIN_RECON_ECOSYSTEMS'] = project.get('supplyChainReconEcosystems', DEFAULT_SETTINGS['SUPPLY_CHAIN_RECON_ECOSYSTEMS'])
    settings['SUPPLY_CHAIN_RECON_DEEP_ANALYSIS_ENABLED'] = project.get('supplyChainReconDeepAnalysisEnabled', DEFAULT_SETTINGS['SUPPLY_CHAIN_RECON_DEEP_ANALYSIS_ENABLED'])
    settings['SCA_INTEL_CORRELATION_ENABLED'] = project.get('scaIntelCorrelationEnabled', DEFAULT_SETTINGS['SCA_INTEL_CORRELATION_ENABLED'])
    settings['SUPPLY_CHAIN_TYPOSQUAT_ENABLED'] = project.get('supplyChainTyposquatEnabled', DEFAULT_SETTINGS['SUPPLY_CHAIN_TYPOSQUAT_ENABLED'])
    # Not exposed in the UI (internal budgets): env override, else the default.
    # They live in settings so apply_memory_governor can byte-budget them.
    settings['SUPPLY_CHAIN_IMPORT_MAX_FILES'] = _env_int('SUPPLY_CHAIN_IMPORT_MAX_FILES', DEFAULT_SETTINGS['SUPPLY_CHAIN_IMPORT_MAX_FILES'])
    settings['SUPPLY_CHAIN_IMPORT_MAX_BYTES'] = _env_int('SUPPLY_CHAIN_IMPORT_MAX_BYTES', DEFAULT_SETTINGS['SUPPLY_CHAIN_IMPORT_MAX_BYTES'])
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
    settings['JS_RECON_VALIDATE_ENDPOINTS'] = project.get('jsReconValidateEndpoints', DEFAULT_SETTINGS['JS_RECON_VALIDATE_ENDPOINTS'])
    settings['JS_RECON_ENDPOINT_ACCEPT_STATUS'] = project.get('jsReconEndpointAcceptStatus') or DEFAULT_SETTINGS['JS_RECON_ENDPOINT_ACCEPT_STATUS']
    settings['JS_RECON_ENDPOINT_CUSTOM_HEADERS'] = project.get('jsReconEndpointCustomHeaders', DEFAULT_SETTINGS['JS_RECON_ENDPOINT_CUSTOM_HEADERS'])
    settings['JS_RECON_ENDPOINT_CONCURRENCY'] = project.get('jsReconEndpointConcurrency', DEFAULT_SETTINGS['JS_RECON_ENDPOINT_CONCURRENCY'])
    settings['JS_RECON_AI_SDK_DETECTION_ENABLED'] = project.get('jsReconAiSdkDetectionEnabled', DEFAULT_SETTINGS['JS_RECON_AI_SDK_DETECTION_ENABLED'])

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
    settings['FFUF_AI_EXTENSIONS'] = project.get('ffufAiExtensions', DEFAULT_SETTINGS['FFUF_AI_EXTENSIONS'])

    # AI in Pipeline (master switch + model)
    settings['AI_IN_PIPELINE'] = project.get('aiInPipeline', DEFAULT_SETTINGS['AI_IN_PIPELINE'])
    settings['AI_PIPELINE_MODEL'] = project.get('aiPipelineModel', DEFAULT_SETTINGS['AI_PIPELINE_MODEL'])

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
    settings['WAF_AI_CLASSIFIER'] = project.get('wafAiClassifier', DEFAULT_SETTINGS['WAF_AI_CLASSIFIER'])
    settings['SECURITY_CHECK_TLS_EXPIRING_SOON'] = project.get('securityCheckTlsExpiringSoon', DEFAULT_SETTINGS['SECURITY_CHECK_TLS_EXPIRING_SOON'])
    settings['SECURITY_CHECK_TLS_EXPIRY_DAYS'] = project.get('securityCheckTlsExpiryDays', DEFAULT_SETTINGS['SECURITY_CHECK_TLS_EXPIRY_DAYS'])
    settings['SECURITY_CHECK_TLS_EXPIRED'] = project.get('securityCheckTlsExpired', DEFAULT_SETTINGS['SECURITY_CHECK_TLS_EXPIRED'])
    settings['SECURITY_CHECK_TLS_SELF_SIGNED'] = project.get('securityCheckTlsSelfSigned', DEFAULT_SETTINGS['SECURITY_CHECK_TLS_SELF_SIGNED'])
    settings['SECURITY_CHECK_TLS_HOSTNAME_MISMATCH'] = project.get('securityCheckTlsHostnameMismatch', DEFAULT_SETTINGS['SECURITY_CHECK_TLS_HOSTNAME_MISMATCH'])
    settings['SECURITY_CHECK_TLS_WEAK_VERSION'] = project.get('securityCheckTlsWeakVersion', DEFAULT_SETTINGS['SECURITY_CHECK_TLS_WEAK_VERSION'])
    settings['SECURITY_CHECK_TLS_WEAK_CIPHER'] = project.get('securityCheckTlsWeakCipher', DEFAULT_SETTINGS['SECURITY_CHECK_TLS_WEAK_CIPHER'])
    settings['SECURITY_CHECK_TLS_WILDCARD_OVERBROAD'] = project.get('securityCheckTlsWildcardOverbroad', DEFAULT_SETTINGS['SECURITY_CHECK_TLS_WILDCARD_OVERBROAD'])
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

    # Origin-IP Discovery (ORIGIN_DISCOVERY_RATE is internal — no camelCase mapping)
    settings['ORIGIN_DISCOVERY_ENABLED'] = project.get('originDiscoveryEnabled', DEFAULT_SETTINGS['ORIGIN_DISCOVERY_ENABLED'])
    settings['ORIGIN_DISCOVERY_KEYLESS'] = project.get('originDiscoveryKeyless', DEFAULT_SETTINGS['ORIGIN_DISCOVERY_KEYLESS'])
    settings['ORIGIN_DISCOVERY_SCANNERS'] = project.get('originDiscoveryScanners', DEFAULT_SETTINGS['ORIGIN_DISCOVERY_SCANNERS'])
    settings['ORIGIN_DISCOVERY_PASSIVE_DNS'] = project.get('originDiscoveryPassiveDns', DEFAULT_SETTINGS['ORIGIN_DISCOVERY_PASSIVE_DNS'])
    settings['ORIGIN_DISCOVERY_MAX_CANDIDATES'] = project.get('originDiscoveryMaxCandidates', DEFAULT_SETTINGS['ORIGIN_DISCOVERY_MAX_CANDIDATES'])
    settings['ORIGIN_DISCOVERY_MAX_SEARCH_CALLS'] = project.get('originDiscoveryMaxSearchCalls', DEFAULT_SETTINGS['ORIGIN_DISCOVERY_MAX_SEARCH_CALLS'])
    settings['ORIGIN_DISCOVERY_THRESHOLD'] = project.get('originDiscoveryThreshold', DEFAULT_SETTINGS['ORIGIN_DISCOVERY_THRESHOLD'])
    settings['ORIGIN_DISCOVERY_TIMEOUT'] = project.get('originDiscoveryTimeout', DEFAULT_SETTINGS['ORIGIN_DISCOVERY_TIMEOUT'])
    settings['ORIGIN_DISCOVERY_WORKERS'] = project.get('originDiscoveryWorkers', DEFAULT_SETTINGS['ORIGIN_DISCOVERY_WORKERS'])

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
    if settings['DOMAIN_BATCH_MODE'] and settings['DOMAIN_BATCH_GROUPS']:
        # Domain batch scans EXACTLY the uploaded hostnames, UNLESS the operator
        # wrote a wildcard. This is not a nicety: a group made of one bare root
        # domain yields prefixes ['.'], and parse_target() treats a '.'-only list
        # as NOT filtered mode, which would silently start full subdomain
        # enumeration for that domain.
        #
        # The toggle is a run-wide scalar and wildcard-ness is per group, so this
        # can only answer "may ANY group enumerate". The per-group decision lives
        # in run_domain_group(), which is the only place that sees one group's
        # prefixes; a batch with no wildcard at all resolves exactly as before.
        if not any('*' in (g.get('prefixes') or [])
                   for g in settings['DOMAIN_BATCH_GROUPS']):
            settings['SUBDOMAIN_DISCOVERY_ENABLED'] = False
    settings['DOMAIN_RECON_AI_TXT_HINT_ENABLED'] = project.get('domainReconAiTxtHintEnabled', DEFAULT_SETTINGS['DOMAIN_RECON_AI_TXT_HINT_ENABLED'])
    settings['DOMAIN_RECON_AI_NS_HINT_ENABLED'] = project.get('domainReconAiNsHintEnabled', DEFAULT_SETTINGS['DOMAIN_RECON_AI_NS_HINT_ENABLED'])
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

    # Origin-IP Discovery reuses the scanner keys (Shodan/Censys/FOFA/ZoomEye/OTX/
    # VT) for its favicon/cert pivots. Those keys are otherwise only fetched when
    # each scanner's OWN tool is on, so without this the pivots silently no-op when
    # only OriginDiscovery is enabled (G10). Widen each gate below to also fire here.
    origin_scanners = bool(
        settings.get('ORIGIN_DISCOVERY_ENABLED') and settings.get('ORIGIN_DISCOVERY_SCANNERS')
    )

    # Shodan
    shodan_any = any([
        settings['SHODAN_HOST_LOOKUP'], settings['SHODAN_REVERSE_DNS'],
        settings['SHODAN_DOMAIN_DNS'], settings['SHODAN_PASSIVE_CVES'],
    ])
    if shodan_any or origin_scanners:
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
    if settings.get('CENSYS_ENABLED') or origin_scanners:
        settings['CENSYS_API_TOKEN'] = user_global.get('censysApiToken', '')
        settings['CENSYS_ORG_ID'] = user_global.get('censysOrgId', '')

    if settings.get('FOFA_ENABLED') or origin_scanners:
        fofa_key = user_global.get('fofaApiKey', '')
        settings['FOFA_API_KEY'] = fofa_key
        settings['FOFA_KEY_ROTATOR'] = _build_rotator(fofa_key, 'fofa')

    if settings.get('OTX_ENABLED') or origin_scanners:
        otx_key = user_global.get('otxApiKey', '')
        settings['OTX_API_KEY'] = otx_key
        settings['OTX_KEY_ROTATOR'] = _build_rotator(otx_key, 'otx')

    if settings.get('NETLAS_ENABLED'):
        netlas_key = user_global.get('netlasApiKey', '')
        settings['NETLAS_API_KEY'] = netlas_key
        settings['NETLAS_KEY_ROTATOR'] = _build_rotator(netlas_key, 'netlas')

    if settings.get('VIRUSTOTAL_ENABLED') or origin_scanners:
        vt_key = user_global.get('virusTotalApiKey', '')
        settings['VIRUSTOTAL_API_KEY'] = vt_key
        settings['VIRUSTOTAL_KEY_ROTATOR'] = _build_rotator(vt_key, 'virustotal')

    if settings.get('ZOOMEYE_ENABLED') or origin_scanners:
        ze_key = user_global.get('zoomEyeApiKey', '')
        settings['ZOOMEYE_API_KEY'] = ze_key
        settings['ZOOMEYE_KEY_ROTATOR'] = _build_rotator(ze_key, 'zoomeye')

    if settings.get('CRIMINALIP_ENABLED'):
        cip_key = user_global.get('criminalIpApiKey', '')
        settings['CRIMINALIP_API_KEY'] = cip_key
        settings['CRIMINALIP_KEY_ROTATOR'] = _build_rotator(cip_key, 'criminalip')

    # Origin-IP Discovery passive-DNS keys (SecurityTrails + ViewDNS). Net-new
    # UserSettings credentials; only fetched when OriginDiscovery + its passive-DNS
    # group are on. Keep them RUNTIME_ONLY (never in /defaults).
    if settings.get('ORIGIN_DISCOVERY_ENABLED') and settings.get('ORIGIN_DISCOVERY_PASSIVE_DNS'):
        st_key = user_global.get('securitytrailsApiKey', '')
        settings['SECURITYTRAILS_API_KEY'] = st_key
        settings['SECURITYTRAILS_KEY_ROTATOR'] = _build_rotator(st_key, 'securitytrails')
        vd_key = user_global.get('viewdnsApiKey', '')
        settings['VIEWDNS_API_KEY'] = vd_key
        settings['VIEWDNS_KEY_ROTATOR'] = _build_rotator(vd_key, 'viewdns')

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

    # Engagement limits. ROE_ENABLED is DERIVED, never read from the column:
    # a writable master switch would silently disable the ceiling, the
    # exclusions and the window at once. recon_settings.engagement is the one
    # implementation the agent and the orchestrator also call.
    settings['ROE_ENABLED'] = derive_roe_enabled(project)
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
    settings['AUTH_PROFILE'] = project.get('authProfile', DEFAULT_SETTINGS['AUTH_PROFILE'])
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

    # Web Cache Poisoning
    settings['WEB_CACHE_POISON_ENABLED'] = project.get('webCachePoisonEnabled', DEFAULT_SETTINGS['WEB_CACHE_POISON_ENABLED'])
    settings['WEB_CACHE_POISON_DOCKER_IMAGE'] = project.get('webCachePoisonDockerImage', DEFAULT_SETTINGS['WEB_CACHE_POISON_DOCKER_IMAGE'])
    settings['WEB_CACHE_POISON_SCAN_PROFILE'] = project.get('webCachePoisonScanProfile', DEFAULT_SETTINGS['WEB_CACHE_POISON_SCAN_PROFILE'])
    settings['WEB_CACHE_POISON_TIMEOUT'] = project.get('webCachePoisonTimeout', DEFAULT_SETTINGS['WEB_CACHE_POISON_TIMEOUT'])
    settings['WEB_CACHE_POISON_TIMEOUT_PER_REQ'] = project.get('webCachePoisonTimeoutPerReq', DEFAULT_SETTINGS['WEB_CACHE_POISON_TIMEOUT_PER_REQ'])
    settings['WEB_CACHE_POISON_CONCURRENCY'] = project.get('webCachePoisonConcurrency', DEFAULT_SETTINGS['WEB_CACHE_POISON_CONCURRENCY'])
    settings['WEB_CACHE_POISON_CONFIRM_WORKERS'] = project.get('webCachePoisonConfirmWorkers', DEFAULT_SETTINGS['WEB_CACHE_POISON_CONFIRM_WORKERS'])
    settings['WEB_CACHE_POISON_MAX_RPS_PER_HOST'] = project.get('webCachePoisonMaxRpsPerHost', DEFAULT_SETTINGS['WEB_CACHE_POISON_MAX_RPS_PER_HOST'])
    settings['WEB_CACHE_POISON_MIN_CONFIDENCE'] = project.get('webCachePoisonMinConfidence', DEFAULT_SETTINGS['WEB_CACHE_POISON_MIN_CONFIDENCE'])
    settings['WEB_CACHE_POISON_ALLOW_FRAMEWORK_PACKS'] = project.get('webCachePoisonAllowFrameworkPacks', DEFAULT_SETTINGS['WEB_CACHE_POISON_ALLOW_FRAMEWORK_PACKS'])
    settings['WEB_CACHE_POISON_ALLOW_DECEPTION'] = project.get('webCachePoisonAllowDeception', DEFAULT_SETTINGS['WEB_CACHE_POISON_ALLOW_DECEPTION'])
    settings['WEB_CACHE_POISON_ALLOW_CPDOS'] = project.get('webCachePoisonAllowCpdos', DEFAULT_SETTINGS['WEB_CACHE_POISON_ALLOW_CPDOS'])
    settings['WEB_CACHE_POISON_CROSS_VANTAGE'] = project.get('webCachePoisonCrossVantage', DEFAULT_SETTINGS['WEB_CACHE_POISON_CROSS_VANTAGE'])
    settings['WEB_CACHE_POISON_CACHE_HEADER'] = project.get('webCachePoisonCacheHeader', DEFAULT_SETTINGS['WEB_CACHE_POISON_CACHE_HEADER'])
    settings['WEB_CACHE_POISON_CACHE_BUSTER_PARAM'] = project.get('webCachePoisonCacheBusterParam', DEFAULT_SETTINGS['WEB_CACHE_POISON_CACHE_BUSTER_PARAM'])
    settings['WEB_CACHE_POISON_VERIFY_SSL'] = project.get('webCachePoisonVerifySsl', DEFAULT_SETTINGS['WEB_CACHE_POISON_VERIFY_SSL'])
    settings['WEB_CACHE_POISON_BEHAVIORAL_ORACLE'] = project.get('webCachePoisonBehavioralOracle', DEFAULT_SETTINGS['WEB_CACHE_POISON_BEHAVIORAL_ORACLE'])
    settings['WEB_CACHE_POISON_BEHAVIORAL_DELAY'] = project.get('webCachePoisonBehavioralDelay', DEFAULT_SETTINGS['WEB_CACHE_POISON_BEHAVIORAL_DELAY'])
    settings['WEB_CACHE_POISON_DIFFERENTIAL'] = project.get('webCachePoisonDifferential', DEFAULT_SETTINGS['WEB_CACHE_POISON_DIFFERENTIAL'])

    # RoE: cap every rate the engagement ceiling applies to.
    apply_roe_rate_cap(settings)

    # V3: reject any attacker-influenced tool Docker image before it can reach
    # `docker run` on the host daemon.
    sanitize_image_settings(settings)

    # The same shape for path-valued settings, which reach a tool that reads the
    # file and reports what matched.
    sanitize_project_file_settings(settings)

    logger.info(f"Loaded {len(settings)} settings for project {project_id}")
    return settings


# =============================================================================
# Memory governor (Part 2): dynamically cap RAM-relevant tool parameters to the
# memory actually available when the scan starts. Ratio-scale concurrency knobs;
# byte-budget the in-memory *_MAX_* accumulators. Emits [RESOURCE-CAP] log lines
# (rendered red in the recon drawer) only when a value is actually reduced.
# Applied AFTER stealth/RoE so those low-resource profiles win first, then the
# governor tightens further under live memory pressure. Fail-open on any error.
# =============================================================================

# The two governor tables are REGISTRY QUERIES. Neither is derivable from a
# field's unit: only 45 of the model's thread-shaped fields are ratio-scaled and
# only 20 of its count-shaped ones are byte-budgeted, and a budgeted key also
# carries a bytes-per-unit FAMILY and a floor that were chosen per key. So the
# registry records the tables and this reads them, which keeps the lists in the
# same place as every other fact about a parameter.


def _gov_ratio_keys() -> dict[str, int]:
    return _registry.governor_ratio_keys()


def _gov_budget_keys() -> dict[str, tuple[str, int]]:
    return _registry.governor_budget_keys()


def apply_memory_governor(settings: dict[str, Any]) -> dict[str, Any]:
    """Cap RAM-relevant tool parameters to available memory. Pure; fail-open."""
    try:
        from graph_db import resource_governor as rg
    except Exception:
        try:
            import resource_governor as rg   # direct (tests / alt path)
        except Exception:
            return settings  # governor unavailable -> unchanged (fail open)
    try:
        if not rg.governor_enabled():
            return settings
    except Exception:
        return settings

    for key, floor in _gov_ratio_keys().items():
        val = settings.get(key)
        if isinstance(val, int) and not isinstance(val, bool) and val > 0:
            try:
                eff = rg.scaled(val, floor)
            except Exception:
                continue
            if eff < val:
                tool = key.split('_')[0].lower()
                rg.log_cap(tool, key, val, eff, 'ratio')
                settings[key] = eff

    for key, (family, floor) in _gov_budget_keys().items():
        val = settings.get(key)
        if isinstance(val, int) and not isinstance(val, bool) and val > 0:
            try:
                per = rg.bytes_per_unit(family)
                eff = rg.scaled_cap(val, per, None, floor)
            except Exception:
                continue
            if eff < val:
                tool = key.split('_')[0].lower()
                rg.log_cap(tool, key, val, eff, 'byte-budget')
                settings[key] = eff

    return settings


def fetch_node_filters(project_id: str, webapp_url: str | None = None) -> dict | None:
    """The project's node-filter rules and exemptions, read NOW.

    A scan's end-of-run sweep calls this rather than using what was fetched at
    scan start, so it never applies rules older than the operator's latest save:
    a long partial recon must not undo an apply made while it ran.

    Returns None when the project has no filters. Raises on a failed request,
    and the caller treats that as "filter nothing", never as "no exemptions".
    """
    import requests

    webapp_url = webapp_url or os.environ.get('WEBAPP_API_URL')
    if not project_id or not webapp_url:
        return None
    url = f"{webapp_url.rstrip('/')}/api/projects/{project_id}"
    headers = {"X-Internal-Key": (os.environ.get("SCANNER_API_KEY") or os.environ.get("INTERNAL_API_KEY", ""))}
    response = requests.get(url, timeout=30, headers=headers)
    response.raise_for_status()
    node_filter = response.json().get('nodeFilter')
    if node_filter is None:
        return None
    if not isinstance(node_filter, dict) or not isinstance(node_filter.get('exemptions'), list):
        raise ValueError("the project's node filters arrived without their exemptions")
    return node_filter


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
        except Exception as e:
            logger.error(f"Failed to fetch project settings: {e}")
            raise  # Don't silently fall back - fail loudly if API is expected but unavailable
    else:
        # Fallback to DEFAULT_SETTINGS for CLI usage only
        logger.info("Using DEFAULT_SETTINGS (no PROJECT_ID/WEBAPP_API_URL set - CLI mode)")
        settings = DEFAULT_SETTINGS.copy()

    # Apply project-level cascade overrides. Stealth runs first so that AI
    # overrides see the post-stealth state (e.g., FFUF_ENABLED=False from
    # stealth makes FFUF_AI_EXTENSIONS moot). Both functions are pure and
    # idempotent.
    settings = apply_stealth_overrides(settings)
    settings = apply_ai_pipeline_overrides(settings)
    # Memory governor (Part 2): last, so it tightens whatever stealth/RoE left,
    # based on the RAM available at scan start.
    settings = apply_memory_governor(settings)
    return settings


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
    Apply stealth mode overrides to every recon tool.

    When STEALTH_MODE is on, tools are forced to passive, low-noise settings and
    the noisiest ones are switched off entirely.

    The profile is a REGISTRY QUERY. It used to be 105 explicit assignments in
    this function, which is a list of tools kept in step with the pipeline by
    hand: a tool added without a stealth entry is simply as loud in stealth mode
    as it is normally, and nothing anywhere says so. Recording it beside every
    other fact about a parameter is what makes that visible.

    Two operations, and the difference is load-bearing:

      set       force this value. Stealth wins whatever the operator chose.
      ceiling   lower to at most N, leaving an already-quieter value alone. An
                operator who asked for 50 results keeps 50 rather than being
                raised to the stealth figure.

    One override stays hand-written below, because it is neither: the nuclei
    exclude-tag list is a UNION of the operator's own excluded tags with the
    stealth set, and expressing a union as a value would discard their choice.

    Applied BEFORE the RoE capper and the memory governor, so a low-resource
    profile wins first and the later passes only tighten further.
    """
    if not settings.get('STEALTH_MODE', False):
        return settings

    logger.info("STEALTH MODE ENABLED — applying passive/low-noise overrides to all recon tools")

    for key, rule in _registry.stealth_profile().items():
        if key not in settings:
            continue
        if 'set' in rule:
            settings[key] = rule['set']
            continue
        ceiling = rule.get('ceiling')
        current = settings.get(key)
        if isinstance(current, (int, float)) and not isinstance(current, bool):
            settings[key] = min(current, ceiling)
        else:
            # A non-numeric where a ceiling was declared: fall back to the
            # ceiling rather than leaving a value stealth was meant to bound.
            settings[key] = ceiling

    # Exclude intrusive template tags
    existing_exclude = settings.get('NUCLEI_EXCLUDE_TAGS', [])
    stealth_exclude = ['dos', 'fuzz', 'intrusive', 'sqli', 'rce']
    # Sorted, not just de-duplicated: `list(set(...))` over strings orders by
    # hash, which varies per process, so the same project produced a different
    # nuclei command line on every run. Order means nothing to nuclei and
    # everything to anyone comparing two runs.
    settings['NUCLEI_EXCLUDE_TAGS'] = sorted(set(existing_exclude + stealth_exclude))

    return settings


# =============================================================================
# AI IN PIPELINE OVERRIDES
# =============================================================================

def apply_ai_pipeline_overrides(settings: dict[str, Any]) -> dict[str, Any]:
    """
    Apply AI-in-pipeline cascade to per-tool AI flags.

    When AI_IN_PIPELINE is True, every supported per-tool AI flag is forced ON.
    When False, every per-tool AI flag is forced OFF (defense-in-depth against
    drift between master and per-tool fields).

    Currently FFUF_AI_EXTENSIONS, NUCLEI_AI_TAGS, WAF_AI_CLASSIFIER,
    NUCLEI_AI_RESPONSE_FILTER and TAKEOVER_AI_CLASSIFIER are governed by
    this cascade; future per-tool AI flags should be added to both branches.
    """
    if not settings.get('AI_IN_PIPELINE', False):
        settings['FFUF_AI_EXTENSIONS'] = False
        settings['NUCLEI_AI_TAGS'] = False
        settings['WAF_AI_CLASSIFIER'] = False
        settings['NUCLEI_AI_RESPONSE_FILTER'] = False
        settings['TAKEOVER_AI_CLASSIFIER'] = False
        return settings

    settings['FFUF_AI_EXTENSIONS'] = True
    settings['NUCLEI_AI_TAGS'] = True
    settings['WAF_AI_CLASSIFIER'] = True
    settings['NUCLEI_AI_RESPONSE_FILTER'] = True
    settings['TAKEOVER_AI_CLASSIFIER'] = True
    logger.info(
        "AI in pipeline enabled, model=%s, FFuf=AI-extensions, Nuclei=AI-tags, "
        "WAF=AI-classifier, Nuclei-FP=AI-response-filter, Takeover=AI-classifier",
        settings.get('AI_PIPELINE_MODEL', 'claude-opus-4-6'),
    )
    return settings
