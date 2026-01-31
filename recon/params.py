"""
Recon - Parameters
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv(Path(__file__).parent / ".env")

# =============================================================================
# Domain Ownership Verification
# =============================================================================
# Verify domain ownership via DNS TXT record before scanning.
# This ensures you only scan domains you control.
#
# How it works:
#   1. Set VERIFY_DOMAIN_OWNERSHIP = True
#   2. Add a TXT record to your DNS: _redamon-verify.yourdomain.com
#   3. TXT record value must be: redamon-verify=<OWNERSHIP_TOKEN>
#   4. Recon will check this TXT record before starting - fails if not found
#
# Example DNS record for domain "example.com" with token "my-secret-token":
#   _redamon-verify.example.com.  IN  TXT  "redamon-verify=my-secret-token"
#
# To disable verification (e.g., for testing on your own infrastructure):
#   Set VERIFY_DOMAIN_OWNERSHIP = False

VERIFY_DOMAIN_OWNERSHIP = False
OWNERSHIP_TOKEN = "your-secret-token-here"  # Change this to a unique secret token
OWNERSHIP_TXT_PREFIX = "_redamon-verify"    # DNS record prefix (don't change unless needed)

# =============================================================================
# Target for RECON
# =============================================================================
# TARGET_DOMAIN: Always specify the root domain (e.g., "vulnweb.com", "example.com")
# SUBDOMAIN_LIST: Filter which subdomains to scan
#   - Empty list []: Discover and scan ALL subdomains + root domain (full discovery mode)
#   - Specific prefixes ["testphp.", "www."]: Only scan these specific subdomains (filtered mode)
#   - Special prefix ".": Include the root domain directly (no subdomain prefix)
#
# Examples:
#   TARGET_DOMAIN = "vulnweb.com", SUBDOMAIN_LIST = []              → Scan all subdomains + root domain
#   TARGET_DOMAIN = "vulnweb.com", SUBDOMAIN_LIST = ["testphp."]    → Only scan testphp.vulnweb.com
#   TARGET_DOMAIN = "vulnweb.com", SUBDOMAIN_LIST = ["testphp.","."]→ Scan testphp.vulnweb.com AND vulnweb.com
#   TARGET_DOMAIN = "vulnweb.com", SUBDOMAIN_LIST = ["."]           → Only scan vulnweb.com (root only)
#   TARGET_DOMAIN = "example.com", SUBDOMAIN_LIST = ["dev.", "staging.", "."] → Scan dev.example.com, staging.example.com, AND example.com
#
# Note: When following HTTP redirects, only URLs within TARGET_DOMAIN scope are kept.
#       Redirects to external domains are filtered out.
#
TARGET_DOMAIN = "devergolabs.com"
SUBDOMAIN_LIST = ["gpigs."]  # Empty [] = discover all, "." = root domain, or prefixes like ["www.", "api.", "."]
USER_ID = "samgiam"
PROJECT_ID = "project_2"

# =============================================================================
# SCAN MODULES - Control which modules to run
# =============================================================================
# Available modules (tool-agnostic names):
#   - "domain_discovery" : WHOIS + Subdomain discovery + DNS (creates initial JSON)
#   - "port_scan"        : Fast port scanning (updates JSON)
#   - "http_probe"       : HTTP probing and technology detection (updates JSON)
#   - "resource_enum"    : Endpoint discovery & classification (Katana crawl + form parsing)
#   - "vuln_scan"        : Web vulnerability scanning + MITRE CWE/CAPEC enrichment (updates JSON)
#   - "github"           : GitHub secret hunting (creates separate JSON)
#
# Pipeline: domain_discovery -> port_scan -> http_probe -> resource_enum -> vuln_scan -> github
#
# Note: vuln_scan automatically includes MITRE CWE/CAPEC enrichment for all CVEs found.
#       Configure MITRE enrichment settings in the "MITRE CWE/CAPEC Enrichment" section below.
#
# Examples:
#   ["domain_discovery"]                                                      - Only domain recon
#   ["domain_discovery", "port_scan", "http_probe"]                           - Recon + port/HTTP probing
#   ["domain_discovery", "port_scan", "http_probe", "resource_enum"]          - + endpoint discovery
#   ["domain_discovery", "port_scan", "http_probe", "resource_enum", "vuln_scan"] - Full web scan (default)
#   ["domain_discovery", "port_scan", "http_probe", "resource_enum", "vuln_scan", "github"] - Complete scan

SCAN_MODULES = ["domain_discovery", "port_scan", "http_probe", "resource_enum", "vuln_scan"]
UPDATE_GRAPH_DB = True

# Hide your real IP during subdomain enumeration (uses Tor + proxychains)
# Requires: Tor running (sudo systemctl start tor) + proxychains4 installed
USE_TOR_FOR_RECON = False

# Enable Knockpy bruteforce mode for subdomain discovery
# Only applies when SUBDOMAIN_LIST = [] (full discovery mode)
# Ignored when SUBDOMAIN_LIST has entries (filtered mode - no discovery needed)
# Bruteforce is slower but can find hidden subdomains not in passive sources
USE_BRUTEFORCE_FOR_SUBDOMAINS = True

# =============================================================================
# WHOIS Configuration
# =============================================================================
# Maximum retry attempts for WHOIS lookups (handles rate limiting and timeouts)
# Uses exponential backoff: 1s, 2s, 4s delays between retries
WHOIS_MAX_RETRIES = 6

# =============================================================================
# DNS Configuration
# =============================================================================
# Maximum retry attempts for DNS lookups (handles temporary failures and timeouts)
# Uses exponential backoff: 1s, 2s, 4s delays between retries
DNS_MAX_RETRIES = 3

# =============================================================================
# GitHub Secret Hunt Configuration
# =============================================================================

# GitHub Personal Access Token (loaded from .env file)
# Generate at: https://github.com/settings/tokens
# Required scopes: repo (for private repos) or public_repo (for public only)
GITHUB_ACCESS_TOKEN = os.getenv("GITHUB_ACCESS_TOKEN", "")

# Target organization or username to scan
GITHUB_TARGET_ORG = "xxxxxxx"

# Also scan repos of organization members (slower but more thorough)
GITHUB_SCAN_MEMBERS = False

# Also scan gists of organization members
GITHUB_SCAN_GISTS = True

# Scan commit history for leaked secrets (much slower but finds deleted secrets)
GITHUB_SCAN_COMMITS = True

# Maximum number of commits to scan per repo (0 = all commits)
GITHUB_MAX_COMMITS = 100

# Output results to JSON file
GITHUB_OUTPUT_JSON = True

# =============================================================================
# Naabu Port Scanner Configuration (ProjectDiscovery)
# =============================================================================
# Fast, lightweight port scanner optimized for reconnaissance
# Docker image: projectdiscovery/naabu:latest
# Docs: https://github.com/projectdiscovery/naabu

# Docker image for Naabu
NAABU_DOCKER_IMAGE = "projectdiscovery/naabu:latest"

# Ports to scan: "100", "1000", "full", or custom like "80,443,8080-8090"
NAABU_TOP_PORTS = "1000"

# Custom ports (overrides TOP_PORTS if set)
# Example: "22,80,443,8080,8443" or "1-65535"
NAABU_CUSTOM_PORTS = ""

# Rate limit (packets per second)
# Higher = faster but may trigger rate limiting
NAABU_RATE_LIMIT = 1000

# Concurrent threads for scanning
NAABU_THREADS = 25

# Timeout per port in milliseconds
NAABU_TIMEOUT = 10000

# Number of retries for failed probes
NAABU_RETRIES = 1

# Scan type: "s" (SYN - requires root, faster) or "c" (CONNECT - no root needed)
# SYN scan is more reliable and faster but requires root/sudo
NAABU_SCAN_TYPE = "s"

# Exclude CDN/WAF IPs (only scan ports 80,443 on CDN hosts)
# Helps avoid false positives from CDN-protected sites
# Note: Set to False for testing sites hosted on AWS/cloud providers
NAABU_EXCLUDE_CDN = False

# Display CDN information in output
NAABU_DISPLAY_CDN = True

# Skip host discovery (assume all hosts are up)
# Recommended: True for web targets, False for network discovery
NAABU_SKIP_HOST_DISCOVERY = True

# Verify ports are actually open (extra TCP connection check)
NAABU_VERIFY_PORTS = True

# Passive mode - query Shodan InternetDB instead of active scanning
# No packets sent to target (stealthier but may be outdated)
NAABU_PASSIVE_MODE = False

# =============================================================================
# httpx HTTP Probing Configuration (ProjectDiscovery)
# =============================================================================
# Multi-purpose HTTP toolkit for probing and technology detection
# Docker image: projectdiscovery/httpx:latest
# Docs: https://github.com/projectdiscovery/httpx

# Docker image for httpx
HTTPX_DOCKER_IMAGE = "projectdiscovery/httpx:latest"

# Concurrent threads for HTTP probing
HTTPX_THREADS = 50

# Request timeout in seconds
HTTPX_TIMEOUT = 10

# Number of retries for failed requests
HTTPX_RETRIES = 2

# Rate limit (requests per second, 0 = no limit)
# Lower values (10-50) look more human-like and avoid triggering WAFs
HTTPX_RATE_LIMIT = 50

# Follow HTTP redirects
HTTPX_FOLLOW_REDIRECTS = True

# Maximum redirects to follow
HTTPX_MAX_REDIRECTS = 10

# ----- Probing Options (what data to extract) -----

# HTTP response information
HTTPX_PROBE_STATUS_CODE = True     # HTTP status code (200, 404, etc.)
HTTPX_PROBE_CONTENT_LENGTH = True  # Response body size
HTTPX_PROBE_CONTENT_TYPE = True    # Content-Type header
HTTPX_PROBE_TITLE = True           # HTML page title
HTTPX_PROBE_SERVER = True          # Server header (nginx, Apache, etc.)
HTTPX_PROBE_RESPONSE_TIME = True   # Response time in milliseconds
HTTPX_PROBE_WORD_COUNT = True      # Word count in response
HTTPX_PROBE_LINE_COUNT = True      # Line count in response

# Technology detection (Wappalyzer-based)
HTTPX_PROBE_TECH_DETECT = True     # Detect technologies (frameworks, CMS, etc.)

# Network information
HTTPX_PROBE_IP = True              # Resolved IP address
HTTPX_PROBE_CNAME = True           # CNAME DNS records

# SSL/TLS information
HTTPX_PROBE_TLS_INFO = True        # TLS certificate details
HTTPX_PROBE_TLS_GRAB = True        # Grab TLS certificate data

# Fingerprinting
HTTPX_PROBE_FAVICON = True         # Favicon hash (for fingerprinting)
HTTPX_PROBE_JARM = True            # JARM TLS fingerprint
HTTPX_PROBE_HASH = "sha256"        # Response body hash (md5, sha256, etc.)

# Response data inclusion
HTTPX_INCLUDE_RESPONSE = True      # Include full response body (larger output)
HTTPX_INCLUDE_RESPONSE_HEADERS = True  # Include response headers

# ASN and CDN detection
HTTPX_PROBE_ASN = True             # Autonomous System Number detection
HTTPX_PROBE_CDN = True             # CDN detection

# Web server paths to probe (in addition to root)
# Example: ["/robots.txt", "/.well-known/security.txt"]
HTTPX_PATHS = []

# Custom headers to send with requests
# These headers mimic a real Chrome browser to avoid WAF/bot detection
HTTPX_CUSTOM_HEADERS = [
    # Core browser identification
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    # Content negotiation (what browser accepts)
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "Accept-Language: en-US,en;q=0.9",
    "Accept-Encoding: gzip, deflate",
    # Connection behavior
    "Connection: keep-alive",
    "Upgrade-Insecure-Requests: 1",
    # Chrome security headers (Sec-Fetch-*)
    "Sec-Fetch-Dest: document",
    "Sec-Fetch-Mode: navigate", 
    "Sec-Fetch-Site: none",
    "Sec-Fetch-User: ?1",
    # Cache behavior
    "Cache-Control: max-age=0",
]

# Filter responses by status code (empty = all)
# Example: ["200", "301", "302"] - only keep these status codes
HTTPX_MATCH_CODES = []

# Exclude responses by status code
# Example: ["404", "503"] - exclude these status codes
HTTPX_FILTER_CODES = []


# =============================================================================
# Wappalyzer Technology Enhancement Configuration
# =============================================================================
# Enhances httpx technology detection with Wappalyzer's full pattern database
# Uses existing HTML from httpx (no additional HTTP requests needed)
# Detects: CMS plugins, analytics tools, security tools, frameworks, etc.

# Enable/disable Wappalyzer technology enhancement
WAPPALYZER_ENABLED = True

# Minimum confidence level (0-100) to include a technology
# Lower = more detections but potentially more false positives
WAPPALYZER_MIN_CONFIDENCE = 50

# Analyze only URLs with HTML body (recommended: True)
# When False, attempts to analyze URLs without body (limited detection)
WAPPALYZER_REQUIRE_HTML = True

# -----------------------------------------------------------------------------
# Wappalyzer Auto-Update Settings
# -----------------------------------------------------------------------------
# The python-Wappalyzer library is archived (Sept 2020) with outdated database.
# Enable auto-update to download the latest technologies.json from official repo.

# Enable automatic download of latest Wappalyzer technologies database
WAPPALYZER_AUTO_UPDATE = True

# URL base for downloading latest technologies database
# Uses unpkg CDN which mirrors the npm package (more reliable than GitHub raw)
# Technologies are split into alphabetical files (a.json, b.json, etc.)
WAPPALYZER_NPM_VERSION = "6.10.66"  # Latest stable version with full tech database
WAPPALYZER_BASE_URL = f"https://unpkg.com/wappalyzer@{WAPPALYZER_NPM_VERSION}"
WAPPALYZER_CATEGORIES_URL = f"{WAPPALYZER_BASE_URL}/categories.json"

# Local cache directory and file for downloaded database
WAPPALYZER_CACHE_DIR = os.path.join(os.path.dirname(__file__), "data")
WAPPALYZER_CACHE_FILE = os.path.join(WAPPALYZER_CACHE_DIR, "wappalyzer_technologies.json")

# Cache TTL in hours (0 = always download fresh, 24 = update daily)
WAPPALYZER_CACHE_TTL_HOURS = 24


# =============================================================================
# Banner Grabbing Configuration (Non-HTTP Service Detection)
# =============================================================================
# Detects service versions on non-HTTP ports (SSH, FTP, SMTP, MySQL, etc.)
# Integrated into httpx_scan module - runs automatically after httpx probing

# Enable/disable banner grabbing for non-HTTP ports
BANNER_GRAB_ENABLED = True

# Connection timeout per port (seconds)
BANNER_GRAB_TIMEOUT = 5

# Number of concurrent threads for banner grabbing
BANNER_GRAB_THREADS = 20

# Maximum banner length to store (characters)
BANNER_GRAB_MAX_LENGTH = 500


# =============================================================================
# Nuclei Vulnerability Scanner Configuration
# =============================================================================
# Template-based vulnerability scanning using ProjectDiscovery's Nuclei
# Runs after httpx to leverage discovered URLs and technologies
# Docker image: projectdiscovery/nuclei:latest

# Severity levels to scan (empty = all severities)
# Options: "critical", "high", "medium", "low", "info"
NUCLEI_SEVERITY = ["critical", "high", "medium", "low"]  # Exclude info by default

# Template folders to use (empty = all templates)
# Options: "cves", "vulnerabilities", "misconfiguration", "exposures",
#          "technologies", "default-logins", "takeovers", "file", "fuzzing"
NUCLEI_TEMPLATES = []  # Empty = use all templates

# Template PATHS to exclude (directories or files, NOT tag names)
# Example: ["http/vulnerabilities/generic/", "dast/command-injection/"]
# For excluding by TAG, use NUCLEI_EXCLUDE_TAGS instead
NUCLEI_EXCLUDE_TEMPLATES = []  # Empty - use NUCLEI_EXCLUDE_TAGS for tag-based exclusion

# Custom template paths (your own templates)
# Example: ["/path/to/custom-templates", "~/my-nuclei-templates"]
NUCLEI_CUSTOM_TEMPLATES = []

# Rate limiting (requests per second, 0 = no limit)
# Recommended: 100-150 for most targets, lower for sensitive systems
NUCLEI_RATE_LIMIT = 100

# Bulk size (number of hosts to process in parallel)
NUCLEI_BULK_SIZE = 25

# Concurrency (number of templates to execute in parallel)
NUCLEI_CONCURRENCY = 25

# Request timeout in seconds
NUCLEI_TIMEOUT = 10

# Number of retries for failed requests
NUCLEI_RETRIES = 1

# Template tags to include (empty = all tags)
# Popular tags: "cve", "xss", "sqli", "rce", "lfi", "ssrf", "xxe", "ssti",
#               "exposure", "misconfig", "default-login", "takeover", "tech"
NUCLEI_TAGS = []  # Empty = no tag filter

# Template tags to exclude
# Example: ["dos", "fuzz"] - exclude denial of service
NUCLEI_EXCLUDE_TAGS = []

# Enable DAST mode (-dast flag) for active vulnerability fuzzing
# This mode actively injects payloads to find XSS, SQLi, etc.
# WARNING: This is more aggressive and may trigger security alerts
# NOTE: DAST requires URLs with parameters - Katana crawler will discover them
NUCLEI_DAST_MODE = True

# =============================================================================
# Katana Web Crawler Configuration (for DAST mode)
# =============================================================================
# Katana crawls the website to discover URLs with parameters for DAST fuzzing
# Only runs when NUCLEI_DAST_MODE is True

# Docker image for Katana crawler
KATANA_DOCKER_IMAGE = "projectdiscovery/katana:latest"

# Maximum crawl depth (how many links deep to follow)
# Higher = more URLs found, but slower
KATANA_DEPTH = 3

# Maximum number of URLs to crawl
KATANA_MAX_URLS = 500

# Request rate limit (requests per second)
KATANA_RATE_LIMIT = 50

# Timeout for the entire crawl (seconds)
KATANA_TIMEOUT = 900  # 15 minutes

# Include URLs from JavaScript parsing
KATANA_JS_CRAWL = True

# Only keep URLs with query parameters (for DAST fuzzing)
KATANA_PARAMS_ONLY = False

# Exclude patterns - skip static assets and image optimization endpoints
# These generate many URLs but are usually not vulnerable to injection attacks
KATANA_EXCLUDE_PATTERNS = [
    # ===================
    # Next.js / React
    # ===================
    "/_next/image",          # Next.js image optimization
    "/_next/static",         # Next.js static files
    "/_next/data",           # Next.js data fetching
    "/__nextjs",             # Next.js internals

    # ===================
    # Nuxt.js / Vue.js
    # ===================
    "/_nuxt/",               # Nuxt.js static files
    "/__nuxt",               # Nuxt.js internals

    # ===================
    # Angular
    # ===================
    "/runtime.",             # Angular runtime
    "/polyfills.",           # Angular polyfills
    "/vendor.",              # Angular vendor bundle

    # ===================
    # Webpack / Build Tools
    # ===================
    "/webpack",              # Webpack internals
    "/chunk.",               # Webpack chunks
    ".chunk.js",             # Chunk files
    ".bundle.js",            # Bundle files
    "hot-update",            # HMR updates

    # ===================
    # Static Files / CDN
    # ===================
    "/static/",              # Generic static files
    "/public/",              # Public assets
    "/dist/",                # Distribution files
    "/build/",               # Build output
    "/lib/",                 # Library files
    "/vendor/",              # Vendor files
    "/node_modules/",        # Node modules (shouldn't be exposed but sometimes is)

    # ===================
    # Images
    # ===================
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif",
    ".bmp", ".tiff", ".tif", ".heic", ".heif", ".raw",
    "/images/", "/img/", "/image/", "/pics/", "/pictures/",
    "/thumbnails/", "/thumb/", "/thumbs/",

    # ===================
    # CSS / Stylesheets
    # ===================
    ".css", ".scss", ".sass", ".less", ".styl",
    ".css.map",              # CSS source maps
    "/css/", "/styles/", "/style/", "/stylesheet/",

    # ===================
    # JavaScript (non-application)
    # ===================
    ".js.map",               # JS source maps
    ".min.js",               # Minified JS (usually libraries)
    "/js/lib/", "/js/vendor/", "/js/plugins/",
    "jquery", "bootstrap.js", "popper.js",  # Common libraries

    # ===================
    # Fonts
    # ===================
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    "/fonts/", "/font/", "/webfonts/",

    # ===================
    # Documents / Downloads
    # ===================
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".txt", ".rtf", ".odt", ".ods", ".odp",
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2",

    # ===================
    # Audio / Video
    # ===================
    ".mp3", ".mp4", ".avi", ".mov", ".wmv", ".flv", ".webm", ".mkv",
    ".wav", ".ogg", ".aac", ".m4a", ".flac",
    "/video/", "/videos/", "/audio/", "/music/", "/sounds/",

    # ===================
    # WordPress
    # ===================
    "/wp-content/uploads/",  # WP uploads
    "/wp-content/themes/",   # WP themes (static)
    "/wp-includes/",         # WP core includes

    # ===================
    # Drupal
    # ===================
    "/sites/default/files/", # Drupal files
    "/core/assets/",         # Drupal core assets

    # ===================
    # Magento
    # ===================
    "/pub/static/",          # Magento static
    "/pub/media/",           # Magento media

    # ===================
    # Laravel / PHP
    # ===================
    "/storage/",             # Laravel storage

    # ===================
    # Django / Python
    # ===================
    "/staticfiles/",         # Django static

    # ===================
    # Ruby on Rails
    # ===================
    "/packs/",               # Webpacker

    # ===================
    # CDN / External Resources
    # ===================
    "cdn.", "cdnjs.", "cloudflare.", "akamai.", "fastly.",
    "googleapis.com", "gstatic.com", "cloudfront.net",
    "unpkg.com", "jsdelivr.net", "bootstrapcdn.com",

    # ===================
    # Analytics / Tracking (not vulnerable to injection)
    # ===================
    "google-analytics", "googletagmanager", "gtag/",
    "facebook.com/tr", "facebook.net",
    "analytics.", "tracking.", "pixel.",
    "hotjar.", "mouseflow.", "clarity.",

    # ===================
    # Ads
    # ===================
    "googlesyndication", "doubleclick", "adservice",

    # ===================
    # Social Media Widgets
    # ===================
    "platform.twitter", "connect.facebook", "platform.linkedin",

    # ===================
    # Maps
    # ===================
    "maps.google", "maps.googleapis",
    "openstreetmap", "mapbox",

    # ===================
    # Captcha / Security
    # ===================
    "recaptcha", "hcaptcha", "captcha",

    # ===================
    # Manifest / Service Workers / Config
    # ===================
    "manifest.json", "sw.js", "service-worker",
    "browserconfig.xml", "robots.txt", "sitemap.xml",
    ".well-known/",

    # ===================
    # Favicon / Icons
    # ===================
    "favicon", "apple-touch-icon", "android-chrome",
    "/icons/", "/icon/",
]

# Crawl scope: "dn" (domain name), "rdn" (root domain), "fqdn" (exact hostname)
# "dn" = stays within same domain
KATANA_SCOPE = "dn"

# Custom headers for authenticated crawling
# Using browser-like headers helps avoid detection during DAST crawling
KATANA_CUSTOM_HEADERS = [
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language: en-US,en;q=0.9",
]

# =============================================================================
# GAU (GetAllUrls) Passive URL Discovery Configuration
# =============================================================================
# Fetches historical URLs from Wayback Machine, Common Crawl, OTX, and URLScan
# Runs in PARALLEL with Katana crawler for comprehensive URL discovery
# GAU finds old/deleted endpoints, debug pages, backup files, admin panels
# Docker image: sxcurity/gau:latest
# Docs: https://github.com/lc/gau

# Enable/disable GAU passive URL discovery
GAU_ENABLED = True

# Docker image for GAU
GAU_DOCKER_IMAGE = "sxcurity/gau:latest"

# Data sources to query
# Options: "wayback", "commoncrawl", "otx", "urlscan"
GAU_PROVIDERS = ["wayback", "commoncrawl", "otx", "urlscan"]

# Maximum number of URLs to fetch per domain (0 = unlimited)
GAU_MAX_URLS = 1000

# Request timeout for each provider (seconds)
GAU_TIMEOUT = 60

# Number of parallel threads for fetching
GAU_THREADS = 5

# Blacklist file extensions (filter out static assets)
# These URLs will be excluded from results
GAU_BLACKLIST_EXTENSIONS = [
    "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "avif",
    "css", "woff", "woff2", "ttf", "eot", "otf",
    "mp3", "mp4", "avi", "mov", "wmv", "flv", "webm",
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "zip", "rar", "7z", "tar", "gz"
]

# Year range for wayback machine (empty = all years)
# Format: ["YYYY", "YYYY"] e.g., ["2020", "2024"]
GAU_YEAR_RANGE = []

# Enable verbose output
GAU_VERBOSE = False

# =============================================================================
# GAU URL Verification Configuration
# =============================================================================
# Verify discovered URLs are live before adding to resource_enum

# Enable URL verification (HTTP HEAD/GET check)
GAU_VERIFY_URLS = True

# Use httpx Docker container for verification (matches http_probe)
GAU_VERIFY_DOCKER_IMAGE = "projectdiscovery/httpx:latest"

# Verification timeout per URL (seconds)
GAU_VERIFY_TIMEOUT = 5

# Verification rate limit (requests per second)
GAU_VERIFY_RATE_LIMIT = 100

# Verification threads
GAU_VERIFY_THREADS = 50

# Accept URLs with these status codes as "live"
GAU_VERIFY_ACCEPT_STATUS = [200, 201, 301, 302, 307, 308, 401, 403]

# -----------------------------------------------------------------------------
# Method Detection (OPTIONS probe)
# -----------------------------------------------------------------------------
# Enable OPTIONS probe to detect allowed HTTP methods for GAU endpoints
# Queries OPTIONS method and parses 'Allow' header to find GET, POST, PUT, DELETE, etc.
GAU_DETECT_METHODS = True

# Timeout for OPTIONS probe per URL (seconds)
GAU_METHOD_DETECT_TIMEOUT = 5

# Rate limit for method detection (requests per second)
GAU_METHOD_DETECT_RATE_LIMIT = 50

# Threads for method detection
GAU_METHOD_DETECT_THREADS = 25

# Filter out endpoints that don't respond to any method
# If True, endpoints returning 404/500/timeout on all methods are excluded from results
GAU_FILTER_DEAD_ENDPOINTS = True

# =============================================================================
# Kiterunner API Endpoint Discovery Configuration
# =============================================================================
# Bruteforces API routes using Swagger/OpenAPI specifications
# Discovers hidden APIs that aren't linked or archived
# Runs in PARALLEL with Katana and GAU for comprehensive endpoint discovery
# Binary: Auto-downloaded from GitHub releases to ~/.redamon/tools/kiterunner/
# Docs: https://github.com/assetnote/kiterunner

# Enable/disable Kiterunner API discovery
KITERUNNER_ENABLED = True

# Wordlists to use (run `kr wordlist list` to see all available):
# IMPORTANT: Choose wordlists based on target technology:
# - "apiroutes-251227"        - REST APIs (Node.js, Python, Go, etc.) ~354k routes
# - "directories-251227"      - Generic directories (/login/, /admin/, etc.) ~703k routes
# - "raft-large-directories"  - SecLists classic directory wordlist ~62k routes
# - "php-251227"              - PHP applications (WordPress, Laravel, etc.) ~177k routes
# - "aspx-251227"             - ASP.NET applications ~82k routes
# - "jsp-251227"              - Java JSP applications ~21k routes
# - "cgi-251227"              - CGI/Perl scripts ~11k routes
# - Custom path: "/path/to/wordlist.kite"
#
# RECOMMENDED: Use multiple wordlists for comprehensive coverage
# - Default covers: APIs + web directories + classic SecLists paths
# - Add technology-specific wordlists based on detected stack (php, aspx, jsp)
#
# NOTE: Wordlists are MERGED into a single deduplicated file, then run in parallel
#       with Katana and GAU. This eliminates duplicate routes across wordlists.
KITERUNNER_WORDLISTS = ["apiroutes-251227", "directories-251227", "raft-large-directories"]

# Request rate limit (requests per second)
# Lower values are stealthier but slower
KITERUNNER_RATE_LIMIT = 100

# Concurrent connections per target
KITERUNNER_CONNECTIONS = 100

# Request timeout per endpoint (seconds)
KITERUNNER_TIMEOUT = 10

# Overall scan timeout (seconds)
# Note: Large wordlists need more time. php-251227 has 177k routes.
KITERUNNER_SCAN_TIMEOUT = 1000

# Threads for scanning
KITERUNNER_THREADS = 50

# Ignore these response status codes (filter out noise)
KITERUNNER_IGNORE_STATUS = [404, 400, 502, 503]

# Content-Length filter (ignore responses smaller than this in bytes)
# Useful for filtering empty/tiny error responses
KITERUNNER_MIN_CONTENT_LENGTH = 0

# Only show results with these status codes (empty = all except ignored)
KITERUNNER_MATCH_STATUS = []

# Custom headers for authenticated scanning
# Example: ["Authorization: Bearer token123", "X-API-Key: key123"]
KITERUNNER_HEADERS = []

# -----------------------------------------------------------------------------
# Kiterunner Method Detection Configuration
# -----------------------------------------------------------------------------
# Kiterunner's wordlist only contains GET routes. These settings allow
# discovering additional HTTP methods (POST, PUT, DELETE) on found endpoints.

# Enable method detection for Kiterunner-discovered endpoints
KITERUNNER_DETECT_METHODS = True

# Method detection strategy:
# - "options": Send OPTIONS request, parse 'Allow' header (faster, fewer requests)
# - "bruteforce": Try each method directly to see if it responds (slower, more accurate)
KITERUNNER_METHOD_DETECTION_MODE = "bruteforce"

# Methods to try in "bruteforce" mode (ignored in "options" mode)
# These will be tried on each discovered endpoint
KITERUNNER_BRUTEFORCE_METHODS = ["POST", "PUT", "DELETE", "PATCH"]

# Timeout for method detection requests (seconds)
KITERUNNER_METHOD_DETECT_TIMEOUT = 5

# Rate limit for method detection (requests per second)
KITERUNNER_METHOD_DETECT_RATE_LIMIT = 50

# Threads for method detection
KITERUNNER_METHOD_DETECT_THREADS = 25

# =============================================================================

# Auto-update nuclei templates before each scan
# Checks for new templates and downloads them (adds ~10-30 seconds to scan)
# Recommended: True for production, False for faster testing
NUCLEI_AUTO_UPDATE_TEMPLATES = True

# Only use newly added templates (within last nuclei-templates update)
NUCLEI_NEW_TEMPLATES_ONLY = False

# Enable headless browser for JavaScript-rendered pages
# Requires: Chrome/Chromium installed
NUCLEI_HEADLESS = False

# Use system DNS resolvers instead of nuclei's default resolvers
NUCLEI_SYSTEM_RESOLVERS = True

# Follow HTTP redirects
NUCLEI_FOLLOW_REDIRECTS = True

# Maximum number of redirects to follow
NUCLEI_MAX_REDIRECTS = 10

# Scan IP addresses in addition to hostnames
# Set to False to only scan hostnames (faster, avoids duplicate findings)
NUCLEI_SCAN_ALL_IPS = False

# Enable Interactsh for Out-of-Band (OOB) testing
# Detects blind vulnerabilities like blind SSRF, XXE, RCE
# Note: Requires internet access to interactsh servers
NUCLEI_INTERACTSH = True

# Docker image to use (can pin to specific version)
# Nuclei runs exclusively via Docker - requires Docker installed and running
NUCLEI_DOCKER_IMAGE = "projectdiscovery/nuclei:latest"

# =============================================================================
# CVE Lookup Configuration (Technology-Based)
# =============================================================================
# Looks up CVEs for technologies detected by httpx (nginx, PHP, etc.)
# This replicates what Nmap's vulners script does - version-based CVE lookup
# Note: These are POTENTIAL CVEs based on version, not confirmed exploitable vulns

# Enable/disable technology-based CVE lookup
CVE_LOOKUP_ENABLED = True

# Data source: "nvd" (free, rate limited) or "vulners" (better, needs API key)
CVE_LOOKUP_SOURCE = "nvd"

# Maximum CVEs to return per technology
CVE_LOOKUP_MAX_CVES = 20

# Minimum CVSS score to include (0.0 = all, 4.0 = medium+, 7.0 = high+)
CVE_LOOKUP_MIN_CVSS = 0.0

# Vulners API key (optional - for better results with vulners source)
# Get free API key at: https://vulners.com/
VULNERS_API_KEY = ""

# NVD API key (optional but STRONGLY RECOMMENDED, for lookup_cves_nvd in vuln_scan)
# Without an API key, NVD enforces aggressive rate limiting (6 requests/minute)
# With an API key, you get 50 requests/10 seconds
# Get free API key at: https://nvd.nist.gov/developers/request-an-api-key
NVD_API_KEY = os.getenv("NVD_API_KEY", "")


# =============================================================================
# MITRE CWE/CAPEC Enrichment Configuration
# =============================================================================
# Enriches CVE data with CWE weaknesses and CAPEC attack patterns
# Uses the CVE2CAPEC database (github.com/Galeax/CVE2CAPEC)
# Mapping chain: CVE → CWE → CAPEC (direct mappings only)
#
# Note: ATT&CK techniques and D3FEND defenses are NOT included because
# CVE2CAPEC's mappings are inherited from generic parent CWEs (inaccurate).
# Only direct CWE→CAPEC mappings from the most specific CWEs are used.

# Auto-update MITRE database when running enrichment
# If True, downloads latest CVE2CAPEC data before enrichment (respects TTL cache)
# If False, uses existing cached database only
MITRE_AUTO_UPDATE_DB = True

# Include CWE (Common Weakness Enumeration) information
# Shows the weakness type that enabled the vulnerability
MITRE_INCLUDE_CWE = True

# Include CAPEC (Common Attack Pattern Enumeration) information
# Shows the attack patterns directly associated with the specific CWE
MITRE_INCLUDE_CAPEC = True

# Which scan outputs to enrich with MITRE data
# Set to True to enrich recon output (vuln_scan.all_cves + technology_cves.by_technology.<tech>.cves)
MITRE_ENRICH_RECON = True

# Set to True to enrich GVM/OpenVAS output (scans[].unique_cves)
MITRE_ENRICH_GVM = True

# Local database cache settings
# Path where CVE2CAPEC database will be cached
MITRE_DATABASE_PATH = os.path.join(os.path.dirname(__file__), "data", "mitre_db")

# How long to cache the database before checking for updates (hours)
# CVE2CAPEC updates daily at 00:05 UTC
MITRE_CACHE_TTL_HOURS = 24






# =============================================================================
# Custom Security Checks Configuration
# =============================================================================
# These are custom security checks that complement Nuclei scanning.
# Each check can be individually enabled/disabled.
# Those security checks are not executed by Nuclei or other project libraries

# Global switch - set to False to skip ALL security checks entirely
SECURITY_CHECK_ENABLED = True

# --- Direct IP Access Checks ---
# Detect WAF bypass opportunities and direct IP exposure

# Check if HTTP is accessible directly via IP (no TLS)
SECURITY_CHECK_DIRECT_IP_HTTP = True

# Check if HTTPS is accessible directly via IP
SECURITY_CHECK_DIRECT_IP_HTTPS = True

# Check if API endpoints are exposed on direct IP
SECURITY_CHECK_IP_API_EXPOSED = True

# Check if WAF can be bypassed via direct IP access
SECURITY_CHECK_WAF_BYPASS = True

# --- TLS/SSL Security Checks ---
# Note: Most TLS checks (expired, self-signed, weak cipher, mismatch, missing, HSTS)
# are already covered by Nuclei templates. Only unique checks are kept here.

# Check for certificates expiring soon (within threshold days)
# Nuclei only checks expired certs, not "expiring soon"
SECURITY_CHECK_TLS_EXPIRING_SOON = True

# Days before expiry to warn about certificate renewal
SECURITY_CHECK_TLS_EXPIRY_DAYS = 30

# --- Security Headers Checks ---
# Note: Common headers (CSP, X-Frame-Options, X-Content-Type-Options, CORS, Server disclosure)
# are already covered by Nuclei templates. Only less common headers are checked here.

# Referrer-Policy - Controls referrer information leakage
SECURITY_CHECK_MISSING_REFERRER_POLICY = True

# Permissions-Policy - Controls browser feature access
SECURITY_CHECK_MISSING_PERMISSIONS_POLICY = True

# Cross-Origin-Opener-Policy - Prevents Spectre-like attacks
SECURITY_CHECK_MISSING_COOP = True

# Cross-Origin-Resource-Policy - Prevents cross-origin resource loading
SECURITY_CHECK_MISSING_CORP = True

# Cross-Origin-Embedder-Policy - Required for advanced features
SECURITY_CHECK_MISSING_COEP = True

# Cache-Control - Detects missing or weak cache control headers
SECURITY_CHECK_CACHE_CONTROL_MISSING = True

# --- Authentication Security Checks ---
# Detect authentication-related security issues

# Login form served over HTTP (credentials sent in clear text)
SECURITY_CHECK_LOGIN_NO_HTTPS = True

# Session cookie missing Secure flag (can be sent over HTTP)
SECURITY_CHECK_SESSION_NO_SECURE = True

# Session cookie missing HttpOnly flag (accessible via JavaScript)
SECURITY_CHECK_SESSION_NO_HTTPONLY = True

# Basic authentication used over HTTP (credentials in clear text)
SECURITY_CHECK_BASIC_AUTH_NO_TLS = True

# --- DNS Security Checks ---
# Email security and DNS configuration checks

# No SPF record (email spoofing possible)
SECURITY_CHECK_SPF_MISSING = True

# No DMARC record (no email authentication policy)
SECURITY_CHECK_DMARC_MISSING = True

# DNSSEC not enabled (DNS responses not cryptographically signed)
SECURITY_CHECK_DNSSEC_MISSING = True

# Zone transfer enabled (AXFR allowed - data leak)
SECURITY_CHECK_ZONE_TRANSFER = True

# --- Port/Service Security Checks ---
# Detect exposed sensitive services

# Admin ports exposed (SSH:22, RDP:3389, VNC:5900)
SECURITY_CHECK_ADMIN_PORT_EXPOSED = True

# Database ports exposed (MySQL:3306, PostgreSQL:5432, MongoDB:27017)
SECURITY_CHECK_DATABASE_EXPOSED = True

# Redis without authentication
SECURITY_CHECK_REDIS_NO_AUTH = True

# Kubernetes API exposed publicly
SECURITY_CHECK_KUBERNETES_API_EXPOSED = True

# SMTP open relay (accepts mail from any sender to any recipient)
SECURITY_CHECK_SMTP_OPEN_RELAY = True

# --- Application Security Checks ---
# Web application security issues

# CSP allows unsafe-inline (XSS protection weakened)
SECURITY_CHECK_CSP_UNSAFE_INLINE = True

# HTTPS form posts to HTTP endpoint (credentials leak)
SECURITY_CHECK_INSECURE_FORM_ACTION = True

# --- Rate Limiting Checks ---
# Detect missing rate limiting protections

# No rate limiting on sensitive endpoints
SECURITY_CHECK_NO_RATE_LIMITING = True

# --- Security Checks Performance ---
# Timeout for security check requests (seconds)
SECURITY_CHECK_TIMEOUT = 10

# Maximum concurrent workers for security checks
SECURITY_CHECK_MAX_WORKERS = 10


