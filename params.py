"""
RedAmon - Global Parameters
Configure target URL and other settings here.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv(Path(__file__).parent / ".env")

# Target for RECON
# TARGET_DOMAIN: Always specify the root domain (e.g., "vulnweb.com", "example.com")
# SUBDOMAIN_LIST: Filter which subdomains to scan
#   - Empty list []: Discover and scan ALL subdomains (full discovery mode)
#   - Specific prefixes ["testphp.", "www."]: Only scan these specific subdomains (filtered mode)
#
# Examples:
#   TARGET_DOMAIN = "vulnweb.com", SUBDOMAIN_LIST = []           → Scan all subdomains of vulnweb.com
#   TARGET_DOMAIN = "vulnweb.com", SUBDOMAIN_LIST = ["testphp."] → Only scan testphp.vulnweb.com
#   TARGET_DOMAIN = "example.com", SUBDOMAIN_LIST = ["dev.", "staging."] → Only scan dev.example.com and staging.example.com
#
TARGET_DOMAIN = "devergolabs.com"
SUBDOMAIN_LIST = []  # Empty = discover all, or specify prefixes like ["www.", "api."]
USER_ID = "samgiam"
PROJECT_ID = "project_testphp.vulnweb.com"

# =============================================================================
# SCAN MODULES - Control which modules to run
# =============================================================================
# Available modules (tool-agnostic names):
#   - "domain_discovery" : WHOIS + Subdomain discovery + DNS (creates initial JSON)
#   - "port_scan"        : Fast port scanning (updates JSON)
#   - "http_probe"       : HTTP probing and technology detection (updates JSON)
#   - "vuln_scan"        : Web vulnerability scanning + MITRE CWE/CAPEC enrichment (updates JSON)
#   - "github"           : GitHub secret hunting (creates separate JSON)
#
# Pipeline: domain_discovery -> port_scan -> http_probe -> vuln_scan -> github
#
# Note: vuln_scan automatically includes MITRE CWE/CAPEC enrichment for all CVEs found.
#       Configure MITRE enrichment settings in the "MITRE CWE/CAPEC Enrichment" section below.
#
# Examples:
#   ["domain_discovery"]                                         - Only domain recon
#   ["domain_discovery", "port_scan", "http_probe"]              - Recon + port/HTTP probing
#   ["domain_discovery", "port_scan", "http_probe", "vuln_scan"] - Full web scan (default)
#   ["domain_discovery", "port_scan", "http_probe", "vuln_scan", "github"] - Complete scan

SCAN_MODULES = ["domain_discovery", "port_scan", "http_probe", "vuln_scan"]
UPDATE_GRAPH_DB = True

# Hide your real IP during subdomain enumeration (uses Tor + proxychains)
# Requires: Tor running (sudo systemctl start tor) + proxychains4 installed
USE_TOR_FOR_RECON = False
USE_BRUTEFORCE_FOR_SUBDOMAINS = False

# =============================================================================
# GitHub Secret Hunt Configuration
# =============================================================================

# GitHub Personal Access Token (loaded from .env file)
# Generate at: https://github.com/settings/tokens
# Required scopes: repo (for private repos) or public_repo (for public only)
GITHUB_ACCESS_TOKEN = os.getenv("GITHUB_ACCESS_TOKEN", "")

# Target organization or username to scan
GITHUB_TARGET_ORG = "samugit83"

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
NAABU_RETRIES = 3

# Scan type: "s" (SYN - requires root, faster) or "c" (CONNECT - no root needed)
# SYN scan is more reliable and faster but requires root/sudo
NAABU_SCAN_TYPE = "s"

# Exclude CDN/WAF IPs (only scan ports 80,443 on CDN hosts)
# Helps avoid false positives from CDN-protected sites
NAABU_EXCLUDE_CDN = True

# Display CDN information in output
NAABU_DISPLAY_CDN = True

# Service name detection
# NOTE: Naabu's -sD flag exists but is NOT YET IMPLEMENTED
# RedAmon uses internal port-to-service mapping instead (see get_service_name())
# This setting is currently ignored until naabu implements service discovery
NAABU_SERVICE_DETECTION = True

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
WAPPALYZER_CACHE_DIR = os.path.join(os.path.dirname(__file__), "recon", "data")
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
NUCLEI_EXCLUDE_TAGS = ["dos", "ddos"]

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
KATANA_TIMEOUT = 300  # 5 minutes

# Include URLs from JavaScript parsing
KATANA_JS_CRAWL = True

# Only keep URLs with query parameters (for DAST fuzzing)
KATANA_PARAMS_ONLY = True

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
MITRE_DATABASE_PATH = os.path.join(os.path.dirname(__file__), "recon", "data", "mitre_db")

# How long to cache the database before checking for updates (hours)
# CVE2CAPEC updates daily at 00:05 UTC
MITRE_CACHE_TTL_HOURS = 24






# =============================================================================
# GVM/OpenVAS Vulnerability Scanner Configuration
# =============================================================================

USE_RECON_FOR_TARGET=True
GVM_IP_LIST=[]
GVM_HOSTNAME_LIST=[]

# GVM connection settings (for Docker deployment)
GVM_SOCKET_PATH = "/run/gvmd/gvmd.sock"  # Unix socket path inside container
GVM_USERNAME = "admin"
GVM_PASSWORD = os.getenv("GVM_PASSWORD", "admin")  # Set in .env for security

# Scan configuration preset:
# - "Full and fast" - Comprehensive scan, good performance (recommended)
# - "Full and fast ultimate" - Most thorough, slower
# - "Full and very deep" - Deep scan, very slow
# - "Full and very deep ultimate" - Maximum coverage, very slow
# - "Discovery" - Network discovery only, no vulnerability tests
# - "Host Discovery" - Basic host enumeration
# - "System Discovery" - System enumeration
GVM_SCAN_CONFIG = "Full and fast"

# Scan targets strategy:
# - "both" - Scan IPs and hostnames separately for thorough coverage
# - "ips_only" - Only scan IP addresses
# - "hostnames_only" - Only scan hostnames/subdomains
GVM_SCAN_TARGETS = "both"

# Maximum time to wait for a single scan task (seconds, 0 = unlimited)
# Note: "Full and fast" scans can take 1-2+ hours per target
GVM_TASK_TIMEOUT = 14400  # 4 hours (increase if needed for many targets)

# Poll interval for checking scan status (seconds)
GVM_POLL_INTERVAL = 30

# Cleanup targets and tasks after scan completion
GVM_CLEANUP_AFTER_SCAN = True

