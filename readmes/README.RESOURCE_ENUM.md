# RedAmon - Resource Enumeration Module

## Complete Technical Documentation

> **Module:** `recon/resource_enum.py`
> **Purpose:** Endpoint discovery, classification, and parameter extraction
> **Author:** RedAmon Security Suite

---

## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Installation](#installation)
4. [Configuration Parameters](#configuration-parameters)
5. [GAU Configuration](#gau-configuration)
6. [Kiterunner Configuration](#kiterunner-configuration)
7. [Hakrawler Configuration](#hakrawler-configuration)
8. [jsluice Configuration](#jsluice-configuration)
9. [Architecture & Flow](#architecture--flow)
10. [Output Data Structure](#output-data-structure)
11. [Endpoint Classification](#endpoint-classification)
12. [Parameter Classification](#parameter-classification)
13. [Form Parsing](#form-parsing)
14. [Usage Examples](#usage-examples)
15. [Troubleshooting](#troubleshooting)

---

## Overview

The `resource_enum.py` module provides comprehensive endpoint discovery and classification for web applications. It combines **active crawling** (Katana + Hakrawler), **passive historical URL discovery** (GAU), **passive parameter mining** (ParamSpider), **API bruteforcing** (Kiterunner), **JavaScript analysis** (jsluice), **directory fuzzing** (FFuf), and **hidden parameter discovery** (Arjun) to maximize endpoint coverage, extracts parameters, parses HTML forms, discovers embedded secrets, and organizes everything into a structured format ready for vulnerability scanning.

**Pipeline Position:** GROUP 5 in the parallelized pipeline (`GROUP 4: http_probe -> GROUP 5: resource_enum -> GROUP 6: vuln_scan`). Katana, Hakrawler, GAU, ParamSpider, and Kiterunner run concurrently via internal `ThreadPoolExecutor`. jsluice runs sequentially after crawling to analyze discovered JavaScript files. FFuf runs after jsluice to brute-force directory paths using wordlists. Arjun runs after FFuf to discover hidden parameters on discovered endpoints, with multiple methods (GET/POST/JSON/XML) executing in parallel.

### Why Resource Enumeration?

| Feature | Without resource_enum | With resource_enum |
|---------|----------------------|-------------------|
| Endpoint Discovery | Manual or basic | **Automated crawling + passive + API bruteforce** |
| Historical URLs | Missed | **GAU finds old/deleted endpoints** |
| Hidden APIs | Missed | **Kiterunner finds undocumented APIs** |
| POST Endpoints | Missed | **Form parsing** |
| Parameter Extraction | None | **Full extraction** |
| Endpoint Classification | None | **Categorized** |
| Parameter Types | Unknown | **Inferred** |
| Vulnerability Coverage | Limited | **Comprehensive** |

### How It Works

```
┌─────────────────┐     ┌────────────────────────────────────────────────┐     ┌─────────────────┐
│  http_probe     │────▶│              resource_enum                      │────▶│  js_recon (5b)  │────▶│  vuln_scan      │
│  (live URLs,    │     │                                                │     │  (targeted      │
│   responses)    │     │  ┌────────────┐ ┌────────────┐ ┌─────────────┐ │     │   scanning)     │
└─────────────────┘     │  │  Katana    │ │    GAU     │ │ Kiterunner  │ │     └─────────────────┘
                        │  │  (active)  │ │  (passive) │ │ (API brute) │ │
                        │  │            │ │            │ │             │ │
                        │  │ Crawl site │ │ Query:     │ │ Bruteforce: │ │
                        │  │ Parse JS   │ │ - Wayback  │ │ - 40k+ APIs │ │
                        │  │ Find forms │ │ - CommonCrl│ │ - Swagger   │ │
                        │  └─────┬──────┘ │ - OTX      │ │ - OpenAPI   │ │
                        │        │        │ - URLScan  │ └──────┬──────┘ │
                        │        │        └─────┬──────┘        │        │
                        │        └───────────┬──┴───────────────┘        │
                        │                    ▼                           │
                        │  ┌──────────────────────────────────────────┐  │
                        │  │  Merge & Deduplicate                     │  │
                        │  │  + Source tracking (sources array)       │  │
                        │  │  + Endpoint Classification               │  │
                        │  └──────────────────────────────────────────┘  │
                        └────────────────────────────────────────────────┘
```

---

## Features

| Feature | Description |
|---------|-------------|
| **Katana Crawling** | Deep endpoint discovery using ProjectDiscovery's Katana (active) |
| **GAU Discovery** | Historical URL discovery from Wayback, CommonCrawl, OTX, URLScan (passive) |
| **Kiterunner API Bruteforce** | Hidden API discovery using 40k+ Swagger/OpenAPI specifications |
| **Hakrawler Crawling** | DOM-aware web crawling via Docker (active) |
| **jsluice JS Analysis** | JavaScript analysis to extract URLs, endpoints, and secrets (downloads JS files from target) |
| **FFuf Directory Fuzzing** | Brute-force directory/endpoint discovery using wordlists (built-in SecLists + custom uploads) |
| **ParamSpider Parameter Mining** | Passive Wayback Machine CDX query for parameterized URLs — returns only URLs with query parameters, values replaced by placeholder (FUZZ) |
| **Arjun Parameter Discovery** | Discovers hidden HTTP query/body parameters on discovered endpoints using ~25,000 parameter names. Multi-method parallel execution (GET/POST/JSON/XML) |
| **Parallel Execution** | Katana, Hakrawler, GAU, ParamSpider, and Kiterunner run simultaneously, then jsluice → FFuf → Arjun sequential (Arjun methods run in parallel internally) |
| **URL Verification** | Verifies GAU URLs are live before adding to results |
| **Method Detection** | OPTIONS probe detects allowed HTTP methods (GET, POST, PUT, DELETE) |
| **Dead Endpoint Filtering** | Filters out endpoints that don't respond (404, 500, timeout) |
| **JavaScript Parsing** | Discovers endpoints in JavaScript files |
| **Form Extraction** | Parses HTML forms for POST endpoints |
| **Parameter Extraction** | Extracts query and body parameters |
| **Type Inference** | Infers parameter data types (integer, email, URL, etc.) |
| **Endpoint Classification** | Categorizes endpoints (auth, api, admin, file_access, etc.) |
| **Parameter Classification** | Identifies sensitive params (id, file, auth, redirect, command) |
| **Source Tracking** | Each endpoint tracked with `sources` array: `["katana", "hakrawler", "gau", "paramspider", "kiterunner", "jsluice", "arjun"]` |
| **Docker Execution** | Runs via Docker for consistency |
| **Tor Support** | Anonymous crawling via SOCKS proxy |
| **Incremental Output** | Saves results as crawling progresses |

---

## Installation

### Requirements

- **Docker** installed and running
- Previous pipeline steps completed (`http_probe`)

### Setup

```bash
# Make sure Docker is running
sudo systemctl start docker

# Run the scan - image will be pulled automatically
python3 recon/main.py
```

### Verify Docker is Ready

```bash
# Check Docker is running
docker info

# Optionally pre-pull the images
docker pull projectdiscovery/katana:latest
docker pull sxcurity/gau:latest
# Kiterunner binary is auto-downloaded from GitHub releases (no Docker needed)
docker pull projectdiscovery/httpx:latest  # For URL verification
```

---

## Configuration Parameters

All parameters are configured via the webapp project settings (stored in PostgreSQL) or as defaults in `project_settings.py`.

---

### 1. Core Katana Configuration

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `KATANA_DOCKER_IMAGE` | `str` | `"projectdiscovery/katana:latest"` | Docker image to use |
| `KATANA_DEPTH` | `int` | `3` | Maximum crawl depth (how many links deep to follow) |
| `KATANA_MAX_URLS` | `int` | `1000` | Maximum URLs to discover per target |
| `KATANA_RATE_LIMIT` | `int` | `150` | Requests per second |
| `KATANA_TIMEOUT` | `int` | `300` | Maximum crawl time in seconds (5 minutes) |

**Depth Tuning Guide:**

| Depth | Use Case | Coverage | Time |
|-------|----------|----------|------|
| 1 | Quick scan, homepage only | Low | Fast |
| 2 | Standard reconnaissance | Medium | Moderate |
| **3** | **Default** - balanced coverage | Good | ~5 min |
| 5+ | Deep analysis, large sites | Comprehensive | Long |

---

### 2. Crawl Behavior

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `KATANA_JS_CRAWL` | `bool` | `True` | Parse JavaScript files for endpoints |
| `KATANA_PARAMS_ONLY` | `bool` | `False` | Only keep URLs with query parameters |
| `KATANA_SCOPE` | `str` | `"rdn"` | Scope: `rdn` (root domain), `dn` (domain), `fqdn` (full) |

**Scope Options:**

| Scope | Description | Example |
|-------|-------------|---------|
| `rdn` | Root domain and all subdomains | `*.example.com` |
| `dn` | Exact domain only | `www.example.com` |
| `fqdn` | Exact FQDN only | `www.example.com` (no subdomains) |

---

### 3. Filtering

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `KATANA_EXCLUDE_PATTERNS` | `list` | See below | URL patterns to exclude |
| `KATANA_CUSTOM_HEADERS` | `list` | `[]` | Custom HTTP headers |

**Default Exclude Patterns:**

```python
KATANA_EXCLUDE_PATTERNS = [
    # Next.js / React
    "/_next/image",          # Image optimization
    "/_next/static",         # Static assets

    # WordPress
    "/wp-content/uploads",   # Media uploads
    "/wp-includes",          # Core files

    # Common static
    "/static/",              # Static directories
    "/assets/",              # Asset directories
    ".css", ".js",           # Stylesheets, scripts
    ".jpg", ".png", ".gif",  # Images
    ".woff", ".ttf",         # Fonts
]
```

---

### 4. Performance Profiles

#### Fast Mode (Quick Recon)
```python
KATANA_DEPTH = 2
KATANA_MAX_URLS = 500
KATANA_RATE_LIMIT = 200
KATANA_TIMEOUT = 120
KATANA_JS_CRAWL = False
KATANA_PARAMS_ONLY = True
```
**Expected:** ~1-2 minutes per target

#### Balanced Mode (Default)
```python
KATANA_DEPTH = 3
KATANA_MAX_URLS = 1000
KATANA_RATE_LIMIT = 150
KATANA_TIMEOUT = 300
KATANA_JS_CRAWL = True
KATANA_PARAMS_ONLY = False
```
**Expected:** ~3-5 minutes per target

#### Deep Analysis Mode
```python
KATANA_DEPTH = 5
KATANA_MAX_URLS = 5000
KATANA_RATE_LIMIT = 100
KATANA_TIMEOUT = 600
KATANA_JS_CRAWL = True
KATANA_PARAMS_ONLY = False
```
**Expected:** ~10-15 minutes per target

---

## GAU Configuration

GAU (GetAllUrls) provides passive URL discovery from historical archives. It runs in parallel with Katana.

### 1. Core GAU Settings

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `GAU_ENABLED` | `bool` | `True` | Enable/disable GAU discovery |
| `GAU_DOCKER_IMAGE` | `str` | `"sxcurity/gau:latest"` | Docker image to use |
| `GAU_PROVIDERS` | `list` | `["wayback", "commoncrawl", "otx", "urlscan"]` | Data sources to query |
| `GAU_MAX_URLS` | `int` | `1000` | Maximum URLs per domain (0 = unlimited) |
| `GAU_TIMEOUT` | `int` | `60` | Timeout per provider in seconds |
| `GAU_THREADS` | `int` | `5` | Parallel threads for fetching |

### 2. GAU Data Sources

| Provider | Description | URL Type |
|----------|-------------|----------|
| **wayback** | Wayback Machine (web.archive.org) | Historical snapshots |
| **commoncrawl** | Common Crawl (index.commoncrawl.org) | Web crawl data |
| **otx** | AlienVault OTX | Threat intelligence |
| **urlscan** | URLScan.io | Security scan results |

### 3. Filtering Options

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `GAU_BLACKLIST_EXTENSIONS` | `list` | See below | File extensions to exclude |
| `GAU_YEAR_RANGE` | `list` | `[]` | Filter by year range, e.g., `["2020", "2024"]` |

**Default Blacklisted Extensions:**
```python
GAU_BLACKLIST_EXTENSIONS = [
    "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "avif",
    "css", "woff", "woff2", "ttf", "eot", "otf",
    "mp3", "mp4", "avi", "mov", "wmv", "flv", "webm",
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "zip", "rar", "7z", "tar", "gz"
]
```

### 4. URL Verification

GAU URLs are verified to check if they're still live before adding to results.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `GAU_VERIFY_URLS` | `bool` | `True` | Enable HTTP verification |
| `GAU_VERIFY_DOCKER_IMAGE` | `str` | `"projectdiscovery/httpx:latest"` | httpx image for verification |
| `GAU_VERIFY_TIMEOUT` | `int` | `5` | Timeout per URL in seconds |
| `GAU_VERIFY_RATE_LIMIT` | `int` | `100` | Requests per second |
| `GAU_VERIFY_THREADS` | `int` | `50` | Concurrent verification threads |
| `GAU_VERIFY_ACCEPT_STATUS` | `list` | `[200, 201, 301, 302, 307, 308, 401, 403]` | HTTP status codes to accept |

### 5. HTTP Method Detection (OPTIONS Probe)

GAU doesn't know which HTTP methods an endpoint supports. This feature uses the OPTIONS HTTP method to detect allowed methods from the server's `Allow` header.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `GAU_DETECT_METHODS` | `bool` | `True` | Enable OPTIONS probe for method detection |
| `GAU_METHOD_DETECT_TIMEOUT` | `int` | `5` | Timeout per URL in seconds |
| `GAU_METHOD_DETECT_RATE_LIMIT` | `int` | `50` | Requests per second |
| `GAU_METHOD_DETECT_THREADS` | `int` | `25` | Concurrent threads |
| `GAU_FILTER_DEAD_ENDPOINTS` | `bool` | `True` | Filter out endpoints that don't respond |

**How It Works:**

1. Send OPTIONS request to each verified GAU URL
2. Parse `Allow` header from response (e.g., `Allow: GET, POST, PUT, DELETE`)
3. If no Allow header, fall back to GET check
4. Filter out dead endpoints (404, 500, timeout)
5. Store detected methods in endpoint data

**Example Output:**

```json
{
  "/api/users": {
    "methods": ["GET", "POST", "PUT", "DELETE"],
    "source": "gau"
  },
  "/login": {
    "methods": ["GET", "POST"],
    "source": "gau"
  }
}
```

**Why This Matters:**
- Katana can detect methods from form parsing (e.g., `<form method="POST">`)
- GAU only returns URLs - no method info
- OPTIONS probe discovers POST/PUT/DELETE endpoints that would otherwise be missed
- Dead endpoints (404/500) are filtered out to reduce noise

### 6. GAU Configuration Profiles

#### Minimal (Fast)
```python
GAU_ENABLED = True
GAU_PROVIDERS = ["wayback"]  # Single source
GAU_MAX_URLS = 500
GAU_VERIFY_URLS = False  # Skip verification
GAU_DETECT_METHODS = False  # Skip method detection
```
**Expected:** ~10-20 seconds per domain

#### Balanced (Default)
```python
GAU_ENABLED = True
GAU_PROVIDERS = ["wayback", "commoncrawl", "otx", "urlscan"]
GAU_MAX_URLS = 1000
GAU_VERIFY_URLS = True
GAU_DETECT_METHODS = True
GAU_FILTER_DEAD_ENDPOINTS = True
```
**Expected:** ~30-60 seconds per domain

#### Comprehensive
```python
GAU_ENABLED = True
GAU_PROVIDERS = ["wayback", "commoncrawl", "otx", "urlscan"]
GAU_MAX_URLS = 5000
GAU_YEAR_RANGE = []  # All years
GAU_VERIFY_URLS = True
GAU_DETECT_METHODS = True
GAU_FILTER_DEAD_ENDPOINTS = True
```
**Expected:** ~2-5 minutes per domain

### 7. What GAU Finds

| Category | Examples | Why It Matters |
|----------|----------|----------------|
| **Old Admin Panels** | `/admin/`, `/wp-admin/`, `/administrator/` | May still be accessible |
| **Debug Endpoints** | `/phpinfo.php`, `/debug/`, `/test/` | Information disclosure |
| **Backup Files** | `/backup.sql`, `/db_dump.sql`, `/config.bak` | Sensitive data |
| **Old API Versions** | `/api/v1/`, `/api/beta/` | May have unpatched vulns |
| **Hidden Parameters** | `?debug=1`, `?admin=true` | Bypass security |
| **Forgotten Uploads** | `/uploads/temp/`, `/files/old/` | Sensitive files |

---

## Kiterunner Configuration

Kiterunner provides API endpoint bruteforcing using real Swagger/OpenAPI specifications. It runs in parallel with Katana and GAU.

### 1. Core Kiterunner Settings

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `KITERUNNER_ENABLED` | `bool` | `True` | Enable/disable Kiterunner discovery |
| (Binary auto-download) | - | `~/.redamon/tools/kiterunner/kr` | Auto-downloaded from GitHub releases |
| `KITERUNNER_WORDLIST` | `str` | `"apiroutes-251227"` | Wordlist (354k+ API routes) |
| `KITERUNNER_RATE_LIMIT` | `int` | `100` | Requests per second |
| `KITERUNNER_CONNECTIONS` | `int` | `100` | Concurrent connections |
| `KITERUNNER_TIMEOUT` | `int` | `10` | Request timeout per endpoint (seconds) |
| `KITERUNNER_SCAN_TIMEOUT` | `int` | `300` | Overall scan timeout (seconds) |
| `KITERUNNER_THREADS` | `int` | `50` | Scanning threads |

### 2. Kiterunner Wordlists

Run `kr wordlist list` to see all available wordlists.

| Wordlist | Description | Routes |
|----------|-------------|--------|
| `apiroutes-251227` | Comprehensive API routes (default) | 354,000+ |
| `aspx-251227` | ASP.NET specific routes | ~82,000 |
| `jsp-251227` | JSP/Java specific routes | ~21,000 |
| `php-251227` | PHP specific routes | ~178,000 |
| `directories-251227` | Directory discovery | ~703,000 |
| Custom path | Your own wordlist | Variable |

### 3. Filtering Options

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `KITERUNNER_IGNORE_STATUS` | `list` | `[404, 400, 502, 503]` | Status codes to ignore |
| `KITERUNNER_MATCH_STATUS` | `list` | `[]` | Only match these status codes (empty = all) |
| `KITERUNNER_MIN_CONTENT_LENGTH` | `int` | `0` | Ignore responses smaller than this |
| `KITERUNNER_HEADERS` | `list` | `[]` | Custom headers for authenticated scanning |

### 4. Kiterunner Configuration Profiles

#### Minimal (Fast)
```python
KITERUNNER_ENABLED = True
KITERUNNER_WORDLIST = "apiroutes-251227"
KITERUNNER_RATE_LIMIT = 200
KITERUNNER_SCAN_TIMEOUT = 120
```
**Expected:** ~1-2 minutes per target

#### Balanced (Default)
```python
KITERUNNER_ENABLED = True
KITERUNNER_WORDLIST = "apiroutes-251227"
KITERUNNER_RATE_LIMIT = 100
KITERUNNER_CONNECTIONS = 100
KITERUNNER_SCAN_TIMEOUT = 300
```
**Expected:** ~3-5 minutes per target

#### Comprehensive (Stealth)
```python
KITERUNNER_ENABLED = True
KITERUNNER_WORDLIST = "apiroutes-251227"
KITERUNNER_RATE_LIMIT = 50
KITERUNNER_CONNECTIONS = 50
KITERUNNER_SCAN_TIMEOUT = 600
```
**Expected:** ~5-10 minutes per target

### 5. What Kiterunner Finds

| Category | Examples | Why It Matters |
|----------|----------|----------------|
| **Hidden REST APIs** | `/api/v1/users`, `/api/admin/config` | Undocumented functionality |
| **GraphQL Endpoints** | `/graphql`, `/gql`, `/api/graphql` | Complex query surface |
| **Internal APIs** | `/internal/`, `/private/`, `/debug/` | Bypass access controls |
| **Version Endpoints** | `/version`, `/health`, `/status` | Information disclosure |
| **CRUD Operations** | `/users/create`, `/posts/delete` | Data manipulation |
| **Swagger/OpenAPI** | `/swagger.json`, `/api-docs` | API documentation exposure |

### 6. Why Kiterunner Over Traditional Wordlists?

| Feature | Traditional Wordlists | Kiterunner |
|---------|----------------------|------------|
| Route coverage | Limited to common paths | 40k+ real API routes |
| HTTP Methods | Usually GET only | Correct method per route |
| Parameters | None | Swagger-defined params |
| Headers | None | API-specific headers |
| False positives | Many 404s | Validated responses |

---

## Hakrawler Configuration

Hakrawler is a DOM-aware web crawler that runs as a Docker container (`jauderho/hakrawler`). It runs in parallel with Katana, GAU, and Kiterunner, providing an additional crawling perspective with scope-aware link following.

### 1. Core Hakrawler Settings

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `HAKRAWLER_ENABLED` | `bool` | `True` | Enable/disable Hakrawler crawling |
| `HAKRAWLER_DOCKER_IMAGE` | `str` | `"jauderho/hakrawler:latest"` | Docker image to use |
| `HAKRAWLER_DEPTH` | `int` | `2` | Crawl depth (how many links deep to follow) |
| `HAKRAWLER_THREADS` | `int` | `5` | Concurrent threads |
| `HAKRAWLER_TIMEOUT` | `int` | `30` | Per-URL timeout in seconds |
| `HAKRAWLER_MAX_URLS` | `int` | `500` | Maximum URLs to discover |
| `HAKRAWLER_INCLUDE_SUBS` | `bool` | `True` | Include subdomains in crawl scope |
| `HAKRAWLER_INSECURE` | `bool` | `True` | Skip TLS certificate verification |
| `HAKRAWLER_CUSTOM_HEADERS` | `list` | `[]` | Custom HTTP headers |

### 2. Scope Filtering

Hakrawler scope filtering works at two levels:

| Level | Mechanism | Description |
|-------|-----------|-------------|
| **Crawl scope** | `-subs` flag | If `INCLUDE_SUBS=True`, Hakrawler follows links to subdomains of the target |
| **Output scope** | Hostname exact match | After crawling, results are filtered against `target_domains` set (from http_probe). URLs with hostnames not in scope are captured as `ExternalDomain` nodes instead of `Endpoint` nodes |

### 3. What Hakrawler Finds

| Category | Examples | Why It Matters |
|----------|----------|----------------|
| **DOM links** | `<a href="...">`, `<link>`, `<script src>` | Links that JS-rendered crawlers may miss |
| **Form actions** | `<form action="/submit">` | POST endpoints for parameter fuzzing |
| **Asset references** | CSS imports, image URLs, font files | Reveals directory structure |
| **Subdomain links** | Links pointing to `api.example.com` | Discovers related subdomains |
| **External domains** | Links to third-party services | Maps external dependencies |

### 4. Stealth Mode

When `STEALTH_MODE` is enabled, Hakrawler is automatically **disabled** to reduce the active crawling footprint. jsluice max files is reduced to 20.

---

## jsluice Configuration

jsluice is a JavaScript analysis tool compiled into the recon container (no Docker image needed). It downloads JavaScript files already discovered by Katana/Hakrawler from the target and analyzes their contents locally to extract URLs, API endpoints, and embedded secrets.

### 1. Core jsluice Settings

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `JSLUICE_ENABLED` | `bool` | `True` | Enable/disable jsluice analysis |
| `JSLUICE_MAX_FILES` | `int` | `50` | Maximum number of JS files to analyze |
| `JSLUICE_TIMEOUT` | `int` | `120` | Overall timeout in seconds |
| `JSLUICE_CONCURRENCY` | `int` | `5` | Files to process concurrently |
| `JSLUICE_EXTRACT_URLS` | `bool` | `True` | Run URL extraction mode |
| `JSLUICE_EXTRACT_SECRETS` | `bool` | `True` | Run secret detection mode |

### 2. How jsluice Works

jsluice sends HTTP requests to download each JS file from the target, then analyzes them locally:

1. **Filter**: Selects `.js` and `.mjs` URLs from all URLs discovered by Katana/Hakrawler/GAU
2. **Download**: Fetches JS files to a temporary directory (`/tmp/redamon/jsluice_<pid>/`)
3. **Analyze URLs**: Runs `jsluice urls` to extract embedded URLs and API endpoints
4. **Analyze Secrets**: Runs `jsluice secrets` to detect API keys, tokens, credentials
5. **Scope filter**: Extracted URLs are filtered against `allowed_hosts`; out-of-scope URLs become `ExternalDomain` nodes
6. **Cleanup**: Temporary files are deleted in a `finally` block

### 3. What jsluice Finds

**URL Extraction:**

| Category | Examples | Why It Matters |
|----------|----------|----------------|
| **API endpoints** | `/api/v2/users`, `/graphql` | Hidden backend routes |
| **Internal URLs** | `/admin/config`, `/debug/vars` | Undocumented functionality |
| **External services** | `https://api.stripe.com/v1/charges` | Third-party integrations |
| **CDN/asset paths** | `/static/js/`, `/assets/` | Directory structure |

**Secret Detection:**

| Secret Type | Examples | Severity |
|-------------|----------|----------|
| **AWS Access Keys** | `AKIA...` | High |
| **GitHub Tokens** | `ghp_...`, `gho_...` | High |
| **GCP Credentials** | `AIza...` | High |
| **API Keys** | Generic API key patterns | Medium |
| **Private Keys** | `-----BEGIN RSA PRIVATE KEY-----` | High |
| **JWT Tokens** | `eyJ...` | Medium |

Discovered secrets are stored as **Secret** nodes in Neo4j, linked to their parent `BaseURL` via `[:HAS_SECRET]`.

### 4. jsluice in the Pipeline

jsluice runs **sequentially after** the parallel crawling phase (Katana + Hakrawler + GAU + Kiterunner), because it needs their discovered URLs as input. It adds minimal time since JS file analysis is CPU-bound (no network scanning).

---

## Architecture & Flow

> **Pipeline context:** Resource enumeration runs in **GROUP 5** of the parallelized recon pipeline, after HTTP probing (GROUP 4). The four discovery tools (Katana, Hakrawler, GAU, Kiterunner) run concurrently via an internal `ThreadPoolExecutor`. jsluice then runs sequentially on discovered JS files. Graph DB updates happen in a background thread.

### Execution Flow

```
1. INITIALIZATION
   └── Check Docker availability
   └── Pull Katana + GAU + Kiterunner images in parallel
   └── Check Tor availability (if enabled)

2. TARGET EXTRACTION
   └── Get live URLs from http_probe
   └── Extract domains for GAU
   └── Filter by status code (< 500)
   └── Fallback to DNS data if no http_probe

3. PARALLEL DISCOVERY (Katana + Hakrawler + GAU + Kiterunner)
   ┌───────────────────────────────────────────────────────────────────────────┐
   │  ThreadPoolExecutor (max_workers=4)                                       │
   │                                                                           │
   │  ┌───────────┐  ┌────────────┐  ┌───────────┐  ┌────────────────────┐    │
   │  │  KATANA   │  │ HAKRAWLER  │  │    GAU    │  │    KITERUNNER      │    │
   │  │  (active) │  │  (active)  │  │ (passive) │  │    (API brute)     │    │
   │  │           │  │            │  │           │  │                    │    │
   │  │ - Crawl   │  │ - DOM-walk │  │ - Wayback │  │ - Swagger specs    │    │
   │  │ - Parse JS│  │ - Docker   │  │ - CmnCrl  │  │ - 40k+ API routes  │    │
   │  │ - Find URL│  │ - Scope    │  │ - OTX     │  │ - Method detection │    │
   │  │           │  │            │  │ - URLScan │  │                    │    │
   │  └─────┬─────┘  └─────┬──────┘  └─────┬─────┘  └─────────┬──────────┘    │
   │        │               │               │                  │               │
   └────────┴───────────────┴───────────────┴──────────────────┴───────────────┘
                              │
                              ▼
3b. JSLUICE ANALYSIS (sequential, after parallel discovery)
   └── Filter discovered URLs to .js/.mjs files
   └── Download JS files to /tmp/redamon/jsluice_<pid>/
   └── Run jsluice urls (extract endpoints)
   └── Run jsluice secrets (detect API keys, tokens, credentials)
   └── Scope-filter extracted URLs
   └── Cleanup temp files

4. GAU URL VERIFICATION (if enabled)
   └── Write GAU URLs to temp file
   └── Run httpx Docker for verification
   └── Filter to live URLs only

5. METHOD DETECTION (if enabled)
   └── Send OPTIONS request to each verified URL
   └── Parse 'Allow' header for supported methods
   └── Fall back to GET check if OPTIONS fails
   └── Filter out dead endpoints (404/500/timeout)

6. MERGE & DEDUPLICATE
   └── Mark Katana endpoints with sources=['katana']
   └── Merge Hakrawler URLs, add 'hakrawler' to sources array
   └── Merge GAU URLs, add 'gau' to sources array
   └── Merge Kiterunner APIs, add 'kiterunner' to sources array
   └── Merge jsluice URLs, add 'jsluice' to sources array
   └── Apply detected methods to endpoints
   └── Track overlap statistics for each tool

7. FORM PARSING
   └── Extract HTML from http_probe responses
   └── Parse <form> elements
   └── Extract action URLs and methods
   └── Extract input fields

8. ENDPOINT ORGANIZATION
   └── Group by base URL
   └── Parse query parameters
   └── Merge form data
   └── Classify endpoints
   └── Classify parameters

9. OUTPUT GENERATION
   └── Build structured JSON
   └── Include GAU + Hakrawler + Kiterunner + jsluice stats
   └── Generate summary statistics
   └── Save to recon file
```

### Data Flow Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                        http_probe data                           │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐     │
│  │ live URLs      │  │ response bodies │  │ status codes   │     │
│  │ (for crawling) │  │ (for forms)     │  │ (filtering)    │     │
│  └───────┬────────┘  └───────┬────────┘  └───────┬────────┘     │
└──────────┼───────────────────┼───────────────────┼──────────────┘
           │                   │                   │
           ▼                   ▼                   │
    ┌──────────────┐    ┌──────────────┐          │
    │ Katana       │    │ Form Parser  │          │
    │ Crawler      │    │              │          │
    └──────┬───────┘    └──────┬───────┘          │
           │                   │                   │
           ▼                   ▼                   │
    ┌──────────────────────────────────────┐      │
    │          organize_endpoints()         │◄─────┘
    │  - Parse URLs                         │
    │  - Extract parameters                 │
    │  - Merge form data                    │
    │  - Classify endpoints                 │
    │  - Classify parameters                │
    └──────────────────┬───────────────────┘
                       │
                       ▼
    ┌──────────────────────────────────────┐
    │          resource_enum result         │
    │  - by_base_url (organized endpoints)  │
    │  - forms (POST endpoints)             │
    │  - discovered_urls (raw list)         │
    │  - summary (statistics)               │
    └──────────────────────────────────────┘
```

---

## Output Data Structure

### Complete JSON Schema

```json
{
  "resource_enum": {
    "scan_metadata": {
      "scan_timestamp": "2024-01-15T12:00:00.000000",
      "scan_duration_seconds": 145.5,

      "katana_docker_image": "projectdiscovery/katana:latest",
      "katana_crawl_depth": 3,
      "katana_max_urls": 1000,
      "katana_rate_limit": 150,
      "katana_js_crawl": true,
      "katana_params_only": false,
      "katana_urls_found": 234,

      "gau_enabled": true,
      "gau_docker_image": "sxcurity/gau:latest",
      "gau_providers": ["wayback", "commoncrawl", "otx", "urlscan"],
      "gau_urls_found": 156,
      "gau_verify_enabled": true,
      "gau_method_detection_enabled": true,
      "gau_filter_dead_endpoints": true,
      "gau_stats": {
        "gau_total": 156,
        "gau_parsed": 142,
        "gau_new": 87,
        "gau_overlap": 55,
        "gau_skipped_unverified": 14,
        "gau_skipped_dead": 8,
        "gau_with_post": 23,
        "gau_with_multiple_methods": 15
      },

      "kiterunner_enabled": true,
      "kiterunner_binary_path": "~/.redamon/tools/kiterunner/kr",
      "kiterunner_wordlist": "apiroutes-251227",
      "kiterunner_endpoints_found": 45,
      "kiterunner_stats": {
        "kr_total": 45,
        "kr_parsed": 45,
        "kr_new": 38,
        "kr_overlap": 7,
        "kr_methods": {"GET": 30, "POST": 12, "PUT": 3}
      },

      "hakrawler_enabled": true,
      "hakrawler_docker_image": "jauderho/hakrawler:latest",
      "hakrawler_depth": 2,
      "hakrawler_threads": 5,
      "hakrawler_urls_found": 78,

      "jsluice_enabled": true,
      "jsluice_max_files": 50,
      "jsluice_urls_found": 42,
      "jsluice_secrets_found": 3,

      "proxy_used": false,
      "target_urls_count": 5,
      "target_domains_count": 3,
      "total_discovered_urls": 321
    },

    "discovered_urls": [
      "https://example.com/",
      "https://example.com/login?redirect=/dashboard",
      "https://example.com/api/v1/users?id=1",
      "https://example.com/old-admin/config.php",
      "https://example.com/search?q=test"
    ],

    "by_base_url": {
      "https://example.com": {
        "base_url": "https://example.com",
        "endpoints": {
          "/login": {
            "path": "/login",
            "methods": ["GET", "POST"],
            "parameters": {
              "query": [
                {
                  "name": "redirect",
                  "type": "url",
                  "sample_values": ["/dashboard", "/home"],
                  "category": "redirect_params"
                }
              ],
              "body": [
                {
                  "name": "username",
                  "type": "string",
                  "input_type": "text",
                  "required": true,
                  "category": "auth_params"
                },
                {
                  "name": "password",
                  "type": "string",
                  "input_type": "password",
                  "required": true,
                  "category": "auth_params"
                }
              ],
              "path": []
            },
            "sample_urls": ["https://example.com/login?redirect=/dashboard"],
            "urls_found": 3,
            "category": "authentication",
            "sources": ["katana", "gau"],
            "parameter_count": {
              "query": 1,
              "body": 2,
              "path": 0,
              "total": 3
            }
          },
          "/api/v1/users": {
            "path": "/api/v1/users",
            "methods": ["GET"],
            "parameters": {
              "query": [
                {
                  "name": "id",
                  "type": "integer",
                  "sample_values": ["1", "2", "100"],
                  "category": "id_params"
                }
              ],
              "body": [],
              "path": []
            },
            "sample_urls": ["https://example.com/api/v1/users?id=1"],
            "urls_found": 5,
            "category": "api",
            "sources": ["katana"],
            "parameter_count": {
              "query": 1,
              "body": 0,
              "path": 0,
              "total": 1
            }
          },
          "/old-admin/config.php": {
            "path": "/old-admin/config.php",
            "methods": ["GET"],
            "parameters": {
              "query": [
                {
                  "name": "debug",
                  "category": "other"
                }
              ],
              "body": [],
              "path": []
            },
            "sample_urls": ["https://example.com/old-admin/config.php?debug=1"],
            "category": "admin",
            "sources": ["gau"],
            "parameter_count": {
              "query": 1,
              "body": 0,
              "path": 0,
              "total": 1
            }
          }
        },
        "summary": {
          "total_endpoints": 15,
          "total_parameters": 23,
          "methods": {
            "GET": 12,
            "POST": 3
          },
          "categories": {
            "api": 5,
            "authentication": 2,
            "dynamic": 4,
            "static": 3,
            "search": 1
          }
        }
      }
    },

    "forms": [
      {
        "action": "https://example.com/login",
        "method": "POST",
        "enctype": "application/x-www-form-urlencoded",
        "found_at": "https://example.com/login",
        "inputs": [
          {"name": "username", "type": "text", "value": "", "required": true},
          {"name": "password", "type": "password", "value": "", "required": true},
          {"name": "remember", "type": "checkbox", "value": "1", "required": false}
        ]
      },
      {
        "action": "https://example.com/upload",
        "method": "POST",
        "enctype": "multipart/form-data",
        "found_at": "https://example.com/dashboard",
        "inputs": [
          {"name": "file", "type": "file", "value": "", "required": true},
          {"name": "description", "type": "text", "value": "", "required": false}
        ]
      }
    ],

    "summary": {
      "total_base_urls": 3,
      "total_endpoints": 45,
      "total_parameters": 78,
      "total_forms": 5,
      "from_katana": 234,
      "from_gau": 156,
      "gau_new_endpoints": 87,
      "gau_overlap": 55,
      "methods": {
        "GET": 38,
        "POST": 7
      },
      "categories": {
        "api": 15,
        "dynamic": 12,
        "static": 8,
        "authentication": 4,
        "search": 3,
        "admin": 2,
        "file_access": 1
      }
    }
  }
}
```

### Endpoint Sources Field

Each endpoint includes a `sources` array indicating where it was discovered:

| Example | Meaning |
|---------|---------|
| `["katana"]` | Found only by Katana active crawling |
| `["hakrawler"]` | Found only by Hakrawler DOM crawling |
| `["gau"]` | Found only by GAU passive discovery |
| `["kiterunner"]` | Found only by Kiterunner API bruteforce |
| `["jsluice"]` | Found only by jsluice JavaScript analysis |
| `["katana", "hakrawler"]` | Found by both active crawlers |
| `["katana", "gau"]` | Found by both Katana and GAU |
| `["katana", "hakrawler", "gau", "kiterunner", "jsluice"]` | Found by all five tools |

**Why Array Format?**
- With 5 discovery tools, a simple string can't capture all combinations
- Arrays allow precise tracking of which tools found each endpoint
- Helps prioritize endpoints found by multiple tools (higher confidence)

---

## Endpoint Classification

The module automatically classifies endpoints into categories based on URL patterns, HTTP methods, and parameters.

### Categories

| Category | Detection Patterns | Security Relevance |
|----------|-------------------|-------------------|
| **authentication** | `/login`, `/signup`, `/auth`, `/token`, body params with `username`/`password` | Credential stuffing, brute force |
| **admin** | `/admin`, `/dashboard`, `/panel`, `/wp-admin` | Privilege escalation |
| **api** | `/api/`, `/v1/`, `/v2/`, `/rest/`, `/graphql` | API abuse, IDOR |
| **file_access** | `/download`, `/file`, `/image`, `/attachment` | LFI, path traversal |
| **upload** | `/upload`, `/import` | Malicious file upload |
| **search** | `/search`, `/find`, `/query` | SQL injection, XSS |
| **dynamic** | `.php`, `.asp`, `.jsp`, or URLs with params | Various injection attacks |
| **static** | `.html`, `.css`, `.js`, images | Low priority |
| **other** | Everything else | Manual review |

### Classification Logic

```python
def classify_endpoint(path, methods, params):
    # Priority order:
    # 1. Check path patterns (auth, admin, api, file, search)
    # 2. Check body parameters for auth indicators
    # 3. Check file extension (static vs dynamic)
    # 4. Check for query parameters (dynamic)
    # 5. Default to "other"
```

---

## Parameter Classification

Parameters are classified to identify potentially vulnerable inputs.

### Parameter Categories

| Category | Examples | Vulnerability Risk |
|----------|----------|-------------------|
| **id_params** | `id`, `user_id`, `product_id`, `cat` | IDOR, SQL injection |
| **file_params** | `file`, `path`, `template`, `include` | LFI, RFI, path traversal |
| **search_params** | `q`, `query`, `search`, `keyword` | SQL injection, XSS |
| **auth_params** | `username`, `password`, `token`, `apikey` | Credential exposure |
| **redirect_params** | `url`, `redirect`, `next`, `callback` | Open redirect, SSRF |
| **command_params** | `cmd`, `exec`, `host`, `ip` | Command injection |
| **other** | Everything else | Context-dependent |

### Type Inference

The module infers parameter data types from names and sample values:

| Type | Detection Method | Example |
|------|------------------|---------|
| `integer` | Numeric values, names like `id`, `page` | `id=123` |
| `email` | Contains `@` and `.` | `email=user@example.com` |
| `url` | Starts with `http://` or `https://` | `redirect=https://...` |
| `path` | Contains `/`, `\`, or file extensions | `file=../etc/passwd` |
| `datetime` | Names like `date`, `time`, `timestamp` | `created_at=...` |
| `boolean` | Names like `enabled`, `active`, `is_*` | `active=true` |
| `string` | Default | Everything else |

---

## Form Parsing

The module parses HTML to extract form elements and their inputs.

### Extracted Form Information

```json
{
  "action": "https://example.com/login",
  "method": "POST",
  "enctype": "application/x-www-form-urlencoded",
  "found_at": "https://example.com/",
  "inputs": [
    {
      "name": "username",
      "type": "text",
      "value": "",
      "required": true,
      "placeholder": "Enter username"
    },
    {
      "name": "password",
      "type": "password",
      "value": "",
      "required": true
    }
  ]
}
```

### Supported Input Types

| HTML Element | Extracted Info |
|-------------|----------------|
| `<form>` | action, method, enctype |
| `<input>` | name, type, value, required, placeholder |
| `<textarea>` | name, required |
| `<select>` | name, required |
| `<button type="submit">` | name, value |

### Form Data in Endpoints

Forms are merged into the endpoint structure:
- Form `action` URL becomes the endpoint path
- Form `method` is added to endpoint methods
- Form inputs become body parameters with `input_type` field

---

## Usage Examples

### Basic Usage (via main.py)

```python
# Include "resource_enum" in SCAN_MODULES in project settings
SCAN_MODULES = ["domain_discovery", "port_scan", "http_probe", "resource_enum", "vuln_scan"]

# Run the full pipeline
python3 recon/main.py
```

### Standalone Enrichment

```python
from resource_enum import run_resource_enum
from pathlib import Path
import json

# Load existing recon data
with open("output/recon_example.com.json", "r") as f:
    recon_data = json.load(f)

# Run resource enumeration
enriched = run_resource_enum(recon_data, output_file=Path("output/recon_example.com.json"))
```

### Command Line

```bash
# Enrich an existing recon file
python3 recon/resource_enum.py output/recon_example.com.json
```

### Using Results in vuln_scan

The `vuln_scan` module automatically uses resource_enum data:

```python
# vuln_scan.py - build_target_urls()

# Priority 1: Use resource_enum endpoints (most comprehensive)
resource_enum_data = recon_data.get("resource_enum")
if resource_enum_data:
    base_urls, endpoint_urls = build_target_urls_from_resource_enum(resource_enum_data)
    # Returns both base URLs and URLs with parameters for comprehensive scanning
```

---

## Integration with Graph Database

Resource enumeration data is stored in Neo4j:

### Node Types

| Node | Properties |
|------|------------|
| **Endpoint** | path, method, category, has_parameters, query_param_count, body_param_count |
| **Parameter** | name, position (query/body), type, category, sample_values |
| **Secret** | secret_type, severity, source, source_url, base_url, sample |
| **ExternalDomain** | domain, source (katana, hakrawler, jsluice, gau), url |

### Relationships

```
(BaseURL) -[:HAS_ENDPOINT]-> (Endpoint) -[:HAS_PARAMETER]-> (Parameter)
(BaseURL) -[:HAS_SECRET]-> (Secret)
(Domain) -[:HAS_EXTERNAL_DOMAIN]-> (ExternalDomain)
```

### Example Cypher Queries

```cypher
// Find all authentication endpoints
MATCH (e:Endpoint {category: 'authentication'})
RETURN e.path, e.method

// Find endpoints with file parameters (LFI risk)
MATCH (e:Endpoint)-[:HAS_PARAMETER]->(p:Parameter {category: 'file_params'})
RETURN e.path, p.name

// Find all POST forms
MATCH (e:Endpoint {method: 'POST', is_form: true})
RETURN e.path, e.form_found_at

// Find secrets discovered in JavaScript files
MATCH (b:BaseURL)-[:HAS_SECRET]->(s:Secret)
WHERE s.severity IN ['high', 'critical']
RETURN b.url, s.secret_type, s.source_url, s.sample

// Find endpoints discovered by Hakrawler but not Katana
MATCH (e:Endpoint)
WHERE 'hakrawler' IN e.sources AND NOT 'katana' IN e.sources
RETURN e.path, e.method
```

---

## Troubleshooting

### Common Issues

#### "Docker not found"

```bash
# Install Docker
sudo apt install docker.io

# Start Docker daemon
sudo systemctl start docker
```

#### "No URLs discovered"

Possible causes:
1. JavaScript-heavy site (SPAs)
2. WAF blocking crawler
3. Rate limiting

Solutions:
```python
# Increase depth
KATANA_DEPTH = 5

# Enable JS crawling
KATANA_JS_CRAWL = True

# Reduce rate limit
KATANA_RATE_LIMIT = 50

# Use Tor for anonymous crawling
USE_TOR_FOR_RECON = True
```

#### "Too many URLs (noise)"

```python
# Enable params-only mode
KATANA_PARAMS_ONLY = True

# Add exclude patterns
KATANA_EXCLUDE_PATTERNS = [
    "/static/",
    "/assets/",
    "/wp-content/",
    ".css", ".js", ".jpg", ".png"
]

# Reduce max URLs
KATANA_MAX_URLS = 500
```

#### "Crawl taking too long"

```python
# Reduce depth
KATANA_DEPTH = 2

# Reduce timeout
KATANA_TIMEOUT = 120

# Increase rate limit
KATANA_RATE_LIMIT = 200

# Disable JS crawling
KATANA_JS_CRAWL = False
```

#### "GAU returning too many URLs"

```python
# Limit URLs per domain
GAU_MAX_URLS = 500

# Use fewer providers
GAU_PROVIDERS = ["wayback"]  # Only Wayback Machine

# Filter by date range
GAU_YEAR_RANGE = ["2022", "2024"]

# Add more extensions to blacklist
GAU_BLACKLIST_EXTENSIONS.extend(["aspx", "jsp"])
```

#### "GAU URLs not being added to results"

Possible causes:
1. URL verification filtering them out
2. URLs from different domains (subdomains disabled)
3. Extension blacklist filtering

Solutions:
```python
# Disable verification to see all URLs
GAU_VERIFY_URLS = False

# Check blacklist isn't too aggressive
GAU_BLACKLIST_EXTENSIONS = ["png", "jpg", "gif", "css"]  # Minimal
```

#### "GAU timeout errors"

```python
# Increase timeout
GAU_TIMEOUT = 120

# Reduce providers
GAU_PROVIDERS = ["wayback", "commoncrawl"]  # Skip slower ones

# Reduce threads
GAU_THREADS = 2
```

#### "Kiterunner not finding endpoints"

Possible causes:
1. Target doesn't have REST APIs
2. WAF blocking bruteforce attempts
3. APIs use non-standard routes

Solutions:
```python
# Try different wordlist
KITERUNNER_WORDLIST = "aspx-251227"  # For ASP.NET

# Reduce rate to avoid WAF
KITERUNNER_RATE_LIMIT = 50

# Add authentication headers
KITERUNNER_HEADERS = ["Authorization: Bearer <token>"]
```

#### "Kiterunner timeout errors"

```python
# Increase scan timeout
KITERUNNER_SCAN_TIMEOUT = 600

# Reduce concurrent connections
KITERUNNER_CONNECTIONS = 50

# Increase per-request timeout
KITERUNNER_TIMEOUT = 15
```

#### "Kiterunner too aggressive (WAF blocks)"

```python
# Stealth mode
KITERUNNER_RATE_LIMIT = 30
KITERUNNER_CONNECTIONS = 20
KITERUNNER_THREADS = 10
```

### Debug Mode

Run Katana manually via Docker:

```bash
docker run --rm \
  projectdiscovery/katana:latest \
  -u https://example.com \
  -d 2 \
  -jc \
  -silent
```

Run GAU manually via Docker:

```bash
docker run --rm \
  sxcurity/gau:latest \
  --threads 5 \
  --timeout 60 \
  --providers wayback,commoncrawl \
  example.com
```

Run Kiterunner manually (binary auto-downloads to ~/.redamon/tools/kiterunner/):

```bash
# Binary location after first run
# Use -A flag for auto-downloaded wordlists
~/.redamon/tools/kiterunner/kr scan https://example.com \
  -A apiroutes-251227:20000 \
  -x 50 \
  -j 25 \
  -t 10s
```

---

## Security Considerations

| Risk | Mitigation |
|------|------------|
| Rate limiting/bans | Reduce `KATANA_RATE_LIMIT` and `KITERUNNER_RATE_LIMIT` |
| WAF blocking | Use custom User-Agent, reduce rate |
| API bruteforce detection | Lower `KITERUNNER_CONNECTIONS` and `KITERUNNER_THREADS` |
| Detection | Use Tor proxy |
| Legal issues | Only scan authorized targets |

### Safe Defaults

```python
# Katana (Active Crawling)
KATANA_RATE_LIMIT = 50
KATANA_DEPTH = 2
KATANA_TIMEOUT = 120
KATANA_CUSTOM_HEADERS = [
    "User-Agent: Mozilla/5.0 (compatible; SecurityScanner/1.0)"
]

# Kiterunner (API Bruteforce)
KITERUNNER_RATE_LIMIT = 50
KITERUNNER_CONNECTIONS = 30
KITERUNNER_THREADS = 20
```

---

## Dependencies

| Package | Purpose |
|---------|---------|
| Docker | Container runtime for Katana, GAU, and httpx |
| `projectdiscovery/katana:latest` | Katana Docker image (auto-pulled) |
| `sxcurity/gau:latest` | GAU Docker image (auto-pulled) |
| Kiterunner binary | Auto-downloaded from GitHub releases to `~/.redamon/tools/kiterunner/` |
| `projectdiscovery/httpx:latest` | httpx Docker image for URL verification (auto-pulled) |
| Python 3.8+ | Script runtime |
| `html.parser` | Built-in HTML form parsing |
| `urllib.parse` | Built-in URL parsing for GAU endpoint extraction |

---

## References

- [Katana Documentation](https://github.com/projectdiscovery/katana)
- [Katana Docker Hub](https://hub.docker.com/r/projectdiscovery/katana)
- [GAU (GetAllUrls) Documentation](https://github.com/lc/gau)
- [GAU Docker Hub](https://hub.docker.com/r/sxcurity/gau)
- [Kiterunner Documentation](https://github.com/assetnote/kiterunner)
- [Kiterunner Releases](https://github.com/assetnote/kiterunner/releases)
- [httpx Documentation](https://github.com/projectdiscovery/httpx)
- [Wayback Machine CDX API](https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server)
- [Common Crawl Index](https://index.commoncrawl.org/)
- [AlienVault OTX](https://otx.alienvault.com/)
- [URLScan.io](https://urlscan.io/)
- [OWASP Testing Guide - Information Gathering](https://owasp.org/www-project-web-security-testing-guide/)
- [ProjectDiscovery Blog](https://blog.projectdiscovery.io/)

---

*Documentation generated for RedAmon v1.0 - Resource Enumeration Module*
