# RedAmon - Resource Enumeration Module

## Complete Technical Documentation

> **Module:** `recon/main_recon_modules/resource_enum.py`
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
9. [OpenAPI / Swagger Import](#openapi--swagger-import)
10. [Architecture & Flow](#architecture--flow)
11. [Output Data Structure](#output-data-structure)
12. [Endpoint Classification](#endpoint-classification)
13. [Parameter Classification](#parameter-classification)
14. [Form Parsing](#form-parsing)
15. [Usage Examples](#usage-examples)
16. [Troubleshooting](#troubleshooting)

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
| **ParamSpider Parameter Mining** | Passive Wayback Machine CDX query for parameterized URLs — returns only URLs with query parameters, values replaced by placeholder (FUZZ). `paramspider -d` answers for every archived host under the domain, so only URLs on a host the run targets (`target_domains`, as for GAU) and not RoE-excluded reach the merge, `discovered_urls` (Nuclei DAST) and `archived_urls`; the rest count as `paramspider_out_of_scope`. Partial ParamSpider applies the same filter (`paramspider_urls_in_scope` in `paramspider_helpers`) before its merge |
| **Arjun Parameter Discovery** | Discovers hidden HTTP query/body parameters on discovered endpoints using ~25,000 parameter names. Multi-method parallel execution (GET/POST/JSON/XML) |
| **Parallel Execution** | Katana, Hakrawler, GAU, ParamSpider, and Kiterunner run simultaneously, then jsluice → FFuf → Arjun sequential (Arjun methods run in parallel internally) |
| **URL Verification** | Verifies GAU URLs are live before adding to results |
| **Method Detection** | OPTIONS probe detects allowed HTTP methods (GET, POST, PUT, DELETE) |
| **Dead Endpoint Filtering** | Filters out endpoints that don't respond (404, 500, timeout) |
| **JavaScript Parsing** | Discovers endpoints in JavaScript files |
| **Form Extraction** | Parses HTML forms for POST endpoints. Under an RoE rate ceiling each page fetch, and each redirect hop, waits for its slot of the ceiling |
| **Parameter Extraction** | Extracts query and body parameters |
| **Type Inference** | Infers parameter data types (integer, email, URL, etc.) |
| **Endpoint Classification** | Categorizes endpoints (auth, api, admin, file_access, etc.) |
| **Parameter Classification** | Identifies sensitive params (id, file, auth, redirect, command) |
| **Source Tracking** | Each endpoint tracked with `sources` array: `["katana", "hakrawler", "gau", "paramspider", "kiterunner", "jsluice", "arjun", "openapi"]` |
| **OpenAPI / Swagger Import** | Endpoints and parameters declared in API specification documents, merged last and never called |
| **Docker Execution** | Runs via Docker for consistency |
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
| `KATANA_DOCKER_IMAGE` | `str` | `"projectdiscovery/katana:latest"` | Fixed: the image RedAmon ships for this tool. Not a project setting. |
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

**Field scope:** Katana always runs with `-fs fqdn` (the seed's exact host); there
is no setting for it. `run_katana_crawler` keeps only URLs on `allowed_hosts`, built
from the seed URLs' hosts, so a wider field scope would only send requests to hosts
no scan admitted and then discard what they return. The retired `katanaScope`
column is kept in Prisma and read by nothing.

**Redirects:** katana follows a redirect inside its HTTP client, before `-fs`,
`-cos` or `-e` judge anything (those see only the links it queues), so a seed
answering 302 into an RoE-excluded host would get that host requested. While
the run admits its targets one by one, that is while any RoE exclusion is in
force or the project scans by IP (`target_admission.admission_context(...).active`,
read through `redirects_contained`), Katana gets `-dr` and follows no redirect,
a same-host one included, and logs `[*][Katana] Redirects not followed: RoE
exclusions or the IP target list are in force`. The same condition turns off
Hakrawler's `-subs` and limits the form fetch to same-host redirects (see
[Hakrawler scope filtering](#2-scope-filtering) and [Form Parsing](#form-parsing)).
Full and partial runs alike; with no exclusion outside IP mode, every argv and
fetch is as configured (`recon/tests/test_crawler_redirects_roe.py`).

**Arjun and FFuf redirects:** under the same condition neither fuzzer follows a
redirect, since each would follow one to any host and has no same-host mode.
Arjun 2.2.7's first request to a URL (`stable_request()`) follows redirects and
returns the URL it landed on, and every later GET and POST for that target goes
there. So `run_arjun_discovery` (`recon/helpers/resource_enum/arjun_helpers.py`)
adds `--disable-redirects` whatever `ARJUN_DISABLE_REDIRECTS` says and logs
`[*][Arjun] Redirects not followed: RoE exclusions or the IP target list are in
force`. In the full pipeline its URLs also pass `admit_urls` (module `arjun`), as
Nuclei's do, because crawler endpoints can name any host they saw; a partial
run's graph and typed URLs were admitted before, so its list is kept as given.
ffuf `-r` follows a redirect with Go's default client, so `run_ffuf_discovery`
(`recon/helpers/resource_enum/ffuf_helpers.py`) drops `-r` when
`FFUF_FOLLOW_REDIRECTS` is on and logs `[*][FFuf] Redirects not followed: RoE
exclusions or the IP target list are in force`. Both take the run (`settings`,
`recon_data`), from `resource_enum` and from partial Arjun and FFuf. The cost:
neither tests what a redirect leads to, on the same host or not. With no
exclusion outside IP mode, both argvs and Arjun's URL list are unchanged
(`recon/tests/test_roe_redirect_following.py`).

---

### 3. Filtering

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `KATANA_EXCLUDE_PATTERNS` | `list` | See below | URL patterns to exclude from the crawl's URL list and the Endpoints. Not from JS recon: see below |
| `KATANA_CUSTOM_HEADERS` | `list` | `[]` | Custom HTTP headers |

**The exclude list does not hide JS from js_recon.** The defaults hold `/static/`,
`/_next/static`, `.chunk.js`, `.bundle.js`, `/dist/`, `/build/` and `.min.js`, which
is where React, Next.js and webpack apps keep their own code, and js_recon cannot
browse: it analyzes only the JS URLs it is handed. So Katana and Hakrawler collect
every in-scope JS URL (the shared detector, `recon/helpers/js_recon/urls.py`) after
the scope check and **before** the exclude check, and return it apart from their
URL list (`meta["js_urls"]`). resource_enum returns the union as
`resource_enum["js_urls"]`, and jsluice reads it too. `discovered_urls`,
`by_base_url` and therefore the Endpoint nodes keep honouring the excludes: a JS
file is never an Endpoint.

`resource_enum["archived_urls"]` lists the URLs only a web archive reported (GAU,
URLScan, ParamSpider) and no live tool saw; js_recon leaves their JS out when
`JS_RECON_INCLUDE_ARCHIVED_JS` is off.

Archive URLs go through the quarantine first (`recon/helpers/url_leaks.py`): a URL
carrying a one-time link, a secret, a state-changing value or a web-shell trace
never reaches `discovered_urls`, and the Endpoint it would have made is written
`quarantined` (no `full_url`, no parameter values). The remaining archive values
are masked before they enter the lists DAST reads. The held GAU and ParamSpider
URLs are reported, never requested: `resource_enum["archive_leaks"]`
(`recon/helpers/archive_leaks.py`) groups their leaked one-time links and
secrets like urlscan's, written as Vulnerability / Secret `{source: 'url_archive'}`
with the value and the full links in the display-only fields
(`graph_db/display_only.py`) that the UI shows and the agent never reads. urlscan's addresses join
`by_base_url` only on bases that are live in this scan
(`recon/helpers/resource_enum/urlscan_helpers.py`), before OpenAPI, so a
Swagger address urlscan saw seeds the OpenAPI step; every source writes the same
`Endpoint.category` and `Parameter.type` words (`classification.py`).

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
| `GAU_DOCKER_IMAGE` | `str` | `"sxcurity/gau:latest"` | Fixed: the image RedAmon ships for this tool. Not a project setting. |
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
]
```

Images, fonts and media only: archived documents, exports and archives (pdf,
xlsx, zip...) are kept so the URL quarantine and URLScan's sensitive-file checks
see them. A project saved with the older default (which also dropped them) keeps
its own list.

### 4. URL Verification

GAU URLs are verified to check if they're still live before adding to results.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `GAU_VERIFY_URLS` | `bool` | `True` | Enable HTTP verification |
| `GAU_VERIFY_DOCKER_IMAGE` | `str` | `"projectdiscovery/httpx:latest"` | Fixed: the image RedAmon ships for this tool. Not a project setting. |
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
| `KITERUNNER_RATE_LIMIT` | `int` | `100` | Passed as kr's `--delay`, which kr v1.0.2 parses and never applies: it limits nothing |
| `KITERUNNER_CONNECTIONS` | `int` | `100` | Concurrent connections |
| `KITERUNNER_TIMEOUT` | `int` | `10` | Request timeout per endpoint (seconds) |
| `KITERUNNER_SCAN_TIMEOUT` | `int` | `300` | Overall scan timeout (seconds) |
| `KITERUNNER_THREADS` | `int` | `50` | Scanning threads |

**Nothing bounds kr's request rate.** `-x` (connections per host) and `-j`
(hosts at once) cap concurrency, not requests per second: even `-x 1 -j 1` sends
back to back as fast as the target answers. So under an RoE rate ceiling
(`ROE_GLOBAL_MAX_RPS`, in full and partial recon) Kiterunner does not run: it
logs `[-][Kiterunner] Not run: kr cannot hold the N rps RoE ceiling`, returns no
endpoints, and records a coverage gap entry (`resource_enum` / `kiterunner`),
never a switch-off. Kiterunner writes Endpoint assets, not findings, so the gap
keeps nothing from the prune. With no ceiling the command is unchanged.

**Redirects:** kr v1.0.2 follows up to 3 redirects by default (`--max-redirects`,
`scan` and `brute` alike), to any host. So under the same condition as Katana's
`-dr` (`redirects_contained`: RoE exclusions, or IP mode's target list),
`run_kiterunner_discovery` (`recon/helpers/resource_enum/kiterunner_helpers.py`)
passes `--max-redirects 0` and logs `[*][Kiterunner] Redirects not followed: RoE
exclusions or the IP target list are in force`, so an admitted target's 302 into
an excluded host does not get every route sent on to it. It takes the run
(`settings`, `recon_data`), from `resource_enum` and from partial Kiterunner. With
no exclusion outside IP mode the argv is unchanged
(`recon/tests/test_roe_redirect_following.py`). The method-detection probe runs
httpx without `-fr`, so it follows no redirect in any mode.

The method-detection probes (OPTIONS, then one httpx run per method) run in
containers named `kiterunner-methods-<run id>-<8 hex>`, killed by that name at
their timeout. What httpx wrote before the cut is read: the endpoints it
answered keep their detected methods, the others keep Kiterunner's, and the
cut is noted as a `kiterunner` coverage gap entry.

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
KITERUNNER_SCAN_TIMEOUT = 120
```
**Expected:** ~1-2 minutes per target

#### Balanced (Default)
```python
KITERUNNER_ENABLED = True
KITERUNNER_WORDLIST = "apiroutes-251227"
KITERUNNER_CONNECTIONS = 100
KITERUNNER_SCAN_TIMEOUT = 300
```
**Expected:** ~3-5 minutes per target

#### Comprehensive (Stealth)
```python
KITERUNNER_ENABLED = True
KITERUNNER_WORDLIST = "apiroutes-251227"
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
| `HAKRAWLER_DOCKER_IMAGE` | `str` | `"jauderho/hakrawler:latest"` | Fixed: the image RedAmon ships for this tool. Not a project setting. |
| `HAKRAWLER_DEPTH` | `int` | `2` | Crawl depth (how many links deep to follow) |
| `HAKRAWLER_THREADS` | `int` | `5` | Concurrent threads |
| `HAKRAWLER_TIMEOUT` | `int` | `30` | Per-URL timeout in seconds |
| `HAKRAWLER_MAX_URLS` | `int` | `500` | Maximum URLs to discover |
| `HAKRAWLER_INCLUDE_SUBS` | `bool` | `True` | Include subdomains in crawl scope. Forced off on an EXACT group, while RoE exclusions are in force, and in IP mode |
| `HAKRAWLER_INSECURE` | `bool` | `True` | Skip TLS certificate verification |
| `HAKRAWLER_CUSTOM_HEADERS` | `list` | `[]` | Custom HTTP headers |

### 2. Scope Filtering

Hakrawler scope filtering works at two levels:

| Level | Mechanism | Description |
|-------|-----------|-------------|
| **Crawl scope** | `-subs` flag | If `INCLUDE_SUBS=True`, Hakrawler follows links to subdomains of the target. Forced off on an EXACT (listed-hosts) group, in full and partial runs; a partial run passes one flag for every seed, so one EXACT group in it turns it off for the whole run. Also forced off while any RoE exclusion is in force and in IP mode (`redirects_contained`): `-subs` widens the only filter hakrawler applies before a request, so it would follow a link or a redirect into an excluded sibling; without it hakrawler stays on the seed's host, same-host redirects included. The log says `[*][Hakrawler] Seed hosts only (RoE exclusions or the IP target list are in force): subdomain crawling off` |
| **Output scope** | Hostname exact match | After crawling, results are filtered against `target_domains` set (from http_probe). URLs with hostnames not in scope are recorded as external domains instead of `Endpoint` nodes: an `ExternalDomain` when the host is under none of the project's scan roots; a host under a scan root becomes neither an `ExternalDomain` nor a Subdomain, it only links to a Subdomain the graph already holds, so a link never adds a name the run did not admit |

### 3. What Hakrawler Finds

| Category | Examples | Why It Matters |
|----------|----------|----------------|
| **DOM links** | `<a href="...">`, `<link>`, `<script src>` | Links that JS-rendered crawlers may miss |
| **Form actions** | `<form action="/submit">` | POST endpoints for parameter fuzzing |
| **Asset references** | CSS imports, image URLs, font files | Reveals directory structure |
| **Subdomain links** | Links pointing to `api.example.com` | Shows links between the project's hosts; a linked name is never added as a Subdomain (see Output scope) |
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
5. **Scope filter**: Extracted URLs are filtered against `allowed_hosts`; an out-of-scope host becomes an `ExternalDomain` when it is under none of the project's scan roots, and otherwise only links to a Subdomain the graph already holds (never a new one)
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

## OpenAPI / Swagger Import

OpenAPI is a resource-enumeration source, next to Kiterunner. It downloads
Swagger 2.0 and OpenAPI 3.0/3.1 documents (JSON or YAML) and turns every
operation they declare into an `Endpoint`, with its declared `Parameter`s,
through the same writer as every other source. **OpenAPI never calls a declared
operation. Later scanners request an endpoint known only from a specification
with GET or HEAD only. Nuclei templates send their own requests to such an
endpoint, as to any other target URL.**

### 1. Configuration

| Setting | Default | What it does |
|---------|---------|--------------|
| `openapiEnabled` / `OPENAPI_ENABLED` | `true` | The source on or off. It runs inside Resource Enumeration, so it also needs `resource_enum` in the scan modules. |
| `openapiSources` / `OPENAPI_SOURCES` | `[]` | Configured documents: `{id, url, serverOverride?, enabled}`. Always fetched. A token in a URL is stored and exported with the project, like the project's other secrets; it never reaches a log, the graph, a preset or MCP. |
| `openapiAutoDiscover` / `OPENAPI_AUTO_DISCOVER` | `false` | Also look for documents on the live BaseURLs, on crawled URLs whose path looks like API documentation (`openapi`, `swagger`, `api-docs`, `/docs`), and at the discovery paths on each in-scope origin. |
| `openapiDiscoveryPaths` / `OPENAPI_DISCOVERY_PATHS` | 12 common paths | At most 200 origin-relative paths (`url_path_list` validator: starts with `/`, no `//`, no whitespace, query or fragment). A bad entry is refused at the write and skipped on its own at scan time. Empty disables the common-path probes. |
| `openapiTimeout` / `OPENAPI_TIMEOUT` | `10` | Seconds per document, 1 to 60. |
| `openapiMaxDocuments` / `OPENAPI_MAX_DOCUMENTS` | `50` | Documents parsed per run, 1 to 200 (at most ten requests per document). |

Literal Swagger UI `url`, `urls` and `configUrl` references, Redoc `spec-url`
attributes and JSON literals under `swaggerDoc`/`spec` are followed; page
JavaScript is never executed. Fixed limits: 5 MiB per document, 32 MiB per run,
five redirects, 10,000 operations and 16 MiB of operation data per run.

**Run conditions.** OpenAPI follows Resource Enumeration's gates: it does not
run when active scans are skipped, when `resource_enum` is not a scan module, or
when the run has no live target URL; stealth mode turns it off in full and
partial runs. A partial **OpenAPI** run imports documents without a full recon:
it fetches the configured documents, and each custom URL typed in the partial
recon window as a specification document even with Auto-discover off (it must
sit under the project scope).

### 2. Security model

- **Scope before any request.** Every document, redirect and `$ref` must stay on
  the same origin and inside the project scope and the Rules of Engagement
  exclusions; anything else is refused before a request is sent. A declared API
  server outside the scope is never fetched and never written.
- **Address guard.** A host the operator typed (the target domain and its
  subdomain prefixes, Domain-batch hosts, configured document URLs, custom URLs,
  target IPs and CIDRs) is fetched whatever it resolves to, as everywhere in
  recon. Any other host is resolved on every hop and refused if it is a cloud
  metadata name, if any address is loopback, link-local, unspecified or
  multicast (IPv4-mapped IPv6 judged on its IPv4), or if it does not resolve:
  recon runs on the host network, and the agent API there serves `/openapi.json`.
  Private and CGNAT addresses stay allowed. A refusal sends nothing and reports
  `blocked_address`. The check and the connection resolve separately (the
  recon-wide DNS-rebinding limitation in README.SECURITY_POSTURE.md).
- **Credentials.** The Authenticated Session profile's headers go to the exact
  document origin (scheme, host, port) only; cookies are cleared per request and
  no ambient credentials are used.
- **Rate.** Every request takes a slot of the process-wide request clock on the
  engagement ceiling (`ROE_GLOBAL_MAX_RPS`, `recon/helpers/request_pacer.py`),
  which the security checks, the cache scan, the GraphQL scan, Route Exposure
  and the takeover AI probe share, as do every Domain-batch group and partial
  root; redirects and references count. The wait for a slot extends the
  document's `OPENAPI_TIMEOUT` deadline instead of counting against it: a long
  queue for the ceiling is not a slow server.
- **Capture proxy.** With traffic capture on, document requests go through the
  proxy with the signed context tag; direct requests never carry it. TLS is not
  verified, as for every recon fetcher.
- **Circuit breaker.** A host another phase found down is skipped (`host_down`),
  and the run reports what it could not re-check.
- **Ledger.** Every request is logged as
  `[*][OpenAPI] GET <url> session=<yes|no> capture=<yes|no> -> <code>` and kept
  (at most 500) under `resource_enum.openapi.requests`; neither holds a header
  value or a query string.

### 3. Graph output

Each declared operation becomes an `Endpoint` under the `BaseURL` of the API
server it names (`HAS_ENDPOINT`), keyed like every endpoint by path, method and
base URL. A path with variables is stored as a concrete example path (the
parameter's `example`, then `examples`, `default`, `enum[0]`, else `1`, or the
nil UUID for a `uuid` string); a value longer than 64 characters, with a control
character, or with `/`, `\`, `?`, `#` or a dot segment once percent-decoded
becomes `1`, so a specification cannot rewrite a request target. The template
is kept in `openapi_path_templates`. The document itself is a `GET` endpoint with
`openapi_spec`, `openapi_spec_version` and `openapi_operation_count`.

| Endpoint property | Meaning |
|-------------------|---------|
| `openapi_declared` | Declared by a specification recon imported |
| `openapi_declared_only` | Known only from a specification, not observed by any tool; requested with GET/HEAD only. Cleared by any tool that observes the endpoint. |
| `openapi_path_templates` | The templates this concrete path stands for |
| `openapi_operation_id` | operationId, kept only when it is a plain identifier (`[A-Za-z0-9_.:-]`, at most 128) |
| `openapi_deprecated` | Declared deprecated |
| `openapi_security` | Security scheme names (plain identifiers, at most 16) |
| `openapi_tags` | Tags (printable ASCII without quotes, backticks or angle brackets, at most 10) |
| `openapi_spec_urls` | The declaring documents, without query strings |

No free text from a specification (summary, description) reaches the graph or
the agent. Declared `query`, body (JSON, form, multipart top-level properties,
Swagger 2 `body`/`formData`) and `path` parameters become `Parameter` nodes;
header and cookie parameters are counted, not stored. An endpoint a crawler
already found keeps everything it had and is marked as declared, not
declared-only. A declared server on a host discovery has not found is listed in
`resource_enum.openapi.skipped_servers` (at most 200), not added. Each Domain
records `openapi_source_status`: one `<source id>|<url hash>|<code>|<time>`
string per configured document, which the project form shows as a badge while
the row's URL is the one fetched.

**Withdrawn declarations.** A full run clears every recon asset first. A partial
run withdraws what a document it fetched and parsed no longer declares: the
document's URL leaves the endpoint, and when no declaring document is left, an
endpoint known only from a specification, with no finding on it or its
parameters, is deleted; any other one stops being declared. A failed fetch
withdraws nothing. A removed configured document's endpoints are cleared at the
next full recon. A changed specification example moves a declared endpoint to a
new concrete path, so Recon Delta shows it as removed and added.

**Domain batch.** A configured document is fetched and reported by the one group
whose scope allows it; a document no group allows is reported `out_of_scope`
once, by the first group. `resource_enum.openapi.groups` holds one entry per
group, so the canonical file adds them up.

**Consumers.** The partial crawlers, JS analysis, supply chain, cache poisoning,
the GraphQL scanner and the serialized scan read declared-only endpoints only
when they are GET or HEAD; partial Arjun, which sends its own methods, reads
none when any method but GET is configured; AI Surface never probes a host
because of a declared-only endpoint, and on a host it probes for its own AI
signal its chat-shape probe skips them; nuclei gets a declared-only path only when it declares GET or HEAD, and at
most 500 of them per run (the overflow is logged and recorded as
`declared_not_sent_to_nuclei`). A node written by an earlier release with
`openapi_declared` and no `openapi_declared_only` counts as declared-only.

**Counts.** Red Zone, the report, Insights and the MCP
`get_attack_surface_overview` count declared-only endpoints and their parameters
apart from observed ones, so a specification never inflates the surface, the
risk gauge or the posture score; the overview reports them as
`declaredEndpoints` and `declaredParameters`.

### 4. Verification

```bash
./redamon.sh test unit   # includes the OpenAPI recon, merge, guard, consumer and writer tests
# real-Neo4j writer and withdrawal checks (disposable database, see the file's docstring):
#   tests/test_resource_enum_openapi_graph_integration.py
#   recon/tests/test_declared_only_predicate_integration.py
```

---

## Architecture & Flow

> **Pipeline context:** Resource enumeration runs in **GROUP 5** of the parallelized recon pipeline, after HTTP probing (GROUP 4). The four discovery tools (Katana, Hakrawler, GAU, Kiterunner) run concurrently via an internal `ThreadPoolExecutor`. jsluice then runs sequentially on discovered JS files. Graph DB updates happen in a background thread.

### Execution Flow

```
1. INITIALIZATION
   └── Check Docker availability
   └── Pull Katana + GAU + Kiterunner images in parallel

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
   └── OpenAPI last: fetch and parse specification documents, merge their
       declared operations (no tool in this module requests one)

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

    "js_urls": [
      "https://example.com/_next/static/chunks/pages/_app-91c.js",
      "https://example.com/static/js/main.4f3a.js"
    ],

    "archived_urls": [
      "https://example.com/old-admin/config.php"
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

`fetch_forms_from_urls` requests up to 100 of the URLs Katana and Hakrawler
reported (3xx ones included) with urllib. While any RoE exclusion is in force or
the project scans by IP (`redirects_contained`), it follows a redirect only to
the host the request went to; a refused hop ends that fetch, which is skipped
like any other failed one. Otherwise it follows redirects as urllib does.

The fetch is sequential, and under an RoE rate ceiling (`ROE_GLOBAL_MAX_RPS`)
every request the opener sends takes a slot of recon's request clock
(`request_pacer`) first, each redirect hop included, since urllib sends a hop
through the opener again; a refused hop is never sent and takes none. A `429`
pushes the next slot of every in-process requester back by its `Retry-After`.
With no ceiling the pacer is inert and the requests are unchanged.

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
from recon.main_recon_modules.resource_enum import run_resource_enum
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
python3 recon/main_recon_modules/resource_enum.py output/recon_example.com.json
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
| **Endpoint** | path, method, category, has_parameters, query_param_count, body_param_count, path_param_count |
| **Parameter** | name, position (query/body), type, category, sample_values |
| **Secret** | secret_type, severity, source, source_url, base_url, sample |
| **ExternalDomain** | domain, source (katana, hakrawler, jsluice, gau), url |

Every crawler and most partial tools write through `update_graph_from_resource_enum`
(`graph_db/mixins/recon/resource_mixin.py`), so a later tool must not undo what an
earlier one observed. A fact the caller did not observe keeps the stored value:
`has_parameters` only goes from false to true; each `*_param_count` keeps the stored
count when the caller counted none there (a partial FFuf or Kiterunner run counts
none), and a count it measured replaces it; a body Parameter's `input_type` and
`required`, and a path Parameter's `required`, keep the stored value when the caller
states none (the defaults apply only when nothing is stored). `Parameter.source` is the first
writer's, like `Endpoint.source`.

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

# Fewer concurrent requests to avoid WAF blocks (kr applies no rate limit)
KITERUNNER_CONNECTIONS = 20

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

Fewer connections and threads lower the concurrency; `KITERUNNER_RATE_LIMIT`
does not slow kr down. When the engagement sets a request rate, set the RoE
ceiling: Kiterunner then does not run.

```python
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
| Rate limiting/bans | Reduce `KATANA_RATE_LIMIT`; Kiterunner has no working rate limit, so lower its concurrency or set the RoE ceiling, under which it does not run |
| WAF blocking | Use custom User-Agent, reduce rate |
| API bruteforce detection | Lower `KITERUNNER_CONNECTIONS` and `KITERUNNER_THREADS` |
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

# Kiterunner (API Bruteforce): concurrency only, kr applies no rate limit
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

## Related modules

- **Downstream — [AI Surface Recon (Phase 4.5)](AI_SURFACE_RECON_MODULE.md):** consumes the
  endpoints classified here (`ai_interface_type` = `llm-chat`/`mcp`/…) and
  actively confirms the AI/LLM/MCP/vector-DB surfaces with benign protocol probes.

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
