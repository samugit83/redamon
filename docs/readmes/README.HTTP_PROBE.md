# RedAmon - httpx HTTP Prober + Banner Grabbing

## Complete Technical Documentation

> **Module:** `recon/main_recon_modules/http_probe.py`  
> **Purpose:** HTTP probing, technology detection, and non-HTTP service detection  
> **Author:** RedAmon Security Suite

---

## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Requirements](#requirements)
4. [Configuration Parameters](#configuration-parameters)
5. [Banner Grabbing](#banner-grabbing)
6. [Architecture & Flow](#architecture--flow)
7. [Output Data Structure](#output-data-structure)
8. [Usage Examples](#usage-examples)
9. [Troubleshooting](#troubleshooting)

---

## Overview

The `http_probe.py` module integrates ProjectDiscovery's httpx toolkit into RedAmon's reconnaissance pipeline. httpx is a multi-purpose HTTP toolkit designed for probing, technology detection, and web service analysis.

**This module also includes integrated banner grabbing** for non-HTTP services (SSH, FTP, SMTP, MySQL, etc.) and a Wappalyzer pass over the captured pages, to provide complete service detection across all open ports.

**⚠️ Important:** httpx runs exclusively via Docker, as a sibling container the recon container starts with `docker run`. No native installation is supported.

### Why httpx + Banner Grabbing?

| Feature | Traditional Tools | httpx + Banner Grab |
|---------|------------------|---------------------|
| HTTP Technology Detection | Limited | **Wappalyzer-based** |
| Non-HTTP Service Detection | None | **SSH, FTP, SMTP, etc.** |
| TLS Analysis | Basic | **Comprehensive** |
| Speed | Slow | **Highly concurrent** |
| Output Format | Variable | **Rich JSON** |
| Fingerprinting | None | **Favicon, JARM, hash** |

### How It Works

```
┌──────────────────┐     ┌─────────────────────────┐     ┌──────────────────┐
│  port_scan       │────▶│  http_probe.py          │────▶│  http_probe key  │
│  (Naabu+Masscan  │     │                         │     │  live URLs,      │
│   open ports)    │     │  1. Build URLs          │     │  technologies,   │
└──────────────────┘     │  2. httpx probe         │     │  TLS info,       │
        │                │  3. Parse + scope filter│     │  redirects       │
        │                │  4. AI surface signals  │     └──────────────────┘
        │                │  5. Wappalyzer          │     ┌──────────────────┐
        ▼                │  6. Banner grab         │────▶│  banner_grab key │
┌──────────────────┐     └─────────────────────────┘     └──────────────────┘
│  DNS Data        │  (Fallback if the port scan found no open port)
│  (hostnames)     │
└──────────────────┘
```

---

## Features

| Feature | Description |
|---------|-------------|
| **HTTP Probing** | Identifies live HTTP/HTTPS endpoints |
| **Technology Detection** | httpx `-td` plus a Wappalyzer pass over the captured HTML |
| **TLS Analysis** | Certificate info, cipher suites, JARM |
| **CDN Detection** | Identifies CDN providers |
| **ASN Lookup** | Autonomous System Number detection |
| **Response Analysis** | Status codes, headers, body hashing |
| **Redirect Chain** | First status, every hop's status and the final URL per probed URL |
| **Scope Filter** | Drops results outside the target scope; an off-scope redirect becomes an external domain |
| **AI Surface Signals** | Flags AI frameworks and frontends from headers, favicon, title and body |
| **Favicon Hashing** | Fingerprint via favicon hash |
| **Banner Grabbing** | Service detection for non-HTTP ports (SSH, FTP, SMTP, etc.) |
| **Runtime Budget** | A probe that outlives its computed budget is stopped and keeps what it found |
| **Docker Execution** | No local installation required |

---

## Requirements

Nothing to install by hand: the recon container reaches the host's Docker daemon
and, on first use, `pull_httpx_docker_image()` pulls the httpx image.
`run_http_probe()` checks `docker` is on the path and `docker info` answers,
and skips the probe otherwise. `python-Wappalyzer` is installed in the recon
image (`recon/requirements.txt`).

To pre-pull the image:

```bash
docker pull projectdiscovery/httpx:latest
```

---

## Configuration Parameters

All parameters are set in the webapp project settings (stored in PostgreSQL) and reach the module as the runtime keys below; `recon/project_settings.py` holds the fallback defaults. Each field's meaning and bounds are in the settings registry (`recon_settings/registry.yaml`). This section provides **detailed explanations** including performance impact for each option.

At scan start the engagement ceiling caps `HTTPX_RATE_LIMIT`, the memory governor can lower `HTTPX_THREADS` and `BANNER_GRAB_THREADS`, and stealth mode sets `HTTPX_RATE_LIMIT = 2` and `HTTPX_THREADS = 1` and turns off `HTTPX_PROBE_FAVICON`, `HTTPX_PROBE_JARM` and `BANNER_GRAB_ENABLED`.

**Under an RoE rate ceiling C** (`ROE_GLOBAL_MAX_RPS`) the cap alone does not hold httpx: its limiter counts only each URL's main request, in fixed one-second windows. So `httpx_ceiling_pacing()` builds the command with `-t 1`, `-retries 0`, `-rl max(1, floor(C/2))` (never above `HTTPX_RATE_LIMIT`) and `-delay ceil(2000/C)ms`, without `-favicon` and `-jarm`, and `httpx_budget()` adds the delay to the run's time budget. The run logs `[*][httpx] Paced to the 2 rps RoE ceiling: one URL at a time, -rl 1, -delay 1000ms, no retries` (plus `; its redirect hops take no token of httpx's limiter and can exceed it` with `HTTPX_FOLLOW_REDIRECTS` on) and `[-][httpx] JARM and favicon not collected while the 2 rps RoE ceiling is in force: httpx's limiter does not count their requests`, and records coverage gaps `httpx_jarm` and `httpx_favicon` (module `http_probe`) for the probes the project had on. The graph writers skip absent values, so a hash an earlier run stored is kept. The banner grab connects in-process, so each of its connections takes a slot of recon's request clock (`request_pacer`). With no ceiling the command is unchanged and the banner grab never touches the clock.

---

### 1. Core Configuration

| Parameter | Type | Default | httpx Flag | Description |
|-----------|------|---------|------------|-------------|
| `HTTPX_ENABLED` | `bool` | `True` | - | Run the probe. The phase runs only when `http_probe` is in the project's scan modules. |
| `HTTPX_DOCKER_IMAGE` | `str` | `"projectdiscovery/httpx:latest"` | - | Fixed: the image RedAmon ships for this tool. Not a project setting. |
| `HTTPX_THREADS` | `int` | `50` | `-t` | Number of concurrent HTTP requests. Higher = faster but uses more CPU/memory. |
| `HTTPX_TIMEOUT` | `int` | `10` | `-timeout` | Seconds to wait for each HTTP response before giving up. |
| `HTTPX_RETRIES` | `int` | `2` | `-retries` | Number of retry attempts for failed/timeout requests. |
| `HTTPX_RATE_LIMIT` | `int` | `50` | `-rl` | Maximum requests per second, held in fixed one-second windows (a window's requests can all leave at its start) and counting only each URL's main request: retries, redirect hops, the favicon fetch and JARM's handshakes take no token. Lower = more stealthy. |

**Thread Tuning Guide:**

| Threads | Use Case |
|---------|----------|
| 10-25 | Stealth scanning, limited bandwidth |
| 50 | **Default** - balanced performance |
| 100-200 | Fast scanning, good hardware |

**Timeout Considerations:**
- `5s` - Fast networks, modern servers
- `10s` - **Default** - handles most scenarios
- `15-30s` - Slow servers, high latency networks

**Run budget.** The whole probe is stopped after `httpx_budget()` seconds:
`ceil(URLs / HTTPX_THREADS) * HTTPX_TIMEOUT * (HTTPX_RETRIES + 1) + 60`. A
stopped probe keeps the results it already wrote, records
`scan_metadata.stopped_at_budget: true`, and leaves http_probe out of the
finding prune for that run.

---

### 2. Redirect Handling

| Parameter | Type | Default | httpx Flag | Description |
|-----------|------|---------|------------|-------------|
| `HTTPX_FOLLOW_REDIRECTS` | `bool` | `True` | `-fr` | Follow HTTP 301/302/307/308 redirects. Essential for modern web apps. With session headers attached, `-fhr` (same host only) is used instead, so the session never follows a redirect to another host. An IP-mode run always uses `-fhr`, so a redirect never takes httpx off the target IPs. A run with RoE exclusions in force uses it too (`[*][httpx] Redirects followed on the same host only: RoE exclusions are in force`): an admitted host's redirect into an excluded one is not followed, and the URL keeps its own answer (its 3xx, `final_url` the URL itself), not the excluded host's page. |
| `HTTPX_MAX_REDIRECTS` | `int` | `10` | `-maxr` | Maximum redirect chain length. Prevents infinite redirect loops. |

**Why Follow Redirects?**
- Many sites redirect `http://` → `https://`
- www → non-www redirects are common
- Login pages often redirect after authentication
- Without following, you might miss the actual content

**What is stored for a redirect.** httpx reports the URL it was *asked* for
(`url`) and the last hop (`final_url`), but the status, title, technologies,
server, favicon and body hash it prints describe the **last** page. So
`status_code` on the Endpoint is the last hop's, and each probed URL also keeps:

| Field (on the probed Endpoint) | Meaning |
|---|---|
| `first_status_code` | The first answer, before any redirect: `chain_status_codes[0]`, or `status_code` when nothing redirected. Rank on this, not on `status_code`: a host that answers `302` to a login page is not a `200` page. |
| `redirect_chain_codes` | The status of each hop, first to last (`[302, 200]`); one entry when nothing redirected. |
| `final_url` | Where the answer came from; equals `url` when nothing redirected. |
| `redirected_off_host` | The last hop is on another host. |

**An in-scope host that redirects off scope.** The scope filter checks the
requested host *and* the last hop's host. When `old.example.com` (in scope)
redirects to a third-party IdP (not in scope), the entry is kept (the host is
live and redirects away) but none of the foreign page's fingerprint is: no
title, technologies, server, favicon, body hash, content type, word/line
counts, headers, body or TLS certificate (Go reports the final connection's).
JARM, the IP, CNAME, ASN and CDN are measured on the requested host and stay.
The foreign host becomes an external-domain entry (`source:
"http_probe_redirect"`, `redirect_from_url` = the in-scope URL), which
`run_http_probe` returns as `http_probe.external_domains` and the pipeline writes
as an `ExternalDomain`. When neither host is in scope the entry is dropped and
counted in `summary.filtered_out_of_scope`. `HTTPX_FOLLOW_REDIRECTS` stays on by
default: with the chain stored, nothing needs the pre-redirect page itself.

**What "in scope" means** (`is_host_in_scope()`): a subdomain of a scan root
(the root itself only when it is a target); for an EXACT scope group or a
filtered run, exactly the listed hosts. An IP literal is in scope only as one
of the run's own addresses (`_run_addresses`): one it resolved, port-scanned or
asked httpx to probe, less those the RoE excludes, compared in canonical form
so any IPv6 spelling matches. An in-scope host that redirects to someone
else's address (`http://203.0.113.50/sso`) is therefore an off-scope redirect,
and that page's title, technologies and certificate are not credited to the
target.

**IPv6 literals.** `url_port` and `extract_host_from_url` parse with
`urllib.parse`: `https://[2001:db8::10]:8443` keeps port 8443 and its host
comes back bare (`2001:db8::10`, the form the graph keys an IP by), and
userinfo (`user@host`) is never read as the host. A port that is not a number
reads as `-1`.

---

### 3. HTTP Response Probing (Fast Options)

These options extract basic HTTP response information with **minimal performance impact**:

| Parameter | Type | Default | httpx Flag | What It Extracts | Speed Impact |
|-----------|------|---------|------------|------------------|--------------|
| `HTTPX_PROBE_STATUS_CODE` | `bool` | `True` | `-sc` | HTTP status code (200, 301, 404, 500, etc.) | ✅ **None** |
| `HTTPX_PROBE_CONTENT_LENGTH` | `bool` | `True` | `-cl` | Response body size in bytes | ✅ **None** |
| `HTTPX_PROBE_CONTENT_TYPE` | `bool` | `True` | `-ct` | MIME type (`text/html`, `application/json`, etc.) | ✅ **None** |
| `HTTPX_PROBE_TITLE` | `bool` | `True` | `-title` | HTML `<title>` tag content | ✅ **Minimal** |
| `HTTPX_PROBE_SERVER` | `bool` | `True` | `-server` | Server header value (nginx, Apache, IIS, etc.) | ✅ **None** |
| `HTTPX_PROBE_RESPONSE_TIME` | `bool` | `True` | `-rt` | Response time | ✅ **None** |
| `HTTPX_PROBE_WORD_COUNT` | `bool` | `True` | `-wc` | Number of words in response body | ✅ **Minimal** |
| `HTTPX_PROBE_LINE_COUNT` | `bool` | `True` | `-lc` | Number of lines in response body | ✅ **Minimal** |

**Example Output:**
```json
{
  "status_code": 200,
  "content_length": 15234,
  "content_type": "text/html; charset=UTF-8",
  "title": "Example Domain",
  "server": "nginx/1.19.0",
  "response_time_ms": 145,
  "word_count": 892,
  "line_count": 156
}
```

---

### 4. Technology Detection

| Parameter | Type | Default | httpx Flag | Description | Speed Impact |
|-----------|------|---------|------------|-------------|--------------|
| `HTTPX_PROBE_TECH_DETECT` | `bool` | `True` | `-td` | Detects technologies using Wappalyzer-like fingerprinting | ⚡ **Medium** |

**How It Works:**
- Analyzes response headers, body content, and JavaScript
- Matches against signature database
- Identifies frameworks, CMS, libraries

**Detected Technologies Include:**

| Category | Examples |
|----------|----------|
| **Web Servers** | nginx, Apache, IIS, LiteSpeed, Caddy |
| **Languages** | PHP, Python, Java, Node.js, Ruby, Go |
| **Frameworks** | Laravel, Django, Spring, Express, Rails |
| **CMS** | WordPress, Drupal, Joomla, Magento |
| **Frontend** | React, Angular, Vue.js, jQuery |
| **CDN/WAF** | Cloudflare, Akamai, AWS CloudFront, Sucuri |
| **Analytics** | Google Analytics, Matomo, Hotjar |
| **Caching** | Varnish, Redis, Memcached |

---

### 5. Network Information

| Parameter | Type | Default | httpx Flag | What It Does | Speed Impact |
|-----------|------|---------|------------|--------------|--------------|
| `HTTPX_PROBE_IP` | `bool` | `True` | `-ip` | Resolves and returns the target's IP address | ✅ **Minimal** (DNS lookup) |
| `HTTPX_PROBE_CNAME` | `bool` | `True` | `-cname` | Extracts CNAME DNS records - reveals CDN/hosting | ✅ **Minimal** (DNS lookup) |
| `HTTPX_PROBE_ASN` | `bool` | `True` | `-asn` | Autonomous System Number - identifies network provider | ⚡ **Medium** (external lookup) |
| `HTTPX_PROBE_CDN` | `bool` | `True` | `-cdn` | Detects CDN provider (Cloudflare, Akamai, etc.) | ✅ **Minimal** |

**ASN Information Reveals:**
- Hosting provider (AWS, Google Cloud, Azure, DigitalOcean)
- ISP information
- Geographic region hints
- Useful for identifying shared hosting

---

### 6. SSL/TLS Information

| Parameter | Type | Default | httpx Flag | What It Does | Speed Impact |
|-----------|------|---------|------------|--------------|--------------|
| `HTTPX_PROBE_TLS_INFO` | `bool` | `True` | `-tls-probe` | Also probes the names the TLS certificate of each probed host lists (its SANs), each as one more target. Not passed in IP mode or while RoE exclusions are in force, where it would request the names the certificate lists, an excluded one included (`[-][httpx] TLS probing: off in IP mode` / `off while RoE exclusions are in force`); `-tls-grab` (its own setting) still reads the certificate, and in a domain run its names still join as late names, each admitted on its own | ⚡ **Medium** |
| `HTTPX_PROBE_TLS_GRAB` | `bool` | `True` | `-tls-grab` | Full certificate extraction | ⚠️ **SLOW** |

**TLS_INFO probes** the hostnames the certificate lists, so a probe can reach a
host nobody handed httpx; that is why it is off in IP mode and under RoE
exclusions. The TLS fields stored on a URL come from TLS_GRAB.

**TLS_GRAB extracts:**
- TLS version (TLS 1.0, 1.1, 1.2, 1.3) and the cipher suite in use
- Certificate subject (CN, DN, organisation) and issuer (DN, CN, organisation)
- Validity period (not_before, not_after)
- Subject Alternative Names (all domains on cert)
- Serial number and SHA-256 fingerprint
- The verdicts httpx's tlsx library reports: expired, self-signed, hostname mismatch, wildcard

**Example TLS Output** (`by_url[...].tls`):
```json
{
  "tls": {
    "version": "tls13",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "certificate": {
      "subject_cn": "*.example.com",
      "subject_dn": "CN=*.example.com",
      "subject_org": null,
      "issuer": "CN=R3, O=Let's Encrypt, C=US",
      "issuer_dn": "CN=R3, O=Let's Encrypt, C=US",
      "issuer_cn": "R3",
      "issuer_org": ["Let's Encrypt"],
      "serial": "03:1A:...",
      "not_before": "2024-01-01T00:00:00Z",
      "not_after": "2024-04-01T00:00:00Z",
      "san": ["example.com", "*.example.com", "www.example.com"],
      "fingerprint_sha256": "9f86d081884c7d65...",
      "expired": false,
      "self_signed": false,
      "mismatched": false,
      "wildcard": true
    }
  }
}
```

The certificate fields feed the TLS-hygiene security checks (see [README.VULN_SCAN.md](README.VULN_SCAN.md)), and the SANs are offered back to the pipeline as new hostnames after GROUP 4 (`collect_certificate_sans`, when `TLSX_INJECT_HOSTNAMES` is on).

⚠️ **Performance Note:** `TLS_GRAB` requires a full TLS handshake and certificate parsing. Disable for faster scans.

---

### 7. Fingerprinting (Advanced)

| Parameter | Type | Default | httpx Flag | What It Does | Speed Impact |
|-----------|------|---------|------------|--------------|--------------|
| `HTTPX_PROBE_FAVICON` | `bool` | `True` | `-favicon` | Calculates MMH3 hash of favicon.ico. Not sent under an RoE ceiling (coverage gap `httpx_favicon`; a stored hash is kept) | ⚡ **Medium** (extra HTTP request) |
| `HTTPX_PROBE_JARM` | `bool` | `True` | `-jarm` | JARM TLS fingerprint. Not sent under an RoE ceiling (coverage gap `httpx_jarm`; a stored hash is kept) | ⚠️ **VERY SLOW** |
| `HTTPX_PROBE_HASH` | `str` | `"sha256"` | `-hash` | Hash of response body | ⚡ **Medium** |

#### Favicon Hashing

**What It Is:**
- Downloads `/favicon.ico` and calculates MMH3 hash
- Same favicon = same application/framework

**Use Cases:**
- Identify Cobalt Strike C2 servers (known hashes)
- Find admin panels (phpMyAdmin, cPanel)
- Detect specific applications (RedAmon matches AI frontends by favicon, see [AI surface signals](#10-ai-surface-signals))
- Cross-reference with Shodan favicon database

**Example:**
```json
{
  "favicon_hash": "-1396576824"
}
```

#### JARM Fingerprinting

**What It Is:**
- An active TLS server fingerprint (Salesforce's JARM)
- Creates unique fingerprint based on TLS server configuration
- Requires **10 separate TLS handshakes** per target

**Why It's Slow:**
```
Each JARM fingerprint requires:
- 10 different TLS ClientHello messages
- 10 separate connections
- Parsing 10 ServerHello responses
```

**Use Cases:**
- Identify C2 (Command & Control) servers
- Detect malware infrastructure
- Fingerprint load balancers
- Track threat actors

⚠️ **Recommendation:** Disable JARM (`HTTPX_PROBE_JARM = False`) for regular scans. Enable only for targeted threat hunting.

#### Body Hash

**Options:** `"md5"`, `"sha256"`, `"sha512"`, `""` (disabled). Stored as `body_hash`.

**Use Cases:**
- Detect identical pages across different URLs
- Find mirror sites
- Identify default/template pages

**Shared pages (`shared_body_cluster`).** After every http_probe graph write,
full or partial, the http mixin groups the project's root Endpoints (path `/`) by
`body_sha256`. When 3 or more distinct BaseURLs serve the same body with status
200 or 403, each of those Endpoints gets `shared_body_cluster` = that count: one
gateway deny, parking or default page, not each host's own content. The mark is
recomputed over the whole project each time and removed from an Endpoint whose
host no longer serves the shared page.

---

### 8. Response Content Inclusion

| Parameter | Type | Default | httpx Flag | What It Does | Speed Impact |
|-----------|------|---------|------------|--------------|--------------|
| `HTTPX_INCLUDE_RESPONSE` | `bool` | `True` | `-irr` | Include full HTTP response (headers + body) | ⚠️ **SLOW** |
| `HTTPX_INCLUDE_RESPONSE_HEADERS` | `bool` | `True` | `-irh` | Include only response headers | ⚡ **Medium** |

**The body is used, then dropped.** `run_http_probe()` hands the captured bodies
to the Wappalyzer pass, the AI body fingerprints, HTTP traffic capture (when
`CAPTURE_PROXY_ENABLED` is on) and the Jev page-type labels, then removes `body`
from every `by_url` entry before storing the result. Headers stay.

**When to Enable Full Response:**
- ✅ Wappalyzer and AI body fingerprints need it
- ✅ Traffic capture stores the transactions
- ❌ Speed is priority

---

### 9. Advanced Options

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `HTTPX_PATHS` | `list` | `[]` | Additional paths to probe beyond root (`-path`, joined with commas) |
| `HTTPX_CUSTOM_HEADERS` | `list` | browser-like headers | HTTP headers to send (`-H` each); the default is a desktop Chrome `User-Agent` with the `Accept*`, `Sec-Fetch-*` and related headers a browser sends |
| `HTTPX_MATCH_CODES` | `list` | `[]` | Only keep responses with these status codes (`-mc`) |
| `HTTPX_FILTER_CODES` | `list` | `[]` | Exclude responses with these status codes (`-fc`) |

#### Path Probing

```python
# Probe common sensitive paths
HTTPX_PATHS = [
    "/robots.txt",           # Discover hidden paths
    "/.well-known/security.txt",  # Security contact info
    "/sitemap.xml",          # Site structure
    "/.git/config",          # Git exposure
    "/wp-admin/",            # WordPress admin
    "/phpmyadmin/",          # Database admin
]
```

⚠️ Each path multiplies your scan time!

#### Custom Headers

```python
HTTPX_CUSTOM_HEADERS = [
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
    "Accept-Language: en-US,en;q=0.9",
    "X-Forwarded-For: 127.0.0.1",  # Bypass some WAFs
]
```

**Authenticated sessions.** When the project has an authenticated-session
profile, its headers are added to these (`merge_auth_headers_ex`), checked
against the hosts this run actually probes: httpx sends one header set to the
whole target file, so a probe with any out-of-scope host gets no session.

#### Status Code Filtering

```python
# Only successful responses
HTTPX_MATCH_CODES = ["200", "301", "302"]

# Exclude noise
HTTPX_FILTER_CODES = ["404", "403", "500", "502", "503"]
```

---

### 10. AI Surface Signals

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `HTTP_PROBE_AI_HEADER_SCAN_ENABLED` | `bool` | `True` | Match response header names against the AI header catalogue (vLLM, TGI, LangChain, ...) |
| `HTTP_PROBE_AI_FAVICON_HASH_ENABLED` | `bool` | `True` | Match the favicon hash against known AI frontends |
| `HTTP_PROBE_AI_TITLE_DETECTION_ENABLED` | `bool` | `True` | Match the page title against AI frontends |
| `HTTP_PROBE_AI_WAPPALYZER_ENABLED` | `bool` | `True` | Match the response body (up to 512 KB) against AI body fingerprints |
| `HTTPX_JEV_PAGE_TYPE` | `bool` | `False` | With `AI_IN_PIPELINE` on, label each page (login wall, parked domain, default install, placeholder, error page, app) with native Jev 1.13 through the project's selected TypeSafe or OpenRouter Jev configuration |

The catalogues live in `recon/helpers/ai_signal_catalog.py`. A match sets
`is_ai_framework_detected`, `ai_framework_name`, `ai_framework_category` and,
for a frontend, `ai_frontend_product_guess` on the `by_url` entry; the summary
counts the matches (`ai_header_matches`, `ai_favicon_matches`,
`ai_title_matches`, `ai_wappalyzer_matches`). The page-type pass writes
`page_class`, `page_class_confidence` and `page_class_source`.

---

### Speed Profiles

#### 🏎️ Fast Mode (Reconnaissance)
```python
# Minimal features, maximum speed
HTTPX_THREADS = 100
HTTPX_TIMEOUT = 5
HTTPX_RETRIES = 0
HTTPX_RATE_LIMIT = 300

HTTPX_PROBE_JARM = False           # DISABLE - very slow
HTTPX_PROBE_TLS_GRAB = False       # DISABLE - slow
HTTPX_PROBE_FAVICON = False        # DISABLE - extra request
HTTPX_PROBE_HASH = ""              # DISABLE
HTTPX_INCLUDE_RESPONSE = False     # DISABLE - no Wappalyzer or AI body pass
```

#### ⚖️ Balanced Mode
```python
# Good balance of speed and information
HTTPX_THREADS = 50
HTTPX_TIMEOUT = 10
HTTPX_RETRIES = 1
HTTPX_RATE_LIMIT = 150

HTTPX_PROBE_JARM = False           # DISABLE for balance
HTTPX_PROBE_TLS_GRAB = True
HTTPX_PROBE_FAVICON = True
HTTPX_INCLUDE_RESPONSE = True
```

#### 🔬 Deep Analysis Mode
```python
# Maximum information gathering
HTTPX_THREADS = 25
HTTPX_TIMEOUT = 15
HTTPX_RETRIES = 2
HTTPX_RATE_LIMIT = 50

HTTPX_PROBE_JARM = True            # Enable for threat hunting
HTTPX_PROBE_TLS_GRAB = True
HTTPX_PROBE_FAVICON = True
HTTPX_PROBE_HASH = "sha256"
HTTPX_INCLUDE_RESPONSE = True      # Full response capture
```

The defaults match the deep profile, except for 50 threads and a 10-second timeout.

---

## Banner Grabbing

Banner grabbing is **integrated into http_probe.py** (`run_banner_grab()`) and runs after HTTP probing, when `BANNER_GRAB_ENABLED` is on and port-scan data exists. It detects service versions on non-HTTP ports that httpx cannot probe.

### Configuration

```python
# Banner Grabbing Configuration (project settings, runtime keys)

# Enable/disable banner grabbing for non-HTTP ports
BANNER_GRAB_ENABLED = True

# Connection timeout per port (seconds)
BANNER_GRAB_TIMEOUT = 5

# Number of concurrent threads
BANNER_GRAB_THREADS = 20

# Maximum banner length to store (characters)
BANNER_GRAB_MAX_LENGTH = 1000
```

### How It Works

For every open port in `port_scan.by_host` that is not in
`BANNER_GRAB_SKIP_PORTS` (every port in `HTTP_PORTS` and `HTTPS_PORTS`, plus
9090 and 8800, which httpx already probes), `grab_banner_for_target()` connects
to the address the port detail names, else the host's IP
(`socket.create_connection`, so an IPv6 address is reached too): a domain
run's name on two addresses is reached on each port at the address it was
found on, and each detail takes only its own address's banner. It reads what
the service sends first, sends the port's probe if nothing came, and retries
over TLS on 993, 995, 465, 636 and 990. Targets the RoE
excludes are never connected to (see
[RoE admission of the target list](#roe-admission-of-the-target-list)).
`identify_service()` matches the banner against `SERVICE_PATTERNS`.

FTP and SMTP both greet with `220`, so their patterns are anchored at the start
of the banner and the product decides (`vsFTPd`, `ProFTPD`, ... vs `Postfix`,
`Exim 4.94.2`, `Sendmail`, `Microsoft ESMTP`, any `ESMTP`). A bare `220` that
names no product is decided by the port: 25, 465, 587 and 2525 are SMTP, 21 and
990 FTP, and any other port is FTP only when the banner says FTP, else
`unknown`. Do not define `HTTP_PORTS` a second time for the skip set: a second
definition once shadowed the first, and 443, 8443, 9090 and 8800 were
banner-grabbed.

### Supported Services

| Service | Port(s) | Detection Method |
|---------|---------|------------------|
| SSH | 22 | Banner: `SSH-2.0-OpenSSH_8.2p1` |
| FTP | 21 | Banner: `220 vsFTPd 3.0.3` |
| SMTP | 25, 465, 587, 2525 | `EHLO` response: `220 mail.example.com ESMTP Postfix` |
| POP3 | 110, 995 | Banner: `+OK Dovecot ready` |
| IMAP | 143, 993 | Banner: `* OK Dovecot IMAP` |
| MySQL / MariaDB | 3306 | Connection handshake |
| PostgreSQL | 5432 | Cancel request response |
| Redis | 6379 | `INFO` command response |
| MongoDB | 27017 | Banner or error text |
| VNC | 5900 | RFB protocol banner |
| Memcached | 11211 | `version` command |
| Telnet | 23 | Login prompt |

### Skipped Ports (Handled by httpx)

Ports in `BANNER_GRAB_SKIP_PORTS` (`http_probe.py`) are skipped, because httpx
already probes them:

```
80, 8080, 8000, 8888, 8008, 3000, 5000, 9000   HTTP_PORTS
443, 8443, 4443, 9443, 8843                    HTTPS_PORTS
9090, 8800
```

### Output Structure

```json
{
  "banner_grab": {
    "scan_metadata": {
      "scan_timestamp": "2024-01-15T10:30:00",
      "scan_duration_seconds": 5.2,
      "total_ports_scanned": 3,
      "banners_retrieved": 2
    },
    "by_host": {
      "example.com": {
        "host": "example.com",
        "ports": {
          "22": {
            "port": 22,
            "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
            "service": "ssh",
            "version": "OpenSSH_8.2p1",
            "confidence": "high"
          },
          "21": {
            "port": 21,
            "banner": "220 (vsFTPd 3.0.3)",
            "service": "ftp",
            "version": "vsFTPd 3.0.3",
            "confidence": "high"
          }
        }
      }
    },
    "services_found": {
      "ssh": [{"host": "example.com", "port": 22, "version": "OpenSSH_8.2p1"}],
      "ftp": [{"host": "example.com", "port": 21, "version": "vsFTPd 3.0.3"}]
    }
  }
}
```

The banner and version are also copied onto the matching `port_scan.by_host[...].port_details` entries, and the CVE lookup reads `services_found` versions.

### Limitations

| Limitation | Description |
|------------|-------------|
| Binary protocols | RDP, LDAP, DNS don't send text banners |
| Authentication required | Some services won't respond without auth |
| Custom services | Unknown port/protocol combinations |
| Firewall blocking | May timeout on filtered ports |

For comprehensive service detection, the pipeline also runs Nmap service detection (`-sV`) in GROUP 3.5 when `NMAP_ENABLED` is on.

---

## Wappalyzer Technology Enhancement

Wappalyzer enhancement is **integrated into http_probe.py** (`enhance_with_wappalyzer()`) and runs automatically after httpx parsing. It uses the HTML and headers httpx already captured (no additional HTTP requests to the target) to detect technologies httpx's own detection might miss, including CMS plugins, analytics tools, security tools, and frameworks.

### How It Works

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  httpx Output    │────▶│  Wappalyzer      │────▶│  Enhanced JSON   │
│  (HTML bodies,   │     │  Enhancement     │     │  with additional │
│   headers)       │     │                  │     │  technologies    │
└──────────────────┘     │  1. Load the DB  │     └──────────────────┘
                          │  2. Analyze each │
                          │     captured page│
                          │  3. Drop matches │
                          │     below min    │
                          │     confidence   │
                          │  4. Merge new    │
                          │     techs into   │
                          │     httpx techs  │
                          └──────────────────┘
```

**The fingerprint database.** `download_wappalyzer_database()` fetches the
`wappalyzer@WAPPALYZER_NPM_VERSION` package's `categories.json` and
`technologies/*.json` from unpkg, normalizes them for python-Wappalyzer and
caches the result in `recon/main_recon_modules/data/wappalyzer_cache/` for
`WAPPALYZER_CACHE_TTL_HOURS`. When the download fails it uses the cached copy,
then python-Wappalyzer's bundled (older) database.

### Configuration

```python
# Wappalyzer Configuration (project settings, runtime keys)

# Enable/disable Wappalyzer technology enhancement
WAPPALYZER_ENABLED = True

# Minimum confidence level (0-100) to include a technology
# Lower = more detections but potentially more false positives
WAPPALYZER_MIN_CONFIDENCE = 50

# Analyze only URLs with HTML body (URLs without a captured body are skipped either way)
WAPPALYZER_REQUIRE_HTML = True

# Fetch the newer fingerprint database (False = the bundled one)
WAPPALYZER_AUTO_UPDATE = True
WAPPALYZER_CACHE_TTL_HOURS = 24
WAPPALYZER_NPM_VERSION = "6.10.56"
```

### Installation

`python-Wappalyzer` is installed in the recon image (`recon/requirements.txt`). If the import fails, the enhancement is skipped with a warning message.

### What Wappalyzer Detects

| Category | Examples | Why It Matters |
|----------|----------|----------------|
| **CMS Plugins** | Yoast SEO, WooCommerce, Contact Form 7, Advanced Custom Fields | Plugin vulnerabilities, outdated plugins |
| **Analytics Tools** | Google Analytics, Facebook Pixel, Hotjar, Mixpanel | Privacy concerns, tracking detection |
| **Security Tools** | Cloudflare, Sucuri, reCAPTCHA, Wordfence | WAF detection, security posture |
| **JavaScript Frameworks** | React, Vue.js, Angular, jQuery | Framework-specific vulnerabilities |
| **E-commerce Platforms** | Shopify, WooCommerce, Magento | Payment processing, PCI compliance |
| **CDN Providers** | Cloudflare, Fastly, Akamai | CDN-specific features, bypass techniques |
| **Database Tools** | phpMyAdmin, Adminer | Database exposure risks |
| **Version Information** | WordPress 6.0, jQuery 3.6.0 | Version-based CVE lookup |

### Output Structure

Wappalyzer results are added under the `wappalyzer` key within the `http_probe` section, and every technology httpx did not report is appended to that URL's `technologies` as `Name:version` (or `Name`):

```json
{
  "http_probe": {
    "by_url": {
      "https://example.com": {
        "technologies": ["Nginx:1.19.0", "PHP:5.6.40", "WordPress:6.0", "jQuery:3.6.0", "Yoast SEO:20.0"]
      }
    },
    "wappalyzer": {
      "scan_metadata": {
        "scan_timestamp": "2025-12-31T12:34:56.789012",
        "min_confidence": 50,
        "urls_analyzed": 1,
        "new_technologies_found": 2
      },
      "by_url": {
        "https://example.com": [
          {
            "name": "jQuery",
            "version": "3.6.0",
            "categories": ["JavaScript libraries"],
            "versions_all": ["3.6.0"],
            "confidence": 100
          },
          {
            "name": "Yoast SEO",
            "version": "20.0",
            "categories": ["SEO"],
            "versions_all": ["20.0"],
            "confidence": 100
          }
        ]
      },
      "new_technologies": {
        "jQuery": ["https://example.com"],
        "Yoast SEO": ["https://example.com"]
      },
      "all_technologies": {
        "jQuery": {
          "name": "jQuery",
          "versions_found": ["3.6.0"],
          "categories": ["JavaScript libraries"],
          "urls": ["https://example.com"],
          "confidence": 100
        }
      },
      "summary": {
        "urls_analyzed": 1,
        "total_technologies": 4,
        "new_technologies": 2,
        "httpx_missed": ["jQuery", "Yoast SEO"]
      }
    },
    "summary": {
      "technology_count": 5,
      "unique_technologies": ["Nginx:1.19.0", "PHP:5.6.40", "WordPress:6.0", "jQuery:3.6.0", "Yoast SEO:20.0"],
      "wappalyzer_additions": 2
    }
  }
}
```

### Benefits for CVE Lookup

Wappalyzer enhancement improves CVE lookup results:

1. **More Technologies Detected:** More technologies = more CVEs found
2. **Version Information:** Better version detection enables accurate CVE matching
3. **Plugin Vulnerabilities:** CMS plugins often have their own CVEs
4. **Framework CVEs:** JavaScript frameworks (jQuery, React) have known vulnerabilities

**Example:**
- **httpx only:** Detects `WordPress:6.0`
- **httpx + Wappalyzer:** Detects `WordPress:6.0`, `jQuery:3.6.0`, `Yoast SEO:20.0`, and each versioned one is looked up

### Performance Impact

Wappalyzer uses the HTML httpx already captured, so it sends **no additional requests to the target**. The time is HTML parsing and pattern matching, plus the database download when the cache is stale.

### Troubleshooting

#### "Wappalyzer not installed - skipping enhancement"

The recon image ships `python-Wappalyzer`; this message means the image was built without it. Rebuild the recon image.

#### "No new technologies found"

Possible causes:
1. httpx already detected all technologies
2. HTML body not included (`HTTPX_INCLUDE_RESPONSE = False`)
3. Technologies don't match Wappalyzer patterns
4. Confidence threshold too high (`WAPPALYZER_MIN_CONFIDENCE`)

Solutions:
```python
# Ensure HTML is included
HTTPX_INCLUDE_RESPONSE = True

# Lower confidence threshold
WAPPALYZER_MIN_CONFIDENCE = 30
```

#### "Wappalyzer errors for some URLs"

Wappalyzer may fail on:
- Malformed HTML
- Non-HTML responses (JSON, XML)
- Empty responses

This is normal - the enhancement continues for other URLs.

### Integration with CVE Lookup

Wappalyzer-detected technologies are automatically included in CVE lookup, because the lookup reads `http_probe.by_url[...].technologies`:

```json
{
  "technology_cves": {
    "by_technology": {
      "WordPress:6.0": {"cve_count": 5, "cves": [...]},
      "jQuery:3.6.0": {"cve_count": 3, "cves": [...]},  // From Wappalyzer
      "Yoast SEO:20.0": {"cve_count": 2, "cves": [...]}  // From Wappalyzer
    }
  }
}
```

---

## Architecture & Flow

> **Pipeline context:** HTTP probing runs in **GROUP 4** of the recon pipeline (`recon/main.py`), after GROUP 3 (Shodan + port scan), GROUP 3.5 (Nmap) and GROUP 3.6 (tlsx), when `http_probe` is in the scan modules and `HTTPX_ENABLED` is on. It depends on the merged `port_scan` to build probe targets. The module runs sequentially in the pipeline; httpx uses parallel threads internally. After it, `update_graph_from_http_probe` writes the graph in the background, certificate SANs are offered back as hostnames, and when no live URL was found the active scans that need one (resource enumeration, Nuclei and the web checks, the URL-reading Phase A tools) are skipped. Subdomain Takeover, the port and service checks, the org DNS checks and certificate hygiene still run, and each skipped source that was switched on keeps its earlier findings on the group's hosts (`_note_gate_skipped`).

### Execution Flow (`run_http_probe`)

```
1. PRECHECKS
   └── is_docker_installed() / is_docker_running()
   └── pull_httpx_docker_image() pulls the image if it is missing

2. TARGET BUILDING
   └── port_scan present → build_targets_from_naabu()
       (falls back to build_targets_from_dns() when it yields no URL)
   └── no port_scan → build_targets_from_dns()
   └── apply_custom_port_scope(): with NAABU_CUSTOM_PORTS set, drop every
       URL on another port
   └── admit_urls(): drop a URL whose host the RoE excludes, by name or, under
       IP/CIDR entries, by any address the run resolved it to (below)

3. PROBE EXECUTION
   └── targets.txt in a per-run dir /tmp/redamon/.httpx_temp_<id>
   └── build_httpx_command() → docker run ... -json, session headers
       checked against the hosts in targets.txt
   └── Stop at httpx_budget(); parse whatever was written

4. RESULT PROCESSING  (parse_httpx_output)
   └── Parse the JSON Lines output line by line
   └── Scope filter (requested host and final host); off-scope redirects
       become external_domains
   └── Redirect chain, TLS certificate, fingerprints, headers
   └── AI surface signals (_annotate_ai_http_signals)
   └── Aggregate by host; track technologies and servers; summary

5. ENRICHMENT
   └── enhance_with_wappalyzer()
   └── capture_httpx_transactions() (traffic capture, when enabled)
   └── Jev page-type labels (AI_IN_PIPELINE and HTTPX_JEV_PAGE_TYPE)
   └── Drop the bodies

6. RESULT
   └── recon_data["http_probe"] = {...}
   └── run_banner_grab() → recon_data["banner_grab"]
   └── Written to output_file when one is passed
   └── The temp dir is removed
```

### URL Building from the Port Scan

`build_targets_from_naabu()` reads `port_scan.by_host[...].port_details` (Naabu and Masscan merged):

```python
# A port's service name decides first, then the port number
# 443, or service containing "https"/"ssl"/"tls" -> https://host[:port]
# 80, or service containing "http"               -> http://host[:port]
HTTPS_PORTS = {443, 8443, 4443, 9443, 8843}      # -> https://host:port
HTTP_PORTS  = {80, 8080, 8000, 8888, 8008, 3000, 5000, 9000}  # -> http://host:port
# Any other port -> try both http:// and https://
```

`build_targets_from_dns()` (the fallback) probes each resolved host (the root only when it is a target): with `NAABU_CUSTOM_PORTS` set, exactly those ports; otherwise ports 80 and 443 plus 8080, 8000, 8888, 3000, 5000, 9000 over HTTP and 8443, 4443, 9443 over HTTPS. In IP mode a placeholder name (`10-0-0-1`) is replaced by its IP, and no reverse-DNS name is ever a target here: the hostnames an IP-mode run scans are probed later, by the hostnames step (README.RECON.md, "IP / CIDR: hostnames on target IPs"), on their target IPs only.

### RoE admission of the target list

httpx resolves each name itself, so the URL list passes the Rules of Engagement
admission gate (`admit_urls` in `recon/helpers/target_admission.py`) after the
custom-port guard. A URL survives when its host is an admitted IP literal, or a
name the RoE host entries do not exclude whose every known address is outside
the RoE IP and CIDR entries. While such an entry is set, a name with no known
address is refused too and recorded as not checked, so its earlier findings
are kept. Each refusal is logged once (`[-][RoE] httpx: not sent to ...`) and
noted under the coverage source `roe_excluded`. With no exclusion the list,
and so the httpx command, is unchanged.

The banner grab connects to addresses itself, and `by_host` can hold one a
passive source or a partial run's graph rows added, so its targets pass the
same gate (module `banner_grab`): an excluded address, an address reached only
through an excluded name, and, under IP or CIDR entries, a name with no known
address are not connected to.

### Docker Command Structure

What `build_httpx_command()` produces with the default settings:

```bash
docker run --rm --net=host \
  --name redamon-httpx-<id> \
  -v /tmp/redamon/.httpx_temp_<id>:/targets:ro \
  -v /tmp/redamon/.httpx_temp_<id>:/output \
  projectdiscovery/httpx:latest \
  -l /targets/targets.txt \
  -o /output/httpx_output.json \
  -json \
  -silent \
  -nc \
  -t 50 \                    # Threads
  -timeout 10 \
  -retries 2 \
  -rl 50 \                   # Rate limit
  -fr \                      # Follow redirects (-fhr with session headers, in IP mode, under RoE exclusions)
  -maxr 10 \                 # Max redirects
  -sc \                      # Status code
  -cl \                      # Content length
  -ct \                      # Content type
  -title \                   # Page title
  -server \                  # Server header
  -rt \                      # Response time
  -wc \                      # Word count
  -lc \                      # Line count
  -td \                      # Tech detect
  -ip \                      # IP address
  -cname \                   # CNAME records
  -tls-probe \               # probe the certificate's names (not in IP mode, not under RoE exclusions)
  -tls-grab \                # TLS certificate
  -favicon \                 # Favicon hash
  -jarm \                    # JARM fingerprint
  -hash sha256 \             # Body hash
  -irr \                     # Include response (headers + body)
  -irh \                     # Include headers only
  -asn \                     # ASN info
  -cdn \                     # CDN detection
  -H "User-Agent: ..." ...   # One -H per HTTPX_CUSTOM_HEADERS entry
```

`-path`, `-mc` and `-fc` are added when `HTTPX_PATHS`, `HTTPX_MATCH_CODES` and `HTTPX_FILTER_CODES` are set. `--net=host` lets httpx reach loopback and local-lab targets; the name lets the budget watchdog `docker kill` the container.

---

## Output Data Structure

### Complete JSON Schema

```json
{
  "http_probe": {
    "scan_metadata": {
      "scan_timestamp": "2024-01-15T12:00:00.000000",
      "scan_duration_seconds": 120.5,
      "docker_image": "projectdiscovery/httpx:latest",
      "threads": 50,
      "timeout": 10,
      "rate_limit": 50,
      "follow_redirects": true,
      "tech_detection": true,
      "tls_probing": true,
      "response_included": true,
      "proxy_used": false,
      "total_urls_probed": 150,
      "stopped_at_budget": false,
      "root_domain_filter": "example.com",
      "filtered_mode": false,
      "allowed_hosts_filter": null
    },

    "by_url": {
      "https://example.com": {
        "url": "https://example.com",
        "host": "example.com",
        "status_code": 200,
        "content_length": 45678,
        "content_type": "text/html; charset=UTF-8",
        "title": "Example Domain",
        "server": "nginx/1.18.0",
        "response_time_ms": 245,
        "word_count": 1234,
        "line_count": 89,
        "technologies": ["Nginx:1.18.0", "PHP", "WordPress"],
        "ip": "93.184.216.34",
        "cname": null,
        "cdn": null,
        "is_cdn": false,
        "asn": {
          "as_number": "AS15133",
          "as_name": "Edgecast Inc.",
          "as_country": "US"
        },
        "final_url": "https://example.com",
        "first_status_code": 200,
        "redirect_chain_codes": [200],
        "redirected_off_host": false,
        "tls": { "...": "see SSL/TLS Information" },
        "favicon_hash": "116323821",
        "jarm": "29d29d15d29d29d00029d29d29d29d...",
        "body_hash": {"body_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                      "header_sha256": "..."},
        "headers": {
          "content_type": "text/html; charset=UTF-8",
          "x_powered_by": "PHP/7.4.3"
        }
      }
    },

    "external_domains": [
      {"domain": "idp.example.net", "source": "http_probe_redirect",
       "url": "https://idp.example.net/saml/login", "redirect_from_url": "http://old.example.com",
       "status_code": 200, "title": "SAML Login", "server": "nginx"}
    ],

    "by_host": {
      "example.com": {
        "hostname": "example.com",
        "urls": ["http://example.com", "https://example.com"],
        "live_urls": ["https://example.com"],
        "technologies": ["Nginx:1.18.0", "PHP", "WordPress"],
        "servers": ["nginx/1.18.0"],
        "status_codes": [200, 301]
      }
    },

    "technologies_found": {
      "Nginx:1.18.0": ["https://example.com", "https://api.example.com"],
      "PHP": ["https://example.com"],
      "WordPress": ["https://example.com"],
      "React": ["https://app.example.com"]
    },

    "servers_found": {
      "nginx/1.18.0": ["https://example.com"],
      "Apache/2.4.41": ["https://legacy.example.com"]
    },

    "summary": {
      "total_urls_probed": 150,
      "live_urls": 45,
      "total_hosts": 25,
      "by_status_code": {
        "200": 35,
        "301": 8,
        "404": 2
      },
      "unique_technologies": ["Nginx:1.18.0", "PHP", "WordPress", "React"],
      "technology_count": 4,
      "unique_servers": ["nginx/1.18.0", "Apache/2.4.41"],
      "server_count": 2,
      "cdn_hosts": 3,
      "filtered_out_of_scope": 2,
      "ai_header_matches": 0,
      "ai_favicon_matches": 0,
      "ai_title_matches": 0,
      "ai_wappalyzer_matches": 0,
      "wappalyzer_additions": 0
    },

    "wappalyzer": { "...": "see Wappalyzer Technology Enhancement" }
  }
}
```

- Most values are passed through as httpx writes them: `body_hash` is httpx's `hash` object (the graph stores its `body_sha256` and `header_sha256`), and header names arrive with underscores (`x_powered_by`).
- A URL counts as live when it answered with a status below 500.
- `summary.total_urls_probed` counts the parsed results; `scan_metadata.total_urls_probed` the URLs sent.
- `body` is not stored (see [Response Content Inclusion](#8-response-content-inclusion)).
- `update_graph_from_http_probe` (`graph_db/mixins/recon/http_mixin.py`) writes the result to the graph.

---

## Usage Examples

### Basic Usage (full pipeline)

The probe runs when the project's scan modules include `http_probe` (they do by default) and `HTTPX_ENABLED` is on. Start a recon scan from the webapp; the orchestrator spawns the recon container, which runs `recon/main.py` with the project's settings.

### Partial Recon

`recon/partial_recon_modules/http_probing.py` (`run_httpx`) re-runs `run_http_probe()` on demand against the graph's hosts and ports and any targets the user typed in. It turns off the custom-port guard (`HTTPX_ENFORCE_CUSTOM_PORT_SCOPE = False`), since it scopes the ports itself.

### Standalone Enrichment

```python
from recon.main_recon_modules.http_probe import enrich_recon_file
from pathlib import Path

enriched = enrich_recon_file(Path("output/recon_example.com.json"))
```

`enrich_recon_file()` loads the settings with `get_settings()`, runs `run_http_probe()` and writes the result back to the same file.

### Configuration Profiles

Values to enter in the project settings (shown as runtime keys):

**Quick Probe (Fast):**
```python
HTTPX_THREADS = 100
HTTPX_RATE_LIMIT = 300
HTTPX_TIMEOUT = 5
HTTPX_PROBE_TECH_DETECT = True
HTTPX_INCLUDE_RESPONSE = False  # Skips Wappalyzer and the AI body pass
```

**Comprehensive Analysis:**
```python
HTTPX_THREADS = 50
HTTPX_RATE_LIMIT = 100
HTTPX_TIMEOUT = 15
HTTPX_PROBE_TECH_DETECT = True
HTTPX_PROBE_TLS_INFO = True
HTTPX_PROBE_TLS_GRAB = True
HTTPX_PROBE_FAVICON = True
HTTPX_PROBE_JARM = True
HTTPX_INCLUDE_RESPONSE = True
HTTPX_INCLUDE_RESPONSE_HEADERS = True
```

**Stealth Probe:**
```python
HTTPX_THREADS = 10
HTTPX_RATE_LIMIT = 20
HTTPX_TIMEOUT = 20
HTTPX_CUSTOM_HEADERS = [
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
]
```

**Technology-Focused:**
```python
HTTPX_PROBE_TECH_DETECT = True
HTTPX_PROBE_SERVER = True
HTTPX_PROBE_FAVICON = True
HTTPX_PROBE_HASH = "sha256"
HTTPX_INCLUDE_RESPONSE_HEADERS = True
```

---

## Troubleshooting

### Common Issues

#### "[!][httpx] Docker is not installed" / "Docker daemon is not running"

httpx runs through the host's Docker daemon. Check that Docker is running on the host (`docker info`) and that the recon container can reach it.

#### "No live URLs found"

Possible causes:
1. Hosts are down
2. Firewall blocking requests
3. Wrong ports probed (with `NAABU_CUSTOM_PORTS` set, only those ports are probed)
4. Results filtered as out of scope (see `summary.filtered_out_of_scope`)

Solutions:
```python
# Increase timeout
HTTPX_TIMEOUT = 20

# Increase retries
HTTPX_RETRIES = 3
```

With no live URL, the pipeline skips resource enumeration, Nuclei and the web checks, and the Phase A tools that read URLs (`metadata.active_scans_skipped`). Subdomain Takeover (Subjack and BadDNS read names, not URLs), the port and service checks (admin and database ports, Redis, SMTP relay, Kubernetes API), the org DNS checks and certificate hygiene still run. A skipped source that was switched on is noted degraded ("not run: no live HTTP URL") by host on the group's hosts, so its earlier findings are kept there and it shows as a coverage gap; one switched off prunes as usual.

#### "[!][httpx] ... - nothing was probed; earlier findings are kept"

httpx could not run: Docker missing or down, the image unavailable, an exit or its runtime budget with nothing written, or an exception. A failed probe is not "no live URL". It records `metadata.phase_errors.http_probe`, keeps the `http_probe` source, and is not listed in `modules_executed`. The pipeline takes the same skip as above (`SKIPPING ACTIVE SCANS: http_probe failed (...)`), with the coverage reason "http_probe failed, no host probed", and keeps more: `security_check` on every host, the port- and DNS-check ones included, since the web checks were not re-checked anywhere, and the findings of JS Recon and AI Surface Recon, which still run without httpx's pages.

#### "Probe hit its ...s budget"

The probe outlived `httpx_budget()` and was stopped; downstream phases run on what it found. If it had written nothing by then, the probe counts as failed (see above). Raise `HTTPX_THREADS`, or lower `HTTPX_RETRIES`, or probe fewer URLs.

#### Scan too slow

```python
# Increase performance
HTTPX_THREADS = 100
HTTPX_RATE_LIMIT = 300
HTTPX_TIMEOUT = 5
HTTPX_RETRIES = 1

# Disable expensive probes
HTTPX_PROBE_JARM = False
HTTPX_INCLUDE_RESPONSE = False
```

#### Too much output data

```python
# Disable response headers
HTTPX_INCLUDE_RESPONSE_HEADERS = False

# Filter status codes
HTTPX_MATCH_CODES = ["200"]
```

### Debug Mode

Run httpx manually via Docker:

```bash
docker run --rm \
  projectdiscovery/httpx:latest \
  -u https://example.com \
  -sc -td -server -title \
  -v -debug
```

---

## Security Considerations

⚠️ **Legal Warning:** Only scan systems you have explicit permission to test.

| Risk | Mitigation |
|------|------------|
| Rate limiting/bans | Reduce `HTTPX_RATE_LIMIT`, or set the engagement ceiling (`ROE_GLOBAL_MAX_RPS`) |
| WAF blocking | Use custom User-Agent, reduce rate |
| Detection | Reduce threads, or use stealth mode |
| Fingerprinting | Your requests are identifiable |
| Session leakage | Session headers go only to probes whose hosts are all in scope, and redirects stay on the same host |

### Safe Defaults

```python
HTTPX_THREADS = 25
HTTPX_RATE_LIMIT = 50
HTTPX_TIMEOUT = 15
HTTPX_CUSTOM_HEADERS = [
    "User-Agent: Mozilla/5.0 (compatible; SecurityScanner/1.0)"
]
```

---

## Dependencies

| Package | Purpose |
|---------|---------|
| Docker | Container runtime for httpx |
| `projectdiscovery/httpx:latest` | httpx Docker image (auto-pulled) |
| `python-Wappalyzer` | Wappalyzer pass (in `recon/requirements.txt`) |
| Python 3.11 | The recon image's runtime |

---

## References

- [httpx Documentation](https://github.com/projectdiscovery/httpx)
- [httpx Docker Hub](https://hub.docker.com/r/projectdiscovery/httpx)
- [Wappalyzer](https://www.wappalyzer.com/) - Technology detection rules
- [JARM Fingerprinting](https://github.com/salesforce/jarm)
- [ProjectDiscovery Blog](https://blog.projectdiscovery.io/)
