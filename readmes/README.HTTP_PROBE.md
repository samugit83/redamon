# RedAmon - httpx HTTP Prober + Banner Grabbing

## Complete Technical Documentation

> **Module:** `recon/httpx_scan.py`  
> **Purpose:** HTTP probing, technology detection, and non-HTTP service detection  
> **Author:** RedAmon Security Suite

---

## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Installation](#installation)
4. [Configuration Parameters](#configuration-parameters)
5. [Banner Grabbing](#banner-grabbing)
6. [Architecture & Flow](#architecture--flow)
7. [Output Data Structure](#output-data-structure)
8. [Usage Examples](#usage-examples)
9. [Troubleshooting](#troubleshooting)

---

## Overview

The `httpx_scan.py` module integrates ProjectDiscovery's httpx toolkit into RedAmon's reconnaissance pipeline. httpx is a multi-purpose HTTP toolkit designed for probing, technology detection, and web service analysis.

**This module also includes integrated banner grabbing** for non-HTTP services (SSH, FTP, SMTP, MySQL, etc.) to provide complete service detection across all open ports.

**⚠️ Important:** httpx runs exclusively via Docker. No native installation is supported.

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
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Naabu Results  │────▶│  httpx_scan.py   │────▶│  Enriched JSON  │
│  (open ports,   │     │                  │     │  with live URLs,│
│   hostnames)    │     │  1. Build URLs   │     │  technologies,  │
└─────────────────┘     │  2. HTTP probe   │     │  TLS info,      │
        │               │  3. Tech detect  │     │  banners, etc.  │
        │               │  4. Banner grab  │     └─────────────────┘
        │               │  5. Parse JSON   │
        ▼               └──────────────────┘
┌─────────────────┐
│  DNS Data       │  (Fallback if no Naabu)
│  (hostnames)    │
└─────────────────┘
```

---

## Features

| Feature | Description |
|---------|-------------|
| **HTTP Probing** | Identifies live HTTP/HTTPS endpoints |
| **Technology Detection** | Wappalyzer-based tech fingerprinting |
| **TLS Analysis** | Certificate info, cipher suites, JARM |
| **CDN Detection** | Identifies CDN providers |
| **ASN Lookup** | Autonomous System Number detection |
| **Response Analysis** | Status codes, headers, body hashing |
| **Favicon Hashing** | Fingerprint via favicon hash |
| **Banner Grabbing** | Service detection for non-HTTP ports (SSH, FTP, SMTP, etc.) |
| **Docker Execution** | No local installation required |
| **Tor Support** | Anonymous probing via SOCKS proxy |

---

## Installation

### Requirements

- **Docker** installed and running

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

# Optionally pre-pull the image
docker pull projectdiscovery/httpx:latest
```

---

## Configuration Parameters

All parameters are configured via the webapp project settings (stored in PostgreSQL) or as defaults in `project_settings.py`. This section provides **detailed explanations** including performance impact for each option.

---

### 1. Core Configuration

| Parameter | Type | Default | httpx Flag | Description |
|-----------|------|---------|------------|-------------|
| `HTTPX_DOCKER_IMAGE` | `str` | `"projectdiscovery/httpx:latest"` | - | Docker image to use. Only change for custom builds or specific versions. |
| `HTTPX_THREADS` | `int` | `50` | `-t` | Number of concurrent HTTP requests. Higher = faster but uses more CPU/memory. |
| `HTTPX_TIMEOUT` | `int` | `10` | `-timeout` | Seconds to wait for each HTTP response before giving up. |
| `HTTPX_RETRIES` | `int` | `2` | `-retries` | Number of retry attempts for failed/timeout requests. |
| `HTTPX_RATE_LIMIT` | `int` | `150` | `-rl` | Maximum requests per second. Set to `0` for unlimited. Lower = more stealthy. |

**Thread Tuning Guide:**

| Threads | Use Case | CPU Usage | Memory |
|---------|----------|-----------|--------|
| 10-25 | Stealth scanning, limited bandwidth | Low | ~100MB |
| 50 | **Default** - balanced performance | Medium | ~200MB |
| 100-200 | Fast scanning, good hardware | High | ~500MB |
| 300+ | Maximum speed, powerful servers only | Very High | 1GB+ |

**Timeout Considerations:**
- `5s` - Fast networks, modern servers
- `10s` - **Default** - handles most scenarios
- `15-30s` - Slow servers, high latency networks, Tor usage

---

### 2. Redirect Handling

| Parameter | Type | Default | httpx Flag | Description |
|-----------|------|---------|------------|-------------|
| `HTTPX_FOLLOW_REDIRECTS` | `bool` | `True` | `-fr` | Follow HTTP 301/302/307/308 redirects. Essential for modern web apps. |
| `HTTPX_MAX_REDIRECTS` | `int` | `10` | `-maxr` | Maximum redirect chain length. Prevents infinite redirect loops. |

**Why Follow Redirects?**
- Many sites redirect `http://` → `https://`
- www → non-www redirects are common
- Login pages often redirect after authentication
- Without following, you might miss the actual content

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
| `HTTPX_PROBE_RESPONSE_TIME` | `bool` | `True` | `-rt` | Time to first byte in milliseconds | ✅ **None** |
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
| `HTTPX_PROBE_TLS_INFO` | `bool` | `True` | `-tls-probe` | Basic TLS info: version, cipher suite | ⚡ **Medium** |
| `HTTPX_PROBE_TLS_GRAB` | `bool` | `True` | `-tls-grab` | Full certificate extraction | ⚠️ **SLOW** |

**TLS_INFO extracts:**
- TLS version (TLS 1.0, 1.1, 1.2, 1.3)
- Cipher suite in use

**TLS_GRAB extracts (additional):**
- Certificate subject (CN, O, OU)
- Certificate issuer (CA)
- Validity period (not_before, not_after)
- Subject Alternative Names (all domains on cert)
- Serial number

**Example TLS Output:**
```json
{
  "tls": {
    "version": "TLS 1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "certificate": {
      "subject_cn": "*.example.com",
      "issuer": "Let's Encrypt Authority X3",
      "not_before": "2024-01-01T00:00:00Z",
      "not_after": "2024-04-01T00:00:00Z",
      "san": ["example.com", "*.example.com", "www.example.com"]
    }
  }
}
```

⚠️ **Performance Note:** `TLS_GRAB` requires a full TLS handshake and certificate parsing. Disable for faster scans.

---

### 7. Fingerprinting (Advanced)

| Parameter | Type | Default | httpx Flag | What It Does | Speed Impact |
|-----------|------|---------|------------|--------------|--------------|
| `HTTPX_PROBE_FAVICON` | `bool` | `True` | `-favicon` | Calculates MMH3 hash of favicon.ico | ⚡ **Medium** (extra HTTP request) |
| `HTTPX_PROBE_JARM` | `bool` | `True` | `-jarm` | JARM TLS fingerprint | ⚠️ **VERY SLOW** |
| `HTTPX_PROBE_HASH` | `str` | `"sha256"` | `-hash` | Hash of response body | ⚡ **Medium** |

#### Favicon Hashing

**What It Is:**
- Downloads `/favicon.ico` and calculates MMH3 hash
- Same favicon = same application/framework

**Use Cases:**
- Identify Cobalt Strike C2 servers (known hashes)
- Find admin panels (phpMyAdmin, cPanel)
- Detect specific applications
- Cross-reference with Shodan favicon database

**Example:**
```json
{
  "favicon_hash": "-1396576824"
}
```

#### JARM Fingerprinting

**What It Is:**
- JARM = JA3 + RDP fingerprint for servers
- Creates unique fingerprint based on TLS server configuration
- Requires **10 separate TLS handshakes** per target

**Why It's Slow:**
```
Each JARM fingerprint requires:
- 10 different TLS ClientHello messages
- 10 separate connections
- Parsing 10 ServerHello responses
- Total: ~5-10 seconds per target
```

**Use Cases:**
- Identify C2 (Command & Control) servers
- Detect malware infrastructure
- Fingerprint load balancers
- Track threat actors

⚠️ **Recommendation:** Disable JARM (`HTTPX_PROBE_JARM = False`) for regular scans. Enable only for targeted threat hunting.

#### Body Hash

**Options:** `"md5"`, `"sha256"`, `"sha512"`, `""` (disabled)

**Use Cases:**
- Detect identical pages across different URLs
- Find mirror sites
- Identify default/template pages

---

### 8. Response Content Inclusion

| Parameter | Type | Default | httpx Flag | What It Does | Speed Impact |
|-----------|------|---------|------------|--------------|--------------|
| `HTTPX_INCLUDE_RESPONSE` | `bool` | `True` | `-irr` | Include full HTTP response (headers + body) | ⚠️ **SLOW** + Large Output |
| `HTTPX_INCLUDE_RESPONSE_HEADERS` | `bool` | `True` | `-irh` | Include only response headers | ⚡ **Medium** |

**Output Size Comparison:**

| Setting | Typical Size per URL |
|---------|---------------------|
| Headers only | 1-5 KB |
| Headers + Body | 50-500 KB |
| Full response | 100+ KB |

**When to Enable Full Response:**
- ✅ Detailed analysis of response content
- ✅ Looking for sensitive data exposure
- ✅ Custom pattern matching needed
- ❌ Large-scale scanning (creates huge files)
- ❌ Speed is priority

---

### 9. Advanced Options

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `HTTPX_PATHS` | `list` | `[]` | Additional paths to probe beyond root |
| `HTTPX_CUSTOM_HEADERS` | `list` | `[]` | Custom HTTP headers to send |
| `HTTPX_MATCH_CODES` | `list` | `[]` | Only keep responses with these status codes |
| `HTTPX_FILTER_CODES` | `list` | `[]` | Exclude responses with these status codes |

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

#### Status Code Filtering

```python
# Only successful responses
HTTPX_MATCH_CODES = ["200", "301", "302"]

# Exclude noise
HTTPX_FILTER_CODES = ["404", "403", "500", "502", "503"]
```

---

### Speed Profiles

#### 🏎️ Fast Mode (Reconnaissance)
```python
# Minimal features, maximum speed
HTTPX_THREADS = 100
HTTPX_TIMEOUT = 5
HTTPX_RETRIES = 0
HTTPX_RATE_LIMIT = 0

HTTPX_PROBE_JARM = False           # DISABLE - very slow
HTTPX_PROBE_TLS_GRAB = False       # DISABLE - slow
HTTPX_PROBE_FAVICON = False        # DISABLE - extra request
HTTPX_PROBE_HASH = ""              # DISABLE
HTTPX_INCLUDE_RESPONSE = False     # DISABLE - large output
```
**Expected:** ~5-10 seconds for 10 URLs

#### ⚖️ Balanced Mode (Default)
```python
# Good balance of speed and information
HTTPX_THREADS = 50
HTTPX_TIMEOUT = 10
HTTPX_RETRIES = 1
HTTPX_RATE_LIMIT = 150

HTTPX_PROBE_JARM = False           # DISABLE for balance
HTTPX_PROBE_TLS_GRAB = True
HTTPX_PROBE_FAVICON = True
HTTPX_INCLUDE_RESPONSE = False
```
**Expected:** ~20-40 seconds for 10 URLs

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
**Expected:** ~2-5 minutes for 10 URLs

---

## Banner Grabbing

Banner grabbing is **integrated into httpx_scan.py** and runs automatically after HTTP probing. It detects service versions on non-HTTP ports that httpx cannot probe.

### Configuration

```python
# Banner Grabbing Configuration (project_settings.py)

# Enable/disable banner grabbing for non-HTTP ports
BANNER_GRAB_ENABLED = True

# Connection timeout per port (seconds)
BANNER_GRAB_TIMEOUT = 5

# Number of concurrent threads
BANNER_GRAB_THREADS = 20

# Maximum banner length to store (characters)
BANNER_GRAB_MAX_LENGTH = 500
```

### Supported Services

| Service | Port(s) | Detection Method |
|---------|---------|------------------|
| SSH | 22 | Banner: `SSH-2.0-OpenSSH_8.2p1` |
| FTP | 21 | Banner: `220 vsFTPd 3.0.3` |
| SMTP | 25, 465, 587 | Banner: `220 mail.example.com ESMTP Postfix` |
| POP3 | 110, 995 | Banner: `+OK Dovecot ready` |
| IMAP | 143, 993 | Banner: `* OK Dovecot IMAP` |
| MySQL | 3306 | Connection handshake |
| PostgreSQL | 5432 | Cancel request response |
| Redis | 6379 | `INFO` command response |
| VNC | 5900 | RFB protocol banner |
| Memcached | 11211 | `VERSION` command |
| Telnet | 23 | Login prompt |

### Skipped Ports (Handled by httpx)

HTTP ports are automatically skipped since httpx provides better detection:

```
80, 443, 8080, 8443, 8000, 8888, 8008, 3000, 5000, 9000, 9090, 8800
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
            "version": "OpenSSH 8.2p1",
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
      "ssh": [{"host": "example.com", "port": 22, "version": "OpenSSH 8.2p1"}],
      "ftp": [{"host": "example.com", "port": 21, "version": "vsFTPd 3.0.3"}]
    }
  }
}
```

### Limitations

| Limitation | Description |
|------------|-------------|
| Binary protocols | RDP, LDAP, DNS don't send text banners |
| Authentication required | Some services won't respond without auth |
| Custom services | Unknown port/protocol combinations |
| Firewall blocking | May timeout on filtered ports |

For comprehensive service detection (1000+ services), consider using nmap with `-sV` flag separately.

---

## Wappalyzer Technology Enhancement

Wappalyzer enhancement is **integrated into httpx_scan.py** and runs automatically after httpx parsing. It uses existing HTML from httpx (no additional HTTP requests) to detect 1000+ technologies, including CMS plugins, analytics tools, security tools, and frameworks that httpx might miss.

### How It Works

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  httpx Output    │────▶│  Wappalyzer      │────▶│  Enhanced JSON   │
│  (HTML bodies,   │     │  Enhancement     │     │  with additional │
│   technologies)   │     │                  │     │  technologies    │
└──────────────────┘     │  1. Parse HTML   │     └──────────────────┘
                          │  2. Match 1000+  │
                          │     patterns     │
                          │  3. Detect       │
                          │     plugins,     │
                          │     analytics    │
                          │  4. Merge with   │
                          │     httpx techs  │
                          └──────────────────┘
```

### Configuration

```python
# Wappalyzer Configuration (project_settings.py)

# Enable/disable Wappalyzer technology enhancement
WAPPALYZER_ENABLED = True

# Minimum confidence level (0-100) to include a technology
# Lower = more detections but potentially more false positives
WAPPALYZER_MIN_CONFIDENCE = 50

# Analyze only URLs with HTML body (recommended: True)
# When False, attempts to analyze URLs without body (limited detection)
WAPPALYZER_REQUIRE_HTML = True
```

### Installation

Wappalyzer requires the `python-Wappalyzer` library:

```bash
pip install python-Wappalyzer
```

**Note:** If Wappalyzer is not installed, the enhancement will be skipped with a warning message.

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

### Comparison: httpx vs Wappalyzer

| Feature | httpx Built-in | Wappalyzer Enhancement |
|---------|---------------|------------------------|
| **Pattern Database** | ~50-100 patterns | **1000+ patterns** |
| **CMS Plugins** | ❌ Limited | ✅ **Excellent** |
| **Analytics Tools** | ❌ Few | ✅ **Comprehensive** |
| **Security Tools** | ⚠️ Basic | ✅ **Detailed** |
| **Version Detection** | ⚠️ Basic | ✅ **Enhanced with confidence** |
| **Category Classification** | ❌ None | ✅ **Full categorization** |
| **Confidence Scores** | ❌ None | ✅ **Per-technology** |

### Output Structure

Wappalyzer results are added under the `wappalyzer` key within the `httpx` section:

```json
{
  "httpx": {
    "by_url": {
      "https://example.com": {
        "technologies": ["Nginx:1.19.0", "PHP:5.6.40", "WordPress:6.0", "jQuery:3.6.0", "Yoast SEO"]
      }
    },
    "wappalyzer": {
      "scan_metadata": {
        "scan_timestamp": "2025-12-31T12:34:56.789012",
        "urls_analyzed": 1,
        "new_technologies_found": 3,
        "plugins_detected": 1,
        "analytics_detected": 1,
        "security_tools_detected": 1
      },
      "by_url": {
        "https://example.com": [
          {
            "name": "jQuery",
            "version": "3.6.0",
            "categories": ["JavaScript frameworks"],
            "confidence": 100
          },
          {
            "name": "Yoast SEO",
            "version": "20.0",
            "categories": ["CMS"],
            "confidence": 95
          },
          {
            "name": "Google Analytics",
            "version": null,
            "categories": ["Analytics"],
            "confidence": 100
          }
        ]
      },
      "new_technologies": {
        "jQuery:3.6.0": ["https://example.com"],
        "Yoast SEO": ["https://example.com"],
        "Google Analytics": ["https://example.com"]
      },
      "all_technologies": {
        "WordPress": {
          "name": "WordPress",
          "versions_found": ["6.0"],
          "categories": ["CMS"],
          "urls": ["https://example.com"]
        },
        "jQuery": {
          "name": "jQuery",
          "versions_found": ["3.6.0"],
          "categories": ["JavaScript frameworks"],
          "urls": ["https://example.com"]
        }
      },
      "plugins": [
        {
          "name": "Yoast SEO",
          "version": "20.0",
          "url": "https://example.com"
        }
      ],
      "analytics": [
        {
          "name": "Google Analytics",
          "url": "https://example.com"
        }
      ],
      "security_tools": [
        {
          "name": "Cloudflare",
          "url": "https://example.com"
        }
      ],
      "frameworks": [
        {
          "name": "jQuery",
          "version": "3.6.0",
          "url": "https://example.com"
        }
      ],
      "summary": {
        "urls_analyzed": 1,
        "total_technologies": 5,
        "new_technologies": 3,
        "httpx_missed": ["jQuery:3.6.0", "Yoast SEO", "Google Analytics"],
        "plugins_count": 1,
        "analytics_count": 1,
        "security_tools_count": 1,
        "frameworks_count": 1
      }
    },
    "summary": {
      "technology_count": 5,
      "unique_technologies": ["Nginx:1.19.0", "PHP:5.6.40", "WordPress:6.0", "jQuery:3.6.0", "Yoast SEO"],
      "wappalyzer_additions": 3
    }
  }
}
```

### Benefits for CVE Lookup

Wappalyzer enhancement significantly improves CVE lookup results:

1. **More Technologies Detected:** More technologies = more CVEs found
2. **Version Information:** Better version detection enables accurate CVE matching
3. **Plugin Vulnerabilities:** CMS plugins often have their own CVEs
4. **Framework CVEs:** JavaScript frameworks (jQuery, React) have known vulnerabilities

**Example:**
- **httpx only:** Detects `WordPress:6.0` → 5 CVEs found
- **httpx + Wappalyzer:** Detects `WordPress:6.0`, `jQuery:3.6.0`, `Yoast SEO:20.0` → 15 CVEs found

### Performance Impact

| URLs | Wappalyzer Time | Total Scan Time |
|------|----------------|-----------------|
| 1 URL | ~1-2 seconds | +1-2 seconds |
| 10 URLs | ~5-10 seconds | +5-10 seconds |
| 100 URLs | ~30-60 seconds | +30-60 seconds |

**Note:** Wappalyzer uses existing HTML from httpx, so there are **no additional HTTP requests**. The time is purely for HTML parsing and pattern matching.

### Troubleshooting

#### "Wappalyzer not installed"

```bash
pip install python-Wappalyzer
```

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

Wappalyzer-detected technologies are automatically included in CVE lookup:

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

> **Pipeline context:** HTTP probing runs in **GROUP 4** of the parallelized recon pipeline, sequentially after GROUP 3 (Shodan + Port Scan). It depends on port scan results to build probe targets. While the module itself runs sequentially in the pipeline, httpx internally uses parallel threads for probing multiple targets.

### Execution Flow

```
1. INITIALIZATION
   └── Check Docker availability
   └── Pull httpx image if needed
   └── Check Tor availability (if enabled)

2. TARGET BUILDING
   └── Priority 1: Build URLs from Naabu port data
   └── Priority 2: Build URLs from DNS data (fallback)
   └── Determine HTTP/HTTPS based on port numbers

3. PROBE EXECUTION
   └── Create targets file with URLs
   └── Build httpx Docker command
   └── Execute with JSON Lines output
   └── Monitor progress

4. RESULT PROCESSING
   └── Parse JSONL output line by line
   └── Extract technologies per URL
   └── Aggregate data by host
   └── Track unique technologies and servers

5. DATA ENRICHMENT
   └── Add "httpx" section to recon_data
   └── Save incrementally to JSON file
   └── Generate summary statistics
```

### URL Building from Naabu

```python
# Port-based protocol detection
https_ports = {443, 8443, 4443, 9443}
http_ports = {80, 8080, 8000, 8888}

# Example transformations:
# Port 443 -> https://example.com
# Port 80 -> http://example.com
# Port 8443 -> https://example.com:8443
# Port 8080 -> http://example.com:8080
# Unknown port -> try both http:// and https://
```

### Docker Command Structure

```bash
docker run --rm -i \
  -v /targets:/targets:ro \
  -v /output:/output \
  projectdiscovery/httpx:latest \
  -l /targets/targets.txt \
  -o /output/httpx_output.json \
  -json \
  -silent \
  -nc \
  -t 50 \                    # Threads
  -timeout 10 \
  -retries 2 \
  -rl 150 \                  # Rate limit
  -fr \                      # Follow redirects
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
  -tls-probe \               # TLS info
  -tls-grab \                # TLS certificate
  -favicon \                 # Favicon hash
  -jarm \                    # JARM fingerprint
  -hash sha256 \             # Body hash
  -irr \                     # Include response (headers + body)
  -irh \                     # Include headers only
  -asn \                     # ASN info
  -cdn                       # CDN detection
```

---

## Output Data Structure

### Complete JSON Schema

```json
{
  "httpx": {
    "scan_metadata": {
      "scan_timestamp": "2024-01-15T12:00:00.000000",
      "scan_duration_seconds": 120.5,
      "docker_image": "projectdiscovery/httpx:latest",
      "threads": 50,
      "timeout": 10,
      "rate_limit": 150,
      "follow_redirects": true,
      "tech_detection": true,
      "tls_probing": true,
      "response_included": true,
      "proxy_used": false,
      "total_urls_probed": 150
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
        "technologies": ["nginx", "PHP", "WordPress"],
        "ip": "93.184.216.34",
        "cname": null,
        "cdn": null,
        "is_cdn": false,
        "asn": {
          "as_number": "AS15133",
          "as_name": "Edgecast Inc.",
          "as_country": "US"
        },
        "tls": {
          "version": "TLS 1.3",
          "cipher": "TLS_AES_256_GCM_SHA384",
          "certificate": {
            "subject_cn": "example.com",
            "issuer": "Let's Encrypt Authority X3",
            "not_before": "2024-01-01T00:00:00Z",
            "not_after": "2024-04-01T00:00:00Z",
            "san": ["example.com", "www.example.com"]
          }
        },
        "favicon_hash": "116323821",
        "jarm": "29d29d15d29d29d00029d29d29d29d...",
        "body_hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "headers": {
          "Content-Type": "text/html; charset=UTF-8",
          "X-Powered-By": "PHP/7.4.3"
        },
        "body": "<!DOCTYPE html>..."
      }
    },
    
    "by_host": {
      "example.com": {
        "hostname": "example.com",
        "urls": ["http://example.com", "https://example.com"],
        "live_urls": ["https://example.com"],
        "technologies": ["nginx", "PHP", "WordPress"],
        "servers": ["nginx/1.18.0"],
        "status_codes": [200, 301]
      }
    },
    
    "technologies_found": {
      "nginx": ["https://example.com", "https://api.example.com"],
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
      "unique_technologies": ["nginx", "PHP", "WordPress", "React"],
      "technology_count": 4,
      "unique_servers": ["nginx/1.18.0", "Apache/2.4.41"],
      "server_count": 2,
      "cdn_hosts": 3
    }
  }
}
```

---

## Usage Examples

### Basic Usage (via main.py)

```python
# Include "http_probe" in SCAN_MODULES in project settings
SCAN_MODULES = ["initial_recon", "naabu", "httpx", "nuclei"]

# Run the full pipeline
python3 recon/main.py
```

### Standalone Enrichment

```python
from httpx_scan import enrich_recon_file
from pathlib import Path

enriched = enrich_recon_file(Path("output/recon_example.com.json"))
```

### Command Line

```bash
# Enrich an existing recon file
python3 recon/httpx_scan.py output/recon_example.com.json
```

### Configuration Profiles

**Quick Probe (Fast):**
```python
HTTPX_THREADS = 100
HTTPX_RATE_LIMIT = 300
HTTPX_TIMEOUT = 5
HTTPX_PROBE_TECH_DETECT = True
HTTPX_INCLUDE_RESPONSE = False  # Smaller output
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
USE_TOR_FOR_RECON = True
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

#### "Docker not found"

```bash
# Install Docker
sudo apt install docker.io

# Start Docker daemon
sudo systemctl start docker
```

#### "No live URLs found"

Possible causes:
1. Hosts are down
2. Firewall blocking requests
3. Wrong ports probed

Solutions:
```python
# Increase timeout
HTTPX_TIMEOUT = 20

# Increase retries
HTTPX_RETRIES = 3

# Try without Naabu (probe default ports)
SCAN_MODULES = ["initial_recon", "httpx"]
```

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
# Disable response body inclusion
HTTPX_INCLUDE_RESPONSE = False
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
| Rate limiting/bans | Reduce `HTTPX_RATE_LIMIT` |
| WAF blocking | Use custom User-Agent, reduce rate |
| Detection | Use Tor, reduce threads |
| Fingerprinting | Your requests are identifiable |

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
| Python 3.8+ | Script runtime |

---

## References

- [httpx Documentation](https://github.com/projectdiscovery/httpx)
- [httpx Docker Hub](https://hub.docker.com/r/projectdiscovery/httpx)
- [Wappalyzer](https://www.wappalyzer.com/) - Technology detection rules
- [JARM Fingerprinting](https://github.com/salesforce/jarm)
- [ProjectDiscovery Blog](https://blog.projectdiscovery.io/)

---

*Documentation generated for RedAmon v1.0 - httpx HTTP Prober Module*

