# RedAmon

**Unmask the hidden before the world does.**

An automated OSINT reconnaissance and vulnerability scanning framework combining multiple security tools for comprehensive target assessment.

---

## 🎯 Quick Start

```bash
# 1. Install requirements
pip install -r requirements.txt
sudo apt install tor proxychains4  # Optional: for anonymous scanning

# 2. Configure target in params.py
TARGET_DOMAIN = "example.com"    # Root domain to scan
SUBDOMAIN_LIST = []              # Empty = discover all subdomains
# OR filter specific subdomains:
SUBDOMAIN_LIST = ["www.", "api."]  # Only scan www.example.com and api.example.com

# 3. Run the scan
python recon/main.py
```

---

## 🔄 Scanning Pipeline Overview

RedAmon executes scans in a modular pipeline. Each module adds data to a single JSON output file.

```
┌───────────────────────────────────────────────────────────────────────────────────────┐
│                              RedAmon Scanning Pipeline                                │
├───────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                       │
│  ┌────────────┐   ┌────────────┐   ┌────────────┐   ┌────────────────────────────┐   │
│  │  domain_   │──►│ port_scan  │──►│ http_probe │──►│        vuln_scan           │   │
│  │  discovery │   │            │   │            │   │  ┌──────────┬───────────┐  │   │
│  │  • WHOIS   │   │ • Port scan│   │ • HTTP     │   │  │ • Web    │ • CWE     │  │   │
│  │  • DNS     │   │ • CDN      │   │ • Tech     │   │  │   vulns  │   weakness│  │   │
│  │  • Subs    │   │ • Services │   │ • TLS/SSL  │   │  │ • CVEs   │ • CAPEC   │  │   │
│  └────────────┘   └────────────┘   └────────────┘   │  └──────────┴───────────┘  │   │
│        │                │                │          └────────────────────────────┘   │
│        └────────────────┴────────────────┴───────────────────────│                   │
│                                          │                                            │
│                                          ▼                                            │
│                       📄 recon/output/recon_<domain>.json                             │
│                                                                                       │
│  Optional: ┌───────────┐                                                              │
│            │  github   │ ──► github_secrets_<org>.json                                │
│            │  • Secrets│                                                              │
│            │  • Leaks  │                                                              │
│            └───────────┘                                                              │
└───────────────────────────────────────────────────────────────────────────────────────┘
```

> **Note:** `vuln_scan` automatically includes MITRE CWE/CAPEC enrichment for all discovered CVEs.

---

## 📋 Scan Modules Explained

### Configure Which Modules to Run

Edit `params.py`:

```python
# Run all modules (recommended for full assessment)
SCAN_MODULES = ["domain_discovery", "port_scan", "http_probe", "vuln_scan", "github"]

# Quick recon only (no vulnerability scanning)
SCAN_MODULES = ["domain_discovery"]

# Port scan + HTTP probing (skip vulnerability scanning)
SCAN_MODULES = ["domain_discovery", "port_scan", "http_probe"]

# Full scan (default) - vuln_scan includes MITRE CWE/CAPEC enrichment
SCAN_MODULES = ["domain_discovery", "port_scan", "http_probe", "vuln_scan"]
```

> **Note:** `vuln_scan` automatically includes MITRE CWE/CAPEC enrichment for all CVEs found.
> Configure MITRE settings (CWE, CAPEC) in the "MITRE CWE/CAPEC Enrichment" section of `params.py`.

---

### Module 1: `domain_discovery` - Domain Intelligence

**Purpose:** Gather information about the target domain and discover attack surface.

| What It Does | Output |
|--------------|--------|
| **WHOIS lookup** | Registrar, creation date, owner info |
| **Subdomain discovery** | Finds subdomains via passive sources (or uses filtered list) |
| **DNS enumeration** | A, AAAA, MX, NS, TXT, CNAME records |
| **IP resolution** | Maps all discovered hostnames to IPs |

**Key Parameters:**
```python
# Target Configuration
TARGET_DOMAIN = "example.com"           # Root domain (always specify the root)
SUBDOMAIN_LIST = []                     # Empty = discover ALL subdomains

# OR filter specific subdomains (skip discovery, scan only these):
SUBDOMAIN_LIST = ["www.", "api.", "dev."]  # Only scan www/api/dev.example.com

# Scan Options
USE_TOR_FOR_RECON = False               # Use Tor for anonymity
USE_BRUTEFORCE_FOR_SUBDOMAINS = False   # Brute force subdomain discovery
```

**Scan Modes:**

| SUBDOMAIN_LIST | Mode | Description |
|----------------|------|-------------|
| `[]` (empty) | Full Discovery | Discovers all subdomains using passive sources |
| `["www.", "api."]` | Filtered Scan | Skips discovery, only scans specified subdomains |

---

### Module 2: `port_scan` - Fast Port Scanning

**Purpose:** Discover open ports on discovered hosts using ProjectDiscovery's Naabu.

| What It Finds | Examples |
|---------------|----------|
| **Open ports** | 22/SSH, 80/HTTP, 443/HTTPS, 3306/MySQL |
| **CDN detection** | Cloudflare, Akamai, Fastly |
| **Service hints** | Common service identification |

**Execution:** Runs via Docker (`projectdiscovery/naabu:latest`) - no local installation needed.

**Key Parameters:**
```python
NAABU_TOP_PORTS = "1000"               # Number of top ports to scan
NAABU_RATE_LIMIT = 1000                # Packets per second
NAABU_SCAN_TYPE = "s"                  # SYN scan (requires root)
NAABU_SERVICE_DETECTION = True         # Identify services
NAABU_EXCLUDE_CDN = True               # Skip CDN-protected ports
```

📖 **Detailed documentation:** [readmes/README.PORT_SCAN.md](readmes/README.PORT_SCAN.md)

---

### Module 3: `http_probe` - HTTP Probing & Technology Detection + Wappalyzer Enhancement

**Purpose:** Probe HTTP/HTTPS services and detect technologies, server info, and TLS details. Enhanced with Wappalyzer for comprehensive technology detection.

| What It Finds | Examples |
|---------------|----------|
| **Live URLs** | Which endpoints are responding |
| **Technologies** | WordPress, nginx, PHP, React |
| **CMS Plugins** | Yoast SEO, WooCommerce, Contact Form 7 (via Wappalyzer) |
| **Analytics Tools** | Google Analytics, Facebook Pixel, Hotjar (via Wappalyzer) |
| **Security Tools** | Cloudflare, Sucuri, reCAPTCHA (via Wappalyzer) |
| **Server info** | Apache 2.4.41, nginx 1.18 |
| **TLS certificates** | Issuer, expiry, SANs |
| **CDN/ASN** | Cloudflare, AWS, network info |
| **Response data** | Status codes, headers, body hash |

**Execution:** Runs via Docker (`projectdiscovery/httpx:latest`). Wappalyzer enhancement uses existing HTML (no extra HTTP requests).

**Key Parameters:**
```python
HTTPX_THREADS = 50                     # Concurrent threads
HTTPX_PROBE_TECH_DETECT = True         # Technology detection (httpx built-in)
HTTPX_PROBE_TLS_INFO = True            # TLS certificate info
HTTPX_INCLUDE_RESPONSE = True          # Include response body (required for Wappalyzer)
WAPPALYZER_ENABLED = True              # Enable Wappalyzer enhancement
WAPPALYZER_MIN_CONFIDENCE = 50         # Minimum confidence level
```

**Wappalyzer Enhancement:**
- Uses existing HTML from httpx (no additional HTTP requests)
- Detects 1000+ technologies vs httpx's ~50-100 patterns
- Finds CMS plugins, analytics tools, security tools, frameworks
- Provides version detection and category classification
- Automatically merges new technologies into httpx results

📖 **Detailed documentation:** [readmes/README.HTTP_PROBE.md](readmes/README.HTTP_PROBE.md)

---

### Module 4: `vuln_scan` - Web Application Vulnerability Scanning + MITRE Enrichment

**Purpose:** Deep web application security testing with thousands of vulnerability templates. Automatically enriches discovered CVEs with MITRE CWE weaknesses and CAPEC attack patterns.

| What It Finds | Examples |
|---------------|----------|
| **Web CVEs** | Log4Shell, Spring4Shell, Drupalgeddon |
| **Injection flaws** | SQL injection, XSS, Command injection |
| **Misconfigurations** | Exposed admin panels, debug endpoints |
| **Information leaks** | .git exposure, backup files, API keys |
| **Default credentials** | Admin:admin, test accounts |
| **CWE Weaknesses** | Nested hierarchy from broad to specific weakness type |
| **CAPEC Attack Patterns** | Detailed attack patterns with severity, execution flow |

**Execution:** Runs via Docker (`projectdiscovery/nuclei:latest`) with Katana crawler for DAST. MITRE enrichment runs automatically after vulnerability scanning.

**Key Parameters:**
```python
# Vulnerability Scanning
NUCLEI_SEVERITY = ["critical", "high", "medium", "low"]  # What to report
NUCLEI_DAST_MODE = True                  # Active fuzzing (XSS, SQLi testing)
NUCLEI_RATE_LIMIT = 100                  # Requests per second
NUCLEI_AUTO_UPDATE_TEMPLATES = True      # Update 9000+ templates

# MITRE CWE/CAPEC Enrichment (automatically included)
MITRE_AUTO_UPDATE_DB = True              # Auto-download CVE2CAPEC database
MITRE_INCLUDE_CWE = True                 # Include CWE weakness mappings
MITRE_INCLUDE_CAPEC = True               # Include CAPEC attack patterns
```

📖 **Detailed documentation:** [readmes/README.VULN_SCAN.md](readmes/README.VULN_SCAN.md) | [readmes/README.MITRE.md](readmes/README.MITRE.md)

---

### Module 5: `github` - Secret Hunting

**Purpose:** Find leaked credentials, API keys, and secrets in GitHub repositories.

| What It Finds | Examples |
|---------------|----------|
| **API keys** | AWS, Google Cloud, Stripe, Twilio |
| **Credentials** | Passwords, tokens, private keys |
| **Database strings** | Connection strings with passwords |
| **Private keys** | SSH keys, SSL certificates |

**Key Parameters:**
```python
GITHUB_ACCESS_TOKEN = "ghp_xxxxx"        # Required - set in .env file
GITHUB_TARGET_ORG = "company-name"       # Organization or username
GITHUB_SCAN_COMMITS = True               # Search git history
GITHUB_MAX_COMMITS = 100                 # Commits per repo
```

---

## 🆚 Complete Tool Comparison

Understanding what each tool does is crucial for effective reconnaissance. RedAmon uses 6 different tools in its pipeline.

### 📊 Overview: All Tools at a Glance

| Tool | Primary Purpose | Layer | Speed | Output |
|------|-----------------|-------|-------|--------|
| **WHOIS** | Domain ownership & registration | DNS/Registry | ⚡ Instant | Registrar, dates, contacts |
| **DNS** | Domain resolution & records | Layer 3 (Network) | ⚡ Instant | IPs, MX, TXT, CNAME records |
| **Naabu** | Port discovery | Layer 4 (Transport) | ⚡ Very Fast | Open ports, protocols |
| **httpx** | HTTP probing & tech detection | Layer 7 (Application) | ⚡ Fast | Live URLs, technologies, TLS |
| **Nuclei** | Vulnerability scanning | Layer 7 (Application) | 🔄 Medium | CVEs, misconfigs, vulns |
| **MITRE CWE/CAPEC** | Weakness & attack pattern enrichment | Data Enrichment | ⚡ Fast | CWE weaknesses, CAPEC patterns |
| **GVM/OpenVAS** | Deep vulnerability assessment | All Layers | 🐢 Slow | Full security audit |

---

### 🔍 WHOIS - Domain Intelligence

| What It Does | What It Finds |
|--------------|---------------|
| Queries domain registries | **Registrar**: Who registered the domain |
| Retrieves registration data | **Dates**: Created, expires, last updated |
| Identifies ownership | **Name Servers**: DNS infrastructure |
| Discovers related domains | **Contacts**: Admin, tech contacts (often redacted) |

**Example Output:**
```
Domain: vulnweb.com
Registrar: Gandi SAS
Created: 2010-06-14
Expires: 2027-06-14
Organization: Invicti Security Limited
```

**Speed:** ⚡ <1 second | **Requires:** Nothing (Python library)

---

### 🌐 DNS - Domain Resolution

| What It Does | What It Finds |
|--------------|---------------|
| Resolves hostnames to IPs | **A/AAAA Records**: IPv4/IPv6 addresses |
| Discovers subdomains | **MX Records**: Mail servers |
| Maps infrastructure | **TXT Records**: SPF, DKIM, verification |
| Finds related services | **CNAME Records**: Aliases, CDN endpoints |

**Example Output:**
```
testphp.vulnweb.com → 44.228.249.3 (A record)
                    → "google-site-verification:xxx" (TXT record)
```

**Speed:** ⚡ <1 second per domain | **Requires:** Nothing (Python library)

---

### 🚀 Naabu - Port Scanner

| What It Does | What It Finds |
|--------------|---------------|
| Scans TCP/UDP ports | **Open Ports**: Which ports accept connections |
| Identifies services | **Protocols**: TCP/UDP |
| Detects CDN/Cloud | **CDN Detection**: Cloudflare, AWS, etc. |
| Fast SYN scanning | **Service Hints**: Port-based service guessing |

**Detection Capabilities:**

| Capability | Status | Details |
|------------|--------|---------|
| Open Ports | ✅ Primary | SYN/CONNECT scan, top-N or custom ports |
| CDN Detection | ✅ Yes | Identifies CDN-protected IPs |
| Service Names | ⚠️ Basic | Port-based mapping only (80→http) |
| Service Versions | ❌ No | Cannot detect actual versions |
| Banner Grabbing | ❌ No | Does not connect to services |

**Speed:** ⚡ ~5-10 seconds for 1000 ports | **Requires:** Docker, root (for SYN scan)

---

### 🔬 httpx - HTTP Prober & Tech Detector + Wappalyzer Enhancement

| What It Does | What It Finds |
|--------------|---------------|
| Probes HTTP/HTTPS endpoints | **Live URLs**: Which URLs respond |
| Detects web technologies | **Technologies**: PHP, WordPress, nginx, React |
| **Wappalyzer Enhancement** | **CMS Plugins**: Yoast SEO, WooCommerce, Contact Form 7 |
| **Wappalyzer Enhancement** | **Analytics**: Google Analytics, Facebook Pixel, Hotjar |
| **Wappalyzer Enhancement** | **Security Tools**: Cloudflare, Sucuri, reCAPTCHA |
| Extracts SSL/TLS info | **Certificates**: Issuer, expiry, SANs |
| Fingerprints servers | **Server Headers**: nginx, Apache, IIS |
| Captures response data | **Hashes**: Favicon, body, JARM fingerprint |

**Detection Capabilities:**

| Capability | Status | Details |
|------------|--------|---------|
| Live URL Discovery | ✅ Primary | HTTP status codes, response validation |
| Technology Detection (httpx) | ✅ Excellent | Wappalyzer-like fingerprinting (~50-100 patterns) |
| **Technology Detection (Wappalyzer)** | ✅ **Enhanced** | **1000+ technology patterns, CMS plugins, analytics** |
| **CMS Plugin Detection** | ✅ **NEW** | **WordPress/Drupal/Joomla plugins via Wappalyzer** |
| **Version Detection** | ✅ **Enhanced** | **Software versions with confidence scores** |
| TLS/SSL Analysis | ✅ Excellent | Cert chain, cipher suites, versions |
| CDN Detection | ✅ Yes | Via headers and IP analysis |
| Server Fingerprint | ✅ Yes | Server header, JARM, favicon hash |
| Response Capture | ✅ Yes | Headers, body, word/line count |
| Vulnerability Scanning | ❌ No | Detection only, no exploitation |

**Speed:** ⚡ ~10-30 seconds per URL (with all options) + ~1-2 seconds per URL for Wappalyzer | **Requires:** Docker, `python-Wappalyzer` library

---

### 🎯 Nuclei - Vulnerability Scanner + CVE Lookup

| What It Does | What It Finds |
|--------------|---------------|
| Template-based scanning | **CVEs**: Known vulnerabilities |
| Active vulnerability testing | **Misconfigurations**: Exposed panels, default creds |
| DAST fuzzing | **Injection Flaws**: XSS, SQLi, SSTI |
| Exposure detection | **Information Disclosure**: Backup files, debug info |
| Technology-specific checks | **CMS Vulns**: WordPress, Joomla, Drupal |
| **CVE Lookup** | **Version-based CVEs**: Like Nmap's vulners script |

**Detection Capabilities:**

| Capability | Status | Details |
|------------|--------|---------|
| CVE Detection | ✅ Excellent | 8000+ templates, constantly updated |
| **CVE Lookup** | ✅ **NEW** | Queries NVD for technology CVEs (nginx, PHP, etc.) |
| Misconfiguration | ✅ Excellent | Default passwords, exposed endpoints |
| XSS Testing | ✅ DAST Mode | Active payload injection |
| SQL Injection | ✅ DAST Mode | Active fuzzing with payloads |
| SSRF/SSTI | ✅ DAST Mode | Server-side vulnerability testing |
| Information Disclosure | ✅ Yes | Sensitive files, backup exposure |
| Authentication Issues | ✅ Yes | Default creds, auth bypass |
| Port Scanning | ❌ No | Uses pre-discovered URLs |

**CVE Lookup Example (like Nmap's vulners):**
```
Technologies detected: Nginx:1.19.0, PHP:5.6.40
CVEs found: 23 (2 CRITICAL, 10 HIGH)
  - CVE-2017-8923 (CVSS 9.8) - PHP buffer overflow
  - CVE-2021-23017 (CVSS 7.7) - nginx resolver
  - CVE-2022-41741 (CVSS 7.0) - nginx mp4 module
```

**Speed:** 🔄 ~1-30 minutes depending on templates | **Requires:** Docker

---

### 🛡️ GVM/OpenVAS - Deep Vulnerability Assessment

| What It Does | What It Finds |
|--------------|---------------|
| Full network vulnerability scan | **Network Vulns**: Service-level vulnerabilities |
| CVE-based detection | **Missing Patches**: Outdated software |
| Compliance checking | **Security Issues**: Weak configs, protocols |
| Comprehensive audit | **All Services**: Not just web (SSH, FTP, DB) |

**Detection Capabilities:**

| Capability | Status | Details |
|------------|--------|---------|
| CVE Detection | ✅ Excellent | 100,000+ NVTs (vulnerability tests) |
| Service Vulnerabilities | ✅ Primary | SSH, FTP, SMTP, databases, etc. |
| SSL/TLS Issues | ✅ Excellent | Weak ciphers, expired certs |
| Network Misconfig | ✅ Yes | Open services, weak protocols |
| Web Vulnerabilities | ✅ Good | Basic web testing included |
| Compliance Checks | ✅ Yes | PCI-DSS, CIS benchmarks |
| False Positive Rate | ⚠️ Higher | Requires manual verification |

**Speed:** 🐢 30 minutes - 2+ hours | **Requires:** GVM installation (complex setup)

---

### 📈 Detailed Feature Matrix

| Feature | WHOIS | DNS | Naabu | httpx | Nuclei | GVM |
|---------|-------|-----|-------|-------|--------|-----|
| **Domain Info** | ✅ | ⚠️ | ❌ | ❌ | ❌ | ❌ |
| **IP Resolution** | ❌ | ✅ | ⚠️ | ✅ | ❌ | ❌ |
| **Subdomain Discovery** | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Port Scanning** | ❌ | ❌ | ✅ | ❌ | ❌ | ✅ |
| **Service Detection** | ❌ | ❌ | ⚠️ | ✅ | ⚠️ | ✅ |
| **Live URL Check** | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ |
| **Technology Detection** | ❌ | ❌ | ❌ | ✅ **+ Wappalyzer** | ⚠️ | ⚠️ |
| **CMS Plugin Detection** | ❌ | ❌ | ❌ | ✅ **Wappalyzer** | ❌ | ❌ |
| **TLS/SSL Analysis** | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ |
| **CDN Detection** | ❌ | ⚠️ | ✅ | ✅ | ❌ | ❌ |
| **CVE Detection** | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ |
| **CVE Lookup (version)** | ❌ | ❌ | ❌ | ❌ | ✅ **NEW** | ❌ |
| **Web Vuln Scanning** | ❌ | ❌ | ❌ | ❌ | ✅ | ⚠️ |
| **XSS/SQLi Testing** | ❌ | ❌ | ❌ | ❌ | ✅ | ⚠️ |
| **Network Vuln Scan** | ❌ | ❌ | ❌ | ❌ | ⚠️ | ✅ |
| **Compliance Check** | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |

**Legend:** ✅ Primary/Excellent | ⚠️ Limited/Basic | ❌ Not supported

> **CVE Lookup (version)**: Queries NVD for CVEs based on detected technology versions (like Nmap's vulners script). Example: Nginx 1.19.0 → finds CVE-2021-23017, CVE-2022-41741, etc.

---

### 🔄 Pipeline Flow & Why This Order

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         REDAMON RECONNAISSANCE PIPELINE                          │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  📋 WHOIS        → Domain ownership, registrar, expiration dates                │
│       │                                                                         │
│       ▼                                                                         │
│  🌐 DNS          → Resolve hostnames to IPs, find subdomains                    │
│       │                                                                         │
│       ▼                                                                         │
│  🚀 Naabu        → Fast port scan to find open services                         │
│       │              (Feeds port info to httpx)                                 │
│       ▼                                                                         │
│  🔬 httpx        → Probe HTTP services, detect technologies                     │
│       │              (Feeds live URLs + tech versions to Nuclei)                │
│       ▼                                                                         │
│  🎯 Nuclei       → Scan for vulnerabilities on live URLs                        │
│       │              + CVE Lookup for detected technologies                     │
│       │              (nginx, PHP, jQuery → query NVD for CVEs)                  │
│       ▼                                                                         │
│  🔗 MITRE CWE/CAPEC → Enrich CVEs with weakness & attack patterns               │
│       │              (CVE → CWE hierarchy → CAPEC direct mappings)               │
│       ▼                                                                         │
│  🛡️ GVM (opt)    → Deep vulnerability assessment (if needed)                    │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 🎯 When to Use Each Tool

| Scenario | Use These Tools |
|----------|-----------------|
| **Quick recon** | WHOIS + DNS + Naabu + httpx |
| **Full web assessment** | All above + Nuclei |
| **Compliance audit** | All above + GVM |
| **Bug bounty** | DNS + Naabu + httpx + Nuclei (DAST) |
| **Penetration test** | Full pipeline + manual testing |
| **Asset discovery** | WHOIS + DNS + Naabu |

### ⏱️ Time Comparison (Single Target)

| Tool | Typical Duration | Notes |
|------|------------------|-------|
| WHOIS | <1 second | Instant |
| DNS | <1 second | Instant |
| Naabu | 5-10 seconds | 1000 ports |
| httpx | 10-30 seconds | All options enabled |
| Nuclei | 1-30 minutes | Depends on templates |
| GVM | 30 min - 2+ hours | Full scan |

**Total Quick Scan (WHOIS→Nuclei):** ~2-5 minutes
**Total Full Scan (with GVM):** 30 min - 2+ hours

---

## ⚙️ Key Configuration Parameters

### `params.py` - Essential Settings

```python
# ═══════════════════════════════════════════════════════════════════
# TARGET & MODULES
# ═══════════════════════════════════════════════════════════════════
TARGET_DOMAIN = "example.com"         # Always the root domain
SUBDOMAIN_LIST = []                   # Empty = discover all, ["www.", "api."] = filtered
SCAN_MODULES = ["domain_discovery", "port_scan", "http_probe", "vuln_scan"]

# ═══════════════════════════════════════════════════════════════════
# ANONYMITY (Optional)
# ═══════════════════════════════════════════════════════════════════
USE_TOR_FOR_RECON = False       # Route traffic through Tor

# ═══════════════════════════════════════════════════════════════════
# PORT SCAN - Port Scanning
# ═══════════════════════════════════════════════════════════════════
NAABU_TOP_PORTS = "1000"        # Top ports to scan
NAABU_RATE_LIMIT = 1000         # Packets per second
NAABU_SCAN_TYPE = "s"           # SYN scan (requires root)

# ═══════════════════════════════════════════════════════════════════
# HTTP PROBE - HTTP Probing
# ═══════════════════════════════════════════════════════════════════
HTTPX_THREADS = 50              # Concurrent threads
HTTPX_PROBE_TECH_DETECT = True  # Technology detection
HTTPX_PROBE_TLS_INFO = True     # TLS certificate info

# ═══════════════════════════════════════════════════════════════════
# VULN SCAN - Vulnerability Scanning
# ═══════════════════════════════════════════════════════════════════
NUCLEI_DAST_MODE = True         # Active fuzzing for XSS, SQLi
NUCLEI_SEVERITY = ["critical", "high", "medium", "low"]
NUCLEI_RATE_LIMIT = 100         # Requests per second
NUCLEI_AUTO_UPDATE_TEMPLATES = True  # Get latest templates

# ═══════════════════════════════════════════════════════════════════
# MITRE CWE/CAPEC - Weakness & Attack Pattern Enrichment
# ═══════════════════════════════════════════════════════════════════
MITRE_AUTO_UPDATE_DB = True     # Auto-download CVE2CAPEC database
MITRE_INCLUDE_CWE = True        # Include CWE weakness mappings
MITRE_INCLUDE_CAPEC = True      # Include CAPEC attack patterns

# ═══════════════════════════════════════════════════════════════════
# GITHUB - Secret Hunting
# ═══════════════════════════════════════════════════════════════════
GITHUB_ACCESS_TOKEN = ""        # Set in .env file!
GITHUB_TARGET_ORG = "company"   # Organization/username to scan
```

---

## 🔧 Prerequisites

### Required
- **Python 3.8+**
- **Docker** (for Naabu, httpx, Nuclei, and optionally GVM)

### Optional
```bash
# For anonymous scanning
sudo apt install tor proxychains4
sudo systemctl start tor
```

### Docker Images (auto-pulled on first run)
```bash
# ProjectDiscovery tools
docker pull projectdiscovery/naabu:latest
docker pull projectdiscovery/httpx:latest
docker pull projectdiscovery/nuclei:latest
docker pull projectdiscovery/katana:latest  # For DAST crawling
```

---

## 📁 Project Structure

```
RedAmon/
├── params.py              # 🎛️  Global configuration (edit this!)
├── requirements.txt       # Python dependencies
├── .env                   # Secrets (GITHUB_TOKEN, GVM_PASSWORD)
│
├── recon/                 # Reconnaissance & scanning modules
│   ├── main.py            # 🚀 Entry point - run this!
│   ├── domain_recon.py    # Subdomain discovery
│   ├── whois_recon.py     # WHOIS lookup
│   ├── port_scan.py       # Port scanning
│   ├── http_probe.py      # HTTP probing
│   ├── vuln_scan.py       # Vulnerability scanning
│   ├── add_mitre.py       # MITRE CWE/CAPEC enrichment (called by vuln_scan)
│   ├── github_secret_hunt.py  # GitHub secret hunting
│   ├── output/            # 📄 Scan results (JSON)
│   └── data/
│       └── mitre_db/      # 📦 Cached CVE2CAPEC database
│           ├── resources/ # CWE, CAPEC mappings
│           └── database/  # CVE-year.jsonl files
│
├── readmes/               # 📖 Detailed documentation
│   ├── README.PORT_SCAN.md    # Port scan configuration guide
│   ├── README.HTTP_PROBE.md   # HTTP probe configuration guide
│   ├── README.VULN_SCAN.md    # Vulnerability scan configuration guide
│   ├── README.MITRE.md        # MITRE CWE/CAPEC enrichment guide
│   └── README.GVM.md          # GVM/OpenVAS setup guide
│
├── gvm_scan/              # GVM/OpenVAS integration
│   ├── docker-compose.yml # GVM container orchestration
│   ├── Dockerfile         # Python scanner image
│   ├── main.py            # GVM scan entry point
│   └── output/            # GVM results
```

---

## 📊 Output Format

All modules write to a single JSON file: `recon/output/recon_<domain>.json`

```json
{
  "metadata": {
    "target": "example.com",
    "scan_timestamp": "2024-01-15T10:30:00",
    "modules_executed": ["whois", "subdomain_discovery", "port_scan", "http_probe", "vuln_scan"],
    "mitre_enrichment": {
      "total_cves_processed": 23,
      "total_cves_enriched": 23
    }
  },
  "whois": {
    "registrar": "GoDaddy",
    "creation_date": "2010-01-01"
  },
  "subdomains": ["www.example.com", "api.example.com", "admin.example.com"],
  "dns": {
    "A": ["93.184.216.34"],
    "MX": ["mail.example.com"]
  },
  "port_scan": {
    "by_host": {
      "example.com": {
        "ports": [80, 443, 8080],
        "is_cdn": false
      }
    },
    "summary": {
      "total_open_ports": 15,
      "hosts_with_open_ports": 3
    }
  },
  "http_probe": {
    "by_url": {
      "https://example.com": {
        "status_code": 200,
        "technologies": ["nginx", "PHP", "WordPress"],
        "server": "nginx/1.18.0"
      }
    },
    "summary": {
      "live_urls": 12,
      "technology_count": 8
    }
  },
  "vuln_scan": {
    "vulnerabilities": {
      "critical": [],
      "high": [{"template": "cve-2021-44228", "name": "Log4Shell"}]
    },
    "summary": {
      "total_findings": 25,
      "critical": 0,
      "high": 1
    }
  },
  "technology_cves": {
    "by_technology": {
      "Log4j:2.14.1": {
        "technology": "Log4j:2.14.1",
        "product": "log4j",
        "version": "2.14.1",
        "cve_count": 1,
        "critical": 1,
        "high": 0,
        "cves": [
          {
            "id": "CVE-2021-44228",
            "cvss": 10.0,
            "severity": "CRITICAL",
            "mitre_attack": {
              "enriched": true,
              "cwe_hierarchy": {
                "id": "CWE-502",
                "name": "Deserialization of Untrusted Data",
                "abstraction": "Base",
                "mapping": "ALLOWED",
                "description": "The product deserializes untrusted data...",
                "consequences": [{"scope": ["Integrity"], "impact": ["Execute Unauthorized Code"]}],
                "mitigations": [{"description": "If available, use signing/sealing features...", "phase": ["Architecture and Design"]}],
                "related_capec": [
                  {
                    "id": "CAPEC-586",
                    "name": "Object Injection",
                    "severity": "High"
                  }
                ]
              }
            }
          }
        ]
      }
    },
    "summary": {
      "total_unique_cves": 1,
      "critical": 1,
      "high": 0
    }
  }
}
```

---

## 🛡️ GVM/OpenVAS - Enterprise Vulnerability Scanning

**GVM (Greenbone Vulnerability Management)** is an open-source vulnerability scanner for comprehensive enterprise security assessment.

📖 **Detailed documentation:** [readmes/README.GVM.md](readmes/README.GVM.md)

---

## 🧪 Test Targets

Safe, **legal** targets specifically designed for security testing. No authorization needed.

### Acunetix Vulnweb (Recommended)

| Target | Technology | Vulnerabilities |
|--------|------------|-----------------|
| `testphp.vulnweb.com` | PHP + MySQL | SQL Injection, XSS, File Upload, LFI, CSRF |
| `testhtml5.vulnweb.com` | HTML5 + JavaScript | DOM XSS, Client-side attacks |
| `testasp.vulnweb.com` | ASP.NET + SQL Server | SQL Injection, XSS |

```python
# Example: Test with vulnweb
TARGET_DOMAIN = "testphp.vulnweb.com"
SCAN_MODULES = ["domain_discovery", "port_scan", "http_probe", "vuln_scan"]
NUCLEI_DAST_MODE = True  # Will find XSS, SQLi
```

### Other Legal Test Targets

| Target | Description |
|--------|-------------|
| `scanme.nmap.org` | Test target (port scanning only) |
| `demo.testfire.net` | IBM AppScan demo banking app |
| `juice-shop.herokuapp.com` | OWASP Juice Shop |

---

## ⚠️ Legal Disclaimer

**Only scan systems you own or have explicit written permission to test.**

Unauthorized scanning is illegal in most jurisdictions. RedAmon is intended for:
- Penetration testers with proper authorization
- Security researchers on approved targets
- Bug bounty hunters within program scope
- System administrators testing their own infrastructure

---

## 📖 Detailed Documentation

| Module | Documentation |
|--------|---------------|
| Port Scan | [readmes/README.PORT_SCAN.md](readmes/README.PORT_SCAN.md) |
| HTTP Probe | [readmes/README.HTTP_PROBE.md](readmes/README.HTTP_PROBE.md) |
| Vuln Scan | [readmes/README.VULN_SCAN.md](readmes/README.VULN_SCAN.md) |
| MITRE CWE/CAPEC | [readmes/README.MITRE.md](readmes/README.MITRE.md) |
| GVM/OpenVAS | [readmes/README.GVM.md](readmes/README.GVM.md) |
