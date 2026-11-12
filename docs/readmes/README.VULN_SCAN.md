# RedAmon - Nuclei Vulnerability Scanner

## Complete Technical Documentation

> **Module:** `recon/main_recon_modules/vuln_scan.py`  
> **Purpose:** Template-based web application vulnerability scanning using ProjectDiscovery's Nuclei  
> **Author:** RedAmon Security Suite

---

## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [CVE Lookup (Technology-Based)](#cve-lookup-technology-based)
4. [Requirements](#requirements)
5. [Configuration Parameters](#configuration-parameters)
6. [Architecture & Flow](#architecture--flow)
7. [Function Reference](#function-reference)
8. [Nuclei Arguments Explained](#nuclei-arguments-explained)
9. [Template Categories](#template-categories)
10. [Output Data Structure](#output-data-structure)
11. [Nmap vs Nuclei Comparison](#nmap-vs-nuclei-comparison)
12. [Usage Examples](#usage-examples)
13. [Troubleshooting](#troubleshooting)

---

## Overview

The `vuln_scan.py` module integrates ProjectDiscovery's Nuclei scanner into RedAmon's reconnaissance pipeline. Nuclei is a fast, template-based vulnerability scanner that excels at web application security testing. The same module also runs the technology-based CVE lookup and RedAmon's own security checks, which work without Nuclei.

**⚠️ Important:** Nuclei runs exclusively via Docker, as a sibling container the recon container starts with `docker run`. No native installation is supported.

### Why Nuclei?

| Feature | Nmap NSE | Nuclei |
|---------|----------|--------|
| Templates | Scripts shipped with nmap | **Thousands of community templates** |
| Update Frequency | With nmap releases | **Daily community updates** |
| Web App Depth | Surface-level | **Deep application testing** |
| CVE Coverage | Older CVEs | **Recent CVEs (within days)** |
| Focus | Network layer | **Application layer** |

### How It Works

```
┌──────────────────┐     ┌─────────────────────────┐     ┌──────────────────┐
│  Recon Data      │────▶│  vuln_scan.py           │────▶│  vuln_scan key   │
│  • DNS hosts/IPs │     │                         │     │  (findings, CVEs,│
│  • http_probe    │     │  1. Build target URLs   │     │   coverage,      │
│    live URLs     │     │  2. DETECTION pass      │     │   security_      │
│  • resource_enum │     │  3. DAST pass (opt.)    │     │   checks)        │
│    endpoints     │     │  4. Drop false positives│     │                  │
└──────────────────┘     │  5. Classify, aggregate │     │  technology_cves │
                         │  6. CVE lookup          │     │  (top level)     │
                         │  7. Security checks     │     └──────────────────┘
                         └─────────────────────────┘
```

### DAST Mode Pipeline

When `NUCLEI_DAST_MODE = True`, a second Nuclei pass fuzzes the parameterized URLs that resource enumeration (GROUP 5: Katana, GAU, Kiterunner and the other crawlers, see [README.RESOURCE_ENUM.md](README.RESOURCE_ENUM.md)) already found:

```
┌──────────────────────┐     ┌─────────────────────┐     ┌─────────────┐
│ resource_enum        │────▶│   NUCLEI DAST pass  │────▶│   Results   │
│ .discovered_urls     │     │                     │     │             │
│                      │     │  -dast, no tag or   │     │ • XSS       │
│ keeps URLs with      │     │  template filters   │     │ • SQLi      │
│ ?key=value only      │     │                     │     │ • SSTI      │
└──────────────────────┘     └─────────────────────┘     └─────────────┘
```

**Why DAST needs parameterized URLs:**
- Nuclei DAST templates inject payloads into URL parameters
- Without parameters (`?key=value`), DAST finds nothing
- `vuln_scan.py` does not crawl: with no such URL in `resource_enum`, the DAST pass is skipped and only the detection pass runs

---

## Features

| Feature | Description |
|---------|-------------|
| **Template Scanning** | CVEs, misconfigs, exposures, takeovers, default logins |
| **CVE Detection** | Automatic CVE ID and CVSS extraction |
| **Smart URL Building** | Union of httpx live URLs, resource_enum endpoints and not-yet-probed hostnames |
| **Two Passes** | A detection pass with your tags/templates, plus an optional DAST pass on parameterized URLs |
| **DAST Mode** | Active fuzzing for XSS, SQLi, SSTI, Command Injection |
| **Auto-Update Templates** | Template update (`-ut`) before each scan, into a persistent Docker volume |
| **Custom Templates** | Per-project selection of uploaded templates |
| **False-Positive Filter** | Drops a time-based or blind finding whose response the server throttled, and an injection finding whose response is a WAF block page (optionally AI-assisted) |
| **AI Tag Selection** | Optionally lets an LLM prune `NUCLEI_TAGS` to the detected tech stack |
| **Category Classification** | Auto-categorizes findings (XSS, SQLi, RCE, etc.) |
| **Authenticated Scanning** | The project's authenticated-session headers, when every scanned host is in scope |
| **Runtime Cap & Coverage** | Each pass stops at `NUCLEI_MAX_RUNTIME`; per-host coverage is recorded |
| **CVE Lookup** | Technology-based CVE lookup (like Nmap's vulners) |
| **Security Checks** | RedAmon's own checks for what Nuclei does not cover |

---

## CVE Lookup (Technology-Based)

The module includes an integrated CVE lookup that queries the NVD (National Vulnerability Database), or Vulners, for known vulnerabilities in the versioned technologies RedAmon detected. This replicates what Nmap's `vulners` script does. It runs after the Nuclei passes (and also when Nuclei is disabled or unavailable), whenever `CVE_LOOKUP_ENABLED` is on and `http_probe` data exists.

### How It Works

```
┌─────────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Versioned techs:   │────▶│  run_cve_lookup  │────▶│ technology_cves │
│  • httpx techs and  │     │                  │     │ in JSON output  │
│    Server headers   │     │  NVD (or Vulners)│     │                 │
│  • banner_grab      │     │  per product +   │     │ by_technology,  │
│  • nmap services    │     │  version         │     │ summary         │
└─────────────────────┘     └──────────────────┘     └─────────────────┘
```

Products without a version, and generic names (operating systems, CDNs, analytics tags), are skipped.

### Configuration

```python
# Project settings (runtime keys)

# Enable/disable technology-based CVE lookup
CVE_LOOKUP_ENABLED = True

# Data source: "nvd" (free, rate limited) or "vulners" (needs a Vulners API key)
CVE_LOOKUP_SOURCE = "nvd"

# Maximum CVEs to keep per technology
CVE_LOOKUP_MAX_CVES = 20

# Minimum CVSS score to include (0.0 = all, 4.0 = medium+, 7.0 = high+)
CVE_LOOKUP_MIN_CVSS = 0.0
```

The NVD and Vulners API keys are not project settings: they come from the user's account (Global Settings → Tool API Keys) as `NVD_API_KEY` / `VULNERS_API_KEY`, with key rotation.

### Supported Technologies

Product names are mapped to CPEs (Common Platform Enumeration) by the `CPE_MAPPINGS` table in `recon/helpers/cve_helpers.py`, which covers, for example:

| Category | Technologies |
|----------|--------------|
| **Web Servers** | nginx, Apache, IIS, Tomcat, Lighttpd, Caddy |
| **Languages** | PHP, Python, Node.js, Ruby, Perl |
| **Databases** | MySQL, MariaDB, PostgreSQL, MongoDB, Redis, Elasticsearch |
| **CMS/Frameworks** | WordPress, Drupal, Joomla, Django, Laravel, Spring |
| **JavaScript** | jQuery, Angular, React, Vue, Bootstrap |
| **Security** | OpenSSH, OpenSSL |
| **Other** | Varnish, HAProxy, Grafana, Jenkins, GitLab |

A name the table does not know is retried without the words nmap puts after a product and without a leading vendor word (`Exim smtpd`, `PostgreSQL DB`, `ISC BIND`), so it still reaches the exact CPE query when the shorter name is in the table.

A product outside the table is looked up by an NVD keyword search on its name alone, since a CVE's text gives a range ("before 1.13.0") rather than the version found. That only proves the name occurs somewhere in a CVE's text, so a hit is kept only when the CVE's NVD configuration lists that product (or, for a name that is the vendor, an edition of it such as `liferay_portal` for Liferay, but not a separate product such as `elementor_pro`) as vulnerable at a version inside its affected range. A CVE NVD has not analysed carries no configuration, and many are "Deferred" for good; it is kept only when its text names the product directly followed by the version (`mini_httpd 1.30`).

For an nmap service outside the table, the CPE nmap reported is also matched by NVD, under any vendor, against every CVE's configuration. This finds the CVEs whose text never names the product: Webmin's behind nmap's `MiniServ`, Zerologon for Samba.

Every lookup reads NVD's whole answer (up to 4,000 CVEs) and keeps the `CVE_LOOKUP_MAX_CVES` with the highest CVSS. NVD lists the oldest CVEs first, so reading only the first `CVE_LOOKUP_MAX_CVES` kept the oldest and dropped the newest, often the most severe.

httpx/Wappalyzer labels carry a version only after a colon (`Nginx:1.19.0`), so a label such as `HTTP/3` or `Microsoft 365` is a name with no version and is not looked up. Server headers, banners and nmap services keep the `Name/version` form.

### Example Output

For a host whose responses name nginx 1.19.0 and PHP 5.6.40:

```
============================================================
[*][CVE] Technology-Based Vulnerability Discovery
============================================================
[*][CVE] Source: NVD
[*][CVE] Min CVSS: 0.0

[*][CVE] Technologies with versions: 2
[*][CVE] [1/2] Nginx:1.19.0... ✓ 6 CVEs found
[*][CVE] [2/2] PHP:5.6.40... ✓ 17 CVEs found

[+][CVE] CVE LOOKUP SUMMARY:
[+][CVE] Total unique CVEs: 23
[!][CVE] CRITICAL: 2
[!][CVE] HIGH: 10
[*][CVE] MEDIUM: 10
============================================================
```

### JSON Output Structure

`run_cve_lookup()` writes `technology_cves` at the **top level** of the recon data (beside `vuln_scan`, not inside it):

```json
{
  "technology_cves": {
    "lookup_timestamp": "2025-12-31T14:30:00.000000",
    "source": "nvd",
    "technologies_checked": 2,
    "technologies_with_cves": 2,
    "by_technology": {
      "Nginx:1.19.0": {
        "technology": "Nginx:1.19.0",
        "product": "nginx",
        "version": "1.19.0",
        "cve_count": 6,
        "critical": 0,
        "high": 5,
        "cves": [
          {
            "id": "CVE-2021-23017",
            "cvss": 7.7,
            "severity": "HIGH",
            "description": "A security issue in nginx resolver...",
            "published": "2021-06-01T13:15:07.853",
            "references": ["..."],
            "source": "nvd",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-23017"
          }
        ]
      },
      "PHP:5.6.40": {
        "technology": "PHP:5.6.40",
        "product": "php",
        "version": "5.6.40",
        "cve_count": 17,
        "critical": 2,
        "high": 5,
        "cves": [...]
      }
    },
    "summary": {
      "total_unique_cves": 23,
      "critical": 2,
      "high": 10,
      "medium": 10,
      "low": 1
    }
  }
}
```

The graph writer (`update_graph_from_vuln_scan`) and MITRE enrichment (`recon/main_recon_modules/add_mitre.py`) read `technology_cves.by_technology`. The writer also reads `vuln_scan.all_cves`, which MITRE enrichment fills with CWE and CAPEC, to link each nuclei finding to the CVEs its template cites: `(v:Vulnerability)-[:INCLUDES_CVE]->(c:CVE)-[:HAS_CWE]->(m:MitreData)-[:HAS_CAPEC]->(cap:Capec)`. A finding's `INCLUDES_CVE` edges are exactly the CVEs it cites on the latest write: a CVE its template dropped loses the edge, even when none is left, while the shared CVE node and its chain stay. In the domain pipeline's GROUP 6 fan-out, `run_vuln_scan_isolated()` returns a `TopLevelKeys` holding `vuln_scan` and, when the CVE lookup ran, `technology_cves`, and the fan-out merges both.

### Nuclei Template CVEs vs Technology CVE Lookup

| Source | What It Detects | Type |
|--------|-----------------|------|
| **Nuclei Templates** | Specific CVEs with exploits/checks | **Confirmed exploitable** |
| **CVE Lookup** | All CVEs for detected version | **Potential vulnerabilities** |

**Example:**
- Nuclei template for CVE-2021-23017 → Checks if nginx resolver is vulnerable → Confirmed if matched
- CVE Lookup for nginx 1.19.0 → Lists CVE-2021-23017 → May or may not be exploitable (depends on config)

**Both are valuable:**
- Nuclei = "This IS vulnerable"
- CVE Lookup = "This COULD be vulnerable based on version"

### Rate Limiting

The NVD API has rate limits:
- **Without API key:** 5 requests per 30 seconds
- **With API key:** 50 requests per 30 seconds

`run_cve_lookup()` waits 6 seconds between NVD queries without a key and 0.6 seconds with one. A rate-limited or failing source is paused by its circuit breaker (`recon/helpers/circuit_breaker.py`), and the run logs a hint to configure an NVD key.

### Vulners Integration (Optional)

For results like Nmap's vulners script, use the Vulners API:

1. Get a free API key at [vulners.com](https://vulners.com/)
2. Add it in Global Settings → Tool API Keys, and set in the project settings:
   ```python
   CVE_LOOKUP_SOURCE = "vulners"
   ```

Without a Vulners key, the lookup uses NVD even when the source is `"vulners"`.

Vulners provides:
- Faster responses
- More CVE data
- Same format as Nmap's vulners script

---

## Requirements

- **Docker** reachable from the recon container. `run_vuln_scan()` checks `docker` is on the path and `docker info` answers; otherwise it skips the Nuclei passes (and keeps the previous Nuclei findings) but still runs the CVE lookup and the security checks.
- Nothing to install by hand. On each scan:
  - `pull_nuclei_docker_image()` pulls the image, so a moving tag stays current, and falls back to the copy already on the host when the pull fails
  - `ensure_templates_volume()` creates the `nuclei-templates` Docker volume, downloads the templates into it on first use and updates them when `NUCLEI_AUTO_UPDATE_TEMPLATES` is on
  - each pass mounts its targets and output directories and runs nuclei inside the container
  - the JSONL results are parsed into the recon data

To pre-pull the image:

```bash
docker pull projectdiscovery/nuclei:latest
```

---

## Configuration Parameters

All parameters are set in the webapp project settings (stored in PostgreSQL) and reach the module as the runtime keys below; `recon/project_settings.py` holds the fallback defaults. Each field's meaning and bounds are in the settings registry (`recon_settings/registry.yaml`).

At scan start the engagement ceiling caps `NUCLEI_RATE_LIMIT`, the memory governor can lower `NUCLEI_BULK_SIZE` and `NUCLEI_CONCURRENCY`, and stealth mode sets `NUCLEI_RATE_LIMIT = 5`, `NUCLEI_BULK_SIZE = 5`, `NUCLEI_CONCURRENCY = 2`, turns off DAST, headless and Interactsh, and adds `dos`, `fuzz`, `intrusive`, `sqli` and `rce` to `NUCLEI_EXCLUDE_TAGS`.

### Toggle

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `NUCLEI_ENABLED` | `bool` | `True` | Run the Nuclei passes. When off, `vuln_scan` holds an empty result (`execution_mode: "disabled"`) and the CVE lookup and security checks still run |

The module runs only when `vuln_scan` is in the project's scan modules (`SCAN_MODULES`).

### Severity Filtering

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `NUCLEI_SEVERITY` | `list` | `["critical", "high", "medium", "low"]` | Severity levels to include |

**Severity Levels:**
- `critical` - Remote code execution, authentication bypass
- `high` - SQL injection, XSS, SSRF
- `medium` - Information disclosure, misconfigurations
- `low` - Minor issues, informational findings
- `info` - Technology detection, version info (excluded by default)

### Template Selection

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `NUCLEI_TEMPLATES` | `list` | `[]` | Specific template paths to include (`-t`) |
| `NUCLEI_EXCLUDE_TEMPLATES` | `list` | `[]` | Template paths to exclude |
| `NUCLEI_CUSTOM_TEMPLATES` | `list` | `[]` | Paths to custom templates (manual entry, passed as `-t`) |
| `NUCLEI_SELECTED_CUSTOM_TEMPLATES` | `list` | `[]` | Per-project selected custom templates from the upload UI |

**Tags decide whether the built-in templates load.** With `NUCLEI_TAGS` set and no explicit `-t` path, the detection pass loads the whole built-in pool (`-t /root/nuclei-templates/`) filtered by the tags, plus any selected custom templates. With `NUCLEI_TAGS` empty, only the selected custom templates run. With no tags and no template of any kind, the detection pass is skipped (the DAST pass, which has its own template set, can still run).

**Custom Templates:**

Custom nuclei templates (`mcp/nuclei-templates/`) can be uploaded, viewed, and deleted directly from Project Settings → Nuclei → Template Options. Each template has a **per-project checkbox** — only checked templates are included in that project's scans. Templates are global (shared across all projects), but selection is per-project.

**Management:**
- **Upload** `.yaml`/`.yml` templates — validated for nuclei format (`id:`, `info.name:`, `info.severity:`); a `.yml` name is saved as `.yaml`, since Nuclei v3 reads a `.yml` path as a list of paths
- **Select** templates per project via checkboxes — only selected templates run during scans
- **View** all uploaded templates with severity badges and metadata
- **Delete** individual templates
- API: `GET/POST/DELETE /api/nuclei-templates`

**How it works:**
- The orchestrator passes the templates' host path as `HOST_CUSTOM_TEMPLATES_PATH`; it is mounted read-only at `/custom-templates`, and each selected template is passed as `-t /custom-templates/{path}`
- Recon logs list each selected template by name at scan start
- The AI agent also sees all templates automatically — at startup, the nuclei MCP server (`mcp/servers/nuclei_server.py`) appends the template paths to the `execute_nuclei` tool description

Currently available custom templates: Spring Boot Actuator templates (`springboot-*.yaml`: actuator discovery, `/env`, `/heapdump`, `/jolokia`, gateway SSRF, with URL-encoding, semicolon and alternate-base-path bypasses) and an AEM JSON exposure template.

**Template paths** (inside the templates volume, as upstream `nuclei-templates` lays them out):
```
http/cves/               - Known CVE exploits
http/vulnerabilities/    - General vulnerabilities
http/misconfiguration/   - Security misconfigurations
http/exposures/          - Exposed files/panels/data
http/technologies/       - Technology detection
http/default-logins/     - Default credentials
http/takeovers/          - Subdomain takeovers
dast/                    - DAST fuzzing templates (used by the DAST pass)
```

### Tag Filtering

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `NUCLEI_TAGS` | `list` | `["cve", "xss", "sqli", "rce", "lfi", "ssrf", "xxe", "ssti"]` | Template tags to include (empty = custom templates only) |
| `NUCLEI_EXCLUDE_TAGS` | `list` | `["dos", "fuzz"]` | Tags to exclude |

**Popular Tags:**
```
cve         - CVE templates
xss         - Cross-site scripting
sqli        - SQL injection
rce         - Remote code execution
lfi         - Local file inclusion
ssrf        - Server-side request forgery
xxe         - XML external entity
ssti        - Server-side template injection
exposure    - Data exposure
misconfig   - Misconfigurations
default-login - Default credentials
takeover    - Subdomain takeover
tech        - Technology detection
dos         - Denial of service (excluded by default)
fuzz        - Fuzzing templates (excluded by default)
```

### Rate Limiting & Performance

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `NUCLEI_RATE_LIMIT` | `int` | `100` | Requests per second, across all templates and targets |
| `NUCLEI_BULK_SIZE` | `int` | `25` | Hosts to process in parallel |
| `NUCLEI_CONCURRENCY` | `int` | `25` | Templates to run in parallel |
| `NUCLEI_TIMEOUT` | `int` | `10` | Per-request timeout (seconds), not a cap on the run |
| `NUCLEI_RETRIES` | `int` | `1` | Retries for failed requests |
| `NUCLEI_MAX_HOST_ERROR` | `int` | `30` | Errors tolerated from one host before nuclei stops probing it (`-mhe`) |
| `NUCLEI_MAX_RUNTIME` | `int` | `86400` | Wall-clock cap for one pass (seconds). At the cap the container is killed, its partial findings are kept and the run is recorded as truncated |

**Recommended Settings:**

| Scenario | Rate Limit | Bulk Size | Concurrency |
|----------|------------|-----------|-------------|
| **Safe/Slow** | 50 | 10 | 10 |
| **Normal** | 100 | 25 | 25 |
| **Aggressive** | 300 | 50 | 50 |
| **Internal Network** | 500+ | 100 | 100 |

### Scan Modes

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `NUCLEI_DAST_MODE` | `bool` | `False` | Add a DAST pass on resource_enum's parameterized URLs |
| `NUCLEI_AUTO_UPDATE_TEMPLATES` | `bool` | `True` | Update templates (`-ut`) before the scan; it fetches from the public template repository |
| `NUCLEI_NEW_TEMPLATES_ONLY` | `bool` | `False` | Only use newly added templates (`-nt`) |
| `NUCLEI_HEADLESS` | `bool` | `False` | Enable headless browser for JS apps |

### AI Assistance

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `NUCLEI_AI_TAGS` | `bool` | `False` | Let an LLM replace `NUCLEI_TAGS` with a subset that fits the technologies and Server headers http_probe found (detection pass only) |
| `NUCLEI_TAGS_AI_USE_JEV` | `bool` | `False` | Use native Jev 1.13 through the project's selected TypeSafe or OpenRouter Jev configuration instead of the LLM for the tag selector |
| `NUCLEI_AI_RESPONSE_FILTER` | `bool` | `False` | Ask the LLM whether a suspicious-status response (403/406/418/429/503/451) to an injection template is a block page |

The AI-in-pipeline switch (`AI_IN_PIPELINE`) turns `NUCLEI_AI_TAGS`, `NUCLEI_AI_RESPONSE_FILTER` and the security checks' `WAF_AI_CLASSIFIER` on or off together; the model is `AI_PIPELINE_MODEL`. When the AI is unavailable, the user's tags and the static filter are used.

### Network Settings

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `NUCLEI_SYSTEM_RESOLVERS` | `bool` | `True` | Use system DNS resolvers |
| `NUCLEI_FOLLOW_REDIRECTS` | `bool` | `True` | Follow HTTP redirects (`-follow-redirects`). Same host only (`-follow-host-redirects`) when session headers are attached, and in IP mode or while RoE exclusions are in force, in both passes and the takeover templates (`[*][Nuclei] Redirects followed on the same host only: RoE exclusions are in force`); that flag also holds a template's own `redirects: true` to the same host. Off, no flag is passed, so a template with `redirects: true` follows its redirects to any host, except in those same three cases (a session, IP mode, RoE exclusions): there `-disable-redirects` holds it (`[*][Nuclei] Template redirects held (-disable-redirects): RoE exclusions are in force`) |
| `NUCLEI_MAX_REDIRECTS` | `int` | `10` | Maximum redirects to follow |
| `NUCLEI_SCAN_ALL_IPS` | `bool` | `False` | Also scan `http(s)://<ip>` for every resolved IP no other target URL covers |
| `NUCLEI_INTERACTSH` | `bool` | `True` | Enable OOB testing (blind vulns); always off when session headers are attached, since callbacks go to a third-party collector |

### Docker Settings

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `NUCLEI_DOCKER_IMAGE` | `str` | `"projectdiscovery/nuclei:latest"` | Fixed: the image RedAmon ships for this tool. Not a project setting. |

**Docker Mode Advantages:**
- No Go installation required
- No binary management
- Templates kept in a persistent volume
- Easy updates (image pulled on each scan)
- Isolated execution

**How it works:**
`build_nuclei_command()` produces, for each pass:
```bash
docker run --rm --net=host \
  --name redamon-nuclei-detection-<id> \
  -v /tmp/redamon/.nuclei_temp_<id>:/targets:ro \
  -v /tmp/redamon/.nuclei_temp_<id>:/output \
  -v nuclei-templates:/root/nuclei-templates \
  [-v <HOST_CUSTOM_TEMPLATES_PATH>:/custom-templates:ro] \
  projectdiscovery/nuclei:latest \
  [nuclei arguments...]
```

`--net=host` lets Nuclei reach loopback and local-lab targets; the name lets the runtime-cap watchdog `docker kill` that exact container.

---

## Architecture & Flow

> **Pipeline context:** Vulnerability scanning runs in **GROUP 6 Phase A** of the recon pipeline (`recon/main.py`). In domain mode, `run_vuln_scan_isolated()` runs in one `ThreadPoolExecutor` with the other active scanners the project enabled (the GraphQL scanner `recon/graphql_scan/`, subdomain takeover, VHost/SNI, web cache poisoning, origin discovery, route exposure); every worker is handed one `_fan_out_snapshot` (a deep copy of `combined_result` taken before the first submit), its `_isolated` wrapper deep-copies that again, and only its own key is merged back into the live dict, so no worker copies a dict mid-merge. In IP mode `run_vuln_scan()` runs first on its own, then the others fan out. Phase B (MITRE CWE/CAPEC enrichment) runs after Phase A — it depends on Nuclei's CVEs. Both phases depend on resource enumeration (GROUP 5) output, and the whole group is skipped when http_probe found no live URL: then the certificate-hygiene checks run from stored certificate data, the port and service checks and the org DNS checks run on their own (`_maybe_run_port_checks`, `_maybe_run_dns_checks` in `recon/main.py`), Subdomain Takeover still runs, and the skipped sources keep their findings on the group's hosts. Graph DB updates happen in a background thread.

### Execution Flow (`run_vuln_scan`)

```
1. PRECHECKS (when NUCLEI_ENABLED)
   └── is_docker_installed() / is_docker_running()
   └── pull_nuclei_docker_image()
   └── ensure_templates_volume() (creates, downloads, -ut when auto-update is on)
   └── Any failure → skip the Nuclei passes, keep the previous Nuclei findings,
       record the live URLs as "failed" coverage

2. TARGETS
   └── extract_targets_from_recon(): hostnames and IPs from the DNS section
       (the root domain only when it is a target)
   └── build_target_urls(): resource_enum base and endpoint URLs
       + http_probe URLs answering < 500
       + http(s)://<host> for hostnames neither already covers (mock IP
         hostnames skipped)
       + http(s)://<ip> for uncovered IPs when NUCLEI_SCAN_ALL_IPS
   └── DAST URLs: resource_enum.discovered_urls holding "?" and "="

3. OPTIONAL AI STEPS
   └── set_fp_ai_ctx() arms the AI false-positive filter
   └── NUCLEI_AI_TAGS: get_ai_tags() may replace NUCLEI_TAGS

4. PASS A: DETECTION   (skipped when no tags and no templates)
   └── targets_detection.txt in /tmp/redamon/.nuclei_temp_<id>
   └── build_nuclei_command(...) with tags, templates, custom templates,
       session headers (merge_auth_headers, in-scope hosts only)
   └── _execute_nuclei_pass(): stream output, watch -stats, kill at
       NUCLEI_MAX_RUNTIME, parse the JSONL, is_false_positive() per line,
       parse_nuclei_finding() for the rest

5. PASS B: DAST        (NUCLEI_DAST_MODE and at least one parameterized URL)
   └── targets_dast.txt; build_nuclei_command(force_dast_pass=True):
       -dast, no tag/template filters

6. RESULT
   └── Aggregate by target, category, template; deduplicate CVEs by id
   └── recon_data["vuln_scan"] = {...} with per-host coverage
   └── Written to output_file only when one is passed
   └── The run's temp dir is removed

7. CVE LOOKUP          (CVE_LOOKUP_ENABLED and http_probe data)
   └── run_cve_lookup() → recon_data["technology_cves"]

8. SECURITY CHECKS     (SECURITY_CHECK_ENABLED and any check on)
   └── run_security_checks() → recon_data["vuln_scan"]["security_checks"]
```

A pass that exits non-zero (a Docker error, an OOM kill, a fatal nuclei error) still has its partial JSONL ingested, but the findings of everything it did not reach are kept rather than pruned.

### Data Flow

```
┌──────────────────────────────────────────────────────────────────────────┐
│              project settings (webapp) → recon/project_settings.py         │
│  NUCLEI_SEVERITY, NUCLEI_RATE_LIMIT, NUCLEI_TAGS, NUCLEI_DOCKER_IMAGE... │
└─────────────────────────────────┬────────────────────────────────────────┘
                                  │
                                  ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                          vuln_scan.py                                    │
│                                                                          │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────────┐  │
│  │ extract_targets │───▶│ build_target    │───▶│ build_nuclei        │  │
│  │ _from_recon()   │    │ _urls()         │    │ _command()          │  │
│  └─────────────────┘    └─────────────────┘    └─────────────────────┘  │
│           │                     │                        │               │
│           ▼                     ▼                        ▼               │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                    run_vuln_scan()                               │    │
│  │  ┌───────────────┐  ┌───────────────┐  ┌───────────────────┐   │    │
│  │  │ _execute_     │─▶│ is_false_     │─▶│ parse_nuclei      │   │    │
│  │  │ nuclei_pass() │  │ positive()    │  │ _finding()        │   │    │
│  │  └───────────────┘  └───────────────┘  └───────────────────┘   │    │
│  │  then run_cve_lookup() and run_security_checks()                │    │
│  └─────────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
                    ┌──────────────────────────────┐
                    │   recon_<domain>.json        │
                    │   "vuln_scan" (+ security_   │
                    │   checks), "technology_cves" │
                    └──────────────────────────────┘
```

---

## Function Reference

The module's own functions live in `recon/main_recon_modules/vuln_scan.py`; the helpers it imports from `recon.helpers` live in `docker_helpers.py`, `target_helpers.py`, `nuclei_helpers.py`, `cve_helpers.py` and `security_checks.py` under `recon/helpers/`.

### `run_vuln_scan(recon_data: dict, output_file: Path = None, settings: dict = None) -> dict`

**Purpose:** Main entry point; runs the flow above and returns `recon_data` with `vuln_scan` (and `technology_cves`) added.

---

### `run_vuln_scan_isolated(combined_result: dict, settings: dict) -> dict`

**Purpose:** Thread-safe wrapper for the GROUP 6 fan-out. Deep-copies `combined_result`, runs `run_vuln_scan()` on the copy with no incremental saves, and returns only the copy's `vuln_scan` dict (security checks included).

---

### `enrich_recon_file(recon_file: Path) -> dict`

**Purpose:** Standalone use: loads settings with `get_settings()`, runs `run_vuln_scan()` on a recon JSON file and saves the result back to it.

---

### `_execute_nuclei_pass(cmd, output_file, label, runtime_cap=0, container_name=None) -> tuple`

**Purpose:** Runs one nuclei container and parses its JSONL output.

**Behavior:**
1. Streams nuclei's output to the log; `_nuclei_watch_stats()` warns once when, for 10 minutes, more than half of the requests error with no match
2. A watchdog timer `docker kill`s the named container at `runtime_cap` (`NUCLEI_MAX_RUNTIME`); the partial output is still parsed
3. Each JSONL line goes through `is_false_positive()`; kept lines go through `parse_nuclei_finding()`
4. A non-zero exit marks Nuclei as degraded for the run, so its earlier findings are kept

**Returns:** `(findings, false_positives, duration_seconds, return_code)`

---

### `is_docker_installed() -> bool` / `is_docker_running() -> bool`

**Purpose:** `docker` is on the path / `docker info` returns 0.

---

### `pull_nuclei_docker_image(docker_image: str) -> bool`

**Purpose:** Pulls the image through `pull_image_or_use_local()`.

**Returns:** `True` when the pull succeeded, or when it failed but the image is already on the host.

---

### `ensure_templates_volume(docker_image: str, auto_update: bool = False) -> bool`

**Purpose:** Ensures the `nuclei-templates` Docker volume exists and has templates.

**Behavior:**
1. Creates the volume if it is missing
2. Otherwise checks it holds `.yaml` files
3. Runs `nuclei -ut` into the volume when it is new or empty, or when `auto_update` is on (10-minute limit)
4. A timed-out update is killed and returns `False`, because a half-written template set fails to load; Nuclei is then skipped for the run

**Returns:** `True` if templates are ready.

---

### `extract_targets_from_recon(recon_data: dict) -> Tuple[Set[str], Set[str], Dict[str, List[str]]]`

**Purpose:** Extracts IPs, hostnames, and the IP-to-hostnames mapping from the DNS section:
- Root domain DNS records, only when the root is a target (`metadata.include_root_domain`)
- Subdomain DNS records (hostnames with records, and their IPs)

**Returns:** `(ips, hostnames, ip_to_hostnames)`

---

### `build_target_urls(hostnames, ips, recon_data=None, scan_all_ips=False) -> List[str]`

**Purpose:** The detection pass's target list: the deduplicated union of
1. resource_enum base URLs and endpoint URLs (`build_target_urls_from_resource_enum()`: a templated path such as `/users/{id}` is never a target, and endpoints known only from an API specification count only when they declare GET or HEAD, up to `MAX_DECLARED_NUCLEI_URLS`)
2. http_probe URLs answering below 500 (`build_target_urls_from_httpx()`)
3. `http://` and `https://` for every hostname sources 1 and 2 do not already cover, except mock IP hostnames (`10-0-0-1` for an IP with no PTR record)
4. `http(s)://<ip>` for uncovered IPs, only with `scan_all_ips` (IPv6 in brackets)

**Returns:** Sorted list of URLs.

---

### `build_nuclei_command(targets_file, output_file, docker_image, ..., force_dast_pass=False, auth_headers=None, container_name=None, max_host_error=0, ip_mode=False, roe_exclusions=False) -> List[str]`

**Purpose:** Constructs the nuclei Docker CLI command for one pass. The keyword arguments mirror the settings above.

**Generated Command Structure** (detection pass, default settings):
```bash
docker run --rm --net=host --name redamon-nuclei-detection-<id> \
  -v /tmp/redamon/.nuclei_temp_<id>:/targets:ro \
  -v /tmp/redamon/.nuclei_temp_<id>:/output \
  -v nuclei-templates:/root/nuclei-templates \
  projectdiscovery/nuclei:latest \
  -l /targets/targets_detection.txt \
  -jsonl \
  -o /output/nuclei_detection.jsonl \
  -silent \
  -nc \
  -duc \
  -stats -stats-interval 30 \
  -severity critical,high,medium,low \
  -t /root/nuclei-templates/ \
  -tags cve,xss,sqli,rce,lfi,ssrf,xxe,ssti \
  -exclude-tags dos,fuzz \
  -rate-limit 100 \
  -bulk-size 25 \
  -concurrency 25 \
  -timeout 10 \
  -retries 1 \
  -mhe 30 \
  -system-resolvers \
  -follow-redirects \
  -max-redirects 10
```

- `force_dast_pass=True` adds `-dast` and drops every tag and template filter, which would otherwise empty-intersect with the DAST template set.
- `auth_headers` become `-H` flags; with them, redirects use `-follow-host-redirects` and `-no-interactsh` is forced.
- `ip_mode=True` or `roe_exclusions=True` also switches redirects to `-follow-host-redirects`. The target list is admitted, but a target's redirect is not, and nuclei follows it inside its client before any scope check. `run_vuln_scan` passes `roe_exclusions` from `admission_context(settings, recon_data).excluded`, so a partial run reads the exclusions from `metadata.roe`; `_run_nuclei_takeover` reads them from its settings.
- With `follow_redirects=False`, any of the three (`auth_headers`, `ip_mode`, `roe_exclusions`) adds `-disable-redirects`. Without it, a template that sets its own `redirects: true` follows a redirect to any host: an excluded one, an address off the IP target list, or a third party that would receive the `-H` session. With none of the three, follow-off passes no redirect flag.
- When HTTP traffic capture is on and reachable, `-proxy <capture proxy>` and an `X-Redamon-Ctx` header are added.

---

### `is_false_positive(finding: dict) -> tuple`

**Purpose:** Decides whether a raw nuclei finding is a false positive.

**Rules:**
1. For time-based and blind templates only (a `time-based`, `blind` or `time-based-sqli` tag, or `time` / `blind` as a whole word of the template id), a response the server throttled is a false positive: the delay the template measured is the throttle's. Throttled means the raw response's status line reads `429`, or it reads `503` or carries a `Retry-After` header and the response holds throttle wording ("too many requests", "rate limit", "please wait", "try again later", ...). Nuclei's JSONL has no status field, so the status and headers are parsed from the raw `response`. Any other template keeps its match, and the same wording on a page the server did not throttle ("Loading, please wait...") is ordinary copy
2. For injection templates (`sqli`, `xss`, `rce`, `lfi`, `ssti`, `injection` tags), a `403` response with a WAF marker ("Access Denied", "ModSecurity", "Cloudflare", ...) is a false positive
3. With `NUCLEI_AI_RESPONSE_FILTER` on, an injection finding the keyword lists missed, whose response's first 50 characters hold a suspicious status (403, 406, 418, 429, 503, 451), is classified by the LLM; a "blocked" verdict with confidence of at least 70 is a false positive

**Returns:** `(is_false_positive, reason)`. Dropped findings are listed in `vuln_scan.false_positives`.

---

### `parse_nuclei_finding(finding: dict) -> dict`

**Purpose:** Parses a single nuclei JSON finding into standardized format.

**CVE Extraction Sources:**
1. `info.classification.cve-id`
2. `info.classification.cve`

Nuclei v3 emits `cve-id` as a **lowercase list** (`["cve-2021-41773"]`), so ids
are matched case-insensitively and stored upper-case (`CVE-2021-41773`); a
case-sensitive `CVE-` test dropped every CVE. The parser returns each CVE as a
`{id, cvss, url}` map (below), but the graph writer (`nuclei_cve_ids` in
`graph_db/mixins/recon/vuln_mixin.py`) stores the `Vulnerability` node's `cves`
as a flat list of id strings: Neo4j cannot store a map inside a property, and one
map fails the whole write. That list is what CVE enrichment, reports and the
Mute Rules CVE fields (`has_cve`, `cve_year`, `cve_ids`) read. Regression tests:
`recon/tests/test_nuclei_cve_findings_reach_graph.py`.

**Category Classification:** the first tag that names one of these keys (keys checked in this order) decides; no match is `general`. A key matches whole words of a tag, split on anything that is not a letter or digit, never a substring: `time-based-sqli` is sqli and `open-redirect` is open_redirect, while `ecommerce`, `salesforce` and `source` are not rce and `sqlite` is not sqli. The Priority Board ranks on this category.

| Tag Containing | Category |
|----------------|----------|
| `xss` | xss |
| `sqli` | sqli |
| `rce` | rce |
| `lfi` | lfi |
| `rfi` | rfi |
| `ssrf` | ssrf |
| `xxe` | xxe |
| `ssti` | ssti |
| `cve` | cve |
| `exposure` | exposure |
| `misconfig`, `misconfiguration` | misconfiguration |
| `default-login`, `auth-bypass` | authentication |
| `panel` | exposed_panel |
| `tech` | technology |
| `takeover` | takeover |
| `dos` | dos |
| `idor` | idor |
| `csrf` | csrf |
| `redirect` | open_redirect |
| `crlf` | crlf |
| `injection` | injection |
| `file-upload` | file_upload |
| `traversal` | path_traversal |
| `disclosure` | information_disclosure |
| `ssl`, `tls` | ssl_tls |
| `cloud`, `aws`, `azure`, `gcp`, `kubernetes`, `docker` | cloud |

**Returns:**
```python
{
    "template_id": "CVE-2021-44228",
    "template_path": "http/cves/2021/CVE-2021-44228.yaml",
    "name": "Apache Log4j RCE",
    "description": "...",
    "severity": "critical",
    "category": "rce",
    "tags": ["cve", "rce", "log4j"],
    "reference": [...],
    "cves": [{"id": "CVE-2021-44228", "cvss": 10.0, "url": "..."}],
    "cvss_score": 10.0,
    "cvss_metrics": "CVSS:3.1/...",
    "cwe_id": ["cwe-502"],
    "target": "https://example.com",
    "matched_at": "https://example.com/api/login",
    "matcher_name": "",
    "extracted_results": [],
    "curl_command": "curl ...",
    "request": "...",
    "response": "...",      # first 500 characters
    "timestamp": "...",
    "raw": {...}            # the raw nuclei line
}
```

---

### `run_cve_lookup(recon_data, enabled=True, source="nvd", max_cves=20, min_cvss=0.0, vulners_api_key=None, nvd_api_key=None, nvd_key_rotator=None, vulners_key_rotator=None) -> dict`

**Purpose:** The technology-based CVE lookup described [above](#cve-lookup-technology-based).

**Returns:** `{"technology_cves": {...}}`, merged into `recon_data`.

---

### `run_security_checks(recon_data, enabled_checks, timeout, tls_expiry_days, max_workers, ...) -> dict`

**Purpose:** RedAmon's own checks (see [Custom Security Checks](#custom-security-checks)).

**Returns:** `{"security_checks": {...}}`; `run_vuln_scan()` stores it as `vuln_scan.security_checks`.

---

## Updating Templates & Vulnerability Data

Nuclei's vulnerability detection is entirely based on YAML templates maintained by the community. Understanding how templates are updated is critical for effective scanning.

### How Nuclei Gets CVE/CVSS Data

Nuclei does **NOT calculate CVSS scores** - template authors embed pre-calculated scores from NVD:

```yaml
# Example template structure
info:
  name: "Apache Log4j RCE"
  severity: critical
  classification:
    cve-id: CVE-2021-44228
    cvss-score: 10.0                    # From NVD
    cvss-metrics: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
```

| Data Field | Source | When Added |
|------------|--------|------------|
| `cve-id` | Template author | When template created |
| `cvss-score` | NIST NVD (copied by author) | When template created |
| `cvss-metrics` | NIST NVD (copied by author) | When template created |
| `severity` | Nuclei classification | Based on CVSS |

### Template Update Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     NUCLEI TEMPLATE UPDATE FLOW                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   PROJECTDISCOVERY                      YOUR SYSTEM                     │
│   ┌─────────────────┐                   ┌─────────────────┐            │
│   │ nuclei-templates│                   │ Docker Volume   │            │
│   │    (GitHub)     │                   │ nuclei-templates│            │
│   │                 │   nuclei -ut      │                 │            │
│   │  YAML           │ ───────────────▶  │  Local copy of  │            │
│   │  templates      │                   │  all templates  │            │
│   │                 │                   │                 │            │
│   │ Updated daily   │                   │ Persists across │            │
│   │ by community    │                   │ scans           │            │
│   └─────────────────┘                   └─────────────────┘            │
│                                                  │                      │
│                                                  ▼                      │
│                                         ┌─────────────────┐            │
│                                         │  Nuclei Scan    │            │
│                                         │  Uses templates │            │
│                                         │  to detect CVEs │            │
│                                         └─────────────────┘            │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Automatic Template Updates

RedAmon updates templates when `NUCLEI_AUTO_UPDATE_TEMPLATES = True` (default):

```python
# In project settings
NUCLEI_AUTO_UPDATE_TEMPLATES = True  # Runs "nuclei -ut" before each scan
```

**What happens on each scan** (`ensure_templates_volume()`):
1. Check if the `nuclei-templates` Docker volume exists; create it if not
2. If the volume is new or empty, or `NUCLEI_AUTO_UPDATE_TEMPLATES = True`, run `nuclei -ut` into it (10-minute limit)
3. Templates are downloaded/updated in the persistent volume
4. The scan itself runs with `-duc`, so nuclei does not check for updates again

**Console output when updating:**
```
[*][Docker] Checking for template updates...
[✓][Docker] Templates updated successfully
```

### Manual Template Update

Force a template update without running a scan:

```bash
# Update templates via Docker
docker run --rm \
  -v nuclei-templates:/root/nuclei-templates \
  projectdiscovery/nuclei:latest \
  -ut

# Or delete the volume to force fresh download
docker volume rm nuclei-templates
# Next scan will download all templates fresh
```

### Template Update Frequency

| Source | Update Frequency | Coverage |
|--------|------------------|----------|
| **ProjectDiscovery GitHub** | Multiple times daily | Official templates |
| **Community contributions** | Continuous | New CVEs within hours/days |
| **Your local volume** | Per scan (if auto-update on) | Synced on demand |

### Disabling Auto-Update

For faster scan startup, or to keep the scan from fetching anything from the public template repository:

```python
# In project settings
NUCLEI_AUTO_UPDATE_TEMPLATES = False
```

**Console output when disabled:**
```
[✓][Docker] Templates volume ready (auto-update disabled)
```

An empty volume is still filled on first use.

### Verifying Template Status

```bash
# Count templates in volume
docker run --rm \
  -v nuclei-templates:/root/nuclei-templates \
  alpine \
  sh -c "find /root/nuclei-templates -name '*.yaml' | wc -l"

# Check template version
docker run --rm \
  -v nuclei-templates:/root/nuclei-templates \
  projectdiscovery/nuclei:latest \
  -version
```

### Troubleshooting Template Updates

| Issue | Solution |
|-------|----------|
| "Templates not updating" | Delete volume: `docker volume rm nuclei-templates` |
| "Template parse error" | Update Nuclei image: `docker pull projectdiscovery/nuclei:latest` |
| "Breaking changes" | Nuclei engine version must match template requirements |
| "Template update timed out" | The update was stopped after 10 minutes and Nuclei skipped for the run; run the manual update above |

---

## Nuclei Arguments Explained

The flags `build_nuclei_command()` can pass:

### Output Formats

| Flag | Description |
|------|-------------|
| `-jsonl` | JSON Lines output (one JSON per line) |
| `-o <file>` | Output file path |
| `-silent` | Suppress banner and progress |
| `-nc` | No color output |
| `-duc` | Disable the automatic update check |
| `-stats -stats-interval 30` | Progress heartbeat every 30 seconds |

### Target Selection

| Flag | Description |
|------|-------------|
| `-l <file>` | List of targets from file |

### Template Selection

| Flag | Description |
|------|-------------|
| `-t <path>` | Template folder or file |
| `-exclude-templates <path>` | Exclude specific templates |
| `-tags <tags>` | Include templates with tags |
| `-exclude-tags <tags>` | Exclude templates with tags |
| `-severity <levels>` | Filter by severity |
| `-nt` | New templates only |
| `-dast` | Run DAST (fuzzing) templates |

### Rate Limiting

| Flag | Description |
|------|-------------|
| `-rate-limit <n>` | Maximum requests per second |
| `-bulk-size <n>` | Hosts to scan in parallel |
| `-concurrency <n>` | Templates to run in parallel |
| `-mhe <n>` | Errors tolerated per host before it is skipped |

### Network Options

| Flag | Description |
|------|-------------|
| `-timeout <s>` | Request timeout in seconds |
| `-retries <n>` | Number of retries |
| `-system-resolvers` | Use system DNS |
| `-follow-redirects` | Follow HTTP redirects |
| `-follow-host-redirects` | Follow redirects on the same host only |
| `-disable-redirects` | Follow no redirect, a template's own `redirects: true` included |
| `-max-redirects <n>` | Max redirect depth |
| `-proxy <url>` | Send traffic through the capture proxy |

### Advanced Features

| Flag | Description |
|------|-------------|
| `-headless` | Enable headless browser |
| `-no-interactsh` | Disable OOB testing |
| `-H <header>` | Custom HTTP headers |

---

## Template Categories

The built-in templates live in the `nuclei-templates` volume at `/root/nuclei-templates/`, laid out by upstream `nuclei-templates`:

| Path | Contents |
|------|----------|
| `http/cves/<year>/` | CVE templates, updated within days of disclosure |
| `http/vulnerabilities/` | Generic and product vulnerabilities (WordPress, Joomla, Drupal, ...) |
| `http/misconfiguration/` | Server, CORS and header misconfigurations |
| `http/exposures/` | Exposed configs, files and logs (`.git/config`, `.env`, ...) |
| `http/technologies/` | Technology, WAF and CMS detection |
| `http/default-logins/` | Default credentials |
| `http/takeovers/` | Subdomain takeovers |
| `dast/` | Fuzzing templates the DAST pass runs |

---

## Output Data Structure

### Complete JSON Schema

```json
{
  "vuln_scan": {
    "scan_metadata": {
      "scan_timestamp": "2024-01-15T12:00:00.000000",
      "scan_duration_seconds": 245.5,
      "nuclei_version": "Docker: projectdiscovery/nuclei:latest",
      "templates_available": 8000,
      "execution_mode": "docker",
      "docker_image": "projectdiscovery/nuclei:latest",
      "anonymous_mode": false,
      "severity_filter": ["critical", "high", "medium", "low"],
      "tags_filter": ["cve", "xss", "sqli", "rce", "lfi", "ssrf", "xxe", "ssti"],
      "tags_ai_selected": false,
      "exclude_tags": ["dos", "fuzz"],
      "rate_limit": 100,
      "dast_mode": true,
      "dast_pass_executed": true,
      "dast_urls_discovered": 47,
      "katana_crawl_depth": 2,
      "total_urls_scanned": 52,
      "total_hostnames": 5,
      "total_ips": 2,
      "false_positives_filtered": 1,
      "coverage": {
        "at": "2024-01-15T11:58:00+00:00",
        "hosts": {
          "https://example.com:443": {"status": "complete", "inputs": 2, "outputs": 1, "reason": null}
        }
      }
    },

    "discovered_urls": {
      "base_urls": [
        "http://api.example.com",
        "https://example.com"
      ],
      "dast_urls_with_params": [
        "http://example.com/search?q=test",
        "http://example.com/api/users?id=1"
      ],
      "all_scanned_urls": [
        "http://api.example.com",
        "http://example.com/api/users?id=1",
        "..."
      ]
    },

    "by_target": {
      "https://example.com": {
        "findings": [
          { "...": "parse_nuclei_finding() output, see above" }
        ],
        "severity_counts": {
          "critical": 1,
          "high": 2,
          "medium": 5,
          "low": 3,
          "info": 10
        }
      }
    },

    "summary": {
      "total_findings": 50,
      "critical": 1,
      "high": 5,
      "medium": 15,
      "low": 10,
      "info": 19,
      "unknown": 0
    },

    "vulnerabilities": {
      "critical": 1,
      "high": 5,
      "medium": 15,
      "low": 10,
      "info": 19,
      "unknown": 0
    },

    "all_cves": [
      {
        "id": "CVE-2021-44228",
        "cvss": 10.0,
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
      }
    ],

    "by_category": {
      "rce": [
        {
          "template_id": "CVE-2021-44228",
          "name": "Apache Log4j RCE",
          "target": "https://example.com",
          "matched_at": "https://example.com/api/v1/login",
          "category": "rce",
          "cves": ["CVE-2021-44228"],
          "cvss": 10.0
        }
      ],
      "xss": [...]
    },

    "by_template": {
      "CVE-2021-44228": {
        "name": "Apache Log4j RCE",
        "severity": "critical",
        "findings_count": 3,
        "targets": ["https://example.com", "https://api.example.com"]
      }
    },

    "false_positives": [
      {"template_id": "...", "matched_at": "...", "reason": "Rate limiting detected (...)"}
    ],

    "security_checks": { "...": "see Custom Security Checks" }
  }
}
```

- `templates_available` is a fixed approximation, not a count of the volume.
- `vulnerabilities` holds per-severity counts (the same figures as `summary`).
- `all_cves` is deduplicated by id and sorted by CVSS, highest first.
- `coverage.hosts` is keyed by `scheme://host:port`: `complete` when every pass that targeted the host finished, `partial` when one was stopped (e.g. by the runtime cap), `failed` when none ran or all failed; `inputs` counts the URLs sent, `outputs` the findings.
- When Nuclei is disabled, `vuln_scan` keeps this shape with empty values and `execution_mode: "disabled"`. When it could not run (no Docker, no templates, no template selected), `vuln_scan` holds only `scan_metadata.coverage`, marking the hosts `failed`, and the `security_checks` added after it.

---

## Nmap vs Nuclei Comparison

### When to Use Each Tool

| Use Case | Nmap | Nuclei | Both |
|----------|------|--------|------|
| Port discovery | ✅ | ❌ | |
| Service detection | ✅ | ❌ | |
| OS fingerprinting | ✅ | ❌ | |
| Network protocol vulns | ✅ | ❌ | |
| SMB/FTP/SSH vulns | ✅ | ⚠️ | |
| Web application vulns | ⚠️ | ✅ | |
| CVE detection | ⚠️ | ✅ | |
| Exposed panels | ❌ | ✅ | |
| Default credentials | ⚠️ | ✅ | |
| Cloud misconfigs | ❌ | ✅ | |
| **Full assessment** | | | ✅ |

### Complementary Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│                    COMPLETE VULNERABILITY SCAN                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. Nmap Scan (GROUP 3.5)           2. Nuclei Scan (GROUP 6)    │
│  ─────────────                      ────────────                │
│  • Service/version detection        • URLs from httpx and       │
│    on the open ports                  resource_enum             │
│  • NSE vuln scripts                 • Web application CVEs      │
│  • Versions feed the CVE lookup     • Exposed panels/files      │
│                                     • Default credentials       │
│                                     • Cloud misconfigs          │
│                                     • Technology detection      │
│           │                                   │                 │
│           └──────────────┬───────────────────┘                 │
│                          ▼                                      │
│              ┌─────────────────────────┐                       │
│              │    Combined Results     │                       │
│              │   (recon_domain.json)   │                       │
│              └─────────────────────────┘                       │
└─────────────────────────────────────────────────────────────────┘
```

---

## Usage Examples

### Basic Usage (full pipeline)

The module runs when the project's scan modules include `vuln_scan` (they do by default). Start a recon scan from the webapp; the orchestrator spawns the recon container, which runs `recon/main.py` with the project's settings.

### Partial Recon

`recon/partial_recon_modules/vulnerability_scanning.py` re-runs `run_vuln_scan()` on demand (`run_nuclei`) against the graph's BaseURLs and endpoints and any URLs the user typed in, and `run_security_checks_partial` runs the security checks alone.

### Standalone Enrichment

```python
from recon.main_recon_modules.vuln_scan import enrich_recon_file
from pathlib import Path

enriched = enrich_recon_file(Path("output/recon_example.com.json"))
```

### Custom Configuration Profiles

Values to enter in the project settings (shown as runtime keys):

**Quick Web Scan (Fast):**
```python
NUCLEI_SEVERITY = ["critical", "high"]
NUCLEI_RATE_LIMIT = 200
NUCLEI_TEMPLATES = []
NUCLEI_EXCLUDE_TEMPLATES = []
```

**Comprehensive Security Audit:**
```python
NUCLEI_SEVERITY = ["critical", "high", "medium", "low", "info"]
NUCLEI_RATE_LIMIT = 50
NUCLEI_HEADLESS = True
NUCLEI_INTERACTSH = True
```

**CVE-Only Scan:**
```python
NUCLEI_TAGS = ["cve"]
NUCLEI_SEVERITY = ["critical", "high", "medium"]
```

**Web Application Pentest:**
```python
NUCLEI_TAGS = ["xss", "sqli", "rce", "lfi", "ssrf", "ssti"]
NUCLEI_SEVERITY = ["critical", "high", "medium"]
NUCLEI_HEADLESS = True
```

**DAST Mode (Active Fuzzing):**
```python
# Enable the DAST pass; it fuzzes resource_enum's parameterized URLs
NUCLEI_DAST_MODE = True
NUCLEI_SEVERITY = ["critical", "high", "medium"]
```

The crawl that finds those URLs is configured in resource enumeration (Katana depth, max URLs, JavaScript crawling: see [README.RESOURCE_ENUM.md](README.RESOURCE_ENUM.md)). For authenticated scanning, attach an authenticated-session profile to the project: its headers reach both passes when every scanned host is in scope.

**DAST Expected Findings:**
- SQL Injection in search forms
- XSS in URL parameters
- Command injection in API endpoints
- SSTI in template parameters
- Path traversal in file parameters

---

## Troubleshooting

### Common Issues

#### "[!][Nuclei] Docker not found" / "Docker daemon is not running"

Nuclei runs through the host's Docker daemon. Check that Docker is running on the host (`docker info`) and that the recon container can reach it. The CVE lookup and the security checks still run, and the previous Nuclei findings are kept.

#### "Include Tags is empty AND no custom templates are selected"

Empty `NUCLEI_TAGS` means custom templates only. Add tags (e.g. `cve`, `xss`, `sqli`) or select a custom template; until then the detection pass is skipped.

#### Scan too slow

```python
# Increase performance in project settings
NUCLEI_RATE_LIMIT = 300
NUCLEI_BULK_SIZE = 50
NUCLEI_CONCURRENCY = 50
NUCLEI_SEVERITY = ["critical", "high"]  # Skip lower severities
```

A log line "N% of ... requests are erroring with no matches after 10 min" means the targets are mostly failing (a tarpit or dead hosts): lower `NUCLEI_MAX_RUNTIME` or `NUCLEI_MAX_HOST_ERROR`.

#### Pass stopped at the runtime cap

"hit the ...h runtime cap (NUCLEI_MAX_RUNTIME)" means the pass was killed; its partial findings are kept and its hosts are marked `partial`. Raise `NUCLEI_MAX_RUNTIME` (up to 7 days) or narrow the tags.

#### Too many false positives

```python
# Be more selective
NUCLEI_SEVERITY = ["critical", "high"]
NUCLEI_EXCLUDE_TAGS = ["dos", "fuzz", "intrusive"]
```

Check `vuln_scan.false_positives` for what the filter already dropped.

#### Memory issues

```python
# Reduce parallel operations
NUCLEI_BULK_SIZE = 10
NUCLEI_CONCURRENCY = 10
```

#### DAST mode finds nothing

**Problem:** `NUCLEI_DAST_MODE = True` but no XSS/SQLi findings.

**Cause:** DAST templates need URLs with parameters (`?key=value`) to fuzz, and they come only from `resource_enum`.

**Solution:**
- Check `vuln_scan.scan_metadata.dast_pass_executed` and `discovered_urls.dast_urls_with_params` in the output JSON: an empty list means resource enumeration found no parameterized URL, and the log says "DAST pass skipped (no parameterized URLs available)"
- Make sure resource enumeration runs (`resource_enum` in the scan modules) and crawls deep enough

**Manual test:**
```bash
# Test Katana directly
docker run --rm projectdiscovery/katana:latest \
  -u https://example.com -d 3 -jc -silent | grep "?"
```

#### Templates not updating

```bash
# Force template update
docker volume rm nuclei-templates
# Then run scan again - templates will re-download
```

### Debug Mode

Run nuclei manually via Docker to debug:

```bash
docker run --rm \
  -v nuclei-templates:/root/nuclei-templates \
  projectdiscovery/nuclei:latest \
  -u https://example.com \
  -tags cve \
  -severity critical,high \
  -v -debug
```

---

## Security Considerations

⚠️ **Legal Warning:** Only scan systems you have explicit permission to test.

| Risk | Mitigation |
|------|------------|
| Rate limiting/bans | Reduce `NUCLEI_RATE_LIMIT`, or set the engagement ceiling (`ROE_GLOBAL_MAX_RPS`) |
| WAF blocking | Reduce concurrency, use delays |
| Service disruption | Exclude `dos` and `fuzz` tags |
| Detection | Reduce rate limit, or use stealth mode |
| Account lockouts | Exclude `brute` tag |
| Session leakage | With session headers, OAST and cross-host redirects are disabled automatically |

### Safe Defaults

```python
NUCLEI_RATE_LIMIT = 50
NUCLEI_SEVERITY = ["critical", "high", "medium"]
NUCLEI_EXCLUDE_TAGS = ["dos", "fuzz", "intrusive"]
```

---

## Dependencies

| Package | Purpose |
|---------|---------|
| Docker | Container runtime for nuclei |
| `projectdiscovery/nuclei:latest` | Nuclei Docker image (pulled on each scan) |
| `nuclei-templates` volume | Persistent template storage (auto-created) |
| `alpine` image | Checks the templates volume and removes root-owned output files |
| Python 3.11 | The recon image's runtime |

---

## References

### Nuclei
- [Nuclei Documentation](https://docs.nuclei.sh/)
- [Nuclei Templates Repository](https://github.com/projectdiscovery/nuclei-templates)
- [DAST Templates](https://github.com/projectdiscovery/nuclei-templates/tree/main/dast)
- [Template Guide](https://docs.nuclei.sh/template-guide/introduction)
- [Docker Hub - Nuclei](https://hub.docker.com/r/projectdiscovery/nuclei)

### Katana
- [Katana Documentation](https://docs.projectdiscovery.io/tools/katana/overview)
- [Katana GitHub](https://github.com/projectdiscovery/katana)
- [Docker Hub - Katana](https://hub.docker.com/r/projectdiscovery/katana)
- [JavaScript Crawling Guide](https://docs.projectdiscovery.io/tools/katana/running#crawling-mode)

### ProjectDiscovery
- [ProjectDiscovery Blog](https://blog.projectdiscovery.io/)
- [ProjectDiscovery GitHub](https://github.com/projectdiscovery)

---

## Custom Security Checks

In addition to Nuclei templates, RedAmon includes custom Python-based security checks (`recon/helpers/security_checks.py`) that detect vulnerabilities **not covered by Nuclei**. They run after the Nuclei passes, also when Nuclei is disabled.

### Why Custom Checks?

| Check Type | Nuclei Coverage | Custom Check Adds |
|------------|-----------------|-------------------|
| **Direct IP Access** | No | WAF bypass via IP (blocked-vs-allowed payload differential) + unauthenticated `PURGE`/`BAN` cache endpoint |
| **TLS** | No | Expiry warning, plus hygiene from the certificate data tlsx/httpx already hold |
| **Security Headers** | Partial | Only headers Nuclei does not check |
| **DNS Security** | No | SPF, DMARC, DNSSEC, Zone Transfer |
| **Rate Limiting** | No | Brute-force protection detection |
| **Service Exposure** | Partial | Redis no-auth, K8s API, SMTP relay |

The header, cookie, CSP and form checks (and `no_rate_limiting`) follow a redirect only while it stays on the probed host (`_get_on_host`; http to https on the same name is followed). A page another host serves after a redirect is not judged as this host's, and that host gets no request, so an apex that only redirects to `www` gets no header findings of its own.

### Which hosts the checks probe

A domain run hands the checks its whole DNS block and port scan. Three gates in
`recon/helpers/security_checks.py` decide which of those hosts get a request.
IP mode keeps its own rules (a target's live ports, redirect hops onto targets).

**Only a web port the run found live.** A host is probed on `:80` or `:443`
only when this run has evidence that the port is live there
(`_domain_live_ports`): the port scan lists it open on the address, or found it
by name (live on the name and its address), or httpx reached a URL on it (by the
URL's host and the address httpx used). A name has every port that is live on
an address it resolves to (the run's DNS and the port scan's name maps), since
it is the same TCP endpoint. So an HTTP-only host gets its `:80` checks and no
`:443` connection, the WAF bypass pairs a name with an address only when both
are live on `:443`, and the bare-origin comparison skips a name that is not live
on the port. The log says `[*][SecurityCheck] A host is probed only on a web
port this run found live (:80 on N, :443 on M of T host(s))`.

A host left unprobed is never marked unreachable (`_keep_unproven_domain_hosts`):

- A host with no live port at all in that data is not probed. The port scan and
  httpx do not reach every name the checks read (a name found after them, a name
  naabu never got), so their silence is no verdict.
- When an evidence source was cut (naabu, masscan or httpx stopped early or
  failed) and no finished port scan says a port is closed, a host with an
  unproven web port is kept the same way.

Both keep their `security_check` findings, for that source alone, through a
`security_checks` coverage gap ("no live web port in this run's port or URL
data"), and the log says `[!][SecurityCheck] N host(s) without live-port
evidence for a web check: not probed there, earlier findings kept`. A run whose
port and URL data show nothing live at all probes every host on both ports, as
before the gate.

A deliberate refusal is no cut (`_REFUSAL_GAP_SOURCES` in
`recon/helpers/security_checks.py`): the gap naabu or masscan records when the
RoE gate keeps a target from it (`{"source": "roe_excluded", "module": "naabu"}`;
the scanner still scanned every target it was allowed), and the `httpx_jarm` /
`httpx_favicon` gaps the RoE ceiling leaves when it turns those fingerprints off
(httpx still probed every URL). So under an RoE exclusion a finished port scan
stays a verdict: an HTTP-only or HTTPS-only host is no longer kept as unproven,
and its stale `security_check` findings are pruned. Any other gap under an evidence
source, an unknown or new one included, still counts as a cut. IP mode
(`_keep_unproven_targets`) and `vhost_sni_enum` read the same cuts.

**The Rules of Engagement.** The three target lists (the direct-IP checks'
addresses, the WAF bypass's name-address pairs, the hostname checks' names) pass
`target_admission.admit_host_targets` (`_domain_roe_hosts`):

- an excluded address is never probed;
- a name with any excluded address is neither probed by name (the HTTP stack
  would resolve it onto any of its addresses) nor paired with an address, while
  its allowed addresses are still checked as bare IPs;
- a name an entry excludes by name takes the addresses only it holds with it.

The port and service checks drop an excluded address and an address held only
by excluded names, as nmap does (`admit_ip_map`, `_domain_roe_port_ips`). The
RoE list comes from the caller, else from a partial builder's `metadata.roe`.
Each refusal is logged once per run (`[-][RoE] security_checks: not sent to N
target(s) the Rules of Engagement exclude: <address> (<name>), ...`) and noted
under `roe_excluded`, and each refused host is kept as not checked for
`security_check` alone (`[-][SecurityCheck] N host(s) the Rules of Engagement
refuse: not checked, earlier findings kept`). With no exclusion the gate
changes nothing.

**Redirect chains.** `check_direct_ip_http` and `check_direct_ip_https` follow
an address's redirects hop by hop (`_follow_admitted_redirects` with
`_domain_redirect_admission`), not through requests' own following. A hop is
sent only to one of the run's own hosts that the RoE admit: a name the run
resolved (its DNS and the port scan's name maps) or an address they hold.
`hop_guard.hop_refusal` asks the RoE again for each hop, on the name's current
addresses. A third party, an address the run never resolved (cloud metadata, an
internal service the target points at) and an excluded host get no request; no
SSRF guard is added on top, so an internal project's own private addresses
still pass. A refused hop counts no host failure: the chain ends there and is
reported as where the target pointed (`final_url` is the refused `Location`).
Each hop takes its own slot of the RoE rate ceiling.

**Partial runs.** `run_security_checks_partial` reads the graph through
`_build_vuln_scan_data_from_graph`, so its evidence is the graph's open `Port`
nodes and `BaseURL`s, and a graph host follows the rule above. A subdomain or IP
typed into the modal that the graph has no live row for is probed on both web
ports, as before the gate: the run stamps the typed hosts and a typed name's
resolved addresses in `metadata.typed_hosts` (not in IP mode). A typed host the
graph has evidence for follows it, a name that only shares a typed address gains
nothing, and the RoE gate still refuses an excluded typed host and a typed name
with any excluded address.

The builder keeps a graph name's RoE-excluded address in the `dns` block, which
every reader's gate reads, and out of `port_scan.by_ip`, a `BaseURL`'s resolved
address and the nmap services the CVE lookup reads. While the run has
exclusions (outside IP mode) it stamps the run's RoE in `metadata.roe`. So the
partial security checks, Nuclei and Subdomain Takeover refuse a graph name with
one excluded and one allowed address by name, and a name whose only address is
excluded as excluded, not as unresolved.

### Check Categories

#### Authentication Security
| Check | Severity | Description |
|-------|----------|-------------|
| `login_no_https` | High | Login form served over HTTP: only a page with a password input, and only when a made-up path next to it answers differently (the catch-all control, recorded as `control_check`) |
| `session_no_secure` | Medium | Session cookie missing Secure flag |
| `session_no_httponly` | Medium | Session cookie missing HttpOnly flag (never on an anti-CSRF cookie such as `csrftoken` or `XSRF-TOKEN`, which the page's JavaScript must read) |
| `basic_auth_no_tls` | High | Basic Auth over unencrypted HTTP |

#### TLS / Certificates
| Check | Severity | Description |
|-------|----------|-------------|
| `tls_expiring_soon` | Low | Certificate expires within `SECURITY_CHECK_TLS_EXPIRY_DAYS` |
| `tls_expired` | High | Certificate already expired |
| `tls_self_signed` | Medium | Self-signed certificate |
| `tls_hostname_mismatch` | Low / Medium | Certificate does not name the host |
| `tls_weak_version` | Medium | A weak TLS version negotiated or supported |
| `tls_weak_cipher` | Medium | A weak cipher negotiated or supported |
| `tls_wildcard_overbroad` | Low | Wildcard certificate with an overbroad SAN list |

The hygiene checks (all but `tls_expiring_soon`) read stored certificate data and send nothing; they also run when the active scans are skipped.

#### Security Headers
| Check | Severity | Description |
|-------|----------|-------------|
| `missing_referrer_policy` | Low | No `Referrer-Policy` |
| `missing_permissions_policy` | Low | No `Permissions-Policy` |
| `missing_coop` / `missing_corp` / `missing_coep` | Info | No cross-origin isolation headers |
| `cache_control_missing` | Info | No `no-store` / `no-cache` / `private` |

#### DNS Security
| Check | Severity | Description |
|-------|----------|-------------|
| `spf_missing` | Medium | No SPF record (email spoofing risk) |
| `dmarc_missing` | Medium | No DMARC record |
| `dnssec_missing` | Low | DNSSEC not enabled |
| `zone_transfer` | High | DNS zone transfer allowed (AXFR) |

#### Port/Service Security
| Check | Severity | Description |
|-------|----------|-------------|
| `admin_port_exposed` | Medium | SSH/RDP/VNC/Telnet publicly accessible |
| `database_exposed` | High | MySQL/PostgreSQL/MongoDB/Redis exposed |
| `redis_no_auth` | Critical | Redis responds without authentication |
| `kubernetes_api_exposed` | Critical/High | K8s API publicly accessible |
| `smtp_open_relay` | High | SMTP server accepts external relay |

#### Application Security
| Check | Severity | Description |
|-------|----------|-------------|
| `csp_unsafe_inline` | Medium | CSP allows 'unsafe-inline' |
| `insecure_form_action` | High | HTTPS form posts to HTTP |

#### Rate Limiting
| Check | Severity | Description |
|-------|----------|-------------|
| `no_rate_limiting` | Medium | No rate limit on login endpoints: one GET, then 10 login POSTs all processed (2xx, 3xx or 401) with no throttling status, header or text; redirects followed only on the same host |

#### Direct IP Access
| Check | Severity | Description |
|-------|----------|-------------|
| `direct_ip_http` / `direct_ip_https` | Varies | Content served on the bare IP over HTTP / HTTPS |
| `ip_api_exposed` | High / Medium | An API path (`/api`, `/api/v1`, `/api/v2`, `/graphql`, `/rest`, `/v1`, `/v2`) answers on the bare IP over plain HTTP: `200` + JSON is High, an API's own `401`/`403` is Medium |
| `waf_bypass` (`payload_differential`) | High | The edge blocks a WAF-signature probe that the origin, addressed by IP with the real Host header, serves |
| `cache_purge_exposed` | High | The cache at the IP accepts an unauthenticated `PURGE`/`BAN` that a bogus control method does not get |

**The catch-all control (`ip_api_exposed`).** Many servers answer every path
alike (`200 {"code":"NOT_FOUND"}`, an SPA shell). After a `200` + JSON hit the
check asks the same server for a path that cannot exist next to it
(`<parent prefix>rdm-<12 hex>`, through the same `_hh_get`, headers and
`allow_redirects=False`; `recon/helpers/catchall.py`). The same answer means the
hit proves nothing: the path is skipped and the next one tried. A real hit
records `control_check: passed` in its evidence and as a `control_check`
property; a control that could not be sent or read keeps the finding as
`control_check: failed` (never evidence either way). "The same answer" is the
same status (2xx/3xx by class, others exactly) and normalised bodies (the echoed
path, nonce, hostname and request ids stripped) within 64 bytes or 5%, word
counts within 5 or 10%, sharing at least 90% of their tokens. One control is
sent per IP and path prefix per run (`ControlCache`), never to an RoE-excluded
host, and the run logs how many it sent. JS Recon's endpoint validation uses
the same control (`validation_status: catch_all`, no Endpoint node).

**The payload differential (`waf_bypass`).** A bypass needs the edge to block
the probe (403, 406, 429, 501, 999 or 202) **and** the origin to serve it: a
**2xx** answer whose normalised body shares at least 80% of its tokens with the
page the edge serves for a benign request to `https://<host>/` (one extra
request, sent only once a probe is a candidate). A 302 to login, a 401, a 404
or a 421 from the origin is the origin refusing; a 2xx default page that is not
the site, or an edge with no 2xx page of its own, gives no finding either. The
evidence carries `edge_status`, `origin_status`, `edge_baseline_status` and
`body_similarity`, and the Priority Board rates the method's confidence 0.95.
The `waf-bypass` guinea pig exercises it.

**Challenge pages.** A Cloudflare challenge (`cf-mitigated`,
`challenge-platform`, "Just a moment...") or an Akamai "Access Denied" page with
a reference number is the edge answering, not the target. `ip_api_exposed`
stops probing a challenged IP and reports nothing for it, and the host is
recorded once per run as a `challenge_blocked` coverage gap of `vuln_scan`, so
the report's Coverage Limitations shows it was not really checked. A challenged
control is "no conclusion" and records the same gap.

**User-Agent.** The checks send `DEFAULT_BROWSER_UA`
(`recon/helpers/user_agent.py`), the full desktop Chrome string httpx and katana
default to; a bare `Mozilla/5.0` or a truncated Chrome string is what bot rules
match first.

### Configuration

All checks are enabled by default. Disable in the webapp project settings:

```python
# Global switch
SECURITY_CHECK_ENABLED = True  # Set False to skip all custom checks

# Individual checks
SECURITY_CHECK_LOGIN_NO_HTTPS = True
SECURITY_CHECK_SPF_MISSING = True
SECURITY_CHECK_REDIS_NO_AUTH = True
SECURITY_CHECK_NO_RATE_LIMITING = True
# ... one SECURITY_CHECK_<NAME> key per check (see the settings registry)

# Performance
SECURITY_CHECK_TIMEOUT = 10   # Request timeout (seconds)
SECURITY_CHECK_MAX_WORKERS = 10  # Parallel workers
SECURITY_CHECK_TLS_EXPIRY_DAYS = 30  # tls_expiring_soon threshold
```

Stealth mode turns off `direct_ip_http`, `direct_ip_https`, `waf_bypass`, `admin_port_exposed`, `database_exposed`, `redis_no_auth`, `kubernetes_api_exposed`, `smtp_open_relay`, `zone_transfer` and `no_rate_limiting`. `WAF_AI_CLASSIFIER` (driven by the AI-in-pipeline switch) adds an LLM classification of WAF/CDN presence when the static check misses.

### Output Structure

Custom security check findings are stored in `vuln_scan.security_checks`:

```json
{
  "vuln_scan": {
    "security_checks": {
      "scan_timestamp": "2025-01-04T12:00:00",
      "checks_enabled": {"redis_no_auth": true, "spf_missing": true, "...": true},
      "targets_checked": {"hostnames": 5, "ips": 2},
      "findings": [
        {
          "type": "redis_no_auth",
          "severity": "critical",
          "name": "Redis Without Authentication",
          "description": "Redis at 192.168.1.100:6379 responds to commands without authentication. ...",
          "ip": "192.168.1.100",
          "port": 6379,
          "evidence": "PING command returned PONG without authentication",
          "recommendation": "Enable Redis AUTH and use strong passwords. Never expose Redis to the internet."
        }
      ],
      "by_type": {
        "redis_no_auth": [...]
      },
      "summary": {
        "total_findings": 5,
        "critical": 1,
        "high": 2,
        "medium": 2,
        "low": 0,
        "info": 0
      }
    }
  }
}
```
