# RedAmon - Port Scanning (Masscan + Naabu)

## Complete Technical Documentation

> **Modules:** `recon/main_recon_modules/masscan_scan.py`, `recon/main_recon_modules/port_scan.py`
> **Purpose:** High-speed port scanning using Masscan and Naabu in parallel
> **Author:** RedAmon Security Suite

---

## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Requirements](#requirements)
4. [Configuration Parameters](#configuration-parameters)
5. [Architecture & Flow](#architecture--flow)
6. [Output Data Structure](#output-data-structure)
7. [Usage Examples](#usage-examples)
8. [Troubleshooting](#troubleshooting)

---

## Overview

The `port_scan.py` module integrates ProjectDiscovery's Naabu scanner into RedAmon's reconnaissance pipeline. Naabu is optimized for fast, reliable port scanning at scale.

**⚠️ Important:** Naabu runs exclusively via Docker, as a sibling container the recon container starts with `docker run`. No native installation is supported.

### Why Naabu?

| Feature | Traditional Scanners | Naabu |
|---------|---------------------|-------|
| Speed | Minutes-hours | **Seconds-minutes** |
| Resource Usage | High | **Low** |
| Docker Support | Variable | **Native** |
| CDN Detection | Limited | **Built-in** |
| Rate Control | Basic | **Fine-grained** |

### How It Works

```
┌─────────────────┐     ┌──────────────────────┐     ┌─────────────────┐
│  Recon Data     │────▶│  port_scan.py        │────▶│  port_scan key  │
│  (hostnames,    │     │                      │     │  with ports,    │
│   IPs from DNS) │     │  1. Extract targets  │     │  services, CDN  │
└─────────────────┘     │  2. Write targets    │     └─────────────────┘
                        │  3. Run Naabu        │
                        │     (SYN, CONNECT    │
                        │      fallback)       │
                        │  4. Parse JSON Lines │
                        └──────────────────────┘
```

---

## Features

| Feature | Description |
|---------|-------------|
| **Fast Scanning** | SYN scan with configurable rate limiting |
| **CONNECT Fallback** | A SYN scan that crashes, fails or finds no open port is retried once as a CONNECT scan |
| **CDN Detection** | Identifies CDN-protected hosts (Cloudflare, Akamai, etc.) |
| **Service Detection** | Maps each open port to a service name (IANA registry) |
| **AI Port Catalogue** | Tags ports of known AI runtimes, vector databases and frontends with `ai_service` |
| **Docker Execution** | No local installation required |
| **Passive Mode** | Query Shodan InternetDB instead of active scanning |

---

## Requirements

Nothing to install by hand: the recon container reaches the host's Docker daemon
and, on first use, `pull_naabu_docker_image()` pulls the Naabu image. Masscan is
a native binary built from source into the recon image (`recon/Dockerfile`).

- **Docker** reachable from the recon container. `run_port_scan()` checks
  `docker` is on the path and `docker info` answers, and skips the scan otherwise.
- **Raw sockets** for SYN scans. Naabu runs with `--net=host`; when a SYN scan
  cannot run, the module retries it as a CONNECT scan by itself. Masscan has no
  such fallback and needs root or `CAP_NET_RAW`.

To pre-pull the image:

```bash
docker pull projectdiscovery/naabu:latest
```

---

## Configuration Parameters

All parameters are set in the webapp project settings (stored in PostgreSQL) and reach the module as the runtime keys below; `recon/project_settings.py` holds the fallback defaults. Each field's meaning and bounds are in the settings registry (`recon_settings/registry.yaml`).

Three things can change a value at scan start: the engagement ceiling (`apply_roe_rate_cap`) caps `NAABU_RATE_LIMIT` and `MASSCAN_RATE`, the memory governor can lower `NAABU_THREADS`, and stealth mode overrides several keys (see [Stealth Mode Behavior](#stealth-mode-behavior)).

### Toggles

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `NAABU_ENABLED` | `bool` | `True` | Run Naabu inside the port-scan phase |
| `PORT_SCAN_AI_PORT_CATALOG_ENABLED` | `bool` | `True` | Annotate Naabu's ports that match the AI port catalogue |

The phase itself runs only when `port_scan` is in the project's scan modules (`SCAN_MODULES`).

### Docker Settings

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `NAABU_DOCKER_IMAGE` | `str` | `"projectdiscovery/naabu:latest"` | Fixed: the image RedAmon ships for this tool. Not a project setting. |

### Port Selection

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `NAABU_TOP_PORTS` | `str` | `"1000"` | Number of top ports, passed to `-top-ports` ("100", "1000", "full") |
| `NAABU_CUSTOM_PORTS` | `str` | `""` | Custom ports (overrides TOP_PORTS) |

**Port Examples:**
```python
NAABU_TOP_PORTS = "100"           # Top 100 ports
NAABU_TOP_PORTS = "1000"          # Top 1000 ports (default)
NAABU_CUSTOM_PORTS = "22,80,443"  # Specific ports
NAABU_CUSTOM_PORTS = "1-65535"    # Full port range
```

### Scan Type

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `NAABU_SCAN_TYPE` | `str` | `"s"` | Scan type: "s" (SYN) or "c" (CONNECT) |

**Scan Types:**
- `"s"` (SYN) - Faster, more reliable, **requires raw sockets**
- `"c"` (CONNECT) - No raw sockets needed, full TCP handshake

With `"s"`, a run that crashes (SIGSEGV), fails with an error, or finds no open ports (a firewall may be dropping SYN probes) is retried once with `"c"`, and the result records `scan_metadata.scan_type_fallback: true`.

**SYN Scan (Half-Open) - Default:**
```
   You                                    Target
    │                                        │
    │──────────── 1. SYN ───────────────────►│
    │                                        │
    │◄─────────── 2. SYN/ACK ───────────────│  ← Port OPEN
    │                                        │
    │──────────── 3. RST (abort) ───────────►│  ← Connection killed
    │                                        │
    │         ❌ NO CONNECTION ESTABLISHED    │
    │         ❌ MINIMAL LOGGING ON TARGET    │
```

**CONNECT Scan (Full TCP):**
```
   You                                    Target
    │                                        │
    │──────────── 1. SYN ───────────────────►│
    │                                        │
    │◄─────────── 2. SYN/ACK ───────────────│
    │                                        │
    │──────────── 3. ACK ───────────────────►│  ← FULL HANDSHAKE
    │                                        │
    │         ✅ CONNECTION ESTABLISHED       │
    │         ✅ LOGGED BY APPLICATION        │
    │                                        │
    │──────────── 4. FIN ───────────────────►│
    │◄─────────── 5. FIN/ACK ───────────────│  ← GRACEFUL CLOSE
    │──────────── 6. ACK ───────────────────►│
```

**Comparison:**

| Aspect | SYN (`-scan-type s`) | CONNECT (`-scan-type c`) |
|--------|--------------|------------------|
| Packets sent | 2 (SYN, RST) | 6+ (full handshake) |
| Speed | ⚡ Faster | 🐢 Slower |
| Stealth | 🥷 Stealthier | 👀 Easily detected |
| Application logging | ❌ Usually not | ✅ Logged |
| Requires raw sockets | ✅ Yes | ❌ No |

### Performance Settings

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `NAABU_RATE_LIMIT` | `int` | `1000` | Packets per second |
| `NAABU_THREADS` | `int` | `25` | Concurrent threads |
| `NAABU_TIMEOUT` | `int` | `10000` | Timeout per port (ms) |
| `NAABU_RETRIES` | `int` | `1` | Retries for failed probes |
| `NAABU_RUN_TIMEOUT` | `int` | `1800` | Cap on the whole naabu run (s); a cut run keeps the ports it wrote |

**Recommended Settings:**

| Scenario | Rate Limit | Threads | Timeout |
|----------|------------|---------|---------|
| **Safe/Slow** | 500 | 10 | 15000 |
| **Normal** | 1000 | 25 | 10000 |
| **Aggressive** | 3000 | 50 | 5000 |
| **Internal Network** | 5000+ | 100 | 3000 |

### Feature Flags

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `NAABU_EXCLUDE_CDN` | `bool` | `False` | Skip non-standard ports on CDN hosts (`-exclude-cdn`) |
| `NAABU_DISPLAY_CDN` | `bool` | `True` | Show CDN information in output (`-cdn`) |
| `NAABU_SKIP_HOST_DISCOVERY` | `bool` | `True` | Assume all hosts are up (`-Pn`) |
| `NAABU_VERIFY_PORTS` | `bool` | `True` | Extra TCP check to verify ports (`-verify`) |
| `NAABU_PASSIVE_MODE` | `bool` | `False` | Use Shodan InternetDB, no active scan (`-passive`) |

---

#### `NAABU_EXCLUDE_CDN` - CDN Port Filtering

**Problem:** CDN providers (Cloudflare, Akamai, AWS CloudFront) expose thousands of ports on their edge servers that belong to the CDN infrastructure, not the actual target.

```
Without CDN Exclusion:
┌─────────────────────────────────────────────────────────────────┐
│  Target: example.com (behind Cloudflare)                        │
│                                                                 │
│  Scan Result: Ports 22, 80, 443, 2052, 2053, 2082, 2083,       │
│               2086, 2087, 2095, 2096, 8080, 8443...            │
│                                                                 │
│  Reality: Only 80/443 are YOUR server                          │
│           All others are Cloudflare's infrastructure ❌         │
└─────────────────────────────────────────────────────────────────┘

With CDN Exclusion (NAABU_EXCLUDE_CDN = True):
┌─────────────────────────────────────────────────────────────────┐
│  Target: example.com (behind Cloudflare)                        │
│                                                                 │
│  Scan Result: Ports 80, 443                                    │
│  CDN Detected: cloudflare ✅                                    │
│                                                                 │
│  Clean results - only ports that reach YOUR origin server      │
└─────────────────────────────────────────────────────────────────┘
```

| Setting | Behavior |
|---------|----------|
| `True` | Only scan 80/443 on CDN hosts, skip other ports |
| `False` (default) | Scan all ports (includes CDN infrastructure noise) |

---

#### `NAABU_DISPLAY_CDN` - CDN Detection Display

Shows which CDN provider protects each host in the output: `cdn` is Naabu's `cdn-name`, and `is_cdn` is true when Naabu reported a CDN at all.

```json
{
  "host": "cdn.example.com",
  "ip": "104.16.123.96",
  "ports": [80, 443],
  "cdn": "cloudflare",    // ← This field
  "is_cdn": true          // ← And this field
}
```

**Detected CDN Providers:**
- Cloudflare, Akamai, Fastly, AWS CloudFront
- Google Cloud CDN, Azure CDN, Incapsula
- MaxCDN, KeyCDN, StackPath, and more

Naabu's flag is one of several that reach `IP.is_cdn`: tlsx adds a CDN named
by a certificate issuer, httpx its own `-cdn` result, and IP attribution a
shared edge it recognised from a published prefix, a response header or an
edge-only ASN (`cdn_source` names the tool when it was not naabu; none of them
ever clears the flag). A cloud label (`aws`, `google`) is not a shared edge.
The attribution itself is `IP.ownership` (see README.RECON.md, "IP
attribution"): later modules read that tag rather than `is_cdn`.

---

#### `NAABU_SKIP_HOST_DISCOVERY` - Skip Ping Check (`-Pn`)

**Host Discovery** = Check if host is alive before scanning ports.

```
WITH Host Discovery (NAABU_SKIP_HOST_DISCOVERY = False):
┌─────────────────────────────────────────────────────────────────┐
│   You                                        Target             │
│    │                                            │               │
│    │   PHASE 1: Is host alive?                  │               │
│    │                                            │               │
│    │──────────── ICMP Ping ────────────────────►│               │
│    │◄─────────── Pong (or timeout) ────────────│               │
│    │                                            │               │
│    │   If NO response → Host "DOWN" → SKIP ❌   │               │
│    │   If response → Continue to port scan      │               │
│    │                                            │               │
│    │   PHASE 2: Port scan (only if UP)          │               │
│    │──────────── SYN port 80 ──────────────────►│               │
└─────────────────────────────────────────────────────────────────┘

WITHOUT Host Discovery (NAABU_SKIP_HOST_DISCOVERY = True):
┌─────────────────────────────────────────────────────────────────┐
│   You                                        Target             │
│    │                                            │               │
│    │   SKIP Phase 1 - Assume host is UP         │               │
│    │                                            │               │
│    │   Go directly to port scanning             │               │
│    │──────────── SYN port 80 ──────────────────►│               │
│    │──────────── SYN port 443 ─────────────────►│               │
└─────────────────────────────────────────────────────────────────┘
```

| Setting | Behavior | Use When |
|---------|----------|----------|
| `True` (default) | Skip ping, assume all hosts UP | Firewalls block ICMP, hosts from DNS |
| `False` | Ping first, skip "dead" hosts | Large IP ranges, internal networks |

**Why default is `True`:** RedAmon already confirmed hosts exist via DNS resolution. Many firewalls block ICMP ping, causing false negatives.

---

#### `NAABU_VERIFY_PORTS` - Double-Check Open Ports

After finding an open port via SYN scan, perform an additional TCP connection to verify.

```
Without Verification:
┌─────────────────────────────────────────────────────────────────┐
│   SYN scan says port 8080 is OPEN                              │
│   → Report as open (might be false positive)                   │
└─────────────────────────────────────────────────────────────────┘

With Verification (NAABU_VERIFY_PORTS = True):
┌─────────────────────────────────────────────────────────────────┐
│   SYN scan says port 8080 is OPEN                              │
│   → Try full TCP connection to verify                          │
│   → Connection successful? Report as open ✅                    │
│   → Connection failed? Discard (was false positive) ❌          │
└─────────────────────────────────────────────────────────────────┘
```

| Setting | Behavior | Trade-off |
|---------|----------|-----------|
| `True` (default) | Verify each open port with TCP connect | More accurate, slightly slower |
| `False` | Trust SYN scan results directly | Faster, may have false positives |

**Reduces false positives from:**
- Stateful firewalls that RST after SYN/ACK
- Load balancers with connection limits
- Rate-limiting that causes inconsistent responses

---

#### `NAABU_PASSIVE_MODE` - Shodan InternetDB (No Active Scan)

Instead of actively scanning the target, query **Shodan's InternetDB** for known open ports.

```
Active Scanning (NAABU_PASSIVE_MODE = False):
┌─────────────────────────────────────────────────────────────────┐
│   You ──────── SYN packets ──────────────────► Target           │
│                                                                 │
│   • Sends packets to target                                    │
│   • Target sees your IP                                        │
│   • May trigger IDS/IPS alerts                                 │
│   • Real-time results                                          │
└─────────────────────────────────────────────────────────────────┘

Passive Mode (NAABU_PASSIVE_MODE = True):
┌─────────────────────────────────────────────────────────────────┐
│   You ──────── API query ──────────────────► Shodan InternetDB  │
│                                                                 │
│   • NO packets to target                                       │
│   • Target never sees you                                      │
│   • 100% stealth                                               │
│   • Data may be days/weeks old                                 │
└─────────────────────────────────────────────────────────────────┘
```

| Setting | Behavior | Trade-off |
|---------|----------|-----------|
| `False` (default) | Active SYN scan | Real-time, target aware |
| `True` | Query Shodan database | Stealth, but potentially stale data |

**Use Passive Mode when:**
- Initial reconnaissance (don't want to touch target yet)
- Target has strict IDS/IPS
- Legal constraints on active scanning
- Quick overview before active scan

**Limitations:**
- Data freshness depends on Shodan's last scan
- May miss recently opened ports
- May show ports that are now closed

### CDN Handling

When `NAABU_EXCLUDE_CDN = True`:
- CDN-protected hosts only scanned on ports 80/443
- Reduces false positives from CDN edge servers
- Still reports CDN detection in output

### How an IP gets its CDN tag (`IP.is_cdn`, `cdn_name`, `cdn_source`)

Three scanners can say an IP is a CDN edge, and all three reach the graph:

| Source | When | Graph write |
|---|---|---|
| naabu `-cdn` | GROUP 3, port scan | `update_graph_from_port_scan` raises `is_cdn` from `port_scan.by_ip` and `port_scan.by_host` and fills a blank `cdn_name` (no `cdn_source`). It never lowers `is_cdn` and keeps the first `cdn_name`, so a later port write (masscan, late names, a second batch group, a partial run) cannot untag an edge |
| httpx `-cdn` | GROUP 4, per URL | on the `Endpoint` (`is_cdn`, `cdn`); readers that need an IP's tag also read `http_probe.by_url` |
| tlsx certificate issuer | GROUP 3.6 | `_attribute_cdn` (`recon/main_recon_modules/tls_scan.py`) fills a **blank** tag on `port_scan.by_ip` from the issuer (Cloudflare, Akamai, Fastly, Sucuri, Incapsula/Imperva; never Amazon, since ACM certificates sit on real origins, and never a Cloudflare Origin CA issuer, whose certificate only an origin presents; `cdn_from_certificate` in `recon/helpers/cdn_ranges.py`) and lists those IPs in the tlsx payload as `cdn_by_ip` |

The port graph write runs **before** tlsx in a full run, so the tlsx graph writer
(`update_graph_from_tlsx`) carries its own tag: for each IP in `cdn_by_ip` it
sets `is_cdn = true`, fills a blank `cdn_name`, and stamps `cdn_source = 'tlsx'`
unless another tool tagged the IP first. It MATCHes the tenant-scoped IP (never
creates one) and never writes `is_cdn = false`.

Partial runs rebuild `port_scan` from the graph (`_build_port_scan_data_from_graph`)
and carry each IP's existing `is_cdn` / `cdn_name`. Every port detail the builder
makes names its own IP and carries the graph's `passive_only` mark, so a
hostname's second address keeps its own ports. Partial Nmap, httpx and tlsx then
write back only what they measured (`measured_port_data`): Nmap the custom ports
still open, httpx the typed targets' ports that answered, tlsx none of the
graph's own ports. The writer lowers `Port.passive_only` only for a port its
caller saw, so a Shodan-only port does not turn into an actively found one.
nmap, httpx and GVM lower it too, in a full and a partial run alike:
`update_graph_from_nmap` on every open port nmap reports on an address, on the
Port of the protocol it scanned (a TCP answer says nothing of UDP),
`update_graph_from_http_probe` on the TCP Port it got an HTTP answer from, and
`update_graph_from_gvm_scan` on the Port of the protocol it detected a service
on. A Port no active tool reported keeps its mark.

**One CDN list.** `recon/helpers/cdn_ranges.py` is the single source every module
reads for "is this a CDN edge?": edge prefixes for Cloudflare, Fastly, CloudFront,
Azure Front Door, Imperva and Sucuri (static, `recon/helpers/cdn_edge_prefixes.py`,
each list with its source and retrieval date; nothing is fetched at run time
except the optional live Cloudflare list `is_cloudflare_ip` already used), the
edge ASNs (Cloudflare, Fastly, Akamai, Imperva, Sucuri; never a generic cloud
ASN), the certificate-issuer markers and the edge response-header signatures.
Origin discovery, `ip_filter` (Shodan, Netlas, Uncover, the OSINT enrichers),
security checks and vhost/SNI import it. Akamai has no prefix list: ARIN shows
compute (`AKAMAI-COMPUTE`, Linode) reassignments inside its CDN blocks, so a
prefix cannot tell an Akamai edge from a customer's server.

---

## Architecture & Flow

> **Pipeline context:** Port scanning runs in **GROUP 3** of the recon pipeline (`recon/main.py`), in one `ThreadPoolExecutor` with Shodan enrichment: `run_port_scan_isolated()` and `run_masscan_scan_isolated()` are handed the fan-out's shared snapshot (`_fan_out_snapshot`, a deep copy taken before the first submit), deep-copy it again, and return only their own payload (`port_scan`, `masscan_scan`). After the fan-in, `merge_port_scan_results()` folds `masscan_scan` into `port_scan`, the results are saved, and `update_graph_from_port_scan` writes them to the graph in the background. Nmap (GROUP 3.5) and tlsx (GROUP 3.6) then read the merged `port_scan`.

### Execution Flow (`run_port_scan`)

```
1. PRECHECKS
   └── NAABU_ENABLED off → return unchanged
   └── is_docker_installed() / is_docker_running()
   └── pull_naabu_docker_image() pulls the image if it is missing

2. TARGET EXTRACTION  (extract_targets_from_recon)
   └── dns.domain: the scan root and its IPs, only when the root is a target
       (recon_scope(...).include_root)
   └── dns.subdomains: every subdomain with records, and its IPv4/IPv6 IPs
   └── Build the IP-to-hostnames mapping
   └── RoE admission (admit_host_targets, module naabu): drop an excluded
       address, a name the RoE excludes, and a name left with no admitted
       address; under RoE IP/CIDR entries, hand naabu addresses only
   └── Target list = the hostnames followed by the IPs

3. SCAN EXECUTION
   └── Write targets.txt in a per-run dir /tmp/redamon/.naabu_temp_<id>
       (/tmp/redamon is the same path on the host, so no translation;
        get_host_path() maps /app/recon/output via HOST_RECON_OUTPUT_PATH)
   └── build_naabu_command() → docker run --name naabu-<run id>-<8 hex> ... -json
   └── Run with NAABU_RUN_TIMEOUT (1800 s by default)
   └── SYN run crashed, failed or found nothing → retry once as CONNECT
   └── Timeout → kill the container by its name, no CONNECT retry; keep the
       ports it wrote, list the targets it wrote none for in
       scan_metadata.unchecked_targets (timed_out set) and note them as not
       checked (module port_scan, source naabu); nothing written → no
       port_scan, plus a naabu coverage gap

4. RESULT PROCESSING  (parse_naabu_output)
   └── Parse the JSON Lines output line by line
   └── Group results by host and by IP (a bare IP with no host is keyed by the IP)
   └── Map ports to service names (get_service_name_friendly)
   └── Annotate AI-catalogue ports (_annotate_ai_port_catalog)
   └── Calculate summary statistics

5. RESULT
   └── recon_data["port_scan"] = {scan_metadata, by_host, by_ip, all_ports,
                                  ip_to_hostnames, summary}
   └── Written to output_file only when one is passed (the pipeline passes
       none and saves after the fan-in)
   └── The temp dir is removed
```

**RoE exclusions on resolved addresses.** An RoE IP or CIDR entry is checked on
every address a name resolved to, not only on IP targets
(`recon/helpers/target_admission.py`). An excluded address is never a naabu,
masscan or nmap target, and a name with one excluded and one allowed address is
scanned on the allowed one only. naabu resolves a name itself, so while an IP or
CIDR entry is set it is handed addresses only; each name still gets the ports
found on its addresses through `ip_to_hostnames`. Masscan and nmap pass their
address lists through the same gate (`admit_ip_map`), since the port scan's map
can carry an address a passive source added. Each refusal is logged once as
`[-][RoE] <tool>: not sent to ...` and noted under the coverage source
`roe_excluded`. With no exclusion in force every target list is unchanged.

**NSE redirects under RoE exclusions and in IP mode.** The NSE http scripts
follow a redirect through `http.lua`, whose default rule allows any host in the
domain of the target's reverse-DNS (PTR) name, and `--exclude` does not bind NSE
(nmap 7.93, the recon image's). So while any RoE exclusion is in force, and in IP
mode, `build_nmap_command` (`recon/main_recon_modules/nmap_scan.py`) adds `-n`,
which leaves the target no name, so the rule allows only the same IP literal.
With `NMAP_SCRIPT_SCAN` on it also passes `--script "vuln and not
http-cross-domain-policy"` (`NSE_SCRIPTS_SAME_HOST`) instead of `--script vuln`:
`http-cross-domain-policy` hands `http.get` a redirect rule of its own (three
hops, no host rule). Under exclusions the run logs `[*][Nmap] NSE redirects kept
on the target address (-n, no http-cross-domain-policy): RoE exclusions are in
force`. The NSE requests then carry the address, not the PTR name, as `Host`. No
stored field changes: the XML parser keys hosts by the run's own
`ip_to_hostnames` map and never reads nmap's hostnames. A partial run reads the
exclusions from `metadata.roe`. Domain mode with no exclusion keeps
`--script vuln` and no `-n` (`recon/tests/test_roe_redirect_following.py`,
`recon/tests/test_nmap_ip_mode_no_dns.py`).

### Docker Command Structure

What `build_naabu_command()` produces with the default settings:

```bash
docker run --rm \
  --net=host \                              # Required for SYN scans
  -v /tmp/redamon/.naabu_temp_<id>:/targets:ro \
  -v /tmp/redamon/.naabu_temp_<id>:/output \
  projectdiscovery/naabu:latest \
  -list /targets/targets.txt \
  -o /output/naabu_output.json \
  -json \
  -silent \
  -top-ports 1000 \                         # -p <ports> when NAABU_CUSTOM_PORTS is set
  -scan-type s \
  -rate 1000 \
  -c 25 \
  -timeout 10000 \
  -retries 1 \
  -cdn \                                    # NAABU_DISPLAY_CDN
  -Pn \                                     # NAABU_SKIP_HOST_DISCOVERY
  -verify                                   # NAABU_VERIFY_PORTS
```

`-exclude-cdn` and `-passive` are added when `NAABU_EXCLUDE_CDN` and `NAABU_PASSIVE_MODE` are on.

---

## Output Data Structure

### Complete JSON Schema

```json
{
  "port_scan": {
    "scan_metadata": {
      "scan_timestamp": "2024-01-15T12:00:00.000000",
      "scan_duration_seconds": 45.2,
      "docker_image": "projectdiscovery/naabu:latest",
      "scan_type": "syn",
      "scan_type_fallback": false,
      "ports_config": "top-1000",
      "rate_limit": 1000,
      "passive_mode": false,
      "proxy_used": false,
      "total_targets": 15,
      "cdn_exclusion": false
    },

    "by_host": {
      "example.com": {
        "host": "example.com",
        "ip": "93.184.216.34",
        "ports": [80, 443, 11434],
        "port_details": [
          {
            "port": 80,
            "protocol": "tcp",
            "service": "http",
            "ip": "93.184.216.34"
          },
          {
            "port": 443,
            "protocol": "tcp",
            "service": "https",
            "ip": "93.184.216.34"
          },
          {
            "port": 11434,
            "protocol": "tcp",
            "service": "ollama",
            "ip": "93.184.216.34",
            "ai_service": {
              "name": "ollama",
              "category": "ai-runtime",
              "detected_by": "naabu-ai-port"
            }
          }
        ],
        "cdn": null,
        "is_cdn": false
      },
      "cdn.example.com": {
        "host": "cdn.example.com",
        "ip": "104.16.123.96",
        "ports": [80, 443],
        "port_details": [...],
        "cdn": "cloudflare",
        "is_cdn": true
      }
    },

    "by_ip": {
      "93.184.216.34": {
        "ip": "93.184.216.34",
        "hostnames": ["example.com", "www.example.com"],
        "ports": [80, 443, 11434],
        "cdn": null,
        "is_cdn": false
      }
    },

    "all_ports": [22, 80, 443, 3306, 11434],

    "ip_to_hostnames": {
      "93.184.216.34": ["example.com", "www.example.com"]
    },

    "summary": {
      "hosts_scanned": 15,
      "ips_scanned": 12,
      "hosts_with_open_ports": 10,
      "total_open_ports": 45,
      "unique_ports": [22, 80, 443, 3306, 11434],
      "unique_port_count": 5,
      "cdn_hosts": 3,
      "ai_ports_annotated": 1
    }
  }
}
```

- `scan_type` is the type that actually ran; `scan_type_fallback` is true when a SYN scan was retried as CONNECT.
- In a domain run every naabu and masscan port detail names the address it was found on (`ip`), one detail per address and port, so a name on two addresses keeps each address's ports apart: the graph writer puts a detail under its own `ip` (else under the entry's `ip`, the first address). The entry's `ports` lists every address's port numbers, which is what httpx builds its targets from. IP mode, whose `by_host` is keyed by address, has no detail `ip`. The readers keep the split: `merge_port_scan_results` (`recon/main.py`) folds masscan into naabu one detail per address and port, a name found after the port scan gets one detail per address and port, copied from that address's own (`recon/helpers/late_names.py`), and the banner grab and the tlsx enrichment of the port details read each detail's own `ip`.
- nmap's newly confirmed ports (`new_open_ports`, `recon/helpers/nmap_merge.py`) are judged per address: a port the name lists only for its other address is still new on this one, it joins every entry that spans the address (tagged with it when the entry's details are), and nmap's versions go to the detail on nmap's own address.
- `ai_service` appears only on ports the AI port catalogue (`recon/helpers/ai_signal_catalog.py`) knows. Ports the catalogue marks ambiguous (e.g. 8000, 8080) are not annotated here.
- When Masscan also ran, `merge_port_scan_results()` adds its hosts, ports and hostnames, sets `scan_metadata.scanners` to `["naabu", "masscan"]`, and recomputes `summary` (without `ai_ports_annotated`). When only Masscan ran, its payload becomes `port_scan` as it is.

### Service Name Mapping

`get_service_name_friendly()` (`recon/helpers/iana_services.py`) checks a short list of friendly overrides, then the IANA registry bundled as `recon/data/iana-services.csv`. Some common results:

| Port | Service |
|------|---------|
| 21 | ftp |
| 22 | ssh |
| 23 | telnet |
| 25 | smtp |
| 53 | domain |
| 80 | http |
| 110 | pop3 |
| 143 | imap |
| 443 | https |
| 445 | microsoft-ds |
| 3306 | mysql |
| 3389 | rdp |
| 5432 | postgresql |
| 6379 | redis |
| 8080 | http-proxy |
| 8443 | https-alt |
| 27017 | mongodb |

---

## Usage Examples

### Basic Usage (full pipeline)

The port-scan phase runs when the project's scan modules include `port_scan` (they do by default) and at least one of `NAABU_ENABLED` / `MASSCAN_ENABLED` is on. Start a recon scan from the webapp; the orchestrator spawns the recon container, which runs `recon/main.py` with the project's settings.

### Partial Recon

`recon/partial_recon_modules/port_scanning.py` runs one scanner on demand (`run_naabu`, `run_masscan`) against the graph's IPs and subdomains and any targets the user typed in, and writes only its own scan output with `update_graph_from_port_scan`.

### Standalone Enrichment

```python
from recon.main_recon_modules.port_scan import enrich_recon_file
from pathlib import Path

enriched = enrich_recon_file(Path("output/recon_example.com.json"))
```

`enrich_recon_file()` loads the settings with `get_settings()` (the project's settings when `PROJECT_ID` and `WEBAPP_API_URL` are set, `DEFAULT_SETTINGS` otherwise), runs `run_port_scan()` and writes the result back to the same file.

### Configuration Profiles

Values to enter in the project settings (shown as runtime keys):

**Quick Scan (Fast):**
```python
NAABU_TOP_PORTS = "100"
NAABU_RATE_LIMIT = 3000
NAABU_THREADS = 50
NAABU_VERIFY_PORTS = False
```

**Comprehensive Scan:**
```python
NAABU_TOP_PORTS = "1000"
NAABU_RATE_LIMIT = 1000
NAABU_THREADS = 25
NAABU_VERIFY_PORTS = True
```

**Stealth Scan:**
```python
NAABU_TOP_PORTS = "100"
NAABU_RATE_LIMIT = 100
NAABU_THREADS = 5
NAABU_SCAN_TYPE = "c"  # CONNECT instead of SYN
```

**Full Port Scan:**
```python
NAABU_CUSTOM_PORTS = "1-65535"
NAABU_RATE_LIMIT = 5000
NAABU_THREADS = 100
NAABU_TIMEOUT = 5000
```

---

## Troubleshooting

### Common Issues

#### "[!][Naabu] Docker is not installed" / "Docker daemon is not running"

Naabu runs through the host's Docker daemon. Check that Docker is running on the host (`docker info`) and that the recon container can reach it.

#### SYN scan fails or crashes

The module handles this by itself: it retries once with a CONNECT scan and logs `Retrying with CONNECT scan...`. `scan_metadata.scan_type_fallback` is then true. To skip the SYN attempt altogether:

```python
NAABU_SCAN_TYPE = "c"
```

Masscan has no fallback: `Permission denied — masscan requires root or CAP_NET_RAW` means it could not open a raw socket.

#### "No open ports found"

Possible causes:
1. Target firewall blocking scans
2. Rate limiting triggered
3. CDN blocking non-80/443 ports

Solutions:
```python
# Reduce rate limit
NAABU_RATE_LIMIT = 100

# Make sure CDN exclusion is off to see all ports
NAABU_EXCLUDE_CDN = False

# Try passive mode
NAABU_PASSIVE_MODE = True
```

#### Scan too slow

A Naabu run is stopped at `NAABU_RUN_TIMEOUT` (30 minutes by default), a Masscan
run after 30 minutes. A cut naabu run keeps the ports it wrote, and the targets it
wrote none for are recorded as not checked: their earlier findings are kept and
none of their ports reads as closed.

```python
# Increase performance
NAABU_RATE_LIMIT = 3000
NAABU_THREADS = 50
NAABU_TIMEOUT = 5000
NAABU_RETRIES = 1
```

### Debug Mode

Run Naabu manually via Docker:

```bash
docker run --rm --net=host \
  projectdiscovery/naabu:latest \
  -host example.com \
  -top-ports 100 \
  -v -debug
```

---

## Security Considerations

⚠️ **Legal Warning:** Only scan systems you have explicit permission to test.

| Risk | Mitigation |
|------|------------|
| Rate limiting/bans | Reduce `NAABU_RATE_LIMIT`, or set the engagement ceiling (`ROE_GLOBAL_MAX_RPS`) |
| IDS/IPS detection | Use CONNECT mode, lower rate, or stealth mode |
| CDN blocking | Use `NAABU_EXCLUDE_CDN = True` |
| Detection | Reduce rate limit |

### Safe Defaults

```python
NAABU_RATE_LIMIT = 500
NAABU_THREADS = 10
NAABU_TOP_PORTS = "100"
NAABU_EXCLUDE_CDN = True
```

---

## Dependencies

| Package | Purpose |
|---------|---------|
| Docker | Container runtime for Naabu |
| `projectdiscovery/naabu:latest` | Naabu Docker image (auto-pulled) |
| `masscan` | Native binary built from source in `recon/Dockerfile` |
| Python 3.11 | The recon image's runtime |

---

## References

- [Naabu Documentation](https://github.com/projectdiscovery/naabu)
- [Naabu Docker Hub](https://hub.docker.com/r/projectdiscovery/naabu)
- [ProjectDiscovery Blog](https://blog.projectdiscovery.io/)

---

# Masscan Port Scanner

## Overview

The `masscan_scan.py` module integrates Robert David Graham's Masscan — the fastest Internet port scanner — into RedAmon's reconnaissance pipeline. Masscan runs as a native binary built from source inside the recon container (not Docker-in-Docker). Masscan is **off** by default (`MASSCAN_ENABLED = False`); when it is on, it runs in parallel with Naabu and the results are merged and deduplicated automatically.

### Masscan vs Naabu

| Feature | Masscan | Naabu |
|---------|---------|-------|
| **Speed** | Fastest (10M+ pps capable) | Fast (1000s pps) |
| **Best for** | Large CIDR ranges, bulk IP scanning | Hostname-based scanning, CDN detection |
| **CDN Detection** | No | Built-in |
| **Passive Mode** | No | Yes (Shodan InternetDB) |
| **CONNECT fallback** | No (SYN only) | Yes |
| **Execution** | Native binary | Docker container |
| **Banner Grabbing** | Optional (`--banners`) | No |
| **Output Format** | NDJSON (`-oD`) | JSON Lines |

### How It Works

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Recon Data      │────▶│  masscan_scan.py  │────▶│  masscan_scan   │
│  (IPs from DNS,  │     │                  │     │  key in JSON    │
│   metadata)      │     │  1. Extract IPs  │     └────────┬────────┘
└─────────────────┘     │  2. Write targets │              │
                        │  3. Run masscan   │     ┌────────▼────────┐
                        │  4. Parse NDJSON  │     │ merge into      │
                        └──────────────────┘     │ port_scan key   │
                                                  └─────────────────┘
```

`run_masscan_scan()`:

1. Skips when `MASSCAN_ENABLED` is off or `is_masscan_installed()` finds no binary.
2. Picks the targets. In IP mode it takes `metadata.expanded_ips` (which may hold CIDRs) and files every port under the address itself (`ip_to_hostnames = {ip: [ip]}`), whatever `metadata.ip_to_hostname` names it: neither a placeholder (`10-0-0-1`) nor a reverse-DNS name becomes a host key, so the address is always probed and no name reaches tlsx as an SNI. Otherwise `resolve_targets_to_ips()` collects the IPs of the scan root (only when it is a target) and of every subdomain with records.
3. Writes `targets.txt` in a temp dir, runs the command from `build_masscan_command()` with a 30-minute timeout, and parses the NDJSON with `parse_masscan_output()`: only `status` records with `open` count, `banner` records are skipped, and each port is filed under every hostname mapped to its IP (or under the IP when there is none).
4. Stores the result as `recon_data["masscan_scan"]`, with the same `by_host` / `by_ip` / `all_ports` / `ip_to_hostnames` / `summary` shape as Naabu (CDN fields are always empty) and a `scan_metadata` of `scanner`, `scan_timestamp`, `scan_duration_seconds`, `scan_type` (`syn`), `ports_config`, `rate_limit`, `banners_enabled` and `total_targets`.

**Pipeline integration:** Masscan runs in the same `ThreadPoolExecutor` as Naabu (GROUP 3 fan-out). After both complete, `merge_port_scan_results()` combines their output into the unified `port_scan` key, deduplicating by host+port. Downstream modules (httpx, Nuclei, graph DB) consume `port_scan` unchanged.

---

## Configuration Parameters

All parameters are set in the webapp project settings; `recon/project_settings.py` holds the fallback defaults:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `MASSCAN_ENABLED` | `bool` | `False` | Enable/disable Masscan |
| `MASSCAN_TOP_PORTS` | `str` | `"1000"` | Top N ports ("100", "1000", "full") |
| `MASSCAN_CUSTOM_PORTS` | `str` | `""` | Custom ports (overrides TOP_PORTS) |
| `MASSCAN_RATE` | `int` | `1000` | Packets per second (capped by the engagement ceiling) |
| `MASSCAN_BANNERS` | `bool` | `False` | Capture service banners |
| `MASSCAN_WAIT` | `int` | `10` | Seconds to wait for late responses |
| `MASSCAN_RETRIES` | `int` | `1` | Retry attempts |
| `MASSCAN_EXCLUDE_TARGETS` | `str` | `""` | Comma-separated IPs/CIDRs to exclude (written to an `--excludefile`) |
| `MASSCAN_AI_PORT_CATALOG_ENABLED` | `bool` | `True` | Annotate Masscan's ports that match the AI port catalogue (`detected_by: masscan-ai-port`) |

**Port Examples:**
```python
MASSCAN_TOP_PORTS = "100"              # Top 100 ports
MASSCAN_TOP_PORTS = "1000"             # Top 1000 ports (default)
MASSCAN_TOP_PORTS = "full"             # All ports (-p 0-65535)
MASSCAN_CUSTOM_PORTS = "80,443,8080"   # Specific ports
MASSCAN_CUSTOM_PORTS = "8080-8090"     # Port range
```

---

## Key Design Decisions

- **NDJSON output (`-oD`)** instead of `-oJ` to avoid Masscan's known trailing-comma JSON bug
- **Native binary** (built from source in multi-stage Dockerfile) instead of Docker-in-Docker for simplicity
- **Results merged** into existing `port_scan` key so all downstream modules work unchanged
- **IP mode keys every port by its address**, so no placeholder (`10-0-0-1`) or reverse-DNS name becomes a host or a URL
- **Raw SYN packets** bypass the TCP stack for maximum scanning speed

---

## Stealth Mode Behavior

Stealth mode (`STEALTH_MODE`) applies the stealth values the settings registry declares. For port scanning:

| Key | Stealth value |
|-----|---------------|
| `MASSCAN_ENABLED` | `False` (active SYN scanning generates significant traffic) |
| `NAABU_PASSIVE_MODE` | `True` (Shodan InternetDB queries) |
| `NAABU_SCAN_TYPE` | `"c"` |
| `NAABU_RATE_LIMIT` | `10` |
| `NAABU_THREADS` | `1` |
| `NAABU_SKIP_HOST_DISCOVERY` | `True` |

---

## References

- [Masscan GitHub](https://github.com/robertdavidgraham/masscan)
- [Masscan Usage Guide](https://github.com/robertdavidgraham/masscan#usage)
