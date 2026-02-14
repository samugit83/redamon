<p align="center">
  <img src="assets/logo.png" alt="RedAmon Logo" width="120"/>
  <br/>
  <img src="assets/title.svg" alt="RedAmon" width="340"/>
</p>

<h3 align="center">Unmask the hidden before the world does.</h3>

<p align="center">
  An AI-powered agentic red team framework that automates offensive security operations, from reconnaissance to exploitation to post-exploitation, with zero human intervention.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/v1.2.0-release-brightgreen?style=for-the-badge" alt="Version 1.2.0"/>
  <img src="https://img.shields.io/badge/WARNING-SECURITY%20TOOL-red?style=for-the-badge" alt="Security Tool Warning"/>
  <img src="https://img.shields.io/badge/LICENSE-MIT-blue?style=for-the-badge" alt="MIT License"/>
  <br/>
  <img src="https://img.shields.io/badge/AI-AUTONOMOUS%20AGENT-blueviolet?style=for-the-badge&logo=openai&logoColor=white" alt="AI Powered"/>
  <img src="https://img.shields.io/badge/ZERO-HUMAN%20INTERVENTION-orange?style=for-the-badge" alt="Zero Click"/>
  <img src="https://img.shields.io/badge/Kali-Powered-557C94?style=for-the-badge&logo=kalilinux&logoColor=white" alt="Kali Powered"/>
  <img src="https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker"/>
</p>

> **LEGAL DISCLAIMER**: This tool is intended for **authorized security testing**, **educational purposes**, and **research only**. Never use this system to scan, probe, or attack any system you do not own or have explicit written permission to test. Unauthorized access is **illegal** and punishable by law. By using this tool, you accept **full responsibility** for your actions. **[Read Full Disclaimer](DISCLAIMER.md)**

<p align="center">
  <img src="assets/agent.gif" alt="RedAmon Agent Demo" width="100%"/>
</p>

---

## Quick Start

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) & Docker Compose v2+

That's it. No Node.js, Python, or security tools needed on your host.

### 1. Clone & Configure

```bash
git clone https://github.com/samugit83/redamon.git
cd redamon
cp .env.example .env
```

Edit `.env` and add at least one AI provider key:
```env
ANTHROPIC_API_KEY=sk-ant-...   # recommended
# or
OPENAI_API_KEY=sk-proj-...
```
Get your key from [Anthropic Console](https://console.anthropic.com/) or [OpenAI Platform](https://platform.openai.com/api-keys).

**Optional keys** (add these for extra capabilities):
```env
TAVILY_API_KEY=tvly-...        # Web search for the AI agent — get one at tavily.com
NVD_API_KEY=...                # NIST NVD API — higher rate limits for CVE lookups — nist.gov/developers
```

### 2. Build & Start

```bash
docker compose --profile tools build          # Build all images (recon + vuln-scanner + services)
docker compose up -d                          # Start all services (first GVM run takes ~30 min for feed sync)
                                              # Total image size: ~15 GB
```

**Without GVM (lighter, faster startup):**
```bash
docker compose --profile tools build          # Build all images
docker compose up -d postgres neo4j recon-orchestrator kali-sandbox agent webapp   # Start core services only
```

### 3. Open the Webapp

Go to **http://localhost:3000** — create a project, configure your target, and start scanning.

### Services

| Service | URL |
|---------|-----|
| **Webapp** | http://localhost:3000 |
| Neo4j Browser | http://localhost:7474 |
| Recon Orchestrator | http://localhost:8010 |
| Agent API | http://localhost:8090 |
| MCP Naabu | http://localhost:8000 |
| MCP Curl | http://localhost:8001 |
| MCP Nuclei | http://localhost:8002 |
| MCP Metasploit | http://localhost:8003 |

### Common Commands

```bash
docker compose up -d                        # Start all services (including GVM)
docker compose down                         # Stop all services (keeps data)
docker compose ps                           # Check service status
docker compose logs -f                      # Follow all logs
docker compose logs -f webapp               # Webapp (Next.js)
docker compose logs -f agent                # AI agent orchestrator
docker compose logs -f recon-orchestrator   # Recon orchestrator
docker compose logs -f kali-sandbox         # MCP tool servers
docker compose logs -f gvmd                 # GVM vulnerability scanner daemon
docker compose logs -f neo4j                # Neo4j graph database
docker compose logs -f postgres             # PostgreSQL database

# Stop services without removing volumes (preserves all data, fast restart)
docker compose down

# Stop and remove locally built images (forces rebuild on next start)
docker compose --profile tools down --rmi local

# Full cleanup: remove all containers, images, and volumes (destroys all data!)
docker compose --profile tools down --rmi local --volumes --remove-orphans
```

### Development Mode

For active development with **Next.js fast refresh** (no rebuild on every change):

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d
```

This swaps the production webapp image for a dev container with your source code volume-mounted. Every file save triggers instant hot-reload in the browser.

**Refreshing Python services after code changes:**

The Python services (`agent`, `recon-orchestrator`, `kali-sandbox`) already have their source code volume-mounted, so files are synced live. However, the running Python process won't pick up changes until you restart the container:

```bash
# Restart a single service (picks up code changes instantly)
docker compose restart agent              # AI agent orchestrator
docker compose restart recon-orchestrator  # Recon orchestrator
docker compose restart kali-sandbox       # MCP tool servers
```

No rebuild needed — just restart.

---

## Table of Contents

- [Overview](#overview)
  - [Reconnaissance Pipeline](#reconnaissance-pipeline)
  - [AI Agent Orchestrator](#ai-agent-orchestrator)
  - [GitHub Secret Hunter](#github-secret-hunter)
  - [GVM Vulnerability Scanner](#gvm-vulnerability-scanner-optional)
  - [Attack Surface Graph](#attack-surface-graph)
  - [Project Settings](#project-settings)
- [System Architecture](#system-architecture)
  - [High-Level Architecture](#high-level-architecture)
  - [Data Flow Pipeline](#data-flow-pipeline)
  - [Docker Container Architecture](#docker-container-architecture)
- [Components](#components)
  - [Reconnaissance Pipeline](#1-reconnaissance-pipeline)
  - [Graph Database](#2-graph-database)
  - [MCP Tool Servers](#3-mcp-tool-servers)
  - [AI Agent Orchestrator](#4-ai-agent-orchestrator)
  - [Web Application](#5-web-application)
  - [GVM Scanner](#6-gvm-scanner)
  - [GitHub Secret Hunter](#7-github-secret-hunter)
  - [Test Environments](#8-test-environments)
- [Technology Stack](#technology-stack)
  - [Frontend](#frontend)
  - [Backend & API](#backend--api)
  - [AI & LLM](#ai--llm)
  - [Databases](#databases)
  - [Security & Penetration Testing Tools](#security--penetration-testing-tools)
  - [Vulnerability Assessment](#vulnerability-assessment)
  - [Data Sources & Threat Intelligence](#data-sources--threat-intelligence)
  - [Infrastructure & DevOps](#infrastructure--devops)
  - [Protocols & Communication](#protocols--communication)
- [Development Mode](#development-mode)
- [Documentation](#documentation)
- [Legal](#legal)

---

## Overview

RedAmon is a modular, containerized penetration testing framework that chains automated reconnaissance, AI-driven exploitation, and graph-powered intelligence into a single, end-to-end offensive security pipeline. Every component runs inside Docker — no tools installed on your host — and communicates through well-defined APIs so each layer can evolve independently.

The platform is built around four pillars:

| Pillar | What it does |
|--------|-------------|
| **Reconnaissance Pipeline** | Six sequential scanning phases that map your target's entire attack surface — from subdomain discovery to vulnerability detection — and store the results as a rich, queryable graph. Complemented by standalone GVM network scanning and GitHub secret hunting modules. |
| **AI Agent Orchestrator** | A LangGraph-based autonomous agent that reasons about the graph, selects security tools via MCP, transitions through informational / exploitation / post-exploitation phases, and can be steered in real-time via chat. |
| **Attack Surface Graph** | A Neo4j knowledge graph with 17 node types and 20+ relationship types that serves as the single source of truth for every finding — and the primary data source the AI agent queries before every decision. |
| **Project Settings Engine** | 180+ per-project parameters — exposed through the webapp UI — that control every tool's behavior, from Naabu thread counts to Nuclei severity filters to agent approval gates. |

---

### Reconnaissance Pipeline

The recon pipeline is a fully automated, six-phase scanning engine that runs inside a Kali Linux container. Given a single root domain (or a specific subdomain list), it progressively builds a complete picture of the target's external attack surface. Each phase feeds its output into the next, and the final result is both a structured JSON file and a populated Neo4j graph.

<p align="center">
  <img src="assets/recon.gif" alt="RedAmon Reconnaissance Pipeline" width="100%"/>
</p>

#### Phase 1 — Domain Discovery

The pipeline starts by mapping the target's subdomain landscape using three complementary techniques:

- **Certificate Transparency** via crt.sh — queries the public CT logs to find every certificate ever issued for the root domain, extracting subdomain names from Subject and SAN fields.
- **HackerTarget API** — a passive lookup that returns known subdomains without sending any traffic to the target.
- **Knockpy** (optional brute-force) — an active subdomain bruteforcer that tests thousands of common prefixes against the target's DNS. Controlled by the `useBruteforceForSubdomains` toggle.
- **WHOIS Lookup** — retrieves registrar, registrant, creation/expiration dates, name servers, and contact information with automatic retry logic and exponential backoff.
- **DNS Resolution** — resolves every discovered subdomain to its A, AAAA, MX, NS, TXT, CNAME, and SOA records, building a map of IP addresses and mail infrastructure.

When a specific `subdomainList` is provided (e.g., `www.`, `api.`, `mail.`), the pipeline skips active discovery and only resolves the specified subdomains — useful for focused assessments.

#### Phase 2 — Port Scanning

All resolved IP addresses are fed into **Naabu**, a fast SYN/CONNECT port scanner. Key capabilities:

- **SYN scanning** (default) with automatic fallback to CONNECT mode if raw sockets are unavailable.
- Top-N port selection (100, 1000, or custom port ranges).
- **CDN/WAF detection** — identifies Cloudflare, Akamai, AWS CloudFront and other CDN providers, optionally excluding them from deeper scans.
- **Passive mode** — queries Shodan's InternetDB instead of sending packets, for zero-touch reconnaissance.
- **IANA service lookup** — maps port numbers to service names using the 15,000-entry IANA registry.

#### Phase 3 — HTTP Probing & Technology Detection

Every host+port combination is probed over HTTP/HTTPS using **httpx** to determine which services are live and what they run:

- **Response metadata** — status codes, content types, page titles, server headers, response times, word/line counts.
- **TLS inspection** — certificate subject, issuer, expiry, cipher suite, JARM fingerprint.
- **Technology fingerprinting** — a dual-engine approach:
  - httpx's built-in detection identifies major frameworks and servers.
  - **Wappalyzer** (6,000+ fingerprints, auto-updated from npm) performs a second pass on the response HTML, catching CMS plugins, JavaScript libraries, and analytics tools that httpx misses. The merge is fully automatic with configurable minimum confidence thresholds.
- **Banner grabbing** — for non-HTTP ports (SSH, FTP, SMTP, MySQL, Redis, etc.), raw socket connections extract service banners and version strings using protocol-specific probe strings.

#### Phase 4 — Resource Enumeration

Three tools run **in parallel** (via ThreadPoolExecutor) to discover every reachable endpoint on the live URLs:

- **Katana** — an active web crawler that follows links to a configurable depth, optionally rendering JavaScript to discover dynamic routes. Extracts forms, input fields, and query parameters.
- **GAU** (GetAllUrls) — a passive discovery tool that queries the Wayback Machine, Common Crawl, AlienVault OTX, and URLScan.io for historical URLs. Results are verified with httpx to filter out dead links, and HTTP methods are detected via OPTIONS probes.
- **Kiterunner** — an API-specific brute-forcer that tests wordlists of common API routes (REST, GraphQL) against each base URL, detecting allowed HTTP methods (GET, POST, PUT, DELETE, PATCH).

Results are merged, deduplicated, and organized by base URL. Every endpoint is classified into categories (auth, file_access, api, dynamic, static, admin) and its parameters are typed (id, file, search, auth_param).

#### Phase 5 — Vulnerability Scanning

The discovered endpoints — especially those with query parameters — are fed into **Nuclei**, a template-based vulnerability scanner with 8,000+ community templates:

- **DAST mode** (active fuzzing) — injects XSS, SQLi, RCE, LFI, SSRF, and SSTI payloads into every discovered parameter. This catches vulnerabilities that signature-only scanning misses.
- **Severity filtering** — scan for critical, high, medium, and/or low findings.
- **Interactsh integration** — out-of-band detection for blind vulnerabilities (SSRF, XXE, blind SQLi) via callback servers.
- **CVE enrichment** — each finding is cross-referenced against the NVD (or Vulners) API for CVSS scores, descriptions, and references.
- **30+ custom security checks** — direct IP access, missing security headers (CSP, HSTS, Referrer-Policy, Permissions-Policy, COOP, CORP, COEP), TLS certificate expiry, DNS security (SPF, DMARC, DNSSEC, zone transfer), open services (Redis without auth, exposed Kubernetes API, SMTP open relay), insecure form actions, and missing rate limiting.

#### Phase 6 — MITRE Enrichment

- **MITRE CWE/CAPEC mapping** — every CVE found in Phase 5 is automatically enriched with its corresponding CWE weakness and CAPEC attack patterns, using an auto-updated database from the CVE2CAPEC repository (24-hour cache TTL).

#### Output

All results are combined into a single JSON file (`recon/output/recon_{PROJECT_ID}.json`) and simultaneously imported into the Neo4j graph database, creating a fully connected knowledge graph of the target's attack surface.

#### Running Reconnaissance

1. Create a project with target domain and settings
2. Navigate to Graph page
3. Click "Start Recon" button
4. Watch real-time logs in the drawer

---

### GVM Vulnerability Scanner (Optional)

After reconnaissance completes, you can optionally run a **GVM/OpenVAS network-level vulnerability scan** to complement the web-layer findings from Nuclei.

#### What is GVM/OpenVAS?

**Greenbone Vulnerability Management (GVM)** — formerly known as OpenVAS — is the world's largest open-source network vulnerability scanner. While Nuclei focuses on web application testing via HTTP templates, GVM operates at a fundamentally different level: it probes services directly at the **protocol layer**, testing for misconfigurations, outdated software, default credentials, and known CVEs across every open port.

The GVM ecosystem consists of several components working together:

- **OpenVAS Scanner (ospd-openvas)** — the scanning engine that executes Network Vulnerability Tests (NVTs) against targets, performing actual protocol-level probes (SSH version checks, SMB enumeration, TLS cipher analysis, banner fingerprinting).
- **GVM Daemon (gvmd)** — the central management service that orchestrates scans, manages scan configs, stores results, and exposes the GMP (Greenbone Management Protocol) API.
- **Vulnerability Feed** — a continuously updated database of **170,000+ NVTs** covering operating systems, network services, databases, embedded devices, industrial control systems, and more — the largest open-source vulnerability test feed available.
- **PostgreSQL + Redis** — backend storage for scan results, NVT metadata, and inter-process communication.

What makes GVM particularly powerful is its **depth of testing**. Unlike signature-based scanners that match HTTP responses against patterns, GVM actively negotiates protocols, authenticates to services, checks software versions against vulnerability databases, tests for default credentials, and probes for misconfigurations that are invisible at the HTTP layer — things like weak SSH ciphers, exposed database ports with no authentication, SNMP community string guessing, and SMB vulnerabilities.

#### Scan Profiles & Time Estimates

GVM includes seven pre-configured scan profiles, each trading thoroughness for speed. Times below are per-target estimates:

| Scan Profile | NVTs | Duration | Description |
|---|---|---|---|
| **Host Discovery** | ~100 | 2-5 min | Basic host detection — is the target alive? |
| **Discovery** | ~500 | 5-10 min | Network discovery — open ports, running services, OS fingerprint |
| **System Discovery** | ~2,000 | 10-20 min | Detailed OS and service enumeration for asset inventory |
| **Full and fast** | ~50,000 | 30-60 min | Comprehensive vulnerability scan using port scan results to select relevant NVTs — **recommended default** |
| **Full and fast ultimate** | ~70,000 | 1-2 hours | Same as above but includes dangerous NVTs that may crash services or hosts |
| **Full and very deep** | ~50,000 | 2-4 hours | Ignores previously collected port/service data and runs all NVTs unconditionally — waits for timeouts on every test, significantly slower |
| **Full and very deep ultimate** | ~70,000 | 4-8 hours | Most thorough and slowest option — runs all NVTs including dangerous ones, ignores prior scan data, waits for all timeouts |

The key difference between "fast" and "very deep" profiles is how they use prior information: **fast** profiles leverage port scan results to skip irrelevant NVTs (e.g., skipping SSH checks on a host with no port 22), while **very deep** profiles ignore all prior data and execute every NVT unconditionally, waiting for timeouts on non-responding services. The "ultimate" variants add NVTs that may cause denial-of-service conditions on the target — use them only in controlled lab environments.

> **Note:** The first GVM startup requires a one-time feed synchronization that takes ~30 minutes. Subsequent starts are instant.

#### Integration with RedAmon

GVM findings are stored as Vulnerability nodes (`source="gvm"`) in Neo4j, linked to IP and Subdomain nodes via `HAS_VULNERABILITY` relationships, with associated CVE nodes. This means the AI agent can reason about both web-layer vulnerabilities (from Nuclei) and network-layer vulnerabilities (from GVM) in a single unified graph.

#### Running a GVM Scan

1. GVM starts automatically with `docker compose up -d` (first run takes ~30 min for feed sync)
2. Navigate to Graph page
3. Click the "GVM Scan" button (enabled only when recon data exists for the project)
4. Watch real-time logs in the GVM logs drawer
5. Download the GVM results JSON when complete

> **Note:** Default GVM credentials are `admin` / `admin` (auto-created by gvmd on first start).

---

### AI Agent Orchestrator

The AI agent is a **LangGraph-based autonomous system** that implements the ReAct (Reasoning + Acting) pattern. It operates in a loop — reason about the current state, select and execute a tool, analyze the results, repeat — until the objective is complete or the user stops it.

#### Three Execution Phases

The agent progresses through three distinct operational phases, each with different tool access and objectives:

**Informational Phase** — The default starting phase. The agent gathers intelligence by querying the Neo4j graph, running web searches for CVE details, performing HTTP requests with curl, and scanning ports with Naabu. No offensive tools are available. The agent analyzes the attack surface, identifies high-value targets, and builds a mental model of what's exploitable.

**Exploitation Phase** — When the agent identifies a viable attack path, it requests a phase transition. This requires **user approval** (configurable). Once approved, the agent gains access to the Metasploit console via MCP and can execute exploits. Two attack paths are supported:

- **CVE Exploit** — the agent searches for a matching Metasploit module, configures the payload (reverse shell or bind shell), sets target parameters, and fires the exploit. For statefull mode, it establishes a Meterpreter session; for stateless mode, it executes one-shot commands.
- **Brute Force Credential Guess** — the agent selects appropriate wordlists and attacks services like SSH, FTP, or MySQL, with configurable maximum attempts per wordlist.

When an exploit succeeds, the agent automatically creates an **Exploit node** in the Neo4j graph — recording the attack type, target IP, port, CVE IDs, Metasploit module used, payload, session ID, and any credentials discovered. This node is linked to the targeted IP, the exploited CVE, and the entry port, making every successful compromise a permanent, queryable part of the attack surface graph.

<p align="center">
  <img src="assets/exploit.gif" alt="RedAmon Exploitation Demo" width="100%"/>
</p>

**Post-Exploitation Phase** — After a successful exploit, the agent can optionally transition to post-exploitation (if enabled). In statefull mode (Meterpreter), it runs interactive commands — enumeration, lateral movement, data exfiltration. In stateless mode, it re-runs exploits with different command payloads. This phase also requires user approval.

#### Chat-Based Graph Interaction

Users interact with the agent through a real-time **WebSocket chat interface** in the webapp. You can ask natural language questions and the agent will automatically translate them into Cypher queries against the Neo4j graph:

- *"What vulnerabilities exist on 192.168.1.100?"* — the agent generates a Cypher query, injects tenant filters (so you only see your project's data), executes it, and returns the results in natural language.
- *"Which technologies have critical CVEs?"* — traverses the Technology → CVE relationship chain.
- *"Show me all open ports on the subdomains of example.com"* — walks the Subdomain → IP → Port path.
- *"Find all endpoints with injectable parameters"* — queries Parameter nodes marked as injectable by Nuclei.

The text-to-Cypher system includes 25+ example patterns, handles the critical distinction between Vulnerability nodes (scanner findings, lowercase severity) and CVE nodes (NVD entries, uppercase severity), and automatically retries with error context if a query fails (up to 3 attempts).

#### Real-Time Control

The agent runs as a background task, keeping the WebSocket connection free for control messages:

- **Guidance** — send steering messages while the agent works (e.g., *"Focus on SSH vulnerabilities, ignore web apps"*). These are injected into the system prompt before the next reasoning step.
- **Stop** — pause execution at any point. The agent's state is checkpointed via LangGraph's MemorySaver.
- **Resume** — continue from the last checkpoint with full context preserved.
- **Approval workflows** — phase transitions to exploitation or post-exploitation pause the agent and present a structured request (reason, planned actions, risks) for the user to approve, modify, or abort.

#### MCP Tool Integration

The agent executes security tools through the **Model Context Protocol**, with each tool running in a dedicated server inside the Kali sandbox container:

| Tool | Purpose | Available In |
|------|---------|-------------|
| **query_graph** | Neo4j Cypher queries for target intelligence | All phases |
| **web_search** | Tavily-based CVE/exploit research | All phases |
| **execute_curl** | HTTP requests, API probing, header inspection | All phases |
| **execute_naabu** | Fast port scanning and service detection | All phases |
| **metasploit_console** | Exploit execution, payload delivery, sessions | Exploitation & Post-exploitation |

For long-running Metasploit operations (e.g., brute force with large wordlists), the agent streams progress updates every 5 seconds to the WebSocket, so you see output in real time.

#### Attack Path Routing

The agent uses an **LLM-powered Intent Router** to classify each user request into the appropriate attack path category. Rather than following a single, fixed exploitation workflow, the router analyzes the user's objective, the available target intelligence from the Neo4j graph, and the current operational phase to select the correct attack chain — each with its own Metasploit workflow, tool sequence, and post-exploitation behavior.

The architecture supports **10 attack path categories** (CVE exploitation, brute force, social engineering, DoS, fuzzing, credential capture, wireless attacks, web application attacks, client-side exploitation, and local privilege escalation), with an implementation roadmap to progressively enable each one. Attack paths can also **chain into each other** — for example, a credential capture can feed captured usernames into a brute force attack, or a fuzzing discovery can chain into CVE research and exploitation.

**Currently implemented attack paths:**

| # | Attack Path | Description | Module Type | Post-Exploitation |
|---|-------------|-------------|-------------|-------------------|
| 1 | **CVE-Based Exploitation** | Exploits known vulnerabilities identified by CVE identifier. The agent searches for a matching Metasploit exploit module, configures target parameters and payload (reverse/bind shell), and fires the exploit. Supports both statefull (Meterpreter session) and stateless (one-shot command) post-exploitation. | `exploit/*` | Yes |
| 2 | **Brute Force / Credential Guess** | Password guessing attacks against authentication services (SSH, FTP, MySQL, SMB, HTTP, and more). The agent selects the appropriate `auxiliary/scanner/*/login` module, configures wordlists from Metasploit's built-in collection, and runs the attack. When SSH brute force succeeds with `CreateSession: true`, the agent transitions to a shell-based post-exploitation phase. | `auxiliary/scanner/*` | Sometimes (SSH) |

For full details on all 10 attack path categories, the intent router architecture, chain-specific workflows, and the implementation roadmap, see the **[Attack Paths Documentation](agentic/README.ATTACK_PATHS.md)**.

---

### Attack Surface Graph

The Neo4j graph database is the **single source of truth** for every finding in RedAmon. It stores the complete topology of the target's attack surface as an interconnected knowledge graph, enabling both visual exploration in the webapp and intelligent querying by the AI agent.

#### Node Types

The graph contains **17 node types** organized into four categories:

**Infrastructure Nodes** — represent the network topology:

| Node | Key Properties | Description |
|------|---------------|-------------|
| **Domain** | name, registrar, creation_date, expiration_date, WHOIS data | Root domain with full WHOIS information |
| **Subdomain** | name, has_dns_records | Discovered hostname |
| **IP** | address, version, is_cdn, cdn_name, asn | Resolved IP address with CDN/ASN metadata |
| **Port** | number, protocol, state | Open port on an IP |
| **Service** | name, product, version, banner | Running service with version info |

**Web Application Nodes** — represent the application layer:

| Node | Key Properties | Description |
|------|---------------|-------------|
| **BaseURL** | url, status_code, title, server, response_time_ms, resolved_ip | Live HTTP endpoint with full response metadata |
| **Endpoint** | path, method, has_parameters, is_form, source | Discovered URL path with HTTP method |
| **Parameter** | name, position (query/body/header/path), is_injectable | Input parameter, flagged when a vulnerability affects it |

**Technology & Security Nodes** — represent detected software and security posture:

| Node | Key Properties | Description |
|------|---------------|-------------|
| **Technology** | name, version, categories, confidence, detected_by, known_cve_count | Detected framework, library, or server |
| **Header** | name, value, is_security_header | HTTP response header |
| **Certificate** | subject_cn, issuer, not_after, san, tls_version | TLS certificate details |
| **DNSRecord** | type (A/AAAA/MX/NS/TXT/SOA), value, ttl | DNS record for a subdomain |

**Vulnerability & Exploitation Nodes** — represent security findings and successful attacks:

| Node | Key Properties | Description |
|------|---------------|-------------|
| **Vulnerability** | id, name, severity (lowercase), source (nuclei/gvm/security_check), category, curl_command | Scanner finding with evidence |
| **CVE** | id, cvss, severity (uppercase), description, published | Known vulnerability from NVD |
| **MitreData** | cve_id, cwe_id, cwe_name, abstraction | CWE weakness mapping |
| **Capec** | capec_id, name, likelihood, severity, execution_flow | Common attack pattern |
| **Exploit** | attack_type, target_ip, session_id, cve_ids, metasploit_module | Agent-created successful exploitation record |

#### Relationship Chain

The graph connects these nodes through a directed relationship chain that mirrors real-world infrastructure topology:

```mermaid
flowchart TB
    Domain -->|HAS_SUBDOMAIN| Subdomain
    Subdomain -->|RESOLVES_TO| IP
    IP -->|HAS_PORT| Port
    Port -->|RUNS_SERVICE| Service
    Service -->|POWERED_BY| BaseURL
    Port -->|SERVES_URL| BaseURL
    BaseURL -->|HAS_ENDPOINT| Endpoint
    BaseURL -->|USES_TECHNOLOGY| Technology
    BaseURL -->|HAS_HEADER| Header
    Endpoint -->|HAS_PARAMETER| Parameter
    Technology -->|HAS_KNOWN_CVE| CVE
    CVE -->|HAS_CWE| MitreData
    MitreData -->|HAS_CAPEC| Capec
    Vulnerability -->|FOUND_AT| Endpoint
    Vulnerability -->|AFFECTS_PARAMETER| Parameter
    Exploit -->|EXPLOITED_CVE| CVE
    Exploit -->|TARGETED_IP| IP
    Exploit --> Vulnerability

    style Domain fill:#1a365d,color:#fff
    style Subdomain fill:#1a365d,color:#fff
    style IP fill:#1a365d,color:#fff
    style Port fill:#1a365d,color:#fff
    style Service fill:#1a365d,color:#fff
    style BaseURL fill:#2a4365,color:#fff
    style Endpoint fill:#2a4365,color:#fff
    style Parameter fill:#2a4365,color:#fff
    style Technology fill:#285e61,color:#fff
    style Header fill:#285e61,color:#fff
    style CVE fill:#742a2a,color:#fff
    style Vulnerability fill:#742a2a,color:#fff
    style MitreData fill:#744210,color:#fff
    style Capec fill:#744210,color:#fff
    style Exploit fill:#7b341e,color:#fff
```

Vulnerabilities connect differently depending on their source:
- **Nuclei findings** (web application) → linked via `FOUND_AT` to the specific Endpoint and `AFFECTS_PARAMETER` to the vulnerable Parameter.
- **GVM findings** (network level) → linked via `HAS_VULNERABILITY` directly to the IP and Subdomain nodes, with associated CVE nodes.
- **Security checks** (DNS/email/headers) → linked via `HAS_VULNERABILITY` to the Subdomain or Domain.

#### How the Agent Uses the Graph

Before the agent takes any offensive action, it queries the graph to build situational awareness. This is the core intelligence loop:

1. **Attack surface mapping** — the agent queries the Domain → Subdomain → IP → Port → Service chain to understand what's exposed.
2. **Technology-CVE correlation** — traverses Technology → CVE relationships to find which detected software versions have known vulnerabilities, prioritizing by CVSS score.
3. **Injectable parameter discovery** — queries Parameter nodes flagged as `is_injectable: true` by Nuclei to identify confirmed injection points.
4. **Exploit feasibility assessment** — cross-references open ports, running services, and known CVEs to determine which Metasploit modules are likely to succeed.
5. **Post-exploitation context** — after a successful exploit, the agent creates an Exploit node linked to the target IP, CVE, and port, so subsequent queries can reference what's already been compromised.

All queries are automatically scoped to the current user and project via regex-based tenant filter injection — the agent never generates tenant filters itself, preventing accidental cross-project data access.

---

### Project Settings

Every project in RedAmon has **180+ configurable parameters** that control the behavior of each reconnaissance module and the AI agent. These settings are managed through the webapp's project form UI, stored in PostgreSQL via Prisma ORM, and fetched by the recon container and agent at runtime.

<p align="center">
  <img src="assets/new_project.gif" alt="RedAmon Project Settings" width="100%"/>
</p>

#### Target Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| Target Domain | — | The root domain to assess |
| Subdomain List | [] | Specific subdomain prefixes to scan (empty = discover all) |
| Verify Domain Ownership | false | Require DNS TXT record proof before scanning |
| Use Tor | false | Route all recon traffic through the Tor network |
| Use Bruteforce | true | Enable Knockpy active subdomain bruteforcing |

#### Scan Module Toggles

Modules can be individually enabled/disabled with automatic dependency resolution — disabling a parent module automatically disables all children:

```
domain_discovery (root)
  └── port_scan
       └── http_probe
            ├── resource_enum
            └── vuln_scan
```

#### Port Scanner (Naabu)

Controls how ports are discovered on target hosts. Key settings include scan type (SYN vs. CONNECT), top-N port selection or custom port ranges, rate limiting, thread count, CDN exclusion, passive mode via Shodan InternetDB, and host discovery skip.

#### HTTP Prober (httpx)

Controls what metadata is extracted from live HTTP services. Over 25 toggles for individual probe types: status codes, content analysis, technology detection, TLS/certificate inspection, favicon hashing, JARM fingerprinting, ASN/CDN detection, response body inclusion, and custom header injection. Also configures redirect following depth and rate limiting.

#### Technology Detection (Wappalyzer)

Controls the second-pass technology fingerprinting engine. Settings include enable/disable toggle, minimum confidence threshold (0-100%), HTML requirement filter, auto-update from npm, and cache TTL.

#### Banner Grabbing

Controls raw socket banner extraction for non-HTTP ports (SSH, FTP, SMTP, MySQL, Redis). Settings include enable/disable toggle, connection timeout, thread count, and maximum banner length.

#### Web Crawler (Katana)

Active web crawling using Katana from ProjectDiscovery. Discovers URLs, endpoints, and parameters by following links and parsing JavaScript. Found URLs with parameters feed into Nuclei DAST mode for vulnerability fuzzing.

| Parameter | Default | Description |
|-----------|---------|-------------|
| Enable Katana | true | Master toggle for active web crawling |
| Crawl Depth | 2 | How many links deep to follow (1-10). Each level adds ~50% time |
| Max URLs | 300 | Maximum URLs to collect per domain. 300: ~1-2 min/domain, 1000+: scales linearly |
| Rate Limit | 50 | Requests per second to avoid overloading target |
| Timeout | 3600 | Overall crawl timeout in seconds (default: 60 minutes) |
| JavaScript Crawling | false | Parse JS files to find hidden endpoints and API calls. Uses headless browser (+50-100% time) |
| Parameters Only | false | Only keep URLs with query parameters (?key=value) for DAST fuzzing |
| Exclude Patterns | [...] | URL patterns to skip — static assets, images, CDN URLs. 100+ default patterns pre-configured |
| Custom Headers | [] | Browser-like request headers to avoid detection during DAST crawling (e.g., User-Agent) |
| Docker Image | (locked) | Katana Docker image used for crawling (system-managed) |

#### Passive URL Discovery (GAU)

Passive URL discovery using GetAllUrls (GAU). Retrieves historical URLs from web archives and threat intelligence sources without touching the target directly. Complements Katana's active crawling with archived data (~20-60 sec per domain).

| Parameter | Default | Description |
|-----------|---------|-------------|
| Enable GAU | false | Master toggle for passive URL discovery |
| Providers | wayback, commoncrawl, otx, urlscan | Data sources to query for archived URLs |
| Max URLs | 1000 | Maximum URLs to fetch per domain (0 = unlimited) |
| Timeout | 60 | Request timeout per provider (seconds) |
| Threads | 5 | Parallel fetch threads (1-20) |
| Year Range | [] | Filter Wayback Machine by year (e.g., "2020, 2024"). Empty = all years |
| Verbose Output | false | Enable detailed logging for debugging |
| Blacklist Extensions | [...] | File extensions to exclude (e.g., png, jpg, css, pdf, zip) |

**URL Verification** — when enabled, GAU verifies each discovered URL is still live using httpx, filtering out dead links. This doubles or triples GAU time but eliminates false leads:

| Parameter | Default | Description |
|-----------|---------|-------------|
| Verify URLs | false | HTTP check to confirm archived URLs still exist |
| Verify Timeout | 5 | Seconds per URL check |
| Verify Rate Limit | 100 | Verification requests per second |
| Verify Threads | 50 | Concurrent verification threads (1-100) |
| Accept Status Codes | [200, 201, 301, ...] | Status codes that indicate a live URL. Include 401/403 for auth-protected endpoints |
| Filter Dead Endpoints | true | Exclude URLs returning 404/500/timeout from final results |

**HTTP Method Detection** — when URL verification is enabled, GAU can additionally discover allowed HTTP methods (GET, POST, PUT, DELETE) via OPTIONS probes (+30-50% time on top of verification):

| Parameter | Default | Description |
|-----------|---------|-------------|
| Detect Methods | false | Send OPTIONS request to discover allowed methods |
| Method Detect Timeout | 5 | Seconds per OPTIONS request |
| Method Detect Rate Limit | 50 | Requests per second |
| Method Detect Threads | 25 | Concurrent threads |

#### API Discovery (Kiterunner)

API endpoint bruteforcing using Kiterunner from Assetnote. Discovers hidden REST API routes by testing against comprehensive wordlists derived from real-world Swagger/OpenAPI specifications (~5-30 min per endpoint).

| Parameter | Default | Description |
|-----------|---------|-------------|
| Enable Kiterunner | true | Master toggle for API route bruteforcing |
| Wordlist | routes-large | API route wordlist: `routes-large` (~100k routes, 10-30 min) or `routes-small` (~20k routes, 5-10 min) |
| Rate Limit | 100 | Requests per second. Lower is stealthier |
| Connections | 100 | Concurrent connections per target |
| Timeout | 10 | Per-request timeout (seconds) |
| Scan Timeout | 1000 | Overall scan timeout (seconds). Large wordlists need more time |
| Threads | 50 | Parallel scanning threads |
| Min Content Length | 0 | Ignore responses smaller than this (bytes). Filters empty or trivial responses |

**Status Code Filters** — control which HTTP responses are kept:

| Parameter | Default | Description |
|-----------|---------|-------------|
| Ignore Status Codes | [] | Blacklist: filter out noise from common errors (e.g., 404, 500) |
| Match Status Codes | [200, 201, ...] | Whitelist: only show endpoints with these codes. Includes auth-protected (401, 403) |
| Custom Headers | [] | Request headers for authenticated API scanning (e.g., Authorization: Bearer token) |

**Method Detection** — Kiterunner wordlists only contain GET routes. This feature discovers POST/PUT/DELETE methods on found endpoints (+30-50% scan time):

| Parameter | Default | Description |
|-----------|---------|-------------|
| Detect Methods | true | Find additional HTTP methods beyond GET |
| Detection Mode | bruteforce | `bruteforce` — try each method (slower, more accurate) or `options` — parse Allow header (faster) |
| Bruteforce Methods | POST, PUT, DELETE, PATCH | Methods to try in bruteforce mode |
| Method Detect Timeout | 5 | Seconds per request |
| Method Detect Rate Limit | 50 | Requests per second |
| Method Detect Threads | 25 | Concurrent threads |

#### Vulnerability Scanner (Nuclei)

Template-based vulnerability scanning using ProjectDiscovery's Nuclei. Runs thousands of security checks against discovered endpoints to identify CVEs, misconfigurations, exposed panels, and other security issues.

**Performance Settings:**

| Parameter | Default | Description |
|-----------|---------|-------------|
| Severity Levels | critical, high, medium, low, info | Filter vulnerabilities by severity. Excluding "info" is ~70% faster |
| Rate Limit | 100 | Requests per second. 100-150 for most targets, lower for sensitive systems |
| Bulk Size | 25 | Number of hosts to process in parallel |
| Concurrency | 25 | Templates to execute in parallel |
| Timeout | 10 | Request timeout per template check (seconds) |
| Retries | 1 | Retry attempts for failed requests (0-10) |
| Max Redirects | 10 | Maximum redirect chain to follow (0-50) |

**Template Configuration:**

| Parameter | Default | Description |
|-----------|---------|-------------|
| Template Folders | [] | Template directories to include: cves, vulnerabilities, misconfiguration, exposures, technologies, default-logins, takeovers. Empty = all |
| Exclude Template Paths | [] | Exclude specific directories or template files by path (e.g., http/vulnerabilities/generic/) |
| Custom Template Paths | [] | Add your own templates in addition to the official repository |
| Include Tags | [] | Filter by functionality tags: cve, xss, sqli, rce, lfi, ssrf, xxe, ssti. Empty = all |
| Exclude Tags | [] | Exclude tags — recommended: dos, fuzz for production |

**Template Options:**

| Parameter | Default | Description |
|-----------|---------|-------------|
| Auto Update Templates | true | Download latest templates before scan. Adds ~10-30 seconds |
| New Templates Only | false | Only run templates added since last update. Good for daily scans |
| DAST Mode | true | Active fuzzing for XSS, SQLi, RCE. More aggressive, requires URLs with parameters (+50-100% time) |

**Advanced Options:**

| Parameter | Default | Description |
|-----------|---------|-------------|
| Headless Mode | false | Use headless browser for JavaScript-rendered pages (+100-200% time) |
| System DNS Resolvers | false | Use OS DNS instead of Nuclei defaults. Better for internal networks |
| Interactsh | true | Detect blind vulnerabilities (SSRF, XXE, RCE) via out-of-band callback servers. Requires internet |
| Follow Redirects | true | Follow HTTP redirects during template execution |
| Scan All IPs | false | Scan all resolved IPs, not just hostnames. May find duplicate vulnerabilities |

#### CVE Enrichment

Enrich vulnerability findings with detailed CVE data from NVD and other sources. Provides CVSS scores, affected versions, exploitation status, and remediation guidance (~1-5 min depending on technologies found).

| Parameter | Default | Description |
|-----------|---------|-------------|
| Enable CVE Lookup | true | Master toggle for CVE enrichment |
| CVE Source | nvd | Data source: `nvd` (National Vulnerability Database) or `vulners` |
| Max CVEs per Finding | 20 | Maximum CVE entries to retrieve per technology/vulnerability (1-100) |
| Min CVSS Score | 0 | Only include CVEs at or above this CVSS score (0-10, step 0.1) |
| NVD API Key | — | Free key from nist.gov — without key: rate-limited (10 req/min), with key: ~80x faster |
| Vulners API Key | — | API key for Vulners data source |

#### MITRE Mapping

Controls CWE/CAPEC enrichment of CVE findings. Settings include auto-update toggle, CWE/CAPEC inclusion toggles, and cache TTL.

#### Security Checks

25+ individual toggle-controlled checks grouped into six categories:

- **Network Exposure** — direct IP access (HTTP/HTTPS), IP-based API exposure, WAF bypass detection.
- **TLS/Certificate** — certificate expiry warning (configurable days threshold).
- **Security Headers** — missing Referrer-Policy, Permissions-Policy, COOP, CORP, COEP, Cache-Control, CSP unsafe-inline.
- **Authentication** — login forms over HTTP, session cookies without Secure/HttpOnly flags, Basic Auth without TLS.
- **DNS Security** — missing SPF, DMARC, DNSSEC records, zone transfer enabled.
- **Exposed Services** — admin ports, databases, Redis without auth, Kubernetes API, SMTP open relay.
- **Application** — insecure form actions, missing rate limiting.

#### GVM Vulnerability Scan

Configure GVM/OpenVAS network-level vulnerability scanning. These settings control scan depth, target strategy, and timeouts for the Greenbone vulnerability scanner. Requires the GVM stack to be running (starts automatically with `docker compose up -d`).

**Scan Configuration:**

| Parameter | Default | Description |
|-----------|---------|-------------|
| Scan Profile | Full and fast | GVM scan configuration preset — see [Scan Profiles & Time Estimates](#scan-profiles--time-estimates) for the full comparison of all 7 profiles |
| Scan Targets Strategy | both | Which targets from recon data to scan: `both` (IPs and hostnames), `ips_only`, or `hostnames_only`. "Both" doubles the target count |

**Timeouts & Polling:**

| Parameter | Default | Description |
|-----------|---------|-------------|
| Task Timeout | 14400 | Maximum seconds to wait for a single scan task. 0 = unlimited. Default: 4 hours |
| Poll Interval | 5 | Seconds between scan status checks (5-300). Lower values give faster log updates |

**Post-Scan:**

| Parameter | Default | Description |
|-----------|---------|-------------|
| Cleanup After Scan | true | Remove scan targets and tasks from GVM's internal database after results are extracted. Keeps GVM clean across multiple scans. Results are always saved to JSON and Neo4j regardless |

#### GitHub Secret Hunting

Search GitHub repositories for exposed secrets, API keys, and credentials related to your target domain. GitHub Secret Hunting runs as an **independent module** (separate from the recon pipeline), triggered from the Graph page toolbar after reconnaissance completes — exactly like the GVM vulnerability scanner.

The scanner uses **40+ regex patterns** and **Shannon entropy analysis** to detect leaked credentials including AWS keys, Google Cloud credentials, database connection strings, JWT tokens, private RSA/SSH keys, Slack/Discord/Stripe tokens, and many more. Results are stored in the Neo4j graph and can be downloaded as JSON.

> **Important:** The GitHub token is used **exclusively for read-only scanning**. It accesses the GitHub API to list repositories and read file contents — it never creates, modifies, or deletes anything on GitHub.

**How to Create a GitHub Personal Access Token:**

1. Go to **GitHub.com** → click your profile picture (top-right) → **Settings**
2. In the left sidebar, scroll to the bottom and click **Developer settings**
3. Click **Personal access tokens** → **Tokens (classic)**
4. Click **Generate new token** → **Generate new token (classic)**
5. Give it a descriptive name (e.g., `redamon-secret-scan`)
6. Set an expiration (recommended: 30 or 90 days)
7. Select the following scopes:
   - **`repo`** — Full control of private repositories. Required to read repository contents and search through code. This is the minimum required scope.
   - **`read:org`** — Read organization membership. Required to list organization repositories and discover member accounts when "Scan Member Repositories" is enabled.
   - **`gist`** — Access gists. Required only if you enable "Scan Gists" to search for secrets in public and private gists.
8. Click **Generate token** and copy the token immediately (it starts with `ghp_`). You won't be able to see it again.
9. Paste the token into the **GitHub Access Token** field in your project settings.

**Parameters:**

| Parameter | Default | Description |
|-----------|---------|-------------|
| GitHub Access Token | — | The Personal Access Token (PAT) that authenticates API requests to GitHub. Without this token, no scanning can occur — all other options remain disabled until a valid token is provided. The token format is `ghp_xxxxxxxxxxxx`. See the step-by-step guide above for creating one with the correct scopes |
| Target Organization | — | The GitHub **organization name** or **username** to scan. This is the account whose repositories will be searched for leaked secrets. For example, if your target domain is `example.com` and their GitHub organization is `example-inc`, enter `example-inc` here. You can also enter a personal GitHub username to scan that user's public repositories. The scanner will enumerate all accessible repositories under this account and search their contents for secret patterns |
| Target Repositories | — | Comma-separated list of **repository names** to scan (e.g., `repo1, repo2, repo3`). When specified, only the listed repositories are scanned instead of all repositories under the target organization/user. Matching is **case-insensitive** and uses the repository name only (not `owner/repo`). Leave empty to scan **all** accessible repositories — which is the default behavior |
| Scan Member Repositories | false | When enabled, the scanner also discovers and scans repositories belonging to **individual members** of the target organization — not just the organization's own repos. This is useful because developers often store work-related code (including secrets) in their personal accounts. Requires the `read:org` scope on your token. Significantly increases scan scope and time |
| Scan Gists | false | When enabled, the scanner searches **GitHub Gists** (code snippets) created by the organization and its members. Developers frequently paste configuration files, API keys, and connection strings into gists without realizing they're public. Requires the `gist` scope on your token |
| Scan Commits | false | When enabled, the scanner examines **commit history** — not just the current state of files, but also previous versions. This catches secrets that were committed and later removed (but remain in git history). **This is the most expensive operation** — disabling it saves 50%+ of total scan time. Each commit requires a separate API call to retrieve and analyze the diff |
| Max Commits to Scan | 100 | The maximum number of commits to examine **per repository**. Only visible when "Scan Commits" is enabled. Scan time scales linearly with this value: 100 commits (default) provides a reasonable balance between coverage and speed; 500 covers more history at ~5x the time; 1000 is thorough but ~10x slower. Valid range: 1–1000 |
| Output as JSON | false | When enabled, saves the complete scan results as a structured JSON file (`github_hunt_{project_id}.json`) that can be downloaded from the Graph page. The JSON includes every detected secret with its file path, line number, matched pattern, repository name, and entropy score |

#### Agent Behavior

Configure the AI agent orchestrator that performs autonomous pentesting. Controls LLM model, phase transitions, payload settings, tool access, and safety gates.

**LLM & Phase Configuration:**

| Parameter | Default | Description |
|-----------|---------|-------------|
| LLM Model | gpt-5.2 | The language model powering the agent. Supports Anthropic (Claude Opus 4.6, Sonnet 4.5, Haiku 4.5) and OpenAI (GPT-5.2, GPT-5, GPT-4.1 families). Anthropic models require ANTHROPIC_API_KEY |
| Post-Exploitation Type | statefull | `statefull` — keeps Meterpreter sessions between turns. `stateless` — executes one-shot commands |
| Activate Post-Exploitation Phase | true | Whether post-exploitation is available at all. When disabled, the agent stops after exploitation |
| Informational Phase System Prompt | — | Custom instructions injected during the informational/recon phase. Leave empty for default |
| Exploitation Phase System Prompt | — | Custom instructions injected during the exploitation phase. Leave empty for default |
| Post-Exploitation Phase System Prompt | — | Custom instructions injected during the post-exploitation phase. Leave empty for default |

**Payload Direction:**

Controls how reverse/bind shell payloads connect. **Reverse**: target connects back to you (LHOST + LPORT). **Bind**: you connect to the target (leave LPORT empty).

| Parameter | Default | Description |
|-----------|---------|-------------|
| LHOST (Attacker IP) | — | Your IP address for reverse shell callbacks. Leave empty for bind mode |
| LPORT | — | Your listening port for reverse shells. Leave empty for bind mode |
| Bind Port on Target | — | Port the target opens when using bind shell payloads. Leave empty if unsure (agent will ask) |
| Payload Use HTTPS | false | Use `reverse_https` instead of `reverse_tcp` for reverse payloads |

**Agent Limits:**

| Parameter | Default | Description |
|-----------|---------|-------------|
| Max Iterations | 100 | Maximum LLM reasoning-action loops per objective |
| Trace Memory Steps | 100 | Number of past steps kept in the agent's working context |
| Tool Output Max Chars | 20000 | Truncation limit for tool output passed to the LLM (min: 1000) |

**Approval Gates:**

| Parameter | Default | Description |
|-----------|---------|-------------|
| Require Approval for Exploitation | true | User confirmation before transitioning to exploitation phase |
| Require Approval for Post-Exploitation | true | User confirmation before transitioning to post-exploitation phase |

**Brute Force Credential Guess:**

Configure brute force credential guessing attack parameters including speed throttling and retry limits.

| Parameter | Default | Description |
|-----------|---------|-------------|
| Bruteforce Speed | 5 | Delay between login attempts. `5` — No delay (Fastest), `4` — 0.1s (Aggressive), `3` — 0.5s (Normal), `2` — 1s (Polite), `1` — 15s (Sneaky), `0` — 5 min (Glacial/Stealth). Lower values reduce detection risk but take longer |
| Brute Force Max Wordlist Attempts | 3 | Wordlist combinations to try before giving up (1-10) |

**Retries, Logging & Debug:**

| Parameter | Default | Description |
|-----------|---------|-------------|
| Cypher Max Retries | 3 | Neo4j query retry attempts on failure (0-10) |
| Log Max MB | 10 | Maximum log file size before rotation |
| Log Backups | 5 | Number of rotated log backups to keep |
| Create Graph Image on Init | false | Generate a LangGraph visualization when the agent starts. Useful for debugging |

**Tool Phase Restrictions:**

A matrix that controls which tools the agent can use in each operational phase. Each tool can be enabled/disabled independently per phase:

| Tool | Informational | Exploitation | Post-Exploitation |
|------|:---:|:---:|:---:|
| query_graph | ✓ | ✓ | ✓ |
| web_search | ✓ | ✓ | ✓ |
| execute_curl | ✓ | ✓ | ✓ |
| execute_naabu | ✓ | ✓ | ✓ |
| metasploit_console | — | ✓ | ✓ |
| msf_restart | — | ✓ | ✓ |

---

## System Architecture

### High-Level Architecture

```mermaid
flowchart TB
    subgraph User["👤 User Layer"]
        Browser[Web Browser]
        CLI[Terminal/CLI]
    end

    subgraph Frontend["🖥️ Frontend Layer"]
        Webapp[Next.js Webapp<br/>:3000]
    end

    subgraph Backend["⚙️ Backend Layer"]
        Agent[AI Agent Orchestrator<br/>FastAPI + LangGraph<br/>:8090]
        ReconOrch[Recon Orchestrator<br/>FastAPI + Docker SDK<br/>:8010]
    end

    subgraph Tools["🔧 MCP Tools Layer"]
        Naabu[Naabu Server<br/>:8000]
        Curl[Curl Server<br/>:8001]
        Nuclei[Nuclei Server<br/>:8002]
        Metasploit[Metasploit Server<br/>:8003]
    end

    subgraph Scanning["🔍 Scanning Layer"]
        Recon[Recon Pipeline<br/>Docker Container]
        GVM[GVM/OpenVAS Scanner<br/>Network Vuln Assessment]
        GHHunt[GitHub Secret Hunter<br/>Credential Scanning]
    end

    subgraph Data["💾 Data Layer"]
        Neo4j[(Neo4j Graph DB<br/>:7474/:7687)]
        Postgres[(PostgreSQL<br/>Project Settings<br/>:5432)]
    end

    subgraph Targets["🎯 Target Layer"]
        Target[Target Systems]
        GuineaPigs[Guinea Pigs<br/>Test VMs]
    end

    Browser --> Webapp
    CLI --> Recon
    Webapp <-->|WebSocket| Agent
    Webapp -->|REST + SSE| ReconOrch
    Webapp --> Neo4j
    Webapp --> Postgres
    ReconOrch -->|Docker SDK| Recon
    ReconOrch -->|Docker SDK| GVM
    ReconOrch -->|Docker SDK| GHHunt
    Recon -->|Fetch Settings| Webapp
    GHHunt -->|GitHub API| GHHunt
    Agent --> Neo4j
    Agent -->|MCP Protocol| Naabu
    Agent -->|MCP Protocol| Curl
    Agent -->|MCP Protocol| Nuclei
    Agent -->|MCP Protocol| Metasploit
    Recon --> Neo4j
    GVM -->|Reads Recon Output| Recon
    GVM --> Neo4j
    GVM --> Target
    GVM --> GuineaPigs
    Naabu --> Target
    Nuclei --> Target
    Metasploit --> Target
    Naabu --> GuineaPigs
    Nuclei --> GuineaPigs
    Metasploit --> GuineaPigs
```

### Data Flow Pipeline

```mermaid
flowchart TB
    subgraph Phase1["Phase 1: Reconnaissance"]
        Domain[🌐 Domain] --> Subdomains[📋 Subdomains<br/>crt.sh, HackerTarget, Knockpy]
        Subdomains --> DNS[🔍 DNS Resolution]
        DNS --> Ports[🔌 Port Scan<br/>Naabu]
        Ports --> HTTP[🌍 HTTP Probe<br/>Httpx]
        HTTP --> Tech[🔧 Tech Detection<br/>Wappalyzer]
        Tech --> Vulns[⚠️ Vuln Scan<br/>Nuclei]
    end

    subgraph Phase2["Phase 2: Data Storage"]
        Vulns --> JSON[(JSON Output)]
        JSON --> Graph[(Neo4j Graph)]
    end

    subgraph Phase2b["Phase 2b: Network Vuln Scan (Optional)"]
        JSON -->|IPs + Hostnames| GVM[🛡️ GVM/OpenVAS<br/>170k+ NVTs]
        GVM --> GVMResults[(GVM JSON Output)]
        GVMResults --> Graph
    end

    subgraph Phase2c["Phase 2c: GitHub Secret Hunt (Optional)"]
        JSON -->|Target Domain| GHHunt[🔑 GitHub Secret Hunter<br/>40+ Patterns + Entropy]
        GHHunt --> GHResults[(GitHub Hunt JSON Output)]
        GHResults --> Graph
    end

    subgraph Phase3["Phase 3: AI Analysis"]
        Graph --> Agent[🤖 AI Agent]
        Agent --> Query[Natural Language<br/>→ Cypher Query]
        Query --> Graph
    end

    subgraph Phase4["Phase 4: Exploitation"]
        Agent --> MCP[MCP Tools]
        MCP --> Naabu2[Naabu<br/>Port Scan]
        MCP --> Nuclei2[Nuclei<br/>Vuln Verify]
        MCP --> MSF[Metasploit<br/>Exploit]
        MSF --> Shell[🐚 Shell/Meterpreter]
    end

    subgraph Phase5["Phase 5: Post-Exploitation"]
        Shell --> Enum[Enumeration]
        Enum --> Pivot[Lateral Movement]
        Pivot --> Exfil[Data Exfiltration]
    end
```

### Docker Container Architecture

```mermaid
flowchart TB
    subgraph Host["🖥️ Host Machine"]
        subgraph Containers["Docker Containers"]
            subgraph ReconOrchContainer["recon-orchestrator"]
                OrchAPI[FastAPI :8010]
                DockerSDK[Docker SDK]
                SSEStream[SSE Log Streaming]
            end

            subgraph ReconContainer["recon-container"]
                ReconPy[Python Scripts]
                Naabu1[Naabu]
                Httpx[Httpx]
                Knockpy[Knockpy]
            end

            subgraph MCPContainer["kali-mcp-sandbox"]
                MCPServers[MCP Servers]
                NaabuTool[Naabu :8000]
                CurlTool[Curl :8001]
                NucleiTool[Nuclei :8002]
                MSFTool[Metasploit :8003]
            end

            subgraph AgenticContainer["agentic-container"]
                FastAPI[FastAPI :8090]
                LangGraph[LangGraph Engine]
                Claude[Claude AI]
            end

            subgraph Neo4jContainer["neo4j-container"]
                Neo4jDB[(Neo4j :7687)]
                Browser[Browser :7474]
            end

            subgraph PostgresContainer["postgres-container"]
                PostgresDB[(PostgreSQL :5432)]
                Prisma[Prisma ORM]
            end

            subgraph WebappContainer["webapp-container"]
                NextJS[Next.js :3000]
                PrismaClient[Prisma Client]
            end

            subgraph GVMStack["GVM Stack (Network Vuln Scanner)"]
                GVMd[gvmd<br/>GVM Daemon]
                OSPD[ospd-openvas<br/>Scanner Engine]
                RedisGVM[redis-gvm<br/>Cache/Queue]
                PgGVM[pg-gvm<br/>GVM Database]
                GVMData[Data Containers<br/>VT + SCAP + CERT + Notus]
            end

            subgraph GVMScanContainer["gvm-scanner-container"]
                GVMScanPy[Python Scripts]
                GVMClient[python-gvm Client]
            end

            subgraph GHHuntContainer["github-secret-hunter-container"]
                GHHuntPy[Python Scripts]
                PyGithub[PyGithub Client]
            end

            subgraph GuineaContainer["guinea-pigs"]
                Apache1[Apache 2.4.25<br/>CVE-2017-3167]
                Apache2[Apache 2.4.49<br/>CVE-2021-41773]
            end
        end

        Volumes["📁 Shared Volumes"]
        ReconOrchContainer -->|Manages| ReconContainer
        ReconOrchContainer -->|Manages| GVMScanContainer
        ReconOrchContainer -->|Manages| GHHuntContainer
        GVMScanContainer -->|Unix Socket| GVMd
        GVMd --> OSPD
        GVMd --> PgGVM
        OSPD --> RedisGVM
        GVMData -->|Feed Sync| GVMd
        ReconContainer --> Volumes
        GVMScanContainer -->|Reads Recon Output| Volumes
        Volumes --> Neo4jContainer
        GVMScanContainer --> Neo4jContainer
        WebappContainer --> PostgresContainer
        ReconContainer -->|Fetch Settings| WebappContainer
    end
```

### Recon Pipeline Detail

```mermaid
flowchart TB
    subgraph Input["📥 Input Configuration"]
        Params[project_settings.py<br/>Webapp API → PostgreSQL<br/>TARGET_DOMAIN, SCAN_MODULES]
        Env[.env<br/>API Keys<br/>Neo4j Credentials]
    end

    subgraph Container["🐳 recon-container (Kali Linux)"]
        Main[main.py<br/>Pipeline Orchestrator]

        subgraph Module1["1️⃣ domain_discovery"]
            WHOIS[whois_recon.py<br/>WHOIS Lookup]
            CRT[crt.sh API<br/>Certificate Transparency]
            HT[HackerTarget API<br/>Subdomain Search]
            Knock[Knockpy<br/>Active Bruteforce]
            DNS[DNS Resolution<br/>A, AAAA, MX, NS, TXT]
        end

        subgraph Module2["2️⃣ port_scan"]
            Naabu[Naabu<br/>SYN/CONNECT Scan<br/>Top 100-1000 Ports]
            Shodan[Shodan InternetDB<br/>Passive Mode]
        end

        subgraph Module3["3️⃣ http_probe"]
            Httpx[Httpx<br/>HTTP/HTTPS Probe]
            Tech[Wappalyzer Rules<br/>Technology Detection]
            Headers[Header Analysis<br/>Security Headers]
            Certs[TLS Certificate<br/>Extraction]
        end

        subgraph Module4["4️⃣ resource_enum"]
            Katana[Katana<br/>Web Crawler]
            Forms[Form Parser<br/>Input Discovery]
            Endpoints[Endpoint<br/>Classification]
        end

        subgraph Module5["5️⃣ vuln_scan"]
            Nuclei[Nuclei<br/>9000+ Templates]
            MITRE[add_mitre.py<br/>CWE/CAPEC Enrichment]
        end
    end

    subgraph Output["📤 Output"]
        JSON[(recon/output/<br/>recon_domain.json)]
        Graph[(Neo4j Graph<br/>via neo4j_client.py)]
    end

    Params --> Main
    Env --> Main

    Main --> WHOIS
    WHOIS --> CRT
    CRT --> HT
    HT --> Knock
    Knock --> DNS

    DNS --> Naabu
    Naabu -.-> Shodan

    Naabu --> Httpx
    Httpx --> Tech
    Tech --> Headers
    Headers --> Certs

    Certs --> Katana
    Katana --> Forms
    Forms --> Endpoints

    Endpoints --> Nuclei
    Nuclei --> MITRE

    MITRE --> JSON
    JSON --> Graph
```

### Recon Module Data Flow

```mermaid
sequenceDiagram
    participant User
    participant Main as main.py
    participant DD as domain_discovery
    participant PS as port_scan
    participant HP as http_probe
    participant RE as resource_enum
    participant VS as vuln_scan
    participant JSON as JSON Output
    participant Neo4j as Neo4j Graph
    participant GVM as GVM Scanner

    User->>Main: python main.py
    Main->>Main: Load project settings (API or defaults)

    rect rgb(40, 40, 80)
        Note over DD: Phase 1: Domain Discovery
        Main->>DD: discover_subdomains(domain)
        DD->>DD: WHOIS lookup
        DD->>DD: crt.sh query
        DD->>DD: HackerTarget API
        DD->>DD: Knockpy bruteforce
        DD->>DD: DNS resolution (all records)
        DD-->>Main: subdomains + IPs
    end

    rect rgb(40, 80, 40)
        Note over PS: Phase 2: Port Scanning
        Main->>PS: run_port_scan(targets)
        PS->>PS: Naabu SYN scan
        PS->>PS: Service detection
        PS->>PS: CDN/WAF detection
        PS-->>Main: open ports + services
    end

    rect rgb(80, 40, 40)
        Note over HP: Phase 3: HTTP Probing
        Main->>HP: run_http_probe(targets)
        HP->>HP: HTTP/HTTPS requests
        HP->>HP: Follow redirects
        HP->>HP: Technology fingerprint
        HP->>HP: Extract headers + certs
        HP-->>Main: live URLs + tech stack
    end

    rect rgb(80, 80, 40)
        Note over RE: Phase 4: Resource Enumeration
        Main->>RE: run_resource_enum(urls)
        RE->>RE: Katana crawl
        RE->>RE: Parse forms + inputs
        RE->>RE: Classify endpoints
        RE-->>Main: endpoints + parameters
    end

    rect rgb(80, 40, 80)
        Note over VS: Phase 5: Vulnerability Scan
        Main->>VS: run_vuln_scan(targets)
        VS->>VS: Nuclei templates
        VS->>VS: CVE detection
        VS->>VS: MITRE CWE/CAPEC mapping
        VS-->>Main: vulnerabilities + CVEs
    end

    Main->>JSON: Save recon_domain.json
    Main->>Neo4j: Update graph database
    Neo4j-->>User: Graph ready for visualization

    rect rgb(40, 80, 80)
        Note over GVM: Phase 6 (Optional): Network Vuln Scan
        User->>GVM: Trigger GVM scan from UI
        GVM->>JSON: Read recon output (IPs + hostnames)
        GVM->>GVM: Create scan targets
        GVM->>GVM: Run 170k+ NVTs per target
        GVM->>GVM: Parse results + CVE extraction
        GVM->>Neo4j: Store Vulnerability + CVE nodes
        Neo4j-->>User: Network vulns added to graph
    end

    rect rgb(80, 60, 80)
        Note over GVM: Phase 7 (Optional): GitHub Secret Hunt
        User->>GVM: Trigger GitHub Hunt from UI
        GVM->>GVM: Load project settings (token, org, options)
        GVM->>GVM: Enumerate repositories + gists
        GVM->>GVM: Scan contents with 40+ patterns + entropy
        GVM->>GVM: Scan commit history (if enabled)
        GVM->>Neo4j: Store findings in graph
        Neo4j-->>User: Leaked secrets added to graph
    end
```

### Agent Workflow (ReAct Pattern)

```mermaid
stateDiagram-v2
    [*] --> Idle: Start
    Idle --> Reasoning: User Message

    Reasoning --> ToolSelection: Analyze Task
    ToolSelection --> AwaitApproval: Dangerous Tool?
    ToolSelection --> ToolExecution: Safe Tool

    AwaitApproval --> ToolExecution: User Approves
    AwaitApproval --> Reasoning: User Rejects

    ToolExecution --> Observation: Execute MCP Tool
    Observation --> Reasoning: Analyze Results

    Reasoning --> Response: Task Complete
    Response --> Idle: Send to User

    Reasoning --> AskQuestion: Need Clarification?
    AskQuestion --> Reasoning: User Response

    state "User Guidance" as Guidance
    Reasoning --> Guidance: User sends guidance
    Guidance --> Reasoning: Injected in next think step

    state "Stopped" as Stopped
    Reasoning --> Stopped: User clicks Stop
    ToolExecution --> Stopped: User clicks Stop
    Stopped --> Reasoning: User clicks Resume
```

### MCP Tool Integration

```mermaid
sequenceDiagram
    participant User
    participant Agent as AI Agent
    participant MCP as MCP Manager
    participant Tool as Tool Server
    participant Target

    User->>Agent: "Scan ports on 10.0.0.5"
    Agent->>Agent: Reasoning (ReAct)
    Agent->>MCP: Request naabu tool
    MCP->>Tool: JSON-RPC over SSE
    Tool->>Target: SYN Packets
    Target-->>Tool: Open Ports
    Tool-->>MCP: JSON Results
    MCP-->>Agent: Parsed Output
    Agent->>Agent: Analyze Results
    Agent-->>User: "Found ports 22, 80, 443..."
```

---

## Components

### 1. Reconnaissance Pipeline

Automated OSINT and vulnerability scanning starting from a single domain.

| Tool | Purpose |
|------|---------|
| crt.sh | Certificate Transparency subdomain discovery |
| HackerTarget | API-based subdomain enumeration |
| Knockpy | Active subdomain bruteforcing |
| Naabu | Fast port scanning |
| Httpx | HTTP probing and technology detection |
| Nuclei | Template-based vulnerability scanning |

📖 **[Read Recon Documentation](recon/README.RECON.md)**

---

### 2. Graph Database

Neo4j-powered attack surface mapping with multi-tenant support.

```
Domain → Subdomain → IP → Port → Service → Technology → Vulnerability → CVE
```

- **Browser UI**: http://localhost:7474
- **Bolt Protocol**: bolt://localhost:7687

📖 **[Read Graph DB Documentation](graph_db/readmes/README.GRAPH_DB.md)**
📖 **[View Graph Schema](graph_db/readmes/GRAPH.SCHEMA.md)**

---

### 3. MCP Tool Servers

Security tools exposed via Model Context Protocol for AI agent integration.

| Server | Port | Tool | Capability |
|--------|------|------|------------|
| naabu | 8000 | Naabu | Fast port scanning, service detection |
| curl | 8001 | Curl | HTTP requests, header inspection |
| nuclei | 8002 | Nuclei | 9000+ vulnerability templates |
| metasploit | 8003 | Metasploit | Exploitation, post-exploitation, sessions |

📖 **[Read MCP Documentation](mcp/README.MCP.md)**

---

### 4. AI Agent Orchestrator

LangGraph-based autonomous agent with ReAct pattern.

- **WebSocket Streaming**: Real-time updates to frontend
- **Phase-Aware Execution**: Human approval for dangerous operations
- **Memory Persistence**: Conversation history via MemorySaver
- **Multi-Objective Support**: Complex attack chain planning
- **Live Guidance**: Send steering messages to the agent while it works
- **Stop & Resume**: Interrupt execution and resume from the last checkpoint

📖 **[Read Agentic Documentation](agentic/README.AGENTIC.md)**
📖 **[Metasploit Integration Guide](agentic/README.METASPLOIT.GUIDE.md)**
📖 **[Attack Paths Architecture](agentic/README.ATTACK_PATHS.md)**

---

### 5. Web Application

Next.js dashboard for visualization and AI interaction.

- **Graph Visualization**: Interactive Neo4j graph explorer
- **AI Chat Interface**: WebSocket-based agent communication
- **Node Inspector**: Detailed view of assets and relationships
- **Approval Workflows**: Confirm dangerous tool executions

📖 **[Read Webapp Documentation](webapp/README.WEBAPP.md)**

---

### 6. GVM Scanner

Greenbone Vulnerability Management (GVM), formerly known as OpenVAS, is an enterprise-grade network vulnerability scanner. Unlike Nuclei (which focuses on web application testing via HTTP templates), GVM performs deep network-level vulnerability assessment by probing services directly at the protocol layer — testing for misconfigurations, outdated software, default credentials, and known CVEs across every open port.

- **170,000+ Network Vulnerability Tests (NVTs)** — the largest open-source vulnerability test feed, covering operating systems, network services, databases, and embedded devices.
- **CVSS scoring and CVE mapping** — every finding includes a CVSS score, CVE references, and remediation guidance.
- **Recon output integration** — consumes the IP addresses and hostnames discovered by the recon pipeline, eliminating the need for redundant host discovery.
- **Graph database linkage** — GVM findings are stored as Vulnerability nodes (source="gvm") in Neo4j, linked to IP and Subdomain nodes via `HAS_VULNERABILITY` relationships, with associated CVE nodes — complementing the web-layer findings from Nuclei.
- **Webapp integration** — triggered from the Graph page via a dedicated "GVM Scan" button (requires prior recon data). Logs stream in real-time to a log drawer with 4-phase progress tracking, and results can be downloaded as JSON.

📖 **[Read GVM Documentation](gvm_scan/README.GVM.md)**

---

### 7. GitHub Secret Hunter

Standalone module that scans GitHub repositories, gists, and commit history for exposed secrets and credentials related to your target. Runs independently from the recon pipeline — triggered from the Graph page after reconnaissance completes.

- **40+ secret detection patterns** — regex-based matching for AWS keys, Google Cloud credentials, database connection strings, JWT tokens, private keys, Slack/Discord/Stripe tokens, SSH keys, and more.
- **Shannon entropy analysis** — detects high-entropy strings that may be secrets even when no regex pattern matches, reducing false negatives.
- **Commit history scanning** — examines git diffs to find secrets that were committed and later removed but remain in version history.
- **Organization and member scanning** — enumerates repositories under a target organization and optionally extends to repositories of individual organization members.
- **Gist scanning** — searches public and private gists for leaked credentials.
- **Graph database linkage** — findings are stored in Neo4j and linked to the target's attack surface graph.
- **Webapp integration** — triggered from the Graph page via a dedicated "GitHub Hunt" button (requires prior recon data). Logs stream in real-time to a log drawer with 3-phase progress tracking, and results can be downloaded as JSON.

#### Running a GitHub Secret Hunt

1. Configure a **GitHub Personal Access Token** and **Target Organization** in the project settings (see [GitHub Secret Hunting parameters](#github-secret-hunting) for step-by-step token setup)
2. Navigate to Graph page
3. Click the **GitHub Hunt** button (enabled only when recon data exists for the project)
4. Watch real-time logs in the GitHub Hunt logs drawer (3-phase progress: Loading Settings, Scanning Repositories, Complete)
5. Download the results JSON when complete

> **Note:** The GitHub token is used **exclusively for read-only scanning** — it searches repositories and gists for leaked secrets using pattern matching and entropy analysis. It does not modify, create, or delete any content on GitHub.

---

### 8. Test Environments

> **Status: Under Development** — Guinea pig environments are provided as reference configurations but are not yet fully integrated into the automated pipeline.

Intentionally vulnerable Docker containers for safe, isolated testing. These environments let you validate the full RedAmon pipeline — from reconnaissance to exploitation — without touching any external system.

| Environment | Vulnerability | Description |
|-------------|--------------|-------------|
| Apache 2.4.25 | CVE-2017-3167 | Authentication bypass in `mod_auth_digest`, allowing unauthorized access to protected resources |
| Apache 2.4.49 | CVE-2021-41773 (Path Traversal + RCE) | Path normalization flaw enabling directory traversal and remote code execution via `mod_cgi` |

These containers are designed to be deployed alongside the main stack so the AI agent can discover, scan, and exploit them in a controlled lab environment.

📖 **[Read Guinea Pigs Documentation](guinea_pigs/README.GPIGS.md)**

---

## Technology Stack

### Frontend

| Technology | Role |
|-----------|------|
| **Next.js** (v16) | Full-stack React framework — server-side rendering, API routes, and the project webapp |
| **React** (v19) | Component-based UI library powering all interactive views |
| **TypeScript** | Static typing across the entire frontend codebase |
| **TanStack React Query** | Server state management, caching, and data synchronization |
| **React Force Graph (2D & 3D)** | Interactive attack surface graph visualization |
| **Three.js** | 3D rendering engine behind the 3D graph view |
| **D3 Force** | Force-directed layout algorithms for graph positioning |
| **React Markdown** | Rendering agent chat responses with markdown formatting |
| **React Syntax Highlighter** | Code block highlighting in agent outputs |
| **Lucide React** | Icon system used throughout the UI |

### Backend & API

| Technology | Role |
|-----------|------|
| **FastAPI** | Async Python web framework for the Recon Orchestrator and Agent API |
| **Uvicorn** | ASGI server running both FastAPI services |
| **Pydantic** | Data validation and settings management across all Python services |
| **Docker SDK for Python** | Programmatic container lifecycle management — the Recon Orchestrator uses it to spawn and control recon, GVM, and GitHub hunt containers |
| **SSE (Server-Sent Events)** | Real-time log streaming from recon pipeline and GVM scans to the webapp |
| **WebSocket** | Bidirectional real-time communication between the agent and the webapp chat |

### AI & LLM

| Technology | Role |
|-----------|------|
| **LangChain** | LLM application framework — prompt management, tool binding, chain composition |
| **LangGraph** | State machine engine implementing the ReAct (Reasoning + Acting) agent loop |
| **Claude** (Anthropic) | Supported LLM family — Opus 4.6, Sonnet 4.5, Haiku 4.5 |
| **GPT** (OpenAI) | Supported LLM family — GPT-5.2, GPT-5, GPT-4.1 |
| **Tavily** | AI-powered web search used by the agent for CVE research and exploit intelligence |
| **Model Context Protocol (MCP)** | Standardized protocol for tool integration — the agent calls security tools through MCP servers |
| **LangChain MCP Adapters** | Bridges LangChain tool interface with MCP server endpoints |
| **Text-to-Cypher** | LLM-powered natural language to Neo4j Cypher query translation |

### Databases

| Technology | Role |
|-----------|------|
| **Neo4j** (Community Edition) | Graph database — stores the entire attack surface as an interconnected knowledge graph with 17 node types and 20+ relationship types |
| **APOC** | Neo4j plugin providing advanced procedures and functions for graph operations |
| **PostgreSQL** (v16) | Relational database — stores project settings, user accounts, and configuration data |
| **Prisma** | TypeScript ORM for PostgreSQL — schema management, migrations, and type-safe queries |
| **Redis** | In-memory cache and message queue used within the GVM vulnerability scanning stack |

### Security & Penetration Testing Tools

| Tool | Category | Role |
|------|----------|------|
| **Kali Linux** | Base Platform | Penetration testing distribution used as the base Docker image for recon and MCP tool containers |
| **Metasploit Framework** | Exploitation | Exploit execution, payload delivery, Meterpreter sessions, auxiliary scanners, and post-exploitation |
| **Naabu** | Port Scanning | Fast SYN/CONNECT port scanner from ProjectDiscovery |
| **Nmap** | Network Scanning | Network mapper used as fallback for service detection and banner grabbing |
| **Nuclei** | Vulnerability Scanning | Template-based scanner with 9,000+ community templates — DAST fuzzing, CVE detection, misconfiguration checks |
| **Httpx** | HTTP Probing | HTTP/HTTPS probing, technology detection, TLS inspection, and response metadata extraction |
| **Katana** | Web Crawling | Active web crawler with JavaScript rendering — discovers URLs, endpoints, forms, and parameters |
| **GAU** (GetAllUrls) | Passive Recon | Passive URL discovery from Wayback Machine, Common Crawl, AlienVault OTX, and URLScan.io |
| **Kiterunner** | API Discovery | API endpoint brute-forcer using real-world Swagger/OpenAPI-derived wordlists |
| **Knockpy** | Subdomain Discovery | Active subdomain brute-forcing tool |
| **Wappalyzer** | Fingerprinting | Technology fingerprinting engine with 6,000+ detection rules |
| **Interactsh** | Out-of-Band Detection | Callback server for detecting blind vulnerabilities (SSRF, XXE, blind SQLi) |
| **Tor / Proxychains4** | Anonymity | Anonymous traffic routing for stealthy reconnaissance |

### Vulnerability Assessment

| Technology | Role |
|-----------|------|
| **GVM / OpenVAS** (Greenbone) | Network-level vulnerability scanner with 170,000+ Network Vulnerability Tests (NVTs) |
| **ospd-openvas** | OpenVAS scanner engine — executes protocol-level probes against target services |
| **gvmd** | GVM daemon — orchestrates scans, manages configurations, and exposes the GMP API |
| **GitHub Secret Hunter** | Custom scanner using 40+ regex patterns and Shannon entropy analysis to detect leaked credentials in GitHub repositories |

### Data Sources & Threat Intelligence

| Source | Role |
|--------|------|
| **NVD** (National Vulnerability Database) | CVE lookup, CVSS scores, and vulnerability descriptions |
| **MITRE CWE / CAPEC** | Weakness classification and common attack pattern mapping for discovered CVEs |
| **Shodan InternetDB** | Passive port and service data without sending packets to the target |
| **crt.sh** | Certificate Transparency log queries for subdomain discovery |
| **Wayback Machine** | Historical URL archive for passive endpoint discovery |
| **Common Crawl** | Web archive data for passive URL collection |
| **AlienVault OTX** | Open threat intelligence feed for URL and indicator enrichment |
| **URLScan.io** | URL scanning and analysis data |
| **HackerTarget** | Passive subdomain enumeration API |
| **Vulners** | Alternative vulnerability database for CVE enrichment |
| **GitHub API** | Repository and code search for secret scanning via PyGithub |

### Infrastructure & DevOps

| Technology | Role |
|-----------|------|
| **Docker** | Container runtime — every component runs containerized with zero host dependencies |
| **Docker Compose** (v2) | Multi-container orchestration — defines and manages the entire 12+ container stack |
| **Docker-in-Docker (DinD)** | Architecture pattern allowing the Recon Orchestrator to spawn ephemeral scan containers |
| **Python** (3.11) | Core language for all backend services — recon pipeline, agent, orchestrator, GVM scanner, GitHub hunter |
| **Node.js** (v22) | JavaScript runtime for the Next.js webapp |
| **Go** (1.25) | Build environment for compiling ProjectDiscovery tools (Naabu, Nuclei) from source |
| **Bash / Shell** | Container entrypoint scripts, tool orchestration, and automation |

### Protocols & Communication

| Protocol | Role |
|----------|------|
| **MCP (Model Context Protocol)** | Standardized tool integration — four MCP servers (Naabu, Curl, Nuclei, Metasploit) running inside the Kali sandbox |
| **SSE (Server-Sent Events)** | Unidirectional real-time streaming for recon logs, GVM scan progress, and GitHub hunt output |
| **WebSocket** | Bidirectional real-time communication for the agent chat interface |
| **Bolt** (Neo4j) | Binary protocol for high-performance Neo4j graph database queries |
| **GMP** (Greenbone Management Protocol) | XML-based protocol for communicating with the GVM daemon |
| **REST / HTTP** | Inter-service API communication between all containers |

---

## Documentation

| Component | Documentation |
|-----------|---------------|
| Reconnaissance | [recon/README.RECON.md](recon/README.RECON.md) |
| Recon Orchestrator | [recon_orchestrator/README.md](recon_orchestrator/README.md) |
| Graph Database | [graph_db/readmes/README.GRAPH_DB.md](graph_db/readmes/README.GRAPH_DB.md) |
| Graph Schema | [graph_db/readmes/GRAPH.SCHEMA.md](graph_db/readmes/GRAPH.SCHEMA.md) |
| PostgreSQL Database | [postgres_db/README.md](postgres_db/README.md) |
| MCP Servers | [mcp/README.MCP.md](mcp/README.MCP.md) |
| AI Agent | [agentic/README.AGENTIC.md](agentic/README.AGENTIC.md) |
| Attack Paths | [agentic/README.ATTACK_PATHS.md](agentic/README.ATTACK_PATHS.md) |
| Metasploit Guide | [agentic/README.METASPLOIT.GUIDE.md](agentic/README.METASPLOIT.GUIDE.md) |
| Webapp | [webapp/README.WEBAPP.md](webapp/README.WEBAPP.md) |
| GVM Scanner | [gvm_scan/README.GVM.md](gvm_scan/README.GVM.md) |
| GitHub Secret Hunter | [github_secret_hunt/README.md](github_secret_hunt/README.md) |
| Test Environments | [guinea_pigs/README.GPIGS.md](guinea_pigs/README.GPIGS.md) |
| Changelog | [CHANGELOG.md](CHANGELOG.md) |
| Full Disclaimer | [DISCLAIMER.md](DISCLAIMER.md) |
| License | [LICENSE](LICENSE) |

---

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to get started, code style conventions, and the pull request process.

---

## Maintainer

**Samuele Giampieri** — creator and lead maintainer.

- [LinkedIn](https://www.linkedin.com/in/samuele-giampieri-b1b67597/)
- [Devergo Labs](https://www.devergolabs.com/)
- [GitHub](https://github.com/samugit83)

---

## Legal

This project is released under the [MIT License](LICENSE).

See [DISCLAIMER.md](DISCLAIMER.md) for full terms of use, acceptable use policy, and legal compliance requirements.

---

<p align="center">
  <strong>Use responsibly. Test ethically. Defend better.</strong>
</p>
