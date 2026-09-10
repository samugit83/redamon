# RedAmon Reconnaissance Module

**Unmask the hidden before the world does.**

An automated OSINT reconnaissance and vulnerability scanning framework combining multiple security tools for comprehensive target assessment.

---

## Table of Contents

- [Quick Start](#-docker-quick-start-recommended)
- [Architecture](#-docker-in-docker-architecture)
- [Pipeline Overview](#-scanning-pipeline-overview)
- [Targeting Modes](#-targeting-modes)
- [Scan Modules](#-scan-modules-explained)
- [Tool Comparison](#-complete-tool-comparison)
- [Configuration](#-key-configuration-parameters)
- [Prerequisites](#-prerequisites)
- [Project Structure](#-project-structure)
- [Output Format](#-output-format)
- [Test Targets](#-test-targets)

---

## 🐳 Docker Quick Start (Recommended)

The recon module is fully containerized. All tools run inside Docker containers.

### Option 1: Start from Webapp (Recommended)

The easiest way to run recon is through the webapp UI, which provides:
- Real-time log streaming
- Phase progress tracking
- Project-specific settings from PostgreSQL
- Automatic Neo4j graph updates

```bash
# 1. Start all services
cd services/postgres_db && docker-compose up -d
cd ../graph_db && docker-compose up -d
cd ../recon_orchestrator && docker-compose up -d
cd ../webapp && npm run dev

# 2. Open http://localhost:3000/graph
# 3. Click "Start Recon" button
```

### Option 2: CLI with Environment Variables

For standalone CLI usage without the webapp:

```bash
# 1. Build the container (first time only)
cd recon/
docker-compose build

# 2. Run a scan with target specified via environment variable
TARGET_DOMAIN=testphp.vulnweb.com docker-compose run --rm recon python /app/recon/main.py
```

### Docker Environment Variables

Override default settings via environment variables:

```bash
# Run with custom target
TARGET_DOMAIN=example.com docker-compose run --rm recon python /app/recon/main.py

# Run specific modules only
SCAN_MODULES="domain_discovery,port_scan,http_probe" docker-compose run --rm recon python /app/recon/main.py
```

### When to Rebuild

| Change Type | Action Required |
|-------------|-----------------|
| Python code (*.py) changes | `docker-compose build` |
| `requirements.txt` changes | `docker-compose build --no-cache` |
| `Dockerfile` changes | `docker-compose build --no-cache` |
| `.env` file changes | No rebuild needed (mounted as volume) |

> **Pinned build artifacts (STRIDE T17).** The recon image build no longer pulls tools from moving refs: `recon/Dockerfile` pins ffuf (`@v2.1.0`), subjack/jsluice/masscan (commits), the SecLists + jhaddix wordlists (a commit / gist revision), and `recon/requirements.txt` pins knock + paramspider to commits. A moved or removed pinned artifact now **fails the build loudly** (a caught supply-chain change, not a silent runtime compromise). To bump a pin, edit the tag/commit in `recon/Dockerfile` or `recon/requirements.txt` and rebuild. (The auto-pulled sibling *tool containers* - naabu/httpx/nuclei/katana/gau/amass - are runtime images, out of T17 scope, and keep their `:latest` tags.)

---

## 🔗 Recon Orchestrator Integration

When started from the webapp, the recon module is managed by the **Recon Orchestrator** service, which provides:

- **Container Lifecycle Management** - Start/stop/monitor recon containers
- **Real-time Log Streaming** - SSE-based log streaming to the frontend
- **Phase Detection** - Automatic detection of scan phases from log output
- **Status Tracking** - Track running/completed/error states per project

### Configuration Hierarchy

Settings are resolved in the following order of precedence:

1. **Webapp API (Primary)** - When `PROJECT_ID` and `WEBAPP_API_URL` environment variables are set:
   ```bash
   # Set by recon orchestrator when starting container
   PROJECT_ID=cml6xov4q0002h58pln96n20d
   WEBAPP_API_URL=http://localhost:3000
   ```
   The recon module fetches all 169+ configurable parameters from:
   ```
   GET /api/projects/{projectId}
   ```

2. **Environment Variables** - Override individual settings:
   ```bash
   TARGET_DOMAIN=example.com docker-compose run --rm recon python /app/recon/main.py
   ```

3. **DEFAULT_SETTINGS (Fallback)** - Built-in defaults in `project_settings.py` for CLI usage without webapp

### project_settings.py

The `project_settings.py` module handles settings resolution:

```python
from recon.project_settings import get_settings

# Returns dict with all settings from API or DEFAULT_SETTINGS fallback
settings = get_settings()

TARGET_DOMAIN = settings['TARGET_DOMAIN']
SUBDOMAIN_LIST = settings['SUBDOMAIN_LIST']
SCAN_MODULES = settings['SCAN_MODULES']
# ... all 169+ parameters
```

### Orchestrator Communication Flow

```mermaid
sequenceDiagram
    participant Webapp as Webapp UI
    participant Orchestrator as Recon Orchestrator
    participant Recon as Recon Container
    participant API as Webapp API
    participant Neo4j as Neo4j

    Webapp->>Orchestrator: POST /recon/{projectId}/start
    Orchestrator->>Recon: docker run with PROJECT_ID, WEBAPP_API_URL
    Recon->>API: GET /api/projects/{projectId}
    API-->>Recon: Project settings (169+ params)
    Recon->>Recon: Execute scan pipeline
    Recon->>Neo4j: Update graph with results
    Orchestrator->>Webapp: SSE log stream
    Recon-->>Orchestrator: Container exits
    Orchestrator->>Webapp: Complete event
```

---

## 🏗️ Docker-in-Docker Architecture

The recon module uses a **Docker-in-Docker (DinD)** pattern where the main recon container orchestrates sibling containers for each scanning tool.

### How It Works

The recon container reaches the host's Docker daemon through a **filtering broker** rather than the raw socket. The broker validates every container-creation request — permitting only the known tool images, with mounts restricted to the shared scratch / output directories — and forwards the approved ones to the host daemon. All tool containers are therefore **siblings** managed by the same host daemon, while the recon container itself cannot create a container that mounts the host filesystem, runs privileged, or uses an unapproved image.

```mermaid
flowchart TB
    subgraph Host["🖥️ HOST MACHINE"]
        subgraph DockerDaemon["Docker Daemon (dockerd)"]
            Socket["/var/run/docker.sock"]
        end

        Broker["🛡️ docker-broker<br/>validates container creates<br/>allowlisted images + scratch mounts only"]

        subgraph Containers["Sibling Containers"]
            Recon["redamon-recon<br/>Python Orchestrator<br/>📋 Coordinates all scans"]
            NaabuC["naabu<br/>projectdiscovery/naabu<br/>🔌 Port Scanner"]
            HttpxC["httpx<br/>projectdiscovery/httpx<br/>🌐 HTTP Prober"]
            NucleiC["nuclei<br/>projectdiscovery/nuclei<br/>🎯 Vuln Scanner"]
            KatanaC["katana<br/>projectdiscovery/katana<br/>🕸️ Web Crawler"]
            GAUC["gau<br/>sxcurity/gau<br/>📚 URL Archives"]
            PurednsC["puredns<br/>frost19k/puredns<br/>🧹 Wildcard Filter"]
        end

        Volume["📁 Shared Volume<br/>recon/output/"]
    end

    Broker -.->|filtered socket| Recon
    Broker -.->|approved creates| Socket
    Recon -->|docker run| NaabuC
    Recon -->|docker run| HttpxC
    Recon -->|docker run| NucleiC
    Recon -->|docker run| KatanaC
    Recon -->|docker run| GAUC
    Recon -->|docker run| PurednsC

    NaabuC --> Volume
    HttpxC --> Volume
    NucleiC --> Volume
    KatanaC --> Volume
    GAUC --> Volume
    Recon --> Volume
```

### Container Execution Flow (Parallelized)

The pipeline uses a **fan-out / fan-in** pattern with `ThreadPoolExecutor` to run independent modules concurrently, significantly reducing total scan time while respecting data dependencies between groups.

```mermaid
sequenceDiagram
    participant User
    participant Recon as redamon-recon
    participant Docker as Docker Daemon
    participant Naabu as naabu container
    participant Httpx as httpx container
    participant Katana as katana container
    participant GAU as gau container
    participant KR as kiterunner container
    participant Nuclei as nuclei container
    participant GraphBG as Graph DB (background)

    User->>Recon: docker-compose run recon python main.py
    activate Recon

    Note over Recon: GROUP 1 — Fan-Out (parallel)
    par WHOIS + Discovery + URLScan
        Recon->>Recon: WHOIS lookup
    and
        Recon->>Recon: 5 discovery tools in parallel<br/>(crt.sh ∥ HackerTarget ∥ Subfinder ∥ Amass ∥ Knockpy)
    and
        Recon->>Recon: URLScan.io enrichment
    end
    Note over Recon: Fan-In — merge results + Puredns wildcard filtering + DNS (20 parallel workers)
    Recon->>GraphBG: Background: domain discovery graph update

    Note over Recon,Naabu: GROUP 3 — Fan-Out (parallel)
    par Shodan + Port Scan
        Recon->>Recon: Shodan enrichment
    and
        Recon->>Docker: docker run naabu
        Docker->>Naabu: Start container
        activate Naabu
        Naabu-->>Recon: JSON output (open ports)
        deactivate Naabu
    end
    Note over Recon: Fan-In — merge Shodan + port scan
    Recon->>GraphBG: Background: shodan + port scan graph update

    Note over Recon,Httpx: GROUP 4 — HTTP Probe (sequential)
    Recon->>Docker: docker run httpx
    Docker->>Httpx: Start container
    activate Httpx
    Httpx-->>Recon: JSON output (live URLs + tech)
    deactivate Httpx
    Recon->>GraphBG: Background: http probe graph update

    Note over Recon,KR: GROUP 5 — Resource Enum (parallel + sequential)
    par Katana ∥ Hakrawler ∥ GAU ∥ Kiterunner
        Recon->>Docker: docker run katana
        Docker->>Katana: Crawl live URLs
        Katana-->>Recon: endpoints
    and
        Recon->>Docker: docker run hakrawler
        Docker->>Hakrawler: DOM-aware crawl
        Hakrawler-->>Recon: links & forms
    and
        Recon->>Docker: docker run gau
        Docker->>GAU: Fetch archived URLs
        GAU-->>Recon: historical URLs
    and
        Recon->>Docker: docker run kiterunner
        Docker->>KR: API bruteforce
        KR-->>Recon: hidden APIs
    end
    Recon->>Recon: jsluice — extract URLs & secrets from JS files
    Recon->>Recon: FFuf — directory/endpoint fuzzing with wordlists
    Recon->>Recon: Merge & classify endpoints
    Recon->>GraphBG: Background: resource enum graph update

    Note over Recon,KR: GROUP 5b — JS Recon (if enabled)
    Recon->>Recon: Download JS files (parallel)
    Recon->>Recon: 100 regex patterns + key validation + source maps
    Recon->>Recon: Dependency confusion + endpoint extraction + DOM sinks
    Recon->>GraphBG: Background: js_recon graph update

    Note over Recon,Nuclei: GROUP 6 — Vuln Scan + MITRE
    Recon->>Docker: docker run nuclei
    Docker->>Nuclei: Start container
    activate Nuclei
    Nuclei-->>Recon: JSON output (vulns)
    deactivate Nuclei
    Recon->>Recon: MITRE CWE/CAPEC enrichment
    Recon->>GraphBG: Background: vuln scan graph update

    Note over Recon,GraphBG: Wait for all background graph updates
    Recon->>Recon: Save recon_domain.json
    Recon-->>User: Scan complete
    deactivate Recon
```

### Why Docker-in-Docker?

| Benefit | Description |
|---------|-------------|
| **Isolation** | Each tool runs in its own container with minimal dependencies |
| **Consistency** | Same tool versions regardless of host OS |
| **No host pollution** | Go binaries (naabu, httpx, nuclei) don't need to be installed on host |
| **Easy updates** | Just pull new Docker images to update tools |
| **Portability** | Works on any system with Docker installed |

---

## 🔄 Scanning Pipeline Overview

RedAmon executes scans in a **parallelized pipeline** using a fan-out / fan-in pattern. Independent modules within each group run concurrently via `ThreadPoolExecutor`, while groups that depend on prior results run sequentially. Graph DB updates happen in a dedicated background thread so the main pipeline is never blocked.

### High-Level Pipeline

```mermaid
flowchart LR
    subgraph Input["📥 Input"]
        Domain[🌐 Target Domain]
    end

    subgraph G1["GROUP 1 — parallel fan-out"]
        DD[WHOIS]
        SUB[Subdomain Discovery<br/>5 tools in parallel]
        URLSCAN[URLScan.io]
    end

    subgraph G3["GROUP 3 — parallel fan-out"]
        SHODAN[Shodan Enrichment]
        PS[Port Scan — Naabu]
    end

    subgraph G4["GROUP 4 — sequential"]
        HP[HTTP Probe<br/>Httpx + Wappalyzer]
    end

    subgraph G5["GROUP 5 — parallel + sequential"]
        RE[Resource Enum<br/>Katana ∥ Hakrawler ∥ GAU ∥ ParamSpider ∥ Kiterunner<br/>then jsluice → FFuf → Arjun]
    end

    subgraph G6["GROUP 6 Phase A — parallel (4-way fan-out)"]
        VS[Vuln Scan — Nuclei]
        GQL[GraphQL Security<br/>Introspection + graphql-cop]
        TKO[Subdomain Takeover<br/>Subjack + Nuclei + BadDNS]
        VHOST[VHost & SNI Enum<br/>L7 Host header + L4 SNI probing]
    end

    subgraph G6B["GROUP 6 Phase B — sequential"]
        MIT[MITRE Enrichment<br/>CWE + CAPEC]
    end

    subgraph Output["📤 Output"]
        JSON[(recon_domain.json)]
        Graph[(Neo4j Graph<br/>background updates)]
    end

    Domain --> G1
    G1 -->|fan-in: merge + puredns filter| G3
    G3 -->|fan-in: merge| G4
    G4 --> G5
    G5 --> G6
    G6 --> G6B
    G6B --> JSON
    JSON --> Graph
```

### Detailed Module Flow (Parallelized)

The pipeline uses **fan-out / fan-in** concurrency: modules within each group run in parallel threads, and results are merged before the next group starts. Graph DB writes happen in a single-writer background thread that never blocks the main pipeline.

```mermaid
flowchart TB
    subgraph Phase1["GROUP 1 — Fan-Out: WHOIS + Discovery + URLScan (parallel)"]
        direction TB
        Start([🌐 TARGET_DOMAIN]) --> FanOut1

        subgraph FanOut1["ThreadPoolExecutor — 3 parallel tasks"]
            direction LR
            WHOIS[WHOIS Lookup<br/>Registrar, dates, contacts]
            SubD[Subdomain Discovery]
            URLScanE[URLScan.io Enrichment<br/>Historical scans]
        end

        subgraph SubSources["5 Discovery Tools (parallel — ThreadPoolExecutor)"]
            CRT[crt.sh<br/>Certificate Transparency]
            HT[HackerTarget API<br/>DNS records]
            SF[Subfinder<br/>50+ passive sources]
            Amass[Amass<br/>50+ data sources]
            Knock[Knockpy<br/>Bruteforce]
        end

        SubD --> CRT
        SubD --> HT
        SubD --> SF
        SubD --> Amass
        SubD --> Knock

        CRT --> Merge[Fan-In: Merge & Dedupe]
        HT --> Merge
        SF --> Merge
        Amass --> Merge
        Knock --> Merge

        Merge --> Puredns[Puredns Wildcard Filter<br/>Validates against public resolvers<br/>Removes wildcards & poisoned entries]
        Puredns --> DNS[DNS Resolution<br/>20 parallel workers<br/>A, AAAA, MX, NS, TXT, CNAME]
        DNS --> Out1[(Subdomains + IPs)]
    end

    subgraph Phase2["GROUP 3 — Fan-Out: Shodan + Port Scan (parallel)"]
        direction TB
        Out1 --> FanOut3

        subgraph FanOut3["ThreadPoolExecutor — 2 parallel tasks"]
            direction LR
            ShodanE[Shodan Enrichment<br/>Host, DNS, CVEs]
            Naabu[Naabu Port Scanner<br/>SYN/CONNECT/Passive]
        end

        FanOut3 --> Out2[Fan-In: Merge Shodan + Ports]
    end

    subgraph Phase3["GROUP 4 — HTTP Probing (sequential, internally parallel)"]
        direction TB
        Out2 --> Httpx[Httpx HTTP Prober]

        subgraph HttpxFeatures["Detection Features"]
            Live[Live URL Check<br/>Status codes]
            Tech[Technology Detection<br/>Wappalyzer enhanced]
            TLS[TLS/SSL Analysis<br/>Certs, ciphers]
            Headers[Header Analysis<br/>Security headers]
        end

        Httpx --> Live
        Httpx --> Tech
        Httpx --> TLS
        Httpx --> Headers

        Live --> Out3[(Live URLs + Tech Stack)]
        Tech --> Out3
        TLS --> Out3
        Headers --> Out3
    end

    subgraph Phase4["GROUP 5 — Resource Enumeration (internally parallel)"]
        direction TB
        Out3 --> ResEnum[Resource Enumeration]

        subgraph EnumTools["3 Tools in Parallel"]
            Katana[Katana<br/>Active Crawling<br/>Current endpoints]
            GAU[GAU<br/>Passive Archives<br/>Historical URLs]
            KR[Kiterunner<br/>API Bruteforce<br/>Hidden endpoints]
        end

        ResEnum --> Katana
        ResEnum --> GAU
        ResEnum --> KR

        Katana --> MergeURL[Merge & Classify]
        GAU --> MergeURL
        KR --> MergeURL

        MergeURL --> Out4[(Endpoints + Parameters)]
    end

    subgraph Phase4b["GROUP 5b — JS Recon (if enabled)"]
        direction TB
        Out4 --> JsRecon[JS Recon Scanner]

        subgraph JsModules["5 Analyzers in Parallel"]
            Patterns[Secret Detection<br/>100 regex patterns]
            SrcMap[Source Map<br/>Discovery & Analysis]
            DepConf[Dependency<br/>Confusion Check]
            EpExtract[Endpoint<br/>Extraction]
            FwSink[Framework +<br/>DOM Sink Detection]
        end

        JsRecon --> Patterns
        JsRecon --> SrcMap
        JsRecon --> DepConf
        JsRecon --> EpExtract
        JsRecon --> FwSink

        Patterns --> KeyVal[Key Validation<br/>21 service validators]
        KeyVal --> Out4b[(JS Findings + Secrets + Endpoints)]
        SrcMap --> Out4b
        DepConf --> Out4b
        EpExtract --> Out4b
        FwSink --> Out4b
    end

    subgraph Phase5["GROUP 6 Phase A — Fan-Out: Nuclei ∥ GraphQL ∥ Takeover ∥ VHost/SNI (parallel)"]
        direction TB
        Out4b --> FanOut6

        subgraph FanOut6["ThreadPoolExecutor — 4 parallel tasks (_isolated wrappers, deep-copy snapshots)"]
            direction LR
            Nuclei[Nuclei Scanner]
            GraphQL[GraphQL Security Scanner]
            Takeover[Subdomain Takeover Scanner]
            VhostSni[VHost & SNI Enum]
        end

        subgraph NucleiFeatures["Nuclei Scan Types"]
            CVE[CVE Detection<br/>Known vulnerabilities]
            DAST[DAST Fuzzing<br/>XSS, SQLi, SSTI]
            Misconfig[Misconfiguration<br/>Exposed panels, defaults]
            Info[Info Disclosure<br/>Backup files, .git]
        end

        subgraph GraphQLFeatures["GraphQL Tests"]
            Discover[Endpoint Discovery<br/>pattern + evidence probing]
            Intros[Introspection Test<br/>schema + sensitive fields]
            Cop[graphql-cop<br/>12 misconfig checks]
        end

        subgraph TakeoverFeatures["Takeover Tools"]
            Subjack[Subjack<br/>DNS-first fingerprints]
            NucTkO[Nuclei takeover templates<br/>http/takeovers + dns]
            BadDNS[BadDNS sidecar<br/>CNAME/NS/MX/TXT/SPF/wildcard]
        end

        subgraph VhostSniFeatures["VHost & SNI Probing"]
            L7[L7 probe<br/>Host header override]
            L4[L4 probe<br/>TLS SNI via --resolve]
            Anomaly[Anomaly oracle<br/>vs baseline status/size]
        end

        Nuclei --> CVE
        Nuclei --> DAST
        Nuclei --> Misconfig
        Nuclei --> Info

        GraphQL --> Discover
        GraphQL --> Intros
        GraphQL --> Cop

        Takeover --> Subjack
        Takeover --> NucTkO
        Takeover --> BadDNS

        VhostSni --> L7
        VhostSni --> L4
        VhostSni --> Anomaly

        CVE --> FanIn6
        DAST --> FanIn6
        Misconfig --> FanIn6
        Info --> FanIn6
        Discover --> FanIn6
        Intros --> FanIn6
        Cop --> FanIn6
        Subjack --> FanIn6
        NucTkO --> FanIn6
        BadDNS --> FanIn6
        L7 --> FanIn6
        L4 --> FanIn6
        Anomaly --> FanIn6
    end

    subgraph Phase5b["GROUP 6 Phase B — MITRE Enrichment (sequential, depends on Nuclei CVEs)"]
        FanIn6[Fan-In: Merge Nuclei + GraphQL + Takeover + VHost/SNI findings] --> MITRE[MITRE Enrichment<br/>CWE + CAPEC]
        MITRE --> Out5[(Vulnerabilities + Attack Patterns)]
    end

    subgraph Phase6["Phase 6: GitHub Hunting"]
        direction TB
        Out5 --> GitHub[GitHub Secret Hunter]

        subgraph Secrets["Secret Types"]
            API[API Keys<br/>AWS, GCP, Stripe]
            Creds[Credentials<br/>Passwords, tokens]
            Keys[Private Keys<br/>SSH, SSL]
            DB[Database Strings<br/>Connection strings]
        end

        GitHub --> API
        GitHub --> Creds
        GitHub --> Keys
        GitHub --> DB

        API --> Out6[(Exposed Secrets)]
        Creds --> Out6
        Keys --> Out6
        DB --> Out6
    end

    subgraph FinalOutput["📤 Final Output"]
        Out6 --> FinalJSON[(recon_domain.json)]
        FinalJSON --> Neo4j[(Neo4j Graph DB<br/>background thread writes)]
    end
```

### Data Enrichment Flow

```mermaid
flowchart LR
    subgraph Discovery["Discovery Phase"]
        Sub[Subdomains] --> IP[IP Addresses]
        IP --> Port[Open Ports]
        Port --> Service[Services]
    end

    subgraph Analysis["Analysis Phase"]
        Service --> URL[Live URLs]
        URL --> Tech[Technologies]
        Tech --> Endpoint[Endpoints]
    end

    subgraph Assessment["Assessment Phase"]
        Endpoint --> Vuln[Vulnerabilities]
        Vuln --> CVE[CVE IDs]
        CVE --> CWE[CWE Weaknesses]
        CWE --> CAPEC[CAPEC Attacks]
    end

    subgraph Graph["Graph Storage"]
        CAPEC --> Neo4j[(Neo4j)]
    end
```

---

## ⚡ Parallelization Architecture

The recon pipeline uses a **fan-out / fan-in** pattern with Python's `concurrent.futures.ThreadPoolExecutor` to run independent modules concurrently, significantly reducing total scan time while respecting data dependencies.

### Execution Groups

| Group | Modules | Parallelism | Dependencies |
|-------|---------|-------------|--------------|
| **GROUP 1** | WHOIS + Subdomain Discovery + URLScan | 3 parallel tasks | Only needs `root_domain` |
| *Discovery* | crt.sh + HackerTarget + Subfinder + Amass + Knockpy | 5 parallel tools | Part of GROUP 1 |
| *Puredns* | Wildcard filtering (validates against public resolvers) | Sequential | After discovery fan-in, before DNS |
| *DNS* | DNS resolution for all subdomains | 20 parallel workers | After puredns filtering |
| **GROUP 2b** | Uncover Target Expansion (13 search engines) | Sequential | Needs domain from GROUP 1; runs before GROUP 3 |
| **GROUP 3** | Shodan Enrichment + Port Scan (Naabu) | 2 parallel tasks | Needs IPs from GROUP 1 + GROUP 2b |
| **GROUP 3b** | OSINT Enrichment (Censys + FOFA + OTX + Netlas + VirusTotal + ZoomEye + CriminalIP) | 7 parallel tasks | Needs IPs/domains from GROUP 1; runs concurrently with GROUP 3 |
| **GROUP 4** | HTTP Probe (httpx) | Sequential (internally parallel) | Needs ports from GROUP 3 |
| **GROUP 5** | Resource Enum (Katana + GAU + Kiterunner) | 3 tools internally parallel | Needs live URLs from GROUP 4 |
| **GROUP 5b** | JS Recon Scanner (100 regex patterns, key validation, source maps, dependency confusion, endpoint extraction, DOM sinks) | 5 analyzers parallel per file | Needs JS files from GROUP 5; runs if `JS_RECON_ENABLED` |
| **GROUP 5.5** | Supply-Chain Recon (black-box package harvest + offline OSV verdict, retire.js over served JS, optional GuardDog; then incident enrichment, malicious-host correlation and typosquat detection) | Sequential; dispatches the DIRTY analyzer | Needs JS files from GROUP 5b; runs if `SUPPLY_CHAIN_RECON_ENABLED` |
| **GROUP 6 Phase A** | Vuln Scan (Nuclei) ∥ GraphQL Security Testing ∥ Subdomain Takeover ∥ VHost & SNI Enumeration | 4 parallel tasks (ThreadPoolExecutor, `_isolated` wrappers) | Needs endpoints from GROUP 5/5b |
| **GROUP 6 Phase B** | MITRE Enrichment (CWE + CAPEC) | Sequential | Needs CVEs from Phase A (Nuclei) |

### Background Graph DB Updates

All Neo4j graph updates run in a **dedicated single-writer background thread** (`ThreadPoolExecutor(max_workers=1)`). The main pipeline submits deep-copy snapshots of recon data and continues immediately. A final `_graph_wait_all()` ensures all updates complete before the pipeline exits.

### Structured Logging

All log messages use a consistent `[level][Module]` prefix format (e.g., `[+][crt.sh] Found 42 subdomains`) for clarity when multiple tools produce interleaved output from concurrent threads.

### Thread Safety

Each parallelized tool function is thread-safe:
- Discovery tools (`query_crtsh`, `query_hackertarget`, etc.) create their own `requests.Session` instances
- Module `_isolated` variants (e.g., `run_port_scan_isolated`, `run_shodan_enrichment_isolated`) accept a read-only snapshot of `combined_result` and return only their data section
- The main thread handles all merging — no shared mutable state between workers

---

## 🎯 Targeting Modes

A project picks one of three targeting modes at creation. The mode is locked
afterwards, and all three run the **same** pipeline.

| Mode | Target | What differs |
| --- | --- | --- |
| **Single Domain** | one root domain plus optional subdomain prefixes | the default; full OSINT and subdomain discovery are available |
| **IP / CIDR** | a list of addresses or ranges | skips domain ownership, subdomain enumeration and domain WHOIS; runs reverse DNS and IP WHOIS instead |
| **Domain batch** | a list of hostnames spanning several domains | groups them by domain and scans each group in turn, in one run |

### Domain batch

Paste or upload a flat hostname list. RedAmon groups it and scans the groups one
after another.

**The grouping rule is the last two labels.** `suba.sub3.domain3.com` belongs to
`domain3.com`, with the prefix `suba.sub3`. This is deliberately not a public
suffix list: it is exactly what an operator does by hand when filling the
single-domain form (target = the domain, everything else = subdomain prefixes),
so a batch and a hand-built project scan identically. The consequence worth
knowing is that `foo.example.co.uk` groups under `co.uk`. The project form shows
the computed groups before you save, so the grouping is never a surprise.

```
sub1.domain1.com          Group 1  domain1.com      sub1
sub2.domain2.it      ->   Group 2  domain2.it       sub2
sub3.domain3.com          Group 3  domain3.com      sub3, suba.sub3
suba.sub3.domain3.com
```

**A batch is ONE scan, not many.** It takes a single slot in the scan queue, one
memory reservation, one container and one run id. It is not a new scan kind:
it is what a full recon does when the project is in batch mode, so the queue,
the scheduler, the stop button, run history and the traffic view all treat it
exactly like any other full recon.

**The graph fills progressively.** Previous recon data is cleared **once**, before
the first group. Each group then completes its whole pipeline and writes its
results before the next one starts, so all groups accumulate into a single graph
and the run produces **one** new version covering every domain. Re-running works
the same way it does in the other two modes.

**Only the hostnames you list are scanned.** Subdomain discovery is forced off for
a batch, including for a group that is just a bare root domain.

**A failing group does not stop the batch.** One unresolvable domain should not
cost you the other nineteen: failures are reported at the end, and the run only
fails outright if every group failed.

**Output.** Each group writes `recon_<project_id>__<domain>.json`, and the
canonical `recon_<project_id>.json` is rebuilt as the union of them after every
group. Everything downstream (GVM, the project export, the report) reads the
canonical file and sees the whole batch, and a batch stopped part way still
leaves a file that parses.

**Limits.** 500 hostnames and 50 domain groups per project. A batch holds the
project's single scan slot for as long as it runs, so a very long list is a very
long scan.

Implementation: `_batch_groups()` / `run_domain_batch()` / `run_domain_group()` in
`recon/main.py`, grouping in `webapp/src/lib/domainBatch.ts`, output handling in
`recon/helpers/output_paths.py`.

---

## 🎯 Partial Recon

Partial Recon lets you run any single tool from the pipeline independently, without triggering a full scan. From the Workflow View or section headers, click the play button on any tool to open a modal that shows existing graph data (subdomains, IPs, ports, BaseURLs, endpoints), accepts custom targets, and launches the tool in isolation. Results are merged into the existing Neo4j graph via `MERGE` -- no duplicates. All 23 pipeline tools are supported (including `graphql_scan` -- custom URLs are validated against project scope and injected via `GRAPHQL_ENDPOINTS` -- and `vhost_sni` -- custom subdomains and IPs are validated and injected before probing). The tool runs with the project's saved settings (timeouts, wordlists, API keys). Custom inputs are validated in real time (scope checks, IP/CIDR format, port ranges). See `recon/partial_recon.py` for the implementation.

> **[Wiki: Recon Pipeline Workflow -- Partial Recon](https://github.com/samugit83/redamon/wiki/Recon-Pipeline-Workflow#partial-recon)**

---

## 📋 Scan Modules Explained

### Configure Which Modules to Run

Configure via the webapp project settings or environment variables:

```bash
# Run all modules (recommended for full assessment)
SCAN_MODULES="domain_discovery,port_scan,http_probe,resource_enum,vuln_scan"

# Quick recon only (no vulnerability scanning)
SCAN_MODULES="domain_discovery"

# Port scan + HTTP probing (skip vulnerability scanning)
SCAN_MODULES="domain_discovery,port_scan,http_probe"
```

### Module 1: `domain_discovery`

All 5 subdomain discovery tools run **concurrently** via `ThreadPoolExecutor(max_workers=5)`. Each tool is a thread-safe function with its own HTTP session. After merging, **Puredns** validates the combined list against public DNS resolvers to remove wildcard and DNS-poisoned entries. DNS resolution is then parallelized with **20 concurrent workers**. WHOIS and URLScan run in a separate parallel group alongside discovery.

```mermaid
flowchart LR
    subgraph Input
        Domain[example.com]
    end

    subgraph Discovery["Domain Discovery (5 tools in parallel)"]
        CRT[crt.sh<br/>CT logs]
        HT[HackerTarget<br/>DNS search]
        SF[Subfinder<br/>50+ sources]
        Amass[Amass<br/>50+ data sources]
        Knock[Knockpy<br/>Bruteforce]
    end

    subgraph Merge["Fan-In"]
        MergeDedupe[Merge & Dedupe]
    end

    subgraph DNSPhase["DNS Resolution (20 parallel workers)"]
        DNS[DNS Resolver<br/>A, AAAA, MX, NS, TXT, CNAME]
    end

    subgraph Output
        Subs[Subdomains]
        IPs[IP Addresses]
        Records[DNS Records]
    end

    Domain --> CRT
    Domain --> HT
    Domain --> SF
    Domain --> Amass
    Domain --> Knock

    CRT --> MergeDedupe
    HT --> MergeDedupe
    SF --> MergeDedupe
    Amass --> MergeDedupe
    Knock --> MergeDedupe

    MergeDedupe --> PD[Puredns<br/>Wildcard Filter]
    PD --> DNS

    DNS --> Subs
    DNS --> IPs
    DNS --> Records
```

| What It Does | Output |
|--------------|--------|
| **WHOIS lookup** | Registrar, creation date, owner info |
| **Subdomain discovery** | Finds subdomains via 5 parallel sources (crt.sh, HackerTarget, Subfinder, Amass, Knockpy) |
| **Wildcard filtering** | Puredns validates subdomains against public DNS resolvers, removes wildcards and DNS-poisoned entries |
| **DNS enumeration** | A, AAAA, MX, NS, TXT, CNAME records (20 parallel workers) |
| **IP resolution** | Maps all discovered hostnames to IPs |

📖 **Key Parameters:**
```python
TARGET_DOMAIN = "example.com"           # Root domain
SUBDOMAIN_LIST = []                     # Empty = discover ALL
USE_BRUTEFORCE_FOR_SUBDOMAINS = False   # Brute force mode
```

---

### Module 2: `port_scan`

```mermaid
flowchart LR
    subgraph Input
        IPs[IP Addresses]
    end

    subgraph Scanner["Naabu Scanner"]
        SYN[SYN Scan]
        Service[Service Detection]
        CDN[CDN Detection]
    end

    subgraph Output
        Ports[Open Ports]
        Services[Service Names]
        CDNInfo[CDN/WAF Info]
    end

    IPs --> SYN
    SYN --> Service
    Service --> CDN
    CDN --> Ports
    CDN --> Services
    CDN --> CDNInfo
```

| What It Finds | Examples |
|---------------|----------|
| **Open ports** | 22/SSH, 80/HTTP, 443/HTTPS, 3306/MySQL |
| **CDN detection** | Cloudflare, Akamai, Fastly |
| **Service hints** | Common service identification |

📖 **Key Parameters:**
```python
NAABU_TOP_PORTS = "1000"        # Number of top ports
NAABU_RATE_LIMIT = 1000         # Packets per second
NAABU_SCAN_TYPE = "s"           # SYN scan
```

📖 **Detailed documentation:** [docs/readmes/README.PORT_SCAN.md](README.PORT_SCAN.md)

---

### Module 3: `http_probe`

```mermaid
flowchart LR
    subgraph Input
        URLs[Target URLs<br/>from port scan]
    end

    subgraph Httpx["Httpx Prober"]
        Probe[HTTP/S Requests]
        Tech[Technology Detection]
        TLS[TLS Analysis]
        Headers[Header Extraction]
    end

    subgraph Wappalyzer["Wappalyzer Enhancement"]
        CMS[CMS Detection]
        Plugins[Plugin Detection]
        Analytics[Analytics Tools]
    end

    subgraph Output
        Live[Live URLs]
        Stack[Tech Stack]
        Certs[Certificates]
        SecHeaders[Security Headers]
    end

    URLs --> Probe
    Probe --> Tech
    Probe --> TLS
    Probe --> Headers

    Tech --> Wappalyzer
    Wappalyzer --> CMS
    Wappalyzer --> Plugins
    Wappalyzer --> Analytics

    CMS --> Live
    Plugins --> Stack
    Analytics --> Stack
    TLS --> Certs
    Headers --> SecHeaders
```

| What It Finds | Examples |
|---------------|----------|
| **Live URLs** | Which endpoints are responding |
| **Technologies** | WordPress, nginx, PHP, React |
| **CMS Plugins** | Yoast SEO, WooCommerce (via Wappalyzer) |
| **TLS certificates** | Issuer, expiry, SANs |

📖 **Detailed documentation:** [docs/readmes/README.HTTP_PROBE.md](README.HTTP_PROBE.md)

---

### Module 4: `resource_enum`

```mermaid
flowchart TB
    subgraph Input
        URLs[Live URLs]
    end

    subgraph Parallel["Parallel Execution"]
        subgraph Active["Active Discovery"]
            Katana[🕸️ Katana<br/>Web Crawler<br/>Current endpoints]
            Hakrawler[🔗 Hakrawler<br/>DOM-aware Crawler<br/>Links & Forms]
        end

        subgraph Passive["Passive Discovery"]
            GAU[📚 GAU<br/>Archive Search<br/>Historical URLs]
        end

        subgraph Bruteforce["API Discovery"]
            KR[🔑 Kiterunner<br/>Swagger Specs<br/>Hidden APIs]
        end
    end

    subgraph JSAnalysis["Sequential JS Analysis"]
        jsluice[🔍 jsluice<br/>JS URL & Secret Extraction]
    end

    subgraph Merge["Merge & Classify"]
        Dedup[Deduplicate]
        Classify[Classify Endpoints<br/>API, Admin, Form, Static]
        Parse[Parse Parameters]
    end

    subgraph Output
        Endpoints[All Endpoints]
        Forms[Forms + Inputs]
        APIs[API Routes]
        Secrets[Secrets & API Keys]
    end

    URLs --> Katana
    URLs --> Hakrawler
    URLs --> GAU
    URLs --> KR

    Katana --> jsluice
    Hakrawler --> jsluice
    Katana --> Dedup
    Hakrawler --> Dedup
    GAU --> Dedup
    KR --> Dedup
    jsluice --> Dedup

    Dedup --> Classify
    Classify --> Parse

    Parse --> Endpoints
    Parse --> Forms
    Parse --> APIs
    Parse --> Secrets
```

| Tool | Method | What It Finds |
|------|--------|---------------|
| **Katana** | Active crawling | Current live endpoints |
| **Hakrawler** | Active crawling | Links, forms, DOM-discovered URLs |
| **GAU** | Passive archives | Historical/deleted pages |
| **Kiterunner** | API bruteforce | Hidden API routes |
| **jsluice** | JS analysis (active download) | URLs, endpoints, and secrets from JS files |

📖 **Detailed documentation:** [docs/readmes/README.RESOURCE_ENUM.md](README.RESOURCE_ENUM.md)

---

### Module 4.5: `ai_surface_recon`

The **detection / fingerprinting half** of the adversarial-AI pipeline. Runs as
**Phase 4.5** (after `resource_enum`, before `vuln_scan`), gated on
`AI_SURFACE_RECON_ENABLED` (not on `SCAN_MODULES`). It sends **benign,
protocol-aware shape-probes** to confirm and characterize AI/LLM infrastructure
that generic web recon can't see — and writes the results onto the graph as
`ai_*` property annotations plus MCP tool-poisoning `Vulnerability` nodes. It
never jailbreaks, injects, or fuzzes, and never presents credentials.

Seven workloads run per host (hosts in parallel, workloads sequential within a host):

| # | Workload | Confirms / extracts |
|---|----------|---------------------|
| 1 | Chat-shape probe | LLM chat endpoint, dialect, streaming, p50 latency |
| 2 | MCP handshake + `tools/list` + YARA | MCP server, tools, capabilities, tool-poisoning findings |
| 3 | OpenAPI / manifest / model listing | tool/vision/streaming support, model ids + family, cached spec |
| 4 | Julius probe pack (YAML) | confirmed AI `Technology` (vLLM, Ollama, …) |
| 5 | Vector-DB confirmation reads | qdrant / chroma / weaviate / milvus, unauthenticated read exposure |
| 6 / 7 | latency baseline + summary glue | counters, merged model family |

**Input:** `resource_enum.by_base_url` (classified endpoints), `http_probe.by_url`
(AI flags), `port_scan.by_host` (AI + vector-DB ports).
**Output:** `combined_result["ai_surface_recon"]` → graph via
`update_graph_from_ai_surface_recon` (enriches `Endpoint` / `Parameter` /
`Technology`, adds `Vulnerability` nodes). Heavy deps (`mcp`, `yara`, `prance`,
`jq`, `PyYAML`) are lazy-imported, so a missing dep degrades one workload, not the job.

📖 **Detailed documentation:** [docs/readmes/AI_SURFACE_RECON_MODULE.md](AI_SURFACE_RECON_MODULE.md)

---

### Module 5: `vuln_scan`

```mermaid
flowchart TB
    subgraph Input
        Endpoints[All Endpoints]
        Tech[Technology Stack]
    end

    subgraph Nuclei["Nuclei Scanner"]
        Templates[9000+ Templates]

        subgraph ScanTypes["Scan Types"]
            CVEScan[CVE Detection<br/>Known vulns]
            DAST[DAST Fuzzing<br/>XSS, SQLi, SSTI]
            Misconfig[Misconfiguration<br/>Exposed panels]
            InfoLeak[Info Disclosure<br/>.git, backups]
        end
    end

    subgraph CVELookup["CVE Lookup"]
        NVD[Query NVD<br/>by technology version]
        Match[Match CVEs<br/>nginx:1.19 → CVE-2021-23017]
    end

    subgraph MITRE["MITRE Enrichment"]
        CWE[CWE Weaknesses<br/>Weakness hierarchy]
        CAPEC[CAPEC Patterns<br/>Attack techniques]
    end

    subgraph Output
        Vulns[Vulnerabilities]
        CVEs[CVE Details]
        Attacks[Attack Patterns]
    end

    Endpoints --> Templates
    Tech --> CVELookup

    Templates --> CVEScan
    Templates --> DAST
    Templates --> Misconfig
    Templates --> InfoLeak

    CVEScan --> MITRE
    DAST --> MITRE
    CVELookup --> NVD
    NVD --> Match
    Match --> MITRE

    MITRE --> CWE
    CWE --> CAPEC

    Misconfig --> Vulns
    InfoLeak --> Vulns
    CAPEC --> CVEs
    CAPEC --> Attacks
```

| What It Finds | Examples |
|---------------|----------|
| **Web CVEs** | Log4Shell, Spring4Shell |
| **Injection flaws** | SQL injection, XSS |
| **Misconfigurations** | Exposed admin panels |
| **CWE Weaknesses** | Weakness hierarchy |
| **CAPEC Attacks** | Attack techniques |

📖 **Detailed documentation:** [docs/readmes/README.VULN_SCAN.md](README.VULN_SCAN.md) | [docs/readmes/README.MITRE.md](README.MITRE.md)

---

### Module 5b: `graphql_scan`

Dedicated GraphQL security scanner -- runs as **GROUP 6 Phase A in parallel with Nuclei, Subdomain Takeover, and VHost & SNI Enumeration** because all four scanners consume `BaseURL` / `Endpoint` / `Technology` / `Subdomain` / `IP` and emit `Vulnerability` nodes but have zero data dependency on each other. Each phase-A tool is wrapped in an `_isolated` variant that deep-copies `combined_result` so the four threads never race on the shared dict.

Toggle: `GRAPHQL_SECURITY_ENABLED` (default: `false`, opt-in).

```mermaid
flowchart TB
    subgraph Input
        BaseURLs[BaseURLs]
        Endpoints[Endpoints]
        JSFindings[JS Recon findings<br/>graphql/graphql_introspection]
        UserURLs[User-specified URLs<br/>GRAPHQL_ENDPOINTS]
    end

    subgraph Discovery["Endpoint Discovery"]
        HTTPProbe[HTTP probe matches<br/>Content-Type: application/graphql]
        ResourceEnum[Resource enum paths<br/>/graphql, /gql, /query POST]
        Pattern[Pattern probing<br/>/graphql, /api/graphql,<br/>/v1/graphql, /v2/graphql]
        Secondary[Secondary patterns<br/>/query, /graphiql, /playground<br/>only on bases with evidence]
    end

    subgraph Filter["RoE Filter"]
        ROE[ROE_EXCLUDED_HOSTS<br/>*.example.com wildcards]
    end

    subgraph NativeTest["Native Introspection Test"]
        Probe[POST __typename<br/>reachability check]
        Simple[Simple introspection<br/>queryType/mutationType]
        Deep[Full introspection<br/>TypeRef depth 1-20]
        Sens[Sensitive field detection<br/>password, token, ssn, cvv...]
    end

    subgraph CopTest["graphql-cop Docker<br/>dolevf/graphql-cop:1.14"]
        Cop1[field_suggestions]
        Cop2[detect_graphiql]
        Cop3[get_method_support]
        Cop4[trace_mode]
        Cop5[alias_overloading DoS]
        Cop6[batch_query DoS]
        Cop7[directive_overloading DoS]
        Cop8[circular_introspection DoS]
        Cop9[get_based_mutation]
        Cop10[post_based_csrf]
        Cop11[unhandled_error_detection]
    end

    subgraph Output
        Vulns[Vulnerability nodes]
        Flags[Endpoint capability flags<br/>graphql_graphiql_exposed,<br/>graphql_tracing_enabled,<br/>graphql_get_allowed, etc.]
        Schema[Schema hash + operation counts<br/>queries/mutations/subscriptions]
    end

    BaseURLs --> Discovery
    Endpoints --> Discovery
    JSFindings --> Discovery
    UserURLs --> Discovery

    Discovery --> HTTPProbe
    Discovery --> ResourceEnum
    Discovery --> Pattern
    Discovery --> Secondary

    HTTPProbe --> Filter
    ResourceEnum --> Filter
    Pattern --> Filter
    Secondary --> Filter

    Filter --> ROE
    ROE --> NativeTest
    ROE --> CopTest

    NativeTest --> Probe
    Probe --> Simple
    Simple --> Deep
    Deep --> Sens

    NativeTest --> Vulns
    NativeTest --> Schema
    CopTest --> Vulns
    CopTest --> Flags
```

**Capabilities:**

| Layer | What It Does |
|-------|--------------|
| **Endpoint discovery** | Merges user-specified URLs, HTTP probe matches (`Content-Type: application/graphql`), resource-enum endpoints (paths containing `graphql`/`gql`/`query` via POST, or with `query`/`mutation`/`variables`/`operationName` parameters), JS Recon findings (`graphql` / `graphql_introspection` types), and pattern probes (primary `/graphql`, `/api/graphql`, `/v1/graphql`, `/v2/graphql`; secondary `/query`, `/gql`, `/graphiql`, `/playground` only on bases with prior evidence). |
| **RoE filtering** | Drops endpoints matching `ROE_EXCLUDED_HOSTS` (wildcards supported). Skipped count exposed in `summary.endpoints_skipped`. |
| **Native introspection test** | 3-step probe per endpoint: `POST { __typename }` reachability, simple introspection, full introspection at configurable TypeRef depth (1-20, default 10). Extracts schema hash (16-char SHA256), query/mutation/subscription counts, and sensitive-field list (`password`, `secret`, `token`, `key`, `api`, `private`, `credential`, `auth`, `ssn`, `credit`, `card`, `payment`, `bank`, `account`, `pin`, `cvv`, `salary`, `medical`). Response larger than 10 MB falls back to simple result. |
| **graphql-cop (opt-in)** | Docker-in-Docker wrapper around `dolevf/graphql-cop:1.14`. Runs 12 checks per endpoint: field suggestions, GraphiQL/Playground detection, trace mode, GET-method queries/mutations, POST url-encoded CSRF, alias overloading (DoS), batch query (DoS), directive overloading (DoS), circular introspection (DoS), unhandled errors. Per-test toggles are applied post-execution because the `1.14` image does not honor the `-e` flag. |
| **Authentication** | 5 modes: `bearer`, `cookie`, `header` (custom name), `basic` (base64), `apikey`. Values masked in logs. Same headers propagate to graphql-cop via `-H '{"K":"V"}'` JSON args. |
| **Rate limiting + retries** | Global RPS cap (`GRAPHQL_RATE_LIMIT`, 0-100), retry on `429`/`5xx` with exponential backoff (`GRAPHQL_RETRY_COUNT`, `GRAPHQL_RETRY_BACKOFF`), concurrency clamp (1-20). Sequential mode at `concurrency=1`. |
| **Endpoint enrichment** | Updates existing `Endpoint` nodes with capability flags (`graphql_graphiql_exposed`, `graphql_tracing_enabled`, `graphql_get_allowed`, `graphql_field_suggestions_enabled`, `graphql_batching_enabled`, `graphql_cop_ran`) — recorded even on negative results so the graph captures server state explicitly. |

**Stealth overrides:** `GRAPHQL_RATE_LIMIT=2`, `GRAPHQL_CONCURRENCY=1`, `GRAPHQL_TIMEOUT=60`, and the four DoS-class graphql-cop tests (alias / batch / directive / circular) forced off.

**Schema contract:** `KNOWN_VULN_KEYS` + `KNOWN_ENDPOINT_INFO_KEYS` in [graph_db/mixins/graphql_mixin.py](../../graph_db/mixins/graphql_mixin.py) pin every field the scanner may emit. Adding a new key without updating the mixin triggers a warning at graph-ingest time — no silent drops.

**Source layout:**

```
recon/graphql_scan/
├── __init__.py           # Package entry point
├── scanner.py            # Orchestration (run_graphql_scan, run_graphql_scan_isolated, test_single_endpoint)
├── discovery.py          # Endpoint discovery from 5 sources + RoE filtering
├── introspection.py      # Configurable-depth introspection query + schema operations
├── misconfig.py          # graphql-cop Docker-in-Docker wrapper (12 tests)
├── normalizers.py        # Finding normalization + severity aggregation
└── auth.py               # 5 auth modes (bearer/cookie/header/basic/apikey) with masked logs
```

📖 **Detailed documentation:** [docs/readmes/GRAPH.SCHEMA.md — GraphQL-specific Endpoint & Vulnerability properties](GRAPH.SCHEMA.md) | **[Wiki: GraphQL Security Testing](https://github.com/samugit83/redamon/wiki/GraphQL-Security-Testing)**

---

### Module 5d: `vhost_sni_enum`

Hidden-virtual-host discovery scanner -- runs as the **fourth GROUP 6 Phase A sibling** alongside Nuclei, GraphQL Scan, and Subdomain Takeover. Probes every target IP twice per candidate hostname: an **L7** test that overrides the HTTP `Host` header and an **L4** test that pins TLS SNI via curl `--resolve`. Each probe is compared against a per-port baseline raw-IP request; a status-code change OR a body-size delta beyond `VHOST_SNI_BASELINE_SIZE_TOLERANCE` (default 50 bytes) flags an anomaly. L4 catches modern reverse proxies (NGINX ingress, Traefik, Cloudflare, k8s) that route at the TLS handshake before reading any HTTP header; L7 catches classic Apache / Nginx vhost routing.

Toggle: `VHOST_SNI_ENABLED` (default: `false`, opt-in). Zero new binaries -- relies on `curl` already in the recon image.

```mermaid
flowchart TB
    subgraph Input
        IPs[IPs from port_scan + DNS]
        DefaultWL[Default wordlist<br/>2,471 entries]
        CustomWL[Custom wordlist setting]
        GraphCands[Graph-derived candidates<br/>DNS subdomains, httpx hosts,<br/>TLS SANs, CNAME, PTR, co-resident]
    end

    subgraph CandidateSet["Candidate Set Build"]
        Merge[Merge + dedupe + hostname validation<br/>regex with \Z to block newline injection]
        Cap[Deterministic sort + slice<br/>VHOST_SNI_MAX_CANDIDATES_PER_IP]
    end

    subgraph Baseline["Per-Port Baseline"]
        BaseReq[curl raw-IP request<br/>no Host override, no SNI swap]
    end

    subgraph Probing["Per-Candidate Probing (ThreadPoolExecutor)"]
        L7Probe[L7 probe<br/>-H 'Host: candidate']
        L4Probe[L4 probe<br/>--resolve candidate:port:ip<br/>https only]
    end

    subgraph Anomaly["Anomaly Oracle"]
        StatusDiff[Status code differs?]
        SizeDiff[Body size differs<br/>beyond tolerance?]
    end

    subgraph Severity["Severity Ladder"]
        High[high: L7 vs L4 disagree<br/>routing inconsistency / proxy bypass]
        Med[medium: matches INTERNAL_KEYWORDS<br/>~80 entries: admin, jenkins, vault, ...]
        Low[low: confirmed hidden vhost<br/>different status]
        Info[info: size-delta only]
    end

    subgraph Output
        Vulns[Vulnerability nodes<br/>hidden_vhost / hidden_sni_route / host_header_bypass]
        SubEnrich[Subdomain enrichment<br/>vhost_tested, vhost_hidden, sni_routed, ...]
        IPEnrich[IP enrichment<br/>is_reverse_proxy, hidden_vhost_count, ...]
        Feedback[Discovery feedback loop<br/>inject discovered vhost into http_probe.by_url]
    end

    DefaultWL --> Merge
    CustomWL --> Merge
    GraphCands --> Merge
    Merge --> Cap

    IPs --> BaseReq
    Cap --> L7Probe
    Cap --> L4Probe
    BaseReq --> StatusDiff
    BaseReq --> SizeDiff
    L7Probe --> StatusDiff
    L7Probe --> SizeDiff
    L4Probe --> StatusDiff
    L4Probe --> SizeDiff

    StatusDiff --> High
    StatusDiff --> Med
    StatusDiff --> Low
    SizeDiff --> Info

    High --> Vulns
    Med --> Vulns
    Low --> Vulns
    Info --> Vulns

    Vulns --> SubEnrich
    Vulns --> IPEnrich
    Vulns --> Feedback
```

**Capabilities:**

| Layer | What It Does |
|-------|--------------|
| **IP target collection** | Merges (no fallback) every available IP source: `port_scan.by_host` (authoritative ports + per-port scheme overrides), then `dns.subdomains[*].ips.ipv4` and `dns.domain.ips.ipv4` get default 80/443 added. Per-IP port list deduped on `(port, scheme)`. |
| **Candidate set build** | Six sources merged: default wordlist (2,471 entries shipped in-image), custom wordlist setting, DNS subdomains resolving to the IP, httpx-known hosts on the IP, TLS SAN list per-URL, and CNAME/PTR/co-resident external domains. UTF-8 BOM auto-handled for Windows-edited overrides. Hostname validation uses `\Z` to block newline-injected hostnames from corrupting `--resolve` syntax. |
| **Per-port baseline** | One raw-IP curl request per port. Status `0` (curl couldn't connect) is dropped as no-data instead of being recorded as a real probe. |
| **L7 probing** | `-H "Host: <candidate>"` against `https://<ip>:<port>/`. Catches classic Apache / Nginx vhost routing. |
| **L4 probing** | `--resolve <candidate>:<port>:<ip>` so the TLS handshake carries the candidate as SNI. Catches modern reverse proxies (NGINX ingress, Traefik, Cloudflare, k8s) that route at the TLS layer. Skipped when scheme is `http` (no SNI to set). |
| **Anomaly detection** | Per-(candidate, layer) probe compared to baseline. Anomaly if status differs OR body size deviates beyond `VHOST_SNI_BASELINE_SIZE_TOLERANCE` (default 50 bytes). |
| **Severity ladder** | `high` when L7 and L4 disagree on the same hostname (proxy bypass primitive); `medium` when discovered vhost matches `INTERNAL_KEYWORDS` (~80 entries: `admin`, `jenkins`, `vault`, `keycloak`, `argocd`, `kibana`, `grafana`, ...); `low` for any anomaly with a different status code; `info` for size-delta-only anomalies. Compound names like `admin-portal` matched via longest-keyword-wins with lexicographic tie-break. |
| **Discovery feedback loop** | When `VHOST_SNI_INJECT_DISCOVERED=true` (default), discovered hidden vhosts are folded into `combined_result["http_probe"]["by_url"]` as fresh BaseURLs with `discovery_source="vhost_sni_enum"`, so downstream graph methods and follow-up partial-recon runs see them as real targets. |
| **Concurrency + safety** | All candidates per IP fanned out via internal `ThreadPoolExecutor(max_workers=VHOST_SNI_CONCURRENCY)` (default 20). Each curl invocation has a `--connect-timeout` + `--max-time = 3 * timeout`, plus a subprocess `timeout * 3 + 2` belt-and-braces guard. Per-IP candidate cap (default 2,000) is deterministic across reruns. |

**Stealth overrides:** `VHOST_SNI_ENABLED=false` outright. Bare-IP curl probes plus per-candidate retries are too noisy for stealth profiles.

**Three vulnerability shapes:**
- `host_header_bypass` (layer = `both`, attached to BOTH the Subdomain AND the IP node since the IP itself is the bypass surface)
- `hidden_sni_route` (layer = `L4`, attached to the Subdomain)
- `hidden_vhost` (layer = `L7`, attached to the Subdomain)

Each finding carries a deterministic id `vhost_sni_<host>_<ip>_<port>_<layer>` so rescans MERGE on the same Vulnerability node in Neo4j (no duplicates).

**Source layout:**

```
recon/main_recon_modules/vhost_sni_enum.py   # The full module (run_vhost_sni_enrichment, run_vhost_sni_enrichment_isolated, _build_candidate_set, _collect_ip_targets, _is_anomaly, _classify_severity, _inject_into_http_probe, _is_valid_hostname)
recon/wordlists/vhost-common.txt             # 2,471-entry default wordlist (shipped in-image)
graph_db/mixins/recon/vhost_sni_mixin.py     # Neo4jClient.update_graph_from_vhost_sni()
```

📖 **Detailed documentation:** [docs/readmes/GRAPH.SCHEMA.md -- VHost/SNI Vulnerability properties + Subdomain/IP enrichment](GRAPH.SCHEMA.md) | **[Wiki: VHost & SNI Enumeration](https://github.com/samugit83/redamon/wiki/VHost-and-SNI-Enumeration)**

---

### Module 6: `github`

```mermaid
flowchart LR
    subgraph Input
        Org[GitHub Org/User]
    end

    subgraph Hunter["GitHub Secret Hunter"]
        Repos[List Repositories]
        Commits[Search Commits]
        Code[Search Code]
    end

    subgraph Patterns["Detection Patterns"]
        AWS[AWS Keys]
        GCP[GCP Credentials]
        Stripe[Stripe Keys]
        DB[Database Strings]
        SSH[SSH Keys]
    end

    subgraph Output
        Secrets[Exposed Secrets]
    end

    Org --> Repos
    Repos --> Commits
    Repos --> Code

    Commits --> Patterns
    Code --> Patterns

    AWS --> Secrets
    GCP --> Secrets
    Stripe --> Secrets
    DB --> Secrets
    SSH --> Secrets
```

---

### Module 7: `trufflehog`

```mermaid
flowchart LR
    subgraph Input
        Org2[GitHub Org/User]
    end

    subgraph Scanner["TruffleHog Secret Scanner"]
        Repos2[List Repositories]
        GitHistory[Deep Git History Scan]
        Verify[Credential Verification]
    end

    subgraph Detectors["Detector Engine"]
        AWS2[AWS Keys]
        GCP2[GCP Credentials]
        Stripe2[Stripe Keys]
        DB2[Database Strings]
        Custom[700+ Detectors]
    end

    subgraph Output2
        Findings[Verified + Unverified Findings]
    end

    Org2 --> Repos2
    Repos2 --> GitHistory
    GitHistory --> Verify

    Verify --> Detectors

    AWS2 --> Findings
    GCP2 --> Findings
    Stripe2 --> Findings
    DB2 --> Findings
    Custom --> Findings
```

TruffleHog provides deep credential detection by scanning the full git history of all repositories belonging to the target GitHub organization or user. Unlike the built-in GitHub Secret Hunter (regex + entropy), TruffleHog uses a detector-based engine with 700+ credential detectors and can **verify** whether discovered credentials are still active.

| Feature | GitHub Secret Hunter | TruffleHog |
|---------|---------------------|------------|
| Detection method | 40+ regex patterns + Shannon entropy | 700+ detector-based engine |
| Verification | No | Yes (active credential checking) |
| Git history depth | Commit + code search API | Full local clone history |
| Output | Secrets + Sensitive files | Verified + Unverified findings |

The `scanners/trufflehog_scan/` directory contains the scanner wrapper and its docker-compose service definition.

---

## 🆚 Complete Tool Comparison

### Overview Matrix

```mermaid
flowchart TB
    subgraph Layer1["Layer 1: DNS/Registry"]
        WHOIS[WHOIS<br/>Domain info]
        DNS[DNS<br/>Resolution]
    end

    subgraph Layer2["Layer 4: Transport"]
        Naabu[Naabu<br/>Port scan]
    end

    subgraph Layer3["Layer 7: Application"]
        Httpx[Httpx<br/>HTTP probe]
        Katana[Katana<br/>Crawl]
        Hakrawler[Hakrawler<br/>DOM crawl]
        GAU[GAU<br/>Archives]
        KR[Kiterunner<br/>API brute]
        jsluice[jsluice<br/>JS analysis]
        Nuclei[Nuclei<br/>Vuln scan]
    end

    subgraph Layer1b["OSINT Enrichment"]
        Shodan2[Shodan<br/>Host/DNS/CVEs]
        URLScan[URLScan<br/>Historical scans]
        Censys2[Censys<br/>Host intelligence]
        FOFA2[FOFA<br/>Asset search]
        OTX2[OTX<br/>Threat intel]
        Netlas2[Netlas<br/>Internet intel]
        VT2[VirusTotal<br/>Reputation]
        ZoomEye2[ZoomEye<br/>Host search]
        CrimIP2[CriminalIP<br/>Risk score]
    end

    subgraph Layer4["Data Enrichment"]
        MITRE[MITRE<br/>CWE/CAPEC]
        GVM[GVM<br/>Deep scan]
    end

    WHOIS --> DNS
    DNS --> Shodan2
    DNS --> URLScan
    Shodan2 --> Naabu
    URLScan --> Naabu
    Naabu --> Httpx
    Httpx --> Katana
    Httpx --> Hakrawler
    Httpx --> GAU
    Httpx --> KR
    Katana --> jsluice
    Hakrawler --> jsluice
    jsluice --> Nuclei
    Katana --> Nuclei
    Hakrawler --> Nuclei
    GAU --> Nuclei
    KR --> Nuclei
    Nuclei --> MITRE
    Nuclei --> GVM
```

### Feature Comparison

| Feature | WHOIS | DNS | Shodan | URLScan | Censys | FOFA | OTX | Netlas | VirusTotal | ZoomEye | CriminalIP | Masscan | Naabu | httpx | Katana | Hakrawler | GAU | Kiterunner | jsluice | Nuclei | GVM |
|---------|-------|-----|--------|---------|--------|------|-----|--------|------------|---------|------------|---------|-------|-------|--------|-----------|-----|------------|---------|--------|-----|
| **Domain Info** | ✅ | ⚠️ | ❌ | ❌ | ❌ | ⚠️ | ⚠️ | ⚠️ | ❌ | ⚠️ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **IP Resolution** | ❌ | ✅ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ❌ | ⚠️ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Subdomain Discovery** | ❌ | ❌ | ⚠️ | ✅ | ❌ | ⚠️ | ❌ | ⚠️ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Port / Service Data** | ❌ | ❌ | ⚠️ | ❌ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ⚠️ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Live URL Check** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Tech Detection** | ❌ | ❌ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ❌ | ⚠️ | ⚠️ | ⚠️ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ⚠️ | ⚠️ |
| **Endpoint Discovery** | ❌ | ❌ | ❌ | ⚠️ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ | ⚠️ | ❌ | ❌ |
| **Historical URLs** | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ⚠️ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Threat Reputation** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Passive DNS** | ❌ | ❌ | ⚠️ | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Malware / CVE Intel** | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ |
| **TLS / Certificate** | ❌ | ❌ | ⚠️ | ⚠️ | ✅ | ✅ | ❌ | ✅ | ❌ | ✅ | ⚠️ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Geolocation / ASN** | ❌ | ❌ | ✅ | ⚠️ | ✅ | ✅ | ⚠️ | ✅ | ⚠️ | ✅ | ✅ | ❌ | ❌ | ⚠️ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **API Discovery** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| **XSS/SQLi Testing** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ⚠️ |
| **Secret Detection** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ |

**Legend:** ✅ Primary | ⚠️ Limited | ❌ Not supported

### Timing Comparison

| Tool | Typical Duration | Notes |
|------|------------------|-------|
| WHOIS | <1 second | Instant |
| DNS | <1 second | Instant |
| Shodan | 5-15 seconds | Passive, per-IP queries |
| URLScan | 5-20 seconds | Passive, API rate-limited |
| Censys | 5-30 seconds | Passive, per-IP queries, 429 detection |
| FOFA | 5-30 seconds | Passive, domain/IP query, max 10,000 results |
| OTX | 5-60 seconds | Passive, per-IP + per-domain queries |
| Netlas | 5-30 seconds | Passive, per-IP/domain queries, max 1,000 results |
| VirusTotal | 1-5 minutes | Free tier: 4 req/min; 65s wait on rate limit |
| ZoomEye | 5-30 seconds | Passive, per-IP/domain queries, max 1,000 results |
| CriminalIP | 5-30 seconds | Passive, per-IP + per-domain queries |
| Amass | 1-10 minutes | Passive; longer with active/brute |
| Puredns | 30-90 seconds | Depends on subdomain count |
| Masscan | 1-30 seconds | Fastest for large CIDR ranges |
| Naabu | 5-10 seconds | 1000 ports |
| httpx | 10-30 seconds | All options |
| Katana | 1-5 minutes | Crawl depth 3 |
| Hakrawler | 30-120 seconds | Active crawling, depth 2 |
| GAU | 10-30 seconds | Passive |
| jsluice | 10-60 seconds | Active JS download + analysis |
| Nuclei | 1-30 minutes | Depends on templates |
| GVM | 30 min - 2+ hours | Full scan |

---

## ⚙️ Key Configuration Parameters

### Essential Settings

All settings are managed through the webapp project form or via environment variables. Key defaults are defined in `project_settings.py`:

| Setting | Default | Description |
|---------|---------|-------------|
| `TARGET_DOMAIN` | — | Root domain to scan |
| `SUBDOMAIN_LIST` | `[]` | Empty = discover all |
| `SCAN_MODULES` | all 5 modules | Modules to run |
| `NAABU_TOP_PORTS` | `"1000"` | Top-N ports to scan |
| `NAABU_SCAN_TYPE` | `"s"` | SYN scan |
| `MASSCAN_RATE` | `1000` | Masscan packets/sec |
| `OTX_ENABLED` | `true` | OTX threat intel enrichment (anonymous by default) |
| `VIRUSTOTAL_RATE_LIMIT` | `4` | VirusTotal requests per minute (free tier) |
| `VIRUSTOTAL_MAX_TARGETS` | `20` | Max IPs+domains to query with VirusTotal |
| `FOFA_MAX_RESULTS` | `1000` | FOFA results per query (max 10,000) |
| `NETLAS_MAX_RESULTS` | `1000` | Netlas results per query (max 1,000) |
| `ZOOMEYE_MAX_RESULTS` | `1000` | ZoomEye results per query |
| `NUCLEI_DAST_MODE` | `true` | Active fuzzing |
| `NUCLEI_SEVERITY` | critical, high, medium, low | Severity filter |
| `WAPPALYZER_ENABLED` | `true` | Technology detection |
| `MITRE_INCLUDE_CWE` | `true` | CWE enrichment |
| `MITRE_INCLUDE_CAPEC` | `true` | CAPEC enrichment |

---

## 🔧 Prerequisites

### Docker Mode (Recommended)

- **Docker** with Docker Compose
- **Docker daemon access via the filtering broker** for nested (sibling) container execution

```bash
# Verify Docker is running
docker info

# Build and run
cd recon/
docker-compose build --network=host
docker-compose run --rm recon python /app/recon/main.py
```

### Tool Containers (auto-pulled)

| Tool | Docker Image | Purpose |
|------|--------------|---------|
| Masscan | Built from source (native binary) | High-speed SYN port scanning |
| Naabu | `projectdiscovery/naabu:latest` | Port scanning |
| httpx | `projectdiscovery/httpx:latest` | HTTP probing |
| Nuclei | `projectdiscovery/nuclei:latest` | Vuln scanning |
| Katana | `projectdiscovery/katana:latest` | Web crawling |
| GAU | `sxcurity/gau:latest` | URL discovery |
| Amass | `caffix/amass:latest` | Subdomain enumeration |
| Puredns | `frost19k/puredns:latest` | Wildcard filtering |

---

## 📁 Project Structure

```
recon/
├── Dockerfile              # Container build
├── docker-compose.yml      # Orchestration
├── project_settings.py     # 🔗 Settings fetcher (API or built-in defaults)
├── main.py                 # 🚀 Entry point
├── domain_recon.py         # Subdomain discovery
├── whois_recon.py          # WHOIS lookup
├── urlscan_enrich.py       # URLScan.io OSINT enrichment
├── censys_enrich.py        # Censys threat intelligence enrichment
├── fofa_enrich.py          # FOFA internet asset search enrichment
├── otx_enrich.py           # OTX (AlienVault) threat intelligence enrichment
├── netlas_enrich.py        # Netlas internet intelligence enrichment
├── virustotal_enrich.py    # VirusTotal reputation enrichment
├── zoomeye_enrich.py       # ZoomEye host search enrichment
├── criminalip_enrich.py    # Criminal IP threat intelligence enrichment
├── port_scan.py            # Port scanning
├── http_probe.py           # HTTP probing
├── resource_enum.py        # Endpoint discovery
├── main_recon_modules/
│   └── ai_surface_recon.py # AI/LLM/MCP/vector-DB surface fingerprinting (Phase 4.5)
├── vuln_scan.py            # Vulnerability scanning
├── add_mitre.py            # MITRE enrichment
├── github_secret_hunt.py   # GitHub secrets
├── scanners/trufflehog_scan/        # TruffleHog secret scanner (separate service)
├── output/                 # 📄 Scan results (JSON)
├── data/                   # 📦 Cached databases
│   ├── mitre_db/           # CVE2CAPEC database
│   └── wappalyzer/         # Technology rules
├── helpers/                # Tool helpers
└── docs/readmes/                # 📖 Module docs
```

---

## 📊 Output Format

All modules write to: `recon/output/recon_<domain>.json`

```mermaid
flowchart TB
    subgraph JSON["recon_domain.json"]
        Meta[metadata<br/>scan info, timestamps]
        WHOIS[whois<br/>registrar, dates]
        Subs[subdomains<br/>discovered hosts]
        DNSData[dns<br/>A, MX, TXT records]
        Ports[port_scan<br/>open ports, services]
        HTTP[http_probe<br/>live URLs, tech stack]
        Resources[resource_enum<br/>endpoints, forms]
        AISurface[ai_surface_recon<br/>AI/LLM/MCP/vector-DB]
        Vulns[vuln_scan<br/>CVEs, misconfigs]
        TechCVE[technology_cves<br/>version-based CVEs]
    end

    Meta --> WHOIS
    WHOIS --> Subs
    Subs --> DNSData
    DNSData --> Ports
    Ports --> HTTP
    HTTP --> Resources
    Resources --> AISurface
    AISurface --> Vulns
    Vulns --> TechCVE
```

---

## 🧪 Test Targets

Safe, **legal** targets for security testing:

| Target | Technology | Vulnerabilities |
|--------|------------|-----------------|
| `testphp.vulnweb.com` | PHP + MySQL | SQLi, XSS, LFI |
| `testhtml5.vulnweb.com` | HTML5 | DOM XSS |
| `testasp.vulnweb.com` | ASP.NET | SQLi, XSS |
| `scanme.nmap.org` | N/A | Port scanning only |

```python
# Example configuration
TARGET_DOMAIN = "vulnweb.com"
SUBDOMAIN_LIST = ["testphp."]
NUCLEI_DAST_MODE = True
```

---

## ⚠️ Legal Disclaimer

**Only scan systems you own or have explicit written permission to test.**

Unauthorized scanning is illegal. RedAmon is intended for:
- Penetration testers with proper authorization
- Security researchers on approved targets
- Bug bounty hunters within program scope
- System administrators testing their infrastructure

---

## 📖 Detailed Documentation

| Module | Documentation |
|--------|---------------|
| Port Scan | [docs/readmes/README.PORT_SCAN.md](README.PORT_SCAN.md) |
| HTTP Probe | [docs/readmes/README.HTTP_PROBE.md](README.HTTP_PROBE.md) |
| Vuln Scan | [docs/readmes/README.VULN_SCAN.md](README.VULN_SCAN.md) |
| MITRE CWE/CAPEC | [docs/readmes/README.MITRE.md](README.MITRE.md) |
| GVM/OpenVAS | [README.GVM.md](README.GVM.md) |
