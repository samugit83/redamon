# RedAmon Reconnaissance Module

**Unmask the hidden before the world does.**

An automated OSINT reconnaissance and vulnerability scanning framework combining multiple security tools for comprehensive target assessment.

---

## Table of Contents

- [Quick Start](#-docker-quick-start-recommended)
- [Architecture](#-docker-in-docker-architecture)
- [Pipeline Overview](#-scanning-pipeline-overview)
- [How a Run Ends](#-how-a-run-ends-prune-and-mute-rules)
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
   The recon module fetches every project setting (each one is described in `recon_settings/registry.yaml`) from:
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
# ... and every other setting
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
    API-->>Recon: Project settings
    Recon->>Recon: Execute scan pipeline
    Recon->>Neo4j: Update graph with results
    Orchestrator->>Webapp: SSE log stream
    Recon-->>Orchestrator: Container exits
    Orchestrator->>Webapp: Complete event
```

---

## 🏗 Docker-in-Docker Architecture

The recon module uses a **Docker-in-Docker (DinD)** pattern where the main recon container orchestrates sibling containers for each scanning tool.

### How It Works

The recon container reaches the host's Docker daemon through a **filtering broker** (`services/docker_broker/broker.py`) rather than the raw socket. The broker blocks by default: it forwards only the Docker API calls the tools' own `docker` invocations send (create, pull, attach, start/wait/kill/stop, logs, remove, and inspect or create of the tool volumes and networks) and refuses anything else with a 403 before the daemon sees it. A container create may use only the known tool images, bind only the shared scratch dir `/tmp/redamon` (read-write) and three repository subdirectories (`recon/wordlists`, `mcp/nuclei-templates`, `scanners/supply_chain_common`, read-only), and mount named volumes read-only except `nuclei-templates`. Verbs on an existing container work only on containers the broker created. All tool containers are therefore **siblings** managed by the same host daemon, while the recon container itself cannot create a container that mounts the host filesystem, runs privileged, or uses an unapproved image.

```mermaid
flowchart TB
    subgraph Host["🖥️ HOST MACHINE"]
        subgraph DockerDaemon["Docker Daemon (dockerd)"]
            Socket["/var/run/docker.sock"]
        end

        Broker["🛡️ docker-broker<br/>default-deny API allowlist<br/>tool images + scratch mounts only"]

        subgraph Containers["Sibling Containers"]
            Recon["redamon-recon<br/>Python Orchestrator<br/>📋 Coordinates all scans"]
            NaabuC["naabu<br/>projectdiscovery/naabu<br/>🔌 Port Scanner"]
            HttpxC["httpx<br/>projectdiscovery/httpx<br/>🌐 HTTP Prober"]
            NucleiC["nuclei<br/>projectdiscovery/nuclei<br/>🎯 Vuln Scanner"]
            KatanaC["katana<br/>projectdiscovery/katana<br/>🕸️ Web Crawler"]
            GAUC["gau<br/>sxcurity/gau<br/>📚 URL Archives"]
            PurednsC["puredns<br/>frost19k/puredns<br/>🧹 Wildcard Filter"]
        end

        Volume["📁 Shared scratch dir<br/>/tmp/redamon/"]
    end

    Broker -.->|filtered socket| Recon
    Broker -.->|allowlisted calls| Socket
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
    Note over Recon: Fan-In — merge results + Puredns wildcard filtering + DNS (DNS_MAX_WORKERS, default 80)
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
    Recon->>Recon: OpenAPI — fetch specifications, merge declared endpoints (never called)
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
        RE[Resource Enum<br/>Katana ∥ Hakrawler ∥ GAU ∥ ParamSpider ∥ Kiterunner<br/>crawlers one at a time under an RoE ceiling<br/>then jsluice → FFuf → Arjun → OpenAPI]
    end

    subgraph G6["GROUP 6 Phase A — parallel (up to 7-way fan-out, enabled tools only; one at a time under an RoE ceiling)"]
        VS[Vuln Scan — Nuclei]
        GQL[GraphQL Security<br/>Introspection + graphql-cop]
        TKO[Subdomain Takeover<br/>Subjack + Nuclei + BadDNS]
        VHOST[VHost & SNI Enum<br/>L7 Host header + L4 SNI probing]
        WCP[Web Cache Poisoning<br/>WCVS + native confirmer]
        ORIG[Origin Discovery]
        REXP[Route Exposure]
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
        Puredns --> DNS[DNS Resolution<br/>DNS_MAX_WORKERS parallel workers, default 80<br/>A, AAAA, MX, NS, TXT, CNAME]
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
        JsRecon -.->|on by default for new projects| TruffleHog[TruffleHog sidecar<br/>local copies only, 33 detectors excluded<br/>network none unless keys are validated]

        Patterns --> SecretMerge[Merge<br/>one finding per key]
        TruffleHog --> SecretMerge
        SecretMerge --> KeyVal[Key Validation<br/>21 service validators<br/>TruffleHog: validated or unknown, never rejected]
        KeyVal --> Out4b[(JS Findings + Secrets + Endpoints)]
        SrcMap --> Out4b
        DepConf --> Out4b
        EpExtract --> Out4b
        FwSink --> Out4b
    end

    subgraph Phase5["GROUP 6 Phase A — Fan-Out: Nuclei ∥ GraphQL ∥ Takeover ∥ VHost/SNI ∥ Cache ∥ Origin ∥ Route Exposure (parallel)"]
        direction TB
        Out4b --> FanOut6

        subgraph FanOut6["ThreadPoolExecutor — up to 7 parallel tasks, one worker under an RoE ceiling (one shared deep-copy snapshot; _isolated wrappers copy again)"]
            direction LR
            Nuclei[Nuclei Scanner]
            GraphQL[GraphQL Security Scanner]
            Takeover[Subdomain Takeover Scanner]
            VhostSni[VHost & SNI Enum]
            CachePoison[Web Cache Poisoning]
            OriginDisc[Origin Discovery]
            RouteExp[Route Exposure]
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
        CachePoison --> FanIn6
        OriginDisc --> FanIn6
        RouteExp --> FanIn6
    end

    subgraph Phase5b["GROUP 6 Phase B — MITRE Enrichment (sequential, depends on Nuclei CVEs)"]
        FanIn6[Fan-In: merge each Phase A tool's findings as it lands] --> MITRE[MITRE Enrichment<br/>CWE + CAPEC]
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
| **GROUP 1** | WHOIS + Subdomain Discovery + URLScan | 3 parallel tasks | Only needs `root_domain`. URLScan's recent host names join the merged host list (`merge_group_hosts`, `extra_hosts`) through the late-name gates; its findings are written right after discovery |
| *Discovery* | crt.sh + HackerTarget + Subfinder + Amass + Knockpy | 5 parallel tools | Part of GROUP 1 |
| *Puredns* | Wildcard filtering (validates against public resolvers) | Sequential | After discovery fan-in, before DNS |
| *DNS* | DNS resolution for all subdomains | `DNS_MAX_WORKERS` parallel workers (default 80) | After puredns filtering |
| **GROUP 2b** | Uncover Target Expansion (13 search engines) | Sequential | Needs domain from GROUP 1; runs before GROUP 3 |
| **GROUP 3** | Shodan Enrichment + Port Scan (Naabu, Masscan) | Up to 3 parallel tasks, each enabled tool only | Needs IPs from GROUP 1 + GROUP 2b; then Nmap (3.5; `NMAP_PARALLELISM` IPs at a time, one under an RoE ceiling) and tlsx (3.6) run in sequence |
| **GROUP 3b** | OSINT Enrichment (Censys + FOFA + OTX + Netlas + VirusTotal + ZoomEye + CriminalIP) | Up to 7 tasks on 5 workers, each enabled tool only | Needs IPs/domains from GROUP 1; runs after GROUPs 3, 3.5 and 3.6 |
| **GROUP 4** | HTTP Probe (httpx) | Sequential (internally parallel) | Needs ports from GROUP 3 |
| *Late names* | uncover, tlsx, certificate-SAN and JS Recon names get their DNS; after the port scan, the ports their addresses showed (or a port scan of an unscanned address); after httpx, a probe of their own (`recon/helpers/late_names.py`) | Sequential | At each merge point (2b, 3.6, after GROUP 4, 5b) |
| *Takeover verdict* | Which deleted-service pages urlscan recorded still describe their host, from this scan's DNS and live pages (`main_recon_modules/urlscan_takeover.py`) | Sequential; DNS only, through the `dns:takeover-verdict` breaker | After GROUP 4, outside the httpx step; before Phase A, whose Subdomain Takeover reads `urlscan.takeover_hosts` |
| *IP attribution* | Tags every IP `shared_edge` / `dedicated` / `unknown` (`main_recon_modules/ip_attribution.py`), then writes the Shodan CVEs and the Netlas data GROUP 3/3b held back | Sequential; the TLS handshakes without SNI in a small pool, paced at the RoE ceiling | After GROUP 4 and the certificate SAN feedback; before GROUP 5 and 6. Runs if `IP_ATTRIBUTION_ENABLED` |
| **GROUP 5** | Resource Enum (Katana + GAU + Kiterunner, then OpenAPI) | 3 tools internally parallel | Needs live URLs from GROUP 4 |
| **GROUP 5b** | JS Recon Scanner (250+ regex patterns, key validation, source maps, dependency confusion, endpoint extraction, DOM sinks; optionally TruffleHog in a hardened sidecar, its keys merged one per key) | 5 analyzers parallel per file (TruffleHog in its own worker, on its own running-time budget) | Needs JS files from GROUP 5; runs if `JS_RECON_ENABLED` |
| **GROUP 5.5** | Supply-Chain Recon (black-box package harvest + offline OSV verdict, retire.js over served JS, optional GuardDog; then incident enrichment, malicious-host correlation and typosquat detection) | Sequential; dispatches the DIRTY analyzer | Needs JS files from GROUP 5b; runs if `SUPPLY_CHAIN_RECON_ENABLED` |
| **GROUP 6 Phase A** | Vuln Scan (Nuclei) ∥ GraphQL Security Testing ∥ Subdomain Takeover ∥ VHost & SNI Enumeration ∥ Web Cache Poisoning ∥ Origin Discovery ∥ Route Exposure | Up to 7 parallel tasks (ThreadPoolExecutor, `_isolated` wrappers), each only when enabled; under an RoE rate ceiling one at a time, in the same order (`_run_phase_a_fan_out`) | Needs endpoints from GROUP 5/5b |
| **GROUP 6 Phase B** | MITRE Enrichment (CWE + CAPEC) | Sequential | Needs CVEs from Phase A (Nuclei) |

### IP attribution

`run_ip_attribution` labels every IP of the run once, so the modules that ask
"is this IP the target's?" stop guessing on their own. The rule
(`ownership_tag`, pure):

- `shared_edge`: `cdn_ranges.classify_ip` fires on a published edge prefix,
  an edge-only CDN name naabu, tlsx or httpx reported, or an edge's response
  header; or on an edge-only ASN (`CDN_ASNS`) while the default certificate
  does not cover a target domain;
- `dedicated`: the certificate the IP presents to a TLS client that sends no
  SNI covers a target domain (the org of every project root; IP mode has none);
- `unknown`: otherwise. Never "not ours": a cloud label is no signal.

Its one active check is that handshake (`recon/helpers/peer_cert.py`, shared
with origin discovery), only where :443 was found open. It skips RoE-excluded,
loopback and link-local addresses and hosts `host_health` marks down, is paced
at `min(10 rps, ROE_GLOBAL_MAX_RPS)`, and is capped per run by
`IP_ATTRIBUTION_TLS_MAX_PROBES` (stealth sets 0). A failed handshake is never
evidence: the reasons say "default certificate not checked (<why>)". The step
never raises; an IP it could not attribute is `unknown` with the reason.

Output: `combined_result["ip_attribution"]["by_ip"]`, written by
`update_graph_from_ip_attribution` to the existing IP (`ownership`,
`ownership_reasons`, `default_cert_names`, `current_dns_names`, plus the CDN
tag on a shared edge). Consumers read it through `shared_edge_ips()`:
the IP-mode hostnames step (`scan_all` refuses a name seen on or resolving to a
`shared_edge` IP, and every name when the step did not run or failed on its IP;
`current_dns_names` is then the number of names recorded on the IP), vhost/SNI (`_shared_edge_ips`, plan 07's CDN check as the fallback for an
untagged IP), origin discovery (`_cdn_flagged_ips`), the Shodan CVE write
(`_write_shodan_cves`) and the Netlas write (`_write_netlas`, both held back
until the step runs), and the Priority Board (`ip_ownership` fact). A partial
run loads the graph's tag with `attach_graph_ownership`. The step writes no
finding, so it has nothing for the prune to keep.

### Background Graph DB Updates

All Neo4j graph updates run in a **dedicated single-writer background thread** (`ThreadPoolExecutor(max_workers=1)`). The main pipeline submits deep-copy snapshots of recon data and continues immediately. A final `_graph_wait_all()` ensures all updates complete before the pipeline exits.

### Structured Logging

All log messages use a consistent `[level][Module]` prefix format (e.g., `[+][crt.sh] Found 42 subdomains`) for clarity when multiple tools produce interleaved output from concurrent threads.

### Thread Safety

Each parallelized tool function is thread-safe:
- Discovery tools (`query_crtsh`, `query_hackertarget`, etc.) create their own `requests.Session` instances
- Module `_isolated` variants (e.g., `run_port_scan_isolated`, `run_shodan_enrichment_isolated`) accept a read-only snapshot of `combined_result`, deep-copy it, and return only their data section. Every fan-out (GROUP 3, the GROUP 3b OSINT pool, GROUP 6 Phase A) takes one `_fan_out_snapshot` (a deep copy) before its first submit and hands every worker that copy, never the live `combined_result` the main thread merges answers into: a wrapper copying the live dict mid-merge raised "dictionary changed size during iteration" and lost its tool. A failed GROUP 3 or OSINT worker is recorded in `metadata.phase_errors`, as a Phase A one is
- The main thread handles all merging — no shared mutable state between workers

---

## 🧹 How a Run Ends: Prune and Mute Rules

Outside the modules themselves, a full run touches the project's findings in
three places, all in `recon/main.py`:

1. **Clear, at the start** (`_clear_recon_graph`). It removes the project's
   previous recon *assets* and records the run's start time. Findings are NOT
   cleared up front: the operator's mutes, verdicts and fix items hang off them.
   It runs only after `_refuse_before_clear` let at least one scan root through
   the same Rules of Engagement and ownership checks `run_domain_group` makes
   (ownership answers cached for the run): when every root is refused the run
   returns 1 with the graph as it was ("Nothing was cleared"), and a batch with
   one eligible root clears once while its refused groups still refuse in the
   loop. IP mode has no root check and clears directly.
2. **Prune, after a successful run** (`_prune_recon_findings`, which calls
   `prune_unseen_findings`). It deletes the findings from recon's own sources
   (`RECON_FINDING_SOURCES` in `recon/helpers/finding_sources.py`) that this run
   did not write again. A finding a person muted, or one with a human verdict,
   is kept and stamped `stale_since` instead. A Mute Rules mute is not a
   judgement of the finding, so it is pruned like any other. A run that failed,
   or whose clear did not run, prunes nothing.
3. **The Mute Rules sweep, whatever happened** (`_apply_node_filters`, in
   `main()`'s `finally`). If the project's
   [Mute Rules](../../redamon.wiki/Mute-Rules.md) are *active on new scans*
   (Apply → New scans only, or Both), the run applies them once, to what it
   wrote: findings stamped after the run started, from recon's own sources. It
   mutes what the rules match and releases rule mutes no rule matches any more.
   It never touches a person's mute, a guarded finding (a human verdict, a
   confirmed or proven finding, one a `ChainFinding` CONFIRMS) or one an
   operator unmuted (an exemption). The rules are re-read at sweep time, so a
   save made during the scan applies. The sweep never raises and never changes
   the exit code; its counts are written to the output file's
   `metadata.node_filter`. It runs once per run, a Domain batch included.

What follows from that:

- **Some kinds are never swept by a scan.** The supply-chain findings (OSV
  advisories, malicious packages) come from sources outside
  `RECON_FINDING_SOURCES`, so only "apply to current graph" reaches them. GVM
  findings cannot be filtered yet.
- **Passive CVEs are recon sources.** `shodan_api`, `internetdb`, `netlas` and
  `criminalip` (plus `shodan` and `shodan_host_lookup`, the Shodan writer's
  create-only fallbacks) are in `RECON_FINDING_SOURCES`, grouped per enricher
  in `PASSIVE_CVE_SOURCES`, which also feeds `_PHASE_FINDING_SOURCES`: an
  enricher that raises, in its module or at the fan-in, keeps its findings.
- **Switched off vs degraded.** A source switched off by configuration (the
  module disabled, no API key) notes nothing, so its old findings are pruned
  like any other's; muted and judged ones are kept as stale, as the nmap rule in
  `_note_nmap_without_port_data` does. A source that was meant to run and could
  not check everything is degraded instead, through
  `note_cve_coverage` in `recon/helpers/passive_cve_coverage.py`: each lookup records
  which IPs got an answer ("no data" included), the IPs it could not ask about
  are kept by host (`target_ip`, source-only), and a lookup that reached
  nothing (a refused key, a crash, no IP at all) keeps its whole source.
  A Netlas answer cut short by its row cap keeps that IP; one that reached the
  provider never degrades the whole source, or its stale findings would never
  be pruned. The provider names one coverage gap: `note_degraded(aliases=...)`
  cuts its other source values with it.
- **A failed graph write keeps its findings.** `_WRITER_SOURCES` maps each
  background writer of findings to the `_PHASE_FINDING_SOURCES` phase whose
  sources it writes. A writer that raises, reports an item error on a finding,
  finds Neo4j unreachable, or is never queued because the writer was already
  closed notes those sources degraded (`graph write failed (<writer>)`), which
  wins over any `note_checked`. Writers of assets only, and errors that cost no
  finding, degrade nothing. A new writer of findings needs its row (a test
  enforces it).
- **A failed layer or input phase keeps what it did not re-check.** Subdomain
  Takeover notes each failed layer's targets by host for `takeover_scan` alone
  (Subjack or BadDNS: every subdomain; Nuclei: the hosts of its live URLs; a
  BadDNS per-target timeout: that name); a Subjack timeout still keeps the rows
  it wrote, and a BadDNS run timeout keeps the findings it printed and notes
  only the names from the last one with a printed finding onwards (BadDNS
  prints a name's findings once it is done with it, in target order). The
  GraphQL scan keeps `graphql_cop` alone, by host, on an endpoint whose
  graphql-cop timed out, could not start or returned no report; the native
  GraphQL checks reached that host. The cache scan does the same for `cache_poisoning` (and its `wcvs`
  alias) on the hosts past the 200-URL cap, of a URL whose confirmation raised
  or that never answered the oracle, and on every target of an unfinished WCVS
  run. The serialized scan degrades its whole source on an error, or when
  `http_probe` or `resource_enum` is in `metadata.phase_errors`.
- **Skipped for no live URL.** When `should_skip_active_scans` fires, Subdomain
  Takeover still runs, and so do the port and service checks
  (`_maybe_run_port_checks`), the org DNS checks (`_maybe_run_dns_checks`) and
  certificate hygiene. `_note_gate_skipped` keeps, by host on the group's hosts,
  the findings of every enabled source the skip stopped (resource_enum, nuclei,
  the Phase A tools in `_LIVE_URL_PHASE_A`); `security_check` is kept except on
  the addresses the port checks read and the orgs the DNS checks asked. A tool
  switched off prunes as before.
- **A failed probe is not "no live URL".** When httpx could not run (Docker
  missing or down, the image unavailable, an exit or its runtime budget with
  nothing written, an exception), `run_http_probe` records
  `metadata.phase_errors.http_probe`, keeps the `http_probe` source, and is not
  listed in `modules_executed`. `should_skip_active_scans` then takes the skip
  above with the reason `http_probe failed (...)`, and `_note_gate_skipped`
  notes "http_probe failed, no host probed": `security_check` is kept on every
  host, the port- and DNS-check ones included, and JS Recon and AI Surface
  Recon, which still run without httpx's pages, keep their findings by host
  too. A tlsx run cut short (timeout, exit, missing runner) keeps the rows it
  printed (on `TLSX_RUN_TIMEOUT` its container is first killed by its name,
  `tlsx-<run id>-<8 hex>`, so no handshake goes out after the cut)
  and notes `security_check` by host on every target it did not answer,
  under module `tlsx`; one that answered nothing records a phase error.
- **A finding is matched on every host it names.** The keep regexes and the
  `only_hosts` lookup read the scalar host fields (`_KEEP_HOST_FIELDS` in
  `graph_db/mixins/base_mixin.py`) and each element of a list field
  (`_KEEP_HOST_LIST_FIELDS`: `source_urls`, the JS files that import a
  dependency-confusion package). A cut host among them keeps the finding; a
  re-checked one makes it a prune candidate, and a kept host still wins. Host
  names may contain `_` (`_dmarc.example.com`): the coverage notes keep them
  like any other host.
- **A source can prune only the hosts it re-checked (positive coverage).** A
  module that calls `circuit_breaker.note_checked(source, hosts=..., checks=...,
  module=...)` records the hosts it reached a verdict on, and
  `_checked_prune_batches` prunes that source through
  `prune_unseen_findings(only_hosts=..., types=...)`: a host it never reached
  keeps its findings even when nothing noted it degraded. Degraded wins: a host
  cut for the source, or for every source, leaves its checked set and is kept.
  Hosts match by hostname, so any port checked counts the host as checked. An
  empty `only_hosts` prunes nothing (the revive still runs).
  `coverage_stamps.note_rows_checked(source, rows)` turns a per-host coverage
  record into the same note: `complete` is checked, `partial` or `failed` is cut
  for that host and source, `no_input` is neither. A source that records
  nothing keeps the source-level rule above.
- **`security_check` records per finding type.** The DNS checks (SPF, DMARC,
  DNSSEC, zone transfer) record each verdict on the org (`Vulnerability.domain`),
  Redis No Auth and SMTP Open Relay on the IP. A check with no verdict (a
  timeout, SERVFAIL, a reset: `CheckUnknown`) records its type on no host, so
  its finding there is kept, and leaves a coverage gap. Every type the source
  did not record (headers, TLS, cookies, a switched-off check) is pruned by one
  more source-level call with `exclude_types=`, as before. DNS findings written
  before they stored `domain` get the org of the Domain they hang off first
  (`backfill_security_check_domains`); if that fails, the DNS types prune
  nothing that run.
- **The security checks keep the hosts they did not probe.** A domain run
  probes a host only on a web port its port scan or httpx found live, and never
  a host the Rules of Engagement refuse
  ([README.VULN_SCAN.md](README.VULN_SCAN.md#which-hosts-the-checks-probe)).
  A host with no live port in that data, one with an unproven web port while an
  evidence source was cut, and an RoE-refused host are noted degraded for
  `security_check` alone (`source_only_hosts`): the prune keeps their findings,
  and none is marked unreachable, which would keep the host's findings for every
  source. In a partial run, a typed host the graph has no live row for is probed
  on both web ports.
- **Passive CVE lookups record positive coverage.** Shodan (with InternetDB),
  Netlas and CriminalIP pass `note_cve_coverage` the IPs they started from
  (`considered=`), the ones they asked about and the ones whose whole answer
  they saw ("no data" included). It notes as checked, for every source value of
  the provider, the IPs answered whole plus the IPs the CDN or private-address
  filter dropped before asking (decided, not skipped: an edge's CVEs describe
  the provider). The prune then deletes a stale passive CVE only on those IPs.
  An IP no longer in the run (DNS stopped pointing at it, it left the target
  list) keeps its CVEs until a run asks about it again; the asset clear removed
  its IP node, so the Priority Board reads their reach as unknown
  (`target_ip_in_graph` in `agentic/cypherfix_triage/fact_queries.py`).
- **Restored findings prune like any others.** The export and the Scan Timeline
  snapshot flatten Neo4j DateTimes to ISO strings. A restore writes RedAmon's
  own timestamps (`updated_at`, `stale_since`, `created_at`, the triage and
  coverage `*_at`) back as DateTimes (`webapp/src/lib/graphRestore.ts`), and the
  prune and its revive also read an ISO-string `updated_at`, so a graph
  restored by an earlier release needs no rescan. A value that is no timestamp
  keeps its finding.
- **Older passive CVEs get their host first.** `backfill_passive_cve_hosts`
  sets `target_ip` from the id (`shodan-<cve>-<ip>`, `criminalip-<cve>-<ip>`)
  on rows written before the writers stored it, so the by-host keep can match
  them. If it fails, passive sources are left out of that run's prune.
- **Passive CVEs are checked against the port scan.** `_reachcheck_shodan_cves`
  runs after the nmap merge (which adds the open ports nmap confirmed and the
  port scan missed), right before `_write_shodan_cves`, in both pipelines, and
  sets `port_confirmed` from
  `recon/helpers/port_coverage.py`: open, looked at and not open, or unknown.
  What a scan looked at comes from its recorded `ports_config`: a custom list
  or `top-full` is known; naabu's and masscan's top-100/1000 lists are not
  shipped here, so they can confirm an open port but never call one closed;
  naabu passive mode confirms nothing; masscan with an exclusion list never
  says closed. Partial recon reads `active_open_ports` from the graph and only
  confirms.
- **Netlas findings are per IP and port.** `netlas-<cve>-<ip>-<port>`, under
  the IP. Rows from earlier releases were keyed on the bare CVE id;
  `tooling/scripts/netlas_finding_rekey.py` (dry run by default; `--apply`
  with the services stopped, before the first scan on the new release) moves
  their mutes, layers, proof edges and Postgres references.
- **An AI Surface Recon MCP finding is per YARA rule.** Its id hashes type,
  base URL, path, tool and the rule name (`_mk_finding` in
  `recon/main_recon_modules/ai_surface_recon.py`). Rows from earlier releases
  merged every rule on a server into one node; `tooling/scripts/aisr_finding_rekey.py`
  (dry run by default; `--apply` with the services stopped, before the first
  scan on the new release) moves each to the id of the rule its stored `name`
  gives, and the other rules come back as new findings.
- **A VHost/SNI finding id is a hash of hostname, IP, port and layer**
  (`finding_id` in `recon/main_recon_modules/vhost_sni_enum.py`,
  `vhost_sni_<20 hex>`, the IP canonicalised). The earlier id folded
  punctuation to `_`, so `dev-api` and `dev.api` on one IP and port were one
  node. `tooling/scripts/vhost_finding_rekey.py` (same usage) moves rows from
  earlier releases; a node two names collided on moves to the name it stores.
- **A web-cache-deception finding is keyed on the page, not the plant URL.**
  `cache_param` holds the leaked shape (`static-suffix:/.css`) and the random
  plant URL stays in `poc_link`. `tooling/scripts/cache_deception_rekey.py`
  (same usage) moves rows from earlier releases, which got a new id every run.
- **A JS Recon Secret's id is a hash of its pattern, match and file**
  (`_make_finding_id` in `recon/helpers/js_recon/patterns.py`). The keyword
  gap of about 70 patterns is now `[^\n]{0,120}?` (the nearest value, at most
  120 characters away) instead of `.*`, so a match that ran to the last
  candidate on a minified line is shorter and gets a new id.
  `tooling/scripts/js_secret_rekey.py` finds the pattern that produced each
  stored id, re-runs its current regex over the stored match, and moves the
  mute, layers, CONFIRMS edges and Postgres references to the id the scanner
  now writes (dry run by default; `--apply` with the services stopped, before
  the first scan on the new release). A match the new pattern rejects (the old
  Azure AD false positives) is left for the prune. A hit re-read under another
  name (`_refine`: an Algolia key labelled as the search key, a Supabase JWT by
  its `role`) keeps the id of the pattern that matched it, so it needs no
  re-key.
- **Secret validation states.** `validators.py` returns an explicit `state`
  (`valid`, `rejected`, `unknown`, `format_invalid`); js_recon stores
  `validated`, `rejected`, `unknown`, `format_invalid`, `format_validated`,
  `incomplete`, `unvalidated` (no validator) or `skipped`. Only a `401` or a
  provider's own "invalid key" answer is `rejected`; a timeout, `429`, `5xx`,
  breaker skip or `403` is `unknown`. With TruffleHog on
  (`recon/helpers/js_recon/trufflehog_bridge.py`), only its `Verified: true`
  changes a status, to `validated` with `checked_by: trufflehog`; a
  TruffleHog-only key it did not verify is `unknown` (`skipped` with validation
  off). TruffleHog never writes `rejected`: without a route to the provider its
  check answers as for a dead key. A key it verified skips js_recon's provider
  call, except `validate_firebase` and `validate_google_maps`, which test what
  the key opens. The node-filter catalog keeps the legacy
  `invalid` as an alias (`aliases: {invalid: [rejected, format_invalid]}` on the
  field, expanded in `graph_db/node_filters/evaluate.py`), so saved rules keep
  matching.
- **JS Recon's TruffleHog engine merges by key, never re-keys.**
  `trufflehog_bridge.py` stages the analysed files under
  `/tmp/redamon/js_recon_th_<run>_<id>`, runs `redamon-trufflehog:latest`
  through the broker (`--network none`, or `redamon-trufflehog-net` with key
  validation on) with `TRUFFLEHOG_EXCLUDED_DETECTORS` (33 verifiers that would
  dial a host from the JavaScript; review the list on every TruffleHog
  upgrade). A key both engines found keeps the regex finding's id and gains
  `TruffleHog:<Detector>` in `alternate_names`; a TruffleHog-only key is
  `detection_method: 'trufflehog'`, its id built like a regex one.
  `SUPERSEDED_BY_TRUFFLEHOG` in `patterns.py` (today `Travis CI Token`) drops a
  rule's unconfirmed hits only when the run's status is `ran`. With the switch
  off `_run_analysis` makes no TruffleHog call at all
  (`test_regression_js_recon_trufflehog_off_identical.py`). A run that did not
  complete keeps the earlier TruffleHog-only Secrets of the files it was given
  alive (`trufflehog_kept_alive` in `js_recon_mixin.py`). A stage directory a
  killed run left behind is removed by the orchestrator when it reaps the run
  or sees it complete, by its startup sweep, and by `./redamon.sh purge`.
- **`jsReconTrufflehogEnabled` is on for new projects only.** `db push` would
  add the column as `NOT NULL DEFAULT true`, which fills every existing row.
  `webapp/scripts/add-js-recon-trufflehog-column.mjs` runs before the push in
  both the production entrypoint and the dev command and adds the column with
  `DEFAULT false`, so the push only moves the default; it is a no-op on a fresh
  database and once the column exists, and fails closed.
- **Public client keys.** `PUBLIC_CLIENT_KEY_NAMES` in `patterns.py` is written
  at severity info with `public_client_key`. The same names, lowercased, live in
  `score_model.PUBLIC_CLIENT_KEY_TYPES`, `triage_mixin._PUBLIC_CLIENT_KEY_TYPES`,
  `graph_db/node_filters/normalize.py` and `webapp/src/lib/secrets/publicClientKeys.ts`;
  tests pin all five equal. Readers decide on the flag OR the name, for nodes
  written before the flag.
- **The legacy path (domain discovery off) keeps what it does not run.**
  `_run_pipeline` clears the graph, then `run_domain_group`'s legacy branch
  reloads the previous run's file and re-runs only HTTP probing, resource
  enumeration, AI Surface, JS Recon and vuln_scan on it. Every other recon
  source (Shodan, InternetDB, Netlas, Criminal IP, nmap NSE, GraphQL,
  takeover, VHost/SNI, cache poisoning, WCVS, origin discovery, serialized
  scan) is noted degraded first (`_note_legacy_unrun_sources`), so the prune
  keeps its findings. The branch rebuilds the Domain and Subdomain nodes from
  the file (`_write_legacy_domain_nodes`, synchronous, after the RoE filter,
  which covers `subdomains`, `subdomain_status_map` and `dns.subdomains`),
  resets the graph writer so its background writes land, and drains it before
  the coverage record. The file can carry the previous run's
  `technology_cves` when the CVE lookup does not run this time, and IP
  attribution is not re-run on this path.
- **A stopped scan runs step 3, never step 2.** Python is PID 1 in the recon
  container, so it installs its own SIGTERM handler before anything else
  (`recon/helpers/shutdown.py`, from the top of `main.py` and
  `partial_recon.py`). The handler raises nothing (a `SystemExit` would wait on
  every `with ThreadPoolExecutor`, and partial recon catches it per root); it
  sets a flag and wakes a stopper thread, which signals the run's own processes,
  waits for the queued graph writes (`_drain_graph_writes`) until a deadline
  inside `RECON_STOP_GRACE_S`, runs the sweep once (`sweep_once`, which the
  normal `finally` shares) and exits 143. Once the flag is up,
  `subprocess.Popen` refuses (no new tool), `_graph_update_bg` queues nothing,
  `save_recon_file` parks the thread instead of starting the next phase, a
  batch or a per-root partial loop starts no further group or root, and
  `_prune_recon_findings` refuses: the killed tools returned empty results,
  which would read as "gone".
- **One graph writer at a time, drained before it is read.** `_graph_reset`
  drains a writer still live from a group that raised, and `main()`'s `finally`
  drains before it sweeps, so the sweep sees every write of the run.
- **Scans and applies exclude each other.** A full scan cannot start while an
  "apply to current graph" runs (`describeScanWriters`), and an apply to the
  current graph cannot start while a scan runs. Arming the rules for new scans
  is allowed at any time.

### Per-host coverage stamps (what each host got)

The coverage record above is per run and per org, and lists what was CUT. It
cannot say whether "no Secret on `app.example.com`" means analyzed and clean, JS
Recon off, no JS from the crawler, or the file cap. So the modules that work
per web host also report, for every host they *considered*, one row
`{status, inputs, outputs, reason}`, and their graph writers stamp it on the
matching `BaseURL` as `<module>_at` / `_status` / `_inputs` / `_outputs` /
`_reason` (declared in `graph_db/schema_sections.md`).

| Piece | Where |
|---|---|
| Row vocabulary, `base_url_key` (`https://x` and `https://x:443` are one host) | `recon/helpers/coverage_stamps.py` |
| JS Recon rows | `_js_coverage` in `recon/main_recon_modules/js_recon.py`, in `scan_metadata.coverage` |
| Nuclei rows | `_nuclei_coverage` in `recon/main_recon_modules/vuln_scan.py`, in `vuln_scan.scan_metadata.coverage` |
| The stamp (MATCH only, tenant-scoped, module name from an allowlist) | `stamp_base_url_coverage` in `graph_db/coverage_stamps.py`, called by `update_graph_from_js_recon` and `update_graph_from_vuln_scan` |
| The per-module counts readers use | `COVERAGE_SUMMARY_CYPHER` / `coverage_summary` in the same file: the agent's `/graph/exec` summary op (MCP `graph_summary`) and the in-app `graph_summary` |
| Webapp copy of the vocabulary | `webapp/src/lib/coverageStamps.ts` (node drawer, report, MCP); `tests/test_coverage_stamps_parity.py` holds the three lists equal |

- **Considered.** JS Recon: every host http_probe got a live (< 500) answer
  from, every host it was handed pages on (`resource_enum` URLs, which is how
  partial runs pass their targets), and every host serving a JS candidate; a
  host the RoE exclude is never considered. Nuclei: every host a pass targeted;
  when Nuclei was meant to run but could not start, every live host.
- **Status.** `complete`; `no_input` (no candidate, or every candidate turned
  out not to be JavaScript); `partial` with the reasons (`file cap`, `host
  unreachable`, `analyzer failed or timed out`; `runtime cap`, `nuclei exited
  <code>`); `failed` (all lost, a fatal error, or Nuclei unavailable). A Nuclei
  pass stopped at `NUCLEI_MAX_RUNTIME` leaves all its hosts partial: the run
  never says which targets it reached.
- **Absence.** A module switched off stamps nothing. Readers say "not scanned"
  for a live BaseURL without a module's stamp only when some BaseURL of the
  project carries it, and "coverage not recorded" otherwise (a graph written
  before the stamps, or a module that never ran). A full run rebuilds every
  BaseURL, so stamps describe the latest full run plus partial JS Recon and
  Nuclei runs since; partial JS Recon writes even when it found nothing.
- **Recon Delta.** Every stamp is in `VOLATILE_PROPERTIES`.
- **Follow-ups.** Only JS Recon and Nuclei stamp. `resource_enum`, the security
  checks and the GraphQL, cache and vhost scanners are the obvious next modules,
  and Subdomain / IP nodes the place for host-level modules.

---

## 🎯 Targeting Modes

A project picks one of three targeting modes at creation. The mode is locked
afterwards, and all three run the **same** pipeline.

| Mode | Target | What differs |
| --- | --- | --- |
| **Single Domain** | one root domain plus optional subdomain prefixes | the default; full OSINT and subdomain discovery are available |
| **IP / CIDR** | a list of addresses or ranges | skips domain ownership, subdomain enumeration and domain WHOIS; runs IP WHOIS, and reverse DNS only when its hostname mode records names (below) |
| **Domain batch** | a list of hostnames spanning several domains | groups them by registrable domain and scans each group in turn, in one run; a `*.example.com` entry enumerates that domain instead of scanning it literally |

### IP / CIDR: hostnames on target IPs

Every scanner of an IP-mode run reads the expanded target IPs after the RoE
filter (`metadata.expanded_ips`; the admission helpers in
`recon/helpers/target_admission.py`), and each IP keeps its dashed placeholder
(`recon/helpers/ip_placeholders.py`) in `dns.subdomains`, `subdomains`,
`subdomain_filter` and `ip_to_hostname`, so no tool is handed a real name by
GROUP 1. A reverse-DNS answer is evidence, never a scope entry: its own A/AAAA
can point anywhere. httpx follows redirects with `-fhr` and no `-tls-probe`,
nuclei with `-follow-host-redirects`, JS recon only to admitted hosts, origin
discovery is skipped, GVM takes the IPs only, and nmap runs with `-n`. In IP mode
the NSE vuln set leaves out `http-cross-domain-policy` (`--script "vuln and not
http-cross-domain-policy"`), because that script follows a redirect off the
target address on its own.

What happens to the names seen on the IPs is the project's **Hostnames on target
IPs** policy (`IP_HOSTNAME_MODE` and six more `IP_HOSTNAME_*` settings, validated
by `_resolve_ip_hostname_policy` in `recon/project_settings.py`, which refuses an
unconfirmed `scan_all` and a `record_filter` with no readable include entry):

| Mode | GROUP 1 PTR | Name sources | Scanned names |
| --- | --- | --- | --- |
| `ip_only` (default) | off | none; Shodan rDNS and vhost graph candidates forced off | none |
| `record_only` | every answer | all, recorded | none |
| `record_filter` | every answer | all + passive search of the `*.x` include entries (`recon/helpers/ip_hostnames_expand.py`) | include − exclude, every address a target |
| `scan_all` | every answer | all | every name not on a `shared_edge` IP, every address a target |

`apply_ip_hostname_overrides` (after the stealth profile in `get_settings`)
forces `TLSX_REV_PTR_SNI` off in every mode and `SHODAN_REVERSE_DNS` and
`VHOST_SNI_USE_GRAPH_CANDIDATES` off in `ip_only`; `print_effective_settings`
marks them `(forced by ...)`. The webapp copy is `webapp/src/lib/ipHostnameOverrides.ts`,
pinned by `recon/tests/test_ip_hostname_overrides.py`.

The **hostnames step** (`hostname_step` in `recon/helpers/ip_hostnames.py`, called
by `_ip_hostnames_step` in `main.py` after IP attribution and the Shodan CVE write,
before `should_skip_active_scans`) collects the candidates of every source bound
to the target IP they were seen on (at most 500 per IP and 20,000 per run, live
sources first, the rest counted as `truncated`), evaluates them with the one
selection rule, `recon_settings/ip_hostnames.py` (`evaluate`, mirrored for the
form preview by `webapp/src/lib/ipHostnameFilter.ts`, both pinned by
`tests/fixtures/ip_hostname_vectors.json`), and in the scanning modes resolves
the survivors (A and AAAA, the resolver breaker's canary armed first), keeps a
name only when every address is a target (`address_verdict`), inserts the
selected ones with their pinned answer and scans them through the IP-mode path of
`recon/helpers/late_names.py` (`_scan_pinned`): the pinned answer only fills the
recon dict's DNS block and attaches the ports the port scan found on those target
IPs (no second naabu); httpx is handed the names and resolves them itself, with
no `--resolve`. A post-probe guard drops a row whose address is not a target
(`moved_during_scan`). `update_graph_from_ip_hostnames`
(`graph_db/mixins/recon/ip_hostnames_mixin.py`) writes recorded names as
`ExternalDomain` + `SEEN_ON` and scanned ones as `Subdomain` under their org
`Domain {ip_hostname_org: true}`; `classify_host` admits only
`metadata.ip_mode_hosts`. The log prints one `[*][IpNames]` line per IP and a
total; the recon JSON carries `ip_hostnames.summary`. Names cut by the cap, DNS
off or a resolver outage are noted degraded, so the prune keeps their findings.

VHost & SNI (off by default) tries every recorded name on the target IP it was
seen on, in all three recording modes, whatever the selection decided
(`_ip_mode_names` with `may_send`): only `invalid_name`, `hard_blocked` and
`roe_excluded` (`NEVER_SENT`) are withheld, and no name goes to a `shared_edge`
IP. An exclude entry therefore stops a name from being scanned, not from being
sent as `Host`/SNI to its own target IP; the RoE exclusions keep it off the wire.

Residual risk: a name is checked right before its scan, but the tools resolve it
again and nothing pins them to the checked address, so a DNS change inside that
window of seconds can send a tool to a new address. The post-probe guard discards
such a probe answer and the check repeats every run.

The one name lookup outside this policy is the agent's soft guardrail, which
reverse-resolves the public target addresses at session start and project save in
every mode, `ip_only` included (README.AGENTIC_SYSTEM.md, "Soft Guardrail, LLM Judgment"). The
recon run itself sends nothing name-related in `ip_only`.

Partial recon follows the mode (`recon/partial_recon_modules/ip_hostname_scope.py`):
each run computes the names it may scan once, from the graph with the current
policy and live DNS, and refuses typed names in `ip_only` and `record_only`.

### Domain batch

Paste or upload a flat hostname list. RedAmon groups it and scans the groups one
after another.

**The grouping rule is the registrable domain**, read from the Public Suffix
List with its private section (`tldts` in the webapp, `publicsuffixlist` in
recon; both pinned and bumped together, README.DEV.md 5.8).
`suba.sub3.domain3.com` belongs to `domain3.com`, `foo.example.co.uk` to
`example.co.uk`, `alice.github.io` to itself. The webapp derives the project's
**scope groups** from the stored hostname list on every read
(`webapp/src/lib/domainBatch.ts` + `scopeGroups.ts`, returned as `scopeGroups`
by `GET /api/projects/[id]`); they are never stored. Each group is
`{scanRoot, orgDomain, mode: exact|enumerate, includeRoot, exactHosts}`: an EXACT
group scans exactly its listed hosts (and its scan root only when listed), an
ENUMERATE group runs subdomain discovery under its scan root. A single-domain
project is one such group, whose scan root is the typed target at any depth.

**Scan root vs registrable domain.** A wildcard may sit below its registrable
domain: `*.api.example.com` is an ENUMERATE group with scan root
`api.example.com` and org `example.com`. A wildcard under another wildcard
collapses into the broader one (`*.v1.api.example.com` beside
`*.api.example.com`; the preview notes "covered by"), and a plain line under a
wildcard is seeded into its group. Plain lines of one org that no wildcard
covers form that org's EXACT group, so one org can have several groups
(`*.api.example.com` and `www.example.com` are two groups of `example.com`).

**A `*` entry enumerates that domain.** `*.example.com` (or `*example.com`) is
the one way to run subdomain discovery inside a batch: that group takes the same
FULL DISCOVERY path a single-domain project takes, and every other group in the
same run still scans exactly the hostnames it was given. A plain line under a
wildcard is seeded into its group. The settings toggle can only say whether
enumeration is permitted at all; the per-group decision is the group's `mode`.

**What is refused**, with a reason per line: a public suffix (`co.uk`), a wildcard
on one (`*.co.uk`, `*.github.io`), an IP literal (use IP mode), a malformed
wildcard (`a*.example.com`) and a name that is not a hostname.

**Recon re-validates, and fails closed.** `fetch_project_settings` reads
`scopeGroups` into `SCOPE_GROUPS` (`recon/project_settings.py`,
`_parse_scope_groups`): each name is re-checked against the hostname charset,
and each scan root against recon's own Public Suffix List
(`recon/helpers/public_suffix.py`); a suffix root or a malformed group is
dropped. A batch with no usable group, a single-domain target that is a public
suffix or not a hostname, or a suffix list that fails to import raises
`ScopeRefused` before any tool starts. When the two suffix lists disagree on a
name's org (one is newer), the webapp's org is kept and a warning is logged.
`DOMAIN_BATCH_GROUPS` (the legacy `{rootDomain, prefixes}` shape) is derived from
`SCOPE_GROUPS` for the readers that have not moved; only a webapp that sends no
`scopeGroups` makes recon fall back to the stored record. Each run logs:

```
[*][PSL] publicsuffixlist <pinned version>
[*][Scope] acme.co.uk org=acme.co.uk mode=enumerate root=true exact=0
[*][Scope] example.com org=example.com mode=exact root=false exact=2
```

A wildcard group discovers hosts the list never names, so `MAX_BATCH_HOSTS` and
`MAX_BATCH_GROUPS` stop bounding the run's length. The preview badges the group,
the form warns, and the start-scan dialog repeats the count.

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

**Only the hostnames you list are scanned**, except in a wildcard group.
Subdomain discovery is forced off when no group enumerates, including for a
group that is just a bare root domain. An EXACT group stays exact all the way
through: names a certificate, JS bundle or uncover reveals under its scan root
are never injected as targets (`merge_discovered_hostnames` takes the group's
scope from the recon metadata), uncover adds no IPs for it, and VHost/SNI
fabricates no `{word}.<root>` candidates.

**Root is honoured everywhere.** Without Include Root (a `*.example.com` line
with Root unticked) the scan root itself is no target: it is removed from the
merged host list, `dns.domain` is blanked (it is still resolved, only as the
resolver canary), and port scan, masscan, HTTP probe, TLS/header checks, VHost
and takeover never add it or its addresses.

**Ownership** (when Verify Domain Ownership is on) accepts the token at
`<prefix>.<scan root>` **or** `<prefix>.<registrable domain>`; RoE is checked
first, each name is asked once per run, and a resolver failure fails the group
closed with the resolver's message instead of reading as "no record". The
preview lists both accepted record names per group.

**The DNS resolver latch is per group, not per process**
(`_ResolverBreaker` in `domain_recon.py`). One transient failure that a
re-probe of the canary (the most recent root that answered) confirms opens it,
and the open latch skips this module's lookups, the ownership TXT lookup,
reverse DNS and the certificate-name check. `recheck()` runs at the start of
every `run_domain_group` and of every partial root (`run_per_root`): one
canary probe closes a recovered latch (`[+][DNS] Resolver answering again:
lookups resumed`) or keeps it open and records the DNS gap again for this group
(`[!][DNS] Resolver still down: skipping this group's lookups`). Inside a
group an open latch is probed again after 120 s, doubling up to 1800 s, by one
thread. Each hostname whose lookup is skipped is recorded with
`note_degraded("domain_recon", hosts=[...], host_source="dns")`, so its
findings are kept for every source; and a certificate name that cannot be
resolved is recorded, never injected unchecked (`_resolves_to_routable` fails
closed). Do not call `reset()` per group: it also drops the canary, and with a
dead resolver every lookup would then wait out dnspython's 5 s timeout.

**Org-level work runs once per registrable domain per run** (`recon/helpers/org_work.py`):
WHOIS, Shodan domain DNS, OTX/VirusTotal/Criminal IP domain reports and FOFA
`domain=` are asked for the org by the org's first group that passed RoE and
ownership, and its other groups get a copy (`[*][...] <org>: answered earlier
this run, reused`). SPF/DMARC/DNSSEC and the zone transfer run on the org once,
inside vuln_scan, for the first group of that org that reaches it; when no group
of an org reached them, that org keeps its DNS findings and only those
(`_note_unchecked_dns_orgs`): the rest of `security_check` prunes as usual.
Origin discovery keys its candidate sources on the org only when the org is in
scope (some group's scan root is the org, or ownership was proven at the org),
else on the scan root (`[*][Origin] candidate key: <root> (org not in scope)`).
crt.name asks the org once and keeps names under the scan root; uncover's
`ssl:"<registrant>"` query runs only for a group whose scan root is its org.

**A failing group does not stop the batch.** One unresolvable domain should not
cost you the other nineteen: failures are reported at the end, and the run only
fails outright if every group failed.

**Output.** Each group writes `recon_<project_id>__<scan root>.json`, and the
canonical `recon_<project_id>.json` is rebuilt as the union of them after every
group. Everything downstream (GVM, the project export, the report) reads the
canonical file and sees the whole batch, and a batch stopped part way still
leaves a file that parses. Every recon file (single-domain and IP mode too)
states its scope: `metadata.org_domain`, `metadata.scope_mode` (`exact` |
`enumerate`), `metadata.include_root_domain` (always stamped; a file without
`scope_mode` is an older one and keeps the old default, root included), plus
top-level `scope_groups` (every group of the project, snake-case keys) and
`all_project_roots`. The merged canonical file drops the per-group scalars
(`scope_mode`, `org_domain`, `include_root_domain`, `filtered_mode`,
`wildcard_mode`, `subdomain_filter`) and carries `metadata.org_domains` and
`metadata.scope_groups` instead. A run that skips discovery reads each group's
previous file as its input, so only the files of removed roots are cleared.

**Graph.** One `Domain` per registrable domain: every in-scope host is a
`Subdomain` of its org, a deeper scan root that is a target is
`Subdomain {is_scan_root: true}`, and a host under no scan root is an
`ExternalDomain` even when it shares the org. Each group stamps the coverage
record on its org Domain, merged across the run's groups of that org
(`recon_coverage_roots`). A graph built before this model (a `Domain` named
after an old scan root) refuses partial recon, GVM and AI-attack starts until a
full recon rebuilds it.

**Limits.** 500 hostnames and 50 domain groups per project. A batch holds the
project's single scan slot for as long as it runs, so a very long list is a very
long scan.

Implementation: `_batch_groups()` / `run_domain_batch()` / `run_domain_group(group)` in
`recon/main.py` (a batch group runs on `target_info_from_group`,
`recon/helpers/batch_groups.py`; ownership in `_group_ownership`), grouping in
`webapp/src/lib/domainBatch.ts`, output handling in `recon/helpers/output_paths.py`,
graph scope in `graph_db/mixins/recon/scope.py` (`scan_root_for_host`,
`org_for_scan_root`).

### Authenticated scans: where the session goes

An Authenticated Session profile's headers attach only to hosts in the auth
scope (`recon/helpers/auth_profile.py`, `default_scope_hosts`), built from the
scope groups: an ENUMERATE group gives `*.<scan root>` (its strict subdomains),
an EXACT group gives exactly its listed hosts, and either gives its scan root
only when `includeRoot` is set. A listed single-domain project therefore never
authorises `*.<target>`. RoE exclusions are removed, and a tool that sends one
header set for a whole target file gets no session at all if any host in it is
out of scope.

An explicit `scopeHosts` on the profile only **narrows** that scope
(`resolve_scope_hosts` intersects the two, then applies RoE): `*.example.com` on
a project listing only `www.example.com` resolves to `www.example.com`, and a host
the project does not cover resolves to nothing. The agent's replay and curl and
the webapp's recording default use the same rule (`agentic/scope_groups.py`,
`webapp/src/lib/scopeGroups.ts` `authScopePatterns`).

---

## 🎯 Partial Recon

Partial Recon lets you run any single tool from the pipeline independently, without triggering a full scan. From the Workflow View or section headers, click the play button on any tool to open a modal that shows existing graph data (subdomains, IPs, ports, BaseURLs, endpoints), accepts custom targets, and launches the tool in isolation. Results are merged into the existing Neo4j graph via `MERGE` -- no duplicates. All 23 pipeline tools are supported (including `graphql_scan` -- custom URLs are validated against project scope and injected via `GRAPHQL_ENDPOINTS` -- and `vhost_sni` -- custom subdomains and IPs are validated and injected before probing). The tool runs with the project's saved settings (timeouts, wordlists, API keys). Custom inputs are validated in real time (scope checks, IP/CIDR format, port ranges). See `recon/partial_recon.py` for the implementation.

A partial run applies the Mute Rules that are active on new scans to what it wrote, in a `finally` and with its own start time, exactly as a full run does ([How a Run Ends](#-how-a-run-ends-prune-and-mute-rules)). It prunes nothing. The webapp refuses to start one while an "apply to current graph" is running.

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

All 5 subdomain discovery tools run **concurrently** via `ThreadPoolExecutor(max_workers=5)`. Each tool is a thread-safe function with its own HTTP session. After merging, **Puredns** validates the combined list against public DNS resolvers to remove wildcard and DNS-poisoned entries. DNS resolution is then parallelized with **`DNS_MAX_WORKERS` concurrent workers** (default 80). WHOIS and URLScan run in a separate parallel group alongside discovery.

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

    subgraph DNSPhase["DNS Resolution (DNS_MAX_WORKERS workers, default 80)"]
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
    DNS --> WC[Wildcard control<br/>random-label probe per zone]

    WC --> Subs
    DNS --> IPs
    DNS --> Records
```

| What It Does | Output |
|--------------|--------|
| **WHOIS lookup** | Registrar, creation date, owner info |
| **Subdomain discovery** | Finds subdomains via 5 parallel sources (crt.sh, HackerTarget, Subfinder, Amass, Knockpy) |
| **Wildcard filtering** | Puredns validates subdomains against public DNS resolvers, removes wildcards and DNS-poisoned entries |
| **DNS enumeration** | A, AAAA, MX, NS, TXT, CNAME records (`DNS_MAX_WORKERS` parallel workers, default 80) |
| **Wildcard control** | RedAmon's own check after DNS: drops names that answer only through their zone's wildcard DNS, and stamps the zone |
| **IP resolution** | Maps all discovered hostnames to IPs |

**Puredns can be skipped.** `run_puredns_resolve` returns `(names, status)`:
`"filtered"`, or `"skipped:<reason>"` with the list unchanged. Discovery stores the
status as `metadata.wildcard_filter`. `disabled` (the setting, or Stealth Mode) and
`no_input` are not cuts; `breaker_open`, `no_resolvers`, `no_output`, `timeout`,
`docker_missing` and `error` record a coverage gap (source `puredns`, no prune
effect, shown in the report's Coverage Limitations).

**The wildcard control** (`recon/helpers/wildcard_control.py`) runs whatever
puredns did, so it stands in when puredns was skipped:

- **Zones.** The scan root, plus each deeper parent with at least 5 direct
  candidates; a candidate is checked against its nearest probed zone. Each zone is
  probed with up to 3 random labels (`rdm-<uuid12>.<zone>`) through dnspython and the
  shared `resolver_breaker`; answers mean a wildcard zone, and their union is its
  `wildcard_ips`. Cached per run (`circuit_breaker.run_cache`).
- **The rule.** A candidate is dropped when its own A/AAAA set is non-empty and a
  subset of `wildcard_ips`, unless a non-guessing source listed it AND it has a
  CNAME that is not the wildcard's own. Guessing sources: knockpy with brute force,
  amass with `-brute` (`_guessing_sources`). A name with no address is unresolved,
  not a wildcard match, and is kept. The scan root is never checked.
- **Two entry points.** `filter_discovered` reads discovery's own `resolve_all_dns`
  answers (no extra lookups); `filter_late_names` serves the names added after
  puredns and looks up A/AAAA/CNAME only for names under a wildcard zone:
  `merge_discovered_hostnames` (certificate SANs, tlsx, JS recon, Uncover) and
  `run_tlsx_enrichment`, which lists the dropped SANs as `tlsx.wildcard_dropped` so
  the tlsx writer links no `COVERS_HOST` Subdomain to them (full and partial tlsx).
- **Limits.** At most 3 labels per zone and 50 zones per run; probes one at a time,
  paced to `ROE_GLOBAL_MAX_RPS` when RoE is on (the capper's own rule); an
  RoE-excluded zone is never queried. With `DNS_ENABLED` off the control does not
  run. Stealth Mode keeps DNS on and turns puredns off, so the control is what
  filters there.
- **Never evidence on failure.** A failed probe leaves the zone unknown: nothing
  under it is dropped, and a `wildcard_control` coverage gap is recorded, as for
  the zone cap and for DNS off when puredns did not filter either.
- **The graph.** Probed zones travel as `wildcard_zones` (`{zone: {is_wildcard,
  ips}}`, definite answers only). `update_graph_wildcard_zones` (Domain mixin)
  stamps `is_wildcard_zone` / `wildcard_ips` with MATCH and SET only: the org
  Domain for an org zone, the Subdomain of that name for a deeper one. The domain
  and partial discovery writers call it, and `main._stamp_wildcard_zones` once
  more at the end of each domain group for zones the late names added.

**DNS skipped.** With `resolve=False`, discovery writes every candidate's status as
`"unverified"`, the value uncover and the passive-DNS writers use for names nobody
resolved. `Subdomain.status` is shared with http_probe, which later writes
`"no_http"` or the HTTP code; the readers count "resolved" by a `RESOLVES_TO` edge
(report, Insights) or by `status = 'resolved'` (http_probe's `no_http` demotion),
so an unverified name never counts as resolved.

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
            OA[📄 OpenAPI<br/>Specification import<br/>Declared APIs]
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
| **OpenAPI** | Specification import (never calls a declared operation) | Endpoints and parameters declared in OpenAPI/Swagger documents |
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
| 3 | OpenAPI / manifest / model listing | tool/vision/streaming support, model ids + family, cached spec (only in-document `#/` refs inlined, no I/O) |
| 4 | Julius probe pack (YAML) | confirmed AI `Technology` (vLLM, Ollama, …) |
| 5 | Vector-DB confirmation reads | qdrant / chroma / weaviate / milvus, unauthenticated read exposure |
| 6 / 7 | latency baseline + summary glue | counters, merged model family |

**Input:** `resource_enum.by_base_url` (classified endpoints), `http_probe.by_url`
(AI flags), `port_scan.by_host` (AI + vector-DB ports).
**Output:** `combined_result["ai_surface_recon"]` → graph via
`update_graph_from_ai_surface_recon` (enriches `Endpoint` / `Parameter` /
`Technology`, adds `Vulnerability` nodes). Heavy deps (`mcp`, `yara`,
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

Dedicated GraphQL security scanner -- runs as **GROUP 6 Phase A in parallel with Nuclei, Subdomain Takeover, and VHost & SNI Enumeration** because all four scanners consume `BaseURL` / `Endpoint` / `Technology` / `Subdomain` / `IP` and emit `Vulnerability` nodes but have zero data dependency on each other. Every Phase A tool is handed one `_fan_out_snapshot` of `combined_result`, taken before the first submit, and its `_isolated` variant deep-copies that again, so no thread reads the dict the main thread merges finished answers into.

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
| **graphql-cop (opt-in)** | Docker-in-Docker wrapper around `dolevf/graphql-cop:1.14`. Runs 12 checks per endpoint: field suggestions, GraphiQL/Playground detection, trace mode, GET-method queries/mutations, POST url-encoded CSRF, alias overloading (DoS), batch query (DoS), directive overloading (DoS), circular introspection (DoS), unhandled errors. The `1.14` image does not honor the `-e` flag, so `run_graphql_cop` builds no command while any DoS test is excluded (logged; no `graphql_cop_ran`, earlier findings prune like a switched-off source's); excluding only non-DoS tests runs it and filters their results post-execution. |
| **Authentication** | 5 modes: `bearer`, `cookie`, `header` (custom name), `basic` (base64), `apikey`. Values masked in logs. Same headers propagate to graphql-cop via `-H '{"K":"V"}'` JSON args. |
| **Rate limiting + retries** | Global RPS cap (`GRAPHQL_RATE_LIMIT`, 0-100; `zero_means: unlimited`, and under an RoE ceiling `apply_roe_rate_cap` raises 0 to the ceiling), retry on `429`/`5xx` with exponential backoff (`GRAPHQL_RETRY_COUNT`, `GRAPHQL_RETRY_BACKOFF`), concurrency clamp (1-20). Sequential mode at `concurrency=1`. |
| **Endpoint enrichment** | Updates existing `Endpoint` nodes with capability flags (`graphql_graphiql_exposed`, `graphql_tracing_enabled`, `graphql_get_allowed`, `graphql_field_suggestions_enabled`, `graphql_batching_enabled`) — recorded even on negative results so the graph captures server state explicitly — and `graphql_cop_scanned_at`, the time graphql-cop last ran on the endpoint. The recon JSON's `graphql_cop_ran` flag is what sets that timestamp; the graph does not store the flag. |

**Stealth overrides:** `GRAPHQL_RATE_LIMIT=2`, `GRAPHQL_CONCURRENCY=1`, `GRAPHQL_TIMEOUT=60`, the four DoS-class graphql-cop tests (alias / batch / directive / circular) forced off, and `GRAPHQL_COP_ENABLED=false` (full pipeline and partial recon).

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

📖 **Detailed documentation:** [graph_db/schema_sections.md — GraphQL-specific Endpoint & Vulnerability properties](../../graph_db/schema_sections.md) | **[Wiki: GraphQL Security Testing](https://github.com/samugit83/redamon/wiki/GraphQL-Security-Testing)**

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
        GraphCands[Graph-derived candidates<br/>DNS subdomains, httpx hosts,<br/>TLS SANs, CNAME, co-resident<br/>IP mode: the names recorded on the IP]
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
| **Candidate set build** | Six sources merged: default wordlist (2,471 entries shipped in-image), custom wordlist setting, DNS subdomains resolving to the IP, httpx-known hosts on the IP, TLS SAN list per-URL, and CNAME/co-resident external domains. In IP mode the graph sources are the hostnames the hostnames step recorded on that IP (`_ip_mode_names`: only on an IP they were seen on, never on a `shared_edge` IP, none without IP attribution, none in `ip_only`), and there is no apex, so neither the default wordlist nor a bare prefix is used. UTF-8 BOM auto-handled for Windows-edited overrides. Hostname validation uses `\Z` to block newline-injected hostnames from corrupting `--resolve` syntax. |
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

📖 **Detailed documentation:** [graph_db/schema_sections.md -- VHost/SNI Vulnerability properties + Subdomain/IP enrichment](../../graph_db/schema_sections.md) | **[Wiki: VHost & SNI Enumeration](https://github.com/samugit83/redamon/wiki/VHost-and-SNI-Enumeration)**

---

### Module 5e: `route_exposure`

Requests the routes recon found, and routes it generates, without credentials, and again
logged in where the project's authentication profile covers the host. Runs in GROUP 6
Phase A beside Nuclei and the other active scanners, after resource_enum and JS Recon have
landed. Toggle: `ROUTE_EXPOSURE_ENABLED` (default `false`). Code: `recon/route_exposure/`.

| Stage | What it does |
| --- | --- |
| Harvest | One route per (base URL, path, GET) from resource_enum (with its OpenAPI security, tags and declared-only flag and a discovery tool's 401/403), JS Recon's endpoints and http_probe's pages. An API that the bundle defining a client-side router route calls under that route's first segment is tagged `client_gated` (a partial run rebuilds that pairing from the graph's JS file → Endpoint edges). Templated, static, auth-flow and state-changing paths (`logout`, `delete`, `reset`, ... as whole tokens) are never kept; a POST-only route is skipped. |
| Generate | Seed paths (internal, admin and debug, 60 per host), `.git`/`.svn`/`.hg`/`.env`/`web.config` at each base and top-level folder (30), backup variants of server-side files plus root archives and dumps (40, read with HEAD then `Range: bytes=0-1023`), older API versions (3 per route), siblings of API routes (`/export`, `/all`, `/list`, the collection, an inserted `admin`/`internal`; 6 per route, 100 per host), framework paths from the host's technologies (Spring actuator, Laravel Ignition, Django and Rails debug routes; 30; a heap dump HEAD only). Each has its own setting. |
| Rank | A deterministic prior score whose reasons are the `auth_expected_by` hints; the floor (score 5 or more, every VCS/env guess) goes first; per-host and total budgets, hosts round-robin. |
| Probe | One process-wide locked pacer (`ROUTE_EXPOSURE_MAX_RPS`, under the RoE ceiling), per-worker sessions that keep no cookie, `verify=False` with the TLS warning silenced, bodies capped at 256 KiB, no redirect followed, the host breaker, the stop flag, capture routing (logged-in requests only for bearer, basic and cookie profiles). One guard for every request and control: the run's own hosts follow the pipeline's address rule, a host seen only in a bundle must pass the probe scope and the attacker-URL rule. |
| Follow-up | One round, never recursive: the routes an open catalog lists (actuator mappings, OpenAPI, the Rails route table; templated routes skipped; 500) and, with `ROUTE_EXPOSURE_CROSS_HOST` (off by default), the paths that hit tried on sibling hosts sharing the page title or technology set (50). |
| Assess | Signatures first (a debug page answers 500; a `/.git/HEAD` signature is followed by a bounded walk to its ref and commit object, inflated to at most 64 KiB, recorded as `git_walk_proof`), then the logged-in GET whatever the anonymous answer was, then the drops (denied, empty, catch-all by a control request sent exactly like the hit, login wall by the page-type prefilter) and the content signals (PII kinds and one count, sensitive key names, secret detector names). A second pass adds `siblings_locked` (same content kind as the locked neighbours), `version_locked` and `vary_auth`. On a personalised logged-in 2xx with a leak signal, two riders: four hostile origins for a credentialed CORS reflection (`cors_misconfig`, `cors_variants`) and the shared-cache headers (`auth_cacheable`). |
| Jev (act) | With `AI_IN_PIPELINE` and each flag: `route_privacy_rank` after the prior score and before the selection, so its answer (`Route.jev_rank`) fills each host's budget after the floor; `route_exposure_wall` and `route_exposure_assess` after the assessment, writing `anon_page_class*` and `route_jev_*` onto the leads, then `_order_leads` puts the most sensitive first and a confident wall or public-content reading last (`recon/helpers/ai_planner/route_*.py`, `recon/route_exposure/scanner.py`). They never drop a lead or a floor route; the graph writer persists the fields, and each answer is also recorded beside the deterministic one under `jev_shadow.<hook>`. |

Output: `combined_result["route_exposure"]` (summary, findings, endpoint_status,
new_endpoints) and, through `update_graph_from_route_exposure`, `Endpoint.anon_status`,
new Endpoints for generated routes that answered with content (never an artifact) and one
`:Vulnerability {source:'route_exposure'}` per finding: leads with
`needs_agent_confirmation` at severity info, findings with their signature's severity. A
failure is noted degraded so the prune keeps last run's findings. Logs are counts only.

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

| Feature | WHOIS | DNS | Shodan | URLScan | Censys | FOFA | OTX | Netlas | VirusTotal | ZoomEye | CriminalIP | Masscan | Naabu | httpx | Katana | Hakrawler | GAU | Kiterunner | OpenAPI | jsluice | Nuclei | GVM |
|---------|-------|-----|--------|---------|--------|------|-----|--------|------------|---------|------------|---------|-------|-------|--------|-----------|-----|------------|---------|---------|--------|-----|
| **Domain Info** | ✅ | ⚠️ | ❌ | ❌ | ❌ | ⚠️ | ⚠️ | ⚠️ | ❌ | ⚠️ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **IP Resolution** | ❌ | ✅ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ❌ | ⚠️ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Subdomain Discovery** | ❌ | ❌ | ⚠️ | ✅ | ❌ | ⚠️ | ❌ | ⚠️ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Port / Service Data** | ❌ | ❌ | ⚠️ | ❌ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ⚠️ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Live URL Check** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Tech Detection** | ❌ | ❌ | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ❌ | ⚠️ | ⚠️ | ⚠️ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ⚠️ | ⚠️ |
| **Endpoint Discovery** | ❌ | ❌ | ❌ | ⚠️ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ⚠️ | ❌ | ❌ |
| **Historical URLs** | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ⚠️ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Threat Reputation** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Passive DNS** | ❌ | ❌ | ⚠️ | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Malware / CVE Intel** | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ |
| **TLS / Certificate** | ❌ | ❌ | ⚠️ | ⚠️ | ✅ | ✅ | ❌ | ✅ | ❌ | ✅ | ⚠️ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Geolocation / ASN** | ❌ | ❌ | ✅ | ⚠️ | ✅ | ✅ | ⚠️ | ✅ | ⚠️ | ✅ | ✅ | ❌ | ❌ | ⚠️ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **API Discovery** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ | ❌ |
| **XSS/SQLi Testing** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ⚠️ |
| **Secret Detection** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ |

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

## ⚙ Key Configuration Parameters

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
docker-compose build
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
├── Dockerfile                # Container build (the redamon-recon image)
├── docker-compose.yml        # Standalone compose (the root docker-compose.yml runs the stack)
├── entrypoint.sh             # Container entrypoint
├── project_settings.py       # 🔗 Settings fetcher (API or built-in defaults)
├── settings_registry.py      # Reads the recon settings registry (recon_settings/registry.json)
├── main.py                   # 🚀 Full-pipeline entry point
├── partial_recon.py          # Partial recon: one tool on demand, inputs from the graph
├── main_recon_modules/       # One module per pipeline tool
│   ├── domain_recon.py       #   Subdomain discovery
│   ├── whois_recon.py        #   WHOIS lookup
│   ├── urlscan_enrich.py     #   URLScan.io OSINT enrichment
│   ├── shodan_enrich.py      #   Shodan / InternetDB enrichment
│   ├── censys_enrich.py      #   Censys, and fofa_, otx_, netlas_, virustotal_, zoomeye_,
│   │                         #   criminalip_, uncover_enrich.py beside it
│   ├── port_scan.py          #   Port scanning (Naabu); masscan_scan.py, nmap_scan.py beside it
│   ├── http_probe.py         #   HTTP probing (+ Wappalyzer); tls_scan.py beside it
│   ├── resource_enum.py      #   Endpoint discovery
│   ├── js_recon.py           #   JavaScript analysis
│   ├── ai_surface_recon.py   #   AI/LLM/MCP/vector-DB surface fingerprinting (Phase 4.5)
│   ├── vuln_scan.py          #   Vulnerability scanning (Nuclei)
│   ├── add_mitre.py          #   MITRE enrichment
│   ├── subdomain_takeover.py, vhost_sni_enum.py, origin_discovery.py,
│   │   supply_chain_recon.py, sca_intel_correlate.py, ip_filter.py
│   └── data/                 #   📦 Cached databases
│       ├── mitre_db/         #     CVE2CAPEC database (CVE year files downloaded at scan time)
│       └── wappalyzer_cache/ #     Technology rules, refreshed by http_probe.py
├── partial_recon_modules/    # Per-tool modules for partial recon
├── helpers/                  # Tool helpers (ai_planner/, js_recon/, openapi/, resource_enum/, supply_chain/)
├── graphql_scan/             # GraphQL probe
├── cache_scan/               # Web cache poisoning probe
├── serialized_scan/          # Serialized-object probe
├── route_exposure/           # Route exposure scan (anonymous vs logged-in routes, exposed files)
├── data/                     # Static data (IANA services, popular npm names)
├── wordlists/                # vhost wordlist
├── tests/                    # pytest suite (runs in the redamon-recon image)
└── output/                   # 📄 Scan results (JSON)
```

The GitHub secret hunt and TruffleHog run in their own images, from
`scanners/github_secret_hunt/` and `scanners/trufflehog_scan/`; the module docs
are in `docs/readmes/` (this folder).

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
