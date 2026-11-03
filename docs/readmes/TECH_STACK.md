# Technology Stack

## Frontend

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

## Backend & API

| Technology | Role |
|-----------|------|
| **FastAPI** | Async Python web framework for the Recon Orchestrator and Agent API |
| **Uvicorn** | ASGI server running both FastAPI services |
| **Pydantic** | Data validation and settings management across all Python services |
| **Docker SDK for Python** | Programmatic container lifecycle management — the Recon Orchestrator uses it to spawn and control recon, GVM, and GitHub hunt containers |
| **SSE (Server-Sent Events)** | Real-time log streaming from recon pipeline and GVM scans to the webapp |
| **WebSocket** | Bidirectional real-time communication between the agent and the webapp chat |

## Plugin Platform

| Technology | Role |
|-----------|------|
| **Plugin runner** (Python 3.11, FastAPI + Uvicorn) | Supervisor that runs third-party plugin code, one worker process per plugin version. Workers start with `python -I -S` and see only the standard library, the plugin SDK and the plugin's own `vendor/` folder |
| **plugin-gateway proxy** (Python standard library) | The only door between the internal plugin network and the webapp; built from the runner image |
| **Ed25519** (Node.js `crypto` in the webapp, Python `cryptography` in `redamon-plugins`) | Signature over the exact bytes of the plugin catalog; archives are pinned by SHA-256 |

See [README.PLUGINS.md](README.PLUGINS.md) for the design and [README.PLUGIN_SDK.md](README.PLUGIN_SDK.md) for the plugin author's contract.

## AI & LLM

| Technology | Role |
|-----------|------|
| **LangChain** | LLM application framework — prompt management, tool binding, chain composition |
| **LangGraph** | State machine engine implementing the ReAct (Reasoning + Acting) agent loop |
| **OpenAI** (Direct) | Supported LLM family — GPT-5.2, GPT-5, GPT-4.1. Configure in Global Settings |
| **Anthropic** (Direct) | Supported LLM family — Claude Opus 4.6, Sonnet 4.5, Haiku 4.5. Configure in Global Settings |
| **OpenAI-Compatible** | Any OpenAI-compatible endpoint (Ollama, vLLM, Groq, etc.). Configure in Global Settings |
| **OpenRouter** | Multi-model gateway — access 300+ models through a single API key. Configure in Global Settings |
| **AWS Bedrock** | Managed AWS service — access foundation models (Claude, Titan, Llama, Cohere, etc.) via `langchain-aws`. Configure in Global Settings |
| **Agent in the Loop** | Not a provider: with `AGENT_IN_THE_LOOP_ENABLED=true` the chat model `loop/mcp` hands every model call of a run to the person's own MCP client (Claude Code, Codex) over the inbound MCP server; no key needed |
| **Tavily** | AI-powered web search used by the agent for CVE research and exploit intelligence |
| **Model Context Protocol (MCP)** | Standardized protocol for tool integration — the agent calls security tools through MCP servers |
| **LangChain AWS** | AWS Bedrock integration — `ChatBedrockConverse` for Bedrock foundation models |
| **LangChain MCP Adapters** | Bridges LangChain tool interface with MCP server endpoints |
| **Text-to-Cypher** | LLM-powered natural language to Neo4j Cypher query translation |

## Databases

| Technology | Role |
|-----------|------|
| **Neo4j** (Community Edition) | Graph database — stores the entire attack surface as an interconnected knowledge graph; every node type and relationship is declared in `graph_db/schema_sections.md` |
| **APOC** | Neo4j plugin providing advanced procedures and functions for graph operations |
| **PostgreSQL** (v16) | Relational database — stores project settings, user accounts, and configuration data |
| **Prisma** | TypeScript ORM for PostgreSQL — schema management, migrations, and type-safe queries |
| **Redis** | In-memory cache and message queue used within the GVM vulnerability scanning stack |

## Security & Penetration Testing Tools

| Tool | Category | Role |
|------|----------|------|
| **Kali Linux** | Base Platform | Penetration testing distribution used as the base image of the `kali-sandbox` (MCP tool) container; the recon image is `python:3.11-slim-bookworm` |
| **Metasploit Framework** | Exploitation | Exploit execution, payload delivery, Meterpreter sessions, auxiliary scanners, and post-exploitation |
| **Naabu** | Port Scanning | Fast SYN/CONNECT port scanner from ProjectDiscovery |
| **Nmap** | Network Scanning | Network mapper for deep service detection, OS fingerprinting, and NSE vulnerability scripts — exposed as a dedicated MCP server |
| **Nuclei** | Vulnerability Scanning | Template-based scanner with 9,000+ community templates + custom template upload — DAST fuzzing, CVE detection, misconfiguration checks |
| **Httpx** | HTTP Probing | HTTP/HTTPS probing, technology detection, TLS inspection, and response metadata extraction |
| **Katana** | Web Crawling | Active web crawler with JavaScript rendering — discovers URLs, endpoints, forms, and parameters |
| **GAU** (GetAllUrls) | Passive Recon | Passive URL discovery from Wayback Machine, Common Crawl, AlienVault OTX, and URLScan.io |
| **ParamSpider** | Parameter Mining | Passive URL parameter discovery from Wayback Machine CDX API — returns only parameterized URLs for fuzzing |
| **Kiterunner** | API Discovery | API endpoint brute-forcer using real-world Swagger/OpenAPI-derived wordlists |
| **Subfinder** | Subdomain Discovery | Passive subdomain enumeration using 50+ online sources (certificate logs, DNS databases, web archives) |
| **Knockpy** | Subdomain Discovery | Active subdomain brute-forcing tool |
| **Wappalyzer** | Fingerprinting | Technology fingerprinting engine with 6,000+ detection rules |
| **Interactsh** | Out-of-Band Detection | Callback server for detecting blind vulnerabilities (SSRF, XXE, blind SQLi) |

## Vulnerability Assessment

| Technology | Role |
|-----------|------|
| **GVM / OpenVAS** (Greenbone) | Network-level vulnerability scanner with 170,000+ Network Vulnerability Tests (NVTs) |
| **ospd-openvas** | OpenVAS scanner engine — executes protocol-level probes against target services |
| **gvmd** | GVM daemon — orchestrates scans, manages configurations, and exposes the GMP API |
| **GitHub Secret Hunter** | Custom scanner using 40+ regex patterns and Shannon entropy analysis to detect leaked credentials in GitHub repositories |

## Data Sources & Threat Intelligence

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

## Infrastructure & DevOps

| Technology | Role |
|-----------|------|
| **Docker** (Engine 28.0.0+) | Container runtime — every component runs containerized with zero host dependencies |
| **Docker Compose** (v2) | Multi-container orchestration — defines and manages the entire 12+ container stack |
| **Docker-in-Docker (DinD)** | Architecture pattern allowing the Recon Orchestrator to spawn ephemeral scan containers |
| **Python** (3.11, 3.12) | Core language for all backend services. On 3.11 (each Dockerfile's `FROM python:3.11-slim...`): the agent, recon pipeline, recon orchestrator, plugin runner, supply-chain scanner and analyzer. On 3.12: the GVM scanner, GitHub hunter, TruffleHog, AI attack-surface, capture proxy, BadDNS and Docker broker images. The Kali sandbox runs whatever Python `kalilinux/kali-rolling:latest` ships |
| **Node.js** (v22) | JavaScript runtime for the Next.js webapp |
| **Go** (1.25) | Build environment for compiling ProjectDiscovery tools (Naabu, Nuclei) from source |
| **Bash / Shell** | Container entrypoint scripts, tool orchestration, and automation |

## Protocols & Communication

| Protocol | Role |
|----------|------|
| **MCP (Model Context Protocol)** | Standardized tool integration — five MCP servers (Network Recon, Nuclei, Metasploit, Nmap, Playwright) running inside the Kali sandbox |
| **SSE (Server-Sent Events)** | Unidirectional real-time streaming for recon logs, GVM scan progress, and GitHub hunt output |
| **WebSocket** | Bidirectional real-time communication for the agent chat interface |
| **Bolt** (Neo4j) | Binary protocol for high-performance Neo4j graph database queries |
| **GMP** (Greenbone Management Protocol) | XML-based protocol for communicating with the GVM daemon |
| **REST / HTTP** | Inter-service API communication between all containers |
