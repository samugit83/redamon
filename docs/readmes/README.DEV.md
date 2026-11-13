# RedAmon — Developer Guide

**Everything you need to understand, develop, and extend RedAmon.**

This guide is the single entry point for developers. It covers the technology stack, system architecture, project layout, how each subsystem works, and the exact commands you need to apply your changes. For deep dives into specific components, follow the links to the dedicated documentation pages listed in the [Documentation Index](#9-documentation-index) at the end.

> **Legal**: This tool is for authorized security testing only. See [DISCLAIMER.md](../../DISCLAIMER.md).

---

## Table of Contents

1. [Technology Stack](#1-technology-stack)
2. [Architecture at a Glance](#2-architecture-at-a-glance)
3. [Project Filesystem Overview](#3-project-filesystem-overview)
4. [How the System Works](#4-how-the-system-works)
   - [Agent System (agentic/)](#41-agent-system-agentic)
   - [CypherFix Agents](#42-cypherfix-agents)
   - [Reconnaissance Pipeline (recon/)](#43-reconnaissance-pipeline-recon)
   - [Webapp (webapp/)](#44-webapp-webapp)
   - [Settings Architecture](#45-settings-architecture)
5. [Development Workflow](#5-development-workflow)
   - [Prerequisites](#51-prerequisites)
   - [First-Time Setup](#52-first-time-setup)
   - [Hot-Reload vs Rebuild](#53-hot-reload-vs-rebuild)
   - [Common Commands](#54-common-commands)
   - [Important Rules](#55-important-rules)
   - [AI-Assisted Coding](#56-ai-assisted-coding)
   - [Several Agent Sessions in One Checkout](#57-several-agent-sessions-in-one-checkout)
   - [Release Step: Public Suffix List Data](#58-release-step-public-suffix-list-data)
6. [Feature Development Checklists](#6-feature-development-checklists)
7. [Debugging & Testing](#7-debugging--testing)
8. [Environment Variables](#8-environment-variables)
9. [Documentation Index](#9-documentation-index)

---

## 1. Technology Stack

Every technology used in RedAmon, organized by layer. Each entry links to its **official documentation** so you can learn how it works.

> For detailed role descriptions of each technology within RedAmon, see [TECH_STACK.md](TECH_STACK.md).

### Frontend

| Technology | Role | Official Docs |
|-----------|------|---------------|
| **Next.js** (v16) | Full-stack React framework — SSR, API routes, webapp | [nextjs.org/docs](https://nextjs.org/docs) |
| **React** (v19) | Component-based UI library | [react.dev](https://react.dev) |
| **TypeScript** | Static typing across the frontend | [typescriptlang.org/docs](https://www.typescriptlang.org/docs) |
| **Prisma** | TypeScript ORM for PostgreSQL | [prisma.io/docs](https://www.prisma.io/docs) |
| **TanStack React Query** | Server state management and caching | [tanstack.com/query](https://tanstack.com/query/latest/docs/framework/react/overview) |
| **TanStack React Table** | Headless table UI primitives | [tanstack.com/table](https://tanstack.com/table/latest/docs/introduction) |
| **React Force Graph** (2D & 3D) | Interactive attack surface graph visualization | [github.com/vasturiano/react-force-graph](https://github.com/vasturiano/react-force-graph) |
| **Three.js** | 3D rendering engine behind 3D graph view | [threejs.org/docs](https://threejs.org/docs) |
| **D3 Force** | Force-directed graph layout algorithms | [d3js.org/d3-force](https://d3js.org/d3-force) |
| **Recharts** | Charting library for analytics dashboards | [recharts.org](https://recharts.org/en-US/api) |
| **Lucide React** | Icon system | [lucide.dev](https://lucide.dev/guide) |
| **React Markdown** | Markdown rendering in agent chat | [github.com/remarkjs/react-markdown](https://github.com/remarkjs/react-markdown) |
| **React Syntax Highlighter** | Code block highlighting | [github.com/react-syntax-highlighter](https://github.com/react-syntax-highlighter/react-syntax-highlighter) |

### AI & Agent

| Technology | Role | Official Docs |
|-----------|------|---------------|
| **LangChain** | LLM application framework — prompts, tool binding, chains | [python.langchain.com/docs](https://python.langchain.com/docs/introduction/) |
| **LangGraph** | State machine engine for the ReAct agent loop | [langchain-ai.github.io/langgraph](https://langchain-ai.github.io/langgraph/) |
| **LangChain MCP Adapters** | Bridges LangChain tools with MCP server endpoints | [github.com/langchain-ai/langchain-mcp-adapters](https://github.com/langchain-ai/langchain-mcp-adapters) |
| **MCP** (Model Context Protocol) | Standardized protocol for tool integration | [modelcontextprotocol.io](https://modelcontextprotocol.io) |
| **Tree-sitter** | AST parsing for CodeFix agent code navigation | [tree-sitter.github.io](https://tree-sitter.github.io/tree-sitter/) |
| **PyGithub** | GitHub API client for CodeFix PR creation | [pygithub.readthedocs.io](https://pygithub.readthedocs.io) |
| **Tavily** | AI-powered web search for CVE research | [docs.tavily.com](https://docs.tavily.com) |
| **LangChain AWS** | AWS Bedrock integration (`ChatBedrockConverse`) | [python.langchain.com/docs/integrations/providers/aws](https://python.langchain.com/docs/integrations/providers/aws/) |

### Backend

| Technology | Role | Official Docs |
|-----------|------|---------------|
| **Python** (3.11, 3.12) | Core language for all backend services; each image's version is its Dockerfile's `FROM` (see [TECH_STACK.md](TECH_STACK.md)) | [docs.python.org/3.11](https://docs.python.org/3.11/) |
| **FastAPI** | Async Python web framework (agent + recon orchestrator) | [fastapi.tiangolo.com](https://fastapi.tiangolo.com) |
| **Uvicorn** | ASGI server for FastAPI services | [uvicorn.org](https://www.uvicorn.org) |
| **Pydantic** | Data validation and settings management | [docs.pydantic.dev](https://docs.pydantic.dev) |
| **Docker SDK for Python** | Programmatic container lifecycle management | [docker-py.readthedocs.io](https://docker-py.readthedocs.io) |
| **HTTPX** | Async HTTP client for inter-service communication | [www.python-httpx.org](https://www.python-httpx.org) |

### Databases

| Technology | Role | Official Docs |
|-----------|------|---------------|
| **PostgreSQL** (v16) | Relational DB — users, projects, settings, conversations | [postgresql.org/docs/16](https://www.postgresql.org/docs/16/) |
| **Neo4j** (v5 Community) | Graph DB — attack surface knowledge graph | [neo4j.com/docs](https://neo4j.com/docs/) |
| **Neo4j APOC** | Advanced graph procedures and functions | [neo4j.com/labs/apoc](https://neo4j.com/labs/apoc/) |
| **Neo4j Python Driver** | Python client for Cypher queries | [neo4j.com/docs/python-manual](https://neo4j.com/docs/python-manual/current/) |
| **Redis** | In-memory cache within the GVM scanning stack | [redis.io/docs](https://redis.io/docs/) |

### Security & Penetration Testing Tools

| Tool | Category | Official Docs |
|------|----------|---------------|
| **Metasploit Framework** | Exploitation & post-exploitation | [docs.metasploit.com](https://docs.metasploit.com) |
| **Nmap** | Network scanning & service detection | [nmap.org/docs](https://nmap.org/docs.html) |
| **Nuclei** | Template-based vulnerability scanning | [docs.projectdiscovery.io/nuclei](https://docs.projectdiscovery.io/tools/nuclei/overview) |
| **Naabu** | Fast SYN/CONNECT port scanner | [docs.projectdiscovery.io/naabu](https://docs.projectdiscovery.io/tools/naabu/overview) |
| **Httpx** | HTTP/HTTPS probing & tech detection | [docs.projectdiscovery.io/httpx](https://docs.projectdiscovery.io/tools/httpx/overview) |
| **Katana** | Web crawler with JS rendering | [docs.projectdiscovery.io/katana](https://docs.projectdiscovery.io/tools/katana/overview) |
| **GAU** (GetAllUrls) | Passive URL discovery | [github.com/lc/gau](https://github.com/lc/gau) |
| **Kiterunner** | API endpoint brute-forcer | [github.com/assetnote/kiterunner](https://github.com/assetnote/kiterunner) |
| **GVM / OpenVAS** | Network vulnerability scanner (170k+ NVTs) | [greenbone.github.io/docs](https://greenbone.github.io/docs/) |
| **Hydra** | Brute-force credential testing | [github.com/vanhauser-thc/thc-hydra](https://github.com/vanhauser-thc/thc-hydra) |
| **SQLMap** | Automated SQL injection detection | [sqlmap.org](https://sqlmap.org) |
| **Interactsh** | Out-of-band vulnerability detection | [github.com/projectdiscovery/interactsh](https://github.com/projectdiscovery/interactsh) |
| **Knockpy** | Active subdomain brute-forcing | [github.com/guelfoweb/knock](https://github.com/guelfoweb/knock) |
| **Wappalyzer** | Technology fingerprinting (6000+ rules) | [github.com/chorsley/python-Wappalyzer](https://github.com/chorsley/python-Wappalyzer) |

### LLM Providers

Configured **per-user** in the webapp UI (`/settings`), not in `.env`.

| Provider | Official Docs |
|----------|---------------|
| **OpenAI** (GPT-5.2, GPT-5, GPT-4.1) | [platform.openai.com/docs](https://platform.openai.com/docs) |
| **Anthropic** (Claude Opus 4.6, Sonnet 4.5, Haiku 4.5) | [docs.anthropic.com](https://docs.anthropic.com) |
| **AWS Bedrock** (Claude, Titan, Llama, Cohere) | [docs.aws.amazon.com/bedrock](https://docs.aws.amazon.com/bedrock/) |
| **OpenRouter** (300+ models via single API key) | [openrouter.ai/docs](https://openrouter.ai/docs) |
| **Ollama** (local models) | [ollama.com](https://ollama.com) |
| **vLLM** (local models) | [docs.vllm.ai](https://docs.vllm.ai) |
| **LM Studio** (local models) | [lmstudio.ai](https://lmstudio.ai) |
| **OpenAI-Compatible** (any endpoint) | Supports any server implementing the OpenAI API format |

OpenAI-compatible (Ollama) providers expose an optional reasoning control in **Global Settings → LLM Providers**. The webapp persists the enabled state and selected `low`, `medium`, `high`, or `max` effort per provider. When enabled, the agent forwards the value as `reasoning_effort` through the OpenAI-compatible chat-completions API; when disabled it sends nothing, preserving the model's default. `max` is available for models that support it, while models with binary thinking may treat effort levels identically. Enabling reasoning on a model without the thinking capability makes the endpoint reject the request with a 400 (`"<model>" does not support thinking`); `retry_llm_call` self-heals this by dropping `reasoning_effort` and retrying once, so a misconfigured provider degrades gracefully instead of failing every call.

**Agent in the Loop** (`loop/mcp`) is not a provider: with `AGENT_IN_THE_LOOP_ENABLED=true` it appears in the chat model picker, and every model call of a chat run becomes a step that the person's own agent (Claude Code, Codex) answers over the MCP server. It needs no provider key and works only in chat runs; every other model picker hides it and every builder outside a chat run refuses it (`loop_model_not_supported_here`). Rules for new model call sites: the `agent-in-the-loop` skill; setup: the wiki page `Agent-in-the-Loop`.

Turning it off is the switch alone. Before **reverting** its code, reset every project and user row still on a `loop/` model first (the SQL block under "Turning it off for good" in [README.MCP.SERVER.md](README.MCP.SERVER.md#9-agent-in-the-loop)), or `parse_model_provider` would route `loop/mcp` to OpenAI with the user's key.

### Infrastructure

| Technology | Role | Official Docs |
|-----------|------|---------------|
| **Docker** | Container runtime — every component is containerized | [docs.docker.com](https://docs.docker.com) |
| **Docker Compose** (v2) | Multi-container orchestration | [docs.docker.com/compose](https://docs.docker.com/compose/) |
| **Node.js** (v22) | JavaScript runtime for the Next.js webapp | [nodejs.org/docs](https://nodejs.org/docs/latest-v22.x/api/) |
| **Go** (1.22) | Build environment for ProjectDiscovery tools (compiled from source) | [go.dev/doc](https://go.dev/doc/) |

---

## 2. Architecture at a Glance

RedAmon is a fully Dockerized system: the compose services listed below talk over the networks in the table after the diagrams.

### Service Topology

```
Browser ──→ Webapp (Next.js :3000) ──WebSocket──→ Agent (FastAPI :8080, exposed :8090)
                │                                       │
                │ REST+SSE                              │ MCP Protocol
                ▼                                       ▼
        Recon Orchestrator (:8010)              Kali Sandbox (MCP Servers)
                │                               ├── Network Recon (:8000)
                │ Docker SDK                    ├── Nuclei (:8002)
                ▼                               ├── Metasploit (:8003)
        Ephemeral Containers                    ├── Nmap (:8004)
        ├── Recon Pipeline                      └── Playwright (:8005)
        ├── GVM/OpenVAS Scanner
        ├── GitHub Secret Hunter
        └── TruffleHog Secret Scanner

                    ┌─────────────┐     ┌──────────────┐
                    │ PostgreSQL  │     │    Neo4j      │
                    │   :5432     │     │ :7474 / :7687 │
                    └──────┬──────┘     └──────┬───────┘
                           │                   │
            Used by: Webapp (Prisma)    Used by: Recon, Agent, Webapp
            Stores: users, projects,    Stores: attack surface graph
            settings, conversations,    (labels and relationships:
            remediations, reports        graph_db/schema_sections.md)
```

The plugin platform ([README.PLUGINS.md](README.PLUGINS.md)) adds two more services, which reach
the rest of the stack only through each other:

```
Webapp ──runner key──→ plugin-gateway :7072 ──→ plugin-runner :7080 ──spawns──→ plugin workers
   ▲                                                                                │
   └── /api/plugin-gateway/v1/* ←── plugin-gateway :7071 ←──────── call token ──────┘
```

The agent never calls plugin code: a plugin change a person approved reaches it as data in its
settings fetch.

### Networks

| Network | Subnet | Purpose |
|---------|--------|---------|
| **`redamon`** (`redamon-network`) | bridge (default) | Inter-service communication for webapp, agent, worker, databases |
| **`orchestrator-net`** (`redamon-orchestrator-net`) | bridge | **Isolation network** for the privileged recon-orchestrator. Shared only with the webapp (multi-homed) and the on-demand Ollama judge, so a compromised worker cannot reach the orchestration API. |
| **`pentest-net`** | 172.28.0.0/16 | Isolated scanning network — Kali sandbox, MCP tools, and target containers (guinea pigs) |
| **`codefix-net`** (`redamon-codefix-net`) | bridge, auto subnet | CodeFix build sandboxes only: NAT egress so builds can fetch dependencies, and no RedAmon service on it. The orchestrator creates it on demand |
| **`plugins-net`** (`redamon-plugins-net`) | bridge, `internal` | Plugin platform only: the plugin runner and the plugin-gateway proxy. No route out |
| **`plugins-edge`** (`redamon-plugins-edge`) | bridge, `internal` | Plugin platform only: the plugin-gateway proxy and the webapp, which joins it through `docker-compose.plugins.yml` |

> **Worker isolation.** The `recon-orchestrator` holds the Docker socket and is
> the privileged component. It is **not** on `redamon`; it sits alone on
> `orchestrator-net` with only the webapp and the Ollama judge, and its host port
> is bound to `127.0.0.1`. The `kali-sandbox` worker therefore has no path to it
> (DNS `NXDOMAIN` + the gateway back-door is closed). The worker is not given the
> `INTERNAL_API_KEY`, so a compromised worker holds no master credential. The
> recon containers the orchestrator spawns receive a filtering broker socket
> (not the raw Docker socket), so they can only create the known tool images and
> cannot mount the host filesystem or run privileged.

> **Plugin isolation.** Plugin code runs in `plugin-runner`, alone on `plugins-net` with the
> `plugin-gateway` proxy, which never joins `redamon`. The proxy passes only the webapp's
> `/api/plugin-gateway/v1/*` and `/api/plugin-runner/v1/*` towards the webapp and the
> supervisor's `/runner/v1/*` towards the runner, so a worker reaches neither Postgres, Neo4j,
> the agent nor the internet. Both plugin networks set `gateway_mode_ipv4: isolated`, which
> needs Docker Engine 28.0.0 or newer and stops a worker reaching the host through the bridge
> address. `redamon.sh` creates both networks and the plugins volume; a plain
> `docker compose up -d` creates neither.

### Docker Compose Services

Every service in `docker-compose.yml`; host ports are the defaults of their `${..._PORT:-...}` variables.

| Service | Container Name | Port | Role |
|---------|---------------|------|------|
| `webapp` | redamon-webapp | 3000 | Next.js frontend + backend API |
| `agent` | redamon-agent | 8090 (→8080 internal) | AI agent (LangGraph + FastAPI WebSocket) |
| `kb-refresh` | redamon-kb-refresh | — | Opt-in knowledge-base refresher on the agent image (profile: kb-refresh) |
| `recon-orchestrator` | redamon-recon-orchestrator | 8010 (127.0.0.1) | Spawns the recon, GVM, GitHub-hunt, TruffleHog, supply-chain and AI-surface containers via Docker SDK |
| `docker-broker` | redamon-docker-broker | internal | Filtering Docker socket proxy the spawned recon containers get instead of the raw socket |
| `kali-sandbox` | redamon-kali | 8000, 8002–8005 (127.0.0.1) | The five MCP tool servers (network-recon, nuclei, metasploit, nmap, playwright; `SERVERS` in `mcp/servers/run_servers.py`); also the progress streams (8013, 8014), ngrok API (4040) and tunnel manager (8015) on 127.0.0.1, the terminal (8016) on the Docker network only, and 4444 open for direct reverse shells |
| `postgres` | redamon-postgres | 5432 (127.0.0.1) | PostgreSQL database |
| `neo4j` | redamon-neo4j | 7474, 7687 (127.0.0.1) | Neo4j graph database |
| `gvmd` | redamon-gvm-gvmd | internal | GVM daemon (vulnerability scanner) |
| `gvm-ospd` | redamon-gvm-ospd | internal | OpenVAS scanner engine |
| `gvm-redis`, `gvm-postgres` | redamon-gvm-redis, redamon-gvm-postgres | internal | GVM's own Redis and PostgreSQL |
| `gvm-vt`, `gvm-notus-data`, `gvm-scap-data`, `gvm-cert-bund-data`, `gvm-dfn-cert-data`, `gvm-data-objects`, `gvm-report-formats`, `gvm-gpg-data` | redamon-gvm-* | — | GVM feed data containers |
| `capture-proxy`, `traffic-ingest` | redamon-capture-proxy, redamon-traffic-ingest | 8888 (127.0.0.1, proxy) | HTTP Traffic Capture, one image (profile: capture; started on demand by the orchestrator) |
| `recon`, `vuln-scanner`, `github-secret-hunter`, `trufflehog-scanner`, `wcvs`, `codefix-sandbox`, `supply-chain-analyzer`, `supply-chain`, `baddns-scanner`, `ai-attack-surface` | (profile: tools) | — | Tool images: built, never started by compose; a container is spawned per scan |
| `plugin-runner` | redamon-plugin-runner | internal (7080) | Runs plugin code, one worker process per plugin version (profile: plugins; started only by `redamon.sh`) |
| `plugin-gateway` | redamon-plugin-gateway | internal (7071, 7072) | The only door between `plugins-net` and the webapp (same image as `plugin-runner`, profile: plugins) |

> For full Mermaid diagrams, container architecture, and data flow pipelines, see [ARCHITECTURE.md](ARCHITECTURE.md).

---

## 3. Project Filesystem Overview

A selection of the files a developer reaches for first; `git ls-files <folder>` lists the rest.

```
redamon/
├── agentic/                        # AI agent orchestrator (Python 3.11 / LangGraph / FastAPI)
│   ├── api.py                      #   FastAPI entry point, mounts WebSocket endpoints
│   ├── plugin_api.py               #   Master-key /plugins/* routes: skill parts, proposal validation, plugin model calls
│   ├── orchestrator.py             #   Main ReAct agent loop: think → select tool → observe → repeat
│   ├── state.py                    #   LangGraph AgentState (execution trace, todos, phases, messages)
│   ├── tools.py                    #   Tool managers: MCP, Neo4j (Cypher), WebSearch, Shodan, GoogleDork
│   ├── websocket_api.py            #   Session management, streaming events, approval flow
│   ├── project_settings.py         #   Fetches settings from webapp API, falls back to DEFAULT_AGENT_SETTINGS
│   ├── logging_config.py           #   Structured logging setup for the agent container
│   ├── utils.py                    #   Shared utility functions
│   ├── prompts/                    #   All LLM prompt templates
│   │   ├── base.py                 #     Core system prompt + tool availability tables
│   │   ├── classification.py       #     Attack path classification (CVE, brute force, phishing, etc.)
│   │   ├── tool_registry.py        #     Single source of truth for tool definitions
│   │   ├── skill_parts.py          #     Registry of the built-in skill parts a plugin may override
│   │   ├── skill_part_seam.py      #     Renders an approved override of a part, or its factory text
│   │   ├── cve_exploit_prompts.py  #     CVE research & exploitation guidance
│   │   ├── brute_force_credential_guess_prompts.py  # Credential attack strategy
│   │   ├── phishing_social_engineering_prompts.py   # Social engineering tactics
│   │   ├── post_exploitation.py    #     Post-exploitation phase guidance
│   │   ├── stealth_rules.py        #     Stealth mode constraints
│   │   └── unclassified_prompts.py #     Generic/unclassified attack prompts
│   ├── orchestrator_helpers/       #   Supporting modules for the orchestrator
│   │   ├── nodes/                  #     LangGraph node implementations
│   │   │   ├── initialize_node.py  #       Session + LLM + MCP initialization
│   │   │   ├── think_node.py       #       LLM reasoning step
│   │   │   ├── execute_tool_node.py #      Tool execution + result handling
│   │   │   ├── execute_plan_node.py #      Multi-step plan execution
│   │   │   ├── generate_response_node.py # Final response formatting
│   │   │   └── approval_nodes.py   #      Human-in-the-loop approval + question gates
│   │   ├── llm_setup.py            #     LLM initialization with project settings, prefix-routed model ids
│   │   ├── model_providers.py      #     Lists the models each configured provider offers, for the frontend
│   │   ├── guardrail.py            #     Soft (LLM) scope guardrail — prevents scanning unauthorized targets
│   │   ├── hard_guardrail.py       #     Deterministic, non-disableable target blocklist
│   │   ├── roe_gate.py             #     RoE + recon-budget gate every executor path asks before a tool runs
│   │   ├── web_sources.py          #     Pure web helpers shared by Tradecraft and URL import (links, GitHub URLs, sitemaps, HTML/PDF text)
│   │   ├── chat_persistence.py     #     Saves conversation history to PostgreSQL via webapp API
│   │   ├── report_summarizer.py    #     Generates pentest report summaries from agent sessions
│   │   ├── streaming.py            #     WebSocket event emission (status, thoughts, tool output)
│   │   ├── phase.py                #     Phase classification & transition logic
│   │   ├── chain_graph_writer.py   #     Neo4j attack chain recording (EvoGraph)
│   │   ├── parsing.py              #     LLM output parsing (JSON extraction)
│   │   ├── config.py               #     Orchestrator configuration constants
│   │   ├── json_utils.py           #     JSON serialization helpers
│   │   └── debug.py                #     Debug utilities
│   ├── workspace_import/           #   Folder/archive uploads and URL imports into the Agent Workspace
│   │   ├── extract.py              #     safe_extract: hand-written extraction, real-byte caps, no links or devices
│   │   ├── staging.py              #     /workspace/.staging op dirs, disk-reservation ledger, boot swap recovery
│   │   ├── place.py                #     Atomic placement: Keep both / Replace (crash-safe swap) / Fail
│   │   ├── busy.py                 #     Paths a running import will replace; drawer and fs_* writes refuse them
│   │   ├── executor.py             #     Bounded thread pool for import CPU/disk work (never the default pool)
│   │   ├── downloads.py            #     Streaming file and archive downloads (attachment + nosniff)
│   │   ├── http_routes.py          #     Master-key /workspace/* routes of the package (job status, ...)
│   │   └── errors.py / limits.py   #     Failure codes with fixed sentences; env caps and the URL-import switch
│   ├── cypherfix_triage/           #   Vulnerability triage agent
│   │   ├── orchestrator.py         #     Hybrid orchestrator: static Cypher + ReAct analysis
│   │   ├── state.py                #     TriageFinding, RemediationDraft, TriageState
│   │   ├── tools.py                #     Neo4j query manager + Tavily web search
│   │   ├── websocket_handler.py    #     WebSocket endpoint + streaming callback
│   │   ├── project_settings.py     #     CypherFix-specific settings loader
│   │   └── prompts/                #     Triage system prompt + 9 Cypher queries
│   └── cypherfix_codefix/          #   Automated code fix agent
│       ├── orchestrator.py         #     Pure ReAct while-loop (Claude Code pattern)
│       ├── state.py                #     DiffBlock, CodeFixSettings, CodeFixState
│       ├── websocket_handler.py    #     WebSocket endpoint + streaming callback
│       ├── project_settings.py     #     CodeFix settings loader
│       ├── prompts/                #     Dynamic system prompt + diff format instructions
│       └── tools/                  #     11 code-aware tools (read, edit, grep, glob, bash, symbols, etc.)
│
├── recon_orchestrator/             # Container lifecycle manager (Python 3.11 / FastAPI)
│   ├── api.py                      #   /recon, /gvm, /github-hunt, /trufflehog endpoints with SSE streaming
│   ├── container_manager.py        #   Docker SDK: spawn containers, health checks, log streaming, cleanup
│   └── models.py                   #   Pydantic request/response models (ReconState, GvmState, etc.)
│
├── recon/                          # Reconnaissance pipeline (redamon-recon image, spawned per scan by the orchestrator)
│   ├── main.py                     #   Full-pipeline entry point — runs the phases in order
│   ├── partial_recon.py            #   Partial-recon entry point (one tool on demand, inputs from the graph)
│   ├── entrypoint.sh               #   Docker entrypoint script
│   ├── project_settings.py         #   Fetches scan settings from webapp API
│   ├── main_recon_modules/         #   One module per pipeline tool
│   │   ├── domain_recon.py         #     DNS, crt.sh, HackerTarget, Knockpy subdomain enumeration
│   │   ├── whois_recon.py          #     WHOIS lookups
│   │   ├── port_scan.py            #     Naabu SYN/CONNECT scan (masscan_scan.py beside it)
│   │   ├── http_probe.py           #     Httpx probing, Wappalyzer tech detection, TLS inspection
│   │   ├── resource_enum.py        #     Katana web crawling, Kiterunner API discovery, GAU passive URLs
│   │   ├── vuln_scan.py            #     Nuclei template scanning
│   │   ├── shodan_enrich.py        #     Shodan host lookup, reverse DNS, passive CVEs (and the other *_enrich.py)
│   │   └── add_mitre.py            #     MITRE CWE/CAPEC enrichment for discovered CVEs
│   ├── partial_recon_modules/      #   Per-tool modules for partial recon
│   ├── helpers/                    #   Shared helper modules
│   │   ├── target_helpers.py       #     Target parsing and validation
│   │   ├── nuclei_helpers.py       #     Nuclei result parsing
│   │   ├── security_checks.py      #     Security header analysis
│   │   ├── cve_helpers.py          #     CVE lookup and enrichment
│   │   ├── docker_helpers.py       #     Container-aware path resolution
│   │   ├── iana_services.py        #     IANA port/service mapping
│   │   └── resource_enum/          #     Resource enumeration sub-helpers (katana_helpers.py, gau_helpers.py, ...)
│   ├── tests/                      #   Recon test suite
│   ├── data/                       #   Static data files (IANA services, popular npm names)
│   └── Dockerfile                  #   python:3.11-slim-bookworm image, Go tools built in earlier stages
│
├── webapp/                         # Next.js frontend + backend API (TypeScript)
│   ├── src/
│   │   ├── app/                    #   Next.js App Router — pages and API routes
│   │   │   ├── api/                #     Backend REST endpoints
│   │   │   │   ├── projects/       #       CRUD for projects, settings, recon/GVM/github-hunt triggers
│   │   │   │   ├── conversations/  #       Conversation + chat message management
│   │   │   │   ├── remediations/   #       CypherFix remediation CRUD + batch operations
│   │   │   │   ├── reports/        #       Pentest report generation and retrieval
│   │   │   │   ├── models/         #       Available LLM model listing
│   │   │   │   ├── users/          #       User management and settings
│   │   │   │   ├── analytics/      #       Project analytics data
│   │   │   │   ├── graph/          #       Neo4j graph query endpoints
│   │   │   │   ├── agent/          #       Agent-related API endpoints
│   │   │   │   ├── cypherfix/      #       CypherFix-specific API endpoints
│   │   │   │   ├── recon/          #       Recon status and control
│   │   │   │   ├── gvm/            #       GVM scanner status and control
│   │   │   │   ├── github-hunt/    #       GitHub secret hunt control
│   │   │   │   ├── trufflehog/    #       TruffleHog secret scanner control
│   │   │   │   ├── roe/            #       Rules of Engagement management
│   │   │   │   ├── plugins/        #       Plugin platform: Plugins page model, lifecycle, actions, jobs, overrides
│   │   │   │   ├── plugin-gateway/ #       The Gateway plugin code calls (call token only)
│   │   │   │   ├── plugin-runner/  #       The plugin runner's run list (runner key only)
│   │   │   │   ├── internal/plugins/ #     Plugin reconciliation (master internal key)
│   │   │   │   ├── ws/             #       WebSocket proxy endpoints
│   │   │   │   └── health/         #       Health check
│   │   │   ├── projects/           #     Project dashboard pages
│   │   │   ├── graph/              #     Attack surface graph visualization (2D/3D)
│   │   │   ├── settings/           #     Global settings (LLM keys, API keys)
│   │   │   ├── cypherfix/          #     CypherFix remediation dashboard
│   │   │   ├── reports/            #     Report listing and viewing
│   │   │   ├── insights/           #     Analytics, charts, reporting
│   │   │   └── plugins/            #     Plugins page and plugin screens (/plugins/<id>)
│   │   ├── components/             #   React UI components
│   │   │   ├── layout/             #     App shell, sidebar, header
│   │   │   ├── projects/           #     Project-specific UI (settings panels, agent drawer, graph view)
│   │   │   ├── settings/           #     Global settings forms
│   │   │   ├── plugins/            #     Plugin cards and dialogs, UI host primitives, review and versions modals
│   │   │   ├── ui/                 #     Shared primitives (buttons, modals, badges, tables)
│   │   │   └── icons/              #     Custom icon components
│   │   ├── lib/                    #   Shared utilities
│   │   │   ├── prisma.ts           #     Prisma client singleton
│   │   │   ├── websocket-types.ts  #     WebSocket message type definitions
│   │   │   ├── cypherfix-types.ts  #     CypherFix TypeScript types
│   │   │   ├── recon-types.ts      #     Recon pipeline TypeScript types
│   │   │   ├── llmProviderPresets.ts #   LLM provider configuration presets
│   │   │   ├── validation.ts       #     Input validation utilities
│   │   │   ├── plugins/            #     Plugin platform library (see §4.4)
│   │   │   └── report/             #     Report generation utilities
│   │   └── hooks/                  #   React hooks
│   │       ├── useAgentWebSocket.ts #    Agent chat WebSocket connection
│   │       ├── useCypherFixTriageWS.ts # Triage agent WebSocket
│   │       ├── useCypherFixCodeFixWS.ts # CodeFix agent WebSocket
│   │       ├── useReconSSE.ts      #     Recon progress SSE stream
│   │       ├── useGvmSSE.ts        #     GVM scan progress SSE stream
│   │       ├── useGithubHuntSSE.ts #     GitHub hunt progress SSE stream
│   │       ├── useProjects.ts      #     Project CRUD operations
│   │       ├── useConversations.ts #     Conversation management
│   │       ├── useRemediations.ts  #     CypherFix remediation data
│   │       ├── useReports.ts       #     Report management
│   │       ├── useSession.ts       #     User session management
│   │       ├── useUsers.ts         #     User management
│   │       ├── useActiveSessions.ts #    Track active agent sessions
│   │       ├── useReconStatus.ts   #     Recon pipeline status polling
│   │       ├── useGvmStatus.ts     #     GVM scanner status polling
│   │       ├── useGithubHuntStatus.ts #  GitHub hunt status polling
│   │       ├── useChatPersistence.ts #   Chat history persistence
│   │       └── useTheme.ts         #     Dark/light theme toggle
│   ├── server_actions/             #   Next.js server actions
│   │   └── graph_queries.ts        #     Neo4j Cypher queries for graph visualization
│   └── prisma/                     #   Prisma schema (push-based, NOT migration-based)
│       └── schema.prisma           #     Database schema (each Project column is described in recon_settings/registry.yaml)
│
├── mcp/                            # MCP tool infrastructure
│   ├── kali-sandbox/               #   Kali Linux Docker image for MCP servers
│   │   └── Dockerfile              #     Kali image with all security tools pre-installed
│   ├── servers/                    #   MCP server implementations
│   │   ├── network_recon_server.py #     HTTP probing + Naabu port scanning (:8000)
│   │   ├── nuclei_server.py        #     Nuclei vulnerability scanning (:8002)
│   │   ├── metasploit_server.py    #     Metasploit Framework RPC (:8003)
│   │   ├── nmap_server.py          #     Nmap network scanning (:8004)
│   │   ├── playwright_server.py    #     Browser automation (:8005)
│   │   ├── run_servers.py          #     Supervisor that starts the MCP servers in its SERVERS dict
│   │   └── terminal_server.py      #     WebSocket PTY behind the RedAmon Terminal tab (:8016, not an MCP server)
│   ├── nuclei-templates/           #   Nuclei template collection
│   └── docker-compose.yml          #   MCP-specific compose overrides
│
├── graph_db/                       # Neo4j graph layer: client, mixins, schema (schema_keys.py, schema_sections.md)
├── recon_settings/                 # The recon settings registry (registry.yaml) and its generator (build.py)
├── scanners/                       # One folder per scan tool, each its own image
│   ├── gvm_scan/                   #   OpenVAS/GVM vulnerability scanner Python wrapper
│   ├── github_secret_hunt/         #   GitHub credential scanner (40+ regex patterns + Shannon entropy)
│   ├── trufflehog_scan/            #   TruffleHog secret scanner (detector-based credential verification + deep git history)
│   ├── supply_chain_scan/          #   Supply-chain scan (with supply_chain_analyzer/ and supply_chain_common/)
│   ├── capture_proxy/              #   mitmproxy HTTP capture
│   ├── ai_attack_surface_scan/     #   LLM/AI attack-surface scanning
│   └── baddns_scan/  wcvs/  codefix_sandbox/  scan_targets/
├── services/docker_broker/         # Filtering Docker socket proxy the recon containers get instead of the raw socket
├── services/knowledge_base/        # Knowledge base package (baked into the agent image as `knowledge_base`)
├── services/postgres_db/           # Postgres compose file
├── services/plugin_runner/          # Plugin runner + plugin-gateway proxy: one image, two services (plugin platform)
│   ├── supervisor/                 #   FastAPI supervisor on :7080: run list, workers, jobs, logs, data migrations
│   ├── worker/bootstrap.py         #   One worker process per plugin version (python -I -S, own UID, limits)
│   ├── gateway_proxy/              #   The plugin-gateway proxy (:7071 towards the webapp, :7072 towards the runner)
│   ├── sdk/                        #   redamon_plugin_sdk (the package plugin code imports) + contract_cases.json
│   ├── platform_version.py         #   Must equal PLUGIN_PLATFORM_VERSION in the webapp
│   ├── tests/                      #   The plugin_runner test section (image redamon-plugin-runner)
│   └── tests_live/probe.py         #   Isolation probe run by tests/plugins_isolation_live.sh
├── testing/guinea_pigs/            # Intentionally vulnerable test applications (README.GPIGS.md lists them)
├── testing/e2e/                    # Playwright end-to-end tests
├── tests/                          # Repo-root Python tests and the shell suites (tests/*_test.sh)
├── tooling/                        # scripts/, the git hooks (hooks/pre-commit), deploy/
├── skills/                         # Agent skills (this repository's ruleset system)
│
├── docs/readmes/                   # All documentation (you are here)
├── .github/                        # Issue and pull request templates (there is no CI)
├── docker-compose.yml              # Full stack orchestration — all containers, networks, volumes
├── docker-compose.plugins.yml      # Plugin overlay (webapp on plugins-edge + plugins volume); loaded only by redamon.sh
├── redamon-plugins/                # NOT part of this repository: optional local clone of the plugin repository, ignored by .gitignore
├── CONTRIBUTING.md                 # Contribution guidelines and contributor ranks
├── CHANGELOG.md                    # Release history
├── DISCLAIMER.md                   # Legal disclaimer
└── SECURITY.md                     # Security vulnerability reporting
```

**`redamon-plugins/` is a separate repository.** The plugins themselves, their signed catalog
and the tools that pack, sign and validate them live in
[`samugit83/redamon-plugins`](https://github.com/samugit83/redamon-plugins) (branch `master`). A
developer may clone it at the root of this checkout, where `.gitignore` keeps it untracked; its
git commands, commits and pushes are its own. RedAmon never reads that folder at runtime: it
installs plugins from the published catalog or from uploaded files. How to write a plugin is in
[README.PLUGIN_SDK.md](README.PLUGIN_SDK.md).

---

## 4. How the System Works

### 4.1 Agent System (agentic/)

The agent is an autonomous AI pentester built on **LangGraph** implementing the **ReAct (Reasoning and Acting)** pattern.

**How the ReAct loop works:**

1. **Think** — The LLM analyzes the current state, reasons about what to do next, and selects a tool (or generates a final response).
2. **Execute** — The orchestrator executes the selected tool (MCP call, Neo4j query, web search, etc.) and captures the output.
3. **Observe** — The tool result is fed back to the LLM as context for the next reasoning step.
4. This cycle repeats until the task is complete or the max iteration limit is reached (default: 100).

**LangGraph state machine:**

The orchestrator is built as a LangGraph graph with these nodes:

- **`initialize_node`** — Sets up the LLM, loads project settings, establishes MCP connections to the Kali sandbox.
- **`think_node`** — LLM reasoning step. Outputs either a tool call, a multi-step plan, or a text response.
- **`execute_tool_node`** — Runs the selected tool and records the result. Supports parallel execution of independent tools via `asyncio.gather()`.
- **`execute_plan_node`** — Executes a multi-step plan the LLM has produced.
- **`generate_response_node`** — Formats the final response for the user.
- **`approval_nodes`** — Pauses execution and asks the user for approval before dangerous operations. Also handles agent-initiated questions to the user.

Conditional edges route between nodes based on the current phase, tool requirements, and whether approval is needed.

**Phase-based execution:**

The agent operates in three phases, each with its own tool availability and approval requirements:

| Phase | Tools Available | Approval Required |
|-------|----------------|-------------------|
| **Reconnaissance** | Neo4j queries, web search, Shodan, Google Dork, Deep Think | No |
| **Exploitation** | All recon tools + MCP tools (Nmap, Nuclei, Metasploit, Network Recon) | Yes (configurable) |
| **Post-Exploitation** | All tools + Metasploit post modules | Yes (configurable) |

Phase transitions happen automatically — the agent classifies its own actions using the classification prompt and shifts phases when the task requires it.

**Tool execution:**

- **MCP tools** — Security tools (Network Recon, Nuclei, Metasploit, Nmap, Playwright) run in the `kali-sandbox` container and are accessed via the MCP protocol through `langchain-mcp-adapters`. Each server has its own URL in the agent's environment (`MCP_NETWORK_RECON_URL` is `http://kali-sandbox:8000/sse`, and so on for `MCP_NUCLEI_URL`, `MCP_METASPLOIT_URL`, `MCP_NMAP_URL`, `MCP_PLAYWRIGHT_URL`).
- **Native tools** — Neo4j Cypher queries (text-to-Cypher via LLM), Tavily web search, Shodan API, and Google Dork are implemented directly in Python within `tools.py`.

**WebSocket streaming:**

The agent streams events to the frontend in real-time via WebSocket (`/ws/agent`): status updates, reasoning thoughts (including streaming chunks), tool calls with arguments, tool results, approval requests, questions, and final responses.

**Multi-objective support:**

Multiple agent sessions can run in parallel against the same target, each pursuing different attack paths (e.g., one brute-forcing SSH while another exploits a web CVE). Sessions are isolated by `session_id`.

> For the complete WebSocket protocol spec, state diagrams, multi-objective support, RoE guardrails, and EvoGraph attack chain recording, see [README.AGENTIC_SYSTEM.md](README.AGENTIC_SYSTEM.md).

### 4.2 CypherFix Agents

CypherFix bridges the gap between discovering vulnerabilities and fixing them in code. It consists of two independent agents that run inside the same `agent` container:

**Triage Agent** (`cypherfix_triage/`):

Five steps, of which only the last one writes:

1. **Authorize** (no LLM) - `POST /api/internal/triage-runs`, BEFORE reading
   anything. Strict ownership, no activation in progress, no other live run.
2. **Score** (no LLM) - reads the project's fact sets once, then one row per
   finding, and scores each with `score_model.py`: real x exploit x impact x
   reach, into one of four tiers, as a 0-100 number.
3. **Group** (no LLM) - findings that share a fix become one group, by
   deterministic key. The same CVE on three hosts is one group.
4. **Review + remediate** (LLM) - the model corrects the four FACTORS against
   quoted evidence (never a score), and writes the prose for one fix item per
   group. Both calls bind no tools.
5. **Publish** - claims the write with a conditional transition, writes the
   graph in batches guarded by each node's `updated_at`, then upserts the fix
   list by `(projectId, groupKey)` in one transaction.

Steps 2 to 4 are entirely in memory, so a run that is stopped or refused leaves
the previous ranking exactly as it was.

**CodeFix Agent** (`cypherfix_codefix/`):

Replicates **Claude Code's agentic design** — a pure ReAct while-loop where the LLM is the sole controller:

1. Clones the target repository (shallow clone, `--depth 50`), creates a fix branch (`cypherfix/{remediation_id}`).
2. Explores the codebase using 11 code-aware tools: `github_read`, `github_edit`, `github_grep`, `github_glob`, `github_bash`, `github_symbols`, `github_find_definition`, `github_find_references`, `github_repo_map`, `github_write`, `github_list_dir`.
3. Implements targeted fixes with diff blocks sent to the frontend for user approval. Users can accept, reject (with reason), or send guidance messages mid-loop.
4. Commits, pushes (force, to allow reruns), and opens a GitHub pull request (or updates an existing one).

The CodeFix agent ships with a full polyglot runtime: Node.js 20, Python 3.11, Go 1.22, Ruby, Java 17, PHP, .NET 8 — so it can build and test any target repository.

> For the full architecture, tool specs, diff approval flow, and WebSocket protocols, see [README.CYPHERFIX_AGENTS.md](README.CYPHERFIX_AGENTS.md).

### 4.3 Reconnaissance Pipeline (recon/)

The recon pipeline runs a 6-phase sequential scan inside an ephemeral Docker container:

| Phase | Module | What it does |
|-------|--------|-------------|
| 1 | `domain_recon.py` + `whois_recon.py` | WHOIS lookup, DNS resolution, subdomain enumeration (crt.sh, HackerTarget, Knockpy) |
| 2 | `port_scan.py` | Naabu SYN/CONNECT port scanning + Shodan InternetDB passive data |
| 3 | `http_probe.py` | Httpx HTTP/HTTPS probing, Wappalyzer tech detection, TLS certificate extraction, security header checks |
| 4 | `resource_enum.py` | Katana web crawling, Kiterunner API discovery, GAU passive URL collection |
| 5 | `vuln_scan.py` + `add_mitre.py` | Nuclei template scanning (9000+ templates) + MITRE CWE/CAPEC enrichment |
| 6 | `shodan_enrich.py` | Shodan host lookup, reverse DNS, passive CVE discovery |

**Container lifecycle:**

1. User clicks "Start Recon" in the webapp.
2. Webapp calls the recon API route, which proxies to the recon orchestrator (`:8010`).
3. The `container_manager.py` uses Docker SDK to spawn an ephemeral container from the `recon` image with host network access. It auto-detects the host mount paths from its own mounts (no hardcoded paths).
4. The recon container runs all phases sequentially. Progress is streamed to the webapp via SSE.
5. Results are written to JSON files (`recon/output/`) and to the Neo4j graph incrementally per phase.
6. The container is cleaned up after completion.

The recon orchestrator also manages **GVM scanner** (`vuln-scanner` service), **GitHub Secret Hunter** (`github-secret-hunter` service), and **TruffleHog Secret Scanner** (`trufflehog-scanner` service) containers using the same lifecycle pattern.

> For per-phase details, see [README.RECON.md](README.RECON.md) and the individual phase READMEs ([PORT_SCAN](README.PORT_SCAN.md), [HTTP_PROBE](README.HTTP_PROBE.md), [RESOURCE_ENUM](README.RESOURCE_ENUM.md), [VULN_SCAN](README.VULN_SCAN.md), [MITRE](README.MITRE.md)).

### 4.4 Webapp (webapp/)

The webapp is a **Next.js 16** application that serves as both the frontend UI and the backend API.

**Backend (API routes):**

All REST endpoints live in `webapp/src/app/api/`. The main route groups:

| Route Group | Purpose |
|-------------|---------|
| `projects/` | CRUD for projects + all project settings |
| `conversations/` | Agent conversation + chat message management |
| `remediations/` | CypherFix remediation CRUD + batch operations |
| `reports/` | Pentest report generation and retrieval |
| `models/` | Available LLM model listing based on configured providers |
| `users/` | User management and per-user settings |
| `analytics/` | Project analytics data aggregation |
| `graph/` | Neo4j graph query proxy endpoints |
| `agent/` | Agent-related API endpoints |
| `cypherfix/` | CypherFix-specific API |
| `recon/` | Recon pipeline status and control |
| `gvm/` | GVM scanner status and control |
| `github-hunt/` | GitHub secret hunt control |
| `trufflehog/` | TruffleHog secret scanner control |
| `guardrail/` | Scope guardrail validation |
| `roe/` | Rules of Engagement management |
| `ws/` | WebSocket proxy to agent container |
| `health/` | Health check |
| `plugins/` | Plugin platform: the Plugins page model, admin lifecycle (install, update, rollback, enable, disable, uninstall, export, logs), actions and jobs, skill-version review |
| `plugin-gateway/v1/` | The Gateway plugin code calls through the proxy; call token only |
| `plugin-runner/v1/` | The plugin runner's run list; runner key only |
| `internal/plugins/` | Plugin reconciliation, called by the recon orchestrator with the master internal key |

**Frontend pages:**

| Page | URL | Purpose |
|------|-----|---------|
| Home | `/` | Landing / project selector |
| Projects | `/projects/[id]` | Project dashboard with agent drawer, settings, recon controls |
| Graph | `/graph` | 2D/3D attack surface graph visualization |
| CypherFix | `/cypherfix` | Remediation dashboard and CodeFix agent |
| Reports | `/reports` | Pentest report listing and viewing |
| Settings | `/settings` | Global settings (LLM providers, API keys) |
| Insights | `/insights` | Analytics charts and project metrics |
| Plugins | `/plugins` | Plugin catalog, install and management; plugin screens at `/plugins/<id>` |

**Database access:**

- **PostgreSQL** via Prisma ORM — all user, project, conversation, and remediation data. Uses **push-based schema management** (`prisma db push`), NOT migrations.
- **Neo4j** via the official driver — read-only queries for attack surface visualization. Graph queries live in `server_actions/graph_queries.ts`.

**Real-time communication:**

- **WebSocket** — Agent chat connections are proxied to the agent container (internal `:8080`, host `:8090`) via the `/api/ws` route.
- **SSE** — Recon, GVM, GitHub hunt, and TruffleHog progress is streamed from the recon orchestrator (`:8010`).

**Internal service URLs** (for inter-container communication within Docker network):

| Service | Internal URL |
|---------|-------------|
| Agent | `http://agent:8080` |
| Recon Orchestrator | `http://recon-orchestrator:8010` (reachable **only from the webapp** — on `orchestrator-net`, not `redamon`) |
| Webapp | `http://webapp:3000` (the orchestrator reaches it via its own `WEBAPP_API_URL` for RoE/guardrail pre-flight) |
| Kali Sandbox (MCP) | `http://kali-sandbox:8000/sse` (requires `Authorization: Bearer $MCP_AUTH_TOKEN`) |
| Neo4j | `bolt://neo4j:7687` |
| PostgreSQL | `postgresql://redamon:<POSTGRES_PASSWORD>@postgres:5432/redamon` (password from `.env`, generated on fresh install) |
| Plugin runner | `http://plugin-gateway:7072` (`PLUGIN_RUNNER_URL`: the supervisor, through the proxy, over `plugins-edge`) |

**React hooks:**

The webapp exposes 19 custom hooks in `src/hooks/` that encapsulate all real-time communication and data fetching logic. Each SSE/WebSocket connection has its own dedicated hook (e.g., `useAgentWebSocket`, `useReconSSE`, `useCypherFixTriageWS`).

**Plugin platform library (`src/lib/plugins/`):**

The webapp is the trusted half of the plugin platform: it alone reads the database, writes the
plugins volume and serves the Gateway. When the runner is down, actions answer
`503 runner_unavailable` and the Plugins page says so. The design is in
[README.PLUGINS.md](README.PLUGINS.md).

| Area | Modules |
|------|---------|
| Catalog and downloads | `catalog.ts` (Ed25519 signature over the exact bytes; the highest serial is kept in `plugin_platform_state`; a catalog never expires), `keyring.ts` (the official public keys, plus `PLUGINS_EXTRA_TRUSTED_KEYS`), `fetchRemote.ts` (https only, `PLUGINS_DOWNLOAD_HOSTS` on every redirect hop) |
| Archives and the volume | `archive.ts` (strict ustar reader), `installChecks.ts` (checksum, manifest, screens, in memory), `staging.ts` (the plugins volume layout) |
| Plugin Manager | `lifecycle.ts`, `lifecycleRoutes.ts` (`platform:plugins`, asked of the account read from the database), `registry.ts` (`plugin_installs`, the source of truth), `migrations.ts`, `reconcile.ts`, `runnerClient.ts` |
| Gateway | `gateway.ts`, `callToken.ts`, `permissions.ts`, `dataStore.ts`, `transcript.ts` + `redact.ts` (masked session reads), `llmBudget.ts`, `jobs.ts` |
| Skill-text overrides | `overrides.ts`, `overrideOps.ts`, `overrideDelivery.ts` (approved versions into the agent's settings payload), `skillPartsRegistry.ts`, `reviewModel.ts`, `riskFlags.ts`, `textDiff.ts` |
| Contract | `schemas/` (zod manifest, screen and catalog schemas; `schemas/json/` is generated by `npm run plugins:schemas`), `extensionPoints.ts`, `contributions.ts`, `platformVersion.ts` |
| Settings and time | `settings.ts` (limits from the environment; an invalid value falls back to the default), `clock.ts` (the only clock, so tests pin time) |
| Test doubles | `__testing__/` (fake Prisma, fake runner, fake HTTP server, catalog builder); no production module may import it |

> For the component tree and page structure, see [README.WEBAPP.md](README.WEBAPP.md).

### 4.5 Settings Architecture

RedAmon's project settings control everything from Katana crawl depth to Metasploit payload configuration. Each one is described once in `recon_settings/registry.yaml`; the generated wiki page [Project-Settings-Registry](https://github.com/samugit83/redamon/wiki/Project-Settings-Registry) lists them all.

**Where settings live:**

```
User edits in Webapp UI (/projects/[id] → Settings panels)
        │
        ▼
PostgreSQL (Project model, via Prisma)
        │
        ▼
Agent/Recon fetch at runtime via GET /api/projects/:id
        │
        ▼
Merged with DEFAULT_AGENT_SETTINGS (project_settings.py)
        │
        ▼
Applied during execution
```

**Multi-layer defaults:**

Settings have defaults defined in **four layers** that must stay in sync:

1. **Prisma schema** (`webapp/prisma/schema.prisma`) — Database column default value
2. **Python defaults** (`agentic/project_settings.py` → `DEFAULT_AGENT_SETTINGS` dict) — Fallback when the webapp API is unavailable or returns null
3. **Frontend fallback** — `onChange` handler in the settings UI component provides a client-side default
4. **Existing DB rows** — Must be backfilled via SQL `UPDATE` when adding a new setting with a non-null default

> **Critical**: When changing a default value, you MUST update ALL four layers and restart agent + webapp. See the [Adding a New Project Setting](#61-adding-a-new-project-setting) checklist.

---

## 5. Development Workflow

### 5.1 Prerequisites

- **Docker Engine 28.0.0 or newer** & **Docker Compose v2+** ([install guide](https://docs.docker.com/get-docker/)). `redamon.sh` refuses an older engine, because the plugin networks need it
- **Git**
- A code editor (VS Code recommended)
- At least one LLM API key — configured in the webapp UI at `/settings`, NOT in `.env`
- Recommended: **8 GB RAM minimum** (GVM stack is memory-hungry)

### 5.2 First-Time Setup

```bash
git clone https://github.com/samugit83/redamon.git
cd redamon

# Enable dev mode (one-time, creates a gitignored override file)
cp docker-compose.dev.yml docker-compose.override.yml

# Build all images
docker compose --profile tools build

# Start core services (without GVM):
docker compose up -d postgres neo4j recon-orchestrator kali-sandbox agent webapp

# Or start all services (with GVM):
docker compose up -d
```

Once the override file exists, all `docker compose` commands automatically use dev mode with Next.js hot-reload -- no `-f` flags needed. To switch back to production mode: `rm docker-compose.override.yml`

- **First run with GVM**: feed sync takes **~30 minutes**. All other services are ready immediately.
- Access the webapp at **http://localhost:3000**.
- Create a user account.
- Configure your LLM provider API key and other settings in the webapp at `/settings` (Global Settings page). No `.env` file is needed -- all API keys, tunnel credentials, and tool settings are configured from the UI.
- Create a project, set a target domain, and you're ready to go.

> **Not a developer?** Use `./redamon.sh install` for a single-command production setup. See the [README Quick Start](../../README.md#quick-start).

**Verify everything is running:**

```bash
docker compose ps              # All services should show "running" or "healthy"
docker compose logs webapp --tail=5   # Should show "Ready in X ms"
docker compose logs agent --tail=5    # Should show "Uvicorn running on 0.0.0.0:8080"
```

### 5.3 Hot-Reload vs Rebuild

This is the most important table for day-to-day development. It tells you exactly what to do after changing any file:

| What you changed | Action needed | Why |
|---|---|---|
| `webapp/src/**`, `webapp/server_actions/**` | Dev mode (`./redamon.sh up dev`): **nothing**. Otherwise `docker compose build webapp && docker compose up -d webapp` | `docker-compose.dev.yml` mounts `./webapp` and runs `next dev` (fast refresh); the default stack runs a built image with no source mount, and `./redamon.sh update` rebuilds it for any `webapp/` change |
| `agentic/**/*.py` | `docker compose build agent && docker compose up -d agent` | Source code is baked into the image; rebuild is required |
| `recon_orchestrator/**/*.py` | `docker compose restart recon-orchestrator` | The source is mounted (`./recon_orchestrator:/app`) but uvicorn runs without `--reload` (`recon_orchestrator/Dockerfile`), so the process keeps the old code until it restarts; `update` restarts it |
| `recon/**/*.py` | **Nothing** for the next scan; `docker compose restart recon-orchestrator` for `recon/project_settings.py` or `recon/settings_registry.py` | Each scan container gets the host's `recon/` bind-mounted; the orchestrator imports those two files for `/defaults`. `update` also rebuilds the recon image, whose baked copy runs where the orchestrator cannot resolve the host path (Docker Desktop / WSL2) |
| `recon_settings/**` | `python3 recon_settings/build.py`, then rebuild the agent and the webapp, `docker compose --profile tools build recon`, and `docker compose restart recon-orchestrator` | `build.py` rewrites the generated copies (one under `webapp/`). The agent bakes `recon_settings/` and refuses every RoE upload with a 503 once its registry digest differs; the recon image bakes a fallback copy; the orchestrator loads its read-only mount at start. `update` does all of it |
| `mcp/servers/**/*.py` | `docker compose restart kali-sandbox` | Mounted over the baked copy (`./mcp/servers:/opt/mcp_servers`); the servers load their modules at startup |
| `mcp/kali-sandbox/**`, `mcp/requirements.txt` | `docker compose build kali-sandbox && docker compose up -d kali-sandbox` | Baked into the kali image (pip constraints, the adkc helpers, the motd, the entrypoint); `update` rebuilds it |
| `graph_db/**/*.py` | `docker compose build agent && docker compose up -d agent`, `docker compose restart recon-orchestrator`, and `docker compose restart kali-sandbox` for `resource_governor.py` | The agent image bakes its own copy: every agent graph read and the Mute Rules preview and apply run from it. The orchestrator imports `Neo4jClient` from its read-only mount, and kali's terminal server imports `graph_db.resource_governor` from its mount. Scan containers get `graph_db` bind-mounted. `update` rebuilds the agent, restarts the orchestrator and rebuilds the recon, vuln-scanner and github-secret-hunter images (their baked copy is the fallback), but does not restart kali |
| `graph_db/node_filters/catalog.yaml` | `python3 graph_db/node_filters/build.py`, then rebuild the agent | The Mute Rules catalog is compiled into `graph_db/node_filters/catalog.json` (the engine) and `webapp/src/lib/nodeFilters/catalog.json` (the page). Editing the YAML alone changes nothing, and the unit gate's `build.py --check` fails on a stale copy |
| `services/knowledge_base/**` | `docker compose build agent && docker compose up -d agent` (only `docker compose restart agent` for `kb_config.yaml`) | The package is COPY-baked into the agent image; `kb_config.yaml` is mounted over it. A running `kb-refresh` (same image) is not recreated by `update`: `docker compose --profile kb-refresh up -d kb-refresh` |
| `services/docker_broker/**` | `docker compose build docker-broker && docker compose up -d docker-broker` | `broker.py` is baked into the image; `update` rebuilds it |
| `scanners/{gvm_scan,github_secret_hunt,trufflehog_scan,supply_chain_scan,ai_attack_surface_scan}/**/*.py` | **Nothing** for the next scan | The orchestrator bind-mounts each folder into the scan container it spawns. A `Dockerfile` or requirements change needs `docker compose --profile tools build <service>` (`vuln-scanner`, `github-secret-hunter`, `trufflehog-scanner`, `supply-chain`, `ai-attack-surface`); `update` rebuilds the first three on any change in their folder, the last two only on those files |
| `scanners/{baddns_scan,wcvs,codefix_sandbox,supply_chain_analyzer}/**` | `docker compose --profile tools build <service>` (`baddns-scanner`, `wcvs`, `codefix-sandbox`, `supply-chain-analyzer`) | Build-only images with their code baked in, run per scan; `update` rebuilds the one whose folder changed |
| `scanners/capture_proxy/**`, `recon_orchestrator/{hard_guardrail,ip_denylist}.py` | `docker compose --profile capture build capture-proxy` | Both capture services run that image, which the orchestrator starts on demand and never builds; it also bakes the two orchestrator guard files. `update` rebuilds it and moves a running proxy onto it |
| `webapp/package.json` (new dep) | `docker compose build webapp && docker compose up -d webapp` | New npm packages require image rebuild |
| `agentic/requirements.txt` (new dep) | `docker compose build agent && docker compose up -d agent` | New pip packages require image rebuild |
| `recon_orchestrator/requirements.txt` | `docker compose build recon-orchestrator && docker compose up -d recon-orchestrator` | Same |
| `recon/requirements.txt` | `docker compose --profile tools build recon` | The next scan is spawned from the new image |
| Any `Dockerfile` | `docker compose build <service> && docker compose up -d <service>` | Dockerfile changes always need rebuild |
| Bump a pinned tool/model (T15/T17) | rebuild the affected image | `recon/Dockerfile`+`requirements.txt` and `services/knowledge_base/curation/pins.py` pin third-party pulls to commits/tags; a moved/removed pin **fails the build loudly**. Edit the pin, then rebuild. |
| `docker-compose.yml` | `docker compose up -d` | Compose detects config changes and recreates affected containers |
| `services/plugin_runner/**` (supervisor, worker, SDK, proxy) | `docker compose --profile plugins build plugin-runner`, then `./redamon.sh up` | Baked into one image, `redamon-plugin-runner`, that both plugin services run; `up` recreates them from the new image |
| `docker-compose.plugins.yml` | `./redamon.sh up` | Only `redamon.sh` loads the overlay |
| A plugin variable in `.env` | `./redamon.sh up` | A plain restart keeps the old environment; `up` runs the plugin preflight again and recreates the services whose environment changed |
| The plugin platform version | Bump every copy (see [§6.6](#66-adding-a-plugin-extension-point)), rebuild webapp and runner | A runner whose version differs from the webapp's reports itself out of date and starts no worker |
| `webapp/prisma/schema.prisma` | `docker compose exec webapp npx prisma db push` | Push schema changes to PostgreSQL |
| New default value | Update ALL 4 layers + rebuild agent & webapp | See [checklist](#61-adding-a-new-project-setting) |

### 5.4 Common Commands

```bash
# ─── Logs ────────────────────────────────────────────────────────────────
docker compose logs -f agent                    # Follow agent logs (live)
docker compose logs -f webapp                   # Follow webapp logs
docker compose logs -f recon-orchestrator       # Follow recon orchestrator
docker compose logs --tail=200 agent            # Last 200 lines

# ─── Shell Access ────────────────────────────────────────────────────────
docker compose exec agent bash                  # Shell into agent container
docker compose exec webapp sh                   # Shell into webapp (Alpine, no bash)
docker compose exec kali-sandbox bash           # Shell into Kali sandbox
docker compose exec postgres psql -U redamon    # PostgreSQL interactive shell

# ─── Rebuild ─────────────────────────────────────────────────────────────
docker compose build webapp                     # Rebuild webapp image only
docker compose build agent                      # Rebuild agent image only
docker compose build                            # Rebuild ALL images
docker compose up -d                            # Recreate containers with new images

# ─── Database (PostgreSQL) ──────────────────────────────────────────────
docker compose exec webapp npx prisma db push   # Apply Prisma schema changes
docker compose exec webapp npx prisma studio    # Visual DB browser (http://localhost:5555)
docker compose exec postgres psql -U redamon -c "SELECT * FROM \"Project\" LIMIT 5;"

# ─── Database (Neo4j) ───────────────────────────────────────────────────
# Browser UI:  http://127.0.0.1:7474   (loopback-only host publish)
# Bolt URL:    bolt://127.0.0.1:7687
# Credentials: neo4j / <NEO4J_PASSWORD from .env>
#   On a fresh install redamon.sh generates a strong NEO4J_PASSWORD into .env;
#   there is no compose fallback anymore - Neo4j refuses to start if the var is
#   unset (${NEO4J_PASSWORD:?...} fail-closed, STRIDE S13). Run redamon.sh.
#   Get it with:  grep '^NEO4J_PASSWORD=' .env

# ─── Service Management ─────────────────────────────────────────────────
docker compose ps                               # Check all container statuses
docker compose build agent && docker compose up -d agent  # Rebuild agent (code baked into image)
docker compose restart kali-sandbox              # Restart kali-sandbox (code volume-mounted)
docker compose down && docker compose up -d     # Full restart (preserves data)
docker compose down -v && docker compose up -d  # DANGER: deletes ALL data (volumes)

# ─── Plugin platform ────────────────────────────────────────────────────
./redamon.sh status                             # PLUGINS: the runner and gateway state, or why they cannot run
docker compose --profile plugins ps plugin-runner plugin-gateway
docker compose --profile plugins logs -f plugin-runner plugin-gateway
docker compose --profile plugins build plugin-runner   # one image for both plugin services
# redamon.sh adds docker-compose.plugins.yml to COMPOSE_FILE. A plain `up` must name the
# overlay and the profile itself (in dev mode also docker-compose.override.yml: an
# explicit -f stops compose loading it):
docker compose -f docker-compose.yml -f docker-compose.plugins.yml --profile plugins up -d webapp plugin-runner plugin-gateway
docker compose --profile plugins down           # with the profile, or older Compose leaves the plugin containers running
```

A plain `docker compose up -d` that leaves out the overlay recreates the webapp without
`plugins-edge` and the plugins volume, so it loses the runner until the next
`./redamon.sh up`. Prefer `./redamon.sh up`: it runs the plugin preflight (Docker Engine 28.0.0
or newer, the internal key and the two plugin secrets, the runner image), loads the overlay,
and starts the plugin services. A failed preflight stops it before any service is created and
names the cause.

### 5.5 Important Rules

1. **Never use `prisma migrate`** — The project uses `prisma db push` (push-based workflow). Migrations are not tracked.
2. **Never build the webapp locally** with `npx` or `npm run build` — Always use `docker compose build webapp`. The local `node_modules` may differ from the container image.
3. **Never add Python imports** to `agentic/` without ensuring the package is listed in `requirements.txt` and the image has been rebuilt — Otherwise the container will crash-loop on startup.
4. **LLM API keys are per-user** — They are configured in the webapp UI at `/settings` and stored in PostgreSQL. They are NOT environment variables.
5. **Docker timestamps** use RFC3339Nano format with nanoseconds — If you parse them in Python, truncate to 6 fractional digits before passing to `datetime.fromisoformat()`.
6. **Agent source code is baked into the image** -- Unlike `recon_orchestrator/` (which is volume-mounted), `agentic/` source code is copied into the Docker image at build time. You MUST rebuild the agent image after editing `.py` files in `agentic/`: `docker compose build agent && docker compose up -d agent`.

### 5.6 AI-Assisted Coding

AI-assisted development is welcome and encouraged. RedAmon is a large, multi-language, multi-container codebase — AI coding tools can significantly speed up development and help you navigate unfamiliar subsystems.

**Recommended model:** We recommend **Anthropic Claude Opus 4.6** (`claude-opus-4-6`) given the complexity of this repository. Opus handles large context windows, multi-file reasoning, and architectural decisions better than smaller models. You can use it through [Claude Code](https://claude.com/claude-code), Cursor, Windsurf, or any editor that supports Anthropic models.

Other capable models (GPT-5, Gemini 2.5 Pro) can also work, but Opus 4.6 has been tested extensively on this codebase and provides the most reliable results.

**Ground rules for AI-assisted contributions:**

1. **Understand before committing** — Always review and understand the code your AI generates before submitting a PR. You are responsible for every line you push, not the AI.
2. **Read the relevant files first** — Point your AI tool at the specific files and subsystems it needs to understand. Blind generation without context produces hallucinated imports, wrong API signatures, and broken integrations.
3. **Respect the architecture** — RedAmon has clear boundaries between subsystems (webapp, agent, recon, MCP). Don't let AI tools blur these boundaries by generating cross-cutting shortcuts that bypass the established communication patterns (REST, WebSocket, MCP protocol).
4. **Test inside Docker** — AI tools often generate code that works locally but fails in the container. Always verify your changes inside the Docker stack, not just in your editor's preview.
5. **Don't blindly add dependencies** — If the AI suggests a new `import` or `require`, check that the package exists in the relevant `requirements.txt` or `package.json` first. Adding an uninstalled dependency will crash-loop the container.
6. **Keep diffs minimal** — Resist the temptation to let AI refactor, reformat, or "improve" surrounding code. PRs should only contain changes relevant to the task. Large AI-generated diffs that touch unrelated files are hard to review and will be rejected.
7. **No AI-generated comments or docs unless requested** — Don't let AI litter the code with docstrings, inline comments, or type annotations that weren't there before. Follow the existing code style.
8. **Validate Cypher queries and Prisma schemas** — AI models frequently hallucinate Neo4j node labels, relationship types, and Prisma field names. Always cross-check generated queries against [graph_db/schema_sections.md](../../graph_db/schema_sections.md) - the single declaration of every label, property and relationship - and the actual Prisma schema.

### 5.7 Several Agent Sessions in One Checkout

Parallel agent sessions in one working tree share its git index, so a plain
`git add` / `git commit` sweeps in, or reverts, another session's work. Never
`git add -A`, `git commit -a`, `stash`, `checkout` or `reset --hard` in a shared
tree. Commit only your own paths through a private index, with a compare-and-swap
on the branch:

```bash
old=$(git rev-parse HEAD)
export GIT_INDEX_FILE="$(git rev-parse --absolute-git-dir)/priv.idx"
git read-tree HEAD
git add -- path/one path/two                 # your files, staged privately
# a file that ALSO holds another session's hunks: stage HEAD + only your edits
git update-index --add --cacheinfo 100644,$(git hash-object -w mine.tmp),path/three
tree=$(git write-tree)
new=$(git commit-tree "$tree" -p "$old" -F msg.txt)
rm "$GIT_INDEX_FILE"; unset GIT_INDEX_FILE
git update-ref refs/heads/<branch> "$new" "$old"   # refuses if <branch> moved meanwhile
git reset -q -- path/one path/two path/three       # shared index follows YOUR paths only
```

Skip the final `reset` and the next session's commit silently reverts yours. To
test the exact tree before committing, export it with
`GIT_INDEX_FILE=... git checkout-index -a --prefix=<dir>/` and run the checks
there. The same technique works in the `redamon.wiki` submodule; its gitlink in
the parent repository uses mode `160000`.

The final `update-ref` is a compare-and-swap on the branch ref: it writes `$new`
only while `refs/heads/<branch>` still holds `$old`. It does not look at `HEAD`.

**Committing to a branch that is not checked out** (for example `master` while the
tree is on a feature branch): base the commit on `refs/heads/<branch>`, not on
`HEAD`, which belongs to the other branch.

```bash
old=$(git rev-parse refs/heads/<branch>)
export GIT_INDEX_FILE="$(git rev-parse --absolute-git-dir)/priv.idx"
git read-tree refs/heads/<branch>
git add -- path/one                          # only if it differs from <branch> by your edits alone
# otherwise stage <branch>'s version (git show <branch>:path/two) + only your edits
git update-index --add --cacheinfo 100644,$(git hash-object -w mine.tmp),path/two
tree=$(git write-tree)
new=$(git commit-tree "$tree" -p "$old" -F msg.txt)
rm "$GIT_INDEX_FILE"; unset GIT_INDEX_FILE
git update-ref refs/heads/<branch> "$new" "$old"   # refuses if <branch> moved meanwhile
```

Skip the `git reset` here: the checked-out branch did not move, so the shared
index is still right for it.

### 5.8 Release Step: Public Suffix List Data

Scope groups use the Public Suffix List twice: the webapp groups and validates
with `tldts` (pinned in `webapp/package.json`), and recon refuses to enumerate a
suffix with `publicsuffixlist` (pinned in `recon/requirements.txt`). Each ships a
frozen copy of the list, so a suffix the registries add after the snapshot reads
as registrable and `*.<new-suffix>` passes validation. The guarantee "never
enumerate a public suffix" holds only while both copies are current.

Whoever cuts a release, at least once per minor release:

1. Bump both pins **in the same commit**. A snapshot older than about three
   months is a release blocker. For `publicsuffixlist`, take the newest release
   that is at least 7 days old, and put its wheel's sha256 (from
   `https://pypi.org/pypi/publicsuffixlist/<version>/json`) in a comment on the
   same line.
2. Rebuild the `recon` and `webapp` images.
3. Run the parity vectors (`recon/tests/fixtures/public_suffix_vectors.json`,
   read by `webapp/src/lib/publicSuffix.test.ts` and
   `recon/tests/test_public_suffix.py`) through `./redamon.sh test unit`.
4. Run `python3 tooling/scripts/psl_drift_report.py`: it lists the rules where
   the two snapshots disagree. A non-empty report means the older side needs a
   bump.
5. If the new snapshot changes how an existing project's hosts group, say so
   in the CHANGELOG `Upgrade` bullet, and tell operators to run
   `tooling/scripts/dns_finding_rekey.py`. A Domain batch keys its SPF, DMARC,
   DNSSEC and zone-transfer findings on the group's root, so a regroup gives
   them new ids. The script moves the mute, the Priority Board layers, the
   un-mute exemptions and the fix items to the new ids. It is a dry run by
   default; use `--apply` with the services stopped, before the first scan.

---

## 6. Feature Development Checklists

### 6.1 Adding a New Project Setting

1. Add the field to the Prisma schema (`webapp/prisma/schema.prisma`) with a default value.
2. Push the schema:
   ```bash
   docker compose exec webapp npx prisma db push
   ```
3. Add the same default to `DEFAULT_AGENT_SETTINGS` in `agentic/project_settings.py` (and/or `recon/project_settings.py` if the recon pipeline uses it).
4. Add the UI control in the appropriate webapp settings component. Include a fallback value in the `onChange` handler.
5. Backfill existing database rows if needed:
   ```bash
   docker compose exec postgres psql -U redamon -c \
     "UPDATE \"Project\" SET \"newField\" = 'default_value' WHERE \"newField\" IS NULL;"
   ```
6. Rebuild affected services:
   ```bash
   docker compose build agent && docker compose up -d agent webapp
   ```

### 6.2 Adding a New Agent Tool

1. Define the tool schema (name, description, parameters) in `agentic/prompts/tool_registry.py`.
2. Implement the tool manager -- either add to `agentic/tools.py` or create a dedicated file.
3. Register the tool in the orchestrator's tool binding (in `orchestrator.py` or the relevant node file).
4. If the tool should only be available in certain phases, add it to the phase-tool mapping in `prompts/base.py`.
5. Rebuild:
   ```bash
   docker compose build agent && docker compose up -d agent
   ```

### 6.3 Adding a New Webapp API Route

1. Create the route handler at `webapp/src/app/api/<your-route>/route.ts`.
2. Follow existing patterns: validate input with TypeScript types, use `prisma` from `lib/prisma.ts` for DB access, return `NextResponse.json()`.
3. If you need to call other services, use the internal Docker network URLs (see the [Internal service URLs](#44-webapp-webapp) table):
   - Agent: `http://agent:8080` (NOT `:8090` — that's the host-mapped port)
   - Recon Orchestrator: `http://recon-orchestrator:8010`
   - Webapp itself: `http://webapp:3000` (for inter-route calls)
4. No restart needed — Next.js HMR picks up new files automatically.

### 6.4 Adding a New Recon Phase

1. Create the phase module in `recon/` (e.g., `new_phase.py`).
2. Add the phase call to the pipeline in `recon/main.py`.
3. If the phase writes to Neo4j, add the Cypher queries using the existing Neo4j driver pattern (see other phase modules for examples).
4. Add any new settings to `project_settings.py` (both `recon/` and `webapp/` layers via Prisma).
5. The next recon run will automatically use the new phase — source is volume-mounted.

### 6.5 Adding a New Frontend Hook

1. Create the hook in `webapp/src/hooks/` following the naming convention: `useYourFeature.ts`.
2. Export it from `webapp/src/hooks/index.ts`.
3. For WebSocket hooks, follow the pattern in `useAgentWebSocket.ts` (connect, message handling, cleanup).
4. For SSE hooks, follow `useReconSSE.ts` (EventSource, reconnection, progress tracking).
5. For data fetching hooks, use TanStack React Query (see `useProjects.ts` for examples).

### 6.6 Adding a Plugin Extension Point

An extension point (a UI slot such as `chat.session.actions`, or a behaviour point such as
`skill.text`) is part of the plugin platform's public contract. Adding one is a **minor**
platform version bump; changing or removing one is a **major** bump that makes every plugin
whose `platform` range excludes the new version incompatible ([README.PLUGINS.md](README.PLUGINS.md)
§11). The base repository still holds no plugin-specific code: the point must be generic.

1. **Name it** in `webapp/src/lib/plugins/extensionPoints.ts` (`UI_EXTENSION_POINTS` or
   `BEHAVIOUR_EXTENSION_POINTS`). A behaviour point also gets its permission in
   `POINT_PERMISSION` and `permissions.ts`; a screen only the core may draw goes in
   `CORE_SCREENS`.
2. **Accept it in the manifest** (`schemas/manifest.ts`, the `contributes` object), including the
   cross-check that every `action` it names exists, then regenerate the JSON schemas with
   `cd webapp && npm run plugins:schemas` (`schemas/json/`, which `redamon-plugins` validates against).
3. **Serve it** from `contributions.ts` (`GET /api/plugins/contributions` lists only enabled,
   non-revoked plugins) and draw it in the core component that owns the slot, through
   `usePluginContributions()`. Plugin text is React-escaped or `SafeMarkdown` without images; a
   plugin never ships JavaScript or React.
4. **Behaviour points only:** the agent side is data, never a call into plugin code. Mirror the
   `skill.text` pattern: the approved value is delivered in the settings payload, the agent
   validates it and falls back to the factory behaviour (`agentic/prompts/skill_part_seam.py`,
   `agentic/plugin_api.py`).
5. **Bump the platform version** in every copy, which `platformVersion.parity.test.ts` holds
   equal: `webapp/src/lib/plugins/platformVersion.ts`, `services/plugin_runner/platform_version.py`,
   `services/plugin_runner/sdk/redamon_plugin_sdk/__init__.py`,
   `services/plugin_runner/sdk/contract_cases.json` and
   `services/plugin_runner/tests/runner_contract_cases.json` (its `platformVersion` and the health
   case), plus the pin in `services/plugin_runner/tests/test_sdk_contract.py`; the runner's other
   tests read it from `platform_version.py`. Rebuild the webapp and the runner image together:
   a runner whose version differs from the webapp's reports itself out of date and starts no worker.
6. **Test the empty slot** (with no plugin contributing to it the slot renders nothing), and
   **document** the point in README.PLUGINS.md §7.6 and in the author reference
   [README.PLUGIN_SDK.md](README.PLUGIN_SDK.md).
7. **A point whose approval creates something instead of overriding** (as `user_skill.text`
   saves a new user skill) leaves a product that outlives the plugin, so it needs two more
   things: a **proposer gate** at save time (the proposing plugin still serving at the version
   that made the proposal, which the Gateway records from the call token) and a **revocation
   path** (reconciliation withdrawing that version's waiting proposals and quarantining what was
   saved from them, installed or not). Its rows end in a terminal status of their own, never
   `active`, so delivery, reconciliation and the one-active index never see them.

---

## 7. Debugging & Testing

### Debugging the Agent

The agent logs to stdout inside the container. All reasoning steps, tool calls, and errors are logged.

```bash
# Live agent logs (most useful for debugging)
docker compose logs -f agent

# Check if the agent container is healthy
docker compose ps agent

# Shell in and inspect the running process
docker compose exec agent bash
ps aux | grep uvicorn
```

**Common agent issues:**

| Symptom | Cause | Fix |
|---------|-------|-----|
| Container keeps restarting | Missing Python package or import error | Check logs: `docker compose logs agent --tail=50`, then fix the import and rebuild if needed |
| WebSocket connection refused | Agent not ready yet | Wait a few seconds; check logs for "Uvicorn running" |
| Tool execution timeout | MCP server (Kali sandbox) not responding | `docker compose restart kali-sandbox`, then `docker compose restart agent` |
| "Settings fetch failed" | Webapp not reachable from agent | Ensure webapp is running: `docker compose ps webapp` |
| LLM API error (401/429) | Invalid or rate-limited API key | Check/update API key in webapp `/settings` |

### Debugging the Webapp

```bash
docker compose logs -f webapp               # Live logs (Next.js + API)
docker compose exec webapp sh               # Shell into webapp container
```

**Prisma debugging:**

```bash
# Open Prisma Studio for visual DB inspection
docker compose exec webapp npx prisma studio

# Check current schema state
docker compose exec webapp npx prisma db pull

# Validate schema without pushing
docker compose exec webapp npx prisma validate
```

### Debugging Neo4j

```bash
# Open Neo4j Browser at http://localhost:7474
# Run Cypher queries directly:
MATCH (n) RETURN labels(n), count(n) ORDER BY count(n) DESC;

# Check graph size
MATCH (n) RETURN count(n) AS nodes;
MATCH ()-[r]-() RETURN count(r) AS relationships;
```

### Testing with Guinea Pigs

The `testing/guinea_pigs/` folder contains intentionally vulnerable applications you can use to test the full pipeline locally. Three of them, for example ([README.GPIGS.md](README.GPIGS.md) lists every one):

| Guinea Pig | Vulnerability | How to use |
|-----------|---------------|------------|
| `apache_2.4.49` | CVE-2021-41773 (path traversal + RCE) | `docker compose -f testing/guinea_pigs/apache_2.4.49/docker-compose.yml up -d` |
| `apache_2.4.25` | CVE-2017-3167 (auth bypass) | `docker compose -f testing/guinea_pigs/apache_2.4.25/docker-compose.yml up -d` |
| `node_serialize_1.0.0` | Node.js deserialization RCE | `docker compose -f testing/guinea_pigs/node_serialize_1.0.0/docker-compose.yml up -d` |

These three publish ports on the host (all three on 8080, so run one at a time). Some of the others (`skiller_*`, `proxy_brain_target`, `php2shell_upload_progress`) join `pentest-net` instead, so the agent and MCP tools reach them by address; each folder's README says how to reach it. Point your project target at the guinea pig to test reconnaissance, exploitation, and post-exploitation flows end-to-end.

### Running Recon Tests

The recon `tests/` directory is mounted into the recon-orchestrator container at `/app/recon/tests/`:

```bash
docker compose exec recon-orchestrator bash
cd /app/recon && python -m pytest tests/ -v
```

Alternatively, you can run the recon container directly:

```bash
docker compose run --rm recon python -m pytest tests/ -v
```

---

## 8. Environment Variables

You do not write a `.env` by hand: `./redamon.sh install` creates it with the generated secrets (below). All user-configurable settings (API keys, tunnel credentials) are managed from the **Global Settings** page (`/settings`) and stored in PostgreSQL.

> **Note**: LLM API keys, tool API keys (Tavily, Shodan, NVD, SerpAPI), and tunnel credentials (ngrok, chisel) are all configured **per-user** in the webapp UI at `/settings`. They are NOT set via environment variables.

### Variables in `docker-compose.yml` (with defaults)

These use Docker Compose's `${VAR:-default}` syntax. Override them in `.env` if needed. The table is a selection, the variables a developer meets first. Every variable the stack reads is in [`.env.example`](../../.env.example), with its comment, and `tests/test_env_example_keys.py` checks that each one is forwarded by a compose file or read by `redamon.sh`.

> **Secrets are auto-generated on install (since 5.3.1).** `redamon.sh` writes
> strong random values for `POSTGRES_PASSWORD`, `NEO4J_PASSWORD` and
> `MCP_AUTH_TOKEN` into `.env` on a **fresh** install (and warns, without
> changing anything, if an existing DB volume is still on the old default). The
> `${VAR:-default}` fallbacks below are only used when the variable is left
> unset — they are **not** the value a normal install runs with.
>
> The DB host ports (`5432/7474/7687`) are published on `127.0.0.1` only; the
> app tier reaches them over the internal `redamon` bridge.

| Variable | Fallback (if unset) | Description |
|----------|---------------------|-------------|
| `POSTGRES_USER` | `redamon` | PostgreSQL username |
| `POSTGRES_PASSWORD` | *(required, no fallback; Postgres refuses to start if unset)* | PostgreSQL password, **auto-generated on fresh install** |
| `POSTGRES_DB` | `redamon` | PostgreSQL database name |
| `NEO4J_PASSWORD` | *(required, no fallback; Neo4j refuses to start if unset)* | Neo4j password, **auto-generated on fresh install** |
| `MCP_AUTH_TOKEN` | *(required; empty ⇒ MCP servers fail closed / reject)* | Bearer token the agent presents to the Kali MCP servers, **auto-generated on fresh install** |
| `POSTGRES_PORT` | `5432` | Host port for PostgreSQL (bound to `127.0.0.1`) |
| `NEO4J_HTTP_PORT` | `7474` | Host port for Neo4j Browser UI (bound to `127.0.0.1`) |
| `NEO4J_BOLT_PORT` | `7687` | Host port for Neo4j Bolt protocol (bound to `127.0.0.1`) |
| `WEBAPP_PORT` | `3000` | Host port for the webapp |
| `AGENT_PORT` | `8090` | Host port for the agent API (maps to internal :8080) |
| `RECON_ORCH_PORT` | `8010` | Host port for the recon orchestrator |

### RBAC feature switches (webapp)

Read only by [`webapp/src/lib/authz/flags.ts`](../../webapp/src/lib/authz/flags.ts). Each defaults to `false` in `docker-compose.yml`; `true`, `1` or `yes` turn it on, and any other value reads off. A switch whose requirement is off reads off too, with one `[rbac]` warning per webapp process. Recreate the webapp after a change (`./redamon.sh up`).

After turning `RBAC_PERMISSIONS_ENABLED` on or off, also run `docker compose restart agent`, or have everyone reload their open chat tabs. An agent chat socket keeps the approval permissions its ticket carried when it opened (the `cap` claim, [README.SECURITY_POSTURE.md](README.SECURITY_POSTURE.md) §9). Recreating the webapp does not close it, because the browser talks to the agent directly. Until a tab reconnects, its phase approvals and dangerous-tool confirmations follow the switch it opened under. The restart closes every chat socket and stops the runs in progress, so do it when no run matters.

| Variable | Default | Turns on | Requires |
|----------|---------|----------|----------|
| `REDAMON_SHARED_TOOLS_COMPAT` | `false` | The pre-upgrade behaviour of the five shared tools for accounts created before the upgrade (escape hatch) | none |
| `RBAC_IDENTITY_ENABLED` | `false` | Root powers and protections, account status and disable, invites and reset links, must-change password, instance settings, email step-up, session lifetimes | none |
| `RBAC_PERMISSIONS_ENABLED` | `false` | Stored permission sets, overrides and profiles, the assignment UI, impersonation rules | `RBAC_IDENTITY_ENABLED` |
| `RBAC_SHARING_ENABLED` | `false` | Project collaborators, the share dialog, Shared with me, the activity feed, oversight | `RBAC_PERMISSIONS_ENABLED` |
| `RBAC_SHARING_WRITE_ENABLED` | `false` | Read + Write sharing and its toggles, consent, transfer, the deletion wizard, conversation sharing | `RBAC_SHARING_ENABLED` |
| `RBAC_GOVERNANCE_ENABLED` | `false` | The admin console, quotas, per-plugin allowlists, device sessions, instance providers | `RBAC_PERMISSIONS_ENABLED` |

`RBAC_IDENTITY_ENABLED` turns on Root, account status, invites and reset links, forced password changes, the password policy, email step-up, the session lifetimes and the instance settings (the tunnel and TrafficMind as one row). Its data is ready before it is turned on: the boot backfills `backfill-rbac-instance-settings.mjs` (copies the tunnel and capture values in force from the account rows, again at every boot while the switch is off) and `backfill-rbac-root.mjs` (picks an unconfirmed Root among the admins with a password) run whatever the switch, after `db push` in both startup lists, never fatal. Four things also run whatever the switch: the session-version comparison (only the host commands raise the version while it is off), the tunnel sync's `TUNNEL_AUTH_TOKEN` bearer, the enable route, and the same-origin JSON check of the identity routes. `./redamon.sh update` confirms Root only with it on in `.env`; `./redamon.sh set-root <email>` works either way. Turning it off again is the roll-back: the account rows are the truth again, and an account disabled meanwhile stays disabled until an admin enables it (the enable route works with the switch off) or a host reset re-enables it.

`RBAC_PERMISSIONS_ENABLED` turns on the stored permissions: the member permission sets, the overrides and the admin profiles count, the management routes (`/api/admin/permission-sets`, `/api/admin/admin-profiles`, `/api/users/[id]/permissions`) answer instead of 404, the Users page offers **Permissions**, invites and creates accept `sets`, MCP tokens are capped by their owner's permissions, and act-as follows the impersonation rules (reason, duration, password, banner, never-list). With it off every account resolves to its account type's default, which is exactly the behaviour before the switch, so the route checks (every route asks `can()` whatever the switch) answer as before: the live matrix's `baseline p1 p2` files give the same results with it on and off while every member is on *Default member*. Its one boot step, `backfill-rbac-legacy-overrides.mjs` (after `backfill-rbac-root.mjs` in both startup lists), runs only with it on: it turns the legacy grants an admin kept into 90-day overrides and lets the undecided ones lapse, once, under the legacy-grant lock. Turning it off is the roll-back: the rows stay and are ignored, and the legacy grants count again.

`RBAC_SHARING_ENABLED` turns on read sharing, and a share counts only while Root's instance sharing policy is on too (`instance_settings.sharing_policy`, `{}` by default, which reads as off). Only the confirmed Root changes the policy (the admin console's Instance page, with Root's password); on an instance whose Root is unconfirmed a test window sets it by SQL, `UPDATE instance_settings SET sharing_policy = '{"enabled":true}'`, and puts `{}` back after. With either off no share or break-glass row is read: the share routes, the activity feed, the oversight list and break-glass answer 404 and every project is its owner's only (with the switch off `/api/projects/[id]/my-access` answers 404 too and no project read carries `myAccess`). Its data is additive (`project_collaborators`, `project_break_glass`, and `include_shared_projects` / `project_allowlist` on `mcp_access_tokens` at their defaults). Turning it off is the roll-back: every project is private again and the shares wait for the next time. With sharing in force every admin holding `projects:oversee` (*Full admin*, *Security auditor*) reads every project, audited. The expiry sweep runs from the recon orchestrator's reaper every `RBAC_SWEEP_INTERVAL` seconds (300; forwarded by `docker-compose.yml`, so a change needs the orchestrator recreated) and reads nothing of a part whose switch is off.

`RBAC_AUTHZ_CACHE_MS` (blank = `5000`, `0` = no cache, at most `60000`) bounds how long a webapp process keeps an account it read (role, status, session version) while `RBAC_IDENTITY_ENABLED` is on. A change made through the webapp drops the account in the process that made it; another copy, or a host command, sees it within this bound. Sign-in, step-up, user administration, act-as, MCP token minting and WebSocket tickets always read the database. With the identity switch off nothing is cached.

`REDAMON_SHARED_TOOLS_COMPAT` is not a feature switch but the escape hatch of the hardening: the five shared tools (the Kali terminal, every user's shell sessions, the reverse-shell tunnel, the instance-wide emergency stop, every Nuclei template) are an admin's, and members who existed before the upgrade keep the terminal, the sessions and (if they had configured one) the tunnel as legacy grants an admin reviews on the Users page. Set to `true`, it gives all five back to every account created before the upgrade's cutoff (the `system.rbac_legacy_grants_cutoff` audit row, read once per webapp process); accounts created later are never covered. While it is on, admins see a red banner, and each use logs `[rbac] shared-tools compat used` and writes an `rbac.compat_used` audit row. Only `sharedToolAccess` in [`webapp/src/lib/authz/sharedTools.ts`](../../webapp/src/lib/authz/sharedTools.ts) decides with it; `/api/auth/me` passes it to the banner (`webapp/src/lib/authz/sharedToolsCompat.test.ts` fails on any other reader).

### Audit forwarding (webapp)

`AUDIT_FORWARD` (default `off` in `docker-compose.yml`, read by [`webapp/src/lib/auditForward.ts`](../../webapp/src/lib/auditForward.ts), independent of the RBAC switches). Set to `stdout`, the webapp prints every row it writes to `audit_log`, `act_as_audit` and `fireteam_settings_audit` once, as one line: `[audit-forward] {"table":"audit_log","id":...,"createdAt":...,"action":...}`, the row as stored. Ship the webapp container's log to a store the database cannot rewrite, and a row edited or deleted later no longer matches its copy (tamper evidence). A row written in a transaction is printed only after that transaction commits, so a refused change leaves no line. `off`, blank or any other value prints nothing (another value logs one `[audit-forward]` warning). The short `[audit] <action> ...` line every row already prints stays. Recreate the webapp after a change (`./redamon.sh up`).

What is not forwarded: the rows the host scripts write with their own database client (`webapp/scripts/*.mjs`: every `backfill-*.mjs`, `set-root.mjs`, `create-admin.mjs`, `reset-password.mjs`) and `tooling/scripts/engagement_derivation_migrate.py`; they stay in the database and in the boot or command output. A failed print never fails the write: it logs an `[audit-forward]` error and the row stands. A new audit writer goes through `auditForward.ts`, and a transaction that writes a row runs in `auditedTransaction`: `webapp/src/lib/auditWriters.static.test.ts` fails otherwise.

### Model provider rate limits (agent)

| Variable | Default | Description |
|----------|---------|-------------|
| `LLM_RATE_LIMIT_MAX_WAIT_S` | `120` | Seconds one model call waits, in total, for a provider's rate limit (HTTP 429) to clear before it gives up. Limits are counted per minute, so keep it above 60; `0` fails at the first 429. A 429 that waiting cannot fix (no credit, a daily quota, one request over the limit) is never waited for. See README.AGENTIC_SYSTEM, *Model Provider Errors and Rate Limits*. |

### Agent Workspace uploads and URL import (agent)

Read by the agent with safe fallbacks: a size or count that is not a positive integer falls back to its default, so a typo can never disable a cap. Every one has a compose default; `.env` needs none of them.

| Variable | Default | Description |
|----------|---------|-------------|
| `WORKSPACE_IMPORT_MAX_BYTES` | `2147483648` (2 GiB) | Cap per upload or import: the download and the extracted total each |
| `WORKSPACE_IMPORT_MAX_ENTRIES` | `50000` | Entries per extraction or import |
| `WORKSPACE_IMPORT_MIN_FREE_BYTES` | `1073741824` (1 GiB) | Headroom on top of the scan floor: the free disk left after an operation must be `JOB_QUEUE_MIN_FREE_DISK` + this |
| `JOB_QUEUE_MIN_FREE_DISK` | `10737418240` (10 GiB) | The recon scan dispatcher's disk floor, also given to the agent so imports never take the disk below it (`0` turns that floor off, as it does for the dispatcher) |
| `WORKSPACE_IMPORT_MAX_JOBS` | `4` | Upload commits and URL imports running at once, across projects (they take no governed background-job slot) |
| `WORKSPACE_IMPORT_WORKERS` | `2` | Threads of the import pool (extraction, hashing, archive builds); work beyond them waits as `queued` |
| `WORKSPACE_UPLOAD_CHUNK_BYTES` | `8388608` (8 MiB) | Chunk size of an upload session; keep it well under the web app's 60 MB request cap (`proxyClientMaxBodySize` in `webapp/next.config.ts`) |
| `WORKSPACE_UPLOAD_SESSION_IDLE_SEC` | `3600` | An upload session idle longer than this is deleted |
| `WORKSPACE_URL_IMPORT_ENABLED` | `true` | Kill switch for import from a URL; any value but `true`/`1`/`yes` turns it off (the import routes answer 403 `import_disabled`). Folder and archive upload have no switch |

> The MCP servers listen on fixed container ports (8000, 8002–8005, from `SERVERS` in
> `mcp/servers/run_servers.py`). Their host ports, bound to `127.0.0.1`, come from
> `MCP_NETWORK_RECON_PORT`, `MCP_NUCLEI_PORT`, `MCP_METASPLOIT_PORT`, `MCP_NMAP_PORT` and
> `MCP_PLAYWRIGHT_PORT` in `docker-compose.yml` (defaults 8000, 8002, 8003, 8004, 8005). The agent
> reaches the servers on the internal network at the container ports, so a host port change does
> not affect it.

---

## 9. Documentation Index

All deep-dive documentation lives in the `docs/readmes/` folder alongside this file.

> The project also maintains a **[GitHub Wiki](https://github.com/samugit83/redamon/wiki)** with additional guides and walkthroughs.

### System-Level

| Document | What it covers |
|----------|----------------|
| [README.DEV.md](README.DEV.md) | This page: the developer guide |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Mermaid diagrams: system topology, data flow pipeline, Docker container architecture, MCP integration, agent workflow |
| [TECH_STACK.md](TECH_STACK.md) | Detailed technology role descriptions organized by layer |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | OS-specific issues and fixes (Linux, Windows, macOS) |
| [README.TESTING.md](README.TESTING.md) | How the tests run (the per-file Docker gate, tiers) and how to write them |
| [README.MEMORY_GOVERNOR.md](README.MEMORY_GOVERNOR.md) | How RedAmon keeps one host from running out of RAM while scans and agent sessions run at once |
| [README.SECURITY_POSTURE.md](README.SECURITY_POSTURE.md) | The defense-in-depth control catalog: every security layer in the product, with its evidence |
| [README.TM.SYSTEM_OVERVIEW.md](README.TM.SYSTEM_OVERVIEW.md) | Threat model: assets, architecture, data flow, trust boundaries, entry points, network surface |
| [README.DRIFT_MAP.md](README.DRIFT_MAP.md) | Every fact written down more than once, the guards that hold the copies equal, and what is stale today |

### Agent

| Document | What it covers |
|----------|----------------|
| [README.AGENTIC_SYSTEM.md](README.AGENTIC_SYSTEM.md) | Full pentest agent architecture: ReAct loop, LangGraph state machine, WebSocket protocol, tool specs, multi-objective support, RoE guardrails, EvoGraph attack chains, prompt token optimization |
| [README.CYPHERFIX_AGENTS.md](README.CYPHERFIX_AGENTS.md) | Triage + CodeFix agents: hybrid architecture, prioritization algorithm, 11 code tools, diff approval flow, GitHub PR integration, WebSocket protocols |
| [README.KBASE.md](README.KBASE.md) | The Knowledge Base: offline retrieval (FAISS + Neo4j) over curated security datasets, ahead of web search |
| [README.TRADECRAFT.md](README.TRADECRAFT.md) | Tradecraft Lookup: how a knowledge resource a user adds reaches the agent during a session |

### Reconnaissance and scanning

| Document | What it covers |
|----------|----------------|
| [README.RECON.md](README.RECON.md) | Reconnaissance pipeline overview |
| [README.RECON_ORCHESTRATOR.md](README.RECON_ORCHESTRATOR.md) | Container lifecycle management (spawn, health-check, SSE streaming, cleanup) |
| [README.SETTINGS_REGISTRY.md](README.SETTINGS_REGISTRY.md) | The recon settings registry: why every parameter is described once, and what that guarantees |
| [README.PORT_SCAN.md](README.PORT_SCAN.md) | Port scanning: Masscan + Naabu |
| [README.HTTP_PROBE.md](README.HTTP_PROBE.md) | Httpx probing, Wappalyzer, TLS inspection |
| [README.RESOURCE_ENUM.md](README.RESOURCE_ENUM.md) | Katana crawling, Kiterunner API discovery, GAU |
| [README.OPENAPI.md](README.OPENAPI.md) | OpenAPI / Swagger import as a resource-enumeration source |
| [AI_SURFACE_RECON_MODULE.md](AI_SURFACE_RECON_MODULE.md) | AI Surface Recon: fingerprinting LLM, MCP and vector-DB surfaces |
| [README.VULN_SCAN.md](README.VULN_SCAN.md) | Nuclei template scanning |
| [README.WCP_RECON_MODULE.md](README.WCP_RECON_MODULE.md) | Web cache poisoning and web cache deception detection |
| [README.MITRE.md](README.MITRE.md) | MITRE CWE/CAPEC enrichment for discovered CVEs |
| [README.SUPPLY_CHAIN.md](README.SUPPLY_CHAIN.md) | Malicious- and vulnerable-package detection, offline against a local OSV copy |
| [AI_GAUNTLET_TECH_DOC.md](AI_GAUNTLET_TECH_DOC.md) | AI Gauntlet: the AI attack-surface scanner that runs discovered LLM endpoints through adversarial tools |
| [README.GVM.md](README.GVM.md) | OpenVAS/GVM scanner integration (170k+ NVTs) |
| [README.TRAFFIC.md](README.TRAFFIC.md) | HTTP Traffic Capture: the engagement-scoped proxy history, replay and fuzz |

### Infrastructure & Data

| Document | What it covers |
|----------|----------------|
| [README.MCP.md](README.MCP.md) | The five MCP tool servers in the Kali sandbox (Network Recon, Nuclei, Metasploit, Nmap, Playwright) |
| [README.MCP.SERVER.md](README.MCP.SERVER.md) | RedAmon as an inbound MCP server: external agents connecting with a personal access token |
| [README.WEBAPP.md](README.WEBAPP.md) | Webapp architecture, component tree, page structure |
| [README.GRAPH_DB.md](README.GRAPH_DB.md) | Neo4j graph utilities |
| [graph_db/schema_sections.md](../../graph_db/schema_sections.md) | THE declaration: every node label, property and relationship |
| [GRAPH.SCHEMA.md](GRAPH.SCHEMA.md) | Why the graph is shaped this way: design principles, tenancy, the `Muted` label. Lists no labels |
| [README.POSTGRES.md](README.POSTGRES.md) | PostgreSQL schema details (Prisma models, field reference) |
| [README.GPIGS.md](README.GPIGS.md) | Guinea pigs — intentionally vulnerable test applications for local testing |

### Plugins

| Document | What it covers |
|----------|----------------|
| [README.PLUGINS.md](README.PLUGINS.md) | The plugin platform end to end: architecture, install, update, uninstall |
| [README.PLUGIN_SDK.md](README.PLUGIN_SDK.md) | The plugin author's reference: everything a plugin can declare, call and show |

### Guides for coding agents

| Document | What it covers |
|----------|----------------|
| [coding_agent_prompts/](coding_agent_prompts/) | "How to add X" prompts: an agent tool, a recon tool, partial recon, an AI hook in recon, a built-in, community or chat skill, an LLM provider |
| [skills_management/SKILLS_MANAGEMENT.md](skills_management/SKILLS_MANAGEMENT.md) | The skills and `AGENTS.md` ruleset system, its generator and its drift checks |

### Project-Level

| Document | Location | What it covers |
|----------|----------|----------------|
| [CONTRIBUTING.md](../../CONTRIBUTING.md) | repo root | Contribution guidelines, PR process, contributor ranks |
| [CHANGELOG.md](../../CHANGELOG.md) | repo root | Release history and version notes |
| [DISCLAIMER.md](../../DISCLAIMER.md) | repo root | Legal disclaimer — authorized testing only |
| [SECURITY.md](../../SECURITY.md) | repo root | Security vulnerability reporting |
