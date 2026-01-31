# RedAmon Project Guidelines

## Project Overview

**RedAmon** - *Unmask the hidden before the world does.*

An automated OSINT reconnaissance and vulnerability scanning framework for comprehensive security assessment. The platform combines multiple security tools orchestrated by AI agents with results stored in a Neo4j graph database and visualized through a Next.js webapp.

---

## Project Structure

```
RedAmon/
├── .claude/              # Claude Code configuration
│   ├── CLAUDE.md         # General project guidelines (this file)
│   └── webapp.md         # Webapp-specific guidelines
│
├── recon/                # Reconnaissance Module (Phase 1)
│   ├── main.py           # Main entry point
│   ├── params.py         # Configuration parameters
│   ├── domain_recon.py   # Subdomain discovery (crt.sh, HackerTarget, Knockpy)
│   ├── port_scan.py      # Port scanning (naabu)
│   ├── http_probe.py     # HTTP probing (httpx, headers, tech detection)
│   ├── vuln_scan.py      # Vulnerability scanning (nuclei)
│   ├── whois_recon.py    # WHOIS lookups
│   ├── github_secret_hunt.py  # GitHub secret hunting
│   ├── add_mitre.py      # MITRE ATT&CK mapping
│   ├── helpers/          # Utility modules
│   ├── data/             # Static data files
│   ├── output/           # Scan results (JSON)
│   ├── Dockerfile        # Kali-based container
│   └── docker-compose.yml
│
├── gvm_scan/             # GVM Vulnerability Scanner (Phase 2)
│   ├── main.py           # Entry point
│   ├── gvm_scanner.py    # GVM API client
│   ├── params.py         # Configuration
│   ├── output/           # Scan results
│   ├── Dockerfile        # GVM container
│   └── docker-compose.yml
│
├── graph_db/             # Neo4j Graph Database
│   ├── neo4j_client.py   # Python client for Neo4j operations
│   ├── update_graph_from_json.py  # Import scan results to Neo4j
│   ├── readmes/          # Database documentation
│   └── docker-compose.yml  # Neo4j container
│
├── mcp/                  # MCP Servers (Model Context Protocol)
│   ├── servers/          # MCP server implementations
│   │   ├── naabu_server.py     # Port scanning tool
│   │   ├── nuclei_server.py    # Vuln scanning tool
│   │   ├── curl_server.py      # HTTP client tool
│   │   ├── metasploit_server.py  # Exploitation tool
│   │   └── run_servers.py      # Server launcher
│   ├── kali-sandbox/     # Kali Docker container
│   ├── nuclei-templates/ # Custom nuclei templates
│   ├── output/           # Scan results
│   └── docker-compose.yml
│
├── agentic/              # AI Agent Orchestrator
│   ├── orchestrator.py   # LangGraph-based agent orchestration
│   ├── api.py            # FastAPI REST endpoints
│   ├── state.py          # LangGraph state definitions
│   ├── prompts.py        # System prompts for AI
│   ├── utils.py          # Utility functions
│   ├── params.py         # Configuration
│   ├── Dockerfile
│   └── docker-compose.yml
│
├── webapp/               # Next.js Frontend Application
│   ├── src/
│   │   ├── app/          # Next.js App Router pages
│   │   ├── components/   # React components
│   │   ├── hooks/        # Custom hooks
│   │   ├── lib/          # Utilities, API clients
│   │   ├── providers/    # React context providers
│   │   └── styles/       # Design tokens & themes
│   └── See .claude/webapp.md for frontend guidelines
│
├── guinea_pigs/          # Test Targets (Vulnerable VMs)
│   ├── apache_2.4.25/    # CVE test environment
│   └── apache_2.4.49/    # CVE test environment
│
└── README.recon_to_add.md  # Additional recon tools to integrate
```

---

## Component Details

### 1. Reconnaissance Module (`recon/`)

Automated OSINT and scanning framework. Runs entirely in Docker (Kali-based).

**Scan Pipeline:**
```
Domain → Subdomain Discovery → DNS Resolution → Port Scanning
       → HTTP Probing → Tech Detection → Vulnerability Scanning
       → MITRE Mapping → JSON Output → Neo4j Import
```

**Key Commands:**
```bash
cd recon/
docker-compose build --network=host
docker-compose run --rm recon python /app/recon/main.py
```

### 2. GVM Scanner (`gvm_scan/`)

Greenbone Vulnerability Management (OpenVAS) for deep vulnerability scanning.

- Consumes IPs/hosts from recon output
- 170,000+ Network Vulnerability Tests (NVTs)
- CVSS scoring and CVE mapping

### 3. Graph Database (`graph_db/`)

Neo4j for storing and querying security data relationships.

**Node Types:**
- Domain, Subdomain, IP, Port, Service
- Technology, Certificate, Header
- Vulnerability, CVE, MITRE ATT&CK

**Key Files:**
- `neo4j_client.py` - Full CRUD operations
- `update_graph_from_json.py` - Import scan results

### 4. MCP Servers (`mcp/`)

Model Context Protocol servers exposing security tools to AI agents.

**Available Tools:**
| Server | Port | Tool | Purpose |
|--------|------|------|---------|
| naabu | 8000 | naabu | Fast port scanning |
| curl | 8001 | curl | HTTP requests |
| nuclei | 8002 | nuclei | Vulnerability scanning |
| metasploit | 8003 | msfconsole | Exploitation |

### 5. Agent Orchestrator (`agentic/`)

LangGraph-based AI agent with REST API for autonomous pentesting.

**Features:**
- MCP tool execution (curl, naabu, nuclei)
- Neo4j text-to-Cypher queries
- Conversation memory (LangGraph MemorySaver)

**API Endpoint:**
```
POST /chat
{
  "question": "What vulnerabilities exist on port 443?",
  "session_id": "optional-session-id"
}
```

### 6. Webapp (`webapp/`)

Next.js 16 frontend for graph visualization. See `.claude/webapp.md` for detailed guidelines.

---

## Development Conventions

### Docker-First Approach

All security tools run in Docker containers. Never install scanning tools on host.

```bash
# Each module has its own docker-compose.yml
cd <module>/
docker-compose build
docker-compose up -d
```

### Configuration Pattern

Each module uses `params.py` for configuration:
```python
# recon/params.py
TARGET_DOMAIN = "example.com"
SCAN_MODULES = ["domain_discovery", "port_scan", "http_probe"]
USE_TOR = False
```

Override with environment variables:
```bash
TARGET_DOMAIN=target.com docker-compose run --rm recon python /app/recon/main.py
```

### Output Format

All modules output JSON to `<module>/output/`:
```
recon/output/
├── domain_discovery.json
├── port_scan.json
├── http_probe.json
└── vuln_scan.json
```

### Neo4j Connection

```python
from graph_db import Neo4jClient

with Neo4jClient() as client:
    client.update_graph_from_domain_discovery(data, user_id, project_id)
```

Environment variables (in each module's `.env`):
```
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=<password>
```

---

## Git Workflow

- Use descriptive commit messages with prefix like fix: feat: and others
- Keep commits atomic and focused
- Branch naming: `feature/`, `fix/`, `refactor/`

---
