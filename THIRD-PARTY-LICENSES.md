# Third-Party Licenses

RedAmon integrates, bundles, or dynamically invokes the following third-party open-source software. Each component is governed by its own license. **The authors of RedAmon do not own, maintain, or provide warranty for any of these tools.** This file documents all third-party components, their licenses, and where to obtain their source code.

> **AGPL-3.0 Notice**: Several tools bundled in RedAmon's Docker images are licensed under the GNU Affero General Public License v3.0. Under AGPL-3.0, the complete corresponding source code for these tools must be made available to any user who interacts with them. Source code for all AGPL-licensed components is available at their respective repositories listed below.

---

## ProjectDiscovery Tools

These tools are either installed in Docker images or pulled as Docker containers at runtime.

| Tool | Purpose | License | Source Repository | How Used |
|------|---------|---------|-------------------|----------|
| **Naabu** | Port scanning | AGPL-3.0 | https://github.com/projectdiscovery/naabu | Installed via `go install` in `mcp/kali-sandbox/Dockerfile`; also pulled as Docker image `projectdiscovery/naabu:latest` at runtime |
| **Nuclei** | Template-based vulnerability scanning (9,000+ templates) | AGPL-3.0 | https://github.com/projectdiscovery/nuclei | Installed via `go install` in `mcp/kali-sandbox/Dockerfile`; also pulled as Docker image `projectdiscovery/nuclei:latest` at runtime |
| **Nuclei Templates** | Community vulnerability detection templates | MIT | https://github.com/projectdiscovery/nuclei-templates | Downloaded via `nuclei -update-templates` in `mcp/kali-sandbox/entrypoint.sh` |
| **Katana** | Web crawling and endpoint discovery | AGPL-3.0 | https://github.com/projectdiscovery/katana | Pulled as Docker image `projectdiscovery/katana:latest` at runtime |
| **HTTPx** | HTTP probing and technology detection | AGPL-3.0 | https://github.com/projectdiscovery/httpx | Installed via `go install` in `mcp/kali-sandbox/Dockerfile`; also pulled as Docker image `projectdiscovery/httpx:latest` at runtime |
| **Subfinder** | Subdomain enumeration via passive sources | AGPL-3.0 | https://github.com/projectdiscovery/subfinder | Pulled as Docker image `projectdiscovery/subfinder:latest` at runtime |
| **DNSx** | Fast DNS toolkit (resolution, bruteforce, wildcard filtering) | AGPL-3.0 | https://github.com/projectdiscovery/dnsx | Pulled as Docker image `projectdiscovery/dnsx:latest` at runtime |
| **Interactsh** | OOB (Out-of-Band) interaction gathering | MIT | https://github.com/projectdiscovery/interactsh | Installed via `go install` in `mcp/kali-sandbox/Dockerfile` |

---

## Exploitation & Post-Exploitation Tools

| Tool | Purpose | License | Source Repository | How Used |
|------|---------|---------|-------------------|----------|
| **Metasploit Framework** | Exploitation, post-exploitation, and payload generation | BSD-3-Clause (Rapid7) | https://github.com/rapid7/metasploit-framework | Installed via `apt-get` in `mcp/kali-sandbox/Dockerfile` |
| **Hydra** | Network login brute-force (50+ protocols) | AGPL-3.0 | https://github.com/vanhauser-thc/thc-hydra | Installed via `apt-get` in `mcp/kali-sandbox/Dockerfile` |
| **SQLMap** | Automated SQL injection detection and exploitation | GPL-2.0 | https://github.com/sqlmapproject/sqlmap | Installed via `apt-get` in `mcp/kali-sandbox/Dockerfile` |
| **John the Ripper** | Password cracking | GPL-2.0 | https://github.com/openwall/john | Installed via `apt-get` in `mcp/kali-sandbox/Dockerfile` |
| **ExploitDB** | Public exploit archive and search | GPL-2.0 | https://gitlab.com/exploit-database/exploitdb | Installed via `apt-get` in `mcp/kali-sandbox/Dockerfile` |
| **Impacket** | Python classes for working with network protocols | Apache-1.1 (modified) | https://github.com/fortra/impacket | Installed via `pip` in `mcp/requirements.txt` |
| **Pwntools** | CTF framework and exploit development library | MIT | https://github.com/Gallopsled/pwntools | Installed via `pip` in `mcp/requirements.txt` |
| **Dalfox** | XSS vulnerability scanner and parameter analysis | MIT | https://github.com/hahwul/dalfox | Installed via `go install` in `mcp/kali-sandbox/Dockerfile` |

---

## Network Scanning & Reconnaissance Tools

| Tool | Purpose | License | Source Repository | How Used |
|------|---------|---------|-------------------|----------|
| **Nmap** | Network scanning and service detection | NPSL (Nmap Public Source License) | https://github.com/nmap/nmap | Installed via `apt-get` in `mcp/kali-sandbox/Dockerfile` |
| **Masscan** | Asynchronous TCP port scanner | AGPL-3.0 | https://github.com/robertdavidgraham/masscan | Built from source in `recon/Dockerfile`; also installed via `apt-get` in `mcp/kali-sandbox/Dockerfile` |
| **Amass** | In-depth subdomain enumeration | Apache-2.0 | https://github.com/owasp-amass/amass | Pulled as Docker image `caffix/amass:latest` at runtime |
| **Knockpy** | Subdomain enumeration via wordlist | GPL-3.0 | https://github.com/guelfoweb/knock | Installed via `pip` in `recon/Dockerfile` |
| **puredns** | DNS wildcard filtering and resolution | GPL-3.0 | https://github.com/d3mondev/puredns | Pulled as Docker image `frost19k/puredns:latest` at runtime |
| **Hakrawler** | Web crawling and link discovery | MIT | https://github.com/hakluke/hakrawler | Pulled as Docker image `jauderho/hakrawler:latest` at runtime |
| **GAU (GetAllUrls)** | Passive URL discovery from web archives | MIT | https://github.com/lc/gau | Pulled as Docker image `sxcurity/gau:latest` at runtime |
| **Kiterunner** | API endpoint discovery | AGPL-3.0 | https://github.com/assetnote/kiterunner | Binary downloaded from GitHub releases at runtime |
| **jsluice** | JavaScript file analysis for endpoints and secrets | MIT | https://github.com/BishopFox/jsluice | Built from source via `go install` in `recon/Dockerfile` (multi-stage) |
| **ffuf** | Web fuzzer (directories, parameters, vhosts) | MIT | https://github.com/ffuf/ffuf | Built from source in `recon/Dockerfile`; also installed via `go install` in `mcp/kali-sandbox/Dockerfile` |
| **Arjun** | HTTP hidden parameter discovery | AGPL-3.0 | https://github.com/s0md3v/Arjun | Installed via `pip` in `recon/requirements.txt` |
| **ParamSpider** | URL parameter mining from web archives | MIT | https://github.com/devanshbatham/ParamSpider | Installed via `pip` (git) in `recon/requirements.txt` |
| **TruffleHog** | Credential and secret scanning | AGPL-3.0 | https://github.com/trufflesecurity/trufflehog | Pulled as Docker image `trufflesecurity/trufflehog:latest` at runtime; also installed as binary in `trufflehog_scan/Dockerfile` |
| **Subjack** | Subdomain takeover detection (CNAME/NS/MX/SPF + stale A records) | Apache-2.0 | https://github.com/haccer/subjack | Built from source via `go install` in `recon/Dockerfile` (multi-stage); invoked as native binary inside the recon container |
| **BadDNS** | Deep DNS takeover detection (CNAME/NS/MX/TXT/SPF/DMARC/MTA-STS/wildcard/NSEC/references/zonetransfer modules) | **AGPL-3.0** | https://github.com/blacklanternsecurity/baddns | **Isolated in its own Docker image `redamon-baddns:latest`** (built from `baddns_scan/Dockerfile` via `pip install baddns`). RedAmon never imports from this package. The recon container spawns the sidecar via `docker run --rm` and receives results as NDJSON on stdout. The process + filesystem boundary preserves the AGPL-3.0 license scope. Upstream source code is available at the linked repository. |

---

## Web Application & API Security Tools

| Tool | Purpose | License | Source Repository | How Used |
|------|---------|---------|-------------------|----------|
| **jwt_tool** | JWT token testing and exploitation | GPL-3.0 | https://github.com/ticarpi/jwt_tool | Installed via `pip` (git) in `mcp/kali-sandbox/Dockerfile` |
| **graphql-cop** | GraphQL security auditing | BSD-3-Clause | https://github.com/dolevf/graphql-cop | Installed via `pip` (git) in `mcp/kali-sandbox/Dockerfile` |
| **GraphQLmap** | GraphQL endpoint exploitation | MIT | https://github.com/swisskyrepo/GraphQLmap | Installed via `pip` (git) in `mcp/kali-sandbox/Dockerfile` |

---

## Vulnerability Assessment (GVM/OpenVAS)

| Tool | Purpose | License | Source Repository | How Used |
|------|---------|---------|-------------------|----------|
| **GVM (Greenbone Vulnerability Management)** | Network vulnerability scanning (170,000+ NVTs) | AGPL-3.0 | https://github.com/greenbone | Multiple Docker images from `registry.community.greenbone.net` in `docker-compose.yml` |
| **gvmd** | GVM management daemon | AGPL-3.0 | https://github.com/greenbone/gvmd | Docker image: `registry.community.greenbone.net/community/gvmd:stable` |
| **ospd-openvas** | OpenVAS scanner daemon | AGPL-3.0 | https://github.com/greenbone/ospd-openvas | Docker image: `registry.community.greenbone.net/community/ospd-openvas:22.7.1` |
| **pg-gvm** | GVM PostgreSQL database | AGPL-3.0 | https://github.com/greenbone/pg-gvm | Docker image: `registry.community.greenbone.net/community/pg-gvm:stable` |
| **Greenbone Redis** | GVM data store | AGPL-3.0 | https://github.com/greenbone | Docker image: `registry.community.greenbone.net/community/redis-server:stable` |
| **Greenbone Feed Data** | Vulnerability tests, SCAP, CERT, NVT data | AGPL-3.0 | https://github.com/greenbone | Docker images for `vulnerability-tests`, `notus-data`, `scap-data`, `cert-bund-data`, `dfn-cert-data`, `data-objects`, `report-formats`, `gpg-data` |
| **python-gvm** | Python API client for GVM | GPL-3.0 | https://github.com/greenbone/python-gvm | Installed via `pip` in `gvm_scan/requirements.txt` |

---

## Anonymity & Tunneling

| Tool | Purpose | License | Source Repository | How Used |
|------|---------|---------|-------------------|----------|
| **Tor** | Anonymous network routing (optional) | BSD-3-Clause | https://gitlab.torproject.org/tpo/core/tor | Installed via `apt-get` in `recon/Dockerfile` |
| **Proxychains4** | SOCKS proxy chaining | LGPL-2.1+ | https://github.com/rofl0r/proxychains-ng | Installed via `apt-get` in `recon/Dockerfile` |
| **Ngrok** | TCP tunneling for reverse shells (optional) | Proprietary (free tier) | https://ngrok.com/ | Binary downloaded in `mcp/kali-sandbox/Dockerfile` |
| **Chisel** | Multi-port TCP tunneling | MIT | https://github.com/jpillora/chisel | Binary downloaded in `mcp/kali-sandbox/Dockerfile` |

---

## DoS / Stress Testing

| Tool | Purpose | License | Source Repository | How Used |
|------|---------|---------|-------------------|----------|
| **hping3** | Packet crafting and stress testing | GPL-2.0 | https://github.com/antirez/hping | Installed via `apt-get` in `mcp/kali-sandbox/Dockerfile` |
| **slowhttptest** | Slow HTTP attack testing | Apache-2.0 | https://github.com/shekyan/slowhttptest | Installed via `apt-get` in `mcp/kali-sandbox/Dockerfile` |

---

## Technology Fingerprinting

| Tool | Purpose | License | Source Repository | How Used |
|------|---------|---------|-------------------|----------|
| **python-Wappalyzer** | Technology detection on web targets | GPL-3.0 | https://github.com/chorsley/python-Wappalyzer | Installed via `pip` in `recon/Dockerfile` |

---

## Databases

| Tool | Purpose | License | Source Repository | How Used |
|------|---------|---------|-------------------|----------|
| **Neo4j Community** | Graph database for attack surface mapping | GPL-3.0 (Neo4j Community) | https://github.com/neo4j/neo4j | Docker image: `neo4j:5.26-community` in `docker-compose.yml` |
| **PostgreSQL** | Relational database for project settings | PostgreSQL License (BSD-like) | https://github.com/postgres/postgres | Docker image: `postgres:16-alpine` in `docker-compose.yml` |

---

## Wordlists & Data Resources

| Resource | Purpose | License | Source Repository | How Used |
|----------|---------|---------|-------------------|----------|
| **SecLists** | Security assessment wordlists (directories, passwords, payloads) | MIT | https://github.com/danielmiessler/SecLists | Downloaded in `recon/Dockerfile` for web content discovery |
| **Trickest Resolvers** | Curated DNS resolver list | MIT | https://github.com/trickest/resolvers | Downloaded at runtime in `recon/entrypoint.sh` |

---

## Web Frameworks & Application Stack

These are libraries and frameworks used to build RedAmon's own web application, API servers, and agent system.

| Library | Purpose | License | Source Repository | How Used |
|---------|---------|---------|-------------------|----------|
| **Next.js** | React framework for the web dashboard | MIT | https://github.com/vercel/next.js | `webapp/package.json` |
| **React** | UI component library | MIT | https://github.com/facebook/react | `webapp/package.json` |
| **Prisma** | Database ORM and schema management | Apache-2.0 | https://github.com/prisma/prisma | `webapp/package.json` |
| **FastAPI** | Python async web framework | MIT | https://github.com/tiangolo/fastapi | `recon_orchestrator/requirements.txt`, `agentic/requirements.txt` |
| **Uvicorn** | ASGI server | BSD-3-Clause | https://github.com/encode/uvicorn | `recon_orchestrator/requirements.txt`, `agentic/requirements.txt` |
| **Pydantic** | Data validation and settings management | MIT | https://github.com/pydantic/pydantic | Multiple `requirements.txt` files |

---

## AI / Agent Framework

| Library | Purpose | License | Source Repository | How Used |
|---------|---------|---------|-------------------|----------|
| **LangChain** | LLM application framework | MIT | https://github.com/langchain-ai/langchain | `agentic/requirements.txt` |
| **LangGraph** | Multi-agent orchestration framework | MIT | https://github.com/langchain-ai/langgraph | `agentic/requirements.txt` |
| **LangChain-Anthropic** | Anthropic model integration for LangChain | MIT | https://github.com/langchain-ai/langchain | `agentic/requirements.txt` |
| **LangChain-OpenAI** | OpenAI model integration for LangChain | MIT | https://github.com/langchain-ai/langchain | `agentic/requirements.txt` |
| **LangChain-AWS** | AWS Bedrock integration for LangChain | MIT | https://github.com/langchain-ai/langchain-aws | `agentic/requirements.txt` |
| **LangChain-Neo4j** | Neo4j graph integration for LangChain | MIT | https://github.com/langchain-ai/langchain | `agentic/requirements.txt` |
| **LangChain-Tavily** | Tavily search integration for LangChain | MIT | https://github.com/langchain-ai/langchain | `agentic/requirements.txt` |
| **LangChain-MCP-Adapters** | MCP server integration for LangChain | MIT | https://github.com/langchain-ai/langchain-mcp-adapters | `agentic/requirements.txt` |
| **FastMCP** | Fast Model Context Protocol server framework | MIT | https://github.com/jlowin/fastmcp | `mcp/requirements.txt` |
| **MCP SDK** | Model Context Protocol Python SDK | MIT | https://github.com/modelcontextprotocol/python-sdk | `mcp/requirements.txt` |

---

## Key Python Libraries

| Library | Purpose | License | Source Repository | How Used |
|---------|---------|---------|-------------------|----------|
| **Docker SDK for Python** | Docker API client | Apache-2.0 | https://github.com/docker/docker-py | `recon_orchestrator/requirements.txt` |
| **neo4j (Python driver)** | Neo4j database driver | Apache-2.0 | https://github.com/neo4j/neo4j-python-driver | Multiple `requirements.txt` files |
| **PyGithub** | GitHub API v3 client | LGPL-3.0 | https://github.com/PyGithub/PyGithub | `recon/requirements.txt`, `github_secret_hunt/requirements.txt`, `agentic/requirements.txt` |
| **GitPython** | Git repository interaction | BSD-3-Clause | https://github.com/gitpython-developers/GitPython | `agentic/requirements.txt` |
| **Paramiko** | SSH2 protocol library | LGPL-2.1 | https://github.com/paramiko/paramiko | `mcp/requirements.txt` |
| **Boto3** | AWS SDK for Python | Apache-2.0 | https://github.com/boto/boto3 | `agentic/requirements.txt` |
| **BeautifulSoup4** | HTML/XML parsing | MIT | https://www.crummy.com/software/BeautifulSoup/ | `mcp/requirements.txt` |
| **httpx** | Async HTTP client for Python | BSD-3-Clause | https://github.com/encode/httpx | `mcp/requirements.txt`, `agentic/requirements.txt` |
| **Requests** | HTTP library for Python | Apache-2.0 | https://github.com/psf/requests | Multiple `requirements.txt` files |
| **dnspython** | DNS toolkit for Python | ISC | https://github.com/rthalley/dnspython | `recon/requirements.txt` |
| **python-whois** | WHOIS lookup library | MIT | https://github.com/richardpenman/whois | `recon/requirements.txt` |
| **xmltodict** | XML to Python dict parser | MIT | https://github.com/martinblech/xmltodict | `gvm_scan/requirements.txt` |
| **SSE-Starlette** | Server-Sent Events for Starlette/FastAPI | BSD-3-Clause | https://github.com/sysid/sse-starlette | `recon_orchestrator/requirements.txt`, `mcp/requirements.txt` |
| **websockets** | WebSocket client and server library | BSD-3-Clause | https://github.com/python-websockets/websockets | `mcp/requirements.txt`, `agentic/requirements.txt` |
| **PyYAML** | YAML parser and emitter | MIT | https://github.com/yaml/pyyaml | `mcp/requirements.txt` |
| **PyCryptodome** | Cryptographic library | BSD-2-Clause | https://github.com/Legrandin/pycryptodome | `mcp/requirements.txt` |
| **PyJWT** | JSON Web Token implementation | MIT | https://github.com/jpadilla/pyjwt | `mcp/requirements.txt` |
| **NetworkX** | Graph/network analysis library | BSD-3-Clause | https://github.com/networkx/networkx | `agentic/requirements.txt` |
| **tree-sitter** | Incremental parsing system | MIT | https://github.com/tree-sitter/tree-sitter | `agentic/requirements.txt` |
| **tree-sitter-languages** | Pre-built Tree-sitter language grammars | MIT | https://github.com/grantjenks/py-tree-sitter-languages | `agentic/requirements.txt` |

---

## Key Node.js Libraries

| Library | Purpose | License | Source Repository | How Used |
|---------|---------|---------|-------------------|----------|
| **neo4j-driver** | Neo4j database driver for Node.js | Apache-2.0 | https://github.com/neo4j/neo4j-javascript-driver | `webapp/package.json` |
| **@tanstack/react-query** | Async state management for React | MIT | https://github.com/TanStack/query | `webapp/package.json` |
| **@tanstack/react-table** | Headless table UI for React | MIT | https://github.com/TanStack/table | `webapp/package.json` |
| **XTerm.js** | Terminal emulator for the browser | MIT | https://github.com/xtermjs/xterm.js | `webapp/package.json` (`@xterm/xterm`, `@xterm/addon-fit`, `@xterm/addon-web-links`) |
| **Three.js** | 3D graphics library | MIT | https://github.com/mrdoob/three.js | `webapp/package.json` |
| **react-force-graph-2d/3d** | Force-directed graph visualization | MIT | https://github.com/vasturiano/react-force-graph | `webapp/package.json` |
| **Recharts** | Charting library for React | MIT | https://github.com/recharts/recharts | `webapp/package.json` |
| **react-markdown** | Markdown renderer for React | MIT | https://github.com/remarkjs/react-markdown | `webapp/package.json` |
| **react-syntax-highlighter** | Syntax highlighting for React | MIT | https://github.com/react-syntax-highlighter/react-syntax-highlighter | `webapp/package.json` |
| **remark-gfm** | GitHub Flavored Markdown plugin | MIT | https://github.com/remarkjs/remark-gfm | `webapp/package.json` |
| **Lucide React** | Icon library for React | ISC | https://github.com/lucide-icons/lucide | `webapp/package.json` |
| **Archiver** | Streaming archive generation (ZIP) | MIT | https://github.com/archiverjs/node-archiver | `webapp/package.json` |
| **JSZip** | ZIP file creation and reading | MIT / GPL-3.0 (dual) | https://github.com/Stuk/jszip | `webapp/package.json` |
| **SheetJS (xlsx)** | Spreadsheet parser and writer | Apache-2.0 | https://github.com/SheetJS/sheetjs | `webapp/package.json` |
| **pdf-parse** | PDF text extraction | MIT | https://gitlab.com/nicola.zanon/pdf-parse | `webapp/package.json` |
| **Mammoth** | DOCX to HTML/Markdown converter | BSD-2-Clause | https://github.com/mwilliamson/mammoth.js | `webapp/package.json` |
| **d3-force** | Force-directed graph layout | ISC | https://github.com/d3/d3-force | `webapp/package.json` |
| **three-spritetext** | Text sprites for Three.js | MIT | https://github.com/vasturiano/three-spritetext | `webapp/package.json` |
| **TypeScript** | Typed JavaScript superset | Apache-2.0 | https://github.com/microsoft/TypeScript | `webapp/package.json` (devDependency) |
| **ESLint** | JavaScript/TypeScript linter | MIT | https://github.com/eslint/eslint | `webapp/package.json` (devDependency) |
| **Vitest** | Unit testing framework | MIT | https://github.com/vitest-dev/vitest | `webapp/package.json` (devDependency) |

---

## Guinea Pig / Vulnerable Test Applications

These are intentionally vulnerable applications included for testing purposes only.

| Application | Purpose | License | Source Repository | How Used |
|-------------|---------|---------|-------------------|----------|
| **DVWS-Node** | Damn Vulnerable Web Services (Node.js) | MIT | https://github.com/snoopysecurity/dvws-node | Cloned in `guinea_pigs/dvws-node/setup.sh` |
| **Log4Shell Vulnerable App** | Log4j RCE demonstration (CVE-2021-44228) | Apache-2.0 | https://github.com/christophetd/log4shell-vulnerable-app | Docker image: `ghcr.io/christophetd/log4shell-vulnerable-app:latest` |
| **vsftpd 2.3.4** | Backdoored FTP server (CVE-2011-2523) | GPL-2.0 | N/A (pre-built image) | Docker image: `clintmint/vsftpd-2.3.4:1.0` |
| **Apache Tomcat 8.5.19** | JSP upload RCE (CVE-2017-12617) | Apache-2.0 | https://github.com/vulhub/vulhub | Docker image: `vulhub/tomcat:8.5.19` |
| **Apache httpd 2.4.49** | Path traversal RCE (CVE-2021-41773) | Apache-2.0 | https://github.com/apache/httpd | Built from source in `guinea_pigs/apache_2.4.49/Dockerfile` |
| **Apache httpd 2.4.25** | Auth bypass (CVE-2017-3167) | Apache-2.0 | https://github.com/apache/httpd | Built from source in `guinea_pigs/apache_2.4.25/Dockerfile` |
| **node-serialize 0.0.4** | Deserialization RCE demo | MIT | https://github.com/luin/serialize | Built from `guinea_pigs/node_serialize_1.0.0/Dockerfile` |

---

## Runtime Languages & Build Tools (in Agent Container)

The agent container (`agentic/Dockerfile`) bundles multiple language runtimes for code analysis:

| Tool | Version | License | How Used |
|------|---------|---------|----------|
| **Node.js** | 20 LTS | MIT | Installed in `agentic/Dockerfile` |
| **Go** | 1.22.10 | BSD-3-Clause | Installed in `agentic/Dockerfile` |
| **Ruby** + Bundler | System | BSD-2-Clause / MIT | Installed via `apt-get` in `agentic/Dockerfile` |
| **OpenJDK** + Maven | Headless | GPL-2.0 (w/ Classpath Exception) / Apache-2.0 | Installed via `apt-get` in `agentic/Dockerfile` |
| **PHP** + Composer | CLI | PHP-3.01 / MIT | Installed via `apt-get` in `agentic/Dockerfile` |
| **.NET SDK** | 8 | MIT | Installed in `agentic/Dockerfile` |
| **ripgrep** | System | MIT / Unlicense (dual) | Installed via `apt-get` in `agentic/Dockerfile` |

---

## AGPL-3.0 Source Code Availability

In compliance with the AGPL-3.0 license, the complete corresponding source code for all AGPL-licensed components is available at the repositories listed above. If you have received a RedAmon Docker image containing any of these tools and cannot access their source code at the listed repositories, please contact the maintainers at devergo.sam@gmail.com and we will provide the source code.

## License Compatibility Note

RedAmon's own source code is released under the **MIT License**.

### Separate-process tools (CLI / Docker containers)

The majority of third-party tools are invoked as **separate processes** via CLI commands, Docker containers, or network APIs. Under the GPL, AGPL, and related copyleft licenses this constitutes "mere aggregation" (GPL v3 sec. 5, AGPL v3 sec. 5) and does **not** require RedAmon's own source code to adopt a copyleft license. Any modifications made to those tools themselves must still comply with their respective licenses.

### GPL-3.0 libraries linked at the Python import level

The following GPL-3.0-licensed Python libraries are **imported directly** into RedAmon source code. Under the GPL-3.0, the resulting combined work in each container must be distributed under GPL-3.0-compatible terms:

| Library | License | Container | Source files affected |
|---------|---------|-----------|----------------------|
| **python-gvm** | GPL-3.0 | `gvm_scan` | All `.py` files in `gvm_scan/` |
| **python-Wappalyzer** | GPL-3.0 | `recon` | Files in `recon/` that import Wappalyzer |

Accordingly, **the Python source files listed above are dual-licensed MIT AND GPL-3.0**. You may use, copy, and distribute them under either license. When they are combined with the GPL-3.0 libraries they import, the combined executable is governed by the GPL-3.0.

All other RedAmon source code (the webapp, the agent, the recon orchestrator, MCP servers, shell scripts, Dockerfiles, and configuration) remains under the MIT License only.

### LGPL libraries

Several LGPL-licensed libraries (PyGithub, Paramiko, Proxychains4) are used via standard Python imports or dynamic linking. The LGPL explicitly permits this without requiring the calling code to adopt LGPL or GPL terms, provided the libraries can be replaced or re-linked by the end user. Since RedAmon installs these via standard `pip` (user-replaceable), this condition is satisfied.

### AGPL network-interaction obligation

AGPL-3.0 extends the GPL-3.0 copyleft to users who interact with the software **over a network**. Several tools in RedAmon (GVM/OpenVAS, Nuclei, Naabu, Katana, HTTPx, Subfinder, DNSx, Masscan, TruffleHog, Hydra, Kiterunner, Arjun) are AGPL-3.0. RedAmon does not modify any of these tools. Their unmodified source code is available at the repositories listed in this document. If you modify any AGPL-3.0 component and make it available over a network, you must offer the corresponding source code to users of that network service.

---

*Last updated: March 2026*
