# NEW TOOL IN RECON PIPELINE

Integrate **[TOOL_NAME]** into the RedAmon recon pipeline.

### Critical Rules

- **Python import safety**: The `recon_orchestrator` container volume-mounts source code (`./recon_orchestrator:/app`). Adding a new Python `import` that isn't already installed in the container image will **crash-loop** the service. Before importing any package, verify it exists in `recon_orchestrator/requirements.txt` or the `recon_orchestrator/Dockerfile`. If it's missing, add it and rebuild: `docker compose build recon-orchestrator`.
- **Don't break existing tools**: Adding a new tool must NOT modify the behavior, output format, or settings of any existing tool. If you change a shared file (e.g., `recon/project_settings.py`, `recon/main.py`), verify that all existing tools still work after your changes.
- **Container restart rules**: The `recon_orchestrator` container volume-mounts code — changes are live immediately. The `recon` container is built fresh per scan job, so Dockerfile changes require `docker compose build recon`. Frontend changes require `docker compose build webapp`.
- **Build/restart quick reference**:
  - Changed `recon/Dockerfile` or `recon/entrypoint.sh` → `docker compose build recon`
  - Changed `recon_orchestrator/*.py` → `docker compose restart recon-orchestrator`
  - Changed `recon/*.py` → no restart needed (spawned fresh per job), but rebuild if Dockerfile changed
  - Changed `webapp/prisma/schema.prisma` → `docker compose exec webapp npx prisma db push`
  - Changed `webapp/src/**` → `docker compose build webapp && docker compose up -d webapp`

### Phase 1: Research (do NOT write code yet)

1. **Tool research** — Search the tool's official documentation, GitHub repository, and README online. Determine:
   - **Integration type**: Does it have an official Docker image? A Python/Go library? A REST API? Is it CLI-only?
   - **Is it passive or active?** (passive = queries third-party APIs/databases only, active = sends traffic to target)
   - **Dependencies**: Does it need external binaries, wordlists, resolver lists, config files?
   - **API keys**: Does it use API keys? Can it run without them?

2. **Tool output** — Based on the integration type determined above, test the tool and capture its **exact output schema**:
   - If Docker image available: run `docker run <image> -h` to study all CLI flags, then run a real query against a safe target (e.g., `example.com`) with JSON output enabled to capture field names, types, and structure.
   - If API-based: study the API docs, endpoints, request/response schemas.
   - If Python library: study the package docs and return types.

3. **Choose integration pattern** — Based on the research above, match to the existing codebase patterns:
   - **Docker-in-Docker** (Naabu, httpx, Katana, Nuclei, GAU): `subprocess.run(['docker', 'run', '--rm', ...])` — see `recon/port_scan.py`, `recon/resource_enum.py`
   - **Direct subprocess** (Knockpy): `subprocess.run(['toolname', ...])` — see `recon/domain_recon.py`
   - **API/HTTP calls** (crt.sh, HackerTarget, URLScan, Shodan): `requests.get(...)` — see `recon/domain_recon.py`, `recon/urlscan_enrich.py`, `recon/shodan_enrich.py`

   If the tool has an official Docker image, prefer Docker-in-Docker. If it's a simple API, use HTTP calls. Only use direct subprocess if the tool is a pip package already in the container.

3. **Identify the pipeline phase** — Read `recon/main.py` to understand the phase structure. Determine which phase the tool belongs to and where its results feed into.

4. **Settings multi-layer flow** — Every new setting must be added in ALL these layers (miss one and it breaks):
   - `webapp/prisma/schema.prisma` — field with `@default()` and `@map()` (camelCase field, snake_case DB column)
   - `recon/project_settings.py` → `DEFAULT_SETTINGS` dict (SCREAMING_SNAKE_CASE keys)
   - `recon/project_settings.py` → `fetch_project_settings()` mapping (camelCase from DB → SCREAMING_SNAKE_CASE for Python)
   - `recon_orchestrator/api.py` → `GET /defaults` endpoint (include in served defaults)
   - `recon_orchestrator/api.py` → `RUNTIME_ONLY_KEYS` set (only if the setting should NOT appear in defaults)
   - Frontend section component (with fallback default in `onChange`)
   - **Naming convention**: `tool_setting` (DB column) → `toolSetting` (Prisma/frontend) → `TOOL_SETTING` (Python)

5. **Frontend settings page** — Study `webapp/src/components/projects/ProjectForm/ProjectForm.tsx` to find which tab the tool belongs to. Study existing section components in `webapp/src/components/projects/ProjectForm/sections/` — each has: collapsible header, toggle, description, badges (Passive/Active), conditional parameter inputs, and `NodeInfoTooltip` from `nodeMapping.ts`. Study how API key checks work in `ShodanSection.tsx` and `UrlscanSection.tsx` if the tool needs keys.

6. **API key handling** — Determine if the tool uses API keys (for external data sources, premium features, higher rate limits, etc.). If yes: check if the tool works **without** API keys (degraded/limited mode) and **with** them (full coverage). Follow the existing pattern: API keys are stored in the `UserSettings` model in Prisma (global, per-user, NOT per-project). At runtime, fetch via `_fetch_user_api_key()` in `recon/project_settings.py` using `?internal=true` for unmasked values. In the frontend section component, check key status via `/api/users/{userId}/settings` and show an info banner (like `ShodanSection.tsx` and `UrlscanSection.tsx` do): if key is set, use it; if empty, tool runs without it (reduced results but still functional). Study `webapp/src/app/api/users/[id]/settings/route.ts` for the GET/PUT pattern and the key masking logic.

7. **Graph DB integration** — Read `readmes/GRAPH.SCHEMA.md` for the full node/relationship schema. `graph_db/neo4j_client.py` is now a **thin orchestrator** (30 lines) — the actual graph methods live in the mixin files under `graph_db/mixins/`. For a new OSINT enrichment tool, the method goes in `graph_db/mixins/osint_mixin.py`. For a new core recon phase, it goes in `graph_db/mixins/recon_mixin.py`. Find the `update_graph_from_*()` method in the relevant mixin that is closest to the new tool's output type. Understand MERGE keys (always `(name/address, user_id, project_id)`), `ON CREATE SET` vs unconditional `SET`, and deduplication with existing nodes from other tools.

8. **RoE (Rules of Engagement) scope** — Study how the RoE settings affect tool execution. Check `recon/main.py` and the RoE tab in `ProjectForm.tsx` to understand how scope restrictions (allowed domains, IPs, excluded targets) are enforced. Determine if the new tool's output could include out-of-scope results (e.g., subdomains of unrelated domains, IPs outside allowed ranges) and ensure results are filtered against the RoE before being stored. Study how existing tools handle scope filtering — e.g., `domain_recon.py` splits results into in-scope `subdomains` vs out-of-scope `external_domains`.

9. **Output format** — Study how the tool's results merge into the combined recon JSON output in `recon/main.py`. Determine if results extend an existing section (e.g., subdomains into `discover_subdomains()` return) or need a new section in the combined output.

10. **Report integration** — The reports page (`/reports`) generates HTML reports from Neo4j data. Study the report pipeline to plan how the new tool's findings will appear:
   - `webapp/src/lib/report/reportData.ts` — contains query functions that pull tool data from Neo4j (e.g., `queryTrufflehog`, `querySecrets`, `queryJsRecon`, `queryOtx`), the `ReportData` interface, the `gatherReportData()` orchestrator, and the **risk score** calculation. Each tool has a dedicated `queryX()` function that runs Cypher queries filtered by `{project_id: $pid}` and returns structured data (totals, breakdowns by severity/type, and capped findings lists — typically max 50 items).
   - `webapp/src/lib/report/reportTemplate.ts` — contains `renderX()` functions that produce conditional HTML sections (only rendered if findings > 0), and the dynamic TOC builder that includes/excludes sections based on data availability.
   - `webapp/src/app/api/projects/[id]/reports/route.ts` — the POST handler that orchestrates data gathering, optional LLM narrative generation (via `condenseForAgent()`), and HTML generation. The `condenseForAgent()` function sends a summarized subset (15-20 items per tool) to the agent service for narrative text.
   - **Risk score**: Every tool contributes a weighted score to the overall risk metric. Study the `rawRisk` calculation in `reportData.ts` to determine the appropriate weight for the new tool (e.g., Trufflehog: verified=80pts, unverified=30pts; OTX: pulses=20pts, malware=50pts; JsRecon: high/critical=40pts).
   - **Existing pattern summary**: For each tool, there is (1) a TypeScript interface for its findings, (2) a `queryX()` function with Neo4j Cypher, (3) a section in the `ReportData` interface, (4) a call in `gatherReportData()`, (5) a `renderX()` function, (6) a TOC entry, (7) a risk score contribution, and (8) a condensed payload in `condenseForAgent()`.

11. **Workflow view integration** — The project settings form has a visual workflow view (`webapp/src/components/projects/ProjectForm/WorkflowView/`) that renders the entire recon pipeline as an interactive node graph. Study these files to plan the new tool's integration:

   - **`workflowDefinition.ts`** — Central registry. Contains:
     - `WORKFLOW_TOOLS` array: each tool has `{ id, label, enabledField, group, badge }`. The `id` must match the key used in `nodeMapping.ts`. The `group` number determines the pipeline phase/column (1=Discovery, 2=OSINT, 3=Port Scanning, 4=HTTP Probing, 5=Resource Enum, 5.5=JS Recon, 6=Vuln Scanning, 7=CVE & MITRE, 8=Security Checks). The `badge` is `'active'`, `'passive'`, or `'both'`.
     - `UNIVERSAL_DATA_NODES` (Domain, Subdomain, IP) — always shown, provided by Input node.
     - `TRANSITIONAL_DATA_NODES` — shown only when connected to at least one tool.
     - `DATA_NODE_CATEGORIES` — maps each data node type to a category (`identity`, `network`, `web`, `technology`, `security`, `external`) which determines its color.
     - `WORKFLOW_GROUPS` — group metadata with label and color.
   
   - **`nodeMapping.ts`** — Two critical maps:
     - `SECTION_INPUT_MAP[toolId]` — array of data node types the tool **consumes** (its inputs). These create edges FROM the data node TO the tool.
     - `SECTION_NODE_MAP[toolId]` — array of data node types the tool **produces** (its outputs). These create edges FROM the tool TO the data node.
     - The workflow graph uses these maps to automatically wire edges, compute data flow status (active vs starved), and detect broken chains.
   
   - **`workflowLayout.ts`** — Three-band layout engine:
     - Upper band: data nodes that serve as inputs to tools (Domain, Subdomain, IP, Port, BaseURL, Endpoint, CVE, Service).
     - Center band: tool nodes arranged by group column left-to-right.
     - Lower band: data nodes that are outputs/enrichments (DNSRecord, ExternalDomain, Technology, Vulnerability, etc.).
     - `getDataPlacement()` has an explicit placement map assigning each data node to `{ band: 'upper'|'lower', row: number }`. If the new tool produces a **new data node type**, it must be added here. Row 0 is closest to tools, higher rows are farther.
   
   - **`WorkflowNodeModal.tsx`** — Modal that opens when clicking a tool node. Has a `switch(toolId)` that renders the tool's settings section component. The new tool needs a case here.
   
   - **`useWorkflowGraph.ts`** — Builds React Flow nodes and edges from the definitions. Computes:
     - Data node status: "active" if at least one enabled tool is a TRUE SOURCE (produces it without consuming it), otherwise "starved" (pulsing red).
     - Tool chain-broken status: if any consumed transitional data node is starved.
     - Edge colors: category-colored when active, grey when disabled, red when starved.
     - No changes needed here for a new tool — it reads from `workflowDefinition.ts` and `nodeMapping.ts` automatically.

   **Decision checklist for workflow integration:**
   1. Determine the `group` number (which pipeline phase column).
   2. Determine the `badge` type (`'active'`, `'passive'`, or `'both'`).
   3. List all data node types consumed (inputs) and produced (outputs).
   4. Check if any produced data types are NEW (not in `ALL_WORKFLOW_DATA_NODES`). If so, add them to `TRANSITIONAL_DATA_NODES`, `DATA_NODE_CATEGORIES`, and `getDataPlacement()` in the layout.
   5. Check if existing data nodes need to be added to the tool's input/output maps (e.g., if the tool also enriches existing node types).

12. **Parallelization opportunities (fan-out / fan-in)** — Determine which execution group in `recon/main.py` the new tool belongs to. The pipeline runs these groups in strict order; tools within a group run in parallel via `ThreadPoolExecutor`:

   | Group | Execution | Tools | Input dependency |
   |-------|-----------|-------|------------------|
   | **GROUP 1** | Parallel (`max_workers=3`) | WHOIS, Subdomain Discovery (crt.sh + HackerTarget + Subfinder + Amass + Knockpy internally parallel), URLScan | Root domain only (no prior group) |
   | **DNS** | Sequential | dnspython (`resolve_all_dns`, 20 workers internally) | GROUP 1 subdomains |
   | **GROUP 2b** | Sequential, conditional | Uncover Target Expansion | DNS results; requires `OSINT_ENRICHMENT_ENABLED` + `UNCOVER_ENABLED` |
   | **GROUP 3** | Parallel (`max_workers=3`) | Shodan, Naabu, Masscan | DNS-resolved IPs/hostnames |
   | **GROUP 3.5** | Sequential | Nmap (-sV, --script vuln) | GROUP 3 merged port_scan data |
   | **GROUP 3b** | Parallel (`max_workers=5`), independent of GROUP 3/3.5 | Censys, FOFA, OTX, Netlas, VirusTotal, ZoomEye, CriminalIP | DNS results only (passive OSINT, no port data needed) |
   | **GROUP 4** | Sequential (httpx internally parallel) | httpx HTTP probe + Wappalyzer | GROUP 3 open ports + hostnames |
   | **GROUP 5** | Mixed -- 4 parallel then 4 sequential | **Parallel**: Katana, Hakrawler, GAU, ParamSpider (`max_workers=4`). **Then sequential**: Kiterunner, jsluice (post-crawl), FFuf (post-jsluice), Arjun (post-FFuf). Then GAU results merged last. | GROUP 4 live URLs |
   | **GROUP 5b** | Sequential (runs even if active scans skipped) | JS Recon | Resource enum output + uploaded JS files |
   | **GROUP 6** | Sequential (Nuclei internally parallel) | Nuclei vuln scan, then MITRE enrichment | GROUP 4 live URLs |

   **Rules for placing a new tool:**
   - If it's a passive OSINT enrichment (queries third-party APIs, no traffic to target): add to **GROUP 3b** -- register it in the `_osint_tools` dict and provide a `run_X_enrichment_isolated()` wrapper (deep-copies `combined_result` so threads don't conflict).
   - If it's a new subdomain discovery source: add to **GROUP 1** inside `discover_subdomains()` in `recon/domain_recon.py` (internally parallel).
   - If it's a new port scanner or active host enrichment: add to **GROUP 3**.
   - If it's a new URL discovery / crawling tool: add to the parallel phase of **GROUP 5** (the `ThreadPoolExecutor(max_workers=4)` block).
   - If it's a new post-crawl analysis tool (needs crawled URLs): add to the sequential phase of **GROUP 5** after the parallel block.
   - Any tool added to a parallel fan-out group **must** use the `_isolated` wrapper pattern: `run_X_isolated(combined_result, settings)` that deep-copies the input, runs the tool on the copy, and returns only the tool's result dict. See `recon/censys_enrich.py` or `recon/shodan_enrich.py` for the pattern.
   - **Never parallelize across dependency boundaries** -- if the tool needs port scan results, it cannot run in GROUP 3; if it needs live URLs, it cannot run before GROUP 4.

### Phase 2: Implementation checklist

- [ ] Tool runner function in the appropriate `recon/*.py` file following the **enrichment module contract**:
  - Main function `run_X_enrichment(combined_result: dict, settings: dict) -> dict` — mutates `combined_result` in place by writing to `combined_result["toolname"]` and returns it
  - The top-level key **must match** the tool identifier used everywhere else in the pipeline (e.g. `combined_result["virustotal"]`, `combined_result["censys"]`) — never abbreviate or vary the name
  - Isolated wrapper `run_X_enrichment_isolated(combined_result: dict, settings: dict) -> dict` — shallow-copies `combined_result`, calls the main runner on the copy, returns only the tool's payload dict (e.g. `snapshot.get("toolname", {})`). This is the **actual call path** used by GROUP 3b fan-out in `recon/main.py` and by all unit tests — it must be present
  - If the tool uses API keys: follow the `_effective_key(api_key, key_rotator)` pattern. Copy this helper verbatim from an existing module (e.g. `censys_enrich.py`). Add a `TOOL_KEY_ROTATOR` settings key alongside `TOOL_API_KEY` so key rotation is supported from day one
- [ ] Settings keys in `recon/project_settings.py` (`DEFAULT_SETTINGS` + `fetch_project_settings()` mapping)
- [ ] Prisma schema fields in `webapp/prisma/schema.prisma`
- [ ] Run `docker compose exec webapp npx prisma db push` (never use `prisma migrate`)
- [ ] Docker image added to `recon/entrypoint.sh` IMAGES array (if Docker-based)
- [ ] Docker image setting (e.g. `TOOL_DOCKER_IMAGE`) in `DEFAULT_SETTINGS` (if Docker-based)
- [ ] Temp files in `/tmp/redamon/`, cleaned up in `finally` block
- [ ] Frontend section component in `webapp/src/components/projects/ProjectForm/sections/`
- [ ] Section imported and rendered in `ProjectForm.tsx` under the correct tab
- [ ] Section exported from `sections/index.ts`
- [ ] `SECTION_INPUT_MAP` and `SECTION_NODE_MAP` updated in `nodeMapping.ts` — list ALL data node types the tool consumes (inputs) and produces (outputs). These drive the workflow graph edges automatically.
- [ ] **Workflow view** (`webapp/src/components/projects/ProjectForm/WorkflowView/`):
  1. Add entry to `WORKFLOW_TOOLS` in `workflowDefinition.ts` with correct `id` (must match `nodeMapping.ts` key), `label`, `enabledField` (camelCase Prisma field), `group` (pipeline phase number), and `badge` (`'active'`, `'passive'`, or `'both'`)
  2. If tool produces **new data node types** not already in `TRANSITIONAL_DATA_NODES`: add them to `TRANSITIONAL_DATA_NODES` and `DATA_NODE_CATEGORIES` in `workflowDefinition.ts`, and add placement to `getDataPlacement()` in `workflowLayout.ts` (choose `band: 'upper'` for nodes consumed by later tools, `band: 'lower'` for terminal outputs/enrichments; `row: 0` closest to tools, higher rows farther)
  3. Add a `case 'ToolId':` to the `switch(toolId)` in `WorkflowNodeModal.tsx` that renders the tool's section component (import it at the top of the file). Use `baseProps` for sections that only need `{ data, updateField }`, or `extendedProps` for sections that also need `{ projectId, mode }`
  4. No changes needed in `useWorkflowGraph.ts` or `workflowLayout.ts` (unless adding new data node types) — they read from the definition files automatically
- [ ] `/defaults` endpoint updated in `recon_orchestrator/api.py`
- [ ] Graph DB: add or extend the appropriate `update_graph_from_*()` method in the correct mixin — `graph_db/mixins/osint_mixin.py` for OSINT enrichment tools, `graph_db/mixins/recon_mixin.py` for core recon phases. Do NOT edit `graph_db/neo4j_client.py` directly — it is a thin orchestrator that only imports the mixins.
- [ ] **Graph completeness**: Cross-check every field stored in the enrichment output dict (`combined_result["toolname"]`) against the `update_graph_from_*()` method — every collected field must be written to a node property or relationship. Silently dropping a field (collecting it in the enrichment module but never reading it in the graph method) is a data loss bug. If a field doesn't fit any existing node, either map it to the closest existing property or document explicitly why it is intentionally omitted.
- [ ] **Graph node reuse**: Before creating new node labels, check if the tool's output can be mapped to **existing** node types in `readmes/GRAPH.SCHEMA.md`. For example, discovered hostnames should go into `Subdomain`, not a new label. Only introduce new node labels if the data genuinely doesn't fit any existing type.
- [ ] **Schema sync (mandatory for every tool)**: If the tool writes **any** data to Neo4j — new node labels, new relationships, or new properties on existing nodes — update **ALL** of these. This applies even when adding properties to existing node types (e.g., new enrichment flags on `IP`, new fields on `Service`):
  1. `readmes/GRAPH.SCHEMA.md` — the canonical schema reference
  2. `agentic/prompts/base.py` — the `TEXT_TO_CYPHER_SYSTEM` prompt (LLM-facing schema for natural-language-to-Cypher). Missing this will cause the AI agent to generate incorrect Cypher or fail to expose the new data in queries.
  3. `webapp/src/app/graph/config/colors.ts` — add entry to `NODE_COLORS` dict with an appropriate color for the new node type (read existing color families as reference)
  4. `webapp/src/app/graph/config/colors.ts` — add entry to `NODE_SIZES` if the new node type needs a non-default size
  5. `webapp/src/app/graph/components/DataTable/DataTableToolbar.tsx` — add the new node type to the type filter dropdown so users can filter by it
  6. `webapp/src/app/graph/components/PageBottomBar/PageBottomBar.tsx` — add the new node type to the legend if applicable
- [ ] **Report data layer** (`webapp/src/lib/report/reportData.ts`):
  1. Add a TypeScript interface for the tool's findings (e.g., `MyToolRecord`) with all fields queried from Neo4j
  2. Add a new section to the `ReportData` interface (e.g., `myTool: { totalFindings: number; bySeverity: ...; findings: MyToolRecord[] }`)
  3. Create a `queryMyTool(session, pid)` function with Cypher queries — must filter by `{project_id: $pid}`, include summary counts + breakdowns, and cap detailed findings (typically 50 items)
  4. Call the new query function in `gatherReportData()` and include its result in the returned `ReportData` object
  5. Add the tool's weighted contribution to the `rawRisk` score calculation — choose weights consistent with existing tools (study the risk score block for reference)
  6. If the tool produces secrets/credentials, also add its count to the `metrics.secretsExposed` total
- [ ] **Report template** (`webapp/src/lib/report/reportTemplate.ts`):
  1. Create a `renderMyTool(data: ReportData): string` function that returns an HTML section — must be **conditional** (return empty string if no findings), include a `page-break` div, and use a unique `id` for the section anchor
  2. Add the section to the **dynamic TOC** builder (look for `dynamicSections.push(...)`) — only include if findings > 0
  3. Call `renderMyTool(data)` in the main `generateReportHtml()` function alongside the other render calls
- [ ] **Report LLM condensing** (`webapp/src/app/api/projects/[id]/reports/route.ts`):
  1. Add the tool's summarized data to the `condenseForAgent()` payload — include totals, breakdowns, and a capped subset of findings (15-20 items max) so the LLM can generate narrative text about the tool's results
- [ ] If tool needs API keys: add field to `UserSettings` model in Prisma, fetch at runtime via `_fetch_user_api_key()`, show key status banner in frontend section. **Also update the API keys import/export template** (see checklist item below).
- [ ] **API Keys Import/Export Template** (only if tool uses API keys stored in `UserSettings`):
  Update `webapp/src/lib/apiKeysTemplate.ts`: add new key to `ALLOWED_KEY_FIELDS` and rotation tool name to `ALLOWED_ROTATION_TOOLS`. Update test counts in `webapp/src/lib/apiKeysTemplate.test.ts` to match.
- [ ] If tool is active (sends traffic to target): add overrides in `apply_stealth_overrides()` in `recon/project_settings.py`
- [ ] If tool is involved in subdomain enumeration: results may include out-of-scope subdomains (e.g., related but not under the target root domain). These must be split into in-scope `subdomains` vs `external_domains` — follow the existing pattern in `recon/domain_recon.py` where discovered subdomains are checked against the target domain and out-of-scope entries are collected separately as external domains
- [ ] **Logging format**: All `print()` log lines MUST follow the standard `[symbol][ToolName] message` format used throughout the recon pipeline. The symbol prefix indicates the log level/type:
   - `[*][ToolName]` — informational / progress (e.g., `[*][Naabu] Starting scan...`)
   - `[+][ToolName]` — success / positive result (e.g., `[+][Subfinder] Found 42 subdomains`)
   - `[-][ToolName]` — negative result or skipped (e.g., `[-][crt.sh] Disabled — skipping`)
   - `[!][ToolName]` — error / warning (e.g., `[!][Amass] Error: timeout`)
   - `[✓][ToolName]` — completed / verified (e.g., `[✓][Naabu] Image already available`)
   - `[⚡]` — special mode indicator (e.g., `[⚡] BRUTEFORCE MODE`)

   See `recon/domain_recon.py`, `recon/port_scan.py`, `recon/whois_recon.py` for reference. Never use bare `print()` without the `[symbol][ToolName]` prefix.
- [ ] **Recon Presets** (`webapp/src/lib/recon-presets/presets/*.ts`):
  Hardcoded parameter presets exist in `webapp/src/lib/recon-presets/presets/`. Each preset is a partial dictionary of camelCase project settings that override defaults when a user selects it. When adding a new tool:
  1. Review EVERY preset file in the `presets/` folder
  2. For each preset, decide: should this new tool be **enabled or disabled** given the preset's stated goal? Read the preset's `fullDescription` to understand its intent (e.g., "JS Secret Miner" is JS-focused and disables irrelevant tools)
  3. If the tool should be disabled in a preset, add `toolEnabled: false` to that preset's `parameters` object
  4. If the tool should be enabled with non-default settings (e.g., higher limits, specific mode), add those parameters to the preset
  5. If the tool uses default settings and the preset doesn't need to change it, do NOT add it -- missing keys automatically inherit from defaults (safe merge)
  6. The preset registry is at `webapp/src/lib/recon-presets/index.ts` -- no changes needed there unless adding a new preset
  7. Add all new tool parameters to `reconPresetSchema` in `webapp/src/lib/recon-presets/recon-preset-schema.ts` (Zod validation). Without this, AI-generated presets will silently strip the new tool's settings during validation.
  8. Add the new tool's parameters (name, type, default, description) to the `RECON_PARAMETER_CATALOG` in `webapp/src/app/api/presets/generate/route.ts`. Without this, the LLM that generates AI presets won't know the tool exists and will never include its settings.
  9. If the new tool introduces file-upload or target-identity settings, add them to `PRESET_EXCLUDED_FIELDS` in `webapp/src/lib/project-preset-utils.ts` so they are stripped when users save reusable presets. Standard toggle/number/string settings do NOT need to be excluded.
- [ ] Error handling: try/except with timeout, Docker/binary not found, API errors — follow existing patterns
- [ ] Build and test: `docker compose build recon` then run a scan
