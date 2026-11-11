# ADD PARTIAL RECON FOR A NEW PIPELINE SECTION
# THIS IS THE TOOL SECTION TO IMPLEMENT: 

Extend the partial recon system to support a new tool/section from the recon pipeline. Partial recon lets users run a single pipeline phase on demand from the workflow graph, without running the full pipeline. Results are merged into the existing Neo4j graph (always deduplicated via MERGE).

> **Reference implementations**: SubdomainDiscovery, Naabu, Masscan, Nmap, Httpx, and Katana are fully implemented. **Study Naabu** (Subdomain + IP inputs), **Masscan** (IP-only inputs), **Nmap** (IP + port inputs), and **Katana** (URL inputs) as the primary patterns -- they demonstrate user inputs, graph querying, structured targets, and the full data flow.

---

## Tool Specification (FILL THIS IN BEFORE STARTING)

> **Fill in these three fields.** Everything else (tool function, graph update method, result key, phase name, settings) should be derived by reading the codebase -- check `workflowDefinition.ts`, `nodeMapping.ts`, `main.py`, `project_settings.py`.

| Field | Value |
|-------|-------|
| **Tool name** |      |
| **Input nodes** |     |
| **Output nodes** |    |
| **Enriches** |    |

How to manage input fields from modal:

### How input nodes determine the modal UI

**Input nodes (`SECTION_INPUT_MAP`) = what the tool reads from the graph.** Not all input node types should get a user textarea -- some only come from the graph (e.g. Port, Endpoint) and should never be manually entered. Decide per tool which types make sense for manual entry.

| Textarea type | When to show | Validation | Attachment |
|---|---|---|---|
| Subdomain | Tool accepts subdomain input | hostname regex + domain ownership | Auto-attach to Domain (no dropdown) |
| IP | Tool accepts IP input | IPv4/IPv6/CIDR /24-/32 | "Associate to" dropdown (subdomain or Generic) |
| URL | Tool accepts URL input | URL format | "Associate to" dropdown (BaseURL or Generic) |

**Examples:**
- Naabu: input nodes `['IP', 'Subdomain']`, user inputs = Subdomain + IP -> two textareas
- Masscan: input nodes `['IP']`, user inputs = IP only -> one textarea (no subdomains)
- Nmap: input nodes `['IP', 'Port']`, user inputs = IP + Port -> two textareas
- Httpx: input nodes `['Subdomain', 'IP', 'Port']`, user inputs = Subdomain + IP + Port -> three textareas
- Katana: input nodes `['BaseURL']`, user inputs = URL only -> one textarea
- Hakrawler: input nodes `['BaseURL']`, user inputs = URL only -> one textarea

---

## Critical Rules

- **NEVER duplicate recon code.** Import and call the exact same functions from the existing pipeline modules (`domain_recon.py`, `port_scan.py`, `http_probe.py`, etc.). The partial recon entry point is a thin orchestration layer.
- **All graph writes use MERGE -- deduplication is automatic.** Every node type has a uniqueness constraint declared in `graph_db/schema_keys.py` (e.g. IP is unique on `(address, user_id, project_id)`, Port on `(number, protocol, ip_address, user_id, project_id)`); `graph_db/schema.py` renders the `CREATE CONSTRAINT` statements from it. All Cypher writes use `MERGE` matching on these keys -- if the node exists it gets updated, if not it gets created. Never use CREATE for nodes that might already exist. You do NOT need to implement deduplication logic -- it's handled by the schema + MERGE.
- **Container-based execution.** Partial recon runs inside the same `redamon-recon` Docker image as the full pipeline, with a different command (`python /app/recon/partial_recon.py`). The orchestrator manages the container lifecycle.
- **Settings come from `get_settings()`.** The recon container fetches project settings via the webapp API (camelCase to UPPER_SNAKE_CASE conversion). Never pass raw camelCase settings.
- **Input node types come from `nodeMapping.ts`.** This is the single source of truth for what each tool consumes and produces. The modal reads from this mapping.
- **Each input type gets its own textarea + validation.** Never mix input types in a single textarea. Each has its own validator, error display, and graph association logic.
- **Validate on BOTH frontend and backend.** Frontend validates inline (regex, domain ownership, CIDR range) and disables Run on errors. Backend re-validates and skips invalid entries with log messages.
- **Typed input is scope-checked centrally -- never in your module.** The orchestrator filters `user_inputs` / `user_targets` before it spawns the container, and `_prepare_scope` runs `filter_partial_user_input(config, settings)` again inside it, against the container's own settings: a typed host or URL host must pass the partial rule of the run's scope groups (strictly under an ENUMERATE scan root, or one of an EXACT group's listed hosts; the scan root itself only with Root on), an IP or CIDR may be no wider than /24 (IPv4) or /120 (IPv6), `ip_attach_to` must be an in-scope host and `url_attach_to` is judged by its URL's host. A host, URL host, address or attach target the Rules of Engagement exclude is dropped too, and a typed CIDR holding an excluded address becomes its other hosts (the orchestrator image has no `recon/`, so `recon_orchestrator/batch_scope.py` keeps a copy of the `roe_scope` matcher, pinned by `roe_exclusion_vectors.json`). Refused entries are dropped with a log line, and a run that typed targets, kept none and reads no graph targets is refused. Your module reads the surviving `config["user_targets"]`; it must not add a typed URL's host to the writer's scope itself (`_scope_partial_urls` adds it only when the scope admits it).
- **Stealth mode refuses a tool it switches off.** Your module forces its tool's switch on, so `main()` in `recon/partial_recon.py` first refuses, before the scope pass, a tool one of whose switches the registry's stealth profile sets to false (`<tool> is off in stealth mode`, exit 1, no container). Add your tool's row to `PARTIAL_TOOL_SWITCHES`: a tool with no row is refused in stealth mode, and `test_partial_stealth_refusal.py` fails a dispatched tool with no row.
- **An old-model graph refuses the run.** Before `_run_tool`, `_legacy_graph_refusal` asks the graph whether a Domain from an older scope model still holds data (`legacy_domain_nodes`) and refuses the run, failing closed when Neo4j is unreachable; the webapp refuses the same start with a 409 first. A full recon clears it. New tools inherit this; do not bypass it.
- **User input graph strategy -- choose by type:**
  - **Subdomain** -> attaches to the **org** Domain of the scan root it sits under (`root_for_host(sub, roots)` gives the scan root, `attach_org(root)` its registrable domain; the graph has one Domain per org). Create real Subdomain + IP + RESOLVES_TO nodes directly. No UserInput. The typed subdomain already passed the scope check (see above); `typed_host_ok(host, roots, groups)` is the module-side backstop if you re-check.
  - **Any other node type** (IP, URL, etc.) -> user must choose which existing node to attach to via a dropdown, OR select "Generic (UserInput)" for orphan provenance.
  - If attachment target doesn't exist at scan time, fall back to UserInput automatically.
- **Mutual exclusion.** Only one partial recon OR full recon can run at a time per project. The orchestrator enforces this (409 Conflict).
- **Honor the "Include Root Domain" scope toggle.** Every graph-builder call must pass `include_root_domain=_should_include_root_domain(settings)`. The graph builder gates the apex `Domain → IP` query, filters apex BaseURLs from Source 2, and stamps `metadata.include_root_domain` so `extract_targets_from_recon` excludes the apex hostname when scope says no. **Default is `False`** -- forgetting to pass it means the apex is excluded (safe default; mirrors `recon/main.py:parse_target`). See "Include Root Domain scope" below.
- **Rebuild the recon image** after changing `recon/partial_recon.py`: `docker compose --profile tools build recon`

---

## Architecture Overview

```
User clicks Play on tool node (ProjectForm) 
  -> PartialReconModal opens (shows input/output nodes, per-type input textareas)
  -> Frontend validates each textarea independently (IP format, CIDR range, subdomain domain ownership)
  -> For non-subdomain inputs: user selects attachment node from dropdown (or "Generic")
  -> User clicks "Run" (disabled if any validation errors)
  -> Frontend POST /api/recon/{projectId}/partial  { user_targets: { ...per user input types... } }
  -> Proxied to orchestrator POST /recon/{project_id}/partial  
  -> Orchestrator writes config JSON to /tmp/redamon/, spawns recon container
  -> Container runs: python /app/recon/partial_recon.py
  -> partial_recon.py reads config, processes user_targets, calls tool function
  -> Updates Neo4j graph via mixin methods
  -> Orchestrator streams logs via SSE
  -> Graph page shows drawer with real-time logs (no phase progress bar for partial recon)
```

### End-to-End Data Flow

```
1. Modal builds: { tool_id, graph_inputs, user_inputs:[], user_targets: { ...per user input types... } }
2. ProjectForm.handlePartialReconConfirm: JSON.stringify(params) -> POST /api/recon/{projectId}/partial
   [passes full params as-is]
3. Proxy route (partial/route.ts): destructures body, adds project metadata, forwards to orchestrator
   [must include user_targets: body.user_targets || null]
4. Orchestrator model (models.py): PartialReconStartRequest validates via Pydantic
   [user_targets: dict | None = None]
5. Orchestrator API (api.py): builds config dict, includes "user_targets": request.user_targets
6. Container manager: json.dump(config) -> /tmp/redamon/partial_{project_id}.json
7. Container: load_config() reads JSON, run_<tool>(config) reads config["user_targets"]
8. Processing: if tool has multiple user input types, process in dependency order
   (e.g. subdomains resolved FIRST so IPs can reference them via ip_attach_to)
```

---

## Modal Input Design Pattern

**Each input type the tool accepts gets its own section in the modal.** This is the core UI pattern:

### Rule: Subdomains auto-attach to their root's Domain
A subdomain belongs to the scan root it sits under, so no dropdown is needed. A Domain-batch project has several scan roots: the container has already dropped any typed subdomain the scope groups do not admit (`filter_partial_user_input`), so attach each survivor to `attach_org(root_for_host(entry, roots))`, the org Domain. Read the roots with `roots = scope_roots(config)`, never `config["domain"]` -- `recon/tests/test_partial_scope_guard.py` fails the gate on a direct read. A UserInput node takes `root_orgs=root_orgs(roots)` so it lands on the org of its first host's scan root.

**Scope versus attach, in the writers.** `graph_db/mixins/recon/scope.py` splits the two decisions: `scan_root_for_host(host, recon_data)` is the scope (the longest scan root the host is under; a scan root itself only when its group has Root on, and the match stops there), `org_for_scan_root(root, recon_data)` is the attach key, and `attach_for_host` returns both for a writer (`IN_SCOPE` with the org, `SKIPPED` for a scan root that is no target, `OUT_OF_SCOPE` for an ExternalDomain). The groups come from `recon_data["scope_groups"]`; a partial run's dicts usually carry none, so `_prepare_scope` calls `set_project_scope(groups)`, which sets the run's default through `set_run_scope_groups`. A recon dict's own `scope_groups` always wins.

### Rule: All other input types need a "Associate to" dropdown
IPs, URLs, or any other user values need explicit association. The dropdown offers:
- `"-- Generic (UserInput) --"` (default) -- creates a UserInput node
- Existing nodes from the graph (fetched via graph-inputs API)
- Custom nodes from other textareas in the same modal (live-updated)

### Generic Pattern

For each user input type from the Tool Specification, add:
1. A state variable (e.g. `customIps`, `customUrls`)
2. A textarea with per-line validation via `useMemo`
3. An "Associate to" dropdown (except Subdomain which auto-attaches to Domain)

**The dropdown only appears when the textarea has content and no validation errors.**

**On "Run"**, build `UserTargets` from only the types this tool supports (check `hasSubdomainInput` etc.):
```typescript
const userTargets: UserTargets | undefined = hasContent
  ? { subdomains: hasSubdomainInput ? parseLines(customSubdomains) : [], ips: parseLines(customIps), ip_attach_to: ipAttachTo }
  : undefined
```

### Include Graph Targets checkbox

The modal has an `includeGraphTargets` checkbox (default: checked). When unchecked, the backend starts with empty `recon_data` instead of querying the graph -- only user-provided targets are scanned. The value is passed as `include_graph_targets: boolean` through the full stack (modal -> proxy -> orchestrator -> container config).

**When adding a new tool, check if unchecking graph targets can create an impossible scan state.** Some tools require graph data that users cannot provide manually. For example:

- **Nmap** requires ports. Ports come from the graph (from prior Naabu/Masscan scans). If the user unchecks graph targets and provides only IPs with no custom ports, there's nothing to scan.
- **Port scanners** (Naabu, Masscan) are fine -- they discover ports themselves from IPs.
- **Katana** requires BaseURLs -- if unchecked with no custom URLs, nothing to crawl.

**For each new tool, add a guard if needed:**

1. In the modal, define a boolean like `const toolNameMissingX = isToolName && !includeGraphTargets && !customX.trim()`
2. Add it to the Run button's `disabled` condition
3. Show a red warning explaining what's missing and how to fix it (provide custom X or re-enable graph targets)

**Nmap example (implemented):**
```typescript
const nmapNoPorts = isNmap && !includeGraphTargets && !customPorts.trim()
// Added to: disabled={... || nmapNoPorts}
// Warning: "Nmap requires ports to scan. Provide custom ports below or enable graph targets."
```

### Include Root Domain scope (apex toggle)

The project's "Include Root Domain" setting (TargetSection UI) maps to whether `"."` is in `subdomainList`. Partial recon must honor this scope rule **exactly the same way the full pipeline does** (`recon/main.py:parse_target`). Without this, partial-recon writes apex BaseURL/Endpoint nodes that violate the user's stated scope.

**Scope groups decide it per root.** `_prepare_scope` writes `config["domain_groups"]`, built by `partial_domain_groups(settings, roots)` from the container's `SCOPE_GROUPS` (`settings_scope_groups(settings)`), never from anything in the config payload. With `domain_groups` passed to a graph builder, each root follows its own group: `include_root_for(root, groups)` is that group's `includeRoot`, and `allowed_hosts_for(root, groups)` narrows an EXACT group -- a single-domain project with a subdomain prefix list included -- to its listed hosts (None for an ENUMERATE group: any host under the scan root). `org_for_root(root, groups)` gives the root's registrable domain. The graph builders read hosts with `toLower(d.name) IN <orgs>` and keep a host only when its longest project scan root is one of the run's and the §4.6 rule admits it (`_GraphScope`, `graph_scope_subdomains`), so a removed scan root's hosts are never offered. `_should_include_root_domain(settings)` below is only the fallback for a call that passes no groups.

**The contract (single source of truth: `metadata.include_root_domain`):**
- `_should_include_root_domain(settings)` returns True iff `SUBDOMAIN_LIST` contains `"."` (or any prefix that strips to empty). Mirrors `parse_target`.
- The result flows into `_build_*_data_from_graph(..., include_root_domain=...)`.
- The graph builder: (a) skips the apex `Domain → IP` query when False, (b) filters apex BaseURLs from `http_probe.by_url` (defends against stale apex BaseURLs from prior runs), (c) stamps `recon_data["metadata"]["include_root_domain"]`.
- `extract_targets_from_recon` reads that metadata and skips `hostnames.add(domain)` when False.

**Pattern to copy (graph-on branch):**
```python
recon_data = _build_http_probe_data_from_graph(
    roots, user_id, project_id,
    include_root_domain=_should_include_root_domain(settings),
    domain_groups=config.get("domain_groups"),   # each root keeps its group's scope
)
```

**Pattern for the graph-off `else` branch** (when `include_graph_targets=False`):
```python
recon_data = {
    "domain": roots[0],
    "domains": roots,
    "dns": {
        "domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
        "subdomains": {},
    },
    "http_probe": {"by_url": {}},
    "metadata": {"include_root_domain": _should_include_root_domain(settings)},
}
```
Always stamp the metadata flag, even when not querying the graph -- downstream consumers of `recon_data` rely on it.

**Why the default is `False`:** the safer failure mode. Forgetting to pass `include_root_domain=` means the apex is excluded -- better to under-scan than to silently scan something the user toggled off. This also makes future graph-builder callers fail-safe.

**Mirrors full pipeline:** the full pipeline already sets `combined_result["metadata"]["include_root_domain"]` in `recon/main.py:1032/1105`. Partial recon's metadata flag uses the same key so `extract_targets_from_recon` is the single point of enforcement for both pipelines.

### Naabu Example (Subdomain + IP textareas)

See `PartialReconModal.tsx` -- search for `hasSubdomainInput` and `isPortScanner`:
- Subdomain textarea: guarded by `hasSubdomainInput` (Naabu yes, Masscan no)
- IP textarea: guarded by `hasUserInputs` (both port scanners)
- Dropdown: `attachToOptions` built from graph subdomains + custom subdomains (via `useMemo`)

### Masscan Example (IP textarea only)

Same as Naabu but no subdomain textarea (`hasSubdomainInput` is false for Masscan).
The "Associate to" dropdown shows only graph subdomains (no custom subdomains since there's no subdomain textarea).

---

## What to Implement for Each New Tool

### 1. Backend: `recon/partial_recon.py`

**Check if an existing shared helper fits your tool first.** Port scanners (Naabu, Masscan) share `_run_port_scanner()` -- if your tool is another port scanner, add a thin wrapper like `run_masscan()`.

For other tool types, add a `run_<tool_name>(config)` function that:
1. Calls `get_settings()` for project settings
2. Reads `config["user_targets"]` for structured user input (keys depend on what the tool accepts)
3. Builds `recon_data` from the graph via `_build_*_data_from_graph(..., include_root_domain=_should_include_root_domain(settings))` -- **always pass the apex flag** (see Critical Rules and "Include Root Domain scope")
4. If you have an `else` branch for `include_graph_targets=False`, stamp `recon_data["metadata"]["include_root_domain"]` there too
5. Injects user-provided targets into `recon_data`
6. Calls the tool's scan function (same one used by the full pipeline)
7. Normalizes results if needed (e.g. `masscan_scan` -> `port_scan`)
8. Updates the graph via the appropriate `update_graph_from_*()` method
9. Links user-provided inputs to graph nodes (RESOLVES_TO or UserInput PRODUCED)

**Register in `_dispatch()`** (called by `main()`, which sweeps node filters in a `finally` around it):
```python
elif tool_id == "<ToolName>":
    run_<tool_name>(config)
```

**Study existing implementations:** `run_naabu()` and `run_masscan()` (port scanners via `_run_port_scanner`), `run_subdomain_discovery()` (standalone).

### 2. Backend: Graph Mixin

Reuse the existing `update_graph_from_<stage>()` methods; a writer attaches every host through `attach_for_host` (scope then org, above), never `MATCH (d:Domain {name: <scan root>})`.

Never hand a full-pipeline writer the dict a builder rebuilt from the graph: every node in it would be rewritten from the graph's own lossy copy. Pass only what your tool measured (`measured_port_data` in `recon/partial_recon_modules/port_scanning.py` cuts port data to it), or write a dedicated Cypher for your tool's own fields. A shared writer never takes `IP.is_cdn` from true to false, sets `Port.passive_only` false only for a port its caller saw (`update_graph_from_port_scan` in `graph_db/mixins/recon/port_mixin.py`), and writes enrichment fields (category, sample values, provenance) with `coalesce` or `ON CREATE SET`.

The graph-input counts and dropdown name lists live in the webapp only: add the tool's case to `webapp/src/app/api/recon/[projectId]/graph-inputs/[toolId]/route.ts`, using its positive scope test (`graphHostInScopeCypher`). The old orchestrator endpoint and `get_graph_inputs_for_tool()` are gone.

### 3. Frontend: Types (`recon-types.ts`)

- Add `'<ToolName>'` to `PARTIAL_RECON_SUPPORTED_TOOLS`
- No phase entry: a partial run is always phase 1 of 1 (`PARTIAL_RECON_TOTAL_PHASES`). The orchestrator pins every partial-run log event to phase 1 (`stream_partial_logs` in `recon_orchestrator/container_manager.py`) and takes the phase name from the full pipeline's log patterns
- Extend `GraphInputs` if the tool needs new count/list fields for the dropdown (e.g. `existing_baseurls`)
- Extend `UserTargets` if the tool introduces new user input types (e.g. `urls: string[]`, `url_attach_to: string | null`)

### 4. Frontend: Graph Inputs API Route

File: `webapp/src/app/api/recon/[projectId]/graph-inputs/[toolId]/route.ts`

Add `else if (toolId === '<NewToolId>')` -- return node name lists for dropdown alongside counts. Must use `else if`, not `if`.

### 5. Frontend: PartialReconModal

File: `webapp/src/components/projects/ProjectForm/WorkflowView/PartialReconModal.tsx`

For each new tool:
1. Add tool description to `TOOL_DESCRIPTIONS`
2. Add the tool to the appropriate condition flags (e.g. `isPortScanner`, `hasSubdomainInput`, `hasUserInputs`) -- these control which textareas render. **Only add textareas for input types that make sense for manual user entry** (see "How input nodes determine the modal UI" above).
3. Each textarea has its own `useMemo` validator. `hasValidationErrors` is OR of all active validators.
4. `handleRun` builds `UserTargets` from only the active textarea states.
5. Show warning if graph has no data for this tool.
6. **Check if unchecking "Include graph targets" creates an impossible scan state** for this tool (see "Include Graph Targets checkbox" above). If so, add a guard boolean, disable the Run button, and show a red warning.

**Validation helpers already exist:**
- `validateIp(value)` -- IPv4 octets, IPv6, CIDR /24-/32
- `validateSubdomain(value, projectDomain)` -- hostname regex + domain ownership
- `validateLines(text, validator)` -- runs validator per line, returns `{errors, validCount}`

### 6. Frontend: Proxy Route

File: `webapp/src/app/api/recon/[projectId]/partial/route.ts`

Already passes `user_targets: body.user_targets || null`. No changes needed for new tools.

### 7. Backend: Orchestrator

Files: `recon_orchestrator/models.py` + `recon_orchestrator/api.py`

Already has `user_targets: dict | None = None` in model and passes it to config. No changes needed.

### 8. Frontend: Drawer & Toolbar (already generic)

No changes needed:
- Drawer title uses `WORKFLOW_TOOLS.find()` lookup
- Toolbar badge uses `WORKFLOW_TOOLS.find()` lookup  
- Phase progress hidden for partial recon via `hidePhaseProgress`
- Status shows `"Scanning: <phase>"` instead of `"Phase 1/1: <phase>"`

### 9. Frontend: Input/Output Logic Tooltip

File: `webapp/src/components/projects/ProjectForm/WorkflowView/inputLogicTooltips.tsx`

Every tool exposed via partial recon must have an entry in the `INPUT_LOGIC_TOOLTIPS` map. The tooltip is rendered automatically in two places:
1. The project-form section header (merged under the existing graph-info icon).
2. The partial recon modal, next to the "Input" label.

**Each tooltip has two sections:**
1. **"How input is generated"** — what graph nodes feed the scan, any priority/fallback chain, how custom user input from the modal merges in, and any bail conditions (when the scan refuses to start).
2. **"How output transforms the graph"** — which nodes get created (real names: BaseURL, Endpoint, Vulnerability, etc.), which relationships (real names: HAS_ENDPOINT, RESOLVES_TO, etc.), and which existing nodes get enriched.

**Rules:**
- User-facing language only. Reference graph node and relationship names users see in the graph UI. **Never** mention internal Python/JS variable names, function names, file paths, JSON keys, or settings constants.
- No em dashes (—).
- Use the existing styled helpers (`sectionTitleStyle`, `paraStyle`, `codeStyle`, `listStyle`, `wrapperStyle`).
- First section header is "How input is generated" (not "Final input").
- Verify claims against the tool's `update_graph_from_*` mixin before writing the output section. If you claim a Vulnerability node is created, it must actually be created.

### 10. Frontend: Section Header "Run partial recon" Button

File: `webapp/src/components/projects/ProjectForm/sections/<ToolName>Section.tsx`

Each tool's settings section has a header with a Toggle switch. Add a "Run partial recon" button next to it so users can launch partial recon directly from the tab view (not just the workflow graph).

**Pattern (already implemented for all existing tools):**

1. Add `Play` to the lucide-react import
2. Add `onRun?: () => void` to the section's props interface
3. Destructure `onRun` in the component function
4. Add the button inside `sectionHeaderRight`, before the Toggle:

```tsx
{onRun && data.<toolName>Enabled && (
  <button
    type="button"
    onClick={(e) => { e.stopPropagation(); onRun() }}
    style={{
      display: 'inline-flex', alignItems: 'center', gap: '4px',
      padding: '3px 8px', borderRadius: '4px',
      border: '1px solid rgba(34, 197, 94, 0.3)',
      backgroundColor: 'rgba(34, 197, 94, 0.1)',
      color: '#22c55e', cursor: 'pointer', fontSize: '11px', fontWeight: 500,
    }}
    title="Run <ToolLabel>"
  >
    <Play size={10} /> Run partial recon
  </button>
)}
```

5. In `ProjectForm.tsx`, pass `onRun` when rendering the section:

```tsx
<ToolNameSection data={formData} updateField={updateField}
  onRun={mode === 'edit' && projectId ? () => setPartialReconToolId('<ToolName>') : undefined} />
```

**Key rules:**
- Button only appears when `onRun` is provided (edit mode + existing project) AND the tool's toggle is enabled
- `e.stopPropagation()` prevents the click from toggling the section open/closed
- Clicking the button opens the PartialReconModal, then on confirm redirects to `/graph`

---

## File Reference

### Files you MUST modify:

| File | What to change |
|------|----------------|
| `recon/partial_recon.py` | Add `run_<tool>(config)` + register in `_dispatch()` |
| `webapp/src/lib/recon-types.ts` | Add to `PARTIAL_RECON_SUPPORTED_TOOLS`, extend `UserTargets` if needed |
| `webapp/src/components/.../PartialReconModal.tsx` | Add per-type textareas + validation + dropdown for the tool |

### Files you MAY need to modify:

| File | When |
|------|------|
| `webapp/src/app/api/recon/[projectId]/graph-inputs/[toolId]/route.ts` | Add tool-specific Neo4j query for counts + names |
| `webapp/src/lib/recon-types.ts` | Extend `GraphInputs` / `UserTargets` if tool has new input types |
| `recon/tests/test_partial_recon.py` | Add test class for new tool |
| `webapp/src/lib/partial-recon-types.test.ts` | Update supported tools and type shape tests |
| `webapp/src/components/.../sections/<ToolName>Section.tsx` | Add `onRun` prop + "Run partial recon" button in section header |
| `webapp/src/components/.../ProjectForm.tsx` | Pass `onRun` prop to the tool's section component |

### Files you should NOT modify:

| File | Why |
|------|-----|
| `recon/main_recon_modules/domain_recon.py`, `port_scan.py`, `http_probe.py`, etc. | Source pipeline modules. Import, don't modify. |
| `recon/main.py` | Full pipeline. Partial recon is independent. |
| `recon_orchestrator/api.py` | Already passes `user_targets` generically. |
| `recon_orchestrator/models.py` | Already has `user_targets: dict \| None`. |
| `recon_orchestrator/container_manager.py` | Generic. Writes whatever config it receives. |
| `webapp/src/app/api/recon/[projectId]/partial/route.ts` | Already passes `user_targets`. |
| `webapp/src/hooks/usePartialRecon*.ts` | Generic hooks. |
| `webapp/src/components/.../ToolNode.tsx` | Checks `PARTIAL_RECON_SUPPORTED_TOOLS`. |
| `webapp/src/components/.../WorkflowView.tsx`, `ProjectForm.tsx` | Already generic. |
| `webapp/src/app/graph/page.tsx` | Uses `PARTIAL_RECON_TOTAL_PHASES`, the same for every tool. |
| `webapp/src/app/graph/components/GraphToolbar/GraphToolbar.tsx` | Uses `WORKFLOW_TOOLS.find()`. |
| `webapp/src/app/graph/components/ReconLogsDrawer/ReconLogsDrawer.tsx` | Has `hidePhaseProgress`. |

### Key reference files (read-only):

| File | Contains |
|------|----------|
| `webapp/src/components/projects/ProjectForm/nodeMapping.ts` | `SECTION_INPUT_MAP` and `SECTION_NODE_MAP` -- tool I/O node types |
| `webapp/src/components/projects/ProjectForm/WorkflowView/workflowDefinition.ts` | `WORKFLOW_TOOLS` -- tool IDs, labels, groups |
| `graph_db/schema_keys.py` | Each label's uniqueness key -- THE declaration |
| `graph_db/schema.py` | Renders the constraints from it, plus the indexes |
| `graph_db/schema_sections.md` | Every label, property and relationship -- THE declaration |
| `recon/project_settings.py` | `get_settings()` + `DEFAULT_SETTINGS` |
| `recon/main.py` | Full pipeline -- see what `recon_data` structure each tool expects |

---

## Naabu Reference Implementation (study this)

Naabu is the reference for any tool that needs user inputs. Read these files in order:

### 1. Frontend: Modal inputs
**`PartialReconModal.tsx`** -- search for `isPortScanner`, `hasSubdomainInput`, `hasUserInputs`:
- Section A: `customSubdomains` textarea guarded by `hasSubdomainInput` (Naabu yes, Masscan no)
- Section B: `customIps` textarea guarded by `hasUserInputs` (all port scanners)
- Dropdown: `ipAttachTo` select, options from `attachToOptions` (graph + custom subdomains, via `useMemo`)
- `handleRun` builds `UserTargets` only when there's actual custom input, sends empty `subdomains` if `hasSubdomainInput` is false

### 2. Frontend: Graph inputs API  
**`graph-inputs/[toolId]/route.ts`** -- Naabu case:
- Cypher query returns `collect(DISTINCT s.name) AS subdomains` (name list for dropdown)
- Returns `{ domain, existing_subdomains, existing_subdomains_count, existing_ips_count, source }`

### 3. Backend: Processing
**`partial_recon.py` -- port scanners use `_run_port_scanner()` shared helper:**
- Reads `config["user_targets"]` with legacy `user_inputs` fallback
- STEP 1: Resolves hostnames (if tool accepts subdomains), creates Subdomain + IP + RESOLVES_TO in Neo4j
- STEP 2: Injects IPs into `recon_data` (into subdomain bucket if `ip_attach_to`, or domain bucket if generic)
- Safety: if `ip_attach_to` subdomain doesn't exist in graph, falls back to UserInput
- Calls the tool's scan function (same as full pipeline)
- Normalizes results if needed (Masscan: `masscan_scan` -> `port_scan`)
- Post-scan: creates `Subdomain -[:RESOLVES_TO]-> IP` or `UserInput -[:PRODUCED]-> IP` depending on `ip_attach_to`

### 4. Graph relationships created (port scanner example)
```
User provides subdomain (Naabu only):
  Domain -[:HAS_SUBDOMAIN]-> Subdomain -[:RESOLVES_TO]-> IP -[:HAS_PORT]-> Port

User provides IP attached to subdomain:
  Subdomain -[:RESOLVES_TO]-> IP -[:HAS_PORT]-> Port

User provides IP (generic):
  Domain -[:HAS_USER_INPUT]-> UserInput -[:PRODUCED]-> IP -[:HAS_PORT]-> Port
```


---

## UserInput Node Strategy

**Rule: Subdomains auto-attach to Domain. Everything else: user chooses via dropdown.**

| User provides | Attachment | Strategy |
|---|---|---|
| Subdomain | Auto -> Domain (only one per project) | Create Subdomain + IP + RESOLVES_TO. No UserInput. |
| IP attached to subdomain | User selects subdomain | Create `Subdomain -[:RESOLVES_TO]-> IP`. No UserInput. |
| IP generic | User selects "Generic" | `UserInput -[:PRODUCED]-> IP` |
| URL attached to BaseURL | User selects BaseURL | Create Endpoint under BaseURL. No UserInput. |
| URL generic | User selects "Generic" | `UserInput -[:PRODUCED]-> Endpoint` |

**Safety fallback**: if the selected attachment node doesn't exist at scan time (deleted between modal open and run), the backend detects this via a graph query and automatically falls back to UserInput. No orphan nodes.

**Close the UserInput your module creates.** After its `PRODUCED` edges are written, set its final state with `update_user_input_status(ui_id, "completed" | "error", stats, user_id=user_id, project_id=project_id)` (`graph_db/mixins/recon/user_input_mixin.py`): the tenant arguments are required, the node is matched on `{id, user_id, project_id}`, and a miss is printed rather than raised, leaving the node `running`. The end-of-run orphan cleanup (`_cleanup_orphan_user_inputs` in `recon/partial_recon_modules/user_inputs.py`) deletes an edge-less UserInput only when this process created it or its status is `completed` or `error`: up to twelve partial runs of a project run at once, and another run's `running` node may still be waiting for its results (httpx creates its node before it scans). Once the tool has returned, the cleanup also marks the run's own nodes still `running` as `completed` (`_close_own_user_inputs`), so a node your module never closes reads `completed` with no stats after a run that ended normally, and stays `running` after a crash or a stop: set `error` yourself on a failure path you catch.

---

## Helper Functions in `partial_recon.py`

Reuse these -- do not reimplement:

| Function | Purpose |
|----------|---------|
| `_classify_ip(address, version=None)` | Returns `"ipv4"` or `"ipv6"`. |
| `_is_ip_or_cidr(value)` | Validates IP or CIDR. |
| `_is_valid_hostname(value)` | Validates hostname regex. |
| `_resolve_hostname(hostname)` | DNS resolves via `socket.getaddrinfo()`. Returns `{"ipv4": [...], "ipv6": [...]}`. |
| `_build_recon_data_from_graph(domain, user_id, project_id, include_root_domain=False)` | Queries Neo4j, returns `recon_data` dict for `extract_targets_from_recon()`. **Always pass `include_root_domain`** -- see Critical Rules. |
| `_should_include_root_domain(settings)` | Returns True iff `SUBDOMAIN_LIST` contains `"."` (or empty-stripped prefix). Mirrors `recon/main.py:parse_target`. The fallback for a graph-builder call that passes no `domain_groups`. |
| `partial_domain_groups(settings, roots)` | The run's scope groups (from `SCOPE_GROUPS`), as `config["domain_groups"]` holds them. Built by `_prepare_scope`; pass `config.get("domain_groups")` on, never rebuild. |
| `include_root_for(root, groups)` / `allowed_hosts_for(root, groups)` | Per-group apex flag, and the exact host set of an EXACT group (None for ENUMERATE). |
| `admits_partial_host(groups, host)` | The §4.6 partial rule for one typed host. Already applied to typed input by `filter_partial_user_input`. |
| `load_config()` | Loads JSON config from `PARTIAL_RECON_CONFIG` env var. |

---

## Frontend Validation

Separate validators per input type (in `PartialReconModal.tsx`):

| Validator | Input type | Rules |
|---|---|---|
| `validateSubdomain(value, domain)` | Hostnames | Hostname regex + must end with `.{domain}` or equal `{domain}` |
| `validateIp(value)` | IPs/CIDRs | IPv4 octets 0-255, IPv6 format, CIDR /24-/32 (v4) or /120-/128 (v6) |

Each textarea runs its validator per line via `validateLines(text, validator)` in `useMemo`. Errors show per-line below each textarea. Run button disabled if any textarea has errors.

---

## Build & Verification

After implementing:

1. `docker compose --profile tools build recon` (code baked into image)
2. `docker compose restart recon-orchestrator` (if you changed models.py or api.py)
3. Dev webapp hot-reloads (no rebuild for frontend)
4. Click play on the new tool in workflow graph
5. Verify: modal shows separate textareas per input type
6. Verify: dropdown shows existing graph nodes + custom subdomains from textarea
7. Verify: validation works per textarea (invalid entries, wrong domain, oversized CIDR)
8. Verify: Run button disabled while errors exist
9. Click Run, check logs drawer (no phase dots, shows "Scanning: <name>")
10. Query Neo4j: verify output nodes created, user inputs linked correctly (RESOLVES_TO or UserInput PRODUCED)
11. **Compare with a reference implementation**: run Naabu or Masscan partial recon to see expected behavior

---

## Tests

- **Python**: `recon/tests/test_partial_recon.py` -- read existing test classes for patterns, add a new `TestRun<ToolName>` class
- **TypeScript**: `webapp/src/lib/partial-recon-types.test.ts` -- add supported tool, phase map, and params tests
