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
- **All graph writes use MERGE -- deduplication is automatic.** Every node type has a uniqueness constraint in `graph_db/schema.py` (e.g. IP is unique on `(address, user_id, project_id)`, Port on `(number, protocol, ip_address, user_id, project_id)`). All Cypher writes use `MERGE` matching on these keys -- if the node exists it gets updated, if not it gets created. Never use CREATE for nodes that might already exist. You do NOT need to implement deduplication logic -- it's handled by the schema + MERGE.
- **Container-based execution.** Partial recon runs inside the same `redamon-recon` Docker image as the full pipeline, with a different command (`python /app/recon/partial_recon.py`). The orchestrator manages the container lifecycle.
- **Settings come from `get_settings()`.** The recon container fetches project settings via the webapp API (camelCase to UPPER_SNAKE_CASE conversion). Never pass raw camelCase settings.
- **Input node types come from `nodeMapping.ts`.** This is the single source of truth for what each tool consumes and produces. The modal reads from this mapping.
- **Each input type gets its own textarea + validation.** Never mix input types in a single textarea. Each has its own validator, error display, and graph association logic.
- **Validate on BOTH frontend and backend.** Frontend validates inline (regex, domain ownership, CIDR range) and disables Run on errors. Backend re-validates and skips invalid entries with log messages.
- **User input graph strategy -- choose by type:**
  - **Subdomain** -> always attaches to the project's Domain (only one domain per project). Create real Subdomain + IP + RESOLVES_TO nodes directly. No UserInput.
  - **Any other node type** (IP, URL, etc.) -> user must choose which existing node to attach to via a dropdown, OR select "Generic (UserInput)" for orphan provenance.
  - If attachment target doesn't exist at scan time, fall back to UserInput automatically.
- **Mutual exclusion.** Only one partial recon OR full recon can run at a time per project. The orchestrator enforces this (409 Conflict).
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

### Rule: Subdomains always auto-attach to Domain
Since there is only one Domain per project, subdomains always belong to it. No dropdown needed -- just validate that the subdomain ends with `.{projectDomain}`.

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
3. Builds `recon_data` from the graph via `_build_recon_data_from_graph()` or similar
4. Injects user-provided targets into `recon_data`
5. Calls the tool's scan function (same one used by the full pipeline)
6. Normalizes results if needed (e.g. `masscan_scan` -> `port_scan`)
7. Updates the graph via the appropriate `update_graph_from_*()` method
8. Links user-provided inputs to graph nodes (RESOLVES_TO or UserInput PRODUCED)

**Register in `main()`:**
```python
elif tool_id == "<ToolName>":
    run_<tool_name>(config)
```

**Study existing implementations:** `run_naabu()` and `run_masscan()` (port scanners via `_run_port_scanner`), `run_subdomain_discovery()` (standalone).

### 2. Backend: Graph Mixin

File: `graph_db/mixins/recon_mixin.py`

Reuse existing `update_graph_from_<stage>()` methods. Add a case to `get_graph_inputs_for_tool()` that returns counts AND node name lists (for the dropdown).

The Cypher query should return counts of the tool's input node types, plus name lists for dropdown options. See existing cases in `get_graph_inputs_for_tool()` for Naabu/Masscan (port scanners) and Nmap patterns.

### 3. Frontend: Types (`recon-types.ts`)

- Add `'<ToolName>'` to `PARTIAL_RECON_SUPPORTED_TOOLS`
- Add `<ToolName>: ['<Phase Name>']` to `PARTIAL_RECON_PHASE_MAP`
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

### 9. Frontend: Section Header "Run partial recon" Button

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
| `recon/partial_recon.py` | Add `run_<tool>(config)` + register in `main()` |
| `webapp/src/lib/recon-types.ts` | Add to `PARTIAL_RECON_SUPPORTED_TOOLS` + `PARTIAL_RECON_PHASE_MAP`, extend `UserTargets` if needed |
| `webapp/src/components/.../PartialReconModal.tsx` | Add per-type textareas + validation + dropdown for the tool |

### Files you MAY need to modify:

| File | When |
|------|------|
| `graph_db/mixins/recon_mixin.py` | Add `get_graph_inputs_for_tool()` case with node name lists |
| `webapp/src/app/api/recon/[projectId]/graph-inputs/[toolId]/route.ts` | Add tool-specific Neo4j query for counts + names |
| `webapp/src/lib/recon-types.ts` | Extend `GraphInputs` / `UserTargets` if tool has new input types |
| `recon/tests/test_partial_recon.py` | Add test class for new tool |
| `webapp/src/lib/partial-recon-types.test.ts` | Update supported tools, phase map, type shape tests |
| `webapp/src/components/.../sections/<ToolName>Section.tsx` | Add `onRun` prop + "Run partial recon" button in section header |
| `webapp/src/components/.../ProjectForm.tsx` | Pass `onRun` prop to the tool's section component |

### Files you should NOT modify:

| File | Why |
|------|-----|
| `recon/domain_recon.py`, `port_scan.py`, `http_probe.py`, etc. | Source pipeline modules. Import, don't modify. |
| `recon/main.py` | Full pipeline. Partial recon is independent. |
| `recon_orchestrator/api.py` | Already passes `user_targets` generically. |
| `recon_orchestrator/models.py` | Already has `user_targets: dict \| None`. |
| `recon_orchestrator/container_manager.py` | Generic. Writes whatever config it receives. |
| `webapp/src/app/api/recon/[projectId]/partial/route.ts` | Already passes `user_targets`. |
| `webapp/src/hooks/usePartialRecon*.ts` | Generic hooks. |
| `webapp/src/components/.../ToolNode.tsx` | Checks `PARTIAL_RECON_SUPPORTED_TOOLS`. |
| `webapp/src/components/.../WorkflowView.tsx`, `ProjectForm.tsx` | Already generic. |
| `webapp/src/app/graph/page.tsx` | Uses `PARTIAL_RECON_PHASE_MAP`. |
| `webapp/src/app/graph/components/GraphToolbar/GraphToolbar.tsx` | Uses `WORKFLOW_TOOLS.find()`. |
| `webapp/src/app/graph/components/ReconLogsDrawer/ReconLogsDrawer.tsx` | Has `hidePhaseProgress`. |

### Key reference files (read-only):

| File | Contains |
|------|----------|
| `webapp/src/components/projects/ProjectForm/nodeMapping.ts` | `SECTION_INPUT_MAP` and `SECTION_NODE_MAP` -- tool I/O node types |
| `webapp/src/components/projects/ProjectForm/WorkflowView/workflowDefinition.ts` | `WORKFLOW_TOOLS` -- tool IDs, labels, groups |
| `graph_db/schema.py` | Neo4j constraints and indexes |
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

---

## Helper Functions in `partial_recon.py`

Reuse these -- do not reimplement:

| Function | Purpose |
|----------|---------|
| `_classify_ip(address, version=None)` | Returns `"ipv4"` or `"ipv6"`. |
| `_is_ip_or_cidr(value)` | Validates IP or CIDR. |
| `_is_valid_hostname(value)` | Validates hostname regex. |
| `_resolve_hostname(hostname)` | DNS resolves via `socket.getaddrinfo()`. Returns `{"ipv4": [...], "ipv6": [...]}`. |
| `_build_recon_data_from_graph(domain, user_id, project_id)` | Queries Neo4j, returns `recon_data` dict for `extract_targets_from_recon()`. |
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
