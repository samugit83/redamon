# NEW TOOL IN AGENTIC SYSTEM

Integrate **[TOOL_NAME]** into the RedAmon agentic system.

> **Scope**: This prompt covers tools used by the AI agent during interactive pentesting sessions (chat-based). It does NOT cover the recon pipeline.

### Critical Rules

- **Python import safety**: The `agent` container has source code baked into the Docker image. Adding a new Python `import` that isn't already installed in the container image will **crash-loop** the agent. Before importing any package, verify it exists in `agentic/requirements.txt` or the `agentic/Dockerfile`. If it's missing, add it and rebuild: `docker compose build agent`.
- **Don't break existing tools**: Adding a new tool must NOT modify the behavior, arguments, or output format of any existing tool. If you change a shared file (e.g., `tools.py`, `project_settings.py`), verify that all existing tools still work after your changes.
- **Container rebuild rules**: MCP server code in `mcp/servers/` is volume-mounted and **hot-reloads** -- changes are live immediately. But agent Python code in `agentic/` is baked into the Docker image -- you MUST run `docker compose build agent && docker compose up -d agent` after any change there. Frontend changes require `docker compose build webapp`.
- **Build/restart quick reference**:
  - Changed `mcp/kali-sandbox/Dockerfile` → `docker compose build kali-sandbox && docker compose up -d kali-sandbox`
  - Changed `mcp/servers/*.py` → `docker compose restart kali-sandbox`
  - Changed `agentic/*.py` → `docker compose build agent && docker compose up -d agent`
  - Changed `webapp/prisma/schema.prisma` → `docker compose exec webapp npx prisma db push`
  - Changed `webapp/src/**` → `docker compose build webapp && docker compose up -d webapp`

---

### Phase 0: Pre-flight — Does the tool already exist?

Before doing ANY work, check whether the tool is already available:

1. **Check `agentic/prompts/tool_registry.py`** — Is the tool (or a functional equivalent) already registered? The `TOOL_REGISTRY` dict is the single source of truth for all agentic tools. If found, STOP and tell the user.
2. **Check `kali_shell` availability** — Is the tool already installed in the Kali sandbox? Read `mcp/kali-sandbox/Dockerfile` and search for its binary/package. If it's already in Kali, the agent can already use it via `kali_shell` or `execute_code`. Consider whether a dedicated tool wrapper adds enough value vs simply using `kali_shell`.
3. **Check MCP servers** — Read `mcp/servers/network_recon_server.py`, `mcp/servers/nmap_server.py`, `mcp/servers/nuclei_server.py`, `mcp/servers/metasploit_server.py`. Is the tool already exposed as an MCP function?

If the tool already exists in any form, explain what's already available and ask whether a dedicated integration is still wanted.

---

### Phase 1: Research (do NOT write code yet)

#### Step 1 — Tool research

Search the tool's official docs, GitHub repo, and README online. Determine:
- **What it does**: One-line purpose
- **CLI interface**: Key flags, input format, output format
- **Output format**: Does it support JSON output? What fields does it return?
- **Dependencies**: External binaries, config files, wordlists, API keys?
- **Installation method**: apt, pip, go install, binary download, Docker image?
- **Timeout profile**: Fast (<30s), medium (30s-5min), or long-running (5min+)?
- **Is it interactive or batch?**: Does it require interactive input (like `msfconsole`) or is it fire-and-forget (like `nmap`)?

#### Step 2 — Choose the integration type

There are **4 integration types**, ordered from simplest to most complex. Choose the SIMPLEST that meets the tool's requirements:

---

**Type A: Kali Shell Tool (SIMPLEST — no new tool registration needed)**

The tool works well via `kali_shell` / `execute_code`. No dedicated MCP tool or tool registry entry is needed.

**When to use:**
- Tool is already in Kali or trivially installable
- CLI is simple enough that the agent can use it via `kali_shell` without a wrapper
- 300s `kali_shell` timeout is sufficient
- No progress streaming needed

**What to change:**
1. `mcp/kali-sandbox/Dockerfile` — Install tool if not already present
2. `agentic/prompts/tool_registry.py` — Update `kali_shell` entry's `description` field to mention the new tool in the CLI tools list
3. Rebuild kali-sandbox: `docker compose build kali-sandbox`

> **This is not only the in-app agent's catalogue any more.** The INBOUND MCP
> server's `kali_toolbox` tool serves `TOOL_REGISTRY["kali_shell"]["description"]`
> **verbatim** (`agentic/api.py`, `GET /kali/toolbox`), and `kali_exec` is the only
> way an external agent runs anything at all. A binary you install but leave out of
> that description does not exist as far as every MCP client is concerned. Nothing
> tests this, so step 2 is the whole safeguard. Rebuild the **agent** as well as
> kali-sandbox, since the registry is baked into the agent image.

**Examples:** searchsploit, john, smbclient, sqlmap

---

**Type B: New MCP Tool on Existing Server (RECOMMENDED for most CLI tools)**

Add a new `@mcp.tool()` function to an existing MCP server (usually `network_recon_server.py`). The tool gets its own name, custom timeout, output parsing, and rich docstring.

**When to use:**
- Tool needs a custom timeout different from `kali_shell`'s 300s
- Tool output benefits from dedicated parsing/cleaning
- The agent should see a dedicated tool name in the tool list
- Tool is fire-and-forget (not interactive/stateful)

**What to change (full list in Phase 2 checklist):**
1. MCP server file — Add `@mcp.tool()` function (follow `execute_nmap` in `nmap_server.py` as reference)
2. `agentic/prompts/tool_registry.py` — Add entry to `TOOL_REGISTRY` dict
3. `agentic/project_settings.py` — Add to `TOOL_PHASE_MAP` + optionally to `DANGEROUS_TOOLS`
4. Frontend `ToolMatrixSection.tsx` — Add tool row to the phase matrix grid
5. Prisma schema — Default `agentToolPhaseMap` value must include the new tool
6. `agentic/tools.py` — Add the tool name to `SYSTEM_MCP_TOOL_NAMES` (see "MCP Auto-Discovery" below)
7. If tool binary not in Kali: `mcp/kali-sandbox/Dockerfile`

**Examples:** `execute_naabu`, `execute_curl`, `execute_hydra`, `execute_nmap`, `execute_nuclei`

---

**Type C: New Dedicated MCP Server (for complex/stateful tools)**

Create a new MCP server file with its own port, process, and optionally a progress streaming endpoint.

**When to use:**
- Tool is interactive or stateful (needs persistent process)
- Tool needs its own progress streaming endpoint
- Tool has complex lifecycle management
- Isolation from other tools is important

**What to change (full list in Phase 2 checklist):**
1. `mcp/servers/[tool]_server.py` — New server file (follow `nmap_server.py` for simple, `metasploit_server.py` for stateful)
2. `mcp/servers/run_servers.py` — Register in `SERVERS` dict with port
3. `agentic/tools.py` — Add an `MCPServer` entry for the server to `_build_system_mcp_servers()` (its URL from `MCP_[TOOL]_URL`, with the shared `auth=_mcp_auth` bearer)
4. Both `docker-compose.yml` files — Add `MCP_[TOOL]_URL` env var + expose port on kali-sandbox
5. Everything from Type B (registry, settings, frontend, `SYSTEM_MCP_TOOL_NAMES`, etc.)

**Already-taken ports:** 8000 (network_recon), 8002 (nuclei), 8003 (metasploit), 8004 (nmap), 8005 (playwright), 8013 (msf progress), 8014 (hydra progress), 8015 (tunnel manager), 8016 (terminal). Next available: **8006**.

**Examples:** `metasploit_server.py`

---

**Type D: API/HTTP-Based Tool (for external services)**

A Python wrapper around an external API. It runs inside the `agent` container, not `kali-sandbox`. The tool is **always registered**: it reads the key of the run it serves at call time (the project owner's key from Global Settings), and a run without a key gets a "not configured" answer instead of a call.

**When to use:**
- Tool is an external API service (like Shodan, Tavily, SerpAPI)
- Tool needs API keys stored in user settings
- No CLI binary needed — pure Python HTTP calls
- Tool cannot do its job without the user's API key

**Architecture pattern — no shared object holds a key (RBAC T17).** The tool managers and the executor are built once and shared by every run of every owner, so a key written onto one was spent by the next run of any owner. Read the existing implementations and follow them exactly:

1. **`[Tool]ToolManager` class** in `agentic/tools.py` — Takes no key and holds none. `get_tool()` always returns the `@tool` function, whose first step is `api_key, rotator = _call_key('<tool>')`: with no key it returns "<Tool> is not configured: add a <Tool> API key in Global Settings -> API Keys.", and after a successful call it ticks the rotator (`if rotator: rotator.tick()`). Read `ShodanToolManager` or `GoogleDorkToolManager` as reference.

2. **The per-run key lookup** in `agentic/tools.py` (section "PER-RUN SEARCH KEYS") — `_call_key()` asks `run_key_rotator()`, which reads `run_user_settings()`: the `USER_SETTINGS` bound to the run's own task, never the module-global snapshot of whichever project loaded last. It builds the key pool from the main key plus the `rotationConfigs[<tool>]` extras. Add the tool to `_SEARCH_KEY_FIELDS` (`'<tool>': '<tool>ApiKey'`), using the same tool name as its `ROTATION_TOOLS` entry in `webapp/src/lib/rotationTools.ts`; a key without rotation is a pool of one.

3. **`PhaseAwareToolExecutor`** in `agentic/tools.py` — Accepts the tool in `__init__()` and has a dispatch branch in `execute()`. Read how `shodan` and `google_dork` are handled. There is no `update_[tool]_tool()` hot-swap: the tool never changes with the key. A per-project on/off switch is read in `execute()` with `get_setting(...)`, like the `SHODAN_ENABLED` gate, never by adding or removing the tool from the shared `_all_tools`.

4. **Orchestrator** in `agentic/orchestrator.py` — `_setup_tools()` builds the manager once, with no key, and passes its tool to `PhaseAwareToolExecutor`. `_apply_project_settings()` is not touched: it writes no credential onto a shared manager. The run's keys arrive in its `USER_SETTINGS`, which `fetch_agent_settings()` in `agentic/project_settings.py` loads from the project owner's `GET /api/users/{id}/settings?internal=true`.

`agentic/tests/test_run_credentials_isolation.py` holds this in place: `NoSharedKeyPath` fails a manager that accepts or holds a key, and `SearchKeysPerRun` proves each run spends its own key and that an empty key never inherits the previous run's.

**CRITICAL**: The `PhaseAwareToolExecutor.execute()` method has hardcoded if/elif dispatch (in its `_invoke` closure) for non-MCP tools (query_graph, graph_schema, graph_summary, web_search, shodan, google_dork, execute_guarddog, the tradecraft tools) and for MCP tools that need key injection (execute_wpscan, execute_gau, cve_intel). Each extracts arguments differently. For Type D, you MUST add a new `elif` branch. For Types B/C, the `else` branch (MCP tools) handles dispatch automatically -- no change needed UNLESS the tool needs API key injection (see Step 6).

**What to change (full list in Phase 2 checklist):**
1. `agentic/tools.py` — New ToolManager class (no key, reads it per call) + `_SEARCH_KEY_FIELDS` entry + registration in `PhaseAwareToolExecutor.__init__()` + dispatch branch in `execute()`
2. `agentic/orchestrator.py` — Build the manager in `_setup_tools()` and pass its tool to the executor (nothing in `_apply_project_settings()`)
3. API key storage across Prisma, settings API, Global Settings page, ToolMatrix warnings
4. Everything from Type B (registry, phase map, frontend matrix, Prisma default, etc.)

**Examples:** `shodan`, `web_search`, `google_dork`

---

#### Step 3 — Determine phase restrictions

Decide which phases the tool should be available in. The 3 phases are:

| Phase | Purpose | Typical tools |
|-------|---------|---------------|
| **informational** | Passive/active recon, scanning, OSINT | query_graph, web_search, shodan, google_dork, execute_curl, execute_naabu, execute_nmap, execute_nuclei, kali_shell |
| **exploitation** | Active exploitation, credential attacks | All informational tools + execute_code, execute_hydra, metasploit_console, msf_restart |
| **post_exploitation** | Post-exploit activities, lateral movement, persistence | query_graph, web_search, execute_curl, execute_nmap, kali_shell, execute_code, execute_hydra, metasploit_console, msf_restart |

Guidelines:
- **Passive/reconnaissance** → all 3 phases
- **Active scanning** → informational + exploitation
- **Exploitation-focused** → exploitation + post_exploitation
- **Post-exploitation only** → post_exploitation

#### Step 4 — Determine if tool is dangerous

A tool is "dangerous" if it actively modifies the target, sends attack traffic, or could cause unintended impact. If yes, add to `DANGEROUS_TOOLS` frozenset — this requires user confirmation before each execution.

**Dangerous** (add): active scanners, exploits, brute force, shell execution, code execution
**Not dangerous** (skip): passive OSINT, graph queries, web searches, read-only API calls

#### Step 5 — Determine RoE category mapping

Read `agentic/orchestrator_helpers/roe_gate.py`. Its `check_tool_call()` is the one pre-dispatch gate (the Rules of Engagement, then the recon budget) that every executor path asks: the single-tool node, the plan wave and every fireteam member. Its `CATEGORY_TOOL_MAP` maps RoE categories to tools (brute_force, dos, social_engineering, exploitation): if the new tool fits any category, add it to that list so category-based blocking works. If it is a discovery or scanning tool, also add it to `RECON_DISCOVERY_TOOLS`, the family the recon budget refuses once informational recon has used its iterations. Every name in both must be a `TOOL_REGISTRY` key; `agentic/tests/test_roe_gate.py` fails otherwise.

#### Step 5b — Determine stealth mode constraints

Read `agentic/prompts/stealth_rules.py` — this file defines **per-tool stealth constraints** injected into the system prompt when `STEALTH_MODE` is enabled. Every active tool has a dedicated section under "Per-Tool Stealth Constraints" specifying what is allowed and forbidden.

If the new tool sends any traffic to a target, you MUST add a stealth constraint section for it. Determine the restriction level:
- **FORBIDDEN**: Tool is inherently noisy and cannot be used stealthily (e.g., brute force, DoS)
- **HEAVILY RESTRICTED**: Tool can be used in very limited ways only (e.g., nmap only `-sV` on known ports)
- **RESTRICTED**: Tool can be used with rate/scope limits (e.g., curl for single targeted requests)
- **NO RESTRICTIONS**: Tool is passive and doesn't touch the target (e.g., query_graph, web_search)

Read existing tool sections in `stealth_rules.py` as reference for the format and level of detail expected.

#### Step 6 — Check if tool needs API keys

If the tool uses external API keys, there are **two patterns** depending on whether the key is required or optional:

---

**Pattern 1: Key required, read per call (Type D tools -- Shodan, Google Dork, Tavily)**

The tool is always registered, and every call reads the key of the run it serves. No key = the call answers "not configured" (the UI warns about the missing key beforehand, see the frontend files below).

**When to use:** The tool is a pure API service that cannot function without a key (e.g., Shodan API, SerpAPI).

**How it works:**
1. `[Tool]ToolManager.get_tool()` always returns the tool; the tool calls `_call_key('<tool>')` at the start of every call and answers "not configured" when the run has no key
2. The key is the run's own: `run_key_rotator()` reads `run_user_settings()`, the `USER_SETTINGS` of the run's task, so an empty key means none, never the previous run's (possibly another owner's)
3. A key changed in Global Settings applies from the next run, which loads its settings afresh. Rotation comes from the same lookup: the `rotationConfigs[<tool>]` extra keys, cycled every `rotateEveryN` calls by a `KeyRotator` shared only by runs that hold the very same pool

**Backend files:** `agentic/tools.py` (ToolManager class + `_SEARCH_KEY_FIELDS` entry + registration in `PhaseAwareToolExecutor.__init__()` + dispatch branch in `execute()`) + `agentic/orchestrator.py` (`_setup_tools()` only)

**Examples:** `shodan`, `web_search`, `google_dork`

---

**Pattern 2: Optional enrichment / silent injection (Type B MCP tools with optional API keys -- WPScan)**

The tool **always works** without the key, but the key enriches results (e.g., vulnerability database access). The key is silently passed beside the args at execution time, and the sandbox hands it to that one child process through its environment (or a private per-call file), never its command line, which `ps` shows to every process in the shared sandbox and on the host -- the LLM never sees the key.

**When to use:** The tool is a CLI binary in kali-sandbox (Type B/C MCP tool) that optionally accepts an API key (as a flag, an environment variable or a config file) but functions without it.

**How it works:**
1. Tool is always registered (MCP auto-discovery) -- availability does NOT depend on the key
2. The key is read at call time from the run's own settings (`run_user_settings().get('[tool]ApiToken', '')`), never stored on `PhaseAwareToolExecutor`, which every run of every owner shares. The existing `execute_wpscan`, `execute_gau` and `cve_intel` branches read `get_setting('USER_SETTINGS', {})` and still fall back to a `set_*` setter field that nothing in production calls: copy neither the setter nor the fallback
3. An `elif tool_name == "execute_[tool]"` branch in `PhaseAwareToolExecutor.execute()` reads the key and adds it as its own MCP argument (e.g., `api_token`) beside `args`. The MCP tool takes that parameter and gives it to the child as the environment variable the binary reads (`env=safe_env({"WPSCAN_API_TOKEN": api_token})`), or, for a binary that reads keys only from a config file, a `tempfile.mkstemp` file it passes with the binary's config flag and removes in `finally` (`execute_gau`). Never a CLI flag, never a file in the shared home directory
4. The injection is silent -- the LLM's original args are shown in the UI, the key is never exposed in prompts or logs
5. If the user manually passes the flag in their args, injection is skipped (no double-injection)

**Backend files:**
- `agentic/tools.py` -- Add the `elif` dispatch branch in `execute()` that reads the run's key per call and injects it
- `mcp/servers/<server>.py` -- The tool's extra key parameter, handed to the child's environment or a per-call file
- Nothing in `agentic/orchestrator.py`: `_apply_project_settings()` writes no key anywhere

**Reference implementation:** Read the `execute_wpscan` block in `PhaseAwareToolExecutor.execute()` and `execute_wpscan` in `mcp/servers/network_recon_server.py`.

**Example:**
```python
# In PhaseAwareToolExecutor.execute(), inside _invoke(active_tool):
elif tool_name == "execute_[tool]":
    args = tool_args.get("args", "")
    token = run_user_settings().get('[tool]ApiToken', '')   # this run's key, read per call
    if token and '--api-token' not in args:
        adjusted = {**tool_args, "api_token": token}
    else:
        adjusted = tool_args
    output = await active_tool.ainvoke(adjusted)

# In mcp/servers/network_recon_server.py: the child's environment, never its argv
@mcp.tool()
def execute_wpscan(args: str, _redamon_ctx: str = "", api_token: str = "") -> str:
    ...
    subprocess.run(["wpscan"] + cmd_args, capture_output=True, text=True, timeout=600,
                   env=safe_env({"WPSCAN_API_TOKEN": api_token} if api_token else None))
```

**Examples:** `execute_wpscan`

---

**Frontend files (BOTH patterns -- always required when adding API key support):**

The frontend integration is identical regardless of which backend pattern is used. The UI always shows missing-key warnings and provides inline modals to configure keys.

**Key files for API key integration:**
- `webapp/prisma/schema.prisma` -- `UserSettings` model (add key field)
- `webapp/src/app/api/users/[id]/settings/route.ts` -- GET masking + PUT whitelist
- `webapp/src/app/settings/page.tsx` -- `UserSettings` interface, `EMPTY_SETTINGS`, `SecretField` rendering, both response handlers (`fetchSettings()` and the save path's `applySaved`)
- `webapp/src/lib/rotationTools.ts` -- `ROTATION_TOOLS`, the one list of Key Rotation tools (tool name + settings field) that the page, the settings PUT and the key template all read
- `webapp/src/components/projects/ProjectForm/sections/ToolMatrixSection.tsx` -- `TOOL_KEY_INFO` + `fetchKeyStatus()`
- `webapp/src/app/graph/components/AIAssistantDrawer/hooks/useApiKeyModal.ts` -- `API_KEY_INFO` dict (top of file) + `fetchApiKeyStatus()` -- **duplicate** of ToolMatrix key check, used to show missing-key warnings in the chat UI
- `webapp/src/app/graph/components/AIAssistantDrawer/ToolExecutionCard.tsx` -- `TOOL_KEY_LABEL` dict -- maps tool name to human-readable API key label for chat tool cards

**The full frontend key lifecycle:**
1. **Storage**: Keys stored per-user (NOT per-project) in `UserSettings` Prisma model; a run spends its project owner's keys, never a collaborator's
2. **Frontend input**: Global Settings page (`/settings`) with `SecretField` component -- masked display, toggle visibility, key rotation
3. **Frontend warning**: Tool Matrix (`ToolMatrixSection.tsx`) shows yellow warning icon next to tools with missing keys, with inline modal to set the key
4. **Chat drawer warning**: `useApiKeyModal.ts` shows missing-key warnings in the chat UI (duplicate of Tool Matrix check)
5. **Runtime fetch**: `fetch_agent_settings()` (`agentic/project_settings.py`) fetches the project owner's keys via `GET /api/users/{ownerId}/settings?internal=true` each time a run loads its settings, into that run's `USER_SETTINGS`; the tools read them per call (`run_user_settings()`), and no manager caches one
6. **Key rotation** (optional): for tools with rate limits, the `rotationConfigs[<tool>]` extra keys are cycled every N calls by `run_key_rotator()` (Pattern 1 tools, through `_SEARCH_KEY_FIELDS`)

#### Step 7 — Check if tool needs progress streaming

Long-running tools (>60s typical) benefit from progress streaming. If needed, **TWO files** must be updated (they have duplicated logic):

1. `agentic/orchestrator_helpers/nodes/execute_tool_node.py` (`execute_tool_node()`) — hardcoded `is_long_running_*` checks per tool (`is_long_running_msf`, `is_long_running_hydra`) that pick `execute_with_progress()`
2. `agentic/orchestrator_helpers/nodes/execute_plan_node.py` (`_execute_single_step()`) — **same duplicated logic** for parallel plan execution

Both files need a new long-running detection check with the progress URL. Also:
3. Create an HTTP progress endpoint in the MCP server (follow Hydra pattern in `network_recon_server.py`)
4. Add `MCP_[TOOL]_PROGRESS_URL` env var in docker-compose files

#### Step 8 — Check if tool manages sessions or listeners

Read the end of `execute_tool_node()` in `agentic/orchestrator_helpers/nodes/execute_tool_node.py`. There are hardcoded post-execution handlers for `metasploit_console` (session detection, posted to `/session-chat-map`) and `kali_shell` (listener detection, posted to `/non-msf-sessions`). The **same code is duplicated** in `_execute_single_step()` in `execute_plan_node.py`.

If the new tool creates reverse shells, listeners, or sessions, add similar detection logic in **BOTH** files.

---

### Phase 2: Implementation Checklist

The exact set of files depends on the integration type chosen in Phase 1.

#### Core: Tool Registration & Execution (ALL types except A)

- [ ] **`agentic/prompts/tool_registry.py`** — Add entry to `TOOL_REGISTRY` dict with `purpose`, `when_to_use`, `args_format`, and `description`. Position matters: dict insertion order = tool priority. Read existing entries as reference.

- [ ] **`webapp/src/lib/mcp/schema.ts`** — Add the tool name to `BUILTIN_RESERVED_TOOL_NAMES`. That set stops a user's **outbound MCP Tool Plugin** registering a tool with the same name and shadowing yours at dispatch. The set lives in TypeScript and `TOOL_REGISTRY` in Python, so `agentic/tests/test_reserved_tool_names_parity.py` parses the TypeScript set and fails until it equals the names the agent reserves (`_builtin_tool_names()` in `agentic/mcp_registry.py`), in both directions.

- [ ] **`agentic/project_settings.py`** — Up to 3 changes:
  1. Add tool to the `'TOOL_PHASE_MAP'` entry of `DEFAULT_AGENT_SETTINGS`
  2. If dangerous: add to the module-level `DANGEROUS_TOOLS` frozenset
  3. If tool has configurable settings: add defaults to `DEFAULT_AGENT_SETTINGS` + mapping in `fetch_agent_settings()`

- [ ] **`agentic/orchestrator_helpers/roe_gate.py`** — If the tool fits an RoE category: add it to `CATEGORY_TOOL_MAP`; if it is a discovery or scanning tool: add it to `RECON_DISCOVERY_TOOLS`. Every executor path already asks `check_tool_call()`, so no node changes

- [ ] **`agentic/prompts/stealth_rules.py`** — If tool sends any traffic to a target: add a per-tool stealth constraint section under "Per-Tool Stealth Constraints". Specify what is ALLOWED and FORBIDDEN when stealth mode is active. Read existing tool sections as reference for format.

#### MCP Server (Types B and C only)

- [ ] **Type B**: Add `@mcp.tool()` function to `mcp/servers/network_recon_server.py` (or whichever server fits). Read `execute_nmap` in `nmap_server.py` as the simplest reference. Include: rich docstring with examples (LLM reads this), `shlex.split` for arg parsing, `subprocess.run` with appropriate timeout, ANSI escape stripping, error handling.

- [ ] **Types B and C**: Add the tool name to `SYSTEM_MCP_TOOL_NAMES` in `agentic/tools.py`. `agentic/tests/test_system_mcp_tool_coverage.py` parses every `@mcp.tool()` in `mcp/servers/` and fails on a name missing there.

- [ ] **Type C**: Create `mcp/servers/[tool]_server.py`. Read `nmap_server.py` for simple tools or `metasploit_server.py` for stateful tools. Then:
  - Register in `mcp/servers/run_servers.py` `SERVERS` dict with module name and port (next available: 8006; 8000 and 8002-8005 are taken)
  - Add an `MCPServer` entry to `_build_system_mcp_servers()` in `agentic/tools.py` — read the existing entries for the exact format (URL from `MCP_[TOOL]_URL`, timeouts, `auth=_mcp_auth`)
  - Add `MCP_[TOOL]_URL` env var to **BOTH** `docker-compose.yml` (root: `http://kali-sandbox:PORT/sse`) and `agentic/docker-compose.yml` (`http://host.docker.internal:PORT/sse`)
  - Expose port on kali-sandbox in root `docker-compose.yml`

#### API-Based Tool (Type D only)

- [ ] **`agentic/tools.py`** — Read `ShodanToolManager` or `GoogleDorkToolManager` as reference. Create:
  1. `[Tool]ToolManager` class — no key argument and no key attribute; `get_tool()` always returns the tool, which reads its key per call with `_call_key('<tool>')` and answers "not configured" without one
  2. A `_SEARCH_KEY_FIELDS` entry (`'<tool>': '<tool>ApiKey'`), so `run_key_rotator()` finds the run's key and its rotation pool
  3. Registration in `PhaseAwareToolExecutor.__init__()` — accept tool param, add to `self._all_tools`
  4. Dispatch branch in `PhaseAwareToolExecutor.execute()` — add an `elif` for the new tool in its `_invoke` closure, with correct arg extraction

- [ ] **`agentic/orchestrator.py`** — In `_setup_tools()`, build the manager (no key) and pass its tool to `PhaseAwareToolExecutor`, as the Shodan and Google dork managers are. Add nothing to `_apply_project_settings()`: no key is ever written onto a shared manager or the executor.

- [ ] **`agentic/tests/test_run_credentials_isolation.py`** — Add the new manager to `NoSharedKeyPath`, and a `SearchKeysPerRun` case: two owners' concurrent runs each spend their own key, and an empty key does not inherit the previous run's.

#### MCP Tool with Optional API Key (Type B/C + Pattern 2 from Step 6)

For MCP tools that accept an optional API key (tool works without it, key enriches results):

- [ ] **`agentic/tools.py`** -- Read the `execute_wpscan` elif branch as reference. Add an `elif tool_name == "execute_[tool]":` branch in `PhaseAwareToolExecutor.execute()` -- reads the run's key at call time (`run_user_settings().get('[tool]ApiToken', '')`), skips injection if the flag is already in args, adds the token as its own argument (`api_token`) beside `args`, never inside them, in a new dict (do NOT mutate the original), then calls `active_tool.ainvoke(...)` with it. No `set_[tool]_api_token()` setter: a key stored on the shared executor is spent by the next run of any owner

- [ ] **`mcp/servers/<server>.py`** -- Read `execute_wpscan` (environment) and `execute_gau` (per-call config file) as reference. Add the key parameter to the MCP tool and pass it as `env=safe_env({"<ENV_VAR>": key} if key else None)`, or in a `tempfile.mkstemp` file removed in `finally`; never on the command line, never in a file under the shared home directory

**Key difference from Type D:** No `ToolManager` class, no `_setup_tools()` change, no orchestrator change at all. The tool is always available via MCP auto-discovery. The key is injected beside the args at execution time and reaches the binary through its environment or a per-call file.

#### Kali Sandbox (if tool binary is not already installed)

- [ ] **`mcp/kali-sandbox/Dockerfile`** — Install the tool. Read existing installation patterns in the Dockerfile (apt, pip, go install, wget binary). Rebuild: `docker compose build kali-sandbox`

#### Frontend: Tool Matrix (ALL types except A)

- [ ] **`webapp/src/components/projects/ProjectForm/sections/ToolMatrixSection.tsx`** — Add a `{ id, label }` entry to the inline tools array rendered with `.map(tool => ...)` in the phase grid. Place it logically among existing tools.

- [ ] If tool needs API key: add entry to `TOOL_KEY_INFO` constant at top of file, and add missing-key check in `fetchKeyStatus()` callback. Read existing entries (web_search, shodan, google_dork) as reference.

#### Frontend: Prisma Schema & Database

- [ ] **`webapp/prisma/schema.prisma`** — Update the default JSON value of `agentToolPhaseMap` in the `Project` model to include the new tool's phase array.

- [ ] Run schema push: `docker compose exec webapp npx prisma db push` (NEVER use `prisma migrate`)

- [ ] **Update existing DB rows** — Existing projects won't have the new tool in their `agentToolPhaseMap`. The Prisma default only applies to NEW projects. Without this step, the agent will NOT see the tool in existing projects (it won't appear in the prompt's tool_name enum). Run:

```bash
docker compose exec postgres psql -U redamon -d redamon -c "
UPDATE projects
SET agent_tool_phase_map = agent_tool_phase_map::jsonb || '{\"TOOL_NAME\": [\"PHASE1\", \"PHASE2\"]}'::jsonb
WHERE NOT (agent_tool_phase_map::jsonb ? 'TOOL_NAME');
"
```

Replace `TOOL_NAME` with the tool name (e.g. `execute_httpx`) and `PHASE1`, `PHASE2` with the phases from `TOOL_PHASE_MAP` (e.g. `informational`, `exploitation`). Then rebuild the agent: `docker compose build agent && docker compose up -d agent`.

#### Frontend: API Key in UserSettings (Type D or any tool needing API keys)

- [ ] **`webapp/prisma/schema.prisma`** — Add `[tool]ApiKey` field to `UserSettings` model (read existing key fields as reference)
- [ ] **`webapp/src/app/api/users/[id]/settings/route.ts`** — Add to GET masking logic + PUT whitelist (read how existing keys are handled)
- [ ] **`webapp/src/app/settings/page.tsx`** — Add to `UserSettings` interface, `EMPTY_SETTINGS`, add `SecretField` component in JSX (read the Shodan `SecretField`, bound to `settings.shodanApiKey`, as reference), add to both response handlers (`fetchSettings()` and the save path's `applySaved`)
- [ ] **`webapp/src/components/projects/ProjectForm/sections/ToolMatrixSection.tsx`** — Add to `TOOL_KEY_INFO` + `fetchKeyStatus()` (if not already done above)
- [ ] **`webapp/src/app/graph/components/AIAssistantDrawer/hooks/useApiKeyModal.ts`** — Add to `API_KEY_INFO` dict (top of file) and missing key detection in `fetchApiKeyStatus()`. This is a **duplicate** of the ToolMatrix key check — the chat drawer also warns users about missing API keys.
- [ ] **`webapp/src/app/graph/components/AIAssistantDrawer/ToolExecutionCard.tsx`** — Add to the `TOOL_KEY_LABEL` dict — maps tool name to human-readable label shown on tool cards in chat when key is missing.

#### API Keys Import/Export Template (Type D or any tool needing API keys)

- [ ] **`webapp/src/lib/apiKeysTemplate.ts`** — Add new key to `ALLOWED_KEY_FIELDS`. It must stay in sync with the `UserSettings` interface in `settings/page.tsx`.
- [ ] **`webapp/src/lib/rotationTools.ts`** — If the key supports rotation, add one `ROTATION_TOOLS` entry (`tool`, `field`, `label`). The settings page (Key Rotation button), the settings PUT (which rows it saves) and the template all read this list, so there is no second copy to update; `rotationTools.test.ts` fails if the page has no Key Rotation button for the field.
- [ ] **`webapp/src/lib/apiKeysTemplate.test.ts`** — Update test counts to match (key count, rotation count, round-trip test).
- [ ] **`webapp/src/lib/apiUsage/registry.ts`** — Register a usage probe for the new key (a `providers/<id>.ts` with its `<id>.test.ts`, written from the provider's account/usage endpoint), or add the field to `NOT_PROBED` with the reason it cannot be checked for free. `registry.drift.test.ts` fails until the new field is covered, so the **Check API usage** report never silently skips a key.

#### Progress Streaming (if long-running tool, >60s typical)

- [ ] **MCP server** — Add progress tracking (read Hydra pattern in `network_recon_server.py`: thread-safe state, background subprocess, HTTP progress endpoint)
- [ ] **`agentic/orchestrator_helpers/nodes/execute_tool_node.py`** (`execute_tool_node()`) — Add long-running detection and progress execution branch (read the existing `is_long_running_msf` / `is_long_running_hydra` checks as reference)
- [ ] **`agentic/orchestrator_helpers/nodes/execute_plan_node.py`** (`_execute_single_step()`) — **DUPLICATE the same logic** (this file has copy-pasted tool execution for parallel plan mode)
- [ ] **docker-compose files** — Add `MCP_[TOOL]_PROGRESS_URL` env var to agent service in both files

#### Session/Listener Registration (if tool creates reverse shells or listeners)

- [ ] **`agentic/orchestrator_helpers/nodes/execute_tool_node.py`** (end of `execute_tool_node()`) — Add post-execution handler (read existing metasploit_console and kali_shell handlers as reference)
- [ ] **`agentic/orchestrator_helpers/nodes/execute_plan_node.py`** (`_execute_single_step()`) — **DUPLICATE the same handler**

#### Agent Defaults Endpoint

- [ ] **`agentic/api.py`** — If the tool has configurable settings, add them to the `/defaults` endpoint response

#### Optional: Tool-Specific Project Settings

If the tool has configurable parameters (like Hydra's threads, SQLMap's level/risk):

- [ ] **`webapp/prisma/schema.prisma`** — Add fields to `Project` model with `@default()` and `@map()`
- [ ] **`agentic/project_settings.py`** — Add to `DEFAULT_AGENT_SETTINGS` + mapping in `fetch_agent_settings()` (camelCase → SCREAMING_SNAKE_CASE)
- [ ] **Frontend section component** — Create `[Tool]Section.tsx` in `webapp/src/components/projects/ProjectForm/sections/` (read `BruteForceSection.tsx` or `SqliSection.tsx` as reference). There is no sections index: `ProjectForm.tsx` imports each section from its own file.
- [ ] **`webapp/src/components/projects/ProjectForm/ProjectForm.tsx`** — Import and render section in appropriate tab
- [ ] Run `docker compose exec webapp npx prisma db push`
- [ ] **`recon_settings/registry.yaml`** — Describe every new `Project` column, then run `python3 recon_settings/build.py`. The build FAILS on an undescribed column, so this layer announces itself.
  - **`mcp: settable` is the normal answer for an agent setting**, and that is a change from how this used to work. Agent behaviour was denied wholesale as "out of scope for a recon credential"; the result was 63 columns the API could not reach while the form could, which is a capability gap rather than a control. `parity.test.ts` now fails exactly that shape.
  - Put it in the `agent` group and give it real `bounds` or a `values:` list. The bound is the control, not the classification: a settable field with a fake bound (`0..10000000`) is a fake control on the form input AND the API validator at once, because both are generated from it.
  - Use `never` only for a column that configures nothing about a run, with a `deny_reason` the schema defines — `escalation` for `mcpKaliExecEnabled`, `secret` for a stored token, `internal` for state the application writes. There is no ALLOW/DENY table and no `agent`, `llm` or `intrusive` deny reason.
  - The build reads `Prisma.ProjectScalarFieldEnum` from the **generated client**, not `schema.prisma`, so it stays green until the client is regenerated (`docker compose build webapp`, or `prisma generate`). A green local run right after editing the schema does **not** mean you are done.

#### Optional: Attack Skill Integration

If the tool is the PRIMARY tool for a new built-in attack skill (like Hydra is for brute_force, or SQLMap is for sql_injection), follow [PROMPT.ADD_BUILTIN_AGENT_SKILL.md](PROMPT.ADD_BUILTIN_AGENT_SKILL.md): a built-in skill spans ten layers, and the list below is only the part that touches the tool.

- [ ] **`agentic/prompts/[skill]_prompts.py`** — Create new prompt file with tool workflow guidance and step-by-step methodology (read `sql_injection_prompts.py` or `brute_force_credential_guess_prompts.py` as reference)
- [ ] **`agentic/prompts/__init__.py`** — Add an `elif` branch in `_build_builtin_skill_workflow_parts()`, gated on `"<tool>" in allowed_tools`, that appends each static part through `_seam.resolve_skill_part(...)` and returns `parts` — read existing branches as reference (`_inject_builtin_skill_workflow()` inside `get_phase_tools()` is a thin wrapper over `build_builtin_skill_workflow()`; never add a branch there)
- [ ] **`agentic/prompts/skill_parts.py`** — Register each static part in `_SPECS`, in assembly order, or plugin overrides never reach the skill
- [ ] **`agentic/state.py`** — Add the skill id to `KNOWN_ATTACK_PATHS`
- [ ] **`agentic/project_settings.py`** — Add skill to `ATTACK_SKILL_CONFIG` > `builtIn` defaults in `DEFAULT_AGENT_SETTINGS`
- [ ] **`webapp/src/components/projects/ProjectForm/sections/AttackSkillsSection.tsx`** — Add to the `BUILT_IN_SKILLS` array
- [ ] **`webapp/src/app/api/users/[id]/attack-skills/available/route.ts`** — Add to `BUILT_IN_SKILLS` array
- [ ] **`webapp/src/app/graph/components/AIAssistantDrawer/phaseConfig.ts`** — Add to `KNOWN_ATTACK_PATH_CONFIG` for chat UI badge
- [ ] **`agentic/prompts/classification.py`** — Add the new skill to the attack path classification prompt

---

### Phase 3: Verification

1. **Build containers**: `docker compose build kali-sandbox` and/or `docker compose build webapp`
2. **Push schema**: `docker compose exec webapp npx prisma db push`
3. **Rebuild & restart services**: `docker compose build agent && docker compose up -d agent kali-sandbox` (agent code is baked into image -- rebuild is mandatory)
4. **Check Tool Matrix**: Project settings > AI Agent > Tool Matrix — new tool should appear with phase checkboxes
5. **Check MCP server**: `docker compose logs kali-sandbox` — tool's server should start without errors
6. **Test execution**: In agent chat, ask it to use the tool. Verify: correct phase availability, confirmation dialog if dangerous, output returned and truncated to `TOOL_OUTPUT_MAX_CHARS`
7. **Test phase restrictions**: Use tool in a disabled phase — agent should refuse
8. **Test RoE blocking** (if applicable): Enable RoE with the tool's category forbidden — verify blocked

---

### Architecture Reference

#### File Map

| File | Purpose | When to modify |
|------|---------|---------------|
| `agentic/prompts/tool_registry.py` | **TOOL_REGISTRY** — single source of truth for tool metadata and LLM descriptions | All types except A |
| `agentic/project_settings.py` | **TOOL_PHASE_MAP**, **DANGEROUS_TOOLS**, default settings, `fetch_agent_settings()` | All types except A |
| `agentic/tools.py` | **MCPToolsManager**, `_build_system_mcp_servers()` (system MCP server URLs), `SYSTEM_MCP_TOOL_NAMES`, **PhaseAwareToolExecutor** (dispatch + phase enforcement), API tool managers, the per-run key lookup (`run_user_settings`, `run_key_rotator`, `_SEARCH_KEY_FIELDS`), optional key injection | Types B/C (`SYSTEM_MCP_TOOL_NAMES`), Type C (server entry), Type D (manager + `_SEARCH_KEY_FIELDS` + dispatch), Type B/C with optional API key (elif branch) |
| `agentic/orchestrator.py` | Orchestrator -- `_setup_tools()` builds the tool managers once, with no key; `_apply_project_settings()` binds the run's settings and writes no credential | Type D (manager construction in `_setup_tools()`) |
| `agentic/prompts/base.py` | Dynamic prompt builders — **auto-reads TOOL_REGISTRY, no change needed** | Never |
| `agentic/orchestrator_helpers/nodes/execute_tool_node.py` | Tool execution — progress streaming, session detection | If long-running or session-creating |
| `agentic/orchestrator_helpers/nodes/execute_plan_node.py` | **Duplicate** of above for parallel plans | If long-running or session-creating |
| `agentic/orchestrator_helpers/roe_gate.py` | `check_tool_call()`, the RoE + recon-budget gate every executor path asks; `CATEGORY_TOOL_MAP`, `RECON_DISCOVERY_TOOLS` | If RoE-categorized or a discovery/scanning tool |
| `agentic/orchestrator_helpers/nodes/tool_confirmation_nodes.py` | Dangerous tool confirmation — **auto-reads DANGEROUS_TOOLS** | Never |
| `agentic/orchestrator_helpers/nodes/think_node.py` | ReAct reasoning — **auto-reads TOOL_PHASE_MAP + TOOL_REGISTRY** | Never |
| `agentic/prompts/stealth_rules.py` | Per-tool stealth constraints (FORBIDDEN/RESTRICTED/allowed) | If tool sends traffic to target |
| `agentic/prompts/__init__.py` | `_build_builtin_skill_workflow_parts()` (one branch per built-in skill) | If tool is part of an attack skill |
| `agentic/prompts/skill_parts.py` | `_SPECS`, the registry of built-in skill parts a plugin may override | If tool is part of a new attack skill |
| `agentic/prompts/classification.py` | Attack path classification prompt | If tool is part of a new attack skill |
| `mcp/servers/run_servers.py` | **SERVERS** dict — MCP server registry with ports | Type C only |
| `mcp/servers/network_recon_server.py` | MCP tools: curl, naabu, kali_shell, execute_code, hydra | Type B (add tool here) |
| `mcp/servers/nmap_server.py` | MCP tool: nmap — reference for simple Type C | — |
| `mcp/servers/metasploit_server.py` | MCP tool: metasploit — reference for stateful Type C | — |
| `mcp/kali-sandbox/Dockerfile` | Kali sandbox — tool binary installation | If tool not already in Kali |
| `mcp/kali-sandbox/entrypoint.sh` | Container startup sequence | Rarely |
| `webapp/prisma/schema.prisma` | `Project.agentToolPhaseMap` default, `UserSettings` API keys | All types except A |
| `webapp/src/components/projects/ProjectForm/sections/ToolMatrixSection.tsx` | Tool × phase grid + API key warnings/modals | All types except A |
| `webapp/src/components/projects/ProjectForm/sections/AttackSkillsSection.tsx` | Built-in attack skill toggles | If part of attack skill |
| `webapp/src/components/projects/ProjectForm/ProjectForm.tsx` | Tab layout, section rendering | If adding settings section |
| `webapp/src/app/graph/components/AIAssistantDrawer/phaseConfig.ts` | `KNOWN_ATTACK_PATH_CONFIG` — chat UI badges | If part of new attack skill |
| `webapp/src/app/graph/components/AIAssistantDrawer/hooks/useApiKeyModal.ts` | `API_KEY_INFO` + `fetchApiKeyStatus()` — missing key detection in chat drawer | If tool needs API keys |
| `webapp/src/app/graph/components/AIAssistantDrawer/ToolExecutionCard.tsx` | `TOOL_KEY_LABEL` — human label on tool cards when key missing | If tool needs API keys |
| `webapp/src/app/api/users/[id]/settings/route.ts` | API key storage, masking, PUT whitelist | If tool needs API keys |
| `webapp/src/app/api/users/[id]/attack-skills/available/route.ts` | Built-in skills list | If part of new attack skill |
| `webapp/src/app/settings/page.tsx` | Global Settings — API key inputs with `SecretField`, `UserSettings` interface | If tool needs API keys |
| `webapp/src/lib/rotationTools.ts` | `ROTATION_TOOLS` — the single Key Rotation tool list (page, settings PUT, template) | If the key supports rotation |
| `webapp/src/lib/apiKeysTemplate.ts` | Bulk import/export JSON template — `ALLOWED_KEY_FIELDS`, `ALLOWED_TUNNEL_FIELDS` allowlists (rotation tools come from `rotationTools.ts`) | If tool needs API keys |
| `webapp/src/lib/apiKeysTemplate.test.ts` | 82 unit tests for template generation and validation — field counts, round-trips, injection tests | If tool needs API keys (update counts) |
| `docker-compose.yml` | Root compose — agent env vars, kali-sandbox ports | Type C |
| `agentic/docker-compose.yml` | Dev compose — agent env vars | Type C |
| `agentic/api.py` | Agent `/defaults` endpoint | If tool has configurable settings |

#### Tool Execution Flow

```
User message → WebSocket → Agent Orchestrator
    ↓
Think Node (auto-reads TOOL_REGISTRY + TOOL_PHASE_MAP)
    ↓ decides: action=use_tool, tool_name="execute_[tool]"
    ↓
Phase Check: is_tool_allowed_in_phase() → blocked if not in TOOL_PHASE_MAP
RoE + recon budget: roe_gate.check_tool_call() → blocked if the RoE forbids the tool or its category
    (CATEGORY_TOOL_MAP) or the phase, or if informational recon is past its budget (RECON_DISCOVERY_TOOLS)
Dangerous Check: in DANGEROUS_TOOLS? → pause for user confirmation
    ↓
Long-running check (hardcoded per tool) → execute_with_progress() or execute()
    ↓
PhaseAwareToolExecutor.execute() dispatch:
    - Non-MCP tools: hardcoded elif branches (query_graph, web_search, shodan, google_dork, ...)
    - MCP tools with optional API key: elif branch reads the run's key, passes it beside the args (execute_wpscan, execute_gau, cve_intel)
    - MCP tools (Types B/C): automatic via else branch
    ↓
Output: _extract_text_from_output() → truncate to TOOL_OUTPUT_MAX_CHARS
    ↓
Post-execution handlers (hardcoded): session detection, listener registration
    ↓
Execution trace updated → Think Node loops back
```

#### MCP Auto-Discovery (key insight for Types B/C)

For Type B, adding a new `@mcp.tool()` to an existing server means it gets **auto-discovered** by `MCPToolsManager.get_tools()` — no dispatch change in `tools.py`. The tool name in `_tools_cache` matches the Python function name. This is why Type B requires fewer files than Type D.

The one `tools.py` edit it still needs is its name in `SYSTEM_MCP_TOOL_NAMES`. Once a user MCP server is loaded, `register_mcp_tools()` keeps only the tools a user manifest declares plus that set, so a system tool missing from it is dropped ("Skipped registering ... not declared in any manifest") while the prompt still offers it, and every call answers "Tool not found". `agentic/tests/test_system_mcp_tool_coverage.py` fails on the gap.

#### Naming Conventions

| Layer | Convention | Example |
|-------|-----------|---------|
| MCP function name | `execute_[tool]` | `execute_nikto` |
| Tool Registry key | Same as MCP function name | `"execute_nikto"` |
| TOOL_PHASE_MAP key | Same | `'execute_nikto'` |
| DANGEROUS_TOOLS entry | Same | `'execute_nikto'` |
| CATEGORY_TOOL_MAP | Same | `'exploitation': [..., 'execute_nikto']` |
| Tool Matrix ID | Same | `{ id: 'execute_nikto', label: 'execute_nikto' }` |
| Prisma setting field | camelCase | `niktoTimeout` |
| Python setting key | SCREAMING_SNAKE_CASE | `'NIKTO_TIMEOUT'` |
| DB column name | snake_case via `@map()` | `nikto_timeout` |
| MCP URL env var | `MCP_[TOOL]_URL` | `MCP_NIKTO_URL` |
| Progress URL env var | `MCP_[TOOL]_PROGRESS_URL` | `MCP_NIKTO_PROGRESS_URL` |

---

### Decision Tree: Which Integration Type?

```
Is the tool already in Kali or trivially installable?
├─ YES → Is kali_shell (300s timeout, no custom parsing) sufficient?
│   ├─ YES → Type A (Dockerfile + update kali_shell description)
│   └─ NO → Is it fire-and-forget (not stateful)?
│       ├─ YES → Type B (new @mcp.tool() on existing server)
│       │   └─ Does it accept an optional API key via CLI flag?
│       │       ├─ YES → Type B + Pattern 2 (silent key injection in executor)
│       │       └─ NO → Type B only (no key management needed)
│       └─ NO → Type C (new dedicated MCP server)
└─ NO → Is it an external API/service?
    ├─ YES → Does the tool REQUIRE the key to function?
    │   ├─ YES → Type D + Pattern 1 (key read per call -- no key = "not configured")
    │   └─ NO → Type D + Pattern 2 (always available, key enriches results)
    └─ NO → Can the binary be installed in Kali?
        ├─ YES → Add to Dockerfile → then Type B or C
        └─ NO → Investigate alternative or skip
```
