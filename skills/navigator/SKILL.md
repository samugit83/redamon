---
name: navigator
description: >
  AI Navigator: the read-only chat overlay that answers questions about RedAmon's docs and one
  project's data, on the person's own model. Every project read is a webapp callback
  re-authorized fresh; no tool writes; a tool declares its permissions, exact MCP scopes and
  level; nothing a chat calls takes a process-wide resource. Trigger: editing agentic/navigator/,
  webapp/src/lib/navigator/, webapp/src/app/api/navigator/, webapp/src/app/api/internal/navigator/,
  webapp/src/components/navigator/, or webapp/src/lib/authz/navigatorPolicy.ts; adding a Navigator
  tool or route.
license: MIT
metadata:
  author: redamon
  version: "1.0.0"
  scope: [root, agentic, webapp]
  auto_invoke:
    - "Editing AI Navigator (agentic/navigator, lib/navigator, the navigator routes or components)"
    - "Adding a tool AI Navigator can call"
---

## When to Use

- Adding, removing or changing a tool AI Navigator calls, or a route under `/api/navigator`.
- Changing how a Navigator run is authorized, bound to its login, stopped or saved.
- Changing the wiki index, the citations, the router or the specialists in `agentic/navigator/`.

The user doc is the wiki page `AI-Navigator`; the developer notes are the AI Navigator sections of
`docs/readmes/README.WEBAPP.md` and `docs/readmes/README.AGENTIC_SYSTEM.md`. Also follow `rbac-authz` (every check), `agent-in-the-loop`
(the model builder) and `mcp-server-tools` (anything under `webapp/src/lib/mcp/`).

---

## Critical Rules

- **Every project read goes through the internal tool route.** The agent holds the model and the
  wiki, never project data: a tool is a `POST /api/internal/navigator/tools/<name>` callback with
  the master key and the run's credential, and the route takes every id from the run entry
  ([run.ts](../../webapp/src/lib/navigator/tools/run.ts) `runNavigatorTool`). Never read Neo4j,
  Postgres or the workspace from `agentic/navigator/`.
- **The person's model only.** Read `readFeatureModel(personId, 'navigator')` and build it with
  `_build_feature_llm` (refuses `loop/`); never the project owner's model, never the MCP
  `question` path (`queryGraph` with `cypher` only), never `/graph/nl-query`.
- **No write tool.** Every tool's permissions reach at most `R` / `R*`
  ([registry.test.ts](../../webapp/src/lib/navigator/tools/registry.test.ts) fails otherwise).
- **A new tool declares its permissions, its exact MCP scopes and its level, and gets a refusal
  test.** `registry.test.ts` calls each MCP-backed tool with exactly its scopes and with each one
  removed; a function whose `requireScope` changed fails it. Call the MCP functions directly
  through `navigatorMcpContext`, never `server.ts`'s `handler()` (it writes `mcp.*` audit rows).
- **Nothing a chat calls may take a shared, process-wide resource.** `compare_scan_versions`
  compares two stored versions only: a live side takes a graph snapshot slot that version
  activation waits on.
- **Results go through `shapeToolResult`** ([output.ts](../../webapp/src/lib/navigator/tools/output.ts)):
  step content stripped below `R*`, owner-only columns never returned, secret shapes masked
  unless the RoE says `full_access`, size caps.
- **A run is bound to its login.** The guard's context carries the session version, device
  session and act-as start; each tool call checks them fresh, and every `onAccessReduced` plan,
  the act-as end, teardown, transfer and emergency stop abort the matching runs in the registry
  ([runRegistry.ts](../../webapp/src/lib/navigator/runRegistry.ts)).
- **Threads are their author's alone.** `{id, projectId}` plus `ownsRow`, the same 404 for a missing,
  another person's or another project's thread; no manager, oversight or break-glass read; no
  route creates an empty thread.
- **No secret value reaches the model unless the project's RoE says `full_access`.** Every result
  goes through `shapeToolResult`, which withholds the properties in `SECRET_VALUE_KEYS` by name
  before the secret-shape masker (a 40-character AWS secret has no shape), and `run_cypher` refuses
  a query that names one or reads a property by a computed key
  ([secretGuard.ts](../../webapp/src/lib/navigator/tools/secretGuard.ts)). Judge a query as Neo4j
  reads it, never as raw text: Neo4j decodes `\uXXXX` before it lexes (`s.\u006datched_text`), a
  comment may sit before a subscript (`properties(s)/**/[k]`), and most keywords are valid variable
  names (`limit[k]`); each of these read values in the security review. A tool that returns a new
  secret-bearing field adds it to `SECRET_VALUE_KEYS`.
- **Never log message text, deltas, tool results or Cypher**, in the webapp or the agent: ids,
  codes and timings only (`test_navigator_logging.py`, `stream.test.ts`). That includes the code
  a tool calls: a Neo4j error quotes the query and the value it failed on, so `/graph/exec` and
  `graphClient.ts` log a code and a status, never the exception's text.

---

## Commands

```bash
cd webapp && npx vitest run --no-file-parallelism src/lib/navigator src/app/api/navigator src/app/api/internal/navigator src/components/navigator
./agentic/run_tests.sh tests/test_navigator_graph.py   # one file; the gate runs each in isolation
bash tests/redamon_wiki_checkout_test.sh
./agentic/run_tests.sh tests/test_navigator_docs_eval.py   # docs retrieval hit@3 against its floors
node testing/navigator_eval/run.mjs --user <userId>       # by hand: 73 cases on a real model, synthetic project
```
