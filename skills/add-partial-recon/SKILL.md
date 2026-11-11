---
name: add-partial-recon
description: >
  Adding partial-recon support for a tool: running a single pipeline phase
  on demand from the workflow graph, reading its inputs from the existing Neo4j
  graph and merging results back. The input-node map decides the modal UI, and
  some input types must never be manually entered.
  Trigger: adding a tool to partial recon; a new recon/partial_recon_modules/*.py;
  editing SECTION_INPUT_MAP in nodeMapping.ts; wiring the partial-recon modal or a
  single-phase re-run.
license: MIT
metadata:
  author: redamon
  version: "1.1.0"
  scope: [recon]
  auto_invoke:
    - "Adding partial-recon support for a recon tool"
    - "Editing SECTION_INPUT_MAP or the partial-recon modal wiring"
---

## When to Use

- Making an existing recon tool runnable as a single on-demand phase from the graph.

For adding the tool to the full pipeline, use `recon-tool-integration`. For the
graph write itself, use `graph-db-writes`. This skill is the partial-recon path:
graph-sourced inputs, the modal, and the single-phase re-run.

---

## Critical Rules

- **NEVER let partial-recon results create duplicate nodes.** Partial runs merge
  into the **existing** graph and must dedup via `MERGE` on the tenant triple -
  see `graph-db-writes`. Partial and full share the same graph.
- **NEVER write back a field the partial run did not measure.** A builder
  rebuilds a full-run dict from the graph; handed whole to a full-pipeline
  writer, every node in it is rewritten from the graph's own lossy copy. Give
  the writer only what your tool measured (`measured_port_data` in
  [port_scanning.py](../../recon/partial_recon_modules/port_scanning.py) cuts
  port data to it), or write a dedicated Cypher for your tool's own fields. A
  shared writer never takes `IP.is_cdn` from true to false, sets
  `Port.passive_only` false only for a port its caller saw (a detail carrying
  the graph's mark is none: `update_graph_from_port_scan` in
  [port_mixin.py](../../graph_db/mixins/recon/port_mixin.py)), and writes
  enrichment fields (category, sample values, provenance) with `coalesce` or
  `ON CREATE SET`.
- **NEVER expose a graph-only input type as a manual textarea.** `SECTION_INPUT_MAP`
  in [nodeMapping.ts](../../webapp/src/components/projects/ProjectForm/nodeMapping.ts)
  lists what the tool reads from the graph, but only the types that make sense for
  manual entry get a user field. Types like `Port` and `Endpoint` come from the
  graph only and must not be hand-entered.
- **ALWAYS wire the shared entry so it works in BOTH the full pipeline AND partial
  recon.** Partial recon is spawned as a **separate** container from the full
  pipeline (`recon_orchestrator/container_manager.py`); hook the shared entry
  function once so both inherit (see `recon-ai-enrichment` for the same rule).
- **ALWAYS mirror the reference impl matching your tool's input shape**, not an
  arbitrary one: Naabu (`Subdomain` + `IP`), Masscan (`IP` only), Nmap
  (`IP` + `Port`), Katana (`URL`). The input-node shape drives the whole wiring.
- **ALWAYS read the run's roots through `scope_roots(config)`, NEVER
  `config["domain"]`.** A Domain-batch run covers every root in
  `config["domains"]`; `config["domain"]` is only the first, so a tool reading it
  silently skips the rest. [test_partial_scope_guard.py](../../recon/tests/test_partial_scope_guard.py)
  fails the gate on a direct read. Pass `domain_groups=config.get("domain_groups")`
  (built from the container's `SCOPE_GROUPS`) to the graph builders so each root
  keeps its group's scope: an EXACT group, a single-domain prefix list included,
  scans only its listed hosts. Attach each typed host to the org Domain of its
  scan root, `attach_org(root_for_host(host, roots))`: the graph has one Domain
  per registrable domain, never one per scan root.
- **NEVER re-implement the typed-input scope check in a module.** The orchestrator
  and `_prepare_scope` (`filter_partial_user_input`) already dropped every typed
  host, URL host, over-wide CIDR and out-of-scope attach target, and a typed URL's
  host joins the writer's scope only through `_scope_partial_urls`. The run is
  also refused before your module runs while the graph holds an older scope
  model's Domain (`_legacy_graph_refusal`, fails closed).
- **ALWAYS loop an API that takes one domain per call through `run_per_root`**,
  never a bare `for`. It fails only the root that raised or called `sys.exit`,
  retries a rate-limited root once, and returns the `{root: status}` the run report
  and exit code read. Mirror Urlscan (a 429 returns `STATUS_RATE_LIMITED`) or Shodan.
- **A writer attaches a host through `attach_for_host(host, recon_data)`**
  (`graph_db/mixins/recon/scope.py`): the scope is the longest scan root among
  `attach_roots(recon_data)` (every project root, from `all_project_roots`, so a
  host found under another group's root joins it instead of becoming an
  `ExternalDomain`), and the Domain is that root's org (`org_for_scan_root`). A
  partial run's recon dicts carry no `scope_groups`; `_prepare_scope` sets the
  run's default (`set_project_scope` -> `set_run_scope_groups`), and a dict's own
  `scope_groups` always wins.

---

## Input-node shape -> reference impl

| Tool reads | User enters | Mirror |
| --- | --- | --- |
| Subdomain + IP | Subdomain + IP (two textareas) | Naabu |
| IP only | IP (one textarea) | Masscan |
| IP + Port | IP (Port from graph) | Nmap |
| BaseURL | URL (maps to a BaseURL node) | Katana |

## Commands

```bash
# recon/*.py is spawned fresh per job (volume-mounted) - no rebuild
./redamon.sh test unit                    # recon + root-recon sections
```

## Resources

- [docs/readmes/coding_agent_prompts/PROMPT.ADD_PARTIAL_RECON.md](../../docs/readmes/coding_agent_prompts/PROMPT.ADD_PARTIAL_RECON.md) - full walkthrough, modal UI, input validation, reference impls
- Related skills: `recon-tool-integration`, `graph-db-writes`, `recon-ai-enrichment`
