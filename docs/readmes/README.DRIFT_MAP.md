# What goes stale: the RedAmon drift map

Every place in this repository where one fact is written down more than once, or
copied from something that keeps changing, and so can silently stop being true.

Use it **before** you change something: find the thing you are touching in the
tables below, and you get every other place that has to move with it, the guard
that will (or will not) catch you, and the command that refreshes it.

> **Last audit: 2026-10-25. Last re-map: 2026-10-25. Last fix pass: 2026-10-25.**
> Branch `fix_multiple_recon_bugs_23_oct`. The audit ran six parallel read-only
> audits, one per area, and every claim was re-verified against the source. The
> fix pass the same day fixed items #1-#64, then the staleness it found on the
> way (#65-#86; the numbers in that range that were not staleness left the page),
> and the guards it added moved from section 6 to section 3. Section 2 is empty.
> Numbers are never reused: the next audit starts at #89.
> `git log --grep 'drift-map #N'` finds the commit that fixed item N.

## Contents

1. [How to read this page, and how it is kept current](#1-how-to-read-this-page-and-how-it-is-kept-current)
2. [Already stale on 2026-10-25](#2-already-stale-on-2026-10-25)
3. [The guards that exist, and their blind spots](#3-the-guards-that-exist-and-their-blind-spots)
4. [Catalogue by area](#4-catalogue-by-area)
   - [4.1 Agent tools](#41-agent-tools-the-tool-registry-and-its-satellites)
   - [4.2 Built-in attack skills](#42-built-in-attack-skills-and-community-skills)
   - [4.3 LLM providers and model ids](#43-llm-providers-and-model-ids)
   - [4.4 Settings registry and the default cascade](#44-recon-settings-registry-and-the-default-cascade)
   - [4.5 Recon presets](#45-recon-presets-and-every-other-kind-of-preset)
   - [4.6 Recon pipeline mechanics](#46-recon-pipeline-mechanics)
   - [4.7 Graph schema](#47-graph-schema)
   - [4.8 Inbound MCP server and API docs](#48-inbound-mcp-server-and-api-docs)
   - [4.9 Plugin platform contract](#49-plugin-platform-contract)
   - [4.10 Cross-image mirrors](#410-cross-image-mirrors-python-typescript-and-other-images)
   - [4.11 Bundled third-party data and external ids](#411-bundled-third-party-data-and-external-ids)
   - [4.12 Version pins and images](#412-version-pins-and-container-images)
   - [4.13 Control plane, compose, env, tests](#413-control-plane-compose-env-and-the-test-runner)
   - [4.14 Docs, wiki and agent rulesets](#414-docs-wiki-and-agent-rulesets)
   - [4.15 Data stored in Postgres and Neo4j](#415-data-stored-in-postgres-and-neo4j)
5. [Patterns: why things drift here](#5-patterns-why-things-drift-here)
6. [Recommended new guards, ranked](#6-recommended-new-guards-ranked)
7. [Re-running this audit](#7-re-running-this-audit)

---

## 1. How to read this page, and how it is kept current

### Kinds of drift

| Kind | What it is | Example |
|---|---|---|
| **Generated** | A file a script writes from a source. Stale when the source changed and nobody re-ran the script. | `registry.yaml` -> two `registry.json` |
| **Mirror** | The same fact typed by hand in 2+ places, often across languages or images. | the hard guardrail in 3 Python copies + TS |
| **Enumeration** | A list that must name every member of a set defined elsewhere. Stale when the set grows. | the UI tool matrix listing every agent tool |
| **Frozen copy** | A default copied into each database row at creation. Stale for every existing row the moment the default changes. | `agentToolPhaseMap` JSON per project |
| **Split path** | The same rule enforced on one execution path and not on its twin. | the `/traffic/replay` and `/browser` phase gates, which ignore `TOOL_PHASE_MAP` |
| **External data** | A snapshot of something outside the repo that keeps moving. | MITRE CWE/CAPEC, CDN prefixes, PSL |
| **Pin** | A version, tag, digest, model id, UUID or key that the world moves past. | `TRUFFLEHOG_VERSION=3.96.0`, `claude-opus-4-6` |
| **Prose** | Docs, prompts, comments and UI text that name code identifiers, paths, counts or behaviour. | "21 built-in presets" when there were 26 |

### Guard levels

| Guard | Meaning |
|---|---|
| **GEN** | A generator with a `--check` (or byte-compare) mode that the unit gate actually runs. Drift fails the gate. |
| **TEST** | A test reads *both* sides and compares them. |
| **PART** | A test covers one direction, one copy, only some members, compares with a hand copy, or duplicates the cases instead of comparing the constant. |
| **NONE** | Nothing fails. Drift is found by a user, or never. |

> There is **no CI** (`.github/` holds only issue and PR templates) and the
> pre-commit hook is advisory only. Every guard below fires only when someone
> runs `./redamon.sh test unit` (or the webapp suite). "Guarded" means "caught at
> the next gate run", not "cannot be merged". A guard that looks like one and
> is not goes in section 2.2.

### How this page is kept current

Three passes, on three cadences. The prompts that run them are kept in the
maintainer's prompt library, outside this repository.

| Pass | Cadence | What it does | Writes |
|---|---|---|---|
| **Audit** | weekly, after a release or a large merge | Six read-only agents, one per area, re-check every item in section 2 and every number and line reference in sections 3 and 4, and look for new copies in their area. One writer re-verifies and updates the page. | only this page: fixed rows deleted from section 2, new ones added, the "last audit" date refreshed |
| **Fix** | on demand, after reading an audit | Fixes the section-2 items you name, keeps the gate green, one commit per group. | code, docs, wiki, and the fixed rows removed from here |
| **Re-map** | monthly, after a structural refactor, or when audits keep finding drift outside this page | Six read-only agents, one per discovery lens (declared mirrors, enumerations next to a source, build plumbing, external data and pins, prose, stored data), sweep the whole repository from `git log --since=<last re-map>`. | every section of this page: new and obsolete section-4 rows, new patterns, a re-ranked section 6, the "last re-map" date |

Run them locally in the main checkout, never as a cloud routine: a fresh clone
has an empty `redamon.wiki` (a submodule a plain clone leaves empty), no Docker
gate and no site project, so most doc checks would skip. Every guard from
section 6 that becomes a real test moves a check out of the audit into the gate.

---

## 2. Already stale on 2026-10-25

Ordered by impact within each group. Numbers are stable handles for the fix
pass. Each item was verified by reading both sides; "inferred" marks an effect
reasoned from the code and not reproduced.

### 2.1 Behaviour: wrong results at runtime

None open.

### 2.2 Guards that do not guard

None open.

### 2.3 Agent-facing and developer text (produces wrong code)

None open.

### 2.4 Counts and links in docs

None open.

### 2.5 Dead or diverging data

None open.

---

## 3. The guards that exist, and their blind spots

### 3.1 Generators

| Source | Command | Outputs | Gate check |
|---|---|---|---|
| `recon_settings/registry.yaml` (+ Prisma join; each tool's `produces` from `SECTION_NODE_MAP` in `nodeMapping.ts`) | `python3 recon_settings/build.py` | `recon_settings/registry.json`, `webapp/src/lib/reconSettings/registry.json` (byte-identical), `webapp/src/lib/reconSettings/registryDigest.generated.ts`, `recon_settings/roe_parse_prompt.py` | GEN: `tests/test_registry_build_check.py` runs `build.py --check`; the gate also compares the two JSON copies, the prompt against the JSON, and the JSON against Prisma |
| `registry.json` | `cd webapp && npm run docs:settings` | `redamon.wiki/Project-Settings-Registry.md` | `settingsReference.test.ts` byte-compare, **only when the wiki checkout is present** |
| Prisma columns with no registry entry | `python3 tooling/scripts/extract_recon_registry.py` | draft entries in `registry.yaml` (top-up, never overwrites) | `registry.prisma.test.ts` fails on a column with no entry |
| `graph_db/node_filters/catalog.yaml` | `python3 graph_db/node_filters/build.py` | `graph_db/node_filters/catalog.json`, `webapp/src/lib/nodeFilters/catalog.json`, and the 31 `fixtures/*.json` mirrored into `webapp/src/lib/nodeFilters/fixtures/` | GEN: `build.py --check` via `tests/test_node_filters_engine.py:63-66`; also fails on a setting the registry lacks or a form tab `ProjectForm.tsx` lacks |
| `graph_db/schema_sections.md` | `python3 tooling/scripts/seed_schema_catalog.py` | `graph_db/schema_catalog.py` | GEN: `--check` regenerates and compares with the committed `graph_db/schema_catalog.py`; `recon/tests/test_schema_catalog.py` runs it and checks the segments against `schema_sections.md` |
| live `tools/list` of the inbound MCP server | `cd webapp && npm run docs:mcp` | `redamon.wiki/MCP-API-Reference.md` | `apiReference.test.ts` byte-compare, **only when the wiki checkout is present** |
| zod plugin schemas | `cd webapp && npm run plugins:schemas` | `webapp/src/lib/plugins/schemas/json/{manifest,screen,catalog}.schema.json` | `schemasExport.test.ts` |
| multi-mute suggestion contract | `MULTI_MUTE_CONTRACT_WRITE=1` on `agentic/tests/test_multi_mute_contract.py` | `webapp/src/app/graph/components/MuteNode/multiMuteSuggest.contract.json` | the same test, compare mode |
| node-filter run contracts | `NODE_FILTER_CONTRACT_WRITE=1` on `agentic/tests/test_node_filter_runs.py` and `route.nodeFilter.test.ts` | `webapp/src/lib/nodeFilters/contracts/{run_callbacks,project_get}.json` | the same tests, compare mode |
| `skills/*/SKILL.md` frontmatter | `bash skills/skill-sync/assets/sync.sh` | the "Auto-invoke Skills" tables in every `AGENTS.md` | `sync.sh --dry-run` (no gate test) |
| skill + AGENTS.md citations | `bash skills/skill-sync/assets/drift-audit.sh` | report of dead cited paths in `skills/*/SKILL.md` and `AGENTS.md`; exits 1 on any | manual; a markdown link resolves only from the citing file's folder; `tests/drift_audit_test.sh` tests the script; `citation-check.sh` in the advisory pre-commit hook |
| cited repo paths in every doc | `bash skills/skill-sync/assets/drift-audit.sh --docs` | dead paths in `docs/readmes/**`, `README.md`, `CONTRIBUTING.md`, the top-level wiki, `SKILL.md`, `AGENTS.md` (a path counts only if git tracks it) | GEN-like: `tests/docs_cited_paths_test.sh`; `tests/fixtures/docs_paths_drift_{wiki,readmes,root}.json` hold only the seven tokens that look like paths and are not (an entry that stops failing must leave) |
| built-in skill prompts | `agentic/tests/tools/record_skill_golden.py` | `agentic/tests/fixtures/skill_workflow_golden.json` | `test_skill_workflow_golden.py` (fails until re-recorded) |
| the settings resolution path | `recon/tests/regen_golden_settings.py` (inside `redamon-recon`, see `README.SETTINGS_REGISTRY.md`) | `recon/tests/fixtures/golden_settings/*.json` (18 cases) | `test_golden_master.py` |
| the two PSL snapshots | `python3 tooling/scripts/psl_drift_report.py` | report only | manual release step (`README.DEV.md` §5.8) |
| the wiki | `DevergoLabs/scripts/sync-docs.mjs` (nightly `refresh-docs.sh` on the server), `add-wiki-canonical.mjs` | redamon.org `/docs` pages (top-level pages only; `hacklab/` and the session subtrees are not copied, so links into them probably break there, unverified), the canonical banner on each wiki page | none; the banner bytes are duplicated in `webapp/src/lib/mcp/apiReference.ts` `CANONICAL_BANNER` |

On 2026-10-25 all three Python generators reported up to date (all three are
gate checks since wave 1, and `tooling/hooks/pre-commit` runs them when a commit
stages a generator's files), the skill sync dry run changed nothing,
`drift-audit.sh` found one false positive (`tools/list`, an MCP method name), and
ten webapp drift suites passed (298 tests; the one skip is the write-mode case).

### 3.2 Parity tests worth knowing

| Pair | Test |
|---|---|
| Python `DEFAULT_SETTINGS` keys <-> registry, both directions; registry `runtime_key` <-> the `fetch_project_settings` mapping | `recon/tests/test_registry_runtime_keys.py`, `recon/tests/test_settings_mapping_coverage.py` |
| every Prisma `@default` == its Python default, recon and agent, with a named allowlist | `recon/tests/test_prisma_default_parity.py`, `agentic/tests/test_prisma_default_parity.py` |
| every agent column is loaded through `AGENT_SETTING_COLUMNS`; the agent `/defaults` emits only real columns, each with its Python default | `agentic/tests/test_agent_setting_columns.py`, `agentic/tests/test_agent_defaults_columns.py` |
| `registry.yaml` <-> its four generated artifacts | `tests/test_registry_build_check.py` (`build.py --check`) |
| registry bound == the hand-written server validator's bound | `webapp/src/lib/validation/registryBounds.test.ts` |
| `tools.*.partial_recon_module` == the module `partial_recon.py` runs | `recon/tests/test_registry_partial_recon_module.py` |
| every `.env.example` key is forwarded by compose or is a `HOST_ONLY_ENV_KEYS` entry `redamon.sh` reads | `tests/test_env_example_keys.py` |
| `docker-compose.dev.yml` runs the startup steps `webapp/Dockerfile` runs, in order | `tests/webapp_dev_startup_parity_test.sh` |
| every default inside its registry bound | `recon/tests/test_defaults_within_registry_bounds.py`, `agentic/tests/test_defaults_within_registry_bounds.py` |
| form inputs <-> MCP-writable fields | `webapp/src/lib/reconSettings/parity.test.ts` |
| preset schema keys are real, settable columns, documented in the catalog | `webapp/src/lib/recon-preset-schema.test.ts` |
| RoE forbidden-tool vocabulary <-> `TOOL_PHASE_MAP`; category keys <-> `CATEGORY_TOOL_MAP` keys | `agentic/tests/test_forbidden_tool_vocabulary.py` |
| one RoE + recon-budget gate (`roe_gate.check_tool_call`) asked by the single-tool node, the plan wave and every fireteam member; every `CATEGORY_TOOL_MAP` and discovery-list name is a `TOOL_REGISTRY` key | `agentic/tests/test_roe_gate.py` |
| the fireteam mutex validator rejects any two members sharing a `TOOL_MUTEX_GROUPS` tool; every group tool is a registry key | `agentic/tests/test_fireteam_mutex_groups.py` |
| the unclassified routing table names every `KNOWN_ATTACK_PATHS` id once | `agentic/tests/test_unclassified_routing_table.py` |
| `BUILTIN_RESERVED_TOOL_NAMES` (TS) == `mcp_registry._builtin_tool_names()` (registry keys, `tradecraft_lookup` and `SYSTEM_MCP_TOOL_NAMES`), both ways | `agentic/tests/test_reserved_tool_names_parity.py` |
| server tools -> `SYSTEM_MCP_TOOL_NAMES` (one direction: a stale allowlist name passes) | `agentic/tests/test_system_mcp_tool_coverage.py` |
| fs_ tools <-> registry both ways; job_ tools one way plus a count lock of 29 | `agentic/tests/test_tool_registry_completeness.py` |
| every timeout in `mcp/servers/*_server.py` has a larger `TOOL_DEADLINES_S` entry | `agentic/tests/test_tool_deadline.py` |
| skill-part ids == `KNOWN_ATTACK_PATHS`; `skill_parts.py` <-> drawer `phaseConfig` | `agentic/tests/test_skill_parts_registry.py`, `webapp/src/lib/plugins/skillDisplayName.test.ts` |
| `ExploitTree.to_view()` <-> its `websocket-types.ts` shape, both ways | `agentic/tests/test_lats_view_contract.py` |
| WebSocket `MessageType` values equal on both sides; each handled or ignored with a reason | `webapp/src/lib/websocket-types.parity.test.ts` |
| phase lists: the TS GVM, GitHub-hunt and TruffleHog lists <-> `*_PHASE_PATTERNS`; each `*State.total_phases` and the webapp's `RECON_TOTAL_PHASES` == the last phase number | `webapp/src/lib/recon-types.phases.test.ts`, `recon_orchestrator/tests/test_phase_totals.py` |
| triage proof Cypher <-> `score_model.is_proven`; GuardDog field names agent -> webapp -> orchestrator; Jev items | `tests/test_fix_triage_proof_mirror.py`, `tests/test_guarddog_contract.py`, `agentic/tests/test_jev_item_contract.py` |
| MCP onboarding pack covers every advertised tool | `webapp/src/lib/mcp/onboarding.test.ts` |
| agent-facing strings name only live MCP tools | `webapp/src/lib/mcp/toolNameDrift.test.ts` |
| scope `learnMore` links resolve to wiki anchors | `webapp/src/lib/mcp/scopeCopy.test.ts` (wiki checkout only) |
| unseen-badge labels <-> labels the schema indexes; ViewTabs coverage | `webapp/src/app/graph/unseen/registry.test.ts` (skips without `graph_db/`) |
| every relationship Python or webapp Cypher reads (every member of `A\|B`) is written somewhere; a named allowlist for legacy aliases | `recon/tests/test_graph_writes_documented.py` |
| no unconditional legacy drop names a live constraint or index; index names unique | `tests/test_schema_legacy_drops.py` |
| global reference labels: `schema.py` reads `GLOBAL_REFERENCE_LABELS`; the TS copies (`injectProjectFilter.ts`, `graphRestore.ts`, `mcp/graphGuard.ts`) equal it, and no exempt label has a per-project key | `tests/test_reference_labels_mirrors.py` |
| the finding-label set: 11 copies (`agentic/api.py`, `chain_graph_writer.py`, `fact_queries.py`, the triage mixin, `actions.ts`, `findingLabels.ts`, `reportData.ts`, ...) equal `MUTEABLE_LABELS`; the Multi mute pool is it minus `ExploitGvm` | `tests/test_finding_labels_mirrors.py` |
| `graph_db/schema_sections.md` <-> `graph_db/schema_catalog.py` | `recon/tests/test_schema_catalog.py` (`seed_schema_catalog.py --check`) |
| Red Zone network-initial-access ports and finding types <-> `security_checks.py` | `recon/tests/test_net_init_access_parity.py` |
| deleted bundled data stays deleted; `cpe_resolver` reads the cache `http_probe` refreshes | `recon/tests/test_dead_bundled_data.py` |
| nothing in `agentic/` shadows a file the agent image bakes earlier | `tests/test_agent_image_no_shadowed_copy.py` |
| broker allowlist <-> every image recon runs, both ways (a broker image recon does not run needs a named caller); the entrypoint `IMAGES` == the `*_DOCKER_IMAGE` defaults | `services/docker_broker/test_image_parity.py` |
| a stop removes its own run's tool containers, of any image, by the broker's run labels (no image list to keep); `remove_redamon_images` removes every third-party image (it reads the entrypoint `IMAGES`) | `recon_orchestrator/tests/test_run_label_cleanup.py`, `services/docker_broker/test_run_labels.py`, `tests/redamon_runtime_images_test.sh` |
| what `update` rebuilds: every COPY/ADD source of every image compose builds must rebuild it (or restart it under a compose bind mount), derived from the compose file and the Dockerfiles | `tests/redamon_update_map_test.sh` |
| OSV ecosystems in 4 places (`SEED_MANIFESTS`, `_OSV_SYNC_ECOSYSTEMS`, `OSV_ALL_ECOSYSTEMS`, compose `OSV_DB_ECOSYSTEMS`) | `tests/test_supply_chain_osv_refresh.py` |
| TruffleHog sources/registry Python <-> TS | `tests/test_trufflehog_registry_parity.py` |
| plugin platform version, 5 pinned copies (`platformVersion.ts`, `platform_version.py`, the SDK `__init__.py`, `sdk/contract_cases.json`, `tests/runner_contract_cases.json`) | `webapp/src/lib/plugins/platformVersion.parity.test.ts` |
| resource profile JSON <-> both governors | `tests/test_resource_governor.py` |
| API-usage probes cover every saved credential | `webapp/src/lib/apiUsage/registry.drift.test.ts` |
| GVM data containers count | `tests/redamon_gvm_compose_test.sh:216-217` |
| fireteam timeout UI fallbacks == `FIRETEAM_TIMEOUT_SEC` | `webapp/src/components/projects/ProjectForm/sections/AgentBehaviourSection.test.tsx` |
| the preset-generation no-temperature rules (TS) == `llm_setup.py`'s | `webapp/src/lib/llmTemperature.test.ts` |
| the triage score and tiers, Python and TS, answer one vector file; a score-only fallback at a tier boundary is an accepted, listed difference | `webapp/src/app/graph/components/Triage/triageScore.vectors.json` (`triageLayers.parity.test.ts`, `agentic/tests/test_triage_score_vectors.py`) |
| every preset decides each default-on active toggle, and passive or stealth presets run none (allowlist with reasons) | `webapp/src/lib/recon-presets/traffic-decisions.test.ts` |
| every webapp route Python calls with the internal or scanner key matches the middleware allowlists, computed from the callers | `webapp/src/middleware.internalCallers.test.ts` |
| one version per pinned tool (TruffleHog, osv-scanner, guarddog, retire.js) across Dockerfiles, prose, the licence file and fixtures | `tests/test_tool_version_pins.py` |
| wiki links, anchors, images and doc counts; an empty `(#)` link fails | `tests/test_docs_not_stale.py` (P21; `tests/fixtures/docs_drift_*.json` are empty after wave 3) |
| the `README.md` version badge names the release in `VERSION` | `tests/test_readme_version_badge.py` |
| no `SKILL.md` or `AGENTS.md` links a `file#L<n>` line number | `tests/test_ruleset_line_anchors.py` |
| every memory-governor knob compose hands the orchestrator reaches both recon spawn sites, and every knob the governor reads is forwarded | `recon_orchestrator/tests/test_governor_env_forwarding.py` |
| every graph label is produced by a tool (from `SECTION_NODE_MAP`) or named with its writer in `WRITTEN_OUTSIDE_A_SECTION` | `tests/test_registry_tool_wiring.py` |
| `testing/guinea_pigs/README.md` lists every tracked lab, and only those | `tests/test_guinea_pigs_index.py` |
| `redamon.wiki` is a declared submodule; an empty checkout fails the wiki tests unless allowed | `tests/test_wiki_submodule.py`, `tooling/scripts/wiki_checkout.py`, `webapp/src/lib/wikiCheckout.testUtils.ts` |
| the pre-commit hook blocks a commit that leaves a generated artifact stale | `tests/pre_commit_hook_test.sh` |
| every registered recon preset records a vhost-SNI decision | `webapp/src/lib/recon-presets/vhost-sni.test.ts` |
| `drift-audit.sh` reports a dead relative link | `tests/drift_audit_test.sh` |
| `_GENERATED` names files that exist | `tests/test_docs_not_stale.py` |
| shared vectors read by both languages | `recon/tests/fixtures/roe_exclusion_vectors.json` (recon, agent and webapp RoE matchers), `webapp/src/lib/llmTemperature.vectors.json`, `webapp/src/app/graph/components/Triage/triageScore.vectors.json`, `recon_orchestrator/tests/fixtures/hard_guardrail_vectors.json`, `tests/fixtures/scope_groups_contract.json`, `tests/fixtures/legacy_domain_vectors.json`, `webapp/src/lib/engagement.derivation.fixtures.json`, `recon/tests/fixtures/public_suffix_vectors.json`, `agentic/tests/fixtures/redaction_vectors.json`, `agentic/tests/fixtures/skill_metadata_contract.json`, `webapp/src/lib/mcp/contracts/triage_mute.json`, `webapp/src/app/graph/components/MuteNode/multiMuteSuggest.contract.json`, `webapp/src/lib/nodeFilters/contracts/*.json`, `services/plugin_runner/sdk/contract_cases.json`, `services/plugin_runner/tests/runner_contract_cases.json` |

### 3.3 Blind spots shared by all of them

- **No CI.** A guard that nobody runs guards nothing. The pre-commit hook runs
  the three generator checks, but only where `tooling/hooks/install-hooks.sh`
  has installed the current copy.
- **The wiki is a separate checkout.** `.gitmodules` declares it, and an empty
  `redamon.wiki` fails every wiki-dependent test unless
  `REDAMON_TEST_ALLOW_MISSING` names `wiki`; with that opt-out they skip.
- **Cross-tree tests skip when the other tree is absent.** 31 webapp test files
  use `skipIf(!existsSync(...))` or similar; they run in the host checkout but
  not inside the webapp image.
- **Expectations copied into the test.** The dangerous-tools test (19 names
  pinned) and the hand-written label lists in `tests/test_mcp_cypher_scoping.py`,
  `tests/test_triage_mixin.py`, `agentic/tests/test_triage_security_hardening.py`,
  `recon/tests/test_schema_constraints_generated.py` and
  `recon/tests/test_schema_catalog.py` compare the code with a hand copy, so they
  catch an edit but not an omission.
- **Mirrored cases are not mirrored constants.** Several TS tests copy the
  Python test cases (e.g. `injectProjectFilter.test.ts` mirrors
  `tests/test_tenant_filter_muted.py`) instead of reading the Python constant, so
  both suites stay green while the two constants differ.
- **The path audit reads prose, not fences.** `drift-audit.sh --docs` does not
  see paths inside code fences (the file trees in the subsystem docs), bare file names
  (`HydraSection.tsx`) or shorthand (`sections/index.ts`).
- **Structure, not truth.** As `README.SETTINGS_REGISTRY.md` says: no test knows
  whether a `meaning`, a bound or a prose sentence is *true*.

---

## 4. Catalogue by area

### 4.1 Agent tools: the tool registry and its satellites

**Source of truth:** `TOOL_REGISTRY` in `agentic/prompts/tool_registry.py`
(58 entries; dict order is prompt priority) plus `tradecraft_lookup` (per-session
overlay) plus tools injected from MCP manifests at runtime.

| Dependent | Where | Guard | Fails how |
|---|---|---|---|
| Default phase map (28 tools) | `TOOL_PHASE_MAP` `agentic/project_settings.py:288` | PART (phase-gating tests) | A tool missing from the map is **denied in every phase** (`is_tool_allowed_in_phase` returns False for an unmapped tool) |
| Same map as a Prisma JSON default | `agentToolPhaseMap @default(...)` `webapp/prisma/schema.prisma:1136` | NONE | Matches Python (28 = 28, identical phases). **Frozen copy:** see below |
| UI tool matrix | inline array `ToolMatrixSection.tsx:221` | NONE | Matches today. The `⚠` label is a hand marker on two tools, unrelated to `DANGEROUS_TOOLS` |
| Which tool needs which API key (6 tools), 5 copies | `TOOL_KEY_INFO` + `fetchKeyStatus` (`ToolMatrixSection.tsx:38,136-141`), `API_KEY_INFO` + `fetchApiKeyStatus` (`AIAssistantDrawer/hooks/useApiKeyModal.ts:3-30`), `TOOL_KEY_LABEL` (`ToolExecutionCard.tsx:18-25`), hint text in `app/settings/page.tsx:1268-1316` | NONE | Agree today |
| RoE forbidden-tool vocabulary | closed vocabulary `roeForbiddenTools` in `recon_settings/registry.yaml` | TEST (`test_forbidden_tool_vocabulary.py`) | A tool not in it is the one an engagement cannot forbid |
| RoE enforcement | `roe_gate.check_tool_call` (`agentic/orchestrator_helpers/roe_gate.py`), asked by the single-tool node, the plan wave and every fireteam member | TEST (`agentic/tests/test_roe_gate.py`) | A new executor path must ask it; the test fails a module that calls `tool_executor.execute` without it |
| RoE category -> tools | `CATEGORY_TOOL_MAP` (`roe_gate.py`) | TEST (keys: `test_forbidden_tool_vocabulary.py`; members are registry keys: `test_roe_gate.py`) | A new tool in a forbidden class must be added to its category |
| Recon-budget discovery tools | `RECON_DISCOVERY_TOOLS` (`roe_gate.py`), a hand list: no registry field marks a discovery tool | PART (`test_roe_gate.py`: every name is a registry key) | A new discovery tool left out is not budgeted |
| Dangerous tools (confirmation gate) | `DANGEROUS_TOOLS` `agentic/project_settings.py:42` | PART (`test_tool_confirmation.py:181-194` pins the 19 by equality) | A new traffic-emitting tool left out runs **without confirmation** |
| Fireteam mutex groups | `TOOL_MUTEX_GROUPS` (`agentic/project_settings.py:61`), read by `_validate_mutex_groups` (`fireteam_deploy_node.py`) | TEST (`agentic/tests/test_fireteam_mutex_groups.py`) | `state.py:568` is the LLM-filled `tools` field the check reads, not a stored list |
| Reserved names for user MCP tools (TS) | `BUILTIN_RESERVED_TOOL_NAMES` `webapp/src/lib/mcp/schema.ts:18` | TEST (`agentic/tests/test_reserved_tool_names_parity.py`, both ways) | A new system MCP tool must be added to the TS list too; the parity test fails until it is |
| System server ids and ports, 5 copies | `SYSTEM_SERVER_IDS` (`agentic/mcp_registry.py:33`, `webapp/src/lib/mcp/schema.ts`), `_build_system_mcp_servers` (`agentic/tools.py:266`), `SERVERS` (`mcp/servers/run_servers.py:56`), the smoke-test module list (`mcp/kali-sandbox/Dockerfile:542`) | NONE | Agree today (5) |
| Names the Kali MCP servers expose | `SYSTEM_MCP_TOOL_NAMES` `agentic/tools.py:341` | PART (one direction) | Its comment records the failure: `execute_osv_scanner` was missing, so every call returned "Tool not found". Matches the 23 server tools today |
| CLIs the agent is told exist in Kali | the `kali_shell` description, skill prompts, `mcp/servers/proxy_brain_manual.md` | NONE (the Kali build smoke-tests only MCP imports and HTTP/2); every name was checked against the built image on 2026-10-25 | The agent runs a command that is not installed; a Kali rolling update can drop a package |
| Capture-routed HTTP tools | `_CAPTURE_ROUTED_TOOLS` `agentic/tools.py:123` | PART (per-tool integration tests) | Equals the 8 server tools that take `_redamon_ctx` today; a new HTTP tool left out bypasses the capture proxy |
| Per-tool deadlines | `TOOL_DEADLINES_S` `agentic/tools.py:2096` | PART (`test_tool_deadline.py:89` parses the servers' timeouts) | An unknown tool gets `TOOL_DEADLINE_DEFAULT_S = 1860` s, so a lost answer waits 31 minutes |
| Output offload policy | `OFFLOAD_POLICY` `agentic/tool_offload_policy.py:15` | NONE | An unlisted tool gets `"auto"`, which still offloads anything over 20,000 chars: low risk |
| Per-tool stealth rules | `agentic/prompts/stealth_rules.py:31-183` | PART (some per-tool tests) | No section for `shodan`, `google_dork`, `msf_restart`, and no fallback rule |
| Replay and browser phase gates | `/traffic/replay` (`agentic/api.py:4829`) and `/browser` (`:4935`) hard-code exploitation phases, a frozen copy of the retired `proxy_replay`/`proxy_fuzz` entries | NONE | The stored `TOOL_PHASE_MAP` for `proxy_brain` (all three phases) is never consulted. The inbound MCP Kali surface (`/kali/exec`, `kaliTools.ts`) skips phase checks by design |
| Prompts naming tools | `agentic/prompts/*.py`, `agentic/skills/**/*.md`, `agentic/community-skills/*.md`, `proxy_brain_manual.md` | NONE (`toolNameDrift.test.ts` covers only the inbound MCP surface) | The agent is told to call a renamed tool |
| Drawer example prompts | `AIAssistantDrawer/suggestionData.ts` | PART (5 skill tests assert their group id) | Suggestions name a removed tool |

**Frozen copy, the big one.** `fetch_agent_settings` *replaces* the stored
`agentToolPhaseMap` rather than merging it with the default (its
`TOOL_PHASE_MAP` entry in `AGENT_SETTING_COLUMNS`, `agentic/project_settings.py`). A new tool therefore stays **disabled on
every existing project** until its JSON is backfilled (past backfills:
`webapp/prisma/migrations/20260219120000_expand_tool_phase_gating/`,
`20260221140000_execute_code_informational/`). `GRAPH_COMPANION_TOOLS` exists
precisely to avoid adding keys (comment at `agentic/project_settings.py:25`).

### 4.2 Built-in attack skills and community skills

**Source of truth:** `KNOWN_ATTACK_PATHS` in `agentic/state.py` (14 skills).
The ten layers are listed in `skills/builtin-agent-skill/SKILL.md`. Every layer
names all 14, and the Prisma default's values equal Python's
(`agentic/tests/test_prisma_default_parity.py`).

| Layer | Where | Guard |
|---|---|---|
| Classifier | `_BUILTIN_SKILL_MAP` (`classification.py:137`) and `_CLASSIFICATION_INSTRUCTIONS` (`:155`), 14 each | PART (see below) |
| Settings default | `ATTACK_SKILL_CONFIG.builtIn` `agentic/project_settings.py:403` | PART |
| Prisma default (**frozen copy**) | `attackSkillConfig @default(...)` `schema.prisma:1310` | TEST for the values (`test_prisma_default_parity.py`); existing rows need a backfill, same as 4.1 (`get_enabled_builtin_skills` reads only stored keys) |
| Form default | `DEFAULT_CONFIG` `AttackSkillsSection.tsx:157-175` | NONE |
| UI toggle + badge | `AttackSkillsSection.tsx`, `AIAssistantDrawer/phaseConfig.ts` | PART |
| Drawer tooltip | `BUILT_IN_SKILLS` in `webapp/src/app/api/users/[id]/attack-skills/available/route.ts` | PART |
| Example prompts | `AIAssistantDrawer/suggestionData.ts` (7 skills have their own group id) | PART |
| Unclassified routing table | `agentic/prompts/unclassified_prompts.py:25-34` | TEST (`agentic/tests/test_unclassified_routing_table.py`); the classifier text in `classification.py` is prose |
| Plugin-overridable parts | `agentic/prompts/skill_parts.py` `_SPECS`; the webapp fetches them at runtime from `GET /plugins/skill-parts` (`skillPartsRegistry.ts`, not a copy) | TEST (`test_skill_parts_registry.py:131-132`, `skillDisplayName.test.ts`) |
| Golden prompt hashes | `agentic/tests/fixtures/skill_workflow_golden.json` | GEN-like: fails until re-recorded with `record_skill_golden.py` |
| Wiki | `redamon.wiki/Agent-Skills.md` and per-skill pages | links and anchors: TEST (`tests/test_docs_not_stale.py` P21) |

"Per-skill tests" vary: crypto_attack, deserialization, http_request_smuggling,
path_traversal and xxe read every webapp layer; rce reads some; sqli, ssrf and
xss are Python-only; cve_exploit, brute_force, phishing, dos and access_control
have no per-skill test file.

User skills: the enabled-skill limit is 20 in both `MAX_ENABLED_USER_SKILLS`
(`agentic/project_settings.py:1134`) and `MAX_ENABLED_USER_SKILLS_PER_PROJECT`
(`webapp/src/lib/userSkills.ts:14`); each side pins its own, nothing compares
them. Community skills: 18 files in `agentic/community-skills/`, indexed by hand
in its `README.md` (complete). Knowledge skills: 46 files under
`agentic/skills/`, found by directory scan, no index. Both are **prose naming
tools and wordlist paths**.

### 4.3 LLM providers and model ids

| Fact | Copies | Guard | Fails how |
|---|---|---|---|
| Default model id `claude-opus-4-6` | 20 hand-edited occurrences in 16 files (`webapp/prisma/schema.prisma`, `agentic/project_settings.py`, `agentic/api.py`, `llm_setup.py`, `recon/project_settings.py`, `recon/helpers/security_checks.py`, `recon/main_recon_modules/{resource_enum,subdomain_takeover,vuln_scan}.py`, `recon/partial_recon_modules/{vulnerability_scanning,web_crawling}.py`, `webapp/src/app/api/projects/route.ts`, `ModelPicker.tsx`, `ModelPickerModal.tsx`, `recon-preset-schema.ts`, `registry.yaml`); 28 in 20 counting the generated JSON, a migration and a test helper | NONE | A retired id breaks fresh installs; stored rows keep the old id |
| Model ids pinned for the key test | `gpt-4o-mini`, `claude-opus-4-6`, `openrouter/openai/gpt-4o-mini` (`agentic/api.py:2256-2263`) | NONE | The "test this key" button fails when one is retired |
| Models that reject `temperature` | `ANTHROPIC_NO_TEMPERATURE_MODELS` / `_PREFIXES`, `OPENAI_NO_TEMPERATURE_PREFIXES`, `OPENAI_TEMPERATURE_EXCEPTIONS` (`llm_setup.py:21-59`); a TS copy for preset generation (`webapp/src/lib/llmTemperature.ts`) | TEST (`llmTemperature.test.ts` reads the Python constants; shared vectors); runtime self-heal in `llm_retry.py` and one retry in the preset route | |
| Fallback model catalogues | `_XAI_`, `_MISTRAL_`, `_DEEPSEEK_FALLBACK_MODELS` (`model_providers.py:160-274`) | NONE | The picker offers retired models during a provider outage |
| Provider API hosts, 5 copies | `llm_setup.py`, `model_providers.py`, `defaultBaseUrlFor` (`presets/generate/route.ts:85`), `webapp/src/lib/apiUsage/providers/llm/*.ts`, `llmProviderPresets.ts` (20 URLs) | NONE | Agree today |
| Model-prefix routing, 3 copies | `parse_model_provider` (`llm_setup.py`), `resolveModel` (`presets/generate/route.ts:54-79`, lacks the legacy `openai_compat/` prefix, unverified effect), `formatModelDisplay` (`phaseConfig.ts:14`, display only) | PART | A model chat accepts is misrouted by preset generation |
| Provider-type facts | `NON_CHAT_PROVIDER_TYPES` (`agentic/llm_builder.py:38`, `webapp/src/lib/llmProviderKinds.ts`); `CUSTOM_PROVIDER_TYPES` (`llm_builder.py:41`) names `bedrock_custom`, `ollama_local`, which no webapp code creates | NONE | A new non-chat provider counted as a chat LLM on one side |
| Feature-model ids | `FEATURE_IDS` (`agentic/feature_models.py:16`) <-> `webapp/src/lib/llmFeatures.ts`, 9 each | TEST (`test_feature_models.py`) | |
| Local judge model | `qwen2.5:7b` in `local_llm_manager.py:52`, `scanners/ai_attack_surface_scan/{project_settings,adapters/*}.py`, `docker-compose.yml:687`; the UI reads it from the orchestrator (`/local-llm/status` via `/api/ai-attack-surface/[projectId]/judge-model`) | NONE for the scanner copies | |

### 4.4 Recon settings registry and the default cascade

The registry is the best-guarded area (section 3.1). What it does *not*
close:

**The default cascade.** One setting's default lives in up to six places:

1. `@default()` in `webapp/prisma/schema.prisma`: what a row gets when the
   creating path does not set the column (MCP `create_project`, import, the form
   when `/defaults` is down)
2. `DEFAULT_SETTINGS` in `recon/project_settings.py`
3. `DEFAULT_AGENT_SETTINGS` in `agentic/project_settings.py` (plus the scanner
   copies: `scanners/{gvm_scan,github_secret_hunt,supply_chain_scan}/project_settings.py`,
   `agentic/cypherfix_triage/project_settings.py`)
4. `/api/projects/defaults` = recon `/defaults` + agent `/defaults`
   (`RUNTIME_ONLY_KEYS` from the registry, `recon_orchestrator/api.py:1044`;
   the agent half serves `AGENT_SETTING_COLUMNS`, real columns only; the GVM
   and GitHub merges add non-column keys the POST strips): what the **form
   starts from** and what a **preset apply resets to**
5. `MINIMAL_DEFAULTS` (`ProjectForm/formDefaults.ts`) and per-section fallbacks:
   7 differ from both defaults today (`hakrawlerParallelism` 4/5,
   `jsluiceParallelism` 3/5, `katanaParallelism` 5/8, `katanaConcurrency` 10/15,
   `kiterunnerParallelism` 2/3, `nmapParallelism` 2/5, `paramspiderWorkers` 5/8,
   `dnsMaxWorkers` 50/80)
6. every **existing row** (needs a SQL backfill)

The agent's setting names are mapped once, in `AGENT_SETTING_COLUMNS`
(`agentic/project_settings.py`), which both `fetch_agent_settings` and the agent
`/defaults` read; agent fields still have no registry `runtime_key`, and
`agentic/tests/test_agent_setting_columns.py` fails on an agent column nothing
loads.

| Guard | Covers |
|---|---|
| `test_registry_runtime_keys.py`, `test_settings_mapping_coverage.py` | key sets, not values |
| `test_defaults_within_registry_bounds.py` (x2) | value is inside its bound, not equal to Prisma |
| per-tool tests | `test_gvm_scan_hardening.py:620`, `test_puredns.py` and `test_arjun.py` compare with the Prisma default (TEST) |
| `test_prisma_default_parity.py` (recon and agent) | Prisma value == Python value for every field, with a named allowlist |

The `project-settings-cascade` skill is the procedure; nothing enforces it.

**Other registry-adjacent items**

| Item | Where | Guard |
|---|---|---|
| `meaning`, `bounds`, `unit` content | `recon_settings/registry.yaml` | human review only; the hand-written server validators' bounds are checked (`registryBounds.test.ts`) |
| RoE parse prompt (generated) | `recon_settings/roe_parse_prompt.py`; the agent bakes its own copy and the webapp compares (`webapp/src/app/api/roe/parse/route.ts:170`) | GEN (`build.py --check` in the gate) + runtime compare |
| `ROE_PARSE_MAX_CHARS` | `agentic/api.py:355` <-> `MAX_MODEL_CHARS` `webapp/src/lib/roe/limits.ts:28` | TEST (`test_roe_parse_timeout.py:96`) |
| Golden master baselines | `recon/tests/fixtures/golden_settings/*.json` (18) | regenerate only on purpose; every diff line is a value a scan runs with |
| Hand-written settings narrative | `redamon.wiki/Project-Settings-Reference.md` | count only (`settingsReference.test.ts`) |
| Scope-group fact | `GRAPH_DOMAIN_IS_ORG` in `webapp/src/lib/scopeGroups.ts` <-> `recon/partial_recon.py:243` | PART (`scopeGroups.test.ts:129` asserts only the TS value) |

### 4.5 Recon presets, and every other kind of preset

**Built-in recon presets: 26** files in `webapp/src/lib/recon-presets/presets/`,
listed by hand in `webapp/src/lib/recon-presets/index.ts` (import + array).

| Dependency | Guard | Fails how |
|---|---|---|
| Parameter **names** (`Partial<ProjectFormData>`) | `tsc` (type-check) | A renamed column fails the build: good |
| Parameter **semantics** when a tool is added | TEST (`traffic-decisions.test.ts`: every default-on active toggle is decided per preset, 780 pairs still pending a decision; `vhost-sni.test.ts` derives its list; `tlsxPresetGuard.test.ts`) | Applying a preset resets every field it does not name to its default (`applyPresetSettings`, `defaultFor`), so a tool whose default is ON runs under every preset that does not mention it |
| The count | `recon-presets.test.ts` "registry contains exactly 26 presets" | intentional tripwire |
| Icons `webapp/public/preset-*.svg` | PART (`recon-presets.test.ts:3535` checks the path pattern, not that the file exists; all 26 exist) | |
| `fullDescription` / `shortDescription` prose | "required section headers" + "no em dashes" only | Description and parameters disagree; counts such as "all 10 OSINT providers" (`osint-investigator.ts:8`, correct today) age |
| Docs | `redamon.wiki/Recon-Presets.md` (reference table lists all 26), counts across the wiki | counts: TEST (`tests/test_docs_not_stale.py` P21) |

**Measured: tools most presets never decide.** 68 `traffic: active` `*Enabled`
fields exist. "Unnamed" is how many of the 26 presets never name the field; on
apply they get the default.

| Field | Default | Unnamed |
|---|---|---|
| 10 `aiSurfaceRecon*` probe toggles, `jsReconAiSdkDetectionEnabled`, `masscanAiPortCatalogEnabled`, `nmapAiVersionRegexEnabled` | true | 25 |
| `takeoverCertValidationEnabled` | true (inert while takeover is off) | 26 |
| `baddnsEnabled` | false | 25 |
| `tlsxEnabled` | true | 21, including **Stealth Recon**, which runs the HTTP-probe phase: applying it turns tlsx on, and the stealth profile only lowers `tlsxConcurrency` to 5 and turns off cipher, version and JARM probing |
| `nucleiTakeoversEnabled`, `subjackEnabled` | true (inert while takeover is off) | 20 |
| `originDiscoveryEnabled`, `webCachePoisonEnabled` | false | 20 |
| `subdomainTakeoverEnabled` | false | 18 |
| `openapiEnabled` | true | 15 (every preset that turns it off names it) |
| `aiSurfaceReconEnabled` | **true** | 6: bug-bounty-deep, full-active-scan, full-maximum-scan, graphql-recon, secret-hunter, secret-miner |
| `purednsEnabled` / `dnsEnabled` | true | 4 / 3 |
| `bannerGrabEnabled`, `httpxEnabled`, `wappalyzerEnabled` | true | 2 (secret-miner, supply-chain-audit) |
| `graphqlCopEnabled`, `vhostSniEnabled` | false | 2 each (vhost: recorded as intended by `vhost-sni.test.ts`) |
| `securityCheckEnabled` (true), `zapAjaxSpiderEnabled` (false) | | 1 (ai-surface-recon) |
| arjun, ffuf, graphqlSecurity, hakrawler, jsRecon, jsluice, katana, kiterunner, masscan, naabu, nmap, nuclei | | 0 |
| 24 agent and attack toggles (`hydraEnabled`, `fireteamEnabled`, `agentGuardrailEnabled`, the ssrf, rce, path-traversal and deserialization families, `captureProxyEnabled`, tunnel, Kali install, LATS) | 16 default true | 26: every recon preset apply resets them |

Passive: `supplyChainReconEnabled` 18 unnamed, `serializedScanEnabled` 20,
`trufflehogEnabled` 26, all default false. Flipping any default to `true`
silently changes what up to 26 presets do.

**AI-generated presets.** `webapp/src/lib/recon-preset-schema.ts` holds a
hand-written zod schema of the 489 fields a generated preset may carry (unknown
keys are **stripped**) and `RECON_PARAMETER_CATALOG`, the prose the generating
model reads.

- Guarded: every schema key is a real, MCP-settable column with the right shape,
  and schema <-> catalog both directions (`recon-preset-schema.test.ts`).
- Not guarded: a **new** column does not have to be added. The schema covers 489
  of the 653 preset fields; the 164 missing are mostly agent and attack fields,
  `*DockerImage`, 15 trufflehog fields, and the gau/kiterunner method detection.

**Preset apply rules that are hand lists**

| List | Where | Risk |
|---|---|---|
| `PRESET_EXCLUDED_FIELDS` | `webapp/src/lib/project-preset-utils.ts:57` | Derived from registry classes: good. `UNCLASSIFIED_EXCLUDED_FIELDS` (`name`, `description`, `vhostSniCustomWordlist`, `supplyChainInputMode`) is a hand list |
| `KEPT_WHEN_ABSENT` | `project-preset-utils.ts:92` | Complete today (9 of 9 Jev fields + 2 models). It duplicates `JEV_ENGINE_FIELDS` (`webapp/src/lib/reconSettings/jevEngine.ts:8`, a length tripwire only) and `JEV_HOOK_LABEL`; none is compared with the registry. A Jev field missing from the first is switched off by every preset apply; missing from the second, it skips the Jev-token check |

**Other presets**

| Preset kind | Where | Stale-prone because |
|---|---|---|
| MCP server templates (33) | `webapp/src/lib/mcp/presets.ts` | third-party URLs, auth rules and quotas ("verified live as of writing"), per-server tool counts in the blurbs |
| Mute-rule presets | `webapp/src/lib/nodeFilters/presets.ts`, `/api/mute-rule-presets` | name finding kinds from the node-filter catalog |
| Graph-view presets | `webapp/src/app/graph/components/NodeFilters/Preset*.tsx` | stored filter shapes |
| User-saved project presets | `UserProjectPreset.settings` (Postgres JSON) | snapshot of every column at save time; see 4.15 |

### 4.6 Recon pipeline mechanics

| Fact | Copies | Guard | Fails how |
|---|---|---|---|
| Partial-recon tool ids (32) | dispatch `recon/partial_recon.py:389-452`; `SECTION_INPUT_MAP` (`nodeMapping.ts`, + 4 non-partial keys); `TOOL_QUERIES` (graph-inputs `route.ts:188`); `PARTIAL_RECON_SUPPORTED_TOOLS` and `PARTIAL_RECON_PHASE_MAP` (`recon-types.ts:239-274`); `workflowDefinition.ts`; `PartialReconModal.tsx` | PART (per-tool wiring tests) | All 32 agree today |
| Graph-input queries | `TOOL_QUERIES` in the graph-inputs route (the live implementation since the Python one moved here) | TEST (`recon/tests/test_graph_writes_documented.py` reads webapp Cypher) | |
| Phase strings | `GVM_PHASES`, `GITHUB_HUNT_PHASES`, `TRUFFLEHOG_PHASES` (`recon-types.ts`); `*_PHASE_PATTERNS` (`container_manager.py`); `*State.total_phases` (`models.py`) | TEST (`recon-types.phases.test.ts`, `test_phase_totals.py`) | Agree today: recon has 6 (`RECON_TOTAL_PHASES` in `recon-types.ts`) |
| Execution groups and their order | `recon/main.py` (GROUP 1..6) | `recon/tests` per group | Docs (`Recon-Pipeline-Workflow.md`, `Running-Reconnaissance.md`, `README.RECON.md`) describe the old order; a renamed heading breaks wiki anchors until the gate's docs test runs |
| Per-tool explanations in the UI | `WorkflowView/inputLogicTooltips.tsx`, `PartialReconModal.tsx`; `workflowDefinition.ts` traffic badges (5 differ from the registry, 3 of them "both", which the registry cannot express) | NONE | Hand prose on dedup keys, sources, limits |
| Tool image lists, 4 copies | `*_DOCKER_IMAGE` defaults (`recon/project_settings.py`), `IMAGES` (`recon/entrypoint.sh`), `_DEFAULT_ALLOWED_IMAGES` (broker), `remove_redamon_images` (reads `IMAGES`); plus `settings.get(...)` fallbacks in modules. A stop selects tool containers by run label, not by image | TEST (`test_image_parity.py` both ways, `redamon_runtime_images_test.sh`) | Agree today; every broker image beyond recon's names its caller (`BROKER_IMAGES_BEYOND_RECON`) |
| Red Zone "network initial access" | `PORT_CATEGORY`, `NET_VULN_TYPES` (`netInitAccess/route.ts`) vs `security_checks.py` | TEST (`recon/tests/test_net_init_access_parity.py`) | `cache_purge_exposed` is excluded on purpose (a cache-DoS finding, not an access vector) |
| Every Red Zone / Insights query | `webapp/src/app/api/analytics/**/route.ts` | PART (route tests with mocked results; `insightsDeclared.test.ts` covers one predicate) | Hard-coded labels, properties and `type` strings |
| AI hook catalogues | `recon/helpers/ai_signal_catalog.py`, port-scan / JS-SDK / AI-surface catalogues | TEST (`test_ai_*_catalog*.py`) | |
| Jev extension catalogue vs recon `EXT_REGEX` | `recon/helpers/ai_planner/ffuf_extensions.py` | TEST (`test_jev_catalog_contract.py`) | |
| Partial-recon setting overrides | `ALLOWED_SETTINGS_OVERRIDES` `recon/partial_recon.py` <-> `recon_orchestrator/batch_scope.py:54`; `PARTIAL_RECON_OVERRIDE_KEYS` in `recon-types.ts` | TEST (`test_partial_recon_multi_root.py:490`, `test_partial_recon_roots.py:166`) | |
| Partial-run CIDR bounds (`/24-/32`, `/120-/128`); batch ceiling 50 | `PartialReconModal.tsx:269,274` <-> `batch_scope.py:305`; `MAX_REQUESTED_ROOTS` (`batch_scope.py:61`) <-> `MAX_BATCH_GROUPS` (`webapp/src/lib/domainBatch.ts:41`) | NONE | Agree today |
| Registry tool metadata | `tools.*.partial_recon_module` in `registry.yaml`; `produces` derived by `build.py` from `SECTION_NODE_MAP` (`SECTION_ALIASES` maps the five section names that differ) | `partial_recon_module`: TEST (`test_registry_partial_recon_module.py`); `produces`: GEN (`build.py` refuses a hand-written one) | A tool with no partial-recon section has no `produces` |

### 4.7 Graph schema

**Source of truth:** `graph_db/schema_sections.md` (labels, properties,
relationships) and `graph_db/schema_keys.py` (uniqueness keys, 45 labels).
`schema_catalog.py` is generated and `schema.py` renders constraints from
`schema_keys.py`.

| Dependent | Where | Guard | Note |
|---|---|---|---|
| Constraint / index counts in prose | `docs/readmes/GRAPH.SCHEMA.md` (45 constraints, 77 indexes, 41 + 3 drops) | NONE | Correct today |
| Legacy drops vs live names | `DROP_LEGACY_CONSTRAINTS` and `LEGACY_SHAPED_CONSTRAINTS` (`schema.py`) vs `schema_keys.py` | TEST (`tests/test_schema_legacy_drops.py`) | |
| Relationships read by Python code | all `*.py` | TEST (`test_graph_writes_documented.py`, every member of `A\|B`) | |
| Relationships read by **webapp** Cypher | `webapp/src/**/*.ts(x)` | TEST (the same test; the legacy `HAS_BASEURL` alias is allowlisted) | |
| Legacy alias reads | `HAS_BASE_URL\|HAS_BASEURL` in `agentic/cypherfix_triage/fact_queries.py:54,226`, `recon/partial_recon_modules/origin_enrichment.py:53,55`, the graph-inputs route `:315,334,365`, `clusterNodes.ts:44`, and the agent's prompt Cypher `agentic/prompts/base.py:2045` (teaches the old spelling) | intentional until `tooling/scripts/triage_graph_migrate.py` has run everywhere | |
| **The finding-label set (8 labels)** | `MUTEABLE_LABELS` (`graph_db/mixins/recon/triage_mixin.py:47`, the source), `graph_db/node_filters/catalog.py`, `FINDING_LABELS` (`base_mixin.py`), `_FINDING_LABELS` (`agentic/api.py`), `_CONFIRMABLE_LABELS` (`chain_graph_writer.py`), `fact_queries.py`, `FINDING_LABELS` (`webapp/src/lib/triage/actions.ts`), `MUTEABLE_FINDING_LABELS` (`webapp/src/lib/mcp/findingLabels.ts`), `reportData.ts`, and test/tooling copies | TEST (`tests/test_finding_labels_mirrors.py`, 11 copies, plus the three older Python tests) | A new finding label must be added everywhere or it cannot be muted, triaged, confirmed or counted |
| Global reference labels (5 copies) | `GLOBAL_REFERENCE_LABELS` (`graph_db/tenant_filter.py:236`), read by `graph_db/schema.py`; `GLOBAL_LABELS` (`webapp/src/app/api/graph-views/execute/injectProjectFilter.ts`), `graphRestore.ts`, `webapp/src/lib/mcp/graphGuard.ts` | TEST (`tests/test_reference_labels_mirrors.py`) | Exempting a per-tenant label is a cross-tenant read; the test also fails an exempt label with a per-project key |
| Saved-view function namespaces (8) | `tenant_filter.py:108` <-> `injectProjectFilter.ts:189` | PART (mirrored cases) | |
| Node colours / sizes | `NODE_COLORS` (`webapp/src/app/graph/config/colors.ts`), `NODE_SIZES` (`sizes.ts`, 30 keys; 16 keyed labels use `Default`) | NONE | New labels render grey and default-sized |
| Labels behind the unseen badges | `ALL_GRAPH_LABELS` (`webapp/src/app/graph/unseen/registry.ts`) | TEST (skips without `graph_db/`) | |
| Write-time props per label | `UPDATED_AT_PROPS` (`RedZoneTables/updatedAt.tsx:54`) and the `coalesce` in `unseen/counts.ts:55` | PART | |
| Finding-key contracts | `cache_mixin.py:15`, `graphql_mixin.py:15`, `osint_mixin.py:109` (`_split_url` byte-identical), `tlsx_mixin.py:53` (duplicated from `security_checks.py`), `secret_mixin.py:601` (digest = `scanners/trufflehog_scan/findings.py`) | mostly TEST (the secret one by `tests/test_trufflehog_graph_scoped_clear.py`) | |
| Certificate key derivation; orphan-sweep depth 3 | `deriveCertKey` (`webapp/src/lib/graphRestore.ts:31,91`) <-> `build_cert_key` (`graph_db/cert_key.py:17-37`), `base_mixin.py:38` | NONE | A whitespace-only fingerprint keys differently on restore, giving a duplicate Certificate (edge case) |
| Agent's graph prompt | `agentic/prompts/base.py` text-to-cypher rules, `agentic/graph_schema_prompt.py` | the fidelity tests | query guidance prose is hand-written |
| Wiki | `redamon.wiki/Attack-Surface-Graph.md` | node-type counts: TEST (`tests/test_docs_not_stale.py` P21) | |
| Graph export / import / restore | `graphSerialize.ts`, `graphRestore.ts`, `projectExport/`, `api/projects/import/route.ts` | integration tests | a new label must be exported and restored |
| Mixin split snapshot | `tests/fixtures/recon_mixin_snapshot.json` (2026-04-18) | `tests/test_recon_mixin_split.py` | a one-time refactor guard that ages with the mixins |
| One-shot graph migrations | `tooling/scripts/{triage_graph_migrate,dns_finding_rekey,js_secret_rekey,netlas_finding_rekey,mute_provenance_cleanup,node_filters_rollback}.py` | NONE | written against the schema of their day |

### 4.8 Inbound MCP server and API docs

Well guarded: `MCP-API-Reference.md` is rendered from the live `tools/list` (48
tools, 17 scopes), the onboarding pack must cover every tool, every scope sits in
exactly one group, and the server's own agent-facing strings are checked against
the live surface.

| Item | Where | Guard |
|---|---|---|
| Server narrative | `docs/readmes/README.MCP.SERVER.md`, `redamon.wiki/MCP-Server.md` | counts: TEST (P21); prose: NONE |
| Playbook prose | `webapp/src/lib/mcp/playbook.ts`, `onboarding.ts` | PART (tool names only) |
| Scope labels and blurbs | `webapp/src/lib/mcp/scopeCopy.ts` | TEST |
| Canonical banner bytes | `CANONICAL_BANNER` (`apiReference.ts`) == `DevergoLabs/scripts/add-wiki-canonical.mjs` | the byte-compare fails if they differ |
| User MCP manifest schema | `webapp/src/lib/mcp/schema.ts` <-> `agentic/mcp_registry.py:49-105` | NONE (TS is stricter) |
| Kali exec wait cap 60 | `webapp/src/lib/mcp/kaliTools.ts:87` <-> `agentic/api.py:5083` | NONE |
| OpenAPI | `docs/readmes/README.OPENAPI.md`, `route.openapi.test.ts` files | PART |

### 4.9 Plugin platform contract

| Fact | Copies | Guard |
|---|---|---|
| Platform version `1.1.0` | 5 pinned copies (section 3.2) + a literal in `services/plugin_runner/tests/test_sdk_contract.py:39` | TEST |
| JSON schemas | `webapp/src/lib/plugins/schemas/json/*.schema.json` | GEN (`npm run plugins:schemas`) |
| SDK local validator rules | `services/plugin_runner/sdk/redamon_plugin_sdk/testing.py:36-74` copies permissions, `MAX_PENDING_CHANGE_SETS=5`, `USER_SKILL_MAX_CHARS=512000`, group regex, 8 reserved headings, reserved markers, 10 credential shapes and data-store limits from `webapp/src/lib/plugins/{permissions,overrides,redact,dataStore,settings}.ts`, `userSkills.ts:19`, `agentic/prompts/skill_parts.py:231,241` | PART (`contract_cases.json` exercises a few). The Gateway's value limit is env-tunable (`PLUGIN_DATA_MAX_VALUE_BYTES`), the SDK's is fixed |
| Plugin and action id regexes | `webapp/src/lib/plugins/ids.ts:8`, `schemas/common.ts:4`, `services/plugin_runner/supervisor/runlist.py:15,17`, `llmFeatures.ts:29` | NONE on the Python side |
| Signing keys | `webapp/src/lib/plugins/keyring.ts` (key id + public key, optional `notAfter`) | NONE. **Time-based:** the next key must ship before the plugin repo signs with it |
| Default catalog URL | `DEFAULT_CATALOG_URL` `webapp/src/lib/plugins/catalog.ts:28` | NONE |
| Extension points and actions | `extensionPoints.ts`, `contributions.ts`, the SDK, `README.PLUGINS.md`, `README.PLUGIN_SDK.md`, `README.DEV.md` §6.6 | PART |
| The plugins themselves | `redamon-plugins/` (separate repo) | its own signed catalog |

### 4.10 Cross-image mirrors: Python, TypeScript and other images

The agent image does not carry `recon/`, scan containers do not carry `webapp/`,
and the webapp build cannot import across its root. So shared facts are copied.

| Fact | Copies | Guard |
|---|---|---|
| Hard guardrail | `agentic/orchestrator_helpers/hard_guardrail.py`, `recon_orchestrator/hard_guardrail.py`, `webapp/src/lib/hard-guardrail.ts` (+ COPYed into the capture proxy) | TEST (shared vectors) |
| Scope groups | `agentic/scope_groups.py`, `webapp/src/lib/scopeGroups.ts`, `graph_db/mixins/recon/scope.py`, `recon/helpers/auth_profile.py`; `agentic/auth_profile.py` copies the recon auth-profile and RoE-scope helpers | TEST (contract JSON); PART for the agent auth-profile twin (cases repeated by hand) |
| RoE exclusion matching | `recon/helpers/roe_scope.py:17-46`, `agentic/auth_profile.py`, `webapp/src/lib/roeScope.ts` (used by `recordingSession.ts` and `openapiSourceStatus.ts`) | TEST (`recon/tests/fixtures/roe_exclusion_vectors.json`, all three) |
| Engagement derivation | Python + `webapp/src/lib/engagement.ts` | TEST (fixtures JSON) |
| Public Suffix List | `recon/helpers/public_suffix.py` (`publicsuffixlist` pin) <-> `webapp/src/lib/publicSuffix.ts` (`tldts` pin) | TEST (vectors) + manual release step `README.DEV.md` §5.8 |
| Resolved-IP denylist | `recon_orchestrator/ip_denylist.py`, COPYed into the capture proxy | no drift possible (one file) |
| URL guard | `agentic/orchestrator_helpers/llm_url_guard.py` <-> `recon/main_recon_modules/ip_filter.py`; third copy `webapp/src/lib/llm-url-guard.ts:16-23` | TEST for the Python pair; PART for TS (separate suites) |
| **WebSocket protocol** | `MessageType` (`agentic/websocket_api.py`) <-> `webapp/src/lib/websocket-types.ts`; the job string again in `agentic/ws_job_emitter.py:37` | TEST (`websocket-types.parity.test.ts`; `job_update` is ignored on purpose, nothing lists agent jobs); the LATS view is guarded (3.2) |
| Scan status enums | 6 in `recon_orchestrator/models.py` <-> `webapp/src/lib/recon-types.ts`; `AiAttackSurfaceStatus` <-> `AiAttackStatus` (`webapp/src/lib/aiAttackSurface.ts:368`) | NONE. Agree today (TS adds a client-side `pausing`) |
| Orchestrator payload shapes | 27 Pydantic models (`recon_orchestrator/models.py`) <-> hand-written interfaces (`recon-types.ts`, `orchestrator.ts`) | NONE (no codegen) |
| Traffic filter vocabulary | `agentic/traffic_tools.py:68` <-> `buildTrafficWhere` (`webapp/src/app/api/traffic/[projectId]/route.ts:59`) | NONE |
| Capture body families and policies | `webapp/src/lib/captureBodyRules.ts:9-35` <-> `scanners/capture_proxy/capture_lib.py:148,157` | NONE |
| Capture-tag signer | `redamon_ctx.py` in `agentic/`, `recon/helpers/`, `scanners/capture_proxy/` (identical) + TS minter `webapp/src/lib/redamonCtx.ts:15` | TEST for the Python copies (`test_replay_and_sync.py:91`); PART for TS |
| `scaIntelIgnoreSuffixes` default (5 copies) | `scanners/supply_chain_common/intel.py:32`, `webapp/src/lib/scaIntel.ts:40`, `schema.prisma:306`, `webapp/src/app/api/users/[id]/settings/route.ts:219`, `DEFAULT_CAPTURE` (`webapp/src/components/traffic/captureSettingsForm.ts:54`) | PART (`scaIntel.test.ts:125`) |
| Supply-chain input validation | `webapp/src/lib/validation/supplyChainInput.ts` <-> `scanners/supply_chain_scan/repo_clone.py:48` | NONE |
| GuardDog charset and ecosystems (7) | `SAFE` (`webapp/src/app/api/internal/supply-chain/guarddog/route.ts:21`) <-> `container_manager.py:4125`; ecosystems in `agentic/supply_chain_tools.py:39`, `guarddog/route.ts:16`, `container_manager.py:4117`, `supply_chain_common/guarddog_runner.py:30`, prose `tool_registry.py:585` | NONE |
| Analyzer hardening flags | `container_manager.py:4078-4086` (memory precedence `:593`) <-> `supply_chain_common/analyzer_dispatch.py:128`; an unused third copy `guarddog_runner.py:75` | NONE |
| Supply-chain three-layer gate | `agentic/supply_chain_tools.py:43` + webapp + orchestrator | PART |
| TruffleHog sources / registry / digest / result filenames | `scanners/trufflehog_scan/sources.py` <-> `webapp/src/lib/trufflehogSources.ts`; `recon_orchestrator/trufflehog_registry.py`; filenames in `webapp/src/app/api/trufflehog/[projectId]/download/route.ts:15`, `scanners/trufflehog_scan/job_config.py:51`, `container_manager.py:3749` | TEST (filenames: NONE) |
| Resource governor profile | `recon_orchestrator/resource_profile.default.json` <-> both `resource_governor.py` <-> `redamon.sh:503,704` weights; per-kind envelope bytes `SCAN_JOB_ENVELOPE_BYTES` (`webapp/src/lib/jobQueue.ts:37`, lacks `partial_recon:SupplyChainRecon`, `partial_recon:JsRecon` and `codefix`) | TEST (JSON <-> governors); NONE for `redamon.sh` and the TS envelopes |
| Triage score formula | `score_model.py` <-> `Triage/triageLayers.ts` | TEST (`triageScore.vectors.json`, both sides); with no stored tier, the UI names the higher tier at a boundary score (accepted, in `KNOWN_DIFFERENCES`) |
| Triage vocabulary | `TRIAGE_PROPERTIES` (`webapp/src/lib/triage/properties.ts:10`) <-> the mixin; `DECIDED_BY`, `REVIEWED_VIA`, `REVIEW_CURRENT`, `VERDICT_STATUSES` (`actions.ts:49-294`), `RESOLVED_TRIAGE_STATES` (`reportable.ts:27`), `_TRIAGE_FILTERS` (`agentic/api.py:3738`) | TEST for properties (`properties.test.ts` reads the mixin); PART for the vocabularies |
| Proof types / proof bar 70-80; passive CVE sources | `triage_mixin.py:308-319`, `fact_queries.py:125-128`, `score_model.py:1135-1141`; `recon/helpers/finding_sources.py:22`, `score_model.py:616`, `osint_mixin.py:81` | types NONE, bar TEST; sources TEST (skips without `recon/`) |
| Mute selector / severity rank | `agentic/multi_mute/{kind,pool}.py` <-> Cypher in the triage mixin | TEST (contract JSON) |
| Diagnostic failure classes (5) | `productivity.py:250` <-> `error_class.py:203` | NONE |
| Auth headers, project file roots, chat-skill caps, baddns modules, workspace protected dirs | `webapp/src/lib/authProfile.ts` <-> `recon/helpers/auth_profile.py`; `reconSettings/validators.ts:69-79` <-> `recon/project_settings.py:988-998`; `chat-skills/route.ts:32-57` <-> `import-community/route.ts:9-11`; `TakeoverSection.tsx:27` <-> `takeover_helpers.py:378`; `workspace_fs.py:68` <-> `FileSystemDrawer.tsx:72` | PART / NONE (each agrees today) |
| Neo4j-to-JSON coercion | `agentic/api.py:3667` <-> `mcp/servers/redagraph.py:86` | NONE |
| Internal routes Python calls on the webapp | `INTERNAL_ALLOWLIST` (28 patterns) and `SCANNER_ALLOWLIST` (3) in `webapp/src/middleware.ts` <-> 32 distinct method+route pairs called with `X-Internal-Key` (all match today) | TEST (`middleware.internalCallers.test.ts`, computed from the callers). Enforcement is **log-only** unless `INTERNAL_KEY_ALLOWLIST_ENFORCE=true` |

### 4.11 Bundled third-party data and external ids

| Data | Where | Refreshed by | Guard / risk |
|---|---|---|---|
| MITRE CWE / CAPEC / CVE2CAPEC | `recon/main_recon_modules/data/mitre_db/` | `add_mitre.py` at scan time (24h TTL), **writing into the mounted source tree** | The 4 tracked resource files churn in `git status`; whether they belong in git is guard 23 |
| Wappalyzer fingerprints | `recon/main_recon_modules/data/wappalyzer_cache/technologies.json` | `http_probe.py` (24h TTL) from `unpkg.com/wappalyzer@<WAPPALYZER_NPM_VERSION>` (immutable per version) | `cpe_resolver.py` reads this copy (`test_dead_bundled_data.py`); the GVM container has none |
| DNS resolvers | `recon/data/resolvers.txt` (gitignored) | `recon/entrypoint.sh:79` every 7 days | `tests/recon_resolvers_refresh_test.sh` |
| Public Suffix List | inside `tldts` and `publicsuffixlist` | dependency bump | release blocker if older than ~3 months |
| CDN / WAF edge prefixes | `recon/helpers/cdn_edge_prefixes.py` | **manual**; "retrieved 2026-10-25" | `recon/tests/test_cdn_edge_list.py` guards that consumers use the one list, not its freshness |
| IANA service names, popular npm names, VHost wordlist | `recon/data/iana-services.csv`, `recon/data/npm_popular.txt`, `recon/wordlists/vhost-common.txt` | manual | NONE |
| Kali wordlist and tool paths | named in prompts and skills (e.g. `/usr/share/wordlists/rockyou.txt`) | Kali rolling image | NONE |
| Supply-chain incident intel (offline copy) | `scanners/supply_chain_common/sca_intel_seed.json.gz` (2026-09-18), `SEED_SHA256` in `intel_seed.py` | rebuild from a good live sync | the live feed replaces it at runtime; the seed only ages |
| Offline OSV database | Docker volume | `./redamon.sh supply-chain-sync`, install/update, orchestrator TTL | ecosystems guarded across 4 lists |
| TruffleHog detector names (1,060) | `webapp/src/lib/trufflehogDetectors.ts` | **manual**, parsed from the pinned binary | TEST for the version (`tests/test_tool_version_pins.py`); the list itself is regenerated by hand |
| Greenbone object UUIDs | XML report format and port list in `scanners/gvm_scan/gvm_scanner.py:308,345` | Greenbone feed | NONE; `:344` records one port-list mix-up |
| AI red-team tool vocabularies | promptfoo strategy ids (`local_strategies.py:98`), garak and PyRIT probe names | tool upgrades | PART |
| Custom Nuclei templates | `mcp/nuclei-templates/` (8 templates); `recon_orchestrator/nuclei-templates/` is only an empty mountpoint for the same folder | manual | upstream templates may supersede them |
| Knowledge-base feeds | `services/knowledge_base/curation/pins.py`, `kb_config.yaml` | edit the pin, rebuild | a moved pin fails the build loudly; content ages |
| Exploit-DB CSV mirror | `services/knowledge_base/curation/exploitdb_client.py` | KB refresh | URL can move |
| External MCP servers | `webapp/src/lib/mcp/presets.ts` | manual | see 4.5 |

### 4.12 Version pins and container images

| Kind | Examples | Risk |
|---|---|---|
| Floating tags | 13 of the 15 images `recon/entrypoint.sh` pre-pulls are `:latest` (2 of them local builds); in `docker-compose.yml` 22 of 23 `:latest` lines are local `redamon-*` builds and the only third-party one is `ollama/ollama:latest`; Greenbone images on `:stable` (4) or untagged; `kalilinux/kali-rolling:latest`; `golang:1-bookworm` in 4 Dockerfiles; `ghcr.io/zaproxy/zaproxy:stable` | behaviour changes under you; output parsers break with no repo change |
| Exact pins | `TRUFFLEHOG_VERSION=3.96.0`, `BADDNS_VERSION=2.1.0`, `TRIVY_VERSION=v0.73.0`, `PROMPTFOO_VERSION=0.121.17`, garak 0.15.1 / PyRIT 0.14.0 / `giskard[llm]==2.19.1` (`scanners/ai_attack_surface_scan/adapters/*/requirements.txt`), `dolevf/graphql-cop:1.14`, the plugin runner base by digest, `@modelcontextprotocol/sdk 1.30.0`, `tldts 7.0.28`, `pdfjs-dist`, `mammoth`, `recon/requirements.txt`, test toolchain pins (`agentic/requirements.txt:66-73`, `requirements-test.txt`, `recon/requirements.txt:54-55`) | age; data derived from a pin must move with it |
| Pins repeated across images | osv-scanner in 4 Dockerfiles + `supply_chain_common` prose + `THIRD-PARTY-LICENSES.md`; guarddog (kali, analyzer); retire (analyzer, `retire_runner.py`); TruffleHog (Dockerfile, `trufflehogDetectors.ts`, e2e fixtures); the Ollama default image (`docker-compose.yml:686`, `redamon.sh:78`, `local_llm_manager.py:49`) | TEST for all but Ollama (`tests/test_tool_version_pins.py`); NONE for the Ollama image |
| Paths tied to a base image | `scanners/supply_chain_analyzer/Dockerfile:56` hard-codes `python3.11/site-packages` (base at `:23`), hidden by `\|\| true` | breaks silently when the base moves |
| Python base images | 3.11: agent, recon, orchestrator, supply chain, plugin runner; 3.12: the others; kali: whatever `kali-rolling` ships | the root `AGENTS.md` and `TECH_STACK.md` state each image's |
| Licences | `THIRD-PARTY-LICENSES.md` (hand-maintained) | the pinned versions it names: TEST (`test_tool_version_pins.py`); the rest by hand |
| Release version | `VERSION` -> `redamon.sh`; `README.md` badge (hand); `CHANGELOG.md`; `REDAMON_VERSION` (`webapp/Dockerfile:31`); `webapp/src/lib/disclaimerVersion.ts` | TEST for the badge (`tests/test_readme_version_badge.py`) |

### 4.13 Control plane, compose, env and the test runner

| Item | Where | Guard | Note |
|---|---|---|---|
| **What `update` rebuilds** | `cmd_update`, `_map_core_changes`, `_map_tool_changes` and `_map_baked_graph_db` (`redamon.sh`): one hand-written rule per folder | TEST (`tests/redamon_update_map_test.sh`, derived from every built image's COPY sources) | Cross-folder COPYs: recon, gvm, github-hunt -> `graph_db`; recon and the agent -> `recon_settings`; the agent and kb-refresh -> `graph_db`, `services/knowledge_base`; capture-proxy and traffic-ingest -> `recon_orchestrator/{hard_guardrail,ip_denylist}.py` |
| Image and service name lists | `TOOL_IMAGES` (`redamon.sh:24`, 10 = the tools-profile services), compose `image:` tags, the orchestrator `*_IMAGE` env (`docker-compose.yml:505-511`); `CORE_BUILD_SERVICES` (`redamon.sh:29`) typed again at `:3680` | NONE | Agree today |
| Memory specs | `_MEM_SPECS_*` (`redamon.sh:508-542`, 16) vs compose `mem_limit` variables; `_status_expected_mb` (`:4604-4613`) maps only 10 containers; `_GVM_DATA_CONTAINERS=8` | NONE / NONE / TEST (`redamon_gvm_compose_test.sh:216-217`) | `status` never flags the GVM and kb-refresh caps |
| Env vars | `.env.example` vs what compose forwards | TEST (`tests/test_env_example_keys.py`: every key is forwarded or a `HOST_ONLY_ENV_KEYS` entry `redamon.sh` reads) | A knob a spawned container reads must also be forwarded by `container_manager.py` (the governor knobs are, through `_governor_overrides`) |
| Env var reference | `README.DEV.md` §8 | NONE | marked as a selection; `.env.example` is the reference |
| Service table | `README.DEV.md` §2 | NONE | every compose service, as of the fix pass |
| Hot-reload table | `README.DEV.md` §5.3 | NONE | matches the images, mounts and update map as of the fix pass |
| Production compose | `tooling/deploy/single-host/compose/docker-compose.prod.yml`, which re-lists all kali host ports with `!override` (`:61-72`) | `tests/deploy_*_test.sh` (partial) | A port added only to the base compose is unpublished on deploy hosts |
| Capture-proxy module list | `scanners/capture_proxy/Dockerfile:22-28` names its 7 modules; no source mount | NONE | A new module fails with ImportError |
| Orchestrator host-path mounts | compose volumes, `recon_orchestrator/api.py:127-189` (10 lookups), the test runner's `-e *_PATH` list (`redamon.sh:5019-5028`, 9) | NONE | |
| Runtime cache paths | `RUNTIME_TRACKED_PATHS` (`redamon.sh:52`) vs the writers (`add_mitre.py:38`, `http_probe.py:1456`) | NONE | Agree today |
| Webapp startup scripts | the inline entrypoint `webapp/Dockerfile:127` and the dev copy in `docker-compose.dev.yml` | TEST (`tests/webapp_dev_startup_parity_test.sh`) | |
| Prisma migrations | `webapp/prisma/migrations/` (17, last 2026-09-24) | none; the schema is applied with `db push` | historical record only |
| Test sections | `_TEST_SECTIONS` `redamon.sh:4942` | PART (`redamon_gate_unskippable_test.sh` stops a known section skipping silently) | every tracked `test_*.py` falls in some section today |
| Root tests routed to the recon image | `_ROOT_RECON_TESTS` `redamon.sh:4939` (14) | NONE | 6 more reach into `recon/` via `sys.path` and run in the agent image; fine while they need no recon-only dependency |
| Coverage floors | `REDAMON_COV_FLOOR`, `docs/readmes/README.TESTING.md` | manual ratchet | |
| Memory calibration | `recon_orchestrator/resource_profile.json` (gitignored, host-local) | `tests/redamon_mem_calibrate.sh baseline` / `scan` | measured peaks age as services grow |
| End-to-end suites | 21 Playwright specs in `testing/e2e/tests/` | not in the unit gate | selectors break with UI changes |
| `redamon.sh` help text | `cmd_help` `redamon.sh:4879` | NONE | every dispatched command is listed today |
| Issue templates | `.github/ISSUE_TEMPLATE/bug_report.yml` (6 components) | NONE | no scanner, plugin or graph entry |

### 4.14 Docs, wiki and agent rulesets

**Generated (do not hand-edit):** `redamon.wiki/MCP-API-Reference.md`,
`redamon.wiki/Project-Settings-Registry.md`, the "Auto-invoke Skills" tables in
`AGENTS.md` files.

**Agent-facing text: the highest-stakes prose.** A stale line here becomes wrong code.

| Item | Guard |
|---|---|
| `docs/readmes/coding_agent_prompts/*.md` | crude checks in `tests/test_docs_not_stale.py` (retired names, deny reasons, generated files); cited paths: TEST (`tests/docs_cited_paths_test.sh`) |
| `skills/*/SKILL.md` layer tables and file lists | `drift-audit.sh` (a link resolves from the file's folder) and `--docs` in the gate; `#L<n>` anchors: TEST (`tests/test_ruleset_line_anchors.py`) |
| `AGENTS.md` per component (`CLAUDE.md` is a symlink to it in the root and in six component folders), incl. QA checklists | `drift-audit.sh` |
| `AGENTS.md` SKILLS CATALOGUE (by hand) | none; 16 = 16 today |
| `drift-audit.sh` `ROOTS` and `sync.sh` scope map | none; cover every `AGENTS.md` today |

**Human-facing**

| Item | Risk |
|---|---|
| Count claims in README and wiki | four kinds checked against the code (P21); any other count is prose |
| `README.md` (107 KB): features, tool tables, screenshots, wiki links, badge | links, anchors and counts: P21; the badge: TEST (`tests/test_readme_version_badge.py`) |
| Subsystem docs (37 tracked, this page included) | cited paths: TEST; function-by-function sections are prose, unguarded (the recon and KB ones were rewritten from the code on 2026-10-25); `README.DEV.md` §9 indexes all |
| Anchors | TEST (P21, GitHub's slug rules, combining marks kept); a heading rename still breaks every incoming `Page#anchor` until someone runs the gate |
| Wiki file links and images | TEST (P21 for images and repo URLs, `docs_cited_paths_test.sh` for paths); screenshots age with every UI change |
| Doc screenshots generated by Playwright | `testing/e2e/tests/capture{Auth,Jev,McpServer,Tlsx}DocsShots.spec.ts`; every other screenshot is manual |
| Links into `_local/` (untracked) | none left; the path audit treats any `_local/` path as dead |
| `README.GPIGS.md`, `testing/guinea_pigs/README.md` | list all 19 labs; the second is guarded (`tests/test_guinea_pigs_index.py`) |
| redamon.org `/docs` | nightly copy of the wiki's top-level pages; a stale wiki page is a stale public page within a day |
| `CHANGELOG.md` (614 KB) | append-only; not a drift source |

### 4.15 Data stored in Postgres and Neo4j

Rows written once and read for ever. Every one goes stale against the code that
reads it.

| Stored | Model / place | When it goes stale |
|---|---|---|
| Per-project tool phase map and skill toggles | `Project.agentToolPhaseMap`, `Project.attackSkillConfig` | a tool or skill is added (4.1, 4.2); rows created over MCP before the fix pass carry brute force, phishing and DoS ON (6 of 13 projects on the audited stack) |
| Every project column default | `Project` rows | a `@default` changes (needs a backfill) |
| User project presets | `UserProjectPreset.settings` | a column is renamed or reclassified |
| User mute-rule presets | `UserMuteRulesPreset.rules` | a finding kind changes in the node-filter catalog |
| Saved graph views | `GraphView` (stored Cypher/filters) | a label, relationship or naming rule changes; `staleViewNote.ts` warns only for the Domain-is-the-org change |
| Scan schedules | `ScanSchedule` | the scan payload shape changes |
| Scan Timeline snapshots | `ScanVersion.snapshot` (gzipped graph) | restoring after a schema change (`graphRestore.ts`) |
| Exports | project export archives | import must accept every older format |
| Graph data written by an older recon | Neo4j | properties renamed or added (`legacyGraph.ts`, the alias reads in 4.7) |

---

## 5. Patterns: why things drift here

The item numbers below are examples, most of them fixed on 2026-10-25; `git log
--grep 'drift-map #N'` shows how each was fixed.

1. **Image boundaries force copies.** The agent image has no `recon/`, scan
   containers have no `webapp/`, the capture proxy has neither. Any fact two of
   them need is duplicated. The good fix already used here: one JSON vector file
   both sides' tests read.
2. **Defaults are copied into rows.** Prisma `@default` writes the value into
   each new row, and the Python loaders *replace* rather than merge stored JSON.
3. **Two creation paths, two default sources.** The form starts from Python's
   `/defaults`; MCP and import fall back to Prisma. Any field where the two
   differ depends on how the project was born (#3, #12).
4. **Two execution paths, one rule.** A rule written into the plan-wave executor
   and not the single-tool one (or the reverse) holds half the time (#1, #9).
5. **Name mapping by convention.** camelCase <-> SNAKE_CASE with a hand prefix
   list: a family that does not fit the convention is silently mis-keyed or
   never loaded (#4, #13).
6. **Apply = reset.** Presets reset every unnamed field to its default, so a
   preset's meaning depends on defaults it does not mention (4.5 measures it).
7. **Hand enumerations next to a registry.** Where a registry exists
   (`TOOL_REGISTRY`, `registry.json`, `schema_keys.py`), most leaks are lists
   written beside it instead of derived from it (#8, #9, #11, #21).
8. **Hand-written build plumbing.** The `update` rebuild map, the webapp
   entrypoint's script list and its dev twin, the test sections and
   `_ROOT_RECON_TESTS` each list by hand what the Dockerfiles or a glob already
   know (#7, #18).
9. **A rename that keeps the old name somewhere.** A legacy drop list that now
   names live constraints (#5), retired tools in a category map (#8), modules
   moved without the prose following (#37-#41), headings renamed under incoming
   anchors (#53).
10. **Prose counts.** A number in a sentence is a copy of a `len()`.
11. **Runtime caches in the source tree.** Recon writes refreshed data into the
    mounted checkout, so committed snapshots and live data are the same path.
12. **Guards that skip, or compare with a copy of themselves.** A drift test
    that cannot find its other half skips; one that compares with expectations
    typed into the test catches edits but not omissions; one that is
    documented but never invoked catches nothing (2.2).

---

## 6. Recommended new guards, ranked

Ranked by (silent impact) x (likelihood). Each closes items in section 2 or a
NONE in section 4.

| # | Guard | Closes |
|---|---|---|
| 22 | A Kali tool-presence smoke step: `command -v` every CLI the `kali_shell` description and the skill prompts name (checked by hand on 2026-10-25) | 4.1 |
| 23 | Decide whether runtime caches (`mitre_db/resources`, `wappalyzer_cache`) belong in git (the dead data is deleted and `cpe_resolver.py` reads the refreshed cache) | 4.11 |
| 24 | Derive `_ROOT_RECON_TESTS` from imports; one default model id constant per language | 4.3, 4.13 |

---

## 7. Re-running this audit

The commands behind section 3. All are read-only.

```bash
# generators: the gate runs all three --check modes (section 3.1)
python3 recon_settings/build.py --check
python3 graph_db/node_filters/build.py --check
python3 tooling/scripts/seed_schema_catalog.py --check

# rulesets, and every doc's cited paths. drift-audit exits 1 on its three
# false positives (samugit83/redamon-plugins, tools/list, scanners/graph_db);
# --docs lists only the seven non-paths its gate test allowlists
bash skills/skill-sync/assets/sync.sh --dry-run
bash skills/skill-sync/assets/drift-audit.sh
bash skills/skill-sync/assets/drift-audit.sh --docs

# docs links, anchors, images and counts (P21) and cited paths, in the gate
./redamon.sh test unit   # or the single files: tests/test_docs_not_stale.py, tests/docs_cited_paths_test.sh

# settings mapping count quoted in README.SETTINGS_REGISTRY.md
python3 tooling/scripts/parse_settings_mappings.py

# webapp drift suites (no MCP_DOCS_WRITE, so nothing is written)
cd webapp && npx vitest run --no-file-parallelism \
  src/lib/mcp/apiReference.test.ts src/lib/reconSettings/settingsReference.test.ts \
  src/lib/mcp/toolNameDrift.test.ts src/lib/mcp/onboarding.test.ts \
  src/lib/plugins/schemasExport.test.ts src/app/graph/unseen/registry.test.ts \
  src/lib/reconSettings/registry.consistency.test.ts \
  src/lib/plugins/platformVersion.parity.test.ts \
  src/lib/apiUsage/registry.drift.test.ts src/lib/recon-preset-schema.test.ts
```

The rest is done by comparing lists directly. The checks worth repeating:

- **Tool lists:** `TOOL_REGISTRY` keys vs `TOOL_PHASE_MAP` vs the Prisma
  `agentToolPhaseMap` default vs `ToolMatrixSection.tsx` ids vs
  `BUILTIN_RESERVED_TOOL_NAMES`; every tool name in `CATEGORY_TOOL_MAP`, the
  discovery fallback and `_validate_mutex_groups` against `TOOL_REGISTRY`.
- **Split paths:** every rule in `execute_plan_node.py` has a twin in
  `execute_tool_node.py` (and the reverse).
- **Skills:** `KNOWN_ATTACK_PATHS` vs every layer in 4.2, names **and** values.
- **Defaults:** for each `registry.json` field with a `runtime_key`, `default`
  vs `recon.project_settings.DEFAULT_SETTINGS[runtime_key]` (Json defaults are
  strings: parse them); for each `project.get(...)` in `fetch_agent_settings`,
  Prisma vs `DEFAULT_AGENT_SETTINGS`; every agent column is read at all; the
  agent `/defaults` keys are real columns.
- **Presets:** for each `traffic: active` `*Enabled` field, count the presets in
  `webapp/src/lib/recon-presets/presets/` that never name it, with its default.
- **Graph:** every `[:REL]` and every member of `[:A|B]` in `webapp/src` and in
  Python against the types any `MERGE`/`CREATE` writes; `DROP_LEGACY_CONSTRAINTS`
  names against `schema_keys.py`; duplicate index names.
- **Images and rebuilds:** `IMAGES`, `*_DOCKER_IMAGE` defaults, the broker list,
  `remove_redamon_images`; for each compose service with
  a `build`, every COPY/ADD source and whether `cmd_update` rebuilds (not only
  restarts) that service.
- **WebSocket:** `class MessageType` in `agentic/websocket_api.py` vs `enum
  MessageType` in `webapp/src/lib/websocket-types.ts`.
- **Partial recon:** `tool_id == "..."` in `recon/partial_recon.py` vs
  `SECTION_INPUT_MAP`, `TOOL_QUERIES`, `PARTIAL_RECON_SUPPORTED_TOOLS`.
- **Env:** `.env.example` keys vs compose variables, both directions, and
  whether a key is read anywhere.
- **Cited paths:** every backticked repo path and relative link in
  `docs/readmes/**/*.md`, `skills/**`, `README.md`, `CONTRIBUTING.md` and the
  wiki must exist in `git ls-files` at the path shown, not just somewhere by
  basename (skip placeholders like `[tool]` and gitignored runtime paths).
- **Wiki:** count claims read in context ("at most 200 presets" or "top 10 node
  types" are not counts of the set), page links, `Page#anchor` links against
  GitHub heading slugs (lowercase, punctuation dropped except `-` and `_`, spaces
  to `-`, so " - " becomes `---`), `images/` references, `_Sidebar.md`, the
  `README.DEV.md` §9 index. GitHub resolves wiki page links by name in any
  subfolder; redamon.org copies only top-level pages.
- **Data:** `cmp` the copies under `recon/data/` and
  `recon/main_recon_modules/data/`; check the "retrieved" dates in
  `recon/helpers/cdn_edge_prefixes.py`.

When you fix an item from section 2, delete its row. When you add a new copy
of a fact anywhere in the repository, add a row to section 4, or better, a guard
from section 6.
