# What goes stale: the RedAmon drift map

Every place in this repository where one fact is written down more than once, or
copied from something that keeps changing, and so can silently stop being true.

Use it **before** you change something: find the thing you are touching in the
tables below, and you get every other place that has to move with it, the guard
that will (or will not) catch you, and the command that refreshes it.

> **Last audit: 2026-11-19. Last re-map: 2026-11-19. Last fix pass: 2026-11-19.**
> Branch `feat-15-november`. The audit (1,747 commits after the one before it:
> Tradecraft 2.0, AI Navigator, URLScan, RBAC) found 36 stale items (#89-#124);
> the fix pass the same day fixed all 36 and moved the four guards it added
> (28-31) from section 6 to section 3.2.
> The re-map the same day swept the 1,748 commits since the 2026-10-25 re-map
> through six read-only discovery lenses (declared mirrors, enumerations, build
> plumbing, external data and pins, prose, stored data), and the one writer
> re-verified every claim against the source. Section 2 holds the 25 items it
> found (#125-#149); section 3 gains four generators and two blind spots;
> section 4 gains 72 rows, two new areas among them (4.16 Authorization, 4.17
> Knowledge base), and corrects about 25 more; section 5 gains ten patterns
> (13-22) and section 6 ten guards (32-41). The wiki checkout had uncommitted
> edits from another session, so the wiki line numbers cited here can move.
> Numbers are never reused: the next audit starts at #150.
> `git log --grep 'drift-map #N'` finds the commit that fixed item N.

## Contents

1. [How to read this page, and how it is kept current](#1-how-to-read-this-page-and-how-it-is-kept-current)
2. [Already stale on 2026-11-19](#2-already-stale-on-2026-11-19)
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
   - [4.16 Authorization (RBAC)](#416-authorization-rbac)
   - [4.17 Knowledge base](#417-knowledge-base)
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
| **Stored reference** | A row that stores a code id (a permission, scope, set slug, feature id) or a digest or decision code computed, matched later by exact string. Stale for every stored row when the id is renamed or the code behind the digest changes. | a deny override naming a renamed permission |
| **Build input** | A value baked into an image from env or a compose overlay, not from a file. A file-diff rebuild never sees it change. | `NEXT_PUBLIC_AGENT_WS_URL` |

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
>
> A test the unit tier does not select is no guard for the gate, whatever it
> checks: a Python file whose name puts it in the integration or live tier
> (`_integration.py`, `_skill.py`, `_e2e`, `live_`, `_live`, `_smoke`, `smoke_`;
> `tooling/scripts/pytest_isolated.py`), and a shell file outside the
> `tests/*_test.sh` glob. Such a guard is rated as if it were absent.

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

## 2. Already stale on 2026-11-19

Ordered by impact within each group. Numbers are stable handles for the fix
pass. Each item was verified by reading both sides; "inferred" marks an effect
reasoned from the code and not reproduced.

### 2.1 Behaviour: wrong results at runtime

| # | What | Both sides | Effect |
|---|---|---|---|
| 125 | Three tool branches read API keys from the module-wide settings snapshot | `execute_wpscan`, `execute_gau` and `cve_intel` in `PhaseAwareToolExecutor.execute` (`agentic/tools.py:2792`, `:2803`, `:2814`) read `get_setting('USER_SETTINGS', {})`, which falls back to the module-global snapshot of whichever project loaded last (`project_settings.py:890-902`), then to the `_wpscan_api_token` / `_gau_urlscan_api_key` / `_cve_intel_api_key` fields only tests set (`tools.py:2424-2430`). Every other key read goes through `run_user_settings()` (`tools.py:1139`), written for exactly this (RBAC T17) | Outside a run's own task the call spends another owner's WPScan, URLScan or PDCP key (inferred; whether the fallback can fire in a real run is unverified). Reported by the fix-pass session |
| 126 | Saved user presets and export bundles keep the tool phase map and skill toggles of their day | `extractPresetSettings` captures `agentToolPhaseMap` and `attackSkillConfig` whole (`project-preset-utils.ts:153-165`; both are `mcp: settable` preset fields), and `applyPresetSettings` replaces the phase map (`:186-196`), on the form and over MCP (`reconPresets/server.ts`). `backfill-tradecraft-phases.mjs:62-69` updates only `projects` rows created before its cutoff, and import passes columns through unmerged (`import/route.ts:263-273`) | Applying a user preset saved before 2026-11-18 puts `tradecraft_lookup` and its companions back to exploitation and post-exploitation only; a preset older than a tool denies that tool in every phase (4.1); a bundle imported after the cutoff keeps its old map (inferred) |
| 127 | Web-archive leak findings have no triage row | The OSINT mixin writes `Vulnerability` / `Secret {source: 'url_archive'}` (`osint_mixin.py:1098-1102`), listed in `RECON_FINDING_SOURCES` (`recon/helpers/finding_sources.py:18`). `CONFIDENCE_BY_SOURCE` (`score_model.py:600-672`) has `urlscan` and `urlscan_leak` at 0.4 and no `url_archive` (nor the legacy `shodan_host_lookup` stamp); class routing, the detector key and the exploitable gate test `source == "urlscan_leak"` only (`:1028-1035`, `:1382`, `:1944`); the report's source CASE (`reportData.ts:1384-1391`) has no `url_archive` | A leaked one-time link from GAU or ParamSpider scores at the default confidence 0.75 with a warning, is classed "unclassified" instead of `credential_exposure`, and the client report's source column reads "Security Check" |
| 128 | Most JsReconFinding types are ranked as a generic secret | `JS_RECON_CLASSES` (`score_model.py:477-498`) has 14 types. The writers also stamp `framework`, `object_reference`, `cloud_asset`, `external_domain` (`js_recon_mixin.py:493`, `:660`, `:705`, `:749`), `dependency_confusion` (`recon/helpers/js_recon/dependency.py:227`) and `ai-sdk-*`; an unmatched type falls to `_secret_class` (`:1961`), the generic-secret class. The `cloud_storage` row matches nothing a writer stamps | A detected framework, an external domain or a cloud bucket takes the generic-secret likelihood and impact, and the board explains it as one (inferred) |
| 129 | Key Rotation is offered for 8 services that only ever spend their first key | `ROTATION_TOOLS` (`webapp/src/lib/rotationTools.ts:15-38`, 22 tools) drives the settings buttons and the settings PUT; recon builds rotators for 12 (`recon/project_settings.py:2205-2211`), the agent for tavily, shodan and serp (`_SEARCH_KEY_FIELDS`, `agentic/tools.py:1134`). Nothing reads `rotationConfigs` for quake, hunter, publicwww, hunterhow, onyphe, driftnet, wpscan or pdcp | Extra keys saved for those 8 are never spent; the operator still hits the first key's quota, while the API-usage page probes the extras as live |
| 130 | Typing 0 into a numeric field whose minimum is 0 saves the default instead | `onChange` handlers of the form `parseInt(e.target.value) \|\| N`: `httpxRetries` (`HttpxSection.tsx:113`, N=2), `nucleiRetries` (`NucleiSection.tsx:290`, 1), `masscanWait` (`MasscanSection.tsx:109`, 10), `roeDataRetentionDays` (`RoeSection.tsx:360`, 90), all with registry minimum 0; about 20 such fields by the fix-pass session's count (the four above re-checked). `clearedFallbacks.test.ts` checks that N is the registry default, not that a typed 0 survives | A person who sets retries, the masscan wait or the data retention to 0 saves the default, with no error; 4.4 item 5 |
| 131 | The knowledge base never embeds the post-exploitation skills | `SKILL_CATEGORIES` (`services/knowledge_base/curation/tool_docs_client.py:14-30`, "Keep this list aligned with the actual subdirs under agentic/skills/") lacks `post_exploitation/` (3 files since 2026-04-29) and names two folders that do not exist (`scan_modes`, `coordination`); the ingest walks only the dict (`:85`) | The privilege-escalation and container-escape docs never reach KB search (effect on answers inferred) |
| 132 | Long-running containers `update` does not recreate | `kb-refresh` runs `image: redamon-agent` under its own profile (`docker-compose.yml:1039-1046`); `cmd_update` recreates only `CORE_SERVICES` (`redamon.sh:18`), and the deploy starts it only at `init`. Same family: kali-sandbox imports `graph_db.resource_governor` through its `./graph_db` bind (`docker-compose.yml:809`, `mcp/servers/terminal_server.py:54-62`), and `_map_core_changes` restarts it only for `mcp/` (`redamon.sh:3795-3799`) | After a release that changes `services/knowledge_base/`, the weekly KB refresh runs the old ingestion code until someone recreates it; the terminal session cap keeps the old governor (fails open). Both inferred |
| 133 | A deploy `update` after a host or scheme change keeps the old baked WebSocket URL | `deploy.sh:169` recomputes `NEXT_PUBLIC_AGENT_WS_URL`, a webapp build argument only in the prod overlay (`docker-compose.prod.yml:27-33`); `redamon.sh update` rebuilds the webapp only for file changes, and the follow-up `up -d webapp` (`deploy.sh:991`) has no `--build` (its own comment: "An .env-only edit changes no image") | Moving a deploy from an IP to a domain, or from ws to wss, leaves the chat dialling the old origin (inferred; the #95 fix covers `REDAMON_VERSION` only) |

### 2.2 Guards that do not guard

| # | What | Both sides | Effect |
|---|---|---|---|
| 134 | The per-skill wiring tests never run in the unit gate | The 16 `agentic/tests/test_*_skill.py` files, including the crypto_attack, deserialization, http_smuggling, path_traversal, xxe and rce ones section 4.2 credits, end in `_skill.py`, which `tooling/scripts/pytest_isolated.py:40` puts in the integration tier; `./redamon.sh test` defaults to `unit` (`redamon.sh:5555`). They only read files (`schema.prisma`, `AttackSkillsSection.tsx`, the attack-skills route). The same holds for `tests/test_supply_chain_ecosystems_integration.py` (the form's OSV ecosystem copy) and `test_questions_file_is_current` (`agentic/tests/test_tradecraft_eval_integration.py:60-63`, the Tradecraft eval corpus against `make_corpus.py`) | A skill layer, the form's ecosystem list or the eval corpus goes stale with the unit gate green; for the gate, the PART guards of 4.2 are NONE |
| 135 | Offline checks in shell files the gate never globs | `tests/test_port_bindings.sh` (debug ports on loopback, 8016 unpublished; "works in CI") is named `test_*.sh`, outside the `tests/*_test.sh` glob (`redamon.sh:5615`), and exits 0 without `docker compose` (`:23-26`); `README.SECURITY_POSTURE.md:508` cites it as coverage. `rbac_upgrade_live.sh selftest` ("offline, no Docker") checks the capability oracles against `permissionCatalog.json` inside a `*_live.sh`. `testing/guinea_pigs/js_secret_lab/gen_lab.py --check-expected` is called by nothing | A port published on every interface, a renamed permission in the upgrade oracles, or a stale lab `expected.json` passes the gate |
| 136 | The coverage tier enforces no floor, and the agent runner skips silently | `./redamon.sh test coverage` passes `--cov-floor ${REDAMON_COV_FLOOR:-0}` (`redamon.sh:5523`); `README.TESTING.md:631-639` says the floor is enforced and settable "per section … (or the section spec in `redamon.sh`)", which has no floor field; 79 lives only in `agentic/run_tests.sh:31`. That runner, "the agent-image unit gate" in the root `AGENTS.md` and a line of the `agentic/AGENTS.md` QA checklist, exits 0 with "SKIP" when the image is missing (`:34-37`) | The canonical coverage run passes at any coverage; the component checklist can be ticked with nothing run |
| 137 | Three knowledge-base test files always skip on a default install | `services/knowledge_base/tests/test_{embedder,faiss_indexer,reranker}.py:10-12` `importorskip` the KB extras, which the agent image installs only with `--kbase` (`SKIP_KB`, `agentic/Dockerfile:131-154`) | Embedder, FAISS and reranker code is untested on a gate host installed without `--kbase`; the run reports them as empty, not failed |
| 138 | Mirror comments that name a guard that is not there | `webapp/src/lib/scaIntel.ts:8` "`scaIntel.parity.test.ts` pins the two implementations" (no such file; the real check, `tests/test_sca_ioc_match.py:177-200`, only finds each host string in the TS test); `graph_db/resource_governor.py:23-24` "Keep the two byte-identical" (the orchestrator copy adds `disk_stats()` and differs in comments; `tests/test_resource_governor.py` compares only `_FALLBACK_PROFILE`); `tests/test_supply_chain_mcp.py:108` "matches_shared_one" checks hand cases against the Kali copy only (#147) | A reader, and this page, credit a TEST that is PART or NONE |

### 2.3 Agent-facing and developer text (produces wrong code)

| # | What | Both sides | Effect |
|---|---|---|---|
| 139 | The agent is pointed at 14 of the 21 proxy_brain manual sections | `tool_registry.py:63-64` lists 14, the MCP docstring (`network_recon_server.py:689-690`) 13, `AI-Agent-Guide.md:1000` says "20 sections"; the manual has 21 `## ` sections (`mcp/servers/proxy_brain_manual.md`, its own index at `:137-161`). Both agent-facing lists miss nosql, graphql, lfi, cmdi, cors, xxe and auth; the docstring also misses browser | The agent is steered away from 7 recipe sections (inferred; the manual's own index lists them) |
| 140 | Operator docs that teach knobs nothing reads | `README.MEMORY_GOVERNOR.md:766-773` documents `RECON_CONTAINER_MEM`, `AI_ATTACK_MEM`, `GVM_SCAN_MEM`, `GITHUB_HUNT_MEM` and `TRUFFLEHOG_MEM` ("set one to force a fixed ceiling"); no code reads any of them, and the 2026-10-25 fix of #23 removed them from `.env.example` as unread. `README.CYPHERFIX_AGENTS.md:925-931`, `:989-1003` give `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENROUTER_API_KEY`, `TAVILY_API_KEY`, `CYPHERFIX_REPOS_BASE` and the AWS keys as env vars; nothing in `agentic/` reads them (keys live in `user_llm_providers` and user settings) | An operator's override, or a developer's env key, is silently ignored |
| 141 | `README.DEV.md:587` says the CodeFix agent "ships with a full polyglot runtime: Node.js 20, Python 3.11, Go 1.22, Ruby, Java 17, PHP, .NET 8 — so it can build and test any target repository" | Builds run in the sandbox (`agentic/cypherfix_codefix/tools/bash_tool.py:23` -> `sandbox_client.run_bash`), whose image has Node 20, python3 and build-essential only (`scanners/codefix_sandbox/Dockerfile:16-31`: "Builds needing a toolchain not installed here will fail") | A Go, Java, .NET, PHP or Ruby target fails to build (inferred) |

### 2.4 Counts and links in docs

| # | What | Doc | Truth |
|---|---|---|---|
| 142 | Downgrade loss | `README.DEV.md:1255`, `Identity-and-Access-Management.md:767`, `Deploying-to-a-Server.md:351`: "16 tables and 28 columns" | 27 tables and 46 columns in `DOWNGRADE_TABLES` / `DOWNGRADE_COLUMNS` (`webapp/scripts/rbac-upgrade-preview.mjs`); the 11 added tables are Tradecraft's and Navigator's, so an operator going back to 7.7.2 is not told it deletes them |
| 143 | A command that does not exist | `Knowledge-Base-Web-Search.md:135,140` and the diagram at `README.KBASE.md:820`: `./redamon.sh restart` | no `restart` in the `redamon.sh` dispatch: "Unknown command", exit 1 |
| 144 | Identifiers that exist nowhere in the code | `README.md:727` and `Agent-Workspace.md:110,391` `WORKSPACE_LAYOUT_BLOCK`; `Chat-Skills.md:401,408` `_resolve_user_skill()`; `Recon-Presets.md:219` `stripExcludedOnApply()`; `Insights-Dashboard.md:503` label `DnsRecord`; `README.AGENTIC_SYSTEM.md:4188` `get_tenant_context()`, `:3954` `_start_new_objective_node()`, `:2303` `_highest_prior`, `:3038` `_deploy_fireteam_plan` | `_WORKSPACE_LAYOUT_HEADER` / `_FOOTER` (`agentic/prompts/base.py:41,170`), `resolve_user_skill` (`agentic/prompts/__init__.py:175`), no such export in `project-preset-utils.ts`, `DNSRecord`; the four agent functions do not exist (`agent_context.py` has `set_*` and the `get_*_context` readers only). No guard reads identifiers in prose |
| 145 | Scanner count in the root ruleset | `AGENTS.md:107` "the 11 scan tools, each its own container image" | 12 folders under `scanners/`, 10 with a Dockerfile (`supply_chain_common` is a library, `scan_targets` a data folder) |
| 146 | Docs outside the path audit | `testing/guinea_pigs/supply_chain_target/README.md:275-277` "`run_supply_chain_recon` never passes `js_contents` … Unit tests only", and its `#L51` / `#L93` anchors; `agentic/labs/ai-surface/README.md:62` links an untracked `internal/` tree; `THIRD-PARTY-LICENSES.md:188` `ospd-openvas:22.7.1` | the code passes `js_contents` since `c5dbf106` (`supply_chain_recon.py:611-614`); compose runs `ospd-openvas:stable` since 2026-04-13 (`docker-compose.yml:256`); `drift-audit.sh --docs` reads none of these files (4.14) |

### 2.5 Dead or diverging data

| # | What | Both sides | Effect |
|---|---|---|---|
| 147 | The Kali copy of the package-name gate anchors with `$` | `_SC_NAME_RE` (`mcp/servers/network_recon_server.py:1591`, "Mirror of supply_chain_common.security.sanitize_name") against `_NAME_RE` (`scanners/supply_chain_common/security.py:45`, `\Z`, whose comment says `$` lets `"evil\n"` through); the Kali copy also applies the name charset to a purl, so `%` is refused | `"pkg:npm/x\n"` passes, into a temporary SBOM only (low); a percent-encoded scoped purl is refused by the agent's OSV tool |
| 148 | Knowledge-base defaults in code differ from the YAML | `kb_config.yaml:125,136` (score threshold 0.80, MMR lambda 0.65, a `cpu-lite` profile) against `DEFAULTS` and the dataclass defaults in `kb_config.py:49,54,129,136` (0.35, 0.5, no `cpu-lite`) | Inert while the YAML loads; on a YAML read error the agent falls back to 0.35 and the web fallback fires far less (inferred) |
| 149 | Small diverging copies | `McpAccessToken.scopes @default(["recon:read"])` (`schema.prisma:296`) against `DEFAULT_MCP_SCOPES` (`mcpAuth.ts:110`, adds `kali:exec`), and the only create path always sets scopes; `origin_discovery.py:103` sends Chrome/131, not `DEFAULT_BROWSER_UA` (Chrome/120, `recon/helpers/user_agent.py:16`); `http_probe.py:1408-1413` "must mirror the tlsx writer's precedence" adds an `issuer_org` fallback `tlsx_mixin.py:219` lacks; the broker's governor branch (`broker.py:473-479`) cannot run in its image (`services/docker_broker/Dockerfile:12` copies only `broker.py`) and compose always passes `BROKER_TOOL_MEM_BYTES`; the garak test's `UI_FAMILIES` (40, count-locked) keeps 7 families the card dropped on 2026-06-22 (`aiAttackSurface.ts:80`, 33) | Dead or cosmetic; low |

---

## 3. The guards that exist, and their blind spots

### 3.1 Generators

| Source | Command | Outputs | Gate check |
|---|---|---|---|
| `recon_settings/registry.yaml` (+ Prisma join; each tool's `produces` from `SECTION_NODE_MAP` in `nodeMapping.ts`) | `python3 recon_settings/build.py` | `recon_settings/registry.json`, `webapp/src/lib/reconSettings/registry.json` (byte-identical), `webapp/src/lib/reconSettings/registryDigest.generated.ts`, `recon_settings/roe_parse_prompt.py` | GEN: `tests/test_registry_build_check.py` runs `build.py --check`; the gate also compares the two JSON copies, the prompt against the JSON, and the JSON against Prisma |
| `registry.json` | `cd webapp && npm run docs:settings` | `redamon.wiki/Project-Settings-Registry.md` | `settingsReference.test.ts` byte-compare; an empty wiki checkout fails it unless `REDAMON_TEST_ALLOW_MISSING` names `wiki` (`wikiCheckout.testUtils.ts`) |
| Prisma columns with no registry entry | `python3 tooling/scripts/extract_recon_registry.py` | draft entries in `registry.yaml` (top-up, never overwrites) | `registry.prisma.test.ts` fails on a column with no entry |
| `graph_db/node_filters/catalog.yaml` | `python3 graph_db/node_filters/build.py` | `graph_db/node_filters/catalog.json`, `webapp/src/lib/nodeFilters/catalog.json`, and the 31 `fixtures/*.json` mirrored into `webapp/src/lib/nodeFilters/fixtures/` | GEN: `build.py --check` via `tests/test_node_filters_engine.py:63-66`; also fails on a setting the registry lacks or a form tab `ProjectForm.tsx` lacks |
| `graph_db/schema_sections.md` | `python3 tooling/scripts/seed_schema_catalog.py` | `graph_db/schema_catalog.py` | GEN: `--check` regenerates and compares with the committed `graph_db/schema_catalog.py`; `recon/tests/test_schema_catalog.py` runs it and checks the segments against `schema_sections.md` |
| live `tools/list` of the inbound MCP server | `cd webapp && npm run docs:mcp` | `redamon.wiki/MCP-API-Reference.md` | `apiReference.test.ts` byte-compare; an empty wiki checkout fails it unless `REDAMON_TEST_ALLOW_MISSING` names `wiki` |
| zod plugin schemas | `cd webapp && npm run plugins:schemas` | `webapp/src/lib/plugins/schemas/json/{manifest,screen,catalog}.schema.json` | `schemasExport.test.ts` |
| every `webapp/src/app/api/**/route.ts`, the middleware's `PUBLIC_PATHS` / `TOKEN_AUTH_PREFIXES`, the permission registry | `cd webapp && node scripts/gen-route-manifest.mjs` | the `ROUTE_MANIFEST` initializer in `webapp/src/lib/authz/routeManifest.ts` (its notes are hand-kept) and `routeManifest.json` | GEN: `routeManifest.test.ts` ("the generator would change nothing", and the JSON equals the render; coverage both ways) |
| the route manifest JSON, `permissionCatalog.json`, `e2e-rbac-seed.mjs` | `cd webapp && node scripts/gen-rbac-matrix-rows.mjs` | `tests/fixtures/rbac_matrix/p{3,4,5}_generated.tsv` | GEN: `routePermissions.test.ts` runs `--check`; the rows themselves run only in `tests/rbac_matrix_live.sh`, which the gate does not glob (`*_live.sh`) |
| `webapp/src/lib/tradecraft/settingsSpec.json`, `vocab.json` | `node webapp/scripts/gen-tradecraft-spec.mjs` | `agentic/tradecraft/settings_spec.json`, `agentic/tradecraft/vocab.json` (byte copies) | GEN: `webapp/scripts/gen-tradecraft-spec.test.ts` (`--check`); `agentic/tests/test_tradecraft_settings.py` and `test_tradecraft_vocab.py` byte-compare in the agent image |
| `webapp/src/lib/authz/permissions.ts` + the built-in sets | `cd webapp && npx vitest run src/lib/authz/builtinSets.test.ts -u` | `webapp/src/lib/authz/permissionCatalog.json` (read by the `.mjs` scripts) | `builtinSets.test.ts` (`toMatchFileSnapshot` compare) |
| multi-mute suggestion contract | `MULTI_MUTE_CONTRACT_WRITE=1` on `agentic/tests/test_multi_mute_contract.py` | `webapp/src/app/graph/components/MuteNode/multiMuteSuggest.contract.json` | the same test, compare mode |
| node-filter run contracts | `NODE_FILTER_CONTRACT_WRITE=1` on `agentic/tests/test_node_filter_runs.py` and `route.nodeFilter.test.ts` | `webapp/src/lib/nodeFilters/contracts/{run_callbacks,project_get}.json` | the same tests, compare mode |
| `skills/*/SKILL.md` frontmatter | `bash skills/skill-sync/assets/sync.sh` | the "Auto-invoke Skills" tables in every `AGENTS.md` | `sync.sh --dry-run` (no gate test) |
| skill + AGENTS.md citations | `bash skills/skill-sync/assets/drift-audit.sh` | report of dead cited paths in `skills/*/SKILL.md` and `AGENTS.md`; exits 1 on any | manual; a markdown link resolves only from the citing file's folder; `tests/drift_audit_test.sh` tests the script; `citation-check.sh` in the advisory pre-commit hook |
| cited repo paths in every doc | `bash skills/skill-sync/assets/drift-audit.sh --docs` | dead paths in `docs/readmes/**`, `README.md`, `CONTRIBUTING.md`, the top-level wiki, `SKILL.md`, `AGENTS.md` (a path counts only if git tracks it) | GEN-like: `tests/docs_cited_paths_test.sh`; `tests/fixtures/docs_paths_drift_{wiki,readmes,root}.json` hold only the seven tokens that look like paths and are not (an entry that stops failing must leave) |
| built-in skill prompts | `agentic/tests/tools/record_skill_golden.py` | `agentic/tests/fixtures/skill_workflow_golden.json` | `test_skill_workflow_golden.py` (fails until re-recorded) |
| the settings resolution path | `recon/tests/regen_golden_settings.py` (inside `redamon-recon`, see `README.SETTINGS_REGISTRY.md`) | `recon/tests/fixtures/golden_settings/*.json` (18 cases) | `test_golden_master.py` |
| the two PSL snapshots | `python3 tooling/scripts/psl_drift_report.py` | report only | manual release step (`README.DEV.md` §5.8) |
| the wiki | `DevergoLabs/scripts/sync-docs.mjs` (nightly `refresh-docs.sh` on the server), `add-wiki-canonical.mjs` | redamon.org `/docs` pages (top-level pages only; `hacklab/` and the session subtrees are not copied, so links into them probably break there, unverified), the canonical banner on each wiki page | none; the banner bytes are duplicated in `webapp/src/lib/mcp/apiReference.ts` `CANONICAL_BANNER` |
| `agentic/tests/fixtures/tradecraft_sites/make_fixtures.py` | run it in the agent image (its docstring) | the whole `tradecraft_sites/` tree (sites, API answers, archives, PDFs) | GEN: `agentic/tests/test_tradecraft_doubles.py` rebuilds it and compares the file set and the bytes (archives decompressed) |
| `agentic/tests/fixtures/tradecraft_eval/make_corpus.py` | `python make_corpus.py` | `tradecraft_eval/questions.jsonl` | **not in the unit gate**: `test_questions_file_is_current` needs no database but sits in `test_tradecraft_eval_integration.py`, an integration-tier name (#134) |
| `tests/fixtures/rbac_upgrade/seed/<scenario>.sql` and the pinned `redamon-webapp:rbac-7.7.2` image | `bash tests/rbac_upgrade_live.sh regen` | `tests/fixtures/rbac_upgrade/<scenario>.sql`, `expected/<scenario>.out` (the `.after*` and `.capabilities*` oracles are hand-written) | live only; the offline `selftest` mode, which checks the oracles against `permissionCatalog.json`, sits inside a `*_live.sh` (#135) |
| `testing/guinea_pigs/js_secret_lab/gen_lab.py` | `--emit-expected` | `js_secret_lab/expected.json` | NONE: `--check-expected` exists and nothing calls it (#135) |

On 2026-11-19 all three Python generators reported up to date (all three are
gate checks, and `tooling/hooks/pre-commit` runs them when a commit stages a
generator's files; it runs none of the three JS generators above), the skill
sync dry run changed nothing (20 skills), `drift-audit.sh` exited 1 on eight
false positives (the two GitHub slugs in `AGENTS.md`, the `loop/` and `instance/`
model-id prefixes in three skills, `tools/list`, `scanners/graph_db`), the ten
webapp drift suites passed (316 tests; the one skip is the write-mode case), and
so did the four generator suites added since (63 tests). The re-map the same day
re-ran them all after the fix pass: the same results, the five pure-bash guards
of section 7 green (`redamon_update_map_test.sh` 401 checks), and the 14 webapp
suites of section 7 plus `gen-rbac-matrix-rows.test.ts` 401 passed, 1 skipped.
The pre-commit hook picks the commits that run a generator from
`GENERATOR_AREAS` (`tooling/hooks/pre-commit`), a hand list of the three Python
generators' inputs, complete today.

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
| a forbidden parent forbids its companions (`GRAPH_COMPANION_TOOLS`, `TRADECRAFT_COMPANION_TOOLS`) on every executor path, and every companion constant's parent is a `roeForbiddenTools` value (guard 30, first half) | `agentic/tests/test_roe_gate.py` |
| every `set_tenant_context` call in an executor node passes the chat session id; `_build_redamon_ctx` falls back to the log session (guard 30, second half) | `agentic/tests/test_tool_call_session_id.py` |
| the agent's `LOOP_ANSWER_MAX_CHARS` default and maximum == the webapp's `LOOP_ANSWER_MAX_CHARS` | `agentic/tests/test_agent_in_the_loop_settings.py` |
| every numeric display or cleared-field fallback in the project form == the field's registry default (a named, empty allowlist) | `webapp/src/components/projects/ProjectForm/sections/clearedFallbacks.test.ts` |
| the preset modal names every `*Enabled` key the preset schema accepts from the registry; the partial-recon modal describes every partial-recon tool | `GeneratePresetModal.labels.test.ts`, `WorkflowView/PartialReconModal.runButton.test.tsx` |
| the unclassified routing table names every `KNOWN_ATTACK_PATHS` id once | `agentic/tests/test_unclassified_routing_table.py` |
| `BUILTIN_RESERVED_TOOL_NAMES` (TS) == `mcp_registry._builtin_tool_names()` (registry keys, the three tradecraft tools and `SYSTEM_MCP_TOOL_NAMES`), both ways | `agentic/tests/test_reserved_tool_names_parity.py` |
| server tools -> `SYSTEM_MCP_TOOL_NAMES` (one direction: a stale allowlist name passes) | `agentic/tests/test_system_mcp_tool_coverage.py` |
| fs_ tools <-> registry both ways; job_ tools one way plus a count lock of 29 on the fs_ and job_ tools together (24 + 5) | `agentic/tests/test_tool_registry_completeness.py` |
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
| the finding-label set: 14 copies (`agentic/api.py`, `chain_graph_writer.py`, `fact_queries.py`, the triage mixin, `actions.ts`, `findingLabels.ts`, `reportData.ts`, the copies in `test_partial_recon_excludes_muted.py`, `reportCountable.test.ts` and `reportData.test.ts`, ...) equal `MUTEABLE_LABELS`; the Multi mute pool is it minus `ExploitGvm` | `tests/test_finding_labels_mirrors.py` |
| `graph_db/schema_sections.md` <-> `graph_db/schema_catalog.py` | `recon/tests/test_schema_catalog.py` (`seed_schema_catalog.py --check`) |
| Red Zone network-initial-access ports and finding types <-> `security_checks.py` | `recon/tests/test_net_init_access_parity.py` |
| deleted bundled data stays deleted; `cpe_resolver` reads the cache `http_probe` refreshes | `recon/tests/test_dead_bundled_data.py` |
| nothing in `agentic/` shadows a file the agent image bakes earlier | `tests/test_agent_image_no_shadowed_copy.py` |
| broker allowlist <-> every image recon runs, both ways (a broker image recon does not run needs a named caller); the entrypoint `IMAGES` == the `*_DOCKER_IMAGE` defaults | `services/docker_broker/test_image_parity.py` |
| broker API routes, repository bind subdirectories (`REPO_TOOL_SUBDIRS`), writable volumes and networks <-> every docker call site under `recon/` and `scanners/supply_chain_common/`, both ways (one missing or unused fails) | `services/docker_broker/test_tool_invocations.py` |
| a stop removes its own run's tool containers, of any image, by the broker's run labels (no image list to keep); `remove_redamon_images` removes every third-party image (it reads the entrypoint `IMAGES`) | `recon_orchestrator/tests/test_run_label_cleanup.py`, `services/docker_broker/test_run_labels.py`, `tests/redamon_runtime_images_test.sh` |
| what `update` rebuilds: every COPY/ADD source of every image compose builds must rebuild it (or restart it under a compose bind mount), derived from the compose file and the Dockerfiles; every module recon-orchestrator and traffic-ingest import from a bind mount restarts them (guard 31, derived from their imports); a `VERSION` change rebuilds every service taking `REDAMON_VERSION` | `tests/redamon_update_map_test.sh` |
| a shell suite that cannot run exits 77, and the shell section fails on it unless `REDAMON_TEST_ALLOW_MISSING` names `shell` or the suite; no `tests/*_test.sh` may print SKIP for python3, PyYAML or git and exit 0 (guard 28) | `tests/redamon_gate_unskippable_test.sh` |
| OSV ecosystems in 4 places (`SEED_MANIFESTS`, `_OSV_SYNC_ECOSYSTEMS`, `OSV_ALL_ECOSYSTEMS`, compose `OSV_DB_ECOSYSTEMS`); a fifth, the form's `SUPPLY_CHAIN_ECOSYSTEMS` (`supplyChainEcosystems.ts`), only by an integration-tier test and a literal copy (#134) | `tests/test_supply_chain_osv_refresh.py`; `tests/test_supply_chain_ecosystems_integration.py` and `supplyChainEcosystems.test.ts` for the fifth |
| TruffleHog sources/registry Python <-> TS | `tests/test_trufflehog_registry_parity.py` |
| plugin platform version, 5 pinned copies (`platformVersion.ts`, `platform_version.py`, the SDK `__init__.py`, `sdk/contract_cases.json`, `tests/runner_contract_cases.json`) | `webapp/src/lib/plugins/platformVersion.parity.test.ts` |
| resource profile JSON <-> both governors (the two governor modules themselves are not compared, #138) | `tests/test_resource_governor.py` |
| API-usage probes cover every saved credential | `webapp/src/lib/apiUsage/registry.drift.test.ts` |
| GVM data containers count | `tests/redamon_gvm_compose_test.sh:216-217` |
| fireteam timeout UI fallbacks == `FIRETEAM_TIMEOUT_SEC` | `webapp/src/components/projects/ProjectForm/sections/AgentBehaviourSection.test.tsx` |
| the preset-generation no-temperature rules (TS) == `llm_setup.py`'s | `webapp/src/lib/llmTemperature.test.ts` |
| the triage score and tiers, Python and TS, answer one vector file; a score-only fallback at a tier boundary is an accepted, listed difference | `webapp/src/app/graph/components/Triage/triageScore.vectors.json` (`triageLayers.parity.test.ts`, `agentic/tests/test_triage_score_vectors.py`) |
| the IP-mode hostname selection rule (`recon_settings/ip_hostnames.py`) and its TS preview mirror (`webapp/src/lib/ipHostnameFilter.ts`) answer one vector file, in the recon, orchestrator and agent images; the Python side fails if the TS test stops naming the fixture path, since that suite skips when the file is missing | `tests/fixtures/ip_hostname_vectors.json` (`recon/tests/test_ip_hostname_vectors.py`, `recon_orchestrator/tests/test_ip_hostname_vectors.py`, `agentic/tests/test_ip_hostname_vectors.py`, `webapp/src/lib/ipHostnameFilter.test.ts`); the never-scannable predicate copied from `ip_filter.is_never_scannable_ip` is pinned address by address in `recon/tests/test_ip_hostname_rule.py` |
| the settings an IP project's hostname mode forces at scan start (`_IP_HOSTNAME_FORCED` in `recon/project_settings.py`) == the table MCP `get_recon_settings` and `preflight_scope_check` report (`webapp/src/lib/ipHostnameOverrides.ts`, keyed by column) | `recon/tests/test_ip_hostname_overrides.py::test_the_webapp_copy_equals_the_python_table` (parses the TS object; skips only when the webapp file is absent) |
| the hostname policy's defaults and cap bounds in `webapp/src/lib/scopeGroups.ts` (`IP_HOSTNAME_DEFAULTS`, the bounds the write rule repeats) == the registry | `webapp/src/lib/scopeGroups.ipHostnames.test.ts` (defaults vs Prisma via the registry, bounds vs `registry.json`); the recon loader reads its bounds from the registry itself |
| every preset decides each default-on active toggle, and passive or stealth presets run none (allowlist with reasons) | `webapp/src/lib/recon-presets/traffic-decisions.test.ts` |
| every webapp route Python calls with the internal or scanner key matches the middleware allowlists, computed from the callers | `webapp/src/middleware.internalCallers.test.ts` |
| one version per pinned tool (TruffleHog, osv-scanner, guarddog, retire.js) across Dockerfiles, prose, the licence file and fixtures | `tests/test_tool_version_pins.py` |
| wiki links, anchors (the anchor of a `github.com/.../blob/...#...` link too), images and doc counts (recon presets, MCP presets on every page, node types, settings, RBAC permissions, MCP scopes, LLM providers, chat skills; guard 29); an empty `(#)` link fails; every file a generator owns is in `_GENERATED` (P19) | `tests/test_docs_not_stale.py` (P21; `tests/fixtures/docs_drift_*.json` are empty after wave 3) |
| the `README.md` version badge names the release in `VERSION` | `tests/test_readme_version_badge.py` |
| no `SKILL.md` or `AGENTS.md` links a `file#L<n>` line number; every `` [`symbol`](path#L<n>) `` link in `docs/readmes/**` lands within 3 lines of its symbol (guard 29; a link whose text names a file and line, not a symbol, is not checked) | `tests/test_ruleset_line_anchors.py` |
| every memory-governor knob compose hands the orchestrator reaches both recon spawn sites, and every knob the governor reads is forwarded | `recon_orchestrator/tests/test_governor_env_forwarding.py` |
| every graph label is produced by a tool (from `SECTION_NODE_MAP`) or named with its writer in `WRITTEN_OUTSIDE_A_SECTION` | `tests/test_registry_tool_wiring.py` |
| `testing/guinea_pigs/README.md` lists every tracked lab, and only those | `tests/test_guinea_pigs_index.py` |
| `redamon.wiki` is a declared submodule; an empty checkout fails the wiki tests unless allowed | `tests/test_wiki_submodule.py`, `tooling/scripts/wiki_checkout.py`, `webapp/src/lib/wikiCheckout.testUtils.ts` |
| the pre-commit hook blocks a commit that leaves a generated artifact stale | `tests/pre_commit_hook_test.sh` |
| every registered recon preset records a vhost-SNI decision | `webapp/src/lib/recon-presets/vhost-sni.test.ts` |
| `drift-audit.sh` reports a dead relative link | `tests/drift_audit_test.sh` |
| `_GENERATED` names files that exist | `tests/test_docs_not_stale.py` |
| `agentic/tradecraft/contract.py` <-> `webapp/src/lib/tradecraft/agentContract.ts`: both parse every valid and invalid fixture and match `enums.json` | `agentic/tests/test_tradecraft_contract.py`, `webapp/src/lib/tradecraft/agentContract.test.ts` (fixtures in `agentic/tests/fixtures/tradecraft_contract/`) |
| the machine credential: the TS minter `webapp/src/lib/authz/machineCredential.ts` <-> `agentic/machine_credential.py` <-> `recon_orchestrator/job_credential.py` | `tests/fixtures/machine_credential/vectors.json` (`machineCredential.test.ts`, `agentic/tests/test_machine_credential_interop.py`, `recon_orchestrator/tests/test_job_credential_admission.py`) |
| the triage disposition: `webapp/src/lib/triage/disposition.ts` <-> Python `combine_layers` | `disposition.vectors.json`, `disposition.gates.vectors.json` (`agentic/tests/test_disposition_parity.py`, `disposition.test.ts`) |
| the RoE scanning window, 3 copies (`recon/helpers/roe_scope.py`, `recon_orchestrator/api.py`, `webapp/src/lib/roe/scanWindow.ts`) | `recon/tests/fixtures/roe_time_window_vectors.json` (the recon test also fails if the other two stop naming the fixture; the orchestrator test; `scanWindow.vectors.test.ts`) |
| the partial-run typed-input RoE filter: `recon/partial_recon_modules/helpers.py` <-> `recon_orchestrator/batch_scope.py` | `recon/tests/fixtures/partial_typed_input_roe_vectors.json` (`recon/tests/test_partial_typed_input_roe.py`, `recon_orchestrator/tests/test_partial_typed_input_roe.py`) |
| coverage-stamp modules, statuses and fields, 3 copies (`graph_db/coverage_stamps.py`, `recon/helpers/coverage_stamps.py`, `webapp/src/lib/coverageStamps.ts`) | `tests/test_coverage_stamps_parity.py` |
| the password policy `webapp/scripts/lib/password-policy.json`, read by TS and `.mjs`; the floors in `redamon.sh` and `deploy.sh` | `webapp/src/lib/authz/passwordPolicy.drift.test.ts` |
| workspace-transfer failure codes and stop reasons (`agentic/workspace_import/errors.py`, `mirror.py`) <-> the transfers panel | `FileSystemDrawer/transferMessages.contract.test.ts` (skips when the Python files are absent) |
| the agent's download card <-> `FileDownloadCard` | `tests/fixtures/download_card/owner_card.json` (`agentic/tests/test_download_card_workspace.py`, `FileDownloadCard.route.test.tsx`) |
| Tradecraft skill topics == `KNOWN_ATTACK_PATHS` (14, count-locked) | `webapp/src/lib/tradecraft/vocab.test.ts` |
| the Tradecraft site fixtures == what `make_fixtures.py` writes | `agentic/tests/test_tradecraft_doubles.py` |
| Tradecraft adds no environment key: the agent and webapp compose `environment:` keys and `.env.example` pinned as at the plan's base commit, so any new key, Tradecraft's or not, must join the list (a hand copy, section 3.3) | `tests/tradecraft_no_new_env_test.sh` |
| shared vectors read by both languages | `recon/tests/fixtures/roe_exclusion_vectors.json` (recon, agent, webapp, AI attack-surface and orchestrator partial-run RoE matchers), `recon/tests/fixtures/roe_time_window_vectors.json`, `recon/tests/fixtures/partial_typed_input_roe_vectors.json`, `tests/fixtures/machine_credential/vectors.json`, `webapp/src/lib/triage/disposition.vectors.json`, `disposition.gates.vectors.json`, `agentic/tests/fixtures/tradecraft_contract/`, `tests/fixtures/download_card/owner_card.json`, `webapp/src/lib/llmTemperature.vectors.json`, `webapp/src/app/graph/components/Triage/triageScore.vectors.json`, `recon_orchestrator/tests/fixtures/hard_guardrail_vectors.json`, `tests/fixtures/scope_groups_contract.json`, `tests/fixtures/legacy_domain_vectors.json`, `tests/fixtures/ip_hostname_vectors.json`, `webapp/src/lib/engagement.derivation.fixtures.json`, `recon/tests/fixtures/public_suffix_vectors.json`, `agentic/tests/fixtures/redaction_vectors.json`, `agentic/tests/fixtures/skill_metadata_contract.json`, `webapp/src/lib/mcp/contracts/triage_mute.json`, `webapp/src/app/graph/components/MuteNode/multiMuteSuggest.contract.json`, `webapp/src/lib/nodeFilters/contracts/*.json`, `services/plugin_runner/sdk/contract_cases.json`, `services/plugin_runner/tests/runner_contract_cases.json` |

### 3.3 Blind spots shared by all of them

- **No CI.** A guard that nobody runs guards nothing. The pre-commit hook runs
  the three Python generator checks (none of the JS ones), but only where
  `tooling/hooks/install-hooks.sh` has installed the current copy.
- **The wiki is a separate checkout.** `.gitmodules` declares it, and an empty
  `redamon.wiki` fails every wiki-dependent test unless
  `REDAMON_TEST_ALLOW_MISSING` names `wiki`; with that opt-out they skip.
- **Cross-tree tests skip when the other tree is absent.** 27 webapp test files
  use `skipIf(!existsSync(...))` or similar; the gate runs vitest in the host
  checkout (`_test_run_webapp`), so they run there, but they skip in a
  webapp-only tree. The TS halves of two shared vector files
  (`hard-guardrail.test.ts`, `legacyGraph.test.ts`) also skip if their fixture
  moves, and no Python test checks that they still name it (the IP-hostname and
  RoE-window pairs have that check).
- **Expectations copied into the test.** The dangerous-tools test (19 names
  pinned) and the hand-written label lists in `tests/test_mcp_cypher_scoping.py`,
  `tests/test_triage_mixin.py`, `agentic/tests/test_triage_security_hardening.py`,
  `recon/tests/test_schema_constraints_generated.py` and
  `recon/tests/test_schema_catalog.py` compare the code with a hand copy, so they
  catch an edit but not an omission. So do `FINDING_SOURCES`, `TYPES` and
  `ROUTE_TYPES` in `test_score_model.py`, `test_score_model_urlscan.py` and
  `test_route_exposure_triage.py`, the garak test's `UI_FAMILIES`, the Kali
  `_sc_safe_name` cases in `tests/test_supply_chain_mcp.py`, the conftest string
  in `tests/test_pytest_isolated_tiers.py`, `supplyChainEcosystems.test.ts`,
  `TestPhase0Mirror` in `tests/test_github_hunt_patterns.py`, and the agent-cap
  and WebSocket-audience literals each side pins (4.16).
- **The file name decides whether a guard runs.** `pytest_isolated.py` sorts
  tests into tiers by file name, the unit gate runs only the unit tier, and the
  shell section globs only `tests/*_test.sh`. The 16 per-skill wiring tests
  (`*_skill.py`), the OSV ecosystem form check and the Tradecraft corpus check
  (`*_integration.py`), the port-publish policy (`test_port_bindings.sh`) and the
  RBAC oracle selftest (`*_live.sh`) are hermetic and outside the gate (#134,
  #135). The tier rule itself is written nine times (4.13).
- **A comment is not a guard.** A mirror comment can name a test that does not
  exist or claim a byte identity that does not hold (#138).
- **Mirrored cases are not mirrored constants.** Several TS tests copy the
  Python test cases (e.g. `injectProjectFilter.test.ts` mirrors
  `tests/test_tenant_filter_muted.py`) instead of reading the Python constant, so
  both suites stay green while the two constants differ.
- **The path audit reads prose, not fences.** `drift-audit.sh --docs` does not
  see paths inside code fences (the file trees in the subsystem docs), bare file names
  (`HydraSection.tsx`) or shorthand (`sections/index.ts`); the 2026-11-19
  audit found dead paths there (#106, #119).
- **Structure, not truth.** As `README.SETTINGS_REGISTRY.md` says: no test knows
  whether a `meaning`, a bound or a prose sentence is *true*.

---

## 4. Catalogue by area

### 4.1 Agent tools: the tool registry and its satellites

**Source of truth:** `TOOL_REGISTRY` in `agentic/prompts/tool_registry.py`
(58 entries; dict order is prompt priority) plus `tradecraft_lookup`, `tradecraft_search` and `tradecraft_ask` (per-run
overlay) plus tools injected from MCP manifests at runtime.

| Dependent | Where | Guard | Fails how |
|---|---|---|---|
| Default phase map (28 tools) | `TOOL_PHASE_MAP` `agentic/project_settings.py:297` | PART (phase-gating tests) | A tool missing from the map is **denied in every phase** (`is_tool_allowed_in_phase` returns False for an unmapped tool) |
| Same map as a Prisma JSON default | `agentToolPhaseMap @default(...)` `webapp/prisma/schema.prisma:1481` | TEST (`agentic/tests/test_prisma_default_parity.py` compares every `AGENT_SETTING_COLUMNS` entry through `registry.json`, which `registry.prisma.test.ts` keeps equal to the schema) | Matches Python (28 = 28, identical phases). **Frozen copy:** see below |
| UI tool matrix | inline array `ToolMatrixSection.tsx:284` | NONE | Matches today (28 ids). The `⚠` label is a hand marker on two tools, unrelated to `DANGEROUS_TOOLS` |
| Which tool needs which API key (6 tools), 4 copies | `TOOL_KEY_INFO` + `fetchKeyStatus` (`ToolMatrixSection.tsx:50,181-186`), `API_KEY_INFO` (`AIAssistantDrawer/hooks/useApiKeyModal.ts:6-13`; `fetchApiKeyStatus` now derives from it), `TOOL_KEY_LABEL` (`ToolExecutionCard.tsx:19-26`), hint text in `app/settings/page.tsx:1270-1319` and the URLScan entry at `:1354` | NONE (the settings page's URLScan badges and hint: `page.urlscanKey.test.tsx`) | Agree today |
| RoE forbidden-tool vocabulary | closed vocabulary `roeForbiddenTools` in `recon_settings/registry.yaml` | TEST (`test_forbidden_tool_vocabulary.py`) | A tool not in it is the one an engagement cannot forbid |
| RoE enforcement | `roe_gate.check_tool_call` (`agentic/orchestrator_helpers/roe_gate.py`), asked by the single-tool node, the plan wave and every fireteam member | TEST (`agentic/tests/test_roe_gate.py`) | A new executor path must ask it; the test fails a module that calls `tool_executor.execute` without it |
| RoE category -> tools | `CATEGORY_TOOL_MAP` (`roe_gate.py`) | TEST (keys: `test_forbidden_tool_vocabulary.py`; members are registry keys: `test_roe_gate.py`) | A new tool in a forbidden class must be added to its category |
| Recon-budget discovery tools | `RECON_DISCOVERY_TOOLS` (`roe_gate.py`), a hand list: no registry field marks a discovery tool | PART (`test_roe_gate.py`: every name is a registry key) | A new discovery tool left out is not budgeted |
| Dangerous tools (confirmation gate) | `DANGEROUS_TOOLS` `agentic/project_settings.py:51`; the TS copy `DANGEROUS_AGENT_TOOLS` (`webapp/src/lib/authz/settingsRisk.ts:238`) | PART (`test_tool_confirmation.py:181-194` pins the 19 by equality); TEST for the TS copy (`settingsRisk.test.ts` reads the Python set; skips in a webapp-only tree) | A new traffic-emitting tool left out runs **without confirmation** |
| Fireteam mutex groups | `TOOL_MUTEX_GROUPS` (`agentic/project_settings.py:82`), read by `_validate_mutex_groups` (`fireteam_deploy_node.py`) | TEST (`agentic/tests/test_fireteam_mutex_groups.py`) | `state.py:574` is the LLM-filled `tools` field the check reads, not a stored list |
| Reserved names for user MCP tools (TS) | `BUILTIN_RESERVED_TOOL_NAMES` `webapp/src/lib/mcp/schema.ts:26` | TEST (`agentic/tests/test_reserved_tool_names_parity.py`, both ways) | A new system MCP tool must be added to the TS list too; the parity test fails until it is |
| System server ids and ports, 5 copies | `SYSTEM_SERVER_IDS` (`agentic/mcp_registry.py:34`, `webapp/src/lib/mcp/schema.ts`), `_build_system_mcp_servers` (`agentic/tools.py:290`), `SERVERS` (`mcp/servers/run_servers.py:56`), the smoke-test module list (`mcp/kali-sandbox/Dockerfile:543`) | NONE | Agree today (5). The Kali entrypoint also starts `tunnel_manager.py` and `terminal_server.py` (`mcp/kali-sandbox/entrypoint.sh:14,83`), which the build smoke step never imports, so a broken one dies in the background |
| Names the Kali MCP servers expose | `SYSTEM_MCP_TOOL_NAMES` `agentic/tools.py:365` | PART (one direction) | Its comment records the failure: `execute_osv_scanner` was missing, so every call returned "Tool not found". Matches the 23 server tools today |
| CLIs the agent is told exist in Kali | the `kali_shell` description, skill prompts, `mcp/servers/proxy_brain_manual.md` | NONE (the Kali build smoke-tests only MCP imports and HTTP/2); every name was checked against the built image on 2026-10-25 | The agent runs a command that is not installed; a Kali rolling update can drop a package |
| Capture-routed HTTP tools | `_CAPTURE_ROUTED_TOOLS` `agentic/tools.py:128` | PART (per-tool integration tests) | 8 of the 9 server tools that take `_redamon_ctx`; `proxy_brain` is left out on purpose and gets its tag on its own branch. A new HTTP tool left out bypasses the capture proxy |
| Metasploit tools stamped with their owner | `_MSF_CONSOLE_TOOLS` (`agentic/tools.py:138`) <-> the `metasploit_server.py` tools that take `_redamon_owner` <-> the msf group in `TOOL_MUTEX_GROUPS` | PART (`test_ghsa_w454_msf_owner_stamp.py`, per tool) | Agree today; a new console tool left out runs unstamped |
| Per-tool deadlines | `TOOL_DEADLINES_S` `agentic/tools.py:2195` (31 entries) | PART (`test_tool_deadline.py:89` parses the servers' timeouts) | An unknown tool gets `TOOL_DEADLINE_DEFAULT_S = 1860` s (`:2237`), so a lost answer waits 31 minutes; `execute_guarddog` and `msf_restart` have no entry |
| Output offload policy | `OFFLOAD_POLICY` `agentic/tool_offload_policy.py:15` | NONE | An unlisted tool gets `"auto"`, which still offloads anything over 20,000 chars: low risk |
| Per-tool stealth rules | `agentic/prompts/stealth_rules.py:32-190`; the Tradecraft section is injected per run (`overlay.py`) | PART (some per-tool tests; `test_tradecraft_library_now_prompt.py` for the Tradecraft section) | No section for `shodan`, `google_dork`, `msf_restart`, and no fallback rule |
| Replay and browser phase gates | `/traffic/replay` (`agentic/api.py:5317`, route `:5300`) and `/traffic/browser` (`:5435`, route `:5418`) hard-code exploitation phases, a frozen copy of the retired `proxy_replay`/`proxy_fuzz` entries | NONE | The stored `TOOL_PHASE_MAP` for `proxy_brain` (all three phases) is never consulted. The inbound MCP Kali surface (`/kali/exec`, `kaliTools.ts`) skips phase checks by design |
| The chat session id in the tool context | `set_tenant_context(tenant, project, session_id)` in every node under `orchestrator_helpers/nodes/` (single tool, plan wave, fireteam deploy, fireteam member, think); `_msf_console_owner`, `_build_run_credential` and `_build_redamon_ctx` (`tools.py`) fall back to `current_log_session_id` | TEST (`agentic/tests/test_tool_call_session_id.py`: every call passes a non-literal session id, the scan finds every executor node, and the plan and member waves see it) | A new executor node that sets the context without it signs tags with no session (fixed 2026-11-19, #89) |
| Tradecraft tool set (3 names), 11 copies | `tool_proxies.py:15`, `agent_tools.py`, `overlay.py`, `TRADECRAFT_COMPANION_TOOLS` and the phase-map key (`project_settings.py:46`), `mcp_registry.py` `_builtin_tool_names`, `schema.ts`, `TOOL_DEADLINES_S` and the dispatch tuple (`tools.py`), `tool_offload_policy.py`, `tool_registry.py`, `TOOL_ROW_NOTES` (`ToolMatrixSection.tsx:46`) | PART (`test_tradecraft_search_tool.py`, a literal set; the reserved-name parity; per-name offload asserts); NONE for the deadlines and the dispatch tuple | Agree today. A fourth tool missed in the dispatch tuple or the deadlines takes the generic path and the 1860 s wait. A forbidden `tradecraft_lookup` forbids its companions through `companion_tools_by_parent` (`roe_gate.py`) |
| Prompts naming tools | `agentic/prompts/*.py`, `agentic/skills/**/*.md`, `agentic/community-skills/*.md`, `proxy_brain_manual.md` | PART for community skills (`test_community_skills.py` checks `execute_*`/`query_*` names against its hand list `_REAL_AGENT_TOOLS`, 23 names, which lacks `execute_osv_scanner` and `execute_guarddog`); NONE elsewhere (`toolNameDrift.test.ts` covers only the inbound MCP surface) | The agent is told to call a renamed tool |
| Drawer example prompts | `AIAssistantDrawer/suggestionData.ts` | PART (5 skill tests assert their group id; `suggestionData.routeExposure.test.ts`) | Suggestions name a removed tool |
| API keys the executor injects per tool | `execute_wpscan`, `execute_gau`, `cve_intel` (`agentic/tools.py:2792-2814`) read `get_setting('USER_SETTINGS')` and setter fields; every other key path reads `run_user_settings()` / `run_key_rotator()` (`tools.py:1139-1160`) | NONE | Split path (#125) |
| proxy_brain manual sections, 4 copies | the 21 `## ` headings of `mcp/servers/proxy_brain_manual.md` and its own index (`:137-161`), parsed by `_manual_sections` (`mcp/servers/redamon.py:679`); the lists in `tool_registry.py:63-64`, the MCP docstring (`network_recon_server.py:689-690`), `AI-Agent-Guide.md:1000` | NONE | Stale today (#139) |
| Defaults and caps quoted in tool descriptions | `tool_registry.py` fs and job tools (`fs_read` 2,000 lines, `fs_read_many` 200,000 chars, `fs_grep` 50, `fs_find` 200, `fs_tree` 3 levels / 500, `fs_glob` 500, undo 20, job wait 30 s) <-> `workspace_fs.py`, `job_runner.py`; the MCP descriptions in `server.ts` (200 presets, 2,500, 8 chars, 1,000, 300 s) <-> `MAX_USER_PRESETS`, `CAP_BUNDLE`, `min_quote_length`, `MAX_REVIEW_BUDGET`, the `kali_shell` timeout | NONE (`apiReference.test.ts` keeps only the wiki equal to the text) | Agree today; the model plans around a stale limit |

**Frozen copy, the big one.** `fetch_agent_settings` *replaces* the stored
`agentToolPhaseMap` rather than merging it with the default (its
`TOOL_PHASE_MAP` entry in `AGENT_SETTING_COLUMNS`, `agentic/project_settings.py`). A new tool therefore stays **disabled on
every existing project** until its JSON is backfilled (past backfills:
`webapp/prisma/migrations/20260219120000_expand_tool_phase_gating/`,
`20260221140000_execute_code_informational/`, and for the Tradecraft key the
startup script `webapp/scripts/backfill-tradecraft-phases.mjs`, run from the
`webapp/Dockerfile` entrypoint and `docker-compose.dev.yml`, its `NEW_PHASES`
pinned to the Prisma default by `backfill-tradecraft-phases.test.ts`).
`GRAPH_COMPANION_TOOLS` and `TRADECRAFT_COMPANION_TOOLS` exist precisely to
avoid adding keys: the companions inherit their parent's phase gate
(`is_tool_allowed_in_phase`) and its RoE entry (`companion_tools_by_parent` in
`roe_gate.py` reads both constants).

### 4.2 Built-in attack skills and community skills

**Source of truth:** `KNOWN_ATTACK_PATHS` in `agentic/state.py` (14 skills).
The ten layers are listed in `skills/builtin-agent-skill/SKILL.md`. Every layer
names all 14, and the Prisma default's values equal Python's
(`agentic/tests/test_prisma_default_parity.py`).

| Layer | Where | Guard |
|---|---|---|
| Classifier | `_BUILTIN_SKILL_MAP` (`classification.py:137`) and `_CLASSIFICATION_INSTRUCTIONS` (`:155`), 14 each | PART (see below) |
| Settings default | `ATTACK_SKILL_CONFIG.builtIn` `agentic/project_settings.py:420` | PART |
| Prisma default (**frozen copy**) | `attackSkillConfig @default(...)` `schema.prisma:1666` | TEST for the values (`test_prisma_default_parity.py`); existing rows need a backfill, same as 4.1 (`get_enabled_builtin_skills` reads only stored keys) |
| Form default | `DEFAULT_CONFIG` `AttackSkillsSection.tsx:172-190` | PART (`AttackSkillsSection.default.test.tsx` renders two toggles and asserts 5 Prisma values as literals; all 14 agree today) |
| UI toggle + badge | `AttackSkillsSection.tsx`, `AIAssistantDrawer/phaseConfig.ts` | PART |
| Drawer tooltip | `BUILT_IN_SKILLS` in `webapp/src/app/api/users/[id]/attack-skills/available/route.ts` | PART |
| Example prompts | `AIAssistantDrawer/suggestionData.ts` (7 skills have their own group id) | PART |
| Unclassified routing table | `agentic/prompts/unclassified_prompts.py:32-47` | TEST (`agentic/tests/test_unclassified_routing_table.py`); the classifier text in `classification.py` is prose |
| Plugin-overridable parts | `agentic/prompts/skill_parts.py` `_SPECS` (58 parts over the 14 skills); the webapp fetches them at runtime from `GET /plugins/skill-parts` (`skillPartsRegistry.ts`, not a copy) | TEST (`test_skill_parts_registry.py:143-145`, `skillDisplayName.test.ts`) |
| Tradecraft skill topics | `webapp/src/lib/tradecraft/vocab.json` (copied to `agentic/tradecraft/vocab.json` by `gen-tradecraft-spec.mjs`) | TEST (`vocab.test.ts` reads `KNOWN_ATTACK_PATHS`, count-locked at 14) |
| Golden prompt hashes | `agentic/tests/fixtures/skill_workflow_golden.json` | GEN-like: fails until re-recorded with `record_skill_golden.py` |
| Wiki | `redamon.wiki/Agent-Skills.md` and per-skill pages | links and anchors: TEST (`tests/test_docs_not_stale.py` P21) |

"Per-skill tests" vary: crypto_attack, deserialization, http_request_smuggling,
path_traversal and xxe read every webapp layer; rce reads some; sqli, ssrf and
xss are Python-only; cve_exploit, brute_force, phishing, dos and access_control
have no per-skill test file. None of these files runs in the unit gate: a
`_skill.py` name is the integration tier (#134), so for the gate the PART guards
above that rest on them are NONE.

User skills: the enabled-skill limit is 20 in both `MAX_ENABLED_USER_SKILLS`
(`agentic/project_settings.py:1325`) and `MAX_ENABLED_USER_SKILLS_PER_PROJECT`
(`webapp/src/lib/userSkills.ts:14`); each side pins its own, nothing compares
them. Community skills: 18 files in `agentic/community-skills/`, indexed by hand
in its `README.md` (complete). Knowledge skills: 46 files under
`agentic/skills/`, found by directory scan, no index; the knowledge-base ingest
reads them through a hand list of folders instead (4.17, #131). Both are **prose
naming tools and wordlist paths**.

### 4.3 LLM providers and model ids

| Fact | Copies | Guard | Fails how |
|---|---|---|---|
| Default model id `claude-opus-4-6` | 21 hand-edited occurrences in 18 files (`webapp/prisma/schema.prisma`, `agentic/project_settings.py`, `agentic/api.py` (the `DEFAULT_OUT_OF_RUN_MODEL` fallback), `llm_setup.py`, `recon/project_settings.py`, `recon/helpers/security_checks.py`, `recon/main_recon_modules/{resource_enum,subdomain_takeover,vuln_scan}.py`, `recon/partial_recon_modules/{vulnerability_scanning,web_crawling}.py`, `webapp/src/app/api/projects/route.ts`, `ModelPicker.tsx`, `ModelPickerModal.tsx`, `recon-preset-schema.ts`, `registry.yaml`, `SCHEMA_DEFAULT_AGENT_MODEL` (`webapp/src/lib/agentInTheLoop.ts`, the import route's loop replacement), `MODEL_COLUMNS` resets (`webapp/src/lib/authz/ownershipTransfer.ts`)); 29 in 22 counting the generated JSON, a migration and a test helper, plus test vectors and the `tests/fixtures/rbac_upgrade/*.sql` fixtures | PART: Prisma == agent and recon Python (`test_prisma_default_parity.py` x2), the transfer resets == Prisma (`ownershipTransfer.test.ts`); the other copies NONE | A retired id breaks fresh installs; stored rows keep the old id |
| Model ids pinned for the key test | `gpt-4o-mini`, `claude-opus-5`, `openrouter/openai/gpt-4o-mini` (`agentic/api.py:2514-2521`) | NONE | The "test this key" button fails when one is retired |
| Models that reject `temperature` | `ANTHROPIC_NO_TEMPERATURE_MODELS` / `_PREFIXES`, `OPENAI_NO_TEMPERATURE_PREFIXES`, `OPENAI_TEMPERATURE_EXCEPTIONS` (`llm_setup.py:29-87`); a TS copy for preset generation (`webapp/src/lib/llmTemperature.ts`). `_anthropic_sdk_refuses_sampling` (`llm_setup.py:56-69`) is Python-only by design: the requests RedAmon builds itself pin `anthropic-version: 2023-06-01` (`presets/generate/route.ts:274`, `apiUsage/providers/llm/validity.ts:149`, `model_providers.py:88`), while the agent goes through the `anthropic` SDK, which no requirements file pins (it comes with `langchain-anthropic>=0.3.0`) | TEST (`llmTemperature.test.ts` reads the Python constants; shared vectors); runtime self-heal in `llm_retry.py` and one retry in the preset route | |
| Fallback model catalogues | `_XAI_`, `_MISTRAL_`, `_DEEPSEEK_FALLBACK_MODELS` (`model_providers.py:160-274`) | NONE | The picker offers retired models during a provider outage |
| Provider API hosts, 5 copies | `llm_setup.py`, `model_providers.py`, `defaultBaseUrlFor` (`presets/generate/route.ts:111`), `webapp/src/lib/apiUsage/providers/llm/*.ts`, `llmProviderPresets.ts` (21 URLs) | NONE | Agree today |
| Model-prefix routing, 3 copies | `parse_model_provider` (`llm_setup.py`), `resolveModel` (`presets/generate/route.ts:69-94`; `UNSUPPORTED_PREFIXES` at `:60` refuses `loop/`, `instance/` and `openai_compat/`, tested in `route.instance.test.ts`), `formatModelDisplay` (`phaseConfig.ts:15`, display only) | PART | A model chat accepts is misrouted by preset generation |
| Provider-type facts | `NON_CHAT_PROVIDER_TYPES` (`agentic/llm_builder.py:39`, `webapp/src/lib/llmProviderKinds.ts`); `CUSTOM_PROVIDER_TYPES` (`llm_builder.py:42`) names `bedrock_custom`, `ollama_local`, which no webapp code creates | NONE | A new non-chat provider counted as a chat LLM on one side |
| Instance provider identity: row type `instance`, model prefix `instance/`, the keyed kinds | `INSTANCE_ROW_TYPE`, `INSTANCE_MODEL_PREFIX`, `_INSTANCE_KEYED_KINDS` (`agentic/llm_builder.py:51-57`) <-> `webapp/src/lib/instanceProviders/rows.ts` | TEST (`instanceProviders.test.ts` reads the Python constants) | |
| Agent in the Loop identity: prefix `loop/`, id `loop/mcp`, label, the switch's accepted values, step `contractVersion` | `agentic/agent_in_the_loop/__init__.py` <-> `webapp/src/lib/agentInTheLoop.ts`, `LOOP_CONTRACT_VERSION` (`webapp/src/lib/mcp/loopSkill.ts`) | TEST (`agentInTheLoop.twins.test.ts` reads the Python constants) | |
| Who refuses a `loop/` model outside a chat run | `refuse_loop_model` in `agentic/llm_builder.py` and the `api.py` builders; `excludeLoop` / `projectModelProblem` / `loopModelRefusal` in the webapp | PART (`test_loop_out_of_session.py`, `agentInTheLoop.refusals.test.ts`); a NEW builder is unguarded (the `agent-in-the-loop` skill) | A builder that forgets the check waits for a driver that never comes, or routes `loop/mcp` to OpenAI after a revert |
| Feature-model ids | `FEATURE_IDS` (`agentic/feature_models.py:16`) <-> `webapp/src/lib/llmFeatures.ts`, 10 each | TEST (`test_feature_models.py`) | |
| Local judge model | `qwen2.5:7b` in `local_llm_manager.py:52`, `scanners/ai_attack_surface_scan/adapters/*.py`, `docker-compose.yml:721`; the UI reads it from the orchestrator (`/local-llm/status` via `/api/ai-attack-surface/[projectId]/judge-model`) | NONE for the scanner copies | |
| Jev model pin `jev-1.13.0` / `typesafe/jev-1.13` | `JEV_MODEL`, `OPENROUTER_MODEL` and two regexes that hard-code `1.13` again (`agentic/jev_client.py:30-43`) <-> `JEV_MODEL`, `JEV_OPENROUTER_MODEL` (`webapp/src/lib/llmProviderKinds.ts:28-30`: the API-usage key probe, and each Jev row's stored `modelIdentifier`); "measured live on jev-1.13.0" thresholds (`jev_hooks.py`, `route_exposure_assess.py:25`); 12 `registry.yaml` meanings and 9 catalog lines | NONE | A bump on one side: the key probe validates a model the hooks never call, stored rows keep the old label, and the recon thresholds were calibrated on the old one |
| The 11 built-in providers, enumerated by hand per LLM call site | `_BUILTIN_PROVIDERS` (`agentic/llm_builder.py:31`); hand chains in `agentic/api.py` (the out-of-run builders and the key test), `cypherfix_triage/orchestrator.py`, `cypherfix_codefix/orchestrator.py`, `llm_setup.py`, `model_providers.py`; `isKeyBased` (`LlmProviderForm.tsx`, 10, Bedrock left out on purpose) | NONE (only the `instanceProviders/rows.ts` copy is TEST) | A 12th provider missed at one site fails only at that endpoint. Agree today |
| Knowledge-base embedder and reranker ids | 4.17 | PART | |

### 4.4 Recon settings registry and the default cascade

The registry is the best-guarded area (section 3.1). What it does *not*
close:

**The default cascade.** One setting's default lives in up to seven places:

1. `@default()` in `webapp/prisma/schema.prisma`: what a row gets when the
   creating path does not set the column (MCP `create_project`, import, the form
   when `/defaults` is down)
2. `DEFAULT_SETTINGS` in `recon/project_settings.py`
3. `DEFAULT_AGENT_SETTINGS` in `agentic/project_settings.py` (plus the scanner
   copies: `scanners/{gvm_scan,github_secret_hunt,supply_chain_scan}/project_settings.py`,
   `agentic/cypherfix_triage/project_settings.py`)
4. `/api/projects/defaults` = recon `/defaults` + agent `/defaults`
   (`RUNTIME_ONLY_KEYS` from the registry plus five column keys,
   `recon_orchestrator/api.py:1160-1165`, and `strip_engagement_limits` at
   `:1213`; the agent half serves `AGENT_SETTING_COLUMNS`, real columns only;
   the GVM and GitHub merges add non-column keys the POST strips): what the
   **form starts from** and what a **preset apply resets to**
5. `MINIMAL_DEFAULTS` (`ProjectForm/formDefaults.ts`, which also copies the 7
   hostname-policy defaults at `:18-24`) and per-section fallbacks: every
   numeric display or cleared-field fallback in `ProjectForm/sections/*.tsx`
   reads the registry default through `numericDefault(key)` (`formDefaults.ts`),
   and `sections/clearedFallbacks.test.ts` fails a literal that differs from it
   (15 differed until 2026-11-19, #93). Separate and open: about 20 `|| N`
   fallbacks swallow a typed 0 on fields whose minimum is 0 (e.g.
   `httpxRetries`, `nucleiRetries`, `masscanWait`, `roeDataRetentionDays`; #130)
6. every **existing row**: a changed default needs a backfill. A **new** column
   is the reverse: `db push` writes its default into every existing row, so a
   default meant for new projects only needs a keep-off script before the push
   (one exists, `webapp/scripts/add-js-recon-trufflehog-column.mjs`).
   `ipAttributionEnabled`, default true and `traffic: active` since 2026-10-26,
   reached every existing project without one; its intent is unrecorded
7. the literal fallbacks of `settings.get('KEY', literal)` in `recon/` and
   `recon_orchestrator/`: 98 of 1,001 differ from `DEFAULT_SETTINGS` (e.g.
   `DNS_MAX_WORKERS` 50 in `recon/main.py`, `MASSCAN_ENABLED` True against a
   default of False, `KATANA_MAX_URLS` 300 against 300,000). Inert while
   settings come from `fetch_project_settings`, which supplies every key; live
   for any caller that passes a partial dict

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
| RoE parse prompt (generated) | `recon_settings/roe_parse_prompt.py`; the agent bakes its own copy and the webapp compares (`webapp/src/app/api/roe/parse/route.ts:185`) | GEN (`build.py --check` in the gate) + runtime compare |
| `ROE_PARSE_MAX_CHARS` | `agentic/api.py:346` <-> `MAX_MODEL_CHARS` `webapp/src/lib/roe/limits.ts:29` | TEST (`test_roe_parse_timeout.py:93-99`) |
| Golden master baselines | `recon/tests/fixtures/golden_settings/*.json` (18) | regenerate only on purpose; every diff line is a value a scan runs with |
| Hand-written settings narrative | `redamon.wiki/Project-Settings-Reference.md` | count only (`settingsReference.test.ts`) |
| Scope-group fact | `GRAPH_DOMAIN_IS_ORG` in `webapp/src/lib/scopeGroups.ts` <-> `recon/partial_recon.py:329` | PART (`scopeGroups.test.ts:129` asserts only the TS value) |
| Hostname-policy defaults, unguarded copies | `MINIMAL_DEFAULTS` (`formDefaults.ts:18-24`), the `agentic/project_settings.py` fallbacks (`:768-774`), beside the guarded `IP_HOSTNAME_DEFAULTS` (section 3.2) | NONE for the form copy; PART for the agent's (`test_project_settings_scope_groups.py` asserts literals) |
| The URLScan read cap (10,000 with a key, 1,000 without) | `KEYED_MAX_RESULTS` / `KEYLESS_MAX_RESULTS` (`recon/main_recon_modules/urlscan_enrich.py:37-38`), the field's `meaning` in `registry.yaml`, the hint in `UrlscanSection.tsx:125-126`, `recon-preset-schema.ts` | NONE (agree today) |

### 4.5 Recon presets, and every other kind of preset

**Built-in recon presets: 26** files in `webapp/src/lib/recon-presets/presets/`,
listed by hand in `webapp/src/lib/recon-presets/index.ts` (import + array).

| Dependency | Guard | Fails how |
|---|---|---|
| Parameter **names** (`Partial<ProjectFormData>`) | `tsc` (type-check) | A renamed column fails the build: good |
| Parameter **semantics** when a tool is added | TEST (`traffic-decisions.test.ts`: every default-on active toggle is decided per preset, 757 of the 831 flagged pairs still pending a decision; `vhost-sni.test.ts` derives its list; `tlsxPresetGuard.test.ts`) | Applying a preset resets every field it does not name to its default (`applyPresetSettings`, `defaultFor`), so a tool whose default is ON runs under every preset that does not mention it |
| The count | `recon-presets.test.ts` "registry contains exactly 26 presets" | intentional tripwire |
| Icons `webapp/public/preset-*.svg` | PART (`recon-presets.test.ts:3534` checks the path pattern, not that the file exists; all 26 exist) | |
| `fullDescription` / `shortDescription` prose | "required section headers" + "no em dashes" only | Description and parameters disagree; counts such as "all 10 OSINT providers" (`osint-investigator.ts:8`, correct today) age |
| Docs | `redamon.wiki/Recon-Presets.md` (reference table lists all 26), counts across the wiki | digit counts: TEST (`tests/test_docs_not_stale.py` P21); the word counts at `Recon-Presets.md:79-96` ("Six", "Eleven", "Seven", "eighteen" presets, true today) and the IP-preset prose at `:40` (vs `IP_PRESETS_RELYING_ON_HOSTNAMES`, `recon-presets/targeting.ts:19`, ids checked by `presetTools.test.ts`) are NONE |

**Measured: tools most presets never decide.** 74 `traffic: active` `*Enabled`
fields exist. "Unnamed" is how many of the 26 presets never name the field; on
apply they get the default.

| Field | Default | Unnamed |
|---|---|---|
| 9 `aiSurfaceRecon*` probe toggles, `jsReconAiSdkDetectionEnabled`, `masscanAiPortCatalogEnabled`, `nmapAiVersionRegexEnabled` | true | 25 (`aiSurfaceReconCacheEnabled` is retired, not a preset field, never applied) |
| `takeoverCertValidationEnabled` | true (inert while takeover is off) | 26 |
| `baddnsEnabled` | false | 25 |
| `routeExposureEnabled` | false | 21 |
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
| arjun, ffuf, graphqlSecurity, hakrawler, ipAttribution (true), jsRecon, jsReconTrufflehog (true), jsluice, katana, kiterunner, masscan, naabu, nmap, nuclei | | 0 |
| 27 agent and attack toggles (`hydraEnabled`, `fireteamEnabled`, `agentGuardrailEnabled`, the ssrf, rce, path-traversal and deserialization families, `captureProxyEnabled`, tunnel, Kali install, LATS) | 16 default true | 26: every recon preset apply resets them |

Passive, all default false: `supplyChainReconEnabled` and
`supplyChainReconDeepAnalysisEnabled` 18 unnamed, `serializedScanEnabled` 20,
`trufflehogEnabled`, `supplyChainDeepAnalysisEnabled`,
`supplyChainOrgDeepAnalysisEnabled` and `supplyChainTyposquatEnabled` 26.
Flipping any default to `true` silently changes what up to 26 presets do.

**AI-generated presets.** `webapp/src/lib/recon-preset-schema.ts` holds a
hand-written zod schema of the 528 fields a generated preset may carry (unknown
keys are **stripped**) and `RECON_PARAMETER_CATALOG`, the prose the generating
model reads.

- Guarded: every schema key is a real, MCP-settable column with the right shape,
  and schema <-> catalog both directions (`recon-preset-schema.test.ts`).
- Not guarded: a **new** column does not have to be added. The schema covers 528
  of the 682 preset fields; the 154 missing are mostly agent and attack fields
  (agent 44, ssrf 11, fireteam, hydra and path traversal 8 each), 15 trufflehog
  fields, and the gau/kiterunner method detection. Of the 50 preset fields added
  since 2026-10-25, 3 are missing (`pathTraversalGitReconstructEnabled`,
  `pathTraversalValidateSecretsEnabled`, `rceHeapdumpAnalysisEnabled`).

**Preset apply rules that are hand lists**

| List | Where | Risk |
|---|---|---|
| `PRESET_EXCLUDED_FIELDS` | `webapp/src/lib/project-preset-utils.ts:58` | Derived from registry classes (now including `validator: provider_reference`): good. `UNCLASSIFIED_EXCLUDED_FIELDS` (`name`, `description`, `vhostSniCustomWordlist`, `supplyChainInputMode`) is a hand list |
| `KEPT_WHEN_ABSENT` | `project-preset-utils.ts:94` | Complete today (12 of 12 Jev fields + 2 models). It duplicates `JEV_ENGINE_FIELDS` (`webapp/src/lib/reconSettings/jevEngine.ts:9`, a length tripwire only) and `JEV_HOOK_LABEL`; none is compared with the registry. A Jev field missing from the first is switched off by every preset apply; missing from the second, it skips the Jev-token check. PART: the literal test in `project-preset-utils.test.ts` names 5 of the 8 Jev-only flags |
| The Jev hook set beyond those three | `AI_HOOKS` (`webapp/src/lib/mcp/engagementTools.ts:655`), the Jev-only union and cards in `TargetSection.tsx` (8), the prose in `mcp/catalogTools.ts` (8), `JEV_ONLY_COLUMNS` (`recon/tests/test_jev_settings_mapping.py`, 8) | PART (`engagementTools.test.ts` repeats the list as literals); agree today, none compared with the registry |

**Other presets**

| Preset kind | Where | Stale-prone because |
|---|---|---|
| MCP server templates (33) | `webapp/src/lib/mcp/presets.ts` | third-party URLs, auth rules and quotas ("verified live as of writing"), per-server tool counts in the blurbs; about 20 stdio templates start an unversioned `npx -y` / `uvx` package, two of them `@latest` (`presets.ts:381`, `:724`), in the agent at every server start |
| Mute-rule presets | `webapp/src/lib/nodeFilters/presets.ts`, `/api/mute-rule-presets` | name finding kinds from the node-filter catalog |
| Graph-view presets | `webapp/src/app/graph/components/NodeFilters/Preset*.tsx` | stored filter shapes |
| User-saved project presets | `UserProjectPreset.settings` (Postgres JSON) | snapshot of every preset column at save time, the whole `agentToolPhaseMap` and `attackSkillConfig` included, which apply replaces (#126); see 4.15 |

### 4.6 Recon pipeline mechanics

| Fact | Copies | Guard | Fails how |
|---|---|---|---|
| Partial-recon tool ids (34) | dispatch `recon/partial_recon.py:508-577`; `PARTIAL_TOOL_SWITCHES` (`partial_recon.py:135`); `SECTION_INPUT_MAP` (`nodeMapping.ts`, + 4 non-partial keys); `TOOL_QUERIES` (graph-inputs `[toolId]/route.ts:212`); `PARTIAL_RECON_SUPPORTED_TOOLS` (`recon-types.ts:233`); `workflowDefinition.ts` (no `Uncover` node on purpose: it runs from `ProjectForm.tsx`); `PartialReconModal.tsx` `TOOL_DESCRIPTIONS` | PART (per-tool wiring tests; `test_partial_stealth_refusal.py` for the switches) | The dispatch, the switches, `SECTION_INPUT_MAP`, `TOOL_QUERIES` and the supported set agree at 34; the modal describes every partial-recon tool (`PartialReconModal.runButton.test.tsx`) |
| Tools refused, or limited to hostnames, in IP mode | `IP_MODE_REFUSED_TOOLS`, `IP_MODE_NAME_ONLY_TOOLS` (`recon/partial_recon_modules/helpers.py:415-430`) <-> `webapp/src/lib/partialReconScope.ts:245-261` | NONE across the two (`partialReconScope.test.ts` iterates only the TS list) | Agree today (3 refused, 3 hostname-only) |
| Graph-input queries | `TOOL_QUERIES` in the graph-inputs route (the live implementation since the Python one moved here) | TEST (`recon/tests/test_graph_writes_documented.py` reads webapp Cypher) | |
| Phase strings | `GVM_PHASES`, `GITHUB_HUNT_PHASES`, `TRUFFLEHOG_PHASES` (`recon-types.ts`); `*_PHASE_PATTERNS` (`container_manager.py`); `*State.total_phases` (`models.py`) | TEST (`recon-types.phases.test.ts`, `test_phase_totals.py`) | Agree today: recon has 6 (`RECON_TOTAL_PHASES` in `recon-types.ts`) |
| Execution groups and their order | `recon/main.py` (GROUP 1..6; Phase A at `:2812-2831` registers 7 tools; GROUP 5's pool in `resource_enum.py` runs Katana, Hakrawler, GAU and ParamSpider, then Kiterunner, jsluice, FFuf, ZAP, Arjun and OpenAPI in turn) | `recon/tests` per group | The docs restate it by hand (`Recon-Pipeline-Workflow.md`, `Running-Reconnaissance.md`, `README.RECON.md`, `Origin-Discovery.md`), with nothing comparing them; they agree since 2026-11-19 (#108, #109); a renamed heading breaks wiki anchors until the gate's docs test runs |
| Per-tool explanations in the UI | `WorkflowView/inputLogicTooltips.tsx`, `PartialReconModal.tsx`; `workflowDefinition.ts` traffic badges (6 differ from the registry, 5 of them "both", which the registry cannot express); the preset modal's toggle labels, read from the registry by `enabledKeyLabel()` (`GeneratePresetModal.tsx`; `GeneratePresetModal.labels.test.ts` names every `*Enabled` key the preset schema accepts) | NONE | Hand prose on dedup keys, sources, limits |
| Tool image lists, 5 copies | `*_DOCKER_IMAGE` defaults (`recon/project_settings.py`), `IMAGES` (`recon/entrypoint.sh`), `_DEFAULT_ALLOWED_IMAGES` (broker), `remove_redamon_images` (reads `IMAGES`), the registry's `tools.*.image` (15); plus `settings.get(...)` fallbacks in modules. A stop selects tool containers by run label, not by image | TEST (`test_image_parity.py` both ways, `redamon_runtime_images_test.sh`); PART for the registry copy (`registry.tools.test.ts`) | Agree today (15 images); every broker image beyond recon's names its caller (`BROKER_IMAGES_BEYOND_RECON`, 4) |
| Red Zone "network initial access" | `PORT_CATEGORY`, `NET_VULN_TYPES` (`netInitAccess/route.ts`) vs `security_checks.py` | TEST (`recon/tests/test_net_init_access_parity.py`) | `cache_purge_exposed` is excluded on purpose (a cache-DoS finding, not an access vector) |
| Every Red Zone / Insights query | `webapp/src/app/api/analytics/**/route.ts` | PART (route tests with mocked results; `insightsDeclared.test.ts` covers one predicate) | Hard-coded labels, properties and `type` strings |
| AI hook catalogues | `recon/helpers/ai_signal_catalog.py`, port-scan / JS-SDK / AI-surface catalogues | TEST (`test_ai_*_catalog*.py`) | |
| Jev extension catalogue vs recon `EXT_REGEX` | `recon/helpers/ai_planner/ffuf_extensions.py` | TEST (`test_jev_catalog_contract.py`) | |
| Partial-recon setting overrides | `ALLOWED_SETTINGS_OVERRIDES` `recon/partial_recon.py` <-> `recon_orchestrator/batch_scope.py:54`; `PARTIAL_RECON_OVERRIDE_KEYS` in `recon-types.ts` | TEST (`test_partial_recon_multi_root.py:490`, `test_partial_recon_roots.py:165-167`) | |
| Partial-run CIDR bounds (`/24-/32`, `/120-/128`); batch ceiling 50 | `PartialReconModal.tsx:293,298` <-> `batch_scope.py:330`; `MAX_REQUESTED_ROOTS` (`batch_scope.py:61`) <-> `MAX_BATCH_GROUPS` (`webapp/src/lib/domainBatch.ts:41`) | NONE | Agree today |
| Registry tool metadata | `tools.*.partial_recon_module` in `registry.yaml`; `produces` derived by `build.py` from `SECTION_NODE_MAP` (`SECTION_ALIASES` maps the five section names that differ) | `partial_recon_module`: TEST (`test_registry_partial_recon_module.py`); `produces`: GEN (`build.py` refuses a hand-written one) | A tool with no partial-recon section has no `produces` |
| Wiki link per workflow node | `TOOL_WIKI` (`webapp/src/components/ui/WikiInfoButton/wiki-links.ts:31-34`, "Keys mirror the WORKFLOW_TOOLS ids") <-> `WORKFLOW_TOOLS` (`workflowDefinition.ts`) | NONE for coverage (`test_navigator_wiki_index.py` checks only that anchors resolve) | `SerializedScan` has no entry, so its info button opens nothing |
| Partial-run typed-host admission | `admits_partial_host` (`recon/partial_recon_modules/helpers.py:748`, "Mirrors recon_orchestrator/batch_scope.py:admits_partial_host") <-> `batch_scope.py:223` | PART (cases on each side; `scope_groups_contract.json` covers group parsing only) | The recon side strips a trailing dot and reads legacy `prefixes`, the orchestrator's does not; the orchestrator refuses first, so it fails closed |

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
| Relationships read by **webapp** Cypher | `webapp/src/**/*.ts(x)` | TEST (the same test; the legacy `HAS_BASEURL` alias is allowlisted). It reads line by line (a type must sit on the `-[` line), skips `mcp/`, `tooling/`, `services/` and `testing/`, and never counts a dynamic write (`{rel}`, `apoc.create.relationship`) as written; none hides a phantom today | |
| Legacy alias reads | `HAS_BASE_URL\|HAS_BASEURL` in `agentic/cypherfix_triage/fact_queries.py:69,251`, `recon/partial_recon_modules/origin_enrichment.py:59,61`, the graph-inputs route `:342,361,392`, `clusterNodes.ts:43`, and the agent's prompt Cypher `agentic/prompts/base.py:2246` (teaches the old spelling) | intentional until `tooling/scripts/triage_graph_migrate.py` has run everywhere | |
| **The finding-label set (8 labels)** | `MUTEABLE_LABELS` (`graph_db/mixins/recon/triage_mixin.py:47`, the source), `graph_db/node_filters/catalog.py`, `FINDING_LABELS` (`base_mixin.py`), `_FINDING_LABELS` (`agentic/api.py`), `_CONFIRMABLE_LABELS` (`chain_graph_writer.py`), `fact_queries.py`, `FINDING_LABELS` (`webapp/src/lib/triage/actions.ts`), `MUTEABLE_FINDING_LABELS` (`webapp/src/lib/mcp/findingLabels.ts`), `reportData.ts`, and test/tooling copies | TEST (`tests/test_finding_labels_mirrors.py`, 14 copies, plus the three older Python tests) | A new finding label must be added everywhere or it cannot be muted, triaged, confirmed or counted |
| Global reference labels (6 copies) | `GLOBAL_REFERENCE_LABELS` (`graph_db/tenant_filter.py:298`), read by `graph_db/schema.py`; `GLOBAL_LABELS` (`webapp/src/app/api/graph-views/execute/injectProjectFilter.ts`), `graphRestore.ts`, `webapp/src/lib/mcp/graphGuard.ts`, `REFERENCE_KEY_PROPERTY` (`webapp/src/lib/graphReferenceLinks.ts:19`) | TEST (`tests/test_reference_labels_mirrors.py`; the `graphReferenceLinks.ts` labels transitively through `graphReferenceLinks.test.ts`) | Exempting a per-tenant label is a cross-tenant read; the test also fails an exempt label with a per-project key |
| Reference-node natural keys and id formats | `REFERENCE_KEY_PROPERTY` / `REFERENCE_KEY_PATTERN` (`graphReferenceLinks.ts:19-28`) <-> `schema_keys.py` (CVE `id`, MitreData `id`, Capec `capec_id`) and the writers in `vuln_mixin.py` | NONE for the keys and formats | A renamed key or a new id format drops every restored reference link silently |
| Saved-view and agent call gates | `_SAFE_CALL_NAMESPACES` and `find_disallowed_call` (`tenant_filter.py`) <-> `FUNCTION_ALLOWLIST` / `PURE_NAMESPACES` (`injectProjectFilter.ts`); the `NOT_A_CALL` keyword lists on both sides | NONE by design: two policies, each documented in its file as such; the saved-view gate is the stricter (a whole-function allowlist, two `vector.similarity.*` functions, no `db.*`). The keyword lists are kept by hand (the webapp's adds `OFFSET`, `CONTAINS`, `STARTS`, `ENDS`) | Loosening the saved-view gate to match the agent's would widen what a saved view can call |
| `\uXXXX` escape refusal, 3 copies | `_UNICODE_ESCAPE_RE` (`graph_db/tenant_filter.py:1347`), `UNICODE_ESCAPE` (`injectProjectFilter.ts:55`, "the agent's copy of this rule"), `webapp/src/lib/navigator/tools/secretGuard.ts:41` | PART (three separate regression suites) | It closed a confirmed cross-tenant read; a drift on one side reopens it there |
| "Goal reached" ChainFinding types (11) | `GOAL_FINDING_TYPES` (`webapp/src/app/graph/config/colors.ts:121`), the `IN [...]` list in `analytics/attack-chains/route.ts:115`, `reportData.ts:1534`, the comment at `agentic/state.py:388`, the prompt at `agentic/prompts/base.py:1448` (10, without `credential_found`); narrower subsets in `lats.py:639` and the four `_EXPLOIT_OVERLAP` copies (`think_node.py`, `fireteam_member_think_node.py`) | NONE | A new goal type is not drawn green, counted in Insights or put in the report |
| Node colours / sizes | `NODE_COLORS` (`webapp/src/app/graph/config/colors.ts`, lacks `DNSRecord`, `KBChunk`, `UserInput`), `NODE_SIZES` (`sizes.ts`, 30 keys; 16 keyed labels use `Default`) | NONE | New labels render grey and default-sized |
| Labels behind the unseen badges | `ALL_GRAPH_LABELS` (`webapp/src/app/graph/unseen/registry.ts`) | TEST (skips without `graph_db/`) | |
| Write-time props per label | `UPDATED_AT_PROPS` (`RedZoneTables/updatedAt.tsx:54`) and the `coalesce` in `unseen/counts.ts:55` | PART | |
| Finding-key contracts | `cache_mixin.py:15`, `graphql_mixin.py:15`, `osint_mixin.py:119` (`_split_url`, the same result as `http_mixin.py`'s though not the same text; `tests/test_graph_writer_fixes.py` checks two expressions), `tlsx_mixin.py:53` (duplicated from `security_checks.py`), `secret_mixin.py:601` (digest = `scanners/trufflehog_scan/findings.py`) | mostly TEST (the secret one by `tests/test_trufflehog_graph_scoped_clear.py`) | |
| Certificate key derivation; orphan-sweep depth 3 | `deriveCertKey` (`webapp/src/lib/graphRestore.ts:35`, called at `:304`) <-> `build_cert_key` (`graph_db/cert_key.py:17-37`), `base_mixin.py:38` | NONE | A whitespace-only fingerprint keys differently on restore, giving a duplicate Certificate (edge case) |
| Agent's graph prompt | `agentic/prompts/base.py` text-to-cypher rules, `agentic/graph_schema_prompt.py` | the fidelity tests | query guidance prose is hand-written |
| Wiki | `redamon.wiki/Attack-Surface-Graph.md` | node-type counts: TEST (`tests/test_docs_not_stale.py` P21) | |
| Graph export / import / restore | `graphSerialize.ts`, `graphRestore.ts`, `projectExport/`, `api/projects/import/route.ts` | integration tests | a new label must be exported and restored |
| Mixin split snapshot | `tests/fixtures/recon_mixin_snapshot.json` (2026-04-18) | `tests/test_recon_mixin_split.py` | a one-time refactor guard that ages with the mixins |
| One-shot graph migrations | `tooling/scripts/{triage_graph_migrate,dns_finding_rekey,js_secret_rekey,netlas_finding_rekey,cache_deception_rekey,aisr_finding_rekey,vhost_finding_rekey,takeover_finding_rekey,urlscan_backfill,mute_provenance_cleanup,node_filters_rollback}.py` | NONE | written against the schema of their day |
| APOC procedures Neo4j loads | `NEO4J_dbms_security_procedures_{unrestricted,allowlist}` in `docker-compose.yml:69-70` and `graph_db/docker-compose.yml:15-16`, prose in `README.SECURITY_POSTURE.md`; every `apoc.*` caller (`graphRestore.ts`, `graphReferenceLinks.ts`, `agentic/tools.py` through `Neo4jGraph`, lab scripts) | NONE | The four lists agree and every `apoc.*` call is on them today; a call outside them fails at runtime (the js_secret_lab validator now hashes in Python) |

### 4.8 Inbound MCP server and API docs

Well guarded: `MCP-API-Reference.md` is rendered from the live `tools/list` (51
tools with both switches on, 18 scopes), the onboarding pack must cover every tool, every scope sits in
exactly one group, and the server's own agent-facing strings are checked against
the live surface.

| Item | Where | Guard |
|---|---|---|
| Server narrative, the scope count and the default on/off | `docs/readmes/README.MCP.SERVER.md`, `redamon.wiki/MCP-Server.md`, `README.md:703-705`, `README.TM.SYSTEM_OVERVIEW.md`, `Global-Settings.md` | the scope count: TEST (P21's MCP-scope kind); the tool count and the default on/off: NONE |
| Playbook prose | `webapp/src/lib/mcp/playbook.ts`, `onboarding.ts` | PART (tool names only) |
| Scope labels and blurbs | `webapp/src/lib/mcp/scopeCopy.ts` | TEST |
| Canonical banner bytes | `CANONICAL_BANNER` (`apiReference.ts`) == `DevergoLabs/scripts/add-wiki-canonical.mjs` | the byte-compare fails if they differ |
| User MCP manifest schema | `webapp/src/lib/mcp/schema.ts` <-> `agentic/mcp_registry.py:74-157` | NONE (TS is stricter) |
| Loop status names and the `loop_status` frame | `agentic/websocket_api.py` (`LOOP_STATUS`, `_loop_note`) <-> `websocket-types.ts` (`LoopStatusPayload`), `hooks/loopStatus.ts` | message type: TEST (the WebSocket parity test); the state names: NONE (agree today: 6 states, 3 error codes) |
| Loop tools withdrawn with the switch | `LOOP_TOOL_NAMES` (`webapp/src/lib/mcp/server.ts:329`); every MCP test that stubs `MCP_KALI_EXEC_ENABLED` also stubs `AGENT_IN_THE_LOOP_ENABLED` (`kaliTools.test.ts` does not, harmlessly: it never builds the server) | TEST (`server.contract.test.ts`); the stub pairing: NONE (the `mcp-server-tools` skill) |
| Agent in the Loop answer cap | `LOOP_ANSWER_MAX_CHARS`: env-tunable in the agent, only downwards (`WEBAPP_ANSWER_MAX_CHARS` in `agent_in_the_loop/__init__.py` is its default and maximum; `.env.example`, compose) <-> the constant in `webapp/src/lib/mcp/loopTools.ts` | TEST (`agentic/tests/test_agent_in_the_loop_settings.py` reads the TS constant) |
| Loop tool count in prose | `Agent-in-the-Loop.md`, `README.MCP.SERVER.md` ("three loop tools") <-> `LOOP_TOOL_NAMES` | NONE (agree today) |
| Kali exec wait cap 60 | `webapp/src/lib/mcp/kaliTools.ts:90` <-> `KALI_EXEC_MAX_WAIT` (`agentic/api.py:5590`) | NONE |
| OpenAPI | `docs/readmes/README.OPENAPI.md`, `route.openapi.test.ts` files | PART |

### 4.9 Plugin platform contract

| Fact | Copies | Guard |
|---|---|---|
| Platform version `1.1.0` | 5 pinned copies (section 3.2) + a literal in `services/plugin_runner/tests/test_sdk_contract.py:39` | TEST |
| JSON schemas | `webapp/src/lib/plugins/schemas/json/*.schema.json` | GEN (`npm run plugins:schemas`) |
| SDK local validator rules | `services/plugin_runner/sdk/redamon_plugin_sdk/testing.py:36-79` copies permissions, `MAX_PENDING_CHANGE_SETS=5`, `USER_SKILL_MAX_CHARS=512000`, group regex, 8 reserved headings, reserved markers, 10 credential shapes and data-store limits from `webapp/src/lib/plugins/{permissions,overrides,redact,dataStore,settings}.ts`, `userSkills.ts:19`, `agentic/prompts/skill_parts.py:253,263` | PART (`contract_cases.json` exercises a few); every constant equals its source today. The Gateway's value limit is env-tunable (`PLUGIN_DATA_MAX_VALUE_BYTES`), the SDK's is fixed |
| Plugin and action id regexes | `webapp/src/lib/plugins/ids.ts:8`, `schemas/common.ts:4`, `services/plugin_runner/supervisor/runlist.py:15,17`, `llmFeatures.ts:31` | NONE on the Python side |
| Signing keys | `webapp/src/lib/plugins/keyring.ts` (key id + public key, optional `notAfter`; one key, made 2026-10-11, none set); the key's bytes again in `keyring.test.ts:14` and twice in `README.PLUGINS.md` | PART (the test pins its own copy). **Time-based:** the next key must ship before the plugin repo signs with it |
| Default catalog URL (branch `master`, signature-checked) | `DEFAULT_CATALOG_URL` (`webapp/src/lib/plugins/catalog.ts:29`); compose's `${PLUGINS_CATALOG_URL:-...}` (`docker-compose.yml:1233`), the default the stack actually runs with (`.env.example` leaves it empty); a hand copy in `catalogVerify.test.ts:111`; `README.PLUGINS.md` | PART (the hand copy) |
| Plugin download hosts (4 GitHub hosts) | `DEFAULT_DOWNLOAD_HOSTS` (`webapp/src/lib/plugins/fetchRemote.ts:26-30`), compose's default (`docker-compose.yml:1234`, the one the stack runs with), `README.PLUGINS.md`, `README.TM.SYSTEM_OVERVIEW.md` | NONE. GitHub moving release assets to a new host refuses every plugin download |
| Extension points and actions | `extensionPoints.ts`, `contributions.ts`, the SDK, `README.PLUGINS.md`, `README.PLUGIN_SDK.md`, `README.DEV.md` §6.6 | PART |
| The plugins themselves | `redamon-plugins/` (separate repo) | its own signed catalog |

### 4.10 Cross-image mirrors: Python, TypeScript and other images

The agent image does not carry `recon/`, scan containers do not carry `webapp/`,
and the webapp build cannot import across its root. So shared facts are copied.

| Fact | Copies | Guard |
|---|---|---|
| Hard guardrail | `agentic/orchestrator_helpers/hard_guardrail.py`, `recon_orchestrator/hard_guardrail.py`, `recon_settings/hard_guardrail.py` (the recon copy, for names found on IP-mode targets), `webapp/src/lib/hard-guardrail.ts` (+ COPYed into the capture proxy) | TEST (shared vectors; the three Python copies' pattern and exact lists are compared for identity) |
| IP-mode hostname selection rule | `recon_settings/ip_hostnames.py` (the rule, imported in the recon, orchestrator and agent images) <-> `webapp/src/lib/ipHostnameFilter.ts` (parsing, matching, address canonicalisation and checks 1-9 for the preview; its filter parsing reuses `domainBatch.parseEntry`, so the PSL refusals the Python side leaves to callers happen there); the never-scannable predicate copies `recon/main_recon_modules/ip_filter.py`; the Python IP-literal refusal ports tldts-core 7.0.28 (`is-valid`, `extract-hostname`, `is-ip`) so a refused entry has the same reason on both sides, and a tldts bump can move it | TEST (`tests/fixtures/ip_hostname_vectors.json`, four suites; the predicate pinned address by address) |
| Settings an IP project's hostname mode forces | `recon/project_settings.py` `_IP_HOSTNAME_FORCED` (applied by `apply_ip_hostname_overrides`, marked by `print_effective_settings`) <-> `webapp/src/lib/ipHostnameOverrides.ts` (MCP `effective_overrides`, preflight `rewrittenAtScanStart`, the form's disabled toggles) | TEST (`recon/tests/test_ip_hostname_overrides.py` parses the TS object) |
| Hostname policy validation | `webapp/src/lib/scopeGroups.ts` `ipHostnamePolicyProblem` (every write path, through `reconSettings/crossField.ts`) and `ipHostnameStartProblem` (every start path) <-> `recon/project_settings.py` `_resolve_ip_hostname_policy` (the re-validation at load: refuses an unconfirmed or third-party `scan_all` and a `record_filter` with no usable include, drops unreadable include entries, keeps unreadable exclude entries so the rule fails closed) <-> `recon_orchestrator/batch_scope.py` `ip_hostname_include_bases` (the hard guardrail at start) | PART (each side tested; no shared vector file: the Python side has the PSL, the TS side the Domain-batch refusals, and both refuse rather than scan) |
| Scope groups | `agentic/scope_groups.py`, `webapp/src/lib/scopeGroups.ts`, `graph_db/mixins/recon/scope.py`, `recon/helpers/auth_profile.py`; `agentic/auth_profile.py` copies the recon auth-profile and RoE-scope helpers | TEST (contract JSON); PART for the agent auth-profile twin (cases repeated by hand) |
| RoE exclusion matching | `recon/helpers/roe_scope.py:17-46`, `agentic/auth_profile.py`, `webapp/src/lib/roeScope.ts` (used by `recordingSession.ts` and `openapiSourceStatus.ts`), `scanners/ai_attack_surface_scan/target_loader.py` `_roe_excluded` (the AI scanner's IP-mode admission; its image has no recon/), `recon_orchestrator/batch_scope.py` (the partial-run typed-input filter; that image has no recon/ either) | TEST (`recon/tests/fixtures/roe_exclusion_vectors.json`, all five; the scanner's in `scanners/ai_attack_surface_scan/tests/test_roe_exclusion_vectors.py`, the orchestrator's in `recon_orchestrator/tests/test_partial_typed_input_roe.py`) |
| RoE scanning window | `recon/helpers/roe_scope.py`, `recon_orchestrator/api.py`, `webapp/src/lib/roe/scanWindow.ts` | TEST (`roe_time_window_vectors.json`, section 3.2) |
| Engagement derivation | Python + `webapp/src/lib/engagement.ts` | TEST (fixtures JSON) |
| Public Suffix List | `recon/helpers/public_suffix.py` (`publicsuffixlist` pin) <-> `webapp/src/lib/publicSuffix.ts` (`tldts` pin) | TEST (vectors) + manual release step `README.DEV.md` §5.8 |
| Resolved-IP denylist | `recon_orchestrator/ip_denylist.py`, COPYed into the capture proxy | no drift possible (one file) |
| URL guard | `agentic/orchestrator_helpers/llm_url_guard.py` <-> `recon/main_recon_modules/ip_filter.py`; third copy `webapp/src/lib/llm-url-guard.ts:16-23` | TEST for the Python pair; PART for TS (separate suites) |
| **WebSocket protocol** | `MessageType` (`agentic/websocket_api.py`) <-> `webapp/src/lib/websocket-types.ts`; the job string again in `agentic/ws_job_emitter.py:37` | TEST (`websocket-types.parity.test.ts`, 54 values each side; `IGNORED_SERVER_MESSAGES` names 4 the webapp ignores on purpose, each with its reason: `job_update`, `thinking_chunk`, `execution_step`, `skill_inject_ack`); the LATS view is guarded (3.2) |
| Scan status enums | 6 in `recon_orchestrator/models.py` <-> `webapp/src/lib/recon-types.ts`; `AiAttackSurfaceStatus` <-> `AiAttackStatus` (`webapp/src/lib/aiAttackSurface.ts:368`) | NONE. Agree today (TS adds a client-side `pausing`) |
| Orchestrator payload shapes | 27 Pydantic models (`recon_orchestrator/models.py`) <-> hand-written interfaces (`recon-types.ts`, `orchestrator.ts`) | NONE (no codegen) |
| Traffic filter vocabulary | `agentic/traffic_tools.py:70-73` <-> `buildTrafficWhere` (`webapp/src/app/api/traffic/[projectId]/route.ts:62`) | NONE |
| Capture body families and policies | `webapp/src/lib/captureBodyRules.ts:9-35` <-> `scanners/capture_proxy/capture_lib.py:148,157` | NONE |
| Capture-tag signer | `redamon_ctx.py` in `agentic/`, `recon/helpers/`, `scanners/capture_proxy/` (identical) + TS minter `webapp/src/lib/redamonCtx.ts:15` | TEST for the Python copies (`test_replay_and_sync.py:91`); PART for TS |
| `scaIntelIgnoreSuffixes` default (8 copies), and the other capture, egress and SCA defaults the instance settings share | `scanners/supply_chain_common/intel.py:32`, `webapp/src/lib/scaIntel.ts:40`, `schema.prisma:596` (UserSettings) and `:167` (InstanceSettings), `webapp/src/app/api/users/[id]/settings/route.ts:294`, `DEFAULT_CAPTURE` (`webapp/src/components/traffic/captureSettingsForm.ts:54`), `sharedInstanceSettings.ts:51-61`, `webapp/scripts/backfill-rbac-instance-settings.mjs` | TEST for the four RBAC copies (`authz/instanceSettings.backfill.test.ts`); PART for the rest (`scaIntel.test.ts:124`); agree today |
| Supply-chain input validation | `webapp/src/lib/validation/supplyChainInput.ts` <-> `scanners/supply_chain_scan/repo_clone.py:48` | NONE |
| GuardDog charset and ecosystems (7) | `SAFE` (`webapp/src/app/api/internal/supply-chain/guarddog/route.ts:21`) <-> `container_manager.py:4559`; ecosystems in `agentic/supply_chain_tools.py:39`, `guarddog/route.ts:16`, `container_manager.py:4551`, `supply_chain_common/guarddog_runner.py:30`, prose `tool_registry.py:587` | NONE |
| Analyzer hardening flags | `container_manager.py:4516-4521` (memory precedence `:878`) <-> `supply_chain_common/analyzer_dispatch.py:122`; an unused third copy `guarddog_runner.py:75` | NONE |
| Supply-chain three-layer gate | `agentic/supply_chain_tools.py:43` + webapp + orchestrator | PART |
| TruffleHog sources / registry / digest / result filenames | `scanners/trufflehog_scan/sources.py` <-> `webapp/src/lib/trufflehogSources.ts`; `recon_orchestrator/trufflehog_registry.py`; filenames in `webapp/src/app/api/trufflehog/[projectId]/download/route.ts:17-19`, `scanners/trufflehog_scan/job_config.py:51`, `container_manager.py:4188`. The orchestrator imports the registry from its mount; `update` restarts it for a `.py` change at the top of `scanners/trufflehog_scan/` | TEST (filenames: NONE) |
| Resource governor profile | `recon_orchestrator/resource_profile.default.json` <-> both `resource_governor.py` <-> `redamon.sh` weights (`_MEM_SPECS_BASE` `:509`, `BLAST_PCT` near `:715`); per-kind envelope bytes `SCAN_JOB_ENVELOPE_BYTES` (`webapp/src/lib/jobQueue.ts:37`, lacks `partial_recon:SupplyChainRecon`, `partial_recon:JsRecon` and `codefix`; adds `supply_chain_repo`) | TEST (JSON <-> governors); NONE for `redamon.sh` and the TS envelopes; PART for the two governor modules, which their docstring calls byte-identical and are not (#138) |
| Triage score formula | `score_model.py` <-> `Triage/triageLayers.ts` | TEST (`triageScore.vectors.json`, both sides); with no stored tier, the UI names the higher tier at a boundary score (accepted, in `KNOWN_DIFFERENCES`) |
| Triage vocabulary | `TRIAGE_PROPERTIES` (`webapp/src/lib/triage/properties.ts:10`) <-> the mixin; `DECIDED_BY`, `REVIEWED_VIA`, `REVIEW_CURRENT`, `VERDICT_STATUSES` (`actions.ts:49-327`), `RESOLVED_TRIAGE_STATES` (`reportable.ts:27`), `_TRIAGE_FILTERS` (`agentic/api.py:4038`) | TEST for properties (`properties.test.ts` reads the mixin); PART for the vocabularies |
| Proof types / proof bar 70-80; passive CVE sources | `triage_mixin.py:310-317`, `fact_queries.py:152-155`, `score_model.py:1254-1264`; `recon/helpers/finding_sources.py:26`, `score_model.py:680`, `osint_mixin.py:81` | types NONE, bar TEST; sources TEST (skips without `recon/`) |
| Mute selector / severity rank | `agentic/multi_mute/{kind,pool}.py` <-> Cypher in the triage mixin | TEST (contract JSON) |
| Diagnostic failure classes (5) | `productivity.py:250` <-> `error_class.py:203` | NONE |
| Auth headers, project file roots, chat-skill caps, baddns modules, workspace protected dirs | `webapp/src/lib/authProfile.ts` <-> `recon/helpers/auth_profile.py`; `reconSettings/validators.ts:70-78` <-> `recon/project_settings.py:1049-1057`; `chat-skills/route.ts:34,62,75` <-> `import-community/route.ts:12-13`; `TakeoverSection.tsx:27` <-> `takeover_helpers.py:427`; `workspace_fs.py:73-74` <-> `FileSystemDrawer.tsx:100` | PART / NONE (each agrees today) |
| Neo4j-to-JSON coercion | `_graph_exec_coerce` (`agentic/api.py:3961`) and `_coerce` (`mcp/servers/redagraph.py:123`) | none needed: no longer a pair. The agent's adds `nodeId` and strips display-only props; redagraph has no driver and only re-coerces the agent's JSON; the agent's docstring says so |
| Display-only graph props | `graph_db/display_only.py` <-> `webapp/src/lib/secrets/secretProps.ts` | TEST for the union (`tests/test_display_only.py`); PART for the TS subsets, split by hand |
| Internal routes Python calls on the webapp | `INTERNAL_ALLOWLIST` (36 patterns) and `SCANNER_ALLOWLIST` (3) in `webapp/src/middleware.ts` <-> the method+route pairs Python calls with `X-Internal-Key` (about 40, count unverified) | TEST (`middleware.internalCallers.test.ts`, computed from the callers). Enforcement is **log-only** unless `INTERNAL_KEY_ALLOWLIST_ENFORCE=true` |
| Workspace upload size caps (60 MB body, 8 MiB chunk, 16 MiB ceiling) | `webapp/next.config.ts:41`, nginx `client_max_body_size` (`tooling/deploy/single-host/nginx/redamon.conf.tmpl:92`, `redamon-http.conf.tmpl:49`); the chunk in `agentic/workspace_import/limits.py`, compose and `uploadSession.ts`; the ceiling in `uploadSession.ts` and `chunk/route.ts` | NONE for equality (agree today) |
| Scan disk floor 10 GiB and its parse rule | `JOB_QUEUE_MIN_FREE_DISK` in `docker-compose.yml:605,924`, `recon_orchestrator/job_dispatcher.py:66`, `agentic/workspace_import/limits.py:31`, `.env.example`, `README.DEV.md` §8 | NONE (agree today) |
| Package-name charset gate | `_SC_NAME_RE` / `_sc_safe_name` (`mcp/servers/network_recon_server.py:1589-1600`, "Mirror of supply_chain_common.security.sanitize_name") <-> `_NAME_RE` / `sanitize_name` (`scanners/supply_chain_common/security.py:43-80`) | PART (`tests/test_supply_chain_mcp.py:108-114` runs hand cases against the Kali copy only, with no newline case); differ today (#147) |
| SCA IOC matcher and its case table | `scanners/capture_proxy/ioc_match.py` and the matching half of `scanners/supply_chain_common/intel.py` <-> `webapp/src/lib/scaIntel.ts` ("every rule added here has to be added there too"); the reload window `RELOAD_CHECK_SECONDS` (`intel.py:43`, env-tunable, forwarded nowhere) <-> `RELOAD_CHECK_MS` (`scaIntel.ts:77`) | PART (`tests/test_sca_ioc_match.py:177-200` runs `PARITY_CASES` on the Python side and only checks that each host string appears in `scaIntel.test.ts`; the guard the TS header names does not exist, #138) |
| Secret-hunter PEM and nearby-keyword checks | `scanners/github_secret_hunt/github_secret_hunt.py:411-458` ("mirrored from js_recon") <-> `recon/helpers/js_recon/patterns.py:728-770` | PART (`TestPhase0Mirror` in `tests/test_github_hunt_patterns.py` repeats cases on the hunter side). Identical today; three same-named regexes in the hunter's `SECRET_PATTERNS` (Databricks, Resend, GitHub Credentials URL) lack js_recon's 2026-11-01 boundary fixes, a copy no comment declares |
| Triage tables keyed by values the writers stamp | `CONFIDENCE_BY_SOURCE` (`agentic/cypherfix_triage/score_model.py:600`) against `RECON_FINDING_SOURCES` (`recon/helpers/finding_sources.py:9-19`) and the GVM, GitHub-hunt and supply-chain writers; `JS_RECON_CLASSES` (`:477-498`) against the `finding_type` values the JS writers stamp; `URLSCAN_LEAK_CLASSES` (`:527`), `ROUTE_EXPOSURE_CLASSES` (`:505`); the report's source CASE (`reportData.ts:1384-1391`) | PART: `test_score_model.py:203-221` checks a hand tuple `FINDING_SOURCES`, never `RECON_FINDING_SOURCES`; the urlscan and route-exposure tests are hand lists; NONE for the JS classes and the report CASE; only `SECURITY_CHECK_CLASSES` is TEST (`test_fix_triage_scoring.py` reads the producers). An unknown value takes a quiet default (confidence 0.75, the secret class, "Security Check"): stale today (#127, #128) |
| Priority Board section ids 0-3 | `SECTION_RANKED`..`SECTION_RESOLVED` (`graph_db/mixins/recon/triage_mixin.py:410-413`) <-> `TriageTable.tsx`, `SECTION_NAMES` in `webapp/src/lib/mcp/findingTools.ts:73` and again in `triageTools.ts:46` | NONE. A fifth section shows as `unknown` over MCP and the `section` filter never matches it; agree today |
| Workspace import kinds (11) | `REPO_KINDS`, `MIRROR_KINDS`, `ALL_KINDS` (`agentic/workspace_import/detect.py:13-16`) <-> `KIND_LABELS`, `REPOSITORY_KINDS`, `MIRROR_KINDS` (`FileSystemDrawer/ImportUrlDialog.tsx:21-37`) | NONE (`transferMessages.contract.test.ts` covers failure codes only). A new kind shows its raw id and is not treated as a repository; agree today |
| Grants of the `traffic_ingest` role (INSERT on one table, never SELECT) | `scanners/capture_proxy/sql/001_traffic_ingest_role.sql:21-30` (the manual path compose's comments name) <-> `webapp/scripts/apply-ingest-role.mjs:53-63` (what the entrypoint runs) | NONE; equal today |
| Third-party OSINT API endpoints | the Censys v3, OTX, SecurityTrails and ViewDNS URLs in the recon modules (`censys_enrich.py`, `otx_enrich.py`, `origin_discovery.py`) <-> the API-usage probes (`webapp/src/lib/apiUsage/providers/{censys,otx,securitytrails,viewdns}.ts`) | NONE; agree today |

#### Tradecraft

| Item | Where | Guard | Risk when it drifts |
|---|---|---|---|
| Agent contract enums (15 lists) and the owner-run rule | `agentic/tradecraft/contract.py` <-> `webapp/src/lib/tradecraft/agentContract.ts` <-> `agentic/tests/fixtures/tradecraft_contract/enums.json`; owner run also in `catalog.ts` | TEST (section 3.2) | |
| Agent routes (7) | `contract.py` `ROUTES` <-> `agentContract.ts` `AGENT_ROUTES`; the FastAPI decorators in `tradecraft/api.py` | TEST for api vs `ROUTES` (`test_tradecraft_api.py`); PART for TS vs Python | |
| Slug pattern | `contract.py` <-> `agentContract.ts` | PART (hand cases each side) | |
| `librarian.use` default `'agent'` | `settingsSpec.json` <-> a literal fallback in `fetch_agent_settings` (`agentic/project_settings.py:841`) | NONE; the spec is meant to be the only home of a Tradecraft setting (the `tradecraft-library` skill) | A changed default in the spec is ignored when the catalog omits the key |
| Think-prompt finding types (17) | `FINDING_TYPES` (`agentic/tradecraft/library/profile.py:46-51`) <-> the `finding_type` contract in `prompts/base.py` and `state.py` | NONE (agree today) | A new finding type never triggers a CVE search |
| Tradecraft tool count in prose | `agentic/AGENTS.md`, `ARCHITECTURE.md`, `README.AGENTIC_SYSTEM.md`, `README.TRADECRAFT.md`, `AI-Agent-Guide.md`, `Creating-a-Project.md` ("three tools") <-> `V2_TOOLS` (`agent_tools.py`) | NONE (agree today) | |
| Counts and limits restated in prose | "105 presets" (`Home.md`, `Global-Settings.md`, `Tradecraft-Library.md`), "95 settings in 15 sections" (`README.TRADECRAFT.md`, `Home.md`), about 25 limits in `README.TRADECRAFT.md` and `Tradecraft-Lookup.md` (e.g. 38,000 = `MAX_PART_CHARS`, `library/split.py:22`) <-> `settingsSpec.json`, `presets.ts` | NONE for the prose (the code side is count-locked by `presets.test.ts`) | Agree today; the skill says a setting lives only in the spec, yet about 30 values are copied by hand |
| Retired setting keys | `REMOVED_KEYS` (`webapp/src/lib/tradecraft/settingsSpec.ts:82`), a hand list outside the generated spec | NONE | A key removed from the spec and not listed is reported as unknown on old rows |

#### AI Navigator

| Item | Where | Guard | Risk when it drifts |
|---|---|---|---|
| Navigator tool permissions and MCP scopes vs the MCP functions' `requireScope` | `webapp/src/lib/navigator/tools/registry.ts` <-> `webapp/src/lib/mcp/*Tools.ts` | TEST (`tools/registry.test.ts` calls each tool with exactly its scopes and with each one removed) | A tool refused for every person, or a scope granted that no permission decided |
| Shared MCP / Navigator tool text | `UNTRUSTED_DATA_NOTE` in `webapp/src/lib/mcp/toolText.ts`, read by `server.ts` and the Navigator registry | TEST (`toolNameDrift.test.ts` lists `toolText.ts`) | |
| Wiki slugger vs the docs site's `rehype-slug` (github-slugger) | `agentic/navigator/wiki_index.py` `github_slug` | TEST (`test_navigator_wiki_index.py`: every anchor of `wiki-links.ts` resolves) | A citation lands at the top of its page instead of its section |
| Citation URL allowlist, 2 copies | `agentic/navigator/citations.py` <-> `webapp/src/lib/navigator/events.ts` | TEST (`test_navigator_citations.py`, `events.test.ts`), same regexes by hand | A docs link the webapp drops, or one it lets through |
| Navigator limits, 4 copies | `agentic/navigator/limits.py` <-> `webapp/src/lib/navigator/constants.ts`; the prose in `AI-Navigator.md:125-132`; the specialist prompts in `agentic/navigator/prompts.py` ("at most 200" rows = `ROWS_MAX`, "at most 3 files" = `WORKSPACE_FILES_PER_RUN`) | NONE (every value agrees today) | The agent and the webapp cap an answer or a run differently, or the model is told a limit that is not the one enforced |
| Navigator tool names (21) | `SUMMARIES` (`agentic/navigator/remote_tools.py:30`) <-> `webapp/src/lib/navigator/tools/registry.ts` | NONE (`events.parity.test.ts` checks only that each name fits the pattern) | A new tool shows "Called <name>"; a rename leaves the summary for a gone tool |
| Tool names in the specialist prompts | `agentic/navigator/prompts.py` names 19 remote tools and 4 local ones <-> `webapp/src/lib/navigator/tools/registry.ts` and the agent's wiki and schema tools | NONE (`toolNameDrift.test.ts` covers the MCP surface only) | A specialist told to call a tool it does not have; agree today |
| Navigator tool-name pattern | `_NAME_RE` (`remote_tools.py:27`) <-> `TOOL_NAME_RE` (`events.ts`) | TEST (`webapp/src/lib/navigator/events.parity.test.ts` reads the Python pattern and runs both on the same names, and every `SUMMARIES` name) | A name the agent accepts and the webapp refuses loses every trace event |
| Navigator credential header | `CREDENTIAL_HEADER` (`remote_tools.py:26`) <-> `NAVIGATOR_CREDENTIAL_HEADER` (`constants.ts:51`) | PART (each side's test uses its own literal) | |
| Navigator wiki mount | the `./redamon.wiki:/app/wiki:ro` mount (`docker-compose.yml`) <-> `WIKI_DIR` (`agentic/navigator/limits.py:16`) | NONE | The index finds no pages. The mount serves the wiki working tree, uncommitted edits included, as cited answers (pattern 22) |

### 4.11 Bundled third-party data and external ids

| Data | Where | Refreshed by | Guard / risk |
|---|---|---|---|
| MITRE CWE / CAPEC / CVE2CAPEC | `recon/main_recon_modules/data/mitre_db/` | `add_mitre.py` at scan time (24h TTL), **writing into the mounted source tree** | The 4 tracked resource files churn in `git status`; whether they belong in git is guard 23 |
| Wappalyzer fingerprints | `recon/main_recon_modules/data/wappalyzer_cache/technologies.json` | `http_probe.py` (24h TTL) from `unpkg.com/wappalyzer@<WAPPALYZER_NPM_VERSION>` (immutable per version) | `cpe_resolver.py` reads this copy (`test_dead_bundled_data.py`); the GVM container has none |
| DNS resolvers | `recon/data/resolvers.txt` (gitignored) | `recon/entrypoint.sh:107-114` every 7 days | `tests/recon_resolvers_refresh_test.sh` |
| Public Suffix List | inside `tldts` (7.0.28) and `publicsuffixlist` (`1.1.0.20261010`, a 2026-10-10 snapshot) | dependency bump | release blocker if older than ~3 months |
| CDN / WAF edge prefixes | `recon/helpers/cdn_edge_prefixes.py` | **manual**; "retrieved 2026-10-25" | `recon/tests/test_cdn_edge_list.py` guards that consumers use the one list, not its freshness |
| IANA service names, popular npm names, VHost wordlist | `recon/data/iana-services.csv`, `recon/data/npm_popular.txt`, `recon/wordlists/vhost-common.txt` | manual | NONE |
| Kali wordlist and tool paths | named in prompts and skills (e.g. `/usr/share/wordlists/rockyou.txt`) | Kali rolling image | NONE |
| Supply-chain incident intel (offline copy) | `scanners/supply_chain_common/sca_intel_seed.json.gz` (fetched 2026-08-18, committed 2026-09-18), `SEED_SHA256` in `intel_seed.py` (matches the file) | rebuild from a good live sync | the live feed replaces it at runtime; the seed only ages |
| Offline OSV database | Docker volume | `./redamon.sh supply-chain-sync`, install/update, orchestrator TTL | ecosystems guarded across 4 lists |
| TruffleHog detector names (1,060) | `webapp/src/lib/trufflehogDetectors.ts`; the count again in `README.md` (twice) and several wiki pages | **manual**, parsed from the pinned binary | TEST for the version (`tests/test_tool_version_pins.py`); the list itself is regenerated by hand; the prose counts NONE |
| Greenbone object UUIDs | XML report format and port list in `scanners/gvm_scan/gvm_scanner.py:308,345` | Greenbone feed | NONE; `:343-344` records one port-list mix-up |
| AI red-team tool vocabularies | promptfoo strategy ids (`TRANSFORMS`, `local_strategies.py:99`), garak and PyRIT probe names | tool upgrades | PART |
| Custom Nuclei templates | `mcp/nuclei-templates/` (8 templates); `recon_orchestrator/nuclei-templates/` is only an empty mountpoint for the same folder | manual | upstream templates may supersede them |
| Knowledge-base feeds | `services/knowledge_base/curation/pins.py`, `kb_config.yaml` | edit the pin, rebuild | a moved pin fails the build loudly; content ages |
| Exploit-DB CSV mirror | `services/knowledge_base/curation/exploitdb_client.py` | KB refresh | URL can move |
| External MCP servers | `webapp/src/lib/mcp/presets.ts` | manual | see 4.5 |
| Tradecraft Quick Add site catalog (105 sites) | `TRADECRAFT_PRESETS` (100, `webapp/src/lib/tradecraft/presets.ts:36`, no check date), `FEATURED_PRESETS` (5, `:155`, "Checked on 15 November 2026"), per-site layouts in `SETTINGS_BY_KEY` (CVE-archive paths, Read-the-Docs search-index URLs); derived copies in `webapp/src/lib/workspaceImport/presets.ts` and `tooling/scripts/tradecraft_e2e/library.yaml` | manual re-check | PART (`presets.test.ts` locks 100/5/105, unique keys and URLs); nothing checks a site still answers or allows crawling, though Check URL does at add time |
| Site-generator fingerprints | `agentic/tradecraft/ingest/detect.py:26-50` (MkDocs, mdBook, Sphinx, Docusaurus, GitBook); the fixtures `make_fixtures.py` writes share its assumptions | manual | PART (the fixtures test themselves); a platform redesign quietly drops detection to a plain crawl |
| AI-surface fingerprints | `AI_FAVICON_HASHES` (`recon/helpers/ai_signal_catalog.py:308-380`, 32 hashes "as of 2026-05-23"), `_GEMINI_CONTEXT_TOKENS` (`:1074`, `gemini-1.5` and `gemini-2` only), the MCP `protocolVersion` `2025-06-18` (`ai_surface_recon.py:219`), vendored Julius packs and Cisco MCP YARA rules with no upstream commit recorded | manual | PART (`test_ai_*_catalog*` check structure only); detection quietly finds less as products move |
| Cloudflare fallback prefixes | `_CLOUDFLARE_FALLBACK_V4` (`recon/helpers/cdn_ranges.py:177`), no retrieval date, used only when the live fetch fails | manual | NONE |

### 4.12 Version pins and container images

| Kind | Examples | Risk |
|---|---|---|
| Floating tags | 13 of the 15 images `recon/entrypoint.sh` pre-pulls are `:latest` (2 of them local builds); in `docker-compose.yml` 22 of 23 `:latest` lines are local `redamon-*` builds and the only third-party one is `ollama/ollama:latest`; Greenbone images on `:stable` (4) or untagged; `kalilinux/kali-rolling:latest`; `golang:1-bookworm` in 4 Dockerfiles; `ghcr.io/zaproxy/zaproxy:stable` | behaviour changes under you; output parsers break with no repo change |
| Exact pins | `TRUFFLEHOG_VERSION=3.96.0`, `BADDNS_VERSION=2.1.0`, `TRIVY_VERSION=v0.73.0`, `PROMPTFOO_VERSION=0.121.17`, garak 0.15.1 / PyRIT 0.14.0 / `giskard[llm]==2.19.1` (`scanners/ai_attack_surface_scan/adapters/*/requirements.txt`), `dolevf/graphql-cop:1.14`, the plugin runner base by digest, `@modelcontextprotocol/sdk 1.30.0`, `tldts 7.0.28`, `pdfjs-dist 5.4.296`, `mammoth 1.11.0`, the exact lines of `recon/requirements.txt` (5 of 22) | age; data derived from a pin must move with it |
| Pins repeated across images | osv-scanner (v2.4.0) in 4 Dockerfiles + `supply_chain_common` prose + `THIRD-PARTY-LICENSES.md`; guarddog (kali, analyzer); retire (analyzer, `retire_runner.py`); TruffleHog (Dockerfile, `trufflehogDetectors.ts`, e2e fixtures); the Ollama default image (`docker-compose.yml:720`, `redamon.sh:79`, `local_llm_manager.py:49`); promptfoo 0.121.17 also in the adapter's `adapter.py`, `plugins.py`, `local_strategies.py` and `TOOL_API.md` | TEST for osv-scanner, guarddog, retire and the TruffleHog sites it lists (`tests/test_tool_version_pins.py`); PART for TruffleHog: the "3.96.0" notes in `scanners/trufflehog_scan/sources.py`, `findings.py` and `recon/helpers/js_recon/trufflehog_bridge.py` (the JS-recon detector exclusions among them) are outside its `SITES`; NONE for the Ollama image and the promptfoo copies |
| Paths tied to a base image | `scanners/supply_chain_analyzer/Dockerfile:56` hard-codes `python3.11/site-packages` (base at `:23`), hidden by `\|\| true` | breaks silently when the base moves |
| Python base images | 3.11: agent, recon, orchestrator, supply chain, plugin runner; 3.12: the others; kali: whatever `kali-rolling` ships | the root `AGENTS.md` and `TECH_STACK.md` state each image's |
| Python images without a lockfile | most requirements use `>=` (the plugin runner alone is fully pinned); the `anthropic` SDK comes unpinned with `langchain-anthropic>=0.3.0` (`agentic/requirements.txt:6`); two soft imports reach into private or versioned modules of unbounded packages, `mcp.shared._httpx_utils` (`recon/main_recon_modules/ai_surface_recon.py:317`, `mcp>=1.27.0`) and `GMPv227` / `gvm.protocols.gmp.requests.v224._targets` (`scanners/gvm_scan/gvm_scanner.py:68-69`, `python-gvm>=24.0.0`); the pytest toolchain floors in three files kept "in sync" by hand (`requirements-test.txt:12-15`, `agentic/requirements.txt:70-73`, `recon/requirements.txt:50-53`) | NONE. A rebuild changes behaviour with no repo change; a failed gvm import reports the scanner unavailable and the AI-surface MCP probe degrades with no error (inferred) |
| One tool built at different refs in recon and Kali | ffuf `v2.1.0` (`recon/Dockerfile:21`) vs `@latest` (`mcp/kali-sandbox/Dockerfile:164`); jsluice commit `0ddfab1` (`recon/Dockerfile:14`) vs `@latest` (Kali `:173`); ParamSpider commit `c44bdaa` (`recon/requirements.txt`) vs git HEAD (Kali) | PART (`tests/test_t17_build_pins.py` checks recon's refs and names the Kali `@latest` installs as an accepted residual). The agent's copy can behave or print differently from the one recon ran (inferred) |
| Floating refs outside the T17 pin test | `ARG WCVS_REF=master` (`scanners/wcvs/Dockerfile:23`, under a comment asking to pin it); Trivy's installer from `main` and an unversioned `trivy plugin install mcp` (`agentic/Dockerfile:179-181`, under "Version pinned for reproducible builds"); an unpinned `pip install semgrep` in Kali while `mcp/requirements.txt` and `mcp/kali-sandbox/pip-constraints.txt` pick `mcp==1.29.0` because semgrep hard-pins it; 16 Kali `go install …@latest`; LinEnum, deepce and PowerUp on their default branch; `npm install -g yarn pnpm` in the agent | NONE beyond the Kali MCP import smoke step. A semgrep release that moves its mcp pin breaks the Kali build |
| Language runtimes baked into the agent and the CodeFix sandbox | Node 20 (`agentic/Dockerfile:39`, `scanners/codefix_sandbox/Dockerfile:16`), Go 1.22.10 (`agentic/Dockerfile:61`), .NET `--channel 8.0` (`:97`), `default-jdk-headless` on the floating `python:3.11-slim`; prose in `README.DEV.md:587` and `THIRD-PARTY-LICENSES.md`; the webapp, AI-surface and dev images use Node 22 | NONE. Runtimes age past upstream support (dates not checked here); the prose already overstates what the sandbox has (#141) |
| Desktop-Chrome User-Agent | `DEFAULT_BROWSER_UA` (`recon/helpers/user_agent.py:14-17`, Chrome/120), `recon/project_settings.py:164,390`, the Prisma defaults of `httpxCustomHeaders` and `katanaCustomHeaders` (`schema.prisma:934,1147`, frozen into every row), `mcp/servers/browser_launch.py:25-29`; `origin_discovery.py:103` sends Chrome/131 (#149) | TEST for the helper vs the httpx and katana defaults (`test_user_agent_hygiene.py`) and the Prisma parity test; NONE for the MCP and origin-discovery copies. An old UA reads as a bot (inferred) |
| CUDA torch index | `cu124` in `redamon.sh:3281` and the `agentic/Dockerfile:123` comment; torch itself unpinned | PART (`tests/redamon_gpu_torch_test.sh` covers the CPU-index copies only) |
| LangGraph checkpoint tables | the Prisma `Checkpoint*` models ("Schema mirrors langgraph.checkpoint.postgres.base.MIGRATIONS — keep in sync") <-> `langgraph-checkpoint-postgres>=2.0.0` (`agentic/requirements.txt:64`), unpinned | NONE. A column the library adds and Prisma lacks would be dropped by `db push --accept-data-loss` at every webapp start (inferred; today's match unverified) |
| Licences | `THIRD-PARTY-LICENSES.md` (hand-maintained) | the pinned versions it names: TEST (`test_tool_version_pins.py`); the rest by hand, and it lags (`ospd-openvas:22.7.1`, #146) |
| Release version | `VERSION` -> `redamon.sh`; `README.md` badge (hand); `CHANGELOG.md`; `REDAMON_VERSION` (`webapp/Dockerfile:31`); `webapp/src/lib/disclaimerVersion.ts` | TEST for the badge (`tests/test_readme_version_badge.py`) |

### 4.13 Control plane, compose, env and the test runner

| Item | Where | Guard | Note |
|---|---|---|---|
| **What `update` rebuilds** | `cmd_update`, `_map_core_changes`, `_map_tool_changes` and `_map_baked_graph_db` (`redamon.sh`): one hand-written rule per folder | TEST (`tests/redamon_update_map_test.sh`, 401 checks: derived from every built image's COPY sources; for recon-orchestrator and traffic-ingest, from every module their code imports from a bind mount, with one reasoned exception (`/app/recon`, which `api.py` puts on the path); every service that takes the `REDAMON_VERSION` build argument is rebuilt by a `VERSION` change). What it cannot see: a profile service that shares a rebuilt image is rebuilt and never recreated (`kb-refresh`), kali-sandbox's bind import of `graph_db`, and build arguments that come from env or an overlay (`NEXT_PUBLIC_AGENT_WS_URL`) (#132, #133) | Cross-folder COPYs: recon, gvm, github-hunt -> `graph_db`; recon, the agent and ai-attack-surface -> `recon_settings`; the agent and kb-refresh -> `graph_db`, `services/knowledge_base`; capture-proxy and traffic-ingest -> `recon_orchestrator/{hard_guardrail,ip_denylist}.py` |
| Image and service name lists | `TOOL_IMAGES` (`redamon.sh:24`, 10 = the tools-profile services), compose `image:` tags, the orchestrator `*_IMAGE` env (`docker-compose.yml:523-529`, `CAPTURE_PROXY_IMAGE` at `:551`); `CORE_BUILD_SERVICES` (`redamon.sh:29`) typed again, in another order, as `rebuild_core` at `:4164` | NONE | Agree today |
| Memory specs | `_MEM_SPECS_*` (`redamon.sh:509-542`, 16) vs compose `mem_limit` variables; `_status_expected_mb` (`:5093-5106`) maps only 10 containers; `_GVM_DATA_CONTAINERS=8` (`:528`) | NONE / NONE / TEST (`redamon_gvm_compose_test.sh:216-217`) | `status` never flags the GVM and kb-refresh caps |
| Env vars | `.env.example` vs what compose forwards | TEST, one direction (`tests/test_env_example_keys.py`: every key is forwarded or a `HOST_ONLY_ENV_KEYS` entry `redamon.sh` reads); the reverse is unguarded by design: compose reads over a hundred more variables, each with a fallback, as `README.DEV.md` §8 says. `tests/tradecraft_no_new_env_test.sh` pins the agent and webapp keys by hand (3.2) | A knob a spawned container reads must also be forwarded by `container_manager.py` (the governor knobs are, through `_governor_overrides`) |
| Env var reference | `README.DEV.md` §8 | NONE | marked as a selection; says what `.env.example` holds and that compose reads more, with fallbacks |
| RBAC switch defaults | compose `false`, `.env.example` `true`, `redamon.sh` writes `true` on install, `webapp/src/lib/authz/flags.ts` treats unset as off | PART (`tests/redamon_rbac_env_test.sh`) | The three levels differ on purpose |
| Service table | `README.DEV.md` §2 | NONE | lists all 34 compose services today |
| Hot-reload table | `README.DEV.md` §5.3 | NONE | matches the images, mounts and update map as of 2026-11-19, `scanners/supply_chain_common/` included |
| Production compose | `tooling/deploy/single-host/compose/docker-compose.prod.yml`, which re-lists all kali host ports with `!override` (`:61-72`) | PART: no deploy test compares the two port lists; only `tests/test_ghsa_3cjg_terminal_unauth_pty.py` reads both, for one port | A port added only to the base compose is unpublished on deploy hosts; 10 on each side today |
| Capture-proxy module list | `scanners/capture_proxy/Dockerfile:22-28` names its 7 modules; no source mount | NONE | A new module fails with ImportError |
| Orchestrator host-path mounts | compose volumes, `recon_orchestrator/api.py:128-190` (10 lookups), the test runner's `-e *_PATH` list (`redamon.sh:5527-5535`, 9; no `RECON_SETTINGS_PATH`) | NONE | |
| Runtime cache paths | `RUNTIME_TRACKED_PATHS` (`redamon.sh:52`) vs the writers (`add_mitre.py:38`, `http_probe.py:1700`) | NONE | Agree today |
| Webapp startup scripts | the inline entrypoint `webapp/Dockerfile:139` and the dev copy in `docker-compose.dev.yml` | TEST (`tests/webapp_dev_startup_parity_test.sh`) | |
| Prisma migrations | `webapp/prisma/migrations/` (17, last 2026-09-24) | none; the schema is applied with `db push`; backfills now run as startup scripts (`webapp/scripts/backfill-*.mjs`) | historical record only |
| Test sections | `_TEST_SECTIONS` `redamon.sh:5438` | PART (`redamon_gate_unskippable_test.sh` stops a known section skipping silently); a shell suite that cannot run exits 77 and fails the gate unless `REDAMON_TEST_ALLOW_MISSING` names it (guard 28) | every tracked test file (1,416) falls in some section today; a file's name still decides its tier, so 18 hermetic guards sit outside the unit tier (#134), and `tests/test_*.sh` files are outside the shell glob (#135) |
| Root tests routed to the recon image | `_ROOT_RECON_TESTS` `redamon.sh:5435` (14) | NONE | 6 more reach into `recon/` via `sys.path` and run in the agent image; `test_key_rotation.py` is one and puts `recon/main_recon_modules` on its own path, so all its classes run (they skipped in every image until 2026-11-19, #97) |
| Coverage floors | `--cov-floor ${REDAMON_COV_FLOOR:-0}` (`redamon.sh:5523`, one value for all nine sections); 79 only in `agentic/run_tests.sh:31`; `README.TESTING.md:631-639` | NONE | The canonical coverage tier enforces nothing (#136) |
| The file-name tier rule, 9 copies, and 8 `pytest.ini` | `_INT` / `_LIVE` (`tooling/scripts/pytest_isolated.py:40-41`) and `_INTEGRATION_MARKERS` / `_LIVE_MARKERS` in 8 `conftest.py` (root, `agentic/`, `recon/`, `recon_orchestrator/`, `scanners/{ai_attack_surface_scan,capture_proxy}/`, `services/{docker_broker,plugin_runner}/`; six byte-identical); the 8 `pytest.ini` repeat the markers under `--strict-markers` | NONE (`tests/test_pytest_isolated_tiers.py` runs on its own copy) | All agree. A suffix added in one place puts a file in one tier for the runner and another for its conftest, so its tests run in no tier (inferred) |
| Which image a component's tests run in | `_TEST_SECTIONS` has 9 sections for 20 built services; the tests of `mcp/servers` (kali-rolling), `scanners/{gvm_scan,github_secret_hunt,trufflehog_scan}` (Python 3.12) and `scanners/supply_chain_{scan,analyzer}` run in `redamon-agent` (3.11, the agent's requirements) | NONE | The wrong-dependency-set problem the root ruleset forbids for host pytest: a pin bump in those images is never exercised |
| The agent section spec, 2 copies | `_TEST_SECTIONS` "agent" (`redamon.sh`) <-> `agentic/run_tests.sh:44-51` (image, workdir, PYTHONPATH: "must match") | NONE (agree today) | `run_tests.sh` does not forward `REDAMON_TEST_ALLOW_MISSING` or the `*_PATH` variables, and exits 0 without the image (#136) |
| The capture pair, 2 spawn specs | compose `capture-proxy` / `traffic-ingest` (`docker-compose.yml`) <-> `container_manager.start_capture_proxy`, which starts the containers that actually run (compose's are for a manual `--profile capture up`) | PART (`recon_orchestrator/tests/test_capture_proxy_env.py` checks the spawned env only) | Differ only in a compose-only `WEBAPP_API_URL` today; a guard that reads compose checks the twin, not the running container |
| Hermetic tests outside every runner | `testing/e2e/scripts/stub-llm-server.test.mjs` (`node --test`, "no stack needed") | NONE | vitest runs only inside `webapp/` |
| Memory calibration | `recon_orchestrator/resource_profile.json` (gitignored, host-local) | `tests/redamon_mem_calibrate.sh baseline` / `scan` | measured peaks age as services grow |
| End-to-end suites | 49 Playwright specs in `testing/e2e/tests/` | not in the unit gate | selectors break with UI changes |
| `redamon.sh` help text | `cmd_help` `redamon.sh:5368` | NONE | every dispatched command is listed today |
| Issue templates | `.github/ISSUE_TEMPLATE/bug_report.yml` (6 components); `feature_request.yml` has its own 7-option list | NONE | no scanner, plugin or graph entry |

### 4.14 Docs, wiki and agent rulesets

**Generated (do not hand-edit):** `redamon.wiki/MCP-API-Reference.md`,
`redamon.wiki/Project-Settings-Registry.md`, the "Auto-invoke Skills" tables in
`AGENTS.md` files.

**Agent-facing text: the highest-stakes prose.** A stale line here becomes wrong code.

| Item | Guard |
|---|---|
| `docs/readmes/coding_agent_prompts/*.md` | crude checks in `tests/test_docs_not_stale.py` (retired names, deny reasons, generated files); cited paths: TEST (`tests/docs_cited_paths_test.sh`); function names and layer counts: NONE (the prompts were rewritten from the code on 2026-11-19 and cite symbols, not `~line` hints; #101-#104) |
| The built-in skill layer list: `skills/builtin-agent-skill/SKILL.md` (10), `AGENTS.md` (10), this page's 4.2 (ten), `PROMPT.ADD_BUILTIN_AGENT_SKILL.md` (10) | NONE (agree since 2026-11-19, #102) |
| `skills/*/SKILL.md` layer tables and file lists | `drift-audit.sh` (a link resolves from the file's folder) and `--docs` in the gate; `#L<n>` anchors: TEST (`tests/test_ruleset_line_anchors.py`) |
| `AGENTS.md` per component (`CLAUDE.md` is a symlink to it in the root and in six component folders), incl. QA checklists | `drift-audit.sh`; the root names the component roots that carry one (`mcp/` and `graph_db/` follow the root file) |
| `AGENTS.md` SKILLS CATALOGUE (by hand) | none; 20 = 20 today (21 folders under `skills/`, `skill-sync` included) |
| `drift-audit.sh` `ROOTS` and `sync.sh` scope map | none; cover every `AGENTS.md` today (9 roots, 7 scopes, 7 files) |

**Human-facing**

| Item | Risk |
|---|---|
| Count claims in README and wiki | eight kinds checked against the code (P21: recon presets, MCP presets on every page, node types, settings, RBAC permissions, MCP scopes, LLM providers, chat skills); any other count is prose. Counts with several copies and still no guard: agent tools (no single set to count; the 2026-11-19 fixes dropped those numbers, #113), Tradecraft and loop tools (4.10, 4.8), the Tradecraft presets and settings (4.10), the downgrade tables and columns (#142), the Navigator limits (4.10), the proxy_brain sections (#139) |
| `README.md` (117 KB): features, tool tables, screenshots, wiki links, badge | links, anchors and counts: P21; the badge: TEST (`tests/test_readme_version_badge.py`) |
| Subsystem docs (37 tracked, this page included) | cited paths: TEST; `` [`symbol`](path#L<n>) `` anchors: TEST (`test_ruleset_line_anchors.py`); a link naming `file:line` instead of a symbol: NONE; function-by-function sections are prose, unguarded (the recon and KB ones were rewritten from the code on 2026-10-25); `README.DEV.md` §9 indexes all |
| Anchors | TEST (P21, GitHub's slug rules, combining marks kept) for wiki and relative links and for the anchor of a `github.com/.../blob/...` URL; a heading rename still breaks every incoming `Page#anchor` until someone runs the gate |
| Wiki file links and images | TEST (P21 for images and repo URLs, `docs_cited_paths_test.sh` for paths); screenshots age with every UI change |
| Doc screenshots generated by Playwright | `testing/e2e/tests/capture{Auth,Jev,McpServer,Tlsx,AgentInTheLoop,Urlscan}DocsShots.spec.ts`; every other screenshot is manual |
| Links into `_local/` (untracked) | none left; the path audit treats any `_local/` path as dead |
| `README.GPIGS.md`, `testing/guinea_pigs/README.md` | 26 tracked labs; both list all 26; the second is guarded (`tests/test_guinea_pigs_index.py`), the first is not (it lagged three labs behind until 2026-11-19, #116) |
| redamon.org `/docs` | nightly copy of the wiki's top-level pages; a stale wiki page is a stale public page within a day, and AI Navigator serves the wiki working tree as cited answers at once (pattern 22) |
| Markdown outside the path audit | `drift-audit.sh --docs` reads `docs/readmes/**`, `README.md`, `CONTRIBUTING.md`, `SKILL.md`, `AGENTS.md` and the top-level wiki only (`skills/skill-sync/assets/drift-audit.sh:62-79`); 59 other tracked `.md` files are never read (lab READMEs, `tooling/**/README.md`, `recon_settings/README.md`, `tests/fixtures/*/README.md`, adapter `TOOL_API.md`, `agentic/labs/**`, `GOVERNANCE.md`, `THIRD-PARTY-LICENSES.md`): stale today (#146) |
| Code identifiers named in prose (functions, constants, labels) | no guard reads them: the path audit checks paths, `toolNameDrift.test.ts` MCP tool names: stale today (#144) |
| `redamon.sh` subcommands and `npm run` scripts named in docs | NONE against the dispatch `case` and `webapp/package.json`: stale today (#143) |
| Env-var tables in subsystem docs (`README.MEMORY_GOVERNOR.md`, `README.CYPHERFIX_AGENTS.md`, `README.TRAFFIC.md`, `README.MCP.SERVER.md`, `README.DEV.md` §8) | NONE: no table is compared with a reader: stale today (#140) |
| Agent in the Loop timings in the driver's text | `loopSkill.ts`, `playbook.ts`, `Agent-in-the-Loop.md` (30 min, 60 min, 55 s, 90 s, 16 steps) <-> `_TUNABLES` (`agentic/agent_in_the_loop/__init__.py`), which the env can lower; they agree with the defaults, and some lines do not say the value can change: NONE |
| `CHANGELOG.md` (777 KB) | append-only; not a drift source |

### 4.15 Data stored in Postgres and Neo4j

Rows written once and read for ever. Every one goes stale against the code that
reads it.

| Stored | Model / place | When it goes stale |
|---|---|---|
| Per-project tool phase map and skill toggles | `Project.agentToolPhaseMap`, `Project.attackSkillConfig` | a tool or skill is added (4.1, 4.2); rows created over MCP before the fix pass carry brute force, phishing and DoS ON (6 of 13 projects on the audited stack) |
| Every project column default | `Project` rows | a `@default` changes (needs a backfill) |
| User project presets | `UserProjectPreset.settings` | the reader drops and reports unknown keys (`projectPresetForRead`, `reconPresets/server.ts:164`), so a rename is tolerated; what goes stale is the whole `agentToolPhaseMap` and `attackSkillConfig` each preset holds, which apply replaces and no backfill touches (#126) |
| User mute-rule presets | `UserMuteRulesPreset.rules` | a finding kind changes in the node-filter catalog |
| Saved graph views | `GraphView` (stored Cypher/filters) | a label, relationship or naming rule changes (`staleViewNote.ts` warns only for the Domain-is-the-org change); since 2026-11-13 the execute route refuses plugins, `db.*`, unknown functions, dynamic labels and parameter maps, while the create route stores Cypher unchecked and PUT cannot edit it, so an older view that uses one of them answers 400 at every run and can only be deleted |
| Scan schedules | `ScanSchedule` | it holds no scan payload; it freezes `estimatedEnvelopeBytes`, which the overlap check reads (`webapp/src/lib/scanSchedule.ts`) and import copies from another host as-is. The payload a queued job runs is `JobQueue.payload` plus `settingsHash` (below) |
| Scan Timeline snapshots | `ScanVersion.snapshot` (gzipped graph) | restoring after a schema change (`graphRestore.ts`) |
| Exports | project export archives | export writes `version: '1.1.0'`; import only checks that a version exists (`import/route.ts:246`) and is lenient section by section, with no dispatch on the version; PART (`route.retiredSettings.test.ts`, `route.ownershipToken.test.ts`) |
| Graph data written by an older recon | Neo4j | properties renamed or added (`legacyGraph.ts`, the alias reads in 4.7) |
| Settings fingerprints of queued jobs and past runs | `JobQueue.settingsHash`, `ScanJob.settingsHash` | a hash with no version over `FINGERPRINT_FIELDS` (`webapp/src/lib/jobQueue.ts:91-95`), which the registry decides at runtime: adding or reclassifying a traffic field changes every stored hash, so jobs queued across an update stop as `settings_changed` and MCP `get_engagement` reports `settingsChangedSince: true` though nobody touched the project (fails safe, misleading); NONE |
| The stored triage answer | `triage_disposition`, `triage_blocker`, score and tier on finding nodes, with `triage_model_version` | readers prefer the stored answer when it is whole and never compare `triage_model_version` with `SCORE_MODEL_VERSION`; after a change to the rules or gates, findings keep their old blocker until the next triage run (inferred) |
| Tradecraft page copies carried forward | `tradecraft_entries` / `tradecraft_sections` (raw SQL) | an incremental refresh copies a page forward on a 304 whenever the resource's `settings_hash` equals the job's (`agentic/tradecraft/ingest/incremental.py:59`); the hash covers setting values only, so a fix to the builders or the extraction never reaches unchanged pages of sites that send ETag or Last-Modified (inferred) |
| Armed mute rules and each run's snapshot | `ProjectNodeFilter.rules`, `NodeFilterRun.rules` | a catalog kind, field or value renamed: the reader ignores an unknown kind and drops an invalid rule (`graph_db/node_filters/model.py`), so the rule silently stops muting; only value `aliases` exist |
| Workspace import provenance | `.import.json` in the workspace (`agentic/workspace_import/provenance.py`) | read only at `version == VERSION` (`:94`), with an HMAC keyed from `INTERNAL_API_KEY`: a version bump or a key rotation drops every record, and with it re-sync |
| Agent state in LangGraph checkpoints | `Checkpoint*` tables (`PERSISTENT_CHECKPOINTER`) | a new or renamed `AgentState` field read as `state["x"]` breaks a resumed older checkpoint; tolerance is a convention only, and none breaks today |
| Restored chat history | `ChatMessage.type` / `data` | a renamed or retired message type: old rows stop rendering (`useConversationRestoration.ts`; the WebSocket parity test covers live types only) |
| Engagement record archive | `EngagementAuthorizationArchive` | its `INSERT` names columns by hand (`webapp/src/lib/engagementArchive.ts`), so a new `engagement_authorizations` column is not archived (`idempotency_key` already is not); PART (`engagementArchive.schema.test.ts`: insert ⊆ model) |
| Per-user feature models | `UserSettings.featureModels` | exact key, no fallback: a renamed feature id loses every user's choice; a new feature has no model for anyone |
| Permission ids, set slugs, MCP token scopes, the sharing policy | the RBAC tables | 4.16 |
| One-shot Postgres migration | `tooling/scripts/engagement_derivation_migrate.py` (audit-only, 2026-09-17) | written against the schema of its day |

Checked on 2026-11-19 and tolerant: Tradecraft account settings (only changed
keys are stored, merged with the spec on read), the plugin manifest (re-checked
against the platform range on every reconcile), Tradecraft resource maps
(`map_version` 1 to 3 with a lazy conversion), the preset badge fingerprint
(versioned, skips defaults, accepts the old digests), Navigator citations
(re-checked when history renders) and coverage stamps.

### 4.16 Authorization (RBAC)

**Source of truth:** the permission registry `webapp/src/lib/authz/permissions.ts`
(99 ids, every one `introducedIn: 'UNRELEASED'`), the built-in sets
(`builtinSets.ts`, rendered to `permissionCatalog.json`, section 3.1), and
`MCP_SCOPES` (18). The route manifest and the RBAC matrix rows are generated
(3.1). What is not:

| Fact | Copies | Guard | Fails how |
|---|---|---|---|
| Permission ids stored in rows | `UserPermissionOverride.permission` (`schema.prisma:261-273`), `PermissionSet.permissions` (custom sets, admin profiles), read by `addOverrides` (`capabilities.ts:361-369`), `setContents` (`:181-193`), `keptPermissions` (`permissionAdmin.ts:55-58`) | PART: `permissions.test.ts` pins all 99 ids as literals, so a rename forces a test edit, but nothing migrates stored rows and there is no retired-id map | A rename or split: a stored **deny** override silently stops applying (`addOverrides` skips an id `isPermissionId` does not know) while the built-in set grants the new id, so it **fails open**; a custom set loses the permission (fails closed) |
| New permissions reaching custom sets | `gatesExisting` / `introducedIn` (`permissions.ts:55-64`: "a later release adds a new one of these to custom sets") | NONE: nothing outside tests reads either field, and no backfill exists | A permission that gates an existing feature reaches only the built-ins; every custom set loses that feature at upgrade |
| Built-in set ids `builtin:<slug>` stored in rows | `UserPermissionSet.setId`, `InstanceSettings.defaultMemberSetId`, `User.adminProfileId`, `PluginAccessRule.setId`, the per-set quotas | PART (`builtinSets.test.ts:56-77` pins ids and names as literals) | A slug rename resolves the account to No access (fails closed, warned) and lapses a per-set quota to unlimited |
| MCP token scopes stored per token | `McpAccessToken.scopes` (`schema.prisma:296`) <-> `MCP_SCOPES`; `resolveMcpToken` (`mcpAuth.ts:381-383`) rejects the whole token on one unknown scope; the column's `@default(["recon:read"])` differs from `DEFAULT_MCP_SCOPES` (`mcpAuth.ts:110`) and nothing uses it (#149) | PART (count lock of 18 in `permissions.test.ts`; MCP map keys == `MCP_SCOPES`); no retired-scope list | A scope renamed or removed: every token minted with it stops working (re-mint) |
| Agent-ticket caps, WebSocket audiences, decision kinds and modes | `AGENT_CAPS` (`agentic/ws_ticket.py:54`) <-> `AGENT_TICKET_CAPS` (`webapp/src/lib/authz/agentCap.ts:20`), 4; `WS_AUDIENCES` (`ws_ticket.py:49`) <-> `WS_SOCKETS` (`webapp/src/lib/wsTicket.ts:12`), 4; `DECISION_KINDS` / `DECISION_MODES` (`agentic/decision_check.py:34-39`) <-> `KINDS` / `MODES` (`api/internal/agent/authorize-decision/route.ts:42,58`) | PART: caps and sockets pinned by a literal on each side (`agentCap.test.ts`, `test_approval_cap.py`; `wsTicket.test.ts`, `test_ws_ticket_audience.py`); kinds Python ⊂ TS by substring only (`test_decision_check.py:147-154`) | A cap added on one side is dropped by `ticket_cap` (`ws_ticket.py:57-71`), so that decision is refused for everyone, or never checked. Agree today |
| Features a collaborator may spend the owner's credentials on | the `SpendFeature` union and `SPEND_FEATURES` (`webapp/src/lib/authz/ownerSpend.ts:16-32`, typed `readonly SpendFeature[]`, so a missing member still compiles), the filter at `ownerCredentials.ts:122`, `SPEND_FEATURE_TEXT` (`ApiUsageReportModal.tsx:162-174`, `Record<string,string>`) | NONE | A feature added to the union only: its usage rows drop out of the report or show a raw key. 11 each today |
| Browser copies of server rules | `QUOTA_FIELDS` / `QUOTA_FIELD_SPECS` (`app/admin/instance/quotaModel.ts:11-38`) <-> `lib/authz/quotas.ts`; `myAccessMeets` (`lib/readOnlyProject.ts:17-40`) <-> `meetsLevel` (`lib/authz/levelTable.ts`, split out so the browser can import it); `permissionModel.ts`, `setModel.ts` ("client mirror of the rules") | TEST for the first two (`quotaModel.test.ts` imports the server constants; `readOnlyProject.write.test.ts` compares every level); PART for the last two (cases repeated) | Fail-safe by design: a stale copy costs a refusal, never a permission |
| The permission reference on the wiki | `Identity-and-Access-Management.md`: member-set matrix (71 rows), admin-profile matrix (28 rows), descriptions and levels (99 rows); it says "Everything below comes from RedAmon's permission registry", and no generator exists | NONE (P21 has no permission kind) | A new permission or a changed built-in set leaves the public page wrong. Agrees today: every mark was compared with `permissionCatalog.json` on 2026-11-19 |
| Downgrade loss lists and their prose | `DOWNGRADE_TABLES` / `DOWNGRADE_COLUMNS` (`webapp/scripts/rbac-upgrade-preview.mjs`, pinned to the schema by `rbac-upgrade-preview.test.ts`) <-> the counts in `README.DEV.md`, `Identity-and-Access-Management.md`, `Deploying-to-a-Server.md` | TEST for the lists; NONE for the prose (#142) | |
| Upgrade oracles | `tests/fixtures/rbac_upgrade/` (generated by `tests/rbac_upgrade_live.sh regen` against the pinned 7.7.2 image; the `.after*` and `.capabilities*` oracles are hand-written) | live only; the offline `selftest` mode is not gated (#135) | A renamed permission or set leaves the oracles stale |
| Instance sharing policy | `InstanceSettings.sharingPolicy` (`schema.prisma:119`): `sharingPolicyToStore` (`sharingPolicy.ts:137-139`) writes every field with that day's defaults; `parseSharingPolicy` (`:93-101`) reads an invalid row as the defaults as a whole | NONE | After Root's first save, a later change to `SHARING_POLICY_DEFAULTS` never reaches that instance; a later narrowing of a field's values makes the stored row invalid, which turns sharing off for the whole instance |

### 4.17 Knowledge base

| Fact | Copies | Guard | Fails how |
|---|---|---|---|
| Which `agentic/skills/` folders are ingested | `SKILL_CATEGORIES` (`services/knowledge_base/curation/tool_docs_client.py:14-30`) <-> the folders of `agentic/skills/` (14) | NONE | Stale today (#131) |
| Embedder and reranker model ids | `intfloat/e5-large-v2` in 8 places (`agentic/Dockerfile:143` ARG, `agentic/orchestrator.py:473`, `services/knowledge_base/Makefile:34`, `curation/data_ingestion.py:185`, `kb_config.py:18,92`, `kb_config.yaml:43`, `curation/pins.py:73`); `BAAI/bge-reranker-base` in 6 (`agentic/Dockerfile:152`, `kb_config.py:35,111`, `kb_config.yaml:92`, `reranker.py:24`, `pins.py:74`); the API default `text-embedding-3-small` (`.env.example:79`, `api_embedder.py:40`) | PART (`services/knowledge_base/tests/test_t15_pins.py` pins the revisions of the two names only) | The image pre-downloads one model and the YAML loads another; a model missing from `MODEL_PINS` loads the branch head with a warning; the stored index's dimension is a frozen copy |
| Retrieval defaults and profiles | `kb_config.yaml` <-> `DEFAULTS` and the dataclass defaults in `kb_config.py` <-> `_FALLBACK_PROFILE_SOURCES` (`curation/data_ingestion.py:36-41`) <-> the profile names in `redamon.sh` | PART (`test_api_embedder.py` checks `cpu-lite` in two copies) | Differ today (#148) |
| Tests of the KB extras | `test_{embedder,faiss_indexer,reranker}.py` | skip without `--kbase` (#137) | |
| The `kb-refresh` sidecar | `docker-compose.yml:1039-1046`, profile `kb-refresh`, `image: redamon-agent`; it passes only `TORCH_INDEX_URL`, not `SKIP_KB` | NONE | `update` never recreates it (#132); a manual `--profile kb-refresh build` rewrites `redamon-agent:latest` with the Dockerfile default `SKIP_KB=false` (inferred) |
| Feeds | `services/knowledge_base/curation/pins.py`, `kb_config.yaml` (4.11) | a moved pin fails the build | |

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
   and not the single-tool one (or the reverse) holds half the time (#1, #9,
   #89).
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
   know (#7, #18). The update map now derives from the Dockerfiles, but what a
   running service imports from a bind mount was a hand list until 2026-11-19
   (#91); the test now derives that too.
9. **A rename that keeps the old name somewhere.** A legacy drop list that now
   names live constraints (#5), retired tools in a category map (#8), modules
   moved without the prose following (#37-#41), headings renamed under incoming
   anchors (#53, and #117 in the links P21 does not follow), coding-agent
   prompts that teach the code as it was before a refactor (#101-#104), a
   cleanup that removes the unread copy and leaves the doc that teaches it (#140).
10. **Prose counts and values.** A number in a sentence is a copy of a `len()` or
    of a limit (#110-#115, #139, #142).
11. **Runtime caches in the source tree.** Recon writes refreshed data into the
    mounted checkout, so committed snapshots and live data are the same path.
12. **Guards that skip, or compare with a copy of themselves.** A drift test
    that cannot find its other half skips; one that compares with expectations
    typed into the test catches edits but not omissions; one that is
    documented but never invoked catches nothing; one that exits 0 when it
    cannot run reports green (#96, #97, #98).
13. **The file name decides whether a guard runs.** The runner tiers tests by
    name and the shell section globs `tests/*_test.sh`, so a hermetic parity
    check named `*_skill.py`, `*_integration.py` or `test_*.sh` never runs in the
    unit gate, though it passes whenever someone runs it (#134, #135). Unlike 12,
    the guard works; the gate never calls it.
14. **A comment is taken for a guard.** A mirror comment names a test that does
    not exist, claims a byte identity that does not hold, or a test is named
    "matches" while it compares hand cases (#138); readers, and this page, then
    credit a TEST that is PART or NONE.
15. **What a file-diff update cannot see.** Build arguments from env or an
    overlay change an image with no file changing (#133, and #95 before it); a
    profile service that shares a rebuilt image is rebuilt and never recreated
    (#132); a compose service can be only the twin of a container the
    orchestrator spawns with its own spec (4.13).
16. **The test image is not the ship image.** Code that ships in kali-rolling or
    a Python 3.12 image is tested in the 3.11 agent image, and optional extras
    make tests skip on the default build (#137, 4.13).
17. **Stored ids and digests carry no version.** Rows store code ids and match
    them by exact string with no retired-id map, so one rename drops a
    permission (fails closed), rejects a token, or skips a deny (fails open)
    (4.16). Digests and decisions computed by code carry no version of that
    code, so they go stale for no reason a user can see: job fingerprints,
    stored triage answers, Tradecraft 304 copies (4.15). The preset badge
    fingerprint, versioned and blind to defaults, is the model.
18. **A new column's default reaches every existing row, and backfills reach only
    `projects`.** `db push` adds a column with its default to every row, the
    reverse of 2 (4.4 item 6); a backfill that moves a project column misses the
    user presets and export bundles that hold the same column (#126).
19. **Open vocabularies read through closed tables with a quiet default.**
    Writers stamp a `source`, `finding_type` or `type` freely; readers are dicts
    or CASEs whose fallback hides the omission (#127, #128). The reverse also
    happens: a UI option list wider than any runtime that reads it (#129).
20. **A compose default hides the code default.** A `${VAR:-x}` in compose and a
    literal fallback in code set one knob; inside the stack only compose's
    applies, while tests pin the code's (`PLUGINS_CATALOG_URL`,
    `PLUGINS_DOWNLOAD_HOSTS`, `LOCAL_LLM_MODEL`, `TORCH_INDEX_URL`; 4.9).
21. **Unbounded dependencies behind soft imports, and "verified against vX".** A
    lazy or try/except import of a private module from a `>=`-pinned package
    loses a capability at a rebuild with no error (4.12); calibration and review
    notes tied to one version (the TruffleHog 3.96.0 exclusions, the Jev 1.13.0
    thresholds, semgrep's mcp pin) move only if a pin test names them.
22. **The docs are runtime input.** AI Navigator indexes the mounted wiki working
    tree and answers from it with citations, so every stale wiki line,
    uncommitted edits included, is served as a cited answer. This raises the
    impact of every wiki item.

---

## 6. Recommended new guards, ranked

Ranked by (silent impact) x (likelihood). Each closes items in section 2 or a
NONE in section 4.

| # | Guard | Closes |
|---|---|---|
| 32 | A retired-id map for permissions, MCP scopes, built-in set slugs and feature ids, read by `addOverrides`, `keptPermissions`, `resolveMcpToken` and the set resolver, plus an append-only fixture of every id ever shipped: removing an id without a map entry fails | 4.16, pattern 17 |
| 33 | A backfill that moves a `projects` column which is also a preset field moves `user_project_presets` too (or says why not), and import merges a stored phase map with the current default; a schema test lists every new default-true `traffic: active` column with a keep-off decision | #126, pattern 18 |
| 34 | Every executor key read goes through `run_user_settings()` (a static test over `PhaseAwareToolExecutor`); every `ROTATION_TOOLS` tool has a runtime reader (`_build_rotator(..., '<tool>')` in recon, `_SEARCH_KEY_FIELDS` in the agent) or leaves the list | #125, #129 |
| 35 | Tier and glob audit: a hermetic file with an integration-tier name (no database, network or env) is renamed into the unit tier or allowlisted with a reason; any tracked `tests/*.sh` that is not `*_test.sh`, `*_live.sh` or `*_smoke.sh` fails; the offline modes (`rbac_upgrade_live.sh selftest`, `gen_lab.py --check-expected`) run from `*_test.sh` wrappers; one test compares the 9 tier tuples | #134, #135, 4.13 |
| 36 | The triage tables read the producers: `test_score_model.py` reads `RECON_FINDING_SOURCES` and the other writers' sources; every literal JS `finding_type` needs a `JS_RECON_CLASSES` row or a named allowlist entry; the report CASE and the board share one source -> label table | #127, #128 |
| 37 | Prose identifiers and commands: every backticked identifier in the docs, wiki, rulesets and prompts exists as a whole word in tracked code (with an allowlist of placeholders); every `./redamon.sh X` is a dispatch label and every `npm run X` a script; every env var in a doc table is read somewhere; `drift-audit.sh --docs` reads every tracked `.md`; P21 counts the downgrade tables and columns and the Tradecraft presets and settings | #139-#146, 4.14 |
| 38 | Declared mirrors become tests: every test file a code comment names is tracked, every "byte-identical" pair passes `cmp`; set equality for `SKILL_CATEGORIES` vs `agentic/skills/`, the Jev pins, the agent caps and WebSocket audiences; shared vectors for the two package-name gates (with `"x\n"` and a `%40` purl), the SCA IOC cases and the typed-host admission | #131, #138, #147, 4.3, 4.10, 4.16 |
| 39 | Extend the derived update map: a service whose `image:` is a rebuilt image is recreated or named with a reason (`kb-refresh`); build arguments from every overlay `redamon.sh` and `deploy.sh` load rebuild their service; the mount-import derivation covers every long-running service with a repository bind (kali-sandbox) | #132, #133 |
| 40 | Widen the pin tests: `test_t17_build_pins.py` over every Dockerfile, requirements file and `presets.ts` (`@latest`, `main`/`master` refs, `ARG *_REF=master`, unversioned `pip`, `npm -g`, `npx -y`) with a reasoned allowlist; `test_tool_version_pins.py` `SITES` gains the TruffleHog notes, Jev, the mcp constraint, promptfoo, `anthropic-version` and the KB model ids; an AST check refuses private-module imports from a package not pinned with `==` | 4.12, 4.17, pattern 21 |
| 41 | A floor field in `_TEST_SECTIONS` (agentic 79), and `agentic/run_tests.sh` delegating to `redamon.sh test` for the agent section or failing without its image | #136 |
| 22 | A Kali tool-presence smoke step: `command -v` every CLI the `kali_shell` description and the skill prompts name (checked by hand on 2026-10-25) | 4.1 |
| 23 | Decide whether runtime caches (`mitre_db/resources`, `wappalyzer_cache`) belong in git (the dead data is deleted and `cpe_resolver.py` reads the refreshed cache) | 4.11 |
| 24 | Derive `_ROOT_RECON_TESTS` from imports; one default model id constant per language | 4.3, 4.13 |

---

## 7. Re-running this audit

The commands behind section 3. All are read-only.

```bash
# generators: the gate runs all three Python --check modes (section 3.1); the
# JS generators are checked by the vitest suites below
python3 recon_settings/build.py --check
python3 graph_db/node_filters/build.py --check
python3 tooling/scripts/seed_schema_catalog.py --check

# rulesets, and every doc's cited paths. drift-audit exits 1 on its eight
# false positives (samugit83/redamon and samugit83/redamon-plugins in AGENTS.md,
# the loop/ and instance/ model-id prefixes, tools/list, scanners/graph_db);
# --docs lists only the seven non-paths its gate test allowlists
bash skills/skill-sync/assets/sync.sh --dry-run
bash skills/skill-sync/assets/drift-audit.sh
bash skills/skill-sync/assets/drift-audit.sh --docs

# pure-bash guards safe to run on the host (each writes only under mktemp)
bash tests/docs_cited_paths_test.sh
bash tests/drift_audit_test.sh
bash tests/redamon_update_map_test.sh
bash tests/webapp_dev_startup_parity_test.sh
bash tests/tradecraft_no_new_env_test.sh

# docs links, anchors, images and counts (P21) and cited paths, in the gate
./redamon.sh test unit   # or the single files: tests/test_docs_not_stale.py, tests/docs_cited_paths_test.sh

# settings mapping count quoted in README.SETTINGS_REGISTRY.md
python3 tooling/scripts/parse_settings_mappings.py

# which tier a test file is in (the unit gate runs only "unit"), and the shell
# files outside the gate's glob
python3 -I -c 'import sys; sys.path.insert(0, "tooling/scripts"); import pytest_isolated as p; print(p.tier_of(sys.argv[1]))' test_xxe_skill.py
ls tests/*.sh | grep -vE '_(test|live|smoke)\.sh$'

# the downgrade loss the docs quote
(cd webapp && node --input-type=module -e 'const m = await import("./scripts/rbac-upgrade-preview.mjs"); console.log(m.DOWNGRADE_TABLES.length, m.DOWNGRADE_COLUMNS.length)')

# webapp drift suites (no MCP_DOCS_WRITE, so nothing is written)
cd webapp && npx vitest run --no-file-parallelism \
  src/lib/mcp/apiReference.test.ts src/lib/reconSettings/settingsReference.test.ts \
  src/lib/mcp/toolNameDrift.test.ts src/lib/mcp/onboarding.test.ts \
  src/lib/plugins/schemasExport.test.ts src/app/graph/unseen/registry.test.ts \
  src/lib/reconSettings/registry.consistency.test.ts \
  src/lib/plugins/platformVersion.parity.test.ts \
  src/lib/apiUsage/registry.drift.test.ts src/lib/recon-preset-schema.test.ts \
  src/lib/authz/routeManifest.test.ts src/lib/authz/routePermissions.test.ts \
  scripts/gen-tradecraft-spec.test.ts src/lib/authz/builtinSets.test.ts \
  scripts/gen-rbac-matrix-rows.test.ts
```

On 2026-11-19 the first 14 suites gave 378 passed and 1 skipped (the write-mode
case); at the re-map the same day, all 15 gave 401 passed and 1 skipped. Further parity suites worth adding to a run: `agentContract.test.ts`,
`passwordPolicy.drift.test.ts`, `scanWindow.vectors.test.ts`,
`triage/disposition.test.ts`, `websocket-types.parity.test.ts`.

The rest is done by comparing lists directly. The checks worth repeating:

- **Tool lists:** `TOOL_REGISTRY` keys vs `TOOL_PHASE_MAP` vs the Prisma
  `agentToolPhaseMap` default vs `ToolMatrixSection.tsx` ids vs
  `BUILTIN_RESERVED_TOOL_NAMES`; every tool name in `CATEGORY_TOOL_MAP`, the
  discovery fallback and `_validate_mutex_groups` against `TOOL_REGISTRY`.
- **Split paths:** every rule in `execute_plan_node.py` has a twin in
  `execute_tool_node.py` (and the reverse), the fireteam nodes included; every
  `set_tenant_context` call passes the same arguments (#89).
- **Coding-agent prompts:** every function, constant and file a prompt in
  `docs/readmes/coding_agent_prompts/` names still exists, its `~line` hints
  and `#L` anchors land on it, and its layer counts equal the skill's table.
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
  `recon/helpers/cdn_edge_prefixes.py`, the "as of" date of
  `AI_FAVICON_HASHES` and the "Checked on" date of the Tradecraft featured sites.
- **Tiers and globs:** every test file this page credits as a guard is unit tier
  (the command above), and no hermetic check sits in a `test_*.sh` or `*_live.sh`.
- **Declared mirrors:** `git grep -nIiE 'mirror|keeps? in sync|kept in sync|must
  (match|equal)|twin of|byte.identical|parity' -- . ':!*.md'`; compare each pair,
  and check that every test file a comment names is tracked.
- **Triage tables:** `RECON_FINDING_SOURCES` and the other writers' `source`
  values against `CONFIDENCE_BY_SOURCE`; every `"finding_type": "..."` the JS
  writers stamp against `JS_RECON_CLASSES`; both against the report CASE.
- **Key reads and rotation:** every key read in `PhaseAwareToolExecutor.execute`
  uses `run_user_settings()`; `ROTATION_TOOLS` against the `_build_rotator(...)`
  calls and `_SEARCH_KEY_FIELDS`.
- **Stored data:** for each backfill script, the tables it touches against every
  table holding the same column (`user_project_presets`, export bundles); every
  new `@default(true)` column with `traffic: active`; the ids rows store
  (permissions, scopes, set slugs, feature ids) against their registries.
- **Pins:** `git grep -nE '@latest|/(main|master)/|_REF=master' --
  '*Dockerfile*' '*requirements*' webapp/src/lib/mcp/presets.ts`; one version
  per tool across recon and Kali.
- **Prose identifiers and commands:** backticked identifiers in the docs against
  `git grep -w` in code; every `./redamon.sh <cmd>` against the dispatch `case`;
  every env var in a doc table against its readers; `tool_registry.py`'s
  proxy_brain section list against the manual's headings.

When you fix an item from section 2, delete its row. When you add a new copy
of a fact anywhere in the repository, add a row to section 4, or better, a guard
from section 6.
