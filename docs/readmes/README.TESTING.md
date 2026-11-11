# RedAmon testing guide

This document has two audiences: the human maintainer, and **the next Claude Code
session, which reads it before writing or running a test**. It is therefore an
applied rulebook, not just reference. If you are about to add or run a test, read
the [authoring rules](#test-authoring-rules-hard-rules) first.

---

## TL;DR

```bash
./redamon.sh test              # unit gate across every section (the canonical gate)
./redamon.sh test unit         # same
./redamon.sh test integration  # integration tier (heavier deps / cross-layer)
./redamon.sh test all          # unit + integration
./redamon.sh test live         # live tier (self-skips when the stack is down)
./redamon.sh test coverage     # all tiers + per-section coverage + floor

./agentic/run_tests.sh         # just the agent image, unit gate (fast path)
./agentic/run_tests.sh coverage
./agentic/run_tests.sh tests/test_foo.py::TestBar::test_baz   # one node id
```

The **unit tier must be 100% green** — that is the gate (the modern replacement for
the old hand-maintained 31-module `focused` list; `focused` still works as an
alias for `unit`).

---

## How it is built

- Runner: **pytest**, which runs the existing `unittest.TestCase` tests unchanged.
  This was a runner swap, not a test rewrite.
- Tests run **inside each section's Docker image** (where `pydantic`, `langgraph`,
  `tree-sitter`, ripgrep, etc. live). The whole repo is mounted at `/repo` so
  cross-layer tests and `git HEAD` resolve.
- Config lives at each in-container test root: a small `pytest.ini` +
  `conftest.py` at `agentic/`, `recon/`, `recon_orchestrator/`,
  `scanners/ai_attack_surface_scan/`, `scanners/capture_proxy/`, `services/docker_broker/`, and the repo root.
  Keep the `conftest.py` copies in sync — they are intentionally near-identical.
- Test deps are `requirements-test.txt` (`pytest`, `pytest-cov`, `pytest-xdist`,
  `pytest-asyncio`). They are **baked** into the daily-driver images
  (`agentic/requirements.txt`, `recon/requirements.txt`) and **runtime-installed**
  into the occasional-run slim images by the runner.

### Section / image map

| Section | Image | Test root(s) |
|---|---|---|
| agent | `redamon-agent` | `agentic/tests` |
| root group | `redamon-agent` | `tests/`, `supply_chain_*`, `graph_db`, `knowledge_base`, `mcp` |
| recon | `redamon-recon` | `recon/tests` |
| recon_orchestrator | `redamon-recon-orchestrator` | `recon_orchestrator/` + `recon_orchestrator/tests` |
| ai_attack_surface | `redamon-ai-attack-surface` | `scanners/ai_attack_surface_scan/tests` + `adapters/*/tests` |
| capture_proxy | `redamon-capture-proxy` | `scanners/capture_proxy/tests` |
| docker_broker | `redamon-docker-broker` | `services/docker_broker/` |
| plugin_runner | `redamon-plugin-runner` | `services/plugin_runner/tests` |
| shell | (host bash) | `tests/*_test.sh` |
| webapp | (node) | `webapp/src/**/*.test.ts(x)` via vitest |

A section that cannot run (its image is not built, or the shell or webapp suite is
missing its input) **fails** the `unit`, `all` and `coverage` gates: a suite that never
ran proves nothing. Other tiers print `SKIP` and go on. The deliberate opt-out for a working
copy that genuinely lacks an input is `REDAMON_TEST_ALLOW_MISSING=<section>[,<section>...]`
(or `all`), which prints a `SKIPPED` line so the hole is visible in the log
(`_test_missing_input` in `redamon.sh`).

### The wiki checkout

`redamon.wiki/` is a git submodule: `.gitmodules` declares it, and
`tests/test_wiki_submodule.py` checks the declaration. A clone made without
`--recurse-submodules` leaves it empty, and then every wiki-dependent test
**fails** instead of skipping, because a skip there would pass while checking
nothing. Those tests are `tests/test_docs_not_stale.py`,
`tests/docs_cited_paths_test.sh`, the community-skill tests in `agentic/tests/`
that read `Agent-Skills.md`, and the webapp's `apiReference`, `settingsReference`,
`scopeCopy`, `onboarding` and `profiles` tests under `webapp/src/lib/`. Fill the
checkout with `git submodule update --init redamon.wiki`, or opt out with
`REDAMON_TEST_ALLOW_MISSING=wiki` (or `all`), which the gate forwards into every
section's container: the wiki checks then skip with
`SKIPPED: no wiki checkout, allowed by REDAMON_TEST_ALLOW_MISSING`, and
`./redamon.sh test` prints a `SKIPPED the wiki checks` line. The rule lives in
`tooling/scripts/wiki_checkout.py`, with its TypeScript twin in
`webapp/src/lib/wikiCheckout.testUtils.ts`.

### Drift guards

Tests that fail when one copy of a fact moves and another does not. The full
list, with what each one cannot see, is section 3 of
[README.DRIFT_MAP.md](README.DRIFT_MAP.md); the ones you meet when you edit docs
or generated files:

| Guard | Fails when |
|---|---|
| `tests/test_docs_not_stale.py` | a doc's wiki link, anchor, image or count no longer holds, or an agent-facing guide names something deleted or tells you to hand-edit a generated file. Today's known drift is allowlisted in `tests/fixtures/docs_drift_{wiki,readmes,root}.json`, and an entry that stops failing must leave its file |
| `tests/docs_cited_paths_test.sh` | a doc cites a repository path git does not track (`drift-audit.sh --docs`), against the allowlists in `tests/fixtures/docs_paths_drift_{wiki,readmes,root}.json` under the same rule |
| `tests/drift_audit_test.sh` | `skills/skill-sync/assets/drift-audit.sh` stops reporting a dead link or a basename-only match |
| `tests/test_registry_build_check.py` | the settings registry's generated files are stale (`recon_settings/build.py --check`) |
| `tests/pre_commit_hook_test.sh` | `tooling/hooks/pre-commit` stops blocking a commit that leaves a generated artifact stale, or blocks one that does not touch a generator |
| `tests/redamon_update_map_test.sh` | `./redamon.sh update` would not rebuild (or restart) an image whose `COPY` sources changed |
| `tests/redamon_gate_unskippable_test.sh` | the gate could go green with a section's image or `webapp/node_modules` missing |

### The `shell` section

Parts of RedAmon are bash, not Python: the proportional memory allocator, the
preflight RAM/disk gates, secret and admin handling, and the `tooling/deploy`
driver. Those are covered by `tests/*_test.sh`, which run **on the host** (they
`source redamon.sh` — the `BASH_SOURCE` guard at the bottom of the script stops
the command dispatch from firing) and need no image.

They run in the same tiers as webapp (`unit`, `all`, `coverage`), so the
canonical `./redamon.sh test` gate covers them. Every suite matched by the glob
must be **hermetic or self-skipping**: one that needs a live stack (e.g.
`scan_timeline_db_test.sh` without postgres) prints a `SKIP` line and exits 0.
Smoke/live shell suites are named `*_smoke.sh` / `*_live.sh` and are deliberately
not matched.

### The plugin platform

The plugin platform ([README.PLUGINS.md](README.PLUGINS.md)) is tested at every level:

| Layer | Where | Tier |
|---|---|---|
| Runner, worker, proxy, SDK | `services/plugin_runner/tests/` (the `plugin_runner` section; build the image first: `docker compose --profile plugins build plugin-runner`) | unit / integration |
| Webapp platform (catalog, archives, Manager, Gateway, overrides, UI host) | `webapp/src/lib/plugins/**/*.test.ts`, `src/app/api/plugin*/**`, `src/components/plugins/**`, `src/app/plugins/**` | vitest |
| Agent seam and endpoints | `agentic/tests/test_skill_parts_*.py`, `test_skill_workflow_golden.py` (the factory prompt pinned byte for byte), `test_plugin_llm_endpoint.py` (and `test_plugin_llm_live.py`, live tier, which skips without a configured provider) | unit |
| `redamon.sh` and compose | `tests/redamon_plugins_env_test.sh`, `redamon_plugins_lifecycle_test.sh` (install, update, up, old clones, refused hosts, all with a stubbed `docker`), `redamon_plugins_profile_test.sh`, `plugins_db_test.sh` | shell |
| Single-host deploy | `tests/deploy_plugins_env_chain_test.sh`, `deploy_plugins_nginx_test.sh` (the three plugin-internal prefixes denied at nginx) | shell |
| Isolation, live | `tests/plugins_isolation_live.sh`: runs a probe inside the runner and the proxy and fails on any leak (internet, stack services, host through the bridge, `/plugins` writes, worker environments). Needs a stack started with `./redamon.sh up`; not in the gate | live |
| Official catalog, live | `webapp/src/lib/plugins/catalog.live.test.ts`: opt-in with `PLUGINS_LIVE=1` (network), optionally `PLUGINS_LIVE_EXPECT=<id>@<version>`; skipped otherwise | live |
| Real Postgres | `webapp/src/lib/plugins/{stores,lifecycle,jobs,userSkillAdoption}.pg.integration.test.ts`, `webapp/src/lib/userSkillNames.pg.integration.test.ts`, `webapp/scripts/backfill-user-skill-toggles.pg.integration.test.ts`, `webapp/scripts/e2e-rbac-cleanup.pg.integration.test.ts`: the SQL name key, the advisory locks, the CHECK constraints, the toggle backfill and the live-check fixture cleanup's checkpoint SQL, on a DISPOSABLE database after `prisma db push` and `scripts/apply-plugin-constraints.mjs`. Opt-in with `PLUGINS_PG_TEST_URL`; skipped otherwise, so **not in the gate**: run them after changing any of that | integration |
| End to end | `testing/e2e/tests/pluginsPage.spec.ts` (install and uninstall the `echo` test plugin) and `pluginsSkiller.spec.ts` (Skiller: analyse a seeded session, review, approve, versions, reset) | Playwright |

Hermetic doubles, all in `webapp/src/lib/plugins/__testing__/` (no production module may import
them; `noProductionImports.test.ts` checks): an in-process fake catalog and archive server on
`127.0.0.1` ephemeral ports (`fakeHttpServer.ts`, `catalogBuilder.ts`), a fake runner, a fake
Prisma, and a throwaway Ed25519 key per test. Time comes only from `src/lib/plugins/clock.ts`,
so tests pin it. On the Python side the SDK ships `FakeSdk`, `ScriptedLlm` and `make_context`
for plugin tests, and a contract suite (`sdk/contract_cases.json`) runs against both the fake
and the real Gateway.

The e2e specs need a stack started with `./redamon.sh up`. `pluginsPage.spec.ts` builds its fixtures with
`testing/e2e/scripts/make-plugin-fixtures.mjs`, which signs them with a throwaway key and prints
the `PLUGINS_EXTRA_TRUSTED_KEYS` value to set before `./redamon.sh up`. `pluginsSkiller.spec.ts`
installs Skiller from `SKILLER_DIST` (default `../../redamon-plugins/dist`, packed and signed with
a development key) or, with `SKILLER_FROM_CATALOG=1`, from the official catalog. It drives the model
through `testing/e2e/scripts/stub-llm-server.mjs`, registered as an OpenAI-compatible provider for
the run and removed at the end, and analyses `testing/e2e/fixtures/skiller-session.json`. Each
spec skips itself when its files are missing.

### Agent in the Loop

Agent in the Loop (the `loop/mcp` brain, the `agent-in-the-loop` skill) is tested at three levels:

| Layer | Where | Tier |
|---|---|---|
| Broker, adapter, prompt document, routes | `agentic/tests/test_loop_*.py`, `test_agent_in_the_loop_settings.py`, `test_ws_session_cap.py` (the session cap counts live runs). `test_loop_flow.py` drives a whole run (guardrail, think, tool, report) through the real broker with a scripted driver | unit |
| MCP tools, token rule, refusals, drawer, onboarding pack | `webapp/src/lib/mcp/loop*.test.ts`, `server.loopAudit.test.ts`, `src/lib/agentInTheLoop*.test.ts`, `hooks/loopStatus.test.ts`, `ChatArea.loop.test.tsx`, `ModelPicker.loopFilter.test.tsx`, `agentSessions.loop.test.ts`, `projects/import/route.loopModel.test.ts` | vitest |
| Compose and deploy wiring | `tests/redamon_mcp_env_test.sh`, `tests/deploy_mcp_env_chain_test.sh` (the switch reaches both containers) | shell |
| End to end | `testing/e2e/tests/agentInTheLoop.spec.ts`: a scripted driver over `/api/mcp-server` answers a real run against the `skiller_sqli_csrf` lab; needs a stack with `AGENT_IN_THE_LOOP_ENABLED=true` and `MCP_SERVER_ENABLED=true`, and skips itself otherwise | Playwright |

Every MCP test that stubs `MCP_KALI_EXEC_ENABLED` also stubs `AGENT_IN_THE_LOOP_ENABLED`: both
switches change `tools/list`, and a host whose `.env` turns one on would otherwise see a different
tool count from the one the test pins.

### The live RBAC route matrix

`tests/rbac_matrix_live.sh` asks the running webapp who may call which route, as rows of
`tests/fixtures/rbac_matrix/<file>.tsv` (`id`, `since`, `actor`, `method`, `path`, `body`,
`expect`, `tags`; the format is in the script's header). `baseline.tsv` is today's behaviour,
recorded on untouched code: a later change that moves an owner's answer shows up as a `FAIL`.

```bash
bash tests/rbac_matrix_live.sh baseline        # one or more files, or: all
RBAC_MATRIX_ROWS='^bl-settings-' bash tests/rbac_matrix_live.sh baseline   # re-run some rows
```

It needs a stack on `:3000` (`BASE_URL` overrides it) and prints `SKIP` otherwise; as a
`*_live.sh` it is never in the gate. It seeds synthetic accounts and projects
(`webapp/scripts/e2e-rbac-seed.mjs`: `rbac-*@e2e.local`, `rbac.test`) and always removes them
(`e2e-rbac-cleanup.mjs`, Ctrl-C included); both are fed to the webapp container on stdin, so no
image rebuild is needed. Rows never start a scan or an agent run. Response bodies are never
printed, and the internal and scanner keys are read from `.env` only for their rows. Two actors
of `p1.tsv` change the users table through `psql` in the `postgres` container: `admin_b_demoted`
(and `admin_b_as_<user>_demoted`) keeps the cookies `rbac-admin-b` got as an admin, is demoted
to `standard` just before its row and restored right after; `deleted` signs in as the
throwaway `rbac-deleted` account, which is then deleted, and replays its still-valid cookie. The
Playwright helper `testing/e2e/tests/rbacUsers.ts` signs in as any of those accounts through the
real form (`seedRbac`, `loginAs`, `cleanupRbac`); `rbacUsers.spec.ts` shows the use.

`tests/rbac_user_audit_live.sh` uses the same fixtures to check the audit of user
administration: `rbac-admin-a` creates, edits, promotes, demotes, resets and deletes a throwaway
`rbac-audit-*@e2e.local` account, and `audit_log` must hold exactly those six rows, in order,
with that admin as actor and no password or hash; it then checks that the act-as end row names
its target and that a logout row names who signed out. It reads both audit tables through `psql`
in the `postgres` container and prints `SKIP` without a stack.

`tests/rbac_user_delete_teardown_live.sh` deletes a throwaway `rbac-teardown-owner@e2e.local`
account whose project holds an engagement authorization, a `Domain` node and a
`recon_<id>.json`: the delete must answer 200 and leave no account, project, authorization row,
graph node or file, with the record archived as `user_deleted` and a `user.delete` row listing
the project. Its trap removes every fixture, the archive row included. It also needs the
`neo4j` and `recon-orchestrator` containers, and prints `SKIP` without them.

`tests/rbac_kali_terminal_live.sh` checks the Kali terminal gate: a member created after the
upgrade is refused a `kali-terminal` ticket and still gets a chat ticket, a member given the
`kali_terminal` legacy grant by SQL gets one (audited `agent.terminal_opened`), and, inside the
agent container (`tests/rbac_kali_terminal_live_ws.py`, fed on stdin with the tickets), a chat
ticket does not open the terminal, the sandbox's `:8016` refuses an upgrade without the agent's
bearer, the shell runs as the ticket's user and project whatever the init frame says, and
`POST /ws/close` ends the open terminal with close 4403. It also needs the `agent` and
`kali-sandbox` containers.

`tests/rbac_legacy_review_live.sh` checks the admin review of legacy grants: a member is refused
`/api/admin/legacy-grants` and gets no `rbac` block from `/api/auth/me`; no request adds a grant;
an admin's Keep and Remove each write one audit row; removing the `kali_terminal` grant closes the
holder's open terminal (watched inside the agent container by
`tests/rbac_legacy_review_live_ws.py`) and refuses its next ticket; the "What changed" card's
dismissal sticks. It decides only fixture accounts' grants, never `keep_all` or `remove_all`,
which would decide the stack's real members' grants. It needs the same containers.

### The RBAC upgrade harness

`tests/rbac_upgrade_live.sh` runs a webapp image's own startup list (its `/app/entrypoint.sh`
without `exec node server.js`) against synthetic 7.7.x-shaped databases, in throwaway
containers on a private network, and checks what the upgrade did. The scenarios are full dumps
in `tests/fixtures/rbac_upgrade/` (one admin, several, none, passwordless admins, tunnel and
capture rows, members with and without passwords), made with the pinned image
`redamon-webapp:rbac-7.7.2` so they keep the 7.7.x shape while `redamon-webapp:latest` moves
on. After every run it asserts that the row count of every table and every `users` column are
unchanged, and diffs `checks.sql` against `expected/<scenario>.out`.

```bash
bash tests/rbac_upgrade_live.sh all twice parallel failure   # the regression chain
RBAC_UPGRADE_SCENARIOS='^one_admin$' bash tests/rbac_upgrade_live.sh twice
bash tests/rbac_upgrade_live.sh serve several_admins   # 127.0.0.1:3901 until Ctrl-C
```

`twice` runs the list twice; `parallel` starts two containers at once (several webapp copies);
`failure` deletes a backfill's marker, holds a lock on the table it reads and re-runs only that
backfill with a 2 s `lock_timeout`: it must log the failure, exit 0 and write no marker, and the
next run completes it. `serve` boots the server on the scenario database with fake secrets, the
disposable instance for checks that would move or sign out the dev stack's own admin. It needs
Docker, `redamon-webapp:latest`, `redamon-webapp:rbac-7.7.2` and `postgres:16-alpine`, and
prints `SKIP` without one (it never pulls or builds); as a `*_live.sh` it is never in the gate.
The fixtures' README explains the password, the regeneration (`regen` mode) and how to rebuild
the pinned image with `git archive 442debbf:webapp | docker build -t redamon-webapp:rbac-7.7.2 -`.

### The scripted stub model (agent runs without a real LLM)

`testing/e2e/scripts/stub-llm-server.mjs` answers an agent prompt with `OK.`, which the agent
cannot parse, so a run stops at once. Its scripted mode drives a real run: `STUB_LLM_SCRIPT=<file>`
names a JSON list of turns `{match, content, delayMs?, repeat?, note?}`. A request takes the first
unused turn whose `match` is a substring of the latest user or tool message; the turn is then
spent unless `repeat` is true; with no hit the stub answers as before. `content` is sent as is, or
as JSON when it is an object. A delayed streamed turn sends SSE comments while it waits, so the
provider's 120 s read timeout does not cut it. `GET /__calls` lists which turn answered each call.

| The agent asks | Latest user message contains | It expects |
|---|---|---|
| scope guardrail (at the start, and again on every resume until a step has run) | `for a penetration testing scan:` | `{"allowed": true, "reason": "..."}` |
| intent router | `You are classifying a penetration testing request` | `{"required_phase", "attack_path_type", "confidence", "reasoning"}` |
| think node (every iteration) | `what is your next action` | one `LLMDecision` JSON: `thought`, `reasoning`, `action`, plus `tool_name`/`tool_args`, `phase_transition`, `completion_reason` as the action needs |

The scripts in `testing/e2e/scripts/stub-llm-scripts/` (guardrail and router turns are `repeat`):
`approval.json` asks for the exploitation phase (the phase approval prompt), then completes;
`kali-shell-env.json` calls `kali_shell` with `env | grep -cE '...'` (a tool confirmation first),
then completes; `long-run.json` answers its first think turn after 120 s. To use one, start the
stub on the address the agent reaches the host by (`docker exec redamon-agent getent hosts
host.docker.internal`), register it as an `openai_compatible` provider of the project's owner
(`http://host.docker.internal:<port>/v1`) and set the project's `agentOpenaiModel` to
`custom/<providerId>`. One stub per run: turns are spent per process. The fixture cleanup
(`e2e-rbac-cleanup.mjs`) also clears the fixture projects' graph nodes (shared `CVE`, `MitreData`
and `Capec` nodes stay) and the checkpoint rows of their agent runs, and of any `rbac-*` session
whose user and project are both gone, before it deletes a row; when Neo4j or the checkpoint delete
fails it deletes nothing and exits 1, so a rerun finishes the job. The matcher has its own test,
outside the gate:

```bash
node --test testing/e2e/scripts/stub-llm-server.test.mjs
```

### Two oracles, and only one of them runs in the gate

Some unit-tier files mix hermetic checks with checks that need a live Neo4j and
self-skip without one. The graph-schema suites are the example, and the split is
deliberate rather than accidental:

| Check | Needs a database | Runs in the gate |
|---|---|---|
| every relationship/property the CODE writes is documented (`test_graph_writes_documented.py`) | no | **yes** |
| every relationship/property in a LIVE graph is documented (`test_schema_catalog.py`) | yes | no, skips |

Both are needed because neither sees everything. The code scan misses the 22
labels written with `SET n += $props`, where the property names are assembled in
Python and appear in no file. The live graph misses every feature this
particular deployment never ran.

So a green gate does NOT mean the live-graph checks passed - it usually means
they skipped. Run them against a stack before trusting a schema change:

```bash
NEO4J_PASSWORD="$(grep '^NEO4J_PASSWORD=' .env | cut -d= -f2-)" \
docker run --rm --network host --entrypoint python3 \
  -e NEO4J_URI=bolt://localhost:7687 -e NEO4J_USER=neo4j -e NEO4J_PASSWORD="$NEO4J_PASSWORD" \
  -v "$PWD:/work:ro" -w /work redamon-recon:latest recon/tests/test_schema_catalog.py
```

Mute Rules (node filters in the code) have the same split. The unit tier pins
the rule decisions against a fake graph and a mocked Prisma; three checks need
real services and skip in the gate. Run them after touching the engine
(`graph_db/node_filters/`, `node_filter_mixin.py`) or `webapp/src/lib/nodeFilterRun.ts`:

| Check | Needs | How to run |
|---|---|---|
| the sweep's real Cypher: keyset paging, the guard re-check in the mute write, tenant scoping, `updated_at` never touched (`tests/test_node_filters_graph_live.py`) | Neo4j | the command in the file's docstring (agent image, on `redamon-network`) |
| one live apply per project, decided by Postgres's serializable transaction (`webapp/src/lib/nodeFilterRun.integration.test.ts`) | Postgres | set `DATABASE_URL`; the command is in the file's header |

A failing file is reported with the command to re-run it on its own:

```
  FAIL  redamon_governor_test.sh (exit 1) — re-run: bash tests/redamon_governor_test.sh
```

---

## Tiers and auto-tiering

Three markers: `unit`, `integration`, `live`. Rather than editing hundreds of
files, each `conftest.py` auto-marks by **filename**:

- `*_integration.py`, `*_skill.py`, `*_e2e*` -> **integration**
- `live_*`, `*_live*`, `*_smoke*`, `smoke_*` -> **live** (self-skip when a stack is down)
- everything else -> **unit**

Override with an explicit `@pytest.mark.{unit,integration,live}`, on the file or
on a single test inside it.

The gate engine (`tooling/scripts/pytest_isolated.py`) infers the same tiers from the
filename to pick which FILES to run, so the two must stay consistent - and it also
passes the tier to pytest as `-m`, so a single test that has opted out of the tier
its filename implies is honoured. Without that `-m`, filename selection alone
cannot see inside a file: a wall-clock test marked `integration` still ran in the
unit gate and failed whenever the parallel run loaded the host.

---

## Determinism: why each test file runs in its own process

A large body of these tests was written for the old per-file
`python -m unittest tests.test_x` runner, where **every file was its own process**.
Many of them, at import time:

- stub `langchain`/`langgraph` into `sys.modules` (`if X not in sys.modules: ...`), and
- **bake real tool objects against a fake `@tool` decorator** during import.

In a single shared pytest process this is order-dependent: whichever file is
collected first decides for all of them, so e.g. the Shodan tool silently becomes
a `MagicMock` and its tests fail with *"a coroutine was expected, got
`<MagicMock>`"*. This is exactly the class of phantom failure that sends an AI
author "fixing" code that was never broken.

The fix is structural: the gate runs **each test FILE in its own pytest
subprocess**, parallelized, via `tooling/scripts/pytest_isolated.py`. That reproduces the
isolation the tests were designed for and makes the gate deterministic.

Consequences you must know:

- `./redamon.sh test` / `./agentic/run_tests.sh` are deterministic. Prefer them.
- Running `pytest -m unit` over the **whole tree in one process** is *not* the gate
  and may show phantom failures from legacy import-time stubbing. Each
  `conftest.py` adds a `pytest_ignore_collect` that makes a single-process
  `-m unit` run at least skip importing the heavier integration/live files, but
  per-file isolation is still the source of truth.
- A single file, or a single node id, is already isolated — use that while iterating.

Two determinism helpers also live in every `conftest.py`:

- an autouse `_ensure_event_loop` fixture (restores a usable event loop after a
  `unittest.IsolatedAsyncioTestCase` sets it to `None`), and
- the auto-tiering + `-m unit` path-scoping hooks above.

---

## The surgical loop (iterate cheaply)

Each containerized full run costs latency + context. When a test is red, do NOT
re-run the whole suite. Read the precise failure and re-run just that test:

```bash
# one node id, single process (isolated), short traceback:
./agentic/run_tests.sh tests/test_execute_nodes.py::TestCheckRoeBlocked::test_forbidden_tool_blocked

# stop at first failure while iterating, re-run only last failures:
./agentic/run_tests.sh tests/test_foo.py -x
./agentic/run_tests.sh tests/test_foo.py --lf
```

`addopts` in each `pytest.ini` already sets `-ra --tb=short --strict-markers -p
no:cacheprovider` for concise, deterministic output.

---

## Coverage

`./redamon.sh test coverage` (or `./agentic/run_tests.sh coverage`) runs the
unit+integration tiers with `pytest-cov` and prints per-section totals.
`COVERAGE_FILE=/tmp/redamon.coverage` keeps root-owned `.coverage` files out of
the bind mount.

Coverage runs **serially with `--cov-append`** (parallel appends can corrupt the
data file). The floor is enforced with `--cov-fail-under`; set it per section via
`REDAMON_COV_FLOOR` (or the section spec in `redamon.sh`).

To **ratchet** a floor: run coverage, read the section total, set the floor to
`floor(total) - 2`. Measured agentic total (unit+integration) is **81%** — once
the import-time pollution was fixed, real coverage was far above the depressed
41% the old polluted `discover` run reported — so the agentic floor is **79**
(`REDAMON_COV_FLOOR`, default in `agentic/run_tests.sh`). supply_chain baseline
to beat is 72%.

> **The floor guards against rot, not quality.** Because an AI writes these tests,
> the number is gameable by hollow tests that execute code and assert nothing. The
> real quality gate — mutation testing on security-critical modules — is future
> work. The interim defense is the authoring rules below.

---

## Test-authoring rules (hard rules)

1. **Assert on behavior and output, not mere execution.** A test that runs code
   but checks nothing is worse than no test — it inflates coverage and asserts
   nothing.
2. **Name each test as the guarantee it enforces**
   (`test_edit_rejects_non_unique_target`), never `test_edit_2`. The name is the
   spec a human reviews.
3. **Do not assert "current behavior" you have not confirmed is correct.** Tests
   must not enshrine bugs. If a test reveals a real bug, mark it
   `@pytest.mark.xfail(strict=True, reason=...)` and surface it — do not rewrite
   it to pass.
4. **Never mock the unit under test.** Keep an `integration` test that exercises
   the real dependency so the mocks cannot drift from reality.
5. **Never mutate global state (`sys.modules`, `os.environ`, cwd) at import time.**
   Use fixtures or `mock.patch.dict(sys.modules, {...})` / `mock.patch.dict(
   os.environ, {...})` scoped to a single test. If you must shim at import time
   (e.g. to import a module on bare Python), **capture the originals and restore
   them in `tearDownModule()`** — see `agentic/tests/test_t14_prompt_injection_previews.py`
   for the reference pattern. Leaving a stub in place drops later-imported victims
   to 0% coverage and breaks their collection.

### Environmental prerequisites (bucket 2)

A test that needs a live stack, a network service, a tool binary, or git HEAD
must **self-skip cleanly** (`skipUnless`/`skipIf` / `raise unittest.SkipTest`),
never hard-fail. If it currently hard-fails on a missing prerequisite, that
missing skip-guard *is* the bug.

---

## Adding a test to a tier

- **unit**: name it `test_*.py` with no special suffix. It must be hermetic (no
  network, no running stack) and pass in its own process.
- **integration**: name it `*_integration.py` / `*_skill.py`, or add
  `@pytest.mark.integration`. It may reach across layers / use heavier deps.
- **live**: name it `live_*` / `*_live*` / `*_smoke*`, or add `@pytest.mark.live`,
  and make it self-skip when the stack/service is absent.

---

## Future work / next steps

- **CI**: run the unit gate on every PR and the full `all` tier nightly.
- **Mutation testing** on the security-critical modules (supply-chain, auth /
  access control) as the *real* quality gate — coverage alone is not one.
- **HTTP record/replay** (`respx` / VCR) so the `live` tier shrinks.
- **Playwright e2e** wired into the gate (see `testing/e2e/`).
