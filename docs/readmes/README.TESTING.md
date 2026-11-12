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
| Single-host deploy | `tests/deploy_plugins_env_chain_test.sh`, `deploy_plugins_nginx_test.sh` (the three plugin-internal prefixes denied at nginx), `deploy_rbac_nginx_test.sh` (`/api/internal/`, the tunnel credentials and the tunnel sync denied at nginx) | shell |
| Isolation, live | `tests/plugins_isolation_live.sh`: runs a probe inside the runner and the proxy and fails on any leak (internet, stack services, host through the bridge, `/plugins` writes, worker environments). Needs a stack started with `./redamon.sh up`; not in the gate | live |
| Official catalog, live | `webapp/src/lib/plugins/catalog.live.test.ts`: opt-in with `PLUGINS_LIVE=1` (network), optionally `PLUGINS_LIVE_EXPECT=<id>@<version>`; skipped otherwise | live |
| Real Postgres | `webapp/src/lib/plugins/{stores,lifecycle,jobs,userSkillAdoption}.pg.integration.test.ts`, `webapp/src/lib/userSkillNames.pg.integration.test.ts`, `webapp/scripts/backfill-user-skill-toggles.pg.integration.test.ts`, `webapp/scripts/e2e-rbac-cleanup.pg.integration.test.ts`, `webapp/scripts/{backfill-rbac-legacy-grants,backfill-nuclei-template-owners,backfill-rbac-root,rbac-upgrade-preview,db-push-locked}.pg.integration.test.ts`: the SQL name key, the advisory locks, the CHECK constraints, the toggle backfill, the live-check fixture cleanup's checkpoint SQL, the RBAC boot backfills (legacy grants, Nuclei template owners, Root), the read-only upgrade preview (with and without the `instance_settings` table) and the serialized boot `db push` (that one creates and drops its own throwaway database beside the one named), on a DISPOSABLE database after `prisma db push` and `scripts/apply-plugin-constraints.mjs`. Opt-in with `PLUGINS_PG_TEST_URL`; skipped otherwise, so **not in the gate**: run them after changing any of that | integration |
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
throwaway `rbac-deleted` account, which is then deleted, and replays its still-valid cookie.
`p2.tsv` adds `<user>_revoked` (for example `member_a_revoked`): the account's session version is
raised just before the row and put back right after, so the row sends a cookie of an older
version; `;hdr=<text>` / `;nohdr=<text>` check the answer's headers (the cleared cookie). With
`RBAC_IDENTITY_ENABLED` on, the webapp keeps an account it read for `RBAC_AUTHZ_CACHE_MS`, so the
runner waits that long after each of these SQL changes (it reads both values from the webapp
container and prints the wait once). A row tagged `identity:on` or `identity:off` runs only while
the webapp's switch is so and is a SKIP otherwise: with the switch off a refused cookie is kept and
`/api/auth/me` answers a bare 401, with it on the cookie is cleared and the 401 says
`session_ended`. `permissions:on` / `permissions:off` do the same for `RBAC_PERMISSIONS_ENABLED`,
which reads off while the identity switch is off, as in the webapp; the equivalence check of the
permission engine (PE-28) runs `baseline p1 p2` with the identity switch on, once with the
permissions switch on and once off, and expects the same results. The runner's tag handling has a
hermetic suite, `tests/rbac_matrix_runner_test.sh` (stubbed `docker` and `curl`, in the gate). Every
non-GET row sends the webapp's own `Origin`, as a browser does; a row tagged
`origin:<url>` sends that one instead, so `p2.tsv`'s `p2-xo-*` rows play a page of another site
against the identity routes, which answer 403 `cross_origin`. The
Playwright helper `testing/e2e/tests/rbacUsers.ts` signs in as any of those accounts through the
real form (`seedRbac`, `loginAs`, `cleanupRbac`); `rbacUsers.spec.ts` shows the use.

`tests/rbac_user_audit_live.sh` uses the same fixtures to check the audit of user
administration: `rbac-admin-a` creates, edits, promotes, demotes, resets and deletes a throwaway
`rbac-audit-*@e2e.local` account, and `audit_log` must hold exactly those six rows, in order,
with that admin as actor, its email in `actor_email`, nobody in `on_behalf_of_user_id` and no
password or hash; it then checks that the act-as end row names
its target and that a logout row names who signed out, with their email. It reads both audit tables through `psql`
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

`tests/rbac_nuclei_templates_live.sh` checks template ownership over HTTP: a member's upload cannot be overwritten, seen, deleted or selected by another member (nor reached through a free-form path), a scan's settings read drops it even when written behind the save's back, an admin overwrites and promotes it, and a deleted member's templates pass to the deleting admin. Its templates live under `rbac-e2e/` in the shared templates folder; the trap removes them.

`tests/rbac_run_credential_live.sh` checks the sandbox side: no Kali process holds `SCANNER_API_KEY`, the agent's `/graph/exec`, `/text-to-cypher` and `/traffic/exec` refuse the bare scanner key and take a run credential (an expired one, another audience's, one whose terminal has closed and a traffic one of another run are refused with their codes), and `redagraph` answers in a legacy holder's terminal (`tests/rbac_run_credential_live_ws.py`, inside the agent container). It needs the `agent` and `kali-sandbox` containers.

`tests/rbac_job_credential_live.sh` checks the scan side: the bare scanner key reads no settings or project and ingests nothing, the key with a job credential reads only that tenant and project, the agent's `/llm/*` and `/jev/*` refuse a body naming someone else, the orchestrator refuses a start without a credential or with a forged one, and a real one-phase partial recon (Shodan, on the reserved name `rbac.test`) runs with a container that holds the credential and no `INTERNAL_API_KEY` (`tests/rbac_job_credential_live_checks.py`, inside the agent container). It needs the agent and the orchestrator.

`tests/rbac_set_root_live.sh` runs the host Root commands on a disposable instance (`tests/rbac_upgrade_live.sh serve several_admins`, never the running stack: since step 2.5 every real stack has a real Root, and moving it would sign that account out). It sources `redamon.sh` and runs its own `cmd_set_root` and `_confirm_root` through a `docker` shim that sends `docker compose exec webapp` to the instance's webapp and refuses every other compose call: `set-root` moves Root to a seeded `rbac-step27-a@e2e.local` admin and on to `rbac-step27-b`, each move signing out the new Root and the one it replaced and revoking the new Root's MCP tokens; `check-root.mjs` reports it, a repeat changes nothing, and `_confirm_root` (the switch on in a scratch `.env`) keeps an unconfirmed Root without `ADMIN_EMAIL` and confirms it, signing nobody out, when `ADMIN_EMAIL` names it. The instance runs with the caller's `RBAC_IDENTITY_ENABLED` (default off); it SKIPs when `redamon-webapp:latest` has no `set-root.mjs` or port 3901 is taken. The same scripts are proved on Postgres in the gate by `tests/rbac_scripts_db_test.sh`, in a throwaway schema built from the checkout's `schema.prisma`.

`tests/rbac_instance_settings_live.sh` checks the instance settings (step 2.4) on a disposable instance: it starts `tests/rbac_upgrade_live.sh serve tunnel_rows` with `RBAC_IDENTITY_ENABLED=true` (its own Postgres and webapp on 127.0.0.1:3901, never the running stack), then checks that the boot backfill copied the tunnel and capture rows in force, that the readers answer the instance row, that an admin's TrafficMind and tunnel changes through `/api/admin/instance-settings` reach the proxy config and are mirrored into their source user rows (the 7.7.x reading), that the user settings PUT refuses a real change with 409, that the `tunnels` legacy holder changes the tunnel but not the capture policy, that the audit names no credential and that the tunnel sync refuses a call without the sandbox's bearer. It needs a `redamon-webapp:latest` with the step and SKIPs otherwise.

`tests/rbac_root_live.sh` checks the Root (step 2.5) on the same disposable instance, scenario `several_admins`, with `RBAC_IDENTITY_ENABLED=true` and then off. Switch on: the boot chose the oldest admin with a password, automatic and unconfirmed, with one `system.rbac_root_assigned` row; `/api/auth/me` gives each account its type and every admin the unconfirmed Root (the header banner's data); another admin's demote, edit, disable, password reset, sign-out, act-as and delete of Root each answer 403 `root_protected`, change nothing and are audited; Root's own deletion is the 400 every account gets and its own demotion is refused; `set-root` in the instance's webapp confirms it without signing anyone out, and the admins' answer then reads confirmed. Switch off: the Root is still chosen, but `/api/auth/me` and the routes answer as after Phase 1 and nothing is refused. It needs a `redamon-webapp:latest` with the step and SKIPs otherwise.

`tests/rbac_root_admin_live.sh` checks step 2.6 (only Root manages admins, role changes, the Root transfer) on the same disposable instance, scenario `several_admins`, with `RBAC_IDENTITY_ENABLED=true` and then off. Switch on: an admin and the still unconfirmed Root get 403 `root_only` creating an admin or promoting the member; after `set-root` confirms Root, an admin still gets `root_only` on another admin (before any password), while Root promotes the member with its password (not without), whose session version rises and whose older cookie is refused, and creates an admin; the instance security policy is Root's; Root offers Root to an admin, who alone is told, accepts with its own password, and becomes Root (confirmed, by transfer) while both accounts' session versions rise and both old cookies are refused, with one `root.transfer` row; another admin cannot list the new Root's MCP tokens; a later offer is declined, another cancelled, both audited. Switch off: the transfer routes answer 404 and an admin manages admins under the Phase 1 rules, nothing bumped. It needs a `redamon-webapp:latest` with the step and SKIPs otherwise.

`tests/rbac_account_status_live.sh` checks account status in whichever state the webapp's `RBAC_IDENTITY_ENABLED` is. Switch on: an admin disables `rbac-member-c`, whose open cookie is refused at once, whose sign-in gets the generic answer (audited `auth.login.disabled`) and whose MCP token (inserted by SQL with a random hash) is revoked, the password waiting on hold; a second disable changes nothing; enabled again, the member signs in with the same password; an admin's "Sign out everywhere" refuses the member's new cookie, and the member's own (`/api/auth/sessions/revoke-all`) clears this browser's cookie and refuses the other browser's. Each change has one audit row. Switch off: disable, revoke-sessions and revoke-all answer 404, and an account disabled by SQL as the switch-on route does stays out and is restored by enable, which stays open. It reads `users`, `mcp_access_tokens` and `audit_log` through `psql`.

`tests/rbac_must_change_live.sh` checks must-change passwords (step 2.8) in whichever state the webapp's `RBAC_IDENTITY_ENABLED` is. Switch on: an admin sets `rbac-member-c` a temporary password (the default), which flags the account and raises its session version, so its open cookie is refused and the reset row says `mustChangePassword`; signed in with it, the member gets 403 `must_change_password` from other APIs and is sent to `/account?changePassword=1` by other pages, while `/account`, `/api/auth/me` and `/api/auth/password-policy` answer and a common password is refused; its own change re-issues the login cookie, which then reaches everything; an admin who unticks the choice sets a password that is not temporary. Since step 2.10 each of these resets carries a reason (the member has signed in before) and raises the session version, unticked too. Switch off: the same reset flags nothing and the policy route answers 404. Root's short-password prompt is left to the unit tests (it would change the real instance settings row). It SKIPs on an image without the step.

`testing/e2e/tests/rbacInvite.spec.ts` is E2E-P2-06 (step 2.9), run with `RBAC_IDENTITY_ENABLED` on (it skips otherwise): `rbac-admin-a` invites `rbac-invitee-p2-06@e2e.local` from the Users page and copies the link; a second browser context opens it, lands on `/invite` with the token gone from the address and `Referrer-Policy: no-referrer` on both hops, sees the policy, sets the password and is signed in as a member; a third context opening the same link gets the invalid page. The `p2-invite-*` rows of the route matrix check the same routes without making an account. `skipFirstRunScreens` (in `rbacUsers.ts`) dismisses the first-run screens in a context that never signs in.

`testing/e2e/tests/rbacResetCredentials.spec.ts` is E2E-P2-08 (step 2.10), run with `RBAC_IDENTITY_ENABLED` on (it skips otherwise): while `rbac-member-c` is signed in, `rbac-admin-a` resets its credentials from the Users page with a reset link and a reason; the member's open session ends (its cookie answers 401 and the page reloads to `/login`); the member opens the link, chooses a password and is signed in, and the reset notice (who, when, the reason) is shown once; a later sign-in shows none. It counts the member's `auth.login.after_reset` rows through psql in the postgres container: one after the first sign-in, still one after the next. The `p2-reset-*` rows of the route matrix check the refusals of `POST /api/users/[id]/reset-credentials` without resetting anyone.

`testing/e2e/tests/rbacTunnels.spec.ts` (step 1.10) holds under either `RBAC_IDENTITY_ENABLED` setting: the `tunnels` legacy holder changes the chisel URL from Global Settings (switch off: the page's Save, read back from its own settings row; switch on: the Tunneling section's own Save, read back from `/api/admin/instance-settings`, and only while the instance's tunnel is unconfigured, else it skips rather than replace it), a member without the grant sees the status only, an admin keeps the controls, and no browser reads the credentials.

`tests/rbac_account_live.sh` is E2E-P2-09 (step 2.11) on the disposable instance (`tests/rbac_upgrade_live.sh serve several_admins`), with `RBAC_IDENTITY_ENABLED=true` and then off; it waits once for 65 s. Switch on: a member's login cookie lives 168 h and an admin's 12 h, the admin's token carrying `adm`, its idle limit `idl` and its last activity `lat`; the member's own email change is refused without its current password (nothing written) and done with it (stored lowercased, one `user.email_changed` row, a notice), its next sign-in with the new address shows the notice once, My activity (`/api/account/activity`) lists the change, and the old address no longer signs in; an admin changing the member's email needs its own password and the notice names the admin. It then sets `admin_idle_minutes` by SQL (only this instance may change): an admin signed in under a 1-minute limit and idle for 65 s is sent to `/login` and refused 401 `session_ended`, while one signed in under a 2-minute limit is still in and is handed a refreshed cookie (same expiry, `lat` moved), not again a moment later. Switch off: 7-day cookies with no lifetime claim, the email changes without a password (a `user.update` row, no notice), My activity 404. It SKIPs on an image without the step. The `p2-email-*`, `p2-lifetime-*` and `p2-activity-*` rows of the route matrix check the refusals and the cookie lifetimes on the running stack without changing any address.

`tests/test_e2e_bola_live.sh` is the two-user cross-tenant test with its own fixtures (`webapp/scripts/e2e-bola-seed.mjs`: `bola-*@e2e.local`, removed before and after the run by `e2e-bola-cleanup.mjs`, both fed on stdin): ownership of projects, graph, exports, conversations, presets, scans and user settings, the admin's act-as chain, and every case of the RBAC hardening (shell sessions, tunnel read and write, template overwrite, emergency stop scope, MCP reload, terminal ticket, a stdio MCP test, the browser's project read) for a member created after the upgrade and for `bola-legacy@e2e.local`, who holds the three legacy grants. It never presses the instance-wide stop, reloads the agent's MCP set or writes a tunnel.

### The RBAC upgrade harness

`tests/rbac_upgrade_live.sh` runs a webapp image's own startup list (its `/app/entrypoint.sh`
without `exec node server.js`) against synthetic 7.7.x-shaped databases, in throwaway
containers on a private network, and checks what the upgrade did. The scenarios are full dumps
in `tests/fixtures/rbac_upgrade/` (one admin, several, none, passwordless admins, tunnel and
capture rows, members with and without passwords), made with the pinned image
`redamon-webapp:rbac-7.7.2` so they keep the 7.7.x shape while `redamon-webapp:latest` moves
on. It checks each fixture with `checks.sql` against `expected/<scenario>.out` before the run;
after every run it asserts that the row count of every table and every `users` column are
unchanged, and diffs `checks.sql` then `checks_after.sql` (what the upgrade adds: legacy
grants, Nuclei template owners, the identity columns at their defaults, the instance settings
row and the Root the boot chose in it, the empty invite and permission tables) against
`expected/<scenario>.after.out`.

```bash
bash tests/rbac_upgrade_live.sh all twice parallel failure   # the regression chain
RBAC_UPGRADE_SCENARIOS='^one_admin$' bash tests/rbac_upgrade_live.sh twice
bash tests/rbac_upgrade_live.sh serve several_admins   # 127.0.0.1:3901 until Ctrl-C
```

`twice` runs the list twice; `parallel` starts two containers at once (several webapp copies);
`failure` deletes a backfill's marker, holds a lock on the table it reads and re-runs only that
backfill with a 2 s `lock_timeout`: it must log the failure, exit 0 and write no marker, and the
next run completes it (`RBAC_UPGRADE_FAIL_BACKFILL` picks the backfill: `user-skill-toggles`,
`rbac-legacy-grants`, `rbac-instance-settings` or `rbac-root`; the Root choice skips on its data,
so that preset also clears the Root it chose). `serve` boots the server on the scenario database with fake secrets, the
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
`kali-shell-env.json` calls `kali_shell` with `env | grep -cE '...' || true` (a tool confirmation
first; `|| true` because a non-zero exit makes `kali_shell` report an error without the count), then
completes; `long-run.json` answers its first think turn after 120 s. To use one, start the
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
