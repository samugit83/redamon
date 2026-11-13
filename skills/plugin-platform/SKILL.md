---
name: plugin-platform
description: >
  The plugin platform, always on: third-party plugin code runs isolated in the plugin
  runner, reaches RedAmon only through the Gateway, and changes agent behaviour only
  through text a person approved in core UI. The base repository holds no plugin
  logic, and a host that cannot run the platform is refused, never half-started.
  Trigger: editing webapp/src/lib/plugins/, webapp/src/app/api/plugins/,
  webapp/src/app/api/plugin-gateway/, webapp/src/app/api/plugin-runner/,
  webapp/src/app/api/internal/plugins/, webapp/src/components/plugins/,
  webapp/src/app/plugins/, services/plugin_runner/, agentic/plugin_api.py,
  agentic/prompts/skill_part_seam.py, docker-compose.plugins.yml, the plugin-runner or
  plugin-gateway services, or a _plugins_* / plugins_* function in redamon.sh.
license: MIT
metadata:
  author: redamon
  version: "1.1.0"
  scope: [root, webapp, agentic]
  auto_invoke:
    - "Editing the plugin platform: the plugins lib or routes, the plugin runner, or the Gateway"
    - "Changing how plugin services, networks or the plugins overlay are started by redamon.sh or compose"
---

## When to Use

- Changing the Plugin Manager, the catalog check, the Gateway, the override store or the UI host.
- Changing the runner, its worker spawn, the SDK or the `plugin-gateway` proxy.
- Touching how `redamon.sh` or compose start, remove or wire the plugin services.

For a new built-in skill part also follow `builtin-agent-skill` (layer 10, the part registry);
for an LLM call path, `llm-provider-integration`; for tests, `redamon-testing`.

---

## Critical Rules

- **NEVER put plugin-specific logic in the base repository.** No plugin id, prompt or behaviour
  in `webapp/src`, `agentic` or `services`; a plugin's name may appear only in tests, fixtures
  and docs. Check: `grep -rnw -i "skiller" --include=*.ts --include=*.tsx --include=*.py webapp/src agentic services`
  finds only test files (`-w`, or every `UserSkillError` matches). The platform is generic; a plugin lives in `redamon-plugins`.
- **NEVER add an off switch or a degrade-to-off path.** The platform always runs (owner decision
  2026-10-12). A host that cannot run it is refused by install, update and up with the cause
  named, before any core service is recreated (`require_plugin_engine`, `plugins_preflight`,
  `_plugins_prepare` in [redamon.sh](../../redamon.sh)); a runner that is down at runtime is a
  state the UI shows (the runner banner, 503 `runner_unavailable`), never a 404.
- **NEVER name a plugin service in a plain `up`.** `docker compose up -d --no-deps <profile service>`
  starts a profile service even without `--profile` (measured, experiment E8), so a plugin service
  in `rebuild_core`, `restart_only` or any ad-hoc `up` starts it without the recreate a runner
  rebuild needs and without the failure that stops the command. Only `plugins_converge` starts
  `plugin-runner` and `plugin-gateway`.
- **NEVER wire the webapp to the plugins in `docker-compose.yml`.** Its `plugins-edge` network
  and `plugins` volume live in [docker-compose.plugins.yml](../../docker-compose.plugins.yml),
  which `redamon.sh` loads only after the plugin preflight created the plugin networks, so a
  Docker that refuses them stops the command with that cause instead of failing halfway through
  the core `up`. A new webapp plugin variable still goes in the webapp's `environment:` list:
  the webapp has no `env_file`.
- **NEVER put the runner or the proxy on `redamon`, and never widen the proxy's prefixes.**
  Postgres, Neo4j, kali-sandbox and agent routes there trust the network. The proxy passes only
  `/api/plugin-gateway/v1/*`, `/api/plugin-runner/v1/*` and `/runner/v1/*`
  ([proxy.py](../../services/plugin_runner/gateway_proxy/proxy.py)); `tests/redamon_plugins_profile_test.sh`
  asserts the networks.
- **ALWAYS serve a Gateway call through `withGateway`** ([gateway.ts](../../webapp/src/lib/plugins/gateway.ts)).
  It re-authorizes every call: the call token, `action_ended`/`job_ended` (a token must not outlive
  its action or job; found by the phase 04 review), the plugin still serving (enabled, ready, not
  revoked), the permission an admin granted, and the tenancy (`checkTenancy`): `projectAccess` for
  the token's `sub` (as acted under `act`) meets every level `pluginProjectLevels` gives the
  plugin's permissions (`W`, `W+A` for `llm:invoke`, `O` with none), the project's owner is still
  the token's `ten`, and a session's conversation is reached only through `conversationReachable`.
  Every shortfall is the same 404. A model call spends `ten`'s model and keys, never the person's.
  A route that reads the token itself skips some of these.
- **NEVER let a plugin write what the agent runs.** A plugin may only `propose`; approval, rejection,
  reset and deletion are core routes that decide the scope with `scopeRefusal`
  ([changeSetAccess.ts](../../webapp/src/lib/plugins/changeSetAccess.ts)): a user scope is its
  account's own (`ownsRow`, plus `bodyOwnerMatches` because the act-as cookie is site-wide), a
  project scope needs Manage on the project (403 level `M` to a collaborator below it, 404 to
  anyone else). Admin lifecycle routes ask `platform:plugins` of the account read fresh
  (`requirePluginAdmin`, [lifecycleRoutes.ts](../../webapp/src/lib/plugins/lifecycleRoutes.ts))
  because the session JWT outlives a demotion. A `reviewProposal` that
  a job reports is validated in
  [jobs/complete](../../webapp/src/app/api/plugin-gateway/v1/jobs/complete/route.ts) like a sync
  result, never trusted.
- **NEVER deliver approved text outside the agent's own settings fetch.** `skillTextOverrides` goes
  only to the master internal key with `includeSkillOverrides=true`
  ([projects/[id]/route.ts](../../webapp/src/app/api/projects/[id]/route.ts)): `includeSkillContent`
  alone is also sent by text-to-cypher and accepted from the scanner key. On the agent side the seam
  reads only the session's settings context and falls back to the factory text
  ([skill_part_seam.py](../../agentic/prompts/skill_part_seam.py)); it never raises.
  The one exception is `user_skill.text`: approving never makes it active, it saves a NEW user
  skill (`adopted`), which is the person's own and travels the ordinary user-skill path
  (`userAttackSkills` with `includeSkillContent`, which the scanner key can read too). Never deliver
  a `user_skill.text` row's value any other way.
- **ALWAYS gate saving a `user_skill.text` proposal on the proposer** (enabled, ready, not
  revoked, granted `override:user_skill.text`, and `activeVersion === meta.pluginVersion`) in the
  save transaction, failing closed ([userSkillAdoption.ts](../../webapp/src/lib/plugins/userSkillAdoption.ts)).
  What a save creates outlives the plugin, so the catalog's revocation must reach it: reconcile
  withdraws the revoked version's waiting proposals and quarantines the skills saved from them,
  installed or not ([userSkillRevocation.ts](../../webapp/src/lib/plugins/userSkillRevocation.ts)),
  and every toggle writer refuses `true` on a quarantined skill.
- **NEVER hand a plugin a user skill outside its session or holding credentials.** The Gateway's
  `user_skill.text` target ([userSkillOverrideOps.ts](../../webapp/src/lib/plugins/userSkillOverrideOps.ts))
  requires the token's user as owner, a session whose turns used the skill
  ([sessionSkills.ts](../../webapp/src/lib/plugins/sessionSkills.ts)) and no quarantine, answers
  every refusal with the same 404 (no existence oracle), and refuses credential-shaped text with
  422 `skill_contains_credentials`. The platform's meta keys (`PLATFORM_META_KEYS` in
  [overrides.ts](../../webapp/src/lib/plugins/overrides.ts)) are stripped from a plugin's meta;
  the proposer's version, conversation and job come from the call token.
- **ALWAYS read time from `clock.ts` and never import the test doubles from production code.**
  [clock.ts](../../webapp/src/lib/plugins/clock.ts) is the only clock, so tests pin it;
  [noProductionImports.test.ts](../../webapp/src/lib/plugins/__testing__/noProductionImports.test.ts)
  fails when a production module imports `webapp/src/lib/plugins/__testing__/`.
- **A new extension point, SDK call or UI primitive is a platform version bump** held equal in five
  files by `platformVersion.parity.test.ts` (the runner's contract cases included). Follow the checklist in
  [README.DEV.md §6.6](../../docs/readmes/README.DEV.md#66-adding-a-plugin-extension-point).

---

## Commands

```bash
cd webapp && npx vitest run --no-file-parallelism src/lib/plugins src/components/plugins src/app/api/plugins src/app/plugins
cd webapp && npm run plugins:schemas          # regenerate schemas/json after a schema change
docker compose --profile plugins build plugin-runner   # before the plugin_runner test section
./redamon.sh test unit                        # includes plugin_runner, shell and vitest
bash tests/redamon_plugins_lifecycle_test.sh  # install/update/up and every refusal, stubbed docker
bash tests/plugins_isolation_live.sh          # live: needs ./redamon.sh up
```

---

## Resources

- [docs/readmes/README.PLUGINS.md](../../docs/readmes/README.PLUGINS.md) - design, lifecycle, trust model
- [docs/readmes/README.PLUGIN_SDK.md](../../docs/readmes/README.PLUGIN_SDK.md) - the plugin author's contract
- [docs/readmes/README.TESTING.md](../../docs/readmes/README.TESTING.md) - "The plugin platform" test map
- Related skills: `builtin-agent-skill`, `llm-provider-integration`, `rbac-authz`, `redamon-testing`
