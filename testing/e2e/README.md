# Browser end-to-end tests

Drives the real RedAmon web app in Chromium against the running stack.

```bash
cd testing/e2e
npm install
npx playwright install chromium
npx playwright test                 # everything
npx playwright test filtersSynthetic
```

## Why this lives outside `webapp/`

`webapp/node_modules` is created by the Docker build and is owned by root, so
`npm install` there fails for the desktop user. This directory has its own
`package.json` and depends on nothing from the app - it only speaks HTTP.

## Prerequisites

The stack must already be serving `http://localhost:3000`
(`docker compose up -d webapp`). The suite deliberately does NOT start the app:
it is meant to exercise the built image, so **rebuild after changing
`webapp/src`** (`docker compose build webapp && docker compose up -d webapp`)
or the tests will run against the previous bundle.

Override the target with `REDAMON_BASE_URL`, and the fixtures with
`REDAMON_PROJECT` / `REDAMON_USER`.

## Auth

`tests/auth.ts` signs the app's own session JWT with `AUTH_SECRET` from the
repo `.env` and sets it as the `redamon-auth` cookie. No password is stored
here, and the tests do not depend on the login page's markup.

The onboarding gate and the GitHub star banner are full-screen overlays keyed
off localStorage; every spec pre-accepts them in `beforeEach` or nothing else
is reachable.

## The suites

- `filters.spec.ts` - the honest pass over every filterable page using whatever
  the project actually contains. Sheets with no rows assert that the Filters
  button is correctly disabled and then skip, and the run prints a coverage
  table so an empty project cannot look like an all-pass.
- `filtersSynthetic.spec.ts` - the same journey with the analytics API stubbed,
  so all 19 pages are really rendered, filtered, reloaded and re-checked
  regardless of project data.
- `tradecraftSettings.spec.ts`, `tradecraftProjects.spec.ts`, `tradecraftMap.spec.ts` -
  Tradecraft in Global Settings (Configure ingestion, a card's stale badge and report, the
  delete confirmation), in a project (the per-project switches, the drawer's window, the counter
  badge) and the Map view (search, block all matching, unblock, restore a dropped page, the
  accordion's read-only Pages, and no answer carrying the fake site login).
  They run on synthetic accounts and resources written straight into the database by
  `webapp/scripts/e2e-tradecraft-seed.mjs` (removed by `e2e-tradecraft-cleanup.mjs`): no agent
  and no site is reached. Each file's header has its command.

## Per-user Kali sandboxes

`tests/perUserSandbox.spec.ts` (fixtures in `tests/perUserSandboxFixtures.ts`) clicks through
the app as two members and the admin and checks that every Kali path still works from the UI
and runs in the person's own sandbox: first use and the drawer's starting line, an engagement
with a plan wave, a Fireteam and the Traffic tab, a shared project, shell sessions across
people, the terminal (also under act-as), access loss, the everyday screens and the emergency
stop (group A); the idle stop (B); the "Not enough memory" modal (C); per-person tunnels (D).
Each test finds where its command ran from the marker it left in a container's `/tmp`
(`docker exec ... test -e`, read only); those checks are soft and say `ISOLATION`.

Always run it through the wrapper, which takes the shared heavy lock, starts the running
stack's `recon-orchestrator` with each group's variables in its own shell (never `.env`),
replaying every other input the orchestrator was created with, and puts it back as it was on
exit, even after a failure or a signal. Before its first change it writes the originals to
`.git/redamon-g1-e2e-orchestrator.env` (0600, secrets as hashes), so a run killed outright is
put back by the next one. It fails before doing anything when Docker, `npx`, `curl`, the
orchestrator, the agent or the webapp is missing (`G1_E2E_ALLOW_SKIP=1` skips instead):

```bash
bash testing/e2e/scripts/per-user-sandbox-e2e.sh              # groups A-D, per-user mode
bash testing/e2e/scripts/per-user-sandbox-e2e.sh --dry-run    # what each group would recreate
bash testing/e2e/scripts/per-user-sandbox-e2e.sh --shared     # group A in shared mode ("fails before")
bash testing/e2e/scripts/per-user-sandbox-e2e.sh --check-lock # take the lock as a run would, then exit
```

It needs the stack up, Docker, `python3` and `node`, and the accounts of
`tests/kali_sandbox_seed_live.py` (`g1-alice@e2e.local`, `g1-bob@e2e.local`, projects `g1-PA`,
`g1-PB`, `g1-PS`), which the spec seeds again itself; `G1_STATE` names the seed's state file. The
model is `scripts/stub-llm-server.mjs` with the `scripts/stub-llm-scripts/per-user-sandbox-*.json`
scripts, registered as each owner's provider for the run. The lab is a throwaway busybox
container on the compose pentest network, joined to a person's sandbox network when a test
needs it; group D's tunnel edge is a local chisel server. A caller already holding the lock
(`flock LOCK bash ...`, or a descriptor it passes down) is recognised; `G1_E2E_LOCK_HELD=1` asks
for that and fails when it is not so. The wait for the lock is bounded by `G1_E2E_LOCK_WAIT_S`.
