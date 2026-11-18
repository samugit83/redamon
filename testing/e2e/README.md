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
