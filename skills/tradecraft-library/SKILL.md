---
name: tradecraft-library
description: >
  Tradecraft, each account's library of knowledge sites: a page store the agent writes with raw
  SQL that every statement keys by owner and resource, a read path that never writes, page text
  that is always untrusted, site logins that reach only their own host and their owner's own runs,
  one catalog policy, model calls that carry their purpose and are never retried, and settings
  that live only in the generated spec. Trigger: editing agentic/tradecraft/,
  webapp/src/lib/tradecraft/, webapp/src/app/api/users/[id]/tradecraft-resources/ or
  tradecraft-settings/, webapp/src/app/api/projects/[id]/tradecraft/,
  webapp/src/app/api/internal/agent/tradecraft/, webapp/src/components/settings/tradecraft/ or
  TradecraftResourcesAccordion.tsx; adding a Tradecraft setting, table or column.
license: MIT
metadata:
  author: redamon
  version: "1.0.1"
  scope: [root, agentic, webapp]
  auto_invoke:
    - "Editing Tradecraft (agentic/tradecraft, lib/tradecraft, the tradecraft routes or components)"
    - "Adding a Tradecraft setting, table or column"
---

## When to Use

- Changing how a resource is ingested, stored, refreshed, curated, converted or deleted.
- Changing what a chat run reads from the library: the catalog, search, a section read, the
  librarian, hints, the coverage map.
- Adding a Tradecraft setting, a table or a column, or a route under the tradecraft paths.

How the feature works is in [docs/readmes/README.TRADECRAFT.md](../../docs/readmes/README.TRADECRAFT.md);
this skill holds only the rules a change must keep. Authorization of the routes themselves is the
`rbac-authz` skill; a new agent tool is `agentic-tool-integration`.

---

## Critical Rules

- **NEVER write a page-store statement that is not keyed by the owner and the resource.** The SQL
  lives in four places only: `STATEMENTS` in [agentic/tradecraft/store.py](../../agentic/tradecraft/store.py),
  [library/search_sql.py](../../agentic/tradecraft/library/search_sql.py), the conversion's own
  `STATEMENTS` in [convert.py](../../agentic/tradecraft/convert.py) and `COVERAGE_SQL` in
  [library/coverage.py](../../agentic/tradecraft/library/coverage.py). Each statement takes `user_id`
  and the resource id (or the run catalog's resource ids), and reads entries, sections and the tree
  joined to the resource row's live `generation`: no caller names a generation except the job writing
  its own. A statement that cannot be keyed by one owner goes in its module's `UNKEYED_STATEMENTS`
  with its reason (today `store.py`'s install total and expired-lease scan, `convert.py`'s
  `sweep_users`); a new place for SQL is a new place every reviewer must know. On the webapp, a resource is read only by
  its id **and** the path's account (`loadOwnResource` in
  [resourceAccess.ts](../../webapp/src/lib/tradecraft/resourceAccess.ts)). Failed before:
  `522b9f7e` (an administrator read another account's page text and map), `85616179` (one search
  read two generations across its statements).
- **NEVER write from a read path.** `agentic/tradecraft/library/reader.py`, `read_now.py`,
  `check_url.py` and `preview.py` store nothing: Check URL imports neither the store nor a model builder, the preview
  neither the store nor a database driver. There is no page cache, and the code-search test fails on its names
  ([tests/tradecraft_no_cache_names_test.sh](../../tests/tradecraft_no_cache_names_test.sh)). Failed
  before: 1.x cached pages by URL in one volume for every account (removed in `d0506809`).
- **NEVER let page text, a title or a target's output reach a prompt or a tool result outside the
  untrusted envelope** (`wrap_untrusted` in [library/types.py](../../agentic/tradecraft/library/types.py)),
  and never let a model's answer through unchecked: the librarian's page IDs, excerpts and why lines
  are checked in [librarian/validate.py](../../agentic/tradecraft/librarian/validate.py); a hint's
  trusted lines hold page IDs and vocabulary names only, and never a CVE id. Failed before:
  `aab51561` (the librarian's plan prompt and why lines carried unchecked text), `1b0657be` (a
  target-planted CVE id in a hint's trusted lines).
- **NEVER send a site login anywhere but its own host, through the browser, or in another person's
  run.** Bind it with `fetch.use_login` and send it only as `same_host_headers` in
  [ingest/fetch.py](../../agentic/tradecraft/ingest/fetch.py); while one is bound, the browser is
  refused. A login resource enters a run's catalog only when `isOwnerRun` holds
  ([catalog.ts](../../webapp/src/lib/tradecraft/catalog.ts)), and its pages are read only within its
  live map. A login is used and changed only through the act-as refusals of
  [actAs.ts](../../webapp/src/lib/tradecraft/actAs.ts), and no answer carries a secret value
  ([masking.ts](../../webapp/src/lib/tradecraft/masking.ts)). Failed before: `ce84a975` (a login read
  accepted dropped entries as the map), `497c00da` (a catalog asked with no person, and a login in the 1.x run payload).
- **NEVER decide which resources a run or a project uses outside `catalog.ts`.** The run catalog
  and the chat's counter badge both read `activeResourcesFor`; a second rule anywhere else makes
  them disagree. On the agent, a run reads its catalog only through `runtime.bound_catalog()`,
  never `get_setting`, whose fallback outside the run's task is whichever project loaded last.
- **NEVER act on the live map without the resource's row lock.** A webapp writer that decides on the
  claim or the live map takes `lockOwnResource` / `lockOwnResourceGeneration` first, the lock the
  agent's swap takes. Failed before: `00530153` (a curation acted on a generation a refresh had just
  replaced).
- **NEVER retry a Tradecraft model call, or build one for a loop model.** An ingestion call carries
  the `tradecraft_ingest` purpose and the librarian `tradecraft_librarian`, both built from the
  owner's providers ([models.py](../../agentic/tradecraft/models.py)); an Agent in the Loop model is
  refused before any request. A call the daily budget refuses fails the job so the previous version stays
  live. Failed before: `97967db9` (a budget-cut refresh replaced a good map).
- **NEVER add a Tradecraft setting outside the spec, or an environment variable.** A setting is an
  entry of [settingsSpec.json](../../webapp/src/lib/tradecraft/settingsSpec.json) with its range and
  ceiling; `node webapp/scripts/gen-tradecraft-spec.mjs` copies it (and `vocab.json`) to the agent,
  which clamps every value again ([settings.py](../../agentic/tradecraft/settings.py)).
  [tests/tradecraft_no_new_env_test.sh](../../tests/tradecraft_no_new_env_test.sh) fails on a new
  key.
- **ALWAYS give a new Tradecraft table its cascade, its downgrade entry and the agent's name list.**
  `onDelete: Cascade` from the user and the resource (or project), an entry in `DOWNGRADE_TABLES` /
  `DOWNGRADE_COLUMNS` of [rbac-upgrade-preview.mjs](../../webapp/scripts/rbac-upgrade-preview.mjs),
  and, when the agent reads or writes it, its names in
  [schema_columns.py](../../agentic/tradecraft/schema_columns.py). Failed before: three tables added
  with no `DOWNGRADE_TABLES` entry left the upgrade-preview test red.
- **ALWAYS reach the web through `net.py` and time through `clock.py`.** They are the package's only
  boundaries ([test_tradecraft_fetcher_contract.py](../../agentic/tests/test_tradecraft_fetcher_contract.py)
  holds it), so every test can swap both.

---

## Where a change goes

| Change | File |
| --- | --- |
| A pipeline stage | `agentic/tradecraft/ingest/<stage>.py`, wired in `agentic/tradecraft/ingest/pipeline.py` and `contract.JOB_STAGES` |
| A body crossing webapp ↔ agent | `agentic/tradecraft/contract.py` and `webapp/src/lib/tradecraft/agentContract.ts`, plus a fixture in `agentic/tests/fixtures/tradecraft_contract/` |
| A page-store statement | `STATEMENTS` in `agentic/tradecraft/store.py`; a search one in `agentic/tradecraft/library/search_sql.py` |
| What a run may read | `webapp/src/lib/tradecraft/catalog.ts` |
| What a non-owner sees of a project's resources | `webapp/src/lib/tradecraft/projectView.ts` |
| A setting | `webapp/src/lib/tradecraft/settingsSpec.json`, then the generator |

## Commands

```bash
node webapp/scripts/gen-tradecraft-spec.mjs --check          # the agent's spec and vocabulary copies
./agentic/run_tests.sh tests/test_tradecraft_store.py         # keyed statements; any agent file the same way
bash tests/tradecraft_no_cache_names_test.sh && bash tests/tradecraft_no_new_env_test.sh
TC_PG_DB=tc_mine tooling/scripts/tradecraft_pg_testdb.sh agent tests/test_tradecraft_store_integration.py
```

The Postgres files need the disposable database of `tooling/scripts/tradecraft_pg_testdb.sh`
([README.TESTING.md](../../docs/readmes/README.TESTING.md), "Tradecraft").

## Resources

- [docs/readmes/README.TRADECRAFT.md](../../docs/readmes/README.TRADECRAFT.md) - how it works, end to end
- [docs/readmes/README.SECURITY_POSTURE.md](../../docs/readmes/README.SECURITY_POSTURE.md) - "Tradecraft is per account"
