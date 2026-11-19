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
  version: "1.1.0"
  scope: [root, agentic, webapp]
  auto_invoke:
    - "Editing Tradecraft (agentic/tradecraft, lib/tradecraft, the tradecraft routes or components)"
    - "Adding a Tradecraft setting, table or column"
---

## When to Use

- Changing how a resource is ingested, stored, refreshed, curated, converted or deleted.
- Changing what a chat run reads from the library: the catalog, search, a section read, the
  librarian, Library now, the coverage map.
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
  its own. A read by CVE id of a CVE archive's index (`archive_entries` in `search_sql.py`) is keyed
  the same way and leaves out an entry the person blocked. A statement that cannot be keyed by one owner goes in its module's `UNKEYED_STATEMENTS`
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
  are checked in [librarian/validate.py](../../agentic/tradecraft/librarian/validate.py). Library
  now's trusted lines and notices are fixed text: the steps it searches for (model- or person-written)
  and its rows sit inside the envelope, with no page text ([library/hints.py](../../agentic/tradecraft/library/hints.py));
  a reading tool's refusal, outside the envelope, names a page by its ID or a resource by its slug,
  never a title, a heading or a URL (the URL follows in an envelope of its own, `reader.with_url`: a
  site's link with spaces carries a sentence), and a CVE archive's refusal of a page ID names the ID
  ([library/reader.py](../../agentic/tradecraft/library/reader.py)). Failed
  before: `aab51561` (the librarian's plan prompt and why lines carried unchecked text), `1b0657be` (a
  target-planted CVE id in a hint's trusted lines), `18b7fdcb` (Library now's step, with its hidden
  characters, in the block's trusted header), `0c030034` (a read's refusal quoted a map title and a
  page's headings outside the envelope).
- **NEVER send a site login anywhere but its own host, through the browser, or in another person's
  run.** Bind it with `fetch.use_login` and send it only as `same_host_headers` in
  [ingest/fetch.py](../../agentic/tradecraft/ingest/fetch.py); while one is bound, the browser is
  refused. A login resource enters a run's catalog only when `isOwnerRun` holds
  ([catalog.ts](../../webapp/src/lib/tradecraft/catalog.ts)), and its pages are read only within its
  live map. A login is used and changed only through the act-as refusals of
  [actAs.ts](../../webapp/src/lib/tradecraft/actAs.ts), and no answer carries a secret value
  ([masking.ts](../../webapp/src/lib/tradecraft/masking.ts)). A URL moved to another host keeps its
  login only when the person types it again (`tradecraftLoginSecretReentry` in
  [secretEndpointRebind.ts](../../webapp/src/lib/authz/secretEndpointRebind.ts), from the patch's
  "set" parts). Failed before: `ce84a975` (a login read
  accepted dropped entries as the map), `497c00da` (a catalog asked with no person, and a login in the 1.x run payload),
  a login that followed an edited URL to any host.
- **NEVER read or parse a site's answer without a byte ceiling and a bound on what it expands to.**
  Ingestion and reads run in the agent process every account shares: every `fetch_raw` of a page,
  index or listing passes its `max_bytes` (a page's `fetch.PAGE_MAX_BYTES`, an index's
  `constants.sitemapMaxBytes`), a truncated index is not parsed, and a parsed structure is walked
  within the map limit, not its declared size. Failed before: a ~300-byte `mkdocs.yml` of YAML
  aliases named a million nav entries (a billion in ~400 bytes) before `_dedupe` capped them, and a
  CVE archive's file was read up to the 100 MB transport ceiling. Held by
  [test_tradecraft_ingest_builders.py](../../agentic/tests/test_tradecraft_ingest_builders.py) and
  [test_tradecraft_cve_patterns.py](../../agentic/tests/test_tradecraft_cve_patterns.py).
- **NEVER let a run's read leave its resource, or send a GitHub token outside its repository or its
  owner's run.** A forced `section_path` reads only a page of the resource (`_in_resource` in
  [library/reader.py](../../agentic/tradecraft/library/reader.py): its start page, its live map, its
  1.x map); a run's token is `_Read.token_for(url)`, which is `fetch.repo_token` (the same owner and
  repository, no dot segment) and is None outside `V2Catalog.owner_run`; the catalog carries a
  resource's override only in its owner's run ([catalog.ts](../../webapp/src/lib/tradecraft/catalog.ts)).
  A new read path takes its token from `token_for`, never the raw value. Failed before: 1.x through
  7.8.0 read any URL a `section_path` named, with the project owner's token, in every run on the
  project. Held by [test_tradecraft_read_scope.py](../../agentic/tests/test_tradecraft_read_scope.py).
- **NEVER list a CVE archive's index without a GitHub token, or send the token anywhere but GitHub.**
  `index_cve` in [ingest/builders.py](../../agentic/tradecraft/ingest/builders.py) makes no call
  without the job's token (`cve_index_needs_token`; `build_cve`'s repository and root calls, which
  confirm the type, are made either way): an unauthenticated address gets 60 GitHub API
  calls an hour, and an index takes about one per year folder. `fetch.github_headers` adds the token
  only to https URLs on GitHub's hosts. Keep the listing bounded (one call per year folder and per
  folder a pattern names before `{year}`, every listing answer, the root's included, within
  `CVE_LISTING_MAX_BYTES` (`constants.sitemapMaxBytes`), at most
  `cve_index_cap()` entries, the 20,000 map ceiling every type shares) and a blocked file never
  requested, matched on the archive's own URL for it ([library/cve.py](../../agentic/tradecraft/library/cve.py)).
  Held by [test_tradecraft_cve_index.py](../../agentic/tests/test_tradecraft_cve_index.py).
- **NEVER put Tradecraft text in a run with no active resource, or Library now's rules where it does
  not run.** A prompt text that names the tools follows `overlay.offered_catalog()`
  ([overlay.py](../../agentic/tradecraft/overlay.py)); rules 6 and 7 come only from
  `hints.library_rule` through `with_step_naming_rule` ([prompts/base.py](../../agentic/prompts/base.py)),
  so a run without Library now reads as it does with no library; the block goes at the end of the
  think call's one system message (`hints.with_note`), never in a second one, which a
  single-system-message chat template answers with a 400 that ends the run. Held by
  [test_tradecraft_library_now_prompt.py](../../agentic/tests/test_tradecraft_library_now_prompt.py).
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
| Library now: its steps, its fit, its block and rule 6 | `agentic/tradecraft/library/profile.py`, `agentic/tradecraft/library/hints.py`; rule 7 is `STEP_NAMING_RULE` in `agentic/prompts/base.py` |
| A CVE archive's index | `index_cve` in `agentic/tradecraft/ingest/builders.py`; its refresh rules in `agentic/tradecraft/ingest/pipeline.py`; its reads in `agentic/tradecraft/library/search.py` and `agentic/tradecraft/library/reader.py` |
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
