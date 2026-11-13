# RBAC upgrade fixtures

Synthetic 7.7.x-shaped databases for `tests/rbac_upgrade_live.sh`. Every row is made up:
accounts are `upg-*@e2e.local`, targets are under `.test`, tokens are `upg-fake-*`. No real
user, host, scan result or secret is in any file here.

| File | What it is |
| --- | --- |
| `<scenario>.sql` | a full dump (schema and data, `pg_dump --no-owner`), loadable alone into an empty Postgres 16 database |
| `seed/<scenario>.sql` | the synthetic rows of the scenario, the only hand-written part of its dump |
| `checks.sql` | the scenario checks (`psql -At`, `\|` between fields), run on the fixture and after every startup list |
| `checks_after.sql` | what the upgrade adds by design (legacy grants, Nuclei template owners, the instance settings row, the Root the boot chose, their markers, the identity columns and tables at their defaults, the empty permission tables, the legacy-grant conversion, the empty sharing tables and the token sharing defaults), run after every startup list only |
| `expected/<scenario>.out` | what `checks.sql` prints on the scenario's dump |
| `expected/<scenario>.after.out` | what `checks.sql` then `checks_after.sql` must print after the new image's startup list, the RBAC switches off |
| `expected/<scenario>.after.identity.out` | the same with `RBAC_IDENTITY_ENABLED` on and `RBAC_PERMISSIONS_ENABLED` off (the harness picks it when only the identity switch reads on) |
| `expected/<scenario>.after.permissions.out` | the same with `RBAC_IDENTITY_ENABLED` and `RBAC_PERMISSIONS_ENABLED` on (the harness picks it when both read on) |
| `expected/<scenario>.capabilities.out`, `.capabilities.identity.out`, `.capabilities.permissions.out` | what each account may do after the upgrade, as `/api/auth/me` must answer it in `serve-check`, picked by the switches as the `.after` files are (below) |
| `preview_after.sql` | what the startup list wrote, in the lines the `preview` mode makes of the upgrade preview, run after the list only |

## Scenarios

| Scenario | Population |
| --- | --- |
| `one_admin` | one admin, one member, a project each |
| `several_admins` | three admins whose id order is the reverse of their creation order (`upg-admin-c` is the oldest), one member with a project |
| `no_admin` | two members with passwords and projects, no admin |
| `passwordless_admins` | two admins, both passwordless; one member with a password and a project, one passwordless member |
| `tunnel_rows` | two members with tunnel credentials (an ngrok token; a chisel URL without auth); two admins with different capture settings, admin B's saved last (in force) |
| `members_with_tools` | one admin; two members with passwords (member A keeps a stdio MCP server and a fake Tavily key); two passwordless members, one with a project |

## The password

Every account with a password has `rbac-upgrade-pass-0001`. The stored value is one bcrypt
hash (12 rounds, the webapp's `BCRYPT_ROUNDS`):
`$2a$12$ReeHabwQQ0lhyJEC1PHGIu6tszNiZwXQG2HTtjsa2wCyWRXquBZ42`. A passwordless account
has `password = ''` (the column default), so it can never sign in.

## How the dumps were made

Each dump is the database the pinned image `redamon-webapp:rbac-7.7.2` creates, plus its seed:

1. an empty `postgres:16-alpine` database;
2. the 7.7.2 image's startup list (its `/app/entrypoint.sh` without `exec node server.js`),
   which creates the schema and writes the one-time markers 7.7.2 writes at its first boot
   (`system.user_skill_toggles_*`, `system.jev_provider_selection_*` in `audit_log`);
3. `seed/<scenario>.sql`;
4. `pg_dump --no-owner`, with a header saying the file is synthetic;
5. the dump loaded into a fresh database and `checks.sql` run on it, which writes
   `expected/<scenario>.out`.

`bash tests/rbac_upgrade_live.sh regen` does all of it for every scenario
(`RBAC_UPGRADE_SCENARIOS=<regex>` narrows it). The dumps change on every regeneration (the
`\restrict` key, marker ids and times), so regenerate only when a seed changes, and review
`git diff tests/fixtures/rbac_upgrade/expected` before committing: those files are the
oracle. Never edit a dump by hand.

`expected/<scenario>.after.out` is NOT generated: it is the reviewed statement of what the
upgrade must leave, written by hand from the seed and the step's rules (step 1.8: every
non-admin account with a password keeps `kali_terminal,shell_sessions`, a tunnel holder also
`tunnels`; the marker counts the holders of each grant; step 1.12: the harness mounts no
templates folder, so the Nuclei owner backfill finds no file, writes one marker recording 0
files and no `nuclei_templates` row; step 2.4: one `instance_settings` row holding the tunnel
row the readers pick (enabled first, then saved last, then the lowest id) and the capture
settings of the admin row saved last, both sources named, defaults where nothing is
configured, and one marker recording the identity switch off, the sources and the candidate
ids; step 2.5: the Root the boot chooses in that row, the only admin with a password or the
oldest of several (created_at, then id), automatic and unconfirmed, with one
`system.rbac_root_assigned` row naming it, the rule and the candidate count; no Root and no
row when no admin has a password; step 3.3: the three permission tables exist and are empty,
so every account resolves to its account type's default; step 3.15: no conversion marker with
the switches off; step 4.2: the two sharing tables exist and are empty, no MCP token is opted in
to shared projects or narrowed by an allowlist, the two token columns default to `false` and
`ARRAY[]::text[]` (Prisma leaves a list column nullable; existing rows are filled with `{}`), and
the stored sharing policy is the column default `{}`, which reads as sharing off). `expected/<scenario>.after.identity.out` is the same statement for a boot with
the identity switch on and the permissions switch off: it differs only in the instance settings
marker, which records the identity switch on. `expected/<scenario>.after.permissions.out` is the
statement for a boot with the identity and permissions switches on: the instance settings marker
records the identity switch on, and the legacy-grant conversion writes one marker; no fixture
holds a Keep decision, so every grant a member holds lapses and no override is written. A step
that changes the upgrade by design appends its queries to `checks_after.sql`, its lines to every
`.after.out`, `.after.identity.out` and `.after.permissions.out`, and the audit actions it writes to
`UPGRADE_AUDIT_ACTIONS` in the harness (left out of the row-count comparison, pinned by count in
the markers section instead).

## The capabilities oracles (`serve-check`)

`serve-check` boots the scenario's server as `serve` does, signs every account in with the
password above, and diffs the `capabilities` of `/api/auth/me` against the scenario's oracle;
a login cookie minted as 7.7.x minted it (`{sub, role}` with `iat` and a 7-day `exp`, no `sv`,
no `sid`, signed with the harness's fake `AUTH_SECRET`) must give the same answer, one signed
with another secret 401, and `/api/projects` must list each account's own projects only. The
oracle is hand-written, one line per account, `<email>|<tokens>`, the tokens applied left to
right against the image's own `src/lib/authz/permissionCatalog.json`:

| Token | Meaning |
| --- | --- |
| `builtin:<slug>` | adds every permission of that built-in set or admin profile |
| `root` / `root_unconfirmed` | adds every permission / every one but the Root-only ones |
| `+<permission>` / `-<permission>` | adds / removes one permission |
| `login_refused` (alone) | the account has no password: the sign-in must answer 401 |

The statement each file makes, for every scenario (step 7.1, UP-04: each account keeps its
7.7.x rights, minus the Phase 1 holes and the admin-on-admin actions, plus its legacy grants):

- `.capabilities.out`, every switch off: an admin holds `builtin:full-admin
  builtin:default-member +admins:manage` (Phase 1's rule: admins manage admins); a member
  `builtin:default-member` plus a platform permission per legacy grant the boot wrote
  (`kali_terminal`, `shell_sessions`, `tunnels` -> `platform:<grant>`).
- `.capabilities.identity.out`, `RBAC_IDENTITY_ENABLED` on: the Root the boot chose holds
  `root_unconfirmed` (it is automatic until the host confirms it); the other admins lose
  `admins:manage`; members as above.
- `.capabilities.permissions.out`, identity and permissions on (also the file for all five
  switches: the resolution reads no other switch, `src/lib/authz/capabilities.ts`): the same
  holders, but every account loses `self:mcp_tokens` and `agent:loop`, capped by the instance
  because the server runs without `MCP_SERVER_ENABLED` and `AGENT_IN_THE_LOOP_ENABLED`, and
  members lose their legacy grants, which the boot's conversion lapsed (no Keep decision).

A step that changes what an account holds after the upgrade by design updates these lines;
`bash tests/rbac_upgrade_live.sh selftest` (offline, no Docker) checks that each file names
every fixture account once and only known sets and permissions.

## The preview diff (`preview`)

`preview` runs the image's `scripts/rbac-upgrade-preview.mjs` on the fixture, as
`./redamon.sh update` does between the build and the restart, then the startup list. The
harness reduces each preview section to one line per fact (`root|<email>|<rule>|<candidates>`,
`legacy_grants|<email>|<grants>`, `tunnel_rows|<email>|<role>|<kinds>|<enabled>`,
`tunnel_pick|<email>`, `instance_settings|tunnel|<email>|<candidates>` and `|capture|`,
`stdio_mcp|<email>|<server>`, `mcp_token_env_var|<email>|<server>|<variable>`,
`scanner_key|set`) and diffs them against what `preview_after.sql` reads of the database the
run left. The preview must also write nothing and exit 10 exactly when `preview_after.sql`
says it has something to review (`review|yes`), else 0, when it prints only `root` and
`instance_settings`. `legacy_grants` after a boot with the permissions switch on is what
members keep once the conversion ran: only the grants kept as overrides, none in any fixture.

## The pinned 7.7.2 image

The dumps must keep the 7.7.x shape while `redamon-webapp:latest` changes, so they come from
an image built from the 7.7.2 release commit. When it is absent, rebuild it from the
repository root (no worktree, no checkout; the context goes on stdin):

```bash
git archive 442debbf:webapp | docker build -t redamon-webapp:rbac-7.7.2 -
```

The `:webapp` suffix drops the path prefix, so the Dockerfile is at the top of the archive.
With snap Docker, `docker build <dir>` cannot read a directory under `/tmp`, which is why the
context is piped. The harness skips (exit 0) while this image, `redamon-webapp:latest` or
`postgres:16-alpine` is missing; it never pulls or builds.
