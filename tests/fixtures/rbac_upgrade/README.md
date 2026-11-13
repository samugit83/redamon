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
