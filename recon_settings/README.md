# `recon_settings` — the one place a recon parameter is described

`registry.yaml` is the single hand-maintained description of every recon
parameter and every pipeline tool. `registry.json` is its build artifact, and
the artifact is what every consumer reads.

It is also an importable Python package. Three services read the registry on
three different schedules — the agent has it COPY-baked, recon mounts it, the
orchestrator mounts it read-only — so a rule that lives in one of them and is
re-implemented in the others is the drift this package exists to remove.
`recon/settings_registry.py` is a thin re-export kept so existing imports keep
working; nothing new belongs there.

## What lives here and what does not

Prisma stays the source of truth for the database. It owns which columns exist,
their type and their `@default()`, so the registry never restates any of those:
the build joins them from `webapp/prisma/schema.prisma`. Copying a default in
here would create a third definition of a value that already has two, which is
the drift this directory exists to remove.

| Lives in | Holds |
| --- | --- |
| `webapp/prisma/schema.prisma` | existence, type, `@default()`, `@map` |
| `recon_settings/registry.yaml` | `runtime_key`, `bounds`, `validator`, `zero_means`, `fallback`, `coerce`, `unit`, `tool`, `phase`, `traffic`, `roe_capped`, `mcp`, `meaning`, and the `tools:` blocks |
| a Postgres row | one project's actual values |

Descriptions never enter the database. A description is identical for every
project, so it is metadata about the schema rather than data about a project;
storing it in Postgres would mean a migration to fix a typo and would force the
recon pipeline to take a database dependency just to know what a field means.
It also preserves a property the MCP surface already advertises:
`describe_recon_settings` answers even when Postgres and Neo4j are down.

## Files

| File | Role |
| --- | --- |
| `registry.yaml` | authored source. Edit this. |
| `registry.schema.json` | JSON Schema the YAML validates against |
| `build.py` | YAML -> JSON, validating; writes all three artifacts |
| `loader.py` | reads the built registry, standard library only |
| `engagement.py` | one derivation of "are the engagement limits live" |
| `roe_prompt.py` | which fields the RoE parse prompt names, and how it renders |
| `registry.json` | build artifact, read by Python |
| `roe_parse_prompt.py` | build artifact: the RoE parse prompt, with the registry digest embedded |
| `webapp/src/lib/reconSettings/registry.json` | the same registry artifact, read by TypeScript |

The artifacts are emitted by one build from one source and are byte-compared by
the drift tests, so the duplicate copy cannot diverge. Two registry copies exist
because a scan container mounts `recon/` but never `webapp/`, and the webapp
build tree cannot import across its own root.

## Rebuilding

```bash
python3 recon_settings/build.py           # writes all three artifacts
python3 recon_settings/build.py --check   # fails if any is stale
```

`--check` is what the drift tests run.

## Then rebuild the agent

The registry reaches three services on three different schedules, and only one of
them needs a human:

| Service | How it gets the registry | After a change |
| --- | --- | --- |
| `recon` | volume-mounted, spawned per scan | nothing |
| `recon-orchestrator` | read-only mount | `docker compose restart recon-orchestrator` |
| `agent` | **COPY-baked** | `docker compose build agent && docker compose up -d agent` |

`roe_parse_prompt.py` embeds the SHA-256 of `registry.json`, and `/roe/parse`
compares it against the registry it actually loaded. A stale agent image returns
**503** on every document upload rather than parsing against a field list that no
longer matches what will validate the answer. The agent also logs the mismatch at
boot, so an operator finds out before a user does.

## The `mcp:` disposition

| Value | Meaning |
| --- | --- |
| `settable` | write any time through `update_recon_settings` |
| `create_only` | write once at `create_project`; immutable afterwards |
| `never` | not a pipeline parameter; `deny_reason` says which class |

**`settable` is the normal answer, not the incautious one.** The allowlist is no
longer the control; validation at the point of use is. A field is open and its
VALUE is bounded, validated, or enforced at scan start. Denying a tuning field
"to be safe" makes the API the weaker of two doors while the form still sets it,
and `parity.test.ts` fails exactly that shape: every settable field must have a
form input, and every form input must name a field the API can write or a
deny reason that says why it cannot.

There used to be a fourth disposition, `tighten_only`, holding the Rules of
Engagement under a write-time direction rule. It is deleted. The rule bought the
appearance of a guarantee rather than the guarantee: five of the fields it
covered — the whole time window — accepted a WIDENING while reporting a
tightening, because `narrow` has no machine-checkable direction.

## The engagement, in two halves

The `roe*` columns keep their names and no longer mean one thing. Anything that
needs "the engagement" asks the registry, never the name prefix:

| Half | Query | What it is |
| --- | --- | --- |
| **limits** | `group: engagement_limits` | The rate ceiling, the never-touch hosts, the scanning window, the agent's denylists. Ordinary `settable` fields. What makes them safe is enforcement at scan start, not a write-time rule |
| **record** | `deny_reason: engagement-record` | The client, the contacts, the dates, the document. A person writes it, a model reads it, nothing enforces it, and it carries a third party's personal data |

`roeEnabled` is in neither sense writable: it is `mcp: never` with
`deny_reason: derived`. `engagement.py` computes it — limits apply when there is
a limit to apply — and a matching TypeScript copy in `webapp/src/lib/engagement.ts`
is pinned to it by a shared fixture table.

## Three keys that exist because uniformity is a lie

- **`zero_means: unlimited`** — several rate fields treat `0` as unlimited,
  which is the *fastest* value available and not the slowest. Without this key a
  reader concludes `0` is the gentlest setting and writes it onto a 3 rps
  engagement.
- **`fallback: falsy`** — a few mappings are `project.get(k) or DEFAULT` rather
  than `project.get(k, DEFAULT)`, so a stored empty value is replaced by the
  default instead of being honoured.
- **`coerce: int | strip`** — a few mappings wrap the stored value.

## Two more keys, and what they are for

- **`values:`** — a closed vocabulary. The form renders a select and the write
  REFUSES anything outside it. That is what closed the container-image hole: the
  17 `*DockerImage` columns used to accept any string and have it silently
  replaced at scan start, so `get_recon_settings` echoed an image the scan would
  never run. The danger was contained; the dishonesty was not.
- **`form_section:`** — which `ProjectForm` section renders the field. Joined
  from the field's TOOL unless the field names its own, so a new field lands
  beside its tool automatically. An explicit `null` means "no input anywhere",
  which the parity test reads to tell a deliberate omission from a forgotten one.

## Who may read or change a field: `readable:` and `share:`

- **`readable: false`** withholds the column from every MCP read
  (`mcpReadableFields`), with `read_deny_reason` saying why. Absent means readable.
- **`share: secret`** keeps the column the owner's when the project is shared:
  `projectReadView` (`webapp/src/lib/authz/projectReadView.ts`) removes it from
  every project read by anyone else. Absent means `ordinary`. It covers every
  `readable: false` column except `userId` (the owner's id names the owner, which
  the project read returns anyway) and the custom request-header lists, which an
  owner's token reads but which is where an operator puts an API key. The build
  refuses a `readable: false` column that is not `share: secret` unless its
  reason is `other_user`, so a credential column added later is never shared by
  default. `share` is not `deny_reason: secret`, which refuses an MCP write.
- **`share: gate`** and **`share: scope`** class the writes on a shared project
  (`webapp/src/lib/authz/settingsRisk.ts`, asked by every writer of the project
  row). Ordinary columns are Write's. A `gate` is a safety gate: Write may
  tighten it, loosening it needs Manage, plus Exploitation & shells for the
  agent's approval, tunnel and Kali switches. A `scope` column decides what the
  engagement targets or permits: Manage narrows it, only the owner widens it.
  "Looser" and "wider" are the RoE review's `wideningReason`
  (`webapp/src/lib/roe/roeWidening.ts`), which reads `roe_safe_value`; the
  fields it does not judge have a row in `settingsRisk.ts`. The build makes every
  `roe_parse: tighten_only` switch a `gate` and every field of the `scope` and
  `engagement_limits` groups `scope` (the ownership token stays `secret`), so a
  safety switch or target column added later is not an editor's by default.
  Two kinds of ordinary column stay the owner's anyway: the identity columns
  (`deny_reason: identity`) and `engagementKind`. A refused change answers 403
  naming each column and the level it needs, and writes nothing; the owner's
  saves are never judged. A RoE replace or removal by a co-owner is judged by
  the review instead: none of its rows may widen (`wideningReason`), and a
  project's first RoE is the owner's.

## Bounds are not decoration

The form input and the MCP validator are both generated from `bounds`, so a fake
bound is a fake control on both doors at once. `bounds.test.ts` fails a `count`
or `threads` maximum out of proportion to what the tool ships with: twenty-four
fields once declared `0..10000000`, which is a field with no bound wearing one.
