---
name: rbac-authz
description: >
  Authorization in RedAmon: who may reach a project and at which level, what a non-owner
  may read of it, whose data a request touches (the tenant, the project's owner) against
  who acts (the person), and the static tests and switches every change meets. One policy
  lives in webapp/src/lib/authz/; a check written anywhere else is a second policy that
  the next sharing or permission change silently misses.
  Trigger: editing webapp/src/lib/authz/; adding a route.ts under webapp/src/app/api/ or
  changing its requirePermission / withPermission / requireLevel call; editing
  routeManifest.ts, scripts/gen-route-manifest.mjs or tests/fixtures/rbac_matrix/; editing
  a share, consent, transfer or revocation path; minting or reading a ticket, call token or
  run credential (webapp/src/lib/auth.ts, webapp/src/lib/plugins/callToken.ts,
  agentic/ws_ticket.py, agentic/machine_credential.py); editing
  webapp/src/app/api/graph-views/execute/injectProjectFilter.ts or graph_db/tenant_filter.py.
license: MIT
metadata:
  author: redamon
  version: "1.1.0"
  scope: [root, webapp, agentic]
  auto_invoke:
    - "Editing webapp/src/lib/authz, a route's permission guard, or the route manifest"
    - "Adding a path a project collaborator can reach, or a ticket, token or job that carries a tenant and an actor"
    - "Editing the caller-supplied Cypher filters (injectProjectFilter.ts, graph_db/tenant_filter.py)"
---

## When to Use

- Adding a route, a permission, a share level or toggle, or any read a non-owner can reach.
- Changing who a request acts for: a WebSocket ticket, an MCP tool, a plugin call token, a
  scan's job credential, the agent's run config.
- Changing the filters that scope a caller's own Cypher.

The prohibition itself (no ownership or admin check outside `webapp/src/lib/authz/`) is a CRITICAL RULE in
[webapp/AGENTS.md](../../webapp/AGENTS.md); this skill says which helper to call instead. Also
follow `mcp-server-tools` for an MCP tool, `plugin-platform` for a Gateway call,
`graph-db-writes` for a graph write (its MERGE key is the tenant), `priority-board-triage` for a
triage write, `redamon-testing` for the tests.

---

## Critical Rules

- **NEVER compare ids or roles to decide access; call the helper for the case.**
  [authzStaticGuard.test.ts](../../webapp/src/lib/authz/authzStaticGuard.test.ts) fails on a new
  `x.userId === user`, `role === 'admin'`, `findFirst({ where: { id, userId } })` or `isAdmin`
  under `src/app/api` and `src/lib` (it caught an inline `ctx.token.userId !== owner` in the MCP
  triage start, `b54b78fe`).

  | You need | Call (all in `webapp/src/lib/authz/`) |
  | --- | --- |
  | a route's permission, on a project or the instance | `requirePermission(request, perm, { projectId })` or `withPermission(perm, handler, { projectId })` ([guards.ts](../../webapp/src/lib/authz/guards.ts)) |
  | a second permission in the same request | `requireAlso(auth, perm)` (guards.ts) |
  | a level beyond the permission's own (raw data is `'R*'`) | `requireLevel(auth, level)` (guards.ts) |
  | a project outside a route (a lib, a job, a socket) | `projectAccess(subject, id, opts)`, then `meetsLevel(access, level)` ([projectAccess.ts](../../webapp/src/lib/authz/projectAccess.ts), [levelTable.ts](../../webapp/src/lib/authz/levelTable.ts)) |
  | a per-user row (preset, conversation author, token, user scope) | `ownsRow(subject, row.userId)`; a list: `rowOwnerFilter(subject)` ([rowOwner.ts](../../webapp/src/lib/authz/rowOwner.ts)) |
  | the projects a person sees | `visibleProjectsWhere(subject)` / `visibleProjects(subject)` ([visibleProjects.ts](../../webapp/src/lib/authz/visibleProjects.ts)) |
  | an administration permission of the signed-in person | `requireSessionPermission(session, perm)`; a route that changes the host reads the account again: `accountHolds(userId, perm, { fresh: true })` ([adminPermission.ts](../../webapp/src/lib/authz/adminPermission.ts)) |
  | an account's own catalog under `/api/users/[id]/` | `requireSelfPermission(request, accountId, perm)` ([selfService.ts](../../webapp/src/lib/authz/selfService.ts)) |

- **Under act-as, pass `{ actingAs: true }` to `projectAccess`.** An admin acting as a
  collaborator reaches the share at Read and never more; without the option the acting admin gets
  the share's write level. `can()` passes it; a lib that calls `projectAccess` itself must too.
- **NEVER let a level-less owner helper guard a write.** `guardProject`, `requireProjectAccess`,
  `requireProjectScopedResource`, `requireProjectOwner` and the conversation helpers admit a read
  share, oversight and break-glass as readily as the owner. Only a permission at `W` or above on
  the same path stops them; [levelLessHelpers.test.ts](../../webapp/src/lib/authz/levelLessHelpers.test.ts)
  fails on a POST, PUT, PATCH or DELETE that reaches one without it.
- **Name the project in the guard whenever the route acts on one**, as a literal `projectId` key.
  Without it `can()` makes a capability-only check: neither the person's access to the project
  nor its level is decided, `auth.access` is null, and the manifest classes the call as a session
  guard.
- **ALWAYS update the route manifest in the same commit as the route.** Run
  `node scripts/gen-route-manifest.mjs` and commit `routeManifest.ts` with `routeManifest.json`;
  [routePermissions.test.ts](../../webapp/src/lib/authz/routePermissions.test.ts) fails when a
  handler's first permission differs from its entry, or a handler asks none (add it to
  `SESSION_ONLY` with the reason). The live matrix rows are generated from the manifest:
  `node scripts/gen-rbac-matrix-rows.mjs --check`.
- **A new permission goes in the registry with all its metadata**
  ([permissions.ts](../../webapp/src/lib/authz/permissions.ts): level, `crossTenant`,
  `gatesExisting`, `closesCrossTenantHole`, `mcpScopes`; `introducedIn` stays `UNRELEASED`). Then
  regenerate the JSON copy with `npx vitest run src/lib/authz/builtinSets.test.ts -u`; never edit
  `permissionCatalog.json` by hand.
- **A non-owner's read goes through the read views, never a hand-picked field list.** A project
  row: `projectReadView(row, auth.access)` ([projectReadView.ts](../../webapp/src/lib/authz/projectReadView.ts))
  drops every column marked `share: secret` in [registry.yaml](../../recon_settings/registry.yaml),
  so a new owner-only column is marked there. A graph answer: `graphReadView(graph, access)`
  ([graphReadView.ts](../../webapp/src/lib/authz/graphReadView.ts)); any other output of chain
  nodes (export, versions, MCP): `stripStepContent(nodes, access)`
  ([stepContent.ts](../../webapp/src/lib/authz/stepContent.ts)). Raw files (traffic, workspace,
  scan outputs) need `requireLevel(auth, 'R*')`.
- **A caller's own Cypher runs only through an allowlist.** Saved views go through
  [injectProjectFilter.ts](../../webapp/src/app/api/graph-views/execute/injectProjectFilter.ts),
  which refuses any character, call or node pattern it does not positively know; the agent, the
  triage tools and the sandbox CLI go through `scope_query` in
  [tenant_filter.py](../../graph_db/tenant_filter.py) (inject, then `find_unscoped_node_pattern`
  refuses what it cannot prove scoped). Never add a denylist regex for one more shape: every shape
  Neo4j read and a denylist missed ran unscoped, a read of every project's graph. A new function
  or procedure joins the positive allowlist with a test of its cross-tenant case.
- **Keep the tenant and the person apart in every hop.** The tenant (the project's owner) keys
  graph, traffic, credential and model reads and writes; the person keys sessions, chats, the loop,
  quotas and the audit actor. Swapping them writes a collaborator's work into an empty graph of
  their own, or hands the owner's chats to the collaborator.

  | Hop | Tenant | Person |
  | --- | --- | --- |
  | webapp route | `auth.access.project.userId` | `auth.effective.userId` |
  | WebSocket ticket ([auth.ts](../../webapp/src/lib/auth.ts)) | `ten`, always written | `sub`; `act` under act-as |
  | plugin call token ([callToken.ts](../../webapp/src/lib/plugins/callToken.ts)) | `ten` | `sub` |
  | run credential ([machine_credential.py](../../agentic/machine_credential.py)) | `ten` | `sub`, `act` |
  | scan job credential ([machineCredential.ts](../../webapp/src/lib/authz/machineCredential.ts)) | `ten` | on the job row, re-checked when it fires: `actorScanRefusal` ([scanActor.ts](../../webapp/src/lib/authz/scanActor.ts)) |
  | agent run ([config.py](../../agentic/orchestrator_helpers/config.py)) | `get_tenant_id(state, config)` | `get_identifiers(state, config)` |
  | MCP tool | `assertMcpProjectAccess(...).userId` | `ctx.token.userId` |

  A ticket or token without `ten` reads as `sub` only so tokens minted before an update still
  verify; a new minting site always writes it ([ws_ticket.py](../../agentic/ws_ticket.py) `ticket_tenant`).
- **A collaborator spends the owner's credentials only through a run toggle and the owner's
  consent.** `effectiveToggles` turns Run scans, Use AI agent and Exploitation & shells off without
  the consent row ([ownerConsent.ts](../../webapp/src/lib/authz/ownerConsent.ts)): never read a
  share's toggle columns yourself. A model-calling feature whose permission sits below Use AI agent
  asks `ownerCredentialRefusal(auth)`, then writes the `credits.used` row first with
  `recordFeatureSpend(auth, feature)` ([ownerSpend.ts](../../webapp/src/lib/authz/ownerSpend.ts)):
  no row, no spend.
- **Every loss of access calls `onAccessReduced` once its change has committed**
  ([revocation.ts](../../webapp/src/lib/authz/revocation.ts)): a share revoked, narrowed, left or
  expired, consent withdrawn, an account disabled, deleted or reset, a capability removed, a device
  session revoked. A ticket and a queued scan are checked only when they start, so without it the
  person's runs, sockets, queued scans, schedules and triage run go on. A new reason joins
  `ProjectReduction` or `AccountReduction` with its entry in `PLANS`.
- **A start that writes a project asks who else is writing it.** With sharing in force one
  person writes a project at a time: while anyone writes it (a scan, an agent run, a triage run, a
  mute-rule apply), another person's scan start or agent run is refused, 409 `project_writer_busy`
  naming who holds it (`secondWriterRefusal` / `secondWriterResponse`,
  [projectWriters.ts](../../webapp/src/lib/authz/projectWriters.ts); `SECOND_WRITER_POLICY`).
  The scan starts and the chat ticket ask it; a new start path asks the same function, never its
  own query. A socket outlives its ticket, so the agent asks again before every run it starts on
  the socket (a message, an approval, an answer, a tool confirmation, a resume: `_refused_second_writer`
  in [websocket_api.py](../../agentic/websocket_api.py)) through
  [writer_check.py](../../agentic/writer_check.py) and the internal-key
  [writer-check route](../../webapp/src/app/api/internal/agent/writer-check/route.ts), which reads
  the owner from the database. Keep the agent's answer map: 200 `{allowed: true}` starts; 409
  `project_writer_busy` refuses in the webapp's words; no answer or a 5xx is unverified (the owner,
  `sub == ten`, goes ahead with `[rbac] project_writer_unverified`, anyone else is refused); any
  other answer (400, 401, 404, a malformed body) refuses everyone, the owner included, because the
  browser picks the session id and an answer it can provoke must never let a run through.
- **One rule for a session id: `isWsSessionId`** ([wsTicket.ts](../../webapp/src/lib/wsTicket.ts):
  1-200 characters, no control or line-separator character). The ticket mint (400
  `invalid_session_id`) and the writer-check route use it, so a ticket the mint signed is never
  refused by the check. A client value written into an `[rbac]` log line goes through `logValue`
  ([routeErrors.ts](../../webapp/src/lib/routeErrors.ts); the agent's `_loggable`).
- **A privileged change and its audit row commit together.** Write the row with
  `writeAuditTx(tx, entry)` inside `auditedTransaction(prisma, async (tx) => ...)`
  ([audit.ts](../../webapp/src/lib/audit.ts), [auditForward.ts](../../webapp/src/lib/auditForward.ts)):
  a failed insert rolls the change back. A bare `prisma.$transaction` around an audit write, or a
  direct `tx.auditLog.create`, fails [auditWriters.static.test.ts](../../webapp/src/lib/auditWriters.static.test.ts)
  (its row would never be forwarded). The actor is `auditActorOf(real, effectiveUserId)`
  ([auditActor.ts](../../webapp/src/lib/auditActor.ts)): the person signed in, the account acted as
  in `onBehalfOfUserId`. `writeAudit` (best effort, swallows a failed insert) is never the row of
  a privileged change.
- **A new audit action needs a label, and a reader of it a retention rule.**
  [auditLabels.test.ts](../../webapp/src/lib/authz/auditLabels.test.ts) fails on an action without
  an `AUDIT_ACTION_LABELS` entry; [auditRetention.test.ts](../../webapp/src/lib/authz/auditRetention.test.ts)
  fails on an `audit_log` reader whose actions no `KEPT_AUDIT_RULES` rule keeps, since retention
  would delete the rows the code decides on.
- **A new feature sits behind its switch, and that switch's flags-off test proves nothing
  changed.** Read a switch only through `rbacFlags()` ([flags.ts](../../webapp/src/lib/authz/flags.ts)).
  A new reader of the switch, or of a table it introduces, joins the readers list of
  `webapp/src/lib/authz/<switch>.flags.off.test.ts` (`IDENTITY_READERS`, `PERMISSION_READERS`,
  `SHARING_STORAGE_READERS`, `WRITE_SWITCH_READERS`, `GOVERNANCE_READERS`, ...), with a block
  appended (never a rewrite) saying what the off state does. A schema change stays additive: a
  column added to an existing table is nullable or has a default
  ([schemaAdditive.test.ts](../../webapp/src/lib/authz/schemaAdditive.test.ts)).
- **A live matrix row whose answer depends on a switch carries its tag** (`identity:`,
  `permissions:`, `sharing:`, `sharingwrite:`, `governance:` with `on` or `off`, read by
  [rbac_matrix_live.sh](../../tests/rbac_matrix_live.sh)), or it fails in the other state.
  `sharing:` is sharing in force (the switch and Root's policy); a route or field gated on
  `RBAC_SHARING_ENABLED` itself, which exists with the switch on and the policy `{}`, takes
  `sharingswitch:` (the S3a red: four `sharing:off` rows failed there). A write grant refused
  while write sharing is not in force answers per the write switch (`write_sharing_off` off,
  `above_max_level` on with Root's policy at Read): `sharingwrite:off` plus `sharingwriteswitch:`.
  A row that raises a share to write with it in force acts on `viewer_tmp` and puts it back: the
  runner seeds once, so a raised `viewer` fails every later Read-viewer row (the S5 red).
- **A project the caller cannot see and one that does not exist are the same 404.** A 403 names
  the permission (`forbiddenResponse`, `requireLevel`) and goes only to someone who reaches the
  project below the level.

---

## Pattern: the prologue of a project route

```ts
import { NextRequest, NextResponse } from 'next/server'
import { requireLevel, requirePermission } from '@/lib/authz/guards'

const { projectId } = await params
const auth = await requirePermission(request, 'recon:read', { projectId })
if (auth instanceof NextResponse) return auth
const raw = requireLevel(auth, 'R*')         // only for raw data: files, traffic, step content
if (raw) return raw
const tenant = auth.access!.project.userId   // the owner: key every graph, file and credential read on it
const person = auth.effective.userId         // who acts: sessions, quotas, the audit actor
```

[supply-chain download](../../webapp/src/app/api/supply-chain/[projectId]/download/route.ts) is
a full route that starts this way.

---

## Commands

```bash
cd webapp
node scripts/gen-route-manifest.mjs --check
node scripts/gen-rbac-matrix-rows.mjs --check
npx vitest run --no-file-parallelism src/lib/authz/authzStaticGuard.test.ts src/lib/authz/levelLessHelpers.test.ts \
  src/lib/authz/routePermissions.test.ts src/lib/auditWriters.static.test.ts src/lib/authz/auditRetention.test.ts
npx vitest run --no-file-parallelism src/lib/authz/identity.flags.off.test.ts   # one switch file at a time
cd .. && ./agentic/run_tests.sh tests/test_ticket_tenant_actor.py
./redamon.sh test unit          # includes tests/test_tenant_filter_*.py (root-agent section)
bash tests/rbac_matrix_live.sh  # live: needs the stack up
```

---

## Resources

- [README.SECURITY_POSTURE.md](../../docs/readmes/README.SECURITY_POSTURE.md) §7 (authorization and multi-tenancy), §9 (tickets), §16 (audit)
- [README.DEV.md](../../docs/readmes/README.DEV.md) §8, "RBAC feature switches" - each switch, its requirement and roll-back
- [Sharing-Projects.md](../../redamon.wiki/Sharing-Projects.md), [User-Management.md](../../redamon.wiki/User-Management.md) - the levels and toggles as users see them
- Related skills: `mcp-server-tools`, `plugin-platform`, `graph-db-writes`, `priority-board-triage`, `redamon-testing`
