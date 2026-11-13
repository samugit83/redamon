# RedAmon Web Application

Production-ready Next.js 16 web application with Neo4j integration, PostgreSQL project storage, and integrated recon control.

## Tech Stack

- **Framework**: Next.js 16.1 with App Router & Turbopack
- **Runtime**: Node.js 22
- **Graph Database**: Neo4j 5.x (attack surface data)
- **Relational Database**: PostgreSQL 16 with Prisma ORM (project settings)
- **Language**: TypeScript 5.7
- **UI**: React 19.2
- **Production**: Docker with multi-stage builds

## Project Structure

```
webapp/
├── prisma/
│   └── schema.prisma          # Database schema (each Project column is described in recon_settings/registry.yaml)
├── src/
│   ├── app/                    # Next.js App Router
│   │   ├── api/               # API Routes
│   │   │   ├── graph/         # Graph query endpoint (+ neo4j.ts, the Neo4j driver)
│   │   │   ├── health/        # Health check endpoint
│   │   │   ├── nuclei-templates/ # Custom nuclei template CRUD (global)
│   │   │   ├── projects/      # Project CRUD endpoints
│   │   │   └── recon/         # Recon control endpoints
│   │   │       └── [projectId]/
│   │   │           ├── start/     # POST - Start recon
│   │   │           ├── status/    # GET - Check status
│   │   │           ├── logs/      # GET - SSE log stream
│   │   │           └── download/  # GET - Download JSON
│   │   ├── graph/             # Graph visualization page
│   │   │   └── components/
│   │   │       ├── GraphToolbar/      # Recon controls
│   │   │       ├── ReconLogsDrawer/   # Real-time logs
│   │   │       ├── ReconConfirmModal/ # Confirmation dialog
│   │   │       └── AIAssistantDrawer/ # Agent chat & tool confirmation UI
│   │   ├── plugins/           # Plugins page and plugin screens (plugin platform)
│   │   ├── layout.tsx         # Root layout (imports styles/index.css)
│   │   └── page.tsx           # Home page
│   ├── styles/                # Global styles: index.css imports tokens, themes, base/global.css
│   ├── components/            # React components
│   ├── hooks/                 # Custom hooks
│   │   ├── useReconStatus.ts  # Status polling
│   │   ├── useReconSSE.ts     # SSE log streaming
│   │   └── useAgentWebSocket.ts # Agent WebSocket (queries, approvals, tool confirmation)
│   ├── lib/
│   │   ├── prisma.ts          # Prisma client
│   │   ├── recon-types.ts     # TypeScript types
│   │   ├── websocket-types.ts # Agent WebSocket message types
│   │   ├── hard-guardrail.ts  # Deterministic domain blocklist (gov/mil/edu/int)
│   │   └── plugins/           # Plugin platform: catalog, archives, lifecycle, reconcile, Gateway
│   └── providers/             # React context providers
├── public/                    # Static assets
├── Dockerfile                 # Production multi-stage build
├── docker-compose.yml         # Standalone compose (the root docker-compose.yml runs the stack)
└── package.json
```

---

## Authorization & Multi-User Access Control

RedAmon is multi-user. An account is an administrator (`role: admin`) or a member (`role: standard`); with `RBAC_IDENTITY_ENABLED` on, one administrator is Root (`lib/authz/root.ts`). **Each person's data is their own** (projects, graph, conversations, scans, reports, settings), and what an account may do at all is its permissions (`lib/authz/capabilities.ts`): with `RBAC_PERMISSIONS_ENABLED` off, its account type's default, which is what it could do before the switches; with it on, its permission sets, admin profile and overrides. With project sharing in force (below) an owner also lets named people read a project or, with write sharing, work in it at the level the owner picks; an administrator holding `projects:oversee` reads any project, audited; Root may open a time-limited break-glass. Authentication (a JWT in the httpOnly `redamon-auth` cookie, verified in `middleware.ts` and `lib/session.ts`) proves *who* is calling; **authorization** (`lib/authz/`: `can()`, `projectAccess()`) decides what they may reach, and at which level.

**Effective user.** `getEffectiveUser()` (`lib/session.ts`) returns the identity a request is scoped to:

- standard user -> their own id (any impersonation input is ignored);
- admin, not simulating -> their own id;
- admin simulating user X -> X, and only X (via a signed httpOnly `redamon-act-as` cookie set by the admin-only `POST /api/auth/act-as`).

To work as a user an admin explicitly *switches to* that user (see the User-Management wiki page) and reaches only what that user reaches, a project shared with them at Read and never more (`projectAccess(..., { actingAs: true })`). Outside act-as an admin reads another person's project only through oversight (`projects:oversee`: Read, without Raw data & files or private conversations, each read recorded for its owner) or Root's break-glass, both only with sharing in force (below).

**Guards (`lib/access.ts`).** Every API route that reads or mutates a per-user resource must scope to the effective user. Use:

- `guardProject(projectId)` - one-call guard for `[projectId]` routes (scan/analytics/workspace/graph): resolves the effective user and 404s if they cannot see the project. Since sharing, "see" is any level (owner, share, break-glass, oversight), so these level-less helpers never decide a write: a write handler asks its write-level permission through `requirePermission` (`levelLessHelpers.test.ts` fails otherwise).
- `requireProjectAccess(eff, projectId)` / `requireConversationAccess(eff, id)` / `requireProjectScopedResource(eff, loadProjectId)` - when you already hold the effective user.
- `ownerScope(eff)` - a Prisma `where` fragment (`{ userId }`) for list endpoints; never trust a client-supplied `userId`/`projectId`.
- `requireProjectOwner(projectId)` (`lib/triageClient.ts`) - the STRICT owner check, for routes that decide what is hidden: triage, Muted Nodes and Mute Rules (`/api/projects/[id]/node-filters/*`). A mismatch is a 404, as with the guards above. A user-scoped resource with the same stakes, such as a Mute Rules preset (`/api/mute-rule-presets/*`), loads the row and answers 404 unless `row.userId` is the effective user.
- `requireUserAccess(request, targetUserId)` (`lib/session.ts`) - for `users/[id]/*` READ routes (own-or-admin, with an `X-Internal-Key` carve-out for the agent). **Write** routes (POST `/api/users`, PUT/DELETE `/api/users/[id]`, POST `/api/users/[id]/llm-providers`) require an admin/owner **session** and do NOT accept the internal-key bypass, so an internal key can no longer mint an admin (STRIDE S2/E2). GET `/api/users/[id]/settings` additionally accepts the lower-tier `SCANNER_API_KEY` via `isScannerRequest` (STRIDE S3/E6).

Cross-user access is reported as **404** (anti-enumeration). Enforcement is always on: `ACCESS_ENFORCE`, which once ran these guards log-only, is ignored, and a process that still sees it set logs `[rbac] access_enforce_ignored` once.

`lib/authz/can.ts` is the one policy function the route checks move onto: `can(principal, permission, {projectId})` asks the person's capabilities (`lib/authz/capabilities.ts`) and, for a project, `projectAccess()` (`lib/authz/projectAccess.ts`: the owner, or with sharing in force a share, break-glass or oversight, each with its level; see Project sharing below). A route calls it through `requirePermission(request, permission, {projectId})` or `withPermission(permission, handler, {projectId})` (`lib/authz/guards.ts`): 401 without a session, 404 for a project the caller cannot see, 403 `{error, code: 'forbidden', permission}` for a permission they lack.

The screens follow the same set. `GET /api/auth/me` answers, beside the account fields (`id`, `name`, `email`, `role`, `accountType`), `capabilities` (the permission ids `can()` decides with, in registry order; under act-as what the admin may use while acting, from `capabilitiesInForce`; `null` when they could not be resolved, logged as `[rbac] could not resolve the capabilities`) and `flags` (the RBAC switch states); `rbac` stays for administrator accounts. A component asks `useCan(permission, projectId?)` (`hooks/useCan.ts`), never the account type: the user directory and user switcher, the TrafficMind settings, the plugin management controls, the Kali terminal tab and the projects page user bar are shown only to whoever holds their permission. The route still decides; a 403 that names a permission is shown with `components/auth/ForbiddenNotice.tsx` (the permission, what it allows, "ask an administrator"). The provider reads the session again after an act-as switch (`refresh`), since that changes the set.

The owner helpers keep their signatures and ask the same policy instead of comparing owners themselves: a project through `projectAccess()` (`guardProject`, `requireProjectAccess`, `requireProjectScopedResource`, `requireProjectOwner`, `assertMcpProjectAccess`, and the plugin platform's change-set, action-context and Gateway tenancy checks), a per-user row through `ownsRow()` / `rowOwnerFilter()` in `lib/authz/rowOwner.ts` (`assertOwner`, `ownerScope`), and a conversation through both: `requireConversationAccess[BySession]` need its author and `projectAccess()` on its project, so an author who can no longer see the project (transferred, membership revoked) gets 404, and the project alone never opens another author's conversation (with write sharing in force a conversation its author shared, or the owner's *Co-owners can read every session of this project*, opens read-only: Conversations on a shared project, below). A row filter for an account without an id matches no row. The plugin checks, which no route permission backs, ask the level the plugin's own permissions need (Read + Write, and Use AI agent for `llm:invoke`; a plugin that declares none, and every other caller, stays at the owner level: Plugins, Agent in the Loop and shell sessions on shared projects, below), so a Read share, oversight and break-glass never reach a plugin by this path; an MCP token reaches one only through `mcpProjectAccess` when it opted in (`docs/readmes/README.MCP.SERVER.md`, "Shared projects reach a token only when it opts in").

**Permissions (`RBAC_PERMISSIONS_ENABLED`, off by default, needs `RBAC_IDENTITY_ENABLED`).** The registry `lib/authz/permissions.ts` names every permission (98, with its kind, scope, level, description and the MCP scopes it backs); `permissionCatalog.json` is its JSON copy for `.mjs` scripts. The built-in member sets (*Default member*, *Read-only analyst*, *Recon operator*, *Red-team operator*, *Automation*, *No access*) and admin profiles (*Full admin*, *User manager*, *Platform operator*, *Security auditor*) live in `builtinSets.ts`; custom ones are `PermissionSet` rows, assignments `UserPermissionSet` rows and `User.adminProfileId`, overrides `UserPermissionOverride` rows. `resolveCapabilities()` (`capabilities.ts`) turns an account into the set it holds and `explain()` says why; with the switch off every account resolves to its account type's default, which is the behaviour before the switch. The management API: `GET|POST /api/admin/permission-sets`, `PUT|DELETE /api/admin/permission-sets/[id]` (`roles:manage`; the instance default set is Root's), `GET|POST /api/admin/admin-profiles`, `PUT|DELETE /api/admin/admin-profiles/[id]` (Root), `GET|PUT /api/users/[id]/permissions` (`users:assign_permissions`, `admins:manage` for an admin; the account itself reads its own), all 404 with the switch off; the rules (give only what you hold, never your own, a password for the sensitive ones) are in `hierarchy.ts`, the writers in `permissionSetAdmin.ts` and `userPermissionAdmin.ts`, under the `rbac.permissions` advisory lock. `POST /api/users/invite` and `POST /api/users` accept `sets` (`initialSets.ts`). The screens: the Users page's **Permissions** row action (`components/admin/UserPermissionsPanel.tsx`, with `PermissionPicker.tsx` and `EffectivePermissions.tsx`), the **Permission set** picker of the invite and create dialogs (`InitialSetPicker.tsx`), and **My permissions** on My account.

**Which check a route uses.** Every handler names its permission in the route manifest (`lib/authz/routeManifest.ts`, per method), or `null` with the reason when no person's permission backs it (a key-only route, or one every signed-in account may call); `routePermissions.test.ts` fails when the manifest and the handler disagree, and the live matrix rows of `tests/fixtures/rbac_matrix/p3_generated.tsv` are generated from the manifest (`node scripts/gen-rbac-matrix-rows.mjs`, `--check` in the tests). Use:

- `requirePermission(request, '<permission>', {projectId})` / `withPermission` for a project permission, the `projectId` key written literally (the manifest generator reads it); without `projectId` for an instance permission;
- `requireAlso(auth, '<permission>')` for a second permission the same request needs (an overwrite on top of a scan, a rescope on top of a settings save), decided on the same context;
- `requireSelfPermission(request, accountId, 'self:…')` (`selfService.ts`) for a route over an account's own data (providers, skills, MCP servers, tokens);
- `requireSessionPermission(session, '<permission>')` / `sessionHolds` / `accountHolds` (`adminPermission.ts`) for the real person's administration and platform permissions, never through an act-as target; `{fresh: true}` where a credential, a role or code on the host is at stake;
- `sharedToolAccess(principal, tool)` (`sharedTools.ts`) for the five shared tools, which keeps the legacy grants and the `REDAMON_SHARED_TOOLS_COMPAT` escape hatch.

`authzStaticGuard.test.ts` fails on an owner comparison, a role check or a "my projects" filter outside `lib/authz/` (lists go through `visibleProjectsWhere()`); `permissions.flags.off.test.ts` lists every production file that reads the permission tables and proves the switch-off answers.

**Acting as someone, with the permissions switch on.** `POST /api/auth/act-as` takes `{targetUserId, reason, durationMinutes, stepUpPassword}`; `lib/authz/actAs.ts` holds the rule (`users:impersonate`, members only unless Root, Root's reason and duration policy), the start and end rows and the token binding, and `actAsRefusals.ts` the actions refused while acting (`refuseWhileActingAs`, 403 `not_while_acting_as`). `/api/auth/me` adds `actingAs` (whom, why, until when) and `impersonation` (the dialog's limits) for admins; `components/auth/ActAsDialog.tsx` asks the reason, the duration and the password, and `ActAsBanner.tsx` shows the session on every page with Stop. The switcher no longer restores an act-as from `localStorage`.

**Gated panels.** A panel whose whole content needs one permission asks it before it fetches: the shell sessions panel and the Insights shells card read `useSessionsAccess()` (`hooks/useActiveSessions.ts`) and show `ForbiddenNotice permission="agent:sessions"` (the panel) or nothing (the card) to an account without `agent:sessions`; with the switch off they behave as before. A control that only works with one permission reads `usePermissionRefused(permission, projectId?)` (`hooks/useCan.ts`: true only with `RBAC_PERMISSIONS_ENABLED` on, once `/api/auth/me` answered, and the permission missing) and asks the permission its route asks: on the graph page the toolbar's Start/Resume Recon (`recon:scan`) and GVM Scan (`scan:gvm`), the empty graph's start, the Other Scans starts (`scan:secrets` for GitHub Hunt and every TruffleHog source, `scan:supply_chain` for Supply-Chain and its organisation batch) and the recon dialog's Overwrite (`recon:overwrite`) are disabled with the notice as their title (`forbiddenNoticeText`), the recon and GVM dialogs never open for a refused start, and the Workflow view's partial-recon play needs `recon:partial`. The page mounts `AIAssistantDrawer/AgentDrawer.tsx`: without `agent:chat` the drawer holds only `ForbiddenNotice permission="agent:chat"` and none of the chat is mounted (no socket ticket, conversation, key or model read), and the page's agent status poll for the toolbar stops.

**Project sharing (`RBAC_SHARING_ENABLED`, needs `RBAC_PERMISSIONS_ENABLED`, and Root's sharing policy).** Sharing is in force only while the switch and the instance policy's `enabled` are both on: `lib/authz/sharingPolicy.ts` (`parseSharingPolicy`: any invalid stored setting reads as the defaults, sharing off; `sharingPolicyInForce`, one cached column read; `sharingInForce` = `{enabled, maxLevel}`), set by Root through `PUT /api/admin/instance-settings` (confirmed Root, password): from the admin console's Instance page, which needs `RBAC_GOVERNANCE_ENABLED`, or without the console from a tab signed in as Root. `GET /api/auth/me` returns `sharing: {enabled, maxLevel}` (only with the switch on), which every sharing screen reads. `projectAccess(subject, projectId)` answers `{project: {id, userId}, level: 'owner'|'write'|'read', toggles: {rawData, and on a write answer runScans, useAgent, exploit, manage}, via: 'owner'|'share'|'break_glass'|'oversight'}` or null (404): the owner first, then a live `ProjectCollaborator` row, an unexpired `ProjectBreakGlass` row (with `projects:administer`), the subject's own `projects:oversee`; under act-as the subject is the account acted as, and the guard answers 404 to an oversight or break-glass access while acting. `meetsLevel(access, level)` is the table (read meets `R`, and `R*` with `toggles.rawData`); a route that needs Raw data & files beyond its permission's level calls `requireLevel(auth, 'R*')` (`guards.ts`) after `requirePermission`. A read route gives a collaborator the owner's data: take the tenant from `auth.access.project.userId` (never the caller; traffic through `traffic/[projectId]/trafficTenant.ts`), pass graph nodes through `graphReadView` / `stripStepContent` (`lib/authz/graphReadView.ts`, `stepContent.ts`: attack-chain step content is raw data, and the option-(a) switch of OQ-R7, `RAW_DATA_GRAPH_PROPS`, sits there) and a project row through `projectReadView` (`lib/authz/projectReadView.ts`: drops the registry's `share: secret` fields for anyone but the owner). Lists use `visibleProjects()` / `visibleProjectsWhere()` (owned OR a live share, only with sharing in force; oversight and break-glass fill no list) and `withMyAccess` for the rows' `myAccess`; api-usage keeps `ownedProjectsWhere`. The share writers are `lib/authz/projectShares.ts` behind `GET|POST /api/projects/[id]/collaborators`, `PATCH|DELETE .../collaborators/[userId]` (`project:share`) and `POST .../leave` (the collaborator's own share), all 404 with sharing not in force; the dialog is `components/sharing/` (`ShareDialog`, `AccessPicker`, `CollaboratorList`, `LeaveShareButton`, the presets in `sharePresets.ts`), opened from the projects page's cards and the header's project selector. The projects page shows **Shared with me** (`lib/sharedProjects.ts`, `ProjectCard` `sharedBy` / `accessLabel`) and, for `projects:oversee` holders, **All projects (oversight)** (`GET /api/projects/oversight`, `hooks/useOversightProjects.ts`) with Root's break-glass (`POST|DELETE /api/projects/[id]/breakglass`, `lib/authz/breakGlass.ts`, `components/auth/BreakGlassDialog.tsx`). `lib/authz/oversight.ts` writes the per-day `project.oversee` row from the guard. The project activity is `GET /api/projects/[id]/activity` (`lib/authz/projectActivity.ts`; owner through `project:share`, then oversight or break-glass) and the page `app/projects/[id]/activity/`, linked from the settings page; every audit action needs a label in `lib/authz/auditLabels.ts` (`auditLabels.test.ts` reads every writer). Expired shares, overrides, break-glass rows and links are removed by `lib/authz/expirySweep.ts` (`POST /api/internal/rbac/sweep`, called by the recon orchestrator). `lib/authz/sharing.flags.off.test.ts` lists every production file that reads the sharing storage or a collaborator or break-glass row and proves the answers with sharing not in force.

**Read-only projects (sharing, step 4.11).** With `RBAC_SHARING_ENABLED` on, every project read carries the person's own access (`myAccess`: level, Raw data & files, how it was reached, the owner); `ProjectSummary.myAccess` holds it and `ProjectProvider` puts the open project's access in `ProjectAccessContext` (`providers/projectAccessContext.ts`). `useRefusal(permission, projectId?)` (`hooks/useRefusal.ts`) answers why a control is refused: `level` when the access does not reach the permission's level (`lib/readOnlyProject.ts`, the browser's copy of `meetsLevel`: a read share reaches `R`, and `R*` with Raw data & files), shown as "Read access, shared by <owner>"; else `permission` with the permission notice. `usePermissionRefused` is `useRefusal(...) !== null`, so every gate above turns read-only for a read collaborator; `useCan(permission, projectId)` checks the level only when given the project. At read: the scan starts, pauses and stops (toolbar, Other Scans, project settings, partial-recon badges), the Priority Board's verdicts, mutes and triage run, report generation and deletion (per report, from the list rows' `myAccess`), the workspace drawer's upload, new folder, rename, delete and clean all, traffic deletion, the version manager's save, activate, rename, pin and delete, the scan schedules and the scan queue's Cancel and Re-confirm are disabled with that title; the settings form shows a notice and puts its sections in a disabled fieldset (`RegistryFieldsReadOnly`), with Update Settings, Load Preset and Export off. While the open project carries `myAccess`, `ProjectProvider` asks `GET /api/projects/[id]/my-access` every 30 s (doubling up to 5 minutes after a failure, nothing while the tab is hidden): access ended sends the person to `/projects` with a toast (`AccessNoticeToast`, under the toast layer), access narrowed re-renders the controls. A 404 is confirmed with the project read, so with the switch turned off the owner stays. With the switch off no read carries `myAccess`: nothing is asked or refused by level (DV-30).

**Read + Write shares and stale single-field saves (sharing, step 5.2).** With write sharing in force (`RBAC_SHARING_WRITE_ENABLED` and Root's `maxLevel: "write"`) a Read + Write share answers `myAccess.level` `write` with its toggles (Raw data always; Run scans, Use AI agent and Exploitation & shells only with the owner's consent, step 5.6; Manage as stored), from the project GET, `/my-access` and the list rows (`visibleProjects.withMyAccess`), and as `read` under act-as (D-22). `myAccessMeets` holds the same write rows as `meetsLevel` (W, a toggled level with its toggle, never O), so a write share's controls open at their level; a refused one says "Read + Write access without <toggle>, shared by <owner>". A collaborator's form leaves the owner's `share: secret` columns out of its saves, and the PUT and the RoE replace answer the row through `projectReadView`. Every single-field PUT of the project row (the settings form's workflow auto-save, the chat drawer's settings, the graph page's stealth and model switches, the traffic capture toggle) sends the `updatedAt` it read (`lib/projectFieldSave.ts`); the PUT's stale 409 carries `code: 'stale_save'`, and the screen then says "Someone else changed this project", reloads the row and takes it. The share routes grant it (step 5.14, `lib/authz/projectShares.ts`): `levelRefusal` admits a write body only while Root's `maxLevel` is `write` (`maxShareLevel`); `grantorRefusal` lets a member grant Exploitation & shells only with Root's `membersMayGrantExploit` (409 `exploit_admins_only`; admins and Root always may) and a co-owner only the toggles their own share holds now (403 `grant_above_held`); then `requireStepUp` asks the granter's password when the body sets `exploit: true`. A write toggle on a Read share is a 400, a held toggle can always be cleared, and lowering a share to Read drops its toggles (a narrowing, so `onAccessReduced`). With write sharing in force the list answers each share's toggles and `grantable` (`{grantor: owner|co_owner, toggles, ownerConsent}`); otherwise Phase 4's answer, the consent unread. The dialog's presets (`sharePresets.ts`: *Editor* = Read + Write, *Operator* = + Run scans + Use AI agent, *Red-teamer* = + Exploitation & shells, *Co-owner* = + Manage, *Custom*) disable what cannot be granted with the reason and hide a co-owner's unheld toggles; one password prompt (`StepUpModal`) covers the owner's consent (posted to `access-policy` first) and the exploit step-up; the sandbox (HD-22), target-credentials (SH-29) and copy warnings sit beside their toggles; the owner sees the consent there and can withdraw it.

**Concurrent writers (sharing, step 5.11).** `lib/authz/projectWriters.ts` says who is writing a project now: each active scan of any kind with its `actor_user_id` (the orchestrator's `/system/active-scans`), each agent session the agent confirms live with its author (`agentSessions.runningSessionAuthors`), the live triage run and mute-rule apply with their actor; a writer whose person is not recorded is the owner's. `secondWriterRefusal` refuses a start by another PERSON with 409 `{error, code: 'project_writer_busy', busy}` naming them ("<name> (<email>) is running a partial recon"); the same person still runs several things at once. It runs inside the project's graph lock (`startUnderGraphLock` for the six start buttons, `dispatchStart` for the queue and the scheduler, which requeue the 409, `startFullScan`), so two people pressing Start at once meet there, and on the chat socket's ticket (`/api/agent/ws-ticket`, socket `agent`). Only with sharing in force (the switch and Root's policy); a source it cannot read lets the owner's start through with an `[rbac] project_writer_unverified` line and refuses anyone else's. `SECOND_WRITER_POLICY` is `refuse` until experiment E10 (`tests/rbac_e10_writers_live.sh`) records concurrent writes safe, then `notice`. The `ProjectWriters` strip on the graph page (`components/projects/ProjectWriters`) reads `GET /api/projects/[id]/writers` (graph:read at the Write level, 404 with sharing not in force) every 30 s for an owner or a write share and shows "<IdentityLabel> is running <kind> on this project". Runs start over the chat socket long after its ticket, so the agent asks again before each run starts (a message, an approval, an answer, a tool confirmation, a resume; `agentic/writer_check.py`): `POST /api/internal/agent/writer-check` (internal key; the ticket's `sub`, project and session) answers with `secondWriterResponse`, 200 `{allowed: true}` or the same 409, and a refused run starts nothing and sends the socket an ERROR frame with `code: 'project_writer_busy'`, the 409's sentence and `busy` (and `answer` for a refused answer, so the drawer puts its card back). No answer (the webapp unreachable or slow) or a 5xx lets the owner's run start and refuses anyone else's, as an unreadable source does here; any other answer (the route's 400 for a malformed check, a 401, a 404) refuses everyone, the owner included, because the session id in the check is the browser's. The ticket never signs a session id the check would refuse: `isWsSessionId` (`lib/wsTicket.ts`, 1-200 characters, no control character) is the one rule at the mint (400 `invalid_session_id`) and in the route, and every client value reaches the `[rbac]` lines through `logValue` (`lib/routeErrors.ts`).

**Settings a collaborator may change (sharing, step 5.1).** `recon_settings/registry.yaml` classes each project field `share: ordinary | gate | scope | secret` (`build.py` refuses a `roe_parse: tighten_only` switch that is not `gate` and a scope or engagement-limits field that is not `scope`), and `lib/authz/settingsRisk.ts` `classifyChange(before, after, access)` judges a non-owner's change key by key, by direction: an ordinary field or a tightened gate needs Write; loosening a gate needs Manage, and also Exploitation & shells for `EXPLOIT_GATES` (the approvals and confirmations, the tunnels, Kali installs and package lists, `mcpKaliExecEnabled`, a dangerous tool the tool phase map admits earlier or at all); narrowing scope needs Manage; widening scope, a secret, an identity column, `engagementKind` or a key the registry does not know needs the owner. The direction rules (`OWN_DIRECTIONS`, `lib/roe/roeWidening.ts`): emptying an allowlist whose empty value admits everything widens (the subdomain list, judged by the hosts it scans; the Kali package and GitHub repository lists), the RoE time window is judged whole as the minutes of a day it admits (an end before the start crosses midnight), and a gate or scope value its readers cannot read (`validateValue`, an HH:MM or YYYY-MM-DD format) widens before any order. Every writer of the project row judges it: the project PUT (a non-owner's columns without the server-derived ones, before the scope busy check), `lib/roe/applyRoe.ts` (a non-owner's first RoE and any widening row are the owner's), the preset apply, the supply-chain organisation batch (another org is the owner's) and the MCP settings, preset and scope tools (`refuseSettingsChange`); `settingsRisk.writers.test.ts` fails on a writer it cannot place. A refusal is 403 `{code: 'forbidden', permission, level, needs, refused: [{key, needs, levels, reason}]}` with a `[rbac] settings_refused` log line (no audit row).

**The collaborator's project form and graph page (step 5.7).** A non-owner's form reads the owner's catalogs from `GET /api/projects/[id]/owner-catalog` (`recon:read`; `?models=1` at Manage; 404 with sharing not in force): the owner's model providers, Jev configurations, agent skills and MCP servers by name, the owner's keys by presence, never a value. Who reads it is one rule, `hooks/useProjectOwnerCatalog.ts`: any `myAccess` below `owner` (read, write, oversight, break-glass), the owner's models only at Manage. The form and the graph page both call it, and `hooks/useOwnerCatalog.ts` (`OwnerCatalogContext`) feeds `ModelPicker`, `useCredentialKeys` (read-only: key rows say *Owner's setting*), the Jev select, `ToolMatrixSection`, `AttackSkillsSection`, `CypherFixSettingsSection` and the key warnings of the Shodan, Urlscan, OSINT and origin-discovery sections and the partial-recon modal; pickers, skill toggles and MCP tool phases are disabled below Manage with the access words. One chokepoint in `ProjectForm.tsx` (`lib/settingsFieldAccess.ts` `fieldChangeRefusal`: 5.1's `classifyField` run in the browser against the stored row, which is why the level table lives in `lib/authz/levelTable.ts`) refuses a change the server would refuse with a toast naming the key, its need and the reason, and `writeAccessSummary` says above the form what the level may change. The graph page (`app/graph/page.tsx`) reads the catalog once and provides the same context around its Other Scans modal and AI drawer, since scans and runs spend the owner's keys and models: the Other Scans cards show the owner's GitHub and TruffleHog keys as *Owner's setting* (a missing one says the owner has not set it, with no link to the viewer's own settings); the drawer's missing-key warnings follow the owner's keys with no *Add* (`useApiKeyModal`), its model picker lists the owner's models at Manage, read only while the drawer is open, and is locked with the reason below it (`useModelPicker`, the `PhaseIndicatorBar` badge), and its MCP tools tooltip, user-skills tooltip (`useAttackSkillData`) and settings sections read the owner's catalog; the person's own chat skills stay theirs. The owner's screens and the switch-off screens read the person's own account as before and never request `owner-catalog` (DV-30).

**The owner's credentials: consent and attribution (sharing, step 5.6, C1).** Run scans, Use AI agent and Exploitation & shells spend the owner's model providers, scan keys and target credentials, so they count only with the owner's consent: `effectiveToggles(row, consent)` (`projectAccess.ts`) turns them off without a `project_access_policies` row (`lib/authz/ownerConsent.ts`, read fresh for a write answer whose row holds a run toggle); Manage does not need it. `GET|POST /api/projects/[id]/access-policy` (`project:share`; POST is the owner's, with the password to grant and none to withdraw, refused while an admin acts as the owner; same-origin; 404 unless write sharing is in force) writes `project.owner_consent.grant` / `.withdraw`, and a withdrawal plays `onAccessReduced(..., 'consent_withdrawn')` for each collaborator. Each spend is recorded before it happens (`lib/authz/ownerSpend.ts`): a `credits.used {feature, actor}` row through `writeAuditTx` from every scan start (`scanStartFields`), a triage run's start, the chat, CodeFix and terminal tickets, the report narratives, RoE parse, multi-mute suggest, the whisperer, text-to-cypher and the plugin LLM; no row, no spend (503 `spend_not_recorded`, and a scan does not start). A model-calling feature whose permission sits below Use AI agent asks `ownerCredentialRefusal(auth)` (W+A for a non-owner) and runs the owner's model under the owner's id; a report without it comes back without narratives (`narrativesSkipped: 'use_agent_required'`). The owner's own use writes nothing. The API usage report adds `collaboratorSpends` (30 days, by collaborator, feature and project; the modal's *Spent by collaborators*).

**Scans carry their actor (step 5.5).** Every scan start names the person beside the tenant: `scanJobCredential(projectId, ownerId, actorUserId)` returns `{job_credential, actor_user_id}`, and the orchestrator admits and caps the scan on its actor (`[scan] start <kind> project= tenant= actor=`) and lists it in `/system/active-scans`. Deferred work re-checks its actor when it fires, whatever the switches (`lib/authz/scanActor.ts` `actorScanRefusal`: a fresh `can()` for each permission of `queuedJobPermissions`): the queue cancels a job whose actor lost access (`actor_no_access`, `job_queue.cancelled`), the scheduler pauses the schedule (`pausedReason: 'actor_no_access'`, `scan_schedule.paused`, a `schedule_paused` notice to the owner), and only `POST /api/projects/[id]/schedules/[scheduleId]/confirm` (`recon:schedule` at Manage plus what the schedule starts; `scan_schedule.confirmed`) resumes it, with the confirmer as its actor; `ScanScheduleTable` shows the paused badge and Confirm.

**Revocation stops live work (step 5.9).** Every loss of access calls `onAccessReduced(projectId, userId, reason)` (`lib/authz/revocation.ts`) after its change commits, and each reason plays its plan (`PLANS`). On a project (`share_revoked`, `share_left`, `share_expired`, `share_force_revoked`, `share_reduced`, `consent_withdrawn`) the agent stops the person's runs there (`/agent-sessions/stop-for`) and closes their sockets on it (`/ws/close`, scope `access`); their not-started jobs and enabled schedules on the project are re-checked with the queue's own check and only the refused ones are cancelled or paused, each with its audit row and conditional on its state; a live triage run they started is stopped. For an account (`account_disabled`, `account_deleted`, `sessions_revoked`, `credentials_reset`, `reset_link_used`, `root_transferred`, `capability_removed`, `device_session_revoked`, `terminal_grant_removed`) its sockets close and, where the reason says so, its runs stop and its impersonations end. A narrowing plays the project plan too (sockets reconnect with a fresh `cap`; only the scans the person may no longer start are cancelled). A step that cannot reach the agent logs `[rbac] revocation step failed step=<step>` and the change stands; MCP tokens fail at their next call.

**Conversations on a shared project (step 5.8).** A conversation stays its author's (`lib/authz/conversationAccess.ts`). With write sharing in force the author may share it with the project, read-only (`POST /api/conversations/[id]/share`, `agent:conversations_share`; `conversation.share` / `.unshare`), and the owner may let the owner and co-owners read every conversation (`GET|POST /api/conversations/policy?projectId=`: GET at `agent:chat` so a collaborator sees who reads theirs, POST the owner's; `project.conversations_policy`; stored in `project_access_policies.managers_see_all_conversations`). Another person's conversation is the agent's thoughts and tool output word for word, so it is raw data: read at `graph:read` + `R*` (`requireConversationRead`), never by a Read share without Raw data or an overseer, and read-only (PATCH and appends answer 409 `conversation_read_only`). The list answers own + shared + all under the policy (`conversationListScope`). Deleting an account reassigns its conversations in other people's projects to each project's owner with `formerAuthorId` / `formerAuthorLabel`, in the delete's transaction, whenever the write switch is on; the drawer shows them *by <name> (account deleted)* without the composer (`ReadOnlyConversationNotice.tsx`), and the owner may delete them.

**Plugins, Agent in the Loop and shell sessions on shared projects (step 5.10).** A plugin's project level comes from its granted and declared permissions (`lib/plugins/permissions.ts` `pluginProjectLevels`): any permission Read + Write, `llm:invoke` also Use AI agent, none the owner's. The Gateway asks it of the call token's user on every call (a shortfall is the same 404 as a revoked share) and refuses a project whose owner is no longer the token's `ten`; the action start and the skill picker answer a collaborator below it 403 `{permission: plugins:use, level}`. A plugin reads a session only when it is its user's own or its author shared it with the project. A plugin's model call runs the owner's model as the owner after a `credits.used` row (`feature: plugin_llm`). The project-scope change sets (approve, reject, delete, reset, the review and versions reads) need Manage. Over MCP the loop list and `start_triage_run` / `stop_triage_run` reach a shared project at Use AI agent (the run names its person as `actor_user_id`), `kali_exec`, `kali_output` and `kali_cancel` at Exploitation & shells; the shell sessions list adds the projects shared at `agent:sessions`' W+X (`agentSessionsAccess.ts`).

**Ownership transfer (step 5.12).** The owner offers a project to a collaborator with an unexpired share (`POST /api/projects/[id]/transfer`, `project:transfer` at the owner level, the owner's password, never while acting; one open offer), choosing whether to stay on as a co-owner or leave; the recipient accepts with their own password (`.../accept`) or declines (`.../decline`), both session-only; the owner cancels (`.../cancel`); the new owner dismisses the re-pick list (`.../acknowledge`); `GET /api/projects/transfers` feeds the header banners (`components/projects/OwnershipTransfer/`). An offer lapses after 7 days. Acceptance (`lib/authz/ownershipTransfer.ts`) takes the in-process graph lock (holder `transfer`), then the project lock (`Project.activationState`, `lib/graphHold.ts`: scan starts, tickets, partial recon, recording, rescope, the settings save and the MCP settings, preset, scope and RoE writers answer 409 `project_transfer_in_progress`), checks that nothing runs (live scans and queue rows, and the agent's `GET /agent-sessions/project-work`: agent runs, CodeFix sockets, the triage run; 409 `project_busy` naming it, and an agent that cannot say counts as busy), writes `in_progress`, closes every socket of the project, has the agent move the graph (`POST /graph/retenant`, graph_db `TenancyMixin.retenant_project`: every tenant-keyed label, only `user_id` changes, a key collision refused before any write, a failed write moved back), then commits one Postgres transaction (the owner, the auth profile, the conversations a deleted author left and a leaving owner's own, the co-owner share, the consent cleared, the old owner's providers, Jev provider, skills, Nuclei templates and GitHub token cleared and listed for the new owner to re-pick, `completed` with its audit row; it compares `updatedAt` as it read it, `project_changed` otherwise), then calls `onAccessReduced` and sends both people a `project_transfer` notice. From the moment the graph move starts the hold is `transfer_split`: it never goes stale and nothing else takes it until the move completes or the graph is verified whole again, so an attempt that may have split the graph (a lost agent answer, a failed move back, a crashed copy) keeps the project held, never lapses, and is completed by accepting again or undone by a decline or cancel, which first moves the graph back under the same locks. The agent refuses a ticket whose `ten` is no longer the project's owner or whose project a transfer holds (`ws_ticket.ticket_tenancy_refusal`), and a version activation restores under the current owner. Some finding ids name the owner whose scan minted them (OQ-R8), so after a transfer the new owner's scans record such a finding anew; the offer and the re-pick banner say so.

**Deleting a user who owns shared projects (step 5.13).** With the write switch on, `DELETE /api/users/[id]` refuses while the account owns a project with an unexpired share that is neither transferred nor named in the body's `deleteAnyway` (409 `deletion_plan_unresolved {projects, plan}`, after the last-admin, Root and step-up checks and before any teardown); `user.delete` records `deletedAnyway`. `GET|POST /api/users/[id]/deletion-plan` (`users:delete`, never one's own account, never while acting) lists the plan and takes `{action: offer|force|cancel, projectId, toUserId?, stepUpPassword?}`: an offer to a collaborator (the admin's password; the old owner leaves), Root's forced transfer without acceptance (`projects:administer`, then Root's password; the acceptance's own path, audited `project.transfer.forced`), or a withdrawal. `components/admin/DeleteUserWizard.tsx` replaces the Users page's Delete confirmation while the switch is on and keeps Delete disabled until each shared project is transferred or marked *delete anyway*. After the account row is gone `onAccessReduced(null, id, 'account_deleted')` runs with sharing on (`lib/authz/userDeletion.ts`), and a role change under the identity switch calls `'sessions_revoked'`. With the switch off the plan answers 404 and the delete is the Phase 1 teardown.

**Admin console and governance (`RBAC_GOVERNANCE_ENABLED`, needs `RBAC_PERMISSIONS_ENABLED`).** `app/admin/layout.tsx` answers `notFound()` with the switch off, before anything renders or is fetched; `consoleSections.ts` lists the eight sections with the permissions that open each (`anyOf`), and `AdminConsole.tsx` is the shell that shows a denied state naming the missing permission on any section path, so a section page only renders its routes' 403 with `ForbiddenNotice`. `app/settings/users/layout.tsx` sends a `users:read` holder to `/admin/users` (another console permission to `/admin`; members and `?changePassword=true` stay), and the header's **Users** link becomes **Admin**. Every route below answers 404 with the switch off before any read; `lib/authz/governance.flags.off.test.ts` lists every production reader of the switch and proves the switch-off answers.
- **Users** (`app/admin/users/`): `GET /api/admin/users` (search, status, type, `set`, keyset cursor) and `GET /api/admin/users/[id]` (`users:read`; `lib/authz/userDirectory.ts`, row actions from `hierarchy.ts` `canManage`; recent audit rows through `auditReader.ts` with `audit:read`). The page reuses the Phases 2-3 account routes for its actions; there is no create-with-a-temporary-password form under the console.
- **Permission sets / Admin profiles** (`app/admin/permission-sets/`, `app/admin/admin-profiles/`): the Phase 3 management routes; `setModel.ts` mirrors `permissionSetAdmin.ts`'s rules, and the editor offers only what the viewer holds.
- **Projects and Shares** (`app/admin/projects/`, `app/admin/shares/`): `GET /api/admin/projects` (`projects:oversee`), `DELETE /api/admin/projects/[id]` (Root through `requireRootPower`, the owner's `teardownProject` with the owner as tenant, `project.delete` `after.forced` written after the teardown), `GET /api/admin/shares` (`users:read`, sharing in force, 403 `shares_hidden` while `adminsSeeAllShares` is false), `DELETE /api/admin/shares/[projectId]/[userId]` (Root; `lib/authz/adminShares.ts` `forceRevokeShare`).
- **Operations** (`app/admin/operations/`): `GET /api/admin/operations` and `POST /api/admin/operations/agent-runs/stop` (`platform:operations`, the stop also `platform:emergency_stop`; `lib/authz/adminOperations.ts` reads the agent's `GET /agent-sessions/all`, the orchestrator's active scans, the queue, live triage runs and shell sessions).
- **Audit** (`app/admin/audit/`): `GET /api/admin/audit`, `/api/admin/audit/[id]` (`audit:read`) and `/api/admin/audit/export` (`audit:export`; streamed in batches, at most 100 000 rows written before it started, `audit.exported` written before the first byte or nothing is sent; `lib/authz/auditReader.ts`, `auditExport.ts`). There is no delete route; `lib/authz/auditRetention.ts` is the only deleter (below).
- **Instance** (`app/admin/instance/`): one `GET /api/admin/instance-settings` drives the panels (`instanceView.ts` decides which), each group of `PUT` asks its own permission: the security policy, public address, sharing policy and audit retention the confirmed Root with step-up, `quotas` `instance:quotas` (no step-up), the tunnel `platform:tunnels`; the default member set goes through `PUT /api/admin/permission-sets/[id]`, Nuclei templates through `/api/nuclei-templates`, TrafficMind through the kept `TrafficMindSettingsModal`.
- **Quotas**: `lib/authz/quotas.ts` (`quotaLimit(userId, kind)`: the account's entry, else the most permissive set in force, else the default; `null` unlimited; Root never limited; nothing read with the switch off; a failed read throws, so callers fail closed). Enforced at the project create and import routes and MCP `create_project` (`maxProjects`), the MCP token mint and its expiry PATCH (`maxMcpTokens`, `maxMcpTokenExpiryDays`), every scan start (the actor's `maxConcurrentScans`, sent as `actor_max_concurrent`; the orchestrator admits `min(quota, RECON_MAX_CONCURRENT_PER_USER)`), the agent socket's ticket (`maxConcurrentAgentRuns` from the agent's `GET /agent-sessions/count`, 503 `agent_run_count_unavailable` when it cannot answer). Refusal: 409 `quota_exceeded {quota, limit}` and `[rbac] quota_exceeded`. `GET /api/users/[id]/quota` feeds `components/quotas/QuotaUsage.tsx` on My account and the admin user page.
- **Device sessions**: `lib/authz/deviceSessions.ts` (a `user_sessions` row and a `sid` claim at login and invite accept; `getSession` refuses a revoked or unknown `sid`; a token without `sid` stays valid; sign-out ends the row), `deviceSessionAdmin.ts`, `GET /api/account/sessions`, `DELETE /api/account/sessions/[sid]`, `GET /api/users/[id]/sessions`, `DELETE /api/users/[id]/sessions/[sid]` (`users:revoke_sessions`, an admin target the hierarchy's step-up, never Root), `components/admin/DeviceSessions.tsx`. A revoke closes every socket the account opened (tickets name no device session).
- **Instance LLM providers**: `lib/instanceProviders/` (`store.ts`, `entitlement.ts`: assigned through permission sets, the project owner's on a shared project; `models.ts`: picker groups `Instance: <name>` with ids `instance/<providerId>/<model>`; `budget.ts`), `GET|POST /api/admin/llm-providers`, `PUT|DELETE /api/admin/llm-providers/[providerId]`, `PUT /api/admin/llm-providers/policy` (`byoLlmForbidden`; all the confirmed Root's, writes with step-up, keys masked by `maskProvider`), `GET /api/account/llm-providers` (Global Settings' list). The agent receives the entitled rows only on the master-key `GET /api/users/[id]/llm-providers?internal=true` list, and reports usage to `GET|POST /api/internal/llm-usage` (master key, in `INTERNAL_ALLOWLIST`).
- **Per-plugin allowlists**: `lib/plugins/accessRules.ts` and `/api/plugins/[pluginId]/access-rules` ([README.PLUGINS.md](README.PLUGINS.md) §7.1).
- **Audit retention and forwarding**: Root's `auditRetentionDays` (null = forever, else 90 to 36 500 days) waits 7 days in `auditRetentionPending` before the expiry sweep applies it, and `auditRetention.ts` keeps every action a `prisma.auditLog.find*` reads back (its static test fails on a new reader whose action is not kept). `AUDIT_FORWARD` ([README.DEV.md](README.DEV.md) §8): every audit-table write goes through `lib/auditForward.ts`, and a transaction that writes a row runs in `auditedTransaction` (`lib/auditWriters.static.test.ts`).

**Internal callers (STRIDE S2/E2 + S3/E6).** The agent, cypherfix and the orchestrator present `X-Internal-Key` (constant-time compared) and are carved out via `isInternalRequest(request)`, restricted to an **allowlist** of the exact routes they call. `INTERNAL_ALLOWLIST` in `webapp/src/middleware.ts` is that list; it covers the user and project reads (llm-providers, settings, tradecraft, project GET), codefix-sandbox and GuardDog, capture config and traffic ingest, conversations/by-session and remediations, the tunnel config, the scan scheduler and scan queue, MCP token pruning, and the tracked graph writers' check-ins: `/api/internal/triage-runs/*` and `/api/internal/node-filter-runs/*` (the agent reads the Mute Rules apply run it was handed, heartbeats it and reports how it ended). Each of those routes re-checks `isInternalRequest` itself, because the key is global and not a tenant boundary. The allowlist is **log-only by default**; set `INTERNAL_KEY_ALLOWLIST_ENFORCE=true` to block off-allowlist internal-key requests once logs confirm only known routes. Scanners instead present a **lower-tier `SCANNER_API_KEY`** (`isScannerRequest`), accepted ONLY on GET `/api/users/[id]/settings` and GET `/api/projects/[id]` - never llm-providers or user-CRUD, so a compromised scanner cannot harvest LLM keys or mint an admin.

**When adding a route:** with sharing in mind, a read route answers a collaborator and an overseer too, so take the tenant from the access and run its output through the read views above; derive identity from `getEffectiveUser()`/`requireUserAccess`, never from a query/body `userId`/`projectId`; ask its permission through one of the checks above before any data read (never an inline owner or role check); add its manifest entry with that permission (`node scripts/gen-route-manifest.mjs`); and cover it with a cross-user 403/404 test and its family's `*.permissions.test.ts` case. The live end-to-end checks are `tests/test_e2e_bola_live.sh` and `tests/rbac_matrix_live.sh`.

---

## Prerequisites

**Neo4j must be running first.** This webapp connects to the existing Neo4j instance in `../graph_db/`.

```bash
# Start Neo4j from the graph_db folder
cd ../graph_db
docker compose up -d

# Verify Neo4j is running
# Neo4j Browser: http://localhost:7474
```

---

## Development Setup

```bash
# 1. Make sure Neo4j is running (see Prerequisites above)

# 2. Install dependencies
npm install

# 3. Environment is auto-configured via docker-compose defaults
# All API keys and settings are managed from the webapp UI at /settings

# 4. Run development server (with hot reload)
npm run dev

# 5. Access the application
# Web App: http://localhost:3000
```

The development server uses Turbopack for fast refresh - changes to your code are reflected instantly.

---

## Production Build & Deployment

### Build Production Image

```bash
# Build the production image
docker build -t redamon-webapp:latest .

# Run production container locally
docker run -p 3000:3000 \
  --network graph_db_default \
  -e NEO4J_URI=bolt://redamon-neo4j:7687 \
  -e NEO4J_USER=neo4j \
  -e NEO4J_PASSWORD=your_password \
  redamon-webapp:latest
```

### Production with Docker Compose

```bash
# 1. Make sure Neo4j is running (from graph_db folder)
cd ../graph_db && docker compose up -d && cd ../webapp

# 2. Environment is auto-configured via docker-compose defaults
# All API keys and settings are managed from the webapp UI at /settings

# 3. Build and start services
docker compose up -d --build

# 4. View logs
docker compose logs -f webapp

# 5. Check health
curl http://localhost:3000/api/health
```

### Production Image Details

The production Dockerfile uses a multi-stage build:

1. **deps**: Installs production dependencies
2. **builder**: Builds the Next.js application
3. **runner**: Minimal runtime image (~150MB)

Features:
- Non-root user for security
- Standalone output for minimal image size
- Health check endpoint included
- Optimized for container orchestration

### Gotchas

- **The stack serves the baked production build.** Outside dev mode (see
  [README.DEV.md §5.3](README.DEV.md#53-hot-reload-vs-rebuild)) an edit under
  `webapp/src` is invisible until you rebuild:
  `docker compose build webapp && docker compose up -d --no-deps webapp`.
  Do not use `./redamon.sh update` for uncommitted work, because it runs `git pull`
  first. Confirm the change reached what is served with
  `docker exec redamon-webapp grep -rl '<new rule>' /app/.next/static/chunks/`,
  and check free memory before building
  ([TROUBLESHOOTING.md](TROUBLESHOOTING.md#host-and-docker-gotchas)).
- **Every container start runs `prisma db push --accept-data-loss`** against the
  image's own `prisma/schema.prisma` ([webapp/Dockerfile](../../webapp/Dockerfile)).
  Starting an image built from an older schema DROPS every column that exists only
  in a newer one, including a column someone else added in an uncommitted schema
  edit on the same database.
- **A new column's `@default` fills every existing row.** The push adds it as
  `ADD COLUMN ... NOT NULL DEFAULT <value>`, so a default meant for new projects
  only (a switch that should stay off where it never existed) reaches every
  project on the next start. Add the column first, with the value existing rows
  must keep, in a step that runs before the push in both the entrypoint and the
  dev command (`tests/webapp_dev_startup_parity_test.sh` compares them); the push
  then only changes the default. `webapp/scripts/add-js-recon-trufflehog-column.mjs`
  is the pattern.
- **A CSS-module selector list whose items each hold two `:global()`s compiles
  wrong.** Next 16 / Turbopack emits a stray `)` on the last item, for example
  `:global([data-theme="light"]) .header :global(.a):disabled, :global([data-theme="light"]) .header :global(.b):disabled {}`.
  The browser drops the whole rule and the build prints no error. Write one
  selector per rule. One `:global()` per list item is fine. It only shows in the
  built CSS, so check the served chunks as above.

---

## AWS Deployment Guide

### Prerequisites

- AWS CLI configured
- ECR repository created
- ECS cluster or EKS cluster ready

### 1. Push to Amazon ECR

```bash
# Authenticate with ECR
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin \
  YOUR_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com

# Tag image
docker tag redamon-webapp:latest \
  YOUR_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/redamon-webapp:latest

# Push image
docker push \
  YOUR_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/redamon-webapp:latest
```

### 2. ECS Fargate Deployment

Create a task definition (`task-definition.json`):

```json
{
  "family": "redamon-webapp",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "arn:aws:iam::YOUR_ACCOUNT:role/ecsTaskExecutionRole",
  "containerDefinitions": [
    {
      "name": "webapp",
      "image": "YOUR_ACCOUNT.dkr.ecr.us-east-1.amazonaws.com/redamon-webapp:latest",
      "portMappings": [
        {
          "containerPort": 3000,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {"name": "NODE_ENV", "value": "production"},
        {"name": "NEO4J_URI", "value": "bolt://your-neo4j-endpoint:7687"}
      ],
      "secrets": [
        {
          "name": "NEO4J_PASSWORD",
          "valueFrom": "arn:aws:secretsmanager:us-east-1:YOUR_ACCOUNT:secret:redamon/neo4j"
        }
      ],
      "healthCheck": {
        "command": ["CMD-SHELL", "wget -q --spider http://localhost:3000/api/health || exit 1"],
        "interval": 30,
        "timeout": 5,
        "retries": 3,
        "startPeriod": 60
      },
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/redamon-webapp",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
```

Deploy:
```bash
# Register task definition
aws ecs register-task-definition --cli-input-json file://task-definition.json

# Create service with ALB
aws ecs create-service \
  --cluster your-cluster \
  --service-name redamon-webapp \
  --task-definition redamon-webapp \
  --desired-count 2 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[subnet-xxx],securityGroups=[sg-xxx],assignPublicIp=ENABLED}" \
  --load-balancers "targetGroupArn=arn:aws:elasticloadbalancing:...,containerName=webapp,containerPort=3000"
```

### 3. Auto Scaling Configuration

```bash
# Register scalable target
aws application-autoscaling register-scalable-target \
  --service-namespace ecs \
  --scalable-dimension ecs:service:DesiredCount \
  --resource-id service/your-cluster/redamon-webapp \
  --min-capacity 2 \
  --max-capacity 100

# Create scaling policy (target tracking)
aws application-autoscaling put-scaling-policy \
  --service-namespace ecs \
  --scalable-dimension ecs:service:DesiredCount \
  --resource-id service/your-cluster/redamon-webapp \
  --policy-name cpu-tracking \
  --policy-type TargetTrackingScaling \
  --target-tracking-scaling-policy-configuration '{
    "TargetValue": 70.0,
    "PredefinedMetricSpecification": {
      "PredefinedMetricType": "ECSServiceAverageCPUUtilization"
    },
    "ScaleOutCooldown": 60,
    "ScaleInCooldown": 120
  }'
```

### 4. Neo4j on AWS Options

**Option A: Amazon Neptune (Managed)**
- Fully managed graph database
- Compatible with openCypher (Neo4j query language)

**Option B: Neo4j AuraDB**
- Neo4j's managed cloud service
- Available on AWS Marketplace

**Option C: Self-hosted on EC2/EKS**
```bash
# EC2 with Docker
docker run -d \
  -p 7474:7474 -p 7687:7687 \
  -v /data/neo4j:/data \
  -e NEO4J_AUTH=neo4j/your_password \
  -e NEO4J_dbms_memory_heap_max__size=4G \
  neo4j:5-enterprise
```

---

## API Reference

### Health Check
```
GET /api/health
```
Returns service health status:
```json
{
  "status": "healthy",
  "timestamp": "2025-01-02T12:00:00.000Z",
  "services": {
    "neo4j": "connected"
  }
}
```

### Project Graph
```
GET /api/graph?projectId=<id>[&fresh=1]
```
Returns the project's graph for the visualization (cached per project, ETag-aware;
`fresh=1` drops the cache). The caller must own the project.

```
DELETE /api/graph?nodeId=<id>&projectId=<id>
```
Deletes one node of the project's graph.

### Recon Control API

The webapp provides endpoints to control reconnaissance scans via the Recon Orchestrator.

#### Start Recon
```
POST /api/recon/[projectId]/start
Content-Type: application/json

{
  "userId": "user-123"
}
```

Starts a new recon scan for the specified project. The recon container will:
1. Fetch project settings from `GET /api/projects/{projectId}`
2. Execute the scan pipeline
3. Stream logs in real-time
4. Update Neo4j with results

**Response:**
```json
{
  "project_id": "project-123",
  "status": "starting",
  "container_id": "abc123...",
  "started_at": "2024-01-15T10:30:00Z"
}
```

#### Get Recon Status
```
GET /api/recon/[projectId]/status
```

Returns current recon status:
```json
{
  "project_id": "project-123",
  "status": "running",
  "current_phase": "Port Scanning",
  "phase_number": 2,
  "total_phases": 7,
  "started_at": "2024-01-15T10:30:00Z"
}
```

**Status Values:** `idle`, `starting`, `running`, `completed`, `error`, `stopping`

#### Stream Recon Logs (SSE)
```
GET /api/recon/[projectId]/logs
Accept: text/event-stream
```

Server-Sent Events stream of real-time log output:
```
event: log
data: {"log": "Starting port scan...", "timestamp": "...", "phase": "Port Scanning", "phaseNumber": 2, "level": "info"}

event: complete
data: {"status": "completed", "completedAt": "..."}
```

#### Stop Recon
```
POST /api/recon/[projectId]/stop
```

Gracefully stops a running recon container.

#### Download Recon JSON
```
GET /api/recon/[projectId]/download
```

Downloads the recon output JSON file for the project.

### Plugin platform API

The design is in [README.PLUGINS.md](README.PLUGINS.md). Errors are `{error, code}` with a stable
`code`; a route that needs the plugin runner while it is down answers `503 runner_unavailable`.

**For the signed-in user** (session cookie; state-changing routes also require a JSON body and a
same-origin request, checked against `PLUGINS_ALLOWED_ORIGIN` when it is set):

| Route | What it does |
|---|---|
| `GET /api/plugins/status` | Platform version and whether the plugin runner is reachable (never a 5xx) |
| `GET /api/plugins/llm-features` | The plugins the user can choose a model for in Models by feature: `[{featureId: "plugin:<id>", pluginId, label, description}]` |
| `POST /api/plugins/[pluginId]/actions/[actionId]` | Runs a plugin action. Body `{context: {projectId?, sessionId?}, params}`; the project and session must be the user's. A sync action answers `{ok, result \| error}`; an async one `202 {jobId}` (a second click while it runs answers the same job). `409 model_required` when the action calls a model and none is chosen; `503 runner_unavailable` / `plugin_not_running` when the runner cannot run it |
| `GET /api/plugins/jobs/[jobId]` | An async action's job: `{status: queued\|running\|succeeded\|failed\|cancelled, progress, result, error, ...}`; owner only |
| `POST /api/plugins/jobs/[jobId]/cancel` | Cancels the owner's job |
| `GET /api/plugins` | The Plugins page model: the catalog's state, one entry per catalog plugin merged with the installed rows, each with its card state, the newest release this platform can run (with consent text) and any update; admins also see errors |
| `GET /api/plugins/[pluginId]` | One plugin; admins also get the last error, versions on disk, data usage, approved versions and whether a rollback is possible |
| `GET /api/plugins/contributions` | The UI every enabled plugin contributes (`nav`, `chatSessionActions`, `projectSkillsRow`), read from the stored manifests; an `updating` plugin is flagged |
| `GET /api/plugins/overrides/change-sets/[id]` | The review model of a proposed skill version (before/after per part, warnings, risk flags), built against the agent's live registry; only whoever decides the scope: its owner (or an admin acting as them), or a co-owner with Manage on a project scope (`scopeRefusal`, `lib/plugins/changeSetAccess.ts`); anyone else reads a 404 |
| `POST /api/plugins/overrides/change-sets/[id]/approve`, `.../reject` | Decide a proposal. A user-scope decision carries `{scopeOwnerId}`, which must be the effective user (`403 wrong_owner`). Approve re-checks the factory text and size with the agent: `409 stale_proposal` / `already_decided`, `422 over_limit`, `503 agent_outdated` |
| `DELETE /api/plugins/overrides/change-sets/[id]` | Deletes a version that is not active (`409 active_not_deletable`) |
| `GET /api/plugins/overrides/versions?point=skill.text&group=<skill>&projectId=<id>` | The versions of a built-in skill for the user's own scope, plus a project whose scope they decide (the owner, or a co-owner with Manage) |
| `POST /api/plugins/overrides/reset` | `{point, group, scopeType, scopeOwnerId?, projectId?}`: the scope's active version is cleared; works whatever the plugin's state |
| `GET /api/plugins/overrides/summary?projectId=<id>` | Per built-in skill of a project the user owns: the version that governs it, whether it applies (and why not), pending proposals |

Plugin pages: `/plugins/<pluginId>[/<screen>]` draws a plugin's `nav` screen (404 unless the plugin
is enabled and the screen is listed in its manifest) and `/plugins/external-link?url=` is where
every link in plugin text lands. The middleware sets a strict Content-Security-Policy on
`/plugins` and `/plugins/*` only.

**For admins** (the role is read from the database on every request, so a demoted admin's token is
refused; same-origin and JSON bodies; `409 plugin_busy` when another operation holds the plugin):

| Route | What it does |
|---|---|
| `POST /api/plugins/[pluginId]/install` | `{version, acceptedPermissions, restoreOverrides?}`: downloads the release the signed catalog pins, checks it, installs it. `acceptedPermissions` must be exactly the release's list; `restoreOverrides` is required when an earlier install left approved skill versions |
| `POST /api/plugins/[pluginId]/update` | `{version, acceptedPermissions}`: side by side, with the plugin's data migrations; new permissions need consent again |
| `POST /api/plugins/[pluginId]/rollback` | The previous version active again; refused (`no_down_migration`) when the data moved and cannot go back |
| `POST /api/plugins/[pluginId]/enable`, `.../disable` | Enable (also the Retry of a failed plugin) or disable; code and data stay |
| `POST /api/plugins/[pluginId]/uninstall` | `{mode: "keep" \| "purge", confirm: "<pluginId>"}`; purge deletes the plugin's data for every user and project and needs an export from the last hour |
| `GET /api/plugins/[pluginId]/export` | A JSON download of every row the plugin left (install, data, overrides) |
| `GET /api/plugins/[pluginId]/logs?lines=N` | The plugin's log from the runner's ring buffer |
| `POST /api/plugins/offline-install` | `multipart/form-data` with `archive`, `catalog`, `signature`, `acceptedPermissions`: the same checks as a download (Content-Length checked before the body is read) |

**For plugin code** (`/api/plugin-gateway/v1/*`, the Gateway): authenticated only by the call
token the webapp mints per action (`Authorization: Bearer`), never by a cookie or the internal key;
reached through the plugin-gateway proxy and denied at the single-host nginx. Every call re-checks
the plugin (enabled, ready, at the token's version), the permission (granted and declared), and that
the project and session still belong to the user. Operations: `session/read`, `llm/invoke`,
`data/{get,put,query,count,delete}`, `override/{get,propose,withdraw}`, `jobs/{progress,complete}`.
The wire format is `services/plugin_runner/sdk/contract_cases.json`.

**For the plugin runner** (`/api/plugin-runner/v1/run-list`): the runner key (`X-Plugin-Runner-Key`)
only.

**For the recon orchestrator** (`POST /api/internal/plugins/reconcile`): the master internal key.
Crash recovery, heals, revocations and clean-up; one at a time (`202 {skipped: "busy"}` while
another runs).

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NEO4J_URI` | Neo4j connection URI | `bolt://localhost:7687` (dev) / `bolt://redamon-neo4j:7687` (Docker) |
| `NEO4J_USER` | Neo4j username | `neo4j` |
| `NEO4J_PASSWORD` | Neo4j password | (set in .env.local) |
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://redamon:<POSTGRES_PASSWORD>@localhost:5432/redamon` (password from `.env`, generated on fresh install; host port loopback-only) |
| `RECON_ORCHESTRATOR_URL` | Recon orchestrator service URL | `http://localhost:8010` |
| `ORCHESTRATOR_API_KEY` | Sent as `X-Orchestrator-Key` on every orchestrator call; must match the orchestrator's value (auto-generated in `.env`) | (generated) |
| `INTERNAL_API_KEY` | Master service-to-service key. Attached (as `x-internal-key`) when the webapp proxies to the agent's guarded endpoints; accepted (constant-time) on the internal-route allowlist | (generated) |
| `SCANNER_API_KEY` | Lower-tier scanner token (S3/E6). Accepted only on GET `settings`, GET `projects` and POST `traffic/[projectId]/ingest`, and only beside the scan's job credential (`X-Redamon-Job`, `lib/authz/jobCredential.ts`), which binds the read to its tenant or project (the settings read also needs that project to still exist and belong to the tenant: `project_gone` otherwise); cannot mint admins or read llm-providers | (generated) |
| `INTERNAL_KEY_ALLOWLIST_ENFORCE` | When `true`, block internal-key requests to routes outside the allowlist; default is log-only | (unset = log-only) |
| `NODE_ENV` | Environment mode | `development` |
| `PORT` | Application port | `3000` |
| `PLUGIN_RUNNER_KEY`, `PLUGIN_CALL_TOKEN_SECRET` | The webapp↔runner key and the secret that signs plugin call tokens (must differ from `AUTH_SECRET`); empty, plugin routes fail closed | (generated) |
| `PLUGINS_ALLOWED_ORIGIN` | The public origin the same-origin check of plugin routes accepts (behind nginx, which drops the port from `Host`) | (unset: the request's host) |
| `PLUGIN_ACTION_MAX_TIMEOUT` | Cap on any plugin action, seconds | `900` |
| `PLUGIN_GATEWAY_CALLS_PER_TOKEN` | Gateway calls one call token may make | `600` |
| `PLUGIN_LLM_DAILY_CALL_CAP` | Model calls one plugin may make per user and UTC day | `100` |
| `PLUGIN_TRANSCRIPT_MAX_BYTES` | The most of one session transcript a plugin receives | `2097152` |
| `PLUGINS_CATALOG_URL` | The signed plugin catalog (its signature is `<url>.sig`) | the `redamon-plugins` repository's `catalog.json` |
| `PLUGINS_DOWNLOAD_HOSTS` | The only hosts the catalog and archives are fetched from, on every redirect hop (https only, public addresses only) | `github.com,objects.githubusercontent.com,release-assets.githubusercontent.com,raw.githubusercontent.com` |
| `PLUGINS_EXTRA_TRUSTED_KEYS` | Extra catalog signing keys an admin trusts, JSON `[{keyId, publicKey}]` (a custom catalog; the page warns) | (unset) |
| `PLUGINS_DIR` | Where the plugins volume is mounted | `/data/plugins` |
| `PLUGIN_ARCHIVE_MAX_BYTES` | Cap on a plugin archive, unpacked | `20971520` |
| `PLUGIN_DATA_MAX_ROWS`, `PLUGIN_DATA_MAX_BYTES` | One plugin's data quota (per data namespace, across every owner; platform-reserved collections not counted): rows, and bytes of stored values | `10000`, `52428800` |
| `PLUGIN_DATA_MAX_VALUE_BYTES` | The largest single value a plugin may store | `1048576` |
| `PLUGIN_DATA_MAX_ROWS_PER_OWNER` | Rows one plugin may keep for one user or project | `2000` |
| `PLUGIN_SKILL_TEXT_MAX_GROWTH` | How much larger than its factory text a whole skill may grow in an approved version (also read by the agent, which applies the same bound) | `1.5` |
| `AGENT_IN_THE_LOOP_ENABLED` | Shows the `loop/mcp` brain in the chat model picker and registers the three `loop_*` MCP tools; must match the agent's value (both read the repo-root `.env`) | `true` |
| `MCP_RATE_LOOP_PER_MIN` | The `loop` bucket of the MCP rate limiter, per token: the three `loop_*` tools | `120` |

---

## Recon Integration

The webapp integrates with the Recon Orchestrator to provide real-time reconnaissance control.

### React Hooks

**useReconStatus** - Polls recon status with smart intervals:
```typescript
import { useReconStatus } from '@/hooks/useReconStatus'

const { state, startRecon, stopRecon, isLoading, error } = useReconStatus({
  projectId: 'project-123',
  enabled: true,
  onComplete: () => refetchGraph(),
  onStatusChange: (status) => console.log('Status:', status)
})
```

**useReconSSE** - Connects to real-time log stream:
```typescript
import { useReconSSE } from '@/hooks/useReconSSE'

const { logs, currentPhase, currentPhaseNumber, isConnected, clearLogs } = useReconSSE({
  projectId: 'project-123',
  enabled: state?.status === 'running',
  onPhaseChange: (phase, num) => console.log(`Phase ${num}: ${phase}`),
  onComplete: (status) => console.log('Recon finished:', status)
})
```

### Components

| Component | Description |
|-----------|-------------|
| `GraphToolbar` | Contains Start Recon and Download JSON buttons |
| `ReconConfirmModal` | Confirmation dialog before starting recon (warns about data replacement) |
| `ReconLogsDrawer` | Slide-out panel showing real-time logs with phase progress |
| `KaliTerminal` | Interactive Kali sandbox terminal (xterm.js) with WebSocket PTY, auto-reconnect, fullscreen, dark theme |

### AI Agent Chat (AIAssistantDrawer)

The `AIAssistantDrawer` is the primary interface for interacting with the RedAmon pentesting agent. It communicates over WebSocket via the `useAgentWebSocket` hook and renders a real-time timeline of agent activity.

The component is split into a thin orchestrator (`AIAssistantDrawer.tsx`, ~426 lines) that composes purpose-built hooks and sub-components. All files live in `webapp/src/app/graph/components/AIAssistantDrawer/`.

#### Sub-components

| Component | Description |
|-----------|-------------|
| `AIAssistantDrawer` | Thin orchestrator — wires hooks together, renders sub-components |
| `DrawerHeader` | Header bar — connection status, history toggle, new chat, download, close |
| `PhaseIndicatorBar` | Phase badge, tool icons, attack skill badge, stealth/deep-think toggles, model badge, settings dropdown (Agent Behaviour, Tool Matrix, Agent Skills, then one group per enabled plugin with chat-session actions) |
| `ChatArea` | Scrollable message list — renders grouped items, loading eye, empty state |
| `InputArea` | Textarea, send/stop/resume buttons, Chat Skill picker (lightning bolt), `/skill` autocomplete, active skill badge |
| `ApprovalDialog` | Phase-transition approval overlay |
| `QuestionDialog` | Agent Q&A overlay (text / single-choice / multi-choice) |
| `SettingsModal` | Agent behaviour / tool matrix / attack skills settings overlay |
| `ModelPickerModal` | Model search and selection modal |
| `ApiKeyModal` | API key input modal |
| `SuggestionPanels` | Suggestion accordion shown in empty chat state |
| `AgentTimeline` | Chronological timeline of thinking steps, tool executions, plan waves, and confirmations |
| `ToolExecutionCard` | Individual tool execution card — tool name, args, output chunks, status, **Allow/Deny** buttons |
| `PlanWaveCard` | Parallel wave card — groups tools in a plan wave, **Allow/Deny** for dangerous waves |
| `TodoListWidget` | Agent's live task list |
| `FileDownloadCard` | Download card for agent-generated files (reports, exports) |

#### Plugin actions in the gear menu

After "Agent Skills" the settings dropdown shows a divider and one group per enabled plugin that
contributes `chat.session.actions`, labelled with the plugin's name and the plugin badge (never
"Plugins": the Tool Matrix already speaks of "MCP Tool Plugins"). The items stay disabled until the
first message creates the conversation. The click flow lives in
`components/plugins/usePluginChatActions.tsx` and `runPluginAction.ts`: an action that calls a model
asks for one first, an async action opens `JobProgressModal`, and a result that proposes a skill
version opens the core `OverrideReviewModal`; the "skill versions" item opens `SkillVersionsModal`
on the session's skill. These modals are core UI (`components/plugins/review/`), also reachable from
a project's Agent Skills settings.

#### Custom Hooks (`hooks/`)

| Hook | Owns |
|------|------|
| `useWebSocketHandler` | WebSocket message dispatch (18+ message types) |
| `useSendHandlers` | `handleSend`, `handleApproval`, `handleAnswer`, `handleStop`, `handleResume`, `handleSkillCommand`, `activateSkill`, active skill state |
| `useChatState` | `chatItems`, loading/stopped/phase state, `groupedChatItems` memo |
| `useInteractionState` | Approval / Q&A / tool-confirmation state + double-submit refs |
| `useConversationRestoration` | Conversation history, load/delete, `handleSelectConversation` |
| `useScrollBehavior` | Auto-scroll, `scrollToBottom`, `checkIfAtBottom` |
| `useApiKeyModal` | `API_KEY_INFO`, missing key detection, key save flow |
| `useModelPicker` | Model list fetch, search filtering, model selection |
| `useSettingsModal` | Project form state, debounced save, settings dropdown |
| `useAttackSkillData` | Attack skill list fetch |
| `useLoadingWord` | Rotating loading status word |
| `useDownloadMarkdown` | Markdown report generation and download |

#### Static files

| File | Content |
|------|---------|
| `types.ts` | `Phase`, `Message`, `FileDownloadItem`, `ChatItem`, `AIAssistantDrawerProps` |
| `phaseConfig.ts` | `PHASE_CONFIG`, `KNOWN_ATTACK_PATH_CONFIG`, `getAttackPathConfig()`, `formatModelDisplay()` |
| `suggestionData.ts` | Suggestion panel data (informational / exploitation / post-exploitation groups) |

#### Tool Confirmation in the Chat

When `REQUIRE_TOOL_CONFIRMATION` is enabled in Project Settings, the agent pauses before executing dangerous tools and the chat renders inline confirmation cards:

- **Single tool**: A `ToolExecutionCard` appears with `status: "pending_approval"` and **Allow / Deny** buttons
- **Parallel wave**: A `PlanWaveCard` appears listing all dangerous tools in the wave with **Allow / Deny** buttons
- The chat input is disabled while awaiting confirmation
- On **Allow**: the card transitions to `running` and the tool executes
- On **Deny**: the card shows an error state and the agent re-plans with an alternative approach

When the setting is disabled, an orange warning badge appears in the chat header.

An **Agent in the Loop** run (`loop/mcp`) follows this setting too. Turned off, a dangerous tool the external agent picks runs with no person checking it, so the chat drawer puts a red risk icon next to the run's *Agent in the Loop* chip; hovering it explains the risk (`LOOP_UNATTENDED_TOOLTIP` in `hooks/loopStatus.ts`).

#### Agent in the Loop status

A run whose model is `loop/mcp` sends `loop_status` frames (`LoopStatusPayload`; never persisted; no prompt or answer text). A frame carries the run's `state` (`thinking`, `running_tool`, `awaiting_human`, `finished`, `stopped`, `error` with a `code` such as `loop_no_driver` or `loop_step_declined`), the open step if any (`open`, or `claimed` while an agent's lease is live, with its purpose and iteration), whether an agent of the user has called in during the last minute (`driver.connected`), and, with no agent connected, `noDriverEndsInSeconds` before the run ends. The drawer stamps each frame with its arrival time (`stampLoopStatus`) to show that as a clock time: "Your agent stopped responding … ends at 14:32" once an agent served the chat, or a second line under the first-use notice. `hooks/loopStatus.ts` turns them into the strings the drawer shows: a chip in `AgentStatusChips`, the waiting line under the loading eye in `ChatArea`, and an "answered by" note on each think card. `CONNECTED.loop_state` restores the state after a reconnect.

Only the agent's own model picker (the project form's agent model and the drawer's model picker) offers `loop/mcp`, in an "Agent in the Loop" group, while the switch is on. Every other picker (AI pipeline model, Models by feature, Tradecraft, the project LLM gate) passes `excludeLoop`, and the saves behind them refuse a `loop/` id ([agentInTheLoop.ts](../../webapp/src/lib/agentInTheLoop.ts)).

#### WebSocket Hook API

```typescript
const {
  sendQuery,              // Send user question
  sendApproval,           // Respond to phase transition approval
  sendToolConfirmation,   // Respond to tool confirmation (approve/modify/reject)
  sendAnswer,             // Answer agent's question
  sendGuidance,           // Send mid-execution guidance
  sendStop,               // Stop agent execution
  sendResume,             // Resume from checkpoint
} = useAgentWebSocket({ userId, projectId, sessionId, onMessage })
```

### Phase Detection

The recon orchestrator automatically detects scan phases from log output:

| Phase | Description |
|-------|-------------|
| 1 | Domain Discovery |
| 2 | Port Scanning |
| 3 | HTTP Probing |
| 4 | Resource Enumeration |
| 4b | JS Recon (post-resource_enum, if enabled) |
| 5 | Vulnerability Scanning |
| 6 | MITRE Enrichment |
| 7 | GitHub Secret Hunt |

---

## Useful Commands

```bash
# Development
npm run dev              # Start dev server with Turbopack (hot reload)
npm run build            # Build for production
npm run start            # Start production server
npm run lint             # Run ESLint
npm run type-check       # Run TypeScript check

# Docker Production
docker compose up -d --build                           # Start prod
docker compose down                                    # Stop prod
docker compose ps                                      # List services
docker compose logs -f webapp                          # View logs

# Debugging
docker compose exec webapp sh                          # Shell into container

# Neo4j CLI (from graph_db folder)
cd ../graph_db && docker compose exec neo4j cypher-shell
```

---

## Troubleshooting

### Neo4j Connection Failed

1. Check if Neo4j is running: `cd ../graph_db && docker compose ps`
2. Verify credentials in `.env.local` match those in `../graph_db/.env`
3. Check Neo4j logs: `cd ../graph_db && docker compose logs neo4j`

### Build Fails with Memory Error

Increase Node.js memory limit:
```bash
NODE_OPTIONS="--max-old-space-size=4096" npm run build
```

### Permission Denied Errors (Docker)

The production image runs as non-root user. Ensure mounted volumes have correct permissions.

---

## Security Considerations

- Never commit `.env` or `.env.local` files
- Use AWS Secrets Manager for production credentials
- Enable Neo4j SSL/TLS in production
- Configure proper security groups for AWS deployment
- Implement rate limiting for API endpoints
- Use HTTPS with proper certificates (ALB handles this)
