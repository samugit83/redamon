/**
 * Live route-matrix rows for the permissions the routes ask (steps 3.8, 3.9, 4.7, 5.2):
 * tests/fixtures/rbac_matrix/p3_generated.tsv, p4_generated.tsv and p5_generated.tsv, run by
 * tests/rbac_matrix_live.sh like any other file.
 *
 *   node scripts/gen-rbac-matrix-rows.mjs           write the three files, print how many rows
 *   node scripts/gen-rbac-matrix-rows.mjs --check   change nothing, exit 1 if any file is stale
 *
 * Run from webapp/ (only Node is needed). For each permission the rows come from one
 * representative route, checked against the route manifest (routeManifest.json, the JSON copy
 * .mjs scripts read), so a route that stops asking for the permission fails the run instead of
 * leaving a row that proves nothing. Who holds what is read from the built-in sets
 * (permissionCatalog.json): the allowed row signs in as a seeded account whose set holds the
 * permission, the refused rows as one whose set lacks it, each on a project it owns
 * (webapp/scripts/e2e-rbac-seed.mjs); a member permission picks among the members, an
 * administration or platform one among the admins (an admin's refusal with the switch off would
 * be the account type's, not the permission's). Three rows per permission:
 *
 *   p3g-<permission>-allow   the holder; untagged (the answer is the same with the switch off)
 *   p3g-<permission>-deny    the account without it: 403 naming it        permissions:on
 *   p3g-<permission>-off     the same account with the switch off: allowed permissions:off
 *
 * Rows never start a scan: an allowed request is one the route refuses AFTER its permission check
 * (an invalid mode, a missing field, an unknown version), stops what is not running, or only reads;
 * `lacks="code":"forbidden"` proves the answer is not the permission's refusal. The one row that
 * changes something deletes a throwaway project the seed recreates (as baseline.tsv's owner rows do).
 * Permissions a route asks only after its own (requireAlso: recon:overwrite, project:rescope,
 * engagement:authorize on an import) are proved by the route tests: a built-in set that holds the
 * route's own permission and lacks the second does not exist, and the allowed request would act.
 *
 * p4_generated.tsv (step 4.7, SH-07): the same representatives, called by an account that reaches
 * another member's project at the Read level without Raw data & files (READERS: a collaborator on a
 * Read share, an admin by oversight), with sharing in force. A permission at `R` answers as its
 * holder's row; every other project level (`R*` and each write level) is refused, 403 naming the
 * permission, because the level decides, not the set: the reader's set holds it. Only the
 * representatives that call the reader's project are used (not a throwaway: a refusal that failed
 * would delete the shared project).
 *
 * p5_generated.tsv (step 5.2, SH-02, SH-03, PE-25): the same project representatives, called by the
 * Read + Write collaborators on member_c's PSHARED (WRITERS: an editor without a toggle, an operator
 * with Run scans, a red-teamer with Exploitation & shells, a co-owner with Manage; never PA or
 * member_b). With write sharing in force (`sharingwrite:on`) a writer reaches R, R* and W, M with
 * Manage, and a run level (W+S, W+A, W+X) only with its toggle AND the owner's consent, which the seed
 * does not give (step 5.6): those rows prove the run levels stay closed without it. With write sharing
 * not in force (`sharingwrite:off`, sharing still on) each share reads as Read without Raw data: the
 * editor's rows answer as p4's viewer.
 */
import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const WEBAPP = join(dirname(fileURLToPath(import.meta.url)), '..')
const OUT = join('..', 'tests', 'fixtures', 'rbac_matrix', 'p3_generated.tsv')
const OUT_SHARED = join('..', 'tests', 'fixtures', 'rbac_matrix', 'p4_generated.tsv')
const OUT_WRITE = join('..', 'tests', 'fixtures', 'rbac_matrix', 'p5_generated.tsv')

/**
 * The seeded accounts, in the order an allowed or a refused row picks them, with their set, how the
 * seed gives it (`sets`: assigned; `default`: no assignment, so *Default member* or, for an admin
 * without a profile, *Full admin*; `profile`: the admin profile), the seed key of their account id
 * (`{U}` in a path) and of the projects they own (`tmp`: a throwaway the delete row may remove).
 */
export const ACTORS = [
  { actor: 'operator', kind: 'member', set: 'builtin:recon-operator', seeded: 'sets', user: 'OPERATOR_ID', project: 'POPERATOR_ID', tmp: 'POPERATOR_TMP_ID' },
  { actor: 'analyst', kind: 'member', set: 'builtin:read-only-analyst', seeded: 'sets', user: 'ANALYST_ID', project: 'PANALYST_ID', tmp: 'PANALYST_TMP_ID' },
  { actor: 'noaccess', kind: 'member', set: 'builtin:no-access', seeded: 'sets', user: 'NOACCESS_ID', project: 'PNOACCESS_ID', tmp: null },
  { actor: 'member_a', kind: 'member', set: 'builtin:default-member', seeded: 'default', user: 'MEMBER_A_ID', project: 'PA_ID', tmp: null },
  { actor: 'admin_a', kind: 'admin', set: 'builtin:full-admin', seeded: 'default', user: 'ADMIN_A_ID', project: 'PADM_ID', tmp: null },
  { actor: 'usermgr', kind: 'admin', set: 'builtin:user-manager', seeded: 'profile', user: 'USERMGR_ID', project: null, tmp: null },
]

/**
 * The readers of p4_generated.tsv: who reaches whose project at Read without Raw data & files, with
 * sharing in force. `set` is the member set that decides their member permissions (an admin's member
 * side is *Default member* when never assigned), `project` the seed key of the project they read
 * (the viewer's Read share on member_c's PSHARED, step 4.4's seed; admin_a's oversight of member_a's PA).
 */
export const READERS = [
  { actor: 'viewer', id: 'viewer', via: 'share', set: 'builtin:default-member', seeded: 'default', user: 'VIEWER_ID', project: 'PSHARED_ID', tags: 'req:SH-07 req:SH-02' },
  { actor: 'admin_a', id: 'oversee', via: 'oversight', set: 'builtin:default-member', seeded: 'default', user: 'ADMIN_A_ID', project: 'PA_ID', tags: 'req:SH-07 req:SH-47' },
]

/**
 * The writers of p5_generated.tsv (step 5.2): member_c's Read + Write collaborators on PSHARED
 * (e2e-rbac-seed.mjs), each on *Default member*, with the toggles their share stores. `off` marks the
 * one whose rows are repeated with write sharing not in force.
 */
export const WRITERS = [
  { actor: 'editor', id: 'editor', set: 'builtin:default-member', user: 'EDITOR_ID', project: 'PSHARED_ID', toggles: {}, off: true },
  { actor: 'woperator', id: 'operator', set: 'builtin:default-member', user: 'WOPERATOR_ID', project: 'PSHARED_ID', toggles: { runScans: true } },
  { actor: 'redteamer', id: 'redteamer', set: 'builtin:default-member', user: 'REDTEAMER_ID', project: 'PSHARED_ID', toggles: { exploit: true } },
  { actor: 'coowner', id: 'coowner', set: 'builtin:default-member', user: 'COOWNER_ID', project: 'PSHARED_ID', toggles: { manage: true } },
]

/** Whether a Read + Write share with `toggles` reaches `level` with no owner consent (meetsLevel + 5.6). */
export function writeShareReaches(level, toggles) {
  if (level === 'R' || level === 'R*' || level === 'W') return true
  if (level === 'M') return toggles.manage === true
  return false
}

const NOT_REFUSED = ';lacks="code":"forbidden"'

/**
 * permission -> its representative request. `path` takes `{P}` (the actor's own project), `{TMP}`
 * (its throwaway) or `{U}` (its account id); `body` takes `{P}` too; `route` is the manifest path;
 * `allow` the answer of a holder. Routes that reach a service (the agent, Neo4j) also allow its
 * unavailable answers: the row proves the permission, not the service. The permissions without a
 * representative are listed with the reason in routePermissions.test.ts (NO_ROWS).
 */
export const REPRESENTATIVES = {
  'project:create': { method: 'POST', path: '/api/projects', route: '/api/projects', body: '{}', allow: '400;has=name is required' },
  'project:import': { method: 'POST', path: '/api/projects/import', route: '/api/projects/import', body: '{}', allow: '400;has=invalid_multipart' },
  'project:settings': { method: 'PUT', path: '/api/projects/{P}', route: '/api/projects/[id]', body: '{"updatedAt":"rbac-not-a-date"}', allow: '400;has=updatedAt is not a valid timestamp' },
  'project:delete': { method: 'DELETE', path: '/api/projects/{TMP}', route: '/api/projects/[id]', body: '-', allow: '200' },
  'project:export': { method: 'GET', path: '/api/projects/{P}/export', route: '/api/projects/[id]/export', body: '-', allow: '200' },
  'engagement:authorize': { method: 'GET', path: '/api/projects/{P}/authorizations', route: '/api/projects/[id]/authorizations', body: '-', allow: '200' },
  'roe:read': { method: 'GET', path: '/api/projects/{P}/roe/revisions', route: '/api/projects/[id]/roe/revisions', body: '-', allow: '200' },
  'roe:manage': { method: 'DELETE', path: '/api/projects/{P}/roe', route: '/api/projects/[id]/roe', body: '{}', allow: `400${NOT_REFUSED}` },
  'auth_profile:read': { method: 'GET', path: '/api/projects/{P}/auth-profile', route: '/api/projects/[id]/auth-profile', body: '-', allow: '200' },
  'auth_profile:manage': { method: 'PUT', path: '/api/projects/{P}/auth-profile', route: '/api/projects/[id]/auth-profile', body: '{"authType":"rbac-bogus"}', allow: '400;has=authType must be one of' },
  'recon:read': { method: 'GET', path: '/api/projects/{P}/versions', route: '/api/projects/[id]/versions', body: '-', allow: '200' },
  'recon:scan': { method: 'POST', path: '/api/recon/{P}/start', route: '/api/recon/[projectId]/start', body: '{"mode":"rbac-bogus"}', allow: '400;has=Invalid mode' },
  'recon:partial': { method: 'POST', path: '/api/recon/{P}/partial', route: '/api/recon/[projectId]/partial', body: '{}', allow: `400|409${NOT_REFUSED}` },
  'recon:schedule': { method: 'POST', path: '/api/projects/{P}/schedules', route: '/api/projects/[id]/schedules', body: '{"mode":"rbac-bogus"}', allow: `400${NOT_REFUSED}` },
  'scan:gvm': { method: 'POST', path: '/api/gvm/{P}/stop', route: '/api/gvm/[projectId]/stop', body: '-', allow: `200|404|409|502|503${NOT_REFUSED}` },
  'scan:secrets': { method: 'POST', path: '/api/trufflehog/{P}/profiles', route: '/api/trufflehog/[projectId]/profiles', body: '{}', allow: `400${NOT_REFUSED}` },
  'scan:supply_chain': { method: 'POST', path: '/api/supply-chain/{P}/stop', route: '/api/supply-chain/[projectId]/stop', body: '-', allow: `200|404|409|502|503${NOT_REFUSED}` },
  'scan:ai_attack': { method: 'POST', path: '/api/ai-attack-surface/{P}/rbac-no-such-run/stop', route: '/api/ai-attack-surface/[projectId]/[runId]/stop', body: '-', allow: `200|404|409|502|503${NOT_REFUSED}` },
  'scan:uploads': { method: 'DELETE', path: '/api/projects/{P}/wordlists', route: '/api/projects/[id]/wordlists', body: '-', allow: '400;has=Missing name parameter' },
  'scan:custom_templates': { method: 'DELETE', path: '/api/nuclei-templates', route: '/api/nuclei-templates', body: '-', allow: '400;has=Missing path parameter' },
  'scan:versions': { method: 'PATCH', path: '/api/projects/{P}/versions/rbac-no-such-version', route: '/api/projects/[id]/versions/[versionId]', body: '{}', allow: `404${NOT_REFUSED}` },
  'scan:versions_delete': { method: 'DELETE', path: '/api/projects/{P}/versions/rbac-no-such-version', route: '/api/projects/[id]/versions/[versionId]', body: '-', allow: `404${NOT_REFUSED}` },
  'self:presets': { method: 'GET', path: '/api/presets', route: '/api/presets', body: '-', allow: '200' },
  'preset:write': { method: 'POST', path: '/api/presets', route: '/api/presets', body: '{}', allow: '400;has=Preset name is required' },
  // Step 3.9: agent, analysis, data, self-service, plugins, platform.
  'agent:chat': { method: 'POST', path: '/api/agent/ws-ticket', route: '/api/agent/ws-ticket', body: '{"projectId":"{P}","sessionId":"rbac-probe-chat"}', allow: `200${NOT_REFUSED}` },
  // The route refuses nothing itself after its permission check: it relays the agent, which refuses
  // the missing question (422, before any model call; it counts one call against the caller's cap).
  'agent:assistants': { method: 'POST', path: '/api/agent/text-to-cypher', route: '/api/agent/text-to-cypher', body: '{"project_id":"{P}"}', allow: '422;has="upstreamStatus":422' },
  'agent:sessions': { method: 'GET', path: '/api/agent/sessions', route: '/api/agent/sessions', body: '-', allow: `200|502|503${NOT_REFUSED}` },
  'workspace:read': { method: 'GET', path: '/api/agent/workspace/list?projectId={P}&path=.', route: '/api/agent/workspace/list', body: '-', allow: `200|404|502|503${NOT_REFUSED}` },
  'graph:read': { method: 'GET', path: '/api/analytics/graph-overview?projectId={P}', route: '/api/analytics/graph-overview', body: '-', allow: `200|500|503${NOT_REFUSED}` },
  'graph:cypher': { method: 'POST', path: '/api/graph-views/execute', route: '/api/graph-views/execute', body: '{"projectId":"{P}","cypherQuery":"CREATE (n:RbacProbe) RETURN n"}', allow: `400${NOT_REFUSED}` },
  'graph:edit': { method: 'DELETE', path: '/api/graph?projectId={P}&nodeId=rbac-no-such-node', route: '/api/graph', body: '-', allow: `400|404|500|503${NOT_REFUSED}` },
  'triage:read': { method: 'GET', path: '/api/triage/muted?projectId={P}', route: '/api/triage/muted', body: '-', allow: `200|500|503${NOT_REFUSED}` },
  'triage:verdict': { method: 'POST', path: '/api/triage/verdict', route: '/api/triage/verdict', body: '{"projectId":"{P}"}', allow: '400;has=nodeId is required' },
  'triage:mute': { method: 'POST', path: '/api/triage/mute', route: '/api/triage/mute', body: '{"projectId":"{P}"}', allow: '400;has=nodeId is required' },
  'node_filters:manage': { method: 'PUT', path: '/api/projects/{P}/node-filters', route: '/api/projects/[id]/node-filters', body: '{}', allow: `400${NOT_REFUSED}` },
  'remediation:read': { method: 'GET', path: '/api/remediations?projectId={P}', route: '/api/remediations', body: '-', allow: '200' },
  'reports:read': { method: 'GET', path: '/api/projects/{P}/reports', route: '/api/projects/[id]/reports', body: '-', allow: '200' },
  'reports:delete': { method: 'DELETE', path: '/api/projects/{P}/reports/rbac-no-such-report', route: '/api/projects/[id]/reports/[reportId]', body: '-', allow: `404${NOT_REFUSED}` },
  'traffic:read': { method: 'GET', path: '/api/traffic/{P}', route: '/api/traffic/[projectId]', body: '-', allow: '200' },
  'traffic:export': { method: 'GET', path: '/api/traffic/{P}/export', route: '/api/traffic/[projectId]/export', body: '-', allow: '200' },
  'self:attack_skills': { method: 'GET', path: '/api/users/{U}/attack-skills', route: '/api/users/[id]/attack-skills', body: '-', allow: '200' },
  'self:chat_skills': { method: 'GET', path: '/api/users/{U}/chat-skills', route: '/api/users/[id]/chat-skills', body: '-', allow: '200' },
  'self:tradecraft': { method: 'GET', path: '/api/users/{U}/tradecraft-resources', route: '/api/users/[id]/tradecraft-resources', body: '-', allow: '200' },
  'self:mcp_servers': { method: 'GET', path: '/api/users/{U}/mcp', route: '/api/users/[id]/mcp', body: '-', allow: '200' },
  'self:llm_providers': { method: 'GET', path: '/api/users/{U}/llm-providers/rbac-no-such-provider', route: '/api/users/[id]/llm-providers/[providerId]', body: '-', allow: `404${NOT_REFUSED}` },
  'self:api_keys': { method: 'GET', path: '/api/users/{U}/settings/api-usage', route: '/api/users/[id]/settings/api-usage', body: '-', allow: '200' },
  'plugins:use': { method: 'GET', path: '/api/plugins/status', route: '/api/plugins/status', body: '-', allow: `200|503${NOT_REFUSED}` },
  'plugins:approve_overrides': { method: 'POST', path: '/api/plugins/overrides/change-sets/rbac-no-such-change-set/reject', route: '/api/plugins/overrides/change-sets/[id]/reject', body: '{}', allow: `400|404${NOT_REFUSED}` },
  'platform:nuclei_templates': { method: 'PATCH', path: '/api/nuclei-templates', route: '/api/nuclei-templates', body: '{"path":"rbac-no-such-template.yaml","promote":true}', allow: `400|404${NOT_REFUSED}` },
  // An id the route's own pattern refuses (an underscore): an unknown but valid id reaches the runner,
  // whose ring buffer answers 200 with no lines.
  'platform:plugins': { method: 'GET', path: '/api/plugins/rbac_no_such_plugin/logs', route: '/api/plugins/[pluginId]/logs', body: '-', allow: '400;has="code":"invalid_plugin_id"' },
  'users:delete': { method: 'DELETE', path: '/api/users/rbac-no-such-user', route: '/api/users/[id]', body: '{}', allow: `400|404${NOT_REFUSED}` },
  'users:impersonate': { method: 'POST', path: '/api/auth/act-as', route: '/api/auth/act-as', body: '{}', allow: `400${NOT_REFUSED}` },
}

/** The representatives step 3.9 added (their rows' `since`). */
const STEP_39 = new Set(Object.keys(REPRESENTATIVES).slice(Object.keys(REPRESENTATIVES).indexOf('agent:chat')))

function readJson(webappDir, rel) {
  return JSON.parse(readFileSync(join(webappDir, rel), 'utf8'))
}

function manifestPermission(entry, method) {
  if (!entry?.permission) return undefined
  return typeof entry.permission === 'string' ? entry.permission : entry.permission[method]
}

/** The rows, or throws naming the first representative the manifest or the sets cannot back. */
export function generateRows(manifest, catalog) {
  const byPath = new Map(manifest.map(e => [e.path, e]))
  const sets = new Map(catalog.sets.map(s => [s.id, new Set(s.permissions)]))
  const holds = (a, p) => sets.get(a.set)?.has(p) === true
  const rows = []
  for (const [permission, r] of Object.entries(REPRESENTATIVES)) {
    if (!Object.hasOwn(catalog.permissions, permission)) throw new Error(`${permission}: not in the permission registry`)
    const named = manifestPermission(byPath.get(r.route), r.method)
    if (named !== permission) {
      throw new Error(`${permission}: the manifest gives ${r.method} ${r.route} ${named ?? 'no permission'}; pick a route that asks for ${permission}`)
    }
    const pool = ACTORS.filter(a => a.kind === catalog.permissions[permission].kind)
    const holder = pool.find(a => holds(a, permission))
    const lacker = pool.find(a => !holds(a, permission))
    if (!holder || !lacker) throw new Error(`${permission}: no seeded account ${holder ? 'lacks' : 'holds'} it`)
    for (const a of [holder, lacker]) {
      if (r.path.includes('{TMP}') && !a.tmp) throw new Error(`${permission}: ${a.actor} owns no throwaway project`)
      if ((r.path + r.body).includes('{P}') && !a.project) throw new Error(`${permission}: ${a.actor} owns no project`)
    }
    const fill = (text, a) => text.replace('{P}', `\${${a.project}}`).replace('{TMP}', `\${${a.tmp}}`).replace('{U}', `\${${a.user}}`)
    const at = a => fill(r.path, a)
    const body = a => fill(r.body, a)
    const tags = 'req:PE-19 req:PE-22 probe:generated'
    const since = STEP_39.has(permission) ? '3.9' : '3.8'
    rows.push(
      [`p3g-${permission}-allow`, since, holder.actor, r.method, at(holder), body(holder), r.allow, tags],
      [`p3g-${permission}-deny`, since, lacker.actor, r.method, at(lacker), body(lacker), `403;has=${permission}`, `${tags} permissions:on`],
      [`p3g-${permission}-off`, since, lacker.actor, r.method, at(lacker), body(lacker), r.allow, `${tags} permissions:off`],
    )
  }
  return rows
}

/** The p4_generated rows, or throws naming the first representative the manifest cannot back. */
export function generateSharedRows(manifest, catalog) {
  const byPath = new Map(manifest.map(e => [e.path, e]))
  const sets = new Map(catalog.sets.map(s => [s.id, new Set(s.permissions)]))
  const rows = []
  for (const reader of READERS) {
    for (const [permission, r] of Object.entries(REPRESENTATIVES)) {
      const entry = catalog.permissions[permission]
      if (!entry) throw new Error(`${permission}: not in the permission registry`)
      if (entry.kind !== 'member' || entry.scope !== 'project' || entry.level === null) continue
      const text = r.path + r.body
      if (!text.includes('{P}') || text.includes('{TMP}') || text.includes('{U}')) continue
      if (manifestPermission(byPath.get(r.route), r.method) !== permission) {
        throw new Error(`${permission}: the manifest gives ${r.method} ${r.route} another permission`)
      }
      if (sets.get(reader.set)?.has(permission) !== true) continue
      const fill = t => t.replace('{P}', `\${${reader.project}}`)
      const expect = entry.level === 'R' ? r.allow : `403;has=${permission}`
      rows.push([`p4g-${reader.id}-${permission}`, '4.7', reader.actor, r.method, fill(r.path), fill(r.body), expect,
        `${reader.tags} probe:generated sharing:on`])
    }
  }
  return rows
}

/** The p5_generated rows, or throws naming the first representative the manifest cannot back. */
export function generateWriteRows(manifest, catalog) {
  const byPath = new Map(manifest.map(e => [e.path, e]))
  const sets = new Map(catalog.sets.map(s => [s.id, new Set(s.permissions)]))
  const rows = []
  for (const writer of WRITERS) {
    for (const [permission, r] of Object.entries(REPRESENTATIVES)) {
      const entry = catalog.permissions[permission]
      if (!entry) throw new Error(`${permission}: not in the permission registry`)
      if (entry.kind !== 'member' || entry.scope !== 'project' || entry.level === null) continue
      const text = r.path + r.body
      if (!text.includes('{P}') || text.includes('{TMP}') || text.includes('{U}')) continue
      if (manifestPermission(byPath.get(r.route), r.method) !== permission) {
        throw new Error(`${permission}: the manifest gives ${r.method} ${r.route} another permission`)
      }
      if (sets.get(writer.set)?.has(permission) !== true) continue
      const fill = t => t.replace('{P}', `\${${writer.project}}`)
      const refused = `403;has=${permission}`
      rows.push([`p5g-${writer.id}-${permission}`, '5.2', writer.actor, r.method, fill(r.path), fill(r.body),
        writeShareReaches(entry.level, writer.toggles) ? r.allow : refused,
        'req:SH-02 req:SH-03 probe:generated sharing:on sharingwrite:on'])
      if (writer.off) {
        rows.push([`p5g-${writer.id}-off-${permission}`, '5.2', writer.actor, r.method, fill(r.path), fill(r.body),
          entry.level === 'R' ? r.allow : refused, 'req:SH-02 req:DV-30 probe:generated sharing:on sharingwrite:off'])
      }
    }
  }
  return rows
}

export function renderWriteRows(rows) {
  const header = [
    '# Live RBAC route matrix: Phase 5 write sharing, generated by webapp/scripts/gen-rbac-matrix-rows.mjs (step 5.2).',
    '# Do not edit: change the representative or writer table there and run `node scripts/gen-rbac-matrix-rows.mjs`',
    "# from webapp/. Each project permission's representative request, called by member_c's Read + Write",
    '# collaborators on PSHARED: editor (no toggle), woperator (Run scans), redteamer (Exploitation & shells),',
    '# coowner (Manage). With write sharing in force (sharingwrite:on: RBAC_SHARING_WRITE_ENABLED and the policy',
    "# maxLevel \"write\") R, R* and W answer as for the owner, M for the co-owner, and every run level (W+S, W+A,",
    "# W+X) is refused: it also needs the owner's consent, which the seed does not give (step 5.6). With it not",
    '# in force (sharingwrite:off) the editor reads as Read without Raw data: R answers, the rest 403.',
    '#',
    '# id\tsince\tactor\tmethod\tpath\tbody\texpect\ttags',
  ]
  return [...header, ...rows.map(r => r.join('\t'))].join('\n') + '\n'
}

export function renderSharedRows(rows) {
  const header = [
    '# Live RBAC route matrix: Phase 4, generated by webapp/scripts/gen-rbac-matrix-rows.mjs (step 4.7). Do not edit:',
    '# change the representative or reader table there and run `node scripts/gen-rbac-matrix-rows.mjs` from webapp/.',
    "# Each project permission's representative request, called by a reader of another member's project at the",
    '# Read level without Raw data & files: viewer = a Read share on PSHARED (member_c\'s; step 4.4\'s seed),',
    '# admin_a = oversight of PA (member_a\'s). A permission at R answers as for its holder; R* and every write',
    '# level answer 403 naming the permission (the level refuses: the reader\'s set holds it). Every row needs',
    '# sharing in force: RBAC_SHARING_ENABLED on and the instance policy enabled (sharing:on).',
    '#',
    '# id\tsince\tactor\tmethod\tpath\tbody\texpect\ttags',
  ]
  return [...header, ...rows.map(r => r.join('\t'))].join('\n') + '\n'
}

export function renderRows(rows) {
  const header = [
    '# Live RBAC route matrix: Phase 3, generated by webapp/scripts/gen-rbac-matrix-rows.mjs (steps 3.8, 3.9). Do not edit:',
    '# change the representative table there and run `node scripts/gen-rbac-matrix-rows.mjs` from webapp/.',
    '# One permission per three rows: its holder (allowed, refused after the permission check or only reading),',
    '# an account whose built-in set lacks it with RBAC_PERMISSIONS_ENABLED on (403 naming it) and the same',
    '# account with it off (allowed, as today). Actors: operator = Recon operator, analyst = Read-only analyst,',
    '# noaccess = No access, member_a = Default member, each on a project it owns; admin_a = Full admin,',
    '# usermgr = an admin on User manager (e2e-rbac-seed.mjs).',
    '#',
    '# id\tsince\tactor\tmethod\tpath\tbody\texpect\ttags',
  ]
  return [...header, ...rows.map(r => r.join('\t'))].join('\n') + '\n'
}

/** The command line, on the webapp at `webappDir`; answers the exit code. */
export function run(argv, webappDir = WEBAPP, log = console.log) {
  const files = []
  try {
    const manifest = readJson(webappDir, 'src/lib/authz/routeManifest.json')
    const catalog = readJson(webappDir, 'src/lib/authz/permissionCatalog.json')
    files.push({ out: OUT, text: renderRows(generateRows(manifest, catalog)) })
    files.push({ out: OUT_SHARED, text: renderSharedRows(generateSharedRows(manifest, catalog)) })
    files.push({ out: OUT_WRITE, text: renderWriteRows(generateWriteRows(manifest, catalog)) })
  } catch (err) {
    log(`problem  ${err.message}. Nothing was written.`)
    return 1
  }
  const count = text => text.split('\n').filter(l => l && !l.startsWith('#')).length
  const name = out => out.replace(/^\.\.[\\/]/, '').split(/[\\/]/).join('/')
  const current = out => { try { return readFileSync(join(webappDir, out), 'utf8') } catch { return null } }
  if (argv.includes('--check')) {
    const stale = files.filter(f => current(f.out) !== f.text)
    for (const f of stale) log(`${name(f.out)} is out of date: run \`node scripts/gen-rbac-matrix-rows.mjs\` from webapp/.`)
    if (stale.length) return 1
    log(`rbac matrix rows up to date: ${files.map(f => `${count(f.text)} rows`).join(', ')}`)
    return 0
  }
  for (const f of files) {
    if (current(f.out) !== f.text) writeFileSync(join(webappDir, f.out), f.text)
    log(`rbac matrix rows: ${count(f.text)} rows written to ${name(f.out)}`)
  }
  return 0
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = run(process.argv.slice(2))
}
