/**
 * Live route-matrix rows for the permissions the routes ask (steps 3.8, 3.9):
 * tests/fixtures/rbac_matrix/p3_generated.tsv, run by tests/rbac_matrix_live.sh like any other file.
 *
 *   node scripts/gen-rbac-matrix-rows.mjs           write the file, print how many rows
 *   node scripts/gen-rbac-matrix-rows.mjs --check   change nothing, exit 1 if the file is stale
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
 */
import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const WEBAPP = join(dirname(fileURLToPath(import.meta.url)), '..')
const OUT = join('..', 'tests', 'fixtures', 'rbac_matrix', 'p3_generated.tsv')

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
  'auth_profile:manage': { method: 'PUT', path: '/api/projects/{P}/auth-profile', route: '/api/projects/[id]/auth-profile', body: '{}', allow: `400${NOT_REFUSED}` },
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
  'agent:assistants': { method: 'POST', path: '/api/agent/text-to-cypher', route: '/api/agent/text-to-cypher', body: '{"projectId":"{P}"}', allow: `400${NOT_REFUSED}` },
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
  'platform:plugins': { method: 'GET', path: '/api/plugins/rbac-no-such-plugin/logs', route: '/api/plugins/[pluginId]/logs', body: '-', allow: `400|404${NOT_REFUSED}` },
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
  const out = join(webappDir, OUT)
  let text
  try {
    text = renderRows(generateRows(
      readJson(webappDir, 'src/lib/authz/routeManifest.json'),
      readJson(webappDir, 'src/lib/authz/permissionCatalog.json'),
    ))
  } catch (err) {
    log(`problem  ${err.message}. Nothing was written.`)
    return 1
  }
  let current = null
  try { current = readFileSync(out, 'utf8') } catch { /* not written yet */ }
  if (argv.includes('--check')) {
    if (current !== text) {
      log('tests/fixtures/rbac_matrix/p3_generated.tsv is out of date: run `node scripts/gen-rbac-matrix-rows.mjs` from webapp/.')
      return 1
    }
    log(`rbac matrix rows up to date: ${text.split('\n').filter(l => l && !l.startsWith('#')).length} rows`)
    return 0
  }
  if (current !== text) writeFileSync(out, text)
  log(`rbac matrix rows: ${text.split('\n').filter(l => l && !l.startsWith('#')).length} rows written to tests/fixtures/rbac_matrix/p3_generated.tsv`)
  return 0
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = run(process.argv.slice(2))
}
