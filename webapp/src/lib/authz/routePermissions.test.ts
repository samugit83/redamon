/** @vitest-environment node */
/**
 * Every route's permission (PE-19, PE-22; steps 3.8, 3.9): each handler of each route names one in
 * the manifest, per method, and it is the permission the handler asks first, read from the source's
 * syntax tree (requirePermission, withPermission, requireSelfPermission, the administration checks
 * of adminPermission.ts, the shared tools of sharedTools.ts, and the module's own helpers it calls).
 * A route that changes its permission and not its entry (or the reverse) fails here, naming the
 * method and the path; so does a new route that asks for none. A handler no person's permission
 * backs is `null`: the route's credential is a key or none, or it answers every signed-in account
 * (SESSION_ONLY, with the reason).
 *
 * Whether each permission is enforced is proved by the families' `*.permissions.test.ts`, which run
 * the real guard; this file keeps the manifest, which the live matrix rows are generated from
 * (scripts/gen-rbac-matrix-rows.mjs), equal to the code, the generated rows equal to the manifest,
 * and every permission of an existing feature used somewhere (PE-19).
 */
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import ts from 'typescript'
import { describe, expect, test, vi } from 'vitest'
import { ROUTE_MANIFEST, type HttpMethod, type RouteManifestEntry } from './routeManifest'
import { PERMISSIONS, PERMISSION_IDS, isPermissionId } from './permissions'
import { SHARED_TOOL_PERMISSIONS, type SharedTool } from './sharedTools'
import { REPRESENTATIVES, run as runMatrixRows } from '../../../scripts/gen-rbac-matrix-rows.mjs'

// sharedTools.ts is imported for its table only: nothing here may reach a database or a session.
vi.mock('@/lib/prisma', () => ({ default: {}, prisma: {} }))
vi.mock('@/lib/session', () => ({ mayActAs: vi.fn() }))

const WEBAPP = join(__dirname, '..', '..', '..')

/**
 * Classes whose credential is a key or none: no person's permission backs them (`permission: null`).
 * A plugin call token is checked against the plugin namespace by withGateway (PLUGIN_PERMISSIONS),
 * not this registry.
 */
const NO_PERSON = new Set(['public', 'internal', 'scanner', 'plugin-token'])

/**
 * `<METHOD> <path>` of the handlers that answer every signed-in account, and why (`permission: null`).
 * Some ask a permission inside to decide a scope or a hint, which the reader below would read as
 * the route's: they are listed here so it is not.
 */
const SESSION_ONLY: Readonly<Record<string, string>> = {
  'GET /api/gvm/available': 'whether this install runs the GVM stack: an instance fact the scan tab reads to show or hide itself, no project data',
  'GET /api/js-recon/trufflehog/available': 'whether the TruffleHog image is present: an instance fact the JS recon tab reads, no project data',
  'GET /api/projects': 'the projects the account can see (visibleProjectsWhere): seeing one is project access, and each action on it asks its own permission',
  'GET /api/projects/defaults': 'the default values of a new project form: registry data, no project, nothing written',
  'GET /api/nuclei-templates': 'the templates the account may select or manage, scoped by owner inside (own and instance ones; every one with platform:nuclei_templates): reading the library changes nothing',
  'GET /api/account/activity': "the signed-in account's own notices and the audit rows about it (404 with the identity switch off): an account reads its own history",
  'GET /api/agent/health': 'whether the agent answers: an instance fact the drawer shows, no project data',
  'GET /api/agent/host-ip': "the host's address the drawer offers as a callback address: an instance fact, nothing written",
  'GET /api/agent/tunnel-status': 'whether the instance tunnel is up, for the drawer: an instance fact; changing the tunnel is platform:tunnels',
  'GET /api/auth/me': 'the signed-in account, its capabilities and the switches: what every screen reads to decide what to offer',
  'GET /api/auth/password-policy': 'the password rules a form shows before a password is typed: instance policy, no account data',
  'POST /api/auth/sessions/revoke-all': "signing one's own account out everywhere: always one's own",
  'GET /api/community-skills': 'the catalog of community skills an account may import: public catalog data; importing one is self:attack_skills / self:chat_skills',
  'GET /api/cypherfix/health': 'whether the CypherFix agent answers: an instance fact, no project data',
  'GET /api/skills': 'the built-in skill catalog the forms list: registry data, nothing written',
  'GET /api/system/stats': 'the memory meters of the header: an instance fact, no tenant data',
  'GET /api/user/preferences': "the signed-in account's own interface preferences",
  'PATCH /api/user/preferences': "the signed-in account's own interface preferences",
  'GET /api/ws': 'the WebSocket upgrade stub: no data; each socket is opened by its ticket, which asks its permission',
  'GET /api/system/jobs': "the account's own running and queued jobs and only a count of others': platform:operations is Phase 6's operations view",
  'DELETE /api/auth/act-as': 'ending act-as clears the cookie of the admin who set it: always allowed, never a new power',
  'GET /api/agent/emergency-stop-all': 'the scope a press would have: every account stops its own runs; platform:emergency_stop decides the global scope inside (sharedToolAccess)',
  'POST /api/agent/emergency-stop-all': 'every account stops its own runs (a safety stop is never refused); platform:emergency_stop decides the global scope inside (sharedToolAccess)',
  'GET /api/users/[id]/settings': "the account's own settings, secrets masked, which every screen reads (feature models, which keys are set); the tunnel hint inside is not a gate; storing them is self:api_keys",
}

/**
 * `<METHOD> <path>` of the handlers whose permission is not wired yet, and why. They name no
 * permission in the manifest until then.
 */
const LATER: Readonly<Record<string, string>> = {
  'GET /api/users/[id]/llm-providers': 'self:llm_providers: the route file is held by the review fix of step 3.7 (step 3.9 BLOCKED overlap); requireSelfPermission once it lands',
  'POST /api/users/[id]/llm-providers': 'self:llm_providers: the route file is held by the review fix of step 3.7 (step 3.9 BLOCKED overlap); requireSelfPermission once it lands',
  'GET /api/users/[id]/mcp-tokens': 'self:mcp_tokens: the route files are held by the review fix of step 3.7 (step 3.9 BLOCKED overlap); requireSelfPermission once it lands',
  'POST /api/users/[id]/mcp-tokens': 'self:mcp_tokens: the route files are held by the review fix of step 3.7 (step 3.9 BLOCKED overlap); requireSelfPermission once it lands',
  'PATCH /api/users/[id]/mcp-tokens/[tokenId]': 'self:mcp_tokens: the route files are held by the review fix of step 3.7 (step 3.9 BLOCKED overlap); requireSelfPermission once it lands',
  'DELETE /api/users/[id]/mcp-tokens/[tokenId]': 'self:mcp_tokens: the route files are held by the review fix of step 3.7 (step 3.9 BLOCKED overlap); requireSelfPermission once it lands',
}

/**
 * `<METHOD> <path>` of the handlers whose permission a helper asks without naming it to the reader,
 * and which helper. The manifest still names it (checked against the registry).
 */
const ASKED_IN_LIB: Readonly<Record<string, string>> = {
  'POST /api/admin/admin-profiles': 'admin_profiles:manage is Root-only: requireRootPower (the confirmed Root with step-up)',
  'PUT /api/admin/admin-profiles/[id]': 'admin_profiles:manage is Root-only: requireRootPower (the confirmed Root with step-up)',
  'DELETE /api/admin/admin-profiles/[id]': 'admin_profiles:manage is Root-only: requireRootPower (the confirmed Root with step-up)',
  'GET /api/users/[id]/permissions': 'userPermissionAdmin.readUserPermissions asks users:assign_permissions (admins:manage for an admin)',
  'PUT /api/users/[id]/permissions': 'userPermissionAdmin.changeUserPermissions asks users:assign_permissions (admins:manage for an admin)',
}

/**
 * Permissions a route names that have no generated live rows, and why. A row needs a seeded account
 * that holds the permission and one of the same kind that lacks it, and a request the holder makes
 * that changes nothing.
 */
const NO_ROWS: Readonly<Record<string, string>> = {
  'graph:views': 'every request that passes the route\'s own checks creates or changes a saved view',
  'remediation:write': 'every request that passes the route\'s own checks writes a remediation (the row checks come before the permission)',
  'reports:generate': 'generating a report writes it and may spend the owner\'s model credits',
  'traffic:delete': 'deleting captured traffic acts; route-tested (traffic.permissions.test.ts)',
  'workspace:write': 'every request that passes the route\'s own checks writes the agent\'s workspace',
  'workspace:import': 'every request that passes the route\'s own checks fetches from the network into the workspace',
  'self:mcp_tokens': 'the onboarding pack mints a token for the account; route-tested (selfService.permissions.test.ts)',
  'platform:agent_mcp': 'the reload acts on the shared agent; platformOverrideHolders.test.ts proves who holds it',
  'platform:tunnels': 'every administrator account opens the instance settings (the security policy), so no admin is refused there for lacking it; a member is refused with the switch either way; route-tested',
  'users:read': 'no seeded admin lacks it (User manager holds it); p2.tsv and the route tests cover the directory',
  'users:create': 'no seeded admin lacks it; p2.tsv covers invites and creation',
  'users:edit': 'no seeded admin lacks it; p2.tsv and the route tests cover account edits',
  'users:disable': 'no seeded admin lacks it; p2.tsv covers disabling and enabling',
  'users:reset_credentials': 'no seeded admin lacks it; p2.tsv covers resets',
  'users:revoke_sessions': 'no seeded admin lacks it; p2.tsv covers session revocation',
  'users:assign_permissions': 'no seeded admin lacks it; p3.tsv and the route tests cover permission changes',
  'root:transfer': 'Root\'s own (rootOnly): no seeded account other than Root holds it; p2.tsv covers the transfer',
  'roles:manage': 'no seeded admin lacks it and a member is refused by the switch-off 404 as well; the route tests cover it',
  'admin_profiles:manage': 'Root\'s own (rootOnly); the route tests cover it',
}

/**
 * Registry permissions no route names, and where they are enforced instead. Each is a feature that
 * exists today (`gatesExisting`); the later-phase ones are each phase's to wire.
 */
const ENFORCED_ELSEWHERE: Readonly<Record<string, string>> = {
  'agent:approve_phase': 'the agent refuses the answer through the ticket\'s cap (step 3.9b, websocket_api.py)',
  'agent:approve_dangerous': 'the agent refuses the answer through the ticket\'s cap (step 3.9b, websocket_api.py)',
  'agent:fireteam': 'the agent: a Fireteam member confirmation needs it in the ticket\'s cap (step 3.9b); starting a wave is the run\'s (OQ-R6 (b), step 5.3)',
  'admins:manage': 'asked of an admin target inside the user routes (hierarchy.ts canManage / canAssignProfile, rootPowers.ts adminTargetGate), after their users:* permission',
  'instance:settings': 'Root\'s own (rootOnly): the security policy of the instance settings and the instance default set, through requireRootPower (the confirmed Root with step-up)',
  'platform:shell_sessions': 'the every-session scope of the shell-session routes, under agent:sessions: agentSessionsAccess.ts asks sharedToolAccess(shell_sessions_all)',
}

const HANDLER_METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'])

/** Guards that take their permission as an argument, and its index. */
const PERMISSION_ARG: Readonly<Record<string, number>> = {
  requirePermission: 1, withPermission: 0, requireSelfPermission: 2,
  requireSessionPermission: 1, sessionHolds: 1, accountHolds: 1,
}

/** Helpers that always ask one permission. */
const FIXED_PERMISSION: Readonly<Record<string, string>> = {
  requirePluginAdmin: 'platform:plugins', lifecyclePost: 'platform:plugins', lifecycleGet: 'platform:plugins',
  transferForbidden: 'root:transfer',
}

interface Scope {
  /** Module-level string constants (`const PERMISSION = 'users:assign_permissions'`). */
  consts: Map<string, string>
  /** Module-level functions and constants a handler may call or pass by name. */
  locals: Map<string, ts.Node>
}

function literal(node: ts.Node | undefined, scope: Scope): string {
  if (node && ts.isStringLiteralLike(node)) return node.text
  if (node && ts.isIdentifier(node) && scope.consts.has(node.text)) return scope.consts.get(node.text)!
  return '<not a literal>'
}

/**
 * The permission of each guard call in a subtree, in order, following the module's own functions
 * the handler names (a helper it calls, a handler passed to withRouteErrors).
 */
function guardPermissions(node: ts.Node, scope: Scope = { consts: new Map(), locals: new Map() }): string[] {
  const out: string[] = []
  const followed = new Set<string>()
  const visit = (n: ts.Node) => {
    if (ts.isCallExpression(n) && ts.isIdentifier(n.expression)) {
      const name = n.expression.text
      if (Object.hasOwn(PERMISSION_ARG, name)) out.push(literal(n.arguments[PERMISSION_ARG[name]], scope))
      else if (Object.hasOwn(FIXED_PERMISSION, name)) out.push(FIXED_PERMISSION[name])
      else if (name === 'requireAnyPermission') {
        const list = n.arguments[1]
        out.push(list && ts.isArrayLiteralExpression(list) ? literal(list.elements[0], scope) : '<not a literal>')
      } else if (name === 'sharedToolAccess') {
        const tool = literal(n.arguments[1], scope)
        out.push(Object.hasOwn(SHARED_TOOL_PERMISSIONS, tool) ? SHARED_TOOL_PERMISSIONS[tool as SharedTool] : '<not a literal>')
      }
    }
    if (ts.isIdentifier(n) && scope.locals.has(n.text) && !followed.has(n.text)) {
      followed.add(n.text)
      visit(scope.locals.get(n.text)!)
    }
    ts.forEachChild(n, visit)
  }
  visit(node)
  return out
}

/** Each exported handler of a route file -> the permissions its body asks for, in order. */
function handlerPermissions(source: string): Map<string, string[]> {
  const sf = ts.createSourceFile('route.ts', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS)
  const scope: Scope = { consts: new Map(), locals: new Map() }
  for (const stmt of sf.statements) {
    if (ts.isFunctionDeclaration(stmt) && stmt.name && !HANDLER_METHODS.has(stmt.name.text)) scope.locals.set(stmt.name.text, stmt)
    if (ts.isVariableStatement(stmt)) {
      for (const d of stmt.declarationList.declarations) {
        if (!ts.isIdentifier(d.name) || !d.initializer || HANDLER_METHODS.has(d.name.text)) continue
        if (ts.isStringLiteralLike(d.initializer)) scope.consts.set(d.name.text, d.initializer.text)
        else scope.locals.set(d.name.text, d.initializer)
      }
    }
  }
  const out = new Map<string, string[]>()
  const exported = (n: ts.Node) => ts.getModifiers?.(n as ts.HasModifiers)?.some(m => m.kind === ts.SyntaxKind.ExportKeyword)
  for (const stmt of sf.statements) {
    if (ts.isFunctionDeclaration(stmt) && stmt.name && exported(stmt) && HANDLER_METHODS.has(stmt.name.text)) {
      out.set(stmt.name.text, guardPermissions(stmt, scope))
    }
    if (ts.isVariableStatement(stmt) && exported(stmt)) {
      for (const d of stmt.declarationList.declarations) {
        if (ts.isIdentifier(d.name) && HANDLER_METHODS.has(d.name.text) && d.initializer) out.set(d.name.text, guardPermissions(d.initializer, scope))
      }
    }
  }
  return out
}

/** The manifest's permission for a method: a registry id, null (nothing backs it), or undefined (not set). */
function permissionOf(entry: RouteManifestEntry, method: HttpMethod): string | null | undefined {
  if (entry.permission === undefined || entry.permission === null || typeof entry.permission === 'string') return entry.permission
  return entry.permission[method]
}

const fileOf = (path: string) => join(WEBAPP, 'src', 'app', ...path.split('/').slice(1), 'route.ts')
const handlers = ROUTE_MANIFEST.flatMap(e => e.methods.map(m => ({ entry: e, method: m, key: `${m} ${e.path}` })))
const named = (): string[] => ROUTE_MANIFEST.flatMap(e => {
  if (e.permission === undefined || e.permission === null) return []
  return typeof e.permission === 'string' ? [e.permission] : Object.values(e.permission).filter((p): p is string => typeof p === 'string')
})

describe('route permissions: every route (steps 3.8, 3.9; PE-19, PE-22)', () => {
  test('every handler names its permission in the manifest, or null where no person\'s permission backs it', () => {
    const wrong: string[] = []
    for (const { entry, method, key } of handlers) {
      const p = permissionOf(entry, method)
      if (key in LATER) {
        if (p !== undefined) wrong.push(`${key}: LATER, but the manifest names ${p}`)
      } else if (key in SESSION_ONLY) {
        if (p !== null) wrong.push(`${key}: SESSION_ONLY, so the manifest gives null, not ${p}`)
      } else if (p === undefined) {
        wrong.push(`${key}: no permission in the manifest (give it one, or null with a reason)`)
      } else if (p === null && !NO_PERSON.has(entry.guard)) {
        wrong.push(`${key}: null on a ${entry.guard} route: list it in SESSION_ONLY with the reason, or name its permission`)
      }
    }
    expect(wrong).toEqual([])
    for (const [key, why] of [...Object.entries(SESSION_ONLY), ...Object.entries(LATER), ...Object.entries(ASKED_IN_LIB)]) {
      expect(handlers.some(h => h.key === key), `${key} is not a handler in the manifest`).toBe(true)
      expect(why.length).toBeGreaterThan(20)
    }
  })

  test("each method's manifest permission is the one its handler asks first", () => {
    const wrong: string[] = []
    const cache = new Map<string, Map<string, string[]>>()
    for (const { entry, method, key } of handlers) {
      const p = permissionOf(entry, method)
      if (p === null || p === undefined || key in ASKED_IN_LIB) continue
      if (!cache.has(entry.path)) cache.set(entry.path, handlerPermissions(readFileSync(fileOf(entry.path), 'utf8')))
      const asked = cache.get(entry.path)!.get(method) ?? []
      if (asked[0] !== p) wrong.push(`${key}: manifest ${p}, handler asks ${asked.join(', ') || 'nothing'}`)
    }
    expect(wrong).toEqual([])
  })

  test('the permissions named are registry ids', () => {
    expect(named().filter(p => !isPermissionId(p))).toEqual([])
  })

  test('permissions covered: every permission of a feature that exists is named by a route, asked inside one, carried by an MCP scope, or enforced elsewhere', () => {
    const askedInRoutes = new Set(ROUTE_MANIFEST.flatMap(e => [...handlerPermissions(readFileSync(fileOf(e.path), 'utf8')).values()].flat()))
    const requireAlso = new Set(ROUTE_MANIFEST.flatMap(e => [...readFileSync(fileOf(e.path), 'utf8').matchAll(/requireAlso\(\w+,\s*'([a-z_]+:[a-z_]+)'/g)].map(m => m[1])))
    const used = new Set([...named(), ...askedInRoutes, ...requireAlso])
    const uncovered = PERMISSION_IDS.filter(p => PERMISSIONS[p].gatesExisting && !used.has(p) && PERMISSIONS[p].mcpScopes.length === 0 && !(p in ENFORCED_ELSEWHERE))
    expect(uncovered, 'name it on its route, or say in ENFORCED_ELSEWHERE where it is enforced').toEqual([])
    for (const p of Object.keys(ENFORCED_ELSEWHERE)) {
      expect(isPermissionId(p) && PERMISSIONS[p].gatesExisting, `${p} in ENFORCED_ELSEWHERE`).toBe(true)
      expect(used.has(p), `${p} is named by a route now: drop it from ENFORCED_ELSEWHERE`).toBe(false)
    }
    // A later phase's feature is that phase's to wire (each later manifest test requires its own).
    expect(PERMISSION_IDS.filter(p => !PERMISSIONS[p].gatesExisting && named().includes(p))).toEqual([])
  })

  test('every permission a route names has generated live rows, or NO_ROWS says why; p3_generated.tsv is up to date', () => {
    const missing = [...new Set(named())].filter(p => !Object.hasOwn(REPRESENTATIVES, p) && !(p in NO_ROWS)).sort()
    expect(missing, 'add a representative to gen-rbac-matrix-rows.mjs, or list it in NO_ROWS').toEqual([])
    for (const p of Object.keys(NO_ROWS)) expect(Object.hasOwn(REPRESENTATIVES, p), `${p} has rows now: drop it from NO_ROWS`).toBe(false)
    const out: string[] = []
    expect(runMatrixRows(['--check'], WEBAPP, (line: string) => out.push(line)), out.join('\n')).toBe(0)
  })

  test('the reader of handler permissions finds each handler and only its own calls', () => {
    const src = [
      "const PERMISSION = 'users:assign_permissions'",
      "async function reviewer(s: unknown) { return requireSessionPermission(s, PERMISSION) }",
      "async function tunnel(p: unknown) { return sharedToolAccess(p, 'tunnels') }",
      "export async function GET(r: Request) { await requirePermission(r, 'recon:read', { projectId }) }",
      "export const POST = withRouteErrors('x', async (r: Request) => { const a = await requirePermission(r, 'recon:scan', { projectId }); requireAlso(a, 'recon:overwrite') })",
      "export const PUT = withPermission('preset:write', handler)",
      'export async function DELETE(r: Request) { await requirePermission(r, permission) }',
      "export async function PATCH(r: Request) { return (await reviewer(r)) ?? tunnel(r) }",
      "export async function HEAD(r: Request) { await requireAnyPermission(s, ['roles:manage', 'users:assign_permissions']); return lifecycleGet(r) }",
      "export const OPTIONS = withRouteErrors('x', selfOnly)",
      "async function selfOnly(r: Request) { return requireSelfPermission(r, 'u1', 'self:mcp_servers') }",
      "function helper(r: Request) { return requirePermission(r, 'users:read') }",
    ].join('\n')
    expect(Object.fromEntries(handlerPermissions(src))).toEqual({
      GET: ['recon:read'], POST: ['recon:scan'], PUT: ['preset:write'], DELETE: ['<not a literal>'],
      PATCH: ['users:assign_permissions', 'platform:tunnels'], HEAD: ['roles:manage', 'platform:plugins'], OPTIONS: ['self:mcp_servers'],
    })
  })
})
