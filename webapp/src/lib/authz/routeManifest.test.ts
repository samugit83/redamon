/** @vitest-environment node */
/**
 * The route manifest lists every API route with the guard it runs (DV-03, T20).
 *
 * The tree is read at test time, so a route another change adds, removes or
 * re-guards fails here with its file named, and `node scripts/gen-route-manifest.mjs`
 * (from webapp/) brings the manifest back in line for review. The generator's
 * own rules are tested on synthetic sources below the tree checks.
 */
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import ts from 'typescript'
import { beforeAll, describe, expect, test, vi } from 'vitest'
import manifestJson from './routeManifest.json'
import { GUARD_CLASSES, ROUTE_MANIFEST, type RouteManifestEntry } from './routeManifest'
import { actsOnProject as canActsOnProject } from './can'
import { PERMISSION_IDS } from './permissions'
import {
  GUARD_PRECEDENCE,
  actsOnProject,
  calledGuards,
  classify,
  exportedMethods,
  mergeManifest,
  parseManifestSource,
  permissionCallProblems,
  permissionGuardCalls,
  readMiddlewarePaths,
  readPermissions,
  renderJson,
  renderManifestSource,
  run,
  scanRoutes,
} from '../../../scripts/gen-route-manifest.mjs'

// can.ts is imported for its pure actsOnProject only: nothing here may reach a database or a session.
vi.mock('@/lib/prisma', () => ({ default: {}, prisma: {} }))
vi.mock('@/lib/session', () => ({ mayActAs: vi.fn() }))

const WEBAPP = join(__dirname, '..', '..', '..')
const FIX = 'cd webapp && node scripts/gen-route-manifest.mjs, then review the changes it prints'

type PermissionCall = { helper: string; permission: string | null; project: boolean; line: number }
type Scanned = { path: string; file: string; methods: string[]; auto: string; permissionCalls: PermissionCall[]; problems: string[] }
let scanned: Scanned[]
let byPath: Map<string, RouteManifestEntry>

beforeAll(() => {
  scanned = scanRoutes(WEBAPP)
  byPath = new Map(ROUTE_MANIFEST.map(e => [e.path, e]))
})

/**
 * The twenty routes the middleware's login check was all that guarded
 * (01_current_state.md §1.2). Each now reads the session first, so a deleted
 * account's still-valid cookie gets 401 (HD-10); a later step that gives one of
 * them a stronger guard moves it out of `session` here in the same commit
 * (STRONGER_THAN_SESSION).
 */
const FORMER_LOGIN_ONLY = [
  '/api/agent/emergency-stop-all',
  '/api/agent/health',
  '/api/agent/host-ip',
  '/api/agent/jobs/[id]/kill',
  '/api/agent/sessions',
  '/api/agent/sessions/[id]/interact',
  '/api/agent/sessions/[id]/kill',
  '/api/agent/tunnel-status',
  '/api/community-skills',
  '/api/cypherfix/health',
  '/api/gvm/available',
  '/api/js-recon/trufflehog/available',
  '/api/nuclei-templates',
  '/api/projects/defaults',
  '/api/skills',
  '/api/system/stats',
  '/api/ws',
]

/** Former login-only routes a later step moved to a stronger guard, with that guard. */
const STRONGER_THAN_SESSION: Record<string, string> = {
  // Unmasked tunnel credentials: the agent's internal-key lookup only (HD-05, step 1.10).
  '/api/global/tunnel-config': 'internal',
  // The shared agent's MCP reload is an admin's (HD-03, HD-15, step 1.9).
  '/api/mcp/reload': 'admin-jwt',
  // Your own servers, for whoever holds self:mcp_servers (requirePermission with no project, step 3.9).
  '/api/mcp/manifest': 'session',
}

describe('the manifest and the route tree', () => {
  test('every route file is in the manifest', () => {
    const unlisted = scanned
      .filter(r => !byPath.has(r.path))
      .map(r => `${r.file} (its calls give the class "${r.auto}")`)
    expect(unlisted, `route files missing from routeManifest.ts: ${FIX}`).toEqual([])
  })

  test('no manifest entry points at a missing file', () => {
    const files = new Set(scanned.map(r => r.path))
    const missing = ROUTE_MANIFEST.filter(e => !files.has(e.path)).map(e => `${e.path} (no src/app${e.path}/route.ts)`)
    expect(missing, `manifest entries without a route file: ${FIX}`).toEqual([])
  })

  test("every entry's methods match the file's exported handlers", () => {
    const wrong = scanned
      .filter(r => byPath.has(r.path))
      .filter(r => byPath.get(r.path)!.methods.join(',') !== r.methods.join(','))
      .map(r => `${r.file}: manifest [${byPath.get(r.path)!.methods.join(', ')}], file exports [${r.methods.join(', ')}]`)
    expect(wrong, `methods out of date: ${FIX}`).toEqual([])
  })

  test('no route is login-only: the 20 former login-only routes read the session or something stronger', () => {
    const listed = ROUTE_MANIFEST.filter(e => e.guard === 'login-only').map(e => e.path)
    expect(listed, 'a route the middleware alone guards must read the session (HD-10)').toEqual([])
    expect(FORMER_LOGIN_ONLY.length + Object.keys(STRONGER_THAN_SESSION).length).toBe(20)
    expect(FORMER_LOGIN_ONLY.filter(p => byPath.get(p)?.guard !== 'session')).toEqual([])
    for (const [p, guard] of Object.entries(STRONGER_THAN_SESSION)) expect(byPath.get(p)?.guard, p).toBe(guard)
  })

  test('the JSON copy equals the manifest', () => {
    expect(manifestJson, `routeManifest.json is stale: ${FIX}`).toEqual(ROUTE_MANIFEST)
  })

  test('every entry without a note has the class its calls give', () => {
    const drifted = scanned
      .filter(r => byPath.has(r.path) && !byPath.get(r.path)!.note)
      .filter(r => byPath.get(r.path)!.guard !== r.auto)
      .map(r => `${r.file}: manifest "${byPath.get(r.path)!.guard}", calls give "${r.auto}"`)
    expect(drifted, `a class its calls do not give needs a note saying why; otherwise ${FIX}`).toEqual([])
  })

  test('each route is listed once, in path order', () => {
    const paths = ROUTE_MANIFEST.map(e => e.path)
    expect(new Set(paths).size).toBe(paths.length)
    expect(paths).toEqual([...paths].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)))
  })

  test('every class is a known guard class, and the generator ranks each of them', () => {
    const unknown = ROUTE_MANIFEST.filter(e => !(GUARD_CLASSES as readonly string[]).includes(e.guard))
    expect(unknown).toEqual([])
    expect([...GUARD_PRECEDENCE].sort()).toEqual([...GUARD_CLASSES].sort())
  })

  test('a comment naming the internal key does not make a route internal', () => {
    // agent/emergency-stop-all's comment names INTERNAL_API_KEY, which a text grep counts as a guard.
    const file = join(WEBAPP, 'src', 'app', 'api', 'agent', 'emergency-stop-all', 'route.ts')
    const source = readFileSync(file, 'utf8')
    expect(source).toContain('INTERNAL_API_KEY')
    expect([...calledGuards(source)]).toEqual(['requireSession'])
    expect(byPath.get('/api/agent/emergency-stop-all')?.guard).toBe('session')
    expect(scanned.find(r => r.path === '/api/agent/emergency-stop-all')?.auto).toBe('session')
  })

  test('the generator would change nothing', () => {
    const { entries, changes } = mergeManifest(ROUTE_MANIFEST, scanned)
    expect(changes, FIX).toEqual([])
    expect(entries).toEqual(ROUTE_MANIFEST)
    const jsonOnDisk = readFileSync(join(__dirname, 'routeManifest.json'), 'utf8')
    expect(jsonOnDisk === renderJson(ROUTE_MANIFEST), `routeManifest.json is not the generator's output: ${FIX}`).toBe(true)
  })

  test('every permission guard call names a registered permission literally, and a project only for a permission that acts on one', () => {
    const problems = scanned.flatMap(r => r.problems.map(p => `${r.file} ${p}`))
    expect(problems, 'the manifest classes a route from these calls: fix each call').toEqual([])
  })

  test('a permission that acts on a project is checked with no project only where CAPABILITY_ONLY says why', () => {
    const found = capabilityOnlyChecks(scanned)
    expect(found.filter(k => !Object.hasOwn(CAPABILITY_ONLY, k)), 'pass the projectId, or list the call in CAPABILITY_ONLY with the reason').toEqual([])
    expect(Object.keys(CAPABILITY_ONLY).filter(k => !found.includes(k)), 'stale CAPABILITY_ONLY entries').toEqual([])
  })
})

/**
 * `<path> <permission>`: a route that checks a permission acting on a project without naming the
 * project, so can() checks the capability alone and no project access or level (can.ts), with why
 * that is right. A missing `projectId` otherwise reads as a forgotten one: the manifest classes the
 * call `session`, and the route checks no project.
 */
const CAPABILITY_ONLY: Record<string, string> = {
  '/api/agent/files agent:chat': 'the in-chat download of a file the agent wrote under /tmp, which names no project (older messages): the chat capability alone; with a projectId the route asks workspace:read on it (step 3.9)',
  '/api/plugins/overrides/change-sets/[id] plugins:approve_overrides': 'the change set\'s scope (an account or a project) is read from the row and checked strictly by changeSetAccess (ownsScope, bodyOwnerMatches): the capability alone here; plugin levels on a shared project are Phase 5\'s (step 3.9)',
  '/api/plugins/overrides/change-sets/[id]/approve plugins:approve_overrides': 'the change set\'s scope (an account or a project) is read from the row and checked strictly by changeSetAccess (ownsScope, bodyOwnerMatches): the capability alone here; plugin levels on a shared project are Phase 5\'s (step 3.9)',
  '/api/plugins/overrides/change-sets/[id]/reject plugins:approve_overrides': 'the change set\'s scope (an account or a project) is read from the row and checked strictly by changeSetAccess (ownsScope, bodyOwnerMatches): the capability alone here; plugin levels on a shared project are Phase 5\'s (step 3.9)',
  '/api/plugins/overrides/reset plugins:approve_overrides': 'the change set\'s scope (an account or a project) is read from the row and checked strictly by changeSetAccess (ownsScope, bodyOwnerMatches): the capability alone here; plugin levels on a shared project are Phase 5\'s (step 3.9)',
  '/api/agent/jobs/[id]/kill agent:sessions': 'the agent\'s session list spans every project (the Kali sandbox runs one msfconsole): the capability alone here; which sessions the caller sees and drives is resolveSessionsViewer\'s rule (own projects, or platform:shell_sessions for all) (step 3.9)',
  '/api/agent/sessions agent:sessions': 'the agent\'s session list spans every project (the Kali sandbox runs one msfconsole): the capability alone here; which sessions the caller sees and drives is resolveSessionsViewer\'s rule (own projects, or platform:shell_sessions for all) (step 3.9)',
  '/api/agent/sessions/[id]/interact agent:sessions': 'the agent\'s session list spans every project (the Kali sandbox runs one msfconsole): the capability alone here; which sessions the caller sees and drives is resolveSessionsViewer\'s rule (own projects, or platform:shell_sessions for all) (step 3.9)',
  '/api/agent/sessions/[id]/kill agent:sessions': 'the agent\'s session list spans every project (the Kali sandbox runs one msfconsole): the capability alone here; which sessions the caller sees and drives is resolveSessionsViewer\'s rule (own projects, or platform:shell_sessions for all) (step 3.9)',
  '/api/nuclei-templates scan:custom_templates': 'a template belongs to an account, not a project: uploading or deleting one is the capability alone; selecting it for a project is the project PUT\'s check (templateSelectionRefusal, under project:settings) (step 3.8)',
  '/api/reports reports:read': 'the list of every report over the projects the account can see (visibleProjectsWhere): no one project to name; opening or deleting one asks on its project (step 3.9)',
}

/** The `<path> <permission>` of each permission guard call that acts on a project and names none. */
function capabilityOnlyChecks(routes: Pick<Scanned, 'path' | 'permissionCalls'>[]): string[] {
  const permissions = readPermissions(WEBAPP)
  const keys = routes.flatMap(r => r.permissionCalls
    .filter(c => !c.project && c.permission !== null && Object.hasOwn(permissions, c.permission) && actsOnProject(permissions[c.permission]))
    .map(c => `${r.path} ${c.permission}`))
  return [...new Set(keys)]
}

/**
 * Every route that changes identity, permissions or instance settings accepts only same-origin
 * JSON (ID-26, T14, step 2.12): its manifest entry says `sameOrigin: true`, and each of its
 * write handlers calls `sameOrigin`, then `readJsonBody` when it takes a body. A DELETE takes
 * none (a member's deletion, stopping act-as, revoking a token): a browser form cannot send one.
 */
const SAME_ORIGIN_ROUTES = [
  '/api/admin/admin-profiles',
  '/api/admin/admin-profiles/[id]',
  '/api/admin/instance-settings',
  '/api/admin/legacy-grants',
  '/api/admin/permission-sets',
  '/api/admin/permission-sets/[id]',
  '/api/auth/act-as',
  '/api/auth/sessions/revoke-all',
  '/api/invite/accept',
  '/api/root/transfer',
  '/api/root/transfer/accept',
  '/api/root/transfer/cancel',
  '/api/users',
  '/api/users/[id]',
  '/api/users/[id]/disable',
  '/api/users/[id]/enable',
  '/api/users/[id]/invite/cancel',
  '/api/users/[id]/invite/resend',
  '/api/users/[id]/mcp-tokens',
  '/api/users/[id]/mcp-tokens/[tokenId]',
  '/api/users/[id]/password',
  '/api/users/[id]/permissions',
  '/api/users/[id]/reset-credentials',
  '/api/users/[id]/revoke-sessions',
  '/api/users/[id]/settings',
  '/api/users/invite',
]

/** The families a new route joins the list from: accounts, credentials, sessions, Root, instance and access policy. */
const SAME_ORIGIN_FAMILIES = [
  /^\/api\/users(\/invite)?$/,
  /^\/api\/users\/\[id\](\/(password|permissions|disable|enable|revoke-sessions|reset-credentials|settings|invite\/[^/]+|mcp-tokens(\/\[tokenId\])?))?$/,
  /^\/api\/auth\/(act-as|sessions\/.+)$/,
  /^\/api\/root\//,
  /^\/api\/admin\/(instance-settings|legacy-grants|permission-sets(\/\[id\])?|admin-profiles(\/\[id\])?)$/,
  /^\/api\/invite\//,
  /^\/api\/account\//,
]

const WRITE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])

/**
 * The functions each exported write handler calls, its own body and the same-file functions it
 * reaches (a local `guard(request)` counts), by name.
 */
function handlerCalls(source: string): Map<string, Set<string>> {
  const sf = ts.createSourceFile('route.ts', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS)
  const local = new Map<string, ts.Node>()
  const exported = new Map<string, ts.Node>()
  const isExported = (n: ts.Node) => ts.getModifiers(n as ts.HasModifiers)?.some(m => m.kind === ts.SyntaxKind.ExportKeyword)
  for (const stmt of sf.statements) {
    if (ts.isFunctionDeclaration(stmt) && stmt.name) {
      local.set(stmt.name.text, stmt)
      if (isExported(stmt)) exported.set(stmt.name.text, stmt)
    }
    if (ts.isVariableStatement(stmt)) {
      for (const d of stmt.declarationList.declarations) {
        if (!ts.isIdentifier(d.name) || !d.initializer) continue
        local.set(d.name.text, d.initializer)
        if (isExported(stmt)) exported.set(d.name.text, d.initializer)
      }
    }
  }
  const calledIn = (root: ts.Node) => {
    const names = new Set<string>()
    const seen = new Set<ts.Node>()
    const walk = (node: ts.Node) => {
      if (ts.isCallExpression(node)) {
        const callee = node.expression
        const name = ts.isIdentifier(callee) ? callee.text : ts.isPropertyAccessExpression(callee) ? callee.name.text : null
        if (name) {
          names.add(name)
          const fn = local.get(name)
          if (fn && !seen.has(fn)) {
            seen.add(fn)
            walk(fn)
          }
        }
      }
      ts.forEachChild(node, walk)
    }
    walk(root)
    return names
  }
  const out = new Map<string, Set<string>>()
  for (const [name, node] of exported) if (WRITE_METHODS.has(name)) out.set(name, calledIn(node))
  return out
}

describe('same-origin JSON on identity, permission and instance routes (ID-26, step 2.12)', () => {
  test('rbac routes same-origin: every listed route is flagged, and every write route of their families is listed', () => {
    const unflagged = SAME_ORIGIN_ROUTES.filter(p => byPath.get(p)?.sameOrigin !== true)
    expect(unflagged, 'add sameOrigin: true to these manifest entries').toEqual([])
    const unlisted = ROUTE_MANIFEST
      .filter(e => SAME_ORIGIN_FAMILIES.some(re => re.test(e.path)))
      .filter(e => e.methods.some(m => WRITE_METHODS.has(m)))
      .map(e => e.path)
      .filter(p => !SAME_ORIGIN_ROUTES.includes(p))
    expect(unlisted, 'a route that changes identity, permissions or instance settings checks the origin (T14)').toEqual([])
  })

  test('flagged routes call sameOrigin: each write handler, and readJsonBody when it takes a body', () => {
    const flagged = ROUTE_MANIFEST.filter(e => e.sameOrigin === true)
    expect(flagged.map(e => e.path).sort()).toEqual([...SAME_ORIGIN_ROUTES].sort())
    const missing: string[] = []
    for (const entry of flagged) {
      const route = scanned.find(r => r.path === entry.path)!
      const calls = handlerCalls(readFileSync(join(WEBAPP, route.file), 'utf8'))
      expect(calls.size, `${route.file} exports no write handler`).toBeGreaterThan(0)
      for (const [method, names] of calls) {
        if (!names.has('sameOrigin')) missing.push(`${route.file} ${method}: no sameOrigin(request)`)
        if (method !== 'DELETE' && !names.has('readJsonBody')) missing.push(`${route.file} ${method}: no readJsonBody(request)`)
      }
    }
    expect(missing).toEqual([])
  })

  test('the check reaches a call in a local helper, not one in a comment', () => {
    const src = [
      '// sameOrigin(request) is checked by the proxy',
      'async function guard(r: Request) { return sameOrigin(r) }',
      'export const POST = withRouteErrors("x", async (r: Request) => { await guard(r); return readJsonBody(r) })',
      'export async function DELETE() { return ok() }',
    ].join('\n')
    const calls = handlerCalls(src)
    expect(calls.get('POST')?.has('sameOrigin')).toBe(true)
    expect(calls.get('POST')?.has('readJsonBody')).toBe(true)
    expect(calls.get('DELETE')?.has('sameOrigin')).toBe(false)
  })
})

describe('the generator', () => {
  const middleware = { publicPaths: ['/api/auth/login', '/api/health'], tokenPrefixes: ['/api/plugin-gateway/v1/'] }

  test('sameOrigin is written after the methods and the permission, before the note', () => {
    const entry = { note: 'why', sameOrigin: true, methods: ['POST'], guard: 'admin-jwt', path: '/api/a', permission: 'users:create' }
    const written = renderManifestSource('export const ROUTE_MANIFEST = []', [entry])
    expect(written).toContain("{ path: '/api/a', guard: 'admin-jwt', methods: ['POST'], permission: 'users:create', sameOrigin: true, note: 'why' }")
    expect(renderJson([entry])).toContain('{"path":"/api/a","guard":"admin-jwt","methods":["POST"],"permission":"users:create","sameOrigin":true,"note":"why"}')
  })

  test('reads the public paths and token prefixes from the middleware', () => {
    const paths = readMiddlewarePaths(WEBAPP)
    expect(paths.publicPaths).toContain('/api/auth/login')
    expect(paths.publicPaths).toContain('/api/mcp-server')
    expect(paths.tokenPrefixes).toEqual(expect.arrayContaining(['/api/plugin-gateway/v1/', '/api/plugin-runner/v1/']))
  })

  test('a helper named in a comment or a string is not a call', () => {
    const src = [
      '// isInternalRequest(request) is checked by the agent, not here',
      '/* guardProject(projectId) */',
      "const hint = 'requireAdmin()'",
      'export async function GET() { return ok(hint) }',
    ].join('\n')
    expect([...calledGuards(src)]).toEqual([])
    expect(classify('/api/x', calledGuards(src), middleware)).toBe('login-only')
  })

  test('a helper called as a method or inside a local helper still counts', () => {
    const src = [
      'async function authorize(id: string) { return access.guardProject(id) }',
      'export const POST = withRouteErrors("x", async () => authorize("p"))',
    ].join('\n')
    expect([...calledGuards(src)]).toEqual(['guardProject'])
  })

  test('the user-facing guard wins over the internal key', () => {
    const calls = new Set(['isInternalRequest', 'requireEffectiveUser', 'guardProject'])
    expect(classify('/api/remediations', calls, middleware)).toBe('project')
    expect(classify('/api/c', new Set(['isInternalRequest', 'requireConversationAccessBySession']), middleware)).toBe('conversation')
    expect(classify('/api/i', new Set(['isInternalRequest']), middleware)).toBe('internal')
    expect(classify('/api/t', new Set(['isInternalRequest', 'isScannerRequest']), middleware)).toBe('scanner')
    expect(classify('/api/s', new Set(['getSession', 'isInternalRequest']), middleware)).toBe('session')
  })

  test('each helper family gives its class', () => {
    const cases: [string, string][] = [
      ['requireProjectScopedResource', 'project'],
      ['requireProjectOwner', 'project'],
      ['requireUserAccess', 'user'],
      ['requireOwnBrowserRequest', 'user'],
      ['lifecyclePost', 'admin-db'],
      ['requirePluginAdmin', 'admin-db'],
      ['requireAdmin', 'admin-jwt'],
      ['strictContext', 'other'],
      ['handleAction', 'other'],
      ['ownerScope', 'effective-user'],
      ['getEffectiveUser', 'effective-user'],
      ['requireSession', 'session'],
      ['requirePermission', 'session'],
      ['withPermission', 'session'],
      ['requirePermission({projectId})', 'project'],
      ['withPermission({projectId})', 'project'],
    ]
    for (const [helper, guard] of cases) expect([helper, classify('/api/x', new Set([helper]), middleware)]).toEqual([helper, guard])
  })

  test('a permission guard is a project guard only when it names the project (step 3.5)', () => {
    const calls = (body: string) => [...calledGuards(body)]
    expect(calls("export async function POST(r: Request) { return requirePermission(r, 'recon:scan', { projectId }) }"))
      .toEqual(['requirePermission({projectId})'])
    expect(calls("export async function POST(r: Request) { return requirePermission(r, 'recon:scan', { projectId: p.id, fresh: true }) }"))
      .toEqual(['requirePermission({projectId})'])
    expect(calls("export const GET = withPermission('recon:read', handler, { projectId: async (_r, c) => (await c.params).id })"))
      .toEqual(['withPermission({projectId})'])
    expect(calls("export const GET = authz.withPermission('recon:read', handler, { 'projectId': fromParams })"))
      .toEqual(['withPermission({projectId})'])
    // Capability only: no project option, another option, a spread or a variable the scan cannot read.
    expect(calls("export async function GET(r: Request) { return requirePermission(r, 'users:read') }")).toEqual(['requirePermission'])
    expect(calls("export async function GET(r: Request) { return requirePermission(r, 'users:read', { fresh: true }) }")).toEqual(['requirePermission'])
    expect(calls("export async function GET(r: Request) { return requirePermission(r, 'recon:read', { ...opts }) }")).toEqual(['requirePermission'])
    expect(calls("export async function GET(r: Request) { return requirePermission(r, 'recon:read', opts) }")).toEqual(['requirePermission'])
    expect(calls("export const GET = withPermission('users:read', handler)")).toEqual(['withPermission'])
    // The project option is read on the guard's own options argument, not on another argument.
    expect(calls("export async function GET(r: Request) { return requirePermission({ projectId }, 'x') }")).toEqual(['requirePermission'])
    expect(classify('/api/x', calledGuards("export async function GET(r: Request) { return requirePermission(r, 'recon:read', { projectId }) }"), middleware))
      .toBe('project')
    expect(classify('/api/x', new Set(['requirePermission', 'isInternalRequest']), middleware)).toBe('session')
  })

  test('a permission guard is a project guard only when its permission acts on a project', () => {
    const calls = (body: string) => [...calledGuards(body)]
    const klass = (body: string) => classify('/api/x', calledGuards(body), middleware)
    // can() ignores the id for a permission that acts on no project: such a call checks no project.
    for (const p of ['plugins:use', 'self:api_keys', 'project:create', 'preset:write', 'users:read', 'platform:plugins']) {
      expect([p, calls(`export async function POST(r: Request) { return requirePermission(r, '${p}', { projectId }) }`)]).toEqual([p, ['requirePermission']])
      expect([p, klass(`export async function POST(r: Request) { return requirePermission(r, '${p}', { projectId }) }`)]).toEqual([p, 'session'])
      expect([p, calls(`export const GET = withPermission('${p}', handler, { projectId: fromParams })`)]).toEqual([p, ['withPermission']])
    }
    // An instance permission that needs a level checks the project it is given (project:share, plugins:approve_overrides).
    expect(calls("export async function POST(r: Request) { return requirePermission(r, 'project:share', { projectId }) }"))
      .toEqual(['requirePermission({projectId})'])
    expect(klass("export const POST = withPermission('plugins:approve_overrides', handler, { projectId: fromBody })")).toBe('project')
    expect(calls("export const GET = withPermission(('recon:read' as const), handler, { projectId: fromParams })")).toEqual(['withPermission({projectId})'])
    // A permission the scan cannot read, or one the registry does not hold, is never a project guard.
    expect(calls('export async function POST(r: Request) { return requirePermission(r, permission, { projectId }) }')).toEqual(['requirePermission'])
    expect(calls('export async function POST(r: Request) { return requirePermission(r, `recon:${verb}`, { projectId }) }')).toEqual(['requirePermission'])
    expect(calls("export async function POST(r: Request) { return requirePermission(r, cond ? 'recon:read' : 'recon:scan', { projectId }) }")).toEqual(['requirePermission'])
    expect(calls("export async function POST(r: Request) { return requirePermission(r, 'recon:nope', { projectId }) }")).toEqual(['requirePermission'])
    expect(calls('export const GET = withPermission(PERMISSION, handler, { projectId: fromParams })')).toEqual(['withPermission'])
  })

  test('each permission guard call is read with its permission, its project option and its line', () => {
    const src = [
      'export async function GET(r: Request) {',
      "  await requirePermission(r, 'recon:read', { projectId, fresh: true })",
      "  return authz.requirePermission(r, 'users:read')",
      '}',
      "export const POST = withPermission('recon:scan', handler, { projectId: fromParams })",
      'export const PUT = withPermission(permission, handler)',
      "// requirePermission(r, 'plugins:use', { projectId })",
    ].join('\n')
    expect(permissionGuardCalls(src)).toEqual([
      { helper: 'requirePermission', permission: 'recon:read', project: true, line: 2 },
      { helper: 'requirePermission', permission: 'users:read', project: false, line: 3 },
      { helper: 'withPermission', permission: 'recon:scan', project: true, line: 5 },
      { helper: 'withPermission', permission: null, project: false, line: 6 },
    ])
  })

  test('the generator reads the registry can() decides with, and the same project rule', () => {
    const permissions = readPermissions(WEBAPP)
    expect(Object.keys(permissions).sort()).toEqual([...PERMISSION_IDS].sort())
    const differ = PERMISSION_IDS.filter(p => actsOnProject(permissions[p]) !== canActsOnProject(p))
    expect(differ, 'gen-route-manifest.mjs actsOnProject must answer as can.ts actsOnProject').toEqual([])
    expect(PERMISSION_IDS.filter(p => !canActsOnProject(p)).length).toBeGreaterThan(0)
    expect(PERMISSION_IDS.filter(p => canActsOnProject(p)).length).toBeGreaterThan(0)
  })

  test('a permission guard call the manifest cannot class is a problem, named with its line', () => {
    const problems = (body: string) => permissionCallProblems(permissionGuardCalls(body))
    expect(problems("export async function POST(r: Request) {\n  return requirePermission(r, 'plugins:use', { projectId })\n}"))
      .toEqual([expect.stringMatching(/^line 2: requirePermission\('plugins:use', \{projectId\}\): .*no project/)])
    expect(problems("export const GET = withPermission('self:llm_providers', handler, { projectId: fromParams })"))
      .toEqual([expect.stringMatching(/^line 1: withPermission\('self:llm_providers', \{projectId\}\)/)])
    expect(problems('export async function POST(r: Request) { return requirePermission(r, permission, { projectId }) }'))
      .toEqual([expect.stringMatching(/^line 1: requirePermission\(\) .*string literal/)])
    expect(problems('export async function GET(r: Request) { return requirePermission(r, permission) }'))
      .toEqual([expect.stringMatching(/^line 1: requirePermission\(\) .*string literal/)])
    expect(problems("export async function GET(r: Request) { return requirePermission(r, 'recon:nope') }"))
      .toEqual([expect.stringMatching(/^line 1: requirePermission\('recon:nope'\): .*registry/)])
    // Calls the manifest classes as can() decides them: no problem (a project permission with no
    // project is the tree test's CAPABILITY_ONLY rule, not the generator's).
    expect(problems([
      "export async function GET(r: Request) { return requirePermission(r, 'recon:read', { projectId }) }",
      "export async function PUT(r: Request) { return requirePermission(r, 'roles:manage', { fresh: true }) }",
      "export async function POST(r: Request) { return requirePermission(r, 'recon:scan') }",
      "export const DELETE = withPermission('project:share', handler, { projectId: fromParams })",
    ].join('\n'))).toEqual([])
  })

  test('a problem fails the run, with or without --check, and nothing is written', () => {
    const dir = mkdtempSync(join(tmpdir(), 'route-manifest-'))
    const put = (file: string, text: string) => {
      mkdirSync(dirname(join(dir, file)), { recursive: true })
      writeFileSync(join(dir, file), text)
    }
    try {
      put('src/middleware.ts', "const PUBLIC_PATHS = ['/api/health']\nconst TOKEN_AUTH_PREFIXES = ['/api/plugin-gateway/v1/']\n")
      put('src/lib/authz/permissionCatalog.json', readFileSync(join(__dirname, 'permissionCatalog.json'), 'utf8'))
      const manifestTs = [
        'export const ROUTE_MANIFEST = [',
        "  { path: '/api/x', guard: 'session', methods: ['POST'] },",
        "  { path: '/api/y', guard: 'project', methods: ['GET'] },",
        ']',
        '',
      ].join('\n')
      put('src/lib/authz/routeManifest.ts', manifestTs)
      put('src/lib/authz/routeManifest.json', renderJson(parseManifestSource(manifestTs)))
      put('src/app/api/x/route.ts', "export async function POST(r: Request) { return requirePermission(r, 'plugins:use', { projectId: 'p' }) }\n")
      put('src/app/api/y/route.ts', "export async function GET(r: Request) { return requirePermission(r, 'recon:read', { projectId: 'p' }) }\n")
      const read = () => readFileSync(join(dir, 'src/lib/authz/routeManifest.ts'), 'utf8')
      // Listed and up to date but for the call: --check fails on the problem alone.
      const lines: string[] = []
      expect(run(['--check'], dir, (l: string) => lines.push(l))).toBe(1)
      expect(lines.join('\n')).toMatch(/problem\s+src\/app\/api\/x\/route\.ts line 1: requirePermission\('plugins:use', \{projectId\}\)/)
      // A new route the write would add: the write refuses while the problem stands.
      put('src/app/api/z/route.ts', "export async function GET(r: Request) { return requirePermission(r, 'users:read') }\n")
      expect(run([], dir, () => {})).toBe(1)
      expect(read()).toBe(manifestTs)
      put('src/app/api/x/route.ts', "export async function POST(r: Request) { return requirePermission(r, 'plugins:use') }\n")
      expect(run([], dir, () => {})).toBe(0)
      expect(parseManifestSource(read())).toEqual([
        { path: '/api/x', guard: 'session', methods: ['POST'] },
        { path: '/api/y', guard: 'project', methods: ['GET'] },
        { path: '/api/z', guard: 'session', methods: ['GET'] },
      ])
      expect(run(['--check'], dir, () => {})).toBe(0)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  test('the CAPABILITY_ONLY rule finds each permission that acts on a project and is checked with none', () => {
    const call = (permission: string | null, project: boolean) => ({ helper: 'requirePermission', permission, project, line: 1 })
    const routes = [
      { path: '/api/a', permissionCalls: [call('recon:read', false), call('recon:read', false), call('recon:scan', true), call('users:read', false)] },
      { path: '/api/b', permissionCalls: [call('plugins:approve_overrides', false), call('plugins:use', false), call(null, false)] },
    ]
    expect(capabilityOnlyChecks(routes)).toEqual(['/api/a recon:read', '/api/b plugins:approve_overrides'])
  })

  test('public and plugin-token come from the path, whatever the handler calls', () => {
    expect(classify('/api/auth/login', new Set(['getSession']), middleware)).toBe('public')
    expect(classify('/api/health/deep', new Set(), middleware)).toBe('public')
    expect(classify('/api/healthz', new Set(), middleware)).toBe('login-only')
    expect(classify('/api/plugin-gateway/v1/data/get', new Set(), middleware)).toBe('plugin-token')
    expect(classify('/api/plugin-gateway/v10/data/get', new Set(), middleware)).toBe('login-only')
  })

  test('methods come from every export form, in a fixed order', () => {
    const src = [
      'export const runtime = "nodejs"',
      'export const POST = withRouteErrors("x", async () => ok())',
      'export async function GET() {}',
      'export function DELETE() {}',
      'const handler = () => ok()',
      'export { handler as PATCH }',
      'export function GETTER() {}',
    ].join('\n')
    expect(exportedMethods(src)).toEqual(['GET', 'POST', 'PATCH', 'DELETE'])
  })

  test('merging keeps a noted class, follows the calls otherwise, refreshes methods, adds and drops files', () => {
    const existing = [
      { path: '/api/a', guard: 'admin-jwt', methods: ['GET'], note: 'inline role check' },
      { path: '/api/b', guard: 'login-only', methods: ['GET'] },
      { path: '/api/gone', guard: 'project', methods: ['GET'] },
      { path: '/api/p', guard: 'project', methods: ['GET'], permission: { GET: 'recon:read' } },
    ]
    const routes = [
      { path: '/api/a', file: 'a', methods: ['GET', 'POST'], auto: 'session' },
      { path: '/api/b', file: 'b', methods: ['GET'], auto: 'session' },
      { path: '/api/new', file: 'n', methods: ['POST'], auto: 'project' },
      { path: '/api/p', file: 'p', methods: ['GET'], auto: 'project' },
    ]
    const { entries, changes } = mergeManifest(existing, routes)
    expect(entries).toEqual([
      { path: '/api/a', guard: 'admin-jwt', methods: ['GET', 'POST'], note: 'inline role check' },
      { path: '/api/b', guard: 'session', methods: ['GET'] },
      { path: '/api/new', guard: 'project', methods: ['POST'] },
      { path: '/api/p', guard: 'project', methods: ['GET'], permission: { GET: 'recon:read' } },
    ])
    expect(changes).toEqual([
      'methods  /api/a: [GET] -> [GET, POST] (review its class)',
      'class    /api/b: login-only -> session (its calls changed)',
      'removed  /api/gone (its route file is gone)',
      'added    /api/new as project (n)',
    ])
  })

  test('the TypeScript manifest round-trips through the generator', () => {
    const entries = [
      { path: '/api/a', guard: 'user', methods: ['GET'], note: "the owner's 'own' check" },
      { path: '/api/b', guard: 'project', methods: ['GET', 'POST'], permission: { GET: 'recon:read', POST: 'recon:scan' } },
      { path: '/api/c', guard: 'internal', methods: ['POST'], permission: null, sameOrigin: true },
    ]
    const shell = [
      'export type X = 1',
      'export const ROUTE_MANIFEST: readonly RouteManifestEntry[] = []',
      'export const AFTER = 2',
    ].join('\n')
    const written = renderManifestSource(shell, entries)
    expect(parseManifestSource(written)).toEqual(entries)
    expect(written.startsWith('export type X = 1\n')).toBe(true)
    expect(written.endsWith('\nexport const AFTER = 2')).toBe(true)
    expect(renderManifestSource(written, entries)).toBe(written)
  })

  test('a computed value in the manifest is refused with its line', () => {
    const src = 'export const ROUTE_MANIFEST = [\n  { path: `/api/${x}`, guard: "public", methods: [] },\n]'
    expect(() => parseManifestSource(src)).toThrow(/line 2/)
  })
})
