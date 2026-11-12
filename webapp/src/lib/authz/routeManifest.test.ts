/** @vitest-environment node */
/**
 * The route manifest lists every API route with the guard it runs (DV-03, T20).
 *
 * The tree is read at test time, so a route another change adds, removes or
 * re-guards fails here with its file named, and `node scripts/gen-route-manifest.mjs`
 * (from webapp/) brings the manifest back in line for review. The generator's
 * own rules are tested on synthetic sources below the tree checks.
 */
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import ts from 'typescript'
import { beforeAll, describe, expect, test } from 'vitest'
import manifestJson from './routeManifest.json'
import { GUARD_CLASSES, ROUTE_MANIFEST, type RouteManifestEntry } from './routeManifest'
import {
  GUARD_PRECEDENCE,
  calledGuards,
  classify,
  exportedMethods,
  mergeManifest,
  parseManifestSource,
  readMiddlewarePaths,
  renderJson,
  renderManifestSource,
  scanRoutes,
} from '../../../scripts/gen-route-manifest.mjs'

const WEBAPP = join(__dirname, '..', '..', '..')
const FIX = 'cd webapp && node scripts/gen-route-manifest.mjs, then review the changes it prints'

type Scanned = { path: string; file: string; methods: string[]; auto: string }
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
  // The shared agent's MCP reload is an admin's; the manifest is your own servers (HD-03, HD-15, step 1.9).
  '/api/mcp/reload': 'admin-jwt',
  '/api/mcp/manifest': 'effective-user',
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
})

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
      ['guardImport', 'project'],
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
