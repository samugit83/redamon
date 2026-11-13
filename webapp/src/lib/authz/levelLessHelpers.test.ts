/**
 * Once shares enter projectAccess() (step 4.3), the owner helpers that ask it without a level admit
 * a read share, oversight and break-glass as readily as the owner: `guardProject`,
 * `requireProjectAccess`, `requireProjectScopedResource` (access.ts), `requireProjectOwner`
 * (triageClient.ts) and the conversation helpers (`requireConversationAccess[BySession]`, which add
 * the author but no level). So only a route permission's level stops a read collaborator's write
 * (fix of the 3.6 review, 2026-11-12).
 *
 * This test reads every route's syntax tree (TypeScript, as scripts/gen-route-manifest.mjs does)
 * and fails when a write handler (POST, PUT, PATCH, DELETE) reaches one of those helpers, directly
 * or through functions of its own module, without a `requirePermission` / `withPermission` naming a
 * permission at a write level (W and above) on the same path: the check must stand outside every
 * branch (if, ternary, `&&`/`||`/`??`, switch case, loop, catch) that does not also hold the call.
 * A read handler (GET, HEAD) that reaches one needs a permission with a project level. Production
 * code outside access.ts never calls these helpers, so no route reaches one through a library: the
 * helper modules beside the routes (any non-route module under src/app/api) count as library code.
 *
 * The level stops a read collaborator's write only when the write handler's permission asks one: a
 * write handler whose permission needs only R or R* lets every read share through, so the routes
 * that have one are listed by name with the reason they write nothing (review of 4.3).
 *
 * From step 5.2a a write share passes a W-level check (and the toggled levels its row opens): that is
 * the point of write sharing, and which actions need M or O is each permission's level in the
 * registry. What this test asks still holds unchanged: a read share, oversight and break-glass never
 * reach a write level (projectAccess.test.ts, the level table), so the checks it requires stop them.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/authz/levelLessHelpers.test.ts
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import path from 'node:path'
import ts from 'typescript'
import { PERMISSIONS, isPermissionId } from './permissions'
import { ROUTE_MANIFEST, type HttpMethod, type RouteManifestEntry } from './routeManifest'

const WEBAPP = path.resolve(__dirname, '../../..')
const API = path.join(WEBAPP, 'src', 'app', 'api')

const LEVEL_LESS = new Set([
  'guardProject', 'requireProjectAccess', 'requireProjectScopedResource', 'requireProjectOwner',
  'requireConversationAccess', 'requireConversationAccessBySession',
])
const WRITE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])
const READ_METHODS = new Set(['GET', 'HEAD'])
const WRITE_LEVELS = new Set(['W', 'W+S', 'W+A', 'W+X', 'M', 'O'])
/** The permission argument of each guard. */
const GUARD_PERMISSION_ARG: Record<string, number> = { requirePermission: 1, withPermission: 0 }

function callName(call: ts.CallExpression): string | null {
  const callee = call.expression
  return ts.isIdentifier(callee) ? callee.text : ts.isPropertyAccessExpression(callee) ? callee.name.text : null
}

function literal(node: ts.Node | undefined): string | null {
  while (node && (ts.isAsExpression(node) || ts.isParenthesizedExpression(node) || ts.isSatisfiesExpression(node))) node = node.expression
  return node && (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) ? node.text : null
}

function descendants(node: ts.Node): ts.Node[] {
  const out: ts.Node[] = []
  const walk = (n: ts.Node): void => {
    out.push(n)
    ts.forEachChild(n, walk)
  }
  ts.forEachChild(node, walk)
  return out
}

/** The branch bodies between `node` and `root`: the parts of the code that may not run. */
function branchesAbove(node: ts.Node, root: ts.Node): ts.Node[] {
  const out: ts.Node[] = []
  let child = node
  for (let parent = node.parent; parent && child !== root; child = parent, parent = parent.parent) {
    if (ts.isIfStatement(parent) && (child === parent.thenStatement || child === parent.elseStatement)) out.push(child)
    else if (ts.isConditionalExpression(parent) && (child === parent.whenTrue || child === parent.whenFalse)) out.push(child)
    else if (ts.isBinaryExpression(parent) && child === parent.right && [
      ts.SyntaxKind.AmpersandAmpersandToken, ts.SyntaxKind.BarBarToken, ts.SyntaxKind.QuestionQuestionToken,
    ].includes(parent.operatorToken.kind)) out.push(child)
    else if (ts.isCaseClause(parent) || ts.isDefaultClause(parent) || ts.isCatchClause(parent)) out.push(parent)
    else if (ts.isIterationStatement(parent, false) && child === parent.statement) out.push(child)
    if (parent === root) break
  }
  return out
}

const contains = (outer: ts.Node, inner: ts.Node): boolean => inner.pos >= outer.pos && inner.end <= outer.end

/** Top-level functions of the module, by name: declarations and `const name = <expression>`. */
function moduleFunctions(sf: ts.SourceFile): Map<string, ts.Node> {
  const out = new Map<string, ts.Node>()
  for (const stmt of sf.statements) {
    if (ts.isFunctionDeclaration(stmt) && stmt.name) out.set(stmt.name.text, stmt)
    if (ts.isVariableStatement(stmt)) {
      for (const d of stmt.declarationList.declarations) if (ts.isIdentifier(d.name) && d.initializer) out.set(d.name.text, d.initializer)
    }
  }
  return out
}

function exportedHandlers(sf: ts.SourceFile): Map<string, ts.Node> {
  const out = new Map<string, ts.Node>()
  const exported = (n: ts.Node) => ts.getModifiers?.(n as ts.HasModifiers)?.some(m => m.kind === ts.SyntaxKind.ExportKeyword)
  for (const stmt of sf.statements) {
    if (ts.isFunctionDeclaration(stmt) && stmt.name && exported(stmt)) out.set(stmt.name.text, stmt)
    if (ts.isVariableStatement(stmt) && exported(stmt)) {
      for (const d of stmt.declarationList.declarations) if (ts.isIdentifier(d.name) && d.initializer) out.set(d.name.text, d.initializer)
    }
  }
  return new Map([...out].filter(([name]) => WRITE_METHODS.has(name) || READ_METHODS.has(name)))
}

export interface Reach {
  method: string
  helper: string
  /** The handler, then each module function on the way to the helper's call. */
  via: string[]
  covered: boolean
}

/**
 * Every place a handler of `source` reaches a level-less helper, and whether a permission check of
 * the level its method needs stands over that path.
 */
export function analyse(source: string, file = 'route.ts'): Reach[] {
  const sf = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS)
  const functions = moduleFunctions(sf)
  const out: Reach[] = []
  for (const [method, handler] of exportedHandlers(sf)) {
    const strong = (permission: string): boolean => {
      if (!isPermissionId(permission)) return false
      const level = PERMISSIONS[permission].level
      return WRITE_METHODS.has(method) ? level !== null && WRITE_LEVELS.has(level) : level !== null
    }
    const visit = (unit: ts.Node, guarded: boolean, via: string[]): void => {
      const nodes = descendants(unit)
      const checks = nodes.filter((n): n is ts.CallExpression => ts.isCallExpression(n)).filter((c) => {
        const name = callName(c)
        return name !== null && name in GUARD_PERMISSION_ARG && strong(literal(c.arguments[GUARD_PERMISSION_ARG[name]]) ?? '')
      })
      const covers = (site: ts.Node): boolean =>
        guarded || checks.some((check) => branchesAbove(check, unit).every((branch) => contains(branch, site)))
      for (const n of nodes) {
        // A call by its callee's name; any other use of a name (an argument, a value) by the name.
        const callee = ts.isIdentifier(n) && ts.isCallExpression(n.parent) && n.parent.expression === n
        const name = ts.isCallExpression(n) ? callName(n) : ts.isIdentifier(n) && !callee ? n.text : null
        if (name === null) continue
        if (ts.isCallExpression(n) && LEVEL_LESS.has(name)) out.push({ method, helper: name, via, covered: covers(n) })
        // A module function called or handed on (`withPermission('p', handler)`) runs on this path.
        else if (functions.has(name) && !via.includes(name) && (ts.isCallExpression(n) || ts.isIdentifier(n))) {
          visit(functions.get(name)!, covers(n), [...via, name])
        }
      }
    }
    visit(handler, false, [method])
  }
  return out
}

function files(dir: string, keep: (file: string) => boolean): string[] {
  const out: string[] = []
  for (const name of readdirSync(dir)) {
    const full = path.join(dir, name)
    if (statSync(full).isDirectory()) {
      if (!['node_modules', '__testing__', '__fixtures__'].includes(name)) out.push(...files(full, keep))
    } else if (keep(full)) out.push(full)
  }
  return out
}

/** Paths relative to webapp/, `/`-separated. */
const relative = (file: string): string => path.relative(WEBAPP, file).split(path.sep).join('/')

/** The files `analyse` reads, from their handlers. */
export const isRouteFile = (file: string): boolean => /^src\/app\/api\/(?:.+\/)?route\.ts$/.test(file)

/** What the library check reads: every module but tests and route files, those under src/app/api too. */
export const isLibraryModule = (file: string): boolean =>
  /\.(ts|tsx)$/.test(file) && !/\.test\.(ts|tsx)$/.test(file) && !isRouteFile(file)

/** The library modules among `modules` that call a level-less helper. */
export function libraryCallers(modules: ReadonlyArray<{ file: string; source: string }>): string[] {
  return modules.filter(({ file, source }) => {
    if (!isLibraryModule(file)) return false
    const sf = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, file.endsWith('x') ? ts.ScriptKind.TSX : ts.ScriptKind.TS)
    return descendants(sf).some((n) => ts.isCallExpression(n) && LEVEL_LESS.has(callName(n) ?? ''))
  }).map(({ file }) => file)
}

const READ_LEVELS = new Set(['R', 'R*'])

/** `METHOD path` of every write handler whose manifest permission needs only R or R*. */
export function readLevelWrites(manifest: readonly RouteManifestEntry[]): string[] {
  const out: string[] = []
  for (const entry of manifest) {
    for (const method of entry.methods.filter((m) => WRITE_METHODS.has(m))) {
      const p = entry.permission
      const permission = p && typeof p === 'object' ? p[method as HttpMethod] : p
      if (typeof permission !== 'string' || !isPermissionId(permission)) continue
      const level = PERMISSIONS[permission].level
      if (level !== null && READ_LEVELS.has(level)) out.push(`${method} ${entry.path}`)
    }
  }
  return out.sort()
}

/**
 * The write handlers a read collaborator passes, each with why it changes nothing. A new one fails
 * until it asks a write-level permission or is listed here with its reason; a stale one fails too.
 */
const READ_LEVEL_WRITES: Readonly<Record<string, string>> = {
  'POST /api/agent/workspace/bulk-archive': 'streams an archive of the files named, as the archive-download GET does at the same permission (workspace:read, R*); writes nothing',
  'POST /api/analytics/unseen': 'a POST only to carry the per-tab watermarks: label counts and the Red Zone GETs called in-process (graph:read); writes nothing',
  'POST /api/graph-views/execute': 'read-only Neo4j session (fix of review finding 1)',
}

const SOURCES = files(path.join(WEBAPP, 'src'), (f) => /\.(ts|tsx)$/.test(f)).map(relative)
const routes = SOURCES.filter(isRouteFile)

describe('the analysis (fixtures)', () => {
  const uncovered = (src: string) => analyse(src).filter((r) => !r.covered).map((r) => `${r.method} ${r.helper} via ${r.via.join(' > ')}`)

  test('flags the terminal branch as it was: the helper in a module function, the write checks in other ternary branches', () => {
    const src = `
      async function terminalIdentity(projectId) {
        const identity = await getAuthzIdentity({ fresh: true })
        const access = await requireProjectAccess({ userId: identity.principal.id }, projectId)
        return access
      }
      export const POST = withRouteErrors('x', async (request) => {
        const identity = socket === 'agent'
          ? await requirePermission(request, 'agent:chat', { projectId })
          : await terminalIdentity(projectId)
        return identity
      })`
    expect(uncovered(src)).toEqual(['POST requireProjectAccess via POST > terminalIdentity'])
  })

  test('flags the same written inline: a check in one branch does not cover a call in another', () => {
    const src = `export async function POST(r) {
      const a = kind === 'agent' ? await requirePermission(r, 'agent:chat', { projectId }) : await requireProjectAccess(eff, projectId)
    }`
    expect(uncovered(src)).toEqual(['POST requireProjectAccess via POST'])
  })

  test('accepts the conversation pattern: the helper, then a write-level check in the same branch', () => {
    const src = `export async function PATCH(request) {
      try {
        if (!isInternalRequest(request)) {
          const guard = await requireConversationAccessBySession(eff, sessionId)
          if (guard instanceof NextResponse) return guard
          const auth = await requirePermission(request, 'agent:chat', { projectId: guard.conversation.projectId })
          if (auth instanceof NextResponse) return auth
        }
      } catch (e) { return internalError(e, 'x') }
    }`
    expect(analyse(src)).toHaveLength(1)
    expect(uncovered(src)).toEqual([])
  })

  test('accepts a withPermission wrapper at a write level over a module handler, two functions deep', () => {
    const src = `
      async function deeper(id) { return guardProject(id) }
      async function handler(r, ctx, auth) { return deeper(ctx.id) }
      export const DELETE = withRouteErrors('x', withPermission('project:delete', handler, { projectId: async () => 'p' }))`
    expect(analyse(src)).toHaveLength(1)
    expect(uncovered(src)).toEqual([])
  })

  test('flags a write behind a read-level permission, an unknown permission, or a permission given by a variable', () => {
    for (const permission of ["'recon:read'", "'traffic:read'", "'no:such'", 'PERMISSION']) {
      const src = `export async function PUT(r) { await requirePermission(r, ${permission}, { projectId }); await guardProject(projectId) }`
      expect([permission, uncovered(src)]).toEqual([permission, ['PUT guardProject via PUT']])
    }
  })

  test('flags a write whose check sits in a branch the helper call is outside of', () => {
    const src = `export async function POST(r) {
      if (overwrite) { await requirePermission(r, 'recon:scan', { projectId }) }
      await requireProjectScopedResource(eff, load)
    }`
    expect(uncovered(src)).toEqual(['POST requireProjectScopedResource via POST'])
  })

  test('a read handler needs a permission with a project level; a write level is not asked of it', () => {
    expect(uncovered(`export async function GET(r) { await requireProjectOwner(projectId) }`)).toEqual(['GET requireProjectOwner via GET'])
    expect(uncovered(`export async function GET(r) { await requirePermission(r, 'triage:read', { projectId }); await requireProjectOwner(projectId) }`)).toEqual([])
    expect(uncovered(`export async function GET(r) { await requirePermission(r, 'users:read'); await requireProjectOwner(projectId) }`)).toEqual(['GET requireProjectOwner via GET'])
  })

  test('a name in a comment or a string is not a call', () => {
    expect(analyse(`// requireProjectAccess(eff, id)\nexport async function POST(r) { log('guardProject(id)') }`)).toEqual([])
  })
})

describe('the routes (step 4.3)', () => {
  const reaches = routes.flatMap((file) => analyse(readFileSync(path.join(WEBAPP, file), 'utf8'), file).map((r) => ({ ...r, file })))

  test('every route was read, and the analysis finds the handlers that reach a level-less helper (not vacuous)', () => {
    expect(routes.length).toBeGreaterThan(300)
    const conversationWrites = reaches.filter((r) => r.file.includes('/conversations/') && WRITE_METHODS.has(r.method))
    expect(conversationWrites.length).toBeGreaterThanOrEqual(6)
  })

  test('no handler reaches a level-less helper without a permission check of the level its method needs', () => {
    const uncovered = reaches.filter((r) => !r.covered).map((r) => `${r.file} ${r.method} reaches ${r.helper} via ${r.via.join(' > ')}`)
    expect(uncovered, 'ask requirePermission / withPermission with the action\'s permission (a write level for a write) on the same path, or projectAccess + meetsLevel').toEqual([])
  })

  test('the Kali terminal branch reaches none: it asks projectAccess at Exploitation & shells (W+X)', () => {
    const ticket = reaches.filter((r) => r.file.endsWith('agent/ws-ticket/route.ts'))
    expect(ticket).toEqual([])
    // Step 5.2 lifted the owner hold of step 4.3 to W+X (the ticket names the owner as tenant since 5.3).
    expect(readFileSync(path.join(API, 'agent', 'ws-ticket', 'route.ts'), 'utf8')).toMatch(/meetsLevel\(access, 'W\+X'\)/)
  })

  test('production code outside access.ts never calls a level-less helper, so no route reaches one through a library', () => {
    const lib = SOURCES.filter(isLibraryModule)
    // Not vacuous: the helper modules beside the routes are read as well.
    expect(lib.filter((f) => f.startsWith('src/app/api/')).length).toBeGreaterThan(10)
    const callers = libraryCallers(lib.map((file) => ({ file, source: readFileSync(path.join(WEBAPP, file), 'utf8') })))
    // access.ts: guardProject and requireProjectScopedResource are built on requireProjectAccess.
    // conversationAccess.ts (step 5.8): requireConversationRead, the conversation read routes' guard, runs the
    // author guard and then asks agent:chat (W+A) of the author, or graph:read at R* of anyone else, on every
    // path that answers a conversation; it is a read, never a write (conversations.access.test.ts, "every read
    // path asks a permission with a project level").
    expect(callers).toEqual(['src/lib/access.ts', 'src/lib/authz/conversationAccess.ts'])
  })
})

describe('the library check (fixtures, review of 4.3)', () => {
  const call = 'export async function check(eff, id) { return requireProjectAccess(eff, id) }'

  test('a helper module under src/app/api is library code: its call is found; a route file is left to the route analysis', () => {
    expect(libraryCallers([
      { file: 'src/app/api/foo/shared.ts', source: call },
      { file: 'src/app/api/foo/bar/helpers.tsx', source: call },
      { file: 'src/app/api/foo/routes.ts', source: call },
      { file: 'src/app/api/foo/route.ts', source: call },
      { file: 'src/app/api/foo/route.test.ts', source: call },
      { file: 'src/lib/thing.ts', source: call },
      { file: 'src/lib/quiet.ts', source: 'export const x = 1 // guardProject(id)' },
    ])).toEqual(['src/app/api/foo/shared.ts', 'src/app/api/foo/bar/helpers.tsx', 'src/app/api/foo/routes.ts', 'src/lib/thing.ts'])
  })

  test('route files are exactly the route.ts files under src/app/api', () => {
    expect(['src/app/api/route.ts', 'src/app/api/a/[id]/route.ts', 'src/app/api/a/route.tsx', 'src/app/api/a/myroute.ts', 'src/lib/route.ts']
      .filter(isRouteFile)).toEqual(['src/app/api/route.ts', 'src/app/api/a/[id]/route.ts'])
  })
})

describe('write handlers behind a read-level permission (review of 4.3)', () => {
  test('found from the manifest: a per-method permission, a write level, a key route and an unknown id are told apart', () => {
    const manifest: RouteManifestEntry[] = [
      { path: '/api/a', guard: 'project', methods: ['GET', 'POST'], permission: { GET: 'graph:read', POST: 'graph:read' } },
      { path: '/api/b', guard: 'project', methods: ['GET', 'DELETE'], permission: { GET: 'graph:read', DELETE: 'graph:edit' } },
      { path: '/api/c', guard: 'project', methods: ['PUT', 'PATCH'], permission: 'workspace:read' },
      { path: '/api/d', guard: 'internal', methods: ['POST'], permission: null },
      { path: '/api/e', guard: 'project', methods: ['POST'], permission: 'no:such' },
      { path: '/api/f', guard: 'session', methods: ['GET'], permission: 'recon:read' },
    ]
    expect(readLevelWrites(manifest)).toEqual(['PATCH /api/c', 'POST /api/a', 'PUT /api/c'])
  })

  test('on the tree: exactly the listed routes, each with its reason', () => {
    expect(ROUTE_MANIFEST.length).toBeGreaterThan(300)
    for (const [route, why] of Object.entries(READ_LEVEL_WRITES)) expect([route, why.length > 20]).toEqual([route, true])
    expect(
      readLevelWrites(ROUTE_MANIFEST),
      'a write handler a read share passes: ask a write-level permission, or list it in READ_LEVEL_WRITES with why it writes nothing',
    ).toEqual(Object.keys(READ_LEVEL_WRITES).sort())
  })
})
