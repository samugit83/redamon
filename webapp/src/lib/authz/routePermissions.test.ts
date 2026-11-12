/** @vitest-environment node */
/**
 * The route families whose permission step 3.8 wires (PE-19, PE-22): every route has one in the
 * manifest, per method, and it is the permission the route's handler asks `requirePermission` for
 * first, read from the source's syntax tree. A route that changes its permission and not its entry
 * (or the reverse) fails here, naming the file and the method; so does a new route in a family
 * that asks for none. The routes of a family that answer every signed-in account are listed in
 * SESSION_ONLY with the reason.
 *
 * Whether each permission is enforced is proved by the families' `*.permissions.test.ts`, which run
 * the real guard; this file keeps the manifest, which the live matrix rows are generated from
 * (scripts/gen-rbac-matrix-rows.mjs), equal to the code, and the generated rows equal to the manifest.
 * Handlers whose permission a later step wires are in LATER, with the step.
 */
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import ts from 'typescript'
import { describe, expect, test } from 'vitest'
import { ROUTE_MANIFEST, type HttpMethod, type RouteManifestEntry } from './routeManifest'
import { PERMISSION_IDS } from './permissions'
import { REPRESENTATIVES, run as runMatrixRows } from '../../../scripts/gen-rbac-matrix-rows.mjs'

const WEBAPP = join(__dirname, '..', '..', '..')

/** The families of step 3.8: projects, recon and scans. */
const WAVE_A: readonly RegExp[] = [
  /^\/api\/recon\//,
  /^\/api\/job-queue\//,
  /^\/api\/(gvm|github-hunt|trufflehog|supply-chain|ai-attack-surface|js-recon)\//,
  /^\/api\/projects(\/(import|defaults))?$/,
  /^\/api\/projects\/\[id\]$/,
  /^\/api\/projects\/\[id\]\/(queue|schedules|versions|delta|supply-chain-batch|wordlists|auth-profile|authorizations|export|ip-hostnames|recording|roe)(\/|$)/,
  /^\/api\/roe\//,
  /^\/api\/presets(\/|$)/,
  /^\/api\/nuclei-templates$/,
]

/**
 * `<METHOD> <path>` of the families' handlers that answer every signed-in account, and why (3.9 gives
 * them `permission: null`).
 */
const SESSION_ONLY: Readonly<Record<string, string>> = {
  'GET /api/gvm/available': 'whether this install runs the GVM stack: an instance fact the scan tab reads to show or hide itself, no project data',
  'GET /api/js-recon/trufflehog/available': 'whether the TruffleHog image is present: an instance fact the JS recon tab reads, no project data',
  'GET /api/projects': 'the projects the account can see (visibleProjectsWhere): seeing one is project access, and each action on it asks its own permission',
  'GET /api/projects/defaults': 'the default values of a new project form: registry data, no project, nothing written',
  'GET /api/nuclei-templates': 'the templates the account may select or manage, scoped by owner inside (own and instance ones; every one with the shared tool): reading the library changes nothing',
}

/**
 * `<METHOD> <path>` of the families' handlers whose permission a later step wires, and which step.
 * They name no permission in the manifest until then.
 */
const LATER: Readonly<Record<string, string>> = {
  'PATCH /api/nuclei-templates': 'promoting a template to an instance one is platform:nuclei_templates, the shared-tool check step 3.9 moves onto can()',
}

const HANDLER_METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'])

/** The literal permission of each requirePermission / withPermission call in a subtree, in order. */
function guardPermissions(node: ts.Node): string[] {
  const out: string[] = []
  const visit = (n: ts.Node) => {
    if (ts.isCallExpression(n) && ts.isIdentifier(n.expression)
      && (n.expression.text === 'requirePermission' || n.expression.text === 'withPermission')) {
      const arg = n.arguments[n.expression.text === 'requirePermission' ? 1 : 0]
      out.push(arg && ts.isStringLiteralLike(arg) ? arg.text : '<not a literal>')
    }
    ts.forEachChild(n, visit)
  }
  visit(node)
  return out
}

/** Each exported handler of a route file -> the permissions its body asks for, in order. */
function handlerPermissions(source: string): Map<string, string[]> {
  const sf = ts.createSourceFile('route.ts', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS)
  const out = new Map<string, string[]>()
  const exported = (n: ts.Node) => ts.getModifiers?.(n as ts.HasModifiers)?.some(m => m.kind === ts.SyntaxKind.ExportKeyword)
  for (const stmt of sf.statements) {
    if (ts.isFunctionDeclaration(stmt) && stmt.name && exported(stmt) && HANDLER_METHODS.has(stmt.name.text)) {
      out.set(stmt.name.text, guardPermissions(stmt))
    }
    if (ts.isVariableStatement(stmt) && exported(stmt)) {
      for (const d of stmt.declarationList.declarations) {
        if (ts.isIdentifier(d.name) && HANDLER_METHODS.has(d.name.text) && d.initializer) out.set(d.name.text, guardPermissions(d.initializer))
      }
    }
  }
  return out
}

function permissionOf(entry: RouteManifestEntry, method: HttpMethod): string | undefined {
  if (typeof entry.permission === 'string') return entry.permission
  return entry.permission?.[method]
}

const family = ROUTE_MANIFEST.filter(e => WAVE_A.some(re => re.test(e.path)))
const fileOf = (path: string) => join(WEBAPP, 'src', 'app', ...path.split('/').slice(1), 'route.ts')

describe('route permissions, wave A: projects, recon, scans (step 3.8)', () => {
  test('the families are in the manifest', () => {
    expect(family.length).toBeGreaterThan(0)
  })

  test('every route of the families names a permission in the manifest for each method, or is SESSION_ONLY with a reason', () => {
    const missing = family.flatMap(e => e.methods.map(m => `${m} ${e.path}`).filter(key => !(key in SESSION_ONLY) && !(key in LATER)))
      .filter(key => { const [m, path] = key.split(' '); return !permissionOf(family.find(e => e.path === path)!, m as HttpMethod) })
    expect(missing, 'give the route a permission (requirePermission) and its manifest entry the same').toEqual([])
    for (const [key, why] of [...Object.entries(SESSION_ONLY), ...Object.entries(LATER)]) {
      const [m, path] = key.split(' ')
      const entry = family.find(e => e.path === path)
      expect(entry?.methods.includes(m as HttpMethod), `SESSION_ONLY names ${key}, which is not a handler of the families`).toBe(true)
      expect(permissionOf(entry!, m as HttpMethod), `${key} is SESSION_ONLY and names a permission`).toBeUndefined()
      expect(why.length).toBeGreaterThan(20)
    }
  })

  test("each method's manifest permission is the one its handler asks requirePermission for first", () => {
    const wrong: string[] = []
    for (const e of family) {
      const handlers = handlerPermissions(readFileSync(fileOf(e.path), 'utf8'))
      for (const m of e.methods) {
        if (`${m} ${e.path}` in SESSION_ONLY || `${m} ${e.path}` in LATER) continue
        const asked = handlers.get(m) ?? []
        if (asked[0] !== permissionOf(e, m)) wrong.push(`${m} ${e.path}: manifest ${permissionOf(e, m)}, handler asks ${asked.join(', ') || 'nothing'}`)
      }
    }
    expect(wrong).toEqual([])
  })

  test('the permissions named are registry ids', () => {
    const named = family.flatMap(e => (typeof e.permission === 'string' ? [e.permission] : Object.values(e.permission ?? {})))
    expect(named.filter(p => !(PERMISSION_IDS as readonly string[]).includes(p))).toEqual([])
  })

  test('every permission the families name has generated live rows, and p3_generated.tsv is up to date', () => {
    const named = new Set(family.flatMap(e => (typeof e.permission === 'string' ? [e.permission] : Object.values(e.permission ?? {}))))
    expect([...named].filter(p => !Object.hasOwn(REPRESENTATIVES, p)).sort(), 'add a representative to gen-rbac-matrix-rows.mjs').toEqual([])
    const out: string[] = []
    expect(runMatrixRows(['--check'], WEBAPP, (line: string) => out.push(line)), out.join('\n')).toBe(0)
  })

  test('the reader of handler permissions finds each handler and only its own calls', () => {
    const src = [
      "export async function GET(r: Request) { await requirePermission(r, 'recon:read', { projectId }) }",
      "export const POST = withRouteErrors('x', async (r: Request) => { const a = await requirePermission(r, 'recon:scan', { projectId }); requireAlso(a, 'recon:overwrite') })",
      "export const PUT = withPermission('preset:write', handler)",
      'export async function DELETE(r: Request) { await requirePermission(r, permission) }',
      "function helper(r: Request) { return requirePermission(r, 'users:read') }",
    ].join('\n')
    expect(Object.fromEntries(handlerPermissions(src))).toEqual({
      GET: ['recon:read'], POST: ['recon:scan'], PUT: ['preset:write'], DELETE: ['<not a literal>'],
    })
  })
})
