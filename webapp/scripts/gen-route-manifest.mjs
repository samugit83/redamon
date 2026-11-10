/**
 * Keep src/lib/authz/routeManifest.ts (and its JSON copy) in line with the route tree.
 *
 *   node scripts/gen-route-manifest.mjs           write both files, print what changed
 *   node scripts/gen-route-manifest.mjs --check   change nothing, exit 1 if either file is stale
 *
 * Run from webapp/. Every src/app/api/**\/route.ts gets one entry: its URL path, the
 * methods it exports and a guard class. The class comes from the guard helpers the
 * file CALLS, read from the TypeScript syntax tree, so a helper named in a comment or
 * a string does not count (agent/emergency-stop-all names INTERNAL_API_KEY in a
 * comment and guards nothing). `public` and `plugin-token` come from the middleware's
 * PUBLIC_PATHS and TOKEN_AUTH_PREFIXES instead, since those routes carry no session.
 *
 * The manifest is reviewed and kept by hand. On a run the generator keeps every
 * listed entry's fields, refreshes its methods, re-derives the class of an entry
 * that has no `note` (an entry with a note is the reviewer's class, never changed),
 * adds new route files with the class their calls give, and drops entries whose
 * file is gone. Only the ROUTE_MANIFEST initializer is rewritten: the rest of the
 * .ts file is hand-kept, and comments inside the list are not.
 *
 * The JSON copy exists because .mjs scripts (step 3.8's row generator) cannot import
 * TypeScript with `@/` aliases. Needs only Node and the webapp's devDependencies.
 */
import { existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { dirname, join, relative, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import ts from 'typescript'

export const METHOD_ORDER = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']

/**
 * Guard helper -> class. A file calling helpers of several classes gets the first
 * class of GUARD_PRECEDENCE: the guard a signed-in user meets wins over the
 * internal or scanner key the same route also accepts.
 */
export const GUARD_HELPERS = {
  requireConversationAccess: 'conversation',
  requireConversationAccessBySession: 'conversation',
  guardProject: 'project',
  requireProjectAccess: 'project',
  requireProjectScopedResource: 'project',
  requireProjectOwner: 'project',
  // importUrlRequest.ts: requireEffectiveUser + requireProjectAccess for the URL-import proxies.
  guardImport: 'project',
  requireUserAccess: 'user',
  // userSkillRouteGuard.ts: same origin + the effective user is the path's user, no admin bypass.
  requireOwnBrowserRequest: 'user',
  requirePluginAdmin: 'admin-db',
  lifecyclePost: 'admin-db',
  lifecycleGet: 'admin-db',
  requireAdmin: 'admin-jwt',
  // plugins/actions.ts: the effective user must own the optional project and chat session.
  strictContext: 'other',
  handleAction: 'other',
  requireEffectiveUser: 'effective-user',
  getEffectiveUser: 'effective-user',
  ownerScope: 'effective-user',
  getSession: 'session',
  requireSession: 'session',
  isScannerRequest: 'scanner',
  isInternalRequest: 'internal',
}

export const GUARD_PRECEDENCE = [
  'public',
  'plugin-token',
  'conversation',
  'project',
  'user',
  'admin-db',
  'admin-jwt',
  'other',
  'effective-user',
  'session',
  'scanner',
  'internal',
  'login-only',
]

const WEBAPP = join(dirname(fileURLToPath(import.meta.url)), '..')
const MANIFEST_TS = join('src', 'lib', 'authz', 'routeManifest.ts')
const MANIFEST_JSON = join('src', 'lib', 'authz', 'routeManifest.json')
const API_DIR = join('src', 'app', 'api')

function parse(file, source) {
  return ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS)
}

/** The guard helpers the source calls, as `f(...)` or `x.f(...)`, anywhere in the file. */
export function calledGuards(source) {
  const found = new Set()
  const visit = node => {
    if (ts.isCallExpression(node)) {
      const callee = node.expression
      const name = ts.isIdentifier(callee) ? callee.text : ts.isPropertyAccessExpression(callee) ? callee.name.text : null
      if (name && Object.hasOwn(GUARD_HELPERS, name)) found.add(name)
    }
    ts.forEachChild(node, visit)
  }
  visit(parse('route.ts', source))
  return found
}

/** The HTTP methods the route module exports, in METHOD_ORDER. */
export function exportedMethods(source) {
  const found = new Set()
  const isExported = node => ts.getModifiers?.(node)?.some(m => m.kind === ts.SyntaxKind.ExportKeyword)
  for (const stmt of parse('route.ts', source).statements) {
    if (ts.isFunctionDeclaration(stmt) && isExported(stmt) && stmt.name) found.add(stmt.name.text)
    if (ts.isVariableStatement(stmt) && isExported(stmt)) {
      for (const decl of stmt.declarationList.declarations) {
        if (ts.isIdentifier(decl.name)) found.add(decl.name.text)
      }
    }
    if (ts.isExportDeclaration(stmt) && stmt.exportClause && ts.isNamedExports(stmt.exportClause)) {
      for (const spec of stmt.exportClause.elements) found.add(spec.name.text)
    }
  }
  return METHOD_ORDER.filter(m => found.has(m))
}

function stringArray(sf, name) {
  let out = null
  const visit = node => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.name.text === name) {
      const init = node.initializer
      if (init && ts.isArrayLiteralExpression(init) && init.elements.every(ts.isStringLiteralLike)) {
        out = init.elements.map(e => e.text)
      }
    }
    if (!out) ts.forEachChild(node, visit)
  }
  visit(sf)
  if (!out) throw new Error(`src/middleware.ts: ${name} is no longer an array of string literals; update gen-route-manifest.mjs`)
  return out
}

/** The middleware's sessionless paths, matched as the middleware matches them. */
export function readMiddlewarePaths(webappDir = WEBAPP) {
  const file = join(webappDir, 'src', 'middleware.ts')
  const sf = parse(file, readFileSync(file, 'utf8'))
  return { publicPaths: stringArray(sf, 'PUBLIC_PATHS'), tokenPrefixes: stringArray(sf, 'TOKEN_AUTH_PREFIXES') }
}

export function classify(path, calls, middleware) {
  if (middleware.publicPaths.some(p => path === p || path.startsWith(p + '/'))) return 'public'
  if (middleware.tokenPrefixes.some(p => path.startsWith(p))) return 'plugin-token'
  const classes = new Set([...calls].map(name => GUARD_HELPERS[name]))
  return GUARD_PRECEDENCE.find(c => classes.has(c)) ?? 'login-only'
}

function routeFiles(dir, out = []) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name)
    if (entry.isDirectory()) routeFiles(full, out)
    else if (entry.name === 'route.ts') out.push(full)
  }
  return out
}

function byPath(a, b) {
  return a.path < b.path ? -1 : a.path > b.path ? 1 : 0
}

/** Every route file: `{path, file, methods, auto}`, `auto` being the class its calls give. */
export function scanRoutes(webappDir = WEBAPP) {
  const middleware = readMiddlewarePaths(webappDir)
  const appDir = join(webappDir, 'src', 'app')
  return routeFiles(join(webappDir, API_DIR))
    .map(full => {
      const source = readFileSync(full, 'utf8')
      const path = '/' + relative(appDir, dirname(full)).split(sep).join('/')
      return {
        path,
        file: relative(webappDir, full).split(sep).join('/'),
        methods: exportedMethods(source),
        auto: classify(path, calledGuards(source), middleware),
      }
    })
    .sort(byPath)
}

const KEY_ORDER = ['path', 'guard', 'methods', 'permission', 'note']

function ordered(entry) {
  const keys = [...KEY_ORDER.filter(k => k in entry), ...Object.keys(entry).filter(k => !KEY_ORDER.includes(k))]
  return Object.fromEntries(keys.map(k => [k, entry[k]]))
}

/**
 * The manifest after a run, and one line per change. `existing` entries keep every
 * field but methods; the class follows the calls unless the entry has a note.
 */
export function mergeManifest(existing, routes) {
  const old = new Map(existing.map(e => [e.path, e]))
  const files = new Set(routes.map(r => r.path))
  const changes = []
  const entries = []
  for (const route of routes) {
    const prev = old.get(route.path)
    if (!prev) {
      entries.push({ path: route.path, guard: route.auto, methods: route.methods })
      changes.push(`added    ${route.path} as ${route.auto} (${route.file})`)
      continue
    }
    const next = { ...prev, methods: route.methods }
    if (prev.methods.join() !== route.methods.join()) {
      changes.push(`methods  ${route.path}: [${prev.methods.join(', ')}] -> [${route.methods.join(', ')}] (review its class)`)
    }
    if (!prev.note && prev.guard !== route.auto) {
      next.guard = route.auto
      changes.push(`class    ${route.path}: ${prev.guard} -> ${route.auto} (its calls changed)`)
    }
    entries.push(ordered(next))
  }
  for (const prev of existing) {
    if (!files.has(prev.path)) changes.push(`removed  ${prev.path} (its route file is gone)`)
  }
  const rank = line => line.split(/\s+/)[1].replace(/:$/, '')
  changes.sort((a, b) => (rank(a) < rank(b) ? -1 : rank(a) > rank(b) ? 1 : 0))
  return { entries: entries.sort(byPath), changes }
}

function manifestInitializer(sf) {
  let found = null
  const visit = node => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.name.text === 'ROUTE_MANIFEST') found = node
    if (!found) ts.forEachChild(node, visit)
  }
  visit(sf)
  let init = found?.initializer
  while (init && (ts.isAsExpression(init) || ts.isSatisfiesExpression(init) || ts.isParenthesizedExpression(init))) {
    init = init.expression
  }
  if (!init || !ts.isArrayLiteralExpression(init)) {
    throw new Error('routeManifest.ts: no `ROUTE_MANIFEST = [ ... ]` array literal found')
  }
  return init
}

function literalValue(sf, node) {
  const fail = () => {
    const { line } = sf.getLineAndCharacterOfPosition(node.getStart(sf))
    throw new Error(`routeManifest.ts line ${line + 1}: only literal values (strings, arrays, objects, true/false/null, numbers) may appear in ROUTE_MANIFEST`)
  }
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text
  if (ts.isNumericLiteral(node)) return Number(node.text)
  if (node.kind === ts.SyntaxKind.TrueKeyword) return true
  if (node.kind === ts.SyntaxKind.FalseKeyword) return false
  if (node.kind === ts.SyntaxKind.NullKeyword) return null
  if (ts.isArrayLiteralExpression(node)) return node.elements.map(e => literalValue(sf, e))
  if (ts.isObjectLiteralExpression(node)) {
    const out = {}
    for (const prop of node.properties) {
      if (!ts.isPropertyAssignment(prop) || !(ts.isIdentifier(prop.name) || ts.isStringLiteral(prop.name))) fail()
      out[prop.name.text] = literalValue(sf, prop.initializer)
    }
    return out
  }
  return fail()
}

/** The entries of a routeManifest.ts source. */
export function parseManifestSource(source) {
  const sf = parse('routeManifest.ts', source)
  return manifestInitializer(sf).elements.map(e => literalValue(sf, e))
}

const IDENT = /^[A-Za-z_$][\w$]*$/

function tsLiteral(value) {
  if (typeof value === 'string') return `'${value.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n')}'`
  if (Array.isArray(value)) return `[${value.map(tsLiteral).join(', ')}]`
  if (value && typeof value === 'object') {
    const props = Object.entries(value).map(([k, v]) => `${IDENT.test(k) ? k : tsLiteral(k)}: ${tsLiteral(v)}`)
    return props.length ? `{ ${props.join(', ')} }` : '{}'
  }
  return JSON.stringify(value)
}

/** `source` with the ROUTE_MANIFEST initializer replaced by `entries`, one per line. */
export function renderManifestSource(source, entries) {
  const sf = parse('routeManifest.ts', source)
  const init = manifestInitializer(sf)
  const body = entries.length ? `[\n${entries.map(e => `  ${tsLiteral(ordered(e))},`).join('\n')}\n]` : '[]'
  return source.slice(0, init.getStart(sf)) + body + source.slice(init.end)
}

/** The JSON copy, one entry per line. */
export function renderJson(entries) {
  return `[\n${entries.map(e => `  ${JSON.stringify(ordered(e))}`).join(',\n')}\n]\n`
}

function main(argv) {
  const check = argv.includes('--check')
  const tsFile = join(WEBAPP, MANIFEST_TS)
  const jsonFile = join(WEBAPP, MANIFEST_JSON)
  const source = readFileSync(tsFile, 'utf8')
  const { entries, changes } = mergeManifest(parseManifestSource(source), scanRoutes(WEBAPP))
  const nextTs = renderManifestSource(source, entries)
  const nextJson = renderJson(entries)
  const jsonStale = !existsSync(jsonFile) || readFileSync(jsonFile, 'utf8') !== nextJson
  for (const line of changes) console.log(line)
  if (check) {
    if (jsonStale) console.log(`stale    ${MANIFEST_JSON} (it must equal ${MANIFEST_TS})`)
    if (changes.length || jsonStale) {
      console.log('The route manifest is out of date: run `node scripts/gen-route-manifest.mjs` from webapp/ and review it.')
      return 1
    }
    console.log(`route manifest up to date: ${entries.length} routes`)
    return 0
  }
  if (nextTs !== source) writeFileSync(tsFile, nextTs)
  if (jsonStale) writeFileSync(jsonFile, nextJson)
  const loginOnly = entries.filter(e => e.guard === 'login-only').length
  console.log(`route manifest: ${entries.length} routes, ${changes.length} change(s), ${loginOnly} login-only`)
  if (changes.length) console.log('Review the changes: give a class its calls do not give a `note` saying why.')
  return 0
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = main(process.argv.slice(2))
}
