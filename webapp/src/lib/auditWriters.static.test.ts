/**
 * Audit forwarding (AU-06, step 6.12) prints a row only after the transaction that wrote it commits,
 * and Prisma tells nobody when that is: only `auditedTransaction` (lib/auditForward.ts) knows. So two
 * rules must hold for every audit row the webapp writes, and this test reads every production file's
 * syntax tree (TypeScript, as scripts/gen-route-manifest.mjs does) to hold them:
 *
 *  1. every insert into `audit_log`, `act_as_audit` or `fireteam_settings_audit` goes through the
 *     three `create*` functions of lib/auditForward.ts, the only file that writes those tables (a
 *     direct `tx.auditLog.create`, or raw SQL inserting into them, fails here: its row would never be
 *     forwarded);
 *  2. the client each of those functions is handed is either the root client (`prisma` from
 *     lib/prisma: the row is committed when its insert resolves) or the transaction client of an
 *     `auditedTransaction` callback. The client is followed through the functions that pass it on
 *     (`writeAuditTx(tx, ...)`, a module's own `audit(tx, ...)` or `write(tx, ...)`), to every place
 *     those are called or handed over, in any file, and through a function that runs a callback
 *     inside its own `auditedTransaction` (`withLastAdminGuard`). A raw `prisma.$transaction(...)`
 *     around a write, or a client the trail loses (an object property, a re-export), fails here.
 *
 * The host scripts under webapp/scripts are not forwarded (README.DEV.md §8) and are not read.
 * The analysis itself is checked first on small sources, so a green run cannot mean it saw nothing.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/auditWriters.static.test.ts
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import path from 'node:path'
import ts from 'typescript'

const WEBAPP = path.resolve(__dirname, '../..')
const FORWARD_MODULE = 'src/lib/auditForward.ts'
const PRISMA_MODULE = 'src/lib/prisma.ts'
const RUNNER = 'auditedTransaction'
/** The writers of lib/auditForward.ts, each taking the client as its first argument. */
const SINKS = new Set(['createAuditLogRow', 'createActAsAuditRow', 'createFireteamAuditRows'])
const AUDIT_MODELS = new Set(['auditLog', 'actAsAudit', 'fireteamSettingsAudit'])
const INSERTS = new Set(['create', 'createMany', 'createManyAndReturn', 'upsert'])
const RAW_INSERT = /INSERT\s+INTO\s+"?(audit_log|act_as_audit|fireteam_settings_audit)\b/i

function productionSources(): Map<string, string> {
  const out = new Map<string, string>()
  const walk = (dir: string): void => {
    for (const name of readdirSync(dir)) {
      const full = path.join(dir, name)
      if (statSync(full).isDirectory()) {
        if (name !== 'node_modules' && name !== '__testing__' && name !== '__fixtures__') walk(full)
      } else if (/\.(ts|tsx)$/.test(name) && !/\.test\.(ts|tsx)$/.test(name) && !name.endsWith('.d.ts')) {
        out.set(path.relative(WEBAPP, full).split(path.sep).join('/'), readFileSync(full, 'utf8'))
      }
    }
  }
  walk(path.join(WEBAPP, 'src'))
  return out
}

type FnNode = ts.FunctionDeclaration | ts.FunctionExpression | ts.ArrowFunction
type Decl =
  | { kind: 'param'; file: string; fn: ts.SignatureDeclaration; index: number }
  | { kind: 'fn'; file: string; node: FnNode; name: string; exported: boolean }
  | { kind: 'import'; file: string; module: string; name: string }
  | { kind: 'other' }

const isFn = (n: ts.Node): n is FnNode => ts.isFunctionDeclaration(n) || ts.isFunctionExpression(n) || ts.isArrowFunction(n)

function strip(e: ts.Expression): ts.Expression {
  while (ts.isAsExpression(e) || ts.isParenthesizedExpression(e) || ts.isNonNullExpression(e) ||
    ts.isSatisfiesExpression(e) || ts.isTypeAssertionExpression(e)) e = e.expression
  return e
}

function isExported(node: ts.Node): boolean {
  return ts.canHaveModifiers(node) && (ts.getModifiers(node) ?? []).some((m) => m.kind === ts.SyntaxKind.ExportKeyword)
}

/** Whether a binding pattern (`{ tx }`, `[a, b]`) binds `name`. */
const binds = (pattern: ts.Node, name: string) =>
  new RegExp(`(^|[^\\w$])${name.replace(/\$/g, '\\$')}($|[^\\w$])`).test(pattern.getText())

const lineOf = (file: string, sf: ts.SourceFile, node: ts.Node) =>
  `${file}:${sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1}`

/**
 * The places a write can reach an audit table outside lib/auditForward.ts or through a client that is
 * neither the root client nor an `auditedTransaction` transaction, as `file:line what`.
 */
export function auditWriteProblems(sources: Map<string, string>): string[] {
  const trees = new Map<string, ts.SourceFile>()
  const tree = (file: string): ts.SourceFile => {
    let sf = trees.get(file)
    if (!sf) {
      sf = ts.createSourceFile(file, sources.get(file)!, ts.ScriptTarget.Latest, true, file.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS)
      trees.set(file, sf)
    }
    return sf
  }
  const problems: string[] = []

  function resolveModule(from: string, spec: string): string | null {
    let base: string
    if (spec.startsWith('@/')) base = `src/${spec.slice(2)}`
    else if (spec.startsWith('.')) base = path.posix.normalize(path.posix.join(path.posix.dirname(from), spec))
    else return null
    for (const c of [base, `${base}.ts`, `${base}.tsx`, `${base}/index.ts`, `${base}/index.tsx`]) if (sources.has(c)) return c
    return null
  }

  /** What `name` declares in one block's statements (a function, a const, an import), if anything. */
  function declaredIn(file: string, statements: readonly ts.Statement[], name: string): Decl | null {
    for (const st of statements) {
      if (ts.isFunctionDeclaration(st) && st.name?.text === name) return { kind: 'fn', file, node: st, name, exported: isExported(st) }
      if (ts.isVariableStatement(st)) {
        for (const d of st.declarationList.declarations) {
          if (ts.isIdentifier(d.name) && d.name.text === name) {
            const init = d.initializer && strip(d.initializer)
            return init && isFn(init) ? { kind: 'fn', file, node: init, name, exported: isExported(st) } : { kind: 'other' }
          }
          if (!ts.isIdentifier(d.name) && binds(d.name, name)) return { kind: 'other' }
        }
      }
      if ((ts.isClassDeclaration(st) || ts.isEnumDeclaration(st)) && st.name?.text === name) return { kind: 'other' }
      if (ts.isImportDeclaration(st) && st.importClause && ts.isStringLiteral(st.moduleSpecifier)) {
        const module = resolveModule(file, st.moduleSpecifier.text) ?? `external:${st.moduleSpecifier.text}`
        const clause = st.importClause
        if (clause.name?.text === name) return { kind: 'import', file, module, name: 'default' }
        const bindings = clause.namedBindings
        if (bindings && ts.isNamespaceImport(bindings) && bindings.name.text === name) return { kind: 'other' }
        if (bindings && ts.isNamedImports(bindings)) {
          for (const el of bindings.elements) {
            if (el.name.text === name) return { kind: 'import', file, module, name: (el.propertyName ?? el.name).text }
          }
        }
      }
    }
    return null
  }

  /** The declaration an identifier names, by walking its scopes outwards (null: a global). */
  function resolve(file: string, id: ts.Identifier): Decl | null {
    const name = id.text
    for (let n: ts.Node | undefined = id.parent; n; n = n.parent) {
      if (ts.isFunctionLike(n)) {
        const params = (n as ts.SignatureDeclaration).parameters
        for (let i = 0; i < params.length; i++) {
          const p = params[i].name
          if (ts.isIdentifier(p) && p.text === name) return { kind: 'param', file, fn: n as ts.SignatureDeclaration, index: i }
          if (!ts.isIdentifier(p) && binds(p, name)) return { kind: 'other' }
        }
      }
      if (ts.isCatchClause(n) && n.variableDeclaration?.name.getText() === name) return { kind: 'other' }
      if ((ts.isForOfStatement(n) || ts.isForInStatement(n) || ts.isForStatement(n)) && n.initializer &&
        ts.isVariableDeclarationList(n.initializer) && n.initializer.declarations.some((d) => binds(d.name, name))) {
        return { kind: 'other' }
      }
      if (ts.isBlock(n) || ts.isSourceFile(n) || ts.isModuleBlock(n) || ts.isCaseClause(n) || ts.isDefaultClause(n)) {
        const found = declaredIn(file, n.statements, name)
        if (found) return found
      }
    }
    return null
  }

  /** An import followed to the function it names in its module; sinks, the runner and prisma stay imports. */
  function follow(d: Decl | null): Decl | null {
    if (!d || d.kind !== 'import' || d.module === PRISMA_MODULE || d.module === FORWARD_MODULE || !sources.has(d.module)) return d
    const sf = tree(d.module)
    for (const st of sf.statements) {
      if (ts.isExportDeclaration(st) && st.exportClause && ts.isNamedExports(st.exportClause) &&
        st.exportClause.elements.some((el) => el.name.text === d.name)) return { kind: 'other' }
    }
    const found = declaredIn(d.module, sf.statements, d.name)
    return found && found.kind === 'fn' && found.exported ? found : { kind: 'other' }
  }

  const calleeIs = (file: string, call: ts.CallExpression, names: Set<string>): string | null => {
    const callee = strip(call.expression)
    if (!ts.isIdentifier(callee)) return null
    const d = resolve(file, callee)
    if (d?.kind === 'import' && d.module === FORWARD_MODULE && names.has(d.name)) return d.name
    if (file === FORWARD_MODULE && d?.kind === 'fn' && names.has(d.name)) return d.name
    return null
  }

  const okParamMemo = new Map<ts.Node, Map<number, boolean>>()
  const runnerMemo = new Map<ts.Node, Map<string, boolean>>()
  const refsMemo = new Map<ts.Node, Map<number, boolean>>()

  /**
   * Whether `e`, handed as its client to `writer` called at `site`, is the root client or a forwarded
   * transaction's. Each problem is reported once, where the trail goes wrong.
   */
  function okClient(file: string, site: ts.CallExpression, writer: string, e: ts.Expression | undefined): boolean {
    const s = e && strip(e)
    const d = s && ts.isIdentifier(s) ? resolve(file, s) : null
    if (d?.kind === 'import' && d.module === PRISMA_MODULE) return true
    if (d?.kind === 'param') return okParam(d.file, d.fn, d.index)
    problems.push(`${lineOf(file, tree(file), site)} ${writer}(...) gets a client the analysis cannot follow (${e ? e.getText() : 'none'})`)
    return false
  }

  function notForwarded(file: string, call: ts.CallExpression): false {
    problems.push(`${lineOf(file, tree(file), call)} ${strip(call.expression).getText()}(...) runs an audit write in a transaction ` +
      `${RUNNER} does not run, so its row is never forwarded after the commit`)
    return false
  }

  function memo<K>(table: Map<ts.Node, Map<K, boolean>>, node: ts.Node, key: K, compute: () => boolean): boolean {
    let byKey = table.get(node)
    if (!byKey) table.set(node, (byKey = new Map()))
    const known = byKey.get(key)
    if (known !== undefined) return known
    byKey.set(key, true) // a function that reaches itself again does not decide its own answer
    const value = compute()
    byKey.set(key, value)
    return value
  }

  /** A function argument passed at position `k` of `call`: does its parameter `index` get a forwarded client? */
  function okCallbackParam(file: string, call: ts.CallExpression, k: number, index: number): boolean {
    if (calleeIs(file, call, new Set([RUNNER]))) return (k === 1 && index === 0) || notForwarded(file, call)
    const callee = strip(call.expression)
    const g = ts.isIdentifier(callee) ? follow(resolve(file, callee)) : null
    return (g?.kind === 'fn' && isRunner(g, k, index)) || notForwarded(file, call)
  }

  /** Parameter `index` of `fn` (in `file`) always holds the root client or a forwarded transaction's. */
  function okParam(file: string, fn: ts.SignatureDeclaration, index: number): boolean {
    return memo(okParamMemo, fn, index, () => {
      const parent = fn.parent
      if ((ts.isArrowFunction(fn) || ts.isFunctionExpression(fn)) && ts.isCallExpression(parent) && parent.arguments.includes(fn as ts.Expression)) {
        return okCallbackParam(file, parent, parent.arguments.indexOf(fn as ts.Expression), index)
      }
      if (ts.isFunctionDeclaration(fn) && fn.name) {
        return everyReferenceOk({ kind: 'fn', file, node: fn, name: fn.name.text, exported: isExported(fn) }, index)
      }
      if ((ts.isArrowFunction(fn) || ts.isFunctionExpression(fn)) && ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) {
        const statement = parent.parent.parent
        return everyReferenceOk({ kind: 'fn', file, node: fn, name: parent.name.text, exported: isExported(statement) }, index)
      }
      problems.push(`${lineOf(file, tree(file), fn)} a function the client passes through that cannot be followed`)
      return false
    })
  }

  /** `g` calls its parameter `k` with a forwarded client at position `index`, and only that way. */
  function isRunner(g: Extract<Decl, { kind: 'fn' }>, k: number, index: number): boolean {
    return memo(runnerMemo, g.node, `${k}:${index}`, () => {
      const param = g.node.parameters[k]
      if (!param || !ts.isIdentifier(param.name)) return false
      const uses: ts.Identifier[] = []
      const walk = (n: ts.Node): void => {
        if (ts.isIdentifier(n) && n.text === (param.name as ts.Identifier).text && n !== param.name) {
          const d = resolve(g.file, n)
          if (d?.kind === 'param' && d.fn === g.node && d.index === k) uses.push(n)
        }
        ts.forEachChild(n, walk)
      }
      if (g.node.body) walk(g.node.body)
      const calls = uses.filter((u) => ts.isCallExpression(u.parent) && u.parent.expression === u)
      return calls.length > 0 && calls.length === uses.length && calls.every((u) =>
        okClient(g.file, u.parent as ts.CallExpression, u.text, (u.parent as ts.CallExpression).arguments[index]))
    })
  }

  /** Every place `d` is called or handed over passes a forwarded client at parameter `index`. */
  function everyReferenceOk(d: Extract<Decl, { kind: 'fn' }>, index: number): boolean {
    return memo(refsMemo, d.node, index, () => {
      const files = [d.file, ...(d.exported ? [...sources.keys()].filter((f) => f !== d.file && sources.get(f)!.includes(d.name)) : [])]
      let ok = true
      for (const file of files) {
        const sf = tree(file)
        const walk = (n: ts.Node): void => {
          if (ts.isIdentifier(n) && n.text === d.name) {
            const parent = n.parent
            const declaration = (ts.isFunctionDeclaration(parent) || ts.isVariableDeclaration(parent)) && parent.name === n
            const bookkeeping = ts.isImportSpecifier(parent) || ts.isImportClause(parent) || ts.isExportSpecifier(parent) ||
              ts.isTypeQueryNode(parent) ||
              (ts.isPropertyAccessExpression(parent) && parent.name === n) || (ts.isPropertyAssignment(parent) && parent.name === n)
            if (!declaration && !bookkeeping) {
              const target = file === d.file ? resolve(file, n) : follow(resolve(file, n))
              if (target?.kind === 'fn' && target.node === d.node) {
                let good: boolean
                if (ts.isCallExpression(parent) && parent.expression === n) good = okClient(file, parent, d.name, parent.arguments[index])
                else if (ts.isCallExpression(parent) && parent.arguments.includes(n)) good = okCallbackParam(file, parent, parent.arguments.indexOf(n), index)
                else {
                  problems.push(`${lineOf(file, sf, n)} ${d.name} is used where the client it writes through cannot be followed`)
                  good = false
                }
                ok = ok && good
              }
            }
            if (ts.isExportSpecifier(parent) && parent.parent.parent.moduleSpecifier) {
              problems.push(`${lineOf(file, sf, n)} ${d.name} is re-exported: its callers cannot be followed`)
              ok = false
            }
          }
          ts.forEachChild(n, walk)
        }
        walk(sf)
      }
      return ok
    })
  }

  for (const file of sources.keys()) {
    const text = sources.get(file)!
    if (file !== FORWARD_MODULE && RAW_INSERT.test(text)) problems.push(`${file} inserts into an audit table with raw SQL`)
    if (file === FORWARD_MODULE) continue
    const sf = tree(file)
    const walk = (n: ts.Node): void => {
      if (ts.isCallExpression(n)) {
        const callee = strip(n.expression)
        if (ts.isPropertyAccessExpression(callee) && INSERTS.has(callee.name.text)) {
          const owner = strip(callee.expression)
          if (ts.isPropertyAccessExpression(owner) && AUDIT_MODELS.has(owner.name.text)) {
            problems.push(`${lineOf(file, sf, n)} writes ${owner.name.text} directly instead of through lib/auditForward.ts`)
          }
        }
        const sink = calleeIs(file, n, SINKS)
        if (sink) okClient(file, n, sink, n.arguments[0])
      }
      ts.forEachChild(n, walk)
    }
    walk(sf)
  }
  return [...new Set(problems)].sort()
}

/** Small sources: the forwarding module, the audit helper and prisma, as the real ones export them. */
function world(extra: Record<string, string>): Map<string, string> {
  return new Map(Object.entries({
    'src/lib/prisma.ts': 'const prisma = {} as any\nexport default prisma\n',
    'src/lib/auditForward.ts': [
      'export async function createAuditLogRow(db: any, data: any) { await db.auditLog.create({ data }) }',
      'export async function createActAsAuditRow(db: any, data: any) { await db.actAsAudit.create({ data }) }',
      'export async function auditedTransaction(db: any, fn: any) { return db.$transaction(fn) }',
    ].join('\n'),
    'src/lib/audit.ts': [
      "import prisma from '@/lib/prisma'",
      "import { createAuditLogRow } from '@/lib/auditForward'",
      'export async function writeAudit(entry: any) { await createAuditLogRow(prisma, entry) }',
      'export async function writeAuditTx(tx: any, entry: any) { await createAuditLogRow(tx, entry) }',
    ].join('\n'),
    ...extra,
  }))
}

const UNWRAPPED = 'runs an audit write in a transaction auditedTransaction does not run, so its row is never forwarded after the commit'

describe('the analysis finds what it must (small sources)', () => {
  test('the shapes the webapp uses pass: the callback, a helper, a guard that runs a callback, the root client', () => {
    const sources = world({
      'src/lib/adminSet.ts': [
        "import prisma from '@/lib/prisma'",
        "import { auditedTransaction } from '@/lib/auditForward'",
        'export async function withGuard(id: string, write: (tx: any, n: number) => Promise<void>) {',
        '  return auditedTransaction(prisma, async (tx) => { await write(tx, 1) })',
        '}',
      ].join('\n'),
      'src/lib/good.ts': [
        "import prisma from '@/lib/prisma'",
        "import { writeAuditTx as w, writeAudit } from '@/lib/audit'",
        "import { auditedTransaction, createActAsAuditRow } from '@/lib/auditForward'",
        "import { withGuard } from './adminSet'",
        'async function audit(tx: any, e: any) { await w(tx, e) }',
        'export async function a() { await auditedTransaction(prisma, async (tx) => { await w(tx, {}); await audit(tx, {}) }) }',
        'export async function b() { await withGuard("x", (tx) => w(tx, {})) }',
        'export async function c() { const write = async (tx: any) => { await createActAsAuditRow(tx, {}) }',
        '  await auditedTransaction(prisma, write); await withGuard("y", async (tx) => write(tx)) }',
        'export async function d() { await w(prisma as unknown as never, {}); await writeAudit({}) }',
      ].join('\n'),
    })
    expect(auditWriteProblems(sources)).toEqual([])
  })

  test('a raw transaction, a helper reached from one, a lost client and a direct insert are reported', () => {
    const sources = world({
      'src/lib/bad.ts': [
        "import prisma from '@/lib/prisma'",
        "import { writeAuditTx } from '@/lib/audit'",
        "import { createAuditLogRow } from '@/lib/auditForward'",
        'export async function raw() { await prisma.$transaction(async (tx: any) => { await writeAuditTx(tx, {}) }) }',
        'export async function helper(tx: any) { await writeAuditTx(tx, {}) }',
        'export async function viaHelper() { await prisma.$transaction(async (tx: any) => helper(tx)) }',
        'export async function lost(ctx: { tx: any }) { await createAuditLogRow(ctx.tx, {}) }',
        'export async function direct(tx: any) { await tx.actAsAudit.create({ data: {} }) }',
        "export async function sql(tx: any) { await tx.$executeRaw`INSERT INTO audit_log (id) VALUES ('x')` }",
      ].join('\n'),
    })
    expect(auditWriteProblems(sources)).toEqual([
      'src/lib/bad.ts inserts into an audit table with raw SQL',
      `src/lib/bad.ts:4 prisma.$transaction(...) ${UNWRAPPED}`,
      `src/lib/bad.ts:6 prisma.$transaction(...) ${UNWRAPPED}`,
      'src/lib/bad.ts:7 createAuditLogRow(...) gets a client the analysis cannot follow (ctx.tx)',
      'src/lib/bad.ts:8 writes actAsAudit directly instead of through lib/auditForward.ts',
    ])
  })

  test('a writer handed to another module that does not forward is followed there', () => {
    const sources = world({
      'src/lib/helper.ts': [
        "import { writeAuditTx } from '@/lib/audit'",
        'export const record = async (tx: any) => { await writeAuditTx(tx, {}) }',
      ].join('\n'),
      'src/app/api/x/route.ts': [
        "import prisma from '@/lib/prisma'",
        "import { record } from '@/lib/helper'",
        'export async function POST() { await prisma.$transaction(record) }',
      ].join('\n'),
    })
    expect(auditWriteProblems(sources)).toEqual([`src/app/api/x/route.ts:3 prisma.$transaction(...) ${UNWRAPPED}`])
  })
})

describe('every webapp audit row is forwarded once it is committed', () => {
  const sources = productionSources()

  test('the writers exist where the analysis looks for them', () => {
    const forward = sources.get(FORWARD_MODULE) ?? ''
    for (const name of [...SINKS, RUNNER]) expect(forward).toMatch(new RegExp(`export async function ${name}\\b`))
    expect(sources.get('src/lib/audit.ts')).toMatch(/createAuditLogRow\(tx, /)
  })

  test('every audit row goes through lib/auditForward.ts, in an auditedTransaction or on the root client', () => {
    expect(auditWriteProblems(sources)).toEqual([])
  })
})
