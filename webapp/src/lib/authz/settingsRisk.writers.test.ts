/**
 * Every writer of the project row asks classifyChange, or is shown not to need it (step 5.1b;
 * SH-08). A new writer fails here until it is placed:
 *   - judged: every write it makes sits in a function that first asks classifyChange (directly,
 *     or through a helper that does: `refuseSettingsChange`, the MCP tools' wrapper, and
 *     `collaboratorRefusal`, the RoE apply's), and the file's own tests prove the refusal stops it;
 *   - ordinary at W: every write it makes names, in a literal `data` object, only columns the
 *     registry calls ordinary, behind a permission at Write or above, so classifyChange could only
 *     agree with the guard; reclassifying one of its columns, or writing another, fails the test
 *     below, and the writer must then be judged;
 *   - owner or system: no collaborator reaches it (the owner's own projects, a creation, a lock, a
 *     maintenance script or a schema migration).
 * A writer is any Prisma `project.update`, `updateMany` or `upsert`, and any raw `UPDATE projects`,
 * in the webapp's code, scripts and migrations; no service outside the webapp writes the row.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs'
import path from 'node:path'
import { classifyField } from './settingsRisk'
import { PERMISSIONS, type PermissionId, type ProjectLevel } from './permissions'

const WEBAPP = path.resolve(__dirname, '../../..')
const REPO = path.resolve(WEBAPP, '..')

const SKIP_DIRS = new Set(['node_modules', '.next', '__testing__', '__fixtures__', '__pycache__', '.venv', 'venv', '.git', 'tests'])

function sources(dir: string, ext: RegExp): string[] {
  const out: string[] = []
  let names: string[]
  try {
    names = readdirSync(dir)
  } catch {
    return out
  }
  for (const name of names) {
    const full = path.join(dir, name)
    let isDir: boolean
    try {
      isDir = statSync(full).isDirectory()
    } catch {
      continue
    }
    if (isDir) {
      if (!SKIP_DIRS.has(name)) out.push(...sources(full, ext))
    } else if (ext.test(name) && !/\.test\.(ts|tsx)$/.test(name) && !/_test\.(py|sh)$/.test(name)) {
      out.push(full)
    }
  }
  return out
}

/** A Prisma write of the project row, on any client (`prisma.`, `tx.`, `db.`). */
const PRISMA_WRITE = /\bproject\.(?:update|updateMany|upsert)\(/g
/** A raw SQL write of the project table. */
const SQL_WRITE = /\bUPDATE\s+"?projects"?\s/gi

const writesProject = (src: string): boolean => new RegExp(PRISMA_WRITE.source).test(src) || new RegExp(SQL_WRITE.source, 'i').test(src)

/** Each judged writer, and the call its writes must follow in the same function. */
const JUDGED: Record<string, string> = {
  'src/app/api/projects/[id]/route.ts': 'classifyChange',
  'src/lib/roe/applyRoe.ts': 'collaboratorRefusal',
  'src/lib/mcp/writeTools.ts': 'refuseSettingsChange',
  'src/lib/mcp/scopeTools.ts': 'refuseSettingsChange',
  'src/lib/mcp/presetTools.ts': 'refuseSettingsChange',
}

/** The helpers a judged writer may call instead, each asking classifyChange itself. */
const JUDGE_HELPERS: Record<string, string> = {
  refuseSettingsChange: 'src/lib/mcp/writeTools.ts',
  collaboratorRefusal: 'src/lib/roe/applyRoe.ts',
}

/** Each upload route: the columns it writes and the permissions it asks before writing them. */
const ORDINARY_AT_W: Record<string, { columns: string[]; permissions: PermissionId[] }> = {
  'src/app/api/js-recon/[projectId]/upload/route.ts': { columns: ['jsReconUploadedFiles'], permissions: ['scan:uploads'] },
  'src/app/api/js-recon/[projectId]/custom-files/route.ts': {
    columns: ['jsReconCustomPatterns', 'jsReconCustomSourcemapPaths', 'jsReconCustomPackages', 'jsReconCustomEndpointKeywords', 'jsReconCustomFrameworks'],
    permissions: ['scan:uploads'],
  },
  'src/app/api/supply-chain/[projectId]/upload/route.ts': { columns: ['supplyChainSbomFile'], permissions: ['scan:supply_chain'] },
}

const OWNER_OR_SYSTEM: Record<string, string> = {
  'src/app/api/projects/route.ts': 'the create: the creator owns the new project',
  'src/app/api/users/[id]/llm-providers/[providerId]/route.ts': "clears a deleted provider from the account's own projects",
  'src/lib/activationLock.ts': 'the version-activation lock columns, written by the activation itself',
  'src/lib/authz/ownershipTransfer.ts':
    "the ownership move (owner's offer at O + recipient's acceptance, both step-up, or Root's forced transfer): the new owner, the lock, and server-computed clears of the old owner's own providers, skills, templates and token, no body value",
  'src/lib/plugins/userSkillAdoption.ts': 'system: a plugin skill adopted into its author\'s own projects',
  'src/lib/plugins/userSkillRevocation.ts': 'system: a revoked skill switched off where it was on',
  'src/lib/reconPresets/badges.ts': "the preset owner's own projects' badge",
  'src/lib/userSkillWrites.ts': "the skill author's own projects (where: {userId})",
  'scripts/backfill-jev-provider-selection.mjs': 'system: a one-time backfill the operator runs at install or update',
  'scripts/backfill-user-skill-toggles.mjs': 'system: a one-time backfill the operator runs at install or update',
  'scripts/clamp-triage-review-budget.mjs': 'system: clamps stored budgets at install or update',
  'scripts/e2e-rbac-seed.mjs': 'system: the live test seed of synthetic fixtures',
  'scripts/migrate-trufflehog-profiles.mjs': 'system: a schema migration run before prisma db push',
  'prisma/migrations/20260219120000_expand_tool_phase_gating/migration.sql': 'system: a schema migration',
  'prisma/migrations/20260221120000_add_hydra_settings/migration.sql': 'system: a schema migration',
  'prisma/migrations/20260221140000_execute_code_informational/migration.sql': 'system: a schema migration',
}

/** The levels at or above Write: a permission at one of them is never a reader's. */
const WRITE_OR_ABOVE: readonly ProjectLevel[] = ['W', 'W+S', 'W+A', 'W+X', 'M', 'O']

/** The text from `open` to its matching close, skipping quoted text; `start` indexes the opener. */
function balanced(src: string, start: number): string {
  const pairs: Record<string, string> = { '(': ')', '{': '}', '[': ']' }
  const stack: string[] = []
  for (let i = start; i < src.length; i++) {
    const c = src[i]
    if (c === "'" || c === '"' || c === '`') {
      for (i++; i < src.length && src[i] !== c; i++) if (src[i] === '\\') i++
      continue
    }
    if (pairs[c]) stack.push(pairs[c])
    else if (c === stack[stack.length - 1]) {
      stack.pop()
      if (stack.length === 0) return src.slice(start, i + 1)
    }
  }
  return src.slice(start)
}

/** The top-level entries of an object literal `{ ... }`, split at depth-0 commas. */
function entriesOf(objectText: string): string[] {
  const body = objectText.slice(1, -1)
  const out: string[] = []
  let depth = 0
  let current = ''
  for (let i = 0; i < body.length; i++) {
    const c = body[i]
    if (c === "'" || c === '"' || c === '`') {
      const end = balancedString(body, i)
      current += body.slice(i, end + 1)
      i = end
      continue
    }
    if ('([{'.includes(c)) depth++
    if (')]}'.includes(c)) depth--
    if (c === ',' && depth === 0) {
      out.push(current.trim())
      current = ''
    } else current += c
  }
  if (current.trim()) out.push(current.trim())
  return out
}

function balancedString(src: string, start: number): number {
  let i = start + 1
  for (; i < src.length && src[i] !== src[start]; i++) if (src[i] === '\\') i++
  return i
}

/** The code without its comments, so a judge named only in prose does not count. */
const code = (src: string): string => src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:'"\w])\/\/.*$/gm, '$1')

/** Where each Prisma write starts in `src`, and the whole call. */
function prismaWrites(src: string): Array<{ index: number; call: string }> {
  return [...src.matchAll(PRISMA_WRITE)].map(m => ({ index: m.index!, call: balanced(src, m.index! + m[0].length - 1) }))
}

/** The top-level function a position sits in: its name and where it starts. */
function enclosingFunction(src: string, index: number): { name: string; start: number } | null {
  let found: { name: string; start: number } | null = null
  for (const m of src.matchAll(/^(?:export\s+)?(?:async\s+)?function\s+(\w+)/gm)) {
    if (m.index! > index) break
    found = { name: m[1], start: m.index! }
  }
  return found
}

/** The body of the top-level function `name` defined in `src`. */
function functionBody(src: string, name: string): string {
  const m = new RegExp(`^(?:export\\s+)?(?:async\\s+)?function\\s+${name}\\s*\\(`, 'm').exec(src)
  if (!m) return ''
  const open = src.indexOf('{', src.indexOf(')', m.index + m[0].length - 1))
  return balanced(src, open)
}

/**
 * The columns one write's `data` names: plain keys as written; a computed `[x]` key resolved through
 * the file's `const x = MAP[...]` and every value of MAP's object literal. Null for anything this
 * reading cannot pin down (a `data` that is not a literal, a spread, an unresolvable key).
 */
function writtenColumns(src: string, call: string): string[] | null {
  const at = call.search(/\bdata\s*:/)
  if (at < 0) return null
  const open = call.indexOf('{', at)
  if (open < 0 || call.slice(call.indexOf(':', at) + 1, open).trim() !== '') return null
  const columns: string[] = []
  for (const entry of entriesOf(balanced(call, open))) {
    if (entry.startsWith('...')) return null
    const computed = entry.match(/^\[\s*(\w+)\s*\]\s*:/)
    if (computed) {
      const mapName = src.match(new RegExp(`\\bconst\\s+${computed[1]}\\s*=\\s*(\\w+)\\[`))?.[1]
      const mapAt = mapName ? src.search(new RegExp(`\\bconst\\s+${mapName}\\b[^=]*=\\s*\\{`)) : -1
      if (mapAt < 0) return null
      const values = entriesOf(balanced(src, src.indexOf('{', mapAt))).map(e => e.match(/:\s*'([A-Za-z]+)'$/)?.[1])
      if (values.some(v => !v)) return null
      columns.push(...(values as string[]))
      continue
    }
    const key = entry.match(/^['"]?(\w+)['"]?\s*(?::|$)/)?.[1]
    if (!key) return null
    columns.push(key)
  }
  return columns
}

describe('every writer of the project row is placed (step 5.1b)', () => {
  const ext = /\.(ts|tsx|js|mjs|cjs|sql)$/
  const writers = ['src', 'scripts', 'prisma'].flatMap(d => sources(path.join(WEBAPP, d), ext))
    .filter(f => writesProject(readFileSync(f, 'utf8')))
    .map(f => path.relative(WEBAPP, f))
    .sort()

  test('the writers found are exactly the placed ones', () => {
    expect(writers).toEqual([...Object.keys(JUDGED), ...Object.keys(ORDINARY_AT_W), ...Object.keys(OWNER_OR_SYSTEM)].sort())
  })

  test.each(Object.entries(JUDGED))('%s asks %s before every write, in the same function', (file, judge) => {
    const src = code(readFileSync(path.join(WEBAPP, file), 'utf8'))
    const writes = prismaWrites(src)
    expect(writes.length).toBeGreaterThan(0)
    expect(new RegExp(SQL_WRITE.source, 'i').test(src), 'a raw UPDATE is not judged').toBe(false)
    for (const { index } of writes) {
      const fn = enclosingFunction(src, index)
      const line = src.slice(0, index).split('\n').length
      expect(fn, `${file}:${line}`).not.toBeNull()
      const before = src.slice(fn!.start, index)
      expect(before, `${file}:${line} (in ${fn!.name}) writes the row without asking ${judge}`).toMatch(new RegExp(`(?<!function\\s)\\b${judge}\\(`))
    }
  })

  test.each(Object.entries(JUDGE_HELPERS))('the helper %s asks classifyChange itself', (helper, file) => {
    expect(functionBody(code(readFileSync(path.join(WEBAPP, file), 'utf8')), helper)).toMatch(/\bclassifyChange\(/)
  })

  test.each(Object.entries(ORDINARY_AT_W))('%s writes only its ordinary columns, behind a Write permission', (file, { columns, permissions }) => {
    const src = readFileSync(path.join(WEBAPP, file), 'utf8')
    expect(new RegExp(SQL_WRITE.source, 'i').test(src), 'a raw UPDATE cannot be read').toBe(false)
    const writes = prismaWrites(src)
    expect(writes.length).toBeGreaterThan(0)
    for (const { call } of writes) {
      const written = writtenColumns(src, call)
      expect(written, `a write whose columns cannot be read: ${call.slice(0, 120)}`).not.toBeNull()
      expect(written!.filter(k => !columns.includes(k)), call.slice(0, 120)).toEqual([])
    }
    for (const key of columns) expect(classifyField(key, 'before', 'after').needs, key).toBe('write')
    for (const p of permissions) {
      expect(src, p).toContain(`'${p}'`)
      expect(WRITE_OR_ABOVE, p).toContain(PERMISSIONS[p].level)
    }
  })
})

describe('the inventory reads what it claims to (step 5.1 review)', () => {
  test('an upsert, a raw UPDATE and a computed column are seen', () => {
    expect(writesProject('await tx.project.upsert({ where, create, update })')).toBe(true)
    expect(writesProject('await prisma.$executeRawUnsafe(`UPDATE "projects" SET x = 1`)')).toBe(true)
    expect(writesProject('await prisma.project.findUnique({ where })')).toBe(false)
    const src = "const MAP: Record<string, string> = {\n  a: 'colA',\n  b: 'colB',\n}\nconst field = MAP[kind]\n"
    expect(writtenColumns(src, "update({ where: { id }, data: { [field]: path } })")).toEqual(['colA', 'colB'])
    expect(writtenColumns(src, 'update({ where: { id }, data: { ...body } })')).toBeNull()
    expect(writtenColumns(src, 'update({ where: { id }, data: payload })')).toBeNull()
    expect(writtenColumns(src, "update({ where: { id }, data: { colA: '', updatedById: user } })")).toEqual(['colA', 'updatedById'])
  })

  test('a judge named only in a comment, or after the write, or in another function, does not count', () => {
    const src = code([
      '// classifyChange( is asked elsewhere',
      'export async function other() { classifyChange(a, b, c) }',
      'export async function write() {',
      '  /* classifyChange(a, b, c) */ // classifyChange(a, b, c)',
      '  await prisma.project.update({ data: {} })',
      '  classifyChange(a, b, c)',
      '}',
    ].join('\n'))
    const { index } = prismaWrites(src)[0]
    const fn = enclosingFunction(src, index)!
    expect(fn.name).toBe('write')
    expect(src.slice(fn.start, index)).not.toMatch(/\bclassifyChange\(/)
    // A URL in the code is not a comment.
    expect(code("const u = 'http://x' // note")).toBe("const u = 'http://x' ")
  })
})

// Python, shell or SQL in the other services would bypass every check above.
describe.skipIf(!existsSync(path.join(REPO, 'agentic')))('no service outside the webapp writes the project row', () => {
  test('agent, recon, orchestrator, graph, MCP, services, scanners and tooling hold no project write', () => {
    const dirs = ['agentic', 'recon', 'recon_orchestrator', 'graph_db', 'mcp', 'services', 'scanners', 'tooling']
    const found = dirs.flatMap(d => sources(path.join(REPO, d), /\.(py|sh|sql|js|mjs|ts)$/))
      .filter(f => writesProject(readFileSync(f, 'utf8')))
      .map(f => path.relative(REPO, f))
    expect(found).toEqual([])
  })
})
