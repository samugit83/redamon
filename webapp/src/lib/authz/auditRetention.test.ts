/**
 * Audit retention (step 6.6; AU-04, OQ-31, OQ-40): the sweep part deletes the audit_log rows older than
 * the retention in force, never one the code reads back, never below the floor, and in batches that
 * several webapp copies may run at once.
 *
 * - `every audit row the code reads back is kept`: a static read of every audit_log reader in src/ and
 *   scripts/ (each `auditLog.find*`, `count`, `aggregate`, `groupBy` call and each raw `FROM audit_log`),
 *   with the actions it names resolved through their constants. A reader whose actions no
 *   KEPT_AUDIT_RULES rule keeps fails, unless it is a display reader listed in DISPLAY_READERS with
 *   why losing its old rows changes no behaviour;
 * - the runtime tests run the real part (lib/authz/auditRetention.ts) on an in-memory Prisma that
 *   evaluates each `where` (__testing__/auditRowsDb.ts).
 *
 * Run: npx vitest run --no-file-parallelism src/lib/authz/auditRetention.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import path from 'node:path'
import { auditRowsDb, emptyAuditRowsState, type AuditRowsState, type Row } from './__testing__/auditRowsDb'

const h = vi.hoisted(() => ({ db: null as unknown as Record<string, unknown>, devices: vi.fn(async () => 0) }))
vi.mock('@/lib/prisma', () => {
  const client = new Proxy({}, { get: (_t, name) => (h.db as Record<string | symbol, unknown>)[name] })
  return { default: client, prisma: client }
})
vi.mock('./deviceSessions', () => ({ sweepDeviceSessions: h.devices }))

import {
  AUDIT_RETENTION_MIN_DAYS, KEPT_AUDIT_RULES, RETENTION_BATCH, RETENTION_MAX_BATCHES, keptRuleFor, sweepAuditRetention,
} from './auditRetention'
import { LEGACY_KEEP_DAYS } from './legacyOverrides'
import { setFlagsForTests } from './flags'
import { setNowForTests } from './clock'
import { sweepExpired } from './expirySweep'
import { KEEP_DAYS as BACKFILL_KEEP_DAYS } from '../../../scripts/backfill-rbac-legacy-overrides.mjs'

const WEBAPP = path.resolve(__dirname, '../../..')
const DAY = 86_400_000
const NOW = new Date('2026-11-13T12:00:00.000Z')
const daysAgo = (d: number) => new Date(NOW.getTime() - d * DAY)

// ---------------------------------------------------------------------------------------------------
// The static read of the audit_log readers.

function productionFiles(): string[] {
  const out: string[] = []
  const walk = (dir: string): void => {
    for (const name of readdirSync(dir)) {
      const full = path.join(dir, name)
      if (statSync(full).isDirectory()) {
        if (name !== 'node_modules' && name !== '__testing__' && name !== '__fixtures__') walk(full)
      } else if (/\.(ts|tsx|mjs|js)$/.test(name) && !/\.(test|spec)\.(ts|tsx|mjs|js)$/.test(name)) {
        out.push(full)
      }
    }
  }
  walk(path.join(WEBAPP, 'src'))
  walk(path.join(WEBAPP, 'scripts'))
  return out
}

const ACTION_SHAPE = /^[a-z][a-z0-9_-]*(\.[a-z0-9_-]+)+$/
const CONSTANT = /^[A-Z][A-Z0-9_]*(ACTION|MARKER)S?$/
const CONST_DECL = /(?:export\s+)?const\s+([A-Z][A-Z0-9_]*)(?:\s*:\s*[^=\n]+)?\s*=\s*['"]([^'"\n]+)['"]/g

/** The text from `open` (an opening parenthesis) to its matching close, strings skipped. */
function balanced(src: string, open: number): string {
  let depth = 0
  let quote: string | null = null
  for (let i = open; i < src.length; i++) {
    const c = src[i]
    if (quote) {
      if (c === '\\') i++
      else if (c === quote) quote = null
      continue
    }
    if (c === "'" || c === '"' || c === '`') quote = c
    else if (c === '(') depth++
    else if (c === ')' && --depth === 0) return src.slice(open + 1, i)
  }
  return src.slice(open + 1)
}

interface ReaderSite { file: string; line: number; arg: string }

function readerSites(files: Array<{ file: string; source: string }>): ReaderSite[] {
  const sites: ReaderSite[] = []
  const CALL = /\bauditLog\s*\.\s*(findFirst|findFirstOrThrow|findMany|findUnique|findUniqueOrThrow|count|aggregate|groupBy)\s*\(/g
  const RAW = /\$queryRaw(?:Unsafe)?\s*[(`]/g
  for (const { file, source } of files) {
    for (const m of source.matchAll(CALL)) {
      const open = m.index! + m[0].length - 1
      sites.push({ file, line: source.slice(0, m.index).split('\n').length, arg: balanced(source, open) })
    }
    for (const m of source.matchAll(RAW)) {
      const opener = m[0].at(-1)
      const arg = opener === '(' ? balanced(source, m.index! + m[0].length - 1) : source.slice(m.index!, source.indexOf('`', m.index! + m[0].length) + 1)
      if (/\bfrom\s+"?audit_log\b/i.test(arg)) sites.push({ file, line: source.slice(0, m.index).split('\n').length, arg })
    }
  }
  return sites
}

/** The values each constant name has, per file and across the tree (one name can have several). */
function constants(files: Array<{ file: string; source: string }>) {
  const local = new Map<string, Map<string, string>>()
  const global = new Map<string, Set<string>>()
  for (const { file, source } of files) {
    const mine = new Map<string, string>()
    for (const m of source.matchAll(CONST_DECL)) {
      mine.set(m[1], m[2])
      if (!global.has(m[1])) global.set(m[1], new Set())
      global.get(m[1])!.add(m[2])
    }
    local.set(file, mine)
  }
  /** A name's values in a file: its own constant, else the name it imports under this alias, else the tree's. */
  return (file: string, source: string, name: string): string[] | null => {
    const own = local.get(file)?.get(name)
    if (own) return [own]
    const alias = source.match(new RegExp(`\\b([A-Z][A-Z0-9_]*)\\s*(?:as|:)\\s*${name}\\b`))?.[1]
    const values = global.get(alias ?? name)
    return values ? [...values] : null
  }
}

/** The actions a reader asks: string literals in its `action` clauses and the constants it names. */
function actionsOf(site: ReaderSite, source: string, resolve: ReturnType<typeof constants>): { actions: string[]; unresolved: string[] } {
  const actions = new Set<string>()
  const unresolved: string[] = []
  for (const m of site.arg.matchAll(/\baction\s*:\s*(\{[^}]*\}|'[^']*'|"[^"]*"|[A-Za-z_][\w.]*)/g)) {
    for (const lit of m[1].matchAll(/['"]([^'"]+)['"]/g)) if (ACTION_SHAPE.test(lit[1])) actions.add(lit[1])
  }
  for (const m of site.arg.matchAll(/\b[A-Z][A-Z0-9_]*\b/g)) {
    if (!CONSTANT.test(m[0])) continue
    const values = resolve(site.file, source, m[0])
    if (values) values.forEach((v) => actions.add(v))
    else unresolved.push(m[0])
  }
  return { actions: [...actions].sort(), unresolved }
}

/**
 * Readers whose old rows may go: each reads to show a history (or is the retention or test tooling
 * itself), so a row deleted by retention only shortens what it shows. File: why.
 */
const DISPLAY_READERS: Readonly<Record<string, string>> = {
  'src/lib/authz/auditReader.ts': 'the admin console: one account\'s latest rows and the audit viewer and export (step 6.6)',
  'src/lib/authz/projectActivity.ts': 'the project activity feed (step 4.13): a project\'s rows, newest first',
  'src/lib/authz/accountActivity.ts': "My account's activity list: the person's own recent events",
  'src/lib/authz/auditRetention.ts': 'the retention sweep\'s own read of the rows it deletes',
  'scripts/e2e-rbac-cleanup.mjs': 'test tooling: removes the e2e accounts\' rows after a live run',
  // Readers of steps still in flight when this list was written (step 6.6); each entry applies once its
  // file exists.
  'src/lib/authz/oversight.ts': "step 4.14's one row per admin, project and day: it reads only today's rows",
  'src/lib/authz/adminProjects.ts': "step 6.4's projects overview: each project's latest activity, shown",
}

describe('every audit row the code reads back is kept', () => {
  const files = productionFiles().map((file) => ({ file, source: readFileSync(file, 'utf8') }))
  const sources = new Map(files.map((f) => [f.file, f.source]))
  const resolve = constants(files)
  const sites = readerSites(files)

  test('the reader finds the readers it must (a guard against a scan that finds nothing)', () => {
    const found = new Set(sites.map((s) => path.relative(WEBAPP, s.file)))
    for (const f of ['src/lib/authz/legacyOverrides.ts', 'src/lib/authz/sharedTools.ts', 'src/app/api/auth/me/route.ts',
      'src/lib/authz/updateReview.ts', 'scripts/backfill-rbac-legacy-overrides.mjs', 'scripts/rbac-upgrade-preview.mjs']) {
      expect(found.has(f), f).toBe(true)
    }
  })

  test('each reader asks only actions a rule keeps, or is a listed display reader', () => {
    const problems: string[] = []
    const displaySeen = new Set<string>()
    for (const site of sites) {
      const rel = path.relative(WEBAPP, site.file)
      const { actions, unresolved } = actionsOf(site, sources.get(site.file)!, resolve)
      const notKept = actions.filter((a) => !keptRuleFor(a))
      if (!notKept.length && !unresolved.length && actions.length) continue
      if (rel in DISPLAY_READERS) {
        displaySeen.add(rel)
        continue
      }
      problems.push(`${rel}:${site.line} reads ${[...notKept, ...unresolved].join(', ') || 'rows by something other than their action'}`)
    }
    expect(problems, 'keep its rows in KEPT_AUDIT_RULES (auditRetention.ts), or list it in DISPLAY_READERS with why').toEqual([])
    const present = (f: string) => { try { return statSync(path.join(WEBAPP, f)).isFile() } catch { return false } }
    expect(Object.keys(DISPLAY_READERS).filter((f) => present(f) && !displaySeen.has(f)), 'a DISPLAY_READERS entry no reader needs').toEqual([])
  })

  test('the markers and decisions the plan names are kept, with the scope the conversion reads', () => {
    for (const a of [
      'system.rbac_root_assigned', 'system.rbac_legacy_grants_cutoff', 'system.rbac_legacy_grants_backfill',
      'system.rbac_legacy_overrides_backfill', 'system.rbac_instance_settings_backfill', 'system.user_skill_toggles_backfill',
      'system.user_skill_toggles_cutoff', 'system.jev_provider_selection_backfill', 'system.nuclei_template_owners_backfill',
      'rbac.legacy_grant.keep', 'rbac.legacy_grant.remove', 'rbac.whats_new_dismissed',
    ]) expect(keptRuleFor(a)?.scope, a).toBeUndefined()
    expect(keptRuleFor('user.permissions_changed')?.scope).toBe('legacy_grant_holders')
    for (const a of ['auth.login.success', 'user.update', 'audit.exported', 'project.share.grant']) expect(keptRuleFor(a), a).toBeNull()
    expect(KEPT_AUDIT_RULES.every((r) => r.why.length > 10)).toBe(true)
  })

  test('the floor covers the legacy keep window: a person\'s change older than the floor can no longer decide a conversion', () => {
    // A user.permissions_changed row matters only while the Keep it supersedes is inside its window
    // (LEGACY_KEEP_DAYS from the conversion or a later Keep), and such a row is never older than the
    // conversion; deleting rows older than the floor is safe while the floor is at least the window.
    // The scoped rule keeps the rows about legacy holders anyway; this pins the reasoning.
    expect(LEGACY_KEEP_DAYS).toBe(BACKFILL_KEEP_DAYS)
    expect(AUDIT_RETENTION_MIN_DAYS).toBeGreaterThanOrEqual(LEGACY_KEEP_DAYS)
  })
})

// ---------------------------------------------------------------------------------------------------
// The sweep part.

let state: AuditRowsState
let seq = 0
const row = (action: string, createdAt: Date, over: Row = {}): Row => {
  seq += 1
  return { id: `r-${String(seq).padStart(6, '0')}`, action, createdAt, actorId: 'adm-a', actorEmail: 'ada@e2e.local', targetType: 'user', targetId: null, ...over }
}
const ids = () => state.audit.map((r) => r.id).sort()

beforeEach(() => {
  seq = 0
  state = emptyAuditRowsState()
  state.instance = { id: 'instance', auditRetentionDays: 120 }
  state.users = [
    { id: 'legacy-1', legacyGrants: ['tunnels'] },
    { id: 'plain-1', legacyGrants: [] },
  ]
  h.db = auditRowsDb(state, () => NOW) as unknown as Record<string, unknown>
  setFlagsForTests({ identity: true, permissions: true, governance: true })
})
afterEach(() => {
  setFlagsForTests(null)
  vi.restoreAllMocks()
})

describe('sweep deletes only older rows', () => {
  test('rows older than the retention go; a row at the cut-off and newer ones stay', async () => {
    state.audit = [
      row('user.update', daysAgo(400), { id: 'old-1' }),
      row('auth.login.success', daysAgo(121), { id: 'old-2' }),
      row('project.share.grant', new Date(daysAgo(120).getTime() - 1), { id: 'old-3' }),
      row('user.update', daysAgo(120), { id: 'edge' }),
      row('user.update', daysAgo(5), { id: 'new-1' }),
    ]
    expect(await sweepAuditRetention(NOW)).toEqual({ days: 120, deleted: 3 })
    expect(ids()).toEqual(['edge', 'new-1'])
  })

  test('a marker, a cut-off and the decisions older than the retention survive; so do the act-as and Fireteam rows', async () => {
    state.audit = [
      row('system.rbac_legacy_overrides_backfill', daysAgo(900), { id: 'marker', actorId: null, targetType: 'system' }),
      row('system.rbac_legacy_grants_cutoff', daysAgo(900), { id: 'cutoff', actorId: null, targetType: 'system' }),
      row('system.rbac_root_assigned', daysAgo(700), { id: 'root', targetId: 'root-1' }),
      row('rbac.legacy_grant.keep', daysAgo(800), { id: 'keep', targetId: 'legacy-1' }),
      row('rbac.legacy_grant.remove', daysAgo(800), { id: 'remove', targetId: 'plain-1' }),
      row('rbac.whats_new_dismissed', daysAgo(800), { id: 'dismissed', targetType: 'notice' }),
      row('user.permissions_changed', daysAgo(800), { id: 'changed-legacy', targetId: 'legacy-1' }),
      row('user.permissions_changed', daysAgo(800), { id: 'changed-plain', targetId: 'plain-1' }),
      row('user.update', daysAgo(800), { id: 'plain-old' }),
    ]
    state.actAs = [{ id: 'x1', createdAt: daysAgo(900) }]
    state.fireteam = [{ id: 'f1', createdAt: daysAgo(900) }]
    expect(await sweepAuditRetention(NOW)).toEqual({ days: 120, deleted: 2 })
    expect(ids()).toEqual(['changed-legacy', 'cutoff', 'dismissed', 'keep', 'marker', 'remove', 'root'])
    expect(state.actAs).toHaveLength(1)
    expect(state.fireteam).toHaveLength(1)
    expect(state.calls.filter((c) => c.startsWith('actAsAudit') || c.startsWith('fireteamSettingsAudit'))).toEqual([])
  })

  test('with no legacy holder, no permission change is kept for that reason', async () => {
    state.users = []
    state.audit = [row('user.permissions_changed', daysAgo(800), { targetId: 'legacy-1' })]
    expect((await sweepAuditRetention(NOW)).deleted).toBe(1)
  })

  test('with RBAC_GOVERNANCE_ENABLED off nothing is read or deleted, whatever retention Root set while it was on', async () => {
    state.audit = [row('user.update', daysAgo(5000))]
    for (const flags of [{}, { identity: true, permissions: true }]) {
      setFlagsForTests(flags)
      expect(await sweepAuditRetention(NOW)).toEqual({ days: null, deleted: 0 })
    }
    expect(state.audit).toHaveLength(1)
    expect(state.calls).toEqual([])
  })

  test('null keeps every row and reads no audit row', async () => {
    state.instance = { id: 'instance', auditRetentionDays: null }
    state.audit = [row('user.update', daysAgo(5000))]
    expect(await sweepAuditRetention(NOW)).toEqual({ days: null, deleted: 0 })
    expect(state.audit).toHaveLength(1)
    expect(state.calls.filter((c) => c.startsWith('auditLog'))).toEqual([])
  })

  test('no instance row (the boot backfill has not run): every row is kept', async () => {
    state.instance = null
    state.audit = [row('user.update', daysAgo(5000))]
    expect(await sweepAuditRetention(NOW)).toEqual({ days: null, deleted: 0 })
  })

  test('retention floor: a stored value under it (written around the API) deletes as the floor does, and says so', async () => {
    const err = vi.spyOn(console, 'error').mockImplementation(() => {})
    state.instance = { id: 'instance', auditRetentionDays: 30 }
    state.audit = [row('user.update', daysAgo(31), { id: 'a' }), row('user.update', daysAgo(89), { id: 'b' }), row('user.update', daysAgo(91), { id: 'c' })]
    expect(await sweepAuditRetention(NOW)).toEqual({ days: AUDIT_RETENTION_MIN_DAYS, deleted: 1 })
    expect(ids()).toEqual(['a', 'b'])
    expect(err.mock.calls.map((c) => String(c[0]))).toEqual([expect.stringContaining('[rbac] audit retention 30 is below the floor')])
  })

  test('a backlog is deleted in batches, at most RETENTION_MAX_BATCHES a sweep; the next sweep goes on', async () => {
    const backlog = RETENTION_BATCH * RETENTION_MAX_BATCHES + 1_500
    state.audit = Array.from({ length: backlog }, () => row('user.update', daysAgo(200)))
    state.audit.push(row('system.rbac_root_assigned', daysAgo(200), { id: 'kept' }), row('user.update', daysAgo(1), { id: 'fresh' }))
    expect((await sweepAuditRetention(NOW)).deleted).toBe(RETENTION_BATCH * RETENTION_MAX_BATCHES)
    expect(state.calls.filter((c) => c === 'auditLog.deleteMany')).toHaveLength(RETENTION_MAX_BATCHES)
    expect((await sweepAuditRetention(NOW)).deleted).toBe(1_500)
    expect(ids()).toEqual(['fresh', 'kept'])
  })

  test('two copies sweeping at once delete each old row once and nothing else', async () => {
    state.audit = Array.from({ length: 2_400 }, (_, i) => row(i % 3 ? 'user.update' : 'system.user_skill_toggles_backfill', daysAgo(300)))
    state.audit.push(row('user.update', daysAgo(10), { id: 'fresh' }))
    const kept = state.audit.filter((r) => String(r.action).startsWith('system.')).length
    const [a, b] = await Promise.all([sweepAuditRetention(NOW), sweepAuditRetention(NOW)])
    expect(a.deleted + b.deleted).toBe(1_600)
    expect(state.audit).toHaveLength(kept + 1)
  })

  test('a failed delete throws, so the sweep records the part as failed and retries it', async () => {
    state.audit = [row('user.update', daysAgo(300))]
    ;(h.db.auditLog as Record<string, unknown>).deleteMany = async () => { throw Object.assign(new Error('lost'), { code: 'P1001' }) }
    await expect(sweepAuditRetention(NOW)).rejects.toMatchObject({ code: 'P1001' })
  })
})

describe('the expiry sweep runs the part (lib/authz/expirySweep.ts)', () => {
  beforeEach(() => {
    setNowForTests(() => NOW)
    // The parts the identity and permissions switches run, with nothing to remove.
    Object.assign(h.db, {
      userInvite: { deleteMany: async () => ({ count: 0 }) },
      userPermissionOverride: { findMany: async () => [] },
    })
    vi.spyOn(console, 'info').mockImplementation(() => {})
  })
  afterEach(() => setNowForTests(null))

  test('governance on: the old rows go and the answer says how many, with the days applied', async () => {
    state.audit = [row('user.update', daysAgo(200), { id: 'old' }), row('system.rbac_root_assigned', daysAgo(900), { id: 'kept' })]
    const result = await sweepExpired()
    expect(result.auditRetention).toEqual({ days: 120, deleted: 1 })
    expect(result.failed).toEqual([])
    expect(ids()).toEqual(['kept'])
    expect(vi.mocked(console.info).mock.calls.map((c) => String(c[0]))).toEqual([expect.stringContaining('audit_rows=1 (retention 120 days)')])
  })

  test('governance off: no auditRetention key, nothing of it read', async () => {
    setFlagsForTests({ identity: true, permissions: true })
    state.audit = [row('user.update', daysAgo(2000))]
    const result = await sweepExpired()
    expect('auditRetention' in result).toBe(false)
    expect(state.audit).toHaveLength(1)
    expect(state.calls.filter((c) => c.startsWith('auditLog') || c.startsWith('instanceSettings'))).toEqual([])
  })

  test('a failed retention part is reported (the route answers sweep_incomplete) and the other parts stand', async () => {
    const err = vi.spyOn(console, 'error').mockImplementation(() => {})
    h.devices.mockResolvedValueOnce(2)
    state.audit = [row('user.update', daysAgo(300))]
    ;(h.db.auditLog as Record<string, unknown>).findMany = async () => { throw Object.assign(new Error('lost'), { code: 'P1001' }) }
    const result = await sweepExpired()
    expect(result.failed).toEqual(['auditRetention'])
    expect(result.auditRetention).toBeNull()
    expect(result.removed).toMatchObject({ devices: 2, overrides: 0, links: 0 })
    expect(err.mock.calls.map((c) => String(c[0]))).toEqual(['[rbac] sweep failed part=auditRetention:'])
  })
})
