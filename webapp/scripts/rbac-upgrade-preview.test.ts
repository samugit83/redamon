/**
 * The upgrade preview (scripts/rbac-upgrade-preview.mjs, HD-31, DV-32): what the RBAC
 * hardening changes for the accounts of an install, printed by `./redamon.sh update`
 * between the build and the restart. It reads the live database in one read-only
 * transaction, works on the 7.7.x schema (no `users.legacy_grants`), and lists the legacy
 * grants exactly as scripts/backfill-rbac-legacy-grants.mjs will write them.
 *
 * Its `--downgrade` report (UP-05, step 7.2) reads the new schema before a downgrade to
 * 7.7.2: every table and column that release's `db push --accept-data-loss` drops, with its
 * rows, the accounts whose rights go back to their account type's, and the projects on an
 * `instance/` model.
 *
 * The SQL runs against a fake transaction here (which refuses any statement naming a
 * column the schema lacks); scripts/rbac-upgrade-preview.pg.integration.test.ts runs it on
 * a real Postgres.
 *
 * @vitest-environment node
 */
import { spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { describe, test, expect, beforeEach, afterEach } from 'vitest'
import { createFakePrisma, type FakePrisma } from '@/lib/plugins/__testing__/fakePrisma'
import { setNowForTests } from '@/lib/plugins/clock'
import {
  CUTOFF_ACTION, MARKER_ACTION, REMOVE_ACTION, backfillRbacLegacyGrants,
} from './backfill-rbac-legacy-grants.mjs'
import { CANDIDATE_ORDER, CANDIDATE_WHERE, chooseRoot } from './backfill-rbac-root.mjs'
import {
  CAPTURE_ROW_ORDER, MARKER_ACTION as INSTANCE_MARKER_ACTION, deriveInstanceValues,
} from './backfill-rbac-instance-settings.mjs'
import {
  MEMBER_CHANGES, NEW_COLUMNS, NOTHING_CHANGES_EXIT, READ_ONLY_SQL, REVIEW_EXIT, SECTIONS,
  buildReport, previewRbacUpgrade, readUpgradeState,
  BUILTIN_SET_NAMES, DOWNGRADE_COLUMNS, DOWNGRADE_SECTIONS, DOWNGRADE_TABLES, DOWNGRADE_TARGET, FULL_ADMIN_PROFILE,
  INSTANCE_MODEL_COLUMNS, INSTANCE_MODEL_PRESET_KEYS, SETS_EQUAL_TO_DEFAULT_MEMBER, USAGE_EXIT,
  buildDowngradeReport, instanceModelResetSql, parseMode, previewRbacDowngrade, readDowngradeState,
} from './rbac-upgrade-preview.mjs'
import { parsePrismaModels, baseType } from '@/lib/authz/__testing__/prismaSchema'
import release772 from '@/lib/authz/__fixtures__/schema-7.7.2-fields.json'
import permissionCatalog from '@/lib/authz/permissionCatalog.json'

type Row = Record<string, unknown>

const T0 = Date.parse('2026-11-11T08:00:00.000Z')
const BEFORE = new Date(T0 - 86_400_000)
const UPDATED = new Date('2026-03-01T09:00:00.000Z')
const PW = '$2a$12$hash'
const SECRET_NGROK = 'fake-ngrok-secret-0001'
const SECRET_BEARER = 'fake-bearer-secret-0001'
const SCANNER_SET = { SCANNER_API_KEY: 'a'.repeat(64) }

let db: FakePrisma
let t = T0
// The instance settings row (step 2.1's table; the fake Prisma has no such model).
let instanceRow: { rootUserId?: string | null; rootConfirmedAt?: Date | null; adminSaved?: boolean } | null = null

beforeEach(() => {
  db = createFakePrisma()
  t = T0
  instanceRow = null
  setNowForTests(() => new Date(t))
})
afterEach(() => setNowForTests(null))

function user(id: string, opts: { role?: string; password?: string; createdAt?: Date; legacyGrants?: string[]; email?: string } = {}) {
  db.seed('user', [{
    id, name: id, email: opts.email ?? `${id}@e2e.local`, role: opts.role ?? 'standard', password: opts.password ?? PW,
    createdAt: opts.createdAt ?? BEFORE, updatedAt: UPDATED, legacyGrants: opts.legacyGrants ?? [],
  }])
}

function settings(userId: string, s: Row = {}) {
  db.seed('userSettings', [{
    id: `s-${userId}`, userId, tunnelsEnabled: false, ngrokAuthtoken: '', chiselServerUrl: '', chiselAuth: '',
    mcpServers: [], updatedAt: UPDATED, ...s,
  }])
}

const stdio = (id: string, extra: Row = {}) => ({ id, name: id, transport: 'stdio', command: 'true', env: { K: 'fake-env-secret' }, ...extra })
const http = (id: string, auth?: Row) => ({ id, name: id, transport: 'sse', url: 'https://mcp.example.invalid/sse', ...(auth ? { auth } : {}) })

/**
 * A transaction over the fake's rows, answering the preview's SQL with the rows the SQL
 * selects. A statement naming a column the schema lacks fails as Postgres would.
 */
function sqlDb(opts: { legacyColumn?: boolean; instanceTable?: boolean } = {}) {
  const legacyColumn = opts.legacyColumn ?? true
  const instanceTable = opts.instanceTable ?? true
  const calls: string[] = []
  let transactions = 0
  const answer = (sql: string, params: unknown[]): Row[] => {
    if (!legacyColumn && /legacy_grants/.test(sql)) throw new Error('column "legacy_grants" does not exist')
    if (/^\s*SELECT now\(\)/i.test(sql)) return [{ now: new Date(t) }]
    if (/information_schema\.columns/.test(sql)) {
      return NEW_COLUMNS
        .filter((c: { table: string; column: string }) => legacyColumn || `${c.table}.${c.column}` !== 'users.legacy_grants')
        .filter((c: { table: string }) => instanceTable || c.table !== 'instance_settings')
        .filter((c: { table: string; column: string }) => params.includes(`${c.table}.${c.column}`))
        .map((c: { table: string; column: string }) => ({ table_name: c.table, column_name: c.column }))
    }
    if (/\binstance_settings\b/.test(sql)) {
      if (!instanceTable) throw new Error('relation "instance_settings" does not exist')
      if (!/FROM instance_settings WHERE id = \$1/.test(sql) || params[0] !== 'instance') throw new Error(`unexpected SQL: ${sql}`)
      return instanceRow ? [{
        root_user_id: instanceRow.rootUserId ?? null,
        root_confirmed_at: instanceRow.rootConfirmedAt ?? null,
        admin_saved: instanceRow.adminSaved === true,
      }] : []
    }
    if (/jsonb_array_elements/.test(sql)) {
      return db.rows('userSettings').flatMap((s) => ((s.mcpServers as Row[]) ?? []).map((srv) => {
        const auth = (srv.auth ?? {}) as Row
        return {
          user_id: s.userId, server_id: srv.id, name: srv.name, transport: srv.transport,
          enabled: srv.enabled !== false, token_env_var: auth.token_env_var ?? '', has_token: Boolean(auth.token),
        }
      }))
    }
    if (/FROM user_settings/.test(sql)) {
      return db.rows('userSettings').map((s) => ({
        id: s.id, user_id: s.userId, tunnels_enabled: s.tunnelsEnabled, has_ngrok: s.ngrokAuthtoken !== '',
        has_chisel_url: s.chiselServerUrl !== '', updated_at: s.updatedAt,
      }))
    }
    if (/FROM users/.test(sql)) {
      return db.rows('user').map((u) => ({
        id: u.id, email: u.email, role: u.role, has_password: u.password !== '', created_at: u.createdAt,
        ...(legacyColumn ? { legacy_grants: u.legacyGrants } : {}),
      }))
    }
    if (/FROM audit_log/.test(sql)) {
      return db.rows('auditLog')
        .filter((r) => params.includes(r.action))
        .map((r) => ({ action: r.action, target_id: r.targetId ?? null, after: r.after ?? null, created_at: r.createdAt }))
    }
    throw new Error(`unexpected SQL: ${sql}`)
  }
  const tx = {
    $executeRawUnsafe: async (sql: string) => { calls.push(sql); return 0 },
    $queryRawUnsafe: async (sql: string, ...params: unknown[]) => { calls.push(sql); return answer(sql, params) },
  }
  const prisma = {
    $transaction: async (fn: (t: typeof tx) => Promise<unknown>) => {
      transactions++
      calls.push('BEGIN')
      const r = await fn(tx)
      calls.push('COMMIT')
      return r
    },
  }
  return { prisma, calls, transactions: () => transactions }
}

async function report(opts: { legacyColumn?: boolean; instanceTable?: boolean; env?: Record<string, string | undefined>; templateFiles?: number } = {}) {
  const { prisma } = sqlDb(opts)
  return previewRbacUpgrade(prisma, { env: opts.env ?? SCANNER_SET, templateFiles: opts.templateFiles ?? 0 })
}

/** What the preview says each account holds after the backfill, by id. */
/** A backfill's Prisma `orderBy` list (plain JS, typed loosely) as the fake's type. */
const asOrderBy = (order: unknown) => order as Record<string, 'asc' | 'desc'>[]

const predicted = (r: { grants: { id: string; grants: string[] }[] }) =>
  Object.fromEntries(r.grants.map((a) => [a.id, a.grants]))

describe('one read-only transaction (DV-32)', () => {
  test('opens a read-only transaction', async () => {
    user('admin', { role: 'admin' })
    user('alice')
    settings('alice', { ngrokAuthtoken: SECRET_NGROK, mcpServers: [stdio('local')] })
    const { prisma, calls, transactions } = sqlDb()
    await previewRbacUpgrade(prisma, { env: SCANNER_SET, templateFiles: 0 })
    expect(transactions()).toBe(1)
    expect(calls[0]).toBe('BEGIN')
    expect(calls[1]).toBe(READ_ONLY_SQL)
    expect(READ_ONLY_SQL).toMatch(/^SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY$/)
    expect(calls.at(-1)).toBe('COMMIT')
    for (const sql of calls.slice(2, -1)) expect(sql).toMatch(/^\s*SELECT\b/i)
  })

  test('never writes, locks or changes the schema', async () => {
    user('alice')
    const { prisma, calls } = sqlDb()
    await previewRbacUpgrade(prisma, { env: SCANNER_SET, templateFiles: 0 })
    for (const sql of calls) {
      expect(sql).not.toMatch(/\b(INSERT|UPDATE|DELETE|MERGE|ALTER|CREATE|DROP|TRUNCATE|GRANT|COPY|LOCK)\b|pg_advisory/i)
    }
  })

  test('selects no secret: only whether a password, a tunnel credential or a bearer is set', async () => {
    user('alice')
    const { prisma, calls } = sqlDb()
    await readUpgradeState(prisma)
    const sql = calls.join('\n')
    expect(sql.match(/\bpassword\b[^,\n]*/g)).toEqual(["password <> '' AS has_password"])
    expect(sql).not.toMatch(/chisel_auth|tavily|api_key|github_access_token/)
    expect(sql.match(/\bngrok_authtoken\b[^,\n]*/g)).toEqual(["ngrok_authtoken <> '' AS has_ngrok"])
    expect(sql).not.toMatch(/'token'\)?\s+AS/)
    expect(sql).not.toMatch(/->\s*'env'/)
  })
})

describe('works when the new columns are absent (the 7.7.x schema)', () => {
  test('no statement names a missing column, and every member is listed with the grants it will get', async () => {
    user('admin', { role: 'admin' })
    user('alice')
    user('bob')
    settings('bob', { chiselServerUrl: 'https://chisel.example.invalid:8443' })
    const r = await report({ legacyColumn: false })
    expect(predicted(r)).toEqual({
      alice: ['kali_terminal', 'shell_sessions'],
      bob: ['kali_terminal', 'shell_sessions', 'tunnels'],
    })
    expect(r.applied).toBe(false)
    expect(r.review).toBe(true)
  })

  test('the column check is data-driven: each new column names the step that adds it', () => {
    expect(NEW_COLUMNS).toContainEqual({ table: 'users', column: 'legacy_grants', step: '1.8' })
    for (const column of ['root_user_id', 'root_confirmed_at', 'updated_by_id']) {
      expect(NEW_COLUMNS).toContainEqual({ table: 'instance_settings', column, step: '2.1' })
    }
    for (const c of NEW_COLUMNS) expect(c.step).toMatch(/^\d+\.\d+$/)
  })

  test('no instance_settings table: no statement names it, and Root and the sources are still reported', async () => {
    user('admin', { role: 'admin' })
    settings('admin', { updatedAt: new Date('2026-04-01T09:00:00Z') })
    user('alice')
    const r = await report({ legacyColumn: false, instanceTable: false })
    expect(r.text).toMatch(/Root: admin@e2e\.local, the only admin with a password/)
    expect(r.text).toMatch(/TrafficMind, egress, SCA\s+admin@e2e\.local, saved 2026-04-01/)
  })
})

describe('lists grants exactly as the backfill would', () => {
  /** Runs the preview, then the backfill on the same rows, and compares every account. */
  async function previewThenBackfill(opts: { legacyColumn?: boolean } = {}) {
    const before = Object.fromEntries(db.rows('user').map((u) => [u.id as string, u.legacyGrants as string[]]))
    const r = await report(opts)
    const result = await backfillRbacLegacyGrants(db)
    const after = Object.fromEntries(db.rows('user').map((u) => [u.id as string, u.legacyGrants as string[]]))
    const expected = { ...before, ...predicted(r) }
    expect(after).toEqual(expected)
    return { r, result }
  }

  test('a first upgrade: members, tunnel holders, admins, passwordless accounts, grants already held', async () => {
    user('admin', { role: 'admin' })
    settings('admin', { ngrokAuthtoken: SECRET_NGROK })
    user('alice', { legacyGrants: ['beta_flag'] })
    user('ngrok')
    settings('ngrok', { ngrokAuthtoken: SECRET_NGROK, tunnelsEnabled: true })
    user('chisel')
    settings('chisel', { chiselServerUrl: 'https://chisel.example.invalid:8443' })
    user('authonly')
    settings('authonly', { chiselAuth: 'fake-user:fake-pass' })
    user('managed', { password: '' })
    settings('managed', { ngrokAuthtoken: SECRET_NGROK })
    const { r, result } = await previewThenBackfill()
    expect(result).toMatchObject({ done: true })
    expect(predicted(r)).toEqual({
      alice: ['kali_terminal', 'shell_sessions', 'beta_flag'],
      ngrok: ['kali_terminal', 'shell_sessions', 'tunnels'],
      chisel: ['kali_terminal', 'shell_sessions', 'tunnels'],
      authonly: ['kali_terminal', 'shell_sessions'],
    })
  })

  test('a user created after the cutoff gets nothing', async () => {
    user('alice')
    db.seed('auditLog', [{ action: CUTOFF_ACTION, targetType: 'system', source: 'system' }])
    t += 60_000
    user('late', { createdAt: new Date(t) })
    const { r } = await previewThenBackfill()
    expect(Object.keys(predicted(r))).toEqual(['alice'])
  })

  test('the backfill already ran: nothing changes, and the report says the hardening is in place', async () => {
    user('alice')
    await backfillRbacLegacyGrants(db)
    t += 60_000
    const { r, result } = await previewThenBackfill()
    expect(result).toEqual({ done: false })
    expect(r.applied).toBe(true)
    expect(r.grants).toEqual([])
    expect(r.review).toBe(false)
    expect(r.text).toMatch(/already in place/)
  })

  test('a marker that recorded no grant is final: a member added later gets nothing', async () => {
    user('root', { role: 'admin' })
    await backfillRbacLegacyGrants(db)
    user('alice')
    const { r } = await previewThenBackfill()
    expect(r.applied).toBe(true)
    expect(r.grants).toEqual([])
  })

  test('after a downgrade dropped the column: grants again, minus each grant an admin removed', async () => {
    user('alice')
    user('bob')
    settings('alice', { ngrokAuthtoken: SECRET_NGROK })
    await backfillRbacLegacyGrants(db)
    db.seed('auditLog', [
      { action: REMOVE_ACTION, targetType: 'user', targetId: 'alice', after: { grant: 'tunnels' }, source: 'api' },
      { action: REMOVE_ACTION, targetType: 'user', targetId: 'bob', after: { grant: 'kali_terminal' }, source: 'api' },
    ])
    for (const u of db.rows('user')) db.tables.user.set(u.id as string, { ...u, legacyGrants: [] })
    t += 60_000
    const { r } = await previewThenBackfill()
    expect(r.applied).toBe(false)
    expect(predicted(r)).toEqual({ alice: ['kali_terminal', 'shell_sessions'], bob: ['shell_sessions'] })
  })

  test('the 7.7.x schema (no column): the same grants as the backfill writes once the column exists', async () => {
    user('alice')
    user('ngrok')
    settings('ngrok', { ngrokAuthtoken: SECRET_NGROK })
    user('admin', { role: 'admin' })
    await previewThenBackfill({ legacyColumn: false })
  })
})

describe('the report', () => {
  test('a single-operator install: nothing changes, nothing to confirm; only who will be Root and where the instance settings come from', async () => {
    user('root', { role: 'admin' })
    settings('root', { mcpServers: [stdio('admin-tool')] })
    user('managed-admin', { role: 'admin', password: '' })
    const r = await report()
    expect(r.review).toBe(false)
    const [header, verdict, ...rest] = r.text.trim().split('\n')
    expect(header).toMatch(/^RBAC upgrade preview/)
    expect(verdict).toMatch(/nothing changes for existing accounts/i)
    expect(r.sections.map((s: { id: string }) => s.id)).toEqual(['root', 'instance_settings'])
    expect(rest.filter((l) => l.trim() !== '')).toEqual(r.sections.flatMap((s: { lines: string[] }) => s.lines))
  })

  test('members: the grants by email, what changes for them, and the escape hatch', async () => {
    user('admin', { role: 'admin' })
    user('alice')
    const r = await report({ templateFiles: 3 })
    expect(r.review).toBe(true)
    expect(r.text).toMatch(/alice@e2e\.local\s+Kali terminal, all shell sessions/)
    expect(r.text).toMatch(/Accounts: 1 admin, 1 member who can sign in, 0 without a password/)
    expect(r.text).toMatch(/Emergency stop/)
    expect(r.text).toMatch(/the 3 template file\(s\) already in the folder become instance templates/)
    expect(r.text).toMatch(/REDAMON_SHARED_TOOLS_COMPAT=true/)
  })

  test('tunnel rows: every candidate, enabled first, then the newest, then the lowest id; no credential', async () => {
    user('admin', { role: 'admin' })
    user('old')
    settings('old', { tunnelsEnabled: true, ngrokAuthtoken: SECRET_NGROK, updatedAt: new Date('2026-03-10T09:00:00Z') })
    user('new')
    settings('new', { tunnelsEnabled: true, chiselServerUrl: 'https://chisel.example.invalid:8443', updatedAt: new Date('2026-03-20T09:00:00Z') })
    user('off')
    settings('off', { tunnelsEnabled: false, ngrokAuthtoken: SECRET_NGROK, updatedAt: new Date('2026-04-01T09:00:00Z') })
    settings('admin', { chiselAuth: 'fake-user:fake-pass' })
    const r = await report()
    const tunnel = r.sections.find((s: { id: string }) => s.id === 'tunnel_rows')!
    const rows = tunnel.lines.filter((l: string) => /@e2e\.local/.test(l))
    expect(rows).toHaveLength(3)
    expect(rows[0]).toMatch(/new@e2e\.local \(member\)\s+chisel\s+enabled\s+saved 2026-03-20\s+<- the agent's tunnel/)
    expect(rows[1]).toMatch(/old@e2e\.local \(member\)\s+ngrok\s+enabled\s+saved 2026-03-10$/)
    expect(rows[2]).toMatch(/off@e2e\.local \(member\)\s+ngrok\s+disabled\s+saved 2026-04-01$/)
    expect(r.text).not.toContain(SECRET_NGROK)
    expect(r.text).not.toContain('fake-pass')
  })

  test('an admin\'s single tunnel row changes nothing for anyone', async () => {
    user('admin', { role: 'admin' })
    settings('admin', { ngrokAuthtoken: SECRET_NGROK })
    const r = await report()
    expect(r.review).toBe(false)
  })

  test('stdio MCP servers of non-admins stop loading; admins\' do not; disabled ones are named as such', async () => {
    user('admin', { role: 'admin' })
    settings('admin', { mcpServers: [stdio('admin-tool')] })
    user('managed', { password: '' })
    settings('managed', { mcpServers: [stdio('scraper'), stdio('old', { enabled: false }), http('remote')] })
    const r = await report()
    expect(r.review).toBe(true)
    const section = r.sections.find((s: { id: string }) => s.id === 'stdio_mcp')!
    expect(section.lines.join('\n')).toMatch(/managed@e2e\.local\s+scraper, old \(disabled\)/)
    expect(section.lines.join('\n')).not.toMatch(/admin-tool|remote/)
    expect(r.text).not.toContain('fake-env-secret')
  })

  test('MCP servers whose bearer came from the agent\'s environment, with the variable named', async () => {
    user('admin', { role: 'admin' })
    settings('admin', { mcpServers: [http('ops', { type: 'bearer', token_env_var: 'OPS_TOKEN' })] })
    user('managed', { password: '' })
    settings('managed', { mcpServers: [
      http('exfil', { type: 'bearer', token_env_var: 'INTERNAL_API_KEY' }),
      http('literal', { type: 'bearer', token: SECRET_BEARER, token_env_var: 'IGNORED' }),
    ] })
    const r = await report()
    expect(r.review).toBe(true)
    const lines = r.sections.find((s: { id: string }) => s.id === 'mcp_token_env_var')!.lines.join('\n')
    expect(lines).toMatch(/managed@e2e\.local\s+exfil \(INTERNAL_API_KEY\)/)
    expect(lines).toMatch(/admin@e2e\.local\s+ops \(OPS_TOKEN\)/)
    expect(lines).not.toMatch(/literal|IGNORED/)
    expect(r.text).not.toContain(SECRET_BEARER)
  })

  test.each([[undefined], [''], ['changeme']])('scanner key %j: scans would refuse to start, so it is worth a question', async (key) => {
    user('root', { role: 'admin' })
    const r = await report({ env: key === undefined ? {} : { SCANNER_API_KEY: key } })
    expect(r.review).toBe(true)
    expect(r.text).toMatch(/SCANNER_API_KEY is not set/)
  })

  test('a set scanner key is stated in a full report and never printed', async () => {
    user('alice')
    const r = await report()
    expect(r.text).toMatch(/SCANNER_API_KEY is set/)
    expect(r.text).not.toContain(SCANNER_SET.SCANNER_API_KEY)
  })

  test('the hardening already in place: one line besides Root and the instance settings, unless the scanner key is missing', async () => {
    user('alice')
    settings('alice', { mcpServers: [stdio('scraper')] })
    await backfillRbacLegacyGrants(db)
    const quiet = await report()
    expect(quiet.review).toBe(false)
    const [, verdict, ...rest] = quiet.text.trim().split('\n')
    expect(verdict).toMatch(/already in place/)
    expect(quiet.sections.map((s: { id: string }) => s.id)).toEqual(['root', 'instance_settings'])
    expect(rest.filter((l) => l.trim() !== '')).toEqual(quiet.sections.flatMap((s: { lines: string[] }) => s.lines))
    const missing = await report({ env: {} })
    expect(missing.review).toBe(true)
    expect(missing.text).toMatch(/SCANNER_API_KEY is not set/)
  })

  test('control characters in stored names never reach the operator\'s terminal', async () => {
    user('evil', { password: '', email: 'evil\u001b[2J@e2e.local' })
    settings('evil', { mcpServers: [stdio('x\u001b]0;pwned\u0007y')] })
    const r = await report()
    expect(r.text).not.toMatch(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/)
    expect(r.text).toContain('evil?[2J@e2e.local')
  })

  test('each section and each member-visible change names the step whose behaviour it reports', () => {
    expect(SECTIONS.map((s: { id: string }) => s.id)).toEqual([
      'accounts', 'root', 'legacy_grants', 'tunnel_rows', 'instance_settings', 'stdio_mcp', 'mcp_token_env_var',
      'scanner_key', 'member_changes',
    ])
    for (const s of [...SECTIONS, ...MEMBER_CHANGES]) expect(s.step).toMatch(/^\d+\.\d+(-\d+\.\d+)?$/)
  })

  test('buildReport is pure: the same state gives the same report', async () => {
    user('alice')
    const { prisma } = sqlDb()
    const state = await readUpgradeState(prisma)
    const a = buildReport(state, { env: SCANNER_SET, templateFiles: 1 })
    const b = buildReport(state, { env: SCANNER_SET, templateFiles: 1 })
    expect(a).toEqual(b)
  })
})

describe('who will be Root, and where the instance settings come from (HD-31 Root part, ID-34)', () => {
  const lines = (r: { sections: { id: string; lines: string[] }[] }, id: string) =>
    r.sections.find((s) => s.id === id)?.lines ?? []
  const SWITCH_ON = { ...SCANNER_SET, RBAC_IDENTITY_ENABLED: 'true' }

  test('the only admin with a password is Root; a passwordless admin never is; switch off: nothing changes yet', async () => {
    user('admin', { role: 'admin' })
    user('managed-admin', { role: 'admin', password: '', createdAt: new Date('2020-01-01T00:00:00Z') })
    user('alice')
    const root = lines(await report(), 'root').join('\n')
    expect(root).toMatch(/Root: admin@e2e\.local, the only admin with a password, chosen automatically at the next start/)
    expect(root).not.toMatch(/managed-admin/)
    expect(root).toMatch(/Nothing changes while RBAC_IDENTITY_ENABLED is off/)
  })

  test('several admins: the oldest is proposed and every candidate is listed in the Root backfill\'s order', async () => {
    const SAME = new Date('2026-01-01T00:00:00Z')
    user('zed', { role: 'admin', createdAt: SAME })
    user('amy', { role: 'admin', createdAt: SAME })
    user('old', { role: 'admin', createdAt: new Date('2025-06-01T00:00:00Z') })
    user('nopw', { role: 'admin', password: '', createdAt: new Date('2024-01-01T00:00:00Z') })
    user('member', { createdAt: new Date('2023-01-01T00:00:00Z') })
    const order = (await db.user.findMany({ where: CANDIDATE_WHERE, orderBy: asOrderBy(CANDIDATE_ORDER), select: { id: true } }))
      .map((u) => u.id as string)
    expect(order).toEqual(['old', 'amy', 'zed'])
    expect(chooseRoot(order.map((id) => ({ id })))).toMatchObject({ userId: 'old', rule: 'oldest_admin', candidateCount: 3 })

    const root = lines(await report(), 'root')
    expect(root[0]).toMatch(/Root: old@e2e\.local, the oldest of 3 admins with a password, chosen automatically/)
    const listed = root.filter((l) => /^ {4}\S+@e2e\.local/.test(l)).map((l) => l.trim().split(/\s+/)[0])
    expect(listed).toEqual(order.map((id) => `${id}@e2e.local`))
    expect(root.find((l) => l.includes('old@e2e.local') && l.trim().startsWith('old'))).toMatch(/<- proposed/)
  })

  test('with the identity switch on: the update confirms the only admin, or asks among several', async () => {
    user('admin', { role: 'admin' })
    expect(lines(await report({ env: SWITCH_ON }), 'root').join('\n')).toMatch(/After the restart this update confirms it\./)
    user('second', { role: 'admin', createdAt: new Date(T0 - 3_600_000) })
    const root = lines(await report({ env: SWITCH_ON }), 'root').join('\n')
    expect(root).toMatch(/asks which admin to confirm/)
    expect(root).toMatch(/ADMIN_EMAIL/)
  })

  test('a Root already recorded is named, confirmed or not; one that is no longer an admin is chosen again', async () => {
    user('admin', { role: 'admin' })
    user('older', { role: 'admin', createdAt: new Date('2025-01-01T00:00:00Z') })
    instanceRow = { rootUserId: 'admin', rootConfirmedAt: new Date('2026-11-01T00:00:00Z') }
    expect(lines(await report(), 'root')).toEqual(['  Root: admin@e2e.local (confirmed).'])

    instanceRow = { rootUserId: 'admin', rootConfirmedAt: null }
    const unconfirmed = lines(await report({ env: SWITCH_ON }), 'root').join('\n')
    expect(unconfirmed).toMatch(/Root: admin@e2e\.local, chosen automatically, not confirmed yet/)
    expect(unconfirmed).not.toMatch(/older@/)

    instanceRow = { rootUserId: 'gone', rootConfirmedAt: new Date('2026-11-01T00:00:00Z') }
    const stale = lines(await report(), 'root').join('\n')
    expect(stale).toMatch(/The Root recorded \(account gone\) is no longer an admin/)
    expect(stale).toMatch(/Root: older@e2e\.local, the oldest of 2 admins/)
  })

  test('no admin with a password: no Root yet, and the command that makes one', async () => {
    user('managed-admin', { role: 'admin', password: '' })
    user('alice')
    expect(lines(await report(), 'root').join('\n'))
      .toMatch(/Root: none yet \(no admin has a password\); \.\/redamon\.sh create-admin makes one/)
  })

  test('instance settings: the rows the instance settings backfill copies, with their candidates, never a value', async () => {
    user('admin', { role: 'admin' })
    user('admin2', { role: 'admin' })
    user('alice')
    user('bob')
    settings('admin', { chiselAuth: 'fake-user:fake-pass', updatedAt: new Date('2026-04-01T09:00:00Z') })
    settings('admin2', { updatedAt: new Date('2026-03-01T09:00:00Z') })
    settings('alice', { tunnelsEnabled: true, ngrokAuthtoken: SECRET_NGROK, updatedAt: new Date('2026-02-01T09:00:00Z') })
    settings('bob', { chiselServerUrl: 'https://chisel.example.invalid:8443', updatedAt: new Date('2026-05-01T09:00:00Z') })
    const derived = await deriveInstanceValues(db)
    expect(derived.data.tunnelSourceUserId).toBe('alice')
    // The capture pick by the backfill's own order; the fake reads deriveInstanceValues'
    // `userId: {in}` as a compound unique key, so the same admin filter is spelled with OR.
    const adminIds = (await db.user.findMany({ where: { role: 'admin' }, select: { id: true } })).map((u) => u.id as string)
    const [capture] = await db.userSettings.findMany({ where: { OR: adminIds.map((userId) => ({ userId })) }, orderBy: asOrderBy(CAPTURE_ROW_ORDER) })
    expect(capture.userId).toBe('admin')

    const r = await report()
    expect(r.review).toBe(true)
    const text = lines(r, 'instance_settings').join('\n')
    expect(text).toMatch(/tunnel\s+alice@e2e\.local \(member\), saved 2026-02-01; 2 accounts hold one/)
    expect(text).toMatch(/TrafficMind, egress, SCA\s+admin@e2e\.local, saved 2026-04-01, the latest of 2 admin rows/)
    expect(text).toMatch(/While RBAC_IDENTITY_ENABLED is off the accounts' settings stay in force/)
    expect(r.text).not.toContain(SECRET_NGROK)
    expect(r.text).not.toContain('fake-pass')
  })

  test('nothing saved in any account: the defaults', async () => {
    user('admin', { role: 'admin' })
    const text = lines(await report(), 'instance_settings').join('\n')
    expect(text).toMatch(/tunnel\s+none saved \(off\)/)
    expect(text).toMatch(/TrafficMind, egress, SCA\s+none saved \(the defaults\)/)
  })

  test('switch on: the copy becomes the one in force; once filled with the switch on, or saved by an admin, it is not copied again', async () => {
    user('admin', { role: 'admin' })
    settings('admin')
    instanceRow = { rootUserId: 'admin', rootConfirmedAt: new Date('2026-11-01T00:00:00Z') }
    expect(lines(await report({ env: SWITCH_ON }), 'instance_settings').join('\n'))
      .toMatch(/With RBAC_IDENTITY_ENABLED on this copy is the one in force/)

    db.seed('auditLog', [{ action: INSTANCE_MARKER_ACTION, targetType: 'system', source: 'system', after: { identity: false } }])
    expect(lines(await report({ env: SWITCH_ON }), 'instance_settings').join('\n')).toMatch(/copied at the next start/)

    t += 60_000
    db.seed('auditLog', [{ action: INSTANCE_MARKER_ACTION, targetType: 'system', source: 'system', after: { identity: true } }])
    const inForce = lines(await report({ env: SWITCH_ON }), 'instance_settings').join('\n')
    expect(inForce).toMatch(/Instance settings .* in force; admins change them in Global Settings/s)
    expect(inForce).not.toMatch(/copied at the next start/)
    // Switch off again: the accounts' rows are the truth again, so each start copies them.
    expect(lines(await report(), 'instance_settings').join('\n')).toMatch(/copied at the next start/)
  })

  test('an admin saved the instance settings: in force with the switch on, even without a marker', async () => {
    user('admin', { role: 'admin' })
    instanceRow = { rootUserId: null, adminSaved: true }
    expect(lines(await report({ env: SWITCH_ON }), 'instance_settings').join('\n')).toMatch(/in force; admins change them/)
  })

  test('Root and the instance settings never make the update ask', async () => {
    user('a', { role: 'admin', createdAt: new Date('2025-01-01T00:00:00Z') })
    user('b', { role: 'admin' })
    settings('a', { updatedAt: new Date('2026-04-01T09:00:00Z') })
    settings('b', { updatedAt: new Date('2026-05-01T09:00:00Z') })
    for (const env of [SCANNER_SET, SWITCH_ON]) {
      const r = await report({ env })
      expect(r.review).toBe(false)
      expect(r.sections.map((s: { id: string }) => s.id)).toEqual(['root', 'instance_settings'])
    }
  })
})

describe('exit codes and invocation', () => {
  test('a report to confirm and a report with nothing to confirm exit differently from a failure', () => {
    expect(NOTHING_CHANGES_EXIT).toBe(0)
    expect(REVIEW_EXIT).toBe(10)
  })

  test.each([['as a file'], ['fed on stdin']])('runs %s, finds the backfill beside it, and fails cleanly without a database', (how) => {
    const webapp = path.resolve(__dirname, '..')
    const script = path.join(webapp, 'scripts', 'rbac-upgrade-preview.mjs')
    const env = { ...process.env, DATABASE_URL: 'postgresql://nobody:nothing@127.0.0.1:1/none?connect_timeout=2' }
    const run = how === 'as a file'
      ? spawnSync(process.execPath, [script], { cwd: webapp, env, encoding: 'utf8', timeout: 60_000 })
      : spawnSync(process.execPath, ['--input-type=module', '-'], {
        cwd: webapp, env, encoding: 'utf8', timeout: 60_000, input: readFileSync(script, 'utf8'),
      })
    expect(run.stderr).not.toMatch(/ERR_MODULE_NOT_FOUND|Cannot find module/)
    expect(run.stderr).toMatch(/\[rbac\] upgrade preview failed/)
    expect(run.stderr).not.toContain('nothing@')
    expect(run.status).toBe(1)
  })
})

// ---------------------------------------------------------------------------------------
// The downgrade report (`--downgrade`, UP-05, step 7.2)
// ---------------------------------------------------------------------------------------

type SnapshotModels = Record<string, { table: string; fields: Record<string, { type: string; column: string }> }>
const HEAD_MODELS = parsePrismaModels(readFileSync(path.resolve(__dirname, '../prisma/schema.prisma'), 'utf8'))
const OLD_MODELS = (release772 as { models: SnapshotModels }).models
/** Every column of the schema in the tree, by table (a relation field has no column). */
const HEAD_COLUMNS: Record<string, string[]> = Object.fromEntries(Object.values(HEAD_MODELS).map((m) => [
  m.table, Object.values(m.fields).filter((f) => !HEAD_MODELS[baseType(f.type)]).map((f) => f.column),
]))
const headField = (table: string, column: string) =>
  Object.values(Object.values(HEAD_MODELS).find((m) => m.table === table)?.fields ?? {}).find((f) => f.column === column)

const FUTURE = new Date(T0 + 86_400_000)
const PAST = new Date(T0 - 86_400_000)
const HELD_HASH = '$2a$12$held-hash-of-a-disabled-account'
const PROVIDER_KEY = 'fake-instance-provider-key-0001'

/**
 * A transaction over rows by table (snake_case columns, the current schema), answering the
 * downgrade report's SQL. A statement naming a table or column listed in `absent` fails as
 * Postgres would, so the report must check before it names one.
 */
function downgradeDb(tables: Record<string, Row[]> = {}, absent: string[] = []) {
  const calls: string[] = []
  let transactions = 0
  const rowsOf = (table: string) => tables[table] ?? []
  const lacks = (table: string, column?: string) => absent.includes(table) || (column !== undefined && absent.includes(`${table}.${column}`))
  const nowMs = () => t
  const live = (d: unknown) => d === null || d === undefined || new Date(d as string).getTime() > nowMs()
  const isInstance = (v: unknown) => typeof v === 'string' && v.startsWith('instance/')

  /** `"c" IS DISTINCT FROM <literal>` for the literals the report uses. */
  const differs = (value: unknown, literal: string) => {
    if (literal === 'NULL') return value !== null && value !== undefined
    if (literal === 'true' || literal === 'false') return Boolean(value) !== (literal === 'true')
    if (/^-?\d+$/.test(literal)) return Number(value) !== Number(literal)
    const text = literal.slice(1, -1)
    if (text === '{}') return Array.isArray(value) && value.length > 0
    if (Array.isArray(value) || (value !== null && typeof value === 'object')) return JSON.stringify(value) !== text
    return String(value ?? '') !== text
  }

  const answer = (sql: string, params: unknown[]): Row[] => {
    for (const name of absent) {
      const [table, column] = name.split('.')
      const namesTable = new RegExp(`\\b${table}\\b`).test(sql)
      if (!column && namesTable) throw new Error(`relation "${table}" does not exist`)
      if (column && namesTable && new RegExp(`(?<!AS )\\b${column}\\b`).test(sql)) throw new Error(`column "${column}" does not exist`)
    }
    if (/^\s*SELECT now\(\)/i.test(sql)) return [{ now: new Date(t) }]
    if (/information_schema\.columns/.test(sql)) {
      return (params as string[]).filter((table) => !lacks(table)).flatMap((table) =>
        (HEAD_COLUMNS[table] ?? []).filter((c) => !lacks(table, c)).map((c) => ({ table_name: table, column_name: c })))
    }
    if (/::text AS t, count\(\*\)::int AS n FROM/.test(sql)) {
      return [...sql.matchAll(/SELECT \$(\d+)::text AS t, count\(\*\)::int AS n FROM "(\w+)"/g)].map(([, i, table]) => {
        if (params[Number(i) - 1] !== table) throw new Error(`label ${String(params[Number(i) - 1])} for table ${table}`)
        return { t: table, n: rowsOf(table).length }
      })
    }
    if (/count\(\*\) FILTER \(WHERE "\w+" IS DISTINCT FROM/.test(sql)) {
      const table = sql.match(/FROM "(\w+)"\s*$/)![1]
      const out: Row = {}
      for (const [, col, literal, alias] of sql.matchAll(/count\(\*\) FILTER \(WHERE "(\w+)" IS DISTINCT FROM (.+?)\)::int AS "(\w+)"/g)) {
        out[alias] = rowsOf(table).filter((r) => differs(r[col], literal)).length
      }
      return [out]
    }
    if (/count\(\*\) FILTER \(WHERE "\w+" LIKE \$1\)/.test(sql)) {
      if (params[0] !== 'instance/%') throw new Error('instance models are matched by their prefix')
      const table = sql.match(/FROM "(\w+)"\s*$/)![1]
      const out: Row = {}
      for (const [, col, alias] of sql.matchAll(/count\(\*\) FILTER \(WHERE "(\w+)" LIKE \$1\)::int AS "(\w+)"/g)) {
        out[alias] = rowsOf(table).filter((r) => isInstance(r[col])).length
      }
      return [out]
    }
    if (/FROM users ORDER BY id/.test(sql)) {
      return rowsOf('users').map((u) => ({
        id: u.id, email: u.email, role: u.role,
        status: lacks('users', 'status') ? 'active' : (u.status ?? 'active'),
        must_change_password: lacks('users', 'must_change_password') ? false : u.must_change_password === true,
        session_version: lacks('users', 'session_version') ? 0 : (u.session_version ?? 0),
        admin_profile_id: lacks('users', 'admin_profile_id') ? null : (u.admin_profile_id ?? null),
        has_held_password: lacks('users', 'password_on_hold') ? false : (u.password_on_hold ?? '') !== '',
      }))
    }
    if (/FROM user_permission_sets/.test(sql)) return rowsOf('user_permission_sets').map((r) => ({ user_id: r.user_id, set_id: r.set_id }))
    if (/FROM permission_sets/.test(sql)) return rowsOf('permission_sets').map((r) => ({ id: r.id, kind: r.kind, name: r.name }))
    if (/FROM user_permission_overrides/.test(sql)) {
      const counts = new Map<string, number>()
      for (const o of rowsOf('user_permission_overrides')) {
        if (o.effect === 'deny' && live(o.expires_at)) counts.set(o.user_id as string, (counts.get(o.user_id as string) ?? 0) + 1)
      }
      return [...counts].map(([user_id, n]) => ({ user_id, n }))
    }
    if (/FROM instance_settings WHERE id = \$1/.test(sql)) {
      if (params[0] !== 'instance') throw new Error('the singleton row')
      return rowsOf('instance_settings').slice(0, 1).map((r) => ({ default_member_set_id: r.default_member_set_id ?? null }))
    }
    if (/FROM user_sessions/.test(sql)) {
      return [{ revoked: rowsOf('user_sessions').filter((s) => s.revoked_at && live(s.expires_at)).length }]
    }
    if (/FROM projects\s+WHERE/.test(sql)) {
      if (params[0] !== 'instance/%') throw new Error('instance models are matched by their prefix')
      return rowsOf('projects')
        .filter((p) => ['agent_openai_model', 'ai_pipeline_model', 'cypherfix_llm_model'].some((c) => isInstance(p[c])))
        .map((p) => ({
          id: p.id, name: p.name, user_id: p.user_id, agent_openai_model: p.agent_openai_model ?? '',
          ai_pipeline_model: p.ai_pipeline_model ?? '', cypherfix_llm_model: p.cypherfix_llm_model ?? '',
        }))
    }
    if (/FROM user_project_presets\s+WHERE/.test(sql)) {
      if (params[0] !== 'instance/%') throw new Error('instance models are matched by their prefix')
      return rowsOf('user_project_presets')
        .filter((p) => INSTANCE_MODEL_PRESET_KEYS.some((k: string) => isInstance((p.settings as Row)?.[k])))
        .map((p) => ({ user_id: p.user_id, name: p.name }))
    }
    throw new Error(`unexpected SQL: ${sql}`)
  }
  const tx = {
    $executeRawUnsafe: async (sql: string) => { calls.push(sql); return 0 },
    $queryRawUnsafe: async (sql: string, ...params: unknown[]) => { calls.push(sql); return answer(sql, params) },
  }
  const prisma = {
    $transaction: async (fn: (t: typeof tx) => Promise<unknown>) => {
      transactions++
      calls.push('BEGIN')
      const r = await fn(tx)
      calls.push('COMMIT')
      return r
    },
  }
  return { prisma, calls, transactions: () => transactions }
}

const SWITCHES_ON = {
  RBAC_IDENTITY_ENABLED: 'true', RBAC_PERMISSIONS_ENABLED: 'true', RBAC_SHARING_ENABLED: 'true',
  RBAC_SHARING_WRITE_ENABLED: 'true', RBAC_GOVERNANCE_ENABLED: 'true',
}

const account = (id: string, extra: Row = {}): Row => ({
  id, email: `${id}@e2e.local`, role: 'standard', status: 'active', must_change_password: false, session_version: 0,
  admin_profile_id: null, password_on_hold: '', legacy_grants: [], pending_notices: [], last_login_at: null, ...extra,
})

/** An install after the RBAC upgrade, with RBAC state of every phase. */
function upgradedInstall(): Record<string, Row[]> {
  return {
    users: [
      account('root', { role: 'admin', last_login_at: PAST }),
      account('usermgr', { role: 'admin', admin_profile_id: 'builtin:user-manager' }),
      account('fulladmin', { role: 'admin', admin_profile_id: 'builtin:full-admin' }),
      account('analyst', { legacy_grants: ['kali_terminal'] }),
      account('defaulted'),
      account('plain'),
      account('denied'),
      account('custom'),
      account('noaccess'),
      account('disabled', { status: 'disabled', password_on_hold: HELD_HASH, session_version: 1 }),
      account('invited', { status: 'invited' }),
      account('mustchange', { must_change_password: true }),
    ],
    instance_settings: [{ id: 'instance', root_user_id: 'root', default_member_set_id: 'builtin:recon-operator' }],
    permission_sets: [{ id: 'set-custom', kind: 'member', name: 'Scanners only' }],
    user_permission_sets: [
      { user_id: 'analyst', set_id: 'builtin:read-only-analyst' },
      { user_id: 'plain', set_id: 'builtin:default-member' },
      { user_id: 'custom', set_id: 'set-custom' },
      { user_id: 'noaccess', set_id: 'builtin:no-access' },
    ],
    user_permission_overrides: [
      { user_id: 'denied', permission: 'agent:chat', effect: 'deny', expires_at: null },
      { user_id: 'denied', permission: 'scan:start', effect: 'deny', expires_at: FUTURE },
      { user_id: 'plain', permission: 'scan:start', effect: 'deny', expires_at: PAST },
      { user_id: 'plain', permission: 'platform:kali_terminal', effect: 'grant', expires_at: null },
    ],
    project_collaborators: [{ project_id: 'p1', user_id: 'plain' }, { project_id: 'p1', user_id: 'custom' }],
    conversation_shares: [{ id: 'cs1' }],
    project_transfers: [{ id: 'tr1' }],
    project_access_policies: [{ project_id: 'p1' }],
    instance_llm_providers: [{ id: 'prov1', api_key: PROVIDER_KEY }],
    permission_set_providers: [{ set_id: 'set-custom', provider_id: 'prov1' }],
    quota_usage: [{ user_id: 'plain', kind: 'agent_runs', count: 3 }],
    user_sessions: [
      { id: 's1', revoked_at: PAST, expires_at: FUTURE },
      { id: 's2', revoked_at: PAST, expires_at: PAST },
      { id: 's3', revoked_at: null, expires_at: FUTURE },
    ],
    plugin_access_rules: [{ plugin_id: 'x', set_id: 'set-custom' }],
    user_invites: [{ id: 'inv1', token_hash: 'fake-hash' }],
    projects: [
      { id: 'p1', name: 'Shared project', user_id: 'plain', agent_openai_model: 'instance/prov1/gpt-x', ai_pipeline_model: 'claude-opus-4-6', cypherfix_llm_model: '' },
      { id: 'p2', name: 'Own model', user_id: 'analyst', agent_openai_model: 'claude-opus-4-6', ai_pipeline_model: 'instance/prov1/gpt-x', cypherfix_llm_model: 'instance/prov1/gpt-y' },
      { id: 'p3', name: 'Untouched', user_id: 'analyst', agent_openai_model: 'gpt-4o', ai_pipeline_model: 'claude-opus-4-6', cypherfix_llm_model: '' },
    ],
    user_tradecraft_resources: [{ id: 'tc1', llm_model: 'instance/prov1/gpt-x' }, { id: 'tc2', llm_model: '' }],
    user_project_presets: [
      { user_id: 'plain', name: 'Fast preset', settings: { agentOpenaiModel: 'instance/prov1/gpt-x' } },
      { user_id: 'plain', name: 'Mine', settings: { agentOpenaiModel: 'gpt-4o' } },
    ],
    scan_schedules: [{ id: 'sch1', paused_reason: 'actor_lost_access' }, { id: 'sch2', paused_reason: null }],
    mcp_access_tokens: [{ id: 'tok1', include_shared_projects: true, project_allowlist: ['p1'] }],
  }
}

async function downgrade(tables: Record<string, Row[]> = upgradedInstall(), opts: { env?: Record<string, string>; absent?: string[] } = {}) {
  const { prisma } = downgradeDb(tables, opts.absent)
  return previewRbacDowngrade(prisma, { env: opts.env ?? SWITCHES_ON })
}
const sectionText = (r: { sections: { id: string; lines: string[] }[] }, id: string) =>
  (r.sections.find((s) => s.id === id)?.lines ?? []).join('\n')
/** The line of a table or column list that names `name` first. */
const listed = (r: { sections: { id: string; lines: string[] }[] }, id: string, name: string) =>
  (r.sections.find((s) => s.id === id)?.lines ?? []).find((l) => l.trim().split(/\s+/)[0] === name)

describe('downgrade report: what 7.7.2 drops is exactly what it lacks (UP-05)', () => {
  const oldTables = new Map(Object.values(OLD_MODELS).map((m) => [m.table, new Set(Object.values(m.fields).map((f) => f.column))]))

  test('the target is the release the schema snapshot was taken from', () => {
    expect(DOWNGRADE_TARGET).toEqual({ version: '7.7.2', commit: '442debbf' })
    expect((release772 as { source: string }).source).toContain(`${DOWNGRADE_TARGET.commit}:webapp/prisma/schema.prisma (release ${DOWNGRADE_TARGET.version})`)
  })

  test('every table schema.prisma adds since 7.7.2 is in DOWNGRADE_TABLES, and nothing else', () => {
    const added = Object.keys(HEAD_COLUMNS).filter((table) => !oldTables.has(table)).sort()
    expect(DOWNGRADE_TABLES.map((d: { table: string }) => d.table).sort(),
      'a table added to schema.prisma goes in DOWNGRADE_TABLES of scripts/rbac-upgrade-preview.mjs, with what a downgrade loses').toEqual(added)
  })

  test('every column schema.prisma adds to a 7.7.2 table is in DOWNGRADE_COLUMNS, and nothing else', () => {
    const added = Object.entries(HEAD_COLUMNS)
      .filter(([table]) => oldTables.has(table))
      .flatMap(([table, columns]) => columns.filter((c) => !oldTables.get(table)!.has(c)).map((c) => `${table}.${c}`))
      .sort()
    expect(DOWNGRADE_COLUMNS.map((d: { table: string; column: string }) => `${d.table}.${d.column}`).sort(),
      'a column added to a 7.7.2 table goes in DOWNGRADE_COLUMNS of scripts/rbac-upgrade-preview.mjs, with its default and what a downgrade loses').toEqual(added)
  })

  test('a column holds a value when it differs from the default a new row gets', () => {
    const DEFAULT = /@default\(((?:[^()"]|"[^"]*")*)\)/
    for (const c of DOWNGRADE_COLUMNS as { table: string; column: string; unset: string }[]) {
      const field = headField(c.table, c.column)!
      const d = field.line.match(DEFAULT)?.[1]
      const expected = d === undefined ? 'NULL' : d === '[]' ? "'{}'" : /^".*"$/.test(d) ? `'${d.slice(1, -1)}'` : d
      expect(c.unset, `${c.table}.${c.column}`).toBe(expected)
      if (d === undefined) expect(field.type, `${c.table}.${c.column} has no default, so it is nullable`).toMatch(/\?$/)
    }
  })

  test('each entry says what is lost and names the step, or the other feature, that added it', () => {
    for (const d of [...DOWNGRADE_TABLES, ...DOWNGRADE_COLUMNS] as { step: string | null; feature?: string; lost: string }[]) {
      expect(d.lost).toMatch(/^\S.{9,}[^.]$/)
      if (d.step === null) expect(d.feature).toMatch(/\S/)
      else expect(d.step).toMatch(/^\d+\.\d+$/)
    }
  })

  test('the built-in set names and the sets equal to Default member follow the permission catalog', () => {
    const sets = (permissionCatalog as { sets: { id: string; kind: string; name: string; permissions: string[] }[] }).sets
    expect(BUILTIN_SET_NAMES).toEqual(Object.fromEntries(sets.map((s) => [s.id, s.name])))
    const def = sets.find((s) => s.id === 'builtin:default-member')!
    const same = sets.filter((s) => s.kind === 'member' && [...s.permissions].sort().join() === [...def.permissions].sort().join())
    expect([...SETS_EQUAL_TO_DEFAULT_MEMBER].sort()).toEqual(same.map((s) => s.id).sort())
    expect(FULL_ADMIN_PROFILE).toBe('builtin:full-admin')
  })

  test('the instance model columns exist in both schemas; the reset puts back the default and touches no other row', () => {
    for (const c of INSTANCE_MODEL_COLUMNS as { table: string; column: string }[]) {
      expect(headField(c.table, c.column), `${c.table}.${c.column} now`).toBeDefined()
      expect(oldTables.get(c.table)?.has(c.column), `${c.table}.${c.column} in 7.7.2`).toBe(true)
    }
    expect(oldTables.get('user_project_presets')?.has('settings')).toBe(true)
    const sql = instanceModelResetSql()
    expect(sql).toHaveLength(INSTANCE_MODEL_COLUMNS.length + INSTANCE_MODEL_PRESET_KEYS.length)
    for (const s of sql) {
      expect(s).toMatch(/^UPDATE \w+ SET (\w+ = DEFAULT|settings = settings - '\w+') WHERE (\w+|settings->>'\w+') LIKE 'instance\/%';$/)
    }
    expect(sql).toContain("UPDATE projects SET agent_openai_model = DEFAULT WHERE agent_openai_model LIKE 'instance/%';")
    expect(sql).toContain("UPDATE user_project_presets SET settings = settings - 'agentOpenaiModel' WHERE settings->>'agentOpenaiModel' LIKE 'instance/%';")
  })
})

describe('downgrade report: one read-only transaction', () => {
  test('a read-only transaction of SELECTs; nothing written, locked or changed', async () => {
    const { prisma, calls, transactions } = downgradeDb(upgradedInstall())
    await readDowngradeState(prisma)
    expect(transactions()).toBe(1)
    expect(calls.slice(0, 2)).toEqual(['BEGIN', READ_ONLY_SQL])
    expect(calls.at(-1)).toBe('COMMIT')
    for (const sql of calls.slice(2, -1)) expect(sql).toMatch(/^\s*SELECT\b/i)
    for (const sql of calls) expect(sql).not.toMatch(/\b(INSERT|UPDATE|DELETE|MERGE|ALTER|CREATE|DROP|TRUNCATE|GRANT|COPY|LOCK)\b|pg_advisory/i)
  })

  test('selects no secret: never a password, a held hash, a token hash or a provider key', async () => {
    const { prisma, calls } = downgradeDb(upgradedInstall())
    const r = await previewRbacDowngrade(prisma, { env: SWITCHES_ON })
    const sql = calls.join('\n')
    expect(sql).not.toMatch(/\bpassword\b/)
    expect(sql.match(/password_on_hold[^,\n]*/g)?.filter((s) => !/IS DISTINCT FROM ''/.test(s))).toEqual(["password_on_hold <> '' AS has_held_password"])
    expect(sql).not.toMatch(/token_hash|api_key|aws_secret_key|aws_bearer_token|ngrok_authtoken|chisel_auth/)
    expect(r.text).not.toContain(HELD_HASH)
    expect(r.text).not.toContain(PROVIDER_KEY)
  })

  test('a table or column this database lacks is reported as absent and never queried', async () => {
    const r = await downgrade(upgradedInstall(), { absent: ['quota_usage', 'user_permission_overrides', 'users.pending_notices', 'users.status'] })
    expect(listed(r, 'tables', 'quota_usage')).toMatch(/not in this database/)
    expect(listed(r, 'tables', 'user_permission_overrides')).toMatch(/not in this database/)
    expect(listed(r, 'columns', 'users.pending_notices')).toMatch(/not in this database/)
    expect(sectionText(r, 'rights')).not.toMatch(/denied permission/)
    expect(sectionText(r, 'sign_in')).not.toMatch(/disabled@|invited@/)
  })
})

describe('downgrade report: the data dropped', () => {
  test('every dropped table with its rows, and what it held', async () => {
    const r = await downgrade()
    for (const d of DOWNGRADE_TABLES as { table: string; lost: string }[]) {
      expect(listed(r, 'tables', d.table), d.table).toContain(d.lost)
    }
    expect(listed(r, 'tables', 'instance_settings')).toMatch(/\s1 row\s/)
    expect(listed(r, 'tables', 'project_collaborators')).toMatch(/\s2 rows\s/)
    expect(listed(r, 'tables', 'user_sessions')).toMatch(/\s3 rows\s/)
    expect(listed(r, 'tables', 'nuclei_templates')).toMatch(/\s0 rows\s/)
  })

  test('every dropped column with the rows holding a value, and what it held', async () => {
    const r = await downgrade()
    for (const d of DOWNGRADE_COLUMNS as { table: string; column: string; lost: string }[]) {
      expect(listed(r, 'columns', `${d.table}.${d.column}`), `${d.table}.${d.column}`).toContain(d.lost)
    }
    expect(listed(r, 'columns', 'users.status')).toMatch(/\s2 rows\s/)
    expect(listed(r, 'columns', 'users.password_on_hold')).toMatch(/\s1 row\s/)
    expect(listed(r, 'columns', 'users.admin_profile_id')).toMatch(/\s2 rows\s/)
    expect(listed(r, 'columns', 'users.legacy_grants')).toMatch(/\s1 row\s/)
    expect(listed(r, 'columns', 'users.last_login_at')).toMatch(/\s1 row\s/)
    expect(listed(r, 'columns', 'scan_schedules.paused_reason')).toMatch(/\s1 row\s/)
    expect(listed(r, 'columns', 'mcp_access_tokens.project_allowlist')).toMatch(/\s1 row\s/)
    expect(listed(r, 'columns', 'users.pending_notices')).toMatch(/\s0 rows\s/)
  })

  test('the backup comes first: the dump command, and the db push that drops the data', async () => {
    const r = await downgrade()
    const [header] = r.text.split('\n')
    expect(header).toMatch(/^RBAC downgrade preview: going back to 7\.7\.2 \(read-only: nothing has been changed\)$/)
    const backup = sectionText(r, 'backup')
    expect(backup).toMatch(/prisma db push --accept-data-loss/)
    expect(backup).toContain(`docker compose exec -T postgres sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc' > redamon-before-downgrade.dump`)
    expect(r.sections[0].id).toBe('backup')
  })
})

describe('downgrade report: accounts', () => {
  test('accounts whose stored sets, profile or denies narrow them get their account type\'s rights back (fail open)', async () => {
    const r = await downgrade()
    const rights = sectionText(r, 'rights')
    expect(rights).toMatch(/usermgr@e2e\.local\s+admin profile User manager/)
    expect(rights).toMatch(/analyst@e2e\.local\s+permission set Read-only analyst/)
    expect(rights).toMatch(/custom@e2e\.local\s+permission set Scanners only \(custom\)/)
    expect(rights).toMatch(/noaccess@e2e\.local\s+permission set No access/)
    expect(rights).toMatch(/defaulted@e2e\.local\s+the instance default set Recon operator/)
    expect(rights).toMatch(/denied@e2e\.local\s+.*2 denied permissions/)
    // Default member, Full admin, an expired deny and a grant change nothing.
    expect(rights).not.toMatch(/plain@|fulladmin@|root@/)
    // Not active: they hold nothing now and cannot sign in afterwards either.
    expect(rights).not.toMatch(/disabled@|invited@/)
    expect(rights).toMatch(/Every member can again use the five shared tools/)
    expect(rights).toMatch(/every admin can again manage the other admins/i)
  })

  test('with the permissions switch off the stored sets are not in force: the report says their rights do not change', async () => {
    const r = await downgrade(upgradedInstall(), { env: { RBAC_IDENTITY_ENABLED: 'true' } })
    const rights = sectionText(r, 'rights')
    expect(rights).toMatch(/analyst@e2e\.local/)
    expect(rights).toMatch(/RBAC_PERMISSIONS_ENABLED is off/)
  })

  test('disabled, invited and must-change accounts: who cannot sign in, and what a re-upgrade needs', async () => {
    const r = await downgrade()
    const signIn = sectionText(r, 'sign_in')
    expect(signIn).toMatch(/disabled@e2e\.local\s+disabled/)
    expect(signIn).toMatch(/invited@e2e\.local\s+invited/)
    expect(signIn).toMatch(/mustchange@e2e\.local\s+must change their password/)
    expect(signIn).toMatch(/reset-password/)
  })

  test('a revoked session or an account signed out everywhere: rotate AUTH_SECRET; none: no line', async () => {
    const r = await downgrade()
    const sessions = sectionText(r, 'sessions')
    expect(sessions).toMatch(/1 device session revoked/)
    expect(sessions).toMatch(/1 account signed out everywhere/)
    expect(sessions).toMatch(/AUTH_SECRET/)
    const quiet = upgradedInstall()
    quiet.user_sessions = []
    quiet.users = quiet.users.map((u) => ({ ...u, session_version: 0 }))
    expect(sectionText(await downgrade(quiet), 'sessions')).toBe('')
  })
})

describe('downgrade report: projects on an instance provider\'s model', () => {
  test('each project with its owner and fields, the other rows counted, and the SQL that resets them', async () => {
    const r = await downgrade()
    const text = sectionText(r, 'instance_models')
    expect(text).toMatch(/Shared project \(plain@e2e\.local\)\s+agent model/)
    expect(text).toMatch(/Own model \(analyst@e2e\.local\)\s+AI pipeline model, CypherFix model/)
    expect(text).not.toMatch(/Untouched/)
    expect(text).toMatch(/1 tradecraft resource/)
    expect(text).toMatch(/1 saved preset/)
    for (const s of instanceModelResetSql()) expect(text).toContain(s)
    expect(text).toMatch(/--downgrade-sql/)
  })

  test('no instance model anywhere: no section', async () => {
    const tables = upgradedInstall()
    tables.projects = tables.projects.slice(2)
    tables.user_tradecraft_resources = []
    tables.user_project_presets = []
    expect(sectionText(await downgrade(tables), 'instance_models')).toBe('')
  })
})

describe('downgrade report: the verdict and the re-upgrade', () => {
  test('sections in order; the backup, the lists and the re-upgrade always printed', async () => {
    expect(DOWNGRADE_SECTIONS.map((s: { id: string }) => s.id)).toEqual([
      'backup', 'tables', 'columns', 'rights', 'sign_in', 'sessions', 'instance_models', 'reupgrade',
    ])
    const r = await downgrade()
    expect(r.sections.map((s: { id: string }) => s.id)).toEqual(DOWNGRADE_SECTIONS.map((s: { id: string }) => s.id))
    const reup = sectionText(r, 'reupgrade')
    expect(reup).toMatch(/backfills run again/)
    expect(reup).toMatch(/Root/)
    expect(reup).toMatch(/pg_restore/)
    expect(r.review).toBe(true)
  })

  test('nothing to lose (no RBAC row, every column at its default): nothing to confirm', async () => {
    const r = await downgrade({ users: [account('root', { role: 'admin' })] }, { env: {} })
    expect(r.review).toBe(false)
    expect(r.sections.map((s: { id: string }) => s.id)).toEqual(['backup', 'tables', 'columns', 'reupgrade'])
    expect(r.text).toMatch(/Nothing is lost/)
  })

  test('control characters in stored names never reach the operator\'s terminal', async () => {
    const tables = upgradedInstall()
    tables.users.push(account('evil', { email: 'evil\u001b[2J@e2e.local', status: 'disabled' }))
    tables.projects.push({ id: 'p9', name: 'x\u001b]0;pwned\u0007y', user_id: 'evil', agent_openai_model: 'instance/a/b' })
    const r = await downgrade(tables)
    expect(r.text).not.toMatch(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/)
    expect(r.text).toContain('evil?[2J@e2e.local')
  })

  test('buildDowngradeReport is pure', async () => {
    const { prisma } = downgradeDb(upgradedInstall())
    const state = await readDowngradeState(prisma)
    expect(buildDowngradeReport(state, { env: SWITCHES_ON })).toEqual(buildDowngradeReport(state, { env: SWITCHES_ON }))
  })
})

describe('downgrade report: invocation', () => {
  test.each([
    [[], 'upgrade'], [['--downgrade'], 'downgrade'], [['--downgrade-sql'], 'downgrade-sql'],
    [['--down'], null], [['--downgrade', 'extra'], null], [['--preview'], null],
  ])('arguments %j -> %s', (argv, mode) => {
    expect(parseMode(argv)).toBe(mode)
  })

  const webapp = path.resolve(__dirname, '..')
  const script = path.join(webapp, 'scripts', 'rbac-upgrade-preview.mjs')
  const env = { ...process.env, DATABASE_URL: 'postgresql://nobody:nothing@127.0.0.1:1/none?connect_timeout=2' }

  test.each([['as a file'], ['fed on stdin']])('--downgrade runs %s and fails cleanly without a database', (how) => {
    const run = how === 'as a file'
      ? spawnSync(process.execPath, [script, '--downgrade'], { cwd: webapp, env, encoding: 'utf8', timeout: 60_000 })
      : spawnSync(process.execPath, ['--input-type=module', '-', '--downgrade'], {
        cwd: webapp, env, encoding: 'utf8', timeout: 60_000, input: readFileSync(script, 'utf8'),
      })
    expect(run.stderr).not.toMatch(/ERR_MODULE_NOT_FOUND|Cannot find module/)
    expect(run.stderr).toMatch(/\[rbac\] downgrade preview failed/)
    expect(run.stderr).not.toContain('nothing@')
    expect(run.status).toBe(1)
  })

  test('--downgrade-sql prints the reset statements without a database', () => {
    const run = spawnSync(process.execPath, [script, '--downgrade-sql'], { cwd: webapp, env, encoding: 'utf8', timeout: 60_000 })
    expect(run.status).toBe(0)
    expect(run.stdout.trim().split('\n')).toEqual(instanceModelResetSql())
  })

  test('an unknown argument is a usage error, never a report', () => {
    const run = spawnSync(process.execPath, [script, '--downgrad'], { cwd: webapp, env, encoding: 'utf8', timeout: 60_000 })
    expect(USAGE_EXIT).toBe(2)
    expect(run.status).toBe(USAGE_EXIT)
    expect(run.stderr).toMatch(/--downgrade/)
    expect(run.stdout).toBe('')
  })
})
