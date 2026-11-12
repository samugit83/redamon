/**
 * The upgrade preview (scripts/rbac-upgrade-preview.mjs, HD-31, DV-32): what the RBAC
 * hardening changes for the accounts of an install, printed by `./redamon.sh update`
 * between the build and the restart. It reads the live database in one read-only
 * transaction, works on the 7.7.x schema (no `users.legacy_grants`), and lists the legacy
 * grants exactly as scripts/backfill-rbac-legacy-grants.mjs will write them.
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
} from './rbac-upgrade-preview.mjs'

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
