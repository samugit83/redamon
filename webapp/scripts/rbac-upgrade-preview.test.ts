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

beforeEach(() => {
  db = createFakePrisma()
  t = T0
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
function sqlDb(opts: { legacyColumn?: boolean } = {}) {
  const legacyColumn = opts.legacyColumn ?? true
  const calls: string[] = []
  let transactions = 0
  const answer = (sql: string, params: unknown[]): Row[] => {
    if (!legacyColumn && /legacy_grants/.test(sql)) throw new Error('column "legacy_grants" does not exist')
    if (/^\s*SELECT now\(\)/i.test(sql)) return [{ now: new Date(t) }]
    if (/information_schema\.columns/.test(sql)) {
      return NEW_COLUMNS
        .filter((c: { table: string; column: string }) => legacyColumn || `${c.table}.${c.column}` !== 'users.legacy_grants')
        .filter((c: { table: string; column: string }) => params.includes(`${c.table}.${c.column}`))
        .map((c: { table: string; column: string }) => ({ table_name: c.table, column_name: c.column }))
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

async function report(opts: { legacyColumn?: boolean; env?: Record<string, string | undefined>; templateFiles?: number } = {}) {
  const { prisma } = sqlDb(opts)
  return previewRbacUpgrade(prisma, { env: opts.env ?? SCANNER_SET, templateFiles: opts.templateFiles ?? 0 })
}

/** What the preview says each account holds after the backfill, by id. */
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
    for (const c of NEW_COLUMNS) expect(c.step).toMatch(/^\d+\.\d+$/)
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
  test('a single-operator install: one line, nothing to confirm', async () => {
    user('root', { role: 'admin' })
    settings('root', { mcpServers: [stdio('admin-tool')] })
    user('managed-admin', { role: 'admin', password: '' })
    const r = await report()
    expect(r.review).toBe(false)
    expect(r.text.trim().split('\n')).toHaveLength(2)
    expect(r.text).toMatch(/nothing changes for existing accounts/i)
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

  test('the hardening already in place: one line, unless the scanner key is missing', async () => {
    user('alice')
    settings('alice', { mcpServers: [stdio('scraper')] })
    await backfillRbacLegacyGrants(db)
    const quiet = await report()
    expect(quiet.review).toBe(false)
    expect(quiet.text.trim().split('\n')).toHaveLength(2)
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
      'accounts', 'legacy_grants', 'tunnel_rows', 'stdio_mcp', 'mcp_token_env_var', 'scanner_key', 'member_changes',
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
