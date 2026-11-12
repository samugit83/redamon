/**
 * The conversion of the legacy grants at the first boot with the permissions switch on
 * (scripts/backfill-rbac-legacy-overrides.mjs, step 3.15, HD-02, OQ-26): a grant whose latest
 * review decision is Keep becomes an override grant of its platform permission, with the reason
 * "kept from 7.7.x" and a 90-day expiry; every other held grant lapses; `User.legacyGrants` is
 * never written, so a roll-back (the switch off) finds Phase 1's grants again. It runs under the
 * review's lock and the permission writers' lock, writes its marker with the overrides, and does
 * nothing with the switch off.
 *
 * The database is an in-memory double of the five calls the script makes (one transaction at a
 * time, rolled back when it throws); scripts/backfill-rbac-legacy-overrides.pg.integration.test.ts
 * runs it on a real Postgres.
 *
 * @vitest-environment node
 */
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

vi.mock('@/lib/prisma', () => ({ default: {}, prisma: {} }))

import {
  CHANGED_ACTION, KEEP_ACTION, KEEP_DAYS, KEPT_REASON, LEGACY_PERMISSION, MARKER_ACTION, PERMISSIONS_LOCK,
  REVIEW_LOCK, backfillRbacLegacyOverrides, permissionsSwitchOn, run,
} from '../../../scripts/backfill-rbac-legacy-overrides.mjs'
import {
  LEGACY_GRANTS as BACKFILL_GRANTS, LOCK_KEY as LEGACY_GRANTS_LOCK, REMOVE_ACTION as BACKFILL_REMOVE_ACTION,
} from '../../../scripts/backfill-rbac-legacy-grants.mjs'
import { rbacFlags, setFlagsForTests } from './flags'
import {
  KEPT_LEGACY_REASON, LEGACY_GRANT_PERMISSION, LEGACY_KEEP_DAYS, LEGACY_OVERRIDES_MARKER, legacyKeepExpiry,
} from './legacyOverrides'
import { KEEP_ACTION as REVIEW_KEEP_ACTION, LEGACY_GRANTS, LEGACY_GRANTS_LOCK_KEY, REMOVE_ACTION } from './updateReview'
import { PERMISSIONS_LOCK as WRITERS_LOCK } from './permissionAdmin'

type Row = Record<string, unknown>

const DAY = 86_400_000
const T0 = Date.parse('2026-11-12T08:00:00.000Z')
const ON = { RBAC_IDENTITY_ENABLED: 'true', RBAC_PERMISSIONS_ENABLED: 'true' } as unknown as NodeJS.ProcessEnv
const UPDATED = new Date('2026-03-01T09:00:00.000Z')

let t = T0
const clock = () => new Date(t)

/** Equality, `{not}`, `{in}` and `{hasSome}`: the filters the script sends. */
function matches(row: Row, where: Row = {}): boolean {
  for (const [k, cond] of Object.entries(where)) {
    const v = row[k]
    if (cond !== null && typeof cond === 'object' && !(cond instanceof Date)) {
      const c = cond as Row
      if ('not' in c && v === c.not) return false
      if ('in' in c && !(c.in as unknown[]).includes(v)) return false
      if ('hasSome' in c && !(Array.isArray(v) && (c.hasSome as unknown[]).some((x) => v.includes(x)))) return false
      continue
    }
    if (v !== cond) return false
  }
  return true
}

const pick = (row: Row, select?: Row): Row =>
  select ? Object.fromEntries(Object.keys(select).filter((k) => select[k]).map((k) => [k, structuredClone(row[k])])) : structuredClone(row)

function byOrder(rows: Row[], orderBy?: Row | Row[]): Row[] {
  const keys = (Array.isArray(orderBy) ? orderBy : orderBy ? [orderBy] : []).flatMap((o) => Object.entries(o))
  return [...rows].sort((a, b) => {
    for (const [k, dir] of keys) {
      const x = a[k] instanceof Date ? (a[k] as Date).getTime() : String(a[k])
      const y = b[k] instanceof Date ? (b[k] as Date).getTime() : String(b[k])
      if (x < y) return dir === 'asc' ? -1 : 1
      if (x > y) return dir === 'asc' ? 1 : -1
    }
    return 0
  })
}

function createDb() {
  let state = { users: [] as Row[], audit: [] as Row[], overrides: [] as Row[] }
  const locks: unknown[] = []
  const calls: string[] = []
  let seq = 0
  let failCreate: string | null = null
  let queue: Promise<unknown> = Promise.resolve()
  let transactions = 0

  const client = {
    $executeRaw: async (strings: TemplateStringsArray, ...values: unknown[]) => {
      const sql = strings.join('?')
      if (!/^SELECT pg_advisory_xact_lock\(hashtext\(\?\)\)$/.test(sql)) throw new Error(`raw SQL not supported: ${sql}`)
      locks.push(values[0])
      return 1
    },
    user: {
      findMany: async (a: { where?: Row; select?: Row; orderBy?: Row | Row[] }) => {
        calls.push('user.findMany')
        return byOrder(state.users.filter((u) => matches(u, a.where)), a.orderBy).map((u) => pick(u, a.select))
      },
    },
    auditLog: {
      findFirst: async (a: { where?: Row; select?: Row; orderBy?: Row | Row[] }) => {
        calls.push('auditLog.findFirst')
        const r = byOrder(state.audit.filter((x) => matches(x, a.where)), a.orderBy)[0]
        return r ? pick(r, a.select) : null
      },
      findMany: async (a: { where?: Row; select?: Row; orderBy?: Row | Row[] }) => {
        calls.push('auditLog.findMany')
        return byOrder(state.audit.filter((x) => matches(x, a.where)), a.orderBy).map((x) => pick(x, a.select))
      },
      create: async (a: { data: Row }) => {
        if (failCreate === a.data.action) throw new Error('audit insert failed')
        const row = { id: `a-${String(++seq).padStart(4, '0')}`, actorId: null, targetId: null, createdAt: clock(), ...a.data }
        state.audit.push(row)
        return row
      },
    },
    userPermissionOverride: {
      findMany: async (a: { where?: Row; select?: Row }) => {
        calls.push('userPermissionOverride.findMany')
        return state.overrides.filter((o) => matches(o, a.where)).map((o) => pick(o, a.select))
      },
      createMany: async (a: { data: Row[] }) => {
        for (const d of a.data) {
          if (state.overrides.some((o) => o.userId === d.userId && o.permission === d.permission)) throw new Error('P2002')
          state.overrides.push({ createdAt: clock(), ...d })
        }
        return { count: a.data.length }
      },
    },
  }
  const $transaction = <T>(fn: (tx: typeof client) => Promise<T>): Promise<T> => {
    const run = queue.then(async () => {
      transactions++
      const snapshot = structuredClone(state)
      try {
        return await fn(client)
      } catch (e) {
        state = snapshot
        throw e
      }
    })
    queue = run.catch(() => undefined)
    return run
  }
  return {
    ...client,
    $transaction,
    locks,
    calls,
    get transactions() { return transactions },
    failAuditCreate(action: string | null) { failCreate = action },
    member(id: string, legacyGrants: string[], role = 'standard') {
      state.users.push({ id, role, legacyGrants, updatedAt: UPDATED })
    },
    decide(action: string, targetId: string, grant: string, at: number, actorId = 'admin-1') {
      state.audit.push({
        id: `a-${String(++seq).padStart(4, '0')}`, action, targetType: 'user', targetId, actorId,
        after: { grant }, source: 'api', createdAt: new Date(at),
      })
    },
    audit: (action: string) => state.audit.filter((r) => r.action === action).map((r) => structuredClone(r)),
    seedAudit(row: Row) { state.audit.push({ id: `a-${String(++seq).padStart(4, '0')}`, ...row }) },
    overrides: () => state.overrides.map((o) => structuredClone(o)),
    seedOverride(row: Row) { state.overrides.push({ expiresAt: null, reason: null, grantedById: 'root-1', createdAt: new Date(0), ...row }) },
    users: () => state.users.map((u) => structuredClone(u)),
  }
}

let db: ReturnType<typeof createDb>
const convert = (env: NodeJS.ProcessEnv = ON) => backfillRbacLegacyOverrides(db as never, env, { now: clock })
const markers = () => db.audit(MARKER_ACTION)

beforeEach(() => {
  db = createDb()
  t = T0
})
afterEach(() => {
  setFlagsForTests(null)
  vi.unstubAllEnvs()
  vi.restoreAllMocks()
})

describe('the constants', () => {
  test('equal the review, the legacy-grants backfill, the permission writers and the resolution', () => {
    expect(MARKER_ACTION).toBe('system.rbac_legacy_overrides_backfill')
    expect(LEGACY_OVERRIDES_MARKER).toBe(MARKER_ACTION)
    expect(KEPT_REASON).toBe('kept from 7.7.x')
    expect(KEPT_LEGACY_REASON).toBe(KEPT_REASON)
    expect(KEEP_DAYS).toBe(90)
    expect(LEGACY_KEEP_DAYS).toBe(KEEP_DAYS)
    expect(LEGACY_PERMISSION).toEqual({
      kali_terminal: 'platform:kali_terminal', shell_sessions: 'platform:shell_sessions', tunnels: 'platform:tunnels',
    })
    expect(Object.fromEntries(LEGACY_GRANT_PERMISSION)).toEqual(LEGACY_PERMISSION)
    expect(Object.keys(LEGACY_PERMISSION)).toEqual(BACKFILL_GRANTS)
    expect(Object.keys(LEGACY_PERMISSION)).toEqual([...LEGACY_GRANTS])
    expect(KEEP_ACTION).toBe(REVIEW_KEEP_ACTION)
    expect(BACKFILL_REMOVE_ACTION).toBe(REMOVE_ACTION)
    expect(REVIEW_LOCK).toBe(LEGACY_GRANTS_LOCK)
    expect(REVIEW_LOCK).toBe(LEGACY_GRANTS_LOCK_KEY)
    expect(PERMISSIONS_LOCK).toBe(WRITERS_LOCK)
    expect(legacyKeepExpiry(new Date(T0)).getTime()).toBe(T0 + KEEP_DAYS * DAY)
  })

  test('the change action is the one the account permission writer records', () => {
    const writer = readFileSync(path.resolve(__dirname, 'userPermissionAdmin.ts'), 'utf8')
    expect(CHANGED_ACTION).toBe('user.permissions_changed')
    expect(writer).toContain(`action: '${CHANGED_ACTION}'`)
  })
})

describe('the switch', () => {
  const VALUES: [string | undefined, string | undefined][] = [
    [undefined, undefined], ['true', 'true'], ['true', undefined], [undefined, 'true'], ['false', 'true'],
    [' YES ', '1'], ['1', 'TRUE'], ['yes', 'yes'], ['true', 'on'], ['true', 'maybe'], ['On', 'true'], ['true', '0'],
  ]

  test('on only with identity and permissions on, parsed as flags.ts reads them (permissions needs identity)', () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    for (const [identity, permissions] of VALUES) {
      const env: Record<string, string> = {}
      if (identity !== undefined) env.RBAC_IDENTITY_ENABLED = identity
      if (permissions !== undefined) env.RBAC_PERMISSIONS_ENABLED = permissions
      vi.stubEnv('RBAC_IDENTITY_ENABLED', identity ?? '')
      vi.stubEnv('RBAC_PERMISSIONS_ENABLED', permissions ?? '')
      setFlagsForTests(null)
      expect([identity, permissions, permissionsSwitchOn(env as NodeJS.ProcessEnv)])
        .toEqual([identity, permissions, rbacFlags().permissions])
    }
  })

  test('switch off → the script does nothing: no transaction, no lock, no read, no row', async () => {
    db.member('m-1', ['kali_terminal'])
    db.decide(KEEP_ACTION, 'm-1', 'kali_terminal', T0 - DAY)
    for (const env of [{}, { RBAC_IDENTITY_ENABLED: 'true' }, { RBAC_PERMISSIONS_ENABLED: 'true' }]) {
      expect(await convert(env as NodeJS.ProcessEnv)).toEqual({ ran: false })
    }
    const log = vi.spyOn(console, 'log').mockImplementation(() => {})
    const err = vi.spyOn(console, 'error').mockImplementation(() => {})
    await run(db as never, { RBAC_IDENTITY_ENABLED: 'true' } as unknown as NodeJS.ProcessEnv, { now: clock })
    expect(log).not.toHaveBeenCalled()
    expect(err).not.toHaveBeenCalled()
    expect(db.transactions).toBe(0)
    expect(db.locks).toEqual([])
    expect(db.calls).toEqual([])
    expect(db.overrides()).toEqual([])
    expect(markers()).toEqual([])
  })
})

describe('the conversion', () => {
  test('kept → override grant with the reason and a 90-day expiry, given by the admin who kept it', async () => {
    db.member('m-1', ['kali_terminal', 'shell_sessions'])
    db.decide(KEEP_ACTION, 'm-1', 'kali_terminal', T0 - 3 * DAY, 'admin-7')
    const out = await convert()
    expect(db.overrides()).toEqual([{
      userId: 'm-1', permission: 'platform:kali_terminal', effect: 'grant', reason: 'kept from 7.7.x',
      expiresAt: new Date(T0 + 90 * DAY), grantedById: 'admin-7', createdAt: new Date(T0),
    }])
    expect(out).toMatchObject({ ran: true, marker: true, converted: 1, lapsed: 1 })
  })

  test('each grant becomes its own platform permission', async () => {
    db.member('m-1', ['kali_terminal', 'shell_sessions', 'tunnels'])
    for (const g of ['kali_terminal', 'shell_sessions', 'tunnels']) db.decide(KEEP_ACTION, 'm-1', g, T0 - DAY)
    await convert()
    expect(db.overrides().map((o) => o.permission).sort())
      .toEqual(['platform:kali_terminal', 'platform:shell_sessions', 'platform:tunnels'])
  })

  test('undecided → lapsed: no override, counted', async () => {
    db.member('m-1', ['kali_terminal', 'shell_sessions'])
    db.member('m-2', ['tunnels'])
    expect(await convert()).toMatchObject({ converted: 0, lapsed: 3 })
    expect(db.overrides()).toEqual([])
  })

  test('removed → nothing: the grant left the column with its Remove, so nothing is converted or counted', async () => {
    db.member('m-1', ['shell_sessions'])
    db.decide(REMOVE_ACTION, 'm-1', 'kali_terminal', T0 - 2 * DAY)
    expect(await convert()).toMatchObject({ converted: 0, lapsed: 1 })
    expect(db.overrides()).toEqual([])
  })

  test('the latest decision counts: a Remove after a Keep is no Keep', async () => {
    db.member('m-1', ['kali_terminal'])
    db.decide(KEEP_ACTION, 'm-1', 'kali_terminal', T0 - 5 * DAY)
    db.decide(REMOVE_ACTION, 'm-1', 'kali_terminal', T0 - 4 * DAY)
    expect(await convert()).toMatchObject({ converted: 0, lapsed: 1 })
    expect(db.overrides()).toEqual([])
  })

  test('another account\'s decision, or one on another grant, keeps nothing', async () => {
    db.member('m-1', ['kali_terminal'])
    db.member('m-2', ['shell_sessions'])
    db.decide(KEEP_ACTION, 'm-2', 'kali_terminal', T0 - DAY)
    db.decide(KEEP_ACTION, 'm-1', 'shell_sessions', T0 - DAY)
    expect(await convert()).toMatchObject({ converted: 0, lapsed: 2 })
  })

  test('User.legacyGrants is never written: with the switch off again Phase 1 rules find them (roll-back)', async () => {
    db.member('m-1', ['kali_terminal', 'shell_sessions'])
    db.decide(KEEP_ACTION, 'm-1', 'kali_terminal', T0 - DAY)
    const before = db.users()
    await convert()
    expect(db.users()).toEqual(before)
  })

  test('admins are not converted (their tools come from their profile; an override cannot carry them)', async () => {
    db.member('adm', ['kali_terminal'], 'admin')
    db.decide(KEEP_ACTION, 'adm', 'kali_terminal', T0 - DAY)
    expect(await convert()).toMatchObject({ converted: 0, lapsed: 0 })
    expect(db.overrides()).toEqual([])
  })

  test('an override already standing for that permission is left as it is (a person set it)', async () => {
    db.member('m-1', ['kali_terminal', 'tunnels'])
    db.decide(KEEP_ACTION, 'm-1', 'kali_terminal', T0 - DAY)
    db.decide(KEEP_ACTION, 'm-1', 'tunnels', T0 - DAY)
    db.seedOverride({ userId: 'm-1', permission: 'platform:kali_terminal', effect: 'deny' })
    db.seedOverride({ userId: 'm-1', permission: 'platform:tunnels', effect: 'grant', expiresAt: new Date(T0 + 400 * DAY) })
    expect(await convert()).toMatchObject({ converted: 0, overridden: 2 })
    expect(db.overrides().map((o) => [o.permission, o.effect, o.reason])).toEqual([
      ['platform:kali_terminal', 'deny', null], ['platform:tunnels', 'grant', null],
    ])
  })

  test('the marker records the counts, under the review lock then the permission writers\' lock', async () => {
    db.member('m-1', ['kali_terminal', 'shell_sessions', 'tunnels'])
    db.member('m-2', ['kali_terminal'])
    db.decide(KEEP_ACTION, 'm-1', 'kali_terminal', T0 - DAY)
    db.decide(KEEP_ACTION, 'm-1', 'tunnels', T0 - DAY)
    await convert()
    expect(markers()).toEqual([expect.objectContaining({
      action: MARKER_ACTION, targetType: 'system', source: 'system', actorId: null,
      after: {
        converted: 2, lapsed: 2, overridden: 0, superseded: 0, expired: 0,
        kali_terminal: 1, shell_sessions: 0, tunnels: 1, expiresAt: new Date(T0 + 90 * DAY).toISOString(),
      },
    })])
    expect(db.locks).toEqual([REVIEW_LOCK, PERMISSIONS_LOCK])
  })

  test('the first conversion writes its marker even when nothing was kept: from then on the column no longer counts', async () => {
    db.member('m-1', ['kali_terminal'])
    expect(await convert()).toMatchObject({ marker: true, converted: 0, lapsed: 1 })
    expect(markers()).toHaveLength(1)
    expect(await convert()).toMatchObject({ marker: false, converted: 0 })
    expect(markers()).toHaveLength(1)
  })

  test('a failed write leaves no override and no marker (one transaction), and the next boot converts', async () => {
    db.member('m-1', ['kali_terminal'])
    db.decide(KEEP_ACTION, 'm-1', 'kali_terminal', T0 - DAY)
    db.failAuditCreate(MARKER_ACTION)
    await expect(convert()).rejects.toThrow('audit insert failed')
    expect(db.overrides()).toEqual([])
    expect(markers()).toEqual([])
    db.failAuditCreate(null)
    expect(await convert()).toMatchObject({ converted: 1 })
  })
})

describe('idempotent', () => {
  test('a second boot writes nothing and no second marker', async () => {
    db.member('m-1', ['kali_terminal', 'shell_sessions'])
    db.decide(KEEP_ACTION, 'm-1', 'kali_terminal', T0 - DAY)
    await convert()
    const overrides = db.overrides()
    t = T0 + DAY
    expect(await convert()).toMatchObject({ marker: false, converted: 0, overridden: 1, lapsed: 1 })
    expect(db.overrides()).toEqual(overrides)
    expect(markers()).toHaveLength(1)
  })

  test('two webapp copies booting together convert once', async () => {
    db.member('m-1', ['kali_terminal'])
    db.decide(KEEP_ACTION, 'm-1', 'kali_terminal', T0 - DAY)
    const [a, b] = await Promise.all([convert(), convert()])
    expect([a.converted, b.converted].sort()).toEqual([0, 1])
    expect(db.overrides()).toHaveLength(1)
    expect(markers()).toHaveLength(1)
  })

  test('a downgrade dropped the overrides: the next boot writes them again, ending when the first ones did', async () => {
    db.member('m-1', ['kali_terminal'])
    db.decide(KEEP_ACTION, 'm-1', 'kali_terminal', T0 - DAY)
    db.seedAudit({ action: MARKER_ACTION, targetType: 'system', source: 'system', createdAt: new Date(T0), after: {} })
    t = T0 + 20 * DAY
    expect(await convert()).toMatchObject({ marker: true, converted: 1 })
    expect(db.overrides()[0].expiresAt).toEqual(new Date(T0 + 90 * DAY))
  })

  test('after the 90 days nothing comes back', async () => {
    db.member('m-1', ['kali_terminal'])
    db.decide(KEEP_ACTION, 'm-1', 'kali_terminal', T0 - DAY)
    db.seedAudit({ action: MARKER_ACTION, targetType: 'system', source: 'system', createdAt: new Date(T0), after: {} })
    t = T0 + 90 * DAY
    expect(await convert()).toMatchObject({ marker: false, converted: 0, expired: 1 })
    expect(db.overrides()).toEqual([])
  })

  test('a person who changed the account\'s permissions after the Keep decides: it is not converted again', async () => {
    db.member('m-1', ['kali_terminal', 'tunnels'])
    db.decide(KEEP_ACTION, 'm-1', 'kali_terminal', T0 - 3 * DAY)
    db.decide(KEEP_ACTION, 'm-1', 'tunnels', T0 - DAY)
    db.seedAudit({ action: MARKER_ACTION, targetType: 'system', source: 'system', createdAt: new Date(T0 - 2 * DAY), after: {} })
    db.seedAudit({ action: CHANGED_ACTION, targetType: 'user', targetId: 'm-1', createdAt: new Date(T0 - 2 * DAY + 1000) })
    expect(await convert()).toMatchObject({ converted: 1, superseded: 1 })
    expect(db.overrides().map((o) => o.permission)).toEqual(['platform:tunnels'])
  })

  test('a Keep decided after the first conversion (the switch off meanwhile) gets its own 90 days', async () => {
    db.member('m-1', ['kali_terminal'])
    db.seedAudit({ action: MARKER_ACTION, targetType: 'system', source: 'system', createdAt: new Date(T0 - 30 * DAY), after: {} })
    db.decide(KEEP_ACTION, 'm-1', 'kali_terminal', T0 - 10 * DAY)
    expect(await convert()).toMatchObject({ marker: true, converted: 1 })
    expect(db.overrides()[0].expiresAt).toEqual(new Date(T0 - 10 * DAY + 90 * DAY))
  })
})

describe('run (the entrypoint)', () => {
  test('logs the counts and the end date, never an address', async () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {})
    db.member('m-1', ['kali_terminal', 'shell_sessions'])
    db.decide(KEEP_ACTION, 'm-1', 'kali_terminal', T0 - DAY)
    await run(db as never, ON, { now: clock })
    expect(log.mock.calls.map((c) => c.join(' '))).toEqual([
      '[rbac] legacy grants converted: 1 kept grant(s) became override(s) ending 2027-02-10T08:00:00.000Z, 1 lapsed (0 already overridden, 0 changed since, 0 past their 90 days).',
    ])
    log.mockClear()
    await run(db as never, ON, { now: clock })
    expect(log).not.toHaveBeenCalled()
  })

  test('never throws; a failure is logged with its reason and retried next boot', async () => {
    const err = vi.spyOn(console, 'error').mockImplementation(() => {})
    const broken = { $transaction: async () => { throw new Error('canceling statement due to lock timeout') } }
    await expect(run(broken as never, ON, { now: clock })).resolves.toBeUndefined()
    expect(err).toHaveBeenCalledWith(
      '[rbac] could not convert the legacy grants (retried next boot):', 'canceling statement due to lock timeout')
  })
})

describe('the startup lists', () => {
  const dockerfile = readFileSync(path.resolve(__dirname, '../../../Dockerfile'), 'utf8')

  test('the entrypoint runs it after db push and the Root backfill, before the server, never fatally', () => {
    const entry = dockerfile.split('\n').find((l) => l.startsWith('RUN printf') && l.includes('entrypoint'))!
    const push = entry.indexOf('db push')
    const grants = entry.indexOf('backfill-rbac-legacy-grants.mjs')
    const root = entry.indexOf('backfill-rbac-root.mjs')
    const ours = entry.indexOf('backfill-rbac-legacy-overrides.mjs')
    const server = entry.indexOf('exec node server.js')
    expect(push).toBeGreaterThan(0)
    expect(grants).toBeGreaterThan(push)
    expect(root).toBeGreaterThan(grants)
    expect(ours).toBeGreaterThan(root)
    expect(server).toBeGreaterThan(ours)
    expect(entry).toMatch(/\\nnode scripts\/backfill-rbac-legacy-overrides\.mjs 2>&1\\nexec node server\.js/)
  })

  test('the dev command runs it in the same place', () => {
    const dev = readFileSync(path.resolve(__dirname, '../../../../docker-compose.dev.yml'), 'utf8')
    const lines = dev.split('\n').map((l) => l.trim())
    const root = lines.indexOf('node scripts/backfill-rbac-root.mjs')
    expect(root).toBeGreaterThan(0)
    expect(lines[root + 1]).toBe('node scripts/backfill-rbac-legacy-overrides.mjs')
    expect(lines[root + 2]).toBe('npm run dev')
  })
})
