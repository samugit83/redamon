/**
 * The boot-time recognition of the instance's Root (scripts/backfill-rbac-root.mjs, step
 * 2.5, ID-09, ID-02, DV-26, master §14.4 step 1): nothing when an existing admin is Root;
 * else the only admin with a password, or the oldest of several (createdAt, then id), marked
 * automatic and unconfirmed, with its `system.rbac_root_assigned` row in the same
 * transaction; no candidate, no Root. A Root id that names no account, or an account that is
 * no longer an admin, is no Root. The assignment is a conditional update under the host
 * commands' advisory lock, so two copies booting together choose one Root.
 *
 * Prisma is an in-memory double whose `pg_advisory_xact_lock` serializes two transactions
 * and whose transaction rolls back its own writes when the callback throws.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/authz/root.backfill.test.ts
 * @vitest-environment node
 */
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { describe, test, expect, beforeEach, vi } from 'vitest'
import {
  ASSIGNED_ACTION, CANDIDATE_ORDER, CANDIDATE_WHERE, LOCK_KEY, SINGLETON_ID, backfillRbacRoot, chooseRoot, run,
} from '../../../scripts/backfill-rbac-root.mjs'

type Row = Record<string, unknown>
type Where = Record<string, unknown>

const PW = '$2a$12$hash'
const T = (day: number) => new Date(Date.UTC(2026, 0, day, 9))

function matches(row: Row, where: Where | undefined): boolean {
  if (!where) return true
  return Object.entries(where).every(([k, cond]) => {
    if (cond && typeof cond === 'object' && !Array.isArray(cond) && !(cond instanceof Date)) {
      const c = cond as { not?: unknown }
      if ('not' in c) return row[k] !== c.not
      throw new Error(`fake: unsupported condition on ${k}`)
    }
    return cond === null ? row[k] === null || row[k] === undefined : row[k] === cond
  })
}

const pick = (row: Row, select?: Row) =>
  select ? Object.fromEntries(Object.keys(select).map((k) => [k, structuredClone(row[k])])) : structuredClone(row)

class FakeDb {
  users: Row[] = []
  instance: Row | null = null
  audit: Row[] = []
  locks: string[] = []
  userWrites = 0
  failAudit = false
  /** Runs once, right before the conditional update: another writer moving the row. */
  beforeUpdate: (() => void) | null = null
  private lockTail = new Map<string, Promise<void>>()

  async $transaction<T>(fn: (tx: unknown) => Promise<T>, opts?: unknown): Promise<T> {
    expect(opts).toEqual({ timeout: 60_000, maxWait: 30_000 })
    const snapshot = { instance: structuredClone(this.instance), audit: [...this.audit] }
    const releases: (() => void)[] = []
    const refuse = async () => { this.userWrites++; throw new Error('the backfill never writes a user row') }
    const tx = {
      $executeRaw: async (strings: TemplateStringsArray, ...values: unknown[]) => {
        expect(strings.join('?')).toBe('SELECT pg_advisory_xact_lock(hashtext(?))')
        const key = String(values[0])
        this.locks.push(key)
        const prev = this.lockTail.get(key) ?? Promise.resolve()
        let release!: () => void
        const held = new Promise<void>((r) => { release = r })
        this.lockTail.set(key, prev.then(() => held))
        releases.push(release)
        await prev
        return 1
      },
      user: {
        findUnique: async ({ where, select }: { where: { id: string }; select?: Row }) => {
          await Promise.resolve()
          const r = this.users.find((u) => u.id === where.id)
          return r ? pick(r, select) : null
        },
        findMany: async ({ where, orderBy, select }: { where: Where; orderBy: unknown; select?: Row }) => {
          expect(orderBy).toEqual([{ createdAt: 'asc' }, { id: 'asc' }])
          await Promise.resolve()
          return this.users.filter((u) => matches(u, where))
            .sort((a, b) => (a.createdAt as Date).getTime() - (b.createdAt as Date).getTime()
              || String(a.id).localeCompare(String(b.id)))
            .map((u) => pick(u, select))
        },
        update: refuse, updateMany: refuse, create: refuse, upsert: refuse, delete: refuse,
      },
      instanceSettings: {
        findUnique: async ({ where, select }: { where: { id: string }; select?: Row }) => {
          expect(where).toEqual({ id: SINGLETON_ID })
          await Promise.resolve()
          return this.instance ? pick(this.instance, select) : null
        },
        createMany: async ({ data, skipDuplicates }: { data: Row[]; skipDuplicates: boolean }) => {
          expect(skipDuplicates).toBe(true)
          expect(data).toEqual([{ id: SINGLETON_ID }])
          if (this.instance) return { count: 0 }
          this.instance = { id: SINGLETON_ID, rootUserId: null, rootConfirmedAt: null, rootAssignedBy: null,
            pendingRootTransferTo: null, pendingRootTransferExpires: null, tunnelsEnabled: false, updatedById: null }
          return { count: 1 }
        },
        updateMany: async ({ where, data }: { where: Where; data: Row }) => {
          if (this.beforeUpdate) { const f = this.beforeUpdate; this.beforeUpdate = null; f() }
          await Promise.resolve()
          if (!this.instance || !matches(this.instance, where)) return { count: 0 }
          this.instance = { ...this.instance, ...structuredClone(data) }
          return { count: 1 }
        },
        upsert: async () => { throw new Error('the Root columns are written by a conditional update only') },
        update: async () => { throw new Error('the Root columns are written by a conditional update only') },
      },
      auditLog: {
        create: async ({ data }: { data: Row }) => {
          if (this.failAudit) throw new Error('audit insert failed')
          this.audit.push(structuredClone(data))
          return data
        },
      },
    }
    try {
      return await fn(tx)
    } catch (err) {
      this.instance = snapshot.instance
      this.audit = snapshot.audit
      throw err
    } finally {
      for (const r of releases) r()
    }
  }
}

let db: FakeDb

function account(id: string, role: string, createdAt: Date, password = PW) {
  db.users.push({ id, email: `${id}@e2e.local`, role, password, createdAt })
}
const assigned = () => db.audit.filter((r) => r.action === ASSIGNED_ACTION)
const rootOf = () => db.instance && {
  rootUserId: db.instance.rootUserId, confirmed: db.instance.rootConfirmedAt !== null, by: db.instance.rootAssignedBy,
}

beforeEach(() => {
  db = new FakeDb()
})

describe('backfillRbacRoot', () => {
  test('exports the lock key the host commands take, the action and the candidate rule', () => {
    expect(LOCK_KEY).toBe('rbac-root')
    expect(ASSIGNED_ACTION).toBe('system.rbac_root_assigned')
    expect(SINGLETON_ID).toBe('instance')
    expect(CANDIDATE_WHERE).toEqual({ role: 'admin', password: { not: '' } })
    expect(CANDIDATE_ORDER).toEqual([{ createdAt: 'asc' }, { id: 'asc' }])
  })

  test('one: the only admin with a password becomes Root, automatic and unconfirmed, audited', async () => {
    account('adm', 'admin', T(5))
    account('mem', 'standard', T(1))
    const out = await backfillRbacRoot(db)
    expect(out).toEqual({ assigned: true, userId: 'adm', rule: 'only_admin', candidateCount: 1 })
    expect(rootOf()).toEqual({ rootUserId: 'adm', confirmed: false, by: 'automatic' })
    expect(assigned()).toEqual([{
      action: ASSIGNED_ACTION, targetType: 'user', targetId: 'adm', source: 'system',
      after: { userId: 'adm', rule: 'only_admin', candidateCount: 1 },
    }])
    expect(db.locks).toEqual(['rbac-root'])
    expect(db.userWrites).toBe(0)
  })

  test('several: the oldest admin with a password (createdAt, then id)', async () => {
    account('adm-a', 'admin', T(15))
    account('adm-c', 'admin', T(5))
    account('adm-b', 'admin', T(10))
    expect(await backfillRbacRoot(db)).toEqual({ assigned: true, userId: 'adm-c', rule: 'oldest_admin', candidateCount: 3 })
    expect(rootOf()).toEqual({ rootUserId: 'adm-c', confirmed: false, by: 'automatic' })
  })

  test('several created in the same instant: the lowest id', async () => {
    account('adm-z', 'admin', T(5))
    account('adm-m', 'admin', T(5))
    expect((await backfillRbacRoot(db)).userId).toBe('adm-m')
  })

  test('none: no admin at all, no Root, no row, no audit', async () => {
    account('mem', 'standard', T(1))
    expect(await backfillRbacRoot(db)).toEqual({ assigned: false, rootUserId: null, candidateCount: 0 })
    expect(db.instance).toBeNull()
    expect(db.audit).toEqual([])
  })

  test('only passwordless admins: none (they can never sign in)', async () => {
    account('adm-a', 'admin', T(1), '')
    account('adm-b', 'admin', T(2), '')
    account('mem', 'standard', T(3))
    expect(await backfillRbacRoot(db)).toEqual({ assigned: false, rootUserId: null, candidateCount: 0 })
    expect(db.audit).toEqual([])
  })

  test('already set: an existing admin stays Root, confirmed or not, even if not the oldest', async () => {
    account('old', 'admin', T(1))
    account('host-root', 'admin', T(9))
    db.instance = { id: SINGLETON_ID, rootUserId: 'host-root', rootConfirmedAt: T(10), rootAssignedBy: 'host' }
    expect(await backfillRbacRoot(db)).toEqual({ assigned: false, rootUserId: 'host-root' })
    expect(rootOf()).toEqual({ rootUserId: 'host-root', confirmed: true, by: 'host' })
    db.instance.rootConfirmedAt = null
    db.instance.rootAssignedBy = 'automatic'
    expect(await backfillRbacRoot(db)).toEqual({ assigned: false, rootUserId: 'host-root' })
    expect(db.audit).toEqual([])
  })

  test('idempotent: a second boot changes nothing and writes no second row', async () => {
    account('adm', 'admin', T(1))
    await backfillRbacRoot(db)
    const after = structuredClone(db.instance)
    expect(await backfillRbacRoot(db)).toEqual({ assigned: false, rootUserId: 'adm' })
    expect(db.instance).toEqual(after)
    expect(assigned()).toHaveLength(1)
  })

  test('concurrent: two copies booting together choose one Root and write one row', async () => {
    account('adm-a', 'admin', T(1))
    account('adm-b', 'admin', T(2))
    const results = await Promise.all([backfillRbacRoot(db), backfillRbacRoot(db), backfillRbacRoot(db)])
    expect(results.filter((r) => r.assigned)).toHaveLength(1)
    expect(results.filter((r) => !r.assigned)).toEqual([
      { assigned: false, rootUserId: 'adm-a' }, { assigned: false, rootUserId: 'adm-a' },
    ])
    expect(rootOf()).toEqual({ rootUserId: 'adm-a', confirmed: false, by: 'automatic' })
    expect(assigned()).toHaveLength(1)
    expect(db.locks).toEqual(['rbac-root', 'rbac-root', 'rbac-root'])
  })

  test('a Root id that names no account is no Root: chosen again, the stale id recorded, a pending transfer dropped', async () => {
    account('adm', 'admin', T(1))
    db.instance = {
      id: SINGLETON_ID, rootUserId: 'gone', rootConfirmedAt: T(2), rootAssignedBy: 'host',
      pendingRootTransferTo: 'adm', pendingRootTransferExpires: T(3), tunnelsEnabled: true,
    }
    expect(await backfillRbacRoot(db)).toEqual({ assigned: true, userId: 'adm', rule: 'only_admin', candidateCount: 1 })
    expect(db.instance).toEqual({
      id: SINGLETON_ID, rootUserId: 'adm', rootConfirmedAt: null, rootAssignedBy: 'automatic',
      pendingRootTransferTo: null, pendingRootTransferExpires: null, tunnelsEnabled: true,
    })
    expect(assigned()[0].after).toEqual({ userId: 'adm', rule: 'only_admin', candidateCount: 1, previousRootUserId: 'gone' })
  })

  test('a Root that is no longer an admin (demoted while the switch was off) is no Root either', async () => {
    account('was-root', 'standard', T(1))
    account('adm', 'admin', T(2))
    db.instance = { id: SINGLETON_ID, rootUserId: 'was-root', rootConfirmedAt: null, rootAssignedBy: 'automatic' }
    expect((await backfillRbacRoot(db)).userId).toBe('adm')
    expect(rootOf()).toEqual({ rootUserId: 'adm', confirmed: false, by: 'automatic' })
  })

  test('a stale Root and no candidate: nothing is written (readers already treat it as no Root)', async () => {
    db.instance = { id: SINGLETON_ID, rootUserId: 'gone', rootConfirmedAt: null, rootAssignedBy: 'automatic' }
    expect(await backfillRbacRoot(db)).toEqual({ assigned: false, rootUserId: null, candidateCount: 0 })
    expect(db.instance.rootUserId).toBe('gone')
    expect(db.audit).toEqual([])
  })

  test('the instance settings row the earlier backfill wrote keeps every other value', async () => {
    account('adm', 'admin', T(1))
    db.instance = { id: SINGLETON_ID, rootUserId: null, rootConfirmedAt: null, rootAssignedBy: null,
      tunnelsEnabled: true, ngrokAuthtoken: 'fake-ngrok', updatedById: null }
    await backfillRbacRoot(db)
    expect(db.instance).toMatchObject({ tunnelsEnabled: true, ngrokAuthtoken: 'fake-ngrok', updatedById: null, rootUserId: 'adm' })
  })

  test('no row yet: it is created with its defaults (never overwriting one), then Root is set', async () => {
    account('adm', 'admin', T(1))
    await backfillRbacRoot(db)
    expect(rootOf()).toEqual({ rootUserId: 'adm', confirmed: false, by: 'automatic' })
  })

  test('a writer that moved the Root without the lock wins: conditional update, no row written', async () => {
    account('adm', 'admin', T(1))
    account('other', 'admin', T(2))
    db.instance = { id: SINGLETON_ID, rootUserId: null, rootConfirmedAt: null, rootAssignedBy: null }
    db.beforeUpdate = () => { db.instance!.rootUserId = 'other'; db.instance!.rootAssignedBy = 'transfer' }
    expect(await backfillRbacRoot(db)).toEqual({ assigned: false, rootUserId: null, candidateCount: 2, raced: true })
    expect(rootOf()).toEqual({ rootUserId: 'other', confirmed: false, by: 'transfer' })
    expect(db.audit).toEqual([])
  })

  test('a failed audit write rolls the assignment back: no Root without its row', async () => {
    account('adm', 'admin', T(1))
    db.instance = { id: SINGLETON_ID, rootUserId: null, rootConfirmedAt: null, rootAssignedBy: null }
    db.failAudit = true
    await expect(backfillRbacRoot(db)).rejects.toThrow('audit insert failed')
    expect(db.instance.rootUserId).toBeNull()
    db.failAudit = false
    expect((await backfillRbacRoot(db)).assigned).toBe(true)
  })

  test('a downgrade dropped the table while the row survives: the next boot assigns again', async () => {
    account('adm', 'admin', T(1))
    await backfillRbacRoot(db)
    db.instance = null
    expect((await backfillRbacRoot(db)).assigned).toBe(true)
    expect(assigned()).toHaveLength(2)
  })
})

describe('chooseRoot', () => {
  test('one, several, none', () => {
    expect(chooseRoot([{ id: 'a' }])).toEqual({ userId: 'a', rule: 'only_admin', candidateCount: 1 })
    expect(chooseRoot([{ id: 'a' }, { id: 'b' }])).toEqual({ userId: 'a', rule: 'oldest_admin', candidateCount: 2 })
    expect(chooseRoot([])).toBeNull()
  })
})

describe('run (the entrypoint)', () => {
  test('never throws; a failure is logged with its reason and retried next boot', async () => {
    const err = vi.spyOn(console, 'error').mockImplementation(() => {})
    const broken = { $transaction: async () => { throw new Error('canceling statement due to lock timeout') } }
    await expect(run(broken)).resolves.toBeUndefined()
    expect(err).toHaveBeenCalledWith(
      '[rbac] could not recognise the Root (retried next boot):', 'canceling statement due to lock timeout')
    err.mockRestore()
  })

  test('logs the choice by account id (never an address), or that there is no Root yet', async () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {})
    account('adm-a', 'admin', T(1))
    account('adm-b', 'admin', T(2))
    await run(db)
    expect(log.mock.calls.map((c) => c.join(' '))).toEqual([
      '[rbac] Root chosen automatically: user adm-a, the oldest of 2 admins with a password; unconfirmed until the host confirms it (./redamon.sh update or ./redamon.sh set-root <email>).',
    ])
    expect(JSON.stringify(log.mock.calls)).not.toContain('@')
    log.mockClear()
    await run(db)
    expect(log).not.toHaveBeenCalled()
    db = new FakeDb()
    await run(db)
    expect(log.mock.calls.map((c) => c.join(' '))).toEqual([
      '[rbac] this instance has no Root yet: no admin has a password (./redamon.sh create-admin makes one, and it becomes Root).',
    ])
    log.mockRestore()
  })
})

describe('agreement with the host commands (step 2.7)', () => {
  const script = (name: string) => readFileSync(path.resolve(__dirname, '../../../scripts', name), 'utf8')

  test('create-admin and set-root take the same advisory lock', () => {
    expect(script('create-admin.mjs')).toContain("pg_advisory_xact_lock(hashtext('rbac-root'))")
    expect(script('set-root.mjs')).toContain("pg_advisory_xact_lock(hashtext('rbac-root'))")
  })

  test('check-root lists the same candidates in the same order', () => {
    expect(script('check-root.mjs').replace(/\s+/g, ' '))
      .toContain("SELECT email FROM users WHERE role = 'admin' AND password <> '' ORDER BY created_at, id")
  })
})

describe('the startup lists', () => {
  const dockerfile = readFileSync(path.resolve(__dirname, '../../../Dockerfile'), 'utf8')

  test('the entrypoint runs it after db push and the instance settings backfill, before the server, never fatally', () => {
    const entry = dockerfile.split('\n').find((l) => l.startsWith('RUN printf') && l.includes('entrypoint'))!
    const push = entry.indexOf('db push')
    const instance = entry.indexOf('backfill-rbac-instance-settings.mjs')
    const ours = entry.indexOf('backfill-rbac-root.mjs')
    const server = entry.indexOf('exec node server.js')
    expect(push).toBeGreaterThan(0)
    expect(instance).toBeGreaterThan(push)
    expect(ours).toBeGreaterThan(instance)
    expect(server).toBeGreaterThan(ours)
    expect(entry).toMatch(/\\nnode scripts\/backfill-rbac-root\.mjs 2>&1\\n/)
  })

  test('the dev command runs it in the same place', () => {
    const dev = readFileSync(path.resolve(__dirname, '../../../../docker-compose.dev.yml'), 'utf8')
    const lines = dev.split('\n').map((l) => l.trim())
    const instance = lines.indexOf('node scripts/backfill-rbac-instance-settings.mjs')
    expect(instance).toBeGreaterThan(0)
    expect(lines[instance + 1]).toBe('node scripts/backfill-rbac-root.mjs')
  })
})
