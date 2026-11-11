/**
 * The one-time backfill that keeps, as legacy grants, the shared tools existing members
 * could use before the RBAC hardening (scripts/backfill-rbac-legacy-grants.mjs, HD-28,
 * DV-26): members with a password get the terminal and the shell sessions, tunnel holders
 * get tunnels, admins and passwordless accounts nothing, accounts created after the
 * cutoff nothing; an AuditLog marker written in the same transaction makes a second boot
 * do nothing, unless the grants are gone (a downgrade dropped the column).
 *
 * @vitest-environment node
 */
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { describe, test, expect, beforeEach, afterEach } from 'vitest'
import { createFakePrisma, type FakePrisma } from '@/lib/plugins/__testing__/fakePrisma'
import { setNowForTests } from '@/lib/plugins/clock'
import {
  CUTOFF_ACTION, LEGACY_GRANTS, LOCK_KEY, MARKER_ACTION, REMOVE_ACTION, backfillRbacLegacyGrants,
} from '../../../scripts/backfill-rbac-legacy-grants.mjs'
import { LEGACY_GRANTS_CUTOFF_ACTION } from './sharedTools'

let db: FakePrisma

const T0 = Date.parse('2026-11-11T08:00:00.000Z')
const BEFORE = new Date(T0 - 86_400_000)
const UPDATED = new Date('2026-03-01T09:00:00.000Z')
const PW = '$2a$12$hash'

let t = T0

function user(id: string, opts: { role?: string; password?: string; createdAt?: Date; legacyGrants?: string[] } = {}) {
  db.seed('user', [{
    id, name: id, email: `${id}@e2e.local`, role: opts.role ?? 'standard', password: opts.password ?? PW,
    createdAt: opts.createdAt ?? BEFORE, updatedAt: UPDATED, legacyGrants: opts.legacyGrants ?? [],
  }])
}

const grants = (id: string) => db.rows('user').find((u) => u.id === id)!.legacyGrants
const markers = () => db.rows('auditLog').filter((r) => r.action === MARKER_ACTION)
const cutoffs = () => db.rows('auditLog').filter((r) => r.action === CUTOFF_ACTION)

/** Records each user write; `fail` makes the first one throw. */
function instrument(fail = false) {
  const writes: { id: unknown; data: Record<string, unknown> }[] = []
  const original = db.$transaction
  const tx = original.bind(db)
  ;(db as unknown as Record<string, unknown>).$transaction = (fn: (t: FakePrisma) => Promise<unknown>) =>
    tx(async (t) => {
      const u = t.user as unknown as Record<string, (a: unknown) => Promise<unknown>>
      const update = u.update
      u.update = async (a) => {
        const { where, data } = a as { where: { id: unknown }; data: Record<string, unknown> }
        writes.push({ id: where.id, data })
        if (fail) throw new Error('connection reset')
        return update(a)
      }
      u.updateMany = async () => { throw new Error('one update per account, with its own updatedAt') }
      return fn(t)
    })
  return { writes, restore: () => { (db as unknown as Record<string, unknown>).$transaction = original } }
}

beforeEach(() => {
  db = createFakePrisma()
  t = T0
  setNowForTests(() => new Date(t))
})
afterEach(() => setNowForTests(null))

describe('backfillRbacLegacyGrants', () => {
  test('exports the actions, the lock key and the grants, and the cutoff action sharedTools reads', () => {
    expect(LOCK_KEY).toBe('system.rbac_legacy_grants')
    expect(CUTOFF_ACTION).toBe('system.rbac_legacy_grants_cutoff')
    expect(MARKER_ACTION).toBe('system.rbac_legacy_grants_backfill')
    expect(REMOVE_ACTION).toBe('rbac.legacy_grant.remove')
    expect(LEGACY_GRANTS).toEqual(['kali_terminal', 'shell_sessions', 'tunnels'])
    expect(LEGACY_GRANTS_CUTOFF_ACTION).toBe(CUTOFF_ACTION)
  })

  test('members with a password get terminal and sessions', async () => {
    user('alice')
    user('bob')
    const out = await backfillRbacLegacyGrants(db)
    expect(grants('alice')).toEqual(['kali_terminal', 'shell_sessions'])
    expect(grants('bob')).toEqual(['kali_terminal', 'shell_sessions'])
    expect(out).toEqual({ done: true, kali_terminal: 2, shell_sessions: 2, tunnels: 0, usersChanged: 2 })
  })

  test('admins get nothing', async () => {
    user('root', { role: 'admin' })
    db.seed('userSettings', [{ id: 's-root', userId: 'root', ngrokAuthtoken: 'fake-ngrok' }])
    await backfillRbacLegacyGrants(db)
    expect(grants('root')).toEqual([])
  })

  test('passwordless get nothing, a tunnel in their settings included', async () => {
    user('managed', { password: '' })
    db.seed('userSettings', [{ id: 's-m', userId: 'managed', ngrokAuthtoken: 'fake-ngrok', chiselServerUrl: 'https://c.test' }])
    expect(await backfillRbacLegacyGrants(db)).toMatchObject({ done: true, kali_terminal: 0, shell_sessions: 0, tunnels: 0, usersChanged: 0 })
    expect(grants('managed')).toEqual([])
  })

  test('tunnel holders get tunnels (ngrok token, or a chisel URL without auth)', async () => {
    user('ngrok')
    user('chisel')
    user('authonly')
    user('nosettings')
    db.seed('userSettings', [
      { id: 's1', userId: 'ngrok', tunnelsEnabled: false, ngrokAuthtoken: 'fake-ngrok', chiselServerUrl: '', chiselAuth: '' },
      { id: 's2', userId: 'chisel', tunnelsEnabled: true, ngrokAuthtoken: '', chiselServerUrl: 'https://chisel.test:8443', chiselAuth: '' },
      // An auth string with no server URL configures no tunnel (the tunnel-config rule).
      { id: 's3', userId: 'authonly', tunnelsEnabled: true, ngrokAuthtoken: '', chiselServerUrl: '', chiselAuth: 'u:p' },
    ])
    const out = await backfillRbacLegacyGrants(db)
    expect(grants('ngrok')).toEqual(['kali_terminal', 'shell_sessions', 'tunnels'])
    expect(grants('chisel')).toEqual(['kali_terminal', 'shell_sessions', 'tunnels'])
    expect(grants('authonly')).toEqual(['kali_terminal', 'shell_sessions'])
    expect(grants('nosettings')).toEqual(['kali_terminal', 'shell_sessions'])
    expect(out).toMatchObject({ kali_terminal: 4, shell_sessions: 4, tunnels: 2 })
  })

  test('the marker records how many accounts hold each grant, under the advisory lock', async () => {
    user('alice')
    user('bob')
    db.seed('userSettings', [{ id: 's', userId: 'bob', ngrokAuthtoken: 'fake-ngrok' }])
    await backfillRbacLegacyGrants(db)
    expect(markers()).toEqual([expect.objectContaining({
      action: MARKER_ACTION, targetType: 'system', source: 'system', actorId: null,
      after: { kali_terminal: 2, shell_sessions: 2, tunnels: 1 },
    })])
    const locks = db.rawCalls.filter((c) => c.sql.includes('pg_advisory_xact_lock(hashtext('))
    expect(locks.map((c) => c.values[0])).toEqual([LOCK_KEY, LOCK_KEY])
  })

  test('the marker and the cutoff are written even when there is nothing to grant', async () => {
    user('root', { role: 'admin' })
    expect(await backfillRbacLegacyGrants(db)).toEqual({ done: true, kali_terminal: 0, shell_sessions: 0, tunnels: 0, usersChanged: 0 })
    expect(markers()).toHaveLength(1)
    expect(cutoffs()).toHaveLength(1)
  })

  test("one update per account, keeping the row's updatedAt (a grant is not an edit)", async () => {
    user('alice')
    user('root', { role: 'admin' })
    const { writes } = instrument()
    await backfillRbacLegacyGrants(db)
    expect(writes).toEqual([{ id: 'alice', data: { legacyGrants: ['kali_terminal', 'shell_sessions'], updatedAt: UPDATED } }])
    expect(db.rows('user').find((u) => u.id === 'alice')!.updatedAt).toEqual(UPDATED)
  })

  test('grants an account already holds are kept, in order, and an unknown value is left alone', async () => {
    user('alice', { legacyGrants: ['custom', 'shell_sessions'] })
    user('bob', { legacyGrants: ['kali_terminal', 'shell_sessions'] })
    const { writes } = instrument()
    await backfillRbacLegacyGrants(db)
    expect(grants('alice')).toEqual(['kali_terminal', 'shell_sessions', 'custom'])
    // Bob already holds exactly what is due: no write.
    expect(writes.map((w) => w.id)).toEqual(['alice'])
  })

  test('a second run changes nothing', async () => {
    user('alice')
    await backfillRbacLegacyGrants(db)
    const before = db.rows('user')
    // A member created after the first run is a new member: no grant.
    t += 60_000
    user('late', { createdAt: new Date(t) })
    const { writes } = instrument()
    expect(await backfillRbacLegacyGrants(db)).toEqual({ done: false })
    expect(writes).toEqual([])
    expect(db.rows('user').filter((u) => u.id !== 'late')).toEqual(before)
    expect(grants('late')).toEqual([])
    expect(markers()).toHaveLength(1)
    expect(cutoffs()).toHaveLength(1)
  })

  test('two copies booting together: one grants, the other finds the marker', async () => {
    user('alice')
    const results = await Promise.all([backfillRbacLegacyGrants(db), backfillRbacLegacyGrants(db)])
    expect(results.filter((r) => r.done)).toHaveLength(1)
    expect(results.filter((r) => !r.done)).toEqual([{ done: false }])
    expect(markers()).toHaveLength(1)
    expect(cutoffs()).toHaveLength(1)
    expect(grants('alice')).toEqual(['kali_terminal', 'shell_sessions'])
  })

  test('a failure rolls back every grant and writes no marker; the cutoff is kept for the retry', async () => {
    user('alice')
    user('bob')
    instrument(true)
    await expect(backfillRbacLegacyGrants(db)).rejects.toThrow('connection reset')
    expect(grants('alice')).toEqual([])
    expect(grants('bob')).toEqual([])
    expect(markers()).toHaveLength(0)
    expect(cutoffs()).toHaveLength(1)
  })
})

describe('the cutoff: only accounts that existed when the new code first started', () => {
  test('a user created after the cutoff gets nothing, also on a retry after a failed first run', async () => {
    user('old')
    const failing = instrument(true)
    await expect(backfillRbacLegacyGrants(db)).rejects.toThrow('connection reset')
    failing.restore()

    // Served for a while without the backfill: a member signs up and sets a tunnel.
    t += 60_000
    user('new', { createdAt: new Date(t) })
    db.seed('userSettings', [{ id: 's-new', userId: 'new', ngrokAuthtoken: 'fake-ngrok' }])

    t += 60_000
    expect(await backfillRbacLegacyGrants(db)).toMatchObject({ done: true, kali_terminal: 1, tunnels: 0 })
    expect(grants('old')).toEqual(['kali_terminal', 'shell_sessions'])
    expect(grants('new')).toEqual([])
  })

  test('an account created at the cutoff instant counts as existing', async () => {
    user('edge', { createdAt: new Date(T0) })
    await backfillRbacLegacyGrants(db)
    expect(grants('edge')).toEqual(['kali_terminal', 'shell_sessions'])
  })

  test('the first call records the cutoff and every later call reads the same one', async () => {
    await backfillRbacLegacyGrants(db)
    t += 60_000
    await backfillRbacLegacyGrants(db)
    expect(cutoffs()).toHaveLength(1)
    expect(new Date(cutoffs()[0].createdAt as Date).getTime()).toBe(T0)
  })
})

describe('skips only when the marker AND the grants exist (master §9.7)', () => {
  /** What a downgrade leaves: the AuditLog marker, and the column re-added empty. */
  function dropTheColumn() {
    for (const u of db.rows('user')) db.tables.user.set(u.id, { ...u, legacyGrants: [] })
  }

  test('a marker with no grant left (the column was dropped by a downgrade) grants again, once', async () => {
    user('alice')
    user('bob')
    db.seed('userSettings', [{ id: 's', userId: 'bob', chiselServerUrl: 'https://chisel.test' }])
    await backfillRbacLegacyGrants(db)
    dropTheColumn()
    t += 60_000
    // A member created while the old version ran is after the cutoff: no grant.
    user('during', { createdAt: new Date(t) })
    t += 60_000
    expect(await backfillRbacLegacyGrants(db)).toEqual({ done: true, kali_terminal: 2, shell_sessions: 2, tunnels: 1, usersChanged: 2 })
    expect(grants('alice')).toEqual(['kali_terminal', 'shell_sessions'])
    expect(grants('bob')).toEqual(['kali_terminal', 'shell_sessions', 'tunnels'])
    expect(grants('during')).toEqual([])
    expect(markers()).toHaveLength(2)
    expect(cutoffs()).toHaveLength(1)
    expect(await backfillRbacLegacyGrants(db)).toEqual({ done: false })
  })

  test('a re-derivation never gives back a grant an admin removed', async () => {
    user('alice')
    user('bob')
    db.seed('userSettings', [{ id: 's', userId: 'alice', ngrokAuthtoken: 'fake-ngrok' }])
    await backfillRbacLegacyGrants(db)
    db.seed('auditLog', [
      { action: REMOVE_ACTION, targetType: 'user', targetId: 'alice', after: { grant: 'tunnels' }, source: 'api' },
      { action: REMOVE_ACTION, targetType: 'user', targetId: 'bob', after: { grant: 'kali_terminal' }, source: 'api' },
    ])
    dropTheColumn()
    await backfillRbacLegacyGrants(db)
    expect(grants('alice')).toEqual(['kali_terminal', 'shell_sessions'])
    expect(grants('bob')).toEqual(['shell_sessions'])
  })

  test('every grant removed by an admin: one re-derivation that grants nothing, then final', async () => {
    user('alice')
    await backfillRbacLegacyGrants(db)
    db.seed('auditLog', [
      { action: REMOVE_ACTION, targetType: 'user', targetId: 'alice', after: { grant: 'kali_terminal' }, source: 'api' },
      { action: REMOVE_ACTION, targetType: 'user', targetId: 'alice', after: { grant: 'shell_sessions' }, source: 'api' },
    ])
    db.tables.user.set('alice', { ...db.rows('user')[0], legacyGrants: [] })
    t += 60_000
    expect(await backfillRbacLegacyGrants(db)).toEqual({ done: true, kali_terminal: 0, shell_sessions: 0, tunnels: 0, usersChanged: 0 })
    expect(grants('alice')).toEqual([])
    t += 60_000
    expect(await backfillRbacLegacyGrants(db)).toEqual({ done: false })
    expect(markers()).toHaveLength(2)
  })

  test('a marker that recorded no grant is final, whoever exists now', async () => {
    user('root', { role: 'admin' })
    await backfillRbacLegacyGrants(db)
    user('alice')
    expect(await backfillRbacLegacyGrants(db)).toEqual({ done: false })
    expect(grants('alice')).toEqual([])
  })

  test('a marker without counts reads as one that granted nothing', async () => {
    user('alice')
    db.seed('auditLog', [{ action: MARKER_ACTION, targetType: 'system', source: 'system', after: null }])
    expect(await backfillRbacLegacyGrants(db)).toEqual({ done: false })
  })
})

describe('the startup lists', () => {
  const dockerfile = readFileSync(path.resolve(__dirname, '../../../Dockerfile'), 'utf8')

  test('the entrypoint runs it after db push and the Jev backfill, before the server, never fatally', () => {
    const entry = dockerfile.split('\n').find((l) => l.startsWith('RUN printf') && l.includes('entrypoint'))!
    const push = entry.indexOf('db push')
    const jev = entry.indexOf('backfill-jev-provider-selection.mjs')
    const ours = entry.indexOf('backfill-rbac-legacy-grants.mjs')
    const server = entry.indexOf('exec node server.js')
    expect(push).toBeGreaterThan(0)
    expect(ours).toBeGreaterThan(jev)
    expect(jev).toBeGreaterThan(push)
    expect(server).toBeGreaterThan(ours)
    expect(entry).toMatch(/\\nnode scripts\/backfill-rbac-legacy-grants\.mjs 2>&1\\n/)
  })
})
