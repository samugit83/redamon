/**
 * Two admins demoting each other at the same moment (HD-09): each request alone
 * leaves an admin behind, so only the lock taken before the check makes the pair
 * safe. fakePrisma's `pg_advisory_xact_lock` serializes two transactions where
 * Postgres would; the session is read from the same table on every request, as
 * getSession does, so a request that runs after the other's commit sees its
 * account demoted.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { AsyncLocalStorage } from 'node:async_hooks'
import bcrypt from 'bcryptjs'
import { createFakePrisma, type FakePrisma } from '@/lib/plugins/__testing__/fakePrisma'

const h = vi.hoisted(() => ({ db: null as unknown as FakePrisma }))
const caller = new AsyncLocalStorage<string>()

vi.mock('@/lib/prisma', () => ({
  default: new Proxy({}, {
    get: (_t, k) => (k === 'capturedHttpTransaction' ? { findMany: async () => [] } : h.db[k as keyof FakePrisma]),
  }),
}))
vi.mock('@/lib/session', () => ({
  getSession: async () => {
    const id = caller.getStore()
    const row = id ? h.db.tables.user.get(id) : undefined
    return row ? { userId: id, role: row.role } : null
  },
  isInternalRequest: () => false,
}))
vi.mock('@/lib/workspacePurge', () => ({ purgeProjectWorkspace: async () => undefined }))

import { __resetThrottle } from '@/lib/loginThrottle'
import { PUT, DELETE } from './route'

const PW: Record<string, string> = { 'admin-a': 'admin-a-passphrase', 'admin-b': 'admin-b-passphrase' }

function seed() {
  h.db = createFakePrisma()
  h.db.seed('user', [
    { id: 'admin-a', email: 'a@e2e.local', role: 'admin', password: bcrypt.hashSync(PW['admin-a'], 4) },
    { id: 'admin-b', email: 'b@e2e.local', role: 'admin', password: bcrypt.hashSync(PW['admin-b'], 4) },
    // A passwordless managed admin never counts as the admin that remains.
    { id: 'managed', email: 'm@e2e.local', role: 'admin', password: '' },
  ])
}

const as = <T,>(userId: string, fn: () => Promise<T>) => caller.run(userId, fn)
const put = (actor: string, target: string, body: Record<string, unknown>) =>
  as(actor, () => PUT(new Request(`http://localhost/api/users/${target}`, {
    method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  }) as never, { params: Promise.resolve({ id: target }) }))
const del = (actor: string, target: string, body: Record<string, unknown>) =>
  as(actor, () => DELETE(new Request(`http://localhost/api/users/${target}`, {
    method: 'DELETE', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  }) as never, { params: Promise.resolve({ id: target }) }))

const adminsWithPassword = () => h.db.rows('user').filter(r => r.role === 'admin' && r.password !== '')

beforeEach(() => {
  __resetThrottle()
  seed()
})

describe('two admins demoting each other at once leave one admin', () => {
  test.each([1, 2, 3])('run %i: exactly one 409, one admin left', async () => {
    const [ab, ba] = await Promise.all([
      put('admin-a', 'admin-b', { role: 'standard', stepUpPassword: PW['admin-a'] }),
      put('admin-b', 'admin-a', { role: 'standard', stepUpPassword: PW['admin-b'] }),
    ])
    expect([ab.status, ba.status].sort()).toEqual([200, 409])
    const refused = ab.status === 409 ? ab : ba
    expect((await refused.json()).code).toBe('last_admin')
    expect(adminsWithPassword()).toHaveLength(1)
    // The two transactions took the same lock key.
    const locks = h.db.rawCalls.filter(c => c.sql.includes('pg_advisory_xact_lock')).map(c => c.values[0])
    expect(locks).toEqual(['rbac.admin_set', 'rbac.admin_set'])
  })

  test('two self-demotions at once leave one admin', async () => {
    const res = await Promise.all([
      put('admin-a', 'admin-a', { role: 'standard' }),
      put('admin-b', 'admin-b', { role: 'standard' }),
    ])
    expect(res.map(r => r.status).sort()).toEqual([200, 409])
    expect(adminsWithPassword()).toHaveLength(1)
  })

  test('a deletion racing a demotion of the deleter leaves one admin', async () => {
    const [deleteB, demoteA] = await Promise.all([
      del('admin-a', 'admin-b', { stepUpPassword: PW['admin-a'] }),
      put('admin-b', 'admin-a', { role: 'standard', stepUpPassword: PW['admin-b'] }),
    ])
    expect([deleteB.status, demoteA.status].sort()).toEqual([200, 409])
    expect(adminsWithPassword()).toHaveLength(1)
  })
})
