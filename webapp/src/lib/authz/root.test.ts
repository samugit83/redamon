/**
 * Who the instance's Root is (step 2.5, ID-02, ID-03 resolution, ID-10): the one account the
 * instance settings row names, while it exists and is an admin; confirmed or not. Read only
 * with the identity switch on, cached per process apart from the accounts for
 * RBAC_AUTHZ_CACHE_MS (one row for the whole process, so a request's account read stays one
 * query, DV-25), `fresh` for the protections. The account type: root, admin or member.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/authz/root.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

const h = vi.hoisted(() => ({
  instance: null as Record<string, unknown> | null,
  users: new Map<string, Record<string, unknown>>(),
  instanceReads: 0,
  userReads: 0,
  fail: false,
}))
vi.mock('@/lib/prisma', () => ({
  default: {
    instanceSettings: {
      findUnique: async (a: { where: { id: string }; select: Record<string, boolean> }) => {
        h.instanceReads++
        if (h.fail) throw Object.assign(new Error('connection lost'), { code: 'P1001' })
        expect(a).toEqual({ where: { id: 'instance' }, select: { rootUserId: true, rootConfirmedAt: true, rootAssignedBy: true } })
        return h.instance && { ...h.instance }
      },
    },
    user: {
      findUnique: async (a: { where: { id: string }; select: Record<string, boolean> }) => {
        h.userReads++
        expect(a.select).toEqual({ email: true, role: true })
        const u = h.users.get(a.where.id)
        return u ? { email: u.email, role: u.role } : null
      },
    },
  },
}))

import { setFlagsForTests } from './flags'
import { setNowForTests } from './clock'
import {
  accountTypeOf, clearInstanceRootCacheForTests, invalidateInstanceRoot, isRootAccount, loadInstanceRoot,
} from './root'

let t = Date.parse('2026-11-12T09:00:00Z')
const reads = () => h.instanceReads

function seed() {
  h.users = new Map([
    ['root-1', { email: 'root@e2e.local', role: 'admin' }],
    ['admin-2', { email: 'adm@e2e.local', role: 'admin' }],
    ['member-1', { email: 'mem@e2e.local', role: 'standard' }],
  ])
  h.instance = { rootUserId: 'root-1', rootConfirmedAt: null, rootAssignedBy: 'automatic' }
}

beforeEach(() => {
  seed()
  h.instanceReads = 0
  h.userReads = 0
  h.fail = false
  setFlagsForTests({ identity: true })
  setNowForTests(() => new Date(t))
  vi.stubEnv('RBAC_AUTHZ_CACHE_MS', '')
  clearInstanceRootCacheForTests()
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
  vi.unstubAllEnvs()
})

describe('loadInstanceRoot', () => {
  test('single root: the account the singleton row names, unconfirmed while chosen automatically', async () => {
    expect(await loadInstanceRoot()).toEqual({ userId: 'root-1', email: 'root@e2e.local', confirmed: false, assignedBy: 'automatic' })
  })

  test('confirmed once the host (or the install, or a transfer) confirmed it', async () => {
    h.instance = { rootUserId: 'root-1', rootConfirmedAt: new Date(t), rootAssignedBy: 'host' }
    expect(await loadInstanceRoot()).toMatchObject({ userId: 'root-1', confirmed: true, assignedBy: 'host' })
  })

  test('no row, or a row naming nobody: no Root', async () => {
    h.instance = null
    expect(await loadInstanceRoot()).toBeNull()
    clearInstanceRootCacheForTests()
    h.instance = { rootUserId: null, rootConfirmedAt: null, rootAssignedBy: null }
    expect(await loadInstanceRoot()).toBeNull()
    expect(h.userReads).toBe(0)
  })

  test('a Root id that names no account is no Root', async () => {
    h.users.delete('root-1')
    expect(await loadInstanceRoot()).toBeNull()
  })

  test('a Root that is no longer an admin (demoted while the switch was off) is no Root', async () => {
    h.users.set('root-1', { email: 'root@e2e.local', role: 'standard' })
    expect(await loadInstanceRoot()).toBeNull()
  })

  test('switch off: no Root, and nothing is read', async () => {
    setFlagsForTests({ identity: false })
    expect(await loadInstanceRoot()).toBeNull()
    expect(await loadInstanceRoot({ fresh: true })).toBeNull()
    expect(await isRootAccount('root-1')).toBe(false)
    expect(reads() + h.userReads).toBe(0)
  })

  test('cached for the bound: a second read within it makes no query; after it, one', async () => {
    await loadInstanceRoot()
    await loadInstanceRoot()
    expect(reads()).toBe(1)
    t += 4999
    await loadInstanceRoot()
    expect(reads()).toBe(1)
    t += 2
    await loadInstanceRoot()
    expect(reads()).toBe(2)
  })

  test('the absence of a Root is cached too', async () => {
    h.instance = null
    await loadInstanceRoot()
    await loadInstanceRoot()
    expect(reads()).toBe(1)
  })

  test('fresh bypasses the cache and refreshes it', async () => {
    await loadInstanceRoot()
    h.instance = { rootUserId: 'admin-2', rootConfirmedAt: new Date(t), rootAssignedBy: 'host' }
    expect((await loadInstanceRoot())?.userId).toBe('root-1')
    expect((await loadInstanceRoot({ fresh: true }))?.userId).toBe('admin-2')
    expect((await loadInstanceRoot())?.userId).toBe('admin-2')
    expect(reads()).toBe(2)
  })

  test('invalidateInstanceRoot drops the cached row (a writer in this process)', async () => {
    await loadInstanceRoot()
    h.instance = null
    invalidateInstanceRoot()
    expect(await loadInstanceRoot()).toBeNull()
  })

  test('RBAC_AUTHZ_CACHE_MS=0: every call reads', async () => {
    vi.stubEnv('RBAC_AUTHZ_CACHE_MS', '0')
    await loadInstanceRoot()
    await loadInstanceRoot()
    expect(reads()).toBe(2)
  })

  test('a failed read throws (the caller decides) and is not cached', async () => {
    h.fail = true
    await expect(loadInstanceRoot()).rejects.toThrow('connection lost')
    h.fail = false
    expect((await loadInstanceRoot())?.userId).toBe('root-1')
  })

  test('the answer is frozen: a caller cannot change what the cache shares', async () => {
    const root = await loadInstanceRoot()
    expect(Object.isFrozen(root)).toBe(true)
  })
})

describe('account type and isRootAccount', () => {
  test('root for the account the row names, admin for another admin, member for the rest', async () => {
    const root = await loadInstanceRoot()
    expect(accountTypeOf({ id: 'root-1', role: 'admin' }, root)).toBe('root')
    expect(accountTypeOf({ id: 'admin-2', role: 'admin' }, root)).toBe('admin')
    expect(accountTypeOf({ id: 'member-1', role: 'standard' }, root)).toBe('member')
    expect(accountTypeOf({ id: 'root-1', role: 'admin' }, null)).toBe('admin')
  })

  test('isRootAccount reads through the same cache; fresh when asked', async () => {
    expect(await isRootAccount('root-1')).toBe(true)
    expect(await isRootAccount('admin-2')).toBe(false)
    expect(reads()).toBe(1)
    expect(await isRootAccount('root-1', { fresh: true })).toBe(true)
    expect(reads()).toBe(2)
  })

  test('one Root per instance: of two admins only the one the row names is root', async () => {
    const root = await loadInstanceRoot()
    const types = ['root-1', 'admin-2'].map((id) => accountTypeOf({ id, role: 'admin' }, root))
    expect(types.filter((x) => x === 'root')).toEqual(['root'])
  })
})
