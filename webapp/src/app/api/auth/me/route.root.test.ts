/**
 * GET /api/auth/me and the Root (step 2.5, ID-10, ID-03): with the identity switch on every
 * account gets its `accountType` (root, admin, member) and every admin gets `rbac.root`, what
 * the header's Root banner shows: who Root is, whether the host confirmed it, and when an
 * automatic choice was made; `null` when the instance has no Root. A failed Root read never
 * fails the session: the two fields are left out and the failure logged. With the switch off
 * the answer is exactly the one before (no field, no read).
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/auth/me/route.root.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

vi.stubEnv('AUTH_SECRET', 'f'.repeat(64))

type Row = Record<string, unknown>
const h = vi.hoisted(() => ({
  jar: {} as { auth?: string },
  users: [] as Record<string, unknown>[],
  instance: null as Record<string, unknown> | null,
  audit: [] as Record<string, unknown>[],
  instanceReads: 0,
  failInstance: false,
}))
vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => (name === 'redamon-auth' && h.jar.auth ? { value: h.jar.auth } : undefined),
    delete: () => {},
  })),
}))
const pick = (row: Row, select?: Row) =>
  select ? Object.fromEntries(Object.keys(select).filter((k) => select[k]).map((k) => [k, row[k]])) : { ...row }
vi.mock('@/lib/prisma', () => ({
  default: {
    user: {
      findUnique: async ({ where, select }: { where: { id: string }; select?: Row }) => {
        const r = h.users.find((u) => u.id === where.id)
        return r ? pick(r, select) : null
      },
    },
    instanceSettings: {
      findUnique: async ({ select }: { select?: Row }) => {
        h.instanceReads++
        if (h.failInstance) throw Object.assign(new Error('boom'), { code: 'P1001' })
        return h.instance && pick(h.instance, select)
      },
    },
    auditLog: {
      findFirst: async ({ where, orderBy }: { where: Row; orderBy: Row }) => {
        expect(orderBy).toEqual({ createdAt: 'desc' })
        const rows = h.audit.filter((r) => r.action === where.action && r.targetId === where.targetId)
          .sort((a, b) => (b.createdAt as Date).getTime() - (a.createdAt as Date).getTime())
        return rows[0] ? { createdAt: rows[0].createdAt } : null
      },
    },
  },
}))
vi.mock('@/lib/authz/updateReview', () => ({ pendingLegacyGrantCount: async () => 0 }))

import { createToken } from '@/lib/auth'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { GET } from './route'

const T = new Date('2026-01-01T00:00:00.000Z')
const CHOSEN = new Date('2026-11-12T08:30:00.000Z')
const account = (id: string, role: string, email: string) => ({
  id, name: id, email, role, password: 'h', createdAt: T, legacyGrants: [], status: 'active', sessionVersion: 0,
  mustChangePassword: false, adminProfileId: null, lastLoginAt: null,
})

async function me(id: string) {
  const row = h.users.find((u) => u.id === id)!
  h.jar.auth = await createToken(id, String(row.role))
  const res = await GET()
  expect(res.status).toBe(200)
  return res.json()
}

beforeEach(() => {
  h.users = [
    account('root-1', 'admin', 'root@e2e.local'),
    account('admin-2', 'admin', 'adm2@e2e.local'),
    account('member-1', 'standard', 'mem@e2e.local'),
  ]
  h.instance = { id: 'instance', rootUserId: 'root-1', rootConfirmedAt: null, rootAssignedBy: 'automatic' }
  h.audit = [
    { action: 'system.rbac_root_assigned', targetId: 'root-1', createdAt: new Date('2026-11-01T00:00:00Z') },
    { action: 'system.rbac_root_assigned', targetId: 'root-1', createdAt: CHOSEN },
    { action: 'system.rbac_root_assigned', targetId: 'admin-2', createdAt: new Date('2026-11-20T00:00:00Z') },
  ]
  h.instanceReads = 0
  h.failInstance = false
  h.jar = {}
  setFlagsForTests({ identity: true })
  clearPrincipalCacheForTests()
  clearInstanceRootCacheForTests()
})
afterEach(() => {
  setFlagsForTests(null)
  vi.restoreAllMocks()
})

describe('GET /api/auth/me with the identity switch on', () => {
  test('Root: account type root, and the unconfirmed Root it is, with the date it was chosen', async () => {
    const body = await me('root-1')
    expect(body.accountType).toBe('root')
    expect(body.rbac.root).toEqual({ email: 'root@e2e.local', confirmed: false, chosenAt: CHOSEN.toISOString() })
  })

  test('another admin: account type admin, and the same Root', async () => {
    const body = await me('admin-2')
    expect(body).toMatchObject({ id: 'admin-2', role: 'admin', accountType: 'admin' })
    expect(body.rbac).toEqual({
      compat: false, legacyGrantsPending: 0, identity: true,
      root: { email: 'root@e2e.local', confirmed: false, chosenAt: CHOSEN.toISOString() },
    })
  })

  test('a confirmed Root: confirmed, no date needed', async () => {
    h.instance!.rootConfirmedAt = T
    h.instance!.rootAssignedBy = 'host'
    expect((await me('admin-2')).rbac.root).toEqual({ email: 'root@e2e.local', confirmed: true, chosenAt: null })
  })

  test('no Root (none chosen, a dangling id, or a demoted one): rbac.root is null', async () => {
    h.instance = null
    expect((await me('admin-2')).rbac.root).toBeNull()
    clearInstanceRootCacheForTests()
    h.instance = { id: 'instance', rootUserId: 'gone', rootConfirmedAt: T, rootAssignedBy: 'host' }
    expect((await me('admin-2')).rbac.root).toBeNull()
  })

  test('a member: account type member, no rbac block, and no Root read', async () => {
    const body = await me('member-1')
    expect(body).toEqual({ id: 'member-1', name: 'member-1', email: 'mem@e2e.local', role: 'standard', accountType: 'member' })
    expect(h.instanceReads).toBe(0)
  })

  test('the Root is cached: two admin page loads, one read', async () => {
    await me('admin-2')
    await me('root-1')
    expect(h.instanceReads).toBe(1)
  })

  test('a failed Root read answers the account without the two fields and logs it', async () => {
    h.failInstance = true
    const err = vi.spyOn(console, 'error').mockImplementation(() => {})
    const body = await me('admin-2')
    expect(body).not.toHaveProperty('accountType')
    expect(body.rbac).toEqual({ compat: false, legacyGrantsPending: 0, identity: true })
    expect(String(err.mock.calls[0]?.[0])).toMatch(/^\[rbac\] could not read the Root: P1001/)
  })
})

describe('GET /api/auth/me with the switch off', () => {
  test('the answer before the switch existed: no account type, no Root, nothing read', async () => {
    setFlagsForTests({ identity: false })
    expect(await me('root-1')).toEqual({
      id: 'root-1', name: 'root-1', email: 'root@e2e.local', role: 'admin', rbac: { compat: false, legacyGrantsPending: 0 },
    })
    expect(await me('member-1')).toEqual({ id: 'member-1', name: 'member-1', email: 'mem@e2e.local', role: 'standard' })
    expect(h.instanceReads).toBe(0)
  })
})
