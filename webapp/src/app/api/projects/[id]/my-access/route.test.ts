/**
 * GET /api/projects/[id]/my-access (step 4.3, PE-21 per project): the signed-in account's own
 * access to one project, for the stale-access poll of an open project (step 4.11). The effective
 * user's level, toggles and how it was reached, and the owner's name and email; a project the
 * account cannot see is 404, the same as one that does not exist. With RBAC_SHARING_ENABLED off the
 * route does not exist (404 for everyone, nothing read: DV-30); with the switch on but the instance
 * policy disabled only the owner gets an answer, as every project route answers.
 *
 * The session (requireEffectiveUser) and Prisma are doubles; projectAccess(), the sharing policy
 * reader and the capabilities are the real ones.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const h = vi.hoisted(() => ({
  eff: null as null | { userId: string },
  shares: new Map<string, { access: string; rawData: boolean; expiresAt: Date | null; user: { status: string } }>(),
  failProjects: false,
  policy: { enabled: true } as unknown,
}))
const userFindUnique = vi.hoisted(() => vi.fn(async ({ where }: { where: { id: string } }) => ({
  id: where.id, email: `${where.id}@example.test`, name: `Name of ${where.id}`, role: where.id.startsWith('admin') ? 'admin' : 'standard',
  password: 'hash', createdAt: new Date(0), legacyGrants: [], status: 'active', sessionVersion: 0, mustChangePassword: false,
  adminProfileId: null, lastLoginAt: null, permissionSets: [], permissionOverrides: [],
})))
const projectFindUnique = vi.hoisted(() => vi.fn(async ({ where }: { where: { id: string } }) => {
  if (h.failProjects) throw Object.assign(new Error('db down'), { code: 'P1001' })
  return where.id === 'P-alice' ? { id: 'P-alice', userId: 'alice' } : null
}))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: async () => h.eff ?? NextResponse.json({ error: 'Unauthorized' }, { status: 401 }),
}))
vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: projectFindUnique },
    projectCollaborator: {
      findUnique: async ({ where }: { where: { projectId_userId: { projectId: string; userId: string } } }) =>
        h.shares.get(`${where.projectId_userId.projectId}|${where.projectId_userId.userId}`) ?? null,
    },
    projectBreakGlass: { findFirst: async () => null },
    instanceSettings: { findUnique: async () => ({ sharingPolicy: h.policy, rootUserId: null, rootConfirmedAt: null, rootAssignedBy: null, defaultMemberSetId: null }) },
    permissionSet: { findMany: async () => [] },
    user: { findUnique: userFindUnique },
  },
}))

import { GET } from './route'
import { setFlagsForTests } from '@/lib/authz/flags'
import { setNowForTests } from '@/lib/authz/clock'
import { clearSharingPolicyCacheForTests } from '@/lib/authz/sharingPolicy'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'

const NOW = new Date('2026-11-13T12:00:00Z')
const ALICE = { name: 'Name of alice', email: 'alice@example.test' }

const get = (id = 'P-alice') =>
  GET(new NextRequest(`http://x/api/projects/${id}/my-access`), { params: Promise.resolve({ id }) })

beforeEach(() => {
  h.eff = null
  h.shares.clear()
  h.failProjects = false
  h.policy = { enabled: true }
  userFindUnique.mockClear()
  projectFindUnique.mockClear()
  setFlagsForTests({})
  setNowForTests(() => NOW)
  clearSharingPolicyCacheForTests()
  clearCapabilityCachesForTests()
  clearInstanceRootCacheForTests()
  clearPrincipalCacheForTests()
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
  vi.restoreAllMocks()
})

describe('GET /api/projects/[id]/my-access, RBAC_SHARING_ENABLED off: the route does not exist (DV-30)', () => {
  test.each([
    ['every switch off', {}],
    ['identity + permissions on, the sharing switch off', { identity: true, permissions: true }],
    ['the sharing switch set without permissions', { identity: true, sharing: true }],
  ])('%s: 404 for the owner, a share holder, an admin and no session; nothing read', async (_what, flags) => {
    setFlagsForTests(flags)
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    h.shares.set('P-alice|bob', { access: 'read', rawData: true, expiresAt: null, user: { status: 'active' } })
    for (const eff of [{ userId: 'alice' }, { userId: 'bob' }, { userId: 'admin-1' }, null]) {
      h.eff = eff
      const res = await get()
      expect([eff, res.status]).toEqual([eff, 404])
      expect(await res.json()).toEqual({ error: 'Not found' })
    }
    expect(projectFindUnique).not.toHaveBeenCalled()
    expect(userFindUnique).not.toHaveBeenCalled()
  })
})

describe('GET /api/projects/[id]/my-access, the switch on but the policy disabled: the owner only', () => {
  beforeEach(() => {
    setFlagsForTests({ identity: true, permissions: true, sharing: true })
    h.policy = {}
  })

  test('no session: 401, nothing read', async () => {
    expect((await get()).status).toBe(401)
    expect(projectFindUnique).not.toHaveBeenCalled()
  })

  test('the owner: 200 with the owner level, every toggle, and themselves as the owner', async () => {
    h.eff = { userId: 'alice' }
    const res = await get()
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ myAccess: { level: 'owner', toggles: { rawData: true }, via: 'owner', owner: ALICE } })
    // The owner's name and email only: never the account row's other columns.
    expect(userFindUnique).toHaveBeenCalledWith({ where: { id: 'alice' }, select: { name: true, email: true } })
  })

  test('anyone else, even with a share row: 404, the same as a project that does not exist, and the owner is not read', async () => {
    h.shares.set('P-alice|bob', { access: 'read', rawData: true, expiresAt: null, user: { status: 'active' } })
    for (const policy of [{}, { enabled: 'yes' }]) {
      h.policy = policy
      clearSharingPolicyCacheForTests()
      h.eff = { userId: 'bob' }
      const other = await get()
      expect(other.status).toBe(404)
      expect(await other.json()).toEqual({ error: 'Not found' })
      const missing = await get('P-none')
      expect(missing.status).toBe(404)
      expect(await missing.json()).toEqual({ error: 'Not found' })
    }
    expect(userFindUnique).not.toHaveBeenCalled()
  })

  test('a failed read is a coded 500, never an answer', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    h.eff = { userId: 'alice' }
    h.failProjects = true
    const res = await get()
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Could not read your access to the project', code: 'P1001' })
  })
})

describe('GET /api/projects/[id]/my-access, sharing in force', () => {
  beforeEach(() => setFlagsForTests({ identity: true, permissions: true, sharing: true }))

  test('a read share: read, without raw, through the share, shared by the owner', async () => {
    h.shares.set('P-alice|bob', { access: 'read', rawData: false, expiresAt: null, user: { status: 'active' } })
    h.eff = { userId: 'bob' }
    expect(await (await get()).json()).toEqual({ myAccess: { level: 'read', toggles: { rawData: false }, via: 'share', owner: ALICE } })
  })

  test('a share with Raw data says so; a write row reads as read', async () => {
    h.shares.set('P-alice|bob', { access: 'write', rawData: true, expiresAt: null, user: { status: 'active' } })
    h.eff = { userId: 'bob' }
    expect(await (await get()).json()).toEqual({ myAccess: { level: 'read', toggles: { rawData: true }, via: 'share', owner: ALICE } })
  })

  test('the poll sees a share end: expired at the clock → 404', async () => {
    h.shares.set('P-alice|bob', { access: 'read', rawData: false, expiresAt: new Date(NOW.getTime() + 1000), user: { status: 'active' } })
    h.eff = { userId: 'bob' }
    expect((await get()).status).toBe(200)
    setNowForTests(() => new Date(NOW.getTime() + 1000))
    expect((await get()).status).toBe(404)
  })

  test('oversight is named as such', async () => {
    h.eff = { userId: 'admin-1' }
    expect(await (await get()).json()).toEqual({ myAccess: { level: 'read', toggles: { rawData: false }, via: 'oversight', owner: ALICE } })
  })

  test('under act-as the answer is the account acted as (the effective user)', async () => {
    h.shares.set('P-alice|bob', { access: 'read', rawData: false, expiresAt: null, user: { status: 'active' } })
    h.eff = { userId: 'bob' }
    expect((await (await get()).json()).myAccess.level).toBe('read')
    h.eff = { userId: 'carol' }
    expect((await get()).status).toBe(404)
  })
})
