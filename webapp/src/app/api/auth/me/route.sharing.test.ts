/**
 * GET /api/auth/me tells every account whether sharing is in force (step 4.2, for the screens of
 * 4.5, 4.11 and 4.12): `sharing: {enabled, maxLevel}`, where `enabled` is RBAC_SHARING_ENABLED AND
 * the instance sharing policy's `enabled`, and `maxLevel` the highest level a share may be granted
 * at now (Read unless the write switch is on and the policy allows Read + Write).
 *
 * - The policy is read from the instance row only with the switch on, and cached
 *   (RBAC_AUTHZ_CACHE_MS): this route is also nginx's `auth_request` for the WebSocket paths, so it
 *   costs at most one indexed read per bound and writes nothing.
 * - Switch off: no `sharing` key and no read (the answer is the one before this step; the
 *   `flags.sharing` the UI already reads says off).
 * - A failed read never fails the session: `sharing: null` (the screens show no share control) and
 *   a `[rbac]` line naming the error code.
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/auth/me/route.sharing.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

vi.stubEnv('AUTH_SECRET', 'f'.repeat(64))

type Row = Record<string, unknown>
const h = vi.hoisted(() => ({
  jar: {} as { auth?: string },
  users: [] as Record<string, unknown>[],
  instance: null as Record<string, unknown> | null,
  /** Reads of the sharing policy column (each reader of the instance row selects its own columns). */
  policyReads: 0,
  failPolicy: false,
}))
vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => (name === 'redamon-auth' && h.jar.auth ? { value: h.jar.auth } : undefined),
    delete: () => {},
  })),
}))
const pick = (row: Row, select?: Row) =>
  select ? Object.fromEntries(Object.keys(select).filter((k) => select[k] && typeof select[k] !== 'object').map((k) => [k, row[k]])) : { ...row }
vi.mock('@/lib/prisma', () => ({
  default: {
    user: {
      findUnique: async ({ where, select }: { where: { id: string }; select?: Row }) => {
        const r = h.users.find((u) => u.id === where.id)
        if (!r) return null
        const out = pick(r, select)
        if (select?.permissionSets) out.permissionSets = []
        if (select?.permissionOverrides) out.permissionOverrides = []
        return out
      },
    },
    instanceSettings: {
      findUnique: async ({ select }: { select?: Row }) => {
        if (select?.sharingPolicy) {
          h.policyReads++
          if (h.failPolicy) throw Object.assign(new Error('db down'), { code: 'P1001' })
        }
        return h.instance && structuredClone(pick(h.instance, select))
      },
    },
    permissionSet: { findMany: async () => [] },
    auditLog: { findFirst: async () => null },
    actAsAudit: { findFirst: async () => null },
  },
}))
vi.mock('@/lib/authz/updateReview', () => ({ pendingLegacyGrantCount: async () => 0 }))

import { createToken } from '@/lib/auth'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { clearSharingPolicyCacheForTests, invalidateSharingPolicy } from '@/lib/authz/sharingPolicy'
import { GET } from './route'

const T = new Date('2026-01-01T00:00:00.000Z')
const ON = { identity: true, permissions: true, sharing: true }
const account = (id: string, role: string) => ({
  id, name: id, email: `${id}@e2e.local`, role, password: 'h', createdAt: T, legacyGrants: [], status: 'active',
  sessionVersion: 0, mustChangePassword: false, adminProfileId: null, lastLoginAt: null,
})

async function me(id: string) {
  const row = h.users.find((u) => u.id === id)!
  h.jar.auth = await createToken(id, String(row.role))
  const res = await GET()
  expect(res.status).toBe(200)
  return res.json()
}

beforeEach(() => {
  h.users = [account('root-1', 'admin'), account('member-1', 'standard')]
  h.instance = { id: 'instance', rootUserId: 'root-1', rootConfirmedAt: T, rootAssignedBy: 'install', defaultMemberSetId: null, sharingPolicy: {} }
  h.policyReads = 0
  h.failPolicy = false
  h.jar = {}
  setFlagsForTests(ON)
  vi.stubEnv('RBAC_AUTHZ_CACHE_MS', '')
  clearPrincipalCacheForTests()
  clearInstanceRootCacheForTests()
  clearCapabilityCachesForTests()
  clearSharingPolicyCacheForTests()
})
afterEach(() => {
  setFlagsForTests(null)
  vi.restoreAllMocks()
  vi.stubEnv('RBAC_AUTHZ_CACHE_MS', '')
})

describe('the switch on', () => {
  test.each(['member-1', 'root-1'])('%s: the stored {} -> sharing not in force, Read', async (id) => {
    expect((await me(id)).sharing).toEqual({ enabled: false, maxLevel: 'read' })
  })

  test('the policy enabled: in force for every account; Read while the write switch is off', async () => {
    h.instance!.sharingPolicy = { enabled: true, maxLevel: 'write' }
    expect((await me('member-1')).sharing).toEqual({ enabled: true, maxLevel: 'read' })
    expect((await me('root-1')).sharing).toEqual({ enabled: true, maxLevel: 'read' })
  })

  test('the write switch on: the policy\'s level', async () => {
    setFlagsForTests({ ...ON, sharingWrite: true })
    h.instance!.sharingPolicy = { enabled: true }
    expect((await me('member-1')).sharing).toEqual({ enabled: true, maxLevel: 'write' })
    invalidateSharingPolicy()
    h.instance!.sharingPolicy = { enabled: true, maxLevel: 'read' }
    expect((await me('member-1')).sharing).toEqual({ enabled: true, maxLevel: 'read' })
  })

  test('an invalid stored policy reads as off', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    h.instance!.sharingPolicy = { enabled: 'yes' }
    expect((await me('member-1')).sharing).toEqual({ enabled: false, maxLevel: 'read' })
  })

  test('one read per cache bound, whoever asks (the WebSocket auth_request path)', async () => {
    vi.stubEnv('RBAC_AUTHZ_CACHE_MS', '60000')
    await me('member-1')
    await me('root-1')
    await me('member-1')
    expect(h.policyReads).toBe(1)
  })

  test('a failed read: sharing null, a [rbac] line with the code, the session still answered', async () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})
    h.failPolicy = true
    const body = await me('member-1')
    expect(body.sharing).toBeNull()
    expect(body).toMatchObject({ id: 'member-1', flags: { sharing: true } })
    expect(error.mock.calls.map((c) => String(c[0]))).toContain('[rbac] could not read the sharing policy: P1001')
  })
})

describe('the switch off: the answer before this step', () => {
  test.each([
    ['identity + permissions on', { identity: true, permissions: true }],
    ['sharing set without permissions (the chain reads it off)', { identity: true, sharing: true }],
    ['every switch off', {}],
  ])('%s: no sharing key, no policy read', async (_what, flags) => {
    setFlagsForTests(flags)
    h.instance!.sharingPolicy = { enabled: true }
    for (const id of ['member-1', 'root-1']) {
      const body = await me(id)
      expect(body).not.toHaveProperty('sharing')
      expect(body.flags.sharing).toBe(false)
    }
    expect(h.policyReads).toBe(0)
  })
})
