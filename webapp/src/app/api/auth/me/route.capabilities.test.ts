/**
 * GET /api/auth/me tells the browser what the signed-in person may use (step 3.12; PE-21 instance
 * part, UI-01): `capabilities`, the permission ids `can()` decides with, in registry order, and
 * `flags`, the RBAC switch states the UI needs. Both reach every account, beside the top-level
 * fields other readers rely on (AuthProvider, McpTokensTab, e2e specs, urlscan_lab run_lab.py),
 * which stay as they were; `rbac` stays admin-only.
 *
 * - Switch off, every account gets its account type's default, today's product (PE-27).
 * - Under act-as the set is what the admin may use while acting (can.ts, §4.7): member permissions
 *   both people hold, administration ones the admin's. The top-level `id` stays the real person.
 * - The nginx `auth_request` of the WebSocket paths calls this route (T2): the capabilities come
 *   from the account getSession read and the Root this route already reads, no further query.
 * - A failed resolution never fails the session: `capabilities: null` (the UI shows nothing it
 *   gates) and a `[rbac]` line.
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/auth/me/route.capabilities.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

vi.stubEnv('AUTH_SECRET', 'f'.repeat(64))

type Row = Record<string, unknown>
const h = vi.hoisted(() => ({
  jar: {} as { auth?: string; actAs?: string },
  users: [] as Record<string, unknown>[],
  assignments: [] as { userId: string; setId: string }[],
  sets: [] as { id: string; kind: string; name: string; permissions: string[] }[],
  instance: null as Record<string, unknown> | null,
  instanceReads: 0,
  failSets: false,
}))
vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => {
      if (name === 'redamon-auth' && h.jar.auth) return { value: h.jar.auth }
      if (name === 'redamon-act-as' && h.jar.actAs) return { value: h.jar.actAs }
      return undefined
    },
    delete: () => {},
  })),
}))
const pick = (row: Row, select?: Row) =>
  select ? Object.fromEntries(Object.keys(select).filter((k) => select[k] && !(typeof select[k] === 'object')).map((k) => [k, row[k]])) : { ...row }
const userFindUnique = vi.fn(async ({ where, select }: { where: { id: string }; select?: Row }) => {
  const r = h.users.find((u) => u.id === where.id)
  if (!r) return null
  const out = pick(r, select)
  if (select?.permissionSets) out.permissionSets = h.assignments.filter((a) => a.userId === r.id).map((a) => ({ setId: a.setId }))
  if (select?.permissionOverrides) out.permissionOverrides = []
  return out
})
vi.mock('@/lib/prisma', () => ({
  default: {
    user: { findUnique: (a: { where: { id: string }; select?: Row }) => userFindUnique(a) },
    instanceSettings: {
      findUnique: async ({ select }: { select?: Row }) => {
        h.instanceReads++
        return h.instance && pick(h.instance, select)
      },
    },
    permissionSet: {
      findMany: async ({ where }: { where: { id: { in: string[] } } }) => {
        if (h.failSets) throw Object.assign(new Error('db down'), { code: 'P1001' })
        return h.sets.filter((s) => where.id.in.includes(s.id)).map((s) => ({ ...s }))
      },
    },
    auditLog: { findFirst: async () => null },
    // The act-as log (step 3.14): no row, so a cookie from before the switch acts (IM-12).
    actAsAudit: { findFirst: async () => null },
  },
}))
vi.mock('@/lib/authz/updateReview', () => ({ pendingLegacyGrantCount: async () => 0 }))

import { createActAsToken, createToken } from '@/lib/auth'
import { setFlagsForTests, type RbacFlags } from '@/lib/authz/flags'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { PERMISSIONS, PERMISSION_IDS, type PermissionId } from '@/lib/authz/permissions'
import { builtinSet, DEFAULT_MEMBER_SET_ID, FULL_ADMIN_PROFILE_ID } from '@/lib/authz/builtinSets'
import { GET } from './route'

const T = new Date('2026-01-01T00:00:00.000Z')
const account = (id: string, role: string, over: Row = {}) => ({
  id, name: id, email: `${id}@e2e.local`, role, password: 'h', createdAt: T, legacyGrants: [], status: 'active',
  sessionVersion: 0, mustChangePassword: false, adminProfileId: null, lastLoginAt: null, ...over,
})
const contents = (id: string): readonly PermissionId[] => builtinSet(id)!.permissions
/** In registry order, each once: the order the route answers in. */
const union = (...groups: ReadonlyArray<readonly string[]>): PermissionId[] => {
  const wanted = new Set(groups.flat())
  return PERMISSION_IDS.filter((p) => wanted.has(p))
}
const DEFAULT_MEMBER = contents(DEFAULT_MEMBER_SET_ID)
const FULL_ADMIN = contents(FULL_ADMIN_PROFILE_ID)
const ANALYST = contents('builtin:read-only-analyst')
const OFF: RbacFlags = { sharedToolsCompat: false, identity: false, permissions: false, sharing: false, sharingWrite: false, governance: false }

async function me(id: string, actAs?: string) {
  const row = h.users.find((u) => u.id === id)!
  h.jar.auth = await createToken(id, String(row.role))
  h.jar.actAs = actAs ? await createActAsToken(id, actAs) : undefined
  const res = await GET()
  expect(res.status).toBe(200)
  return res.json()
}

beforeEach(() => {
  h.users = [
    account('root-1', 'admin'),
    account('admin-2', 'admin'),
    account('member-1', 'standard'),
    account('legacy-1', 'standard', { legacyGrants: ['kali_terminal'] }),
  ]
  h.assignments = []
  h.sets = []
  h.instance = { id: 'instance', rootUserId: 'root-1', rootConfirmedAt: T, rootAssignedBy: 'install', defaultMemberSetId: null }
  h.instanceReads = 0
  h.failSets = false
  h.jar = {}
  userFindUnique.mockClear()
  setFlagsForTests({})
  vi.stubEnv('MCP_SERVER_ENABLED', 'true')
  vi.stubEnv('AGENT_IN_THE_LOOP_ENABLED', 'true')
  clearPrincipalCacheForTests()
  clearInstanceRootCacheForTests()
  clearCapabilityCachesForTests()
})
afterEach(() => {
  setFlagsForTests(null)
  vi.restoreAllMocks()
  vi.stubEnv('RBAC_AUTHZ_CACHE_MS', '')
})

describe('GET /api/auth/me: capabilities and flags (step 3.12)', () => {
  test('me returns capabilities beside the unchanged top-level fields (switch off: the account type\'s default)', async () => {
    expect(await me('member-1')).toEqual({
      id: 'member-1', name: 'member-1', email: 'member-1@e2e.local', role: 'standard',
      capabilities: union(DEFAULT_MEMBER), flags: OFF,
    })
    // Identity off: every admin also manages admins (Phase 1's rule, with step-up).
    expect(await me('admin-2')).toEqual({
      id: 'admin-2', name: 'admin-2', email: 'admin-2@e2e.local', role: 'admin',
      capabilities: union(FULL_ADMIN, DEFAULT_MEMBER, ['admins:manage']), flags: OFF,
      rbac: { compat: false, legacyGrantsPending: 0 },
    })
  })

  test('a member keeps its legacy grant as the platform permission it stands for (§14.7)', async () => {
    const body = await me('legacy-1')
    expect(body.capabilities).toEqual(union(DEFAULT_MEMBER, ['platform:kali_terminal']))
    expect(body.capabilities).not.toContain('users:read')
  })

  test('a member holds no administration permission: nothing the UI hides from members is held', async () => {
    const body = await me('member-1')
    expect(body.capabilities.filter((p: PermissionId) => PERMISSIONS[p].kind === 'admin')).toEqual([])
  })

  test('identity switch on: the confirmed Root holds every permission, an admin Full admin and its member side; flags reach the member too', async () => {
    setFlagsForTests({ identity: true })
    const root = await me('root-1')
    expect([root.accountType, root.capabilities]).toEqual(['root', [...PERMISSION_IDS]])
    const adm = await me('admin-2')
    expect([adm.accountType, adm.capabilities]).toEqual(['admin', union(FULL_ADMIN, DEFAULT_MEMBER)])
    const mem = await me('member-1')
    expect(mem).toEqual({
      id: 'member-1', name: 'member-1', email: 'member-1@e2e.local', role: 'standard', accountType: 'member',
      capabilities: union(DEFAULT_MEMBER), flags: { ...OFF, identity: true },
    })
  })

  test('permissions switch on: the sets assigned decide, and rbac stays admin-only', async () => {
    setFlagsForTests({ identity: true, permissions: true })
    h.assignments = [{ userId: 'member-1', setId: 'builtin:read-only-analyst' }]
    h.users[1].adminProfileId = 'builtin:user-manager'
    const mem = await me('member-1')
    expect(mem.capabilities).toEqual(union(ANALYST))
    expect(mem.flags).toEqual({ ...OFF, identity: true, permissions: true })
    expect(mem).not.toHaveProperty('rbac')
    const adm = await me('admin-2')
    expect(adm.capabilities).toEqual(union(contents('builtin:user-manager'), DEFAULT_MEMBER))
    expect(adm.rbac).toMatchObject({ identity: true })
  })

  test('under act-as: what the admin may use while acting (member permissions both hold, administration ones its own); the real person stays the answer\'s id', async () => {
    setFlagsForTests({ identity: true, permissions: true })
    h.assignments = [{ userId: 'member-1', setId: 'builtin:read-only-analyst' }]
    const body = await me('admin-2', 'member-1')
    expect(body).toMatchObject({ id: 'admin-2', role: 'admin', accountType: 'admin' })
    expect(body.capabilities).toEqual(union(FULL_ADMIN, ANALYST.filter((p) => DEFAULT_MEMBER.includes(p))))
    expect(body.capabilities).toContain('users:impersonate')
    expect(body.capabilities).not.toContain('recon:scan')
    // Back to itself: its own set again.
    expect((await me('admin-2')).capabilities).toEqual(union(FULL_ADMIN, DEFAULT_MEMBER))
  })

  test("a member's act-as cookie changes nothing: its own set", async () => {
    setFlagsForTests({ identity: true, permissions: true })
    h.assignments = [{ userId: 'member-1', setId: 'builtin:read-only-analyst' }]
    expect((await me('legacy-1', 'member-1')).capabilities).toEqual(union(DEFAULT_MEMBER, ['platform:kali_terminal']))
  })

  test('a failed resolution never fails the session: capabilities null, the rest unchanged, and logged', async () => {
    setFlagsForTests({ identity: true, permissions: true })
    h.sets = [{ id: 'set-x', kind: 'member', name: 'X', permissions: ['recon:read'] }]
    h.assignments = [{ userId: 'member-1', setId: 'set-x' }]
    h.failSets = true
    const err = vi.spyOn(console, 'error').mockImplementation(() => {})
    expect(await me('member-1')).toEqual({
      id: 'member-1', name: 'member-1', email: 'member-1@e2e.local', role: 'standard', accountType: 'member',
      capabilities: null, flags: { ...OFF, identity: true, permissions: true },
    })
    expect(err.mock.calls.map((c) => c.join(' '))).toEqual(['[rbac] could not resolve the capabilities: P1001'])
  })

  test('no extra query (T2: the nginx auth_request calls this route): one Root read per admin load, also with no cache', async () => {
    vi.stubEnv('RBAC_AUTHZ_CACHE_MS', '0')
    setFlagsForTests({ identity: true })
    await me('admin-2')
    expect(h.instanceReads).toBe(1)
    // A member reads no instance row at all.
    h.instanceReads = 0
    await me('member-1')
    expect(h.instanceReads).toBe(0)
  })

  test('the account is read as getSession read it: the capabilities cost no account read of their own', async () => {
    // The account cache exists with the identity switch on (principal.ts).
    setFlagsForTests({ identity: true, permissions: true })
    await me('member-1')
    userFindUnique.mockClear()
    // Cached account: the one read left is the route's own name and email read.
    await me('member-1')
    expect(userFindUnique).toHaveBeenCalledTimes(1)
  })
})
