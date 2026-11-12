/**
 * The administration and platform permissions of the signed-in person (adminPermission.ts): the
 * route-side form of `can()` for user administration, plugins and the instance capture. With
 * RBAC_PERMISSIONS_ENABLED off the account type's default answers, which is today's admin check
 * (Root and admins hold every administration permission but Root's own, members none); with it on
 * the admin profile decides. The real person decides, never the account acted as.
 *
 * Prisma (accounts, the instance row, custom sets) is a double; the registry, the built-in sets,
 * the resolution and can() are the real ones.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

const db = vi.hoisted(() => ({
  users: new Map<string, Record<string, unknown>>(),
  instance: null as Record<string, unknown> | null,
  sets: new Map<string, { id: string; kind: string; name: string; permissions: string[] }>(),
  failUsers: false,
}))
const userFindUnique = vi.fn(async ({ where }: { where: { id: string } }) => {
  if (db.failUsers) throw Object.assign(new Error('db down'), { code: 'P1001' })
  return db.users.get(where.id) ?? null
})
const instanceFindUnique = vi.fn(async () => (db.instance ? { ...db.instance } : null))
const setFindMany = vi.fn(async ({ where }: { where: { id: { in: string[] } } }) =>
  where.id.in.flatMap((id) => (db.sets.has(id) ? [{ ...db.sets.get(id)! }] : [])))
vi.mock('@/lib/prisma', () => ({
  default: {
    user: { findUnique: (a: { where: { id: string } }) => userFindUnique(a) },
    instanceSettings: { findUnique: () => instanceFindUnique() },
    permissionSet: { findMany: (a: { where: { id: { in: string[] } } }) => setFindMany(a) },
  },
}))

import { accountHolds, requireSessionPermission, sessionHolds } from './adminPermission'
import { setFlagsForTests } from './flags'
import { clearCapabilityCachesForTests } from './capabilities'
import { clearInstanceRootCacheForTests } from './root'
import { clearPrincipalCacheForTests, loadPrincipal } from './principal'
import { rememberSessionPrincipal } from './sessionPrincipal'
import { PERMISSIONS, PERMISSION_IDS, type PermissionId } from './permissions'

const ADMIN_SIDE = PERMISSION_IDS.filter((p) => PERMISSIONS[p].kind === 'admin')
const NOT_ROOT_ONLY = ADMIN_SIDE.filter((p) => !PERMISSIONS[p].rootOnly)
const CHECKED: PermissionId[] = ['users:read', 'users:create', 'users:edit', 'users:delete', 'users:reset_credentials',
  'users:assign_permissions', 'platform:plugins', 'platform:traffic_capture', 'admins:manage']

function account(id: string, role: string, over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id, email: `${id}@example.test`, name: id, role, password: 'hash', createdAt: new Date(0), legacyGrants: [],
    status: 'active', sessionVersion: 0, mustChangePassword: false, adminProfileId: null, lastLoginAt: null,
    permissionSets: [], permissionOverrides: [], ...over,
  }
}

/** The session getSession answers, with the account it read remembered beside it. */
async function readSession(id: string): Promise<{ userId: string; role: string }> {
  const principal = await loadPrincipal(id, { fresh: true })
  const session = { userId: principal!.id, role: principal!.role }
  rememberSessionPrincipal(session, principal!)
  return session
}

beforeEach(() => {
  db.users.clear()
  db.users.set('root', account('root', 'admin'))
  db.users.set('admin-1', account('admin-1', 'admin'))
  db.users.set('alice', account('alice', 'standard'))
  db.instance = { rootUserId: 'root', rootConfirmedAt: new Date(0), rootAssignedBy: 'install', defaultMemberSetId: null }
  db.sets.clear()
  db.failUsers = false
  for (const fn of [userFindUnique, instanceFindUnique, setFindMany]) fn.mockClear()
  setFlagsForTests({ identity: true, permissions: false })
  clearCapabilityCachesForTests()
  clearInstanceRootCacheForTests()
  clearPrincipalCacheForTests()
})
afterEach(() => {
  setFlagsForTests(null)
})

describe('switch off: the admin check of today, through can()', () => {
  test.each([[{ identity: false }], [{ identity: true }]])('%j: admins and Root hold every administration permission but Root\'s own; members none', async (flags) => {
    setFlagsForTests({ ...flags, permissions: false })
    for (const p of NOT_ROOT_ONLY) {
      expect(await sessionHolds(await readSession('admin-1'), p)).toBe(true)
      expect(await sessionHolds(await readSession('root'), p)).toBe(true)
      expect(await sessionHolds(await readSession('alice'), p)).toBe(false)
    }
  })

  test('admins:manage: every admin with the identity switch off (Phase 1), Root alone with it on', async () => {
    setFlagsForTests({ identity: false, permissions: false })
    expect(await sessionHolds(await readSession('admin-1'), 'admins:manage')).toBe(true)
    setFlagsForTests({ identity: true, permissions: false })
    clearInstanceRootCacheForTests()
    expect(await sessionHolds(await readSession('admin-1'), 'admins:manage')).toBe(false)
    expect(await sessionHolds(await readSession('root'), 'admins:manage')).toBe(true)
    expect(await sessionHolds(await readSession('alice'), 'admins:manage')).toBe(false)
  })

  test("a session object getSession did not build answers from the role it carries, reading neither person's account", async () => {
    for (const p of CHECKED.filter((x) => x !== 'admins:manage')) {
      expect(await sessionHolds({ userId: 'admin-1', role: 'admin' }, p)).toBe(true)
      expect(await sessionHolds({ userId: 'alice', role: 'standard' }, p)).toBe(false)
    }
    // Only the Root's account is read (root.ts), to tell Root from an admin.
    const read = userFindUnique.mock.calls.map(([a]) => a.where.id)
    expect(read.filter((id) => id !== 'root')).toEqual([])
  })

  test("a member's legacy grant is not on a session copy: the shared tool reads as not held (fail closed)", async () => {
    db.users.set('alice', account('alice', 'standard', { legacyGrants: ['tunnels'] }))
    expect(await sessionHolds({ userId: 'alice', role: 'standard' }, 'platform:tunnels')).toBe(false)
  })
})

describe('switch on: the admin profile decides', () => {
  beforeEach(() => {
    setFlagsForTests({ identity: true, permissions: true })
  })

  test('a User manager holds the user administration, not the platform', async () => {
    db.users.set('admin-1', account('admin-1', 'admin', { adminProfileId: 'builtin:user-manager' }))
    const session = await readSession('admin-1')
    expect(await sessionHolds(session, 'users:create')).toBe(true)
    expect(await sessionHolds(session, 'users:edit')).toBe(true)
    expect(await sessionHolds(session, 'platform:plugins')).toBe(false)
    expect(await sessionHolds(session, 'platform:traffic_capture')).toBe(false)
    expect(await sessionHolds(session, 'users:delete')).toBe(false)
  })

  test('a Platform operator holds the platform, not the user administration', async () => {
    db.users.set('admin-1', account('admin-1', 'admin', { adminProfileId: 'builtin:platform-operator' }))
    const session = await readSession('admin-1')
    expect(await sessionHolds(session, 'platform:plugins')).toBe(true)
    expect(await sessionHolds(session, 'users:create')).toBe(false)
    expect(await sessionHolds(session, 'users:read')).toBe(false)
  })

  test('a member holds a platform tool only through an override; never a user administration permission', async () => {
    db.users.set('alice', account('alice', 'standard', {
      permissionOverrides: [{ permission: 'platform:plugins', effect: 'grant', expiresAt: null, reason: 'r' }],
    }))
    const session = await readSession('alice')
    expect(await sessionHolds(session, 'platform:plugins')).toBe(true)
    expect(await sessionHolds(session, 'users:create')).toBe(false)
  })

  test('a session object getSession did not build: the account is read, never guessed from the role', async () => {
    db.users.set('admin-1', account('admin-1', 'admin', { adminProfileId: 'builtin:security-auditor' }))
    expect(await sessionHolds({ userId: 'admin-1', role: 'admin' }, 'users:create')).toBe(false)
    expect(await sessionHolds({ userId: 'admin-1', role: 'admin' }, 'users:read')).toBe(true)
    expect(userFindUnique).toHaveBeenCalled()
  })

  test('an account gone since the session was read holds nothing', async () => {
    expect(await sessionHolds({ userId: 'ghost', role: 'admin' }, 'users:read')).toBe(false)
  })

  test('a disabled account holds nothing', async () => {
    db.users.set('admin-1', account('admin-1', 'admin', { status: 'disabled' }))
    expect(await sessionHolds(await readSession('admin-1'), 'users:read')).toBe(false)
  })

  test('fresh: the account and the Root are read again', async () => {
    await sessionHolds({ userId: 'admin-1', role: 'admin' }, 'users:read')
    userFindUnique.mockClear()
    instanceFindUnique.mockClear()
    await sessionHolds({ userId: 'admin-1', role: 'admin' }, 'users:read', { fresh: true })
    expect(userFindUnique).toHaveBeenCalled()
    expect(instanceFindUnique).toHaveBeenCalled()
  })
})

describe('the real person, never a member permission', () => {
  test('a member permission throws: it acts on the effective user (requirePermission)', async () => {
    const session = await readSession('admin-1')
    await expect(sessionHolds(session, 'recon:scan')).rejects.toThrow(/member permission/)
    await expect(accountHolds('admin-1', 'graph:read')).rejects.toThrow(/member permission/)
  })

  test('an unknown permission throws', async () => {
    const session = await readSession('admin-1')
    await expect(sessionHolds(session, 'users:everything' as PermissionId)).rejects.toThrow()
  })

  test('a failed read throws, it never reads as held', async () => {
    setFlagsForTests({ identity: true, permissions: true })
    db.failUsers = true
    await expect(sessionHolds({ userId: 'admin-1', role: 'admin' }, 'users:read')).rejects.toThrow('db down')
  })
})

describe('requireSessionPermission', () => {
  test('null when held, else the 403 naming the permission', async () => {
    expect(await requireSessionPermission(await readSession('admin-1'), 'users:create')).toBeNull()
    const res = await requireSessionPermission(await readSession('alice'), 'users:create')
    expect(res?.status).toBe(403)
    expect(await res?.json()).toMatchObject({ code: 'forbidden', permission: 'users:create' })
  })
})

describe('accountHolds: an account named by id, read from the database', () => {
  test('the account read decides, whatever a session claimed', async () => {
    expect(await accountHolds('admin-1', 'platform:plugins')).toBe(true)
    expect(await accountHolds('alice', 'platform:plugins')).toBe(false)
    expect(await accountHolds('ghost', 'platform:plugins')).toBe(false)
  })

  test('fresh reads the account again', async () => {
    await accountHolds('admin-1', 'platform:plugins', { fresh: true })
    db.users.set('admin-1', account('admin-1', 'standard'))
    expect(await accountHolds('admin-1', 'platform:plugins', { fresh: true })).toBe(false)
  })
})
