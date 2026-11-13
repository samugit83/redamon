/**
 * GET /api/admin/users and GET /api/admin/users/[id] (step 6.2; GV-01, ID-27): the admin console's
 * users directory and one account's detail. With RBAC_GOVERNANCE_ENABLED off both are 404 having
 * read nothing; users:read opens them (a 403 naming it otherwise); the directory pages with a cursor
 * and filters; each row carries the actions the signed-in person may take on it (hierarchy.ts);
 * shared-project counts and lists read collaborator rows only with sharing in force (lists only
 * while Root's policy lets admins see every share); the audit section needs audit:read and never
 * carries a row's before/after.
 *
 * The routes and lib/authz/userDirectory.ts are real; the session, the permission answers, the
 * Root, the sharing policy and Prisma are doubles (Prisma inline: the queries are asserted).
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/admin/users/route.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const h = vi.hoisted(() => ({
  session: { userId: 'adm-a', role: 'admin' } as { userId: string; role: string } | null,
  held: new Set<string>(),
  manager: { id: 'adm-a', accountType: 'admin', held: [] as string[] },
  root: { userId: 'root-1', email: 'root@e2e.local', confirmed: true, assignedBy: 'host' } as unknown,
  /** 'real': the real reader answers (it reads nothing with the sharing switch off). */
  policy: null as null | 'real' | { enabled: boolean; adminsSeeAllShares: boolean },
  db: {
    userFindMany: vi.fn(),
    userFindUnique: vi.fn(),
    userCount: vi.fn(),
    setFindMany: vi.fn(),
    setFindUnique: vi.fn(),
    collaboratorFindMany: vi.fn(),
    auditFindMany: vi.fn(),
  },
}))

vi.mock('@/lib/prisma', () => {
  const client = {
    user: { findMany: h.db.userFindMany, findUnique: h.db.userFindUnique, count: h.db.userCount },
    permissionSet: { findMany: h.db.setFindMany, findUnique: h.db.setFindUnique },
    projectCollaborator: { findMany: h.db.collaboratorFindMany },
    auditLog: { findMany: h.db.auditFindMany },
  }
  return { default: client, prisma: client }
})
vi.mock('@/lib/session', () => ({
  requireSession: vi.fn(async () => h.session ?? NextResponse.json({ error: 'Unauthorized' }, { status: 401 })),
}))
vi.mock('@/lib/authz/adminPermission', async () => {
  const { forbiddenResponse } = await import('@/lib/authz/guards')
  return {
    sessionHolds: vi.fn(async (_s: unknown, p: string) => h.held.has(p)),
    requireSessionPermission: vi.fn(async (_s: unknown, p: Parameters<typeof forbiddenResponse>[0]) => (h.held.has(p) ? null : forbiddenResponse(p))),
  }
})
vi.mock('@/lib/authz/permissionAdmin', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/authz/permissionAdmin')>()),
  managerOf: vi.fn(async () => ({ manager: h.manager })),
}))
vi.mock('@/lib/authz/root', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/authz/root')>()),
  loadInstanceRoot: vi.fn(async () => h.root),
}))
vi.mock('@/lib/authz/sharingPolicy', async (importOriginal) => {
  const real = await importOriginal<typeof import('@/lib/authz/sharingPolicy')>()
  return { ...real, sharingPolicyInForce: vi.fn(async () => (h.policy === 'real' ? real.sharingPolicyInForce() : h.policy)) }
})

import { setFlagsForTests } from '@/lib/authz/flags'
import { setNowForTests } from '@/lib/authz/clock'
import { BUILTIN_ADMIN_PROFILES, BUILTIN_MEMBER_SETS, BUILTIN_SETS } from '@/lib/authz/builtinSets'
import { encodeCursor } from '@/lib/authz/userDirectory'
import { GET as listUsers } from './route'
import { GET as getUser } from './[id]/route'

const NOW = new Date('2026-11-13T12:00:00.000Z')
const GOV = { identity: true, permissions: true, governance: true }
const MEMBER_SIDE = BUILTIN_MEMBER_SETS.find((s) => s.id === 'builtin:default-member')!.permissions
const userManager = BUILTIN_ADMIN_PROFILES.find((s) => s.id === 'builtin:user-manager')!.permissions

function account(id: string, over: Record<string, unknown> = {}) {
  return {
    id, name: `${id} name`, email: `${id}@e2e.local`, role: 'standard', status: 'active', mustChangePassword: false,
    lastLoginAt: null, createdAt: new Date(`2026-11-0${(id.length % 9) + 1}T08:00:00.000Z`), adminProfileId: null,
    permissionSets: [], _count: { projects: 0 }, ...over,
  }
}

const list = (qs = '') => listUsers(new NextRequest(`http://redamon.test/api/admin/users${qs ? `?${qs}` : ''}`))
const detail = (id: string) => getUser(new NextRequest(`http://redamon.test/api/admin/users/${id}`), { params: Promise.resolve({ id }) })
const body = async (res: Response) => res.json() as Promise<Record<string, any>>
const findManyArg = () => h.db.userFindMany.mock.calls[0][0]

beforeEach(() => {
  setFlagsForTests(GOV)
  setNowForTests(() => NOW)
  h.session = { userId: 'adm-a', role: 'admin' }
  h.held = new Set(['users:read'])
  h.manager = { id: 'adm-a', accountType: 'admin', held: [...userManager, ...MEMBER_SIDE] }
  h.root = { userId: 'root-1', email: 'root@e2e.local', confirmed: true, assignedBy: 'host' }
  h.policy = null
  for (const fn of Object.values(h.db)) fn.mockReset()
  h.db.userFindMany.mockResolvedValue([])
  h.db.userCount.mockResolvedValue(0)
  h.db.setFindMany.mockResolvedValue([])
  h.db.setFindUnique.mockResolvedValue(null)
  h.db.collaboratorFindMany.mockResolvedValue([])
  h.db.auditFindMany.mockResolvedValue([])
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
})

describe('with RBAC_GOVERNANCE_ENABLED off', () => {
  test.each([
    ['every switch off', {}],
    ['identity and permissions on', { identity: true, permissions: true }],
  ])('%s: both routes are 404 and read nothing', async (_what, flags) => {
    setFlagsForTests(flags)
    expect((await list()).status).toBe(404)
    expect((await detail('m-1')).status).toBe(404)
    for (const fn of Object.values(h.db)) expect(fn).not.toHaveBeenCalled()
  })
})

describe('who may read it', () => {
  test('signed out: 401', async () => {
    h.session = null
    expect((await list()).status).toBe(401)
    expect((await detail('m-1')).status).toBe(401)
  })

  test('without users:read: 403 naming it, nothing read', async () => {
    h.held = new Set(['audit:read'])
    for (const res of [await list(), await detail('m-1')]) {
      expect(res.status).toBe(403)
      expect(await body(res)).toMatchObject({ code: 'forbidden', permission: 'users:read' })
    }
    expect(h.db.userFindMany).not.toHaveBeenCalled()
    expect(h.db.userFindUnique).not.toHaveBeenCalled()
  })

  test('an unknown filter value: 400 naming the field, nothing read', async () => {
    const res = await list('status=gone')
    expect(res.status).toBe(400)
    expect(await body(res)).toMatchObject({ code: 'invalid_filter', field: 'status' })
    expect(h.db.userFindMany).not.toHaveBeenCalled()
  })
})

describe('filters and pagination', () => {
  test('the filters reach the query; one row more than the page is asked, and its presence gives the next cursor', async () => {
    const rows = [account('m-3'), account('m-2'), account('m-1')]
    h.db.userFindMany.mockResolvedValue(rows)
    h.db.userCount.mockResolvedValue(7)
    const res = await list('q=ada&status=active&type=member&limit=2')
    expect(res.status).toBe(200)
    const answer = await body(res)
    const where = { AND: [
      { OR: [{ name: { contains: 'ada', mode: 'insensitive' } }, { email: { contains: 'ada', mode: 'insensitive' } }] },
      { status: 'active' },
      { role: { not: 'admin' } },
    ] }
    expect(findManyArg()).toMatchObject({ where, take: 3, orderBy: [{ createdAt: 'desc' }, { id: 'desc' }] })
    expect(h.db.userCount).toHaveBeenCalledWith({ where })
    expect(answer.users.map((u: { id: string }) => u.id)).toEqual(['m-3', 'm-2'])
    expect(answer.total).toBe(7)
    expect(answer.nextCursor).toBe(encodeCursor({ createdAt: rows[1].createdAt, id: 'm-2' }))
  })

  test('the next page starts after the cursor; the total ignores it; the last page has no cursor', async () => {
    const cursor = { createdAt: new Date('2026-11-05T08:00:00.000Z'), id: 'm-2' }
    h.db.userFindMany.mockResolvedValue([account('m-1')])
    const answer = await body(await list(`cursor=${encodeCursor(cursor)}`))
    expect(findManyArg().where).toEqual({ AND: [{}, { OR: [
      { createdAt: { lt: cursor.createdAt } },
      { createdAt: cursor.createdAt, id: { lt: 'm-2' } },
    ] }] })
    expect(h.db.userCount).toHaveBeenCalledWith({ where: {} })
    expect(answer.nextCursor).toBeNull()
  })

  test('set: a custom admin profile lists the admins naming it; a member set its assignment rows', async () => {
    h.db.setFindUnique.mockResolvedValueOnce({ kind: 'admin' })
    await list('set=prof-1')
    expect(findManyArg().where).toEqual({ AND: [{ role: 'admin', adminProfileId: 'prof-1' }] })
    h.db.userFindMany.mockClear()
    await list('set=builtin:recon-operator')
    expect(findManyArg().where).toEqual({ AND: [{ permissionSets: { some: { setId: 'builtin:recon-operator' } } }] })
  })

  test('type=root without a Root on the instance selects nobody', async () => {
    h.root = null
    await list('type=root')
    expect(findManyArg().where).toEqual({ AND: [{ id: { in: [] } }] })
  })

  test('the set filter offers every built-in set and profile and the custom ones', async () => {
    h.db.setFindMany.mockImplementation(async (a: { where?: unknown }) => (a.where ? [] : [
      { id: 'set-b', name: 'B custom', kind: 'member' }, { id: 'prof-a', name: 'A profile', kind: 'admin' },
    ]))
    const answer = await body(await list())
    expect(answer.setOptions).toEqual([
      ...BUILTIN_SETS.map((s) => ({ id: s.id, name: s.name, kind: s.kind })),
      { id: 'prof-a', name: 'A profile', kind: 'admin' },
      { id: 'set-b', name: 'B custom', kind: 'member' },
    ])
  })
})

describe('what a row shows', () => {
  test('type, status, sets or profile, last sign-in and project counts; nothing else of the account', async () => {
    const login = new Date('2026-11-12T09:30:00.000Z')
    h.db.userFindMany.mockResolvedValue([
      account('root-1', { role: 'admin', adminProfileId: null }),
      account('adm-b', { role: 'admin', adminProfileId: 'builtin:user-manager', lastLoginAt: login }),
      account('adm-c', { role: 'admin', adminProfileId: null }),
      account('adm-d', { role: 'admin', adminProfileId: 'prof-gone' }),
      account('m-1', { permissionSets: [{ setId: 'builtin:recon-operator' }, { setId: 'set-1' }, { setId: 'set-gone' }], _count: { projects: 3 } }),
      account('m-2', { status: 'invited', mustChangePassword: true }),
    ])
    h.db.setFindMany.mockImplementation(async (a: { where?: { id: { in: string[] } } }) => (
      a.where ? [{ id: 'set-1', name: 'Custom one', kind: 'member', permissions: [] }].filter((r) => a.where!.id.in.includes(r.id)) : []
    ))
    const answer = await body(await list())
    const byId = Object.fromEntries(answer.users.map((u: { id: string }) => [u.id, u]))
    expect(Object.keys(byId['m-1']).sort()).toEqual([
      'accountType', 'actions', 'createdAt', 'email', 'id', 'lastLoginAt', 'mustChangePassword', 'name', 'profile',
      'projects', 'self', 'sets', 'status',
    ])
    expect(byId['root-1']).toMatchObject({ accountType: 'root', sets: null, profile: null })
    expect(byId['adm-b']).toMatchObject({
      accountType: 'admin', sets: null, profile: { id: 'builtin:user-manager', name: 'User manager' }, lastLoginAt: login.toISOString(),
    })
    expect(byId['adm-c'].profile).toEqual({ id: 'builtin:full-admin', name: 'Full admin' })
    expect(byId['adm-d'].profile).toEqual({ id: 'prof-gone', name: null })
    expect(byId['m-1']).toMatchObject({
      accountType: 'member', profile: null, projects: { owned: 3, shared: null },
      sets: [{ id: 'builtin:recon-operator', name: 'Recon operator' }, { id: 'set-1', name: 'Custom one' }, { id: 'set-gone', name: null }],
    })
    expect(byId['m-2']).toMatchObject({ status: 'invited', mustChangePassword: true, sets: [] })
    // The password hash, notices and session version are never selected.
    const select = findManyArg().select
    for (const secret of ['password', 'passwordOnHold', 'pendingNotices', 'sessionVersion', 'legacyGrants']) expect(select).not.toHaveProperty(secret)
  })

  test('row actions follow the hierarchy (a User manager): members only, by status; none on admins, Root or the own row', async () => {
    h.db.userFindMany.mockResolvedValue([
      account('root-1', { role: 'admin' }),
      account('adm-a', { role: 'admin', adminProfileId: 'builtin:user-manager' }),
      account('adm-b', { role: 'admin', adminProfileId: 'builtin:user-manager' }),
      account('m-1'),
      account('m-2', { status: 'disabled' }),
      account('m-3', { status: 'invited' }),
    ])
    const answer = await body(await list())
    const actions = Object.fromEntries(answer.users.map((u: { id: string; actions: string[] }) => [u.id, u.actions]))
    expect(actions).toEqual({
      'root-1': [],
      'adm-a': [],
      'adm-b': [],
      'm-1': ['edit', 'assign_permissions', 'disable', 'reset_credentials', 'revoke_sessions'],
      'm-2': ['edit', 'assign_permissions', 'enable', 'reset_credentials'],
      'm-3': ['create', 'edit', 'assign_permissions'],
    })
    expect(answer.users.find((u: { id: string }) => u.id === 'adm-a').self).toBe(true)
  })

  test('with sharing not in force no collaborator count is selected and shared reads null', async () => {
    h.policy = { enabled: false, adminsSeeAllShares: true }
    h.db.userFindMany.mockResolvedValue([account('m-1')])
    const answer = await body(await list())
    expect(findManyArg().select._count).toEqual({ select: { projects: true } })
    expect(answer.sharing).toBe(false)
    expect(answer.users[0].projects.shared).toBeNull()
  })

  test('the sharing switch off (the real policy reader): no policy read, no collaborator count, no share listed', async () => {
    h.policy = 'real'
    h.db.userFindMany.mockResolvedValue([account('m-1')])
    h.db.userFindUnique.mockResolvedValue({ ...account('m-1'), projects: [] })
    const page = await body(await list())
    expect(findManyArg().select._count).toEqual({ select: { projects: true } })
    expect(page.users[0].projects.shared).toBeNull()
    expect((await body(await detail('m-1'))).shared).toEqual({ state: 'off' })
    expect(h.db.collaboratorFindMany).not.toHaveBeenCalled()
  })

  test('with sharing in force the live shares are counted (an expired one is not)', async () => {
    h.policy = { enabled: true, adminsSeeAllShares: false }
    h.db.userFindMany.mockResolvedValue([account('m-1', { _count: { projects: 1, collaborations: 2 } })])
    const answer = await body(await list())
    expect(findManyArg().select._count).toEqual({ select: {
      projects: true, collaborations: { where: { OR: [{ expiresAt: null }, { expiresAt: { gt: NOW } }] } },
    } })
    expect(answer.sharing).toBe(true)
    expect(answer.users[0].projects).toEqual({ owned: 1, shared: 2 })
  })
})

describe('detail sections', () => {
  const PROJECT = {
    id: 'p-1', name: 'Lab', createdAt: new Date('2026-11-01T00:00:00Z'), updatedAt: new Date('2026-11-02T00:00:00Z'),
    targetDomain: 'lab.example.test', ipMode: false, targetIps: [], subdomainList: [], domainBatchMode: false, domainBatchHosts: [],
  }

  test('an unknown account: 404', async () => {
    h.db.userFindUnique.mockResolvedValue(null)
    const res = await detail('nobody')
    expect(res.status).toBe(404)
    expect(await body(res)).toMatchObject({ code: 'user_not_found' })
  })

  test('the row with its actions, its own projects by name and date (scope only with projects:oversee), shares off, audit denied', async () => {
    h.db.userFindUnique.mockResolvedValue({ ...account('m-1', { _count: { projects: 1 } }), projects: [PROJECT] })
    const answer = await body(await detail('m-1'))
    expect(h.db.userFindUnique.mock.calls[0][0].select.projects.select).toEqual({ id: true, name: true, createdAt: true, updatedAt: true })
    expect(answer.user).toMatchObject({ id: 'm-1', accountType: 'member', actions: ['edit', 'assign_permissions', 'disable', 'reset_credentials', 'revoke_sessions'] })
    expect(answer.owned).toEqual([{ id: 'p-1', name: 'Lab', createdAt: '2026-11-01T00:00:00.000Z', updatedAt: '2026-11-02T00:00:00.000Z' }])
    expect(answer.shared).toEqual({ state: 'off' })
    expect(answer.audit).toEqual({ denied: 'audit:read' })
    expect(h.db.collaboratorFindMany).not.toHaveBeenCalled()
    expect(h.db.auditFindMany).not.toHaveBeenCalled()
  })

  test('with projects:oversee each own project carries its scope label', async () => {
    h.held = new Set(['users:read', 'projects:oversee'])
    h.db.userFindUnique.mockResolvedValue({ ...account('m-1'), projects: [PROJECT] })
    const answer = await body(await detail('m-1'))
    expect(answer.owned[0]).toMatchObject({ id: 'p-1', targetLabel: 'lab.example.test' })
  })

  test('shares: hidden when Root\'s policy keeps others\' shares from admins, listed (live ones) when it does not', async () => {
    h.db.userFindUnique.mockResolvedValue({ ...account('m-1'), projects: [] })
    h.policy = { enabled: true, adminsSeeAllShares: false }
    expect((await body(await detail('m-1'))).shared).toEqual({ state: 'hidden' })
    expect(h.db.collaboratorFindMany).not.toHaveBeenCalled()

    h.policy = { enabled: true, adminsSeeAllShares: true }
    h.db.collaboratorFindMany.mockResolvedValue([{
      access: 'read', expiresAt: new Date('2026-12-01T00:00:00Z'), createdAt: new Date('2026-11-10T00:00:00Z'),
      project: { id: 'p-9', name: 'Shared lab', user: { id: 'm-9', name: 'Owner', email: 'owner@e2e.local' } },
    }])
    const answer = await body(await detail('m-1'))
    expect(h.db.collaboratorFindMany.mock.calls[0][0].where).toEqual({ userId: 'm-1', OR: [{ expiresAt: null }, { expiresAt: { gt: NOW } }] })
    expect(answer.shared).toEqual({ state: 'listed', projects: [{
      id: 'p-9', name: 'Shared lab', owner: { id: 'm-9', name: 'Owner', email: 'owner@e2e.local' }, access: 'read',
      expiresAt: '2026-12-01T00:00:00.000Z', sharedAt: '2026-11-10T00:00:00.000Z',
    }] })
  })

  test('with audit:read: the latest 20 rows where the account is the actor or the target, never their before/after', async () => {
    h.held = new Set(['users:read', 'audit:read'])
    h.db.userFindUnique.mockResolvedValue({ ...account('m-1'), projects: [] })
    h.db.auditFindMany.mockResolvedValue([{
      id: 'a-1', action: 'user.disabled', createdAt: new Date('2026-11-13T11:00:00Z'), actorId: 'adm-a', actorEmail: 'adm-a@e2e.local',
      onBehalfOfUserId: null, targetType: 'user', targetId: 'm-1', projectId: null, permission: 'users:disable', source: 'api',
    }])
    const answer = await body(await detail('m-1'))
    const arg = h.db.auditFindMany.mock.calls[0][0]
    expect(arg.where).toEqual({ OR: [{ actorId: 'm-1' }, { targetType: 'user', targetId: 'm-1' }] })
    expect(arg.take).toBe(20)
    expect(arg.select).not.toHaveProperty('before')
    expect(arg.select).not.toHaveProperty('after')
    expect(answer.audit).toEqual({ rows: [{
      id: 'a-1', action: 'user.disabled', createdAt: '2026-11-13T11:00:00.000Z', actorId: 'adm-a', actorEmail: 'adm-a@e2e.local',
      onBehalfOfUserId: null, targetType: 'user', targetId: 'm-1', projectId: null, permission: 'users:disable', source: 'api',
    }] })
  })

  test('the confirmed Root on another admin: every action; on its own detail none', async () => {
    h.manager = { id: 'root-1', accountType: 'root', held: [...BUILTIN_SETS.flatMap((s) => s.permissions), 'admins:manage', 'instance:settings'] }
    h.db.userFindUnique.mockResolvedValue({ ...account('adm-b', { role: 'admin', adminProfileId: 'builtin:user-manager' }), projects: [] })
    expect((await body(await detail('adm-b'))).user.actions).toEqual(
      ['edit', 'assign_permissions', 'disable', 'reset_credentials', 'revoke_sessions', 'impersonate', 'delete'])
    h.db.userFindUnique.mockResolvedValue({ ...account('root-1', { role: 'admin' }), projects: [] })
    expect((await body(await detail('root-1'))).user).toMatchObject({ accountType: 'root', self: true, actions: [] })
  })
})
