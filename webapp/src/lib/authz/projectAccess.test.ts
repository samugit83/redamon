/**
 * The project layer of the policy (step 3.5, step 4.3; feature document §4.2, §6.1): how far a
 * person may go on one project. The person is the effective user, so under act-as it is the account
 * acted as, exactly as `getEffectiveUser` answers today.
 *
 * Step 4.3 (SH-02, SH-03, SH-14, SH-16, SH-18, IM-07, DV-27): with sharing in force (the switch
 * and Root's policy) a live share is `read` (Raw data & files when the row says so), a row at
 * `write` reads as `read` until Phase 5, an unexpired break-glass row of someone who holds
 * `projects:administer` is `read` with raw, `projects:oversee` is `read` without raw; an expired,
 * disabled or deleted collaborator's share is inert. `meetsLevel` gives each level its table.
 *
 * Prisma is a double (the project, the share, the break-glass rows, the accounts, the instance row);
 * the clock is injected; the policy reader, the principal and the capabilities are the real ones.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

interface Share {
  access: string
  rawData: boolean
  expiresAt: Date | null
  user: { status: string } | null
}

const db = vi.hoisted(() => ({
  projects: new Map<string, { id: string; userId: string }>(),
  shares: new Map<string, Share>(),
  breakGlass: [] as Array<{ projectId: string; userId: string; expiresAt: Date }>,
  users: new Map<string, Record<string, unknown>>(),
  instance: null as Record<string, unknown> | null,
}))
const findUnique = vi.fn(async ({ where }: { where: { id: string } }) => {
  const row = db.projects.get(where.id)
  return row ? { ...row } : null
})
const collaboratorFindUnique = vi.fn(async ({ where }: { where: { projectId_userId: { projectId: string; userId: string } } }) => {
  const { projectId, userId } = where.projectId_userId
  const row = db.shares.get(`${projectId}|${userId}`)
  return row ? { ...row } : null
})
// The double ignores the expiry filter on purpose: projectAccess() must judge expiry itself too.
const breakGlassFindFirst = vi.fn(async ({ where }: { where: { projectId: string; userId: string } }) => {
  const row = db.breakGlass.find((r) => r.projectId === where.projectId && r.userId === where.userId)
  return row ? { expiresAt: row.expiresAt } : null
})
const userFindUnique = vi.fn(async ({ where }: { where: { id: string } }) => {
  const row = db.users.get(where.id)
  return row ? { ...row } : null
})
const instanceFindUnique = vi.fn(async () => (db.instance ? { ...db.instance } : null))
vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: (a: { where: { id: string } }) => findUnique(a) },
    projectCollaborator: { findUnique: (a: Parameters<typeof collaboratorFindUnique>[0]) => collaboratorFindUnique(a) },
    projectBreakGlass: { findFirst: (a: Parameters<typeof breakGlassFindFirst>[0]) => breakGlassFindFirst(a) },
    user: { findUnique: (a: { where: { id: string } }) => userFindUnique(a) },
    instanceSettings: { findUnique: () => instanceFindUnique() },
    permissionSet: { findMany: async () => [] },
  },
}))

import { projectAccess, meetsLevel, type ProjectAccess } from './projectAccess'
import { PROJECT_LEVELS, type ProjectLevel } from './permissions'
import { setFlagsForTests } from './flags'
import { setNowForTests } from './clock'
import { clearSharingPolicyCacheForTests } from './sharingPolicy'
import { clearPrincipalCacheForTests } from './principal'
import { clearCapabilityCachesForTests } from './capabilities'
import { clearInstanceRootCacheForTests } from './root'

const NOW = new Date('2026-11-13T12:00:00Z')
const HOUR = 3_600_000

function account(id: string, over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id, email: `${id}@example.test`, name: id, role: 'standard', password: 'hash', createdAt: new Date(0),
    legacyGrants: [], status: 'active', sessionVersion: 0, mustChangePassword: false, adminProfileId: null,
    lastLoginAt: null, permissionSets: [], permissionOverrides: [], ...over,
  }
}

function share(projectId: string, userId: string, over: Partial<Share> = {}): void {
  db.shares.set(`${projectId}|${userId}`, { access: 'read', rawData: false, expiresAt: null, user: { status: 'active' }, ...over })
}

const owner = (projectId = 'P', userId = 'owner-1') =>
  ({ project: { id: projectId, userId }, level: 'owner', toggles: { rawData: true }, via: 'owner' })
const read = (via: string, rawData: boolean, projectId = 'P', userId = 'owner-1') =>
  ({ project: { id: projectId, userId }, level: 'read', toggles: { rawData }, via })

const WRITE_LEVELS: ProjectLevel[] = ['W', 'W+S', 'W+A', 'W+X', 'M', 'O']

function levelsMet(access: ProjectAccess): ProjectLevel[] {
  return PROJECT_LEVELS.filter((l) => meetsLevel(access, l))
}

beforeEach(() => {
  db.projects.clear()
  db.projects.set('P', { id: 'P', userId: 'owner-1' })
  db.shares.clear()
  db.breakGlass = []
  db.users.clear()
  for (const id of ['owner-1', 'viewer', 'stranger']) db.users.set(id, account(id))
  db.users.set('admin-1', account('admin-1', { role: 'admin' }))
  db.users.set('root-1', account('root-1', { role: 'admin' }))
  db.instance = {
    sharingPolicy: { enabled: true }, rootUserId: 'root-1', rootConfirmedAt: new Date(0), rootAssignedBy: null,
    defaultMemberSetId: null,
  }
  for (const f of [findUnique, collaboratorFindUnique, breakGlassFindFirst, userFindUnique, instanceFindUnique]) f.mockClear()
  setNowForTests(() => NOW)
  setFlagsForTests({})
  clearSharingPolicyCacheForTests()
  clearPrincipalCacheForTests()
  clearCapabilityCachesForTests()
  clearInstanceRootCacheForTests()
})
afterEach(() => {
  setNowForTests(null)
  setFlagsForTests(null)
  vi.restoreAllMocks()
})

describe('projectAccess: the owner and anyone else, sharing not in force (Phase 3 answers)', () => {
  test('the owner sees the project as its owner, with every toggle', async () => {
    const access = await projectAccess({ userId: 'owner-1' }, 'P')
    expect(access).toEqual(owner())
    expect(Object.isFrozen(access)).toBe(true)
    expect(Object.isFrozen(access!.project)).toBe(true)
    expect(Object.isFrozen(access!.toggles)).toBe(true)
  })

  test('one read by primary key, the id and the owner only', async () => {
    await projectAccess({ userId: 'owner-1' }, 'P')
    expect(findUnique).toHaveBeenCalledTimes(1)
    expect(findUnique).toHaveBeenCalledWith({ where: { id: 'P' }, select: { id: true, userId: true } })
  })

  test('anyone else does not see it: null, the same answer as a project that does not exist (anti-enumeration)', async () => {
    expect(await projectAccess({ userId: 'other' }, 'P')).toBeNull()
    expect(await projectAccess({ userId: 'other' }, 'missing')).toBeNull()
    expect(await projectAccess({ userId: 'owner-1' }, 'missing')).toBeNull()
  })

  test('no project id: null, and nothing is read', async () => {
    expect(await projectAccess({ userId: 'owner-1' }, '')).toBeNull()
    expect(findUnique).not.toHaveBeenCalled()
  })

  test('no person: null, and nothing is read', async () => {
    expect(await projectAccess({ userId: '' }, 'P')).toBeNull()
    expect(findUnique).not.toHaveBeenCalled()
  })

  test('a failed read throws: it never reads as access', async () => {
    findUnique.mockRejectedValueOnce(Object.assign(new Error('db down'), { code: 'P1001' }))
    await expect(projectAccess({ userId: 'owner-1' }, 'P')).rejects.toMatchObject({ code: 'P1001' })
  })

  test('switch off → owner only: a share, a break-glass row and oversight give nothing, and none is read', async () => {
    share('P', 'viewer', { rawData: true })
    db.breakGlass.push({ projectId: 'P', userId: 'root-1', expiresAt: new Date(NOW.getTime() + HOUR) })
    for (const flags of [{}, { identity: true, permissions: true }]) {
      setFlagsForTests(flags)
      for (const who of ['viewer', 'root-1', 'admin-1']) expect([who, await projectAccess({ userId: who }, 'P')]).toEqual([who, null])
      expect(await projectAccess({ userId: 'owner-1' }, 'P')).toEqual(owner())
    }
    expect(collaboratorFindUnique).not.toHaveBeenCalled()
    expect(breakGlassFindFirst).not.toHaveBeenCalled()
    expect(instanceFindUnique).not.toHaveBeenCalled()
    expect(userFindUnique).not.toHaveBeenCalled()
  })

  test('policy disabled → owner only: the switch on but Root has not enabled sharing (the stored {})', async () => {
    setFlagsForTests({ identity: true, permissions: true, sharing: true })
    db.instance = { ...db.instance, sharingPolicy: {} }
    share('P', 'viewer', { rawData: true })
    db.breakGlass.push({ projectId: 'P', userId: 'root-1', expiresAt: new Date(NOW.getTime() + HOUR) })
    for (const who of ['viewer', 'root-1', 'admin-1']) expect([who, await projectAccess({ userId: who }, 'P')]).toEqual([who, null])
    expect(await projectAccess({ userId: 'owner-1' }, 'P')).toEqual(owner())
    expect(collaboratorFindUnique).not.toHaveBeenCalled()
    expect(breakGlassFindFirst).not.toHaveBeenCalled()
  })
})

describe('projectAccess with sharing in force (step 4.3)', () => {
  beforeEach(() => setFlagsForTests({ identity: true, permissions: true, sharing: true }))

  test('owner: the same single read, and the policy is not read for the owner', async () => {
    expect(await projectAccess({ userId: 'owner-1' }, 'P')).toEqual(owner())
    expect(findUnique).toHaveBeenCalledTimes(1)
    expect(instanceFindUnique).not.toHaveBeenCalled()
    expect(collaboratorFindUnique).not.toHaveBeenCalled()
  })

  test('read share: read, no raw, via the share; the owner stays the tenant', async () => {
    share('P', 'viewer')
    const access = (await projectAccess({ userId: 'viewer' }, 'P'))!
    expect(access).toEqual(read('share', false))
    expect(Object.isFrozen(access) && Object.isFrozen(access.toggles)).toBe(true)
    expect(access.project.userId).toBe('owner-1')
    expect(collaboratorFindUnique).toHaveBeenCalledWith({
      where: { projectId_userId: { projectId: 'P', userId: 'viewer' } },
      select: { access: true, rawData: true, expiresAt: true, user: { select: { status: true } } },
    })
  })

  test('raw share: read with Raw data & files, decided by the share alone', async () => {
    share('P', 'viewer', { rawData: true })
    expect(await projectAccess({ userId: 'viewer' }, 'P')).toEqual(read('share', true))
    // Nothing more is needed to decide: no break-glass row and no account is read.
    expect(breakGlassFindFirst).not.toHaveBeenCalled()
    expect(userFindUnique).not.toHaveBeenCalled()
  })

  test('write row read as read while write is off (Phase 5 gives write its own level)', async () => {
    share('P', 'viewer', { access: 'write' })
    expect(await projectAccess({ userId: 'viewer' }, 'P')).toEqual(read('share', false))
    setFlagsForTests({ identity: true, permissions: true, sharing: true, sharingWrite: true })
    expect(await projectAccess({ userId: 'viewer' }, 'P')).toEqual(read('share', false))
  })

  test('a share of an access kind the policy does not know is inert (fail closed)', async () => {
    for (const access of ['owner', 'admin', '', 'READ']) {
      share('P', 'viewer', { access, rawData: true })
      expect([access, await projectAccess({ userId: 'viewer' }, 'P')]).toEqual([access, null])
    }
  })

  test('expired share none (injected clock): expiry acts like a revoke, judged on every read', async () => {
    share('P', 'viewer', { rawData: true, expiresAt: new Date(NOW.getTime() + 1000) })
    expect(await projectAccess({ userId: 'viewer' }, 'P')).toEqual(read('share', true))
    setNowForTests(() => new Date(NOW.getTime() + 1000))
    expect(await projectAccess({ userId: 'viewer' }, 'P')).toBeNull()
    setNowForTests(() => new Date(NOW.getTime() + 2000))
    expect(await projectAccess({ userId: 'viewer' }, 'P')).toBeNull()
  })

  test('disabled collaborator none (SH-16, DV-27): a share of an account that is not active is inert', async () => {
    for (const status of ['disabled', 'invited', '']) {
      share('P', 'viewer', { rawData: true, user: { status } })
      expect([status, await projectAccess({ userId: 'viewer' }, 'P')]).toEqual([status, null])
    }
  })

  test('deleted collaborator none: a share whose account is gone is inert', async () => {
    share('P', 'viewer', { rawData: true, user: null })
    expect(await projectAccess({ userId: 'viewer' }, 'P')).toBeNull()
  })

  test('a share of another project or another person gives nothing here', async () => {
    db.projects.set('Q', { id: 'Q', userId: 'owner-1' })
    share('Q', 'viewer', { rawData: true })
    share('P', 'someone-else', { rawData: true })
    expect(await projectAccess({ userId: 'viewer' }, 'P')).toBeNull()
    expect(await projectAccess({ userId: 'viewer' }, 'Q')).toEqual(read('share', true, 'Q'))
  })

  test('oversight read without raw: projects:oversee (Full admin) reads any project', async () => {
    expect(await projectAccess({ userId: 'admin-1' }, 'P')).toEqual(read('oversight', false))
    // A member does not hold it: nothing.
    expect(await projectAccess({ userId: 'stranger' }, 'P')).toBeNull()
  })

  test('oversight needs the permission as it stands now: an admin profile without it, a disabled admin, a gone account', async () => {
    db.users.set('admin-1', account('admin-1', { role: 'admin', adminProfileId: 'builtin:user-manager' }))
    expect(await projectAccess({ userId: 'admin-1' }, 'P')).toBeNull()
    clearPrincipalCacheForTests()
    db.users.set('admin-1', account('admin-1', { role: 'admin', status: 'disabled' }))
    expect(await projectAccess({ userId: 'admin-1' }, 'P')).toBeNull()
    expect(await projectAccess({ userId: 'nobody' }, 'P')).toBeNull()
  })

  test('the account a caller already read is used for oversight, not read again', async () => {
    const principal = { id: 'admin-1', role: 'admin', status: 'active', adminProfileId: null, legacyGrants: [], permissionSets: [], permissionOverrides: [] }
    expect(await projectAccess({ userId: 'admin-1' }, 'P', { principal })).toEqual(read('oversight', false))
    expect(userFindUnique).not.toHaveBeenCalledWith(expect.objectContaining({ where: { id: 'admin-1' } }))
    // Someone else's account is never taken for the subject's.
    expect(await projectAccess({ userId: 'stranger' }, 'P', { principal })).toBeNull()
  })

  test('break-glass read with raw: an unexpired row of someone holding projects:administer (the confirmed Root)', async () => {
    db.breakGlass.push({ projectId: 'P', userId: 'root-1', expiresAt: new Date(NOW.getTime() + HOUR) })
    expect(await projectAccess({ userId: 'root-1' }, 'P')).toEqual(read('break_glass', true))
  })

  test('break-glass ends at expiry (lazily, on the clock) and falls back to what else the person holds', async () => {
    db.breakGlass.push({ projectId: 'P', userId: 'root-1', expiresAt: new Date(NOW.getTime() + 1000) })
    expect(await projectAccess({ userId: 'root-1' }, 'P')).toEqual(read('break_glass', true))
    setNowForTests(() => new Date(NOW.getTime() + 1000))
    // The confirmed Root holds projects:oversee too: read without raw now, through oversight.
    expect(await projectAccess({ userId: 'root-1' }, 'P')).toEqual(read('oversight', false))
  })

  test('a break-glass row is inert for someone who no longer holds projects:administer (fail closed)', async () => {
    db.breakGlass.push({ projectId: 'P', userId: 'admin-1', expiresAt: new Date(NOW.getTime() + HOUR) })
    // An admin who is not Root (Root was transferred): the row gives no raw, oversight still reads.
    expect(await projectAccess({ userId: 'admin-1' }, 'P')).toEqual(read('oversight', false))
    db.breakGlass.push({ projectId: 'P', userId: 'stranger', expiresAt: new Date(NOW.getTime() + HOUR) })
    expect(await projectAccess({ userId: 'stranger' }, 'P')).toBeNull()
  })

  test('the strongest answer wins: a share without raw and a break-glass row give raw through the break-glass', async () => {
    share('P', 'root-1')
    db.breakGlass.push({ projectId: 'P', userId: 'root-1', expiresAt: new Date(NOW.getTime() + HOUR) })
    expect(await projectAccess({ userId: 'root-1' }, 'P')).toEqual(read('break_glass', true))
  })

  test('a share is preferred to oversight (no audit needed for what the owner granted)', async () => {
    share('P', 'admin-1')
    expect(await projectAccess({ userId: 'admin-1' }, 'P')).toEqual(read('share', false))
    expect(userFindUnique).not.toHaveBeenCalledWith(expect.objectContaining({ where: { id: 'admin-1' } }))
  })

  test('act-as via share is read-only (D-22): the subject is the account acted as, whose share is read', async () => {
    // can() passes the account acted as; its share is read and never more, whoever acts.
    share('P', 'viewer', { access: 'write', rawData: true })
    const access = (await projectAccess({ userId: 'viewer' }, 'P'))!
    expect(access).toEqual(read('share', true))
    expect(WRITE_LEVELS.filter((l) => meetsLevel(access, l))).toEqual([])
    // The acting admin's own oversight never enters: the member acted as holds none.
    expect(await projectAccess({ userId: 'stranger' }, 'P')).toBeNull()
  })

  test('fresh reaches the policy and the account: a critical check reads them again', async () => {
    await projectAccess({ userId: 'admin-1' }, 'P')
    const policyReads = instanceFindUnique.mock.calls.length
    const accountReads = userFindUnique.mock.calls.length
    await projectAccess({ userId: 'admin-1' }, 'P')
    expect(instanceFindUnique.mock.calls.length).toBe(policyReads)
    expect(userFindUnique.mock.calls.length).toBe(accountReads)
    await projectAccess({ userId: 'admin-1' }, 'P', { fresh: true })
    expect(instanceFindUnique.mock.calls.length).toBeGreaterThan(policyReads)
    expect(userFindUnique.mock.calls.length).toBeGreaterThan(accountReads)
  })

  test('a failed read of the share, the break-glass rows or the policy throws: it never reads as access', async () => {
    collaboratorFindUnique.mockRejectedValueOnce(Object.assign(new Error('db down'), { code: 'P1001' }))
    await expect(projectAccess({ userId: 'viewer' }, 'P')).rejects.toMatchObject({ code: 'P1001' })
    breakGlassFindFirst.mockRejectedValueOnce(Object.assign(new Error('db down'), { code: 'P1002' }))
    await expect(projectAccess({ userId: 'viewer' }, 'P')).rejects.toMatchObject({ code: 'P1002' })
    clearSharingPolicyCacheForTests()
    instanceFindUnique.mockRejectedValueOnce(Object.assign(new Error('db down'), { code: 'P1003' }))
    await expect(projectAccess({ userId: 'viewer' }, 'P')).rejects.toMatchObject({ code: 'P1003' })
  })

  test('a project that does not exist is null before anything else is read', async () => {
    share('missing', 'viewer', { rawData: true })
    expect(await projectAccess({ userId: 'viewer' }, 'missing')).toBeNull()
    expect(collaboratorFindUnique).not.toHaveBeenCalled()
  })
})

describe('meetsLevel: the level table (step 4.3)', () => {
  test('the owner holds every project level (§6.1: the owner can do everything)', () => {
    expect(levelsMet(owner() as ProjectAccess)).toEqual([...PROJECT_LEVELS])
  })

  test('read meets R only; read with Raw data meets R and R*; neither meets a write level', () => {
    for (const via of ['share', 'oversight', 'break_glass']) {
      expect([via, levelsMet(read(via, false) as ProjectAccess)]).toEqual([via, ['R']])
      expect([via, levelsMet(read(via, true) as ProjectAccess)]).toEqual([via, ['R', 'R*']])
    }
  })

  test('an access level the policy does not know meets nothing (fail closed)', () => {
    for (const level of ['viewer', 'write', 'manage', '']) {
      const unknown = { project: { id: 'P', userId: 'owner-1' }, level, toggles: { rawData: true }, via: 'share' } as unknown as ProjectAccess
      expect([level, levelsMet(unknown)]).toEqual([level, []])
    }
  })

  test('a read access without its toggles meets R only (a missing toggle is off)', () => {
    const bare = { project: { id: 'P', userId: 'owner-1' }, level: 'read' } as unknown as ProjectAccess
    expect(levelsMet(bare)).toEqual(['R'])
  })
})
