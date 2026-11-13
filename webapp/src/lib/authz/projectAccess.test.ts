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
 * Step 5.2a (SH-02, SH-03, SH-07, PE-25, D-22): with write sharing in force (RBAC_SHARING_WRITE_ENABLED
 * and Root's `maxLevel: 'write'`) a live `write` share is `write`, Raw data included, with the
 * Manage toggle of its row; Run scans, Use AI agent and Exploitation & shells read false until step
 * 5.6 (`effectiveToggles`). Otherwise, and for the account an admin acts as, it reads exactly as in
 * Phase 4. `meetsLevel`: write reaches R, R* and W, each toggle its level, never O.
 *
 * Step 5.6 (C1, SH-32): the three run toggles are the row's while the owner consents to
 * collaborators spending the project's credentials (the ProjectAccessPolicy row, read fresh and only
 * for a row that holds one); without the consent they read false, as before.
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
  runScans?: boolean
  useAgent?: boolean
  exploit?: boolean
  manage?: boolean
}

const db = vi.hoisted(() => ({
  projects: new Map<string, { id: string; userId: string }>(),
  shares: new Map<string, Share>(),
  breakGlass: [] as Array<{ projectId: string; userId: string; expiresAt: Date }>,
  users: new Map<string, Record<string, unknown>>(),
  instance: null as Record<string, unknown> | null,
  /** projectId -> the owner's consent time (the ProjectAccessPolicy row). */
  consent: new Map<string, Date | null>(),
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
const policyFindUnique = vi.fn(async ({ where }: { where: { projectId: string } }) =>
  (db.consent.has(where.projectId)
    ? { ownerCredentialConsentAt: db.consent.get(where.projectId) ?? null, ownerCredentialConsentById: 'owner-1' }
    : null))
vi.mock('@/lib/prisma', () => ({
  default: {
    project: { findUnique: (a: { where: { id: string } }) => findUnique(a) },
    projectCollaborator: { findUnique: (a: Parameters<typeof collaboratorFindUnique>[0]) => collaboratorFindUnique(a) },
    projectBreakGlass: { findFirst: (a: Parameters<typeof breakGlassFindFirst>[0]) => breakGlassFindFirst(a) },
    user: { findUnique: (a: { where: { id: string } }) => userFindUnique(a) },
    instanceSettings: { findUnique: () => instanceFindUnique() },
    permissionSet: { findMany: async () => [] },
    projectAccessPolicy: { findUnique: (a: { where: { projectId: string } }) => policyFindUnique(a) },
  },
}))

import { projectAccess, meetsLevel, effectiveToggles, myAccessView, type ProjectAccess } from './projectAccess'
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
const NO_RUNS = { runScans: false, useAgent: false, exploit: false }
const write = (manage = false, over: Record<string, boolean> = {}, projectId = 'P', userId = 'owner-1') =>
  ({ project: { id: projectId, userId }, level: 'write', toggles: { rawData: true, ...NO_RUNS, manage, ...over }, via: 'share' })
const PHASE4_SHARE_SELECT = { access: true, rawData: true, expiresAt: true, user: { select: { status: true } } }
const WRITE_SHARE_SELECT = { ...PHASE4_SHARE_SELECT, runScans: true, useAgent: true, exploit: true, manage: true }
const ALL_TOGGLES = { runScans: true, useAgent: true, exploit: true, manage: true }
const shareSelect = (arg: unknown) => (arg as { select: unknown }).select

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
  db.consent.clear()
  db.instance = {
    sharingPolicy: { enabled: true }, rootUserId: 'root-1', rootConfirmedAt: new Date(0), rootAssignedBy: null,
    defaultMemberSetId: null,
  }
  for (const f of [findUnique, collaboratorFindUnique, breakGlassFindFirst, userFindUnique, instanceFindUnique]) f.mockClear()
  policyFindUnique.mockClear()
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

  test('write row read as read while write is off: the write switch off, or on with Root\'s policy at read (step 5.2a)', async () => {
    share('P', 'viewer', { access: 'write', ...ALL_TOGGLES })
    expect(await projectAccess({ userId: 'viewer' }, 'P')).toEqual(read('share', false))
    setFlagsForTests({ identity: true, permissions: true, sharing: true, sharingWrite: true })
    db.instance = { ...db.instance, sharingPolicy: { enabled: true, maxLevel: 'read' } }
    clearSharingPolicyCacheForTests()
    expect(await projectAccess({ userId: 'viewer' }, 'P')).toEqual(read('share', false))
    // Both off paths read the share exactly as Phase 4 did: no toggle column.
    expect(collaboratorFindUnique).toHaveBeenCalledTimes(2)
    for (const [arg] of collaboratorFindUnique.mock.calls) expect(shareSelect(arg)).toEqual(PHASE4_SHARE_SELECT)
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
    // `write` became a level in step 5.2a (its table is below).
    for (const level of ['viewer', 'manage', 'editor', 'WRITE', '']) {
      const unknown = { project: { id: 'P', userId: 'owner-1' }, level, toggles: { rawData: true }, via: 'share' } as unknown as ProjectAccess
      expect([level, levelsMet(unknown)]).toEqual([level, []])
    }
  })

  test('a read access without its toggles meets R only (a missing toggle is off)', () => {
    const bare = { project: { id: 'P', userId: 'owner-1' }, level: 'read' } as unknown as ProjectAccess
    expect(levelsMet(bare)).toEqual(['R'])
  })
})

describe('projectAccess with write sharing in force (step 5.2a)', () => {
  const WRITE_ON = { identity: true, permissions: true, sharing: true, sharingWrite: true }
  beforeEach(() => setFlagsForTests(WRITE_ON))

  test('write share: write with Raw data included, via the share; the owner stays the tenant', async () => {
    share('P', 'viewer', { access: 'write' })
    const access = (await projectAccess({ userId: 'viewer' }, 'P'))!
    expect(access).toEqual(write())
    expect(Object.isFrozen(access) && Object.isFrozen(access.toggles) && Object.isFrozen(access.project)).toBe(true)
    expect(access.project.userId).toBe('owner-1')
    expect(collaboratorFindUnique).toHaveBeenCalledWith({
      where: { projectId_userId: { projectId: 'P', userId: 'viewer' } },
      select: WRITE_SHARE_SELECT,
    })
  })

  test('run toggles read false without the owner\'s consent: Manage comes from the row, Run scans, Use AI agent and Exploitation & shells never', async () => {
    share('P', 'viewer', { access: 'write', ...ALL_TOGGLES })
    expect(await projectAccess({ userId: 'viewer' }, 'P')).toEqual(write(true))
    share('P', 'viewer', { access: 'write', runScans: true, useAgent: true, exploit: true, manage: false })
    expect(await projectAccess({ userId: 'viewer' }, 'P')).toEqual(write(false))
    // A withdrawn consent (the row kept, its time cleared) is no consent.
    db.consent.set('P', null)
    expect(await projectAccess({ userId: 'viewer' }, 'P')).toEqual(write(false))
  })

  test('run toggles read true from step 5.6 with the owner\'s consent: each is the row\'s', async () => {
    db.consent.set('P', new Date(NOW.getTime() - HOUR))
    share('P', 'viewer', { access: 'write', ...ALL_TOGGLES })
    expect(await projectAccess({ userId: 'viewer' }, 'P')).toEqual(write(true, { runScans: true, useAgent: true, exploit: true }))
    expect(policyFindUnique).toHaveBeenCalledWith({
      where: { projectId: 'P' }, select: { ownerCredentialConsentAt: true, ownerCredentialConsentById: true },
    })
    for (const toggle of ['runScans', 'useAgent', 'exploit'] as const) {
      share('P', 'viewer', { access: 'write', [toggle]: true })
      expect([toggle, await projectAccess({ userId: 'viewer' }, 'P')]).toEqual([toggle, write(false, { [toggle]: true })])
    }
  })

  test('the consent is read on every request, only for a row holding a run toggle, and only its own project\'s', async () => {
    db.consent.set('P', new Date(NOW.getTime() - HOUR))
    share('P', 'viewer', { access: 'write', manage: true })
    expect(await projectAccess({ userId: 'viewer' }, 'P')).toEqual(write(true))
    expect(policyFindUnique).not.toHaveBeenCalled()
    share('P', 'viewer', { access: 'write', useAgent: true })
    expect(await projectAccess({ userId: 'viewer' }, 'P')).toEqual(write(false, { useAgent: true }))
    // Withdrawn: the next request reads it (nothing cached).
    db.consent.set('P', null)
    expect(await projectAccess({ userId: 'viewer' }, 'P')).toEqual(write(false))
    // Another project's consent opens nothing here.
    db.consent.delete('P')
    db.consent.set('P-other', new Date(NOW.getTime() - HOUR))
    expect(await projectAccess({ userId: 'viewer' }, 'P')).toEqual(write(false))
    expect(policyFindUnique.mock.calls.every(([a]) => (a as { where: { projectId: string } }).where.projectId === 'P')).toBe(true)
  })

  test('a consent that cannot be read throws: it never reads as consent', async () => {
    share('P', 'viewer', { access: 'write', useAgent: true })
    policyFindUnique.mockRejectedValueOnce(new Error('db down'))
    await expect(projectAccess({ userId: 'viewer' }, 'P')).rejects.toThrow('db down')
  })

  test('the consent opens nothing past the write rule: act-as and Root\'s policy at read stay read; the owner is not asked', async () => {
    db.consent.set('P', new Date(NOW.getTime() - HOUR))
    share('P', 'viewer', { access: 'write', ...ALL_TOGGLES })
    expect(await projectAccess({ userId: 'viewer' }, 'P', { actingAs: true })).toEqual(read('share', false))
    expect(await projectAccess({ userId: 'owner-1' }, 'P')).toEqual(owner())
    db.instance = { ...db.instance, sharingPolicy: { enabled: true, maxLevel: 'read' } }
    clearSharingPolicyCacheForTests()
    expect(await projectAccess({ userId: 'viewer' }, 'P')).toEqual(read('share', false))
    expect(policyFindUnique).not.toHaveBeenCalled()
  })

  test('a write share decides alone: no break-glass row and no account is read', async () => {
    share('P', 'root-1', { access: 'write' })
    db.breakGlass.push({ projectId: 'P', userId: 'root-1', expiresAt: new Date(NOW.getTime() + HOUR) })
    expect(await projectAccess({ userId: 'root-1' }, 'P')).toEqual(write())
    expect(breakGlassFindFirst).not.toHaveBeenCalled()
    expect(userFindUnique).not.toHaveBeenCalled()
  })

  test("Root's policy at read: a write share reads as read, with the row's Raw data, Phase 4's select", async () => {
    db.instance = { ...db.instance, sharingPolicy: { enabled: true, maxLevel: 'read' } }
    share('P', 'viewer', { access: 'write', rawData: true, ...ALL_TOGGLES })
    expect(await projectAccess({ userId: 'viewer' }, 'P')).toEqual(read('share', true))
    expect(shareSelect(collaboratorFindUnique.mock.calls[0][0])).toEqual(PHASE4_SHARE_SELECT)
  })

  test('act-as via a write share is read-only (D-22, IM-07): read with the row\'s Raw data, nothing above', async () => {
    share('P', 'viewer', { access: 'write', rawData: false, ...ALL_TOGGLES })
    const acted = (await projectAccess({ userId: 'viewer' }, 'P', { actingAs: true }))!
    expect(acted).toEqual(read('share', false))
    expect(WRITE_LEVELS.filter((l) => meetsLevel(acted, l))).toEqual([])
    expect(shareSelect(collaboratorFindUnique.mock.calls[0][0])).toEqual(PHASE4_SHARE_SELECT)
    // The same account signed in itself reaches write.
    expect(await projectAccess({ userId: 'viewer' }, 'P')).toEqual(write(true))
    // The owner acted as is still the owner (act-as onto an owned project is today's behaviour).
    expect(await projectAccess({ userId: 'owner-1' }, 'P', { actingAs: true })).toEqual(owner())
  })

  test('a read share stays read; the owner is unchanged; break-glass and oversight stay read', async () => {
    share('P', 'viewer', { rawData: true, ...ALL_TOGGLES })
    expect(await projectAccess({ userId: 'viewer' }, 'P')).toEqual(read('share', true))
    expect(await projectAccess({ userId: 'owner-1' }, 'P')).toEqual(owner())
    expect(await projectAccess({ userId: 'admin-1' }, 'P')).toEqual(read('oversight', false))
    db.breakGlass.push({ projectId: 'P', userId: 'root-1', expiresAt: new Date(NOW.getTime() + HOUR) })
    expect(await projectAccess({ userId: 'root-1' }, 'P')).toEqual(read('break_glass', true))
  })

  test('an expired, disabled or deleted collaborator\'s write share is inert, as a read share is', async () => {
    share('P', 'viewer', { access: 'write', manage: true, expiresAt: new Date(NOW.getTime()) })
    expect(await projectAccess({ userId: 'viewer' }, 'P')).toBeNull()
    share('P', 'viewer', { access: 'write', manage: true, user: { status: 'disabled' } })
    expect(await projectAccess({ userId: 'viewer' }, 'P')).toBeNull()
    share('P', 'viewer', { access: 'write', manage: true, user: null })
    expect(await projectAccess({ userId: 'viewer' }, 'P')).toBeNull()
  })

  test('the write switch set while sharing is off reads off: owner only, nothing read', async () => {
    setFlagsForTests({ identity: true, permissions: true, sharingWrite: true })
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    share('P', 'viewer', { access: 'write', ...ALL_TOGGLES })
    expect(await projectAccess({ userId: 'viewer' }, 'P')).toBeNull()
    expect(collaboratorFindUnique).not.toHaveBeenCalled()
  })
})

describe('effectiveToggles: the run toggles need the owner\'s consent (step 5.6)', () => {
  test('without the consent, every combination of the row: Run scans, Use AI agent, Exploitation & shells false; Manage the row\'s', () => {
    for (let bits = 0; bits < 16; bits++) {
      const row = { runScans: (bits & 1) > 0, useAgent: (bits & 2) > 0, exploit: (bits & 4) > 0, manage: (bits & 8) > 0 }
      expect([row, effectiveToggles(row)]).toEqual([row, { ...NO_RUNS, manage: row.manage }])
      expect([row, effectiveToggles(row, false)]).toEqual([row, { ...NO_RUNS, manage: row.manage }])
    }
  })

  test('with the consent, every combination of the row: each toggle is the row\'s', () => {
    for (let bits = 0; bits < 16; bits++) {
      const row = { runScans: (bits & 1) > 0, useAgent: (bits & 2) > 0, exploit: (bits & 4) > 0, manage: (bits & 8) > 0 }
      expect([row, effectiveToggles(row, true)]).toEqual([row, row])
    }
  })

  test('a run toggle is on only for a stored true with a consent that is exactly true', () => {
    for (const v of ['true', 1, null, undefined, {}]) {
      expect(effectiveToggles({ runScans: v, useAgent: v, exploit: v } as never, true)).toEqual({ ...NO_RUNS, manage: false })
      expect(effectiveToggles({ runScans: true, useAgent: true, exploit: true }, v as never)).toEqual({ ...NO_RUNS, manage: false })
    }
  })

  test('Manage is on only for a stored true (fail closed on anything else)', () => {
    for (const manage of ['true', 1, null, undefined, {}]) {
      expect(effectiveToggles({ manage } as never).manage).toBe(false)
    }
  })
})

describe('meetsLevel: the write rows (step 5.2a)', () => {
  const W = (toggles: Record<string, boolean>) =>
    ({ project: { id: 'P', userId: 'owner-1' }, level: 'write', toggles: { rawData: true, ...NO_RUNS, manage: false, ...toggles }, via: 'share' }) as ProjectAccess

  test('an editor (no toggle) meets R, R* and W: write includes Raw data & files', () => {
    expect(levelsMet(W({}))).toEqual(['R', 'R*', 'W'])
  })

  test('each toggle opens its own level and no other; the owner level never', () => {
    expect(levelsMet(W({ runScans: true }))).toEqual(['R', 'R*', 'W', 'W+S'])
    expect(levelsMet(W({ useAgent: true }))).toEqual(['R', 'R*', 'W', 'W+A'])
    expect(levelsMet(W({ exploit: true }))).toEqual(['R', 'R*', 'W', 'W+X'])
    expect(levelsMet(W({ manage: true }))).toEqual(['R', 'R*', 'W', 'M'])
    expect(levelsMet(W({ runScans: true, useAgent: true, exploit: true, manage: true }))).toEqual(['R', 'R*', 'W', 'W+S', 'W+A', 'W+X', 'M'])
  })

  test('a co-owner without Exploitation & shells does not reach W+X (Manage implies no run toggle)', () => {
    expect(meetsLevel(W({ manage: true }), 'W+X')).toBe(false)
    expect(meetsLevel(W({ manage: true }), 'W+S')).toBe(false)
    expect(meetsLevel(W({ manage: true }), 'W+A')).toBe(false)
  })

  test('a write access without its toggles meets R, R* and W only (a missing toggle is off)', () => {
    const bare = { project: { id: 'P', userId: 'owner-1' }, level: 'write' } as unknown as ProjectAccess
    expect(levelsMet(bare)).toEqual(['R', 'R*', 'W'])
    const truthy = { ...bare, toggles: { rawData: true, manage: 'yes', exploit: 1 } } as unknown as ProjectAccess
    expect(levelsMet(truthy)).toEqual(['R', 'R*', 'W'])
  })

  test('a level the table does not know is never met by a write access', () => {
    expect(meetsLevel(W({ runScans: true, useAgent: true, exploit: true, manage: true }), 'X' as ProjectLevel)).toBe(false)
  })
})

describe('myAccessView: what a person is told of a write share (step 5.2a)', () => {
  const who = { name: 'Owner', email: 'owner@example.test' }

  test('a write access carries its four toggles as meetsLevel answers them', () => {
    expect(myAccessView(write(true) as ProjectAccess, who)).toEqual({
      level: 'write', toggles: { rawData: true, runScans: false, useAgent: false, exploit: false, manage: true }, via: 'share', owner: who,
    })
  })

  test('an owner or read answer keeps the Phase 4 shape, Raw data alone (DV-30)', () => {
    expect(myAccessView(owner() as ProjectAccess, who)).toEqual({ level: 'owner', toggles: { rawData: true }, via: 'owner', owner: who })
    expect(myAccessView(read('share', false) as ProjectAccess, null)).toEqual({
      level: 'read', toggles: { rawData: false }, via: 'share', owner: { name: null, email: null },
    })
  })
})
