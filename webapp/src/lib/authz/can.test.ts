/**
 * The one policy function (step 3.5; feature document §4.2, §6.8.4; PE-06, PE-23, DV-07):
 * `can(principal, permission, {projectId})` = the capability (capabilities.ts) and, for a project,
 * the caller's access to it (projectAccess.ts, owner-only in Phase 3). A project the caller cannot
 * see answers 404 whatever they hold (anti-enumeration); a visible project, or an instance action,
 * the caller lacks the permission for answers 403 naming it. Instance permissions never read a
 * project.
 *
 * Under act-as the project is the acted-as account's (as `getEffectiveUser` answers today), a
 * member permission needs both people to hold it (§4.7: the admin can use only what both may do),
 * and an administration or platform permission stays the real person's. An `actingAs` the act-as
 * rule refuses (session.ts `mayActAs`: only an admin, never as Root) throws: a caller bug.
 *
 * With RBAC_PERMISSIONS_ENABLED on unless a test says otherwise (permissions.flags.off.test.ts
 * holds the switch-off side). Prisma (projects, the instance row, the Root's account, custom
 * sets) is a double; the registry, the built-in sets and the resolution are the real ones.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

const db = vi.hoisted(() => ({
  users: new Map<string, Record<string, unknown>>(),
  projects: new Map<string, { id: string; userId: string }>(),
  instance: null as Record<string, unknown> | null,
  sets: new Map<string, { id: string; kind: string; name: string; permissions: string[] }>(),
  failProjects: false,
}))
const userFindUnique = vi.fn(async ({ where }: { where: { id: string } }) => db.users.get(where.id) ?? null)
const instanceFindUnique = vi.fn(async () => (db.instance ? { ...db.instance } : null))
const setFindMany = vi.fn(async ({ where }: { where: { id: { in: string[] } } }) =>
  where.id.in.flatMap((id) => (db.sets.has(id) ? [{ ...db.sets.get(id)! }] : [])))
const projectFindUnique = vi.fn(async ({ where }: { where: { id: string } }) => {
  if (db.failProjects) throw Object.assign(new Error('db down'), { code: 'P1001' })
  const row = db.projects.get(where.id)
  return row ? { ...row } : null
})
vi.mock('@/lib/prisma', () => ({
  default: {
    user: { findUnique: (a: { where: { id: string } }) => userFindUnique(a) },
    instanceSettings: { findUnique: () => instanceFindUnique() },
    permissionSet: { findMany: (a: { where: { id: { in: string[] } } }) => setFindMany(a) },
    project: { findUnique: (a: { where: { id: string } }) => projectFindUnique(a) },
  },
}))

import { can, ActAsNotAllowedError } from './can'
import { setFlagsForTests } from './flags'
import { clearCapabilityCachesForTests, type CapabilityPrincipal } from './capabilities'
import { clearInstanceRootCacheForTests } from './root'
import { clearPrincipalCacheForTests } from './principal'
import { PERMISSIONS, PERMISSION_IDS, type PermissionId } from './permissions'

function member(id: string, over: Partial<CapabilityPrincipal> = {}): CapabilityPrincipal {
  return { id, role: 'standard', status: 'active', adminProfileId: null, legacyGrants: [], permissionSets: [], permissionOverrides: [], ...over }
}
function admin(id: string, over: Partial<CapabilityPrincipal> = {}): CapabilityPrincipal {
  return member(id, { role: 'admin', ...over })
}
const ANALYST = { permissionSets: ['builtin:read-only-analyst'] }

beforeEach(() => {
  db.users.clear()
  db.projects.clear()
  db.projects.set('P-alice', { id: 'P-alice', userId: 'alice' })
  db.projects.set('P-bob', { id: 'P-bob', userId: 'bob' })
  db.projects.set('P-admin', { id: 'P-admin', userId: 'admin-1' })
  db.projects.set('P-admin-2', { id: 'P-admin-2', userId: 'admin-2' })
  db.instance = { rootUserId: null, rootConfirmedAt: null, rootAssignedBy: null, defaultMemberSetId: null }
  db.sets.clear()
  db.failProjects = false
  for (const fn of [userFindUnique, instanceFindUnique, setFindMany, projectFindUnique]) fn.mockClear()
  setFlagsForTests({ identity: true, permissions: true })
  vi.stubEnv('MCP_SERVER_ENABLED', 'true')
  vi.stubEnv('AGENT_IN_THE_LOOP_ENABLED', 'true')
  clearCapabilityCachesForTests()
  clearInstanceRootCacheForTests()
  clearPrincipalCacheForTests()
})
afterEach(() => {
  setFlagsForTests(null)
  vi.unstubAllEnvs()
})

describe('can(): capability and project access (PE-06)', () => {
  test('owner allowed: the project access comes back with the decision', async () => {
    const d = await can(member('alice'), 'recon:scan', { projectId: 'P-alice' })
    expect(d.allowed).toBe(true)
    if (!d.allowed) return
    expect(d.permission).toBe('recon:scan')
    expect(d.access).toEqual({ project: { id: 'P-alice', userId: 'alice' }, level: 'owner' })
    expect(d.capabilities.userId).toBe('alice')
    expect(d.capabilities.has('recon:scan')).toBe(true)
  })

  test('non-owner 404: another person\'s project and a project that does not exist answer the same (PE-23)', async () => {
    const other = await can(member('alice'), 'recon:read', { projectId: 'P-bob' })
    const missing = await can(member('alice'), 'recon:read', { projectId: 'P-none' })
    expect(other).toEqual({ allowed: false, status: 404, reason: 'project_not_visible', permission: 'recon:read' })
    expect(missing).toEqual(other)
  })

  test('missing capability on a visible project 403 with the permission (PE-23)', async () => {
    const analyst = member('alice', ANALYST)
    const d = await can(analyst, 'recon:scan', { projectId: 'P-alice' })
    expect(d).toMatchObject({ allowed: false, status: 403, reason: 'capability', permission: 'recon:scan' })
    // What the set holds is still allowed on the same project.
    expect((await can(analyst, 'recon:read', { projectId: 'P-alice' })).allowed).toBe(true)
  })

  test('a project the caller cannot see answers 404 even when they lack the permission too', async () => {
    const d = await can(member('alice', ANALYST), 'recon:scan', { projectId: 'P-bob' })
    expect(d).toEqual({ allowed: false, status: 404, reason: 'project_not_visible', permission: 'recon:scan' })
  })

  test('a deny override on the person refuses on their own project: 403 naming it (PE-01 through can)', async () => {
    const denied = member('alice', { permissionOverrides: [{ permission: 'agent:chat', effect: 'deny', expiresAt: null, reason: null }] })
    expect(await can(denied, 'agent:chat', { projectId: 'P-alice' })).toMatchObject({ status: 403, permission: 'agent:chat' })
    expect((await can(denied, 'graph:read', { projectId: 'P-alice' })).allowed).toBe(true)
  })

  test('instance permission ignores projects: no project is read, whatever project is named', async () => {
    const adminDecision = await can(admin('admin-1'), 'users:read', { projectId: 'P-bob' })
    expect(adminDecision).toMatchObject({ allowed: true, permission: 'users:read', access: null })
    expect(await can(member('alice'), 'users:read', { projectId: 'P-alice' }))
      .toMatchObject({ allowed: false, status: 403, reason: 'capability', permission: 'users:read' })
    expect(await can(member('alice'), 'project:create')).toMatchObject({ allowed: true, access: null })
    expect(projectFindUnique).not.toHaveBeenCalled()
  })

  test('an instance permission that acts on a project (project:share, plugins:approve_overrides) checks that project', async () => {
    const acting = PERMISSION_IDS.filter((p) => PERMISSIONS[p].scope === 'instance' && PERMISSIONS[p].level !== null)
    expect(acting).toEqual(['project:share', 'plugins:approve_overrides'])
    for (const p of acting) {
      expect([p, (await can(member('alice'), p, { projectId: 'P-alice' })).allowed]).toEqual([p, true])
      expect([p, await can(member('alice'), p, { projectId: 'P-bob' })])
        .toEqual([p, { allowed: false, status: 404, reason: 'project_not_visible', permission: p }])
    }
  })

  test('a project permission without a project is the capability alone (the "may this person use X at all" layer)', async () => {
    expect(await can(member('alice'), 'recon:scan')).toMatchObject({ allowed: true, access: null })
    expect(await can(member('alice', ANALYST), 'recon:scan')).toMatchObject({ allowed: false, status: 403, permission: 'recon:scan' })
    expect(projectFindUnique).not.toHaveBeenCalled()
  })

  test('a project named but empty is a 400, never the capability alone: nothing is read', async () => {
    for (const projectId of ['', null, undefined]) {
      expect(await can(member('alice'), 'recon:read', { projectId }))
        .toEqual({ allowed: false, status: 400, reason: 'project_required', permission: 'recon:read' })
    }
    expect(projectFindUnique).not.toHaveBeenCalled()
  })

  test('an unknown permission throws (PE-02): a typo never reads as allowed or as a plain refusal', async () => {
    await expect(can(member('alice'), 'recon:scans' as PermissionId, { projectId: 'P-alice' })).rejects.toThrow(/Unknown permission/)
    await expect(can(member('alice'), 'users:invite' as PermissionId)).rejects.toThrow(/Unknown permission/)
  })

  test('a failed project read throws: it never reads as allowed', async () => {
    db.failProjects = true
    await expect(can(member('alice'), 'recon:read', { projectId: 'P-alice' })).rejects.toMatchObject({ code: 'P1001' })
  })

  test('a disabled account holds nothing with the switch on: 403 on its own project', async () => {
    const d = await can(member('alice', { status: 'disabled' }), 'recon:read', { projectId: 'P-alice' })
    expect(d).toMatchObject({ allowed: false, status: 403, permission: 'recon:read' })
  })

  test('the decision is frozen', async () => {
    const d = await can(member('alice'), 'recon:read', { projectId: 'P-alice' })
    expect(Object.isFrozen(d)).toBe(true)
  })
})

describe('can() under act-as (§4.7: the target\'s project, both people\'s member permissions)', () => {
  test('the project is the acted-as account\'s: the admin\'s own project is not visible', async () => {
    const opts = { actingAs: member('alice') }
    expect((await can(admin('admin-1'), 'recon:read', { ...opts, projectId: 'P-alice' })).allowed).toBe(true)
    expect(await can(admin('admin-1'), 'recon:read', { ...opts, projectId: 'P-admin' }))
      .toEqual({ allowed: false, status: 404, reason: 'project_not_visible', permission: 'recon:read' })
  })

  test('a member permission needs both: what the target lacks is refused, what the admin lacks is refused', async () => {
    expect(await can(admin('admin-1'), 'recon:scan', { actingAs: member('alice', ANALYST), projectId: 'P-alice' }))
      .toMatchObject({ allowed: false, status: 403, reason: 'capability', permission: 'recon:scan' })
    expect(await can(admin('admin-1', ANALYST), 'recon:scan', { actingAs: member('alice'), projectId: 'P-alice' }))
      .toMatchObject({ allowed: false, status: 403, reason: 'capability', permission: 'recon:scan' })
    expect((await can(admin('admin-1'), 'recon:scan', { actingAs: member('alice'), projectId: 'P-alice' })).allowed).toBe(true)
  })

  test('an administration or platform permission stays the real person\'s', async () => {
    const opts = { actingAs: member('alice', { permissionSets: ['builtin:no-access'] }) }
    expect(await can(admin('admin-1'), 'users:read', opts)).toMatchObject({ allowed: true })
    expect(await can(admin('admin-1'), 'platform:emergency_stop', opts)).toMatchObject({ allowed: true })
    // A member handed an actingAs is a caller bug, not a refusal (the act-as rule below).
    await expect(can(member('bob'), 'users:read', { actingAs: member('alice') })).rejects.toThrow(ActAsNotAllowedError)
  })

  test('acting as oneself is no act-as', async () => {
    const self = admin('admin-1')
    expect((await can(self, 'recon:read', { actingAs: self, projectId: 'P-admin' })).allowed).toBe(true)
  })
})

describe('can() holds an actingAs to the act-as rule (session.ts mayActAs: only an admin, never as Root)', () => {
  test('a member handed an actingAs throws a coded error, for a member and an administration permission alike, before anything is read', async () => {
    for (const permission of ['recon:read', 'recon:scan', 'users:read'] as const) {
      await expect(can(member('bob'), permission, { actingAs: member('alice'), projectId: 'P-alice' }))
        .rejects.toMatchObject({ name: 'ActAsNotAllowedError', message: expect.stringMatching(/^\[rbac\] act_as_refused: /) })
    }
    await expect(can(member('bob'), 'recon:read', { actingAs: member('alice') })).rejects.toThrow(ActAsNotAllowedError)
    expect(projectFindUnique).not.toHaveBeenCalled()
    expect(setFindMany).not.toHaveBeenCalled()
  })

  test('nobody acts as Root; an admin still acts as another admin (Phase 2 rule)', async () => {
    db.instance = { rootUserId: 'root-1', rootConfirmedAt: new Date(0), rootAssignedBy: null, defaultMemberSetId: null }
    db.users.set('root-1', { email: 'root-1@e2e.local', role: 'admin' })
    await expect(can(admin('admin-1'), 'recon:read', { actingAs: admin('root-1'), projectId: 'P-admin' })).rejects.toThrow(ActAsNotAllowedError)
    await expect(can(admin('admin-1'), 'users:read', { actingAs: admin('root-1') })).rejects.toThrow(ActAsNotAllowedError)
    expect((await can(admin('admin-1'), 'recon:read', { actingAs: admin('admin-2'), projectId: 'P-admin-2' })).allowed).toBe(true)
  })
})

describe('can() under act-as returns what the person may use while acting (§4.7), not their own set', () => {
  test('member permissions both people hold, administration ones the real person\'s; the 403 carries the same set', async () => {
    const opts = { actingAs: member('alice', ANALYST), projectId: 'P-alice' }
    const d = await can(admin('admin-1'), 'recon:read', opts)
    expect(d.allowed).toBe(true)
    if (!d.allowed) return
    const c = d.capabilities
    expect(c.userId).toBe('admin-1')
    expect([c.has('recon:read'), c.has('recon:scan'), c.has('agent:approve_dangerous'), c.has('users:read')]).toEqual([true, false, false, true])
    expect(c.held).toContain('users:read')
    expect(c.held).not.toContain('agent:approve_dangerous')
    expect(c.held.every((p) => c.has(p))).toBe(true)
    expect(c.explainAll().filter((e) => e.held).map((e) => e.permission)).toEqual(c.held)
    // The reasons of a member permission the account acted as lacks are that account's.
    expect(c.explain('recon:scan')).toMatchObject({ permission: 'recon:scan', held: false, reasons: [{ effect: 'deny', kind: 'not_granted', sets: [{ id: 'builtin:read-only-analyst' }] }] })
    expect(c.explain('users:read').held).toBe(true)
    expect(() => c.has('recon:everything' as PermissionId)).toThrow(/Unknown permission/)
    expect(Object.isFrozen(c)).toBe(true)

    const refused = await can(admin('admin-1'), 'recon:scan', opts)
    expect(refused).toMatchObject({ allowed: false, status: 403, reason: 'capability' })
    if (refused.allowed || refused.status !== 403) return
    expect(refused.capabilities.has('recon:scan')).toBe(false)
  })

  test('without act-as the decision carries the person\'s own set', async () => {
    const d = await can(admin('admin-1'), 'recon:scan', { projectId: 'P-admin' })
    expect(d.allowed && d.capabilities.has('agent:approve_dangerous')).toBe(true)
  })
})

describe('can() with fresh (a critical check)', () => {
  const OPS = { id: 'set-ops', kind: 'member', name: 'Ops', permissions: ['recon:read', 'recon:scan'] }

  test('the custom sets are read again; without fresh the cached contents stand for the cache bound', async () => {
    db.sets.set('set-ops', OPS)
    const alice = member('alice', { permissionSets: ['set-ops'] })
    expect((await can(alice, 'recon:scan', { projectId: 'P-alice' })).allowed).toBe(true)
    db.sets.set('set-ops', { ...OPS, permissions: ['recon:read'] })
    expect((await can(alice, 'recon:scan', { projectId: 'P-alice' })).allowed).toBe(true)
    expect(await can(alice, 'recon:scan', { projectId: 'P-alice', fresh: true })).toMatchObject({ allowed: false, status: 403 })
  })

  test('the account acted as: its sets are read again too', async () => {
    db.sets.set('set-ops', OPS)
    const opts = { actingAs: member('alice', { permissionSets: ['set-ops'] }), projectId: 'P-alice' }
    expect((await can(admin('admin-1'), 'recon:scan', opts)).allowed).toBe(true)
    db.sets.set('set-ops', { ...OPS, permissions: ['recon:read'] })
    expect((await can(admin('admin-1'), 'recon:scan', opts)).allowed).toBe(true)
    expect(await can(admin('admin-1'), 'recon:scan', { ...opts, fresh: true })).toMatchObject({ allowed: false, status: 403 })
  })

  test('the act-as rule reads the Root again: an account that became Root is acted as by nobody', async () => {
    const opts = { actingAs: admin('admin-2'), projectId: 'P-admin-2' }
    expect((await can(admin('admin-1'), 'recon:read', opts)).allowed).toBe(true)
    db.instance = { rootUserId: 'admin-2', rootConfirmedAt: new Date(0), rootAssignedBy: null, defaultMemberSetId: null }
    db.users.set('admin-2', { email: 'admin-2@e2e.local', role: 'admin' })
    expect((await can(admin('admin-1'), 'recon:read', opts)).allowed).toBe(true)
    await expect(can(admin('admin-1'), 'recon:read', { ...opts, fresh: true })).rejects.toThrow(ActAsNotAllowedError)
  })

  test('the people are the caller\'s read: can() reads no account, fresh or not (DV-25: a request reads its account once)', async () => {
    const alice = member('alice', { permissionSets: ['builtin:read-only-analyst'] })
    // The rows the caller read decide, whatever the account table says now.
    db.users.set('alice', { id: 'alice', role: 'standard', status: 'active', permissionSets: [], permissionOverrides: [] })
    expect(await can(alice, 'recon:scan', { projectId: 'P-alice', fresh: true })).toMatchObject({ allowed: false, status: 403 })
    await can(admin('admin-1'), 'recon:read', { actingAs: alice, projectId: 'P-alice', fresh: true })
    expect(userFindUnique).not.toHaveBeenCalled()
  })
})
