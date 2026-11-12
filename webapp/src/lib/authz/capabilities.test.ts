/**
 * What a person may do at all (step 3.4; feature document §4.2, §4.6, §14.3): the capability
 * layer, before any project access. With RBAC_PERMISSIONS_ENABLED on: confirmed Root -> every
 * permission; an unconfirmed Root -> all but the Root-only ones; an admin -> the admin profile
 * plus the member side; a member -> the sets (never assigned -> the instance default set, else
 * Default member; assigned but every set gone -> No access) plus unexpired grants minus
 * unexpired denies (a deny wins), minus the instance caps. With it off, the account type's
 * default (PE-27, DV-30; permissions.flags.off.test.ts holds the rest of that side).
 *
 * Prisma (the instance row, the custom sets, the Root's account), the clock and the
 * environment are doubles; the registry and the built-in sets are the real ones.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

type SetRow = { id: string; kind: string; name: string; permissions: string[] }
const db = vi.hoisted(() => ({
  users: new Map<string, Record<string, unknown>>(),
  instance: null as Record<string, unknown> | null,
  sets: new Map<string, { id: string; kind: string; name: string; permissions: string[] }>(),
  failSets: false,
}))
const userFindUnique = vi.fn(async ({ where }: { where: { id: string } }) => db.users.get(where.id) ?? null)
const instanceFindUnique = vi.fn(async () => (db.instance ? { ...db.instance } : null))
const setFindMany = vi.fn(async ({ where }: { where: { id: { in: string[] } } }) => {
  if (db.failSets) throw Object.assign(new Error('db down'), { code: 'P1001' })
  return where.id.in.flatMap((id) => (db.sets.has(id) ? [{ ...db.sets.get(id)! }] : []))
})
vi.mock('@/lib/prisma', () => ({
  default: {
    user: { findUnique: (a: { where: { id: string } }) => userFindUnique(a) },
    instanceSettings: { findUnique: () => instanceFindUnique() },
    permissionSet: { findMany: (a: { where: { id: { in: string[] } } }) => setFindMany(a) },
  },
}))

import {
  resolveCapabilities, invalidatePermissionSets, clearCapabilityCachesForTests, type CapabilityPrincipal,
} from './capabilities'
import { setFlagsForTests } from './flags'
import { setNowForTests } from './clock'
import { clearInstanceRootCacheForTests } from './root'
import { clearPrincipalCacheForTests, loadPrincipal } from './principal'
import { PERMISSIONS, PERMISSION_IDS, type PermissionId } from './permissions'
import { builtinSet, DEFAULT_MEMBER_SET_ID, FULL_ADMIN_PROFILE_ID, NO_ACCESS_SET_ID } from './builtinSets'
import { LEGACY_GRANTS } from './updateReview'

const T0 = Date.parse('2026-11-12T10:00:00Z')
let t = T0

const ALL = [...PERMISSION_IDS]
const ROOT_ONLY = ALL.filter((p) => PERMISSIONS[p].rootOnly)
const contents = (id: string): PermissionId[] => [...builtinSet(id)!.permissions]
const DEFAULT_MEMBER = contents(DEFAULT_MEMBER_SET_ID)
const FULL_ADMIN = contents(FULL_ADMIN_PROFILE_ID)
/** In registry order, each once: how `held` is compared. */
const union = (...groups: ReadonlyArray<readonly string[]>): PermissionId[] => {
  const wanted = new Set(groups.flat())
  return ALL.filter((p) => wanted.has(p))
}
const minus = (from: readonly PermissionId[], ...out: string[]): PermissionId[] => from.filter((p) => !out.includes(p))
const held = (caps: { held: readonly PermissionId[] }): PermissionId[] => [...caps.held]

function member(over: Partial<CapabilityPrincipal> = {}): CapabilityPrincipal {
  return {
    id: 'member-1', role: 'standard', status: 'active', adminProfileId: null, legacyGrants: [],
    permissionSets: [], permissionOverrides: [], ...over,
  }
}
function admin(over: Partial<CapabilityPrincipal> = {}): CapabilityPrincipal {
  return member({ id: 'admin-1', role: 'admin', ...over })
}
function override(permission: string, effect: string, expiresAt: Date | null = null, reason: string | null = null) {
  return { permission, effect, expiresAt, reason }
}
function seedRoot(userId: string, { confirmed = true } = {}): void {
  db.users.set(userId, { id: userId, email: `${userId}@e2e.local`, role: 'admin' })
  db.instance = { ...(db.instance ?? {}), rootUserId: userId, rootConfirmedAt: confirmed ? new Date(T0 - 86_400_000) : null, rootAssignedBy: confirmed ? 'host' : 'automatic' }
}
function seedSet(row: SetRow): void {
  db.sets.set(row.id, row)
}

beforeEach(() => {
  db.users.clear()
  db.sets.clear()
  db.instance = { rootUserId: null, rootConfirmedAt: null, rootAssignedBy: null, defaultMemberSetId: null }
  db.failSets = false
  userFindUnique.mockClear()
  instanceFindUnique.mockClear()
  setFindMany.mockClear()
  t = T0
  setNowForTests(() => new Date(t))
  setFlagsForTests({ identity: true, permissions: true })
  vi.stubEnv('RBAC_AUTHZ_CACHE_MS', '')
  vi.stubEnv('MCP_SERVER_ENABLED', 'true')
  vi.stubEnv('AGENT_IN_THE_LOOP_ENABLED', 'true')
  clearCapabilityCachesForTests()
  clearInstanceRootCacheForTests()
  clearPrincipalCacheForTests()
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
  vi.unstubAllEnvs()
})

describe('members (permissions switch on)', () => {
  test('never assigned → instance default set → Default member (PE-27, §14.3)', async () => {
    // No instance default: Default member, what a member can do today.
    let caps = await resolveCapabilities(member())
    expect(held(caps)).toEqual(DEFAULT_MEMBER)
    expect(caps.sets).toEqual([{ id: DEFAULT_MEMBER_SET_ID, name: 'Default member', kind: 'member', via: 'default' }])

    // The instance default names a built-in set: that set, read from code.
    db.instance!.defaultMemberSetId = 'builtin:read-only-analyst'
    clearCapabilityCachesForTests()
    caps = await resolveCapabilities(member())
    expect(held(caps)).toEqual(contents('builtin:read-only-analyst'))
    expect(caps.sets).toEqual([{ id: 'builtin:read-only-analyst', name: 'Read-only analyst', kind: 'member', via: 'instance_default' }])
    expect(setFindMany).not.toHaveBeenCalled()

    // The instance default names a custom set: its row.
    seedSet({ id: 'set-triage', kind: 'member', name: 'Triage desk', permissions: ['triage:read', 'triage:verdict'] })
    db.instance!.defaultMemberSetId = 'set-triage'
    clearCapabilityCachesForTests()
    caps = await resolveCapabilities(member())
    expect(held(caps)).toEqual(['triage:read', 'triage:verdict'])
    expect(caps.sets).toEqual([{ id: 'set-triage', name: 'Triage desk', kind: 'member', via: 'instance_default' }])

    // No instance row at all (its backfill has not run): Default member.
    db.instance = null
    clearCapabilityCachesForTests()
    caps = await resolveCapabilities(member())
    expect(held(caps)).toEqual(DEFAULT_MEMBER)
  })

  test('an assigned set replaces the instance default', async () => {
    db.instance!.defaultMemberSetId = 'builtin:no-access'
    const caps = await resolveCapabilities(member({ permissionSets: ['builtin:recon-operator'] }))
    expect(held(caps)).toEqual(contents('builtin:recon-operator'))
    expect(caps.sets).toEqual([{ id: 'builtin:recon-operator', name: 'Recon operator', kind: 'member', via: 'assigned' }])
    expect(instanceFindUnique).not.toHaveBeenCalled()
  })

  test('several sets are a union', async () => {
    seedSet({ id: 'set-gvm', kind: 'member', name: 'GVM', permissions: ['scan:gvm'] })
    const caps = await resolveCapabilities(member({ permissionSets: ['builtin:read-only-analyst', 'set-gvm'] }))
    expect(held(caps)).toEqual(union(contents('builtin:read-only-analyst'), ['scan:gvm']))
  })

  test('assigned but dangling → No access (PE-17: fail closed)', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    try {
      // Every assigned set is gone: No access, never the default.
      let caps = await resolveCapabilities(member({ permissionSets: ['set-deleted'] }))
      expect(held(caps)).toEqual([])
      expect(caps.sets).toEqual([{ id: NO_ACCESS_SET_ID, name: 'No access', kind: 'member', via: 'dangling' }])
      expect(caps.missingSets).toEqual(['set-deleted'])
      expect(warn.mock.calls.flat().join('\n')).toMatch(/^\[rbac\] .*set-deleted/m)

      // A set of the wrong kind is no member set: an admin profile, a custom admin row.
      seedSet({ id: 'prof-custom', kind: 'admin', name: 'Ops', permissions: ['platform:tunnels'] })
      caps = await resolveCapabilities(member({ permissionSets: ['builtin:full-admin', 'prof-custom'] }))
      expect(held(caps)).toEqual([])
      expect(caps.missingSets).toEqual(['builtin:full-admin', 'prof-custom'])

      // Only some gone: the ones that exist still count.
      caps = await resolveCapabilities(member({ permissionSets: ['set-deleted', 'builtin:read-only-analyst'] }))
      expect(held(caps)).toEqual(contents('builtin:read-only-analyst'))
      expect(caps.missingSets).toEqual(['set-deleted'])

      // An instance default that names a set that is gone: No access too.
      db.instance!.defaultMemberSetId = 'set-deleted'
      caps = await resolveCapabilities(member())
      expect(held(caps)).toEqual([])
      expect(caps.sets[0]).toMatchObject({ id: NO_ACCESS_SET_ID, via: 'dangling' })

      // Explicit grants still count on top of No access.
      caps = await resolveCapabilities(member({ permissionSets: ['set-deleted'], permissionOverrides: [override('recon:read', 'grant')] }))
      expect(held(caps)).toEqual(['recon:read'])
    } finally {
      warn.mockRestore()
    }
  })

  test('a custom set holds only the known member permissions it names', async () => {
    seedSet({ id: 'set-odd', kind: 'member', name: 'Odd', permissions: ['recon:scan', 'users:read', 'platform:kali_terminal', 'recon:everything'] })
    const caps = await resolveCapabilities(member({ permissionSets: ['set-odd'] }))
    expect(held(caps)).toEqual(['recon:scan'])
  })

  test('deny wins over a grant and a set (PE-01)', async () => {
    const caps = await resolveCapabilities(member({
      legacyGrants: ['kali_terminal'],
      permissionOverrides: [override('recon:scan', 'deny'), override('platform:kali_terminal', 'deny')],
    }))
    expect(caps.has('recon:scan')).toBe(false)
    expect(caps.has('platform:kali_terminal')).toBe(false)
    expect(held(caps)).toEqual(minus(DEFAULT_MEMBER, 'recon:scan'))
    expect(caps.explain('recon:scan')).toEqual({
      permission: 'recon:scan', held: false,
      reasons: [
        { effect: 'grant', kind: 'set', set: { id: DEFAULT_MEMBER_SET_ID, name: 'Default member', kind: 'member', via: 'default' } },
        { effect: 'deny', kind: 'override', expiresAt: null, reason: null },
      ],
    })
  })

  test('an override grant adds a permission no set holds', async () => {
    const caps = await resolveCapabilities(member({
      permissionSets: ['builtin:read-only-analyst'],
      permissionOverrides: [override('recon:scan', 'grant')],
    }))
    expect(held(caps)).toEqual(union(contents('builtin:read-only-analyst'), ['recon:scan']))
  })

  test('expired grant ignored (injected clock)', async () => {
    const until = new Date(T0 + 60_000)
    const p = member({
      permissionSets: ['builtin:read-only-analyst'],
      permissionOverrides: [override('recon:scan', 'grant', until, 'ACME engagement'), override('platform:tunnels', 'grant', until)],
    })
    expect((await resolveCapabilities(p)).has('recon:scan')).toBe(true)
    t = T0 + 59_999
    expect((await resolveCapabilities(p)).has('platform:tunnels')).toBe(true)
    t = T0 + 60_000
    const caps = await resolveCapabilities(p)
    expect(caps.has('recon:scan')).toBe(false)
    expect(caps.has('platform:tunnels')).toBe(false)
    expect(caps.explain('recon:scan').reasons).toEqual([{ effect: 'deny', kind: 'not_granted', sets: caps.sets }])
  })

  test('expired deny ignored', async () => {
    const p = member({ permissionOverrides: [override('recon:scan', 'deny', new Date(T0 + 1000))] })
    expect((await resolveCapabilities(p)).has('recon:scan')).toBe(false)
    t = T0 + 1000
    expect((await resolveCapabilities(p)).has('recon:scan')).toBe(true)
  })

  test('an override grant reaches only what a member may hold by override', async () => {
    const caps = await resolveCapabilities(member({
      permissionSets: ['builtin:no-access'],
      permissionOverrides: [
        // a platform tool: the §14.7 legacy route (step 3.15 writes these), D-20
        override('platform:shell_sessions', 'grant'),
        // administration is an admin profile's, never a member's (D-19)
        override('users:read', 'grant'),
        override('root:transfer', 'grant'),
        // not in the registry, or an effect nobody writes: nothing
        override('recon:everything', 'grant'),
        override('graph:read', 'allow'),
      ],
    }))
    expect(held(caps)).toEqual(['platform:shell_sessions'])
  })

  test('legacy grant counts as a grant before conversion (§14.7, step 3.15 converts it)', async () => {
    const caps = await resolveCapabilities(member({ legacyGrants: ['kali_terminal', 'shell_sessions', 'tunnels', 'something_else'] }))
    expect(held(caps)).toEqual(union(DEFAULT_MEMBER, ['platform:kali_terminal', 'platform:shell_sessions', 'platform:tunnels']))
    expect(caps.explain('platform:tunnels').reasons).toEqual([{ effect: 'grant', kind: 'legacy_grant', grant: 'tunnels' }])
    // Every grant the backfill writes names a registry permission.
    for (const grant of LEGACY_GRANTS) {
      const one = await resolveCapabilities(member({ permissionSets: ['builtin:no-access'], legacyGrants: [grant] }))
      expect(held(one)).toEqual([`platform:${grant}`])
    }
  })

  test('a disabled account resolves to nothing (DV-27)', async () => {
    for (const status of ['disabled', 'invited']) {
      const caps = await resolveCapabilities(member({
        status, legacyGrants: ['kali_terminal'], permissionOverrides: [override('recon:scan', 'grant')],
      }))
      expect(held(caps)).toEqual([])
      expect(caps.explain('recon:read').reasons).toEqual([{ effect: 'deny', kind: 'inactive', status }])
    }
    seedRoot('admin-1')
    expect(held(await resolveCapabilities(admin({ status: 'disabled' })))).toEqual([])
    // Nothing is read for an account that resolves to nothing.
    expect(setFindMany).not.toHaveBeenCalled()
  })
})

describe('admins and Root (permissions switch on)', () => {
  test('admin with null profile = Full admin (§4.5)', async () => {
    const caps = await resolveCapabilities(admin())
    expect(caps.accountType).toBe('admin')
    expect(held(caps)).toEqual(union(FULL_ADMIN, DEFAULT_MEMBER))
    expect(caps.sets).toEqual([
      { id: FULL_ADMIN_PROFILE_ID, name: 'Full admin', kind: 'admin', via: 'default' },
      { id: DEFAULT_MEMBER_SET_ID, name: 'Default member', kind: 'member', via: 'default' },
    ])
    for (const p of ROOT_ONLY) expect(caps.has(p)).toBe(false)
  })

  test('admin = profile ∪ member side (PE-13)', async () => {
    let caps = await resolveCapabilities(admin({ adminProfileId: 'builtin:user-manager', permissionSets: ['builtin:read-only-analyst'] }))
    expect(held(caps)).toEqual(union(contents('builtin:user-manager'), contents('builtin:read-only-analyst')))
    expect(caps.sets.map((s) => [s.id, s.via])).toEqual([['builtin:user-manager', 'assigned'], ['builtin:read-only-analyst', 'assigned']])

    // Never assigned a member set: Default member (§14.3 "admin → Full admin + Default member"),
    // whatever the instance default for new members says.
    db.instance!.defaultMemberSetId = 'builtin:no-access'
    caps = await resolveCapabilities(admin({ adminProfileId: 'builtin:security-auditor' }))
    expect(held(caps)).toEqual(union(contents('builtin:security-auditor'), DEFAULT_MEMBER))

    // A custom profile: its admin permissions; of the Root-only ones only admins:manage (OQ-02).
    seedSet({ id: 'prof-ops', kind: 'admin', name: 'Ops lead', permissions: ['platform:tunnels', 'admins:manage', 'root:transfer', 'recon:scan', 'nope:x'] })
    caps = await resolveCapabilities(admin({ adminProfileId: 'prof-ops', permissionSets: ['builtin:no-access'] }))
    expect(held(caps)).toEqual(['admins:manage', 'platform:tunnels'])
  })

  test('a profile that is gone, or a member set named as one, gives no admin power (fail closed)', async () => {
    for (const id of ['prof-deleted', 'builtin:default-member']) {
      const caps = await resolveCapabilities(admin({ adminProfileId: id, permissionSets: ['builtin:read-only-analyst'] }))
      expect(held(caps)).toEqual(contents('builtin:read-only-analyst'))
      expect(caps.missingSets).toEqual([id])
    }
  })

  test("an admin's overrides act on the member side only (D-20)", async () => {
    const caps = await resolveCapabilities(admin({
      adminProfileId: 'builtin:user-manager',
      legacyGrants: ['kali_terminal'],
      permissionOverrides: [
        override('scan:gvm', 'deny'),
        override('platform:kali_terminal', 'grant'),
        override('users:delete', 'grant'),
        override('users:read', 'deny'),
      ],
    }))
    expect(caps.has('scan:gvm')).toBe(false)
    // The profile states an admin's whole admin power: no grant beside it, legacy or override.
    expect(caps.has('platform:kali_terminal')).toBe(false)
    expect(caps.has('users:delete')).toBe(false)
    // A deny still wins.
    expect(caps.has('users:read')).toBe(false)
    expect(caps.has('users:create')).toBe(true)
  })

  test('Root all (ID-03)', async () => {
    seedRoot('admin-1')
    const caps = await resolveCapabilities(admin({
      adminProfileId: 'builtin:security-auditor', permissionSets: ['set-deleted'],
      permissionOverrides: [override('recon:scan', 'deny'), override('root:transfer', 'deny')],
    }))
    expect(caps.accountType).toBe('root')
    expect(held(caps)).toEqual(ALL)
    expect(caps.sets).toEqual([])
    expect(caps.explain('root:transfer').reasons).toEqual([{ effect: 'grant', kind: 'root' }])
    // Root never depends on stored data (§14.3): no set is read for it.
    expect(setFindMany).not.toHaveBeenCalled()
  })

  test('unconfirmed Root all but rootOnly', async () => {
    seedRoot('admin-1', { confirmed: false })
    const caps = await resolveCapabilities(admin({ adminProfileId: 'builtin:user-manager' }))
    expect(caps.accountType).toBe('root')
    expect(held(caps)).toEqual(minus(ALL, ...ROOT_ONLY))
    expect(ROOT_ONLY).toEqual(['admins:manage', 'admin_profiles:manage', 'projects:administer', 'instance:settings', 'root:transfer'])
    expect(caps.explain('admins:manage')).toEqual({
      permission: 'admins:manage', held: false, reasons: [{ effect: 'deny', kind: 'root_unconfirmed' }],
    })
    expect(caps.explain('platform:kali_terminal').reasons).toEqual([{ effect: 'grant', kind: 'root_unconfirmed' }])
  })

  test('another admin is not Root; a member costs no Root read', async () => {
    seedRoot('admin-root')
    expect((await resolveCapabilities(admin())).accountType).toBe('admin')
    instanceFindUnique.mockClear()
    userFindUnique.mockClear()
    expect((await resolveCapabilities(member())).accountType).toBe('member')
    expect(userFindUnique).not.toHaveBeenCalled()
  })
})

describe('instance caps (permissions switch on)', () => {
  test('MCP disabled removes self:mcp_tokens', async () => {
    vi.stubEnv('MCP_SERVER_ENABLED', '')
    const caps = await resolveCapabilities(member({ permissionOverrides: [override('self:mcp_tokens', 'grant')] }))
    expect(caps.has('self:mcp_tokens')).toBe(false)
    expect(held(caps)).toEqual(minus(DEFAULT_MEMBER, 'self:mcp_tokens'))
    expect(caps.explain('self:mcp_tokens').reasons.at(-1)).toEqual({ effect: 'deny', kind: 'instance_cap', setting: 'MCP_SERVER_ENABLED' })
    seedRoot('admin-1')
    expect((await resolveCapabilities(admin())).has('self:mcp_tokens')).toBe(false)
    vi.stubEnv('MCP_SERVER_ENABLED', '1')
    expect((await resolveCapabilities(member())).has('self:mcp_tokens')).toBe(true)
  })

  test('loop disabled removes agent:loop', async () => {
    vi.stubEnv('AGENT_IN_THE_LOOP_ENABLED', 'false')
    const caps = await resolveCapabilities(member({ permissionSets: ['builtin:automation'] }))
    expect(caps.has('agent:loop')).toBe(false)
    expect(caps.explain('agent:loop').reasons.at(-1)).toEqual({ effect: 'deny', kind: 'instance_cap', setting: 'AGENT_IN_THE_LOOP_ENABLED' })
    vi.stubEnv('AGENT_IN_THE_LOOP_ENABLED', 'yes')
    expect((await resolveCapabilities(member({ permissionSets: ['builtin:automation'] }))).has('agent:loop')).toBe(true)
  })
})

describe('the switches', () => {
  test('switch off → account-type default only (PE-27, PE-28)', async () => {
    setFlagsForTests({ identity: true, permissions: false })
    vi.stubEnv('MCP_SERVER_ENABLED', '')
    seedSet({ id: 'set-narrow', kind: 'member', name: 'Narrow', permissions: ['recon:read'] })
    db.instance!.defaultMemberSetId = 'builtin:no-access'
    const narrowed = {
      adminProfileId: 'builtin:user-manager', permissionSets: ['set-narrow'],
      permissionOverrides: [override('recon:scan', 'deny'), override('users:read', 'grant')],
    }
    const m = await resolveCapabilities(member(narrowed))
    expect(held(m)).toEqual(DEFAULT_MEMBER)
    expect(m.enforced).toBe(false)
    const a = await resolveCapabilities(admin(narrowed))
    expect(held(a)).toEqual(union(FULL_ADMIN, DEFAULT_MEMBER))
    // No set, no instance default and no cap is read for it.
    expect(setFindMany).not.toHaveBeenCalled()
    seedRoot('admin-1')
    clearInstanceRootCacheForTests()
    expect(held(await resolveCapabilities(admin()))).toEqual(ALL)
  })

  test('identity off → an admin manages another admin with step-up (Phase 1 rule)', async () => {
    // No Root exists, so admins:manage stays with every admin, as in Phase 1, where the user
    // routes ask the acting admin's password (rootOnlyAdmins.test.ts runs them switch off).
    setFlagsForTests({ identity: false, permissions: false })
    seedRoot('admin-1')
    const caps = await resolveCapabilities(admin())
    expect(caps.accountType).toBe('admin')
    expect(held(caps)).toEqual(union(FULL_ADMIN, DEFAULT_MEMBER, ['admins:manage']))
    expect(caps.explain('admins:manage').reasons).toEqual([{ effect: 'grant', kind: 'phase1_admin' }])
    expect(instanceFindUnique).not.toHaveBeenCalled()
    expect((await resolveCapabilities(member())).has('admins:manage')).toBe(false)
  })
})

describe('explain (PE-16, UI-12 data)', () => {
  test('explain lists the reasons', async () => {
    vi.stubEnv('MCP_SERVER_ENABLED', '')
    seedSet({ id: 'set-graph', kind: 'member', name: 'Graph desk', permissions: ['graph:read', 'graph:cypher', 'self:mcp_tokens'] })
    const until = new Date(T0 + 86_400_000)
    const caps = await resolveCapabilities(member({
      permissionSets: ['builtin:read-only-analyst', 'set-graph'],
      legacyGrants: ['tunnels'],
      permissionOverrides: [override('scan:gvm', 'grant', until, 'ACME engagement'), override('graph:cypher', 'deny', null, 'no raw queries')],
    }))
    const analyst = { id: 'builtin:read-only-analyst', name: 'Read-only analyst', kind: 'member', via: 'assigned' }
    const graph = { id: 'set-graph', name: 'Graph desk', kind: 'member', via: 'assigned' }
    expect(caps.explain('graph:read')).toEqual({
      permission: 'graph:read', held: true,
      reasons: [{ effect: 'grant', kind: 'set', set: analyst }, { effect: 'grant', kind: 'set', set: graph }],
    })
    expect(caps.explain('graph:cypher')).toEqual({
      permission: 'graph:cypher', held: false,
      reasons: [
        { effect: 'grant', kind: 'set', set: analyst },
        { effect: 'grant', kind: 'set', set: graph },
        { effect: 'deny', kind: 'override', expiresAt: null, reason: 'no raw queries' },
      ],
    })
    expect(caps.explain('scan:gvm')).toEqual({
      permission: 'scan:gvm', held: true,
      reasons: [{ effect: 'grant', kind: 'override', expiresAt: until, reason: 'ACME engagement' }],
    })
    // "you can't start recon: your set Read-only analyst has no recon:scan"
    expect(caps.explain('recon:scan')).toEqual({
      permission: 'recon:scan', held: false, reasons: [{ effect: 'deny', kind: 'not_granted', sets: [analyst, graph] }],
    })
    expect(caps.explain('self:mcp_tokens')).toEqual({
      permission: 'self:mcp_tokens', held: false,
      reasons: [{ effect: 'grant', kind: 'set', set: graph }, { effect: 'deny', kind: 'instance_cap', setting: 'MCP_SERVER_ENABLED' }],
    })
    expect(caps.explain('platform:tunnels').held).toBe(true)

    // Every permission, in registry order, each answering as has() does.
    const all = caps.explainAll()
    expect(all.map((e) => e.permission)).toEqual(ALL)
    for (const e of all) {
      expect(e.held).toBe(caps.has(e.permission))
      expect(e.reasons.length).toBeGreaterThan(0)
    }
  })

  test('has() and explain() reject a permission the registry does not hold (PE-02)', async () => {
    const caps = await resolveCapabilities(member())
    expect(() => caps.has('recon:everything' as PermissionId)).toThrow(/Unknown permission/)
    expect(() => caps.explain('toString' as PermissionId)).toThrow(/Unknown permission/)
  })

  test('the result cannot be changed by a caller', async () => {
    const caps = await resolveCapabilities(member())
    expect(Object.isFrozen(caps)).toBe(true)
    expect(Object.isFrozen(caps.sets)).toBe(true)
    expect(Object.isFrozen(caps.held)).toBe(true)
    expect(() => (caps.held as PermissionId[]).push('users:read')).toThrow()
    expect(caps.has('users:read')).toBe(false)
  })
})

describe('reads (permissions switch on)', () => {
  test('built-in sets read nothing; custom sets are one read, kept for the cache bound', async () => {
    await resolveCapabilities(member({ permissionSets: ['builtin:recon-operator'] }))
    expect(setFindMany).not.toHaveBeenCalled()

    seedSet({ id: 'set-a', kind: 'member', name: 'A', permissions: ['recon:read'] })
    seedSet({ id: 'set-b', kind: 'member', name: 'B', permissions: ['graph:read'] })
    const p = member({ permissionSets: ['set-a', 'set-b', 'set-gone'] })
    await resolveCapabilities(p)
    expect(setFindMany).toHaveBeenCalledTimes(1)
    expect(setFindMany.mock.calls[0][0]).toMatchObject({ where: { id: { in: ['set-a', 'set-b', 'set-gone'] } } })
    // Warm: no read, the missing one included.
    await resolveCapabilities(p)
    expect(setFindMany).toHaveBeenCalledTimes(1)
    // A change elsewhere is seen within the bound (5 s by default).
    db.sets.set('set-a', { id: 'set-a', kind: 'member', name: 'A', permissions: ['recon:read', 'recon:scan'] })
    t = T0 + 5000
    expect((await resolveCapabilities(p)).has('recon:scan')).toBe(true)
    expect(setFindMany).toHaveBeenCalledTimes(2)
    // A writer in this process (step 3.11) drops them at once.
    db.sets.delete('set-b')
    invalidatePermissionSets()
    expect((await resolveCapabilities(p)).has('graph:read')).toBe(false)
  })

  test('the instance default is read once for the bound, and only for a member never assigned', async () => {
    await resolveCapabilities(member({ permissionSets: ['builtin:recon-operator'] }))
    expect(instanceFindUnique).not.toHaveBeenCalled()
    await resolveCapabilities(member())
    await resolveCapabilities(member({ id: 'member-2' }))
    expect(instanceFindUnique).toHaveBeenCalledTimes(1)
    db.instance!.defaultMemberSetId = 'builtin:read-only-analyst'
    invalidatePermissionSets()
    expect(held(await resolveCapabilities(member()))).toEqual(contents('builtin:read-only-analyst'))
  })

  test('RBAC_AUTHZ_CACHE_MS=0 reads on every call', async () => {
    vi.stubEnv('RBAC_AUTHZ_CACHE_MS', '0')
    seedSet({ id: 'set-a', kind: 'member', name: 'A', permissions: ['recon:read'] })
    await resolveCapabilities(member({ permissionSets: ['set-a'] }))
    await resolveCapabilities(member({ permissionSets: ['set-a'] }))
    expect(setFindMany).toHaveBeenCalledTimes(2)
  })

  test('a failed read throws: it never resolves to a grant', async () => {
    db.failSets = true
    await expect(resolveCapabilities(member({ permissionSets: ['set-a'] }))).rejects.toThrow('db down')
  })

  test('a principal read without its permission rows is refused, not read as never assigned', async () => {
    const { permissionSets: _s, permissionOverrides: _o, ...bare } = member()
    await expect(resolveCapabilities(bare)).rejects.toThrow(/permission/)
  })

  test('end to end: the principal carries the assignments in its one read', async () => {
    db.users.set('member-9', {
      id: 'member-9', email: 'member-9@e2e.local', name: '', role: 'standard', password: 'h', createdAt: new Date(0),
      legacyGrants: [], status: 'active', sessionVersion: 0, mustChangePassword: false, adminProfileId: null, lastLoginAt: null,
      permissionSets: [{ setId: 'builtin:read-only-analyst' }],
      permissionOverrides: [{ permission: 'recon:scan', effect: 'grant', expiresAt: null, reason: 'pilot' }],
    })
    const principal = await loadPrincipal('member-9')
    expect(userFindUnique).toHaveBeenCalledTimes(1)
    const caps = await resolveCapabilities(principal!)
    expect(held(caps)).toEqual(union(contents('builtin:read-only-analyst'), ['recon:scan']))
  })
})
