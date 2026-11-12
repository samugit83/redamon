/**
 * The permissions switch (RBAC_PERMISSIONS_ENABLED, Phase 3) off: everything behaves as after
 * Phase 2 (master plan §9.4, DV-30; PE-27, PE-28). Each Phase 3 step adds its part here.
 *
 * Step 3.4 resolves what a person may do. With the switch off:
 *   - the principal reads no assignment and no override: its query is Phase 2's;
 *   - every account resolves to its account type's default, whatever rows exist (members:
 *     Default member and their legacy grants; admins: Full admin + Default member; the confirmed
 *     Root everything, an unconfirmed one all but the Root-only permissions; with the identity
 *     switch off as well there is no Root, and every admin keeps admins:manage, Phase 1's rule);
 *   - nothing reads a set, the instance default set or an instance cap, and the account's status
 *     decides nothing here (Phase 2's session checks keep deciding it);
 *   - the five shared tools resolve as `sharedToolAccess` answers them without the escape hatch;
 *   - no production file other than the named readers names a permission table.
 *
 * Step 3.5 decides with `can()`. With the switch off it answers what the guards answer today: on
 * a project, its owner (the account acted as, under act-as) may do every member action and anyone
 * else gets 404; an instance action is an admin's (Root's own ones the confirmed Root's), and a
 * member's only through a legacy grant, whatever rows exist.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import path from 'node:path'

const db = vi.hoisted(() => ({
  users: new Map<string, Record<string, unknown>>(),
  instance: null as Record<string, unknown> | null,
}))
const userFindUnique = vi.fn(async ({ where }: { where: { id: string } }) => db.users.get(where.id) ?? null)
const instanceFindUnique = vi.fn(async () => (db.instance ? { ...db.instance } : null))
const setFindMany = vi.fn(async () => [])
const PROJECTS: Record<string, { id: string; userId: string }> = {
  'P-member': { id: 'P-member', userId: 'member-1' },
  'P-admin': { id: 'P-admin', userId: 'admin-1' },
}
const projectFindUnique = vi.fn(async ({ where }: { where: { id: string } }) => PROJECTS[where.id] ?? null)
vi.mock('@/lib/prisma', () => ({
  default: {
    user: { findUnique: (a: { where: { id: string } }) => userFindUnique(a) },
    instanceSettings: { findUnique: () => instanceFindUnique() },
    permissionSet: { findMany: () => setFindMany() },
    project: { findUnique: (a: { where: { id: string } }) => projectFindUnique(a) },
  },
}))

import { rbacFlags, setFlagsForTests } from './flags'
import { resolveCapabilities, clearCapabilityCachesForTests, type CapabilityPrincipal } from './capabilities'
import { loadPrincipal, clearPrincipalCacheForTests } from './principal'
import { clearInstanceRootCacheForTests } from './root'
import { PERMISSIONS, PERMISSION_IDS, type PermissionId } from './permissions'
import { builtinSet, DEFAULT_MEMBER_SET_ID, FULL_ADMIN_PROFILE_ID } from './builtinSets'
import { sharedToolAccess, resetSharedToolsForTests, SHARED_TOOLS, type SharedTool } from './sharedTools'
import { can } from './can'

const WEBAPP = path.resolve(__dirname, '../../..')
const ALL = [...PERMISSION_IDS]
const ROOT_ONLY = ALL.filter((p) => PERMISSIONS[p].rootOnly)
const DEFAULT_MEMBER = [...builtinSet(DEFAULT_MEMBER_SET_ID)!.permissions]
const FULL_ADMIN = [...builtinSet(FULL_ADMIN_PROFILE_ID)!.permissions]
const union = (...groups: ReadonlyArray<readonly string[]>): PermissionId[] => {
  const wanted = new Set(groups.flat())
  return ALL.filter((p) => wanted.has(p))
}

/** Rows a later step may write while the switch is on, and that must change nothing while it is off. */
const NARROWED = {
  adminProfileId: 'builtin:security-auditor',
  permissionSets: ['builtin:no-access'],
  permissionOverrides: [
    { permission: 'recon:scan', effect: 'deny', expiresAt: null, reason: null },
    { permission: 'users:read', effect: 'grant', expiresAt: null, reason: null },
  ],
}

function account(id: string, role: string, over: Partial<CapabilityPrincipal> = {}): CapabilityPrincipal {
  return { id, role, status: 'active', adminProfileId: null, legacyGrants: [], ...over }
}

beforeEach(() => {
  db.users.clear()
  db.instance = { rootUserId: null, rootConfirmedAt: null, rootAssignedBy: null, defaultMemberSetId: 'builtin:no-access' }
  userFindUnique.mockClear()
  instanceFindUnique.mockClear()
  setFindMany.mockClear()
  setFlagsForTests({ identity: true, permissions: false })
  vi.stubEnv('MCP_SERVER_ENABLED', '')
  vi.stubEnv('AGENT_IN_THE_LOOP_ENABLED', '')
  clearCapabilityCachesForTests()
  clearInstanceRootCacheForTests()
  clearPrincipalCacheForTests()
  resetSharedToolsForTests()
})
afterEach(() => {
  setFlagsForTests(null)
  vi.unstubAllEnvs()
})

describe('RBAC_PERMISSIONS_ENABLED off (step 3.4)', () => {
  test('the switch is off unless set, and off while the identity switch is off', () => {
    setFlagsForTests(null)
    vi.stubEnv('RBAC_IDENTITY_ENABLED', 'true')
    vi.stubEnv('RBAC_PERMISSIONS_ENABLED', '')
    expect(rbacFlags().permissions).toBe(false)
    vi.stubEnv('RBAC_IDENTITY_ENABLED', '')
    vi.stubEnv('RBAC_PERMISSIONS_ENABLED', 'true')
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    try {
      expect(rbacFlags().permissions).toBe(false)
    } finally {
      warn.mockRestore()
    }
  })

  test.each([true, false])('the principal reads no assignment and no override (identity %s)', async (identity) => {
    setFlagsForTests({ identity, permissions: false })
    db.users.set('member-1', {
      id: 'member-1', email: 'member-1@e2e.local', role: 'standard', password: 'h', createdAt: new Date(0), legacyGrants: [],
      permissionSets: [{ setId: 'builtin:no-access' }], permissionOverrides: [],
    })
    const p = await loadPrincipal('member-1')
    const select = (userFindUnique.mock.calls[0][0] as unknown as { select: Record<string, unknown> }).select
    expect(Object.keys(select).sort()).toEqual([
      'adminProfileId', 'createdAt', 'email', 'id', 'lastLoginAt', 'legacyGrants', 'mustChangePassword', 'name',
      'password', 'role', 'sessionVersion', 'status',
    ])
    expect(p).not.toHaveProperty('permissionSets')
    expect(p).not.toHaveProperty('permissionOverrides')
  })

  test('a member resolves to Default member and their legacy grants, whatever rows exist', async () => {
    const caps = await resolveCapabilities(account('member-1', 'standard', { ...NARROWED, legacyGrants: ['kali_terminal'] }))
    expect(caps.enforced).toBe(false)
    expect(caps.accountType).toBe('member')
    expect([...caps.held]).toEqual(union(DEFAULT_MEMBER, ['platform:kali_terminal']))
    expect(caps.sets).toEqual([{ id: DEFAULT_MEMBER_SET_ID, name: 'Default member', kind: 'member', via: 'default' }])
    // Neither the sets nor the instance default set is read; no instance read at all for a member.
    expect(setFindMany).not.toHaveBeenCalled()
    expect(instanceFindUnique).not.toHaveBeenCalled()
  })

  test('an admin resolves to Full admin + Default member, whatever profile it names', async () => {
    const caps = await resolveCapabilities(account('admin-1', 'admin', NARROWED))
    expect(caps.accountType).toBe('admin')
    expect([...caps.held]).toEqual(union(FULL_ADMIN, DEFAULT_MEMBER))
    for (const p of ROOT_ONLY) expect(caps.has(p)).toBe(false)
    expect(setFindMany).not.toHaveBeenCalled()
  })

  test('Root keeps Phase 2: confirmed everything, unconfirmed all but the Root-only permissions', async () => {
    db.users.set('admin-1', { id: 'admin-1', email: 'admin-1@e2e.local', role: 'admin' })
    db.instance = { ...db.instance, rootUserId: 'admin-1', rootConfirmedAt: new Date(0), rootAssignedBy: 'host' }
    expect([...(await resolveCapabilities(account('admin-1', 'admin', NARROWED))).held]).toEqual(ALL)
    db.instance = { ...db.instance, rootConfirmedAt: null, rootAssignedBy: 'automatic' }
    clearInstanceRootCacheForTests()
    expect([...(await resolveCapabilities(account('admin-1', 'admin'))).held]).toEqual(ALL.filter((p) => !ROOT_ONLY.includes(p)))
  })

  test('identity off too: no Root, and every admin keeps admins:manage (Phase 1)', async () => {
    setFlagsForTests({ identity: false, permissions: false })
    db.users.set('admin-1', { id: 'admin-1', email: 'admin-1@e2e.local', role: 'admin' })
    db.instance = { ...db.instance, rootUserId: 'admin-1', rootConfirmedAt: new Date(0) }
    const caps = await resolveCapabilities(account('admin-1', 'admin'))
    expect(caps.accountType).toBe('admin')
    expect([...caps.held]).toEqual(union(FULL_ADMIN, DEFAULT_MEMBER, ['admins:manage']))
    expect(instanceFindUnique).not.toHaveBeenCalled()
  })

  test('no instance cap: the MCP server and Agent in the Loop switched off change nothing here', async () => {
    const caps = await resolveCapabilities(account('member-1', 'standard'))
    expect(caps.has('self:mcp_tokens')).toBe(true)
    expect(caps.has('agent:loop')).toBe(true)
  })

  test("the account's status decides nothing here: Phase 2's session checks keep deciding it", async () => {
    const caps = await resolveCapabilities(account('member-1', 'standard', { status: 'disabled' }))
    expect([...caps.held]).toEqual(DEFAULT_MEMBER)
  })

  test('the five shared tools resolve as sharedToolAccess answers them without the escape hatch', async () => {
    const TOOL_PERMISSION: Record<SharedTool, PermissionId> = {
      kali_terminal: 'platform:kali_terminal',
      shell_sessions_all: 'platform:shell_sessions',
      tunnels: 'platform:tunnels',
      emergency_stop_all: 'platform:emergency_stop',
      nuclei_templates_all: 'platform:nuclei_templates',
    }
    expect(Object.keys(TOOL_PERMISSION).sort()).toEqual([...SHARED_TOOLS].sort())
    const people = [
      account('admin-1', 'admin'),
      account('member-1', 'standard'),
      account('member-2', 'standard', { legacyGrants: ['kali_terminal'] }),
      account('member-3', 'standard', { legacyGrants: ['shell_sessions'] }),
      account('member-4', 'standard', { legacyGrants: ['tunnels', 'kali_terminal', 'shell_sessions'] }),
    ]
    for (const identity of [true, false]) {
      setFlagsForTests({ identity, permissions: false })
      for (const person of people) {
        const caps = await resolveCapabilities(person)
        for (const tool of SHARED_TOOLS) {
          const today = await sharedToolAccess({ ...person, createdAt: new Date(0) }, tool, { record: false })
          expect([person.id, tool, caps.has(TOOL_PERMISSION[tool])]).toEqual([person.id, tool, today.allowed])
        }
      }
    }
  })

  test('no production code names a permission table outside the named readers', () => {
    const PERMISSION_READERS = [
      // Step 3.4: the resolution reads the sets and the instance default set only with the switch on.
      'src/lib/authz/capabilities.ts',
      // Step 3.4: selects the assignments and overrides only with the switch on.
      'src/lib/authz/principal.ts',
    ]
    const NAMES = /\b(permissionSets?|permissionOverrides?|userPermissionSet|userPermissionOverride|permission_sets|user_permission_sets|user_permission_overrides|defaultMemberSetId|default_member_set_id)\b/
    const files: string[] = []
    const walk = (dir: string): void => {
      for (const name of readdirSync(dir)) {
        const full = path.join(dir, name)
        if (statSync(full).isDirectory()) {
          if (name !== 'node_modules' && name !== '__testing__' && name !== '__fixtures__') walk(full)
        } else if (/\.(ts|tsx|mjs|js)$/.test(name) && !/\.test\.(ts|tsx|mjs)$/.test(name)) {
          files.push(full)
        }
      }
    }
    walk(path.join(WEBAPP, 'src'))
    walk(path.join(WEBAPP, 'scripts'))
    expect(files).toContain(path.join(WEBAPP, 'src/lib/authz/principal.ts'))
    const readers = files.filter((f) => NAMES.test(readFileSync(f, 'utf8'))).map((f) => path.relative(WEBAPP, f)).sort()
    expect(readers).toEqual(PERMISSION_READERS)
  })
})

describe('RBAC_PERMISSIONS_ENABLED off: can() answers as the guards do today (step 3.5)', () => {
  const ON_A_PROJECT = ALL.filter((p) => PERMISSIONS[p].scope === 'project' || PERMISSIONS[p].level !== null)
  const ADMIN_SIDE = ALL.filter((p) => PERMISSIONS[p].kind === 'admin')

  test.each([true, false])('on a project: its owner may do every member action, anyone else gets 404, whatever rows exist (identity %s)', async (identity) => {
    setFlagsForTests({ identity, permissions: false })
    const owner = account('member-1', 'standard', NARROWED)
    for (const p of ON_A_PROJECT) {
      expect([p, (await can(owner, p, { projectId: 'P-member' })).allowed]).toEqual([p, true])
      expect([p, await can(owner, p, { projectId: 'P-admin' })])
        .toEqual([p, { allowed: false, status: 404, reason: 'project_not_visible', permission: p }])
      expect([p, (await can(account('admin-1', 'admin', NARROWED), p, { projectId: 'P-member' })).allowed]).toEqual([p, false])
    }
    expect(setFindMany).not.toHaveBeenCalled()
  })

  test('act-as: the project is the account acted as (getEffectiveUser), and every member action stays open', async () => {
    const opts = { actingAs: account('member-1', 'standard', NARROWED) }
    for (const p of ON_A_PROJECT) {
      expect([p, (await can(account('admin-1', 'admin'), p, { ...opts, projectId: 'P-member' })).allowed]).toEqual([p, true])
      expect([p, await can(account('admin-1', 'admin'), p, { ...opts, projectId: 'P-admin' })]).toMatchObject([p, { allowed: false, status: 404 }])
    }
  })

  test("an instance action: an admin's (but Root's own), a member's only through a legacy grant (requireAdmin, sharedToolAccess)", async () => {
    const memberDecisions = await Promise.all(ADMIN_SIDE.map(async (p) => [p, (await can(account('member-1', 'standard', NARROWED), p)).allowed]))
    expect(memberDecisions.filter(([, allowed]) => allowed)).toEqual([])
    const granted = account('member-2', 'standard', { legacyGrants: ['kali_terminal', 'tunnels'] })
    expect((await can(granted, 'platform:kali_terminal')).allowed).toBe(true)
    expect((await can(granted, 'platform:tunnels')).allowed).toBe(true)
    expect(await can(granted, 'platform:emergency_stop')).toMatchObject({ allowed: false, status: 403, permission: 'platform:emergency_stop' })
    for (const p of ADMIN_SIDE) {
      expect([p, (await can(account('admin-1', 'admin', NARROWED), p)).allowed]).toEqual([p, !ROOT_ONLY.includes(p)])
    }
    setFlagsForTests({ identity: false, permissions: false })
    expect((await can(account('admin-1', 'admin'), 'admins:manage')).allowed).toBe(true)
  })
})
