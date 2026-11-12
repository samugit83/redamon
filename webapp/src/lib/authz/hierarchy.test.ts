/**
 * Who may manage whom (step 3.11; feature document §4.5, §4.8; PE-03, PE-08, PE-09, PE-10): Root >
 * admin > member. An admin acts on members with the permission of the action; on another admin
 * only Root, or (D-02, opt-in) an admin holding `admins:manage` whose admin side strictly
 * contains the target's profile, and even then never a reset, an impersonation or a creation.
 * Nobody acts on Root. Nobody gives a permission they do not hold.
 *
 * Pure rules: no database, no switch.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/authz/hierarchy.test.ts
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import {
  MANAGE_ACTIONS, MANAGE_PERMISSION, ROOT_ONLY_ON_ADMINS, STEP_UP_PERMISSIONS,
  adminSide, canAssignProfile, canManage, isStrictSubset, overrideAllowed, stepUpPermissionsIn, unheld,
  type ManageAction, type Managed, type Manager,
} from './hierarchy'
import { PERMISSIONS, PERMISSION_IDS, type PermissionId } from './permissions'
import { builtinSet, DEFAULT_MEMBER_SET_ID, FULL_ADMIN_PROFILE_ID } from './builtinSets'

const ALL = [...PERMISSION_IDS]
const contents = (id: string): PermissionId[] => [...builtinSet(id)!.permissions]
const FULL_ADMIN = contents(FULL_ADMIN_PROFILE_ID)
const USER_MANAGER = contents('builtin:user-manager')
const PLATFORM_OPERATOR = contents('builtin:platform-operator')
const DEFAULT_MEMBER = contents(DEFAULT_MEMBER_SET_ID)
const READ_ONLY = contents('builtin:read-only-analyst')
const RECON = contents('builtin:recon-operator')
const MANAGER_PROFILE: PermissionId[] = [...FULL_ADMIN, 'admins:manage']

const actor = (id: string, accountType: Manager['accountType'], ...held: PermissionId[][]): Manager =>
  ({ id, accountType, held: [...new Set(held.flat())] })
const target = (id: string, accountType: Managed['accountType'], profile: PermissionId[] = []): Managed =>
  ({ id, accountType, profile })

const ROOT = actor('root', 'root', ALL)
const ROOT_UNCONFIRMED = actor('root', 'root', ALL.filter((p) => !PERMISSIONS[p].rootOnly))
const ADMIN = actor('admin-a', 'admin', FULL_ADMIN, DEFAULT_MEMBER)
const MANAGER = actor('admin-m', 'admin', MANAGER_PROFILE, DEFAULT_MEMBER)
const USER_MGR = actor('admin-u', 'admin', USER_MANAGER, DEFAULT_MEMBER)
const MEMBER = actor('member-a', 'member', DEFAULT_MEMBER)

const T_ROOT = target('root', 'root')
const T_ADMIN = target('admin-b', 'admin', FULL_ADMIN)
const T_MEMBER = target('member-b', 'member')

describe('MANAGE_PERMISSION', () => {
  test('each action of the §4.8 table names its §5.1 permission', () => {
    expect(MANAGE_PERMISSION).toEqual({
      create: 'users:create',
      edit: 'users:edit',
      assign_permissions: 'users:assign_permissions',
      disable: 'users:disable',
      enable: 'users:disable',
      reset_credentials: 'users:reset_credentials',
      revoke_sessions: 'users:revoke_sessions',
      impersonate: 'users:impersonate',
      delete: 'users:delete',
    })
    for (const p of Object.values(MANAGE_PERMISSION)) expect(PERMISSIONS[p].kind).toBe('admin')
    expect(MANAGE_ACTIONS).toEqual(Object.keys(MANAGE_PERMISSION))
  })

  test('on another admin, a creation, a reset and an impersonation stay Root\'s (§4.5, §4.8)', () => {
    expect([...ROOT_ONLY_ON_ADMINS].sort()).toEqual(['create', 'impersonate', 'reset_credentials'])
  })
})

describe('canManage: every row of the §4.8 table (PE-08)', () => {
  test.each(MANAGE_ACTIONS)('%s: Root → Admin ✓, Root → Member ✓', (action) => {
    expect(canManage(ROOT, T_ADMIN, action)).toEqual({ allowed: true })
    expect(canManage(ROOT, T_MEMBER, action)).toEqual({ allowed: true })
  })

  test.each(MANAGE_ACTIONS)('%s: Admin → Admin ✗ (root_only), Admin → Member ✓ with the permission', (action) => {
    expect(canManage(ADMIN, T_ADMIN, action)).toEqual({ allowed: false, reason: 'root_only' })
    expect(canManage(ADMIN, T_MEMBER, action)).toEqual({ allowed: true })
  })

  test.each(MANAGE_ACTIONS)('%s: Admin → Member ✗ without the permission of the action (403 naming it)', (action) => {
    const permission = MANAGE_PERMISSION[action]
    const lacking = actor('admin-x', 'admin', FULL_ADMIN.filter((p) => p !== permission), DEFAULT_MEMBER)
    expect(canManage(lacking, T_MEMBER, action)).toEqual({ allowed: false, reason: 'forbidden', permission })
  })

  test.each(MANAGE_ACTIONS)('%s: act on Root ✗ for every other account, Root included only as itself', (action) => {
    for (const a of [ADMIN, MANAGER, MEMBER, USER_MGR]) {
      expect(canManage(a, T_ROOT, action)).toEqual({ allowed: false, reason: 'root_protected' })
    }
    expect(canManage(ROOT, T_ROOT, action)).toEqual({ allowed: false, reason: 'own_account' })
  })

  test.each(MANAGE_ACTIONS)('%s: a member manages nobody', (action) => {
    expect(canManage(MEMBER, T_MEMBER, action)).toEqual({ allowed: false, reason: 'forbidden', permission: MANAGE_PERMISSION[action] })
    expect(canManage(MEMBER, T_ADMIN, action)).toEqual({ allowed: false, reason: 'root_only' })
  })

  test('the own account is never a target here: the routes decide it', () => {
    expect(canManage(ADMIN, target('admin-a', 'admin', FULL_ADMIN), 'edit')).toEqual({ allowed: false, reason: 'own_account' })
  })

  test('User manager: members only, and only what its profile names (no delete, no impersonate)', () => {
    expect(canManage(USER_MGR, T_MEMBER, 'disable')).toEqual({ allowed: true })
    expect(canManage(USER_MGR, T_MEMBER, 'assign_permissions')).toEqual({ allowed: true })
    expect(canManage(USER_MGR, T_MEMBER, 'delete')).toEqual({ allowed: false, reason: 'forbidden', permission: 'users:delete' })
    expect(canManage(USER_MGR, T_MEMBER, 'impersonate')).toEqual({ allowed: false, reason: 'forbidden', permission: 'users:impersonate' })
    expect(canManage(USER_MGR, target('admin-p', 'admin', PLATFORM_OPERATOR), 'disable')).toEqual({ allowed: false, reason: 'root_only' })
  })

  test('an unconfirmed Root has none of Root\'s powers over admins (2.6) but acts on members', () => {
    for (const action of MANAGE_ACTIONS) {
      expect(canManage(ROOT_UNCONFIRMED, T_ADMIN, action)).toEqual({ allowed: false, reason: 'root_only' })
      expect(canManage(ROOT_UNCONFIRMED, T_MEMBER, action)).toEqual({ allowed: true })
    }
  })
})

describe('admins:manage (D-02 opt-in, PE-09)', () => {
  test('strict subset: an admin whose profile is strictly inside the actor\'s admin side is managed', () => {
    for (const action of ['edit', 'assign_permissions', 'disable', 'enable', 'revoke_sessions', 'delete'] as ManageAction[]) {
      expect([action, canManage(MANAGER, T_ADMIN, action)]).toEqual([action, { allowed: true }])
      expect([action, canManage(MANAGER, target('admin-u', 'admin', USER_MANAGER), action)]).toEqual([action, { allowed: true }])
    }
  })

  test('never reset, impersonate or create an admin, even over a strict subset', () => {
    for (const action of ROOT_ONLY_ON_ADMINS) {
      expect(canManage(MANAGER, target('admin-u', 'admin', USER_MANAGER), action)).toEqual({ allowed: false, reason: 'root_only' })
    }
  })

  test('equal profiles cannot manage each other (F-08)', () => {
    const peerA = actor('admin-1', 'admin', MANAGER_PROFILE, DEFAULT_MEMBER)
    const peerB = actor('admin-2', 'admin', MANAGER_PROFILE, DEFAULT_MEMBER)
    for (const action of MANAGE_ACTIONS.filter((a) => !ROOT_ONLY_ON_ADMINS.has(a))) {
      expect(canManage(peerA, target('admin-2', 'admin', MANAGER_PROFILE), action)).toEqual({ allowed: false, reason: 'not_a_subset' })
      expect(canManage(peerB, target('admin-1', 'admin', MANAGER_PROFILE), action)).toEqual({ allowed: false, reason: 'not_a_subset' })
    }
  })

  test('a target holding anything the actor lacks is not a subset, however small', () => {
    const narrow = actor('admin-n', 'admin', ['admins:manage', 'users:read', 'users:edit', 'users:disable'], DEFAULT_MEMBER)
    expect(canManage(narrow, target('admin-p', 'admin', ['users:read', 'platform:plugins']), 'edit')).toEqual({ allowed: false, reason: 'not_a_subset' })
    expect(canManage(narrow, target('admin-r', 'admin', ['users:read']), 'edit')).toEqual({ allowed: true })
    expect(canManage(narrow, target('admin-r', 'admin', ['users:read']), 'delete')).toEqual({ allowed: false, reason: 'forbidden', permission: 'users:delete' })
  })

  test('the actor\'s side is what it holds now: a denied admin permission no longer counts', () => {
    const denied = actor('admin-d', 'admin', MANAGER_PROFILE.filter((p) => p !== 'platform:plugins'), DEFAULT_MEMBER)
    expect(canManage(denied, T_ADMIN, 'edit')).toEqual({ allowed: false, reason: 'not_a_subset' })
  })

  test('promote only to a subset: canAssignProfile', () => {
    expect(canAssignProfile(ROOT, MANAGER_PROFILE)).toEqual({ allowed: true })
    expect(canAssignProfile(MANAGER, FULL_ADMIN)).toEqual({ allowed: true })
    expect(canAssignProfile(MANAGER, USER_MANAGER)).toEqual({ allowed: true })
    expect(canAssignProfile(MANAGER, MANAGER_PROFILE)).toEqual({ allowed: false, reason: 'not_a_subset' })
    expect(canAssignProfile(MANAGER, [...FULL_ADMIN, 'admins:manage', 'instance:settings'])).toEqual({ allowed: false, reason: 'not_a_subset' })
    expect(canAssignProfile(ADMIN, USER_MANAGER)).toEqual({ allowed: false, reason: 'root_only' })
    expect(canAssignProfile(ROOT_UNCONFIRMED, USER_MANAGER)).toEqual({ allowed: false, reason: 'root_only' })
    expect(canAssignProfile(MEMBER, [])).toEqual({ allowed: false, reason: 'root_only' })
  })
})

describe('no escalation (PE-03, PE-10)', () => {
  test('assign only held: what the actor does not hold is listed, in registry order', () => {
    const analystAdmin = actor('admin-r', 'admin', FULL_ADMIN, READ_ONLY)
    expect(unheld(analystAdmin, READ_ONLY)).toEqual([])
    const missing = unheld(analystAdmin, RECON)
    expect(missing.length).toBeGreaterThan(0)
    expect(missing).toContain('recon:scan')
    expect(missing).toEqual(ALL.filter((p) => RECON.includes(p) && !READ_ONLY.includes(p)))
    expect(unheld(ADMIN, DEFAULT_MEMBER)).toEqual([])
    expect(unheld(ADMIN, ['admins:manage', 'users:read'])).toEqual(['admins:manage'])
  })

  test('Root holds everything; an unconfirmed Root lacks the Root-only permissions', () => {
    expect(unheld(ROOT, ALL)).toEqual([])
    expect(unheld(ROOT_UNCONFIRMED, ['admins:manage', 'users:read'])).toEqual(['admins:manage'])
  })

  test('unknown ids are never "held"', () => {
    expect(unheld(ROOT, ['nope:never' as PermissionId])).toEqual(['nope:never'])
  })
})

describe('isStrictSubset and adminSide', () => {
  test('strict subset', () => {
    expect(isStrictSubset([], ['users:read'])).toBe(true)
    expect(isStrictSubset(['users:read'], ['users:read', 'users:edit'])).toBe(true)
    expect(isStrictSubset(['users:read', 'users:edit'], ['users:edit', 'users:read'])).toBe(false)
    expect(isStrictSubset(['users:read', 'audit:read'], ['users:read', 'users:edit'])).toBe(false)
    expect(isStrictSubset([], [])).toBe(false)
  })

  test('adminSide keeps the administration and platform permissions, in registry order', () => {
    expect(adminSide([...DEFAULT_MEMBER, 'users:edit', 'platform:plugins', 'users:read'])).toEqual(['users:read', 'users:edit', 'platform:plugins'])
  })
})

describe('step-up (ID-25)', () => {
  test('granting a crossTenant permission or an exploitation approval, sessions or Kali exec needs the password', () => {
    const crossTenant = ALL.filter((p) => PERMISSIONS[p].crossTenant)
    expect(crossTenant.length).toBe(9)
    expect([...STEP_UP_PERMISSIONS].sort()).toEqual(
      [...crossTenant, 'agent:approve_phase', 'agent:approve_dangerous', 'agent:sessions', 'agent:kali_exec'].sort(),
    )
    expect(stepUpPermissionsIn(['recon:scan', 'agent:kali_exec', 'platform:tunnels'])).toEqual(['platform:tunnels', 'agent:kali_exec'])
    expect(stepUpPermissionsIn(READ_ONLY)).toEqual([])
  })
})

describe('overrideAllowed (D-20, PE-30)', () => {
  test('any member permission, for a member and an admin', () => {
    for (const p of DEFAULT_MEMBER) {
      expect(overrideAllowed(p, 'member')).toBe(true)
      expect(overrideAllowed(p, 'admin')).toBe(true)
    }
  })

  test('a platform tool (§5.2) only on a member: an admin\'s admin side is its profile, whole', () => {
    for (const p of ALL.filter((x) => PERMISSIONS[x].crossTenant)) {
      expect([p, overrideAllowed(p, 'member')]).toEqual([p, true])
      expect([p, overrideAllowed(p, 'admin')]).toEqual([p, false])
    }
  })

  test('never an administration permission (§5.1), never on Root', () => {
    for (const p of ALL.filter((x) => PERMISSIONS[x].kind === 'admin' && !PERMISSIONS[x].crossTenant)) {
      expect([p, overrideAllowed(p, 'member')]).toEqual([p, false])
      expect([p, overrideAllowed(p, 'admin')]).toEqual([p, false])
    }
    expect(overrideAllowed('recon:scan', 'root')).toBe(false)
  })
})
