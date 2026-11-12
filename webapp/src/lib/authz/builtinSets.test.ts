/**
 * The built-in permission sets and admin profiles (step 3.2): their contents (feature document
 * §4.5, §4.6, §5.14), that no built-in escalates past today's account types, and the JSON copy
 * the .mjs scripts read.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'

import {
  BUILTIN_ADMIN_PROFILES,
  BUILTIN_MEMBER_SETS,
  BUILTIN_SETS,
  BUILTIN_SET_IDS,
  DEFAULT_MEMBER_SET_ID,
  FULL_ADMIN_PROFILE_ID,
  NO_ACCESS_SET_ID,
  builtinSet,
  isBuiltinSetId,
  type BuiltinSet,
} from './builtinSets'
import { PERMISSIONS, PERMISSION_IDS, type PermissionId } from './permissions'

const byId = (id: string): BuiltinSet => {
  const set = BUILTIN_SETS.find((s) => s.id === id)
  if (!set) throw new Error(`no built-in ${id}`)
  return set
}
const held = (id: string): ReadonlySet<string> => new Set(byId(id).permissions)

const MEMBER_SIDE = PERMISSION_IDS.filter((p) => PERMISSIONS[p].kind === 'member')
const ADMIN_SIDE = PERMISSION_IDS.filter((p) => PERMISSIONS[p].kind === 'admin')
const ROOT_ONLY = PERMISSION_IDS.filter((p) => PERMISSIONS[p].rootOnly)
const EXPLOITATION_TOGGLE = PERMISSION_IDS.filter((p) => PERMISSIONS[p].level === 'W+X')
const inRegistryOrder = (ids: string[]): string[] => PERMISSION_IDS.filter((p) => ids.includes(p))

/** §5.14 "Read everything (`*:read`, `graph:cypher`)" over the member side. */
const READS = [
  'roe:read', 'recon:read', 'workspace:read', 'graph:read', 'graph:cypher', 'triage:read', 'remediation:read',
  'reports:read', 'traffic:read', 'auth_profile:read',
]
/** §5.14 "Scans (`recon:*`, `scan:*`)", the reads aside. */
const SCANS = [
  'recon:scan', 'recon:partial', 'recon:overwrite', 'recon:schedule', 'scan:gvm', 'scan:secrets', 'scan:supply_chain',
  'scan:ai_attack', 'scan:uploads', 'scan:custom_templates', 'scan:versions', 'scan:versions_delete',
]
/** §5.14 "Write (settings, triage, views, reports, workspace)": every other change to a project or its data. */
const WRITES = [
  'project:settings', 'project:rescope', 'engagement:authorize', 'roe:manage', 'auth_profile:manage', 'project:export',
  'project:delete', 'project:transfer', 'preset:apply', 'preset:write', 'workspace:write', 'workspace:import',
  'graph:views', 'graph:edit', 'triage:verdict', 'triage:mute', 'triage:review', 'triage:run', 'node_filters:manage',
  'remediation:write', 'codefix:run', 'reports:generate', 'reports:delete', 'traffic:export', 'traffic:delete',
]

describe('the built-ins: ids, kinds, shape', () => {
  test('six member sets and four admin profiles, ids builtin:<slug>', () => {
    expect(BUILTIN_MEMBER_SETS.map((s) => [s.id, s.name])).toEqual([
      ['builtin:default-member', 'Default member'],
      ['builtin:read-only-analyst', 'Read-only analyst'],
      ['builtin:recon-operator', 'Recon operator'],
      ['builtin:red-team-operator', 'Red-team operator'],
      ['builtin:automation', 'Automation'],
      ['builtin:no-access', 'No access'],
    ])
    expect(BUILTIN_ADMIN_PROFILES.map((s) => [s.id, s.name])).toEqual([
      ['builtin:full-admin', 'Full admin'],
      ['builtin:user-manager', 'User manager'],
      ['builtin:platform-operator', 'Platform operator'],
      ['builtin:security-auditor', 'Security auditor'],
    ])
    expect(BUILTIN_MEMBER_SETS.every((s) => s.kind === 'member')).toBe(true)
    expect(BUILTIN_ADMIN_PROFILES.every((s) => s.kind === 'admin')).toBe(true)
    expect(BUILTIN_SETS).toEqual([...BUILTIN_MEMBER_SETS, ...BUILTIN_ADMIN_PROFILES])
    expect(BUILTIN_SET_IDS).toEqual(BUILTIN_SETS.map((s) => s.id))
    expect(DEFAULT_MEMBER_SET_ID).toBe('builtin:default-member')
    expect(NO_ACCESS_SET_ID).toBe('builtin:no-access')
    expect(FULL_ADMIN_PROFILE_ID).toBe('builtin:full-admin')
  })

  test('names are distinct ignoring case, and every built-in has a description for the screens', () => {
    expect(new Set(BUILTIN_SETS.map((s) => s.name.toLowerCase())).size).toBe(BUILTIN_SETS.length)
    for (const set of BUILTIN_SETS) {
      expect(set.description.length, set.id).toBeGreaterThan(20)
      expect(set.description, set.id).toMatch(/\.$/)
    }
    expect(new Set(BUILTIN_SETS.map((s) => s.description)).size).toBe(BUILTIN_SETS.length)
  })

  test('every permission is a registry id, listed once, in registry order (PE-02)', () => {
    for (const set of BUILTIN_SETS) {
      expect(set.permissions, set.id).toEqual(inRegistryOrder([...set.permissions]))
      expect(new Set(set.permissions).size, set.id).toBe(set.permissions.length)
    }
  })

  test('a member set holds only member permissions, an admin profile only admin ones (§4.5)', () => {
    for (const set of BUILTIN_MEMBER_SETS) {
      expect(set.permissions.filter((p) => PERMISSIONS[p].kind !== 'member'), set.id).toEqual([])
    }
    for (const set of BUILTIN_ADMIN_PROFILES) {
      expect(set.permissions.filter((p) => PERMISSIONS[p].kind !== 'admin'), set.id).toEqual([])
    }
  })

  test('the built-ins cannot be changed at run time', () => {
    expect(Object.isFrozen(BUILTIN_SETS)).toBe(true)
    expect(Object.isFrozen(BUILTIN_MEMBER_SETS)).toBe(true)
    expect(Object.isFrozen(BUILTIN_ADMIN_PROFILES)).toBe(true)
    expect(Object.isFrozen(BUILTIN_SET_IDS)).toBe(true)
    for (const set of BUILTIN_SETS) {
      expect(Object.isFrozen(set), set.id).toBe(true)
      expect(Object.isFrozen(set.permissions), set.id).toBe(true)
    }
  })
})

describe('member sets (PE-14, §4.6, §5.14)', () => {
  test('Default member = every non-crossTenant member permission (PE-05, PE-28)', () => {
    const expected = PERMISSION_IDS.filter((p) => PERMISSIONS[p].kind === 'member' && !PERMISSIONS[p].crossTenant)
    expect(byId(DEFAULT_MEMBER_SET_ID).permissions).toEqual(expected)
    expect(expected).toEqual(MEMBER_SIDE)
    expect(expected).toHaveLength(70)
    // OQ-46: the Kali sandbox stays in today's member abilities, labelled sandboxShared.
    expect(held(DEFAULT_MEMBER_SET_ID).has('agent:kali_exec')).toBe(true)
  })

  test('crossTenant is in no member set: the platform tools reach members only as legacy grants (§14.7)', () => {
    for (const set of BUILTIN_MEMBER_SETS) {
      expect(set.permissions.filter((p) => PERMISSIONS[p].crossTenant), set.id).toEqual([])
    }
  })

  test('Read-only analyst has no write, scan or agent chat', () => {
    const analyst = byId('builtin:read-only-analyst')
    expect(analyst.permissions).toEqual(inRegistryOrder(['self:presets', ...READS, 'agent:assistants']))
    const ids = held(analyst.id)
    for (const p of [...SCANS, ...WRITES, ...EXPLOITATION_TOGGLE, 'agent:chat', 'agent:fireteam', 'agent:loop']) {
      expect(ids.has(p), p).toBe(false)
    }
    for (const p of ['project:create', 'project:import', 'project:share', 'self:llm_providers', 'self:api_keys', 'self:mcp_tokens']) {
      expect(ids.has(p), p).toBe(false)
    }
    // Every project permission it holds needs at most Read, except the assistants (§5.14 "assistants only").
    const aboveRead = analyst.permissions.filter(
      (p) => PERMISSIONS[p].scope === 'project' && !['R', 'R*'].includes(PERMISSIONS[p].level ?? ''),
    )
    expect(aboveRead).toEqual(['agent:assistants'])
  })

  test('Recon operator has no approve_*, sessions or kali_exec: Default member less the exploitation toggle', () => {
    const recon = held('builtin:recon-operator')
    for (const p of ['agent:approve_phase', 'agent:approve_dangerous', 'agent:sessions', 'agent:kali_exec', 'traffic:replay']) {
      expect(recon.has(p), p).toBe(false)
    }
    expect(EXPLOITATION_TOGGLE).toEqual(['agent:approve_phase', 'agent:approve_dangerous', 'agent:sessions', 'agent:kali_exec', 'traffic:replay'])
    expect(byId('builtin:recon-operator').permissions).toEqual(MEMBER_SIDE.filter((p) => !EXPLOITATION_TOGGLE.includes(p)))
    for (const p of [...SCANS, 'agent:chat', 'agent:fireteam', 'agent:loop', 'agent:assistants', 'project:create']) {
      expect(recon.has(p), p).toBe(true)
    }
  })

  test('Red-team operator: full offensive use, the same member abilities as Default member', () => {
    expect(byId('builtin:red-team-operator').permissions).toEqual(byId(DEFAULT_MEMBER_SET_ID).permissions)
    for (const p of [...EXPLOITATION_TOGGLE, 'agent:fireteam']) {
      expect(held('builtin:red-team-operator').has(p), p).toBe(true)
    }
  })

  test('Automation has self:mcp_tokens and agent:loop only on the agent side', () => {
    const automation = byId('builtin:automation')
    expect(automation.permissions).toEqual(
      inRegistryOrder(['self:mcp_tokens', 'project:create', ...READS, ...WRITES, ...SCANS, 'agent:loop']),
    )
    expect(automation.permissions.filter((p) => p.startsWith('self:'))).toEqual(['self:mcp_tokens'])
    expect(automation.permissions.filter((p) => p.startsWith('agent:'))).toEqual(['agent:loop'])
    expect(automation.permissions.filter((p) => EXPLOITATION_TOGGLE.includes(p))).toEqual([])
    expect(automation.permissions.filter((p) => p.startsWith('plugins:'))).toEqual([])
    // It drives RedAmon over MCP: every MCP scope but kali:exec (exploitation) stays usable.
    const mcpBacked = PERMISSION_IDS.filter((p) => PERMISSIONS[p].mcpScopes.length > 0 && p !== 'agent:kali_exec')
    expect(mcpBacked.filter((p) => !held(automation.id).has(p))).toEqual([])
  })

  test('No access is empty', () => {
    expect(byId(NO_ACCESS_SET_ID).permissions).toEqual([])
  })

  test('the §5.14 areas cover the member side once each', () => {
    const areas = [
      MEMBER_SIDE.filter((p) => p.startsWith('self:')),
      ['project:create', 'project:import', 'project:share'],
      READS, SCANS, WRITES,
      ['agent:chat', 'agent:fireteam', 'agent:loop', 'agent:assistants', 'agent:conversations_share'],
      EXPLOITATION_TOGGLE,
      ['plugins:use', 'plugins:approve_overrides'],
    ].flat()
    expect(new Set(areas).size).toBe(areas.length)
    expect([...areas].sort()).toEqual([...MEMBER_SIDE].sort())
  })

  test('no member set holds more than Default member: nothing escalates past today (PE-28)', () => {
    const today = held(DEFAULT_MEMBER_SET_ID)
    for (const set of BUILTIN_MEMBER_SETS) {
      expect(set.permissions.filter((p) => !today.has(p)), set.id).toEqual([])
    }
  })
})

describe('admin profiles (PE-07, §4.5)', () => {
  test('Full admin has no rootOnly: every other admin permission', () => {
    expect(byId(FULL_ADMIN_PROFILE_ID).permissions).toEqual(ADMIN_SIDE.filter((p) => !PERMISSIONS[p].rootOnly))
    expect(byId(FULL_ADMIN_PROFILE_ID).permissions).toHaveLength(23)
    expect(ROOT_ONLY).toEqual(['admins:manage', 'admin_profiles:manage', 'projects:administer', 'instance:settings', 'root:transfer'])
  })

  test('no built-in profile holds a rootOnly permission (OQ-02: admins:manage is Root opt-in only)', () => {
    for (const set of BUILTIN_ADMIN_PROFILES) {
      expect(set.permissions.filter((p) => PERMISSIONS[p].rootOnly), set.id).toEqual([])
    }
  })

  test('User manager has no platform and no impersonate', () => {
    const manager = byId('builtin:user-manager')
    expect(manager.permissions).toEqual([
      'users:read', 'users:create', 'users:edit', 'users:disable', 'users:reset_credentials', 'users:revoke_sessions',
      'users:assign_permissions',
    ])
    expect(manager.permissions.filter((p) => p.startsWith('platform:'))).toEqual([])
    expect(held(manager.id).has('users:impersonate')).toBe(false)
    expect(held(manager.id).has('roles:manage')).toBe(false)
    expect(held(manager.id).has('users:delete')).toBe(false)
  })

  test('Platform operator: the platform tools of §4.5, no user management', () => {
    const operator = byId('builtin:platform-operator')
    expect(operator.permissions).toEqual([
      'platform:plugins', 'platform:traffic_capture', 'platform:tunnels', 'platform:nuclei_templates',
      'platform:agent_mcp', 'platform:emergency_stop', 'platform:shell_sessions', 'platform:operations',
    ])
    expect(operator.permissions.filter((p) => /^(users|admins|roles|admin_profiles):/.test(p))).toEqual([])
  })

  test('Security auditor changes nothing: every permission is a read or oversight (ID-11)', () => {
    const auditor = byId('builtin:security-auditor')
    expect(auditor.permissions).toEqual(['users:read', 'audit:read', 'audit:export', 'projects:oversee'])
    const READ_OR_OVERSIGHT = new Set<PermissionId>(['users:read', 'audit:read', 'audit:export', 'projects:oversee'])
    for (const p of auditor.permissions) {
      expect(READ_OR_OVERSIGHT.has(p), p).toBe(true)
      expect(PERMISSIONS[p].takeoverEquivalent, p).toBe(false)
      expect(PERMISSIONS[p].crossTenant, p).toBe(false)
    }
  })

  test('every profile is within Full admin', () => {
    const full = held(FULL_ADMIN_PROFILE_ID)
    for (const set of BUILTIN_ADMIN_PROFILES) {
      expect(set.permissions.filter((p) => !full.has(p)), set.id).toEqual([])
    }
  })
})

describe('lookups', () => {
  test('builtinSet finds a built-in by id; anything else is undefined', () => {
    for (const set of BUILTIN_SETS) expect(builtinSet(set.id)).toBe(set)
    for (const other of ['builtin:', 'builtin:Default-member', 'Default member', 'clxyz0000000000000000000', '__proto__',
      'toString', 'builtin:constructor', '', 'builtin:default-member ']) {
      expect(builtinSet(other), other).toBeUndefined()
      expect(isBuiltinSetId(other), other).toBe(false)
    }
    for (const other of [null, undefined, 42, {}]) expect(isBuiltinSetId(other)).toBe(false)
    for (const id of BUILTIN_SET_IDS) expect(isBuiltinSetId(id)).toBe(true)
  })
})

/**
 * The .mjs scripts (step 3.8's matrix-row generator) cannot import TypeScript, so they read this
 * copy. Fix a mismatch by regenerating it, never by hand:
 *   cd webapp && npx vitest run src/lib/authz/builtinSets.test.ts -u
 */
describe('the JSON copy for scripts', () => {
  test('permissionCatalog.json is the registry and the built-ins', async () => {
    const catalog = {
      '//': 'Generated from permissions.ts and builtinSets.ts for .mjs scripts. Do not edit: cd webapp && npx vitest run src/lib/authz/builtinSets.test.ts -u',
      permissions: PERMISSIONS,
      sets: BUILTIN_SETS,
    }
    await expect(`${JSON.stringify(catalog, null, 2)}\n`).toMatchFileSnapshot('./permissionCatalog.json')
  })
})
