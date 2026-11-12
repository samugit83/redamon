/**
 * The permission registry (step 3.1): the feature document's §5 catalog, its metadata, and the
 * check that rejects a permission string the registry does not know.
 *
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'

import {
  PERMISSIONS,
  PERMISSION_IDS,
  PROJECT_LEVELS,
  UNRELEASED,
  assertKnownPermission,
  isPermissionId,
  type PermissionId,
} from './permissions'
import { MCP_SCOPES } from '@/lib/mcpAuth'
import { MCP_SCOPE_COPY } from '@/lib/mcp/scopeCopy'
import { PLUGIN_PERMISSIONS } from '@/lib/plugins/permissions'
import { ROUTE_MANIFEST } from './routeManifest'

/** Feature document §5.1-§5.12, in its order (98 ids). */
const CATALOG: Record<string, string[]> = {
  '5.1': [
    'users:read', 'users:create', 'users:edit', 'users:disable', 'users:delete', 'users:reset_credentials',
    'users:revoke_sessions', 'users:assign_permissions', 'users:impersonate', 'admins:manage', 'roles:manage',
    'admin_profiles:manage', 'audit:read', 'audit:export', 'projects:oversee', 'projects:administer',
    'instance:settings', 'instance:quotas', 'root:transfer',
  ],
  '5.2': [
    'platform:plugins', 'platform:traffic_capture', 'platform:tunnels', 'platform:nuclei_templates',
    'platform:agent_mcp', 'platform:emergency_stop', 'platform:shell_sessions', 'platform:kali_terminal',
    'platform:operations',
  ],
  '5.3': [
    'self:llm_providers', 'self:api_keys', 'self:mcp_servers', 'self:mcp_tokens', 'self:attack_skills',
    'self:chat_skills', 'self:tradecraft', 'self:presets',
  ],
  '5.4': [
    'project:create', 'project:import', 'project:share', 'project:settings', 'project:rescope',
    'engagement:authorize', 'roe:read', 'roe:manage', 'auth_profile:manage', 'project:export', 'project:delete',
    'project:transfer',
  ],
  '5.5': [
    'recon:read', 'recon:scan', 'recon:partial', 'recon:overwrite', 'recon:schedule', 'scan:gvm', 'scan:secrets',
    'scan:supply_chain', 'scan:ai_attack', 'scan:uploads', 'scan:custom_templates', 'scan:versions',
    'scan:versions_delete', 'preset:apply', 'preset:write',
  ],
  '5.6': [
    'agent:chat', 'agent:approve_phase', 'agent:approve_dangerous', 'agent:fireteam', 'agent:loop', 'agent:sessions',
    'agent:kali_exec', 'agent:assistants', 'agent:conversations_share',
  ],
  '5.7': ['workspace:read', 'workspace:write', 'workspace:import'],
  '5.8': ['graph:read', 'graph:cypher', 'graph:views', 'graph:edit'],
  '5.9': [
    'triage:read', 'triage:verdict', 'triage:mute', 'triage:review', 'triage:run', 'node_filters:manage',
    'remediation:read', 'remediation:write', 'codefix:run',
  ],
  '5.10': ['reports:read', 'reports:generate', 'reports:delete'],
  '5.11': ['traffic:read', 'traffic:export', 'traffic:delete', 'traffic:replay', 'auth_profile:read'],
  '5.12': ['plugins:use', 'plugins:approve_overrides'],
}
const ALL_IDS = Object.values(CATALOG).flat()
const ADMIN_SECTIONS = ['5.1', '5.2']

/** The project level each project permission needs (§5.4-§5.12 "Level" columns). */
const PROJECT_LEVEL: Record<string, string> = {
  'project:settings': 'W', 'project:rescope': 'M', 'engagement:authorize': 'M', 'roe:read': 'R', 'roe:manage': 'M',
  'auth_profile:manage': 'M', 'project:export': 'M', 'project:delete': 'O', 'project:transfer': 'O',
  'recon:read': 'R', 'recon:scan': 'W+S', 'recon:partial': 'W+S', 'recon:overwrite': 'W+S', 'recon:schedule': 'W+S',
  'scan:gvm': 'W+S', 'scan:secrets': 'W+S', 'scan:supply_chain': 'W+S', 'scan:ai_attack': 'W+S', 'scan:uploads': 'W',
  'scan:custom_templates': 'W', 'scan:versions': 'W', 'scan:versions_delete': 'M', 'preset:apply': 'W',
  'agent:chat': 'W+A', 'agent:approve_phase': 'W+X', 'agent:approve_dangerous': 'W+X', 'agent:fireteam': 'W+A',
  'agent:loop': 'W+A', 'agent:sessions': 'W+X', 'agent:kali_exec': 'W+X', 'agent:assistants': 'W+A',
  'agent:conversations_share': 'W+A',
  'workspace:read': 'R*', 'workspace:write': 'W', 'workspace:import': 'W',
  'graph:read': 'R', 'graph:cypher': 'R', 'graph:views': 'W', 'graph:edit': 'M',
  'triage:read': 'R', 'triage:verdict': 'W', 'triage:mute': 'W', 'triage:review': 'W', 'triage:run': 'W+A',
  'node_filters:manage': 'W', 'remediation:read': 'R', 'remediation:write': 'W', 'codefix:run': 'W+A',
  'reports:read': 'R', 'reports:generate': 'W', 'reports:delete': 'W',
  'traffic:read': 'R*', 'traffic:export': 'R*', 'traffic:delete': 'W', 'traffic:replay': 'W+X', 'auth_profile:read': 'R',
}
/** Instance permissions that still name a project when they act on one (§5.4 `I + M`, §5.12 `I / P M`). */
const INSTANCE_WITH_LEVEL: Record<string, string> = { 'project:share': 'M', 'plugins:approve_overrides': 'M' }

/** §5.13: every MCP scope and the catalog permissions it absorbs. */
const MCP_MAP: Record<string, string[]> = {
  'recon:read': ['recon:read', 'graph:read'],
  'recon:scan': ['recon:scan', 'recon:partial'],
  'recon:overwrite': ['recon:overwrite'],
  'recon:settings': ['project:settings'],
  'recon:queue': ['recon:schedule'],
  'triage:read': ['triage:read'],
  'triage:write': ['triage:verdict'],
  'triage:mute': ['triage:mute'],
  'triage:review': ['triage:review'],
  'triage:run': ['triage:run'],
  'graph:cypher': ['graph:cypher'],
  'project:create': ['project:create'],
  'project:rescope': ['project:rescope'],
  'engagement:authorize': ['engagement:authorize'],
  'preset:write': ['preset:write'],
  'preset:apply': ['preset:apply'],
  'agent:loop': ['agent:loop'],
  'kali:exec': ['agent:kali_exec'],
}

/** Gate features later phases of this release build (phase file 3.9 correction). */
const LATER_PHASE_FEATURES = [
  'project:share', 'project:transfer', 'projects:oversee', 'projects:administer', 'audit:read', 'audit:export',
  'instance:quotas', 'agent:conversations_share', 'traffic:replay', 'platform:operations',
]

const FIELDS = [
  'kind', 'scope', 'level', 'description', 'crossTenant', 'sandboxShared', 'takeoverEquivalent', 'rootOnly',
  'mcpScopes', 'introducedIn', 'gatesExisting', 'closesCrossTenantHole',
].sort()

const idsWhere = (pick: (id: PermissionId) => boolean) => PERMISSION_IDS.filter(pick).sort()

describe('catalog complete', () => {
  test('98 ids, exactly the feature document §5.1-§5.12, in its order', () => {
    expect(ALL_IDS).toHaveLength(98)
    expect(new Set(ALL_IDS).size).toBe(98)
    expect([...PERMISSION_IDS]).toEqual(ALL_IDS)
    expect(Object.keys(PERMISSIONS)).toEqual(ALL_IDS)
  })

  test('each entry carries every metadata field, with a value of its type', () => {
    for (const id of PERMISSION_IDS) {
      const m = PERMISSIONS[id]
      expect(Object.keys(m).sort(), id).toEqual(FIELDS)
      expect(['admin', 'member'], id).toContain(m.kind)
      expect(['instance', 'project'], id).toContain(m.scope)
      expect(m.level === null || (PROJECT_LEVELS as readonly string[]).includes(m.level), id).toBe(true)
      expect(typeof m.description, id).toBe('string')
      expect(m.description.trim().length, id).toBeGreaterThan(10)
      for (const flag of ['crossTenant', 'sandboxShared', 'takeoverEquivalent', 'rootOnly', 'gatesExisting', 'closesCrossTenantHole'] as const) {
        expect(typeof m[flag], `${id}.${flag}`).toBe('boolean')
      }
      expect(Array.isArray(m.mcpScopes), id).toBe(true)
    }
  })

  test('the levels are the eight of §5', () => {
    expect([...PROJECT_LEVELS]).toEqual(['R', 'R*', 'W', 'W+S', 'W+A', 'W+X', 'M', 'O'])
  })

  test('§5.1 and §5.2 are the admin side, §5.3-§5.12 the member side', () => {
    for (const [section, ids] of Object.entries(CATALOG)) {
      for (const id of ids) {
        expect(PERMISSIONS[id as PermissionId].kind, id).toBe(ADMIN_SECTIONS.includes(section) ? 'admin' : 'member')
      }
    }
  })

  test('project permissions carry the level of §5; instance ones only where they act on a project', () => {
    for (const id of PERMISSION_IDS) {
      const m = PERMISSIONS[id]
      if (id in PROJECT_LEVEL) {
        expect(m.scope, id).toBe('project')
        expect(m.level, id).toBe(PROJECT_LEVEL[id])
      } else {
        expect(m.scope, id).toBe('instance')
        expect(m.level, id).toBe(INSTANCE_WITH_LEVEL[id] ?? null)
      }
    }
  })

  test('the descriptions are distinct', () => {
    const descriptions = PERMISSION_IDS.map((id) => PERMISSIONS[id].description)
    expect(new Set(descriptions).size).toBe(descriptions.length)
  })

  test('the registry cannot be changed at run time', () => {
    expect(Object.isFrozen(PERMISSIONS)).toBe(true)
    expect(Object.isFrozen(PERMISSION_IDS)).toBe(true)
    for (const id of PERMISSION_IDS) {
      expect(Object.isFrozen(PERMISSIONS[id]), id).toBe(true)
      expect(Object.isFrozen(PERMISSIONS[id].mcpScopes), id).toBe(true)
    }
  })
})

describe('unknown rejected (PE-02)', () => {
  test('every registry id is known', () => {
    for (const id of ALL_IDS) {
      expect(isPermissionId(id), id).toBe(true)
      expect(() => assertKnownPermission(id), id).not.toThrow()
    }
  })

  test('an unknown string throws, naming it', () => {
    for (const bad of ['users:invite', 'recon:read ', 'RECON:READ', 'recon', '', 'admin', 'kali:exec', 'triage:write']) {
      expect(isPermissionId(bad), bad).toBe(false)
      expect(() => assertKnownPermission(bad), bad).toThrow(/unknown permission/i)
    }
    expect(() => assertKnownPermission('nope:nothing')).toThrow('nope:nothing')
  })

  test('names inherited from Object are not permissions', () => {
    for (const bad of ['toString', 'constructor', '__proto__', 'hasOwnProperty', 'valueOf']) {
      expect(isPermissionId(bad), bad).toBe(false)
      expect(() => assertKnownPermission(bad), bad).toThrow(/unknown permission/i)
    }
  })

  test('a value that is not a string is not a permission', () => {
    for (const bad of [undefined, null, 1, {}, ['recon:read'], true]) {
      expect(isPermissionId(bad)).toBe(false)
      expect(() => assertKnownPermission(bad)).toThrow(/unknown permission/i)
    }
  })

  test('the permissions Phase 1 and 2 already name in a 403 are known; users:invite is not (step 3.7 renames it users:create)', () => {
    for (const named of [
      'platform:kali_terminal', 'users:disable', 'users:revoke_sessions', 'users:reset_credentials',
      'users:assign_permissions', 'root:transfer', 'instance:settings',
    ]) {
      expect(isPermissionId(named), named).toBe(true)
    }
    expect(isPermissionId('users:invite')).toBe(false)
    expect(isPermissionId('users:create')).toBe(true)
  })

  test('every permission the route manifest names is in the registry (PE-19, registry half)', () => {
    const named = ROUTE_MANIFEST.flatMap((entry) => {
      const p = (entry as { permission?: unknown }).permission
      if (p === undefined || p === null) return []
      return typeof p === 'string' ? [p] : Object.values(p as Record<string, string>)
    })
    expect(named.filter((p) => !isPermissionId(p))).toEqual([])
  })
})

describe('MCP scopes (§5.13)', () => {
  test('there are 18 scopes and the scope copy describes the same ones', () => {
    expect(MCP_SCOPES).toHaveLength(18)
    expect(Object.keys(MCP_SCOPE_COPY).sort()).toEqual([...MCP_SCOPES].sort())
    expect(Object.keys(MCP_MAP).sort()).toEqual([...MCP_SCOPES].sort())
  })

  test('every one of the 18 MCP scopes maps to at least one permission', () => {
    for (const scope of MCP_SCOPES) {
      expect(idsWhere((id) => PERMISSIONS[id].mcpScopes.includes(scope)).length, scope).toBeGreaterThan(0)
    }
  })

  test('each scope maps to exactly the permissions of §5.13', () => {
    for (const scope of MCP_SCOPES) {
      expect(idsWhere((id) => PERMISSIONS[id].mcpScopes.includes(scope)), scope).toEqual([...MCP_MAP[scope]].sort())
    }
  })

  test('a permission names only real scopes, each once', () => {
    for (const id of PERMISSION_IDS) {
      const scopes = PERMISSIONS[id].mcpScopes
      expect(new Set(scopes).size, id).toBe(scopes.length)
      for (const s of scopes) expect(MCP_SCOPES as readonly string[], id).toContain(s)
    }
  })
})

describe('registry ids and PLUGIN_PERMISSIONS are disjoint', () => {
  test('no plugin capability is a registry id, and no registry id a plugin capability', () => {
    expect(PLUGIN_PERMISSIONS.length).toBeGreaterThan(0)
    for (const p of PLUGIN_PERMISSIONS) expect(isPermissionId(p), p).toBe(false)
    for (const id of PERMISSION_IDS) expect((PLUGIN_PERMISSIONS as readonly string[]).includes(id), id).toBe(false)
  })
})

describe('labels', () => {
  test('crossTenant never in a default member set (PE-05): the cross-tenant ids are the nine §5.2 platform tools, all on the admin side', () => {
    expect(idsWhere((id) => PERMISSIONS[id].crossTenant)).toEqual([...CATALOG['5.2']].sort())
    for (const id of PERMISSION_IDS) {
      if (PERMISSIONS[id].crossTenant) expect(PERMISSIONS[id].kind, id).toBe('admin')
    }
    // Default member is drawn from the member side without crossTenant (phase 3 Design); 3.2 checks the set itself.
    const memberDefault = idsWhere((id) => PERMISSIONS[id].kind === 'member' && !PERMISSIONS[id].crossTenant)
    expect(memberDefault.filter((id) => PERMISSIONS[id].crossTenant)).toEqual([])
    expect(memberDefault).toContain('agent:kali_exec')
  })

  test('kali_exec is sandboxShared, not crossTenant (OQ-46, HD-22)', () => {
    expect(PERMISSIONS['agent:kali_exec'].sandboxShared).toBe(true)
    expect(PERMISSIONS['agent:kali_exec'].crossTenant).toBe(false)
    expect(idsWhere((id) => PERMISSIONS[id].sandboxShared)).toEqual(['agent:kali_exec'])
    expect(PERMISSIONS['agent:kali_exec'].description).toMatch(/shared/i)
  })

  test('closesCrossTenantHole implies crossTenant', () => {
    for (const id of PERMISSION_IDS) {
      if (PERMISSIONS[id].closesCrossTenantHole) expect(PERMISSIONS[id].crossTenant, id).toBe(true)
    }
    expect(idsWhere((id) => PERMISSIONS[id].closesCrossTenantHole)).toEqual([...CATALOG['5.2']].sort())
  })

  test('takeover flag (PE-12): resetting credentials and acting as someone are takeover-equivalent', () => {
    expect(idsWhere((id) => PERMISSIONS[id].takeoverEquivalent)).toEqual(['users:impersonate', 'users:reset_credentials'])
  })

  test('rootOnly: the five Root powers, admins:manage among them (OQ-02)', () => {
    expect(idsWhere((id) => PERMISSIONS[id].rootOnly)).toEqual(
      ['admin_profiles:manage', 'admins:manage', 'instance:settings', 'projects:administer', 'root:transfer'],
    )
    for (const id of PERMISSION_IDS) {
      if (PERMISSIONS[id].rootOnly) expect(PERMISSIONS[id].kind, id).toBe('admin')
    }
  })
})

describe('introduction declared (PE-26, §14.8)', () => {
  test('every entry names its release and whether it gates an existing feature', () => {
    expect(UNRELEASED).toBe('UNRELEASED')
    for (const id of PERMISSION_IDS) {
      expect(PERMISSIONS[id].introducedIn, id).toBe(UNRELEASED)
      expect(typeof PERMISSIONS[id].gatesExisting, id).toBe('boolean')
    }
  })

  test('only the features later phases build are declared new', () => {
    expect(idsWhere((id) => !PERMISSIONS[id].gatesExisting)).toEqual([...LATER_PHASE_FEATURES].sort())
  })
})
