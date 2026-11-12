/**
 * The registry's areas for the permission screens (step 3.13): every permission in exactly one
 * area, in registry order, each area starting where its §5 section starts.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/authz/permissionAreas.test.ts
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { PERMISSION_IDS, type PermissionId } from './permissions'
import { PERMISSION_AREAS, areaOf, groupByArea } from './permissionAreas'

describe('permission areas', () => {
  test('every permission sits in exactly one area, and the areas read the registry in order', () => {
    expect(PERMISSION_AREAS.flatMap((a) => a.permissions)).toEqual(PERMISSION_IDS)
    expect(PERMISSION_AREAS.every((a) => a.permissions.length > 0)).toBe(true)
    expect(new Set(PERMISSION_AREAS.map((a) => a.id)).size).toBe(PERMISSION_AREAS.length)
  })

  test('the §5 sections: a few ids land where the feature document puts them', () => {
    const where = (p: PermissionId) => areaOf(p).id
    expect([
      where('users:read'), where('root:transfer'), where('platform:operations'), where('self:presets'),
      where('auth_profile:manage'), where('preset:write'), where('agent:conversations_share'),
      where('graph:edit'), where('codefix:run'), where('reports:delete'), where('auth_profile:read'),
      where('plugins:approve_overrides'),
    ]).toEqual([
      'administration', 'administration', 'platform', 'self', 'projects', 'recon', 'agent', 'graph', 'triage',
      'reports', 'traffic', 'plugins',
    ])
  })

  test('groupByArea keeps registry order and leaves empty areas out', () => {
    const items = (['reports:read', 'agent:chat', 'agent:loop', 'users:read'] as PermissionId[]).map((permission) => ({ permission }))
    expect(groupByArea(items).map((g) => [g.area.id, g.items.map((i) => i.permission)])).toEqual([
      ['administration', ['users:read']],
      ['agent', ['agent:chat', 'agent:loop']],
      ['reports', ['reports:read']],
    ])
    expect(groupByArea([])).toEqual([])
  })
})
