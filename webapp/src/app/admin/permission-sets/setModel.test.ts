/**
 * The rules the permission sets and admin profiles pages mirror (step 6.3; GV-02, GV-03): which
 * permissions a set or profile may hold (permissionSetAdmin.ts `parsePermissions`), what the editor
 * may add (PE-11: only what they hold; a permission the set already has may stay or go), what a
 * clone starts from, the body each save sends, and when the server takes a password (ID-25 for a
 * member set gaining a dangerous permission; every profile write is the confirmed Root's).
 *
 * Run: npx vitest run --no-file-parallelism src/app/admin/permission-sets/setModel.test.ts
 */
import { describe, test, expect } from 'vitest'
import { PERMISSIONS, PERMISSION_IDS, type PermissionId } from '@/lib/authz/permissions'
import { BUILTIN_SETS } from '@/lib/authz/builtinSets'
import {
  MAX_NAME, addable, addedBy, cloneStart, createBody, defaultSetId, editBody, passwordNeeded, pickable, pickableAreas,
  type SetRow,
} from './setModel'

const inRegistryOrder = (ids: PermissionId[]) => [...ids].sort((a, b) => PERMISSION_IDS.indexOf(a) - PERMISSION_IDS.indexOf(b))

function set(over: Partial<SetRow> = {}): SetRow {
  return {
    id: 'set-1', kind: 'member', name: 'Lab readers', description: null, permissions: ['graph:read', 'reports:read'],
    builtin: false, clonedFrom: null, createdAt: null, updatedAt: null, holders: 0, instanceDefault: false, ...over,
  }
}

describe('what a set or profile may hold', () => {
  test('a member set lists member permissions only, an admin profile admin ones, never Root\'s own but admins:manage', () => {
    const member = pickable('member')
    const admin = pickable('admin')
    expect(member.length).toBeGreaterThan(0)
    expect(member.every((p) => PERMISSIONS[p].kind === 'member')).toBe(true)
    expect(admin.every((p) => PERMISSIONS[p].kind === 'admin')).toBe(true)
    expect(admin).toContain('admins:manage')
    for (const p of ['admin_profiles:manage', 'instance:settings', 'root:transfer', 'projects:administer'] as PermissionId[]) {
      expect(admin).not.toContain(p)
    }
    // Every built-in's contents can be shown and cloned with the same list.
    for (const b of BUILTIN_SETS) expect(b.permissions.filter((p) => !pickable(b.kind).includes(p))).toEqual([])
  })

  test('grouped by area, areas and permissions in registry order, no empty area', () => {
    const groups = pickableAreas('admin')
    expect(groups.map((g) => g.area.id)).toEqual(['administration', 'platform'])
    expect(groups.flatMap((g) => g.permissions)).toEqual(pickable('admin'))
    expect(pickableAreas('member').every((g) => g.permissions.length > 0)).toBe(true)
    expect(pickableAreas('member').map((g) => g.area.id)).not.toContain('administration')
  })
})

describe('what the editor may add (PE-11)', () => {
  const givable = new Set<PermissionId>(['graph:read'])
  test('a held permission, or one the set already holds; nothing else', () => {
    expect(addable('graph:read', [], givable)).toBe(true)
    expect(addable('reports:read', ['reports:read'], givable)).toBe(true)
    expect(addable('agent:kali_exec', [], givable)).toBe(false)
  })

  test('the permissions a draft adds, in registry order', () => {
    expect(addedBy(['reports:read'], ['graph:read', 'reports:read', 'agent:chat'])).toEqual(inRegistryOrder(['graph:read', 'agent:chat']))
    expect(addedBy(['reports:read'], [])).toEqual([])
  })
})

describe('a clone', () => {
  test('starts from the source\'s permissions the editor holds, names the ones left out, and records the source', () => {
    const source = set({ id: 'builtin:red-team-operator', builtin: true, name: 'Red-team operator', description: 'Full use',
      permissions: ['graph:read', 'agent:kali_exec', 'reports:read'] })
    const { draft, leftOut } = cloneStart(source, new Set<PermissionId>(['graph:read', 'reports:read']))
    expect(draft).toEqual({ name: 'Copy of Red-team operator', description: 'Full use', permissions: ['graph:read', 'reports:read'] })
    expect(leftOut).toEqual(['agent:kali_exec'])
    expect(createBody(draft, source.id)).toEqual({
      name: 'Copy of Red-team operator', description: 'Full use', permissions: ['graph:read', 'reports:read'],
      cloneFrom: 'builtin:red-team-operator',
    })
  })

  test('a long name is cut to the server\'s limit', () => {
    const { draft } = cloneStart(set({ name: 'x'.repeat(MAX_NAME) }), new Set())
    expect(draft.name.length).toBe(MAX_NAME)
  })
})

describe('the body a save sends', () => {
  test('a new set: trimmed name, empty description as null, no cloneFrom', () => {
    expect(createBody({ name: '  Lab  ', description: '  ', permissions: ['reports:read'] })).toEqual({
      name: 'Lab', description: null, permissions: ['reports:read'],
    })
  })

  test('an edit sends only what changed; nothing changed is null', () => {
    const s = set({ description: 'Read the lab' })
    expect(editBody(s, { name: 'Lab readers', description: 'Read the lab', permissions: ['reports:read', 'graph:read'] })).toBeNull()
    expect(editBody(s, { name: ' Lab analysts ', description: 'Read the lab', permissions: ['graph:read', 'reports:read'] }))
      .toEqual({ name: 'Lab analysts' })
    expect(editBody(s, { name: 'Lab readers', description: '', permissions: ['graph:read'] }))
      .toEqual({ description: null, permissions: ['graph:read'] })
  })
})

describe('when the server takes a password', () => {
  test('every admin profile write is the confirmed Root\'s, with Root\'s password', () => {
    expect(passwordNeeded('admin', 'create', [])).toBe('root')
    expect(passwordNeeded('admin', 'edit', [])).toBe('root')
  })

  test('a member set: a new one holds nobody (none asked); an edit adding a dangerous permission asks', () => {
    expect(passwordNeeded('member', 'create', ['agent:kali_exec'])).toBeNull()
    expect(passwordNeeded('member', 'edit', ['reports:read'])).toBeNull()
    expect(passwordNeeded('member', 'edit', ['reports:read', 'agent:kali_exec', 'agent:approve_dangerous']))
      .toEqual(inRegistryOrder(['agent:approve_dangerous', 'agent:kali_exec']))
  })
})

describe('the default set for new members', () => {
  test('the stored default, else the built-in Default member', () => {
    expect(defaultSetId({ instanceDefaultSetId: 'set-1' })).toBe('set-1')
    expect(defaultSetId({ instanceDefaultSetId: null })).toBe('builtin:default-member')
    expect(defaultSetId({})).toBe('builtin:default-member')
  })
})
