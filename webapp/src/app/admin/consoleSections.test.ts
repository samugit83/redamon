/**
 * The admin console's sections and what opens each (step 6.1, UI-10, OQ-44): the left navigation,
 * the header's "Admin" link and the denied state all read this one list.
 *
 * Run: npx vitest run --no-file-parallelism src/app/admin/consoleSections.test.ts
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { PERMISSION_IDS, PERMISSIONS, type PermissionId } from '@/lib/authz/permissions'
import { BUILTIN_ADMIN_PROFILES } from '@/lib/authz/builtinSets'
import {
  CONSOLE_PERMISSIONS, CONSOLE_SECTIONS, holdsConsolePermission, openSections, sectionAccess, sectionForPath,
  type AllSharesView,
} from './consoleSections'

const holding = (...ids: PermissionId[]) => (p: PermissionId) => ids.includes(p)
const profile = (slug: string) => BUILTIN_ADMIN_PROFILES.find((s) => s.id === `builtin:${slug}`)!.permissions
const labels = (held: readonly PermissionId[], shares: AllSharesView = 'no') =>
  openSections(holding(...held), shares).map((s) => s.label)

describe('the sections', () => {
  test('eight sections in the order of the feature document, each under /admin', () => {
    expect(CONSOLE_SECTIONS.map((s) => [s.label, s.href])).toEqual([
      ['Users', '/admin/users'],
      ['Permission sets', '/admin/permission-sets'],
      ['Admin profiles', '/admin/admin-profiles'],
      ['Projects', '/admin/projects'],
      ['Shares', '/admin/shares'],
      ['Operations', '/admin/operations'],
      ['Audit', '/admin/audit'],
      ['Instance', '/admin/instance'],
    ])
    for (const s of CONSOLE_SECTIONS) expect(s.description).toMatch(/\.$/)
  })

  test('every permission named is in the registry; Instance opens with instance:settings, instance:quotas or any platform:*', () => {
    for (const s of CONSOLE_SECTIONS) for (const p of s.anyOf) expect(PERMISSION_IDS).toContain(p)
    const instance = CONSOLE_SECTIONS.find((s) => s.id === 'instance')!
    const platform = PERMISSION_IDS.filter((p) => p.startsWith('platform:'))
    expect(platform.length).toBeGreaterThan(0)
    expect([...instance.anyOf].sort()).toEqual(['instance:quotas', 'instance:settings', ...platform].sort())
  })

  test('the console permissions are the union of the sections, each once', () => {
    const union = new Set(CONSOLE_SECTIONS.flatMap((s) => s.anyOf))
    expect([...CONSOLE_PERMISSIONS].sort()).toEqual([...union].sort())
    expect(new Set(CONSOLE_PERMISSIONS).size).toBe(CONSOLE_PERMISSIONS.length)
    // Members' own permissions open nothing here.
    for (const p of CONSOLE_PERMISSIONS) expect(PERMISSIONS[p].kind).toBe('admin')
  })
})

describe('nav shows only permitted sections', () => {
  test('a member holding no admin permission: no section, no console permission', () => {
    expect(labels(['recon:scan', 'agent:chat', 'self:mcp_tokens'])).toEqual([])
    expect(holdsConsolePermission(holding('recon:scan', 'agent:chat'))).toBe(false)
  })

  test('User manager: Users only (no Shares without the policy)', () => {
    expect(labels(profile('user-manager'))).toEqual(['Users'])
    expect(holdsConsolePermission(holding(...profile('user-manager')))).toBe(true)
  })

  test('Security auditor: Users, Projects, Audit', () => {
    expect(labels(profile('security-auditor'))).toEqual(['Users', 'Projects', 'Audit'])
  })

  test('Platform operator: Operations and Instance', () => {
    expect(labels(profile('platform-operator'))).toEqual(['Operations', 'Instance'])
  })

  test("Full admin: everything but Root's Admin profiles; Instance through instance:quotas and platform:*", () => {
    expect(labels(profile('full-admin'))).toEqual(['Users', 'Permission sets', 'Projects', 'Operations', 'Audit', 'Instance'])
  })

  test('the confirmed Root (every permission) with the policy letting admins see all shares: all eight', () => {
    expect(labels(PERMISSION_IDS, 'yes')).toEqual(CONSOLE_SECTIONS.map((s) => s.label))
  })

  test('one permission opens its one section', () => {
    expect(labels(['roles:manage'])).toEqual(['Permission sets'])
    expect(labels(['admin_profiles:manage'])).toEqual(['Admin profiles'])
    expect(labels(['audit:read'])).toEqual(['Audit'])
    expect(labels(['instance:quotas'])).toEqual(['Instance'])
    expect(labels(['platform:tunnels'])).toEqual(['Instance'])
    expect(labels(['platform:operations'])).toEqual(['Operations', 'Instance'])
  })
})

describe('Shares needs users:read and the policy that lets admins see every share', () => {
  const shares = CONSOLE_SECTIONS.find((s) => s.id === 'shares')!

  test('users:read with the policy: open', () => {
    expect(sectionAccess(shares, holding('users:read'), 'yes')).toEqual({ state: 'open' })
    expect(labels(['users:read'], 'yes')).toEqual(['Users', 'Shares'])
  })

  test('users:read, policy off or sharing not in force: refused by the policy, not by a permission', () => {
    expect(sectionAccess(shares, holding('users:read'), 'no')).toEqual({ state: 'policy' })
  })

  test('users:read, the policy still being read: pending (hidden from the nav)', () => {
    expect(sectionAccess(shares, holding('users:read'), 'pending')).toEqual({ state: 'pending' })
    expect(labels(['users:read'], 'pending')).toEqual(['Users'])
  })

  test('without users:read the permission is missing, whatever the policy', () => {
    expect(sectionAccess(shares, holding('audit:read'), 'yes')).toEqual({ state: 'denied', missing: ['users:read'] })
  })
})

describe('denied names what is missing', () => {
  test('one permission', () => {
    const audit = CONSOLE_SECTIONS.find((s) => s.id === 'audit')!
    expect(sectionAccess(audit, holding('users:read'), 'no')).toEqual({ state: 'denied', missing: ['audit:read'] })
  })

  test('Instance names every permission that would open it', () => {
    const instance = CONSOLE_SECTIONS.find((s) => s.id === 'instance')!
    const access = sectionAccess(instance, holding('users:read'), 'no')
    expect(access).toEqual({ state: 'denied', missing: instance.anyOf })
  })
})

describe('sectionForPath', () => {
  test.each([
    ['/admin/users', 'users'],
    ['/admin/users/u1', 'users'],
    ['/admin/permission-sets/builtin:recon-operator', 'permission-sets'],
    ['/admin/admin-profiles', 'admin-profiles'],
    ['/admin/projects', 'projects'],
    ['/admin/shares', 'shares'],
    ['/admin/operations', 'operations'],
    ['/admin/audit', 'audit'],
    ['/admin/instance', 'instance'],
  ])('%s is the %s section', (path, id) => {
    expect(sectionForPath(path)?.id).toBe(id)
  })

  test.each(['/admin', '/admin/', '/admin/unknown', '/admin/usersx', '/settings/users', '/'])('%s is no section', (path) => {
    expect(sectionForPath(path)).toBeNull()
  })
})
