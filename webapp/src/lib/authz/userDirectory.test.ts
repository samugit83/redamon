/**
 * The admin users directory's pure parts (step 6.2; GV-01): the query it takes, the accounts each
 * filter selects (the `set` filter as listSets counts holders, which step 6.3 relies on), the cursor,
 * and which actions a row offers: exactly what hierarchy.ts `canManage` allows the signed-in person
 * on that account, in a status where the action exists.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/authz/userDirectory.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi } from 'vitest'

vi.mock('@/lib/prisma', () => ({ default: {}, prisma: {} }))

import {
  DEFAULT_PAGE_SIZE, decodeCursor, directoryWhere, encodeCursor, parseDirectoryQuery, rowActions,
  type DirectoryFilters,
} from './userDirectory'
import { BUILTIN_ADMIN_PROFILES, BUILTIN_MEMBER_SETS } from './builtinSets'
import type { Managed, Manager, ManageAction } from './hierarchy'
import { PERMISSION_IDS, type PermissionId } from './permissions'

const NONE: DirectoryFilters = { q: null, status: null, type: null, set: null, cursor: null, limit: DEFAULT_PAGE_SIZE }
const parse = (qs: string) => parseDirectoryQuery(new URLSearchParams(qs))

describe('the query', () => {
  test('nothing given: every account, 50 a page', () => {
    expect(parse('')).toEqual(NONE)
  })

  test('each filter is read, trimmed, and empty values count as absent', () => {
    expect(parse('q=%20ada%20&status=disabled&type=admin&set=builtin:user-manager&limit=10')).toEqual({
      ...NONE, q: 'ada', status: 'disabled', type: 'admin', set: 'builtin:user-manager', limit: 10,
    })
    expect(parse('q=&status=&type=&set=&cursor=')).toEqual(NONE)
  })

  test.each([
    ['status=gone', 'status'],
    ['type=owner', 'type'],
    ['limit=0', 'limit'],
    ['limit=101', 'limit'],
    ['limit=2.5', 'limit'],
    ['limit=ten', 'limit'],
    [`q=${'a'.repeat(201)}`, 'q'],
    [`set=${'s'.repeat(201)}`, 'set'],
    ['cursor=not-a-cursor', 'cursor'],
  ])('%s answers invalid_filter naming %s', (qs, field) => {
    expect(parse(qs)).toMatchObject({ code: 'invalid_filter', field })
  })

  test('a cursor round-trips, and only one this directory gave is taken', () => {
    const c = { createdAt: new Date('2026-11-13T10:00:00.000Z'), id: 'cuid-1' }
    expect(decodeCursor(encodeCursor(c))).toEqual(c)
    expect(parse(`cursor=${encodeCursor(c)}`)).toEqual({ ...NONE, cursor: c })
    expect(decodeCursor(Buffer.from('nonsense|x').toString('base64url'))).toBeNull()
    expect(decodeCursor(Buffer.from('2026-11-13T10:00:00.000Z|').toString('base64url'))).toBeNull()
  })
})

describe('filters and the accounts they select', () => {
  const ctx = { rootId: 'root-1', setKind: 'member' as const }

  test('no filter: no condition', () => {
    expect(directoryWhere(NONE, ctx)).toEqual({})
  })

  test('the search looks in the name and the email, ignoring case', () => {
    expect(directoryWhere({ ...NONE, q: 'Ada' }, ctx)).toEqual({ AND: [{ OR: [
      { name: { contains: 'Ada', mode: 'insensitive' } },
      { email: { contains: 'Ada', mode: 'insensitive' } },
    ] }] })
  })

  test('type: Root is the instance Root, an admin any other admin, a member any non-admin', () => {
    expect(directoryWhere({ ...NONE, type: 'root' }, ctx)).toEqual({ AND: [{ id: { in: ['root-1'] } }] })
    expect(directoryWhere({ ...NONE, type: 'root' }, { ...ctx, rootId: null })).toEqual({ AND: [{ id: { in: [] } }] })
    expect(directoryWhere({ ...NONE, type: 'admin' }, ctx)).toEqual({ AND: [{ role: 'admin', id: { not: 'root-1' } }] })
    expect(directoryWhere({ ...NONE, type: 'admin' }, { ...ctx, rootId: null })).toEqual({ AND: [{ role: 'admin' }] })
    expect(directoryWhere({ ...NONE, type: 'member' }, ctx)).toEqual({ AND: [{ role: { not: 'admin' } }] })
  })

  test('set: a member set by its assignment rows, as listSets counts its holders', () => {
    expect(directoryWhere({ ...NONE, set: 'set-1' }, ctx)).toEqual({ AND: [{ permissionSets: { some: { setId: 'set-1' } } }] })
  })

  test('set: an admin profile by the admins naming it; Full admin also has the admins with none recorded', () => {
    const admin = { ...ctx, setKind: 'admin' as const }
    expect(directoryWhere({ ...NONE, set: 'prof-1' }, admin)).toEqual({ AND: [{ role: 'admin', adminProfileId: 'prof-1' }] })
    expect(directoryWhere({ ...NONE, set: 'builtin:full-admin' }, admin)).toEqual({ AND: [{
      role: 'admin', OR: [{ adminProfileId: 'builtin:full-admin' }, { adminProfileId: null }],
    }] })
  })

  test('filters combine: every one must hold', () => {
    expect(directoryWhere({ ...NONE, q: 'x', status: 'active', type: 'member', set: 'builtin:recon-operator' }, ctx)).toEqual({ AND: [
      { OR: [{ name: { contains: 'x', mode: 'insensitive' } }, { email: { contains: 'x', mode: 'insensitive' } }] },
      { status: 'active' },
      { role: { not: 'admin' } },
      { permissionSets: { some: { setId: 'builtin:recon-operator' } } },
    ] })
  })
})

describe('row actions follow the hierarchy', () => {
  const MEMBER_SIDE = BUILTIN_MEMBER_SETS.find((s) => s.id === 'builtin:default-member')!.permissions
  const profile = (slug: string) => BUILTIN_ADMIN_PROFILES.find((s) => s.id === `builtin:${slug}`)!.permissions
  const admin = (id: string, slug: string): Manager => ({ id, accountType: 'admin', held: [...profile(slug), ...MEMBER_SIDE] })
  const confirmedRoot: Manager = { id: 'root-1', accountType: 'root', held: [...PERMISSION_IDS] }
  // An unconfirmed Root holds none of the Root-only permissions, admins:manage among them.
  const unconfirmedRoot: Manager = { id: 'root-1', accountType: 'root', held: [...profile('full-admin'), ...MEMBER_SIDE] }
  const member: Managed = { id: 'm-1', accountType: 'member', profile: [] }
  const adminTarget = (perms: readonly PermissionId[]): Managed => ({ id: 'a-2', accountType: 'admin', profile: [...perms] })
  const rootTarget: Managed = { id: 'root-1', accountType: 'root', profile: [] }
  const ALL_ACTIVE: ManageAction[] = ['edit', 'assign_permissions', 'disable', 'reset_credentials', 'revoke_sessions', 'impersonate', 'delete']

  test('a User manager on an active member: everything but acting as them and deleting them', () => {
    expect(rowActions(admin('a-1', 'user-manager'), member, 'active')).toEqual(
      ['edit', 'assign_permissions', 'disable', 'reset_credentials', 'revoke_sessions'])
  })

  test('a Full admin on an active member: every action, acting as them included', () => {
    expect(rowActions(admin('a-1', 'full-admin'), member, 'active')).toEqual(ALL_ACTIVE)
  })

  test('a Security auditor (users:read only) is offered nothing', () => {
    expect(rowActions(admin('a-1', 'security-auditor'), member, 'active')).toEqual([])
  })

  test('another admin: nothing for an admin without admins:manage, everything for the confirmed Root', () => {
    expect(rowActions(admin('a-1', 'full-admin'), adminTarget(profile('user-manager')), 'active')).toEqual([])
    expect(rowActions(confirmedRoot, adminTarget(profile('full-admin')), 'active')).toEqual(ALL_ACTIVE)
    expect(rowActions(unconfirmedRoot, adminTarget(profile('user-manager')), 'active')).toEqual([])
    expect(rowActions(unconfirmedRoot, member, 'active')).toEqual(ALL_ACTIVE)
  })

  test('admins:manage reaches only an admin whose profile sits strictly inside its own, and never resets, acts as or re-invites one', () => {
    const manager: Manager = { id: 'a-1', accountType: 'admin', held: [...profile('full-admin'), 'admins:manage', ...MEMBER_SIDE] }
    expect(rowActions(manager, adminTarget(profile('user-manager')), 'active')).toEqual(
      ['edit', 'assign_permissions', 'disable', 'revoke_sessions', 'delete'])
    expect(rowActions(manager, adminTarget([...profile('full-admin'), 'admins:manage']), 'active')).toEqual([])
    expect(rowActions(manager, adminTarget(profile('user-manager')), 'invited')).toEqual(['edit', 'assign_permissions', 'delete'])
  })

  test('nothing on Root, nothing on the own account', () => {
    expect(rowActions(confirmedRoot, rootTarget, 'active')).toEqual([])
    expect(rowActions(admin('a-1', 'full-admin'), rootTarget, 'active')).toEqual([])
    expect(rowActions(admin('m-1', 'full-admin'), member, 'active')).toEqual([])
  })

  test('the status decides which exist: invited resends or cancels, disabled enables, nobody acts as a disabled account', () => {
    const full = admin('a-1', 'full-admin')
    expect(rowActions(full, member, 'invited')).toEqual(['create', 'edit', 'assign_permissions', 'delete'])
    expect(rowActions(full, member, 'disabled')).toEqual(['edit', 'assign_permissions', 'enable', 'reset_credentials', 'delete'])
  })
})
