/**
 * Settings > Users with the permissions switch on (step 3.13; PE-15, ID-28, UI-12): each account
 * the signed-in person may assign gets "Permissions", which opens its panel (sets, overrides, an
 * admin's profile, effective permissions); a member's needs users:assign_permissions, an admin's
 * admins:manage; never one's own row or Root's. The create dialog chooses the set a new member
 * starts with. With the switch off none of it shows.
 *
 * Run: npx vitest run --no-file-parallelism src/app/settings/users/page.userPermissions.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor, within } from '@testing-library/react'
import { AlertProvider } from '@/components/ui'
import { json, memberSetList, viewOf } from '@/components/admin/__testing__/permissionViews'

const h = vi.hoisted(() => ({
  granted: new Set<string>(),
  flags: { permissions: true } as { permissions: boolean } | null,
  create: vi.fn(),
  refetch: vi.fn(),
  fetch: vi.fn(),
}))

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  useSearchParams: () => new URLSearchParams(''),
}))
vi.mock('@/hooks/useCan', () => ({ useCan: (p: string) => h.granted.has(p), useRbacFlags: () => h.flags }))
vi.mock('@/providers/AuthProvider', () => ({
  useAuth: () => ({
    user: {
      id: 'admin-1', name: 'Ada', email: 'ada@e2e.local', role: 'admin', accountType: 'admin',
      rbac: { compat: false, legacyGrantsPending: 0, identity: true, root: { email: 'root@e2e.local', confirmed: true } },
    },
    isLoading: false,
  }),
}))
vi.mock('@/hooks/useUsers', () => ({
  useUsers: () => ({ data: ROWS, isLoading: false, error: null, refetch: h.refetch }),
  useCreateUser: () => ({ mutateAsync: h.create, isPending: false }),
  useDeleteUser: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useChangePassword: () => ({ mutateAsync: vi.fn(), isPending: false }),
}))
vi.mock('@/components/admin/LegacyAccessCard', () => ({ LegacyAccessCard: () => null }))
vi.mock('@/components/admin/WhatChangedCard', () => ({ WhatChangedCard: () => null }))

import UsersPage from './page'

const row = (id: string, name: string, role: string, email = `${id}@e2e.local`) =>
  ({ id, name, email, role, status: 'active', hasPassword: true, createdAt: '', updatedAt: '', _count: { projects: 0 } })
const ROWS = [
  row('admin-1', 'Ada', 'admin', 'ada@e2e.local'),
  row('root-1', 'Rhea', 'admin', 'root@e2e.local'),
  row('admin-2', 'Bruno', 'admin'),
  row('member-1', 'Marco', 'standard'),
]
const ME = viewOf({
  userId: 'admin-1', accountType: 'admin',
  sets: [{ id: 'builtin:full-admin', via: 'default' }, { id: 'builtin:default-member', via: 'default' }],
})

beforeEach(() => {
  h.granted = new Set(['users:read', 'users:create', 'users:assign_permissions'])
  h.flags = { permissions: true }
  h.create.mockReset().mockResolvedValue({ id: 'user-9' })
  h.refetch.mockReset()
  h.fetch.mockReset().mockImplementation(async (url: string) => {
    if (url === '/api/admin/permission-sets') return json(memberSetList())
    if (url === '/api/users/admin-1/permissions') return json(ME)
    if (url === '/api/users/member-1/permissions') return json(viewOf({ userId: 'member-1', sets: [{ id: 'builtin:read-only-analyst' }] }))
    if (url === '/api/auth/password-policy') return json({ error: 'Not found' }, 404)
    throw new Error(`unexpected fetch ${url}`)
  })
  vi.stubGlobal('fetch', h.fetch)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

const renderPage = () => render(<AlertProvider><UsersPage /></AlertProvider>)
const permissionsButtons = () => screen.queryAllByRole('button', { name: /^Permissions of / }).map((b) => b.getAttribute('aria-label'))

describe('Permissions on the Users page', () => {
  test('a member\'s row with users:assign_permissions; never one\'s own, Root\'s, or an admin\'s without admins:manage', () => {
    renderPage()
    expect(permissionsButtons()).toEqual(['Permissions of Marco'])
  })

  test('admins:manage adds the other admins, still not Root', () => {
    h.granted.add('admins:manage')
    renderPage()
    expect(permissionsButtons()).toEqual(['Permissions of Bruno', 'Permissions of Marco'])
  })

  test('the switch off, or no permission to assign: no button', () => {
    h.flags = { permissions: false }
    renderPage()
    expect(permissionsButtons()).toEqual([])
    cleanup()
    h.flags = { permissions: true }
    h.granted = new Set(['users:read'])
    renderPage()
    expect(permissionsButtons()).toEqual([])
  })

  test('Permissions opens the account\'s panel', async () => {
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: 'Permissions of Marco' }))
    const dialog = await screen.findByRole('dialog', { name: 'Permissions - Marco' })
    const sets = await within(dialog).findByRole('group', { name: 'Member permission sets' })
    expect((within(sets).getByRole('checkbox', { name: /^Read-only analyst/ }) as HTMLInputElement).checked).toBe(true)
    expect(h.fetch.mock.calls.map((c) => c[0])).toEqual(expect.arrayContaining(['/api/users/member-1/permissions', '/api/users/admin-1/permissions']))
  })
})

describe('the create dialog chooses the set (ID-28)', () => {
  test('a new member with the chosen set; an admin gets no picker', async () => {
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: 'Create with a temporary password' }))
    const dialog = screen.getByRole('dialog', { name: 'Create User' })
    fireEvent.change(within(dialog).getByLabelText('Name *'), { target: { value: 'Nina' } })
    fireEvent.change(within(dialog).getByLabelText('Email *'), { target: { value: 'nina@e2e.local' } })
    fireEvent.change(await within(dialog).findByRole('combobox', { name: 'Permission set' }), { target: { value: 'builtin:recon-operator' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Create User' }))
    await waitFor(() => expect(h.create).toHaveBeenCalled())
    expect(h.create.mock.calls[0][0]).toMatchObject({ name: 'Nina', email: 'nina@e2e.local', role: 'standard', sets: ['builtin:recon-operator'] })
  })

  test('no set chosen sends none; the switch off shows no picker', async () => {
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: 'Create with a temporary password' }))
    const dialog = screen.getByRole('dialog', { name: 'Create User' })
    await within(dialog).findByRole('combobox', { name: 'Permission set' })
    fireEvent.change(within(dialog).getByLabelText('Name *'), { target: { value: 'Nina' } })
    fireEvent.change(within(dialog).getByLabelText('Email *'), { target: { value: 'nina@e2e.local' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Create User' }))
    await waitFor(() => expect(h.create).toHaveBeenCalled())
    expect(h.create.mock.calls[0][0]).not.toHaveProperty('sets')
    cleanup()
    h.flags = { permissions: false }
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: 'Create with a temporary password' }))
    expect(within(screen.getByRole('dialog', { name: 'Create User' })).queryByRole('combobox', { name: 'Permission set' })).toBeNull()
  })
})
