/**
 * Settings > Users and `?changePassword=true` (the user menu's Change Password, or the typed
 * address): the page opens the own-password dialog by `opensOwnPasswordDialog`, the rule the menu
 * follows too (the S5 red P6-01). With the permissions switch on it opens for everyone, over the
 * directory for a users:read holder (the User manager set, an admin typing the address); with every
 * switch off it is Phase 1's: a member gets it, an admin's typed address opens nothing (DV-30).
 *
 * Run: npx vitest run --no-file-parallelism src/app/settings/users/page.changeOwnPassword.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'

// The page's effects depend on the router, the search params and the user: one object each, as in the app.
const h = vi.hoisted(() => ({
  granted: new Set<string>(),
  flags: null as { permissions?: boolean } | null,
  search: new URLSearchParams('changePassword=true'),
  router: { push: vi.fn(), replace: vi.fn() },
  user: { id: 'me-1', name: 'Ada', email: 'ada@e2e.local', role: 'admin' },
  changePassword: vi.fn(),
}))

vi.mock('next/navigation', () => ({ useRouter: () => h.router, useSearchParams: () => h.search }))
vi.mock('@/hooks/useCan', () => ({ useCan: (p: string) => h.granted.has(p), useRbacFlags: () => h.flags }))
vi.mock('@/providers/AuthProvider', () => ({ useAuth: () => ({ user: h.user, isLoading: false }) }))
vi.mock('@/hooks/useUsers', () => ({
  useUsers: () => ({
    data: [
      { id: 'me-1', name: 'Ada', email: 'ada@e2e.local', role: 'admin', status: 'active', hasPassword: true, _count: { projects: 0 } },
      { id: 'member-1', name: 'Marco', email: 'marco@e2e.local', role: 'standard', status: 'active', hasPassword: true, _count: { projects: 1 } },
    ],
    isLoading: false, error: null,
  }),
  useCreateUser: () => ({ mutateAsync: vi.fn() }),
  useDeleteUser: () => ({ mutateAsync: vi.fn() }),
  useChangePassword: () => ({ mutateAsync: h.changePassword, isPending: false }),
}))
vi.mock('@/hooks/usePasswordPolicy', () => ({ usePasswordPolicy: () => null }))
vi.mock('@/components/admin/LegacyAccessCard', () => ({ LegacyAccessCard: () => null }))
vi.mock('@/components/admin/WhatChangedCard', () => ({ WhatChangedCard: () => null }))

import UsersPage from './page'

const ADMIN = ['users:read', 'users:impersonate', 'users:create', 'users:delete']
const USER_MANAGER = ['users:read']
const NEW_PASSWORD = 'a-long-enough-new-password'

beforeEach(() => {
  h.granted = new Set()
  h.flags = null
  h.search = new URLSearchParams('changePassword=true')
  h.router.push.mockReset()
  h.router.replace.mockReset()
  h.changePassword.mockReset().mockResolvedValue(undefined)
})
afterEach(() => cleanup())

const ownPasswordDialog = () => screen.queryByRole('dialog', { name: 'Change Password' })
const type = (label: string, value: string) => fireEvent.change(screen.getByLabelText(label), { target: { value } })

describe('permissions switch on: the dialog opens for everyone who asks', () => {
  beforeEach(() => { h.flags = { permissions: true } })

  test('the directory without the switcher (User manager): the dialog over the directory', async () => {
    h.granted = new Set(USER_MANAGER)
    render(<UsersPage />)
    expect(ownPasswordDialog()).toBeInTheDocument()
    expect(screen.getByText('marco@e2e.local')).toBeInTheDocument()
    await waitFor(() => expect(h.router.replace).toHaveBeenCalledWith('/settings/users', { scroll: false }))
  })

  test('it changes the person\'s own password, with the current one', async () => {
    h.granted = new Set(USER_MANAGER)
    render(<UsersPage />)
    type('Current Password', 'the-current-password')
    type('New Password', NEW_PASSWORD)
    type('Confirm New Password', NEW_PASSWORD)
    fireEvent.click(screen.getAllByRole('button', { name: 'Change Password' }).at(-1)!)
    await waitFor(() => expect(h.changePassword).toHaveBeenCalledWith({
      userId: 'me-1', data: { newPassword: NEW_PASSWORD, currentPassword: 'the-current-password' },
    }))
    expect(await screen.findByText('Password updated successfully')).toBeInTheDocument()
  })

  test('an admin who types the address (adm-a, the switcher too): the dialog', () => {
    h.granted = new Set(ADMIN)
    render(<UsersPage />)
    expect(ownPasswordDialog()).toBeInTheDocument()
  })

  test('closing it leaves a directory holder on the directory', () => {
    h.granted = new Set(USER_MANAGER)
    render(<UsersPage />)
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(ownPasswordDialog()).toBeNull()
    expect(screen.getByText('marco@e2e.local')).toBeInTheDocument()
    expect(h.router.push).not.toHaveBeenCalledWith('/graph')
  })

  test('no address, a directory holder: no dialog', () => {
    h.search = new URLSearchParams('')
    h.granted = new Set(USER_MANAGER)
    render(<UsersPage />)
    expect(ownPasswordDialog()).toBeNull()
  })

  test('a member: the dialog alone, as before', () => {
    render(<UsersPage />)
    expect(ownPasswordDialog()).toBeInTheDocument()
    expect(screen.queryByText('marco@e2e.local')).toBeNull()
  })
})

describe('every switch off: Phase 1 (DV-30)', () => {
  test('an admin\'s typed address opens nothing: the directory, the query stripped as before', async () => {
    h.granted = new Set(ADMIN)
    render(<UsersPage />)
    expect(screen.getByText('marco@e2e.local')).toBeInTheDocument()
    expect(ownPasswordDialog()).toBeNull()
    await waitFor(() => expect(h.router.replace).toHaveBeenCalledWith('/settings/users', { scroll: false }))
  })

  test('a member: the dialog', () => {
    render(<UsersPage />)
    expect(ownPasswordDialog()).toBeInTheDocument()
  })
})
