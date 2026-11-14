/**
 * The user menu's Change Password opens the own-password dialog for everyone it is offered to
 * (the S5 red P6-01): the menu and the Users page follow one rule, `opensOwnPasswordDialog`. An
 * account holding the directory (users:read) without the switcher (users:impersonate), the User
 * manager set, got the item, and the page opened nothing for it. With every switch off the menu is
 * Phase 1's: an admin's switcher offers no Change Password, a member's item opens the dialog (DV-30).
 *
 * Each case renders the menu, follows the item to the address it pushes, and renders the page there.
 *
 * Run: npx vitest run --no-file-parallelism src/components/layout/GlobalHeader/UserSelector/UserSelector.changePassword.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent } from '@testing-library/react'

// The page's effects depend on the router, the search params and the user: one object each, as in the app.
const h = vi.hoisted(() => ({
  granted: new Set<string>(),
  flags: null as { permissions?: boolean } | null,
  search: new URLSearchParams(''),
  push: vi.fn(),
  router: { push: vi.fn(), replace: vi.fn() },
  user: { id: 'me', name: 'Me Myself', email: 'me@e2e.local', role: 'admin' },
}))

vi.mock('next/navigation', () => ({ useRouter: () => h.router, useSearchParams: () => h.search }))
vi.mock('@/providers/ProjectProvider', () => ({
  useProject: () => ({ userId: 'me', setUserId: vi.fn(), setCurrentProject: vi.fn(), userSwitchError: null }),
}))
vi.mock('@/providers/AuthProvider', () => ({
  useAuth: () => ({ user: h.user, isLoading: false, logout: vi.fn(), sessionError: null }),
}))
vi.mock('@/hooks/useCan', () => ({ useCan: (p: string) => h.granted.has(p), useRbacFlags: () => h.flags }))
vi.mock('@/hooks/useUsers', () => ({
  useUsers: () => ({
    data: [
      { id: 'me', name: 'Me Myself', email: 'me@e2e.local', role: 'admin', status: 'active', hasPassword: true, _count: { projects: 0 } },
      { id: 'm1', name: 'Marco', email: 'marco@e2e.local', role: 'standard', status: 'active', hasPassword: true, _count: { projects: 1 } },
    ],
    isLoading: false, error: null,
  }),
  useCreateUser: () => ({ mutateAsync: vi.fn() }),
  useDeleteUser: () => ({ mutateAsync: vi.fn() }),
  useChangePassword: () => ({ mutateAsync: vi.fn(), isPending: false }),
}))
vi.mock('@/hooks/usePasswordPolicy', () => ({ usePasswordPolicy: () => null }))
vi.mock('@/context/NavigationGuardContext', () => ({ useGuardedRouter: () => ({ push: h.push }), useNavigationGuard: () => null }))
vi.mock('@/hooks/useErrorToast', () => ({ useErrorToast: () => {} }))
vi.mock('@/components/admin/LegacyAccessCard', () => ({ LegacyAccessCard: () => null }))
vi.mock('@/components/admin/WhatChangedCard', () => ({ WhatChangedCard: () => null }))

import { UserSelector } from './UserSelector'
import UsersPage from '@/app/settings/users/page'
import { opensOwnPasswordDialog } from '@/components/auth/ownPasswordDialog'

const ADMIN = ['users:read', 'users:impersonate', 'users:create', 'users:delete']
const USER_MANAGER = ['users:read']

beforeEach(() => {
  h.granted = new Set()
  h.flags = null
  h.search = new URLSearchParams('')
  h.push.mockReset()
  h.router.push.mockReset()
  h.router.replace.mockReset()
})
afterEach(() => cleanup())

/** Opens the menu; the address Change Password pushes, or null when the menu does not offer it. */
function changePasswordAddress(): string | null {
  render(<UserSelector />)
  fireEvent.click(screen.getByTitle('User Menu'))
  const item = screen.queryByRole('button', { name: /Change Password/ })
  if (!item) {
    cleanup()
    return null
  }
  fireEvent.click(item)
  cleanup()
  expect(h.push).toHaveBeenCalledTimes(1)
  return h.push.mock.calls[0][0] as string
}

function pageAt(address: string) {
  const url = new URL(address, 'http://redamon.test')
  expect(url.pathname).toBe('/settings/users')
  h.search = url.searchParams
  render(<UsersPage />)
}

const ownPasswordDialog = () => screen.queryByRole('dialog', { name: 'Change Password' })

describe('Change Password from the user menu', () => {
  test('the directory without the switcher (User manager), permissions on: the item opens the dialog', () => {
    h.flags = { permissions: true }
    h.granted = new Set(USER_MANAGER)
    const address = changePasswordAddress()
    expect(address).toBe('/settings/users?changePassword=true')
    pageAt(address!)
    expect(ownPasswordDialog()).toBeInTheDocument()
    expect(screen.getByLabelText('Current Password')).toBeInTheDocument()
  })

  test('a member, permissions on: the item opens the dialog', () => {
    h.flags = { permissions: true }
    pageAt(changePasswordAddress()!)
    expect(ownPasswordDialog()).toBeInTheDocument()
  })

  test('every switch off, a member: the item opens the dialog, as in Phase 1', () => {
    pageAt(changePasswordAddress()!)
    expect(ownPasswordDialog()).toBeInTheDocument()
  })

  test('every switch off, an admin: the switcher, no Change Password, as in Phase 1 (DV-30)', () => {
    h.granted = new Set(ADMIN)
    expect(changePasswordAddress()).toBeNull()
  })

  test.each([
    ['switches off', null],
    ['permissions on', { permissions: true }],
  ])('one rule (%s): the menu offers the item only to whom the page opens the dialog', (_name, flags) => {
    for (const granted of [[], USER_MANAGER, ['users:impersonate'], ADMIN]) {
      h.flags = flags
      h.granted = new Set(granted)
      h.push.mockReset()
      const offered = changePasswordAddress() !== null
      const opens = opensOwnPasswordDialog({
        readUsers: h.granted.has('users:read'),
        switchUser: h.granted.has('users:impersonate'),
        permissionsOn: flags?.permissions === true,
      })
      if (offered) expect(opens).toBe(true)
    }
  })
})
