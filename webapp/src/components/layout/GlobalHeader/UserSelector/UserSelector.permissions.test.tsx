/**
 * The user menu follows the permissions (step 3.12, UI-01): the user switcher is
 * users:impersonate's (the act-as route asks it), Manage Users is users:read's. An admin whose
 * profile lacks one does not see it; a member sees neither, as before.
 *
 * Run: npx vitest run --no-file-parallelism src/components/layout/GlobalHeader/UserSelector/UserSelector.permissions.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent } from '@testing-library/react'

const h = vi.hoisted(() => ({ granted: new Set<string>(), push: vi.fn() }))
vi.mock('@/providers/ProjectProvider', () => ({
  useProject: () => ({ userId: 'me', setUserId: vi.fn(), setCurrentProject: vi.fn(), userSwitchError: null }),
}))
vi.mock('@/providers/AuthProvider', () => ({
  useAuth: () => ({ user: { id: 'me', name: 'Me Myself', email: 'me@e2e.local', role: 'admin' }, logout: vi.fn(), sessionError: null }),
}))
vi.mock('@/hooks/useCan', () => ({ useCan: (p: string) => h.granted.has(p), useRbacFlags: () => null }))
vi.mock('@/hooks/useUsers', () => ({
  useUsers: () => ({ data: [{ id: 'me', name: 'Me Myself', email: 'me@e2e.local', role: 'admin' }, { id: 'm1', name: 'Marco', email: 'marco@e2e.local', role: 'standard' }] }),
}))
vi.mock('@/context/NavigationGuardContext', () => ({ useGuardedRouter: () => ({ push: h.push }), useNavigationGuard: () => null }))
vi.mock('@/hooks/useErrorToast', () => ({ useErrorToast: () => {} }))

import { UserSelector } from './UserSelector'

beforeEach(() => {
  h.granted = new Set()
  h.push.mockReset()
})
afterEach(() => cleanup())

function openMenu() {
  render(<UserSelector />)
  fireEvent.click(screen.getByTitle('User Menu'))
}

describe('the user menu', () => {
  test('users:impersonate and users:read: the switcher lists the accounts, and Manage Users is there', () => {
    h.granted = new Set(['users:impersonate', 'users:read'])
    openMenu()
    expect(screen.getByText('Marco')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /Manage Users/ }))
    expect(h.push).toHaveBeenCalledWith('/settings/users')
  })

  test('users:read without users:impersonate: no switcher, the account menu with Manage Users', () => {
    h.granted = new Set(['users:read'])
    openMenu()
    expect(screen.queryByText('Marco')).toBeNull()
    expect(screen.getByRole('button', { name: /Change Password/ })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Manage Users/ })).toBeInTheDocument()
  })

  test('users:impersonate without users:read: the switcher, no Manage Users', () => {
    h.granted = new Set(['users:impersonate'])
    openMenu()
    expect(screen.getByText('Marco')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Manage Users/ })).toBeNull()
  })

  test('a member: the account menu only', () => {
    openMenu()
    expect(screen.queryByText('Marco')).toBeNull()
    expect(screen.queryByRole('button', { name: /Manage Users/ })).toBeNull()
    expect(screen.getByRole('button', { name: /Logout/ })).toBeInTheDocument()
  })
})
