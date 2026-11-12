/**
 * The user switcher and the identity label (step 2.11, ID-31): with the identity switch on, each
 * account an admin can act as is listed by name, email and account type (Root, Admin, Member),
 * so two accounts with the same display name are told apart, and the menu button shows the type
 * of the account in use. With the switch off the Phase 1 list (the stored role) stays.
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent } from '@testing-library/react'
import { ToastProvider } from '@/components/ui/Toast/Toast'

const state = vi.hoisted(() => ({ identity: true, userId: 'admin-1' }))
const h = vi.hoisted(() => ({ push: vi.fn() }))
const USERS = [
  { id: 'admin-1', name: 'Ada', email: 'ada@x.z', role: 'admin' },
  { id: 'admin-2', name: 'Marco', email: 'marco.admin@x.z', role: 'admin' },
  { id: 'member-1', name: 'Marco', email: 'marco@x.z', role: 'standard' },
]

vi.mock('@/providers/ProjectProvider', () => ({
  useProject: () => ({ userId: state.userId, setUserId: vi.fn(), setCurrentProject: vi.fn(), userSwitchError: null }),
}))
// An admin: the user switcher (users:impersonate) and Manage Users (users:read).
vi.mock('@/hooks/useCan', () => ({ useCan: () => true, useRbacFlags: () => null }))
vi.mock('@/providers/AuthProvider', () => ({
  useAuth: () => ({
    user: {
      id: 'admin-1', name: 'Ada', email: 'ada@x.z', role: 'admin',
      ...(state.identity ? { accountType: 'root' } : {}),
      rbac: {
        compat: false, legacyGrantsPending: 0,
        ...(state.identity ? { identity: true, root: { email: 'ada@x.z', confirmed: true, chosenAt: null } } : {}),
      },
    },
    logout: vi.fn(), sessionError: null,
  }),
}))
vi.mock('@/hooks/useUsers', () => ({ useUsers: () => ({ data: USERS }) }))
vi.mock('@/context/NavigationGuardContext', () => ({
  useGuardedRouter: () => ({ push: h.push }),
  useNavigationGuard: () => null,
}))

import { UserSelector } from './UserSelector'

afterEach(() => {
  cleanup()
  state.identity = true
  state.userId = 'admin-1'
})

function open() {
  render(<ToastProvider><UserSelector /></ToastProvider>)
  fireEvent.click(screen.getByTitle('User Menu'))
}

describe('switch on', () => {
  test('every account is listed by name, email and type', () => {
    open()
    const labels = screen.getAllByTestId('identity-label').map((l) => l.getAttribute('aria-label'))
    expect(labels).toEqual(expect.arrayContaining([
      'Ada, ada@x.z, Root',
      'Marco, marco.admin@x.z, Admin',
      'Marco, marco@x.z, Member',
    ]))
  })

  test('the menu button shows the type of the account in use', () => {
    state.userId = 'member-1'
    render(<ToastProvider><UserSelector /></ToastProvider>)
    const trigger = screen.getByTitle('User Menu')
    expect(trigger).toHaveTextContent('Marco')
    expect(trigger).toHaveTextContent('Member')
    expect(trigger).toHaveAttribute('aria-label', 'User menu: Marco, marco@x.z, Member')
  })
})

describe('My account in the menu', () => {
  test('switch on: the menu leads to /account', () => {
    open()
    fireEvent.click(screen.getByRole('button', { name: 'My account' }))
    expect(h.push).toHaveBeenCalledWith('/account')
  })

  test('switch off: no such entry (Phase 1 menu)', () => {
    state.identity = false
    open()
    expect(screen.queryByRole('button', { name: 'My account' })).toBeNull()
  })
})

describe('switch off: the Phase 1 list', () => {
  test('the stored role, no account type', () => {
    state.identity = false
    open()
    expect(screen.queryByText('Root')).toBeNull()
    expect(screen.queryByText('Member')).toBeNull()
    expect(screen.getAllByText('admin')).toHaveLength(2)
    expect(screen.getByText('standard')).toBeInTheDocument()
    expect(screen.getByTitle('User Menu')).not.toHaveAttribute('aria-label')
  })
})
