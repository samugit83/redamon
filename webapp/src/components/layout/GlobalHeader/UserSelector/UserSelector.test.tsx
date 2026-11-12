/**
 * The user selector shows what the providers above the toast layer cannot:
 * a refused user switch and a session that could not be read.
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { ToastProvider } from '@/components/ui/Toast/Toast'
import { ApiError } from '@/lib/apiError'

const state = vi.hoisted(() => ({
  userSwitchError: null as unknown,
  sessionError: null as unknown,
}))

vi.mock('@/providers/ProjectProvider', () => ({
  useProject: () => ({ userId: 'admin', setUserId: vi.fn(), setCurrentProject: vi.fn(), userSwitchError: state.userSwitchError }),
}))
// An admin: the user switcher (users:impersonate) and Manage Users (users:read).
vi.mock('@/hooks/useCan', () => ({ useCan: () => true, useRbacFlags: () => null }))
vi.mock('@/providers/AuthProvider', () => ({
  useAuth: () => ({ user: { id: 'admin', name: 'Ada Admin' }, logout: vi.fn(), sessionError: state.sessionError }),
}))
vi.mock('@/hooks/useUsers', () => ({ useUsers: () => ({ data: [{ id: 'admin', name: 'Ada Admin' }] }) }))
vi.mock('@/context/NavigationGuardContext', () => ({
  useGuardedRouter: () => ({ push: vi.fn() }),
  useNavigationGuard: () => null,
}))

import { UserSelector } from './UserSelector'

afterEach(() => {
  cleanup()
  state.userSwitchError = null
  state.sessionError = null
})

const renderSelector = () => render(<ToastProvider><UserSelector /></ToastProvider>)

describe('UserSelector failure toasts', () => {
  test('a refused user switch is toasted with its code and status', async () => {
    state.userSwitchError = new ApiError({ reason: 'Could not switch user', status: 500, code: 'P1001' })
    renderSelector()
    expect(await screen.findByText('Could not switch user (P1001 · HTTP 500)')).toBeInTheDocument()
    expect(screen.getByText('User not switched')).toBeInTheDocument()
  })

  test('a session that could not be read is toasted, once', async () => {
    state.sessionError = new ApiError({ reason: 'Internal server error', status: 500, code: 'P2024' })
    const { rerender } = renderSelector()
    expect(await screen.findByText('Internal server error (P2024 · HTTP 500)')).toBeInTheDocument()
    rerender(<ToastProvider><UserSelector /></ToastProvider>)
    expect(screen.getAllByText('Internal server error (P2024 · HTTP 500)')).toHaveLength(1)
  })

  test('no error, no toast', () => {
    renderSelector()
    expect(screen.queryByText('User not switched')).toBeNull()
    expect(screen.queryByText('Your session could not be read')).toBeNull()
  })
})
