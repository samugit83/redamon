/**
 * Acting as another admin asks for the signed-in admin's own password first
 * (HD-09, ID-25); acting as a member or going back to yourself does not.
 */
import { describe, test, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'
import { ToastProvider } from '@/components/ui/Toast/Toast'
import { ApiError } from '@/lib/apiError'

const h = vi.hoisted(() => ({
  userId: 'admin-1',
  setUserId: vi.fn(),
  setCurrentProject: vi.fn(),
}))

vi.mock('@/providers/ProjectProvider', () => ({
  useProject: () => ({ userId: h.userId, setUserId: h.setUserId, setCurrentProject: h.setCurrentProject, userSwitchError: null }),
}))
vi.mock('@/providers/AuthProvider', () => ({
  useAuth: () => ({ user: { id: 'admin-1', name: 'Ada Admin' }, isAdmin: true, logout: vi.fn(), sessionError: null }),
}))
vi.mock('@/hooks/useUsers', () => ({
  useUsers: () => ({
    data: [
      { id: 'admin-1', name: 'Ada Admin', email: 'ada@x.z', role: 'admin' },
      { id: 'admin-2', name: 'Bob Admin', email: 'bob@x.z', role: 'admin' },
      { id: 'member-1', name: 'Mia Member', email: 'mia@x.z', role: 'standard' },
    ],
  }),
}))
vi.mock('@/context/NavigationGuardContext', () => ({
  useGuardedRouter: () => ({ push: vi.fn() }),
  useNavigationGuard: () => null,
}))

import { UserSelector } from './UserSelector'

beforeEach(() => {
  h.userId = 'admin-1'
  h.setUserId.mockReset().mockResolvedValue(null)
  h.setCurrentProject.mockReset()
})
afterEach(() => cleanup())

function pick(name: string) {
  render(<ToastProvider><UserSelector /></ToastProvider>)
  fireEvent.click(screen.getByTitle('User Menu'))
  fireEvent.click(screen.getByText(name))
}

describe('switching to another admin', () => {
  test('opens the step-up dialog instead of switching', () => {
    pick('Bob Admin')
    expect(screen.getByRole('dialog', { name: 'Act as an admin' })).toBeInTheDocument()
    expect(screen.getByText(/Bob Admin is an admin/)).toBeInTheDocument()
    expect(h.setUserId).not.toHaveBeenCalled()
  })

  test('the password goes with the switch; success closes the dialog and resets the project', async () => {
    pick('Bob Admin')
    fireEvent.change(screen.getByLabelText('Your password'), { target: { value: 'ada-own-passphrase' } })
    fireEvent.click(screen.getByRole('button', { name: 'Switch user' }))
    await waitFor(() => expect(h.setUserId).toHaveBeenCalledWith('admin-2', { stepUpPassword: 'ada-own-passphrase' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(h.setCurrentProject).toHaveBeenCalledWith(null)
  })

  test('a refused password keeps the dialog open with the reason, project untouched', async () => {
    h.setUserId.mockResolvedValue(new ApiError({ reason: 'Password is incorrect', status: 403, code: 'step_up_failed' }))
    pick('Bob Admin')
    fireEvent.change(screen.getByLabelText('Your password'), { target: { value: 'guess' } })
    fireEvent.click(screen.getByRole('button', { name: 'Switch user' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Password is incorrect (step_up_failed · HTTP 403)')
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    expect(h.setCurrentProject).not.toHaveBeenCalled()
  })

  test('Cancel switches nothing', () => {
    pick('Bob Admin')
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(h.setUserId).not.toHaveBeenCalled()
  })
})

describe('no step-up', () => {
  test('a member is switched to at once', () => {
    pick('Mia Member')
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(h.setUserId).toHaveBeenCalledWith('member-1')
  })

  test('going back to yourself is switched to at once', () => {
    h.userId = 'admin-2'
    pick('Ada Admin')
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(h.setUserId).toHaveBeenCalledWith('admin-1')
  })
})
