/**
 * The user switcher with RBAC_PERMISSIONS_ENABLED on (step 3.14; IM-04, ID-31): picking another
 * account, member or admin, hands it to the project provider, which opens the act-as dialog (reason,
 * duration, password) named by the account's name, email and type; the Phase 2 step-up prompt is
 * not shown; picking oneself stops acting. The provider clears the project once the switch happened,
 * so the switcher does not. With the switch off UserSelector.stepUp.test.tsx holds, unchanged.
 */
import { describe, test, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'
import { ToastProvider } from '@/components/ui/Toast/Toast'

const h = vi.hoisted(() => ({
  userId: 'admin-1',
  setUserId: vi.fn(),
  setCurrentProject: vi.fn(),
}))

vi.mock('@/providers/ProjectProvider', () => ({
  useProject: () => ({ userId: h.userId, setUserId: h.setUserId, setCurrentProject: h.setCurrentProject, userSwitchError: null }),
}))
vi.mock('@/hooks/useCan', () => ({ useCan: () => true, useRbacFlags: () => ({ permissions: true, identity: true }) }))
vi.mock('@/providers/AuthProvider', () => ({
  useAuth: () => ({
    user: { id: 'admin-1', name: 'Ada Admin', email: 'ada@x.z', accountType: 'root', rbac: { identity: true, root: { email: 'ada@x.z', confirmed: true, chosenAt: null } } },
    logout: vi.fn(),
    sessionError: null,
  }),
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

function pick(label: RegExp) {
  render(<ToastProvider><UserSelector /></ToastProvider>)
  fireEvent.click(screen.getByTitle('User Menu'))
  fireEvent.click(screen.getByRole('group', { name: label }))
}

describe('switching goes through the act-as dialog', () => {
  test('a member: handed over with its name, email and type; no step-up prompt here', async () => {
    pick(/^Mia Member/)
    await waitFor(() => expect(h.setUserId).toHaveBeenCalledWith('member-1', {
      target: { id: 'member-1', name: 'Mia Member', email: 'mia@x.z', accountType: 'member' },
    }))
    expect(screen.queryByRole('dialog', { name: 'Act as an admin' })).toBeNull()
    expect(h.setCurrentProject).not.toHaveBeenCalled()
  })

  test('an admin (Root acting): the same dialog, never the Phase 2 prompt', async () => {
    pick(/^Bob Admin/)
    await waitFor(() => expect(h.setUserId).toHaveBeenCalledWith('admin-2', {
      target: { id: 'admin-2', name: 'Bob Admin', email: 'bob@x.z', accountType: 'admin' },
    }))
    expect(screen.queryByRole('dialog', { name: 'Act as an admin' })).toBeNull()
  })

  test('oneself: stops acting', async () => {
    h.userId = 'member-1'
    pick(/^Ada Admin/)
    await waitFor(() => expect(h.setUserId).toHaveBeenCalledWith('admin-1', undefined))
  })
})
