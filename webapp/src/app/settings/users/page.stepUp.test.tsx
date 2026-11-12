/**
 * Settings > Users, admin-on-admin actions (HD-09, ID-25): "Set Password" on another
 * admin's row asks for the acting admin's own password, on the admin's own row for
 * the current one; deleting an admin asks for the password in the step-up dialog.
 * A member's row asks for nothing extra.
 */
import { describe, test, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor, within } from '@testing-library/react'
import { ApiError } from '@/lib/apiError'

const h = vi.hoisted(() => ({
  search: new URLSearchParams(''),
  router: { push: () => {}, replace: () => {} },
  admin: { id: 'admin-1' },
  changePassword: vi.fn(),
  deleteUser: vi.fn(),
}))

vi.mock('next/navigation', () => ({
  useRouter: () => h.router,
  useSearchParams: () => h.search,
}))
// The page's permissions (hooks/useCan.ts): an admin holding every user permission.
vi.mock('@/hooks/useCan', () => ({ useCan: () => true, useRbacFlags: () => null }))
vi.mock('@/providers/AuthProvider', () => ({
  useAuth: () => ({ user: h.admin, isLoading: false }),
}))
const USERS = [
  { id: 'admin-1', name: 'Ada Admin', email: 'ada@x.z', role: 'admin', hasPassword: true, _count: { projects: 0 } },
  { id: 'admin-2', name: 'Bob Admin', email: 'bob@x.z', role: 'admin', hasPassword: true, _count: { projects: 0 } },
  { id: 'member-1', name: 'Mia Member', email: 'mia@x.z', role: 'standard', hasPassword: true, _count: { projects: 0 } },
]
vi.mock('@/hooks/useUsers', () => ({
  useUsers: () => ({ data: USERS, isLoading: false, error: null }),
  useCreateUser: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useDeleteUser: () => ({ mutateAsync: h.deleteUser, isPending: false }),
  useChangePassword: () => ({ mutateAsync: h.changePassword, isPending: false }),
}))

import UsersPage from './page'

const NEW = 'a-brand-new-passphrase'
const type = (el: HTMLElement, value: string) => fireEvent.change(el, { target: { value } })
const row = (name: string) => screen.getByText(name).closest('tr') as HTMLElement

beforeEach(() => {
  h.changePassword.mockReset().mockResolvedValue(undefined)
  h.deleteUser.mockReset().mockResolvedValue(undefined)
})
afterEach(() => cleanup())

function openSet(name: string) {
  render(<UsersPage />)
  fireEvent.click(within(row(name)).getByRole('button', { name: 'Set Password' }))
  return screen.getByRole('dialog')
}
const submitSet = (dialog: HTMLElement) => fireEvent.click(within(dialog).getByRole('button', { name: 'Set Password' }))

describe('Set Password on another admin asks for your password', () => {
  test('the field is labelled and its value goes as stepUpPassword', async () => {
    const dialog = openSet('Bob Admin')
    type(within(dialog).getByLabelText('New Password'), NEW)
    type(within(dialog).getByLabelText('Confirm Password'), NEW)
    type(within(dialog).getByLabelText('Your password'), 'ada-own-passphrase')
    submitSet(dialog)
    await waitFor(() => expect(h.changePassword).toHaveBeenCalledWith({
      userId: 'admin-2', data: { newPassword: NEW, stepUpPassword: 'ada-own-passphrase' },
    }))
  })

  test('left empty, nothing is sent', async () => {
    const dialog = openSet('Bob Admin')
    type(within(dialog).getByLabelText('New Password'), NEW)
    type(within(dialog).getByLabelText('Confirm Password'), NEW)
    submitSet(dialog)
    expect(await within(dialog).findByText('Enter your password to reset another admin\'s password')).toBeInTheDocument()
    expect(h.changePassword).not.toHaveBeenCalled()
  })

  test('a refused step-up shows the server reason', async () => {
    h.changePassword.mockRejectedValue(new ApiError({ reason: 'Password is incorrect', status: 403, code: 'step_up_failed' }))
    const dialog = openSet('Bob Admin')
    type(within(dialog).getByLabelText('New Password'), NEW)
    type(within(dialog).getByLabelText('Confirm Password'), NEW)
    type(within(dialog).getByLabelText('Your password'), 'guess')
    submitSet(dialog)
    expect(await within(dialog).findByText('Password is incorrect (step_up_failed · HTTP 403)')).toBeInTheDocument()
  })
})

describe('Set Password on your own row asks for the current one', () => {
  test('its value goes as currentPassword', async () => {
    const dialog = openSet('Ada Admin')
    expect(within(dialog).queryByLabelText('Your password')).toBeNull()
    type(within(dialog).getByLabelText('Current Password'), 'ada-old-passphrase')
    type(within(dialog).getByLabelText('New Password'), NEW)
    type(within(dialog).getByLabelText('Confirm Password'), NEW)
    submitSet(dialog)
    await waitFor(() => expect(h.changePassword).toHaveBeenCalledWith({
      userId: 'admin-1', data: { newPassword: NEW, currentPassword: 'ada-old-passphrase' },
    }))
  })

  test('left empty, nothing is sent', async () => {
    const dialog = openSet('Ada Admin')
    type(within(dialog).getByLabelText('New Password'), NEW)
    type(within(dialog).getByLabelText('Confirm Password'), NEW)
    submitSet(dialog)
    expect(await within(dialog).findByText('Current password is required')).toBeInTheDocument()
    expect(h.changePassword).not.toHaveBeenCalled()
  })
})

describe('a member row asks for nothing extra', () => {
  test('only the new password is sent', async () => {
    const dialog = openSet('Mia Member')
    expect(within(dialog).queryByLabelText('Your password')).toBeNull()
    expect(within(dialog).queryByLabelText('Current Password')).toBeNull()
    type(within(dialog).getByLabelText('New Password'), NEW)
    type(within(dialog).getByLabelText('Confirm Password'), NEW)
    submitSet(dialog)
    await waitFor(() => expect(h.changePassword).toHaveBeenCalledWith({ userId: 'member-1', data: { newPassword: NEW } }))
  })

  test('deleting a member keeps the plain confirmation', async () => {
    render(<UsersPage />)
    fireEvent.click(within(row('Mia Member')).getByRole('button', { name: 'Delete' }))
    const dialog = screen.getByRole('dialog', { name: 'Delete User' })
    expect(within(dialog).queryByLabelText('Your password')).toBeNull()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete User' }))
    await waitFor(() => expect(h.deleteUser).toHaveBeenCalledWith('member-1'))
  })
})

describe('deleting another admin goes through the step-up dialog', () => {
  function openDelete() {
    render(<UsersPage />)
    fireEvent.click(within(row('Bob Admin')).getByRole('button', { name: 'Delete' }))
    return screen.getByRole('dialog', { name: 'Delete an admin' })
  }

  test('the password goes with the delete', async () => {
    const dialog = openDelete()
    expect(within(dialog).getByText(/Bob Admin/)).toBeInTheDocument()
    type(within(dialog).getByLabelText('Your password'), 'ada-own-passphrase')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete User' }))
    await waitFor(() => expect(h.deleteUser).toHaveBeenCalledWith({ userId: 'admin-2', stepUpPassword: 'ada-own-passphrase' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
  })

  test('a refusal keeps the dialog open with the reason', async () => {
    h.deleteUser.mockRejectedValue(new ApiError({
      reason: 'This is the last admin with a password: promote another account first.', status: 409, code: 'last_admin',
    }))
    const dialog = openDelete()
    type(within(dialog).getByLabelText('Your password'), 'ada-own-passphrase')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Delete User' }))
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('(last_admin · HTTP 409)')
  })
})
