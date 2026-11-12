/**
 * Settings > Users and temporary passwords (step 2.8, ID-17): with the identity switch on, an
 * admin setting someone else's password, or creating an account with one, chooses "Require a
 * change at first sign-in", ticked by default; the admin's own row never offers it. With the
 * switch off the forms send exactly what they sent after Phase 1.
 */
import { describe, test, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor, within } from '@testing-library/react'

const h = vi.hoisted(() => ({
  search: new URLSearchParams(''),
  router: { push: () => {}, replace: () => {} },
  admin: {
    id: 'admin-1', email: 'admin-1@e2e.local', role: 'admin', accountType: 'admin',
    rbac: { compat: false, legacyGrantsPending: 0, identity: true } as Record<string, unknown>,
  } as Record<string, unknown>,
  createUser: vi.fn(),
  changePassword: vi.fn(),
}))

vi.mock('next/navigation', () => ({
  useRouter: () => h.router,
  useSearchParams: () => h.search,
}))
vi.mock('@/providers/AuthProvider', () => ({
  useAuth: () => ({ user: h.admin, isAdmin: true, isLoading: false }),
}))
vi.mock('@/hooks/useUsers', () => ({
  useUsers: () => ({
    data: [
      { id: 'admin-1', name: 'Me', email: 'admin-1@e2e.local', role: 'admin', status: 'active', hasPassword: true, _count: { projects: 0 } },
      { id: 'member-1', name: 'Member', email: 'member-1@e2e.local', role: 'standard', status: 'active', hasPassword: true, _count: { projects: 0 } },
    ],
    isLoading: false, error: null, refetch: vi.fn(),
  }),
  useCreateUser: () => ({ mutateAsync: h.createUser, isPending: false }),
  useDeleteUser: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useChangePassword: () => ({ mutateAsync: h.changePassword, isPending: false }),
  useUpdateUser: () => ({ mutateAsync: vi.fn(), isPending: false }),
}))
vi.mock('@/hooks/usePasswordPolicy', () => ({ usePasswordPolicy: () => null }))

import UsersPage from './page'

const PW = 'Temporary-orchid-42'
const REQUIRE = 'Require a change at first sign-in'
const typeIn = (label: string, value: string) => fireEvent.change(screen.getByLabelText(label), { target: { value } })

function openSetFor(rowEmail: string) {
  render(<UsersPage />)
  const row = screen.getByText(rowEmail).closest('tr')!
  fireEvent.click(within(row).getByRole('button', { name: 'Set Password' }))
}
const submitSet = () => fireEvent.click(screen.getAllByRole('button', { name: 'Set Password' }).at(-1)!)

beforeEach(() => {
  h.admin = { ...h.admin, rbac: { compat: false, legacyGrantsPending: 0, identity: true } }
  h.createUser.mockReset().mockResolvedValue({})
  h.changePassword.mockReset().mockResolvedValue(undefined)
  vi.stubGlobal('fetch', vi.fn(async () => new Response('{}', { status: 200 })))
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe("set someone else's password (identity switch on)", () => {
  test('the choice is offered, ticked by default, and sent', async () => {
    openSetFor('member-1@e2e.local')
    const box = screen.getByRole('checkbox', { name: REQUIRE })
    expect(box).toBeChecked()
    typeIn('New Password', PW)
    typeIn('Confirm Password', PW)
    submitSet()
    await waitFor(() => expect(h.changePassword).toHaveBeenCalledWith({
      userId: 'member-1', data: { newPassword: PW, requirePasswordChange: true },
    }))
  })

  test('unticked: sent as false', async () => {
    openSetFor('member-1@e2e.local')
    fireEvent.click(screen.getByRole('checkbox', { name: REQUIRE }))
    typeIn('New Password', PW)
    typeIn('Confirm Password', PW)
    submitSet()
    await waitFor(() => expect(h.changePassword).toHaveBeenCalledWith({
      userId: 'member-1', data: { newPassword: PW, requirePasswordChange: false },
    }))
  })

  test('the own row never offers it', () => {
    openSetFor('admin-1@e2e.local')
    expect(screen.queryByRole('checkbox', { name: REQUIRE })).not.toBeInTheDocument()
  })
})

describe('create an account with a temporary password (identity switch on)', () => {
  test('offered once a password is typed, ticked by default, and sent', async () => {
    render(<UsersPage />)
    fireEvent.click(screen.getByRole('button', { name: 'Create User' }))
    expect(screen.queryByRole('checkbox', { name: REQUIRE })).not.toBeInTheDocument()
    typeIn('Name *', 'New Person')
    typeIn('Email *', 'new-person@e2e.local')
    typeIn('Password', PW)
    typeIn('Confirm Password', PW)
    expect(screen.getByRole('checkbox', { name: REQUIRE })).toBeChecked()
    fireEvent.click(screen.getAllByRole('button', { name: 'Create User' }).at(-1)!)
    await waitFor(() => expect(h.createUser).toHaveBeenCalledWith(expect.objectContaining({
      password: PW, requirePasswordChange: true,
    })))
  })
})

describe('identity switch off', () => {
  test('no choice offered; Phase 1 data', async () => {
    h.admin = { ...h.admin, rbac: { compat: false, legacyGrantsPending: 0 } }
    openSetFor('member-1@e2e.local')
    expect(screen.queryByRole('checkbox', { name: REQUIRE })).not.toBeInTheDocument()
    typeIn('New Password', PW)
    typeIn('Confirm Password', PW)
    submitSet()
    await waitFor(() => expect(h.changePassword).toHaveBeenCalledWith({ userId: 'member-1', data: { newPassword: PW } }))
  })
})
