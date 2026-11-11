/**
 * Settings > Users: the create, set and change-own password forms refuse what
 * the server refuses, with the server's own message (HD-12), and send nothing.
 */
import { describe, test, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'

// Every hook value is the same object across renders, as in the app: the page's
// effects depend on the router, the search params and the signed-in user, and a
// fresh object per render re-runs them forever.
const h = vi.hoisted(() => ({
  isAdmin: true,
  search: new URLSearchParams(''),
  router: { push: () => {}, replace: () => {} },
  admin: { id: 'admin-1' },
  member: { id: 'member-1' },
  createUser: vi.fn(),
  changePassword: vi.fn(),
}))

vi.mock('next/navigation', () => ({
  useRouter: () => h.router,
  useSearchParams: () => h.search,
}))
vi.mock('@/providers/AuthProvider', () => ({
  useAuth: () => ({ user: h.isAdmin ? h.admin : h.member, isAdmin: h.isAdmin, isLoading: false }),
}))
vi.mock('@/hooks/useUsers', () => ({
  useUsers: () => ({
    data: [{ id: 'member-1', name: 'Member', email: 'm@x.z', role: 'standard', hasPassword: true, _count: { projects: 0 } }],
    isLoading: false, error: null,
  }),
  useCreateUser: () => ({ mutateAsync: h.createUser, isPending: false }),
  useDeleteUser: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useChangePassword: () => ({ mutateAsync: h.changePassword, isPending: false }),
}))

import UsersPage from './page'

const SHORT = 'a'.repeat(11)
const OK = 'a'.repeat(12)
const FLOOR_MESSAGE = 'Password must be at least 12 characters'

function passwordInputs(): HTMLInputElement[] {
  return Array.from(document.body.querySelectorAll('input[type="password"]'))
}

function type(input: HTMLInputElement, value: string) {
  fireEvent.change(input, { target: { value } })
}

beforeEach(() => {
  h.isAdmin = true
  h.search = new URLSearchParams('')
  h.createUser.mockReset().mockResolvedValue({})
  h.changePassword.mockReset().mockResolvedValue(undefined)
})
afterEach(() => cleanup())

describe('create user modal', () => {
  function openCreate() {
    render(<UsersPage />)
    fireEvent.click(screen.getByRole('button', { name: 'Create User' }))
    type(screen.getByPlaceholderText('John Doe') as HTMLInputElement, 'New Member')
    type(screen.getByPlaceholderText('john@example.com') as HTMLInputElement, 'new@x.z')
  }
  const submit = () => fireEvent.click(screen.getAllByRole('button', { name: 'Create User' }).at(-1)!)

  test('11 characters: the policy message, nothing sent', async () => {
    openCreate()
    type(passwordInputs()[0], SHORT)
    type(passwordInputs()[1], SHORT)
    submit()
    expect(await screen.findByText(FLOOR_MESSAGE)).toBeInTheDocument()
    expect(h.createUser).not.toHaveBeenCalled()
  })

  test('12 characters are sent', async () => {
    openCreate()
    type(passwordInputs()[0], OK)
    type(passwordInputs()[1], OK)
    submit()
    await waitFor(() => expect(h.createUser).toHaveBeenCalledWith(expect.objectContaining({ password: OK })))
  })

  test('an empty password still creates a passwordless account', async () => {
    openCreate()
    submit()
    await waitFor(() => expect(h.createUser).toHaveBeenCalledWith(expect.objectContaining({ password: undefined })))
  })
})

describe('set password modal (admin)', () => {
  function openSet() {
    render(<UsersPage />)
    fireEvent.click(screen.getByRole('button', { name: 'Set Password' }))
  }
  const submit = () => fireEvent.click(screen.getAllByRole('button', { name: 'Set Password' }).at(-1)!)

  test('11 characters: the policy message, nothing sent', async () => {
    openSet()
    type(passwordInputs()[0], SHORT)
    type(passwordInputs()[1], SHORT)
    submit()
    expect(await screen.findByText(FLOOR_MESSAGE)).toBeInTheDocument()
    expect(h.changePassword).not.toHaveBeenCalled()
  })

  test('12 characters are sent', async () => {
    openSet()
    type(passwordInputs()[0], OK)
    type(passwordInputs()[1], OK)
    submit()
    await waitFor(() => expect(h.changePassword).toHaveBeenCalledWith({ userId: 'member-1', data: { newPassword: OK } }))
  })
})

describe('change own password modal (member)', () => {
  function openOwn() {
    h.isAdmin = false
    h.search = new URLSearchParams('changePassword=true')
    render(<UsersPage />)
  }
  const submit = () => fireEvent.click(screen.getByRole('button', { name: 'Change Password' }))

  test('11 characters: the policy message, nothing sent', async () => {
    openOwn()
    const [current, next, confirm] = passwordInputs()
    type(current, 'the-old-one')
    type(next, SHORT)
    type(confirm, SHORT)
    submit()
    expect(await screen.findByText(FLOOR_MESSAGE)).toBeInTheDocument()
    expect(h.changePassword).not.toHaveBeenCalled()
  })

  test('12 characters are sent', async () => {
    openOwn()
    const [current, next, confirm] = passwordInputs()
    type(current, 'the-old-one')
    type(next, OK)
    type(confirm, OK)
    submit()
    await waitFor(() => expect(h.changePassword).toHaveBeenCalledWith({
      userId: 'member-1', data: { newPassword: OK, currentPassword: 'the-old-one' },
    }))
  })
})
