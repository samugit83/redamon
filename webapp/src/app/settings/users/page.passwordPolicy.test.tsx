/**
 * Settings > Users and the configurable password policy (step 2.8, ID-20): every password
 * field shows the policy in force (/api/auth/password-policy) and the form refuses what the
 * server would, with the server's message, sending nothing. With the identity switch off the
 * route answers 404: no policy text, Phase 1's floor only.
 */
import { describe, test, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'

const h = vi.hoisted(() => ({
  isAdmin: true,
  search: new URLSearchParams(''),
  router: { push: () => {}, replace: () => {} },
  admin: { id: 'admin-1', email: 'rbac-admin-long@e2e.local' },
  member: { id: 'member-1', email: 'rbac-member-long@e2e.local' },
  createUser: vi.fn(),
  changePassword: vi.fn(),
  fetch: vi.fn(),
  policyStatus: 200,
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
    data: [{ id: 'member-1', name: 'Member', email: 'rbac-member-long@e2e.local', role: 'standard', hasPassword: true, _count: { projects: 0 } }],
    isLoading: false, error: null,
  }),
  useCreateUser: () => ({ mutateAsync: h.createUser, isPending: false }),
  useDeleteUser: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useChangePassword: () => ({ mutateAsync: h.changePassword, isPending: false }),
}))

import UsersPage from './page'

const TEXT = 'At least 16 characters and at most 72 bytes; not a common password, not your email address or its name part, not one character repeated.'

const passwordInputs = (): HTMLInputElement[] => Array.from(document.body.querySelectorAll('input[type="password"]'))
const type = (input: HTMLInputElement, value: string) => fireEvent.change(input, { target: { value } })

beforeEach(() => {
  h.isAdmin = true
  h.search = new URLSearchParams('')
  h.policyStatus = 200
  h.createUser.mockReset().mockResolvedValue({})
  h.changePassword.mockReset().mockResolvedValue(undefined)
  h.fetch.mockReset().mockImplementation(async (url: string) => {
    if (String(url) !== '/api/auth/password-policy') throw new Error(`unexpected fetch ${url}`)
    return h.policyStatus === 200
      ? new Response(JSON.stringify({ minLength: 16, maxBytes: 72, rules: true, description: TEXT }), { status: 200 })
      : new Response(JSON.stringify({ error: 'Not found' }), { status: 404 })
  })
  vi.stubGlobal('fetch', h.fetch)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

async function openSet() {
  render(<UsersPage />)
  await waitFor(() => expect(h.fetch).toHaveBeenCalledWith('/api/auth/password-policy'))
  fireEvent.click(screen.getByRole('button', { name: 'Set Password' }))
}
const submitSet = () => fireEvent.click(screen.getAllByRole('button', { name: 'Set Password' }).at(-1)!)

describe('the policy next to every password field', () => {
  test('set password: the new password field is described by the policy', async () => {
    await openSet()
    const input = screen.getByLabelText('New Password')
    await waitFor(() => expect(input).toHaveAccessibleDescription(TEXT))
  })

  test('create user: the password field is described by the policy', async () => {
    render(<UsersPage />)
    fireEvent.click(screen.getByRole('button', { name: 'Create User' }))
    await waitFor(() => expect(screen.getByLabelText('Password')).toHaveAccessibleDescription(expect.stringContaining(TEXT)))
  })

  test('change own password (member): the new password field is described by the policy', async () => {
    h.isAdmin = false
    h.search = new URLSearchParams('changePassword=true')
    render(<UsersPage />)
    await waitFor(() => expect(screen.getByLabelText('New Password')).toHaveAccessibleDescription(TEXT))
  })

  test('switch off (404): no policy text, Phase 1\'s floor only', async () => {
    h.policyStatus = 404
    await openSet()
    expect(screen.queryByText(TEXT)).not.toBeInTheDocument()
    const [next, confirm] = passwordInputs()
    type(next, 'password1234')
    type(confirm, 'password1234')
    submitSet()
    await waitFor(() => expect(h.changePassword).toHaveBeenCalledWith({ userId: 'member-1', data: { newPassword: 'password1234' } }))
  })
})

describe('the form refuses what the server would, sending nothing', () => {
  test('the instance minimum', async () => {
    await openSet()
    await screen.findByText(TEXT)
    const [next, confirm] = passwordInputs()
    type(next, 'quiet-orchid-77')
    type(confirm, 'quiet-orchid-77')
    submitSet()
    expect(await screen.findByText('Password must be at least 16 characters')).toBeInTheDocument()
    expect(h.changePassword).not.toHaveBeenCalled()
  })

  test('the deny list', async () => {
    await openSet()
    await screen.findByText(TEXT)
    const [next, confirm] = passwordInputs()
    type(next, 'PasswordPassword')
    type(confirm, 'PasswordPassword')
    submitSet()
    expect(await screen.findByText(/too common/)).toBeInTheDocument()
    expect(h.changePassword).not.toHaveBeenCalled()
  })

  test("the target account's email", async () => {
    await openSet()
    await screen.findByText(TEXT)
    const [next, confirm] = passwordInputs()
    type(next, 'RBAC-MEMBER-LONG')
    type(confirm, 'RBAC-MEMBER-LONG')
    submitSet()
    expect(await screen.findByText('The password must not be your email address or its name part')).toBeInTheDocument()
    expect(h.changePassword).not.toHaveBeenCalled()
  })

  test("create user: the new account's email", async () => {
    render(<UsersPage />)
    await waitFor(() => expect(h.fetch).toHaveBeenCalled())
    fireEvent.click(screen.getByRole('button', { name: 'Create User' }))
    await screen.findByText(TEXT)
    type(screen.getByPlaceholderText('John Doe') as HTMLInputElement, 'New Person')
    type(screen.getByPlaceholderText('john@example.com') as HTMLInputElement, 'rbac-new-person-x@e2e.local')
    type(passwordInputs()[0], 'rbac-new-person-x')
    type(passwordInputs()[1], 'rbac-new-person-x')
    fireEvent.click(screen.getAllByRole('button', { name: 'Create User' }).at(-1)!)
    expect(await screen.findByText('The password must not be your email address or its name part')).toBeInTheDocument()
    expect(h.createUser).not.toHaveBeenCalled()
  })

  test('a password that meets the policy is sent', async () => {
    await openSet()
    await screen.findByText(TEXT)
    const [next, confirm] = passwordInputs()
    type(next, 'Correct-orchid-paddle')
    type(confirm, 'Correct-orchid-paddle')
    submitSet()
    await waitFor(() => expect(h.changePassword).toHaveBeenCalledWith(
      { userId: 'member-1', data: { newPassword: 'Correct-orchid-paddle' } },
    ))
  })
})
