/**
 * Settings > Users, role editing and the admin rows (step 2.6, ID-03 powers, PE-08, ID-25): a
 * Member/Admin control on each row the viewer may change. With the identity switch off it
 * follows Phase 1 (any admin, on every row but its own; demoting another admin asks for the
 * admin's own password, a promotion is confirmed). With it on only the confirmed Root gets it,
 * every change asks for Root's password and says the account signs in again; an admin (or an
 * unconfirmed Root) sees badges, no Set Password or Delete on another admin's row, and no Admin
 * choice when creating a user. Root also gets Disable / Sign out everywhere on admin rows, with
 * its password. Confirmations go through the app's dialog (useAlertModal), refusals show the
 * server's message and code, controls are labelled.
 */
import { describe, test, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor, within } from '@testing-library/react'
import { AlertProvider } from '@/components/ui'

const h = vi.hoisted(() => ({
  search: new URLSearchParams(''),
  router: { push: () => {}, replace: () => {} },
  me: { id: 'admin-1' } as Record<string, unknown>,
  users: [] as unknown[],
  refetch: vi.fn(),
  create: vi.fn(),
  fetch: vi.fn(),
}))

vi.mock('next/navigation', () => ({
  useRouter: () => h.router,
  useSearchParams: () => h.search,
}))
vi.mock('@/providers/AuthProvider', () => ({
  useAuth: () => ({ user: h.me, isAdmin: true, isLoading: false }),
}))
vi.mock('@/hooks/useUsers', () => ({
  useUsers: () => ({ data: h.users, isLoading: false, error: null, refetch: h.refetch }),
  useCreateUser: () => ({ mutateAsync: h.create, isPending: false }),
  useDeleteUser: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useChangePassword: () => ({ mutateAsync: vi.fn(), isPending: false }),
}))

import UsersPage from './page'

// With the identity switch on the page's create action is "Create with a temporary password"
// beside "Invite user" (step 2.9, ID-36); off it is "Create User".
const CREATE_ACTION = /^(Create User|Create with a temporary password)$/

const row = (id: string, name: string, role: string) =>
  ({ id, name, email: `${id}@x.z`, role, status: 'active', hasPassword: true, _count: { projects: 0 } })

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
const sent = (method: string) => h.fetch.mock.calls.filter((c) => (c[1] as RequestInit | undefined)?.method === method)
const bodyOf = (call: unknown[]) => JSON.parse(String((call[1] as RequestInit).body))

type Viewer = 'admin-off' | 'admin-on' | 'unconfirmed-root' | 'root'
function as(viewer: Viewer) {
  const identity = viewer !== 'admin-off'
  const root = viewer === 'root' || viewer === 'unconfirmed-root'
  h.me = {
    id: 'admin-1',
    ...(identity ? { accountType: root ? 'root' : 'admin' } : {}),
    rbac: {
      compat: false, legacyGrantsPending: 0,
      ...(identity ? { identity: true, root: { email: root ? 'admin-1@x.z' : 'someone@x.z', confirmed: viewer !== 'unconfirmed-root', chosenAt: null } } : {}),
    },
  }
}

function renderPage() {
  render(<AlertProvider><UsersPage /></AlertProvider>)
}
const rowOf = (name: string) => within(screen.getByText(name).closest('tr') as HTMLElement)
const dialog = () => within(screen.getByRole('dialog'))
const roleSelect = (name: string) => screen.queryByRole('combobox', { name: `Role of ${name}` }) as HTMLSelectElement | null

beforeEach(() => {
  h.users = [row('admin-1', 'Ada', 'admin'), row('admin-2', 'Pia', 'admin'), row('member-1', 'Marco', 'standard')]
  h.refetch.mockReset()
  h.create.mockReset().mockResolvedValue({})
  h.fetch.mockReset()
  h.fetch.mockImplementation(async (url: string) =>
    String(url).startsWith('/api/admin/') ? json({ error: 'Forbidden' }, 403) : json({ id: 'x', changed: true }))
  vi.stubGlobal('fetch', h.fetch)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('role edit UI per mode', () => {
  test('switch off: every admin gets the control on every row but its own', () => {
    as('admin-off')
    renderPage()
    expect(roleSelect('Pia')!.value).toBe('admin')
    expect(roleSelect('Marco')!.value).toBe('standard')
    expect(roleSelect('Ada')).toBeNull()
    expect(rowOf('Ada').getByText('admin')).toBeInTheDocument()
  })

  test('switch on, an admin: badges only; no Set Password or Delete on another admin', () => {
    as('admin-on')
    renderPage()
    expect(screen.queryAllByRole('combobox', { name: /^Role of / })).toEqual([])
    expect(rowOf('Pia').queryByRole('button', { name: 'Set Password' })).toBeNull()
    expect(rowOf('Pia').queryByRole('button', { name: 'Delete' })).toBeNull()
    expect(rowOf('Marco').getByRole('button', { name: 'Set Password' })).toBeInTheDocument()
    expect(rowOf('Marco').getByRole('button', { name: 'Delete' })).toBeInTheDocument()
    expect(rowOf('Ada').getByRole('button', { name: 'Set Password' })).toBeInTheDocument()
  })

  test('switch on, an unconfirmed Root: the same as an admin', () => {
    as('unconfirmed-root')
    renderPage()
    expect(screen.queryAllByRole('combobox', { name: /^Role of / })).toEqual([])
    expect(rowOf('Pia').queryByRole('button', { name: 'Delete' })).toBeNull()
  })

  test('switch on, the confirmed Root: the control on every other row, and every action on admins', () => {
    as('root')
    renderPage()
    expect(roleSelect('Pia')!.value).toBe('admin')
    expect(roleSelect('Marco')!.value).toBe('standard')
    expect(roleSelect('Ada')).toBeNull()
    for (const b of ['Set Password', 'Delete', 'Disable Pia', 'Sign Pia out everywhere']) {
      expect(rowOf('Pia').getByRole('button', { name: b })).toBeInTheDocument()
    }
  })
})

describe('changing a role', () => {
  test('switch off: a promotion is confirmed, then sent; the list is read again', async () => {
    as('admin-off')
    renderPage()
    fireEvent.change(roleSelect('Marco')!, { target: { value: 'admin' } })
    expect(dialog().getByText(/Make Marco an admin\?/)).toBeInTheDocument()
    fireEvent.click(dialog().getByRole('button', { name: 'Make admin' }))
    await waitFor(() => expect(sent('PUT')).toHaveLength(1))
    expect(sent('PUT')[0][0]).toBe('/api/users/member-1')
    expect(bodyOf(sent('PUT')[0])).toEqual({ role: 'admin' })
    await waitFor(() => expect(h.refetch).toHaveBeenCalled())
  })

  test('switch off: cancelled, nothing is sent and the control shows the role it had', async () => {
    as('admin-off')
    renderPage()
    fireEvent.change(roleSelect('Marco')!, { target: { value: 'admin' } })
    fireEvent.click(dialog().getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(sent('PUT')).toHaveLength(0)
    expect(roleSelect('Marco')!.value).toBe('standard')
  })

  test("switch off: demoting another admin asks for the admin's own password and sends it", async () => {
    as('admin-off')
    renderPage()
    fireEvent.change(roleSelect('Pia')!, { target: { value: 'standard' } })
    fireEvent.change(dialog().getByLabelText('Your password'), { target: { value: 'ada-own-passphrase' } })
    fireEvent.click(dialog().getByRole('button', { name: 'Make member' }))
    await waitFor(() => expect(sent('PUT')).toHaveLength(1))
    expect(bodyOf(sent('PUT')[0])).toEqual({ role: 'standard', stepUpPassword: 'ada-own-passphrase' })
  })

  test("Root: a promotion asks for Root's password and says the account signs in again", async () => {
    as('root')
    renderPage()
    fireEvent.change(roleSelect('Marco')!, { target: { value: 'admin' } })
    expect(dialog().getByText(/sign in again/)).toBeInTheDocument()
    fireEvent.change(dialog().getByLabelText('Your password'), { target: { value: 'root-passphrase' } })
    fireEvent.click(dialog().getByRole('button', { name: 'Make admin' }))
    await waitFor(() => expect(sent('PUT')).toHaveLength(1))
    expect(bodyOf(sent('PUT')[0])).toEqual({ role: 'admin', stepUpPassword: 'root-passphrase' })
    await waitFor(() => expect(h.refetch).toHaveBeenCalled())
  })

  test("a refusal keeps the dialog open with the server's message and code", async () => {
    as('root')
    h.fetch.mockImplementation(async (url: string) => String(url).startsWith('/api/admin/')
      ? json({}, 403)
      : json({ error: 'Password is incorrect', code: 'step_up_failed' }, 403))
    renderPage()
    fireEvent.change(roleSelect('Pia')!, { target: { value: 'standard' } })
    fireEvent.change(dialog().getByLabelText('Your password'), { target: { value: 'wrong' } })
    fireEvent.click(dialog().getByRole('button', { name: 'Make member' }))
    expect(await dialog().findByText(/Password is incorrect.*step_up_failed/)).toBeInTheDocument()
    expect(h.refetch).not.toHaveBeenCalled()
  })
})

describe('creating a user', () => {
  const open = () => fireEvent.click(screen.getByRole('button', { name: CREATE_ACTION }))
  const fill = () => {
    fireEvent.change(dialog().getByLabelText('Name *'), { target: { value: 'Nina' } })
    fireEvent.change(dialog().getByLabelText('Email *'), { target: { value: 'nina@x.z' } })
  }
  const roleChoices = () => Array.from((dialog().getByLabelText('Role') as HTMLSelectElement).options).map((o) => o.value)

  test('switch on, an admin: members only', () => {
    as('admin-on')
    renderPage()
    open()
    expect(roleChoices()).toEqual(['standard'])
  })

  test("switch on, Root: an admin takes Root's password, sent with the request", async () => {
    as('root')
    renderPage()
    open()
    fill()
    fireEvent.change(dialog().getByLabelText('Role'), { target: { value: 'admin' } })
    fireEvent.click(dialog().getByRole('button', { name: 'Create User' }))
    expect(await dialog().findByText('Enter your password to create an admin')).toBeInTheDocument()
    expect(h.create).not.toHaveBeenCalled()
    fireEvent.change(dialog().getByLabelText('Your password'), { target: { value: 'root-passphrase' } })
    fireEvent.click(dialog().getByRole('button', { name: 'Create User' }))
    await waitFor(() => expect(h.create).toHaveBeenCalledWith({
      name: 'Nina', email: 'nina@x.z', password: undefined, role: 'admin', stepUpPassword: 'root-passphrase',
    }))
  })

  test('switch off: an admin may create an admin with no password asked', async () => {
    as('admin-off')
    renderPage()
    open()
    expect(roleChoices()).toEqual(['standard', 'admin'])
    fill()
    fireEvent.change(dialog().getByLabelText('Role'), { target: { value: 'admin' } })
    expect(dialog().queryByLabelText('Your password')).toBeNull()
    fireEvent.click(dialog().getByRole('button', { name: 'Create User' }))
    await waitFor(() => expect(h.create).toHaveBeenCalledWith({ name: 'Nina', email: 'nina@x.z', password: undefined, role: 'admin' }))
  })
})

describe("Root's status actions on an admin row", () => {
  test("Disable asks for Root's password and sends it", async () => {
    as('root')
    renderPage()
    fireEvent.click(rowOf('Pia').getByRole('button', { name: 'Disable Pia' }))
    fireEvent.change(dialog().getByLabelText('Your password'), { target: { value: 'root-passphrase' } })
    fireEvent.click(dialog().getByRole('button', { name: 'Disable' }))
    await waitFor(() => expect(sent('POST')).toHaveLength(1))
    expect(sent('POST')[0][0]).toBe('/api/users/admin-2/disable')
    expect(bodyOf(sent('POST')[0])).toEqual({ stepUpPassword: 'root-passphrase' })
    await waitFor(() => expect(h.refetch).toHaveBeenCalled())
  })

  test("a member row keeps the plain confirmation for Root too", async () => {
    as('root')
    renderPage()
    fireEvent.click(rowOf('Marco').getByRole('button', { name: 'Disable Marco' }))
    expect(dialog().queryByLabelText('Your password')).toBeNull()
  })
})
