/**
 * Settings > Users and invite links (step 2.9, ID-36, ID-14). With the identity switch on,
 * "Invite user" is the default way to add a person (the admin never knows a working password),
 * "Create with a temporary password" the secondary one; the link is shown once with Copy, its
 * expiry, and a warning while it points to localhost. An invited row offers Resend (a new link,
 * shown once) and Cancel invite, each confirmed through the app's dialog; a refusal shows the
 * server's message. With the switch off the page keeps "Create User" and nothing of this.
 */
import { describe, test, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor, within } from '@testing-library/react'
import { AlertProvider } from '@/components/ui'

const h = vi.hoisted(() => ({
  identity: true as boolean,
  search: new URLSearchParams(''),
  router: { push: () => {}, replace: () => {} },
  admin: { id: 'admin-1', rbac: { compat: false, legacyGrantsPending: 0, identity: true } as Record<string, unknown> },
  users: [] as unknown[],
  refetch: vi.fn(),
  fetch: vi.fn(),
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
vi.mock('@/hooks/useUsers', () => ({
  useUsers: () => ({ data: h.users, isLoading: false, error: null, refetch: h.refetch }),
  useCreateUser: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useDeleteUser: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useChangePassword: () => ({ mutateAsync: vi.fn(), isPending: false }),
}))

import UsersPage from '@/app/settings/users/page'

const LINK = 'https://redamon.example.com/invite/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
const NEW_LINK = 'https://redamon.example.com/invite/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'
const EXPIRES = '2026-11-19T10:00:00.000Z'

const row = (id: string, name: string, role: string, status: string) =>
  ({ id, name, email: `${id}@x.z`, role, status, hasPassword: status === 'active', _count: { projects: 0 } })
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
const posts = (path: string) => h.fetch.mock.calls.filter((c) => c[0] === path && (c[1] as RequestInit | undefined)?.method === 'POST')

function renderPage() {
  render(<AlertProvider><UsersPage /></AlertProvider>)
}
const rowOf = (name: string) => screen.getByText(name).closest('tr') as HTMLElement
const dialogs = () => screen.getAllByRole('dialog')
const lastDialog = () => within(dialogs().at(-1)!)

beforeEach(() => {
  h.admin.rbac = { compat: false, legacyGrantsPending: 0, ...(h.identity ? { identity: true } : {}) }
  h.users = [row('admin-1', 'Ada', 'admin', 'active'), row('member-1', 'Marco', 'standard', 'active'), row('invited-1', 'Nina', 'standard', 'invited')]
  h.refetch.mockReset()
  h.fetch.mockReset()
  h.fetch.mockImplementation(async (url: string) => {
    if (String(url).startsWith('/api/admin/') || url === '/api/auth/password-policy') return json({ error: 'Forbidden' }, 403)
    if (url === '/api/users/invite') return json({ id: 'user-9', name: 'Nina', email: 'nina@x.z', role: 'standard', status: 'invited', link: LINK, expiresAt: EXPIRES, localhostWarning: false }, 201)
    if (String(url).endsWith('/invite/resend')) return json({ id: 'invited-1', link: NEW_LINK, expiresAt: EXPIRES, localhostWarning: true })
    if (String(url).endsWith('/invite/cancel')) return json({ id: 'invited-1', cancelled: true })
    return json({})
  })
  vi.stubGlobal('fetch', h.fetch)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  h.identity = true
})

describe('the create actions', () => {
  test('invite default: "Invite user" is the primary action, the temporary password the secondary one', () => {
    renderPage()
    const invite = screen.getByRole('button', { name: 'Invite user' })
    const temporary = screen.getByRole('button', { name: 'Create with a temporary password' })
    expect(invite).toHaveClass('primaryButton')
    expect(temporary).not.toHaveClass('primaryButton')
    expect(invite.compareDocumentPosition(temporary) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    expect(screen.queryByRole('button', { name: 'Create User' })).toBeNull()
  })

  test('switch off: the Phase 1 "Create User" only', () => {
    h.identity = false
    h.admin.rbac = { compat: false, legacyGrantsPending: 0 }
    renderPage()
    expect(screen.getByRole('button', { name: 'Create User' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Invite user' })).toBeNull()
    expect(within(rowOf('Nina')).queryByRole('button', { name: /Resend/ })).toBeNull()
  })

  test('the temporary-password option opens the create form', () => {
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: 'Create with a temporary password' }))
    expect(lastDialog().getByLabelText('Password')).toBeInTheDocument()
  })
})

describe('inviting a person', () => {
  test('sends only the name and the address; the link is shown once with Copy and its expiry', async () => {
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: 'Invite user' }))
    fireEvent.change(lastDialog().getByLabelText('Name'), { target: { value: 'Nina' } })
    fireEvent.change(lastDialog().getByLabelText('Email'), { target: { value: 'nina@x.z' } })
    fireEvent.submit(lastDialog().getByLabelText('Email').closest('form')!)
    const link = await lastDialog().findByLabelText('Invite link')
    expect(link).toHaveValue(LINK)
    expect(link).toHaveAttribute('readonly')
    expect(posts('/api/users/invite')[0][1]).toMatchObject({ body: JSON.stringify({ name: 'Nina', email: 'nina@x.z' }) })
    expect(lastDialog().getByRole('button', { name: 'Copy the invite link' })).toBeInTheDocument()
    expect(lastDialog().getByText(/Expires/)).toBeInTheDocument()
    expect(lastDialog().getByText(/shown only once/i)).toBeInTheDocument()
    expect(lastDialog().queryByText(/localhost/)).toBeNull()
    expect(h.refetch).toHaveBeenCalled()

    // Closed and opened again: an empty form, the link is gone.
    fireEvent.click(lastDialog().getByRole('button', { name: 'Done' }))
    fireEvent.click(screen.getByRole('button', { name: 'Invite user' }))
    expect(lastDialog().queryByLabelText('Invite link')).toBeNull()
    expect(lastDialog().getByLabelText('Name')).toHaveValue('')
  })

  test('localhost warning while the instance has no public address', async () => {
    h.fetch.mockImplementation(async (url: string) => (url === '/api/users/invite'
      ? json({ id: 'user-9', link: 'http://localhost:3000/invite/x', expiresAt: EXPIRES, localhostWarning: true }, 201)
      : json({ error: 'Forbidden' }, 403)))
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: 'Invite user' }))
    fireEvent.change(lastDialog().getByLabelText('Name'), { target: { value: 'Nina' } })
    fireEvent.change(lastDialog().getByLabelText('Email'), { target: { value: 'nina@x.z' } })
    fireEvent.click(lastDialog().getByRole('button', { name: 'Create the invite link' }))
    expect(await lastDialog().findByText(/points to localhost/)).toBeInTheDocument()
    expect(lastDialog().getByText(/publicBaseUrl/)).toBeInTheDocument()
  })

  test("a refusal shows the server's message, the form stays", async () => {
    h.fetch.mockImplementation(async (url: string) => (url === '/api/users/invite'
      ? json({ error: 'A user with this email already exists', code: 'email_taken' }, 409)
      : json({ error: 'Forbidden' }, 403)))
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: 'Invite user' }))
    fireEvent.change(lastDialog().getByLabelText('Name'), { target: { value: 'Nina' } })
    fireEvent.change(lastDialog().getByLabelText('Email'), { target: { value: 'nina@x.z' } })
    fireEvent.click(lastDialog().getByRole('button', { name: 'Create the invite link' }))
    expect(await lastDialog().findByRole('alert')).toHaveTextContent(/already exists.*email_taken/)
    expect(lastDialog().getByLabelText('Name')).toHaveValue('Nina')
  })

  test('the name and the address are required before anything is sent', async () => {
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: 'Invite user' }))
    fireEvent.click(lastDialog().getByRole('button', { name: 'Create the invite link' }))
    expect(await lastDialog().findByRole('alert')).toHaveTextContent('Name and email are required')
    expect(posts('/api/users/invite')).toHaveLength(0)
  })
})

describe('a pending invite', () => {
  test('an invited row offers Resend and Cancel invite, not Set Password', () => {
    renderPage()
    const nina = within(rowOf('Nina'))
    expect(nina.getByRole('button', { name: 'Resend the invite to Nina' })).toBeInTheDocument()
    expect(nina.getByRole('button', { name: 'Cancel the invite of Nina' })).toBeInTheDocument()
    expect(nina.queryByRole('button', { name: 'Set Password' })).toBeNull()
    expect(within(rowOf('Marco')).queryByRole('button', { name: /Resend/ })).toBeNull()
  })

  test('Resend asks first, then shows the new link once', async () => {
    renderPage()
    fireEvent.click(within(rowOf('Nina')).getByRole('button', { name: 'Resend the invite to Nina' }))
    fireEvent.click(await lastDialog().findByRole('button', { name: 'Resend' }))
    expect(await screen.findByDisplayValue(NEW_LINK)).toBeInTheDocument()
    expect(posts('/api/users/invited-1/invite/resend')).toHaveLength(1)
    expect(screen.getByText(/points to localhost/)).toBeInTheDocument()
  })

  test('Resend cancelled in the dialog sends nothing', async () => {
    renderPage()
    fireEvent.click(within(rowOf('Nina')).getByRole('button', { name: 'Resend the invite to Nina' }))
    fireEvent.click(await lastDialog().findByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(posts('/api/users/invited-1/invite/resend')).toHaveLength(0)
  })

  test('Cancel invite asks first, removes the account and reloads the list', async () => {
    renderPage()
    fireEvent.click(within(rowOf('Nina')).getByRole('button', { name: 'Cancel the invite of Nina' }))
    fireEvent.click(await lastDialog().findByRole('button', { name: 'Cancel invite' }))
    await waitFor(() => expect(posts('/api/users/invited-1/invite/cancel')).toHaveLength(1))
    await waitFor(() => expect(h.refetch).toHaveBeenCalled())
  })

  test("a refused cancel shows the server's message", async () => {
    h.fetch.mockImplementation(async (url: string) => (String(url).endsWith('/invite/cancel')
      ? json({ error: 'This invited account owns projects: delete the account instead.', code: 'has_projects' }, 409)
      : json({ error: 'Forbidden' }, 403)))
    renderPage()
    fireEvent.click(within(rowOf('Nina')).getByRole('button', { name: 'Cancel the invite of Nina' }))
    fireEvent.click(await lastDialog().findByRole('button', { name: 'Cancel invite' }))
    expect(await screen.findByText(/owns projects.*has_projects/)).toBeInTheDocument()
  })
})
