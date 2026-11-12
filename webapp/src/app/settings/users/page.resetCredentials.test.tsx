/**
 * Settings > Users, "Reset credentials" (step 2.10, ID-18, ID-19, PE-08): with the identity
 * switch on, each row the viewer may reset offers it (an admin: members; the confirmed Root:
 * admins too), never the viewer's own row (its password changes with the current one), never an
 * invited row (its invite is resent instead). It opens the reset dialog for that person. The Set
 * Password form on someone else's row is a reset too, so it carries the reason the person will
 * read. With the switch off none of it: Phase 1's page.
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
  changePassword: vi.fn(),
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
  useCreateUser: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useDeleteUser: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useChangePassword: () => ({ mutateAsync: h.changePassword, isPending: false }),
}))

import UsersPage from './page'

const row = (id: string, name: string, role: string, status = 'active') =>
  ({ id, name, email: `${id}@x.z`, role, status, hasPassword: status !== 'invited', _count: { projects: 0 } })
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

type Viewer = 'admin-off' | 'admin-on' | 'root'
function as(viewer: Viewer) {
  const identity = viewer !== 'admin-off'
  h.me = {
    id: 'admin-1',
    email: 'admin-1@x.z',
    ...(identity ? { accountType: viewer === 'root' ? 'root' : 'admin' } : {}),
    rbac: {
      compat: false, legacyGrantsPending: 0,
      ...(identity ? { identity: true, root: { email: viewer === 'root' ? 'admin-1@x.z' : 'someone@x.z', confirmed: true, chosenAt: null } } : {}),
    },
  }
}
function renderPage() {
  render(<AlertProvider><UsersPage /></AlertProvider>)
}
const rowOf = (name: string) => within(screen.getByText(name).closest('tr') as HTMLElement)
const resetOf = (name: string) => rowOf(name).queryByRole('button', { name: `Reset the credentials of ${name}` })

beforeEach(() => {
  h.users = [
    row('admin-1', 'Ada', 'admin'), row('admin-2', 'Pia', 'admin'), row('member-1', 'Marco', 'standard'),
    row('member-2', 'Nina', 'standard', 'invited'),
  ]
  h.refetch.mockReset()
  h.changePassword.mockReset().mockResolvedValue(undefined)
  h.fetch.mockReset()
  h.fetch.mockImplementation(async (url: string) => {
    if (String(url).endsWith('/reset-credentials')) {
      return json({ mode: 'link', link: 'https://redamon.example.com/invite/tok', expiresAt: '2026-11-12T16:00:00.000Z', localhostWarning: false })
    }
    return String(url).startsWith('/api/admin/') ? json({ error: 'Forbidden' }, 403) : json({})
  })
  vi.stubGlobal('fetch', h.fetch)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('which rows offer Reset credentials', () => {
  test('switch on, an admin: members only; never the own row, another admin or an invited row', () => {
    as('admin-on')
    renderPage()
    expect(resetOf('Marco')).toBeInTheDocument()
    expect(resetOf('Ada')).toBeNull()
    expect(resetOf('Pia')).toBeNull()
    expect(resetOf('Nina')).toBeNull()
  })

  test('the confirmed Root: admins too, never its own row', () => {
    as('root')
    renderPage()
    expect(resetOf('Pia')).toBeInTheDocument()
    expect(resetOf('Marco')).toBeInTheDocument()
    expect(resetOf('Ada')).toBeNull()
  })

  test('switch off: no such action (Phase 1 page)', () => {
    as('admin-off')
    renderPage()
    for (const name of ['Ada', 'Pia', 'Marco', 'Nina']) expect(resetOf(name)).toBeNull()
  })
})

describe('the dialog', () => {
  test('opens for that person, a member asks for no password, and a reset reloads the list', async () => {
    as('admin-on')
    renderPage()
    fireEvent.click(resetOf('Marco')!)
    const dialog = within(screen.getByRole('dialog', { name: 'Reset credentials - Marco' }))
    expect(dialog.queryByLabelText('Your password')).toBeNull()
    fireEvent.click(dialog.getByRole('button', { name: 'Reset credentials' }))
    expect(await dialog.findByLabelText('Reset link')).toHaveValue('https://redamon.example.com/invite/tok')
    expect(h.fetch).toHaveBeenCalledWith('/api/users/member-1/reset-credentials', expect.objectContaining({ method: 'POST' }))
    await waitFor(() => expect(h.refetch).toHaveBeenCalled())
  })

  test("Root on another admin is asked for its own password", () => {
    as('root')
    renderPage()
    fireEvent.click(resetOf('Pia')!)
    expect(within(screen.getByRole('dialog', { name: 'Reset credentials - Pia' })).getByLabelText('Your password')).toBeInTheDocument()
  })
})

describe("Set Password on someone else's row is a reset too", () => {
  const openSet = (name: string) => fireEvent.click(rowOf(name).getByRole('button', { name: 'Set Password' }))
  const PW = 'violet-harbour-lantern-42'

  test('switch on: the reason field, sent trimmed when given', async () => {
    as('admin-on')
    renderPage()
    openSet('Marco')
    const dialog = within(screen.getByRole('dialog'))
    expect(dialog.getByLabelText('Reason')).toHaveAccessibleDescription(/they will read it/i)
    fireEvent.change(dialog.getByLabelText('New Password'), { target: { value: PW } })
    fireEvent.change(dialog.getByLabelText('Confirm Password'), { target: { value: PW } })
    fireEvent.change(dialog.getByLabelText('Reason'), { target: { value: '  Locked out  ' } })
    fireEvent.click(dialog.getAllByRole('button', { name: 'Set Password' }).at(-1)!)
    await waitFor(() => expect(h.changePassword).toHaveBeenCalledWith({
      userId: 'member-1', data: { newPassword: PW, requirePasswordChange: true, reason: 'Locked out' },
    }))
  })

  test('the own row has no reason field; switch off neither', () => {
    as('admin-on')
    renderPage()
    openSet('Ada')
    expect(within(screen.getByRole('dialog')).queryByLabelText('Reason')).toBeNull()
    cleanup()
    as('admin-off')
    renderPage()
    openSet('Marco')
    expect(within(screen.getByRole('dialog')).queryByLabelText('Reason')).toBeNull()
  })
})
