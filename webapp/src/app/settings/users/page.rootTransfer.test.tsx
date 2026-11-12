/**
 * Settings > Users, "Transfer Root" (step 2.6, ID-07, ID-25): with the identity switch on, the
 * confirmed Root's own row offers Root to another admin. The dialog lists the admins who can
 * receive it (active, with a password), asks for Root's own password and sends both; the header
 * banner is told to read the offer again. No eligible admin: the dialog says why and nothing is
 * sent. An admin, an unconfirmed Root, or the switch off: no such action.
 */
import { describe, test, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor, within } from '@testing-library/react'
import { AlertProvider } from '@/components/ui'
import { ROOT_TRANSFER_CHANGED_EVENT } from '@/components/admin/RootTransferBanner'

const h = vi.hoisted(() => ({
  search: new URLSearchParams(''),
  router: { push: () => {}, replace: () => {} },
  me: {} as Record<string, unknown>,
  users: [] as unknown[],
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
  useUsers: () => ({ data: h.users, isLoading: false, error: null, refetch: vi.fn() }),
  useCreateUser: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useDeleteUser: () => ({ mutateAsync: vi.fn(), isPending: false }),
  useChangePassword: () => ({ mutateAsync: vi.fn(), isPending: false }),
}))

import UsersPage from './page'

const row = (id: string, name: string, role: string, extra: Record<string, unknown> = {}) =>
  ({ id, name, email: `${id}@x.z`, role, status: 'active', hasPassword: true, _count: { projects: 0 }, ...extra })
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
const posts = () => h.fetch.mock.calls.filter((c) => (c[1] as RequestInit | undefined)?.method === 'POST')
const dialog = () => within(screen.getByRole('dialog'))
const own = () => within(screen.getByText('Ada').closest('tr') as HTMLElement)

function as(viewer: 'root' | 'unconfirmed-root' | 'admin-on' | 'admin-off') {
  const identity = viewer !== 'admin-off'
  const root = viewer === 'root' || viewer === 'unconfirmed-root'
  h.me = {
    id: 'admin-1',
    ...(identity ? { accountType: root ? 'root' : 'admin' } : {}),
    rbac: {
      compat: false, legacyGrantsPending: 0,
      ...(identity ? { identity: true, root: { email: 'x', confirmed: viewer !== 'unconfirmed-root', chosenAt: null } } : {}),
    },
  }
}

function renderPage() {
  render(<AlertProvider><UsersPage /></AlertProvider>)
}

beforeEach(() => {
  h.users = [
    row('admin-1', 'Ada', 'admin'),
    row('admin-2', 'Pia', 'admin'),
    row('admin-3', 'Off', 'admin', { status: 'disabled', hasPassword: false }),
    row('admin-4', 'Nopw', 'admin', { hasPassword: false }),
    row('member-1', 'Marco', 'standard'),
  ]
  h.fetch.mockReset()
  h.fetch.mockImplementation(async (url: string) => String(url).startsWith('/api/admin/')
    ? json({ error: 'Forbidden' }, 403)
    : json({ offered: true, toUserId: 'admin-2', expiresAt: '2026-11-13T10:00:00.000Z' }))
  vi.stubGlobal('fetch', h.fetch)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe("Root's own row", () => {
  test('lists only the admins who can receive Root, and sends the pick with the password', async () => {
    as('root')
    const changed = vi.fn()
    window.addEventListener(ROOT_TRANSFER_CHANGED_EVENT, changed)
    renderPage()
    fireEvent.click(own().getByRole('button', { name: 'Transfer Root' }))
    const pick = dialog().getByLabelText('Transfer Root to') as HTMLSelectElement
    expect(Array.from(pick.options).map((o) => o.value)).toEqual(['', 'admin-2'])
    fireEvent.change(pick, { target: { value: 'admin-2' } })
    fireEvent.change(dialog().getByLabelText('Your password'), { target: { value: 'root-passphrase' } })
    fireEvent.click(dialog().getByRole('button', { name: 'Offer Root' }))
    await waitFor(() => expect(posts()).toHaveLength(1))
    expect(posts()[0][0]).toBe('/api/root/transfer')
    expect(JSON.parse(String((posts()[0][1] as RequestInit).body))).toEqual({ targetUserId: 'admin-2', stepUpPassword: 'root-passphrase' })
    await waitFor(() => expect(changed).toHaveBeenCalled())
    window.removeEventListener(ROOT_TRANSFER_CHANGED_EVENT, changed)
  })

  test('no admin picked: the dialog says so, nothing is sent', async () => {
    as('root')
    renderPage()
    fireEvent.click(own().getByRole('button', { name: 'Transfer Root' }))
    fireEvent.change(dialog().getByLabelText('Your password'), { target: { value: 'root-passphrase' } })
    fireEvent.click(dialog().getByRole('button', { name: 'Offer Root' }))
    expect(await dialog().findByText(/Pick the admin/)).toBeInTheDocument()
    expect(posts()).toHaveLength(0)
  })

  test('no admin can receive Root: told why, nothing sent', async () => {
    as('root')
    h.users = [row('admin-1', 'Ada', 'admin'), row('member-1', 'Marco', 'standard')]
    renderPage()
    fireEvent.click(own().getByRole('button', { name: 'Transfer Root' }))
    expect(await dialog().findByText(/No other admin can receive Root/)).toBeInTheDocument()
    expect(posts()).toHaveLength(0)
  })
})

describe('no Transfer Root for anyone else', () => {
  test.each(['unconfirmed-root', 'admin-on', 'admin-off'] as const)('%s', (viewer) => {
    as(viewer)
    renderPage()
    expect(screen.queryByRole('button', { name: 'Transfer Root' })).toBeNull()
  })
})
