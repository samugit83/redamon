/**
 * Settings > Users, account status (step 2.3, ID-13, ID-21): a status badge, and Disable /
 * Enable / Sign out everywhere per row, as the server's rules allow. With the identity switch
 * on (`rbac.identity` from /api/auth/me) members can be disabled or signed out, another
 * admin's row offers nothing (Root's, step 2.6), and the own row signs this account out
 * everywhere. With it off only Enable is offered, on a disabled row. Every action is confirmed
 * through the app's dialog (useAlertModal), a refusal shows the server's message, and an agent
 * that did not confirm the close is reported.
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

import UsersPage from './page'

const row = (id: string, name: string, role: string, status: string) =>
  ({ id, name, email: `${id}@x.z`, role, status, hasPassword: status !== 'disabled', _count: { projects: 0 } })

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
const posts = () => h.fetch.mock.calls.filter((c) => (c[1] as RequestInit | undefined)?.method === 'POST')

function renderPage() {
  render(<AlertProvider><UsersPage /></AlertProvider>)
}
function rowOf(name: string): HTMLElement {
  return screen.getByText(name).closest('tr') as HTMLElement
}
const dialog = () => screen.getByRole('dialog')

beforeEach(() => {
  h.admin.rbac = { compat: false, legacyGrantsPending: 0, ...(h.identity ? { identity: true } : {}) }
  h.users = [
    row('admin-1', 'Ada', 'admin', 'active'),
    row('admin-2', 'Pia', 'admin', 'active'),
    row('member-1', 'Marco', 'standard', 'active'),
    row('member-2', 'Anna', 'standard', 'disabled'),
  ]
  h.refetch.mockReset()
  h.fetch.mockReset()
  // The admin cards on the page read their own endpoints: refused, so they stay hidden.
  h.fetch.mockImplementation(async (url: string) =>
    String(url).startsWith('/api/admin/') ? json({ error: 'Forbidden' }, 403) : json({ changed: true }))
  vi.stubGlobal('fetch', h.fetch)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  h.identity = true
})

describe('switch on: what each row offers', () => {
  test('a member: Sign out everywhere and Disable; a disabled member: the badge and Enable', () => {
    renderPage()
    const marco = within(rowOf('Marco'))
    expect(marco.getByRole('button', { name: 'Disable Marco' })).toBeInTheDocument()
    expect(marco.getByRole('button', { name: 'Sign Marco out everywhere' })).toBeInTheDocument()
    expect(marco.queryByRole('button', { name: 'Enable Marco' })).toBeNull()
    const anna = within(rowOf('Anna'))
    expect(anna.getByText('Disabled')).toBeInTheDocument()
    expect(anna.getByRole('button', { name: 'Enable Anna' })).toBeInTheDocument()
    expect(anna.queryByRole('button', { name: 'Disable Anna' })).toBeNull()
  })

  test('another admin: nothing (Root only); the own row: sign this account out everywhere', () => {
    renderPage()
    const pia = within(rowOf('Pia'))
    expect(pia.queryByRole('button', { name: /Disable|out everywhere|Enable/ })).toBeNull()
    const ada = within(rowOf('Ada'))
    expect(ada.getByRole('button', { name: 'Sign your account out everywhere' })).toBeInTheDocument()
    expect(ada.queryByRole('button', { name: /Disable/ })).toBeNull()
  })

  test('Disable asks first, then posts JSON and reloads the list', async () => {
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: 'Disable Marco' }))
    expect(within(dialog()).getByText(/Disable Marco\? They are signed out everywhere/)).toBeInTheDocument()
    fireEvent.click(within(dialog()).getByRole('button', { name: 'Disable' }))
    await waitFor(() => expect(posts()).toHaveLength(1))
    const [url, init] = posts()[0] as [string, RequestInit]
    expect(url).toBe('/api/users/member-1/disable')
    expect(init.headers).toMatchObject({ 'Content-Type': 'application/json' })
    expect(init.body).toBe('{}')
    await waitFor(() => expect(h.refetch).toHaveBeenCalled())
  })

  test('cancelled: nothing is sent', async () => {
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: 'Disable Marco' }))
    fireEvent.click(within(dialog()).getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(posts()).toHaveLength(0)
  })

  test('Sign out everywhere on a member posts to revoke-sessions', async () => {
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: 'Sign Marco out everywhere' }))
    fireEvent.click(within(dialog()).getByRole('button', { name: 'Sign out everywhere' }))
    await waitFor(() => expect(posts()[0]?.[0]).toBe('/api/users/member-1/revoke-sessions'))
  })

  test('the own row posts to revoke-all and goes to /login', async () => {
    const replace = vi.fn()
    vi.spyOn(window, 'location', 'get').mockReturnValue({ ...window.location, replace } as Location)
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: 'Sign your account out everywhere' }))
    fireEvent.click(within(dialog()).getByRole('button', { name: 'Sign out everywhere' }))
    await waitFor(() => expect(replace).toHaveBeenCalledWith('/login'))
    expect(posts()[0][0]).toBe('/api/auth/sessions/revoke-all')
    vi.restoreAllMocks()
  })

  test('an agent that did not confirm the close is reported', async () => {
    h.fetch.mockImplementation(async (url: string) => String(url).startsWith('/api/admin/')
      ? json({}, 403)
      : json({ changed: true, agent: { runs: { error: 'agent_unreachable' }, sockets: { error: 'agent_unreachable' } } }))
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: 'Disable Marco' }))
    fireEvent.click(within(dialog()).getByRole('button', { name: 'Disable' }))
    expect(await screen.findByText(/did not confirm that their open sessions and runs were ended \(agent_unreachable\)/)).toBeInTheDocument()
  })

  test("a refusal shows the server's message and code", async () => {
    h.fetch.mockImplementation(async (url: string) => String(url).startsWith('/api/admin/')
      ? json({}, 403)
      : json({ error: 'Only Root can disable, enable or sign out an admin account.', code: 'root_only' }, 403))
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: 'Disable Marco' }))
    fireEvent.click(within(dialog()).getByRole('button', { name: 'Disable' }))
    expect(await screen.findByText(/Only Root can disable.*root_only/)).toBeInTheDocument()
  })

  test('Enable on a disabled member asks first, then posts', async () => {
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: 'Enable Anna' }))
    fireEvent.click(within(dialog()).getByRole('button', { name: 'Enable' }))
    await waitFor(() => expect(posts()[0]?.[0]).toBe('/api/users/member-2/enable'))
  })
})

describe('switch off: Phase 1 rows, plus Enable on a disabled account', () => {
  beforeEach(() => {
    h.identity = false
    h.admin.rbac = { compat: false, legacyGrantsPending: 0 }
    h.users = [...(h.users as object[]), row('admin-3', 'Ines', 'admin', 'disabled')]
  })

  test('no Disable and no Sign out everywhere anywhere; the disabled rows keep their badge and Enable', () => {
    renderPage()
    expect(screen.queryByRole('button', { name: /^Disable / })).toBeNull()
    expect(screen.queryByRole('button', { name: /out everywhere/ })).toBeNull()
    expect(within(rowOf('Anna')).getByRole('button', { name: 'Enable Anna' })).toBeInTheDocument()
    expect(within(rowOf('Ines')).getByText('Disabled')).toBeInTheDocument()
  })

  test('enabling another admin asks for the own password and sends it', async () => {
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: 'Enable Ines' }))
    fireEvent.change(within(dialog()).getByLabelText('Your password'), { target: { value: 'my-own-passphrase' } })
    fireEvent.click(within(dialog()).getByRole('button', { name: 'Enable' }))
    await waitFor(() => expect(posts()).toHaveLength(1))
    expect(posts()[0][0]).toBe('/api/users/admin-3/enable')
    expect(JSON.parse(String((posts()[0][1] as RequestInit).body))).toEqual({ stepUpPassword: 'my-own-passphrase' })
  })
})

describe('outside the app shell (no dialog)', () => {
  test('nothing is sent', async () => {
    render(<UsersPage />)
    fireEvent.click(screen.getByRole('button', { name: 'Disable Marco' }))
    await new Promise((r) => setTimeout(r, 10))
    expect(posts()).toHaveLength(0)
  })
})
