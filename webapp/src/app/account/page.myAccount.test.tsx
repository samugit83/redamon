/**
 * My account (step 2.11, UI-09, ID-25, ID-30): with the identity switch on, beside the password
 * form (step 2.8) the page shows who the account is (name, email, type), lets it rename itself,
 * change its sign-in email with its current password, sign out everywhere (confirmed in the app's
 * dialog), reach its MCP tokens, see "My activity" (notices and the safe audit rows about it,
 * with loading, error + Retry and empty states), and, for the confirmed Root, offer Root to
 * another admin. While a password must change only the password form shows (the other APIs
 * answer 403 then). With the switch off: the step 2.8 page, nothing else fetched.
 */
import { describe, test, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor, within } from '@testing-library/react'
import { AlertProvider } from '@/components/ui'

const h = vi.hoisted(() => ({
  search: new URLSearchParams(''),
  auth: { user: null as Record<string, unknown> | null, isLoading: false, sessionError: null as { message: string } | null },
  fetch: vi.fn(),
  assign: vi.fn(),
  reload: vi.fn(),
  activity: { status: 200, body: { notices: [], events: [] } as unknown },
  put: { status: 200, body: {} as Record<string, unknown> },
  revoke: { status: 200, body: { revoked: true } as Record<string, unknown> },
  users: [] as unknown[],
}))

vi.mock('next/navigation', () => ({ useSearchParams: () => h.search }))
vi.mock('@/providers/AuthProvider', () => ({ useAuth: () => h.auth }))
vi.mock('@/hooks/useUsers', () => ({ useUsers: () => ({ data: h.users, isLoading: false, error: null }) }))

import AccountPage from './page'

const member = (over: Record<string, unknown> = {}) =>
  ({ id: 'member-1', email: 'marco@e2e.local', name: 'Marco', role: 'standard', accountType: 'member', flags: { identity: true }, ...over })
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

function renderPage() {
  return render(<AlertProvider><AccountPage /></AlertProvider>)
}
const realLocation = window.location
const calls = (path: string, method = 'GET') =>
  h.fetch.mock.calls.filter((c) => c[0] === path && ((c[1] as RequestInit | undefined)?.method ?? 'GET') === method)

beforeEach(() => {
  h.search = new URLSearchParams('')
  h.auth = { user: member(), isLoading: false, sessionError: null }
  h.activity = { status: 200, body: { notices: [], events: [] } }
  h.put = { status: 200, body: { id: 'member-1', name: 'Marco R', email: 'marco@e2e.local' } }
  h.revoke = { status: 200, body: { revoked: true } }
  h.users = []
  h.fetch.mockReset().mockImplementation(async (url: string, init?: RequestInit) => {
    if (url === '/api/auth/password-policy') return json({ minLength: 12, maxBytes: 72, rules: true, description: 'At least 12 characters.' })
    if (url === '/api/account/activity') return json(h.activity.body, h.activity.status)
    if (url === '/api/users/member-1' && init?.method === 'PUT') return json(h.put.body, h.put.status)
    if (url === '/api/auth/sessions/revoke-all' && init?.method === 'POST') return json(h.revoke.body, h.revoke.status)
    if (url === '/api/root/transfer') return json({ pending: null })
    throw new Error(`unexpected fetch ${init?.method ?? 'GET'} ${url}`)
  })
  vi.stubGlobal('fetch', h.fetch)
  h.assign.mockReset()
  h.reload.mockReset()
  Object.defineProperty(window, 'location', { configurable: true, value: { ...realLocation, assign: h.assign, reload: h.reload } })
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  Object.defineProperty(window, 'location', { configurable: true, value: realLocation })
})

describe('who the account is', () => {
  test('name, email and type in the profile', async () => {
    renderPage()
    const profile = screen.getByRole('region', { name: 'Profile' })
    expect(within(profile).getByTestId('identity-label')).toHaveAttribute('aria-label', 'Marco, marco@e2e.local, Member')
    await waitFor(() => expect(calls('/api/account/activity')).toHaveLength(1))
  })
})

describe('profile: name, and the email with the current password', () => {
  test('renaming sends the name alone', async () => {
    renderPage()
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'Marco R' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save name' }))
    await waitFor(() => expect(screen.getByText('Your name was saved.')).toBeInTheDocument())
    const [, init] = calls('/api/users/member-1', 'PUT')[0]
    expect(JSON.parse(String((init as RequestInit).body))).toEqual({ name: 'Marco R' })
    expect((init as RequestInit).headers).toMatchObject({ 'Content-Type': 'application/json' })
  })

  test('an email change asks for the current password before sending', async () => {
    renderPage()
    fireEvent.change(screen.getByLabelText('New sign-in email'), { target: { value: 'Marco.New@e2e.local' } })
    fireEvent.click(screen.getByRole('button', { name: 'Change email' }))
    expect(await screen.findByText('Enter your current password to change your email.')).toBeInTheDocument()
    expect(calls('/api/users/member-1', 'PUT')).toEqual([])
  })

  test('with it: sent together, confirmed in the app dialog, then the page reloads', async () => {
    h.put.body = { id: 'member-1', name: 'Marco', email: 'marco.new@e2e.local' }
    renderPage()
    fireEvent.change(screen.getByLabelText('New sign-in email'), { target: { value: 'Marco.New@e2e.local' } })
    fireEvent.change(screen.getByLabelText('Current password for the email change'), { target: { value: 'my-current-pass-1' } })
    // Enter submits the form.
    fireEvent.submit(screen.getByLabelText('New sign-in email').closest('form')!)
    const dialog = await screen.findByRole('dialog', { name: 'Sign-in email changed' })
    expect(dialog).toHaveTextContent('marco.new@e2e.local')
    const [, init] = calls('/api/users/member-1', 'PUT')[0]
    expect(JSON.parse(String((init as RequestInit).body))).toEqual({ email: 'Marco.New@e2e.local', currentPassword: 'my-current-pass-1' })
    fireEvent.click(within(dialog).getByRole('button', { name: 'OK' }))
    await waitFor(() => expect(h.reload).toHaveBeenCalledTimes(1))
  })

  test('a refusal shows the server answer (wrong password, address taken) and keeps the form', async () => {
    h.put = { status: 409, body: { error: 'A user with this email already exists', code: 'email_taken' } }
    renderPage()
    fireEvent.change(screen.getByLabelText('New sign-in email'), { target: { value: 'taken@e2e.local' } })
    fireEvent.change(screen.getByLabelText('Current password for the email change'), { target: { value: 'pw-123456789012' } })
    fireEvent.click(screen.getByRole('button', { name: 'Change email' }))
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('A user with this email already exists')
    expect(alert).toHaveTextContent('email_taken')
    expect(screen.getByLabelText('New sign-in email')).toHaveValue('taken@e2e.local')
    expect(h.reload).not.toHaveBeenCalled()
  })
})

describe('sessions and tokens', () => {
  test('Sign out everywhere asks first in the app dialog; cancelled, nothing is sent', async () => {
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: 'Sign out everywhere' }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(calls('/api/auth/sessions/revoke-all', 'POST')).toEqual([])
  })

  test('confirmed: a same-origin JSON POST, then the sign-in page', async () => {
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: 'Sign out everywhere' }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Sign out everywhere' }))
    await waitFor(() => expect(h.assign).toHaveBeenCalledWith('/login'))
    const [, init] = calls('/api/auth/sessions/revoke-all', 'POST')[0]
    expect((init as RequestInit).body).toBe('{}')
    expect((init as RequestInit).headers).toMatchObject({ 'Content-Type': 'application/json' })
  })

  test('a failed sign-out says why and stays', async () => {
    h.revoke = { status: 500, body: { error: 'Could not sign out everywhere', code: 'P1001' } }
    renderPage()
    fireEvent.click(screen.getByRole('button', { name: 'Sign out everywhere' }))
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Sign out everywhere' }))
    expect(await screen.findByText(/Could not sign out everywhere/)).toBeInTheDocument()
    expect(h.assign).not.toHaveBeenCalled()
  })

  test('a link to the MCP tokens', () => {
    renderPage()
    expect(screen.getByRole('link', { name: 'Manage your MCP tokens' })).toHaveAttribute('href', '/settings?tab=mcp-tokens')
  })
})

describe('My activity', () => {
  test('loading, then the notices and the events, newest first, with who did it', async () => {
    h.activity.body = {
      notices: [{ id: 'n1', type: 'email_changed', at: '2026-11-12T10:00:00.000Z', by: { name: 'Laura', email: 'laura@e2e.local' }, from: 'a@e2e.local', to: 'marco@e2e.local', self: false, shownAt: null }],
      events: [
        { id: 'e2', at: '2026-11-12T10:00:00.000Z', action: 'user.email_changed', by: { name: 'Laura', email: 'laura@e2e.local' }, details: { from: 'a@e2e.local', to: 'marco@e2e.local' } },
        { id: 'e1', at: '2026-11-11T10:00:00.000Z', action: 'act_as.start', by: { name: 'Laura', email: 'laura@e2e.local' }, details: {} },
        { id: 'e0', at: '2026-11-10T10:00:00.000Z', action: 'user.credentials_reset', by: null, details: { mode: 'link', reason: 'Locked out', mustChangePassword: false } },
      ],
    }
    renderPage()
    const region = screen.getByRole('region', { name: 'My activity' })
    expect(within(region).getByRole('status')).toHaveTextContent('Loading your activity')
    const items = await within(region).findAllByRole('listitem')
    const text = items.map((i) => i.textContent)
    expect(text[0]).toMatch(/Your sign-in email was changed from a@e2e\.local to marco@e2e\.local/)
    expect(text[0]).toMatch(/new/i)
    expect(text[1]).toMatch(/Sign-in email changed from a@e2e\.local to marco@e2e\.local.*Laura \(laura@e2e\.local\)/)
    expect(text[2]).toMatch(/An admin started acting as you.*Laura \(laura@e2e\.local\)/)
    expect(text[3]).toMatch(/Password reset with a reset link.*Locked out/)
  })

  test('nothing yet', async () => {
    renderPage()
    expect(await screen.findByText('Nothing to show yet.')).toBeInTheDocument()
  })

  test('a failure says why, and Retry reads again', async () => {
    h.activity = { status: 500, body: { error: 'Could not read your activity', code: 'P2021' } }
    renderPage()
    const region = screen.getByRole('region', { name: 'My activity' })
    expect(await within(region).findByRole('alert')).toHaveTextContent('P2021')
    h.activity = { status: 200, body: { notices: [], events: [] } }
    fireEvent.click(within(region).getByRole('button', { name: 'Retry' }))
    expect(await within(region).findByText('Nothing to show yet.')).toBeInTheDocument()
    expect(calls('/api/account/activity')).toHaveLength(2)
  })
})

describe('Root', () => {
  test('the confirmed Root may offer Root to another admin from here', async () => {
    h.auth.user = member({ id: 'member-1', role: 'admin', accountType: 'root', rbac: { compat: false, legacyGrantsPending: 0, identity: true, root: { email: 'marco@e2e.local', confirmed: true, chosenAt: null } } })
    h.users = [
      { id: 'member-1', name: 'Marco', email: 'marco@e2e.local', role: 'admin', hasPassword: true, status: 'active' },
      { id: 'admin-2', name: 'Pia', email: 'pia@e2e.local', role: 'admin', hasPassword: true, status: 'active' },
    ]
    renderPage()
    expect(screen.getByRole('button', { name: 'Transfer Root' })).toBeInTheDocument()
  })

  test('an admin or a member has no such action', () => {
    renderPage()
    expect(screen.queryByRole('button', { name: 'Transfer Root' })).toBeNull()
  })
})

describe('while the password must change', () => {
  test('only the password form: no profile, no activity read', async () => {
    h.search = new URLSearchParams('changePassword=1')
    renderPage()
    expect(screen.getByLabelText('Current password')).toBeInTheDocument()
    expect(screen.queryByRole('region', { name: 'Profile' })).toBeNull()
    expect(screen.queryByRole('region', { name: 'My activity' })).toBeNull()
    await waitFor(() => expect(calls('/api/auth/password-policy')).toHaveLength(1))
    expect(calls('/api/account/activity')).toEqual([])
  })
})

describe('switch off: the step 2.8 page', () => {
  test('the password form alone; no activity, profile or sign-out', async () => {
    h.auth.user = member({ accountType: undefined, flags: { identity: false } })
    renderPage()
    expect(screen.getByLabelText('Current password')).toBeInTheDocument()
    expect(screen.queryByRole('region', { name: 'Profile' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Sign out everywhere' })).toBeNull()
    expect(screen.queryByRole('region', { name: 'My activity' })).toBeNull()
    // Step 3.13: off, the policy route answers 404 (an error in the console): not asked.
    await new Promise((r) => setTimeout(r, 10))
    expect(calls('/api/auth/password-policy')).toEqual([])
    expect(calls('/api/account/activity')).toEqual([])
  })
})
