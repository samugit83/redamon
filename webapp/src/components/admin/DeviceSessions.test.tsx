/**
 * The device sessions list (step 6.10, GV-17, UI-09; DV-06, DV-19): each browser with its address,
 * browser and last activity; "This device" for the browser asking (no Revoke: Sign out ends it);
 * Revoke on the other live ones, confirmed in the app's dialog (useAlertModal), or with the admin's
 * own password for another admin's; ended ones listed without an action; the agent not confirming
 * the socket close is said; loading, error + Retry, denied and empty states; labelled controls.
 *
 * Run: npx vitest run --no-file-parallelism src/components/admin/DeviceSessions.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor, within } from '@testing-library/react'
import { AlertProvider } from '@/components/ui'
import { DeviceSessions, describeUserAgent, type DeviceSessionItem } from './DeviceSessions'

const FIREFOX = 'Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0'
const CHROME_WIN = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36'
const row = (over: Partial<DeviceSessionItem>): DeviceSessionItem => ({
  id: 'sess-1', createdAt: '2026-11-13T08:00:00.000Z', lastSeenAt: '2026-11-13T11:00:00.000Z', expiresAt: '2026-11-20T08:00:00.000Z',
  ip: '203.0.113.7', ipTrusted: true, userAgent: FIREFOX, state: 'active', revokedAt: null, current: false, ...over,
})
const SESSIONS = [
  row({ id: 'here', current: true }),
  row({ id: 'phone', userAgent: CHROME_WIN, ip: '198.51.100.9', ipTrusted: false }),
  row({ id: 'gone', state: 'revoked', revokedAt: '2026-11-13T09:00:00.000Z' }),
]

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
let list: () => Response
let revokeAnswer: () => Response
let fetchMock: ReturnType<typeof vi.fn>

beforeEach(() => {
  list = () => json({ sessions: SESSIONS })
  revokeAnswer = () => json({ id: 'phone', changed: true, state: 'revoked', agent: { sockets: { closed: 1 } } })
  fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
    if (init?.method === 'DELETE') return revokeAnswer()
    if (url === '/api/account/sessions' || url === '/api/users/u-2/sessions') return list()
    throw new Error(`unexpected fetch ${url}`)
  })
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

const mine = () => render(
  <AlertProvider>
    <DeviceSessions listUrl="/api/account/sessions" revokeUrl={(id) => `/api/account/sessions/${id}`} subject="self" />
  </AlertProvider>,
)
const theirs = (stepUp = false) => render(
  <AlertProvider>
    <DeviceSessions listUrl="/api/users/u-2/sessions" revokeUrl={(id) => `/api/users/u-2/sessions/${id}`} subject={{ name: 'Nina' }} stepUp={stepUp} />
  </AlertProvider>,
)
const deletes = () => fetchMock.mock.calls.filter(([, init]) => (init as RequestInit | undefined)?.method === 'DELETE')
const dialog = () => screen.findByRole('dialog')

describe('the list', () => {
  test('each browser with its address, label and state; "This device" first; Revoke only on the other live ones', async () => {
    mine()
    const items = within(await screen.findByRole('list', { name: 'Your device sessions' })).getAllByRole('listitem')
    expect(items).toHaveLength(3)
    expect(items[0]).toHaveTextContent('Firefox on Linux')
    expect(items[0]).toHaveTextContent('This device')
    expect(within(items[0]).queryByRole('button')).toBeNull()
    expect(items[1]).toHaveTextContent('Chrome on Windows')
    expect(items[1]).toHaveTextContent('198.51.100.9 (address not verified)')
    expect(within(items[1]).getByRole('button', { name: /^Revoke the session of Chrome on Windows, last active / })).toBeInTheDocument()
    expect(items[2]).toHaveTextContent('Revoked')
    expect(within(items[2]).queryByRole('button')).toBeNull()
  })

  test('loading, then empty', async () => {
    list = () => json({ sessions: [] })
    mine()
    expect(screen.getByRole('status')).toHaveTextContent('Loading sessions')
    expect(await screen.findByText(/No device session is recorded for your account yet/)).toBeInTheDocument()
  })

  test('a refused read names the permission (denied state)', async () => {
    list = () => json({ error: 'Forbidden', code: 'forbidden', permission: 'users:revoke_sessions' }, 403)
    theirs()
    expect(await screen.findByText('users:revoke_sessions')).toBeInTheDocument()
  })

  test('a failed read: the error with its code, and Retry reads again', async () => {
    list = () => json({ error: 'Could not read', code: 'P1001' }, 500)
    mine()
    expect(await screen.findByRole('alert')).toHaveTextContent('P1001')
    list = () => json({ sessions: SESSIONS })
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByRole('list', { name: 'Your device sessions' })).toBeInTheDocument()
  })
})

describe('revoke one leaves the others', () => {
  test('confirmed in the dialog: one DELETE for that session, the list read again', async () => {
    mine()
    fireEvent.click(await screen.findByRole('button', { name: /^Revoke the session of Chrome on Windows/ }))
    const confirm = await dialog()
    expect(confirm).toHaveTextContent('the other browsers stay signed in')
    list = () => json({ sessions: [SESSIONS[0], { ...SESSIONS[1], state: 'revoked' }, SESSIONS[2]] })
    fireEvent.click(within(confirm).getByRole('button', { name: 'Revoke' }))
    await waitFor(() => expect(deletes()).toEqual([['/api/account/sessions/phone', { method: 'DELETE' }]]))
    await waitFor(() => expect(screen.queryByRole('button', { name: /^Revoke the session of/ })).toBeNull())
  })

  test('cancelled: nothing is sent', async () => {
    mine()
    fireEvent.click(await screen.findByRole('button', { name: /^Revoke the session of Chrome on Windows/ }))
    fireEvent.click(within(await dialog()).getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(deletes()).toEqual([])
  })

  test('the agent did not confirm the socket close: the revoke stands and the person is told', async () => {
    revokeAnswer = () => json({ id: 'phone', changed: true, state: 'revoked', agent: { sockets: { error: 'agent_unreachable' } } })
    mine()
    fireEvent.click(await screen.findByRole('button', { name: /^Revoke the session of Chrome on Windows/ }))
    fireEvent.click(within(await dialog()).getByRole('button', { name: 'Revoke' }))
    expect(await screen.findByText(/did not confirm that its open agent and terminal connections closed \(agent_unreachable\)/)).toBeInTheDocument()
  })

  test('a refused revoke: an error dialog with the code', async () => {
    revokeAnswer = () => json({ error: 'Session not found', code: 'session_not_found' }, 404)
    mine()
    fireEvent.click(await screen.findByRole('button', { name: /^Revoke the session of Chrome on Windows/ }))
    fireEvent.click(within(await dialog()).getByRole('button', { name: 'Revoke' }))
    expect(await screen.findByText(/session_not_found/)).toBeInTheDocument()
  })

  test('another admin\'s session: the admin\'s own password, sent with the revoke', async () => {
    theirs(true)
    fireEvent.click(await screen.findByRole('button', { name: /^Revoke the session of Chrome on Windows/ }))
    const modal = await dialog()
    expect(modal).toHaveTextContent('Confirm with your own password')
    fireEvent.change(within(modal).getByLabelText('Your password'), { target: { value: 'my-own-pass' } })
    fireEvent.click(within(modal).getByRole('button', { name: 'Revoke' }))
    await waitFor(() => expect(deletes()).toEqual([[
      '/api/users/u-2/sessions/phone',
      { method: 'DELETE', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ stepUpPassword: 'my-own-pass' }) },
    ]]))
  })

  test('another account\'s list is labelled with its name; no session is "This device" there', async () => {
    list = () => json({ sessions: SESSIONS.map((s) => ({ ...s, current: false })) })
    theirs()
    const items = within(await screen.findByRole('list', { name: 'Device sessions of Nina' })).getAllByRole('listitem')
    expect(items[0]).not.toHaveTextContent('This device')
    expect(within(items[0]).getByRole('button', { name: /^Revoke the session of Firefox on Linux/ })).toBeInTheDocument()
  })
})

describe('the browser label', () => {
  test.each([
    [FIREFOX, 'Firefox on Linux'],
    [CHROME_WIN, 'Chrome on Windows'],
    ['Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/130.0 Safari/537.36 Edg/130.0', 'Edge on Windows'],
    ['Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 Version/18.0 Safari/605.1.15', 'Safari on macOS'],
    ['Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Version/18.0 Mobile Safari/604.1', 'Safari on iOS'],
    ['Mozilla/5.0 (Linux; Android 15) AppleWebKit/537.36 Chrome/130.0 Mobile Safari/537.36', 'Chrome on Android'],
    ['curl/8.5.0', 'curl'],
    [null, 'Unknown browser'],
    ['something else', 'Unknown browser'],
  ])('%s -> %s', (ua, label) => {
    expect(describeUserAgent(ua)).toBe(label)
  })
})
