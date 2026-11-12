/**
 * Global Settings → Tunneling (HD-06, UI-03). The tunnel is one listener for the whole
 * instance: only an admin, the member who kept the legacy grant, or a pre-upgrade
 * account under the escape hatch may change it (the settings GET says so in
 * `canManageTunnels`). Everyone else sees its status, read from the login-only
 * /api/agent/tunnel-status, and who manages it; their saves and imports leave the four
 * tunnel fields out, so the PUT never refuses an ordinary save of their own keys.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'
import { ToastProvider } from '@/components/ui/Toast/Toast'

vi.mock('next/navigation', () => ({
  useSearchParams: () => new URLSearchParams('tab=keys'),
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), refresh: vi.fn(), back: vi.fn(), prefetch: vi.fn() }),
  usePathname: () => '/settings',
}))
vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: 'user-1' }) }))

const alertSpies = vi.hoisted(() => ({
  alert: vi.fn(async () => {}),
  alertError: vi.fn(async () => {}),
  alertWarning: vi.fn(async () => {}),
  confirm: vi.fn(async () => true),
  dangerConfirm: vi.fn(async () => true),
}))
vi.mock('@/components/ui/AlertModal/AlertModal', async orig => ({
  ...((await orig()) as Record<string, unknown>),
  useAlertModal: () => alertSpies,
}))
vi.mock('@/components/ui', async orig => ({
  ...((await orig()) as Record<string, unknown>),
  useAlertModal: () => alertSpies,
}))

const SettingsPage = (await import('./page')).default

type Answer = { status: number; body: unknown } | (() => never)
let routes: Record<string, Answer>
const fetchMock = vi.fn()

const BASE = '/api/users/user-1'
const URL_PLACEHOLDER = 'e.g. http://your-vps.com:9090'
const STORED_TUNNEL = {
  tunnelsEnabled: true, ngrokAuthtoken: '••••••••-tok', chiselServerUrl: 'http://vps.example:9090', chiselAuth: '••••••••pass',
}

function settingsBody(canManageTunnels: boolean) {
  return { shodanApiKey: '••••••••ab12', ...STORED_TUNNEL, rotationConfigs: {}, canManageTunnels }
}

beforeEach(() => {
  vi.clearAllMocks()
  routes = {
    [`GET ${BASE}/settings`]: { status: 200, body: settingsBody(false) },
    [`GET ${BASE}/settings/api-usage`]: { status: 200, body: { enabled: true, report: null, running: null, runBy: null, activity: null, tracked: [] } },
    [`GET ${BASE}/llm-providers`]: { status: 200, body: [] },
    [`GET ${BASE}/chat-skills`]: { status: 200, body: [] },
    [`GET ${BASE}/tradecraft-resources`]: { status: 200, body: [] },
    'GET /api/agent/tunnel-status': { status: 200, body: { ngrok: { active: false }, chisel: { active: true, host: 'vps.example', port: 4444 } } },
  }
  fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
    const key = `${init?.method ?? 'GET'} ${url}`
    const a = routes[key]
    if (a) {
      const { status, body } = typeof a === 'function' ? a() : a
      return new Response(JSON.stringify(body), { status })
    }
    if (key.startsWith('PUT ')) return new Response(JSON.stringify(settingsBody(false)), { status: 200 })
    return new Response('[]', { status: 200 })
  })
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

const renderPage = () => render(<ToastProvider><SettingsPage /></ToastProvider>)
const putBodies = () => fetchMock.mock.calls
  .filter(c => (c[1] as RequestInit | undefined)?.method === 'PUT')
  .map(c => JSON.parse(String((c[1] as RequestInit).body)) as Record<string, unknown>)

describe('Tunneling for an account that may not change it', () => {
  test('tunnel section read-only without access', async () => {
    renderPage()
    expect(await screen.findByText('The tunnel is managed by an administrator.')).toBeInTheDocument()
    expect(await screen.findByText(/On \(chisel\)/)).toBeInTheDocument()
    expect(screen.queryByPlaceholderText(URL_PLACEHOLDER)).toBeNull()
    expect(screen.queryByLabelText('Enable tunnels')).toBeNull()
    expect(screen.queryByText('ngrok Auth Token')).toBeNull()
    expect(fetchMock).toHaveBeenCalledWith('/api/agent/tunnel-status', expect.anything())
  })

  test('no tunnel up reads as off', async () => {
    routes['GET /api/agent/tunnel-status'] = { status: 200, body: { ngrok: { active: false }, chisel: { active: false } } }
    renderPage()
    expect(await screen.findByText(/^Off$/)).toBeInTheDocument()
  })

  test('a status that cannot be read says so', async () => {
    routes['GET /api/agent/tunnel-status'] = () => { throw new TypeError('Failed to fetch') }
    renderPage()
    expect(await screen.findByText(/Status unavailable/)).toBeInTheDocument()
    expect(screen.getByText('The tunnel is managed by an administrator.')).toBeInTheDocument()
  })

  test('a save of their own keys leaves the four tunnel fields out', async () => {
    renderPage()
    await screen.findByText('The tunnel is managed by an administrator.')
    fireEvent.change(await screen.findByPlaceholderText('Enter shodan api key'), { target: { value: 'new-shodan-key' } })
    fireEvent.click(await screen.findByRole('button', { name: 'Save Settings' }))
    await waitFor(() => expect(putBodies()).toHaveLength(1))
    const sent = putBodies()[0]
    expect(sent.shodanApiKey).toBe('new-shodan-key')
    for (const f of ['tunnelsEnabled', 'ngrokAuthtoken', 'chiselServerUrl', 'chiselAuth']) expect(sent).not.toHaveProperty(f)
  })
})

describe('Tunneling for an account that may change it', () => {
  test('the controls are there and a save sends them', async () => {
    routes[`GET ${BASE}/settings`] = { status: 200, body: settingsBody(true) }
    routes[`PUT ${BASE}/settings`] = { status: 200, body: settingsBody(true) }
    renderPage()
    const url = await screen.findByPlaceholderText(URL_PLACEHOLDER)
    expect(screen.queryByText('The tunnel is managed by an administrator.')).toBeNull()
    fireEvent.change(url, { target: { value: 'http://vps2.example:9090' } })
    fireEvent.click(await screen.findByRole('button', { name: 'Save Settings' }))
    await waitFor(() => expect(putBodies()).toHaveLength(1))
    expect(putBodies()[0]).toMatchObject({ chiselServerUrl: 'http://vps2.example:9090', tunnelsEnabled: true })
  })

  test('an answer without the hint keeps the controls: the PUT decides', async () => {
    routes[`GET ${BASE}/settings`] = { status: 200, body: { ...STORED_TUNNEL, rotationConfigs: {} } }
    renderPage()
    expect(await screen.findByPlaceholderText(URL_PLACEHOLDER)).toBeInTheDocument()
  })
})
