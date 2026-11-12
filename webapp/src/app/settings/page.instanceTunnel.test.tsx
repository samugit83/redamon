/**
 * Global Settings → Tunneling with the identity switch on (step 2.4, UI-04 gating part):
 * the settings GET answers `sharedSettingsAt: 'instance'`, so the tunnel is read and saved
 * through /api/admin/instance-settings with a Save of its own, the page's own save and key
 * import leave the four tunnel fields out, and an account that may not change the tunnel
 * sees its status. A new chisel URL asks for the password in the step-up dialog.
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

type Answer = { status: number; body: unknown }
let routes: Record<string, Answer | ((init?: RequestInit) => Answer)>
const fetchMock = vi.fn()

const BASE = '/api/users/user-1'
const INSTANCE = '/api/admin/instance-settings'
const URL_PLACEHOLDER = 'e.g. http://your-vps.com:9090'
// The member row (what the user GET answers): no tunnel of its own.
const USER_ROW = {
  shodanApiKey: '••••••••ab12', tunnelsEnabled: false, ngrokAuthtoken: '', chiselServerUrl: '', chiselAuth: '',
  rotationConfigs: {}, canManageTunnels: false, sharedSettingsAt: 'instance',
}
const INSTANCE_TUNNEL = {
  tunnelsEnabled: true, ngrokAuthtoken: '', chiselServerUrl: 'http://vps.example:9090', chiselAuth: '••••••••pass',
  canManageTunnels: true, canManageCapture: true,
}

beforeEach(() => {
  vi.clearAllMocks()
  routes = {
    [`GET ${BASE}/settings`]: { status: 200, body: USER_ROW },
    [`GET ${BASE}/settings/api-usage`]: { status: 200, body: { enabled: true, report: null, running: null, runBy: null, activity: null, tracked: [] } },
    [`GET ${INSTANCE}`]: { status: 200, body: INSTANCE_TUNNEL },
    [`PUT ${INSTANCE}`]: (init) => ({ status: 200, body: { ...INSTANCE_TUNNEL, ...JSON.parse(String(init?.body)), chiselAuth: '••••••••pass' } }),
    'GET /api/agent/tunnel-status': { status: 200, body: { ngrok: { active: false }, chisel: { active: true } } },
  }
  fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
    const key = `${init?.method ?? 'GET'} ${url}`
    const a = routes[key]
    if (a) {
      const { status, body } = typeof a === 'function' ? a(init) : a
      return new Response(JSON.stringify(body), { status })
    }
    if (key.startsWith('PUT ')) return new Response(JSON.stringify(USER_ROW), { status: 200 })
    return new Response('[]', { status: 200 })
  })
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

const renderPage = () => render(<ToastProvider><SettingsPage /></ToastProvider>)
const putsTo = (url: string) => fetchMock.mock.calls
  .filter(c => c[0] === url && (c[1] as RequestInit | undefined)?.method === 'PUT')
  .map(c => JSON.parse(String((c[1] as RequestInit).body)) as Record<string, unknown>)

describe('Tunneling as an instance setting', () => {
  test('the Tunneling section talks to the admin route: its values, its own save', async () => {
    renderPage()
    const url = await screen.findByPlaceholderText(URL_PLACEHOLDER)
    expect(url).toHaveValue('http://vps.example:9090')
    expect(screen.getByLabelText('Enable tunnels')).toBeChecked()
    fireEvent.click(screen.getByLabelText('Enable tunnels'))
    fireEvent.click(screen.getByRole('button', { name: 'Save tunnel settings' }))
    await waitFor(() => expect(putsTo(INSTANCE)).toHaveLength(1))
    expect(putsTo(INSTANCE)[0]).toMatchObject({ tunnelsEnabled: false, chiselServerUrl: 'http://vps.example:9090', chiselAuth: '••••••••pass' })
    expect(putsTo(`${BASE}/settings`)).toEqual([])
  })

  test('the page\'s own save sends no tunnel field', async () => {
    renderPage()
    await screen.findByPlaceholderText(URL_PLACEHOLDER)
    fireEvent.change(await screen.findByPlaceholderText('Enter shodan api key'), { target: { value: 'new-shodan-key' } })
    fireEvent.click(await screen.findByRole('button', { name: 'Save Settings' }))
    await waitFor(() => expect(putsTo(`${BASE}/settings`)).toHaveLength(1))
    const sent = putsTo(`${BASE}/settings`)[0]
    expect(sent.shodanApiKey).toBe('new-shodan-key')
    for (const f of ['tunnelsEnabled', 'ngrokAuthtoken', 'chiselServerUrl', 'chiselAuth']) expect(sent).not.toHaveProperty(f)
    expect(putsTo(INSTANCE)).toEqual([])
  })

  test('a new chisel URL asks for the password and sends it with the same save', async () => {
    routes[`PUT ${INSTANCE}`] = (init) => {
      const body = JSON.parse(String(init?.body))
      return body.stepUpPassword === 'my-password'
        ? { status: 200, body: { ...INSTANCE_TUNNEL, chiselServerUrl: body.chiselServerUrl } }
        : { status: 403, body: { error: 'Enter your password to confirm this action.', code: 'step_up_required' } }
    }
    renderPage()
    fireEvent.change(await screen.findByPlaceholderText(URL_PLACEHOLDER), { target: { value: 'http://vps2.example:9090' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save tunnel settings' }))
    const dialog = await screen.findByText(/Moving the tunnel to another server/)
    expect(dialog).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('Your password'), { target: { value: 'my-password' } })
    fireEvent.click(screen.getAllByRole('button', { name: 'Save tunnel settings' }).at(-1)!)
    await waitFor(() => expect(putsTo(INSTANCE)).toHaveLength(2))
    expect(putsTo(INSTANCE)[1]).toMatchObject({ chiselServerUrl: 'http://vps2.example:9090', stepUpPassword: 'my-password' })
  })

  test('an account the route refuses sees the tunnel status, not the controls', async () => {
    routes[`GET ${INSTANCE}`] = { status: 403, body: { error: 'Only an administrator changes the instance settings.', code: 'forbidden' } }
    renderPage()
    expect(await screen.findByText('The tunnel is managed by an administrator.')).toBeInTheDocument()
    expect(await screen.findByText(/On \(chisel\)/)).toBeInTheDocument()
    expect(screen.queryByPlaceholderText(URL_PLACEHOLDER)).toBeNull()
  })

  test('a failed load says so and offers a retry', async () => {
    routes[`GET ${INSTANCE}`] = { status: 503, body: { error: 'The instance settings are not ready', code: 'instance_settings_unavailable' } }
    renderPage()
    expect(await screen.findByText(/Couldn't load the tunnel settings/)).toBeInTheDocument()
    routes[`GET ${INSTANCE}`] = { status: 200, body: INSTANCE_TUNNEL }
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByPlaceholderText(URL_PLACEHOLDER)).toBeInTheDocument()
  })
})
