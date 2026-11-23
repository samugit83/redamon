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
const {
  CHISEL_FORWARDS, NGROK_TOKEN_HINT, TUNNEL_BOTH_SWITCHES, TUNNEL_ENABLE_HINT, TUNNEL_NEVER_ACTING_AS, TUNNEL_REACHES,
  TUNNEL_SECTION_HINT_MANAGE, TUNNEL_SECTION_HINT_READ,
} = await import('@/components/settings/tunnelTexts')

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

// Every tunnel is its person's own, in their own Kali sandbox (group 1): an answer without the
// `tunnelScope` hint is read the same way.
describe('Tunneling for an account that may not change it', () => {
  test('tunnel section read-only without access: the person\'s own status, never "managed by an administrator"', async () => {
    renderPage()
    expect(await screen.findByText(/Turning one on needs the Tunnels permission/)).toBeInTheDocument()
    expect(screen.queryByText('The tunnel is managed by an administrator.')).toBeNull()
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
    expect(screen.getByText(/Turning one on needs the Tunnels permission/)).toBeInTheDocument()
  })

  test('a save of their own keys leaves the four tunnel fields out', async () => {
    renderPage()
    await screen.findByText(/Turning one on needs the Tunnels permission/)
    fireEvent.change(await screen.findByPlaceholderText('Enter shodan api key'), { target: { value: 'new-shodan-key' } })
    fireEvent.click(await screen.findByRole('button', { name: 'Save Settings' }))
    await waitFor(() => expect(putBodies()).toHaveLength(1))
    const sent = putBodies()[0]
    expect(sent.shodanApiKey).toBe('new-shodan-key')
    for (const f of ['tunnelsEnabled', 'ngrokAuthtoken', 'chiselServerUrl', 'chiselAuth']) expect(sent).not.toHaveProperty(f)
  })
})

describe('Tunneling for an account that may change it', () => {
  test('the controls are there and a save sends them (the toggle only once touched)', async () => {
    routes[`GET ${BASE}/settings`] = { status: 200, body: settingsBody(true) }
    routes[`PUT ${BASE}/settings`] = { status: 200, body: settingsBody(true) }
    renderPage()
    const url = await screen.findByPlaceholderText(URL_PLACEHOLDER)
    expect(screen.queryByText('The tunnel is managed by an administrator.')).toBeNull()
    fireEvent.change(url, { target: { value: 'http://vps2.example:9090' } })
    fireEvent.click(await screen.findByRole('button', { name: 'Save Settings' }))
    await waitFor(() => expect(putBodies()).toHaveLength(1))
    expect(putBodies()[0]).toMatchObject({ chiselServerUrl: 'http://vps2.example:9090' })
    expect(putBodies()[0]).not.toHaveProperty('tunnelsEnabled')
  })

  test('the identity switch on (`sharedSettingsAt: instance`) moves no tunnel: the controls stay the person\'s own, nothing goes to the instance settings', async () => {
    routes[`GET ${BASE}/settings`] = { status: 200, body: { ...settingsBody(true), sharedSettingsAt: 'instance' } }
    routes[`PUT ${BASE}/settings`] = { status: 200, body: settingsBody(true) }
    renderPage()
    const url = await screen.findByPlaceholderText(URL_PLACEHOLDER)
    expect(screen.queryByText(/shared by the whole instance|Instance page/)).toBeNull()
    fireEvent.change(url, { target: { value: 'http://vps2.example:9090' } })
    fireEvent.click(await screen.findByRole('button', { name: 'Save Settings' }))
    await waitFor(() => expect(putBodies()).toHaveLength(1))
    expect(putBodies()[0]).toMatchObject({ chiselServerUrl: 'http://vps2.example:9090' })
    expect(fetchMock.mock.calls.some(([u]) => String(u) === '/api/admin/instance-settings')).toBe(false)
  })

  test('an answer without the hint keeps the controls: the PUT decides', async () => {
    routes[`GET ${BASE}/settings`] = { status: 200, body: { ...STORED_TUNNEL, rotationConfigs: {} } }
    renderPage()
    expect(await screen.findByPlaceholderText(URL_PLACEHOLDER)).toBeInTheDocument()
  })
})

describe('per-person tunnels (group 1: per-user Kali sandboxes)', () => {
  const perPerson = (canManageTunnels: boolean, over: Record<string, unknown> = {}) =>
    ({ ...settingsBody(canManageTunnels), tunnelScope: 'own_sandbox', sharedSettingsAt: 'instance', ...over })

  test('the controls are the person\'s own, even with the identity switch on, and say the tunnel runs in their sandbox and stops with it', async () => {
    routes[`GET ${BASE}/settings`] = { status: 200, body: perPerson(true) }
    renderPage()
    expect(await screen.findByPlaceholderText(URL_PLACEHOLDER)).toBeInTheDocument()
    expect(screen.getByText(/runs in your own Kali sandbox/)).toBeInTheDocument()
    expect(screen.getByText(/turned off whenever your sandbox restarts/)).toBeInTheDocument()
    expect(fetchMock).not.toHaveBeenCalledWith('/api/admin/instance-settings', expect.anything())
  })

  test('FU-27: both switches, what the tunnel reaches (4444, never the pool port), and no tunnel under act-as', async () => {
    routes[`GET ${BASE}/settings`] = { status: 200, body: perPerson(true) }
    renderPage()
    await screen.findByPlaceholderText(URL_PLACEHOLDER)
    const text = document.body.textContent ?? ''
    expect(screen.getByText(TUNNEL_SECTION_HINT_MANAGE)).toBeInTheDocument()
    for (const line of [TUNNEL_BOTH_SWITCHES, TUNNEL_REACHES, TUNNEL_NEVER_ACTING_AS]) expect(TUNNEL_SECTION_HINT_MANAGE).toContain(line)
    expect(TUNNEL_BOTH_SWITCHES).toMatch(/your own tunnel is on here AND the project's Tunnel Provider/)
    expect(TUNNEL_REACHES).toMatch(/reaches port 4444 inside it; your sandbox's port from the operator's port pool.*is reached directly, without a tunnel/)
    // Round 2: act-as never turns a tunnel on and its sandbox never uses one; the people's own tunnels keep running.
    expect(TUNNEL_NEVER_ACTING_AS).toBe(
      'While you act as another person, that work runs in a separate act-as sandbox that never uses a tunnel, and no tunnel can be turned on (turning one off still works).',
    )
    expect(text).not.toMatch(/act as another person, no tunnel runs/)
    expect(screen.getByText(TUNNEL_ENABLE_HINT)).toBeInTheDocument()
    expect(text).toContain(NGROK_TOKEN_HINT)
    expect(text).toContain(CHISEL_FORWARDS)
    expect(text).not.toMatch(/exposes its reverse-shell listener|The tunnel exposes your listener/)
  })

  test('FU-27: without the permission, the hint still names both switches and the act-as rule', async () => {
    routes[`GET ${BASE}/settings`] = { status: 200, body: perPerson(false) }
    renderPage()
    expect(await screen.findByText(TUNNEL_SECTION_HINT_READ)).toBeInTheDocument()
    expect(TUNNEL_SECTION_HINT_READ).toContain(TUNNEL_BOTH_SWITCHES)
    expect(TUNNEL_SECTION_HINT_READ).toContain(TUNNEL_NEVER_ACTING_AS)
  })

  test('without the permission: their own tunnel\'s status, and a way to turn it off while it is on', async () => {
    routes[`GET ${BASE}/settings`] = { status: 200, body: perPerson(false) }
    renderPage()
    expect(await screen.findByText(/Turning one on needs the Tunnels permission/)).toBeInTheDocument()
    expect(screen.queryByText('The tunnel is managed by an administrator.')).toBeNull()
    expect(screen.queryByPlaceholderText(URL_PLACEHOLDER)).toBeNull()
    fireEvent.click(await screen.findByRole('button', { name: 'Turn my tunnel off' }))
    await waitFor(() => expect(putBodies()).toEqual([{ tunnelsEnabled: false }]))
  })

  test('a save that does not touch the toggle never sends it: a page left open across a sandbox restart cannot turn the tunnel back on', async () => {
    routes[`GET ${BASE}/settings`] = { status: 200, body: perPerson(true) }
    routes[`PUT ${BASE}/settings`] = { status: 200, body: perPerson(true) }
    renderPage()
    fireEvent.change(await screen.findByPlaceholderText('Enter shodan api key'), { target: { value: 'new-shodan-key' } })
    fireEvent.click(await screen.findByRole('button', { name: 'Save Settings' }))
    await waitFor(() => expect(putBodies()).toHaveLength(1))
    expect(putBodies()[0].shodanApiKey).toBe('new-shodan-key')
    expect(putBodies()[0]).not.toHaveProperty('tunnelsEnabled')
  })

  test('a save after the person toggled it sends it', async () => {
    routes[`GET ${BASE}/settings`] = { status: 200, body: perPerson(true, { tunnelsEnabled: false }) }
    routes[`PUT ${BASE}/settings`] = { status: 200, body: perPerson(true) }
    renderPage()
    fireEvent.click(await screen.findByLabelText('Enable tunnels'))
    fireEvent.click(await screen.findByRole('button', { name: 'Save Settings' }))
    await waitFor(() => expect(putBodies()).toHaveLength(1))
    expect(putBodies()[0].tunnelsEnabled).toBe(true)
  })

  test('without the permission, stored off and no tunnel running: nothing to turn off', async () => {
    routes[`GET ${BASE}/settings`] = { status: 200, body: perPerson(false, { tunnelsEnabled: false }) }
    routes['GET /api/agent/tunnel-status'] = { status: 200, body: { ngrok: { active: false }, chisel: { active: false } } }
    renderPage()
    await screen.findByText(/^Off$/)
    expect(screen.queryByRole('button', { name: 'Turn my tunnel off' })).toBeNull()
  })

  test.each([['without', false], ['with', true]])(
    '%s the permission, stored off while a tunnel still runs (a stop not delivered): the off control shows and resends the stop (review C3)',
    async (_name, canManage) => {
      routes[`GET ${BASE}/settings`] = { status: 200, body: perPerson(canManage, { tunnelsEnabled: false }) }
      renderPage()
      fireEvent.click(await screen.findByRole('button', { name: 'Turn my tunnel off' }))
      await waitFor(() => expect(putBodies()).toEqual([{ tunnelsEnabled: false }]))
    })
})
