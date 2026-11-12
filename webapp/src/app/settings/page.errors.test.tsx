/**
 * Global Settings: a failure shows its cause, and a failed load never feeds a save.
 *
 * The data-loss case first: when the settings GET failed, the form kept its
 * empty starting values and Save sent '' for every key. The PUT keeps a stored
 * key only when it comes back masked ('••••'), so that save wiped every saved
 * key. The page now says the load failed and refuses to save until one succeeds.
 *
 * The rest: deletes that toasted success whatever happened, lists that read a
 * failure as "nothing here", saves whose follow-up (kali-sandbox push) failed
 * silently, and messages that dropped the code and status the routes send.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor, within } from '@testing-library/react'
import { ToastProvider } from '@/components/ui/Toast/Toast'

const nav = vi.hoisted(() => ({ tab: 'keys' }))
vi.mock('next/navigation', () => ({
  useSearchParams: () => new URLSearchParams(`tab=${nav.tab}`),
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

type Answer = { status: number; body: unknown } | (() => { status: number; body: unknown })
/** Keyed by "METHOD url"; anything else answers a harmless empty 200. */
let routes: Record<string, Answer>
const fetchMock = vi.fn()

function answer(a: Answer) {
  const { status, body } = typeof a === 'function' ? a() : a
  return new Response(JSON.stringify(body), { status })
}

const BASE = '/api/users/user-1'
const API_USAGE = { enabled: true, report: null, running: null, runBy: null, activity: null, tracked: [] }

beforeEach(() => {
  vi.clearAllMocks()
  nav.tab = 'keys'
  routes = {
    [`GET ${BASE}/settings`]: { status: 200, body: { shodanApiKey: '••••••••ab12', rotationConfigs: {} } },
    [`GET ${BASE}/settings/api-usage`]: { status: 200, body: API_USAGE },
    [`GET ${BASE}/llm-providers`]: { status: 200, body: [] },
    [`GET ${BASE}/chat-skills`]: { status: 200, body: [] },
    [`GET ${BASE}/tradecraft-resources`]: { status: 200, body: [] },
  }
  fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
    const key = `${init?.method ?? 'GET'} ${url}`
    if (routes[key]) return answer(routes[key])
    if (url === '/api/models') return answer({ status: 200, body: {} })
    return answer({ status: 200, body: [] })
  })
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

const renderPage = () => render(<ToastProvider><SettingsPage /></ToastProvider>)
const puts = () => fetchMock.mock.calls.filter(c => (c[1] as RequestInit | undefined)?.method === 'PUT')

describe('U-1: a failed settings load never reaches a save', () => {
  test('the load error is shown with its cause, there is no Save, and nothing is written', async () => {
    routes[`GET ${BASE}/settings`] = { status: 500, body: { error: 'Failed to fetch user settings', code: 'P1001' } }
    renderPage()
    const banners = await screen.findAllByText(/Couldn't load your saved keys \(P1001 · HTTP 500\)\. Saving is off until they load/)
    expect(banners.length).toBeGreaterThan(0)
    expect(screen.queryByRole('button', { name: 'Save Settings' })).toBeNull()
    expect(screen.queryByPlaceholderText('e.g. http://your-vps.com:9090')).toBeNull()
    expect(puts()).toHaveLength(0)
  })

  test('Retry loads them, and only then can the form be edited and saved', async () => {
    routes[`GET ${BASE}/settings`] = { status: 503, body: { error: 'Failed to fetch user settings', code: 'P2024' } }
    renderPage()
    await screen.findAllByText(/Couldn't load your saved keys/)
    routes[`GET ${BASE}/settings`] = { status: 200, body: { shodanApiKey: '••••••••ab12', rotationConfigs: {} } }
    fireEvent.click(screen.getAllByRole('button', { name: 'Retry' })[0])
    const url = await screen.findByPlaceholderText('e.g. http://your-vps.com:9090')
    fireEvent.change(url, { target: { value: 'http://vps.example:9090' } })
    fireEvent.click(await screen.findByRole('button', { name: 'Save Settings' }))
    await waitFor(() => expect(puts()).toHaveLength(1))
    // The masked key goes back masked, so the route keeps the stored value.
    expect(JSON.parse(String((puts()[0][1] as RequestInit).body)).shodanApiKey).toBe('••••••••ab12')
  })

  test('a load that got no answer says so too', async () => {
    routes[`GET ${BASE}/settings`] = () => { throw new TypeError('Failed to fetch') }
    renderPage()
    expect((await screen.findAllByText(/Couldn't load your saved keys \(network_error\)/)).length).toBeGreaterThan(0)
  })
})

describe('the keys tab Save is in its header, never a scroll away', () => {
  test('there before any edit and disabled; an edit enables it and flags unsaved work; a save clears both', async () => {
    renderPage()
    const save = await screen.findByRole('button', { name: 'Save Settings' })
    // Beside Import Keys, in the sticky header above both sections it saves.
    expect(save.parentElement).toBe(screen.getByRole('button', { name: /Import Keys/ }).parentElement)
    expect(save).toBeDisabled()
    expect(screen.queryByText('Unsaved changes')).toBeNull()

    fireEvent.change(await screen.findByPlaceholderText('e.g. http://your-vps.com:9090'), { target: { value: 'http://vps.example:9090' } })
    expect(save).toBeEnabled()
    expect(screen.getByText('Unsaved changes')).toBeInTheDocument()

    fireEvent.click(save)
    await waitFor(() => expect(puts()).toHaveLength(1))
    await waitFor(() => expect(save).toBeDisabled())
    expect(screen.queryByText('Unsaved changes')).toBeNull()
  })
})

describe('U-17 / U-18: saving the keys', () => {
  async function editAndSave() {
    renderPage()
    fireEvent.change(await screen.findByPlaceholderText('e.g. http://your-vps.com:9090'), { target: { value: 'http://vps.example:9090' } })
    fireEvent.click(await screen.findByRole('button', { name: 'Save Settings' }))
  }

  test('a failed save shows the route sentence with its code and status', async () => {
    routes[`PUT ${BASE}/settings`] = { status: 500, body: { error: 'Failed to update user settings', code: 'P2024' } }
    await editAndSave()
    expect(await screen.findByText('Failed to update user settings (P2024 · HTTP 500)')).toBeInTheDocument()
  })

  test('saved, but the tunnel push failed: a warning with the cause beside "Settings saved"', async () => {
    routes[`PUT ${BASE}/settings`] = {
      status: 200,
      body: {
        chiselServerUrl: 'http://vps.example:9090', rotationConfigs: {},
        warnings: [{ service: 'kali_sandbox', message: 'The tunnel configuration was not applied', code: 'kali_sandbox_error', upstreamStatus: 401 }],
      },
    }
    await editAndSave()
    expect(await screen.findByText('Settings saved')).toBeInTheDocument()
    expect(await screen.findByText('The tunnel configuration was not applied (kali_sandbox_error · upstream HTTP 401)')).toBeInTheDocument()
  })
})

describe('U-27 / U-28: LLM providers', () => {
  beforeEach(() => { nav.tab = 'providers' })

  test('a refused delete is an error with its code, not "Provider deleted"', async () => {
    routes[`GET ${BASE}/llm-providers`] = { status: 200, body: [{ id: 'p1', providerType: 'anthropic', name: 'Mine', apiKey: '••••1234' }] }
    routes[`DELETE ${BASE}/llm-providers/p1`] = { status: 500, body: { error: 'Failed to delete LLM provider', code: 'P2003' } }
    renderPage()
    await screen.findByText('Mine')
    fireEvent.click(screen.getByTitle('Delete'))
    expect(await screen.findByText('Failed to delete LLM provider (P2003 · HTTP 500)')).toBeInTheDocument()
    expect(screen.queryByText('Provider deleted')).toBeNull()
  })

  test('a list that failed says why in the providers list', async () => {
    routes[`GET ${BASE}/llm-providers`] = { status: 500, body: { error: 'Failed to fetch LLM providers', code: 'P1001' } }
    renderPage()
    expect((await screen.findAllByText(/Couldn't load your providers \(P1001 · HTTP 500\)\./)).length).toBeGreaterThan(0)
  })
})

describe('chat skills (U-10, U-30, U-31, U-32)', () => {
  beforeEach(() => { nav.tab = 'chat-skills' })

  test('a list that failed is not "No Chat Skills yet"', async () => {
    routes[`GET ${BASE}/chat-skills`] = { status: 500, body: { error: 'Failed to fetch chat skills', code: 'P1001' } }
    renderPage()
    expect(await screen.findByText(/Couldn't load your chat skills \(P1001 · HTTP 500\)\./)).toBeInTheDocument()
    expect(screen.queryByText(/No Chat Skills yet/)).toBeNull()
  })

  test('a refused delete is an error, not "Chat skill deleted"', async () => {
    routes[`GET ${BASE}/chat-skills`] = { status: 200, body: [{ id: 's1', name: 'nmap-cheats', createdAt: '2026-01-01T00:00:00Z' }] }
    routes[`DELETE ${BASE}/chat-skills/s1`] = { status: 500, body: { error: 'Failed to delete chat skill', code: 'P2034' } }
    renderPage()
    await screen.findByText('nmap-cheats')
    fireEvent.click(screen.getByTitle('Delete'))
    expect(await screen.findByText('Failed to delete chat skill (P2034 · HTTP 500)')).toBeInTheDocument()
    expect(screen.queryByText('Chat skill deleted')).toBeNull()
  })

  test('a download that failed is a toast, not nothing', async () => {
    routes[`GET ${BASE}/chat-skills`] = { status: 200, body: [{ id: 's1', name: 'nmap-cheats', createdAt: '2026-01-01T00:00:00Z' }] }
    routes[`GET ${BASE}/chat-skills/s1`] = { status: 404, body: { error: 'Chat skill not found' } }
    renderPage()
    await screen.findByText('nmap-cheats')
    fireEvent.click(screen.getByTitle('Download'))
    expect(await screen.findByText('Chat skill not found (HTTP 404)')).toBeInTheDocument()
  })

  test('an import the agent failed names the upstream status', async () => {
    routes[`POST ${BASE}/chat-skills/import-community`] = {
      status: 502, body: { error: 'Failed to fetch skills catalog from agent service', code: 'agent_error', upstreamStatus: 500 },
    }
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: /Import from Community/ }))
    await waitFor(() => expect(alertSpies.alertError).toHaveBeenCalledWith(
      'Failed to fetch skills catalog from agent service (agent_error · HTTP 502 · upstream HTTP 500)'))
  })

  test('an import that skipped some says why each was skipped', async () => {
    routes[`POST ${BASE}/chat-skills/import-community`] = {
      status: 200,
      body: {
        imported: 2, skipped: 6, total: 8,
        skippedBy: { duplicate: 1, limit: 1, fetchFailed: 1, tooLarge: 1, invalid: 1, saveFailed: 1 },
      },
    }
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: /Import from Community/ }))
    await waitFor(() => expect(alertSpies.alert).toHaveBeenCalledWith(
      'Imported 2 community chat skill(s); skipped 1 already in your chat skills, 1 over your 50-chat-skill limit, '
      + '1 too large, 1 could not be fetched, 1 not valid, 1 could not be saved.'))
  })
})

describe('Tradecraft (U-13, U-61, U-62)', () => {
  beforeEach(() => { nav.tab = 'tradecraft' })
  const RES = {
    id: 'r1', name: 'HackTricks', url: 'https://book.hacktricks.wiki', enabled: true, llmModel: 'm',
    lastVerifiedAt: '2026-01-01T00:00:00Z', summary: 's', resourceType: 'mkdocs-wiki',
  }

  test('a list that failed says why', async () => {
    routes[`GET ${BASE}/tradecraft-resources`] = { status: 500, body: { error: 'Failed to fetch tradecraft resources', code: 'P1001' } }
    renderPage()
    expect(await screen.findByText(/Couldn't load your tradecraft resources \(P1001 · HTTP 500\)\./)).toBeInTheDocument()
  })

  test('a refresh the agent could not do names the cause and re-reads the row', async () => {
    routes[`GET ${BASE}/tradecraft-resources`] = { status: 200, body: [RES] }
    routes[`POST ${BASE}/tradecraft-resources/r1/refresh`] = {
      status: 502, body: { error: 'The agent could not refresh this resource', code: 'agent_error', upstreamStatus: 503 },
    }
    renderPage()
    await screen.findByText('HackTricks')
    const listReads = () => fetchMock.mock.calls.filter(c => c[0] === `${BASE}/tradecraft-resources` && !(c[1] as RequestInit | undefined)?.method).length
    const before = listReads()
    fireEvent.click(screen.getByTitle('Re-fetch and rebuild the sitemap + summary'))
    expect(await screen.findByText(
      'Refresh failed: The agent could not refresh this resource (agent_error · HTTP 502 · upstream HTTP 503)')).toBeInTheDocument()
    await waitFor(() => expect(listReads()).toBeGreaterThan(before))
  })

  test('a refused delete names the code', async () => {
    routes[`GET ${BASE}/tradecraft-resources`] = { status: 200, body: [RES] }
    routes[`DELETE ${BASE}/tradecraft-resources/r1`] = { status: 500, body: { error: 'Failed to delete tradecraft resource', code: 'P2024' } }
    renderPage()
    const row = (await screen.findByText('HackTricks')).closest('div')!.parentElement!
    fireEvent.click(within(row.parentElement ?? row).getByTitle('Delete'))
    expect(await screen.findByText('Delete failed: Failed to delete tradecraft resource (P2024 · HTTP 500)')).toBeInTheDocument()
  })
})

describe('HD-24: a new chisel URL with the masked auth asks for it again', () => {
  test('the refusal is shown with its code and the chisel auth field takes the focus', async () => {
    routes[`GET ${BASE}/settings`] = {
      status: 200,
      body: { chiselServerUrl: 'http://vps.example:9090', chiselAuth: '••••••••pass', rotationConfigs: {} },
    }
    routes[`PUT ${BASE}/settings`] = {
      status: 400,
      body: {
        error: 'The chisel server URL changed: type the chisel auth again, or clear it. A stored secret is never sent to a new address unless it is entered again.',
        code: 'secret_reentry_required', field: 'chiselAuth', fields: ['chiselAuth'], endpoint: 'chiselServerUrl',
      },
    }
    renderPage()
    fireEvent.change(await screen.findByPlaceholderText('e.g. http://your-vps.com:9090'), { target: { value: 'http://elsewhere.example:9090' } })
    fireEvent.click(await screen.findByRole('button', { name: 'Save Settings' }))

    expect(await screen.findByText(/type the chisel auth again, or clear it\..*\(secret_reentry_required · HTTP 400\)/)).toBeInTheDocument()
    await waitFor(() => expect(screen.getByPlaceholderText('Enter chisel auth')).toHaveFocus())
  })
})

describe('ID-25: re-pointing the chisel server asks for the password (review of 1.6)', () => {
  test('the refused save opens the password dialog; the password goes with the same save', async () => {
    routes[`GET ${BASE}/settings`] = {
      status: 200,
      body: { chiselServerUrl: 'http://vps.example:9090', chiselAuth: '••••••••pass', rotationConfigs: {} },
    }
    let n = 0
    routes[`PUT ${BASE}/settings`] = () => (n++ === 0
      ? { status: 403, body: { error: 'Enter your password to confirm this action.', code: 'step_up_required' } }
      : { status: 200, body: { chiselServerUrl: 'http://elsewhere.example:9090', chiselAuth: '••••••••ped!', rotationConfigs: {} } })
    renderPage()
    fireEvent.change(await screen.findByPlaceholderText('e.g. http://your-vps.com:9090'), { target: { value: 'http://elsewhere.example:9090' } })
    fireEvent.change(screen.getByPlaceholderText('Enter chisel auth'), { target: { value: 'user:typed!' } })
    fireEvent.click(await screen.findByRole('button', { name: 'Save Settings' }))

    const dialog = await screen.findByRole('dialog')
    expect(dialog).toHaveTextContent('new address')
    fireEvent.change(within(dialog).getByLabelText('Your password'), { target: { value: 'my-password' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }))

    expect(await screen.findByText('Settings saved')).toBeInTheDocument()
    const bodies = puts().map(c => JSON.parse(String((c[1] as RequestInit).body)))
    expect(bodies).toHaveLength(2)
    expect(bodies[0].stepUpPassword).toBeUndefined()
    expect(bodies[1]).toMatchObject({ chiselServerUrl: 'http://elsewhere.example:9090', chiselAuth: 'user:typed!', stepUpPassword: 'my-password' })
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
  })
})
