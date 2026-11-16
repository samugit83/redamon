/**
 * Global Settings → Tradecraft, as its own component: the same list, form, polling,
 * confirmation and toasts the settings page rendered inline before the move.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor, within } from '@testing-library/react'
import { ToastProvider } from '@/components/ui/Toast/Toast'

vi.mock('next/navigation', () => ({
  useSearchParams: () => new URLSearchParams('tab=tradecraft'),
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
vi.mock('@/components/ui', async orig => ({
  ...((await orig()) as Record<string, unknown>),
  useAlertModal: () => alertSpies,
}))

const { TradecraftTab } = await import('./TradecraftTab')

const BASE = '/api/users/user-1/tradecraft-resources'
const RES = {
  id: 'r1', name: 'Lab Wiki', url: 'https://wiki.tc-fixture.test', enabled: true, llmModel: 'm',
  lastVerifiedAt: '2026-01-01T00:00:00Z', summary: 's', resourceType: 'mkdocs-wiki',
}

type Answer = { status: number; body: unknown }
let routes: Record<string, Answer>
const fetchMock = vi.fn()

beforeEach(() => {
  vi.clearAllMocks()
  routes = { [`GET ${BASE}`]: { status: 200, body: [RES] } }
  fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
    const a = routes[`${init?.method ?? 'GET'} ${url}`] ?? { status: 200, body: [] }
    return new Response(JSON.stringify(a.body), { status: a.status })
  })
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

const onDirtyChange = vi.fn()
const renderTab = () => render(<ToastProvider><TradecraftTab userId="user-1" onDirtyChange={onDirtyChange} /></ToastProvider>)
const calls = (method: string, url: string) =>
  fetchMock.mock.calls.filter(c => c[0] === url && ((c[1] as RequestInit | undefined)?.method ?? 'GET') === method)
const rowOf = async (name: string) => {
  const row = (await screen.findByText(name)).closest('div')!.parentElement!
  return within(row.parentElement ?? row)
}

describe('TradecraftTab', () => {
  test('loads_resources_on_mount', async () => {
    renderTab()
    expect(await screen.findByText('Lab Wiki')).toBeInTheDocument()
    expect(calls('GET', BASE)).toHaveLength(1)
  })

  test('add_button_opens_form', async () => {
    renderTab()
    await screen.findByText('Lab Wiki')
    fireEvent.click(screen.getByRole('button', { name: /Add Resource/ }))
    expect(await screen.findByPlaceholderText('HackTricks')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('https://book.hacktricks.wiki')).toBeInTheDocument()
    // The header's Add button hides while the form is open, as before the move; the
    // only one left is the form's own submit.
    expect(screen.getAllByRole('button', { name: /Add Resource/ }).map(b => b.getAttribute('type'))).toEqual(['submit'])
  })

  test('delete_asks_confirmation_with_today_text', async () => {
    renderTab()
    const row = await rowOf('Lab Wiki')
    fireEvent.click(row.getByTitle('Delete'))
    await waitFor(() => expect(alertSpies.confirm).toHaveBeenCalledWith(
      'Delete "Lab Wiki"? This removes the catalog entry and disk cache.',
      'Delete tradecraft resource',
    ))
    await waitFor(() => expect(calls('DELETE', `${BASE}/r1`)).toHaveLength(1))
    expect(await screen.findByText('Deleted')).toBeInTheDocument()
  })

  test('delete_declined_sends_nothing', async () => {
    alertSpies.confirm.mockResolvedValueOnce(false)
    renderTab()
    const row = await rowOf('Lab Wiki')
    fireEvent.click(row.getByTitle('Delete'))
    await waitFor(() => expect(alertSpies.confirm).toHaveBeenCalled())
    expect(calls('DELETE', `${BASE}/r1`)).toHaveLength(0)
  })

  test('refresh_calls_refresh_route', async () => {
    renderTab()
    await screen.findByText('Lab Wiki')
    fireEvent.click(screen.getByTitle('Re-fetch and rebuild the sitemap + summary'))
    await waitFor(() => expect(calls('POST', `${BASE}/r1/refresh`)).toHaveLength(1))
    const init = calls('POST', `${BASE}/r1/refresh`)[0][1] as RequestInit
    expect(init.body).toBe('{}')
    expect(await screen.findByText('Refreshed')).toBeInTheDocument()
    await waitFor(() => expect(calls('GET', BASE).length).toBeGreaterThanOrEqual(2))
  })

  test('toggle_enabled_puts_enabled', async () => {
    renderTab()
    await screen.findByText('Lab Wiki')
    fireEvent.click(screen.getByTitle('Enabled').querySelector('input')!)
    await waitFor(() => expect(calls('PUT', `${BASE}/r1`)).toHaveLength(1))
    expect(JSON.parse(String((calls('PUT', `${BASE}/r1`)[0][1] as RequestInit).body))).toEqual({ enabled: false })
  })

  test('load_error_shows_retry', async () => {
    routes[`GET ${BASE}`] = { status: 500, body: { error: 'Failed to fetch tradecraft resources', code: 'P1001' } }
    renderTab()
    expect(await screen.findByText(/Couldn't load your tradecraft resources \(P1001 · HTTP 500\)\./)).toBeInTheDocument()
    routes[`GET ${BASE}`] = { status: 200, body: [RES] }
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByText('Lab Wiki')).toBeInTheDocument()
    expect(screen.queryByRole('alert')).toBeNull()
  })

  test('polls_while_a_resource_is_unverified', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    try {
      routes[`GET ${BASE}`] = { status: 200, body: [{ ...RES, lastVerifiedAt: null }] }
      renderTab()
      await screen.findByText('Lab Wiki')
      const before = calls('GET', BASE).length
      await vi.advanceTimersByTimeAsync(5000)
      await waitFor(() => expect(calls('GET', BASE).length).toBeGreaterThan(before))
    } finally {
      vi.useRealTimers()
    }
  })
})

describe('TradecraftTab and the 2.0 switch', () => {
  const SETTINGS = '/api/users/user-1/tradecraft-settings'
  const V2_RESOURCE = {
    ...RES, slug: 'lab-wiki', forcedType: '', storageMode: 'stored', githubTokenOverride: '', hasLogin: false, priority: 'normal',
    mapVersion: 3, summarySource: 'generated', summaryLocked: false, report: null, lastRefreshedAt: null, lastError: '',
    entryCount: 4, stale: false, job: null, createdAt: '2026-01-01T00:00:00Z', updatedAt: '2026-01-01T00:00:00Z',
  }

  test('switch_off_renders_1x: the 1.x tab, with the switch off on top', async () => {
    routes[`GET ${SETTINGS}`] = { status: 200, body: { v2Enabled: false } }
    renderTab()
    expect(await screen.findByText('Lab Wiki')).toBeInTheDocument()
    expect(screen.getByText(/On add, the\s+agent fetches the homepage/)).toBeInTheDocument()
    expect(screen.getByRole('switch', { name: 'Tradecraft 2.0 (preview)' })).toHaveAttribute('aria-checked', 'false')
    expect(screen.queryByText(/ingested in the\s+background/)).toBeNull()
    expect(calls('GET', BASE)).toHaveLength(1)
  })

  test('switch on: the 2.0 list', async () => {
    routes[`GET ${SETTINGS}`] = { status: 200, body: { v2Enabled: true } }
    routes[`GET ${BASE}`] = { status: 200, body: [V2_RESOURCE] }
    renderTab()
    expect(await screen.findByText('Stored')).toBeInTheDocument()
    expect(screen.getByText(/ingested in the\s+background/)).toBeInTheDocument()
    expect(screen.getByRole('switch', { name: 'Tradecraft 2.0 (preview)' })).toHaveAttribute('aria-checked', 'true')
  })

  test('turning the switch on, confirmed, swaps to the 2.0 list', async () => {
    routes[`GET ${SETTINGS}`] = { status: 200, body: { v2Enabled: false } }
    routes[`PUT ${SETTINGS}`] = { status: 200, body: { v2Enabled: true } }
    renderTab()
    await screen.findByText('Lab Wiki')
    routes[`GET ${BASE}`] = { status: 200, body: [V2_RESOURCE] }
    fireEvent.click(screen.getByRole('switch', { name: 'Tradecraft 2.0 (preview)' }))
    expect(await screen.findByText('Stored')).toBeInTheDocument()
    expect(alertSpies.confirm).toHaveBeenCalledTimes(1)
  })

  test('configure_buttons_follow_add: Configure ingestion sits left of Add Resource and shows exactly when it does (R-020)', async () => {
    routes[`GET ${SETTINGS}`] = { status: 200, body: { v2Enabled: true } }
    routes[`GET ${BASE}`] = { status: 200, body: [V2_RESOURCE] }
    renderTab()
    const configure = await screen.findByRole('button', { name: /Configure ingestion/ })
    const add = screen.getByRole('button', { name: /Add Resource/ })
    expect(configure.compareDocumentPosition(add) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    fireEvent.click(add)
    await waitFor(() => expect(screen.queryByRole('button', { name: /Configure ingestion/ })).toBeNull())
    expect(screen.queryByRole('button', { name: /^Add Resource$/ })).toBeNull()
  })

  test('configure_buttons_follow_add: no Configure ingestion while the list is refused, nor on the 1.x tab', async () => {
    routes[`GET ${SETTINGS}`] = { status: 200, body: { v2Enabled: true } }
    routes[`GET ${BASE}`] = { status: 403, body: { error: 'Forbidden', code: 'own_account_only' } }
    renderTab()
    expect(await screen.findByText(/You cannot use these resources/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Configure ingestion/ })).toBeNull()
    expect(screen.queryByRole('button', { name: /Add Resource/ })).toBeNull()
    cleanup()
    routes[`GET ${SETTINGS}`] = { status: 200, body: { v2Enabled: false } }
    routes[`GET ${BASE}`] = { status: 200, body: [RES] }
    renderTab()
    await screen.findByText('Lab Wiki')
    expect(screen.getByRole('button', { name: /Add Resource/ })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Configure ingestion/ })).toBeNull()
  })

  test('Configure ingestion opens the dialog; a save closes it and reads the list again', async () => {
    const DEFAULTS = { 'crawl.maxPages': 200 }
    routes[`GET ${SETTINGS}`] = { status: 200, body: { v2Enabled: true, ingestion: { values: DEFAULTS, changed: [], defaults: DEFAULTS } } }
    routes[`PUT ${SETTINGS}`] = { status: 200, body: { v2Enabled: true, ingestion: { values: { 'crawl.maxPages': 120 }, changed: ['crawl.maxPages'], defaults: DEFAULTS } } }
    routes[`GET ${BASE}`] = { status: 200, body: [V2_RESOURCE] }
    renderTab()
    fireEvent.click(await screen.findByRole('button', { name: /Configure ingestion/ }))
    const dialog = await screen.findByRole('dialog', { name: 'Configure ingestion' })
    fireEvent.click(within(dialog).getByRole('button', { name: /^Website crawl/ }))
    fireEvent.change(within(dialog).getByLabelText('Max pages visited'), { target: { value: '120' } })
    const listReads = calls('GET', BASE).length
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }))
    expect(await screen.findByText(/Saved: each resource uses the new settings/)).toBeInTheDocument()
    expect(screen.queryByRole('dialog', { name: 'Configure ingestion' })).toBeNull()
    await waitFor(() => expect(calls('GET', BASE).length).toBeGreaterThan(listReads))
  })

  test('a switch that cannot be read: the 1.x tab, without the switch', async () => {
    routes[`GET ${SETTINGS}`] = { status: 403, body: { error: 'Forbidden', code: 'forbidden' } }
    renderTab()
    expect(await screen.findByText('Lab Wiki')).toBeInTheDocument()
    expect(screen.queryByRole('switch', { name: 'Tradecraft 2.0 (preview)' })).toBeNull()
  })
})

