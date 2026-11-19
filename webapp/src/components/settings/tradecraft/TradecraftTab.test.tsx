/**
 * Global Settings → Tradecraft, as its own component: the same list, form, polling,
 * confirmation and toasts the settings page rendered inline before the move.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor, within } from '@testing-library/react'
import { ToastProvider } from '@/components/ui/Toast/Toast'

const search = vi.hoisted(() => ({ value: 'tab=tradecraft' }))
vi.mock('next/navigation', () => ({
  useSearchParams: () => new URLSearchParams(search.value),
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

const gate = vi.hoisted(() => ({ ensureFeatureModel: vi.fn(async () => null), fetchWithFeatureModel: vi.fn(), userId: 'user-1', savedVersion: 0 }))
vi.mock('@/components/shared/FeatureModelGate', async orig => ({
  ...((await orig()) as Record<string, unknown>),
  useFeatureModelGate: () => gate,
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
  search.value = 'tab=tradecraft'
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

describe('TradecraftTab: the 2.0 library for every account (T9.3: no switch, no 1.x tab)', () => {
  const SETTINGS = '/api/users/user-1/tradecraft-settings'
  const V2_RESOURCE = {
    ...RES, slug: 'lab-wiki', forcedType: '', storageMode: 'stored', githubTokenOverride: '', hasLogin: false, priority: 'normal',
    mapVersion: 3, summarySource: 'generated', summaryLocked: false, report: null, lastRefreshedAt: null, lastError: '',
    entryCount: 4, stale: false, job: null, createdAt: '2026-01-01T00:00:00Z', updatedAt: '2026-01-01T00:00:00Z',
  }

  test('the 2.0 list, with no preview switch', async () => {
    routes[`GET ${SETTINGS}`] = { status: 200, body: { v2Enabled: true } }
    routes[`GET ${BASE}`] = { status: 200, body: [V2_RESOURCE] }
    renderTab()
    expect(await screen.findByText('Stored')).toBeInTheDocument()
    expect(screen.getByText(/ingested in the\s+background/)).toBeInTheDocument()
    expect(screen.queryByRole('switch', { name: /Tradecraft 2.0/ })).toBeNull()
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

  test('configure_buttons_follow_add: no Configure ingestion while the list is refused', async () => {
    routes[`GET ${SETTINGS}`] = { status: 200, body: { v2Enabled: true } }
    routes[`GET ${BASE}`] = { status: 403, body: { error: 'Forbidden', code: 'own_account_only' } }
    renderTab()
    expect(await screen.findByText(/You cannot use these resources/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Configure ingestion/ })).toBeNull()
    expect(screen.queryByRole('button', { name: /Add Resource/ })).toBeNull()
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

  test('configure_search_button: Configure search sits next to Configure ingestion and opens its dialog (R-021)', async () => {
    routes[`GET ${SETTINGS}`] = { status: 200, body: { v2Enabled: true } }
    routes[`GET ${BASE}`] = { status: 200, body: [V2_RESOURCE] }
    renderTab()
    const search = await screen.findByRole('button', { name: /Configure search/ })
    const ingestion = screen.getByRole('button', { name: /Configure ingestion/ })
    expect(search.compareDocumentPosition(ingestion) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    fireEvent.click(search)
    expect(await screen.findByRole('dialog', { name: 'Configure search' })).toBeInTheDocument()
  })

  const LIBRARIAN = (model: string, use = 'agent') => {
    routes[`GET ${SETTINGS}`] = { status: 200, body: { v2Enabled: true, search: { values: { 'librarian.use': use }, changed: [], defaults: {}, synonyms: [] } } }
    routes['GET /api/users/user-1/settings'] = { status: 200, body: { featureModels: model ? { tradecraft_librarian: model } : {} } }
  }

  test('librarian_line: "Librarian model: <name> (change)" above the list; change opens the gate', async () => {
    LIBRARIAN('openai/gpt-4o-mini')
    routes[`GET ${BASE}`] = { status: 200, body: [V2_RESOURCE] }
    renderTab()
    const line = await screen.findByTestId('librarian-model-line')
    await waitFor(() => expect(line).toHaveTextContent('Librarian model: openai/gpt-4o-mini (change)'))
    expect(line.compareDocumentPosition(await screen.findByText('Lab Wiki')) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    fireEvent.click(within(line).getByRole('button', { name: '(change)' }))
    expect(gate.ensureFeatureModel).toHaveBeenCalledWith('tradecraft_librarian', expect.objectContaining({ force: true }))
    expect(screen.queryByTestId('no-librarian-banner')).toBeNull()
  })

  test('banner_when_missing: resources and no librarian model; none without resources or with Search only', async () => {
    LIBRARIAN('')
    routes[`GET ${BASE}`] = { status: 200, body: [V2_RESOURCE] }
    renderTab()
    const banner = await screen.findByTestId('no-librarian-banner')
    expect(banner).toHaveTextContent('No librarian model: the agent can only use plain search on your resources')
    fireEvent.click(within(banner).getByRole('button', { name: 'Choose a model' }))
    expect(gate.ensureFeatureModel).toHaveBeenCalledWith('tradecraft_librarian', expect.objectContaining({ force: true }))
    expect(screen.getByTestId('librarian-model-line')).toHaveTextContent('Librarian model: not set (choose)')
    cleanup()
    routes[`GET ${BASE}`] = { status: 200, body: [] }
    renderTab()
    await screen.findByText(/No resources yet/)
    expect(screen.queryByTestId('no-librarian-banner')).toBeNull()
    cleanup()
    LIBRARIAN('', 'search_only')
    routes[`GET ${BASE}`] = { status: 200, body: [V2_RESOURCE] }
    renderTab()
    await screen.findByText('Lab Wiki')
    await waitFor(() => expect(screen.getByTestId('librarian-model-line')).toHaveTextContent('not set'))
    expect(screen.queryByTestId('no-librarian-banner')).toBeNull()
  })

  test('banner_when_missing, a deleted provider (Q10): a saved model no longer among the account\'s models shows the banner', async () => {
    const MODELS = { OpenAI: [{ id: 'openai/gpt-4o-mini', name: 'GPT-4o mini', context_length: 128000, description: '' }] }
    LIBRARIAN('openai/gone-model')
    routes['POST /api/models'] = { status: 200, body: MODELS }
    routes[`GET ${BASE}`] = { status: 200, body: [V2_RESOURCE] }
    renderTab()
    expect(await screen.findByTestId('no-librarian-banner')).toBeInTheDocument()
    expect(screen.getByTestId('librarian-model-line')).toHaveTextContent('Librarian model: openai/gone-model (not available: its provider is gone) (choose)')
    cleanup()
    LIBRARIAN('openai/gpt-4o-mini')
    routes['POST /api/models'] = { status: 200, body: MODELS }
    renderTab()
    await waitFor(() => expect(calls('POST', '/api/models')).toHaveLength(2))
    await waitFor(() => expect(screen.getByTestId('librarian-model-line')).toHaveTextContent('Librarian model: openai/gpt-4o-mini (change)'))
    expect(screen.queryByTestId('no-librarian-banner')).toBeNull()
    cleanup()
    // A listing that fails says nothing about the model: no banner on a guess.
    LIBRARIAN('openai/gone-model')
    routes['POST /api/models'] = { status: 503, body: { error: 'Failed to fetch models from agent API', code: 'providers_unreachable' } }
    renderTab()
    await waitFor(() => expect(calls('POST', '/api/models')).toHaveLength(3))
    await screen.findByText('Lab Wiki')
    expect(screen.queryByTestId('no-librarian-banner')).toBeNull()
  })

  test('edit_link target: ?edit=<id> opens that resource\'s Edit form once the list is read (§3.4)', async () => {
    search.value = 'tab=tradecraft&edit=r1'
    routes[`GET ${SETTINGS}`] = { status: 200, body: { v2Enabled: true } }
    routes[`GET ${BASE}`] = { status: 200, body: [V2_RESOURCE] }
    renderTab()
    expect(await screen.findByRole('dialog', { name: 'Edit Tradecraft Resource' })).toBeInTheDocument()
    expect((screen.getByPlaceholderText('HackTricks') as HTMLInputElement).value).toBe('Lab Wiki')
  })

  test('?edit= naming no resource of the account opens nothing', async () => {
    search.value = 'tab=tradecraft&edit=nope'
    routes[`GET ${SETTINGS}`] = { status: 200, body: { v2Enabled: true } }
    routes[`GET ${BASE}`] = { status: 200, body: [V2_RESOURCE] }
    renderTab()
    await screen.findByText('Stored')
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  test('offer_once (T9.1, §7.2): converted resources offer Save & refresh all; accepting records the answer and opens its confirmation', async () => {
    routes[`GET ${SETTINGS}`] = { status: 200, body: { v2Enabled: true, offerBulkRefresh: true } }
    routes[`PUT ${SETTINGS}`] = { status: 200, body: { v2Enabled: true, offerBulkRefresh: false } }
    routes[`GET ${BASE}`] = { status: 200, body: [{ ...V2_RESOURCE, mapVersion: 2 }] }
    routes[`POST ${BASE}/refresh-all`] = { status: 200, body: { bulkId: 'b1', started: [{ resourceId: 'r1', jobId: 'j1' }], skipped: [] } }
    renderTab()
    const offer = await screen.findByTestId('bulk-refresh-offer')
    expect(offer).toHaveTextContent('Refresh them for headings, descriptions and search inside pages')
    fireEvent.click(within(offer).getByRole('button', { name: 'Save & refresh all' }))
    const dialog = await screen.findByRole('dialog', { name: 'Save & refresh all' })
    expect(screen.queryByTestId('bulk-refresh-offer')).toBeNull()
    expect(calls('PUT', SETTINGS).map(c => JSON.parse(String((c[1] as RequestInit).body)))).toEqual([{ bulkRefreshOffered: true }])
    expect(calls('POST', `${BASE}/refresh-all`)).toHaveLength(0)
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save & refresh 1' }))
    await waitFor(() => expect(calls('POST', `${BASE}/refresh-all`)).toHaveLength(1))
    expect(JSON.parse(String((calls('POST', `${BASE}/refresh-all`)[0][1] as RequestInit).body))).toEqual({ resourceIds: ['r1'] })
  })

  test('offer_once: "Not now" records the answer and starts nothing; no offer once answered', async () => {
    routes[`GET ${SETTINGS}`] = { status: 200, body: { v2Enabled: true, offerBulkRefresh: true } }
    routes[`PUT ${SETTINGS}`] = { status: 200, body: { v2Enabled: true, offerBulkRefresh: false } }
    routes[`GET ${BASE}`] = { status: 200, body: [{ ...V2_RESOURCE, mapVersion: 2 }] }
    renderTab()
    fireEvent.click(within(await screen.findByTestId('bulk-refresh-offer')).getByRole('button', { name: 'Not now' }))
    await waitFor(() => expect(screen.queryByTestId('bulk-refresh-offer')).toBeNull())
    expect(calls('PUT', SETTINGS)).toHaveLength(1)
    expect(screen.queryByRole('dialog')).toBeNull()
    cleanup()
    routes[`GET ${SETTINGS}`] = { status: 200, body: { v2Enabled: true, offerBulkRefresh: false } }
    renderTab()
    await screen.findByText('Lab Wiki')
    expect(screen.queryByTestId('bulk-refresh-offer')).toBeNull()
  })

})

