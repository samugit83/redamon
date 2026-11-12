/**
 * Global Settings → LLM Providers → "Models by feature".
 *
 * The grid shares ONE /api/models call across its nine pickers (each call
 * makes the agent list every provider's models). Each change saves only its
 * own key. And the API Keys save must never carry `featureModels`: a stale
 * copy riding that save would put back models changed since the page loaded.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, within, fireEvent, waitFor, act } from '@testing-library/react'
import { ToastProvider } from '@/components/ui/Toast/Toast'

const nav = vi.hoisted(() => ({ tab: 'providers' }))

vi.mock('next/navigation', () => ({
  useSearchParams: () => new URLSearchParams(`tab=${nav.tab}`),
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), refresh: vi.fn(), back: vi.fn(), prefetch: vi.fn() }),
  usePathname: () => '/settings',
}))
vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ userId: 'user-1' }) }))

// The real hook throws outside <AlertProvider>; mock the deep path and the barrel.
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

const MODELS = {
  Anthropic: [
    { id: 'claude-haiku-4-5', name: 'Claude Haiku 4.5', context_length: 200000, description: '' },
    { id: 'claude-opus-4-6', name: 'Claude Opus 4.6', context_length: 200000, description: '' },
  ],
  'AWS Bedrock': [
    { id: 'bedrock/anthropic.claude-3-5-sonnet', name: 'Bedrock Claude Sonnet', context_length: null, description: '' },
  ],
}
const PROVIDER = { id: 'p1', userId: 'user-1', providerType: 'anthropic', name: 'Anthropic', apiKey: '••••1234' }

let providers: unknown[]
let saved: Record<string, string>
let modelsAnswer: () => Promise<{ status: number; body: unknown }>
const fetchMock = vi.fn()

function json(status: number, body: unknown) {
  return { ok: status >= 200 && status < 300, status, json: async () => body }
}

beforeEach(() => {
  nav.tab = 'providers'
  providers = [PROVIDER]
  saved = { triage: 'claude-haiku-4-5', codefix: 'custom/deleted-provider' }
  modelsAnswer = async () => ({ status: 200, body: MODELS })
  fetchMock.mockReset().mockImplementation(async (url: string, init?: RequestInit) => {
    const method = init?.method ?? 'GET'
    if (url === '/api/models') {
      const a = await modelsAnswer()
      return json(a.status, a.body)
    }
    if (url === '/api/users/user-1/settings' && method === 'GET') {
      return json(200, { shodanApiKey: '', featureModels: { ...saved }, rotationConfigs: {} })
    }
    if (url === '/api/users/user-1/settings' && method === 'PUT') {
      const body = JSON.parse(init!.body as string)
      for (const [k, v] of Object.entries((body.featureModels ?? {}) as Record<string, string>)) {
        if (v) saved[k] = v
        else delete saved[k]
      }
      return json(200, { ...body, featureModels: { ...saved }, rotationConfigs: {} })
    }
    if (url === '/api/users/user-1/llm-providers') return json(200, providers)
    if (url === '/api/users/user-1/settings/api-usage') {
      return json(200, { enabled: true, report: null, running: null, runBy: null, activity: null, tracked: [] })
    }
    if (/\/(attack-skills|chat-skills|tradecraft-resources)$/.test(url) || url === '/api/projects') return json(200, [])
    return json(404, {})
  })
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function calls(url: string, method?: string) {
  return fetchMock.mock.calls.filter(([u, init]) =>
    u === url && (!method || ((init as RequestInit | undefined)?.method ?? 'GET') === method))
}

function renderPage() {
  return render(<ToastProvider><SettingsPage /></ToastProvider>)
}

async function tile(id: string) {
  await screen.findByText('Models by feature')
  return waitFor(() => {
    const el = document.querySelector(`[data-feature="${id}"]`) as HTMLElement | null
    if (!el) throw new Error(`no tile ${id}`)
    return el
  })
}

describe('Models by feature section', () => {
  test('nine tiles from ONE /api/models call, with their saved state', async () => {
    renderPage()
    const triage = await tile('triage')
    await waitFor(() => expect(document.querySelectorAll('[data-feature]')).toHaveLength(9))
    expect(calls('/api/models')).toHaveLength(1)
    expect(JSON.parse((calls('/api/models')[0][1] as RequestInit).body as string)).toEqual({ userId: 'user-1' })

    expect(within(triage).getByText('Triage review')).toBeInTheDocument()
    expect(within(triage).getByText('Set')).toBeInTheDocument()
    expect(within(triage).getByText('Claude Haiku 4.5')).toBeInTheDocument()
    expect(within(triage).getByText('Also in: Project settings → CypherFix')).toBeInTheDocument()
    // The saved id is not among the user's current models.
    expect(within(await tile('codefix')).getByText('Provider removed')).toBeInTheDocument()
    expect(within(await tile('multi_mute')).getByText('Not set')).toBeInTheDocument()
    expect(within(await tile('preset_generator')).getByText("A mid-size model. AWS Bedrock isn't supported here.")).toBeInTheDocument()
  })

  test('a skeleton while the models load', async () => {
    modelsAnswer = () => new Promise(() => {})
    renderPage()
    await screen.findByText('Models by feature')
    expect(await screen.findAllByTestId('feature-model-skeleton')).toHaveLength(9)
    expect(document.querySelector('[data-feature]')).toBeNull()
  })

  test('with no provider: one message, no pickers, no /api/models call', async () => {
    providers = []
    renderPage()
    expect(await screen.findByText('Add an LLM provider above to choose models for these features')).toBeInTheDocument()
    expect(document.querySelector('[data-feature]')).toBeNull()
    expect(screen.queryByText('Choose a model')).toBeNull()
    expect(calls('/api/models')).toHaveLength(0)
  })

  test('when /api/models fails: the saved models read-only, and Retry refetches', async () => {
    modelsAnswer = async () => ({ status: 503, body: { error: 'Failed to fetch models from agent API' } })
    renderPage()
    const triage = await tile('triage')
    expect(await within(triage).findByText('claude-haiku-4-5')).toBeInTheDocument()
    // The chip and the read-only value both say so.
    expect(within(await tile('multi_mute')).getAllByText('Not set')).toHaveLength(2)
    // One Retry per feature, plus the plugin list's own: this stub answers every
    // unrouted URL, /api/plugins/llm-features included, with a 404.
    // Looked up on each call: the grid re-renders, so the notice is a new node.
    const pluginNotice = () => screen.getByText(/Plugin items could not be loaded \(HTTP 404\)/).closest('[role="alert"]') as HTMLElement
    await waitFor(() => expect(within(pluginNotice()).getByRole('button', { name: /Retry/ })).toBeInTheDocument())
    const featureRetries = () => screen.queryAllByRole('button', { name: /Retry/ }).filter(b => !pluginNotice().contains(b))
    expect(featureRetries()).toHaveLength(9)
    expect(screen.getAllByRole('button', { name: /Retry/ })).toHaveLength(10)
    expect(screen.queryByText('Choose a model')).toBeNull()

    modelsAnswer = async () => ({ status: 200, body: MODELS })
    fireEvent.click(within(triage).getByRole('button', { name: /Retry/ }))
    // The grid re-renders from the skeleton, so the tile is a new node.
    await waitFor(() => expect(screen.queryAllByTestId('feature-model-skeleton')).toHaveLength(0))
    expect(await within(await tile('triage')).findByText('Claude Haiku 4.5')).toBeInTheDocument()
    // The models are back; only the plugin list's notice (still a 404) keeps a Retry.
    expect(featureRetries()).toHaveLength(0)
    expect(within(pluginNotice()).getByRole('button', { name: /Retry/ })).toBeInTheDocument()
    expect(calls('/api/models')).toHaveLength(2)
  })

  test('a pick saves only that key, then toasts; the preset generator never lists Bedrock', async () => {
    renderPage()
    const multi = await tile('multi_mute')
    fireEvent.click(await within(multi).findByText('Choose a model'))
    fireEvent.click(within(multi).getByText('Claude Haiku 4.5'))
    expect(await screen.findByText('Multi mute now uses Claude Haiku 4.5')).toBeInTheDocument()
    const puts = calls('/api/users/user-1/settings', 'PUT')
    expect(puts).toHaveLength(1)
    expect(JSON.parse((puts[0][1] as RequestInit).body as string)).toEqual({ featureModels: { multi_mute: 'claude-haiku-4-5' } })
    expect(await within(multi).findByText('Set')).toBeInTheDocument()

    const preset = await tile('preset_generator')
    fireEvent.click(within(preset).getByText('Choose a model'))
    expect(within(preset).getByText('Claude Opus 4.6')).toBeInTheDocument()
    expect(within(preset).queryByText('Bedrock Claude Sonnet')).toBeNull()
  })

  test("Clear sends '' for that key", async () => {
    renderPage()
    const triage = await tile('triage')
    fireEvent.click(within(triage).getByRole('button', { name: 'Clear the Triage review model' }))
    await waitFor(() => expect(calls('/api/users/user-1/settings', 'PUT')).toHaveLength(1))
    expect(JSON.parse((calls('/api/users/user-1/settings', 'PUT')[0][1] as RequestInit).body as string))
      .toEqual({ featureModels: { triage: '' } })
    expect(await within(triage).findByText('Not set')).toBeInTheDocument()
  })

  test('every tile waits while one saves (review: a second pick snapped back unsaved)', async () => {
    const answer = fetchMock.getMockImplementation()!
    let release!: () => void
    const held = new Promise<void>(r => { release = r })
    fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
      if (init?.method === 'PUT') await held
      return answer(url, init)
    })
    renderPage()
    const triage = await tile('triage')
    const multi = await tile('multi_mute')
    const codefix = await tile('codefix')
    fireEvent.click(within(triage).getByRole('button', { name: 'Clear the Triage review model' }))
    await waitFor(() => expect(calls('/api/users/user-1/settings', 'PUT')).toHaveLength(1))

    fireEvent.click(within(multi).getByText('Choose a model'))
    expect(within(multi).queryByText('Claude Haiku 4.5')).toBeNull()
    expect(within(codefix).getByRole('button', { name: 'Clear the CodeFix model' })).toBeDisabled()

    await act(async () => { release() })
    expect(await within(triage).findByText('Not set')).toBeInTheDocument()
    fireEvent.click(within(multi).getByText('Choose a model'))
    expect(await within(multi).findByText('Claude Haiku 4.5')).toBeInTheDocument()
  })

  test('hidden while the provider form is open', async () => {
    renderPage()
    await tile('triage')
    fireEvent.click(screen.getByRole('button', { name: /Add Provider/ }))
    await waitFor(() => expect(screen.queryByText('Models by feature')).toBeNull())
  })
})

describe('API Keys save', () => {
  test('the payload never carries featureModels', async () => {
    nav.tab = 'keys'
    renderPage()
    const shodan = await screen.findByPlaceholderText('Enter shodan api key')
    fireEvent.change(shodan, { target: { value: 'NEW-SHODAN-KEY' } })
    fireEvent.click(await screen.findByRole('button', { name: 'Save Settings' }))
    await waitFor(() => expect(calls('/api/users/user-1/settings', 'PUT')).toHaveLength(1))
    const body = JSON.parse((calls('/api/users/user-1/settings', 'PUT')[0][1] as RequestInit).body as string)
    expect(body.shodanApiKey).toBe('NEW-SHODAN-KEY')
    expect(body).not.toHaveProperty('featureModels')
    expect(saved).toEqual({ triage: 'claude-haiku-4-5', codefix: 'custom/deleted-provider' })
  })
})
