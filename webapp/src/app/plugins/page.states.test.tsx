/**
 * Every state of the /plugins page (R-04) and of a plugin card (README.PLUGINS.md §7.1):
 * loading, each card state with its admin actions, the catalog unreachable (installed plugins
 * still listed and manageable, Install disabled with the reason), invalid or untrusted, an
 * extra-key catalog, the runner down, an empty catalog. Confirmations go
 * through useAlertModal, never window.confirm.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { createHash, webcrypto } from 'node:crypto'

const alertSpies = vi.hoisted(() => ({
  alert: vi.fn(async () => {}),
  alertError: vi.fn(async () => {}),
  alertWarning: vi.fn(async () => {}),
  confirm: vi.fn(async () => true),
  dangerConfirm: vi.fn(async () => true),
}))
vi.mock('@/components/ui/AlertModal/AlertModal', async (orig) => ({
  ...((await orig()) as Record<string, unknown>),
  useAlertModal: () => alertSpies,
}))
vi.mock('@/components/ui', async (orig) => ({ ...((await orig()) as Record<string, unknown>), useAlertModal: () => alertSpies }))
vi.mock('next/navigation', () => ({ usePathname: () => '/plugins', useRouter: () => ({ push: vi.fn() }) }))

import { PluginsPageClient } from './PluginsPageClient'
import type { PluginEntry, PluginsPage } from '@/lib/plugins/pageModel'
import { PERMISSION_TEXT } from '@/lib/plugins/permissions'

const PERMS = (['session:read', 'llm:invoke'] as const).map((id) => ({ id, ...PERMISSION_TEXT[id] }))

function entry(state: PluginEntry['state'], over: Partial<PluginEntry> = {}): PluginEntry {
  const installed = state === 'not_installed'
    ? null
    : {
        version: '1.0.0', previousVersion: null, status: state === 'disabled' ? 'ready' : state === 'revoked' ? 'ready' : state,
        enabled: state !== 'disabled', dataVersion: 1, grantedPermissions: ['session:read', 'llm:invoke'], installedAt: null,
        revokedReason: state === 'revoked' ? 'Sends transcripts out.' : null, operationKind: null, lastError: state === 'failed' ? 'worker_failed: the worker is failed' : null,
      }
  return {
    id: 'echo', displayName: 'Echo', description: 'The test fixture.', inCatalog: true, state, installed,
    available: { version: '1.1.0', dataVersion: 1, platform: '>=1.0.0 <2.0.0', permissions: PERMS },
    update: null, installBlocked: null, ...over,
  }
}

function model(plugins: PluginEntry[], over: Partial<PluginsPage> = {}): PluginsPage {
  return {
    platformVersion: '1.0.0', managesPlugins: true,
    catalog: { state: 'ok', message: null, official: true, extraKey: false, replayed: false, serial: 3 },
    plugins, ...over,
  }
}

let page: PluginsPage
let status: unknown
let pageAnswer: (() => Promise<Response>) | null
const posts: { url: string; body: unknown }[] = []
const fetchMock = vi.fn()

beforeEach(() => {
  page = model([entry('not_installed')])
  status = { platformVersion: '1.0.0', runner: { reachable: true, state: 'ok', workers: 1, platformVersion: '1.0.0' } }
  pageAnswer = null
  posts.length = 0
  for (const s of Object.values(alertSpies)) s.mockClear()
  fetchMock.mockReset().mockImplementation(async (url: string, init?: RequestInit) => {
    if (url === '/api/plugins' && !init?.method) return pageAnswer ? pageAnswer() : new Response(JSON.stringify(page), { status: 200 })
    if (url === '/api/plugins/status') return new Response(JSON.stringify(status), { status: 200 })
    if (init?.method === 'POST') {
      posts.push({ url, body: init.body instanceof FormData ? init.body : JSON.parse(String(init.body)) })
      return new Response(JSON.stringify({ plugin: { pluginId: 'echo', status: 'ready' } }), { status: 200 })
    }
    return new Response('{}', { status: 404 })
  })
  vi.stubGlobal('fetch', fetchMock)
  vi.spyOn(window, 'confirm').mockImplementation(() => true)
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

function show() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <PluginsPageClient />
    </QueryClientProvider>,
  )
}
const card = async () => within(await screen.findByTestId('plugin-card-echo'))
const buttons = (scope: ReturnType<typeof within>) => scope.queryAllByRole('button').map((b: HTMLElement) => b.textContent?.trim())

describe('the page', () => {
  test('a loading skeleton first', async () => {
    let release!: (r: Response) => void
    pageAnswer = () => new Promise((r) => (release = r))
    show()
    expect(screen.getByTestId('plugins-loading')).toBeTruthy()
    release(new Response(JSON.stringify(page), { status: 200 }))
    await screen.findByTestId('plugin-card-echo')
  })

  test('the header: title, wiki link, the catalog repository link, the platform version', async () => {
    show()
    expect(await screen.findByRole('heading', { name: 'Plugins' })).toBeTruthy()
    expect(screen.getByText(/Optional features installed from the RedAmon plugin catalog/)).toBeTruthy()
    const wiki = screen.getByRole('link', { name: 'Open Plugins wiki page' })
    expect(wiki.getAttribute('href')).toBe('https://github.com/samugit83/redamon/wiki/Plugins')
    const repo = screen.getByRole('link', { name: /github\.com\/samugit83\/redamon-plugins/ })
    expect(repo.getAttribute('href')).toBe('https://github.com/samugit83/redamon-plugins')
    expect(repo.getAttribute('target')).toBe('_blank')
    expect(screen.queryByText(/MCP Tool Plugins/)).toBeNull()
    expect(screen.getByText(/platform 1\.0\.0/i)).toBeTruthy()
  })

  test('the page cannot be loaded: an error with its code and status, and a retry', async () => {
    pageAnswer = async () => new Response(JSON.stringify({ error: 'The Plugins page could not be read; see the webapp log.', code: 'P2024' }), { status: 500 })
    show()
    expect(await screen.findByText('The Plugins page could not be loaded.')).toBeTruthy()
    expect(screen.getByText('The Plugins page could not be read; see the webapp log. (P2024 · HTTP 500)')).toBeTruthy()
    expect(screen.getByRole('button', { name: /try again/i })).toBeTruthy()
  })

  test("Next's empty 500 still names its status", async () => {
    pageAnswer = async () => new Response('', { status: 500 })
    show()
    expect(await screen.findByText('The Plugins page could not be loaded (empty_response · HTTP 500)')).toBeTruthy()
  })

  test('an empty catalog with nothing installed: "No plugins available"', async () => {
    page = model([])
    show()
    expect(await screen.findByText('No plugins available')).toBeTruthy()
  })

  test.each([
    [false, true],
    [null, false],
  ] as const)('inCatalog %s: "no longer in the catalog" shown %s', async (inCatalog, shown) => {
    page = model([entry('ready', { inCatalog })])
    show()
    const card = await screen.findByTestId('plugin-card-echo')
    expect(/no longer in the catalog/.test(card.textContent ?? '')).toBe(shown)
  })

  test('the catalog unreachable with nothing installed: no claim about what it lists', async () => {
    page = model([], { catalog: { state: 'unreachable', message: 'The plugin catalog could not be reached (http_error).', official: false, extraKey: false, replayed: false, serial: null } })
    show()
    expect(await screen.findByText('No plugins installed')).toBeTruthy()
    expect(screen.queryByText(/catalog lists no plugin/)).toBeNull()
    expect(screen.getByText(/until then an admin can use Install from file/)).toBeTruthy()
  })

  test('the runner down: the banner says actions are unavailable and versions keep applying', async () => {
    status = { platformVersion: '1.0.0', runner: { reachable: false, error: 'runner_unavailable' } }
    show()
    const banner = await screen.findByTestId('runner-banner')
    expect(banner.textContent).toMatch(/Plugin actions are unavailable; approved skill versions keep applying/)
  })
})

describe('the catalog', () => {
  test('official, with no expiry: a catalog never expires', async () => {
    show()
    const s = await screen.findByTestId('catalog-status')
    expect(s.textContent).toMatch(/Official catalog/)
    expect(s.textContent).not.toMatch(/expire/i)
    expect(within(s).queryAllByText(/./).filter((el) => el.className.includes('chipWarning'))).toEqual([])
  })

  test('a catalog in an error state says nothing about expiry either', async () => {
    page = model([], { catalog: { ...model([]).catalog, state: 'unreachable', message: 'The plugin catalog could not be reached (http_error).' } })
    show()
    expect((await screen.findByTestId('catalog-status')).textContent).not.toMatch(/expire/i)
  })

  test('an extra-key catalog is flagged', async () => {
    page = model([entry('not_installed')], { catalog: { ...model([]).catalog, official: false, extraKey: true } })
    show()
    const s = await screen.findByTestId('catalog-status')
    expect(s.textContent).toMatch(/Custom catalog/)
    expect(s.textContent).toMatch(/PLUGINS_EXTRA_TRUSTED_KEYS/)
  })

  test.each([
    ['unreachable', 'Catalog unreachable'],
    ['invalid', 'Catalog invalid'],
    ['untrusted', 'Catalog not trusted'],
  ] as const)('%s: the reason, installed plugins still managed, Install disabled with why', async (state, label) => {
    page = model(
      [entry('ready'), { ...entry('not_installed', { available: null, installBlocked: 'The catalog is unavailable.' }), id: 'other', displayName: 'Other' }],
      { catalog: { ...model([]).catalog, state, message: 'The plugin catalog could not be reached (http_error).' } },
    )
    show()
    expect((await screen.findByTestId('catalog-status')).textContent).toMatch(label)
    const echo = await card()
    expect(echo.getByRole('button', { name: 'Disable' })).toBeTruthy()
    const other = within(screen.getByTestId('plugin-card-other'))
    expect((other.getByRole('button', { name: 'Install' }) as HTMLButtonElement).disabled).toBe(true)
    expect(other.getByText('The catalog is unavailable.')).toBeTruthy()
  })
})

describe('card states, as an admin', () => {
  test.each<[PluginEntry['state'], Partial<PluginEntry>, string[]]>([
    ['not_installed', {}, ['Install']],
    ['not_installed', { keptData: true }, ['Install', 'Delete kept data']],
    ['ready', {}, ['Disable', 'Uninstall']],
    ['ready', { update: { version: '1.1.0', newPermissions: [], migratesData: false } }, ['Update to 1.1.0', 'Disable', 'Uninstall']],
    ['disabled', {}, ['Enable', 'Uninstall']],
    ['failed', {}, ['Retry', 'Uninstall']],
    ['incompatible', {}, ['Uninstall']],
    ['incompatible', { update: { version: '1.1.0', newPermissions: [], migratesData: false } }, ['Update to 1.1.0', 'Uninstall']],
    ['revoked', {}, ['Uninstall']],
    // A fixed release is how a revoked plugin comes back (README.PLUGINS.md §6.2).
    ['revoked', { update: { version: '1.1.0', newPermissions: [], migratesData: false } }, ['Update to 1.1.0', 'Uninstall']],
    ['installing', {}, []],
    ['updating', {}, []],
    ['uninstalling', {}, []],
  ])('%s %j → %j', async (state, over, expected) => {
    page = model([entry(state, over)])
    show()
    const c = await card()
    expect(buttons(c).filter((b: string | undefined) => b !== 'Details')).toEqual(expected)
    if (['installing', 'updating', 'uninstalling'].includes(state)) expect(c.getByRole('status')).toBeTruthy()
  })

  test('a failed plugin shows its last error to the admin', async () => {
    page = model([entry('failed')])
    show()
    expect((await card()).getByText(/worker_failed: the worker is failed/)).toBeTruthy()
  })

  test('a revoked plugin shows the reason', async () => {
    page = model([entry('revoked')])
    show()
    expect((await card()).getByText(/Sends transcripts out\./)).toBeTruthy()
  })

  test('the card carries the plugin badge, the versions and what it may do', async () => {
    page = model([entry('ready', { update: { version: '1.1.0', newPermissions: [], migratesData: false } })])
    show()
    const c = await card()
    expect(c.getByTitle('RedAmon plugin')).toBeTruthy()
    expect(c.getByText(/Installed 1\.0\.0/)).toBeTruthy()
    expect(c.getByText(/1\.1\.0 available/)).toBeTruthy()
    expect(c.getByText(PERMISSION_TEXT['session:read'].title)).toBeTruthy()
  })
})

describe('actions', () => {
  test('Install opens the consent prompt and posts the release permissions', async () => {
    show()
    fireEvent.click((await card()).getByRole('button', { name: 'Install' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText(PERMISSION_TEXT['session:read'].consent)).toBeTruthy()
    fireEvent.click(within(dialog).getByRole('checkbox'))
    fireEvent.click(within(dialog).getByRole('button', { name: /^Install 1\.1\.0/ }))
    await waitFor(() => expect(posts).toHaveLength(1))
    expect(posts[0]).toEqual({ url: '/api/plugins/echo/install', body: { version: '1.1.0', acceptedPermissions: ['session:read', 'llm:invoke'] } })
  })

  test('a refused install shows the reason through the alert modal', async () => {
    fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
      if (init?.method === 'POST') return new Response(JSON.stringify({ error: 'The archive does not match.', code: 'sha256_mismatch' }), { status: 422 })
      if (url === '/api/plugins/status') return new Response(JSON.stringify(status), { status: 200 })
      return new Response(JSON.stringify(page), { status: 200 })
    })
    show()
    fireEvent.click((await card()).getByRole('button', { name: 'Install' }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.click(within(dialog).getByRole('checkbox'))
    fireEvent.click(within(dialog).getByRole('button', { name: /^Install 1\.1\.0/ }))
    await waitFor(() => expect(alertSpies.alertError).toHaveBeenCalled())
    expect(String((alertSpies.alertError.mock.calls[0] as unknown[])[0])).toMatch(/The archive does not match/)
  })

  test('Disable asks through the alert modal, never window.confirm', async () => {
    page = model([entry('ready')])
    show()
    fireEvent.click((await card()).getByRole('button', { name: 'Disable' }))
    await waitFor(() => expect(posts).toHaveLength(1))
    expect(alertSpies.confirm).toHaveBeenCalled()
    expect(window.confirm).not.toHaveBeenCalled()
    expect(posts[0].url).toBe('/api/plugins/echo/disable')
  })

  test('Disable answered no: nothing is posted', async () => {
    alertSpies.confirm.mockImplementationOnce(async () => false)
    page = model([entry('ready')])
    show()
    fireEvent.click((await card()).getByRole('button', { name: 'Disable' }))
    await waitFor(() => expect(alertSpies.confirm).toHaveBeenCalled())
    expect(posts).toEqual([])
  })

  test('Enable and Retry post enable', async () => {
    page = model([entry('failed')])
    show()
    fireEvent.click((await card()).getByRole('button', { name: 'Retry' }))
    await waitFor(() => expect(posts.map((p) => p.url)).toEqual(['/api/plugins/echo/enable']))
  })

  test('Update shows the permissions it adds and posts the full list', async () => {
    page = model([entry('ready', {
      available: { version: '1.2.0', dataVersion: 2, platform: '>=1.0.0', permissions: [...PERMS, { id: 'override:skill.text', ...PERMISSION_TEXT['override:skill.text'] }] },
      update: { version: '1.2.0', newPermissions: ['override:skill.text'], migratesData: true },
    })])
    show()
    fireEvent.click((await card()).getByRole('button', { name: 'Update to 1.2.0' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText('New')).toBeTruthy()
    expect(within(dialog).getByText(/moves the plugin's data/)).toBeTruthy()
    fireEvent.click(within(dialog).getByRole('checkbox'))
    fireEvent.click(within(dialog).getByRole('button', { name: /^Update 1\.2\.0/ }))
    await waitFor(() => expect(posts).toHaveLength(1))
    expect(posts[0]).toEqual({
      url: '/api/plugins/echo/update',
      body: { version: '1.2.0', acceptedPermissions: ['session:read', 'llm:invoke', 'override:skill.text'] },
    })
  })

  test('Uninstall keeps the data by default', async () => {
    page = model([entry('ready')])
    show()
    fireEvent.click((await card()).getByRole('button', { name: 'Uninstall' }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Uninstall' }))
    await waitFor(() => expect(posts).toHaveLength(1))
    expect(posts[0]).toEqual({ url: '/api/plugins/echo/uninstall', body: { mode: 'keep', confirm: 'echo' } })
  })

  test('Delete kept data: only the purge, behind the export and the typed id, then posts it', async () => {
    page = model([entry('not_installed', { keptData: true })])
    show()
    const c = await card()
    expect(c.getByText(/data kept/)).toBeTruthy()
    fireEvent.click(c.getByRole('button', { name: 'Delete kept data' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).queryByRole('radio')).toBeNull()
    const go = within(dialog).getByRole('button', { name: 'Delete kept data' }) as HTMLButtonElement
    expect(go.disabled).toBe(true)
    // The export is fetched by the page and saved from a blob; only a real download unlocks the purge.
    const base = fetchMock.getMockImplementation()!
    fetchMock.mockImplementation(async (url: string, init?: RequestInit) =>
      url === '/api/plugins/echo/export' ? new Response('{"rows":[]}', { status: 200 }) : base(url, init),
    )
    URL.createObjectURL = vi.fn(() => 'blob:x')
    URL.revokeObjectURL = vi.fn()
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    fireEvent.click(within(dialog).getByRole('button', { name: /download the export/i }))
    fireEvent.change(within(dialog).getByRole('textbox', { name: /type echo/i }), { target: { value: 'echo' } })
    await waitFor(() => expect(go.disabled).toBe(false))
    fireEvent.click(go)
    await waitFor(() => expect(posts).toHaveLength(1))
    expect(posts[0]).toEqual({ url: '/api/plugins/echo/uninstall', body: { mode: 'purge', confirm: 'echo' } })
  })

  test('Details opens the admin drawer; a rollback from it asks first, then posts', async () => {
    page = model([entry('ready')])
    fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
      if (init?.method === 'POST') {
        posts.push({ url, body: JSON.parse(String(init.body)) })
        return new Response(JSON.stringify({ plugin: { pluginId: 'echo', status: 'ready' } }))
      }
      if (url === '/api/plugins/status') return new Response(JSON.stringify(status))
      if (url === '/api/plugins/echo') {
        return new Response(JSON.stringify({
          plugin: { ...entry('ready'), installed: { ...entry('ready').installed!, version: '1.1.0', previousVersion: '1.0.0' } },
          admin: {
            lastError: null, versionsOnDisk: ['1.0.0', '1.1.0'], grantedPermissions: [], data: { rows: 0, bytes: 0, maxRows: 1, maxBytes: 1 },
            activeVersions: 0, dormantVersions: 0, rollback: { possible: true, migrates: false },
          },
        }))
      }
      if (url.startsWith('/api/plugins/echo/logs')) return new Response(JSON.stringify({ lines: [] }))
      return new Response(JSON.stringify(page))
    })
    show()
    fireEvent.click((await card()).getByRole('button', { name: 'Details' }))
    fireEvent.click(await screen.findByRole('button', { name: /roll back to 1\.0\.0/i }))
    await waitFor(() => expect(posts).toHaveLength(1))
    expect(alertSpies.confirm).toHaveBeenCalled()
    // The version the admin confirmed: the server refuses if the previous one changed meanwhile.
    expect(posts[0]).toEqual({ url: '/api/plugins/echo/rollback', body: { toVersion: '1.0.0' } })
  })

  test('Details is for installed plugins only', async () => {
    page = model([entry('not_installed')])
    show()
    expect((await card()).queryByRole('button', { name: 'Details' })).toBeNull()
  })

  test('Install from file is offered to the admin', async () => {
    show()
    expect(await screen.findByRole('button', { name: /install from file/i })).toBeTruthy()
  })

  test('Install from file: a reinstall that needs the restore answer asks it in the same dialog', async () => {
    // jsdom's crypto has no subtle; every browser that runs the page has it.
    vi.stubGlobal('crypto', webcrypto)
    const archive = Buffer.from('pretend this is a gzip archive')
    const sha = createHash('sha256').update(archive).digest('hex')
    const catalogText = JSON.stringify({ plugins: [{ id: 'echo', displayName: 'Echo', releases: [{ version: '1.0.0', sha256: sha, permissions: ['session:read'] }] }] })
    const base = fetchMock.getMockImplementation()!
    const forms: FormData[] = []
    fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
      if (url === '/api/plugins/offline-install') {
        forms.push(init!.body as FormData)
        if (forms.length === 1) {
          return new Response(JSON.stringify({ error: 'This plugin left 2 approved skill version(s): say whether to restore them.', code: 'restore_choice_required', details: ['2'] }), { status: 400 })
        }
        return new Response(JSON.stringify({ plugin: { pluginId: 'echo', status: 'ready' } }))
      }
      return base(url, init)
    })
    show()
    fireEvent.click(await screen.findByRole('button', { name: /install from file/i }))
    const dialog = within(await screen.findByRole('dialog'))
    const inputs = document.querySelectorAll('input[type="file"]')
    const pick = (i: number, name: string, content: string | Buffer) =>
      fireEvent.change(inputs[i], { target: { files: [new File([new Uint8Array(Buffer.from(content))], name)] } })
    pick(0, 'echo-1.0.0.tar.gz', archive)
    pick(1, 'catalog.json', catalogText)
    pick(2, 'catalog.json.sig', '{"keyId":"k","sig":"x"}')
    fireEvent.click(await dialog.findByRole('checkbox'))
    fireEvent.click(dialog.getByRole('button', { name: /^Install Echo 1\.0\.0/ }))
    expect(await dialog.findByText(/left 2 approved skill versions/)).toBeTruthy()
    expect(alertSpies.alertError).not.toHaveBeenCalled()
    fireEvent.click(dialog.getByRole('radio', { name: /factory text/i }))
    fireEvent.click(dialog.getByRole('button', { name: /^Install Echo 1\.0\.0/ }))
    await waitFor(() => expect(forms).toHaveLength(2))
    expect(forms[1].get('restoreOverrides')).toBe('false')
  })
})
