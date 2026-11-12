/**
 * The Plugins page lists every enabled plugin's `nav` entry with an "Open" link to its page
 * (design §6: nav entries live there and at the top of the plugin's page, not in the global
 * header). Nothing is drawn when no plugin has one.
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { PluginNavLinks } from './PluginNavLinks'

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function draw(status: number, body: unknown) {
  vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify(body), { status })))
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <PluginNavLinks />
    </QueryClientProvider>,
  )
}

const echo = {
  pluginId: 'echo',
  displayName: 'Echo',
  updating: false,
  nav: { label: 'Echo items', icon: 'list', screen: 'ui/home.json' },
  chatSessionActions: [],
  projectSkillsRow: [],
}
const skiller = { pluginId: 'skiller', displayName: 'Skiller', updating: false, chatSessionActions: [{ key: 'a' }], projectSkillsRow: [] }

describe('PluginNavLinks', () => {
  test('one Open link per plugin with a nav entry, with its badge', async () => {
    draw(200, [echo, skiller])
    const link = await screen.findByRole('link', { name: /open echo items/i })
    expect(link.getAttribute('href')).toBe('/plugins/echo')
    expect(screen.getByTitle('RedAmon plugin').textContent).toContain('Echo')
    expect(screen.queryByText(/skiller/i)).toBeNull()
  })

  test('an updating plugin says so', async () => {
    draw(200, [{ ...echo, updating: true }])
    expect(await screen.findByText(/updating/i)).toBeInTheDocument()
  })

  test('no nav entries: nothing', async () => {
    const { container } = draw(200, [skiller])
    await new Promise((r) => setTimeout(r, 0))
    expect(container.textContent).toBe('')
  })

  test('an answer that is not a list draws nothing and breaks nothing', async () => {
    const { container } = draw(200, { plugins: [], catalog: {} })
    await new Promise((r) => setTimeout(r, 0))
    expect(container.textContent).toBe('')
  })

  test('refused for plugins:use: no link and no hint, nothing failed (step 3.9)', async () => {
    const { container } = draw(403, { error: 'You do not hold the permission this action needs (plugins:use).', code: 'forbidden', permission: 'plugins:use' })
    await new Promise((r) => setTimeout(r, 0))
    await new Promise((r) => setTimeout(r, 0))
    expect(screen.queryByTestId('plugin-nav-error')).toBeNull()
    expect(container.textContent).toBe('')
  })

  // The links must not just vanish: a quiet line says what failed, and Retry asks again.
  test('a failed request shows a small hint with the code and status, and Retry reads again', async () => {
    draw(500, { error: 'The plugin items could not be read; see the webapp log.', code: 'P2024' })
    const hint = await screen.findByTestId('plugin-nav-error')
    expect(hint.textContent).toContain('The plugin items could not be read; see the webapp log. (P2024 · HTTP 500)')
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify([echo]), { status: 200 })))
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByRole('link', { name: /open echo items/i })).toBeInTheDocument()
    expect(screen.queryByTestId('plugin-nav-error')).toBeNull()
  })

  test("Next's empty 500 still names its status", async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('', { status: 500 })))
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <PluginNavLinks />
      </QueryClientProvider>,
    )
    expect((await screen.findByTestId('plugin-nav-error')).textContent).toContain('Plugin items could not be loaded (empty_response · HTTP 500)')
  })
})
