/**
 * Per-column filtering on the JS Recon page.
 *
 * JS Recon is the one page in the table dropdown that does not use the Red Zone
 * shell, so its filter wiring is hand-written and needs its own coverage. Two
 * things here exist nowhere else:
 *
 *   - columns reached through a dotted path (`validation.status`)
 *   - sub-tabs that stack several row shapes, which must NOT offer a filter at
 *     all rather than offering one that silently drops the other shapes
 *
 * Run: npx vitest run src/app/graph/components/JsReconTable/jsReconFilters.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, waitFor, fireEvent, cleanup } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { createElement } from 'react'

import { JsReconTable } from './JsReconTable'

const PROJECT = 'proj-1'

// `nodeId` is the internal graph id the route projects; `id` is the node's own
// stored id property. They are different values on purpose.
const DATA = {
  secrets: [
    { nodeId: '101', id: 's1', severity: 'critical', name: 'aws_key', redacted_value: 'AKIA…', category: 'cloud',
      source_url: 'https://a.invalid/app.js', detection_method: 'regex', confidence: 0.9,
      validation: { status: 'validated' } },
    { nodeId: '102', id: 's2', severity: 'low', name: 'generic_token', redacted_value: 'tok…', category: 'generic',
      source_url: 'https://b.invalid/vendor.js', detection_method: 'entropy', confidence: 0.3,
      validation: { status: 'unvalidated' } },
  ],
  endpoints: [
    { nodeId: '201', id: 'e1', severity: 'info', method: 'GET', path: '/api/v1/users', type: 'rest', category: 'api',
      base_url: 'https://a.invalid', source_js: 'app.js' },
    { nodeId: '202', id: 'e2', severity: 'info', method: 'POST', path: '/api/v1/login', type: 'rest', category: 'auth',
      base_url: 'https://a.invalid', source_js: 'app.js' },
  ],
  dom_sinks: [{ nodeId: '301', id: 'd1', severity: 'medium', finding_type: 'sink', type: 'innerHTML', pattern: 'x' }],
  frameworks: [{ nodeId: '401', id: 'f1', name: 'react', version: '18' }],
}

interface PatchCall { featureKey: string; value: any }

function installFetch(prefs: Record<string, unknown> = {}, data: unknown = DATA) {
  const patches: PatchCall[] = []
  globalThis.fetch = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
    const u = typeof url === 'string' ? url : url.toString()
    if (u.includes('/api/js-recon/')) {
      return new Response(JSON.stringify(data), {
        status: 200, headers: { 'Content-Type': 'application/json' },
      })
    }
    if (u === '/api/user/preferences' && (!init?.method || init.method === 'GET')) {
      return new Response(JSON.stringify(prefs), {
        status: 200, headers: { 'Content-Type': 'application/json' },
      })
    }
    if (init?.method === 'PATCH') {
      const b = JSON.parse(init.body as string) as PatchCall
      patches.push(b)
      return new Response(JSON.stringify({ [b.featureKey]: b.value }), {
        status: 200, headers: { 'Content-Type': 'application/json' },
      })
    }
    return new Response('not found', { status: 404 })
  }) as typeof fetch
  return patches
}

function makeWrapper() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } })
  return ({ children }: { children: ReactNode }) =>
    createElement(QueryClientProvider, { client }, children)
}

function renderTable(search = '') {
  return render(<JsReconTable projectId={PROJECT} search={search} />, { wrapper: makeWrapper() })
}

function rowCount(container: HTMLElement): number {
  return container.querySelectorAll('tbody tr').length
}

async function openFilters() {
  fireEvent.click(await screen.findByRole('button', { name: /^Filters/i }))
  return screen.findByPlaceholderText('Find a column…')
}

function openColumnCard(label: string) {
  const header = screen.getByRole('button', { name: new RegExp(`^Filter by ${label}( \\(active\\))?$`) })
  if (header.getAttribute('aria-expanded') === 'false') fireEvent.click(header)
  return header
}

async function goToTab(label: string) {
  fireEvent.click(await screen.findByRole('button', { name: new RegExp(`^${label}`) }))
}

afterEach(() => { cleanup(); vi.clearAllMocks() })

// ---------------------------------------------------------------------------

describe('JS Recon column filters', () => {
  test('the secrets tab offers its own columns', async () => {
    installFetch()
    renderTable()
    await openFilters()
    for (const label of ['Severity', 'Type', 'Category', 'Validation', 'Detection']) {
      expect(screen.getByRole('button', { name: new RegExp(`^Filter by ${label}`) })).toBeTruthy()
    }
  })

  test('picking a value narrows the rows', async () => {
    installFetch()
    const { container } = renderTable()
    await waitFor(() => expect(rowCount(container)).toBe(2))
    await openFilters()
    openColumnCard('Severity')
    fireEvent.click(await screen.findByRole('checkbox', { name: /critical/ }))
    await waitFor(() => expect(rowCount(container)).toBe(1))
  })

  test('a dotted column path filters on the nested value', async () => {
    installFetch()
    const { container } = renderTable()
    await openFilters()
    openColumnCard('Validation')
    // `validation.status`, not a top-level property - a plain `row[key]` read
    // would offer an empty facet list here.
    fireEvent.click(await screen.findByRole('checkbox', { name: /^validated/ }))
    await waitFor(() => expect(rowCount(container)).toBe(1))
  })

  test('the free-text search still applies on top', async () => {
    installFetch()
    const { container } = renderTable('generic')
    await waitFor(() => expect(rowCount(container)).toBe(1))
  })

  test('each sub-tab filters independently', async () => {
    installFetch()
    const { container } = renderTable()
    await openFilters()
    openColumnCard('Severity')
    fireEvent.click(await screen.findByRole('checkbox', { name: /critical/ }))
    await waitFor(() => expect(rowCount(container)).toBe(1))

    await goToTab('Endpoints')
    // The secrets filter must not follow: endpoints has no `critical` row and
    // would render empty if it did.
    await waitFor(() => expect(rowCount(container)).toBe(2))
  })

  test('the Node ID column is filterable', async () => {
    installFetch()
    renderTable()
    await openFilters()
    expect(screen.getByRole('button', { name: /^Filter by Node ID/ })).toBeTruthy()
  })

  test('a tab that stacks several row shapes offers no column filter', async () => {
    installFetch()
    renderTable()
    await screen.findByRole('button', { name: /^Filters/i })
    await goToTab('Security')
    await waitFor(() => expect(screen.queryByRole('button', { name: /^Filters/i })).toBeNull())
  })
})

describe('JS Recon filter persistence', () => {
  test('a change is saved under the tab\'s own scope', async () => {
    const patches = installFetch()
    renderTable()
    await openFilters()
    openColumnCard('Severity')
    fireEvent.click(await screen.findByRole('checkbox', { name: /critical/ }))

    await waitFor(() => expect(patches.some(p => p.featureKey === 'tableFilters')).toBe(true))
    const value = patches.filter(p => p.featureKey === 'tableFilters').pop()!.value
    expect(value[PROJECT]['redzone:jsRecon:secrets'].severity.selected).toEqual(['critical'])
  })

  test('a saved filter is restored on mount', async () => {
    installFetch({
      tableFilters: {
        [PROJECT]: {
          'redzone:jsRecon:secrets': {
            severity: {
              presence: 'any', selected: ['low'], listMode: 'any', min: null, max: null,
              from: '', to: '', q: '', textMode: 'contains', negate: false,
            },
          },
        },
      },
    })
    const { container } = renderTable()
    await waitFor(() => expect(rowCount(container)).toBe(1))
    expect(await screen.findByText(/Severity is low/)).toBeTruthy()
  })
})

describe('JS Recon Node ID column', () => {
  function firstHeaders(container: HTMLElement): string[] {
    return [...container.querySelectorAll('table')].map(
      t => t.querySelector('thead th')?.textContent?.trim() ?? '')
  }

  function firstCellIds(container: HTMLElement): (string | null)[] {
    return [...container.querySelectorAll('tbody tr')].map(
      r => r.querySelector('td')?.querySelector('[data-node-id]')?.getAttribute('data-node-id') ?? null)
  }

  test('leads the secrets table with the graph id, not the id property', async () => {
    installFetch()
    const { container } = renderTable()
    await waitFor(() => expect(rowCount(container)).toBe(2))
    expect(firstHeaders(container)).toEqual(['Node ID'])
    expect(firstCellIds(container).sort()).toEqual(['101', '102'])
  })

  test('leads every stacked table on the Security tab', async () => {
    installFetch()
    const { container } = renderTable()
    await screen.findByRole('button', { name: /^Filters/i })
    await goToTab('Security')
    // Frameworks + DOM Sinks, each with its own header row.
    await waitFor(() => expect(firstHeaders(container)).toEqual(['Node ID', 'Node ID']))
    expect(firstCellIds(container)).toEqual(['401', '301'])
  })
})

describe('JS Recon secrets: TruffleHog detection, line and alternate names', () => {
  const TH_DATA = {
    secrets: [
      { nodeId: '501', id: 'th1', severity: 'high', name: 'GitHub Token Classic', redacted_value: 'ghp_…', category: 'vcs',
        source_url: 'https://a.invalid/app.js', detection_method: 'trufflehog', line_number: 42, alternate_names: [],
        confidence: 'medium', validation: { status: 'unknown' } },
      { nodeId: '502', id: 'rx1', severity: 'critical', name: 'Stripe Secret Key', redacted_value: 'sk_l…', category: 'payment',
        source_url: 'https://a.invalid/app.js', detection_method: 'regex', line_number: 7,
        alternate_names: ['Generic API Key', 'TruffleHog:Stripe'], confidence: 'high', validation: { status: 'rejected' } },
      // Written before line_number / alternate_names / detection_method existed.
      { nodeId: '503', id: 'old1', severity: 'low', name: 'Sentry DSN', redacted_value: 'https…', category: 'monitoring',
        source_url: 'https://a.invalid/old.js', confidence: 'low', validation: { status: 'unvalidated' } },
    ],
  }

  function cellsByHeader(container: HTMLElement, nodeId: string): Record<string, string> {
    const headers = [...container.querySelectorAll('thead th')].map(th => th.textContent?.trim() ?? '')
    const row = [...container.querySelectorAll('tbody tr')]
      .find(r => r.querySelector(`[data-node-id="${nodeId}"]`))!
    const cells = [...row.querySelectorAll('td')].map(td => td.textContent?.trim() ?? '')
    return Object.fromEntries(headers.map((h, i) => [h, cells[i]]))
  }

  test('Detection reads TruffleHog, Line shows line_number', async () => {
    installFetch({}, TH_DATA)
    const { container } = renderTable()
    await waitFor(() => expect(rowCount(container)).toBe(3))
    expect(cellsByHeader(container, '501')).toMatchObject({ Detection: 'TruffleHog', Line: '42' })
    expect(cellsByHeader(container, '502')).toMatchObject({ Detection: 'Regex', Line: '7' })
  })

  test('the name cell lists the other names, TruffleHog ones readably', async () => {
    installFetch({}, TH_DATA)
    const { container } = renderTable()
    await waitFor(() => expect(rowCount(container)).toBe(3))
    expect(cellsByHeader(container, '502').Type).toBe('Stripe Secret Keyalso: Generic API Key, TruffleHog (Stripe)')
    // An empty list adds nothing.
    expect(cellsByHeader(container, '501').Type).toBe('GitHub Token Classic')
  })

  test('an old node without the properties shows a dash, not a blank or 0', async () => {
    installFetch({}, TH_DATA)
    const { container } = renderTable()
    await waitFor(() => expect(rowCount(container)).toBe(3))
    const old = cellsByHeader(container, '503')
    expect(old.Detection).toBe('—')
    expect(old.Line).toBe('—')
    expect(old.Type).toBe('Sentry DSN')
  })

  test('the Detection filter separates TruffleHog-only rows', async () => {
    installFetch({}, TH_DATA)
    const { container } = renderTable()
    await waitFor(() => expect(rowCount(container)).toBe(3))
    await openFilters()
    openColumnCard('Detection')
    fireEvent.click(await screen.findByRole('checkbox', { name: /^trufflehog/ }))
    await waitFor(() => expect(rowCount(container)).toBe(1))
    expect(cellsByHeader(container, '501').Detection).toBe('TruffleHog')
  })

  test('the alternate names are a filterable column', async () => {
    installFetch({}, TH_DATA)
    renderTable()
    await openFilters()
    expect(screen.getByRole('button', { name: /^Filter by Also matched as/ })).toBeTruthy()
  })
})
