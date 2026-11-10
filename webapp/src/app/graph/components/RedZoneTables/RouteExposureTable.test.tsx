/**
 * RouteExposureTable: the status badge for pending leads, the filters, the
 * snippet masked again and rendered as text (no element is created from it),
 * the empty and error states.
 *
 * Run: npx vitest run src/app/graph/components/RedZoneTables/RouteExposureTable.test.tsx
 */
import { describe, test, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, cleanup, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { RouteExposureTable } from './RouteExposureTable'
import { maskSnippet } from './redact'

vi.mock('../MuteNode', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../MuteNode')>()),
  MuteNodeButton: () => <button>mute</button>,
}))

const ROWS = [
  { nodeId: '11', host: '10.0.0.5', path: '/xss-snippet', url: 'http://10.0.0.5/xss-snippet',
    kind: 'anonymous_access', routeClass: 'unknown', severity: 'info', confidence: 0.4, status: 'pending',
    anonStatus: 200, authedStatus: null, authExpectedBy: '', leakSignals: 'pii, pii_others', piiTypes: 'email',
    signature: '', generatedBy: 'found',
    evidenceSnippet: '<img src=x onerror=alert(1)> a@lab.invalid 1234567890', updatedAt: null },
  { nodeId: '12', host: '10.0.0.5', path: '/.env', url: 'http://10.0.0.5/.env', kind: 'env_file',
    routeClass: 'unknown', severity: 'high', confidence: 0.95, status: 'finding', anonStatus: 200,
    authedStatus: null, authExpectedBy: '', leakSignals: '', piiTypes: '', signature: 'env_lines',
    generatedBy: 'vcs', evidenceSnippet: '3 KEY=value line(s)', updatedAt: null },
]

function wrap(children: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

let response: { ok: boolean; status: number; json: () => Promise<unknown> }
beforeEach(() => {
  response = { ok: true, status: 200, json: async () => ({ rows: ROWS, meta: { totalRows: 2, pending: 1 } }) }
  vi.stubGlobal('fetch', vi.fn(async () => response))
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

describe('RouteExposureTable', () => {
  test('lists every row with its status, pending leads badged', async () => {
    render(wrap(<RouteExposureTable projectId="p1" />))
    await waitFor(() => expect(screen.getByText('/.env')).toBeTruthy())
    expect(screen.getByText('Pending')).toBeTruthy()
    expect(screen.getByText('Finding')).toBeTruthy()
    expect(screen.getByText(/1 finding\(s\) · 1 pending lead\(s\) · 2 total/)).toBeTruthy()
  })

  test('the snippet is masked again and rendered as text, never as HTML', async () => {
    const { container } = render(wrap(<RouteExposureTable projectId="p1" />))
    await waitFor(() => expect(screen.getByText('/xss-snippet')).toBeTruthy())
    expect(container.querySelector('img')).toBeNull()
    const cell = screen.getByText(/onerror=alert\(1\)/)
    expect(cell.textContent).toContain('<img src=x onerror=alert(1)>')
    expect(cell.textContent).not.toContain('@lab.invalid')
    expect(cell.textContent).toContain('<email>')
    expect(cell.textContent).not.toContain('1234567890')
  })

  test('the empty state names where to enable the module', async () => {
    response = { ok: true, status: 200, json: async () => ({ rows: [], meta: { totalRows: 0, pending: 0 } }) }
    render(wrap(<RouteExposureTable projectId="p1" />))
    await waitFor(() => expect(screen.getByText(/No route exposure results yet/)).toBeTruthy())
  })

  test('a failing fetch shows the error state', async () => {
    response = { ok: false, status: 500, json: async () => ({ error: 'boom' }) }
    render(wrap(<RouteExposureTable projectId="p1" />))
    await waitFor(() => expect(screen.queryByText('/.env')).toBeNull())
    await waitFor(() => expect(document.body.textContent).toMatch(/error|failed|boom/i))
  })
})

describe('maskSnippet', () => {
  test('masks e-mails, long digit runs and tokens; keeps the rest', () => {
    expect(maskSnippet('a@b.co 1234567 abcdefghijklmnopqrstuvwxyz <b>')).toBe('<email> <n> <tok> <b>')
    expect(maskSnippet(null)).toBe('-')
  })
})
