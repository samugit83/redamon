/**
 * The Dependencies tab's "On npm?" column is tri-state (S-19).
 *
 * `npm_exists` is true or false only when the npm registry answered; a node
 * written before the field (or by a lookup that never answered) has none. The
 * table read any falsy value as "No", so every row said "not on npm", a package
 * that IS published included.
 *
 * Run: npx vitest run src/app/graph/components/JsReconTable/jsReconDeps.test.tsx
 */
import { test, expect, vi, afterEach } from 'vitest'
import { render, screen, waitFor, fireEvent, cleanup } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { createElement } from 'react'

import { JsReconTable } from './JsReconTable'

const DATA = {
  dependencies: [
    { nodeId: '1', id: 'd1', severity: 'critical', package_name: '@acme/internal-ui', scope: '@acme', npm_exists: false, title: 'missing' },
    { nodeId: '2', id: 'd2', severity: 'high', package_name: '@acme/billing-core', scope: '@acme', npm_exists: true, title: 'published' },
    { nodeId: '3', id: 'd3', severity: 'critical', package_name: '@corp/legacy', scope: '@corp', npm_exists: null, title: 'older node' },
  ],
}

function installFetch() {
  globalThis.fetch = vi.fn(async (url: string | URL | Request) => {
    const u = typeof url === 'string' ? url : url.toString()
    const body = u.includes('/api/js-recon/') ? DATA : {}
    return new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } })
  }) as typeof fetch
}

function renderTable() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } })
  const wrapper = ({ children }: { children: ReactNode }) => createElement(QueryClientProvider, { client }, children)
  return render(<JsReconTable projectId="proj-1" search="" />, { wrapper })
}

afterEach(() => { cleanup(); vi.clearAllMocks() })

/** The text of one column, by header, keyed by package. */
function column(container: HTMLElement, header: string): Record<string, string> {
  const headers = [...container.querySelectorAll('thead th')].map(th => th.textContent?.trim())
  const at = headers.indexOf(header)
  const pkgAt = headers.indexOf('Package')
  return Object.fromEntries([...container.querySelectorAll('tbody tr')].map(tr => {
    const cells = tr.querySelectorAll('td')
    return [cells[pkgAt].textContent?.trim(), cells[at].textContent?.trim()]
  }))
}

test('each row shows its npm answer and scope, and no answer as unknown', async () => {
  installFetch()
  const { container } = renderTable()
  fireEvent.click(await screen.findByRole('button', { name: /^Dependencies/ }))
  await waitFor(() => expect(container.querySelectorAll('tbody tr').length).toBe(3))

  expect(column(container, 'On npm?')).toEqual({
    '@acme/internal-ui': 'No',
    '@acme/billing-core': 'Yes',
    '@corp/legacy': '-',
  })
  expect(column(container, 'Scope')).toEqual({
    '@acme/internal-ui': '@acme',
    '@acme/billing-core': '@acme',
    '@corp/legacy': '@corp',
  })
})
