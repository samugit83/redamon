/**
 * QuotaUsage (step 6.8): the account's quota and use from GET /api/users/[id]/quota, for My account
 * (own) and the admin user detail. Hidden on 404 (RBAC_GOVERNANCE_ENABLED off); loading, denied,
 * error with Retry; Root and an unlimited account say so; every limit is named in words.
 *
 * Run: npx vitest run --no-file-parallelism src/components/quotas/QuotaUsage.test.tsx
 */
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import { QuotaUsage } from './QuotaUsage'

const REPORT = {
  enforced: true,
  quota: { maxProjects: 2, maxConcurrentScans: null, maxConcurrentAgentRuns: 1, maxMcpTokens: 3, maxMcpTokenExpiryDays: 90, llmDailyCalls: null },
  sources: {
    maxProjects: { kind: 'set', setId: 'cset-1', setName: 'Lab team' }, maxConcurrentScans: { kind: 'default' },
    maxConcurrentAgentRuns: { kind: 'user' }, maxMcpTokens: { kind: 'default' }, maxMcpTokenExpiryDays: { kind: 'default' },
    llmDailyCalls: { kind: 'default' },
  },
  use: { maxProjects: 1, maxMcpTokens: 0 },
}

let answer: { status: number; body: unknown }
const fetchMock = vi.fn(async (_url: string) => new Response(JSON.stringify(answer.body), { status: answer.status }))
beforeEach(() => {
  answer = { status: 200, body: REPORT }
  fetchMock.mockClear()
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('QuotaUsage', () => {
  test('quota and use, each limit in words with where it comes from', async () => {
    render(<QuotaUsage userId="mem-c" own />)
    const projects = (await screen.findByRole('rowheader', { name: 'Projects owned' })).closest('tr')!
    expect(within(projects).getAllByRole('cell').map((c) => c.textContent)).toEqual(['2 projects', '1', 'Permission set Lab team'])
    const runs = screen.getByRole('rowheader', { name: 'Agent runs at once' }).closest('tr')!
    expect(within(runs).getAllByRole('cell').map((c) => c.textContent)).toEqual(['1 runs', 'Counted when it starts', 'Set for you'])
    expect(screen.getByRole('rowheader', { name: 'Scans at once' }).closest('tr')).toHaveTextContent('Unlimited')
    expect(String(fetchMock.mock.calls[0][0])).toBe('/api/users/mem-c/quota')
  })

  test("another account's own entry reads as set for this account", async () => {
    render(<QuotaUsage userId="mem-c" own={false} />)
    expect((await screen.findByRole('rowheader', { name: 'Agent runs at once' })).closest('tr')).toHaveTextContent('Set for this account')
  })

  test('switch off (404): nothing is shown', async () => {
    answer = { status: 404, body: { error: 'Not found' } }
    const { container } = render(<QuotaUsage userId="mem-c" own />)
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalled())
    await vi.waitFor(() => expect(container).toBeEmptyDOMElement())
  })

  test('Root and an unlimited account say so', async () => {
    answer = { status: 200, body: { ...REPORT, enforced: false, sources: { ...REPORT.sources, maxProjects: { kind: 'root' } } } }
    render(<QuotaUsage userId="root-1" own />)
    expect(await screen.findByText('Root is never limited by a quota.')).toBeInTheDocument()
  })

  test('denied: the permission named', async () => {
    answer = { status: 403, body: { error: 'Forbidden', code: 'forbidden', permission: 'users:read' } }
    render(<QuotaUsage userId="mem-c" own={false} />)
    expect(await screen.findByRole('alert')).toHaveTextContent('users:read')
  })

  test('an answer without the quota is an error, never a blank section', async () => {
    answer = { status: 200, body: {} }
    render(<QuotaUsage userId="mem-c" own />)
    expect(await screen.findByRole('alert')).toHaveTextContent('unexpected_answer')
  })

  test('error with Retry', async () => {
    answer = { status: 500, body: { error: 'boom', code: 'P1001' } }
    render(<QuotaUsage userId="mem-c" own />)
    expect(await screen.findByRole('alert')).toHaveTextContent('P1001')
    answer = { status: 200, body: REPORT }
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByRole('rowheader', { name: 'Projects owned' })).toBeInTheDocument()
  })
})
