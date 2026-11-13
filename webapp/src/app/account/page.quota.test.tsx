/**
 * My account > Quota (step 6.8; GV-09..GV-13): with RBAC_GOVERNANCE_ENABLED on the person reads their
 * own quota and use (`GET /api/users/<own id>/quota`, components/quotas/QuotaUsage.tsx); with it off
 * the section is not there and nothing is read.
 *
 * Run: npx vitest run --no-file-parallelism src/app/account/page.quota.test.tsx
 */
import { describe, test, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, cleanup, within } from '@testing-library/react'
import { AlertProvider } from '@/components/ui'
import { viewOf } from '@/components/admin/__testing__/permissionViews'

const h = vi.hoisted(() => ({
  auth: { user: null as Record<string, unknown> | null, isLoading: false, sessionError: null },
  fetch: vi.fn(),
}))

vi.mock('next/navigation', () => ({ useSearchParams: () => new URLSearchParams('') }))
vi.mock('@/providers/AuthProvider', () => ({ useAuth: () => h.auth }))
vi.mock('@/hooks/useUsers', () => ({ useUsers: () => ({ data: [], isLoading: false, error: null }) }))

import AccountPage from './page'

const FLAGS = { sharedToolsCompat: false, identity: true, permissions: false, sharing: false, sharingWrite: false, governance: false }
const member = (flags: Record<string, boolean>) =>
  ({ id: 'member-1', email: 'marco@e2e.local', name: 'Marco', role: 'standard', accountType: 'member', flags })
const REPORT = {
  enforced: true,
  quota: { maxProjects: 2, maxConcurrentScans: null, maxConcurrentAgentRuns: null, maxMcpTokens: null, maxMcpTokenExpiryDays: null, llmDailyCalls: null },
  sources: Object.fromEntries(['maxProjects', 'maxConcurrentScans', 'maxConcurrentAgentRuns', 'maxMcpTokens', 'maxMcpTokenExpiryDays', 'llmDailyCalls'].map((f) => [f, { kind: 'default' }])),
  use: { maxProjects: 1, maxMcpTokens: 0 },
}
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status })
const quotaReads = () => h.fetch.mock.calls.filter((c) => c[0] === '/api/users/member-1/quota')

beforeEach(() => {
  h.fetch.mockReset().mockImplementation(async (url: string) => {
    if (url === '/api/users/member-1/quota') return json(REPORT)
    if (url === '/api/users/member-1/permissions') return json(viewOf({ userId: 'member-1', sets: [{ id: 'builtin:default-member' }] }))
    if (url === '/api/auth/password-policy') return json({ minLength: 12, maxBytes: 72, rules: true, description: 'At least 12 characters.' })
    if (url === '/api/account/activity') return json({ notices: [], events: [] })
    if (url.startsWith('/api/account/sessions')) return json({ sessions: [] })
    return json({})
  })
  vi.stubGlobal('fetch', h.fetch)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

const renderPage = () => render(<AlertProvider><AccountPage /></AlertProvider>)

describe('My account: Quota', () => {
  test('governance on: the own quota with its use', async () => {
    h.auth = { user: member({ ...FLAGS, permissions: true, governance: true }), isLoading: false, sessionError: null }
    renderPage()
    const row = (await screen.findByRole('rowheader', { name: 'Projects owned' })).closest('tr')!
    expect(within(row).getAllByRole('cell').map((c) => c.textContent)).toEqual(['2 projects', '1', 'Instance default'])
    expect(screen.getByRole('region', { name: 'Quota' })).toBeTruthy()
    expect(quotaReads()).toHaveLength(1)
  })

  test('governance off: no section and nothing read', async () => {
    h.auth = { user: member(FLAGS), isLoading: false, sessionError: null }
    renderPage()
    await screen.findByRole('heading', { name: /password/i })
    expect(screen.queryByRole('region', { name: 'Quota' })).toBeNull()
    expect(quotaReads()).toHaveLength(0)
  })
})
