/**
 * My account → Sessions with device sessions (step 6.10, UI-09): with RBAC_GOVERNANCE_ENABLED on the
 * section lists the account's browsers under "Sign out everywhere"; off, the section is the step 2.11
 * one and /api/account/sessions is never asked (DV-30).
 *
 * Run: npx vitest run --no-file-parallelism src/app/account/page.deviceSessions.test.tsx
 */
import { describe, test, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, cleanup, waitFor, within } from '@testing-library/react'
import { AlertProvider } from '@/components/ui'

const h = vi.hoisted(() => ({ auth: { user: null as Record<string, unknown> | null, isLoading: false, sessionError: null }, fetch: vi.fn() }))
vi.mock('next/navigation', () => ({ useSearchParams: () => new URLSearchParams('') }))
vi.mock('@/providers/AuthProvider', () => ({ useAuth: () => h.auth }))
vi.mock('@/hooks/useUsers', () => ({ useUsers: () => ({ data: [], isLoading: false, error: null }) }))

import AccountPage from './page'

const json = (body: unknown) => new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } })
const member = (flags: Record<string, boolean>) =>
  ({ id: 'member-1', email: 'marco@e2e.local', name: 'Marco', role: 'standard', accountType: 'member', flags })

beforeEach(() => {
  h.fetch.mockReset().mockImplementation(async (url: string) => {
    if (url === '/api/auth/password-policy') return json({ minLength: 12, maxBytes: 72, rules: true, description: 'At least 12 characters.' })
    if (url === '/api/account/activity') return json({ notices: [], events: [] })
    if (url === '/api/account/sessions') {
      return json({ sessions: [{
        id: 'here', createdAt: '2026-11-13T08:00:00.000Z', lastSeenAt: '2026-11-13T11:00:00.000Z', expiresAt: '2026-11-20T08:00:00.000Z',
        ip: '203.0.113.7', ipTrusted: true, userAgent: 'Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0', state: 'active', revokedAt: null, current: true,
      }] })
    }
    // My permissions is not this test's: its read refused, it shows its own notice.
    if (url.startsWith('/api/users/member-1/permissions')) {
      return new Response(JSON.stringify({ error: 'Forbidden', code: 'forbidden', permission: 'users:read' }), { status: 403 })
    }
    throw new Error(`unexpected fetch ${url}`)
  })
  vi.stubGlobal('fetch', h.fetch)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

const sessionReads = () => h.fetch.mock.calls.filter((c) => c[0] === '/api/account/sessions')

describe('My account → Sessions', () => {
  test('governance on: the browsers are listed under Sign out everywhere, this one marked', async () => {
    h.auth = { user: member({ identity: true, permissions: true, governance: true }), isLoading: false, sessionError: null }
    render(<AlertProvider><AccountPage /></AlertProvider>)
    const section = screen.getByRole('region', { name: 'Sessions and tokens' })
    const list = await within(section).findByRole('list', { name: 'Your device sessions' })
    expect(list).toHaveTextContent('Firefox on Linux')
    expect(list).toHaveTextContent('This device')
    expect(within(section).getByRole('button', { name: 'Sign out everywhere' })).toBeInTheDocument()
  })

  test.each([
    ['identity on', { identity: true }],
    ['identity and permissions on', { identity: true, permissions: true }],
  ])('switch off (%s): no device list, /api/account/sessions never asked', async (_name, flags) => {
    h.auth = { user: member(flags), isLoading: false, sessionError: null }
    render(<AlertProvider><AccountPage /></AlertProvider>)
    await waitFor(() => expect(h.fetch.mock.calls.some((c) => c[0] === '/api/account/activity')).toBe(true))
    expect(screen.queryByRole('list', { name: 'Your device sessions' })).toBeNull()
    expect(sessionReads()).toEqual([])
  })
})
