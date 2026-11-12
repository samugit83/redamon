/**
 * My account > My permissions (step 3.13; UI-09, PE-16, UI-12, DV-06): with the permissions switch
 * on, the signed-in person reads what they hold and why: the sets in force, their overrides with
 * expiry and reason, and each permission with its "because" lines (`GET
 * /api/users/<own id>/permissions`). Loading, error with Retry, denied and "holds nothing" states;
 * with the switch off the section is not there and nothing is read.
 *
 * Run: npx vitest run --no-file-parallelism src/app/account/page.myPermissions.test.tsx
 */
import { describe, test, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, cleanup, fireEvent, within } from '@testing-library/react'
import { AlertProvider } from '@/components/ui'
import { json, viewOf } from '@/components/admin/__testing__/permissionViews'

const h = vi.hoisted(() => ({
  auth: { user: null as Record<string, unknown> | null, isLoading: false, sessionError: null },
  fetch: vi.fn(),
  mine: { status: 200, body: null as unknown },
}))

vi.mock('next/navigation', () => ({ useSearchParams: () => new URLSearchParams('') }))
vi.mock('@/providers/AuthProvider', () => ({ useAuth: () => h.auth }))
vi.mock('@/hooks/useUsers', () => ({ useUsers: () => ({ data: [], isLoading: false, error: null }) }))

import AccountPage from './page'

const FLAGS = { sharedToolsCompat: false, identity: true, permissions: true, sharing: false, sharingWrite: false, governance: false }
const member = (flags: Record<string, boolean> = FLAGS) =>
  ({ id: 'member-1', email: 'marco@e2e.local', name: 'Marco', role: 'standard', accountType: 'member', flags })
const MINE = viewOf({
  userId: 'member-1', sets: [{ id: 'builtin:read-only-analyst' }],
  overrides: [{ permission: 'scan:gvm', effect: 'grant', expiresAt: '2026-12-31T10:00:00.000Z', reason: 'Q4 audit' }],
})
const reads = () => h.fetch.mock.calls.filter((c) => c[0] === '/api/users/member-1/permissions')
const section = () => screen.getByRole('region', { name: 'My permissions' })

beforeEach(() => {
  h.auth = { user: member(), isLoading: false, sessionError: null }
  h.mine = { status: 200, body: MINE }
  h.fetch.mockReset().mockImplementation(async (url: string) => {
    if (url === '/api/users/member-1/permissions') return json(h.mine.body, h.mine.status)
    if (url === '/api/auth/password-policy') return json({ minLength: 12, maxBytes: 72, rules: true, description: 'At least 12 characters.' })
    if (url === '/api/account/activity') return json({ notices: [], events: [] })
    throw new Error(`unexpected fetch ${url}`)
  })
  vi.stubGlobal('fetch', h.fetch)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

const renderPage = () => render(<AlertProvider><AccountPage /></AlertProvider>)

describe('My permissions lists reasons', () => {
  test('the sets in force, the overrides with expiry and reason, each permission with its because lines', async () => {
    renderPage()
    expect(await within(section()).findByText(/In force: set Read-only analyst \(assigned\)/)).toBeTruthy()
    const overrides = within(section()).getByRole('list', { name: 'My overrides' })
    expect(overrides.textContent).toContain('Granted scan:gvm until')
    expect(overrides.textContent).toContain('Q4 audit')
    expect(within(section()).getByRole('listitem', { name: 'graph:read held' }).textContent)
      .toContain('Because granted by the set Read-only analyst (assigned)')
    expect(within(section()).getByRole('listitem', { name: 'scan:gvm held' }).textContent)
      .toContain('Because granted by an override until')
    fireEvent.click(within(section()).getByRole('checkbox', { name: 'Show the permissions not held' }))
    expect(within(section()).getByRole('listitem', { name: 'agent:chat not held' }).textContent)
      .toContain('No set in force holds it (Read-only analyst)')
    expect(reads()).toHaveLength(1)
  })

  test('Root: says so', async () => {
    h.auth = { user: { ...member(), id: 'member-1', accountType: 'root' }, isLoading: false, sessionError: null }
    h.mine = { status: 200, body: { ...MINE, accountType: 'root', sets: [], assignment: { sets: [], overrides: [] } } }
    renderPage()
    expect(await within(section()).findByText(/You are Root: you hold every permission/)).toBeTruthy()
  })
})

describe('states (DV-06)', () => {
  test('loading, then an error with Retry, then the list', async () => {
    h.mine = { status: 500, body: { error: 'Could not read the account\'s permissions', code: 'P1001' } }
    renderPage()
    expect(within(section()).getByRole('status').textContent).toBe('Loading your permissions…')
    expect((await within(section()).findByRole('alert')).textContent).toContain('P1001')
    h.mine = { status: 200, body: MINE }
    fireEvent.click(within(section()).getByRole('button', { name: 'Retry' }))
    expect(await within(section()).findByRole('listitem', { name: 'graph:read held' })).toBeTruthy()
  })

  test('denied: a refusal naming a permission shows the notice', async () => {
    h.mine = { status: 403, body: { error: 'Forbidden', code: 'forbidden', permission: 'users:read' } }
    renderPage()
    expect(await within(section()).findByText('You do not have the permission this needs.')).toBeTruthy()
  })

  test('holding nothing says so', async () => {
    h.mine = { status: 200, body: viewOf({ userId: 'member-1', sets: [{ id: 'builtin:no-access' }] }) }
    renderPage()
    expect(await within(section()).findByText('You hold no permission.')).toBeTruthy()
  })

  test('the permissions switch off: no section, nothing read', async () => {
    h.auth = { user: member({ ...FLAGS, permissions: false }), isLoading: false, sessionError: null }
    renderPage()
    await screen.findByRole('heading', { name: 'My activity' })
    expect(screen.queryByRole('region', { name: 'My permissions' })).toBeNull()
    expect(reads()).toHaveLength(0)
  })
})
