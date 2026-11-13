/**
 * The admin console's user detail, Device sessions section (step 6.10, GV-17): the account's
 * browsers for whoever may sign it out (the row's `revoke_sessions` action), Revoke going to
 * /api/users/[id]/sessions/[sid] (audited there: route.test.ts); another admin's needs the person's
 * own password; the own account points to My account; without the action, a line says why and
 * nothing is read.
 *
 * Run: npx vitest run --no-file-parallelism "src/app/admin/users/[id]/page.deviceSessions.test.tsx"
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, within, waitFor, fireEvent } from '@testing-library/react'
import type { ReactNode } from 'react'
import { AuthContext } from '@/providers/authContext'
import { FLAGS_ON, fakeAuth } from '@/providers/__testing__/fakeAuth'
import { AlertProvider } from '@/components/ui'
import type { DirectoryRow, UserDetail } from '@/lib/authz/userDirectory'

const h = vi.hoisted(() => ({ id: 'm-1' }))
vi.mock('next/navigation', () => ({
  useRouter: () => ({ replace: vi.fn(), push: vi.fn() }),
  useParams: () => ({ id: h.id }),
  usePathname: () => `/admin/users/${h.id}`,
}))
vi.mock('next/link', () => ({
  __esModule: true,
  default: ({ href, children, ...rest }: { href: string; children: ReactNode }) => <a href={href} {...rest}>{children}</a>,
}))
vi.mock('@/providers/ProjectProvider', () => ({ useProject: () => ({ setUserId: vi.fn() }) }))
vi.mock('@/hooks/usePasswordPolicy', () => ({ usePasswordPolicy: () => null }))
vi.mock('@/components/admin/UserPermissionsPanel', () => ({ UserPermissionsPanel: () => <p>permissions panel</p> }))

import AdminUserDetailPage from './page'

const row = (over: Partial<DirectoryRow> = {}): DirectoryRow => ({
  id: 'm-1', name: 'Marco', email: 'marco@e2e.local', accountType: 'member', status: 'active', mustChangePassword: false,
  lastLoginAt: null, createdAt: '2026-10-01T00:00:00.000Z', sets: [], profile: null, projects: { owned: 0, shared: null },
  self: false, actions: ['revoke_sessions'], ...over,
})
const SESSION = {
  id: 'sess-9', createdAt: '2026-11-13T08:00:00.000Z', lastSeenAt: '2026-11-13T11:00:00.000Z', expiresAt: '2026-11-20T08:00:00.000Z',
  ip: '203.0.113.7', ipTrusted: true, userAgent: 'Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0', state: 'active', revokedAt: null, current: false,
}
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status })
let user: DirectoryRow
let fetchMock: ReturnType<typeof vi.fn>

beforeEach(() => {
  user = row()
  fetchMock = vi.fn(async (input: string, init?: RequestInit) => {
    const url = String(input)
    if (init?.method === 'DELETE') return json({ id: 'sess-9', changed: true, state: 'revoked', agent: { sockets: { closed: 0 } } })
    if (url.startsWith('/api/admin/users/')) return json({ user, owned: [], shared: { state: 'off' }, audit: { rows: [] } } satisfies UserDetail)
    if (url.endsWith('/sessions')) return json({ sessions: [SESSION] })
    return json({ tokens: [], features: { agentInTheLoop: false } })
  })
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function renderPage() {
  return render(
    <AuthContext.Provider value={fakeAuth({ ...FLAGS_ON, governance: true }, ['users:read', 'users:revoke_sessions'])}>
      <AlertProvider><AdminUserDetailPage /></AlertProvider>
    </AuthContext.Provider>,
  )
}
const section = async () => within(await screen.findByRole('region', { name: 'Device sessions' }))
const sessionReads = () => fetchMock.mock.calls.filter(([url, init]) => String(url).endsWith('/sessions') && !(init as RequestInit | undefined)?.method)

describe('device sessions on the user detail', () => {
  test('listed for whoever may sign the account out; Revoke confirmed goes to the account\'s route', async () => {
    renderPage()
    const s = await section()
    fireEvent.click(await s.findByRole('button', { name: /^Revoke the session of Firefox on Linux/ }))
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Revoke' }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/users/m-1/sessions/sess-9', { method: 'DELETE' }))
    expect(sessionReads()[0][0]).toBe('/api/users/m-1/sessions')
  })

  test('another admin\'s: the revoke asks for the person\'s own password', async () => {
    user = row({ accountType: 'admin' })
    renderPage()
    const s = await section()
    fireEvent.click(await s.findByRole('button', { name: /^Revoke the session of Firefox on Linux/ }))
    expect(await screen.findByLabelText('Your password')).toBeInTheDocument()
  })

  test('the own account points to My account; without the action a line says why; neither reads the sessions', async () => {
    user = row({ self: true })
    renderPage()
    expect((await section()).getByRole('link', { name: 'My account' })).toHaveAttribute('href', '/account')
    cleanup()
    user = row({ actions: [] })
    renderPage()
    expect((await section()).getByText(/Only whoever may sign this account out/)).toBeInTheDocument()
    expect(sessionReads()).toEqual([])
  })
})
