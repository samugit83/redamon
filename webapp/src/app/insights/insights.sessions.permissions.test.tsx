/**
 * The Insights "Active Shells" card reads GET /api/agent/sessions, which asks agent:sessions (step
 * 3.9). With RBAC_PERMISSIONS_ENABLED on, someone without it gets no card and no request (it would
 * only be refused); while the session is read nothing is asked. With the switch off, the card and
 * its request are as before whatever the set holds (DV-30).
 *
 * Run: npx vitest run --no-file-parallelism src/app/insights/insights.sessions.permissions.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, renderHook, screen, act, waitFor, cleanup } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { AuthContext } from '@/providers/authContext'
import type { AuthContextValue } from '@/providers/AuthProvider'
import type { RbacFlags } from '@/lib/authz/flags'
import type { PermissionId } from '@/lib/authz/permissions'
import { useActiveSessions } from './hooks/useInsightsData'
import { KPICards } from './components/KPICards'

const FLAGS_OFF: RbacFlags = { sharedToolsCompat: false, identity: false, permissions: false, sharing: false, sharingWrite: false, governance: false }
const FLAGS_ON: RbacFlags = { ...FLAGS_OFF, identity: true, permissions: true }

function auth({ flags = null, held = [], isLoading = false }: { flags?: RbacFlags | null; held?: PermissionId[]; isLoading?: boolean }): AuthContextValue {
  return {
    user: isLoading ? null : { id: 'm1', name: 'Member', email: 'member@e2e.local', role: 'standard', flags: flags ?? undefined },
    isLoading,
    capabilities: new Set(held),
    flags,
    sessionError: null,
    login: async () => ({}),
    logout: async () => {},
    refresh: async () => {},
  }
}

const EMPTY = { sessions: [], jobs: [], non_msf_sessions: [], agent_busy: false }
let fetchMock: ReturnType<typeof vi.fn>
let current: AuthContextValue | null
let client: QueryClient
const wrapper = ({ children }: { children: ReactNode }) => (
  <QueryClientProvider client={client}>
    <AuthContext.Provider value={current}>{children}</AuthContext.Provider>
  </QueryClientProvider>
)
const sessionReads = () => fetchMock.mock.calls.filter(([url]) => String(url) === '/api/agent/sessions')

beforeEach(() => {
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  fetchMock = vi.fn(async () => new Response(JSON.stringify(EMPTY), { status: 200 }))
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  client.clear()
  vi.unstubAllGlobals()
})

describe('Insights sessions query and agent:sessions', () => {
  test('switch on, without agent:sessions: the sessions are never asked for', async () => {
    current = auth({ flags: FLAGS_ON, held: ['graph:read'] })
    const { result } = renderHook(() => useActiveSessions(), { wrapper })
    await act(async () => { await Promise.resolve() })
    expect(sessionReads()).toHaveLength(0)
    expect(result.current.fetchStatus).toBe('idle')
    expect(result.current.isError).toBe(false)
  })

  test('switch on, with agent:sessions: the sessions are read as before', async () => {
    current = auth({ flags: FLAGS_ON, held: ['agent:sessions'] })
    const { result } = renderHook(() => useActiveSessions(), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(sessionReads()).toHaveLength(1)
  })

  test('switch off: the sessions are read whatever the set holds (DV-30)', async () => {
    current = auth({ flags: FLAGS_OFF, held: [] })
    const { result } = renderHook(() => useActiveSessions(), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(sessionReads()).toHaveLength(1)
  })

  test('while the session is read nothing is asked; once it allows, the sessions are read', async () => {
    current = auth({ isLoading: true })
    const { result, rerender } = renderHook(() => useActiveSessions(), { wrapper })
    await act(async () => { await Promise.resolve() })
    expect(sessionReads()).toHaveLength(0)

    current = auth({ flags: FLAGS_ON, held: ['agent:sessions'] })
    rerender()
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(sessionReads()).toHaveLength(1)
  })
})

describe('Insights Active Shells card and agent:sessions', () => {
  const cards = (value: AuthContextValue) => render(
    <AuthContext.Provider value={value}>
      <KPICards items={[]} sessions={EMPTY as never} pipeline={{ recon: null, gvm: null, githubHunt: null }} />
    </AuthContext.Provider>,
  )

  test('switch on, without agent:sessions: no Active Shells card, the pipeline cards stay', () => {
    cards(auth({ flags: FLAGS_ON, held: ['graph:read'] }))
    expect(screen.queryByText('Active Shells')).toBeNull()
    expect(screen.getByText('Recon Pipeline')).toBeTruthy()
    expect(screen.getAllByText('idle')).toHaveLength(3)
  })

  test('switch on, with agent:sessions: the card shows the count', () => {
    cards(auth({ flags: FLAGS_ON, held: ['agent:sessions'] }))
    expect(screen.getByText('Active Shells')).toBeTruthy()
    expect(screen.getByText('0')).toBeTruthy()
  })

  test('switch off: the card shows the count whatever the set holds (DV-30)', () => {
    cards(auth({ flags: FLAGS_OFF, held: [] }))
    expect(screen.getByText('Active Shells')).toBeTruthy()
  })
})
