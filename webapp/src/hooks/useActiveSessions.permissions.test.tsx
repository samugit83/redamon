/**
 * The sessions panel's list asks nothing it would be refused (step 3.9: GET /api/agent/sessions asks
 * agent:sessions, no project). With RBAC_PERMISSIONS_ENABLED on, someone /api/auth/me says lacks it
 * is never polled; while the session is still being read nothing is asked, since the switch is not
 * known yet. With the switch off, or with no AuthProvider above, the list is read as before (DV-30).
 *
 * Run: npx vitest run --no-file-parallelism src/hooks/useActiveSessions.permissions.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, act, waitFor, cleanup } from '@testing-library/react'
import type { ReactNode } from 'react'
import { AuthContext } from '@/providers/authContext'
import type { AuthContextValue } from '@/providers/AuthProvider'
import type { RbacFlags } from '@/lib/authz/flags'
import type { PermissionId } from '@/lib/authz/permissions'
import { useActiveSessions } from './useActiveSessions'

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

const LIVE = { sessions: [{ id: 7, type: 'shell' }], jobs: [{ id: 3, name: 'handler' }], non_msf_sessions: [], agent_busy: false }
const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

let fetchMock: ReturnType<typeof vi.fn>
let current: AuthContextValue | null
const wrapper = ({ children }: { children: ReactNode }) => <AuthContext.Provider value={current}>{children}</AuthContext.Provider>
const sessionReads = () => fetchMock.mock.calls.filter(([url]) => String(url) === '/api/agent/sessions')

beforeEach(() => {
  fetchMock = vi.fn(async () => json(200, LIVE))
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.useRealTimers()
  vi.unstubAllGlobals()
})

describe('useActiveSessions and agent:sessions', () => {
  test('switch on, without agent:sessions: nothing is asked, not even by the poll, and the hook says refused', async () => {
    vi.useFakeTimers()
    current = auth({ flags: FLAGS_ON, held: ['agent:chat'] })
    const { result } = renderHook(() => useActiveSessions({ enabled: true, fastPoll: true }), { wrapper })
    await act(async () => { await vi.advanceTimersByTimeAsync(25_000) })
    expect(sessionReads()).toHaveLength(0)
    expect(result.current.refused).toBe(true)
    expect(result.current.isLoading).toBe(false)
    expect(result.current.error).toBeNull()
    expect(result.current.totalCount).toBe(0)
  })

  test('switch on, with agent:sessions: the list is read as before', async () => {
    current = auth({ flags: FLAGS_ON, held: ['agent:sessions'] })
    const { result } = renderHook(() => useActiveSessions({ enabled: true }), { wrapper })
    await waitFor(() => expect(result.current.sessions).toHaveLength(1))
    expect(result.current.refused).toBe(false)
    expect(sessionReads()[0][1]).toEqual({ cache: 'no-store' })
  })

  test('switch off: the list is read whatever the set holds (DV-30)', async () => {
    current = auth({ flags: FLAGS_OFF, held: [] })
    const { result } = renderHook(() => useActiveSessions({ enabled: true }), { wrapper })
    await waitFor(() => expect(result.current.sessions).toHaveLength(1))
    expect(result.current.refused).toBe(false)
  })

  test('no AuthProvider above: the list is read as before', async () => {
    current = null
    const { result } = renderHook(() => useActiveSessions({ enabled: true }), { wrapper })
    await waitFor(() => expect(result.current.sessions).toHaveLength(1))
    expect(result.current.refused).toBe(false)
  })

  test('while the session is read nothing is asked and the list is loading; once it allows, the list is read', async () => {
    current = auth({ isLoading: true })
    const { result, rerender } = renderHook(() => useActiveSessions({ enabled: true }), { wrapper })
    await act(async () => { await Promise.resolve() })
    expect(sessionReads()).toHaveLength(0)
    expect(result.current.isLoading).toBe(true)
    expect(result.current.refused).toBe(false)

    current = auth({ flags: FLAGS_ON, held: ['agent:sessions'] })
    rerender()
    await waitFor(() => expect(result.current.sessions).toHaveLength(1))
  })

  test('a set that loses agent:sessions (an act-as switch) stops the poll and drops the rows it showed', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    current = auth({ flags: FLAGS_ON, held: ['agent:sessions'] })
    const { result, rerender } = renderHook(() => useActiveSessions({ enabled: true }), { wrapper })
    await waitFor(() => expect(result.current.sessions).toHaveLength(1))
    const before = sessionReads().length

    current = auth({ flags: FLAGS_ON, held: [] })
    rerender()
    await act(async () => { await vi.advanceTimersByTimeAsync(25_000) })
    expect(sessionReads()).toHaveLength(before)
    expect(result.current.refused).toBe(true)
    expect(result.current.sessions).toHaveLength(0)
    expect(result.current.jobs).toHaveLength(0)
    expect(result.current.totalCount).toBe(0)
  })
})
