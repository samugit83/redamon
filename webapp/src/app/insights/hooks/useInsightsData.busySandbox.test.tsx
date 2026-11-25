/**
 * The Insights "Active Shells" count follows the Sessions panel's rule for a busy sandbox (group 1,
 * E3; S16b): a 200 naming a sandbox that did not answer keeps that sandbox's rows from the previous
 * read, a sandbox that answered without its row drops it, and a previous read older than
 * STALE_ROW_MAX_MS is no ground to keep anything.
 *
 * Run: npx vitest run --no-file-parallelism src/app/insights/hooks/useInsightsData.busySandbox.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, waitFor, act, cleanup } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { useActiveSessions } from './useInsightsData'
import { STALE_ROW_MAX_MS } from '@/hooks/useActiveSessions'

const B1 = { id: 1, sandbox: 'bbbbb1', type: 'shell', info: '', connection: '', target_ip: '', chat_session_id: 'session_x' }
const lists = (sessions: unknown[], extra: Record<string, unknown> = {}) =>
  ({ sessions, jobs: [], non_msf_sessions: [], agent_busy: false, ...extra })

let client: QueryClient
let answer: unknown
const wrapper = ({ children }: { children: ReactNode }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>

beforeEach(() => {
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify(answer), { status: 200 })))
})
afterEach(() => {
  cleanup()
  client.clear()
  vi.unstubAllGlobals()
})

async function readTwice(second: unknown) {
  answer = lists([B1])
  const { result } = renderHook(() => useActiveSessions(), { wrapper })
  await waitFor(() => expect(result.current.data?.sessions).toHaveLength(1))
  answer = second
  let read: Awaited<ReturnType<typeof result.current.refetch>> | undefined
  await act(async () => { read = await result.current.refetch() })
  // react-query notifies its observers on a later tick: wait for the hook to show what was read.
  await waitFor(() => expect(result.current.data).toBe(read!.data))
  return result.current.data!
}

describe('Insights sessions and a busy sandbox', () => {
  test("keeps the row of the sandbox named as not answering, so the count does not drop", async () => {
    const data = await readTwice(lists([], { unavailable: ['bbbbb1'], unavailable_count: 1 }))
    expect(data.sessions.map(s => `${s.sandbox}:${s.id}`)).toEqual(['bbbbb1:1'])
    expect(data.unavailable_count).toBe(1)
  })

  test('drops it once the sandbox answers without it', async () => {
    const data = await readTwice(lists([], { unavailable_count: 0 }))
    expect(data.sessions).toEqual([])
  })

  test('a cache entry older than STALE_ROW_MAX_MS keeps nothing (an Insights read can be minutes old)', async () => {
    answer = lists([B1])
    const { result } = renderHook(() => useActiveSessions(), { wrapper })
    await waitFor(() => expect(result.current.data?.sessions).toHaveLength(1))
    const [[key, data]] = client.getQueriesData({ queryKey: ['insights', 'sessions'] })
    client.setQueryData(key, data, { updatedAt: Date.now() - STALE_ROW_MAX_MS - 1 })
    answer = lists([], { unavailable: ['bbbbb1'], unavailable_count: 1 })
    let read: Awaited<ReturnType<typeof result.current.refetch>> | undefined
    await act(async () => { read = await result.current.refetch() })
    expect(read!.data!.sessions).toEqual([])
  })
})
