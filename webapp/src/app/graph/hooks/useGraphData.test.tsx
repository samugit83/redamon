/**
 * Scan Timeline — which graph the screen actually fetches.
 *
 * This hook decides between the LIVE graph and a saved snapshot. Getting it wrong
 * is the F0 failure mode in miniature: the user would be looking at one version's
 * data under another version's header. It also must never send a past version
 * down the ETag/`fresh=1` path, which is only meaningful for the live graph.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, waitFor, cleanup } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { useGraphData } from './useGraphData'

function wrapper({ children }: { children: React.ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

let fetchMock: ReturnType<typeof vi.fn>
const urls = () => fetchMock.mock.calls.map(c => String(c[0]))

beforeEach(() => {
  vi.clearAllMocks()
  fetchMock = vi.fn().mockResolvedValue({
    ok: true,
    status: 200,
    headers: new Headers({ etag: '"abc"' }),
    json: async () => ({ nodes: [], links: [] }),
  })
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('useGraphData', () => {
  test('with no version selected it reads the LIVE graph', async () => {
    const { result } = renderHook(() => useGraphData('p1'), { wrapper })
    await waitFor(() => expect(result.current.data).toBeTruthy())
    expect(urls()[0]).toBe('/api/graph?projectId=p1')
  })

  test('with a version selected it reads THAT version, never /api/graph', async () => {
    const { result } = renderHook(() => useGraphData('p1', 'v2'), { wrapper })
    await waitFor(() => expect(result.current.data).toBeTruthy())
    expect(urls()).toEqual(['/api/projects/p1/versions/v2/graph'])
    expect(urls().some(u => u.startsWith('/api/graph'))).toBe(false)
  })

  test('refetchFresh only applies to the live graph (a snapshot cannot go stale)', async () => {
    const { result } = renderHook(() => useGraphData('p1', 'v2'), { wrapper })
    await waitFor(() => expect(result.current.data).toBeTruthy())
    const before = fetchMock.mock.calls.length
    await result.current.refetchFresh()
    expect(fetchMock.mock.calls.length).toBe(before)

    const live = renderHook(() => useGraphData('p1'), { wrapper })
    await waitFor(() => expect(live.result.current.data).toBeTruthy())
    await live.result.current.refetchFresh()
    expect(urls().some(u => u.includes('fresh=1'))).toBe(true)
  })

  test('a version read surfaces the server reason when it has no bytes', async () => {
    fetchMock.mockResolvedValue({
      ok: false,
      status: 409,
      headers: new Headers(),
      json: async () => ({ error: 'This version has no stored snapshot', emptySnapshot: true }),
    })
    const { result } = renderHook(() => useGraphData('p1', 'v2'), { wrapper })
    await waitFor(() => expect(result.current.error).toBeTruthy())
    expect(String(result.current.error)).toMatch(/no stored snapshot/)
  })

  test('nothing is fetched without a project', () => {
    renderHook(() => useGraphData(null), { wrapper })
    expect(fetchMock).not.toHaveBeenCalled()
  })

  test('disabled fetches nothing, and neither refetch path can sneak one through', async () => {
    const { result } = renderHook(() => useGraphData('p1', null, false), { wrapper })
    expect(fetchMock).not.toHaveBeenCalled()
    // react-query still honours an explicit refetch() on a disabled query, and
    // the graph page fires one from every recon SSE event - so the guard has to
    // live on the refetch paths too, not only on `enabled`.
    await result.current.refetch()
    await result.current.refetchFresh()
    expect(fetchMock).not.toHaveBeenCalled()
  })

  test('re-enabling fetches the graph it had been holding back', async () => {
    const { result, rerender } = renderHook(
      ({ on }: { on: boolean }) => useGraphData('p1', null, on),
      { wrapper, initialProps: { on: false } }
    )
    expect(fetchMock).not.toHaveBeenCalled()
    rerender({ on: true })
    await waitFor(() => expect(result.current.data).toBeTruthy())
    expect(urls()).toEqual(['/api/graph?projectId=p1'])
  })

  test('live and version reads are cached under different keys', async () => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    const shared = ({ children }: { children: React.ReactNode }) =>
      <QueryClientProvider client={client}>{children}</QueryClientProvider>

    const live = renderHook(() => useGraphData('p1'), { wrapper: shared })
    await waitFor(() => expect(live.result.current.data).toBeTruthy())
    const past = renderHook(() => useGraphData('p1', 'v2'), { wrapper: shared })
    await waitFor(() => expect(past.result.current.data).toBeTruthy())

    // Two distinct requests: a cached live payload must never satisfy a version read.
    expect(urls()).toEqual(['/api/graph?projectId=p1', '/api/projects/p1/versions/v2/graph'])
  })
})
