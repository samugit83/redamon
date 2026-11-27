/**
 * Traffic queries fail with the route's reason, code and status. The list URL
 * carries host/q/bodyq filter text (target data), so no error may quote it.
 *
 * Run: npx vitest run --no-file-parallelism src/app/traffic/hooks/useTrafficData.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { renderHook, waitFor, cleanup, act } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { useTrafficList, useDeleteTraffic, DEFAULT_FILTERS } from './useTrafficData'

afterEach(() => { cleanup(); vi.unstubAllGlobals() })

function wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

describe('useTrafficData', () => {
  const selections: [{ ids: string[] } | { filter: Record<string, string> }, unknown][] = [
    [{ filter: {} }, { all: true }],
    [{ filter: { host: 'fixture.example' } }, { filter: { host: 'fixture.example' } }],
    [{ ids: ['a'] }, { ids: ['a'] }],
  ]
  test.each(selections)('sends an explicit delete selection for %j', async (body, expected) => {
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({ deleted: 1 })))
    vi.stubGlobal('fetch', fetch)
    const { result } = renderHook(() => useDeleteTraffic('p1'), { wrapper })
    await act(async () => { await result.current.mutateAsync(body) })
    expect(fetch).toHaveBeenCalledWith('/api/traffic/p1', expect.objectContaining({
      method: 'DELETE', body: JSON.stringify(expected),
    }))
  })

  test('a list failure carries code and status and never the filter text', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(
      JSON.stringify({ error: 'Failed to list traffic', code: 'P2024' }), { status: 500 })))
    const filters = { ...DEFAULT_FILTERS, host: 'secret.target.example', bodyq: 'AKIA-SECRET' }
    const { result } = renderHook(() => useTrafficList('p1', filters), { wrapper })
    await waitFor(() => expect(result.current.isError).toBe(true))
    const message = (result.current.error as Error).message
    expect(message).toBe('Failed to list traffic (P2024 · HTTP 500)')
    expect(message).not.toContain('secret.target.example')
    expect(message).not.toContain('AKIA-SECRET')
  })

  test('a network failure on delete is a network_error, not "Delete failed" alone', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('Failed to fetch')))
    const { result } = renderHook(() => useDeleteTraffic('p1'), { wrapper })
    let caught: unknown
    await act(async () => {
      try { await result.current.mutateAsync({ ids: ['a'] }) } catch (e) { caught = e }
    })
    expect((caught as Error).message).toBe('Delete failed (network_error)')
  })
})
