/**
 * useAgentHealth: the preflight that stops an agent outage being read as a bad
 * provider config (issue #184).
 *
 * The load-bearing behaviour: it must start at 'unknown' and callers must be
 * able to distinguish that from 'offline'. If a slow probe collapsed into
 * 'offline', the Test button would be disabled on a perfectly healthy stack.
 *
 * Run: npx vitest run src/hooks/useAgentHealth.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, waitFor, act, cleanup } from '@testing-library/react'
import { useAgentHealth } from './useAgentHealth'

let fetchMock: ReturnType<typeof vi.fn>

function ok() {
  return { ok: true, status: 200, json: async () => ({ status: 'healthy', version: '6.13.0' }) }
}
function offline(error: string) {
  return { ok: false, status: 503, json: async () => ({ error }) }
}

beforeEach(() => {
  fetchMock = vi.fn().mockResolvedValue(ok())
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('useAgentHealth', () => {
  test('starts unknown, so a slow probe never disables a working Test button', () => {
    const { result } = renderHook(() => useAgentHealth())
    expect(result.current.status).toBe('unknown')
    expect(result.current.error).toBeNull()
  })

  test('reports online for a healthy agent', async () => {
    const { result } = renderHook(() => useAgentHealth())
    await waitFor(() => expect(result.current.status).toBe('online'))
    expect(result.current.error).toBeNull()
    expect(fetchMock).toHaveBeenCalledWith('/api/agent/health')
  })

  test('surfaces the route message verbatim when the agent is unreachable', async () => {
    const msg = 'Cannot reach the RedAmon agent service at http://agent:8080: the hostname does not resolve'
    fetchMock.mockResolvedValue(offline(msg))

    const { result } = renderHook(() => useAgentHealth())
    await waitFor(() => expect(result.current.status).toBe('offline'))
    expect(result.current.error).toBe(msg)
  })

  test('falls back to a readable message when the body carries no error string', async () => {
    fetchMock.mockResolvedValue({ ok: false, status: 500, json: async () => ({}) })

    const { result } = renderHook(() => useAgentHealth())
    await waitFor(() => expect(result.current.status).toBe('offline'))
    expect(result.current.error).toContain('not responding')
    expect(result.current.error).toContain('500')
  })

  test('treats a browser-side fetch rejection as offline rather than throwing', async () => {
    fetchMock.mockRejectedValue(new TypeError('Failed to fetch'))

    const { result } = renderHook(() => useAgentHealth())
    await waitFor(() => expect(result.current.status).toBe('offline'))
    expect(result.current.error).toContain('Could not reach the RedAmon webapp')
  })

  test('refresh re-probes and recovers once the agent is back', async () => {
    fetchMock.mockResolvedValue(offline('agent container is not running'))
    const { result } = renderHook(() => useAgentHealth())
    await waitFor(() => expect(result.current.status).toBe('offline'))

    fetchMock.mockResolvedValue(ok())
    act(() => result.current.refresh())

    await waitFor(() => expect(result.current.status).toBe('online'))
    expect(result.current.error).toBeNull()
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  test('does not set state after unmount', async () => {
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    let resolveProbe: (v: unknown) => void = () => {}
    fetchMock.mockReturnValue(new Promise((r) => { resolveProbe = r }))

    const { unmount } = renderHook(() => useAgentHealth())
    unmount()
    await act(async () => { resolveProbe(ok()) })

    expect(errorSpy).not.toHaveBeenCalled()
    errorSpy.mockRestore()
  })
})
