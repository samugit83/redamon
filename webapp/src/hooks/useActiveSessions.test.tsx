/**
 * useActiveSessions: the sessions panel learns why it is stale (G-15, G-27, G-28).
 *
 * A failed poll kept "HTTP 502" in an `error` nobody rendered; a failed kill
 * left the row hidden from every later poll while the session lived on; a
 * failed command printed "[ERROR] HTTP 502" and dropped the route's reason.
 *
 * Run: npx vitest run src/hooks/useActiveSessions.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, act, waitFor, cleanup } from '@testing-library/react'
import { ApiError } from '@/lib/apiError'
import { useActiveSessions } from './useActiveSessions'

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

const LIVE = { sessions: [{ id: 7, type: 'shell' }], jobs: [{ id: 3, name: 'handler' }], non_msf_sessions: [], agent_busy: false }
let answer: (url: string, init?: RequestInit) => Response | Promise<Response>

beforeEach(() => {
  answer = () => json(200, LIVE)
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => answer(url, init)))
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

async function mounted() {
  const hook = renderHook(() => useActiveSessions({ enabled: true }))
  await waitFor(() => expect(hook.result.current.sessions).toHaveLength(1))
  return hook
}

describe('useActiveSessions failures', () => {
  test('an unreachable agent is the error, with its code and status', async () => {
    answer = () => json(503, { error: 'Failed to fetch sessions', code: 'agent_unreachable', cause: 'ECONNREFUSED' })
    const { result } = renderHook(() => useActiveSessions({ enabled: true }))
    await waitFor(() => expect(result.current.error).toBe('Failed to fetch sessions (agent_unreachable · HTTP 503)'))
  })

  test('a refused kill brings the row back and rejects with the cause', async () => {
    const { result } = await mounted()
    answer = (url) => url.includes('/kill')
      ? json(502, { error: 'Failed to kill session', code: 'agent_error', upstreamStatus: 500 })
      : json(200, LIVE)
    let caught: unknown
    await act(async () => {
      try { await result.current.killSession(7) } catch (err) { caught = err }
    })
    expect(caught).toBeInstanceOf(ApiError)
    expect((caught as ApiError).message).toBe('Failed to kill session (agent_error · HTTP 502 · upstream HTTP 500)')
    expect(result.current.sessions.map(s => s.id)).toEqual([7])
  })

  test('a job kill that got no answer brings the job back', async () => {
    const { result } = await mounted()
    answer = (url) => {
      if (url.includes('/kill')) throw new TypeError('Failed to fetch')
      return json(200, LIVE)
    }
    let caught: unknown
    await act(async () => {
      try { await result.current.killJob(3) } catch (err) { caught = err }
    })
    expect((caught as ApiError).code).toBe('network_error')
    expect(result.current.jobs.map(j => j.id)).toEqual([3])
  })

  test('a kill that worked stays removed and resolves', async () => {
    const { result } = await mounted()
    answer = (url) => url.includes('/kill') ? json(200, { ok: true }) : json(200, LIVE)
    await act(async () => { await result.current.killSession(7) })
    expect(result.current.sessions).toHaveLength(0)
  })

  test("a failed command prints the route's reason", async () => {
    const { result } = await mounted()
    answer = () => json(502, { error: 'Failed to interact with session', code: 'agent_error', upstreamStatus: 504 })
    let out: { output?: string } = {}
    await act(async () => { out = await result.current.interactWithSession(7, 'id') })
    // A 504 behind the 502: nobody answered in time, so the command may still be running (S16b).
    expect(out.output).toBe('[ERROR] No answer in time: the command may still be running in the session; check before sending it again (agent_error · HTTP 502 · upstream HTTP 504)')
  })
})
