/**
 * useActiveSessions across per-user Kali sandboxes (group 1, TD-11, WI-S16-1/2): every console
 * numbers its sessions from 1, so a row is the pair (sandbox, number). A kill, a job kill and a
 * command name the row's instance (`?sandbox=`); a session killed in one sandbox never hides the
 * session with the same number in another; how many sandboxes the agent could not reach is passed on
 * for the partial-answer line. A row with no instance (the shared container) is driven as before.
 * A row's id is always encoded into the drive URL (review F2: a planted id must not walk the path).
 *
 * Run: npx vitest run src/hooks/useActiveSessions.sandbox.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, act, waitFor, cleanup } from '@testing-library/react'
import { useActiveSessions } from './useActiveSessions'

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

const LIVE = {
  sessions: [
    { id: 1, sandbox: 'aaaaa1', type: 'shell', chat_session_id: null },
    { id: 1, sandbox: 'bbbbb1', type: 'meterpreter', chat_session_id: null },
  ],
  jobs: [{ id: 0, sandbox: 'aaaaa1', name: 'handler' }, { id: 0, sandbox: 'bbbbb1', name: 'handler' }],
  non_msf_sessions: [],
  unavailable_count: 2,
  agent_busy: false,
}
let answer: (url: string, init?: RequestInit) => Response | Promise<Response>
let fetchMock: ReturnType<typeof vi.fn>

beforeEach(() => {
  answer = () => json(200, LIVE)
  fetchMock = vi.fn(async (url: string, init?: RequestInit) => answer(url, init))
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

async function mounted() {
  const hook = renderHook(() => useActiveSessions({ enabled: true }))
  await waitFor(() => expect(hook.result.current.sessions).toHaveLength(2))
  return hook
}
const posts = () => fetchMock.mock.calls.filter(([, init]) => (init as RequestInit | undefined)?.method === 'POST').map(([url]) => url)
const pairs = (rows: Array<{ id: unknown; sandbox?: unknown }>) => rows.map(r => `${String(r.sandbox)}:${String(r.id)}`)

describe('rows are (sandbox, number)', () => {
  test('both sessions numbered 1 are kept, and the count of sandboxes that did not answer is passed on', async () => {
    const { result } = await mounted()
    expect(pairs(result.current.sessions)).toEqual(['aaaaa1:1', 'bbbbb1:1'])
    expect(result.current.unavailableCount).toBe(2)
  })

  test('killing bbbbb1:1 names its instance and leaves aaaaa1:1 listed, through later polls too', async () => {
    const { result } = await mounted()
    await act(async () => { await result.current.killSession({ id: 1, sandbox: 'bbbbb1' }) })
    expect(posts()).toEqual(['/api/agent/sessions/1/kill?sandbox=bbbbb1'])
    expect(pairs(result.current.sessions)).toEqual(['aaaaa1:1'])
    await act(async () => { await result.current.refetch() })
    expect(pairs(result.current.sessions)).toEqual(['aaaaa1:1'])
  })

  test('a job kill names its instance and hides only that job', async () => {
    const { result } = await mounted()
    await act(async () => { await result.current.killJob({ id: 0, sandbox: 'aaaaa1' }) })
    expect(posts()).toEqual(['/api/agent/jobs/0/kill?sandbox=aaaaa1'])
    expect(pairs(result.current.jobs)).toEqual(['bbbbb1:0'])
  })

  test('a command goes to the instance of the row it was typed in', async () => {
    const { result } = await mounted()
    answer = (url) => (url.includes('/interact') ? json(200, { busy: false, output: 'uid=0' }) : json(200, LIVE))
    let out: unknown
    await act(async () => { out = await result.current.interactWithSession({ id: 1, sandbox: 'bbbbb1' }, 'id') })
    expect(out).toEqual({ busy: false, output: 'uid=0' })
    expect(posts()).toEqual(['/api/agent/sessions/1/interact?sandbox=bbbbb1'])
  })

  test('an instance id is encoded, and a row without one (the shared container) is driven as before', async () => {
    const { result } = await mounted()
    await act(async () => { await result.current.killSession({ id: 1, sandbox: 'a b&c' }) })
    await act(async () => { await result.current.killSession(7) })
    expect(posts()).toEqual(['/api/agent/sessions/1/kill?sandbox=a%20b%26c', '/api/agent/sessions/7/kill'])
  })

  test('no count from the webapp: none; a malformed one: none', async () => {
    answer = () => json(200, { ...LIVE, unavailable_count: undefined })
    let hook = await mounted()
    expect(hook.result.current.unavailableCount).toBe(0)
    cleanup()
    answer = () => json(200, { ...LIVE, unavailable_count: '2; drop' })
    hook = await mounted()
    expect(hook.result.current.unavailableCount).toBe(0)
  })

  test('a row id is encoded: a planted "../emergency-stop-all?" stays inside the kill route (review F2)', async () => {
    const planted = { ...LIVE, jobs: [{ id: '../emergency-stop-all?', sandbox: 'aaaaa1', name: 'handler' }] }
    answer = () => json(200, planted)
    const hook = renderHook(() => useActiveSessions({ enabled: true }))
    await waitFor(() => expect(hook.result.current.jobs).toHaveLength(1))
    const row = hook.result.current.jobs[0]
    await act(async () => { await hook.result.current.killJob({ id: row.id, sandbox: row.sandbox ?? null }) })
    const url = new URL(String(posts()[0]), 'http://redamon.test')
    expect(url.pathname).toBe('/api/agent/jobs/..%2Femergency-stop-all%3F/kill')
    expect(url.searchParams.get('sandbox')).toBe('aaaaa1')
    await act(async () => { await hook.result.current.interactWithSession({ id: '1/../../projects/p/leave' as never, sandbox: null }, 'id') })
    expect(new URL(String(posts()[1]), 'http://redamon.test').pathname).toBe('/api/agent/sessions/1%2F..%2F..%2Fprojects%2Fp%2Fleave/interact')
  })
})
