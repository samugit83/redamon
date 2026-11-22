/**
 * The sessions list keeps a busy sandbox's rows (group 1, E3; S16b, after M-b).
 *
 * In per-user mode the agent asks every running sandbox for its sessions, each within
 * FANOUT_TIMEOUT_S (5 s), and answers 200 without the rows of one that did not answer in time; the
 * webapp passes on the count (`unavailable_count`) and names to each viewer only the silent instances
 * that could hold rows that viewer may see (`unavailable`; every id to holders of every session). A
 * session manager busy with a command was such a sandbox, so the row being typed into vanished on the
 * next poll. Now:
 *
 * - a row shown before whose sandbox the answer names as not answering is kept, marked stale
 *   (`staleSince`); a count without names keeps nothing;
 * - the rows of a sandbox that answered are replaced as before, and a kept row goes once its
 *   sandbox answers again;
 * - only rows this viewer was sent are kept, never those of a sandbox that answered, never an
 *   untagged (shared-mode) row, never one pending a kill, never STALE_ROW_MAX_MS after an answer last
 *   listed it (`listedAt`), never across an act-as switch;
 * - a failed read keeps the lists as before (shared mode's 504);
 * - a kill the console answers `busy` is a failure: the row is listed again.
 *
 * Run: npx vitest run --no-file-parallelism src/hooks/useActiveSessions.busySandbox.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, act, waitFor, cleanup } from '@testing-library/react'
import type { ReactNode } from 'react'
import { AuthContext } from '@/providers/authContext'
import type { AuthContextValue } from '@/providers/AuthProvider'
import {
  useActiveSessions,
  nextSessionLists,
  STALE_ROW_MAX_MS,
  NO_SESSION_ROWS,
  type ShownSessionLists,
} from './useActiveSessions'

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

const session = (sandbox: string | undefined, id: number) =>
  ({ id, ...(sandbox ? { sandbox } : {}), type: 'shell', info: `${sandbox}:${id}`, connection: '', target_ip: '', chat_session_id: 'session_x' })
const A1 = session('aaaaa1', 1)
const A2 = session('aaaaa1', 2)
const B1 = session('bbbbb1', 1)
const B_JOB = { id: 0, sandbox: 'bbbbb1', name: 'handler', payload: 'p', port: 4444 }
const A_JOB = { id: 0, sandbox: 'aaaaa1', name: 'handler', payload: 'p', port: 4444 }
const B_LISTENER = { id: 'raw-1', sandbox: 'bbbbb1', type: 'listener', tool: 'nc', command: 'nc -lvnp 4444', chat_session_id: 'session_x' }

const lists = (sessions: unknown[] = [], extra: Record<string, unknown> = {}) =>
  ({ sessions, jobs: [], non_msf_sessions: [], agent_busy: false, ...extra })

let answers: Array<() => Response | Promise<Response>>
let fetchMock: ReturnType<typeof vi.fn>

beforeEach(() => {
  answers = []
  fetchMock = vi.fn(async (url: string) => {
    if (String(url) !== '/api/agent/sessions') return json(200, { busy: false, output: '' })
    const next = answers.length > 1 ? answers.shift()! : answers[0]
    return next()
  })
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

/** The hook after its first read (`first`), then after one poll per later answer. */
async function polled(first: unknown, ...later: Array<unknown | (() => Response)>) {
  answers = [() => json(200, first), ...later.map(a => (typeof a === 'function' ? a as () => Response : () => json(200, a)))]
  const hook = renderHook(() => useActiveSessions({ enabled: true }))
  await waitFor(() => expect(fetchMock).toHaveBeenCalled())
  await waitFor(() => expect(hook.result.current.isLoading).toBe(false))
  for (let i = 0; i < later.length; i++) await act(async () => { await hook.result.current.refetch() })
  return hook
}

const keys = (rows: Array<{ id: unknown; sandbox?: unknown }>) => rows.map(r => `${String(r.sandbox)}:${String(r.id)}`)
const staleKeys = (rows: Array<{ id: unknown; sandbox?: unknown; staleSince?: number }>) =>
  keys(rows.filter(r => typeof r.staleSince === 'number'))

describe('a 200 that left a sandbox out', () => {
  test('keeps the row of a sandbox the answer names as not answering, marked stale, beside the count', async () => {
    const { result } = await polled(lists([B1]), lists([], { unavailable: ['bbbbb1'], unavailable_count: 1 }))
    expect(keys(result.current.sessions)).toEqual(['bbbbb1:1'])
    expect(staleKeys(result.current.sessions)).toEqual(['bbbbb1:1'])
    expect(result.current.unavailableCount).toBe(1)
    expect(result.current.error).toBeNull()
  })

  test("Bob's sandbox, busy with Alice's own command on his session, is named to her: her row stays (M-b test 4)", async () => {
    // The webapp names to Alice the silent instances that could hold rows she may see (S16b review 3a).
    const bobsSessionAliceSees = { ...B1, info: 'g1-PS', chat_session_id: 'session_bob_on_shared' }
    const { result } = await polled(
      lists([A1, bobsSessionAliceSees]),
      lists([A1], { unavailable: ['bbbbb1'], unavailable_count: 2 }),
    )
    expect(keys(result.current.sessions)).toEqual(['aaaaa1:1', 'bbbbb1:1'])
    expect(staleKeys(result.current.sessions)).toEqual(['bbbbb1:1'])
  })

  test('a count without names keeps nothing: the silent sandboxes may be anybody\'s (S16b review 3a)', async () => {
    const { result } = await polled(lists([A1, B1]), lists([A1], { unavailable_count: 1 }))
    expect(keys(result.current.sessions)).toEqual(['aaaaa1:1'])
    const again = await polled(lists([B1]), lists([], { unavailable: [], unavailable_count: 3 }))
    expect(again.result.current.sessions).toEqual([])
  })

  test('replaces the rows of the sandbox that answered and keeps those of the one named unavailable', async () => {
    const first = { ...lists([A1, B1]), jobs: [A_JOB, B_JOB], non_msf_sessions: [B_LISTENER] }
    const second = lists([A2], { unavailable: ['bbbbb1'], unavailable_count: 1 })
    const { result } = await polled(first, second)
    expect(keys(result.current.sessions)).toEqual(['aaaaa1:2', 'bbbbb1:1'])
    expect(staleKeys(result.current.sessions)).toEqual(['bbbbb1:1'])
    expect(keys(result.current.jobs)).toEqual(['bbbbb1:0'])
    expect(keys(result.current.nonMsfSessions)).toEqual(['bbbbb1:raw-1'])
    expect(result.current.totalCount).toBe(3)
  })

  test('once the sandbox answers again its row is listed afresh, and goes when it is no longer listed', async () => {
    const { result } = await polled(
      lists([B1]),
      lists([], { unavailable: ['bbbbb1'], unavailable_count: 1 }),
      lists([B1], { unavailable_count: 0 }),
    )
    expect(keys(result.current.sessions)).toEqual(['bbbbb1:1'])
    expect(staleKeys(result.current.sessions)).toEqual([])
    answers = [() => json(200, lists([], { unavailable_count: 0 }))]
    await act(async () => { await result.current.refetch() })
    expect(result.current.sessions).toEqual([])
  })

  test('a kept row goes when its sandbox answers without it while another one is still silent', async () => {
    const { result } = await polled(
      lists([A1, B1]),
      lists([A1], { unavailable: ['bbbbb1'], unavailable_count: 1 }),
      lists([A1], { unavailable_count: 1, unavailable: ['ccccc1'] }),
    )
    expect(keys(result.current.sessions)).toEqual(['aaaaa1:1'])
  })

  test('a sandbox not named loses the rows it no longer lists', async () => {
    const { result } = await polled(lists([A1, B1]), lists([], { unavailable: ['bbbbb1'], unavailable_count: 1 }))
    expect(keys(result.current.sessions)).toEqual(['bbbbb1:1'])
  })

  test('a sandbox that still lists a row answered, so its vanished row goes, even if named', async () => {
    const { result } = await polled(lists([A1, A2, B1]), lists([A1], { unavailable: ['aaaaa1', 'bbbbb1'], unavailable_count: 2 }))
    expect(keys(result.current.sessions)).toEqual(['aaaaa1:1', 'bbbbb1:1'])
    expect(staleKeys(result.current.sessions)).toEqual(['bbbbb1:1'])
  })

  test('nothing unavailable: the answer replaces the lists, as before', async () => {
    const { result } = await polled(lists([A1, B1]), lists([A1]))
    expect(keys(result.current.sessions)).toEqual(['aaaaa1:1'])
  })

  test('an untagged row (the shared container of shared mode) is never kept', async () => {
    const { result } = await polled(lists([session(undefined, 4)]), lists([], { unavailable: ['shared'], unavailable_count: 1 }))
    expect(result.current.sessions).toEqual([])
  })

  test('a row pending a kill is not kept', async () => {
    const { result } = await polled(lists([B1]))
    let killed!: (r: Response) => void
    fetchMock.mockImplementation(async (url: string) => {
      if (String(url).includes('/kill')) return new Promise<Response>(r => { killed = r })
      return json(200, lists([], { unavailable: ['bbbbb1'], unavailable_count: 1 }))
    })
    let kill!: Promise<void>
    act(() => { kill = result.current.killSession({ id: 1, sandbox: 'bbbbb1' }) })
    await act(async () => { await result.current.refetch() })
    expect(result.current.sessions).toEqual([])
    await act(async () => { killed(json(200, { busy: false, output: '' })); await kill })
  })

  test('a field the sandbox wrote cannot mark its own row stale', async () => {
    const { result } = await polled(lists([{ ...B1, staleSince: 1 }]))
    expect(result.current.sessions).toHaveLength(1)
    expect(result.current.sessions[0].staleSince).toBeUndefined()
  })

  test('a failed read keeps the lists and only sets the error (shared mode\'s 504), as before', async () => {
    const { result } = await polled(lists([B1]), () => json(504, { error: 'Session manager timeout' }))
    expect(keys(result.current.sessions)).toEqual(['bbbbb1:1'])
    expect(staleKeys(result.current.sessions)).toEqual([])
    expect(result.current.error).not.toBeNull()
  })
})

describe('an act-as switch', () => {
  const FLAGS = { sharedToolsCompat: false, identity: true, permissions: false, sharing: false, sharingWrite: false, governance: false }
  const as = (actingAs: string | null): AuthContextValue => ({
    user: {
      id: 'admin1', name: 'Admin', email: 'admin@e2e.local', role: 'admin', flags: FLAGS,
      actingAs: actingAs ? { id: actingAs, name: 'M', email: 'm@e2e.local', accountType: 'member', reason: null, endsAt: null } : null,
    },
    isLoading: false, capabilities: new Set(), flags: FLAGS, sessionError: null,
    login: async () => ({}), logout: async () => {}, refresh: async () => {},
  })

  test('keeps nothing of the account the rows were read for', async () => {
    let current = as(null)
    const wrapper = ({ children }: { children: ReactNode }) => <AuthContext.Provider value={current}>{children}</AuthContext.Provider>
    answers = [() => json(200, lists([B1])), () => json(200, lists([], { unavailable: ['bbbbb1'], unavailable_count: 1 }))]
    const { result, rerender } = renderHook(() => useActiveSessions({ enabled: true }), { wrapper })
    await waitFor(() => expect(result.current.sessions).toHaveLength(1))
    current = as('member1')
    rerender()
    await act(async () => { await result.current.refetch() })
    expect(result.current.sessions).toEqual([])
  })
})

describe('nextSessionLists', () => {
  const shownWith = (rows: ShownSessionLists['sessions']): ShownSessionLists => ({ ...NO_SESSION_ROWS, sessions: rows })
  const silentB = lists([], { unavailable: ['bbbbb1'], unavailable_count: 1 })

  test('keeps the time a row was first left out, and drops it STALE_ROW_MAX_MS after it was last listed', () => {
    const t0 = 1_000_000
    const listed = nextSessionLists(NO_SESSION_ROWS, lists([B1]), t0)
    expect(listed.sessions[0].listedAt).toBe(t0)
    // Failed reads in between (the hook keeps its lists); the first 200 leaving it out comes later.
    const once = nextSessionLists(listed, silentB, t0 + 20_000)
    expect(once.sessions[0].staleSince).toBe(t0 + 20_000)
    expect(once.sessions[0].listedAt).toBe(t0)
    const later = nextSessionLists(once, silentB, t0 + STALE_ROW_MAX_MS - 1)
    expect(keys(later.sessions)).toEqual(['bbbbb1:1'])
    expect(nextSessionLists(later, silentB, t0 + STALE_ROW_MAX_MS).sessions).toEqual([])
  })

  test('a row never listed by an answer (no listedAt) is not kept', () => {
    expect(nextSessionLists(shownWith([B1 as never]), silentB, 5).sessions).toEqual([])
  })

  test('never adds a row it was not shown, and never lists a key twice', () => {
    const shown = nextSessionLists(NO_SESSION_ROWS, lists([B1, session('bbbbb1', 2)]), 1)
    // A contradictory answer: bbbbb1 named silent yet listing a row. It answered, so nothing of it is kept.
    const out = nextSessionLists(shown, lists([B1], { unavailable: ['bbbbb1'], unavailable_count: 1 }), 5)
    expect(keys(out.sessions)).toEqual(['bbbbb1:1'])
    expect(out.sessions[0].staleSince).toBeUndefined()
    expect(nextSessionLists(NO_SESSION_ROWS, silentB, 5)).toEqual(NO_SESSION_ROWS)
  })

  test('an empty name list, a count alone or a malformed count keeps nothing', () => {
    const shown = nextSessionLists(NO_SESSION_ROWS, lists([B1]), 1)
    expect(nextSessionLists(shown, lists([], { unavailable: [], unavailable_count: 1 }), 5).sessions).toEqual([])
    expect(nextSessionLists(shown, lists([], { unavailable_count: 1 }), 5).sessions).toEqual([])
    expect(nextSessionLists(shown, lists([], { unavailable: ['bbbbb1'], unavailable_count: '1' }), 5).sessions).toEqual([])
    expect(nextSessionLists(shown, lists([], { unavailable: ['bbbbb1'], unavailable_count: -1 }), 5).sessions).toEqual([])
  })

  test('a sandbox-written listedAt is dropped: every listed row is stamped with the answer\'s time', () => {
    const out = nextSessionLists(NO_SESSION_ROWS, lists([{ ...B1, listedAt: 9e15, staleSince: 1 }]), 7)
    expect(out.sessions[0].listedAt).toBe(7)
    expect(out.sessions[0].staleSince).toBeUndefined()
  })
})

describe('a command nobody answered in time (S16b review round 3)', () => {
  test('says it may still be running, so it is not simply sent again', async () => {
    const { result } = await polled(lists([B1]))
    fetchMock.mockImplementation(async (url: string) =>
      (String(url).includes('/interact') ? json(502, { error: 'Failed to interact with session', code: 'agent_error', upstreamStatus: 504 }) : json(200, lists([B1]))))
    let out: { output?: string } = {}
    await act(async () => { out = await result.current.interactWithSession({ id: 1, sandbox: 'bbbbb1' }, 'id') })
    expect(out.output).toMatch(/^\[ERROR\] /)
    expect(out.output).toMatch(/may still be running/)
  })

  test('another failure keeps the route\'s reason', async () => {
    const { result } = await polled(lists([B1]))
    fetchMock.mockImplementation(async (url: string) =>
      (String(url).includes('/interact') ? json(404, { error: 'Not found' }) : json(200, lists([B1]))))
    let out: { output?: string } = {}
    await act(async () => { out = await result.current.interactWithSession({ id: 1, sandbox: 'bbbbb1' }, 'id') })
    expect(out.output).toMatch(/Not found/)
    expect(out.output).not.toMatch(/may still be running/)
  })
})

describe('a kill the console answers busy (S16b review 1)', () => {
  // With the session manager threaded, a kill during a running command waits for the console and
  // can answer 200 {busy: true}: the session is still alive and must not stay hidden.
  const busy = () => json(200, { busy: true, message: 'Agent is busy' })

  test('a session kill answered busy rejects, and the row is listed again', async () => {
    const { result } = await polled(lists([B1]))
    fetchMock.mockImplementation(async (url: string) => (String(url).includes('/kill') ? busy() : json(200, lists([B1]))))
    let caught: unknown
    await act(async () => {
      try { await result.current.killSession({ id: 1, sandbox: 'bbbbb1' }) } catch (err) { caught = err }
    })
    expect((caught as { code?: string }).code).toBe('console_busy')
    expect(String((caught as Error).message)).toMatch(/busy/i)
    expect(keys(result.current.sessions)).toEqual(['bbbbb1:1'])
    await act(async () => { await result.current.refetch() })
    expect(keys(result.current.sessions)).toEqual(['bbbbb1:1'])
  })

  test('a job kill answered busy rejects, and the job is listed again', async () => {
    const { result } = await polled({ ...lists([]), jobs: [B_JOB] })
    fetchMock.mockImplementation(async (url: string) =>
      (String(url).includes('/kill') ? busy() : json(200, { ...lists([]), jobs: [B_JOB] })))
    let caught: unknown
    await act(async () => {
      try { await result.current.killJob({ id: 0, sandbox: 'bbbbb1' }) } catch (err) { caught = err }
    })
    expect((caught as { code?: string }).code).toBe('console_busy')
    expect(keys(result.current.jobs)).toEqual(['bbbbb1:0'])
  })

  test('a kill nobody answered in time may still complete: it says so, and the list is read again', async () => {
    // The agent's 504 reaches the browser as 502 + upstreamStatus 504; the webapp's own timeout as 504.
    for (const noAnswer of [
      () => json(502, { error: 'Failed to kill session', code: 'agent_error', upstreamStatus: 504 }),
      () => json(504, { error: 'Failed to kill session', code: 'agent_timeout' }),
    ]) {
      const { result, unmount } = await polled(lists([B1]))
      const listReads = () => fetchMock.mock.calls.filter(([u]) => String(u) === '/api/agent/sessions').length
      fetchMock.mockImplementation(async (url: string) => (String(url).includes('/kill') ? noAnswer() : json(200, lists([B1]))))
      const before = listReads()
      let caught: unknown
      await act(async () => {
        try { await result.current.killSession({ id: 1, sandbox: 'bbbbb1' }) } catch (err) { caught = err }
      })
      expect(String((caught as Error).message)).toMatch(/may still complete/)
      expect(listReads()).toBeGreaterThan(before)
      expect(keys(result.current.sessions)).toEqual(['bbbbb1:1'])
      unmount()
    }
  })

  test('another kill failure keeps its own reason', async () => {
    const { result } = await polled(lists([B1]))
    fetchMock.mockImplementation(async (url: string) =>
      (String(url).includes('/kill') ? json(404, { error: 'Not found' }) : json(200, lists([B1]))))
    let caught: unknown
    await act(async () => {
      try { await result.current.killSession({ id: 1, sandbox: 'bbbbb1' }) } catch (err) { caught = err }
    })
    expect(String((caught as Error).message)).not.toMatch(/may still complete/)
  })

  test('a kill answered busy: false (or with no body) still succeeds', async () => {
    const { result } = await polled(lists([B1]))
    fetchMock.mockImplementation(async (url: string) =>
      (String(url).includes('/kill') ? json(200, { busy: false, output: 'killed' }) : json(200, lists([]))))
    await act(async () => { await result.current.killSession({ id: 1, sandbox: 'bbbbb1' }) })
    expect(result.current.sessions).toEqual([])
  })
})
