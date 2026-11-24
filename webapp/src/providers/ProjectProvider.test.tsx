/**
 * Component tests for ProjectProvider's impersonation client wiring (A7).
 *
 * Proves:
 *  - a standard user NEVER calls the admin-only act-as endpoint (cannot
 *    impersonate client-side)
 *  - an admin restoring an impersonation target from localStorage reconciles the
 *    server act-as cookie on mount, and the effective userId reflects the target
 *  - data loads are GATED behind that reconcile: the project fetch happens AFTER
 *    the act-as call (no race / no stale-cookie 404 under enforcement)
 *  - switching users sets the cookie (POST act-as) and then flips the effective id
 *
 * Run: npx vitest run src/providers/ProjectProvider.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor, fireEvent, cleanup, act } from '@testing-library/react'
import React from 'react'

// Mutable auth + URL state the mocks read (hoisted-safe: referenced lazily).
let mockAuth: {
  user: { id: string } | null; isLoading: boolean; canSwitchUser: boolean
  /** The RBAC switches /api/auth/me answered; `permissions: true` makes the server own act-as. */
  flags?: { permissions?: boolean } | null
} = {
  user: { id: 'me' }, isLoading: false, canSwitchUser: false,
}
let searchParamsStr = ''

// Whether the signed-in person may act as others (users:impersonate, hooks/useCan.ts).
vi.mock('@/hooks/useCan', () => ({ useCan: () => mockAuth.canSwitchUser, useRbacFlags: () => mockAuth.flags ?? null }))
vi.mock('@/providers/AuthProvider', () => ({ useAuth: () => mockAuth }))
// One object per query string, as Next's own hook keeps it: a new one per render would re-run the
// project load at every render, and a load that succeeds would then never stop.
let searchParamsMemo: { str: string; params: URLSearchParams } | null = null
vi.mock('next/navigation', () => ({
  useSearchParams: () => {
    if (searchParamsMemo?.str !== searchParamsStr) searchParamsMemo = { str: searchParamsStr, params: new URLSearchParams(searchParamsStr) }
    return searchParamsMemo.params
  },
  useRouter: () => ({ replace: vi.fn() }),
  usePathname: () => '/graph',
}))

import { ProjectProvider, useProject } from './ProjectProvider'

function Consumer() {
  const { userId, setUserId } = useProject()
  return (
    <div>
      <span data-testid="userId">{userId ?? 'null'}</span>
      <button data-testid="switch" onClick={() => setUserId('userX')}>switch</button>
    </div>
  )
}

type Call = { url: string; method: string; body: string }
let fetchCalls: Call[]

beforeEach(() => {
  fetchCalls = []
  localStorage.clear()
  searchParamsStr = ''
  mockAuth = { user: { id: 'me' }, isLoading: false, canSwitchUser: false }
  vi.stubGlobal('fetch', vi.fn(async (url: unknown, opts?: RequestInit) => {
    fetchCalls.push({ url: String(url), method: opts?.method ?? 'GET', body: opts?.body ? String(opts.body) : '' })
    return { ok: true, json: async () => ({ id: 'P1' }) } as unknown as Response
  }))
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

const actAsCalls = () => fetchCalls.filter(c => c.url.includes('/api/auth/act-as'))

describe('ProjectProvider impersonation wiring', () => {
  test('standard user: effective id is own, and NEVER calls act-as', async () => {
    mockAuth = { user: { id: 'me' }, isLoading: false, canSwitchUser: false }
    render(<ProjectProvider><Consumer /></ProjectProvider>)
    await waitFor(() => expect(screen.getByTestId('userId').textContent).toBe('me'))
    expect(actAsCalls()).toHaveLength(0)
  })

  test('standard user: setUserId(other) is ignored (stays own, no act-as)', async () => {
    mockAuth = { user: { id: 'me' }, isLoading: false, canSwitchUser: false }
    render(<ProjectProvider><Consumer /></ProjectProvider>)
    await waitFor(() => expect(screen.getByTestId('userId').textContent).toBe('me'))
    fireEvent.click(screen.getByTestId('switch'))
    await new Promise(r => setTimeout(r, 20))
    expect(screen.getByTestId('userId').textContent).toBe('me')
    expect(actAsCalls().some(c => c.method === 'POST')).toBe(false)
  })

  test('admin restoring impersonation from localStorage: POSTs act-as + effective id = target', async () => {
    localStorage.setItem('redamon-current-user', 'userX')
    mockAuth = { user: { id: 'admin' }, isLoading: false, canSwitchUser: true }
    render(<ProjectProvider><Consumer /></ProjectProvider>)
    await waitFor(() =>
      expect(actAsCalls().some(c => c.method === 'POST' && c.body.includes('userX'))).toBe(true),
    )
    expect(screen.getByTestId('userId').textContent).toBe('userX')
  })

  test('admin not simulating: reconcile clears the cookie (DELETE act-as)', async () => {
    mockAuth = { user: { id: 'admin' }, isLoading: false, canSwitchUser: true }
    render(<ProjectProvider><Consumer /></ProjectProvider>)
    await waitFor(() => expect(actAsCalls().some(c => c.method === 'DELETE')).toBe(true))
    expect(screen.getByTestId('userId').textContent).toBe('admin')
  })

  test('GATE: the project fetch happens AFTER the act-as reconcile (no race)', async () => {
    localStorage.setItem('redamon-current-user', 'userX')
    searchParamsStr = 'project=P1'
    mockAuth = { user: { id: 'admin' }, isLoading: false, canSwitchUser: true }
    render(<ProjectProvider><Consumer /></ProjectProvider>)
    await waitFor(() => expect(fetchCalls.some(c => c.url.includes('/api/projects/P1'))).toBe(true))
    const actAsIdx = fetchCalls.findIndex(c => c.url.includes('/api/auth/act-as'))
    const projIdx = fetchCalls.findIndex(c => c.url.includes('/api/projects/P1'))
    expect(actAsIdx).toBeGreaterThanOrEqual(0)
    expect(projIdx).toBeGreaterThan(actAsIdx) // load gated behind reconcile
  })

  // Issue #173: the reconcile only caught a network throw, so a 404 ("User not
  // found", the DB was reset / the account was deleted) left the ghost id as the
  // effective user. Reads then returned an empty list and the first WRITE died on
  // the user_id foreign key as an opaque 500 ("Failed to save provider").
  test('admin restoring a DELETED target: falls back to own id and forgets it', async () => {
    localStorage.setItem('redamon-current-user', 'ghost')
    mockAuth = { user: { id: 'admin' }, isLoading: false, canSwitchUser: true }
    vi.stubGlobal('fetch', vi.fn(async (url: unknown, opts?: RequestInit) => {
      const u = String(url)
      fetchCalls.push({ url: u, method: opts?.method ?? 'GET', body: opts?.body ? String(opts.body) : '' })
      if (u.includes('/api/auth/act-as') && opts?.method === 'POST') {
        return { ok: false, status: 404, json: async () => ({ error: 'User not found' }) } as unknown as Response
      }
      return { ok: true, json: async () => ({ id: 'P1' }) } as unknown as Response
    }))

    render(<ProjectProvider><Consumer /></ProjectProvider>)

    await waitFor(() => expect(screen.getByTestId('userId').textContent).toBe('admin'))
    expect(localStorage.getItem('redamon-current-user')).toBeNull()
    expect(actAsCalls().some(c => c.method === 'DELETE')).toBe(true)
  })

  test('admin switching to a DELETED user: effective id stays own', async () => {
    mockAuth = { user: { id: 'admin' }, isLoading: false, canSwitchUser: true }
    vi.stubGlobal('fetch', vi.fn(async (url: unknown, opts?: RequestInit) => {
      const u = String(url)
      fetchCalls.push({ url: u, method: opts?.method ?? 'GET', body: opts?.body ? String(opts.body) : '' })
      if (u.includes('/api/auth/act-as') && opts?.method === 'POST') {
        return { ok: false, status: 404, json: async () => ({ error: 'User not found' }) } as unknown as Response
      }
      return { ok: true, json: async () => ({ id: 'P1' }) } as unknown as Response
    }))

    render(<ProjectProvider><Consumer /></ProjectProvider>)
    await waitFor(() => expect(screen.getByTestId('userId').textContent).toBe('admin'))
    fireEvent.click(screen.getByTestId('switch'))

    await waitFor(() =>
      expect(actAsCalls().some(c => c.method === 'POST' && c.body.includes('userX'))).toBe(true),
    )
    await waitFor(() => expect(localStorage.getItem('redamon-current-user')).toBeNull())
    expect(screen.getByTestId('userId').textContent).toBe('admin')
  })

  test('admin switching users: POST act-as then effective id flips to target', async () => {
    mockAuth = { user: { id: 'admin' }, isLoading: false, canSwitchUser: true }
    render(<ProjectProvider><Consumer /></ProjectProvider>)
    await waitFor(() => expect(screen.getByTestId('userId').textContent).toBe('admin'))
    fireEvent.click(screen.getByTestId('switch'))
    await waitFor(() => expect(screen.getByTestId('userId').textContent).toBe('userX'))
    expect(actAsCalls().some(c => c.method === 'POST' && c.body.includes('userX'))).toBe(true)
  })
})

function ErrorConsumer() {
  const { userId, setUserId, userSwitchError, currentProject } = useProject()
  return (
    <div>
      <span data-testid="userId">{userId ?? 'null'}</span>
      <span data-testid="switchError">{userSwitchError?.message ?? ''}</span>
      <span data-testid="project">{currentProject?.id ?? 'none'}</span>
      <button data-testid="switch" onClick={() => setUserId('userX')}>switch</button>
    </div>
  )
}

/** fetch stub: `actAsPost` answers (or throws for) POST act-as, `project` answers GET /api/projects/:id. */
function stubFetch(opts: { actAsPost?: () => Response; project?: () => Response }) {
  vi.stubGlobal('fetch', vi.fn(async (url: unknown, init?: RequestInit) => {
    const u = String(url)
    const method = init?.method ?? 'GET'
    fetchCalls.push({ url: u, method, body: init?.body ? String(init.body) : '' })
    if (u.includes('/api/auth/act-as') && method === 'POST' && opts.actAsPost) return opts.actAsPost()
    if (u.startsWith('/api/projects/') && opts.project) return opts.project()
    return new Response(JSON.stringify({ id: 'P1' }), { status: 200 })
  }))
}

describe('ProjectProvider failures keep their cause', () => {
  test('a refused user switch exposes the reason, code and status', async () => {
    mockAuth = { user: { id: 'admin' }, isLoading: false, canSwitchUser: true }
    stubFetch({ actAsPost: () => new Response(JSON.stringify({ error: 'Could not switch user', code: 'P1001' }), { status: 500 }) })
    render(<ProjectProvider><ErrorConsumer /></ProjectProvider>)
    await waitFor(() => expect(screen.getByTestId('userId').textContent).toBe('admin'))
    fireEvent.click(screen.getByTestId('switch'))
    await waitFor(() => expect(screen.getByTestId('switchError').textContent).toBe('Could not switch user (P1001 · HTTP 500)'))
    expect(screen.getByTestId('userId').textContent).toBe('admin')
  })

  test('a switch that got no answer stays on the admin\'s own id and says why', async () => {
    mockAuth = { user: { id: 'admin' }, isLoading: false, canSwitchUser: true }
    stubFetch({ actAsPost: () => { throw new TypeError('Failed to fetch') } })
    render(<ProjectProvider><ErrorConsumer /></ProjectProvider>)
    await waitFor(() => expect(screen.getByTestId('userId').textContent).toBe('admin'))
    fireEvent.click(screen.getByTestId('switch'))
    await waitFor(() => expect(screen.getByTestId('switchError').textContent).toBe('Could not switch user (network_error)'))
    expect(screen.getByTestId('userId').textContent).toBe('admin')
    expect(localStorage.getItem('redamon-current-user')).toBeNull()
  })

  test('a successful switch clears an earlier error', async () => {
    mockAuth = { user: { id: 'admin' }, isLoading: false, canSwitchUser: true }
    let fail = true
    stubFetch({
      actAsPost: () => fail
        ? new Response(JSON.stringify({ error: 'User not found' }), { status: 404 })
        : new Response(JSON.stringify({ actingAs: 'userX' }), { status: 200 }),
    })
    render(<ProjectProvider><ErrorConsumer /></ProjectProvider>)
    await waitFor(() => expect(screen.getByTestId('userId').textContent).toBe('admin'))
    fireEvent.click(screen.getByTestId('switch'))
    await waitFor(() => expect(screen.getByTestId('switchError').textContent).toBe('User not found (HTTP 404)'))
    fail = false
    fireEvent.click(screen.getByTestId('switch'))
    await waitFor(() => expect(screen.getByTestId('userId').textContent).toBe('userX'))
    expect(screen.getByTestId('switchError').textContent).toBe('')
  })

  test('P-20: an outage loading the saved project keeps the saved selection', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    localStorage.setItem('redamon-current-project', 'P1')
    stubFetch({ project: () => new Response(JSON.stringify({ error: 'Failed to fetch project', code: 'P1001' }), { status: 500 }) })
    render(<ProjectProvider><ErrorConsumer /></ProjectProvider>)
    await waitFor(() => expect(fetchCalls.some(c => c.url === '/api/projects/P1')).toBe(true))
    await new Promise(r => setTimeout(r, 20))
    expect(localStorage.getItem('redamon-current-project')).toBe('P1')
    expect(screen.getByTestId('project').textContent).toBe('none')
  })

  test('P-20: a project that is gone (404) is forgotten', async () => {
    localStorage.setItem('redamon-current-project', 'P1')
    stubFetch({ project: () => new Response(JSON.stringify({ error: 'Project not found' }), { status: 404 }) })
    render(<ProjectProvider><ErrorConsumer /></ProjectProvider>)
    await waitFor(() => expect(localStorage.getItem('redamon-current-project')).toBeNull())
  })
})

// The saved project's read that got no answer (Chromium aborts every request in flight with
// net::ERR_NETWORK_CHANGED when a host address appears or goes away) left the page on
// "No Project" for good. It is tried again, bounded; an answer is never tried again.
function LoadConsumer() {
  const { currentProject, isLoading, projectLoadError } = useProject()
  return (
    <div>
      <span data-testid="project">{currentProject?.id ?? 'none'}</span>
      <span data-testid="loading">{String(isLoading)}</span>
      <span data-testid="loadError">{projectLoadError?.message ?? ''}</span>
    </div>
  )
}

describe('ProjectProvider saved project read that got no answer', () => {
  afterEach(() => { vi.useRealTimers() })
  const advance = async (ms: number) => { await act(async () => { await vi.advanceTimersByTimeAsync(ms) }) }
  const projectReads = () => fetchCalls.filter(c => c.url === '/api/projects/P1').length

  test('an aborted read is tried again and the project loads', async () => {
    vi.useFakeTimers()
    localStorage.setItem('redamon-current-project', 'P1')
    let reads = 0
    stubFetch({
      project: () => {
        reads += 1
        if (reads === 1) throw new TypeError('Failed to fetch')
        return new Response(JSON.stringify({ id: 'P1', name: 'One' }), { status: 200 })
      },
    })
    render(<ProjectProvider><LoadConsumer /></ProjectProvider>)
    await advance(0)
    expect(screen.getByTestId('project').textContent).toBe('none')
    expect(screen.getByTestId('loading').textContent).toBe('true')

    await advance(1000)
    expect(projectReads()).toBe(2)
    expect(screen.getByTestId('project').textContent).toBe('P1')
    expect(screen.getByTestId('loadError').textContent).toBe('')
    expect(screen.getByTestId('loading').textContent).toBe('false')
  })

  test('reads that never get an answer stop, bounded, at a load error; the saved selection stays', async () => {
    vi.useFakeTimers()
    vi.spyOn(console, 'error').mockImplementation(() => {})
    localStorage.setItem('redamon-current-project', 'P1')
    stubFetch({ project: () => { throw new TypeError('Failed to fetch') } })
    render(<ProjectProvider><LoadConsumer /></ProjectProvider>)
    await advance(7000)
    expect(screen.getByTestId('loading').textContent).toBe('true')
    await advance(1000)
    expect(projectReads()).toBe(5)
    expect(screen.getByTestId('loading').textContent).toBe('false')
    expect(screen.getByTestId('project').textContent).toBe('none')
    expect(screen.getByTestId('loadError').textContent).toBe('Could not load the saved project (network_error)')
    expect(localStorage.getItem('redamon-current-project')).toBe('P1')
    await advance(60_000)
    expect(projectReads()).toBe(5)
  })

  test('a project named by a new URL while the saved one is still being retried is not overwritten by its late answer', async () => {
    vi.useFakeTimers()
    localStorage.setItem('redamon-current-project', 'P1')
    let p1Reads = 0
    vi.stubGlobal('fetch', vi.fn(async (url: unknown, init?: RequestInit) => {
      const u = String(url)
      fetchCalls.push({ url: u, method: init?.method ?? 'GET', body: '' })
      if (u === '/api/projects/P1') {
        p1Reads += 1
        if (p1Reads === 1) throw new TypeError('Failed to fetch')
        return new Response(JSON.stringify({ id: 'P1', name: 'One' }), { status: 200 })
      }
      if (u === '/api/projects/P2') return new Response(JSON.stringify({ id: 'P2', name: 'Two' }), { status: 200 })
      return new Response('{}', { status: 200 })
    }))
    const { rerender } = render(<ProjectProvider><LoadConsumer /></ProjectProvider>)
    await advance(0)
    expect(p1Reads).toBe(1)

    searchParamsStr = 'project=P2'
    rerender(<ProjectProvider><LoadConsumer /></ProjectProvider>)
    await advance(0)
    expect(screen.getByTestId('project').textContent).toBe('P2')

    await advance(10_000)
    expect(screen.getByTestId('project').textContent).toBe('P2')
    expect(localStorage.getItem('redamon-current-project')).toBe('P2')
    expect(screen.getByTestId('loadError').textContent).toBe('')
  })

  test.each([
    [500, { error: 'Failed to fetch project', code: 'P1001' }, 'P1'],
    [404, { error: 'Project not found' }, null],
    [403, { error: 'Forbidden' }, 'P1'],
  ])('an answered %i is never tried again and is no load error', async (status, body, saved) => {
    vi.useFakeTimers()
    vi.spyOn(console, 'error').mockImplementation(() => {})
    localStorage.setItem('redamon-current-project', 'P1')
    stubFetch({ project: () => new Response(JSON.stringify(body), { status }) })
    render(<ProjectProvider><LoadConsumer /></ProjectProvider>)
    await advance(0)
    const answered = projectReads()
    expect(answered).toBeGreaterThan(0)
    await advance(10_000)
    expect(projectReads()).toBe(answered)
    expect(screen.getByTestId('loading').textContent).toBe('false')
    expect(screen.getByTestId('loadError').textContent).toBe('')
    expect(localStorage.getItem('redamon-current-project')).toBe(saved)
  })
})

// The saved project's read belongs to the view that asked for it. A pick (on a page whose URL names
// no project, too), a clear, or a switch of whom the person acts as supersedes it: its answer, late
// after a retry or simply in flight across the change, changes nothing, and it stops retrying.
describe('ProjectProvider saved project read superseded by a pick, a clear or a switch', () => {
  let api: ReturnType<typeof useProject> | null = null
  function ApiConsumer() {
    const project = useProject()
    React.useEffect(() => { api = project })
    return <LoadConsumer />
  }
  afterEach(() => { vi.useRealTimers(); api = null })
  const advance = async (ms: number) => { await act(async () => { await vi.advanceTimersByTimeAsync(ms) }) }
  const p1Reads = () => fetchCalls.filter(c => c.url === '/api/projects/P1').length
  const P1 = () => new Response(JSON.stringify({ id: 'P1', name: 'One' }), { status: 200 })
  const GONE = () => new Response(JSON.stringify({ error: 'Project not found' }), { status: 404 })

  /** `/api/projects/P1`, n-th read: 'throw' (no answer), 'hold' (the test answers it), or an answer. */
  function stubP1(plan: (n: number) => 'throw' | 'hold' | Response) {
    let n = 0
    const held: ((res: Response) => void)[] = []
    vi.stubGlobal('fetch', vi.fn(async (url: unknown, init?: RequestInit) => {
      const u = String(url)
      fetchCalls.push({ url: u, method: init?.method ?? 'GET', body: init?.body ? String(init.body) : '' })
      if (u === '/api/projects/P1') {
        n += 1
        const step = plan(n)
        if (step === 'throw') throw new TypeError('Failed to fetch')
        if (step === 'hold') return new Promise<Response>(resolve => held.push(resolve))
        return step
      }
      if (u === '/api/projects/P2') return new Response(JSON.stringify({ id: 'P2', name: 'Two' }), { status: 200 })
      return new Response('{}', { status: 200 })
    }))
    return held
  }

  beforeEach(() => {
    vi.useFakeTimers()
    vi.spyOn(console, 'error').mockImplementation(() => {})
    localStorage.setItem('redamon-current-project', 'P1')
  })

  test('a pick that changes no URL (as on /settings or /cypherfix) while the saved project is retried: the pick stays, no more reads', async () => {
    stubP1(n => (n === 1 ? 'throw' : P1()))
    render(<ProjectProvider><ApiConsumer /></ProjectProvider>)
    await advance(0)
    act(() => api!.setCurrentProject({ id: 'P2', name: 'Two' } as never))
    await advance(10_000)
    expect(screen.getByTestId('project').textContent).toBe('P2')
    expect(localStorage.getItem('redamon-current-project')).toBe('P2')
    expect(p1Reads()).toBe(1)
  })

  test.each([
    ['a 200', P1, 'P2'],
    ['a 404', GONE, 'P2'],
  ])('%s in flight when the project is picked lands afterwards and changes nothing', async (_what, answer, saved) => {
    const held = stubP1(() => 'hold')
    render(<ProjectProvider><ApiConsumer /></ProjectProvider>)
    await advance(0)
    act(() => api!.setCurrentProject({ id: 'P2', name: 'Two' } as never))
    await act(async () => { held[0](answer()) })
    await advance(0)
    expect(screen.getByTestId('project').textContent).toBe('P2')
    expect(localStorage.getItem('redamon-current-project')).toBe(saved)
  })

  test('cleared (the user switcher clears the project) while the saved one is retried: nothing comes back', async () => {
    stubP1(n => (n === 1 ? 'throw' : P1()))
    render(<ProjectProvider><ApiConsumer /></ProjectProvider>)
    await advance(0)
    act(() => api!.setCurrentProject(null))
    await advance(10_000)
    expect(screen.getByTestId('project').textContent).toBe('none')
    expect(localStorage.getItem('redamon-current-project')).toBeNull()
  })

  test('permissions on: an act-as switch during the retry wait: the retry never re-applies the previous view\'s project', async () => {
    mockAuth = { user: { id: 'admin' }, isLoading: false, canSwitchUser: true, flags: { permissions: true } }
    stubP1(n => (n === 1 ? 'throw' : P1()))
    render(<ProjectProvider><ApiConsumer /></ProjectProvider>)
    await advance(0)
    await act(async () => { await api!.setUserId('Y', { stepUpPassword: 'pw', reason: 'r', durationMinutes: 10 }) })
    expect(api!.userId).toBe('Y')
    await advance(10_000)
    expect(screen.getByTestId('project').textContent).toBe('none')
    expect(localStorage.getItem('redamon-current-project')).toBeNull()
    expect(p1Reads()).toBe(1)
  })

  test('permissions on: a read in flight across the act-as switch lands afterwards and changes nothing', async () => {
    mockAuth = { user: { id: 'admin' }, isLoading: false, canSwitchUser: true, flags: { permissions: true } }
    const held = stubP1(() => 'hold')
    render(<ProjectProvider><ApiConsumer /></ProjectProvider>)
    await advance(0)
    await act(async () => { await api!.setUserId('Y', { stepUpPassword: 'pw', reason: 'r', durationMinutes: 10 }) })
    await act(async () => { held[0](P1()) })
    await advance(0)
    expect(api!.userId).toBe('Y')
    expect(screen.getByTestId('project').textContent).toBe('none')
    expect(localStorage.getItem('redamon-current-project')).toBeNull()
  })

  test('permissions off: a read in flight across a user switch lands afterwards and changes nothing', async () => {
    mockAuth = { user: { id: 'admin' }, isLoading: false, canSwitchUser: true }
    const held = stubP1(() => 'hold')
    render(<ProjectProvider><ApiConsumer /></ProjectProvider>)
    await advance(0)
    expect(held).toHaveLength(1)
    await act(async () => { await api!.setUserId('userX') })
    expect(api!.userId).toBe('userX')
    await act(async () => { held[0](P1()) })
    await advance(0)
    expect(screen.getByTestId('project').textContent).toBe('none')
  })

  test('five URL changes in one second during a blip: superseded reads stop retrying', async () => {
    stubP1(() => 'throw')
    const { rerender } = render(<ProjectProvider><ApiConsumer /></ProjectProvider>)
    for (let i = 0; i < 5; i++) {
      await advance(200)
      searchParamsStr = `project=P1&tab=${i}`
      rerender(<ProjectProvider><ApiConsumer /></ProjectProvider>)
    }
    await advance(60_000)
    // Six loads, one read each, and the last one's four retries.
    expect(p1Reads()).toBe(10)
  })

  test('a 200 whose body was lost after the headers is tried again, and the project loads', async () => {
    stubP1(n => (n === 1 ? ({ ok: true, status: 200, json: async () => { throw new TypeError('network error') } } as unknown as Response) : P1()))
    render(<ProjectProvider><ApiConsumer /></ProjectProvider>)
    await advance(1000)
    expect(p1Reads()).toBe(2)
    expect(screen.getByTestId('project').textContent).toBe('P1')
    expect(screen.getByTestId('loadError').textContent).toBe('')
  })

  test('the Retry goes away with a pick', async () => {
    stubP1(() => 'throw')
    render(<ProjectProvider><ApiConsumer /></ProjectProvider>)
    await advance(10_000)
    expect(screen.getByTestId('loadError').textContent).toBe('Could not load the saved project (network_error)')
    act(() => api!.setCurrentProject({ id: 'P2', name: 'Two' } as never))
    expect(screen.getByTestId('loadError').textContent).toBe('')
  })

  test('the Retry goes away with an act-as switch', async () => {
    mockAuth = { user: { id: 'admin' }, isLoading: false, canSwitchUser: true, flags: { permissions: true } }
    stubP1(() => 'throw')
    render(<ProjectProvider><ApiConsumer /></ProjectProvider>)
    await advance(10_000)
    expect(screen.getByTestId('loadError').textContent).not.toBe('')
    await act(async () => { await api!.setUserId('Y', { stepUpPassword: 'pw', reason: 'r', durationMinutes: 10 }) })
    expect(screen.getByTestId('loadError').textContent).toBe('')
  })

  test('unmounted during a wait, the provider reads nothing more', async () => {
    stubP1(() => 'throw')
    const { unmount } = render(<ProjectProvider><ApiConsumer /></ProjectProvider>)
    await advance(0)
    unmount()
    await advance(60_000)
    expect(p1Reads()).toBe(1)
  })

  test('a failure while applying an answer (a client bug) is logged, never shown as "could not reach the server"', async () => {
    stubP1(() => new Response(JSON.stringify({ id: 'P1', name: 'One', targetIps: 5 }), { status: 200 }))
    render(<ProjectProvider><ApiConsumer /></ProjectProvider>)
    await advance(10_000)
    expect(p1Reads()).toBe(1)
    expect(screen.getByTestId('loadError').textContent).toBe('')
    expect(console.error).toHaveBeenCalled()
  })
})
