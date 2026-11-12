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
import { render, screen, waitFor, fireEvent, cleanup } from '@testing-library/react'
import React from 'react'

// Mutable auth + URL state the mocks read (hoisted-safe: referenced lazily).
let mockAuth: { user: { id: string } | null; isLoading: boolean; canSwitchUser: boolean } = {
  user: { id: 'me' }, isLoading: false, canSwitchUser: false,
}
let searchParamsStr = ''

// Whether the signed-in person may act as others (users:impersonate, hooks/useCan.ts).
vi.mock('@/hooks/useCan', () => ({ useCan: () => mockAuth.canSwitchUser, useRbacFlags: () => null }))
vi.mock('@/providers/AuthProvider', () => ({ useAuth: () => mockAuth }))
vi.mock('next/navigation', () => ({
  useSearchParams: () => new URLSearchParams(searchParamsStr),
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
