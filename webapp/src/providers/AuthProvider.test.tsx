/**
 * Session hydrate: a database outage is not a sign-out.
 *
 * /api/auth/me failing used to leave `user` null whatever the cause. A 401 is a
 * plain sign-out; a 5xx or no answer is now exposed as `sessionError`, with its
 * code and status, so the app can say the session could not be read.
 *
 * A 401 that ends the session also sends the browser to /login (step 2.2): the Edge
 * middleware checks only the cookie's signature, so a revoked, disabled or deleted account's
 * cookie still loads pages while every API answers 401. Without the redirect the person sat in
 * a signed-in shell that could do nothing. Only the identity switch ends a session this way
 * (/api/auth/me answers `code: session_ended` and the cookie is cleared); with it off the 401
 * is bare and the page stays, as after Phase 1 (review of step 2.2).
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, waitFor, act } from '@testing-library/react'
import { StrictMode } from 'react'
import { AuthProvider, useAuth } from './AuthProvider'

function Consumer() {
  const { user, isLoading, sessionError } = useAuth()
  return (
    <div>
      <span data-testid="loading">{String(isLoading)}</span>
      <span data-testid="user">{user?.id ?? 'none'}</span>
      <span data-testid="error">{sessionError?.message ?? ''}</span>
    </div>
  )
}

/** What /api/auth/me answers for a refused cookie while the identity switch is on. */
const SESSION_ENDED = { error: 'Unauthorized', code: 'session_ended' }

let fetchMock: ReturnType<typeof vi.fn>
const realLocation = window.location
let replaceMock: ReturnType<typeof vi.fn>
function onPage(pathname: string) {
  replaceMock = vi.fn()
  Object.defineProperty(window, 'location', { configurable: true, value: { ...realLocation, pathname, replace: replaceMock } })
}
beforeEach(() => {
  localStorage.clear()
  fetchMock = vi.fn()
  vi.stubGlobal('fetch', fetchMock)
  onPage('/graph')
})
afterEach(() => {
  cleanup()
  vi.useRealTimers()
  vi.unstubAllGlobals()
  Object.defineProperty(window, 'location', { configurable: true, value: realLocation })
})

async function hydrate() {
  render(<AuthProvider><Consumer /></AuthProvider>)
  await waitFor(() => expect(screen.getByTestId('loading').textContent).toBe('false'))
}

/** Fake time forward, past the retries' waits when `ms` covers them. */
async function advance(ms: number) {
  await act(async () => { await vi.advanceTimersByTimeAsync(ms) })
}

describe('AuthProvider session hydrate', () => {
  test('a 5xx is a session error with its code, not a sign-out', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ error: 'Internal server error', code: 'P1001' }), { status: 500 }))
    await hydrate()
    expect(screen.getByTestId('user').textContent).toBe('none')
    expect(screen.getByTestId('error').textContent).toBe('Internal server error (P1001 · HTTP 500)')
  })

  test('no answer at all is a session error too, once the retries are spent', async () => {
    vi.useFakeTimers()
    fetchMock.mockRejectedValue(new TypeError('Failed to fetch'))
    render(<AuthProvider><Consumer /></AuthProvider>)
    await advance(10_000)
    expect(screen.getByTestId('loading').textContent).toBe('false')
    expect(screen.getByTestId('error').textContent).toBe('Could not read your session (network_error)')
  })

  test('a 401 is a plain sign-out, with no error', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 }))
    await hydrate()
    expect(screen.getByTestId('user').textContent).toBe('none')
    expect(screen.getByTestId('error').textContent).toBe('')
  })

  test('a session that reads loads the user', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ id: 'u1', name: 'U', email: 'u@x', role: 'admin' }), { status: 200 }))
    await hydrate()
    expect(screen.getByTestId('user').textContent).toBe('u1')
    expect(screen.getByTestId('error').textContent).toBe('')
  })

  test('a 401 from /api/auth/me goes to /login', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify(SESSION_ENDED), { status: 401 }))
    await hydrate()
    expect(replaceMock).toHaveBeenCalledWith('/login')
  })

  test("a bare 401 (identity switch off) stays on the page, as after Phase 1", async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 }))
    await hydrate()
    expect(screen.getByTestId('user').textContent).toBe('none')
    expect(replaceMock).not.toHaveBeenCalled()
  })

  test('a 401 whose body is not JSON stays on the page', async () => {
    fetchMock.mockResolvedValue(new Response('Unauthorized', { status: 401 }))
    await hydrate()
    expect(screen.getByTestId('error').textContent).toBe('')
    expect(replaceMock).not.toHaveBeenCalled()
  })

  test('on the login page a 401 stays there: no reload loop', async () => {
    onPage('/login')
    fetchMock.mockResolvedValue(new Response(JSON.stringify(SESSION_ENDED), { status: 401 }))
    await hydrate()
    expect(replaceMock).not.toHaveBeenCalled()
  })

  test('on the invite page (step 2.9) a 401 stays there: the person has no session yet', async () => {
    for (const path of ['/invite', '/invite/some-token']) {
      onPage(path)
      fetchMock.mockResolvedValue(new Response(JSON.stringify(SESSION_ENDED), { status: 401 }))
      await hydrate()
      cleanup()
    }
    expect(replaceMock).not.toHaveBeenCalled()
  })

  // Review of step 3.16c: the browser's act-as pick must not resume at the next sign-in.
  test('a session the server ended forgets whom this browser acted as', async () => {
    localStorage.setItem('redamon-current-user', JSON.stringify({ by: 'u1', target: 'member-1' }))
    fetchMock.mockResolvedValue(new Response(JSON.stringify(SESSION_ENDED), { status: 401 }))
    await hydrate()
    expect(replaceMock).toHaveBeenCalledWith('/login')
    expect(localStorage.getItem('redamon-current-user')).toBeNull()
  })

  test('a bare 401 (identity switch off) keeps it, as after Phase 1', async () => {
    localStorage.setItem('redamon-current-user', 'member-1')
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 }))
    await hydrate()
    expect(localStorage.getItem('redamon-current-user')).toBe('member-1')
  })

  test('an outage or a session that reads never leaves the page', async () => {
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ error: 'down', code: 'P1001' }), { status: 500 }))
    await hydrate()
    cleanup()
    vi.useFakeTimers()
    fetchMock.mockRejectedValue(new TypeError('Failed to fetch'))
    render(<AuthProvider><Consumer /></AuthProvider>)
    await advance(10_000)
    expect(screen.getByTestId('loading').textContent).toBe('false')
    cleanup()
    vi.useRealTimers()
    fetchMock.mockReset()
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ id: 'u1', name: 'U', email: 'u@x', role: 'admin' }), { status: 200 }))
    await hydrate()
    expect(replaceMock).not.toHaveBeenCalled()
  })
})

// A session read that got no answer (Chromium aborts every request in flight with
// net::ERR_NETWORK_CHANGED when a host address appears or goes away) left the page on "No User"
// for good. It is tried again, bounded; an answer is never tried again.
const ME = { id: 'u1', name: 'U', email: 'u@x', role: 'admin' }

describe('AuthProvider session read that got no answer', () => {
  test('an aborted read is tried again and the user loads; meanwhile the page waits, with no error', async () => {
    vi.useFakeTimers()
    fetchMock
      .mockRejectedValueOnce(new TypeError('Failed to fetch'))
      .mockResolvedValueOnce(new Response(JSON.stringify(ME), { status: 200 }))
    render(<AuthProvider><Consumer /></AuthProvider>)
    await advance(0)
    expect(screen.getByTestId('loading').textContent).toBe('true')
    expect(screen.getByTestId('error').textContent).toBe('')

    await advance(1000)
    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(screen.getByTestId('user').textContent).toBe('u1')
    expect(screen.getByTestId('error').textContent).toBe('')
    expect(screen.getByTestId('loading').textContent).toBe('false')
  })

  test('reads that never get an answer stop, bounded, at the session error', async () => {
    vi.useFakeTimers()
    fetchMock.mockRejectedValue(new DOMException('The operation was aborted.', 'AbortError'))
    render(<AuthProvider><Consumer /></AuthProvider>)
    await advance(7000)
    expect(screen.getByTestId('loading').textContent).toBe('true')
    await advance(1000)
    expect(screen.getByTestId('loading').textContent).toBe('false')
    expect(screen.getByTestId('error').textContent).toBe('Could not read your session (aborted)')
    expect(fetchMock).toHaveBeenCalledTimes(5)
    await advance(60_000)
    expect(fetchMock).toHaveBeenCalledTimes(5)
  })

  test('a 200 whose body was lost after the headers is tried again too, and the user loads', async () => {
    vi.useFakeTimers()
    fetchMock
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => { throw new TypeError('network error') } } as unknown as Response)
      .mockResolvedValueOnce(new Response(JSON.stringify(ME), { status: 200 }))
    render(<AuthProvider><Consumer /></AuthProvider>)
    await advance(1000)
    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(screen.getByTestId('user').textContent).toBe('u1')
    expect(screen.getByTestId('error').textContent).toBe('')
  })

  test('unmounted during a wait, the provider reads nothing more', async () => {
    vi.useFakeTimers()
    fetchMock.mockRejectedValue(new TypeError('Failed to fetch'))
    const { unmount } = render(<AuthProvider><Consumer /></AuthProvider>)
    await advance(0)
    expect(fetchMock).toHaveBeenCalledTimes(1)
    unmount()
    await advance(60_000)
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  test('StrictMode: one read chain, and the user still loads after a retry', async () => {
    vi.useFakeTimers()
    fetchMock
      .mockRejectedValueOnce(new TypeError('Failed to fetch'))
      .mockResolvedValueOnce(new Response(JSON.stringify(ME), { status: 200 }))
    render(<StrictMode><AuthProvider><Consumer /></AuthProvider></StrictMode>)
    await advance(1000)
    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(screen.getByTestId('user').textContent).toBe('u1')
  })

  test('a 401 that ends the session is never tried again: straight to /login', async () => {
    vi.useFakeTimers()
    fetchMock.mockResolvedValue(new Response(JSON.stringify(SESSION_ENDED), { status: 401 }))
    render(<AuthProvider><Consumer /></AuthProvider>)
    await advance(10_000)
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(replaceMock).toHaveBeenCalledWith('/login')
  })

  test.each([
    [401, { error: 'Unauthorized' }, ''],
    [403, { error: 'Forbidden' }, ''],
    [500, { error: 'Internal server error', code: 'P1001' }, 'Internal server error (P1001 · HTTP 500)'],
  ])('an answered %i is never tried again', async (status, body, error) => {
    vi.useFakeTimers()
    fetchMock.mockResolvedValue(new Response(JSON.stringify(body), { status }))
    render(<AuthProvider><Consumer /></AuthProvider>)
    await advance(10_000)
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(screen.getByTestId('loading').textContent).toBe('false')
    expect(screen.getByTestId('user').textContent).toBe('none')
    expect(screen.getByTestId('error').textContent).toBe(error)
    expect(replaceMock).not.toHaveBeenCalled()
  })
})
