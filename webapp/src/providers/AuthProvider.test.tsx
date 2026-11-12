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
import { render, screen, cleanup, waitFor } from '@testing-library/react'
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
  fetchMock = vi.fn()
  vi.stubGlobal('fetch', fetchMock)
  onPage('/graph')
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  Object.defineProperty(window, 'location', { configurable: true, value: realLocation })
})

async function hydrate() {
  render(<AuthProvider><Consumer /></AuthProvider>)
  await waitFor(() => expect(screen.getByTestId('loading').textContent).toBe('false'))
}

describe('AuthProvider session hydrate', () => {
  test('a 5xx is a session error with its code, not a sign-out', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ error: 'Internal server error', code: 'P1001' }), { status: 500 }))
    await hydrate()
    expect(screen.getByTestId('user').textContent).toBe('none')
    expect(screen.getByTestId('error').textContent).toBe('Internal server error (P1001 · HTTP 500)')
  })

  test('no answer at all is a session error too', async () => {
    fetchMock.mockRejectedValue(new TypeError('Failed to fetch'))
    await hydrate()
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

  test('an outage or a session that reads never leaves the page', async () => {
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ error: 'down', code: 'P1001' }), { status: 500 }))
    await hydrate()
    cleanup()
    fetchMock.mockRejectedValueOnce(new TypeError('Failed to fetch'))
    await hydrate()
    cleanup()
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ id: 'u1', name: 'U', email: 'u@x', role: 'admin' }), { status: 200 }))
    await hydrate()
    expect(replaceMock).not.toHaveBeenCalled()
  })
})
