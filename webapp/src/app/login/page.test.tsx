/**
 * The sign-in form says why a sign-in failed.
 *
 * nginx answers a burst of sign-ins (429) and a restarting webapp (502) with an
 * HTML page; reading that as JSON used to throw and show "Unable to connect to
 * the server" for both. A database outage showed a bare "Internal server error".
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'
import { AlertProvider } from '@/components/ui'

vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn(), replace: vi.fn() }) }))
vi.mock('next/image', () => ({ default: (props: { alt: string }) => <span aria-label={props.alt} /> }))
vi.mock('@/hooks/useVersionCheck', () => ({ useVersionCheck: () => ({ currentVersion: '0.0.0' }) }))

import LoginPage from './page'

let fetchMock: ReturnType<typeof vi.fn>
beforeEach(() => {
  fetchMock = vi.fn()
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function signIn() {
  render(<LoginPage />)
  fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'admin@redamon.local' } })
  fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'pw' } })
  fireEvent.click(screen.getByRole('button', { name: 'Sign In' }))
}

describe('Login errors', () => {
  test('a database outage names its code and status', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ error: 'Internal server error', code: 'P1001' }), { status: 500 }))
    signIn()
    expect(await screen.findByText('Internal server error (P1001 · HTTP 500)')).toBeInTheDocument()
  })

  test("nginx's 429 page: the status and when to retry, not a connection error", async () => {
    fetchMock.mockResolvedValue(new Response('<html><body>429 Too Many Requests</body></html>', {
      status: 429, headers: { 'Retry-After': '30' },
    }))
    signIn()
    expect(await screen.findByText('Login failed (non_json_response · HTTP 429). Retry in 30 s.')).toBeInTheDocument()
  })

  test("a restarting webapp's 502 page names its status", async () => {
    fetchMock.mockResolvedValue(new Response('<html>502 Bad Gateway</html>', { status: 502 }))
    signIn()
    expect(await screen.findByText('Login failed (non_json_response · HTTP 502)')).toBeInTheDocument()
  })

  test('wrong credentials keep the route\'s own sentence', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ error: 'Invalid email or password' }), { status: 401 }))
    signIn()
    expect(await screen.findByText('Invalid email or password (HTTP 401)')).toBeInTheDocument()
  })

  test('no answer at all is a network failure', async () => {
    fetchMock.mockRejectedValue(new TypeError('Failed to fetch'))
    signIn()
    expect(await screen.findByText('Unable to connect to the server (network_error)')).toBeInTheDocument()
  })
})

describe('after the sign-in (step 2.10)', () => {
  const notice = {
    id: 'n1', type: 'credentials_reset', at: '2026-11-12T10:00:00.000Z', by: { name: 'Laura', email: 'laura@e2e.local' },
    reason: 'Locked out', mode: 'temporary',
  }
  let loc: { href: string }
  beforeEach(() => {
    loc = { href: '' }
    vi.stubGlobal('location', loc)
  })

  function signInWithDialogs() {
    render(<AlertProvider><LoginPage /></AlertProvider>)
    fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'marco@redamon.local' } })
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'pw' } })
    fireEvent.click(screen.getByRole('button', { name: 'Sign In' }))
  }

  test('a reset notice is shown once, in the app dialog, before the app opens', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ id: 'u1', notices: [notice] }), { status: 200 }))
    signInWithDialogs()
    const dialog = await screen.findByRole('dialog', { name: 'Your password was reset' })
    expect(dialog).toHaveTextContent('Laura (laura@e2e.local)')
    expect(dialog).toHaveTextContent('Reason: Locked out')
    expect(loc.href).toBe('')
    fireEvent.click(screen.getByRole('button', { name: 'OK' }))
    await waitFor(() => expect(loc.href).toBe('/graph'))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  test('no notice: straight to the app', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ id: 'u1' }), { status: 200 }))
    signInWithDialogs()
    await waitFor(() => expect(loc.href).toBe('/graph'))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })
})
