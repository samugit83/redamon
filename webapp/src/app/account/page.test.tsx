/**
 * /account (step 2.8, ID-17): the change page the middleware holds an account on while its
 * password must change, and where anyone changes their own password. The form shows the
 * policy in force beside the new password, checks it before sending (the server's message),
 * sends the current password with the new one, and after a forced change confirms through the
 * app's dialog and goes on into the app (the response carries the new cookie). Loading, error,
 * signed-out and refusal states; every control labelled and the form submits with Enter.
 */
import { describe, test, expect, vi, afterEach, beforeEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'
import { AlertProvider } from '@/components/ui'

const h = vi.hoisted(() => ({
  search: new URLSearchParams(''),
  auth: {
    user: { id: 'member-1', email: 'rbac-member-long@e2e.local', name: 'Member', role: 'standard' } as Record<string, unknown> | null,
    isLoading: false,
    sessionError: null as { message: string } | null,
  },
  fetch: vi.fn(),
  assign: vi.fn(),
  putStatus: 200,
  putBody: { success: true, revokedMcpTokens: 0 } as Record<string, unknown>,
}))

vi.mock('next/navigation', () => ({ useSearchParams: () => h.search }))
vi.mock('@/providers/AuthProvider', () => ({ useAuth: () => h.auth }))

import AccountPage from './page'

const TEXT = 'At least 16 characters and at most 72 bytes; not a common password, not your email address or its name part, not one character repeated.'

function renderPage() {
  return render(<AlertProvider><AccountPage /></AlertProvider>)
}

function fill(current: string, next: string, confirm = next) {
  fireEvent.change(screen.getByLabelText('Current password'), { target: { value: current } })
  fireEvent.change(screen.getByLabelText('New password'), { target: { value: next } })
  fireEvent.change(screen.getByLabelText('Confirm new password'), { target: { value: confirm } })
}

const realLocation = window.location
const puts = () => h.fetch.mock.calls.filter((c) => (c[1] as RequestInit | undefined)?.method === 'PUT')

beforeEach(() => {
  h.search = new URLSearchParams('')
  h.auth = {
    user: { id: 'member-1', email: 'rbac-member-long@e2e.local', name: 'Member', role: 'standard' },
    isLoading: false,
    sessionError: null,
  }
  h.putStatus = 200
  h.putBody = { success: true, revokedMcpTokens: 0 }
  h.fetch.mockReset().mockImplementation(async (url: string, init?: RequestInit) => {
    if (url === '/api/auth/password-policy') {
      return new Response(JSON.stringify({ minLength: 16, maxBytes: 72, rules: true, description: TEXT }), { status: 200 })
    }
    if (url === '/api/users/member-1/password' && init?.method === 'PUT') {
      return new Response(JSON.stringify(h.putBody), { status: h.putStatus })
    }
    throw new Error(`unexpected fetch ${url}`)
  })
  vi.stubGlobal('fetch', h.fetch)
  h.assign.mockReset()
  Object.defineProperty(window, 'location', { configurable: true, value: { ...realLocation, assign: h.assign } })
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  Object.defineProperty(window, 'location', { configurable: true, value: realLocation })
})

describe('the password form', () => {
  test('labelled fields, the policy beside the new password', async () => {
    renderPage()
    expect(screen.getByRole('heading', { name: 'My account' })).toBeInTheDocument()
    expect(screen.getByLabelText('Current password')).toHaveAttribute('autocomplete', 'current-password')
    await waitFor(() => expect(screen.getByLabelText('New password')).toHaveAccessibleDescription(TEXT))
    expect(screen.getByLabelText('Confirm new password')).toHaveAttribute('type', 'password')
  })

  test('a password the policy refuses: its message, nothing sent', async () => {
    renderPage()
    await screen.findByText(TEXT)
    fill('the-temporary-one', 'rbac-member-long')
    fireEvent.click(screen.getByRole('button', { name: 'Change password' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('The password must not be your email address or its name part')
    expect(puts()).toEqual([])
  })

  test('the two new passwords must match', async () => {
    renderPage()
    fill('the-temporary-one', 'Correct-orchid-paddle', 'Correct-orchid-paddlE')
    fireEvent.click(screen.getByRole('button', { name: 'Change password' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('The new passwords do not match')
    expect(puts()).toEqual([])
  })

  test('the current password is required', async () => {
    renderPage()
    fill('', 'Correct-orchid-paddle')
    fireEvent.click(screen.getByRole('button', { name: 'Change password' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Enter your current password')
    expect(puts()).toEqual([])
  })

  test('Enter submits; the current and the new password go to the own password route', async () => {
    renderPage()
    fill('the-temporary-one', 'Correct-orchid-paddle')
    fireEvent.submit(screen.getByLabelText('Confirm new password').closest('form')!)
    await waitFor(() => expect(puts()).toHaveLength(1))
    expect(JSON.parse(puts()[0][1].body as string)).toEqual({ currentPassword: 'the-temporary-one', newPassword: 'Correct-orchid-paddle' })
    expect(await screen.findByRole('status')).toHaveTextContent('Your password was changed.')
    expect(h.assign).not.toHaveBeenCalled()
  })

  test("the server's refusal is shown with its code", async () => {
    h.putStatus = 401
    h.putBody = { error: 'Current password is incorrect', code: 'step_up_failed' }
    renderPage()
    fill('wrong', 'Correct-orchid-paddle')
    fireEvent.click(screen.getByRole('button', { name: 'Change password' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Current password is incorrect')
    expect(h.assign).not.toHaveBeenCalled()
  })
})

describe('the forced change', () => {
  test('says why the page is shown, and after the change confirms and goes on into the app', async () => {
    h.search = new URLSearchParams('changePassword=1')
    renderPage()
    expect(screen.getByText(/must change your password before you continue/)).toBeInTheDocument()
    fill('the-temporary-one', 'Correct-orchid-paddle')
    fireEvent.click(screen.getByRole('button', { name: 'Change password' }))
    // The app's dialog (useAlertModal), never window.alert.
    const ok = await screen.findByRole('button', { name: 'OK' })
    expect(screen.getByText('Your password was changed. You can now use RedAmon.')).toBeInTheDocument()
    expect(h.assign).not.toHaveBeenCalled()
    fireEvent.click(ok)
    await waitFor(() => expect(h.assign).toHaveBeenCalledWith('/graph'))
  })
})

describe('states', () => {
  test('loading', () => {
    h.auth = { user: null, isLoading: true, sessionError: null }
    renderPage()
    expect(screen.getByRole('status')).toHaveTextContent('Loading your account')
    expect(screen.queryByLabelText('New password')).not.toBeInTheDocument()
  })

  test('the session could not be read: the error and a retry', () => {
    h.auth = { user: null, isLoading: false, sessionError: { message: 'Could not read your session (P1001 · HTTP 500)' } }
    renderPage()
    expect(screen.getByRole('alert')).toHaveTextContent('Could not read your session (P1001 · HTTP 500)')
    expect(screen.getByRole('button', { name: 'Retry' })).toBeInTheDocument()
  })

  test('signed out: a link to sign in, no form', () => {
    h.auth = { user: null, isLoading: false, sessionError: null }
    renderPage()
    expect(screen.getByRole('link', { name: 'Sign in' })).toHaveAttribute('href', '/login')
    expect(screen.queryByLabelText('New password')).not.toBeInTheDocument()
  })

  test('no policy from the server (switch off): Phase 1 floor, no policy text', async () => {
    h.fetch.mockImplementation(async (url: string, init?: RequestInit) => {
      if (url === '/api/auth/password-policy') return new Response('{}', { status: 404 })
      if (init?.method === 'PUT') return new Response(JSON.stringify(h.putBody), { status: 200 })
      throw new Error(`unexpected fetch ${url}`)
    })
    renderPage()
    await waitFor(() => expect(h.fetch).toHaveBeenCalledWith('/api/auth/password-policy'))
    expect(screen.getByLabelText('New password')).not.toHaveAccessibleDescription(TEXT)
    fill('old', 'elevenchars')
    fireEvent.click(screen.getByRole('button', { name: 'Change password' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Password must be at least 12 characters')
  })
})
