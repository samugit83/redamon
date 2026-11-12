/**
 * The public `/invite` page (step 2.9, ID-15, DV-06, DV-19, UI-11): every state (loading, a read
 * error with a retry, the one invalid-link page, the form), the policy shown beside the password
 * and checked before anything is sent, the server's refusal shown inline, the success through the
 * alert dialog then the app. Labelled fields, a real form (Enter submits). With the identity
 * switch off the page does not exist.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'

const h = vi.hoisted(() => ({ alert: vi.fn(), assign: vi.fn(), notFound: vi.fn(() => { throw new Error('NEXT_NOT_FOUND') }) }))
vi.mock('next/image', () => ({ default: (props: { alt: string }) => <span aria-label={props.alt} /> }))
vi.mock('next/navigation', () => ({ notFound: h.notFound }))
vi.mock('@/components/ui', () => ({ useOptionalAlertModal: () => ({ alert: h.alert }) }))

import InvitePage from './page'
import { InviteAcceptForm } from './InviteAcceptForm'
import { setFlagsForTests } from '@/lib/authz/flags'

const DESCRIPTION = 'At least 16 characters and at most 72 bytes; not a common password, not your email address or its name part, not one character repeated.'
const STATE = {
  valid: true, kind: 'invite', name: 'Nina', email: 'nina@e2e.local', expiresAt: '2026-11-19T10:00:00.000Z',
  policy: { minLength: 16, maxBytes: 72, rules: true, description: DESCRIPTION },
}
const GOOD = 'violet-harbour-lantern-42'

let fetchMock: ReturnType<typeof vi.fn>
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status })

beforeEach(() => {
  fetchMock = vi.fn(async (url: string) => (url === '/api/invite/state' ? json(STATE) : json({ id: 'u1' })))
  vi.stubGlobal('fetch', fetchMock)
  h.alert.mockReset().mockResolvedValue(undefined)
  h.assign.mockReset()
  vi.stubGlobal('location', { ...window.location, assign: h.assign })
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  setFlagsForTests(null)
})

const type = (label: string, value: string) => fireEvent.change(screen.getByLabelText(label), { target: { value } })
const posts = () => fetchMock.mock.calls.filter(([url]) => url === '/api/invite/accept')

describe('the states', () => {
  test('loading, then the form with the account and the policy beside the password', async () => {
    render(<InviteAcceptForm />)
    expect(screen.getByRole('status')).toHaveTextContent('Checking the link')
    expect(await screen.findByRole('heading', { name: 'Accept your invitation' })).toBeInTheDocument()
    expect(screen.getByText(/Nina \(nina@e2e\.local\)/)).toBeInTheDocument()
    expect(screen.getByLabelText('Password')).toHaveAccessibleDescription(DESCRIPTION)
    expect(screen.getByLabelText('Confirm password')).toBeInTheDocument()
    expect(fetchMock).toHaveBeenCalledWith('/api/invite/state', { cache: 'no-store' })
  })

  test('expired, used, cancelled or unknown: the one invalid page, no form', async () => {
    fetchMock.mockImplementation(async () => json({ valid: false }))
    render(<InviteAcceptForm />)
    expect(await screen.findByRole('alert')).toHaveTextContent('This link is not valid or has expired')
    expect(screen.queryByLabelText('Password')).toBeNull()
    expect(screen.getByRole('link', { name: 'Go to sign in' })).toHaveAttribute('href', '/login')
  })

  test('a read error names its cause and offers a retry', async () => {
    fetchMock.mockImplementationOnce(async () => json({ error: 'Could not read the link. Try again in a moment.', code: 'P1001' }, 500))
    render(<InviteAcceptForm />)
    expect(await screen.findByRole('alert')).toHaveTextContent(/P1001/)
    fireEvent.click(screen.getByRole('button', { name: 'Try again' }))
    expect(await screen.findByLabelText('Password')).toBeInTheDocument()
  })

  test('a reset link says so', async () => {
    fetchMock.mockImplementation(async () => json({ ...STATE, kind: 'reset' }))
    render(<InviteAcceptForm />)
    expect(await screen.findByRole('heading', { name: 'Choose a new password' })).toBeInTheDocument()
  })
})

describe('setting the password', () => {
  test('accept enforces the policy here first: nothing is sent', async () => {
    render(<InviteAcceptForm />)
    await screen.findByLabelText('Password')
    type('Password', 'fifteen-chars-x')
    type('Confirm password', 'fifteen-chars-x')
    fireEvent.click(screen.getByRole('button', { name: 'Set password and sign in' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Password must be at least 16 characters')
    type('Password', 'nina@e2e.local-x!')
    type('Confirm password', 'different-password-1')
    fireEvent.click(screen.getByRole('button', { name: 'Set password and sign in' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('The two passwords do not match')
    expect(posts()).toHaveLength(0)
  })

  test('Enter submits; success goes through the alert dialog, then to the app', async () => {
    render(<InviteAcceptForm />)
    await screen.findByLabelText('Password')
    type('Password', GOOD)
    type('Confirm password', GOOD)
    fireEvent.submit(screen.getByLabelText('Confirm password').closest('form')!)
    await waitFor(() => expect(h.assign).toHaveBeenCalledWith('/graph'))
    expect(posts()[0][1]).toMatchObject({ method: 'POST', body: JSON.stringify({ password: GOOD }) })
    expect(h.alert).toHaveBeenCalledWith(expect.stringContaining('signed in'), 'Password set')
  })

  test("the server's refusal is shown inline", async () => {
    fetchMock.mockImplementation(async (url: string) => (url === '/api/invite/state'
      ? json(STATE)
      : json({ error: 'This password is too common', code: 'password_common', attemptsLeft: 4 }, 400)))
    render(<InviteAcceptForm />)
    await screen.findByLabelText('Password')
    type('Password', GOOD)
    type('Confirm password', GOOD)
    fireEvent.click(screen.getByRole('button', { name: 'Set password and sign in' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('This password is too common')
    expect(h.assign).not.toHaveBeenCalled()
  })

  test('a link that stopped working meanwhile (410) shows the invalid page', async () => {
    fetchMock.mockImplementation(async (url: string) => (url === '/api/invite/state'
      ? json(STATE)
      : json({ error: 'This link is not valid or has expired', code: 'invite_invalid' }, 410)))
    render(<InviteAcceptForm />)
    await screen.findByLabelText('Password')
    type('Password', GOOD)
    type('Confirm password', GOOD)
    fireEvent.click(screen.getByRole('button', { name: 'Set password and sign in' }))
    expect(await screen.findByText('This link is not valid or has expired')).toBeInTheDocument()
    expect(screen.queryByLabelText('Password')).toBeNull()
  })
})

describe('the page', () => {
  test('switch off 404: the page does not exist', () => {
    setFlagsForTests({ identity: false })
    expect(() => InvitePage()).toThrow('NEXT_NOT_FOUND')
  })

  test('switch on: the form', () => {
    setFlagsForTests({ identity: true })
    expect(InvitePage().type).toBe(InviteAcceptForm)
  })
})
