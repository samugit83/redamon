/**
 * "Reset credentials" on the Users page (step 2.10, ID-18, ID-19, DV-06, DV-19): a reset link by
 * default (shown once, with Copy, its expiry and the localhost warning), or a temporary password
 * the person must change, checked against the policy and its confirmation before anything is
 * sent. The reason the person will read is sent trimmed; the server says when it is required, and
 * its refusal is shown. Another admin's reset (Root only) asks for the viewer's own password.
 * Labelled controls, a real form (Enter submits), a busy state.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'
import { ResetCredentialsModal } from './ResetCredentialsModal'

const POLICY = { minLength: 16, rules: true, description: 'At least 16 characters and at most 72 bytes.' }
const MARCO = { id: 'member-1', name: 'Marco', email: 'marco@e2e.local' }
const LINK = 'https://redamon.example.com/invite/abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG'
const GOOD = 'violet-harbour-lantern-42'

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
let fetchMock: ReturnType<typeof vi.fn>
const onDone = vi.fn()
const onClose = vi.fn()

function open(over: Partial<Parameters<typeof ResetCredentialsModal>[0]> = {}) {
  render(<ResetCredentialsModal isOpen user={MARCO} targetIsAdmin={false} policy={POLICY} onClose={onClose} onDone={onDone} {...over} />)
}
const type = (label: string, value: string) => fireEvent.change(screen.getByLabelText(label), { target: { value } })
const submit = () => fireEvent.click(screen.getByRole('button', { name: 'Reset credentials' }))
const sentBody = () => JSON.parse(String((fetchMock.mock.calls[0][1] as RequestInit).body))

beforeEach(() => {
  fetchMock = vi.fn(async () => json({
    id: 'member-1', mode: 'link', link: LINK, expiresAt: '2026-11-12T16:00:00.000Z', localhostWarning: false,
    tokensRevoked: 0, agent: { sockets: { closed: 0 } },
  }))
  vi.stubGlobal('fetch', fetchMock)
  onDone.mockReset()
  onClose.mockReset()
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('a reset link (the default)', () => {
  test('sends mode link, then shows the link once with Copy and its expiry', async () => {
    open()
    expect(screen.getByRole('dialog', { name: 'Reset credentials - Marco' })).toBeInTheDocument()
    expect(screen.getByRole('radio', { name: 'Send a reset link' })).toBeChecked()
    submit()
    const field = await screen.findByLabelText('Reset link')
    expect(field).toHaveValue(LINK)
    expect(screen.getByRole('button', { name: 'Copy the reset link' })).toBeInTheDocument()
    expect(fetchMock).toHaveBeenCalledWith('/api/users/member-1/reset-credentials', expect.objectContaining({ method: 'POST' }))
    expect(sentBody()).toEqual({ mode: 'link' })
    expect(onDone).toHaveBeenCalledTimes(1)
    fireEvent.click(screen.getByRole('button', { name: 'Done' }))
    expect(onClose).toHaveBeenCalled()
  })

  test('the localhost warning while the instance has no public address', async () => {
    fetchMock.mockImplementation(async () => json({ mode: 'link', link: 'http://localhost:3000/invite/x', expiresAt: '2026-11-12T16:00:00.000Z', localhostWarning: true }))
    open()
    submit()
    expect(await screen.findByRole('note')).toHaveTextContent(/localhost/)
  })
})

describe('the reason', () => {
  test('sent trimmed; the field says the person reads it', async () => {
    open()
    const reason = screen.getByLabelText('Reason')
    expect(reason).toHaveAccessibleDescription(/they will read it/i)
    type('Reason', '  Locked out after a holiday  ')
    submit()
    await screen.findByLabelText('Reset link')
    expect(sentBody()).toEqual({ mode: 'link', reason: 'Locked out after a holiday' })
  })

  test("the server's refusal is shown (a reason is required once the person has signed in)", async () => {
    fetchMock.mockImplementation(async () => json({ error: 'This person has signed in before: give the reason for the reset.', code: 'reason_required' }, 400))
    open()
    submit()
    expect(await screen.findByRole('alert')).toHaveTextContent(/give the reason/)
    expect(screen.queryByLabelText('Reset link')).not.toBeInTheDocument()
    expect(onDone).not.toHaveBeenCalled()
  })
})

describe('a temporary password', () => {
  function chooseTemporary() {
    fireEvent.click(screen.getByRole('radio', { name: 'Set a temporary password' }))
  }

  test('checked against the policy and its confirmation before anything is sent', async () => {
    open()
    chooseTemporary()
    expect(screen.getByLabelText('Temporary password')).toHaveAccessibleDescription(POLICY.description)
    type('Temporary password', 'short')
    type('Confirm the temporary password', 'short')
    submit()
    expect(await screen.findByRole('alert')).toHaveTextContent('at least 16 characters')
    type('Temporary password', GOOD)
    type('Confirm the temporary password', `${GOOD}x`)
    submit()
    expect(await screen.findByRole('alert')).toHaveTextContent('do not match')
    expect(fetchMock).not.toHaveBeenCalled()
  })

  test('sent with the reason; the answer says the person must change it', async () => {
    fetchMock.mockImplementation(async () => json({ id: 'member-1', mode: 'temporary', mustChangePassword: true, tokensRevoked: 1 }))
    open()
    chooseTemporary()
    type('Temporary password', GOOD)
    type('Confirm the temporary password', GOOD)
    type('Reason', 'Asked by phone')
    submit()
    expect(await screen.findByRole('status')).toHaveTextContent(/must choose a new one/)
    expect(sentBody()).toEqual({ mode: 'temporary', temporaryPassword: GOOD, reason: 'Asked by phone' })
    expect(onDone).toHaveBeenCalledTimes(1)
  })

  test('the email rule uses the account\'s address', async () => {
    open({ user: { ...MARCO, email: 'marco.rossi.long@e2e.local' } })
    chooseTemporary()
    type('Temporary password', 'marco.rossi.long@e2e.local')
    type('Confirm the temporary password', 'marco.rossi.long@e2e.local')
    submit()
    expect(await screen.findByRole('alert')).toHaveTextContent(/email/)
    expect(fetchMock).not.toHaveBeenCalled()
  })
})

describe('another admin (Root only)', () => {
  test("asks for the viewer's own password and sends it", async () => {
    open({ targetIsAdmin: true })
    submit()
    expect(await screen.findByRole('alert')).toHaveTextContent('Enter your password')
    expect(fetchMock).not.toHaveBeenCalled()
    type('Your password', 'root-own-passphrase')
    submit()
    await screen.findByLabelText('Reset link')
    expect(sentBody()).toEqual({ mode: 'link', stepUpPassword: 'root-own-passphrase' })
  })

  test('a member target asks for no password', () => {
    open()
    expect(screen.queryByLabelText('Your password')).not.toBeInTheDocument()
  })
})

describe('the form', () => {
  test('Enter submits; the button shows the work and cannot be pressed twice', async () => {
    let answer: (r: Response) => void = () => {}
    fetchMock.mockImplementation(() => new Promise<Response>((resolve) => { answer = resolve }))
    open()
    fireEvent.submit(screen.getByLabelText('Reason').closest('form')!)
    const busy = await screen.findByRole('button', { name: 'Resetting…' })
    expect(busy).toBeDisabled()
    answer(json({ mode: 'link', link: LINK, expiresAt: '2026-11-12T16:00:00.000Z', localhostWarning: false }))
    await screen.findByLabelText('Reset link')
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  test('Cancel closes without sending', () => {
    open()
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(onClose).toHaveBeenCalled()
    expect(fetchMock).not.toHaveBeenCalled()
  })

  test('closed: nothing rendered', () => {
    open({ isOpen: false })
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })
})

describe('switching mode keeps the choice explicit', () => {
  test('the temporary fields appear only with that choice', async () => {
    open()
    expect(screen.queryByLabelText('Temporary password')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('radio', { name: 'Set a temporary password' }))
    await waitFor(() => expect(screen.getByLabelText('Temporary password')).toBeInTheDocument())
  })
})
