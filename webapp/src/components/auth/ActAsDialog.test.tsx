/**
 * The act-as dialog (step 3.14; IM-04, ID-25, ID-31, DV-19): a reason (marked required when Root
 * says so), a duration (default 60 minutes, choices up to the instance limit) and the admin's own
 * password; the account named by name, email and type. It shows why the server refused and stays
 * open until the switch succeeds. Built on Modal; labelled controls, reachable by keyboard.
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'
import { ApiError } from '@/lib/apiError'
import { ActAsDialog, durationChoices, durationLabel } from './ActAsDialog'

afterEach(() => cleanup())

const TARGET = { id: 'member-1', name: 'Marco', email: 'marco@e2e.local', accountType: 'member' as const }

function open(over: Partial<React.ComponentProps<typeof ActAsDialog>> = {}) {
  const props = {
    isOpen: true,
    target: TARGET,
    maxMinutes: 720,
    reasonRequired: false,
    onConfirm: vi.fn(async () => undefined),
    onClose: vi.fn(),
    ...over,
  }
  render(<ActAsDialog {...props} />)
  return {
    ...props,
    reason: () => screen.getByLabelText(/^Reason/) as HTMLInputElement,
    duration: () => screen.getByLabelText('For how long') as HTMLSelectElement,
    password: () => screen.getByLabelText('Your password') as HTMLInputElement,
  }
}

describe('ActAsDialog', () => {
  test('names the account by name, email and type, with three labelled controls', () => {
    const d = open()
    expect(screen.getByRole('dialog', { name: 'Act as another account' })).toBeInTheDocument()
    expect(screen.getByRole('group', { name: 'Marco, marco@e2e.local, Member' })).toBeInTheDocument()
    expect(d.reason().type).toBe('text')
    expect(d.password().type).toBe('password')
    expect(d.password().autocomplete).toBe('current-password')
    expect(screen.getByRole('button', { name: 'Act as Marco' })).toBeInTheDocument()
  })

  test('duration: 60 minutes by default, the choices up to the instance limit', () => {
    const d = open()
    expect(d.duration().value).toBe('60')
    expect([...d.duration().options].map((o) => o.textContent)).toEqual(['15 min', '30 min', '1 hour', '2 hours', '4 hours', '8 hours', '12 hours'])
    cleanup()
    const short = open({ maxMinutes: 45 })
    expect(short.duration().value).toBe('45')
    expect([...short.duration().options].map((o) => Number(o.value))).toEqual([15, 30, 45])
    expect(durationChoices(90)).toEqual([15, 30, 60, 90])
    expect(durationLabel(90)).toBe('90 min')
  })

  test('sends the reason, the duration and the password, then closes', async () => {
    const d = open()
    fireEvent.change(d.reason(), { target: { value: '  ticket #42 ' } })
    fireEvent.change(d.duration(), { target: { value: '30' } })
    fireEvent.change(d.password(), { target: { value: 'my-own-passphrase' } })
    fireEvent.submit(d.password().form!)
    await waitFor(() => expect(d.onClose).toHaveBeenCalledTimes(1))
    expect(d.onConfirm).toHaveBeenCalledWith({ reason: 'ticket #42', durationMinutes: 30, password: 'my-own-passphrase' })
  })

  test('reason required when set: marked, and asked before anything is sent', () => {
    const d = open({ reasonRequired: true })
    expect(screen.getByText('Reason (required)')).toBeInTheDocument()
    fireEvent.change(d.password(), { target: { value: 'pw' } })
    fireEvent.submit(d.password().form!)
    expect(screen.getByRole('alert')).toHaveTextContent('Say why you are acting as this account')
    expect(d.onConfirm).not.toHaveBeenCalled()
  })

  test('no password: asked for, nothing sent', () => {
    const d = open()
    fireEvent.submit(d.password().form!)
    expect(screen.getByRole('alert')).toHaveTextContent('Enter your password')
    expect(d.onConfirm).not.toHaveBeenCalled()
  })

  test('a refusal is shown and the dialog stays open, ready to try again', async () => {
    const onConfirm = vi.fn(async () => { throw new ApiError({ reason: 'Password is incorrect', status: 403, code: 'step_up_failed' }) })
    const d = open({ onConfirm })
    fireEvent.change(d.password(), { target: { value: 'wrong' } })
    fireEvent.submit(d.password().form!)
    expect(await screen.findByRole('alert')).toHaveTextContent('Password is incorrect')
    expect(d.onClose).not.toHaveBeenCalled()
    expect(screen.getByRole('button', { name: 'Act as Marco' })).not.toBeDisabled()
  })

  test('Cancel closes without sending', () => {
    const d = open()
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(d.onClose).toHaveBeenCalledTimes(1)
    expect(d.onConfirm).not.toHaveBeenCalled()
  })
})
