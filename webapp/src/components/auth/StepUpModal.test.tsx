/**
 * The step-up dialog (ID-25): asks the signed-in admin for their own password before
 * an admin-on-admin action, shows why the server refused it, and stays open until the
 * action succeeds. Built on Modal; never window.prompt.
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'
import { ApiError } from '@/lib/apiError'
import { StepUpModal } from './StepUpModal'

afterEach(() => cleanup())

function open(over: Partial<React.ComponentProps<typeof StepUpModal>> = {}) {
  const props = {
    isOpen: true,
    title: 'Act as an admin',
    message: 'Acting as Bob, an admin, needs your password.',
    confirmLabel: 'Switch user',
    onConfirm: vi.fn(async () => undefined),
    onClose: vi.fn(),
    ...over,
  }
  const view = render(<StepUpModal {...props} />)
  return { ...props, view, field: () => screen.getByLabelText('Your password') as HTMLInputElement }
}

describe('StepUpModal', () => {
  test('a labelled, focused password field under the message', () => {
    const { field } = open()
    expect(screen.getByRole('dialog', { name: 'Act as an admin' })).toBeInTheDocument()
    expect(screen.getByText('Acting as Bob, an admin, needs your password.')).toBeInTheDocument()
    expect(field().type).toBe('password')
    expect(field().autocomplete).toBe('current-password')
    expect(document.activeElement).toBe(field())
  })

  test('Enter submits the typed password, then the dialog closes', async () => {
    const { field, onConfirm, onClose } = open()
    fireEvent.change(field(), { target: { value: 'my-own-passphrase' } })
    fireEvent.submit(field().form!)
    await waitFor(() => expect(onConfirm).toHaveBeenCalledWith('my-own-passphrase'))
    await waitFor(() => expect(onClose).toHaveBeenCalledOnce())
  })

  test('an empty password is refused here, nothing sent', async () => {
    const { onConfirm } = open()
    fireEvent.click(screen.getByRole('button', { name: 'Switch user' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Enter your password')
    expect(onConfirm).not.toHaveBeenCalled()
  })

  test('a refusal stays open and shows the server\'s reason with its code', async () => {
    const onConfirm = vi.fn(async () => {
      throw new ApiError({ reason: 'Password is incorrect', status: 403, code: 'step_up_failed' })
    })
    const { field, onClose } = open({ onConfirm })
    fireEvent.change(field(), { target: { value: 'wrong-one' } })
    fireEvent.click(screen.getByRole('button', { name: 'Switch user' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Password is incorrect (step_up_failed · HTTP 403)')
    expect(onClose).not.toHaveBeenCalled()
    expect(screen.getByRole('dialog')).toBeInTheDocument()
  })

  test('while checking, both buttons are disabled and say so', async () => {
    let finish!: () => void
    const onConfirm = vi.fn(() => new Promise<void>(r => { finish = r }))
    const { field } = open({ onConfirm })
    fireEvent.change(field(), { target: { value: 'my-own-passphrase' } })
    fireEvent.click(screen.getByRole('button', { name: 'Switch user' }))
    const busy = await screen.findByRole('button', { name: 'Checking...' })
    expect(busy).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Cancel' })).toBeDisabled()
    finish()
  })

  test('Cancel closes without sending', () => {
    const { onConfirm, onClose } = open()
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(onClose).toHaveBeenCalledOnce()
    expect(onConfirm).not.toHaveBeenCalled()
  })

  test('reopening starts empty, with no old error', async () => {
    const onConfirm = vi.fn(async () => { throw new Error('Password is incorrect') })
    const { field, view, onClose } = open({ onConfirm })
    fireEvent.change(field(), { target: { value: 'wrong-one' } })
    fireEvent.click(screen.getByRole('button', { name: 'Switch user' }))
    await screen.findByRole('alert')
    const props = { title: 'Act as an admin', message: 'm', confirmLabel: 'Switch user', onConfirm, onClose }
    view.rerender(<StepUpModal isOpen={false} {...props} />)
    view.rerender(<StepUpModal isOpen {...props} />)
    expect((screen.getByLabelText('Your password') as HTMLInputElement).value).toBe('')
    expect(screen.queryByRole('alert')).toBeNull()
  })

  test('closed renders nothing', () => {
    open({ isOpen: false })
    expect(screen.queryByRole('dialog')).toBeNull()
  })
})
