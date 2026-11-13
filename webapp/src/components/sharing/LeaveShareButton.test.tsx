/**
 * Leave (step 4.12; SH-10, UI-07): a collaborator gives up their share of a project. The
 * confirmation goes through useAlertModal (the real AlertProvider), then POST .../leave (4.4's
 * route, same-origin JSON); a refusal is shown through the same modal.
 *
 * Run: npx vitest run --no-file-parallelism src/components/sharing/LeaveShareButton.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor, within } from '@testing-library/react'
import { AlertProvider, ToastProvider } from '@/components/ui'
import { LeaveShareButton } from './LeaveShareButton'

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })

const fetchMock = vi.fn()

function renderButton(over: Partial<Parameters<typeof LeaveShareButton>[0]> = {}) {
  const onLeft = vi.fn()
  const parentClick = vi.fn()
  render(
    <ToastProvider>
      <AlertProvider>
        <div onClick={parentClick}>
          <LeaveShareButton project={{ id: 'P1', name: 'Alpha recon' }} onLeft={onLeft} {...over} />
        </div>
      </AlertProvider>
    </ToastProvider>,
  )
  return { onLeft, parentClick }
}
const leave = () => fireEvent.click(screen.getByRole('button', { name: 'Leave Alpha recon' }))

beforeEach(() => {
  fetchMock.mockReset().mockResolvedValue(json({ left: { projectId: 'P1' }, socketsClosed: true }))
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('leave', () => {
  test('confirm, then POST leave as same-origin JSON; the parent card is not opened; onLeft and a toast', async () => {
    const { onLeft, parentClick } = renderButton()
    leave()
    expect(parentClick).not.toHaveBeenCalled()
    const confirm = await screen.findByRole('dialog', { name: 'Leave project' })
    expect(confirm).toHaveTextContent(/You lose access to "Alpha recon" now/)
    fireEvent.click(within(confirm).getByRole('button', { name: 'Leave' }))
    await waitFor(() => expect(onLeft).toHaveBeenCalledTimes(1))
    expect(fetchMock).toHaveBeenCalledWith('/api/projects/P1/leave', expect.objectContaining({
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}',
    }))
    expect(await screen.findByText('You left "Alpha recon".')).toBeInTheDocument()
  })

  test('cancel: nothing sent', async () => {
    const { onLeft } = renderButton()
    leave()
    fireEvent.click(within(await screen.findByRole('dialog', { name: 'Leave project' })).getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Leave project' })).toBeNull())
    expect(fetchMock).not.toHaveBeenCalled()
    expect(onLeft).not.toHaveBeenCalled()
  })

  test('the open project: no toast of its own (the access check that follows says the access ended)', async () => {
    const { onLeft } = renderButton({ announce: false })
    leave()
    fireEvent.click(within(await screen.findByRole('dialog', { name: 'Leave project' })).getByRole('button', { name: 'Leave' }))
    await waitFor(() => expect(onLeft).toHaveBeenCalledTimes(1))
    expect(screen.queryByText('You left "Alpha recon".')).toBeNull()
  })

  test('a refusal is shown with its code, and onLeft is not called', async () => {
    fetchMock.mockResolvedValue(json({ error: 'This person holds no share of the project.', code: 'no_such_share' }, 404))
    const { onLeft } = renderButton()
    leave()
    fireEvent.click(within(await screen.findByRole('dialog', { name: 'Leave project' })).getByRole('button', { name: 'Leave' }))
    expect(await screen.findByText('This person holds no share of the project. (no_such_share · HTTP 404)')).toBeInTheDocument()
    expect(onLeft).not.toHaveBeenCalled()
  })

  test('labelled for the keyboard: a button named after the project, with a title', () => {
    renderButton()
    expect(screen.getByRole('button', { name: 'Leave Alpha recon' })).toHaveAttribute('title', 'Leave this project')
  })
})
