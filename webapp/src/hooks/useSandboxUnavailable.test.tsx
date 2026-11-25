/**
 * The modal of a Kali sandbox that cannot start (group 1, B.13), shown through
 * useAlertModal: "Not enough memory" with the governor's figures in GB, Retry and
 * Close; "Sandbox limit reached" for the hard count; the refused variant with no
 * Retry; and nothing for a payload that is not `unavailable`.
 *
 * Run: npx vitest run --no-file-parallelism src/hooks/useSandboxUnavailable.test.tsx
 */
import { describe, test, expect, afterEach, vi } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor, within } from '@testing-library/react'
import { AlertProvider } from '@/components/ui'
import {
  MODAL_CLOSE_LABEL,
  MODAL_HARD_BODY,
  MODAL_HARD_TITLE,
  MODAL_RAM_BODY,
  MODAL_RAM_TITLE,
  MODAL_REFUSED_BODY,
  MODAL_REFUSED_TITLE,
  MODAL_RETRY_LABEL,
} from '@/lib/sandbox/contract'
import { sandboxModalContent, useSandboxUnavailable, type SandboxModalAnswer } from './useSandboxUnavailable'

const GiB = 1024 ** 3

afterEach(cleanup)

const ramRefusal = {
  state: 'unavailable',
  reason: 'ram',
  limit: {
    admitted: false, limitType: 'ram', resource: 'kali_sandbox',
    current: 0.8 * GiB, ceiling: 12 * GiB, settingName: null,
    detail: 'not enough free memory to start a Kali sandbox now',
  },
}

const hardRefusal = {
  state: 'unavailable',
  reason: 'hard',
  limit: {
    admitted: false, limitType: 'hard', resource: 'kali_sandbox',
    current: 3, ceiling: 3, settingName: 'KALI_SANDBOX_MAX_CONCURRENT',
    detail: '3 of 3 Kali sandboxes allowed',
  },
}

function Harness({ payload, onAnswer }: { payload: unknown; onAnswer: (a: SandboxModalAnswer) => void }) {
  const show = useSandboxUnavailable()
  return <button type="button" onClick={() => { void show(payload).then(onAnswer) }}>show</button>
}

async function open(payload: unknown) {
  const onAnswer = vi.fn()
  render(<AlertProvider><Harness payload={payload} onAnswer={onAnswer} /></AlertProvider>)
  fireEvent.click(screen.getByRole('button', { name: 'show' }))
  const dialog = await screen.findByRole('dialog')
  return { dialog, onAnswer }
}

describe('the modal a person sees', () => {
  test('not enough memory: the title, the body, the figures in GB, Retry and Close', async () => {
    const { dialog, onAnswer } = await open(ramRefusal)
    expect(within(dialog).getByText(MODAL_RAM_TITLE)).toBeInTheDocument()
    expect(dialog.textContent).toContain(MODAL_RAM_BODY)
    expect(dialog.textContent).toContain('Not enough free memory to start a Kali sandbox now (0.8 GB of 12.0 GB).')
    expect(within(dialog).getByRole('button', { name: MODAL_CLOSE_LABEL })).toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('button', { name: MODAL_RETRY_LABEL }))
    await waitFor(() => expect(onAnswer).toHaveBeenCalledWith('retry'))
  })

  test('Close answers close', async () => {
    const { dialog, onAnswer } = await open(ramRefusal)
    fireEvent.click(within(dialog).getByRole('button', { name: MODAL_CLOSE_LABEL }))
    await waitFor(() => expect(onAnswer).toHaveBeenCalledWith('close'))
  })

  test('the hard count: its own title, the count, the setting, Retry and Close', async () => {
    const { dialog } = await open(hardRefusal)
    expect(within(dialog).getByText(MODAL_HARD_TITLE)).toBeInTheDocument()
    expect(dialog.textContent).toContain(MODAL_HARD_BODY)
    expect(dialog.textContent).toContain('3 of 3 Kali sandboxes allowed. Set by KALI_SANDBOX_MAX_CONCURRENT.')
    expect(dialog.textContent).not.toContain('GB')
    expect(within(dialog).getByRole('button', { name: MODAL_RETRY_LABEL })).toBeInTheDocument()
    expect(within(dialog).getByRole('button', { name: MODAL_CLOSE_LABEL })).toBeInTheDocument()
  })

  test('refused: its title and body, and no Retry', async () => {
    const { dialog, onAnswer } = await open({ state: 'unavailable', reason: 'refused' })
    expect(within(dialog).getByText(MODAL_REFUSED_TITLE)).toBeInTheDocument()
    expect(dialog.textContent).toContain(MODAL_REFUSED_BODY)
    expect(within(dialog).queryByRole('button', { name: MODAL_RETRY_LABEL })).toBeNull()
    fireEvent.click(within(dialog).getByRole('button', { name: 'OK' }))
    await waitFor(() => expect(onAnswer).toHaveBeenCalledWith('close'))
  })

  test('a refusal that carries a limit still shows no figure and no Retry', async () => {
    const { dialog } = await open({ ...ramRefusal, reason: 'refused' })
    expect(dialog.textContent).not.toContain('GB')
    expect(within(dialog).queryByRole('button', { name: MODAL_RETRY_LABEL })).toBeNull()
  })

  test('a start that failed offers Retry, and shows no agent detail', async () => {
    const { dialog } = await open({ state: 'unavailable', reason: 'error', detail: 'Traceback: /opt/secret path' })
    expect(within(dialog).getByText('Kali sandbox could not start')).toBeInTheDocument()
    expect(dialog.textContent).not.toContain('Traceback')
    expect(within(dialog).getByRole('button', { name: MODAL_RETRY_LABEL })).toBeInTheDocument()
  })
})

describe('sandboxModalContent', () => {
  test('nothing for a state other than unavailable, or a payload that is not an object', () => {
    expect(sandboxModalContent({ state: 'starting' })).toBeNull()
    expect(sandboxModalContent({ state: 'ready' })).toBeNull()
    expect(sandboxModalContent(null)).toBeNull()
    expect(sandboxModalContent('unavailable')).toBeNull()
  })

  test('an unknown or missing reason reads as a failed start, with Retry', () => {
    for (const reason of [undefined, 'boom', 42]) {
      const c = sandboxModalContent({ state: 'unavailable', reason })
      expect(c?.title).toBe('Kali sandbox could not start')
      expect(c?.retry).toBe(true)
      expect(c?.figures).toBeNull()
    }
  })

  test('a sandbox that stopped during the call says so, with Retry', () => {
    const c = sandboxModalContent({ state: 'unavailable', reason: 'stopped' })
    expect(c?.title).toBe('Kali sandbox stopped')
    expect(c?.retry).toBe(true)
  })

  test('figures only from a limit of the same kind, with finite numbers', () => {
    expect(sandboxModalContent({ ...ramRefusal, limit: { ...ramRefusal.limit, limitType: 'hard' } })?.figures).toBeNull()
    expect(sandboxModalContent({ ...ramRefusal, limit: { ...ramRefusal.limit, current: 'lots' } })?.figures).toBeNull()
    expect(sandboxModalContent({ ...ramRefusal, limit: { ...ramRefusal.limit, ceiling: Number.NaN } })?.figures).toBeNull()
    expect(sandboxModalContent({ ...ramRefusal, limit: null })?.figures).toBeNull()
  })

  test('a limit with no detail still shows its figures', () => {
    expect(sandboxModalContent({ ...ramRefusal, limit: { ...ramRefusal.limit, detail: '' } })?.figures)
      .toBe('Memory (0.8 GB of 12.0 GB).')
    expect(sandboxModalContent({ ...hardRefusal, limit: { ...hardRefusal.limit, detail: undefined, settingName: null } })?.figures)
      .toBe('3 of 3 Kali sandboxes allowed.')
  })

  test('a long or multi-line detail is cut to one short line', () => {
    const c = sandboxModalContent({ ...ramRefusal, limit: { ...ramRefusal.limit, detail: `budget\n${'x'.repeat(500)}` } })
    expect(c?.figures).not.toContain('\n')
    expect((c?.figures ?? '').length).toBeLessThan(200)
  })
})
