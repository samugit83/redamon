/**
 * The Sessions panel keeps the open terminal while its row is not listed (group 1, E3; S16b, after M-b).
 *
 * The terminal's output lives in SessionTerminal's own state. A poll that left the selected row's
 * sandbox out (busy, 200 with `unavailable_count`), or failed with nothing listed, used to return the
 * empty state early: the terminal unmounted mid-command, the command's answer was lost, and when the
 * row came back an empty terminal mounted. Now the terminal stays mounted while a row is selected; the
 * empty state shows only when nothing is selected and nothing is listed, and a terminal whose row is
 * no longer listed can be closed. A row kept from an earlier answer says it was not refreshed. When a
 * complete answer (no sandbox left out, no error) no longer lists the selected row, the terminal says
 * the session ended and takes no more commands.
 *
 * Run: npx vitest run --no-file-parallelism src/app/graph/components/ActiveSessions/ActiveSessions.busySandbox.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, act, waitFor } from '@testing-library/react'

vi.mock('@/components/ui', async (orig) => ({
  ...(await orig<typeof import('@/components/ui')>()),
  useToast: () => ({ success: vi.fn(), error: vi.fn(), info: vi.fn(), warning: vi.fn() }),
}))
vi.mock('@/components/shared/FeatureModelGate', () => ({
  useFeatureModelGate: () => ({ ensureFeatureModel: async () => true, fetchWithFeatureModel: async (_f: string, go: () => Promise<Response>) => go() }),
  FeatureModelLine: () => null,
}))
vi.mock('./useSandboxStatus', () => ({ useSandboxStatus: () => ({ stopAt: null, reversePort: null }) }))

import { ActiveSessions } from './ActiveSessions'

const ROW = { id: 1, sandbox: 'b0b001', type: 'shell', info: 'lab', connection: '', target_ip: '', chat_session_id: 'session_x' }

afterEach(() => { cleanup() })

function panel(sessions: unknown[], over: Record<string, unknown> = {}) {
  return (
    <ActiveSessions
      sessions={sessions as never} jobs={[]} nonMsfSessions={[]} busyInstances={[]} isLoading={false} projectId="p"
      onInteract={(over.onInteract ?? vi.fn(async () => ({ busy: false, output: '' }))) as never}
      onKillSession={(over.onKillSession ?? vi.fn(async () => {})) as never} onKillJob={vi.fn() as never}
      unavailable={(over.unavailable as number | undefined) ?? 0} error={(over.error as string | null | undefined) ?? null}
    />
  )
}

function deferredInteract() {
  let resolve!: (v: unknown) => void
  const onInteract = vi.fn(() => new Promise(r => { resolve = r }))
  return { onInteract, answer: (output: string) => act(async () => { resolve({ busy: false, output }) }) }
}

async function sendCommand(container: HTMLElement, command = 'echo ALICE-$((6*7))') {
  fireEvent.click(container.querySelector('[data-session-key="b0b001:1"]')!)
  const input = screen.getByPlaceholderText('Type a command...')
  fireEvent.change(input, { target: { value: command } })
  fireEvent.keyDown(input, { key: 'Enter' })
  await waitFor(() => expect(screen.getByText(`$ ${command}`)).toBeInTheDocument())
}

describe('the open terminal', () => {
  test('control: no poll in between, the answer is shown', async () => {
    const { onInteract, answer } = deferredInteract()
    const { container } = render(panel([ROW], { onInteract }))
    await sendCommand(container)
    await answer('ALICE-42')
    expect(screen.getByText('ALICE-42')).toBeInTheDocument()
  })

  test("a poll that left the row's sandbox out keeps the terminal mounted, and the answer is shown", async () => {
    const { onInteract, answer } = deferredInteract()
    const { container, rerender } = render(panel([ROW], { onInteract }))
    await sendCommand(container)
    rerender(panel([], { onInteract, unavailable: 1 }))
    expect(screen.queryByText('No Reverse Shells')).toBeNull()
    expect(screen.getByPlaceholderText('Type a command...')).toBeInTheDocument()
    expect(screen.getByText('1 sandbox did not answer; its sessions may be out of date or missing')).toBeInTheDocument()
    await answer('ALICE-42')
    expect(screen.getByText('ALICE-42')).toBeInTheDocument()
    rerender(panel([ROW], { onInteract }))
    expect(screen.getByText('ALICE-42')).toBeInTheDocument()
    expect(screen.getByText('$ echo ALICE-$((6*7))')).toBeInTheDocument()
  })

  test('a failed read with nothing listed keeps the terminal and says the list was not refreshed', async () => {
    const { onInteract, answer } = deferredInteract()
    const { container, rerender } = render(panel([ROW], { onInteract }))
    await sendCommand(container)
    rerender(panel([], { onInteract, error: 'Failed to fetch sessions (agent_timeout · HTTP 504)' }))
    expect(screen.queryByText('Could not load sessions')).toBeNull()
    expect(screen.getByRole('alert')).toHaveTextContent('Not refreshed: Failed to fetch sessions (agent_timeout · HTTP 504)')
    await answer('ALICE-42')
    expect(screen.getByText('ALICE-42')).toBeInTheDocument()
  })

  test('a terminal whose row is no longer listed can be closed; then the empty state shows', async () => {
    const { container, rerender } = render(panel([ROW]))
    await sendCommand(container, 'id')
    rerender(panel([]))
    fireEvent.click(screen.getByRole('button', { name: 'Close terminal' }))
    expect(screen.getByText('No Reverse Shells')).toBeInTheDocument()
    expect(screen.queryByPlaceholderText('Type a command...')).toBeNull()
  })

  test('killing the selected row closes it; with nothing left the empty state shows', async () => {
    const onKillSession = vi.fn(async () => {})
    const { container, rerender } = render(panel([ROW], { onKillSession }))
    fireEvent.click(container.querySelector('[data-session-key="b0b001:1"]')!)
    fireEvent.click(screen.getByTitle('Kill session'))
    await waitFor(() => expect(onKillSession).toHaveBeenCalledWith({ id: 1, sandbox: 'b0b001' }))
    rerender(panel([], { onKillSession }))
    await waitFor(() => expect(screen.getByText('No Reverse Shells')).toBeInTheDocument())
  })
})

describe('a command still running when its answer came (S16b review round 4)', () => {
  // A contended interact reads only what its budget left, so the agent answers before giving up:
  // the session manager returns what it read with `still_running: true`.
  test('shows what was read, then says the rest will not be shown', async () => {
    const { onInteract, answer } = deferredInteract()
    const { container } = render(panel([ROW], { onInteract }))
    await sendCommand(container, 'sleep 15')
    await act(async () => { answer('GHOSTB-0') })
    expect(screen.getByText('GHOSTB-0')).toBeInTheDocument()
    expect(screen.queryByText(/still running in the session/)).toBeNull()
  })

  test('a still-running answer adds the line, in the terminal\'s own words', async () => {
    let resolve!: (v: unknown) => void
    const onInteract = vi.fn(() => new Promise(r => { resolve = r }))
    const { container } = render(panel([ROW], { onInteract }))
    await sendCommand(container, 'sleep 15')
    await act(async () => { resolve({ busy: false, output: 'GHOSTB-0\nGHOSTB-1', still_running: true }) })
    expect(screen.getByText(/GHOSTB-1/)).toBeInTheDocument()
    expect(screen.getByText('The command is still running in the session; its remaining output will not be shown')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('Type a command...')).toBeEnabled()
  })
})

describe('a session that ended (S16b review 5)', () => {
  const OTHER = { ...ROW, id: 2, info: 'other' }

  test('a complete answer without the selected row says the session ended and disables the input', async () => {
    const { container, rerender } = render(panel([ROW, OTHER]))
    await sendCommand(container, 'id')
    rerender(panel([OTHER]))
    expect(screen.getByText('Session ended')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('Type a command...')).toBeDisabled()
    expect(screen.getByText('$ id')).toBeInTheDocument()
    rerender(panel([]))
    expect(screen.getByText('Session ended')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Close terminal' }))
    expect(screen.getByText('No Reverse Shells')).toBeInTheDocument()
  })

  test('a partial answer or a failed read proves nothing: the input stays enabled', async () => {
    const { container, rerender } = render(panel([ROW]))
    await sendCommand(container, 'id')
    rerender(panel([], { unavailable: 1 }))
    expect(screen.queryByText('Session ended')).toBeNull()
    expect(screen.getByPlaceholderText('Type a command...')).toBeEnabled()
    rerender(panel([], { error: 'Failed to fetch sessions (agent_timeout · HTTP 504)' }))
    expect(screen.queryByText('Session ended')).toBeNull()
    expect(screen.getByPlaceholderText('Type a command...')).toBeEnabled()
  })

  test('a row that is listed again takes its input back', async () => {
    const { container, rerender } = render(panel([ROW]))
    await sendCommand(container, 'id')
    rerender(panel([]))
    expect(screen.getByPlaceholderText('Type a command...')).toBeDisabled()
    rerender(panel([ROW]))
    expect(screen.queryByText('Session ended')).toBeNull()
    expect(screen.getByPlaceholderText('Type a command...')).toBeEnabled()
  })
})

describe('a kill in progress (S16b review round 3)', () => {
  // The hook hides a row at once when its kill starts; while the kill waits for the console the
  // terminal must say "Killing…", never that the session ended.
  function pendingKill() {
    let settle!: (fail?: Error) => void
    const onKillSession = vi.fn(() => new Promise<void>((resolve, reject) => { settle = (fail) => (fail ? reject(fail) : resolve()) }))
    return { onKillSession, settle: (fail?: Error) => act(async () => { settle(fail) }) }
  }

  test('the selected row being killed says "Killing…", not "Session ended"; once killed the panel empties', async () => {
    const { onKillSession, settle } = pendingKill()
    const { container, rerender } = render(panel([ROW], { onKillSession }))
    fireEvent.click(container.querySelector('[data-session-key="b0b001:1"]')!)
    fireEvent.click(screen.getByTitle('Kill session'))
    rerender(panel([], { onKillSession }))
    expect(screen.getByText('Killing…')).toBeInTheDocument()
    expect(screen.queryByText('Session ended')).toBeNull()
    expect(screen.getByPlaceholderText('Type a command...')).toBeDisabled()
    await settle()
    expect(screen.getByText('No Reverse Shells')).toBeInTheDocument()
  })

  test('a kill that failed (the console was busy) gives the row and its input back', async () => {
    const { onKillSession, settle } = pendingKill()
    const { container, rerender } = render(panel([ROW], { onKillSession }))
    fireEvent.click(container.querySelector('[data-session-key="b0b001:1"]')!)
    fireEvent.click(screen.getByTitle('Kill session'))
    rerender(panel([], { onKillSession }))
    await settle(new Error('Session 1 was not killed: the Kali console is busy with another command, try again'))
    rerender(panel([ROW], { onKillSession }))
    expect(screen.queryByText('Killing…')).toBeNull()
    expect(screen.queryByText('Session ended')).toBeNull()
    expect(screen.getByPlaceholderText('Type a command...')).toBeEnabled()
  })
})

describe('the empty state', () => {
  test('nothing selected and nothing listed: as before, with the partial line or the error', () => {
    const { rerender } = render(panel([], { unavailable: 1 }))
    expect(screen.getByText('No Reverse Shells')).toBeInTheDocument()
    expect(screen.getByText('1 sandbox did not answer; its sessions may be out of date or missing')).toBeInTheDocument()
    rerender(panel([], { error: 'Failed to fetch sessions (agent_unreachable · HTTP 503)' }))
    expect(screen.getByText('Could not load sessions')).toBeInTheDocument()
  })
})

describe('a row kept from an earlier answer', () => {
  test('says it was not refreshed, and stays selectable', async () => {
    const { container } = render(panel([{ ...ROW, staleSince: 1_000 }], { unavailable: 1 }))
    const card = container.querySelector('[data-session-key="b0b001:1"]') as HTMLElement
    expect(card).toHaveTextContent('not refreshed')
    fireEvent.click(card)
    expect(screen.getByPlaceholderText('Type a command...')).toBeInTheDocument()
  })

  test('a listed row says nothing of the kind', () => {
    const { container } = render(panel([ROW]))
    expect(container.querySelector('[data-session-key="b0b001:1"]')).not.toHaveTextContent('not refreshed')
  })
})
