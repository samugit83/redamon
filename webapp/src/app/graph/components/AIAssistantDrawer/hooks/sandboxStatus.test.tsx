/**
 * The chat drawer and the run's Kali sandbox (group 1, WI-S15-3): `starting`
 * shows "Starting your Kali sandbox…" in place of the loading word, `ready`
 * clears it, and `unavailable` shows the modal once per run. A frame counts only
 * while a run is in flight. Retry sends the run's query again, under the text the
 * person saw when the run started, and only once that run has ended; for
 * `refused` there is no Retry at all.
 *
 * Run: npx vitest run --no-file-parallelism src/app/graph/components/AIAssistantDrawer/hooks/sandboxStatus.test.tsx
 */
import React from 'react'
import { describe, test, expect, afterEach, vi } from 'vitest'
import { act, cleanup, fireEvent, render, renderHook, screen, waitFor, within } from '@testing-library/react'
import { AlertProvider } from '@/components/ui'
import { MessageType, type ServerMessage } from '@/lib/websocket-types'
import {
  MODAL_CLOSE_LABEL,
  MODAL_RAM_TITLE,
  MODAL_REFUSED_TITLE,
  MODAL_RETRY_LABEL,
  SANDBOX_STATUS,
} from '@/lib/sandbox/contract'
import { useSandboxUnavailable } from '@/hooks/useSandboxUnavailable'
import { useWebSocketHandler } from './useWebSocketHandler'
import { SANDBOX_STARTING_WORD, sandboxStatusFromPayload, useSandboxStatus } from './sandboxStatus'

afterEach(cleanup)

const RAM = { state: 'unavailable', reason: 'ram', limit: {
  admitted: false, limitType: 'ram', resource: 'kali_sandbox', current: 1024 ** 3, ceiling: 8 * 1024 ** 3,
  settingName: null, detail: 'not enough free memory to start a Kali sandbox now',
} }

type Opts = Parameters<typeof useSandboxStatus>[0]
type Answer = 'retry' | 'close'

/** A modal the test answers when it wants, after moving the run along. */
function deferredModal() {
  let answer: (a: Answer) => void = () => {}
  const show = vi.fn(() => new Promise<Answer>(r => { answer = r }))
  return { show, answer: (a: Answer) => answer(a) }
}

function hook(over: Partial<Opts> = {}) {
  const run = { ended: false }
  const opts: Opts = {
    isLoading: true,
    sessionId: 's1',
    projectId: 'p1',
    showUnavailable: vi.fn().mockResolvedValue('close'),
    runEnded: () => run.ended,
    resend: vi.fn(),
    ...over,
  }
  const h = renderHook((p: Opts) => useSandboxStatus(p), { initialProps: opts })
  return { ...h, opts, run }
}

describe('the event', () => {
  test('the TS value is the contract value', () => {
    expect(MessageType.SANDBOX_STATUS).toBe(SANDBOX_STATUS)
  })

  test('only the three states pass; a bad payload is dropped', () => {
    expect(sandboxStatusFromPayload({ state: 'starting' })).toEqual({ state: 'starting' })
    expect(sandboxStatusFromPayload(RAM)).toMatchObject({ state: 'unavailable', reason: 'ram' })
    expect(sandboxStatusFromPayload({ state: 'running' })).toBeNull()
    expect(sandboxStatusFromPayload(null)).toBeNull()
    expect(sandboxStatusFromPayload('starting')).toBeNull()
  })

  test("the handler hands the frame's payload to the drawer", () => {
    const onSandboxStatus = vi.fn()
    const noop = vi.fn()
    const ref = <T,>(v: T) => ({ current: v })
    const { result } = renderHook(() => useWebSocketHandler({
      setChatItems: noop, setIsLoading: noop, setIsStopped: noop, setIsStopping: noop,
      setCurrentPhase: noop, setIterationCount: noop, setAttackPathType: noop, setTodoList: noop,
      todoList: [], itemIdCounter: ref(0),
      setAwaitingApproval: noop, setApprovalRequest: noop, setAwaitingQuestion: noop, setQuestionRequest: noop,
      setAwaitingToolConfirmation: noop, setToolConfirmationRequest: noop,
      awaitingApprovalRef: ref(false), isProcessingApproval: ref(false),
      awaitingQuestionRef: ref(false), isProcessingQuestion: ref(false),
      awaitingToolConfirmationRef: ref(false), isProcessingToolConfirmation: ref(false),
      pendingApprovalToolId: ref<string | null>(null), pendingApprovalWaveId: ref<string | null>(null),
      answerUndo: ref({ approval: null, question: null, toolConfirmation: null, fireteam: {} }),
      onSandboxStatus,
    }))
    const msg: ServerMessage = { type: MessageType.SANDBOX_STATUS, payload: { state: 'starting' }, timestamp: '' }
    result.current.handleWebSocketMessage(msg)
    expect(onSandboxStatus).toHaveBeenCalledWith({ state: 'starting' })
    expect(noop).not.toHaveBeenCalled()
  })
})

describe('the status line', () => {
  test('starting shows the line; ready clears it', () => {
    const { result } = hook()
    act(() => result.current.onSandboxStatus({ state: 'starting' }))
    expect(result.current.sandboxWord).toBe(SANDBOX_STARTING_WORD)
    act(() => result.current.onSandboxStatus({ state: 'ready' }))
    expect(result.current.sandboxWord).toBeNull()
  })

  test('unavailable clears it', () => {
    const { result } = hook()
    act(() => result.current.onSandboxStatus({ state: 'starting' }))
    act(() => result.current.onSandboxStatus(RAM))
    expect(result.current.sandboxWord).toBeNull()
  })

  test('it never outlives the loading state, the session or the project', () => {
    const { result, rerender, opts } = hook()
    act(() => result.current.onSandboxStatus({ state: 'starting' }))
    rerender({ ...opts, isLoading: false })
    expect(result.current.sandboxWord).toBeNull()
    rerender({ ...opts, isLoading: true })
    act(() => result.current.onSandboxStatus({ state: 'starting' }))
    rerender({ ...opts, sessionId: 's2' })
    expect(result.current.sandboxWord).toBeNull()
    act(() => result.current.onSandboxStatus({ state: 'starting' }))
    rerender({ ...opts, sessionId: 's2', projectId: 'p2' })
    expect(result.current.sandboxWord).toBeNull()
  })

  test('a new run starts without the last run\'s line', () => {
    const { result } = hook()
    act(() => result.current.onSandboxStatus({ state: 'starting' }))
    act(() => result.current.noteRunStart('next question', 'next question'))
    expect(result.current.sandboxWord).toBeNull()
  })

  test('a starting frame while no run is in flight is dropped, so the next run does not inherit it', () => {
    const { result, run } = hook({ isLoading: false })
    run.ended = true
    act(() => result.current.onSandboxStatus({ state: 'starting' }))
    expect(result.current.sandboxWord).toBeNull()
  })
})

describe('the modal', () => {
  test('shown once per run, and again in the next run', () => {
    const showUnavailable = vi.fn().mockResolvedValue('close')
    const { result } = hook({ showUnavailable })
    act(() => result.current.noteRunStart('scan it', 'scan it'))
    act(() => result.current.onSandboxStatus(RAM))
    act(() => result.current.onSandboxStatus(RAM))
    act(() => result.current.onSandboxStatus({ ...RAM, reason: 'error' }))
    expect(showUnavailable).toHaveBeenCalledTimes(1)
    expect(showUnavailable).toHaveBeenCalledWith(expect.objectContaining({ state: 'unavailable', reason: 'ram' }))
    act(() => result.current.noteRunStart('scan it again', 'scan it again'))
    act(() => result.current.onSandboxStatus(RAM))
    expect(showUnavailable).toHaveBeenCalledTimes(2)
  })

  test('starting and ready never show it', () => {
    const showUnavailable = vi.fn().mockResolvedValue('close')
    const { result } = hook({ showUnavailable })
    act(() => result.current.onSandboxStatus({ state: 'starting' }))
    act(() => result.current.onSandboxStatus({ state: 'ready' }))
    expect(showUnavailable).not.toHaveBeenCalled()
  })

  test('a frame that arrives after the run ended shows nothing and sends nothing', async () => {
    const resend = vi.fn()
    const showUnavailable = vi.fn().mockResolvedValue('retry')
    const { result, run } = hook({ resend, showUnavailable, isLoading: false })
    act(() => result.current.noteRunStart('enumerate the lab host', 'enumerate the lab host'))
    run.ended = true
    await act(async () => { result.current.onSandboxStatus({ state: 'unavailable', reason: 'stopped' }) })
    expect(showUnavailable).not.toHaveBeenCalled()
    expect(resend).not.toHaveBeenCalled()
  })

  test('Retry once the run has ended sends the query again, under the text shown when the run started', async () => {
    const resend = vi.fn()
    const modal = deferredModal()
    const { result, run } = hook({ resend, showUnavailable: modal.show })
    const sent = '[Chat Skill Context]\nskill text\n\n[User Query]\nscan 10.0.0.0/8'
    act(() => result.current.noteRunStart(sent, 'scan 10.0.0.0/8'))
    act(() => result.current.onSandboxStatus(RAM))
    expect(modal.show).toHaveBeenCalledTimes(1)
    run.ended = true
    await act(async () => { modal.answer('retry') })
    expect(resend).toHaveBeenCalledWith(sent, 'scan 10.0.0.0/8')
    expect(resend).toHaveBeenCalledTimes(1)
  })

  test('a resume keeps the run\'s query and text', async () => {
    const resend = vi.fn()
    const modal = deferredModal()
    const { result, run } = hook({ resend, showUnavailable: modal.show })
    act(() => result.current.noteRunStart('scan the host', 'scan the host'))
    act(() => result.current.noteRunStart())
    act(() => result.current.onSandboxStatus(RAM))
    run.ended = true
    await act(async () => { modal.answer('retry') })
    expect(resend).toHaveBeenCalledWith('scan the host', 'scan the host')
  })

  test('Retry while the run is still going only closes', async () => {
    const resend = vi.fn()
    const modal = deferredModal()
    const { result } = hook({ resend, showUnavailable: modal.show })
    act(() => result.current.noteRunStart('scan', 'scan'))
    act(() => result.current.onSandboxStatus(RAM))
    await act(async () => { modal.answer('retry') })
    expect(resend).not.toHaveBeenCalled()
  })

  test('Retry after the session changed sends nothing', async () => {
    const resend = vi.fn()
    const modal = deferredModal()
    const { result, rerender, opts, run } = hook({ resend, showUnavailable: modal.show })
    act(() => result.current.noteRunStart('scan', 'scan'))
    act(() => result.current.onSandboxStatus(RAM))
    rerender({ ...opts, sessionId: 's2' })
    run.ended = true
    await act(async () => { modal.answer('retry') })
    expect(resend).not.toHaveBeenCalled()
  })

  test('Retry after the project changed sends nothing', async () => {
    const resend = vi.fn()
    const modal = deferredModal()
    const { result, rerender, opts, run } = hook({ resend, showUnavailable: modal.show })
    act(() => result.current.noteRunStart('scan', 'scan'))
    act(() => result.current.onSandboxStatus(RAM))
    rerender({ ...opts, projectId: 'p2' })
    run.ended = true
    await act(async () => { modal.answer('retry') })
    expect(resend).not.toHaveBeenCalled()
  })

  test('refused never sends again, whatever the answer', async () => {
    const resend = vi.fn()
    const modal = deferredModal()
    const { result, run } = hook({ resend, showUnavailable: modal.show })
    act(() => result.current.noteRunStart('scan', 'scan'))
    act(() => result.current.onSandboxStatus({ state: 'unavailable', reason: 'refused' }))
    expect(modal.show).toHaveBeenCalledWith(expect.objectContaining({ reason: 'refused' }))
    run.ended = true
    await act(async () => { modal.answer('retry') })
    expect(resend).not.toHaveBeenCalled()
  })

  test('no query known (a run this tab did not start): Retry only closes', async () => {
    const resend = vi.fn()
    const modal = deferredModal()
    const { result, run } = hook({ resend, showUnavailable: modal.show })
    act(() => result.current.onSandboxStatus(RAM))
    expect(modal.show).toHaveBeenCalledTimes(1)
    run.ended = true
    await act(async () => { modal.answer('retry') })
    expect(resend).not.toHaveBeenCalled()
  })
})

// The handler, the drawer hook and the real modal together, as the drawer wires them.
function DrawerHarness({ onWord, resend, run }: {
  onWord: (w: string | null) => void
  resend: (q: string, shown: string) => void
  run: { ended: boolean }
}) {
  const showUnavailable = useSandboxUnavailable()
  const sandbox = useSandboxStatus({
    isLoading: true, sessionId: 's1', projectId: 'p1', showUnavailable, runEnded: () => run.ended, resend,
  })
  const noop = () => {}
  const ref = <T,>(v: T) => ({ current: v })
  const refs = React.useRef({
    itemIdCounter: ref(0), a: ref(false), b: ref(false), c: ref(false), d: ref(false), e: ref(false), f: ref(false),
    tool: ref<string | null>(null), wave: ref<string | null>(null),
    undo: ref({ approval: null, question: null, toolConfirmation: null, fireteam: {} }),
  }).current
  const { handleWebSocketMessage } = useWebSocketHandler({
    setChatItems: noop, setIsLoading: noop, setIsStopped: noop, setIsStopping: noop,
    setCurrentPhase: noop, setIterationCount: noop, setAttackPathType: noop, setTodoList: noop,
    todoList: [], itemIdCounter: refs.itemIdCounter,
    setAwaitingApproval: noop, setApprovalRequest: noop, setAwaitingQuestion: noop, setQuestionRequest: noop,
    setAwaitingToolConfirmation: noop, setToolConfirmationRequest: noop,
    awaitingApprovalRef: refs.a, isProcessingApproval: refs.b, awaitingQuestionRef: refs.c,
    isProcessingQuestion: refs.d, awaitingToolConfirmationRef: refs.e, isProcessingToolConfirmation: refs.f,
    pendingApprovalToolId: refs.tool, pendingApprovalWaveId: refs.wave, answerUndo: refs.undo,
    onSandboxStatus: sandbox.onSandboxStatus,
  })
  onWord(sandbox.sandboxWord)
  const send = (payload: unknown) => handleWebSocketMessage({ type: MessageType.SANDBOX_STATUS, payload, timestamp: '' })
  return (
    <>
      <button type="button" onClick={() => sandbox.noteRunStart('enumerate the host', 'enumerate the host')}>run</button>
      <button type="button" onClick={() => send({ state: 'starting' })}>starting</button>
      <button type="button" onClick={() => send({ state: 'ready' })}>ready</button>
      <button type="button" onClick={() => send(RAM)}>ram</button>
      <button type="button" onClick={() => send({ state: 'unavailable', reason: 'refused' })}>refused</button>
    </>
  )
}

describe('the drawer, end to end', () => {
  function mount() {
    const words: (string | null)[] = []
    const resend = vi.fn()
    const run = { ended: false }
    render(<AlertProvider><DrawerHarness onWord={w => words.push(w)} resend={resend} run={run} /></AlertProvider>)
    return { words, resend, run, click: (name: string) => fireEvent.click(screen.getByRole('button', { name })) }
  }

  test('the status line comes and goes with the frames', () => {
    const { words, click } = mount()
    click('starting')
    expect(words.at(-1)).toBe(SANDBOX_STARTING_WORD)
    click('ready')
    expect(words.at(-1)).toBeNull()
  })

  test('two unavailable frames in one run: one modal; Retry after the run sends the query again', async () => {
    const { resend, run, click } = mount()
    click('run')
    click('ram')
    click('ram')
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText(MODAL_RAM_TITLE)).toBeInTheDocument()
    run.ended = true
    fireEvent.click(within(dialog).getByRole('button', { name: MODAL_RETRY_LABEL }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    await waitFor(() => expect(resend).toHaveBeenCalledWith('enumerate the host', 'enumerate the host'))
    expect(resend).toHaveBeenCalledTimes(1)
  })

  test('Close sends nothing', async () => {
    const { resend, run, click } = mount()
    click('run')
    click('ram')
    const dialog = await screen.findByRole('dialog')
    run.ended = true
    fireEvent.click(within(dialog).getByRole('button', { name: MODAL_CLOSE_LABEL }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(resend).not.toHaveBeenCalled()
  })

  test('refused: the refused modal, no Retry', async () => {
    const { resend, run, click } = mount()
    click('run')
    click('refused')
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText(MODAL_REFUSED_TITLE)).toBeInTheDocument()
    expect(within(dialog).queryByRole('button', { name: MODAL_RETRY_LABEL })).toBeNull()
    run.ended = true
    fireEvent.click(within(dialog).getByRole('button', { name: 'OK' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(resend).not.toHaveBeenCalled()
  })

  test('after the run, a frame raises no modal', async () => {
    const { resend, run, click } = mount()
    click('run')
    run.ended = true
    click('ram')
    await new Promise(r => setTimeout(r, 50))
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(resend).not.toHaveBeenCalled()
  })
})
