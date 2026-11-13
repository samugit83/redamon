/**
 * Regression tests for session restore de-duplication.
 *
 * Run: npx vitest run --no-file-parallelism \
 *   src/app/graph/components/AIAssistantDrawer/hooks/useConversationRestoration.test.tsx
 *
 * The bug being defended: on reload, the restore path collapsed legitimately
 * repeated tool calls / thoughts because it de-duped by CONTENT fingerprint
 * (tool_name+args, raw_output[:500], thought[:200]) within a 60s window - even
 * though the live stream (and the DB) correctly kept both. Result: a tool card
 * silently vanished on reload, leaving two adjacent thinking cards.
 *
 * The fix pairs tool_start<->tool_complete by identity (step_id, else per-name
 * FIFO) and renders every persisted row. These tests craft the exact shapes the
 * old code dropped and assert they now survive.
 */

import { describe, test, expect, vi, beforeEach } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { useConversationRestoration } from './useConversationRestoration'
import type { ChatItem } from '../types'

// Capture whatever the hook hands to setChatItems (non-resync path passes the
// fully-built array directly).
function makeDeps(captured: { items: ChatItem[] }, full: any) {
  return {
    loadConversation: vi.fn(async () => full),
    deleteConversation: vi.fn(async () => {}),
    fetchConversations: vi.fn(async () => []),
    onSwitchSession: vi.fn(),
    onRefetchGraph: vi.fn(),
    projectId: 'p1',
    userId: 'u1',
    setChatItems: vi.fn((v: any) => { captured.items = typeof v === 'function' ? v([]) : v }),
    setCurrentPhase: vi.fn(),
    setAttackPathType: vi.fn(),
    setIterationCount: vi.fn(),
    setIsLoading: vi.fn(),
    setIsStopped: vi.fn(),
    setTodoList: vi.fn(),
    isRestoringConversation: { current: false },
    shouldAutoScroll: { current: false },
    setAwaitingApproval: vi.fn(),
    setApprovalRequest: vi.fn(),
    setAwaitingQuestion: vi.fn(),
    setQuestionRequest: vi.fn(),
    setAwaitingToolConfirmation: vi.fn(),
    setToolConfirmationRequest: vi.fn(),
    awaitingApprovalRef: { current: false },
    awaitingQuestionRef: { current: false },
    awaitingToolConfirmationRef: { current: false },
    pendingApprovalToolId: { current: null },
    pendingApprovalWaveId: { current: null },
    setActiveSkill: vi.fn(),
    updateConvMeta: vi.fn(async () => {}),
    handleNewChat: vi.fn(),
  } as any
}

const conv = { id: 'c1', sessionId: 's1', currentPhase: 'exploitation', iterationCount: 1, agentRunning: false } as any

let t = 0
const at = () => new Date(1700000000000 + (t += 1000)).toISOString()   // +1s each call, well under 60s

const start = (tool_name: string, tool_args: any, extra: any = {}) =>
  ({ id: `ts-${t}`, type: 'tool_start', data: { tool_name, tool_args, ...extra }, createdAt: at() })
const complete = (tool_name: string, raw_output: string, extra: any = {}) =>
  ({ id: `tc-${t}`, type: 'tool_complete', data: { tool_name, success: true, output_summary: 'ok', raw_output, ...extra }, createdAt: at() })
const think = (thought: string) =>
  ({ id: `th-${t}`, type: 'thinking', data: { thought, reasoning: '' }, createdAt: at() })

async function restore(messages: any[], captured: { items: ChatItem[] }, convOverrides: any = {}) {
  const c = { ...conv, ...convOverrides }
  const full = { ...c, messages }
  const { result } = renderHook(() => useConversationRestoration(makeDeps(captured, full)))
  await act(async () => { await result.current.handleSelectConversation(c) })
}

const tools = (items: ChatItem[]) => items.filter(i => (i as any).type === 'tool_execution')
const thinks = (items: ChatItem[]) => items.filter(i => (i as any).type === 'thinking')

beforeEach(() => { t = 0; vi.stubGlobal('fetch', vi.fn(async () => ({ ok: false }))) })

describe('useConversationRestoration - repeated tool/thought survival', () => {
  test('two IDENTICAL legacy tool calls (no step_id) both survive (was: 2nd dropped)', async () => {
    const cap = { items: [] as ChatItem[] }
    await restore([
      start('execute_curl', { u: '/' }),
      complete('execute_curl', 'AAA'),
      start('execute_curl', { u: '/' }),   // identical args, <60s later
      complete('execute_curl', 'AAA'),     // identical output
    ], cap)
    // Old content-fingerprint dedup collapsed this to ONE card. Must be TWO now.
    expect(tools(cap.items)).toHaveLength(2)
    expect(tools(cap.items).every(t => (t as any).status === 'success')).toBe(true)
  })

  test('repeated identical tools pair exactly by step_id', async () => {
    const cap = { items: [] as ChatItem[] }
    await restore([
      start('execute_curl', { u: '/a' }, { step_id: 'S1' }),
      start('execute_curl', { u: '/a' }, { step_id: 'S2' }),
      complete('execute_curl', 'out1', { step_id: 'S1' }),
      complete('execute_curl', 'out2', { step_id: 'S2' }),
    ], cap)
    expect(tools(cap.items)).toHaveLength(2)
  })

  test('two distinct thoughts sharing a 200-char prefix both survive (was: 2nd dropped)', async () => {
    const prefix = 'X'.repeat(220)
    const cap = { items: [] as ChatItem[] }
    await restore([think(prefix + ' ALPHA'), think(prefix + ' BETA')], cap)
    expect(thinks(cap.items)).toHaveLength(2)
  })

  test('a still-running tool (start, no complete) renders as one running card', async () => {
    const cap = { items: [] as ChatItem[] }
    await restore([
      start('execute_code', { code: 'x' }),
      complete('execute_code', 'done'),
      start('execute_code', { code: 'y' }),   // running, no complete yet
    ], cap, { agentRunning: true })
    const ts = tools(cap.items)
    expect(ts).toHaveLength(2)
    expect(ts.filter(x => (x as any).status === 'running')).toHaveLength(1)
    expect(ts.filter(x => (x as any).status === 'success')).toHaveLength(1)
  })

  test('normal single tool restores as exactly one success card (no regression)', async () => {
    const cap = { items: [] as ChatItem[] }
    await restore([start('execute_httpx', { u: 'x' }), complete('execute_httpx', 'r')], cap)
    expect(tools(cap.items)).toHaveLength(1)
    expect((tools(cap.items)[0] as any).status).toBe('success')
  })
})

// ---------------------------------------------------------------------------
// "Agent stuck" incident: cards that kept "Running" after the run had ended,
// and a reconnected page that never caught up with what it missed.
// ---------------------------------------------------------------------------

const finished = (tool_name: string, extra: any = {}) =>
  ({ id: `tf-${t}`, type: 'tool_finished', data: { tool_name, success: true, duration_ms: 12000, ...extra }, createdAt: at() })

describe('useConversationRestoration - run state after the run ended', () => {
  test('a tool cut off by Stop restores as interrupted, not as a ticking running card', async () => {
    const cap = { items: [] as ChatItem[] }
    await restore([start('execute_code', { code: 'x' }, { step_id: 'S1' })], cap, { agentRunning: false })
    const [card] = tools(cap.items) as any[]
    expect(card.status).toBe('error')
    expect(card.interrupted).toBe(true)
    expect(card.step_id).toBe('S1')
  })

  test('a tool that returned before its analysis restores as finished while the run goes on', async () => {
    const cap = { items: [] as ChatItem[] }
    await restore([
      start('tradecraft_lookup', { cve_id: 'CVE-2026-109618' }, { step_id: 'S1' }),
      finished('tradecraft_lookup', { step_id: 'S1' }),
    ], cap, { agentRunning: true })
    const [card] = tools(cap.items) as any[]
    expect(card.status).toBe('running')
    expect(card.finished).toBe(true)
    expect(card.finishedSuccess).toBe(true)
    expect(card.duration).toBe(12000)
  })

  test('a returned tool in a run that is over keeps the tool verdict, not "interrupted"', async () => {
    const cap = { items: [] as ChatItem[] }
    await restore([
      start('execute_curl', { u: '/' }, { step_id: 'S1' }),
      finished('execute_curl', { step_id: 'S1', success: false }),
    ], cap, { agentRunning: false })
    const [card] = tools(cap.items) as any[]
    expect(card.status).toBe('error')
    expect(card.interrupted).toBeFalsy()
  })

  test('tool_finished rows do not render as cards of their own', async () => {
    const cap = { items: [] as ChatItem[] }
    await restore([
      start('execute_curl', { u: '/' }, { step_id: 'S1' }),
      finished('execute_curl', { step_id: 'S1' }),
      complete('execute_curl', 'out', { step_id: 'S1' }),
    ], cap)
    expect(tools(cap.items)).toHaveLength(1)
    expect((tools(cap.items)[0] as any).status).toBe('success')
  })
})

describe('useConversationRestoration - reconnect resync for a session started in this tab', () => {
  function mount(full: any) {
    const cap = { items: [] as ChatItem[] }
    const deps = makeDeps(cap, full)
    deps.setIsStopping = vi.fn()
    const hook = renderHook(() => useConversationRestoration(deps))
    return { cap, deps, hook }
  }

  test('server says the run is over: re-read, stop the spinner, settle the stuck card', async () => {
    const full = { ...conv, agentRunning: true, messages: [
      start('execute_code', { code: 'x' }, { step_id: 'S1' }),
    ] }
    const { cap, deps, hook } = mount(full)
    act(() => { hook.result.current.setConversationId('c1') })
    await act(async () => {
      await hook.result.current.resyncActiveConversation('s1', { agentRunning: false, clientRunning: true })
    })
    expect(deps.loadConversation).toHaveBeenCalledWith('c1')
    expect(deps.setIsLoading).toHaveBeenLastCalledWith(false)
    expect(deps.setIsStopping).toHaveBeenLastCalledWith(false)
    const [card] = tools(cap.items) as any[]
    expect(card.interrupted).toBe(true)
  })

  test('server says the run goes on: re-read and keep the spinner', async () => {
    const full = { ...conv, agentRunning: true, messages: [
      start('execute_code', { code: 'x' }, { step_id: 'S1' }),
    ] }
    const { cap, deps, hook } = mount(full)
    act(() => { hook.result.current.setConversationId('c1') })
    await act(async () => {
      await hook.result.current.resyncActiveConversation('s1', { agentRunning: true, clientRunning: false })
    })
    expect(deps.setIsLoading).toHaveBeenLastCalledWith(true)
    expect((tools(cap.items)[0] as any).status).toBe('running')
  })

  test('idle page and idle server: no needless DB read', async () => {
    const { deps, hook } = mount({ ...conv, messages: [] })
    act(() => { hook.result.current.setConversationId('c1') })
    await act(async () => {
      await hook.result.current.resyncActiveConversation('s1', { agentRunning: false, clientRunning: false })
    })
    expect(deps.loadConversation).not.toHaveBeenCalled()
  })

  test('an older agent without agent_running keeps the history-restore behaviour only', async () => {
    const { deps, hook } = mount({ ...conv, messages: [] })
    act(() => { hook.result.current.setConversationId('c1') })
    await act(async () => { await hook.result.current.resyncActiveConversation('s1', {}) })
    expect(deps.loadConversation).not.toHaveBeenCalled()
  })

  test('nothing persisted yet: the spinner still stops when the server is idle', async () => {
    const { cap, deps, hook } = mount({ ...conv, messages: [] })
    await act(async () => {
      await hook.result.current.resyncActiveConversation('s1', { agentRunning: false, clientRunning: true })
    })
    expect(deps.loadConversation).not.toHaveBeenCalled()
    expect(deps.setIsLoading).toHaveBeenLastCalledWith(false)
    expect(cap.items).toEqual([])
  })
})

describe('useConversationRestoration - events that arrive while the resync reads the DB', () => {
  test('a STOPPED during the read wins: the spinner is not turned back on, the card settles', async () => {
    const full = { ...conv, agentRunning: true, messages: [
      start('execute_code', { code: 'x' }, { step_id: 'S1' }),
    ] }
    const cap = { items: [] as ChatItem[] }
    const deps = makeDeps(cap, full)
    deps.setIsStopping = vi.fn()
    let resolveLoad!: (v: unknown) => void
    deps.loadConversation = vi.fn(() => new Promise(r => { resolveLoad = r }))
    let pageRunning = true
    const hook = renderHook(() => useConversationRestoration(deps))
    act(() => { hook.result.current.setConversationId('c1') })

    let pending!: Promise<void>
    act(() => {
      pending = hook.result.current.resyncActiveConversation('s1', {
        agentRunning: true, clientRunning: true, isRunActive: () => pageRunning,
      })
    })
    expect(deps.setIsLoading.mock.calls).toEqual([[true]])   // applied at CONNECTED

    pageRunning = false   // STOPPED arrives over the socket while the DB read is in flight
    await act(async () => { resolveLoad(full); await pending })

    expect(deps.setIsLoading.mock.calls).toEqual([[true]])   // never re-applied after the read
    const [card] = tools(cap.items) as any[]
    expect(card.interrupted).toBe(true)
  })
})

describe('useConversationRestoration - failures the person is told about (G-10, G-18)', () => {
  test('a failed delete keeps the chat on screen', async () => {
    const deps = makeDeps({ items: [] }, { ...conv, messages: [] })
    deps.deleteConversation = vi.fn(async () => false)
    const hook = renderHook(() => useConversationRestoration(deps))
    act(() => { hook.result.current.setConversationId('c1') })
    await act(async () => { await hook.result.current.handleDeleteConversation('c1') })
    expect(deps.handleNewChat).not.toHaveBeenCalled()
    expect(deps.onRefetchGraph).not.toHaveBeenCalled()
  })

  test('a delete that went through still clears the chat', async () => {
    const deps = makeDeps({ items: [] }, { ...conv, messages: [] })
    deps.deleteConversation = vi.fn(async () => true)
    const hook = renderHook(() => useConversationRestoration(deps))
    act(() => { hook.result.current.setConversationId('c1') })
    await act(async () => { await hook.result.current.handleDeleteConversation('c1') })
    expect(deps.handleNewChat).toHaveBeenCalled()
  })

  test('a project switch whose session list fails says so before opening a fresh chat', async () => {
    const { saveProjectSession } = await import('../sessionMemory')
    saveProjectSession('p1', 'c1')
    const { ApiError } = await import('@/lib/apiError')
    const deps = makeDeps({ items: [] }, { ...conv, messages: [] })
    deps.fetchConversations = vi.fn(async () => new ApiError({ reason: 'Failed to fetch conversations', status: 500, code: 'P1001' }))
    deps.notifyError = vi.fn()
    const hook = renderHook(() => useConversationRestoration(deps))
    await act(async () => { await hook.result.current.restoreForProject() })
    expect(deps.notifyError).toHaveBeenCalledWith('Could not reopen your last session: Failed to fetch conversations (P1001 · HTTP 500)')
    expect(deps.handleNewChat).toHaveBeenCalled()
  })
})

describe('useConversationRestoration - download cards keep their project (4.9 review)', () => {
  const fileReady = (data: any) => ({ id: `fr-${t}`, type: 'file_ready', data, createdAt: at() })
  const files = (items: ChatItem[]) => items.filter(i => (i as any).type === 'file_download')

  test('a card the agent saved with its project restores with it, so it can download', async () => {
    const cap = { items: [] as ChatItem[] }
    await restore([fileReady({
      filepath: '/workspace/p1/notes/payload.exe', filename: 'payload.exe', source: 'msfvenom',
      description: 'Generated payload: payload.exe', projectId: 'p1',
    })], cap)
    expect(files(cap.items)).toHaveLength(1)
    expect((files(cap.items)[0] as any).projectId).toBe('p1')
  })

  test('a card from before (a /tmp file, no project) restores without one', async () => {
    const cap = { items: [] as ChatItem[] }
    await restore([fileReady({ filepath: '/tmp/payload.exe', filename: 'payload.exe', source: 'msfvenom', description: 'd' })], cap)
    expect(files(cap.items)).toHaveLength(1)
    expect((files(cap.items)[0] as any).projectId).toBeUndefined()
  })
})
