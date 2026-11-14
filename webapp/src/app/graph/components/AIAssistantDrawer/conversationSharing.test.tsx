/**
 * The drawer's side of conversation privacy and sharing (step 5.8; SH-22, T24):
 *   - the history names another person's session "by <author>" (or "(account deleted)"), marks it
 *     read-only and offers no delete; Share / Stop sharing on the viewer's own sessions only when allowed;
 *     the owner's "co-owners see every session" as a checkbox for the owner and a line for the others;
 *   - opening a read-only session shows its timeline without the composer: the socket leaves for a fresh
 *     session of the viewer's own, nothing is saved into it and it is not remembered as the project's session;
 *   - useConversations' share call; with write sharing off (no `access` in the list) nothing new shows.
 *
 * Run: npx vitest run --no-file-parallelism src/app/graph/components/AIAssistantDrawer/conversationSharing.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { useRef, useState } from 'react'
import { render, screen, fireEvent, renderHook, act, cleanup } from '@testing-library/react'
import { ConversationHistory, type ConversationSharingControls } from './ConversationHistory'
import { ReadOnlyConversationNotice } from './ReadOnlyConversationNotice'
import { useConversationRestoration } from './hooks/useConversationRestoration'
import { useSessionChangeReset } from './hooks/useSessionChangeReset'
import type { ChatItem } from './types'
import { useConversations, type Conversation } from '@/hooks/useConversations'

const base = {
  sessionId: 's', title: '', status: 'active', agentRunning: false, currentPhase: 'informational',
  iterationCount: 0, activeSkillId: '', createdAt: '2026-11-13T12:00:00Z', updatedAt: '2026-11-13T12:00:00Z',
}
const mine = (id: string, shared = false): Conversation =>
  ({ ...base, id, sessionId: `s-${id}`, title: id, access: { mine: true, readOnly: false, shared, by: null, authorDeleted: false } })
const theirs = (id: string, by: string): Conversation =>
  ({ ...base, id, sessionId: `s-${id}`, title: id, access: { mine: false, readOnly: true, shared: true, by, authorDeleted: false } })
const reassigned = (id: string, by: string): Conversation =>
  ({ ...base, id, sessionId: `s-${id}`, title: id, access: { mine: true, readOnly: true, shared: false, by, authorDeleted: true } })

function history(conversations: Conversation[], sharing: ConversationSharingControls | null = null) {
  const props = { onBack: vi.fn(), onSelect: vi.fn(), onDelete: vi.fn(), onNewChat: vi.fn() }
  render(<ConversationHistory conversations={conversations} currentSessionId="none" sharing={sharing} {...props} />)
  return props
}
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

const row = (title: string) => screen.getByText(title).closest('[class*="item"]') as HTMLElement

describe('the history (step 5.8)', () => {
  test("another person's shared session: by its author, read-only, no delete and no share", () => {
    history([theirs('their-session', 'Bob Writer')], { canShare: true, onShare: vi.fn(), policy: null })
    expect(screen.getByText('by Bob Writer')).toBeInTheDocument()
    expect(screen.getByText('Read-only')).toBeInTheDocument()
    expect(screen.queryByTitle('Delete session')).toBeNull()
    expect(screen.queryByLabelText('Share this session')).toBeNull()
  })

  test('a session reassigned from a deleted account: "(account deleted)", read-only, the owner may delete it', () => {
    history([reassigned('gone', 'Gina Gone')], { canShare: false, onShare: vi.fn(), policy: null })
    expect(screen.getByText('by Gina Gone (account deleted)')).toBeInTheDocument()
    expect(screen.getByText('Read-only')).toBeInTheDocument()
    expect(screen.getByTitle('Delete session')).toBeInTheDocument()
  })

  test('Share and Stop sharing on the viewer\'s own sessions, when agent:conversations_share is held', () => {
    const onShare = vi.fn()
    history([mine('private-one'), mine('shared-one', true)], { canShare: true, onShare, policy: null })
    fireEvent.click(screen.getByLabelText('Share this session'))
    expect(onShare).toHaveBeenCalledWith('private-one', true)
    fireEvent.click(screen.getByLabelText('Stop sharing this session'))
    expect(onShare).toHaveBeenCalledWith('shared-one', false)
    expect(screen.getByText('Shared')).toBeInTheDocument()
    expect(row('shared-one')).toBeTruthy()
  })

  test('no Share without the permission', () => {
    history([mine('private-one')], { canShare: false, onShare: vi.fn(), policy: null })
    expect(screen.queryByLabelText('Share this session')).toBeNull()
  })

  test("the owner's policy: a checkbox for the owner, a line for the others when on, nothing when off", () => {
    const onChange = vi.fn()
    const { unmount } = render(<ConversationHistory conversations={[]} currentSessionId="" onBack={vi.fn()} onSelect={vi.fn()}
      onDelete={vi.fn()} onNewChat={vi.fn()} sharing={{ canShare: true, onShare: vi.fn(), policy: { managersSeeAll: false, editable: true, onChange } }} />)
    fireEvent.click(screen.getByLabelText('Co-owners can read every session of this project'))
    expect(onChange).toHaveBeenCalledWith(true)
    unmount()
    history([], { canShare: true, onShare: vi.fn(), policy: { managersSeeAll: true, editable: false, onChange: vi.fn() } })
    expect(screen.getByText('The owner lets co-owners read every session of this project')).toBeInTheDocument()
    expect(screen.queryByRole('checkbox')).toBeNull()
  })

  test('write sharing off: a list without access shows exactly what it showed before', () => {
    const { ...plain } = mine('old-session')
    delete (plain as { access?: unknown }).access
    history([plain], null)
    expect(screen.getByTitle('Delete session')).toBeInTheDocument()
    expect(screen.queryByText('Read-only')).toBeNull()
    expect(screen.queryByText(/^by /)).toBeNull()
    expect(screen.queryByLabelText('Share this session')).toBeNull()
  })
})

describe('the read-only notice in place of the composer', () => {
  test('names the author and offers a new session of the viewer\'s own', () => {
    const onNewChat = vi.fn()
    render(<ReadOnlyConversationNotice view={{ conversationId: 'c1', by: 'Bob Writer', authorDeleted: false }} onNewChat={onNewChat} />)
    expect(screen.getByRole('status')).toHaveTextContent('Read-only session by Bob Writer.')
    fireEvent.click(screen.getByText('New session'))
    expect(onNewChat).toHaveBeenCalled()
  })

  test('a deleted author says it cannot be continued', () => {
    render(<ReadOnlyConversationNotice view={{ conversationId: 'c1', by: 'Gina Gone', authorDeleted: true }} onNewChat={vi.fn()} />)
    expect(screen.getByRole('status')).toHaveTextContent('by Gina Gone (account deleted)')
    expect(screen.getByRole('status')).toHaveTextContent('can be read but not continued')
  })
})

function deps(full: unknown) {
  return {
    loadConversation: vi.fn(async () => full),
    deleteConversation: vi.fn(async () => true),
    fetchConversations: vi.fn(async () => []),
    onSwitchSession: vi.fn(),
    onRefetchGraph: vi.fn(),
    projectId: 'p1',
    userId: 'u1',
    setChatItems: vi.fn(),
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
  } as never as Parameters<typeof useConversationRestoration>[0]
}

describe('opening a read-only session (step 5.8)', () => {
  beforeEach(() => { vi.stubGlobal('fetch', vi.fn(async () => ({ ok: false }))) })

  const message = { id: 'm1', type: 'user_message', data: { content: 'hello' }, createdAt: '2026-11-13T12:00:00Z' }

  test('the timeline shows, the socket leaves for a fresh session, nothing is saved into it or remembered', async () => {
    const conv = theirs('c-bob', 'Bob Writer')
    const d = deps({ ...conv, messages: [message], access: conv.access })
    const { result } = renderHook(() => useConversationRestoration(d))
    await act(async () => { await result.current.handleSelectConversation(conv) })
    expect(d.handleNewChat).toHaveBeenCalledTimes(1)
    expect(d.onSwitchSession).not.toHaveBeenCalled()
    expect(result.current.conversationId).toBeNull()
    expect(result.current.readOnlyView).toEqual({ conversationId: 'c-bob', by: 'Bob Writer', authorDeleted: false })
    expect((d.setChatItems as ReturnType<typeof vi.fn>).mock.calls.at(-1)?.[0]).toEqual([expect.objectContaining({ type: 'message', role: 'user' })])
    expect(d.updateConvMeta).not.toHaveBeenCalled()
    expect(d.setAwaitingApproval).not.toHaveBeenCalledWith(true)
  })

  test('the viewer\'s own session opens as before and clears a read-only view', async () => {
    const conv = mine('c-own')
    const d = deps({ ...conv, messages: [message] })
    const { result } = renderHook(() => useConversationRestoration(d))
    await act(async () => { await result.current.handleSelectConversation(theirs('c-bob', 'Bob')) })
    ;(d.loadConversation as ReturnType<typeof vi.fn>).mockResolvedValueOnce({ ...conv, messages: [message] })
    await act(async () => { await result.current.handleSelectConversation(conv) })
    expect(result.current.readOnlyView).toBeNull()
    expect(result.current.conversationId).toBe('c-own')
    expect(d.onSwitchSession).toHaveBeenCalledWith('s-c-own')
  })
})

// P5-07 (S4 red): the drawer clears its chat when the live session id changes, and opening a
// read-only session moves the socket to a fresh session of the viewer's own (handleNewChat ->
// onResetSession). The restore and the drawer's real session-change reset run together here, with a
// handleNewChat that does what the drawer's does (clears, then a new session id).
describe('a read-only session opened in the drawer keeps its messages (P5-07)', () => {
  beforeEach(() => { vi.stubGlobal('fetch', vi.fn(async () => ({ ok: false }))) })

  const message = { id: 'm1', type: 'user_message', data: { content: 'hello from Bob' }, createdAt: '2026-11-13T12:00:00Z' }

  function useDrawerSession(base: ReturnType<typeof deps>) {
    const [sessionId, setSessionId] = useState('s-viewer')
    const [chatItems, setChatItems] = useState<ChatItem[]>([])
    const isRestoringConversation = useRef(false)
    const restoration = useConversationRestoration({
      ...base,
      setChatItems,
      isRestoringConversation,
      onSwitchSession: setSessionId,
      handleNewChat: () => { setChatItems([]); setSessionId(`s-fresh-${Math.random()}`) },
    })
    useSessionChangeReset(sessionId, isRestoringConversation, () => setChatItems([]))
    return { ...restoration, sessionId, chatItems, isRestoringConversation }
  }

  test("another person's shared session: its messages stay on screen after the socket moves to a fresh session", async () => {
    const conv = theirs('c-bob', 'Bob Writer')
    const { result } = renderHook(() => useDrawerSession(deps({ ...conv, messages: [message], access: conv.access })))
    await act(async () => { await result.current.handleSelectConversation(conv) })
    expect(result.current.sessionId).toMatch(/^s-fresh-/)
    expect(result.current.readOnlyView).toEqual({ conversationId: 'c-bob', by: 'Bob Writer', authorDeleted: false })
    expect(result.current.chatItems).toEqual([expect.objectContaining({ type: 'message', role: 'user', content: 'hello from Bob' })])
    // The skip is spent on that one change: the next session change (New session) clears as before.
    expect(result.current.isRestoringConversation.current).toBe(false)
  })

  test("the viewer's own session still opens with its messages", async () => {
    const conv = mine('c-own')
    const { result } = renderHook(() => useDrawerSession(deps({ ...conv, messages: [message] })))
    await act(async () => { await result.current.handleSelectConversation(conv) })
    expect(result.current.sessionId).toBe('s-c-own')
    expect(result.current.readOnlyView).toBeNull()
    expect(result.current.chatItems).toHaveLength(1)
  })
})

describe('useConversations: sharing one of the viewer\'s sessions', () => {
  test('posts the choice and marks the row; a refusal is reported and changes nothing', async () => {
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      if (url.startsWith('/api/conversations?')) return new Response(JSON.stringify([mine('c1')]), { status: 200 })
      if (url === '/api/conversations/c1/share' && init?.method === 'POST') return new Response(JSON.stringify({ shared: true, changed: true }), { status: 200 })
      return new Response(JSON.stringify({ error: 'Not found' }), { status: 404 })
    })
    vi.stubGlobal('fetch', fetchMock)
    const onError = vi.fn()
    const { result } = renderHook(() => useConversations('p1', 'u1', { onError }))
    await act(async () => { await result.current.fetchConversations() })
    await act(async () => { expect(await result.current.shareConversation('c1', true)).toBe(true) })
    expect(JSON.parse(fetchMock.mock.calls.find(([u]) => u === '/api/conversations/c1/share')![1]!.body as string)).toEqual({ shared: true })
    expect(result.current.conversations[0].access?.shared).toBe(true)
    await act(async () => { expect(await result.current.shareConversation('c2', true)).toBe(false) })
    expect(onError).toHaveBeenCalledWith('share', expect.anything())
  })
})
