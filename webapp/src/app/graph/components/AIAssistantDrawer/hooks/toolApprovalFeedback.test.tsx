/**
 * Allow on a dangerous-tool card answers at the click, not when the agent starts the tool.
 *
 * The agent can take seconds between the person's Allow and its plan_start / tool_start. The card
 * used to stay "Awaiting approval" with live buttons all that time, so the click looked ignored
 * and a second click sent a second answer. Allow now marks the card `approving` at once: the
 * buttons give way to an "Allowed" chip and the badge reads "Starting...", until the start event
 * makes the card running. A wave's nested tools stay 'pending_approval', since tool_start pairs
 * them by that status. A refused Allow brings the card back unmarked (permissionRefusal.test.tsx).
 *
 * Driven through the real hooks: useInteractionState, useSendHandlers, useWebSocketHandler.
 */
import React from 'react'
import { describe, test, expect, vi, afterEach } from 'vitest'
import { useRef, useState } from 'react'
import { renderHook, render, screen, act, cleanup } from '@testing-library/react'
import { MessageType } from '@/lib/websocket-types'
import type { ChatItem } from '../types'
import type { PlanWaveItem, ToolExecutionItem } from '../AgentTimeline'
import { PlanWaveCard } from '../PlanWaveCard'
import { ToolExecutionCard } from '../ToolExecutionCard'
import { useInteractionState } from './useInteractionState'
import { useSendHandlers } from './useSendHandlers'
import { useWebSocketHandler } from './useWebSocketHandler'

afterEach(cleanup)

const SINGLE = { confirmation_id: 'c1', mode: 'single', tools: [{ tool_name: 'execute_naabu', tool_args: { args: '-p 80' } }] }
const PLAN = {
  confirmation_id: 'c2', mode: 'plan', reasoning: 'Independent quick probes',
  tools: [{ tool_name: 'execute_httpx', tool_args: {} }, { tool_name: 'execute_curl', tool_args: {} }],
}

function useDrawer() {
  const s = useInteractionState()
  const [chatItems, setChatItems] = useState<ChatItem[]>([])
  const [isLoading, setIsLoading] = useState(false)
  const itemIdCounter = useRef(0)
  const [senders] = useState(() => ({
    sendApproval: vi.fn(), sendToolConfirmation: vi.fn(), sendFireteamMemberConfirmation: vi.fn(), sendAnswer: vi.fn(),
  }))
  const noop = () => {}
  const ws = useWebSocketHandler({
    setChatItems, setIsLoading, setIsStopped: noop, setIsStopping: noop,
    setCurrentPhase: noop, setIterationCount: noop, setAttackPathType: noop, setTodoList: noop,
    todoList: [], itemIdCounter,
    setAwaitingApproval: s.setAwaitingApproval, setApprovalRequest: s.setApprovalRequest,
    setAwaitingQuestion: s.setAwaitingQuestion, setQuestionRequest: s.setQuestionRequest,
    setAwaitingToolConfirmation: s.setAwaitingToolConfirmation, setToolConfirmationRequest: s.setToolConfirmationRequest,
    awaitingApprovalRef: s.awaitingApprovalRef, isProcessingApproval: s.isProcessingApproval,
    awaitingQuestionRef: s.awaitingQuestionRef, isProcessingQuestion: s.isProcessingQuestion,
    awaitingToolConfirmationRef: s.awaitingToolConfirmationRef, isProcessingToolConfirmation: s.isProcessingToolConfirmation,
    pendingApprovalToolId: s.pendingApprovalToolId, pendingApprovalWaveId: s.pendingApprovalWaveId,
    answerUndo: s.answerUndo, setAnswerText: s.setAnswerText, setSelectedOptions: s.setSelectedOptions,
  })
  const base: Record<string, unknown> = {
    inputValue: '', setInputValue: noop, isLoading, setIsLoading, setIsStopped: noop, setIsStopping: noop,
    setChatItems, chatItems, activeSkill: null, setActiveSkill: noop,
    awaitingToolConfirmation: s.awaitingToolConfirmation, setAwaitingToolConfirmation: s.setAwaitingToolConfirmation,
    toolConfirmationRequest: s.toolConfirmationRequest, setToolConfirmationRequest: s.setToolConfirmationRequest,
    isProcessingToolConfirmation: s.isProcessingToolConfirmation, awaitingToolConfirmationRef: s.awaitingToolConfirmationRef,
    pendingApprovalToolId: s.pendingApprovalToolId, pendingApprovalWaveId: s.pendingApprovalWaveId,
    answerUndo: s.answerUndo,
    ...senders,
    conversationId: 'conv-1', projectId: 'p1', userId: 'u1', sessionId: 's1',
  }
  // Every other dependency is a sender or a callback these flows never call.
  const deps = new Proxy(base, {
    get: (target, key: string) => (key in target ? target[key] : noop),
  }) as unknown as Parameters<typeof useSendHandlers>[0]
  const send = useSendHandlers(deps)
  return { s, chatItems, ws, send, senders }
}

type Drawer = { current: ReturnType<typeof useDrawer> }

const frame = (result: Drawer, type: MessageType, payload: unknown) =>
  act(() => result.current.ws.handleWebSocketMessage({ type, payload, timestamp: 't' } as never))

const waveOf = (items: ChatItem[]) => items.find((it) => it.type === 'plan_wave') as PlanWaveItem
const toolOf = (items: ChatItem[]) => items.find((it) => it.type === 'tool_execution') as ToolExecutionItem

describe('Allow on a wave', () => {
  test('marks the wave at the click, leaves its tools pending, and plan_start makes it running', () => {
    const { result } = renderHook(() => useDrawer())
    frame(result, MessageType.TOOL_CONFIRMATION_REQUEST, PLAN)
    const wave = waveOf(result.current.chatItems)
    expect(wave.approving).toBeFalsy()

    act(() => result.current.send.handleTimelineToolConfirmation(wave.id, 'approve'))
    const marked = waveOf(result.current.chatItems)
    expect(marked.approving).toBe(true)
    expect(marked.status).toBe('pending_approval')
    expect(marked.tools.map((t) => t.status)).toEqual(['pending_approval', 'pending_approval'])
    expect(result.current.senders.sendToolConfirmation).toHaveBeenCalledWith('approve')

    frame(result, MessageType.PLAN_START, { wave_id: 'w-1', plan_rationale: 'r', tool_count: 2, tools: [] })
    const started = waveOf(result.current.chatItems)
    expect(started.status).toBe('running')
    expect(started.approving).toBeFalsy()

    frame(result, MessageType.TOOL_START, { tool_name: 'execute_httpx', tool_args: {}, wave_id: 'w-1' })
    const tools = waveOf(result.current.chatItems).tools
    expect(tools).toHaveLength(2)
    expect(tools.map((t) => t.status)).toEqual(['running', 'pending_approval'])
  })
})

describe('Allow on a single tool', () => {
  test('marks the card at the click and tool_start makes it running', () => {
    const { result } = renderHook(() => useDrawer())
    frame(result, MessageType.TOOL_CONFIRMATION_REQUEST, SINGLE)
    const card = toolOf(result.current.chatItems)

    act(() => result.current.send.handleTimelineToolConfirmation(card.id, 'approve'))
    expect(toolOf(result.current.chatItems)).toMatchObject({ status: 'pending_approval', approving: true })

    frame(result, MessageType.TOOL_START, { tool_name: 'execute_naabu', tool_args: { args: '-p 80' }, step_id: 's-1' })
    const started = toolOf(result.current.chatItems)
    expect(started.status).toBe('running')
    expect(started.approving).toBeFalsy()
  })

  test('a new request for the same running tool asks again with live buttons', () => {
    const { result } = renderHook(() => useDrawer())
    frame(result, MessageType.TOOL_CONFIRMATION_REQUEST, SINGLE)
    const card = toolOf(result.current.chatItems)
    act(() => result.current.send.handleTimelineToolConfirmation(card.id, 'approve'))
    frame(result, MessageType.TOOL_START, { tool_name: 'execute_naabu', tool_args: {}, step_id: 's-1' })

    act(() => { result.current.s.isProcessingToolConfirmation.current = false })
    frame(result, MessageType.TOOL_CONFIRMATION_REQUEST, SINGLE)
    const again = toolOf(result.current.chatItems)
    expect(again.id).toBe(card.id)
    expect(again.status).toBe('pending_approval')
    expect(again.approving).toBeFalsy()
  })
})

describe('what the card shows', () => {
  const tool: ToolExecutionItem = {
    type: 'tool_execution', id: 'tool-1', timestamp: new Date(), tool_name: 'execute_naabu',
    tool_args: {}, status: 'pending_approval', output_chunks: [],
  }
  const wave: PlanWaveItem = {
    type: 'plan_wave', id: 'wave-1', timestamp: new Date(), wave_id: '', plan_rationale: 'r',
    tool_count: 1, tools: [tool], status: 'pending_approval',
  }
  const cards = [
    ['wave', (approving?: boolean) => (
      <PlanWaveCard item={{ ...wave, approving }} isExpanded={false} onToggleExpand={() => {}}
        onApprove={vi.fn()} onReject={vi.fn()} />
    )],
    ['tool', (approving?: boolean) => (
      <ToolExecutionCard item={{ ...tool, approving }} isExpanded={false} onToggleExpand={() => {}}
        onApprove={vi.fn()} onReject={vi.fn()} />
    )],
  ] as const

  for (const [kind, card] of cards) {
    test(`a pending ${kind} offers Allow and Deny`, () => {
      render(card())
      expect(screen.getByText('Awaiting approval')).toBeTruthy()
      expect(screen.getByRole('button', { name: 'Allow' })).toBeTruthy()
      expect(screen.getByRole('button', { name: 'Deny' })).toBeTruthy()
    })

    test(`an approving ${kind} shows "Allowed" and "Starting...", with no button left to click`, () => {
      render(card(true))
      expect(screen.getByText('Allowed')).toBeTruthy()
      expect(screen.getByText('Starting...')).toBeTruthy()
      expect(screen.queryByText('Awaiting approval')).toBeNull()
      expect(screen.queryByRole('button', { name: 'Allow' })).toBeNull()
      expect(screen.queryByRole('button', { name: 'Deny' })).toBeNull()
    })
  }
})
