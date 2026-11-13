/**
 * An answer the agent refused (step 3.9b review, finding 3; step 5.4 review).
 *
 * The drawer hides a request's card and shows the decision as soon as the person answers. The
 * agent then refuses the answer and keeps waiting, but sends no request again: for a missing
 * permission (`permission_required`), because the decision-time check did not answer
 * (`decision_check_unavailable`, the owner included), or for a reason this drawer does not know
 * yet. Whatever the reason, the card must come back with nothing in flight, the optimistic
 * "Approved phase transition" / "Answer: ..." line must go, and the chat must say why: the phase
 * approval, a top-level dangerous-tool card (approve or reject), a question, and a Fireteam
 * member's card. An answer the agent admits (the owner with sharing off) behaves as before.
 *
 * Driven through the real hooks: useInteractionState, useSendHandlers, useWebSocketHandler.
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { useRef, useState } from 'react'
import { renderHook, act, cleanup } from '@testing-library/react'
import { MessageType } from '@/lib/websocket-types'
import type { ChatItem, FireteamItem, Message } from '../types'
import type { PlanWaveItem, ToolExecutionItem } from '../AgentTimeline'
import { useInteractionState } from './useInteractionState'
import { useSendHandlers } from './useSendHandlers'
import { useWebSocketHandler } from './useWebSocketHandler'
import { DECISION_CHECK_UNAVAILABLE_TEXT, permissionRefusalText, refusedAnswer } from './answerUndo'
import { agentErrorText } from './agentErrorText'

afterEach(cleanup)

const APPROVAL = { from_phase: 'informational', to_phase: 'exploitation', reason: 'r', planned_actions: [], risks: [] }
const CONFIRMATION = { confirmation_id: 'c1', mode: 'single', tools: [{ tool_name: 'execute_naabu', tool_args: { args: '-p 80' } }] }
const TEXT_QUESTION = { question: 'Which port?', context: 'c', format: 'text', options: [] }
const CHOICE_QUESTION = { question: 'Which hosts?', context: 'c', format: 'multi_choice', options: ['a', 'b', 'c'] }

function useDrawer(initialItems: ChatItem[] = []) {
  const s = useInteractionState()
  const [chatItems, setChatItems] = useState<ChatItem[]>(initialItems)
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
    awaitingApproval: s.awaitingApproval, setAwaitingApproval: s.setAwaitingApproval,
    approvalRequest: s.approvalRequest, setApprovalRequest: s.setApprovalRequest,
    modificationText: s.modificationText, setModificationText: s.setModificationText,
    awaitingQuestion: s.awaitingQuestion, setAwaitingQuestion: s.setAwaitingQuestion,
    questionRequest: s.questionRequest, setQuestionRequest: s.setQuestionRequest,
    answerText: s.answerText, setAnswerText: s.setAnswerText,
    selectedOptions: s.selectedOptions, setSelectedOptions: s.setSelectedOptions,
    awaitingToolConfirmation: s.awaitingToolConfirmation, setAwaitingToolConfirmation: s.setAwaitingToolConfirmation,
    toolConfirmationRequest: s.toolConfirmationRequest, setToolConfirmationRequest: s.setToolConfirmationRequest,
    isProcessingApproval: s.isProcessingApproval, awaitingApprovalRef: s.awaitingApprovalRef,
    isProcessingQuestion: s.isProcessingQuestion, awaitingQuestionRef: s.awaitingQuestionRef,
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
  return { s, chatItems, isLoading, ws, send, senders, setChatItems }
}

type Drawer = { current: ReturnType<typeof useDrawer> }

const frame = (result: Drawer, type: MessageType, payload: unknown) =>
  act(() => result.current.ws.handleWebSocketMessage({ type, payload, timestamp: 't' } as never))

const refuse = (result: Drawer, extra: Record<string, unknown>) =>
  frame(result, MessageType.ERROR, {
    message: 'You do not hold the permission this answer needs.', code: 'permission_required', recoverable: true, ...extra,
  })

const messages = (items: ChatItem[]) => items.filter((it): it is Message => it.type === 'message')

describe('the frame the agent sends', () => {
  test('names the refused answer and why; only a recoverable frame naming an answer counts', () => {
    expect(refusedAnswer({ code: 'permission_required', recoverable: true, permission: 'agent:approve_phase', answer: 'approval' }))
      .toEqual({ answer: 'approval', kind: 'permission', permission: 'agent:approve_phase',
        text: permissionRefusalText('agent:approve_phase') })
    expect(refusedAnswer({
      code: 'permission_required', recoverable: true, permission: 'agent:fireteam',
      answer: 'fireteam_member_confirmation', wave_id: 'ft-1', member_id: 'm1',
    })).toEqual({ answer: 'fireteam_member_confirmation', kind: 'permission', permission: 'agent:fireteam',
      text: permissionRefusalText('agent:fireteam'), waveId: 'ft-1', memberId: 'm1' })
    expect(refusedAnswer({ code: 'permission_required', recoverable: true, permission: 'agent:chat', answer: 'question' }))
      .toEqual({ answer: 'question', kind: 'permission', permission: 'agent:chat', text: permissionRefusalText('agent:chat') })
    expect(refusedAnswer({ code: 'decision_check_unavailable', recoverable: true, answer: 'tool_confirmation', message: 'm' }))
      .toEqual({ answer: 'tool_confirmation', kind: 'unavailable', permission: '', text: DECISION_CHECK_UNAVAILABLE_TEXT })
    const unknown = { code: 'decision_window_closed', recoverable: true, answer: 'approval', message: 'Not applied.' }
    expect(refusedAnswer(unknown))
      .toEqual({ answer: 'approval', kind: 'other', permission: '', text: agentErrorText(unknown) })
    for (const other of [
      { code: 'permission_required', recoverable: true, permission: 'agent:approve_phase' },
      { code: 'permission_required', recoverable: false, answer: 'approval' },
      { code: 'decision_check_unavailable', recoverable: false, answer: 'approval' },
      { code: 'decision_check_unavailable', recoverable: true, answer: 'codefix_push' },
      // The agent sends this request again itself (refusedResume.test.tsx).
      { code: 'mcp_toolset_busy', recoverable: true, answer: 'approval' },
      { code: 'permission_required', recoverable: true, answer: 'fireteam_member_confirmation' },
    ]) expect(refusedAnswer(other), JSON.stringify(other)).toBeNull()
  })

  test('the unavailable sentence says the permission could not be confirmed and to try again', () => {
    expect(DECISION_CHECK_UNAVAILABLE_TEXT).toMatch(/could not confirm your permission/)
    expect(DECISION_CHECK_UNAVAILABLE_TEXT).toMatch(/try again/i)
  })

  test('the sentence names the permission and what it allows; an unknown one is not echoed', () => {
    expect(permissionRefusalText('agent:approve_phase')).toBe(
      'Your answer was not applied: it needs agent:approve_phase ("Approve the move into exploitation and '
      + 'post-exploitation"), which you do not hold on this project. The request stays open for someone who holds it.')
    expect(permissionRefusalText('<b>x</b>')).toContain('it needs a permission, which')
  })
})

describe('a phase approval refused for a missing permission', () => {
  test('brings the card back, drops "Approved phase transition" and names the permission', () => {
    const { result } = renderHook(() => useDrawer())
    frame(result, MessageType.APPROVAL_REQUEST, APPROVAL)
    expect(result.current.s.awaitingApproval).toBe(true)

    act(() => result.current.send.handleApproval('approve'))
    expect(result.current.s.awaitingApproval).toBe(false)
    expect(messages(result.current.chatItems).map((m) => m.content)).toEqual(['Approved phase transition'])
    expect(result.current.senders.sendApproval).toHaveBeenCalledTimes(1)

    refuse(result, { permission: 'agent:approve_phase', answer: 'approval' })
    expect(result.current.s.awaitingApproval).toBe(true)
    expect(result.current.s.approvalRequest).toEqual(APPROVAL)
    expect(result.current.isLoading).toBe(false)
    const shown = messages(result.current.chatItems)
    expect(shown.map((m) => m.content)).toEqual(['Your answer was not applied.'])
    expect(shown[0].error).toBe(permissionRefusalText('agent:approve_phase'))

    // The card answers again, e.g. once an admin has given the permission.
    act(() => result.current.send.handleApproval('abort'))
    expect(result.current.senders.sendApproval).toHaveBeenCalledTimes(2)
  })
})

describe('a dangerous-tool confirmation refused for a missing permission', () => {
  for (const decision of ['approve', 'reject'] as const) {
    test(`after ${decision}, the card is pending again and answers again`, () => {
      const { result } = renderHook(() => useDrawer())
      frame(result, MessageType.TOOL_CONFIRMATION_REQUEST, CONFIRMATION)
      const card = result.current.chatItems.find((it) => it.type === 'tool_execution') as ToolExecutionItem
      expect(card.status).toBe('pending_approval')

      act(() => result.current.send.handleTimelineToolConfirmation(card.id, decision))
      expect(result.current.s.awaitingToolConfirmation).toBe(false)

      refuse(result, { permission: 'agent:approve_dangerous', answer: 'tool_confirmation' })
      expect(result.current.s.awaitingToolConfirmation).toBe(true)
      expect(result.current.s.awaitingToolConfirmationRef.current).toBe(true)
      expect(result.current.s.toolConfirmationRequest).toEqual(CONFIRMATION)
      expect(result.current.s.pendingApprovalToolId.current).toBe(card.id)
      const restored = result.current.chatItems.find((it) => it.id === card.id) as ToolExecutionItem
      expect(restored).toEqual(card)
      expect(messages(result.current.chatItems).at(-1)?.error).toBe(permissionRefusalText('agent:approve_dangerous'))

      act(() => result.current.send.handleTimelineToolConfirmation(card.id, 'approve'))
      expect(result.current.senders.sendToolConfirmation).toHaveBeenCalledTimes(2)
    })
  }
})

describe("a Fireteam member's confirmation refused for a missing permission", () => {
  const wave: PlanWaveItem = {
    type: 'plan_wave', id: 'wave-conf-1', timestamp: new Date(0), wave_id: '', plan_rationale: 'escalated',
    tool_count: 1, status: 'pending_approval', isFireteamEscalation: true,
    tools: [{ type: 'tool_execution', id: 'tool-conf-1', timestamp: new Date(0), tool_name: 'execute_naabu',
      tool_args: {}, status: 'pending_approval', output_chunks: [] }],
  }
  const earlier: PlanWaveItem = { ...wave, id: 'wave-done', status: 'success', isFireteamEscalation: undefined }
  const fireteam: FireteamItem = {
    type: 'fireteam', id: 'ft-1', fireteam_id: 'ft-1', iteration: 2, plan_rationale: 'p',
    timestamp: new Date(0), started_at: new Date(0), status: 'running',
    members: [{
      member_id: 'm1', name: 'Web', task: 't', skills: [], status: 'needs_confirmation', started_at: new Date(0),
      tools: [], planWaves: [earlier, wave], iterations_used: 0, tokens_used: 0, input_tokens_used: 0,
      output_tokens_used: 0, findings_count: 0,
    }],
  }
  const memberWaves = (items: ChatItem[]) =>
    (items.find((it) => it.type === 'fireteam') as FireteamItem).members[0].planWaves

  for (const [decision, permission] of [['approve', 'agent:fireteam'], ['reject', 'agent:approve_dangerous']] as const) {
    test(`after ${decision}, the member's card is back where it was`, () => {
      const { result } = renderHook(() => useDrawer([fireteam]))
      act(() => result.current.send.handleTimelineToolConfirmation(wave.id, decision))
      expect(result.current.senders.sendFireteamMemberConfirmation).toHaveBeenCalledWith('ft-1', 'm1', decision)
      expect(memberWaves(result.current.chatItems)).not.toContainEqual(wave)

      refuse(result, { permission, answer: 'fireteam_member_confirmation', wave_id: 'ft-1', member_id: 'm1' })
      expect(memberWaves(result.current.chatItems)).toEqual([earlier, wave])
      expect(messages(result.current.chatItems).at(-1)?.error).toBe(permissionRefusalText(permission))

      act(() => { result.current.s.isProcessingToolConfirmation.current = false })
      act(() => result.current.send.handleTimelineToolConfirmation(wave.id, 'approve'))
      expect(result.current.senders.sendFireteamMemberConfirmation).toHaveBeenCalledTimes(2)
    })
  }

  test('a refusal for a member the drawer holds no card for only says so', () => {
    const { result } = renderHook(() => useDrawer([fireteam]))
    refuse(result, { permission: 'agent:fireteam', answer: 'fireteam_member_confirmation', wave_id: 'ft-9', member_id: 'm9' })
    expect(memberWaves(result.current.chatItems)).toEqual([earlier, wave])
    expect(messages(result.current.chatItems).map((m) => m.error)).toEqual([permissionRefusalText('agent:fireteam')])
  })
})

describe('other errors are unchanged', () => {
  test('a permission_required frame that names no answer keeps the generic bubble and restores nothing', () => {
    const { result } = renderHook(() => useDrawer())
    frame(result, MessageType.APPROVAL_REQUEST, APPROVAL)
    act(() => result.current.send.handleApproval('approve'))
    refuse(result, { permission: 'agent:approve_phase' })
    expect(result.current.s.awaitingApproval).toBe(false)
    expect(messages(result.current.chatItems).map((m) => m.content)).toEqual([
      'Approved phase transition', 'An error occurred while processing your request.',
    ])
  })
})

/**
 * Step 5.4 review: the agent re-checks every answer when it decides, and refuses when the check
 * does not answer, the owner included. Every refusal kind restores every card kind.
 */
const REFUSALS = [
  { name: 'permission_required', frame: { code: 'permission_required', permission: 'agent:approve_phase' },
    text: () => permissionRefusalText('agent:approve_phase') },
  { name: 'decision_check_unavailable', frame: {
    code: 'decision_check_unavailable',
    message: 'Your answer was not applied: RedAmon could not check that you may still take this decision. Try again in a moment.',
  }, text: () => DECISION_CHECK_UNAVAILABLE_TEXT },
  { name: 'an unknown refusal', frame: { code: 'decision_window_closed', message: 'Not applied.' },
    text: () => agentErrorText({ code: 'decision_window_closed', message: 'Not applied.' }) },
] as const

const refuseWith = (result: Drawer, refusal: (typeof REFUSALS)[number], extra: Record<string, unknown>) =>
  frame(result, MessageType.ERROR, { recoverable: true, ...refusal.frame, ...extra })

describe.each(REFUSALS)('an answer refused with $name', (refusal) => {
  test('the phase approval comes back with nothing in flight, and answers again', () => {
    const { result } = renderHook(() => useDrawer())
    frame(result, MessageType.APPROVAL_REQUEST, APPROVAL)
    act(() => result.current.send.handleApproval('approve'))
    expect(result.current.s.isProcessingApproval.current).toBe(true)
    expect(result.current.isLoading).toBe(true)

    refuseWith(result, refusal, { answer: 'approval' })
    expect(result.current.s.awaitingApproval).toBe(true)
    expect(result.current.s.awaitingApprovalRef.current).toBe(true)
    expect(result.current.s.approvalRequest).toEqual(APPROVAL)
    expect(result.current.s.isProcessingApproval.current).toBe(false)
    expect(result.current.isLoading).toBe(false)
    const shown = messages(result.current.chatItems)
    expect(shown.map((m) => m.content)).toEqual(['Your answer was not applied.'])
    expect(shown[0].error).toBe(refusal.text())

    act(() => result.current.send.handleApproval('approve'))
    expect(result.current.senders.sendApproval).toHaveBeenCalledTimes(2)
    expect(messages(result.current.chatItems).map((m) => m.content).at(-1)).toBe('Approved phase transition')
  })

  for (const decision of ['approve', 'reject'] as const) {
    test(`a dangerous-tool card answered ${decision} is pending again, and answers again`, () => {
      const { result } = renderHook(() => useDrawer())
      frame(result, MessageType.TOOL_CONFIRMATION_REQUEST, CONFIRMATION)
      const card = result.current.chatItems.find((it) => it.type === 'tool_execution') as ToolExecutionItem
      act(() => result.current.send.handleTimelineToolConfirmation(card.id, decision))
      expect(result.current.s.isProcessingToolConfirmation.current).toBe(true)

      refuseWith(result, refusal, { answer: 'tool_confirmation' })
      expect(result.current.s.awaitingToolConfirmation).toBe(true)
      expect(result.current.s.awaitingToolConfirmationRef.current).toBe(true)
      expect(result.current.s.toolConfirmationRequest).toEqual(CONFIRMATION)
      expect(result.current.s.isProcessingToolConfirmation.current).toBe(false)
      expect(result.current.s.pendingApprovalToolId.current).toBe(card.id)
      expect(result.current.chatItems.find((it) => it.id === card.id)).toEqual(card)
      expect(result.current.isLoading).toBe(false)
      expect(messages(result.current.chatItems).map((m) => m.error)).toEqual([refusal.text()])

      act(() => result.current.send.handleTimelineToolConfirmation(card.id, 'approve'))
      expect(result.current.senders.sendToolConfirmation).toHaveBeenCalledTimes(2)
    })
  }

  test('a question comes back with the typed answer, and answers again', () => {
    const { result } = renderHook(() => useDrawer())
    frame(result, MessageType.QUESTION_REQUEST, TEXT_QUESTION)
    act(() => result.current.s.setAnswerText('8443'))
    act(() => result.current.send.handleAnswer())
    expect(result.current.senders.sendAnswer).toHaveBeenCalledWith('8443')
    expect(result.current.s.awaitingQuestion).toBe(false)
    expect(result.current.s.isProcessingQuestion.current).toBe(true)
    expect(messages(result.current.chatItems).map((m) => m.content)).toEqual(['Answer: 8443'])

    refuseWith(result, refusal, { answer: 'question' })
    expect(result.current.s.awaitingQuestion).toBe(true)
    expect(result.current.s.awaitingQuestionRef.current).toBe(true)
    expect(result.current.s.questionRequest).toEqual(TEXT_QUESTION)
    expect(result.current.s.isProcessingQuestion.current).toBe(false)
    expect(result.current.s.answerText).toBe('8443')
    expect(result.current.isLoading).toBe(false)
    const shown = messages(result.current.chatItems)
    expect(shown.map((m) => m.content)).toEqual(['Your answer was not applied.'])
    expect(shown[0].error).toBe(refusal.text())

    act(() => result.current.send.handleAnswer())
    expect(result.current.senders.sendAnswer).toHaveBeenCalledTimes(2)
    expect(result.current.senders.sendAnswer).toHaveBeenLastCalledWith('8443')
  })

  test('a choice question comes back with the options picked', () => {
    const { result } = renderHook(() => useDrawer())
    frame(result, MessageType.QUESTION_REQUEST, CHOICE_QUESTION)
    act(() => result.current.s.setSelectedOptions(['a', 'c']))
    act(() => result.current.send.handleAnswer())
    expect(result.current.senders.sendAnswer).toHaveBeenCalledWith('a, c')

    refuseWith(result, refusal, { answer: 'question' })
    expect(result.current.s.questionRequest).toEqual(CHOICE_QUESTION)
    expect(result.current.s.selectedOptions).toEqual(['a', 'c'])
    act(() => result.current.send.handleAnswer())
    expect(result.current.senders.sendAnswer).toHaveBeenLastCalledWith('a, c')
  })

  test("a Fireteam member's card is back where it was", () => {
    const wave: PlanWaveItem = {
      type: 'plan_wave', id: 'wave-conf-1', timestamp: new Date(0), wave_id: '', plan_rationale: 'escalated',
      tool_count: 1, status: 'pending_approval', isFireteamEscalation: true,
      tools: [{ type: 'tool_execution', id: 'tool-conf-1', timestamp: new Date(0), tool_name: 'execute_naabu',
        tool_args: {}, status: 'pending_approval', output_chunks: [] }],
    }
    const fireteam: FireteamItem = {
      type: 'fireteam', id: 'ft-1', fireteam_id: 'ft-1', iteration: 2, plan_rationale: 'p',
      timestamp: new Date(0), started_at: new Date(0), status: 'running',
      members: [{
        member_id: 'm1', name: 'Web', task: 't', skills: [], status: 'needs_confirmation', started_at: new Date(0),
        tools: [], planWaves: [wave], iterations_used: 0, tokens_used: 0, input_tokens_used: 0,
        output_tokens_used: 0, findings_count: 0,
      }],
    }
    const { result } = renderHook(() => useDrawer([fireteam]))
    act(() => result.current.send.handleTimelineToolConfirmation(wave.id, 'approve'))
    refuseWith(result, refusal, { answer: 'fireteam_member_confirmation', wave_id: 'ft-1', member_id: 'm1' })
    const ft = result.current.chatItems.find((it) => it.type === 'fireteam') as FireteamItem
    expect(ft.members[0].planWaves).toEqual([wave])
    expect(result.current.s.isProcessingToolConfirmation.current).toBe(false)
    expect(messages(result.current.chatItems).map((m) => m.error)).toEqual([refusal.text()])

    act(() => result.current.send.handleTimelineToolConfirmation(wave.id, 'approve'))
    expect(result.current.senders.sendFireteamMemberConfirmation).toHaveBeenCalledTimes(2)
  })

  test('with no card to put back (none was hidden here), nothing stays in flight and the chat says why', () => {
    const { result } = renderHook(() => useDrawer())
    act(() => {
      result.current.s.isProcessingApproval.current = true
      result.current.s.isProcessingQuestion.current = true
      result.current.s.isProcessingToolConfirmation.current = true
    })
    refuseWith(result, refusal, { answer: 'approval' })
    refuseWith(result, refusal, { answer: 'question' })
    refuseWith(result, refusal, { answer: 'tool_confirmation' })
    expect(result.current.s.isProcessingApproval.current).toBe(false)
    expect(result.current.s.isProcessingQuestion.current).toBe(false)
    expect(result.current.s.isProcessingToolConfirmation.current).toBe(false)
    expect(result.current.s.awaitingApproval).toBe(false)
    expect(result.current.s.awaitingQuestion).toBe(false)
    expect(result.current.s.awaitingToolConfirmation).toBe(false)
    expect(messages(result.current.chatItems).map((m) => m.error)).toEqual([refusal.text(), refusal.text(), refusal.text()])
  })
})

describe('an answer the agent admits behaves as before (DV-30: the owner, sharing off)', () => {
  test('the approval, the question and the tool confirmation keep their decision line and stay answered', () => {
    const { result } = renderHook(() => useDrawer())
    frame(result, MessageType.APPROVAL_REQUEST, APPROVAL)
    act(() => result.current.send.handleApproval('approve'))
    frame(result, MessageType.THINKING, { iteration: 1, phase: 'exploitation', thought: 't', reasoning: 'r' })
    expect(result.current.s.awaitingApproval).toBe(false)
    expect(result.current.isLoading).toBe(true)

    act(() => { result.current.s.isProcessingQuestion.current = false })
    frame(result, MessageType.QUESTION_REQUEST, TEXT_QUESTION)
    act(() => result.current.s.setAnswerText('443'))
    act(() => result.current.send.handleAnswer())
    expect(result.current.s.awaitingQuestion).toBe(false)
    expect(result.current.s.answerText).toBe('')

    frame(result, MessageType.TOOL_CONFIRMATION_REQUEST, CONFIRMATION)
    const card = result.current.chatItems.find((it) => it.type === 'tool_execution') as ToolExecutionItem
    act(() => result.current.send.handleTimelineToolConfirmation(card.id, 'approve'))
    expect(result.current.s.awaitingToolConfirmation).toBe(false)

    expect(messages(result.current.chatItems).map((m) => m.content)).toEqual(['Approved phase transition', 'Answer: 443'])
    expect(result.current.senders.sendApproval).toHaveBeenCalledTimes(1)
    expect(result.current.senders.sendAnswer).toHaveBeenCalledTimes(1)
    expect(result.current.senders.sendToolConfirmation).toHaveBeenCalledTimes(1)
  })

  test('an error that names no answer still restores nothing', () => {
    const { result } = renderHook(() => useDrawer())
    frame(result, MessageType.QUESTION_REQUEST, TEXT_QUESTION)
    act(() => result.current.s.setAnswerText('443'))
    act(() => result.current.send.handleAnswer())
    frame(result, MessageType.ERROR, { message: 'Error processing answer', code: 'answer_failed', recoverable: true })
    expect(result.current.s.awaitingQuestion).toBe(false)
    expect(messages(result.current.chatItems).map((m) => m.content)).toEqual([
      'Answer: 443', 'An error occurred while processing your request.',
    ])
  })
})
