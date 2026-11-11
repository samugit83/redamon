/**
 * A resume the agent refused (another user's run holds a different set of MCP Tool
 * Plugins, RBAC OQ-41): the person's answer was not applied, the agent sends the
 * request again, and the drawer shows it although the answer left a moment ago.
 * Any other error keeps the short guard that drops a duplicate request.
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { renderHook, act, cleanup } from '@testing-library/react'
import { MessageType } from '@/lib/websocket-types'
import { useWebSocketHandler } from './useWebSocketHandler'

afterEach(cleanup)

const REQUESTS = [
  { frame: MessageType.TOOL_CONFIRMATION_REQUEST, setter: 'setToolConfirmationRequest',
    payload: { confirmation_id: 'c1', mode: 'single', tools: [{ tool_name: 'create_issue', tool_args: {} }] } },
  { frame: MessageType.APPROVAL_REQUEST, setter: 'setApprovalRequest',
    payload: { from_phase: 'informational', to_phase: 'exploitation' } },
  { frame: MessageType.QUESTION_REQUEST, setter: 'setQuestionRequest',
    payload: { question: 'Which port?', format: 'text' } },
] as const

/** The drawer right after the person answered: nothing awaited, the answer in flight. */
function drawerJustAnswered() {
  const noop = () => {}
  const setters = {
    setApprovalRequest: vi.fn(), setQuestionRequest: vi.fn(), setToolConfirmationRequest: vi.fn(),
  }
  const { result } = renderHook(() => useWebSocketHandler({
    setChatItems: noop, setIsLoading: noop, setIsStopped: noop, setIsStopping: noop,
    setCurrentPhase: noop, setIterationCount: noop, setAttackPathType: noop, setTodoList: noop,
    todoList: [], itemIdCounter: { current: 0 },
    setAwaitingApproval: noop, setAwaitingQuestion: noop, setAwaitingToolConfirmation: noop,
    ...setters,
    awaitingApprovalRef: { current: false }, isProcessingApproval: { current: true },
    awaitingQuestionRef: { current: false }, isProcessingQuestion: { current: true },
    awaitingToolConfirmationRef: { current: false }, isProcessingToolConfirmation: { current: true },
    pendingApprovalToolId: { current: null }, pendingApprovalWaveId: { current: null },
  } as never))
  const send = (type: MessageType, payload: unknown) =>
    act(() => result.current.handleWebSocketMessage({ type, payload, timestamp: 't' } as never))
  return { send, setters }
}

describe('a refused resume', () => {
  test('shows the request again so the person can answer it', () => {
    for (const { frame, setter, payload } of REQUESTS) {
      const d = drawerJustAnswered()
      d.send(MessageType.ERROR, {
        message: 'your answer was not applied', code: 'mcp_toolset_busy', recoverable: true,
      })
      d.send(frame, payload)
      expect(d.setters[setter], frame).toHaveBeenCalledWith(payload)
    }
  })

  test('any other error still drops a request that arrives while the answer is in flight', () => {
    for (const error of [
      { message: 'x', code: 'agent_run_failed', recoverable: true },
      { message: 'x', code: 'mcp_toolset_busy', recoverable: false },
    ]) {
      const { frame, setter, payload } = REQUESTS[0]
      const d = drawerJustAnswered()
      d.send(MessageType.ERROR, error)
      d.send(frame, payload)
      expect(d.setters[setter], JSON.stringify(error)).not.toHaveBeenCalled()
    }
  })
})
