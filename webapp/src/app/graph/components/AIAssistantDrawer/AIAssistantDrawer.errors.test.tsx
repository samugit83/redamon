/**
 * What the AI drawer shows when something fails, piece by piece (the drawer
 * itself needs a page of providers; AIAssistantDrawer.socketWiring.test.ts
 * guards how these pieces are wired).
 *
 * - G-1/G-2: the header says why the socket is not connected (the hook's error,
 *   the last close code and reason, the URL dialed, the agent's health answer)
 *   instead of a bare "Connection failed".
 * - G-5/G-54/note 8: an agent ERROR frame shows its code, class and provider
 *   status; G-44: the "chat is not being saved" notice does not end the run.
 * - G-10: the history list says it could not load instead of "No sessions yet".
 * - G-41: the API-key modal says why a save failed. G-46: the download card
 *   parses the route's JSON. G-43: decisions are blocked while disconnected.
 *
 * Run: npx vitest run src/app/graph/components/AIAssistantDrawer/AIAssistantDrawer.errors.test.tsx
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor, renderHook, act } from '@testing-library/react'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { ConnectionStatus, MessageType } from '@/lib/websocket-types'

vi.mock('@/hooks/useTheme', () => ({ useTheme: () => ({ isLight: false }) }))
const alerts = vi.hoisted(() => ({ alertError: vi.fn(async () => {}) }))
vi.mock('@/components/ui', async (orig) => ({
  ...(await orig<typeof import('@/components/ui')>()),
  useAlertModal: () => alerts,
}))

import { DrawerHeader, connectionDetailLines } from './DrawerHeader'
import { ConversationHistory } from './ConversationHistory'
import { ApprovalDialog } from './ApprovalDialog'
import { QuestionDialog } from './QuestionDialog'
import { FileDownloadCard } from './FileDownloadCard'
import { agentErrorText } from './hooks/agentErrorText'
import { useWebSocketHandler } from './hooks/useWebSocketHandler'
import { useApiKeyModal } from './hooks/useApiKeyModal'
import { deleteWarningsText } from './drawerNotices'
import { SkillDataNotice } from './SkillDataNotice'
import { ApiError } from '@/lib/apiError'

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.clearAllMocks()
})

const headerProps = {
  reconnectAttempt: 0,
  sessionId: 'session-12345678',
  requireToolConfirmation: true,
  hasOtherChains: false,
  isOtherChainsHidden: false,
  showHistory: false,
  setShowHistory: () => {},
  handleNewChat: () => {},
  handleDownloadMarkdown: () => {},
  chatItems: [],
  onClose: () => {},
  conversations: [],
  handleSelectConversation: () => {},
  handleDeleteConversation: () => {},
  handleHistoryNewChat: () => {},
}

describe('drawer header: why the socket is not connected (G-1, G-2)', () => {
  test('a failed connection shows the error and the agent health answer', () => {
    render(
      <DrawerHeader
        {...headerProps}
        status={ConnectionStatus.FAILED}
        connectionError="Max reconnection attempts reached (last close 1011: Orchestrator not initialized) · ws://host:8090/ws/agent"
        agentHealthError="Cannot reach the RedAmon agent service at http://agent:8080: connection refused."
      />,
    )
    expect(screen.getByText('Connection failed')).toBeInTheDocument()
    expect(screen.getByText('Max reconnection attempts reached (last close 1011: Orchestrator not initialized) · ws://host:8090/ws/agent')).toBeInTheDocument()
    expect(screen.getByText('Agent service: Cannot reach the RedAmon agent service at http://agent:8080: connection refused.')).toBeInTheDocument()
  })

  test('a refused ticket shows the mint reason, not the update hint', () => {
    render(
      <DrawerHeader
        {...headerProps}
        status={ConnectionStatus.FAILED}
        connectionError="Could not get a ticket for the agent connection: Unauthorized (HTTP 401)"
      />,
    )
    const detail = screen.getByRole('status', { name: 'Agent connection detail' })
    expect(detail).toHaveTextContent('Could not get a ticket for the agent connection: Unauthorized (HTTP 401)')
    expect(detail).not.toHaveTextContent('redamon.sh update')
  })

  test('reconnecting shows the last close and the URL', () => {
    render(
      <DrawerHeader
        {...headerProps}
        status={ConnectionStatus.RECONNECTING}
        reconnectAttempt={2}
        lastClose={{ code: 1013, reason: 'Server busy (low memory) - retry shortly' }}
        socketUrl="ws://host:8090/ws/agent"
      />,
    )
    expect(screen.getByText('Reconnecting... (2/5)')).toBeInTheDocument()
    expect(screen.getByText('Last close 1013: Server busy (low memory) - retry shortly · ws://host:8090/ws/agent')).toBeInTheDocument()
  })

  test('a connected drawer shows no detail', () => {
    expect(connectionDetailLines({ status: ConnectionStatus.CONNECTED, connectionError: 'x', lastClose: { code: 1006, reason: '' } })).toEqual([])
  })
})

describe('agent ERROR frames show their cause (G-5, G-54, note 8)', () => {
  test('code, class and provider status follow the sentence', () => {
    expect(agentErrorText({ message: 'The agent run failed', code: 'agent_run_failed', error_class: 'RateLimitError', provider_status: 429 }))
      .toBe('The agent run failed (agent_run_failed · RateLimitError · provider HTTP 429)')
  })

  test('a model build failure is not a missing key', () => {
    expect(agentErrorText({
      message: 'Could not set up the model custom/m1. Check its provider in Global Settings.',
      code: 'llm_setup_failed', error_class: 'TypeError',
    })).toBe('Could not set up the model custom/m1. Check its provider in Global Settings. (llm_setup_failed · TypeError)')
  })

  test('parts that do not look like a code, class or status are dropped', () => {
    expect(agentErrorText({ message: 'Internal error', code: 'Bad Code!', error_class: 'x y', provider_status: 'sk-ant' }))
      .toBe('Internal error')
  })

  test('a 429 says which kind it was and what to do', () => {
    const base = { message: 'The agent run failed', code: 'agent_run_failed', error_class: 'OpenAIRateLimitError', provider_status: 429 }
    expect(agentErrorText({ ...base, provider_error_kind: 'rate_limited', rate_limit_waited_s: 118 }))
      .toBe("The agent run failed (agent_run_failed · OpenAIRateLimitError · provider HTTP 429 · waited 118 s). The model provider's rate limit did not clear. Send the message again in a minute, or use a plan or model with a higher limit.")
    expect(agentErrorText({ ...base, provider_error_kind: 'quota_exhausted' }))
      .toBe('The agent run failed (agent_run_failed · OpenAIRateLimitError · provider HTTP 429). The model provider account has no credit or quota left. Add credit, or pick another model.')
    expect(agentErrorText({ ...base, provider_error_kind: 'request_too_large' }))
      .toMatch(/\. The request is larger than the provider's per-minute limit for this account\./)
  })

  test('an unknown kind or a malformed wait adds nothing', () => {
    const base = { message: 'The agent run failed', code: 'agent_run_failed', error_class: 'RateLimitError', provider_status: 429 }
    for (const extra of [{ provider_error_kind: 'toString' }, { provider_error_kind: '<b>' },
      { rate_limit_waited_s: -3 }, { rate_limit_waited_s: 1.5 }, { rate_limit_waited_s: '118' }]) {
      expect(agentErrorText({ ...base, ...extra }))
        .toBe('The agent run failed (agent_run_failed · RateLimitError · provider HTTP 429)')
    }
  })

  function handler() {
    let items: unknown[] = []
    const setChatItems = vi.fn((v: unknown) => { items = typeof v === 'function' ? (v as (p: unknown[]) => unknown[])(items) : v as unknown[] })
    const setIsLoading = vi.fn()
    const noop = vi.fn()
    const ref = { current: false }
    const { result } = renderHook(() => useWebSocketHandler({
      setChatItems, setIsLoading, setIsStopped: noop, setIsStopping: noop,
      setCurrentPhase: noop, setIterationCount: noop, setAttackPathType: noop, setTodoList: noop,
      todoList: [], itemIdCounter: { current: 0 },
      setAwaitingApproval: noop, setApprovalRequest: noop, setAwaitingQuestion: noop, setQuestionRequest: noop,
      setAwaitingToolConfirmation: noop, setToolConfirmationRequest: noop,
      awaitingApprovalRef: ref, isProcessingApproval: ref, awaitingQuestionRef: ref, isProcessingQuestion: ref,
      awaitingToolConfirmationRef: ref, isProcessingToolConfirmation: ref,
      pendingApprovalToolId: { current: null }, pendingApprovalWaveId: { current: null },
    } as never))
    return { send: (payload: Record<string, unknown>) => act(() => result.current.handleWebSocketMessage({ type: MessageType.ERROR, payload, timestamp: 't' } as never)), items: () => items, setIsLoading }
  }

  test('an error bubble carries the frame cause', () => {
    const h = handler()
    h.send({ message: 'WebSocket authentication failed: Invalid or missing ticket', code: 'ws_ticket_invalid', recoverable: false })
    expect(h.items()).toEqual([expect.objectContaining({
      content: 'An error occurred while processing your request.',
      error: 'WebSocket authentication failed: Invalid or missing ticket (ws_ticket_invalid)',
    })])
    expect(h.setIsLoading).toHaveBeenCalledWith(false)
  })

  test('the persist notice is shown with the webapp status and does not end the run (G-44)', () => {
    const h = handler()
    h.send({ message: 'The chat is not being saved: messages from this run may be missing after a reload', code: 'persist_failed', http_status: 503, recoverable: true })
    expect(h.items()).toEqual([expect.objectContaining({
      content: 'This chat is not being saved.',
      error: 'The chat is not being saved: messages from this run may be missing after a reload (persist_failed · HTTP 503)',
    })])
    expect(h.setIsLoading).not.toHaveBeenCalled()
  })
})

describe('session history says when it could not load (G-10)', () => {
  const props = { currentSessionId: 's1', onBack: () => {}, onSelect: () => {}, onDelete: () => {}, onNewChat: () => {} }

  test('an empty list with an error is not "No sessions yet"', () => {
    render(<ConversationHistory {...props} conversations={[]} error="Failed to fetch conversations (P1001 · HTTP 500)" />)
    expect(screen.getByText('Could not load the sessions')).toBeInTheDocument()
    expect(screen.getByText('Failed to fetch conversations (P1001 · HTTP 500)')).toBeInTheDocument()
    expect(screen.queryByText('No sessions yet')).toBeNull()
  })

  test('a stale list keeps its rows under the error', () => {
    const conv = { id: 'c1', sessionId: 'abcdefgh12345678', title: 'Old run', status: 'idle', agentRunning: false, currentPhase: 'informational', iterationCount: 0, activeSkillId: '', createdAt: '', updatedAt: new Date().toISOString() }
    render(<ConversationHistory {...props} conversations={[conv]} error="Failed to fetch conversations (agent_unreachable · HTTP 503)" />)
    expect(screen.getByText('Old run')).toBeInTheDocument()
    expect(screen.getByRole('alert')).toHaveTextContent('Failed to fetch conversations (agent_unreachable · HTTP 503)')
  })
})

describe('decisions are blocked while the socket is down (G-43)', () => {
  const approval = { from_phase: 'informational', to_phase: 'exploitation', reason: 'r', planned_actions: [], risks: [] }

  test('the approval buttons are disabled with a notice, and nothing is sent', () => {
    const handleApproval = vi.fn()
    render(
      <ApprovalDialog awaitingApproval approvalRequest={approval as never} modificationText="" isLoading={false}
        isConnected={false} setModificationText={() => {}} handleApproval={handleApproval} />,
    )
    expect(screen.getByText(/Not connected to the agent: your decision cannot be sent/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Approve' }))
    expect(screen.getByRole('button', { name: 'Approve' })).toBeDisabled()
    expect(handleApproval).not.toHaveBeenCalled()
  })

  test('connected, the approval works as before', () => {
    const handleApproval = vi.fn()
    render(
      <ApprovalDialog awaitingApproval approvalRequest={approval as never} modificationText="" isLoading={false}
        isConnected setModificationText={() => {}} handleApproval={handleApproval} />,
    )
    fireEvent.click(screen.getByRole('button', { name: 'Approve' }))
    expect(handleApproval).toHaveBeenCalledWith('approve')
  })

  test('the answer button is disabled while disconnected', () => {
    render(
      <QuestionDialog awaitingQuestion questionRequest={{ question: 'Which port?', format: 'text', options: [] } as never}
        answerText="443" selectedOptions={[]} isLoading={false} isConnected={false}
        setAnswerText={() => {}} setSelectedOptions={() => {}} handleAnswer={() => {}} />,
    )
    expect(screen.getByRole('button', { name: 'Submit Answer' })).toBeDisabled()
    expect(screen.getByText(/your answer cannot be sent/)).toBeInTheDocument()
  })

  test('the drawer guards every decision path on the connection', () => {
    const src = readFileSync(join(__dirname, 'AIAssistantDrawer.tsx'), 'utf8')
    expect(src).toContain('handleApproval={guardedApproval}')
    expect(src).toContain('handleAnswer={guardedAnswer}')
    expect(src).toContain('handleTimelineToolConfirmation={guardedToolConfirmation}')
  })
})

describe('the download card parses the route error (G-46)', () => {
  test('a JSON error shows its sentence and status, not the raw body', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(
      JSON.stringify({ error: 'Failed to download file', code: 'agent_unreachable', cause: 'ECONNREFUSED' }),
      { status: 503, headers: { 'Content-Type': 'application/json' } },
    )))
    render(<FileDownloadCard filepath="/workspace/p1/notes/out.txt" filename="out.txt" description="d" source="s" projectId="p1" />)
    fireEvent.click(screen.getByTitle('Download file'))
    expect(await screen.findByText('Failed to download file (agent_unreachable · HTTP 503)')).toBeInTheDocument()
    expect(screen.queryByText(/\{"error"/)).toBeNull()
  })
})

describe('the API-key modal says why a save failed (G-41)', () => {
  test('a refused save alerts the reason and keeps the modal open', async () => {
    vi.stubGlobal('fetch', vi.fn(async (_url: string, init?: RequestInit) => init?.method === 'PUT'
      ? new Response(JSON.stringify({ error: 'Failed to update settings', code: 'P2024' }), { status: 500 })
      : new Response(JSON.stringify({}), { status: 200 })))
    const { result } = renderHook(() => useApiKeyModal('u1'))
    act(() => { result.current.openApiKeyModal('shodan'); result.current.setApiKeyValue('abc') })
    await act(async () => { await result.current.saveApiKey() })
    expect(alerts.alertError).toHaveBeenCalledWith('Failed to update settings (P2024 · HTTP 500)', 'API key not saved')
    expect(result.current.apiKeyModal).toBe('shodan')
    expect(result.current.apiKeySaving).toBe(false)
  })

  test('no answer at all is a network error, not silence', async () => {
    vi.stubGlobal('fetch', vi.fn(async (_url: string, init?: RequestInit) => {
      if (init?.method === 'PUT') throw new TypeError('Failed to fetch')
      return new Response(JSON.stringify({}), { status: 200 })
    }))
    const { result } = renderHook(() => useApiKeyModal('u1'))
    act(() => { result.current.openApiKeyModal('web_search'); result.current.setApiKeyValue('abc') })
    await act(async () => { await result.current.saveApiKey() })
    await waitFor(() => expect(alerts.alertError).toHaveBeenCalledWith('Could not save the Tavily key (network_error)', 'API key not saved'))
  })
})

describe('a delete that left work behind says so (G-45)', () => {
  test('each failed step is named with its cause', () => {
    expect(deleteWarningsText([
      { step: 'agent_stop', code: 'agent_error', status: 500 },
      { step: 'graph_cleanup', code: 'Neo.TransientError.General.DatabaseUnavailable' },
    ])).toBe(
      'Session deleted, but its agent could not be stopped and may still be running (agent_error · HTTP 500); '
      + 'its attack-chain nodes could not be removed from the graph (Neo.TransientError.General.DatabaseUnavailable).',
    )
  })
})

describe('skill toggles that could not load say why (U-66)', () => {
  test('the notice carries the code and status', () => {
    render(<SkillDataNotice error={new ApiError({ reason: 'Failed to load the attack skills', status: 500, code: 'P1001' })} />)
    expect(screen.getByRole('status')).toHaveTextContent('Skill toggles could not be loaded: Failed to load the attack skills (P1001 · HTTP 500)')
  })

  test('nothing is shown when the skills loaded', () => {
    const { container } = render(<SkillDataNotice error={null} />)
    expect(container).toBeEmptyDOMElement()
  })

  test('the drawer renders the hook error', () => {
    const src = readFileSync(join(__dirname, 'AIAssistantDrawer.tsx'), 'utf8')
    expect(src).toContain('error: skillDataError } = useAttackSkillData(userId, projectId)')
    expect(src).toContain('<SkillDataNotice error={skillDataError} />')
  })
})
