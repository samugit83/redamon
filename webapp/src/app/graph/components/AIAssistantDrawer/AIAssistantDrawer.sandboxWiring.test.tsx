/**
 * Wiring of the run's Kali sandbox status in the chat drawer (group 1, WI-S15-3).
 * The drawer needs a whole page of providers to render, so its wiring is read
 * from the source (as AIAssistantDrawer.socketWiring.test.ts does); the behaviour
 * behind each line is tested in hooks/sandboxStatus.test.tsx. ChatArea, which
 * shows the line, renders here.
 *
 * Run: npx vitest run --no-file-parallelism src/app/graph/components/AIAssistantDrawer/AIAssistantDrawer.sandboxWiring.test.tsx
 */
import React, { createRef } from 'react'
import { describe, test, expect, afterEach, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { act, cleanup, render, renderHook, screen } from '@testing-library/react'
import { ChatArea } from './ChatArea'
import { SANDBOX_STARTING_WORD } from './hooks/sandboxStatus'
import { useSendHandlers } from './hooks/useSendHandlers'

afterEach(cleanup)

const src = readFileSync(join(__dirname, 'AIAssistantDrawer.tsx'), 'utf8')
const between = (from: string, to: string) => src.slice(src.indexOf(from), src.indexOf(to, src.indexOf(from)))

describe('AIAssistantDrawer sandbox wiring', () => {
  test('the status hook follows the run, the session and the project, and shows the modal through useAlertModal', () => {
    expect(src).toContain('useSandboxUnavailable()')
    const opts = between('useSandboxStatus({', '})')
    expect(opts).toMatch(/isLoading,/)
    expect(opts).toMatch(/sessionId,/)
    expect(opts).toMatch(/projectId,/)
  })

  test('the socket handler hands sandbox frames to the hook', () => {
    expect(src).toMatch(/const \{ sandboxWord, onSandboxStatus, noteRunStart \} = useSandboxStatus\(\{/)
    expect(between('useWebSocketHandler({', '})')).toMatch(/\bonSandboxStatus,/)
  })

  test('every query and every resume starts a run for the once-per-run modal', () => {
    const sends = between('useSendHandlers({', '})')
    expect(sends).toMatch(/sendQuery: sendQueryForRun,/)
    expect(sends).toMatch(/sendResume: sendResumeForRun,/)
    expect(between('const sendQueryForRun', '}, [')).toMatch(/noteRunStart\(question, shown\)\s+sendQuery\(question\)/)
    expect(between('const sendResumeForRun', '}, [')).toMatch(/noteRunStart\(\)\s+sendResume\(\)/)
  })

  test('Retry sends the query again as a new run, under the text recorded at its start, only on a live socket', () => {
    const resend = between('resendRunRef.current = (query: string, shown: string) =>', '}, [')
    expect(resend).toMatch(/if \(!isConnectedRef\.current\) \{ toast\.error\(SANDBOX_RETRY_NOT_SENT/)
    expect(resend).toMatch(/content: shown,/)
    expect(resend).toContain('sendQueryForRun(query, shown)')
    expect(resend).not.toContain('chatItems')
    expect(between('useSandboxStatus({', '})')).toContain('resend: (query, shown) => resendRunRef.current(query, shown),')
  })

  test('Retry ends nothing that is still going: the run is over only with no spinner and no decision pending', () => {
    const ended = between('runEnded:', '\n')
    for (const flag of ['isLoadingRef', 'awaitingApprovalRef', 'awaitingQuestionRef', 'awaitingToolConfirmationRef']) {
      expect(ended).toContain(`!${flag}.current`)
    }
  })

  test('the line reaches the chat', () => {
    expect(between('<ChatArea', '/>')).toContain('sandboxWord={sandboxWord}')
  })
})

function renderChat(props: Partial<React.ComponentProps<typeof ChatArea>>) {
  return render(
    <ChatArea
      messagesContainerRef={createRef<HTMLDivElement>()}
      messagesEndRef={createRef<HTMLDivElement>()}
      checkIfAtBottom={() => true}
      chatItems={[]}
      groupedChatItems={[]}
      isLoading
      todoList={[]}
      statusWord="Pondering"
      isConnected
      setInputValue={() => {}}
      missingApiKeys={new Set()}
      handleTimelineToolConfirmation={() => {}}
      {...props}
    />,
  )
}

/** useSendHandlers with every dependency a stub, as useSendHandlers.chatSkills.test.ts builds them. */
function sendDeps(over: Record<string, unknown>) {
  const base: Record<string, unknown> = {
    inputValue: '', isLoading: false, chatItems: [], activeSkill: null,
    awaitingApproval: false, awaitingQuestion: false, awaitingToolConfirmation: false,
    questionRequest: null, modificationText: '', answerText: '', selectedOptions: [],
    conversationId: 'c1', projectId: 'p1', userId: 'alice', sessionId: 's1',
    ...over,
  }
  for (const ref of [
    'isProcessingApproval', 'awaitingApprovalRef', 'isProcessingQuestion', 'awaitingQuestionRef',
    'isProcessingToolConfirmation', 'awaitingToolConfirmationRef', 'pendingApprovalToolId', 'pendingApprovalWaveId',
  ]) base[ref] = { current: null }
  return new Proxy(base, {
    get: (target, key: string) => {
      if (!(key in target)) target[key] = vi.fn()
      return target[key]
    },
  }) as unknown as Parameters<typeof useSendHandlers>[0]
}

describe('the text a run is retried under', () => {
  test('a query sent with a chat skill hands over the text the chat shows, not the skill context', async () => {
    const sendQuery = vi.fn()
    const deps = sendDeps({
      inputValue: 'scan the host', sendQuery,
      activeSkill: { id: 'cs1', name: 'Recon notes', content: 'skill text' },
    })
    const { result } = renderHook(() => useSendHandlers(deps))
    await act(async () => { await result.current.handleSend() })
    expect(sendQuery).toHaveBeenCalledWith('[Chat Skill Context]\nskill text\n\n[User Query]\nscan the host', 'scan the host')
  })

  test('a plain query: the two are the same text', async () => {
    const sendQuery = vi.fn()
    const { result } = renderHook(() => useSendHandlers(sendDeps({ inputValue: 'exploit the ssh service', sendQuery })))
    await act(async () => { await result.current.handleSend() })
    expect(sendQuery).toHaveBeenCalledWith('exploit the ssh service', 'exploit the ssh service')
  })
})

describe('ChatArea while the sandbox starts', () => {
  test('the line replaces the rotating word', () => {
    renderChat({ sandboxWord: SANDBOX_STARTING_WORD })
    expect(screen.getByText(SANDBOX_STARTING_WORD)).toBeInTheDocument()
    expect(screen.queryByText('Pondering')).toBeNull()
  })

  test('a provider rate-limit wait still wins: it says why nothing moves', () => {
    renderChat({ sandboxWord: SANDBOX_STARTING_WORD, rateLimitWord: 'Provider rate limit: retrying the next step in 5 s' })
    expect(screen.getByText('Provider rate limit: retrying the next step in 5 s')).toBeInTheDocument()
    expect(screen.queryByText(SANDBOX_STARTING_WORD)).toBeNull()
  })

  test('no line: the rotating word', () => {
    renderChat({ sandboxWord: null })
    expect(screen.getByText('Pondering')).toBeInTheDocument()
  })

  test('nothing while the run is not loading', () => {
    renderChat({ sandboxWord: SANDBOX_STARTING_WORD, isLoading: false })
    expect(screen.queryByText(SANDBOX_STARTING_WORD)).toBeNull()
  })
})
